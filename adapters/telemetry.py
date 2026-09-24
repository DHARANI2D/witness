"""Parsers for AIOpsLab's real telemetry export formats.

These match the exact schemas AIOpsLab's own code produces, verified
against the vendored source rather than guessed:

- Metrics: `aiopslab.observer.metric_api.PrometheusAPI.export_all_metrics`
  writes one CSV per metric with columns `timestamp,cmdb_id,kpi_name,value`
  (see `aiopslab/observer/metric_api.py`). `TaskActions.get_metrics` is
  the exec-shell-callable wrapper an agent actually invokes, and
  `TaskActions.read_metrics` reads exactly this CSV back with
  `pandas.read_csv`. These are Prometheus-scraped counters: nobody's
  HTTP request writes into them, so they are unambiguously SYS.

- Pod logs: `aiopslab.observer.log_api.log_processing_hotel_reservation`
  builds a DataFrame with columns
  `log_id,timestamp,date,pod_name,container_name,namespace,node_name,message`
  (see `aiopslab/observer/log_api.py`). The structural columns come from
  the Kubernetes API (SYS); `message` is the pod's own stdout/stderr,
  which is exactly where request-supplied content (paths, headers,
  usernames) ends up logged verbatim -- so it is labeled EXT.

- Raw `get_logs()` output: `TaskActions.get_logs` (base.py) returns
  `kubectl logs`/`docker logs` output as a single string with no
  structure at all; each line is pod stdout/stderr, so it is EXT too.
"""

from __future__ import annotations

import csv
import io
from typing import Iterable

from witness_core import Channel, TelemetryEvent


def metrics_csv_to_events(csv_text: str, source_label: str = "prometheus") -> list[TelemetryEvent]:
    """Parse AIOpsLab's `timestamp,cmdb_id,kpi_name,value` metric CSV
    (the real format `PrometheusAPI.export_all_metrics` writes and
    `TaskActions.read_metrics` reads back) into SYS TelemetryEvents.
    """
    events: list[TelemetryEvent] = []
    reader = csv.DictReader(io.StringIO(csv_text))
    required = {"timestamp", "cmdb_id", "kpi_name", "value"}
    if reader.fieldnames is None or not required.issubset(set(reader.fieldnames)):
        raise ValueError(f"metrics CSV missing required columns {required}; got {reader.fieldnames}")

    for i, row in enumerate(reader):
        try:
            observed_at = float(row["timestamp"])
        except (TypeError, ValueError):
            observed_at = None
        event = TelemetryEvent(
            event_id=f"{source_label}-{row['kpi_name']}-{row['cmdb_id']}-{i}",
            channel=Channel.SYS,
            channel_id=f"{source_label}:{row['kpi_name']}",
            field=row["kpi_name"],
            value=row["value"],
            **({"observed_at": observed_at} if observed_at is not None else {}),
        )
        events.append(event)
    return events


def pod_log_rows_to_events(rows: Iterable[dict], source_label: str = "elasticsearch") -> list[TelemetryEvent]:
    """Convert rows shaped like AIOpsLab's `log_processing_hotel_reservation`
    output (one dict per log line, keys: log_id, timestamp, date, pod_name,
    container_name, namespace, node_name, message) into EXT TelemetryEvents
    over the free-text `message` field.
    """
    events: list[TelemetryEvent] = []
    for row in rows:
        missing = {"log_id", "message", "pod_name", "namespace"} - set(row)
        if missing:
            raise ValueError(f"log row missing required keys {missing}: {row}")
        try:
            observed_at = float(row["timestamp"])
        except (TypeError, ValueError, KeyError):
            observed_at = None
        event = TelemetryEvent(
            event_id=f"{source_label}-log-{row['log_id']}",
            channel=Channel.EXT,
            channel_id=f"{source_label}:pod_log_message",
            field="message",
            value=row["message"],
            **({"observed_at": observed_at} if observed_at is not None else {}),
        )
        events.append(event)
    return events


def raw_pod_logs_to_events(raw_text: str, namespace: str, pod: str, source_label: str = "kubectl_logs") -> list[TelemetryEvent]:
    """Convert raw `kubectl logs`/`docker logs` text (as returned by
    `TaskActions.get_logs`) into one EXT event per non-empty line.
    """
    events: list[TelemetryEvent] = []
    for i, line in enumerate(raw_text.splitlines()):
        if not line.strip():
            continue
        events.append(
            TelemetryEvent(
                event_id=f"{source_label}-{namespace}-{pod}-{i}",
                channel=Channel.EXT,
                channel_id=f"{source_label}:{namespace}:{pod}",
                field="log_line",
                value=line,
            )
        )
    return events
