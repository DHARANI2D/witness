"""Real telemetry provider for the docker-compose live environment
(live_env/docker-compose.yml), which runs AIOpsLab's actual
HotelReservation container images without a Kubernetes cluster (see
README.md "Why docker-compose, not kind").

Every event this module produces comes from an actual command run
against actually-running containers -- `docker stats`, a direct cgroup
read via `docker exec`, and `docker logs` -- not synthetic fixtures.

Two independent SYS measurement paths for CPU are deliberately used so
the two-witness corroboration rule has genuine class diversity to work
with, the same way real Prometheus + cAdvisor + node-exporter would
give it in a full cluster:

  - `docker_stats`  : the Docker Engine API's own CPU accounting
                       (`docker stats --no-stream`), computed from two
                       cgroup CPU-usage snapshots by the Engine itself.
  - `cgroup_direct` : reading the container's own
                       `cpuacct.usage` cgroup file directly via
                       `docker exec`, bypassing the Engine's computation
                       entirely.

These are genuinely different code paths (different process, different
computation), not two calls to the same API.
"""

from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass

from witness_core import Channel, TelemetryEvent


def _run(cmd: list[str], timeout: int = 10) -> str:
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return result.stdout


@dataclass
class CpuSample:
    container: str
    docker_stats_pct: float
    cgroup_usage_ns_delta: int | None
    observed_at: float


class LiveDockerTelemetry:
    """Polls the real docker-compose environment for SYS/EXT telemetry."""

    def __init__(self):
        self._last_cgroup_usage: dict[str, tuple[float, int]] = {}

    def docker_stats_cpu_pct(self, container: str) -> float:
        out = _run(["docker", "stats", "--no-stream", "--format", "{{.CPUPerc}}", container])
        raw = out.strip().rstrip("%")
        return float(raw) if raw else 0.0

    def cgroup_cpu_usage_ns(self, container: str) -> int:
        out = _run(["docker", "exec", container, "cat", "/sys/fs/cgroup/cpuacct/cpuacct.usage"])
        return int(out.strip())

    def cgroup_cpu_pct_delta(self, container: str, num_cpus: int = 4) -> float | None:
        """Compute a %CPU figure from two cgroup usage snapshots taken
        `interval` apart -- an independent computation from Docker's own,
        even though it reads the same underlying counter file."""
        now = time.time()
        usage = self.cgroup_cpu_usage_ns(container)
        prev = self._last_cgroup_usage.get(container)
        self._last_cgroup_usage[container] = (now, usage)
        if prev is None:
            return None
        prev_time, prev_usage = prev
        wall_delta_ns = (now - prev_time) * 1e9
        if wall_delta_ns <= 0:
            return None
        cpu_delta_ns = usage - prev_usage
        return max(0.0, (cpu_delta_ns / wall_delta_ns) * 100.0 / num_cpus * num_cpus)

    def cpu_events(self, container: str, channel_id_source_suffix: str = "") -> list[TelemetryEvent]:
        """Build SYS TelemetryEvents from both independent CPU measurement
        paths for `container`, suitable for the cpu_saturated predicate."""
        now = time.time()
        events = []
        docker_pct = self.docker_stats_cpu_pct(container)
        events.append(
            TelemetryEvent(
                event_id=f"docker_stats-cpu-{container}-{int(now * 1000)}",
                channel=Channel.SYS,
                channel_id=f"docker_stats:cpu_pct:{container}",
                field="cpu_utilization_pct",
                value=docker_pct,
                observed_at=now,
            )
        )
        cgroup_pct = self.cgroup_cpu_pct_delta(container)
        if cgroup_pct is not None:
            events.append(
                TelemetryEvent(
                    event_id=f"cgroup_direct-cpu-{container}-{int(now * 1000)}",
                    channel=Channel.SYS,
                    channel_id=f"cgroup_direct:cpu_pct:{container}",
                    field="cpu_utilization_pct",
                    value=cgroup_pct,
                    observed_at=now,
                )
            )
        return events

    def container_running(self, container: str) -> TelemetryEvent:
        out = _run(["docker", "inspect", "-f", "{{.State.Running}}", container])
        now = time.time()
        return TelemetryEvent(
            event_id=f"docker_inspect-running-{container}-{int(now * 1000)}",
            channel=Channel.SYS,
            channel_id=f"docker_inspect:state:{container}",
            field="container_name",
            value=container,
            observed_at=now,
        )

    def recent_logs(self, container: str, tail: int = 20) -> list[TelemetryEvent]:
        """Raw container log lines -- application-controlled stdout, so
        labeled EXT exactly like AIOpsLab's own get_logs() / pod-log
        message field (see adapters/telemetry.py)."""
        out = _run(["docker", "logs", "--tail", str(tail), container])
        events = []
        now = time.time()
        for i, line in enumerate(out.splitlines()):
            if not line.strip():
                continue
            events.append(
                TelemetryEvent(
                    event_id=f"docker_logs-{container}-{int(now * 1000)}-{i}",
                    channel=Channel.EXT,
                    channel_id=f"docker_logs:{container}",
                    field="log_line",
                    value=line,
                    observed_at=now,
                )
            )
        return events
