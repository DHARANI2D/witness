"""A genuine incident: CPU saturation on a real service.

Two independent SYS signals (cAdvisor's container metric and the node
exporter's host-level metric) agree the service is CPU-saturated, and
the restart target is a real, known service name. WITNESS should admit
this remediation — a security gate that also blocks legitimate
automation is not useful.
"""

from __future__ import annotations

from witness_core import (
    Channel,
    Claim,
    EvidenceStore,
    ProposedRemediation,
    RemediationAction,
    TelemetryEvent,
    Verdict,
)

DESCRIPTION = (
    "Genuine CPU saturation confirmed by two independent SYS metrics; restart "
    "target is a known service, so WITNESS ADMITs the fix."
)


def build():
    cadvisor_cpu = TelemetryEvent(
        event_id="sys-cadvisor-cpu",
        channel=Channel.SYS,
        channel_id="cadvisor:container_cpu_pct",
        field="cpu_utilization_pct",
        value=96,
    )

    node_exporter_cpu = TelemetryEvent(
        event_id="sys-node-cpu",
        channel=Channel.SYS,
        channel_id="node_exporter:host_cpu_pct",
        field="cpu_utilization_pct",
        value=94,
    )

    k8s_pod_label = TelemetryEvent(
        event_id="sys-k8s-pod",
        channel=Channel.SYS,
        channel_id="k8s_api:pod_labels",
        field="service_name",
        value="checkout-service",
    )

    store = EvidenceStore([cadvisor_cpu, node_exporter_cpu, k8s_pod_label])

    remediation = ProposedRemediation(
        incident_id="INC-1002-cpu-saturation",
        claims=(
            Claim(
                predicate="cpu_saturated",
                subject="checkout-service",
                value="true",
                source_event_id=cadvisor_cpu.event_id,
            ),
        ),
        action=RemediationAction(
            verb="restart_service",
            target="checkout-service",
            arguments={"service": "checkout-service"},
        ),
    )

    return store, remediation, Verdict.ADMIT, DESCRIPTION
