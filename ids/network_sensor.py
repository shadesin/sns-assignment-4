"""Network sensor that emits normalized flow-level events."""

from __future__ import annotations

from typing import Dict, Iterable, List

from .schema import Event, make_event, validate_event_dict


class NetworkSensor:
    """Transforms flow metadata into schema-compliant network events."""

    def __init__(self, sensor_id: str = "network-sensor-1") -> None:
        self.sensor_id = sensor_id

    def ingest_flows(self, flows: Iterable[Dict]) -> List[Event]:
        events: List[Event] = []
        for flow in flows:
            event = make_event(
                source="network",
                category="network_flow",
                subject=str(flow.get("src_ip", "unknown")),
                src_ip=flow.get("src_ip"),
                dst_ip=flow.get("dst_ip"),
                src_port=flow.get("src_port"),
                dst_port=flow.get("dst_port"),
                protocol=flow.get("protocol", "tcp"),
                outcome=flow.get("outcome"),
                metadata={
                    "packet_count": int(flow.get("packet_count", 0)),
                    "byte_count": int(flow.get("byte_count", 0)),
                    "duration_ms": int(flow.get("duration_ms", 0)),
                    "sensor_id": self.sensor_id,
                    "scan_hint": bool(flow.get("scan_hint", False)),
                    "replay_hint": bool(flow.get("replay_hint", False)),
                },
                timestamp=flow.get("timestamp"),
            )
            errors = validate_event_dict(event.to_dict())
            if errors:
                raise ValueError(f"invalid network event: {errors}")
            events.append(event)
        return events
