"""Host sensor that emits normalized host telemetry events."""

from __future__ import annotations

from typing import Dict, Iterable, List

from .schema import Event, make_event, validate_event_dict


class HostSensor:
    """Transforms host logs into schema-compliant host events."""

    def __init__(self, sensor_id: str = "host-sensor-1") -> None:
        self.sensor_id = sensor_id

    def ingest_logs(self, logs: Iterable[Dict]) -> List[Event]:
        events: List[Event] = []

        for entry in logs:
            action = entry.get("action", "unknown")
            category = "login_attempt" if action in {"login_failed", "login_success"} else "process_start"
            outcome = "failed" if action == "login_failed" else "success" if action == "login_success" else entry.get("outcome")

            event = make_event(
                source="host",
                category=category,  # type: ignore[arg-type]
                subject=str(entry.get("user", "unknown")),
                src_ip=entry.get("src_ip"),
                dst_ip=entry.get("host_ip"),
                protocol="hostlog",
                outcome=outcome,
                metadata={
                    "action": action,
                    "process": entry.get("process"),
                    "command": entry.get("command"),
                    "sensor_id": self.sensor_id,
                },
                timestamp=entry.get("timestamp"),
            )
            errors = validate_event_dict(event.to_dict())
            if errors:
                raise ValueError(f"invalid host event: {errors}")
            events.append(event)

        return events
