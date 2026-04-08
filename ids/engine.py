"""End-to-end IDS pipeline orchestration."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from time import perf_counter
from typing import Dict, Iterable, List

from .alert_manager import AlertManager
from .anomaly import AnomalyDetector
from .config import IDSConfig
from .correlation import CorrelationEngine
from .host_sensor import HostSensor
from .models import Alert, Detection
from .network_sensor import NetworkSensor
from .rules import RuleEngine
from .schema import Event, make_event, validate_event_dict


@dataclass
class EngineOutput:
    alerts: List[Alert]
    detections: List[Detection]
    events: List[Event]
    processing_latency_ms: float


class IDSEngine:
    """Main IDS pipeline: normalize -> detect -> correlate -> alert."""

    def __init__(self, config: IDSConfig | None = None) -> None:
        self.config = config or IDSConfig()
        self.network_sensor = NetworkSensor()
        self.host_sensor = HostSensor()
        self.rules = RuleEngine()
        self.anomaly = AnomalyDetector(
            baseline_window=self.config.anomaly_baseline_window,
            z_threshold=self.config.anomaly_z_threshold,
        )
        self.correlation = CorrelationEngine(self.config)
        self.alert_manager = AlertManager(self.config)

    def process_batch(
        self,
        flow_rows: Iterable[Dict],
        host_rows: Iterable[Dict],
        extra_rows: Iterable[Dict],
    ) -> EngineOutput:
        start = perf_counter()

        events = []
        events.extend(self.network_sensor.ingest_flows(flow_rows))
        events.extend(self.host_sensor.ingest_logs(host_rows))
        events.extend(self._extra_to_events(extra_rows))

        # Keep window sorted to make time-window eviction stable.
        events.sort(key=lambda e: e.timestamp)

        self.correlation.ingest(events)
        window_events = self.correlation.get_window_events()

        detections = []
        detections.extend(self.rules.evaluate(window_events))
        detections.extend(self.anomaly.evaluate(window_events))

        alerts = self.correlation.correlate(detections)
        deduped = self.alert_manager.process(alerts)

        latency_ms = (perf_counter() - start) * 1000.0
        return EngineOutput(alerts=deduped, detections=detections, events=events, processing_latency_ms=latency_ms)

    def _extra_to_events(self, rows: Iterable[Dict]) -> List[Event]:
        out: List[Event] = []
        for row in rows:
            kind = row.get("kind")
            event: Event | None = None
            if kind == "noise":
                event = make_event(
                    source="simulator",
                    category="noise",
                    subject=row.get("subject", "environment"),
                    metadata={"reason": "noise_injection"},
                    timestamp=row.get("timestamp"),
                )
            elif kind == "sensor_status":
                event = make_event(
                    source="system",
                    category="sensor_status",
                    subject="ids",
                    outcome=row.get("status"),
                    metadata={"sensor": row.get("sensor"), "status": row.get("status")},
                    timestamp=row.get("timestamp") or datetime.utcnow().isoformat(),
                )

            if event is None:
                continue

            errors = validate_event_dict(event.to_dict())
            if errors:
                raise ValueError(f"invalid extra event: {errors}")

            out.append(event)
        return out
