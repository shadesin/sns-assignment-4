"""Lightweight statistical anomaly detector for event rates."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from math import sqrt
from typing import Deque, Dict, Iterable, List

from .models import Detection
from .schema import Event


@dataclass
class Baseline:
    values: Deque[float]


class AnomalyDetector:
    """Z-score based detector over request rate and failed login count features."""

    def __init__(self, baseline_window: int = 50, z_threshold: float = 2.2) -> None:
        self.baseline_window = baseline_window
        self.z_threshold = z_threshold
        self.rate_history: Dict[str, Baseline] = defaultdict(lambda: Baseline(deque(maxlen=self.baseline_window)))
        self.fail_history: Dict[str, Baseline] = defaultdict(lambda: Baseline(deque(maxlen=self.baseline_window)))

    def evaluate(self, events: Iterable[Event]) -> List[Detection]:
        events = list(events)
        flow_counts: Dict[str, int] = defaultdict(int)
        fail_counts: Dict[str, int] = defaultdict(int)

        for event in events:
            subject = event.src_ip or event.subject
            if event.category == "network_flow":
                flow_counts[subject] += 1
            if event.category == "login_attempt" and event.outcome == "failed":
                fail_counts[subject] += 1

        detections: List[Detection] = []
        detections.extend(self._feature_anomaly("ANOM_RATE", "network rate spike", flow_counts, self.rate_history, events))
        detections.extend(self._feature_anomaly("ANOM_FAIL", "failed login spike", fail_counts, self.fail_history, events))
        return detections

    def _feature_anomaly(
        self,
        rule_id: str,
        title: str,
        current: Dict[str, int],
        history: Dict[str, Baseline],
        events: List[Event],
    ) -> List[Detection]:
        output: List[Detection] = []
        for subject, count in current.items():
            values = history[subject].values
            mu = sum(values) / len(values) if values else 0.0
            sigma = self._std(values, mu)
            z = (count - mu) / (sigma + 1e-6)

            if len(values) >= 5 and z >= self.z_threshold:
                related_event_ids = [e.event_id for e in events if (e.src_ip or e.subject) == subject]
                output.append(
                    Detection(
                        rule_id=rule_id,
                        title=f"Anomaly: {title}",
                        description=f"subject={subject}, value={count}, baseline={mu:.2f}, z={z:.2f}",
                        subject=subject,
                        score=38,
                        source="system",
                        event_ids=related_event_ids,
                        tags=["anomaly", "statistics"],
                        metadata={"z_score": round(z, 3), "current": count, "baseline": round(mu, 3)},
                    )
                )

            values.append(float(count))

        return output

    @staticmethod
    def _std(values: Deque[float], mean: float) -> float:
        if len(values) <= 1:
            return 0.0
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        return sqrt(variance)
