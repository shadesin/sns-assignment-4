"""Correlation engine: sliding window + source-aware severity scoring."""

from __future__ import annotations

from collections import deque
from datetime import datetime, timedelta
from typing import Deque, Dict, Iterable, List, Set, Tuple
import uuid

from .config import IDSConfig
from .models import Alert, Detection
from .schema import Event


class CorrelationEngine:
    """Maintains an event window and correlates detections into scored alerts."""

    def __init__(self, config: IDSConfig) -> None:
        self.config = config
        self.window: Deque[Event] = deque()

    def ingest(self, events: Iterable[Event]) -> None:
        for event in events:
            self.window.append(event)
        self._evict_old()

    def get_window_events(self) -> List[Event]:
        self._evict_old()
        return list(self.window)

    def correlate(self, detections: Iterable[Detection]) -> List[Alert]:
        # Group by subject to allow multi-rule, multi-source evidence fusion.
        grouped: Dict[str, List[Detection]] = {}
        for detection in detections:
            grouped.setdefault(detection.subject, []).append(detection)

        alerts: List[Alert] = []
        now = datetime.utcnow().isoformat()

        for subject, group in grouped.items():
            total_score = sum(det.score for det in group)
            distinct_sources: Set[str] = {det.source for det in group}
            tags = sorted({tag for det in group for tag in det.tags})
            event_ids = [eid for det in group for eid in det.event_ids]
            rule_ids = sorted({det.rule_id for det in group})

            # Bonus when independent evidence agrees in same window.
            if len(distinct_sources) >= 2:
                total_score += self.config.source_bonus

            severity = self._severity_from_score(total_score)

            # Mandatory requirement: single-source evidence cannot become critical,
            # unless a deterministic strong multi-step rule is matched.
            is_strong_multistep = any(det.rule_id == "R4_MULTI_STEP" and det.score >= 75 for det in group)
            if severity == "critical" and len(distinct_sources) < 2 and not is_strong_multistep:
                severity = "high"
                total_score = min(total_score, self.config.severity_weights["high"])

            alerts.append(
                Alert(
                    alert_id=str(uuid.uuid4()),
                    title=group[0].title if len(rule_ids) == 1 else "Correlated multi-signal intrusion",
                    description=" | ".join(det.description for det in group),
                    subject=subject,
                    score=total_score,
                    severity=severity,
                    sources=distinct_sources,
                    event_ids=event_ids,
                    tags=tags,
                    first_seen=now,
                    last_seen=now,
                    metadata={"rules": rule_ids},
                )
            )

        return alerts

    def _evict_old(self) -> None:
        if not self.window:
            return

        latest = datetime.fromisoformat(self.window[-1].timestamp)
        cutoff = latest - timedelta(seconds=self.config.correlation_window_seconds)
        while self.window and datetime.fromisoformat(self.window[0].timestamp) < cutoff:
            self.window.popleft()

    def _severity_from_score(self, score: int) -> str:
        weights = self.config.severity_weights
        if score >= weights["critical"]:
            return "critical"
        if score >= weights["high"]:
            return "high"
        if score >= weights["medium"]:
            return "medium"
        if score >= weights["low"]:
            return "low"
        return "info"
