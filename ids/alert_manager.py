"""Alert deduplication, cooldown, and sink export utilities."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Iterable, List, Tuple
import json

from .config import IDSConfig
from .models import Alert


class AlertManager:
    """Suppresses duplicate alerts and writes alerts as JSONL output."""

    def __init__(self, config: IDSConfig) -> None:
        self.config = config
        self.last_alert_at: Dict[Tuple[str, str, str], datetime] = {}

    def process(self, alerts: Iterable[Alert]) -> List[Alert]:
        output: List[Alert] = []
        now = datetime.utcnow()

        for alert in alerts:
            signature = (alert.subject, alert.title, alert.severity)
            seen = self.last_alert_at.get(signature)
            if seen is not None:
                cooldown = timedelta(seconds=self.config.alert_cooldown_seconds)
                if now - seen < cooldown:
                    continue

            self.last_alert_at[signature] = now
            output.append(alert)

        return output

    @staticmethod
    def export_jsonl(alerts: Iterable[Alert], output_path: Path) -> None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8") as handle:
            for alert in alerts:
                payload = asdict(alert)
                payload["sources"] = sorted(list(alert.sources))
                handle.write(json.dumps(payload, sort_keys=True) + "\n")
