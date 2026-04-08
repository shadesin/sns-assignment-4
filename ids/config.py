"""Configuration values used by IDS modules."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict


@dataclass(frozen=True)
class IDSConfig:
    correlation_window_seconds: int = 30
    alert_cooldown_seconds: int = 20
    anomaly_baseline_window: int = 50
    anomaly_z_threshold: float = 2.2

    severity_weights: Dict[str, int] = None  # type: ignore[assignment]
    source_bonus: int = 10

    def __post_init__(self) -> None:
        if self.severity_weights is None:
            object.__setattr__(
                self,
                "severity_weights",
                {
                    "info": 10,
                    "low": 25,
                    "medium": 45,
                    "high": 70,
                    "critical": 90,
                },
            )


DEFAULT_CONFIG = IDSConfig()
