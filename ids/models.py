"""Shared internal models for detections and alerts."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Set


@dataclass
class Detection:
    rule_id: str
    title: str
    description: str
    subject: str
    score: int
    source: str
    event_ids: List[str]
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Alert:
    alert_id: str
    title: str
    description: str
    subject: str
    score: int
    severity: str
    sources: Set[str]
    event_ids: List[str]
    tags: List[str]
    first_seen: str
    last_seen: str
    metadata: Dict[str, Any]
