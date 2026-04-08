"""Common event schema used by all IDS components."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional
import json
import uuid

EventSource = Literal["network", "host", "simulator", "system"]
EventCategory = Literal[
    "network_flow",
    "login_attempt",
    "process_start",
    "replay_activity",
    "sensor_status",
    "noise",
]


@dataclass(frozen=True)
class Event:
    """Normalized event representation shared across the IDS pipeline."""

    event_id: str
    timestamp: str
    source: EventSource
    category: EventCategory
    subject: str
    src_ip: Optional[str]
    dst_ip: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: Optional[str]
    outcome: Optional[str]
    metadata: Dict[str, Any]

    def to_json(self) -> str:
        return json.dumps(asdict(self), separators=(",", ":"), sort_keys=True)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


_REQUIRED_FIELDS = {
    "event_id": str,
    "timestamp": str,
    "source": str,
    "category": str,
    "subject": str,
    "metadata": dict,
}


_ALLOWED_SOURCES = {"network", "host", "simulator", "system"}
_ALLOWED_CATEGORIES = {
    "network_flow",
    "login_attempt",
    "process_start",
    "replay_activity",
    "sensor_status",
    "noise",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def make_event(
    *,
    source: EventSource,
    category: EventCategory,
    subject: str,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    src_port: Optional[int] = None,
    dst_port: Optional[int] = None,
    protocol: Optional[str] = None,
    outcome: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    timestamp: Optional[str] = None,
) -> Event:
    return Event(
        event_id=str(uuid.uuid4()),
        timestamp=timestamp or now_iso(),
        source=source,
        category=category,
        subject=subject,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        outcome=outcome,
        metadata=metadata or {},
    )


def validate_event_dict(payload: Dict[str, Any]) -> List[str]:
    errors: List[str] = []

    for key, expected_type in _REQUIRED_FIELDS.items():
        if key not in payload:
            errors.append(f"missing required field: {key}")
            continue
        if not isinstance(payload[key], expected_type):
            errors.append(f"invalid type for {key}: expected {expected_type.__name__}")

    if "source" in payload and payload.get("source") not in _ALLOWED_SOURCES:
        errors.append(f"invalid source: {payload.get('source')}")

    if "category" in payload and payload.get("category") not in _ALLOWED_CATEGORIES:
        errors.append(f"invalid category: {payload.get('category')}")

    if "timestamp" in payload:
        try:
            datetime.fromisoformat(payload["timestamp"])
        except Exception:
            errors.append("timestamp is not valid ISO format")

    int_fields = ["src_port", "dst_port"]
    for name in int_fields:
        if payload.get(name) is not None and not isinstance(payload[name], int):
            errors.append(f"{name} must be int or null")

    optional_str_fields = ["src_ip", "dst_ip", "protocol", "outcome"]
    for name in optional_str_fields:
        value = payload.get(name)
        if value is not None and not isinstance(value, str):
            errors.append(f"{name} must be string or null")

    return errors
