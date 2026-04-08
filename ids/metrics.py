"""Evaluation metrics helpers for IDS experiments."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Set

from .models import Alert


_RULE_TO_LABELS = {
    "R1_BRUTE_FORCE": {"bruteforce"},
    "R2_FAST_SCAN": {"scan"},
    "R3_SLOW_SCAN": {"slow-scan"},
    "R4_MULTI_STEP": {"multi-step"},
    "R5_REPLAY": {"replay"},
    "R6_NOISE_MASKING": {"noise"},
    "R7_SENSOR_DOWN": {"sensor"},
}

_LABEL_UNIVERSE = set().union(*_RULE_TO_LABELS.values())


@dataclass
class EvalResult:
    precision: float
    recall: float
    f1_score: float
    false_positive_rate: float
    false_negative_rate: float
    avg_latency_ms: float
    cpu_memory_note: str


def compute_eval(
    generated_alerts: Iterable[Alert],
    expected_labels: Iterable[str],
    latencies_ms: List[float],
) -> EvalResult:
    generated_labels: Set[str] = set()
    for alert in generated_alerts:
        rules = alert.metadata.get("rules", []) if alert.metadata else []
        for rule_id in rules:
            generated_labels.update(_RULE_TO_LABELS.get(rule_id, set()))

    expected = set(expected_labels)

    true_pos = len(generated_labels.intersection(expected))
    false_pos = len(generated_labels - expected)
    false_neg = len(expected - generated_labels)

    precision = true_pos / (true_pos + false_pos) if (true_pos + false_pos) else 0.0
    recall = true_pos / (true_pos + false_neg) if (true_pos + false_neg) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    true_neg = len(_LABEL_UNIVERSE - generated_labels - expected)
    fpr = false_pos / (false_pos + true_neg) if (false_pos + true_neg) else 0.0
    fnr = false_neg / (false_neg + true_pos) if (false_neg + true_pos) else 0.0

    avg_latency = sum(latencies_ms) / len(latencies_ms) if latencies_ms else 0.0

    return EvalResult(
        precision=precision,
        recall=recall,
        f1_score=f1,
        false_positive_rate=fpr,
        false_negative_rate=fnr,
        avg_latency_ms=avg_latency,
        cpu_memory_note=(
            "Use Task Manager or 'Get-Process python | Select CPU,PM' during run; "
            "runner prints a lightweight live sample via psutil if available."
        ),
    )
