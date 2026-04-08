"""Run reproducible IDS experiments with multiple attack scenarios."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Dict, List, Tuple
import argparse
import json

from ids.alert_manager import AlertManager
from ids.attack_simulator import AttackSimulator
from ids.engine import IDSEngine
from ids.metrics import compute_eval

try:
    import psutil  # type: ignore
except Exception:
    psutil = None


SCENARIO_DETAILS = {
    "baseline": "Benign baseline traffic only; no attack activity. Used to estimate false positives.",
    "bruteforce": "Repeated failed logins against one account, followed by suspicious process execution.",
    "portscan_fast": "High-rate probing of many destination ports in a short time window.",
    "portscan_slow": "Low-rate probing of many destination ports with larger time gaps to evade simple thresholds.",
    "replay": "Repetition of near-identical flow signatures to mimic replayed benign traffic.",
    "noise": "Large background noise mixed with suspicious actions to hide malicious intent.",
    "sensor_failure": "Simulated sensor outage event to test resilience under partial visibility.",
}

SCENARIO_LABELS = {
    "baseline": "Baseline (Benign)",
    "bruteforce": "Brute-force Login",
    "portscan_fast": "Port Scan - Fast",
    "portscan_slow": "Port Scan - Slow",
    "replay": "Replay Attack",
    "noise": "Noise Injection",
    "sensor_failure": "Sensor Failure Simulation",
}


def scenario_catalog(sim: AttackSimulator):
    return {
        "baseline": lambda: sim.baseline_benign(60),
        "bruteforce": sim.brute_force,
        "portscan_fast": lambda: sim.port_scan(slow=False),
        "portscan_slow": lambda: sim.port_scan(slow=True),
        "replay": sim.replay_attack,
        "noise": sim.noise_injection,
        "sensor_failure": sim.sensor_failure,
    }


def expected_labels_for(name: str) -> List[str]:
    mapping = {
        "baseline": [],
        "bruteforce": ["bruteforce", "multi-step"],
        "portscan_fast": ["scan"],
        "portscan_slow": ["slow-scan"],
        "replay": ["replay"],
        "noise": ["noise"],
        "sensor_failure": ["sensor"],
    }
    return mapping.get(name, [])


def _fmt_metric(value: float) -> str:
    return f"{value:.3f}"


def _build_table(headers: List[str], rows: List[List[str]]) -> str:
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    def fmt_row(row: List[str]) -> str:
        return "| " + " | ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)) + " |"

    sep = "+-" + "-+-".join("-" * w for w in widths) + "-+"
    lines = [sep, fmt_row(headers), sep]
    lines.extend(fmt_row(row) for row in rows)
    lines.append(sep)
    return "\n".join(lines)


def format_report(summary: Dict) -> str:
    lines: List[str] = []
    scenarios = summary.get("scenarios", [])
    per_scenario = summary.get("per_scenario", {})
    aggregate = summary.get("evaluation", {}).get("aggregate", {})
    macro = summary.get("evaluation", {}).get("macro_per_scenario", {})

    lines.append("IDS Experiment Report")
    lines.append("=" * 21)
    lines.append("")
    lines.append("Scenario Guide")
    lines.append("-")
    for scenario in scenarios:
        label = SCENARIO_LABELS.get(scenario, scenario)
        detail = SCENARIO_DETAILS.get(scenario, "No description available.")
        lines.append(f"- {label}: {detail}")

    lines.append("")
    lines.append("Per-Scenario Metrics")
    lines.append("-")

    scenario_rows: List[List[str]] = []
    for scenario in scenarios:
        label = SCENARIO_LABELS.get(scenario, scenario)
        s = per_scenario.get(scenario, {})
        ev = s.get("evaluation", {})
        resource = s.get("resource_sample", {})
        scenario_rows.append(
            [
                label,
                str(s.get("events", "-")),
                str(s.get("detections", "-")),
                str(s.get("alerts", "-")),
                _fmt_metric(float(ev.get("precision", 0.0))),
                _fmt_metric(float(ev.get("recall", 0.0))),
                _fmt_metric(float(ev.get("f1_score", 0.0))),
                _fmt_metric(float(ev.get("false_positive_rate", 0.0))),
                _fmt_metric(float(ev.get("false_negative_rate", 0.0))),
                _fmt_metric(float(s.get("latency_ms", 0.0))),
                _fmt_metric(float(resource.get("cpu_percent", 0.0))),
                _fmt_metric(float(resource.get("memory_mb", 0.0))),
            ]
        )

    lines.append(
        _build_table(
            [
                "Scenario",
                "Events",
                "Detections",
                "Alerts",
                "Precision",
                "Recall",
                "F1",
                "FPR",
                "FNR",
                "Latency(ms)",
                "CPU%",
                "Memory(MB)",
            ],
            scenario_rows,
        )
    )

    lines.append("")
    lines.append("Overall Summary")
    lines.append("-")
    summary_rows = [
        ["Total scenarios", str(len(scenarios))],
        ["Total alerts", str(summary.get("total_alerts", 0))],
        ["Aggregate precision (label coverage)", _fmt_metric(float(aggregate.get("precision", 0.0)))],
        ["Aggregate recall (label coverage)", _fmt_metric(float(aggregate.get("recall", 0.0)))],
        ["Aggregate F1 (label coverage)", _fmt_metric(float(aggregate.get("f1_score", 0.0)))],
        ["Aggregate FPR", _fmt_metric(float(aggregate.get("false_positive_rate", 0.0)))],
        ["Aggregate FNR", _fmt_metric(float(aggregate.get("false_negative_rate", 0.0)))],
        ["Macro precision (avg over scenarios)", _fmt_metric(float(macro.get("precision", 0.0)))],
        ["Macro recall (avg over scenarios)", _fmt_metric(float(macro.get("recall", 0.0)))],
        ["Macro F1 (avg over scenarios)", _fmt_metric(float(macro.get("f1_score", 0.0)))],
        ["Macro FPR (avg over scenarios)", _fmt_metric(float(macro.get("false_positive_rate", 0.0)))],
        ["Macro FNR (avg over scenarios)", _fmt_metric(float(macro.get("false_negative_rate", 0.0)))],
        ["Average latency (ms)", _fmt_metric(float(aggregate.get("avg_latency_ms", 0.0)))],
    ]
    lines.append(_build_table(["Metric", "Value"], summary_rows))

    lines.append("")
    lines.append("Interpretation Notes")
    lines.append("-")
    lines.append("- Baseline precision/recall/F1 can be 0.000 when no positive labels are expected and none are predicted.")
    lines.append("- Aggregate metrics use union-style label coverage across all scenarios, so they can be 1.000 even if some single scenarios are imperfect.")
    lines.append("- Macro metrics are the average of per-scenario scores and better reflect scenario-wise consistency.")
    lines.append("")
    lines.append("Detailed machine-readable output is still saved to outputs/summary.json.")
    return "\n".join(lines)


def resource_sample() -> Dict[str, float]:
    if not psutil:
        return {"cpu_percent": -1.0, "memory_mb": -1.0}

    proc = psutil.Process()
    return {
        "cpu_percent": psutil.cpu_percent(interval=0.1),
        "memory_mb": proc.memory_info().rss / (1024 * 1024),
    }


def run(selected: List[str], seed: int, out_dir: Path) -> Dict:
    simulator = AttackSimulator(seed=seed)
    scenarios = scenario_catalog(simulator)

    out_dir.mkdir(parents=True, exist_ok=True)

    all_alerts = []
    all_latencies = []
    scenario_evals = []
    per_scenario = {}

    for name in selected:
        if name not in scenarios:
            raise ValueError(f"unknown scenario: {name}")

        # Keep each scenario independent to match assignment experiment workflow.
        engine = IDSEngine()

        flows, host_logs, extras = scenarios[name]()
        result = engine.process_batch(flows, host_logs, extras)

        # Append only alerts generated in this scenario after dedup/cooldown.
        scenario_alerts = result.alerts
        all_alerts.extend(scenario_alerts)
        all_latencies.append(result.processing_latency_ms)

        scenario_eval = compute_eval(
            scenario_alerts,
            expected_labels_for(name),
            [result.processing_latency_ms],
        )
        scenario_evals.append(scenario_eval)

        per_scenario[name] = {
            "events": len(result.events),
            "detections": len(result.detections),
            "alerts": len(scenario_alerts),
            "latency_ms": round(result.processing_latency_ms, 3),
            "resource_sample": resource_sample(),
            "evaluation": asdict(scenario_eval),
        }

        AlertManager.export_jsonl(scenario_alerts, out_dir / f"alerts_{name}.jsonl")

    expected = []
    for name in selected:
        expected.extend(expected_labels_for(name))

    eval_result = compute_eval(all_alerts, expected, all_latencies)
    if scenario_evals:
        macro_eval = {
            "precision": sum(e.precision for e in scenario_evals) / len(scenario_evals),
            "recall": sum(e.recall for e in scenario_evals) / len(scenario_evals),
            "f1_score": sum(e.f1_score for e in scenario_evals) / len(scenario_evals),
            "false_positive_rate": sum(e.false_positive_rate for e in scenario_evals) / len(scenario_evals),
            "false_negative_rate": sum(e.false_negative_rate for e in scenario_evals) / len(scenario_evals),
            "avg_latency_ms": sum(e.avg_latency_ms for e in scenario_evals) / len(scenario_evals),
        }
    else:
        macro_eval = {
            "precision": 0.0,
            "recall": 0.0,
            "f1_score": 0.0,
            "false_positive_rate": 0.0,
            "false_negative_rate": 0.0,
            "avg_latency_ms": 0.0,
        }

    summary = {
        "scenarios": selected,
        "seed": seed,
        "per_scenario": per_scenario,
        "evaluation": {
            "aggregate": asdict(eval_result),
            "macro_per_scenario": macro_eval,
        },
        "total_alerts": len(all_alerts),
    }

    with (out_dir / "summary.json").open("w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2)

    return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run IDS experiments")
    parser.add_argument(
        "--scenarios",
        nargs="+",
        default=[
            "baseline",
            "bruteforce",
            "portscan_fast",
            "portscan_slow",
            "replay",
            "noise",
            "sensor_failure",
        ],
        help="Scenario names to execute in order",
    )
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--out", type=Path, default=Path("outputs"))
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    summary = run(args.scenarios, args.seed, args.out)
    print(format_report(summary))


if __name__ == "__main__":
    main()
