# Multi-Source Intrusion Detection System (Lab Assignment 4)

A lightweight, modular Intrusion Detection System (IDS) that correlates evidence from multiple independent sources (network flows and host logs) to detect attacks with high confidence and minimal false positives.

## Team Information

**Team Number**: 5

**Members**:
- Souradeep Das (Roll: 2025201004)
- Kushal Mukherjee (Roll: 2025201072)
- Srinjoy Sengupta (Roll: 2025202010)

## Objectives

1. **Multi-source correlation**: Combine weak signals from network and host sensors into stronger evidence
2. **Robust detection**: Operate gracefully under noisy conditions and partial sensor outages
3. **Controlled false positives**: Use structured severity scoring to avoid alert fatigue
4. **Reproducibility**: Implement attack scenarios that can be repeated for consistent evaluation
5. **Modularity**: Design independent, loosely-coupled components with a unified event schema

## Key Features

- **Multi-source event correlation**: Correlates network flows and host logs within configurable time windows
- **9 detection rules**: 7 deterministic rules + 2 statistical anomaly detectors
- **Severity gating**: Critical alerts only when multiple sources agree (or strong multi-step patterns detected)
- **Sliding time window**: Events processed within 30-second windows for correlation
- **Alert deduplication**: 20-second cooldown prevents recurring alerts on same signature
- **JSON-based schema**: Unified event format enforced across all modules with strict validation
- **Reproducible experiments**: Synthetic attack simulation with configurable seed for consistent results
- **Comprehensive metrics**: Precision, Recall, F1, FPR, FNR, latency, and resource usage tracking

## System Architecture

```
┌───────────────────────────────────────────────────────────────────────────┐
│                    IDSEngine (Orchestrator)             │
├───────────────────────────────────────────────────────────────────────────┤
│                                                         │
│  ┌──────────────────────┐ ┌──────────────────────┐ ┌──────────────────┐ │
│  │Network Sensor│  │ Host Sensor  │  │   Simulator   │ │
│  │ (flow data)  │  │  (host logs) │  │ (attack gen)  │ │
│  └────────┬──────────────┘  └────────┬──────────────┘  └────────┬────────┘ │
│         │                │                   │         │
│         └────────────────────┬─────────────────────────────────┘         │
│                          │ (normalized Events)          │
│                          ▼                             │
│            ┌──────────────────────────────────────────┐             │
│            │ Correlation Engine          │             │
│            │ (sliding 30-sec window)     │             │
│            └────────────────────┬─────────────────────┘             │
│                         │ (windowed Events)            │
│                    ┌─────────┬──────────┐                        │
│                    ▼          ▼                        │
│            ┌──────────────────────┐ ┌──────────────────────┐           │
│            │ Rule Engine  │ │ Anomaly      │           │
│            │ (7 rules)    │ │ Detector     │           │
│            │              │ │ (z-score)    │           │
│            └────────┬──────────────┘ └────────┬────────────┘           │
│                   │                │ (Detections)     │
│                   └────────┬────────┴────────────┘                    │
│                            ▼                           │
│            ┌──────────────────────────────────────────┐                  │
│            │ Severity Scorer        │                  │
│            │ (multi-source bonus)   │                  │
│            └────────────────┬─────────────────────────┘                  │
│                         │ (scored Alerts)             │
│                         ▼                             │
│            ┌──────────────────────────────────────────┐                  │
│            │ Alert Manager          │                  │
│            │ (dedup + cooldown)     │                  │
│            └────────────────┬─────────────────────────┘                  │
│                         │ (final Alerts)              │
│                         ▼                             │
│            ┌──────────────────────────────────────────┐                  │
│            │ JSONL Export + Metrics │                  │
│            └──────────────────────────────────────────┘                  │
│                                                         │
└───────────────────────────────────────────────────────────────────────────┘
```

## Project Structure

```
├── ids/
│   ├── schema.py           # Unified Event dataclass + validation
│   ├── network_sensor.py   # Flow normalization (src_ip, dst_ip, ports, etc.)
│   ├── host_sensor.py      # Host log normalization (logins, processes)
│   ├── rules.py            # 7 deterministic rule detectors
│   ├── anomaly.py          # Z-score anomaly detector for 2 features
│   ├── correlation.py      # Sliding window + severity scoring
│   ├── alert_manager.py    # Deduplication + cooldown + JSONL export
│   ├── engine.py           # Full pipeline orchestration
│   ├── models.py           # Detection and Alert dataclasses
│   ├── config.py           # Configuration defaults
│   ├── metrics.py          # Evaluation metric computation
│   ├── attack_simulator.py # Synthetic scenario generators
│   └── __init__.py
├── run_experiments.py      # Main experiment runner
├── README.md               # This file
├── SECURITY.md             # Security design documentation
```

## Deliverables

The following items are included in this submission:

1. **`ids/` module** — Complete IDS implementation with 12 Python source files
   - Core detection rules, anomaly detection, correlation engine, alert management
   
2. **`run_experiments.py`** — Main experiment runner script
   - Orchestrates all 7 scenarios (baseline, brute-force, port scans, replay, noise, sensor failure)
   - Generates human-readable output reports and JSONL alert files
   
3. **`README.md`** — Comprehensive project documentation
   - Architecture explanation, setup instructions, usage guide, metrics interpretation
   - Complete description of all 9 detection rules and severity levels
   
4. **`SECURITY.md`** — Security design and threat model documentation
   - Core design principles, multi-source correlation strategy, Critical alert guardrail
   - Detailed rule analysis, threat coverage, limitations, and future improvements

## Setup

### Requirements
- Python 3.10+
- No external IDS frameworks (Snort/Suricata)
- No root/admin access needed (localhost-only experiment)

### Installation

```bash
# Create virtual environment
python3 -m venv .venv

# Activate (macOS/Linux)
source .venv/bin/activate
# Or on Windows:
# .venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

### Verify Installation

```bash
python3 verify_metrics.py  # Should show all metrics passing
```

## Running Experiments

### Run all scenarios (default)

```bash
python3 run_experiments.py
```

### Run specific scenarios

```bash
python3 run_experiments.py --scenarios baseline bruteforce portscan_fast noise replay sensor_failure
```

### Run with custom seed for reproducibility

```bash
python3 run_experiments.py --seed 42
```

### Run with custom output directory

```bash
python3 run_experiments.py --out ./my_results
```

## Understanding the Output

When you run `python3 run_experiments.py`, you will see a human-readable report:

### Scenario Guide
Each scenario is described in plain English, explaining what conduct is being simulated.

### Per-Scenario Metrics Table

Columns explained:
- **Events**: Total normalized events ingested in this scenario
- **Detections**: Intermediate detections (before deduplication/cooldown)
- **Alerts**: Final deduplicated alerts sent to output
- **Precision**: TP / (TP + FP) — fraction of predicted labels that were correct
- **Recall**: TP / (TP + FN) — fraction of expected labels that were detected
- **F1**: Harmonic mean of precision and recall
- **FPR**: False Positive Rate — false alarms among negatives
- **FNR**: False Negative Rate — missed attacks among positives
- **Latency(ms)**: Processing time for this scenario
- **CPU%**: CPU utilization peak during processing
- **Memory(MB)**: Memory footprint in megabytes

### Overall Summary

- **Aggregate metrics**: Union-based label coverage across all scenarios (indicates overall completeness)
- **Macro metrics**: Average of per-scenario scores (indicates consistency and reliability)
- **Interpretation notes**: Explains why baseline can show 0.0 precision, and the difference between aggregate/macro

### Output Files

```
outputs/
├── alerts_baseline.jsonl        # No alerts expected
├── alerts_bruteforce.jsonl      # 2 alerts: bruteforce + multi-step
├── alerts_portscan_fast.jsonl   # 1 alert: fast scan
├── alerts_portscan_slow.jsonl   # 1 alert: slow scan
├── alerts_replay.jsonl          # 1 alert: replay
├── alerts_noise.jsonl           # 1 alert: noise masking
├── alerts_sensor_failure.jsonl  # 1 alert: sensor down
└── summary.json                 # Detailed metrics (machine-readable)
```

## Detection Model Equations

The IDS combines deterministic rule detections and statistical anomaly detections.

### 1. Evidence Aggregation Score

For subject $u$ in active time window $t$:

$$
	ext{score}(u,t)=\sum_{e \in E(u,t)} w(e)
$$

Where:
- $E(u,t)$ is the set of detections for subject $u$ within the current window.
- $w(e)$ is the score assigned to detection $e$.

Project-specific source-agreement bonus:

$$
	ext{score}_{\text{final}}(u,t)=\sum w(e)+\mathbb{1}\left[|S(u,t)|\ge2\right]\cdot B
$$

Where:
- $S(u,t)$ is the set of distinct sources producing evidence.
- $B=10$ (configured source bonus).

### 2. Statistical Anomaly (Z-Score)

For feature value $f_t$:

$$
z_f=\frac{f_t-\mu_f}{\sigma_f+\epsilon}
$$

Where:
- $\mu_f$ is baseline mean.
- $\sigma_f$ is baseline standard deviation.
- $\epsilon=10^{-6}$ for numerical stability.

Trigger condition used in implementation:

$$
z_f\ge2.2
$$

with at least 5 baseline observations.

### 3. Severity Mapping

Given final score $s$:

$$
	ext{severity}(s)=
\begin{cases}
	ext{critical}, & s \ge 90 \\
	ext{high}, & 70 \le s < 90 \\
	ext{medium}, & 45 \le s < 70 \\
	ext{low}, & 25 \le s < 45 \\
	ext{info}, & s < 25
\end{cases}
$$

Guardrail:
- Single-source evidence is capped at High.
- Exception: strong deterministic multi-step detection (R4) may remain Critical.

## Detected Attack Patterns

### 1. Brute-force Login Attempts
- **Detection**: ≥5 failed logins from same source IP to same user within the window
- **Severity**: Medium (Rule R1)
- **Multi-step trigger**: Combines with suspicious process execution (nc, ncat, powershell, python) to raise Critical alert (Rule R4)

### 2. Fast Port Scanning
- **Detection**: One source IP touches ≥20 distinct destination ports in the window
- **Severity**: Medium (Rule R2)
- **Rationale**: Rapid port enumeration is characteristic of active reconnaissance

### 3. Slow Port Scanning
- **Detection**: One source IP touches ≥12 distinct ports with ≥12 flows and average inter-arrival gap ≥1.0 second
- **Severity**: Medium (Rule R3)
- **Rationale**: Evades threshold-based detection by spacing probes over time

### 4. Multi-step Intrusion Behavior
- **Detection**: ≥3 failed logins for user + suspicious process execution in same window
- **Severity**: High/Critical (Rule R4)
- **Rationale**: Indicates attacker progressed past initial enumeration to post-breach actions

### 5. Replay Attack
- **Detection**: Identical flow signature (src_ip, dst_ip, dst_port, packet_count) repeated ≥4 times
- **Severity**: Medium (Rule R5)
- **Rationale**: Benign flows have natural variation; exact repetition suggests automated replay

### 6. Noise-Assisted Obfuscation
- **Detection**: ≥10 noise events + ≥8 suspicious events (flagged as scan_hint or failed outcome) in window
- **Severity**: Medium (Rule R6)
- **Rationale**: Adversary overwhelms monitoring with noise to hide malicious traffic

### 7. Sensor Failure/Outage
- **Detection**: Any sensor_status event with status="down"
- **Severity**: Low (Rule R7)
- **Rationale**: Alerts on degraded visibility; critical to detect monitoring gaps

### 8-9. Anomaly Detectors (Statistical)
- **Network Rate Spike**: Flow count z-score ≥2.2 (Rule ANOM_RATE, score 38)
- **Failed Login Spike**: Failed login count z-score ≥2.2 (Rule ANOM_FAIL, score 38)
- **Baseline**: 50-event sliding history; requires ≥5 baseline values before triggering

## Severity Levels

| Level | Score Range | Conditions |
|-------|-------------|------------|
| Critical | ≥90 | Multi-source agreement (≥2 sources) OR strong multi-step rule (R4) |
| High | 70–89 | Strong single-source evidence (e.g., R4 multi-step at ≥75 points) |
| Medium | 45–69 | Multiple rule matches or moderate single-source evidence |
| Low | 25–44 | Minor indicators (e.g., sensor failure, weak anomalies) |
| Info | 10–24 | Informational; low confidence |

## Alert Deduplication

Alerts are deduplicated using a 20-second cooldown window per signature:
- Signature = (subject, title, severity) tuple
- If same signature appears within 20s, subsequent alert is suppressed
- Prevents repetitive firing on ongoing conditions

## Multi-source Correlation & Severity Gating

### Core Rule: Critical Alert Guardrail

**No single-source evidence can trigger Critical, unless:**
1. At least 2 independent evidence sources (network + host) agree within the window, OR
2. A deterministic strong multi-step pattern (Rule R4) is matched with score ≥75

**Rationale**: Reduces false positives and ensures high confidence before escalating to Critical.

### Source Bonus

When ≥2 distinct sources (network, host, system, simulator) detect same subject:
- Add +10 points to final score
- Example: brute-force (host) + scan (network) → 45 + 50 + 10 = 105 (Critical)
- If only one source detected it: 50 points → Medium

## Threat Model & Assumptions

### In Scope
- Brute-force login attacks
- Port scanning (fast and slow variants)
- Replay attacks
- Noise injection for evasion
- Temporary sensor failures
- Adversary with limited capabilities (no system compromise)

## Notes

- **Single-machine design**: All components run on a single host; no distributed setup required
- **Flow-level analysis**: Uses only metadata (IPs, ports, counts); no deep packet inspection
- **Synthetic data**: Host logs are simulated; designed for lab experiments, not production
- **Reproducible**: All randomness seeded for repeatable experiment results
- **Modular & testable**: Each component is independent and unit-testable
