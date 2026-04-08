# Security Design Documentation

## Executive Summary

This IDS implements a **multi-source correlation approach** to detect attacks with high confidence and low false positive rates. Core security principles include:

1. **Evidence from multiple independent sources** must agree for high-severity alerts
2. **Deterministic + statistical detection** combines rule-based patterns with anomaly detection
3. **Severity gating** prevents single-source evidence from escalating to Critical
4. **Alert flood protection** via deduplication and cooldown windows
5. **Modular, validated architecture** with unified event schema and strict type enforcement

---

## Security Objectives

1. **High-confidence detection**: Combine weak signals from network and host sensors into stronger evidence
2. **Minimize false positives**: Use structured severity scoring and multi-source gating to avoid alert fatigue
3. **Resilience under adversity**: Operate gracefully when traffic is noisy or sensors are partially degraded
4. **Auditability**: Maintain complete audit trail of events, detections, and alerts in structured format
5. **Reproducibility**: Enable repeatable experiments with fixed random seeds for consistent evaluation

---

## Core Design Principles

### 1. Unified Event Schema (Defense Against Parser Drift)

**Problem**: Different sensors emitting events in different formats leads to inconsistent rule logic and missed attacks.

**Solution**: 
- Single immutable Event dataclass defined in `schema.py`
- All sensors (network, host, system, simulator) normalize to this schema
- Strict validation at sensor output points (raises ValueError on invalid events)
- Schema includes: event_id, timestamp, source, category, subject, src_ip, dst_ip, src_port, dst_port, protocol, outcome, metadata

**Benefit**: Any rule logic written for Events is guaranteed consistent across all sources.

### 2. Multi-source Correlation with Time-Window Awareness

**Problem**: Single-source evidence is weak (can be spoofed or coincidental); multiple independent sources agreeing is much stronger.

**Solution**:
- CorrelationEngine maintains a sliding 30-second event window (configurable)
- Events are sorted by timestamp, with old events automatically evicted
- Detections grouped by subject (user/IP), with distinct_sources tracked
- Evidence from ≥2 independent sources within the window receives +10 bonus points

**Formula**:
```
total_score = sum(detection_scores) + (10 if len(distinct_sources) >= 2 else 0)
```

**Example**:
- Network sensor detects fast port scan (50 points)
- Host sensor detects multiple failed logins (45 points)
- Within 30 seconds, correlated as single alert with score 50 + 45 + 10 = 105 → Critical
- If only one source detected it: 50 points → Medium

### 3. Critical Alert Guardrail (Multi-source Consensus)

**Problem**: Attackers may trigger isolated signals to confuse single-source detectors.

**Solution**: Critical severity (score ≥90) **requires one of**:
1. Evidence from ≥2 distinct independent sources, **OR**
2. Deterministic strong multi-step attack pattern (Rule R4 with score ≥75)

**Enforcement Logic** (in `correlation.py` lines 50-58):
```python
is_strong_multistep = any(det.rule_id == "R4_MULTI_STEP" and det.score >= 75 for det in group)
if severity == "critical" and len(distinct_sources) < 2 and not is_strong_multistep:
    severity = "high"  # Cap to High
    total_score = min(total_score, config.severity_weights["high"])
```

**Rationale**: 
- Requires attacker to succeed on multiple attack vectors simultaneously (expensive)
- Prevents false positives from accidental single-source findings
- Multi-step attacks (failed logins + post-breach process execution) allowed as exception (high confidence)

### 4. Severity Scoring Framework

**Score Mapping**:
| Level | Min Score | Max Score | Interpretation |
|-------|-----------|-----------|----------------|
| Critical | 90 | ∞ | Very high confidence; multi-source or deterministic attack pattern |
| High | 70 | 89 | Single strong attack signal or weak multi-source evidence |
| Medium | 45 | 69 | Moderate confidence; typical rule match or anomaly |
| Low | 25 | 44 | Low confidence; weak signals, sensor issues |
| Info | 10 | 24 | Informational only; background noise or system events |

**Each Detection Contributes**:
- R1_BRUTE_FORCE: 45 points (host source)
- R2_FAST_SCAN: 50 points (network source)
- R3_SLOW_SCAN: 42 points (network source)
- R4_MULTI_STEP: 75 points (host source; deterministic)
- R5_REPLAY: 40 points (network source)
- R6_NOISE_MASKING: 55 points (simulator source)
- R7_SENSOR_DOWN: 35 points (system source; low alert)
- ANOM_RATE: 38 points (statistical)
- ANOM_FAIL: 38 points (statistical)

### 5. Alert Deduplication & Cooldown (Flood Protection)

**Problem**: Same attack can generate many alerts in succession, causing alert fatigue.

**Solution** (in `alert_manager.py`):
- Alert signature = (subject, title, severity) tuple
- Maintain `last_alert_at[signature]` timestamps
- Suppress alert if same signature fired within 20-second cooldown window

**Example**:
```
Time 0s:   Brute-force on user 'admin' → Alert 1 (SENT)
Time 5s:   Brute-force on user 'admin' → Alert 2 (SUPPRESSED, within 20s cooldown)
Time 25s:  Brute-force on user 'admin' → Alert 3 (SENT, cooldown expired)
```

**Benefit**: Prevents thousands of redundant alerts; preserves important first alert + resurgence notifications.

---

## Detection Rules (9 Total)

### Rule R1: Brute-force Login Attempts
- **Source**: Host logs
- **Trigger**: ≥5 failed login attempts from same (src_ip, user) in window
- **Score**: 45 (Medium)
- **Code**: `rules.py:34-55`
- **Evasion risk**: Low (easy to detect if not spoofed)
- **False positive risk**: Medium (legitimate auth failures possible under slow brute-force)

### Rule R2: Fast Port Scanning
- **Source**: Network flows
- **Trigger**: Same src_ip touches ≥20 distinct dst_ports in window
- **Score**: 50 (Medium)
- **Code**: `rules.py:57-82`
- **Evasion risk**: High (can be slowed down via time gaps)
- **False positive risk**: Low (legitimate services rarely probe 20+ ports rapidly)

### Rule R3: Slow Port Scanning
- **Source**: Network flows
- **Trigger**: Same src_ip touches ≥12 distinct ports with ≥12 flows, avg inter-arrival gap ≥1.0s
- **Score**: 42 (Medium)
- **Code**: `rules.py:84-114`
- **Rationale**: Adds time-gap requirement to catch distributed/stealthy scans
- **False positive risk**: Low (legitimate inter-service flows unlikely to have such patterns)

### Rule R4: Multi-step Intrusion Behavior
- **Source**: Host logs (both sides)
- **Trigger**: Same user with ≥3 failed logins AND suspicious process (nc, ncat, powershell, python) in window
- **Score**: 75 (High)
- **Code**: `rules.py:116-145`
- **Exception**: Bypasses multi-source gating; alone can trigger Critical
- **Rationale**: Indicates attacker moved from reconnaissance (failed logins) to post-breach actions
- **False positive risk**: Low (legitimate failed logins + shell execution rare together)

### Rule R5: Replay Attack
- **Source**: Network flows
- **Trigger**: Identical flow signature (src_ip, dst_ip, dst_port, packet_count) repeated ≥4 times
- **Score**: 40 (Medium)
- **Code**: `rules.py:147-178`
- **Evasion risk**: Medium (can vary packet counts slightly)
- **False positive risk**: Medium (some protocols send identical flows, e.g., keepalives)

### Rule R6: Noise-Assisted Obfuscation
- **Source**: Simulator (synthetic) + network/host events
- **Trigger**: ≥10 noise events AND ≥8 suspicious events (scan_hint or failed outcome) in window
- **Score**: 55 (Medium)
- **Code**: `rules.py:180-201`
- **Rationale**: Detects adversary strategy of hiding attacks in traffic noise
- **False positive risk**: Low (legitimate background noise + suspicious activity rare)

### Rule R7: Sensor Failure/Outage
- **Source**: System events
- **Trigger**: Any sensor_status event with status="down"
- **Score**: 35 (Low)
- **Code**: `rules.py:203-223`
- **Rationale**: Alerts operator to monitoring degradation; critical for SLA/compliance
- **False positive risk**: None (sensor down is deterministic)

### Rule ANOM_RATE: Network Rate Spike
- **Source**: System (statistical)
- **Trigger**: Flow count z-score ≥2.2 for any subject (src_ip)
- **Score**: 38 (Medium)
- **Code**: `anomaly.py:41`
- **Baseline**: 50-event sliding history; requires ≥5 values before triggering
- **Formula**: `z = (current_count - mean) / (stdev + 1e-6)`
- **Evasion risk**: Medium (gradual increase avoids spike)
- **False positive risk**: Medium (legitimate traffic bursts possible)

### Rule ANOM_FAIL: Failed Login Spike
- **Source**: System (statistical)
- **Trigger**: Failed login count z-score ≥2.2 for any subject (user)
- **Score**: 38 (Medium)
- **Code**: `anomaly.py:42`
- **Baseline**: 50-event sliding history; requires ≥5 values before triggering
- **Formula**: `z = (current_count - mean) / (stdev + 1e-6)`
- **Evasion risk**: Medium (slow brute-force avoids z-score threshold)
- **False positive risk**: High (legitimate password failures after OS updates; typos by users)

---

## Threat Model

### Threats Covered

1. **Brute-force Login Attacks**
   - Attacker: Repeated failed login attempts to crack credentials
   - Detection: R1 + multi-source correlation with R4
   - Confidence: High

2. **Port Scanning (Reconnaissance)**
   - Fast variant: Rapid probing to enumerate open services
   - Slow variant: Stealthy probing with time gaps to avoid threshold triggers
   - Detection: R2 (fast), R3 (slow) + network source
   - Confidence: High for fast; Medium-High for slow

3. **Replay Attacks**
   - Attacker: Repeats previously-captured flow to replay sessions or transactions
   - Detection: R5 (identical flow signature matching)
   - Confidence: Medium (legitimate protocols may have repeats)

4. **Noise-Assisted Evasion**
   - Attacker: Floods network with noise events to mask malicious activity
   - Detection: R6 (co-occurrence of noise + suspicious events)
   - Confidence: Medium-High

5. **Sensor Degradation / Outage**
   - Attacker: Attempts to disable or overwhelm monitoring sensors
   - Detection: R7 (sensor_status events)
   - Confidence: High (deterministic)

### Threats NOT Covered

1. **Distributed Attacks**: Events from multiple coordinated sources are not correlated
2. **Protocol Exploits**: Deep packet inspection not performed; payload-based attacks invisible
3. **Insider Threats**: Trusted user malfeasance not distinguished from legitimate activity
4. **DDoS Amplification**: Volume-based attacks not explicitly modeled
5. **Compromised System**: If entire host compromised, sensor logs become untrustworthy

### Assumptions

1. **Sensors are trustworthy**: Assume network/host sensors cannot be spoofed or modified
2. **Timestamps are accurate**: Rely on correct NTP sync for time-window correlation
3. **Limited attacker capability**: Assume attacker cannot maintain simultaneous attacks on multiple vectors
4. **Local/lab environment**: Design for single-machine, localhost-only scenarios; not production-grade
5. **Synthetic data acceptable**: Host logs are simulated; acceptable for lab/research

---

## Limitations & Future Improvements

### Current Limitations

1. **Flow-level analysis only**: No deep packet inspection; can miss payload-encoded attacks
2. **Synthetic host logs**: Real-world logs have different distributions, patterns
3. **Single-host scope**: No multi-host correlation or cross-machine pattern detection
4. **Lightweight statistics**: Z-score detector is basic; may miss subtle anomalies or have high false positive rate in heterogeneous environments
5. **No feedback loop**: System does not learn from false positives
6. **Hardcoded thresholds**: Rule triggers (e.g., ≥5 failed logins, ≥20 ports) are tuned for synthetic data; may not generalize
7. **No threat intelligence**: No external feeds (e.g., known malicious IPs, CVE databases)

### Future Improvements

1. **Machine learning**: Train anomaly models on real host/network data for better precision
2. **Multi-host correlation**: Correlate events across multiple machines to detect coordinated attacks
3. **Adaptive thresholds**: Learn detection thresholds dynamically from environment
4. **Feedback integration**: Adjust scoring when alerts are confirmed true/false positives
5. **Real-time compliance**: Integrate with SIEM/log aggregation platforms (Splunk, ELK)
6. **Attack graph reasoning**: Model multi-step attacks as graph traversal to detect attack progressions
7. **Explainability**: Provide human-readable explanations for each alert (why did this trigger?)

---

## Testing & Validation Strategy

### Scenarios

1. **Baseline (Benign)**: 50 normal flows + logins; expect 0 alerts
2. **Brute-force**: 8 failed logins + process execution; expect 2 alerts (R1 + R4)
3. **Port Scan (Fast)**: 30 ports in 3 seconds; expect 1 alert (R2)
4. **Port Scan (Slow)**: 30 ports with 1.4s gaps; expect 1 alert (R3) + false positive (R2)
5. **Replay Attack**: 6 identical flows; expect 1 alert (R5)
6. **Noise Injection**: 25 noise events + 10 suspicious flows; expect 1 alert (R6)
7. **Sensor Failure**: Single sensor_status=down event; expect 1 alert (R7)

### Metrics

- **Precision**: TP / (TP + FP) — should be ≥0.9 for attacks
- **Recall**: TP / (TP + FN) — should be 1.0 (no missed attacks in test scenarios)
- **FPR**: FP / (FP + TN) — should be 0.0 for baseline
- **FNR**: FN / (FN + TP) — should be 0.0 for all attacks
- **Latency**: <2ms per scenario for real-time responsiveness

---

## Compliance & Documentation

This system serves as a proof-of-concept for:
- **NIST Cybersecurity Framework** (Detect function)
- **CIS Controls** (logging/monitoring best practices)
- **ISO 27035** (incident response capability)

---

## Conclusion

This IDS demonstrates how lightweight multi-source correlation can achieve high detection confidence with low false positives. By enforcing evidence from multiple independent sources for critical alerts, the system resists single-vector evasion while remaining responsive to genuine multi-stage attacks.
