"""Rule-based detection module with non-trivial detectors."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Dict, Iterable, List, Set, Tuple

from .models import Detection
from .schema import Event


def _ts(event: Event) -> datetime:
    return datetime.fromisoformat(event.timestamp)


class RuleEngine:
    """Evaluates deterministic security rules over a correlation window."""

    def evaluate(self, events: Iterable[Event]) -> List[Detection]:
        event_list = list(events)
        detections: List[Detection] = []

        detections.extend(self._detect_bruteforce(event_list))
        detections.extend(self._detect_fast_port_scan(event_list))
        detections.extend(self._detect_slow_port_scan(event_list))
        detections.extend(self._detect_process_after_failures(event_list))
        detections.extend(self._detect_replay_traffic(event_list))
        detections.extend(self._detect_noise_obfuscation(event_list))
        detections.extend(self._detect_sensor_failure(event_list))

        return detections

    def _detect_bruteforce(self, events: List[Event]) -> List[Detection]:
        grouped: Dict[Tuple[str, str], List[Event]] = defaultdict(list)
        for event in events:
            if event.category == "login_attempt" and event.outcome == "failed":
                grouped[(event.src_ip or "unknown", event.subject)].append(event)

        out: List[Detection] = []
        for (src_ip, user), samples in grouped.items():
            if len(samples) >= 5:
                out.append(
                    Detection(
                        rule_id="R1_BRUTE_FORCE",
                        title="Repeated failed login attempts",
                        description=f"{len(samples)} failed logins for user={user} from {src_ip}",
                        subject=user,
                        score=45,
                        source="host",
                        event_ids=[e.event_id for e in samples],
                        tags=["bruteforce", "credential"],
                    )
                )
        return out

    def _detect_fast_port_scan(self, events: List[Event]) -> List[Detection]:
        grouped: Dict[str, Set[int]] = defaultdict(set)
        sample_events: Dict[str, List[Event]] = defaultdict(list)

        for event in events:
            if event.category != "network_flow" or not event.src_ip or event.dst_port is None:
                continue
            grouped[event.src_ip].add(event.dst_port)
            sample_events[event.src_ip].append(event)

        out: List[Detection] = []
        for src_ip, ports in grouped.items():
            if len(ports) >= 20:
                out.append(
                    Detection(
                        rule_id="R2_FAST_SCAN",
                        title="Fast port scan suspected",
                        description=f"{src_ip} touched {len(ports)} distinct ports in the active window",
                        subject=src_ip,
                        score=50,
                        source="network",
                        event_ids=[e.event_id for e in sample_events[src_ip]],
                        tags=["scan", "recon"],
                    )
                )
        return out

    def _detect_slow_port_scan(self, events: List[Event]) -> List[Detection]:
        grouped: Dict[str, List[Event]] = defaultdict(list)
        for event in events:
            if event.category == "network_flow" and event.src_ip:
                grouped[event.src_ip].append(event)

        out: List[Detection] = []
        for src_ip, samples in grouped.items():
            ordered = sorted(samples, key=_ts)
            ports = {e.dst_port for e in ordered if e.dst_port is not None}
            if len(ports) < 12 or len(ordered) < 12:
                continue
            # Slow scans typically have wider spacing between attempts.
            deltas = []
            for i in range(1, len(ordered)):
                deltas.append((_ts(ordered[i]) - _ts(ordered[i - 1])).total_seconds())
            avg_gap = sum(deltas) / len(deltas) if deltas else 0
            if avg_gap >= 1.0:
                out.append(
                    Detection(
                        rule_id="R3_SLOW_SCAN",
                        title="Slow port scan pattern",
                        description=f"{src_ip} probed {len(ports)} ports with avg inter-arrival {avg_gap:.2f}s",
                        subject=src_ip,
                        score=42,
                        source="network",
                        event_ids=[e.event_id for e in ordered],
                        tags=["scan", "slow-scan"],
                    )
                )
        return out

    def _detect_process_after_failures(self, events: List[Event]) -> List[Detection]:
        failed_by_user: Dict[str, int] = defaultdict(int)
        suspicious_process_events: Dict[str, List[Event]] = defaultdict(list)

        for event in events:
            if event.category == "login_attempt" and event.outcome == "failed":
                failed_by_user[event.subject] += 1
            if event.category == "process_start":
                process_name = str(event.metadata.get("process") or "")
                if process_name in {"nc", "ncat", "powershell", "python"}:
                    suspicious_process_events[event.subject].append(event)

        out: List[Detection] = []
        for user, process_events in suspicious_process_events.items():
            if failed_by_user[user] >= 3 and process_events:
                out.append(
                    Detection(
                        rule_id="R4_MULTI_STEP",
                        title="Multi-step intrusion behavior",
                        description=(
                            f"user={user} had {failed_by_user[user]} failed logins and then suspicious process execution"
                        ),
                        subject=user,
                        score=75,
                        source="host",
                        event_ids=[e.event_id for e in process_events],
                        tags=["multi-step", "post-auth"],
                    )
                )
        return out

    def _detect_replay_traffic(self, events: List[Event]) -> List[Detection]:
        signatures: Dict[Tuple[str, str, int, int], int] = defaultdict(int)
        sample_events: Dict[Tuple[str, str, int, int], List[Event]] = defaultdict(list)

        for event in events:
            if event.category != "network_flow":
                continue
            key = (
                event.src_ip or "",
                event.dst_ip or "",
                event.dst_port or -1,
                int(event.metadata.get("packet_count", 0)),
            )
            signatures[key] += 1
            sample_events[key].append(event)

        out: List[Detection] = []
        for key, count in signatures.items():
            if count >= 4:
                out.append(
                    Detection(
                        rule_id="R5_REPLAY",
                        title="Replay-like repeated flow signature",
                        description=f"Identical flow signature repeated {count} times",
                        subject=key[0] or "unknown",
                        score=40,
                        source="network",
                        event_ids=[e.event_id for e in sample_events[key]],
                        tags=["replay", "evasion"],
                    )
                )
        return out

    def _detect_noise_obfuscation(self, events: List[Event]) -> List[Detection]:
        noise_events = [e for e in events if e.category == "noise"]
        suspicious_events = [
            e
            for e in events
            if e.category in {"network_flow", "login_attempt", "process_start"}
            and (e.metadata.get("scan_hint") or e.outcome == "failed")
        ]
        if len(noise_events) >= 10 and len(suspicious_events) >= 8:
            return [
                Detection(
                    rule_id="R6_NOISE_MASKING",
                    title="Noise-assisted evasion suspected",
                    description="High background noise observed alongside suspicious activity",
                    subject="environment",
                    score=55,
                    source="simulator",
                    event_ids=[e.event_id for e in noise_events + suspicious_events],
                    tags=["noise", "evasion"],
                )
            ]
        return []

    def _detect_sensor_failure(self, events: List[Event]) -> List[Detection]:
        failure_events = [
            e
            for e in events
            if e.category == "sensor_status" and e.metadata.get("status") == "down"
        ]
        if not failure_events:
            return []

        return [
            Detection(
                rule_id="R7_SENSOR_DOWN",
                title="Sensor availability degraded",
                description=f"{len(failure_events)} sensor-down events observed",
                subject="ids",
                score=35,
                source="system",
                event_ids=[e.event_id for e in failure_events],
                tags=["availability", "sensor"],
            )
        ]
