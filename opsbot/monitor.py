"""
System Monitor — CPU, memory, disk, load average, Docker container stats.

Collects metrics and detects threshold breaches in real-time.
"""

import json
import logging
import os
import platform
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional

import psutil

from opsbot.config import MonitorConfig

logger = logging.getLogger(__name__)


@dataclass
class MetricSnapshot:
    """Point-in-time system metrics."""
    timestamp: str
    cpu_percent: float
    cpu_count: int
    memory_total_gb: float
    memory_used_gb: float
    memory_percent: float
    disk_partitions: List[Dict]
    load_avg_1m: float
    load_avg_5m: float
    load_avg_15m: float
    uptime_seconds: float
    docker_containers: List[Dict] = field(default_factory=list)
    network_io: Dict = field(default_factory=dict)
    alerts: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "timestamp": self.timestamp,
            "cpu_percent": self.cpu_percent,
            "cpu_count": self.cpu_count,
            "memory": {
                "total_gb": self.memory_total_gb,
                "used_gb": self.memory_used_gb,
                "percent": self.memory_percent,
            },
            "disk_partitions": self.disk_partitions,
            "load_avg": {
                "1m": self.load_avg_1m,
                "5m": self.load_avg_5m,
                "15m": self.load_avg_15m,
            },
            "uptime_seconds": self.uptime_seconds,
            "docker_containers": self.docker_containers,
            "network_io": self.network_io,
            "alerts": self.alerts,
        }


class SystemMonitor:
    """Collects system metrics and raises alerts on threshold breaches."""

    def __init__(self, config: Optional[MonitorConfig] = None):
        self.config = config or MonitorConfig()
        self._alert_callbacks: List[Callable] = []
        self._history: List[MetricSnapshot] = []
        self._max_history = 1000

    def on_alert(self, callback: Callable):
        """Register a callback for threshold breach alerts."""
        self._alert_callbacks.append(callback)

    def collect(self) -> MetricSnapshot:
        """Collect a full metric snapshot."""
        now = datetime.now(timezone.utc).isoformat()
        alerts = []

        # CPU
        cpu_percent = psutil.cpu_percent(interval=1)
        cpu_count = psutil.cpu_count()
        if cpu_percent >= self.config.cpu_threshold:
            alerts.append(f"CPU at {cpu_percent:.1f}% (threshold: {self.config.cpu_threshold}%)")

        # Memory
        mem = psutil.virtual_memory()
        mem_total_gb = mem.total / (1024 ** 3)
        mem_used_gb = mem.used / (1024 ** 3)
        if mem.percent >= self.config.memory_threshold:
            alerts.append(f"Memory at {mem.percent:.1f}% (threshold: {self.config.memory_threshold}%)")

        # Disk
        disk_partitions = []
        for part in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(part.mountpoint)
                pct = usage.percent
                disk_partitions.append({
                    "mountpoint": part.mountpoint,
                    "device": part.device,
                    "fstype": part.fstype,
                    "total_gb": round(usage.total / (1024 ** 3), 2),
                    "used_gb": round(usage.used / (1024 ** 3), 2),
                    "percent": pct,
                })
                if pct >= self.config.disk_threshold:
                    alerts.append(f"Disk {part.mountpoint} at {pct:.1f}% (threshold: {self.config.disk_threshold}%)")
            except PermissionError:
                continue

        # Load average
        load1, load5, load15 = os.getloadavg()
        if load1 >= self.config.load_threshold:
            alerts.append(f"Load avg {load1:.2f} (threshold: {self.config.load_threshold})")

        # Uptime
        uptime = time.time() - psutil.boot_time()

        # Docker
        docker_containers = []
        if self.config.docker_enabled:
            docker_containers = self._get_docker_stats()

        # Network I/O
        net = psutil.net_io_counters()
        network_io = {
            "bytes_sent": net.bytes_sent,
            "bytes_recv": net.bytes_recv,
            "packets_sent": net.packets_sent,
            "packets_recv": net.packets_recv,
        }

        snapshot = MetricSnapshot(
            timestamp=now,
            cpu_percent=cpu_percent,
            cpu_count=cpu_count,
            memory_total_gb=round(mem_total_gb, 2),
            memory_used_gb=round(mem_used_gb, 2),
            memory_percent=mem.percent,
            disk_partitions=disk_partitions,
            load_avg_1m=round(load1, 2),
            load_avg_5m=round(load5, 2),
            load_avg_15m=round(load15, 2),
            uptime_seconds=round(uptime, 0),
            docker_containers=docker_containers,
            network_io=network_io,
            alerts=alerts,
        )

        self._history.append(snapshot)
        if len(self._history) > self._max_history:
            self._history = self._history[-self._max_history:]

        if alerts:
            logger.warning("Threshold alerts: %s", alerts)
            for cb in self._alert_callbacks:
                try:
                    cb(snapshot)
                except Exception as e:
                    logger.error("Alert callback error: %s", e)

        return snapshot

    def _get_docker_stats(self) -> List[Dict]:
        """Get Docker container stats via CLI."""
        try:
            result = subprocess.run(
                ["docker", "ps", "--format", '{"name":"{{.Names}}","status":"{{.Status}}","image":"{{.Image}}","cpu":"{{.CPUPerc}}","mem":"{{.MemUsage}}"}'],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                return []
            containers = []
            for line in result.stdout.strip().split("\n"):
                if line:
                    try:
                        containers.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
            return containers
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []

    def get_history(self, last_n: Optional[int] = None) -> List[MetricSnapshot]:
        """Return metric history."""
        if last_n:
            return self._history[-last_n:]
        return list(self._history)

    def is_healthy(self) -> bool:
        """Quick health check — returns False if any threshold is breached."""
        snapshot = self.collect()
        return len(snapshot.alerts) == 0

    def summary(self) -> Dict:
        """Return a quick summary of the latest snapshot."""
        if not self._history:
            self.collect()
        latest = self._history[-1]
        return {
            "healthy": len(latest.alerts) == 0,
            "cpu": f"{latest.cpu_percent:.1f}%",
            "memory": f"{latest.memory_percent:.1f}%",
            "load_1m": latest.load_avg_1m,
            "disk_alerts": [a for a in latest.alerts if "Disk" in a],
            "containers": len(latest.docker_containers),
            "alerts": latest.alerts,
        }
