"""Tests for SystemMonitor."""

import pytest
from unittest.mock import patch, MagicMock

from opsbot.monitor import SystemMonitor, MetricSnapshot
from opsbot.config import MonitorConfig


class TestSystemMonitor:
    """Test suite for SystemMonitor."""

    def test_init_default_config(self):
        monitor = SystemMonitor()
        assert monitor.config.cpu_threshold == 90.0
        assert monitor.config.memory_threshold == 85.0

    def test_init_custom_config(self):
        config = MonitorConfig(cpu_threshold=80.0, memory_threshold=75.0)
        monitor = SystemMonitor(config)
        assert monitor.config.cpu_threshold == 80.0

    def test_collect_returns_snapshot(self):
        monitor = SystemMonitor()
        snapshot = monitor.collect()
        assert isinstance(snapshot, MetricSnapshot)
        assert 0 <= snapshot.cpu_percent <= 100
        assert 0 <= snapshot.memory_percent <= 100
        assert snapshot.cpu_count > 0
        assert snapshot.memory_total_gb > 0

    def test_collect_includes_disk(self):
        monitor = SystemMonitor()
        snapshot = monitor.collect()
        assert isinstance(snapshot.disk_partitions, list)
        if snapshot.disk_partitions:
            disk = snapshot.disk_partitions[0]
            assert "mountpoint" in disk
            assert "percent" in disk

    def test_collect_includes_load(self):
        monitor = SystemMonitor()
        snapshot = monitor.collect()
        assert snapshot.load_avg_1m >= 0
        assert snapshot.load_avg_5m >= 0
        assert snapshot.load_avg_15m >= 0

    def test_collect_includes_network(self):
        monitor = SystemMonitor()
        snapshot = monitor.collect()
        assert "bytes_sent" in snapshot.network_io
        assert "bytes_recv" in snapshot.network_io

    def test_collect_stores_history(self):
        monitor = SystemMonitor()
        monitor.collect()
        monitor.collect()
        assert len(monitor.get_history()) == 2

    def test_alert_callback_triggered(self):
        config = MonitorConfig(cpu_threshold=0.0)  # Will always trigger
        monitor = SystemMonitor(config)
        callback = MagicMock()
        monitor.on_alert(callback)
        monitor.collect()
        callback.assert_called_once()

    def test_is_healthy(self):
        monitor = SystemMonitor()
        # Should be healthy on a normal system
        assert isinstance(monitor.is_healthy(), bool)

    def test_summary(self):
        monitor = SystemMonitor()
        summary = monitor.summary()
        assert "healthy" in summary
        assert "cpu" in summary
        assert "memory" in summary

    def test_to_dict(self):
        monitor = SystemMonitor()
        snapshot = monitor.collect()
        d = snapshot.to_dict()
        assert "timestamp" in d
        assert "cpu_percent" in d
        assert "memory" in d

    def test_history_limit(self):
        config = MonitorConfig()
        monitor = SystemMonitor(config)
        monitor._max_history = 5
        for _ in range(10):
            monitor.collect()
        assert len(monitor.get_history()) == 5
