"""
OpsBot Dashboard — Streamlit-based monitoring dashboard.

Real-time system metrics with gauges, charts, and alert history.
Run with: streamlit run opsbot/dashboard.py
"""

import os
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional

import streamlit as st
import psutil

from opsbot.config import OpsBotConfig
from opsbot.monitor import SystemMonitor, MetricSnapshot
from opsbot.log_analyzer import LogAnalyzer
from opsbot.diagnostic import DiagnosticEngine
from opsbot.alerts import AlertManager


def create_gauge(value: float, label: str, max_val: float = 100.0, threshold: float = 80.0) -> None:
    """Render a colored metric gauge."""
    color = "green" if value < threshold * 0.7 else "orange" if value < threshold else "red"
    st.metric(
        label=label,
        value=f"{value:.1f}%",
        delta=f"{'⚠️ HIGH' if value >= threshold else '✅ OK'}",
        delta_color="inverse" if value >= threshold else "normal",
    )


def render_metric_cards(snapshot: MetricSnapshot) -> None:
    """Render the top metric cards."""
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        color = "normal" if snapshot.cpu_percent < 90 else "inverse"
        st.metric("🖥️ CPU", f"{snapshot.cpu_percent:.1f}%", f"{snapshot.cpu_count} cores")

    with col2:
        st.metric("🧠 Memory", f"{snapshot.memory_percent:.1f}%",
                   f"{snapshot.memory_used_gb:.1f}/{snapshot.memory_total_gb:.1f} GB")

    with col3:
        worst_disk = max(snapshot.disk_partitions, key=lambda d: d["percent"]) if snapshot.disk_partitions else None
        if worst_disk:
            st.metric("💾 Disk (worst)", f"{worst_disk['percent']:.1f}%",
                       worst_disk["mountpoint"])

    with col4:
        st.metric("📊 Load (1m)", f"{snapshot.load_avg_1m:.2f}",
                   f"5m: {snapshot.load_avg_5m:.2f}")


def render_disk_table(snapshot: MetricSnapshot) -> None:
    """Render disk partition table."""
    if not snapshot.disk_partitions:
        return

    st.subheader("💾 Disk Partitions")
    for disk in snapshot.disk_partitions:
        col1, col2, col3 = st.columns([3, 1, 1])
        with col1:
            st.text(f"{disk['mountpoint']} ({disk['device']})")
        with col2:
            st.progress(disk["percent"] / 100)
        with col3:
            st.text(f"{disk['percent']:.1f}% ({disk['used_gb']:.1f}/{disk['total_gb']:.1f} GB)")


def render_docker_table(snapshot: MetricSnapshot) -> None:
    """Render Docker container status."""
    if not snapshot.docker_containers:
        st.info("No Docker containers found.")
        return

    st.subheader("🐳 Docker Containers")
    for container in snapshot.docker_containers:
        status = container.get("status", "unknown")
        icon = "🟢" if "Up" in status else "🔴"
        st.text(f"{icon} {container.get('name', '?')} — {status} [{container.get('image', '?')}]")


def render_alerts(snapshot: MetricSnapshot) -> None:
    """Render active alerts."""
    if not snapshot.alerts:
        st.success("✅ No active alerts")
        return

    st.error(f"🚨 {len(snapshot.alerts)} Active Alert(s)")
    for alert in snapshot.alerts:
        st.warning(alert)


def render_uptime(seconds: float) -> str:
    """Format uptime seconds into human-readable string."""
    days = int(seconds // 86400)
    hours = int((seconds % 86400) // 3600)
    minutes = int((seconds % 3600) // 60)
    parts = []
    if days > 0:
        parts.append(f"{days}d")
    if hours > 0:
        parts.append(f"{hours}h")
    parts.append(f"{minutes}m")
    return " ".join(parts)


def main():
    """Main dashboard entry point."""
    st.set_page_config(
        page_title="OpsBot Dashboard",
        page_icon="🤖",
        layout="wide",
    )

    st.title("🤖 OpsBot — System Dashboard")
    st.caption(f"Last updated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")

    # Initialize
    config = OpsBotConfig.from_env()
    monitor = SystemMonitor(config.monitor)

    # Sidebar
    with st.sidebar:
        st.header("⚙️ Settings")
        auto_refresh = st.checkbox("Auto-refresh", value=True)
        refresh_interval = st.slider("Refresh interval (sec)", 5, 60, 15)

        st.divider()
        st.header("ℹ️ System Info")
        st.text(f"Hostname: {os.uname().nodename}")
        st.text(f"Platform: {os.uname().system} {os.uname().release}")
        st.text(f"CPUs: {psutil.cpu_count()}")

    # Collect metrics
    snapshot = monitor.collect()
    uptime = render_uptime(snapshot.uptime_seconds)

    # Uptime bar
    st.info(f"⏱️ Uptime: {uptime}")

    # Metric cards
    render_metric_cards(snapshot)

    st.divider()

    # Two-column layout
    col_left, col_right = st.columns(2)

    with col_left:
        render_disk_table(snapshot)
        st.divider()
        render_docker_table(snapshot)

    with col_right:
        render_alerts(snapshot)

        st.divider()
        st.subheader("📈 Network I/O")
        net = snapshot.network_io
        if net:
            st.text(f"Sent: {net.get('bytes_sent', 0) / (1024**2):.1f} MB")
            st.text(f"Received: {net.get('bytes_recv', 0) / (1024**2):.1f} MB")

        st.divider()
        st.subheader("📊 Load Average History")
        history = monitor.get_history(last_n=20)
        if history:
            load_data = {
                "1m": [h.load_avg_1m for h in history],
                "5m": [h.load_avg_5m for h in history],
                "15m": [h.load_avg_15m for h in history],
            }
            st.line_chart(load_data)

    # Auto-refresh
    if auto_refresh:
        time.sleep(refresh_interval)
        st.rerun()


if __name__ == "__main__":
    main()
