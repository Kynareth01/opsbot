"""
OpsBot configuration loader.

Loads config from environment variables and optional YAML config file.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml


@dataclass
class MonitorConfig:
    """Configuration for system monitoring."""
    cpu_threshold: float = 90.0
    memory_threshold: float = 85.0
    disk_threshold: float = 90.0
    load_threshold: float = 10.0
    check_interval: int = 30  # seconds
    docker_enabled: bool = True


@dataclass
class AlertConfig:
    """Configuration for alert channels."""
    slack_webhook: Optional[str] = None
    discord_webhook: Optional[str] = None
    telegram_bot_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None
    pagerduty_token: Optional[str] = None
    pagerduty_service_id: Optional[str] = None


@dataclass
class LogConfig:
    """Configuration for log analysis."""
    log_paths: list = field(default_factory=lambda: [
        "/var/log/syslog",
        "/var/log/auth.log",
        "/var/log/kern.log",
    ])
    error_patterns: list = field(default_factory=lambda: [
        r"OOM|out of memory",
        r"segfault|segmentation fault",
        r"disk\s*(full|space|usage)",
        r"killed process",
        r"error|critical|fatal",
    ])
    tail_lines: int = 1000
    analysis_interval: int = 60  # seconds


@dataclass
class RemediationConfig:
    """Configuration for auto-remediation."""
    enabled: bool = True
    dry_run: bool = False
    max_actions_per_hour: int = 10
    playbook_dir: str = "playbooks"


@dataclass
class OpsBotConfig:
    """Top-level OpsBot configuration."""
    monitor: MonitorConfig = field(default_factory=MonitorConfig)
    alerts: AlertConfig = field(default_factory=AlertConfig)
    logs: LogConfig = field(default_factory=LogConfig)
    remediation: RemediationConfig = field(default_factory=RemediationConfig)
    log_level: str = "INFO"

    @classmethod
    def from_file(cls, path: str) -> "OpsBotConfig":
        """Load config from a YAML file, with env var overrides."""
        config_path = Path(path)
        if not config_path.exists():
            return cls.from_env()

        with open(config_path) as f:
            data = yaml.safe_load(f) or {}

        config = cls()

        if "monitor" in data:
            for k, v in data["monitor"].items():
                if hasattr(config.monitor, k):
                    setattr(config.monitor, k, v)

        if "alerts" in data:
            for k, v in data["alerts"].items():
                if hasattr(config.alerts, k):
                    setattr(config.alerts, k, v)

        if "logs" in data:
            for k, v in data["logs"].items():
                if hasattr(config.logs, k):
                    setattr(config.logs, k, v)

        if "remediation" in data:
            for k, v in data["remediation"].items():
                if hasattr(config.remediation, k):
                    setattr(config.remediation, k, v)

        # Env overrides
        config._apply_env_overrides()
        return config

    @classmethod
    def from_env(cls) -> "OpsBotConfig":
        """Create config purely from environment variables."""
        config = cls()
        config._apply_env_overrides()
        return config

    def _apply_env_overrides(self):
        """Override config values with environment variables."""
        self.alerts.slack_webhook = os.getenv("OPSBOT_SLACK_WEBHOOK", self.alerts.slack_webhook)
        self.alerts.discord_webhook = os.getenv("OPSBOT_DISCORD_WEBHOOK", self.alerts.discord_webhook)
        self.alerts.telegram_bot_token = os.getenv("OPSBOT_TELEGRAM_BOT_TOKEN", self.alerts.telegram_bot_token)
        self.alerts.telegram_chat_id = os.getenv("OPSBOT_TELEGRAM_CHAT_ID", self.alerts.telegram_chat_id)
        self.alerts.pagerduty_token = os.getenv("OPSBOT_PAGERDUTY_TOKEN", self.alerts.pagerduty_token)
        self.alerts.pagerduty_service_id = os.getenv("OPSBOT_PAGERDUTY_SERVICE_ID", self.alerts.pagerduty_service_id)

        if val := os.getenv("OPSBOT_CPU_THRESHOLD"):
            self.monitor.cpu_threshold = float(val)
        if val := os.getenv("OPSBOT_MEMORY_THRESHOLD"):
            self.monitor.memory_threshold = float(val)
        if val := os.getenv("OPSBOT_DISK_THRESHOLD"):
            self.monitor.disk_threshold = float(val)
        if val := os.getenv("OPSBOT_LOG_LEVEL"):
            self.log_level = val
        if val := os.getenv("OPSBOT_REMEDIATION_DRY_RUN"):
            self.remediation.dry_run = val.lower() in ("1", "true", "yes")
