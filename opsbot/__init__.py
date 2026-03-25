"""
OpsBot — AI-powered DevOps automation.

Server monitoring, root cause analysis, auto-remediation via YAML playbooks.
"""

__version__ = "0.1.0"
__author__ = "Kynareth01"

from opsbot.monitor import SystemMonitor
from opsbot.log_analyzer import LogAnalyzer
from opsbot.diagnostic import DiagnosticEngine
from opsbot.remediator import RemediationEngine
from opsbot.playbook import PlaybookRunner
from opsbot.alerts import AlertManager

__all__ = [
    "SystemMonitor",
    "LogAnalyzer",
    "DiagnosticEngine",
    "RemediationEngine",
    "PlaybookRunner",
    "AlertManager",
]
