"""
Remediation Engine — 16 built-in auto-remediation handlers.

Executes corrective actions based on diagnostic findings.
All actions are logged, rate-limited, and support dry-run mode.
"""

import logging
import os
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional

from opsbot.config import RemediationConfig
from opsbot.diagnostic import DiagnosticFinding

logger = logging.getLogger(__name__)


@dataclass
class RemediationAction:
    """Record of a remediation action taken."""
    timestamp: str
    handler_name: str
    category: str
    description: str
    command: str
    success: bool
    output: str = ""
    dry_run: bool = False
    duration_ms: int = 0

    def to_dict(self) -> Dict:
        return {
            "timestamp": self.timestamp,
            "handler": self.handler_name,
            "category": self.category,
            "description": self.description,
            "command": self.command,
            "success": self.success,
            "output": self.output[:500],
            "dry_run": self.dry_run,
            "duration_ms": self.duration_ms,
        }


class RemediationEngine:
    """Executes auto-remediation actions based on diagnostic findings."""

    def __init__(self, config: Optional[RemediationConfig] = None):
        self.config = config or RemediationConfig()
        self._handlers: Dict[str, dict] = {}
        self._history: List[RemediationAction] = []
        self._action_count_window: List[float] = []  # timestamps of recent actions

        # Register built-in handlers
        self._register_builtins()

    def _register_builtins(self):
        """Register the 16 built-in remediation handlers."""
        self.register("clean_old_logs", self._clean_old_logs, categories=["disk"])
        self.register("clean_tmp_files", self._clean_tmp_files, categories=["disk"])
        self.register("clean_docker_images", self._clean_docker_images, categories=["disk", "docker"])
        self.register("clean_docker_volumes", self._clean_docker_volumes, categories=["disk", "docker"])
        self.register("clean_journal_logs", self._clean_journal_logs, categories=["disk"])
        self.register("compress_old_logs", self._compress_old_logs, categories=["disk"])
        self.register("restart_docker_container", self._restart_docker_container, categories=["docker"])
        self.register("restart_failed_service", self._restart_failed_service, categories=["systemd"])
        self.register("kill_zombie_processes", self._kill_zombie_processes, categories=["cpu", "memory"])
        self.register("kill_memory_hogs", self._kill_memory_hogs, categories=["memory"])
        self.register("drop_caches", self._drop_caches, categories=["memory"])
        self.register("resize_swap", self._resize_swap, categories=["memory"])
        self.register("limit_cpu_cgroup", self._limit_cpu_cgroup, categories=["cpu"])
        self.register("block_offending_ip", self._block_offending_ip, categories=["network"])
        self.register("rotate_logs", self._rotate_logs, categories=["disk"])
        self.register("notify_only", self._notify_only, categories=["*"])

        logger.info("Registered %d built-in remediation handlers", len(self._handlers))

    def register(self, name: str, handler: Callable, categories: Optional[List[str]] = None):
        """Register a remediation handler."""
        self._handlers[name] = {
            "fn": handler,
            "categories": categories or [],
        }

    def remediate(self, finding: DiagnosticFinding) -> Optional[RemediationAction]:
        """Execute remediation for a diagnostic finding."""
        if not self.config.enabled:
            logger.info("Remediation disabled — skipping.")
            return None

        if not self._check_rate_limit():
            logger.warning("Rate limit hit (%d/hour). Skipping.", self.config.max_actions_per_hour)
            return None

        # Find matching handler
        handler_name = self._select_handler(finding)
        if not handler_name:
            logger.info("No handler found for: %s (%s)", finding.title, finding.category)
            return None

        return self._execute(handler_name, finding)

    def _select_handler(self, finding: DiagnosticFinding) -> Optional[str]:
        """Select the best handler for a finding."""
        candidates = []
        for name, info in self._handlers.items():
            if finding.category in info["categories"] or "*" in info["categories"]:
                candidates.append(name)

        # Priority ordering
        priority = [
            "clean_old_logs", "clean_tmp_files", "clean_docker_images",
            "clean_docker_volumes", "clean_journal_logs", "compress_old_logs",
            "rotate_logs", "restart_docker_container", "restart_failed_service",
            "kill_zombie_processes", "kill_memory_hogs", "drop_caches",
            "resize_swap", "limit_cpu_cgroup", "block_offending_ip", "notify_only",
        ]

        for name in priority:
            if name in candidates:
                return name

        return candidates[0] if candidates else None

    def _execute(self, handler_name: str, finding: DiagnosticFinding) -> RemediationAction:
        """Execute a handler."""
        now = datetime.now(timezone.utc).isoformat()
        handler_info = self._handlers[handler_name]
        handler_fn = handler_info["fn"]

        start = time.monotonic()
        try:
            result = handler_fn(finding, dry_run=self.config.dry_run)
            duration = int((time.monotonic() - start) * 1000)

            action = RemediationAction(
                timestamp=now,
                handler_name=handler_name,
                category=finding.category,
                description=result.get("description", ""),
                command=result.get("command", ""),
                success=result.get("success", False),
                output=result.get("output", ""),
                dry_run=self.config.dry_run,
                duration_ms=duration,
            )
        except Exception as e:
            duration = int((time.monotonic() - start) * 1000)
            action = RemediationAction(
                timestamp=now,
                handler_name=handler_name,
                category=finding.category,
                description=f"Handler failed: {e}",
                command="",
                success=False,
                output=str(e),
                dry_run=self.config.dry_run,
                duration_ms=duration,
            )
            logger.error("Handler '%s' failed: %s", handler_name, e)

        self._history.append(action)
        self._action_count_window.append(time.time())
        return action

    def _check_rate_limit(self) -> bool:
        """Check if we're within the rate limit."""
        now = time.time()
        # Clean entries older than 1 hour
        self._action_count_window = [t for t in self._action_count_window if now - t < 3600]
        return len(self._action_count_window) < self.config.max_actions_per_hour

    def _run_cmd(self, cmd: str, dry_run: bool = False) -> Dict:
        """Run a shell command (or log it in dry-run mode)."""
        if dry_run:
            return {"success": True, "command": cmd, "output": "[DRY RUN] Command logged but not executed."}

        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
            return {
                "success": result.returncode == 0,
                "command": cmd,
                "output": result.stdout + result.stderr,
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "command": cmd, "output": "Command timed out after 60s"}

    # ─── The 16 Built-in Handlers ───────────────────────────────

    def _clean_old_logs(self, finding: DiagnosticFinding, dry_run: bool = False) -> Dict:
        """Delete log files older than 7 days in /var/log."""
        r = self._run_cmd("find /var/log -name '*.log' -mtime +7 -type f -delete", dry_run)
        r["description"] = "Cleaned log files older than 7 days from /var/log"
        return r

    def _clean_tmp_files(self, finding: DiagnosticFinding, dry_run: bool = False) -> Dict:
        """Delete files in /tmp older than 3 days."""
        r = self._run_cmd("find /tmp -type f -mtime +3 -delete", dry_run)
        r["description"] = "Cleaned temp files older than 3 days from /tmp"
        return r

    def _clean_docker_images(self, finding: DiagnosticFinding, dry_run: bool = False) -> Dict:
        """Remove unused Docker images."""
        r = self._run_cmd("docker image prune -af", dry_run)
        r["description"] = "Pruned unused Docker images"
        return r

    def _clean_docker_volumes(self, finding: DiagnosticFinding, dry_run: bool = False) -> Dict:
        """Remove unused Docker volumes."""
        r = self._run_cmd("docker volume prune -f", dry_run)
        r["description"] = "Pruned unused Docker volumes"
        return r

    def _clean_journal_logs(self, finding: DiagnosticFinding, dry_run: bool = False) -> Dict:
        """Vacuum journald logs to 500MB."""
        r = self._run_cmd("journalctl --vacuum-size=500M", dry_run)
        r["description"] = "Vacuumed journald logs to 500MB"
        return r

    def _compress_old_logs(self, finding: DiagnosticFinding, dry_run: bool = False) -> Dict:
        """Compress uncompressed log files older than 1 day."""
        r = self._run_cmd(
            "find /var/log -name '*.log' -mtime +1 -not -name '*.gz' -exec gzip -9 {} \\;",
            dry_run,
        )
        r["description"] = "Compressed old uncompressed log files"
        return r

    def _restart_docker_container(self, finding: DiagnosticFinding, dry_run: bool = False) -> Dict:
        """Restart exited/dead Docker containers."""
        r = self._run_cmd(
            "docker ps -a --filter 'status=exited' --filter 'status=dead' --format '{{.Names}}' "
            "| xargs -r docker restart",
            dry_run,
        )
        r["description"] = "Restarted exited/dead Docker containers"
        return r

    def _restart_failed_service(self, finding: DiagnosticFinding, dry_run: bool = False) -> Dict:
        """Restart failed systemd services."""
        r = self._run_cmd(
            "systemctl list-units --state=failed --plain --no-legend | awk '{print $1}' | xargs -r systemctl restart",
            dry_run,
        )
        r["description"] = "Restarted failed systemd services"
        return r

    def _kill_zombie_processes(self, finding: DiagnosticFinding, dry_run: bool = False) -> Dict:
        """Kill zombie processes."""
        r = self._run_cmd(
            "ps aux | awk '$8 ~ /Z/ {print $2}' | xargs -r kill -9",
            dry_run,
        )
        r["description"] = "Killed zombie processes"
        return r

    def _kill_memory_hogs(self, finding: DiagnosticFinding, dry_run: bool = False) -> Dict:
        """Kill top memory-consuming non-essential process."""
        r = self._run_cmd(
            "ps aux --sort=-%mem | awk 'NR>1 && $11 !~ /^(sshd|systemd|init|bash)$/ {print $2; exit}' "
            "| xargs -r kill -15",
            dry_run,
        )
        r["description"] = "Sent SIGTERM to top memory-consuming process"
        return r

    def _drop_caches(self, finding: DiagnosticFinding, dry_run: bool = False) -> Dict:
        """Drop kernel caches to free memory."""
        r = self._run_cmd("sync && echo 3 > /proc/sys/vm/drop_caches", dry_run)
        r["description"] = "Dropped kernel page/dentry/inode caches"
        return r

    def _resize_swap(self, finding: DiagnosticFinding, dry_run: bool = False) -> Dict:
        """Create additional swap if none exists."""
        r = self._run_cmd(
            "if ! swapon --show | grep -q '/'; then "
            "fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile; fi",
            dry_run,
        )
        r["description"] = "Ensured 2GB swap file is active"
        return r

    def _limit_cpu_cgroup(self, finding: DiagnosticFinding, dry_run: bool = False) -> Dict:
        """Limit CPU for runaway processes (top CPU consumer)."""
        r = self._run_cmd(
            "ps aux --sort=-%cpu | awk 'NR==2 {print $2}' | xargs -r -I{} sh -c 'cpulimit -p {} -l 50 &'",
            dry_run,
        )
        r["description"] = "Applied 50% CPU limit to top consumer"
        return r

    def _block_offending_ip(self, finding: DiagnosticFinding, dry_run: bool = False) -> Dict:
        """Block IPs with excessive connection attempts via iptables."""
        r = self._run_cmd(
            "netstat -ntu | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | "
            "awk '$1 > 100 {print $2}' | head -5 | xargs -r -I{} iptables -A INPUT -s {} -j DROP",
            dry_run,
        )
        r["description"] = "Blocked IPs with >100 connections via iptables"
        return r

    def _rotate_logs(self, finding: DiagnosticFinding, dry_run: bool = False) -> Dict:
        """Force logrotate."""
        r = self._run_cmd("logrotate -f /etc/logrotate.conf", dry_run)
        r["description"] = "Forced log rotation"
        return r

    def _notify_only(self, finding: DiagnosticFinding, dry_run: bool = False) -> Dict:
        """No-op handler — just notify without taking action."""
        return {
            "success": True,
            "command": "(no action — notification only)",
            "description": f"No automated action for: {finding.title}",
        }

    def get_history(self) -> List[RemediationAction]:
        """Return remediation history."""
        return list(self._history)

    def get_handler_names(self) -> List[str]:
        """Return list of registered handler names."""
        return list(self._handlers.keys())
