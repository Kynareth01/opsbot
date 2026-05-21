"""
OpsBot Application — main entry point.

Ties together monitoring, analysis, diagnostics, remediation, and alerting
into a continuous loop.
"""

import argparse
import logging
import signal
import sys
import time
from datetime import datetime, timezone

from opsbot.config import OpsBotConfig
from opsbot.monitor import SystemMonitor
from opsbot.log_analyzer import LogAnalyzer
from opsbot.diagnostic import DiagnosticEngine
from opsbot.remediator import RemediationEngine
from opsbot.playbook import PlaybookRunner
from opsbot.alerts import AlertManager, Alert

logger = logging.getLogger("opsbot")


class OpsBot:
    """Main OpsBot application — continuous monitoring loop."""

    def __init__(self, config: OpsBotConfig):
        self.config = config
        self.monitor = SystemMonitor(config.monitor)
        self.log_analyzer = LogAnalyzer(config.logs)
        self.diagnostic = DiagnosticEngine()
        self.remediator = RemediationEngine(config.remediation)
        self.playbook_runner = PlaybookRunner(config.remediation.playbook_dir)
        self.alert_manager = AlertManager(config.alerts)
        self._running = False

        # Wire monitor alerts to alert manager
        self.monitor.on_alert(self._on_monitor_alert)

    def _on_monitor_alert(self, snapshot):
        """Callback when monitor detects threshold breach."""
        alert = Alert(
            title="System Threshold Breach",
            message="\n".join(snapshot.alerts),
            severity="high" if len(snapshot.alerts) > 1 else "medium",
            source="monitor",
        )
        self.alert_manager.send(alert)

    def run_once(self):
        """Run a single monitoring cycle."""
        logger.info("=== Monitoring cycle ===")

        # 1. Collect metrics
        metrics = self.monitor.collect()
        logger.info("Metrics: CPU=%.1f%% MEM=%.1f%% LOAD=%.2f",
                     metrics.cpu_percent, metrics.memory_percent, metrics.load_avg_1m)

        # 2. Analyze logs
        log_result = None
        try:
            results = self.log_analyzer.analyze_all()
            if results:
                log_result = results[0]
                logger.info("Logs: %d errors, %d warnings",
                            log_result.error_count, log_result.warning_count)
        except Exception as e:
            logger.warning("Log analysis failed: %s", e)

        # 3. Diagnose
        report = self.diagnostic.diagnose(metrics, log_result)
        if report.has_issues:
            logger.warning("Diagnostics: %d findings (severity: %s)",
                           len(report.findings), report.severity)

            # 4. Alert on critical
            if report.severity in ("critical", "high"):
                alert = Alert(
                    title=f"OpsBot: {report.severity.upper()} Issue Detected",
                    message=report.incident_summary,
                    severity=report.severity,
                    source="diagnostic",
                    metadata={"root_cause": report.root_cause or "unknown"},
                )
                self.alert_manager.send(alert)

            # 5. Auto-remediate
            if self.config.remediation.enabled:
                for finding in report.findings:
                    if finding.severity in ("high", "critical"):
                        result = self.remediator.remediate(finding)
                        if result:
                            logger.info("Remediation: %s (%s) — %s",
                                        result.handler_name,
                                        "success" if result.success else "failed",
                                        result.description)
        else:
            logger.info("System healthy — no issues detected.")

    def run(self, interval: int = None):
        """Run the continuous monitoring loop."""
        interval = interval or self.config.monitor.check_interval
        self._running = True

        def shutdown(sig, frame):
            logger.info("Shutdown signal received.")
            self._running = False

        signal.signal(signal.SIGINT, shutdown)
        signal.signal(signal.SIGTERM, shutdown)

        logger.info("OpsBot starting (interval: %ds)", interval)
        logger.info("Remediation: %s", "enabled" if self.config.remediation.enabled else "disabled")
        logger.info("Dry run: %s", "yes" if self.config.remediation.dry_run else "no")

        while self._running:
            try:
                self.run_once()
            except Exception as e:
                logger.error("Monitoring cycle error: %s", e, exc_info=True)

            time.sleep(interval)

        logger.info("OpsBot stopped.")


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="OpsBot — AI DevOps Automation")
    parser.add_argument("--config", "-c", default="opsbot.yaml", help="Config file path")
    parser.add_argument("--interval", "-i", type=int, default=30, help="Check interval (seconds)")
    parser.add_argument("--once", action="store_true", help="Run once and exit")
    parser.add_argument("--dry-run", action="store_true", help="Enable dry-run mode")
    parser.add_argument("--log-level", default="INFO", help="Log level")
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    config = OpsBotConfig.from_file(args.config)
    if args.dry_run:
        config.remediation.dry_run = True

    bot = OpsBot(config)

    if args.once:
        bot.run_once()
    else:
        bot.run(interval=args.interval)


if __name__ == "__main__":
    main()
