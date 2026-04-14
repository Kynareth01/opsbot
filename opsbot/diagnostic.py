"""
Diagnostic Engine — correlates metrics + logs to find root causes.

Takes metric snapshots and log analysis results, correlates them to
identify the most likely root cause of system issues.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

from opsbot.monitor import MetricSnapshot
from opsbot.log_analyzer import LogAnalysisResult, ErrorCluster

logger = logging.getLogger(__name__)


@dataclass
class DiagnosticFinding:
    """A single diagnostic finding."""
    category: str  # e.g., "disk", "memory", "cpu", "docker", "log"
    severity: str  # low, medium, high, critical
    title: str
    description: str
    evidence: List[str] = field(default_factory=list)
    recommended_action: str = ""
    confidence: float = 0.0  # 0.0 to 1.0


@dataclass
class DiagnosticReport:
    """Full diagnostic report combining metrics and logs."""
    timestamp: str
    findings: List[DiagnosticFinding]
    root_cause: Optional[str]
    incident_summary: str
    severity: str  # overall severity

    def to_dict(self) -> Dict:
        return {
            "timestamp": self.timestamp,
            "severity": self.severity,
            "root_cause": self.root_cause,
            "incident_summary": self.incident_summary,
            "findings": [
                {
                    "category": f.category,
                    "severity": f.severity,
                    "title": f.title,
                    "description": f.description,
                    "evidence": f.evidence,
                    "recommended_action": f.recommended_action,
                    "confidence": f.confidence,
                }
                for f in self.findings
            ],
        }

    @property
    def has_issues(self) -> bool:
        return len(self.findings) > 0

    @property
    def critical_findings(self) -> List[DiagnosticFinding]:
        return [f for f in self.findings if f.severity == "critical"]


# Map of metric patterns to diagnostic rules
_DIAGNOSTIC_RULES = [
    {
        "name": "disk_pressure",
        "condition": lambda m, l: any(d["percent"] >= 90 for d in m.disk_partitions),
        "category": "disk",
        "severity": "high",
        "title": "Disk pressure detected",
        "description": "One or more disk partitions are above 90% usage.",
        "action": "Run disk_cleanup playbook or manually clean /var/log, /tmp, old docker images.",
        "confidence": 0.95,
    },
    {
        "name": "memory_exhaustion",
        "condition": lambda m, l: m.memory_percent >= 95,
        "category": "memory",
        "severity": "critical",
        "title": "Memory exhaustion",
        "description": "System memory is critically high (>95%). OOM killer may trigger.",
        "action": "Identify memory-hogging processes. Consider restarting heavy services.",
        "confidence": 0.95,
    },
    {
        "name": "high_memory",
        "condition": lambda m, l: 85 <= m.memory_percent < 95,
        "category": "memory",
        "severity": "medium",
        "title": "High memory usage",
        "description": "Memory usage is elevated and trending toward exhaustion.",
        "action": "Monitor for leaks. Review top memory consumers.",
        "confidence": 0.8,
    },
    {
        "name": "cpu_saturation",
        "condition": lambda m, l: m.cpu_percent >= 95,
        "category": "cpu",
        "severity": "high",
        "title": "CPU saturation",
        "description": "CPU usage is near 100%. System responsiveness may be degraded.",
        "action": "Identify CPU-heavy processes. Consider scaling or throttling.",
        "confidence": 0.9,
    },
    {
        "name": "load_spike",
        "condition": lambda m, l: m.load_avg_1m > m.cpu_count * 2,
        "category": "cpu",
        "severity": "medium",
        "title": "Load average spike",
        "description": f"Load average significantly exceeds CPU count, indicating process contention.",
        "action": "Check for stuck processes or I/O wait.",
        "confidence": 0.85,
    },
    {
        "name": "oom_killer_active",
        "condition": lambda m, l: any("oom" in c.pattern.lower() or "killed" in c.pattern.lower()
                                       for c in l.clusters) if l else False,
        "category": "memory",
        "severity": "critical",
        "title": "OOM killer detected in logs",
        "description": "The kernel OOM killer has been active. Processes were killed due to memory pressure.",
        "action": "Immediately check which process was killed. Increase swap or memory limits.",
        "confidence": 0.98,
    },
    {
        "name": "docker_container_down",
        "condition": lambda m, l: any("exited" in c.get("status", "").lower() or
                                       "dead" in c.get("status", "").lower()
                                       for c in m.docker_containers),
        "category": "docker",
        "severity": "high",
        "title": "Docker container down",
        "description": "One or more Docker containers are in exited/dead state.",
        "action": "Check container logs. Restart the affected service.",
        "confidence": 0.95,
    },
    {
        "name": "log_error_spike",
        "condition": lambda m, l: l.error_count > 50 if l else False,
        "category": "log",
        "severity": "high",
        "title": "High error rate in logs",
        "description": f"Detected elevated error counts in system logs.",
        "action": "Review the error clusters for root cause. Check recent deployments.",
        "confidence": 0.85,
    },
    {
        "name": "segfault",
        "condition": lambda m, l: any("segfault" in c.pattern.lower()
                                       for c in l.clusters) if l else False,
        "category": "system",
        "severity": "critical",
        "title": "Segmentation faults detected",
        "description": "Segfaults indicate memory corruption or software bugs.",
        "action": "Check affected application. May need rebuild or update.",
        "confidence": 0.9,
    },
]


class DiagnosticEngine:
    """Correlates metrics and logs to produce diagnostic reports."""

    def __init__(self):
        self._history: List[DiagnosticReport] = []

    def diagnose(
        self,
        metrics: MetricSnapshot,
        log_result: Optional[LogAnalysisResult] = None,
    ) -> DiagnosticReport:
        """Run diagnostics on a metric snapshot and optional log analysis."""
        now = datetime.now(timezone.utc).isoformat()
        findings: List[DiagnosticFinding] = []

        # Run all rules
        for rule in _DIAGNOSTIC_RULES:
            try:
                if rule["condition"](metrics, log_result):
                    evidence = []
                    if metrics.alerts:
                        evidence.extend(metrics.alerts)
                    if log_result and log_result.clusters:
                        top = log_result.clusters[0]
                        evidence.append(f"Log cluster: '{top.pattern}' ({top.count}x)")

                    findings.append(DiagnosticFinding(
                        category=rule["category"],
                        severity=rule["severity"],
                        title=rule["title"],
                        description=rule["description"],
                        evidence=evidence,
                        recommended_action=rule["action"],
                        confidence=rule["confidence"],
                    ))
            except Exception as e:
                logger.debug("Rule '%s' evaluation error: %s", rule["name"], e)

        # Determine root cause (highest confidence critical/high finding)
        root_cause = None
        if findings:
            prioritized = sorted(findings, key=lambda f: (
                {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(f.severity, 4),
                -f.confidence,
            ))
            root_cause = f"{prioritized[0].title}: {prioritized[0].description}"

        # Overall severity
        if any(f.severity == "critical" for f in findings):
            overall_severity = "critical"
        elif any(f.severity == "high" for f in findings):
            overall_severity = "high"
        elif findings:
            overall_severity = "medium"
        else:
            overall_severity = "healthy"

        summary = self._build_summary(findings, overall_severity)

        report = DiagnosticReport(
            timestamp=now,
            findings=findings,
            root_cause=root_cause,
            incident_summary=summary,
            severity=overall_severity,
        )

        self._history.append(report)
        if len(self._history) > 100:
            self._history = self._history[-100:]

        return report

    def _build_summary(self, findings: List[DiagnosticFinding], severity: str) -> str:
        """Build a human-readable incident summary."""
        if not findings:
            return "System healthy — no issues detected."

        parts = [f"Severity: {severity.upper()}. "]
        parts.append(f"Found {len(findings)} issue(s). ")

        for f in findings[:3]:
            parts.append(f"[{f.severity.upper()}] {f.title}. ")

        if findings[0].recommended_action:
            parts.append(f"Recommended: {findings[0].recommended_action}")

        return "".join(parts)

    def get_history(self) -> List[DiagnosticReport]:
        return list(self._history)
