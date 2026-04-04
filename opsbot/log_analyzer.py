"""
Log Analyzer — parses system logs, clusters errors, detects patterns.

Scans log files for error patterns, groups them by type, and identifies
burst anomalies (sudden spikes in error frequency).
"""

import logging
import os
import re
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Pattern, Tuple

from opsbot.config import LogConfig

logger = logging.getLogger(__name__)


@dataclass
class LogEntry:
    """Parsed log entry."""
    timestamp: Optional[str]
    source: str
    level: str
    message: str = ""


@dataclass
class ErrorCluster:
    """A cluster of similar error messages."""
    pattern: str
    count: int
    first_seen: str
    last_seen: str
    sample_messages: List[str] = field(default_factory=list)
    severity: str = "medium"  # low, medium, high, critical


@dataclass
class LogAnalysisResult:
    """Results of a log analysis pass."""
    timestamp: str
    total_lines_scanned: int
    error_count: int
    warning_count: int
    clusters: List[ErrorCluster]
    anomalies: List[str]
    summary: str

    def to_dict(self) -> Dict:
        return {
            "timestamp": self.timestamp,
            "total_lines_scanned": self.total_lines_scanned,
            "error_count": self.error_count,
            "warning_count": self.warning_count,
            "clusters": [
                {
                    "pattern": c.pattern,
                    "count": c.count,
                    "first_seen": c.first_seen,
                    "last_seen": c.last_seen,
                    "severity": c.severity,
                    "samples": c.sample_messages[:3],
                }
                for c in self.clusters
            ],
            "anomalies": self.anomalies,
            "summary": self.summary,
        }


# Severity keywords ranked
_SEVERITY_MAP = {
    "emergency": "critical",
    "alert": "critical",
    "critical": "critical",
    "fatal": "critical",
    "error": "high",
    "err": "high",
    "segfault": "high",
    "oom": "high",
    "killed": "high",
    "warning": "medium",
    "warn": "medium",
    "notice": "low",
    "info": "low",
}

# Log line regex patterns for common formats
_LOG_PATTERNS = [
    # syslog: Mar 25 10:00:00 hostname service[pid]: message
    re.compile(r"^(\w{3}\s+\d+\s+[\d:]+)\s+\S+\s+(\S+?)(?:\[\d+\])?:\s+(.*)$"),
    # journald: 2026-03-25T10:00:00+00:00 hostname service[pid]: message
    re.compile(r"^(\d{4}-\d{2}-\d{2}T[\d:]+[+-]\d{2}:\d{2})\s+\S+\s+(\S+?)(?:\[\d+\])?:\s+(.*)$"),
    # generic: timestamp level message
    re.compile(r"^(\S+\s+\S+)\s+(ERROR|WARN|INFO|DEBUG|CRITICAL|FATAL)\s+(.*)$"),
]

# Error pattern regexes
_ERROR_RE = re.compile(r"error|critical|fatal|panic|exception|segfault|oom|killed|failed|failure", re.IGNORECASE)
_WARN_RE = re.compile(r"warn|warning|deprecated", re.IGNORECASE)


class LogAnalyzer:
    """Analyzes system logs, clusters errors, detects anomalies."""

    def __init__(self, config: Optional[LogConfig] = None):
        self.config = config or LogConfig()
        self._compiled_patterns: List[Tuple[Pattern, str]] = []
        for p in self.config.error_patterns:
            try:
                self._compiled_patterns.append((re.compile(p, re.IGNORECASE), p))
            except re.error:
                logger.warning("Invalid regex pattern: %s", p)

        self._history: List[LogAnalysisResult] = []
        self._error_counts: List[Tuple[float, int]] = []  # (timestamp, count)

    def analyze(self, log_path: Optional[str] = None, lines: Optional[List[str]] = None) -> LogAnalysisResult:
        """Analyze log content from a file or provided lines."""
        now = datetime.now(timezone.utc).isoformat()

        if lines is None:
            lines = self._read_log(log_path)

        total_lines = len(lines)
        error_lines = []
        warn_lines = []
        pattern_hits: Dict[str, List[str]] = defaultdict(list)

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Classify
            if _ERROR_RE.search(line):
                error_lines.append(line)
            elif _WARN_RE.search(line):
                warn_lines.append(line)

            # Match against configured patterns
            for compiled, raw_pattern in self._compiled_patterns:
                if compiled.search(line):
                    pattern_hits[raw_pattern].append(line)

        # Build clusters
        clusters = self._build_clusters(pattern_hits, error_lines)

        # Detect anomalies (burst detection)
        anomalies = self._detect_anomalies(len(error_lines))

        # Track history
        self._error_counts.append((time.time(), len(error_lines)))

        summary = self._build_summary(total_lines, len(error_lines), len(warn_lines), clusters, anomalies)

        result = LogAnalysisResult(
            timestamp=now,
            total_lines_scanned=total_lines,
            error_count=len(error_lines),
            warning_count=len(warn_lines),
            clusters=clusters,
            anomalies=anomalies,
            summary=summary,
        )

        self._history.append(result)
        if len(self._history) > 100:
            self._history = self._history[-100:]

        return result

    def analyze_all(self) -> List[LogAnalysisResult]:
        """Analyze all configured log paths."""
        results = []
        for path in self.config.log_paths:
            if os.path.exists(path):
                try:
                    results.append(self.analyze(log_path=path))
                except Exception as e:
                    logger.error("Failed to analyze %s: %s", path, e)
        return results

    def _read_log(self, path: str) -> List[str]:
        """Read the last N lines from a log file."""
        path = Path(path)
        if not path.exists():
            logger.warning("Log file not found: %s", path)
            return []

        try:
            with open(path, "r", errors="replace") as f:
                all_lines = f.readlines()
                return all_lines[-self.config.tail_lines:]
        except PermissionError:
            logger.warning("Permission denied: %s", path)
            return []

    def _build_clusters(
        self,
        pattern_hits: Dict[str, List[str]],
        error_lines: List[str],
    ) -> List[ErrorCluster]:
        """Group similar errors into clusters."""
        clusters = []

        # First, clusters by matched pattern
        for pattern, messages in pattern_hits.items():
            if not messages:
                continue
            severity = self._infer_severity(messages[0])
            clusters.append(ErrorCluster(
                pattern=pattern,
                count=len(messages),
                first_seen="",
                last_seen="",
                sample_messages=messages[:5],
                severity=severity,
            ))

        # Then, cluster remaining errors by similarity (simple prefix matching)
        matched = set()
        for msgs in pattern_hits.values():
            matched.update(msgs[:5])

        unmatched = [e for e in error_lines if e not in matched]
        if unmatched:
            word_clusters = defaultdict(list)
            for line in unmatched:
                # Use first 50 chars as rough key
                key = line[:50].strip()
                word_clusters[key].append(line)

            for key, msgs in word_clusters.items():
                if len(msgs) >= 2:  # only cluster if multiple hits
                    severity = self._infer_severity(msgs[0])
                    clusters.append(ErrorCluster(
                        pattern=key + "...",
                        count=len(msgs),
                        first_seen="",
                        last_seen="",
                        sample_messages=msgs[:5],
                        severity=severity,
                    ))

        # Sort by count descending
        clusters.sort(key=lambda c: c.count, reverse=True)
        return clusters

    def _infer_severity(self, message: str) -> str:
        """Infer severity from message content."""
        msg_lower = message.lower()
        for keyword, severity in _SEVERITY_MAP.items():
            if keyword in msg_lower:
                return severity
        return "medium"

    def _detect_anomalies(self, current_error_count: int) -> List[str]:
        """Detect anomalous error rate spikes."""
        anomalies = []

        if len(self._error_counts) < 3:
            return anomalies

        # Check if current count is > 2x the moving average
        recent = [c for _, c in self._error_counts[-10:]]
        avg = sum(recent) / len(recent) if recent else 0

        if current_error_count > avg * 2 and current_error_count > 5:
            anomalies.append(
                f"Error rate spike: {current_error_count} errors "
                f"(avg: {avg:.0f}, ratio: {current_error_count / avg:.1f}x)"
            )

        return anomalies

    def _build_summary(
        self,
        total: int,
        errors: int,
        warnings: int,
        clusters: List[ErrorCluster],
        anomalies: List[str],
    ) -> str:
        """Build a human-readable summary."""
        parts = [f"Scanned {total} lines: {errors} errors, {warnings} warnings."]

        if clusters:
            top = clusters[0]
            parts.append(f"Top cluster: '{top.pattern}' ({top.count}x, severity: {top.severity})")

        if anomalies:
            parts.append(f"⚠ ANOMALY: {anomalies[0]}")

        if errors == 0 and warnings == 0:
            parts.append("All clear — no issues found.")

        return " ".join(parts)

    def get_history(self) -> List[LogAnalysisResult]:
        """Return analysis history."""
        return list(self._history)
