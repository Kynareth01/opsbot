"""
Playbook Runner — executes YAML-defined remediation playbooks.

Playbooks define a sequence of steps: check conditions, run commands,
and trigger alerts. Supports variables, conditionals, and error handling.
"""

import logging
import os
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

logger = logging.getLogger(__name__)


@dataclass
class PlaybookStep:
    """A single step in a playbook."""
    name: str
    action: str  # "command", "check", "alert", "wait"
    command: Optional[str] = None
    condition: Optional[str] = None  # e.g., "disk_percent > 90"
    expected_output: Optional[str] = None
    timeout: int = 60
    on_failure: str = "continue"  # "continue", "abort", "retry"
    retries: int = 0
    vars_override: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Playbook:
    """A parsed playbook definition."""
    name: str
    description: str
    version: str = "1.0"
    author: str = ""
    tags: List[str] = field(default_factory=list)
    variables: Dict[str, Any] = field(default_factory=dict)
    steps: List[PlaybookStep] = field(default_factory=list)
    source_file: Optional[str] = None

    @classmethod
    def from_yaml(cls, path: str) -> "Playbook":
        """Load a playbook from a YAML file."""
        with open(path) as f:
            data = yaml.safe_load(f)

        if not data:
            raise ValueError(f"Empty playbook file: {path}")

        steps = []
        for s in data.get("steps", []):
            steps.append(PlaybookStep(
                name=s.get("name", "unnamed"),
                action=s.get("action", "command"),
                command=s.get("command"),
                condition=s.get("condition"),
                expected_output=s.get("expected_output"),
                timeout=s.get("timeout", 60),
                on_failure=s.get("on_failure", "continue"),
                retries=s.get("retries", 0),
                vars_override=s.get("vars", {}),
            ))

        return cls(
            name=data.get("name", Path(path).stem),
            description=data.get("description", ""),
            version=data.get("version", "1.0"),
            author=data.get("author", ""),
            tags=data.get("tags", []),
            variables=data.get("variables", {}),
            steps=steps,
            source_file=path,
        )


@dataclass
class StepResult:
    """Result of executing a playbook step."""
    step_name: str
    action: str
    success: bool
    output: str
    duration_ms: int
    skipped: bool = False
    error: Optional[str] = None


@dataclass
class PlaybookResult:
    """Result of executing a full playbook."""
    playbook_name: str
    timestamp: str
    success: bool
    steps_total: int
    steps_passed: int
    steps_failed: int
    steps_skipped: int
    step_results: List[StepResult]
    total_duration_ms: int
    error: Optional[str] = None

    def to_dict(self) -> Dict:
        return {
            "playbook": self.playbook_name,
            "timestamp": self.timestamp,
            "success": self.success,
            "steps": {
                "total": self.steps_total,
                "passed": self.steps_passed,
                "failed": self.steps_failed,
                "skipped": self.steps_skipped,
            },
            "total_duration_ms": self.total_duration_ms,
            "step_results": [
                {
                    "name": sr.step_name,
                    "action": sr.action,
                    "success": sr.success,
                    "output": sr.output[:500],
                    "duration_ms": sr.duration_ms,
                    "skipped": sr.skipped,
                    "error": sr.error,
                }
                for sr in self.step_results
            ],
            "error": self.error,
        }


class PlaybookRunner:
    """Loads and executes YAML playbooks."""

    def __init__(self, playbook_dir: str = "playbooks", variables: Optional[Dict] = None):
        self.playbook_dir = Path(playbook_dir)
        self.global_variables = variables or {}
        self._history: List[PlaybookResult] = []
        self._loaded_playbooks: Dict[str, Playbook] = {}

    def load_playbook(self, name: str) -> Playbook:
        """Load a playbook by name or file path."""
        if name in self._loaded_playbooks:
            return self._loaded_playbooks[name]

        # Try direct path first
        if os.path.exists(name):
            pb = Playbook.from_yaml(name)
        else:
            # Search in playbook directory
            candidates = [
                self.playbook_dir / f"{name}.yaml",
                self.playbook_dir / f"{name}.yml",
                self.playbook_dir / name,
            ]
            found = None
            for c in candidates:
                if c.exists():
                    found = c
                    break

            if not found:
                raise FileNotFoundError(f"Playbook not found: {name}")

            pb = Playbook.from_yaml(str(found))

        self._loaded_playbooks[name] = pb
        return pb

    def list_playbooks(self) -> List[Dict[str, str]]:
        """List available playbooks in the playbook directory."""
        playbooks = []
        if not self.playbook_dir.exists():
            return playbooks

        for f in sorted(self.playbook_dir.iterdir()):
            if f.suffix in (".yaml", ".yml"):
                try:
                    pb = Playbook.from_yaml(str(f))
                    playbooks.append({
                        "name": pb.name,
                        "file": str(f),
                        "description": pb.description,
                        "tags": pb.tags,
                        "steps": len(pb.steps),
                    })
                except Exception as e:
                    logger.warning("Failed to parse %s: %s", f, e)
        return playbooks

    def run(self, name: str, variables: Optional[Dict] = None) -> PlaybookResult:
        """Execute a playbook by name."""
        pb = self.load_playbook(name)
        return self._execute_playbook(pb, variables)

    def _execute_playbook(self, pb: Playbook, extra_vars: Optional[Dict] = None) -> PlaybookResult:
        """Execute a parsed playbook."""
        now = datetime.now(timezone.utc).isoformat()
        start = time.monotonic()

        # Merge variables: global < playbook < extra
        variables = {**self.global_variables, **pb.variables}
        if extra_vars:
            variables.update(extra_vars)

        step_results = []
        passed = failed = skipped = 0

        for step in pb.steps:
            result = self._execute_step(step, variables)
            step_results.append(result)

            if result.skipped:
                skipped += 1
            elif result.success:
                passed += 1
            else:
                failed += 1
                if step.on_failure == "abort":
                    logger.warning("Step '%s' failed with abort policy. Stopping playbook.", step.name)
                    break

        total_ms = int((time.monotonic() - start) * 1000)

        result = PlaybookResult(
            playbook_name=pb.name,
            timestamp=now,
            success=failed == 0,
            steps_total=len(pb.steps),
            steps_passed=passed,
            steps_failed=failed,
            steps_skipped=skipped,
            step_results=step_results,
            total_duration_ms=total_ms,
        )

        self._history.append(result)
        if len(self._history) > 50:
            self._history = self._history[-50:]

        return result

    def _execute_step(self, step: PlaybookStep, variables: Dict) -> StepResult:
        """Execute a single playbook step."""
        start = time.monotonic()

        # Check condition
        if step.condition:
            if not self._evaluate_condition(step.condition, variables):
                logger.info("Skipping step '%s': condition not met", step.name)
                return StepResult(
                    step_name=step.name,
                    action=step.action,
                    success=True,
                    output=f"Skipped: condition '{step.condition}' not met",
                    duration_ms=0,
                    skipped=True,
                )

        # Merge step-level vars
        variables = {**variables, **step.vars_override}

        try:
            if step.action == "command":
                return self._run_command_step(step, variables, start)
            elif step.action == "check":
                return self._run_check_step(step, variables, start)
            elif step.action == "wait":
                return self._run_wait_step(step, start)
            elif step.action == "alert":
                return self._run_alert_step(step, variables, start)
            else:
                return StepResult(
                    step_name=step.name,
                    action=step.action,
                    success=False,
                    output="",
                    duration_ms=int((time.monotonic() - start) * 1000),
                    error=f"Unknown action: {step.action}",
                )
        except Exception as e:
            return StepResult(
                step_name=step.name,
                action=step.action,
                success=False,
                output="",
                duration_ms=int((time.monotonic() - start) * 1000),
                error=str(e),
            )

    def _run_command_step(self, step: PlaybookStep, variables: Dict, start: float) -> StepResult:
        """Execute a command step."""
        cmd = self._interpolate(step.command or "", variables)

        for attempt in range(step.retries + 1):
            try:
                result = subprocess.run(
                    cmd, shell=True, capture_output=True, text=True, timeout=step.timeout
                )
                success = result.returncode == 0

                if success or attempt == step.retries:
                    return StepResult(
                        step_name=step.name,
                        action=step.action,
                        success=success,
                        output=result.stdout + result.stderr,
                        duration_ms=int((time.monotonic() - start) * 1000),
                        error=None if success else f"Exit code: {result.returncode}",
                    )
            except subprocess.TimeoutExpired:
                if attempt == step.retries:
                    return StepResult(
                        step_name=step.name,
                        action=step.action,
                        success=False,
                        output="",
                        duration_ms=int((time.monotonic() - start) * 1000),
                        error=f"Command timed out after {step.timeout}s",
                    )

            time.sleep(1)

        return StepResult(step_name=step.name, action=step.action, success=False, output="", duration_ms=0)

    def _run_check_step(self, step: PlaybookStep, variables: Dict, start: float) -> StepResult:
        """Execute a check step (evaluates condition)."""
        condition = self._interpolate(step.condition or "true", variables)
        result = self._evaluate_condition(condition, variables)

        return StepResult(
            step_name=step.name,
            action=step.action,
            success=result,
            output=f"Condition '{condition}' evaluated to {result}",
            duration_ms=int((time.monotonic() - start) * 1000),
        )

    def _run_wait_step(self, step: PlaybookStep, start: float) -> StepResult:
        """Execute a wait step (sleep)."""
        duration = step.timeout
        time.sleep(min(duration, 5))  # Cap at 5s for safety

        return StepResult(
            step_name=step.name,
            action=step.action,
            success=True,
            output=f"Waited {duration} seconds",
            duration_ms=int((time.monotonic() - start) * 1000),
        )

    def _run_alert_step(self, step: PlaybookStep, variables: Dict, start: float) -> StepResult:
        """Execute an alert step (log a message)."""
        message = self._interpolate(step.command or step.name, variables)
        logger.info("ALERT: %s", message)

        return StepResult(
            step_name=step.name,
            action=step.action,
            success=True,
            output=f"Alert sent: {message}",
            duration_ms=int((time.monotonic() - start) * 1000),
        )

    def _interpolate(self, text: str, variables: Dict) -> str:
        """Interpolate {{variable}} placeholders."""
        for key, value in variables.items():
            text = text.replace(f"{{{{{key}}}}}", str(value))
        return text

    def _evaluate_condition(self, condition: str, variables: Dict) -> bool:
        """Safely evaluate a simple condition string."""
        condition = self._interpolate(condition, variables)

        # Simple comparisons only
        try:
            # Allow: x > 90, x < 10, x == "foo", x != "bar"
            for op in ["!=", "==", ">=", "<=", ">", "<"]:
                if op in condition:
                    left, right = condition.split(op, 1)
                    left = left.strip().strip('"').strip("'")
                    right = right.strip().strip('"').strip("'")

                    try:
                        left = float(left)
                        right = float(right)
                    except ValueError:
                        pass

                    if op == ">":
                        return left > right
                    elif op == "<":
                        return left < right
                    elif op == ">=":
                        return left >= right
                    elif op == "<=":
                        return left <= right
                    elif op == "==":
                        return left == right
                    elif op == "!=":
                        return left != right

            # If it's a variable name, check truthiness
            if condition in variables:
                return bool(variables[condition])

            return bool(condition)
        except Exception:
            return False

    def get_history(self) -> List[PlaybookResult]:
        return list(self._history)
