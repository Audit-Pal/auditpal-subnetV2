"""
AuditPal Agent Screener

Screens miner agent.py files BEFORE cloning into the sandbox.

Design principle: the Docker sandbox already handles most threats
(network=none, read-only FS, cap_drop=ALL, tmpfs /output).
This screener only catches what the sandbox CANNOT:
  - Intentional CPU/time abuse (mining loops, sleep bombs)
  - Sandbox escape attempts (ctypes, os.fork, chroot)
  - Hardcoded static findings (gaming the scoring)
  - Syntax errors (fail fast before wasting a container slot)

It does NOT flag legitimate patterns like:
  - subprocess.run   (slither agents need this)
  - json.loads       (parsing tool output)
  - open()           (reading source files)
  - os.environ       (reading CHALLENGE_ID, GEMINI_API_KEY)
  - requests/httpx   (sandbox blocks network anyway)
"""

import ast
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional


class RiskLevel(Enum):
    CRITICAL = "CRITICAL"   # block execution
    HIGH     = "HIGH"       # very likely malicious
    MEDIUM   = "MEDIUM"     # suspicious, log and allow
    LOW      = "LOW"        # informational


@dataclass
class ScreenerFinding:
    risk_level: RiskLevel
    category:   str
    description: str
    line_number: Optional[int] = None
    snippet:    Optional[str] = None


class AgentScreener:
    """
    Screens a miner's agent.py before the sandbox runs it.
    Returns (is_safe, findings).
    """

    # ── things the sandbox CANNOT stop ───────────────────────────────────────

    # CRITICAL: native code execution — can bypass Python sandbox
    NATIVE_EXEC = {
        "ctypes":       "native memory/code access — can escape container",
        "cffi":         "C foreign function interface — can escape container",
        "os.fork":      "process fork — can spawn untracked children",
        "os.chroot":    "chroot escape attempt",
        "pty.":         "pseudo-terminal — interactive shell spawn",
    }

    # CRITICAL: dynamic code execution — hides malicious logic
    DYNAMIC_EXEC = {
        "eval(":            "dynamic eval",
        "exec(":            "dynamic exec",
        "compile(":         "runtime code compilation",
        "__import__(":      "dynamic import injection",
        "importlib.import_module": "dynamic module loading",
    }

    # HIGH: intentional stalling — wastes the validator's container slot
    STALL_PATTERNS = {
        "while True:":  "infinite loop — will consume entire timeout",
        "while 1:":     "infinite loop — will consume entire timeout",
    }

    # HIGH: fork bomb / resource attack
    RESOURCE_ATTACK = {
        "os.fork":          "fork bomb risk",
        "multiprocessing.Process": "uncontrolled subprocess spawning",
        "threading.Thread": "uncontrolled thread spawning",
    }

    # ── static response detection ─────────────────────────────────────────────
    # Catches agents that hardcode findings instead of running analysis.
    # Only flag literal finding dicts, NOT json.loads() of tool output.

    STATIC_FINDING_PATTERNS = [
        # hardcoded finding dict as a return value or assignment
        r'return\s*\[\s*\{[^}]*"vulnerability_type"',
        r'findings\s*=\s*\[\s*\{[^}]*"vulnerability_type"',
        r'findings\s*=\s*\[\s*\{[^}]*"severity"',
        # loading a pre-baked JSON file (not parsing tool stdout)
        r'json\.load\s*\(\s*open\s*\(',
        r'with\s+open\s*\([^)]*\.json[^)]*\)\s+as\b',
    ]

    def __init__(self) -> None:
        self.findings: list[ScreenerFinding] = []
        self._lines:   list[str] = []

    def screen(self, agent_path: Path) -> tuple[bool, list[ScreenerFinding]]:
        """
        Screen agent_path. Returns (is_safe, findings).
        is_safe=False means do not run this agent.
        """
        self.findings = []
        self._lines   = []

        if not agent_path.exists():
            self.findings.append(ScreenerFinding(
                RiskLevel.CRITICAL, "Missing file",
                f"agent.py not found at {agent_path}",
            ))
            return False, self.findings

        try:
            code = agent_path.read_text(encoding="utf-8", errors="ignore")
            self._lines = code.splitlines()
        except Exception as exc:
            self.findings.append(ScreenerFinding(
                RiskLevel.CRITICAL, "Read error",
                f"Cannot read agent.py: {exc}",
            ))
            return False, self.findings

        # run all checks
        self._check_syntax(code)
        self._check_native_exec(code)
        self._check_dynamic_exec(code)
        self._check_stall_patterns(code)
        self._check_resource_attacks(code)
        self._check_static_responses(code)
        self._check_entry_point(code)

        return self._is_safe(), self.findings

    # ── individual checks ─────────────────────────────────────────────────────

    def _check_syntax(self, code: str) -> None:
        try:
            ast.parse(code)
        except SyntaxError as exc:
            self.findings.append(ScreenerFinding(
                RiskLevel.CRITICAL, "Syntax error",
                f"agent.py cannot be parsed: {exc}",
                line_number=exc.lineno,
            ))

    def _check_native_exec(self, code: str) -> None:
        for pattern, desc in self.NATIVE_EXEC.items():
            ln = self._find_line(code, pattern)
            if ln:
                self.findings.append(ScreenerFinding(
                    RiskLevel.CRITICAL, "Native execution",
                    f"{desc}  [{pattern}]",
                    line_number=ln,
                    snippet=self._snippet(ln),
                ))

    def _check_dynamic_exec(self, code: str) -> None:
        for pattern, desc in self.DYNAMIC_EXEC.items():
            ln = self._find_line(code, pattern)
            if ln:
                self.findings.append(ScreenerFinding(
                    RiskLevel.CRITICAL, "Dynamic execution",
                    f"{desc}  [{pattern}]",
                    line_number=ln,
                    snippet=self._snippet(ln),
                ))

    def _check_stall_patterns(self, code: str) -> None:
        for pattern, desc in self.STALL_PATTERNS.items():
            ln = self._find_line(code, pattern)
            if ln:
                self.findings.append(ScreenerFinding(
                    RiskLevel.HIGH, "Stall pattern",
                    desc,
                    line_number=ln,
                    snippet=self._snippet(ln),
                ))

    def _check_resource_attacks(self, code: str) -> None:
        for pattern, desc in self.RESOURCE_ATTACK.items():
            ln = self._find_line(code, pattern)
            if ln:
                self.findings.append(ScreenerFinding(
                    RiskLevel.HIGH, "Resource attack",
                    desc,
                    line_number=ln,
                    snippet=self._snippet(ln),
                ))

    def _check_static_responses(self, code: str) -> None:
        for pattern in self.STATIC_FINDING_PATTERNS:
            for match in re.finditer(pattern, code, re.IGNORECASE | re.DOTALL):
                ln = code[: match.start()].count("\n") + 1
                self.findings.append(ScreenerFinding(
                    RiskLevel.HIGH, "Hardcoded findings",
                    "Agent appears to return static findings without running analysis",
                    line_number=ln,
                    snippet=self._snippet(ln),
                ))

    def _check_entry_point(self, code: str) -> None:
        """
        Agent must define a main() function (any signature is fine —
        the sandbox calls `python agent.py` as a CLI, not main() directly).
        """
        if not re.search(r"^\s*def\s+main\s*\(", code, re.MULTILINE):
            self.findings.append(ScreenerFinding(
                RiskLevel.CRITICAL, "Missing entry point",
                "No main() function found — agent cannot run",
            ))

        if "__name__" not in code or '__main__' not in code:
            self.findings.append(ScreenerFinding(
                RiskLevel.MEDIUM, "Missing __main__ guard",
                "agent.py should call main() under if __name__ == '__main__'",
            ))

    # ── helpers ───────────────────────────────────────────────────────────────

    def _find_line(self, code: str, pattern: str) -> Optional[int]:
        idx = code.find(pattern)
        return (code[:idx].count("\n") + 1) if idx != -1 else None

    def _snippet(self, ln: int, ctx: int = 2) -> str:
        if ln is None:
            return ""
        start = max(0, ln - ctx - 1)
        end   = min(len(self._lines), ln + ctx)
        parts = []
        for i in range(start, end):
            prefix = ">>>" if i == ln - 1 else "   "
            parts.append(f"{prefix} {self._lines[i]}")
        return "\n".join(parts)

    def _is_safe(self) -> bool:
        if any(f.risk_level == RiskLevel.CRITICAL for f in self.findings):
            return False
        high = sum(1 for f in self.findings if f.risk_level == RiskLevel.HIGH)
        return high < 2

    # ── report ────────────────────────────────────────────────────────────────

    def report(self) -> str:
        counts = {r: 0 for r in RiskLevel}
        for f in self.findings:
            counts[f.risk_level] += 1

        lines = [
            "Agent Security Screening Report",
            "=" * 50,
            f"Total findings : {len(self.findings)}",
            f"  CRITICAL     : {counts[RiskLevel.CRITICAL]}",
            f"  HIGH         : {counts[RiskLevel.HIGH]}",
            f"  MEDIUM       : {counts[RiskLevel.MEDIUM]}",
            f"  LOW          : {counts[RiskLevel.LOW]}",
            "",
            f"Verdict: {'SAFE' if self._is_safe() else 'DO NOT RUN'}",
            "=" * 50,
        ]

        for i, f in enumerate(self.findings, 1):
            lines.append(f"\n{i}. [{f.risk_level.value}] {f.category}")
            lines.append(f"   {f.description}")
            if f.line_number:
                lines.append(f"   Line {f.line_number}")
            if f.snippet:
                lines.extend(f"   {l}" for l in f.snippet.splitlines())

        return "\n".join(lines)


# ── convenience function ──────────────────────────────────────────────────────

def screen_agent(agent_path: str) -> tuple[bool, str]:
    screener = AgentScreener()
    is_safe, _ = screener.screen(Path(agent_path))
    return is_safe, screener.report()


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("usage: python agent_screener.py <path/to/agent.py>")
        sys.exit(1)

    safe, report = screen_agent(sys.argv[1])
    print(report)
    sys.exit(0 if safe else 1)