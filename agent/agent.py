import sys
import json
import logging
import os
import subprocess
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stderr,
)
log = logging.getLogger(__name__)

CHALLENGE_DIR    = Path("/challenge")
OUTPUT_FILE      = Path("/output/report.json")
SLITHER_TIMEOUT  = int(os.environ.get("SLITHER_TIMEOUT", "120"))
CHALLENGE_ID     = os.environ.get("CHALLENGE_ID", "")
PROJECT_ID       = os.environ.get("PROJECT_ID", "")
SEVERITY_ALLOWED = {"high", "medium", "low", "info"}
SKIP_DIRS        = {"node_modules", "lib", "vendor", ".git"}


def find_sol_files() -> list[Path]:
    sols: list[Path] = []
    for cb_dir in sorted(CHALLENGE_DIR.iterdir()):
        if cb_dir.is_dir() and cb_dir.name not in SKIP_DIRS:
            sols.extend(sorted(cb_dir.glob("*.sol")))

    if not sols:
        log.warning("No .sol files in immediate subdirs; falling back to rglob.")
        sols = [
            p for p in sorted(CHALLENGE_DIR.rglob("*.sol"))
            if not any(skip in p.parts for skip in SKIP_DIRS)
        ]

    log.info("Found %d Solidity file(s).", len(sols))
    return sols

    
def run_slither(sol_path: Path) -> list[dict]:
    log.info("Running Slither on %s", sol_path)
    try:
        result = subprocess.run(
            ["slither", str(sol_path), "--json", "-", "--disable-color"],
            capture_output=True,
            text=True,
            timeout=SLITHER_TIMEOUT,
        )
    except FileNotFoundError:
        log.error("slither not found in PATH — is it installed?")
        return []
    except subprocess.TimeoutExpired:
        log.warning("Slither timed out on %s (limit: %ds)", sol_path, SLITHER_TIMEOUT)
        return []

    if result.stderr:
        log.debug("slither stderr:\n%s", result.stderr[:2000])

    if not result.stdout.strip():
        log.warning("Slither produced no output for %s (exit %d)", sol_path, result.returncode)
        return []

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        log.error("JSON parse error for %s: %s", sol_path, exc)
        return []

    findings: list[dict] = []
    for detector in data.get("results", {}).get("detectors", []):
        raw_severity = detector.get("impact", "info").lower()
        severity = raw_severity if raw_severity in SEVERITY_ALLOWED else "info"

        elements = detector.get("elements", [])
        line: int | None = None
        if elements:
            lines = elements[0].get("source_mapping", {}).get("lines", [])
            line = lines[0] if lines else None

        description = detector.get("description", "")
        findings.append({
            "file":               sol_path.name,
            "line":               line,
            "severity":           severity,
            "vulnerability_type": detector.get("check", "unknown"),
            "title":              description[:120],
            "description":        description,
            "location":           detector.get("first_markdown_element", ""),
        })

    log.info("  → %d finding(s) from %s", len(findings), sol_path.name)
    return findings


def write_report(findings: list[dict], status: str = "ok") -> None:
    report = {
        "challenge_id": CHALLENGE_ID,
        "project_id":   PROJECT_ID,
        "findings":     findings,
        "status":       status,
    }
    payload = json.dumps(report, indent=2)

    # Print to stdout for console visibility
    print(payload)

   
def main() -> None:
    try:
        sol_files = find_sol_files()

        all_findings: list[dict] = []
        for sol in sol_files:
            all_findings.extend(run_slither(sol))
        write_report(all_findings, status="ok")
    except Exception as exc:
        log.exception("Fatal error during analysis: %s", exc)
        write_report([], status=f"error: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()