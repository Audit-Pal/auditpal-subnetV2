import json
import os
import subprocess
import sys
from pathlib import Path

CHALLENGE_DIR = Path("/challenge")
OUTPUT_FILE   = Path("/output/report.json")

CHALLENGE_ID = os.environ.get("CHALLENGE_ID", "")
PROJECT_ID   = os.environ.get("PROJECT_ID", "")


def find_sol_files() -> list[Path]:
    sols = []
    for cb_dir in CHALLENGE_DIR.iterdir():
        if cb_dir.is_dir():
            sols.extend(cb_dir.glob("*.sol"))
    if not sols:
        sols = list(CHALLENGE_DIR.rglob("*.sol"))
    return sorted(sols)


def run_slither(sol_path: Path) -> list[dict]:
    try:
        result = subprocess.run(
            ["slither", str(sol_path), "--json", "-", "--disable-color"],
            capture_output=True,
            text=True,
       
        )
        if not result.stdout.strip():
            return []

        data = json.loads(result.stdout)
        findings = []
        for detector in data.get("results", {}).get("detectors", []):
            severity = detector.get("impact", "info").lower()
            if severity not in ("high", "medium", "low", "info"):
                severity = "info"

            elements  = detector.get("elements", [])
            line      = None
            if elements:
                src = elements[0].get("source_mapping", {})
                lines = src.get("lines", [])
                line  = lines[0] if lines else None

            findings.append({
                "file":               sol_path.name,
                "line":               line,
                "severity":           severity,
                "vulnerability_type": detector.get("check", "unknown"),
                "title":              detector.get("description", "")[:120],
                "description":        detector.get("description", ""),
                "location":           detector.get("first_markdown_element", ""),
            })
        return findings

    except subprocess.TimeoutExpired:
        return []
    except json.JSONDecodeError:
        return []
    except Exception:
        return []


def main():
    sol_files = find_sol_files()
    all_findings = []
    for sol in sol_files:
        all_findings.extend(run_slither(sol))

    report = {
        "challenge_id": CHALLENGE_ID,
        "project_id":   PROJECT_ID,
        "findings":     all_findings,
    }

    OUTPUT_FILE.write_text(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()