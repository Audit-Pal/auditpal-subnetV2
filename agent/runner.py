#!/usr/bin/env python3
import json
import os
import sys
import traceback
from pathlib import Path
import importlib.util

# ── Fix 1: default path changed from /agent → /miner_agent ──────────────────
AGENT_PATH    = Path(os.getenv("AGENT_PATH", "/miner_agent")) / "agent.py"
CHALLENGE_DIR = Path("/challenge")


def eprint(*args, **kwargs):
    """Print to stderr only (never pollute stdout JSON)."""
    print(*args, file=sys.stderr, flush=True, **kwargs)


def load_agent():
    eprint(f"[runner] Looking for agent at: {AGENT_PATH}")

    if not AGENT_PATH.exists():
        # ── Fix 2: list what IS in /miner_agent so we can see the real layout
        eprint(f"[runner] agent.py NOT found at {AGENT_PATH}")
        parent = AGENT_PATH.parent
        if parent.exists():
            eprint(f"[runner] Contents of {parent}:")
            for p in sorted(parent.rglob("*"))[:30]:
                eprint(f"[runner]   {p.relative_to(parent)}")
        else:
            eprint(f"[runner] Parent dir {parent} does not exist either")
        raise FileNotFoundError(f"agent.py not found at {AGENT_PATH}")

    eprint(f"[runner] agent.py found ✓")

    spec   = importlib.util.spec_from_file_location("agent", str(AGENT_PATH))
    module = importlib.util.module_from_spec(spec)

    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        eprint(f"[runner] Failed to import agent.py: {exc}")
        eprint(traceback.format_exc())
        raise

    if not hasattr(module, "agent_main"):
        raise AttributeError("agent_main(task) not found in agent.py")

    eprint("[runner] agent_main() found ✓")
    return module


def load_challenge():
    contracts: dict[str, str] = {}

    eprint(f"[runner] ── Challenge metadata ──────────────────────────")
    eprint(f"[runner] CHALLENGE_ID  : {os.getenv('CHALLENGE_ID')}")
    eprint(f"[runner] PROJECT_ID    : {os.getenv('PROJECT_ID')}")
    eprint(f"[runner] CHALLENGE_NAME: {os.getenv('CHALLENGE_NAME')}")
    eprint(f"[runner] PLATFORM      : {os.getenv('PLATFORM')}")
    eprint(f"[runner] GEMINI_API_KEY: {'SET ✓' if os.getenv('GEMINI_API_KEY') else 'MISSING ✗'}")
    eprint(f"[runner] ────────────────────────────────────────────────")

    if not CHALLENGE_DIR.exists():
        eprint(f"[runner] /challenge directory does not exist!")
        eprint(f"[runner] Listing / for context:")
        try:
            for p in sorted(Path("/").iterdir()):
                eprint(f"[runner]   /{p.name}")
        except Exception:
            pass
        return _make_task(contracts)

    eprint(f"[runner] /challenge layout:")
    try:
        for p in sorted(CHALLENGE_DIR.rglob("*")):
            eprint(f"[runner]   {p.relative_to(CHALLENGE_DIR)}")
    except Exception as exc:
        eprint(f"[runner]   (could not list: {exc})")

    for codebase_dir in sorted(CHALLENGE_DIR.iterdir()):
        if not codebase_dir.is_dir():
            continue
        for sol_file in sorted(codebase_dir.glob("*.sol")):
            try:
                content = sol_file.read_text(encoding="utf-8", errors="ignore")
                contracts[sol_file.name] = content
                eprint(f"[runner] Loaded {sol_file.name}  ({len(content):,} chars)")
            except Exception as exc:
                eprint(f"[runner] Failed to read {sol_file}: {exc}")

    eprint(f"[runner] Total .sol files loaded: {len(contracts)}")
    return _make_task(contracts)


def _make_task(contracts: dict[str, str]) -> dict:
    return {
        "challenge_id": os.getenv("CHALLENGE_ID", "unknown"),
        "project_id":   os.getenv("PROJECT_ID",   "unknown"),
        "contracts":    contracts,
    }


def main():
    eprint("[runner] ════════════════════════════════════════════════")
    eprint("[runner] AuditPal runner starting")
    eprint(f"[runner] AGENT_PATH   : {AGENT_PATH}")
    eprint(f"[runner] CHALLENGE_DIR: {CHALLENGE_DIR}")
    eprint("[runner] ════════════════════════════════════════════════")

    try:
        agent = load_agent()
        task  = load_challenge()

        eprint(f"[runner] Calling agent_main() with {len(task['contracts'])} contract(s)")

        result = agent.agent_main(task)

        # ── Fix 3: validate what agent_main returned before printing ─────────
        eprint(f"[runner] agent_main() returned type : {type(result)}")
        if not isinstance(result, dict):
            raise TypeError(f"agent_main() must return a dict, got {type(result)}")

        eprint(f"[runner] result keys    : {list(result.keys())}")
        eprint(f"[runner] findings count : {len(result.get('findings', []))}")
        eprint(f"[runner] challenge_id   : {result.get('challenge_id')}")
        eprint(f"[runner] project_id     : {result.get('project_id')}")

        # ── Only line that writes to stdout ───────────────────────────────────
        print(json.dumps(result), flush=True)
        eprint("[runner] JSON written to stdout ✓")

    except Exception as exc:
        eprint(f"[runner] FATAL: {type(exc).__name__}: {exc}")
        eprint(traceback.format_exc())

        # Return a valid-shaped error report so the validator's schema check
        # gets a parseable object rather than nothing at all.
        error_report = {
            "challenge_id": os.getenv("CHALLENGE_ID", "unknown"),
            "project_id":   os.getenv("PROJECT_ID",   "unknown"),
            "findings":     [],
            "_runner_error": str(exc),
        }
        print(json.dumps(error_report), flush=True)
        sys.exit(1)


if __name__ == "__main__":
    main()