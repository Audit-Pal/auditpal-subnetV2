#!/usr/bin/env python3
import json
import os
import sys
import traceback
from pathlib import Path
import importlib.util

AGENT_PATH = Path(os.getenv("AGENT_PATH", "/agent")) / "agent.py"
CHALLENGE_DIR = Path("/challenge")


def eprint(*args, **kwargs):
    """Print to stderr only (never pollute stdout JSON)."""
    print(*args, file=sys.stderr, flush=True, **kwargs)


def load_agent():
    if not AGENT_PATH.exists():
        raise FileNotFoundError(f"agent.py not found at {AGENT_PATH}")

    spec = importlib.util.spec_from_file_location("agent", str(AGENT_PATH))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    if not hasattr(module, "agent_main"):
        raise Exception("agent_main(task) not found in agent.py")

    return module


def load_challenge():
    contracts = {}

    eprint(f"[runner] CHALLENGE_ID : {os.getenv('CHALLENGE_ID')}")
    eprint(f"[runner] PROJECT_ID   : {os.getenv('PROJECT_ID')}")
    eprint(f"[runner] NAME         : {os.getenv('CHALLENGE_NAME')}")

    if not CHALLENGE_DIR.exists():
        eprint("[runner] /challenge directory not found")
        return {
            "challenge_id": os.getenv("CHALLENGE_ID", "unknown"),
            "project_id": os.getenv("PROJECT_ID", "unknown"),
            "contracts": {},
        }

    for codebase_dir in CHALLENGE_DIR.iterdir():
        if not codebase_dir.is_dir():
            continue

        for sol_file in codebase_dir.glob("*.sol"):
            try:
                contracts[sol_file.name] = sol_file.read_text(
                    encoding="utf-8", errors="ignore"
                )
                eprint(f"[runner] Loaded {sol_file.name}")
            except Exception as e:
                eprint(f"[runner] Failed to read {sol_file}: {e}")

    eprint(f"[runner] Total contracts: {len(contracts)}")

    return {
        "challenge_id": os.getenv("CHALLENGE_ID", "unknown"),
        "project_id": os.getenv("PROJECT_ID", "unknown"),
        "contracts": contracts,
    }


def main():
    try:
        eprint("[runner] Starting...")

        agent = load_agent()
        task = load_challenge()

        eprint("[runner] Running agent_main()")
        result = agent.agent_main(task)

        eprint("[runner] Finished — writing JSON")

        # ✅ ONLY stdout output
        print(json.dumps(result), flush=True)

    except Exception as e:
        eprint(f"[runner] FATAL: {e}")
        eprint(traceback.format_exc())

        # Still return valid JSON so validator can handle it
        print(json.dumps({
            "status": "error",
            "error": str(e),
            "trace": traceback.format_exc(),
        }), flush=True)


if __name__ == "__main__":
    main()

