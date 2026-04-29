#!/usr/bin/env python3
import json
import os
import sys
import traceback
import threading
from pathlib import Path
import importlib.util

# ── Paths ─────────────────────────────────────────────────────────────────────
AGENT_PATH    = Path(os.getenv("AGENT_PATH", "/miner_agent")) / "agent.py"
CHALLENGE_DIR = Path("/challenge")

# Pipeline modules baked into the Docker image at /app/
PIPELINE_DIR  = Path("/app")

# Deadline: runner enforces this — miner's agent_main must return before it
RUNNER_DEADLINE_S = int(os.getenv("RUNNER_DEADLINE_S", "150"))


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, flush=True, **kwargs)

def _section(msg):
    eprint(f"[runner] ── {msg} {'─' * (50 - len(msg))}")


# ════════════════════════════════════════════════════════════════════════════════
# Agent loader
# ════════════════════════════════════════════════════════════════════════════════

def load_agent():
    _section("Loading miner agent")
    eprint(f"[runner] AGENT_PATH: {AGENT_PATH}")

    if not AGENT_PATH.exists():
        eprint(f"[runner] ✗ agent.py NOT found at {AGENT_PATH}")
        parent = AGENT_PATH.parent
        if parent.exists():
            eprint(f"[runner] Contents of {parent}:")
            for p in sorted(parent.rglob("*"))[:30]:
                eprint(f"[runner]   {p.relative_to(parent)}")
        else:
            eprint(f"[runner] Parent dir {parent} does not exist either")
        raise FileNotFoundError(f"agent.py not found at {AGENT_PATH}")

    eprint(f"[runner] agent.py found ✓")

    spec   = importlib.util.spec_from_file_location("miner_agent", str(AGENT_PATH))
    module = importlib.util.module_from_spec(spec)

    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        eprint(f"[runner] ✗ Import error in agent.py: {exc}")
        eprint(traceback.format_exc())
        raise ImportError(f"agent.py failed to import: {exc}") from exc

    if not hasattr(module, "agent_main"):
        raise AttributeError(
            "agent_main(task) not found in agent.py — see MINER_README.md"
        )

    eprint("[runner] agent_main() found ✓")
    return module


# ════════════════════════════════════════════════════════════════════════════════
# Challenge loader
# ════════════════════════════════════════════════════════════════════════════════

def load_challenge() -> dict:
    _section("Loading challenge")
    contracts: dict[str, str] = {}

    eprint(f"[runner] CHALLENGE_ID  : {os.getenv('CHALLENGE_ID')}")
    eprint(f"[runner] PROJECT_ID    : {os.getenv('PROJECT_ID')}")
    eprint(f"[runner] CHALLENGE_NAME: {os.getenv('CHALLENGE_NAME')}")
    eprint(f"[runner] PLATFORM      : {os.getenv('PLATFORM')}")
    eprint(f"[runner] GEMINI_API_KEY: {'SET ✓' if os.getenv('GEMINI_API_KEY') else 'MISSING ✗'}")

    if not CHALLENGE_DIR.exists():
        eprint(f"[runner] ✗ /challenge directory does not exist!")
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
                eprint(f"[runner] ✗ Failed to read {sol_file}: {exc}")

    eprint(f"[runner] Total .sol files loaded: {len(contracts)}")
    return _make_task(contracts)


def _make_task(contracts: dict[str, str]) -> dict:
    return {
        "challenge_id": os.getenv("CHALLENGE_ID", "unknown"),
        "project_id":   os.getenv("PROJECT_ID",   "unknown"),
        "contracts":    contracts,
    }


# ════════════════════════════════════════════════════════════════════════════════
# Stage 1 + 2 — run by validator, results injected into task
# ════════════════════════════════════════════════════════════════════════════════

def run_pipeline_stages(task: dict) -> dict:
    """
    Run Stage 1 (static analysis) and Stage 2 (prioritize + group)
    using modules baked into the Docker image.
    Injects results into task dict so miner's agent_main() receives
    pre-computed intelligence without needing to import anything.
    """
    _section("Running Stage 1 — Static Analysis")

    # Ensure /app pipeline modules are importable
    if str(PIPELINE_DIR) not in sys.path:
        sys.path.insert(0, str(PIPELINE_DIR))

    contracts = task.get("contracts", {})

    if not contracts:
        eprint("[runner] No contracts — skipping Stage 1 + 2")
        task["stage1"] = {}
        task["stage2"] = []
        return task

    # ── Stage 1 ───────────────────────────────────────────────────────────────
    try:
        from stage1 import run_stage1
        stage1 = run_stage1(contracts)
        eprint(f"[runner] Stage 1 ✓ | "
               f"slither={stage1.get('slither_ok')} | "
               f"patterns={len(stage1.get('patterns', []))} | "
               f"suspects={len(stage1.get('reentrancy_suspects', []))} | "
               f"high_risk={stage1.get('summary', {}).get('high_risk_files', [])}")
    except Exception as exc:
        eprint(f"[runner] Stage 1 failed: {exc} — injecting empty stage1")
        eprint(traceback.format_exc())
        stage1 = {
            "ast": [], "patterns": [], "money_flows": [],
            "edges": [], "risk_scores": {f: 0 for f in contracts},
            "reentrancy_suspects": [], "external_calls": {},
            "slither_ok": False, "elapsed_s": 0,
            "summary": {
                "contracts": len(contracts),
                "high_risk_files": [],
                "total_patterns": 0,
                "total_flows": 0,
                "total_edges": 0,
            },
        }

    task["stage1"] = stage1

    # ── Stage 2 ───────────────────────────────────────────────────────────────
    _section("Running Stage 2 — Prioritize & Group")
    try:
        from stage2 import run_stage2
        stage2 = run_stage2(stage1, contracts)
        eprint(f"[runner] Stage 2 ✓ | {len(stage2)} session(s) planned")
        for s in stage2:
            eprint(f"[runner]   {s['session_id']}: "
                   f"files={s['cluster']} risk={s['risk_score']}")
    except Exception as exc:
        eprint(f"[runner] Stage 2 failed: {exc} — injecting single fallback session")
        eprint(traceback.format_exc())
        # Fallback: one session with everything
        all_files = list(contracts.keys())
        context   = "\n\n".join(
            f"=== {f} ===\n```solidity\n{contracts[f][:6000]}\n```"
            for f in all_files
        )
        stage2 = [{
            "session_id": "session-01",
            "cluster":    all_files,
            "risk_score": 0,
            "summary":    "Fallback session — Stage 2 error",
            "context":    context,
            "suspects":   [],
            "char_count": len(context),
            "truncated":  False,
        }]

    task["stage2"] = stage2
    return task


# ════════════════════════════════════════════════════════════════════════════════
# Deadline-enforced agent call
# ════════════════════════════════════════════════════════════════════════════════

class _AgentThread(threading.Thread):
    def __init__(self, module, task):
        super().__init__(daemon=True)
        self.module = module
        self.task   = task
        self.result = None
        self.error  = None

    def run(self):
        try:
            self.result = self.module.agent_main(self.task)
        except Exception as exc:
            self.error = (type(exc).__name__, str(exc), traceback.format_exc())


def call_agent_with_deadline(module, task: dict) -> dict:
    _section(f"Calling agent_main() — deadline {RUNNER_DEADLINE_S}s")
    eprint(f"[runner] Contracts    : {len(task.get('contracts', {}))}")
    eprint(f"[runner] Stage1 ok   : {task.get('stage1', {}).get('slither_ok', 'N/A')}")
    eprint(f"[runner] Sessions    : {len(task.get('stage2', []))}")

    thread = _AgentThread(module, task)
    import time
    t0 = time.time()
    thread.start()
    thread.join()
    elapsed = time.time() - t0

    if thread.is_alive():
        eprint(f"[runner] ✗ TIMEOUT — agent_main() did not finish in {RUNNER_DEADLINE_S}s")
        eprint(f"[runner]   MINER: add deadline checks — see MINER_README.md §Timing Budget")
        raise TimeoutError(
            f"agent_main() timed out after {RUNNER_DEADLINE_S}s"
        )

    if thread.error:
        exc_type, exc_msg, tb = thread.error
        eprint(f"[runner] ✗ agent_main() raised {exc_type}: {exc_msg}")
        eprint(f"[runner] Traceback:\n{tb}")
        raise RuntimeError(f"agent_main() raised {exc_type}: {exc_msg}")

    eprint(f"[runner] agent_main() returned in {elapsed:.1f}s ✓")

    result = thread.result
    eprint(f"[runner] Return type  : {type(result)}")

    if not isinstance(result, dict):
        raise TypeError(
            f"agent_main() must return a dict, got {type(result).__name__}"
        )

    eprint(f"[runner] Keys         : {list(result.keys())}")
    eprint(f"[runner] Findings     : {len(result.get('findings', []))}")
    eprint(f"[runner] challenge_id : {result.get('challenge_id')}")
    eprint(f"[runner] project_id   : {result.get('project_id')}")

    return result


# ════════════════════════════════════════════════════════════════════════════════
# Main
# ════════════════════════════════════════════════════════════════════════════════

def main():
    eprint("[runner] ════════════════════════════════════════════════")
    eprint("[runner] AuditPal Validator Runner starting")
    eprint(f"[runner] AGENT_PATH   : {AGENT_PATH}")
    eprint(f"[runner] CHALLENGE_DIR: {CHALLENGE_DIR}")
    eprint(f"[runner] PIPELINE_DIR : {PIPELINE_DIR}")
    eprint(f"[runner] DEADLINE     : {RUNNER_DEADLINE_S}s")
    eprint("[runner] ════════════════════════════════════════════════")

    try:
        # 1. Load miner's agent.py
        agent = load_agent()

        # 2. Load challenge contracts
        task = load_challenge()

        # 3. Run Stage 1 + 2 (validator-controlled) — inject into task
        task = run_pipeline_stages(task)

        # 4. Call miner's agent_main() with enriched task
        result = call_agent_with_deadline(agent, task)

        # 5. Write JSON to stdout (only line that touches stdout)
        print(json.dumps(result), flush=True)
        eprint("[runner] ✓ JSON written to stdout")

    except Exception as exc:
        eprint(f"[runner] ✗ FATAL: {type(exc).__name__}: {exc}")
        eprint(traceback.format_exc())

        error_report = {
            "challenge_id":  os.getenv("CHALLENGE_ID", "unknown"),
            "project_id":    os.getenv("PROJECT_ID",   "unknown"),
            "findings":      [],
            "_runner_error": f"{type(exc).__name__}: {exc}",
        }
        print(json.dumps(error_report), flush=True)
        sys.exit(1)


if __name__ == "__main__":
    main()