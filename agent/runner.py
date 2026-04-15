import json
import os
import traceback
import importlib.util
from pathlib import Path

DEFAULT_AGENT_ROOT = "/agent"
MOUNTED_AGENT_ROOT = "/miner_agent"
CHALLENGE_DIR = "/challenge"


def resolve_agent_path() -> str:
    configured_root = os.getenv("AGENT_PATH", "").rstrip("/")
    candidate_roots = [root for root in (configured_root, MOUNTED_AGENT_ROOT, DEFAULT_AGENT_ROOT) if root]

    for root in candidate_roots:
        agent_file = Path(root) / "agent.py"
        if agent_file.exists():
            return str(agent_file)

    return str(Path(DEFAULT_AGENT_ROOT) / "agent.py")


def load_agent():
    miner = Path("/miner_agent/agent.py")
    # default = Path("/agent/agent.py")

    path = miner 

    print(f"[DEBUG] Using: {path}", flush=True)

    spec = importlib.util.spec_from_file_location("agent", str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    return module


def load_challenge():
    """Load actual challenge files from /challenge directory prepared by sandbox"""
    contracts = {}
    challenge_dir = Path(CHALLENGE_DIR)
    
    # Debug: Print all environment variables
    print(f"Environment variables:", flush=True)
    print(f"CHALLENGE_ID: {os.getenv('CHALLENGE_ID', 'NOT SET')}", flush=True)
    print(f"PROJECT_ID: {os.getenv('PROJECT_ID', 'NOT SET')}", flush=True)
    print(f"CHALLENGE_NAME: {os.getenv('CHALLENGE_NAME', 'NOT SET')}", flush=True)
    print(f"PLATFORM: {os.getenv('PLATFORM', 'NOT SET')}", flush=True)
    
    if not challenge_dir.exists():
        print(f"Challenge directory {CHALLENGE_DIR} not found", flush=True)
        return {
            "challenge_id": os.getenv("CHALLENGE_ID", "error"),
            "project_id":   os.getenv("PROJECT_ID",   "error"),
            "contracts":    {},
        }
    
    # Read all .sol files from all codebase subdirectories
    for codebase_dir in challenge_dir.iterdir():
        if codebase_dir.is_dir():
            for sol_file in codebase_dir.glob("*.sol"):
                try:
                    contracts[sol_file.name] = sol_file.read_text(encoding="utf-8", errors="ignore")
                    print(f"Loaded contract: {sol_file.name} from {codebase_dir.name}", flush=True)
                except Exception as e:
                    print(f"Failed to read {sol_file}: {e}", flush=True)
    
    if not contracts:
        print(f"No .sol files found in {CHALLENGE_DIR}", flush=True)
        return {
            "challenge_id": os.getenv("CHALLENGE_ID", "error"),
            "project_id":   os.getenv("PROJECT_ID",   "error"),
            "contracts":    {},
        }

    print(f"Loaded {len(contracts)} contract(s) from challenge", flush=True)
    return {
        "challenge_id": os.getenv("CHALLENGE_ID", "unknown"),
        "project_id":   os.getenv("PROJECT_ID",   "unknown"),
        "contracts":    contracts,
    }


def main():
    try:
        agent = load_agent()

        if not hasattr(agent, "agent_main"):
            raise Exception("agent_main(task) not found in agent.py")

        task = load_challenge()

        result = agent.agent_main(task)

        # ✅ MUST BE PURE JSON (no logs)
        print(json.dumps(result))

    except Exception as e:
        print(json.dumps({
            "status": "error",
            "error": str(e),
            "trace": traceback.format_exc()
        }))


if __name__ == "__main__":
    main()
