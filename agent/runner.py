import json
import os
import traceback
import importlib.util
from pathlib import Path

AGENT_PATH = "/agent/agent.py"
CHALLENGE_DIR = "/challenge"


def load_agent():
    spec = importlib.util.spec_from_file_location("agent", AGENT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_challenge():
    contracts = {}

    for path in Path(CHALLENGE_DIR).rglob("*.sol"):
        try:
            contracts[str(path)] = path.read_text()
        except Exception:
            pass

    return {
        "challenge_id": os.getenv("CHALLENGE_ID", ""),
        "project_id": os.getenv("PROJECT_ID", ""),
        "contracts": contracts,
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