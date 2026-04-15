import importlib.util
import os
import tempfile
from pathlib import Path


RUNNER_PATH = Path(__file__).resolve().parent.parent / "agent" / "runner.py"
spec = importlib.util.spec_from_file_location("auditpal_agent_runner", RUNNER_PATH)
assert spec is not None and spec.loader is not None
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def test_resolve_agent_path_prefers_configured_mount():
    with tempfile.TemporaryDirectory() as tmp:
        mounted_root = Path(tmp) / "miner_agent"
        default_root = Path(tmp) / "agent"
        mounted_root.mkdir()
        default_root.mkdir()
        (mounted_root / "agent.py").write_text("def agent_main(task): return task\n", encoding="utf-8")
        (default_root / "agent.py").write_text("def agent_main(task): return {'wrong': True}\n", encoding="utf-8")

        original_mounted_root = runner.MOUNTED_AGENT_ROOT
        original_default_root = runner.DEFAULT_AGENT_ROOT
        original_env = os.environ.get("AGENT_PATH")
        try:
            runner.MOUNTED_AGENT_ROOT = str(mounted_root)
            runner.DEFAULT_AGENT_ROOT = str(default_root)
            os.environ["AGENT_PATH"] = str(mounted_root)

            assert runner.resolve_agent_path() == str(mounted_root / "agent.py")
        finally:
            runner.MOUNTED_AGENT_ROOT = original_mounted_root
            runner.DEFAULT_AGENT_ROOT = original_default_root
            if original_env is None:
                os.environ.pop("AGENT_PATH", None)
            else:
                os.environ["AGENT_PATH"] = original_env


def test_resolve_agent_path_falls_back_to_default_agent():
    with tempfile.TemporaryDirectory() as tmp:
        default_root = Path(tmp) / "agent"
        default_root.mkdir()
        (default_root / "agent.py").write_text("def agent_main(task): return task\n", encoding="utf-8")

        original_mounted_root = runner.MOUNTED_AGENT_ROOT
        original_default_root = runner.DEFAULT_AGENT_ROOT
        original_env = os.environ.get("AGENT_PATH")
        try:
            runner.MOUNTED_AGENT_ROOT = str(Path(tmp) / "missing_mount")
            runner.DEFAULT_AGENT_ROOT = str(default_root)
            os.environ.pop("AGENT_PATH", None)

            assert runner.resolve_agent_path() == str(default_root / "agent.py")
        finally:
            runner.MOUNTED_AGENT_ROOT = original_mounted_root
            runner.DEFAULT_AGENT_ROOT = original_default_root
            if original_env is None:
                os.environ.pop("AGENT_PATH", None)
            else:
                os.environ["AGENT_PATH"] = original_env
