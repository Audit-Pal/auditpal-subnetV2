# ── terminal colours ──────────────────────────────────────────────────────────
# The MIT License (MIT)
# Copyright © 2023 Yuma Rao
# Copyright © 2025 AuditPal

import asyncio
import io
import json
import os
import re
import subprocess
import tarfile
import tempfile
import time
from pathlib import Path
from typing import Optional

import bittensor as bt
import docker
import httpx
from pydantic import ValidationError

from auditing.models import AuditReport, Challenge


_R = "\033[0m"
_B = "\033[1m"
_G = "\033[92m"
_Y = "\033[93m"
_E = "\033[91m"
_C = "\033[96m"
_D = "\033[2m"

def _ok(m):   print(f"{_G}  ✓  {m}{_R}")
def _info(m): print(f"{_C}  →  {m}{_R}")
def _warn(m): print(f"{_Y}  ⚠  {m}{_R}")
def _err(m):  print(f"{_E}  ✗  {m}{_R}")
def _dim(m):  print(f"{_D}      {m}{_R}")
def _step(m): print(f"\n{_B}{_C}{'─'*60}{_R}\n{_B}  {m}{_R}")


def _extract_json_blob(text: str) -> str:
    decoder = json.JSONDecoder()
    candidates: list[tuple[int, str]] = []

    for match in re.finditer(r"[\{\[]", text):
        start = match.start()
        try:
            parsed, _ = decoder.raw_decode(text[start:])
        except json.JSONDecodeError:
            continue

        if isinstance(parsed, list):
            parsed = {"findings": parsed}
        if isinstance(parsed, dict):
            candidates.append((start, json.dumps(parsed)))

    if not candidates:
        return text

    _REQUIRED = {"challenge_id", "project_id", "findings"}

    def _score(c: str) -> int:
        try:
            p = json.loads(c)
            return sum(1 for k in _REQUIRED if k in p)
        except Exception:
            return 0

    best = max(candidates, key=lambda item: (_score(item[1]), -item[0]))
    return best[1]


class SandboxRunner:
    """
    Runs one Docker container per miner on the VALIDATOR machine.

    Lifecycle per miner:
      1. git clone miner repo on host  (network OK — before container starts)
      2. download challenge tarball     (network OK — before container starts)
      3. docker run                     (network=none, read-only, tmpfs /tmp)
      4. wait up to SANDBOX_TIMEOUT_S
      5. read report JSON from container stdout
      6. container.remove(force=True)   (always — even on failure)
    """

    IMAGE_NAME        = "my-test-agent:latest"
    CLONE_TIMEOUT_S   = 60
    SANDBOX_TIMEOUT_S = int(os.getenv("SANDBOX_TIMEOUT", "120"))   # bumped 100→120
    MAX_CONCURRENT    = int(os.getenv("MAX_CONCURRENT_SANDBOXES", "8"))
    SANDBOX_NETWORK   = os.getenv("SANDBOX_NETWORK", "bridge")

    def __init__(self):
        self.client = docker.from_env()
        self._semaphore: Optional[asyncio.Semaphore] = None
        print(f"\n{_B}[SandboxRunner] Initialised{_R}")
        _dim(f"image          : {self.IMAGE_NAME}")
        _dim(f"timeout        : {self.SANDBOX_TIMEOUT_S}s")
        _dim(f"max concurrent : {self.MAX_CONCURRENT}")
        _dim(f"network        : {self.SANDBOX_NETWORK}")

    # ── public API ────────────────────────────────────────────────────────────

    def build_image(self, dockerfile_dir: str = "agent/") -> None:
        """Build the base sandbox image. Call once in Validator.__init__()."""
        _step(f"Building Docker image: {self.IMAGE_NAME}")
        _info(f"Dockerfile dir: {dockerfile_dir}")
        t0 = time.time()
        self.client.images.build(path=dockerfile_dir, tag=self.IMAGE_NAME, rm=True)
        _ok(f"Image built in {time.time() - t0:.1f}s")

    async def run_all(
        self,
        repo_urls: list[Optional[str]],
        challenge: Challenge,
    ) -> list[Optional[AuditReport]]:
        _step("DEBUG: Challenge object received")
        _info(f"Challenge type       : {type(challenge)}")
        _info(f"Challenge name       : {getattr(challenge, 'name', 'NOT FOUND')}")
        _info(f"Challenge project_id : {getattr(challenge, 'project_id', 'NOT FOUND')}")

        try:
            challenge_id = challenge.id
            _info(f"challenge.id         : {challenge_id}")
        except AttributeError:
            try:
                challenge_id = challenge._id
                _info(f"challenge._id        : {challenge_id}")
            except AttributeError:
                challenge_id = "UNKNOWN"
                _warn("Could not read challenge id")

        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self.MAX_CONCURRENT)

        valid_miners = [(i, url) for i, url in enumerate(repo_urls) if url]

        total     = len(repo_urls)
        responded = len(valid_miners)
        skipped   = total - responded

        _step("run_all — starting parallel sandbox execution")
        _info(f"Total miners    : {total}")
        _info(f"Responded       : {responded}")
        _info(f"Skipped (no URL): {skipped}")
        _info(f"Challenge       : {challenge.name}  ({challenge.project_id})")
        _info(f"Codebases       : {len(challenge.codebases)}")
        print()

        loop = asyncio.get_running_loop()
        t0   = time.time()

        async def _run_one(idx: int, repo_url: str) -> Optional[AuditReport]:
            short = repo_url.rstrip("/").split("/")[-1]
            _info(f"[miner {idx}] Launching sandbox → {short}")
            async with self._semaphore:
                result = await loop.run_in_executor(
                    None, self._run_sync, idx, repo_url, challenge
                )
                if result is None:
                    _err(f"[miner {idx}] No report produced")
                else:
                    _ok(f"[miner {idx}] {len(result.findings)} finding(s) returned")
            return result

        results = await asyncio.gather(
            *[_run_one(idx, url) for idx, url in valid_miners],
            return_exceptions=False,
        )

        elapsed   = time.time() - t0
        succeeded = sum(1 for r in results if r is not None)
        failed    = len(valid_miners) - succeeded

        print()
        _step("run_all — finished")
        _ok(f"Succeeded : {succeeded} / {len(valid_miners)}")
        (_err if failed else _ok)(f"Failed    : {failed} / {len(valid_miners)}")
        _info(f"Skipped   : {skipped}")
        _info(f"Wall time : {elapsed:.1f}s")

        full_results: list[Optional[AuditReport]] = [None] * total
        for (idx, _), res in zip(valid_miners, results):
            full_results[idx] = res

        return full_results

    def _run_sync(
        self,
        idx: int,
        repo_url: str,
        challenge: Challenge,
    ) -> Optional[AuditReport]:
        tag = f"[miner {idx}]"
        container = None

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path      = Path(tmp)
            agent_dir     = tmp_path / "agent"
            challenge_dir = tmp_path / "challenge"
            challenge_dir.mkdir()

            # step 1 ── clone
            print(f"\n{tag} ── Step 1/5: git clone")
            if not self._clone_repo(tag, repo_url, agent_dir):
                return None

            # step 2 ── challenge files
            print(f"\n{tag} ── Step 2/5: download challenge files")
            if not self._prepare_challenge(tag, challenge, challenge_dir):
                return None

            # step 3 ── start container
            print(f"\n{tag} ── Step 3/5: start Docker container")
            try:
                container = self._run_container(agent_dir, challenge_dir, challenge)
                _ok(f"{tag} Container started: {container.short_id}")
                _dim(f"{tag} Flags: read-only FS | 2 GB RAM | 1 vCPU | network=none")
            except Exception as exc:
                _err(f"{tag} Failed to start container: {exc}")
                return None

            # step 4 ── wait
            print(f"\n{tag} ── Step 4/5: waiting up to {self.SANDBOX_TIMEOUT_S}s")
            t0 = time.time()
            try:
                result    = container.wait(timeout=self.SANDBOX_TIMEOUT_S)
                exit_code = result.get("StatusCode", -1)
                elapsed   = time.time() - t0
                ((_ok if exit_code == 0 else _warn))(
                    f"{tag} Container exited {exit_code} in {elapsed:.1f}s"
                )
            except Exception:
                _err(f"{tag} TIMEOUT after {time.time() - t0:.0f}s — killing container")
                try:
                    container.kill()
                except Exception:
                    pass
                self._cleanup(tag, container)
                return None

            # step 5 ── read report from stdout
            print(f"\n{tag} ── Step 5/5: read report from container stdout")
            report = self._extract_report(tag, container, challenge)
            self._cleanup(tag, container)
            return report

    def _clone_repo(self, tag: str, repo_url: str, dest: Path) -> bool:
        _info(f"{tag} git clone --depth 1  {repo_url}")
        t0 = time.time()
        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", "--single-branch", repo_url, str(dest)],
                check=True,
                timeout=self.CLONE_TIMEOUT_S,
                capture_output=True,
                text=True,
            )
            elapsed = time.time() - t0
            _ok(f"{tag} Cloned in {elapsed:.1f}s")

            all_files = list(dest.rglob("*"))
            sol_count = sum(1 for f in all_files if f.suffix == ".sol")
            py_count  = sum(1 for f in all_files if f.suffix == ".py")
            _dim(f"{tag} {len(all_files)} files total | {sol_count} .sol | {py_count} .py")

            if (dest / "agent.py").exists():
                _ok(f"{tag} agent.py found at repo root ✓")
            else:
                _warn(f"{tag} agent.py NOT found at repo root!")
                _dim(f"{tag} Root contents: {[f.name for f in dest.iterdir()]}")

            return True

        except subprocess.TimeoutExpired:
            _err(f"{tag} Clone timed out after {self.CLONE_TIMEOUT_S}s")
        except subprocess.CalledProcessError as exc:
            _err(f"{tag} Clone failed:\n{exc.stderr.strip()}")
        return False

    def _prepare_challenge(self, tag: str, challenge: Challenge, dest: Path) -> bool:
        prepared = 0
        for cb in challenge.codebases:
            _info(f"{tag} Codebase: {cb.codebase_id}")
            if not cb.tarball_url:
                _warn(f"{tag} No tarball_url — skipping codebase")
                continue
            try:
                _dim(f"{tag} GET {cb.tarball_url[:80]}...")
                t0   = time.time()
                resp = httpx.get(cb.tarball_url, follow_redirects=True, timeout=60)
                resp.raise_for_status()
                size_kb = len(resp.content) / 1024
                _ok(f"{tag} Downloaded {size_kb:.1f} KB in {time.time() - t0:.1f}s")

                cb_dir = dest / cb.codebase_id
                cb_dir.mkdir(exist_ok=True)

                with tarfile.open(fileobj=io.BytesIO(resp.content)) as tar:
                    sol_members = [
                        m for m in tar.getmembers()
                        if m.name.endswith(".sol") and m.isfile()
                    ]
                    for m in sol_members:
                        m.name = Path(m.name).name
                        tar.extract(m, path=cb_dir)

                sols = list(cb_dir.glob("*.sol"))
                _ok(f"{tag} {len(sols)} .sol file(s) extracted → /challenge/{cb.codebase_id}/")
                for sol in sorted(sols):
                    _dim(f"{tag}   {sol.name}  ({sol.stat().st_size / 1024:.1f} KB)")
                prepared += 1

            except httpx.HTTPStatusError as exc:
                _err(f"{tag} HTTP {exc.response.status_code} fetching tarball")
            except Exception as exc:
                _err(f"{tag} Failed to prepare codebase: {exc}")

        if prepared == 0:
            _err(f"{tag} No codebases prepared — aborting")
        else:
            _ok(f"{tag} {prepared}/{len(challenge.codebases)} codebase(s) ready")
        return prepared > 0

    def _run_container(
        self,
        agent_dir: Path,
        challenge_dir: Path,
        challenge: Challenge,
    ) -> "docker.models.containers.Container":
        try:
            challenge_id = challenge.id
        except AttributeError:
            try:
                challenge_id = challenge._id
            except AttributeError:
                challenge_id = "UNKNOWN"

        _dim(f"Using challenge_id: {challenge_id}")

        env = {
            "CHALLENGE_ID":   challenge_id,
            "PROJECT_ID":     challenge.project_id,
            "CHALLENGE_NAME": challenge.name,
            "PLATFORM":       challenge.platform,
            "GEMINI_API_KEY": os.environ.get("GEMINI_API_KEY", ""),
            # ── Fix: tell runner.py where agent.py is mounted ────────────────
            "AGENT_PATH":     "/miner_agent",
        }

        _dim(f"  env keys : {list(env.keys())}")
        _dim(f"  volumes  : {agent_dir} → /miner_agent (ro)")
        _dim(f"  volumes  : {challenge_dir} → /challenge (ro)")

        return self.client.containers.run(
            image=self.IMAGE_NAME,
            detach=True,
            volumes={
                str(agent_dir):     {"bind": "/miner_agent", "mode": "ro"},
                str(challenge_dir): {"bind": "/challenge",   "mode": "ro"},
            },
            tmpfs={
                "/tmp": "size=128m,mode=1777",
            },
            environment=env,
            network=self.SANDBOX_NETWORK,
            read_only=True,
            cap_drop=["ALL"],
            security_opt=["no-new-privileges"],
            cpu_quota=100_000,
            mem_limit="2g",
            memswap_limit="2g",
        )

    def _extract_report(
        self,
        tag: str,
        container: "docker.models.containers.Container",
        challenge: Challenge,
    ) -> Optional[AuditReport]:
        raw = ""
        try:
            stdout = container.logs(stdout=True, stderr=False).decode("utf-8", errors="replace").strip()
            stderr = container.logs(stdout=False, stderr=True).decode("utf-8", errors="replace").strip()

            # Always dump stderr — this is all the agent/runner debug output
            if stderr:
                print(f"\n{_D}  ╔── container stderr ──╗{_R}")
                for line in stderr.splitlines():
                    _dim(f"{tag}   {line}")
                print(f"{_D}  ╚──────────────────────╝{_R}\n")
            else:
                _warn(f"{tag} Container stderr was empty — agent may have crashed before logging")

            print(f"\n{_D}  ╔── container stdout (raw) ──╗{_R}")
            for line in stdout.splitlines():
                _dim(f"{tag}   {line}")
            print(f"{_D}  ╚────────────────────────────╝{_R}\n")

            if not stdout:
                _err(f"{tag} Container produced no stdout")
                _err(f"{tag} Likely causes: agent.py not found, import error, or Gemini API key missing")
                return None

            raw = _extract_json_blob(stdout)

            _ok(f"{tag} JSON blob extracted ({len(raw)} chars)")

            preview = raw[:500] + ("..." if len(raw) > 500 else "")
            print(f"\n{_D}  ╔── report preview ──╗{_R}")
            for line in preview.splitlines():
                _dim(f"{tag}   {line}")
            print(f"{_D}  ╚────────────────────╝{_R}\n")

            data   = json.loads(raw)

            # ── Warn if runner returned an error report ───────────────────────
            if "_runner_error" in data:
                _warn(f"{tag} runner.py reported an error: {data['_runner_error']}")

            report = AuditReport.model_validate(data)

            _ok(f"{tag} Schema validation passed ✓")
            _info(f"{tag} challenge_id : {report.challenge_id}")
            _info(f"{tag} project_id   : {report.project_id}")
            _info(f"{tag} findings     : {len(report.findings)}")
            print()

            sev_map = {"high": _E, "medium": _Y, "low": _C, "info": _D}
            sev_counts: dict[str, int] = {}
            for finding in report.findings:
                sev = finding.severity.lower()
                sev_counts[sev] = sev_counts.get(sev, 0) + 1
                colour = sev_map.get(sev, _D)
                print(
                    f"  {colour}[{sev.upper():6}]{_R} "
                    f"{_D}{finding.file}{_R} | "
                    f"{finding.vulnerability_type} | "
                    f"{finding.title[:55]}"
                )

            print()
            _info(f"{tag} Breakdown → " + "  ".join(f"{k}={v}" for k, v in sev_counts.items()))
            return report

        except json.JSONDecodeError as exc:
            _err(f"{tag} Invalid JSON in stdout: {exc}")
            _dim(f"{tag} Raw stdout (first 500 chars): {stdout[:500]}")

        except ValidationError as exc:
            _err(f"{tag} Schema validation failed:")
            for e in exc.errors():
                _dim(f"{tag}   {e['loc']} → {e['msg']}")

        except Exception as exc:
            _err(f"{tag} Unexpected error extracting report: {exc}")

        return None

    def _cleanup(
        self,
        tag: str,
        container: Optional["docker.models.containers.Container"],
    ) -> None:
        if container is None:
            return
        try:
            container.remove(force=True)
            _ok(f"{tag} Container {container.short_id} destroyed")
        except Exception as exc:
            _warn(f"{tag} Could not remove container: {exc}")