"""Benchmark orchestrator for real-data KEMTLS and OIDC benchmark collectors."""

from __future__ import annotations

import json
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any, Dict


SCRIPT_DIR = Path(__file__).resolve().parent
ROOT_DIR = SCRIPT_DIR.parent
CONFIG_PATH = SCRIPT_DIR / "config.json"


def _load_config() -> Dict[str, Any]:
    if not CONFIG_PATH.exists():
        return {}
    return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))


def _run_script(script_name: str, *, config_path: Path, results_dir: Path, run_id: str, environment_profile: str, repeat: int, warmup: int) -> None:
    script_path = SCRIPT_DIR / "collect" / script_name
    command = [
        sys.executable,
        str(script_path),
        "--config",
        str(config_path),
        "--results-dir",
        str(results_dir),
        "--run-id",
        str(run_id),
        "--environment-profile",
        environment_profile,
        "--repeat",
        str(repeat),
        "--warmup",
        str(warmup),
    ]
    print(f"[*] Running {script_name} for run_id={run_id}")
    subprocess.run(command, check=True, cwd=str(SCRIPT_DIR))


def main() -> None:
    config = _load_config()
    run_id = uuid.uuid4().hex[:8]
    environment_profile = str(config.get("environment_profile", "wsl2_loopback"))
    repeat = int(config.get("repeat", 1000))
    warmup = int(config.get("warmup", 50))
    results_dir = ROOT_DIR / str(config.get("results_dir", "benchmarks/results"))
    raw_run_dir = results_dir / "raw" / run_id
    raw_run_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 60)
    print("KEMTLS Research Benchmark Suite")
    print("=" * 60)
    print(f"[*] run_id={run_id}")
    print(f"[*] environment_profile={environment_profile}")
    print(f"[*] results_dir={results_dir}")

    _run_script(
        "env_snapshot.py",
        config_path=CONFIG_PATH,
        results_dir=results_dir,
        run_id=run_id,
        environment_profile=environment_profile,
        repeat=repeat,
        warmup=warmup,
    )
    suites = {str(item).lower() for item in config.get("suites", ["crypto", "handshake", "oidc"])}
    scripts_run = ["env_snapshot.py"]

    if "crypto" in suites:
        _run_script(
            "run_crypto.py",
            config_path=CONFIG_PATH,
            results_dir=results_dir,
            run_id=run_id,
            environment_profile=environment_profile,
            repeat=repeat,
            warmup=warmup,
        )
        scripts_run.append("run_crypto.py")

    if "handshake" in suites:
        _run_script(
            "run_handshake.py",
            config_path=CONFIG_PATH,
            results_dir=results_dir,
            run_id=run_id,
            environment_profile=environment_profile,
            repeat=repeat,
            warmup=warmup,
        )
        scripts_run.append("run_handshake.py")

    if "oidc" in suites:
        _run_script(
            "run_oidc.py",
            config_path=CONFIG_PATH,
            results_dir=results_dir,
            run_id=run_id,
            environment_profile=environment_profile,
            repeat=repeat,
            warmup=warmup,
        )
        scripts_run.append("run_oidc.py")
        _run_script(
            "run_artifacts.py",
            config_path=CONFIG_PATH,
            results_dir=results_dir,
            run_id=run_id,
            environment_profile=environment_profile,
            repeat=repeat,
            warmup=warmup,
        )
        scripts_run.append("run_artifacts.py")

    if "load" in suites:
        _run_script(
            "run_load.py",
            config_path=CONFIG_PATH,
            results_dir=results_dir,
            run_id=run_id,
            environment_profile=environment_profile,
            repeat=repeat,
            warmup=warmup,
        )
        scripts_run.append("run_load.py")

    if "rust_compare" in suites:
        _run_script(
            "run_rust_fallback_compare.py",
            config_path=CONFIG_PATH,
            results_dir=results_dir,
            run_id=run_id,
            environment_profile=environment_profile,
            repeat=repeat,
            warmup=warmup,
        )
        scripts_run.append("run_rust_fallback_compare.py")

    manifest = {
        "run_id": run_id,
        "environment_profile": environment_profile,
        "repeat": repeat,
        "warmup": warmup,
        "scripts": scripts_run,
        "results_dir": str(results_dir),
    }
    manifest_path = raw_run_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"[*] Manifest saved to {manifest_path}")
    if "load" not in suites:
        print("[*] Load suite skipped because it is not enabled in config.suites")


if __name__ == "__main__":
    main()
