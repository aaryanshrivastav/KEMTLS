from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


def _run_command(command: list[str]) -> Optional[str]:
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return None
    output = completed.stdout.strip() or completed.stderr.strip()
    return output or None


def _detect_host_type() -> str:
    if os.name == "nt":
        return "windows"
    kernel = platform.release().lower()
    if "microsoft" in kernel or os.environ.get("WSL_DISTRO_NAME"):
        return "windows+wsl2"
    virt = _run_command(["systemd-detect-virt"])
    if virt and virt not in {"none", ""}:
        return "linux_vm"
    return "linux_native"


def _get_distro_info() -> Dict[str, Any]:
    if hasattr(platform, "freedesktop_os_release"):
        try:
            return platform.freedesktop_os_release()
        except OSError:
            pass
    return {}


def _get_cpu_model() -> str:
    if os.name == "nt":
        return platform.processor() or "unknown"

    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.exists():
        for line in cpuinfo.read_text(encoding="utf-8", errors="ignore").splitlines():
            if line.lower().startswith("model name"):
                return line.split(":", 1)[1].strip()

    return platform.processor() or "unknown"


def _get_total_memory_bytes() -> Optional[int]:
    try:
        import psutil  # type: ignore

        return int(psutil.virtual_memory().total)
    except Exception:
        pass

    if hasattr(os, "sysconf") and "SC_PHYS_PAGES" in os.sysconf_names and "SC_PAGE_SIZE" in os.sysconf_names:
        try:
            return int(os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE"))
        except (OSError, ValueError):
            return None

    return None


def _get_package_version(package_name: str) -> Optional[str]:
    try:
        from importlib.metadata import version

        return version(package_name)
    except Exception:
        return None


def _get_oqs_version() -> Optional[str]:
    try:
        import oqs  # type: ignore

        return getattr(oqs, "oqs_version", lambda: None)()
    except Exception:
        return None


def _config_hash(config_path: Optional[Path]) -> Optional[str]:
    if config_path is None or not config_path.exists():
        return None
    return hashlib.sha256(config_path.read_bytes()).hexdigest()


def collect_snapshot(
    *,
    results_dir: Path,
    run_id: str,
    environment_profile: str,
    config_path: Optional[Path] = None,
) -> Dict[str, Any]:
    data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "environment_profile": environment_profile,
        "host_type": _detect_host_type(),
        "distro": _get_distro_info(),
        "kernel_version": platform.release(),
        "python_version": sys.version,
        "cryptography_version": _get_package_version("cryptography"),
        "liboqs_version": _get_oqs_version(),
        "cpu_model": _get_cpu_model(),
        "core_count": os.cpu_count(),
        "visible_ram_bytes": _get_total_memory_bytes(),
        "docker_version": _run_command(["docker", "--version"]),
        "git_commit": _run_command(["git", "rev-parse", "HEAD"]),
        "benchmark_config_hash": _config_hash(config_path),
        "tc_netem_active": _run_command(["tc", "qdisc", "show"]),
    }

    run_dir = results_dir / "raw" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    out_path = run_dir / "env_snapshot.json"
    out_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"[*] Environment snapshot saved to {out_path}")
    return data


def main() -> None:
    parser = argparse.ArgumentParser(description="Capture benchmark environment metadata")
    parser.add_argument("--results-dir", default="../results")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--environment-profile", default="wsl2_loopback")
    parser.add_argument("--config", default="../config.json")
    parser.add_argument("--repeat", type=int, default=None)
    parser.add_argument("--warmup", type=int, default=None)
    args = parser.parse_args()

    base_dir = Path(__file__).resolve().parent
    results_dir = (base_dir / args.results_dir).resolve()
    config_path = (base_dir / args.config).resolve() if args.config else None
    collect_snapshot(
        results_dir=results_dir,
        run_id=args.run_id,
        environment_profile=args.environment_profile,
        config_path=config_path,
    )


if __name__ == "__main__":
    main()
