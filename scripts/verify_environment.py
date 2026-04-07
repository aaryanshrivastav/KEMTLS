#!/usr/bin/env python3
"""Environment readiness checks for tests and benchmarks."""

from __future__ import annotations

import argparse
import importlib
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Tuple

ROOT_DIR = Path(__file__).resolve().parent.parent
SRC_DIR = ROOT_DIR / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


def _ok(message: str) -> None:
    print(f"[OK] {message}")


def _warn(message: str) -> None:
    print(f"[WARN] {message}")


def _fail(message: str) -> None:
    print(f"[FAIL] {message}")


def _check_python_version() -> Tuple[bool, str]:
    version = sys.version_info
    if version < (3, 9):
        return False, f"Python {version.major}.{version.minor} is unsupported (need >= 3.9)."
    return True, f"Python {version.major}.{version.minor}.{version.micro}"


def _check_import(module_name: str) -> Tuple[bool, str]:
    try:
        importlib.import_module(module_name)
        return True, module_name
    except Exception as exc:
        return False, f"{module_name}: {exc}"


def _check_oqs_mechanisms() -> Tuple[bool, str]:
    try:
        import oqs  # type: ignore

        get_kems = getattr(oqs, "get_enabled_kem_mechanisms", None) or getattr(
            oqs, "get_enabled_KEM_mechanisms", None
        )
        get_sigs = getattr(oqs, "get_enabled_sig_mechanisms", None)
        if get_kems is None or get_sigs is None:
            return False, "oqs API missing enabled mechanism introspection functions"

        kems = set(get_kems())
        sigs = set(get_sigs())
        if "ML-KEM-768" not in kems:
            return False, "liboqs missing ML-KEM-768 support"
        if "ML-DSA-65" not in sigs:
            return False, "liboqs missing ML-DSA-65 support"
        return True, "liboqs exposes ML-KEM-768 and ML-DSA-65"
    except Exception as exc:
        return False, f"oqs capability check failed: {exc}"


def _check_crypto_smoke() -> Tuple[bool, str]:
    try:
        from crypto.aead import NONCE_SIZE, seal, open_
        from crypto.ml_dsa import MLDSA65
        from crypto.ml_kem import MLKEM768

        key = b"k" * 32
        nonce = b"n" * NONCE_SIZE
        aad = b"hdr"
        plaintext = b"ready"
        ciphertext = seal(key, nonce, plaintext, aad)
        recovered = open_(key, nonce, ciphertext, aad)
        if recovered != plaintext:
            return False, "AEAD round-trip mismatch"

        pk_kem, sk_kem = MLKEM768.generate_keypair()
        ct_kem, ss1 = MLKEM768.encapsulate(pk_kem)
        ss2 = MLKEM768.decapsulate(sk_kem, ct_kem)
        if ss1 != ss2:
            return False, "ML-KEM encapsulate/decapsulate mismatch"

        pk_sig, sk_sig = MLDSA65.generate_keypair()
        message = b"kemtls-env-check"
        sig = MLDSA65.sign(sk_sig, message)
        if not MLDSA65.verify(pk_sig, message, sig):
            return False, "ML-DSA sign/verify failed"

        return True, "AEAD + ML-KEM + ML-DSA smoke tests passed"
    except Exception as exc:
        return False, f"crypto smoke test failed: {exc}"


def _check_flask_imports() -> Tuple[bool, str]:
    required = ["flask", "flask_socketio"]
    failures: List[str] = []
    for module_name in required:
        ok, message = _check_import(module_name)
        if not ok:
            failures.append(message)
    if failures:
        return False, "; ".join(failures)
    return True, "Flask and Flask-SocketIO imports succeeded"


def _check_tool(name: str) -> Tuple[bool, str]:
    path = shutil.which(name)
    if path:
        return True, f"{name} at {path}"
    return False, f"{name} not found in PATH"


def _check_maturin_version() -> Tuple[bool, str]:
    try:
        completed = subprocess.run(
            [sys.executable, "-m", "maturin", "--version"],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            stderr = completed.stderr.strip() or completed.stdout.strip() or "unknown error"
            return False, f"maturin invocation failed: {stderr}"
        return True, completed.stdout.strip()
    except Exception as exc:
        return False, f"maturin check failed: {exc}"


def _check_pytest_collection() -> Tuple[bool, str]:
    try:
        completed = subprocess.run(
            [sys.executable, "-m", "pytest", "tests", "--collect-only", "-q"],
            cwd=ROOT_DIR,
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            detail = completed.stderr.strip() or completed.stdout.strip()
            return False, f"pytest collect failed: {detail}"
        return True, "pytest collection succeeded"
    except Exception as exc:
        return False, f"pytest collect check failed: {exc}"


def run_checks(strict: bool) -> int:
    print(f"[*] KEMTLS environment verification on {platform.system()} {platform.release()}")

    hard_checks = [
        ("python", _check_python_version),
        ("cryptography", lambda: _check_import("cryptography")),
        ("pqcrypto", lambda: _check_import("pqcrypto")),
        ("oqs", lambda: _check_import("oqs")),
        ("pytest", lambda: _check_import("pytest")),
        ("matplotlib", lambda: _check_import("matplotlib")),
        ("flask-stack", _check_flask_imports),
        ("oqs-capabilities", _check_oqs_mechanisms),
        ("crypto-smoke", _check_crypto_smoke),
        ("pytest-collect", _check_pytest_collection),
    ]

    soft_checks = [
        ("rustc", lambda: _check_tool("rustc")),
        ("cargo", lambda: _check_tool("cargo")),
        ("maturin", _check_maturin_version),
    ]

    failures = 0

    for name, fn in hard_checks:
        ok, message = fn()
        if ok:
            _ok(f"{name}: {message}")
        else:
            _fail(f"{name}: {message}")
            failures += 1

    for name, fn in soft_checks:
        ok, message = fn()
        if ok:
            _ok(f"{name}: {message}")
        else:
            _warn(f"{name}: {message}")
            if strict:
                failures += 1

    if failures:
        _fail(f"Environment not ready ({failures} failing checks).")
        return 1

    _ok("Environment is ready for tests and benchmarks.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify local environment for KEMTLS tests and benchmarks")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Treat Rust toolchain checks as required (useful when validating Rust extension build readiness).",
    )
    args = parser.parse_args()
    return run_checks(strict=args.strict)


if __name__ == "__main__":
    raise SystemExit(main())
