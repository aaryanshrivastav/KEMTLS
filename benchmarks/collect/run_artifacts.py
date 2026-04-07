from __future__ import annotations

import argparse
import csv
import json
import uuid
from pathlib import Path
from typing import Any, Dict, List

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT_DIR = SCRIPT_DIR.parent.parent


def _load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _jwt_piece_len(token: str, idx: int) -> int:
    parts = token.split(".")
    if len(parts) <= idx:
        return 0
    return len(parts[idx])


def run(config: Dict[str, Any]) -> Path:
    run_id = str(config.get("run_id") or uuid.uuid4().hex[:8])
    environment_profile = str(config.get("environment_profile", "wsl2_loopback"))
    results_dir = Path(config.get("results_dir", "benchmarks/results"))
    raw_dir = results_dir / "raw" / run_id
    raw_dir.mkdir(parents=True, exist_ok=True)

    oidc_summary = _load_json(raw_dir / "oidc_summary.json")
    oidc_rows_path = raw_dir / "oidc_results.csv"

    artifacts: List[Dict[str, Any]] = []
    if oidc_rows_path.exists():
        with oidc_rows_path.open("r", encoding="utf-8", newline="") as fh:
            import csv as _csv
            reader = _csv.DictReader(fh)
            for row in reader:
                artifacts.append(
                    {
                        "run_id": run_id,
                        "scenario": row.get("scenario", ""),
                        "s_id_token_bytes": int(float(row.get("s_id_token_bytes", 0))),
                        "s_id_token_header": int(float(row.get("s_id_token_header", 0))),
                        "s_id_token_payload": int(float(row.get("s_id_token_payload", 0))),
                        "s_id_token_sig": int(float(row.get("s_id_token_sig", 0))),
                        "s_access_token_bytes": int(float(row.get("s_access_token_bytes", 0))),
                        "s_refresh_token_bytes": int(float(row.get("s_refresh_token_bytes", 0))),
                        "s_total_request_bytes": int(float(row.get("s_total_request_bytes", 0))),
                        "s_total_response_bytes": int(float(row.get("s_total_response_bytes", 0))),
                        "environment_profile": environment_profile,
                    }
                )

    out_csv = raw_dir / "artifacts_results.csv"
    with out_csv.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=[
                "run_id",
                "scenario",
                "s_id_token_bytes",
                "s_id_token_header",
                "s_id_token_payload",
                "s_id_token_sig",
                "s_access_token_bytes",
                "s_refresh_token_bytes",
                "s_total_request_bytes",
                "s_total_response_bytes",
                "environment_profile",
            ],
        )
        writer.writeheader()
        writer.writerows(artifacts)

    (raw_dir / "artifacts_summary.json").write_text(
        json.dumps({"rows": len(artifacts), "oidc_summary_present": bool(oidc_summary)}, indent=2),
        encoding="utf-8",
    )
    print(f"[*] Artifact benchmarks saved to {out_csv}")
    return out_csv


def main() -> None:
    parser = argparse.ArgumentParser(description="Collect token and protocol artifact sizes")
    parser.add_argument("--config", default="../config.json")
    parser.add_argument("--results-dir", default=None)
    parser.add_argument("--run-id", default=None)
    parser.add_argument("--repeat", type=int, default=None)
    parser.add_argument("--warmup", type=int, default=None)
    parser.add_argument("--environment-profile", default=None)
    args = parser.parse_args()

    config_path = (SCRIPT_DIR / args.config).resolve()
    config = _load_json(config_path)
    if args.results_dir is not None:
        config["results_dir"] = args.results_dir
    if args.run_id is not None:
        config["run_id"] = args.run_id
    if args.repeat is not None:
        config["repeat"] = args.repeat
    if args.warmup is not None:
        config["warmup"] = args.warmup
    if args.environment_profile is not None:
        config["environment_profile"] = args.environment_profile

    run(config)


if __name__ == "__main__":
    main()
