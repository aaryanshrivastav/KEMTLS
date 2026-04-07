#!/bin/bash
set -euo pipefail

PROFILE="linux_netem"
PROTOCOLS="kemtls,kemtls_pdk"
SUITES="crypto,handshake,oidc,load"
REPEAT="1000"
WARMUP="50"
SCENARIO_SET="all"

while [[ "$#" -gt 0 ]]; do
	case "$1" in
		--profile) PROFILE="$2"; shift 2 ;;
		--protocols) PROTOCOLS="$2"; shift 2 ;;
		--suites) SUITES="$2"; shift 2 ;;
		--repeat) REPEAT="$2"; shift 2 ;;
		--warmup) WARMUP="$2"; shift 2 ;;
		--scenario-set) SCENARIO_SET="$2"; shift 2 ;;
		*) echo "Unknown arg: $1"; exit 1 ;;
	esac
done

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root_dir="$(cd "$script_dir/../.." && pwd)"
cd "$root_dir"

if command -v python3 >/dev/null 2>&1; then
	PYTHON_BIN="python3"
else
	PYTHON_BIN="python"
fi

if [[ "$SCENARIO_SET" == "loopback" ]]; then
	scenarios=(LAN)
else
	scenarios=(LAN FAST_WAN TYPICAL_WAN SLOW_WAN LOSS_LOW LOSS_HIGH LOSS_SEVERE)
fi

CFG_PATH="benchmarks/config.json"
CFG_BACKUP="$(mktemp)"
cp "$CFG_PATH" "$CFG_BACKUP"

restore_config_and_netem() {
	cp "$CFG_BACKUP" "$CFG_PATH"
	rm -f "$CFG_BACKUP"
	bash benchmarks/setup_netem.sh clear >/dev/null 2>&1 || true
}
trap restore_config_and_netem EXIT

for scenario in "${scenarios[@]}"; do
	echo "[*] Running netem scenario: $scenario"
	bash benchmarks/setup_netem.sh apply "$scenario"

	PROFILE="$PROFILE" \
	PROTOCOLS="$PROTOCOLS" \
	SUITES="$SUITES" \
	REPEAT="$REPEAT" \
	WARMUP="$WARMUP" \
	SCENARIO_NAME="$scenario" \
	"$PYTHON_BIN" - <<'PYCODE'
import json
import os
from pathlib import Path

cfg_path = Path("benchmarks/config.json")
cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
cfg["environment_profile"] = f"{os.environ['PROFILE']}:{os.environ['SCENARIO_NAME']}"
cfg["protocols"] = [p for p in os.environ["PROTOCOLS"].split(",") if p]
cfg["suites"] = [s for s in os.environ["SUITES"].split(",") if s]
cfg["repeat"] = int(os.environ["REPEAT"])
cfg["warmup"] = int(os.environ["WARMUP"])
cfg["scenarios"] = [os.environ["SCENARIO_NAME"]]
cfg["enable_netem"] = True
cfg_path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
PYCODE

	"$PYTHON_BIN" benchmarks/run_benchmarks.py

	run_id=$(
	"$PYTHON_BIN" - <<'PYCODE'
from pathlib import Path

raw_root = Path("benchmarks/results/raw")
candidates = [p for p in raw_root.iterdir() if p.is_dir()]
candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
print(candidates[0].name if candidates else "")
PYCODE
	)
	if [[ -n "$run_id" ]]; then
		mkdir -p "benchmarks/results/processed/$run_id"
		"$PYTHON_BIN" benchmarks/analyze/summary_tables.py --raw-dir "benchmarks/results/raw/$run_id" --out-dir "benchmarks/results/processed/$run_id"
		"$PYTHON_BIN" benchmarks/analyze/plots.py --raw-dir "benchmarks/results/raw/$run_id" --out-dir "benchmarks/results/processed/$run_id"
	fi

	bash benchmarks/setup_netem.sh clear
done

echo "[*] Netem benchmark scenarios complete."
