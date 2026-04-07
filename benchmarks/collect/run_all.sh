#!/bin/bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root_dir="$(cd "$script_dir/../.." && pwd)"

cd "$root_dir"
python benchmarks/run_benchmarks.py
