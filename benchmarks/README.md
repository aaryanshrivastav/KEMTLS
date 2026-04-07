# KEMTLS Benchmarking Guide

This benchmark stack is designed for Windows development with authoritative benchmark execution in WSL2/Linux.

## Environments

- Windows development: code editing and orchestration entrypoint.
- WSL2 loopback: authoritative local measured benchmark results.
- Linux native/VM: required for `tc netem` WAN/loss/jitter benchmarking.

## Quick Start

### Windows launcher

Run from PowerShell:

```powershell
./scripts/run_benchmarks_windows.ps1 -Profile wsl2_loopback -Suites crypto,handshake,oidc,load -Repeat 1000 -Warmup 50
```

### WSL direct

```bash
bash benchmarks/collect/run_all_wsl.sh --profile wsl2_loopback --suites crypto,handshake,oidc,load --repeat 1000 --warmup 50
```

### Linux netem

```bash
bash benchmarks/collect/run_all_netem.sh --profile linux_netem --scenario-set all --suites crypto,handshake,oidc,load
```

## Output Layout

- Raw: `benchmarks/results/raw/<run_id>/`
- Processed: `benchmarks/results/processed/<run_id>/`
- Run manifest: `benchmarks/results/raw/<run_id>/manifest.json`

## Timing Boundaries

- Handshake HCT: first handshake byte to handshake completion.
- OIDC step times: discovery, authorize, token, userinfo, refresh.
- End-to-end auth total: full measured flow duration.

## Notes

- Do not mix legacy benchmark artifacts with new run output.
- Treat measured local data and literature reference values as separate datasets.
