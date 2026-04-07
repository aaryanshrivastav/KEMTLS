#!/bin/bash
set -euo pipefail

OUT_DIR="${1:-benchmarks/results/raw/captures}"
INTERFACE="${2:-lo}"
DURATION="${3:-15}"

mkdir -p "$OUT_DIR"
TS="$(date +%Y%m%d_%H%M%S)"
PCAP="$OUT_DIR/handshake_$TS.pcap"

if ! command -v tcpdump >/dev/null 2>&1; then
  echo "tcpdump not found; skipping capture"
  exit 0
fi

echo "[*] Capturing packets on $INTERFACE for ${DURATION}s -> $PCAP"
sudo timeout "$DURATION" tcpdump -i "$INTERFACE" -w "$PCAP" || true
echo "[*] Capture complete: $PCAP"
