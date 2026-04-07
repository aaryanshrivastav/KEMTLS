#!/bin/bash
set -euo pipefail

IFACE="${IFACE:-lo}"

usage() {
    echo "Usage: $0 apply <scenario>|clear|show"
    echo "Scenarios: LAN FAST_WAN TYPICAL_WAN SLOW_WAN LOSS_LOW LOSS_HIGH LOSS_SEVERE"
}

need_tc() {
    if ! command -v tc >/dev/null 2>&1; then
        echo "tc not found; netem unsupported on this host"
        exit 2
    fi
}

apply_scenario() {
    local scenario="$1"
    sudo tc qdisc del dev "$IFACE" root 2>/dev/null || true

    case "$scenario" in
        LAN)
            sudo tc qdisc add dev "$IFACE" root netem delay 0.5ms
            ;;
        FAST_WAN)
            sudo tc qdisc add dev "$IFACE" root netem delay 10ms
            ;;
        TYPICAL_WAN)
            sudo tc qdisc add dev "$IFACE" root netem delay 30ms
            ;;
        SLOW_WAN)
            sudo tc qdisc add dev "$IFACE" root netem delay 75ms
            ;;
        LOSS_LOW)
            sudo tc qdisc add dev "$IFACE" root netem delay 30ms loss gemodel 0.5% 20% 80% 0.1%
            ;;
        LOSS_HIGH)
            sudo tc qdisc add dev "$IFACE" root netem delay 30ms loss gemodel 2% 30% 70% 0.5%
            ;;
        LOSS_SEVERE)
            sudo tc qdisc add dev "$IFACE" root netem delay 30ms loss gemodel 5% 40% 60% 1%
            ;;
        *)
            echo "Unknown scenario: $scenario"
            usage
            exit 1
            ;;
    esac
}

cmd="${1:-}"
arg="${2:-}"

case "$cmd" in
    apply)
        need_tc
        if [ -z "$arg" ]; then
            usage
            exit 1
        fi
        apply_scenario "$arg"
        echo "[*] Applied netem scenario $arg on $IFACE"
        ;;
    clear)
        need_tc
        sudo tc qdisc del dev "$IFACE" root 2>/dev/null || true
        echo "[*] Cleared netem rules on $IFACE"
        ;;
    show)
        need_tc
        sudo tc qdisc show dev "$IFACE"
        ;;
    *)
        usage
        exit 1
        ;;
esac
