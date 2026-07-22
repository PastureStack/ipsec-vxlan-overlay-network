#!/bin/bash
set -euo pipefail

debug=${PASTURESTACK_DEBUG:-${RANCHER_DEBUG:-false}}
if [ "$debug" = "true" ]; then
    set -x
fi

trap 'exit 1' SIGTERM SIGINT

export PIDFILE=/var/run/ipsec-vxlan-overlay-network.pid
route=$(ip -4 route get 8.8.8.8)
LOCAL_IP=$(awk '{for (i=1; i<=NF; i++) if ($i == "src") {print $(i+1); exit}}' <<<"$route")
GATEWAY=$(awk '{for (i=1; i<=NF; i++) if ($i == "via") {print $(i+1); exit}}' <<<"$route")
if [ -z "$LOCAL_IP" ]; then
    echo "Unable to determine the VXLAN source address" >&2
    exit 1
fi

debug_args=()
if [ "$debug" = "true" ]; then
    debug_args+=(--debug)
fi

if [ -n "$GATEWAY" ]; then
    iptables -t nat -C POSTROUTING -o vtep1042 -s "$GATEWAY" -j MASQUERADE 2>/dev/null || \
        iptables -t nat -I POSTROUTING -o vtep1042 -s "$GATEWAY" -j MASQUERADE
fi

exec ipsec-vxlan-overlay-network \
    -i "${LOCAL_IP}/16" \
    --pid-file "$PIDFILE" \
    --use-metadata \
    --backend vxlan \
    "${debug_args[@]}"
