#!/bin/bash
set -euo pipefail

debug=${PASTURESTACK_DEBUG:-${RANCHER_DEBUG:-false}}
xfrm_netns_path=${PASTURESTACK_NETWORK_XFRM_NETNS_PATH:-${RANCHER_NET_XFRM_NETNS_PATH:-}}
run_in_host_netns=${PASTURESTACK_NETWORK_RUN_IN_HOST_NETNS:-${RANCHER_NET_RUN_IN_HOST_NETNS:-false}}
metadata_client_ip=${PASTURESTACK_METADATA_CLIENT_IP:-${RANCHER_METADATA_CLIENT_IP:-}}

export PASTURESTACK_NETWORK_ARP_INTERFACE=${PASTURESTACK_NETWORK_ARP_INTERFACE:-${RANCHER_NET_ARP_INTERFACE:-eth0}}
export PASTURESTACK_NETWORK_XFRM_TUNNEL_SOURCE=${PASTURESTACK_NETWORK_XFRM_TUNNEL_SOURCE:-${RANCHER_NET_XFRM_TUNNEL_SOURCE:-local}}
export PASTURESTACK_NETWORK_XFRM_NETNS_PATH=$xfrm_netns_path

if [ "$debug" = "true" ]; then
    set -x
fi

trap 'exit 1' SIGTERM SIGINT

xfrm_cmd() {
    if [ -n "$xfrm_netns_path" ]; then
        nsenter "--net=${xfrm_netns_path}" ip xfrm "$@"
    else
        ip xfrm "$@"
    fi
}

host_netns_cmd() {
    if [ "$run_in_host_netns" = "true" ] && [ -n "$xfrm_netns_path" ]; then
        nsenter "--net=${xfrm_netns_path}" "$@"
    else
        "$@"
    fi
}

source /usr/bin/firewall-backend.sh

if [ "$run_in_host_netns" = "true" ] && [ -z "$metadata_client_ip" ]; then
    metadata_client_ip=$(ip -4 -o addr show dev eth0 | awk '{split($4, a, "/"); print a[1]; exit}')
    if [ -z "$metadata_client_ip" ]; then
        echo "Failed to detect metadata client IP from the network holder" >&2
        exit 1
    fi
fi
if [ -n "$metadata_client_ip" ]; then
    export PASTURESTACK_METADATA_CLIENT_IP=$metadata_client_ip
fi

if [ -n "$xfrm_netns_path" ]; then
    nsenter "--net=${xfrm_netns_path}" sh -c \
        'echo 2147483647 > /proc/sys/net/ipv4/xfrm4_gc_thresh' || true
fi

while curl http://localhost:8111 >/dev/null 2>&1; do
    echo "Waiting for the previous overlay process to stop"
    sleep 2
done

export CHARON_PID_FILE=/var/run/charon.pid
rm -f "$CHARON_PID_FILE"

export PIDFILE=/var/run/ipsec-vxlan-overlay-network.pid
GCM=false

for ((i=0; i<6; i++)); do
    if xfrm_cmd state add src 1.1.1.1 dst 1.1.1.1 spi 42 proto esp mode tunnel aead "rfc4106(gcm(aes))" 0x0000000000000000000000000000000000000001 128 sel src 1.1.1.1 dst 1.1.1.1; then
        GCM=true
        xfrm_cmd state del src 1.1.1.1 dst 1.1.1.1 spi 42 proto esp 2>/dev/null || true
        break
    fi
    xfrm_cmd state del src 1.1.1.1 dst 1.1.1.1 spi 42 proto esp 2>/dev/null || true
    sleep 1
done

debug_args=()
if [ "$debug" = "true" ]; then
    debug_args+=(--debug)
fi

: "${CATTLE_ACCESS_KEY:?CATTLE_ACCESS_KEY is required}"
: "${CATTLE_SECRET_KEY:?CATTLE_SECRET_KEY is required}"
: "${CATTLE_URL:?CATTLE_URL is required}"
mkdir -p /etc/ipsec
set +x
curl -f -u "${CATTLE_ACCESS_KEY}:${CATTLE_SECRET_KEY}" "${CATTLE_URL}/configcontent/psk" > /etc/ipsec/psk.txt
curl -f -X PUT -d "" -u "${CATTLE_ACCESS_KEY}:${CATTLE_SECRET_KEY}" "${CATTLE_URL}/configcontent/psk?version=latest"
if [ "$debug" = "true" ]; then
    set -x
fi

route=$(host_netns_cmd ip -4 route get 8.8.8.8)
GATEWAY=$(awk '{for (i=1; i<=NF; i++) if ($i == "via") {print $(i+1); exit}}' <<<"$route")
OUT_IFACE=$(awk '{for (i=1; i<=NF; i++) if ($i == "dev") {print $(i+1); exit}}' <<<"$route")
LOCAL_IP=$(awk '{for (i=1; i<=NF; i++) if ($i == "src") {print $(i+1); exit}}' <<<"$route")
if [ -z "$OUT_IFACE" ] || [ -z "$LOCAL_IP" ]; then
    echo "Unable to determine the host route used by the overlay" >&2
    exit 1
fi
if [ "$run_in_host_netns" = "true" ]; then
    export PASTURESTACK_NETWORK_SYNC_HOST_ROUTES=${PASTURESTACK_NETWORK_SYNC_HOST_ROUTES:-${RANCHER_NET_SYNC_HOST_ROUTES:-true}}
fi
configure_overlay_firewall "$run_in_host_netns" "$GATEWAY" "$OUT_IFACE"

cmd=(
    ipsec-vxlan-overlay-network
    -i "${LOCAL_IP}/16"
    --pid-file "$PIDFILE"
    --gcm="$GCM"
    --use-metadata
    --charon-launch
    --ipsec-config /etc/ipsec
    "${debug_args[@]}"
)

if [ "$run_in_host_netns" = "true" ] && [ -n "$xfrm_netns_path" ]; then
    exec nsenter "--net=${xfrm_netns_path}" "${cmd[@]}"
fi

exec "${cmd[@]}"
