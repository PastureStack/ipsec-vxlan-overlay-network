#!/bin/bash
set -euo pipefail

debug=${PASTURESTACK_DEBUG:-${RANCHER_DEBUG:-false}}
if [ "$debug" = "true" ]; then
    set -x
fi

LABEL="io.rancher.network.l2flat.interface"
METADATA_ADDRESS=${PASTURESTACK_METADATA_ADDRESS:-${RANCHER_METADATA_ADDRESS:-169.254.169.250}}

while ! curl -s -f "http://${METADATA_ADDRESS}/2016-07-29/self/host" >/dev/null; do
    echo "Waiting for metadata"
    sleep 1
done

FLAT_IF_FROM_LABEL=$(curl -s "http://${METADATA_ADDRESS}/2016-07-29/self/host/labels/${LABEL}" || true)
if [ -z "${FLAT_IF_FROM_LABEL}" ] || echo "${FLAT_IF_FROM_LABEL}" | grep -q "Not found"; then
    FLAT_IF=${FLAT_IF:-eth0}
else
    echo "Using flat interface from host label ${LABEL}"
    FLAT_IF=${FLAT_IF_FROM_LABEL}
fi

BRIDGE_NAME=${FLAT_BRIDGE:-flatbr0}
MTU=${MTU:-1500}

TEST_BRIDGE=$(ip -4 addr show dev "${BRIDGE_NAME}" 2>/dev/null | awk '/inet / {print $2; exit}' || true)
if [ -n "${TEST_BRIDGE}" ]; then
    exit 0
fi

FLAT_IF_IP=$(ip -4 addr show dev "${FLAT_IF}" | awk '/inet / {print $2; exit}')
FLAT_IF_MAC=$(ip link show dev "${FLAT_IF}" | awk '/link\/ether/ {print $2; exit}')
GW_IP=$(ip route show default | awk '{print $3; exit}')

if [ -z "${FLAT_IF_IP}" ] || [ -z "${FLAT_IF_MAC}" ]; then
    echo "Flat interface ${FLAT_IF} does not have the required IPv4/MAC address" >&2
    exit 1
fi

ip link add "${BRIDGE_NAME}" type bridge 2>/dev/null || true
ip link set "${BRIDGE_NAME}" address "${FLAT_IF_MAC}"
ip addr del "${FLAT_IF_IP}" dev "${FLAT_IF}" 2>/dev/null || true
ip addr add "${FLAT_IF_IP}" brd + dev "${BRIDGE_NAME}"
ip link set dev "${BRIDGE_NAME}" up
ip link set dev "${FLAT_IF}" master "${BRIDGE_NAME}"
ip link set dev "${BRIDGE_NAME}" mtu "${MTU}"

if [ -n "${GW_IP}" ] && [ -z "$(ip route show default | awk '{print $3; exit}')" ]; then
    ip route add default via "${GW_IP}"
fi
