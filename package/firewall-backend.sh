#!/bin/bash

# Sourced by start.sh. All probes run in the host network namespace when the
# overlay router uses the host XFRM namespace. In particular, never probe the
# legacy frontend after finding Docker's native nftables table: even a read
# through iptables-legacy can load forbidden legacy kernel modules.
resolve_firewall_backend() {
    local requested=${PASTURESTACK_FIREWALL_BACKEND:-auto}
    case "$requested" in
        auto)
            if host_netns_cmd nft list table ip docker-bridges >/dev/null 2>&1; then
                requested=nftables
            elif host_netns_cmd iptables-nft -t nat -S DOCKER >/dev/null 2>&1; then
                requested=iptables-nft
            elif host_netns_cmd grep -qx nat /proc/net/ip_tables_names &&
                 host_netns_cmd iptables-legacy -t nat -S DOCKER >/dev/null 2>&1; then
                requested=iptables-legacy
            else
                echo "Cannot identify Docker firewall backend; set PASTURESTACK_FIREWALL_BACKEND explicitly" >&2
                return 1
            fi
            ;;
        nftables|iptables-nft|iptables-legacy) ;;
        *)
            echo "Unsupported PASTURESTACK_FIREWALL_BACKEND: $requested" >&2
            return 1
            ;;
    esac

    case "$requested" in
        nftables)
            host_netns_cmd nft list table ip docker-bridges >/dev/null || return 1
            ;;
        iptables-nft|iptables-legacy)
            if host_netns_cmd nft list table ip docker-bridges >/dev/null 2>&1; then
                echo "Docker uses native nftables; refusing an xtables overlay backend" >&2
                return 1
            fi
            host_netns_cmd "$requested" -t nat -S DOCKER >/dev/null || return 1
            ;;
    esac
    PASTURESTACK_FIREWALL_BACKEND=$requested
    export PASTURESTACK_FIREWALL_BACKEND
}

ensure_overlay_nat_bypass() {
    case "$PASTURESTACK_FIREWALL_BACKEND" in
        nftables)
            # The manager's native hostnat rule excludes overlay destinations.
            # An ACCEPT in a separate nftables base chain would not exempt a
            # later NAT base chain and must not masquerade as a bypass.
            ;;
        iptables-nft|iptables-legacy)
            if host_netns_cmd "$PASTURESTACK_FIREWALL_BACKEND" -t nat -S CATTLE_NAT_POSTROUTING >/dev/null 2>&1; then
                host_netns_cmd "$PASTURESTACK_FIREWALL_BACKEND" -t nat -C CATTLE_NAT_POSTROUTING -s 10.42.0.0/16 -d 10.42.0.0/16 -j ACCEPT 2>/dev/null ||
                    host_netns_cmd "$PASTURESTACK_FIREWALL_BACKEND" -t nat -I CATTLE_NAT_POSTROUTING 1 -s 10.42.0.0/16 -d 10.42.0.0/16 -j ACCEPT
            fi
            ;;
    esac
}

ensure_gateway_masquerade() {
    local gateway=$1 out_iface=$2
    [ -n "$gateway" ] || return 0
    case "$PASTURESTACK_FIREWALL_BACKEND" in
        nftables)
            # In host-XFRM mode GATEWAY is the next-hop of the physical host,
            # not an overlay source. Native overlay egress is owned by the
            # network manager and this historical rule must not be replicated.
            ;;
        iptables-nft|iptables-legacy)
            host_netns_cmd "$PASTURESTACK_FIREWALL_BACKEND" -t nat -C POSTROUTING -o "$out_iface" -s "$gateway" -j MASQUERADE 2>/dev/null ||
                host_netns_cmd "$PASTURESTACK_FIREWALL_BACKEND" -t nat -I POSTROUTING -o "$out_iface" -s "$gateway" -j MASQUERADE
            ;;
    esac
}

configure_overlay_firewall() {
    local run_in_host_netns=$1 gateway=$2 out_iface=$3
    if [ "$run_in_host_netns" = true ]; then
        resolve_firewall_backend
        ensure_gateway_masquerade "$gateway" "$out_iface"
        ensure_overlay_nat_bypass
        return
    fi
    # Historical container-network-namespace mode has no host Docker tables
    # to detect. Preserve its original local iptables gateway rule.
    [ -n "$gateway" ] || return 0
    host_netns_cmd iptables -t nat -C POSTROUTING -o "$out_iface" -s "$gateway" -j MASQUERADE 2>/dev/null ||
        host_netns_cmd iptables -t nat -I POSTROUTING -o "$out_iface" -s "$gateway" -j MASQUERADE
}
