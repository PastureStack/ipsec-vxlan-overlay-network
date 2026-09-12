#!/bin/bash

# Sourced by start.sh. Firewall probes run in the host network namespace when
# the overlay router uses the host XFRM namespace. Inspect legacy rules only
# when the legacy NAT table is already loaded: a read through iptables-legacy
# on an nft-only host can otherwise load forbidden legacy kernel modules.
native_docker_state() {
    local rules
    if ! rules=$(host_netns_cmd nft list table ip docker-bridges 2>&1); then
        if [[ "$rules" == *"No such file or directory"* ||
              "$rules" == *"Protocol not supported"* || "$rules" == *"Operation not supported"* ||
              "$rules" == *"Address family not supported"* ]]; then
            echo absent
            return 0
        fi
        echo "Cannot inspect Docker native nftables hooks: $rules" >&2
        return 1
    fi
    if grep -Eq 'type[[:space:]]+filter[[:space:]]+hook[[:space:]]+forward' <<<"$rules" &&
       grep -Eq 'type[[:space:]]+nat[[:space:]]+hook[[:space:]]+postrouting' <<<"$rules"; then
        echo active
    else
        echo stale
    fi
}

xt_docker_state() {
    local frontend=$1 rules
    if ! rules=$(host_netns_cmd "$frontend" -t nat -S 2>&1); then
        # An old kernel may have no nf_tables frontend. Do not mistake an
        # inspection error (including permission denied) for an empty table.
        if [ "$frontend" = iptables-nft ] &&
           [[ "$rules" == *"Protocol not supported"* || "$rules" == *"Operation not supported"* ||
              "$rules" == *"Address family not supported"* || "$rules" == *"Could not fetch rule set generation id: Invalid argument"* ]]; then
            echo absent
            return 0
        fi
        echo "Cannot inspect Docker $frontend NAT hooks: $rules" >&2
        return 1
    fi
    if grep -qx -- '-N DOCKER' <<<"$rules"; then
        if grep -Eq '^-A (PREROUTING|OUTPUT)([[:space:]].*)?[[:space:]]-j DOCKER([[:space:]]|$)' <<<"$rules"; then
            echo active
        else
            echo stale
        fi
    elif grep -Eq '^-A (PREROUTING|OUTPUT)([[:space:]].*)?[[:space:]]-j DOCKER([[:space:]]|$)' <<<"$rules"; then
        echo stale
    else
        echo absent
    fi
}

xt_conflicting_host_rules() {
    local frontend=$1 table=$2 rules
    if ! rules=$(host_netns_cmd "$frontend" -t "$table" -S 2>&1); then
        if [ "$frontend" = iptables-nft ] &&
           [[ "$rules" == *"Protocol not supported"* || "$rules" == *"Operation not supported"* ||
              "$rules" == *"Address family not supported"* || "$rules" == *"Could not fetch rule set generation id: Invalid argument"* ]]; then
            echo absent
            return 0
        fi
        echo "Cannot inspect $frontend $table migration rules: $rules" >&2
        return 1
    fi
    if [ "$table" = filter ] && grep -qx -- '-P FORWARD DROP' <<<"$rules"; then
        echo active
        return 0
    fi
    # Follow jumps from built-in chains, not orphan CATTLE_* declarations.
    # This also catches a CATTLE hook reached through DOCKER-USER.
    local awk_status
    if awk '
        $1 == "-A" {
            for (i = 3; i < NF; i++) {
                if ($i == "-j" || $i == "-g") {
                    key = $2 SUBSEP $(i + 1)
                    if (!(key in edge)) {
                        edge[key] = 1
                        edge_count++
                    }
                }
            }
        }
        END {
            reach["INPUT"] = reach["FORWARD"] = reach["OUTPUT"] = 1
            reach["PREROUTING"] = reach["POSTROUTING"] = 1
            for (pass = 0; pass <= edge_count; pass++) {
                for (item in edge) {
                    split(item, pair, SUBSEP)
                    if (reach[pair[1]]) reach[pair[2]] = 1
                }
            }
            for (chain in reach) if (chain ~ /^CATTLE_/) exit 0
            exit 1
        }
    ' <<<"$rules"; then
        echo active
    else
        awk_status=$?
        if [ "$awk_status" -eq 1 ]; then
            echo absent
        else
            echo "Cannot parse $frontend $table migration rules" >&2
            return 1
        fi
    fi
}

resolve_firewall_backend() {
    local requested=${PASTURESTACK_FIREWALL_BACKEND:-auto}
    case "$requested" in
        auto|nftables|iptables-nft|iptables-legacy) ;;
        *)
            echo "Unsupported PASTURESTACK_FIREWALL_BACKEND: $requested" >&2
            return 1
            ;;
    esac

    local driver native nft legacy legacy_tables active frontend table conflict
    driver=$(ipsec-vxlan-overlay-network docker-firewall-driver) || return 1
    native=$(native_docker_state) || return 1
    nft=$(xt_docker_state iptables-nft) || return 1
    legacy_tables=$(host_netns_cmd ipsec-vxlan-overlay-network legacy-loaded-tables) || return 1
    legacy=absent
    if grep -qx nat <<<"$legacy_tables"; then
        legacy=$(xt_docker_state iptables-legacy) || return 1
    fi
    if [ "$native" = stale ] || [ "$nft" = stale ] || [ "$legacy" = stale ]; then
        echo "Stale Docker firewall rules found (native=$native nft=$nft legacy=$legacy); resolve the host migration before starting the overlay" >&2
        return 1
    fi
    case "$driver:$native:$nft:$legacy" in
        nftables:active:absent:absent) active=nftables ;;
        iptables:absent:active:absent) active=iptables-nft ;;
        iptables:absent:absent:active) active=iptables-legacy ;;
        *)
            echo "Docker firewall driver and hooked owner disagree (driver=$driver native=$native nft=$nft legacy=$legacy)" >&2
            return 1
            ;;
    esac

    # A Docker chain can be the sole NAT owner while older platform hooks in
    # the opposite xtables frontend still process packets. Native nftables is
    # also subject to an old xtables FORWARD DROP policy. Inspect only loaded
    # legacy tables, and never mistake an orphan CATTLE chain for a live hook.
    for frontend in iptables-nft iptables-legacy; do
        [ "$active" != "$frontend" ] || continue
        for table in nat filter; do
            if [ "$frontend" = iptables-legacy ] && ! grep -qx "$table" <<<"$legacy_tables"; then
                continue
            fi
            conflict=$(xt_conflicting_host_rules "$frontend" "$table") || return 1
            if [ "$conflict" = active ]; then
                echo "Conflicting $frontend $table CATTLE hook or FORWARD DROP policy remains active; migrate the host before starting the overlay" >&2
                return 1
            fi
        done
    done
    if [ "$requested" != auto ] && [ "$requested" != "$active" ]; then
        echo "Requested $requested but Docker uses $active; refusing to modify another firewall backend" >&2
        return 1
    fi
    PASTURESTACK_FIREWALL_BACKEND=$active
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
