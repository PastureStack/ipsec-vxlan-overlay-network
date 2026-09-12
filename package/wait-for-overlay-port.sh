#!/bin/bash
# Sourced by start.sh after host_netns_cmd is defined. The router listens in the
# host network namespace, even though its startup script begins in the holder's
# network namespace. Probe the same namespace the router will actually use.

wait_for_overlay_port_release() {
    local max_attempts=$1
    local attempt listeners

    for ((attempt = 1; attempt <= max_attempts; attempt++)); do
        if ! listeners=$(host_netns_cmd ss -H -ltn '( sport = :8111 )'); then
            echo "Unable to inspect the overlay listener in its target network namespace" >&2
            return 1
        fi
        if [ -z "$listeners" ]; then
            return 0
        fi
        echo "Waiting for the previous overlay listener to release port 8111 (${attempt}/${max_attempts})"
        sleep 2
    done

    echo "Overlay listener still occupies port 8111 after ${max_attempts} checks" >&2
    return 1
}
