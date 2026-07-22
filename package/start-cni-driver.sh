#!/bin/bash
set -euo pipefail

debug=${PASTURESTACK_DEBUG:-${RANCHER_DEBUG:-false}}
if [ "$debug" = "true" ]; then
    set -x
fi

mkdir -p /opt/cni-driver /var/log
cp -a /opt/cni/bin/. /opt/cni-driver/
touch /var/log/pasturestack-cni.log
ln -sf pasturestack-cni.log /var/log/rancher-cni.log
exec tail ---disable-inotify -F /var/log/pasturestack-cni.log
