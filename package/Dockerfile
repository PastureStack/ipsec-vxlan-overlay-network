FROM ubuntu:26.04@sha256:3131b4cc82a783df6c9df078f86e01819a13594b865c2cad47bd1bca2b7063bb

ARG IMAGE_VERSION=dev
ARG IMAGE_REVISION=unknown
ARG UBUNTU_MIRROR=http://archive.ubuntu.com/ubuntu
ARG STRONGSWAN_VERSION=6.0.4-1ubuntu3.1
ARG STRONGSWAN_ORIG_SHA256=79576bb61b9a406cea9eb73d0c565cc6254a6b6d2e7198f44758d2d7c61a7aec
ARG STRONGSWAN_DEBIAN_SHA256=2813fea68dc93da2c17cc0c7c8a30e39b61dba333c8bdf7a7e0ce7c6e9d01879
ARG STRONGSWAN_DSC_SHA256=64c7e3ad1d44ff5b5e287cf02a65e4b51b351a854a2773d90fbb4a2ff8f1f39b
ARG CNI_VERSION=v0.3.0
ARG CNI_SHA256=b1ae09833a238c51161918a8849031efdb46cf0068ea5b752e362d9836e2af7d
ARG CNI_BRIDGE_VERSION=v0.3.1
ARG CNI_BRIDGE_SHA256=478f9e04772da427455e0bd90c708cc9b96f4cab89acfc0fd67c13cd779e6c34
ARG WEAVE_ROUTER_VERSION=r-v0.0.4
ARG WEAVE_ROUTER_SHA256=15d55366dbcc33c8a9fd3ca5d3e53256b9184966bc1a59e2c88ed524660382ea

RUN set -eux; \
    rm -f /usr/bin/pebble; \
    if [ -f /etc/apt/sources.list.d/ubuntu.sources ]; then \
        sed -i \
            -e "s|http://archive.ubuntu.com/ubuntu|${UBUNTU_MIRROR}|g" \
            -e "s|http://security.ubuntu.com/ubuntu|${UBUNTU_MIRROR}|g" \
            -e 's/^Types: deb$/Types: deb deb-src/' \
            /etc/apt/sources.list.d/ubuntu.sources; \
    fi; \
    apt-get -o Acquire::Retries=5 -o Acquire::http::Timeout=30 update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        arptables \
        bash \
        bridge-utils \
        ca-certificates \
        conntrack \
        curl \
        ethtool \
        iproute2 \
        ipset \
        iptables \
        iputils-ping \
        kmod \
        libstrongswan-extra-plugins="${STRONGSWAN_VERSION}" \
        libstrongswan-standard-plugins="${STRONGSWAN_VERSION}" \
        openssl \
        psmisc \
        strongswan-charon="${STRONGSWAN_VERSION}" \
        strongswan-swanctl="${STRONGSWAN_VERSION}" \
        tar \
        util-linux; \
    mkdir -p /licenses/strongswan-source; \
    cd /licenses/strongswan-source; \
    apt-get source --download-only strongswan="${STRONGSWAN_VERSION}"; \
    echo "${STRONGSWAN_ORIG_SHA256}  strongswan_6.0.4.orig.tar.bz2" | sha256sum -c -; \
    echo "${STRONGSWAN_DEBIAN_SHA256}  strongswan_${STRONGSWAN_VERSION}.debian.tar.xz" | sha256sum -c -; \
    echo "${STRONGSWAN_DSC_SHA256}  strongswan_${STRONGSWAN_VERSION}.dsc" | sha256sum -c -; \
    mkdir -p /licenses/ubuntu-packages; \
    for package in strongswan-charon strongswan-swanctl libstrongswan-standard-plugins libstrongswan-extra-plugins; do \
        cp "/usr/share/doc/${package}/copyright" "/licenses/ubuntu-packages/${package}-copyright"; \
    done; \
    rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    fetch() { \
        url="$1"; destination="$2"; expected="$3"; \
        curl -fsSL --retry 5 --retry-all-errors --retry-delay 2 -o "$destination" "$url"; \
        echo "$expected  $destination" | sha256sum -c -; \
    }; \
    fetch \
        "https://github.com/rancher/weave/releases/download/${WEAVE_ROUTER_VERSION}/r" \
        /usr/bin/weave-router \
        "${WEAVE_ROUTER_SHA256}"; \
    fetch \
        "https://github.com/containernetworking/cni/releases/download/${CNI_VERSION}/cni-${CNI_VERSION}.tgz" \
        /tmp/cni.tgz \
        "${CNI_SHA256}"; \
    fetch \
        "https://github.com/rancher/rancher-cni-bridge/releases/download/${CNI_BRIDGE_VERSION}/rancher-cni-bridge-${CNI_BRIDGE_VERSION}.tar.gz" \
        /tmp/cni-bridge.tgz \
        "${CNI_BRIDGE_SHA256}"; \
    mkdir -p /opt/cni/bin /tmp/cni /tmp/cni-bridge; \
    tar -xzf /tmp/cni.tgz -C /tmp/cni ./loopback; \
    tar -xzf /tmp/cni-bridge.tgz -C /tmp/cni-bridge; \
    install -m 0755 /tmp/cni/loopback /opt/cni/bin/loopback; \
    install -m 0755 /tmp/cni-bridge/rancher-cni-bridge /opt/cni/bin/pasture-bridge; \
    chmod 0755 /usr/bin/weave-router; \
    rm -rf /tmp/cni.tgz /tmp/cni-bridge.tgz /tmp/cni /tmp/cni-bridge

COPY ipsec-vxlan-overlay-network ipsec-vxlan-overlay-topology per-host-subnet mount-propagation /usr/bin/
COPY metadata-cni-ipam host-local-cni-ipam flat-cni-ipam /opt/cni/bin/
COPY start.sh start-ipsec.sh start-vxlan.sh start-flat.sh start-cni-driver.sh update-platform-ca /usr/bin/
COPY pasturestack-entrypoint.sh /pasturestack-entrypoint.sh
COPY strongswan-pasturestack.conf /etc/strongswan.d/pasturestack-overlay.conf
COPY licenses/source /licenses/pasturestack
COPY licenses/vendor /licenses/pasturestack/vendor

RUN set -eux; \
    mkdir -p /etc/cni/net.d /etc/ipsec /var/lib/cattle /var/lib/pasturestack /var/lib/rancher /var/log /var/run; \
    chmod 0755 \
        /pasturestack-entrypoint.sh \
        /usr/bin/ipsec-vxlan-overlay-network \
        /usr/bin/ipsec-vxlan-overlay-topology \
        /usr/bin/per-host-subnet \
        /usr/bin/mount-propagation \
        /usr/bin/start.sh \
        /usr/bin/start-ipsec.sh \
        /usr/bin/start-vxlan.sh \
        /usr/bin/start-flat.sh \
        /usr/bin/start-cni-driver.sh \
        /usr/bin/update-platform-ca \
        /opt/cni/bin/metadata-cni-ipam \
        /opt/cni/bin/host-local-cni-ipam \
        /opt/cni/bin/flat-cni-ipam; \
    ln -s /usr/lib/ipsec/charon /usr/bin/charon; \
    ln -s ipsec-vxlan-overlay-network /usr/bin/ipsec-vxlan-connectivity-check; \
    ln -s ipsec-vxlan-overlay-network /usr/bin/connectivity-check; \
    ln -s ipsec-vxlan-overlay-network /usr/bin/rancher-net; \
    ln -s mount-propagation /usr/bin/share-mnt; \
    ln -s weave-router /usr/bin/r; \
    ln -s pasture-bridge /opt/cni/bin/rancher-bridge; \
    ln -s metadata-cni-ipam /opt/cni/bin/rancher-cni-ipam; \
    ln -s host-local-cni-ipam /opt/cni/bin/rancher-host-local-ipam; \
    ln -s flat-cni-ipam /opt/cni/bin/rancher-flat-ipam

LABEL org.opencontainers.image.source="https://github.com/PastureStack/ipsec-vxlan-overlay-network" \
      org.opencontainers.image.description="PastureStack IPsec and VXLAN overlay network runtime." \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${IMAGE_VERSION}" \
      org.opencontainers.image.revision="${IMAGE_REVISION}" \
      org.pasturestack.third-party-licenses="See /licenses/pasturestack/THIRD_PARTY_NOTICES.md"

ENTRYPOINT ["/pasturestack-entrypoint.sh"]
CMD ["start.sh"]
