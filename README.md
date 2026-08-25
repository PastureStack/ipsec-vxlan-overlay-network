# PastureStack IPsec/VXLAN Overlay Network

This repository provides the privileged network data plane used by PastureStack. It contains IPsec and VXLAN overlay processes, connectivity checks, CNI runtime assets, and an audit-only topology planner.

PastureStack is an independent community effort to preserve, audit, and modernize the Rancher 1.6 ecosystem. It is not affiliated with or endorsed by Rancher Labs or SUSE.

## Runtime image

The Linux AMD64 image is published as:

```text
ghcr.io/pasturestack/ipsec-vxlan-overlay-network:0.14.27
```

The image is intended to be launched by the PastureStack infrastructure catalog. The IPsec router requires host PID access, `NET_ADMIN`-equivalent privileged access, and the network namespace contract documented in [COMPATIBILITY.md](COMPATIBILITY.md). It is not a standalone control plane or an unprivileged application container.

Preferred commands inside the image are:

- `start-ipsec.sh` — start the IPsec overlay router.
- `start-vxlan.sh` — start the VXLAN overlay router.
- `ipsec-vxlan-connectivity-check` — continuously check peer connectivity.
- `start-cni-driver.sh` — install the bundled CNI executables on a host.
- `ipsec-vxlan-overlay-topology` — validate a topology document without changing the host.

Compatibility aliases remain only where the preserved control-plane protocol still requires them. New integrations must use the PastureStack names.

## Build and verification

The build is containerized and requires Docker on a Linux AMD64 host:

```sh
make test
make validate
VERSION_OVERRIDE=0.14.27 make build
TAG=0.14.27 make package
```

The package build downloads dependencies anonymously, verifies every standalone binary with SHA-256, pins the Ubuntu base image by digest, resolves every directly installed package from Canonical snapshot `20260808T000000Z` with the exact versions in `ubuntu-apt.lock`, and includes the corresponding strongSwan source archives in the image. Go dependencies are declared in `go.mod`, checksum-bound by `go.sum`, and committed in the standard module-aware `vendor` tree for offline builds.

The health reconciler canonicalizes strongSwan VICI CHILD_SA runtime names before comparing them with configured peer names. This prevents a VICI unique-ID suffix from being misclassified as a missing SA during a rolling replacement.

## Origin and licensing

The official upstream history and original copyright notices are preserved. See [ORIGIN.md](ORIGIN.md), [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md), and [LICENSE](LICENSE) before redistributing this source or its image.

The repository source is licensed under Apache License 2.0. The runtime image also contains separately licensed operating-system packages, including strongSwan under GPL-2.0-or-later with the OpenSSL exception. Those components are not relicensed by PastureStack.
