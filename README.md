# PastureStack IPsec/VXLAN Overlay Network

This repository provides the privileged network data plane used by PastureStack. It contains IPsec and VXLAN overlay processes, connectivity checks, CNI runtime assets, and an audit-only topology planner.

PastureStack is an independent community effort to preserve, audit, and modernize the Rancher 1.6 ecosystem. It is not affiliated with or endorsed by Rancher Labs or SUSE.

## Release status

The current Catalog coordinate is:

```text
ghcr.io/pasturestack/ipsec-vxlan-overlay-network:v0.14.26
```

This source tree targets the next numeric candidate, `v0.14.27`. It has not
been published, so the build commands below create a candidate only and do not
change the current deployment coordinate. The latest GitHub Release is
`v0.14.25`; the Catalog's `v0.14.26` image therefore remains deployment
evidence rather than a complete matching Release-and-image publication.

The image is intended to be launched by the PastureStack infrastructure catalog. The IPsec router requires host PID access, `NET_ADMIN`-equivalent privileged access, and the network namespace contract documented in [COMPATIBILITY.md](COMPATIBILITY.md). It is not a standalone control plane or an unprivileged application container.

The release gate rejects Critical/High findings and secrets in the source,
shipped binaries, and runtime image. It scans the disposable Dapper builder
separately and retains its raw findings; only exact, already-reviewed
`linux-libc-dev` header findings receive builder-scoped VEX. New builder
findings remain visible and are not evidence that the shipped runtime is safe.
The Dapper image and its kernel headers are not included in the release image.

Preferred commands inside the image are:

- `start-ipsec.sh` — start the IPsec overlay router.
- `start-vxlan.sh` — start the VXLAN overlay router.
- `ipsec-vxlan-connectivity-check` — continuously check peer connectivity.
- `start-cni-driver.sh` — install the bundled CNI executables on a host.
- `ipsec-vxlan-overlay-topology` — validate a topology document without changing the host.

Compatibility aliases remain only where the preserved control-plane protocol still requires them. New integrations must use the PastureStack names.

## Build and verification

The candidate build is containerized and requires Docker on a Linux AMD64 host:

```sh
make test
make validate
VERSION_OVERRIDE=0.14.27 make build
TAG=0.14.27 make package
```

The package build downloads dependencies anonymously, verifies every standalone binary with SHA-256, pins the Ubuntu base image by digest, resolves every directly installed package from Canonical snapshot `20260808T000000Z` with the exact versions in `ubuntu-apt.lock`, and includes the corresponding strongSwan source archives in the image. Go dependencies are declared in `go.mod`, checksum-bound by `go.sum`, and committed in the standard module-aware `vendor` tree for offline builds.

The health reconciler canonicalizes strongSwan VICI CHILD_SA runtime names before comparing them with configured peer names. This prevents a VICI unique-ID suffix from being misclassified as a missing SA during a rolling replacement.

## Host firewall backends

The catalog IPsec `overlay-router` runs in the host network namespace. Its startup script resolves `PASTURESTACK_FIREWALL_BACKEND=auto` once from the host's live Docker firewall tables and passes the selected value to route synchronization. Operators may explicitly choose `nftables`, `iptables-nft`, or `iptables-legacy`; a mismatched selection fails rather than modifying another backend. The native path never invokes `iptables-legacy` and does not write any host firewall rule. The active network manager is the sole owner of overlay forwarding marks and NAT; Docker's native bridge firewall must accept mark `0x1068/0x1068`. See [COMPATIBILITY.md](COMPATIBILITY.md) for the boundary and migration notes.

## Origin and licensing

The official upstream history and original copyright notices are preserved. See [ORIGIN.md](ORIGIN.md), [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md), and [LICENSE](LICENSE) before redistributing this source or its image.

The repository source is licensed under Apache License 2.0. The runtime image also contains separately licensed operating-system packages, including strongSwan under GPL-2.0-or-later with the OpenSSL exception. Those components are not relicensed by PastureStack.
