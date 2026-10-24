# PastureStack IPsec/VXLAN Overlay Network

Linux candidate **`v0.14.41`** integrates shared Ubuntu 26.04 security backports for already-installed packages while preserving the selected coreutils provider. It is unpublished; the last published Linux release is [v0.14.40](https://github.com/PastureStack/ipsec-vxlan-overlay-network/releases/tag/v0.14.40).

Build and image examples below target the candidate. Publication requires completed bundle provenance and the normal final-image release gates. The image retains bundle manifests, source inputs and install/verify receipts under `/usr/share/pasturestack/security/ubuntu-backports/`.

This repository provides the privileged network data plane used by PastureStack. It contains IPsec and VXLAN overlay processes, connectivity checks, CNI runtime assets, and an audit-only topology planner.

PastureStack is an independent community effort to preserve, audit, and modernize the Rancher 1.6 ecosystem. It is not affiliated with or endorsed by Rancher Labs or SUSE.

## Release status

After publication, select `ghcr.io/pasturestack/ipsec-vxlan-overlay-network:v0.14.41` through the infrastructure
Catalog. Security and CodeQL checks, the release scan and immutable publication
must pass first. Image publication, Catalog selection and managed-host
acceptance are separate.

The image is launched by the infrastructure Catalog. The IPsec router requires
host PID access, privileged networking, and the namespace contract in
[COMPATIBILITY.md](COMPATIBILITY.md). Network Plugin Manager owns host NAT,
forwarding and host ports; this update preserves that ownership and the
selected GNU/uutils provider.

The checksum-pinned companions remain metadata CNI IPAM `v0.2.8`, host-local
CNI IPAM `v0.1.6`, flat CNI IPAM `v0.1.6`, mount propagation `v1.0.12`, per-host
subnet `v0.2.5`, and the preserved bridge compatibility binary `v0.7.2`.
The original strongSwan source and package locks remain independently retained.

The release gate retains every severity and rejects fixed findings, unreviewed
findings, Critical/High/Unknown findings, and secrets in the source,
shipped binaries, and runtime image. It scans the disposable Dapper builder
separately and retains its raw findings; only exact, already-reviewed
`linux-libc-dev` header findings receive builder-scoped VEX. New builder
header findings remain explicitly unreviewed; all non-header builder packages
use the same full-severity, exact no-fix policy in a separate ledger.
The Dapper image and its kernel headers are not included in the release image.

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
VERSION_OVERRIDE=0.14.41 make build
TAG=0.14.41 make package
```

The package build downloads dependencies anonymously, verifies every standalone binary with SHA-256, pins the Ubuntu base image by digest, resolves packages from Canonical snapshot `20260808T000000Z` with the exact versions in `ubuntu-apt.lock`, and includes the corresponding strongSwan source archives in the image. The build also retains the checksum-pinned OpenSSL triplet (`openssl`, `libssl3t64`, `openssl-provider-legacy`) at `3.5.5-1ubuntu3.6` from snapshot `20260930T000000Z`, fixing CVE-2026-84782 in both Dapper and runtime without changing other package locks or the kernel-header review boundary. Go dependencies are declared in `go.mod`, checksum-bound by `go.sum`, and committed in the standard module-aware `vendor` tree for offline builds.

The release gate also runs `scripts/integration-optional-cni-isolated` against
the image it just packaged. Inside a disposable, network-isolated container it
checks the bundled per-host-subnet and flat-bridge CNI binaries through ADD,
bridge connectivity, and DEL. A local reproduction must set `IMAGE` to the
exact image under review. This does not replace a live Catalog, Metadata API,
host-port, cross-host, or host-reboot acceptance test.

The flat-network gate deliberately uses a preconfigured bridge address that
differs from the subnet's network address and checks that CNI does not add a
second address. The packaged bridge compatibility binary is v0.7.2, the first
release in this dependency line that recognizes `skipBridgeConfigureIP`.

The health reconciler canonicalizes strongSwan VICI CHILD_SA runtime names before comparing them with configured peer names. This prevents a VICI unique-ID suffix from being misclassified as a missing SA during a rolling replacement.

## Host firewall backends

The Catalog IPsec `overlay-router` runs in the host network namespace. `PASTURESTACK_FIREWALL_BACKEND=auto` reads Docker's actual
firewall driver from the mounted Docker socket and verifies that exactly one
matching Docker-owned firewall backend has live hooks. An explicit selection
is verified the same way; stale, mixed or mismatched Docker rules, reachable
old platform hooks in the opposite frontend, or an opposite `FORWARD DROP`
policy stop startup without changing host NAT rules. Orphan chains
without a live path from a built-in chain are not treated as active hooks.
The router only sends `GET /info` to the
Docker API, but mounting the Unix socket is a privileged capability: `:ro` on
the mount does **not** restrict API writes. The router already requires
privileged access and host PID access; operators must protect this container
accordingly. No host-XFRM backend path writes a host firewall rule. The active
network manager owns overlay forwarding marks and NAT, and Docker's native
bridge firewall must accept mark `0x1068/0x1068`. See
[COMPATIBILITY.md](COMPATIBILITY.md) for the boundary and migration notes.

## Origin and licensing

The official upstream history and original copyright notices are preserved. See [ORIGIN.md](ORIGIN.md), [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md), and [LICENSE](LICENSE) before redistributing this source or its image.

The repository source is licensed under Apache License 2.0. The runtime image also contains separately licensed operating-system packages, including strongSwan under GPL-2.0-or-later with the OpenSSL exception. Those components are not relicensed by PastureStack.

Security micro-updates are constrained by `security/ubuntu-security-packages.lock` to the signed Ubuntu 26.04 snapshot of 2026-10-23; the general package snapshot remains unchanged. Builds record the resulting package versions in `/usr/share/pasturestack/ubuntu-security-packages.tsv`. Existing runtime and firewall contracts are unchanged.
