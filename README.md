# PastureStack IPsec/VXLAN Overlay Network

This repository provides the privileged network data plane used by PastureStack. It contains IPsec and VXLAN overlay processes, connectivity checks, CNI runtime assets, and an audit-only topology planner.

PastureStack is an independent community effort to preserve, audit, and modernize the Rancher 1.6 ecosystem. It is not affiliated with or endorsed by Rancher Labs or SUSE.

## Release status

The prior `v0.14.27` source and image were published with manifest digest
`sha256:917c4369ee22808c100dd890d17296fe341e0dda4b2ad2923050f4fca5c22386`
and release SBOM/provenance attestations. On an isolated Ubuntu 26.04.1 / Docker 29.8 VM, that
published image selected native nftables without modifying host rules, rejected
an explicit legacy mismatch, and passed a two-container XFRM/encrypted-packet
integration test. That test is not a two-physical-host upgrade or reboot gate.
Publishing the image alone does not change deployments.

`v0.14.28` tightened host firewall detection. Published `v0.14.29` keeps that
validation but leaves host NAT, forwarding, and host ports solely to Network
Plugin Manager. The official image manifest is
`sha256:e65921d3ea7ec3a3582400b0bc2ca3297484375bad42dd61bbf74b1201c18ad1`
from source commit `276f8fee8ceb64a216a2907fdb0c60394296a208`; the same-commit
security and CodeQL gates and the release rebuild passed. Upgrade the manager
and verify it is healthy before upgrading this router; publishing an image and
updating Catalog are separate gates. Check the Catalog version lock for the
current deployment coordinate.

The published `v0.14.30` image (manifest
`sha256:326cec5fa786dbb18df68d10653b3cef1af4785cbb0897aecb616ffcec7914ca`,
source `8b9e40b88c027c0c3c76720f8077a5a82aa63473`) addresses a
rolling-upgrade handoff observed on two
managed hosts: both router generations briefly shared host network port 8111,
but the old startup guard inspected the holder namespace instead of the host
namespace where the router actually listens. The new guard checks the target
namespace before launching the router, waits at most 90 seconds for the prior
listener to leave, and fails clearly if that cannot be verified. It does not
change firewall ownership, Docker backend selection, or XFRM policy. Catalog
Templates `v0.3.4` publishes this image in IPsec Overlay template version `5`;
that publication is distinct from a completed live rolling-upgrade gate.

The image is intended to be launched by the PastureStack infrastructure catalog. The IPsec router requires host PID access, `NET_ADMIN`-equivalent privileged access, and the network namespace contract documented in [COMPATIBILITY.md](COMPATIBILITY.md). It is not a standalone control plane or an unprivileged application container.

The published `v0.14.31` image (manifest
`sha256:4d8a51e04bdd27fea3cb2949158103d43e0d2470907c328f76f7a0c6ccec8608`,
source `22f486cbcbcf92bda91fce555268226eddd723ba`) keeps charon running
when one peer is temporarily unavailable (for example, during a host reboot).
The existing 30-second IPsec health reconciliation retries that missing
CHILD_SA; a stale local peer identity still uses its separate explicit charon
restart path. This does not change firewall ownership or the selected Docker
firewall backend. Catalog pinning and live peer-restart verification remain
separate gates.

The `v0.14.32` change is scoped to IPsec peer lifecycle. Each managed IKE
connection requests strongSwan's per-peer `unique=replace` policy, including
older custom templates that omit the option; an explicit template policy is
preserved. The health reconciler force-removes only a `DELETING` IKE_SA for
which the same managed peer already has an established replacement with an
installed CHILD_SA. It never terminates by connection name or changes host
firewall rules. The isolated two-node regression test now forces concurrent
initiation and a one-sided peer restart, and requires exactly one working SA
on each side. This source change is not proof that a Catalog or live host has
already been upgraded.

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

The build is containerized and requires Docker on a Linux AMD64 host:

```sh
make test
make validate
VERSION_OVERRIDE=0.14.32 make build
TAG=0.14.32 make package
```

The package build downloads dependencies anonymously, verifies every standalone binary with SHA-256, pins the Ubuntu base image by digest, resolves every directly installed package from Canonical snapshot `20260808T000000Z` with the exact versions in `ubuntu-apt.lock`, and includes the corresponding strongSwan source archives in the image. Go dependencies are declared in `go.mod`, checksum-bound by `go.sum`, and committed in the standard module-aware `vendor` tree for offline builds.

The health reconciler canonicalizes strongSwan VICI CHILD_SA runtime names before comparing them with configured peer names. This prevents a VICI unique-ID suffix from being misclassified as a missing SA during a rolling replacement.

## Host firewall backends

The Catalog IPsec `overlay-router` runs in the host network namespace. With
`v0.14.29`, `PASTURESTACK_FIREWALL_BACKEND=auto` reads Docker's actual
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
