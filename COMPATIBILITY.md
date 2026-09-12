# Compatibility boundary

PastureStack names are the public interface for new deployments. A limited set of historical identifiers remains because the preserved control-plane protocol, metadata schema, or existing catalog contract still sends those exact values.

## Preferred interfaces

- Executable: `ipsec-vxlan-overlay-network`
- Connectivity check: `ipsec-vxlan-connectivity-check`
- Metadata URL environment variable: `PASTURESTACK_METADATA_URL`
- Metadata address environment variable: `PASTURESTACK_METADATA_ADDRESS`
- Debug environment variable: `PASTURESTACK_DEBUG`
- XFRM and host-route variables: `PASTURESTACK_NETWORK_XFRM_*`, `PASTURESTACK_NETWORK_RUN_IN_HOST_NETNS`, and `PASTURESTACK_NETWORK_SYNC_HOST_ROUTES`
- Host firewall selection: `PASTURESTACK_FIREWALL_BACKEND=auto|nftables|iptables-nft|iptables-legacy` for the IPsec host-XFRM router. From `v0.14.28`, it reads Docker's actual `/info.FirewallBackend.Driver` from the mounted Unix socket and then validates the uniquely active, matching host firewall hooks. An old Docker release with no native nftables support may omit this API field; a Docker 29+ release omitting it is ambiguous and fails closed. A mounted Unix socket is a privileged API capability even if its bind mount says `:ro`.
- CNI log: `/var/log/pasturestack-cni.log`
- Platform CA: `/var/lib/pasturestack/etc/ssl/ca.crt`

## Required compatibility identifiers

The following are compatibility adapters, not PastureStack branding:

- `CATTLE_*` credentials and URL variables used by the preserved control-plane API.
- `io.rancher.*` labels and CNI schema keys supplied by the preserved API.
- `rancher.internal`, the DNS search suffix in the preserved network contract.
- `RANCHER_*` environment variables accepted as lower-priority fallbacks.
- Executable aliases `rancher-net`, `connectivity-check`, `share-mnt`, and `r`.
- CNI aliases `rancher-bridge`, `rancher-cni-ipam`, `rancher-host-local-ipam`, and `rancher-flat-ipam`.
- Legacy CA and state paths under `/var/lib/rancher` and `/var/lib/cattle`.

The default metadata endpoint is the brand-neutral link-local address `http://169.254.169.250/2015-12-19`; it does not depend on an internal DNS alias.

For Docker's native nftables bridge firewall, Docker must report `nftables`
and its `ip docker-bridges` table must contain active forward and postrouting
base hooks. The router never writes host firewall rules in host-XFRM mode:
the active network-plugin-manager must manage the overlay subnet's forwarding
and exclude overlay destinations from its own egress masquerade in all three
backends. Upgrade the manager and verify it is healthy before upgrading the
router; the router no longer patches manager-owned `CATTLE_*` chains. Docker
must be configured to accept mark `0x1068/0x1068`. An xtables `ACCEPT` rule
in a different nftables base chain is not a valid replacement for that NAT
exclusion. For Docker's `iptables` driver, a declared `DOCKER` NAT chain must
also have a live PREROUTING or OUTPUT jump through exactly one frontend,
`iptables-nft` or `iptables-legacy`. A stale table/chain, dual-active hooks,
an explicit mismatch, an opposite frontend's reachable `CATTLE_*` hook or
`FORWARD DROP` policy, or a Docker API failure stops startup. Orphan
`CATTLE_*` chains without a hook are not treated as active. The router reads
legacy NAT rules only if `/proc/net/ip_tables_names` already lists `nat`. A
missing procfs list means no loaded legacy tables; any other read failure stops
startup. It never probes an unloaded legacy table or modifies Docker-owned chains
or the host FORWARD policy. The historical container-network-namespace path
remains independent of this host-mode detection.

The VXLAN router's historical POSTROUTING rule executes only inside its own container network namespace, not in the IPsec host-XFRM namespace. The IPsec firewall selection does not change that independent runtime path.

These identifiers must not be copied into new external APIs. They may be removed only after the server, agent, catalog, and stored environment data no longer emit or reference them.

Vendored Go import paths under `github.com/rancher/*` identify third-party upstream packages and remain for source and license traceability.
