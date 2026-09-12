# Compatibility boundary

PastureStack names are the public interface for new deployments. A limited set of historical identifiers remains because the preserved control-plane protocol, metadata schema, or existing catalog contract still sends those exact values.

## Preferred interfaces

- Executable: `ipsec-vxlan-overlay-network`
- Connectivity check: `ipsec-vxlan-connectivity-check`
- Metadata URL environment variable: `PASTURESTACK_METADATA_URL`
- Metadata address environment variable: `PASTURESTACK_METADATA_ADDRESS`
- Debug environment variable: `PASTURESTACK_DEBUG`
- XFRM and host-route variables: `PASTURESTACK_NETWORK_XFRM_*`, `PASTURESTACK_NETWORK_RUN_IN_HOST_NETNS`, and `PASTURESTACK_NETWORK_SYNC_HOST_ROUTES`
- Host firewall selection: `PASTURESTACK_FIREWALL_BACKEND=auto|nftables|iptables-nft|iptables-legacy` for the IPsec host-XFRM router. `auto` reads Docker's live nftables or xtables NAT tables in the host namespace; it does not infer a mode from whichever CLI binary happens to be installed.
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

For Docker's native nftables bridge firewall, select `nftables` or let `auto` discover `ip docker-bridges`. The router does not write host firewall rules in this mode: the active network-plugin-manager must manage the overlay subnet's forwarding mark and exclude overlay destinations from its own egress masquerade. Docker must be configured to accept mark `0x1068/0x1068`. An xtables `ACCEPT` rule in a different nftables base chain is not a valid replacement for that NAT exclusion. The router does not alter Docker-owned chains, host FORWARD policy, or legacy kernel modules. If Docker's native table is absent, it chooses the live `iptables-nft` DOCKER NAT chain, or an already-loaded legacy DOCKER NAT chain for an old host; it fails closed if neither is identifiable. An explicit xtables selection is rejected while Docker's native table exists. Explicit `iptables-legacy` also refuses an active Docker `iptables-nft` chain or an unloaded legacy NAT table before invoking the legacy CLI, so a mistaken choice on Ubuntu 26.04 cannot load legacy modules merely by probing them.

The VXLAN router's historical POSTROUTING rule executes only inside its own container network namespace, not in the IPsec host-XFRM namespace. The IPsec firewall selection does not change that independent runtime path.

These identifiers must not be copied into new external APIs. They may be removed only after the server, agent, catalog, and stored environment data no longer emit or reference them.

Vendored Go import paths under `github.com/rancher/*` identify third-party upstream packages and remain for source and license traceability.
