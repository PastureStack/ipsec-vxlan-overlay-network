# Compatibility boundary

PastureStack names are the public interface for new deployments. A limited set of historical identifiers remains because the preserved control-plane protocol, metadata schema, or existing catalog contract still sends those exact values.

## Preferred interfaces

- Executable: `ipsec-vxlan-overlay-network`
- Connectivity check: `ipsec-vxlan-connectivity-check`
- Metadata URL environment variable: `PASTURESTACK_METADATA_URL`
- Metadata address environment variable: `PASTURESTACK_METADATA_ADDRESS`
- Debug environment variable: `PASTURESTACK_DEBUG`
- XFRM and host-route variables: `PASTURESTACK_NETWORK_XFRM_*`, `PASTURESTACK_NETWORK_RUN_IN_HOST_NETNS`, and `PASTURESTACK_NETWORK_SYNC_HOST_ROUTES`
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

These identifiers must not be copied into new external APIs. They may be removed only after the server, agent, catalog, and stored environment data no longer emit or reference them.

Vendored Go import paths under `github.com/rancher/*` identify third-party upstream packages and remain for source and license traceability.
