# Third-party notices

PastureStack does not relicense third-party work. Copyright, license, and attribution files remain controlling.

| Component | Version | Source | License |
| --- | --- | --- | --- |
| strongSwan | Ubuntu `6.0.4-1ubuntu3.1` | [Ubuntu source package](https://packages.ubuntu.com/source/resolute-updates/strongswan) | GPL-2.0-or-later with OpenSSL exception, plus file-specific licenses listed by Ubuntu |
| CNI reference plugins | 0.3.0 | [containernetworking/plugins](https://github.com/containernetworking/plugins) | Apache-2.0 |
| CNI bridge compatibility binary | 0.3.1 | [rancher/rancher-cni-bridge](https://github.com/rancher/rancher-cni-bridge) | Apache-2.0 |
| Weave router helper | r-v0.0.4 | [rancher-archives/weave](https://github.com/rancher-archives/weave) | Apache-2.0 |
| Metadata CNI IPAM | 0.2.6 | [PastureStack/metadata-cni-ipam](https://github.com/PastureStack/metadata-cni-ipam) | Apache-2.0 |
| Host-local CNI IPAM | 0.1.3 | [PastureStack/host-local-cni-ipam](https://github.com/PastureStack/host-local-cni-ipam) | Apache-2.0 |
| Flat CNI IPAM | 0.1.3 | [PastureStack/flat-cni-ipam](https://github.com/PastureStack/flat-cni-ipam) | Apache-2.0 |
| Per-host subnet | 0.2.7 | [PastureStack/per-host-subnet](https://github.com/PastureStack/per-host-subnet) | Apache-2.0 |
| Mount propagation | 1.0.10 | [PastureStack/mount-propagation](https://github.com/PastureStack/mount-propagation) | Apache-2.0 |

The reachable vendored Go dependency set and each complete source revision are recorded in [`vendor.lock`](vendor.lock). Unreachable historical test-server dependencies are not shipped.

The image stores Ubuntu package copyright files under `/licenses/ubuntu-packages`. It also carries the exact strongSwan original source archive, Ubuntu packaging archive, and source control file under `/licenses/strongswan-source`, with hashes verified during the image build.

Vendored Go dependency license files are copied to `/licenses/pasturestack/vendor`. The root [LICENSE](LICENSE) and files under [`LICENSES`](LICENSES) cover this repository and the bundled Go toolchain notices; they do not replace any third-party license.
