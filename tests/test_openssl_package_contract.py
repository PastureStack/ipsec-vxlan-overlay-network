"""Offline contract for the narrowly pinned Canonical OpenSSL security overlay."""

from pathlib import Path
import re
import unittest


BASE = Path(__file__).resolve().parents[1]
VERSION = "3.5.5-1ubuntu3.6"
SNAPSHOT = "20260930T000000Z"
CA_VERSION = "20260816ubuntu0.26.04.1"
CA_SHA256 = "5b6326f1932cfd7be57130561dc78192f09ed9f58bfbe6606ed0c50510c3b6cd"
# Canonical snapshot resolute-security/main/binary-amd64/Packages.gz SHA256 fields.
PACKAGES = {
    "libssl3t64": "44742b1e9c947ebb3b82215c13d968bd54e2e60bc42244af69301c5d057bb340",
    "openssl": "588e7f17afb9263a348c9587330805fc856536402328bec1660ff3a95e61bb4c",
    "openssl-provider-legacy": "1b582b937a1f7a8f987da9e1bbfcc806faea714267631ce0fbbd352c924b7daf",
}


def verify_dockerfile(source):
    additions = re.findall(
        r"^ADD --checksum=sha256:([0-9a-f]{64}) (https://\S+/openssl/\S+) (\S+)$",
        source, re.M,
    )
    expected = [
        (digest, "https://snapshot.ubuntu.com/ubuntu/" + SNAPSHOT
         + "/pool/main/o/openssl/" + name + "_" + VERSION + "_amd64.deb",
         "/tmp/pasturestack-" + name + ".deb")
        for name, digest in PACKAGES.items()
    ]
    if additions != expected:
        raise ValueError("exact official triplet URL, architecture and SHA256 required")
    transaction = re.search(
        r"apt-get install -y --no-install-recommends \\\n(.*?); \\\n", source, re.S,
    )
    if not transaction:
        raise ValueError("single pinned apt transaction required")
    local_debs = re.findall(r"/tmp/[^\s;]+\.deb", transaction.group(1))
    if sorted(local_debs) != sorted([item[2] for item in expected] + ["/tmp/ca-certificates.deb"]):
        raise ValueError("exact OpenSSL triplet and CA package required in apt transaction")
    ca_add = ("ADD --checksum=sha256:" + CA_SHA256
              + " https://archive.ubuntu.com/ubuntu/pool/main/c/ca-certificates/"
              + "ca-certificates_" + CA_VERSION + "_all.deb /tmp/ca-certificates.deb")
    ca_check = "test \"$(dpkg-query -W -f='${Version}' ca-certificates)\" = \"${UBUNTU_APT_CA_CERTIFICATES_VERSION}\""
    if source.count(ca_add) != 1 or source.count(ca_check) != 1:
        raise ValueError("official CA package and installed-version readback required")
    if source.index(ca_check) < transaction.end():
        raise ValueError("CA version must be verified after apt install")
    check = ("    for package in openssl libssl3t64 openssl-provider-legacy; do \\\n"
             "        test \"$(dpkg-query -W -f='${Version}' \"$package\")\" "
             "= \"${UBUNTU_APT_OPENSSL_VERSION}\"; \\\n"
             "    done; \\\n")
    if source.count(check) != 1 or source.index(check) < transaction.end():
        raise ValueError("all installed versions must match lock after apt install")
    if 'openssl="${UBUNTU_APT_OPENSSL_VERSION}"' in transaction.group(1):
        raise ValueError("stale snapshot OpenSSL package selection must not remain")
    if "--allow-unauthenticated" in source or "--allow-downgrades" in source:
        raise ValueError("package authentication and downgrade controls must remain")


class OpenSSLPackageContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sources = {name: (BASE / name).read_text(encoding="utf-8")
                       for name in ("Dockerfile.dapper", "package/Dockerfile")}

    def test_both_images_pin_install_and_verify_official_triplet(self):
        lock = (BASE / "ubuntu-apt.lock").read_text(encoding="utf-8")
        self.assertIn("UBUNTU_APT_OPENSSL_VERSION='" + VERSION + "'", lock)
        self.assertIn("UBUNTU_APT_CA_CERTIFICATES_VERSION='" + CA_VERSION + "'", lock)
        self.assertIn("UBUNTU_APT_SNAPSHOT='20260808T000000Z'", lock)
        self.assertIn("UBUNTU_APT_GCC_VERSION='4:15.2.0-5ubuntu1'", lock)
        for name, source in self.sources.items():
            with self.subTest(image=name):
                verify_dockerfile(source)
                self.assertIn('"${UBUNTU_APT_SNAPSHOT}" > /etc/apt/sources.list.d/', source)

    def test_mutated_url_hash_version_and_incomplete_install_rejected(self):
        for name, source in self.sources.items():
            changes = (
                source.replace("20260930T000000Z", "20261001T000000Z", 1),
                source.replace(PACKAGES["openssl"], "0" * 64, 1),
                source.replace(CA_SHA256, "0" * 64, 1),
                source.replace("        /tmp/ca-certificates.deb \\\n", "", 1),
                source.replace("openssl_" + VERSION, "openssl_3.5.5-1ubuntu3.3", 1),
                source.replace("        /tmp/pasturestack-openssl-provider-legacy.deb \\\n", "", 1),
                source.replace("= \"${UBUNTU_APT_OPENSSL_VERSION}\"", "= \"ignored\"", 1),
                source.replace("--no-install-recommends", "--no-install-recommends --allow-unauthenticated", 1),
            )
            for index, changed in enumerate(changes):
                with self.subTest(image=name, mutation=index):
                    self.assertNotEqual(source, changed)
                    with self.assertRaises(ValueError):
                        verify_dockerfile(changed)

    def test_formal_security_gate_executes_contract(self):
        workflow = (BASE / ".github/workflows/security-release-gate.yml").read_text(encoding="utf-8")
        self.assertEqual(workflow.count("          python3 tests/test_openssl_package_contract.py\n"), 1)
        self.assertLess(workflow.index("python3 tests/test_openssl_package_contract.py"),
                        workflow.index("name: Package the candidate runtime image"))

    def test_source_archives_precede_security_index_overlay(self):
        source = self.sources["package/Dockerfile"]
        overlay = source.index("    sh /usr/local/lib/pasturestack/install-ubuntu-security-updates.sh")
        self.assertLess(source.index("apt-get source --download-only strongswan="), overlay)
        self.assertLess(source.index('echo "${STRONGSWAN_DSC_SHA256}'), overlay)
        self.assertLess(overlay, source.index("/licenses/IPSEC-VXLAN-OVERLAY-RUNTIME-UBUNTU-APT-PACKAGES.tsv"))


if __name__ == "__main__":
    unittest.main()
