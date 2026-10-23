"""Prevent a published runtime from bypassing fixed LOW/MEDIUM findings."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]

class FullSeverityContract(unittest.TestCase):
    def test_candidate_and_release_scan_all_severities_and_enforce_policy(self):
        for name in ("security-release-gate.yml", "release.yml"):
            source = (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")
            self.assertNotIn("--severity CRITICAL,HIGH", source)
            self.assertIn("--severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL", source)
            self.assertIn(".github/scripts/enforce-runtime-vulnerabilities.py", source)
            self.assertIn("dapper-nonheader-security.json", source)
        policy = (ROOT / ".github/scripts/enforce-runtime-vulnerabilities.py").read_text(encoding="utf-8")
        self.assertIn(".github/runtime-unfixed.json", policy)
        self.assertIn(".github/dapper-unfixed.json", policy)
        release = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        self.assertLess(release.index(".github/scripts/enforce-runtime-vulnerabilities.py"),
                        release.index("- name: Publish a new tag"))

    def test_builder_filter_is_exact_and_never_replaces_raw_evidence(self):
        source = (ROOT / ".github/workflows/security-release-gate.yml").read_text(encoding="utf-8")
        self.assertIn("pkg:deb/ubuntu/linux-libc-dev@7.0.0-38.38?arch=amd64&distro=ubuntu-26.04", source)
        self.assertIn("select(.PkgIdentifier.PURL != $purl)", source)
        self.assertIn("evidence/dapper-security.json > evidence/dapper-nonheader-security.json", source)
        self.assertIn("linux-libc-dev must not be shipped in the runtime image", source)

    def test_compiled_products_are_identified_by_rootfs_analyzer(self):
        source = (ROOT / ".github/workflows/security-release-gate.yml").read_text(encoding="utf-8")
        self.assertIn('run_path_scan rootfs "$product_tree" product-security.json', source)
        self.assertIn('--scanners vuln,secret --list-all-pkgs', source)
        for name in ("security-release-gate.yml", "release.yml"):
            workflow = (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")
            self.assertIn('.Type == "gobinary" and .Target == $binary', workflow)
            self.assertIn('.Packages[]?] | length > 0', workflow)

    def test_only_reviewed_strongswan_and_sysusers_versions_are_overlaid(self):
        lock = (ROOT / "security/ubuntu-security-packages.lock").read_text(encoding="utf-8")
        for package in ("libstrongswan", "libstrongswan-extra-plugins", "libstrongswan-standard-plugins",
                        "strongswan-charon", "strongswan-libcharon", "strongswan-swanctl"):
            self.assertIn(package + "=6.0.4-1ubuntu3.2\n", lock)
        self.assertIn("systemd-standalone-sysusers=259.5-0ubuntu3.4\n", lock)

if __name__ == "__main__":
    unittest.main()
