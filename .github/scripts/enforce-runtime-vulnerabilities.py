"""Enforce release findings; only exact, reviewed unfixed low/medium entries may pass."""
import argparse
import json
from pathlib import Path


def violations(report, ledger, repository):
    if (not isinstance(report, dict) or report.get("SchemaVersion") != 2
            or not isinstance(report.get("Results"), list) or not report["Results"]):
        raise ValueError("missing or malformed Trivy scan results")
    for result in report["Results"]:
        if not isinstance(result, dict) or not isinstance(result.get("Target"), str):
            raise ValueError("malformed Trivy result")
        for key in ("Vulnerabilities", "Secrets"):
            if key in result and result[key] is not None and not isinstance(result[key], list):
                raise ValueError("malformed Trivy findings")
    if ledger.get("repository") != repository:
        raise ValueError("allowlist repository mismatch")
    reviewed = {}
    for entry in ledger.get("unfixed", []):
        key = (entry["id"], entry["package"], entry["version"], entry.get("purl", ""))
        if key in reviewed:
            raise ValueError("duplicate reviewed finding")
        if (entry.get("severity") not in ("LOW", "MEDIUM")
                or entry.get("status") != "no_official_fix"
                or not entry.get("officialEvidence", "").startswith("https://")
                or not entry.get("reason") or not entry.get("checkedAt")):
            raise ValueError("incomplete official no-fix evidence")
        reviewed[key] = entry
    errors = []
    for result in report.get("Results") or []:
        if result.get("Secrets"):
            errors.append("secret findings remain")
        for finding in result.get("Vulnerabilities") or []:
            severity = finding.get("Severity", "UNKNOWN")
            key = (finding.get("VulnerabilityID"), finding.get("PkgName"),
                   finding.get("InstalledVersion"),
                   (finding.get("PkgIdentifier") or {}).get("PURL", ""))
            entry = reviewed.get(key)
            fixed = str(finding.get("FixedVersion") or "").strip()
            if (severity not in ("LOW", "MEDIUM") or fixed
                    or entry is None or entry["severity"] != severity):
                errors.append("%s %s@%s severity=%s fixed=%s" % (
                    key[0], key[1], key[2], severity, fixed or "none"))
    return errors


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    # Workflows select a known evidence scope, never an arbitrary input path.
    reports = {
        "source": "evidence/source-security.json",
        "product": "evidence/product-security.json",
        "runtime": "evidence/runtime-security.effective.json",
        "dapper": "evidence/dapper-nonheader-security.json",
        "release-runtime": "dist/release/runtime-security.effective.json",
    }
    parser.add_argument("scope", choices=tuple(reports))
    parser.add_argument("--repository", required=True)
    args = parser.parse_args()
    report_path = Path(reports[args.scope])
    ledger_path = Path(".github/dapper-unfixed.json" if args.scope == "dapper"
                       else ".github/runtime-unfixed.json")
    failures = violations(json.loads(report_path.read_text(encoding="utf-8")),
                          json.loads(ledger_path.read_text(encoding="utf-8")), args.repository)
    if failures:
        raise SystemExit("Release vulnerability policy failed:\n" + "\n".join(failures))
    print("RELEASE_VULNERABILITY_POLICY_OK")
