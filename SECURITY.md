# Security policy

## Supported version

Only the newest published PastureStack release is supported. Older image tags are retained for provenance but do not receive security fixes.

## Reporting a vulnerability

Use the repository's **Security** tab to submit a private vulnerability report. Do not include credentials, private topology data, internal addresses, or an exploitable proof of concept in a public issue.

Include the affected image digest, command mode, host operating system, and the smallest redacted reproduction possible. PastureStack will preserve upstream attribution when forwarding an issue that originates in an upstream component.

## Runtime boundary

This image manages host networking and is intentionally privileged when launched by the infrastructure catalog. It must not be exposed as a general-purpose service, and its control-plane credentials must be injected only at runtime. No credentials are embedded in the image or release assets.

## Release gates

The release gate retains raw source, product, runtime, and disposable-builder
scan reports. Source, product binaries, and the runtime image must have zero
Critical, High, or secret findings.

The Ubuntu builder includes `linux-libc-dev` only because `libc6-dev` and GCC
need user-space Linux API headers for compilation and Go race tests. It does
not contain or execute the Linux kernel implementations named by those CVEs,
and it is not shipped as the product. The gate requires every Critical or High
builder finding to match the reviewed CVE list and the exact package PURL. It
also proves that neither the builder nor the product contains a kernel image or
module package, proves that the runtime omits `linux-libc-dev`, and generates a
machine-readable OpenVEX document as short-lived evidence. Any changed CVE,
package version, PURL, duplicate, or unreviewed finding fails closed.
