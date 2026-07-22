# Security policy

## Supported version

Only the newest published PastureStack release is supported. Older image tags are retained for provenance but do not receive security fixes.

## Reporting a vulnerability

Use the repository's **Security** tab to submit a private vulnerability report. Do not include credentials, private topology data, internal addresses, or an exploitable proof of concept in a public issue.

Include the affected image digest, command mode, host operating system, and the smallest redacted reproduction possible. PastureStack will preserve upstream attribution when forwarding an issue that originates in an upstream component.

## Runtime boundary

This image manages host networking and is intentionally privileged when launched by the infrastructure catalog. It must not be exposed as a general-purpose service, and its control-plane credentials must be injected only at runtime. No credentials are embedded in the image or release assets.
