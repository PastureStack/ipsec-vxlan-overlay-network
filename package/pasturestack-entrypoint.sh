#!/bin/bash
set -euo pipefail

/usr/bin/update-platform-ca

exec "$@"
