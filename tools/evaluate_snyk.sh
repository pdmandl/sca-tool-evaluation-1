#!/usr/bin/env bash
# evaluate_snyk.sh — Wrapper invoked by the SnykAdapter to scan a CycloneDX SBOM.
#
# Usage (called by the Python adapter):
#   /bin/bash tools/evaluate_snyk.sh <sbom_path>
#
# Prerequisites:
#   1. Snyk CLI installed:  npm install -g snyk
#   2. Authenticated:       snyk auth
#   3. SNYK_BIN env var set to the snyk binary path (default: /usr/local/bin/snyk)
#
# Output: JSON written to stdout (snyk sbom test --experimental --json).
#         Exit code 0 = success (even when vulnerabilities are found).
#         Exit code != 0 = execution error; the adapter will retry up to
#         SNYK_CLI_MAX_ATTEMPTS times before failing.

set -euo pipefail

SBOM_FILE="${1:-}"

if [ -z "$SBOM_FILE" ]; then
  echo "ERROR: No SBOM file path provided." >&2
  echo "Usage: $0 <sbom_path>" >&2
  exit 1
fi

if [ ! -f "$SBOM_FILE" ]; then
  echo "ERROR: SBOM file not found: $SBOM_FILE" >&2
  exit 1
fi

SNYK_BIN="${SNYK_BIN:-/usr/local/bin/snyk}"

if ! command -v "$SNYK_BIN" >/dev/null 2>&1; then
  echo "ERROR: Snyk CLI not found at $SNYK_BIN" >&2
  echo "       Install with: npm install -g snyk" >&2
  echo "       Then authenticate: snyk auth" >&2
  exit 1
fi

# snyk sbom test returns exit code 1 when vulnerabilities are found — that is
# expected behaviour. We therefore run without 'set -e' for this call and only
# fail on truly unexpected exit codes (2 = usage error, 3 = auth/network).
set +e
"$SNYK_BIN" sbom test \
  --experimental \
  --file="$SBOM_FILE" \
  --json
SNYK_EXIT=$?
set -e

# Exit code 0 = no vulns found (clean), 1 = vulns found (normal).
# Both are valid — the Python adapter parses the JSON from stdout.
if [ $SNYK_EXIT -eq 0 ] || [ $SNYK_EXIT -eq 1 ]; then
  exit 0
fi

echo "ERROR: snyk sbom test exited with unexpected code $SNYK_EXIT" >&2
exit $SNYK_EXIT
