#!/usr/bin/env bash
#set -euo pipefail
set +e

# ------------------------------------------------------------
# Argument check
# ------------------------------------------------------------
if [ "$#" -ne 1 ]; then
  echo " Usage: $0 tool ∈ {dtrack, osv, github, snyk, oss-index, trivy}"
  exit 1
fi

if [ "$1" = "snyk" ]; then
  snyk whoami >/dev/null 2>&1 || \
    echo "WARNING: snyk auth not verified; SBOM scan may still work"
fi


# ------------------------------------------------------------
# Environment variables
# Adjust CODEBASE to your local checkout.
# ------------------------------------------------------------
export CODEBASE="${CODEBASE:-$(pwd)}"
export CODEBASE_BUILD_PATH="${CODEBASE}/build"
export GROUND_TRUTH_BUILD_PATH="${CODEBASE}/build/ground_truth"

# ------------------------------------------------------------
# Load environment from .env
# ------------------------------------------------------------

echo "Environment variables are loaded from $CODEBASE/.env"

if [ -f "$CODEBASE/.env" ]; then
  set -a
  . "$CODEBASE/.env"
  set +a
fi

# ------------------------------------------------------------
# REQUIRED ENV VARS (fail fast)
# ------------------------------------------------------------
require_env() {
  local var="$1"
  if [ -z "${!var:-}" ]; then
    echo "ERROR: Required environment variable '$var' is not set"
    exit 1
  fi
}

require_env GITHUB_TOKEN
require_env OSSINDEX_TOKEN


# ------------------------------------------------------------
# Dependency-Track access
# Values are loaded from .env (DTRACK_URL, DTRACK_API_KEY).
# Project metadata below must match the project into which the
# generated SBOM is uploaded.
# ------------------------------------------------------------
# export DTRACK_PROJECT_UUID="<project-uuid>"
# export DTRACK_PROJECT_NAME="<project-name>"
# export DTRACK_PROJECT_VERSION="1.0"


# ------------------------------------------------------------
# OSV / GitHub Advisory APIs
# Optional: path to a local OSV feed checkout.
# ------------------------------------------------------------
# export OSV_ROOT_PATH=/path/to/local/osv/vulnfeeds


#-----------------------------------------------------------------------------------
# Parameter for SNYK API
# Requires the snyk CLI installed locally. Authenticate first:
#   > snyk auth
#   > snyk sbom test --experimental --file=<sbom.json> --json
#-----------------------------------------------------------------------------------
export SNYK_BIN="${SNYK_BIN:-/usr/local/bin/snyk}"
export BASH_PATH="${BASH_PATH:-/bin/bash}"


#-----------------------------------------------------------------------------------
# OSS Index (Sonatype)
# Account: https://www.sonatype.com
# User token: https://ossindex.sonatype.org/user/settings
# OSSINDEX_USERNAME and OSSINDEX_TOKEN are loaded from .env.
#-----------------------------------------------------------------------------------

# ------------------------------------------------------------
# Ground truth
# Set GROUND_TRUTH and SBOM_PATH to the dataset you want to evaluate.
# ------------------------------------------------------------
# export GROUND_TRUTH=${GROUND_TRUTH_BUILD_PATH}/<dataset>.csv
# export SBOM_PATH=${GROUND_TRUTH_BUILD_PATH}/<dataset>.sbom.json

export SNYK_SBOM_FILE=${SBOM_PATH}
export TRIVY_SBOM_FILE=${SBOM_PATH}
TOOL="$1"

if [ -z "$TOOL" ]; then
  echo "Usage: $0 <tool>"
  exit 1
fi

echo "=== Running evaluation ==="
echo "Ground truth: ${GROUND_TRUTH}"
echo "Tool:         ${TOOL}"
echo

poetry run python -m evaluation.evaluate \
  --ground-truth "${GROUND_TRUTH}" \
  --tool "${TOOL}"

EVAL_RC=$?


if [ $EVAL_RC -ne 0 ]; then
  echo
  echo "=== Evaluation failed (exit code ${EVAL_RC}) ==="
  echo "Skipping findings analysis."
  exit $EVAL_RC
fi

echo
echo "=== Evaluation successful ==="
