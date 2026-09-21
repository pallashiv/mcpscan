#!/usr/bin/env bash
# Runs mcpscan for the GitHub Action (action.yml). Configuration comes from MCPSCAN_* env vars.
#
# This script never fails the step itself. The mcpscan exit code is reported through
# $GITHUB_OUTPUT so the SARIF upload step can still run before the job is failed.
set -u

args=(--fail-on "${MCPSCAN_FAIL_ON:-low}")
if [ -n "${MCPSCAN_BASELINE:-}" ]; then args+=(--baseline "$MCPSCAN_BASELINE"); fi
if [ -n "${MCPSCAN_IGNORE_FILE:-}" ]; then args+=(--ignore-file "$MCPSCAN_IGNORE_FILE"); fi

# Human-readable report in the job log.
mcpscan scan "$MCPSCAN_PATH" "${args[@]}"
code=$?

# Same scan as SARIF for code scanning. Skipped when the input itself was unusable (exit 2).
if [ "$code" -ne 2 ]; then
  mcpscan scan "$MCPSCAN_PATH" "${args[@]}" --format sarif --output "${MCPSCAN_SARIF_FILE:-mcpscan.sarif}" >/dev/null 2>&1
fi

echo "exit-code=$code" >> "${GITHUB_OUTPUT:-/dev/null}"
exit 0
