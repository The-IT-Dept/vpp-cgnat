#!/bin/sh
# Run this repo's tests with VPP's make test.  Usage: scripts/test.sh <TEST> [make args]
# e.g. scripts/test.sh test_cgnat   or   scripts/test.sh test_cgnat.TestCgnatMap
set -e
VPP=${VPP:-$HOME/vpp}
REPO=$(cd "$(dirname "$0")/.." && pwd)
T=${1:-test_cgnat}; shift || true
cd "$VPP"
exec make test-debug TEST="$T" EXTERN_TESTS="$REPO/test" "$@"
