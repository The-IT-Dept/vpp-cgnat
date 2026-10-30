#!/bin/sh
# From a workstation: sync the repo to the build VM, rebuild VPP, run a test there.
# Usage: scripts/remote.sh [TEST]   (VM from $VPPDEV, default root@172.16.0.42)
# The build VM's ~/vpp must be v26.06 + patches/series (scripts/apply-patches.sh);
# scripts/check-patches.sh refuses to build anything else.
set -e
H=${VPPDEV:-root@172.16.0.42}
REPO=$(cd "$(dirname "$0")/.." && pwd)
rsync -rlpc --delete --exclude .git --exclude .superpowers --exclude __pycache__ "$REPO/" "$H:vpp-cgnat/"
ssh "$H" "cd vpp-cgnat && scripts/check-patches.sh ~/vpp || exit 1; scripts/link-into-vpp.sh >/dev/null && cd ~/vpp && make build >/tmp/build.log 2>&1 || { tail -40 /tmp/build.log; exit 1; }"
if [ -n "$1" ]; then ssh "$H" "cd vpp-cgnat && scripts/test.sh $*"; fi
