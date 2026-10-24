#!/bin/sh
# From a workstation: sync the repo to the build VM, rebuild VPP, run a test there.
# Usage: scripts/remote.sh [TEST]   (VM from $VPPDEV, default root@157.20.113.112)
set -e
H=${VPPDEV:-root@157.20.113.112}
REPO=$(cd "$(dirname "$0")/.." && pwd)
rsync -a --delete --exclude .git --exclude .superpowers --exclude __pycache__ "$REPO/" "$H:vpp-cgnat/"
ssh "$H" "cd vpp-cgnat && scripts/link-into-vpp.sh >/dev/null && cd ~/vpp && make build >/tmp/build.log 2>&1 || { tail -40 /tmp/build.log; exit 1; }"
[ -n "$1" ] && ssh "$H" "cd vpp-cgnat && scripts/test.sh $*"
