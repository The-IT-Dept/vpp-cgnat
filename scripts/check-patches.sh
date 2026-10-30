#!/bin/sh
# Check that a VPP checkout is exactly v26.06 (or $VPP_BASE) + patches/series,
# as scripts/apply-patches.sh leaves it, before building or packaging it: a
# reset or recloned tree would otherwise build a VPP without the fixes, and
# the time fix adds no strings to check a binary for.  Untracked files (the
# cgnat plugin symlink) don't count.  Prints the tree hash to record with a
# build.  Usage: scripts/check-patches.sh <vpp-dir>
set -eu
REPO=$(cd "$(dirname "$0")/.." && pwd)
PATCHES=$REPO/patches
BASE=${VPP_BASE:-v26.06}

die() { echo "check-patches: $*" >&2; exit 1; }

[ $# -eq 1 ] || die "usage: $0 <vpp-dir>"
VPP=$(git -C "$1" rev-parse --show-toplevel 2>/dev/null) || die "$1 is not a git checkout"
base=$(git -C "$VPP" rev-parse -q --verify "$BASE^{commit}") || die "$VPP has no $BASE (git fetch --tags?)"
[ "$(git -C "$VPP" rev-parse HEAD)" = "$base" ] ||
  die "$VPP is at $(git -C "$VPP" describe --tags --always HEAD), not $BASE"
[ -f "$PATCHES/series" ] || die "no patches/series"
series=$(sed -e 's/#.*//' -e 's/[[:space:]]*$//' -e '/^$/d' "$PATCHES/series")

# the tree base + series should give, built in a scratch index
idx=$(mktemp)
trap 'rm -f "$idx"' EXIT
GIT_INDEX_FILE=$idx git -C "$VPP" read-tree "$base"
for p in $series; do
  GIT_INDEX_FILE=$idx git -C "$VPP" apply --cached "$PATCHES/$p" ||
    die "$p does not apply on $BASE + the patches before it"
done
want=$(GIT_INDEX_FILE=$idx git -C "$VPP" write-tree)

# ...against the checkout's tracked files as they are on disk
if ! git -C "$VPP" diff --quiet "$want" --; then
  git -C "$VPP" diff --stat "$want" -- >&2
  die "$VPP is not $BASE + patches/series (differences above); start from a clean $BASE and run scripts/apply-patches.sh"
fi
echo "$VPP: $BASE + patches/series, tree $want"
