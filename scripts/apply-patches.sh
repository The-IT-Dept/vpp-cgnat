#!/bin/sh
# Apply this repo's VPP patches to a pristine VPP checkout, in the order of
# patches/series.  Usage: scripts/apply-patches.sh <vpp-dir>
#
# The checkout must be at v26.06 (or $VPP_BASE) with no changes to tracked
# files.  Each patch goes through git apply --index: no fuzz, no 3-way merge.
# If one does not apply, the ones applied before it are reversed, the tree is
# left as it was found, and the script exits non-zero.
set -eu
REPO=$(cd "$(dirname "$0")/.." && pwd)
PATCHES=$REPO/patches
BASE=${VPP_BASE:-v26.06}

die() { echo "apply-patches: $*" >&2; exit 1; }

[ $# -eq 1 ] || die "usage: $0 <vpp-dir>"
VPP=$(git -C "$1" rev-parse --show-toplevel 2>/dev/null) || die "$1 is not a git checkout"

# patches/series names every patch, once, and nothing else
[ -f "$PATCHES/series" ] || die "no patches/series"
series=$(sed -e 's/#.*//' -e 's/[[:space:]]*$//' -e '/^$/d' "$PATCHES/series")
[ -n "$series" ] || die "patches/series is empty"
dups=$(echo "$series" | sort | uniq -d)
[ -z "$dups" ] || die "patches/series lists more than once: $dups"
for p in $series; do
  [ -f "$PATCHES/$p" ] || die "patches/series names $p, which is not in patches/"
done
for f in "$PATCHES"/*.patch; do
  [ -e "$f" ] || continue
  echo "$series" | grep -qxF "$(basename "$f")" || die "patches/$(basename "$f") is not in patches/series"
done

# a pristine base
base=$(git -C "$VPP" rev-parse -q --verify "$BASE^{commit}") || die "$VPP has no $BASE (git fetch --tags?)"
[ "$(git -C "$VPP" rev-parse HEAD)" = "$base" ] ||
  die "$VPP is at $(git -C "$VPP" describe --tags --always HEAD), not $BASE"
[ -z "$(git -C "$VPP" status --porcelain --untracked-files=no)" ] ||
  die "$VPP has changes to tracked files; start from a clean $BASE"

applied="" reverse=""
for p in $series; do
  if git -C "$VPP" apply --index "$PATCHES/$p"; then
    echo "applied $p"
    applied="$applied $p" reverse="$p $reverse"
    continue
  fi
  echo "apply-patches: FAILED: $p does not apply on $BASE +${applied:- nothing}" >&2
  for q in $reverse; do
    git -C "$VPP" apply --index -R "$PATCHES/$q" || die "could not reverse $q, $VPP is half patched"
    echo "reversed $q" >&2
  done
  die "nothing applied, $VPP is back at a clean $BASE"
done
echo "$VPP: $BASE + $(echo "$series" | wc -l | tr -d ' ') patches, staged: $(git -C "$VPP" diff --cached --shortstat)"
