#!/bin/sh
# Symlink this repo's plugin into a VPP checkout so it builds in-tree.
set -e
VPP=${VPP:-$HOME/vpp}
REPO=$(cd "$(dirname "$0")/.." && pwd)
if [ ! -L "$VPP/src/plugins/cgnat" ] || [ ! -e "$VPP/build-root/install-vpp_debug-native/vpp/lib/x86_64-linux-gnu/vpp_plugins/cgnat_plugin.so" ]; then
  ln -sfn "$REPO/src/plugins/cgnat" "$VPP/src/plugins/cgnat"
  # VPP globs src/plugins/* at configure time: force a re-configure
  touch "$VPP/src/plugins/CMakeLists.txt"
fi
echo "linked $REPO/src/plugins/cgnat -> $VPP/src/plugins/cgnat"
