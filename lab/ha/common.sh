# shared settings for the HA lab (sourced)
VPPDIR=${VPPDIR:-$HOME/vpp/build-root/install-vpp-native/vpp}
RUN=/run/vpp-ha
export LD_LIBRARY_PATH=$VPPDIR/lib/x86_64-linux-gnu
vppctl_a() { $VPPDIR/bin/vppctl -s $RUN/a.sock "$@"; }
vppctl_b() { $VPPDIR/bin/vppctl -s $RUN/b.sock "$@"; }
NS() { ip netns exec "$@"; }
