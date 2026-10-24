# SPDX-License-Identifier: Apache-2.0
# vpp-cgnat: deterministic port-block CGNAT for VPP

add_vpp_plugin(cgnat
  SOURCES
  cgnat.c
  cgnat_map.c
  cgnat_session.c
  cgnat_api.c
  cgnat_cli.c
  cgnat_in2out.c
  cgnat_out2in.c
  cgnat_expire.c
  cgnat_cluster.c
  cgnat_cluster_input.c

  MULTIARCH_SOURCES
  cgnat_in2out.c
  cgnat_out2in.c
  cgnat_expire.c

  API_FILES
  cgnat.api
)
