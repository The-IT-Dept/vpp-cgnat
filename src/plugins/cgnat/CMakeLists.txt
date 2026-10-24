# SPDX-License-Identifier: Apache-2.0
# vpp-cgnat: deterministic port-block CGNAT for VPP

add_vpp_plugin(cgnat
  SOURCES
  cgnat.c
  cgnat_map.c
  cgnat_api.c
  cgnat_cli.c

  API_FILES
  cgnat.api
)
