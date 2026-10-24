/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 The vpp-cgnat authors
 */

#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <cgnat/cgnat.h>

cgnat_main_t cgnat_main;

static clib_error_t *
cgnat_init (vlib_main_t *vm)
{
  cgnat_main_t *cm = &cgnat_main;

  clib_memset (cm, 0, sizeof (*cm));
  cm->vlib_main = vm;
  cm->vnet_main = vnet_get_main ();
  return 0;
}

VLIB_INIT_FUNCTION (cgnat_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "CGNAT: deterministic port blocks, HA pair (vpp-cgnat)",
};
