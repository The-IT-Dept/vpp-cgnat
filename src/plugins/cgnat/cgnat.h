/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 The vpp-cgnat authors
 */

#ifndef included_cgnat_h
#define included_cgnat_h

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/fib/fib_source.h>
#include <cgnat/cgnat_map.h>

typedef struct
{
  /* maps */
  cgnat_map_t *maps;
  u32 **maps_by_in_fib;
  u32 **maps_by_out_fib;
  fib_source_t fib_src;

  u16 msg_id_base;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} cgnat_main_t;

extern cgnat_main_t cgnat_main;

#endif /* included_cgnat_h */
