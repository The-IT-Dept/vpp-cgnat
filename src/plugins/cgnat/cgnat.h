/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 The vpp-cgnat authors
 */

#ifndef included_cgnat_h
#define included_cgnat_h

#include <vlib/vlib.h>
#include <vnet/vnet.h>

typedef struct
{
  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} cgnat_main_t;

extern cgnat_main_t cgnat_main;

#endif /* included_cgnat_h */
