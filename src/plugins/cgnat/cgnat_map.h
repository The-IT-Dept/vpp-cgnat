/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 The vpp-cgnat authors
 */

#ifndef included_cgnat_map_h
#define included_cgnat_map_h

#include <vnet/ip/ip4_packet.h>

/*
 * A map is one inside prefix -> outside prefix with det44's formula:
 *   ratio         = inside_size / outside_size
 *   ports_per_sub = (65536 - 1024) / ratio
 *   outside       = outside_base + offset / ratio
 *   port_lo       = 1024 + ports_per_sub * (offset % ratio)
 * where offset = inside - inside_base.
 */
typedef struct
{
  u32 in_table_id;
  u32 out_table_id;
  u32 in_fib_index;
  u32 out_fib_index;
  ip4_address_t in_base; /* network order, masked */
  ip4_address_t out_base;
  u32 in_mask; /* network order */
  u32 out_mask;
  u8 in_plen;
  u8 out_plen;
  u32 ratio;
  u16 ports_per_sub;
} cgnat_map_t;

int cgnat_map_add_del (u32 in_table_id, ip4_address_t *in_pfx, u8 in_plen,
		       u32 out_table_id, ip4_address_t *out_pfx, u8 out_plen,
		       int is_add);

/* map containing inside address a in fib, or 0 */
cgnat_map_t *cgnat_map_by_inside (u32 in_fib_index, ip4_address_t *a);

/* map whose outside prefix contains a in fib, or 0 */
cgnat_map_t *cgnat_map_by_outside (u32 out_fib_index, ip4_address_t *a);

/* ports are host order */
static_always_inline void
cgnat_forward (cgnat_map_t *m, ip4_address_t *in, ip4_address_t *out,
	       u16 *port_lo, u16 *port_hi)
{
  u32 offset = clib_net_to_host_u32 (in->as_u32) -
	       clib_net_to_host_u32 (m->in_base.as_u32);

  out->as_u32 = clib_host_to_net_u32 (
    clib_net_to_host_u32 (m->out_base.as_u32) + offset / m->ratio);
  *port_lo = 1024 + m->ports_per_sub * (offset % m->ratio);
  *port_hi = *port_lo + m->ports_per_sub - 1;
}

/* out_port host order; 0 on success, -1 if the port is outside every block */
static_always_inline int
cgnat_reverse (cgnat_map_t *m, ip4_address_t *out, u16 out_port,
	       ip4_address_t *in)
{
  u32 out_off, block;

  if (out_port < 1024)
    return -1;
  block = (out_port - 1024) / m->ports_per_sub;
  if (block >= m->ratio)
    return -1;
  out_off = clib_net_to_host_u32 (out->as_u32) -
	    clib_net_to_host_u32 (m->out_base.as_u32);
  in->as_u32 = clib_host_to_net_u32 (
    clib_net_to_host_u32 (m->in_base.as_u32) + out_off * m->ratio + block);
  return 0;
}

#endif /* included_cgnat_map_h */
