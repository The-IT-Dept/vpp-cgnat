/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 The vpp-cgnat authors
 */

#include <vnet/fib/fib_table.h>
#include <cgnat/cgnat.h>

static u32
plen_to_mask (u8 plen)
{
  return plen ? clib_host_to_net_u32 (~0u << (32 - plen)) : 0;
}

static int
prefixes_overlap (ip4_address_t *a, u8 alen, ip4_address_t *b, u8 blen)
{
  u32 mask = plen_to_mask (clib_min (alen, blen));
  return (a->as_u32 & mask) == (b->as_u32 & mask);
}

static cgnat_map_t *
map_lookup (u32 **by_fib, u32 fib_index, ip4_address_t *a, int inside)
{
  cgnat_main_t *cm = &cgnat_main;
  u32 *mi;

  if (fib_index >= vec_len (by_fib))
    return 0;
  vec_foreach (mi, by_fib[fib_index])
    {
      cgnat_map_t *m = pool_elt_at_index (cm->maps, *mi);
      if (inside ? (a->as_u32 & m->in_mask) == m->in_base.as_u32 :
		   (a->as_u32 & m->out_mask) == m->out_base.as_u32)
	return m;
    }
  return 0;
}

cgnat_map_t *
cgnat_map_by_inside (u32 in_fib_index, ip4_address_t *a)
{
  return map_lookup (cgnat_main.maps_by_in_fib, in_fib_index, a, 1);
}

cgnat_map_t *
cgnat_map_by_outside (u32 out_fib_index, ip4_address_t *a)
{
  return map_lookup (cgnat_main.maps_by_out_fib, out_fib_index, a, 0);
}

static void
index_del (u32 **by_fib, u32 fib_index, u32 map_index)
{
  u32 i = vec_search (by_fib[fib_index], map_index);
  if (i != ~0)
    vec_del1 (by_fib[fib_index], i);
}

int
cgnat_map_add_del (u32 in_table_id, ip4_address_t *in_pfx, u8 in_plen,
		   u32 out_table_id, ip4_address_t *out_pfx, u8 out_plen,
		   int is_add)
{
  cgnat_main_t *cm = &cgnat_main;
  ip4_address_t in_base, out_base;
  cgnat_map_t *m;
  u32 ratio;

  if (in_plen < 1 || in_plen > 32 || out_plen < 1 || out_plen > 32)
    return VNET_API_ERROR_INVALID_VALUE;

  in_base.as_u32 = in_pfx->as_u32 & plen_to_mask (in_plen);
  out_base.as_u32 = out_pfx->as_u32 & plen_to_mask (out_plen);

  if (!is_add)
    {
      pool_foreach (m, cm->maps)
	{
	  if (m->in_table_id == in_table_id && m->in_plen == in_plen &&
	      m->in_base.as_u32 == in_base.as_u32 &&
	      m->out_table_id == out_table_id && m->out_plen == out_plen &&
	      m->out_base.as_u32 == out_base.as_u32)
	    {
	      u32 mi = m - cm->maps;
	      index_del (cm->maps_by_in_fib, m->in_fib_index, mi);
	      index_del (cm->maps_by_out_fib, m->out_fib_index, mi);
	      fib_table_unlock (m->in_fib_index, FIB_PROTOCOL_IP4,
				cm->fib_src);
	      fib_table_unlock (m->out_fib_index, FIB_PROTOCOL_IP4,
				cm->fib_src);
	      pool_put (cm->maps, m);
	      return 0;
	    }
	}
      return VNET_API_ERROR_NO_SUCH_ENTRY;
    }

  /* inside must be at least as big as outside */
  if (in_plen > out_plen)
    return VNET_API_ERROR_INVALID_VALUE;
  ratio = 1u << (out_plen - in_plen);
  if (ratio > (65536 - 1024))
    return VNET_API_ERROR_INVALID_VALUE;

  pool_foreach (m, cm->maps)
    {
      if (m->in_table_id == in_table_id &&
	  prefixes_overlap (&m->in_base, m->in_plen, &in_base, in_plen))
	return VNET_API_ERROR_VALUE_EXIST;
      if (m->out_table_id == out_table_id &&
	  prefixes_overlap (&m->out_base, m->out_plen, &out_base, out_plen))
	return VNET_API_ERROR_VALUE_EXIST;
    }

  pool_get_zero (cm->maps, m);
  m->in_table_id = in_table_id;
  m->out_table_id = out_table_id;
  m->in_fib_index = fib_table_find_or_create_and_lock (
    FIB_PROTOCOL_IP4, in_table_id, cm->fib_src);
  m->out_fib_index = fib_table_find_or_create_and_lock (
    FIB_PROTOCOL_IP4, out_table_id, cm->fib_src);
  m->in_base = in_base;
  m->out_base = out_base;
  m->in_plen = in_plen;
  m->out_plen = out_plen;
  m->in_mask = plen_to_mask (in_plen);
  m->out_mask = plen_to_mask (out_plen);
  m->ratio = ratio;
  m->ports_per_sub = (65536 - 1024) / ratio;

  vec_validate (cm->maps_by_in_fib, m->in_fib_index);
  vec_validate (cm->maps_by_out_fib, m->out_fib_index);
  vec_add1 (cm->maps_by_in_fib[m->in_fib_index], m - cm->maps);
  vec_add1 (cm->maps_by_out_fib[m->out_fib_index], m - cm->maps);
  return 0;
}
