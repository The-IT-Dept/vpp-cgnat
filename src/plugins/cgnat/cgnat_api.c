/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 The vpp-cgnat authors
 */

#include <vnet/ip/ip_types_api.h>
#include <vnet/fib/fib_table.h>
#include <vlibmemory/api.h>
#include <cgnat/cgnat.h>
#include <cgnat/cgnat.api_enum.h>
#include <cgnat/cgnat.api_types.h>

#define REPLY_MSG_ID_BASE cm->msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
vl_api_cgnat_map_add_del_t_handler (vl_api_cgnat_map_add_del_t *mp)
{
  cgnat_main_t *cm = &cgnat_main;
  vl_api_cgnat_map_add_del_reply_t *rmp;
  ip4_address_t in, out;
  int rv;

  ip4_address_decode (mp->in_addr, &in);
  ip4_address_decode (mp->out_addr, &out);
  rv = cgnat_map_add_del (ntohl (mp->in_vrf), &in, mp->in_plen,
			  ntohl (mp->out_vrf), &out, mp->out_plen, mp->is_add);
  REPLY_MACRO (VL_API_CGNAT_MAP_ADD_DEL_REPLY);
}

static void
vl_api_cgnat_map_dump_t_handler (vl_api_cgnat_map_dump_t *mp)
{
  cgnat_main_t *cm = &cgnat_main;
  vl_api_cgnat_map_details_t *rmp;
  vl_api_registration_t *reg;
  cgnat_map_t *m;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  pool_foreach (m, cm->maps)
    {
      rmp = vl_msg_api_alloc_zero (sizeof (*rmp));
      rmp->_vl_msg_id = htons (VL_API_CGNAT_MAP_DETAILS + cm->msg_id_base);
      rmp->context = mp->context;
      rmp->in_vrf = htonl (m->in_table_id);
      ip4_address_encode (&m->in_base, rmp->in_addr);
      rmp->in_plen = m->in_plen;
      rmp->out_vrf = htonl (m->out_table_id);
      ip4_address_encode (&m->out_base, rmp->out_addr);
      rmp->out_plen = m->out_plen;
      rmp->ratio = htonl (m->ratio);
      rmp->ports_per_sub = htons (m->ports_per_sub);
      vl_api_send_msg (reg, (u8 *) rmp);
    }
}

static void
vl_api_cgnat_forward_t_handler (vl_api_cgnat_forward_t *mp)
{
  cgnat_main_t *cm = &cgnat_main;
  vl_api_cgnat_forward_reply_t *rmp;
  ip4_address_t in, out = {};
  u16 lo = 0, hi = 0;
  cgnat_map_t *m = 0;
  u32 fib_index;
  int rv = 0;

  ip4_address_decode (mp->in_addr, &in);
  fib_index = fib_table_find (FIB_PROTOCOL_IP4, ntohl (mp->in_vrf));
  if (fib_index != ~0)
    m = cgnat_map_by_inside (fib_index, &in);
  if (m)
    cgnat_forward (m, &in, &out, &lo, &hi);
  else
    rv = VNET_API_ERROR_NO_SUCH_ENTRY;

  REPLY_MACRO2 (VL_API_CGNAT_FORWARD_REPLY, ({
		  ip4_address_encode (&out, rmp->out_addr);
		  rmp->port_lo = htons (lo);
		  rmp->port_hi = htons (hi);
		}));
}

static void
vl_api_cgnat_reverse_t_handler (vl_api_cgnat_reverse_t *mp)
{
  cgnat_main_t *cm = &cgnat_main;
  vl_api_cgnat_reverse_reply_t *rmp;
  ip4_address_t in = {}, out;
  cgnat_map_t *m = 0;
  u32 fib_index, table_id = 0;
  int rv = 0;

  ip4_address_decode (mp->out_addr, &out);
  fib_index = fib_table_find (FIB_PROTOCOL_IP4, ntohl (mp->out_vrf));
  if (fib_index != ~0)
    m = cgnat_map_by_outside (fib_index, &out);
  if (!m || cgnat_reverse (m, &out, ntohs (mp->out_port), &in))
    rv = VNET_API_ERROR_NO_SUCH_ENTRY;
  else
    table_id = m->in_table_id;

  REPLY_MACRO2 (VL_API_CGNAT_REVERSE_REPLY, ({
		  rmp->in_vrf = htonl (table_id);
		  ip4_address_encode (&in, rmp->in_addr);
		}));
}

#include <vnet/format_fns.h>
#include <cgnat/cgnat.api.c>

static clib_error_t *
cgnat_api_init (vlib_main_t *vm)
{
  cgnat_main_t *cm = &cgnat_main;
  cm->msg_id_base = setup_message_id_table ();
  return 0;
}

VLIB_INIT_FUNCTION (cgnat_api_init) = {
  .runs_after = VLIB_INITS ("cgnat_init"),
};
