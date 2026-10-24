/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 The vpp-cgnat authors
 */

#include <vnet/ip/ip_types_api.h>
#include <vnet/fib/fib_table.h>
#include <vlibmemory/api.h>
#include <cgnat/cgnat.h>
#include <cgnat/cgnat_session.h>
#include <cgnat/cgnat_owner.h>
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

static void
vl_api_cgnat_interface_add_del_feature_t_handler (
  vl_api_cgnat_interface_add_del_feature_t *mp)
{
  cgnat_main_t *cm = &cgnat_main;
  vl_api_cgnat_interface_add_del_feature_reply_t *rmp;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);
  rv = cgnat_interface_add_del (ntohl (mp->sw_if_index), mp->is_inside,
				mp->is_add);
  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_CGNAT_INTERFACE_ADD_DEL_FEATURE_REPLY);
}

static void
vl_api_cgnat_set_filtering_t_handler (vl_api_cgnat_set_filtering_t *mp)
{
  cgnat_main_t *cm = &cgnat_main;
  vl_api_cgnat_set_filtering_reply_t *rmp;
  int rv = 0;

  cm->endpoint_independent_filtering = mp->endpoint_independent;
  REPLY_MACRO (VL_API_CGNAT_SET_FILTERING_REPLY);
}

static void
vl_api_cgnat_set_session_limit_t_handler (
  vl_api_cgnat_set_session_limit_t *mp)
{
  cgnat_main_t *cm = &cgnat_main;
  vl_api_cgnat_set_session_limit_reply_t *rmp;
  u32 limit = ntohl (mp->per_subscriber);
  u32 inbound = ntohl (mp->inbound_per_subscriber);
  int rv = 0;

  if (limit == 0)
    rv = VNET_API_ERROR_INVALID_VALUE;
  else
    {
      cm->sessions_per_sub = limit;
      if (inbound)
	cm->inbound_sessions_per_sub = inbound;
    }
  REPLY_MACRO (VL_API_CGNAT_SET_SESSION_LIMIT_REPLY);
}

static void
vl_api_cgnat_set_timeouts_t_handler (vl_api_cgnat_set_timeouts_t *mp)
{
  cgnat_main_t *cm = &cgnat_main;
  vl_api_cgnat_set_timeouts_reply_t *rmp;
  u32 v[CGNAT_N_TO];
  int rv = 0, i;

  v[CGNAT_TO_TCP_EST] = ntohl (mp->tcp_established);
  v[CGNAT_TO_TCP_TRANS] = ntohl (mp->tcp_transitory);
  v[CGNAT_TO_UDP] = ntohl (mp->udp);
  v[CGNAT_TO_ICMP] = ntohl (mp->icmp);
  for (i = 0; i < CGNAT_N_TO; i++)
    if (v[i] == 0)
      rv = VNET_API_ERROR_INVALID_VALUE;
  if (!rv)
    clib_memcpy (cm->timeouts, v, sizeof (v));
  REPLY_MACRO (VL_API_CGNAT_SET_TIMEOUTS_REPLY);
}

static u8 cgnat_ip_proto[] = { IP_PROTOCOL_UDP, IP_PROTOCOL_TCP,
			       IP_PROTOCOL_ICMP };
static char *cgnat_class_name[] = { "tcp-established", "tcp-transitory",
				    "udp", "icmp" };

static void
vl_api_cgnat_session_dump_t_handler (vl_api_cgnat_session_dump_t *mp)
{
  cgnat_main_t *cm = &cgnat_main;
  vl_api_cgnat_session_details_t *rmp;
  vl_api_registration_t *reg;
  f64 now = vlib_time_now (vlib_get_main ());
  cgnat_per_thread_t *t;
  ip4_address_t in;
  u32 fib_index = ~0;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;
  ip4_address_decode (mp->in_addr, &in);
  if (!mp->all)
    {
      fib_index = fib_table_find (FIB_PROTOCOL_IP4, ntohl (mp->in_vrf));
      if (fib_index == ~0)
	return;
    }

  vec_foreach (t, cm->per_thread)
    {
      cgnat_session_t *s;

      if (!mp->all &&
	  !cgnat_sub_get (t, t - cm->per_thread, fib_index, &in, 0))
	continue;
      pool_foreach (s, t->sessions_pool)
	{
	  cgnat_mapping_t *m = pool_elt_at_index (t->mappings, s->mapping_index);
	  cgnat_map_t *map = pool_elt_at_index (cm->maps, m->map_index);

	  if (!mp->all && (m->in_fib_index != fib_index ||
			   m->in_addr.as_u32 != in.as_u32))
	    continue;
	  rmp = vl_msg_api_alloc_zero (sizeof (*rmp));
	  rmp->_vl_msg_id =
	    htons (VL_API_CGNAT_SESSION_DETAILS + cm->msg_id_base);
	  rmp->context = mp->context;
	  rmp->thread_index = htonl (t - cm->per_thread);
	  rmp->in_vrf = htonl (map->in_table_id);
	  ip4_address_encode (&m->in_addr, rmp->in_addr);
	  rmp->in_port = m->in_port;
	  ip4_address_encode (&m->out_addr, rmp->out_addr);
	  rmp->out_port = m->out_port;
	  ip4_address_encode (&s->remote_addr, rmp->remote_addr);
	  rmp->remote_port = s->remote_port;
	  rmp->proto = cgnat_ip_proto[m->proto];
	  strncpy ((char *) rmp->timeout_class, cgnat_class_name[s->to_class],
		   sizeof (rmp->timeout_class) - 1);
	  rmp->idle = clib_host_to_net_f64 (now - s->last_heard);
	  rmp->warm = s->warm;
	  vl_api_send_msg (reg, (u8 *) rmp);
	}
    }
}

static void
vl_api_cgnat_get_status_t_handler (vl_api_cgnat_get_status_t *mp)
{
  cgnat_main_t *cm = &cgnat_main;
  vl_api_cgnat_get_status_reply_t *rmp;
  int rv = 0;

  REPLY_MACRO2 (VL_API_CGNAT_GET_STATUS_REPLY, ({
    rmp->maps = htonl (pool_elts (cm->maps));
    rmp->sessions =
      clib_host_to_net_u64 (cgnat_counter_total (CGNAT_COUNTER_SESSIONS));
    rmp->mappings =
      clib_host_to_net_u64 (cgnat_counter_total (CGNAT_COUNTER_MAPPINGS));
    rmp->subscribers =
      clib_host_to_net_u64 (cgnat_counter_total (CGNAT_COUNTER_SUBSCRIBERS));
    rmp->endpoint_independent_filtering = cm->endpoint_independent_filtering;
    rmp->sessions_per_subscriber = htonl (cm->sessions_per_sub);
    rmp->inbound_sessions_per_subscriber =
      htonl (cm->inbound_sessions_per_sub);
    rmp->max_sessions_per_thread = htonl (cm->max_sessions_per_thread);
    rmp->tcp_established_timeout = htonl (cm->timeouts[CGNAT_TO_TCP_EST]);
    rmp->tcp_transitory_timeout = htonl (cm->timeouts[CGNAT_TO_TCP_TRANS]);
    rmp->udp_timeout = htonl (cm->timeouts[CGNAT_TO_UDP]);
    rmp->icmp_timeout = htonl (cm->timeouts[CGNAT_TO_ICMP]);
  }));
}

static void
vl_api_cgnat_cluster_set_t_handler (vl_api_cgnat_cluster_set_t *mp)
{
  cgnat_main_t *cm = &cgnat_main;
  vl_api_cgnat_cluster_set_reply_t *rmp;
  ip4_address_t local, peer;
  int rv;

  ip4_address_decode (mp->local, &local);
  ip4_address_decode (mp->peer, &peer);
  rv = cgnat_cluster_set (mp->enable, mp->node_id, &local, &peer,
			  ntohl (mp->table_id), ntohs (mp->port),
			  ntohl (mp->hello_interval_ms),
			  ntohl (mp->dead_interval_ms),
			  ntohl (mp->refresh_interval_s));
  REPLY_MACRO (VL_API_CGNAT_CLUSTER_SET_REPLY);
}

static void
vl_api_cgnat_cluster_path_add_del_t_handler (
  vl_api_cgnat_cluster_path_add_del_t *mp)
{
  cgnat_main_t *cm = &cgnat_main;
  vl_api_cgnat_cluster_path_add_del_reply_t *rmp;
  ip4_address_t local, peer;
  int rv;

  ip4_address_decode (mp->local, &local);
  ip4_address_decode (mp->peer, &peer);
  rv = cgnat_cluster_path_add_del (&local, &peer, ntohl (mp->table_id),
				   mp->is_add);
  REPLY_MACRO (VL_API_CGNAT_CLUSTER_PATH_ADD_DEL_REPLY);
}

static void
vl_api_cgnat_cluster_owner_t_handler (vl_api_cgnat_cluster_owner_t *mp)
{
  cgnat_main_t *cm = &cgnat_main;
  vl_api_cgnat_cluster_owner_reply_t *rmp;
  ip4_address_t in;
  u8 owner;
  int rv = 0;

  ip4_address_decode (mp->in_addr, &in);
  owner = cgnat_owner_node (ntohl (mp->in_vrf), in.as_u32);
  if (!cm->cluster.enabled)
    owner = cm->cluster.node_id;
  REPLY_MACRO2 (VL_API_CGNAT_CLUSTER_OWNER_REPLY,
		({ rmp->node_id = owner; }));
}

static void
vl_api_cgnat_cluster_get_status_t_handler (
  vl_api_cgnat_cluster_get_status_t *mp)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_cluster_t *cl = &cm->cluster;
  vl_api_cgnat_cluster_get_status_reply_t *rmp;
  int rv = 0;

  REPLY_MACRO2 (VL_API_CGNAT_CLUSTER_GET_STATUS_REPLY, ({
    rmp->enabled = cl->enabled;
    rmp->node_id = cl->node_id;
    rmp->peer_node_id = cl->peer_node_id;
    rmp->ready = cl->enabled ? cl->ready : 1;
    rmp->fenced = cl->fenced;
    strncpy ((char *) rmp->reason,
	     cl->enabled ? cgnat_cluster_reason_strings[cl->reason] : "alone",
	     sizeof (rmp->reason) - 1);
    rmp->peer_alive = cl->peer_alive;
    rmp->pair_alive = cl->pair_alive;
    rmp->peer_ready = cl->peer_alive && (cl->peer_state & CGNAT_HELLO_READY);
    rmp->config_hash = htonl (cgnat_config_hash ());
    rmp->peer_config_hash = htonl (cl->peer_config_hash);
    rmp->epoch = htonl (cl->epoch);
    rmp->peer_epoch = htonl (cl->peer_epoch);
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
