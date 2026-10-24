/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 The vpp-cgnat authors
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/feature/feature.h>
#include <cgnat/cgnat.h>
#include <cgnat/cgnat_session.h>
#include <cgnat/cgnat_inlines.h>
#include <vnet/ip/ip4_to_ip6.h>

#define foreach_cgnat_in2out_error                                            \
  _ (NO_MAP, "no-map", "source address in no map")                            \
  _ (NO_MAPPING, "no-mapping", "ICMP error for an unknown flow")              \
  _ (CAP, "cap", "subscriber session limit reached")                          \
  _ (EXHAUSTED, "exhausted", "subscriber port block exhausted")               \
  _ (UNSUPPORTED, "unsupported", "protocol not translated")                   \
  _ (TRUNCATED, "truncated", "L4 header truncated")

typedef enum
{
#define _(sym, name, desc) CGNAT_IN2OUT_ERROR_##sym,
  foreach_cgnat_in2out_error
#undef _
    CGNAT_IN2OUT_N_ERROR,
} cgnat_in2out_error_t;

static vlib_error_desc_t cgnat_in2out_error_counters[] = {
#define _(sym, n, d) { .name = n, .desc = d, .severity = VL_COUNTER_SEVERITY_ERROR },
  foreach_cgnat_in2out_error
#undef _
};

typedef enum
{
  CGNAT_IN2OUT_NEXT_LOOKUP,
  CGNAT_IN2OUT_NEXT_DROP,
  CGNAT_IN2OUT_NEXT_ICMP_ERROR,
  CGNAT_IN2OUT_NEXT_HAIRPIN,
  CGNAT_IN2OUT_N_NEXT,
} cgnat_in2out_next_t;

typedef struct
{
  u32 sw_if_index;
  u32 next_index;
  u32 mapping_index;
  u32 session_index;
} cgnat_in2out_trace_t;

static u8 *
format_cgnat_in2out_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  cgnat_in2out_trace_t *t = va_arg (*args, cgnat_in2out_trace_t *);

  return format (s, "CGNAT in2out: sw_if_index %u next %u mapping %d session %d",
		 t->sw_if_index, t->next_index, t->mapping_index,
		 t->session_index);
}

/*
 * A subscriber's ICMP error about an inbound packet (e.g. port
 * unreachable): the quoted packet is remote -> subscriber.
 */
static_always_inline u32
cgnat_in2out_icmp_error (vlib_main_t *vm, vlib_node_runtime_t *node,
			 cgnat_per_thread_t *t, vlib_buffer_t *b,
			 ip4_header_t *ip, u32 rx_fib, cgnat_mapping_t **mp)
{
  ip4_header_t *inner;
  cgnat_mapping_t *m;
  u16 sport, dport;
  u32 avail;
  u8 iproto;

  inner = cgnat_icmp_error_inner (ip, &iproto, &sport, &dport, &avail);
  if (!inner || inner->dst_address.as_u32 != ip->src_address.as_u32)
    {
      b->error = node->errors[CGNAT_IN2OUT_ERROR_UNSUPPORTED];
      return CGNAT_IN2OUT_NEXT_DROP;
    }
  m = cgnat_mapping_find (t, 0, rx_fib, inner->dst_address.as_u32, dport,
			  iproto);
  if (!m || !cgnat_session_find (t, m - t->mappings,
				 inner->src_address.as_u32,
				 iproto == CGNAT_PROTO_ICMP ? 0 : sport))
    {
      b->error = node->errors[CGNAT_IN2OUT_ERROR_NO_MAPPING];
      return CGNAT_IN2OUT_NEXT_DROP;
    }
  cgnat_rewrite (ip, 1, m->out_addr.as_u32, 0, iproto, 1 /* ip only */);
  cgnat_rewrite_inner (inner, 0, m->out_addr.as_u32, m->out_port, iproto,
		       avail);
  cgnat_icmp_checksum (vm, b, ip);
  vnet_buffer (b)->sw_if_index[VLIB_TX] = m->out_fib_index;
  *mp = m;
  return CGNAT_IN2OUT_NEXT_LOOKUP;
}

static_always_inline u32
cgnat_in2out_one (vlib_main_t *vm, vlib_node_runtime_t *node, cgnat_per_thread_t *t,
		  u32 thread_index, vlib_buffer_t *b, f64 now,
		  cgnat_mapping_t **mp, cgnat_session_t **sp)
{
  cgnat_main_t *cm = &cgnat_main;
  ip4_header_t *ip = vlib_buffer_get_current (b);
  int non_first = vnet_buffer (b)->ip.reass.is_non_first_fragment;
  u32 rx_fib, next;
  u16 in_port, r_port;
  cgnat_mapping_t *m;
  cgnat_session_t *s;
  cgnat_sub_t *sub;
  cgnat_map_t *map;
  u8 proto;

  rx_fib = ip4_fib_table_get_index_for_sw_if_index (
    vnet_buffer (b)->sw_if_index[VLIB_RX]);
  proto = cgnat_proto_of (ip->protocol);
  map = cgnat_map_by_inside (rx_fib, &ip->src_address);

  if (proto == CGNAT_PROTO_ICMP && map)
    {
      u8 type = vnet_buffer (b)->ip.reass.icmp_type_or_tcp_flags;
      if (icmp_type_is_error_message (type) && !non_first &&
	  !cgnat_is_local (rx_fib, &ip->dst_address))
	return cgnat_in2out_icmp_error (vm, node, t, b, ip, rx_fib, mp);
      if (type != ICMP4_echo_request)
	proto = CGNAT_N_PROTO; /* not translated */
    }

  if (PREDICT_FALSE (!map || proto == CGNAT_N_PROTO))
    {
      /* traffic for this box itself passes untouched */
      if (cgnat_is_local (rx_fib, &ip->dst_address))
	goto pass;
      b->error = node->errors[map ? CGNAT_IN2OUT_ERROR_UNSUPPORTED :
				    CGNAT_IN2OUT_ERROR_NO_MAP];
      return CGNAT_IN2OUT_NEXT_DROP;
    }
  if (PREDICT_FALSE (vnet_buffer (b)->ip.reass.l4_hdr_truncated))
    {
      b->error = node->errors[CGNAT_IN2OUT_ERROR_TRUNCATED];
      return CGNAT_IN2OUT_NEXT_DROP;
    }
  if (PREDICT_FALSE (ip->ttl <= 1))
    {
      vnet_buffer (b)->sw_if_index[VLIB_TX] = ~0;
      icmp4_error_set_vnet_buffer (
	b, ICMP4_time_exceeded, ICMP4_time_exceeded_ttl_exceeded_in_transit,
	0);
      return CGNAT_IN2OUT_NEXT_ICMP_ERROR;
    }

  in_port = vnet_buffer (b)->ip.reass.l4_src_port;
  r_port = proto == CGNAT_PROTO_ICMP ? 0 : vnet_buffer (b)->ip.reass.l4_dst_port;

  m = cgnat_mapping_find (t, 0, rx_fib, ip->src_address.as_u32, in_port,
			  proto);
  if (PREDICT_FALSE (!m))
    {
      ip4_address_t out;
      u16 lo, hi, port;

      if (cgnat_is_local (rx_fib, &ip->dst_address))
	goto pass;
      sub = cgnat_sub_get (t, thread_index, rx_fib, &ip->src_address, 1);
      if (sub->n_sessions >= cm->sessions_per_sub)
	{
	  b->error = node->errors[CGNAT_IN2OUT_ERROR_CAP];
	  cgnat_sub_put_if_idle (t, thread_index, sub);
	  return CGNAT_IN2OUT_NEXT_DROP;
	}
      cgnat_forward (map, &ip->src_address, &out, &lo, &hi);
      port = cgnat_pick_port (t, map->out_fib_index, &out, lo, hi,
			      clib_net_to_host_u16 (in_port), proto);
      if (!port)
	{
	  b->error = node->errors[CGNAT_IN2OUT_ERROR_EXHAUSTED];
	  cgnat_sub_put_if_idle (t, thread_index, sub);
	  return CGNAT_IN2OUT_NEXT_DROP;
	}
      m = cgnat_mapping_create (t, thread_index, map, sub, &ip->src_address,
				in_port, &out, clib_host_to_net_u16 (port),
				proto);
    }

  s = cgnat_session_find (t, m - t->mappings, ip->dst_address.as_u32, r_port);
  if (PREDICT_FALSE (!s))
    {
      sub = pool_elt_at_index (t->subs_pool, m->sub_index);
      if (sub->n_sessions >= cm->sessions_per_sub)
	{
	  b->error = node->errors[CGNAT_IN2OUT_ERROR_CAP];
	  cgnat_mapping_free_if_idle (t, thread_index, m);
	  return CGNAT_IN2OUT_NEXT_DROP;
	}
      s = cgnat_session_create (t, thread_index, m, ip->dst_address.as_u32,
				r_port, CGNAT_TO_TCP_TRANS, now);
    }
  cgnat_session_touch (t, s, cgnat_session_class (s, proto, b, 1), now);

  cgnat_rewrite (ip, 1, m->out_addr.as_u32, m->out_port, proto, non_first);
  vnet_buffer (b)->sw_if_index[VLIB_TX] = m->out_fib_index;
  *mp = m;
  *sp = s;
  /* to another subscriber's public address: translate it back in */
  if (PREDICT_FALSE (cgnat_map_by_outside (m->out_fib_index,
					   &ip->dst_address) != 0))
    return CGNAT_IN2OUT_NEXT_HAIRPIN;
  return CGNAT_IN2OUT_NEXT_LOOKUP;

pass:
  vnet_feature_next (&next, b);
  return next;
}

VLIB_NODE_FN (cgnat_in2out_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  cgnat_main_t *cm = &cgnat_main;
  u32 thread_index = vm->thread_index;
  cgnat_per_thread_t *t = vec_elt_at_index (cm->per_thread, thread_index);
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  f64 now = vlib_time_now (vm);

  vlib_get_buffers (vm, from, bufs, n_left);
  while (n_left)
    {
      cgnat_mapping_t *m = 0;
      cgnat_session_t *s = 0;

      next[0] = cgnat_in2out_one (vm, node, t, thread_index, b[0], now, &m, &s);
      if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  cgnat_in2out_trace_t *tr =
	    vlib_add_trace (vm, node, b[0], sizeof (*tr));
	  tr->sw_if_index = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
	  tr->next_index = next[0];
	  tr->mapping_index = m ? m - t->mappings : ~0;
	  tr->session_index = s ? s - t->sessions_pool : ~0;
	}
      b++;
      next++;
      n_left--;
    }
  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (cgnat_in2out_node) = {
  .name = "cgnat-in2out",
  .vector_size = sizeof (u32),
  .format_trace = format_cgnat_in2out_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = CGNAT_IN2OUT_N_ERROR,
  .error_counters = cgnat_in2out_error_counters,
  .n_next_nodes = CGNAT_IN2OUT_N_NEXT,
  .next_nodes = {
    [CGNAT_IN2OUT_NEXT_LOOKUP] = "ip4-lookup",
    [CGNAT_IN2OUT_NEXT_DROP] = "error-drop",
    [CGNAT_IN2OUT_NEXT_ICMP_ERROR] = "ip4-icmp-error",
    [CGNAT_IN2OUT_NEXT_HAIRPIN] = "cgnat-hairpin",
  },
};

VNET_FEATURE_INIT (cgnat_in2out_feature, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "cgnat-in2out",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa",
			       "ip4-sv-reassembly-feature"),
};
