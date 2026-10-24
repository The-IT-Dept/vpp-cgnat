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

#define foreach_cgnat_out2in_error                                            \
  _ (NO_MAPPING, "no-mapping", "no mapping for pool address and port")        \
  _ (FILTERED, "filtered", "remote not allowed by filtering")                 \
  _ (CAP, "cap", "subscriber session limit reached")                          \
  _ (UNSUPPORTED, "unsupported", "protocol not translated")                   \
  _ (TRUNCATED, "truncated", "L4 header truncated")                           \
  _ (OPTIONS, "options", "IPv4 options not translated")                       \
  _ (TO_INSIDE, "to-inside", "outside traffic addressed to an inside prefix") \
  _ (TABLE_FULL, "table-full", "thread session table full")                   \
  _ (CONGESTION, "congestion", "handoff queue full")

typedef enum
{
#define _(sym, name, desc) CGNAT_OUT2IN_ERROR_##sym,
  foreach_cgnat_out2in_error
#undef _
    CGNAT_OUT2IN_N_ERROR,
} cgnat_out2in_error_t;

static vlib_error_desc_t cgnat_out2in_error_counters[] = {
#define _(sym, n, d) { .name = n, .desc = d, .severity = VL_COUNTER_SEVERITY_ERROR },
  foreach_cgnat_out2in_error
#undef _
};

typedef enum
{
  CGNAT_OUT2IN_NEXT_LOOKUP,
  CGNAT_OUT2IN_NEXT_DROP,
  CGNAT_OUT2IN_N_NEXT,
} cgnat_out2in_next_t;

typedef struct
{
  u32 sw_if_index;
  u32 next_index;
  u32 owner;
  u32 mapping_index;
  u32 session_index;
} cgnat_out2in_trace_t;

static u8 *
format_cgnat_out2in_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  cgnat_out2in_trace_t *t = va_arg (*args, cgnat_out2in_trace_t *);

  if (t->next_index == CGNAT_NEXT_HANDOFF)
    return format (s, "CGNAT out2in: sw_if_index %u handoff to thread %u",
		   t->sw_if_index, t->owner);
  return format (s, "CGNAT out2in: sw_if_index %u next %u mapping %d session %d",
		 t->sw_if_index, t->next_index, t->mapping_index,
		 t->session_index);
}

/*
 * An ICMP error about one of our outbound flows: the quoted packet is
 * pool address:port -> remote, and is sent to the pool address.
 */
static_always_inline u32
cgnat_out2in_icmp_error (vlib_main_t *vm, vlib_node_runtime_t *node,
			 cgnat_per_thread_t *t, vlib_buffer_t *b,
			 ip4_header_t *ip, u32 rx_fib, cgnat_mapping_t **mp)
{
  ip4_header_t *inner;
  cgnat_mapping_t *m;
  u16 sport, dport;
  u32 avail;
  u8 iproto;

  inner = cgnat_icmp_error_inner (ip, &iproto, &sport, &dport, &avail);
  if (!inner || inner->src_address.as_u32 != ip->dst_address.as_u32)
    {
      b->error = node->errors[CGNAT_OUT2IN_ERROR_UNSUPPORTED];
      return CGNAT_OUT2IN_NEXT_DROP;
    }
  m = cgnat_mapping_find (t, 1, rx_fib, inner->src_address.as_u32, sport,
			  iproto);
  if (!m || !cgnat_session_find (t, m - t->mappings,
				 inner->dst_address.as_u32,
				 iproto == CGNAT_PROTO_ICMP ? 0 : dport))
    {
      b->error = node->errors[CGNAT_OUT2IN_ERROR_NO_MAPPING];
      return CGNAT_OUT2IN_NEXT_DROP;
    }
  cgnat_rewrite (ip, 0, m->in_addr.as_u32, 0, iproto, 1 /* ip only */);
  cgnat_rewrite_inner (inner, 1, m->in_addr.as_u32, m->in_port, iproto,
		       avail);
  cgnat_icmp_checksum (vm, b, ip);
  vnet_buffer (b)->sw_if_index[VLIB_TX] = m->in_fib_index;
  *mp = m;
  return CGNAT_OUT2IN_NEXT_LOOKUP;
}

static_always_inline u32
cgnat_out2in_one (vlib_main_t *vm, vlib_node_runtime_t *node,
		  cgnat_per_thread_t *t, u32 thread_index, vlib_buffer_t *b,
		  f64 now, cgnat_mapping_t **mp, cgnat_session_t **sp,
		  u16 *owner, int is_hairpin)
{
  cgnat_main_t *cm = &cgnat_main;
  ip4_header_t *ip = vlib_buffer_get_current (b);
  int non_first = vnet_buffer (b)->ip.reass.is_non_first_fragment;
  u32 rx_fib, next;
  u16 out_port, r_port;
  cgnat_mapping_t *m;
  cgnat_session_t *s;
  cgnat_sub_t *sub;
  cgnat_map_t *map;
  u8 proto;

  /* hairpinned packets were translated by in2out into the outside fib */
  rx_fib = is_hairpin ? vnet_buffer (b)->sw_if_index[VLIB_TX] :
			ip4_fib_table_get_index_for_sw_if_index (
			  vnet_buffer (b)->sw_if_index[VLIB_RX]);

  /* not addressed to a pool: not ours */
  map = cgnat_map_by_outside (rx_fib, &ip->dst_address);
  if (!map)
    {
      /* with inside and outside in one table, never route the outside
	 straight to a subscriber */
      if (!is_hairpin && cgnat_map_by_inside (rx_fib, &ip->dst_address))
	{
	  b->error = node->errors[CGNAT_OUT2IN_ERROR_TO_INSIDE];
	  return CGNAT_OUT2IN_NEXT_DROP;
	}
      if (is_hairpin)
	{
	  b->error = node->errors[CGNAT_OUT2IN_ERROR_NO_MAPPING];
	  return CGNAT_OUT2IN_NEXT_DROP;
	}
      vnet_feature_next (&next, b);
      return next;
    }

  if (PREDICT_FALSE (ip->ip_version_and_header_length != 0x45))
    {
      b->error = node->errors[CGNAT_OUT2IN_ERROR_OPTIONS];
      return CGNAT_OUT2IN_NEXT_DROP;
    }

  /* the subscriber, by the reverse formula, picks the owner thread */
  {
    ip4_address_t in;
    if (cgnat_reverse (map, &ip->dst_address,
		       clib_net_to_host_u16 (
			 vnet_buffer (b)->ip.reass.l4_dst_port),
		       &in))
      {
	b->error = node->errors[CGNAT_OUT2IN_ERROR_NO_MAPPING];
	return CGNAT_OUT2IN_NEXT_DROP;
      }
    *owner = cgnat_owner_thread (map->in_fib_index, in.as_u32);
    if (PREDICT_FALSE (*owner != thread_index))
      return CGNAT_NEXT_HANDOFF;
  }

  proto = cgnat_proto_of (ip->protocol);
  if (proto == CGNAT_PROTO_ICMP)
    {
      u8 type = vnet_buffer (b)->ip.reass.icmp_type_or_tcp_flags;
      if (icmp_type_is_error_message (type) && !non_first)
	return cgnat_out2in_icmp_error (vm, node, t, b, ip, rx_fib, mp);
      if (type != ICMP4_echo_reply)
	proto = CGNAT_N_PROTO; /* not translated */
    }
  if (PREDICT_FALSE (proto == CGNAT_N_PROTO))
    {
      b->error = node->errors[CGNAT_OUT2IN_ERROR_UNSUPPORTED];
      return CGNAT_OUT2IN_NEXT_DROP;
    }
  if (PREDICT_FALSE (vnet_buffer (b)->ip.reass.l4_hdr_truncated))
    {
      b->error = node->errors[CGNAT_OUT2IN_ERROR_TRUNCATED];
      return CGNAT_OUT2IN_NEXT_DROP;
    }

  out_port = vnet_buffer (b)->ip.reass.l4_dst_port;
  r_port = proto == CGNAT_PROTO_ICMP ? 0 : vnet_buffer (b)->ip.reass.l4_src_port;

  m = cgnat_mapping_find (t, 1, rx_fib, ip->dst_address.as_u32, out_port,
			  proto);
  if (PREDICT_FALSE (!m))
    {
      b->error = node->errors[CGNAT_OUT2IN_ERROR_NO_MAPPING];
      return CGNAT_OUT2IN_NEXT_DROP;
    }

  s = cgnat_session_find (t, m - t->mappings, ip->src_address.as_u32, r_port);
  if (PREDICT_FALSE (s && cgnat_session_expired (s, now)))
    {
      u32 mi = m - t->mappings;
      cgnat_session_free (t, thread_index, s);
      s = 0;
      if (pool_is_free_index (t->mappings, mi))
	{
	  b->error = node->errors[CGNAT_OUT2IN_ERROR_NO_MAPPING];
	  return CGNAT_OUT2IN_NEXT_DROP;
	}
    }
  if (PREDICT_FALSE (!s))
    {
      if (!cm->endpoint_independent_filtering &&
	  !cgnat_adf_allows (t, m - t->mappings, ip->src_address.as_u32))
	{
	  b->error = node->errors[CGNAT_OUT2IN_ERROR_FILTERED];
	  return CGNAT_OUT2IN_NEXT_DROP;
	}
      sub = pool_elt_at_index (t->subs_pool, m->sub_index);
      if (cgnat_table_full (t))
	{
	  b->error = node->errors[CGNAT_OUT2IN_ERROR_TABLE_FULL];
	  return CGNAT_OUT2IN_NEXT_DROP;
	}
      /* inbound sessions have their own cap: outsiders can't use up the
	 subscriber's outbound sessions */
      if (cgnat_sub_full (sub, 1))
	{
	  b->error = node->errors[CGNAT_OUT2IN_ERROR_CAP];
	  return CGNAT_OUT2IN_NEXT_DROP;
	}
      s = cgnat_session_create (t, thread_index, m, ip->src_address.as_u32,
				r_port, CGNAT_TO_TCP_TRANS, now, 1);
    }
  cgnat_session_touch (t, s, cgnat_session_class (s, proto, b, 0), now);

  cgnat_rewrite (ip, 0, m->in_addr.as_u32, m->in_port, proto, non_first);
  vnet_buffer (b)->sw_if_index[VLIB_TX] = m->in_fib_index;
  *mp = m;
  *sp = s;
  return CGNAT_OUT2IN_NEXT_LOOKUP;
}

static_always_inline uword
cgnat_out2in_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		     vlib_frame_t *frame, int is_hairpin)
{
  cgnat_main_t *cm = &cgnat_main;
  u32 thread_index = vm->thread_index;
  cgnat_per_thread_t *t = vec_elt_at_index (cm->per_thread, thread_index);
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u32 nexts[VLIB_FRAME_SIZE], *next = nexts;
  u16 owners[VLIB_FRAME_SIZE], *owner = owners;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors, n_drop, n_ok = 0;
  f64 now = vlib_time_now (vm);

  vlib_get_buffers (vm, from, bufs, n_left);
  while (n_left)
    {
      cgnat_mapping_t *m = 0;
      cgnat_session_t *s = 0;

      next[0] = cgnat_out2in_one (vm, node, t, thread_index, b[0], now, &m,
				  &s, owner, is_hairpin);
      if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	{
	  cgnat_out2in_trace_t *tr =
	    vlib_add_trace (vm, node, b[0], sizeof (*tr));
	  tr->sw_if_index = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
	  tr->next_index = next[0];
	  tr->owner = owner[0];
	  tr->mapping_index = m ? m - t->mappings : ~0;
	  tr->session_index = s ? s - t->sessions_pool : ~0;
	}
      n_ok += m != 0; /* translated */
      b++;
      next++;
      owner++;
      n_left--;
    }
  vlib_increment_simple_counter (
    &cm->counters[is_hairpin ? CGNAT_COUNTER_HAIRPIN_PACKETS :
			       CGNAT_COUNTER_OUT2IN_PACKETS],
    thread_index, 0, n_ok);
  n_drop = cgnat_dispatch (vm, node, from, nexts, owners, frame->n_vectors,
			   is_hairpin ? cm->fq_hairpin_index :
					cm->fq_out2in_index);
  if (n_drop)
    vlib_node_increment_counter (vm, node->node_index,
				 CGNAT_OUT2IN_ERROR_CONGESTION, n_drop);
  return frame->n_vectors;
}

VLIB_NODE_FN (cgnat_out2in_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return cgnat_out2in_inline (vm, node, frame, 0);
}

VLIB_NODE_FN (cgnat_hairpin_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return cgnat_out2in_inline (vm, node, frame, 1);
}

VLIB_REGISTER_NODE (cgnat_hairpin_node) = {
  .name = "cgnat-hairpin",
  .vector_size = sizeof (u32),
  .format_trace = format_cgnat_out2in_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = CGNAT_OUT2IN_N_ERROR,
  .error_counters = cgnat_out2in_error_counters,
  .n_next_nodes = CGNAT_OUT2IN_N_NEXT,
  .next_nodes = {
    [CGNAT_OUT2IN_NEXT_LOOKUP] = "ip4-lookup",
    [CGNAT_OUT2IN_NEXT_DROP] = "error-drop",
  },
};

VLIB_REGISTER_NODE (cgnat_out2in_node) = {
  .name = "cgnat-out2in",
  .vector_size = sizeof (u32),
  .format_trace = format_cgnat_out2in_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = CGNAT_OUT2IN_N_ERROR,
  .error_counters = cgnat_out2in_error_counters,
  .n_next_nodes = CGNAT_OUT2IN_N_NEXT,
  .next_nodes = {
    [CGNAT_OUT2IN_NEXT_LOOKUP] = "ip4-lookup",
    [CGNAT_OUT2IN_NEXT_DROP] = "error-drop",
  },
};

VNET_FEATURE_INIT (cgnat_out2in_feature, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "cgnat-out2in",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa",
			       "ip4-sv-reassembly-feature",
			       "ip4-dhcp-client-detect"),
};
