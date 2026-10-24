/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 The vpp-cgnat authors
 */

/*
 * Pair protocol receive node (UDP dst port registered by the cluster).
 * Buffers arrive with current_data at the UDP payload.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/fib/fib_table.h>
#include <cgnat/cgnat.h>

#define foreach_cgnat_cluster_input_error                                     \
  _ (HELLO, "hello", "HELLOs received")                                       \
  _ (STEER, "steer", "steered packets received")                              \
  _ (NO_TABLE, "no-table", "steered packet for an unknown table")             \
  _ (SYNC, "sync", "sync/ack packets received")                               \
  _ (RESYNC, "resync", "resync requests/ends received")                       \
  _ (BAD, "bad", "malformed or wrong version")                                \
  _ (UNKNOWN_PATH, "unknown-path", "HELLO on no configured path")             \
  _ (DUPLICATE, "duplicate-node-id", "peer uses our node id")                 \
  _ (UNSUPPORTED, "unsupported", "message type not handled")

typedef enum
{
#define _(sym, name, desc) CGNAT_CLUSTER_INPUT_ERROR_##sym,
  foreach_cgnat_cluster_input_error
#undef _
    CGNAT_CLUSTER_INPUT_N_ERROR,
} cgnat_cluster_input_error_t;

static vlib_error_desc_t cgnat_cluster_input_error_counters[] = {
#define _(sym, n, d) { .name = n, .desc = d, .severity = VL_COUNTER_SEVERITY_INFO },
  foreach_cgnat_cluster_input_error
#undef _
};

typedef enum
{
  CGNAT_CLUSTER_INPUT_NEXT_DROP,
  CGNAT_CLUSTER_INPUT_NEXT_IN2OUT,
  CGNAT_CLUSTER_INPUT_NEXT_OUT2IN,
  CGNAT_CLUSTER_INPUT_NEXT_HAIRPIN,
  CGNAT_CLUSTER_INPUT_NEXT_SYNC,
  CGNAT_CLUSTER_INPUT_N_NEXT,
} cgnat_cluster_input_next_t;

static_always_inline u32
cgnat_cluster_hello (vlib_main_t *vm, cgnat_cluster_t *cl, ip4_header_t *ip,
		     cgnat_msg_hdr_t *h, u32 len)
{
  cgnat_msg_hello_t *hb = (cgnat_msg_hello_t *) (h + 1);
  cgnat_path_t *p;
  f64 now = vlib_time_now (vm);

  if (len < sizeof (*h) + sizeof (*hb))
    return CGNAT_CLUSTER_INPUT_ERROR_BAD;
  if (h->node_id == cl->node_id)
    {
      cl->dup_last = now;
      return CGNAT_CLUSTER_INPUT_ERROR_DUPLICATE;
    }
  if (hb->path_id >= vec_len (cl->paths))
    return CGNAT_CLUSTER_INPUT_ERROR_UNKNOWN_PATH;
  p = vec_elt_at_index (cl->paths, hb->path_id);
  if (p->peer.as_u32 != ip->src_address.as_u32)
    return CGNAT_CLUSTER_INPUT_ERROR_UNKNOWN_PATH;

  cl->peer_node_id = h->node_id;
  cl->peer_epoch = clib_net_to_host_u32 (h->epoch);
  cl->peer_config_hash = clib_net_to_host_u32 (h->config_hash);
  cl->peer_state = hb->state;
  cl->peer_n_workers = clib_net_to_host_u16 (hb->n_workers);
  cl->peer_first_worker = clib_net_to_host_u16 (hb->first_worker);
  p->last_rx = now;
  return CGNAT_CLUSTER_INPUT_ERROR_HELLO;
}

/* strip outer headers; restore the packet's reassembly metadata */
static_always_inline u32
cgnat_cluster_steer (vlib_main_t *vm, cgnat_cluster_t *cl, vlib_buffer_t *b,
		     ip4_header_t *ip, cgnat_msg_hdr_t *h, u32 len, u32 *next)
{
  cgnat_msg_steer_t *st = (cgnat_msg_steer_t *) (h + 1);
  u32 fib_index;

  if (len < sizeof (*h) + sizeof (*st) + sizeof (ip4_header_t) ||
      st->direction > CGNAT_STEER_HAIRPIN ||
      ip->src_address.as_u32 != cl->paths[0].peer.as_u32)
    return CGNAT_CLUSTER_INPUT_ERROR_BAD;
  fib_index = fib_table_find (FIB_PROTOCOL_IP4,
			      clib_net_to_host_u32 (st->table_id));
  if (fib_index == ~0)
    return CGNAT_CLUSTER_INPUT_ERROR_NO_TABLE;

  vnet_buffer (b)->ip.reass.is_non_first_fragment =
    !!(st->reass_flags & CGNAT_STEER_NON_FIRST_FRAG);
  vnet_buffer (b)->ip.reass.l4_hdr_truncated =
    !!(st->reass_flags & CGNAT_STEER_TRUNCATED);
  vnet_buffer (b)->ip.reass.icmp_type_or_tcp_flags =
    st->icmp_type_or_tcp_flags;
  vnet_buffer (b)->ip.reass.l4_src_port = st->l4_src_port;
  vnet_buffer (b)->ip.reass.l4_dst_port = st->l4_dst_port;
  vlib_buffer_advance (b, sizeof (*h) + sizeof (*st));
  vnet_buffer (b)->sw_if_index[VLIB_TX] = fib_index;
  *next = CGNAT_CLUSTER_INPUT_NEXT_IN2OUT + st->direction;
  vlib_increment_simple_counter (
    &cgnat_main.counters[CGNAT_COUNTER_STEERED_IN], vm->thread_index, 0, 1);
  return CGNAT_CLUSTER_INPUT_ERROR_STEER;
}

VLIB_NODE_FN (cgnat_cluster_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  cgnat_cluster_t *cl = &cgnat_main.cluster;
  u32 *from = vlib_frame_vector_args (frame), n = frame->n_vectors, i;
  u16 nexts[VLIB_FRAME_SIZE];
  u32 local_bi[VLIB_FRAME_SIZE], ho_bi[VLIB_FRAME_SIZE];
  u16 local_next[VLIB_FRAME_SIZE], ho_ti[VLIB_FRAME_SIZE];
  u32 n_local = 0, n_ho = 0;

  for (i = 0; i < n; i++)
    {
      u32 next = CGNAT_CLUSTER_INPUT_NEXT_DROP;
      vlib_buffer_t *b = vlib_get_buffer (vm, from[i]);
      cgnat_msg_hdr_t *h = vlib_buffer_get_current (b);
      ip4_header_t *ip = (ip4_header_t *) ((u8 *) h - sizeof (udp_header_t) -
					   sizeof (ip4_header_t));
      u32 len = b->current_length, e;

      if (!cl->enabled || len < sizeof (*h) ||
	  h->version != CGNAT_PROTO_VERSION ||
	  ip->ip_version_and_header_length != 0x45)
	e = CGNAT_CLUSTER_INPUT_ERROR_BAD;
      else if (h->type == CGNAT_MSG_HELLO)
	e = cgnat_cluster_hello (vm, cl, ip, h, len);
      else if (h->type == CGNAT_MSG_STEER)
	e = cgnat_cluster_steer (vm, cl, b, ip, h, len, &next);
      else if (h->type == CGNAT_MSG_RESYNC_REQ &&
	       ip->src_address.as_u32 == cl->paths[0].peer.as_u32)
	{
	  /* the peer wants our whole table: every thread walks it */
	  cl->want_resync_peer = 0;
	  __atomic_add_fetch (&cl->resync_walk_gen, 1, __ATOMIC_RELEASE);
	  e = CGNAT_CLUSTER_INPUT_ERROR_RESYNC;
	}
      else if (h->type == CGNAT_MSG_RESYNC_END &&
	       len >= sizeof (*h) + sizeof (cgnat_msg_resync_end_t))
	{
	  cgnat_msg_resync_end_t *eb = (cgnat_msg_resync_end_t *) (h + 1);
	  u32 src = clib_net_to_host_u16 (eb->src_thread);
	  if (clib_net_to_host_u32 (h->epoch) == cl->resync_epoch && src < 64)
	    {
	      cl->resync_end_needed = clib_net_to_host_u16 (eb->n_src_threads);
	      __atomic_or_fetch (&cl->resync_end_mask, 1ULL << src,
				 __ATOMIC_RELEASE);
	    }
	  e = CGNAT_CLUSTER_INPUT_ERROR_RESYNC;
	}
      else if ((h->type == CGNAT_MSG_SYNC || h->type == CGNAT_MSG_ACK) &&
	       len >= sizeof (*h) + 8)
	{
	  /* SYNC: to our thread named as dst; ACK: to the stream's sender,
	     our thread named as src */
	  u16 *tp = (u16 *) (h + 1);
	  u32 target =
	    clib_net_to_host_u16 (h->type == CGNAT_MSG_SYNC ? tp[1] : tp[0]);
	  e = CGNAT_CLUSTER_INPUT_ERROR_SYNC;
	  if (target >= vlib_get_n_threads ())
	    e = CGNAT_CLUSTER_INPUT_ERROR_BAD;
	  else if (target != vm->thread_index)
	    {
	      vlib_node_increment_counter (vm, node->node_index, e, 1);
	      ho_bi[n_ho] = from[i];
	      ho_ti[n_ho++] = target;
	      nexts[i] = ~0;
	      continue;
	    }
	  else
	    next = CGNAT_CLUSTER_INPUT_NEXT_SYNC;
	}
      else
	e = CGNAT_CLUSTER_INPUT_ERROR_UNSUPPORTED;
      vlib_node_increment_counter (vm, node->node_index, e, 1);
      nexts[i] = next;
    }
  for (i = 0; i < n; i++)
    if (nexts[i] != (u16) ~0)
      {
	local_bi[n_local] = from[i];
	local_next[n_local++] = nexts[i];
      }
  if (n_local)
    vlib_buffer_enqueue_to_next (vm, node, local_bi, local_next, n_local);
  if (n_ho)
    vlib_buffer_enqueue_to_thread (vm, node, cgnat_main.fq_sync_index, ho_bi,
				   ho_ti, n_ho, 1);
  return n;
}

VLIB_REGISTER_NODE (cgnat_cluster_input_node) = {
  .name = "cgnat-cluster-input",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = CGNAT_CLUSTER_INPUT_N_ERROR,
  .error_counters = cgnat_cluster_input_error_counters,
  .n_next_nodes = CGNAT_CLUSTER_INPUT_N_NEXT,
  .next_nodes = {
    [CGNAT_CLUSTER_INPUT_NEXT_DROP] = "error-drop",
    [CGNAT_CLUSTER_INPUT_NEXT_IN2OUT] = "cgnat-in2out-steered",
    [CGNAT_CLUSTER_INPUT_NEXT_OUT2IN] = "cgnat-out2in-steered",
    [CGNAT_CLUSTER_INPUT_NEXT_HAIRPIN] = "cgnat-hairpin-steered",
    [CGNAT_CLUSTER_INPUT_NEXT_SYNC] = "cgnat-sync-worker",
  },
};
