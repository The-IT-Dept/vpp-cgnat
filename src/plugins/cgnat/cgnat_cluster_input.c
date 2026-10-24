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
#include <cgnat/cgnat.h>

#define foreach_cgnat_cluster_input_error                                     \
  _ (HELLO, "hello", "HELLOs received")                                       \
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

VLIB_NODE_FN (cgnat_cluster_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  cgnat_cluster_t *cl = &cgnat_main.cluster;
  u32 *from = vlib_frame_vector_args (frame), n = frame->n_vectors, i;

  for (i = 0; i < n; i++)
    {
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
      else
	e = CGNAT_CLUSTER_INPUT_ERROR_UNSUPPORTED;
      vlib_node_increment_counter (vm, node->node_index, e, 1);
    }
  vlib_buffer_free (vm, from, n);
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
  },
};
