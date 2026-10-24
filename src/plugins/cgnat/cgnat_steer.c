/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 The vpp-cgnat authors
 */

/*
 * Steering: a packet for a subscriber the peer owns is wrapped in
 * IPv4/UDP + cluster header + steer header, in place, and sent over the
 * pair link.  The outer header has DF clear, so a full-size packet is
 * fragmented on the way and reassembled by the peer's ip4-local.
 */

#include <vnet/ip/ip4.h>
#include <vnet/udp/udp_packet.h>
#include <cgnat/cgnat.h>

#define CGNAT_STEER_OVERHEAD                                                  \
  (sizeof (ip4_header_t) + sizeof (udp_header_t) + sizeof (cgnat_msg_hdr_t) + \
   sizeof (cgnat_msg_steer_t))

void
cgnat_steer_send (vlib_main_t *vm, u32 *bis, u32 n, u8 direction)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_cluster_t *cl = &cm->cluster;
  cgnat_path_t *p = vec_elt_at_index (cl->paths, 0);
  u32 ok[VLIB_FRAME_SIZE], bad[VLIB_FRAME_SIZE], n_ok = 0, n_bad = 0, i;

  for (i = 0; i < n; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, bis[i]);
      u32 table_id = vnet_buffer (b)->sw_if_index[VLIB_TX];
      u32 inner_len = vlib_buffer_length_in_chain (vm, b);
      u32 len = inner_len + CGNAT_STEER_OVERHEAD;
      ip4_header_t *ip;
      udp_header_t *udp;
      cgnat_msg_hdr_t *h;
      cgnat_msg_steer_t *st;

      if (len > 65535 ||
	  b->current_data < (i16) CGNAT_STEER_OVERHEAD - VLIB_BUFFER_PRE_DATA_SIZE)
	{
	  bad[n_bad++] = bis[i];
	  continue;
	}
      vlib_buffer_advance (b, -(word) CGNAT_STEER_OVERHEAD);
      ip = vlib_buffer_get_current (b);
      udp = (udp_header_t *) (ip + 1);
      h = (cgnat_msg_hdr_t *) (udp + 1);
      st = (cgnat_msg_steer_t *) (h + 1);

      clib_memset (ip, 0, sizeof (*ip));
      ip->ip_version_and_header_length = 0x45;
      ip->ttl = CGNAT_PAIR_TTL;
      ip->protocol = IP_PROTOCOL_UDP;
      ip->length = clib_host_to_net_u16 (len);
      ip->src_address = p->local;
      ip->dst_address = p->peer;
      ip->checksum = ip4_header_checksum (ip);
      udp->src_port = udp->dst_port = clib_host_to_net_u16 (cl->port);
      udp->length = clib_host_to_net_u16 (len - sizeof (*ip));
      udp->checksum = 0;
      h->version = CGNAT_PROTO_VERSION;
      h->type = CGNAT_MSG_STEER;
      h->flags = 0;
      h->node_id = cl->node_id;
      h->config_hash = clib_host_to_net_u32 (cl->config_hash);
      h->epoch = clib_host_to_net_u32 (cl->epoch);
      h->seq = 0;
      st->direction = direction;
      st->reass_flags =
	(vnet_buffer (b)->ip.reass.is_non_first_fragment ?
	   CGNAT_STEER_NON_FIRST_FRAG :
	   0) |
	(vnet_buffer (b)->ip.reass.l4_hdr_truncated ? CGNAT_STEER_TRUNCATED :
						       0);
      st->icmp_type_or_tcp_flags =
	vnet_buffer (b)->ip.reass.icmp_type_or_tcp_flags;
      st->pad = 0;
      st->table_id = clib_host_to_net_u32 (table_id);
      st->l4_src_port = vnet_buffer (b)->ip.reass.l4_src_port;
      st->l4_dst_port = vnet_buffer (b)->ip.reass.l4_dst_port;

      b->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
      b->flags &= ~VNET_BUFFER_F_OFFLOAD;
      vnet_buffer (b)->sw_if_index[VLIB_TX] = p->fib_index;
      ok[n_ok++] = bis[i];
    }
  if (n_ok)
    {
      cgnat_cluster_send (vm, ok, n_ok);
      vlib_increment_simple_counter (
	&cm->counters[CGNAT_COUNTER_STEERED_OUT], vm->thread_index, 0, n_ok);
    }
  if (n_bad)
    vlib_buffer_free (vm, bad, n_bad);
}
