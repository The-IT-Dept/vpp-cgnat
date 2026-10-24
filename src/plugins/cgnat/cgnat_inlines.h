/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 The vpp-cgnat authors
 */

#ifndef included_cgnat_inlines_h
#define included_cgnat_inlines_h

#include <vnet/ip/ip.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/tcp/tcp_packet.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/dpo/receive_dpo.h>
#include <vnet/fib/ip4_fib.h>
#include <cgnat/cgnat.h>

static_always_inline u8
cgnat_proto_of (u8 ip_proto)
{
  switch (ip_proto)
    {
    case IP_PROTOCOL_UDP:
      return CGNAT_PROTO_UDP;
    case IP_PROTOCOL_TCP:
      return CGNAT_PROTO_TCP;
    case IP_PROTOCOL_ICMP:
      return CGNAT_PROTO_ICMP;
    }
  return CGNAT_N_PROTO;
}

/* is the address one of this box's own in the fib? */
static_always_inline int
cgnat_is_local (u32 fib_index, ip4_address_t *a)
{
  const load_balance_t *lb;
  const dpo_id_t *dpo;

  lb = load_balance_get (ip4_fib_forwarding_lookup (fib_index, a));
  dpo = load_balance_get_bucket_i (lb, 0);
  return dpo->dpoi_type == DPO_RECEIVE;
}

/* TCP state tracking; returns the session's timeout class */
static_always_inline u8
cgnat_tcp_class (cgnat_session_t *s, u8 flags, int from_inside)
{
  if ((flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) == TCP_FLAG_SYN &&
      (s->tcp_state & (CGNAT_TCP_RST | CGNAT_TCP_I_FIN | CGNAT_TCP_O_FIN)))
    s->tcp_state = 0; /* tuple reused for a new connection */
  if (flags & TCP_FLAG_SYN)
    s->tcp_state |= from_inside ? CGNAT_TCP_I_SYN : CGNAT_TCP_O_SYN;
  if (flags & TCP_FLAG_FIN)
    s->tcp_state |= from_inside ? CGNAT_TCP_I_FIN : CGNAT_TCP_O_FIN;
  if (flags & TCP_FLAG_RST)
    s->tcp_state |= CGNAT_TCP_RST;

  if ((s->tcp_state & CGNAT_TCP_RST) ||
      (s->tcp_state & (CGNAT_TCP_I_FIN | CGNAT_TCP_O_FIN)) ==
	(CGNAT_TCP_I_FIN | CGNAT_TCP_O_FIN))
    return CGNAT_TO_TCP_TRANS;
  if ((s->tcp_state & (CGNAT_TCP_I_SYN | CGNAT_TCP_O_SYN)) ==
      (CGNAT_TCP_I_SYN | CGNAT_TCP_O_SYN))
    return CGNAT_TO_TCP_EST;
  return CGNAT_TO_TCP_TRANS;
}

static_always_inline u8
cgnat_session_class (cgnat_session_t *s, u8 proto, vlib_buffer_t *b,
		     int from_inside)
{
  switch (proto)
    {
    case CGNAT_PROTO_TCP:
      if (vnet_buffer (b)->ip.reass.is_non_first_fragment)
	return s->to_class;
      return cgnat_tcp_class (
	s, vnet_buffer (b)->ip.reass.icmp_type_or_tcp_flags, from_inside);
    case CGNAT_PROTO_UDP:
      return CGNAT_TO_UDP;
    }
  return CGNAT_TO_ICMP;
}

/*
 * Rewrite the source (is_src) or destination address and L4 port/id,
 * updating checksums incrementally.  Ports are network order.
 */
static_always_inline void
cgnat_rewrite (ip4_header_t *ip, int is_src, u32 new_addr, u16 new_port,
	       u8 proto, int non_first)
{
  ip4_address_t *a = is_src ? &ip->src_address : &ip->dst_address;
  u32 old_addr = a->as_u32;
  ip_csum_t sum;

  a->as_u32 = new_addr;
  sum = ip_csum_update (ip->checksum, old_addr, new_addr, ip4_header_t,
			src_address);
  ip->checksum = ip_csum_fold (sum);
  if (non_first)
    return;

  if (proto == CGNAT_PROTO_ICMP)
    {
      icmp46_header_t *icmp = ip4_next_header (ip);
      u16 *id = (u16 *) (icmp + 1);
      u16 old_id = *id;

      *id = new_port;
      sum = ip_csum_update (icmp->checksum, old_id, new_port, udp_header_t,
			    src_port);
      icmp->checksum = ip_csum_fold (sum);
    }
  else
    {
      udp_header_t *udp = ip4_next_header (ip);
      u16 *port = is_src ? &udp->src_port : &udp->dst_port;
      u16 *csum = proto == CGNAT_PROTO_TCP ?
		    &((tcp_header_t *) udp)->checksum :
		    &udp->checksum;
      u16 old_port = *port;

      *port = new_port;
      if (proto == CGNAT_PROTO_UDP && *csum == 0)
	return;
      sum = ip_csum_update (*csum, old_addr, new_addr, ip4_header_t,
			    src_address);
      sum = ip_csum_update (sum, old_port, new_port, udp_header_t, src_port);
      *csum = ip_csum_fold (sum);
      if (proto == CGNAT_PROTO_UDP && *csum == 0)
	*csum = 0xffff;
    }
}

#endif /* included_cgnat_inlines_h */
