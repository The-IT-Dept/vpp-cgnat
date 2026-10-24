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

/*
 * Rewrite the packet quoted inside an ICMP error: address, port/id, the
 * quoted IP header checksum and, when present in full, the quoted L4
 * checksum.  avail is the number of quoted bytes from the inner header.
 */
static_always_inline void
cgnat_rewrite_inner (ip4_header_t *inner, int is_src, u32 new_addr,
		     u16 new_port, u8 proto, u32 avail)
{
  ip4_address_t *a = is_src ? &inner->src_address : &inner->dst_address;
  u32 old_addr = a->as_u32;
  ip_csum_t sum;

  a->as_u32 = new_addr;
  sum = ip_csum_update (inner->checksum, old_addr, new_addr, ip4_header_t,
			src_address);
  inner->checksum = ip_csum_fold (sum);

  if (proto == CGNAT_PROTO_ICMP)
    {
      icmp46_header_t *icmp = (icmp46_header_t *) (inner + 1);
      u16 *id = (u16 *) (icmp + 1);
      u16 old_id = *id;

      *id = new_port;
      sum = ip_csum_update (icmp->checksum, old_id, new_port, udp_header_t,
			    src_port);
      icmp->checksum = ip_csum_fold (sum);
    }
  else
    {
      udp_header_t *udp = (udp_header_t *) (inner + 1);
      u16 *port = is_src ? &udp->src_port : &udp->dst_port;
      u16 old_port = *port, *csum = 0;

      *port = new_port;
      if (proto == CGNAT_PROTO_UDP)
	csum = udp->checksum ? &udp->checksum : 0;
      else if (avail >= sizeof (ip4_header_t) + 18)
	csum = &((tcp_header_t *) udp)->checksum;
      if (csum)
	{
	  sum = ip_csum_update (*csum, old_addr, new_addr, ip4_header_t,
				src_address);
	  sum = ip_csum_update (sum, old_port, new_port, udp_header_t,
				src_port);
	  *csum = ip_csum_fold (sum);
	}
    }
}

/* recompute an ICMP message checksum from scratch (errors are rare) */
static_always_inline void
cgnat_icmp_checksum (vlib_main_t *vm, vlib_buffer_t *b, ip4_header_t *ip)
{
  icmp46_header_t *icmp = ip4_next_header (ip);
  u16 len = clib_net_to_host_u16 (ip->length) - ip4_header_bytes (ip);
  ip_csum_t sum;

  icmp->checksum = 0;
  sum = ip_incremental_checksum_buffer (
    vm, b, (u8 *) icmp - (u8 *) vlib_buffer_get_current (b), len, 0);
  icmp->checksum = ~ip_csum_fold (sum);
}

/*
 * The packet quoted by an ICMP error, or 0 if it is truncated or not
 * something we translate.  Sets *proto, the quoted ports/id (network
 * order, src/dst as in the quoted packet) and *avail.
 */
static_always_inline ip4_header_t *
cgnat_icmp_error_inner (ip4_header_t *ip, u8 *proto, u16 *sport, u16 *dport,
			u32 *avail)
{
  icmp46_header_t *icmp = ip4_next_header (ip);
  ip4_header_t *inner = (ip4_header_t *) ((u8 *) icmp + 8);
  i32 n = (i32) clib_net_to_host_u16 (ip->length) - ip4_header_bytes (ip) - 8;

  if (n < (i32) sizeof (ip4_header_t) + 8 ||
      inner->ip_version_and_header_length != 0x45 ||
      ip4_get_fragment_offset (inner))
    return 0;
  *proto = cgnat_proto_of (inner->protocol);
  if (*proto == CGNAT_PROTO_ICMP)
    {
      icmp46_header_t *ii = (icmp46_header_t *) (inner + 1);
      if (ii->type != ICMP4_echo_request && ii->type != ICMP4_echo_reply)
	return 0;
      *sport = *dport = *(u16 *) (ii + 1);
    }
  else if (*proto == CGNAT_PROTO_UDP || *proto == CGNAT_PROTO_TCP)
    {
      udp_header_t *u = (udp_header_t *) (inner + 1);
      *sport = u->src_port;
      *dport = u->dst_port;
    }
  else
    return 0;
  *avail = n;
  return inner;
}

#endif /* included_cgnat_inlines_h */
