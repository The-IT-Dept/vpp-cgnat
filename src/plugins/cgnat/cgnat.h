/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 The vpp-cgnat authors
 */

#ifndef included_cgnat_h
#define included_cgnat_h

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/fib/fib_source.h>
#include <vppinfra/bihash_16_8.h>
#include <vppinfra/bihash_8_8.h>
#include <vppinfra/dlist.h>
#include <cgnat/cgnat_map.h>

typedef enum
{
  CGNAT_PROTO_UDP,
  CGNAT_PROTO_TCP,
  CGNAT_PROTO_ICMP,
  CGNAT_N_PROTO,
} cgnat_proto_t;

/* timeout classes; each has its own LRU list per thread */
typedef enum
{
  CGNAT_TO_TCP_EST,
  CGNAT_TO_TCP_TRANS,
  CGNAT_TO_UDP,
  CGNAT_TO_ICMP,
  CGNAT_N_TO,
} cgnat_to_class_t;

/* An endpoint-independent mapping: inside ip:port:proto <-> outside port */
typedef struct
{
  ip4_address_t in_addr;
  ip4_address_t out_addr;
  u32 in_fib_index;
  u32 out_fib_index;
  u16 in_port;	/* network order */
  u16 out_port; /* network order */
  u8 proto;	/* cgnat_proto_t */
  u32 map_index;
  u32 sub_index;
  u32 n_sessions;
} cgnat_mapping_t;

/* TCP state bits */
#define CGNAT_TCP_I_SYN (1 << 0)
#define CGNAT_TCP_O_SYN (1 << 1)
#define CGNAT_TCP_I_FIN (1 << 2)
#define CGNAT_TCP_O_FIN (1 << 3)
#define CGNAT_TCP_RST	(1 << 4)

/* A session: mapping + remote endpoint */
typedef struct
{
  u32 mapping_index;
  ip4_address_t remote_addr;
  u16 remote_port; /* network order; 0 for ICMP */
  u8 tcp_state;
  u8 to_class;
  f64 last_heard;
  u32 lru_index;
} cgnat_session_t;

/* A subscriber: (inside fib, inside address) */
typedef struct
{
  ip4_address_t in_addr;
  u32 in_fib_index;
  u32 n_sessions;
  u32 n_mappings;
} cgnat_sub_t;

typedef struct
{
  clib_bihash_16_8_t in2out;   /* (in fib, in addr, in port, proto) -> mapping */
  clib_bihash_16_8_t out2in;   /* (out fib, out addr, out port, proto) -> mapping */
  clib_bihash_16_8_t sessions; /* (mapping, remote addr, remote port) -> session */
  clib_bihash_8_8_t subs;      /* (in fib, in addr) -> subscriber */
  clib_bihash_8_8_t adf;       /* (mapping, remote addr) -> sessions */
  cgnat_mapping_t *mappings;
  cgnat_session_t *sessions_pool;
  cgnat_sub_t *subs_pool;
  dlist_elt_t *lru_pool;
  u32 lru_head[CGNAT_N_TO];
} cgnat_per_thread_t;

typedef struct
{
  /* maps */
  cgnat_map_t *maps;
  u32 **maps_by_in_fib;
  u32 **maps_by_out_fib;
  fib_source_t fib_src;

  /* per thread state */
  cgnat_per_thread_t *per_thread;

  /* policy */
  u32 timeouts[CGNAT_N_TO];
  u32 sessions_per_sub;
  u8 endpoint_independent_filtering;

  /* interfaces with translation enabled */
  uword *inside_ifs;
  uword *outside_ifs;

  u16 msg_id_base;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} cgnat_main_t;

extern cgnat_main_t cgnat_main;
extern vlib_node_registration_t cgnat_in2out_node;
extern vlib_node_registration_t cgnat_out2in_node;

int cgnat_interface_add_del (u32 sw_if_index, int is_inside, int is_add);
void cgnat_map_flush (u32 map_index);

#endif /* included_cgnat_h */
