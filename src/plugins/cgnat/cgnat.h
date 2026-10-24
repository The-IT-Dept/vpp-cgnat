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
#include <cgnat/cgnat_cluster.h>

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

/* stats segment counters, /cgnat/<name> */
#define foreach_cgnat_counter                                                 \
  _ (IN2OUT_PACKETS, "in2out-packets")                                        \
  _ (OUT2IN_PACKETS, "out2in-packets")                                        \
  _ (HAIRPIN_PACKETS, "hairpin-packets")                                      \
  _ (STEERED_OUT, "steered-out")                                              \
  _ (STEERED_IN, "steered-in")                                                \
  _ (SYNC_RECORDS_OUT, "sync/records-out")                                    \
  _ (SYNC_RECORDS_IN, "sync/records-in")                                      \
  _ (SYNC_RETRANSMITS, "sync/retransmits")                                    \
  _ (SYNC_OVERFLOW, "sync/overflow")                                          \
  _ (SESSIONS, "sessions")                                                    \
  _ (MAPPINGS, "mappings")                                                    \
  _ (SUBSCRIBERS, "subscribers")

typedef enum
{
#define _(sym, name) CGNAT_COUNTER_##sym,
  foreach_cgnat_counter
#undef _
    CGNAT_N_COUNTER,
} cgnat_counter_t;

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
  u8 inbound; /* created by an inbound packet (counts against inbound cap) */
  u8 warm;    /* copy of a session the peer owns (installed by sync) */
  f64 last_synced;
  f64 lru_at; /* when last placed at its LRU list tail */
  f64 last_heard;
  u32 lru_index;
} cgnat_session_t;

/* A subscriber: (inside fib, inside address) */
typedef struct
{
  ip4_address_t in_addr;
  u32 in_fib_index;
  u32 n_sessions; /* all sessions */
  u32 n_inbound;  /* of which created by inbound packets */
  u32 n_mappings;
} cgnat_sub_t;

/* a sent SYNC kept until acknowledged */
typedef struct
{
  u32 seq;
  u32 bi; /* copy of what was sent */
  f64 sent;
} cgnat_sync_pending_t;

/* one direction of one (local thread -> peer thread) stream */
typedef struct
{
  u32 bi; /* SYNC being filled, ~0 if none */
  u16 n_records;
  u32 next_seq;
  cgnat_sync_pending_t *unacked; /* oldest first */
} cgnat_sync_tx_t;

/* what we've received from one peer thread */
typedef struct
{
  u32 epoch;
  u32 expected; /* next in-order seq */
  u8 ack_pending;
} cgnat_sync_rx_t;

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

  /* session sync */
  cgnat_sync_tx_t *sync_tx; /* by peer thread */
  cgnat_sync_rx_t *sync_rx; /* by peer thread */
  u32 sync_gen;
  u32 resync_walk_gen; /* last walk started */
  u32 resync_cursor;   /* next session pool index */
  u8 resync_active;
} cgnat_per_thread_t;

typedef struct
{
  /* maps */
  cgnat_map_t *maps;
  u32 **maps_by_in_fib;
  u32 **maps_by_out_fib;
  fib_source_t fib_src;

  /* per thread state; each subscriber is owned by one thread */
  cgnat_per_thread_t *per_thread;
  u32 first_worker_index;
  u32 n_workers;
  u32 fq_in2out_index;
  u32 fq_out2in_index;
  u32 fq_hairpin_index;
  u32 fq_in2out_steered_index;
  u32 fq_out2in_steered_index;
  u32 fq_hairpin_steered_index;
  u32 fq_sync_index;

  /* policy */
  u32 timeouts[CGNAT_N_TO];
  u32 sessions_per_sub;	  /* outbound-created sessions per subscriber */
  u32 inbound_sessions_per_sub; /* inbound-created sessions per subscriber */
  u32 max_sessions_per_thread;
  u8 endpoint_independent_filtering;

  /*
   * Stats.  Packet counters, and gauges kept per thread (each thread
   * only ever increments/decrements its own slot, so per-thread values
   * are never negative and their sum is the total).
   */
  vlib_simple_counter_main_t counters[CGNAT_N_COUNTER];

  /* the HA pair */
  cgnat_cluster_t cluster;

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
extern vlib_node_registration_t cgnat_hairpin_node;
extern vlib_node_registration_t cgnat_in2out_steered_node;
extern vlib_node_registration_t cgnat_out2in_steered_node;
extern vlib_node_registration_t cgnat_hairpin_steered_node;

/* encapsulate buffers (table id stashed in sw_if_index[VLIB_TX]) and send
   them to the owner over the pair link */
void cgnat_steer_send (vlib_main_t *vm, u32 *bis, u32 n, u8 direction);

static_always_inline void
cgnat_gauge (u32 thread_index, cgnat_counter_t c, int delta)
{
  if (delta > 0)
    vlib_increment_simple_counter (&cgnat_main.counters[c], thread_index, 0,
				   delta);
  else
    vlib_decrement_simple_counter (&cgnat_main.counters[c], thread_index, 0,
				   -delta);
}

u64 cgnat_counter_total (cgnat_counter_t c);

int cgnat_interface_add_del (u32 sw_if_index, int is_inside, int is_add);
void cgnat_map_flush (u32 map_index);

#endif /* included_cgnat_h */
