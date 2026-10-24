/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 The vpp-cgnat authors
 */

#ifndef included_cgnat_cluster_h
#define included_cgnat_cluster_h

#include <vlib/vlib.h>
#include <vnet/ip/ip4_packet.h>
#include <cgnat/cgnat_proto.h>

/* a liveness path; path 0 is the pair link (it also carries steer/sync) */
typedef struct
{
  ip4_address_t local;
  ip4_address_t peer;
  u32 table_id;
  u32 fib_index;
  f64 last_rx;
  u8 alive;
} cgnat_path_t;

#define foreach_cgnat_cluster_reason                                          \
  _ (NONE, "none")                                                            \
  _ (STARTING, "starting")                                                    \
  _ (ALONE, "alone")                                                          \
  _ (RESYNCING, "resyncing")                                                  \
  _ (CONFIG_MISMATCH, "config-mismatch")                                      \
  _ (FENCED, "fenced")                                                        \
  _ (DUPLICATE, "duplicate-node-id")

typedef enum
{
#define _(sym, str) CGNAT_REASON_##sym,
  foreach_cgnat_cluster_reason
#undef _
} cgnat_cluster_reason_t;

typedef struct
{
  /* configuration */
  u8 enabled;
  u8 node_id;
  u16 port;
  cgnat_path_t *paths;
  f64 hello_interval;
  f64 dead_interval;
  f64 refresh_interval;

  /* this incarnation */
  u32 epoch;
  u32 config_hash;
  f64 enabled_at;

  /* last heard from the peer (written by the input node, any thread) */
  volatile u8 peer_node_id;
  volatile u8 peer_state;
  volatile u16 peer_n_workers;
  volatile u16 peer_first_worker;
  volatile u32 peer_epoch;
  volatile u32 peer_config_hash;
  volatile f64 dup_last; /* last HELLO claiming our node id */

  /* evaluated by the cluster process each tick */
  u8 peer_alive;
  u8 pair_alive;
  u8 ready;
  u8 fenced;
  u8 serving; /* data path may translate (owner checks come on top) */
  u32 active_word; /* active node set, see cgnat_owner.h */
  cgnat_cluster_reason_t reason;

  /* startup.conf cluster section, applied at main loop entry */
  struct
  {
    u8 set;
    u8 node_id;
    ip4_address_t local, peer;
    u32 table_id, port, hello_ms, dead_ms, refresh_s;
    ip4_address_t *path_local, *path_peer;
    u32 *path_table;
  } startup;

  /* stats gauges */
  u32 ready_gauge;
  u32 peer_alive_gauge;
  u32 fenced_gauge;
} cgnat_cluster_t;

extern char *cgnat_cluster_reason_strings[];

int cgnat_cluster_set (int enable, u8 node_id, ip4_address_t *local,
		       ip4_address_t *peer, u32 table_id, u16 port,
		       u32 hello_ms, u32 dead_ms, u32 refresh_s);
int cgnat_cluster_path_add_del (ip4_address_t *local, ip4_address_t *peer,
				u32 table_id, int is_add);
u32 cgnat_config_hash (void);

/* a buffer holding outer IPv4/UDP + header for path, body to fill */
vlib_buffer_t *cgnat_cluster_alloc (vlib_main_t *vm, u32 path, u8 type,
				    u32 seq, u32 body_len, void **body,
				    u32 *bi);
/* send buffers built by cgnat_cluster_alloc (any thread) */
void cgnat_cluster_send (vlib_main_t *vm, u32 *bis, u32 n);

extern vlib_node_registration_t cgnat_cluster_input_node;
extern vlib_node_registration_t cgnat_cluster_process_node;

#endif /* included_cgnat_cluster_h */
