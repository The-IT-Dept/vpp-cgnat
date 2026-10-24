/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 The vpp-cgnat authors
 */

/*
 * Who owns a subscriber: which node of the pair, and which worker thread
 * on a node.  Both hash the subscriber identity (inside table id, inside
 * address) so every node computes the same answer for the same subscriber,
 * whatever its local fib indices are.
 */

#ifndef included_cgnat_owner_h
#define included_cgnat_owner_h

#include <vppinfra/xxhash.h>
#include <cgnat/cgnat.h>

static_always_inline u64
cgnat_sub_key (u32 in_table_id, u32 in_addr)
{
  return (u64) in_table_id << 32 | in_addr;
}

/* worker thread for a subscriber on a node with these workers */
static_always_inline u32
cgnat_thread_for (u32 in_table_id, u32 in_addr, u16 first_worker,
		  u16 n_workers)
{
  if (PREDICT_TRUE (n_workers <= 1))
    return n_workers ? first_worker : 0;
  return first_worker +
	 clib_xxhash (cgnat_sub_key (in_table_id, in_addr)) % n_workers;
}

/*
 * Rendezvous (highest random weight) hashing over the active nodes: each
 * active node scores the subscriber, the highest score owns it.  Removing
 * a node only moves that node's subscribers; it generalises to N nodes.
 */
static_always_inline u64
cgnat_hrw_score (u64 key, u8 node_id)
{
  return clib_xxhash (key ^ (0x9e3779b97f4a7c15ULL * node_id));
}

/*
 * The active set is published by the cluster process as one word:
 * bits 0-7 count, 8-15 first node id, 16-23 second node id.
 * Returns the owner node id, or 0 if no node is active.
 */
static_always_inline u8
cgnat_owner_of (u32 active_word, u32 in_table_id, u32 in_addr)
{
  u32 n = active_word & 0xff;
  u8 a = (active_word >> 8) & 0xff, b = (active_word >> 16) & 0xff;
  u64 key;

  if (n <= 1)
    return n ? a : 0;
  key = cgnat_sub_key (in_table_id, in_addr);
  return cgnat_hrw_score (key, a) >= cgnat_hrw_score (key, b) ? a : b;
}

static_always_inline u8
cgnat_owner_node (u32 in_table_id, u32 in_addr)
{
  cgnat_cluster_t *cl = &cgnat_main.cluster;

  if (!cl->enabled)
    return 0; /* no cluster: callers treat 0 as "this node" */
  return cgnat_owner_of (
    __atomic_load_n (&cl->active_word, __ATOMIC_ACQUIRE), in_table_id,
    in_addr);
}

#endif /* included_cgnat_owner_h */
