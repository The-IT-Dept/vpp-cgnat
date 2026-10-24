/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 The vpp-cgnat authors
 */

#ifndef included_cgnat_sync_h
#define included_cgnat_sync_h

#include <cgnat/cgnat.h>

#define CGNAT_SYNC_MAX_RECORDS 40    /* 1332-byte packets */
#define CGNAT_SYNC_RTO	       0.05 /* seconds before a retransmit */
#define CGNAT_SYNC_TICK	       0.01 /* flush / retransmit / ack tick */

/* queue a record for the peer if we own the session's subscriber */
void cgnat_sync_session (cgnat_per_thread_t *t, u32 thread_index,
			 cgnat_session_t *s, u8 op);

/* after a touch: sync on class change or when the refresh interval passed */
static_always_inline void
cgnat_sync_touched (cgnat_per_thread_t *t, u32 thread_index,
		    cgnat_session_t *s, u8 old_class, int created, f64 now)
{
  cgnat_cluster_t *cl = &cgnat_main.cluster;

  s->warm = 0; /* we own it now */
  if (PREDICT_TRUE (!cl->enabled))
    return;
  if (created || old_class != s->to_class ||
      now - s->last_synced >= cl->refresh_interval)
    cgnat_sync_session (t, thread_index, s, CGNAT_REC_UPSERT);
}

extern vlib_node_registration_t cgnat_sync_worker_node;
extern vlib_node_registration_t cgnat_sync_flush_node;

#endif /* included_cgnat_sync_h */
