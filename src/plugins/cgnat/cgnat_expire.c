/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 The vpp-cgnat authors
 */

/*
 * Session expiry.  Each thread owns its sessions, so each thread expires
 * its own: a process on main raises an interrupt on every thread ten times
 * a second, and the per-thread input node walks each timeout class's LRU
 * list from the oldest end until it meets a live session.  A run does at
 * most CGNAT_EXPIRE_SLICE of work, then re-arms itself so a large backlog
 * drains over the next loops without stalling forwarding.  Lookups treat
 * expired-but-unwalked sessions as gone, so the walker's pace never
 * changes behaviour, only memory.
 */

#include <vlib/vlib.h>
#include <cgnat/cgnat.h>
#include <cgnat/cgnat_session.h>

#define CGNAT_EXPIRE_SLICE 0.5e-3 /* seconds of work per run */
#define CGNAT_EXPIRE_TICK  0.1	   /* seconds between runs */

VLIB_NODE_FN (cgnat_expire_walk_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  cgnat_main_t *cm = &cgnat_main;
  u32 thread_index = vm->thread_index;
  cgnat_per_thread_t *t = vec_elt_at_index (cm->per_thread, thread_index);
  f64 now = vlib_time_now (vm);
  u32 n = 0;
  int c, more = 0;

  for (c = 0; c < CGNAT_N_TO; c++)
    {
      u32 head = t->lru_head[c];
      f64 timeout = cm->timeouts[c];

      while (1)
	{
	  /* yield to the data path; run again on the next loop */
	  if ((n & 255) == 255 &&
	      vlib_time_now (vm) - now > CGNAT_EXPIRE_SLICE)
	    {
	      more = 1;
	      goto done;
	    }
	  u32 oldest = pool_elt_at_index (t->lru_pool, head)->next;
	  cgnat_session_t *s;

	  if (oldest == head || oldest == ~0) /* empty list head is ~0 */
	    break;
	  s = pool_elt_at_index (t->sessions_pool,
				 pool_elt_at_index (t->lru_pool, oldest)->value);
	  if (now - s->last_heard <
	      timeout + (s->warm ? cm->cluster.refresh_interval : 0))
	    {
	      /* heard since it was placed (lazy touch): move it along */
	      if (s->last_heard > s->lru_at)
		{
		  cgnat_session_relink (t, s, c, s->last_heard, now);
		  n++;
		  continue;
		}
	      break;
	    }
	  cgnat_session_free (t, thread_index, s);
	  n++;
	}
    }
done:
  if (more)
    vlib_node_set_interrupt_pending (vm, node->node_index);
  return n;
}

VLIB_REGISTER_NODE (cgnat_expire_walk_node) = {
  .name = "cgnat-expire-walk",
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_INTERRUPT,
};

#ifndef CLIB_MARCH_VARIANT
static uword
cgnat_expire_process (vlib_main_t *vm, vlib_node_runtime_t *rt,
		      vlib_frame_t *f)
{
  while (1)
    {
      u32 ti;

      vlib_process_wait_for_event_or_clock (vm, CGNAT_EXPIRE_TICK);
      vlib_process_get_events (vm, 0);
      for (ti = 0; ti < vlib_get_n_threads (); ti++)
	vlib_node_set_interrupt_pending (vlib_get_main_by_index (ti),
					 cgnat_expire_walk_node.index);
    }
  return 0;
}

VLIB_REGISTER_NODE (cgnat_expire_process_node) = {
  .function = cgnat_expire_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "cgnat-expire-process",
};
#endif
