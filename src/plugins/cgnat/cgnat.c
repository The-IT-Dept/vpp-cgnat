/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 The vpp-cgnat authors
 */

#include <vnet/plugin/plugin.h>
#include <vnet/feature/feature.h>
#include <vnet/ip/reass/ip4_sv_reass.h>
#include <vpp/app/version.h>
#include <cgnat/cgnat.h>
#include <cgnat/cgnat_session.h>

cgnat_main_t cgnat_main;

int
cgnat_interface_add_del (u32 sw_if_index, int is_inside, int is_add)
{
  cgnat_main_t *cm = &cgnat_main;
  uword **ifs = is_inside ? &cm->inside_ifs : &cm->outside_ifs;
  int rv;

  if (is_add == clib_bitmap_get (*ifs, sw_if_index))
    return is_add ? VNET_API_ERROR_VALUE_EXIST : VNET_API_ERROR_NO_SUCH_ENTRY;

  rv = ip4_sv_reass_enable_disable_with_refcnt (sw_if_index, is_add);
  if (rv)
    return rv;
  rv = vnet_feature_enable_disable (
    "ip4-unicast", is_inside ? "cgnat-in2out" : "cgnat-out2in", sw_if_index,
    is_add, 0, 0);
  if (rv)
    return rv;
  *ifs = clib_bitmap_set (*ifs, sw_if_index, is_add);
  return 0;
}

/* runs on main with workers stopped (CLI/API barrier) */
void
cgnat_map_flush (u32 map_index)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_per_thread_t *t;
  u32 *to_free = 0, *si;

  vec_foreach (t, cm->per_thread)
    {
      u32 ti = t - cm->per_thread;
      cgnat_session_t *s;

      pool_foreach (s, t->sessions_pool)
	{
	  if (pool_elt_at_index (t->mappings, s->mapping_index)->map_index ==
	      map_index)
	    vec_add1 (to_free, s - t->sessions_pool);
	}
      vec_foreach (si, to_free)
	cgnat_session_free (t, ti, pool_elt_at_index (t->sessions_pool, *si));
      vec_reset_length (to_free);
    }
  vec_free (to_free);
}

static clib_error_t *
cgnat_init (vlib_main_t *vm)
{
  cgnat_main_t *cm = &cgnat_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  cgnat_per_thread_t *t;

  cm->vlib_main = vm;
  cm->vnet_main = vnet_get_main ();
  cm->fib_src = fib_source_allocate ("cgnat", FIB_SOURCE_PRIORITY_HI,
				     FIB_SOURCE_BH_SIMPLE);

  cm->timeouts[CGNAT_TO_TCP_EST] = 7440;
  cm->timeouts[CGNAT_TO_TCP_TRANS] = 240;
  cm->timeouts[CGNAT_TO_UDP] = 300;
  cm->timeouts[CGNAT_TO_ICMP] = 60;
  cm->sessions_per_sub = 1000;
  cm->endpoint_independent_filtering = 0;

  cm->first_worker_index = 0;
  cm->n_workers = 0;
  {
    vlib_thread_registration_t *tr;
    uword *p = hash_get_mem (tm->thread_registrations_by_name, "workers");
    if (p)
      {
	tr = (vlib_thread_registration_t *) p[0];
	cm->n_workers = tr->count;
	cm->first_worker_index = tr->first_index;
      }
  }

  vec_validate (cm->per_thread, tm->n_vlib_mains - 1);
  vec_foreach (t, cm->per_thread)
    cgnat_per_thread_init (t);
  return 0;
}

VLIB_INIT_FUNCTION (cgnat_init);

static clib_error_t *
cgnat_main_loop_enter (vlib_main_t *vm)
{
  cgnat_main_t *cm = &cgnat_main;

  /* handoff queues to each node on the subscriber's owner thread */
  cm->fq_in2out_index = vlib_frame_queue_main_init (cgnat_in2out_node.index, 0);
  cm->fq_out2in_index = vlib_frame_queue_main_init (cgnat_out2in_node.index, 0);
  cm->fq_hairpin_index =
    vlib_frame_queue_main_init (cgnat_hairpin_node.index, 0);
  return 0;
}

VLIB_MAIN_LOOP_ENTER_FUNCTION (cgnat_main_loop_enter);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "CGNAT: deterministic port blocks, HA pair (vpp-cgnat)",
};
