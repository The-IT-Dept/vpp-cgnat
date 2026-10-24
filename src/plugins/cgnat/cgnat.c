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

u64
cgnat_counter_total (cgnat_counter_t c)
{
  return vlib_get_simple_counter (&cgnat_main.counters[c], 0);
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
  cm->inbound_sessions_per_sub = 250;
  cm->max_sessions_per_thread = 1 << 20;
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

  {
    static char *names[] = {
#define _(sym, name) name,
      foreach_cgnat_counter
#undef _
    };
    int i;
    for (i = 0; i < CGNAT_N_COUNTER; i++)
      {
	cm->counters[i].name = names[i];
	cm->counters[i].stat_segment_name =
	  (char *) format (0, "/cgnat/%s%c", names[i], 0);
	vlib_validate_simple_counter (&cm->counters[i], 0);
	vlib_zero_simple_counter (&cm->counters[i], 0);
      }
  }

  vec_validate (cm->per_thread, tm->n_vlib_mains - 1);
  vec_foreach (t, cm->per_thread)
    cgnat_per_thread_init (t);
  return 0;
}

VLIB_INIT_FUNCTION (cgnat_init);

uword unformat_cgnat_timeouts (unformat_input_t *input, va_list *args);

/*
 * startup.conf:
 *   cgnat {
 *     sessions-per-subscriber <n>          (outbound-created, default 1000)
 *     inbound-sessions-per-subscriber <n>  (inbound-created, default 250)
 *     max-sessions-per-thread <n>          (default 1048576)
 *     timeouts { tcp-established <s> tcp-transitory <s> udp <s> icmp <s> }
 *     filtering address-dependent | endpoint-independent
 *   }
 */
static clib_error_t *
cgnat_config (vlib_main_t *vm, unformat_input_t *input)
{
  cgnat_main_t *cm = &cgnat_main;
  unformat_input_t sub;
  u32 t[CGNAT_N_TO], n;
  int i;

  clib_memcpy (t, cm->timeouts, sizeof (t));
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "sessions-per-subscriber %u", &n))
	{
	  if (!n)
	    return clib_error_return (0, "cgnat: sessions-per-subscriber 0");
	  cm->sessions_per_sub = n;
	}
      else if (unformat (input, "inbound-sessions-per-subscriber %u", &n))
	cm->inbound_sessions_per_sub = n;
      else if (unformat (input, "max-sessions-per-thread %u", &n))
	{
	  if (!n)
	    return clib_error_return (0, "cgnat: max-sessions-per-thread 0");
	  cm->max_sessions_per_thread = n;
	}
      else if (unformat (input, "timeouts %U", unformat_vlib_cli_sub_input,
			 &sub))
	{
	  if (!unformat (&sub, "%U", unformat_cgnat_timeouts, t) ||
	      unformat_check_input (&sub) != UNFORMAT_END_OF_INPUT)
	    return clib_error_return (0, "cgnat: bad timeouts '%U'",
				      format_unformat_error, &sub);
	  unformat_free (&sub);
	}
      else if (unformat (input, "cluster %U", unformat_vlib_cli_sub_input,
			 &sub))
	{
	  typeof (cm->cluster.startup) *c = &cm->cluster.startup;
	  ip4_address_t pl, pp;
	  u32 pt = 0;

	  c->set = 1;
	  while (unformat_check_input (&sub) != UNFORMAT_END_OF_INPUT)
	    {
	      if (unformat (&sub, "node-id %u", &n))
		c->node_id = n;
	      else if (unformat (&sub, "local %U", unformat_ip4_address,
				 &c->local))
		;
	      else if (unformat (&sub, "peer %U", unformat_ip4_address,
				 &c->peer))
		;
	      else if (unformat (&sub, "table %u", &c->table_id))
		;
	      else if (unformat (&sub, "port %u", &c->port))
		;
	      else if (unformat (&sub, "hello-interval %u", &c->hello_ms))
		;
	      else if (unformat (&sub, "dead-interval %u", &c->dead_ms))
		;
	      else if (unformat (&sub, "refresh-interval %u", &c->refresh_s))
		;
	      else if (unformat (&sub, "path local %U peer %U table %u",
				 unformat_ip4_address, &pl,
				 unformat_ip4_address, &pp, &pt) ||
		       (pt = 0, unformat (&sub, "path local %U peer %U",
					  unformat_ip4_address, &pl,
					  unformat_ip4_address, &pp)))
		{
		  vec_add1 (c->path_local, pl);
		  vec_add1 (c->path_peer, pp);
		  vec_add1 (c->path_table, pt);
		}
	      else
		return clib_error_return (0, "cgnat cluster: unknown '%U'",
					  format_unformat_error, &sub);
	    }
	  unformat_free (&sub);
	}
      else if (unformat (input, "filtering endpoint-independent"))
	cm->endpoint_independent_filtering = 1;
      else if (unformat (input, "filtering address-dependent"))
	cm->endpoint_independent_filtering = 0;
      else
	return clib_error_return (0, "cgnat: unknown input '%U'",
				  format_unformat_error, input);
    }
  for (i = 0; i < CGNAT_N_TO; i++)
    if (!t[i])
      return clib_error_return (0, "cgnat: timeouts must be > 0");
  clib_memcpy (cm->timeouts, t, sizeof (t));
  return 0;
}

VLIB_CONFIG_FUNCTION (cgnat_config, "cgnat");

static clib_error_t *
cgnat_main_loop_enter (vlib_main_t *vm)
{
  cgnat_main_t *cm = &cgnat_main;

  /* handoff queues to each node on the subscriber's owner thread */
  cm->fq_in2out_index = vlib_frame_queue_main_init (cgnat_in2out_node.index, 0);
  cm->fq_out2in_index = vlib_frame_queue_main_init (cgnat_out2in_node.index, 0);
  cm->fq_hairpin_index =
    vlib_frame_queue_main_init (cgnat_hairpin_node.index, 0);

  /* cluster from startup.conf */
  {
    typeof (cm->cluster.startup) *c = &cm->cluster.startup;
    u32 i;
    if (c->set)
      {
	int rv = cgnat_cluster_set (1, c->node_id, &c->local, &c->peer,
				    c->table_id, c->port, c->hello_ms,
				    c->dead_ms, c->refresh_s);
	if (rv)
	  return clib_error_return (0, "cgnat cluster: startup config: %U",
				    format_vnet_api_errno, rv);
	vec_foreach_index (i, c->path_local)
	  cgnat_cluster_path_add_del (&c->path_local[i], &c->path_peer[i],
				      c->path_table[i], 1);
      }
  }
  return 0;
}

VLIB_MAIN_LOOP_ENTER_FUNCTION (cgnat_main_loop_enter);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "CGNAT: deterministic port blocks, HA pair (vpp-cgnat)",
};
