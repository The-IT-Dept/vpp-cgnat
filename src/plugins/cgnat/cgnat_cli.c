/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 The vpp-cgnat authors
 */

#include <vnet/fib/fib_table.h>
#include <cgnat/cgnat.h>
#include <cgnat/cgnat_session.h>

static clib_error_t *
cgnat_map_command_fn (vlib_main_t *vm, unformat_input_t *input,
		      vlib_cli_command_t *cmd)
{
  ip4_address_t in = {}, out = {};
  u32 in_plen = 0, out_plen = 0, in_vrf = 0, out_vrf = 0;
  int is_add = -1, rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "add"))
	is_add = 1;
      else if (unformat (input, "del"))
	is_add = 0;
      else if (unformat (input, "inside %U/%u", unformat_ip4_address, &in,
			 &in_plen))
	;
      else if (unformat (input, "inside-vrf %u", &in_vrf))
	;
      else if (unformat (input, "outside %U/%u", unformat_ip4_address, &out,
			 &out_plen))
	;
      else if (unformat (input, "outside-vrf %u", &out_vrf))
	;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }
  if (is_add < 0 || !in_plen || !out_plen)
    return clib_error_return (
      0, "usage: cgnat map add|del inside <pfx> [inside-vrf <n>] "
	 "outside <pfx> [outside-vrf <n>]");

  rv = cgnat_map_add_del (in_vrf, &in, in_plen, out_vrf, &out, out_plen,
			  is_add);
  if (rv)
    return clib_error_return (0, "cgnat map %s failed: %U",
			      is_add ? "add" : "del", format_vnet_api_errno,
			      rv);
  return 0;
}

VLIB_CLI_COMMAND (cgnat_map_command, static) = {
  .path = "cgnat map",
  .short_help = "cgnat map add|del inside <pfx> [inside-vrf <n>] "
		"outside <pfx> [outside-vrf <n>]",
  .function = cgnat_map_command_fn,
};

static clib_error_t *
show_cgnat_maps_fn (vlib_main_t *vm, unformat_input_t *input,
		    vlib_cli_command_t *cmd)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_map_t *m;

  pool_foreach (m, cm->maps)
    vlib_cli_output (vm,
		     "inside %U/%u vrf %u -> outside %U/%u vrf %u: ratio %u, "
		     "%u ports per subscriber",
		     format_ip4_address, &m->in_base, m->in_plen,
		     m->in_table_id, format_ip4_address, &m->out_base,
		     m->out_plen, m->out_table_id, m->ratio, m->ports_per_sub);
  return 0;
}

VLIB_CLI_COMMAND (show_cgnat_maps_command, static) = {
  .path = "show cgnat maps",
  .short_help = "show cgnat maps",
  .function = show_cgnat_maps_fn,
};

static clib_error_t *
show_cgnat_lookup_fn (vlib_main_t *vm, unformat_input_t *input,
		      vlib_cli_command_t *cmd)
{
  ip4_address_t a, r;
  u32 vrf = 0, port, fib_index;
  cgnat_map_t *m = 0;
  u16 lo, hi;

  if (unformat (input, "forward %U", unformat_ip4_address, &a))
    {
      unformat (input, "inside-vrf %u", &vrf);
      fib_index = fib_table_find (FIB_PROTOCOL_IP4, vrf);
      if (fib_index != ~0)
	m = cgnat_map_by_inside (fib_index, &a);
      if (!m)
	return clib_error_return (0, "%U vrf %u is in no map",
				  format_ip4_address, &a, vrf);
      cgnat_forward (m, &a, &r, &lo, &hi);
      vlib_cli_output (vm, "%U vrf %u -> %U ports %u-%u", format_ip4_address,
		       &a, vrf, format_ip4_address, &r, lo, hi);
    }
  else if (unformat (input, "reverse %U:%u", unformat_ip4_address, &a,
		     &port))
    {
      unformat (input, "outside-vrf %u", &vrf);
      fib_index = fib_table_find (FIB_PROTOCOL_IP4, vrf);
      if (fib_index != ~0)
	m = cgnat_map_by_outside (fib_index, &a);
      if (!m || port > 65535 || cgnat_reverse (m, &a, port, &r))
	return clib_error_return (0, "%U:%u vrf %u is in no block",
				  format_ip4_address, &a, port, vrf);
      vlib_cli_output (vm, "%U:%u vrf %u -> %U vrf %u", format_ip4_address,
		       &a, port, vrf, format_ip4_address, &r, m->in_table_id);
    }
  else
    return clib_error_return (0, "usage: show cgnat lookup forward <addr> "
				 "[inside-vrf <n>] | reverse <addr>:<port> "
				 "[outside-vrf <n>]");
  return 0;
}

VLIB_CLI_COMMAND (show_cgnat_lookup_command, static) = {
  .path = "show cgnat lookup",
  .short_help = "show cgnat lookup forward <addr> [inside-vrf <n>] | "
		"reverse <addr>:<port> [outside-vrf <n>]",
  .function = show_cgnat_lookup_fn,
};

static clib_error_t *
set_interface_cgnat_fn (vlib_main_t *vm, unformat_input_t *input,
			vlib_cli_command_t *cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ~0;
  int is_inside = -1, is_add = 1, rv;

  /* "in"/"out" take the interface as their argument: matched as bare
     keywords they would also match the start of names like "inside" */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "in %U", unformat_vnet_sw_interface, vnm,
		    &sw_if_index))
	is_inside = 1;
      else if (unformat (input, "out %U", unformat_vnet_sw_interface, vnm,
			 &sw_if_index))
	is_inside = 0;
      else if (unformat (input, "del"))
	is_add = 0;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }
  if (is_inside < 0 || sw_if_index == ~0)
    return clib_error_return (0, "usage: set interface cgnat in|out "
				 "<interface> [del]");
  rv = cgnat_interface_add_del (sw_if_index, is_inside, is_add);
  if (rv)
    return clib_error_return (0, "failed: %U", format_vnet_api_errno, rv);
  return 0;
}

VLIB_CLI_COMMAND (set_interface_cgnat_command, static) = {
  .path = "set interface cgnat",
  .short_help = "set interface cgnat in|out <interface> [del]",
  .function = set_interface_cgnat_fn,
};

static char *cgnat_proto_names[] = { "udp", "tcp", "icmp" };
static char *cgnat_class_names[] = { "tcp-established", "tcp-transitory",
				     "udp", "icmp" };

static clib_error_t *
show_cgnat_sessions_fn (vlib_main_t *vm, unformat_input_t *input,
			vlib_cli_command_t *cmd)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_per_thread_t *t;
  ip4_address_t sub = {};
  u32 vrf = 0, fib_index = ~0;
  int filter = 0;

  if (unformat (input, "subscriber %U", unformat_ip4_address, &sub))
    {
      unformat (input, "inside-vrf %u", &vrf);
      fib_index = fib_table_find (FIB_PROTOCOL_IP4, vrf);
      if (fib_index == ~0)
	return clib_error_return (0, "no vrf %u", vrf);
      filter = 1;
    }

  vec_foreach (t, cm->per_thread)
    {
      /* session times are on their owner thread's clock */
      f64 now = cgnat_thread_now (t - cm->per_thread);
      cgnat_session_t *s;

      pool_foreach (s, t->sessions_pool)
	{
	  cgnat_mapping_t *m = pool_elt_at_index (t->mappings, s->mapping_index);
	  if (filter && (m->in_fib_index != fib_index ||
			 m->in_addr.as_u32 != sub.as_u32))
	    continue;
	  vlib_cli_output (
	    vm,
	    "thread %u %s %U:%u fib %u -> %U:%u <-> %U:%u %s idle %.0fs %s",
	    t - cm->per_thread, cgnat_proto_names[m->proto],
	    format_ip4_address, &m->in_addr,
	    clib_net_to_host_u16 (m->in_port), m->in_fib_index,
	    format_ip4_address, &m->out_addr,
	    clib_net_to_host_u16 (m->out_port), format_ip4_address,
	    &s->remote_addr, clib_net_to_host_u16 (s->remote_port),
	    cgnat_class_names[s->to_class], now - s->last_heard,
	    s->warm ? "warm" : "owned");
	}
    }
  return 0;
}

VLIB_CLI_COMMAND (show_cgnat_sessions_command, static) = {
  .path = "show cgnat sessions",
  .short_help = "show cgnat sessions [subscriber <addr> [inside-vrf <n>]]",
  .function = show_cgnat_sessions_fn,
};

static clib_error_t *
cgnat_filtering_fn (vlib_main_t *vm, unformat_input_t *input,
		    vlib_cli_command_t *cmd)
{
  cgnat_main_t *cm = &cgnat_main;

  if (unformat (input, "endpoint-independent"))
    cm->endpoint_independent_filtering = 1;
  else if (unformat (input, "address-dependent"))
    cm->endpoint_independent_filtering = 0;
  else
    return clib_error_return (0, "usage: cgnat filtering "
				 "address-dependent|endpoint-independent");
  return 0;
}

VLIB_CLI_COMMAND (cgnat_filtering_command, static) = {
  .path = "cgnat filtering",
  .short_help = "cgnat filtering address-dependent|endpoint-independent",
  .function = cgnat_filtering_fn,
};

static clib_error_t *
cgnat_session_limit_fn (vlib_main_t *vm, unformat_input_t *input,
			vlib_cli_command_t *cmd)
{
  cgnat_main_t *cm = &cgnat_main;
  u32 n;

  if (!unformat (input, "%u", &n) || n == 0)
    return clib_error_return (0, "usage: cgnat sessions-per-subscriber <n>");
  cm->sessions_per_sub = n;
  return 0;
}

VLIB_CLI_COMMAND (cgnat_session_limit_command, static) = {
  .path = "cgnat sessions-per-subscriber",
  .short_help = "cgnat sessions-per-subscriber <n>",
  .function = cgnat_session_limit_fn,
};

uword
unformat_cgnat_timeouts (unformat_input_t *input, va_list *args)
{
  u32 *t = va_arg (*args, u32 *);
  int n = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "tcp-established %u", &t[CGNAT_TO_TCP_EST]))
	;
      else if (unformat (input, "tcp-transitory %u",
			 &t[CGNAT_TO_TCP_TRANS]))
	;
      else if (unformat (input, "udp %u", &t[CGNAT_TO_UDP]))
	;
      else if (unformat (input, "icmp %u", &t[CGNAT_TO_ICMP]))
	;
      else
	break;
      n++;
    }
  return n > 0;
}

static clib_error_t *
cgnat_timeouts_fn (vlib_main_t *vm, unformat_input_t *input,
		   vlib_cli_command_t *cmd)
{
  cgnat_main_t *cm = &cgnat_main;
  u32 t[CGNAT_N_TO];
  int i;

  clib_memcpy (t, cm->timeouts, sizeof (t));
  if (!unformat (input, "%U", unformat_cgnat_timeouts, t) ||
      unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "usage: cgnat timeouts [tcp-established <s>] "
				 "[tcp-transitory <s>] [udp <s>] [icmp <s>]");
  for (i = 0; i < CGNAT_N_TO; i++)
    if (!t[i])
      return clib_error_return (0, "timeouts must be > 0");
  clib_memcpy (cm->timeouts, t, sizeof (t));
  return 0;
}

VLIB_CLI_COMMAND (cgnat_timeouts_command, static) = {
  .path = "cgnat timeouts",
  .short_help = "cgnat timeouts [tcp-established <s>] [tcp-transitory <s>] "
		"[udp <s>] [icmp <s>]",
  .function = cgnat_timeouts_fn,
};

static clib_error_t *
show_cgnat_status_fn (vlib_main_t *vm, unformat_input_t *input,
		      vlib_cli_command_t *cmd)
{
  cgnat_main_t *cm = &cgnat_main;

  vlib_cli_output (vm, "maps %u, subscribers %lu, mappings %lu, sessions %lu",
		   pool_elts (cm->maps),
		   cgnat_counter_total (CGNAT_COUNTER_SUBSCRIBERS),
		   cgnat_counter_total (CGNAT_COUNTER_MAPPINGS),
		   cgnat_counter_total (CGNAT_COUNTER_SESSIONS));
  vlib_cli_output (vm,
		   "filtering %s, sessions per subscriber %u (+%u inbound), "
		   "max %u per thread",
		   cm->endpoint_independent_filtering ?
		     "endpoint-independent" :
		     "address-dependent",
		   cm->sessions_per_sub, cm->inbound_sessions_per_sub,
		   cm->max_sessions_per_thread);
  vlib_cli_output (vm,
		   "timeouts: tcp-established %us tcp-transitory %us udp %us "
		   "icmp %us",
		   cm->timeouts[CGNAT_TO_TCP_EST],
		   cm->timeouts[CGNAT_TO_TCP_TRANS], cm->timeouts[CGNAT_TO_UDP],
		   cm->timeouts[CGNAT_TO_ICMP]);
  vlib_cli_output (vm, "threads: %u workers from %u", cm->n_workers,
		   cm->first_worker_index);
  vlib_cli_output (
    vm,
    "packets: in2out %lu, out2in %lu, hairpin %lu, steered-out %lu, "
    "steered-in %lu",
    cgnat_counter_total (CGNAT_COUNTER_IN2OUT_PACKETS),
    cgnat_counter_total (CGNAT_COUNTER_OUT2IN_PACKETS),
    cgnat_counter_total (CGNAT_COUNTER_HAIRPIN_PACKETS),
    cgnat_counter_total (CGNAT_COUNTER_STEERED_OUT),
    cgnat_counter_total (CGNAT_COUNTER_STEERED_IN));
  vlib_cli_output (
    vm, "sync: records-out %lu, records-in %lu, retransmits %lu, overflow %lu",
    cgnat_counter_total (CGNAT_COUNTER_SYNC_RECORDS_OUT),
    cgnat_counter_total (CGNAT_COUNTER_SYNC_RECORDS_IN),
    cgnat_counter_total (CGNAT_COUNTER_SYNC_RETRANSMITS),
    cgnat_counter_total (CGNAT_COUNTER_SYNC_OVERFLOW));
  return 0;
}

VLIB_CLI_COMMAND (show_cgnat_status_command, static) = {
  .path = "show cgnat status",
  .short_help = "show cgnat status",
  .function = show_cgnat_status_fn,
};

static clib_error_t *
cgnat_inbound_limit_fn (vlib_main_t *vm, unformat_input_t *input,
			vlib_cli_command_t *cmd)
{
  u32 n;

  if (!unformat (input, "%u", &n))
    return clib_error_return (
      0, "usage: cgnat inbound-sessions-per-subscriber <n>");
  cgnat_main.inbound_sessions_per_sub = n;
  return 0;
}

VLIB_CLI_COMMAND (cgnat_inbound_limit_command, static) = {
  .path = "cgnat inbound-sessions-per-subscriber",
  .short_help = "cgnat inbound-sessions-per-subscriber <n>",
  .function = cgnat_inbound_limit_fn,
};

static clib_error_t *
cgnat_max_sessions_fn (vlib_main_t *vm, unformat_input_t *input,
		       vlib_cli_command_t *cmd)
{
  u32 n;

  if (!unformat (input, "%u", &n) || !n)
    return clib_error_return (0, "usage: cgnat max-sessions-per-thread <n>");
  cgnat_main.max_sessions_per_thread = n;
  return 0;
}

VLIB_CLI_COMMAND (cgnat_max_sessions_command, static) = {
  .path = "cgnat max-sessions-per-thread",
  .short_help = "cgnat max-sessions-per-thread <n>",
  .function = cgnat_max_sessions_fn,
};

static clib_error_t *
cgnat_cluster_command_fn (vlib_main_t *vm, unformat_input_t *input,
			  vlib_cli_command_t *cmd)
{
  ip4_address_t local = {}, peer = {};
  u32 node_id = 0, table_id = 0, port = 0, hello = 0, dead = 0, refresh = 0;
  u32 window = 0;
  int rv, is_add = 1, path = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "disable"))
	return cgnat_cluster_set (0, 0, 0, 0, 0, 0, 0, 0, 0) ?
		 clib_error_return (0, "failed") :
		 0;
      else if (unformat (input, "path add"))
	path = 1;
      else if (unformat (input, "path del"))
	path = 1, is_add = 0;
      else if (unformat (input, "node-id %u", &node_id))
	;
      else if (unformat (input, "local %U", unformat_ip4_address, &local))
	;
      else if (unformat (input, "peer %U", unformat_ip4_address, &peer))
	;
      else if (unformat (input, "table %u", &table_id))
	;
      else if (unformat (input, "port %u", &port))
	;
      else if (unformat (input, "hello-interval %u", &hello))
	;
      else if (unformat (input, "dead-interval %u", &dead))
	;
      else if (unformat (input, "refresh-interval %u", &refresh))
	;
      else if (unformat (input, "window %u", &window) && window)
	;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }
  if (window)
    {
      cgnat_main.cluster.window = window;
      if (!node_id && !path)
	return 0;
    }
  if (path)
    rv = cgnat_cluster_path_add_del (&local, &peer, table_id, is_add);
  else
    rv = cgnat_cluster_set (1, node_id, &local, &peer, table_id, port, hello,
			    dead, refresh);
  if (rv)
    return clib_error_return (0, "cgnat cluster failed: %U",
			      format_vnet_api_errno, rv);
  return 0;
}

VLIB_CLI_COMMAND (cgnat_cluster_command, static) = {
  .path = "cgnat cluster",
  .short_help = "cgnat cluster node-id <n> local <ip> peer <ip> [table <id>] "
		"[port <n>] [hello-interval <ms>] [dead-interval <ms>] "
		"[refresh-interval <s>] | path add|del local <ip> peer <ip> "
		"[table <id>] | disable",
  .function = cgnat_cluster_command_fn,
};

static clib_error_t *
show_cgnat_cluster_fn (vlib_main_t *vm, unformat_input_t *input,
		       vlib_cli_command_t *cmd)
{
  cgnat_cluster_t *cl = &cgnat_main.cluster;
  f64 now = cgnat_clock_now (); /* HELLOs are stamped on the plugin clock */
  cgnat_path_t *p;

  if (!cl->enabled)
    {
      vlib_cli_output (vm, "cluster: disabled (alone, ready)");
      return 0;
    }
  vlib_cli_output (vm, "node %u epoch %08x: %s, %s, config %08x",
		   cl->node_id, cl->epoch, cl->ready ? "ready" : "not ready",
		   cgnat_cluster_reason_strings[cl->reason],
		   cgnat_config_hash ());
  vlib_cli_output (vm, "peer node %u epoch %08x: %s%s%s, config %08x",
		   cl->peer_node_id, cl->peer_epoch,
		   cl->peer_alive ? "alive" : "dead",
		   (cl->peer_state & CGNAT_HELLO_READY) ? ", ready" : "",
		   (cl->peer_state & CGNAT_HELLO_FENCED) ? ", fenced" : "",
		   cl->peer_config_hash);
  if (cl->ready && !cl->forwarding)
    vlib_cli_output (vm, "next hops: down (BFD not up yet?), the peer "
			 "keeps our subscribers");
  vec_foreach (p, cl->paths)
    vlib_cli_output (vm, "  path %u %U -> %U table %u: %s (%.2fs ago)",
		     p - cl->paths, format_ip4_address, &p->local,
		     format_ip4_address, &p->peer, p->table_id,
		     p->alive ? "alive" : "dead",
		     p->last_rx > 0 ? now - p->last_rx : -1.0);
  return 0;
}

VLIB_CLI_COMMAND (show_cgnat_cluster_command, static) = {
  .path = "show cgnat cluster",
  .short_help = "show cgnat cluster",
  .function = show_cgnat_cluster_fn,
};
