/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 The vpp-cgnat authors
 */

#include <vnet/fib/fib_table.h>
#include <cgnat/cgnat.h>

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
