/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 The vpp-cgnat authors
 */

/*
 * Pair membership: configuration, HELLOs on every path, liveness, the
 * config hash, and the ready / serving decision.  A process on the main
 * thread does all of the evaluation each hello interval; the input node
 * only records what it hears, on whichever thread receives it, so every
 * time here is on cgnat_clock_now() (see cgnat.h).
 */

#include <vnet/fib/fib_table.h>
#include <vnet/adj/adj.h>
#include <vnet/adj/adj_nbr.h>
#include <vnet/udp/udp_local.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/ip/ip4.h>
#include <vlib/stats/stats.h>
#include <cgnat/cgnat.h>
#include <cgnat/cgnat_inlines.h>

char *cgnat_cluster_reason_strings[] = {
#define _(sym, str) str,
  foreach_cgnat_cluster_reason
#undef _
};

enum
{
  CGNAT_CLUSTER_EVENT_CHANGED = 1,
};

u32
cgnat_config_hash (void)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_cluster_t *cl = &cm->cluster;
  cgnat_map_t *m;
  u64 h = 0;
  int i;

  /* order-independent over maps */
  pool_foreach (m, cm->maps)
    {
      u64 in = (u64) m->in_table_id << 40 | (u64) m->in_plen << 32 |
	       m->in_base.as_u32;
      u64 out = (u64) m->out_table_id << 40 | (u64) m->out_plen << 32 |
		m->out_base.as_u32;
      h += clib_xxhash (in) ^ (clib_xxhash (out) * 31);
    }
  for (i = 0; i < CGNAT_N_TO; i++)
    h = clib_xxhash (h ^ ((u64) (i + 1) << 32 | cm->timeouts[i]));
  h = clib_xxhash (h ^ (u64) cm->sessions_per_sub << 32 ^
		   cm->inbound_sessions_per_sub);
  /* (max-sessions-per-thread is node-local sizing: not hashed) */
  h = clib_xxhash (h ^ (u64) cm->endpoint_independent_filtering << 48);
  h = clib_xxhash (h ^ (u64) (cl->hello_interval * 1e3) << 32 ^
		   (u64) (cl->dead_interval * 1e3));
  h = clib_xxhash (h ^ (u64) cl->refresh_interval);
  return (u32) (h ^ (h >> 32));
}

vlib_buffer_t *
cgnat_cluster_alloc (vlib_main_t *vm, u32 path, u8 type, u32 seq,
		     u32 body_len, void **body, u32 *bi)
{
  cgnat_cluster_t *cl = &cgnat_main.cluster;
  cgnat_path_t *p = vec_elt_at_index (cl->paths, path);
  ip4_header_t *ip;
  udp_header_t *udp;
  cgnat_msg_hdr_t *h;
  vlib_buffer_t *b;
  u16 len = sizeof (*ip) + sizeof (*udp) + sizeof (*h) + body_len;

  if (vlib_buffer_alloc (vm, bi, 1) != 1)
    return 0;
  b = vlib_get_buffer (vm, *bi);
  b->current_data = 0;
  b->current_length = len;
  b->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
  vnet_buffer (b)->sw_if_index[VLIB_RX] = 0;
  vnet_buffer (b)->sw_if_index[VLIB_TX] = p->fib_index;

  ip = vlib_buffer_get_current (b);
  clib_memset (ip, 0, sizeof (*ip));
  ip->ip_version_and_header_length = 0x45;
  ip->ttl = CGNAT_PAIR_TTL;
  ip->protocol = IP_PROTOCOL_UDP;
  ip->length = clib_host_to_net_u16 (len);
  ip->src_address = p->local;
  ip->dst_address = p->peer;
  ip->checksum = ip4_header_checksum (ip);

  udp = (udp_header_t *) (ip + 1);
  udp->src_port = udp->dst_port = clib_host_to_net_u16 (cl->port);
  udp->length = clib_host_to_net_u16 (len - sizeof (*ip));
  udp->checksum = 0;

  h = (cgnat_msg_hdr_t *) (udp + 1);
  h->version = CGNAT_PROTO_VERSION;
  h->type = type;
  h->flags = 0;
  h->node_id = cl->node_id;
  h->config_hash = clib_host_to_net_u32 (cl->config_hash);
  h->epoch = clib_host_to_net_u32 (cl->epoch);
  h->seq = clib_host_to_net_u32 (seq);
  *body = h + 1;
  return b;
}

void
cgnat_cluster_send (vlib_main_t *vm, u32 *bis, u32 n)
{
  vlib_frame_t *f;
  u32 *to;

  while (n)
    {
      u32 k = clib_min (n, VLIB_FRAME_SIZE);
      f = vlib_get_frame_to_node (vm, ip4_lookup_node.index);
      to = vlib_frame_vector_args (f);
      vlib_buffer_copy_indices (to, bis, k);
      f->n_vectors = k;
      vlib_put_frame_to_node (vm, ip4_lookup_node.index, f);
      bis += k;
      n -= k;
    }
}

static int
cgnat_cluster_peer_in_active (cgnat_cluster_t *cl)
{
  u32 w = cl->active_word, n = w & 0xff;
  return cl->peer_node_id &&
	 ((n >= 1 && ((w >> 8) & 0xff) == cl->peer_node_id) ||
	  (n >= 2 && ((w >> 16) & 0xff) == cl->peer_node_id));
}

static void
cgnat_cluster_send_hellos (vlib_main_t *vm)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_cluster_t *cl = &cm->cluster;
  u32 *bis = 0, bi, i;

  vec_foreach_index (i, cl->paths)
    {
      cgnat_msg_hello_t *hb;
      if (!cgnat_cluster_alloc (vm, i, CGNAT_MSG_HELLO, 0, sizeof (*hb),
				(void **) &hb, &bi))
	break;
      hb->path_id = i;
      /* ready for routing isn't enough for the peer to hand us
	 subscribers: our next hops must be up too */
      hb->state = (cl->ready && cl->forwarding ? CGNAT_HELLO_READY : 0) |
		  (cl->fenced ? CGNAT_HELLO_FENCED : 0) |
		  (cl->want_resync_peer ? CGNAT_HELLO_WANT_RESYNC : 0) |
		  (cgnat_cluster_peer_in_active (cl) ?
		     CGNAT_HELLO_PEER_IN_ACTIVE :
		     0);
      hb->n_workers = clib_host_to_net_u16 (cm->n_workers);
      hb->first_worker = clib_host_to_net_u16 (cm->first_worker_index);
      hb->pad = 0;
      hb->heard_epoch = clib_host_to_net_u32 (cl->peer_epoch);
      vec_add1 (bis, bi);
    }
  cgnat_cluster_send (vm, bis, vec_len (bis));
  vec_free (bis);
}

static void
cgnat_cluster_send_resync_req (vlib_main_t *vm)
{
  void *body;
  u32 bi;

  if (cgnat_cluster_alloc (vm, 0, CGNAT_MSG_RESYNC_REQ, 0, 0, &body, &bi))
    cgnat_cluster_send (vm, &bi, 1);
}

/* is the path's local address on an interface that is up with link? */
static int
cgnat_path_link_up (cgnat_path_t *p)
{
  const load_balance_t *lb;
  const dpo_id_t *dpo;
  const receive_dpo_t *rd;

  if (!cgnat_is_local (p->fib_index, &p->local))
    return 0;
  lb = load_balance_get (ip4_fib_forwarding_lookup (p->fib_index, &p->local));
  dpo = load_balance_get_bucket_i (lb, 0);
  rd = receive_dpo_get (dpo->dpoi_index);
  return rd->rd_sw_if_index != ~0 &&
	 vnet_sw_interface_is_link_up (vnet_get_main (), rd->rd_sw_if_index);
}

/* is every interface we translate on up with link?  A node that can't
   forward must not hold subscribers: at startup a VF's link comes up
   seconds after the pair link, and a lost uplink should hand over */
static int
cgnat_data_links_up (void)
{
  cgnat_main_t *cm = &cgnat_main;
  vnet_main_t *vnm = vnet_get_main ();
  uword *ifs[] = { cm->inside_ifs, cm->outside_ifs };
  u32 i, sw_if_index;

  for (i = 0; i < ARRAY_LEN (ifs); i++)
    clib_bitmap_foreach (sw_if_index, ifs[i])
      {
	if (vnet_get_sw_interface_or_null (vnm, sw_if_index) &&
	    !vnet_sw_interface_is_up (vnm, sw_if_index))
	  return 0;
      }
  return 1;
}

static adj_walk_rc_t
cgnat_adj_down_cb (adj_index_t ai, void *arg)
{
  if (adj_is_up (ai))
    return ADJ_WALK_RC_CONTINUE;
  *(int *) arg = 1;
  return ADJ_WALK_RC_STOP;
}

/* can VPP forward via every neighbour on the interfaces we translate on?
   A neighbour with a BFD session that isn't up is down to the FIB, so
   routes via it drop: routing glue that only enables BFD once we're
   ready leaves a gap of a BFD slow-start round or two, and a lost
   router stays down */
static int
cgnat_next_hops_up (void)
{
  cgnat_main_t *cm = &cgnat_main;
  uword *ifs[] = { cm->inside_ifs, cm->outside_ifs };
  u32 i, sw_if_index;
  int down = 0;

  for (i = 0; i < ARRAY_LEN (ifs) && !down; i++)
    clib_bitmap_foreach (sw_if_index, ifs[i])
      {
	adj_nbr_walk (sw_if_index, FIB_PROTOCOL_IP4, cgnat_adj_down_cb, &down);
	if (down)
	  break;
      }
  return !down;
}

/* evaluate liveness and readiness; runs on main each hello interval.  now
   is cgnat_clock_now(): the input node stamps on the receiving thread */
static void
cgnat_cluster_evaluate (vlib_main_t *vm, f64 now)
{
  cgnat_cluster_t *cl = &cgnat_main.cluster;
  cgnat_path_t *p;
  int starting, dup, mismatch, fence, peer_in, peer_ready;
  u32 n = 0, a = 0, b = 0;

  cl->config_hash = cgnat_config_hash ();
  if (cl->peer_epoch && cl->peer_epoch != cl->last_peer_epoch)
    {
      /* a new peer incarnation: reset sync streams on every thread; a
	 resync we were pulling from the old one starts again */
      cl->last_peer_epoch = cl->peer_epoch;
      cl->sync_gen++;
      cl->resync_done = 0;
      cl->resync_end_mask = 0;
      cl->resync_end_needed = 0;
      cl->resync_req_sent_at = 0;
    }
  cl->peer_alive = 0;
  vec_foreach (p, cl->paths)
    {
      /* alive only both ways: we hear it, and it says it hears us */
      p->alive = p->last_rx > 0 && now - p->last_rx < cl->dead_interval &&
		 p->heard_epoch == cl->epoch;
      cl->peer_alive |= p->alive;
    }
  cl->pair_alive = vec_len (cl->paths) && cl->paths[0].alive;
  cl->forwarding = cgnat_next_hops_up ();

  /* starting lasts one dead interval from when our pair-link address
     exists on an interface that has link: until then we can't hear the
     peer, so we must not conclude we're alone */
  if (!vec_len (cl->paths) || !cgnat_path_link_up (&cl->paths[0]))
    cl->enabled_at = now; /* (a VF's link comes up after its address) */
  /* ...and ends early the moment we hear the peer on the pair link
     (both ways); otherwise after a dead interval plus margin for the
     first ARP/HELLO round trips on a freshly-up link */
  starting = now - cl->enabled_at < cl->dead_interval + 1.5 &&
	     !(vec_len (cl->paths) && cl->paths[0].last_rx > 0 &&
	       now - cl->paths[0].last_rx < cl->dead_interval &&
	       cl->paths[0].heard_epoch == cl->epoch);
  dup = cl->dup_last > 0 && now - cl->dup_last < cl->dead_interval;
  mismatch = cl->peer_alive && cl->peer_config_hash != cl->config_hash;

  /* split-brain: only the pair link is down and the peer is visibly
     alive elsewhere -> the higher id stands down */
  fence = !cl->pair_alive && cl->peer_alive && cl->node_id > cl->peer_node_id;
  cl->fenced = 0;
  peer_ready = !!(cl->peer_state & CGNAT_HELLO_READY);

  /* the same peer incarnation back after a gap (fabric flap, VM pause):
     both of us served alone meanwhile, so the higher id gives way and
     resyncs from the lower before taking subscribers again */
  if (cl->peer_alive && !cl->peer_was_alive &&
      cl->peer_epoch == cl->last_peer_epoch && cl->incumbent &&
      cl->node_id > cl->peer_node_id && peer_ready)
    {
      cl->incumbent = 0;
      cl->resync_done = 0;
      cl->resync_end_mask = 0;
      cl->resync_end_needed = 0;
      cl->resync_req_sent_at = 0;
    }
  cl->peer_was_alive = cl->peer_alive;

  /* every peer thread said RESYNC_END for our current request; we then
     wait for the peer to include us before we take any subscribers */
  if (!cl->resync_done && cl->resync_end_needed &&
      cl->resync_epoch == cl->peer_epoch &&
      count_set_bits (cl->resync_end_mask) >= cl->resync_end_needed)
    {
      cl->resync_done = 1;
      cl->handover_pending = 1;
    }
  if (cl->handover_pending &&
      (!cl->peer_alive || (cl->peer_state & CGNAT_HELLO_PEER_IN_ACTIVE)))
    cl->handover_pending = 0;

  if (dup)
    {
      cl->reason = CGNAT_REASON_DUPLICATE;
      cl->ready = 0;
    }
  else if (starting)
    {
      cl->reason = CGNAT_REASON_STARTING;
      cl->ready = 0;
    }
  else if (!cgnat_data_links_up ())
    {
      /* can't forward: the peer serves everyone; once we can again we
	 pull its table before taking subscribers back */
      cl->reason = CGNAT_REASON_INTERFACE_DOWN;
      cl->ready = 0;
      cl->incumbent = 0;
      cl->resync_done = 0;
      cl->resync_end_mask = 0;
      cl->resync_end_needed = 0;
      cl->resync_req_sent_at = 0;
    }
  else if (pool_elts (cgnat_main.maps) == 0)
    {
      /* nothing to translate: never the serving node */
      cl->reason = CGNAT_REASON_UNCONFIGURED;
      cl->ready = 0;
      cl->incumbent = 0;
    }
  else if (fence)
    {
      cl->reason = CGNAT_REASON_FENCED;
      cl->ready = 0;
      cl->fenced = 1;
      /* when the link returns we resync before serving again */
      cl->incumbent = 0;
      cl->resync_done = 0;
    }
  else if (!cl->peer_alive)
    {
      cl->reason = CGNAT_REASON_ALONE;
      cl->ready = 1;
      cl->incumbent = 1;
    }
  else if (mismatch)
    {
      /* the serving node stays in routing and raises the alarm; a node
	 that isn't serving yet can't join until the configs agree */
      cl->reason = CGNAT_REASON_CONFIG_MISMATCH;
      cl->ready = cl->incumbent;
    }
  else if (cl->incumbent || cl->resync_done ||
	   (!peer_ready && cl->node_id < cl->peer_node_id))
    {
      /* serving already, or just pulled the peer's table, or both of us
	 are starting and the lower id goes first */
      cl->reason = CGNAT_REASON_NONE;
      cl->ready = 1;
      cl->incumbent = 1;
    }
  else
    {
      /* joining: pull the peer's table before taking any subscribers */
      cl->reason = CGNAT_REASON_RESYNCING;
      cl->ready = 0;
      /* (re)request only when the transfer isn't making progress */
      if (peer_ready &&
	  (cl->resync_req_sent_at == 0 ||
	   now - clib_max (cl->resync_req_sent_at, cl->last_sync_rx) >= 3.0))
	{
	  cl->resync_epoch = cl->peer_epoch;
	  cl->resync_end_mask = 0;
	  cl->resync_end_needed = 0;
	  cgnat_cluster_send_resync_req (vm);
	  cl->resync_req_sent_at = now;
	}
    }

  /* the peer lost some of our stream: ask it to send us everything */
  if (cl->ready && cl->peer_alive && cl->pair_alive &&
      (cl->peer_state & CGNAT_HELLO_WANT_RESYNC) &&
      now - cl->resync_req_sent_at >= 1.0)
    {
      cgnat_cluster_send_resync_req (vm);
      cl->resync_req_sent_at = now;
    }
  /*
   * Active set.  The peer counts only if we can reach it over the pair
   * link (that's where steered packets go) and it says it's ready.
   * Frozen while the configs disagree.
   */
  peer_in = cl->peer_alive && cl->pair_alive &&
	    (cl->peer_state & CGNAT_HELLO_READY) &&
	    !(cl->peer_state & CGNAT_HELLO_FENCED);
  if (cl->reason != CGNAT_REASON_CONFIG_MISMATCH)
    {
      if (starting || dup || cl->reason == CGNAT_REASON_UNCONFIGURED)
	n = 0;
      else if (cl->fenced)
	n = 1, a = cl->peer_node_id;
      else
	{
	  /* while our next hops are down the peer serves everyone;
	     alone, we serve what we can */
	  if (cl->ready && !cl->handover_pending &&
	      (cl->forwarding || !peer_in))
	    a = cl->node_id, n++;
	  if (peer_in)
	    {
	      if (n)
		b = cl->peer_node_id;
	      else
		a = cl->peer_node_id;
	      n++;
	    }
	}
      __atomic_store_n (&cl->active_word, n | a << 8 | b << 16,
			__ATOMIC_RELEASE);
    }
  cl->serving = (cl->active_word & 0xff) != 0;

  vlib_stats_set_gauge (cl->ready_gauge, cl->ready);
  vlib_stats_set_gauge (cl->peer_alive_gauge, cl->peer_alive);
  vlib_stats_set_gauge (cl->fenced_gauge, cl->fenced);
}

static uword
cgnat_cluster_process (vlib_main_t *vm, vlib_node_runtime_t *rt,
		       vlib_frame_t *f)
{
  cgnat_cluster_t *cl = &cgnat_main.cluster;

  while (1)
    {
      if (!cl->enabled)
	vlib_process_wait_for_event (vm);
      else
	vlib_process_wait_for_event_or_clock (vm, cl->hello_interval);
      vlib_process_get_events (vm, 0);
      if (!cl->enabled)
	continue;
      cgnat_cluster_evaluate (vm, cgnat_clock_now ());
      cgnat_cluster_send_hellos (vm);
    }
  return 0;
}

VLIB_REGISTER_NODE (cgnat_cluster_process_node) = {
  .function = cgnat_cluster_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "cgnat-cluster-process",
};

static int
path_init (cgnat_path_t *p, ip4_address_t *local, ip4_address_t *peer,
	   u32 table_id)
{
  clib_memset (p, 0, sizeof (*p));
  p->local = *local;
  p->peer = *peer;
  p->table_id = table_id;
  p->fib_index = fib_table_find_or_create_and_lock (
    FIB_PROTOCOL_IP4, table_id, cgnat_main.fib_src);
  /* the pair link is direct; probe paths may cross one router */
  p->min_ttl = vec_len (cgnat_main.cluster.paths) <= 1 ? CGNAT_PAIR_TTL :
						       CGNAT_PAIR_TTL - 1;
  return 0;
}

static void
path_free (cgnat_path_t *p)
{
  fib_table_unlock (p->fib_index, FIB_PROTOCOL_IP4, cgnat_main.fib_src);
}

int
cgnat_cluster_set (int enable, u8 node_id, ip4_address_t *local,
		   ip4_address_t *peer, u32 table_id, u16 port, u32 hello_ms,
		   u32 dead_ms, u32 refresh_s)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_cluster_t *cl = &cm->cluster;
  vlib_main_t *vm = vlib_get_main ();
  cgnat_path_t *p;

  /* validate first: a refused reconfigure leaves the running cluster be */
  if (enable &&
      (node_id == 0 || local->as_u32 == 0 || peer->as_u32 == 0 ||
       (dead_ms ? dead_ms : 500) <= (hello_ms ? hello_ms : 100)))
    return VNET_API_ERROR_INVALID_VALUE;

  if (cl->enabled)
    {
      /* reconfigure = disable then enable */
      vec_foreach (p, cl->paths)
	path_free (p);
      vec_free (cl->paths);
      udp_unregister_dst_port (vm, cl->port, 1);
      cl->enabled = 0;
      cl->ready = 0;
      cl->serving = 1;
    }
  if (!enable)
    return 0;

  if (node_id == 0 || local->as_u32 == 0 || peer->as_u32 == 0)
    return VNET_API_ERROR_INVALID_VALUE;

  cl->node_id = node_id;
  cl->port = port ? port : CGNAT_CLUSTER_PORT;
  cl->hello_interval = (hello_ms ? hello_ms : 100) * 1e-3;
  cl->dead_interval = (dead_ms ? dead_ms : 500) * 1e-3;
  cl->refresh_interval = refresh_s ? refresh_s : 10;
  if (cl->dead_interval <= cl->hello_interval)
    return VNET_API_ERROR_INVALID_VALUE;

  vec_add2 (cl->paths, p, 1);
  path_init (p, local, peer, table_id);

  cl->epoch = (u32) (clib_cpu_time_now () ^ (clib_cpu_time_now () >> 32)) | 1;
  cl->peer_node_id = 0;
  cl->peer_epoch = 0;
  cl->peer_state = 0;
  cl->dup_last = 0;
  cl->last_peer_epoch = 0;
  cl->want_resync_peer = 0;
  cl->incumbent = 0;
  cl->resync_done = 0;
  cl->resync_end_mask = 0;
  cl->resync_end_needed = 0;
  cl->resync_req_sent_at = 0;
  cl->handover_pending = 0;
  cl->peer_was_alive = 0;
  cl->last_sync_rx = 0;
  cl->resync_walk_epoch = 0;
  cl->sync_gen++;
  cl->peer_alive = cl->pair_alive = cl->ready = cl->fenced = 0;
  cl->serving = 0;
  cl->reason = CGNAT_REASON_STARTING;
  cl->enabled_at = cgnat_clock_now ();
  cl->config_hash = cgnat_config_hash ();
  udp_register_dst_port (vm, cl->port, cgnat_cluster_input_node.index, 1);
  cl->enabled = 1;
  vlib_process_signal_event (vm, cgnat_cluster_process_node.index,
			     CGNAT_CLUSTER_EVENT_CHANGED, 0);
  return 0;
}

int
cgnat_cluster_path_add_del (ip4_address_t *local, ip4_address_t *peer,
			    u32 table_id, int is_add)
{
  cgnat_cluster_t *cl = &cgnat_main.cluster;
  cgnat_path_t *p;
  u32 i;

  if (!cl->enabled)
    return VNET_API_ERROR_FEATURE_DISABLED;
  for (i = 1; i < vec_len (cl->paths); i++)
    {
      p = vec_elt_at_index (cl->paths, i);
      if (p->local.as_u32 == local->as_u32 && p->peer.as_u32 == peer->as_u32)
	{
	  if (is_add)
	    return VNET_API_ERROR_VALUE_EXIST;
	  path_free (p);
	  vec_del1 (cl->paths, i); /* path ids after it shift down */
	  return 0;
	}
    }
  if (!is_add)
    return VNET_API_ERROR_NO_SUCH_ENTRY;
  if (vec_len (cl->paths) >= 5)
    return VNET_API_ERROR_LIMIT_EXCEEDED;
  vec_add2 (cl->paths, p, 1);
  return path_init (p, local, peer, table_id);
}

static clib_error_t *
cgnat_cluster_init (vlib_main_t *vm)
{
  cgnat_cluster_t *cl = &cgnat_main.cluster;

  cl->serving = 1; /* no cluster: a lone node always translates */
  cl->window = 1024;
  cl->ready_gauge = vlib_stats_add_gauge ("/cgnat/cluster/ready");
  cl->peer_alive_gauge = vlib_stats_add_gauge ("/cgnat/cluster/peer-alive");
  cl->fenced_gauge = vlib_stats_add_gauge ("/cgnat/cluster/fenced");
  return 0;
}

VLIB_INIT_FUNCTION (cgnat_cluster_init) = {
  .runs_after = VLIB_INITS ("cgnat_init"),
};
