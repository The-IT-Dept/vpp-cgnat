/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 The vpp-cgnat authors
 */

/*
 * Session sync.  The owner of a subscriber streams upsert/delete records
 * for its sessions to the peer.  Records go to the peer thread that owns
 * the subscriber there, in per (local thread -> peer thread) streams, so
 * the receiver applies them without another handoff.  Streams are
 * sequenced; the receiver acks the highest in-order seq; the sender keeps a
 * copy of each packet until acked and retransmits (go-back-N) after
 * CGNAT_SYNC_RTO.  Records are idempotent upserts, so duplicates and
 * reordering are harmless.  A full window drops the oldest copy and asks
 * the peer for a full resync instead.
 */

#include <vnet/ip/ip4.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/fib/fib_table.h>
#include <cgnat/cgnat.h>
#include <cgnat/cgnat_session.h>
#include <cgnat/cgnat_owner.h>
#include <cgnat/cgnat_sync.h>

static cgnat_sync_tx_t *
tx_stream (cgnat_per_thread_t *t, u32 dst)
{
  u32 old = vec_len (t->sync_tx), i;
  if (dst >= old)
    {
      vec_validate (t->sync_tx, dst);
      for (i = old; i <= dst; i++)
	t->sync_tx[i].bi = ~0;
    }
  return vec_elt_at_index (t->sync_tx, dst);
}

static void
tx_flush (vlib_main_t *vm, cgnat_per_thread_t *t, cgnat_sync_tx_t *st,
	  f64 now)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_cluster_t *cl = &cm->cluster;
  vlib_buffer_t *b, *copy;
  ip4_header_t *ip;
  udp_header_t *udp;
  cgnat_msg_hdr_t *h;
  cgnat_msg_sync_t *sb;
  cgnat_sync_pending_t *pe;

  if (st->bi == ~0)
    return;
  b = vlib_get_buffer (vm, st->bi);
  ip = vlib_buffer_get_current (b);
  udp = (udp_header_t *) (ip + 1);
  h = (cgnat_msg_hdr_t *) (udp + 1);
  sb = (cgnat_msg_sync_t *) (h + 1);
  ip->length = clib_host_to_net_u16 (b->current_length);
  ip->checksum = 0;
  ip->checksum = ip4_header_checksum (ip);
  udp->length = clib_host_to_net_u16 (b->current_length - sizeof (*ip));
  sb->n_records = clib_host_to_net_u16 (st->n_records);

  /* too far behind (per stream, or copies held on this thread): give up
     on the oldest, ask the peer for a full resync instead */
  while (vec_len (st->unacked) &&
	 (vec_len (st->unacked) >= cl->window ||
	  t->sync_held >= CGNAT_SYNC_MAX_HELD))
    {
      vlib_buffer_free_one (vm, st->unacked[0].bi);
      vec_delete (st->unacked, 1, 0);
      t->sync_held--;
      cl->want_resync_peer = 1;
      vlib_increment_simple_counter (
	&cm->counters[CGNAT_COUNTER_SYNC_OVERFLOW], vm->thread_index, 0, 1);
    }
  copy = vlib_buffer_copy (vm, b);
  if (copy)
    {
      vec_add2 (st->unacked, pe, 1);
      pe->seq = clib_net_to_host_u32 (h->seq);
      pe->bi = vlib_get_buffer_index (vm, copy);
      pe->sent = now;
      t->sync_held++;
    }
  else
    cl->want_resync_peer = 1; /* can't retransmit it: the peer will skip it */
  /* the receiver may step over anything older than this */
  sb->oldest_unacked = clib_host_to_net_u32 (
    vec_len (st->unacked) ? st->unacked[0].seq : clib_net_to_host_u32 (h->seq));
  if (copy)
    {
      cgnat_msg_sync_t *csb = (cgnat_msg_sync_t *) ((u8 *) vlib_buffer_get_current (copy) +
					      ((u8 *) sb - (u8 *) ip));
      csb->oldest_unacked = sb->oldest_unacked;
    }
  cgnat_cluster_send (vm, &st->bi, 1);
  st->bi = ~0;
  st->n_records = 0;
}

static void sync_session (cgnat_per_thread_t *t, u32 thread_index,
			  cgnat_session_t *s, u8 op, int any);

void
cgnat_sync_session (cgnat_per_thread_t *t, u32 thread_index,
		    cgnat_session_t *s, u8 op)
{
  sync_session (t, thread_index, s, op, 0);
}

void
cgnat_sync_session_any (cgnat_per_thread_t *t, u32 thread_index,
			cgnat_session_t *s, u8 op)
{
  sync_session (t, thread_index, s, op, 1);
}

static void
sync_session (cgnat_per_thread_t *t, u32 thread_index, cgnat_session_t *s,
	      u8 op, int any)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_cluster_t *cl = &cm->cluster;
  vlib_main_t *vm;
  cgnat_mapping_t *m;
  cgnat_map_t *map;
  cgnat_sync_tx_t *st;
  cgnat_sync_record_t *r;
  vlib_buffer_t *b;
  u32 dst;
  f64 now;

  if (!cl->enabled || !cl->peer_alive || !cl->pair_alive)
    return;
  /* only the owning thread speaks for its sessions (not map flushes on
     main: the peer flushes its own copy of the map) */
  if (vlib_get_thread_index () != thread_index)
    return;
  m = pool_elt_at_index (t->mappings, s->mapping_index);
  map = pool_elt_at_index (cm->maps, m->map_index);
  if (!any &&
      cgnat_owner_node (map->in_table_id, m->in_addr.as_u32) != cl->node_id)
    return;

  vm = vlib_get_main ();
  now = vlib_time_now (vm);
  dst = cgnat_thread_for (map->in_table_id, m->in_addr.as_u32,
			  cl->peer_first_worker, cl->peer_n_workers);
  st = tx_stream (t, dst);
  if (st->bi == ~0)
    {
      cgnat_msg_sync_t *sb; /* oldest_unacked is filled at flush */
      if (!cgnat_cluster_alloc (vm, 0, CGNAT_MSG_SYNC, st->next_seq++,
				sizeof (*sb), (void **) &sb, &st->bi))
	{
	  st->bi = ~0;
	  return;
	}
      sb->src_thread = clib_host_to_net_u16 (thread_index);
      sb->dst_thread = clib_host_to_net_u16 (dst);
      sb->n_records = 0;
      sb->pad = 0;
      sb->oldest_unacked = 0;
    }
  b = vlib_get_buffer (vm, st->bi);
  r = vlib_buffer_get_current (b) + b->current_length;
  b->current_length += sizeof (*r);
  r->op = op;
  r->proto = m->proto;
  r->tcp_state = s->tcp_state;
  r->to_class = s->to_class;
  r->in_table_id = clib_host_to_net_u32 (map->in_table_id);
  r->in_addr = m->in_addr.as_u32;
  r->out_addr = m->out_addr.as_u32;
  r->in_port = m->in_port;
  r->out_port = m->out_port;
  r->remote_addr = s->remote_addr.as_u32;
  r->remote_port = s->remote_port;
  r->idle_ds = clib_host_to_net_u16 (
    (u16) clib_min (65535.0, (now - s->last_heard) * 10.0));
  r->pad = clib_host_to_net_u32 (s->inbound ? 1 : 0);
  s->last_synced = now;
  vlib_increment_simple_counter (
    &cm->counters[CGNAT_COUNTER_SYNC_RECORDS_OUT], thread_index, 0, 1);
  if (++st->n_records >= CGNAT_SYNC_MAX_RECORDS)
    tx_flush (vm, t, st, now);
}

static void
streams_reset (vlib_main_t *vm, cgnat_per_thread_t *t)
{
  cgnat_sync_tx_t *st;
  cgnat_sync_pending_t *pe;

  vec_foreach (st, t->sync_tx)
    {
      if (st->bi != ~0)
	vlib_buffer_free_one (vm, st->bi);
      vec_foreach (pe, st->unacked)
	vlib_buffer_free_one (vm, pe->bi);
      vec_free (st->unacked);
      t->sync_held = 0;
      st->bi = ~0;
      st->n_records = 0;
      st->next_seq = 0;
    }
  vec_reset_length (t->sync_rx);
}

/* ---------------------------------------------------------------------
 * receive side: apply records, process acks (on the target thread)
 */

#define foreach_cgnat_sync_worker_error                                       \
  _ (RECORDS, "records", "records applied")                                   \
  _ (ACKS, "acks", "acks received")                                           \
  _ (UNKNOWN_MAP, "sync-unknown-map", "record for a map we don't have")       \
  _ (CONFLICT, "sync-conflict", "record's outside port held by another flow")\
  _ (TABLE_FULL, "sync-table-full", "no room for a synced session")           \
  _ (OWNED, "sync-owned", "record for a session we own (kept ours)")          \
  _ (BAD_RECORD, "sync-bad-record", "record's public ip:port not the subscriber's block") \
  _ (FORWARDED, "sync-forwarded", "records forwarded to the owning thread")  \
  _ (BAD, "bad", "malformed sync/ack")

typedef enum
{
#define _(sym, name, desc) CGNAT_SYNC_WORKER_ERROR_##sym,
  foreach_cgnat_sync_worker_error
#undef _
    CGNAT_SYNC_WORKER_N_ERROR,
} cgnat_sync_worker_error_t;

static vlib_error_desc_t cgnat_sync_worker_error_counters[] = {
#define _(sym, n, d) { .name = n, .desc = d, .severity = VL_COUNTER_SEVERITY_INFO },
  foreach_cgnat_sync_worker_error
#undef _
};

static u32
apply_record (vlib_main_t *vm, cgnat_per_thread_t *t, u32 ti,
	      cgnat_sync_record_t *r, f64 now)
{
  ip4_address_t in = { .as_u32 = r->in_addr }, out = { .as_u32 = r->out_addr };
  cgnat_mapping_t *m, *other;
  cgnat_session_t *s;
  cgnat_map_t *map = 0;
  cgnat_sub_t *sub;
  u32 fib_index;
  int mine;

  fib_index = fib_table_find (FIB_PROTOCOL_IP4,
			      clib_net_to_host_u32 (r->in_table_id));
  if (fib_index != ~0)
    map = cgnat_map_by_inside (fib_index, &in);
  if (!map || r->proto >= CGNAT_N_PROTO || r->to_class >= CGNAT_N_TO)
    return CGNAT_SYNC_WORKER_ERROR_UNKNOWN_MAP;

  /* the public side must be exactly what the formula gives this
     subscriber: no record may claim another subscriber's ip:port */
  {
    ip4_address_t fout;
    u16 lo, hi, op = clib_net_to_host_u16 (r->out_port);
    cgnat_forward (map, &in, &fout, &lo, &hi);
    if (fout.as_u32 != out.as_u32 || op < lo || op > hi)
      return CGNAT_SYNC_WORKER_ERROR_BAD_RECORD;
  }
  /* a copy of ours that we no longer own (ownership moved) or that has
     expired belongs to the new owner's records */
  mine = cgnat_owner_node (map->in_table_id, in.as_u32) == cgnat_main.cluster.node_id;

  m = cgnat_mapping_find (t, 0, map->in_fib_index, in.as_u32, r->in_port,
			  r->proto);
  if (r->op == CGNAT_REC_DELETE)
    {
      /* a live session of ours is ours to end, not the peer's */
      if (m &&
	  (s = cgnat_session_find (t, m - t->mappings, r->remote_addr,
				   r->remote_port)) &&
	  (s->warm || !mine))
	cgnat_session_free (t, ti, s);
      return CGNAT_SYNC_WORKER_ERROR_RECORDS;
    }

  if (!m)
    {
      other = cgnat_mapping_find (t, 1, map->out_fib_index, out.as_u32,
				  r->out_port, r->proto);
      if (other)
	return CGNAT_SYNC_WORKER_ERROR_CONFLICT;
      if (cgnat_table_full (t))
	return CGNAT_SYNC_WORKER_ERROR_TABLE_FULL;
      sub = cgnat_sub_get (t, ti, map->in_fib_index, &in, 1);
      m = cgnat_mapping_create (t, ti, map, sub, &in, r->in_port, &out,
				r->out_port, r->proto);
    }
  else if (m->out_port != r->out_port || m->out_addr.as_u32 != out.as_u32)
    return CGNAT_SYNC_WORKER_ERROR_CONFLICT;

  s = cgnat_session_find (t, m - t->mappings, r->remote_addr, r->remote_port);
  if (!s)
    {
      if (cgnat_table_full (t))
	{
	  cgnat_mapping_free_if_idle (t, ti, m);
	  return CGNAT_SYNC_WORKER_ERROR_TABLE_FULL;
	}
      s = cgnat_session_create (t, ti, m, r->remote_addr, r->remote_port,
				r->to_class, now,
				clib_net_to_host_u32 (r->pad) & 1);
    }
  else if (!s->warm && mine && !cgnat_session_expired (s, now))
    return CGNAT_SYNC_WORKER_ERROR_OWNED; /* we own it: keep our state */
  s->tcp_state = r->tcp_state;
  cgnat_session_relink (t, s, r->to_class,
			now - clib_net_to_host_u16 (r->idle_ds) / 10.0, now);
  s->warm = 1;
  s->last_synced = now;
  return CGNAT_SYNC_WORKER_ERROR_RECORDS;
}

/*
 * Records whose subscriber another local thread owns (the sender's view
 * of our workers was stale) are copied into a forwarded SYNC and handed to
 * that thread.  Forwarded SYNCs don't touch stream state or acks.
 */
static void
forward_records (vlib_main_t *vm, vlib_node_runtime_t *node,
		 cgnat_msg_hdr_t *h,
		 cgnat_sync_record_t **by_thread, u32 n_threads)
{
  u32 bis[64], tis[64], n = 0, ti;
  u16 tis16[64];

  for (ti = 0; ti < n_threads && n < 64; ti++)
    {
      cgnat_sync_record_t *recs = by_thread[ti];
      vlib_buffer_t *b;
      cgnat_msg_hdr_t *fh;
      cgnat_msg_sync_t *sb;
      u32 bi, bytes;

      if (!vec_len (recs))
	continue;
      bytes = sizeof (*fh) + sizeof (*sb) + vec_len (recs) * sizeof (*recs);
      if (vlib_buffer_alloc (vm, &bi, 1) != 1)
	continue;
      b = vlib_get_buffer (vm, bi);
      b->current_data = 0;
      b->current_length = bytes;
      fh = vlib_buffer_get_current (b);
      *fh = *h;
      fh->flags |= CGNAT_MSG_F_FORWARDED;
      sb = (cgnat_msg_sync_t *) (fh + 1);
      sb->src_thread = 0;
      sb->dst_thread = clib_host_to_net_u16 (ti);
      sb->n_records = clib_host_to_net_u16 (vec_len (recs));
      sb->pad = 0;
      clib_memcpy_fast (sb + 1, recs, vec_len (recs) * sizeof (*recs));
      bis[n] = bi;
      tis[n] = ti;
      n++;
    }
  for (ti = 0; ti < n; ti++)
    tis16[ti] = tis[ti];
  if (n)
    vlib_buffer_enqueue_to_thread (vm, node, cgnat_main.fq_sync_index, bis,
				   tis16, n, 1);
}

VLIB_NODE_FN (cgnat_sync_worker_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  cgnat_main_t *cm = &cgnat_main;
  u32 ti = vm->thread_index;
  cgnat_per_thread_t *t = vec_elt_at_index (cm->per_thread, ti);
  u32 *from = vlib_frame_vector_args (frame), n = frame->n_vectors, i;
  f64 now = vlib_time_now (vm);

  for (i = 0; i < n; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, from[i]);
      cgnat_msg_hdr_t *h;
      u32 len;

      /* a SYNC that was fragmented arrives as a buffer chain */
      if (b->flags & VLIB_BUFFER_NEXT_PRESENT)
	vlib_buffer_chain_linearize (vm, b);
      h = vlib_buffer_get_current (b);
      len = b->current_length;

      if (h->type == CGNAT_MSG_SYNC && len >= sizeof (*h) + sizeof (cgnat_msg_sync_t))
	{
	  cgnat_msg_sync_t *sb = (cgnat_msg_sync_t *) (h + 1);
	  cgnat_sync_record_t *r = (cgnat_sync_record_t *) (sb + 1);
	  u32 nr = clib_net_to_host_u16 (sb->n_records), k;
	  u32 src = clib_net_to_host_u16 (sb->src_thread);
	  u32 seq = clib_net_to_host_u32 (h->seq);
	  u32 epoch = clib_net_to_host_u32 (h->epoch);
	  cgnat_sync_rx_t *rx;
	  cgnat_sync_record_t **strays = 0;
	  int n_strays = 0;

	  if (len < sizeof (*h) + sizeof (*sb) + nr * sizeof (*r) || src > 1024)
	    {
	      vlib_node_increment_counter (vm, node->node_index,
					   CGNAT_SYNC_WORKER_ERROR_BAD, 1);
	      continue;
	    }
	  if (!(h->flags & CGNAT_MSG_F_FORWARDED))
	    {
	      u32 oldest = clib_net_to_host_u32 (sb->oldest_unacked);
	      int in_order;

	      vec_validate (t->sync_rx, src);
	      rx = vec_elt_at_index (t->sync_rx, src);
	      if (rx->epoch != epoch)
		{
		  rx->epoch = epoch;
		  rx->expected = 0;
		}
	      /* the sender gave up on everything before oldest */
	      if ((i32) (oldest - rx->expected) > 0)
		rx->expected = oldest;
	      rx->ack_pending = 1;
	      /* strictly in order: an old retransmit or a packet after a gap
		 is not applied (go-back-N resends it in order) */
	      in_order = seq == rx->expected;
	      if (!in_order)
		continue;
	      rx->expected++;
	      cgnat_main.cluster.last_sync_rx = now;
	    }
	  for (k = 0; k < nr; k++)
	    {
	      u32 owner = cgnat_thread_for (
		clib_net_to_host_u32 (r[k].in_table_id), r[k].in_addr,
		cm->first_worker_index, cm->n_workers);
	      if (owner != ti)
		{
		  vec_validate (strays, vlib_get_n_threads () - 1);
		  vec_add1 (strays[owner], r[k]);
		  n_strays++;
		  continue;
		}
	      vlib_node_increment_counter (vm, node->node_index,
					   apply_record (vm, t, ti, r + k, now),
					   1);
	    }
	  if (n_strays)
	    {
	      u32 x;
	      forward_records (vm, node, h, strays, vec_len (strays));
	      vlib_node_increment_counter (vm, node->node_index,
					   CGNAT_SYNC_WORKER_ERROR_FORWARDED,
					   n_strays);
	      vec_foreach_index (x, strays)
		vec_free (strays[x]);
	      vec_free (strays);
	    }
	  if (!(h->flags & CGNAT_MSG_F_FORWARDED))
	    vlib_increment_simple_counter (
	      &cm->counters[CGNAT_COUNTER_SYNC_RECORDS_IN], ti, 0, nr);
	}
      else if (h->type == CGNAT_MSG_ACK && len >= sizeof (*h) + sizeof (cgnat_msg_ack_t))
	{
	  cgnat_msg_ack_t *ab = (cgnat_msg_ack_t *) (h + 1);
	  u32 dst = clib_net_to_host_u16 (ab->dst_thread);
	  u32 acked = clib_net_to_host_u32 (h->seq);
	  cgnat_sync_tx_t *st;
	  u32 k = 0;

	  vlib_node_increment_counter (vm, node->node_index,
				       CGNAT_SYNC_WORKER_ERROR_ACKS, 1);
	  if (dst >= vec_len (t->sync_tx) ||
	      clib_net_to_host_u32 (h->epoch) != cm->cluster.peer_epoch)
	    continue;
	  st = vec_elt_at_index (t->sync_tx, dst);
	  while (k < vec_len (st->unacked) &&
		 (i32) (st->unacked[k].seq - acked) <= 0)
	    vlib_buffer_free_one (vm, st->unacked[k++].bi);
	  if (k)
	    {
	      vec_delete (st->unacked, k, 0);
	      t->sync_held -= k;
	    }
	}
      else
	vlib_node_increment_counter (vm, node->node_index,
				     CGNAT_SYNC_WORKER_ERROR_BAD, 1);
    }
  vlib_buffer_free (vm, from, n);
  return n;
}

VLIB_REGISTER_NODE (cgnat_sync_worker_node) = {
  .name = "cgnat-sync-worker",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = CGNAT_SYNC_WORKER_N_ERROR,
  .error_counters = cgnat_sync_worker_error_counters,
};

/* ---------------------------------------------------------------------
 * per-thread tick: flush partial batches, retransmit, send acks
 */

static void
send_ack (vlib_main_t *vm, u32 src_thread, u32 dst_thread, u32 seq)
{
  cgnat_msg_ack_t *ab;
  u32 bi;

  if (!cgnat_cluster_alloc (vm, 0, CGNAT_MSG_ACK, seq, sizeof (*ab),
			    (void **) &ab, &bi))
    return;
  ab->src_thread = clib_host_to_net_u16 (src_thread);
  ab->dst_thread = clib_host_to_net_u16 (dst_thread);
  ab->pad = 0;
  cgnat_cluster_send (vm, &bi, 1);
}

VLIB_NODE_FN (cgnat_sync_flush_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_cluster_t *cl = &cm->cluster;
  u32 ti = vm->thread_index;
  cgnat_per_thread_t *t = vec_elt_at_index (cm->per_thread, ti);
  f64 now = vlib_time_now (vm);
  cgnat_sync_tx_t *st;
  cgnat_sync_rx_t *rx;

  if (!cl->enabled)
    return 0;
  if (t->sync_gen != cl->sync_gen)
    {
      /* the peer restarted: its view of our streams is gone */
      streams_reset (vm, t);
      t->sync_gen = cl->sync_gen;
    }
  vec_foreach (st, t->sync_tx)
    {
      cgnat_sync_pending_t *pe;

      tx_flush (vm, t, st, now);
      if (!cl->pair_alive)
	continue;
      vec_foreach (pe, st->unacked)
	{
	  vlib_buffer_t *copy;
	  u32 bi;

	  if (now - pe->sent < CGNAT_SYNC_RTO)
	    continue;
	  copy = vlib_buffer_copy (vm, vlib_get_buffer (vm, pe->bi));
	  if (!copy)
	    break;
	  bi = vlib_get_buffer_index (vm, copy);
	  cgnat_cluster_send (vm, &bi, 1);
	  pe->sent = now;
	  vlib_increment_simple_counter (
	    &cm->counters[CGNAT_COUNTER_SYNC_RETRANSMITS], ti, 0, 1);
	}
    }
  vec_foreach (rx, t->sync_rx)
    {
      if (!rx->ack_pending || rx->expected == 0)
	continue;
      send_ack (vm, rx - t->sync_rx, ti, rx->expected - 1);
      rx->ack_pending = 0;
    }

  /* the peer asked for our whole table: walk it in slices */
  if (t->resync_walk_gen !=
      __atomic_load_n (&cl->resync_walk_gen, __ATOMIC_ACQUIRE))
    {
      t->resync_walk_gen = cl->resync_walk_gen;
      t->resync_cursor = 0;
      t->resync_active = 1;
    }
  if (t->resync_active)
    {
      u32 n = 0, end = vec_len (t->sessions_pool);

      /* give up if the peer dies mid-walk.  The request itself shows it
	 was there: right after it comes back our liveness may not have
	 caught up yet, and dropping that walk stalls its join */
      if ((!cl->peer_alive || !cl->pair_alive) &&
	  now - cl->resync_walk_started > cl->dead_interval)
	t->resync_active = 0;
      while (t->resync_active && t->resync_cursor < end &&
	     n < CGNAT_RESYNC_SLICE)
	{
	  u32 i = t->resync_cursor++;
	  if (pool_is_free_index (t->sessions_pool, i))
	    continue;
	  cgnat_sync_session_any (t, ti, pool_elt_at_index (t->sessions_pool, i),
				  CGNAT_REC_UPSERT);
	  n++;
	}
      if (t->resync_active && t->resync_cursor >= end)
	{
	  cgnat_msg_resync_end_t *eb;
	  u32 bi;

	  vec_foreach (st, t->sync_tx)
	    tx_flush (vm, t, st, now);
	  if (cgnat_cluster_alloc (vm, 0, CGNAT_MSG_RESYNC_END, 0,
				   sizeof (*eb), (void **) &eb, &bi))
	    {
	      eb->src_thread = clib_host_to_net_u16 (ti);
	      eb->n_src_threads = clib_host_to_net_u16 (vlib_get_n_threads ());
	      cgnat_cluster_send (vm, &bi, 1);
	    }
	  t->resync_active = 0;
	}
    }
  return 0;
}

VLIB_REGISTER_NODE (cgnat_sync_flush_node) = {
  .name = "cgnat-sync-flush",
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_INTERRUPT,
};

#ifndef CLIB_MARCH_VARIANT
static uword
cgnat_sync_process (vlib_main_t *vm, vlib_node_runtime_t *rt,
		    vlib_frame_t *f)
{
  cgnat_cluster_t *cl = &cgnat_main.cluster;

  while (1)
    {
      u32 ti;
      vlib_process_wait_for_event_or_clock (vm, CGNAT_SYNC_TICK);
      vlib_process_get_events (vm, 0);
      if (!cl->enabled)
	continue;
      for (ti = 0; ti < vlib_get_n_threads (); ti++)
	vlib_node_set_interrupt_pending (vlib_get_main_by_index (ti),
					 cgnat_sync_flush_node.index);
    }
  return 0;
}

VLIB_REGISTER_NODE (cgnat_sync_process_node) = {
  .function = cgnat_sync_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "cgnat-sync-process",
};
#endif
