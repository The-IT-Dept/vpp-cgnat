/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 The vpp-cgnat authors
 */

#include <cgnat/cgnat.h>
#include <cgnat/cgnat_session.h>

cgnat_sub_t *
cgnat_sub_get (cgnat_per_thread_t *t, u32 thread_index, u32 in_fib_index,
	       ip4_address_t *in_addr, int create)
{
  clib_bihash_kv_8_8_t kv;
  cgnat_sub_t *sub;

  kv.key = (u64) in_fib_index << 32 | in_addr->as_u32;
  if (!clib_bihash_search_8_8 (&t->subs, &kv, &kv))
    return pool_elt_at_index (t->subs_pool, kv.value);
  if (!create)
    return 0;
  pool_get_zero (t->subs_pool, sub);
  sub->in_addr = *in_addr;
  sub->in_fib_index = in_fib_index;
  kv.value = sub - t->subs_pool;
  clib_bihash_add_del_8_8 (&t->subs, &kv, 1);
  return sub;
}

void
cgnat_sub_put_if_idle (cgnat_per_thread_t *t, u32 thread_index,
		       cgnat_sub_t *sub)
{
  clib_bihash_kv_8_8_t kv;

  if (sub->n_mappings)
    return;
  kv.key = (u64) sub->in_fib_index << 32 | sub->in_addr.as_u32;
  clib_bihash_add_del_8_8 (&t->subs, &kv, 0);
  pool_put (t->subs_pool, sub);
}

u16
cgnat_pick_port (cgnat_per_thread_t *t, u32 out_fib_index,
		 ip4_address_t *out, u16 lo, u16 hi, u16 in_port, u8 proto)
{
  clib_bihash_kv_16_8_t kv;
  u32 n = (u32) hi - lo + 1, i;

  /* det44's first choice, then probe linearly within the block */
  for (i = 0; i < n; i++)
    {
      u16 port = lo + ((u32) in_port + i) % n;
      cgnat_mapping_kv (&kv, out_fib_index, out->as_u32,
			clib_host_to_net_u16 (port), proto);
      if (clib_bihash_search_inline_16_8 (&t->out2in, &kv))
	return port;
    }
  return 0;
}

cgnat_mapping_t *
cgnat_mapping_create (cgnat_per_thread_t *t, u32 thread_index,
		      cgnat_map_t *map, cgnat_sub_t *sub,
		      ip4_address_t *in_addr, u16 in_port,
		      ip4_address_t *out_addr, u16 out_port, u8 proto)
{
  cgnat_main_t *cm = &cgnat_main;
  clib_bihash_kv_16_8_t kv;
  cgnat_mapping_t *m;

  pool_get_zero (t->mappings, m);
  m->in_addr = *in_addr;
  m->out_addr = *out_addr;
  m->in_fib_index = map->in_fib_index;
  m->out_fib_index = map->out_fib_index;
  m->in_port = in_port;
  m->out_port = out_port;
  m->proto = proto;
  m->map_index = map - cm->maps;
  m->sub_index = sub - t->subs_pool;
  sub->n_mappings++;

  cgnat_mapping_kv (&kv, m->in_fib_index, in_addr->as_u32, in_port, proto);
  kv.value = m - t->mappings;
  clib_bihash_add_del_16_8 (&t->in2out, &kv, 1);
  cgnat_mapping_kv (&kv, m->out_fib_index, out_addr->as_u32, out_port,
		    proto);
  kv.value = m - t->mappings;
  clib_bihash_add_del_16_8 (&t->out2in, &kv, 1);
  return m;
}

void
cgnat_mapping_free_if_idle (cgnat_per_thread_t *t, u32 thread_index,
			    cgnat_mapping_t *m)
{
  clib_bihash_kv_16_8_t kv;
  cgnat_sub_t *sub;

  if (m->n_sessions)
    return;
  cgnat_mapping_kv (&kv, m->in_fib_index, m->in_addr.as_u32, m->in_port,
		    m->proto);
  clib_bihash_add_del_16_8 (&t->in2out, &kv, 0);
  cgnat_mapping_kv (&kv, m->out_fib_index, m->out_addr.as_u32, m->out_port,
		    m->proto);
  clib_bihash_add_del_16_8 (&t->out2in, &kv, 0);
  sub = pool_elt_at_index (t->subs_pool, m->sub_index);
  sub->n_mappings--;
  pool_put (t->mappings, m);
  cgnat_sub_put_if_idle (t, thread_index, sub);
}

static void
adf_ref (cgnat_per_thread_t *t, u32 mapping_index, u32 raddr, int delta)
{
  clib_bihash_kv_8_8_t kv;

  kv.key = (u64) mapping_index << 32 | raddr;
  if (clib_bihash_search_8_8 (&t->adf, &kv, &kv))
    kv.value = 0;
  kv.value += delta;
  clib_bihash_add_del_8_8 (&t->adf, &kv, kv.value != 0);
}

cgnat_session_t *
cgnat_session_create (cgnat_per_thread_t *t, u32 thread_index,
		      cgnat_mapping_t *m, u32 raddr, u16 rport, u8 to_class,
		      f64 now)
{
  clib_bihash_kv_16_8_t kv;
  cgnat_session_t *s;
  dlist_elt_t *e;
  u32 mi = m - t->mappings;

  pool_get_zero (t->sessions_pool, s);
  s->mapping_index = mi;
  s->remote_addr.as_u32 = raddr;
  s->remote_port = rport;
  s->to_class = to_class;
  s->last_heard = now;

  pool_get (t->lru_pool, e);
  s->lru_index = e - t->lru_pool;
  e->value = s - t->sessions_pool;
  clib_dlist_addtail (t->lru_pool, t->lru_head[to_class], s->lru_index);

  cgnat_session_kv (&kv, mi, raddr, rport);
  kv.value = s - t->sessions_pool;
  clib_bihash_add_del_16_8 (&t->sessions, &kv, 1);
  adf_ref (t, mi, raddr, 1);

  m->n_sessions++;
  pool_elt_at_index (t->subs_pool, m->sub_index)->n_sessions++;
  return s;
}

void
cgnat_session_free (cgnat_per_thread_t *t, u32 thread_index,
		    cgnat_session_t *s)
{
  clib_bihash_kv_16_8_t kv;
  cgnat_mapping_t *m = pool_elt_at_index (t->mappings, s->mapping_index);

  cgnat_session_kv (&kv, s->mapping_index, s->remote_addr.as_u32,
		    s->remote_port);
  clib_bihash_add_del_16_8 (&t->sessions, &kv, 0);
  adf_ref (t, s->mapping_index, s->remote_addr.as_u32, -1);
  clib_dlist_remove (t->lru_pool, s->lru_index);
  pool_put_index (t->lru_pool, s->lru_index);
  pool_put (t->sessions_pool, s);

  m->n_sessions--;
  pool_elt_at_index (t->subs_pool, m->sub_index)->n_sessions--;
  cgnat_mapping_free_if_idle (t, thread_index, m);
}

void
cgnat_per_thread_init (cgnat_per_thread_t *t)
{
  dlist_elt_t *head;
  int i;

  clib_bihash_init_16_8 (&t->in2out, "cgnat in2out", 64 << 10, 256 << 20);
  clib_bihash_init_16_8 (&t->out2in, "cgnat out2in", 64 << 10, 256 << 20);
  clib_bihash_init_16_8 (&t->sessions, "cgnat sessions", 256 << 10,
			 512 << 20);
  clib_bihash_init_8_8 (&t->subs, "cgnat subscribers", 16 << 10, 64 << 20);
  clib_bihash_init_8_8 (&t->adf, "cgnat filter", 256 << 10, 256 << 20);
  for (i = 0; i < CGNAT_N_TO; i++)
    {
      pool_get (t->lru_pool, head);
      t->lru_head[i] = head - t->lru_pool;
      clib_dlist_init (t->lru_pool, t->lru_head[i]);
    }
}
