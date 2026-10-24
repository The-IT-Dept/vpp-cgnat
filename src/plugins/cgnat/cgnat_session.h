/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 The vpp-cgnat authors
 */

#ifndef included_cgnat_session_h
#define included_cgnat_session_h

#include <cgnat/cgnat.h>

static_always_inline void
cgnat_mapping_kv (clib_bihash_kv_16_8_t *kv, u32 fib_index, u32 addr,
		  u16 port, u8 proto)
{
  kv->key[0] = (u64) fib_index << 32 | addr;
  kv->key[1] = (u64) port << 8 | proto;
  kv->value = ~0ULL;
}

static_always_inline void
cgnat_session_kv (clib_bihash_kv_16_8_t *kv, u32 mapping_index, u32 raddr,
		  u16 rport)
{
  kv->key[0] = (u64) mapping_index << 32 | raddr;
  kv->key[1] = rport;
  kv->value = ~0ULL;
}

static_always_inline cgnat_mapping_t *
cgnat_mapping_find (cgnat_per_thread_t *t, int outside, u32 fib_index,
		    u32 addr, u16 port, u8 proto)
{
  clib_bihash_kv_16_8_t kv;

  cgnat_mapping_kv (&kv, fib_index, addr, port, proto);
  if (clib_bihash_search_inline_16_8 (outside ? &t->out2in : &t->in2out,
				      &kv))
    return 0;
  return pool_elt_at_index (t->mappings, kv.value);
}

static_always_inline cgnat_session_t *
cgnat_session_find (cgnat_per_thread_t *t, u32 mapping_index, u32 raddr,
		    u16 rport)
{
  clib_bihash_kv_16_8_t kv;

  cgnat_session_kv (&kv, mapping_index, raddr, rport);
  if (clib_bihash_search_inline_16_8 (&t->sessions, &kv))
    return 0;
  return pool_elt_at_index (t->sessions_pool, kv.value);
}

/* has the mapping any session with this remote address? */
static_always_inline int
cgnat_adf_allows (cgnat_per_thread_t *t, u32 mapping_index, u32 raddr)
{
  clib_bihash_kv_8_8_t kv;

  kv.key = (u64) mapping_index << 32 | raddr;
  return clib_bihash_search_inline_8_8 (&t->adf, &kv) == 0;
}

/* move the session to the tail of its timeout class list */
static_always_inline void
cgnat_session_touch (cgnat_per_thread_t *t, cgnat_session_t *s, u8 to_class,
		     f64 now)
{
  s->last_heard = now;
  clib_dlist_remove (t->lru_pool, s->lru_index);
  s->to_class = to_class;
  clib_dlist_addtail (t->lru_pool, t->lru_head[to_class], s->lru_index);
}

cgnat_sub_t *cgnat_sub_get (cgnat_per_thread_t *t, u32 thread_index,
			    u32 in_fib_index, ip4_address_t *in_addr,
			    int create);
void cgnat_sub_put_if_idle (cgnat_per_thread_t *t, u32 thread_index,
			    cgnat_sub_t *sub);

/* host-order port in [lo, hi] free for (out fib, out addr, proto), or 0 */
u16 cgnat_pick_port (cgnat_per_thread_t *t, u32 out_fib_index,
		     ip4_address_t *out, u16 lo, u16 hi, u16 in_port, u8 proto);

cgnat_mapping_t *cgnat_mapping_create (cgnat_per_thread_t *t,
				       u32 thread_index, cgnat_map_t *map,
				       cgnat_sub_t *sub, ip4_address_t *in_addr,
				       u16 in_port, ip4_address_t *out_addr,
				       u16 out_port, u8 proto);

cgnat_session_t *cgnat_session_create (cgnat_per_thread_t *t,
				       u32 thread_index,
				       cgnat_mapping_t *mapping, u32 raddr,
				       u16 rport, u8 to_class, f64 now,
				       int inbound);

/* has the session been idle past its timeout? (walker may not have run) */
static_always_inline int
cgnat_session_expired (cgnat_session_t *s, f64 now)
{
  return now - s->last_heard >= cgnat_main.timeouts[s->to_class];
}

/* room for one more session on this thread / for this subscriber? */
static_always_inline int
cgnat_table_full (cgnat_per_thread_t *t)
{
  return pool_elts (t->sessions_pool) >= cgnat_main.max_sessions_per_thread;
}

static_always_inline int
cgnat_sub_full (cgnat_sub_t *sub, int inbound)
{
  cgnat_main_t *cm = &cgnat_main;
  if (inbound)
    return sub->n_inbound >= cm->inbound_sessions_per_sub;
  return sub->n_sessions - sub->n_inbound >= cm->sessions_per_sub;
}

/* frees the session, and its mapping and subscriber when they go idle */
void cgnat_session_free (cgnat_per_thread_t *t, u32 thread_index,
			 cgnat_session_t *s);
void cgnat_mapping_free_if_idle (cgnat_per_thread_t *t, u32 thread_index,
				 cgnat_mapping_t *mapping);

void cgnat_per_thread_init (cgnat_per_thread_t *t);

#endif /* included_cgnat_session_h */
