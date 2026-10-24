/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 The vpp-cgnat authors
 */

/*
 * Pair protocol: UDP (default port 6200), network byte order.  Every
 * message starts with cgnat_msg_hdr_t.
 */

#ifndef included_cgnat_proto_h
#define included_cgnat_proto_h

#include <vppinfra/clib.h>

#define CGNAT_PROTO_VERSION  1
#define CGNAT_CLUSTER_PORT   6200

typedef enum
{
  CGNAT_MSG_HELLO = 1,
  CGNAT_MSG_STEER = 2,
  CGNAT_MSG_SYNC = 3,
  CGNAT_MSG_ACK = 4,
  CGNAT_MSG_RESYNC_REQ = 5,
  CGNAT_MSG_RESYNC_END = 6,
} cgnat_msg_type_t;

typedef CLIB_PACKED (struct {
  u8 version;
  u8 type;
  u8 flags;
  u8 node_id;
  u32 config_hash;
  u32 epoch; /* random per boot / enable */
  u32 seq;   /* SYNC: stream seq; ACK: highest contiguous seq */
}) cgnat_msg_hdr_t;

#define CGNAT_HELLO_READY	   (1 << 0)
#define CGNAT_HELLO_FENCED	   (1 << 1)
#define CGNAT_HELLO_WANT_RESYNC	   (1 << 2)
#define CGNAT_HELLO_PEER_IN_ACTIVE (1 << 3) /* my active set includes you */

typedef CLIB_PACKED (struct {
  u8 path_id;
  u8 state;
  u16 n_workers;
  u16 first_worker;
  u16 pad;
  u32 heard_epoch; /* the epoch I last heard from you on this path */
}) cgnat_msg_hello_t;

/* every pair message is sent with TTL 255 and checked on receipt (GTSM) */
#define CGNAT_PAIR_TTL 255

typedef enum
{
  CGNAT_STEER_IN2OUT = 0,
  CGNAT_STEER_OUT2IN = 1,
  CGNAT_STEER_HAIRPIN = 2,
} cgnat_steer_dir_t;

#define CGNAT_STEER_NON_FIRST_FRAG (1 << 0)
#define CGNAT_STEER_TRUNCATED	   (1 << 1)

/*
 * The steered packet's shallow-reassembly metadata travels with it: the
 * receiving node's reassembly ran on the outer packet, and a non-first
 * fragment carries no ports of its own.
 */
typedef CLIB_PACKED (struct {
  u8 direction;
  u8 reass_flags;	     /* CGNAT_STEER_* */
  u8 icmp_type_or_tcp_flags;
  u8 pad;
  u32 table_id;		     /* table of the fib the packet was in */
  u16 l4_src_port;	     /* network order, as sv-reass reports them */
  u16 l4_dst_port;
}) cgnat_msg_steer_t;

typedef CLIB_PACKED (struct {
  u16 src_thread;
  u16 dst_thread;
  u16 n_records;
  u16 pad;
  u32 oldest_unacked; /* seqs before this were given up on: skip them */
}) cgnat_msg_sync_t;

/* header flags (local use): records forwarded between our own threads */
#define CGNAT_MSG_F_FORWARDED (1 << 0)

#define CGNAT_REC_UPSERT 1
#define CGNAT_REC_DELETE 2

/* addresses and ports are carried exactly as in the packet (network order) */
typedef CLIB_PACKED (struct {
  u8 op;
  u8 proto;
  u8 tcp_state;
  u8 to_class;
  u32 in_table_id;
  u32 in_addr;
  u32 out_addr;
  u16 in_port;
  u16 out_port;
  u32 remote_addr;
  u16 remote_port;
  u16 idle_ds;
  u32 pad;
}) cgnat_sync_record_t;

typedef CLIB_PACKED (struct {
  u16 src_thread;
  u16 dst_thread;
  u32 pad;
}) cgnat_msg_ack_t;

typedef CLIB_PACKED (struct {
  u16 src_thread;
  u16 n_src_threads;
}) cgnat_msg_resync_end_t;

STATIC_ASSERT_SIZEOF (cgnat_msg_hdr_t, 16);
STATIC_ASSERT_SIZEOF (cgnat_sync_record_t, 32);

#endif /* included_cgnat_proto_h */
