/* Connection table
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */
#ifndef __CONNECTION_TABLE_H
#define __CONNECTION_TABLE_H

#include <linux/hashtable.h>
#include <linux/rwlock.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/atomic.h>
#include <linux/wait.h>
#include <linux/delay.h>
#include <linux/time.h>
#include <linux/net.h>
#include <linux/inet.h>
#include <linux/jhash.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#define MAX_BUCKETS 64
#define MAX_BUCKET_BITS ilog2(MAX_BUCKETS)

typedef atomic64_t stat64_t;

typedef enum conn_op {
	GET=0,
	PUT,
	MAX_OP_TYPE
}conn_op_t;

#define CONN_STATE_ENTRIES \
	X(0, CONN_DOWN, DOWN) \
	X(1, CONN_READY, READY) \
	X(2, CONN_ACTIVE, ACTIVE) \
	X(3, CONN_FAILED, FAILED) \
	X(4, CONN_RETRY, RETRY) \
	X(5, CONN_ZOMBIE, ZOMBIE)

typedef enum conn_state {
	#define X(code, name, string) name = code,
	CONN_STATE_ENTRIES
	#undef X
}conn_state;

static inline const char *conn_state_status(enum conn_state state)
{
	switch (state) {
	#define X(code, name, string) \
	case name : return #string;
	CONN_STATE_ENTRIES
	#undef X
	default: return "illegal cacheobj_connection_node state";
	}
}

#ifdef CONFIG_CACHEOBJS_CONNPOOL // new version
struct cacheobj_connection_pool {
	const char	    *ip;
	unsigned int	    port;
        atomic_t            nr_connections;
        atomic_t            nr_ready; // updated on get/put (cacheline bouncing)
        struct list_head    conn_list;
        wait_queue_head_t   wq;
	struct hlist_node   hentry;
#ifdef CONFIG_CACHEOBJS_STATS
	stat64_t	    nr_slow_paths;
#endif
};

struct cacheobj_connection_node {
	const char		*ip;
	unsigned int            port;
	atomic_long_t	        state;
        unsigned int            nr_retry_attempts;
#ifdef CONFIG_CACHEOBJS_STATS
	ktime_t			now_ns;
	stat64_t		cum_get_ns;  // cum time for GET
	stat64_t		cum_put_ns;  // cum time for PUT
	stat64_t		cum_wait_ns; // cum wait time to grab ready conn
	stat64_t                nr_lookups;
	stat64_t		tx_bytes;
	stat64_t		rx_bytes;
#endif
	struct list_head        list_node;
	struct cacheobj_connection_pool *pool;
};
#else // older version
struct cacheobj_connection_node {
	const char		*ip;
	unsigned int		port;
	conn_state		state;
	struct mutex		lock;
        unsigned int            nr_retry_attempts;
#ifdef CONFIG_CACHEOBJS_STATS
	ktime_t			now_ns;
	stat64_t		cum_get_ns;  // cum time for GET
	stat64_t		cum_put_ns;  // cum time for PUT
	stat64_t		cum_wait_ns; // cum wait time to grab conn
	stat64_t 	        nr_slow_paths;
	stat64_t                nr_lookups;
	stat64_t		tx_bytes;
	stat64_t		rx_bytes;
#endif
	struct hlist_node	hentry;	// hash node for quick lookup
};
#endif

int cacheobj_connection_node_init(struct cacheobj_connection_node *conn,
        const char *ip, unsigned int port);
int cacheobj_connection_node_destroy(struct cacheobj_connection_node *conn);
void cacheobj_connection_node_failed(struct cacheobj_connection_node *);
void cacheobj_connection_node_retry(struct cacheobj_connection_node *);
void cacheobj_connection_node_ready(struct cacheobj_connection_node *);

struct cacheobj_conntable {
	rwlock_t		lock; // lock for the entire table. (TBD : use rcu)
	DECLARE_HASHTABLE(buckets, MAX_BUCKET_BITS);
};

/* connection table operations */
struct cacheobj_conntable_operations {
	int (*cacheobj_conntable_init) (struct cacheobj_conntable *);
	int (*cacheobj_conntable_destroy) (struct cacheobj_conntable *);
	int (*cacheobj_conntable_insert) (struct cacheobj_conntable *,
		struct cacheobj_connection_node *);
	int (*cacheobj_conntable_remove) (struct cacheobj_conntable *,
		struct cacheobj_connection_node *);
        struct cacheobj_connection_node* (*cacheobj_conntable_iter)
                (struct cacheobj_conntable *);
	struct cacheobj_connection_node* (*cacheobj_conntable_lookup)
		(struct cacheobj_conntable *, const char *ip, unsigned int port);
	struct cacheobj_connection_node* (*cacheobj_conntable_timed_get)
		(struct cacheobj_conntable *table, const char *ip,
                unsigned int port, long timeout);
	void (*cacheobj_conntable_put) (struct cacheobj_conntable *table,
		struct cacheobj_connection_node *, conn_op_t);
	void (*cacheobj_conntable_dump)
		(struct cacheobj_conntable *, struct seq_file *);
};

const extern struct cacheobj_conntable_operations cacheobj_conntable_ops;

#define CONNTBL_ASSERT(X)                                               \
do {                                                                    \
        if (unlikely(!(X))) {                                           \
                pr_err("\n");                                           \
                pr_err("CONNTBL Assertion failed\n");		        \
                BUG();                                                  \
        }                                                               \
} while (0)

#endif // header
