/* Connection table
 *
 * Saptarshi Sen, Copyright (C) 2018
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
#include <linux/mutex.h>
#include <linux/wait.h>
#include <linux/delay.h>
#include <linux/time.h>

#define MAX_BUCKETS 128
#define MAX_BUCKET_BITS ilog2(MAX_BUCKETS)

typedef atomic64_t stat64_t;

struct cacheobj_conntable_pool {
	const char		*ip;
	unsigned int		port;
	u32			key; // cache hash key
        wait_queue_head_t       wq;
	atomic_t		upref; // protect pool
        atomic_t                nr_connections;
        atomic_t                nr_idle_connections;
	stat64_t		nr_waits;
        struct list_head        conn_list;
	struct hlist_node	hentry;
};

typedef enum conn_state {
	CONN_DOWN=0,
	CONN_READY,
	CONN_ACTIVE,
	CONN_FAILED,
	CONN_ZOMBIE,
        CONN_LOCKED,
	CONN_MAX_NET_STATE
}conn_state;

/* connection table node definition with pool */
struct cacheobj_conntable_node {
	const char			*ip;
	unsigned int			port;
	conn_state			state;
	stat64_t			nr_lookups;
	unsigned long			flags;
	struct list_head		list_node;
	struct cacheobj_conntable_pool	*pool;
};

int cacheobj_conntable_node_init(struct cacheobj_conntable_node *conn,
	const char *ip, unsigned int port);

int cacheobj_conntable_node_destroy(struct cacheobj_conntable_node *conn);

/* connection table */
struct cacheobj_conntable {
	rwlock_t		lock; // lock for the entire table. (TBD : use rcu)
	DECLARE_HASHTABLE(buckets, MAX_BUCKET_BITS);
};

/* connection table operations */

struct cacheobj_conntable_operations {
	struct cacheobj_conntable* (*cacheobj_conntable_init) (void);
	int (*cacheobj_conntable_destroy) (struct cacheobj_conntable *);
	int (*cacheobj_conntable_insert) (struct cacheobj_conntable *,
		struct cacheobj_conntable_node *);
	int (*cacheobj_conntable_remove) (struct cacheobj_conntable *,
		struct cacheobj_conntable_node *);
	struct cacheobj_conntable_node* (*cacheobj_conntable_peek)
		(struct cacheobj_conntable *, const char *ip, unsigned int port);
	struct cacheobj_conntable_node* (*cacheobj_conntable_timed_get)
		(struct cacheobj_conntable *table, const char *ip, unsigned int port,
		long timeout);
	void (*cacheobj_conntable_put) (struct cacheobj_conntable *table,
		struct cacheobj_conntable_node *);
	void (*cacheobj_conntable_distribution_dump)
		(struct cacheobj_conntable *);
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
