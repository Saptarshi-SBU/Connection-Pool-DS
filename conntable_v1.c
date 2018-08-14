/* Connection table core operations
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */
#include <linux/string.h>
#include <linux/cache.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/sched.h>

#include "conntable.h"
#include "stat.h"

#if !defined(CONFIG_CACHEOBJS_CONNPOOL)

/*
 * Ref : https://www.kfki.hu/~kadlec/sw/netfilter/ct3/
 *
 * We can probably replace this with murmash hash which takes lesser
 * cpu cyles. But could not find an existing kernel implementation.
 */
static inline u32 hashfn(__be32 daddr, __be32 port)
{
	static u32 hash_seed __read_mostly;

	net_get_random_once(&hash_seed, sizeof(hash_seed));
	return jhash_2words((__force u32) daddr, (__force u32) port, hash_seed);
}

/*
 * Convert ipv4 from literal to binary representation and compute hash
 * @ip   : (input)  ip address (parse will fail if ip is fed with hostnames)
 * @port : (input)  port
 * @*key : (output) contains computed hash value
 *
 * TBD   : perform ip conversion outside of core table operations
 */
static inline int ipv4_hash32(const unsigned char *ip, unsigned int port, u32 *key)
{
	__be32 daddr = 0;

	if (ip && (in4_pton(ip, strlen(ip), (u8 *)&daddr, '\0', NULL) == 1)) {
		*key = hashfn(daddr, (__be32) port);
		return 0;
	} else {
		pr_err("ipv4_hash32 error: null or invalid ip-tuple\n");
		return -EINVAL;
	}
}

/*
 * connection node reset stats
 */
static inline
void connection_node_reset_stats(struct cacheobj_connection_node *connp)
{
	cacheobjects_stat64_reset(&connp->nr_lookups);
	cacheobjects_stat64_reset(&connp->tot_js_get);
	cacheobjects_stat64_reset(&connp->tot_js_put);
	cacheobjects_stat64_reset(&connp->tot_js_wait);
	cacheobjects_stat64_reset(&connp->tx_bytes);
	cacheobjects_stat64_reset(&connp->rx_bytes);
}

/*
 * connection node stat for jiffies
 */
static inline
void connection_node_update_jiffies(struct cacheobj_connection_node *connp,
        conn_op_t op)
{
	switch (op) {
	case GET:
		cacheobjects_stat64_add(jiffies_now() - connp->now_js,
			&connp->tot_js_get);
		break;
	case PUT:
		cacheobjects_stat64_add(jiffies_now() - connp->now_js,
			&connp->tot_js_put);
		break;
	default:
		CONNTBL_ASSERT(0);
	}
}

/*
 * connection node initialization
 */
inline int cacheobj_connection_node_init(struct cacheobj_connection_node *connp,
        const char *ip,	unsigned int port)
{
	connp->ip = kstrdup(ip, GFP_KERNEL);
	if (!connp->ip) {
		pr_err("failed to allocate ip string\n");
		return -ENOMEM;
	}
	connp->port = port;
	mutex_init(&connp->lock);
	INIT_HLIST_NODE(&connp->hentry);
        connection_node_reset_stats(connp);
	return 0;
}

/*
 * check and release any reosurces associated with connection node.
 * TBD : currently node is not allocated in net_connection, so probably
 * we need to add a free when we change the net_connection definition.
 */
inline
int cacheobj_connection_node_destroy(struct cacheobj_connection_node *connp)
{
	if (connp->state == CONN_FAILED) {
		CONNTBL_ASSERT(atomic64_read(&connp->nr_waits_pend) == 0);
		CONNTBL_ASSERT(!mutex_is_locked(&connp->lock));
	} else if (mutex_is_locked(&connp->lock)) {
		pr_err("entry is locked, cannot destroy!!!\n");
		return -EBUSY;
	}

	kfree(connp->ip);
	mutex_destroy(&connp->lock);
	return 0;
}

/*
 * Move the connection to failed state
 */
inline
void cacheobj_connection_node_failed(struct cacheobj_connection_node *connp)
{
	// resource must be locked
	if (connp->state == CONN_ACTIVE) {
		CONNTBL_ASSERT(mutex_is_locked(&connp->lock));
		connp->state = CONN_FAILED;
		mutex_unlock(&connp->lock);
	} else {
		CONNTBL_ASSERT(connp->state == CONN_RETRY);
		CONNTBL_ASSERT(mutex_is_locked(&connp->lock));
		connp->state = CONN_FAILED;
		mutex_unlock(&connp->lock);
	}
}

/*
 * Move the connection to retry state
 */
inline
void cacheobj_connection_node_retry(struct cacheobj_connection_node *connp)
{
	mutex_lock(&connp->lock);
	connp->state = CONN_RETRY;
}

/*
 * Move the connection to ready state
 */
inline
void cacheobj_connection_node_ready(struct cacheobj_connection_node *connp)
{
	if (connp->state == CONN_RETRY) {
		CONNTBL_ASSERT(mutex_is_locked(&connp->lock));
		connp->state = CONN_READY;
		mutex_unlock(&connp->lock);
	}
}


/*
 * initialize conn table and associated lock for protection
 */
static int connection_hashtable_init(struct cacheobj_conntable* table)
{
	hash_init(table->buckets);
	rwlock_init(&table->lock);
	return 0;
}

/*
 * insert entry in table, not protected
 */
static inline void __connection_insert(struct cacheobj_conntable *table,
        struct cacheobj_connection_node *connp, u32 key)
{
	hash_add(table->buckets, &connp->hentry, key);
}

/*
 * insert entry in table, protected
 */
static int connection_hashtable_insert(struct cacheobj_conntable *table,
	struct cacheobj_connection_node *connp)
{
	u32 key = 0;

	if (ipv4_hash32(connp->ip, connp->port, &key) < 0)
		return -EINVAL;

	write_lock(&table->lock);
	connp->state = CONN_READY;
	__connection_insert(table, connp, key);
	write_unlock(&table->lock);
	return 0;
}

/*
 * remove entry from table, not protected
 * returns -ENOENT on entry no longer part of table
 */
static inline int __connection_remove(struct cacheobj_conntable *table,
	struct cacheobj_connection_node *connp)
{
	struct hlist_node *hentry = &connp->hentry;

	if (!hash_hashed(hentry)) {
		// this can happen if we have any race in connection destroy path
		pr_err("connection node is invalid!!\n");
		return -ENOENT;
	}

	if (connp->state == CONN_FAILED) {
		CONNTBL_ASSERT(atomic64_read(&connp->nr_waits_pend) == 0);
		CONNTBL_ASSERT(!mutex_is_locked(&connp->lock));
	} else if ((mutex_is_locked(&connp->lock)) ||
                (connp->state == CONN_ACTIVE)) {
		pr_err("connection node <%s/%u/%p> busy cann't destroy",
				connp->ip, connp->port, connp);
		return -EBUSY;
	}

	hash_del(hentry);
	return 0;
}

/*
 * remove entry from table, protected
 */
static int connection_hashtable_remove(struct cacheobj_conntable *table,
        struct cacheobj_connection_node *connp)
{
	int err;

	write_lock(&table->lock);
	err = __connection_remove(table, connp);
	write_unlock(&table->lock);
	return err;
}

/*
 * check if connection exists given ip-port, protected
 * note returned connection handle is not locked and can slip away
 */
static struct cacheobj_connection_node *connection_hashtable_peek
    (struct cacheobj_conntable *table, const char *ip, unsigned int port)
{
	u32 key = 0;
	struct cacheobj_connection_node *connp = NULL;
	struct hlist_node *tmp;

	if (ipv4_hash32(ip, port, &key) < 0)
		return ERR_PTR(-EINVAL);

	read_lock(&table->lock);
	hash_for_each_possible_safe(table->buckets, connp, tmp, hentry, key) {
		if ((connp->port == port) && (strcmp(connp->ip, ip) == 0)) {
			read_unlock(&table->lock);
			return connp;
		}
	}
	read_unlock(&table->lock);
	return NULL;
}

/*
 * iterator for entire conntable, protected
 * currently sole consumer is table destroy
 * note returned connection handle is not locked
 */
static struct cacheobj_connection_node *connection_hashtable_iter
    (struct cacheobj_conntable *table)
{
	int bkt = 0;
	struct cacheobj_connection_node *connp = NULL;

	read_lock(&table->lock);
	hash_for_each(table->buckets, bkt, connp, hentry) {
	        read_unlock(&table->lock);
		return connp;
	}
	read_unlock(&table->lock);
	return NULL;
}

/*
 * finds a ready connection for a node, protected
 * returns :
 * 	locked connection on success
 *	NULL on new node
 *	-EINVAL on bad input
 *	-EPIPE on all paths down
 */
static struct cacheobj_connection_node* connection_get(struct cacheobj_conntable
        *table, const char *ip, unsigned int port)
{
	u32 key = 0;
	unsigned long now_js = 0;
	struct cacheobj_connection_node *connp;
	bool present = false, slow_path = false, apd;

	if (ipv4_hash32(ip, port, &key) < 0)
		return ERR_PTR(-EINVAL);

	// start wait time
	cacheobjects_stat64_jiffies(&now_js);
	read_lock(&table->lock);

	do {
		struct hlist_node *tmp = NULL;
		apd = true;
		hash_for_each_possible_safe(table->buckets, connp, tmp, hentry,
                        key) {
			if ((connp->port != port) ||
                            (strcmp(connp->ip, ip) != 0))
				continue;

			present = true;

			if (slow_path) {
				atomic64_inc(&connp->nr_waits);
				atomic64_inc(&connp->nr_waits_pend);
				pr_debug("enter slow path for get connection"
					"(%s-%u) wait_count :%ld\n", ip, port,
					atomic64_read(&connp->nr_waits));
				mutex_lock(&connp->lock);
				// fast path
			} else if (!mutex_trylock(&connp->lock)) {
				apd = false; // hint we did not check the state
				continue;
			}

			// got mutex
			if (slow_path)
				atomic64_dec(&connp->nr_waits_pend);

			if (connp->state == CONN_READY) {
				connp->state = CONN_ACTIVE;
				read_unlock(&table->lock);
				// end wait time
				cacheobjects_stat64_add(jiffies_now() - now_js,
					&connp->tot_js_wait);
				// start use time
				cacheobjects_stat64_jiffies(&connp->now_js);
				cacheobjects_stat64(&connp->nr_lookups);
				return connp;
			} else {
				mutex_unlock(&connp->lock);
			}
		}

		if (!slow_path)
			slow_path = true;

	} while (present && !apd);

	read_unlock(&table->lock);

	if (!present) {
		pr_info("get connection failed, node not present in table");
		return NULL;
	}

	pr_err("get connection failed, all paths down to node!");
	return ERR_PTR(-EPIPE);
}

/*
 *	timed version is now a plain dfc get (untimed). if we add
 *	waitqueue based implementation, we can update this function (TBD)
 */
static struct cacheobj_connection_node* connection_timed_get
        (struct cacheobj_conntable *table, const char *ip, unsigned int port,
        long timeout)
{
	return connection_get(table, ip, port);
}

static void connection_put(struct cacheobj_conntable *table,
	struct cacheobj_connection_node *connp, conn_op_t op)
{
	if (!mutex_is_locked(&connp->lock))
		pr_err("Mutex not locked for connection %p. Stat=%d",
			connp, connp->state);
	// resource must be locked
	CONNTBL_ASSERT(mutex_is_locked(&connp->lock));

	if (connp->state == CONN_ACTIVE) {
		// end use time
		connection_node_update_jiffies(connp, op);
		connp->state = CONN_READY;
	}
	mutex_unlock(&connp->lock);
}

/*
 * remove all entries from the table, protected
 */
static int connection_hashtable_destroy(struct cacheobj_conntable *table)
{
	int err = 0, bkt;
	unsigned long long nr_items = 0;
	struct cacheobj_connection_node *conn;
	struct hlist_node *tmp;

	write_lock(&table->lock);
	if ((hash_empty(table->buckets)))
		goto exit;

	// safe version for deletion
	hash_for_each_safe(table->buckets, bkt, tmp, conn, hentry) {
		err = __connection_remove(table, conn);
		if (err) {
			pr_err("resource busy, failed to remove from table\n");
			goto exit;
		}
		(void) cacheobj_connection_node_destroy(conn);
		nr_items++;
	}
exit:
	write_unlock(&table->lock);
	pr_info("cleanup removed %llu items from table\n", nr_items);
	return err;
}

/*
 * track connection distribution, protected
 */
static void connection_hashtable_dump(struct cacheobj_conntable *table,
	struct seq_file *m)
{
	int bkt;
	unsigned long total, getus, putus, wtus;
	u64 lookups, waits, tx_mb, rx_mb;
	struct cacheobj_connection_node *connp; // iterator
	struct hlist_node *tmp;

	seq_printf(m, "HOST\tSTATE\tRETRIES\tLOOKUPS\tWAITS\tAVG_WAIT(us)\t"
			"AVG_LAT_GET(us)\tAVG_LAT_PUT(us)\tSEND(kb) RCV(kb)\n");

	read_lock(&table->lock);

	if (hash_empty(table->buckets))
		goto exit;

	hash_for_each_safe(table->buckets, bkt, tmp, connp, hentry) {
		lookups = atomic64_read(&connp->nr_lookups);
		waits = cacheobjects_stat64_read(&connp->nr_waits);
		tx_mb = cacheobjects_stat64_read(&connp->tx_bytes) >> 10;
		rx_mb = cacheobjects_stat64_read(&connp->rx_bytes) >> 10;
		total = cacheobjects_stat64_jiffies2usec(&connp->tot_js_get);
		getus = div64_safe(total, lookups);
		total = cacheobjects_stat64_jiffies2usec(&connp->tot_js_put);
		putus = div64_safe(total, lookups);
		total = cacheobjects_stat64_jiffies2usec(&connp->tot_js_wait);
		wtus = div64_safe(total, lookups);
		seq_printf(m, "%s:%u %s %u %llu %llu %lu %lu %lu %llu %llu\n",
			connp->ip, connp->port, conn_state_status(connp->state),
			connp->nr_retry_attempts, lookups, waits, wtus, getus,
			putus, tx_mb, rx_mb);
	}
exit:
	read_unlock(&table->lock);
}

const struct cacheobj_conntable_operations cacheobj_conntable_ops =
{
    .cacheobj_conntable_init = connection_hashtable_init,
    .cacheobj_conntable_destroy = connection_hashtable_destroy,
    .cacheobj_conntable_insert = connection_hashtable_insert,
    .cacheobj_conntable_remove = connection_hashtable_remove,
    .cacheobj_conntable_peek = connection_hashtable_peek,
    .cacheobj_conntable_iter = connection_hashtable_iter,
    .cacheobj_conntable_timed_get = connection_timed_get,
    .cacheobj_conntable_put = connection_put,
    .cacheobj_conntable_dump = connection_hashtable_dump
};
#endif
