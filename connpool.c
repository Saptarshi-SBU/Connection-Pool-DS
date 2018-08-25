/* Connection pool based hashtable
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */
#include <linux/string.h>
#include <linux/cache.h>
#include <linux/net.h>
#include <linux/inet.h>
#include <linux/jhash.h>
#include <linux/slab.h>
#include <linux/sched.h>

#ifndef CONFIG_CACHEOBJS_CONNPOOL
#define CONFIG_CACHEOBJS_CONNPOOL
#endif

#define CONNTABLE_VERSION 2

#include "conntable.h"
#include "stat.h"

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
void cacheobj_connection_node_reset_stats(struct cacheobj_connection_node *connp)
{
    cacheobjects_stat64_reset(&connp->nr_lookups);
    cacheobjects_stat64_reset(&connp->cum_get_ns);
    cacheobjects_stat64_reset(&connp->cum_put_ns);
    cacheobjects_stat64_reset(&connp->cum_wait_ns);
    cacheobjects_stat64_reset(&connp->tx_bytes);
    cacheobjects_stat64_reset(&connp->rx_bytes);
}

/*
 * connection node stat for updating cumulative time
 */
static inline
void cacheobj_connection_node_update_ktime(struct cacheobj_connection_node *connp,
        conn_op_t op)
{
    switch (op) {
        case GET:
            cacheobjects_stat64_add(ktime_ns_delta(ktime_get(), connp->now_ns),
                    &connp->cum_get_ns);
            break;
        case PUT:
            cacheobjects_stat64_add(ktime_ns_delta(ktime_get(), connp->now_ns),
                    &connp->cum_put_ns);
            break;
        default:
            CONNTBL_ASSERT(0);
    }
}

/*
 * cacheobj_connection_node initialization
 */
inline int cacheobj_connection_node_init(struct cacheobj_connection_node *connp,
        const char *ip, unsigned int port)
{
    CONNTBL_ASSERT(connp);
    CONNTBL_ASSERT(ip);
    CONNTBL_ASSERT(port);
    connp->ip = kstrdup(ip, GFP_KERNEL);
    if (!connp->ip) {
        pr_err("failed to allocate conn ip\n");
        return -ENOMEM;
    }
    connp->port = port;
    connp->pool = NULL;
    connp->nr_retry_attempts = 0;
    atomic_long_set(&connp->state, CONN_DOWN);
    cacheobj_connection_node_reset_stats(connp);
    return 0;
}

/*
 * check and release resources associated with cacheobj_connection_node.
 * TBD: Currently cacheobj_connection_node is an embedded structure and not
 * allocated, so free is not needed.
 * Note: If we reach here, that means we are good to die
 */
inline
int cacheobj_connection_node_destroy(struct cacheobj_connection_node *connp)
{
    unsigned long state;

    CONNTBL_ASSERT(connp);
    CONNTBL_ASSERT(connp->pool == NULL);
    state = atomic_long_read(&connp->state);
    CONNTBL_ASSERT((state != CONN_ACTIVE) || (state != CONN_RETRY));
    kfree(connp->ip);
    connp->ip = NULL;
    connp->port = 0;
    return 0;
}

/*
 * Move the connection to failed state
 */
inline
void cacheobj_connection_node_failed(struct cacheobj_connection_node *connp)
{
    unsigned long state, old;

    state = atomic_long_read(&connp->state);
    if ((state == CONN_ACTIVE) || (state == CONN_RETRY)) {
        old = atomic_long_cmpxchg(&connp->state, state, CONN_FAILED);
        CONNTBL_ASSERT(old == state);
    } else {
        pr_err("invalid connection state :%lu\n", state);
        CONNTBL_ASSERT(0);
    }
}

/*
 * Move the connection to retry state
 */
inline
void cacheobj_connection_node_retry(struct cacheobj_connection_node *connp)
{
    unsigned long state, old;

    state = atomic_long_read(&connp->state);
    if (state == CONN_FAILED) {
        old = atomic_long_cmpxchg(&connp->state, state, CONN_RETRY);
        CONNTBL_ASSERT(old == state);
    } else {
        pr_err("invalid connection state :%lu\n", state);
        CONNTBL_ASSERT(0);
    }
}

/*
 * Move the connection to ready state
 */
inline
void cacheobj_connection_node_ready(struct cacheobj_connection_node *connp)
{
    unsigned long state, old;

    state = atomic_long_read(&connp->state);
    if (state == CONN_RETRY) {
        old = atomic_long_cmpxchg(&connp->state, state, CONN_READY);
        CONNTBL_ASSERT(old == state);
    }
}

/*
 * initialize conn hash table and associated lock for protection
 * Note: We use a static hashtable(no resizing) for managing connection pools.
 */
static int connectionpool_hashtable_init(struct cacheobj_conntable *table)
{
    hash_init(table->buckets);
    rwlock_init(&table->lock);
    return 0;
}

/*
 * allocate and initialize a connection pool
 */
static struct cacheobj_connection_pool *__connection_pool_alloc
        (struct cacheobj_conntable *table, const char *ip, unsigned int port)
{
    int err = 0;
    struct cacheobj_connection_pool *pool;

    pool = (struct cacheobj_connection_pool *)
        kzalloc(sizeof(struct cacheobj_connection_pool), GFP_KERNEL);
    if (!pool) {
        pr_err("failed to allocate connection pool (%s:%u)\n", ip, port);
        err = -ENOMEM;
        goto poolmem_error;
    }

    pool->ip = kstrdup(ip, GFP_KERNEL);
    if (!pool->ip) {
        pr_err("failed to allocate pool ip (%s:%u)\n", ip, port);
        err = -ENOMEM;
        goto ipmem_error;
    }
    pool->port = port;

    // connection list
    INIT_LIST_HEAD(&pool->conn_list);
    atomic_set(&pool->nr_connections, 0);

    // waitqueue for pool busy condition
    init_waitqueue_head(&pool->wq);
    cacheobjects_stat64_reset(&pool->nr_slow_paths);

    // pool is a hashtable node
    INIT_HLIST_NODE(&pool->hentry);

    return pool;

ipmem_error:
    kfree(pool);

poolmem_error:
    return ERR_PTR(-err);
}

/*
 * remove a connection pool.
 * notes:
 * -caller must have table write lock
 * -caller must ensure there are no outstanding pool operations, prior invoking
 * For simplicity, regular conntable ops work under assumption that pool does
 * not slip underneath us. This MUST be called only as part of teardown.
 */
static int __connection_pool_destroy(struct cacheobj_connection_pool *pool)
{
    CONNTBL_ASSERT(pool);

    // pool must be in hash table!
    CONNTBL_ASSERT(hash_hashed(&pool->hentry));

    if (waitqueue_active(&pool->wq)) {
        pr_err("pool destroy error, pool has pending waiters\n");
        goto pool_busy;
    }

    if (!list_empty(&pool->conn_list)) {
        pr_err("pool destroy error, connection list is not empty\n");
        goto pool_busy;
    }
    CONNTBL_ASSERT(atomic_read(&pool->nr_connections) == 0);

    hash_del(&pool->hentry);
    kfree(pool->ip);
    kfree(pool);
    return 0;

pool_busy:
    return -EBUSY;
}

/*
 * get connection pool given ip and port.
 * Note:
 * -caller must take reader lock to protect access
 * -pool is protected via rwlock
 */
static inline struct cacheobj_connection_pool *__get_connection_pool
    (struct cacheobj_conntable *table, const char *ip, unsigned int port,
    u32 key)
{
    struct cacheobj_connection_pool *pool;

    hash_for_each_possible(table->buckets, pool, hentry, key) {
        if ((pool->port == port) && (strcmp(pool->ip, ip) == 0))
            return pool;
    }
    pr_debug("connection pool not found <%s:%u>", ip, port);
    return NULL;
}

/*
 * insert new connection entry to table, protected
 * returns 0 on success otherwise err
 */
static int connectionpool_hashtable_insert(struct cacheobj_conntable *table,
        struct cacheobj_connection_node *connp)
{
    u32 key = 0;
    struct cacheobj_connection_pool *pool, *new_pool = NULL;

    CONNTBL_ASSERT(connp);

    if (ipv4_hash32(connp->ip, connp->port, &key) < 0)
        return -EINVAL;

    read_lock(&table->lock);
    pool = __get_connection_pool(table, connp->ip, connp->port, key);
    if (!pool) {
        bool try_add = false; // for new pool allocation
        read_unlock(&table->lock);
        new_pool = __connection_pool_alloc(table, connp->ip, connp->port);
        if (IS_ERR(new_pool)) {
            pr_err("pool allocation failure\n");
            return -ENOMEM;
        }

        write_lock(&table->lock);
        pool = __get_connection_pool(table, connp->ip, connp->port, key);
        if (!pool) {
            hash_add(table->buckets, &new_pool->hentry, key);
            pool = new_pool;
            try_add = true;
        }
        write_unlock(&table->lock);
	// if someone already created the pool for us
        if (!try_add) {
             kfree(new_pool);
             new_pool = NULL;
        }
    } else {
        read_unlock(&table->lock);
    }

    CONNTBL_ASSERT(pool);
    CONNTBL_ASSERT(!IS_ERR(pool));
    connp->pool = pool;
    atomic_long_set(&connp->state, CONN_READY);

    /* added to head of per-pool connection chain */
    write_lock(&table->lock);
    list_add(&connp->list_node, &pool->conn_list);
    atomic_inc(&pool->nr_connections);
    atomic_inc(&pool->nr_ready);
    write_unlock(&table->lock);

    // wakeup any pending waiters, preceding unlock enforces a barrier
    if (waitqueue_active(&pool->wq))
        wake_up_interruptible_nr(&pool->wq, 1);

    if (new_pool)
        pr_info("created new connection pool <%s:%u>", pool->ip, pool->port);

    pr_debug("added connection to pool <%s:%u>", connp->ip, connp->port);
    return 0;
}

/*
 * remove helper, no lock version
 * returns 0 on success or err if connection is either active or in retry
 * note: caller must have table write lock
 * We need to take lock for the entire routine to cover cases, where a reader
 * does a get while the remove attempt get past the conn in use check
 */
static inline int __connection_remove(struct cacheobj_conntable *table,
        struct cacheobj_connection_node *connp, bool is_locked)
{
    int err;
    unsigned long state, old;

    CONNTBL_ASSERT(connp);
    CONNTBL_ASSERT(connp->pool);

    state = atomic_long_read(&connp->state);
    if ((state == CONN_ACTIVE) || (state == CONN_RETRY)) {
        err = -EBUSY;
        pr_err("conn is in use, cannot destroy!\n");
        goto remove_error;
    }

    // moment of thruth. terminal state for connection
    old = atomic_long_cmpxchg(&connp->state, state, CONN_ZOMBIE);
    if (old != state) {
        err = -EAGAIN;
        pr_err("conn state changed, cannot destroy!\n");
        goto remove_error;
    }

    if (!is_locked) {
        write_lock(&table->lock);
        list_del(&connp->list_node);
        atomic_dec(&connp->pool->nr_connections);
        write_unlock(&table->lock);
    } else {
        list_del(&connp->list_node);
        atomic_dec(&connp->pool->nr_connections);
    }

    connp->pool = NULL; // uncache
    pr_debug("removed connection from pool (%s:%u)\n", connp->ip, connp->port);
    return 0;

remove_error:
    pr_err("failed to remove connection (%s:%u)\n", connp->ip, connp->port);
    return err;
}

/*
 * remove connection entry from table, protected
 * returns 0 on success otherwise -EBUSY on error
 */
static int connectionpool_hashtable_remove(struct cacheobj_conntable
        *table, struct cacheobj_connection_node *connp)
{
    bool is_locked = false;
    return __connection_remove(table, connp, is_locked);
}

/*
 * looks up a connection entry from pool, protected
 * note: return node has no ownership and later validity cannot be assured.
 */
static struct cacheobj_connection_node *connectionpool_hashtable_lookup
    (struct cacheobj_conntable *table, const char *ip, unsigned int port)
{
    u32 key = 0;
    struct cacheobj_connection_pool *pool;
    struct cacheobj_connection_node *connp = NULL;

    if (ipv4_hash32(ip, port, &key) < 0)
        return ERR_PTR(-EINVAL);

    read_lock(&table->lock);
    pool = __get_connection_pool(table, ip, port, key);
    if (pool && !list_empty(&pool->conn_list)) {
        connp = list_first_entry(&pool->conn_list,
                struct cacheobj_connection_node, list_node);
        read_unlock(&table->lock);
        return connp;
    }
    read_unlock(&table->lock);
    return NULL;
}

/*
 * iterator function for conntable, protected
 * note returned connection handle is not be locked
 */
static struct cacheobj_connection_node *connectionpool_hashtable_iter
    (struct cacheobj_conntable *table)
{
    int bkt = 0;
    struct cacheobj_connection_pool *pool;
    struct cacheobj_connection_node *connp = NULL;

    read_lock(&table->lock);
    hash_for_each(table->buckets, bkt, pool, hentry) {
	if (!list_empty(&pool->conn_list)) {
        	connp = list_first_entry(&pool->conn_list,
                	struct cacheobj_connection_node, list_node);
        	read_unlock(&table->lock);
        	return connp;
	}
    }
    read_unlock(&table->lock);
    return NULL;
}

/*
 * get a ready connection.
 * -may suspend current task if pool is busy
 * returns:
 *	locked connection on success
 *	 NULL on no entry
 *	-EINVAL on bad input
 *	-EBUSY on resource busy
 *	-EPIPE on all paths down
 * Intention was to have a timed wait. But did not find wakit_event variant
 * for exclusive process. We may have to write one. (TBD)
 */
static struct cacheobj_connection_node* connection_timed_get
    (struct cacheobj_conntable *table, const char *ip, unsigned int port,
    long timeout)
{
    u32 key;
    bool apd;
    ktime_t now_ns;
    unsigned long state;
    struct cacheobj_connection_pool *pool;
    struct cacheobj_connection_node *connp;

    if (ipv4_hash32(ip, port, &key) < 0)
        return ERR_PTR(-EINVAL);

    cacheobjects_stat64_ktime(&now_ns); // start wait time
    do {
        read_lock(&table->lock);

        pool = __get_connection_pool(table, ip, port, key);
        if (!pool) {
            pr_debug("connection pool not found (%s:%u)\n", ip, port);
            read_unlock(&table->lock);
            return NULL; // hint to upper layer to create a pool
        }

        if (list_empty(&pool->conn_list)) {
            read_unlock(&table->lock);
            pr_info("pool empty, connection not found <%s:%u>\n", ip, port);
            connp = NULL;
            goto exit;
        }

        apd = true;
        list_for_each_entry(connp, &pool->conn_list, list_node) {
            // grab ready connection
            if (((state = atomic_long_read(&connp->state)) == CONN_READY) &&
                (atomic_long_cmpxchg(&connp->state, CONN_READY, CONN_ACTIVE)
                == CONN_READY)) {
                read_unlock(&table->lock);
                atomic_dec(&pool->nr_ready);
		// stats
                cacheobjects_stat64_add(ktime_ns_delta(ktime_get(),
                    now_ns), &connp->cum_wait_ns); // end wait time
                cacheobjects_stat64_ktime(&connp->now_ns); // start use time
                cacheobjects_stat64(&connp->nr_lookups);
                return connp;
            } else if ((state != CONN_FAILED) && (state != CONN_RETRY)) {
                apd = false;
            }
        } //end list

        // error paths
        if (!apd && !list_empty(&pool->conn_list)) {
            // resource busy
	    // we wait as an exclusive thread since many threads will be
	    // sharing wait condition which may lead to thundering herd
            read_unlock(&table->lock);
            connp = ERR_PTR(-EBUSY);
            cacheobjects_stat64(&pool->nr_slow_paths);
            wait_event_interruptible_exclusive(pool->wq, 
                (atomic_read(&pool->nr_ready) > 0));
        } else if (apd) {
            // all paths down
            read_unlock(&table->lock);
            pr_err("get connection node failed <%s:%u>, all paths down "
                    "to node!", pool->ip, pool->port);
            connp = ERR_PTR(-EHOSTDOWN);
            goto exit;
        }
    } while (true); // Fix me: did not find any timeout variant for exclusive

exit:
    return connp;
}

/*
 * puts a connection after use
 * -unlock connection and notify one waiting on pool wq
 */
static void connection_put(struct cacheobj_conntable *table,
        struct cacheobj_connection_node *connp, conn_op_t op)
{
    unsigned long state;
   
    switch((state = atomic_long_read(&connp->state))) {
    case CONN_ACTIVE:
        {
            struct cacheobj_connection_pool *pool = connp->pool;
            cacheobj_connection_node_update_ktime(connp, op); // end use time
            atomic_long_cmpxchg(&connp->state, state, CONN_READY);
            atomic_inc(&pool->nr_ready);
            if (waitqueue_active(&pool->wq))
                wake_up_interruptible_nr(&pool->wq, 1);
            break;
        }
    default:
        CONNTBL_ASSERT(0);
    }
}

/*
 * clears connection table, protected
 */
static int connectionpool_hashtable_destroy(struct cacheobj_conntable *table)
{
    int bkt;
    bool is_locked = true;
    size_t nr_items = 0, pools_left = 0;
    struct hlist_node *tmp;
    struct cacheobj_connection_pool *pool;
    struct cacheobj_connection_node *connp, *tmp_list;

    write_lock(&table->lock);
    if (hash_empty(table->buckets))
        goto exit;

    hash_for_each_safe(table->buckets, bkt, tmp, pool, hentry) {
        pools_left++;
        // iterate connection list
	// This is no op for dfc as it tears down connections and clears pool
	// list prior hashtable destroy
        list_for_each_entry_safe(connp, tmp_list, &pool->conn_list, list_node) {
            if (__connection_remove(table, connp, is_locked) == 0) {
                cacheobj_connection_node_destroy(connp);
                nr_items++;
            }
        }
        if (list_empty(&pool->conn_list)) {
            if (__connection_pool_destroy(pool) == 0)
                pools_left--;
        }
    }

exit:
    write_unlock(&table->lock);
    pr_debug("cleanup removed %lu items from table\n", nr_items);
    return pools_left ? -EBUSY : 0;
}

/*
 * track cacheobj_connection_node usage distribution
 */
static void connectionpool_hashtable_dump(struct cacheobj_conntable
        *table, struct seq_file *m)
{
    int bkt;
    struct hlist_node *tmp;
    unsigned long total, getus, putus, waitus;
    u64 lookups, tx_mb, rx_mb;
    struct cacheobj_connection_pool *pool;
    struct cacheobj_connection_node *connp, *tmp_list;

    seq_printf(m, "conntable stats version :%d\n\n", CONNTABLE_VERSION);

    seq_printf(m, "HOST\tSTATE\tRETRIES\tLOOKUPS\tSLOWPATHS\tAVG_WAIT(ns)\t"
            "AVG_LAT_GET(ns)\tAVG_LAT_PUT(ns)\tSEND(kb) RCV(kb)\n");

    read_lock(&table->lock);
    if (hash_empty(table->buckets))
        goto exit;

    hash_for_each_safe(table->buckets, bkt, tmp, pool, hentry) {
        seq_printf(m, "pool <%s:%u> nr_slow_paths :%lu\n", pool->ip,
                pool->port, atomic64_read(&pool->nr_slow_paths));
        list_for_each_entry_safe(connp, tmp_list, &pool->conn_list,
                list_node) {
            lookups = cacheobjects_stat64_read(&connp->nr_lookups);
            tx_mb = cacheobjects_stat64_read(&connp->tx_bytes) >> 10;
            rx_mb = cacheobjects_stat64_read(&connp->rx_bytes) >> 10;
            total = cacheobjects_stat64_read(&connp->cum_get_ns);
            getus = div64_safe(total, lookups);
            total = cacheobjects_stat64_read(&connp->cum_put_ns);
            putus = div64_safe(total, lookups);
            total = cacheobjects_stat64_read(&connp->cum_wait_ns);
            waitus = div64_safe(total, lookups);
            seq_printf(m, "%s:%u %s %u %llu %lu %lu %lu %lu %llu "
                    "%llu\n", connp->ip, connp->port,
                    conn_state_status(atomic_long_read(&connp->state)),
                    connp->nr_retry_attempts, lookups, ~0UL, waitus, getus,
		    putus, tx_mb, rx_mb);
        }
    }
exit:
    read_unlock(&table->lock);
}

const struct cacheobj_conntable_operations cacheobj_conntable_ops =
{
    .cacheobj_conntable_init = connectionpool_hashtable_init,
    .cacheobj_conntable_destroy = connectionpool_hashtable_destroy,
    .cacheobj_conntable_insert = connectionpool_hashtable_insert,
    .cacheobj_conntable_remove = connectionpool_hashtable_remove,
    .cacheobj_conntable_lookup = connectionpool_hashtable_lookup,
    .cacheobj_conntable_iter = connectionpool_hashtable_iter,
    .cacheobj_conntable_timed_get = connection_timed_get,
    .cacheobj_conntable_put = connection_put,
    .cacheobj_conntable_dump = connectionpool_hashtable_dump
};
