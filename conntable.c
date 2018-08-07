/* Connection pool based hashtable
 *
 * Saptarshi Sen, Copyright (C) 2018
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
#include <linux/wait.h>
#include <linux/sched.h>

#include "conntable.h"

static struct cacheobj_conntable glob_conn_table;

/*
 * Ref : https://www.kfki.hu/~kadlec/sw/netfilter/ct3/
 *
 * We can probably replace this with murmash hash which takes lesser
 * cpu cyles. But could not find an existing kernel implementation.
 */
static inline u32 hashfn(__be32 daddr, __be32 port)
{
    static u32 hash_seed = 0; //__read_mostly;

    //net_get_random_once(&hash_seed, sizeof(hash_seed));
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
 * cacheobj_conntable_node initialization
 * ip and port are redundant for connection node, since pool already has this info
 */
int cacheobj_conntable_node_init(struct cacheobj_conntable_node *conn,
        const char *ip, unsigned int port)
{
    CONNTBL_ASSERT(ip);
    conn->ip = kstrdup(ip, GFP_KERNEL);
    if (!conn->ip) {
        pr_err("failed to allocate conn ip\n");
        return -ENOMEM;
    }
    conn->port = port;
    conn->state = CONN_DOWN;
    conn->flags = 0;
    conn->pool = NULL;
    atomic64_set(&conn->nr_lookups, 0);
    return 0;
}
EXPORT_SYMBOL(cacheobj_conntable_node_init);

/*
 * check and release resources associated with cacheobj_conntable_node.
 * TBD: Currently cacheobj_conntable_node is an embedded structure and not
 * allocated, so free is not needed.
 * Note: If we reach here, that means we are good to die
 */
int cacheobj_conntable_node_destroy(struct cacheobj_conntable_node *conn)
{
    CONNTBL_ASSERT(conn);
    CONNTBL_ASSERT(conn->pool);
    kfree(conn->ip);
    conn->pool = NULL; // uncache
    return 0;
}
EXPORT_SYMBOL(cacheobj_conntable_node_destroy);

/*
 * initialize conn hash table and associated lock for protection
 * Note: We use a static hashtable(no resizing) for managing connection pools.
 */
static struct cacheobj_conntable* cacheobj_conntable_init(void)
{
    struct cacheobj_conntable *table = &glob_conn_table;
    hash_init(table->buckets);
    rwlock_init(&table->lock);
    return table;
}

/*
 * allocate and initialize a connection pool
 */
static struct cacheobj_conntable_pool *cacheobj_conntable_pool_alloc
        (struct cacheobj_conntable *table, const char *ip, unsigned int port)
{
    int err = 0;
    struct cacheobj_conntable_pool *pool;

    pool = (struct cacheobj_conntable_pool *)
        kzalloc(sizeof(struct cacheobj_conntable_pool), GFP_KERNEL);
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

    // cache the hash key
    if (ipv4_hash32(pool->ip, pool->port, &pool->key) < 0) {
        err = -EINVAL;
        goto key_error;
    }

    INIT_LIST_HEAD(&pool->conn_list);
    INIT_HLIST_NODE(&pool->hentry);
    init_waitqueue_head(&pool->wq);
    atomic_set(&pool->upref, 0);

    atomic_set(&pool->nr_connections, 0);
    atomic_set(&pool->nr_idle_connections, 0);
    atomic64_set(&pool->nr_waits, 0);
    return pool;

key_error:
    kfree(pool->ip);
ipmem_error:
    kfree(pool);
poolmem_error:
    return ERR_PTR(-err);
}
EXPORT_SYMBOL(cacheobj_conntable_pool_alloc);

/*
 * remove a connection pool.
 * notes:
 * -caller must have table write lock
 */
static int cacheobj_conntable_pool_destroy(struct cacheobj_conntable_pool *pool)
{
    struct hlist_node *hentry = &pool->hentry;

    // pool must be in hash table!
    CONNTBL_ASSERT(hash_hashed(hentry));

    // note this is updated under a reader/writer lock
    // closes the timing window in which waiters are added to wq
    if (atomic_read(&pool->upref)) {
        pr_err("pool destroy error, pool has bumped up reference (%d)\n",
                atomic_read(&pool->upref));
        goto pool_busy;
    }
    // cannot have pending waiters on pool's wait queue
    if (waitqueue_active(&pool->wq)) {
        pr_err("pool destroy error, pool has pending waiters\n");
        goto pool_busy;
    }

    // caller should ensure all connections dead/ready are removed from list
    if (!list_empty(&pool->conn_list)) {
        pr_err("pool destroy error, connection list is not empty\n");
        goto pool_busy;
    }

    CONNTBL_ASSERT(atomic_read(&pool->nr_connections) == 0);
    CONNTBL_ASSERT(atomic_read(&pool->nr_idle_connections) == 0);

    // upper layer must ensure no connections sneak in after this
    hash_del(hentry);
    pr_info("connection pool destroyed for <%s:%u>\n", pool->ip, pool->port);
    kfree(pool->ip);
    kfree(pool);
    return 0;

pool_busy:
    return -EBUSY;
}
EXPORT_SYMBOL(cacheobj_conntable_pool_destroy);

/*
 * get connection pool given ip and port.
 * Note:
 * -caller must take reader lock to protect access
 * -pool is protected via:
 *   --rwlock
 *   --upref when not under rwlock(suspending on pool wait queue)
 */
static struct cacheobj_conntable_pool *__cacheobj_conntable_get_pool
    (struct cacheobj_conntable *table, const char *ip, unsigned int port)
{
    u32 key = 0;
    struct hlist_node *tmp;
    struct cacheobj_conntable_pool *pool;

    if (ipv4_hash32(ip, port, &key) < 0)
        return ERR_PTR(-EINVAL);

    hash_for_each_possible_safe(table->buckets, pool, tmp, hentry, key) {
        if ((pool->port == port) && (strcmp(pool->ip, ip) == 0)) {
            // probably insane check...
            CONNTBL_ASSERT(pool->key == key);
            return pool;
        }
    }
    return NULL;
}

/*
 * insert new connection entry to table, protected
 * returns 0 on success otherwise err
 */
static int cacheobj_conntable_insert(struct cacheobj_conntable *table,
        struct cacheobj_conntable_node *conn)
{
    struct cacheobj_conntable_pool *pool;

    CONNTBL_ASSERT(conn);

    write_lock(&table->lock);
    pool = __cacheobj_conntable_get_pool(table, conn->ip, conn->port);
    if (!pool) {
        write_unlock(&table->lock);
        pool = cacheobj_conntable_pool_alloc(table, conn->ip, conn->port);
        if (IS_ERR(pool)) {
            pr_err("pool allocation failure\n");
            return -ENOMEM;
        }

        write_lock(&table->lock);
        hash_add(table->buckets, &pool->hentry, pool->key);
    }
    CONNTBL_ASSERT(!IS_ERR(pool));
    conn->pool = pool;

    /* added to head of per-pool connection chain */
    list_add(&conn->list_node, &pool->conn_list);
    atomic_inc(&pool->nr_connections);

    conn->state = CONN_READY;
    atomic_inc(&pool->nr_idle_connections);

    atomic_inc(&pool->upref);
    write_unlock(&table->lock);

    // wakeup any pending waiters, preceding code has implicit barrier
    if (waitqueue_active(&pool->wq))
        wake_up_interruptible(&pool->wq);

    pr_info("added new connection pool <%s:%u>", pool->ip, pool->port);
    atomic_dec(&pool->upref);
    return 0;
}
EXPORT_SYMBOL(cacheobj_conntable_insert);

/*
 * remove helper, no lock version
 * note: caller must have table write lock
 */
static inline int __conntable_remove(struct cacheobj_conntable *table,
        struct cacheobj_conntable_node *conn)
{
    int err;
    struct cacheobj_conntable_pool *pool;

    // we bail out if node is in use
    if (test_and_set_bit_lock(CONN_LOCKED, &conn->flags)) {
        err = -EBUSY;
        pr_err("conn is locked, cannot destroy!!!\n");
        goto remove_error;
    }
    // unlink from chain and update pool counters
    pool = conn->pool;
    CONNTBL_ASSERT(pool);
    CONNTBL_ASSERT(conn->state != CONN_ACTIVE);
    if (conn->state == CONN_READY) {
        atomic_dec(&pool->nr_idle_connections);
        conn->state = CONN_ZOMBIE;
    }

    list_del(&conn->list_node);
    atomic_dec(&pool->nr_connections);
    return 0;

remove_error:
    pr_err("failed to remove connection (%s:%u)\n", conn->ip, conn->port);
    return err;
}

/*
 * remove connection entry from table, protected
 * returns 0 on success otherwise -EBUSY on error
 */
static int cacheobj_conntable_remove(struct cacheobj_conntable *table,
        struct cacheobj_conntable_node *conn)
{
    int err;

    write_lock(&table->lock);
    err = __conntable_remove(table, conn);
    write_unlock(&table->lock);
    return err;
}
EXPORT_SYMBOL(cacheobj_conntable_remove);

/*
 * looks up a connection entry from pool, protected
 * note: return node has no ownership and later validity cannot be assured.
 */
static struct cacheobj_conntable_node *cacheobj_conntable_peek
        (struct cacheobj_conntable *table, const char *ip, unsigned int port)
{
    struct cacheobj_conntable_pool *pool;
    struct cacheobj_conntable_node *conn_nodep = NULL;

    read_lock(&table->lock);
    pool = __cacheobj_conntable_get_pool(table, ip, port);
    if (pool && !IS_ERR(pool) && !list_empty(&pool->conn_list)) {
        conn_nodep = list_first_entry(&pool->conn_list,
                struct cacheobj_conntable_node, list_node);
    }
    read_unlock(&table->lock);
    return conn_nodep;
}
EXPORT_SYMBOL(cacheobj_conntable_peek);

/*
 * gets a ready and exclusive connection from pool conn list, no lock version
 * returns :
 * 	 locked cacheobj_conntable_node on success
 *	 NULL on no entry
 *	-EINVAL on bad input
 *	-EBUSY on resource busy
 *	-EPIPE on all paths down
 * notes : caller must ensure we have table read lock
 */
static struct cacheobj_conntable_node* __cacheobj_conntable_get
        (struct cacheobj_conntable_pool *pool)
{
    int err = 0;
    bool apd = true;
    struct cacheobj_conntable_node *conn, *tmp;

    list_for_each_entry_safe(conn, tmp, &pool->conn_list, list_node) {
        if (test_and_set_bit_lock(CONN_LOCKED, &conn->flags)) {
            apd = false; // hint we did not check the state
            continue;
        }
        // got ownership
        if (conn->state == CONN_READY) {
            atomic_dec(&conn->pool->nr_idle_connections);
            conn->state = CONN_ACTIVE;
            atomic64_inc(&conn->nr_lookups);
            return conn;
        } else {
            clear_bit_unlock(CONN_LOCKED, &conn->flags);
        }
    }

    // error path:
    if (list_empty(&pool->conn_list)) {
        pr_debug("get connection node error <%s:%u>, node not present in pool",
                pool->ip, pool->port);
        err = -ENOENT;
    } else if (apd) {
        pr_debug("get connection node failed <%s:%u>, all paths down to node!",
                pool->ip, pool->port);
        err = -EPIPE;
    } else {
        pr_debug("get connection node error <%s:%u>, resource busy!",
                pool->ip, pool->port);
        err = -EBUSY;
    }
    return ERR_PTR(err);
}

/*
 * get a ready and exclusive connection with timeout.
 * -may suspend current task with timeout if pool is busy
 * returns:
 *	locked connection on success
 *	ERR_PTR or NULL on error
 */
static struct cacheobj_conntable_node* cacheobj_conntable_timed_get
        (struct cacheobj_conntable *table, const char *ip, unsigned int port,
        long timeout)
{
    struct cacheobj_conntable_node *conn_nodep = NULL;
    struct cacheobj_conntable_pool *pool;

    do {
        read_lock(&table->lock);

        pool = __cacheobj_conntable_get_pool(table, ip, port);
        if (!pool) {
            pr_err("get failed, pool not initialized (%s:%u)", ip, port);
            goto exit;
        }
        CONNTBL_ASSERT(!IS_ERR(pool));
        conn_nodep = __cacheobj_conntable_get(pool);
        // got one!
        if (likely(!IS_ERR(conn_nodep)))
            goto exit;

        switch(PTR_ERR(conn_nodep)) {
            case -ENOENT:
                // pool empty
                conn_nodep = NULL;
            case -EPIPE:
                // apd
                CONNTBL_ASSERT(atomic_read(&pool->nr_idle_connections) == 0);
                goto exit;
            case -EBUSY:
                // resource busy
                atomic64_inc(&pool->nr_waits);
                atomic_inc(&pool->upref);
                read_unlock(&table->lock);
                // TBD : check for shutdown in progress
                timeout = wait_event_interruptible_timeout(pool->wq,
                        (atomic_read(&pool->nr_idle_connections) > 0), timeout);
                atomic_dec(&pool->upref);
                break;
            default:
                CONNTBL_ASSERT(0);
        }
        //pr_info("timeout jiffies remaining :%ld\n", timeout);
    } while (timeout >= 0);

    if (!conn_nodep || IS_ERR(conn_nodep))
        pr_err("get connection timed out<%s:%u>(%lu)\n", ip, port, timeout);
    return conn_nodep;

exit:
    read_unlock(&table->lock);
    return conn_nodep;
}
EXPORT_SYMBOL(cacheobj_conntable_timed_get);

/*
 * puts a connection after use
 * -unlock connection and notify one waiting on pool wq
 */
static void cacheobj_conntable_put(struct cacheobj_conntable *table,
        struct cacheobj_conntable_node *connp)
{
    switch (connp->state) {
        case CONN_ACTIVE: {
             struct cacheobj_conntable_pool *pool = connp->pool;
             // ensure pool doesn't slip away on unlock connection!
             atomic_inc(&pool->upref);

             connp->state = CONN_READY;
             atomic_inc(&pool->nr_idle_connections);
             clear_bit_unlock(CONN_LOCKED, &connp->flags);
             // atomic_inc implies a memory barrier
             if (waitqueue_active(&pool->wq))
                 wake_up_interruptible(&pool->wq); // wake up a single task
             atomic_dec(&pool->upref);
             break;
             }
        default:
             clear_bit_unlock(CONN_LOCKED, &connp->flags);
             break;
    }
}
EXPORT_SYMBOL(cacheobj_conntable_put);

/*
 * clears connection table, protected
 */
static int cacheobj_conntable_destroy(struct cacheobj_conntable *table)
{
    int err = 0, bkt;
    size_t nr_items = 0;
    struct hlist_node *tmp;
    struct cacheobj_conntable_pool *pool;
    struct cacheobj_conntable_node *conn, *tmp_list;

    write_lock(&table->lock);
    if (hash_empty(table->buckets))
        goto exit;

    // iterate pool
    hash_for_each_safe(table->buckets, bkt, tmp, pool, hentry) {
        bool offline_pool = true;
        list_for_each_entry_safe(conn, tmp_list, &pool->conn_list, list_node) {
            err = __conntable_remove(table, conn);
            if (err) {
                pr_err("connection remove error <%s:%u>", conn->ip, conn->port);
                offline_pool = false;
                break;
            }
            (void) cacheobj_conntable_node_destroy(conn);
            nr_items++;
        }
        // pool not ready to destroy
        if (offline_pool && (cacheobj_conntable_pool_destroy(pool) < 0))
            pr_err("failed to destroy pool (%s:%u)", pool->ip, pool->port);
    }

exit:
    write_unlock(&table->lock);
    pr_info("cleanup removed %lu items from table\n", nr_items);
    return err;
}
EXPORT_SYMBOL(cacheobj_conntable_destroy);

/*
 * track cacheobj_conntable_node usage distribution
 */
static void cacheobj_conntable_distribution_dump(struct cacheobj_conntable *table)
{
    int i, bkt;
    struct hlist_node *tmp;
    struct cacheobj_conntable_pool *pool;
    struct cacheobj_conntable_node *conn, *tmp_list;

    read_lock(&table->lock);

    if (hash_empty(table->buckets))
        goto exit;

    hash_for_each_safe(table->buckets, bkt, tmp, pool, hentry) {
        pr_info("pool : (%s:%u) nr_waits :%lu", pool->ip,
                pool->port, atomic64_read(&pool->nr_waits));
        i = 0;
        list_for_each_entry_safe(conn, tmp_list, &pool->conn_list, list_node)
            pr_info("connection[%d] nr_lookups :%lu\n", i++,
                    atomic64_read(&conn->nr_lookups));
    }
exit:
    read_unlock(&table->lock);
}

const struct cacheobj_conntable_operations cacheobj_conntable_ops =
{
    .cacheobj_conntable_init = cacheobj_conntable_init,
    .cacheobj_conntable_destroy = cacheobj_conntable_destroy,
    .cacheobj_conntable_insert = cacheobj_conntable_insert,
    .cacheobj_conntable_remove = cacheobj_conntable_remove,
    .cacheobj_conntable_peek = cacheobj_conntable_peek,
    .cacheobj_conntable_timed_get = cacheobj_conntable_timed_get,
    .cacheobj_conntable_put = cacheobj_conntable_put,
    .cacheobj_conntable_distribution_dump = cacheobj_conntable_distribution_dump
};
