/* Connection table unit tests for insert, lookup, delete operations
 *
 * Saptarshi Sen, Copyright (C) 2018
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 *
 * usage: insmod conntable_ktest.ko nr_nodes=16 nr_conns=16 nr_lookup_threads=4
 */
#include <linux/module.h>
#include <linux/time.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/kernel.h>

#include "conntable.h"

MODULE_LICENSE("GPL");

#define HOSTIP	"127.0.0.1"
#define WAIT_FOR_READY_CONN_TIMEOUT (5 * HZ)
//#define WAIT_FOR_READY_CONN_TIMEOUT (1/1000 * HZ)
#define CONFIG_MAX_ALLOCATIONS

/* nr of nodes for test */
static int nr_nodes = 128;
module_param(nr_nodes, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(nr_nodes, "Number of nodes");

/* nr of connections per node (CONFIG_MAX_ALLOCATIONS) */
static unsigned int nr_conns = 100000;
module_param(nr_conns, uint, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(nr_conns, "Number of connections per node");

/* put delay in ms (for testing waits) */
static int put_delay_ms = 0;
module_param(put_delay_ms, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(put_delay_ms, "put delay in ms");

/* nr of threads spawned for test */
static int nr_lookup_threads = 1;
module_param(nr_lookup_threads, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(nr_lookup_threads, "Number of lookup threads");

/* nr of threads spawned for test */
static int nr_insert_threads = 1;
module_param(nr_insert_threads, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(nr_insert_threads, "Number of insert threads");

/* test threads */
struct task_struct **ktest_lookup, **ktest_insert, **ktest_getput, **ktest_clear;

typedef int (*thread_func_t) (void*);

typedef struct node_t {
    unsigned char       *ip;
    unsigned int        port;
    struct list_head    list;
}node_t;

struct list_head g_node_list;

/* get time delta */
    static inline s64
ktime_ns_delta(const ktime_t later, const ktime_t earlier)
{
    return ktime_to_ns(ktime_sub(later, earlier));
}

/* connection table */
struct cacheobj_conntable *g_conntable;

/* connection table operations */
static const struct cacheobj_conntable_operations *conn_ops =
&cacheobj_conntable_ops;

static int alloc_node_entries(void)
{
    int i = 0;

    while (i < nr_nodes) {
        node_t *node = (struct node_t*) kzalloc(sizeof(node_t), GFP_KERNEL);
        if (!node) {
            pr_err("err failed to allocated node\n");
            return -ENOMEM;
        }
        node->ip = HOSTIP;
        node->port = ++i;
        INIT_LIST_HEAD(&node->list);
        list_add(&node->list, &g_node_list);
        pr_info("node entry :<%s:%u>\n", node->ip, node->port);
    }
    pr_info("(%u) nodes allocated\n", nr_nodes);
    return 0;
}

static void destroy_node_entries(void)
{
    struct list_head *iter, *tmp;

    list_for_each_safe(iter, tmp, &g_node_list) {
        node_t *node = list_entry(iter, node_t, list);
        list_del(iter);
        kfree(node);
        nr_nodes--;
    }
    BUG_ON(nr_nodes != 0);
}

/* create and add entry */
static int _alloc_and_insert_entry(struct cacheobj_conntable *conntable,
        unsigned char *ip, unsigned int port)
{
    struct cacheobj_conntable_node *conn;

    conn = (struct cacheobj_conntable_node*) kzalloc
        (sizeof(struct cacheobj_conntable_node), GFP_KERNEL);
    if (!conn) {
        pr_err("failed to allocate object\n");
        return -ENOMEM;
    }

    cacheobj_conntable_node_init(conn, ip, port);
    //pr_info("new entry <%s:%u>\n", ip, port);

    // may fail because of invalid key parameters
    return conn_ops->cacheobj_conntable_insert(conntable, conn);
}

static inline void wait_for_kthread_stop(void)
{
    set_current_state(TASK_INTERRUPTIBLE);
    while (!kthread_should_stop()) {
        msleep(1000);
        yield();
        set_current_state(TASK_INTERRUPTIBLE);
    }
}

/* thread worker function to insert entries */
static int insert_test(void *arg)
{
    ktime_t start;
    unsigned long long items = 0, insert_ns;
    struct cacheobj_conntable *conntable = (struct cacheobj_conntable*) arg;
    node_t *node, *tmp;

    start = ktime_get();
    while(!list_empty(&g_node_list)) {
        list_for_each_entry_safe(node, tmp, &g_node_list, list) {
            if (kthread_should_stop())
                goto exit;
            if (_alloc_and_insert_entry(conntable, node->ip, node->port) < 0) {
                pr_err("insert failed (%llu)\n", items);
                goto exit;
            }
            items++;
            yield();
        }
#ifdef CONFIG_MAX_ALLOCATIONS
        if (items >= nr_conns * nr_nodes)
            break;
#endif
    }
exit:
    if (items) {
        insert_ns = ktime_ns_delta(ktime_get(), start)/items;
        pr_info("<nr_inserted :%llu, avg_time :%llu (ns)>\n", items, insert_ns);
    }
    wait_for_kthread_stop();
    return 0;
}

#ifdef CONFIG_LOOKUP_ONLY
/* lookup and clear entry */
static bool _find_and_delete_entry(struct cacheobj_conntable *conntable,
        unsigned char *ip, unsigned int port)
{
    struct cacheobj_conntable_node *conn;
    bool found = false;

    conn = conn_ops->cacheobj_conntable_lookup(conntable, ip, port);
    if (conn) {
        CONNTBL_ASSERT(!IS_ERR(conn));

#ifdef CONFIG_MAX_ALLOCATIONS // skip delete
        found = true;
#else
        if (conn_ops->cacheobj_conntable_remove(conntable, conn) == 0) {
            kfree(conn);
            found = true;
        }
#endif
    }
    return found;
}

/* thread worker function to lookup and delete entries */
static int lookup_test(void *arg)
{
    ktime_t start;
    node_t *node, *tmp;
    unsigned long long items = 0, success = 0, lookup_ns;
    struct cacheobj_conntable *conntable = (struct cacheobj_conntable*) arg;

    start = ktime_get();
    while(!list_empty(&g_node_list)) {
        list_for_each_entry_safe(node, tmp, &g_node_list, list) {
            if (kthread_should_stop())
                goto exit;
            if (_find_and_delete_entry(conntable, node->ip, node->port))
                success++;
            yield();
        }
    }
exit:
    lookup_ns = ktime_ns_delta(ktime_get(), start)/items;
    pr_info("<nr_lookups :%llu, hits :%llu avg_time :%llu (ns)>\n",
            items, success, lookup_ns);
    return 0;
}
#endif

/* lookup and clear entry */
static int _get_and_put_entry(struct cacheobj_conntable *conntable,
        unsigned char *ip, unsigned int port)
{
    struct cacheobj_conntable_node *conn;

    conn = conn_ops->cacheobj_conntable_timed_get(conntable, ip,
            port, WAIT_FOR_READY_CONN_TIMEOUT);
    if (!conn)
        return -ENOENT;
    if (IS_ERR(conn))
        return PTR_ERR(conn);

    /* trigger waits */
    if (put_delay_ms)
        msleep(put_delay_ms);

    conn_ops->cacheobj_conntable_put(conntable, conn);
    return 0;
}

/* thread worker function to get and put connection entries */
static int get_put_test(void *arg)
{
    int ret = 0;
    ktime_t start;
    node_t *node, *tmp;
    unsigned long long items = 0, success = 0, get_ns;
    struct cacheobj_conntable *conntable = (struct cacheobj_conntable*) arg;

    start = ktime_get();
    while(!list_empty(&g_node_list)) {
        list_for_each_entry_safe(node, tmp, &g_node_list, list) {
            if (kthread_should_stop())
                goto exit;
            ret = _get_and_put_entry(conntable, node->ip, node->port);
            if (ret && ret != -ENOENT)
                pr_err("get failed with %d\n", ret);
            else if (!ret)
                success++;
            items++;
            yield();
        }
	//msleep(50);
    }

exit:
    if (items) {
        get_ns = ktime_ns_delta(ktime_get(), start)/items;
        pr_info("<nr_gets :%llu, hits :%llu avg_time :%llu (ns)>\n",
            items, success, get_ns);
    }
    wait_for_kthread_stop();
    return 0;
}

/* thread worker function to clear table */
static int clear_test(void *arg)
{
    struct cacheobj_conntable *conntable = (struct cacheobj_conntable*) arg;
    while (!kthread_should_stop()) {
        conn_ops->cacheobj_conntable_destroy(conntable);
        msleep(5000);
        yield();
    }
    return 0;
}

/* stops all active threads */
static void stop_test_threads(struct task_struct **ktask,
        unsigned int nr_threads)
{
    unsigned int i;

    if (!ktask)
        return;

    for(i = 0; i < nr_threads; i++) {
        if (ktask[i] && !IS_ERR(ktask[i]))
        // Sets kthread_should_stop for k to return true, wakes it,
        // and waits for it to exit. Your threadfn must not call
        // do_exit itself if you use this function!
            kthread_stop(ktask[i]);
    }
    kfree(ktask);
}

static struct task_struct **spawn_test_threads(thread_func_t func, void *args,
        unsigned int nr_threads, const char* name)
{
    unsigned int i;
    struct task_struct **ktask;

    ktask = kzalloc(sizeof(struct task_struct *) * nr_threads, GFP_KERNEL);
    if (!ktask) {
        pr_err("failed to allocate threads\n");
        return NULL;
    }

    for(i = 0; i < nr_threads; i++) {
        ktask[i] = kthread_run(func, args, name);
        if (IS_ERR(ktask[i])) {
            pr_err("error launching kthread\n");
            goto err;
        }
    }
    return ktask;

err:
    stop_test_threads(ktask, nr_threads);
    return NULL;
}

static void stop_and_cleanup_module(void)
{
    pr_info("stopping stress test...\n");

    stop_test_threads(ktest_lookup, nr_lookup_threads);
    stop_test_threads(ktest_insert, nr_insert_threads);
    stop_test_threads(ktest_getput, nr_lookup_threads);
#ifdef CONFIG_MAX_ALLOCATIONS
    conn_ops->cacheobj_conntable_distribution_dump(g_conntable);
#endif
    if (conn_ops->cacheobj_conntable_destroy(g_conntable))
        pr_err("hash table is not empty !!!\n");
    destroy_node_entries();
}

static int __init start_module(void)
{
    int err = 0;

    pr_info("starting connection table stress test...\n");

    INIT_LIST_HEAD(&g_node_list);

    g_conntable = conn_ops->cacheobj_conntable_init();

    // free node entries only during cleanup module
    alloc_node_entries();

    ktest_insert = spawn_test_threads(insert_test, (void*)g_conntable,
            nr_insert_threads, "ktest_insert");
    if (!ktest_insert) {
        err = -ENOMEM;
        goto fail_startup;
    }

#ifdef CONFIG_LOOKUP_ONLY
    ktest_lookup = spawn_test_threads(lookup_test, (void*)g_conntable,
            nr_lookup_threads, "ktest_lookup");
    if (!ktest_lookup) {
        err = -ENOMEM;
        goto fail_startup;
    }
#endif

    ktest_getput = spawn_test_threads(get_put_test, (void*)g_conntable,
            nr_lookup_threads, "ktest_getput");
    if (!ktest_getput) {
        err = -ENOMEM;
        goto fail_startup;
    }

    ktest_clear = spawn_test_threads(clear_test, (void*)g_conntable,
            1, "ktest_clear");
    if (!ktest_clear) {
        err = -ENOMEM;
        goto fail_startup;
    }

    //pr_info("%lu:%lu\n", sizeof(struct cacheobj_conntable_pool),
    //sizeof(struct cacheobj_conntable_node));
    return 0;

fail_startup:
    stop_and_cleanup_module();
    return err;
}

module_init(start_module);
module_exit(stop_and_cleanup_module);
