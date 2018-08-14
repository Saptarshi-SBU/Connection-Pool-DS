/* Connection table unit tests for insert, lookup, delete operations
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
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include "conntable.h"
#include "stat.h"

MODULE_LICENSE("GPL");

#define CONFIG_MAX_ALLOCATIONS
//#define CONFIG_DELETE
//#define CONFIG_CLEANUP

#define HOSTIP	"127.0.0.1"

#define WAIT_FOR_READY_CONN_TIMEOUT (5 * HZ)
//#define WAIT_FOR_READY_CONN_TIMEOUT (1/1000 * HZ)

#define PROCFS_CONNTABLE_TESTDIR "fs/cacheobjs_test"
#define PROCFS_CONNTABLE_TEST_PATH "fs/cacheobjs_test/conntable"

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

/* nr of threads spawned for test */
static int nr_cleanup_threads = 1;
module_param(nr_cleanup_threads, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(nr_cleanup_threads, "Number of cleanup threads");

/* test threads */
struct task_struct **ktest_lookup, **ktest_insert, **ktest_getput, **ktest_clear;

typedef int (*thread_func_t) (void*);

/* target node */
typedef struct node_t {
    unsigned char       *ip;
    unsigned int        port;
    struct list_head    list;
}node_t;

/* target node list */
struct list_head g_node_list;

/* connection table */
struct cacheobj_conntable glob_conntable, *g_conntable;

/* connection table operations */
static const struct cacheobj_conntable_operations *conn_ops =
	&cacheobj_conntable_ops;

/* get time delta */
static inline s64
ktime_ns_delta(const ktime_t later, const ktime_t earlier)
{
    return ktime_to_ns(ktime_sub(later, earlier));
}

static int _alloc_target_nodes(void)
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
        pr_info("new target: <%s:%u>\n", node->ip, node->port);
    }
    pr_info("(%u) nodes allocated\n", nr_nodes);
    return 0;
}

static void _destroy_target_nodes(void)
{
    node_t *node, *tmp;

    list_for_each_entry_safe(node, tmp, &g_node_list, list) {
        list_del(&node->list);
        kfree(node);
        nr_nodes--;
    }
    CONNTBL_ASSERT(nr_nodes == 0);
}

/* create and add entry */
static int _alloc_and_insert_entry(struct cacheobj_conntable *conntable,
        unsigned char *ip, unsigned int port)
{
    struct cacheobj_connection_node *conn;

    conn = (struct cacheobj_connection_node*) kzalloc
        (sizeof(struct cacheobj_connection_node), GFP_KERNEL);
    if (!conn) {
        pr_err("failed to allocate object\n");
        return -ENOMEM;
    }

    cacheobj_connection_node_init(conn, ip, port);
    return conn_ops->cacheobj_conntable_insert(conntable, conn);
}

static inline void _wait_for_kthread_stop(void)
{
    set_current_state(TASK_INTERRUPTIBLE);
    while (!kthread_should_stop()) {
        msleep(1000);
        yield();
        set_current_state(TASK_INTERRUPTIBLE);
    }
}

/* thread worker function to insert entries */
static int threadfn_test_insert(void *arg)
{
    ktime_t start;
    node_t *node, *tmp;
    unsigned long long items = 0;
    struct cacheobj_conntable *conntable = (struct cacheobj_conntable*) arg;

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
    pr_info("<nr_inserted :%llu, avg_time :%lu (ns)>\n", items,
	div64_safe(ktime_ns_delta(ktime_get(), start), items));
    _wait_for_kthread_stop();
    return 0;
}

#ifdef CONFIG_DELETE
/* lookup and clear entry */
static bool _find_and_delete_entry(struct cacheobj_conntable *conntable,
        unsigned char *ip, unsigned int port)
{
    struct cacheobj_connection_node *conn;
    bool deleted = false;

    conn = conn_ops->cacheobj_conntable_lookup(conntable, ip, port);
    if (conn) {
        CONNTBL_ASSERT(!IS_ERR(conn));
        if (conn_ops->cacheobj_conntable_remove(conntable, conn) == 0) {
            kfree(conn);
            deleted = true;
        }
    }
    return deleted;
}

/* thread worker function to lookup and delete entries */
static int threadfn_test_delete(void *arg)
{
    ktime_t start;
    node_t *node, *tmp;
    unsigned long long items = 0, success = 0;
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
    pr_info("<nr_lookups :%llu, hits :%llu avg_time :%llu (ns)>\n", items,
            success, div64_safe(ktime_ns_delta(ktime_get(), start), items));
    return 0;
}
#endif

/* lookup and clear entry */
static int _get_and_put_entry(struct cacheobj_conntable *conntable,
        unsigned char *ip, unsigned int port)
{
    struct cacheobj_connection_node *conn;

    conn = conn_ops->cacheobj_conntable_timed_get(conntable, ip, port,
	WAIT_FOR_READY_CONN_TIMEOUT);
    if (!conn)
        return -ENOENT;

    if (IS_ERR(conn))
        return PTR_ERR(conn);

    /* inject delay */
    if (put_delay_ms)
        msleep(put_delay_ms);

    conn_ops->cacheobj_conntable_put(conntable, conn, GET);
    return 0;
}

/* thread worker function to get and put connection entries */
static int threadfn_test_getput(void *arg)
{
    int err = 0;
    ktime_t start;
    node_t *node, *tmp;
    unsigned long long items = 0, success = 0;
    struct cacheobj_conntable *conntable = (struct cacheobj_conntable*) arg;

    start = ktime_get();
    while(!list_empty(&g_node_list)) {
        list_for_each_entry_safe(node, tmp, &g_node_list, list) {
            if (kthread_should_stop())
                goto exit;

            err = _get_and_put_entry(conntable, node->ip, node->port);
            if (err && err != -ENOENT)
                pr_err("get failed with %d\n", err);
            else if (!err)
                success++;

            items++;
            yield();
        }
	//msleep(50);
    }

exit:
    pr_info("<nr_gets :%llu, hits :%llu avg_time :%lu (ns)>\n", items,
            success, div64_safe(ktime_ns_delta(ktime_get(), start), items));
    _wait_for_kthread_stop();
    return 0;
}

#ifdef CONFIG_CLEANUP
/* thread worker function to clear table */
static int threadfn_test_clear(void *arg)
{
    struct cacheobj_conntable *conntable = (struct cacheobj_conntable*) arg;
    while (!kthread_should_stop()) {
        conn_ops->cacheobj_conntable_destroy(conntable);
        msleep(1000);
        yield();
    }
    return 0;
}
#endif

/* stops all active threads */
static void stop_test_threads(struct task_struct **ktask,
        unsigned int nr_threads)
{
    unsigned int i;

    if (!ktask)
        return;

    for(i = 0; i < nr_threads; i++) {
        // Sets kthread_should_stop for k to return true, wakes it,
        // and waits for it to exit. Your threadfn must not call
        // do_exit itself if you use this function!
        if (ktask[i] && !IS_ERR(ktask[i]))
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

static int test_proc_dump(struct seq_file *m, void *v)
{
    conn_ops->cacheobj_conntable_dump(g_conntable, m);
    return 0;
}

static int test_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, test_proc_dump, NULL);
}

static const struct file_operations test_proc_fops = {
    .owner      = THIS_MODULE,
    .open       = test_proc_open,
    .read       = seq_read,
    .llseek     = seq_lseek,
    .release    = single_release,
};

static void stop_and_cleanup_module(void)
{
    pr_info("stopping stress test...\n");

    stop_test_threads(ktest_lookup, nr_lookup_threads);
    stop_test_threads(ktest_insert, nr_insert_threads);
    stop_test_threads(ktest_getput, nr_lookup_threads);
    stop_test_threads(ktest_clear, nr_cleanup_threads);
    if (conn_ops->cacheobj_conntable_destroy(g_conntable))
        pr_err("hash table is not empty !!!\n");
    _destroy_target_nodes();
    remove_proc_subtree(PROCFS_CONNTABLE_TESTDIR, NULL);
}

static int __init start_module(void)
{
    int err = 0;

    pr_info("starting connection table stress test...\n");

    INIT_LIST_HEAD(&g_node_list);
    conn_ops->cacheobj_conntable_init(&glob_conntable);
    g_conntable = &glob_conntable;

    // free node entries only during cleanup module
    _alloc_target_nodes();

    ktest_insert = spawn_test_threads(threadfn_test_insert, (void*)g_conntable,
            nr_insert_threads, "ktest_insert");
    if (!ktest_insert) {
        err = -ENOMEM;
        goto fail_startup;
    }

#ifdef CONFIG_DELETE
    ktest_lookup = spawn_test_threads(threadfn_test_delete, (void*)g_conntable,
            nr_lookup_threads, "ktest_lookup");
    if (!ktest_lookup) {
        err = -ENOMEM;
        goto fail_startup;
    }
#endif

    ktest_getput = spawn_test_threads(threadfn_test_getput, (void*)g_conntable,
            nr_lookup_threads, "ktest_getput");
    if (!ktest_getput) {
        err = -ENOMEM;
        goto fail_startup;
    }

#ifdef CONFIG_CLEANUP
    ktest_clear = spawn_test_threads(threadfn_test_clear, (void*)g_conntable,
            nr_cleanup_threads, "ktest_clear");
    if (!ktest_clear) {
        err = -ENOMEM;
        goto fail_startup;
    }
#endif

    // setup proc for stats
    if (!proc_mkdir(PROCFS_CONNTABLE_TESTDIR, NULL) ||
	!proc_create(PROCFS_CONNTABLE_TEST_PATH, 0, NULL, &test_proc_fops)) {
        err = -ENOMEM;
        goto fail_startup;
    }
    return 0;

fail_startup:
    stop_and_cleanup_module();
    return err;
}

module_init(start_module);
module_exit(stop_and_cleanup_module);
