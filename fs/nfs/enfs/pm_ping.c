// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#include "pm_ping.h"
#include <linux/err.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/kthread.h>
#include <linux/nfs.h>
#include <linux/errno.h>
#include <linux/rcupdate.h>
#include <linux/workqueue.h>
#include <net/netns/generic.h>
#include <linux/atomic.h>
#include <linux/sunrpc/clnt.h>

#include "../../../net/sunrpc/netns.h"
#include "pm_state.h"
#include "enfs.h"
#include "enfs_log.h"
#include "enfs_config.h"

#define SLEEP_INTERVAL 2

static struct task_struct *pm_ping_timer_thread;
static struct workqueue_struct *ping_execute_workq;	// timer for test xprt workqueue
static atomic_t check_xprt_count;	// count the ping xprt work on flight

struct ping_xprt_work {
	struct rpc_xprt *xprt;	// use this specific xprt
	struct rpc_clnt *clnt;	// use this specific rpc_client
	struct work_struct ping_work;
};

struct pm_ping_async_callback {
	void *data;
	void (*func)(void *data);
};

// set xprt's enfs_pm_check_state
void pm_ping_set_path_check_state(struct rpc_xprt *xprt, enum enfs_pm_check_state state)
{
	struct enfs_xprt_context *ctx = NULL;

	if (IS_ERR(xprt)) {
		enfs_log_error("The xprt ptr is not exist.\n");
		return;
	}

	if (xprt == NULL) {
		enfs_log_error("The xprt is not valid.\n");
		return;
	}

	xprt_get(xprt);

	ctx = (struct enfs_xprt_context *)xprt_get_reserve_context(xprt);
	if (ctx == NULL) {
		enfs_log_error("The xprt multipath ctx is not valid.\n");
		xprt_put(xprt);
		return;
	}

	atomic_set(&ctx->path_check_state, state);
	xprt_put(xprt);

}

// get xprt's enfs_pm_check_state
static enum enfs_pm_check_state pm_ping_get_path_check_state(struct rpc_xprt *xprt)
{
	struct enfs_xprt_context *ctx = NULL;
	enum enfs_pm_check_state state;

	if (xprt == NULL) {
		enfs_log_error("The xprt is not valid.\n");
		return PM_CHECK_UNDEFINE;
	}

	ctx = (struct enfs_xprt_context *)xprt_get_reserve_context(xprt);
	if (ctx == NULL) {
		enfs_log_error("The xprt multipath ctx is not valid.\n");
		return PM_CHECK_UNDEFINE;
	}

	state = atomic_read(&ctx->path_check_state);

	return state;
}

static void pm_ping_call_done_callback(void *data)
{
	struct pm_ping_async_callback *callback_data =
		(struct pm_ping_async_callback *)data;
	if (callback_data == NULL)
		return;
	callback_data->func(callback_data->data);

	kfree(callback_data);
}

static void set_xprt_close_wait(struct rpc_xprt *xprt)
{
	if (xprt == NULL) {
		enfs_log_error("The xprt is not valid.\n");
		return;
	}

	xprt_get(xprt);
	set_bit(XPRT_CLOSE_WAIT, &xprt->state);
	xprt_put(xprt);

}

static inline s8 enfs_get_next_time_idx(s8 idx)
{
	return (idx + 1) % (ENFS_RECONNECT_TIME_CNT + 1);
}

static inline bool enfs_is_time_buf_empty(struct enfs_reconnect_time *time)
{
	return time->head == time->tail;
}

static inline bool enfs_is_time_buf_full(struct enfs_reconnect_time *time)
{
	return enfs_get_next_time_idx(time->head) == time->tail;
}

static void
enfs_update_reconnect_time(
	struct enfs_reconnect_time *time,
	s64 now_ms,
	unsigned int cookie)
{
	bool is_reconnect = false;

	if (time->xprt_cookie && time->xprt_cookie != cookie)
		is_reconnect = true;
	time->xprt_cookie = cookie;
	if (is_reconnect) {
		/* store reconnect time */
		time->time[time->head] = now_ms;
		time->head = enfs_get_next_time_idx(time->head);
		/* array is full */
		if (time->head == time->tail)
			time->tail = enfs_get_next_time_idx(time->tail);
	}

	while (time->tail != time->head) {
		if (now_ms - time->time[time->tail] <
		    ENFS_UNSTABLE_STATE_TIMEOUT * 1000)
			break;
		/* timed out */
		time->tail = enfs_get_next_time_idx(time->tail);
	}
}

static enum enfs_path_state
enfs_reconnect_next_state(enum enfs_path_state curr_state, bool is_empty,
			  bool is_full)
{
	bool is_normal;

	is_normal = curr_state == PM_STATE_INIT ||
		    (is_empty && curr_state == PM_STATE_UNSTABLE) ||
		    (!is_full && (curr_state == PM_STATE_NORMAL ||
				  curr_state == PM_STATE_FAULT));

	return is_normal ? PM_STATE_NORMAL : PM_STATE_UNSTABLE;
}

static void enfs_check_reconnect(struct rpc_xprt *xprt)
{
	struct enfs_xprt_context *ctx = NULL;
	struct enfs_reconnect_time *time;
	bool is_empty, is_full;
	enum enfs_path_state curr_state = pm_get_path_state(xprt);
	enum enfs_path_state next_state;

	xprt_get(xprt);

	ctx = (struct enfs_xprt_context *)xprt_get_reserve_context(xprt);
	if (ctx == NULL) {
		enfs_log_error("The xprt multipath ctx is not valid.\n");
		goto out;
	}

	time = &ctx->reconnect_time;
	enfs_update_reconnect_time(time, ktime_to_ms(ktime_get()), xprt->connect_cookie);
	is_empty = enfs_is_time_buf_empty(time);
	is_full = enfs_is_time_buf_full(time);

	next_state = enfs_reconnect_next_state(curr_state, is_empty, is_full);
	pm_set_path_state(xprt, next_state);

out:
	xprt_put(xprt);
}

#if IS_ENABLED(CONFIG_ENFS_KUNIT_TEST)
bool enfs_test_reconnect_time(void)
{
	bool ret = true;
	bool match;
	s64 begin_ms = ktime_to_ms(ktime_get());
	s64 ms;
	unsigned int cookie = 1;
	struct enfs_reconnect_time time = {
		.head = 0,
		.tail = 0,
		.xprt_cookie = 0,
	};

	enfs_log_info("begin time: %lld ms\n", begin_ms);

	ms = begin_ms;
	enfs_log_info("%lld ms, cookie:%d\n", ms, cookie);
	enfs_update_reconnect_time(&time, ms, cookie);
	match = enfs_is_time_buf_empty(&time);
	if (!match)
		return false;

	ms = begin_ms + 1000;
	cookie += 1;
	enfs_log_info("%lld ms, cookie:%d\n", ms, cookie);
	enfs_update_reconnect_time(&time, ms, cookie);
	match = time.head == 1 && time.tail == 0;
	if (!match)
		return false;

	ms = begin_ms + 2000;
	cookie += 1;
	enfs_log_info("%lld ms, cookie:%d\n", ms, cookie);
	enfs_update_reconnect_time(&time, ms, cookie);
	match = time.head == 2 && time.tail == 0;
	if (!match)
		return false;

	ms = begin_ms + 3000;
	cookie += 1;
	enfs_log_info("%lld ms, cookie:%d\n", ms, cookie);
	enfs_update_reconnect_time(&time, ms, cookie);
	match = time.head == 3 && time.tail == 0;
	if (!match)
		return false;

	ms = begin_ms + 4000;
	cookie += 1;
	enfs_log_info("%lld ms, cookie:%d\n", ms, cookie);
	enfs_update_reconnect_time(&time, ms, cookie);
	match = time.head == 0 && time.tail == 1;
	if (!match)
		return false;
	match = enfs_is_time_buf_full(&time);
	if (!match)
		return false;

	ms = begin_ms + 5000;
	/* cookie remains unchanged */
	enfs_log_info("%lld ms, cookie:%d\n", ms, cookie);
	enfs_update_reconnect_time(&time, ms, cookie);
	match = time.head == 0 && time.tail == 1;
	if (!match)
		return false;

	ms = begin_ms + 5000 + ENFS_UNSTABLE_STATE_TIMEOUT * 1000 + 1;
	cookie += 1;
	enfs_log_info("%lld ms, cookie:%d\n", ms, cookie);
	enfs_update_reconnect_time(&time, ms, cookie);
	match = time.head == 1 && time.tail == 0;
	if (!match)
		return false;

	return ret;
}

bool enfs_test_fault_recovery_state(void)
{
	/* A recovered fault is normal until the reconnect limit is reached. */
	if (enfs_reconnect_next_state(PM_STATE_FAULT, false, false) !=
	    PM_STATE_NORMAL)
		return false;
	if (enfs_reconnect_next_state(PM_STATE_FAULT, false, true) !=
	    PM_STATE_UNSTABLE)
		return false;

	return true;
}
#endif

// Default callback for async RPC calls
static void pm_ping_call_done(struct rpc_task *task, void *data)
{
	struct rpc_xprt *xprt = task->tk_xprt;
	struct enfs_xprt_context *ctx = NULL;
	ktime_t ktime;

	atomic_dec(&check_xprt_count);
	if (task->tk_status >= 0) {
		enfs_check_reconnect(xprt);
	} else {
		set_xprt_close_wait(xprt);
		pm_set_path_state(xprt, PM_STATE_FAULT);
	}
	pm_ping_set_path_check_state(xprt, PM_CHECK_FINISH);

	pm_ping_call_done_callback(data);

	xprt_get(xprt);
	ctx = (struct enfs_xprt_context *)xprt_get_reserve_context(xprt);
	if (ctx == NULL) {
		enfs_log_error("The xprt multipath ctx is not valid.\n");
		xprt_put(xprt);
		return;
	}
	ktime = ktime_get();
	ctx->lastTime = ktime_to_ms(ktime);
	xprt_put(xprt);
}

// register func to rpc_call_done
static const struct rpc_call_ops pm_ping_set_status_ops = {
	.rpc_call_done = pm_ping_call_done,
};

// execute work which in work_queue
static void pm_ping_execute_work(struct work_struct *work)
{
	int ret = 0;

	// get the work information
	struct ping_xprt_work *work_info =
		container_of(work, struct ping_xprt_work, ping_work);

	// if check state is pending
	if (pm_ping_get_path_check_state(work_info->xprt) == PM_CHECK_WAITING) {
		pm_ping_set_path_check_state(work_info->xprt,
						 PM_CHECK_CHECKING);
		ret = rpc_clnt_test_xprt(work_info->clnt, work_info->xprt,
					 &pm_ping_set_status_ops, NULL,
					 RPC_TASK_ASYNC | RPC_TASK_FIXED);
		if (ret != 1) {
			enfs_log_debug("ping xprt execute failed ,ret %d", ret);
			pm_ping_set_path_check_state(work_info->xprt,
							 PM_CHECK_FINISH);
		} else {
			atomic_inc(&check_xprt_count);
		}
	}

	rpc_release_client(work_info->clnt);
	xprt_put(work_info->xprt);
	kfree(work_info);
}

// init test work and add this work to workqueue
static int pm_ping_add_work(struct rpc_clnt *clnt, struct rpc_xprt *xprt,
				void *data)
{
	struct list_head *head = data;
	struct rpcclnt_release_item *item;
	struct ping_xprt_work *work_info;
	struct enfs_xprt_context *ctx = NULL;
	bool ret = false;

	if (IS_ERR(xprt) || xprt == NULL) {
		enfs_log_error("The xprt ptr is not exist.\n");
		return -EINVAL;
	}

	if (IS_ERR(clnt) || clnt == NULL) {
		enfs_log_error("The clnt ptr is not exist.\n");
		return -EINVAL;
	}

	if (!xprt_get_reserve_context(xprt))
		return -EINVAL;

	ctx = (struct enfs_xprt_context *)xprt_get_reserve_context(xprt);
	if (ctx == NULL) {
		enfs_log_error("The xprt multipath ctx is not valid.\n");
		return -EINVAL;
	}

	if (!enfs_timeout_ms
		((ktime_t *) &ctx->lastTime, ENFS_PM_PING_TMIE_OUT * 1000)) {
		return 0;
	}

	if (pm_ping_get_path_check_state(xprt) == PM_CHECK_FINISH ||
		pm_ping_get_path_check_state(xprt) == PM_CHECK_INIT) {
		/* check xprt pending status, if pending status equals Finish,
		 * means this xprt can inster to work queue
		 */
		enfs_log_debug("find xprt pointer.   %p\n", xprt);
		work_info = kzalloc(sizeof(struct ping_xprt_work), GFP_ATOMIC);
		if (work_info == NULL)
			return -ENOMEM;

		item = kzalloc(sizeof(*item), GFP_KERNEL);
		if (!item) {
			enfs_log_error("alloc item failed.\n");
			kfree(work_info);
			return -ENOMEM;
		}

		work_info->clnt = clnt;
		work_info->xprt = xprt;
		xprt_get(xprt);
		INIT_WORK(&work_info->ping_work, pm_ping_execute_work);
		pm_ping_set_path_check_state(xprt, PM_CHECK_WAITING);
		if (!refcount_inc_not_zero(&clnt->cl_count)) {
			xprt_put(work_info->xprt);
			kfree(item);
			kfree(work_info);
			return 0;
		}

		ret = queue_work(ping_execute_workq, &work_info->ping_work);
		if (!ret) {
			item->clnt = work_info->clnt;
			list_add_tail(&item->node, head);
			xprt_put(work_info->xprt);
			kfree(work_info);
			return -EINVAL;
		}

		/* Note:that normal exit requires release. */
		kfree(item);
	}
	return 0;
}

// encapsulate pm_ping_add_work()
static int pm_ping_execute_xprt_test(struct rpc_clnt *clnt,
					 struct rpc_xprt *xprt, void *data)
{
	pm_ping_add_work(clnt, xprt, data);
	// return 0 for rpc_clnt_iterate_for_each_xprt(clnt,
	// pm_ping_execute_xprt_test, NULL); because negative value will stop
	// iterate all xprt and we need return negative value for debug Therefore,
	// we need this function to iterate all xprt
	return 0;
}

// iterate xprt in the client
static void pm_ping_loop_rpclnt(struct sunrpc_net *sn)
{
	struct rpc_clnt *clnt;
	LIST_HEAD(free_list);

	spin_lock(&sn->rpc_client_lock);
	list_for_each_entry_rcu(clnt, &sn->all_clients, cl_clients) {
		if (clnt->cl_enfs == 1) {
			enfs_log_debug("find rpc_clnt.   %p\n", clnt);
			rpc_clnt_iterate_for_each_xprt(clnt, pm_ping_execute_xprt_test,
							   (void *)&free_list);
		}
	}
	spin_unlock(&sn->rpc_client_lock);
	enfs_destroy_rpcclnt_list(&free_list);
}

// iterate each clnt in the sunrpc_net
static void pm_ping_loop_sunrpc_net(void)
{
	struct net *net;
	struct sunrpc_net *sn;

	rcu_read_lock();
	for_each_net_rcu(net) {
		sn = net_generic(net, sunrpc_net_id);
		if (sn == NULL)
			continue;
		pm_ping_loop_rpclnt(sn);
	}
	rcu_read_unlock();
}

static int pm_ping_routine(void *data)
{
	ktime_t start = ktime_get();
	int32_t interval_ms;

	while (!kthread_should_stop()) {
		interval_ms = enfs_get_config_path_detect_interval() * 1000;
		if (enfs_get_config_multipath_state() == ENFS_MULTIPATH_ENABLE
			&& enfs_timeout_ms(&start, interval_ms)) {
			start = ktime_get();
			pm_ping_loop_sunrpc_net();
		}
		enfs_msleep(1000);
	}
	return 0;
}

// start thread to cycly ping
static int pm_ping_start(void)
{
	pm_ping_timer_thread =
		kthread_run(pm_ping_routine, NULL, "pm_ping_routine");
	if (IS_ERR(pm_ping_timer_thread)) {
		enfs_log_error("Failed to create kernel thread\n");
		return PTR_ERR(pm_ping_timer_thread);
	}
	return 0;
}

// initialize workqueue
static int pm_ping_workqueue_init(void)
{
	ping_execute_workq = create_workqueue("pm_ping_workqueue");
	if (!ping_execute_workq) {
		enfs_log_error("create workqueue failed.\n");
		return -ENOMEM;
	}

	enfs_log_info("create workqueue succeeded.\n");
	return 0;
}

static void pm_ping_workqueue_fini(void)
{
	enfs_log_info("delete work queue\n");

	if (ping_execute_workq)
		destroy_workqueue(ping_execute_workq);
}

// module exit func
void pm_ping_fini(void)
{
	if (pm_ping_timer_thread)
		kthread_stop(pm_ping_timer_thread);

	pm_ping_workqueue_fini();

	while (atomic_read(&check_xprt_count) != 0)
		enfs_msleep(SLEEP_INTERVAL);

}

// module init func
int pm_ping_init(void)
{
	int ret;

	atomic_set(&check_xprt_count, 0);
	ret = pm_ping_workqueue_init();
	if (ret != 0) {
		enfs_log_error("PM_PING Module loading failed.\n");
		return ret;
	}
	ret = pm_ping_start();
	if (ret != 0) {
		enfs_log_error("PM_PING Module loading failed.\n");
		pm_ping_workqueue_fini();
		return ret;
	}

	return ret;
}

bool pm_ping_is_test_xprt_task(struct rpc_task *task)
{
	return task->tk_ops == &pm_ping_set_status_ops ? true : false;
}

int pm_ping_rpc_test_xprt_with_callback(struct rpc_clnt *clnt,
					struct rpc_xprt *xprt,
					void (*func)(void *data), void *data)
{
	int ret;
	struct pm_ping_async_callback *callback_data =
		(struct pm_ping_async_callback *)
		kzalloc(sizeof(struct pm_ping_async_callback), GFP_KERNEL);
	if (callback_data == NULL) {
		enfs_log_error("failed to mzalloc mem\n");
		return -ENOMEM;
	}

	callback_data->data = data;
	callback_data->func = func;
	atomic_inc(&check_xprt_count);
	ret =
		rpc_clnt_test_xprt(clnt, xprt, &pm_ping_set_status_ops,
				   callback_data, RPC_TASK_ASYNC | RPC_TASK_FIXED);
	if (ret != 1) {
		enfs_log_debug("ping xprt execute failed ,ret %d", ret);
		atomic_dec(&check_xprt_count);
	}

	return ret;
}
