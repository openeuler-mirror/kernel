// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */
#include <linux/spinlock.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/kref.h>
#include <linux/rculist.h>
#include <linux/types.h>
#include <linux/sunrpc/xprt.h>
#include <linux/sunrpc/clnt.h>
#include <linux/sunrpc/xprtmultipath.h>
#include "enfs_roundrobin.h"

#include "enfs.h"
#include "enfs_config.h"
#include "pm_state.h"
#include "enfs_proc.h"

typedef struct rpc_xprt *(*enfs_xprt_switch_find_xprt_t)(
	struct rpc_xprt_switch *xps, const struct rpc_xprt *cur);
static const struct rpc_xprt_iter_ops enfs_xprt_iter_roundrobin;
static const struct rpc_xprt_iter_ops enfs_xprt_iter_singular;

static bool enfs_xprt_is_active(struct rpc_xprt *xprt)
{
	enum enfs_path_state state;

	if (kref_read(&xprt->kref) <= 0)
		return false;

	state = pm_get_path_state(xprt);
	if (enfs_is_path_connected(state))
		return true;

	return false;
}

static struct rpc_xprt *
enfs_lb_set_cursor_xprt(struct rpc_xprt_switch *xps, struct rpc_xprt **cursor,
			enfs_xprt_switch_find_xprt_t find_next)
{
	struct rpc_xprt *pos;
	struct rpc_xprt *old;

	old = smp_load_acquire(cursor); // multi thread access
	pos = find_next(xps, old);
	smp_store_release(cursor, pos); // multi thread access
	return pos;
}

static struct rpc_xprt *
enfs_lb_find_next_entry_roundrobin(struct rpc_xprt_switch *xps,
				   const struct rpc_xprt *cur)
{
	struct rpc_xprt *pos;
	struct rpc_xprt *prev = NULL;
	bool found = false;
	struct rpc_xprt *min_queuelen_xprt = NULL;
	unsigned long pos_xprt_queuelen;
	unsigned long min_xprt_queuelen = 0;
	struct enfs_xprt_context *ctx;
	struct rpc_xprt *optimal_xprt = NULL;
	unsigned long optimal_queuelen = 0;
	int nativeLinkStatus = enfs_get_native_link_io_status();

	list_for_each_entry_rcu(pos, &xps->xps_xprt_list, xprt_switch) {
		if (!nativeLinkStatus && enfs_is_main_xprt(pos))
			continue;

		if (!enfs_xprt_is_active(pos)) {
			prev = pos;
			continue;
		}

		ctx = xprt_get_reserve_context(pos);
		pos_xprt_queuelen = atomic_long_read(&ctx->queuelen);
		if (min_queuelen_xprt == NULL ||
		    pos_xprt_queuelen < min_xprt_queuelen) {
			/* Find the xprt with the smallest number of IO in the full-linked list. */
			min_queuelen_xprt = pos;
			min_xprt_queuelen = pos_xprt_queuelen;
		}
		if (cur == prev)
			found = true;

		if (found && (optimal_xprt == NULL ||
			      optimal_queuelen < min_xprt_queuelen)) {
			/* From the subsequent linked list where the xprt has been selected,
			 * select the xprt for minimum IO
			 */
			if (min_xprt_queuelen == 0) {
				/* Minimum xprt, there is no need to traverse subsequent queues. */
				return pos;
			}
			optimal_xprt = pos;
			optimal_queuelen = pos_xprt_queuelen;
		}
		prev = pos;
	};
	if (optimal_xprt != NULL)
		return optimal_xprt;
	return min_queuelen_xprt;
}

struct rpc_xprt *
enfs_lb_switch_find_first_active_xprt(struct rpc_xprt_switch *xps)
{
	struct rpc_xprt *pos;

	list_for_each_entry_rcu(pos, &xps->xps_xprt_list, xprt_switch) {
		if (enfs_xprt_is_active(pos))
			return pos;
	};
	return NULL;
}

struct rpc_xprt *enfs_lb_switch_get_main_xprt(struct rpc_xprt_switch *xps)
{
	return list_first_or_null_rcu(&xps->xps_xprt_list, struct rpc_xprt,
				      xprt_switch);
}

static struct rpc_xprt *
enfs_lb_switch_get_next_xprt_roundrobin(struct rpc_xprt_switch *xps,
					const struct rpc_xprt *cur)
{
	struct rpc_xprt *xprt;

	// disable multipath
	if (enfs_get_config_multipath_state())
		return enfs_lb_switch_get_main_xprt(xps);

	xprt = enfs_lb_find_next_entry_roundrobin(xps, cur);
	if (xprt != NULL)
		return xprt;
	return enfs_lb_switch_get_main_xprt(xps);
}

static struct rpc_xprt *
enfs_lb_iter_next_entry_roundrobin(struct rpc_xprt_iter *xpi)
{
	struct rpc_xprt_switch *xps = rcu_dereference(xpi->xpi_xpswitch);

	if (xps == NULL)
		return NULL;

	return enfs_lb_set_cursor_xprt(xps, &xpi->xpi_cursor,
				       enfs_lb_switch_get_next_xprt_roundrobin);
}

static struct rpc_xprt *
enfs_lb_switch_find_singular_entry(struct rpc_xprt_switch *xps,
				   const struct rpc_xprt *cur)
{
	struct rpc_xprt *pos;
	bool found = false;

	list_for_each_entry_rcu(pos, &xps->xps_xprt_list, xprt_switch) {
		if (cur == pos)
			found = true;
		if (found && enfs_xprt_is_active(pos))
			return pos;
	}
	return NULL;
}

struct rpc_xprt *enfs_lb_get_singular_xprt(struct rpc_xprt_switch *xps,
					   const struct rpc_xprt *cur)
{
	struct rpc_xprt *xprt;

	if (xps == NULL)
		return NULL;
	// disable multipath
	if (enfs_get_config_multipath_state())
		return enfs_lb_switch_get_main_xprt(xps);

	if (cur == NULL || xps->xps_nxprts < 2) {
		xprt = enfs_lb_switch_find_first_active_xprt(xps);
		if (!xprt)
			goto main_xprt;
		return xprt;
	}

	xprt = enfs_lb_switch_find_singular_entry(xps, cur);
	if (!xprt) {
		xprt = enfs_lb_switch_find_first_active_xprt(xps);
		if (!xprt)
			goto main_xprt;
	}
	return xprt;

main_xprt:
	return enfs_lb_switch_get_main_xprt(xps);
}

static struct rpc_xprt *
enfs_lb_iter_next_entry_sigular(struct rpc_xprt_iter *xpi)
{
	struct rpc_xprt_switch *xps = rcu_dereference(xpi->xpi_xpswitch);

	if (xps == NULL)
		return NULL;

	return enfs_lb_set_cursor_xprt(xps, &xpi->xpi_cursor,
				       enfs_lb_get_singular_xprt);
}

static void enfs_lb_iter_default_rewind(struct rpc_xprt_iter *xpi)
{
	WRITE_ONCE(xpi->xpi_cursor, NULL);
}

static void enfs_lb_switch_set_roundrobin(struct rpc_clnt *clnt)
{
	struct rpc_xprt_switch *xps;
	const struct rpc_xprt_iter_ops *ops;

	rcu_read_lock();
	xps = rcu_dereference(clnt->cl_xpi.xpi_xpswitch);
	if (xps && READ_ONCE(xps->xps_nxprts)) {
		ops = clnt->cl_vers == 3 ? &enfs_xprt_iter_roundrobin :
					 &enfs_xprt_iter_singular;
		WRITE_ONCE(xps->xps_iter_ops, ops);
	}
	rcu_read_unlock();
}

static struct rpc_xprt *enfs_lb_switch_find_current(struct list_head *head,
						    const struct rpc_xprt *cur)
{
	struct rpc_xprt *pos;

	list_for_each_entry_rcu(pos, head, xprt_switch) {
		if (cur == pos)
			return pos;
	}
	return NULL;
}

static struct rpc_xprt *enfs_lb_iter_current_entry(struct rpc_xprt_iter *xpi)
{
	struct rpc_xprt_switch *xps = rcu_dereference(xpi->xpi_xpswitch);
	struct list_head *head;

	if (xps == NULL)
		return NULL;
	head = &xps->xps_xprt_list;
	if (xpi->xpi_cursor == NULL || xps->xps_nxprts < 2)
		return enfs_lb_switch_get_main_xprt(xps);
	return enfs_lb_switch_find_current(head, xpi->xpi_cursor);
}

int enfs_lb_set_policy(struct rpc_clnt *clnt, void *data)
{
	if (clnt->cl_enfs == 1)
		enfs_lb_switch_set_roundrobin(clnt);

	return 0;
}

static const struct rpc_xprt_iter_ops enfs_xprt_iter_roundrobin = {
	.xpi_rewind = enfs_lb_iter_default_rewind,
	.xpi_xprt = enfs_lb_iter_current_entry,
	.xpi_next = enfs_lb_iter_next_entry_roundrobin,
};

static const struct rpc_xprt_iter_ops enfs_xprt_iter_singular = {
	.xpi_rewind = enfs_lb_iter_default_rewind,
	.xpi_xprt = enfs_lb_iter_current_entry,
	.xpi_next = enfs_lb_iter_next_entry_sigular,
};

const struct rpc_xprt_iter_ops *enfs_xprt_rr_ops(void)
{
	return &enfs_xprt_iter_roundrobin;
}

const struct rpc_xprt_iter_ops *enfs_xprt_singular_ops(void)
{
	return &enfs_xprt_iter_singular;
}

bool enfs_is_rr_route(struct rpc_clnt *clnt)
{
	bool ret = false;
	struct rpc_xprt_switch *xps;

	rcu_read_lock();
	xps = rcu_dereference(clnt->cl_xpi.xpi_xpswitch);
	if (!xps || !xps->xps_iter_ops) {
		rcu_read_unlock();
		return ret;
	}
	if (xps->xps_iter_ops == &enfs_xprt_iter_roundrobin)
		ret = true;
	rcu_read_unlock();

	return ret;
}

bool enfs_is_singularr_route(struct rpc_clnt *clnt)
{
	bool ret = false;
	struct rpc_xprt_switch *xps;

	rcu_read_lock();
	xps = rcu_dereference(clnt->cl_xpi.xpi_xpswitch);
	if (!xps || !xps->xps_iter_ops) {
		rcu_read_unlock();
		return ret;
	}
	if (xps->xps_iter_ops == &enfs_xprt_iter_singular)
		ret = true;
	rcu_read_unlock();

	return ret;
}

int enfs_lb_revert_policy(struct rpc_clnt *clnt, void *data)
{
	struct rpc_xprt_switch *xps;

	if (clnt->cl_enfs == 1) {
		rcu_read_lock();
		xps = rcu_dereference(clnt->cl_xpi.xpi_xpswitch);
		rcu_read_unlock();
		rpc_xprt_switch_set_singular(xps);
	}

	return 0;
}

int enfs_lb_init(void)
{
	enfs_iter_rpc_clnt(enfs_lb_set_policy, NULL);

	return 0;
}

void enfs_lb_exit(void)
{
	enfs_iter_rpc_clnt(enfs_lb_revert_policy, NULL);
}
