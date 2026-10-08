/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#ifndef PM_PING_H
#define PM_PING_H

#include <linux/sunrpc/clnt.h>

enum enfs_pm_check_state {
	PM_CHECK_INIT,		// this xprt never been queued
	PM_CHECK_WAITING,	// this xprt waiting in the queue
	PM_CHECK_CHECKING,	// this xprt is testing
	PM_CHECK_FINISH,	// this xprt has been finished
	PM_CHECK_UNDEFINE,	// undefine multipath struct
};

int pm_ping_init(void);
void pm_ping_fini(void);
void pm_ping_set_path_check_state(struct rpc_xprt *xprt, enum enfs_pm_check_state state);
bool pm_ping_is_test_xprt_task(struct rpc_task *task);
int pm_ping_rpc_test_xprt_with_callback(struct rpc_clnt *clnt,
					struct rpc_xprt *xprt,
					void (*func)(void *data), void *data);

#if IS_ENABLED(CONFIG_ENFS_KUNIT_TEST)
bool enfs_test_reconnect_time(void);
bool enfs_test_fault_recovery_state(void);
#endif

#endif // PM_PING_H
