// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.
 *
 * Description: ubcore kernel module
 * Author: Qian Guoxin
 * Create: 2021-08-03
 * Note:
 * History: 2021-08-03: create file
 */

#include <linux/module.h>
#include "ubcore_main.h"
#include "ubcore_log.h"
#include "ubcore_workqueue.h"
#include "ubcore_device.h"
#include "net/ubcore_comm.h"
#include "net/ubcore_session.h"
#include "ubcore_connect_adapter.h"
#include "ubcore_connect_bonding.h"
#include "ubcore_genl.h"
#include "ubcm/ub_cm.h"
#include "ubmgr/ubmgr.h"

#define UBCORE_LOG_FILE_PERMISSION (0644)

module_param(g_ubcore_log_level, uint, UBCORE_LOG_FILE_PERMISSION);
MODULE_PARM_DESC(g_ubcore_log_level, " 3: ERR, 4: WARNING, 6: INFO, 7: DEBUG");
module_param(ubcore_conn_timeout, uint, UBCORE_LOG_FILE_PERMISSION);
MODULE_PARM_DESC(ubcore_conn_timeout, "unit milliseconds");

static int __init ubcore_init(void)
{
	int ret;

	ubcore_exchange_init();
	ubcore_connect_bonding_init();

	ret = ubcore_class_register();
	if (ret != 0)
		return -1;

	ret = ubcore_cdev_register();
	if (ret != 0)
		goto class_init;

	ret = ubcore_genl_init();
	if (ret != 0) {
		(void)pr_err("Failed to ubcore genl init\n");
		goto genl_init;
	}

	ret = ubcore_register_pnet_ops();
	if (ret != 0)
		goto reg_pnet;

	ret = ubcore_create_workqueues();
	if (ret != 0) {
		ubcore_log_err("Failed to create all the workqueues, ret = %d\n", ret);
		goto create_wq;
	}

	if (ubcore_session_init() != 0) {
		ubcore_log_err("Failed init connect alpha");
		goto session;
	}

	ret = ubcm_init();
	if (ret != 0) {
		pr_err("Failed to init ubcm, ret: %d.\n", ret);
		goto ubcm;
	}

	ret = ubmgr_init();
	if (ret != 0) {
		pr_err("Failed to init ubmgr, ret: %d.\n", ret);
		goto ubmgr;
	}

	ubcore_log_info("ubcore module init success.\n");
	return 0;

ubmgr:
	ubcm_uninit();
ubcm:
	ubcore_session_uninit();
session:
	ubcore_destroy_workqueues();
create_wq:
	ubcore_unregister_pnet_ops();
reg_pnet:
	ubcore_genl_exit();
genl_init:
	ubcore_cdev_unregister();
class_init:
	ubcore_class_unregister();
	return ret;
}

static void __exit ubcore_exit(void)
{
	ubcm_uninit();
	ubcore_comm_uninit();
	ubcore_session_uninit();
	ubcore_destroy_workqueues();
	ubcore_unregister_pnet_ops();
	ubcore_genl_exit();
	ubcore_cdev_unregister();
	ubcore_class_unregister();
	ubcore_log_info("ubcore module exits.\n");
}

module_init(ubcore_init);
module_exit(ubcore_exit);

MODULE_DESCRIPTION("URMA memory semantic kernel module for direct remote memory access.");
MODULE_AUTHOR("huawei");
MODULE_LICENSE("GPL");
