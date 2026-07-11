// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include <linux/module.h>
#include <linux/dinghai/log.h>
#include <linux/dinghai/driver.h>
#include "en_pf.h"
#include "zxdh_tsn.h"
#include "zxdh_tsn_reg.h"
#include "zxdh_tsn_comm.h"
#include "zxdh_tsn_ioctl.h"

__weak int debug_print;
module_param(debug_print, int, 0644);

s32 zxdh_tsn_init(struct dh_core_dev *dh_dev)
{
	struct zxdh_tsn_private *tsn = NULL;
	struct zxdh_pf_device *pf_dev = NULL;

	if (!dh_dev) {
		DH_LOG_ERR(MODULE_TSN, "[Error: POINT NULL] !\n");
		return -EINVAL;
	}
	if (dh_dev->coredev_type != DH_COREDEV_PF)
		return TSN_OK;

	pf_dev = dh_core_priv(dh_dev);
	if (!pf_dev) {
		DH_LOG_ERR(MODULE_TSN, "[Error: POINT NULL] !\n");
		return -EINVAL;
	}

	tsn = kzalloc(sizeof(*tsn), GFP_KERNEL);
	if (!tsn) {
		DH_LOG_ERR(MODULE_TSN, "[Error: POINT NULL] !\n");
		return -EINVAL;
	}

	pf_dev->tsn = tsn;

	memset(tsn, 0x00, sizeof(struct zxdh_tsn_private));

	tsn->tsn_qbv_cap.ct_min = TSN_CYCLE_TIME_MIN;
	tsn->tsn_qbv_cap.ct_max = TSN_CYCLE_TIME_MAX;
	tsn->tsn_qbv_cap.it_min = TSN_INTERVAL_TIME_MIN;
	tsn->tsn_qbv_cap.it_max = TSN_INTERVAL_TIME_MAX;
	tsn->tsn_qbv_cap.gcl_num = TSN_PORT_GCL_NUM;
	tsn->tsn_port_id.port_id = TSN_PORT_PORT_ID_DEF;
	tsn->pci_ioremap_addr = pf_dev->pci_ioremap_addr[0];

	spin_lock_init(&tsn->tsn_spin_lock);

	hrtimer_init(&tsn->tsn_qbv_change_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	tsn->tsn_qbv_change_timer.function = zxdh_tsn_qbv_change_timer_callback;

	return TSN_OK;
}
EXPORT_SYMBOL(zxdh_tsn_init);

void zxdh_tsn_exit(struct dh_core_dev *dh_dev)
{
	struct zxdh_tsn_private *tsn = NULL;
	struct zxdh_pf_device *pf_dev = NULL;

	if (!dh_dev) {
		DH_LOG_ERR(MODULE_TSN, "[Error: POINT NULL] !\n");
		return;
	}
	if (dh_dev->coredev_type != DH_COREDEV_PF)
		return;

	pf_dev = dh_core_priv(dh_dev);
	if (!pf_dev) {
		DH_LOG_ERR(MODULE_TSN, "[Error: POINT NULL] !\n");
		return;
	}

	tsn = pf_dev->tsn;
	if (!tsn) {
		DH_LOG_ERR(MODULE_TSN, "[Error: POINT NULL] !\n");
		return;
	}

	hrtimer_cancel(&tsn->tsn_qbv_change_timer);

	if (!IS_ERR_OR_NULL((void *)tsn->tsn_reg_base_addr)) {
		tsn_port_disable_set(tsn);
		tsn_port_phy_port_set(tsn, TSN_PORT_PORT_ID_DEF);
	}

	kfree(tsn);
}
EXPORT_SYMBOL(zxdh_tsn_exit);

MODULE_LICENSE("GPL");
