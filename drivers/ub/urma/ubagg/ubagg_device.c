// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 *
 * Description: ubagg device helper implementation file
 */

#include <linux/module.h>
#include <linux/atomic.h>
#include <linux/slab.h>
#include <linux/string.h>

#include <ub/urma/ubcore_uapi.h>
#include "ubagg_ioctl.h"
#include "ubagg_log.h"
#include "ubagg_topo_info.h"

#include "ubagg_device.h"

static atomic_t g_ucontext_cnt = ATOMIC_INIT(0);

struct ubcore_ucontext *ubagg_alloc_ucontext(struct ubcore_device *dev,
					     uint32_t eid_index,
					     struct ubcore_udrv_priv *udrv_data)
{
	struct ubcore_ucontext *uctx;

	uctx = kzalloc(sizeof(*uctx), GFP_KERNEL);
	if (uctx == NULL)
		return NULL;

	atomic_inc(&g_ucontext_cnt);
	return uctx;
}

int ubagg_free_ucontext(struct ubcore_ucontext *uctx)
{
	if (uctx == NULL)
		return 0;

	atomic_dec(&g_ucontext_cnt);
	kfree(uctx);
	return 0;
}

uint32_t ubagg_get_ucontext_count(void)
{
	return (uint32_t)atomic_read(&g_ucontext_cnt);
}

struct ubcore_device *ubagg_find_bonding_device(const union ubcore_eid *eid)
{
	struct ubagg_topo_node *topo_info;
	union ubcore_eid *bonding_eid;
	int dev_id, ue_id, port_id;

	topo_info = get_current_topo_node();
	if (!topo_info) {
		ubagg_log_err("Failed get global topo info");
		return NULL;
	}

	for (dev_id = 0; dev_id < DEV_NUM; dev_id++) {
		if (!is_agg_dev_valid(&topo_info->agg_devs[dev_id]))
			continue;

		if (memcmp(eid,
			   (union ubcore_eid *)topo_info->agg_devs[dev_id]
				   .agg_eid,
			   sizeof(union ubcore_eid)) == 0) {
			goto found;
		}

		for (ue_id = 0; ue_id < IODIE_NUM; ue_id++) {
			if (memcmp(eid,
				   (union ubcore_eid *)topo_info
					   ->agg_devs[dev_id]
					   .ues[ue_id]
					   .primary_eid,
				   sizeof(union ubcore_eid)) == 0) {
				goto found;
			}
			for (port_id = 0; port_id < PORT_NUM; port_id++) {
				if (memcmp(eid,
					   (union ubcore_eid *)topo_info
						   ->agg_devs[dev_id]
						   .ues[ue_id]
						   .port_eid[port_id],
					   sizeof(union ubcore_eid)) == 0) {
					goto found;
				}
			}
		}
	}

	ubagg_log_err("Failed to find bonding device.\n");
	return NULL;

found:
	bonding_eid = (union ubcore_eid *)topo_info->agg_devs[dev_id].agg_eid;
	return ubcore_get_device_by_eid(bonding_eid, UBCORE_TRANSPORT_UB);
}
