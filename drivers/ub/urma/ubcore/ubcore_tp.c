// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2025. All rights reserved.
 *
 * Description: ubcore tp implementation
 * Author: Yan Fangfang
 * Create: 2022-08-25
 * Note:
 * History: 2022-08-25: Create file
 */

#include <net/arp.h>
#include <net/neighbour.h>
#include <net/route.h>
#include <net/netevent.h>
#include <net/ip6_route.h>
#include <net/ipv6_stubs.h>
#include <linux/version.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/list.h>
#include "ubcore_priv.h"
#include "ubcore_log.h"
#include "ubcore_dmac.h"

int ubcore_get_tp_list(struct ubcore_device *dev, struct ubcore_get_tp_cfg *cfg,
		       uint32_t *tp_cnt, struct ubcore_tp_info *tp_list,
		       struct ubcore_udata *udata)
{
	int ret;

	if (dev == NULL || dev->ops == NULL || dev->ops->get_tp_list == NULL ||
		cfg == NULL || tp_cnt == NULL || tp_list == NULL || *tp_cnt == 0) {
		return -EINVAL;
	}

	if (ubcore_check_trans_mode_valid(cfg->trans_mode) != true) {
		return -EINVAL;
	}

	ret = dev->ops->get_tp_list(dev, cfg, tp_cnt, tp_list, udata);
	if (ret != 0)
		ubcore_log_err("[DRV_ERROR]Failed to get to list, ret: %d.\n", ret);

	return ret;
}
EXPORT_SYMBOL(ubcore_get_tp_list);

int ubcore_set_tp_attr(struct ubcore_device *dev, const uint64_t tp_handle,
		       const uint8_t tp_attr_cnt, const uint32_t tp_attr_bitmap,
		       const struct ubcore_tp_attr_value *tp_attr,
		       struct ubcore_udata *udata)
{
	int ret;

	if (dev == NULL || dev->ops == NULL || dev->ops->set_tp_attr == NULL ||
		tp_attr == NULL) {
		ubcore_log_err("Invalid parameter.\n");
		return -EINVAL;
	}

	ret = dev->ops->set_tp_attr(dev, tp_handle, tp_attr_cnt, tp_attr_bitmap,
					tp_attr, udata);
	if (ret != 0) {
		ubcore_log_err("[DRV_ERROR]Failed to set tp attr, ret: %d.\n",
					ret);
		return ret;
	}

	return ret;
}
EXPORT_SYMBOL(ubcore_set_tp_attr);

int ubcore_get_tp_attr(struct ubcore_device *dev, const uint64_t tp_handle,
		       uint8_t *tp_attr_cnt, uint32_t *tp_attr_bitmap,
		       struct ubcore_tp_attr_value *tp_attr,
		       struct ubcore_udata *udata)
{
	int ret;

	if (dev == NULL || dev->ops == NULL || dev->ops->get_tp_attr == NULL ||
		tp_attr_cnt == NULL || tp_attr_bitmap == NULL || tp_attr == NULL) {
		ubcore_log_err("Invalid parameter.\n");
		return -EINVAL;
	}

	ret = dev->ops->get_tp_attr(dev, tp_handle, tp_attr_cnt, tp_attr_bitmap,
					tp_attr, udata);
	if (ret != 0) {
		ubcore_log_err("[DRV_ERROR]Failed to get tp attr, ret: %d.\n",
					ret);
		return ret;
	}

	return ret;
}
EXPORT_SYMBOL(ubcore_get_tp_attr);

int ubcore_get_eid_by_ip(struct ubcore_device *dev, const struct ubcore_net_addr *net_addr,
			 union ubcore_eid *eid)
{
	int ret;

	if (dev == NULL || dev->ops == NULL || dev->ops->get_eid_by_ip == NULL ||
		net_addr == NULL || eid == NULL) {
		ubcore_log_err("Invalid parameter.\n");
		return -EINVAL;
	}

	ret = dev->ops->get_eid_by_ip(dev, net_addr, eid);
	if (ret != 0) {
		ubcore_log_err("[DRV_ERROR]Failed to get_eid_by_ip, ret: %d.\n", ret);
		return ret;
	}

	return ret;
}
EXPORT_SYMBOL(ubcore_get_eid_by_ip);

int ubcore_get_ip_by_eid(struct ubcore_device *dev, const union ubcore_eid *eid,
				 struct ubcore_net_addr *net_addr)
{
	int ret;

	if (dev == NULL || dev->ops == NULL || dev->ops->get_ip_by_eid == NULL ||
		net_addr == NULL || eid == NULL) {
		ubcore_log_err("Invalid parameter.\n");
		return -EINVAL;
	}

	ret = dev->ops->get_ip_by_eid(dev, eid, net_addr);
	if (ret != 0) {
		ubcore_log_err("[DRV_ERROR]Failed to get_ip_by_eid, ret: %d.\n", ret);
		return ret;
	}

	return ret;
}
EXPORT_SYMBOL(ubcore_get_ip_by_eid);

int ubcore_get_smac(struct ubcore_device *dev, uint8_t *mac)
{
	int ret;

	if (dev == NULL || dev->ops == NULL || dev->ops->get_smac == NULL || mac == NULL) {
		ubcore_log_err("Invalid parameter.\n");
		return -EINVAL;
	}

	ret = dev->ops->get_smac(dev, mac);
	if (ret != 0) {
		ubcore_log_err("Failed to get smac, ret: %d.\n", ret);
		return ret;
	}
	ubcore_log_info("Successfully got smac.\n");

	return ret;
}
EXPORT_SYMBOL(ubcore_get_smac);

int ubcore_get_dmac(struct ubcore_device *dev, const struct ubcore_net_addr *net_addr, uint8_t *mac)
{
	int ret;

	if (dev == NULL || net_addr == NULL || mac == NULL) {
		ubcore_log_err("Invalid parameter.\n");
		return -EINVAL;
	}

	if (dev->ops->get_dmac == NULL)
		ret = ubcore_get_dmac_by_ip(dev, net_addr, mac);
	else
		ret = dev->ops->get_dmac(dev, net_addr, mac);

	if (ret != 0) {
		ubcore_log_err("Failed to get dmac, ret: %d.\n", ret);
		if (dev->ops->get_dmac)
			return ret;
	} else {
		ubcore_log_info("Successfully got dmac.\n");
	}

	return ret;
}
EXPORT_SYMBOL(ubcore_get_dmac);
