// SPDX-License-Identifier: GPL-2.0
/* Huawei UDMA Linux driver
 * Copyright (c) 2023-2023 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 */

#include "urma/ubcore_uapi.h"
#include "hns3_udma_abi.h"
#include "hns3_udma_hem.h"
#include "hns3_udma_tp.h"
#include "hns3_udma_jfs.h"

static int init_jfs_cfg(struct udma_dev *dev, struct udma_jfs *jfs,
			const struct ubcore_jfs_cfg *cfg)
{
	if (!cfg->max_sge ||
	    cfg->depth > dev->caps.max_wqes ||
	    cfg->max_sge > dev->caps.max_sq_sg) {
		dev_err(dev->dev, "invalid jfs cfg, depth = %u, sge = %u.\n",
			cfg->depth, cfg->max_sge);
		return -EINVAL;
	}
	memcpy(&jfs->ubcore_jfs.jfs_cfg, cfg, sizeof(struct ubcore_jfs_cfg));
	jfs->tp_mode = cfg->trans_mode;

	return 0;
}

int destroy_jfs_qp(struct udma_dev *dev, struct udma_jfs *jfs)
{
	int ret = 0;

	if (jfs->tp_mode == UBCORE_TP_UM)
		dev_err(dev->dev, "Not support UM mode.\n");

	return ret;
}

static int alloc_jfs_buf(struct udma_dev *udma_dev, struct udma_jfs *jfs,
			 const struct ubcore_jfs_cfg *cfg,
			 struct ubcore_udata *udata)
{
	struct udma_create_jfs_ucmd ucmd = {};
	int ret = 0;

	if (udata) {
		ret = copy_from_user(&ucmd, (void *)udata->udrv_data->in_addr,
				     min(udata->udrv_data->in_len,
					 (uint32_t)sizeof(ucmd)));
		if (ret) {
			dev_err(udma_dev->dev,
				"failed to copy jfs udata, ret = %d.\n", ret);
			return -EFAULT;
		}
	}

	if (cfg->trans_mode == UBCORE_TP_RM) {
		xa_init(&jfs->node_table);
	} else if (cfg->trans_mode == UBCORE_TP_UM) {
		dev_err(udma_dev->dev, "Not Support UM mode.\n");
		return -EINVAL;
	}

	return ret;
}

static int alloc_jfs_id(struct udma_dev *udma_dev, struct udma_jfs *jfs)
{
	struct udma_jfs_table *jfs_table = &udma_dev->jfs_table;
	struct udma_ida *jfs_ida = &jfs_table->jfs_ida;
	int ret;
	int id;

	id = ida_alloc_range(&jfs_ida->ida, jfs_ida->min, jfs_ida->max,
			     GFP_KERNEL);
	if (id < 0) {
		dev_err(udma_dev->dev, "failed to alloc jfs_id(%d).\n", id);
		return id;
	}
	jfs->jfs_id = (uint32_t)id;
	jfs->ubcore_jfs.id = jfs->jfs_id;

	ret = xa_err(xa_store(&jfs_table->xa, jfs->jfs_id, jfs, GFP_KERNEL));
	if (ret) {
		dev_err(udma_dev->dev, "failed to store JFS, ret = %d.\n", ret);
		ida_free(&jfs_ida->ida, id);
	}

	return ret;
}

static void free_jfs_id(struct udma_dev *udma_dev, struct udma_jfs *jfs)
{
	struct udma_jfs_table *jfs_table = &udma_dev->jfs_table;
	struct udma_ida *jfs_ida = &jfs_table->jfs_ida;

	xa_erase(&jfs_table->xa, jfs->jfs_id);
	ida_free(&jfs_ida->ida, (int)jfs->jfs_id);
}

struct ubcore_jfs *udma_create_jfs(struct ubcore_device *dev, const struct ubcore_jfs_cfg *cfg,
			      struct ubcore_udata *udata)
{
	struct udma_dev *udma_dev = to_udma_dev(dev);
	struct udma_jfs *jfs;
	int ret;

	jfs = kcalloc(1, sizeof(struct udma_jfs), GFP_KERNEL);
	if (!jfs)
		return NULL;

	ret = init_jfs_cfg(udma_dev, jfs, cfg);
	if (ret)
		goto err_init_cfg;

	ret = alloc_jfs_id(udma_dev, jfs);
	if (ret)
		goto err_alloc_jfs_id;

	init_jetty_x_qpn_bitmap(udma_dev, &jfs->qpn_map,
				udma_dev->caps.num_jfs_shift,
				UDMA_JFS_QPN_PREFIX, jfs->jfs_id);

	ret = alloc_jfs_buf(udma_dev, jfs, cfg, udata);
	if (ret) {
		dev_err(udma_dev->dev, "alloc jfs buf failed.\n");
		goto err_alloc_jfs_buf;
	}

	return &jfs->ubcore_jfs;

err_alloc_jfs_buf:
	clean_jetty_x_qpn_bitmap(&jfs->qpn_map);
	free_jfs_id(udma_dev, jfs);
err_alloc_jfs_id:
err_init_cfg:
	kfree(jfs);

	return NULL;
}

int udma_destroy_jfs(struct ubcore_jfs *jfs)
{
	struct udma_jfs *udma_jfs;
	struct udma_dev *udma_dev;
	int ret;

	udma_jfs = to_udma_jfs(jfs);
	udma_dev = to_udma_dev(jfs->ub_dev);

	ret = destroy_jfs_qp(udma_dev, udma_jfs);
	clean_jetty_x_qpn_bitmap(&udma_jfs->qpn_map);
	free_jfs_id(udma_dev, udma_jfs);
	kfree(udma_jfs);

	return ret;
}
