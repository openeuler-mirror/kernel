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

#include "urma/ubcore_api.h"
#include "hns3_udma_device.h"
#include "hns3_udma_hem.h"
#include "hns3_udma_cmd.h"

static struct ubcore_ops g_udma_dev_ops = {

};

int udma_init_common_hem(struct udma_dev *udma_dev)
{
	struct device *dev = udma_dev->dev;
	int ret;

	ret = udma_init_hem_table(udma_dev, &udma_dev->seg_table.table,
				  HEM_TYPE_MTPT, udma_dev->caps.mtpt_entry_sz,
				  udma_dev->caps.num_mtpts);
	if (ret) {
		dev_err(dev, "Failed to init MTPT context memory.\n");
		return ret;
	}
	dev_info(dev, "init MPT hem table success.\n");

	ret = udma_init_hem_table(udma_dev, &udma_dev->qp_table.qp_table,
				  HEM_TYPE_QPC, udma_dev->caps.qpc_sz,
				  udma_dev->caps.num_qps);
	if (ret) {
		dev_err(dev, "Failed to init QP context memory.\n");
		goto err_unmap_dmpt;
	}
	dev_info(dev, "init QPC hem table success.\n");

	ret = udma_init_hem_table(udma_dev, &udma_dev->qp_table.irrl_table,
				  HEM_TYPE_IRRL, udma_dev->caps.irrl_entry_sz *
				  udma_dev->caps.max_qp_init_rdma,
				  udma_dev->caps.num_qps);
	if (ret) {
		dev_err(dev, "Failed to init irrl_table memory.\n");
		goto err_unmap_qp;
	}
	dev_info(dev, "init IRRL hem table success.\n");

	if (udma_dev->caps.trrl_entry_sz) {
		ret = udma_init_hem_table(udma_dev,
					  &udma_dev->qp_table.trrl_table,
					  HEM_TYPE_TRRL,
					  udma_dev->caps.trrl_entry_sz *
					  udma_dev->caps.max_qp_dest_rdma,
					  udma_dev->caps.num_qps);
		if (ret) {
			dev_err(dev, "Failed to init trrl_table memory.\n");
			goto err_unmap_irrl;
		}
		dev_info(dev, "init TRRL hem table success.\n");
	}

	ret = udma_init_hem_table(udma_dev, &udma_dev->jfc_table.table,
				  HEM_TYPE_CQC, udma_dev->caps.cqc_entry_sz,
				  udma_dev->caps.num_cqs);
	if (ret) {
		dev_err(dev, "Failed to init CQ context memory.\n");
		goto err_unmap_trrl;
	}
	dev_info(dev, "init CQC hem table success.\n");

	if (udma_dev->caps.flags & UDMA_CAP_FLAG_SRQ) {
		ret = udma_init_hem_table(udma_dev, &udma_dev->jfr_table.table,
					  HEM_TYPE_SRQC,
					  udma_dev->caps.srqc_entry_sz,
					  udma_dev->caps.num_srqs);
		if (ret) {
			dev_err(dev, "Failed to init SRQ context memory.\n");
			goto err_unmap_cq;
		}
		dev_info(dev, "init SRQC hem table success.\n");
	}

	if (udma_dev->caps.flags & UDMA_CAP_FLAG_QP_FLOW_CTRL) {
		ret = udma_init_hem_table(udma_dev,
					  &udma_dev->qp_table.sccc_table,
					  HEM_TYPE_SCCC,
					  udma_dev->caps.scc_ctx_sz,
					  udma_dev->caps.num_qps);
		if (ret) {
			dev_err(dev, "Failed to init SCC context memory.\n");
			goto err_unmap_srq;
		}
		dev_info(dev, "init SCCC hem table success.\n");
	}

	if (udma_dev->caps.gmv_entry_sz) {
		ret = udma_init_hem_table(udma_dev, &udma_dev->gmv_table,
					  HEM_TYPE_GMV,
					  udma_dev->caps.gmv_entry_sz,
					  udma_dev->caps.gmv_entry_num);
		if (ret) {
			dev_err(dev, "failed to init gmv table memory.\n");
			goto err_unmap_ctx;
		}
		dev_info(dev, "init GMV hem table success.\n");
	}

	return 0;
err_unmap_ctx:
	if (udma_dev->caps.flags & UDMA_CAP_FLAG_QP_FLOW_CTRL)
		udma_cleanup_hem_table(udma_dev,
				       &udma_dev->qp_table.sccc_table);
err_unmap_srq:
	if (udma_dev->caps.flags & UDMA_CAP_FLAG_SRQ)
		udma_cleanup_hem_table(udma_dev, &udma_dev->jfr_table.table);
err_unmap_cq:
	udma_cleanup_hem_table(udma_dev, &udma_dev->jfc_table.table);
err_unmap_trrl:
	if (udma_dev->caps.trrl_entry_sz)
		udma_cleanup_hem_table(udma_dev,
				       &udma_dev->qp_table.trrl_table);
err_unmap_irrl:
	udma_cleanup_hem_table(udma_dev, &udma_dev->qp_table.irrl_table);
err_unmap_qp:
	udma_cleanup_hem_table(udma_dev, &udma_dev->qp_table.qp_table);
err_unmap_dmpt:
	udma_cleanup_hem_table(udma_dev, &udma_dev->seg_table.table);

	return ret;
}

static int udma_init_hem(struct udma_dev *udma_dev)
{
	struct device *dev = udma_dev->dev;
	int ret;

	ret = udma_init_common_hem(udma_dev);
	if (ret) {
		dev_err(dev, "Failed to init common hem table of PF.\n");
		return ret;
	}

	if (udma_dev->caps.qpc_timer_entry_sz) {
		ret = udma_init_hem_table(udma_dev, &udma_dev->qpc_timer_table,
					  HEM_TYPE_QPC_TIMER,
					  udma_dev->caps.qpc_timer_entry_sz,
					  udma_dev->caps.num_qpc_timer);
		if (ret) {
			dev_err(dev, "Failed to init QPC timer memory.\n");
			goto err_unmap_vf_hem;
		}
	}
	if (udma_dev->caps.cqc_timer_entry_sz) {
		ret = udma_init_hem_table(udma_dev, &udma_dev->cqc_timer_table,
					  HEM_TYPE_CQC_TIMER,
					  udma_dev->caps.cqc_timer_entry_sz,
					  udma_dev->caps.cqc_timer_bt_num);
		if (ret) {
			dev_err(dev, "Failed to init CQC timer memory.\n");
			goto err_unmap_qpc_timer;
		}
	}

	return 0;
err_unmap_qpc_timer:
	if (udma_dev->caps.qpc_timer_entry_sz)
		udma_cleanup_hem_table(udma_dev, &udma_dev->qpc_timer_table);
err_unmap_vf_hem:
	udma_cleanup_common_hem(udma_dev);

	return ret;
}

void udma_cleanup_common_hem(struct udma_dev *udma_dev)
{
	if (udma_dev->caps.gmv_entry_sz)
		udma_cleanup_hem_table(udma_dev, &udma_dev->gmv_table);
	if (udma_dev->caps.flags & UDMA_CAP_FLAG_QP_FLOW_CTRL)
		udma_cleanup_hem_table(udma_dev,
				       &udma_dev->qp_table.sccc_table);
	if (udma_dev->caps.flags & UDMA_CAP_FLAG_SRQ)
		udma_cleanup_hem_table(udma_dev, &udma_dev->jfr_table.table);
	udma_cleanup_hem_table(udma_dev, &udma_dev->jfc_table.table);
	if (udma_dev->caps.trrl_entry_sz)
		udma_cleanup_hem_table(udma_dev,
				       &udma_dev->qp_table.trrl_table);

	udma_cleanup_hem_table(udma_dev, &udma_dev->qp_table.irrl_table);
	udma_cleanup_hem_table(udma_dev, &udma_dev->qp_table.qp_table);
	udma_cleanup_hem_table(udma_dev, &udma_dev->seg_table.table);
}

static void udma_cleanup_hem(struct udma_dev *udma_dev)
{
	if (udma_dev->caps.qpc_timer_entry_sz)
		udma_cleanup_hem_table(udma_dev, &udma_dev->qpc_timer_table);
	if (udma_dev->caps.cqc_timer_entry_sz)
		udma_cleanup_hem_table(udma_dev, &udma_dev->cqc_timer_table);

	udma_cleanup_common_hem(udma_dev);
}


static void udma_set_devname(struct udma_dev *udma_dev,
			     struct ubcore_device *ub_dev)
{
	scnprintf(udma_dev->dev_name, UBCORE_MAX_DEV_NAME, "udma%d",
		  udma_dev->func_id);
	dev_info(udma_dev->dev, "Set dev_name %s\n", udma_dev->dev_name);
	strlcpy(ub_dev->dev_name, udma_dev->dev_name, UBCORE_MAX_DEV_NAME);
}

static int udma_register_device(struct udma_dev *udma_dev)
{
	struct ubcore_device *ub_dev = NULL;
	struct udma_netdev *uboe = NULL;

	ub_dev = &udma_dev->ub_dev;
	uboe = &udma_dev->uboe;
	spin_lock_init(&uboe->lock);
	ub_dev->transport_type = UBCORE_TRANSPORT_IB;
	ub_dev->ops = &g_udma_dev_ops;
	ub_dev->dev.parent = udma_dev->dev;
	ub_dev->dma_dev = ub_dev->dev.parent;
	ub_dev->netdev = udma_dev->uboe.netdevs[0];
	scnprintf(ub_dev->ops->driver_name, UBCORE_MAX_DRIVER_NAME, "udma_v1");
	udma_set_devname(udma_dev, ub_dev);
	ub_dev->num_comp_vectors = udma_dev->irq_num;

	return ubcore_register_device(ub_dev);
}

static void udma_unregister_device(struct udma_dev *udma_dev)
{
	struct ubcore_device *ub_dev = &udma_dev->ub_dev;

	ubcore_unregister_device(ub_dev);
}

int udma_hnae_client_init(struct udma_dev *udma_dev)
{
	struct device *dev = udma_dev->dev;
	int ret;

	ret = udma_dev->hw->cmq_init(udma_dev);
	if (ret) {
		dev_err(dev, "Init UB Command Queue failed!\n");
		goto error_failed_cmq_init;
	}

	ret = udma_dev->hw->hw_profile(udma_dev);
	if (ret) {
		dev_err(dev, "Get UB engine profile failed!\n");
		goto error_failed_hw_profile;
	}

	ret = udma_cmd_init(udma_dev);
	if (ret) {
		dev_err(dev, "cmd init failed!\n");
		goto error_failed_cmd_init;
	}

	if (udma_dev->cmd_mod) {
		ret = udma_cmd_use_events(udma_dev);
		if (ret) {
			udma_dev->cmd_mod = 0;
			dev_warn(dev,
				 "Cmd event mode failed, set back to poll!\n");
		}
	}

	ret = udma_init_hem(udma_dev);
	if (ret) {
		dev_err(dev, "init HEM(Hardware Entry Memory) failed!\n");
		goto error_failed_hem_init;
	}

	ret = udma_dev->hw->hw_init(udma_dev);
	if (ret) {
		dev_err(dev, "hw_init failed!\n");
		goto error_failed_engine_init;
	}

	ret = udma_register_device(udma_dev);
	if (ret) {
		dev_err(dev, "udma register device failed!\n");
		goto error_failed_register_device;
	}

	return 0;

error_failed_register_device:
	udma_dev->hw->hw_exit(udma_dev);

error_failed_engine_init:
	udma_cleanup_hem(udma_dev);

error_failed_hem_init:
	if (udma_dev->cmd_mod)
		udma_cmd_use_polling(udma_dev);

	udma_cmd_cleanup(udma_dev);

error_failed_cmd_init:
error_failed_hw_profile:
	udma_dev->hw->cmq_exit(udma_dev);

error_failed_cmq_init:
	return ret;
}

void udma_hnae_client_exit(struct udma_dev *udma_dev)
{
	udma_unregister_device(udma_dev);

	if (udma_dev->hw->hw_exit)
		udma_dev->hw->hw_exit(udma_dev);
	if (udma_dev->hw->cmq_exit)
		udma_dev->hw->cmq_exit(udma_dev);
}
