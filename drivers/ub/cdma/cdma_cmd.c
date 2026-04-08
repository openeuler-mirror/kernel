// SPDX-License-Identifier: GPL-2.0+
/* Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved. */

#define dev_fmt(fmt) "CDMA: " fmt

#include <linux/slab.h>
#include <linux/dmapool.h>

#include "cdma.h"
#include <ub/ubase/ubase_comm_dev.h>
#include <ub/ubase/ubase_comm_cmd.h>
#include <ub/ubase/ubase_comm_ctrlq.h>
#include "cdma_cmd.h"

static int cdma_cmd_query_fw_resource(struct cdma_dev *cdev,
				      struct cdma_ue_info *out_addr)
{
#define CDMA_QUERY_UE_RES 0x0004
	struct ubase_cmd_buf out = { 0 };
	struct ubase_cmd_buf in = { 0 };

	ubase_fill_inout_buf(&in, CDMA_QUERY_UE_RES, true, 0, NULL);
	ubase_fill_inout_buf(&out, CDMA_QUERY_UE_RES, true, sizeof(*out_addr),
			     out_addr);

	return ubase_cmd_send_inout(cdev->adev, &in, &out);
}

static int cdma_query_caps_from_firmware(struct cdma_dev *cdev)
{
	struct cdma_caps *caps = &cdev->caps;
	struct cdma_ue_info cmd = { 0 };
	int ret;

	ret = cdma_cmd_query_fw_resource(cdev, &cmd);
	if (ret) {
		dev_err(cdev->dev, "query fw resource failed, ret = %d\n", ret);
		return ret;
	}

	caps->jfs_sge = cmd.jfs_sge;
	caps->trans_mode = cmd.trans_mode;
	caps->seid.max_cnt = cmd.seid_upi_tbl_num;
	caps->feature = cmd.cap_info;
	caps->ue_cnt = cmd.ue_cnt;
	caps->ue_id = cmd.ue_id;

	dev_info(cdev->dev, "jfs_sge = 0x%x, trans_mode = 0x%x, seid.max_cnt = 0x%x\n",
		 caps->jfs_sge, caps->trans_mode, caps->seid.max_cnt);
	dev_info(cdev->dev, "feature = 0x%x, ue_cnt = 0x%x, ue_id = 0x%x\n",
		 caps->feature, caps->ue_cnt, caps->ue_id);

	return 0;
}

static int cdma_set_caps_from_adev_caps(struct cdma_dev *cdev)
{
#define MAX_WQEBB_IN_SQE 4
	struct cdma_caps *caps = &cdev->caps;
	struct ubase_adev_caps *adev_caps;

	adev_caps = ubase_get_cdma_caps(cdev->adev);
	if (!adev_caps) {
		dev_err(cdev->dev, "get cdma adev caps failed\n");
		return -EINVAL;
	}

	caps->jfs.max_cnt = adev_caps->jfs.max_cnt;
	caps->jfs.depth = adev_caps->jfs.depth / MAX_WQEBB_IN_SQE;
	caps->jfs.start_idx = adev_caps->jfs.start_idx;
	caps->jfc.max_cnt = adev_caps->jfc.max_cnt;
	caps->jfc.depth = adev_caps->jfc.depth;
	caps->jfc.start_idx = adev_caps->jfc.start_idx;
	caps->cqe_size = adev_caps->cqe_size;

	return 0;
}

static int cdma_set_caps_from_ubase_caps(struct cdma_dev *cdev)
{
	struct cdma_caps *caps = &cdev->caps;
	struct ubase_caps *ubase_caps;

	ubase_caps = ubase_get_dev_caps(cdev->adev);
	if (!ubase_caps) {
		dev_err(cdev->dev, "get cdma ubase caps failed\n");
		return -EINVAL;
	}

	caps->comp_vector_cnt = ubase_caps->num_ceq_vectors;
	caps->public_jetty_cnt = ubase_caps->public_jetty_cnt;
	cdev->eid = ubase_caps->eid;
	cdev->upi = ubase_caps->upi;

	return 0;
}

static int cdma_set_caps_from_adev_qos(struct cdma_dev *cdev)
{
	struct ubase_adev_qos *qos;

	qos = ubase_get_adev_qos(cdev->adev);
	if (!qos) {
		dev_err(cdev->dev, "get cdma adev qos failed\n");
		return -EINVAL;
	}

	if (!qos->ctp_sl_num || qos->ctp_sl_num > CDMA_MAX_SL_NUM) {
		dev_err(cdev->dev, "sl num %u is invalid\n",
			qos->ctp_sl_num);
		return -EINVAL;
	}

	cdev->sl_num = qos->ctp_sl_num;
	memcpy(cdev->sl, qos->ctp_sl, qos->ctp_sl_num);

	return 0;
}

int cdma_init_dev_caps(struct cdma_dev *cdev)
{
	struct cdma_caps *caps = &cdev->caps;
	int ret;
	u8 i;

	ret = cdma_query_caps_from_firmware(cdev);
	if (ret)
		return ret;

	ret = cdma_set_caps_from_adev_caps(cdev);
	if (ret)
		return ret;

	ret = cdma_set_caps_from_ubase_caps(cdev);
	if (ret)
		return ret;

	ret = cdma_set_caps_from_adev_qos(cdev);
	if (ret)
		return ret;

	caps->queue.max_cnt = min(caps->jfs.max_cnt, caps->jfc.max_cnt);
	caps->queue.start_idx = 0;
	caps->jfce.max_cnt = caps->jfc.max_cnt;
	caps->jfce.start_idx = 0;

	dev_info(cdev->dev, "query cdev eid = 0x%x, cdev upi = 0x%x\n", cdev->eid,
		 cdev->upi);
	dev_info(cdev->dev, "queue:max_cnt = 0x%x, start_idx = 0x%x\n",
		 caps->queue.max_cnt, caps->queue.start_idx);
	dev_info(cdev->dev, "jfs:max_cnt = 0x%x, depth = 0x%x, start_idx = 0x%x\n",
		 caps->jfs.max_cnt, caps->jfs.depth, caps->jfs.start_idx);
	dev_info(cdev->dev, "jfce:max_cnt = 0x%x, depth = 0x%x, start_idx = 0x%x\n",
		 caps->jfce.max_cnt, caps->jfce.depth, caps->jfce.start_idx);
	dev_info(cdev->dev, "jfc:max_cnt = 0x%x, depth = 0x%x, start_idx = 0x%x\n",
		 caps->jfc.max_cnt, caps->jfc.depth, caps->jfc.start_idx);
	dev_info(cdev->dev, "comp_vector_cnt = 0x%x, public_jetty_cnt = 0x%x\n",
		 caps->comp_vector_cnt, caps->public_jetty_cnt);
	dev_info(cdev->dev, "sl_num = 0x%x\n", cdev->sl_num);
	for (i = 0; i < cdev->sl_num; i++)
		dev_info(cdev->dev, "sl[%u] = 0x%x\n", i, cdev->sl[i]);

	return 0;
}

int cdma_ctrlq_query_eu(struct cdma_dev *cdev)
{
#define CDMA_CTRLQ_QUERY_SEID_UPI 0x1
#define CDMA_CTRLQ_CMD_SEID_UPI 0xB5
	struct cdma_device_attr *attr = &cdev->base.attr;
	struct eu_query_out out_query = { 0 };
	struct eu_query_in in_query = { 0 };
	struct ubase_ctrlq_msg msg = { 0 };
	struct eu_info *eus = attr->eus;
	int ret;
	u8 i;

	in_query.cmd = CDMA_CTRLQ_CMD_SEID_UPI;
	msg.service_ver = UBASE_CTRLQ_SER_VER_01;
	msg.service_type = UBASE_CTRLQ_SER_TYPE_DEV_REGISTER;
	msg.opcode = CDMA_CTRLQ_QUERY_SEID_UPI;
	msg.need_resp = 1;
	msg.is_resp = 0;
	msg.resv = 0;
	msg.resp_seq = 0;
	msg.in_size = sizeof(in_query);
	msg.in = &in_query;
	msg.out_size = sizeof(out_query);
	msg.out = &out_query;

	ret = ubase_ctrlq_send_msg(cdev->adev, &msg);
	if (ret) {
		dev_err(cdev->dev,
			"query seid upi from ctrl cpu failed, ret = %d.\n", ret);
		return ret;
	}

	if (!out_query.seid_num || out_query.seid_num > CDMA_MAX_EU_NUM) {
		dev_err(cdev->dev,
			"query seid upi num is invalid, num = %u.\n",
			out_query.seid_num);
		return -EINVAL;
	}

	mutex_lock(&cdev->eu_mutex);
	memcpy(eus, out_query.eus, sizeof(struct eu_info) * out_query.seid_num);
	attr->eu_num = out_query.seid_num;

	for (i = 0; i < attr->eu_num; i++)
		dev_info(
			cdev->dev,
			"init eus[%u], upi = 0x%x, eid = 0x%x, eid_idx = 0x%x.\n",
			i, eus[i].upi, eus[i].eid.dw0, eus[i].eid_idx);
	mutex_unlock(&cdev->eu_mutex);

	return 0;
}

void cdma_cmd_inc(struct cdma_dev *cdev)
{
	atomic_inc(&cdev->cmdcnt);
}

void cdma_cmd_dec(struct cdma_dev *cdev)
{
	if (atomic_dec_and_test(&cdev->cmdcnt))
		complete(&cdev->cmddone);
}

void cdma_cmd_flush(struct cdma_dev *cdev)
{
	cdma_cmd_dec(cdev);
	dev_info(cdev->dev, "cmd flush cmdcnt is %d\n",
		 atomic_read(&cdev->cmdcnt));
	wait_for_completion(&cdev->cmddone);
}

void cdma_kcmd_inc(struct cdma_dev *cdev)
{
	atomic_inc(&cdev->kcmdcnt);
}

void cdma_kcmd_dec(struct cdma_dev *cdev)
{
	if (atomic_dec_and_test(&cdev->kcmdcnt))
		complete(&cdev->kcmddone);
}

void cdma_kcmd_flush(struct cdma_dev *cdev)
{
	cdma_kcmd_dec(cdev);
	dev_info(cdev->dev, "cmd flush kcmdcnt is %d\n",
		 atomic_read(&cdev->kcmdcnt));
	wait_for_completion(&cdev->kcmddone);
}
