// SPDX-License-Identifier: GPL-2.0+
/* Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved. */

#define dev_fmt(fmt) "CDMA: " fmt

#include <linux/auxiliary_bus.h>
#include <linux/ummu_core.h>
#include <linux/iommu.h>
#include <linux/dma-mapping.h>
#include <linux/bitmap.h>
#include <ub/ubase/ubase_comm_ctrlq.h>
#include <ub/ubase/ubase_comm_dev.h>
#include "cdma.h"
#include "cdma_cmd.h"
#include "cdma_tid.h"
#include "cdma_context.h"
#include "cdma_debugfs.h"
#include "cdma_common.h"
#include "cdma_tp.h"
#include "cdma_jfs.h"
#include "cdma_jfc.h"
#include "cdma_queue.h"
#include "cdma_dev.h"
#include "cdma_eq.h"

static DEFINE_XARRAY(cdma_devs_tbl);
static atomic_t cdma_devs_num = ATOMIC_INIT(0);

struct cdma_dev *get_cdma_dev_by_eid(u32 eid)
{
	struct cdma_dev *cdev = NULL;
	unsigned long index = 0;

	xa_for_each(&cdma_devs_tbl, index, cdev)
		if (cdev->eid == eid)
			return cdev;

	return NULL;
}

struct xarray *get_cdma_dev_tbl(u32 *devs_num)
{
	*devs_num = atomic_read(&cdma_devs_num);

	return &cdma_devs_tbl;
}

/* Add the device to the device list for user query. */
static int cdma_add_device_to_list(struct cdma_dev *cdev)
{
	struct auxiliary_device *adev = cdev->adev;
	int ret;

	if (adev->id >= CDMA_UE_MAX_NUM) {
		dev_err(cdev->dev, "invalid ue id %u\n", adev->id);
		return -EINVAL;
	}

	down_write(&g_device_rwsem);
	ret = xa_err(xa_store(&cdma_devs_tbl, adev->id, cdev, GFP_KERNEL));
	if (ret) {
		dev_err(cdev->dev,
			"store cdma device to table failed, adev id = %u, ret = %d\n",
			adev->id, ret);
		up_write(&g_device_rwsem);
		return ret;
	}

	atomic_inc(&cdma_devs_num);
	up_write(&g_device_rwsem);

	return 0;
}

static void cdma_del_device_from_list(struct cdma_dev *cdev)
{
	struct auxiliary_device *adev = cdev->adev;

	if (adev->id >= CDMA_UE_MAX_NUM) {
		dev_err(cdev->dev, "invalid ue id %u\n", adev->id);
		return;
	}

	down_write(&g_device_rwsem);
	atomic_dec(&cdma_devs_num);
	xa_erase(&cdma_devs_tbl, adev->id);
	up_write(&g_device_rwsem);
}

static void cdma_tbl_init(struct cdma_table *table, u32 max, u32 min)
{
	if (!max || max < min)
		return;

	spin_lock_init(&table->lock);
	idr_init(&table->idr_tbl.idr);
	table->idr_tbl.max = max;
	table->idr_tbl.min = min;
	table->idr_tbl.next = min;
}

static void cdma_tbl_destroy(struct cdma_dev *cdev, struct cdma_table *table,
			     const char *table_name)
{
	if (!idr_is_empty(&table->idr_tbl.idr))
		dev_err(cdev->dev, "IDR not empty in clean up %s table\n",
			table_name);
	idr_destroy(&table->idr_tbl.idr);
}

static void cdma_init_tables(struct cdma_dev *cdev)
{
	struct cdma_res *queue = &cdev->caps.queue;
	struct cdma_res *jfce = &cdev->caps.jfce;
	struct cdma_res *jfs = &cdev->caps.jfs;
	struct cdma_res *jfc = &cdev->caps.jfc;

	cdma_tbl_init(&cdev->queue_table, queue->start_idx + queue->max_cnt - 1,
		      queue->start_idx);
	cdma_tbl_init(&cdev->jfce_table, jfce->start_idx + jfce->max_cnt - 1,
		      jfce->start_idx);
	cdma_tbl_init(&cdev->jfc_table, jfc->start_idx + jfc->max_cnt - 1,
		      jfc->start_idx);
	cdma_tbl_init(&cdev->jfs_table, jfs->max_cnt + jfs->start_idx - 1,
		      jfs->start_idx);
	cdma_tbl_init(&cdev->ctp_table, CDMA_RANGE_INDEX_ENTRY_CNT, 0);
	cdma_tbl_init(&cdev->seg_table, CDMA_SEGMENT_ENTRY_CNT, 0);
}

static void cdma_destroy_tables(struct cdma_dev *cdev)
{
	cdma_tbl_destroy(cdev, &cdev->seg_table, "SEG");
	cdma_tbl_destroy(cdev, &cdev->ctp_table, "CTP");
	cdma_tbl_destroy(cdev, &cdev->jfs_table, "JFS");
	cdma_tbl_destroy(cdev, &cdev->jfc_table, "JFC");
	cdma_tbl_destroy(cdev, &cdev->jfce_table, "JFCE");
	cdma_tbl_destroy(cdev, &cdev->queue_table, "QUEUE");
}

static void cdma_release_table_res(struct cdma_dev *cdev)
{
	struct cdma_queue *queue;
	struct cdma_segment *seg;
	struct cdma_jfc *jfc;
	struct cdma_jfs *jfs;
	struct cdma_tp *tmp;
	int id;

	idr_for_each_entry(&cdev->ctp_table.idr_tbl.idr, tmp, id)
		cdma_destroy_ctp_imm(cdev, tmp->base.tp_id);
	idr_for_each_entry(&cdev->jfs_table.idr_tbl.idr, jfs, id)
		cdma_delete_jfs(cdev, jfs->id);
	idr_for_each_entry(&cdev->jfc_table.idr_tbl.idr, jfc, id)
		cdma_delete_jfc(cdev, jfc->jfcn, NULL);
	idr_for_each_entry(&cdev->queue_table.idr_tbl.idr, queue, id)
		cdma_delete_queue(cdev, queue->id);
	idr_for_each_entry(&cdev->seg_table.idr_tbl.idr, seg, id)
		cdma_unregister_seg(cdev, seg);
}

static void cdma_init_base_dev(struct cdma_dev *cdev)
{
	struct cdma_device_attr *attr = &cdev->base.attr;
	struct cdma_device_cap *dev_cap = &attr->dev_cap;
	struct cdma_caps *caps = &cdev->caps;

	attr->eid.dw0 = cdev->eid;
	dev_cap->max_jfc = caps->jfc.max_cnt;
	dev_cap->max_jfs = caps->jfs.max_cnt;
	dev_cap->max_jfc_depth = caps->jfc.depth;
	dev_cap->max_jfs_depth = caps->jfs.depth;
	dev_cap->trans_mode = caps->trans_mode;
	dev_cap->max_jfs_sge = caps->jfs_sge;
	dev_cap->max_jfs_rsge = caps->jfs_rsge;
	dev_cap->max_msg_size = caps->max_msg_len;
	dev_cap->ceq_cnt = caps->comp_vector_cnt;
	dev_cap->max_jfs_inline_len = caps->jfs_inline_sz;
}

static int cdma_init_iopf_feature(struct cdma_dev *cdev)
{
	u32 ummu_features;
	int sva_mode;

	sva_mode = ummu_get_sva_mode(cdev->dev);
	if (sva_mode != UMMU_SVA_SHARE_MODE &&
	    sva_mode != UMMU_SVA_SEPARATE_MODE) {
		dev_err(cdev->dev, "get sva mode failed, ret = %d\n",
			sva_mode);
		return sva_mode;
	}

	ummu_features = ummu_sva_get_features(cdev->dev);
	cdev->iopf_feature = ummu_features & HW_CAP_IOPF;
	cdev->sva_mode = sva_mode;

	dev_info(cdev->dev, "get sva features = %u, sva_mode = %d\n",
		 ummu_features, sva_mode);

	return 0;
}

static int cdma_init_dev_param(struct cdma_dev *cdev)
{
	struct auxiliary_device *adev = cdev->adev;
	struct ubase_resource_space *mem_base;
	int ret;

	mem_base = ubase_get_mem_base(adev);
	if (!mem_base)
		return -EINVAL;

	cdev->k_db_base = mem_base->addr;
	cdev->db_base = mem_base->addr_unmapped;

	ret = cdma_init_iopf_feature(cdev);
	if (ret)
		return ret;

	cdev->hw_ver = ubase_get_hw_ver(cdev->adev);
	if (cdev->hw_ver == UBASE_HW_VER_UNKNOWN) {
		dev_err(cdev->dev, "failed to get hw version\n");
		return -EINVAL;
	}
	dev_info(cdev->dev, "hw version queried: %u\n", cdev->hw_ver);

	ret = cdma_init_dev_caps(cdev);
	if (ret)
		return ret;

	cdma_init_base_dev(cdev);
	cdma_init_tables(cdev);
	mutex_init(&cdev->db_mutex);
	mutex_init(&cdev->eu_mutex);
	mutex_init(&cdev->file_mutex);
	INIT_LIST_HEAD(&cdev->db_page);
	INIT_LIST_HEAD(&cdev->file_list);

	idr_init(&cdev->ctx_idr);
	spin_lock_init(&cdev->ctx_lock);
	atomic_set(&cdev->cmdcnt, 1);
	atomic_set(&cdev->kcmdcnt, 1);
	init_completion(&cdev->cmddone);
	init_completion(&cdev->kcmddone);
	dev_set_drvdata(&adev->dev, cdev);

	return 0;
}

static void cdma_uninit_dev_param(struct cdma_dev *cdev)
{
	struct cdma_context *tmp;
	int id;

	dev_set_drvdata(&cdev->adev->dev, NULL);

	cdma_release_table_res(cdev);
	idr_for_each_entry(&cdev->ctx_idr, tmp, id)
		cdma_free_context(cdev, tmp);
	idr_destroy(&cdev->ctx_idr);

	mutex_destroy(&cdev->file_mutex);
	mutex_destroy(&cdev->eu_mutex);
	mutex_destroy(&cdev->db_mutex);
	cdma_destroy_tables(cdev);
}

static int cdma_ctrlq_eu_add(struct cdma_dev *cdev, struct eu_info *eu)
{
	struct cdma_device_attr *attr = &cdev->base.attr;
	struct eu_info *eus = cdev->base.attr.eus;
	u8 i;

	for (i = 0; i < attr->eu_num; i++) {
		if (eu->eid_idx != eus[i].eid_idx)
			continue;

		dev_info(cdev->dev,
			 "cdma.%u: eid_idx[0x%x] eid[0x%x->0x%x] upi[0x%x->0x%x] update success\n",
			 cdev->adev->id, eu->eid_idx, eus[i].eid.dw0,
			 eu->eid.dw0, eus[i].upi, eu->upi & CDMA_UPI_MASK);

		eus[i].eid = eu->eid;
		eus[i].upi = eu->upi & CDMA_UPI_MASK;

		if (attr->eu.eid_idx == eu->eid_idx) {
			attr->eu.eid = eu->eid;
			attr->eu.upi = eu->upi & CDMA_UPI_MASK;
		}
		return 0;
	}

	if (attr->eu_num >= CDMA_MAX_EU_NUM) {
		dev_err(cdev->dev, "cdma.%u: eu table is full\n",
			cdev->adev->id);
		return -EINVAL;
	}

	eus[attr->eu_num++] = *eu;
	dev_info(cdev->dev,
		 "cdma.%u: eid_idx[0x%x] eid[0x%x] upi[0x%x] add success\n",
		 cdev->adev->id, eu->eid_idx, eu->eid.dw0,
		 eu->upi & CDMA_UPI_MASK);

	return 0;
}

static int cdma_ctrlq_eu_del(struct cdma_dev *cdev, struct eu_info *eu)
{
	struct cdma_device_attr *attr = &cdev->base.attr;
	struct eu_info *eus = cdev->base.attr.eus;
	int ret = -EINVAL;
	u8 i, j;

	if (!attr->eu_num) {
		dev_err(cdev->dev, "cdma.%u: eu table is empty\n",
			cdev->adev->id);
		return -EINVAL;
	}

	for (i = 0; i < attr->eu_num; i++) {
		if (eu->eid_idx != eus[i].eid_idx)
			continue;

		for (j = i; j < attr->eu_num - 1; j++)
			eus[j] = eus[j + 1];
		memset(&eus[j], 0, sizeof(*eus));

		if (attr->eu.eid_idx == eu->eid_idx)
			attr->eu = eus[0];
		attr->eu_num--;
		ret = 0;
		break;
	}

	dev_info(cdev->dev,
		 "cdma.%u: eid_idx[0x%x] eid[0x%x] upi[0x%x] delete %s\n",
		 cdev->adev->id, eu->eid_idx, eu->eid.dw0,
		 eu->upi & CDMA_UPI_MASK, ret ? "failed" : "success");

	return ret;
}

static int cdma_ctrlq_eu_update_response(struct cdma_dev *cdev, u16 seq, int ret_val)
{
	struct ubase_ctrlq_msg msg = { 0 };
	int inbuf = 0;
	int ret;

	msg.service_ver = UBASE_CTRLQ_SER_VER_01;
	msg.service_type = UBASE_CTRLQ_SER_TYPE_DEV_REGISTER;
	msg.opcode = CDMA_CTRLQ_EU_UPDATE;
	msg.need_resp = 0;
	msg.is_resp = 1;
	msg.resp_seq = seq;
	msg.resp_ret = (uint8_t)(-ret_val);
	msg.in = (void *)&inbuf;
	msg.in_size = sizeof(inbuf);

	ret = ubase_ctrlq_send_msg(cdev->adev, &msg);
	if (ret)
		dev_err(cdev->dev, "send eu update response failed, ret = %d, ret_val = %d\n",
			ret, ret_val);
	return ret;
}

static int cdma_ctrlq_eu_update(struct auxiliary_device *adev, u8 service_ver,
				void *data, u16 len, u16 seq)
{
	struct cdma_dev *cdev = dev_get_drvdata(&adev->dev);
	struct cdma_ctrlq_eu_info eu = { 0 };
	int ret = -EINVAL;

	if (cdev->status != CDMA_NORMAL) {
		dev_err(cdev->dev, "status is abnormal and don't update eu\n");
		return cdma_ctrlq_eu_update_response(cdev, seq, 0);
	}

	if (len < sizeof(eu)) {
		dev_err(cdev->dev, "update eu msg len = %u is invalid\n", len);
		return cdma_ctrlq_eu_update_response(cdev, seq, -EINVAL);
	}

	memcpy(&eu, data, sizeof(eu));
	if (eu.op != CDMA_CTRLQ_EU_ADD && eu.op != CDMA_CTRLQ_EU_DEL) {
		dev_err(cdev->dev, "update eu op = %u is invalid\n", eu.op);
		return cdma_ctrlq_eu_update_response(cdev, seq, -EINVAL);
	}

	if (eu.eu.eid_idx >= CDMA_MAX_EU_NUM) {
		dev_err(cdev->dev, "update eu invalid eid_idx = %u\n",
			eu.eu.eid_idx);
		return cdma_ctrlq_eu_update_response(cdev, seq, -EINVAL);
	}

	mutex_lock(&cdev->eu_mutex);
	if (eu.op == CDMA_CTRLQ_EU_ADD)
		ret = cdma_ctrlq_eu_add(cdev, &eu.eu);
	else if (eu.op == CDMA_CTRLQ_EU_DEL)
		ret = cdma_ctrlq_eu_del(cdev, &eu.eu);
	mutex_unlock(&cdev->eu_mutex);

	return cdma_ctrlq_eu_update_response(cdev, seq, ret);
}

static int cdma_create_arm_db_page(struct cdma_dev *cdev)
{
	cdev->arm_db_page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!cdev->arm_db_page) {
		dev_err(cdev->dev, "alloc dev arm db page failed\n");
		return -ENOMEM;
	}
	return 0;
}

static void cdma_destroy_arm_db_page(struct cdma_dev *cdev)
{
	if (!cdev->arm_db_page)
		return;

	put_page(cdev->arm_db_page);
	cdev->arm_db_page = NULL;
}

static int cdma_register_crq_event(struct auxiliary_device *adev)
{
	struct ubase_ctrlq_event_nb nb = {
		.service_type = UBASE_CTRLQ_SER_TYPE_DEV_REGISTER,
		.opcode = CDMA_CTRLQ_EU_UPDATE,
		.back = adev,
		.crq_handler = cdma_ctrlq_eu_update,
	};
	int ret;

	if (!adev)
		return -EINVAL;

	ret = ubase_ctrlq_register_crq_event(adev, &nb);
	if (ret) {
		dev_err(&adev->dev, "register crq event failed, id = %u, ret = %d\n",
			adev->id, ret);
		return ret;
	}

	return 0;
}

static void cdma_unregister_crq_event(struct auxiliary_device *adev)
{
	ubase_ctrlq_unregister_crq_event(adev,
					 UBASE_CTRLQ_SER_TYPE_DEV_REGISTER,
					 CDMA_CTRLQ_EU_UPDATE);
}

static int cdma_register_event(struct cdma_dev *cdev)
{
	struct auxiliary_device *adev = cdev->adev;
	int ret;

	ret = cdma_reg_ae_event(adev);
	if (ret)
		return ret;

	ret = cdma_reg_ce_event(adev);
	if (ret)
		goto err_ce_register;

	ret = cdma_register_crq_event(adev);
	if (ret)
		goto err_crq_register;

	return 0;
err_crq_register:
	cdma_unreg_ce_event(adev);
err_ce_register:
	cdma_unreg_ae_event(adev);

	return ret;
}

static inline void cdma_unregister_event(struct cdma_dev *cdev)
{
	struct auxiliary_device *adev = cdev->adev;

	cdma_unregister_crq_event(adev);
	cdma_unreg_ce_event(adev);
	cdma_unreg_ae_event(adev);
}

struct cdma_func_map {
	char err_msg[SZ_64];
	int (*init_func)(struct cdma_dev *cdev);
	void (*uninit_func)(struct cdma_dev *cdev);
};

static const struct cdma_func_map cdma_dev_func_map[] = {
	{"dev tid", cdma_alloc_dev_tid, cdma_free_dev_tid},
	{"dev param", cdma_init_dev_param, cdma_uninit_dev_param},
	{"debugfs", cdma_dbg_init, cdma_dbg_uninit},
	{"db page", cdma_create_arm_db_page, cdma_destroy_arm_db_page},
	{"event", cdma_register_event, cdma_unregister_event},
	{"device list", cdma_add_device_to_list, cdma_del_device_from_list},
};

void cdma_destroy_dev(struct cdma_dev *cdev)
{
	int i;

	for (i = ARRAY_SIZE(cdma_dev_func_map) - 1; i >= 0; i--)
		if (cdma_dev_func_map[i].uninit_func)
			cdma_dev_func_map[i].uninit_func(cdev);

	kfree(cdev);
}

struct cdma_dev *cdma_create_dev(struct auxiliary_device *adev)
{
	struct cdma_dev *cdev;
	int ret, i;

	cdev = kzalloc((sizeof(*cdev)), GFP_KERNEL);
	if (!cdev)
		return ERR_PTR(-ENOMEM);

	cdev->adev = adev;
	cdev->dev = adev->dev.parent;

	for (i = 0; i < ARRAY_SIZE(cdma_dev_func_map); i++) {
		if (!cdma_dev_func_map[i].init_func)
			continue;

		ret = cdma_dev_func_map[i].init_func(cdev);
		if (ret) {
			dev_err(cdev->dev, "Failed to init %s, ret = %d\n",
				cdma_dev_func_map[i].err_msg, ret);
			ret = -EFAULT;
			goto err_init;
		}
	}

	ret = cdma_ctrlq_query_eu(cdev);
	if (ret == -ETIMEDOUT)
		goto err_init;

	return cdev;
err_init:
	for (i -= 1; i >= 0; i--)
		if (cdma_dev_func_map[i].uninit_func)
			cdma_dev_func_map[i].uninit_func(cdev);

	kfree(cdev);

	return ERR_PTR(ret);
}

bool cdma_find_seid_in_eus(struct eu_info *eus, u8 eu_num, struct dev_eid *eid,
			   struct eu_info *eu_out)
{
	u32 i;

	for (i = 0; i < eu_num; i++)
		if (memcmp(&eus[i].eid, eid, sizeof(*eid)) == 0) {
			*eu_out = eus[i];
			return true;
		}

	return false;
}
