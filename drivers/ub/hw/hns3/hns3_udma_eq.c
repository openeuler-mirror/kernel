// SPDX-License-Identifier: GPL-2.0
/* Huawei HNS3_UDMA Linux driver
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

#include <linux/acpi.h>
#include "urma/ubcore_uapi.h"
#include "hnae3.h"
#include "hns3_udma_hem.h"
#include "hns3_udma_db.h"
#include "hns3_udma_jfc.h"
#include "hns3_udma_jfr.h"
#include "hns3_udma_eq.h"

static int alloc_eq_buf(struct hns3_udma_dev *udma_dev, struct hns3_udma_eq *eq)
{
	struct hns3_udma_buf_attr buf_attr = {};
	int err;

	if (udma_dev->caps.eqe_hop_num == HNS3_UDMA_HOP_NUM_0)
		eq->hop_num = 0;
	else
		eq->hop_num = udma_dev->caps.eqe_hop_num;

	buf_attr.page_shift = PAGE_SHIFT;
	buf_attr.region[0].size = eq->entries * eq->eqe_size;
	buf_attr.region[0].hopnum = eq->hop_num;
	buf_attr.region_count = 1;

	err = hns3_udma_mtr_create(udma_dev, &eq->mtr, &buf_attr,
				   udma_dev->caps.eqe_ba_pg_sz + PAGE_SHIFT, 0,
				   0);
	if (err)
		dev_err(udma_dev->dev,
			"Failed to alloc EQE mtr, err %d.\n", err);

	return err;
}

static void init_eq_config(struct hns3_udma_dev *udma_dev, struct hns3_udma_eq *eq)
{
	eq->db_reg = udma_dev->reg_base + HNS3_UDMA_VF_EQ_DB_CFG0_REG;
	eq->cons_index = 0;
	eq->over_ignore = HNS3_UDMA_EQ_OVER_IGNORE_0;
	eq->coalesce = HNS3_UDMA_EQ_COALESCE_0;
	eq->arm_st = HNS3_UDMA_EQ_ALWAYS_ARMED;
	eq->shift = ilog2((uint32_t)eq->entries);
}

static int config_eqc(struct hns3_udma_dev *udma_dev, struct hns3_udma_eq *eq,
		      void *mb_buf)
{
	uint64_t eqe_ba[MTT_MIN_COUNT] = {};
	struct hns3_udma_eq_context *eqc;
	uint64_t bt_ba = 0;
	int count;

	eqc = (struct hns3_udma_eq_context *)mb_buf;
	memset(eqc, 0, sizeof(struct hns3_udma_eq_context));

	/* if not multi-hop, eqe buffer only use one trunk */
	count = hns3_udma_mtr_find(udma_dev, &eq->mtr, 0, eqe_ba, MTT_MIN_COUNT,
				   &bt_ba);
	if (count < 1) {
		dev_err(udma_dev->dev, "failed to find EQE mtr.\n");
		return -ENOBUFS;
	}

	hns3_udma_reg_write(eqc, EQC_EQ_ST, HNS3_UDMA_EQ_STATE_VALID);
	hns3_udma_reg_write(eqc, EQC_EQE_HOP_NUM, eq->hop_num);
	hns3_udma_reg_write(eqc, EQC_OVER_IGNORE, eq->over_ignore);
	hns3_udma_reg_write(eqc, EQC_COALESCE, eq->coalesce);
	hns3_udma_reg_write(eqc, EQC_ARM_ST, eq->arm_st);
	hns3_udma_reg_write(eqc, EQC_EQN, eq->eqn);
	hns3_udma_reg_write(eqc, EQC_EQE_CNT, HNS3_UDMA_EQ_INIT_EQE_CNT);
	hns3_udma_reg_write(eqc, EQC_EQE_BA_PG_SZ,
			    to_hns3_udma_hw_page_shift(eq->mtr.hem_cfg.ba_pg_shift));
	hns3_udma_reg_write(eqc, EQC_EQE_BUF_PG_SZ,
			    to_hns3_udma_hw_page_shift(eq->mtr.hem_cfg.buf_pg_shift));
	hns3_udma_reg_write(eqc, EQC_EQ_PROD_INDX, HNS3_UDMA_EQ_INIT_PROD_IDX);
	hns3_udma_reg_write(eqc, EQC_EQ_MAX_CNT, eq->eq_max_cnt);

	hns3_udma_reg_write(eqc, EQC_EQ_PERIOD, eq->eq_period);
	hns3_udma_reg_write(eqc, EQC_EQE_REPORT_TIMER, HNS3_UDMA_EQ_INIT_REPORT_TIMER);
	hns3_udma_reg_write(eqc, EQC_EQE_BA_L, bt_ba >> EQC_EQE_BA_L_SHIFT);
	hns3_udma_reg_write(eqc, EQC_EQE_BA_H, bt_ba >> EQC_EQE_BA_H_SHIFT);
	hns3_udma_reg_write(eqc, EQC_SHIFT, eq->shift);
	hns3_udma_reg_write(eqc, EQC_MSI_INDX, HNS3_UDMA_EQ_INIT_MSI_IDX);
	hns3_udma_reg_write(eqc, EQC_CUR_EQE_BA_L, eqe_ba[0] >>
			    EQC_CUR_EQE_BA_L_SHIFT);
	hns3_udma_reg_write(eqc, EQC_CUR_EQE_BA_M, eqe_ba[0] >>
			    EQC_CUR_EQE_BA_M_SHIFT);
	hns3_udma_reg_write(eqc, EQC_CUR_EQE_BA_H, eqe_ba[0] >>
			    EQC_CUR_EQE_BA_H_SHIFT);
	hns3_udma_reg_write(eqc, EQC_EQ_CONS_INDX, HNS3_UDMA_EQ_INIT_CONS_IDX);
	hns3_udma_reg_write(eqc, EQC_NEX_EQE_BA_L, eqe_ba[1] >>
			    EQC_NEX_EQE_BA_L_SHIFT);
	hns3_udma_reg_write(eqc, EQC_NEX_EQE_BA_H, eqe_ba[1] >>
			    EQC_NEX_EQE_BA_H_SHIFT);
	hns3_udma_reg_write(eqc, EQC_EQE_SIZE, eq->eqe_size == HNS3_UDMA_EQE_SIZE);

	return 0;
}

static void free_eq_buf(struct hns3_udma_dev *udma_dev, struct hns3_udma_eq *eq)
{
	hns3_udma_mtr_destroy(udma_dev, &eq->mtr);
}

static int hns3_udma_create_eq(struct hns3_udma_dev *udma_dev, struct hns3_udma_eq *eq,
			       uint32_t eq_cmd)
{
	struct hns3_udma_cmd_mailbox *mailbox;
	struct hns3_udma_cmq_desc desc;
	struct hns3_udma_mbox *mb;
	int ret;

	/* Allocate mailbox memory */
	mailbox = hns3_udma_alloc_cmd_mailbox(udma_dev);
	if (IS_ERR(mailbox))
		return -ENOMEM;

	ret = alloc_eq_buf(udma_dev, eq);
	if (ret) {
		dev_err(udma_dev->dev, "failed to alloc eq buf.\n");
		goto err_cmd_mbox;
	}
	ret = config_eqc(udma_dev, eq, mailbox->buf);
	if (ret) {
		dev_err(udma_dev->dev, "[mailbox cmd] config eqc failed.\n");
		goto err_eq_buf;
	}

	mb = (struct hns3_udma_mbox *)desc.data;
	hns3_udma_cmq_setup_basic_desc(&desc, HNS3_UDMA_OPC_POST_MB, false);
	mbox_desc_init(mb, mailbox->dma, 0, eq->eqn, eq_cmd);
	ret = hns3_udma_cmd_mbox(udma_dev, &desc, HNS3_UDMA_CMD_TIMEOUT_MSECS, 0);
	if (ret) {
		dev_err(udma_dev->dev, "[mailbox cmd] create eqc failed.\n");
		goto err_eq_buf;
	}

	hns3_udma_free_cmd_mailbox(udma_dev, mailbox);
	return 0;

err_eq_buf:
	free_eq_buf(udma_dev, eq);
err_cmd_mbox:
	hns3_udma_free_cmd_mailbox(udma_dev, mailbox);

	return ret;
}

static struct hns3_udma_aeqe *next_aeqe_sw_v2(struct hns3_udma_eq *eq)
{
	struct hns3_udma_aeqe *aeqe;

	aeqe = (struct hns3_udma_aeqe *)hns3_udma_buf_offset(eq->mtr.kmem,
							     (eq->cons_index & (eq->entries - 1)) *
							     eq->eqe_size);

	return (hns3_udma_get_bit(aeqe->asyn, HNS3_UDMA_AEQ_AEQE_OWNER_S) ^
		!!(eq->cons_index & eq->entries)) ? aeqe : NULL;
}

static void aeq_event_dump(struct device *dev, struct hns3_udma_work *irq_work)
{
	switch (irq_work->event_type) {
	case HNS3_UDMA_EVENT_TYPE_COMM_EST:
		break;
	case HNS3_UDMA_EVENT_TYPE_WQ_CATAS_ERROR:
		dev_err(dev, "Local work queue 0x%x catast error, sub_event type is: 0x%x.\n",
			irq_work->queue_num, irq_work->sub_type);
		break;
	case HNS3_UDMA_EVENT_TYPE_INV_REQ_LOCAL_WQ_ERROR:
		dev_err(dev,
			"Invalid request local work queue 0x%x error.\n",
			irq_work->queue_num);
		break;
	case HNS3_UDMA_EVENT_TYPE_LOCAL_WQ_ACCESS_ERROR:
		dev_err(dev,
			"Local access violation work queue 0x%x error, sub_event type is: 0x%x.\n",
			irq_work->queue_num, irq_work->sub_type);
		break;
	case HNS3_UDMA_EVENT_TYPE_JFR_LIMIT_REACH:
		dev_warn(dev, "JFR limit reach.\n");
		break;
	case HNS3_UDMA_EVENT_TYPE_JFR_LAST_WQE_REACH:
		dev_warn(dev, "JFR last wqe reach.\n");
		break;
	case HNS3_UDMA_EVENT_TYPE_JFC_ACCESS_ERROR:
		dev_err(dev, "JFC 0x%x access err.\n",
			irq_work->queue_num);
		break;
	case HNS3_UDMA_EVENT_TYPE_JFC_OVERFLOW:
		dev_warn(dev, "JFC 0x%x overflow.\n",
			 irq_work->queue_num);
		break;
	default:
		break;
	}
}

static void aeq_event_report(struct hns3_udma_dev *udma_dev,
			     struct hns3_udma_work *irq_work)
{
	struct hns3_udma_aeqe *aeqe = &irq_work->aeqe;
	uint32_t queue_num = irq_work->queue_num;
	int event_type = irq_work->event_type;
	uint32_t *tmp = (uint32_t *)aeqe;
	int sub_type;

	sub_type = hns3_udma_get_field(aeqe->asyn,
				       HNS3_UDMA_AEQE_SUB_TYPE_M,
				       HNS3_UDMA_AEQE_SUB_TYPE_S);
	if (event_type != HNS3_UDMA_EVENT_TYPE_COMM_EST)
		dev_err(udma_dev->dev, "print AEQE: 0x%x, 0x%x; "
			"queue:0x%x event_type:0x%x, sub_type:0x%x\n",
			*tmp, *(tmp + 1), queue_num, event_type,
			sub_type);

	switch (event_type) {
	case HNS3_UDMA_EVENT_TYPE_COMM_EST:
	case HNS3_UDMA_EVENT_TYPE_WQ_CATAS_ERROR:
	case HNS3_UDMA_EVENT_TYPE_JFR_LAST_WQE_REACH:
	case HNS3_UDMA_EVENT_TYPE_INV_REQ_LOCAL_WQ_ERROR:
	case HNS3_UDMA_EVENT_TYPE_LOCAL_WQ_ACCESS_ERROR:
		hns3_udma_qp_event(udma_dev, queue_num, event_type);
		break;
	case HNS3_UDMA_EVENT_TYPE_JFR_LIMIT_REACH:
		hns3_udma_jfr_event(udma_dev, queue_num, event_type);
		break;
	case HNS3_UDMA_EVENT_TYPE_JFC_ACCESS_ERROR:
	case HNS3_UDMA_EVENT_TYPE_JFC_OVERFLOW:
		hns3_udma_jfc_event(udma_dev, queue_num, event_type);
		break;
	case HNS3_UDMA_EVENT_TYPE_MB:
		hns3_udma_cmd_event(udma_dev,
				    le16_to_cpu(aeqe->event.cmd.token),
				    aeqe->event.cmd.status,
				    le64_to_cpu(aeqe->event.cmd.out_param));
		break;
	default:
		dev_err(udma_dev->dev,
			"Unhandled event %d on EQ %d at idx %u.\n",
			event_type, irq_work->eqn, irq_work->eq_ci);
		break;
	}
}

static void hns3_udma_irq_work_handle(struct work_struct *work)
{
	struct hns3_udma_work *irq_work =
				container_of(work, struct hns3_udma_work, work);
	struct device *dev = irq_work->udma_dev->dev;

	aeq_event_dump(dev, irq_work);
	aeq_event_report(irq_work->udma_dev, irq_work);

	kfree(irq_work);
}

static void hns3_udma_init_irq_work(struct hns3_udma_dev *udma_dev, struct hns3_udma_eq *eq,
				    struct hns3_udma_aeqe *aeqe, uint32_t queue_num)
{
	struct hns3_udma_work *irq_work;

	irq_work = kzalloc(sizeof(struct hns3_udma_work), GFP_ATOMIC);
	if (!irq_work)
		return;

	irq_work->udma_dev = udma_dev;
	irq_work->event_type = eq->event_type;
	irq_work->sub_type = eq->sub_type;
	irq_work->queue_num = queue_num;
	irq_work->eq_ci = eq->cons_index;
	irq_work->eqn = eq->eqn;

	memcpy(&irq_work->aeqe, aeqe, sizeof(struct hns3_udma_aeqe));

	INIT_WORK(&irq_work->work, hns3_udma_irq_work_handle);
	queue_work(udma_dev->irq_workq, &irq_work->work);
}

static inline void hns3_udma_write64(struct hns3_udma_dev *udma_dev, uint32_t val[2],
				     void __iomem *dest)
{
	struct hns3_udma_priv *priv = (struct hns3_udma_priv *)udma_dev->priv;
	struct hnae3_handle *handle = priv->handle;
	const struct hnae3_ae_ops *ops = handle->ae_algo->ops;

	if (!udma_dev->dis_db && !ops->get_hw_reset_stat(handle))
		writeq(*(uint64_t *)val, dest);
}

static void update_eq_db(struct hns3_udma_eq *eq)
{
	struct hns3_udma_dev *udma_dev = eq->udma_dev;
	struct hns3_udma_eq_db eq_db = {};

	if (eq->type_flag == HNS3_UDMA_AEQ) {
		hns3_udma_reg_write(&eq_db, HNS3_UDMA_EQ_DB_CMD,
			       eq->arm_st == HNS3_UDMA_EQ_ALWAYS_ARMED ?
					     HNS3_UDMA_EQ_DB_CMD_AEQ :
					     HNS3_UDMA_EQ_DB_CMD_AEQ_ARMED);
	} else {
		hns3_udma_reg_write(&eq_db, HNS3_UDMA_EQ_DB_TAG, eq->eqn);

		hns3_udma_reg_write(&eq_db, HNS3_UDMA_EQ_DB_CMD,
			       eq->arm_st == HNS3_UDMA_EQ_ALWAYS_ARMED ?
					     HNS3_UDMA_EQ_DB_CMD_CEQ :
					     HNS3_UDMA_EQ_DB_CMD_CEQ_ARMED);
	}

	hns3_udma_reg_write(&eq_db, HNS3_UDMA_EQ_DB_CI, eq->cons_index);

	hns3_udma_write64(udma_dev, (uint32_t *)&eq_db, eq->db_reg);
}

static int hns3_udma_aeq_int(struct hns3_udma_dev *udma_dev, struct hns3_udma_eq *eq)
{
	struct hns3_udma_aeqe *aeqe = next_aeqe_sw_v2(eq);
	int aeqe_found = 0;
	uint32_t queue_num;
	int event_type;
	uint32_t *tmp;
	int sub_type;

	while (aeqe) {
		/* Make sure we read AEQ entry after we have checked the
		 * ownership bit
		 */
		dma_rmb();

		event_type = hns3_udma_get_field(aeqe->asyn,
						 HNS3_UDMA_AEQE_EVENT_TYPE_M,
						 HNS3_UDMA_AEQE_EVENT_TYPE_S);
		sub_type = hns3_udma_get_field(aeqe->asyn,
					       HNS3_UDMA_AEQE_SUB_TYPE_M,
					       HNS3_UDMA_AEQE_SUB_TYPE_S);
		queue_num = hns3_udma_get_field(aeqe->event.queue_event.num,
						HNS3_UDMA_AEQE_EVENT_QUEUE_NUM_M,
						HNS3_UDMA_AEQE_EVENT_QUEUE_NUM_S);
		tmp = (uint32_t *)aeqe;

		eq->event_type = event_type;
		eq->sub_type = sub_type;
		aeqe_found = 1;

		++eq->cons_index;

		udma_dev->dfx_cnt[HNS3_UDMA_DFX_AEQE]++;
		BUILD_BUG_ON(sizeof(struct hns3_udma_aeqe) > TRACE_AEQE_LEN_MAX);

		hns3_udma_init_irq_work(udma_dev, eq, aeqe, queue_num);

		aeqe = next_aeqe_sw_v2(eq);
	}

	update_eq_db(eq);
	return aeqe_found;
}

static struct hns3_udma_ceqe *next_ceqe_sw_v2(struct hns3_udma_eq *eq)
{
	struct hns3_udma_ceqe *ceqe;

	ceqe = (struct hns3_udma_ceqe *)hns3_udma_buf_offset(eq->mtr.kmem,
				   (eq->cons_index & (eq->entries - 1)) *
				   eq->eqe_size);

	return (!!(hns3_udma_get_bit(ceqe->comp, HNS3_UDMA_CEQ_CEQE_OWNER_S))) ^
		(!!(eq->cons_index & eq->entries)) ? ceqe : NULL;
}

static int hns3_udma_ceq_int(struct hns3_udma_dev *udma_dev,
			     struct hns3_udma_eq *eq)
{
	struct hns3_udma_ceqe *ceqe = next_ceqe_sw_v2(eq);
	int ceqe_found = 0;
	uint32_t cqn;

	while (ceqe) {
		/* Make sure we read CEQ entry after we have checked the
		 * ownership bit
		 */
		dma_rmb();

		cqn = hns3_udma_get_field(ceqe->comp, HNS3_UDMA_CEQE_COMP_CQN_M,
					  HNS3_UDMA_CEQE_COMP_CQN_S);

		hns3_udma_jfc_completion(udma_dev, cqn);

		++eq->cons_index;
		udma_dev->dfx_cnt[HNS3_UDMA_DFX_CEQE]++;
		ceqe_found = 1;

		ceqe = next_ceqe_sw_v2(eq);
	}

	update_eq_db(eq);

	return ceqe_found;
}

static int fmea_ram_ecc_query(struct hns3_udma_dev *udma_dev,
			      struct fmea_ram_ecc *ecc_info)
{
	struct hns3_udma_cmq_desc desc;
	struct hns3_udma_cmq_req *req;
	int ret;

	req = (struct hns3_udma_cmq_req *)desc.data;

	hns3_udma_cmq_setup_basic_desc(&desc, HNS3_UDMA_QUERY_RAM_ECC, true);
	ret = hns3_udma_cmq_send(udma_dev, &desc, 1);
	if (ret)
		return ret;

	ecc_info->is_ecc_err = hns3_udma_reg_read(req, QUERY_RAM_ECC_1BIT_ERR);
	ecc_info->res_type = hns3_udma_reg_read(req, QUERY_RAM_ECC_RES_TYPE);
	ecc_info->index = hns3_udma_reg_read(req, QUERY_RAM_ECC_TAG);

	return 0;
}

static int fmea_recover_gmv(struct hns3_udma_dev *udma_dev, uint32_t idx)
{
	struct hns3_udma_cmq_desc desc;
	struct hns3_udma_cmq_req *req;
	uint32_t addr_upper;
	uint32_t addr_low;
	int ret;

	req = (struct hns3_udma_cmq_req *)desc.data;

	hns3_udma_cmq_setup_basic_desc(&desc, HNS3_UDMA_OPC_CFG_GMV_BT, true);
	hns3_udma_reg_write(req, CFG_GMV_BT_IDX, idx);
	hns3_udma_reg_write(req, CFG_GMV_BT_VF_ID, 0);

	ret = hns3_udma_cmq_send(udma_dev, &desc, 1);
	if (ret) {
		dev_err(udma_dev->dev,
			"failed to execute cmd to read gmv, ret = %d.\n", ret);
		return ret;
	}

	addr_low = hns3_udma_reg_read(req, CFG_GMV_BT_BA_L);
	addr_upper = hns3_udma_reg_read(req, CFG_GMV_BT_BA_H);

	hns3_udma_cmq_setup_basic_desc(&desc, HNS3_UDMA_OPC_CFG_GMV_BT, false);
	hns3_udma_reg_write(req, CFG_GMV_BT_BA_L, addr_low);
	hns3_udma_reg_write(req, CFG_GMV_BT_BA_H, addr_upper);
	hns3_udma_reg_write(req, CFG_GMV_BT_IDX, idx);
	hns3_udma_reg_write(req, CFG_GMV_BT_VF_ID, 0);

	return hns3_udma_cmq_send(udma_dev, &desc, 1);
}

static uint64_t fmea_get_ram_res_addr(uint32_t res_type, uint64_t *data)
{
	if (res_type == ECC_RESOURCE_QPC_TIMER ||
	    res_type == ECC_RESOURCE_CQC_TIMER ||
	    res_type == ECC_RESOURCE_SCCC)
		return le64_to_cpu(*data);

	return le64_to_cpu(*data) << PAGE_SHIFT;
}

static int fmea_recover_others(struct hns3_udma_dev *udma_dev, uint32_t res_type,
			       uint32_t index)
{
	struct hns3_udma_cmd_mailbox *mailbox = hns3_udma_alloc_cmd_mailbox(udma_dev);
	uint8_t write_bt0_op = fmea_ram_res[res_type].write_bt0_op;
	uint8_t read_bt0_op = fmea_ram_res[res_type].read_bt0_op;
	struct hns3_udma_cmq_desc desc;
	struct hns3_udma_mbox *mb;
	uint64_t addr;
	int ret;

	if (IS_ERR(mailbox))
		return PTR_ERR(mailbox);

	mb = (struct hns3_udma_mbox *)desc.data;
	hns3_udma_cmq_setup_basic_desc(&desc, HNS3_UDMA_OPC_POST_MB, false);
	mbox_desc_init(mb, 0, mailbox->dma, index, read_bt0_op);
	ret = hns3_udma_cmd_mbox(udma_dev, &desc, HNS3_UDMA_CMD_TIMEOUT_MSECS, 0);
	if (ret) {
		dev_err(udma_dev->dev,
			"failed to execute cmd to read fmea ram, ret = %d.\n",
			ret);
		goto out;
	}

	addr = fmea_get_ram_res_addr(res_type, (uint64_t *)(mailbox->buf));

	mb = (struct hns3_udma_mbox *)desc.data;
	hns3_udma_cmq_setup_basic_desc(&desc, HNS3_UDMA_OPC_POST_MB, false);
	mbox_desc_init(mb, addr, 0, index, write_bt0_op);
	ret = hns3_udma_cmd_mbox(udma_dev, &desc, HNS3_UDMA_CMD_TIMEOUT_MSECS, 0);
	if (ret)
		dev_err(udma_dev->dev,
			"failed to execute cmd to write fmea ram, ret = %d.\n",
			ret);

out:
	hns3_udma_free_cmd_mailbox(udma_dev, mailbox);

	return ret;
}

static void fmea_ram_ecc_recover(struct hns3_udma_dev *udma_dev,
				 struct fmea_ram_ecc *ecc_info)
{
	uint32_t res_type = ecc_info->res_type;
	uint32_t index = ecc_info->index;
	int ret;

	BUILD_BUG_ON(ARRAY_SIZE(fmea_ram_res) != ECC_RESOURCE_COUNT);

	if (res_type >= ECC_RESOURCE_COUNT) {
		dev_err(udma_dev->dev, "unsupported fmea ram ecc type %u.\n",
			res_type);
		return;
	}

	if (res_type == ECC_RESOURCE_GMV)
		ret = fmea_recover_gmv(udma_dev, index);
	else
		ret = fmea_recover_others(udma_dev, res_type, index);

	if (ret)
		dev_err(udma_dev->dev,
			"failed to recover %s, index = %u, ret = %d.\n",
			fmea_ram_res[res_type].name, index, ret);
}

static void fmea_ram_ecc_work(struct work_struct *ecc_work)
{
	struct hns3_udma_dev *udma_dev =
		container_of(ecc_work, struct hns3_udma_dev, ecc_work);
	struct fmea_ram_ecc ecc_info = {};

	if (fmea_ram_ecc_query(udma_dev, &ecc_info)) {
		dev_err(udma_dev->dev, "failed to query fmea ram ecc.\n");
		return;
	}

	if (!ecc_info.is_ecc_err) {
		dev_err(udma_dev->dev, "there is no fmea ram ecc found.\n");
		return;
	}

	fmea_ram_ecc_recover(udma_dev, &ecc_info);
}

static irqreturn_t abnormal_interrupt_basic(struct hns3_udma_dev *udma_dev,
					    uint32_t int_st)
{
	struct pci_dev *pdev = udma_dev->pci_dev;
	struct hnae3_ae_dev *ae_dev = pci_get_drvdata(pdev);
	const struct hnae3_ae_ops *ops = ae_dev->ops;
	irqreturn_t int_work = IRQ_NONE;
	uint32_t int_en;

	int_en = ub_read(udma_dev, HNS3_UDMA_VF_ABN_INT_EN_REG);
	if (int_st & BIT(HNS3_UDMA_VF_INT_ST_AEQ_OVERFLOW_S)) {
		dev_err(udma_dev->dev, "AEQ overflow!\n");

		ub_write(udma_dev, HNS3_UDMA_VF_ABN_INT_ST_REG,
			 1 << HNS3_UDMA_VF_INT_ST_AEQ_OVERFLOW_S);

		/* Set reset level for reset_event() */
		if (ops->set_default_reset_request)
			ops->set_default_reset_request(ae_dev,
						       HNAE3_FUNC_RESET);
		if (ops->reset_event)
			ops->reset_event(pdev, NULL);

		int_en |= 1 << HNS3_UDMA_VF_ABN_INT_EN_S;
		ub_write(udma_dev, HNS3_UDMA_VF_ABN_INT_EN_REG, int_en);

		int_work = IRQ_HANDLED;
	} else {
		dev_err(udma_dev->dev, "there is no basic abn irq found.\n");
	}

	return IRQ_RETVAL(int_work);
}

static irqreturn_t hns3_udma_msix_interrupt_abn(int irq, void *dev_id)
{
	struct hns3_udma_dev *udma_dev = (struct hns3_udma_dev *)dev_id;
	int int_work = 0;
	uint32_t int_st;

	int_st = ub_read(udma_dev, HNS3_UDMA_VF_ABN_INT_ST_REG);
	if (int_st) {
		int_work = abnormal_interrupt_basic(udma_dev, int_st);
	} else {
		dev_err(udma_dev->dev, "ECC 1bit ERROR!\n");
		queue_work(udma_dev->irq_workq, &udma_dev->ecc_work);
		int_work = IRQ_HANDLED;
	}

	return IRQ_RETVAL(int_work);
}

static irqreturn_t hns3_udma_msix_interrupt_eq(int irq, void *eq_ptr)
{
	struct hns3_udma_eq *eq = (struct hns3_udma_eq *)eq_ptr;
	struct hns3_udma_dev *udma_dev = eq->udma_dev;
	int int_work;

	if (eq->type_flag == HNS3_UDMA_CEQ)
		/* Completion event interrupt */
		int_work = hns3_udma_ceq_int(udma_dev, eq);
	else
		/* Asychronous event interrupt */
		int_work = hns3_udma_aeq_int(udma_dev, eq);

	return IRQ_RETVAL(int_work);
}

static int alloc_and_set_irq_name(struct hns3_udma_dev *udma_dev, int irq_num,
				  int aeq_num, int other_num)
{
	int ret = 0;
	int i;

	if ((irq_num > HNS3_UDMA_MAX_IRQ_NUM) ||
	    (irq_num < (other_num + aeq_num))) {
		dev_err(udma_dev->dev, "check irq num fail: irqn %d, aeqn %d, other %d",
			irq_num, aeq_num, other_num);
		return -EINVAL;
	}

	for (i = 0; i < irq_num; i++) {
		udma_dev->irq_names[i] = kzalloc(HNS3_UDMA_INT_NAME_LEN, GFP_KERNEL);
		if (!udma_dev->irq_names[i]) {
			ret = -ENOMEM;
			goto err_kzalloc_failed;
		}
	}

	/* irq contains: abnormal + AEQ + CEQ */
	for (i = 0; i < other_num; i++)
		snprintf((char *)udma_dev->irq_names[i], HNS3_UDMA_INT_NAME_LEN,
			 "hns3_udma-abn-%d", i);

	for (i = other_num; i < (other_num + aeq_num); i++)
		snprintf((char *)udma_dev->irq_names[i], HNS3_UDMA_INT_NAME_LEN,
			 "hns3_udma-aeq-%d", i - other_num);

	for (i = (other_num + aeq_num); i < irq_num; i++)
		snprintf((char *)udma_dev->irq_names[i], HNS3_UDMA_INT_NAME_LEN,
			 "hns3_udma-ceq-%d", i - other_num - aeq_num);
	return ret;

err_kzalloc_failed:
	for (i -= 1; i >= 0; i--)
		kfree(udma_dev->irq_names[i]);

	return ret;
}

static int hns3_udma_request_irq(struct hns3_udma_dev *udma_dev, int irq_num,
				 int ceq_num, int aeq_num, int other_num)
{
	struct hns3_udma_eq_table *eq_table = &udma_dev->eq_table;
	int ret;
	int j;

	ret = alloc_and_set_irq_name(udma_dev, irq_num, aeq_num, other_num);
	if (ret)
		return ret;
	for (j = 0; j < irq_num; j++) {
		if (j < other_num)
			ret = request_irq(udma_dev->irq[j],
					  hns3_udma_msix_interrupt_abn,
					  0, udma_dev->irq_names[j], udma_dev);

		else if (j < (other_num + ceq_num))
			ret = request_irq(eq_table->eq[j - other_num].irq,
					  hns3_udma_msix_interrupt_eq,
					  0, udma_dev->irq_names[j + aeq_num],
					  &eq_table->eq[j - other_num]);
		else
			ret = request_irq(eq_table->eq[j - other_num].irq,
					  hns3_udma_msix_interrupt_eq,
					  0, udma_dev->irq_names[j - ceq_num],
					  &eq_table->eq[j - other_num]);
		if (ret) {
			dev_err(udma_dev->dev, "Request irq error!\n");
			goto err_request_failed;
		}
	}

	return 0;

err_request_failed:
	for (j -= 1; j >= 0; j--)
		if (j < other_num)
			free_irq(udma_dev->irq[j], udma_dev);
		else
			free_irq(eq_table->eq[j - other_num].irq,
				 &eq_table->eq[j - other_num]);
	for (j = irq_num - 1; j >= 0; j--)
		kfree(udma_dev->irq_names[j]);

	return ret;
}

static void hns3_udma_int_mask_enable(struct hns3_udma_dev *udma_dev,
				      int eq_num, uint32_t enable_flag)
{
	int i;

	for (i = 0; i < eq_num; i++)
		ub_write(udma_dev, HNS3_UDMA_VF_EVENT_INT_EN_REG +
			 i * EQ_REG_OFFSET, enable_flag);

	ub_write(udma_dev, HNS3_UDMA_VF_ABN_INT_EN_REG, enable_flag);
	ub_write(udma_dev, HNS3_UDMA_VF_ABN_INT_CFG_REG, enable_flag);
}

static void set_jfce_attr(struct hns3_udma_dev *udma_dev, struct hns3_udma_eq *eq,
			  int idx)
{
	eq->type_flag = HNS3_UDMA_CEQ;
	eq->entries = udma_dev->caps.ceqe_depth;
	eq->eqe_size = udma_dev->caps.ceqe_size;
	eq->irq = udma_dev->irq[idx];
	eq->eq_max_cnt = HNS3_UDMA_CEQ_DEFAULT_BURST_NUM;
	eq->eq_period = HNS3_UDMA_CEQ_DEFAULT_INTERVAL;
}

static void set_jfae_attr(struct hns3_udma_dev *udma_dev, struct hns3_udma_eq *eq,
			  int idx)
{
	eq->type_flag = HNS3_UDMA_AEQ;
	eq->entries = udma_dev->caps.aeqe_depth;
	eq->eqe_size = udma_dev->caps.aeqe_size;
	eq->irq = udma_dev->irq[idx];
	eq->eq_max_cnt = HNS3_UDMA_AEQ_DEFAULT_BURST_NUM;
	eq->eq_period = HNS3_UDMA_AEQ_DEFAULT_INTERVAL;
}

static void hns3_udma_destroy_eq(struct hns3_udma_dev *udma_dev, struct hns3_udma_eq *eq)
{
	struct device *dev = udma_dev->dev;
	struct hns3_udma_cmq_desc desc;
	struct hns3_udma_mbox *mb;
	int eqn = eq->eqn;
	uint16_t eq_cmd;
	int ret;

	mb = (struct hns3_udma_mbox *)desc.data;
	hns3_udma_cmq_setup_basic_desc(&desc, HNS3_UDMA_OPC_POST_MB, false);
	if (eqn < udma_dev->caps.num_comp_vectors)
		eq_cmd = HNS3_UDMA_CMD_DESTROY_CEQC;
	else
		eq_cmd = HNS3_UDMA_CMD_DESTROY_AEQC;
	mbox_desc_init(mb, 0, 0, eqn & HNS3_UDMA_EQN_M, eq_cmd);

	ret = hns3_udma_cmd_mbox(udma_dev, &desc, HNS3_UDMA_CMD_TIMEOUT_MSECS, 0);
	if (ret)
		dev_err(dev, "[mailbox cmd] destroy eqc(%d) failed.\n", eqn);
	free_eq_buf(udma_dev, eq);
}

static int hns3_udma_create_hw_eq(struct hns3_udma_dev *udma_dev, int ceq_num,
				  int aeq_num, int other_num)
{
	struct hns3_udma_eq_table *eq_table = &udma_dev->eq_table;
	struct hns3_udma_eq *eq;
	uint32_t eq_cmd;
	int ret = 0;
	int eq_num;
	int i;

	eq_num = ceq_num + aeq_num;

	for (i = 0; i < eq_num; i++) {
		eq = &eq_table->eq[i];
		eq->udma_dev = udma_dev;
		eq->eqn = i;
		if (i < ceq_num) {
			/* JFCE */
			eq_cmd = HNS3_UDMA_CMD_CREATE_CEQC;
			set_jfce_attr(udma_dev, eq, (i + other_num + aeq_num));
		} else {
			/* JFAE */
			eq_cmd = HNS3_UDMA_CMD_CREATE_AEQC;
			set_jfae_attr(udma_dev, eq, (i - ceq_num + other_num));
		}
		init_eq_config(udma_dev, eq);
		ret = hns3_udma_create_eq(udma_dev, eq, eq_cmd);
		if (ret) {
			dev_err(udma_dev->dev, "failed to create eq.\n");
			goto err_out;
		}
	}

	return ret;

err_out:
	for (i -= 1; i >= 0; i--)
		hns3_udma_destroy_eq(udma_dev, &eq_table->eq[i]);

	return ret;
}

static void __hns3_udma_free_irq(struct hns3_udma_dev *udma_dev)
{
	int irq_num;
	int eq_num;
	int i;

	eq_num = udma_dev->caps.num_comp_vectors +
		 udma_dev->caps.num_aeq_vectors;
	irq_num = eq_num + udma_dev->caps.num_other_vectors;

	for (i = 0; i < udma_dev->caps.num_other_vectors; i++)
		free_irq(udma_dev->irq[i], udma_dev);

	for (i = 0; i < eq_num; i++)
		free_irq(udma_dev->eq_table.eq[i].irq,
			 &udma_dev->eq_table.eq[i]);

	for (i = 0; i < irq_num; i++)
		kfree(udma_dev->irq_names[i]);
}

void hns3_udma_cleanup_eq_table(struct hns3_udma_dev *udma_dev)
{
	struct hns3_udma_eq_table *eq_table = &udma_dev->eq_table;
	int eq_num;
	int i;

	eq_num = udma_dev->caps.num_comp_vectors +
		 udma_dev->caps.num_aeq_vectors;

	/* Disable irq */
	hns3_udma_int_mask_enable(udma_dev, eq_num, EQ_DISABLE);

	__hns3_udma_free_irq(udma_dev);
	flush_workqueue(udma_dev->irq_workq);
	destroy_workqueue(udma_dev->irq_workq);

	for (i = 0; i < eq_num; i++)
		hns3_udma_destroy_eq(udma_dev, &eq_table->eq[i]);

	kfree(eq_table->eq);
}

int hns3_udma_init_eq_table(struct hns3_udma_dev *udma_dev)
{
	struct hns3_udma_eq_table *eq_table = &udma_dev->eq_table;
	struct device *dev = udma_dev->dev;
	int other_num;
	int irq_num;
	int ceq_num;
	int aeq_num;
	int eq_num;
	int ret;
	int i;

	other_num = udma_dev->caps.num_other_vectors;
	ceq_num = udma_dev->caps.num_comp_vectors;
	aeq_num = udma_dev->caps.num_aeq_vectors;

	eq_num = ceq_num + aeq_num;
	irq_num = eq_num + other_num;

	eq_table->eq = kcalloc(eq_num, sizeof(*eq_table->eq), GFP_KERNEL);
	if (!eq_table->eq)
		return -ENOMEM;
	ret = hns3_udma_create_hw_eq(udma_dev, ceq_num, aeq_num, other_num);
	if (ret)
		goto err_create_eq_fail;

	INIT_WORK(&udma_dev->ecc_work, fmea_ram_ecc_work);

	udma_dev->irq_workq = alloc_ordered_workqueue("hns3_udma_irq_workq", 0);
	if (!udma_dev->irq_workq) {
		dev_err(dev, "failed to create irq workqueue.\n");
		ret = -ENOMEM;
		goto err_alloc_workqueue_fail;
	}

	ret = hns3_udma_request_irq(udma_dev, irq_num, ceq_num, aeq_num,
				    other_num);
	if (ret) {
		dev_err(dev, "failed to request irq.\n");
		goto err_request_irq_fail;
	}

	/* enable irq */
	hns3_udma_int_mask_enable(udma_dev, eq_num, EQ_ENABLE);

	return 0;

err_request_irq_fail:
	destroy_workqueue(udma_dev->irq_workq);

err_alloc_workqueue_fail:
	for (i = ceq_num + aeq_num - 1; i >= 0; i--)
		hns3_udma_destroy_eq(udma_dev, &eq_table->eq[i]);

err_create_eq_fail:
	kfree(eq_table->eq);
	return ret;
}
