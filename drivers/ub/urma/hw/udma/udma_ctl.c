// SPDX-License-Identifier: GPL-2.0+
/* Copyright(c) 2025 HiSilicon Technologies CO., Ltd. All rights reserved. */

#define dev_fmt(fmt) "UDMA: " fmt

#include <linux/slab.h>
#include <linux/dma-mapping.h>
#include <linux/io.h>
#include "udma_common.h"
#include "udma_dev.h"
#include <uapi/ub/urma/udma/udma_abi.h>
#include "udma_cmd.h"
#include "udma_jetty.h"
#include "udma_segment.h"
#include "udma_jfs.h"
#include "udma_jfc.h"
#include "udma_jfr.h"
#include "udma_db.h"
#include "udma_ctrlq_tp.h"
#include <ub/urma/udma/udma_ctl.h>
#include "udma_def.h"

const char *udma_cqe_aux_info_type_str[] = {
	"TPP2TQEM_WR_CNT",
	"DEVICE_RAS_STATUS_2",
	"RXDMA_WR_PAYL_AXI_ERR",
	"RXDMA_HEAD_SPLIT_ERR_FLAG0",
	"RXDMA_HEAD_SPLIT_ERR_FLAG1",
	"RXDMA_HEAD_SPLIT_ERR_FLAG2",
	"RXDMA_HEAD_SPLIT_ERR_FLAG3",
	"TP_RCP_INNER_ALM",
	"TWP_AE_DFX",
	"PA_OUT_PKT_ERR_CNT",
	"TP_DAM_AXI_ALARM",
	"TP_DAM_VFT_BT_ALARM",
	"TP_EUM_AXI_ALARM",
	"TP_EUM_VFT_BT_ALARM",
	"TP_TPMM_AXI_ALARM",
	"TP_TPMM_VFT_BT_ALARM",
	"TP_TPGCM_AXI_ALARM",
	"TP_TPGCM_VFT_BT_ALARM",
	"TWP_ALM",
	"TP_RWP_INNER_ALM",
	"TWP_DFX21",
	"LQC_TA_RNR_TANACK_CNT",
	"FVT",
	"RQMT0",
	"RQMT1",
	"RQMT2",
	"RQMT3",
	"RQMT4",
	"RQMT5",
	"RQMT6",
	"RQMT7",
	"RQMT8",
	"RQMT9",
	"RQMT10",
	"RQMT11",
	"RQMT12",
	"RQMT13",
	"RQMT14",
	"RQMT15",
	"PROC_ERROR_ALM",
	"LQC_TA_TIMEOUT_TAACK_CNT",
	"TP_RRP_ERR_FLG_0",
};

const char *udma_ae_aux_info_type_str[] = {
	"TP_RRP_FLUSH_TIMER_PKT_CNT",
	"TPP_DFX5",
	"TWP_AE_DFX",
	"TP_RRP_ERR_FLG_0",
	"TP_RRP_ERR_FLG_1",
	"TP_RWP_INNER_ALM",
	"TP_RCP_INNER_ALM",
	"LQC_TA_TQEP_WQE_ERR",
	"LQC_TA_CQM_CQE_INNER_ALARM",
};

enum udma_ae_aux_info_type tp_flush_done_type[] = {
	TP_RRP_FLUSH_TIMER_PKT_CNT,
	TPP_DFX5,
};

enum udma_ae_aux_info_type tp_err_type[] = {
	TWP_AE_DFX_FOR_AE,
	TP_RRP_ERR_FLG_0_FOR_AE,
};

enum udma_ae_aux_info_type jetty_err_type[] = {
	TP_RRP_ERR_FLG_0_FOR_AE,
	TP_RRP_ERR_FLG_1,
	TP_RWP_INNER_ALM_FOR_AE,
	TP_RCP_INNER_ALM_FOR_AE,
	LQC_TA_TQEP_WQE_ERR,
	LQC_TA_CQM_CQE_INNER_ALARM,
};

enum udma_ae_aux_info_type jfc_err_type[] = {
	LQC_TA_CQM_CQE_INNER_ALARM,
};

struct udma_ae_aux_info_type_arr ae_type_arr[] = {
	{tp_flush_done_type, ARRAY_SIZE(tp_flush_done_type)},
	{tp_err_type, ARRAY_SIZE(tp_err_type)},
	{jetty_err_type, ARRAY_SIZE(jetty_err_type)},
	{jfc_err_type, ARRAY_SIZE(jfc_err_type)},
};

static int udma_get_sq_buf_ex(struct udma_dev *dev, struct udma_jetty_queue *sq,
			      struct udma_jfs_cfg_ex *cfg_ex)
{
	struct ubcore_jfs_cfg *jfs_cfg;
	uint32_t wqe_bb_depth;
	uint32_t sqe_bb_cnt;
	uint32_t size;

	jfs_cfg = &cfg_ex->base_cfg;

	if (!jfs_cfg->flag.bs.lock_free)
		spin_lock_init(&sq->lock);
	sq->max_inline_size = jfs_cfg->max_inline_data;
	sq->max_sge_num = jfs_cfg->max_sge;
	sq->tid = dev->tid;
	sq->lock_free = jfs_cfg->flag.bs.lock_free;

	sqe_bb_cnt = sq_cal_wqebb_num(SQE_WRITE_NOTIFY_CTL_LEN, jfs_cfg->max_sge);
	if (sqe_bb_cnt > MAX_WQEBB_NUM)
		sqe_bb_cnt = MAX_WQEBB_NUM;
	sq->sqe_bb_cnt = sqe_bb_cnt;

	wqe_bb_depth = roundup_pow_of_two(sqe_bb_cnt * jfs_cfg->depth);
	sq->buf.entry_size = UDMA_JFS_WQEBB_SIZE;
	size = ALIGN(wqe_bb_depth * sq->buf.entry_size, UDMA_HW_PAGE_SIZE);
	sq->buf.entry_cnt = size >> WQE_BB_SIZE_SHIFT;

	if (size != cfg_ex->cstm_cfg.sq.buff_size) {
		dev_err(dev->dev, "buff size is wrong, buf size = %u.\n", size);
		return -EINVAL;
	}

	if (cfg_ex->cstm_cfg.sq.buff == 0) {
		dev_err(dev->dev, "cstm_cfg sq buff is wrong.\n");
		return -EINVAL;
	}

	sq->buf.addr = (dma_addr_t)(uintptr_t)phys_to_virt((uint64_t)
		       (uintptr_t)cfg_ex->cstm_cfg.sq.buff);
	if (sq->buf.addr == 0) {
		dev_err(dev->dev, "sq buff addr is wrong.\n");
		return -EINVAL;
	}

	sq->buf.kva = (void *)(uintptr_t)sq->buf.addr;

	sq->wrid = kcalloc(1, sq->buf.entry_cnt * sizeof(uint64_t), GFP_KERNEL);
	if (!sq->wrid) {
		sq->buf.kva = NULL;
		sq->buf.addr = 0;
		dev_err(dev->dev,
			"failed to alloc wrid for jfs id = %u when entry cnt = %u.\n",
			sq->id, sq->buf.entry_cnt);
		return -ENOMEM;
	}

	udma_set_kernel_db_addr(dev, sq);
	sq->kva_curr = sq->buf.kva;

	sq->trans_mode = jfs_cfg->trans_mode;

	return 0;
}

static int udma_get_jfs_buf_ex(struct udma_dev *dev, struct udma_jfs *jfs,
			       struct udma_jfs_cfg_ex *cfg_ex)
{
	int ret;

	jfs->jfs_addr = (uintptr_t)&jfs->sq;

	ret = udma_get_sq_buf_ex(dev, &jfs->sq, cfg_ex);
	if (ret)
		dev_err(dev->dev,
			"failed to get sq buf in jfs process, ret = %d.\n", ret);

	return ret;
}

static struct ubcore_jfs *udma_create_jfs_ex(struct ubcore_device *ub_dev,
					     struct udma_jfs_cfg_ex *cfg_ex)
{
	struct ubcore_jfs_cfg *cfg = &cfg_ex->base_cfg;
	struct udma_dev *dev = to_udma_dev(ub_dev);
	struct ubase_mbx_attr attr = {};
	struct udma_jetty_ctx ctx = {};
	struct udma_jfs *jfs;
	int ret;

	ret = udma_verify_jfs_param(dev, cfg, true);
	if (ret)
		return NULL;

	jfs = kcalloc(1, sizeof(*jfs), GFP_KERNEL);
	if (!jfs)
		return NULL;

	dev_info_ratelimited(dev->dev, "start alloc id!\n");
	ret = udma_alloc_jetty_id(dev, &jfs->sq.id, &dev->caps.jetty);
	if (ret) {
		dev_err(dev->dev, "alloc JFS id failed, ret = %d.\n", ret);
		goto err_alloc_jfsn;
	}
	jfs->ubcore_jfs.jfs_id.id = jfs->sq.id;
	jfs->ubcore_jfs.jfs_cfg = *cfg;
	jfs->ubcore_jfs.ub_dev = ub_dev;
	jfs->ubcore_jfs.uctx = NULL;
	jfs->ubcore_jfs.jfae_handler = cfg_ex->jfae_handler;
	jfs->mode = UDMA_KERNEL_STARS_JFS_TYPE;

	ret = xa_err(xa_store(&dev->jetty_table.xa, jfs->sq.id, &jfs->sq, GFP_KERNEL));
	if (ret) {
		dev_err(dev->dev, "store jfs sq(%u) failed, ret = %d.\n",
			jfs->sq.id, ret);
		goto err_store_jfs_sq;
	}

	dev_info_ratelimited(dev->dev, "start get stars jfs buf!\n");
	ret = udma_get_jfs_buf_ex(dev, jfs, cfg_ex);
	if (ret)
		goto err_alloc_jfs_id;

	udma_set_query_flush_time(&jfs->sq, cfg->err_timeout);
	jfs->sq.state = UBCORE_JETTY_STATE_READY;
	udma_init_jfsc(dev, cfg, jfs, &ctx);
	attr.tag = jfs->sq.id;
	attr.op = UDMA_CMD_CREATE_JFS_CONTEXT;
	ret = post_mailbox_update_ctx(dev, &ctx, sizeof(ctx), &attr);
	if (ret) {
		dev_err(dev->dev, "failed to upgrade JFSC, ret = %d.\n", ret);
		goto err_update_ctx;
	}

	jfs->sq.activated = true;
	refcount_set(&jfs->ae_refcount, 1);
	init_completion(&jfs->ae_comp);

	if (dfx_switch)
		udma_dfx_store_jfs_id(dev, jfs);

	dev_info_ratelimited(dev->dev, "create stars jfs success!\n");

	return &jfs->ubcore_jfs;

err_update_ctx:
	kfree(jfs->sq.wrid);
err_alloc_jfs_id:
	xa_erase(&dev->jetty_table.xa, jfs->sq.id);
err_store_jfs_sq:
	udma_adv_id_free(&dev->jetty_table.bitmap_table, jfs->sq.id, false);
err_alloc_jfsn:
	kfree(jfs);
	return NULL;
}

static int udma_create_jfs_ops_ex(struct ubcore_device *dev, struct ubcore_ucontext *uctx,
			   struct ubcore_user_ctl_in *in, struct ubcore_user_ctl_out *out)
{
	struct udma_dev *udev = to_udma_dev(dev);
	struct udma_jfs_cfg_ex cfg_ex;
	struct ubcore_jfs *jfs;

	if (udma_check_base_param(in->addr, in->len, sizeof(struct udma_jfs_cfg_ex)) ||
		udma_check_base_param(out->addr, out->len, sizeof(struct ubcore_jfs *))) {
		dev_err(udev->dev, "param invalid in create jfs, in_len = %u, out_len = %u.\n",
			in->len, out->len);
		return -EINVAL;
	}

	memcpy(&cfg_ex, (void *)(uintptr_t)in->addr, sizeof(struct udma_jfs_cfg_ex));

	jfs = udma_create_jfs_ex(dev, &cfg_ex);
	if (jfs == NULL)
		return -EFAULT;

	memcpy((void *)(uintptr_t)out->addr, &jfs, sizeof(struct ubcore_jfs *));

	return 0;
}

static int udma_delete_jfs_ops_ex(struct ubcore_device *dev, struct ubcore_ucontext *uctx,
			   struct ubcore_user_ctl_in *in, struct ubcore_user_ctl_out *out)
{
	struct udma_dev *udev = to_udma_dev(dev);
	struct ubcore_jfs *jfs;

	if (udma_check_base_param(in->addr, in->len, sizeof(struct ubcore_jfs *))) {
		dev_err(udev->dev, "parameter invalid in delete jfs, len = %u.\n",
			in->len);
		return -EFAULT;
	}
	memcpy(&jfs, (void *)(uintptr_t)in->addr, sizeof(struct ubcore_jfs *));
	if (jfs == NULL)
		return -EINVAL;

	if (udma_destroy_jfs(jfs))
		return -EFAULT;

	return 0;
}

static int udma_get_jfc_buf_ex(struct udma_dev *dev,
			       struct udma_jfc *jfc,
			       struct udma_jfc_cfg_ex *cfg_ex)
{
	uint32_t size;

	if (!jfc->lock_free)
		spin_lock_init(&jfc->lock);
	jfc->buf.entry_size = dev->caps.cqe_size;
	jfc->tid = dev->tid;
	size = jfc->buf.entry_size * jfc->buf.entry_cnt;

	if (size != cfg_ex->cstm_cfg.cq.buff_size) {
		dev_err(dev->dev, "cqe buff size is wrong, buf size = %u.\n", size);
		return -EINVAL;
	}

	jfc->buf.addr = (dma_addr_t)(uintptr_t)cfg_ex->cstm_cfg.cq.buff;

	if (jfc->buf.addr == 0) {
		dev_err(dev->dev, "cq buff addr is wrong.\n");
		return -EINVAL;
	}

	jfc->buf.kva = (void *)(uintptr_t)jfc->buf.addr;

	return 0;
}

static struct ubcore_jfc *udma_create_jfc_ex(struct ubcore_device *ubcore_dev,
					     struct udma_jfc_cfg_ex *cfg_ex)
{
	struct udma_dev *dev = to_udma_dev(ubcore_dev);
	struct ubcore_jfc_cfg *cfg = &cfg_ex->base_cfg;
	unsigned long flags_store;
	unsigned long flags_erase;
	struct udma_jfc *jfc;
	int ret;

	jfc = kzalloc(sizeof(struct udma_jfc), GFP_KERNEL);
	if (!jfc)
		return NULL;

	jfc->arm_sn = 1;
	jfc->buf.entry_cnt = cfg->depth ? roundup_pow_of_two(cfg->depth) : cfg->depth;

	ret = udma_check_jfc_cfg(dev, jfc, &cfg_ex->base_cfg);
	if (ret)
		goto err_check_cfg;

	ret = udma_id_alloc_auto_grow(dev, &dev->jfc_table.ida_table, &jfc->jfcn);
	if (ret)
		goto err_alloc_jfc_id;

	udma_init_jfc_param(cfg, jfc);
	jfc->base.ub_dev = ubcore_dev;
	jfc->base.uctx = NULL;
	jfc->base.jfae_handler = cfg_ex->jfae_handler;
	jfc->base.jfce_handler = cfg_ex->jfce_handler;
	jfc->mode = UDMA_KERNEL_STARS_JFC_TYPE;

	xa_lock_irqsave(&dev->jfc_table.xa, flags_store);
	ret = xa_err(__xa_store(&dev->jfc_table.xa, jfc->jfcn, jfc, GFP_ATOMIC));
	xa_unlock_irqrestore(&dev->jfc_table.xa, flags_store);
	if (ret) {
		dev_err(dev->dev,
			"failed to stored jfc id to jfc_table, jfcn: %u.\n",
			jfc->jfcn);
		goto err_store_jfcn;
	}

	ret = udma_get_jfc_buf_ex(dev, jfc, cfg_ex);
	if (ret)
		goto err_get_jfc_buf;

	ret = udma_post_create_jfc_mbox(dev, jfc);
	if (ret)
		goto err_get_jfc_buf;

	refcount_set(&jfc->event_refcount, 1);

	init_completion(&jfc->event_comp);

	if (dfx_switch)
		udma_dfx_store_id(dev, &dev->dfx_info->jfc, jfc->jfcn, "jfc");

	return &jfc->base;

err_get_jfc_buf:
	xa_lock_irqsave(&dev->jfc_table.xa, flags_erase);
	__xa_erase(&dev->jfc_table.xa, jfc->jfcn);
	xa_unlock_irqrestore(&dev->jfc_table.xa, flags_erase);
err_store_jfcn:
	udma_id_free(&dev->jfc_table.ida_table, jfc->jfcn);
err_alloc_jfc_id:
err_check_cfg:
	kfree(jfc);
	return NULL;
}

static int udma_create_jfc_ops_ex(struct ubcore_device *dev, struct ubcore_ucontext *uctx,
				  struct ubcore_user_ctl_in *in, struct ubcore_user_ctl_out *out)
{
	struct udma_dev *udev = to_udma_dev(dev);
	struct udma_jfc_cfg_ex cfg_ex;
	struct ubcore_jfc *jfc;

	if (udma_check_base_param(in->addr, in->len, sizeof(struct udma_jfc_cfg_ex)) ||
		udma_check_base_param(out->addr, out->len, sizeof(struct ubcore_jfc *))) {
		dev_err(udev->dev, "input parameter invalid in create jfc, in_len = %u, out_len = %u.\n",
			in->len, out->len);
		return -EINVAL;
	}

	memcpy(&cfg_ex, (void *)(uintptr_t)in->addr,
		min(in->len, sizeof(struct udma_jfc_cfg_ex)));

	jfc = udma_create_jfc_ex(dev, &cfg_ex);
	if (jfc == NULL)
		return -EFAULT;

	memcpy((void *)(uintptr_t)out->addr, &jfc, sizeof(struct ubcore_jfc *));

	return 0;
}

static int udma_delete_jfc_ops_ex(struct ubcore_device *dev, struct ubcore_ucontext *uctx,
				  struct ubcore_user_ctl_in *in, struct ubcore_user_ctl_out *out)
{
	struct udma_dev *udev = to_udma_dev(dev);
	struct ubcore_jfc *jfc;

	if (udma_check_base_param(in->addr, in->len, sizeof(struct ubcore_jfc *))) {
		dev_err(udev->dev, "parameter invalid in delete jfc, len = %u.\n",
			in->len);
		return -EINVAL;
	}

	memcpy(&jfc, (void *)(uintptr_t)in->addr,
		min(in->len, sizeof(struct ubcore_jfc *)));
	if (jfc == NULL)
		return -EINVAL;

	if (udma_destroy_jfc(jfc))
		return -EFAULT;

	return 0;
}

static int udma_set_cqe_ex(struct ubcore_device *dev, struct ubcore_ucontext *uctx,
			   struct ubcore_user_ctl_in *in, struct ubcore_user_ctl_out *out)
{
	struct udma_dev *udev = to_udma_dev(dev);
	struct udma_ex_jfc_addr *jfc_addr;
	struct udma_set_cqe_ex cqe_ex;
	uint32_t cq_depth;

	if (udma_check_base_param(in->addr, in->len, sizeof(struct udma_set_cqe_ex))) {
		dev_err(udev->dev, "parameter invalid in set cqe, len = %u.\n",
			in->len);
		return -EINVAL;
	}

	memcpy(&cqe_ex, (void *)(uintptr_t)in->addr,
		min(in->len, sizeof(struct udma_set_cqe_ex)));

	if (cqe_ex.jfc_type != UDMA_STARS_JFC_TYPE &&
	    cqe_ex.jfc_type != UDMA_CCU_JFC_TYPE) {
		dev_err(udev->dev, "invalid jfc type, mode = %u.\n", cqe_ex.jfc_type);
		return -EINVAL;
	}

	if (cqe_ex.addr == 0) {
		dev_err(udev->dev, "cq addr is wrong in set cqe.\n");
		return -EINVAL;
	}

	cq_depth = cqe_ex.len / udev->caps.cqe_size;
	if (cq_depth < UDMA_JFC_DEPTH_MIN || cq_depth > udev->caps.jfc.depth ||
	    (cqe_ex.len % udev->caps.cqe_size) != 0 ||
	    cq_depth != roundup_pow_of_two(cq_depth)) {
		dev_err(udev->dev, "cq buff size is wrong in set cqe, size = %u.\n",
			cqe_ex.len);
		return -EINVAL;
	}

	jfc_addr = &udev->cq_addr_array[cqe_ex.jfc_type];
	jfc_addr->cq_addr = cqe_ex.addr;
	jfc_addr->cq_len = cqe_ex.len;

	return 0;
}

static int udma_query_ue_info_ex(struct ubcore_device *dev, struct ubcore_ucontext *uctx,
				 struct ubcore_user_ctl_in *in, struct ubcore_user_ctl_out *out)
{
	struct udma_dev *udev = to_udma_dev(dev);
	struct udma_ue_info_ex info = {};

	if (udma_check_base_param(out->addr, out->len, sizeof(struct udma_ue_info_ex))) {
		dev_err(udev->dev, "parameter invalid in query ue, len = %u.\n",
			out->len);
		return -EINVAL;
	}

	info.chip_id = udev->chip_id;
	info.die_id = udev->die_id;
	info.dwqe_addr = udev->db_base + JETTY_DSQE_OFFSET;
	info.db_base_addr = info.dwqe_addr + UDMA_DOORBELL_OFFSET;
	info.ue_id = udev->ue_id;
	info.register_base_addr = udev->db_base;
	info.offset_len = PAGE_SIZE;

	memcpy((void *)(uintptr_t)out->addr, &info, sizeof(struct udma_ue_info_ex));

	return 0;
}

static int udma_ctrlq_query_tp_sport(struct ubcore_device *dev, struct ubcore_ucontext *uctx,
				     struct ubcore_user_ctl_in *in, struct ubcore_user_ctl_out *out)
{
	struct udma_tp_sport_out tp_sport_out = {};
	struct udma_tp_sport_in tp_sport_in = {};
	struct udma_dev *udev = to_udma_dev(dev);
	struct ubase_cmd_mailbox *mailbox = NULL;
	struct ubase_mbx_attr mbox_attr = {};
	struct udma_tp_ctx *tpc;

	if (udma_check_base_param(out->addr, out->len, sizeof(struct udma_tp_sport_out)) ||
	    udma_check_base_param(in->addr, in->len, sizeof(struct udma_tp_sport_in))) {
		dev_err(udev->dev, "parameter invalid in query tp sport, in_len = %u, out_len = %u.\n",
			in->len, out->len);
		return -EINVAL;
	}

	if (udev->is_ue) {
		dev_err(udev->dev, "ue is not supported.\n");
		return -EINVAL;
	}

	memcpy(&tp_sport_in, (void *)(uintptr_t)in->addr, sizeof(struct udma_tp_sport_in));

	mbox_attr.tag = tp_sport_in.tpn;
	mbox_attr.op = UDMA_CMD_QUERY_TP_CONTEXT;
	mailbox = udma_mailbox_query_ctx(udev, &mbox_attr);
	if (!mailbox)
		return -ENOMEM;

	tpc = (struct udma_tp_ctx *)mailbox->buf;

	tp_sport_out.ack_udp_srcport = tpc->ack_udp_srcport_h << TP_ACK_UDP_SPORT_H_OFFSET |
				       tpc->ack_udp_srcport_l;
	tp_sport_out.data_udp_srcport = tpc->data_udp_srcport;

	memcpy((void *)(uintptr_t)out->addr, &tp_sport_out, out->len);

	udma_free_cmd_mailbox(udev, mailbox);

	return 0;
}

enum udma_cqe_aux_info_type cqe_client_loc_len_err_type[] = {
	TPP2TQEM_WR_CNT,
	DEVICE_RAS_STATUS_2,
};

enum udma_cqe_aux_info_type cqe_client_loc_access_err_type[] = {
	RXDMA_WR_PAYL_AXI_ERR,
	RXDMA_HEAD_SPLIT_ERR_FLAG0,
	RXDMA_HEAD_SPLIT_ERR_FLAG1,
	RXDMA_HEAD_SPLIT_ERR_FLAG2,
	RXDMA_HEAD_SPLIT_ERR_FLAG3,
	TP_RCP_INNER_ALM_FOR_CQE,
	TWP_AE_DFX_FOR_CQE,
	PA_OUT_PKT_ERR_CNT,
	TP_DAM_AXI_ALARM,
	TP_DAM_VFT_BT_ALARM,
	TP_EUM_AXI_ALARM,
	TP_EUM_VFT_BT_ALARM,
	TP_TPMM_AXI_ALARM,
	TP_TPMM_VFT_BT_ALARM,
	TP_TPGCM_AXI_ALARM,
	TP_TPGCM_VFT_BT_ALARM,
	DEVICE_RAS_STATUS_2,
	TWP_ALM,
};

enum udma_cqe_aux_info_type cqe_client_rem_resp_len_err_type[] = {
	TP_RWP_INNER_ALM_FOR_CQE,
};

enum udma_cqe_aux_info_type cqe_client_rem_access_abort_err_type[] = {
	RXDMA_WR_PAYL_AXI_ERR,
	RXDMA_HEAD_SPLIT_ERR_FLAG0,
	RXDMA_HEAD_SPLIT_ERR_FLAG1,
	RXDMA_HEAD_SPLIT_ERR_FLAG2,
	RXDMA_HEAD_SPLIT_ERR_FLAG3,
	TP_RCP_INNER_ALM_FOR_CQE,
	TP_RRP_ERR_FLG_0_FOR_CQE,
	TPP2TQEM_WR_CNT,
	TWP_DFX21
};

enum udma_cqe_aux_info_type cqe_client_ack_timeout_err_type[] = {
	LQC_TA_TIMEOUT_TAACK_CNT,
};

enum udma_cqe_aux_info_type cqe_client_rnr_retry_cnt_exc_err_type[] = {
	LQC_TA_RNR_TANACK_CNT,
	FVT,
	RQMT0,
	RQMT1,
	RQMT2,
	RQMT3,
	RQMT4,
	RQMT5,
	RQMT6,
	RQMT7,
	RQMT8,
	RQMT9,
	RQMT10,
	RQMT11,
	RQMT12,
	RQMT13,
	RQMT14,
	RQMT15,
	PROC_ERROR_ALM,
};

enum udma_cqe_aux_info_type cqe_server_loc_access_err_type[] = {
	TP_RWP_INNER_ALM_FOR_CQE,
	RXDMA_WR_PAYL_AXI_ERR,
	RXDMA_HEAD_SPLIT_ERR_FLAG0,
	RXDMA_HEAD_SPLIT_ERR_FLAG1,
	RXDMA_HEAD_SPLIT_ERR_FLAG2,
	RXDMA_HEAD_SPLIT_ERR_FLAG3,
	TP_RCP_INNER_ALM_FOR_CQE,
	TP_RRP_ERR_FLG_0_FOR_CQE,
};

enum udma_cqe_aux_info_type cqe_server_loc_len_err_type[] = {
	TP_RWP_INNER_ALM_FOR_CQE,
};

struct udma_cqe_aux_info_type_arr cqe_type_arr[14][2] = {
	{{NULL, 0}, {NULL, 0}},
	{{NULL, MAX_CQE_AUX_INFO_TYPE_NUM}, {NULL, MAX_CQE_AUX_INFO_TYPE_NUM}},
	{{cqe_server_loc_len_err_type, ARRAY_SIZE(cqe_server_loc_len_err_type)},
		{cqe_client_loc_len_err_type,
			ARRAY_SIZE(cqe_client_loc_len_err_type)}},
	{{NULL, 0}, {NULL, 0}},
	{{cqe_server_loc_access_err_type, ARRAY_SIZE(cqe_server_loc_access_err_type)},
		{cqe_client_loc_access_err_type,
			ARRAY_SIZE(cqe_client_loc_access_err_type)}},
	{{NULL, MAX_CQE_AUX_INFO_TYPE_NUM},
		{cqe_client_rem_resp_len_err_type,
			ARRAY_SIZE(cqe_client_rem_resp_len_err_type)}},
	{{NULL, MAX_CQE_AUX_INFO_TYPE_NUM}, {NULL, MAX_CQE_AUX_INFO_TYPE_NUM}},
	{{NULL, 0}, {NULL, 0}},
	{{NULL, MAX_CQE_AUX_INFO_TYPE_NUM},
		{cqe_client_rem_access_abort_err_type,
			ARRAY_SIZE(cqe_client_rem_access_abort_err_type)}},
	{{NULL, MAX_CQE_AUX_INFO_TYPE_NUM},
		{cqe_client_ack_timeout_err_type,
			ARRAY_SIZE(cqe_client_ack_timeout_err_type)}},
	{{NULL, MAX_CQE_AUX_INFO_TYPE_NUM},
		{cqe_client_rnr_retry_cnt_exc_err_type,
			ARRAY_SIZE(cqe_client_rnr_retry_cnt_exc_err_type)}},
	{{NULL, MAX_CQE_AUX_INFO_TYPE_NUM}, {NULL, MAX_CQE_AUX_INFO_TYPE_NUM}},
	{{NULL, 0}, {NULL, 0}},
	{{NULL, MAX_CQE_AUX_INFO_TYPE_NUM}, {NULL, MAX_CQE_AUX_INFO_TYPE_NUM}},
};

static void dump_fill_cqe_err_aux_info(struct udma_dev *dev,
					 struct udma_cqe_aux_info_out *aux_info_out,
					 struct udma_cmd_query_cqe_aux_info *info,
					 enum udma_cqe_aux_info_type *type, uint32_t aux_info_num)
{
	int aux_info_type;
	uint32_t i;

	if (aux_info_out->aux_info_type != NULL &&
	    aux_info_out->aux_info_value != NULL &&
	    aux_info_out->aux_info_num >= aux_info_num) {
		for (i = 0; i < aux_info_num; i++) {
			aux_info_type = type == NULL ? i : type[i];
			aux_info_out->aux_info_type[i] = aux_info_type;
			aux_info_out->aux_info_value[i] = info->cqe_aux_info[aux_info_type];
		}
		aux_info_out->aux_info_num = aux_info_num;
	}

	for (i = 0; i < aux_info_num; i++) {
		aux_info_type = type == NULL ? i : type[i];
		dev_info(dev->dev, "%s\t0x%08x\n",
			 udma_cqe_aux_info_type_str[aux_info_type],
			 info->cqe_aux_info[aux_info_type]);
	}
}

static void dump_fill_aux_info(struct udma_dev *dev, struct udma_ae_aux_info_out *aux_info_out,
			       struct udma_cmd_query_ae_aux_info *info,
			       enum udma_ae_aux_info_type *type, uint32_t aux_info_num)
{
	uint32_t i;

	if (aux_info_out->aux_info_type != NULL &&
	    aux_info_out->aux_info_value != NULL &&
	    aux_info_out->aux_info_num >= aux_info_num) {
		for (i = 0; i < aux_info_num; i++) {
			aux_info_out->aux_info_type[i] = type[i];
			aux_info_out->aux_info_value[i] = info->ae_aux_info[type[i]];
		}
		aux_info_out->aux_info_num = aux_info_num;
	}

	for (i = 0; i < aux_info_num; i++)
		dev_info(dev->dev, "%s\t0x%08x\n", udma_ae_aux_info_type_str[type[i]],
			 info->ae_aux_info[type[i]]);
}

static void dump_all_ae_aux_info(struct udma_dev *dev,
	struct udma_ae_aux_info_out *aux_info_out,
	struct udma_cmd_query_ae_aux_info *info)
{
	int i;

	if (aux_info_out->aux_info_type != NULL &&
	    aux_info_out->aux_info_value != NULL &&
	    aux_info_out->aux_info_num >= MAX_AE_AUX_INFO_TYPE_NUM) {
		for (i = 0; i < MAX_AE_AUX_INFO_TYPE_NUM; i++) {
			aux_info_out->aux_info_type[i] = i;
			aux_info_out->aux_info_value[i] = info->ae_aux_info[i];
		}
		aux_info_out->aux_info_num = MAX_AE_AUX_INFO_TYPE_NUM;
	}

	for (i = 0; i < MAX_AE_AUX_INFO_TYPE_NUM; i++)
		dev_info(dev->dev, "%s\t0x%08x\n",
			 udma_ae_aux_info_type_str[i], info->ae_aux_info[i]);
}

static void dump_ae_aux_info(struct udma_dev *dev,
			     struct udma_ae_aux_info_out *aux_info_out,
			     struct udma_cmd_query_ae_aux_info *info)
{
#define UDMA_TP_FLUSH_DONE_TYPE_IDX 0
#define UDMA_TP_LEVEL_ERROR_TYPE_IDX 1
#define UDMA_JETTY_LEVEL_ERROR_TYPE_IDX 2
#define UDMA_JFC_LEVEL_ERROR_TYPE_IDX 3
	switch (info->event_type) {
	case UBASE_EVENT_TYPE_TP_FLUSH_DONE:
		dump_fill_aux_info(dev, aux_info_out, info,
				   ae_type_arr[UDMA_TP_FLUSH_DONE_TYPE_IDX].type_list,
				   ae_type_arr[UDMA_TP_FLUSH_DONE_TYPE_IDX].type_len);
		break;
	case UBASE_EVENT_TYPE_TP_LEVEL_ERROR:
		dump_fill_aux_info(dev, aux_info_out, info,
				   ae_type_arr[UDMA_TP_LEVEL_ERROR_TYPE_IDX].type_list,
				   ae_type_arr[UDMA_TP_LEVEL_ERROR_TYPE_IDX].type_len);
		break;
	case UBASE_EVENT_TYPE_JETTY_LEVEL_ERROR:
		if (info->sub_type == UBASE_SUBEVENT_TYPE_JFS_CHECK_ERROR)
			dump_fill_aux_info(dev, aux_info_out, info,
				ae_type_arr[UDMA_JETTY_LEVEL_ERROR_TYPE_IDX].type_list,
				ae_type_arr[UDMA_JETTY_LEVEL_ERROR_TYPE_IDX].type_len);
		else
			dump_fill_aux_info(dev, aux_info_out, info,
				ae_type_arr[UDMA_JFC_LEVEL_ERROR_TYPE_IDX].type_list,
				ae_type_arr[UDMA_JFC_LEVEL_ERROR_TYPE_IDX].type_len);
		break;
	case UDMA_CMD_QUERY_ALL_AUX_INFO:
		dump_all_ae_aux_info(dev, aux_info_out, info);
		break;
	default:
		break;
	}
}

static int send_cmd_query_single_cqe_aux_info(struct udma_dev *udma_dev,
					      struct udma_cmd_query_cqe_aux_info *info)
{
	struct ubase_cmd_buf cmd_in, cmd_out;
	int ret;

	udma_fill_buf(&cmd_in, UDMA_CMD_GET_CQE_AUX_INFO, true,
		      sizeof(struct udma_cmd_query_cqe_aux_info), info);
	udma_fill_buf(&cmd_out, UDMA_CMD_GET_CQE_AUX_INFO, true,
		      sizeof(struct udma_cmd_query_cqe_aux_info), info);

	ret = ubase_cmd_send_inout(udma_dev->comdev.adev, &cmd_in, &cmd_out);
	if (ret)
		dev_err(udma_dev->dev,
			"failed to query cqe aux info, ret = %d.\n", ret);

	return ret;
}

static int send_cmd_query_all_cqe_aux_info(struct udma_dev *udma_dev,
					   struct udma_cmd_query_cqe_aux_info *info)
{
	struct udma_cmd_query_cqe_aux_info **info_arr;
	uint32_t k, i, j;
	int size;
	int type;
	int ret;

	size = ARRAY_SIZE(cqe_type_arr) * UDMA_CQE_NUM_PER_TYPE *
	       sizeof(struct udma_cmd_query_cqe_aux_info);
	info_arr = kzalloc(size, GFP_KERNEL);

	for (i = 0; i < ARRAY_SIZE(cqe_type_arr); i++) {
		for (j = 0; j < UDMA_CQE_NUM_PER_TYPE; j++) {
			if (cqe_type_arr[i][j].type_list == NULL)
				continue;

			info_arr[i][j].status = i;
			info_arr[i][j].is_client = j;

			ret = send_cmd_query_single_cqe_aux_info(udma_dev, &info_arr[i][j]);
			if (ret) {
				dev_err(udma_dev->dev,
					"failed to query cqe aux info, ret = %d.\n", ret);
				kfree(info_arr);
				return ret;
			}
		}
	}

	for (i = ARRAY_SIZE(cqe_type_arr) - 1; i >= 0; i--) {
		for (j = UDMA_CQE_NUM_PER_TYPE - 1; j >= 0; j--) {
			if (cqe_type_arr[i][j].type_list == NULL)
				continue;

			for (k = 0; k < cqe_type_arr[i][j].type_len; k++) {
				type = cqe_type_arr[i][j].type_list[k];
				info->cqe_aux_info[type] = info_arr[i][j].cqe_aux_info[type];
			}
		}
	}

	kfree(info_arr);
	return ret;
}

static int send_cmd_query_cqe_aux_info(struct udma_dev *udma_dev,
				       struct udma_cmd_query_cqe_aux_info *info)
{
	if (info->status == UDMA_CMD_QUERY_ALL_AUX_INFO ||
	    cqe_type_arr[info->status][info->is_client].type_list == NULL)
		return send_cmd_query_all_cqe_aux_info(udma_dev, info);

	return send_cmd_query_single_cqe_aux_info(udma_dev, info);
}

static void free_kernel_cqe_aux_info(struct udma_cqe_aux_info_out *user_aux_info_out,
				     struct udma_cqe_aux_info_out *aux_info_out)
{
	if (!user_aux_info_out->aux_info_type)
		return;

	kfree(aux_info_out->aux_info_type);
	aux_info_out->aux_info_type = NULL;

	kfree(aux_info_out->aux_info_value);
	aux_info_out->aux_info_value = NULL;
}

static int copy_out_cqe_data_from_user(struct udma_dev *udma_dev,
				       struct ubcore_user_ctl_out *out,
				       struct udma_cqe_aux_info_out *aux_info_out,
				       struct ubcore_ucontext *uctx,
				       struct udma_cqe_aux_info_out *user_aux_info_out)
{
	if (out->addr != 0) {
		memcpy(aux_info_out, (void *)(uintptr_t)out->addr,
		       min(out->len, sizeof(struct udma_cqe_aux_info_out)));
		if (uctx && aux_info_out->aux_info_num > 0 &&
		    aux_info_out->aux_info_type != NULL &&
		    aux_info_out->aux_info_value != NULL) {
			if (aux_info_out->aux_info_num > MAX_CQE_AUX_INFO_TYPE_NUM) {
				dev_info(udma_dev->dev,
					 "cqe aux info num change from %u to %u",
					 aux_info_out->aux_info_num,
					 MAX_CQE_AUX_INFO_TYPE_NUM);
				aux_info_out->aux_info_num = MAX_CQE_AUX_INFO_TYPE_NUM;
			}

			user_aux_info_out->aux_info_type = aux_info_out->aux_info_type;
			user_aux_info_out->aux_info_value = aux_info_out->aux_info_value;
			aux_info_out->aux_info_type =
				kcalloc(aux_info_out->aux_info_num,
					sizeof(enum udma_cqe_aux_info_type), GFP_KERNEL);
			if (!aux_info_out->aux_info_type)
				return -ENOMEM;

			aux_info_out->aux_info_value =
				kcalloc(aux_info_out->aux_info_num,
					sizeof(uint32_t), GFP_KERNEL);
			if (!aux_info_out->aux_info_value) {
				kfree(aux_info_out->aux_info_type);
				aux_info_out->aux_info_type = NULL;
				return -ENOMEM;
			}
		}
	}

	return 0;
}

static int copy_out_cqe_data_to_user(struct udma_dev *udma_dev,
				     struct ubcore_user_ctl_out *out,
				     struct udma_cqe_aux_info_out *aux_info_out,
				     struct ubcore_ucontext *uctx,
				     struct udma_cqe_aux_info_out *user_aux_info_out)
{
	unsigned long byte;

	if (out->addr != 0) {
		if (uctx && aux_info_out->aux_info_num > 0 &&
		    aux_info_out->aux_info_type != NULL &&
		    aux_info_out->aux_info_value != NULL &&
		    user_aux_info_out->aux_info_type != NULL) {
			byte = copy_to_user((void __user *)user_aux_info_out->aux_info_type,
					    (void *)aux_info_out->aux_info_type,
					    aux_info_out->aux_info_num *
					    sizeof(enum udma_cqe_aux_info_type));
			if (byte) {
				dev_err(udma_dev->dev,
					"copy resp to aux info type failed, byte = %lu.\n", byte);
				return -EFAULT;
			}

			byte = copy_to_user((void __user *)user_aux_info_out->aux_info_value,
					    (void *)aux_info_out->aux_info_value,
					    aux_info_out->aux_info_num *
					    sizeof(uint32_t));
			if (byte) {
				dev_err(udma_dev->dev,
					"copy resp to aux info value failed, byte = %lu.\n", byte);
				return -EFAULT;
			}

			kfree(aux_info_out->aux_info_type);
			kfree(aux_info_out->aux_info_value);
			aux_info_out->aux_info_type = user_aux_info_out->aux_info_type;
			aux_info_out->aux_info_value = user_aux_info_out->aux_info_value;
		}
		memcpy((void *)(uintptr_t)out->addr, aux_info_out,
		       sizeof(struct udma_cqe_aux_info_out));
	}

	return 0;
}

static int udma_check_cqe_info(struct udma_dev *udev, struct udma_cmd_query_cqe_aux_info *info,
	struct udma_cqe_info_in *cqe_info_in)
{
	info->status = cqe_info_in->status == UDMA_QUERY_ALL_AUX_INFO ?
		UDMA_CMD_QUERY_ALL_AUX_INFO : cqe_info_in->status;
	if (cqe_info_in->s_r > 1) {
		dev_err(udev->dev, "s_r %u is invalid.\n", cqe_info_in->s_r);
		return -EINVAL;
	}
	info->is_client = !(cqe_info_in->s_r & 1);

	if (cqe_info_in->status == UDMA_QUERY_ALL_AUX_INFO)
		return 0;

	if (cqe_info_in->status >= ARRAY_SIZE(cqe_type_arr) ||
	    (cqe_type_arr[info->status][info->is_client].type_list == NULL &&
	     cqe_type_arr[info->status][info->is_client].type_len == 0)) {
		dev_err(udev->dev, "status %u is invalid or does not need to be queried.\n",
			cqe_info_in->status);
		return -EINVAL;
	}

	return 0;
}

static int udma_verify_aux_info_param(struct udma_dev *udev, struct ubcore_user_ctl_in *in,
				      struct ubcore_user_ctl_out *out, uint32_t except_in_len,
				      uint32_t except_out_len)
{
	if (!in->addr || in->len == 0 || in->len < except_in_len) {
		dev_err(udev->dev, "parameter invalid for in_addr or in_len, in_len=%u, except_in_len=%u.\n",
				    in->len, except_in_len);
		return -EINVAL;
	}

	/*
	 * When out_addr is null and len is 0, the driver does not return
	 * aux_info to the user; it only prints it in kernel mode.
	 */
	if ((out->addr != 0 && (out->len == 0 || out->len < except_out_len)) ||
	    (out->addr == 0 && out->len > 0)) {
		dev_err(udev->dev, "parameter invalid for out_addr or out_len, out_len = %u, except_out_len=%u.\n",
			out->len, except_out_len);
		return -EINVAL;
	}

	return 0;
}

int udma_query_cqe_aux_info(struct ubcore_device *dev, struct ubcore_ucontext *uctx,
			    struct ubcore_user_ctl_in *in, struct ubcore_user_ctl_out *out)
{
	struct udma_cqe_aux_info_out user_aux_info_out = {};
	struct udma_cqe_aux_info_out aux_info_out = {};
	struct udma_cmd_query_cqe_aux_info info = {};
	struct udma_cqe_info_in cqe_info_in = {};
	struct udma_dev *udev = to_udma_dev(dev);
	int ret;

	ret = udma_verify_aux_info_param(udev, in, out, sizeof(struct udma_cqe_info_in),
					 sizeof(struct udma_cqe_aux_info_out));
	if (ret)
		return ret;

	memcpy(&cqe_info_in, (void *)(uintptr_t)in->addr,
	       min(in->len, sizeof(struct udma_cqe_info_in)));

	ret = udma_check_cqe_info(udev, &info, &cqe_info_in);
	if (ret)
		return ret;

	ret = copy_out_cqe_data_from_user(udev, out, &aux_info_out, uctx, &user_aux_info_out);
	if (ret) {
		dev_err(udev->dev,
			"copy out data from user failed, ret = %d.\n", ret);
		return ret;
	}

	ret = send_cmd_query_cqe_aux_info(udev, &info);
	if (ret) {
		dev_err(udev->dev,
			"send cmd query aux info failed, ret = %d.\n",
			ret);
		free_kernel_cqe_aux_info(&user_aux_info_out, &aux_info_out);
		return ret;
	}

	if (info.status == UDMA_CMD_QUERY_ALL_AUX_INFO)
		dump_fill_cqe_err_aux_info(udev, &aux_info_out, &info,
			NULL, MAX_CQE_AUX_INFO_TYPE_NUM);
	else
		dump_fill_cqe_err_aux_info(udev, &aux_info_out, &info,
			cqe_type_arr[info.status][info.is_client].type_list,
			cqe_type_arr[info.status][info.is_client].type_len);

	ret = copy_out_cqe_data_to_user(udev, out, &aux_info_out, uctx, &user_aux_info_out);
	if (ret) {
		dev_err(udev->dev,
			"copy out data to user failed, ret = %d.\n", ret);
		free_kernel_cqe_aux_info(&user_aux_info_out, &aux_info_out);
	}

	return ret;
}

static int to_hw_ae_event_type(struct udma_dev *udma_dev, uint32_t event_type,
			       struct udma_cmd_query_ae_aux_info *info)
{
	switch (event_type) {
	case UBCORE_EVENT_TP_FLUSH_DONE:
		info->event_type = UBASE_EVENT_TYPE_TP_FLUSH_DONE;
		break;
	case UBCORE_EVENT_TP_ERR:
		info->event_type = UBASE_EVENT_TYPE_TP_LEVEL_ERROR;
		break;
	case UBCORE_EVENT_JFS_ERR:
	case UBCORE_EVENT_JETTY_ERR:
		info->event_type = UBASE_EVENT_TYPE_JETTY_LEVEL_ERROR;
		info->sub_type = UBASE_SUBEVENT_TYPE_JFS_CHECK_ERROR;
		break;
	case UBCORE_EVENT_JFC_ERR:
		info->event_type = UBASE_EVENT_TYPE_JETTY_LEVEL_ERROR;
		info->sub_type = UBASE_SUBEVENT_TYPE_JFC_CHECK_ERROR;
		break;
	case UDMA_QUERY_ALL_AUX_INFO:
		info->event_type = UDMA_CMD_QUERY_ALL_AUX_INFO;
		break;
	default:
		dev_err(udma_dev->dev, "Invalid event type %u.\n", event_type);
		return -EINVAL;
	}

	return 0;
}

static int send_cmd_query_single_ae_aux_info(struct udma_dev *udma_dev,
					     struct udma_cmd_query_ae_aux_info *info)
{
	struct ubase_cmd_buf cmd_in, cmd_out;
	int ret;

	udma_fill_buf(&cmd_in, UDMA_CMD_GET_AE_AUX_INFO, true,
		      sizeof(struct udma_cmd_query_ae_aux_info), info);
	udma_fill_buf(&cmd_out, UDMA_CMD_GET_AE_AUX_INFO, true,
		      sizeof(struct udma_cmd_query_ae_aux_info), info);

	ret = ubase_cmd_send_inout(udma_dev->comdev.adev, &cmd_in, &cmd_out);
	if (ret)
		dev_err(udma_dev->dev,
			"failed to query ae aux info, ret = %d.\n", ret);

	return ret;
}

static int send_cmd_query_all_ae_aux_info(struct udma_dev *udma_dev,
					  struct udma_cmd_query_ae_aux_info *info)
{
	struct udma_ae_event_type ae_event_type[UDMA_AE_EVENT_TYPE] = {
		{UBASE_EVENT_TYPE_TP_FLUSH_DONE, 0},
		{UBASE_EVENT_TYPE_TP_LEVEL_ERROR, 0},
		{UBASE_EVENT_TYPE_JETTY_LEVEL_ERROR, UBASE_SUBEVENT_TYPE_JFS_CHECK_ERROR},
		{UBASE_EVENT_TYPE_JETTY_LEVEL_ERROR, UBASE_SUBEVENT_TYPE_JFC_CHECK_ERROR},
	};
	struct udma_cmd_query_ae_aux_info info_arr[UDMA_AE_EVENT_TYPE];
	enum udma_ae_aux_info_type type;
	uint32_t j;
	int ret;
	int i;

	for (i = 0; i < UDMA_AE_EVENT_TYPE; i++) {
		info_arr[i].event_type = ae_event_type[i].event_type;
		info_arr[i].sub_type = ae_event_type[i].sub_type;

		ret = send_cmd_query_single_ae_aux_info(udma_dev, &info_arr[i]);
		if (ret) {
			dev_err(udma_dev->dev,
				"failed to query ae aux info, ret = %d.\n", ret);
			return ret;
		}
	}

	for (i = UDMA_AE_EVENT_TYPE - 1; i >= 0; i--) {
		for (j = 0; j < ae_type_arr[i].type_len; j++) {
			type = ae_type_arr[i].type_list[j];
			info->ae_aux_info[type] = info_arr[i].ae_aux_info[type];
		}
	}

	return 0;
}

static int send_cmd_query_ae_aux_info(struct udma_dev *udma_dev,
					  struct udma_cmd_query_ae_aux_info *info)
{
	if (info->event_type == UDMA_CMD_QUERY_ALL_AUX_INFO)
		return send_cmd_query_all_ae_aux_info(udma_dev, info);

	return send_cmd_query_single_ae_aux_info(udma_dev, info);
}

static void free_kernel_ae_aux_info(struct udma_ae_aux_info_out *user_aux_info_out,
				    struct udma_ae_aux_info_out *aux_info_out)
{
	if (!user_aux_info_out->aux_info_type)
		return;

	kfree(aux_info_out->aux_info_type);
	aux_info_out->aux_info_type = NULL;

	kfree(aux_info_out->aux_info_value);
	aux_info_out->aux_info_value = NULL;
}

static int copy_out_ae_data_from_user(struct udma_dev *udma_dev,
				      struct ubcore_user_ctl_out *out,
				      struct udma_ae_aux_info_out *aux_info_out,
				      struct ubcore_ucontext *uctx,
				      struct udma_ae_aux_info_out *user_aux_info_out)
{
	if (out->addr != 0) {
		memcpy(aux_info_out, (void *)(uintptr_t)out->addr,
		       min(out->len, sizeof(struct udma_ae_aux_info_out)));
		if (uctx && aux_info_out->aux_info_num > 0 &&
		    aux_info_out->aux_info_type != NULL &&
		    aux_info_out->aux_info_value != NULL) {
			if (aux_info_out->aux_info_num > MAX_AE_AUX_INFO_TYPE_NUM) {
				dev_info(udma_dev->dev,
					 "ae aux info num change from %u to %u",
					 aux_info_out->aux_info_num,
					 MAX_AE_AUX_INFO_TYPE_NUM);
				aux_info_out->aux_info_num = MAX_AE_AUX_INFO_TYPE_NUM;
			}

			user_aux_info_out->aux_info_type = aux_info_out->aux_info_type;
			user_aux_info_out->aux_info_value = aux_info_out->aux_info_value;
			aux_info_out->aux_info_type =
				kcalloc(aux_info_out->aux_info_num,
					sizeof(enum udma_ae_aux_info_type), GFP_KERNEL);
			if (!aux_info_out->aux_info_type)
				return -ENOMEM;

			aux_info_out->aux_info_value =
				kcalloc(aux_info_out->aux_info_num,
					sizeof(uint32_t), GFP_KERNEL);
			if (!aux_info_out->aux_info_value) {
				kfree(aux_info_out->aux_info_type);
				aux_info_out->aux_info_type = NULL;
				return -ENOMEM;
			}
		}
	}

	return 0;
}

static int copy_out_ae_data_to_user(struct udma_dev *udma_dev,
				    struct ubcore_user_ctl_out *out,
				    struct udma_ae_aux_info_out *aux_info_out,
				    struct ubcore_ucontext *uctx,
				    struct udma_ae_aux_info_out *user_aux_info_out)
{
	unsigned long byte;

	if (out->addr != 0) {
		if (uctx && aux_info_out->aux_info_num > 0 &&
		    aux_info_out->aux_info_type != NULL &&
		    aux_info_out->aux_info_value != NULL &&
		    user_aux_info_out->aux_info_type != NULL) {
			byte = copy_to_user((void __user *)user_aux_info_out->aux_info_type,
					    (void *)aux_info_out->aux_info_type,
					    aux_info_out->aux_info_num *
					    sizeof(enum udma_ae_aux_info_type));
			if (byte) {
				dev_err(udma_dev->dev,
					"copy resp to aux info type failed, byte = %lu.\n", byte);
				return -EFAULT;
			}

			byte = copy_to_user((void __user *)user_aux_info_out->aux_info_value,
					    (void *)aux_info_out->aux_info_value,
					    aux_info_out->aux_info_num *
					    sizeof(uint32_t));
			if (byte) {
				dev_err(udma_dev->dev,
					"copy resp to aux info value failed, byte = %lu.\n", byte);
				return -EFAULT;
			}

			kfree(aux_info_out->aux_info_type);
			kfree(aux_info_out->aux_info_value);
			aux_info_out->aux_info_type = user_aux_info_out->aux_info_type;
			aux_info_out->aux_info_value = user_aux_info_out->aux_info_value;
		}
		memcpy((void *)(uintptr_t)out->addr, aux_info_out,
		       sizeof(struct udma_ae_aux_info_out));
	}

	return 0;
}

int udma_query_ae_aux_info(struct ubcore_device *dev, struct ubcore_ucontext *uctx,
			   struct ubcore_user_ctl_in *in,
			   struct ubcore_user_ctl_out *out)
{
	struct udma_ae_aux_info_out user_aux_info_out = {};
	struct udma_ae_aux_info_out aux_info_out = {};
	struct udma_dev *udma_dev = to_udma_dev(dev);
	struct udma_cmd_query_ae_aux_info info = {};
	struct udma_ae_info_in ae_info_in = {};
	int ret;

	ret = udma_verify_aux_info_param(udma_dev, in, out, sizeof(struct udma_ae_info_in),
					 sizeof(struct udma_ae_aux_info_out));
	if (ret)
		return ret;

	memcpy(&ae_info_in, (void *)(uintptr_t)in->addr,
	       min(in->len, sizeof(struct udma_ae_info_in)));
	ret = to_hw_ae_event_type(udma_dev, ae_info_in.event_type, &info);
	if (ret)
		return ret;

	ret = copy_out_ae_data_from_user(udma_dev, out, &aux_info_out, uctx, &user_aux_info_out);
	if (ret) {
		dev_err(udma_dev->dev,
			"copy out data from user failed, ret = %d.\n", ret);
		return ret;
	}

	ret = send_cmd_query_ae_aux_info(udma_dev, &info);
	if (ret) {
		dev_err(udma_dev->dev,
			"send cmd query aux info failed, ret = %d.\n",
			ret);
		free_kernel_ae_aux_info(&user_aux_info_out, &aux_info_out);
		return ret;
	}

	dump_ae_aux_info(udma_dev, &aux_info_out, &info);

	ret = copy_out_ae_data_to_user(udma_dev, out, &aux_info_out, uctx, &user_aux_info_out);
	if (ret) {
		dev_err(udma_dev->dev,
			"copy out data to user failed, ret = %d.\n", ret);
		free_kernel_ae_aux_info(&user_aux_info_out, &aux_info_out);
	}

	return ret;
}

static udma_user_ctl_ops g_udma_user_ctl_k_ops[] = {
	[UDMA_USER_CTL_CREATE_JFS_EX] = udma_create_jfs_ops_ex,
	[UDMA_USER_CTL_DELETE_JFS_EX] = udma_delete_jfs_ops_ex,
	[UDMA_USER_CTL_CREATE_JFC_EX] = udma_create_jfc_ops_ex,
	[UDMA_USER_CTL_DELETE_JFC_EX] = udma_delete_jfc_ops_ex,
	[UDMA_USER_CTL_SET_CQE_ADDR] = udma_set_cqe_ex,
	[UDMA_USER_CTL_QUERY_UE_INFO] = udma_query_ue_info_ex,
	[UDMA_USER_CTL_GET_DEV_RES_RATIO] = udma_get_dev_resource_ratio,
	[UDMA_USER_CTL_NPU_REGISTER_INFO_CB] = udma_register_npu_cb,
	[UDMA_USER_CTL_NPU_UNREGISTER_INFO_CB] = udma_unregister_npu_cb,
	[UDMA_USER_CTL_QUERY_TP_SPORT] = udma_ctrlq_query_tp_sport,
	[UDMA_USER_CTL_QUERY_CQE_AUX_INFO] = udma_query_cqe_aux_info,
	[UDMA_USER_CTL_QUERY_AE_AUX_INFO] = udma_query_ae_aux_info,
	[UDMA_USER_CTL_QUERY_UBMEM_INFO] = udma_ctrlq_query_ubmem_info,
	[UDMA_USER_CTL_QUERY_PAIR_DEVNUM] = udma_query_pair_dev_count,
	[UDMA_USER_CTL_QUERY_HOST_UBMEM_INFO] = udma_ctrlq_query_host_ubmem_info,
};

static udma_user_ctl_ops g_udma_user_ctl_u_ops[] = {
	[UDMA_USER_CTL_CREATE_JFS_EX] = NULL,
	[UDMA_USER_CTL_DELETE_JFS_EX] = NULL,
	[UDMA_USER_CTL_CREATE_JFC_EX] = NULL,
	[UDMA_USER_CTL_DELETE_JFC_EX] = NULL,
	[UDMA_USER_CTL_SET_CQE_ADDR] = NULL,
	[UDMA_USER_CTL_QUERY_UE_INFO] = NULL,
	[UDMA_USER_CTL_GET_DEV_RES_RATIO] = NULL,
	[UDMA_USER_CTL_NPU_REGISTER_INFO_CB] = NULL,
	[UDMA_USER_CTL_NPU_UNREGISTER_INFO_CB] = NULL,
	[UDMA_USER_CTL_QUERY_TP_SPORT] = udma_ctrlq_query_tp_sport,
	[UDMA_USER_CTL_QUERY_CQE_AUX_INFO] = udma_query_cqe_aux_info,
	[UDMA_USER_CTL_QUERY_AE_AUX_INFO] = udma_query_ae_aux_info,
	[UDMA_USER_CTL_QUERY_UBMEM_INFO] = NULL,
	[UDMA_USER_CTL_QUERY_PAIR_DEVNUM] = NULL,
};

static int udma_user_data(struct ubcore_device *dev,
			  struct ubcore_user_ctl *k_user_ctl)
{
	struct udma_dev *udev = to_udma_dev(dev);
	struct ubcore_user_ctl_out out = {};
	struct ubcore_user_ctl_in in = {};
	unsigned long byte;
	int ret;

	if (k_user_ctl->in.len >= UDMA_HW_PAGE_SIZE || k_user_ctl->out.len >= UDMA_HW_PAGE_SIZE) {
		dev_err(udev->dev, "The len exceeds the maximum value in user ctrl.\n");
		return -EINVAL;
	}

	in.opcode = k_user_ctl->in.opcode;
	if (in.opcode >= ARRAY_SIZE(g_udma_user_ctl_u_ops) ||
		g_udma_user_ctl_u_ops[in.opcode] == NULL) {
		dev_err(udev->dev, "invalid user opcode: 0x%x.\n", in.opcode);
		return -EINVAL;
	}

	if (k_user_ctl->in.len) {
		in.addr = (uint64_t)kzalloc(k_user_ctl->in.len, GFP_KERNEL);
		if (!in.addr)
			return -ENOMEM;

		in.len = k_user_ctl->in.len;
		byte = copy_from_user((void *)(uintptr_t)in.addr,
			(void __user *)(uintptr_t)k_user_ctl->in.addr,
			k_user_ctl->in.len);
		if (byte) {
			dev_err(udev->dev,
				"failed to copy user data in user ctrl, byte = %lu.\n", byte);
			kfree((void *)in.addr);
			return -EFAULT;
		}
	}

	if (k_user_ctl->out.len) {
		out.addr = (uint64_t)kzalloc(k_user_ctl->out.len, GFP_KERNEL);
		if (!out.addr) {
			kfree((void *)in.addr);

			return -ENOMEM;
		}
		out.len = k_user_ctl->out.len;

		if (k_user_ctl->out.addr) {
			byte = copy_from_user((void *)(uintptr_t)out.addr,
				(void __user *)(uintptr_t)k_user_ctl->out.addr,
				k_user_ctl->out.len);
			if (byte) {
				dev_err(udev->dev,
					"failed to copy out user data out user ctrl, byte = %lu.\n",
					byte);
				kfree((void *)out.addr);
				kfree((void *)in.addr);

				return -EFAULT;
			}
		}
	}

	ret = g_udma_user_ctl_u_ops[in.opcode](dev, k_user_ctl->uctx, &in, &out);
	kfree((void *)in.addr);

	if (out.addr) {
		if (ret == 0) {
			byte = copy_to_user((void __user *)(uintptr_t)k_user_ctl->out.addr,
				    (void *)(uintptr_t)out.addr, min(out.len, k_user_ctl->out.len));
			if (byte) {
				dev_err(udev->dev,
					"copy resp to user failed in user ctrl, byte = %lu.\n",
					byte);
				ret = -EFAULT;
			}
		}

		kfree((void *)out.addr);
	}

	return ret;
}

int udma_user_ctl(struct ubcore_device *dev, struct ubcore_user_ctl *k_user_ctl)
{
	struct udma_dev *udev;

	if (dev == NULL || k_user_ctl == NULL)
		return -EINVAL;

	udev = to_udma_dev(dev);

	if (k_user_ctl->uctx)
		return udma_user_data(dev, k_user_ctl);

	if (k_user_ctl->in.opcode >= ARRAY_SIZE(g_udma_user_ctl_k_ops) ||
		g_udma_user_ctl_k_ops[k_user_ctl->in.opcode] == NULL) {
		dev_err(udev->dev, "invalid opcode: 0x%x.\n", k_user_ctl->in.opcode);
		return -EINVAL;
	}

	return g_udma_user_ctl_k_ops[k_user_ctl->in.opcode](dev, k_user_ctl->uctx, &k_user_ctl->in,
	       &k_user_ctl->out);
}
