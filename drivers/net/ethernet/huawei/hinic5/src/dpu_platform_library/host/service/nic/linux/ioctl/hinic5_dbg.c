/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_dbg.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": [NIC]" fmt

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/semaphore.h>
#include <linux/rhashtable.h>
#include <linux/netdevice.h>

#include "nic_pub_cmd.h"
#include "hinic5_crm.h"
#include "hinic5_hw.h"
#include "hinic5_nic_dev.h"
#include "hinic5_nic_dbg.h"
#include "hinic5_nic_sq.h"
#include "hinic5_nic_rq.h"
#include "hinic5_rx.h"
#include "hinic5_tx.h"
#include "hinic5_dcb.h"
#include "hinic5_bond.h"
#include "nic_cfg_comm.h"
#include "bond_pub_cmd.h"
#include "hinic5_macsec_api.h"
#include "hinic5_tc.h"
#include "drv_nic_api.h"
#include "hinic5_dbg.h"

static int get_nic_drv_version(void *buf_out, const u32 *out_size)
{
	struct drv_version_info *ver_info = buf_out;
	int err;

	if (!buf_out) {
		pr_err("Buf_out is NULL.\n");
		return -EINVAL;
	}

	if (*out_size != sizeof(*ver_info)) {
		pr_err("Unexpect out buf size from user :%u, expect: %lu\n",
		       *out_size, sizeof(*ver_info));
		return -EINVAL;
	}

	err = snprintf(ver_info->ver, sizeof(ver_info->ver), "%s  %s",
		       HINIC5_NIC_DRV_VERSION, "2026-05-20_00:00:00");
	if (err < 0)
		return -EINVAL;

	return 0;
}

static int get_tx_info(struct hinic5_nic_dev *nic_dev, const void *buf_in,
		       u32 in_size, void *buf_out, const u32 *out_size)
{
	struct nic_sq_info *sq_info = buf_out;
	u16 q_id;
	int err;

	if (!HINIC5_CHANNEL_RES_VALID(nic_dev)) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Netdev is down, can't get tx info\n");
		return -EFAULT;
	}

	if (!buf_in || !buf_out) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Buf_in or buf_out is NULL.\n");
		return -EINVAL;
	}

	if (!out_size || in_size != sizeof(u32)) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Unexpect in buf size from user :%u, expect: %lu\n",
			  in_size, sizeof(u32));
		return -EINVAL;
	}

	q_id = (u16)(*((u32 *)buf_in));

	err = hinic5_dbg_get_sq_info(nic_dev->hwdev, q_id, buf_out, *out_size);
	if (err != 0) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Get sq info failed, ret is %d.\n", err);
		return err;
	}

	sq_info->priority = nic_dev->txqs[q_id].cos;

	return 0;
}

static int get_q_num(struct hinic5_nic_dev *nic_dev,
		     const void *buf_in, u32 in_size,
		     void *buf_out, const u32 *out_size)
{
	if (!HINIC5_CHANNEL_RES_VALID(nic_dev)) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Netdev is down, can't get queue number\n");
		return -EFAULT;
	}

	if (!buf_out || !out_size) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Param buf_out or out_size is NULL.\n");
		return -EINVAL;
	}

	if (*out_size != sizeof(u16)) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Unexpect out buf size from user: %u, expect: %lu\n",
			  *out_size, sizeof(u16));
		return -EINVAL;
	}

	*((u16 *)buf_out) = nic_dev->q_params.num_qps;

	return 0;
}

static int get_tx_wqe_info(struct hinic5_nic_dev *nic_dev,
			   const void *buf_in, u32 in_size,
			   void *buf_out, u32 *out_size)
{
	const struct wqe_info *info = buf_in;
	u16 wqebb_cnt = 1;

	if (!HINIC5_CHANNEL_RES_VALID(nic_dev)) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Netdev is down, can't get tx wqe info\n");
		return -EFAULT;
	}

	if (!buf_in || !buf_out) {
		nicif_err(nic_dev, drv, nic_dev->netdev, "Buf_in or buf_out is NULL.\n");
		return -EINVAL;
	}

	if (!out_size || in_size != sizeof(struct wqe_info)) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Unexpect buf size from user, in_size: %u, expect: %lu\n",
			  in_size, sizeof(struct wqe_info));
		return -EINVAL;
	}

	return hinic5_dbg_get_wqe_info(nic_dev->hwdev, (u16)info->q_id,
				       (u16)info->wqe_id, wqebb_cnt,
				       buf_out, (u16 *)(u8 *)out_size, HINIC5_SQ);
}

static int get_rx_info(struct hinic5_nic_dev *nic_dev, const void *buf_in,
		       u32 in_size, void *buf_out, const u32 *out_size)
{
	struct nic_rq_info *rq_info = buf_out;
	u16 q_id;
	int err;

	if (!HINIC5_CHANNEL_RES_VALID(nic_dev)) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Netdev is down, can't get rx info\n");
		return -EFAULT;
	}

	if (!buf_in || !buf_out) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Buf_in or buf_out is NULL.\n");
		return -EINVAL;
	}

	if (!out_size || in_size != sizeof(u32)) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Unexpect buf size from user, in_size: %u, expect: %lu\n",
			  in_size, sizeof(u32));
		return -EINVAL;
	}

	q_id = (u16)(*((u32 *)buf_in));

	err = hinic5_dbg_get_rq_info(nic_dev->hwdev, q_id, buf_out, *out_size);
	if (err != 0) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Get rq info failed, ret is %d.\n", err);
		return err;
	}

	rq_info->delta = (u16)nic_dev->rxqs[q_id].delta;
	rq_info->ci = (u16)(nic_dev->rxqs[q_id].cons_idx & nic_dev->rxqs[q_id].q_mask);
	rq_info->sw_pi = nic_dev->rxqs[q_id].next_to_update;
	rq_info->msix_vector = nic_dev->rxqs[q_id].irq_id;

	rq_info->coalesc_timer_cfg = nic_dev->rxqs[q_id].last_coalesc_timer_cfg;
	rq_info->pending_limt = nic_dev->rxqs[q_id].last_pending_limt;

	return 0;
}

static int get_rx_wqe_info(struct hinic5_nic_dev *nic_dev, const void *buf_in,
			   u32 in_size, void *buf_out, u32 *out_size)
{
	const struct wqe_info *info = buf_in;
	u16 wqebb_cnt = 1;

	if (!HINIC5_CHANNEL_RES_VALID(nic_dev)) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Netdev is down, can't get rx wqe info\n");
		return -EFAULT;
	}

	if (!buf_in || !buf_out) {
		nicif_err(nic_dev, drv, nic_dev->netdev, "Buf_in or buf_out is NULL.\n");
		return -EINVAL;
	}

	if (!out_size || in_size != sizeof(struct wqe_info)) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Unexpect buf size from user, in_size: %u, expect: %lu\n",
			  in_size, sizeof(struct wqe_info));
		return -EINVAL;
	}

	return hinic5_dbg_get_wqe_info(nic_dev->hwdev, (u16)info->q_id,
				       (u16)info->wqe_id, wqebb_cnt,
				       buf_out, (u16 *)(u8 *)out_size, HINIC5_RQ);
}

static int get_rx_cqe_info(struct hinic5_nic_dev *nic_dev, const void *buf_in,
			   u32 in_size, void *buf_out, const u32 *out_size)
{
	const struct wqe_info *info = buf_in;
	u16 q_id = 0;
	u16 idx = 0;

	if (!HINIC5_CHANNEL_RES_VALID(nic_dev)) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Netdev is down, can't get rx cqe info\n");
		return -EFAULT;
	}

	if (!buf_in || !buf_out || !out_size) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Buf_in, buf_out or out_size is NULL.\n");
		return -EINVAL;
	}

	if (in_size != sizeof(struct wqe_info)) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Unexpect buf size from user, in_size: %u, expect: %lu\n",
			  in_size, sizeof(struct wqe_info));
		return -EINVAL;
	}

	if (*out_size != sizeof(struct hinic5_cqe_info)) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Unexpect out buf size from user :%u, expect: %lu\n",
			  *out_size, sizeof(struct hinic5_cqe_info));
		return -EINVAL;
	}
	q_id = (u16)info->q_id;
	idx = (u16)info->wqe_id;

	if (q_id >= nic_dev->q_params.num_qps) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Invalid q_id[%u] >= %u.\n", q_id, nic_dev->q_params.num_qps);
		return -EFAULT;
	}
	if (idx >= nic_dev->rxqs[q_id].q_depth) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Invalid wqe idx[%u] >= %u.\n", idx, nic_dev->rxqs[q_id].q_depth);
		return -EFAULT;
	}

	memcpy(buf_out, nic_dev->rxqs[q_id].rx_info[idx].cqe_info, sizeof(struct hinic5_cqe_info));

	return 0;
}

static void clean_nicdev_stats(struct hinic5_nic_dev *nic_dev)
{
	u64_stats_update_begin(&nic_dev->stats.syncp);
	nic_dev->stats.netdev_tx_timeout = 0;
	nic_dev->stats.tx_carrier_off_drop = 0;
	nic_dev->stats.tx_invalid_qid = 0;
	nic_dev->stats.rsvd1 = 0;
	nic_dev->stats.rsvd2 = 0;
	u64_stats_update_end(&nic_dev->stats.syncp);
}

static int clear_func_static(struct hinic5_nic_dev *nic_dev, const void *buf_in,
			     u32 in_size, void *buf_out, u32 *out_size)
{
	int i;

	*out_size = 0;
#ifndef HAVE_NETDEV_STATS_IN_NETDEV
	memset(&nic_dev->net_stats, 0, sizeof(nic_dev->net_stats));
#endif
	clean_nicdev_stats(nic_dev);
	for (i = 0; i < nic_dev->max_qps; i++) {
		hinic5_rxq_clean_stats(&nic_dev->rxqs[i].rxq_stats);
		hinic5_txq_clean_stats(&nic_dev->txqs[i].txq_stats);
	}

	return 0;
}

static int get_loopback_mode(struct hinic5_nic_dev *nic_dev, const void *buf_in,
			     u32 in_size, void *buf_out, const u32 *out_size)
{
	struct hinic5_nic_loop_mode *mode = buf_out;

	if (!out_size || !mode)
		return -EINVAL;

	if (*out_size != sizeof(*mode)) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Unexpect out buf size from user: %u, expect: %lu\n",
			  *out_size, sizeof(*mode));
		return -EINVAL;
	}

	return hinic5_get_loopback_mode(nic_dev->hwdev, (u8 *)&mode->loop_mode,
					(u8 *)&mode->loop_ctrl);
}

static int set_loopback_mode(struct hinic5_nic_dev *nic_dev, const void *buf_in,
			     u32 in_size, void *buf_out, const u32 *out_size)
{
	const struct hinic5_nic_loop_mode *mode = buf_in;
	int err;

	if (test_bit(HINIC5_INTF_UP, &nic_dev->flags) == 0) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Netdev is down, can't set loopback mode\n");
		return -EFAULT;
	}

	if (!mode || !out_size || in_size != sizeof(*mode))
		return -EINVAL;

	if (*out_size != sizeof(*mode)) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Unexpect out buf size from user: %u, expect: %lu\n",
			  *out_size, sizeof(*mode));
		return -EINVAL;
	}

	err = hinic5_set_loopback_mode(nic_dev->hwdev, (u8)mode->loop_mode,
				       (u8)mode->loop_ctrl);
	if (err == 0)
		nicif_info(nic_dev, drv, nic_dev->netdev, "Set loopback mode %u en %u succeed\n",
			   mode->loop_mode, mode->loop_ctrl);

	return err;
}

enum hinic5_nic_link_mode {
	HINIC5_LINK_MODE_AUTO = 0,
	HINIC5_LINK_MODE_UP,
	HINIC5_LINK_MODE_DOWN,
	HINIC5_LINK_MODE_MAX,
};

static int set_link_mode_param_valid(struct hinic5_nic_dev *nic_dev,
				     const void *buf_in, u32 in_size,
				     const u32 *out_size)
{
	if (test_bit(HINIC5_INTF_UP, &nic_dev->flags) == 0) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Netdev is down, can't set link mode\n");
		return -EFAULT;
	}

	if (!buf_in || !out_size ||
	    in_size != sizeof(enum hinic5_nic_link_mode))
		return -EINVAL;

	if (*out_size != sizeof(enum hinic5_nic_link_mode)) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Unexpect out buf size from user: %u, expect: %lu\n",
			  *out_size, sizeof(enum hinic5_nic_link_mode));
		return -EINVAL;
	}

	return 0;
}

static int set_link_mode(struct hinic5_nic_dev *nic_dev, const void *buf_in,
			 u32 in_size, void *buf_out, u32 *out_size)
{
	const enum hinic5_nic_link_mode *link = buf_in;
	u8 link_status;

	if (set_link_mode_param_valid(nic_dev, buf_in, in_size, out_size) != 0)
		return -EFAULT;

	switch (*link) {
	case HINIC5_LINK_MODE_AUTO:
		if (hinic5_get_link_state(nic_dev->hwdev, &link_status) != 0)
			link_status = false;
		hinic5_link_status_change(nic_dev, (bool)link_status);
		nicif_info(nic_dev, drv, nic_dev->netdev,
			   "Set link mode: auto succeed, now is link %s\n",
			   ((link_status != 0) ? "up" : "down"));
		break;
	case HINIC5_LINK_MODE_UP:
		hinic5_link_status_change(nic_dev, true);
		nicif_info(nic_dev, drv, nic_dev->netdev,
			   "Set link mode: up succeed\n");
		break;
	case HINIC5_LINK_MODE_DOWN:
		hinic5_link_status_change(nic_dev, false);
		nicif_info(nic_dev, drv, nic_dev->netdev,
			   "Set link mode: down succeed\n");
		break;
	default:
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Invalid link mode %d to set\n", *link);
		return  -EINVAL;
	}

	return 0;
}

static int set_pf_bw_limit(struct hinic5_nic_dev *nic_dev, const void *buf_in,
			   u32 in_size, void *buf_out, const u32 *out_size)
{
	u32 pf_bw_limit;
	int err;

	if (HINIC5_FUNC_IS_VF(nic_dev->hwdev)) {
		nicif_err(nic_dev, drv, nic_dev->netdev, "To set VF bandwidth rate, please use ip link cmd\n");
		return -EINVAL;
	}

	if (!buf_in || !buf_out || in_size != sizeof(u32) ||
	    !out_size || *out_size != sizeof(u8))
		return -EINVAL;

	pf_bw_limit = *((u32 *)buf_in);

	err = hinic5_set_pf_bw_limit(nic_dev->hwdev, pf_bw_limit);
	if (err != 0) {
		nicif_err(nic_dev, drv, nic_dev->netdev, "Failed to set pf bandwidth limit to %u%%\n",
			  pf_bw_limit);
		if (err < 0)
			return err;
	}

	*((u8 *)buf_out) = (u8)err;

	return 0;
}

static int get_pf_bw_limit(struct hinic5_nic_dev *nic_dev, const void *buf_in,
			   u32 in_size, void *buf_out, const u32 *out_size)
{
	int err;

	if (HINIC5_FUNC_IS_VF(nic_dev->hwdev)) {
		nicif_err(nic_dev, drv, nic_dev->netdev, "To get VF bandwidth rate, please use ip link cmd\n");
		return -EINVAL;
	}

	if (!buf_out || !out_size)
		return -EINVAL;

	if (*out_size != sizeof(u32)) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Unexpect out buf size from user: %u, expect: %lu\n",
			  *out_size, sizeof(u32));
		return -EFAULT;
	}

	err = hinic5_get_pf_bw_limit(nic_dev->hwdev, (u32 *)buf_out);
	if (err != 0) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Failed to get pf bandwidth limit err: %d\n", err);
		return err;
	}

	return 0;
}

static int get_sset_count(struct hinic5_nic_dev *nic_dev, const void *buf_in,
			  u32 in_size, void *buf_out, const u32 *out_size)
{
	u32 count;

	if (!buf_in || in_size != sizeof(u32) || !out_size ||
	    *out_size != sizeof(u32) || !buf_out) {
		nicif_err(nic_dev, drv, nic_dev->netdev, "Invalid parameters, in_size: %u\n",
			  in_size);
		return -EINVAL;
	}

	switch (*((u32 *)buf_in)) {
	case HINIC5_SHOW_SSET_IO_STATS:
		count = hinic5_get_io_stats_size(nic_dev);
		break;
	default:
		count = 0;
		break;
	}

	*((u32 *)buf_out) = count;

	return 0;
}

static int get_sset_stats(struct hinic5_nic_dev *nic_dev, const void *buf_in,
			  u32 in_size, void *buf_out, const u32 *out_size)
{
	struct hinic5_show_item *items = buf_out;
	u32 sset, count, size;
	int err;

	if (!buf_in || in_size != sizeof(u32) || !out_size || !buf_out) {
		nicif_err(nic_dev, drv, nic_dev->netdev, "Invalid parameters, in_size: %u\n",
			  in_size);
		return -EINVAL;
	}

	size = sizeof(u32);
	err = get_sset_count(nic_dev, buf_in, in_size, &count, &size);
	if (err != 0) {
		nicif_err(nic_dev, drv, nic_dev->netdev, "Get sset count failed, ret=%d\n",
			  err);
		return -EINVAL;
	}
	if (count * sizeof(*items) != *out_size) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Unexpect out buf size from user :%u, expect: %lu\n",
			  *out_size, count * sizeof(*items));
		return -EINVAL;
	}

	sset = *((u32 *)buf_in);

	switch (sset) {
	case HINIC5_SHOW_SSET_IO_STATS:
		err = hinic5_get_io_stats(nic_dev, items);
		if (err < 0)
			return -EINVAL;
		break;

	default:
		nicif_err(nic_dev, drv, nic_dev->netdev, "Unknown %u to get stats\n",
			  sset);
		err = -EINVAL;
		break;
	}

	return err;
}

static int update_pcp_dscp_cfg(struct hinic5_nic_dev *nic_dev,
			       struct hinic5_dcb_config *wanted_dcb_cfg,
			       const struct hinic5_mt_qos_dev_cfg *qos_in)
{
	int i;
	u8 cos_num = 0, valid_cos_bitmap = 0;

	if ((qos_in->cfg_bitmap & CMD_QOS_DEV_PCP2COS) != 0) {
		for (i = 0; i < NIC_DCB_UP_MAX; i++) {
			if ((nic_dev->func_dft_cos_bitmap & BIT(qos_in->pcp2cos[i])) == 0) {
				nicif_err(nic_dev, drv, nic_dev->netdev,
					  "Invalid cos=%u, func cos valid map is %u",
					  qos_in->pcp2cos[i], nic_dev->func_dft_cos_bitmap);
				return -EINVAL;
			}

			if ((BIT(qos_in->pcp2cos[i]) & valid_cos_bitmap) == 0) {
				valid_cos_bitmap |= (u8)BIT(qos_in->pcp2cos[i]);
				cos_num++;
			}
		}

		memcpy(wanted_dcb_cfg->pcp2cos,
		       qos_in->pcp2cos, sizeof(qos_in->pcp2cos));
		wanted_dcb_cfg->pcp_user_cos_num = cos_num;
		wanted_dcb_cfg->pcp_valid_cos_map = valid_cos_bitmap;
	}

	if ((qos_in->cfg_bitmap & CMD_QOS_DEV_DSCP2COS) != 0) {
		cos_num = 0;
		valid_cos_bitmap = 0;
		for (i = 0; i < NIC_DCB_IP_PRI_MAX; i++) {
			u8 cos = qos_in->dscp2cos[i] == DBG_DFLT_DSCP_VAL ?
				nic_dev->hw_dcb_cfg.dscp2cos[i] : qos_in->dscp2cos[i];

			if (cos >= NIC_DCB_UP_MAX ||
			    ((nic_dev->func_dft_cos_bitmap & BIT(cos)) == 0)) {
				nicif_err(nic_dev, drv, nic_dev->netdev,
					  "Invalid cos=%u, func cos valid map is %u",
					  cos, nic_dev->func_dft_cos_bitmap);
				return -EINVAL;
			}

			if ((BIT(cos) & valid_cos_bitmap) == 0) {
				valid_cos_bitmap |= (u8)BIT(cos);
				cos_num++;
			}
		}

		for (i = 0; i < NIC_DCB_IP_PRI_MAX; i++)
			wanted_dcb_cfg->dscp2cos[i] = qos_in->dscp2cos[i] == DBG_DFLT_DSCP_VAL ?
				nic_dev->hw_dcb_cfg.dscp2cos[i] : qos_in->dscp2cos[i];
		wanted_dcb_cfg->dscp_user_cos_num = cos_num;
		wanted_dcb_cfg->dscp_valid_cos_map = valid_cos_bitmap;
	}

	return 0;
}

static int update_wanted_qos_cfg(struct hinic5_nic_dev *nic_dev,
				 struct hinic5_dcb_config *wanted_dcb_cfg,
				 const struct hinic5_mt_qos_dev_cfg *qos_in)
{
	int ret;
	u8 cos_num, valid_cos_bitmap;

	if ((qos_in->cfg_bitmap & CMD_QOS_DEV_TRUST) != 0) {
		if (qos_in->trust > DCB_DSCP) {
			nicif_err(nic_dev, drv, nic_dev->netdev,
				  "Invalid trust=%u\n", qos_in->trust);
			return -EINVAL;
		}

		wanted_dcb_cfg->trust = qos_in->trust;
	}

	if ((qos_in->cfg_bitmap & CMD_QOS_DEV_DFT_COS) != 0) {
		if ((BIT(qos_in->dft_cos) & nic_dev->func_dft_cos_bitmap) == 0) {
			nicif_err(nic_dev, drv, nic_dev->netdev,
				  "Invalid dft_cos=%u\n", qos_in->dft_cos);
			return -EINVAL;
		}

		wanted_dcb_cfg->default_cos = qos_in->dft_cos;
	}

	ret = update_pcp_dscp_cfg(nic_dev, wanted_dcb_cfg, qos_in);
	if (ret != 0)
		return ret;

	if (wanted_dcb_cfg->trust == DCB_PCP) {
		cos_num = wanted_dcb_cfg->pcp_user_cos_num;
		valid_cos_bitmap = wanted_dcb_cfg->pcp_valid_cos_map;
	} else {
		cos_num = wanted_dcb_cfg->dscp_user_cos_num;
		valid_cos_bitmap = wanted_dcb_cfg->dscp_valid_cos_map;
	}

	if (test_bit(HINIC5_DCB_ENABLE, &nic_dev->flags) != 0) {
		if (cos_num > nic_dev->q_params.num_qps) {
			nicif_err(nic_dev, drv, nic_dev->netdev,
				  "DCB is on, cos num should not more than channel num:%u\n",
				  nic_dev->q_params.num_qps);
			return -EOPNOTSUPP;
		}
	}

	if ((BIT(wanted_dcb_cfg->default_cos) & valid_cos_bitmap) == 0) {
		nicif_info(nic_dev, drv, nic_dev->netdev, "Current default_cos=%u, change to %d\n",
			   wanted_dcb_cfg->default_cos, (u8)fls(valid_cos_bitmap) - 1);
		wanted_dcb_cfg->default_cos = (u8)fls(valid_cos_bitmap) - 1;
	}

	return 0;
}

static int dcb_mt_qos_map(struct hinic5_nic_dev *nic_dev, const void *buf_in,
			  u32 in_size, void *buf_out, const u32 *out_size)
{
	const struct hinic5_mt_qos_dev_cfg *qos_in = buf_in;
	struct hinic5_mt_qos_dev_cfg *qos_out = buf_out;
	struct hinic5_dcb_config wanted_dcb_cfg = {0};
	u8 i;
	int err;

	if (!buf_out || !out_size || !buf_in)
		return -EINVAL;

	if (*out_size != sizeof(*qos_out) || in_size != sizeof(*qos_in)) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Unexpect buf size from user, in_size: %u, out_size: %u, expect: %lu\n",
			  in_size, *out_size, sizeof(*qos_in));
		return -EINVAL;
	}

	memcpy(qos_out, qos_in, sizeof(*qos_in));
	qos_out->head.status = 0;
	if ((qos_in->op_code & MT_DCB_OPCODE_WR) != 0) {
		memcpy(&wanted_dcb_cfg, &nic_dev->hw_dcb_cfg,
		       sizeof(struct hinic5_dcb_config));
		err = update_wanted_qos_cfg(nic_dev, &wanted_dcb_cfg, qos_in);
		if (err != 0) {
			qos_out->head.status = MT_EINVAL;
			return 0;
		}

		err = hinic5_dcbcfg_set_up_bitmap(nic_dev, &wanted_dcb_cfg);
		if (err != 0)
			qos_out->head.status = MT_EIO;
	} else {
		qos_out->dft_cos = nic_dev->hw_dcb_cfg.default_cos;
		qos_out->trust = nic_dev->hw_dcb_cfg.trust;
		for (i = 0; i < NIC_DCB_UP_MAX; i++)
			qos_out->pcp2cos[i] = nic_dev->hw_dcb_cfg.pcp2cos[i];
		for (i = 0; i < NIC_DCB_IP_PRI_MAX; i++)
			qos_out->dscp2cos[i] = nic_dev->hw_dcb_cfg.dscp2cos[i];
	}

	return 0;
}

static int dcb_mt_dcb_state(struct hinic5_nic_dev *nic_dev, const void *buf_in,
			    u32 in_size, void *buf_out, const u32 *out_size)
{
	const struct hinic5_mt_dcb_state *dcb_in = buf_in;
	struct hinic5_mt_dcb_state *dcb_out = buf_out;
	int err;
	u8 user_cos_num;
	u8 netif_run = 0;

	if (!buf_in || !buf_out || !out_size)
		return -EINVAL;

	if (*out_size != sizeof(*dcb_out) || in_size != sizeof(*dcb_in)) {
		nicif_err(nic_dev, drv, nic_dev->netdev, "buf size err, in_size: %u, out_size: %u, expect: %lu\n",
			  in_size, *out_size, sizeof(*dcb_in));
		return -EINVAL;
	}

	user_cos_num = hinic5_get_dev_user_cos_num(nic_dev);
	memcpy(dcb_out, dcb_in, sizeof(*dcb_in));
	dcb_out->head.status = 0;
	if ((dcb_in->op_code & MT_DCB_OPCODE_WR) != 0) {
		if (test_bit(HINIC5_DCB_ENABLE, &nic_dev->flags) == dcb_in->state)
			return 0;

		if (dcb_in->state != 0 && (netif_is_rxfh_configured(nic_dev->netdev))) {
			nicif_err(nic_dev, drv, nic_dev->netdev,
				  "Cannot enable dcb when user has configured rss indirect table.\n");
			return -EOPNOTSUPP;
		}

		if (dcb_in->state != 0 && user_cos_num > nic_dev->q_params.num_qps) {
			nicif_err(nic_dev, drv, nic_dev->netdev, "cos num %u is big than qps num %u\n",
				  user_cos_num, nic_dev->q_params.num_qps);
			return -EOPNOTSUPP;
		}

		if (netif_running(nic_dev->netdev)) {
			netif_run = 1;
			hinic5_vport_down(nic_dev);
		}

		err = hinic5_setup_cos(nic_dev->netdev,
				       (dcb_in->state != 0) ? user_cos_num : 0, netif_run);
		if (err != 0)
			goto setup_cos_fail;

		if (netif_run != 0) {
			err = hinic5_vport_up(nic_dev);
			if (err != 0)
				goto vport_up_fail;
		}
	} else {
		dcb_out->state = !!test_bit(HINIC5_DCB_ENABLE, &nic_dev->flags);
	}

	return 0;

vport_up_fail:
	hinic5_setup_cos(nic_dev->netdev, (dcb_in->state != 0) ? 0 : user_cos_num, netif_run);

setup_cos_fail:
	if (netif_run != 0)
		hinic5_vport_up(nic_dev);

	return err;
}

static int dcb_mt_hw_qos_get(struct hinic5_nic_dev *nic_dev, const void *buf_in,
			     u32 in_size, void *buf_out, const u32 *out_size)
{
	const struct hinic5_mt_qos_cos_cfg *cos_cfg_in = buf_in;
	struct hinic5_mt_qos_cos_cfg *cos_cfg_out = buf_out;

	if (!buf_in || !buf_out || !out_size)
		return -EINVAL;

	if (*out_size != sizeof(*cos_cfg_out) || in_size != sizeof(*cos_cfg_in)) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Unexpect buf size from user, in_size: %u, out_size: %u, expect: %lu\n",
			  in_size, *out_size, sizeof(*cos_cfg_in));
		return -EINVAL;
	}

	memcpy(cos_cfg_out, cos_cfg_in, sizeof(*cos_cfg_in));
	cos_cfg_out->head.status = 0;

	cos_cfg_out->port_id = hinic5_physical_port_id(nic_dev->hwdev);
	cos_cfg_out->func_cos_bitmap = (u8)nic_dev->func_dft_cos_bitmap;
	cos_cfg_out->port_cos_bitmap = (u8)nic_dev->port_dft_cos_bitmap;
	cos_cfg_out->func_max_cos_num = nic_dev->cos_config_num_max;

	return 0;
}

static int get_inter_num(struct hinic5_nic_dev *nic_dev, const void *buf_in,
			 u32 in_size, void *buf_out, const u32 *out_size)
{
	u16 intr_num;

	intr_num = hinic5_intr_num(nic_dev->hwdev);

	if (!buf_out || !out_size) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Buf_out or out_size is NULL.\n");
		return -EINVAL;
	}

	if (*out_size != sizeof(u16)) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Unexpect out buf size from user :%u, expect: %lu\n",
			  *out_size, sizeof(u16));
		return -EFAULT;
	}
	*(u16 *)buf_out = intr_num;

	return 0;
}

static int get_netdev_name(struct hinic5_nic_dev *nic_dev, const void *buf_in,
			   u32 in_size, void *buf_out, const u32 *out_size)
{
	if (!buf_out || !out_size) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Buf_out or out_size is NULL.\n");
		return -EINVAL;
	}

	if (*out_size != IFNAMSIZ) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Unexpect out buf size from user :%u, expect: %u\n",
			  *out_size, IFNAMSIZ);
		return -EFAULT;
	}

	strscpy(buf_out, nic_dev->netdev->name, IFNAMSIZ);

	return 0;
}

static int get_netdev_tx_timeout(struct hinic5_nic_dev *nic_dev, const void *buf_in,
				 u32 in_size, void *buf_out, const u32 *out_size)
{
	struct net_device *net_dev = nic_dev->netdev;
	int *tx_timeout = buf_out;

	if (!buf_out || !out_size)
		return -EINVAL;

	if (*out_size != sizeof(int)) {
		nicif_err(nic_dev, drv, net_dev, "Unexpect buf size from user, out_size: %u, expect: %lu\n",
			  *out_size, sizeof(int));
		return -EINVAL;
	}

	*tx_timeout = net_dev->watchdog_timeo;

	return 0;
}

static int set_netdev_tx_timeout(struct hinic5_nic_dev *nic_dev, const void *buf_in,
				 u32 in_size, void *buf_out, u32 *out_size)
{
	struct net_device *net_dev = nic_dev->netdev;
	const int *tx_timeout = buf_in;

	if (!buf_in)
		return -EINVAL;

	if (in_size != sizeof(int)) {
		nicif_err(nic_dev, drv, net_dev, "Unexpect buf size from user, in_size: %u, expect: %lu\n",
			  in_size, sizeof(int));
		return -EINVAL;
	}

	net_dev->watchdog_timeo = *tx_timeout * HZ;
	nicif_info(nic_dev, drv, net_dev, "Set tx timeout check period to %ds\n", *tx_timeout);

	return 0;
}

static int get_xsfp_present(struct hinic5_nic_dev *nic_dev, const void *buf_in,
			    u32 in_size, void *buf_out, const u32 *out_size)
{
	struct mag_cmd_get_xsfp_present *sfp_abs = buf_out;

	if (!buf_in || !buf_out || !out_size)
		return -EINVAL;

	if (*out_size != sizeof(*sfp_abs) || in_size != sizeof(*sfp_abs)) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Unexpect buf size from user, in_size: %u, out_size: %u, expect: %lu\n",
			  in_size, *out_size, sizeof(*sfp_abs));
		return -EINVAL;
	}

	sfp_abs->head.status = 0;
	sfp_abs->abs_status = hinic5_if_sfp_absent(nic_dev->hwdev);

	return 0;
}

static int get_xsfp_info(struct hinic5_nic_dev *nic_dev, const void *buf_in,
			 u32 in_size, void *buf_out, const u32 *out_size)
{
	struct mag_cmd_get_xsfp_info *sfp_info = buf_out;
	int err;

	if (!buf_in || !buf_out || !out_size)
		return -EINVAL;

	if (*out_size != sizeof(*sfp_info) || in_size != sizeof(*sfp_info)) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Unexpect buf size from user, in_size: %u, out_size: %u, expect: %lu\n",
			  in_size, *out_size, sizeof(*sfp_info));
		return -EINVAL;
	}

	err = hinic5_get_sfp_info(nic_dev->hwdev, sfp_info);
	if (err != 0) {
		sfp_info->head.status = MT_EIO;
		return 0;
	}

	return 0;
}

static int get_xsfp_tlv_info(struct hinic5_nic_dev *nic_dev, const void *buf_in,
			     u32 in_size, void *buf_out, const u32 *out_size)
{
	struct drv_tag_mag_cmd_get_xsfp_tlv_rsp *sfp_tlv_info = buf_out;
	const struct tag_mag_cmd_get_xsfp_tlv_req *sfp_tlv_info_req = buf_in;
	int err;

	if (!buf_in || !buf_out || !out_size)
		return -EINVAL;

	if (*out_size != sizeof(*sfp_tlv_info) || in_size != sizeof(*sfp_tlv_info_req)) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Unexpect buf size from user, in_size: %u, out_size: %u, expect: %lu\n",
			  in_size, *out_size, sizeof(*sfp_tlv_info));
		return -EINVAL;
	}

	err = hinic5_get_sfp_tlv_info(nic_dev->hwdev, sfp_tlv_info, sfp_tlv_info_req);
	if (err != 0) {
		sfp_tlv_info->head.status = MT_EIO;
		return 0;
	}

	return 0;
}

static int get_profile_id(struct hinic5_nic_dev *nic_dev, const void *buf_in,
			  u32 in_size, void *buf_out, const u32 *out_size)
{
	struct hinic5_tc_info *tc_info = (struct hinic5_tc_info *)nic_dev->tc_info;

	if (!HINIC5_SUPPORT_FEATURE(nic_dev->hwdev, TC_FLOWER_OFFLOAD)) {
		hinic5_err(nic_dev, drv, "dev is not enable PFE\n");
		return -EINVAL;
	}

	if (!out_size || !buf_out) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Param buf_out or out_size is NULL.\n");
		return -EINVAL;
	}

	if (*out_size != sizeof(u16)) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Unexpect out buf size from user: %u, expect: %lu\n",
			  *out_size, sizeof(u16));
		return -EINVAL;
	}

	*((u16 *)buf_out) = tc_info->profile_id;

	return 0;
}

static int set_profile_id(struct hinic5_nic_dev *nic_dev, const void *buf_in,
			  u32 in_size, void *buf_out, const u32 *out_size)
{
	struct hinic5_tc_info *tc_info = (struct hinic5_tc_info *)nic_dev->tc_info;
	const u16 *profile_id = buf_in;

	if (!HINIC5_SUPPORT_FEATURE(nic_dev->hwdev, TC_FLOWER_OFFLOAD)) {
		hinic5_err(nic_dev, drv, "dev is not enable PFE\n");
		return -EINVAL;
	}

	if (!buf_in) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Param buf_in is NULL.\n");
		return -EINVAL;
	}

	if (in_size != sizeof(u16)) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Unexpect in_size from user: %u, expect: %lu\n",
			  in_size, sizeof(u16));
		return -EINVAL;
	}

	if (*profile_id >= HINIC5_TC_PROFILE_MAX) {
		hinic5_err(nic_dev, drv, "profile_id exceed limit\n");
		return -EINVAL;
	}

	tc_info->profile_id = *profile_id;

	return 0;
}

static int hinic5_move_tcam_table(struct hinic5_nic_dev *nic_dev, const void *buf_in,
				  u32 in_size, void *buf_out, const u32 *out_size)
{
	struct hinic5_tc_move_info *acl_move_info = (struct hinic5_tc_move_info *)buf_in;
	struct hinic5_tc_info *tc_info = (struct hinic5_tc_info *)nic_dev->tc_info;
	struct hinic5_tc_flow_node *flow_node = NULL;
	struct rhashtable_iter iter;
	int ret;
	u32 old_index, new_index, len;

	if (!HINIC5_SUPPORT_FEATURE(nic_dev->hwdev, TC_FLOWER_OFFLOAD)) {
		hinic5_err(nic_dev, drv, "dev is not enable PFE\n");
		return -EINVAL;
	}

	if (!buf_in) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Param buf_in is NULL.\n");
		return -EINVAL;
	}

	old_index = acl_move_info->old_index;
	new_index = acl_move_info->new_index;
	len = acl_move_info->len;

	if (in_size != sizeof(struct hinic5_tc_move_info)) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Unexpect in_size from user: %u, expect: %lu\n",
			  in_size, sizeof(struct hinic5_tc_move_info));
		return -EINVAL;
	}

	ret = hinic5_move_tc_tcam_table(nic_dev->hwdev, acl_move_info);
	if (ret != 0) {
		hinic5_err(nic_dev, drv, "move tcam table failed\n");
		return ret;
	}

	rhashtable_walk_enter(&tc_info->flow_table, &iter);
	rhashtable_walk_start(&iter);
	while ((flow_node = (struct hinic5_tc_flow_node *)rhashtable_walk_next(&iter)) != NULL &&
	       !IS_ERR(flow_node)) {
		if (flow_node->rule_id >= old_index && flow_node->rule_id < old_index + len)
			flow_node->rule_id += (u16)(new_index - old_index);
	}
	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);

	return ret;
}

static int g_bond_event_err;

void hinic_bond_dfx_active_event(const char *bond_name, struct bond_attr *attr, int err)
{
	if (err != 0)
		g_bond_event_err = 1;
}

int hinic_bond_dfx_ops(struct hinic5_nic_dev *nic_dev, const void *buf_in,
		       u32 in_size, void *buf_out, const u32 *out_size)
{
	u16 bond_id;
	int err = 0;
	struct bond_dfx_ops_info *info = (struct bond_dfx_ops_info *)buf_in;
	struct bond_srv_func srv_func = {
		.before_active = NULL,
		.after_active = hinic_bond_dfx_active_event,
		.before_modify = NULL,
		.after_modify = NULL,
		.before_deactive = NULL,
		.after_deactive = NULL,
		.can_attach = NULL,
	};

	if (!buf_in) {
		nicif_err(nic_dev, drv, nic_dev->netdev, "buf_in is NULL.\n");
		return -EINVAL;
	}

	if (in_size != sizeof(struct bond_dfx_ops_info)) {
		nicif_err(nic_dev, drv, nic_dev->netdev, "Unexpect in buf size from user :%u, expect: %lu\n",
			  in_size, sizeof(struct bond_dfx_ops_info));
		return -EINVAL;
	}

	if (info->ops == BOND_DFX_OP_ADD) {
		(void)hinic5_bond_register_service_func(info->user, &srv_func);
		err = hinic5_bond_attach(info->bond_name, info->user, &bond_id);
		if (g_bond_event_err != 0) {
			hinic5_bond_detach(bond_id, info->user);
			g_bond_event_err = 0;
		}
	} else if (info->ops == BOND_DFX_OP_DEL) {
		err = hinic5_bond_get_id_by_name(info->bond_name, &bond_id);
		if (err == 0) {
			hinic5_bond_detach(bond_id, info->user);
			hinic5_bond_unregister_service_func(info->user);
		}
	}

	info->head.status = (u8)err;

	return err;
}

static const struct nic_drv_module_handle nic_driv_module_cmd_handle[] = {
	/* Get sq info */
	{TX_INFO,						(nic_driv_module)get_tx_info},
	/* Get queue number */
	{Q_NUM,							(nic_driv_module)get_q_num},
	/* Get tx wqe info */
	{TX_WQE_INFO,					get_tx_wqe_info},
	/* Get rx info */
	{RX_INFO,						(nic_driv_module)get_rx_info},
	/* Get rx wqe info */
	{RX_WQE_INFO,					get_rx_wqe_info},
	/* Get rx cqe info */
	{RX_CQE_INFO,					(nic_driv_module)get_rx_cqe_info},
	/* Get interrupt number */
	{GET_INTER_NUM,					(nic_driv_module)get_inter_num},
	/* Clear func statistics */
	{CLEAR_FUNC_STASTIC,			clear_func_static},
	/* Get current loopback mode */
	{GET_LOOPBACK_MODE,				(nic_driv_module)get_loopback_mode},
	/* Set loopback mode */
	{SET_LOOPBACK_MODE,				(nic_driv_module)set_loopback_mode},
	/* Set link mode */
	{SET_LINK_MODE,					set_link_mode},
	/* Set pxe bandwidth limit */
	{SET_PF_BW_LIMIT,				(nic_driv_module)set_pf_bw_limit},
	/* Get pxe bandwidth limit */
	{GET_PF_BW_LIMIT,				(nic_driv_module)get_pf_bw_limit},
	/* Get current IO statistics count */
	{GET_SSET_COUNT,				(nic_driv_module)get_sset_count},
	/* Get current IO statistics status */
	{GET_SSET_ITEMS,				(nic_driv_module)get_sset_stats},
	/* Manage DCB state */
	{DCB_STATE,						(nic_driv_module)dcb_mt_dcb_state},
	/* Manage qos mapping relationship */
	{QOS_DEV,						(nic_driv_module)dcb_mt_qos_map},
	/* Get hardware qos configuration */
	{GET_QOS_COS,					(nic_driv_module)dcb_mt_hw_qos_get},
	/* Get network device name */
	{GET_ULD_DEV_NAME,				(nic_driv_module)get_netdev_name},
	/* Get tx timeout value */
	{GET_TX_TIMEOUT,				(nic_driv_module)get_netdev_tx_timeout},
	/* Configure tx timeout value */
	{SET_TX_TIMEOUT,				set_netdev_tx_timeout},
	/* Get optical module presence information */
	{GET_XSFP_PRESENT,				(nic_driv_module)get_xsfp_present},
	/* Get optical module information */
	{GET_XSFP_INFO,					(nic_driv_module)get_xsfp_info},
	/* Get optical module information in TLV format */
	{GET_XSFP_INFO_COMP_CMIS,		(nic_driv_module)get_xsfp_tlv_info},
	/* Get profile id */
	{CMD_GET_PROFILE_ID,			(nic_driv_module)get_profile_id},
	/* Configure profile id */
	{CMD_SET_PROFILE_ID,			(nic_driv_module)set_profile_id},
	/* Configure tcam table */
	{CMD_MOVE_TCAM_TABLE,			(nic_driv_module)hinic5_move_tcam_table},
	/* bond bind/unbind dfx */
	{BOND_DFX_OPS,					(nic_driv_module)hinic_bond_dfx_ops},
	/* Query driver-side MACsec table entries */
	{MACSEC_TOOL_OP_LIST,			(nic_driv_module)macsec_cmd_list},
	/* Query chip-side MACsec table entries */
	{MACSEC_TOOL_OP_DUMP,			(nic_driv_module)macsec_cmd_list},
	/* Get chip-side SC MIB information or PORT MIB information */
	{MACSEC_TOOL_OP_MIB,			(nic_driv_module)macsec_cmd_mib},
	/* Add SC or SA configuration */
	{MACSEC_TOOL_OP_ADD,			(nic_driv_module)macsec_cmd_add},
	/* Delete SC or SA configuration */
	{MACSEC_TOOL_OP_DEL,			(nic_driv_module)macsec_cmd_del},
	/* Modify SC configuration */
	{MACSEC_TOOL_OP_SET,			(nic_driv_module)macsec_cmd_set},
	/* Clear MACsec configuration managed by a device */
	{MACSEC_TOOL_OP_FLUSH,			(nic_driv_module)macsec_cmd_flush}
};

__weak int hinic5_tool_cmd_extend_handle(struct net_device *netdev, u32 cmd,
					 struct hinic5_nt_msg *nt_msg, bool *support)
{
	*support = false;

	return 0;
}

static int send_to_nic_driver(struct hinic5_nic_dev *nic_dev, u32 cmd, struct hinic5_nt_msg *nt_msg)
{
	int index, num_cmds = (int)(sizeof(nic_driv_module_cmd_handle) /
				sizeof(nic_driv_module_cmd_handle[0]));
	enum driver_cmd_type cmd_type = (enum driver_cmd_type)cmd;
	bool support = false;
	int err = 0;

	if (cmd_type == DCB_STATE || cmd_type == QOS_DEV)
		rtnl_lock();

	mutex_lock(&nic_dev->nic_mutex);
	for (index = 0; index < num_cmds; index++) {
		if (cmd_type ==
			nic_driv_module_cmd_handle[index].driv_cmd_name) {
			err = nic_driv_module_cmd_handle[index].driv_func
					(nic_dev, nt_msg->buf_in,
					 nt_msg->in_size, nt_msg->buf_out, &nt_msg->out_size);
			goto cmd_out;
		}
	}

	err = hinic5_tool_cmd_extend_handle(nic_dev->netdev, cmd_type, nt_msg, &support);
	if (!support) {
		pr_err("Can't find callback for %d\n", cmd_type);
		err = -EINVAL;
	}

cmd_out:
	mutex_unlock(&nic_dev->nic_mutex);

	if (cmd_type == DCB_STATE || cmd_type == QOS_DEV)
		rtnl_unlock();

	return err;
}

int hinic5_nic_ioctl(void *uld_dev, u32 cmd, const void *buf_in,
	      u32 in_size, void *buf_out, u32 *out_size)
{
	int err;
	struct hinic5_nt_msg nt_msg = {0};

	if (cmd == GET_DRV_VERSION)
		return get_nic_drv_version(buf_out, out_size);
	else if (!uld_dev)
		return -EINVAL;

	nt_msg.buf_in = (void *)buf_in;
	nt_msg.in_size  = in_size;
	nt_msg.buf_out = buf_out;
	nt_msg.out_size  = *out_size;

	err = send_to_nic_driver(uld_dev, cmd, &nt_msg);

	return err;
}
