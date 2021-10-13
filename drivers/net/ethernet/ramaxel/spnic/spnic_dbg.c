// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#define pr_fmt(fmt) KBUILD_MODNAME ": [NIC]" fmt

#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/types.h>
#include <linux/semaphore.h>

#include "sphw_mt.h"
#include "sphw_crm.h"
#include "spnic_nic_dev.h"
#include "spnic_nic_dbg.h"
#include "spnic_nic_qp.h"
#include "spnic_rx.h"
#include "spnic_tx.h"
#include "spnic_dcb.h"

typedef int (*nic_driv_module)(struct spnic_nic_dev *nic_dev, const void *buf_in, u32 in_size,
			       void *buf_out, u32 *out_size);

struct nic_drv_module_handle {
	enum driver_cmd_type	driv_cmd_name;
	nic_driv_module		driv_func;
};

int get_nic_drv_version(void *buf_out, u32 *out_size)
{
	struct drv_version_info *ver_info = buf_out;

	if (!buf_out) {
		pr_err("Buf_out is NULL.\n");
		return -EINVAL;
	}

	if (*out_size != sizeof(*ver_info)) {
		pr_err("Unexpect out buf size from user :%u, expect: %lu\n",
		       *out_size, sizeof(*ver_info));
		return -EINVAL;
	}

	snprintf(ver_info->ver, sizeof(ver_info->ver), "%s  [compiled with the kernel]",
		 SPNIC_DRV_VERSION);

	return 0;
}

static int get_tx_info(struct spnic_nic_dev *nic_dev, const void *buf_in,
		       u32 in_size, void *buf_out, u32 *out_size)
{
	u16 q_id;

	if (!SPHW_CHANNEL_RES_VALID(nic_dev)) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Netdev is down, can't get tx info\n");
		return -EFAULT;
	}

	if (!buf_in || !buf_out) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Buf_in or buf_out is NULL.\n");
		return -EINVAL;
	}

	q_id = *((u16 *)buf_in);

	return spnic_dbg_get_sq_info(nic_dev->hwdev, q_id, buf_out, *out_size);
}

static int get_q_num(struct spnic_nic_dev *nic_dev,
		     const void *buf_in, u32 in_size,
		     void *buf_out, u32 *out_size)
{
	if (!SPHW_CHANNEL_RES_VALID(nic_dev)) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Netdev is down, can't get queue number\n");
		return -EFAULT;
	}

	if (!buf_out) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Get queue number para buf_out is NULL.\n");
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

static int get_tx_wqe_info(struct spnic_nic_dev *nic_dev,
			   const void *buf_in, u32 in_size,
			   void *buf_out, u32 *out_size)
{
	const struct wqe_info *info = buf_in;
	u16 wqebb_cnt = 1;

	if (!SPHW_CHANNEL_RES_VALID(nic_dev)) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Netdev is down, can't get tx wqe info\n");
		return -EFAULT;
	}

	if (!info || !buf_out) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Buf_in or buf_out is NULL.\n");
		return -EINVAL;
	}

	return spnic_dbg_get_wqe_info(nic_dev->hwdev, (u16)info->q_id,
				       (u16)info->wqe_id, wqebb_cnt,
				       buf_out, (u16 *)out_size, SPNIC_SQ);
}

static int get_rx_info(struct spnic_nic_dev *nic_dev, const void *buf_in,
		       u32 in_size, void *buf_out, u32 *out_size)
{
	struct nic_rq_info *rq_info = buf_out;
	u16 q_id;
	int err;

	if (!SPHW_CHANNEL_RES_VALID(nic_dev)) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Netdev is down, can't get rx info\n");
		return -EFAULT;
	}

	if (!buf_in || !buf_out) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Buf_in or buf_out is NULL.\n");
		return -EINVAL;
	}

	q_id = *((u16 *)buf_in);

	err = spnic_dbg_get_rq_info(nic_dev->hwdev, q_id, buf_out, *out_size);

	if (err) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Get rq info failed, ret is %d.\n", err);
		return err;
	}

	rq_info->ci = (u16)nic_dev->rxqs[q_id].cons_idx &
		      nic_dev->rxqs[q_id].q_mask;

	rq_info->sw_pi = nic_dev->rxqs[q_id].next_to_update;
	rq_info->msix_vector = nic_dev->rxqs[q_id].irq_id;

	rq_info->coalesc_timer_cfg = nic_dev->rxqs[q_id].last_coalesc_timer_cfg;
	rq_info->pending_limt = nic_dev->rxqs[q_id].last_pending_limt;

	return 0;
}

static int get_rx_wqe_info(struct spnic_nic_dev *nic_dev, const void *buf_in,
			   u32 in_size, void *buf_out, u32 *out_size)
{
	const struct wqe_info *info = buf_in;
	u16 wqebb_cnt = 1;

	if (!SPHW_CHANNEL_RES_VALID(nic_dev)) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Netdev is down, can't get rx wqe info\n");
		return -EFAULT;
	}

	if (!info || !buf_out) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Buf_in or buf_out is NULL.\n");
		return -EINVAL;
	}

	return spnic_dbg_get_wqe_info(nic_dev->hwdev, (u16)info->q_id,
				       (u16)info->wqe_id, wqebb_cnt,
				       buf_out, (u16 *)out_size, SPNIC_RQ);
}

static int get_rx_cqe_info(struct spnic_nic_dev *nic_dev, const void *buf_in,
			   u32 in_size, void *buf_out, u32 *out_size)
{
	const struct wqe_info *info = buf_in;
	u16 q_id = 0;
	u16 idx = 0;

	if (!SPHW_CHANNEL_RES_VALID(nic_dev)) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Netdev is down, can't get rx cqe info\n");
		return -EFAULT;
	}

	if (!info || !buf_out) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Buf_in or buf_out is NULL.\n");
		return -EINVAL;
	}

	if (*out_size != sizeof(struct spnic_rq_cqe)) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Unexpect out buf size from user :%u, expect: %lu\n",
			  *out_size, sizeof(struct spnic_rq_cqe));
		return -EINVAL;
	}
	q_id = (u16)info->q_id;
	idx = (u16)info->wqe_id;

	if (q_id >= nic_dev->q_params.num_qps ||
	    idx >= nic_dev->rxqs[q_id].q_depth) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Invalid q_id[%u] >= %u, or wqe idx[%u] >= %u.\n",
			  q_id, nic_dev->q_params.num_qps, idx,
			  nic_dev->rxqs[q_id].q_depth);
		return -EFAULT;
	}

	memcpy(buf_out, nic_dev->rxqs[q_id].rx_info[idx].cqe,
	       sizeof(struct spnic_rq_cqe));

	return 0;
}

static void clean_nicdev_stats(struct spnic_nic_dev *nic_dev)
{
	u64_stats_update_begin(&nic_dev->stats.syncp);
	nic_dev->stats.netdev_tx_timeout = 0;
	nic_dev->stats.tx_carrier_off_drop = 0;
	nic_dev->stats.tx_invalid_qid = 0;
	u64_stats_update_end(&nic_dev->stats.syncp);
}

static int clear_func_static(struct spnic_nic_dev *nic_dev, const void *buf_in,
			     u32 in_size, void *buf_out, u32 *out_size)
{
	int i;

	*out_size = 0;
	clean_nicdev_stats(nic_dev);
	for (i = 0; i < nic_dev->max_qps; i++) {
		spnic_rxq_clean_stats(&nic_dev->rxqs[i].rxq_stats);
		spnic_txq_clean_stats(&nic_dev->txqs[i].txq_stats);
	}

	return 0;
}

static int get_loopback_mode(struct spnic_nic_dev *nic_dev, const void *buf_in,
			     u32 in_size, void *buf_out, u32 *out_size)
{
	struct spnic_nic_loop_mode *mode = buf_out;

	if (!out_size || !mode)
		return -EINVAL;

	if (*out_size != sizeof(*mode)) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Unexpect out buf size from user: %u, expect: %lu\n",
			  *out_size, sizeof(*mode));
		return -EINVAL;
	}

	return spnic_get_loopback_mode(nic_dev->hwdev, (u8 *)&mode->loop_mode,
					(u8 *)&mode->loop_ctrl);
}

static int set_loopback_mode(struct spnic_nic_dev *nic_dev, const void *buf_in,
			     u32 in_size, void *buf_out, u32 *out_size)
{
	const struct spnic_nic_loop_mode *mode = buf_in;
	int err;

	if (!test_bit(SPNIC_INTF_UP, &nic_dev->flags)) {
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

	err = spnic_set_loopback_mode(nic_dev->hwdev, (u8)mode->loop_mode, (u8)mode->loop_ctrl);
	if (err == 0)
		nicif_info(nic_dev, drv, nic_dev->netdev, "Set loopback mode %u en %u succeed\n",
			   mode->loop_mode, mode->loop_ctrl);

	return err;
}

enum spnic_nic_link_mode {
	SPNIC_LINK_MODE_AUTO = 0,
	SPNIC_LINK_MODE_UP,
	SPNIC_LINK_MODE_DOWN,
	SPNIC_LINK_MODE_MAX,
};

static int set_link_mode_param_valid(struct spnic_nic_dev *nic_dev,
				     const void *buf_in, u32 in_size,
				     u32 *out_size)
{
	if (!test_bit(SPNIC_INTF_UP, &nic_dev->flags)) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Netdev is down, can't set link mode\n");
		return -EFAULT;
	}

	if (!buf_in || !out_size ||
	    in_size != sizeof(enum spnic_nic_link_mode))
		return -EINVAL;

	if (*out_size != sizeof(enum spnic_nic_link_mode)) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Unexpect out buf size from user: %u, expect: %lu\n",
			  *out_size, sizeof(enum spnic_nic_link_mode));
		return -EINVAL;
	}

	return 0;
}

static int set_link_mode(struct spnic_nic_dev *nic_dev, const void *buf_in,
			 u32 in_size, void *buf_out, u32 *out_size)
{
	const enum spnic_nic_link_mode *link = buf_in;
	u8 link_status;

	if (set_link_mode_param_valid(nic_dev, buf_in, in_size, out_size))
		return -EFAULT;

	switch (*link) {
	case SPNIC_LINK_MODE_AUTO:
		if (spnic_get_link_state(nic_dev->hwdev, &link_status))
			link_status = false;
		spnic_link_status_change(nic_dev, (bool)link_status);
		nicif_info(nic_dev, drv, nic_dev->netdev,
			   "Set link mode: auto succeed, now is link %s\n",
			   (link_status ? "up" : "down"));
		break;
	case SPNIC_LINK_MODE_UP:
		spnic_link_status_change(nic_dev, true);
		nicif_info(nic_dev, drv, nic_dev->netdev,
			   "Set link mode: up succeed\n");
		break;
	case SPNIC_LINK_MODE_DOWN:
		spnic_link_status_change(nic_dev, false);
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

static int get_sset_count(struct spnic_nic_dev *nic_dev, const void *buf_in,
			  u32 in_size, void *buf_out, u32 *out_size)
{
	u32 count;

	if (!buf_in || in_size != sizeof(u32) || !out_size ||
	    *out_size != sizeof(u32) || !buf_out) {
		nicif_err(nic_dev, drv, nic_dev->netdev, "Invalid parameters, in_size: %u\n",
			  in_size);
		return -EINVAL;
	}

	switch (*((u32 *)buf_in)) {
	case SHOW_SSET_IO_STATS:
		count = spnic_get_io_stats_size(nic_dev);
		break;
	default:
		count = 0;
		break;
	}

	*((u32 *)buf_out) = count;

	return 0;
}

static int get_sset_stats(struct spnic_nic_dev *nic_dev, const void *buf_in,
			  u32 in_size, void *buf_out, u32 *out_size)
{
	struct spnic_show_item *items = buf_out;
	u32 sset, count, size;
	int err;

	if (!buf_in || in_size != sizeof(u32) || !out_size || !buf_out) {
		nicif_err(nic_dev, drv, nic_dev->netdev, "Invalid parameters, in_size: %u\n",
			  in_size);
		return -EINVAL;
	}

	size = sizeof(u32);
	err = get_sset_count(nic_dev, buf_in, in_size, &count, &size);
	if (err) {
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
	case SHOW_SSET_IO_STATS:
		spnic_get_io_stats(nic_dev, items);
		break;

	default:
		nicif_err(nic_dev, drv, nic_dev->netdev, "Unknown %u to get stats\n",
			  sset);
		err = -EINVAL;
		break;
	}

	return err;
}

static int dcb_mt_qos_map(struct spnic_nic_dev *nic_dev, const void *buf_in,
			  u32 in_size, void *buf_out, u32 *out_size)
{
	const struct spnic_mt_qos_info *qos = buf_in;
	struct spnic_mt_qos_info *qos_out = buf_out;
	u8 up_cnt, up;
	int err;

	if (!buf_out || !out_size || !buf_in)
		return -EINVAL;

	if (*out_size != sizeof(*qos_out) || in_size != sizeof(*qos)) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Unexpect buf size from user, in_size: %u, out_size: %u, expect: %lu\n",
			  in_size, *out_size, sizeof(*qos));
		return -EINVAL;
	}

	memcpy(qos_out, qos, sizeof(*qos));
	qos_out->head.status = 0;
	if (qos->op_code & MT_DCB_OPCODE_WR) {
		up_cnt = 0;
		for (up = 0; up < SPNIC_DCB_UP_MAX; up++) {
			if (qos->valid_up_bitmap & BIT(up))
				up_cnt++;
		}

		if (up_cnt != nic_dev->wanted_dcb_cfg.max_cos) {
			nicif_err(nic_dev, drv, nic_dev->netdev,
				  "Invalid up bitmap: 0x%x",
				  qos->valid_up_bitmap);
			qos_out->head.status = MT_EINVAL;
			return 0;
		}

		err = spnic_dcbcfg_set_up_bitmap(nic_dev, qos->valid_up_bitmap);
		if (err)
			qos_out->head.status = MT_EIO;
	} else {
		qos_out->valid_up_bitmap =
			spnic_get_valid_up_bitmap(&nic_dev->wanted_dcb_cfg);
		qos_out->valid_cos_bitmap =
			nic_dev->wanted_dcb_cfg.valid_cos_bitmap;
	}

	return 0;
}

static int dcb_mt_dcb_state(struct spnic_nic_dev *nic_dev, const void *buf_in,
			    u32 in_size, void *buf_out, u32 *out_size)
{
	const struct spnic_mt_dcb_state *dcb = buf_in;
	struct spnic_mt_dcb_state *dcb_out = buf_out;
	int err;

	if (!buf_in || !buf_out || !out_size)
		return -EINVAL;

	if (*out_size != sizeof(*dcb_out) || in_size != sizeof(*dcb)) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Unexpect buf size from user, in_size: %u, out_size: %u, expect: %lu\n",
			  in_size, *out_size, sizeof(*dcb));
		return -EINVAL;
	}

	memcpy(dcb_out, dcb, sizeof(*dcb));
	dcb_out->head.status = 0;
	if (dcb->op_code & MT_DCB_OPCODE_WR) {
		if (test_bit(SPNIC_DCB_ENABLE, &nic_dev->flags) == dcb->state)
			return 0;

		/* nic_mutex has been acquired by send_to_nic_driver and will
		 * also be acquired inside spnic_setup_tc
		 */
		mutex_unlock(&nic_dev->nic_mutex);
		rtnl_lock();
		err = spnic_setup_tc(nic_dev->netdev,
				     dcb->state ? nic_dev->wanted_dcb_cfg.max_cos : 0);
		rtnl_unlock();
		mutex_lock(&nic_dev->nic_mutex);
		if (err)
			dcb_out->head.status = MT_EIO;
	} else {
		dcb_out->state = !!test_bit(SPNIC_DCB_ENABLE, &nic_dev->flags);
	}

	return 0;
}

static int dcb_mt_pfc_state(struct spnic_nic_dev *nic_dev, const void *buf_in,
			    u32 in_size, void *buf_out, u32 *out_size)
{
	const struct spnic_mt_pfc_state *pfc = buf_in;
	struct spnic_mt_pfc_state *pfc_out = buf_out;
	u8 cur_pfc_state, cur_pfc_en_bitmap;
	int err;

	if (!buf_in || !buf_out || !out_size)
		return -EINVAL;

	if (*out_size != sizeof(*pfc_out) || in_size != sizeof(*pfc)) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Unexpect buf size from user, in_size: %u, out_size: %u, expect: %lu\n",
			  in_size, *out_size, sizeof(*pfc));
		return -EINVAL;
	}

	cur_pfc_state = spnic_dcbcfg_get_pfc_state(nic_dev);
	cur_pfc_en_bitmap = spnic_dcbcfg_get_pfc_pri_en(nic_dev);

	memcpy(pfc_out, pfc, sizeof(*pfc));
	pfc_out->head.status = 0;
	if (pfc->op_code & MT_DCB_OPCODE_WR) {
		if (pfc->op_code & MT_DCB_PFC_PFC_STATE)
			spnic_dcbcfg_set_pfc_state(nic_dev, pfc->state);

		if (pfc->op_code & MT_DCB_PFC_PFC_PRI_EN)
			spnic_dcbcfg_set_pfc_pri_en(nic_dev, pfc->pfc_en_bitpamp);

		if (test_bit(SPNIC_DCB_ENABLE, &nic_dev->flags)) {
			err = spnic_configure_dcb(nic_dev->netdev);
			if (err) {
				pfc_out->head.status = MT_EIO;
				goto set_err;
			}
		}
	} else {
		pfc_out->state = cur_pfc_state;
		pfc_out->pfc_en_bitpamp = cur_pfc_en_bitmap;
	}

	return 0;

set_err:
	spnic_dcbcfg_set_pfc_state(nic_dev, cur_pfc_state);
	spnic_dcbcfg_set_pfc_pri_en(nic_dev, cur_pfc_en_bitmap);
	if (test_bit(SPNIC_DCB_ENABLE, &nic_dev->flags)) {
		err = spnic_configure_dcb(nic_dev->netdev);
		if (err)
			nicif_warn(nic_dev, drv, nic_dev->netdev,
				   "Failed to rollback pfc config\n");
	}
	return 0;
}

static int dcb_mt_ets_state(struct spnic_nic_dev *nic_dev, const void *buf_in,
			    u32 in_size, void *buf_out, u32 *out_size)
{
	const struct spnic_mt_ets_state *ets = buf_in;
	struct spnic_mt_ets_state *ets_out = buf_out;
	struct spnic_dcb_config dcb_cfg_backup;
	int err;

	if (!buf_in || !buf_out || !out_size)
		return -EINVAL;

	if (*out_size != sizeof(*ets_out) || in_size != sizeof(*ets)) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Unexpect buf size from user, in_size: %u, out_size: %u, expect: %lu\n",
			  in_size, *out_size, sizeof(*ets));
		return -EINVAL;
	}

	memcpy(ets_out, ets, sizeof(*ets));
	ets_out->head.status = 0;
	if (ets->op_code & MT_DCB_OPCODE_WR) {
		if (ets->op_code & (MT_DCB_ETS_UP_BW | MT_DCB_ETS_UP_PRIO)) {
			nicif_err(nic_dev, drv, nic_dev->netdev, "Not support to set up bw and up prio\n");
			ets_out->head.status = MT_EOPNOTSUPP;
			return 0;
		}

		dcb_cfg_backup = nic_dev->wanted_dcb_cfg;

		if (ets->op_code & MT_DCB_ETS_UP_TC) {
			err = spnic_dcbcfg_set_ets_up_tc_map(nic_dev, ets->up_tc);
			if (err) {
				ets_out->head.status = MT_EIO;
				return 0;
			}
		}
		if (ets->op_code & MT_DCB_ETS_TC_BW) {
			err = spnic_dcbcfg_set_ets_tc_bw(nic_dev, ets->tc_bw);
			if (err) {
				ets_out->head.status = MT_EIO;
				goto set_err;
			}
		}
		if (ets->op_code & MT_DCB_ETS_TC_PRIO)
			spnic_dcbcfg_set_ets_tc_prio_type(nic_dev, ets->tc_prio_bitmap);

		if (test_bit(SPNIC_DCB_ENABLE, &nic_dev->flags)) {
			err = spnic_configure_dcb(nic_dev->netdev);
			if (err) {
				ets_out->head.status = MT_EIO;
				goto set_err;
			}
		}
	} else {
		spnic_dcbcfg_get_ets_up_tc_map(nic_dev, ets_out->up_tc);
		spnic_dcbcfg_get_ets_tc_bw(nic_dev, ets_out->tc_bw);
		spnic_dcbcfg_get_ets_tc_prio_type(nic_dev, &ets_out->tc_prio_bitmap);
	}

	return 0;

set_err:
	nic_dev->wanted_dcb_cfg = dcb_cfg_backup;
	if (test_bit(SPNIC_DCB_ENABLE, &nic_dev->flags)) {
		err = spnic_configure_dcb(nic_dev->netdev);
		if (err)
			nicif_warn(nic_dev, drv, nic_dev->netdev,
				   "Failed to rollback ets config\n");
	}

	return 0;
}

static int get_inter_num(struct spnic_nic_dev *nic_dev, const void *buf_in,
			 u32 in_size, void *buf_out, u32 *out_size)
{
	u16 intr_num;

	intr_num = sphw_intr_num(nic_dev->hwdev);

	if (*out_size != sizeof(u16)) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Unexpect out buf size from user :%u, expect: %lu\n",
			  *out_size, sizeof(u16));
		return -EFAULT;
	}
	*(u16 *)buf_out = intr_num;

	*out_size = sizeof(u16);

	return 0;
}

static int get_netdev_name(struct spnic_nic_dev *nic_dev, const void *buf_in,
			   u32 in_size, void *buf_out, u32 *out_size)
{
	if (*out_size != IFNAMSIZ) {
		nicif_err(nic_dev, drv, nic_dev->netdev,
			  "Unexpect out buf size from user :%u, expect: %u\n",
			  *out_size, IFNAMSIZ);
		return -EFAULT;
	}

	strlcpy(buf_out, nic_dev->netdev->name, IFNAMSIZ);

	return 0;
}

struct nic_drv_module_handle nic_driv_module_cmd_handle[] = {
	{TX_INFO,		get_tx_info},
	{Q_NUM,			get_q_num},
	{TX_WQE_INFO,		get_tx_wqe_info},
	{RX_INFO,		get_rx_info},
	{RX_WQE_INFO,		get_rx_wqe_info},
	{RX_CQE_INFO,		get_rx_cqe_info},
	{GET_INTER_NUM,		get_inter_num},
	{CLEAR_FUNC_STASTIC,	clear_func_static},
	{GET_LOOPBACK_MODE,	get_loopback_mode},
	{SET_LOOPBACK_MODE,	set_loopback_mode},
	{SET_LINK_MODE,		set_link_mode},
	{GET_SSET_COUNT,	get_sset_count},
	{GET_SSET_ITEMS,	get_sset_stats},
	{DCB_QOS_INFO,		dcb_mt_qos_map},
	{DCB_STATE,		dcb_mt_dcb_state},
	{DCB_PFC_STATE,		dcb_mt_pfc_state},
	{DCB_ETS_STATE,		dcb_mt_ets_state},
	{GET_ULD_DEV_NAME,	get_netdev_name},
};

static int send_to_nic_driver(struct spnic_nic_dev *nic_dev,
			      u32 cmd, const void *buf_in,
			      u32 in_size, void *buf_out, u32 *out_size)
{
	int index, num_cmds = sizeof(nic_driv_module_cmd_handle) /
				sizeof(nic_driv_module_cmd_handle[0]);
	enum driver_cmd_type cmd_type = (enum driver_cmd_type)cmd;
	int err = 0;

	mutex_lock(&nic_dev->nic_mutex);
	for (index = 0; index < num_cmds; index++) {
		if (cmd_type ==
			nic_driv_module_cmd_handle[index].driv_cmd_name) {
			err = nic_driv_module_cmd_handle[index].driv_func
					(nic_dev, buf_in,
					 in_size, buf_out, out_size);
			break;
		}
	}
	mutex_unlock(&nic_dev->nic_mutex);

	if (index == num_cmds)
		pr_err("Can't find callback for %d\n", cmd_type);

	return err;
}

int nic_ioctl(void *uld_dev, u32 cmd, const void *buf_in,
	      u32 in_size, void *buf_out, u32 *out_size)
{
	if (cmd == GET_DRV_VERSION)
		return get_nic_drv_version(buf_out, out_size);
	else if (!uld_dev)
		return -EINVAL;

	return send_to_nic_driver(uld_dev, cmd, buf_in,
				  in_size, buf_out, out_size);
}
