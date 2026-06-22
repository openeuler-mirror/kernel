// SPDX-License-Identifier: GPL-2.0+
/* Copyright(c) 2025 HiSilicon Technologies CO., Ltd. All rights reserved. */

#define dev_fmt(fmt) "UDMA: " fmt
#define pr_fmt(fmt) "UDMA: " fmt

#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/random.h>
#include <ub/urma/ubcore_uapi.h>
#include "udma_dev.h"
#include <uapi/ub/urma/udma/udma_abi.h>
#include "udma_cmd.h"
#include "udma_jfr.h"
#include "udma_jfs.h"
#include "udma_jfc.h"
#include "udma_jetty.h"
#include "udma_jetty_group.h"


const char *state_name[] = {
	"RESET",
	"READY",
	"SUSPENDED",
	"ERROR",
	"INVALID"
};

const char *to_state_name(enum ubcore_jetty_state state)
{
	if ((int)state >= (int)STATE_NUM)
		return state_name[STATE_NUM];

	return state_name[state];
}

bool is_support_ccu_jetty(struct udma_dev *dev, struct udma_jetty_queue *sq)
{
	if (!dev->caps.lock_buffer_en)
		return false;

	if (!CFGID_CHECK(sq->id, dev->caps.ccu_jetty))
		return false;

	if (!sq->is_jetty)
		return false;

	if (sq->jetty_type == UDMA_LOCK_BUFFER_JETTY_TYPE ||
	    sq->jetty_type == UDMA_URMA_EX_JETTY_TYPE || sq->jetty_type == UDMA_CCU_JETTY_TYPE)
		return true;

	return false;
}

static int udma_get_user_jetty_cmd(struct udma_dev *dev, struct udma_jetty *jetty,
				   struct ubcore_udata *udata,
				   struct udma_create_jetty_ucmd *ucmd)
{
	struct udma_context *uctx;
	unsigned long byte;

	if (!udata) {
		jetty->sq.jetty_type = (enum udma_jetty_type)UDMA_URMA_NORMAL_JETTY_TYPE;
		return 0;
	}

	if (!udata->udrv_data) {
		dev_err(dev->dev, "jetty user data, user driver data is null.\n");
		return -EINVAL;
	}

	if (!udata->udrv_data->in_addr || udata->udrv_data->in_len < sizeof(*ucmd)) {
		dev_err(dev->dev, "jetty input length(%u) or address is invalid.\n",
			udata->udrv_data->in_len);
		return -EINVAL;
	}

	byte = copy_from_user(ucmd, (void *)(uintptr_t)udata->udrv_data->in_addr,
			      sizeof(*ucmd));
	if (byte) {
		dev_err(dev->dev,
			"failed to copy jetty udata, byte = %lu.\n", byte);
		return -EFAULT;
	}

	uctx = to_udma_context(udata->uctx);
	jetty->sq.udma_ctx = uctx;
	jetty->sq.tid = uctx->tid;
	jetty->jetty_addr = ucmd->jetty_addr;
	jetty->sq.pi_type = ucmd->pi_type;
	jetty->sq.jetty_type = (enum udma_jetty_type)ucmd->jetty_type;
	jetty->sq.non_pin = ucmd->non_pin;

	return 0;
}

static int udma_get_jetty_buf(struct udma_dev *dev, struct udma_jetty *jetty,
			      struct ubcore_udata *udata,
			      struct ubcore_jetty_cfg *cfg,
			      struct udma_create_jetty_ucmd *ucmd)
{
	struct ubcore_jfs_cfg jfs_cfg = {
		.depth = cfg->jfs_depth,
		.trans_mode = cfg->trans_mode,
		.priority = cfg->priority,
		.max_sge = cfg->max_send_sge,
		.max_rsge = cfg->max_send_rsge,
		.max_inline_data = cfg->max_inline_data,
		.rnr_retry = cfg->rnr_retry,
		.err_timeout = cfg->err_timeout,
		.jfs_context = cfg->jetty_context,
		.jfc = cfg->send_jfc,
	};
	int ret;

	jfs_cfg.flag.bs.lock_free = cfg->flag.bs.lock_free;
	if (!udata)
		jetty->jetty_addr = (uintptr_t)&jetty->sq;

	jetty->jfr = to_udma_jfr(cfg->jfr);
	jetty->sq.is_jetty = true;

	ret = udata ? udma_alloc_u_sq_buf(dev, &jetty->sq, ucmd) :
		udma_alloc_k_sq_buf(dev, &jetty->sq, &jfs_cfg);
	if (ret) {
		dev_err(dev->dev, "failed to get SQ buffer, ret = %d.\n", ret);
		return ret;
	}
	jetty->sq.trans_mode = jfs_cfg.trans_mode;

	return ret;
}

static void udma_init_jettyc(struct udma_dev *dev, struct ubcore_jetty_cfg *cfg,
			     struct udma_jetty *jetty, void *mb_buf)
{
	struct udma_jetty_ctx *ctx = (struct udma_jetty_ctx *)mb_buf;
	struct udma_jfc *receive_jfc = to_udma_jfc(cfg->recv_jfc);
	uint8_t i;

	ctx->state = JETTY_READY;
	ctx->jfs_mode = JETTY;
	ctx->type = to_udma_type(cfg->trans_mode, cfg->flag.bs.order_type);
	ctx->sl = dev->udma_sl[UDMA_DEFAULT_SL_NUM];
	if (ctx->type == JETTY_RM || ctx->type == JETTY_RC) {
		ctx->sl = dev->priority_info[cfg->priority].SL;
	} else if (ctx->type == JETTY_UM) {
		ctx->sl = dev->unic_sl[UDMA_DEFAULT_SL_NUM];
		for (i = 0; i < dev->unic_sl_num; i++) {
			if (cfg->priority == dev->unic_sl[i]) {
				ctx->sl = cfg->priority;
				break;
			}
		}
	}
	ctx->sqe_base_addr_l = (jetty->sq.buf.addr >> SQE_VA_L_OFFSET) &
			       (uint32_t)SQE_VA_L_VALID_BIT;
	ctx->sqe_base_addr_h = (jetty->sq.buf.addr >> SQE_VA_H_OFFSET) &
			       (uint32_t)SQE_VA_H_VALID_BIT;
	ctx->sqe_token_id_l = jetty->sq.tid & (uint32_t)SQE_TOKEN_ID_L_MASK;
	ctx->sqe_token_id_h = (jetty->sq.tid >> SQE_TOKEN_ID_H_OFFSET) &
			      (uint32_t)SQE_TOKEN_ID_H_MASK;
	ctx->sqe_bb_shift = ilog2(roundup_pow_of_two(jetty->sq.buf.entry_cnt));
	ctx->tx_jfcn = cfg->send_jfc->id;
	ctx->ta_timeout = udma_get_ta_timeout_gear(dev, cfg->err_timeout);

	if (!!(dev->caps.feature & UDMA_CAP_FEATURE_RNR_RETRY))
		ctx->rnr_retry_num = cfg->rnr_retry;

	ctx->jfrn_l = jetty->jfr->rq.id;
	ctx->jfrn_h = jetty->jfr->rq.id >> JETTY_CTX_JFRN_H_OFFSET;
	ctx->rx_jfcn = cfg->recv_jfc->id;
	ctx->user_data_l = jetty->jetty_addr;
	ctx->user_data_h = jetty->jetty_addr >> UDMA_USER_DATA_H_OFFSET;
	ctx->seid_idx = cfg->eid_index;
	ctx->pi_type = jetty->sq.pi_type ? 1 : 0;

	if (!!(dev->caps.feature & UDMA_CAP_FEATURE_JFC_INLINE))
		ctx->cqe_ie = receive_jfc->inline_en;

	ctx->err_mode = cfg->flag.bs.error_suspend;
	ctx->cmp_odr = cfg->flag.bs.outorder_comp;
	ctx->avail_sgmt_ost = AVAIL_SGMT_OST_INIT;
	ctx->sqe_pld_tokenid = jetty->sq.tid & (uint32_t)SQE_PLD_TOKEN_ID_MASK;
	ctx->next_send_ssn = get_random_u16();
	ctx->next_rcv_ssn = ctx->next_send_ssn;
	ctx->wqe_lock_buffer_en = is_support_ccu_jetty(dev, &jetty->sq);

	if (!!(dev->caps.feature & UDMA_CAP_FEATURE_RC_CTP_MULTIPLE_PATH_MODE))
		ctx->ctp_rc_mul_path_mode = cfg->flag.bs.ctp_rc_mul_path_mode;
}

static int udma_specify_rsvd_jetty_id(struct udma_dev *udma_dev, uint32_t cfg_id)
{
	struct udma_ida *ida_table = &udma_dev->rsvd_jetty_ida_table;
	int id;

	id = ida_alloc_range(&ida_table->ida, cfg_id, cfg_id, GFP_KERNEL);
	if (id < 0) {
		dev_err(udma_dev->dev, "user specified id %u has been used, ret=%d.\n", cfg_id, id);
		return id;
	}

	return 0;
}

static int udma_user_specify_jetty_id(struct udma_dev *udma_dev, uint32_t cfg_id)
{
	if (cfg_id < udma_dev->caps.jetty.start_idx)
		return udma_specify_rsvd_jetty_id(udma_dev, cfg_id);

	return udma_specify_adv_id(udma_dev, &udma_dev->jetty_table.bitmap_table,
				   cfg_id);
}

int udma_alloc_jetty_id(struct udma_dev *udma_dev, uint32_t *idx,
			struct udma_res *jetty_res)
{
	struct udma_group_bitmap *bitmap = &udma_dev->jetty_table.bitmap_table;
	struct ida *ida = &udma_dev->rsvd_jetty_ida_table.ida;
	uint32_t min = jetty_res->start_idx;
	uint32_t next = jetty_res->next_idx;
	uint32_t max;
	int ret;

	if (jetty_res->max_cnt == 0)
		return -EINVAL;

	max = jetty_res->start_idx + jetty_res->max_cnt - 1;
	if (jetty_res != &udma_dev->caps.jetty) {
		ret = ida_alloc_range(ida, next, max, GFP_KERNEL);
		if (ret < 0) {
			ret = ida_alloc_range(ida, min, max, GFP_KERNEL);
			if (ret < 0)
				return ret == -ENOSPC ? -ENOSR : ret;
		}

		*idx = (uint32_t)ret;
	} else {
		ret = udma_adv_id_alloc(udma_dev, bitmap, idx, false, next);
		if (ret) {
			ret = udma_adv_id_alloc(udma_dev, bitmap, idx, false, min);
			if (ret)
				return ret;
		}
	}

	jetty_res->next_idx = (*idx + 1) > max ? min : (*idx + 1);

	return 0;
}

static int udma_alloc_normal_jetty_id(struct udma_dev *udma_dev, uint32_t *idx)
{
	int ret;

	ret = udma_alloc_jetty_id(udma_dev, idx, &udma_dev->caps.jetty);
	if (ret == 0)
		return 0;

	ret = udma_alloc_jetty_id(udma_dev, idx, &udma_dev->caps.user_ctrl_normal_jetty);
	if (ret == 0)
		return 0;

	ret = udma_alloc_jetty_id(udma_dev, idx, &udma_dev->caps.public_jetty);
	if (ret == 0)
		return 0;

	dev_err(udma_dev->dev, "udma alloc jetty id failed, ret = %d.\n", ret);

	return ret;
}

static int udma_verify_jetty_type_dwqe(struct udma_dev *udma_dev,
				       uint32_t cfg_id)
{
	if (!CFGID_CHECK(cfg_id, udma_dev->caps.stars_jetty)) {
		dev_err(udma_dev->dev,
			"user id %u error, cache lock start index %u count %u.\n",
			cfg_id, udma_dev->caps.stars_jetty.start_idx,
			udma_dev->caps.stars_jetty.max_cnt);
		return -EINVAL;
	}

	return 0;
}

static int udma_verify_jetty_type_ccu(struct udma_dev *udma_dev,
				      uint32_t cfg_id)
{
	if (!CFGID_CHECK(cfg_id, udma_dev->caps.ccu_jetty)) {
		dev_err(udma_dev->dev, "user id %u error, CCU start index %u count %u.\n",
			cfg_id, udma_dev->caps.ccu_jetty.start_idx,
			udma_dev->caps.ccu_jetty.max_cnt);
		return -EINVAL;
	}

	return 0;
}

static int udma_verify_jetty_type_lock_buffer(struct udma_dev *udma_dev, uint32_t cfg_id)
{
	if (!CFGID_CHECK(cfg_id, udma_dev->caps.ccu_jetty)) {
		dev_err(udma_dev->dev, "user id %u error, lock buffer start index %u count %u.\n",
			cfg_id, udma_dev->caps.ccu_jetty.start_idx,
			udma_dev->caps.ccu_jetty.max_cnt);
		return -EINVAL;
	}

	return 0;
}

static int udma_verify_jetty_type_normal(struct udma_dev *udma_dev,
					 uint32_t cfg_id)
{
	if (!CFGID_CHECK(cfg_id, udma_dev->caps.user_ctrl_normal_jetty)) {
		dev_err(udma_dev->dev,
			"user id %u error, user ctrl normal state index %u count %u.\n",
			cfg_id,
			udma_dev->caps.user_ctrl_normal_jetty.start_idx,
			udma_dev->caps.user_ctrl_normal_jetty.max_cnt);
		return -EINVAL;
	}

	return 0;
}

static int udma_verify_jetty_type_urma_normal(struct udma_dev *udma_dev,
					      uint32_t cfg_id)
{
	if (!(CFGID_CHECK(cfg_id, udma_dev->caps.public_jetty) ||
		CFGID_CHECK(cfg_id, udma_dev->caps.hdc_jetty) ||
CFGID_CHECK(cfg_id, udma_dev->caps.jetty))) {
		dev_err(udma_dev->dev,
			"user id %u error, CCU start IDX %u cnt %u, stars IDX %u, normal IDX %u cnt %u.\n",
			cfg_id, udma_dev->caps.ccu_jetty.start_idx,
			udma_dev->caps.ccu_jetty.max_cnt,
			udma_dev->caps.stars_jetty.start_idx,
			udma_dev->caps.jetty.start_idx,
			udma_dev->caps.jetty.max_cnt);
		return -EINVAL;
	}

	return 0;
}

static int udma_verify_jetty_type_urma_ex(struct udma_dev *udma_dev, uint32_t cfg_id)
{
	if (!(CFGID_CHECK(cfg_id, udma_dev->caps.public_jetty) ||
		CFGID_CHECK(cfg_id, udma_dev->caps.hdc_jetty) ||
		CFGID_CHECK(cfg_id, udma_dev->caps.ccu_jetty) ||
		CFGID_CHECK(cfg_id, udma_dev->caps.stars_jetty) ||
		CFGID_CHECK(cfg_id, udma_dev->caps.user_ctrl_normal_jetty) ||
		CFGID_CHECK(cfg_id, udma_dev->caps.jetty))) {
		dev_err(udma_dev->dev, "user id %u error, jetty id from %u to %u is not belong to udma.\n",
			cfg_id, udma_dev->caps.user_ctrl_normal_jetty.start_idx +
			udma_dev->caps.user_ctrl_normal_jetty.max_cnt,
			udma_dev->caps.jetty.start_idx - 1);
		return -EINVAL;
	}

	return 0;
}

static int udma_verify_jetty_type(struct udma_dev *udma_dev, enum udma_jetty_type jetty_type,
				  uint32_t cfg_id)
{
	int (*udma_cfg_id_check[UDMA_JETTY_TYPE_MAX])(struct udma_dev *udma_dev,
						      uint32_t cfg_id) = {
		udma_verify_jetty_type_dwqe,
		udma_verify_jetty_type_ccu,
		udma_verify_jetty_type_normal,
		udma_verify_jetty_type_urma_normal,
		udma_verify_jetty_type_lock_buffer,
		udma_verify_jetty_type_urma_ex
	};

	if (jetty_type < UDMA_JETTY_TYPE_MAX) {
		if (!cfg_id)
			return 0;

		return udma_cfg_id_check[jetty_type](udma_dev, cfg_id);
	}

	dev_err(udma_dev->dev, "invalid jetty type 0x%x.\n", jetty_type);
	return -EINVAL;
}

static int udma_alloc_jetty_id_own(struct udma_dev *udma_dev, uint32_t *id,
				   enum udma_jetty_type jetty_type)
{
	int ret;

	switch (jetty_type) {
	case UDMA_CACHE_LOCK_DWQE_JETTY_TYPE:
		ret = udma_alloc_jetty_id(udma_dev, id,
			&udma_dev->caps.stars_jetty);
		break;
	case UDMA_NORMAL_JETTY_TYPE:
		ret = udma_alloc_jetty_id(udma_dev, id,
			&udma_dev->caps.user_ctrl_normal_jetty);
		break;
	case UDMA_CCU_JETTY_TYPE:
		ret = udma_alloc_jetty_id(udma_dev, id, &udma_dev->caps.ccu_jetty);
		break;
	case UDMA_LOCK_BUFFER_JETTY_TYPE:
		ret = udma_alloc_jetty_id(udma_dev, id, &udma_dev->caps.ccu_jetty);
		break;
	default:
		ret = udma_alloc_normal_jetty_id(udma_dev, id);
		break;
	}

	if (ret)
		dev_err(udma_dev->dev,
			"udma alloc jetty id own failed, type = %d, ret = %d.\n",
			jetty_type, ret);

	return ret;
}

int alloc_jetty_id(struct udma_dev *udma_dev, struct udma_jetty_queue *sq,
		   uint32_t cfg_id, struct ubcore_jetty_group *jetty_grp)
{
	int ret;

	if (udma_verify_jetty_type(udma_dev, sq->jetty_type, cfg_id))
		return -EINVAL;

	if (cfg_id > 0 && !jetty_grp) {
		ret = udma_user_specify_jetty_id(udma_dev, cfg_id);
		if (ret)
			return ret;

		sq->id = cfg_id;
	} else if (jetty_grp) {
		ret = add_jetty_to_grp(udma_dev, jetty_grp, sq, cfg_id);
		if (ret) {
			dev_err(udma_dev->dev,
				"add jetty to grp failed, ret = %d.\n", ret);
			return ret;
		}
	} else {
		ret = udma_alloc_jetty_id_own(udma_dev, &sq->id, sq->jetty_type);
	}

	return ret;
}

void free_jetty_id(struct udma_dev *udma_dev,
			  struct udma_jetty *udma_jetty, bool is_grp)
{
	if (udma_jetty->sq.id < udma_dev->caps.jetty.start_idx)
		udma_id_free(&udma_dev->rsvd_jetty_ida_table, udma_jetty->sq.id);
	else if (is_grp)
		remove_jetty_from_grp(udma_dev, udma_jetty);
	else
		udma_adv_id_free(&udma_dev->jetty_table.bitmap_table,
				 udma_jetty->sq.id, false);
}

static void udma_dfx_store_jetty_id(struct udma_dev *udma_dev,
				    struct udma_jetty *udma_jetty)
{
	struct udma_dfx_jetty *jetty;
	int ret;

	jetty = (struct udma_dfx_jetty *)xa_load(&udma_dev->dfx_info->jetty.table,
						 udma_jetty->sq.id);
	if (jetty) {
		dev_warn(udma_dev->dev, "jetty id(%u) already exists in dfx.\n",
			 udma_jetty->sq.id);
		return;
	}

	jetty = kzalloc(sizeof(*jetty), GFP_KERNEL);
	if (!jetty)
		return;

	jetty->id = udma_jetty->sq.id;
	jetty->jfs_depth = udma_jetty->sq.buf.entry_cnt / udma_jetty->sq.sqe_bb_cnt;

	write_lock(&udma_dev->dfx_info->jetty.rwlock);
	ret = xa_err(xa_store(&udma_dev->dfx_info->jetty.table, udma_jetty->sq.id,
			      jetty, GFP_ATOMIC));
	if (ret) {
		write_unlock(&udma_dev->dfx_info->jetty.rwlock);
		dev_err(udma_dev->dev, "store jetty_id(%u) to jetty_table failed in dfx.\n",
			udma_jetty->sq.id);
		kfree(jetty);
		return;
	}

	++udma_dev->dfx_info->jetty.cnt;
	write_unlock(&udma_dev->dfx_info->jetty.rwlock);
}

void udma_free_lock_buffer_sq_buf(struct udma_dev *udma_dev, struct udma_jetty *udma_jetty)
{
	if (udma_jetty->sq.buf.kva)
		udma_jetty->sq.buf.kva = NULL;
	udma_jetty->sq.buf.addr = 0;

	kfree(udma_jetty->sq.wrid);
	udma_jetty->sq.wrid = NULL;
}

static int udma_get_from_user_lock_buffer_sq_buf(struct udma_dev *dev,
						 struct udma_jetty_queue *sq,
						 struct udma_create_jetty_ucmd *ucmd)
{
	if (ucmd->sqe_bb_cnt == 0 || ucmd->buf_len == 0) {
		dev_err(dev->dev, "invalid param, sqe_bb_cnt=%u, buf_len=%u.\n",
			ucmd->sqe_bb_cnt, ucmd->buf_len);
		return -EINVAL;
	}
	sq->sqe_bb_cnt = ucmd->sqe_bb_cnt;
	sq->buf.addr = (ucmd->buf_addr << SQE_VA_L_OFFSET);
	sq->buf.entry_cnt = ucmd->buf_len >> WQE_BB_SIZE_SHIFT;

	return 0;
}

static int udma_get_user_lock_buffer_jetty_buf(struct udma_dev *dev,
					       struct udma_jetty *jetty,
					       struct ubcore_jetty_cfg *cfg,
					       struct udma_create_jetty_ucmd *ucmd)
{
	int ret;

	jetty->jfr = to_udma_jfr(cfg->jfr);
	jetty->sq.is_jetty = true;

	ret = udma_get_from_user_lock_buffer_sq_buf(dev, &jetty->sq, ucmd);
	if (ret) {
		dev_err(dev->dev,
			"failed to get SQ buffer in jfs process, ret = %d.\n", ret);
		return ret;
	}

	jetty->sq.trans_mode = cfg->trans_mode;

	return ret;
}

static int udma_jetty_copy_resp(struct udma_dev *dev, struct udma_jetty *jetty,
				struct ubcore_udata *udata)
{
	struct udma_create_jetty_resp resp = {};
	unsigned long byte;

	if (udma_check_base_param(udata->udrv_data->out_addr, udata->udrv_data->out_len,
	    sizeof(resp))) {
		dev_err(dev->dev, "invalid output address or output length=%u.\n",
			udata->udrv_data->out_len);
		return -EINVAL;
	}
	if (jetty->sq.dtu_en ||
	    (!jetty->sq.non_pin && dev->sq_reserved_info.sq_reserved))
		resp.buf_addr = jetty->sq.buf.addr;

	byte = copy_to_user((void *)(uintptr_t)udata->udrv_data->out_addr, &resp, sizeof(resp));
	if (byte) {
		dev_err(dev->dev, "failed to copy to user, ret=%lu.\n", byte);
		return -EFAULT;
	}

	return 0;
}

static void udma_set_k_jetty_type(struct udma_dev *udma_dev, struct udma_jetty *jetty,
				  struct ubcore_jetty_cfg *cfg, struct ubcore_udata *udata)
{
	if (udata || !cfg->id)
		return;

	if (CFGID_CHECK(cfg->id, udma_dev->caps.ccu_jetty)) {
		jetty->sq.jetty_type = UDMA_CCU_JETTY_TYPE;
		return;
	}

	if (CFGID_CHECK(cfg->id, udma_dev->caps.stars_jetty)) {
		jetty->sq.jetty_type = UDMA_CACHE_LOCK_DWQE_JETTY_TYPE;
		return;
	}

	if (CFGID_CHECK(cfg->id, udma_dev->caps.user_ctrl_normal_jetty)) {
		jetty->sq.jetty_type = UDMA_NORMAL_JETTY_TYPE;
		return;
	}

	if (CFGID_CHECK(cfg->id, udma_dev->caps.public_jetty) ||
	    CFGID_CHECK(cfg->id, udma_dev->caps.hdc_jetty) ||
	    CFGID_CHECK(cfg->id, udma_dev->caps.jetty)) {
		jetty->sq.jetty_type = UDMA_URMA_NORMAL_JETTY_TYPE;
		return;
	}
}

static int
udma_alloc_jetty_sq(struct udma_dev *udma_dev, struct udma_jetty *jetty,
		    struct ubcore_jetty_cfg *cfg, struct ubcore_udata *udata)
{
	struct udma_create_jetty_ucmd ucmd = {};
	int ret;

	ret = udma_get_user_jetty_cmd(udma_dev, jetty, udata, &ucmd);
	if (ret) {
		dev_err(udma_dev->dev,
			"udma get user jetty ucmd failed, ret = %d.\n", ret);
		return ret;
	}

	udma_set_k_jetty_type(udma_dev, jetty, cfg, udata);

	ret = alloc_jetty_id(udma_dev, &jetty->sq, cfg->id, cfg->jetty_grp);
	if (ret) {
		dev_err(udma_dev->dev, "alloc jetty id failed, ret = %d.\n", ret);
		return ret;
	}
	jetty->ubcore_jetty.jetty_id.id = jetty->sq.id;
	jetty->ubcore_jetty.jetty_cfg = *cfg;

	if (jetty->sq.jetty_type == UDMA_LOCK_BUFFER_JETTY_TYPE) {
		ret = udma_get_user_lock_buffer_jetty_buf(udma_dev, jetty, cfg, &ucmd);
		if (ret)
			goto err_get_jetty_buf;
		return ret;
	} else {
		ret = udma_get_jetty_buf(udma_dev, jetty, udata, cfg, &ucmd);
	}
	if (ret)
		goto err_get_jetty_buf;

	if (udata) {
		ret = udma_jetty_copy_resp(udma_dev, jetty, udata);
		if (ret)
			goto err_copy_resp;
	}

	return ret;

err_copy_resp:
	udma_free_sq_buf(udma_dev, &jetty->sq);
err_get_jetty_buf:
	free_jetty_id(udma_dev, jetty, !!cfg->jetty_grp);

	return ret;
}

static void udma_free_jetty_id_buf(struct udma_dev *udma_dev,
				   struct udma_jetty *udma_jetty,
				   struct ubcore_jetty_cfg *cfg)
{
	if (udma_jetty->sq.jetty_type == UDMA_LOCK_BUFFER_JETTY_TYPE)
		udma_free_lock_buffer_sq_buf(udma_dev, udma_jetty);
	else
		udma_free_sq_buf(udma_dev, &udma_jetty->sq);
	free_jetty_id(udma_dev, udma_jetty, !!cfg->jetty_grp);
}

void udma_reset_sw_k_jetty_queue(struct udma_jetty_queue *sq)
{
	sq->kva_curr = sq->buf.kva;
	sq->pi = 0;
	sq->ci = 0;
	sq->flush_flag = false;
}

static int udma_create_hw_jetty_ctx(struct udma_dev *dev, struct udma_jetty *udma_jetty,
				    struct ubcore_jetty_cfg *cfg)
{
	struct ubase_mbx_attr attr = {};
	struct udma_jetty_ctx ctx = {};
	int ret;

	if (cfg->priority >= UDMA_MAX_PRIORITY) {
		dev_err(dev->dev, "kernel mode jetty priority is out of range, priority is %u.\n",
			cfg->priority);
		return -EINVAL;
	}

	udma_init_jettyc(dev, cfg, udma_jetty, &ctx);

	attr.tag = udma_jetty->sq.id;
	attr.op = UDMA_CMD_CREATE_JFS_CONTEXT;
	ret = post_mailbox_update_ctx(dev, &ctx, sizeof(ctx), &attr);
	if (ret)
		dev_err(dev->dev,
			"post mailbox create jetty ctx failed, ret = %d.\n", ret);

	return ret;
}

int udma_add_xa_and_create_hw_ctx(struct udma_dev *udma_dev, struct udma_jetty *udma_jetty,
				  struct ubcore_jetty_cfg *cfg)
{
	int ret;

	ret = xa_err(xa_store(&udma_dev->jetty_table.xa, udma_jetty->sq.id,
			      &udma_jetty->sq, GFP_KERNEL));
	if (ret) {
		dev_err(udma_dev->dev,
			"store jetty sq: %u to sq table failed, ret = %d.\n",
			udma_jetty->sq.id, ret);
		return ret;
	}

	ret = udma_create_hw_jetty_ctx(udma_dev, udma_jetty, cfg);
	if (ret) {
		dev_err(udma_dev->dev,
			"post mailbox create jetty ctx failed, ret = %d.\n", ret);
		goto err_create_hw_jetty;
	}

	udma_set_query_flush_time(udma_dev, &udma_jetty->sq, cfg->err_timeout);
	udma_jetty->sq.state = UBCORE_JETTY_STATE_READY;
	refcount_set(&udma_jetty->ae_refcount, 1);
	init_completion(&udma_jetty->ae_comp);

	if (dfx_switch)
		udma_dfx_store_jetty_id(udma_dev, udma_jetty);

	return ret;
err_create_hw_jetty:
	xa_erase(&udma_dev->jetty_table.xa, udma_jetty->sq.id);

	return ret;
}

static int udma_active_jetty_detail(struct udma_dev *udma_dev, struct udma_jetty *udma_jetty,
				    struct ubcore_jetty_cfg *cfg, struct ubcore_udata *udata)
{
	int ret;

	ret = udma_alloc_jetty_sq(udma_dev, udma_jetty, cfg, udata);
	if (ret) {
		dev_err(udma_dev->dev, "udma alloc jetty id buffer failed, ret = %d.\n", ret);
		return ret;
	}

	ret = udma_add_xa_and_create_hw_ctx(udma_dev, udma_jetty, cfg);
	if (ret)
		udma_free_jetty_id_buf(udma_dev, udma_jetty, cfg);

	return ret;
}

struct ubcore_jetty *udma_create_jetty(struct ubcore_device *ub_dev, struct ubcore_jetty_cfg *cfg,
				       struct ubcore_udata *udata)
{
	struct udma_dev *udma_dev = to_udma_dev(ub_dev);
	struct udma_jetty *udma_jetty;
	int ret;

	udma_jetty = kzalloc(sizeof(*udma_jetty), GFP_KERNEL);
	if (!udma_jetty)
		return ERR_PTR(-ENOMEM);

	ret = udma_jetty_bind_jfc(udma_dev, cfg->send_jfc->id, cfg->recv_jfc->id);
	if (ret) {
		kfree(udma_jetty);
		return ERR_PTR(ret);
	}

	ret = udma_active_jetty_detail(udma_dev, udma_jetty, cfg, udata);
	if (ret) {
		dev_err(udma_dev->dev, "active jetty detail failed, ret = %d.\n", ret);
		udma_jetty_unbind_jfc(udma_dev, cfg->send_jfc->id);
		kfree(udma_jetty);
		return ERR_PTR(ret);
	}

	udma_jetty->sq.activated = true;

	return &udma_jetty->ubcore_jetty;
}

int udma_destroy_hw_jetty_ctx(struct udma_dev *dev, uint32_t jetty_id)
{
	struct ubase_mbx_attr attr = {};
	int ret;

	attr.tag = jetty_id;
	attr.op = UDMA_CMD_DESTROY_JFS_CONTEXT;
	ret = post_mailbox_update_ctx(dev, NULL, 0, &attr);
	if (ret)
		dev_err(dev->dev,
			"post mailbox destroy jetty ctx failed, ret = %d.\n", ret);

	return ret;
}

int udma_set_jetty_state(struct udma_dev *dev, uint32_t jetty_id,
			 enum jetty_state state)
{
	struct udma_jetty_ctx *ctx, *ctx_mask;
	struct ubase_mbx_attr mbox_attr = {};
	struct ubase_cmd_mailbox *mailbox;
	int ret;

	mailbox = udma_alloc_cmd_mailbox(dev);
	if (!mailbox) {
		dev_err(dev->dev, "failed to alloc mailbox for jetty context.\n");
		return -EINVAL;
	}

	ctx = (struct udma_jetty_ctx *)mailbox->buf;

	/* Optimize chip access performance. */
	ctx_mask = (struct udma_jetty_ctx *)((char *)ctx + UDMA_JFS_MASK_OFFSET);
	memset(ctx_mask, 0xff, sizeof(struct udma_jetty_ctx));
	ctx->state = state;
	ctx_mask->state = 0;

	mbox_attr.tag = jetty_id;
	mbox_attr.op = UDMA_CMD_MODIFY_JFS_CONTEXT;
	ret = udma_post_mbox(dev, mailbox, &mbox_attr);
	if (ret)
		dev_err(dev->dev,
			"failed to upgrade jettyc, ret = %d.\n", ret);
	udma_free_cmd_mailbox(dev, mailbox);

	return ret;
}

static int udma_query_jetty_ctx(struct udma_dev *dev,
				struct udma_jetty_ctx *jfs_ctx,
				uint32_t jetty_id)
{
	struct ubase_mbx_attr mbox_attr = {};
	struct ubase_cmd_mailbox *mailbox;

	mbox_attr.tag = jetty_id;
	mbox_attr.op = UDMA_CMD_QUERY_JFS_CONTEXT;
	mailbox = udma_mailbox_query_ctx(dev, &mbox_attr);
	if (!mailbox)
		return -ENOMEM;
	memcpy((void *)jfs_ctx, mailbox->buf, sizeof(*jfs_ctx));

	udma_free_cmd_mailbox(dev, mailbox);

	return 0;
}

void udma_clean_cqe_for_jetty(struct udma_dev *dev, struct udma_jetty_queue *sq,
			      struct ubcore_jfc *send_jfc,
			      struct ubcore_jfc *recv_jfc)
{
	if (sq->buf.kva) {
		if (send_jfc)
			udma_clean_jfc(send_jfc, sq->id, dev);

		if (recv_jfc && recv_jfc != send_jfc)
			udma_clean_jfc(recv_jfc, sq->id, dev);
	}
}

static bool udma_wait_timeout(uint32_t *sum_times, uint32_t times, uint32_t ta_timeout)
{
	uint32_t wait_time;

	if (*sum_times > ta_timeout)
		return true;

	wait_time = 1 << times;
	msleep(wait_time);
	*sum_times += wait_time;

	return false;
}

static void udma_mask_jetty_ctx(struct udma_jetty_ctx *ctx)
{
	ctx->sqe_base_addr_l = 0;
	ctx->sqe_base_addr_h = 0;
	ctx->user_data_l = 0;
	ctx->user_data_h = 0;
}

static bool udma_query_jetty_fd(struct udma_dev *dev, struct udma_jetty_queue *sq)
{
	struct udma_jetty_ctx ctx = {};
	uint16_t rcv_send_diff = 0;
	uint32_t sum_times = 0;
	uint32_t times = 0;

	while (true) {
		if (udma_query_jetty_ctx(dev, &ctx, sq->id))
			return false;

		if (ctx.flush_cqe_done)
			return true;

		if (udma_wait_timeout(&sum_times, times, UDMA_TA_TIMEOUT_64000MS))
			break;

		times++;
	}

	/* In the flip scenario, ctx.next_rcv_ssn - ctx.next_send_ssn value is less than 512. */
	rcv_send_diff = ctx.next_rcv_ssn - ctx.next_send_ssn;
	if (ctx.flush_ssn_vld && rcv_send_diff < UDMA_RCV_SEND_MAX_DIFF)
		return true;

	udma_mask_jetty_ctx(&ctx);
	udma_dfx_ctx_print(dev, "Flush Failed Jetty", sq->id, sizeof(ctx) / sizeof(uint32_t),
			   (uint32_t *)&ctx);

	return false;
}

void udma_modify_jetty_precondition(struct udma_dev *dev, struct udma_jetty_queue *sq)
{
	struct udma_jetty_ctx ctx = {};
	uint16_t rcv_send_diff = 0;
	uint32_t sum_times = 0;
	uint32_t times = 0;
	int ret;

	while (true) {
		ret = udma_query_jetty_ctx(dev, &ctx, sq->id);
		if (ret) {
			dev_warn(dev->dev, "query jetty context not ready, id = %u, ret = %d.\n",
				 sq->id, ret);
		} else {
			rcv_send_diff = ctx.next_rcv_ssn - ctx.next_send_ssn;
			if (ctx.PI == ctx.CI && rcv_send_diff < UDMA_RCV_SEND_MAX_DIFF &&
			    ctx.state == JETTY_READY)
				break;

			if (rcv_send_diff < UDMA_RCV_SEND_MAX_DIFF &&
			    ctx.state == JETTY_ERROR)
				break;
		}

		if (udma_wait_timeout(&sum_times, times, sq->ta_timeout)) {
			dev_warn(dev->dev, "TA timeout, id = %u. PI = %d, CI = %d, nxt_send_ssn = %d nxt_rcv_ssn = %d state = %d.\n",
				 sq->id, ctx.PI, ctx.CI, ctx.next_send_ssn,
				 ctx.next_rcv_ssn, ctx.state);
			break;
		}
		times++;
	}
}

static bool udma_destroy_jetty_precondition(struct udma_dev *dev, struct udma_jetty_queue *sq)
{
#define UDMA_DESTROY_JETTY_DELAY_TIME 100U

	if (sq->state != UBCORE_JETTY_STATE_READY && sq->state != UBCORE_JETTY_STATE_SUSPENDED)
		goto query_jetty_fd;

	if (dev->caps.feature & UDMA_CAP_FEATURE_UE_RX_CLOSE)
		goto modify_to_err;

	if ((dev->hw_ver == UBASE_HW_VER_A_0) || (dev->hw_ver == UBASE_HW_VER_K_0))
		udma_modify_jetty_precondition(dev, sq);

modify_to_err:
	if (udma_set_jetty_state(dev, sq->id, JETTY_ERROR)) {
		dev_err(dev->dev, "modify jetty to error failed, id: %u.\n",
			sq->id);
		return false;
	}

	sq->state = UBCORE_JETTY_STATE_ERROR;

query_jetty_fd:
	if (!udma_query_jetty_fd(dev, sq))
		return false;

	udelay(UDMA_DESTROY_JETTY_DELAY_TIME);

	return true;
}

int udma_modify_and_destroy_jetty(struct udma_dev *dev,
				  struct udma_jetty_queue *sq)
{
	int ret;

	if (!udma_destroy_jetty_precondition(dev, sq))
		return -EFAULT;

	if (sq->state != UBCORE_JETTY_STATE_RESET) {
		ret = udma_destroy_hw_jetty_ctx(dev, sq->id);
		if (ret) {
			dev_err(dev->dev, "jetty destroy failed, id: %u.\n",
				sq->id);
			return ret;
		}
	}

	return 0;
}

static void udma_free_jetty_detail(struct ubcore_jetty *jetty)
{
	struct udma_dev *udma_dev = to_udma_dev(jetty->ub_dev);
	struct udma_jetty *udma_jetty = to_udma_jetty(jetty);

	udma_jetty_unbind_jfc(udma_dev, jetty->jetty_cfg.send_jfc->id);

	udma_clean_cqe_for_jetty(udma_dev, &udma_jetty->sq, jetty->jetty_cfg.send_jfc,
				 jetty->jetty_cfg.recv_jfc);

	if (dfx_switch)
		udma_dfx_delete_id(udma_dev, &udma_dev->dfx_info->jetty,
				   udma_jetty->sq.id);

	xa_erase(&udma_dev->jetty_table.xa, udma_jetty->sq.id);

	if (refcount_dec_and_test(&udma_jetty->ae_refcount))
		complete(&udma_jetty->ae_comp);
	wait_for_completion(&udma_jetty->ae_comp);
	if (udma_jetty->sq.jetty_type == UDMA_LOCK_BUFFER_JETTY_TYPE)
		udma_free_lock_buffer_sq_buf(udma_dev, udma_jetty);
	else
		udma_free_sq_buf(udma_dev, &udma_jetty->sq);
	free_jetty_id(udma_dev, udma_jetty, !!udma_jetty->sq.jetty_grp);
}

int udma_deactive_jetty(struct ubcore_jetty *jetty, struct ubcore_udata *udata)
{
	struct udma_dev *udma_dev = to_udma_dev(jetty->ub_dev);
	struct udma_jetty *udma_jetty = to_udma_jetty(jetty);
	int ret;

	if (!udma_jetty->sq.activated) {
		dev_info_ratelimited(udma_dev->dev, "jetty no need deactivate.\n");
		return 0;
	}

	if (!udma_jetty->ue_rx_closed && udma_close_ue_rx(udma_dev, true, true, false, 0)) {
		dev_err(udma_dev->dev, "close UE rx failed when destroying jetty.\n");
		return -EINVAL;
	}

	ret = udma_modify_and_destroy_jetty(udma_dev, &udma_jetty->sq);
	if (ret) {
		dev_err(udma_dev->dev, "udma modify error and destroy jetty failed, id: %u.\n",
			jetty->jetty_id.id);
		if (!udma_jetty->ue_rx_closed)
			udma_open_ue_rx_with_retry(udma_dev, true, true, false, 0);
		return ret;
	}

	udma_free_jetty_detail(jetty);
	udma_open_ue_rx_with_retry(udma_dev, true, true, false, 0);

	udma_jetty->sq.activated = false;

	return 0;
}

int udma_destroy_jetty(struct ubcore_jetty *jetty)
{
	int ret = udma_deactive_jetty(jetty, NULL);

	if (ret == 0)
		kfree(jetty);

	return ret;
}

static int udma_batch_jetty_get_ack(struct udma_dev *dev,
				    struct udma_jetty_queue **sq_list,
				    uint32_t jetty_cnt, bool *jetty_flag,
				    int *bad_jetty_index)
{
	struct udma_jetty_ctx ctx = {};
	struct udma_jetty_queue *sq;
	uint16_t rcv_send_diff = 0;
	uint32_t i;
	int ret;

	for (i = 0; i < jetty_cnt; i++) {
		sq = sq_list[i];
		if (sq->state != UBCORE_JETTY_STATE_READY &&
		    sq->state != UBCORE_JETTY_STATE_SUSPENDED)
			continue;

		if (jetty_flag[i])
			continue;

		ret = udma_query_jetty_ctx(dev, &ctx, sq->id);
		if (ret) {
			dev_warn(dev->dev, "query jetty context not ready, id = %u, ret = %d.\n",
				 sq->id, ret);
			*bad_jetty_index = 0;
			break;
		}

		rcv_send_diff = ctx.next_rcv_ssn - ctx.next_send_ssn;
		if (ctx.PI == ctx.CI && rcv_send_diff < UDMA_RCV_SEND_MAX_DIFF &&
		    ctx.state == JETTY_READY) {
			jetty_flag[i] = true;
			continue;
		}

		if (rcv_send_diff < UDMA_RCV_SEND_MAX_DIFF &&
		    ctx.state == JETTY_ERROR) {
			jetty_flag[i] = true;
			continue;
		}

		*bad_jetty_index = 0;
		break;
	}

	return (i == jetty_cnt) ? 0 : -EAGAIN;
}

static uint32_t get_max_jetty_ta_timeout(struct udma_jetty_queue **sq_list,
					 uint32_t jetty_cnt)
{
	uint32_t max_timeout = 0;
	uint32_t i;

	for (i = 0; i < jetty_cnt; i++) {
		if (sq_list[i]->ta_timeout > max_timeout)
			max_timeout = sq_list[i]->ta_timeout;
	}

	return max_timeout;
}

static bool udma_batch_query_jetty_fd(struct udma_dev *dev,
				      struct udma_jetty_queue **sq_list,
				      uint32_t jetty_cnt, int *bad_jetty_index)
{
	uint32_t times = (dev->caps.feature & UDMA_CAP_FEATURE_UE_RX_CLOSE) ?
			  batch_flush_query_freq : 0;
	uint32_t ta_timeout = batch_flush_query_timeout;
	struct udma_jetty_ctx ctx = {};
	struct udma_jetty_queue *sq;
	uint16_t rcv_send_diff = 0;
	uint32_t sum_times = 0;
	uint32_t flush_cnt = 0;
	bool all_query_done;
	bool *jetty_flag;
	uint32_t i;

	jetty_flag = kcalloc(jetty_cnt, sizeof(bool), GFP_KERNEL);
	if (!jetty_flag) {
		*bad_jetty_index = 0;
		return false;
	}

	while (true) {
		if (udma_wait_timeout(&sum_times, times, ta_timeout)) {
			dev_warn_ratelimited(dev->dev,
					     "timeout after %u ms, not all jetty get flush done.\n",
					     sum_times);
			break;
		}
		times++;
		if (times < batch_flush_query_freq)
			times = batch_flush_query_freq;

		for (i = 0; i < jetty_cnt; i++) {
			if (jetty_flag[i])
				continue;

			sq = sq_list[i];
			if (udma_query_jetty_ctx(dev, &ctx, sq->id)) {
				kfree(jetty_flag);
				*bad_jetty_index = 0;
				return false;
			}

			if (!ctx.flush_cqe_done)
				continue;

			flush_cnt++;
			jetty_flag[i] = true;
		}

		if (flush_cnt == jetty_cnt) {
			kfree(jetty_flag);
			return true;
		}
	}

	all_query_done = true;

	for (i = 0; i < jetty_cnt; i++) {
		if (jetty_flag[i])
			continue;

		sq = sq_list[i];
		if (udma_query_jetty_ctx(dev, &ctx, sq->id)) {
			kfree(jetty_flag);
			*bad_jetty_index = 0;
			return false;
		}

		rcv_send_diff = ctx.next_rcv_ssn - ctx.next_send_ssn;
		if (ctx.flush_cqe_done || (ctx.flush_ssn_vld &&
		    rcv_send_diff < UDMA_RCV_SEND_MAX_DIFF))
			continue;

		*bad_jetty_index = 0;
		all_query_done = false;

		udma_mask_jetty_ctx(&ctx);
		udma_dfx_ctx_print(dev, "Flush Failed Jetty", sq->id,
				   sizeof(ctx) / sizeof(uint32_t), (uint32_t *)&ctx);
		break;
	}

	kfree(jetty_flag);

	return all_query_done;
}

static int batch_modify_jetty_to_error(struct udma_dev *dev,
				       struct udma_jetty_queue **sq_list,
				       uint32_t jetty_cnt, int *bad_jetty_index)
{
	struct udma_jetty_queue *sq;
	uint32_t i;
	int ret;

	for (i = 0; i < jetty_cnt; i++) {
		sq = sq_list[i];
		if (sq->state == UBCORE_JETTY_STATE_ERROR ||
		    sq->state == UBCORE_JETTY_STATE_RESET)
			continue;

		ret = udma_set_jetty_state(dev, sq->id, JETTY_ERROR);
		if (ret) {
			dev_err(dev->dev, "modify jetty to error failed, id: %u.\n",
				sq->id);
			*bad_jetty_index = 0;
			return ret;
		}

		sq->state = UBCORE_JETTY_STATE_ERROR;
	}

	return 0;
}

static int udma_batch_modify_jetty_precondition(struct udma_dev *dev,
						struct udma_jetty_queue **sq_list,
						uint32_t jetty_cnt, int *bad_jetty_index)
{
	uint32_t ta_timeout = get_max_jetty_ta_timeout(sq_list, jetty_cnt);
	uint32_t times = batch_flush_query_freq;
	uint32_t sum_times = 0;
	bool *jetty_flag;
	int ret;

	jetty_flag = kcalloc(jetty_cnt, sizeof(bool), GFP_KERNEL);
	if (!jetty_flag) {
		*bad_jetty_index = 0;
		return -ENOMEM;
	}

	while (true) {
		if (udma_wait_timeout(&sum_times, times, ta_timeout)) {
			dev_warn_ratelimited(dev->dev,
					     "timeout after %u ms, not all jetty get ack.\n",
					     sum_times);
			break;
		}
		times++;

		ret = udma_batch_jetty_get_ack(dev, sq_list, jetty_cnt, jetty_flag,
					       bad_jetty_index);
		if (ret != -EAGAIN) {
			kfree(jetty_flag);
			return ret;
		}
	}

	kfree(jetty_flag);

	return 0;
}

static bool udma_batch_destroy_jetty_precondition(struct udma_dev *dev,
						  struct udma_jetty_queue **sq_list,
						  uint32_t jetty_cnt, int *bad_jetty_index)
{
	if (!(dev->caps.feature & UDMA_CAP_FEATURE_UE_RX_CLOSE) &&
		((dev->hw_ver == UBASE_HW_VER_A_0) || (dev->hw_ver == UBASE_HW_VER_K_0)) &&
	    udma_batch_modify_jetty_precondition(dev, sq_list, jetty_cnt, bad_jetty_index))
		return false;

	if (batch_modify_jetty_to_error(dev, sq_list, jetty_cnt, bad_jetty_index)) {
		dev_err(dev->dev, "batch modify jetty error failed.\n");
		return false;
	}

	if (!udma_batch_query_jetty_fd(dev, sq_list, jetty_cnt, bad_jetty_index))
		return false;

	udelay(UDMA_DESTROY_JETTY_DELAY_TIME);

	return true;
}

int udma_batch_modify_and_destroy_jetty(struct udma_dev *dev,
					struct udma_jetty_queue **sq_list,
					uint32_t jetty_cnt, int *bad_jetty_index)
{
	uint32_t i;
	int ret;

	if (!udma_batch_destroy_jetty_precondition(dev, sq_list, jetty_cnt, bad_jetty_index))
		return -EFAULT;

	for (i = 0; i < jetty_cnt; i++) {
		if (sq_list[i]->state != UBCORE_JETTY_STATE_RESET) {
			ret = udma_destroy_hw_jetty_ctx(dev, sq_list[i]->id);
			if (ret) {
				dev_err(dev->dev,
					"jetty destroy failed, id: %u.\n",
					sq_list[i]->id);
				*bad_jetty_index = 0;
				return ret;
			}

			sq_list[i]->state = UBCORE_JETTY_STATE_RESET;
		}
	}

	return 0;
}

int udma_destroy_jetty_batch(struct ubcore_jetty **jetty, int jetty_cnt, int *bad_jetty_index)
{
	struct udma_jetty_queue **sq_list;
	uint32_t active_jetty_cnt = 0;
	struct udma_jetty_queue *sq;
	struct udma_dev *udma_dev;
	uint32_t i;
	int ret;

	if (!jetty) {
		pr_err("jetty array is null.\n");
		return -EINVAL;
	}

	if (!jetty_cnt) {
		pr_err("jetty count is 0.\n");
		return -EINVAL;
	}

	udma_dev = to_udma_dev(jetty[0]->ub_dev);

	sq_list = kcalloc(1, sizeof(*sq_list) * jetty_cnt, GFP_KERNEL);
	if (!sq_list) {
		*bad_jetty_index = 0;
		return -ENOMEM;
	}

	for (i = 0; i < (uint32_t)jetty_cnt; i++) {
		sq = &(to_udma_jetty(jetty[i])->sq);
		if (sq->activated)
			sq_list[active_jetty_cnt++] = sq;
	}

	ret = udma_batch_modify_and_destroy_jetty(udma_dev, sq_list, active_jetty_cnt,
						  bad_jetty_index);
	if (ret) {
		dev_err(udma_dev->dev, "udma batch modify error and destroy jetty failed.\n");
		kfree(sq_list);
		return ret;
	}

	for (i = 0; i < active_jetty_cnt; i++)
		udma_free_jetty_detail(&(to_udma_jetty_from_queue(sq_list[i])->ubcore_jetty));

	kfree(sq_list);

	for (i = 0; i < (uint32_t)jetty_cnt; i++)
		kfree(jetty[i]);

	return 0;
}

int udma_unimport_jetty(struct ubcore_tjetty *tjetty)
{
	struct udma_target_jetty *udma_tjetty = to_udma_tjetty(tjetty);
	struct udma_dev *udma_dev = to_udma_dev(tjetty->ub_dev);

	if (!IS_ERR_OR_NULL(tjetty->vtpn)) {
		dev_err(udma_dev->dev,
			"the target jetty is still being used, id = %u.\n",
			tjetty->cfg.id.id);
		return -EINVAL;
	}

	udma_tjetty->token_value = 0;
	tjetty->cfg.token_value.token = 0;
	kfree(udma_tjetty);

	return 0;
}

bool verify_modify_jetty(enum ubcore_jetty_state jetty_state,
			 enum ubcore_jetty_state attr_state)
{
	switch (jetty_state) {
	case UBCORE_JETTY_STATE_RESET:
		return attr_state == UBCORE_JETTY_STATE_READY;
	case UBCORE_JETTY_STATE_READY:
		return attr_state == UBCORE_JETTY_STATE_ERROR ||
		       attr_state == UBCORE_JETTY_STATE_SUSPENDED;
	case UBCORE_JETTY_STATE_SUSPENDED:
		return attr_state == UBCORE_JETTY_STATE_ERROR;
	case UBCORE_JETTY_STATE_ERROR:
		return attr_state == UBCORE_JETTY_STATE_RESET;
	default:
		break;
	}

	return false;
}

enum jetty_state to_jetty_state(enum ubcore_jetty_state state)
{
	switch (state) {
	case UBCORE_JETTY_STATE_ERROR:
		return JETTY_ERROR;
	case UBCORE_JETTY_STATE_SUSPENDED:
		return JETTY_SUSPEND;
	default:
		break;
	}

	return STATE_NUM;
}

static int udma_modify_jetty_state(struct udma_dev *udma_dev, struct udma_jetty *udma_jetty,
				   struct ubcore_jetty_attr *attr)
{
	int ret;

	switch (attr->state) {
	case UBCORE_JETTY_STATE_RESET:
		ret = udma_destroy_hw_jetty_ctx(udma_dev, udma_jetty->sq.id);
		break;
	case UBCORE_JETTY_STATE_READY:
		ret = udma_create_hw_jetty_ctx(udma_dev, udma_jetty,
					       &udma_jetty->ubcore_jetty.jetty_cfg);
		if (ret)
			break;

		udma_reset_sw_k_jetty_queue(&udma_jetty->sq);
		break;
	default:
		ret = udma_close_ue_rx(udma_dev, true, true, false, 0);
		if (ret)
			break;

		if (!(udma_dev->caps.feature & UDMA_CAP_FEATURE_UE_RX_CLOSE) &&
		    ((udma_dev->hw_ver == UBASE_HW_VER_A_0) ||
		     (udma_dev->hw_ver == UBASE_HW_VER_K_0)))
			udma_modify_jetty_precondition(udma_dev, &udma_jetty->sq);

		ret = udma_set_jetty_state(udma_dev, udma_jetty->sq.id,
					   to_jetty_state(attr->state));
		if (ret)
			udma_open_ue_rx_with_retry(udma_dev, true, true, false, 0);
		else
			udma_jetty->ue_rx_closed = true;
		break;
	}

	return ret;
}

int udma_modify_jetty(struct ubcore_jetty *jetty, struct ubcore_jetty_attr *attr,
		      struct ubcore_udata *udata)
{
	struct udma_dev *udma_dev = to_udma_dev(jetty->ub_dev);
	struct udma_jetty *udma_jetty = to_udma_jetty(jetty);
	int ret;

	if (!(attr->mask & UBCORE_JETTY_STATE)) {
		dev_err(udma_dev->dev, "modify jetty mask is error or not set, jetty id = %u.\n",
			udma_jetty->sq.id);
		return -EINVAL;
	}

	if (udma_jetty->sq.state == attr->state) {
		dev_info_ratelimited(udma_dev->dev, "jetty state has been %s.\n",
				     to_state_name(attr->state));
		return 0;
	}

	if (!verify_modify_jetty(udma_jetty->sq.state, attr->state)) {
		dev_err(udma_dev->dev, "not support modify jetty state from %s to %s.\n",
			to_state_name(udma_jetty->sq.state), to_state_name(attr->state));
		return -EINVAL;
	}

	ret = udma_modify_jetty_state(udma_dev, udma_jetty, attr);
	if (ret) {
		dev_err(udma_dev->dev, "modify jetty %u state to %s failed.\n",
			udma_jetty->sq.id, to_state_name(attr->state));
		return ret;
	}
	udma_jetty->sq.state = attr->state;

	return 0;
}

int udma_flush_jetty(struct ubcore_jetty *jetty, int cr_cnt, struct ubcore_cr *cr)
{
	struct udma_dev *udma_dev = to_udma_dev(jetty->ub_dev);
	struct udma_jetty *udma_jetty = to_udma_jetty(jetty);
	struct udma_jetty_queue *sq = &udma_jetty->sq;
	int n_flushed;

	if (!sq->flush_flag)
		return 0;

	if (!sq->lock_free)
		spin_lock(&sq->lock);

	for (n_flushed = 0; n_flushed < cr_cnt; n_flushed++) {
		if (sq->ci == sq->pi)
			break;
		udma_flush_sq(udma_dev, sq, cr + n_flushed);
	}

	if (!sq->lock_free)
		spin_unlock(&sq->lock);

	return n_flushed;
}

int udma_post_jetty_send_wr(struct ubcore_jetty *jetty, struct ubcore_jfs_wr *wr,
			    struct ubcore_jfs_wr **bad_wr)
{
	struct udma_dev *udma_dev = to_udma_dev(jetty->ub_dev);
	struct udma_jetty *udma_jetty = to_udma_jetty(jetty);
	int ret;

	ret = udma_post_sq_wr(udma_dev, &udma_jetty->sq, wr, bad_wr);
	if (ret)
		dev_err(udma_dev->dev,
			"jetty post sq wr failed, ret = %d, jetty id = %u.\n",
			ret, udma_jetty->sq.id);

	return ret;
}

int udma_post_jetty_recv_wr(struct ubcore_jetty *jetty, struct ubcore_jfr_wr *wr,
			    struct ubcore_jfr_wr **bad_wr)
{
	struct udma_dev *udma_dev = to_udma_dev(jetty->ub_dev);
	struct udma_jetty *udma_jetty = to_udma_jetty(jetty);
	struct ubcore_jfr *jfr;
	int ret;

	jfr = &udma_jetty->jfr->ubcore_jfr;
	ret = udma_post_jfr_wr(jfr, wr, bad_wr);
	if (ret)
		dev_err(udma_dev->dev,
			"jetty post jfr wr failed, ret = %d, jetty id = %u.\n",
			ret, udma_jetty->sq.id);

	return ret;
}

int udma_unbind_jetty(struct ubcore_jetty *jetty)
{
	struct udma_jetty *udma_jetty = to_udma_jetty(jetty);

	udma_jetty->sq.rc_tjetty = NULL;

	return 0;
}

struct ubcore_tjetty *udma_import_jetty_ex(struct ubcore_device *ub_dev,
					   struct ubcore_tjetty_cfg *cfg,
					   struct ubcore_active_tp_cfg *active_tp_cfg,
					   struct ubcore_udata *udata)
{
	struct udma_dev *udma_dev = to_udma_dev(ub_dev);
	struct udma_target_jetty *tjetty;
	int ret = 0;

	if (cfg->type != UBCORE_JETTY_GROUP && cfg->type != UBCORE_JETTY) {
		dev_err(udma_dev->dev,
			"the jetty of the type %u cannot be imported in exp.\n",
			cfg->type);
		return ERR_PTR(-EINVAL);
	}

	ret = udma_check_jetty_grp_info(cfg, udma_dev);
	if (ret)
		return ERR_PTR(ret);

	tjetty = kzalloc(sizeof(*tjetty), GFP_KERNEL);
	if (!tjetty)
		return ERR_PTR(-ENOMEM);

	if (cfg->flag.bs.token_policy != UBCORE_TOKEN_NONE) {
		tjetty->token_value = cfg->token_value.token;
		tjetty->token_value_valid = true;
	}

	udma_swap_endian(cfg->id.eid.raw, tjetty->le_eid.raw, UBCORE_EID_SIZE);

	return &tjetty->ubcore_tjetty;
}

int udma_bind_jetty_ex(struct ubcore_jetty *jetty,
		       struct ubcore_tjetty *tjetty,
		       struct ubcore_active_tp_cfg *active_tp_cfg,
		       struct ubcore_udata *udata)
{
	struct udma_jetty *udma_jetty = to_udma_jetty(jetty);

	udma_jetty->sq.rc_tjetty = tjetty;

	return 0;
}

int udma_alloc_jetty(struct ubcore_device *dev, struct ubcore_jetty_cfg *cfg,
		     struct ubcore_jetty **jetty, struct ubcore_udata *udata)
{
	struct udma_jetty *udma_jetty;

	udma_jetty = kzalloc(sizeof(*udma_jetty), GFP_KERNEL);
	if (!udma_jetty)
		return -ENOMEM;

	udma_jetty->ubcore_jetty.jetty_cfg = *cfg;

	*jetty = &udma_jetty->ubcore_jetty;

	return 0;
}

static uint64_t udma_jetty_opt[] = {
	UBCORE_JFS_DEPTH,
	UBCORE_JFS_FLAG,
	UBCORE_JFS_TRANS_MODE,
	UBCORE_JFS_PRIORITY,
	UBCORE_JFS_MAX_SGE,
	UBCORE_JFS_MAX_RSGE,
	UBCORE_JFS_MAX_INLINE_DATA,
	UBCORE_JFS_RNR_RETRY,
	UBCORE_JFS_ERR_TIMEOUT,
	UBCORE_JFS_BIND_JFC,
	UBCORE_JFS_USER_CTX,
	UBCORE_JFS_SQE_BASE_ADDR,
	UBCORE_JFS_ID,
	UBCORE_JFS_DB_ADDR,
	UBCORE_JFS_DB_STATUS,
	UBCORE_JFS_PI,
	UBCORE_JFS_PI_TYPE,
	UBCORE_JFS_CI,
	UBCORE_JFS_FULL_CTX,
	UBCORE_JETTY_ID,
	UBCORE_JETTY_FLAG,
	UBCORE_JETTY_BIND_JFR,
	UBCORE_JETTY_BIND_RX_JFC,
	UBCORE_JETTY_BIND_JTG,
	UBCORE_JETTY_FULL_CTX,
};

static struct udma_jetty_opt_info opt_info[] = {
	{sizeof(uint32_t), PERM_R | PERM_W, USER_IGNORE, JFS_MODE | JETTY_MODE},
	{sizeof(uint32_t), PERM_R | PERM_W, USER_IGNORE, JFS_MODE},
	{sizeof(uint32_t), PERM_R | PERM_W, USER_IGNORE, JFS_MODE | JETTY_MODE},
	{sizeof(uint8_t), PERM_R | PERM_W, USER_IGNORE, JFS_MODE | JETTY_MODE},
	{sizeof(uint8_t), PERM_R | PERM_W, USER_IGNORE, JFS_MODE | JETTY_MODE},
	{sizeof(uint8_t), PERM_R | PERM_W, USER_IGNORE, JFS_MODE | JETTY_MODE},
	{sizeof(uint32_t), PERM_R | PERM_W, USER_IGNORE, JFS_MODE | JETTY_MODE},
	{sizeof(uint8_t), PERM_R | PERM_W, USER_IGNORE, JFS_MODE | JETTY_MODE},
	{sizeof(uint8_t), PERM_R | PERM_W, USER_IGNORE, JFS_MODE | JETTY_MODE},
	{sizeof(uint64_t), PERM_R | PERM_W, USER_IGNORE, JFS_MODE | JETTY_MODE},
	{sizeof(uint64_t), PERM_R | PERM_W, USER_IGNORE, JFS_MODE},
	{sizeof(uint64_t), PERM_R | PERM_W, USER_IGNORE, JFS_MODE | JETTY_MODE},
	{sizeof(uint32_t), PERM_R | PERM_W, USER_IGNORE, JFS_MODE},
	{sizeof(uint64_t), PERM_R, USER_IGNORE, JFS_MODE | JETTY_MODE},
	{sizeof(uint8_t), PERM_R | PERM_W, USER_IGNORE, JFS_MODE | JETTY_MODE},
	{sizeof(uint16_t), PERM_R, 0, JFS_MODE | JETTY_MODE},
	{sizeof(uint16_t), PERM_R | PERM_W, USER_IGNORE, JFS_MODE | JETTY_MODE},
	{sizeof(uint16_t), PERM_R, 0, JFS_MODE | JETTY_MODE},
	{sizeof(struct udma_jetty_ctx), PERM_R, 0, JFS_MODE | JETTY_MODE},
	{sizeof(uint32_t), PERM_R | PERM_W, USER_IGNORE, JETTY_MODE},
	{sizeof(uint32_t), PERM_R | PERM_W, USER_IGNORE, JETTY_MODE},
	{sizeof(uint64_t), PERM_R | PERM_W, USER_IGNORE, JETTY_MODE},
	{sizeof(uint64_t), PERM_R | PERM_W, USER_IGNORE, JETTY_MODE},
	{sizeof(uint64_t), PERM_R | PERM_W, USER_IGNORE, JETTY_MODE},
	{sizeof(struct udma_jetty_ctx), PERM_R, 0, JETTY_MODE},
};

int udma_verify_jetty_opt(struct udma_dev *udma_dev, struct udma_jetty_opt_attr attr)
{
	uint32_t opt_index = ARRAY_SIZE(udma_jetty_opt);
	uint32_t i;

	for (i = 0; i < ARRAY_SIZE(udma_jetty_opt); i++) {
		if (udma_jetty_opt[i] == attr.opt) {
			opt_index = i;
			break;
		}
	}

	if (opt_index >= ARRAY_SIZE(opt_info) || (opt_info[opt_index].mode & attr.mode) == 0) {
		dev_err(udma_dev->dev, "option %llu mode %u is invalid\n", attr.opt, attr.mode);
		return -EINVAL;
	}

	if (attr.len != opt_info[opt_index].buf_len) {
		dev_err(udma_dev->dev, "index %u option %llu len %u error, should be %u\n",
			opt_index, attr.opt, attr.len, opt_info[opt_index].buf_len);
		return -EINVAL;
	}

	if ((opt_info[opt_index].perm & attr.perm) == 0) {
		dev_err(udma_dev->dev, "option %llu not allow write\n", attr.opt);
		return -EINVAL;
	}

	/* The return value EEXIST indicates that the current opt does not need to be processed. */
	if ((attr.is_user && (opt_info[opt_index].ignore_attr & USER_IGNORE)) ||
		(!attr.is_user && (opt_info[opt_index].ignore_attr & KERNEL_IGNORE))) {
		dev_info_ratelimited(udma_dev->dev, "opt %llu no need to process\n", attr.opt);
		return -EEXIST;
	}

	return 0;
}

int udma_set_jetty_field(struct udma_dev *udma_dev, struct udma_jetty_queue *sq,
			 uint64_t opt, void *buf)
{
	unsigned long flags;
	uint64_t in_data;

	switch (opt) {
	case UBCORE_JFS_SQE_BASE_ADDR:
		in_data = *(uint64_t *)buf;
		if (in_data == 0 && !udma_dev->caps.lock_buffer_en) {
			dev_err(udma_dev->dev,
				"JFS SQE base address is null and no support wqe lock buffer\n");
			return -EINVAL;
		}
		sq->buf.addr = in_data;
		sq->buf.kva = (void *)(uintptr_t)sq->buf.addr;
		sq->cstm = true;
		break;
	case UBCORE_JFS_DB_STATUS:
		in_data = *(uint8_t *)buf;
		if (in_data > 1) {
			dev_err(udma_dev->dev, "doorbell status %llu is invalid\n", in_data);
			return -EINVAL;
		}
		sq->db_status = in_data;
		if (sq->db_status == 0 && sq->need_ring_db) {
			if (!sq->lock_free)
				spin_lock_irqsave(&sq->lock, flags);

			sq->need_ring_db = false;
			udma_k_update_sq_db(sq);

			if (!sq->lock_free)
				spin_unlock_irqrestore(&sq->lock, flags);
		}
		break;
	case UBCORE_JFS_PI_TYPE:
		in_data = *(uint16_t *)buf;
		if (in_data > 1) {
			dev_err(udma_dev->dev, "pi type %llu is invalid\n", in_data);
			return -EINVAL;
		}
		sq->pi_type = in_data;
		break;
	default:
		break;
	}

	return 0;
}

int udma_set_jetty_opt(struct ubcore_jetty *jetty, uint64_t opt, void *buf,
		       uint32_t len, struct ubcore_udata *udata)
{
	struct udma_jetty_opt_attr attr = {opt, buf, len, JETTY_MODE, PERM_W, !!udata};
	struct udma_dev *udma_dev = to_udma_dev(jetty->ub_dev);
	struct udma_jetty *udma_jetty = to_udma_jetty(jetty);
	int ret;

	ret = udma_verify_jetty_opt(udma_dev, attr);
	if (ret == -EEXIST)
		return 0;

	if (ret)
		return ret;

	return udma_set_jetty_field(udma_dev, &udma_jetty->sq, opt, buf);
}

static int
udma_k_check_wqe_lock_buffer_jetty(struct udma_dev *udma_dev, struct udma_jetty *udma_jetty,
				   struct ubcore_udata *udata)
{
	if (udata)
		return 0;

	if (!udma_jetty->sq.cstm) {
		dev_err(udma_dev->dev, "ccu jetty no support address not configured.\n");
		return -EINVAL;
	}

	if (((uint64_t)udma_jetty->sq.buf.addr) >= UDMA_WQE_LOCK_BUFFER_JETTY_IDX) {
		dev_err(udma_dev->dev, "buffer index is out of range, buffer index = %llu.\n",
			(uint64_t)udma_jetty->sq.buf.addr);
		return -EINVAL;
	}

	return 0;
}

int udma_active_jetty(struct ubcore_jetty *jetty, struct ubcore_udata *udata)
{
	struct udma_dev *udma_dev = to_udma_dev(jetty->ub_dev);
	struct udma_jetty *udma_jetty = to_udma_jetty(jetty);
	int ret = 0;

	if (udma_dev->caps.lock_buffer_en &&
	    CFGID_CHECK(jetty->jetty_cfg.id, udma_dev->caps.ccu_jetty)) {
		if (udma_k_check_wqe_lock_buffer_jetty(udma_dev, udma_jetty, udata))
			return -EINVAL;
	} else {
		if (udma_jetty->sq.cstm && !udata && udma_jetty->sq.buf.addr == 0) {
			dev_err(udma_dev->dev, "JFS SQE base address is null\n");
			return -EINVAL;
		}
	}

	if (udma_jetty_bind_jfc(udma_dev, jetty->jetty_cfg.send_jfc->id,
				jetty->jetty_cfg.recv_jfc->id))
		return -EINVAL;

	ret = udma_active_jetty_detail(udma_dev, udma_jetty, &jetty->jetty_cfg, udata);
	if (ret) {
		udma_jetty_unbind_jfc(udma_dev, jetty->jetty_cfg.send_jfc->id);
		dev_err(udma_dev->dev, "failed to activate jetty, ret = %d.\n", ret);
		return ret;
	}

	udma_jetty->sq.activated = true;

	return 0;
}

int udma_get_jetty_field(struct udma_dev *dev, struct udma_jetty_queue *sq, uint64_t opt, void *buf)
{
	struct udma_jetty_ctx ctx = {};
	int ret;

	switch (opt) {
	case UBCORE_JFS_SQE_BASE_ADDR:
		*(uint64_t *)buf = sq->buf.addr;
		break;
	case UBCORE_JFS_DB_ADDR:
		*(uint64_t *)buf = (uintptr_t)sq->dwqe_addr + UDMA_DOORBELL_OFFSET;
		break;
	case UBCORE_JFS_DB_STATUS:
		*(uint8_t *)buf = sq->db_status;
		break;
	case UBCORE_JFS_PI:
		ret = udma_query_jetty_ctx(dev, &ctx, sq->id);
		if (ret) {
			dev_err(dev->dev, "query jetty context not ready, id = %u, ret = %d.\n",
				sq->id, ret);
			return ret;
		}
		*(uint16_t *)buf = ctx.PI;
		break;
	case UBCORE_JFS_PI_TYPE:
		*(uint16_t *)buf = sq->pi_type;
		break;
	case UBCORE_JFS_CI:
		ret = udma_query_jetty_ctx(dev, &ctx, sq->id);
		if (ret) {
			dev_err(dev->dev, "failed to query JFS ctx, id = %u, ret = %d.\n",
				sq->id, ret);
			return ret;
		}
		*(uint16_t *)buf = ctx.CI;
		break;
	case UBCORE_JFS_FULL_CTX:
		ret = udma_query_jetty_ctx(dev, (struct udma_jetty_ctx *)buf, sq->id);
		if (ret) {
			dev_err(dev->dev, "failed to query JFS ctx, id = %u, ret = %d.\n",
				sq->id, ret);
			return ret;
		}
		break;
	case UBCORE_JETTY_FULL_CTX:
		ret = udma_query_jetty_ctx(dev, (struct udma_jetty_ctx *)buf, sq->id);
		if (ret) {
			dev_err(dev->dev, "query jetty context not ready, id = %u, ret = %d.\n",
				sq->id, ret);
			return ret;
		}
		break;
	default:
		break;
	}

	return 0;
}

static void udma_get_jetty_cfg_field(struct ubcore_jetty_cfg *jetty_cfg, uint64_t opt, void *buf)
{
	switch (opt) {
	case UBCORE_JETTY_ID:
		*(uint32_t *)buf = jetty_cfg->id;
		break;
	case UBCORE_JETTY_FLAG:
		*(uint32_t *)buf = jetty_cfg->flag.value;
		break;
	case UBCORE_JETTY_BIND_RX_JFC:
		*(uint64_t *)buf = (uintptr_t)jetty_cfg->recv_jfc;
		break;
	case UBCORE_JETTY_BIND_JFR:
		*(uint64_t *)buf = (uintptr_t)jetty_cfg->jfr;
		break;
	case UBCORE_JETTY_BIND_JTG:
		*(uint64_t *)buf = (uintptr_t)jetty_cfg->jetty_grp;
		break;
	default:
		break;
	}
}

void udma_get_jfs_cfg_field(struct ubcore_jfs_cfg *jfs_cfg, uint64_t opt, void *buf)
{
	switch (opt) {
	case UBCORE_JFS_DEPTH:
		*(uint32_t *)buf = jfs_cfg->depth;
		break;
	case UBCORE_JFS_FLAG:
		*(uint32_t *)buf = jfs_cfg->flag.value;
		break;
	case UBCORE_JFS_TRANS_MODE:
		*(uint32_t *)buf = jfs_cfg->trans_mode;
		break;
	case UBCORE_JFS_PRIORITY:
		*(uint8_t *)buf = jfs_cfg->priority;
		break;
	case UBCORE_JFS_MAX_SGE:
		*(uint8_t *)buf = jfs_cfg->max_sge;
		break;
	case UBCORE_JFS_MAX_RSGE:
		*(uint8_t *)buf = jfs_cfg->max_rsge;
		break;
	case UBCORE_JFS_MAX_INLINE_DATA:
		*(uint32_t *)buf = jfs_cfg->max_inline_data;
		break;
	case UBCORE_JFS_RNR_RETRY:
		*(uint8_t *)buf = jfs_cfg->rnr_retry;
		break;
	case UBCORE_JFS_ERR_TIMEOUT:
		*(uint8_t *)buf = jfs_cfg->err_timeout;
		break;
	case UBCORE_JFS_BIND_JFC:
		*(uint64_t *)buf = (uintptr_t)jfs_cfg->jfc;
		break;
	default:
		break;
	}
}

int udma_get_jetty_opt(struct ubcore_jetty *jetty, uint64_t opt, void *buf,
		       uint32_t len, struct ubcore_udata *udata)
{
	struct udma_jetty_opt_attr attr = {opt, buf, len, JETTY_MODE, PERM_R, !!udata};
	struct udma_dev *udma_dev = to_udma_dev(jetty->ub_dev);
	struct ubcore_jetty_cfg *jetty_cfg = &jetty->jetty_cfg;
	struct udma_jetty *udma_jetty = to_udma_jetty(jetty);
	struct ubcore_jfs_cfg jfs_cfg = {
		.depth = jetty_cfg->jfs_depth,
		.trans_mode = jetty_cfg->trans_mode,
		.priority = jetty_cfg->priority,
		.max_sge = jetty_cfg->max_send_sge,
		.max_rsge = jetty_cfg->max_send_rsge,
		.max_inline_data = jetty_cfg->max_inline_data,
		.rnr_retry = jetty_cfg->rnr_retry,
		.err_timeout = jetty_cfg->err_timeout,
		.jfc = jetty_cfg->send_jfc,
	};
	int ret;

	ret = udma_verify_jetty_opt(udma_dev, attr);
	if (ret == -EEXIST)
		return 0;

	if (ret)
		return ret;

	udma_get_jetty_cfg_field(jetty_cfg, opt, buf);
	udma_get_jfs_cfg_field(&jfs_cfg, opt, buf);

	return udma_get_jetty_field(udma_dev, &udma_jetty->sq, opt, buf);
}

int udma_free_jetty(struct ubcore_jetty *jetty, struct ubcore_udata *udata)
{
	kfree(jetty);

	return 0;
}

uint32_t udma_get_ta_timeout(uint8_t gear)
{
	static const uint32_t timeout_table[] = {
		UDMA_TA_TIMEOUT_128MS,
		UDMA_TA_TIMEOUT_1000MS,
		UDMA_TA_TIMEOUT_8000MS,
		UDMA_TA_TIMEOUT_64000MS
	};

	return (gear < ARRAY_SIZE(timeout_table)) ? timeout_table[gear] : UDMA_TA_TIMEOUT_64000MS;
}
