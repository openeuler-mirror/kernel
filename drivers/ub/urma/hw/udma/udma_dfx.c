// SPDX-License-Identifier: GPL-2.0+
/* Copyright(c) 2025 HiSilicon Technologies CO., Ltd. All rights reserved. */

#define dev_fmt(fmt) "UDMA: " fmt

#include <linux/vmalloc.h>
#include "udma_cmd.h"
#include "udma_jfr.h"
#include "udma_jfs.h"
#include "udma_jfc.h"
#include "udma_jetty.h"
#include "udma_dfx.h"

bool dfx_switch;

static int to_udma_trans_mode(uint32_t type, struct udma_dev *dev,
			      enum ubcore_transport_mode *trans_mode)
{
	switch (type) {
	case JETTY_UM:
		*trans_mode = UBCORE_TP_UM;
		break;
	case JETTY_RC:
		*trans_mode = UBCORE_TP_RC;
		break;
	case JETTY_RM:
		*trans_mode = UBCORE_TP_RM;
		break;
	default:
		dev_err(dev->dev, "transport mode error, type = %u.\n", type);
		return -EINVAL;
	}

	return 0;
}

static int to_udma_jfr_ctx_state(uint32_t state, struct udma_dev *dev,
				 enum ubcore_jfr_state *jfr_state)
{
	switch (state) {
	case JETTY_RESET:
		*jfr_state = UBCORE_JFR_STATE_RESET;
		break;
	case JETTY_READY:
		*jfr_state = UBCORE_JFR_STATE_READY;
		break;
	case JETTY_ERROR:
		*jfr_state = UBCORE_JFR_STATE_ERROR;
		break;
	default:
		dev_err(dev->dev, "JFR context state error, state = %u.\n", state);
		return -EINVAL;
	}

	return 0;
}

static int to_udma_jetty_ctx_state(uint32_t state, struct udma_dev *dev,
				   enum ubcore_jetty_state *jetty_state)
{
	switch (state) {
	case JETTY_RESET:
		*jetty_state = UBCORE_JETTY_STATE_RESET;
		break;
	case JETTY_READY:
		*jetty_state = UBCORE_JETTY_STATE_READY;
		break;
	case JETTY_ERROR:
		*jetty_state = UBCORE_JETTY_STATE_ERROR;
		break;
	case JETTY_SUSPEND:
		*jetty_state = UBCORE_JETTY_STATE_SUSPENDED;
		break;
	default:
		dev_err(dev->dev, "JFS context state error, state = %u.\n", state);
		return -EINVAL;
	}

	return 0;
}

int udma_query_jfr(struct ubcore_jfr *jfr, struct ubcore_jfr_cfg *cfg,
		   struct ubcore_jfr_attr *attr)
{
	struct udma_dev *udma_dev = to_udma_dev(jfr->ub_dev);
	struct udma_jfr *udma_jfr = to_udma_jfr(jfr);
	struct ubase_mbx_attr mbox_attr = {};
	struct ubase_cmd_mailbox *mailbox;
	struct udma_jfr_ctx *jfr_ctx;
	int ret;

	mbox_attr.tag = jfr->jfr_id.id;
	mbox_attr.op = UDMA_CMD_QUERY_JFR_CONTEXT;
	mailbox = udma_mailbox_query_ctx(udma_dev, &mbox_attr);
	if (!mailbox)
		return -ENOMEM;

	jfr_ctx = (struct udma_jfr_ctx *)mailbox->buf;

	attr->rx_threshold = to_udma_rx_threshold(jfr_ctx->limit_wl);

	ret = to_udma_jfr_ctx_state(jfr_ctx->state, udma_dev, &attr->state);
	if (ret)
		goto err_jfr_ctx;

	cfg->max_sge = 1 << jfr_ctx->rqe_size_shift;
	cfg->min_rnr_timer = jfr_ctx->rnr_timer;
	cfg->depth = 1 << jfr_ctx->rqe_shift;
	cfg->flag = jfr->jfr_cfg.flag;
	cfg->token_value.token = 0;
	cfg->id = jfr->jfr_id.id;
	cfg->flag.bs.token_policy = UBCORE_TOKEN_NONE;

	ret = to_udma_trans_mode(jfr_ctx->type, udma_dev, &cfg->trans_mode);
	if (ret)
		goto err_jfr_ctx;

	if (udma_jfr->rq.buf.kva) {
		cfg->eid_index = jfr->jfr_cfg.eid_index;
		cfg->jfc = jfr->jfr_cfg.jfc;
	}

err_jfr_ctx:
	jfr_ctx->token_value = 0;
	udma_free_cmd_mailbox(udma_dev, mailbox);

	return ret;
}

int udma_query_jfs(struct ubcore_jfs *jfs, struct ubcore_jfs_cfg *cfg,
		   struct ubcore_jfs_attr *attr)
{
	struct udma_dev *udma_dev = to_udma_dev(jfs->ub_dev);
	struct udma_jfs *udma_jfs = to_udma_jfs(jfs);
	struct ubase_mbx_attr mbox_attr = {};
	struct ubase_cmd_mailbox *mailbox;
	struct udma_jetty_ctx *jfs_ctx;
	uint32_t wqe_bb_depth;
	int ret;

	mbox_attr.tag = jfs->jfs_id.id;
	mbox_attr.op = UDMA_CMD_QUERY_JFS_CONTEXT;
	mailbox = udma_mailbox_query_ctx(udma_dev, &mbox_attr);
	if (!mailbox)
		return -ENOMEM;

	jfs_ctx = (struct udma_jetty_ctx *)mailbox->buf;

	ret = to_udma_jetty_ctx_state(jfs_ctx->state, udma_dev, &attr->state);
	if (ret)
		goto err_jfs_ctx;

	cfg->priority = jfs_ctx->sl;
	cfg->flag = jfs->jfs_cfg.flag;
	cfg->max_sge = jfs->jfs_cfg.max_sge;
	cfg->max_rsge = jfs->jfs_cfg.max_rsge;
	cfg->err_timeout = jfs_ctx->ta_timeout;
	wqe_bb_depth = 1 << jfs_ctx->sqe_bb_shift;
	cfg->depth = wqe_bb_depth / udma_jfs->sq.sqe_bb_cnt;
	cfg->rnr_retry = jfs_ctx->rnr_retry_num;
	cfg->max_inline_data = jfs->jfs_cfg.max_inline_data;

	ret = to_udma_trans_mode(jfs_ctx->type, udma_dev, &cfg->trans_mode);
	if (ret)
		goto err_jfs_ctx;

	if (udma_jfs->sq.buf.kva) {
		cfg->jfc = jfs->jfs_cfg.jfc;
		cfg->eid_index = jfs_ctx->seid_idx;
	}

err_jfs_ctx:
	udma_free_cmd_mailbox(udma_dev, mailbox);

	return ret;
}

int udma_query_jetty(struct ubcore_jetty *jetty, struct ubcore_jetty_cfg *cfg,
		     struct ubcore_jetty_attr *attr)
{
	struct udma_dev *udma_dev = to_udma_dev(jetty->ub_dev);
	struct udma_jetty *udma_jetty = to_udma_jetty(jetty);
	struct ubase_mbx_attr jfr_mbox_attr = {};
	struct ubase_cmd_mailbox *jetty_mailbox;
	struct ubase_cmd_mailbox *jfr_mailbox;
	struct ubase_mbx_attr mbox_attr = {};
	struct udma_jetty_ctx *jetty_ctx;
	struct udma_jfr_ctx *jfr_ctx;
	uint32_t wqe_bb_depth;
	int ret;

	mbox_attr.tag = jetty->jetty_id.id;
	mbox_attr.op = UDMA_CMD_QUERY_JFS_CONTEXT;
	jetty_mailbox = udma_mailbox_query_ctx(udma_dev, &mbox_attr);
	if (!jetty_mailbox)
		return -ENOMEM;

	jfr_mbox_attr.tag = udma_jetty->jfr->ubcore_jfr.jfr_id.id;
	jfr_mbox_attr.op = UDMA_CMD_QUERY_JFR_CONTEXT;
	jfr_mailbox = udma_mailbox_query_ctx(udma_dev, &jfr_mbox_attr);
	if (!jfr_mailbox) {
		udma_free_cmd_mailbox(udma_dev, jetty_mailbox);
		return -ENOMEM;
	}

	jetty_ctx = (struct udma_jetty_ctx *)jetty_mailbox->buf;
	jfr_ctx = (struct udma_jfr_ctx *)jfr_mailbox->buf;

	wqe_bb_depth = 1 << jetty_ctx->sqe_bb_shift;
	cfg->id = jetty->jetty_id.id;
	cfg->jfs_depth = wqe_bb_depth / udma_jetty->sq.sqe_bb_cnt;
	cfg->jfr_depth = 1 << jfr_ctx->rqe_shift;
	cfg->flag = jetty->jetty_cfg.flag;
	cfg->max_send_sge = jetty->jetty_cfg.max_send_sge;
	cfg->max_send_rsge = jetty->jetty_cfg.max_send_rsge;
	cfg->max_recv_sge = jetty->jetty_cfg.max_recv_sge;
	cfg->max_inline_data = jetty->jetty_cfg.max_inline_data;
	cfg->priority = jetty_ctx->sl;
	cfg->rnr_retry = jetty_ctx->rnr_retry_num;
	cfg->err_timeout = jetty_ctx->ta_timeout;
	cfg->min_rnr_timer = jetty->jetty_cfg.min_rnr_timer;

	ret = to_udma_trans_mode(jetty_ctx->type, udma_dev, &cfg->trans_mode);
	if (ret)
		goto err_jetty_ctx;

	cfg->token_value.token = 0;

	ret = to_udma_jetty_ctx_state(jetty_ctx->state, udma_dev, &attr->state);
	if (ret)
		goto err_jetty_ctx;

	attr->rx_threshold = to_udma_rx_threshold(jfr_ctx->limit_wl);

	if (udma_jetty->sq.buf.kva) {
		cfg->eid_index = jetty_ctx->seid_idx;
		cfg->send_jfc = jetty->jetty_cfg.send_jfc;
		cfg->recv_jfc = jetty->jetty_cfg.recv_jfc;
		cfg->jfr = jetty->jetty_cfg.jfr;
		cfg->jetty_grp = jetty->jetty_cfg.jetty_grp;
	}

err_jetty_ctx:
	jfr_ctx->token_value = 0;
	udma_free_cmd_mailbox(udma_dev, jfr_mailbox);
	udma_free_cmd_mailbox(udma_dev, jetty_mailbox);

	return ret;
}

static int udma_query_res_list(struct udma_dev *udma_dev,
			       struct udma_dfx_entity *entity,
			       struct ubcore_res_val *val,
			       const char *name)
{
	struct ubcore_res_list_val *res_list = (struct ubcore_res_list_val *)val->addr;
	size_t idx = 0;
	uint32_t *id;

	res_list->cnt = 0;

	read_lock(&entity->rwlock);
	if (entity->cnt == 0) {
		read_unlock(&entity->rwlock);
		return 0;
	}

	res_list->list = __vmalloc(sizeof(uint32_t) * entity->cnt, GFP_ATOMIC);
	if (!res_list->list) {
		dev_err(udma_dev->dev, "failed to vmalloc %s_list, %s_cnt = %u!\n",
			name, name, entity->cnt);
		read_unlock(&entity->rwlock);
		return -ENOMEM;
	}

	xa_for_each(&entity->table, idx, id) {
		if (res_list->cnt >= entity->cnt) {
			dev_err(udma_dev->dev, "failed to query %s_id, %s_cnt = %u!\n",
				name, name, entity->cnt);
			read_unlock(&entity->rwlock);
			vfree(res_list->list);
			return -EINVAL;
		}
		res_list->list[res_list->cnt] = idx;
		++res_list->cnt;
	}
	read_unlock(&entity->rwlock);

	return 0;
}

static int udma_query_res_dev_seg(struct udma_dev *udma_dev,
				  struct ubcore_res_val *val)
{
	struct ubcore_res_seg_val *res_list = (struct ubcore_res_seg_val *)val->addr;
	struct ubcore_seg_info *seg_list;
	struct udma_dfx_seg *seg = NULL;
	size_t idx;

	res_list->seg_cnt = 0;

	read_lock(&udma_dev->dfx_info->seg.rwlock);
	if (udma_dev->dfx_info->seg.cnt == 0) {
		read_unlock(&udma_dev->dfx_info->seg.rwlock);
		return 0;
	}

	seg_list = __vmalloc(sizeof(*seg_list) * udma_dev->dfx_info->seg.cnt, GFP_ATOMIC);
	if (!seg_list) {
		read_unlock(&udma_dev->dfx_info->seg.rwlock);
		return -ENOMEM;
	}

	xa_for_each(&udma_dev->dfx_info->seg.table, idx, seg) {
		if (res_list->seg_cnt >= udma_dev->dfx_info->seg.cnt) {
			dev_err(udma_dev->dev, "failed to query seg_list, seg_cnt = %u!\n",
				udma_dev->dfx_info->seg.cnt);
			read_unlock(&udma_dev->dfx_info->seg.rwlock);
			vfree(seg_list);
			return -EINVAL;
		}
		seg_list[res_list->seg_cnt].token_id = seg->id;
		seg_list[res_list->seg_cnt].len = seg->len;
		seg_list[res_list->seg_cnt].ubva = seg->ubva;
		seg_list[res_list->seg_cnt].ubva.va = 0;
		++res_list->seg_cnt;
	}
	read_unlock(&udma_dev->dfx_info->seg.rwlock);

	res_list->seg_list = seg_list;

	return 0;
}

static int udma_query_res_rc(struct udma_dev *udma_dev,
			     struct ubcore_res_key *key,
			     struct ubcore_res_val *val)
{
	struct ubcore_res_list_val *res_list;
	struct ubcore_res_rc_val *res_rc;
	struct udma_rc_ctx rcc = {};
	uint32_t i;
	int ret;

	if (key->key_cnt == 0) {
		if (udma_dev->caps.rc_max_cnt == 0) {
			dev_err(udma_dev->dev, "invalid RC max count.\n");
			return -EINVAL;
		}

		res_list = (struct ubcore_res_list_val *)val->addr;
		res_list->list = vmalloc(sizeof(uint32_t) * udma_dev->caps.rc_max_cnt);
		if (!res_list->list)
			return -ENOMEM;

		for (i = 0; i < udma_dev->caps.rc_max_cnt; i++)
			res_list->list[i] = i;
		res_list->cnt = udma_dev->caps.rc_max_cnt;
	} else {
		res_rc = (struct ubcore_res_rc_val *)val->addr;
		ret = ubase_adev_query_rc_ctx(udma_dev->comdev.adev, key->key,
					      (void *)&rcc, sizeof(rcc));
		if (ret) {
			dev_err(udma_dev->dev, "failed to query RC, RC id = %u.\n", key->key);
			return ret;
		}

		res_rc->rc_id = key->key;
		res_rc->depth = 1 << rcc.rce_shift;
		res_rc->type = 0;
		res_rc->state = 0;
		rcc.rce_base_addr_l = 0;
		rcc.rce_base_addr_h = 0;

		udma_dfx_ctx_print(udma_dev, "RC", key->key, sizeof(rcc) / sizeof(uint32_t),
				   (uint32_t *)&rcc);
	}

	return 0;
}

static int udma_query_res_jetty(struct udma_dev *udma_dev,
				struct ubcore_res_key *key,
				struct ubcore_res_val *val)
{
	struct ubcore_res_jetty_val *res_jetty = (struct ubcore_res_jetty_val *)val->addr;
	struct ubase_mbx_attr mbox_attr = {};
	enum ubcore_jetty_state jetty_state;
	struct ubase_cmd_mailbox *mailbox;
	struct udma_jetty_ctx *jettyc;
	struct udma_dfx_jetty *jetty;
	int ret;

	if (key->key_cnt == 0)
		return udma_query_res_list(udma_dev, &udma_dev->dfx_info->jetty, val, "jetty");

	read_lock(&udma_dev->dfx_info->jetty.rwlock);
	jetty = (struct udma_dfx_jetty *)xa_load(&udma_dev->dfx_info->jetty.table, key->key);
	if (!jetty) {
		read_unlock(&udma_dev->dfx_info->jetty.rwlock);
		dev_err(udma_dev->dev, "failed to query jetty, jetty id = %u.\n",
			key->key);
		return -EINVAL;
	}
	res_jetty->jfs_depth = jetty->jfs_depth;
	read_unlock(&udma_dev->dfx_info->jetty.rwlock);

	mbox_attr.tag = key->key;
	mbox_attr.op = UDMA_CMD_QUERY_JFS_CONTEXT;
	mailbox = udma_mailbox_query_ctx(udma_dev, &mbox_attr);
	if (!mailbox)
		return -ENOMEM;

	jettyc = (struct udma_jetty_ctx *)mailbox->buf;
	res_jetty->jetty_id = key->key;

	ret = to_udma_jetty_ctx_state(jettyc->state, udma_dev, &jetty_state);
	if (ret)
		goto err_res_jetty_ctx;

	res_jetty->state = jetty_state;
	res_jetty->recv_jfc_id = jettyc->rx_jfcn;
	res_jetty->send_jfc_id = jettyc->tx_jfcn;
	res_jetty->priority = jettyc->sl;
	res_jetty->jfr_id = jettyc->jfrn_l |
			    jettyc->jfrn_h << JETTY_CTX_JFRN_H_OFFSET;
	jettyc->sqe_base_addr_l = 0;
	jettyc->sqe_base_addr_h = 0;
	jettyc->user_data_l = 0;
	jettyc->user_data_h = 0;

	udma_dfx_ctx_print(udma_dev, "Jetty", key->key, sizeof(*jettyc) / sizeof(uint32_t),
			   (uint32_t *)jettyc);
err_res_jetty_ctx:
	udma_free_cmd_mailbox(udma_dev, mailbox);

	return ret;
}

static int udma_query_res_jetty_grp(struct udma_dev *udma_dev,
				    struct ubcore_res_key *key,
				    struct ubcore_res_val *val)
{
	struct ubcore_res_jetty_group_val *res_jetty_grp =
		(struct ubcore_res_jetty_group_val *)val->addr;
	struct udma_jetty_grp_ctx *jetty_grpc;
	struct ubase_mbx_attr mbox_attr = {};
	struct ubase_cmd_mailbox *mailbox;
	uint32_t *jetty_grp_id;
	int i;

	if (key->key_cnt == 0)
		return udma_query_res_list(udma_dev, &udma_dev->dfx_info->jetty_grp,
					   val, "jetty_grp");

	jetty_grp_id = (uint32_t *)xa_load(&udma_dev->dfx_info->jetty_grp.table, key->key);
	if (!jetty_grp_id) {
		dev_err(udma_dev->dev, "failed to query jetty group, jetty group id = %u.\n",
			key->key);
		return -EINVAL;
	}

	res_jetty_grp->jetty_cnt = 0;
	res_jetty_grp->jetty_list = vmalloc(sizeof(*res_jetty_grp->jetty_list) *
				    NUM_JETTY_PER_GROUP);
	if (!res_jetty_grp->jetty_list)
		return -ENOMEM;

	mbox_attr.tag = key->key;
	mbox_attr.op = UDMA_CMD_QUERY_JETTY_GROUP_CONTEXT;
	mailbox = udma_mailbox_query_ctx(udma_dev, &mbox_attr);
	if (!mailbox) {
		vfree(res_jetty_grp->jetty_list);
		res_jetty_grp->jetty_list = NULL;
		return -ENOMEM;
	}

	jetty_grpc = (struct udma_jetty_grp_ctx *)mailbox->buf;
	for (i = 0; i < NUM_JETTY_PER_GROUP; ++i) {
		if (jetty_grpc->valid & BIT(i)) {
			res_jetty_grp->jetty_list[res_jetty_grp->jetty_cnt] =
				jetty_grpc->start_jetty_id + i;
			++res_jetty_grp->jetty_cnt;
		}
	}

	if (res_jetty_grp->jetty_cnt == 0) {
		vfree(res_jetty_grp->jetty_list);
		res_jetty_grp->jetty_list = NULL;
	}

	udma_dfx_ctx_print(udma_dev, "Jetty_grp", key->key, sizeof(*jetty_grpc) / sizeof(uint32_t),
			   (uint32_t *)jetty_grpc);
	udma_free_cmd_mailbox(udma_dev, mailbox);

	return 0;
}

static int udma_query_res_jfc(struct udma_dev *udma_dev,
			      struct ubcore_res_key *key,
			      struct ubcore_res_val *val)
{
	struct ubcore_res_jfc_val *res_jfc = (struct ubcore_res_jfc_val *)val->addr;
	struct ubase_mbx_attr mbox_attr = {};
	struct ubase_cmd_mailbox *mailbox;
	struct udma_jfc_ctx *jfcc;
	uint32_t *jfc_id;

	if (key->key_cnt == 0)
		return udma_query_res_list(udma_dev, &udma_dev->dfx_info->jfc, val, "jfc");

	jfc_id = (uint32_t *)xa_load(&udma_dev->dfx_info->jfc.table, key->key);
	if (!jfc_id) {
		dev_err(udma_dev->dev, "failed to query JFC, JFC id = %u.\n",
			key->key);
		return -EINVAL;
	}

	mbox_attr.tag = key->key;
	mbox_attr.op = UDMA_CMD_QUERY_JFC_CONTEXT;
	mailbox = udma_mailbox_query_ctx(udma_dev, &mbox_attr);
	if (!mailbox)
		return -ENOMEM;

	jfcc = (struct udma_jfc_ctx *)mailbox->buf;
	res_jfc->jfc_id = key->key;
	res_jfc->state = jfcc->state;
	res_jfc->depth = 1 << (jfcc->shift + UDMA_JFC_DEPTH_SHIFT_BASE);
	jfcc->cqe_va_l = 0;
	jfcc->cqe_va_h = 0;
	jfcc->token_en = 0;
	jfcc->cqe_token_value = 0;
	jfcc->record_db_addr_l = 0;
	jfcc->record_db_addr_h = 0;
	jfcc->remote_token_value = 0;

	udma_dfx_ctx_print(udma_dev, "JFC", key->key, sizeof(*jfcc) / sizeof(uint32_t),
			   (uint32_t *)jfcc);
	udma_free_cmd_mailbox(udma_dev, mailbox);

	return 0;
}

static int udma_query_res_jfs(struct udma_dev *udma_dev,
			      struct ubcore_res_key *key,
			      struct ubcore_res_val *val)
{
	struct ubcore_res_jfs_val *res_jfs = (struct ubcore_res_jfs_val *)val->addr;
	struct ubase_mbx_attr mbox_attr = {};
	enum ubcore_jetty_state jfs_state;
	struct ubase_cmd_mailbox *mailbox;
	struct udma_jetty_ctx *jfsc;
	struct udma_dfx_jfs *jfs;
	int ret;

	if (key->key_cnt == 0)
		return udma_query_res_list(udma_dev, &udma_dev->dfx_info->jfs, val, "jfs");

	read_lock(&udma_dev->dfx_info->jfs.rwlock);
	jfs = (struct udma_dfx_jfs *)xa_load(&udma_dev->dfx_info->jfs.table, key->key);
	if (!jfs) {
		read_unlock(&udma_dev->dfx_info->jfs.rwlock);
		dev_err(udma_dev->dev, "failed to query JFS, JFS id = %u.\n",
			key->key);
		return -EINVAL;
	}
	res_jfs->depth = jfs->depth;
	read_unlock(&udma_dev->dfx_info->jfs.rwlock);

	mbox_attr.tag = key->key;
	mbox_attr.op = UDMA_CMD_QUERY_JFS_CONTEXT;
	mailbox = udma_mailbox_query_ctx(udma_dev, &mbox_attr);
	if (!mailbox)
		return -ENOMEM;

	jfsc = (struct udma_jetty_ctx *)mailbox->buf;
	res_jfs->jfs_id = key->key;

	ret = to_udma_jetty_ctx_state(jfsc->state, udma_dev, &jfs_state);
	if (ret)
		goto err_res_jetty_ctx;

	res_jfs->state = jfs_state;
	res_jfs->priority = jfsc->sl;
	res_jfs->jfc_id = jfsc->tx_jfcn;
	jfsc->sqe_base_addr_l = 0;
	jfsc->sqe_base_addr_h = 0;
	jfsc->user_data_l = 0;
	jfsc->user_data_h = 0;

	udma_dfx_ctx_print(udma_dev, "JFS", key->key, sizeof(*jfsc) / sizeof(uint32_t),
			   (uint32_t *)jfsc);
err_res_jetty_ctx:
	udma_free_cmd_mailbox(udma_dev, mailbox);

	return ret;
}

static int udma_query_res_jfr(struct udma_dev *udma_dev,
			      struct ubcore_res_key *key,
			      struct ubcore_res_val *val)
{
	struct ubcore_res_jfr_val *res_jfr = (struct ubcore_res_jfr_val *)val->addr;
	struct ubase_mbx_attr mbox_attr = {};
	struct ubase_cmd_mailbox *mailbox;
	enum ubcore_jfr_state jfr_state;
	struct udma_jfr_ctx *jfrc;
	uint32_t *jfr_id;
	int ret;

	if (key->key_cnt == 0)
		return udma_query_res_list(udma_dev, &udma_dev->dfx_info->jfr, val, "jfr");

	jfr_id = (uint32_t *)xa_load(&udma_dev->dfx_info->jfr.table, key->key);
	if (!jfr_id) {
		dev_err(udma_dev->dev, "failed to query JFR, JFR id = %u.\n",
			key->key);
		return -EINVAL;
	}

	mbox_attr.tag = key->key;
	mbox_attr.op = UDMA_CMD_QUERY_JFR_CONTEXT;
	mailbox = udma_mailbox_query_ctx(udma_dev, &mbox_attr);
	if (!mailbox)
		return -ENOMEM;

	jfrc = (struct udma_jfr_ctx *)mailbox->buf;
	res_jfr->jfr_id = key->key;

	ret = to_udma_jfr_ctx_state(jfrc->state, udma_dev, &jfr_state);
	if (ret)
		goto err_res_jfr_ctx;

	res_jfr->state = jfr_state;
	res_jfr->depth = 1 << jfrc->rqe_shift;
	res_jfr->jfc_id = jfrc->jfcn_l |
			  jfrc->jfcn_h << JFR_JFCN_H_OFFSET;
	jfrc->rqe_base_addr_l = 0;
	jfrc->rqe_base_addr_h = 0;
	jfrc->token_en = 0;
	jfrc->token_value = 0;
	jfrc->user_data_l = 0;
	jfrc->user_data_h = 0;
	jfrc->idx_que_addr_l = 0;
	jfrc->idx_que_addr_h = 0;
	jfrc->record_db_addr_l = 0;
	jfrc->record_db_addr_m = 0;
	jfrc->record_db_addr_h = 0;

	udma_dfx_ctx_print(udma_dev, "JFR", key->key, sizeof(*jfrc) / sizeof(uint32_t),
			   (uint32_t *)jfrc);
err_res_jfr_ctx:
	jfrc->token_value = 0;
	udma_free_cmd_mailbox(udma_dev, mailbox);

	return ret;
}

static int udma_query_res_seg(struct udma_dev *udma_dev, struct ubcore_res_key *key,
			      struct ubcore_res_val *val)
{
	struct ubcore_res_seg_val *res_seg = (struct ubcore_res_seg_val *)val->addr;
	struct udma_dfx_seg *seg;

	if (key->key_cnt == 0)
		return udma_query_res_dev_seg(udma_dev, val);

	read_lock(&udma_dev->dfx_info->seg.rwlock);
	seg = (struct udma_dfx_seg *)xa_load(&udma_dev->dfx_info->seg.table, key->key);
	if (!seg) {
		read_unlock(&udma_dev->dfx_info->seg.rwlock);
		dev_err(udma_dev->dev, "failed to query seg, token_id = %u.\n",
			key->key);
		return -EINVAL;
	}

	res_seg->seg_list = __vmalloc(sizeof(struct ubcore_seg_info), GFP_ATOMIC);
	if (!res_seg->seg_list) {
		read_unlock(&udma_dev->dfx_info->seg.rwlock);
		return -ENOMEM;
	}

	res_seg->seg_cnt = 1;
	res_seg->seg_list->token_id = seg->id;
	res_seg->seg_list->len = seg->len;
	res_seg->seg_list->ubva = seg->ubva;
	res_seg->seg_list->ubva.va = 0;
	read_unlock(&udma_dev->dfx_info->seg.rwlock);

	return 0;
}

static int udma_query_res_dev_ta(struct udma_dev *udma_dev,
				 struct ubcore_res_key *key,
				 struct ubcore_res_val *val)
{
	struct ubcore_res_dev_ta_val *res_ta = (struct ubcore_res_dev_ta_val *)val->addr;
	struct udma_dfx_info *dfx = udma_dev->dfx_info;
	struct udma_dfx_entity_cnt udma_dfx_entity_cnt_ta[] = {
		{&dfx->jetty.rwlock, &dfx->jetty, &res_ta->jetty_cnt},
		{&dfx->jetty_grp.rwlock, &dfx->jetty_grp, &res_ta->jetty_group_cnt},
		{&dfx->jfs.rwlock, &dfx->jfs, &res_ta->jfs_cnt},
		{&dfx->jfr.rwlock, &dfx->jfr, &res_ta->jfr_cnt},
		{&dfx->jfc.rwlock, &dfx->jfc, &res_ta->jfc_cnt},
		{&dfx->seg.rwlock, &dfx->seg, &res_ta->seg_cnt},
	};

	int size = ARRAY_SIZE(udma_dfx_entity_cnt_ta);
	int i;

	for (i = 0; i < size; i++) {
		read_lock(udma_dfx_entity_cnt_ta[i].rwlock);
		*udma_dfx_entity_cnt_ta[i].res_cnt =
			udma_dfx_entity_cnt_ta[i].entity->cnt;
		read_unlock(udma_dfx_entity_cnt_ta[i].rwlock);
	}

	return 0;
}

typedef int (*udma_query_res_handler)(struct udma_dev *udma_dev,
				      struct ubcore_res_key *key,
				      struct ubcore_res_val *val);

static udma_query_res_handler g_udma_query_res_handlers[] = {
	[0] = NULL,
	[UBCORE_RES_KEY_VTP] = NULL,
	[UBCORE_RES_KEY_TP] = NULL,
	[UBCORE_RES_KEY_TPG] = NULL,
	[UBCORE_RES_KEY_UTP] = NULL,
	[UBCORE_RES_KEY_JFS] = udma_query_res_jfs,
	[UBCORE_RES_KEY_JFR] = udma_query_res_jfr,
	[UBCORE_RES_KEY_JETTY] = udma_query_res_jetty,
	[UBCORE_RES_KEY_JETTY_GROUP] = udma_query_res_jetty_grp,
	[UBCORE_RES_KEY_JFC] = udma_query_res_jfc,
	[UBCORE_RES_KEY_RC] = udma_query_res_rc,
	[UBCORE_RES_KEY_SEG] = udma_query_res_seg,
	[UBCORE_RES_KEY_DEV_TA] = udma_query_res_dev_ta,
	[UBCORE_RES_KEY_DEV_TP] = NULL,
};

int udma_query_res(struct ubcore_device *dev, struct ubcore_res_key *key,
		   struct ubcore_res_val *val)
{
	struct udma_dev *udma_dev = to_udma_dev(dev);

	if (!dfx_switch) {
		dev_warn(udma_dev->dev, "the dfx_switch is not enabled.\n");
		return -EPERM;
	}

	if (key->type < UBCORE_RES_KEY_VTP || key->type > UBCORE_RES_KEY_DEV_TP ||
	    g_udma_query_res_handlers[key->type] == NULL) {
		dev_err(udma_dev->dev, "key type(%u) invalid.\n", key->type);
		return -EINVAL;
	}

	return g_udma_query_res_handlers[key->type](udma_dev, key, val);
}

static void list_lock_init(struct udma_dfx_info *dfx)
{
	struct udma_dfx_entity_initialization udma_dfx_entity_initialization_arr[] = {
		{&dfx->jetty.rwlock, &dfx->jetty.table},
		{&dfx->jetty_grp.rwlock, &dfx->jetty_grp.table},
		{&dfx->jfs.rwlock, &dfx->jfs.table},
		{&dfx->jfr.rwlock, &dfx->jfr.table},
		{&dfx->jfc.rwlock, &dfx->jfc.table},
		{&dfx->seg.rwlock, &dfx->seg.table},
	};
	int size = ARRAY_SIZE(udma_dfx_entity_initialization_arr);
	int i;

	for (i = 0; i < size; i++) {
		rwlock_init(udma_dfx_entity_initialization_arr[i].rwlock);
		xa_init(udma_dfx_entity_initialization_arr[i].table);
	}
}

int udma_dfx_init(struct udma_dev *udma_dev)
{
	if (!dfx_switch)
		return 0;

	udma_dev->dfx_info = kzalloc(sizeof(struct udma_dfx_info), GFP_KERNEL);
	if (!udma_dev->dfx_info)
		return -ENOMEM;

	list_lock_init(udma_dev->dfx_info);

	return 0;
}

static void udma_dfx_destroy_xa(struct udma_dev *udma_dev, struct xarray *table,
				const char *name)
{
	if (!xa_empty(table))
		dev_err(udma_dev->dev, "%s table is not empty.\n", name);
	xa_destroy(table);
}

static void udma_dfx_table_free(struct udma_dev *dev)
{
	udma_dfx_destroy_xa(dev, &dev->dfx_info->jetty.table, "jetty");
	udma_dfx_destroy_xa(dev, &dev->dfx_info->jetty_grp.table, "jetty_grp");
	udma_dfx_destroy_xa(dev, &dev->dfx_info->jfs.table, "jfs");
	udma_dfx_destroy_xa(dev, &dev->dfx_info->jfr.table, "jfr");
	udma_dfx_destroy_xa(dev, &dev->dfx_info->jfc.table, "jfc");
	udma_dfx_destroy_xa(dev, &dev->dfx_info->seg.table, "seg");
}

void udma_dfx_uninit(struct udma_dev *udma_dev)
{
	if (!dfx_switch)
		return;

	udma_dfx_table_free(udma_dev);
	kfree(udma_dev->dfx_info);
	udma_dev->dfx_info = NULL;
}

module_param(dfx_switch, bool, 0444);
MODULE_PARM_DESC(dfx_switch, "Set whether to enable the udma_dfx function, default: 0(0:off, 1:on)");
