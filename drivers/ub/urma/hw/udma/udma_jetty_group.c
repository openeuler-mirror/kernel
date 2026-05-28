// SPDX-License-Identifier: GPL-2.0+
/* Copyright(c) 2026 HiSilicon Technologies CO., Ltd. All rights reserved. */

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

static uint32_t udma_get_jetty_grp_jetty_id(uint32_t *valid, uint32_t *next)
{
	uint32_t bit_idx;

	bit_idx = find_next_zero_bit((unsigned long *)valid, UDMA_BITS_PER_INT, *next);
	if (bit_idx >= UDMA_BITS_PER_INT)
		bit_idx = find_next_zero_bit((unsigned long *)valid, UDMA_BITS_PER_INT, 0);

	*next = (*next + 1) >= UDMA_BITS_PER_INT ? 0 : *next + 1;

	return bit_idx;
}

static int update_jetty_grp_ctx_valid(struct udma_dev *udma_dev,
				      struct udma_jetty_grp *jetty_grp)
{
	struct udma_jetty_grp_ctx ctx[UDMA_CTX_NUM];
	struct ubase_mbx_attr mbox_attr = {};
	int ret;

	ctx[0].valid = jetty_grp->valid;
	/* jetty number indicates the location of the jetty with the largest ID. */
	ctx[0].jetty_number = fls(jetty_grp->valid) - 1;
	memset(ctx + 1, 0xff, sizeof(ctx[1]));
	ctx[1].valid = 0;
	ctx[1].jetty_number = 0;

	mbox_attr.tag = jetty_grp->jetty_grp_id;
	mbox_attr.op = UDMA_CMD_MODIFY_JETTY_GROUP_CONTEXT;
	ret = post_mailbox_update_ctx(udma_dev, ctx, sizeof(ctx), &mbox_attr);
	if (ret)
		dev_err(udma_dev->dev,
			"post mailbox update jetty group context failed, ret = %d.\n",
			ret);

	return ret;
}

int add_jetty_to_grp(struct udma_dev *udma_dev, struct ubcore_jetty_group *jetty_grp,
			    struct udma_jetty_queue *sq, uint32_t cfg_id)
{
	struct udma_jetty_grp *udma_jetty_grp = to_udma_jetty_grp(jetty_grp);
	uint32_t bit_idx = cfg_id - udma_jetty_grp->start_jetty_id;
	int ret = 0;

	mutex_lock(&udma_jetty_grp->valid_lock);

	if (cfg_id == 0)
		bit_idx = udma_get_jetty_grp_jetty_id(&udma_jetty_grp->valid,
						      &udma_jetty_grp->next_jetty_id);

	if (bit_idx >= UDMA_BITS_PER_INT || (udma_jetty_grp->valid & BIT(bit_idx))) {
		dev_err(udma_dev->dev, "jetty group(%u.%u) valid %u is full or user id(%u) error",
			udma_jetty_grp->jetty_grp_id, udma_jetty_grp->start_jetty_id,
			udma_jetty_grp->valid, cfg_id);
		ret = -ENOMEM;
		goto out;
	}

	udma_jetty_grp->valid |= BIT(bit_idx);
	sq->id = udma_jetty_grp->start_jetty_id + bit_idx;
	sq->jetty_grp = udma_jetty_grp;

	ret = update_jetty_grp_ctx_valid(udma_dev, udma_jetty_grp);
	if (ret) {
		dev_err(udma_dev->dev,
			"update jetty group context valid failed, jetty group id is %u.\n",
			udma_jetty_grp->jetty_grp_id);

		udma_jetty_grp->valid &= ~BIT(bit_idx);
	}
out:
	mutex_unlock(&udma_jetty_grp->valid_lock);

	return ret;
}

void remove_jetty_from_grp(struct udma_dev *udma_dev, struct udma_jetty *jetty)
{
	struct udma_jetty_grp *jetty_grp = jetty->sq.jetty_grp;
	uint32_t bit_idx;
	int ret;

	bit_idx = jetty->sq.id - jetty_grp->start_jetty_id;
	if (bit_idx >= UDMA_BITS_PER_INT) {
		dev_err(udma_dev->dev,
			"jetty id(%u) is not in jetty group, start jetty id(%u).\n",
			jetty->sq.id, jetty_grp->start_jetty_id);
		return;
	}

	mutex_lock(&jetty_grp->valid_lock);
	jetty_grp->valid &= ~BIT(bit_idx);
	jetty->sq.jetty_grp = NULL;

	ret = update_jetty_grp_ctx_valid(udma_dev, jetty_grp);
	if (ret)
		dev_err(udma_dev->dev,
			"update jetty group context valid failed, jetty group id is %u.\n",
			jetty_grp->jetty_grp_id);

	mutex_unlock(&jetty_grp->valid_lock);
}

int udma_check_jetty_grp_info(struct ubcore_tjetty_cfg *cfg, struct udma_dev *dev)
{
	if (cfg->type == UBCORE_JETTY_GROUP) {
		if (cfg->trans_mode != UBCORE_TP_RM) {
			dev_err(dev->dev,
				"import jetty group only support RM, transmode is %u.\n",
				cfg->trans_mode);
			return -EINVAL;
		}

		if (cfg->policy != UBCORE_JETTY_GRP_POLICY_HASH_HINT) {
			dev_err(dev->dev,
				"import jetty group only support hint, policy is %u.\n",
				cfg->policy);
			return -EINVAL;
		}
	}

	return 0;
}

static int udma_alloc_group_start_id(struct udma_dev *udma_dev,
				     struct udma_group_bitmap *bitmap_table,
				     uint32_t *start_jetty_id)
{
	int ret;

	ret = udma_adv_id_alloc(udma_dev, bitmap_table, start_jetty_id,
				true, bitmap_table->grp_next);
	if (ret) {
		ret = udma_adv_id_alloc(udma_dev, bitmap_table, start_jetty_id,
					true, bitmap_table->min);
		if (ret)
			return ret;
	}

	bitmap_table->grp_next = (*start_jetty_id + NUM_JETTY_PER_GROUP) >
				 bitmap_table->max ? bitmap_table->min :
				 (*start_jetty_id + NUM_JETTY_PER_GROUP);

	return 0;
}

static int udma_alloc_jetty_grp_id(struct udma_dev *udma_dev,
				   struct udma_jetty_grp *jetty_grp)
{
	int ret;

	ret = udma_alloc_group_start_id(udma_dev,
					&udma_dev->jetty_table.bitmap_table,
					&jetty_grp->start_jetty_id);
	if (ret) {
		dev_err(udma_dev->dev,
			"alloc jetty id for group failed, ret = %d.\n", ret);
		return ret;
	}

	ret = udma_id_alloc_auto_grow(udma_dev, &udma_dev->jetty_grp_table.ida_table,
				      &jetty_grp->jetty_grp_id);
	if (ret) {
		dev_err(udma_dev->dev,
			"alloc jetty group id failed, ret = %d.\n", ret);
		udma_adv_id_free(&udma_dev->jetty_table.bitmap_table,
				 jetty_grp->start_jetty_id, true);
		return ret;
	}

	jetty_grp->ubcore_jetty_grp.jetty_grp_id.id = jetty_grp->jetty_grp_id;

	return 0;
}

struct ubcore_jetty_group *udma_create_jetty_grp(struct ubcore_device *dev,
						 struct ubcore_jetty_grp_cfg *cfg,
						 struct ubcore_udata *udata)
{
	struct udma_dev *udma_dev = to_udma_dev(dev);
	struct ubase_mbx_attr mbox_attr = {};
	struct udma_jetty_grp_ctx ctx = {};
	struct udma_jetty_grp *jetty_grp;
	int ret;

	if (cfg->policy != UBCORE_JETTY_GRP_POLICY_HASH_HINT) {
		dev_err(udma_dev->dev, "policy %u not support.\n", cfg->policy);
		return NULL;
	}

	jetty_grp = kzalloc(sizeof(*jetty_grp), GFP_KERNEL);
	if (!jetty_grp)
		return NULL;

	ret = udma_alloc_jetty_grp_id(udma_dev, jetty_grp);
	if (ret)
		goto err_alloc_jetty_grp_id;

	ctx.start_jetty_id = jetty_grp->start_jetty_id;

	ret = xa_err(xa_store(&udma_dev->jetty_grp_table.xa,
			      jetty_grp->jetty_grp_id, jetty_grp, GFP_KERNEL));
	if (ret) {
		dev_err(udma_dev->dev,
			"store jetty group(%u) failed, ret = %d.\n",
			jetty_grp->jetty_grp_id, ret);
		goto err_store_jetty_grp;
	}

	mbox_attr.tag = jetty_grp->jetty_grp_id;
	mbox_attr.op = UDMA_CMD_CREATE_JETTY_GROUP_CONTEXT;
	ret = post_mailbox_update_ctx(udma_dev, &ctx, sizeof(ctx), &mbox_attr);
	if (ret) {
		dev_err(udma_dev->dev,
			"post mailbox update jetty ctx failed, ret = %d.\n", ret);
		goto err_post_mailbox;
	}

	mutex_init(&jetty_grp->valid_lock);
	refcount_set(&jetty_grp->ae_refcount, 1);
	init_completion(&jetty_grp->ae_comp);

	if (dfx_switch)
		udma_dfx_store_id(udma_dev, &udma_dev->dfx_info->jetty_grp,
				  jetty_grp->jetty_grp_id, "jetty_grp");

	return &jetty_grp->ubcore_jetty_grp;
err_post_mailbox:
	xa_erase(&udma_dev->jetty_grp_table.xa, jetty_grp->jetty_grp_id);
err_store_jetty_grp:
	udma_id_free(&udma_dev->jetty_grp_table.ida_table, jetty_grp->jetty_grp_id);
err_alloc_jetty_grp_id:
	kfree(jetty_grp);

	return NULL;
}

int udma_delete_jetty_grp(struct ubcore_jetty_group *jetty_grp)
{
	struct udma_jetty_grp *udma_jetty_grp = to_udma_jetty_grp(jetty_grp);
	struct udma_dev *udma_dev = to_udma_dev(jetty_grp->ub_dev);
	struct ubase_mbx_attr mbox_attr = {};
	int ret;

	mbox_attr.tag = udma_jetty_grp->jetty_grp_id;
	mbox_attr.op = UDMA_CMD_DESTROY_JETTY_GROUP_CONTEXT;
	ret = post_mailbox_update_ctx(udma_dev, NULL, 0, &mbox_attr);
	if (ret) {
		dev_err(udma_dev->dev,
			"post mailbox destroy jetty group failed, ret = %d.\n", ret);
		return ret;
	}

	xa_erase(&udma_dev->jetty_grp_table.xa, udma_jetty_grp->jetty_grp_id);

	if (refcount_dec_and_test(&udma_jetty_grp->ae_refcount))
		complete(&udma_jetty_grp->ae_comp);
	wait_for_completion(&udma_jetty_grp->ae_comp);

	if (dfx_switch)
		udma_dfx_delete_id(udma_dev, &udma_dev->dfx_info->jetty_grp,
				   udma_jetty_grp->jetty_grp_id);

	if (udma_jetty_grp->valid != 0)
		dev_err(udma_dev->dev,
			"jetty group been used, jetty valid is 0x%x.\n",
			udma_jetty_grp->valid);

	mutex_destroy(&udma_jetty_grp->valid_lock);
	udma_id_free(&udma_dev->jetty_grp_table.ida_table,
		     udma_jetty_grp->jetty_grp_id);
	udma_adv_id_free(&udma_dev->jetty_table.bitmap_table,
			 udma_jetty_grp->start_jetty_id, true);
	kfree(udma_jetty_grp);

	return ret;
}
