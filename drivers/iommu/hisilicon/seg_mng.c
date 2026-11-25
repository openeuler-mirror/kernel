// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * Description: UMMU segment tree manager
 */

#define pr_fmt(fmt) "UMMU: " fmt

#include <linux/errno.h>
#include <linux/kernel.h>

#include "seg_tree.h"
#include "seg_mng.h"

static int ummu_compare(u64 left, u64 size, void *data)
{
	struct ummu_seg_info *seg = data;

	if (seg->start_addr == left && seg->grant_size == size)
		return RANGE_MATCH;

	if ((left + size) < seg->start_addr)
		return RANGE_NOT_EXIST;

	return RANGE_OVERLAP;
}

static enum ummu_grant_op_type ummu_table_param_check(struct ummu_seg_info *exist_addr,
						      struct ummu_data_info *grant_param)
{
	if ((exist_addr->token_check == 1 && grant_param->token_check == 1) &&
	    (exist_addr->permission == grant_param->perm) &&
	    (exist_addr->e_bit == grant_param->e_bit) &&
	    (exist_addr->token_count == 1))
		return UMMU_ADD_TOKEN;

	pr_err("granted addr info: token_check=%u, token_count=%u, permission=%d e_bit=%d.\n",
		exist_addr->token_check, exist_addr->token_count, exist_addr->permission,
		exist_addr->e_bit);
	pr_err("target addr info: token_check=%u, permission=%d, e_bit=%d.\n",
		grant_param->token_check, grant_param->perm, grant_param->e_bit);
	return UMMU_OP_END;
}

static enum ummu_grant_op_type ummu_ungrant_param_check(struct ummu_seg_info *exist_addr,
							struct ummu_data_info *grant_param)
{
	if (grant_param->bytoken == 0)
		return UMMU_UNGRANT;

	if (exist_addr->token_check == 0) {
		pr_err("Target segment grant without token, cannot ungrant by token.\n");
		return UMMU_OP_END;
	}

	if (exist_addr->token_val[0] == grant_param->tokenval ||
	    exist_addr->token_val[1] == grant_param->tokenval) {
		if (exist_addr->token_count == 1)
			return UMMU_UNGRANT;
		else if (exist_addr->token_count == UMMU_MAX_TOKEN_NUM)
			return UMMU_REMOVE_TOKEN;
	}

	pr_err("Token not match.\n");
	return UMMU_OP_END;
}

static void ummu_remove_tokenval(u32 tokenval, struct ummu_seg_info *data)
{
	if (data->token_val[0] == tokenval)
		data->token_val[0] = data->token_val[1];
	else if (data->token_val[1] == tokenval)
		data->token_val[1] = data->token_val[0];

	data->token_count = 1;
}

static enum ummu_grant_op_type ummu_entry_param_check(struct ummu_mapt_info *mapt_info,
						      struct ummu_data_info *grant_param)
{
	struct ummu_mapt_entry_node *node = mapt_info->block_base.entry_block;
	u64 base, limit;

	if (mapt_info->block_base.entry_block->valid == 0)
		return UMMU_GRANT;

	base = ADDR_FULL(node->base_low, node->base_high);
	limit = ADDR_FULL(node->limit_low, node->limit_high);
	if ((base == grant_param->data_base) &&
	    (limit == grant_param->data_limit) &&
	    (node->token_check == 1 && grant_param->token_check == 1) &&
	    (node->permission == (u32)grant_param->perm) &&
	    ((int)node->e_bit == (int)grant_param->e_bit) && (node->nonce == 1))
		return UMMU_ADD_TOKEN;

	pr_err("Node data check failed!\n");
	pr_debug("node.perm = %d, ", (int)node->permission);
	pr_debug("node.e_bit = %d, node.token_check = %d, node.nonce = %d, ",
		(int)node->e_bit, (int)node->token_check, (int)node->nonce);
	pr_debug("perm = %d,e_bit = %d, token_check = %d.\n",
		(int)grant_param->perm, (int)grant_param->e_bit, (int)grant_param->token_check);

	return UMMU_OP_END;
}

enum ummu_grant_op_type ummu_grant_check(struct ummu_mapt_info *mapt_info,
					 struct ummu_data_info *grant_param)
{
	struct ummu_seg_info *data;
	int comp_ret;

	if (mapt_info->mode == MAPT_MODE_ENTRY)
		return ummu_entry_param_check(mapt_info, grant_param);

	if (!mapt_info->block_base.table_ctx->granted_addr_mng) {
		pr_err("Granted addr manager invalid.\n");
		return UMMU_OP_END;
	}

	data = ummu_find_seg(grant_param->data_base, grant_param->data_size - 1,
			     mapt_info->block_base.table_ctx->granted_addr_mng, ummu_compare,
			     &comp_ret);

	switch (comp_ret) {
	case RANGE_MATCH:
		return ummu_table_param_check(data, grant_param);
	case RANGE_OVERLAP:
		return UMMU_OP_END;
	case RANGE_NOT_EXIST:
		return UMMU_GRANT;
	default:
		pr_err("check grant addr state failed.\n");
		return UMMU_OP_END;
	}
}

static enum ummu_grant_op_type ummu_entry_ungrant_param_check(struct ummu_mapt_info *mapt_info,
							      struct ummu_data_info *grant_param)
{
	struct ummu_mapt_entry_node *node = mapt_info->block_base.entry_block;

	if (mapt_info->block_base.entry_block->valid == 0) {
		pr_err("Entry block is not used.\n");
		return UMMU_OP_END;
	}

	if ((ADDR_FULL(node->base_low, node->base_high) != grant_param->data_base) ||
	    (ADDR_FULL(node->limit_low, node->limit_high) != grant_param->data_limit)) {
		pr_err("Base or limit not equal.\n");
		return UMMU_OP_END;
	}

	if (grant_param->bytoken == 0)
		return UMMU_UNGRANT;

	if (node->token_check == 1) {
		if ((node->token_val_0 != grant_param->tokenval) &&
		    (node->token_val_1 != grant_param->tokenval)) {
			pr_err("Token not match.\n");
			return UMMU_OP_END;
		}

		if (node->nonce == 1)
			return UMMU_UNGRANT;
		else if (node->nonce == UMMU_MAX_TOKEN_NUM)
			return UMMU_REMOVE_TOKEN;
	}

	pr_err("Check ungrant param failed. Input bytoken=%d, exist token_check=%d.\n",
		grant_param->bytoken, (int)node->token_check);
	return UMMU_OP_END;
}

enum ummu_grant_op_type ummu_ungrant_check(struct ummu_mapt_info *mapt_info,
					   struct ummu_data_info *grant_param)
{
	struct ummu_seg_info *data;
	int comp_ret;

	if (mapt_info->mode == MAPT_MODE_ENTRY)
		return ummu_entry_ungrant_param_check(mapt_info, grant_param);

	if (!mapt_info->block_base.table_ctx->granted_addr_mng) {
		pr_err("Ungrant input param invalid.\n");
		return UMMU_OP_END;
	}

	data = ummu_find_seg(grant_param->data_base, grant_param->data_size - 1,
			     mapt_info->block_base.table_ctx->granted_addr_mng, ummu_compare,
			     &comp_ret);
	if ((data == NULL) || (comp_ret != RANGE_MATCH)) {
		pr_err("find target address range failed.\n");
		return UMMU_OP_END;
	}

	return ummu_ungrant_param_check(data, grant_param);
}

struct maple_tree *ummu_create_seg_mng(void)
{
	return ummu_create_seg_tree();
}

static void clear_seg_info(void *data)
{
	struct ummu_seg_info *grant_info = data;

	grant_info->token_val[0] = 0;
	grant_info->token_val[1] = 0;
}

void ummu_destroy_seg_mng(struct maple_tree *seg_table)
{
	ummu_destroy_seg_tree(seg_table, clear_seg_info);
}

int ummu_insert_new_addr(struct maple_tree *seg_table, struct ummu_data_info *grant_param)
{
	struct ummu_seg_info *grant_info;
	int ret;

	grant_info = kzalloc(sizeof(*grant_info), GFP_KERNEL);
	if (!grant_info)
		return -ENOMEM;

	grant_info->grant_size = grant_param->data_size - 1;
	grant_info->start_addr = grant_param->data_base;
	grant_info->e_bit = grant_param->e_bit;
	grant_info->permission = grant_param->perm;
	grant_info->token_check = grant_param->token_check;
	if (grant_info->token_check) {
		grant_info->token_count = 1;
		grant_info->token_val[0] = grant_param->tokenval;
		grant_info->token_val[1] = grant_param->tokenval;
	}

	ret = ummu_insert_seg((void *)grant_info, seg_table, grant_info->start_addr,
			      grant_info->grant_size);
	if (ret) {
		grant_info->token_val[0] = 0;
		grant_info->token_val[1] = 0;
		kfree(grant_info);
	}
	return ret;
}

int ummu_delete_addr(struct maple_tree *seg_table, struct ummu_data_info *grant_param)
{
	return ummu_delete_seg(grant_param->data_base, grant_param->data_size - 1, seg_table,
			       ummu_compare, clear_seg_info);
}

int ummu_token_update(struct maple_tree *seg_table, struct ummu_data_info *grant_param,
		      enum ummu_grant_op_type op)
{
	struct ummu_seg_info *data;
	int find_ret;

	data = ummu_find_seg(grant_param->data_base, grant_param->data_size - 1, seg_table,
			     ummu_compare, &find_ret);
	if ((data == NULL) || (find_ret != RANGE_MATCH)) {
		pr_err("find grant address info failed.\n");
		return -EINVAL;
	}

	if (op == UMMU_REMOVE_TOKEN) {
		ummu_remove_tokenval(grant_param->tokenval, data);
		return 0;
	}

	data->token_val[1] = grant_param->tokenval;
	data->token_count = UMMU_MAX_TOKEN_NUM;
	return 0;
}
