// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 *
 * Description: ubagg dfx support
 */

#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

#include "ubagg_dfx.h"
#include "ubagg_hash_table.h"
#include "ubagg_log.h"
#include "ubagg_types.h"

static struct ubagg_hash_table *
ubagg_get_res_ht(struct ubagg_device *ubagg_dev,
		 enum ubagg_show_res_type res_type)
{
	switch (res_type) {
	case UBAGG_SHOW_RES_JETTY:
		return &ubagg_dev->ubagg_ht[UBAGG_HT_JETTY_HT];
	case UBAGG_SHOW_RES_JFR:
		return &ubagg_dev->ubagg_ht[UBAGG_HT_JFR_HT];
	case UBAGG_SHOW_RES_JFS:
		return &ubagg_dev->ubagg_ht[UBAGG_HT_JFS_HT];
	case UBAGG_SHOW_RES_JFC:
		return &ubagg_dev->ubagg_ht[UBAGG_HT_JFC_HT];
	case UBAGG_SHOW_RES_SEG:
		return &ubagg_dev->ubagg_ht[UBAGG_HT_SEGMENT_HT];
	default:
		return NULL;
	}
}

static int ubagg_get_show_res_size(enum ubagg_show_res_type res_type,
				   size_t *out_size)
{
	switch (res_type) {
	case UBAGG_SHOW_RES_JETTY:
	case UBAGG_SHOW_RES_JFR:
		*out_size = sizeof(struct ubagg_jetty_exchange_info);
		return 0;
	case UBAGG_SHOW_RES_JFS:
	case UBAGG_SHOW_RES_JFC:
		*out_size = sizeof(struct ubagg_jetty_id) * UBAGG_DEV_MAX_NUM;
		return 0;
	case UBAGG_SHOW_RES_SEG:
		*out_size = sizeof(struct ubagg_seg_exchange_info);
		return 0;
	default:
		return -EINVAL;
	}
}

static int ubagg_list_v2p_res(struct ubagg_device *ubagg_dev,
			      const struct ubagg_show_res *req,
			      struct ubagg_cmd_v2p_res *arg)
{
	struct ubagg_hash_table *ht;
	struct hlist_node *pos = NULL;
	struct hlist_node *n = NULL;
	uint32_t *id_buf;
	uint32_t count = 0;
	uint32_t cap;
	size_t buf_len;

	ht = ubagg_get_res_ht(ubagg_dev, req->res_type);
	if (ht == NULL || ht->head == NULL) {
		ubagg_log_err("unsupported res_type: %u\n", req->res_type);
		return -EINVAL;
	}

	spin_lock(&ht->lock);
	for (uint32_t i = 0; i < ht->p.size; i++)
		hlist_for_each_safe(pos, n, &ht->head[i])
			count++;
	spin_unlock(&ht->lock);

	if (count == 0) {
		arg->out.len = 0;
		return 0;
	}

	cap = count;
	buf_len = cap * sizeof(*id_buf);
	id_buf = kvmalloc_array(cap, sizeof(*id_buf), GFP_KERNEL);
	if (id_buf == NULL)
		return -ENOMEM;

	count = 0;
	spin_lock(&ht->lock);
	for (uint32_t i = 0; i < ht->p.size; i++) {
		hlist_for_each_safe(pos, n, &ht->head[i]) {
			void *key = ubagg_ht_key(ht, pos);

			if (key != NULL) {
				if (count == cap) {
					spin_unlock(&ht->lock);
					kvfree(id_buf);
					return -EAGAIN;
				}
				id_buf[count++] = *(uint32_t *)key;
			}
		}
	}
	spin_unlock(&ht->lock);

	if (arg->out.addr != 0 &&
	    copy_to_user((void __user *)(uintptr_t)arg->out.addr, id_buf,
			 count * sizeof(*id_buf)) != 0) {
		kvfree(id_buf);
		return -EFAULT;
	}

	arg->out.len = count * sizeof(*id_buf);
	kvfree(id_buf);
	return 0;
}

static int ubagg_show_v2p_res(struct ubagg_device *ubagg_dev,
			      const struct ubagg_show_res *res,
			      struct ubagg_cmd_v2p_res *arg)
{
	struct ubagg_hash_table *ht;
	void *data_buf;
	uint32_t id = res->jetty_id.id;
	size_t out_size = 0;
	int ret;

	ht = ubagg_get_res_ht(ubagg_dev, res->res_type);
	ret = ubagg_get_show_res_size(res->res_type, &out_size);
	if (ht == NULL || ht->head == NULL || ret != 0) {
		ubagg_log_err("unsupported res_type: %u\n", res->res_type);
		return -EINVAL;
	}

	data_buf = kvzalloc(out_size, GFP_KERNEL);
	if (data_buf == NULL)
		return -ENOMEM;

	spin_lock(&ht->lock);
	switch (res->res_type) {
	case UBAGG_SHOW_RES_JETTY: {
		struct ubagg_jetty_hash_node *node;

		node = ubagg_hash_table_lookup_nolock(ht, id, &id);
		if (node == NULL) {
			spin_unlock(&ht->lock);
			ubagg_log_err("Failed to find jetty, id:%u.\n", id);
			kvfree(data_buf);
			return -ENOENT;
		}
		memcpy(data_buf, &node->ex_info, out_size);
		break;
	}
	case UBAGG_SHOW_RES_JFR: {
		struct ubagg_jfr_hash_node *node;

		node = ubagg_hash_table_lookup_nolock(ht, id, &id);
		if (node == NULL) {
			spin_unlock(&ht->lock);
			ubagg_log_err("Failed to find jfr, id:%u.\n", id);
			kvfree(data_buf);
			return -ENOENT;
		}
		memcpy(data_buf, &node->ex_info, out_size);
		break;
	}
	case UBAGG_SHOW_RES_JFS: {
		struct ubagg_jfs *node;

		node = ubagg_hash_table_lookup_nolock(ht, id, &id);
		if (node == NULL) {
			spin_unlock(&ht->lock);
			ubagg_log_err("Failed to find jfs, id:%u.\n", id);
			kvfree(data_buf);
			return -ENOENT;
		}
		memcpy(data_buf, node->slaves, out_size);
		break;
	}
	case UBAGG_SHOW_RES_JFC: {
		struct ubagg_jfc *node;

		node = ubagg_hash_table_lookup_nolock(ht, id, &id);
		if (node == NULL) {
			spin_unlock(&ht->lock);
			ubagg_log_err("Failed to find jfc, id:%u.\n", id);
			kvfree(data_buf);
			return -ENOENT;
		}
		memcpy(data_buf, node->slaves, out_size);
		break;
	}
	case UBAGG_SHOW_RES_SEG: {
		struct ubagg_seg_hash_node *node;

		node = ubagg_hash_table_lookup_nolock(ht, id, &id);
		if (node == NULL) {
			spin_unlock(&ht->lock);
			ubagg_log_err("Failed to find seg, id:%u.\n", id);
			kvfree(data_buf);
			return -ENOENT;
		}
		memcpy(data_buf, &node->ex_info, out_size);
		break;
	}
	default:
		spin_unlock(&ht->lock);
		kvfree(data_buf);
		return -EINVAL;
	}
	spin_unlock(&ht->lock);

	if (arg->out.addr != 0 &&
	    copy_to_user((void __user *)(uintptr_t)arg->out.addr, data_buf,
			 out_size) != 0) {
		kvfree(data_buf);
		return -EFAULT;
	}

	arg->out.len = (uint32_t)out_size;
	kvfree(data_buf);
	return 0;
}

int ubagg_query_v2p_res(struct ubagg_device *ubagg_dev,
			struct ubagg_cmd_v2p_res *arg)
{
	struct ubagg_show_res res = { 0 };

	if (ubagg_dev == NULL || arg == NULL)
		return -EINVAL;

	if (arg->in.type >= UBAGG_SHOW_RES_MAX) {
		ubagg_log_err("unsupported query_v2p_res type: %u\n",
			      arg->in.type);
		return -EINVAL;
	}

	res.res_type = (enum ubagg_show_res_type)arg->in.type;
	res.jetty_id.id = arg->in.key;
	if (arg->in.key_cnt == 0)
		return ubagg_list_v2p_res(ubagg_dev, &res, arg);

	return ubagg_show_v2p_res(ubagg_dev, &res, arg);
}
