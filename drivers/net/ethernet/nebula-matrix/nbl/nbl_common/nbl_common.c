// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#include "nbl_common.h"

struct nbl_common_wq_mgt {
	struct workqueue_struct *ctrl_dev_wq2;
	struct workqueue_struct *net_dev_wq;
	struct workqueue_struct *rdma_wq;
	struct workqueue_struct *rdma_event_wq;
};

void nbl_convert_mac(u8 *mac, u8 *reverse_mac)
{
	int i;

	for (i = 0; i < ETH_ALEN; i++)
		reverse_mac[i] = mac[ETH_ALEN - 1 - i];
}

static struct nbl_common_wq_mgt *wq_mgt;

void nbl_common_queue_work(struct work_struct *task, bool ctrl_task)
{
	if (ctrl_task)
		queue_work(wq_mgt->ctrl_dev_wq2, task);
	else if (!ctrl_task)
		queue_work(wq_mgt->net_dev_wq, task);
}

void nbl_common_queue_work_rdma(struct work_struct *task, bool singlethread)
{
	if (singlethread)
		queue_work(wq_mgt->rdma_wq, task);
	else
		queue_work(wq_mgt->rdma_event_wq, task);
}

void nbl_common_queue_delayed_work(struct delayed_work *task, u32 msec, bool ctrl_task)
{
	if (ctrl_task)
		queue_delayed_work(wq_mgt->ctrl_dev_wq2, task, msecs_to_jiffies(msec));
	else if (!ctrl_task)
		queue_delayed_work(wq_mgt->net_dev_wq, task, msecs_to_jiffies(msec));
}

void nbl_common_release_task(struct work_struct *task)
{
	cancel_work_sync(task);
}

void nbl_common_alloc_task(struct work_struct *task, void *func)
{
	INIT_WORK(task, func);
}

void nbl_common_release_delayed_task(struct delayed_work *task)
{
	cancel_delayed_work_sync(task);
}

void nbl_common_alloc_delayed_task(struct delayed_work *task, void *func)
{
	INIT_DELAYED_WORK(task, func);
}

void nbl_common_flush_task(struct work_struct *task)
{
	flush_work(task);
}

void nbl_common_flush_delay_task(struct delayed_work *task)
{
	flush_delayed_work(task);
}

void nbl_common_destroy_wq(void)
{
	destroy_workqueue(wq_mgt->rdma_event_wq);
	destroy_workqueue(wq_mgt->rdma_wq);
	destroy_workqueue(wq_mgt->net_dev_wq);
	destroy_workqueue(wq_mgt->ctrl_dev_wq2);
	kfree(wq_mgt);
}

int nbl_common_create_wq(void)
{
	wq_mgt = kzalloc(sizeof(*wq_mgt), GFP_KERNEL);
	if (!wq_mgt)
		return -ENOMEM;

	wq_mgt->ctrl_dev_wq2 = alloc_workqueue("%s", WQ_MEM_RECLAIM | WQ_UNBOUND,
					       0, "nbl_ctrldev_wq2");
	if (!wq_mgt->ctrl_dev_wq2) {
		pr_err("Failed to create workqueue nbl_ctrldev_wq2\n");
		goto alloc_ctrl_dev_wq2_failed;
	}

	wq_mgt->net_dev_wq = alloc_workqueue("%s", WQ_MEM_RECLAIM | WQ_UNBOUND,
					     0, "nbl_net_dev_wq1");
	if (!wq_mgt->net_dev_wq) {
		pr_err("Failed to create workqueue nbl_net_dev_wq1\n");
		goto alloc_net_dev_wq_failed;
	}

	wq_mgt->rdma_wq = create_singlethread_workqueue("nbl_rdma_wq1");
	if (!wq_mgt->rdma_wq) {
		pr_err("Failed to create workqueue nbl_rdma_wq1\n");
		goto alloc_rdma_wq_failed;
	}

	wq_mgt->rdma_event_wq = alloc_workqueue("%s", WQ_UNBOUND, 0, "nbl_rdma_wq2");
	if (!wq_mgt->rdma_event_wq) {
		pr_err("Failed to create workqueue nbl_rdma_wq2\n");
		goto alloc_rdma_event_wq_failed;
	}

	return 0;

alloc_rdma_event_wq_failed:
	destroy_workqueue(wq_mgt->rdma_wq);
alloc_rdma_wq_failed:
	destroy_workqueue(wq_mgt->net_dev_wq);
alloc_net_dev_wq_failed:
	destroy_workqueue(wq_mgt->ctrl_dev_wq2);
alloc_ctrl_dev_wq2_failed:
	kfree(wq_mgt);
	return -ENOMEM;
}

u32 nbl_common_pf_id_subtraction_mgtpf_id(struct nbl_common_info *common, u32 pf_id)
{
	u32 diff = U32_MAX;

	if (pf_id >= NBL_COMMON_TO_MGT_PF(common))
		diff = pf_id - NBL_COMMON_TO_MGT_PF(common);

	return diff;
}

/**
 * alloc a index resource poll, the index_size max is 64 * 1024
 * the poll support start_index not zero;
 */
void *nbl_common_init_index_table(struct nbl_index_tbl_key *key)
{
	struct nbl_index_mgt *index_mgt;
	int bucket_size;
	int i;

	if (key->index_size > NBL_INDEX_SIZE_MAX)
		return NULL;

	index_mgt = devm_kzalloc(key->dev, sizeof(struct nbl_index_mgt), GFP_KERNEL);
	if (!index_mgt)
		return NULL;

	index_mgt->bitmap = devm_kcalloc(key->dev, BITS_TO_LONGS(key->index_size),
					 sizeof(long), GFP_KERNEL);
	if (!index_mgt->bitmap)
		goto alloc_bitmap_failed;

	bucket_size = DIV_ROUND_UP(key->index_size, NBL_INDEX_HASH_DIVISOR);
	index_mgt->key_hash = devm_kcalloc(key->dev, bucket_size,
					   sizeof(struct hlist_head), GFP_KERNEL);
	if (!index_mgt->key_hash)
		goto alloc_key_hash_failed;

	for (i = 0; i < bucket_size; i++)
		INIT_HLIST_HEAD(index_mgt->key_hash + i);

	memcpy(&index_mgt->tbl_key, key, sizeof(struct nbl_index_tbl_key));
	index_mgt->free_index_num = key->index_size;
	index_mgt->bucket_size = bucket_size;

	return index_mgt;

alloc_key_hash_failed:
	devm_kfree(key->dev, index_mgt->bitmap);
alloc_bitmap_failed:
	devm_kfree(key->dev, index_mgt);

	return NULL;
}

static void nbl_common_free_index_node(struct nbl_index_mgt *index_mgt,
				       struct nbl_index_entry_node *idx_node)
{
	int i;
	u32 free_index;

	free_index = idx_node->index - index_mgt->tbl_key.start_index;
	for (i = 0; i < idx_node->index_num; i++)
		clear_bit(free_index + i, index_mgt->bitmap);
	index_mgt->free_index_num += idx_node->index_num;
	hlist_del(&idx_node->node);
	devm_kfree(index_mgt->tbl_key.dev, idx_node);
}

void nbl_common_remove_index_table(void *priv, struct nbl_index_tbl_del_key *key)
{
	struct nbl_index_mgt *index_mgt = (struct nbl_index_mgt *)priv;
	struct device *dev;
	struct nbl_index_entry_node *idx_node;
	struct hlist_node *list_node;
	int i;

	if (!index_mgt)
		return;

	dev = index_mgt->tbl_key.dev;
	for (i = 0; i < index_mgt->bucket_size; i++) {
		hlist_for_each_entry_safe(idx_node, list_node, index_mgt->key_hash + i, node) {
			if (key && key->action_func)
				key->action_func(key->action_priv, idx_node->index, idx_node->data);
			nbl_common_free_index_node(index_mgt, idx_node);
		}
	}

	devm_kfree(dev, index_mgt->bitmap);
	devm_kfree(dev, index_mgt->key_hash);
	devm_kfree(dev, index_mgt);
}

void nbl_common_scan_index_table(void *priv, struct nbl_index_tbl_scan_key *key)
{
	struct nbl_index_mgt *index_mgt = (struct nbl_index_mgt *)priv;
	struct nbl_index_entry_node *idx_node;
	struct hlist_node *list_node;
	int i;

	if (!index_mgt)
		return;

	for (i = 0; i < index_mgt->bucket_size; i++) {
		hlist_for_each_entry_safe(idx_node, list_node, index_mgt->key_hash + i, node) {
			if (key && key->action_func)
				key->action_func(key->action_priv, idx_node->index, idx_node->data);
			if (key && key->del)
				nbl_common_free_index_node(index_mgt, idx_node);
		}
	}
}

static u32 nbl_common_calculate_hash_key(void *key, u32 key_size, u32 bucket_size)
{
	u32 i;
	u32 value = 0;
	u32 hash_value;

	/* if bucket size little than 1, the hash value always 0 */
	if (bucket_size == NBL_HASH_TBL_LIST_BUCKET_SIZE)
		return 0;

	for (i = 0; i < key_size; i++)
		value += *((u8 *)key + i);

	hash_value = __hash_32(value);

	return hash_value % bucket_size;
}

int nbl_common_find_available_idx(unsigned long *addr, u32 size, u32 idx_num, u32 multiple)
{
	u32 first_idx;
	u32 next_idx;
	u32 cur_idx;
	u32 idx_num_tmp;

	first_idx = find_first_zero_bit(addr, size);
	/* most find a index */
	if (idx_num == 1)
		return first_idx;

	while (first_idx < size) {
		if (first_idx % multiple == 0) {
			idx_num_tmp = idx_num - 1;
			cur_idx = first_idx;
			while (cur_idx < size && idx_num_tmp > 0) {
				next_idx = find_next_zero_bit(addr, size, cur_idx + 1);
				if (next_idx - cur_idx != 1)
					break;
				idx_num_tmp--;
				cur_idx = next_idx;
			}

			/* has reach tail, return err */
			if (cur_idx >= size)
				return size;

			/* has find available idx, return the begin idx */
			if (!idx_num_tmp)
				return first_idx;

			first_idx = first_idx + multiple;
		} else {
			first_idx = first_idx + 1;
		}

		first_idx = find_next_zero_bit(addr, size, first_idx);
	}

	return size;
}

/**
 * alloc available index
 * it support alloc continuous idx (num > 1) and can select base_idx's multiple
 * input
 *	@key: must not NULL;
 *	@key_size: must > 0;
 *	@extra_key: if alloc idx num > 1, e extra_key must not NULL, detail see
		struct nbl_index_key_extra
 *	@data: the node include extra data if not NULL
 *	@data_size:
 *	@output_data: optional, return the tbl's data if the output_data not NULL
 */
int nbl_common_alloc_index(void *priv, void *key, struct nbl_index_key_extra *extra_key,
			   void *data, u32 data_size, void **output_data)
{
	struct nbl_index_mgt *index_mgt = (struct nbl_index_mgt *)priv;
	struct nbl_index_entry_node *idx_node;
	u32 key_node_size;
	u32 index = U32_MAX;
	u32 hash_value;
	u32 base_index;
	u32 key_size = index_mgt->tbl_key.key_size;
	u32 idx_num = 1;
	u32 idx_multiple = 1;
	u32 i;

	if (!index_mgt->free_index_num)
		return index;

	if (extra_key) {
		idx_num = extra_key->index_num;
		idx_multiple = extra_key->begin_idx_multiple;
	}

	base_index = nbl_common_find_available_idx(index_mgt->bitmap,
						   index_mgt->tbl_key.index_size, idx_num,
						   idx_multiple);
	if (base_index >= index_mgt->tbl_key.index_size)
		return index;

	key_node_size = sizeof(struct nbl_index_entry_node) + key_size + data_size;
	idx_node = devm_kzalloc(index_mgt->tbl_key.dev, key_node_size, GFP_ATOMIC);
	if (!idx_node)
		return index;

	for (i = 0; i < idx_num; i++)
		set_bit(base_index + i, index_mgt->bitmap);

	index_mgt->free_index_num -= idx_num;
	index = base_index + index_mgt->tbl_key.start_index;
	hash_value = nbl_common_calculate_hash_key(key, key_size, index_mgt->bucket_size);
	idx_node->index = index;
	idx_node->index_num = idx_num;
	memcpy(idx_node->data, key, key_size);
	if (data)
		memcpy(idx_node->data + key_size, data, data_size);

	if (output_data)
		*output_data = idx_node->data + key_size;

	hlist_add_head(&idx_node->node, index_mgt->key_hash + hash_value);

	return index;
}

/**
 * if the key has alloced available index, return the base index;
 * default alloc available index, if not alloc, struct nbl_index_key_extra need
 * it support alloc continuous idx (num > 1) and can select base_idx's multiple
 * input
 *	@extra_key: if alloc idx num > 1, the extra_key must not NULL, detail see
		struct nbl_index_key_extra
 */
int nbl_common_get_index(void *priv, void *key, struct nbl_index_key_extra *extra_key)
{
	struct nbl_index_mgt *index_mgt = (struct nbl_index_mgt *)priv;
	struct nbl_index_entry_node *idx_node;
	u32 index = U32_MAX;
	u32 hash_value;
	u32 key_size = index_mgt->tbl_key.key_size;

	hash_value = nbl_common_calculate_hash_key(key, key_size, index_mgt->bucket_size);
	hlist_for_each_entry(idx_node, index_mgt->key_hash + hash_value, node)
		if (!memcmp(idx_node->data, key, key_size)) {
			index = idx_node->index;
			goto out;
		}

	if (extra_key && extra_key->not_alloc_new_node)
		goto out;

	index = nbl_common_alloc_index(index_mgt, key, extra_key, NULL, 0, NULL);
out:
	return index;
}

/**
 * if the key has alloced available index, return the base index;
 * default alloc available index, if not alloc, struct nbl_index_key_extra need
 * it support alloc continuous idx (num > 1) and can select base_idx's multiple
 * input
 *	@key: must not NULL;
 *	@key_size: must > 0;
 *	@extra_key: if alloc idx num > 1, e extra_key must not NULL, detail see
			struct nbl_index_key_extra
 *	@data: the node include extra data if not NULL
 *	@data_size:
 *	@output_data: optional, return the tbl's data if the output_data not NULL
 */
int nbl_common_get_index_with_data(void *priv, void *key, struct nbl_index_key_extra *extra_key,
				   void *data, u32 data_size, void **output_data)
{
	struct nbl_index_mgt *index_mgt = (struct nbl_index_mgt *)priv;
	struct nbl_index_entry_node *idx_node;
	u32 index = U32_MAX;
	u32 hash_value;
	u32 key_size = index_mgt->tbl_key.key_size;

	hash_value = nbl_common_calculate_hash_key(key, key_size, index_mgt->bucket_size);
	hlist_for_each_entry(idx_node, index_mgt->key_hash + hash_value, node)
		if (!memcmp(idx_node->data, key, key_size)) {
			index = idx_node->index;
			if (output_data)
				*output_data = idx_node->data + key_size;
			goto out;
		}

	if (extra_key && extra_key->not_alloc_new_node)
		goto out;

	index = nbl_common_alloc_index(index_mgt, key, extra_key, data, data_size, output_data);
out:
	return index;
}

void nbl_common_free_index(void *priv, void *key)
{
	struct nbl_index_mgt *index_mgt = (struct nbl_index_mgt *)priv;
	struct nbl_index_entry_node *idx_node;
	u32 hash_value;
	u32 key_size = index_mgt->tbl_key.key_size;

	hash_value = nbl_common_calculate_hash_key(key, key_size, index_mgt->bucket_size);
	hlist_for_each_entry(idx_node, index_mgt->key_hash + hash_value, node)
		if (!memcmp(idx_node->data, key, key_size)) {
			nbl_common_free_index_node(index_mgt, idx_node);
			return;
		}
}

/**
 * alloc a hash table
 * the table support multi thread
 */
void *nbl_common_init_hash_table(struct nbl_hash_tbl_key *key)
{
	struct nbl_hash_tbl_mgt *tbl_mgt;
	int bucket_size;
	int i;

	tbl_mgt = devm_kzalloc(key->dev, sizeof(struct nbl_hash_tbl_mgt), GFP_KERNEL);
	if (!tbl_mgt)
		return NULL;

	bucket_size = key->bucket_size;
	tbl_mgt->hash = devm_kcalloc(key->dev, bucket_size,
				     sizeof(struct hlist_head), GFP_KERNEL);
	if (!tbl_mgt->hash)
		goto alloc_hash_failed;

	for (i = 0; i < bucket_size; i++)
		INIT_HLIST_HEAD(tbl_mgt->hash + i);

	memcpy(&tbl_mgt->tbl_key, key, sizeof(struct nbl_hash_tbl_key));

	if (key->lock_need)
		mutex_init(&tbl_mgt->lock);

	return tbl_mgt;

alloc_hash_failed:
	devm_kfree(key->dev, tbl_mgt);

	return NULL;
}

/**
 * alloc a hash node, and add to hlist_head
 */
int nbl_common_alloc_hash_node(void *priv, void *key, void *data, void **out_data)
{
	struct nbl_hash_tbl_mgt *tbl_mgt = (struct nbl_hash_tbl_mgt *)priv;
	struct nbl_hash_entry_node *hash_node;
	u32 hash_value;
	u16 key_size;
	u16 data_size;

	hash_node = devm_kzalloc(tbl_mgt->tbl_key.dev, sizeof(struct nbl_hash_entry_node),
				 GFP_KERNEL);
	if (!hash_node)
		return -1;

	key_size = tbl_mgt->tbl_key.key_size;
	hash_node->key = devm_kzalloc(tbl_mgt->tbl_key.dev, key_size, GFP_KERNEL);
	if (!hash_node->key)
		goto alloc_key_failed;

	data_size = tbl_mgt->tbl_key.data_size;
	hash_node->data = devm_kzalloc(tbl_mgt->tbl_key.dev, data_size, GFP_KERNEL);
	if (!hash_node->data)
		goto alloc_data_failed;

	memcpy(hash_node->key, key, key_size);
	memcpy(hash_node->data, data, data_size);

	hash_value = nbl_common_calculate_hash_key(key, key_size, tbl_mgt->tbl_key.bucket_size);

	if (tbl_mgt->tbl_key.lock_need)
		mutex_lock(&tbl_mgt->lock);

	hlist_add_head(&hash_node->node, tbl_mgt->hash + hash_value);
	tbl_mgt->node_num++;
	if (out_data)
		*out_data = hash_node->data;

	if (tbl_mgt->tbl_key.lock_need)
		mutex_unlock(&tbl_mgt->lock);

	return 0;

alloc_data_failed:
	devm_kfree(tbl_mgt->tbl_key.dev, hash_node->key);
alloc_key_failed:
	devm_kfree(tbl_mgt->tbl_key.dev, hash_node);

	return -1;
}

/**
 * get a hash node, return the data if node exist
 */
void *nbl_common_get_hash_node(void *priv, void *key)
{
	struct nbl_hash_tbl_mgt *tbl_mgt = (struct nbl_hash_tbl_mgt *)priv;
	struct nbl_hash_entry_node *hash_node;
	struct hlist_head *head;
	void *data = NULL;
	u32 hash_value;
	u16 key_size;

	key_size = tbl_mgt->tbl_key.key_size;
	hash_value = nbl_common_calculate_hash_key(key, key_size, tbl_mgt->tbl_key.bucket_size);
	head = tbl_mgt->hash + hash_value;

	if (tbl_mgt->tbl_key.lock_need)
		mutex_lock(&tbl_mgt->lock);

	hlist_for_each_entry(hash_node, head, node)
		if (!memcmp(hash_node->key, key, key_size)) {
			data = hash_node->data;
			break;
		}

	if (tbl_mgt->tbl_key.lock_need)
		mutex_unlock(&tbl_mgt->lock);

	return data;
}

static void nbl_common_remove_hash_node(struct nbl_hash_tbl_mgt *tbl_mgt,
					struct nbl_hash_entry_node *hash_node)
{
	hlist_del(&hash_node->node);
	devm_kfree(tbl_mgt->tbl_key.dev, hash_node->key);
	devm_kfree(tbl_mgt->tbl_key.dev, hash_node->data);
	devm_kfree(tbl_mgt->tbl_key.dev, hash_node);
	tbl_mgt->node_num--;
}

/**
 * free a hash node
 */
void nbl_common_free_hash_node(void *priv, void *key)
{
	struct nbl_hash_tbl_mgt *tbl_mgt = (struct nbl_hash_tbl_mgt *)priv;
	struct nbl_hash_entry_node *hash_node;
	struct hlist_head *head;
	u32 hash_value;
	u16 key_size;

	key_size = tbl_mgt->tbl_key.key_size;
	hash_value = nbl_common_calculate_hash_key(key, key_size, tbl_mgt->tbl_key.bucket_size);
	head = tbl_mgt->hash + hash_value;

	if (tbl_mgt->tbl_key.lock_need)
		mutex_lock(&tbl_mgt->lock);

	hlist_for_each_entry(hash_node, head, node)
		if (!memcmp(hash_node->key, key, key_size))
			break;

	if (hash_node)
		nbl_common_remove_hash_node(tbl_mgt, hash_node);

	if (tbl_mgt->tbl_key.lock_need)
		mutex_unlock(&tbl_mgt->lock);
}

/* 0: the node accord with the match condition */
static int nbl_common_match_and_done_hash_node(struct nbl_hash_tbl_mgt *tbl_mgt,
					       struct nbl_hash_tbl_scan_key *key,
					       struct nbl_hash_entry_node *hash_node)
{
	int ret = 0;

	if (key->match_func) {
		ret = key->match_func(key->match_condition, hash_node->key, hash_node->data);
		if (ret)
			return ret;
	}

	if (key->action_func)
		key->action_func(key->action_priv, hash_node->key, hash_node->data);

	if (key->op_type == NBL_HASH_TBL_OP_DELETE)
		nbl_common_remove_hash_node(tbl_mgt, hash_node);

	return 0;
}

void nbl_common_scan_hash_node(void *priv, struct nbl_hash_tbl_scan_key *key)
{
	struct nbl_hash_tbl_mgt *tbl_mgt = (struct nbl_hash_tbl_mgt *)priv;
	struct nbl_hash_entry_node *hash_node;
	struct hlist_node *safe_node;
	struct hlist_head *head;
	u32 i;
	int match_ret;
	int node_num = 0;

	if (tbl_mgt->tbl_key.lock_need)
		mutex_lock(&tbl_mgt->lock);

	for (i = 0; i < tbl_mgt->tbl_key.bucket_size; i++) {
		head = tbl_mgt->hash + i;
		hlist_for_each_entry_safe(hash_node, safe_node, head, node) {
			match_ret = nbl_common_match_and_done_hash_node(tbl_mgt, key, hash_node);
			if (!match_ret)
				node_num++;
		}
	}

	if (tbl_mgt->tbl_key.lock_need)
		mutex_unlock(&tbl_mgt->lock);
}

u16 nbl_common_get_hash_node_num(void *priv)
{
	struct nbl_hash_tbl_mgt *tbl_mgt = (struct nbl_hash_tbl_mgt *)priv;

	return tbl_mgt->node_num;
}

void nbl_common_remove_hash_table(void *priv, struct nbl_hash_tbl_del_key *key)
{
	struct nbl_hash_tbl_mgt *tbl_mgt = (struct nbl_hash_tbl_mgt *)priv;
	struct nbl_hash_entry_node *hash_node;
	struct hlist_node *safe_node;
	struct hlist_head *head;
	struct device *dev;
	u32 i;

	if (!priv)
		return;

	if (tbl_mgt->tbl_key.lock_need)
		mutex_lock(&tbl_mgt->lock);

	for (i = 0; i < tbl_mgt->tbl_key.bucket_size; i++) {
		head = tbl_mgt->hash + i;
		hlist_for_each_entry_safe(hash_node, safe_node, head, node) {
			if (key && key->action_func)
				key->action_func(key->action_priv, hash_node->key, hash_node->data);
			nbl_common_remove_hash_node(tbl_mgt, hash_node);
		}
	}

	devm_kfree(tbl_mgt->tbl_key.dev, tbl_mgt->hash);

	if (tbl_mgt->tbl_key.lock_need)
		mutex_unlock(&tbl_mgt->lock);

	dev = tbl_mgt->tbl_key.dev;
	devm_kfree(dev, tbl_mgt);
}

/**
 * alloc a hash x and y axis table
 * it support x/y axis store if necessary, so it can scan by x/y axis;
 * the table support multi thread
 */
void *nbl_common_init_hash_xy_table(struct nbl_hash_xy_tbl_key *key)
{
	struct nbl_hash_xy_tbl_mgt *tbl_mgt;
	int i;

	tbl_mgt = devm_kzalloc(key->dev, sizeof(struct nbl_hash_xy_tbl_mgt), GFP_KERNEL);
	if (!tbl_mgt)
		return NULL;

	tbl_mgt->hash = devm_kcalloc(key->dev, key->bucket_size,
				     sizeof(struct hlist_head), GFP_KERNEL);
	if (!tbl_mgt->hash)
		goto alloc_hash_failed;

	tbl_mgt->x_axis_hash = devm_kcalloc(key->dev, key->x_axis_bucket_size,
					    sizeof(struct hlist_head), GFP_KERNEL);
	if (!tbl_mgt->x_axis_hash)
		goto alloc_x_axis_hash_failed;

	tbl_mgt->y_axis_hash = devm_kcalloc(key->dev, key->y_axis_bucket_size,
					    sizeof(struct hlist_head), GFP_KERNEL);
	if (!tbl_mgt->y_axis_hash)
		goto alloc_y_axis_hash_failed;

	for (i = 0; i < key->bucket_size; i++)
		INIT_HLIST_HEAD(tbl_mgt->hash + i);

	for (i = 0; i < key->x_axis_bucket_size; i++)
		INIT_HLIST_HEAD(tbl_mgt->x_axis_hash + i);

	for (i = 0; i < key->y_axis_bucket_size; i++)
		INIT_HLIST_HEAD(tbl_mgt->y_axis_hash + i);

	memcpy(&tbl_mgt->tbl_key, key, sizeof(struct nbl_hash_xy_tbl_key));

	if (key->lock_need)
		mutex_init(&tbl_mgt->lock);

	return tbl_mgt;

alloc_y_axis_hash_failed:
	devm_kfree(key->dev, tbl_mgt->x_axis_hash);
alloc_x_axis_hash_failed:
	devm_kfree(key->dev, tbl_mgt->hash);
alloc_hash_failed:
	devm_kfree(key->dev, tbl_mgt);

	return NULL;
}

/**
 * alloc a hash x and y node, and add to hlist_head
 */
int nbl_common_alloc_hash_xy_node(void *priv, void *x_key, void *y_key, void *data)
{
	struct nbl_hash_xy_tbl_mgt *tbl_mgt = (struct nbl_hash_xy_tbl_mgt *)priv;
	struct nbl_hash_entry_xy_node *hash_node;
	void *key;
	u32 hash_value;
	u32 x_hash_value;
	u32 y_hash_value;
	u32 node_size;
	u16 key_size;
	u16 x_key_size;
	u16 y_key_size;
	u16 data_size;

	node_size = sizeof(struct nbl_hash_entry_xy_node);
	hash_node = devm_kzalloc(tbl_mgt->tbl_key.dev, sizeof(struct nbl_hash_entry_xy_node),
				 GFP_KERNEL);
	if (!hash_node)
		return -1;

	x_key_size = tbl_mgt->tbl_key.x_axis_key_size;
	hash_node->x_axis_key = devm_kzalloc(tbl_mgt->tbl_key.dev, x_key_size, GFP_KERNEL);
	if (!hash_node->x_axis_key)
		goto alloc_x_key_failed;

	y_key_size = tbl_mgt->tbl_key.y_axis_key_size;
	hash_node->y_axis_key = devm_kzalloc(tbl_mgt->tbl_key.dev, y_key_size, GFP_KERNEL);
	if (!hash_node->y_axis_key)
		goto alloc_y_key_failed;

	key_size = x_key_size + y_key_size;
	key = devm_kzalloc(tbl_mgt->tbl_key.dev, key_size, GFP_KERNEL);
	if (!key)
		goto alloc_key_failed;

	data_size = tbl_mgt->tbl_key.data_size;
	hash_node->data = devm_kzalloc(tbl_mgt->tbl_key.dev, data_size, GFP_KERNEL);
	if (!hash_node->data)
		goto alloc_data_failed;

	memcpy(key, x_key, x_key_size);
	memcpy(key + x_key_size, y_key, y_key_size);
	memcpy(hash_node->x_axis_key, x_key, x_key_size);
	memcpy(hash_node->y_axis_key, y_key, y_key_size);
	memcpy(hash_node->data, data, data_size);

	hash_value = nbl_common_calculate_hash_key(key, key_size, tbl_mgt->tbl_key.bucket_size);
	x_hash_value = nbl_common_calculate_hash_key(x_key, x_key_size,
						     tbl_mgt->tbl_key.x_axis_bucket_size);
	y_hash_value = nbl_common_calculate_hash_key(y_key, y_key_size,
						     tbl_mgt->tbl_key.y_axis_bucket_size);

	devm_kfree(tbl_mgt->tbl_key.dev, key);

	if (tbl_mgt->tbl_key.lock_need)
		mutex_lock(&tbl_mgt->lock);

	hlist_add_head(&hash_node->node, tbl_mgt->hash + hash_value);
	hlist_add_head(&hash_node->x_axis_node, tbl_mgt->x_axis_hash + x_hash_value);
	hlist_add_head(&hash_node->y_axis_node, tbl_mgt->y_axis_hash + y_hash_value);

	tbl_mgt->node_num++;

	if (tbl_mgt->tbl_key.lock_need)
		mutex_unlock(&tbl_mgt->lock);

	return 0;

alloc_data_failed:
	devm_kfree(tbl_mgt->tbl_key.dev, key);
alloc_key_failed:
	devm_kfree(tbl_mgt->tbl_key.dev, hash_node->y_axis_key);
alloc_y_key_failed:
	devm_kfree(tbl_mgt->tbl_key.dev, hash_node->x_axis_key);
alloc_x_key_failed:
	devm_kfree(tbl_mgt->tbl_key.dev, hash_node);

	return -1;
}

/**
 * get a hash node, return the data if node exist
 */
void *nbl_common_get_hash_xy_node(void *priv, void *x_key, void *y_key)
{
	struct nbl_hash_xy_tbl_mgt *tbl_mgt = (struct nbl_hash_xy_tbl_mgt *)priv;
	struct nbl_hash_entry_xy_node *hash_node;
	struct hlist_head *head;
	void *data = NULL;
	void *key;
	u32 hash_value;
	u16 key_size;
	u16 x_key_size;
	u16 y_key_size;

	x_key_size = tbl_mgt->tbl_key.x_axis_key_size;
	y_key_size = tbl_mgt->tbl_key.y_axis_key_size;
	key_size = x_key_size + y_key_size;
	key = devm_kzalloc(tbl_mgt->tbl_key.dev, key_size, GFP_KERNEL);
	if (!key)
		return NULL;

	memcpy(key, x_key, x_key_size);
	memcpy(key + x_key_size, y_key, y_key_size);
	hash_value = nbl_common_calculate_hash_key(key, key_size, tbl_mgt->tbl_key.bucket_size);
	head = tbl_mgt->hash + hash_value;

	if (tbl_mgt->tbl_key.lock_need)
		mutex_lock(&tbl_mgt->lock);

	hlist_for_each_entry(hash_node, head, node)
		if (!memcmp(hash_node->x_axis_key, x_key, x_key_size) &&
		    !memcmp(hash_node->y_axis_key, y_key, y_key_size)) {
			data = hash_node->data;
			break;
		}

	if (tbl_mgt->tbl_key.lock_need)
		mutex_unlock(&tbl_mgt->lock);

	devm_kfree(tbl_mgt->tbl_key.dev, key);

	return data;
}

static void nbl_common_remove_hash_xy_node(struct nbl_hash_xy_tbl_mgt *tbl_mgt,
					   struct nbl_hash_entry_xy_node *hash_node)
{
	hlist_del(&hash_node->node);
	hlist_del(&hash_node->x_axis_node);
	hlist_del(&hash_node->y_axis_node);
	devm_kfree(tbl_mgt->tbl_key.dev, hash_node->x_axis_key);
	devm_kfree(tbl_mgt->tbl_key.dev, hash_node->y_axis_key);
	devm_kfree(tbl_mgt->tbl_key.dev, hash_node->data);
	devm_kfree(tbl_mgt->tbl_key.dev, hash_node);
	tbl_mgt->node_num--;
}

/**
 * free a hash node
 */
void nbl_common_free_hash_xy_node(void *priv, void *x_key, void *y_key)
{
	struct nbl_hash_xy_tbl_mgt *tbl_mgt = (struct nbl_hash_xy_tbl_mgt *)priv;
	struct nbl_hash_entry_xy_node *hash_node;
	struct hlist_head *head;
	void *key;
	u32 hash_value;
	u16 key_size;
	u16 x_key_size;
	u16 y_key_size;

	x_key_size = tbl_mgt->tbl_key.x_axis_key_size;
	y_key_size = tbl_mgt->tbl_key.y_axis_key_size;
	key_size = x_key_size + y_key_size;
	key = devm_kzalloc(tbl_mgt->tbl_key.dev, key_size, GFP_KERNEL);
	if (!key)
		return;

	memcpy(key, x_key, x_key_size);
	memcpy(key + x_key_size, y_key, y_key_size);
	hash_value = nbl_common_calculate_hash_key(key, key_size, tbl_mgt->tbl_key.bucket_size);
	head = tbl_mgt->hash + hash_value;

	if (tbl_mgt->tbl_key.lock_need)
		mutex_lock(&tbl_mgt->lock);

	hlist_for_each_entry(hash_node, head, node)
		if (!memcmp(hash_node->x_axis_key, x_key, x_key_size) &&
		    !memcmp(hash_node->y_axis_key, y_key, y_key_size)) {
			break;
		}

	if (hash_node)
		nbl_common_remove_hash_xy_node(tbl_mgt, hash_node);

	if (tbl_mgt->tbl_key.lock_need)
		mutex_unlock(&tbl_mgt->lock);

	devm_kfree(tbl_mgt->tbl_key.dev, key);
}

/* 0: the node accord with the match condition */
static int nbl_common_match_and_done_hash_xy_node(struct nbl_hash_xy_tbl_mgt *tbl_mgt,
						  struct nbl_hash_xy_tbl_scan_key *key,
						  struct nbl_hash_entry_xy_node *hash_node)
{
	int ret = 0;

	if (key->match_func) {
		ret = key->match_func(key->match_condition, hash_node->x_axis_key,
				      hash_node->y_axis_key, hash_node->data);
		if (ret)
			return ret;
	}

	if (key->action_func)
		key->action_func(key->action_priv, hash_node->x_axis_key, hash_node->y_axis_key,
				 hash_node->data);

	if (key->op_type == NBL_HASH_TBL_OP_DELETE)
		nbl_common_remove_hash_xy_node(tbl_mgt, hash_node);

	return 0;
}

/**
 * scan by x_axis or y_aixs or none, and return the match node number
 */
u16 nbl_common_scan_hash_xy_node(void *priv, struct nbl_hash_xy_tbl_scan_key *key)
{
	struct nbl_hash_xy_tbl_mgt *tbl_mgt = (struct nbl_hash_xy_tbl_mgt *)priv;
	struct nbl_hash_entry_xy_node *hash_node;
	struct hlist_node *safe_node;
	struct hlist_head *head;
	int match_ret;
	u32 i;
	u32 hash_value;
	u16 x_axis_key_size;
	u16 y_axis_key_size;
	u16 node_num = 0;

	if (tbl_mgt->tbl_key.lock_need)
		mutex_lock(&tbl_mgt->lock);

	if (key->scan_type == NBL_HASH_TBL_X_AXIS_SCAN) {
		x_axis_key_size = tbl_mgt->tbl_key.x_axis_key_size;
		hash_value = nbl_common_calculate_hash_key(key->x_key, x_axis_key_size,
							   tbl_mgt->tbl_key.x_axis_bucket_size);
		head = tbl_mgt->x_axis_hash + hash_value;
		hlist_for_each_entry_safe(hash_node, safe_node, head, x_axis_node) {
			if (!memcmp(hash_node->x_axis_key, key->x_key, x_axis_key_size)) {
				match_ret = nbl_common_match_and_done_hash_xy_node(tbl_mgt, key,
										   hash_node);
				if (!match_ret) {
					node_num++;
					if (key->only_query_exist)
						break;
				}
			}
		}
	} else if (key->scan_type == NBL_HASH_TBL_Y_AXIS_SCAN) {
		y_axis_key_size = tbl_mgt->tbl_key.y_axis_key_size;
		hash_value = nbl_common_calculate_hash_key(key->y_key, y_axis_key_size,
							   tbl_mgt->tbl_key.y_axis_bucket_size);
		head = tbl_mgt->y_axis_hash + hash_value;
		hlist_for_each_entry_safe(hash_node, safe_node, head, y_axis_node) {
			if (!memcmp(hash_node->y_axis_key, key->y_key, y_axis_key_size)) {
				match_ret = nbl_common_match_and_done_hash_xy_node(tbl_mgt, key,
										   hash_node);
				if (!match_ret) {
					node_num++;
					if (key->only_query_exist)
						break;
				}
			}
		}
	} else {
		for (i = 0; i < tbl_mgt->tbl_key.bucket_size; i++) {
			head = tbl_mgt->hash + i;
			hlist_for_each_entry_safe(hash_node, safe_node, head, node) {
				match_ret = nbl_common_match_and_done_hash_xy_node(tbl_mgt, key,
										   hash_node);
				if (!match_ret)
					node_num++;
			}
		}
	}

	if (tbl_mgt->tbl_key.lock_need)
		mutex_unlock(&tbl_mgt->lock);

	return node_num;
}

u16 nbl_common_get_hash_xy_node_num(void *priv)
{
	struct nbl_hash_xy_tbl_mgt *tbl_mgt = (struct nbl_hash_xy_tbl_mgt *)priv;

	return tbl_mgt->node_num;
}

void nbl_common_remove_hash_xy_table(void *priv, struct nbl_hash_xy_tbl_del_key *key)
{
	struct nbl_hash_xy_tbl_mgt *tbl_mgt = (struct nbl_hash_xy_tbl_mgt *)priv;
	struct nbl_hash_entry_xy_node *hash_node;
	struct hlist_node *safe_node;
	struct hlist_head *head;
	struct device *dev;
	u32 i;

	if (!priv)
		return;

	if (tbl_mgt->tbl_key.lock_need)
		mutex_lock(&tbl_mgt->lock);

	for (i = 0; i < tbl_mgt->tbl_key.bucket_size; i++) {
		head = tbl_mgt->hash + i;
		hlist_for_each_entry_safe(hash_node, safe_node, head, node) {
			if (key->action_func)
				key->action_func(key->action_priv, hash_node->x_axis_key,
						 hash_node->y_axis_key, hash_node->data);
			nbl_common_remove_hash_xy_node(tbl_mgt, hash_node);
		}
	}

	devm_kfree(tbl_mgt->tbl_key.dev, tbl_mgt->hash);
	devm_kfree(tbl_mgt->tbl_key.dev, tbl_mgt->x_axis_hash);
	devm_kfree(tbl_mgt->tbl_key.dev, tbl_mgt->y_axis_hash);

	if (tbl_mgt->tbl_key.lock_need)
		mutex_unlock(&tbl_mgt->lock);

	dev = tbl_mgt->tbl_key.dev;
	devm_kfree(dev, tbl_mgt);
}

int nbl_flow_direct_parse_tlv_data(u8 *tlv, u32 length, handle_tlv callback, void *data)
{
	u32 offset = 0;
	u16 type, len;
	int ret = 0;

	while (offset + NBL_CHAN_FDIR_TLV_HEADER_LEN <= length) {
		type = *(u16 *)tlv;
		len = *(u16 *)(tlv + 2);
		ret = callback(type, len, tlv + 4, data);
		if (ret)
			break;

		offset += (NBL_CHAN_FDIR_TLV_HEADER_LEN + len);
		tlv += (NBL_CHAN_FDIR_TLV_HEADER_LEN + len);
	}
	return ret;
}
