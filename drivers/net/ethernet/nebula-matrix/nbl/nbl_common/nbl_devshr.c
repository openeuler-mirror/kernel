// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#include "nbl_devshr.h"

static DEFINE_MUTEX(devshr_idx_lock);
static struct nbl_devshr_index_pool_info idx_pools[NBL_DEVSHR_MAX_DEV];
static u32 devchr_idxs_cfg[NBL_DEVSHR_INDEX_MAX] = {
	[NBL_DEVSHR_INDEX_MAC] = NBL_DRACO_MAC_PED_NUM,
	[NBL_DEVSHR_INDEX_IP] = NBL_DRACO_IP_PED_NUM,
	[NBL_DEVSHR_INDEX_MCC] = NBL_DRACO_MCC_NUM,
	[NBL_DEVSHR_INDEX_DECAP_VTEP] = NBL_DRACO_TNL_VTEP_NUM,
	[NBL_DEVSHR_INDEX_ENCAP_TNL] = NBL_DRACO_TNL_ENCAP_NUM,
	[NBL_DEVSHR_INDEX_ENCAP_VTEP] = NBL_DRACO_TNL_VTEP_NUM,
};

static void nbl_devshr_free_dev_idx_pool(struct nbl_devshr_dev_index_pool *dev_pool)
{
	int i, j;
	struct nbl_devshr_index_pool *idx_pool;

	for (i = 0; i < NBL_DEVSHR_INDEX_MAX; i++) {
		if (!dev_pool->pool[i])
			continue;

		idx_pool = dev_pool->pool[i];
		for (j = 0; j < NBL_DEVSHR_MAX_FUNC; j++) {
			if (!idx_pool->bitmap[j])
				break;

			kfree(idx_pool->bitmap[j]);
		}

		kfree(idx_pool);
	}

	kfree(dev_pool);
}

static struct nbl_devshr_dev_index_pool *nbl_devshr_alloc_dev_idx_pool(void)
{
	int i, j;
	int size;
	struct nbl_devshr_dev_index_pool *dev_idx_pool;
	struct nbl_devshr_index_pool *idx_pool;

	dev_idx_pool = kzalloc(sizeof(*dev_idx_pool), GFP_KERNEL);
	if (!dev_idx_pool)
		return NULL;

	for (i = 0; i < NBL_DEVSHR_INDEX_MAX; i++) {
		if (!devchr_idxs_cfg[i])
			continue;

		dev_idx_pool->pool[i] = kzalloc(sizeof(*idx_pool), GFP_KERNEL);
		if (!dev_idx_pool->pool[i])
			goto alloc_pool_failed;

		idx_pool = dev_idx_pool->pool[i];
		size = BITS_TO_LONGS(devchr_idxs_cfg[i]);
		for (j = 0; j < NBL_DEVSHR_MAX_FUNC; j++) {
			idx_pool->bitmap[j] = kcalloc(size, sizeof(long), GFP_KERNEL);
			if (!idx_pool->bitmap[j])
				goto alloc_pool_failed;
		}

		init_rwsem(&idx_pool->sem);
	}

	return dev_idx_pool;

alloc_pool_failed:
	nbl_devshr_free_dev_idx_pool(dev_idx_pool);
	return NULL;
}

int nbl_devshr_register_idx_pool(u8 board_id)
{
	if (board_id >= NBL_DEVSHR_MAX_DEV)
		return -EINVAL;

	mutex_lock(&devshr_idx_lock);
	if (!kref_read(&idx_pools[board_id].func_ref)) {
		if (idx_pools[board_id].pool) {
			WARN_ON(1);
			mutex_unlock(&devshr_idx_lock);
			return -1;
		}

		idx_pools[board_id].pool = nbl_devshr_alloc_dev_idx_pool();
		if (!idx_pools[board_id].pool)
			goto alloc_idx_failed;

		kref_init(&idx_pools[board_id].func_ref);
	} else {
		kref_get(&idx_pools[board_id].func_ref);
	}

	mutex_unlock(&devshr_idx_lock);

	return 0;
alloc_idx_failed:
	mutex_unlock(&devshr_idx_lock);
	return -ENOMEM;
}

static void
nbl_devshr_release_dev_idx_pool(struct kref *ref)
{
	struct nbl_devshr_index_pool_info *dev_idx_info =
			container_of(ref, struct nbl_devshr_index_pool_info, func_ref);

	nbl_devshr_free_dev_idx_pool(dev_idx_info->pool);
	dev_idx_info->pool = NULL;
}

void nbl_devshr_unregister_idx_pool(u8 board_id)
{
	if (board_id >= NBL_DEVSHR_MAX_DEV)
		return;

	mutex_lock(&devshr_idx_lock);
	kref_put(&idx_pools[board_id].func_ref, nbl_devshr_release_dev_idx_pool);
	mutex_unlock(&devshr_idx_lock);
}

int nbl_devshr_alloc_idx(enum nbl_devshr_index_type type, struct pci_dev *pdev, u32 *idx)
{
	u8 board_id;
	u8 eth_mode;
	int pf_id;
	int offset;
	u32 avail_idx;
	u32 perf_pf_size;
	struct nbl_adapter *adapter = pci_get_drvdata(pdev);
	struct nbl_common_info *common = NBL_ADAPTER_TO_COMMON(adapter);
	struct nbl_devshr_dev_index_pool *dev_idx_pool;
	struct nbl_devshr_index_pool *pool;

	board_id = NBL_COMMON_TO_BOARD_ID(common);
	if (board_id >= NBL_DEVSHR_MAX_DEV || type >= NBL_DEVSHR_INDEX_MAX ||
	    !devchr_idxs_cfg[type])
		return -EINVAL;

	if (NBL_COMMON_TO_VF_CAP(common))
		return -EINVAL;

	dev_idx_pool = idx_pools[board_id].pool;
	if (!dev_idx_pool)
		return -EIO;

	pool = dev_idx_pool->pool[type];
	if (!pool)
		return -EIO;

	pf_id = NBL_COMMON_TO_MGT_PF(common);
	if (pf_id >= NBL_DEVSHR_REV_FUNC_ID)
		return -EINVAL;

	down_write(&pool->sem);
	eth_mode = NBL_COMMON_TO_ETH_MODE(common);
	/* prefer alloc from offset by the current pf_id, to avoid pf pt in  VM */
	perf_pf_size = devchr_idxs_cfg[type] / eth_mode;
	offset = perf_pf_size * pf_id;
	avail_idx = find_next_zero_bit(pool->bitmap[NBL_DEVSHR_REV_FUNC_ID],
				       devchr_idxs_cfg[type], offset);
	if (avail_idx >= devchr_idxs_cfg[type]) {
		avail_idx = find_first_zero_bit(pool->bitmap[NBL_DEVSHR_REV_FUNC_ID],
						devchr_idxs_cfg[type]);
		if (avail_idx >= devchr_idxs_cfg[type])
			goto alloc_idx_failed;
	}

	set_bit(avail_idx, pool->bitmap[NBL_DEVSHR_REV_FUNC_ID]);
	set_bit(avail_idx, pool->bitmap[pf_id]);
	up_write(&pool->sem);
	*idx = avail_idx;

	return 0;
alloc_idx_failed:
	up_write(&pool->sem);
	return -EIO;
}
EXPORT_SYMBOL(nbl_devshr_alloc_idx);

int nbl_devshr_free_idx(enum nbl_devshr_index_type type, struct pci_dev *pdev, u32 idx)
{
	u8 board_id;
	int pf_id;
	struct nbl_adapter *adapter = pci_get_drvdata(pdev);
	struct nbl_common_info *common = NBL_ADAPTER_TO_COMMON(adapter);
	struct nbl_devshr_dev_index_pool *dev_idx_pool;
	struct nbl_devshr_index_pool *pool;

	board_id = NBL_COMMON_TO_BOARD_ID(common);
	if (board_id >= NBL_DEVSHR_MAX_DEV || type >= NBL_DEVSHR_INDEX_MAX ||
	    !devchr_idxs_cfg[type])
		return -EINVAL;

	if (NBL_COMMON_TO_VF_CAP(common))
		return -EINVAL;

	dev_idx_pool = idx_pools[board_id].pool;
	if (!dev_idx_pool)
		return -EIO;

	pool = dev_idx_pool->pool[type];
	if (!pool)
		return -EIO;

	pf_id = NBL_COMMON_TO_MGT_PF(common);
	if (pf_id >= NBL_DEVSHR_REV_FUNC_ID)
		return -EIO;

	down_write(&pool->sem);
	if (!test_bit(idx, pool->bitmap[pf_id])) {
		nbl_err(common, NBL_DEBUG_COMMON, "dev share free idx error, type-board-pf-idx:%d-%d-%d-%d\n",
			type, board_id, pf_id, idx);
		goto free_idx_err;
	}

	clear_bit(idx, pool->bitmap[NBL_DEVSHR_REV_FUNC_ID]);
	clear_bit(idx, pool->bitmap[pf_id]);
	up_write(&pool->sem);
	return 0;
free_idx_err:
	up_write(&pool->sem);
	return -EINVAL;
}
EXPORT_SYMBOL(nbl_devshr_free_idx);

void nbl_devshr_free_func_idxs(enum nbl_devshr_index_type type, struct pci_dev *pdev)
{
	u8 board_id;
	int pf_id;
	int idx;
	int num = 0;
	struct nbl_adapter *adapter = pci_get_drvdata(pdev);
	struct nbl_common_info *common = NBL_ADAPTER_TO_COMMON(adapter);
	struct nbl_devshr_dev_index_pool *dev_idx_pool;
	struct nbl_devshr_index_pool *pool;

	board_id = NBL_COMMON_TO_BOARD_ID(common);
	if (board_id >= NBL_DEVSHR_MAX_DEV || type >= NBL_DEVSHR_INDEX_MAX ||
	    !devchr_idxs_cfg[type])
		return;

	if (NBL_COMMON_TO_VF_CAP(common))
		return;

	dev_idx_pool = idx_pools[board_id].pool;
	if (!dev_idx_pool)
		return;

	pool = dev_idx_pool->pool[type];
	if (!pool)
		return;

	pf_id = NBL_COMMON_TO_MGT_PF(common);
	if (pf_id >= NBL_DEVSHR_REV_FUNC_ID)
		return;

	down_write(&pool->sem);
	for_each_set_bit(idx, pool->bitmap[pf_id], devchr_idxs_cfg[type]) {
		num++;
		clear_bit(idx, pool->bitmap[NBL_DEVSHR_REV_FUNC_ID]);
		clear_bit(idx, pool->bitmap[pf_id]);
	}

	up_write(&pool->sem);

	nbl_info(common, NBL_DEBUG_COMMON, "dev share free func idx , type-board-pf-num:%d-%d-%d-%d\n",
		 type, board_id, pf_id, num);
}
EXPORT_SYMBOL(nbl_devshr_free_func_idxs);

int nbl_devshr_info_dump(struct seq_file *m, void *v)
{
	int i, j;
	int idx;
	u32 num = 0;
	struct nbl_devshr_dev_index_pool *dev_idx_pool;
	struct nbl_devshr_index_pool *pool;

	for (i = 0; i < NBL_DEVSHR_MAX_DEV; i++) {
		dev_idx_pool = idx_pools[i].pool;
		if (!dev_idx_pool)
			continue;

		seq_printf(m, "board_id ref_func_num: %d\n", kref_read(&idx_pools[i].func_ref));

		for (j = 0; j < NBL_DEVSHR_INDEX_MAX; j++) {
			pool = dev_idx_pool->pool[j];
			if (!pool)
				continue;

			down_read(&pool->sem);
			for_each_set_bit(idx, pool->bitmap[NBL_DEVSHR_REV_FUNC_ID],
					 devchr_idxs_cfg[j]) {
				seq_printf(m, "idx type-idx:%d-%d\n", j, idx);
				num++;
			}

			seq_printf(m, "idx type:%d, total alloc idx:%d\n", j, num);
			up_read(&pool->sem);
		}
	}

	return 0;
}
