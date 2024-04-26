// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2024 Huawei Technologies Co., Ltd
#include <linux/pci.h>
#include <linux/dma-mapping.h>
#include <linux/vmalloc.h>
#include <linux/semaphore.h>

#include "hinic3_crm.h"
#include "hmm_umem.h"
#include "hmm_comp.h"
#include "hinic3_hmm.h"
#include "hmm_mr.h"

/*
 ****************************************************************************
 Prototype	: get_key_from_index
 Description  : mr key的计算算法，通过index移位计算得到
 Input		: u32 mpt_index
 Output	   : None
****************************************************************************
*/
static u32 get_key_from_index(u32 mpt_index)
{
	return (mpt_index >> MR_KEY_RIGHT_SHIFT_OFS) | (mpt_index << MR_KEY_LEFT_SHIFT_OFS);
}

/*
 ****************************************************************************
 Prototype	: hmm_alloc_tpt
 Description  : alloc mpt and mtt
 Input		: struct hinic3_hwdev *hwdev
				struct rdma_mr *mr
				u32 npages
				u32 page_shift
 Output	   : None
****************************************************************************
*/
static int hmm_alloc_tpt(struct hinic3_hwdev *hwdev, struct rdma_mr *mr,
	u32 npages, u32 page_shift, u32 service_type)
{
	int ret;

	ret = hmm_rdma_mpt_alloc(hwdev, &mr->mpt, service_type);
	if (ret != 0) {
		dev_err(hwdev->dev_hdl,
			"[HMM, ERR] %s(%d): Failed to alloc mpt, ret(%d), func_id(%d)\n",
			__func__, __LINE__, ret, hinic3_global_func_id(hwdev));
		return ret;
	}
	mr->enabled = RDMA_MPT_EN_SW;

	/* npages = 0 or 1, means not need mtt */
	ret = hmm_rdma_mtt_alloc(hwdev, npages, page_shift, &mr->mtt, service_type);
	if (ret != 0) {
		dev_err(hwdev->dev_hdl,
			"[HMM, ERR] %s(%d): Failed to alloc mtt, ret(%d), func_id(%d)\n",
			__func__, __LINE__, ret, hinic3_global_func_id(hwdev));
		goto err_alloc_mtt;
	}
	return 0;

err_alloc_mtt:
	hmm_rdma_mpt_free(hwdev, &mr->mpt);
	mr->enabled = HMM_MPT_DISABLED;

	return ret;
}

/*
 ****************************************************************************
 Prototype	: hmm_free_tpt
 Description  : free mpt and mtt
 Input		: struct hinic3_hwdev *hwdev
				struct rdma_mr *mr
****************************************************************************
*/
void hmm_free_tpt(void *hwdev, struct rdma_mr *mr, u32 service_type)
{
	hmm_rdma_mtt_free(hwdev, &mr->mtt, service_type);
	hmm_rdma_mpt_free(hwdev, &mr->mpt);
	mr->enabled = HMM_MPT_DISABLED;
}

/*
 ****************************************************************************
 Prototype	: hmm_set_rdma_mr
 Description  : set the member of rdma_mr
 Input		: struct rdma_mr *mr
				enum rdma_mr_type mr_type
				u32 pdn
				u64 iova
				u64 size
				u32 access
 Output	   : None
****************************************************************************
*/
static void hmm_set_rdma_mr(struct rdma_mr *mr, enum rdma_mr_type mr_type, u32 pdn,
	u64 iova, u64 size, u32 access)
{
	mr->iova = iova;
	mr->size = size;
	mr->pdn = pdn;
	mr->access = access;
	mr->key = get_key_from_index(mr->mpt.mpt_index); /* 由mpt index转换为key */
	mr->mr_type = mr_type;
}

/*
 ****************************************************************************
 Prototype	: hmm_alloc_mr
 Description  : register DMA_MR
 Input		: struct hinic3_hwdev *hwdev
				enum rdma_mr_type mr_type
				u32 max_num_sg
				u32 service_type
 Output	   : None
****************************************************************************
*/
struct hmm_mr *hmm_alloc_mr(struct hinic3_hwdev *hwdev, u32 pdn, enum rdma_mr_type mr_type,
	u32 max_num_sg, u32 service_type, u16 channel)
{
	u32 access_flag;
	int ret = 0;
	struct hmm_mr *mr = NULL;

	if (hwdev == NULL) {
		ret = -EINVAL;
		pr_err("[HMM, ERR] %s(%d): dev is null\n", __func__, __LINE__);
		goto err_out;
	}
#ifndef PANGEA_V6
	if (mr_type != RDMA_DMA_MR && mr_type != RDMA_INDIRECT_MR) {
#else
	if (mr_type != RDMA_DMA_MR) {
#endif
		ret = -EINVAL;
		pr_err("[HMM, ERR] %s(%d): mr_type is invalid\n", __func__, __LINE__);
		goto err_out;
	}

	mr = kzalloc(sizeof(*mr), GFP_KERNEL);
	if (mr == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	ret = hmm_alloc_tpt(hwdev->dev_hdl, &mr->rdmamr, 0, 0, service_type);
	if (ret != 0) {
		dev_err(hwdev->dev_hdl,
			"[HMM, ERR] %s(%d): Failed to alloc mpt and mtt, func_id(%d)\n",
			__func__, __LINE__, hinic3_global_func_id(hwdev));
		goto err_alloc_tpt;
	}

	access_flag = (RDMA_IB_ACCESS_REMOTE_READ | RDMA_IB_ACCESS_REMOTE_WRITE |
		RDMA_IB_ACCESS_LOCAL_WRITE | RDMA_IB_ACCESS_REMOTE_ATOMIC);

	hmm_set_rdma_mr(&mr->rdmamr, mr_type, pdn, 0ULL, ROCE_DMA_MR_SIZE, access_flag);

	ret = hmm_rdma_enable_mr_mpt(hwdev->dev_hdl, &(mr->rdmamr), channel);
	if (ret != 0) {
		dev_err(hwdev->dev_hdl,
			"[HMM, ERR] %s(%d): Failed to enable mpt of DMA mr, func_id(%d)\n",
			__func__, __LINE__, hinic3_global_func_id(hwdev));
		goto err_enable_mpt;
	}

	return mr;

err_enable_mpt:
	hmm_free_tpt(hwdev->dev_hdl, &mr->rdmamr, service_type);

err_alloc_tpt:
	kfree(mr);

err_out:
	return (struct hmm_mr *)ERR_PTR((long)ret);
}

static int hmm_umem_write_mtt_check(const void *hwdev, const struct rdma_mtt *mtt,
	const struct hmm_umem *umem)
{
	if ((hwdev == NULL) || (mtt == NULL) || (umem == NULL)) {
		pr_err("[HMM, ERR] %s(%d): hwdev or mtt or umem is null\n", __func__, __LINE__);
		return -EINVAL;
	}
	return 0;
}

static int hmm_umem_write_mtt_update(struct hinic3_hwdev *hwdev, struct rdma_mtt *mtt,
	struct hmm_umem *umem, u64 *page_list, u32 service_type)
{
	int ret = 0;
	int i = 0;
	u32 j = 0;
	u32 pages_in_chunk = 0; /* umem_chunk中单个内存块的页个数 */
	u32 npages = 0;		 /* 已经记录的页个数 */
	u32 start_index = 0;	/* 要写入mtt的页 */
	struct scatterlist *sg = NULL;
	u64 page_size = 0;

	page_size = BIT((unsigned int)umem->page_shift);
	for_each_sg(umem->sg_head.sgl, sg, umem->nmap, i) {
		/* cal page num in truck */
		pages_in_chunk = sg_dma_len(sg) >> mtt->buf_page_shift;
		for (j = 0; j < pages_in_chunk; ++j) {
			page_list[npages] = sg_dma_address(sg) + (page_size * j);
			npages++;

			/* one page can hold (PAGE_SIZE / sizeof(u64)) addrs */
			if (npages == (PAGE_SIZE / sizeof(u64))) {
				ret = hmm_rdma_write_mtt(hwdev, mtt, start_index,
					npages, page_list, service_type);
				start_index += npages;
				npages = 0;
			}
			if ((npages == (PAGE_SIZE / sizeof(u64))) && (ret != 0)) {
				dev_err(hwdev->dev_hdl,
					"[HMM, ERR] %s(%d): Failed to write mtt, func_id(%d)\n",
					__func__, __LINE__, hinic3_global_func_id(hwdev));
				goto out;
			}
		}
	}

	if (npages != 0) {
		ret = hmm_rdma_write_mtt(hwdev, mtt, start_index, npages, page_list, service_type);
		if (ret != 0) {
			dev_err(hwdev->dev_hdl, "[HMM, ERR] %s(%d): Failed to write mtt, ret(%d), start_index(%d), func_id(%d)\n",
				__func__, __LINE__, ret, start_index, hinic3_global_func_id(hwdev));
			goto out;
		}
	}

out:
	kfree(page_list);

	return ret;
}

/*
 ****************************************************************************
 Prototype	: hmm_umem_write_mtt
 Description  : write mtt for umem(get from memory alloced by user)
 Input		: struct hinic3_hwdev *hwdev
				struct rdma_mtt *mtt
				struct hmm_umem *umem
 Output	   : None
****************************************************************************
*/
int hmm_umem_write_mtt(struct hinic3_hwdev *hwdev, struct rdma_mtt *mtt,
	struct hmm_umem *umem, u32 service_type)
{
	int ret;
	u64 *page_list = NULL; /* 要写入mtt的page_list */

	ret = hmm_umem_write_mtt_check(hwdev, mtt, umem);
	if (ret != 0)
		return ret;

	page_list = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (page_list == NULL)
		return -ENOMEM;
	ret = hmm_umem_write_mtt_update(hwdev, mtt, umem, page_list, service_type);
	return ret;
}

int hmm_reg_user_mr_update(struct hinic3_hwdev *hwdev, struct hmm_mr *mr, u32 pdn,
	u64 length, u64 virt_addr, int access, u32 service_type, u16 channel)
{
	int ret = 0;
	u32 npages = 0;
	u32 page_shift = 0;

	if (hwdev == NULL) {
		pr_err("[HMM, ERR] %s(%d): hwdev is null\n", __func__, __LINE__);
		return 0;
	}
	mr->rdmamr.mtt.mtt_type = MTT_DMTT_TYPE;
	npages = (u32)hmm_umem_page_count(mr->umem);
	page_shift = (u32)(mr->umem->page_shift);
	ret = hmm_alloc_tpt(hwdev, &mr->rdmamr, npages, page_shift, service_type);
	if (ret != 0) {
		dev_err(hwdev->dev_hdl,
			"[HMM, ERR] %s(%d): Failed to alloc mpt and mtt, func_id(%d)\n",
			__func__, __LINE__, hinic3_global_func_id(hwdev));
		goto err_alloc_tpt;
	}

	hmm_set_rdma_mr(&mr->rdmamr, RDMA_USER_MR, pdn, virt_addr, length, (u32)access);

	ret = hmm_umem_write_mtt(hwdev, &mr->rdmamr.mtt, mr->umem, service_type);
	if (ret != 0) {
		dev_err(hwdev->dev_hdl,
			"[HMM, ERR] %s(%d): Failed to write mtt, func_id(%d)\n",
			__func__, __LINE__, hinic3_global_func_id(hwdev));
		goto err_write_mtt;
	}

	ret = hmm_rdma_enable_mr_mpt(hwdev, &mr->rdmamr, channel);
	if (ret != 0) {
		dev_err(hwdev->dev_hdl,
			"[HMM, ERR] %s(%d): Failed to enable mpt of user mr, func_id(%d)\n",
			__func__, __LINE__, hinic3_global_func_id(hwdev));
		goto err_write_mtt;
	}

	return 0;

err_write_mtt:
	hmm_free_tpt(hwdev, &mr->rdmamr, service_type);

err_alloc_tpt:
	return ret;
}

int hmm_dereg_mr_update(struct hinic3_hwdev *hwdev, struct rdma_mr *mr,
	u32 service_type, u16 channel)
{
	int ret = 0;

	ret = hmm_rdma_disable_mr_mpt(hwdev, mr, service_type, channel);
	if (ret != 0) {
		dev_err(hwdev->dev_hdl,
			"[HMM, ERR] %s(%d): Failed to disable mpt of mr, ret(%d)\n",
			__func__, __LINE__, ret);
		return ret;
	}

	hmm_free_tpt(hwdev, mr, service_type);
	return ret;
}

#ifndef ROCE_SERVICE
/*
 ****************************************************************************
 Prototype	: hmm_reg_user_mr
 Description  : register MR for user
 Input		: struct hinic3_hwdev *hwdev
				u64 start
				u64 length
				u64 virt_addr
				int hmm_access
 Output	   : None
****************************************************************************
*/
struct hmm_mr *hmm_reg_user_mr(struct hinic3_hwdev *hwdev, u64 start, u32 pd,
	u64 length, u64 virt_addr, int hmm_access, u32 service_type, u16 channel)
{
	int ret = 0;
	struct hmm_mr *mr = NULL;

	if (hwdev == NULL) {
		pr_err("[HMM, ERR] %s(%d): hwdev is null\n", __func__, __LINE__);
		goto err_out;
	}

	mr = kzalloc(sizeof(*mr), GFP_KERNEL);
	if (mr == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	mr->hwdev = hwdev;
	mr->rdmamr.iova = virt_addr;
	mr->umem = hmm_umem_get(hwdev->dev_hdl, start, (size_t)length, hmm_access, 0);
	if (IS_ERR(mr->umem)) {
		ret = (int)PTR_ERR(mr->umem);
		dev_err(hwdev->dev_hdl,
			"[HMM, ERR] %s(%d): Failed to get ib umem, func_id(%d)\n",
			__func__, __LINE__, hinic3_global_func_id(hwdev));
		goto err_empty;
	}

	rcu_read_lock();
	mr->umem->context->tgid = get_task_pid(current->group_leader, PIDTYPE_PID);
	rcu_read_unlock();
	ret = hmm_reg_user_mr_update(hwdev, mr, pd, length, virt_addr,
		hmm_access, service_type, channel);
	if (ret != 0)
		goto err_get_umem;

	return mr;

err_get_umem:
	hmm_umem_release(mr->umem);
err_empty:
	kfree(mr);

err_out:
	return (struct hmm_mr *)ERR_PTR((long)ret);
}

/*
 ****************************************************************************
 Prototype	: hmm_dereg_mr
 Description  : dereg DMA_MR, user_MR or FRMR
 Input		: struct hmm_mr *mr
 Output	   : None

****************************************************************************
*/
int hmm_dereg_mr(struct hmm_mr *mr, u32 service_type, u16 channel)
{
	int ret = 0;
	struct hinic3_hwdev *hwdev = NULL;

	if (mr == NULL) {
		pr_err("[HMM, ERR] %s(%d): Ibmr is null\n", __func__, __LINE__);
		return -EINVAL;
	}

	hwdev = (struct hinic3_hwdev *)mr->hwdev;
	ret = hmm_dereg_mr_update(hwdev, &(mr->rdmamr), service_type, channel);
	if (ret != 0) {
		dev_err(hwdev->dev_hdl,
			"[HMM, ERR] %s(%d): Failed to de-reg mr update, ret(%d), func_id(%d)\n",
			__func__, __LINE__, ret, hinic3_global_func_id(hwdev));
		return ret;
	}

	if (mr->umem)
		hmm_umem_release(mr->umem);

	kfree(mr);
	return ret;
}
#endif

