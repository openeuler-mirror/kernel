// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2024 Huawei Technologies Co., Ltd

#include "roce_mr.h"
#include "roce_mr_extension.h"
#include "roce_main_extension.h"

/*
 ****************************************************************************
 Prototype	: get_key_from_index
 Description  : get_key_from_index
 Input		: u32 mpt_index
 Output	   : None

  1.Date		 : 2015/5/27
	Modification : Created function

****************************************************************************
*/
static u32 get_key_from_index(u32 mpt_index)
{
	/* Algorithm of mr key is obtained by index shift calculation */
	return (mpt_index >> MR_KEY_RIGHT_SHIFT_OFS) | (mpt_index << MR_KEY_LEFT_SHIFT_OFS);
}

/*
 ****************************************************************************
 Prototype	: convert_ib_access
 Description  : convert ib access to rdma comp access
 Input		: int access_flag
 Output	   : None

  1.Date		 : 2015/7/16
	Modification : Created function

****************************************************************************
*/
static u32 convert_ib_access(int access_flag)
{
	u32 u_access_flag = (u32)access_flag;
	u32 access;

	access = (u32)((((u_access_flag & IB_ACCESS_REMOTE_ATOMIC) != 0) ?
		RDMA_IB_ACCESS_REMOTE_ATOMIC : 0) |
		(((u_access_flag & IB_ACCESS_REMOTE_WRITE) != 0) ?
		RDMA_IB_ACCESS_REMOTE_WRITE : 0) |
		(((u_access_flag & IB_ACCESS_REMOTE_READ) != 0) ?
		RDMA_IB_ACCESS_REMOTE_READ : 0) |
		(((u_access_flag & IB_ACCESS_LOCAL_WRITE) != 0) ?
		RDMA_IB_ACCESS_LOCAL_WRITE : 0) |
		(((u_access_flag & IB_ACCESS_MW_BIND) != 0) ?
		RDMA_IB_ACCESS_MW_BIND : 0) |
		(((u_access_flag & IB_ZERO_BASED) != 0) ?
		RDMA_IB_ACCESS_ZERO_BASED : 0));

	return access;
}

/*
 ****************************************************************************
 Prototype	: check_ib_access
 Description  : check remote access without local write
 Input		: int access_flag
 Output	   : None

  1.Date		 : 2017/11/18
	Modification : Created function

****************************************************************************
*/
static int check_ib_access(int access_flag)
{
	/*
	 * Local write permission is required if remote write or
	 * remote atomic permission is also requested.
	 */

	if (((((u32)access_flag) & (IB_ACCESS_REMOTE_ATOMIC | IB_ACCESS_REMOTE_WRITE)) != 0) &&
		((((u32)access_flag) & IB_ACCESS_LOCAL_WRITE) == 0))
		return -EINVAL;

	return 0;
}

/*
 ****************************************************************************
 Prototype	: roce3_alloc_tpt
 Description  : alloc mpt and mtt
 Input		: struct roce3_device *rdev
				struct rdma_mr *mr
				u32 npages
				u32 page_shift
 Output	   : None

  1.Date		 : 2015/5/8
	Modification : Created function

****************************************************************************
*/
int roce3_alloc_tpt(struct roce3_device *rdev, struct rdma_mr *mr, u32 npages, u32 page_shift)
{
	int ret = 0;

	ret = hmm_rdma_mpt_alloc(rdev->hwdev, &mr->mpt, SERVICE_T_ROCE);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to alloc mpt, ret(%d), func_id(%d)\n",
			__func__, ret, rdev->glb_func_id);
		return ret;
	}

	mr->enabled = RDMA_MPT_EN_SW;

	/*
	 * npages = 0 is a legal case, when npages = 0 or npages = 1,
	 * MTT does not need to do address translation
	 */
	ret = hmm_rdma_mtt_alloc(rdev->hwdev, npages, page_shift, &mr->mtt, SERVICE_T_ROCE);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to alloc mtt, ret(%d), func_id(%d)\n",
			__func__, ret, rdev->glb_func_id);
		goto err_alloc_mtt;
	}

	return 0;

err_alloc_mtt:
	hmm_rdma_mpt_free(rdev->hwdev, &mr->mpt);
	mr->enabled = RDMA_MPT_DISABLED;

	return ret;
}

/*
 ****************************************************************************
 Prototype	: roce3_free_tpt
 Description  : free mpt and mtt
 Input		: struct roce3_device *rdev
				struct rdma_mr *mr
 Output	   : None

  1.Date		 : 2015/5/8
	Modification : Created function

****************************************************************************
*/
void roce3_free_tpt(struct roce3_device *rdev, struct rdma_mr *mr)
{
	hmm_rdma_mtt_free(rdev->hwdev, &mr->mtt, SERVICE_T_ROCE);

	hmm_rdma_mpt_free(rdev->hwdev, &mr->mpt);

	mr->enabled = RDMA_MPT_DISABLED;
}

/*
 ****************************************************************************
 Prototype	: roce3_set_rdma_mr
 Description  : set the member of rdma_mr
 Input		: struct rdma_mr *mr
				enum rdma_mr_type mr_type
				u32 pdn
				u64 iova
				u64 size
				u32 access
 Output	   : None

  1.Date		 : 2015/5/8
	Modification : Created function

****************************************************************************
*/
void roce3_set_rdma_mr(struct rdma_mr *mr, enum rdma_mr_type mr_type, u32 pdn,
	u64 iova, u64 size, u32 access)
{
	mr->iova = iova;
	mr->size = size;
	mr->pdn = pdn;
	/* Convert ib permissions to rdma component permissions */
	mr->access = convert_ib_access((int)access);
	/* Convert from mpt index to key */
	mr->key = get_key_from_index(mr->mpt.mpt_index);
	mr->mr_type = mr_type;
}

/*
 ****************************************************************************
 Prototype	: roce3_set_rdma_mw
 Description  : set the member of rdma_mw
 Input		: struct rdma_mw *mw
				u32 pdn
				enum ib_mw_type type
 Output	   : None

  1.Date		 : 2016/6/25
	Modification : Created function

****************************************************************************
*/
static void roce3_set_rdma_mw(struct rdma_mw *mw, u32 pdn, enum ib_mw_type type)
{
	mw->enabled = RDMA_MPT_EN_SW;
	mw->pdn = pdn;
	mw->key = get_key_from_index(mw->mpt.mpt_index);

	if (type == IB_MW_TYPE_1)
		mw->type = RDMA_MW_TYPE_1;
	else
		mw->type = RDMA_MW_TYPE_2;
}

/*
 ****************************************************************************
 Prototype	: roce3_get_dma_mr
 Description  : register DMA_MR
 Input		: struct ib_pd *ibpd
				int access
 Output	   : None

  1.Date		 : 2015/4/24
	Modification : Created function

****************************************************************************
*/
struct ib_mr *roce3_get_dma_mr(struct ib_pd *ibpd, int access)
{
	int ret = 0;
	struct roce3_mr *mr = NULL;
	struct roce3_pd *pd = NULL;
	struct roce3_device *rdev = NULL;

	if ((ibpd == NULL) || (check_ib_access(access) != 0)) {
		ret = -EINVAL;
		pr_err("[ROCE, ERR] %s: Invalid Param.p1:%d\n", __func__, access);
		goto err_out;
	}

	pd = to_roce3_pd(ibpd);
	rdev = to_roce3_dev(ibpd->device);
	if (roce3_hca_is_present(rdev) == 0) {
		dev_err(rdev->hwdev_hdl, "[ROCE] %s: HCA not present(return fail), func_id(%u)\n",
			__func__, rdev->glb_func_id);
		ret = -EPERM;
		goto err_out;
	}

	mr = kzalloc(sizeof(*mr), GFP_KERNEL);
	if (mr == NULL) {
		ret = -ENOMEM;
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to alloc memory for dma mr, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		goto err_out;
	}

	mr->rdmamr.mtt.mtt_type = MTT_DMTT_TYPE;
	ret = roce3_alloc_tpt(rdev, &mr->rdmamr, 0, 0);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to alloc mpt and mtt, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		goto err_alloc_tpt;
	}

	/* Set the content in rdma_mr */
	roce3_set_rdma_mr(&mr->rdmamr, RDMA_DMA_MR, pd->pdn, 0ULL, ROCE_DMA_MR_SIZE, (u32)access);

	ret = hmm_rdma_enable_mr_mpt(rdev->hwdev, &(mr->rdmamr), HINIC3_CHANNEL_ROCE);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to enable mpt of DMA mr, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		goto err_enable_mpt;
	}

	mr->ibmr.lkey = mr->rdmamr.key;
	mr->ibmr.rkey = mr->rdmamr.key;

	return &mr->ibmr;

err_enable_mpt:
	roce3_free_tpt(rdev, &mr->rdmamr);

err_alloc_tpt:
	kfree(mr);

err_out:
	return (struct ib_mr *)ERR_PTR((long)ret);
}

static int roce3_alloc_priv_pages(struct ib_device *ibdev, struct roce3_mr *rmr, u32 max_pages)
{
	int ret;

#ifndef __PC_LINT__
	rmr->page_map_size = roundup(max_pages * sizeof(u64), ROCE3_MR_PAGES_ALIGN);
#endif
	rmr->pages = (__be64 *)(void *)(uintptr_t)get_zeroed_page(GFP_KERNEL);
	if (rmr->pages == NULL) {
		pr_err("[ROCE] %s: Failed to alloc rmr->pages\n", __func__);
		ret = -ENOMEM;
		goto err_out;
	}

	rmr->page_map = dma_map_single(ibdev->dev.parent, rmr->pages,
		rmr->page_map_size, DMA_TO_DEVICE);
	if (dma_mapping_error(ibdev->dev.parent, rmr->page_map) != 0) {
		pr_err("[ROCE] %s: Failed to do dma mapping\n", __func__);
		ret = -ENOMEM;
		goto err_free_pages;
	}

	return 0;

err_free_pages:
	free_page((unsigned long)(uintptr_t)(void *)rmr->pages);

err_out:
	return ret;
}

static void roce3_free_priv_pages(struct roce3_mr *rmr)
{
	struct ib_device *ib_dev = rmr->ibmr.device;

	if (rmr->pages) {
		ib_dev = rmr->ibmr.device;
		dma_unmap_single(ib_dev->dev.parent, rmr->page_map,
			rmr->page_map_size, DMA_TO_DEVICE);
		free_page((unsigned long)(uintptr_t)(void *)rmr->pages);
		rmr->pages = NULL;
	}
}

static int roce3_alloc_mr_param_validate(const struct ib_pd *ibpd,
	enum ib_mr_type mr_type, u32 max_num_sg)
{
	int ret = 0;

	if (ibpd == NULL) {
		ret = -EINVAL;
		pr_err("[ROCE, ERR] %s: Ibpd is null\n", __func__);
		goto err_out;
	}

	/*lint -e746*/
	ret = roce3_check_alloc_mr_type(mr_type);
	/*lint +e746*/
	if (ret != 0) {
		ret = -EINVAL;
		pr_err("[ROCE, ERR] %s: mr_type is invalid\n", __func__);
		goto err_out;
	}

	if (max_num_sg >= ROCE_FRMR_MAX_PAGES) {
		pr_err("[ROCE] %s: Invalid max_num_sg(%d)\n", __func__, max_num_sg);
		ret = -EINVAL;
		goto err_out;
	}

	return 0;

err_out:
	return ret;
}

static int roce3_alloc_mr_param_check(struct roce3_device *rdev,
	struct roce3_mr **mr, u32 max_num_sg)
{
	if (roce3_hca_is_present(rdev) == 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE] %s: HCA not present(return fail), func_id(%u)\n",
			__func__, rdev->glb_func_id);
		return -ENOMEM;
	}

	*mr = kzalloc(sizeof(struct roce3_mr), GFP_KERNEL);
	if ((*mr) == NULL) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to alloc mr memory, func(%d)\n",
			__func__, rdev->glb_func_id);
		return -ENOMEM;
	}

	(*mr)->max_pages = max_num_sg;
	return 0;
}
/*
 ****************************************************************************
 Prototype	: roce3_alloc_mr
 Description  : register DMA_MR
 Input		: struct ib_pd *ibpd
				enum ib_mr_type mr_type
				u32 max_num_sg
 Output	   : None

  1.Date		 : 2015/4/24
	Modification : Created function

****************************************************************************
*/
struct ib_mr *roce3_alloc_mr(struct ib_pd *ibpd, enum ib_mr_type mr_type, u32 max_num_sg)
{
	int ret = 0;
	struct roce3_mr *mr = NULL;
	struct roce3_pd *pd = NULL;
	struct roce3_device *rdev = NULL;

	ret = roce3_alloc_mr_param_validate(ibpd, mr_type, max_num_sg);
	if (ret != 0)
		goto err_out;

	pd = to_roce3_pd(ibpd);
	rdev = to_roce3_dev(ibpd->device);

	ret = roce3_alloc_mr_param_check(rdev, &mr, max_num_sg);
	if (ret != 0)
		goto err_out;

	mr->rdmamr.mtt.mtt_type = MTT_DMTT_TYPE;
	ret = roce3_alloc_tpt(rdev, &mr->rdmamr, max_num_sg, 0); // alloc mptc and mtt
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to alloc tpt, func(%d)\n",
			__func__, rdev->glb_func_id);
		goto err_alloc_tpt;
	}

	ret = roce3_alloc_priv_pages(ibpd->device, mr, max_num_sg); // alloc memory to store pa
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE] %s: Failed to alloc memory, func(%u)\n",
			__func__, rdev->glb_func_id);
		goto err_alloc_priv_pages;
	}

	/*lint -e746*/
	roce3_set_rdma_mr(&mr->rdmamr, RDMA_FRMR, pd->pdn, 0ULL, 0, 0);
	/*lint +e746*/
	/* send to chip by cmdq */
	ret = hmm_rdma_enable_mr_mpt(rdev->hwdev, &(mr->rdmamr), HINIC3_CHANNEL_ROCE);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to enable mpt, func(%d)\n",
			__func__, rdev->glb_func_id);
		goto err_enale_mpt;
	}

	mr->ibmr.lkey = mr->rdmamr.key;
	mr->ibmr.rkey = mr->rdmamr.key;

	return &mr->ibmr;

err_enale_mpt:
	roce3_free_priv_pages(mr);

err_alloc_priv_pages:
	roce3_free_tpt(rdev, &mr->rdmamr);

err_alloc_tpt:
	kfree(mr);

err_out:
	return (struct ib_mr *)ERR_PTR((long)ret);
}

static int roce3_set_page(struct ib_mr *ibmr, u64 addr)
{
	struct roce3_mr *rmr = NULL;

	if (ibmr == NULL) {
		pr_err("[ROCE] %s: Ibmr is null\n", __func__);
		return -EINVAL;
	}

	rmr = to_roce3_mr(ibmr);
	if (ROCE_UNLIKELY(rmr->npages >= rmr->max_pages)) {
		pr_err("[ROCE] %s: Invalid npages(0x%x), can't set page\n", __func__, rmr->npages);
		return -ENOMEM;
	}

	rmr->pages[rmr->npages] = cpu_to_be64(addr | 0x1);
	rmr->npages++;

	return 0;
}

int roce3_map_kernel_frmr_sg(struct ib_mr *ibmr, struct scatterlist *sg,
	int sg_nents, unsigned int *sg_offset)
{
	int ret;
	struct roce3_mr *rmr = NULL;

	/* sg_offset can be null */
	if ((ibmr == NULL) || (sg == NULL)) {
		pr_err("[ROCE] %s: Ibmr or sg is null\n", __func__);
		return -EINVAL;
	}

	rmr = to_roce3_mr(ibmr);
	rmr->npages = 0;

	if (ROCE_UNLIKELY(((u32)sg_nents) >= rmr->max_pages)) {
		pr_err("[ROCE] %s: Invalid sg_nents(0x%x), ,max(0x%x)\n",
			__func__, sg_nents, rmr->max_pages);
		return -EINVAL;
	}

	ib_dma_sync_single_for_cpu(ibmr->device, rmr->page_map, rmr->page_map_size, DMA_TO_DEVICE);

	ret = ib_sg_to_pages(ibmr, sg, sg_nents, sg_offset, roce3_set_page);

	ib_dma_sync_single_for_device(ibmr->device, rmr->page_map,
		rmr->page_map_size, DMA_TO_DEVICE);

	return ret;
}

static int roce3_umem_write_mtt_check(const struct roce3_device *rdev, const struct rdma_mtt *mtt,
	const struct ib_umem *umem)
{
	if ((rdev == NULL) || (mtt == NULL) || (umem == NULL)) {
		pr_err("[ROCE, ERR] %s: Rdev or mtt or umem is null\n", __func__);
		return -EINVAL;
	}

	return 0;
}

static int roce3_umem_write_mtt_update(struct roce3_device *rdev,
	struct rdma_mtt *mtt, struct ib_umem *umem, u64 *page_list)
{
	int ret = 0;
	int i = 0;
	u32 j = 0;
	u32 pages_in_chunk = 0; /* The number of pages of a single memory block in umem_chunk */
	u32 npages = 0;		 /* The number of recorded pages */
	u32 start_index = 0;	/* page need to be written to mtt */
	struct scatterlist *sg = NULL;
	u64 page_size = BIT(mtt->buf_page_shift);
	u64 page_mask = ~(page_size - 1);
	u64 dma_addr;

	for_each_sg(umem->sg_head.sgl, sg, umem->nmap, i) {
		/*
		 * Calculate the number of pages in a memory block,
		 * the page size is 1 << page_shift
		 */
		dma_addr = sg_dma_address(sg) & page_mask;
		pages_in_chunk = DIV_ROUND_UP(sg_dma_len(sg), page_size);
		for (j = 0; j < pages_in_chunk; ++j) {
			page_list[npages] = dma_addr + (page_size * j);
			npages++;
		/*
		 * The size of the memory pointed to by page_list is one page,
		 * which can store up to PAGE_SIZE / sizeof(u64) pas. After a page is full,
		 * mtt needs to be written, else continue
		 */
			if (npages != PAGE_SIZE / sizeof(u64))
				continue;

			ret = hmm_rdma_write_mtt(rdev->hwdev, mtt, start_index,
				npages, page_list, SERVICE_T_ROCE);
			if (ret) {
				dev_err(rdev->hwdev_hdl,
					"[ROCE, ERR] %s: Failed to write mtt, func_id(%u)\n",
					__func__, rdev->glb_func_id);
				return ret;
			}
			start_index += npages;
			npages = 0;
		}
	}

	if (npages != 0) {
		ret = hmm_rdma_write_mtt(rdev->hwdev, mtt, start_index, npages,
			page_list, SERVICE_T_ROCE);
		if (ret != 0) {
			dev_err(rdev->hwdev_hdl,
				"[ROCE, ERR] %s: Failed to write mtt, ret(%d), start_index(%u), func_id(%u)\n",
				__func__, ret, start_index, rdev->glb_func_id);
		}
	}

	return ret;
}

int roce3_umem_write_mtt(struct roce3_device *rdev, struct rdma_mtt *mtt, struct ib_umem *umem)
{
	int ret = 0;
	u64 *page_list = NULL; /* page_list to write to mtt */

	ret = roce3_umem_write_mtt_check(rdev, mtt, umem);
	if (ret != 0)
		return ret;

	page_list = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (page_list == NULL)
		return -ENOMEM;

	ret = roce3_umem_write_mtt_update(rdev, mtt, umem, page_list);
	kfree(page_list);
	return ret;
}

/*
 ****************************************************************************
 Prototype	: roce3_buf_write_mtt
 Description  : roce3_buf_write_mtt
 Input		: struct roce3_device *rdev
				struct rdma_mtt *mtt
				struct tag_cqm_buf *buf
 Output	   : None

  1.Date		 : 2015/4/24
	Modification : Created function

****************************************************************************
*/
int roce3_buf_write_mtt(struct roce3_device *rdev, struct rdma_mtt *mtt, struct tag_cqm_buf *buf)
{
	u64 *page_list = NULL;
	int ret = 0;
	u32 i = 0;

	if ((rdev == NULL) || (mtt == NULL) || (buf == NULL)) {
		pr_err("[ROCE, ERR] %s: Rdev or mtt or buf is null\n", __func__);
		return (-EINVAL);
	}

	page_list = kzalloc(buf->buf_number * sizeof(*page_list), GFP_KERNEL);
	if (page_list == NULL)
		return (-ENOMEM);

	/* Each buf is written to MTT as a page, buf_size is 2^n times PAGE_SIZE */
	for (i = 0; i < buf->buf_number; ++i)
		page_list[i] = buf->buf_list[i].pa;

	ret = hmm_rdma_write_mtt(rdev->hwdev, mtt, 0, buf->buf_number, page_list, SERVICE_T_ROCE);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to write mtt, func_id(%d)\n",
			__func__, rdev->glb_func_id);
	}

	kfree(page_list);

	return ret;
}

int roce3_user_mr_reg(struct roce3_device *rdev, struct roce3_mr *mr, u32 pdn, u64 virt_addr,
	u64 length, int access)
{
	int ret = 0;
	u32 npages = 0;
	u32 page_shift = PAGE_SHIFT;
	struct hinic3_hwdev *hwdev = (struct hinic3_hwdev *)rdev->hwdev;

	if (hwdev == NULL) {
		pr_err("[HMM, ERR] %s(%d): hwdev is null\n", __func__, __LINE__);
		return 0;
	}

	mr->rdmamr.mtt.mtt_type = MTT_DMTT_TYPE;
	npages = (u32)ib_umem_num_pages(mr->umem);
#ifdef CONFIG_CENTRALIZED_STORAGE
	if (mr->umem->is_umm_mem) {
		page_shift = PAGE_SHIFT_2M;
		npages = ib_umem_num_dma_blocks(mr->umem, BIT(page_shift));
	}
#endif
	ret = roce3_alloc_tpt(rdev, &mr->rdmamr, npages, page_shift);
	if (ret != 0) {
		dev_err(hwdev->dev_hdl,
			"[ROCE, ERR] %s(%d): Failed to alloc mpt and mtt, func_id(%u)\n",
			__func__, __LINE__, hinic3_global_func_id(hwdev));
		goto err_alloc_tpt;
	}

	roce3_set_rdma_mr(&mr->rdmamr, RDMA_USER_MR, pdn, virt_addr, length, (u32)access);

	ret = roce3_umem_write_mtt(rdev, &mr->rdmamr.mtt, mr->umem);
	if (ret != 0) {
		dev_err(hwdev->dev_hdl,
			"[ROCE, ERR] %s(%d): Failed to write mtt, func_id(%u)\n",
			__func__, __LINE__, hinic3_global_func_id(hwdev));
		goto err_write_mtt;
	}

	ret = hmm_rdma_enable_mr_mpt(hwdev, &mr->rdmamr, HINIC3_CHANNEL_ROCE);
	if (ret != 0) {
		dev_err(hwdev->dev_hdl,
			"[ROCE, ERR] %s(%d): Failed to enable mpt of user mr, func_id(%u)\n",
			__func__, __LINE__, hinic3_global_func_id(hwdev));
		goto err_write_mtt;
	}

	return 0;

err_write_mtt:
	roce3_free_tpt(rdev, &mr->rdmamr);

err_alloc_tpt:
	return ret;
}

static int roce3_check_mr_param(struct ib_pd *ibpd)
{
	struct roce3_device *rdev = NULL;

	if (ibpd == NULL) {
		pr_err("[ROCE, ERR] %s: Ibpd is null\n", __func__);
		return -EINVAL;
	}

	rdev = to_roce3_dev(ibpd->device);
	if (roce3_hca_is_present(rdev) == 0) {
		pr_err("[ROCE] %s: HCA not present(return fail), func_id(%u)\n",
			__func__, rdev->glb_func_id);
		return -EPERM;
	}

	return 0;
}

/*
 ****************************************************************************
 Prototype	: roce3_reg_user_mr
 Description  : register MR for user
 Input		: struct ib_pd *ibpd
				u64 start
				u64 length
				u64 virt_addr
				int access
				struct ib_udata *udata
 Output	   : None

  1.Date		 : 2015/4/24
	Modification : Created function

****************************************************************************
*/
struct ib_mr *roce3_reg_user_mr(struct ib_pd *ibpd, u64 start,
	u64 length, u64 virt_addr, int access, struct ib_udata *udata)
{
	int ret;
	struct roce3_mr *mr = NULL;
	struct roce3_device *rdev = NULL;
	struct roce3_pd *pd;

	ret = roce3_check_mr_param(ibpd);
	if (ret != 0)
		goto err_out;

	pd = to_roce3_pd(ibpd);
	rdev = to_roce3_dev(ibpd->device);

	mr = kzalloc(sizeof(*mr), GFP_KERNEL);
	if (mr == NULL) {
		ret = -ENOMEM;
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to alloc memory for roce mr, func_id(%u)\n",
			__func__, rdev->glb_func_id);
		goto err_out;
	}

	mr->umem = ib_umem_get(&rdev->ib_dev, start, (size_t)length, access);
	if (IS_ERR(mr->umem)) {
		ret = (int)PTR_ERR(mr->umem);
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to get ib umem, func_id(%u)\n",
			__func__, rdev->glb_func_id);
		goto err_get_umem;
	}

	ret = roce3_user_mr_reg(rdev, mr, pd->pdn, virt_addr, length, access);
	if (ret != 0)
		goto err_mr_update;

	mr->ibmr.lkey = mr->rdmamr.key;
	mr->ibmr.rkey = mr->rdmamr.key;

	return &mr->ibmr;

err_mr_update:
	ib_umem_release(mr->umem);

err_get_umem:
	kfree(mr);

err_out:
	return (struct ib_mr *)ERR_PTR((long)ret);
}

int roce3_dereg_mr(struct ib_mr *ibmr, struct ib_udata *udata)
{
	int ret = 0;
	struct roce3_mr *mr = NULL;
	struct roce3_device *rdev = NULL;

	if (ibmr == NULL) {
		pr_err("[ROCE, ERR] %s: Ibmr is null\n", __func__);
		return -EINVAL;
	}

	mr = to_roce3_mr(ibmr);
	rdev = to_roce3_dev(ibmr->device);

	roce3_free_priv_pages(mr);

	ret = hmm_rdma_disable_mr_mpt(rdev->hwdev, &mr->rdmamr, SERVICE_T_ROCE,
		HINIC3_CHANNEL_ROCE);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to disable mpt of mr, ret(%d), func_id(%d)\n",
			__func__, ret, rdev->glb_func_id);
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Mr may has mw bind on it, mr_key(%#x), func_id(%d)\n",
			__func__, mr->rdmamr.key, rdev->glb_func_id);
		if (ret == (-RDMA_CMDQ_TIMEOUT))
			rdev->dev_status_to_ofed = ROCE_DEV_STATUS_CMDQ_TIMEOUT;

		return ret;
	}

	roce3_free_tpt(rdev, &mr->rdmamr);

	if (mr->umem)
		ib_umem_release(mr->umem);

	return 0;
}

static void roce3_err_enable_mpt_handler(void *hwdev, struct roce3_mw *mw)
{
	hmm_rdma_mpt_free(hwdev, &mw->rdmamw.mpt);
	mw->rdmamw.enabled = RDMA_MPT_DISABLED;
}

int roce3_alloc_mw(struct ib_mw *ibmw, struct ib_udata *udata)
{
	int ret;
	struct roce3_mw *mw = to_roce3_mw(ibmw);
	struct roce3_pd *pd = to_roce3_pd(ibmw->pd);
	struct roce3_device *rdev = to_roce3_dev(ibmw->device);

	if (roce3_hca_is_present(rdev) == 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE] %s: HCA not present(return fail), func_id(%u)\n",
			__func__, rdev->glb_func_id);
		return -EPERM;
	}

	ret = hmm_rdma_mpt_alloc(rdev->hwdev, &mw->rdmamw.mpt, SERVICE_T_ROCE);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to alloc mpt, func_id(%u)\n",
			__func__, rdev->glb_func_id);
		goto err;
	}

	roce3_set_rdma_mw(&mw->rdmamw, pd->pdn, ibmw->type);
	ret = roce3_rdma_enable_mw_mpt(rdev->hwdev, &mw->rdmamw, SERVICE_T_ROCE);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to enable mpt of mw, func_id(%u)\n",
			__func__, rdev->glb_func_id);
		if (ret == (-RDMA_CMDQ_TIMEOUT))
			rdev->dev_status_to_ofed = ROCE_DEV_STATUS_CMDQ_TIMEOUT;

		goto err_enable_mpt;
	}

	mw->ibmw.rkey = mw->rdmamw.key;
	return 0;
err_enable_mpt:
	roce3_err_enable_mpt_handler(rdev->hwdev, mw);
err:
	return ret;
}

int roce3_dealloc_mw(struct ib_mw *ibmw)
{
	int ret = 0;
	struct roce3_mw *mw = NULL;
	struct roce3_device *rdev = NULL;

	if (ibmw == NULL) {
		pr_err("[ROCE, ERR] %s: Ibmw is null\n", __func__);
		return -EINVAL;
	}

	mw = to_roce3_mw(ibmw);
	rdev = to_roce3_dev(ibmw->device);
	ret = roce3_rdma_disable_mw_mpt(rdev->hwdev, &mw->rdmamw, SERVICE_T_ROCE);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] %s: Failed to disable mpt of mw, func_id(%d)\n",
			__func__, rdev->glb_func_id);
		if (ret == (-RDMA_CMDQ_TIMEOUT))
			rdev->dev_status_to_ofed = ROCE_DEV_STATUS_CMDQ_TIMEOUT;

		return ret;
	}

	hmm_rdma_mpt_free(rdev->hwdev, &mw->rdmamw.mpt);

	mw->rdmamw.enabled = RDMA_MPT_DISABLED;

	return 0;
}
