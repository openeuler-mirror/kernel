// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2021, NEBULARMATRIX */

#include <linux/kernel.h>
#include <linux/bitfield.h>
#include <linux/dma-buf.h>
#include "nbl_compat.h"
#include <linux/dma-resv.h>
#include <rdma/ib_umem_odp.h>
#include "cqp.h"
#include "main.h"
#include "pble.h"
#include "mr.h"
#include "defs.h"
#include "pd.h"
#include "mem.h"
#include "device.h"
#include "user.h"
#include "debug.h"
#include "counters.h"
#include "dump_fields.h"
#include "umr.h"

static int nbl_create_stag(struct nbl_device *nbl_dev, u32 *stag)
{
	u32 stag_index = 0;
	u32 next_stag_idx = 0;
	u32 random;
	u8 consumer_key;
	int ret;

	get_random_bytes(&random, sizeof(random));
	consumer_key = (u8)random;
	ret = nbl_alloc_rsrc(&nbl_dev->rf->rsrc_lock, nbl_dev->rf->allocated_mrs,
			     nbl_dev->rf->max_mr, &stag_index, &next_stag_idx);
	if (ret)
		return -ENOMEM;

	*stag = stag_index << 8;
	*stag |= consumer_key;
	return 0;
}

static void nbl_free_stag(struct nbl_device *nbl_dev, u32 stag)
{
	u32 stag_idx;

	stag_idx = stag >> 8;
	nbl_free_rsrc(&nbl_dev->rf->rsrc_lock, nbl_dev->rf->allocated_mrs, stag_idx);
}

u16 nbl_get_mr_access(struct nbl_device *nbl_dev, int access)
{
	u16 hw_access = 0;

	hw_access |= (access & IB_ACCESS_LOCAL_WRITE) ? NBL_MR_RIGHTS_LW : 0;
	hw_access |= (access & IB_ACCESS_REMOTE_WRITE) ? NBL_MR_RIGHTS_RW : 0;
	hw_access |= (access & IB_ACCESS_REMOTE_READ) ? NBL_MR_RIGHTS_RR : 0;
	hw_access |= (access & IB_ACCESS_MW_BIND) ? NBL_MR_RIGHTS_BIND : 0;
	hw_access |= NBL_MR_RIGHTS_LR;

	if (access & IB_ACCESS_REMOTE_ATOMIC) {
		if (!nbl_dev->atomic_cap)
			nbl_pr_warn(
				"Ignore: request REMOTE_ATOMIC MR access but pcie RC notsupport atomic.\n");
		else
			hw_access |= NBL_MR_RIGHTS_ATOMIC;
	}

	return hw_access;
}

static int nbl_flush_pblc(struct nbl_pci_f *rf, struct nbl_mr *mr)
{
	int err_code = 0;
	__be64 *in;
	u32 first_pble_idx;
	u32 last_pble_idx;

	if (!mr->pbl.pbl_allocated) {
		nbl_ib_warn(&rf->sc_dev, "no pblc need to flush");
		return -EINVAL;
	}

	first_pble_idx = mr->pbl.pble_alloc.pble_info.idx;
	last_pble_idx = first_pble_idx + mr->page_cnt - 1;

	in = kzalloc(NBL_CMD_INPUT_SIZE, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	set_64bit_val(in, 0, FIELD_PREP(NBL_CQPSQ_OPCODE, NBL_CQP_OP_FLUSH_CACHE) |
			FIELD_PREP(NBL_CQP_FLUASH_CACHE_TYPE, FLUSH_CACHE_PBLC) |
			FIELD_PREP(NBL_CQPSQ_FIRST_PBL_ID, first_pble_idx));

	set_64bit_val(in, 8, FIELD_PREP(NBL_CQPSQ_LAST_PBL_ID, last_pble_idx) |
			FIELD_PREP(NBL_CQP_FLUASH_CACHE_VFID, rf->sc_dev.function_id));

	err_code = nbl_cmd_exec(rf, in, NBL_CMD_INPUT_SIZE, NULL, 0);
	if (err_code)
		nbl_ib_err(&rf->sc_dev, "flush pblc cmd err=%d", err_code);

	kfree(in);
	return err_code;
}

static int nbl_hwreg_mr(struct nbl_device *nbl_dev, struct nbl_mr *mr,
			u16 access)
{
	struct nbl_pd *pd = to_nbl_pd(mr->ibmr.pd);
	int err_code;
	__be64 *in;
	u32 first_pble_idx;
	u16 mr_rights = nbl_get_mr_access(nbl_dev, access);
	enum nbl_page_size pg_sz;
	enum nbl_address_type addr_type;
	u64 fbo;
	u8 leaf_sz;
	u64 hw_pa;

	fbo = mr->pbl.usr_base & (mr->page_sz - 1);
	if (mr->page_sz == SZ_4K) {
		pg_sz = NBL_PAGE_SIZE_4K;
		hw_pa = mr->pa & ~(SZ_4K - 1);
	} else if (mr->page_sz == SZ_2M) {
		pg_sz = NBL_PAGE_SIZE_2M;
		hw_pa = mr->pa & ~(SZ_2M - 1);
	} else if (mr->page_sz == SZ_1G) {
		pg_sz = NBL_PAGE_SIZE_1G;
		hw_pa = mr->pa & ~(SZ_1G - 1);
	} else
		return -EINVAL;

	/* When (access & IB_ZERO_BASED), we should set addr type to
	 * NBL_ADDR_TYPE_ZERO_BASED, But now ASIC only support va based,
	 * and addr type 0 is used only for FMR. So here just set
	 * addr type to 1 for ASIC. ONLY for ASIC.
	 */
	addr_type = NBL_ADDR_TYPE_VA_BASED;

	in = kzalloc(NBL_CMD_INPUT_SIZE, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	leaf_sz = mr->pbl.pbl_allocated ? 1 : 0;
	set_64bit_val(in, 0,
		      FIELD_PREP(NBL_CQPSQ_OPCODE, NBL_CQP_OP_REG_MR) |
			      FIELD_PREP(NBL_CQPSQ_MR_STAT, NBL_MR_STAT_VALID) |
			      FIELD_PREP(NBL_CQPSQ_MR_TYPE, NBL_MR_TYPE_MR) |
			      FIELD_PREP(NBL_CQPSQ_MR_RIGHTS, mr_rights) |
			      FIELD_PREP(NBL_CQPSQ_MR_INV, 1) |
			      FIELD_PREP(NBL_CQPSQ_MR_LEAF_SIZE, leaf_sz) |
			      FIELD_PREP(NBL_CQPSQ_MR_HOST_PGSZ, pg_sz) |
			      FIELD_PREP(NBL_CQPSQ_MR_ADDR_TYPE, addr_type) |
			      FIELD_PREP(NBL_CQPSQ_MR_PDN, pd->sc_pd.pd_id) |
			      FIELD_PREP(NBL_CQPSQ_MR_KEY, (mr->stag & 0xFF)));

	set_64bit_val(in, 8, FIELD_PREP(NBL_CQPSQ_MR_LEN, mr->len));
	set_64bit_val(in, 16,
		      (addr_type == NBL_ADDR_TYPE_VA_BASED ?
			       mr->pbl.usr_base :
			       fbo));

	/* TBD pbl_allocated will be set true in nbl_setup_pbles */
	if (mr->pbl.pbl_allocated) {
		first_pble_idx = mr->pbl.pble_alloc.pble_info.idx;
		set_64bit_val(in, 24, FIELD_PREP(NBL_CQPSQ_FIRST_PBL_ID, first_pble_idx));
	} else
		set_64bit_val(in, 24, hw_pa);

	set_64bit_val(in, 32, FIELD_PREP(NBL_CQPSQ_MR_IDX, (mr->stag >> 8)));
	err_code = nbl_cmd_exec(nbl_dev->rf, in, NBL_CMD_INPUT_SIZE, NULL, 0);

	kfree(in);
	return err_code;
}

static void nbl_pble_copy_user_pgaddrs(struct nbl_mr *mr, struct nbl_pble_alloc *pble_alloc)
{
	struct ib_umem *region = mr->region;
	struct ib_block_iter biter;
	struct nbl_pble_info *pble_info = &pble_alloc->pble_info;
	struct list_head *chunk_entry = NULL;
	struct nbl_chunk *pchunk = pble_info->first_chunk.pchunk;
	u64 *pbl;
	u64 tmp_addr;
	u32 total_cnt = pble_alloc->total_cnt;
	u32 idx = pble_info->first_chunk.bit_idx;
	u32 pbl_cnt = 0;
	u32 page_idx = 0;

	/* get the first pble addr */
	pbl = pble_info->addr;

	rdma_umem_for_each_dma_block(region, &biter, mr->page_sz) {
		tmp_addr = (rdma_block_iter_dma_address(&biter) | NBL_PBLE_VLD_FLAG);
		/* skip invalid pages if mr start va page_offset larger than mr page_sz */
		if (mr->sys_page_offset > mr->page_sz) {
			if (page_idx < mr->sys_page_offset / mr->page_sz) {
				page_idx++;
				continue;
			}

		}
		*pbl = cpu_to_be64(tmp_addr);
		if (++pbl_cnt == total_cnt)
			break;
		idx++;
		pbl++;
		if (idx >= pble_info->pble_cnt_per_chunk) {
			idx = 0;
			chunk_entry = pchunk->list.next;
			pchunk = list_entry(chunk_entry, struct nbl_chunk, list);
			pbl = pchunk->va;
		}
	}
}

static int nbl_setup_pbles(struct nbl_pci_f *rf, struct nbl_mr *mr,
			   bool use_pbles)
{
	struct nbl_pbl *pbl = &mr->pbl;
	struct nbl_pble_alloc *pble_alloc = &pbl->pble_alloc;
	int ret;

	ret = nbl_get_pble(rf, pble_alloc, mr->page_cnt);
	if (ret) {
		nbl_ib_err(&rf->sc_dev, "get nbl pble failed.\n");
		return ret;
	}

	nbl_pr_dbg("the mr->page_cnt is %u.\n", mr->page_cnt);

	pbl->pbl_allocated = true; /* indicate get pble success */

	nbl_pble_copy_user_pgaddrs(mr, pble_alloc);

	return 0;
}


#if RUN_IN_MLX_OFED
static void nbl_invalidate_umem(struct ib_umem *umem, void *priv)
{
	struct nbl_mr *mr = priv;

	if (unlikely(!mr)) {
		nbl_pr_err("umr not exist\n");
		return;
	}
	nbl_umr_revoke_mr(mr);
}
#endif

struct ib_mr *nbl_ib_reg_user_mr(struct ib_pd *pd, u64 start, u64 length,
				 u64 iova, int access_flags,
				 struct ib_udata *udata)
{
	struct nbl_device *nbl_dev = to_nbl_dev(pd->device);
	struct ib_umem *region;
	struct nbl_mr *mr;
	struct nbl_pbl *pbl;
	struct nbl_pble_alloc *palloc;
	bool use_pbles = false;
	int err = -EINVAL;
	u32 stag = 0;
	bool is_continue = false;
	u32 page_num = 0;
	struct nbl_sc_dev *sc_dev = &nbl_dev->rf->sc_dev;
	unsigned long flags;

	nbl_ib_dbg(sc_dev, "start=0x%llx,length=0x%llx,access=0x%x", start, length, access_flags);

	if (length > nbl_dev->rf->sc_dev.hw_attrs.max_mr_size) {
		nbl_ib_err(&nbl_dev->rf->sc_dev, "invalid length.\n");
		return ERR_PTR(-EINVAL);
	}

#if RUN_IN_MLX_OFED
	region = ib_umem_get_peer(pd->device, start, length, access_flags,
		IB_PEER_MEM_INVAL_SUPP);
#else
	region = ib_umem_get(pd->device, start, length, access_flags);
#endif

	if (IS_ERR(region)) {
		nbl_ib_err(&nbl_dev->rf->sc_dev, "get ib umem failed.\n");
		return (struct ib_mr *)region;
	}

	nbl_ib_dbg(sc_dev, "kern region info:address=0x%lx,length=0x%lx",
		   region->address, region->length);

	mr = kzalloc(sizeof(*mr), GFP_KERNEL);
	if (!mr) {
		ib_umem_release(region);
		return ERR_PTR(-ENOMEM);
	}

	pbl = &mr->pbl;
	pbl->mr = mr;
	mr->region = region;
	mr->ibmr.pd = pd;
	mr->ibmr.device = pd->device;
	mr->ibmr.iova = iova;

	mr->page_sz =
		ib_umem_find_best_pgsz(region, PAGE_SIZE | SZ_2M | SZ_1G, iova);
	if (unlikely(!mr->page_sz)) {
		nbl_ib_err(&nbl_dev->rf->sc_dev, "find best pgsz failed.\n");
		kfree(mr);
		ib_umem_release(region);
		return ERR_PTR(-EOPNOTSUPP);
	}

	mr->len = region->length;
	pbl->usr_base = iova;
	palloc = &pbl->pble_alloc;
	mr->page_cnt = ib_umem_num_dma_blocks(region, mr->page_sz);
	mr->access_flags = access_flags;

	nbl_get_umem_info(region, &page_num, &is_continue);
	mr->sys_page_offset = iova & (PAGE_SIZE - 1);
	nbl_ib_dbg(sc_dev, "mr page_sz=0x%llx,page_cnt=0x%x,pa=0x%llx,custom 4K pg_num=%u,is_continue=%u",
		   mr->page_sz, mr->page_cnt, nbl_get_first_sg_dma_addr(region),
		   page_num, is_continue);
	if (!is_continue) {
		use_pbles = true;
		if (mr->page_sz == SZ_64K || mr->page_sz == SZ_16K) {
			mr->page_sz = NBL_ADAPTER_PAGE_SIZE;
			mr->page_cnt = (ALIGN(iova + mr->len, mr->page_sz) -
					ALIGN_DOWN(iova, mr->page_sz)) / mr->page_sz;
		}
		err = nbl_setup_pbles(nbl_dev->rf, mr, use_pbles);
		if (err) {
			nbl_ib_err(&nbl_dev->rf->sc_dev, "set nbl pbles failed.\n");
			goto error;
		}
	} else {
		pbl->pbl_allocated = false;
		mr->pa = nbl_get_first_sg_dma_addr(region);
		if (mr->page_sz == SZ_64K || mr->page_sz == SZ_16K) {
			mr->page_sz = NBL_ADAPTER_PAGE_SIZE;
			mr->pa += (mr->sys_page_offset & ~(NBL_ADAPTER_PAGE_SIZE - 1));
		}
		nbl_ib_dbg(sc_dev, "mr->pa=0x%llx", mr->pa);
	}

	err = nbl_create_stag(nbl_dev, &stag);
	if (err) {
		nbl_ib_err(&nbl_dev->rf->sc_dev, "create nbl stag failed.\n");
		err = -ENOMEM;
		goto error;
	}

	nbl_ib_dbg(sc_dev, "created stag=0x%x", stag);
	mr->stag = stag;
	mr->ibmr.rkey = stag;
	mr->ibmr.lkey = stag;
	err = nbl_hwreg_mr(nbl_dev, mr, access_flags);
	if (err) {
		nbl_ib_err(&nbl_dev->rf->sc_dev, "nbl hwreg mr failed.\n");
		nbl_free_stag(nbl_dev, stag);
		goto error;
	}

#if RUN_IN_MLX_OFED
	if (region->is_peer)
		ib_umem_activate_invalidation_notifier(
			mr->region, nbl_invalidate_umem, mr);
#endif

	atomic_inc(&nbl_dev->rf->used_mrs_a);

	spin_lock_irqsave(&nbl_dev->rf->mrtable_lock, flags);
	nbl_dev->rf->mr_table[mr->stag >> 8] = mr;
	spin_unlock_irqrestore(&nbl_dev->rf->mrtable_lock, flags);

	return &mr->ibmr;

error:
	if (pbl->pbl_allocated)
		nbl_free_pble(nbl_dev->rf->pble_rsrc, palloc);

	ib_umem_release(region);
	kfree(mr);
	return ERR_PTR(err);
}

int nbl_ib_dereg_mr(struct ib_mr *ibmr, struct ib_udata *udata)
{
	struct nbl_device *nbl_dev = to_nbl_dev(ibmr->device);
	struct nbl_mr *mr = to_nbl_mr(ibmr);
	struct nbl_pbl *pbl = &mr->pbl;
	struct nbl_pble_alloc *palloc = &pbl->pble_alloc;
	struct nbl_pd *pd = to_nbl_pd(mr->ibmr.pd);
	int err_code;
	__le64 *in;
	unsigned long flags;

	in = kzalloc(NBL_CMD_INPUT_SIZE, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	set_64bit_val(in, 0,
		      FIELD_PREP(NBL_CQPSQ_OPCODE, NBL_CQP_OP_DEALLOC_STAG) |
			  FIELD_PREP(NBL_CQPSQ_MR_PDN, pd->sc_pd.pd_id));
	set_64bit_val(in, 32, FIELD_PREP(NBL_CQPSQ_MR_IDX, (mr->stag >> 8)));
	err_code = nbl_cmd_exec(nbl_dev->rf, in, NBL_CMD_INPUT_SIZE, NULL, 0);
	if (err_code)
		nbl_ib_err(&nbl_dev->rf->sc_dev, "dereg mr cmd err=%d", err_code);

	kfree(in);
	nbl_free_stag(nbl_dev, mr->stag);
	if (pbl->pbl_allocated) {
		nbl_free_pble(nbl_dev->rf->pble_rsrc, palloc);
		err_code = nbl_flush_pblc(nbl_dev->rf, mr);
		if (err_code)
			nbl_ib_err(&nbl_dev->rf->sc_dev, "flush pblc err=%d", err_code);
	}

	nbl_ib_dbg(&nbl_dev->rf->sc_dev, "the released address of region is %p,stag=%#x.\n",
		   mr->region, mr->stag);

#if RUN_IN_MLX_OFED
	if (mr->region && mr->region->is_peer)
		ib_umem_stop_invalidation_notifier(mr->region);
#endif

	spin_lock_irqsave(&nbl_dev->rf->mrtable_lock, flags);
	nbl_dev->rf->mr_table[mr->stag >> 8] = NULL;
	spin_unlock_irqrestore(&nbl_dev->rf->mrtable_lock, flags);

	if (mr->region)
		ib_umem_release(mr->region);
	kfree(mr);

	if (atomic_read(&nbl_dev->rf->used_mrs_a))
		atomic_dec(&nbl_dev->rf->used_mrs_a);
	nbl_ib_dbg(&nbl_dev->rf->sc_dev, "deregister nbl memory region succ,used_mrs=0x%x.\n",
		atomic_read(&nbl_dev->rf->used_mrs_a));
	return 0;
}

struct ib_mr *nbl_ib_rereg_user_mr(struct ib_mr *ib_mr, int flags, u64 new_start,
				   u64 length, u64 virt_addr,
				   int new_access_flags, struct ib_pd *new_pd,
				   struct ib_udata *udata)
{
	struct nbl_device *nbl_dev = to_nbl_dev(ib_mr->device);
	struct nbl_mr *mr = to_nbl_mr(ib_mr);
	struct ib_pd *pd = (flags & IB_MR_REREG_PD) ? new_pd : ib_mr->pd;
	int access_flags = (flags & IB_MR_REREG_ACCESS) ? new_access_flags :
							  mr->access_flags;
	u64 addr, len, start = 0;
	int ret;

	nbl_ib_dbg(
		&nbl_dev->rf->sc_dev,
		"start 0x%llx, virt_addr 0x%llx, length 0x%llx, access_flags 0x%x\n",
		start, virt_addr, length, access_flags);

	if (!mr->region)
		return ERR_PTR(-ENOMEM);

	if (mr->region->is_odp)
		return ERR_PTR(-EOPNOTSUPP);

	if (flags & IB_MR_REREG_TRANS) {
		addr = virt_addr;
		len = length;
		start = new_start;
	} else {
		addr = mr->region->address;
		len = mr->region->length;
		start = addr;
	}

	if (flags != IB_MR_REREG_PD) {
		/* process for access or trans change */
		ib_umem_release(mr->region);
		mr->region = NULL;

		/* access or trans change: register a new nbl memory region */
		return nbl_ib_reg_user_mr(pd, start, len, addr, access_flags, udata);
	}

	/* process for only PD change */
	mr->ibmr.pd = pd;
	mr->ibmr.device = pd->device;

	ret = nbl_hwreg_mr(nbl_dev, mr, access_flags);
	if (ret) {
		nbl_ib_err(&nbl_dev->rf->sc_dev, "hwreg mr failed!\n");
		return ERR_PTR(ret);
	}

#if RUN_IN_MLX_OFED
	if (mr->region->is_peer)
		ib_umem_activate_invalidation_notifier(
			mr->region, nbl_invalidate_umem, mr);
#endif

	return NULL;
}

static int nbl_hw_alloc_stag(struct nbl_device *nbl_dev, struct nbl_mr *nbl_mr)
{
	struct nbl_pd *pd = to_nbl_pd(nbl_mr->ibmr.pd);
	int err_code;
	__be64 *in;

	in = kzalloc(NBL_CMD_INPUT_SIZE, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	set_64bit_val(
		in, 0,
		FIELD_PREP(NBL_CQPSQ_OPCODE, NBL_CQP_OP_ALLOC_STAG) |
			FIELD_PREP(NBL_CQPSQ_MR_STAT, NBL_MR_STAT_FREE) |
			FIELD_PREP(NBL_CQPSQ_MR_TYPE, NBL_MR_TYPE_MR) |
			FIELD_PREP(NBL_CQPSQ_MR_HOST_PGSZ, NBL_PAGE_SIZE_4K) |
			FIELD_PREP(NBL_CQPSQ_MR_PDN, pd->sc_pd.pd_id) |
			FIELD_PREP(NBL_CQPSQ_MR_INV, 1) |
			FIELD_PREP(NBL_CQPSQ_MR_ADDR_TYPE, NBL_ADDR_TYPE_VA_BASED) |
			FIELD_PREP(NBL_CQPSQ_MR_KEY, (nbl_mr->stag & 0xFF)));

	set_64bit_val(in, 8, FIELD_PREP(NBL_CQPSQ_MR_LEN, nbl_mr->len));
	set_64bit_val(in, 32,
		      FIELD_PREP(NBL_CQPSQ_MR_IDX, (nbl_mr->stag >> 8)));

	err_code = nbl_cmd_exec(nbl_dev->rf, in, NBL_CMD_INPUT_SIZE, NULL, 0);

	kfree(in);
	return err_code;
}

/**
 * nbl_ib_alloc_mr: register stag for fast memory registration
 * @pd: ib_pd pointer
 * @mr_type: memory region type
 * @max_num_sg: maximum sg entries available for registration
 */
struct ib_mr *nbl_ib_alloc_mr(struct ib_pd *pd, enum ib_mr_type mr_type,
			      u32 max_num_sg)
{
	struct nbl_device *nbl_dev = to_nbl_dev(pd->device);
	struct nbl_pble_alloc *palloc;
	struct nbl_pbl *nbl_pbl;
	struct nbl_mr *nbl_mr;
	enum nbl_status_code status;
	u32 stag;
	int ret;
	int err_code = 0;
	unsigned long flags;

	nbl_mr = kzalloc(sizeof(*nbl_mr), GFP_KERNEL);
	if (!nbl_mr)
		return ERR_PTR(-ENOMEM);

	ret = nbl_create_stag(nbl_dev, &stag);
	if (ret) {
		nbl_ib_err(&nbl_dev->rf->sc_dev, "create stag failed!\n");
		err_code = -ENOMEM;
		goto err;
	}

	nbl_mr->stag = stag;
	nbl_mr->ibmr.lkey = stag;
	nbl_mr->ibmr.rkey = stag;
	nbl_mr->ibmr.pd = pd;
	nbl_mr->ibmr.device = pd->device;
	nbl_mr->page_cnt = max_num_sg;
	nbl_pbl = &nbl_mr->pbl;
	nbl_pbl->mr = nbl_mr;
	palloc = &nbl_pbl->pble_alloc;

	status = nbl_get_pble(nbl_dev->rf, palloc, nbl_mr->page_cnt);
	if (status) {
		nbl_ib_err(&nbl_dev->rf->sc_dev, "get pble failed!\n");
		err_code = status;
		goto err_get_pble;
	}

	err_code = nbl_hw_alloc_stag(nbl_dev, nbl_mr);
	if (err_code) {
		nbl_ib_err(&nbl_dev->rf->sc_dev, "hw alloc stag failed!\n");
		goto err_alloc_stag;
	}

	spin_lock_irqsave(&nbl_dev->rf->mrtable_lock, flags);
	nbl_dev->rf->mr_table[nbl_mr->stag >> 8] = nbl_mr;
	spin_unlock_irqrestore(&nbl_dev->rf->mrtable_lock, flags);

	nbl_pbl->pbl_allocated = true;
	atomic_inc(&nbl_dev->rf->used_mrs_a);
	nbl_ib_dbg(&nbl_dev->rf->sc_dev, "used_mrs=0x%x.\n",
		   atomic_read(&nbl_dev->rf->used_mrs_a));
	return &nbl_mr->ibmr;

err_alloc_stag:
	nbl_free_pble(nbl_dev->rf->pble_rsrc, palloc);
err_get_pble:
	nbl_free_stag(nbl_dev, stag);
err:
	kfree(nbl_mr);
	return ERR_PTR(err_code);
}

struct ib_mr *nbl_ib_get_dma_mr(struct ib_pd *pd, int access)
{
	struct nbl_device *nbl_dev = to_nbl_dev(pd->device);
	struct nbl_mr *dma_mr;
	struct nbl_pbl *pbl;
	u32 stag;
	int ret;

	nbl_ib_dbg(&nbl_dev->rf->sc_dev, "enter and execute ib get dma mr.\n");

	dma_mr = kzalloc(sizeof(*dma_mr), GFP_KERNEL);
	if (!dma_mr)
		return ERR_PTR(-ENOMEM);

	dma_mr->ibmr.pd = pd;
	dma_mr->ibmr.device = pd->device;
	pbl = &dma_mr->pbl;
	pbl->mr = dma_mr;
	pbl->usr_base = 0;

	ret = nbl_create_stag(nbl_dev, &stag);
	if (ret) {
		ret = -ENOMEM;
		goto err;
	}

	dma_mr->stag = stag;
	dma_mr->ibmr.iova = 0;
	dma_mr->ibmr.rkey = stag;
	dma_mr->ibmr.lkey = stag;
	dma_mr->page_cnt = 1;
	dma_mr->page_sz = SZ_4K;
	dma_mr->len = 0;

	ret = nbl_hwreg_mr(nbl_dev, dma_mr, access);
	if (ret) {
		nbl_free_stag(nbl_dev, stag);
		goto err;
	}

	atomic_inc(&nbl_dev->rf->used_mrs_a);
	nbl_ib_dbg(&nbl_dev->rf->sc_dev, "get dma mr succ,used_mrs=0x%x.\n",
		   atomic_read(&nbl_dev->rf->used_mrs_a));
	return &dma_mr->ibmr;

err:
	kfree(dma_mr);
	return ERR_PTR(ret);
}

static int nbl_set_page(struct ib_mr *ibmr, u64 addr)
{
	struct nbl_mr *mr = to_nbl_mr(ibmr);
	struct nbl_pbl *pbl = &mr->pbl;
	int ret;

	if (unlikely(mr->npages == mr->page_cnt)) {
		nbl_pr_err("sys PAGE_SIZE=0x%lx,mkey=%#x,mr page_cnt=%u",
			   PAGE_SIZE, mr->stag, mr->page_cnt);
		return -ENOMEM;
	}

	if (addr >> NBL_DMA_ADDR_CHK_SHIFT == 0) {
		nbl_pr_err("set page addr:%#llx is unusable!\n", addr);
		return -ENOMEM;
	}

	ret = nbl_fill_pble_value(&pbl->pble_alloc, mr->npages, addr);
	if (ret)
		return ret;

	mr->npages++;
	return 0;
}

static int nbl_ib_sg_to_pages(struct ib_mr *mr, struct scatterlist *sgl, int sg_nents,
		unsigned int *sg_offset_p, int (*set_page)(struct ib_mr *, u64), bool dbg)
{
	struct scatterlist *sg;
	u64 last_end_dma_addr = 0;
	unsigned int sg_offset = sg_offset_p ? *sg_offset_p : 0;
	unsigned int last_page_off = 0;
	u64 page_mask = ~((u64)mr->page_size - 1);
	int i, ret;

	if (unlikely(sg_nents <= 0 || sg_offset > sg_dma_len(&sgl[0])))
		return -EINVAL;

	mr->iova = sg_dma_address(&sgl[0]) + sg_offset;
	mr->length = 0;

	for_each_sg(sgl, sg, sg_nents, i) {
		u64 dma_addr = sg_dma_address(sg) + sg_offset;
		u64 prev_addr = dma_addr;
		unsigned int dma_len = sg_dma_len(sg) - sg_offset;
		u64 end_dma_addr = dma_addr + dma_len;
		u64 page_addr = dma_addr & page_mask;

		/*
		 * For the second and later elements, check whether either the
		 * end of element i-1 or the start of element i is not aligned
		 * on a page boundary.
		 */
		if (i && (last_page_off != 0 || page_addr != dma_addr)) {

			/* Stop mapping if there is a gap. */
			if (last_end_dma_addr != dma_addr)
				break;

			/*
			 * Coalesce this element with the last. If it is small
			 * enough just update mr->length. Otherwise start
			 * mapping from the next page.
			 */
			goto next_page;
		}

		do {
			ret = set_page(mr, page_addr);
			if (unlikely(ret < 0)) {
				sg_offset = prev_addr - sg_dma_address(sg);
				mr->length += prev_addr - dma_addr;
				if (sg_offset_p)
					*sg_offset_p = sg_offset;
				return i || sg_offset ? i : ret;
			}
			prev_addr = page_addr;
next_page:
			page_addr += mr->page_size;
			if (dbg)
				nbl_pr_err("page addr %llx, page size %u, end %llx\n",
					page_addr, mr->page_size, end_dma_addr);

			/* Here is kernel bug fix:
			 * if addr is 0xffff ffff fffe 0000 ~ 0xffff ffff ffff ffff
			 * end_dma_addr is 0, page_addr is for sure bigger than 0,
			 * so this do while will only do once work, this is a bug,
			 * add end_dma_addr 0 judgement, and if page_addr is not 0,
			 * we will continue set page(write pbl).
			 */
		} while (page_addr < end_dma_addr || ((end_dma_addr == 0) && (page_addr != 0)));

		mr->length += dma_len;
		last_end_dma_addr = end_dma_addr;
		last_page_off = end_dma_addr & ~page_mask;

		sg_offset = 0;
	}

	if (sg_offset_p)
		*sg_offset_p = 0;
	return i;
}

int nbl_ib_map_mr_sg(struct ib_mr *ibmr, struct scatterlist *sg, int sg_ents,
		     unsigned int *sg_offset)
{
	struct nbl_mr *mr = to_nbl_mr(ibmr);

	mr->npages = 0;
	if (ibmr->page_size == SZ_64K || ibmr->page_size == SZ_16K) {
		mr->page_sz = NBL_ADAPTER_PAGE_SIZE;
		ibmr->page_size = NBL_ADAPTER_PAGE_SIZE;
	} else {
		mr->page_sz = ibmr->page_size;
	}

	return nbl_ib_sg_to_pages(ibmr, sg, sg_ents, sg_offset, nbl_set_page, false);
}

void nbl_ib_mmap_free(struct rdma_user_mmap_entry *rdma_entry)
{
	struct nbl_user_mmap_entry *entry = container_of(
		rdma_entry, struct nbl_user_mmap_entry, rdma_entry);
	kfree(entry);
}

int nbl_ib_mmap(struct ib_ucontext *ctx, struct vm_area_struct *vma)
{
	struct rdma_user_mmap_entry *rdma_entry;
	struct nbl_user_mmap_entry *entry;
	struct nbl_ucontext *uctx = to_ucontext(ctx);
	struct nbl_sc_dev *sc_dev = &uctx->nbl_dev->rf->sc_dev;
	unsigned long len = (vma->vm_end - vma->vm_start);
	u64 pfn;
	int ret;
	dma_addr_t dma_addr;
	struct shadow_node *node;

	node = nbl_find_shadow_mmap(uctx, vma->vm_pgoff << PAGE_SHIFT, len);
	nbl_ib_dbg(sc_dev, "start=0x%lx,vma->vm_pgoff=0x%lx,len=0x%lx",
		   vma->vm_start, vma->vm_pgoff, len);
	if (node) {
		dma_addr = vma->vm_pgoff << PAGE_SHIFT;
		/*
		 * dma_mmap_coherent() requires vm_pgoff as 0
		 * restore vm_pgoff to initial value for mmap()
		 */
		vma->vm_pgoff = 0;
		return dma_mmap_coherent(sc_dev->hw->device, vma, node->va, dma_addr, len);
	}

	/* not found in the shadow hlist, then try rdma_user_mmap */
	rdma_entry = rdma_user_mmap_entry_get(&uctx->ibucontext, vma);
	if (!rdma_entry) {
		nbl_ib_err(sc_dev, "pgoff[0x%lx] no have valid entry",
			   vma->vm_pgoff);
		return -EINVAL;
	}

	entry = container_of(rdma_entry, struct nbl_user_mmap_entry,
			     rdma_entry);

	pfn = (entry->bar_offset +
	       pci_resource_start(uctx->nbl_dev->rf->pcidev, 0)) >>
	      PAGE_SHIFT;

	switch (entry->mmap_flag) {
	case NBL_MMAP_IO_NC:
		ret = rdma_user_mmap_io(ctx, vma, pfn, PAGE_SIZE,
					pgprot_noncached(vma->vm_page_prot),
					rdma_entry);
		break;
	case NBL_MMAP_IO_WC:
		ret = rdma_user_mmap_io(ctx, vma, pfn, PAGE_SIZE,
					pgprot_writecombine(vma->vm_page_prot),
					rdma_entry);
		break;
	default:
		ret = -EINVAL;
	}

	if (ret)
		nbl_ib_err(sc_dev, "bar_offset [0x%llx] mmap_flag[%d] err[%d]",
			   entry->bar_offset, entry->mmap_flag, ret);

	rdma_user_mmap_entry_put(rdma_entry);

	return 0;
}

int nbl_ib_alloc_mw(struct ib_mw *ibmw, struct ib_udata *udata)
{
	struct nbl_device *nbl_dev = to_nbl_dev(ibmw->device);
	struct nbl_mr *mw = container_of(ibmw, struct nbl_mr, ibmw);
	struct nbl_pd *pd = to_nbl_pd(mw->ibmw.pd);
	u32 stag;
	int ret;
	int err_code;
	__le64 *in;

	ret = nbl_create_stag(nbl_dev, &stag);
	if (ret)
		return -ENOMEM;

	mw->stag = stag;
	ibmw->rkey = stag;

	in = kzalloc(NBL_CMD_INPUT_SIZE, GFP_KERNEL);
	if (!in) {
		nbl_free_stag(nbl_dev, mw->stag);
		return -ENOMEM;
	}

	set_64bit_val(in, 0,
		      FIELD_PREP(NBL_CQPSQ_OPCODE, NBL_CQP_OP_ALLOC_STAG) |
			  FIELD_PREP(NBL_CQPSQ_MR_STAT, NBL_MR_STAT_FREE) |
			  FIELD_PREP(NBL_CQPSQ_MR_TYPE, NBL_MR_TYPE_MW1) |
			  FIELD_PREP(NBL_CQPSQ_MR_INV, 0) |
			  FIELD_PREP(NBL_CQPSQ_MR_ADDR_TYPE, NBL_ADDR_TYPE_VA_BASED) |
			  FIELD_PREP(NBL_CQPSQ_MR_PDN, pd->sc_pd.pd_id) |
			  FIELD_PREP(NBL_CQPSQ_MR_KEY, (stag & 0xFF)));

	set_64bit_val(in, 32, FIELD_PREP(NBL_CQPSQ_MR_IDX, (stag >> 8)));
	err_code = nbl_cmd_exec(nbl_dev->rf, in, NBL_CMD_INPUT_SIZE, NULL, 0);
	if (err_code)
		nbl_free_stag(nbl_dev, mw->stag);
	else
		atomic_inc(&nbl_dev->rf->used_mrs_a);
	kfree(in);
	return err_code;
}

int nbl_ib_dealloc_mw(struct ib_mw *ibmw)
{
	struct nbl_device *nbl_dev = to_nbl_dev(ibmw->device);
	struct nbl_mr *mw = container_of(ibmw, struct nbl_mr, ibmw);
	struct nbl_pd *pd = to_nbl_pd(mw->ibmw.pd);
	int err_code;
	__le64 *in;

	in = kzalloc(NBL_CMD_INPUT_SIZE, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	set_64bit_val(in, 0,
		      FIELD_PREP(NBL_CQPSQ_OPCODE, NBL_CQP_OP_DEALLOC_STAG) |
			  FIELD_PREP(NBL_CQPSQ_MR_PDN, pd->sc_pd.pd_id));
	set_64bit_val(in, 32, FIELD_PREP(NBL_CQPSQ_MR_IDX, (mw->stag >> 8)));
	err_code = nbl_cmd_exec(nbl_dev->rf, in, NBL_CMD_INPUT_SIZE, NULL, 0);
	if (err_code)
		nbl_ib_err(&nbl_dev->rf->sc_dev, "dealloc mw cmd err=%d", err_code);

	kfree(in);
	nbl_free_stag(nbl_dev, mw->stag);
	if (atomic_read(&nbl_dev->rf->used_mrs_a))
		atomic_dec(&nbl_dev->rf->used_mrs_a);
	return 0;
}

int nbl_dump_hmc_mrt(struct nbl_device *nbl_dev, u32 dump_mask)
{
	struct nbl_pci_f *rf = nbl_dev->rf;
	struct nbl_sc_dev *sc_dev = &rf->sc_dev;
	struct nbl_hmc_obj_sd_info *sd_info = rf->mrt_sd_info;
	struct nbl_hmc_obj_sd_addr *sd;
	struct nbl_func_file *func_file = &nbl_dev->func_dump_info->dump_func_file;
	u32 num_one_page; /* how many cqc in one page */
	u32 page_index; /* page index that cqc located */
	u32 mrt_ix_in_page; /* mrt index in a page */
	u32 mrt_key;
	char msg[NBL_DUMP_MRT_MSG_SIZE];

	if (!sd_info) {
		nbl_ib_err(sc_dev, "[mrt] dump hmc mrt sd not inited");
		return -EFAULT;
	}

	mrt_key = dump_mask;
	num_one_page = sd_info->page_sz / NBL_HMC_MRTE_SZ; /* 4K/32=128*/
	page_index = mrt_key / num_one_page;

	sd = &sd_info->sd_addr[page_index];
	mrt_ix_in_page = mrt_key % num_one_page;

	snprintf(msg, NBL_DUMP_MRT_MSG_SIZE,
		"[mrt] dump mkey(%u) mrte(sd va %p, 0x%llx, offset 0x%x)\n",
		mrt_key, sd->va, (u64)((uintptr_t)sd->va), (mrt_ix_in_page * NBL_HMC_MRTE_SZ));

	nbl_ib_err(sc_dev, "%s", msg);
	nbl_dump_hex(rf, (sd->va + (mrt_ix_in_page * NBL_HMC_MRTE_SZ)), NBL_HMC_MRTE_SZ);
	write_to_file_buffer(func_file, msg);
	nbl_dump_fields(func_file, (sd->va + (mrt_ix_in_page * NBL_HMC_MRTE_SZ)), NBL_DBG_DUMP_MRT);
	return 0;
}

struct ib_mr *nbl_ib_reg_user_mr_dmabuf(struct ib_pd *pd, u64 start,
		u64 len, u64 virt, int fd, int access, struct ib_udata *udata)
{
	struct nbl_device *nbl_dev = to_nbl_dev(pd->device);
	struct nbl_sc_dev *sc_dev = &nbl_dev->rf->sc_dev;
	struct ib_umem_dmabuf *umem_dmabuf;
	struct ib_umem *region;
	struct nbl_mr *mr;
	struct nbl_pbl *pbl;
	struct nbl_pble_alloc *palloc;
	bool use_pbles = false;
	int err = -EINVAL;
	u32 stag = 0;
	bool is_continue = false;
	u32 page_num = 0;
	unsigned long flags;

	umem_dmabuf = ib_umem_dmabuf_get_pinned(pd->device, start, len, fd, access);
	if (IS_ERR(umem_dmabuf)) {
		err = PTR_ERR(umem_dmabuf);
		ibdev_dbg(&nbl_dev->ibdev, "Failed to get dmabuf umem[%d]\n", err);
		return ERR_PTR(err);
	}

	region = &umem_dmabuf->umem;

	mr = kzalloc(sizeof(*mr), GFP_KERNEL);
	if (!mr) {
		err = -ENOMEM;
		goto free_umem;
	}

	err = nbl_create_stag(nbl_dev, &stag);
	if (err) {
		nbl_ib_err(&nbl_dev->rf->sc_dev, "create nbl stag failed.\n");
		goto free_mr;
	}
	nbl_ib_dbg(sc_dev, "created stag=0x%x", stag);
	mr->stag = stag;
	mr->ibmr.rkey = stag;
	mr->ibmr.lkey = stag;

	pbl = &mr->pbl;
	pbl->mr = mr;
	mr->region = region;
	mr->ibmr.pd = pd;
	mr->ibmr.device = pd->device;
	mr->ibmr.iova = virt;

	dma_resv_lock(umem_dmabuf->attach->dmabuf->resv, NULL);
	err = ib_umem_dmabuf_map_pages(umem_dmabuf);
	if (err) {
		dma_resv_unlock(umem_dmabuf->attach->dmabuf->resv);
		goto free_stag;
	}

	mr->page_sz =
		ib_umem_find_best_pgsz(region, PAGE_SIZE | SZ_2M | SZ_1G, virt);

	if (unlikely(!mr->page_sz)) {
		nbl_ib_err(&nbl_dev->rf->sc_dev, "find best pgsz failed.\n");
		err = -EOPNOTSUPP;
		goto dma_unmap;
	}

	mr->len = region->length;
	pbl->usr_base = virt;
	palloc = &pbl->pble_alloc;
	mr->page_cnt = ib_umem_num_dma_blocks(region, mr->page_sz);
	mr->access_flags = access;

	nbl_ib_dbg(sc_dev, "mr page_sz=0x%llx,page_cnt=0x%x", mr->page_sz, mr->page_cnt);
	nbl_get_umem_info(region, &page_num, &is_continue);
	mr->sys_page_offset = virt & (PAGE_SIZE - 1);
	if (!is_continue) {
		use_pbles = true;
		if (mr->page_sz == SZ_64K || mr->page_sz == SZ_16K) {
			mr->page_sz = NBL_ADAPTER_PAGE_SIZE;
			mr->page_cnt = (ALIGN(virt + mr->len, mr->page_sz) -
					ALIGN_DOWN(virt, mr->page_sz)) / mr->page_sz;
		}
		err = nbl_setup_pbles(nbl_dev->rf, mr, use_pbles);
		if (err) {
			nbl_ib_err(&nbl_dev->rf->sc_dev, "set nbl pbles failed.\n");
			goto dma_unmap;
		}
	} else {
		pbl->pbl_allocated = false;
		mr->pa = nbl_get_first_sg_dma_addr(region);
		if (mr->page_sz == SZ_64K || mr->page_sz == SZ_16K) {
			mr->page_sz = NBL_ADAPTER_PAGE_SIZE;
			mr->pa += (mr->sys_page_offset & ~(NBL_ADAPTER_PAGE_SIZE - 1));
		}
		nbl_ib_dbg(sc_dev, "mr->pa=0x%llx", mr->pa);
	}

	err = nbl_hwreg_mr(nbl_dev, mr, access);
	if (err) {
		nbl_ib_err(&nbl_dev->rf->sc_dev, "nbl hwreg mr failed.\n");
		goto free_pble;
	}
	dma_resv_unlock(umem_dmabuf->attach->dmabuf->resv);
	spin_lock_irqsave(&nbl_dev->rf->mrtable_lock, flags);
	nbl_dev->rf->mr_table[mr->stag >> 8] = mr;
	spin_unlock_irqrestore(&nbl_dev->rf->mrtable_lock, flags);

	atomic_inc(&nbl_dev->rf->used_mrs_a);
	return &mr->ibmr;

free_pble:
	if (pbl->pbl_allocated)
		nbl_free_pble(nbl_dev->rf->pble_rsrc, palloc);
dma_unmap:
	ib_umem_dmabuf_unmap_pages(umem_dmabuf);
	dma_resv_unlock(umem_dmabuf->attach->dmabuf->resv);
free_stag:
	nbl_free_stag(nbl_dev, stag);
free_mr:
	kfree(mr);
free_umem:
	ib_umem_release(&umem_dmabuf->umem);

	return ERR_PTR(err);
}
