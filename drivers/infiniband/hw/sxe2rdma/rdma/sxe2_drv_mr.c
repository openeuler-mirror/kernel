// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_mr.c
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/err.h>

#include <rdma/ib_verbs.h>
#include <rdma/ib_umem.h>
#include <linux/random.h>

#include "sxe2-abi.h"
#include "sxe2_drv_rdma_common.h"
#include "sxe2_drv_mq.h"
#include "sxe2_drv_main.h"
#include "sxe2_drv_mr.h"
#include "sxe2_drv_rdma_pble.h"
#include "sxe2_drv_rdma_log.h"
#include "sxe2_drv_mr_debugfs.h"

static void sxe2_print_reg_mr_wqe_info(struct sxe2_rdma_device *rdma_dev,
				       void *wqe_info)
{
	union sxe2_reg_mr_info *p_reg_mr_info;

	p_reg_mr_info = (union sxe2_reg_mr_info *)wqe_info;
	DRV_RDMA_LOG_DEBUG_BDF(
		"\nREG_MR:\n"
		"pbl_mode		   : %d\n"
		"access_right	   : %#x\n"
		"va_based_flag	   : %d\n"
		"access_mode	   : %d\n"
		"mr_type		   : %d\n"
		"mr_key		   : %d\n"
		"pd			   : %d\n"
		"is_len64		   : %d\n"
		"start_addr	   : %llx\n"
		"mr_idx		   : 0x%x\n"
		"op			   : %d\n"
		"wqe_valid		   : %d\n"
		"len			   : %llu\n"
		"pbl_index		   : %llx\n"
		"log_entity_size   : %d\n",
		p_reg_mr_info->field.pbl_mode,
		p_reg_mr_info->field.access_right,
		p_reg_mr_info->field.va_based_flag,
		p_reg_mr_info->field.access_mode, p_reg_mr_info->field.mr_type,
		p_reg_mr_info->field.mr_key, p_reg_mr_info->field.pd,
		p_reg_mr_info->field.is_len64, p_reg_mr_info->field.start_addr,
		p_reg_mr_info->field.mr_idx, p_reg_mr_info->field.op,
		p_reg_mr_info->field.wqe_valid, p_reg_mr_info->field.len,
		p_reg_mr_info->field.pbl_index,
		p_reg_mr_info->field.log_entity_size);

}

static void sxe2_print_ah_wqe_info(struct sxe2_rdma_device *rdma_dev,
				   void *wqe_info)
{
	union sxe2_ah_info *p_ah_info;
	u32 srcip[4];
	u32 dstip[4];

	p_ah_info = (union sxe2_ah_info *)wqe_info;
	DRV_RDMA_LOG_DEBUG_BDF(
		"\nCREATE/DESCTROY AH:\n"
		"dest_mac		   : %x:%x:%x:%x:%x:%x\n"
		"vlan_tag		   : %#x\n"
		"tc_tos		   : %d\n"
		"pd_idx		   : %d\n"
		"flow_label	   : %d\n"
		"hop_ttl		   : %d\n"
		"arp_index		   : %d\n"
		"ah_idx		   : %#x\n"
		"op			   : %d\n"
		"ipv4_valid	   : %d\n"
		"insert_vlan_tag   : %d\n"
		"do_lpbk		   : %d\n"
		"wqe_valid		   : %d\n",
		p_ah_info->field.dest_mac[5], p_ah_info->field.dest_mac[4],
		p_ah_info->field.dest_mac[3], p_ah_info->field.dest_mac[2],
		p_ah_info->field.dest_mac[1], p_ah_info->field.dest_mac[0],
		p_ah_info->field.vlan_tag, p_ah_info->field.tc_tos,
		p_ah_info->field.pd_idx, p_ah_info->field.flow_label,
		p_ah_info->field.hop_ttl, p_ah_info->field.arp_index,
		p_ah_info->field.ah_idx, p_ah_info->field.op,
		p_ah_info->field.ipv4_valid, p_ah_info->field.insert_vlan_tag,
		p_ah_info->field.do_lpbk, p_ah_info->field.wqe_valid);
	if (p_ah_info->field.ipv4_valid) {
		srcip[0] = htonl(p_ah_info->field.src_ip_addr[0]);
		dstip[0] = htonl(p_ah_info->field.dest_ip_addr[0]);
		DRV_RDMA_LOG_DEBUG_BDF("dest_ip_addr	  : %pI4\n"
				       "src_ip_addr	   : %pI4\n",
				       dstip, srcip);
	} else {
		sxe2_copy_ip_htonl(srcip, p_ah_info->field.src_ip_addr);
		sxe2_copy_ip_htonl(dstip, p_ah_info->field.dest_ip_addr);
		DRV_RDMA_LOG_DEBUG_BDF("dest_ip_addr	  : %pI6\n"
				       "src_ip_addr	   : %pI6\n",
				       dstip, srcip);
	}

}

void sxe2_print_wqe_info(struct sxe2_rdma_ctx_dev *dev, void *wqe_info,
			 u8 mq_cmd)
{
	struct sxe2_rdma_device *rdma_dev;
	union sxe2_dereg_mr_info *p_dereg_mr_info;
	union sxe2_alloc_key_info *p_alloc_key_info;
	union sxe2_dalloc_key_info *p_dalloc_key_info;
	union sxe2_query_mr_info *p_query_mr_info;

	rdma_dev = to_rdmadev(dev);

	switch (mq_cmd) {
	case MQ_OP_REG_MR:
		sxe2_print_reg_mr_wqe_info(rdma_dev, wqe_info);
		break;
	case MQ_OP_QUERY_MR:
		p_query_mr_info = (union sxe2_query_mr_info *)wqe_info;
		DRV_RDMA_LOG_DEV_DEBUG("\nQUERY_MR:\n"
				       "buf_addr          : %#llx\n"
				       "mr_index          : %u\n"
				       "op                : %d\n"
				       "wqe_valid         : %d\n",
				       p_query_mr_info->field.buf_addr,
				       p_query_mr_info->field.mr_index,
				       p_query_mr_info->field.op,
				       p_query_mr_info->field.wqe_valid);
		break;
	case MQ_OP_DEREGISTER_MR:
		p_dereg_mr_info = (union sxe2_dereg_mr_info *)wqe_info;
		DRV_RDMA_LOG_DEV_DEBUG("\nDEREG_MR:\n"
				       "pd                : %d\n"
				       "mr_idx            : %#x\n"
				       "op                : %d\n"
				       "wqe_valid         : %d\n",
				       p_dereg_mr_info->field.pd,
				       p_dereg_mr_info->field.mr_idx,
				       p_dereg_mr_info->field.op,
				       p_dereg_mr_info->field.wqe_valid);
		break;
	case MQ_OP_ALLOC_MR_KEY:
		p_alloc_key_info = (union sxe2_alloc_key_info *)wqe_info;
		DRV_RDMA_LOG_DEV_DEBUG("\nALLOC_MR/MW_KEY:\n"
				       "pbl_mode          : %d\n"
				       "mw_type           : %d\n"
				       "access_mode       : %d\n"
				       "mr_type           : %d\n"
				       "pd                : %d\n"
				       "mr_idx            : %#x\n"
				       "op                : %d\n"
				       "wqe_valid         : %d\n"
				       "len               : %llx\n"
				       "pbl_idx           : %llx\n"
				       "log_entity_size   : %d\n",
				       p_alloc_key_info->field.pbl_mode,
				       p_alloc_key_info->field.mw_type,
				       p_alloc_key_info->field.access_mode,
				       p_alloc_key_info->field.mr_type,
				       p_alloc_key_info->field.pd,
				       p_alloc_key_info->field.mr_idx,
				       p_alloc_key_info->field.op,
				       p_alloc_key_info->field.wqe_valid,
				       p_alloc_key_info->field.len,
				       p_alloc_key_info->field.pbl_idx,
				       p_alloc_key_info->field.log_entity_size);
		break;
	case MQ_OP_DEALLOC_MR_KEY:
		p_dalloc_key_info = (union sxe2_dalloc_key_info *)wqe_info;
		DRV_RDMA_LOG_DEV_DEBUG("\nREG_MR:\n"
				       "mr_type           : %d\n"
				       "pd                : %d\n"
				       "mr_idx            : %#x\n"
				       "op                : %d\n"
				       "wqe_valid         : %d\n",
				       p_dalloc_key_info->field.mr_type,
				       p_dalloc_key_info->field.pd,
				       p_dalloc_key_info->field.mr_idx,
				       p_dalloc_key_info->field.op,
				       p_dalloc_key_info->field.wqe_valid);
		break;
	case MQ_OP_CREATE_ADDR_HANDLE:
	case MQ_OP_MODIFY_ADDR_HANDLE:
	case MQ_OP_DESTROY_ADDR_HANDLE:
		sxe2_print_ah_wqe_info(rdma_dev, wqe_info);
		break;
	default:
		DRV_RDMA_LOG_DEV_ERR("MR: post unknown type mq wqe\n");
	}
}

void sxe2_set_mq_wqe(struct sxe2_rdma_ctx_dev *dev, __le64 *wqe, void *wqe_info)
{
	u32 offset;
	int i;
	struct sxe2_mq_wqe *mq_wqe;
	struct sxe2_rdma_device *rdma_dev;

	mq_wqe	 = (struct sxe2_mq_wqe *)wqe_info;
	rdma_dev = to_rdmadev(dev);

	offset = 0;
	for (i = 0; i < SXE2_MQ_WQE_SIZE; i++) {
		set_64bit_val(wqe, offset, mq_wqe->buf[i]);
		offset += sizeof(u64);
	}

	DRV_RDMA_LOG_DEV_DEBUG("\n");
	DRV_RDMA_LOG_DEV_DEBUG("---------------POST MQ INFO:---------------\n");
	for (i = 0; i < SXE2_MQ_WQE_SIZE; i++)
		DRV_RDMA_LOG_DEV_DEBUG("info[%d]-----%#llx\n", i,
				       mq_wqe->buf[i]);
}

int sxe2_hw_set_mq_wqe(struct sxe2_rdma_ctx_dev *dev,
		       struct mq_cmds_info *pcmdinfo)
{
	__le64 *wqe;
	void *wqe_info;
	u64 scratch;
	struct sxe2_mq_ctx *mq;
	struct sxe2_rdma_device *rdma_dev;

	mq	 = dev->mq;
	rdma_dev = to_rdmadev(dev);

	switch (pcmdinfo->mq_cmd) {
	case MQ_OP_REG_MR:
		scratch = pcmdinfo->in.u.reg_mr.scratch;
		pcmdinfo->in.u.reg_mr.info.field.wqe_valid = mq->polarity;
		wqe_info = (void *)&pcmdinfo->in.u.reg_mr.info;
		break;
	case MQ_OP_DEREGISTER_MR:
		scratch = pcmdinfo->in.u.dereg_mr.scratch;
		pcmdinfo->in.u.dereg_mr.info.field.wqe_valid = mq->polarity;
		wqe_info = (void *)&pcmdinfo->in.u.dereg_mr.info;
		break;
	case MQ_OP_QUERY_MR:
		scratch = pcmdinfo->in.u.query_mr.scratch;
		pcmdinfo->in.u.query_mr.info.field.op = SXE2_MQ_OP_QUERY_MR;
		pcmdinfo->in.u.query_mr.info.field.wqe_valid = mq->polarity;
		wqe_info = (void *)&pcmdinfo->in.u.query_mr.info;
		break;
	case MQ_OP_ALLOC_MR_KEY:
		scratch = pcmdinfo->in.u.alloc_key.scratch;
		pcmdinfo->in.u.alloc_key.info.field.wqe_valid = mq->polarity;
		wqe_info = (void *)&pcmdinfo->in.u.alloc_key.info;
		break;
	case MQ_OP_DEALLOC_MR_KEY:
		scratch = pcmdinfo->in.u.dalloc_key.scratch;
		pcmdinfo->in.u.dalloc_key.info.field.wqe_valid = mq->polarity;
		wqe_info = (void *)&pcmdinfo->in.u.dalloc_key.info;
		break;
	default:
		return -EOPNOTSUPP;
	}

	wqe = sxe2_kget_next_mq_wqe(mq, scratch);
	if (!wqe) {
		DRV_RDMA_LOG_DEV_ERR("MR:get next mq wqe failed.\n");
		return -ENOMEM;
	}

	sxe2_print_wqe_info(dev, wqe_info, pcmdinfo->mq_cmd);

	sxe2_set_mq_wqe(dev, wqe, wqe_info);

	if (pcmdinfo->post_mq)
		sxe2_kpost_mq(mq);

	return 0;
}

static void sxe2_mr_info_init(union sxe2_reg_mr_info *mr_info,
			      struct sxe2_mr *vendor_mr, int access)
{
	struct sxe2_pbl_pble_alloc_info *palloc = &vendor_mr->pble_alloc;
	struct ib_pd *pd			= vendor_mr->ibmr.pd;
	struct sxe2_rdma_pd *vendor_pd		= ibpd_to_vendor_pd(pd);

	mr_info->field.mr_idx	    = vendor_mr->stag >> SXE2_CQPSQ_STAG_IDX_S;
	mr_info->field.mr_key	    = (u8)vendor_mr->stag;
	mr_info->field.len	    = vendor_mr->len;
	mr_info->field.mr_type	    = vendor_mr->is_mw;
	mr_info->field.access_right = sxe2_get_mr_access(access);
	mr_info->field.pd	    = vendor_pd->pd_ctx.pd_id;
	if (access & IB_ZERO_BASED) {
		mr_info->field.va_based_flag = SXE2_ADDR_TYPE_ZERO_BASED;
		mr_info->field.start_addr =
			vendor_mr->ibmr.iova & (vendor_mr->page_size - 1);
	} else {
		mr_info->field.va_based_flag = SXE2_ADDR_TYPE_VA_BASED;
	}
	mr_info->field.log_entity_size = ilog2(vendor_mr->page_size);
	if (palloc->pbl_mode.mode == MR_ACCESS_MODE_PHY) {
		mr_info->field.access_mode = SXE2_MR_ACCESS_MODE_PA;
		mr_info->field.start_addr =
			vendor_mr->pgaddrmem +
			(vendor_mr->ibmr.iova & (vendor_mr->page_size - 1));
	} else {
		mr_info->field.access_mode = SXE2_MR_ACCESS_MODE_VA;
		if (mr_info->field.va_based_flag == SXE2_ADDR_TYPE_VA_BASED)
			mr_info->field.start_addr = vendor_mr->ibmr.iova;
		mr_info->field.pbl_index = palloc->pbl_index;
	}
	if (vendor_mr->is_len64)
		mr_info->field.is_len64 = 1;
	mr_info->field.pbl_mode = palloc->pbl_mode.mode;
	mr_info->field.op	= SXE2_MQ_OP_REG_MR;

}
static int sxe2_post_regmr_mqinfo(struct sxe2_rdma_device *rdma_dev,
				  struct sxe2_mr *vendor_mr, int access)
{
	union sxe2_reg_mr_info *mr_info;
	struct sxe2_mq_request *mq_request;
	struct mq_cmds_info *cmd_info;
	int ret;

	mq_request =
		sxe2_kalloc_and_get_mq_request(&rdma_dev->rdma_func->mq, true);
	if (!mq_request)
		return -ENOMEM;

	cmd_info = &mq_request->info;
	mr_info	 = &cmd_info->in.u.reg_mr.info;
	memset(mr_info, 0, sizeof(*mr_info));

	sxe2_mr_info_init(mr_info, vendor_mr, access);

#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
	INJECT_START(rdma_dev->rdma_func, "mq_rcs_wqe_mr_pageSize",
		     &rdma_dev->rdma_func->mq.err_cqe_val, mr_info, vendor_mr);
	INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_mr_pageSize");

	INJECT_START(rdma_dev->rdma_func, "mq_rcs_wqe_mr_type",
		     &rdma_dev->rdma_func->mq.err_cqe_val, mr_info, vendor_mr);
	INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_mr_type");

	INJECT_START(rdma_dev->rdma_func, "mq_rcs_wqe_mr_accessRight",
		     &rdma_dev->rdma_func->mq.err_cqe_val, mr_info);
	if (rdma_dev->rdma_func->mq.err_cqe_val.rsc_wqe_err_type ==
	    MR_ACCESS_RIGHT_DEBUGFS)
		DRV_RDMA_LOG_DEBUG_BDF(
			"MQ DEBUGFS:inject ori mr_access_right %#x\n",
			sxe2_get_mr_access(access));

	INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_mr_accessRight");

	INJECT_START(rdma_dev->rdma_func, "mq_rcs_wqe_mr_id_reg",
		     &rdma_dev->rdma_func->mq.err_cqe_val, mr_info);
	INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_mr_id_reg");

#endif

	cmd_info->mq_cmd	      = MQ_OP_REG_MR;
	cmd_info->post_mq	      = 1;
	cmd_info->in.u.reg_mr.ctx_dev = &rdma_dev->rdma_func->ctx_dev;
	cmd_info->in.u.reg_mr.scratch = (uintptr_t)mq_request;
	ret = sxe2_khandle_mq_cmd(rdma_dev->rdma_func, mq_request);
	sxe2_kput_mq_request(&rdma_dev->rdma_func->mq, mq_request);
	if (!ret)
		vendor_mr->is_hwreg = 1;

	return ret;
}

static int sxe2_post_deregmr_mqinfo(struct ib_mr *ib_mr)
{
	struct sxe2_rdma_device *rdma_dev = ibdev_to_rdmadev(ib_mr->device);
	struct sxe2_mr *vendor_mr	  = ibmr_to_vendor_mr(ib_mr);
	struct sxe2_rdma_pd *vendor_pd	  = ibpd_to_vendor_pd(ib_mr->pd);
	union sxe2_dereg_mr_info *mr_info;
	struct sxe2_mq_request *mq_request;
	struct mq_cmds_info *cmd_info;
	int ret;

	if (!vendor_mr->is_hwreg)
		return 0;

	mq_request =
		sxe2_kalloc_and_get_mq_request(&rdma_dev->rdma_func->mq, true);
	if (!mq_request)
		return -ENOMEM;

	cmd_info = &mq_request->info;
	mr_info	 = &cmd_info->in.u.dereg_mr.info;
	memset(mr_info, 0, sizeof(*mr_info));
	mr_info->field.pd     = vendor_pd->pd_ctx.pd_id;
	mr_info->field.mr_idx = vendor_mr->stag >> SXE2_CQPSQ_STAG_IDX_S;
	mr_info->field.op     = SXE2_MQ_OP_DEREGISTER_MR;

#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
	INJECT_START(rdma_dev->rdma_func, "mq_rcs_wqe_mr_id_dereg",
		     &rdma_dev->rdma_func->mq.err_cqe_val, mr_info);
	INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_mr_id_dereg");
#endif

	cmd_info->mq_cmd		= MQ_OP_DEREGISTER_MR;
	cmd_info->post_mq		= 1;
	cmd_info->in.u.dereg_mr.ctx_dev = &rdma_dev->rdma_func->ctx_dev;
	cmd_info->in.u.dereg_mr.scratch = (uintptr_t)mq_request;
	cmd_info->destroy		= true;
	ret = sxe2_khandle_mq_cmd(rdma_dev->rdma_func, mq_request);
	sxe2_kput_mq_request(&rdma_dev->rdma_func->mq, mq_request);

	if (!ret)
		vendor_mr->is_hwreg = 0;

	return ret;
}

static int sxe2_post_alloc_mr_mqinfo(struct sxe2_rdma_device *rdma_dev,
				     struct sxe2_mr *vendor_mr)
{
	union sxe2_alloc_key_info *info;
	struct sxe2_rdma_pd *iwpd = ibpd_to_vendor_pd(vendor_mr->ibmr.pd);
	struct sxe2_mq_request *mq_request;
	struct mq_cmds_info *cmd_info;
	int ret;

	mq_request =
		sxe2_kalloc_and_get_mq_request(&rdma_dev->rdma_func->mq, true);
	if (!mq_request)
		return -ENOMEM;

	cmd_info = &mq_request->info;
	info	 = &cmd_info->in.u.alloc_key.info;
	memset(info, 0, sizeof(*info));

	info->field.mr_idx	    = vendor_mr->stag >> SXE2_CQPSQ_STAG_IDX_S;
	info->field.pd		    = iwpd->pd_ctx.pd_id;
	info->field.mr_type	    = SXE2_MR_TYPE_MR;
	info->field.len		    = vendor_mr->len;
	info->field.log_entity_size = ilog2(vendor_mr->page_size);
	info->field.pbl_idx	    = vendor_mr->pble_alloc.pbl_index;
	info->field.pbl_mode	    = vendor_mr->pble_alloc.pbl_mode.mode;
	info->field.access_mode	    = SXE2_MR_ACCESS_MODE_VA;
	info->field.op		    = SXE2_MQ_OP_ALLOC_MR_key;

	cmd_info->mq_cmd		 = MQ_OP_ALLOC_MR_KEY;
	cmd_info->post_mq		 = 1;
	cmd_info->in.u.alloc_key.ctx_dev = &rdma_dev->rdma_func->ctx_dev;
	cmd_info->in.u.alloc_key.scratch = (uintptr_t)mq_request;
	ret = sxe2_khandle_mq_cmd(rdma_dev->rdma_func, mq_request);
	sxe2_kput_mq_request(&rdma_dev->rdma_func->mq, mq_request);

	return ret;
}

bool sxe2_check_mr_contiguous(struct sxe2_mr *vendor_mr)
{
	struct ib_umem *region = vendor_mr->region;
	struct ib_block_iter biter;
	bool first    = true;
	u64 last_addr = 0;
	u64 curr_addr = 0;

	rdma_umem_for_each_dma_block(region, &biter, vendor_mr->page_size) {
		if (first) {
			last_addr = rdma_block_iter_dma_address(&biter);
			first	  = false;
		} else {
			curr_addr = rdma_block_iter_dma_address(&biter);
			if (last_addr + vendor_mr->page_size != curr_addr)
				return false;
			last_addr = curr_addr;
		}
	}

	return true;
}

static void sxe2_get_mr_first_pgaddrs(struct sxe2_mr *vendor_mr, u64 *addr)
{
	struct ib_umem *region = vendor_mr->region;
	struct ib_block_iter biter;

	rdma_umem_for_each_dma_block(region, &biter, vendor_mr->page_size) {
		*addr = rdma_block_iter_dma_address(&biter);
		break;
	}
}

static int sxe2_set_pble_pgaddrs(struct sxe2_pbl_pble_rsrc *pble_rsrc,
				 struct sxe2_mr *vendor_mr)
{
	struct ib_umem *region			= vendor_mr->region;
	struct sxe2_pbl_pble_alloc_info *palloc = &vendor_mr->pble_alloc;
	struct ib_block_iter biter;
	u32 pbl_cnt = 0;
	u64 page_addr;
	u64 pble_liner_index;
	int ret		 = SXE2_OK;

	pble_liner_index = vendor_mr->pble_alloc.pble_info.liner_addr;
	rdma_umem_for_each_dma_block(region, &biter, vendor_mr->page_size) {
		page_addr = rdma_block_iter_dma_address(&biter);
		ret = sxe2_pbl_set_pble(pble_rsrc, pble_liner_index, page_addr,
					palloc->mr_first_page_flags);
		if (ret != SXE2_OK)
			break;
		if (++pbl_cnt == palloc->needed_pble_cnt)
			break;
		if (!palloc->mr_first_page_flags)
			pble_liner_index += sizeof(u64);
		else
			pble_liner_index += SXE2_FPTE_LINER_ADDR;
	}

	return ret;
}

static void sxe2_free_stag(struct sxe2_rdma_device *rdma_dev, u32 stag)
{
	u32 stag_idx;

	stag_idx = (stag & rdma_dev->rdma_func->mr_stagmask) >>
		   SXE2_CQPSQ_STAG_IDX_S;
	sxe2_kfree_rsrc(rdma_dev->rdma_func, rdma_dev->rdma_func->allocated_mrs,
			stag_idx);

	DRV_RDMA_LOG_DEV_DEBUG(
		"FREE_MR_STAG:stag 0x%x bit_index %u mask 0x%x\n", stag,
		stag_idx, rdma_dev->rdma_func->mr_stagmask);
}

u32 sxe2_create_stag(struct sxe2_rdma_device *rdma_dev)
{
	u32 stag;
	u32 stag_index = 0;
	u32 next_stag_index;
	u32 random;
	u8 consumer_key;
	int ret;

	get_random_bytes(&random, sizeof(random));
	consumer_key = (u8)random;

	next_stag_index = (random & rdma_dev->rdma_func->mr_stagmask) >> 8;
	next_stag_index %= rdma_dev->rdma_func->max_mr;

	ret = sxe2_kalloc_rsrc(rdma_dev->rdma_func,
			       rdma_dev->rdma_func->allocated_mrs,
			       rdma_dev->rdma_func->max_mr, &stag_index,
			       &next_stag_index);
	if (ret) {
		DRV_RDMA_LOG_DEV_DEBUG("MR: kalloc stag_index failed\n");
		return 0;
	}

	stag = stag_index << SXE2_CQPSQ_STAG_IDX_S;
	stag |= (u32)consumer_key;

	DRV_RDMA_LOG_DEV_DEBUG(
		"CREATE_MR_STAG:stag 0x%x bit_index %u mr_key %d mask 0x%x\n",
		stag, stag_index, consumer_key,
		rdma_dev->rdma_func->mr_stagmask);

	return stag;
}

#ifdef HAVE_NO_IB_UMEM_FIND_BEST_PGSZ
static struct sxe2_mr *sxe2_alloc_mr(struct ib_umem *region, struct ib_pd *pd,
				     u64 virt, u64 start)
#else
static struct sxe2_mr *sxe2_alloc_mr(struct ib_umem *region, struct ib_pd *pd,
				     u64 virt)
#endif
{
	struct sxe2_rdma_device *rdma_dev = ibdev_to_rdmadev(pd->device);
	struct sxe2_mr *vendor_mr	  = NULL;
	unsigned long pgsz_bitmap;

	vendor_mr = kzalloc(sizeof(*vendor_mr), GFP_KERNEL);
	if (!vendor_mr) {
		DRV_RDMA_LOG_DEV_ERR("MR: kzalloc mr mem failed\n");
		return ERR_PTR(-ENOMEM);
	}

	vendor_mr->region      = region;
	vendor_mr->ibmr.pd     = pd;
	vendor_mr->ibmr.device = pd->device;
	vendor_mr->ibmr.iova   = virt;

	pgsz_bitmap = rdma_dev->rdma_func->ctx_dev.hw_attrs.page_size_cap;

#ifdef HAVE_NO_IB_UMEM_FIND_BEST_PGSZ
	vendor_mr->page_size =
		sxe2_set_best_pagesz(start, region, pgsz_bitmap);
#else
	vendor_mr->page_size =
		ib_umem_find_best_pgsz(region, pgsz_bitmap, virt);
#endif
	if (unlikely(!vendor_mr->page_size)) {
		DRV_RDMA_LOG_DEV_ERR("MR:0 page size error\n");
		kfree(vendor_mr);
		return ERR_PTR(-EOPNOTSUPP);
	}

	vendor_mr->page_msk = ~(vendor_mr->page_size - 1);

	vendor_mr->len	 = region->length;
	vendor_mr->is_mw = SXE2_MR_TYPE_MR;
#ifdef HAVE_IB_UMEM_NUM_DMA_BLOCKS_NOT_SUPPORT
	vendor_mr->page_cnt =
		sxe2_ib_umem_num_dma_blocks(region, vendor_mr->page_size, virt);
#else
	vendor_mr->page_cnt =
		(u32)ib_umem_num_dma_blocks(region, vendor_mr->page_size);
#endif
	return vendor_mr;
}

static int sxe2_register_mr(struct sxe2_mr *vendor_mr, int access,
			    bool create_stag)
{
	struct sxe2_rdma_device *rdma_dev =
		ibdev_to_rdmadev(vendor_mr->ibmr.device);
	struct sxe2_pbl_pble_alloc_info *pbl_alloc = &vendor_mr->pble_alloc;
	struct sxe2_rdma_pci_f *rdma_func	   = rdma_dev->rdma_func;
	u32 stag				   = 0;
	int ret;

	if (vendor_mr->page_cnt == 1) {
		sxe2_get_mr_first_pgaddrs(vendor_mr, &vendor_mr->pgaddrmem);
		pbl_alloc->pbl_mode.mode = MR_ACCESS_MODE_PHY;
	} else {
		if ((rdma_func->app_mod_all_flush) &&
		    (vendor_mr->page_size >= SXE2_HW_PAGE_SIZE_1G)) {
			pbl_alloc->mr_first_page_flags = true;
		}
		ret = sxe2_pbl_get_pble(rdma_dev->rdma_func->pble_rsrc,
					pbl_alloc, vendor_mr->page_cnt,
					PBL_OBJ_MR);
		if (ret) {
			DRV_RDMA_LOG_DEV_DEBUG(
				"MR:sxe2_pbl_get_pble error, err(%d)\n", ret);
			return ret;
		}
		vendor_mr->alloced_pble = SXE2_MR_ALLOCED_PBLE;
		ret = sxe2_set_pble_pgaddrs(rdma_dev->rdma_func->pble_rsrc,
					    vendor_mr);
		if (ret) {
			DRV_RDMA_LOG_DEV_DEBUG(
				"MR:sxe2_set_pble_pgaddrs error, err(%d)\n",
				ret);
			goto err_case;
		}
	}

	if (create_stag) {
		stag = sxe2_create_stag(rdma_dev);
		if (!stag) {
			ret = -ENOMEM;
			goto err_case;
		}
		vendor_mr->alloced_key = SXE2_MR_ALLOCED_KEY;
		vendor_mr->stag	       = stag;
		vendor_mr->ibmr.rkey   = stag;
		vendor_mr->ibmr.lkey   = stag;
	}

	vendor_mr->access = access;

	ret = sxe2_post_regmr_mqinfo(rdma_dev, vendor_mr, access);
	if (ret)
		goto err_case;

	return 0;

err_case:
	if (vendor_mr->alloced_key == SXE2_MR_ALLOCED_KEY) {
		sxe2_free_stag(rdma_dev, vendor_mr->stag);
		vendor_mr->alloced_key = SXE2_MR_NOTALLOCED_KEY;
	}

	if (vendor_mr->alloced_pble == SXE2_MR_ALLOCED_PBLE) {
		sxe2_pbl_free_pble(rdma_dev->rdma_func->pble_rsrc,
				   vendor_mr->pble_alloc.pbl_index,
				   vendor_mr->page_cnt,
				   vendor_mr->pble_alloc.mr_first_page_flags);
		vendor_mr->alloced_pble = SXE2_MR_NOTALLOCED_PBLE;
	}

	return ret;
}

static struct ib_mr *sxe2_rereg_mr_trans(struct sxe2_mr *vendor_mr, u64 start,
					 u64 len, u64 virt,
					 struct ib_udata *udata)
{
	struct sxe2_rdma_device *rdma_dev =
		ibdev_to_rdmadev(vendor_mr->ibmr.device);
	struct ib_pd *pd = vendor_mr->ibmr.pd;
	struct ib_umem *region;
	int ret;
#ifdef IB_UMEM_GET_V3

#endif

#ifdef IB_UMEM_GET_V2
	region = ib_umem_get(udata, start, len, vendor_mr->access);
#elif defined(IB_UMEM_GET_V1)
	region = ib_umem_get(udata, start, len, vendor_mr->access, 0);
#elif defined IB_UMEM_GET_V3

	region = ib_umem_get(pd->uobject->context, start, len, vendor_mr->access, 0);
#else
	region = ib_umem_get(pd->device, start, len, vendor_mr->access);
#endif
	if (IS_ERR(region)) {
		DRV_RDMA_LOG_DEV_DEBUG("mr umem ib_umem_get failed\n");
		return (struct ib_mr *)region;
	}

	vendor_mr->region    = region;
	vendor_mr->ibmr.iova = virt;
	vendor_mr->ibmr.pd   = pd;
	vendor_mr->page_size = PAGE_SIZE;

#ifdef HAVE_NO_IB_UMEM_FIND_BEST_PGSZ
	vendor_mr->page_size =
			sxe2_set_best_pagesz(start, region,
				rdma_dev->rdma_func->ctx_dev.hw_attrs.page_size_cap);
#else
	vendor_mr->page_size = ib_umem_find_best_pgsz(
		region, rdma_dev->rdma_func->ctx_dev.hw_attrs.page_size_cap,
		virt);
#endif
	if (unlikely(!vendor_mr->page_size)) {
		ret = -EOPNOTSUPP;
		goto ret;
	}

	vendor_mr->len = region->length;
#ifdef HAVE_IB_UMEM_NUM_DMA_BLOCKS_NOT_SUPPORT
	vendor_mr->page_cnt =
		sxe2_ib_umem_num_dma_blocks(region, vendor_mr->page_size, virt);
#else
	vendor_mr->page_cnt =
		(u32)ib_umem_num_dma_blocks(region, vendor_mr->page_size);
#endif
	ret = sxe2_register_mr(vendor_mr, vendor_mr->access, false);
	if (ret)
		goto ret;

	return &vendor_mr->ibmr;

ret:
	ib_umem_release(region);
	return ERR_PTR(ret);
}

static int sxe2_set_page(struct ib_mr *ibmr, u64 addr)
{
	struct sxe2_mr *vendor_mr = ibmr_to_vendor_mr(ibmr);
	struct sxe2_rdma_device *rdma_dev =
		ibdev_to_rdmadev(vendor_mr->ibmr.device);
	struct sxe2_pbl_pble_alloc_info *palloc = &vendor_mr->pble_alloc;
	u64 pble_liner_index;

	if (unlikely(vendor_mr->npages == vendor_mr->page_cnt)) {
		DRV_RDMA_LOG_DEV_ERR(
			"MR: map mr (%d)page exceed mr max pagecnt %d.\n",
			vendor_mr->npages, vendor_mr->page_cnt);
		return -ENOMEM;
	}

	pble_liner_index = palloc->pbl_index;

	pble_liner_index += sizeof(u64) * vendor_mr->npages;
	sxe2_pbl_set_pble(rdma_dev->rdma_func->pble_rsrc, pble_liner_index,
			  addr, false);

	vendor_mr->npages++;
	return 0;
}

static struct ib_mr *sxe2_reg_phys_mr(struct ib_pd *pd, u64 addr, u64 size,
				      int access, u64 *iova_start)
{
	struct sxe2_rdma_device *rdma_dev = ibdev_to_rdmadev(pd->device);
	struct sxe2_pbl_pble_alloc_info *palloc;
	struct sxe2_mr *vendor_mr;
	u32 stag;
	int ret;

	DRV_RDMA_LOG_DEV_DEBUG("mr:kreg phys mr enter.\n");

	vendor_mr = kzalloc(sizeof(*vendor_mr), GFP_KERNEL);
	if (!vendor_mr) {
		DRV_RDMA_LOG_DEV_ERR("MR: kzalloc mr buf failed.\n");
		return ERR_PTR(-ENOMEM);
	}

	palloc = &vendor_mr->pble_alloc;

	vendor_mr->ibmr.pd     = pd;
	vendor_mr->ibmr.device = pd->device;

	stag = sxe2_create_stag(rdma_dev);
	if (!stag) {
		DRV_RDMA_LOG_DEV_ERR("MR: alloc mr idx failed.\n");
		ret = -ENOMEM;
		goto err;
	}

	vendor_mr->stag		= stag;
	vendor_mr->ibmr.iova	= *iova_start;
	vendor_mr->ibmr.rkey	= stag;
	vendor_mr->ibmr.lkey	= stag;
	vendor_mr->is_mw	= SXE2_MR_TYPE_MR;
	vendor_mr->alloced_pble = SXE2_MR_NOTALLOCED_PBLE;
	vendor_mr->alloced_key	= SXE2_MR_ALLOCED_KEY;
	vendor_mr->page_cnt	= 1;
	vendor_mr->pgaddrmem	= addr;
	vendor_mr->access	= access;
	vendor_mr->len		= size;
	vendor_mr->is_len64	= 1;
	vendor_mr->page_size	= PAGE_SIZE;
	vendor_mr->page_msk	= ~(PAGE_SIZE - 1);
	palloc->pbl_mode.mode	= MR_ACCESS_MODE_PHY;
	ret = sxe2_post_regmr_mqinfo(rdma_dev, vendor_mr, access);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR("MR: post regmr failed, ret %d.\n", ret);
		sxe2_free_stag(rdma_dev, stag);
		vendor_mr->alloced_key = SXE2_MR_NOTALLOCED_KEY;
		goto err;
	}

	vendor_mr->is_hwreg = 1;

	(void)sxe2_debbugfs_mr_add(rdma_dev, vendor_mr);

	return &vendor_mr->ibmr;

err:
	kfree(vendor_mr);

	return ERR_PTR(ret);
}

struct ib_mr *sxe2_kreg_user_mr(struct ib_pd *pd, u64 start, u64 len, u64 virt,
				int access, struct ib_udata *udata)
{
	struct sxe2_rdma_device *rdma_dev = ibdev_to_rdmadev(pd->device);
	struct ib_umem *region;
	struct sxe2_mr *vendor_mr;
	int ret;
#ifdef IB_UMEM_GET_V3

#endif

	SXE2_UNUSED_PARA(udata);

	DRV_RDMA_LOG_DEV_DEBUG(
		"mr:kreg user mr enter. start:%#llx, length:%#llx, virt:%#llx,acc:%#x\n",
		start, len, virt, access);

	if (len > rdma_dev->rdma_func->ctx_dev.hw_attrs.max_mr_size) {
		DRV_RDMA_LOG_DEV_ERR(
			"MR: mr len (%#llx) exceed max size 0x%llx.\n", len,
			rdma_dev->rdma_func->ctx_dev.hw_attrs.max_mr_size);
		return ERR_PTR(-EINVAL);
	}
#ifdef IB_UMEM_GET_V2
	region = ib_umem_get(udata, start, len, access);
#elif defined(IB_UMEM_GET_V1)
	region = ib_umem_get(udata, start, len, access, 0);
#elif defined IB_UMEM_GET_V3

	region = ib_umem_get(pd->uobject->context, start, len, access, 0);
#else
	region = ib_umem_get(pd->device, start, len, access);
#endif
	if (IS_ERR(region)) {
		DRV_RDMA_LOG_DEV_ERR("MR: ib umem get failed.\n");
		return (struct ib_mr *)region;
	}

#ifdef HAVE_NO_IB_UMEM_FIND_BEST_PGSZ
	vendor_mr = sxe2_alloc_mr(region, pd, virt, start);
#else
	vendor_mr = sxe2_alloc_mr(region, pd, virt);
#endif
	if (IS_ERR(vendor_mr)) {
		ib_umem_release(region);
		DRV_RDMA_LOG_DEV_ERR("MR: alloc mr mem failed.\n");
		return (struct ib_mr *)vendor_mr;
	}

	ret = sxe2_register_mr(vendor_mr, access, true);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR("MR: register mr failed, ret %d.\n", ret);
		goto error;
	}

	(void)sxe2_debbugfs_mr_add(rdma_dev, vendor_mr);

	return &vendor_mr->ibmr;

error:
	ib_umem_release(region);
	kfree(vendor_mr);

	return ERR_PTR(ret);
}

#ifdef DEREG_ME_V1
int sxe2_kdereg_mr(struct ib_mr *ib_mr)
#else
int sxe2_kdereg_mr(struct ib_mr *ib_mr, struct ib_udata *udata)
#endif
{
	struct sxe2_mr *vendor_mr	  = ibmr_to_vendor_mr(ib_mr);
	struct sxe2_rdma_device *rdma_dev = ibdev_to_rdmadev(ib_mr->device);
	struct sxe2_pbl_pble_alloc_info *pbl_alloc = &vendor_mr->pble_alloc;
	int ret;

	ret = sxe2_post_deregmr_mqinfo(ib_mr);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR("MR: post deregister mr failed, ret %d.\n",
				     ret);
		return ret;
	}

	if (vendor_mr->alloced_key == SXE2_MR_ALLOCED_KEY) {
		sxe2_free_stag(rdma_dev, vendor_mr->stag);
		vendor_mr->alloced_key = SXE2_MR_NOTALLOCED_KEY;
	}

	if (vendor_mr->alloced_pble == SXE2_MR_ALLOCED_PBLE) {
		sxe2_pbl_free_pble(rdma_dev->rdma_func->pble_rsrc,
				   pbl_alloc->pbl_index, vendor_mr->page_cnt,
				   pbl_alloc->mr_first_page_flags);
		vendor_mr->alloced_key = SXE2_MR_NOTALLOCED_PBLE;
	}

	if (vendor_mr->region)
		ib_umem_release(vendor_mr->region);

	sxe2_debugfs_mr_remove(rdma_dev, vendor_mr);

	kfree(vendor_mr);

	return 0;
}

#ifdef REREG_MR_VER_1
int sxe2_krereg_user_mr(struct ib_mr *ib_mr, int flags, u64 start, u64 len,
			u64 virt, int new_access, struct ib_pd *new_pd,
			struct ib_udata *udata)
{
	struct sxe2_rdma_device *rdma_dev = ibdev_to_rdmadev(ib_mr->device);
	struct sxe2_mr *vendor_mr	  = ibmr_to_vendor_mr(ib_mr);
	struct sxe2_pbl_pble_alloc_info *pbl_alloc = &vendor_mr->pble_alloc;
	int ret;

	DRV_RDMA_LOG_DEBUG_BDF("MR: rereg mr enter chgflag 0x%x addr %llu\n"
			       "\tlen %#llx acc 0x%x.\n",
			       flags, start, len, new_access);

	if (len > rdma_dev->rdma_func->ctx_dev.hw_attrs.max_mr_size) {
		DRV_RDMA_LOG_ERROR_BDF(
			"MR: mr len (0x%llx) exceed max size 0x%x.\n", len,
			rdma_dev->rdma_func->ctx_dev.hw_attrs.max_mr_size);
		return -EINVAL;
	}

	if (flags &
	    ~(IB_MR_REREG_TRANS | IB_MR_REREG_PD | IB_MR_REREG_ACCESS)) {
		DRV_RDMA_LOG_ERROR_BDF("MR: has not support flags 0x%x.\n",
				       flags & ~(IB_MR_REREG_TRANS |
						 IB_MR_REREG_PD |
						 IB_MR_REREG_ACCESS));
		return -EOPNOTSUPP;
	}

	ret = sxe2_post_deregmr_mqinfo(ib_mr);
	if (ret) {
		DRV_RDMA_LOG_ERROR_BDF(
			"MR: post deregister mr failed, ret %d.\n", ret);
		return ret;
	}

	if (flags & IB_MR_REREG_ACCESS)
		vendor_mr->access = new_access;

	if (flags & IB_MR_REREG_PD) {
		vendor_mr->ibmr.pd     = new_pd;
		vendor_mr->ibmr.device = new_pd->device;
	}

	if (flags & IB_MR_REREG_TRANS) {
		if (vendor_mr->alloced_pble == SXE2_MR_ALLOCED_PBLE) {
			sxe2_pbl_free_pble(rdma_dev->rdma_func->pble_rsrc,
					   pbl_alloc->pbl_index,
					   vendor_mr->page_cnt,
					   pbl_alloc->mr_first_page_flags);
			vendor_mr->alloced_pble = SXE2_MR_NOTALLOCED_PBLE;
		}

		if (vendor_mr->region) {
			ib_umem_release(vendor_mr->region);
			vendor_mr->region = NULL;
		}

		ib_mr = sxe2_rereg_mr_trans(vendor_mr, start, len, virt, udata);
		if (IS_ERR(ib_mr)) {
			DRV_RDMA_LOG_ERROR_BDF("MR: post rereg mr failed.\n");
			return PTR_ERR(ib_mr);
		}
	} else {
		ret = sxe2_post_regmr_mqinfo(rdma_dev, vendor_mr,
					     vendor_mr->access);
		if (ret) {
			DRV_RDMA_LOG_ERROR_BDF(
				"MR: post reg mr failed, ret %d.\n", ret);
			return ret;
		}
	}

	return 0;
}
#else
struct ib_mr *sxe2_krereg_user_mr(struct ib_mr *ib_mr, int flags, u64 start,
				  u64 len, u64 virt, int new_access,
				  struct ib_pd *new_pd, struct ib_udata *udata)
{
	struct sxe2_rdma_device *rdma_dev = ibdev_to_rdmadev(ib_mr->device);
	struct sxe2_mr *vendor_mr = ibmr_to_vendor_mr(ib_mr);
	struct sxe2_pbl_pble_alloc_info *pbl_alloc = &vendor_mr->pble_alloc;
	int ret;

	DRV_RDMA_LOG_DEV_DEBUG("MR: rereg mr enter chgflag 0x%x addr %llu\n"
			       "\tlen %#llx acc 0x%x.\n",
			       flags, start, len, new_access);

	if (len > rdma_dev->rdma_func->ctx_dev.hw_attrs.max_mr_size) {
		DRV_RDMA_LOG_DEV_ERR(
			"MR: mr len (0x%llx) exceed max size 0x%llx.\n", len,
			rdma_dev->rdma_func->ctx_dev.hw_attrs.max_mr_size);
		return ERR_PTR(-EINVAL);
	}

	if (flags &
	    ~(IB_MR_REREG_TRANS | IB_MR_REREG_PD | IB_MR_REREG_ACCESS)) {
		DRV_RDMA_LOG_DEV_ERR("MR: has not support flags 0x%x.\n",
				     (flags &
				      ~(IB_MR_REREG_TRANS | IB_MR_REREG_PD |
					IB_MR_REREG_ACCESS)));
		return ERR_PTR(-EOPNOTSUPP);
	}

	ret = sxe2_post_deregmr_mqinfo(ib_mr);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR("MR: post deregister mr failed, ret %d.\n",
				     ret);
		return ERR_PTR(ret);
	}

	if (flags & IB_MR_REREG_ACCESS)
		vendor_mr->access = new_access;

	if (flags & IB_MR_REREG_PD) {
		vendor_mr->ibmr.pd = new_pd;
		vendor_mr->ibmr.device = new_pd->device;
	}

	if (flags & IB_MR_REREG_TRANS) {
		if (vendor_mr->alloced_pble == SXE2_MR_ALLOCED_PBLE) {
			sxe2_pbl_free_pble(rdma_dev->rdma_func->pble_rsrc,
					   pbl_alloc->pbl_index,
					   vendor_mr->page_cnt,
					   pbl_alloc->mr_first_page_flags);
			vendor_mr->alloced_pble = SXE2_MR_NOTALLOCED_PBLE;
		}

		if (vendor_mr->region) {
			ib_umem_release(vendor_mr->region);
			vendor_mr->region = NULL;
		}

		ib_mr = sxe2_rereg_mr_trans(vendor_mr, start, len, virt, udata);
		if (IS_ERR(ib_mr)) {
			DRV_RDMA_LOG_DEV_ERR("MR: post rereg mr failed.\n");
			return ib_mr;
		}
	} else {
		ret = sxe2_post_regmr_mqinfo(rdma_dev, vendor_mr,
					     vendor_mr->access);
		if (ret) {
			DRV_RDMA_LOG_DEV_ERR(
				"MR: post reg mr failed, ret %d.\n", ret);
			return ERR_PTR(ret);
		}
	}

	return NULL;
}
#endif

#ifndef REG_USER_MR_DMABUF_VER_1
struct ib_mr *sxe2_kreg_user_mr_dmabuf(struct ib_pd *pd, u64 start, u64 len,
				       u64 virt, int fd, int access,
				       struct ib_udata *udata)
{
	struct sxe2_rdma_device *rdma_dev = ibdev_to_rdmadev(pd->device);
	struct ib_umem_dmabuf *umem_dmabuf;
	struct sxe2_mr *vedor_mr;
	long ret;

	DRV_RDMA_LOG_DEV_DEBUG("mr:kreg user mr dmabuf enter.\n");

	if (len > rdma_dev->rdma_func->ctx_dev.hw_attrs.max_mr_size) {
		DRV_RDMA_LOG_DEV_ERR(
			"MR: mr len (%#llx) exceed max size %#llx.\n", len,
			rdma_dev->rdma_func->ctx_dev.hw_attrs.max_mr_size);
		return ERR_PTR(-EINVAL);
	}

	umem_dmabuf =
		ib_umem_dmabuf_get_pinned(pd->device, start, len, fd, access);
	if (IS_ERR(umem_dmabuf)) {
		ret = PTR_ERR(umem_dmabuf);
		DRV_RDMA_LOG_DEV_ERR("MR: ib umem dmabuf pin failed [%ld].\n",
				     ret);
		return ERR_PTR(ret);
	}
#ifdef HAVE_NO_IB_UMEM_FIND_BEST_PGSZ
	vedor_mr = sxe2_alloc_mr(&umem_dmabuf->umem, pd, virt, start);
#else
	vedor_mr = sxe2_alloc_mr(&umem_dmabuf->umem, pd, virt);
#endif
	if (IS_ERR(vedor_mr)) {
		ret = PTR_ERR(vedor_mr);
		DRV_RDMA_LOG_DEV_ERR("MR: alloc mr mem failed [%ld].\n", ret);
		goto error_release;
	}

	ret = sxe2_register_mr(vedor_mr, access, true);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR("MR: register mr failed, ret %ld.\n", ret);
		goto err_iwmr;
	}

	return &vedor_mr->ibmr;

err_iwmr:
	kfree(vedor_mr);

error_release:
	ib_umem_release(&umem_dmabuf->umem);

	return ERR_PTR(ret);
}
#endif

#ifdef RDMA_ALLOC_MR_VER_1
struct ib_mr *sxe2_kalloc_mr(struct ib_pd *pd, enum ib_mr_type mr_type,
			     u32 max_num_sg, struct ib_udata *udata)
#else
struct ib_mr *sxe2_kalloc_mr(struct ib_pd *pd, enum ib_mr_type mr_type,
			     u32 max_num_sg)
#endif

{
	struct sxe2_rdma_device *rdma_dev = ibdev_to_rdmadev(pd->device);
	struct sxe2_pbl_pble_alloc_info *palloc;
	struct sxe2_mr *vendor_mr;
	int ret;
	u32 stag;
	int err_code = -ENOMEM;

	vendor_mr = kzalloc(sizeof(*vendor_mr), GFP_KERNEL);
	if (!vendor_mr) {
		DRV_RDMA_LOG_DEV_ERR("MR: kzalloc mr buf failed.\n");
		return ERR_PTR(-ENOMEM);
	}

	stag = sxe2_create_stag(rdma_dev);
	if (!stag) {
		DRV_RDMA_LOG_DEV_ERR("MR: mr idx alloc failed.\n");
		err_code = -ENOMEM;
		goto error;
	}
	vendor_mr->alloced_key = SXE2_MR_ALLOCED_KEY;
	vendor_mr->is_mw       = SXE2_MR_TYPE_MR;
	vendor_mr->stag	       = stag;
	vendor_mr->ibmr.rkey   = stag;
	vendor_mr->ibmr.lkey   = stag;
	vendor_mr->ibmr.pd     = pd;
	vendor_mr->ibmr.device = pd->device;

	palloc		     = &vendor_mr->pble_alloc;
	vendor_mr->page_cnt  = max_num_sg;
	vendor_mr->page_size = PAGE_SIZE;
	vendor_mr->len = max_num_sg * PAGE_SIZE;

	ret = sxe2_pbl_get_pble(rdma_dev->rdma_func->pble_rsrc, palloc,
				vendor_mr->page_cnt, PBL_OBJ_MR);
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR("MR: get pble failed, ret %d\n", ret);
		err_code = -ENOMEM;
		goto error;
	}
	vendor_mr->alloced_pble = SXE2_MR_ALLOCED_PBLE;

	err_code = sxe2_post_alloc_mr_mqinfo(rdma_dev, vendor_mr);
	if (err_code) {
		DRV_RDMA_LOG_DEV_ERR("MR: post alloc mr failed, ret %d\n",
				     err_code);
		goto error;
	}

	(void)sxe2_debbugfs_mr_add(rdma_dev, vendor_mr);
	vendor_mr->is_hwreg = 1;

	return &vendor_mr->ibmr;
error:
	if (vendor_mr->alloced_key == SXE2_MR_ALLOCED_KEY) {
		sxe2_free_stag(rdma_dev, vendor_mr->stag);
		vendor_mr->alloced_key = SXE2_MR_NOTALLOCED_KEY;
	}

	if (vendor_mr->alloced_pble == SXE2_MR_ALLOCED_PBLE) {
		sxe2_pbl_free_pble(rdma_dev->rdma_func->pble_rsrc,
				   vendor_mr->pble_alloc.pbl_index,
				   vendor_mr->page_cnt,
				   vendor_mr->pble_alloc.mr_first_page_flags);
		vendor_mr->alloced_pble = SXE2_MR_NOTALLOCED_PBLE;
	}

	kfree(vendor_mr);

	return ERR_PTR(err_code);
}

int sxe2_kmap_mr_sg(struct ib_mr *ibmr, struct scatterlist *sg, int sg_nents,
		    unsigned int *sg_offset)
{
	struct sxe2_mr *vendor_mr = ibmr_to_vendor_mr(ibmr);

	vendor_mr->npages = 0;

	return ib_sg_to_pages(ibmr, sg, sg_nents, sg_offset, sxe2_set_page);
}

struct ib_mr *sxe2_kget_dma_mr(struct ib_pd *pd, int acc)
{
	u64 kva = 0;

	return sxe2_reg_phys_mr(pd, 0, (u64)-1, acc, &kva);
}
