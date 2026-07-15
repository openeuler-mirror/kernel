// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_stats.c
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/printk.h>
#include <linux/jiffies.h>
#include "sxe2_compat.h"
#include "sxe2_drv_rdma_log.h"
#include "sxe2_drv_mq.h"
#include "sxe2_drv_stats.h"
#include "sxe2_drv_rdma_debugfs.h"
#include "sxe2_drv_rdma_virtchnl.h"
#include "sxe2_drv_rdma_rcms.h"

#define STATS_TIMER_DELAY      3600000
#define MQ_GATHER_STATS_POST   1
#define STATS_DEFAULT_LIFESPAN 3600000

#ifdef ALLOC_HW_STATS_STRUCT_V1
const char *const sxe2_rdma_hw_stat_names[] = {
	[SXE2_RDMA_HW_STAT_INDEX_IP4TXOCTS]   = "ip4OutOctets",
	[SXE2_RDMA_HW_STAT_INDEX_IP4TXPKTS]   = "ip4OutPkts",
	[SXE2_RDMA_HW_STAT_INDEX_IP4TXMCOCTS] = "ip4OutMcastOctets",
	[SXE2_RDMA_HW_STAT_INDEX_IP4TXMCPKTS] = "ip4OutMcastPkts",
	[SXE2_RDMA_HW_STAT_INDEX_IP6TXOCTS]   = "ip6OutOctets",
	[SXE2_RDMA_HW_STAT_INDEX_IP6TXPKTS]   = "ip6OutPkts",
	[SXE2_RDMA_HW_STAT_INDEX_IP6TXMCOCTS] = "ip6OutMcastOctets",
	[SXE2_RDMA_HW_STAT_INDEX_IP6TXMCPKTS] = "ip6OutMcastPkts",
	[SXE2_RDMA_HW_STAT_INDEX_RDMATXWRS]   = "OutRdmaWrites",
	[SXE2_RDMA_HW_STAT_INDEX_RDMATXRDS]   = "OutRdmaReads",
	[SXE2_RDMA_HW_STAT_INDEX_RDMATXSNDS]  = "OutRdmaSends",
	[SXE2_RDMA_HW_STAT_INDEX_RDMATXBND]   = "OutRdmaBinds",
	[SXE2_RDMA_HW_STAT_INDEX_RDMATXINV]   = "OutRdmaLocalInvs",
	[SXE2_RDMA_HW_STAT_INDEX_TXCNPSENT]   = "OutCnpSent",
	[SXE2_RDMA_HW_STAT_INDEX_IP4RXOCTS]	  = "ip4InOctets",
	[SXE2_RDMA_HW_STAT_INDEX_IP4RXPKTS]	  = "ip4InPkts",
	[SXE2_RDMA_HW_STAT_INDEX_IP4RXDISCARD]	  = "ip4InDiscards",
	[SXE2_RDMA_HW_STAT_INDEX_IP4RXMCOCTS]	  = "ip4InMcastOctets",
	[SXE2_RDMA_HW_STAT_INDEX_IP4RXMCPKTS]	  = "ip4InMcastPkts",
	[SXE2_RDMA_HW_STAT_INDEX_IP6RXOCTS]	  = "ip6InOctets",
	[SXE2_RDMA_HW_STAT_INDEX_IP6RXPKTS]	  = "ip6InPkts",
	[SXE2_RDMA_HW_STAT_INDEX_IP6RXDISCARD]	  = "ip6InDiscards",
	[SXE2_RDMA_HW_STAT_INDEX_IP6RXMCOCTS]	  = "ip6InMcastOctets",
	[SXE2_RDMA_HW_STAT_INDEX_IP6RXMCPKTS]	  = "ip6InMcastPkts",
	[SXE2_RDMA_HW_STAT_INDEX_RDMARXWRS]	  = "InRdmaWrites",
	[SXE2_RDMA_HW_STAT_INDEX_RDMARXRDS]	  = "InRdmaReads",
	[SXE2_RDMA_HW_STAT_INDEX_RDMARXSNDS]	  = "InRdmaSends",
	[SXE2_RDMA_HW_STAT_INDEX_RDMARXINV]	  = "InRdmaSendInvs",
	[SXE2_RDMA_HW_STAT_INDEX_RXECNMARKEDPKTS] = "InEcnMarkedPkts",
	[SXE2_RDMA_HW_STAT_INDEX_RXCNPHANDLED]	  = "InCnpHandledPkts",
	[SXE2_RDMA_HW_STAT_INDEX_RXCNPIGNORED]	  = "InCnpIgnoredPkts",
	[SXE2_RDMA_HW_STAT_INDEX_RXNAKPKTS]	  = "InNakPkts",
	[SXE2_RDMA_HW_STAT_INDEX_RXSEQERR]	  = "InSequenceErrs",
	[SXE2_RDMA_HW_STAT_INDEX_RXRNRNAKPKTS]	  = "InRnrNakPkts",
	[SXE2_RDMA_HW_STAT_INDEX_RXRETRANS]	  = "TimeoutRetrans",
};
#else
const struct rdma_stat_desc sxe2_rdma_hw_stat_descs[] = {
	[SXE2_RDMA_HW_STAT_INDEX_IP4TXOCTS].name   = "ip4OutOctets",
	[SXE2_RDMA_HW_STAT_INDEX_IP4TXPKTS].name   = "ip4OutPkts",
	[SXE2_RDMA_HW_STAT_INDEX_IP4TXMCOCTS].name = "ip4OutMcastOctets",
	[SXE2_RDMA_HW_STAT_INDEX_IP4TXMCPKTS].name = "ip4OutMcastPkts",
	[SXE2_RDMA_HW_STAT_INDEX_IP6TXOCTS].name   = "ip6OutOctets",
	[SXE2_RDMA_HW_STAT_INDEX_IP6TXPKTS].name   = "ip6OutPkts",
	[SXE2_RDMA_HW_STAT_INDEX_IP6TXMCOCTS].name = "ip6OutMcastOctets",
	[SXE2_RDMA_HW_STAT_INDEX_IP6TXMCPKTS].name = "ip6OutMcastPkts",
	[SXE2_RDMA_HW_STAT_INDEX_RDMATXWRS].name   = "OutRdmaWrites",
	[SXE2_RDMA_HW_STAT_INDEX_RDMATXRDS].name   = "OutRdmaReads",
	[SXE2_RDMA_HW_STAT_INDEX_RDMATXSNDS].name  = "OutRdmaSends",
	[SXE2_RDMA_HW_STAT_INDEX_RDMATXBND].name   = "OutRdmaBinds",
	[SXE2_RDMA_HW_STAT_INDEX_RDMATXINV].name   = "OutRdmaLocalInvs",
	[SXE2_RDMA_HW_STAT_INDEX_TXCNPSENT].name   = "OutCnpSent",
	[SXE2_RDMA_HW_STAT_INDEX_IP4RXOCTS].name       = "ip4InOctets",
	[SXE2_RDMA_HW_STAT_INDEX_IP4RXPKTS].name       = "ip4InPkts",
	[SXE2_RDMA_HW_STAT_INDEX_IP4RXDISCARD].name    = "ip4InDiscards",
	[SXE2_RDMA_HW_STAT_INDEX_IP4RXMCOCTS].name     = "ip4InMcastOctets",
	[SXE2_RDMA_HW_STAT_INDEX_IP4RXMCPKTS].name     = "ip4InMcastPkts",
	[SXE2_RDMA_HW_STAT_INDEX_IP6RXOCTS].name       = "ip6InOctets",
	[SXE2_RDMA_HW_STAT_INDEX_IP6RXPKTS].name       = "ip6InPkts",
	[SXE2_RDMA_HW_STAT_INDEX_IP6RXDISCARD].name    = "ip6InDiscards",
	[SXE2_RDMA_HW_STAT_INDEX_IP6RXMCOCTS].name     = "ip6InMcastOctets",
	[SXE2_RDMA_HW_STAT_INDEX_IP6RXMCPKTS].name     = "ip6InMcastPkts",
	[SXE2_RDMA_HW_STAT_INDEX_RDMARXWRS].name       = "InRdmaWrites",
	[SXE2_RDMA_HW_STAT_INDEX_RDMARXRDS].name       = "InRdmaReads",
	[SXE2_RDMA_HW_STAT_INDEX_RDMARXSNDS].name      = "InRdmaSends",
	[SXE2_RDMA_HW_STAT_INDEX_RDMARXINV].name       = "InRdmaSendInvs",
	[SXE2_RDMA_HW_STAT_INDEX_RXECNMARKEDPKTS].name = "InEcnMarkedPkts",
	[SXE2_RDMA_HW_STAT_INDEX_RXCNPHANDLED].name    = "InCnpHandledPkts",
	[SXE2_RDMA_HW_STAT_INDEX_RXCNPIGNORED].name    = "InCnpIgnoredPkts",
	[SXE2_RDMA_HW_STAT_INDEX_RXNAKPKTS].name       = "InNakPkts",
	[SXE2_RDMA_HW_STAT_INDEX_RXSEQERR].name	       = "InSequenceErrs",
	[SXE2_RDMA_HW_STAT_INDEX_RXRNRNAKPKTS].name    = "InRnrNakPkts",
	[SXE2_RDMA_HW_STAT_INDEX_RXRETRANS].name       = "TimeoutRetrans",
};
#endif

void sxe2_kupdate_vsi_stats(struct sxe2_rdma_ctx_vsi *vsi)
{
	struct sxe2_rdma_dev_hw_stats *hw_stats = &vsi->pestat->hw_stats;
	struct sxe2_rdma_gather_stats *gather_stats =
		vsi->pestat->gather_info.gather_stats_va;
	const struct sxe2_rdma_hw_stat_map *map = vsi->dev->hw_stats_map;
	u16 max_stats_idx = vsi->dev->hw_attrs.max_stat_idx;
	u16 i;
	u16 idx;

	mutex_lock(&vsi->pestat->stats_lock);
	for (i = 0; i < max_stats_idx; i++) {
		idx = map[i].byteoff / sizeof(u64);
		hw_stats->stats_val[i] +=
			((gather_stats->val[idx] >> map[i].bitoff) &
			 map[i].bitmask);
	}
	mutex_unlock(&vsi->pestat->stats_lock);

}

void sxe2_kprocess_mq_stats(struct sxe2_mq_request *mq_request)
{
	struct sxe2_rdma_vsi_pestat *pestat = mq_request->param;

	sxe2_kupdate_vsi_stats(pestat->vsi);
}

int sxe2_kgather_stats(struct sxe2_mq_ctx *mq,
		       struct sxe2_rdma_stats_gather_info *info, u64 scratch)
{
	struct mq_wqe_gather_stats *wqe	  = NULL;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(mq->dev);
	int ret_code			  = 0;

	if (info->stats_buff_mem.size < SXE2_GATHER_STATS_BUF_SIZE) {
		ret_code = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("STATS Buf size < 1K, ret_code %d\n",
				     ret_code);
		goto end;
	}

	wqe = (struct mq_wqe_gather_stats *)sxe2_kget_next_mq_wqe(mq, scratch);
	if (!wqe) {
		ret_code = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR("Get MQ WQE fail, ret_code %d\n",
				     ret_code);
		goto end;
	}

	wqe->statistics_instance_index = info->stats_inst_index;
	wqe->op			       = SXE2_MQ_OP_GATHER_STATS;
	wqe->use_rcms_func_index       = info->use_rdma_fcn_index;
	wqe->use_statistics_instance   = info->use_stats_inst;
	wqe->physical_buffer_address   = info->stats_buff_mem.pa;
	wqe->rcms_fcn_index	       = info->rcms_fcn_index;
	wqe->wqe_valid		       = mq->polarity;

	DRV_RDMA_LOG_DEV_DEBUG(
		"GATHER_STATS WQE: statistics_instance_index %#x, op %#x\n"
		"use_rcms_func_index %#x, use_statistics_instance %#x\n"
		"physical_buffer_address %#llx, rcms_fcn_index %#x, wqe_valid %#x\n",
		wqe->statistics_instance_index, wqe->op,
		wqe->use_rcms_func_index, wqe->use_statistics_instance,
		wqe->physical_buffer_address, wqe->rcms_fcn_index,
		wqe->wqe_valid);

	print_hex_dump_debug("STATS: GATHER_STATS WQE", DUMP_PREFIX_OFFSET,
			     SXE2_PRINT_HEX_BYTE_PER_ROW,
			     SXE2_PRINT_HEX_BREAK_PER_BYTE, (__le64 *)wqe,
			     SXE2_MQ_WQE_SIZE * SXE2_PRINT_HEX_MUL_BYTE_8,
			     false);

	sxe2_kpost_mq(mq);

end:
	return ret_code;
}

int sxe2_kgather_stats_mq_cmd(struct sxe2_rdma_ctx_dev *dev,
			      struct sxe2_rdma_vsi_pestat *pestat, bool wait)
{
	struct sxe2_rdma_pci_f *rdma_func = to_rdmafunc(dev);
	struct sxe2_rdma_device *rdma_dev = rdma_func->rdma_dev;
	struct sxe2_mq *mq		  = &rdma_func->mq;
	struct sxe2_mq_request *mq_request;
	struct mq_cmds_info *mq_info;
	int ret_code = 0;

	if (!dev->privileged) {
		ret_code = -EIO;
		DRV_RDMA_LOG_DEV_ERR("STATS: Current func is %d, ret_code %d\n",
				     dev->privileged, ret_code);
		goto end;
	}

	mq_request = sxe2_kalloc_and_get_mq_request(mq, wait);
	if (!mq_request) {
		ret_code = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR(
			"STATS:Alloc <Gather STATS> MQ Request fail, ret_code %d\n",
			ret_code);
		goto end;
	}

	mq_info = &mq_request->info;
	memset(mq_info, 0, sizeof(*mq_info));
	mq_info->mq_cmd			   = MQ_OP_GATHER_STATS;
	mq_info->post_mq		   = MQ_GATHER_STATS_POST;
	mq_info->in.u.stats_gather.info	   = pestat->gather_info;
	mq_info->in.u.stats_gather.scratch = (uintptr_t)mq_request;
	mq_info->in.u.stats_gather.mq	   = &rdma_func->mq.mq;
	mq_request->param		   = pestat;
	if (!wait)
		mq_request->callback_fcn = sxe2_kprocess_mq_stats;

	ret_code = sxe2_khandle_mq_cmd(rdma_func, mq_request);
	if (wait)
		sxe2_kupdate_vsi_stats(pestat->vsi);

	sxe2_kput_mq_request(&rdma_func->mq, mq_request);

end:
	return ret_code;
}

static int sxe2_kgather_pf_for_vf_stats_val_mq_cmd(
	struct sxe2_rdma_ctx_dev *dev,
	struct sxe2_rdma_stats_gather_info *gather_stats_info,
	u32 stats_req_type, struct sxe2_rdma_gather_stats_vf *gather_stats_resp)
{
	struct sxe2_rdma_pci_f *rdma_func = to_rdmafunc(dev);
	struct sxe2_rdma_device *rdma_dev = rdma_func->rdma_dev;
	struct sxe2_mq *mq		  = &rdma_func->mq;
	struct sxe2_mq_request *mq_request;
	struct mq_cmds_info *mq_info;
	struct sxe2_rdma_gather_stats *gather_stats =
		(struct sxe2_rdma_gather_stats *)(gather_stats_info
							  ->gather_stats_va);
	const struct sxe2_rdma_hw_stat_map *map = dev->hw_stats_map;
	u16 i;
	u16 rx_idx   = 0;
	int ret_code = 0;

	if (stats_req_type == SXE2_RDMA_STATS_VF_TX) {
		DRV_RDMA_LOG_DEV_DEBUG("VF stats_req_type TX %u\n",
				       stats_req_type);
	} else if (stats_req_type == SXE2_RDMA_STATS_VF_RX) {
		memcpy(gather_stats_resp->val,
		       &gather_stats->val[STATS_VF_RX_BUF_START_8BYTE],
		       STATS_VF_RX_BUF_ALL_BYTE);
		for (i = SXE2_RDMA_HW_STAT_INDEX_IP4RXOCTS;
		     i < SXE2_RDMA_HW_STAT_INDEX_MAX; i++) {
			rx_idx = (map[i].byteoff / sizeof(u64) -
				  STATS_VF_RX_BUF_START_8BYTE);
			DRV_RDMA_LOG_DEV_DEBUG(
				"vf i %u, rx_idx %u, bitoff %u, val %#llx\n", i,
				rx_idx, map[i].byteoff,
				gather_stats_resp->val[rx_idx]);
		}
		goto end;
	} else {
		ret_code = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR("VF stats_req_type %u, ret %d\n",
				     stats_req_type, ret_code);
		goto end;
	}

	mq_request = sxe2_kalloc_and_get_mq_request(mq, true);
	if (!mq_request) {
		ret_code = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR(
			"VF STATS:Alloc <Gather STATS> MQ Request fail, ret_code %d\n",
			ret_code);
		goto end;
	}

	mq_info = &mq_request->info;
	memset(mq_info, 0, sizeof(*mq_info));
	mq_info->mq_cmd	 = MQ_OP_GATHER_STATS;
	mq_info->post_mq = MQ_GATHER_STATS_POST;
	memcpy(&mq_info->in.u.stats_gather.info, gather_stats_info,
	       sizeof(*gather_stats_info));
	mq_info->in.u.stats_gather.scratch = (uintptr_t)mq_request;
	mq_info->in.u.stats_gather.mq	   = &rdma_func->mq.mq;
	mq_request->param		   = NULL;

	ret_code = sxe2_khandle_mq_cmd(rdma_func, mq_request);

	memcpy(gather_stats_resp->val, gather_stats->val,
	       STATS_VF_TX_BUF_ALL_BYTE);
	for (i = 0; i < SXE2_RDMA_HW_STAT_INDEX_IP4RXOCTS; i++) {
		DRV_RDMA_LOG_DEV_DEBUG("vf i %u, bitoff %u, val %#llx\n", i,
				       map[i].byteoff,
				       gather_stats_resp->val[i]);
	}

	sxe2_kput_mq_request(&rdma_func->mq, mq_request);

end:
	return ret_code;
}

int sxe2_kgather_pf_for_vf_stats_val(
	struct sxe2_rdma_vchnl_dev *vc_dev, u32 stats_req_type,
	struct sxe2_rdma_gather_stats_vf *gather_stats_resp)
{
	int ret_code = 0;
	struct sxe2_rdma_stats_gather_info *gather_stats_info;
	u16 vf_idx;
	struct sxe2_rdma_ctx_dev *dev	  = vc_dev->pf_dev;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(dev);
	u8 vf_pmf_idx			  = (u8)vc_dev->pmf_index;

	if ((!dev->privileged) ||
	    (vf_pmf_idx > dev->hw_attrs.max_hw_vf_fpm_id ||
	     vf_pmf_idx < dev->hw_attrs.first_hw_vf_fpm_id)) {
		ret_code = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR(
			"STATS:dev if pf err or vf pmf id err, dev\n"
			"\tprivileged=%u, id=%u, ret_code %d\n",
			dev->privileged, vf_pmf_idx, ret_code);
		goto end;
	}

	gather_stats_info = &vc_dev->gather_stats_info;
	vf_idx		  = vc_dev->vf_idx;

	if (!vc_dev->gather_stats_buf.va) {
		if (!dev->vf_gather_stats_buf[vf_idx].va) {
			dev->vf_gather_stats_buf[vf_idx].size =
				ALIGN(SXE2_GATHER_STATS_BUF_SIZE,
				      SXE2_STATS_BUF_ALIGN);
			dev->vf_gather_stats_buf[vf_idx].va =
				dma_alloc_coherent(
					rdma_dev->rdma_func->hw.device,
					dev->vf_gather_stats_buf[vf_idx].size,
					&dev->vf_gather_stats_buf[vf_idx].pa,
					GFP_KERNEL);
			if (!dev->vf_gather_stats_buf[vf_idx].va) {
				ret_code = -ENOMEM;
				DRV_RDMA_LOG_DEV_ERR(
					"STATS:alloc vf stats_buf_mem va fail, ret_code %d\n",
					ret_code);
				goto end;
			}
			memset(dev->vf_gather_stats_buf[vf_idx].va, 0,
			       dev->vf_gather_stats_buf[vf_idx].size);
		}
		memcpy(&vc_dev->gather_stats_buf,
		       &dev->vf_gather_stats_buf[vf_idx],
		       sizeof(vc_dev->gather_stats_buf));
	}

	gather_stats_info->use_rdma_fcn_index = true;
	gather_stats_info->use_stats_inst     = false;
	gather_stats_info->rcms_fcn_index     = vf_pmf_idx;
	gather_stats_info->stats_inst_index   = 0;
	memcpy(&gather_stats_info->stats_buff_mem, &vc_dev->gather_stats_buf,
	       sizeof(gather_stats_info->stats_buff_mem));
	gather_stats_info->gather_stats_va =
		gather_stats_info->stats_buff_mem.va;

	ret_code = sxe2_kgather_pf_for_vf_stats_val_mq_cmd(
		dev, gather_stats_info, stats_req_type, gather_stats_resp);
	if (ret_code) {
		ret_code = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR(
			"STATS:get pmf id %u gather stats val err ret=%d\n",
			vf_pmf_idx, ret_code);
	}

end:
	return ret_code;
}

int sxe2_kgather_vf_stats_mq_cmd(struct sxe2_rdma_ctx_dev *dev,
				 struct sxe2_rdma_vsi_pestat *pestat, bool wait)
{
	struct sxe2_rdma_pci_f *rdma_func = to_rdmafunc(dev);
	struct sxe2_rdma_device *rdma_dev = rdma_func->rdma_dev;
	struct sxe2_rdma_dev_hw_stats *hw_stats =
		&pestat->vsi->pestat->hw_stats;
	const struct sxe2_rdma_hw_stat_map *map =
		pestat->vsi->dev->hw_stats_map;
	struct sxe2_rdma_gather_stats *pgather_stats_resp =
		kzalloc(sizeof(struct sxe2_rdma_gather_stats), GFP_KERNEL);
	int ret_code = 0;
	u16 i;
	u16 idx;

	mutex_lock(&pestat->stats_lock);

	if (dev->privileged) {
		ret_code = -EIO;
		DRV_RDMA_LOG_DEV_ERR("STATS: Current func is %d, ret_code %d\n",
				     dev->privileged, ret_code);
		goto end;
	}

	ret_code = sxe2_vchnl_req_gather_stats(dev, pgather_stats_resp);
	if (ret_code) {
		DRV_RDMA_LOG_DEV_ERR("gather stats vf fail, ret_code %d\n",
				     ret_code);
		goto end;
	}

	for (i = 0; i < SXE2_RDMA_HW_STAT_INDEX_MAX; i++) {
		idx = map[i].byteoff / sizeof(u64);
		hw_stats->stats_val[i] +=
			((pgather_stats_resp->val[idx] >> map[i].bitoff) &
			 map[i].bitmask);
	}

end:
	kfree(pgather_stats_resp);
	mutex_unlock(&pestat->stats_lock);
	return ret_code;
}

static void sxe2_kwork_stats(struct work_struct *work)
{
	struct sxe2_rdma_vsi_pestat *devstat =
		container_of(work, struct sxe2_rdma_vsi_pestat, work);
	struct sxe2_rdma_ctx_vsi *ctx_vsi = devstat->vsi;
	struct sxe2_rdma_device *rdma_dev = to_rdmadev(ctx_vsi->dev);
	int ret_code			  = 0;

	if (ctx_vsi->dev->privileged) {
		ret_code = sxe2_kgather_stats_mq_cmd(ctx_vsi->dev,
						    ctx_vsi->pestat, true);
	} else {
		ret_code = sxe2_kgather_vf_stats_mq_cmd(ctx_vsi->dev, ctx_vsi->pestat,
						true);
	}
	if (ret_code) {
		DRV_RDMA_LOG_DEV_ERR("STATS WORK: work failed,ret %d\n",
				     ret_code);
	}

}

static void sxe2_ktimeout_hw_stats(struct timer_list *t)
{
	struct sxe2_rdma_vsi_pestat *pf_devstat =
		from_timer(pf_devstat, t, stats_timer);

	queue_work(pf_devstat->stats_wq, &pf_devstat->work);
	mod_timer(&pf_devstat->stats_timer,
		  jiffies + msecs_to_jiffies(pf_devstat->timer_delay));
}

static int sxe2_kstart_hw_stats_timer(struct sxe2_rdma_ctx_vsi *vsi)
{
	struct sxe2_rdma_vsi_pestat *devstat = vsi->pestat;
	struct sxe2_rdma_device *rdma_dev    = to_rdmadev(vsi->dev);
	int ret_code			     = 0;

	mutex_init(&devstat->stats_lock);
	devstat->stats_wq = alloc_ordered_workqueue(
		"stats_wq", WQ_HIGHPRI | WQ_UNBOUND);
	if (!devstat->stats_wq) {
		ret_code = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR(
			"failed to create workqueue, ret %d\n",
			ret_code);
		goto end;
	}
	INIT_WORK(&devstat->work, sxe2_kwork_stats);

	timer_setup(&devstat->stats_timer, sxe2_ktimeout_hw_stats, 0);
	mod_timer(&devstat->stats_timer,
		  jiffies + msecs_to_jiffies(devstat->timer_delay));

end:
	return ret_code;
}

static void sxe2_kstop_hw_stats_timer(struct sxe2_rdma_ctx_vsi *vsi)
{
	struct sxe2_rdma_vsi_pestat *devstat = vsi->pestat;

	del_timer_sync(&devstat->stats_timer);

	if (devstat->stats_wq)
		destroy_workqueue(devstat->stats_wq);
	mutex_destroy(&devstat->stats_lock);
}

int sxe2_kinit_vsi_stats(struct sxe2_rdma_device *rdma_dev)
{
	struct sxe2_rdma_ctx_dev *dev	     = &rdma_dev->rdma_func->ctx_dev;
	struct sxe2_rdma_ctx_vsi *vsi	     = &rdma_dev->vsi;
	struct sxe2_rdma_vsi_stats_info info = {};
	struct sxe2_rdma_dma_mem *stats_buff_mem;
	int ret_code = 0;

	info.pestat = kzalloc(sizeof(*info.pestat), GFP_KERNEL);
	if (!info.pestat) {
		ret_code = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR(
			"kzalloc stats_info.pestat fail, ret_code %d\n",
			ret_code);
		goto end;
	}
	info.fcn_id = dev->rcms_fn_id;

	vsi->pestat	 = info.pestat;
	vsi->pestat->hw	 = vsi->dev->hw;
	vsi->pestat->vsi = vsi;

	stats_buff_mem = &vsi->pestat->gather_info.stats_buff_mem;
	stats_buff_mem->size =
		ALIGN(SXE2_GATHER_STATS_BUF_SIZE, SXE2_STATS_BUF_ALIGN);
	stats_buff_mem->va =
		dma_alloc_coherent(vsi->pestat->hw->device,
				   stats_buff_mem->size, &stats_buff_mem->pa,
				   GFP_KERNEL);
	if (!stats_buff_mem->va) {
		ret_code = -ENOMEM;
		DRV_RDMA_LOG_DEV_ERR(
			"kzalloc stats_buf_mem va fail, ret_code %d\n",
			ret_code);
		goto free_pestat;
	}
	memset(stats_buff_mem->va, 0, stats_buff_mem->size);

	vsi->pestat->gather_info.gather_stats_va = stats_buff_mem->va;
	vsi->pestat->gather_info.rcms_fcn_index = vsi->dev->hw->rcms.rcms_fn_id;

	vsi->pestat->timer_delay = STATS_TIMER_DELAY;
	ret_code		 = sxe2_kstart_hw_stats_timer(vsi);
	if (ret_code) {
		DRV_RDMA_LOG_DEV_ERR("kstart stats timer fail, ret_code %d\n",
				     ret_code);
		goto free_stats_buf;
	}

	vsi->stats_idx = info.fcn_id;

#ifdef SXE2_CFG_DEBUG
	ret_code = drv_rdma_debug_stats_add(rdma_dev);
	if (ret_code) {
		DRV_RDMA_LOG_DEV_ERR("init stats debugfs fail, ret:%d\n",
				     ret_code);
		sxe2_kfree_vsi_stats(rdma_dev);
		goto end;
	}
#ifdef SXE2_SUPPORT_INJECT
	ret_code = drv_rdma_stats_overflow_inject_debugfs_add(rdma_dev);
	if (ret_code) {
		DRV_RDMA_LOG_DEV_ERR("init stats inject debugfs fail, ret:%d\n",
				     ret_code);
		goto free_stats_buf;
	}
#endif
#endif

	goto end;

free_stats_buf:
	dma_free_coherent(vsi->pestat->hw->device, stats_buff_mem->size,
			  stats_buff_mem->va, stats_buff_mem->pa);
	stats_buff_mem->va = NULL;
free_pestat:
	kfree(info.pestat);
	info.pestat = NULL;
	vsi->pestat = NULL;
end:
	return ret_code;
}

void sxe2_kfree_vsi_stats(struct sxe2_rdma_device *rdma_dev)
{
	struct sxe2_rdma_ctx_vsi *vsi = &rdma_dev->vsi;
	struct sxe2_rdma_ctx_dev *dev = &rdma_dev->rdma_func->ctx_dev;
	u16 idx;

	if (!vsi->pestat) {
		DRV_RDMA_LOG_DEV_ERR("vsi->pestats is NULL\n");
		goto end;
	}

	sxe2_kstop_hw_stats_timer(vsi);

	for (idx = 0; idx < dev->num_vfs; idx++) {
		if (dev->vf_gather_stats_buf[idx].va) {
			dma_free_coherent(rdma_dev->rdma_func->hw.device,
					  dev->vf_gather_stats_buf[idx].size,
					  dev->vf_gather_stats_buf[idx].va,
					  dev->vf_gather_stats_buf[idx].pa);
			dev->vf_gather_stats_buf[idx].va = NULL;
		}
	}

	dma_free_coherent(vsi->pestat->hw->device,
			  vsi->pestat->gather_info.stats_buff_mem.size,
			  vsi->pestat->gather_info.stats_buff_mem.va,
			  vsi->pestat->gather_info.stats_buff_mem.pa);
	vsi->pestat->gather_info.stats_buff_mem.va = NULL;

	kfree(vsi->pestat);
	vsi->pestat = NULL;

end:
	return;
}

#ifdef ALLOC_HW_STATS_V1
struct rdma_hw_stats *sxe2_kalloc_hw_port_stats(struct ib_device *ibdev,
						u8 port_num)

#else
struct rdma_hw_stats *sxe2_kalloc_hw_port_stats(struct ib_device *ibdev,
						u32 port_num)
#endif
{
	struct sxe2_rdma_device *rdma_dev = to_dev(ibdev);
	struct sxe2_rdma_ctx_dev *dev	  = &rdma_dev->rdma_func->ctx_dev;
	int num_counters		  = dev->hw_attrs.max_stat_idx;
	unsigned long lifespan		  = STATS_DEFAULT_LIFESPAN;

	if (!dev->privileged)
		lifespan = STATS_DEFAULT_LIFESPAN;

#ifdef ALLOC_HW_STATS_STRUCT_V1
	return rdma_alloc_hw_stats_struct(sxe2_rdma_hw_stat_names, num_counters,
					  lifespan);
#else
	return rdma_alloc_hw_stats_struct(sxe2_rdma_hw_stat_descs, num_counters,
					  lifespan);
#endif
}

#ifdef GET_HW_STATS_V1
int sxe2_kget_hw_stats(struct ib_device *ibdev, struct rdma_hw_stats *stats,
		       u8 port_num, int index)
#else
int sxe2_kget_hw_stats(struct ib_device *ibdev, struct rdma_hw_stats *stats,
		       u32 port_num, int index)
#endif
{
	struct sxe2_rdma_device *rdma_dev = to_dev(ibdev);
	struct sxe2_rdma_dev_hw_stats *hw_stats =
		&rdma_dev->vsi.pestat->hw_stats;

	if (rdma_dev->rdma_func->ctx_dev.privileged) {
		sxe2_kgather_stats_mq_cmd(&rdma_dev->rdma_func->ctx_dev,
					  rdma_dev->vsi.pestat, true);
	} else {
		sxe2_kgather_vf_stats_mq_cmd(&rdma_dev->rdma_func->ctx_dev,
					     rdma_dev->vsi.pestat, true);
	}

	memcpy(&stats->value[0], hw_stats, sizeof(u64) * stats->num_counters);
	return stats->num_counters;
}

int sxe2_kget_rdma_features(struct sxe2_rdma_device *rdma_dev)
{
	struct sxe2_rdma_ctx_dev *dev = NULL;
	int ret_code		      = 0;
	u32 hw_version		      = 0;
	u32 fw_version		      = 0;

	dev = &rdma_dev->rdma_func->ctx_dev;

	hw_version =
		SXE2_BAR_READ_32(dev->hw_regs[RDMA_FEATURE_HW_VERSION_LOW]);
	dev->feature_info[SXE2_RDMA_HW_MQ_MAJOR_VERSION] =
		FIELD_GET(SXE2_RDMA_HW_MAJOR_VERSION_BITS, (s64)hw_version);
	dev->feature_info[SXE2_RDMA_HW_MQ_MINOR_VERSION] =
		FIELD_GET(SXE2_RDMA_HW_MINOR_VERSION_BITS, (s64)hw_version);
	DRV_RDMA_LOG_DEV_INFO(
		"Get Features:hw_major_version %#x, hw_minor_version %#x\n",
		dev->feature_info[SXE2_RDMA_HW_MQ_MAJOR_VERSION],
		dev->feature_info[SXE2_RDMA_HW_MQ_MINOR_VERSION]);

	dev->feature_info[SXE2_RDMA_HW_MODEL_VERSION_USED] =
		SXE2_BAR_READ_32(dev->hw_regs[RDMA_FEATURE_HW_VERSION_HIGH]);
	DRV_RDMA_LOG_DEV_INFO(
		"Get Features:hw_model_used %#x\n",
		dev->feature_info[SXE2_RDMA_HW_MODEL_VERSION_USED]);

	dev->feature_info[SXE2_RDMA_ENDPT_TRK_EN] =
		SXE2_BAR_READ_32(dev->hw_regs[RDMA_FEATURE_ENDPT_TRK]);
	DRV_RDMA_LOG_DEV_INFO("Get Features:endpt_trk_en %#x\n",
			      dev->feature_info[SXE2_RDMA_ENDPT_TRK_EN]);

	dev->feature_info[SXE2_RDMA_QSETS_MAX_NUMBER] =
		SXE2_BAR_READ_32(dev->hw_regs[RDMA_FEATURE_QSETS_MAX]);
	DRV_RDMA_LOG_DEV_INFO("Get Features:qsets_max_num %#x\n",
			      dev->feature_info[SXE2_RDMA_QSETS_MAX_NUMBER]);

	fw_version = SXE2_BAR_READ_32(dev->hw_regs[RDMA_FEATURE_FW_VERSION]);
	dev->feature_info[SXE2_RDMA_FW_MAIN_VERSION] =
		FIELD_GET(SXE2_RDMA_FW_MAIN_VERSION_BITS, (s64)fw_version);
	dev->feature_info[SXE2_RDMA_FW_SUB_VERSION] =
		FIELD_GET(SXE2_RDMA_FW_SUB_VERSION_BITS, (s64)fw_version);
	dev->feature_info[SXE2_RDMA_FW_FIX_VERSION] =
		FIELD_GET(SXE2_RDMA_FW_FIX_VERSION_BITS, (s64)fw_version);
	dev->feature_info[SXE2_RDMA_FW_BUILD_NUMBER] =
		FIELD_GET(SXE2_RDMA_FW_BUILD_NUMBER_BITS, (s64)fw_version);
	DRV_RDMA_LOG_DEV_INFO(
		"Get Features:fw_main_version %#x, fw_sub_version\n"
		"\t%#x, fw_fix_version %#x, fw_build_number %#x\n",
		dev->feature_info[SXE2_RDMA_FW_MAIN_VERSION],
		dev->feature_info[SXE2_RDMA_FW_SUB_VERSION],
		dev->feature_info[SXE2_RDMA_FW_FIX_VERSION],
		dev->feature_info[SXE2_RDMA_FW_BUILD_NUMBER]);
	dev->fw_ver = fw_version;

	return ret_code;
}
