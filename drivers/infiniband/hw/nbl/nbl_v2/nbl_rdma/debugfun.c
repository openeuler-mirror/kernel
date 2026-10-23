// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2022, nebula-matrix Limited */

#include <linux/debugfs.h>
#include <linux/bitfield.h>
#include "cqp.h"
#include "main.h"
#include "ceq.h"
#include "aeq.h"
#include "qp.h"
#include "counters.h"
#include "srq.h"
#include "umr.h"
#include "dbgfs.h"
#include "lag.h"

static const char *const nbl_dbg_fun_name[] = {
	"query_voa",
	"cache_qpc",
	"cache_cqc",
	"cache_mrte",
	"cache_pble",
	"cache_sqrqe",
	"cache_irqe",
	"cache_raqe",
	"cache_srqc",
	"cache_pdc",
	"hmc_qpc",
	"hmc_cqc",
	"hmc_sd",
	"hmc_pble",
	"hmc_mrt",
	"hmc_srqc",
	"query_aeq",
	"query_ceq",
	"create_qp",
	"destroy_qp",
	"create_cq",
	"destroy_cq",
	"dump_aeqe",
	"dump_ceqe",
	"query_vsi",
	"set_fwd",
	"set_dport",
	"set_dport_id",
	"set_stat_id",
	"lag_en",
	"tunnel_en",
	"ackreq_th",
	"query_pble_cnt",
	"fmr_nofence_dbg",
	"arm_fifoqutr",
	"arm_fifolimit",
	"arm_fifonz",
	"arm_fiford",
	"dump_sqe",
	"set_dwqe_en",
	"set_debug_err_code",
	"cache_orqe",
	"cache_unaqe",
	"set_llc",
	"umr_revoke",
	"umr_fldpbl",
	"local_rd_no_pkt",
	"global_sd",
	"mem_read",
	"reset_rdma",
	"srp_en",
	"srp_spray_en",
	"srp_srack_timer",
	"rdma_dport",
	"psn_ost",
	"srp_retry_timer",
	"srp_retry_th",
	"srp_ext_bitmap",
	"srp_ooo_th",
	"srp_retry_pkt_th",
	"qpn_alloc_interval",
	"check_cc_param",
	"srp_nic_spray_mode",
	"cem_en",
	"write_atomic_nofence",
	"clear_cache_qpc",
	"clear_cache_cqc",
	"clear_cache_mrte",
	"clear_cache_srqc",
	"clear_cache_sqrqe",
	"slow_path_en",
	"print_grc_src_addr_tbl",
	"mp_en",
};

static void nbl_debugfs_dump_func_file_deinit(struct nbl_func_file *func_file)
{
	kfree(func_file->buf);
	func_file->buf = NULL;
	func_file->used_len = 0;
	func_file->total_len = 0;
}

static int nbl_debugfs_dump_func_file_init(struct nbl_func_file *func_file, int buffer_size)
{
	if (func_file->buf) {
		memset(func_file->buf, 0, buffer_size);
	} else {
		func_file->buf = kzalloc(buffer_size, GFP_KERNEL);
		if (!func_file->buf)
			return -ENOMEM;
	}
	func_file->used_len = 0;
	func_file->total_len = buffer_size;
	return 0;
}

static void nbl_set_nic_spray_mode(struct nbl_pci_f *rf, u32 mode)
{
	if (!nbl_product_cap_enabled(rf, NBL_PRODUCT_CAP_SRP))
		return;

	switch (mode) {
	case NBL_DEF_SRP_NIC_SPRAY_VALUE:
		rf->sc_dev.srp_nic_spray_val = 0x0;
		break;
	case NBL_SRP_NIC_SPRAY_MODE_QP:
		rf->sc_dev.srp_nic_spray_val = 0xf0001;
		break;
	case NBL_SRP_NIC_SPRAY_MODE_GLOBAL:
		rf->sc_dev.srp_nic_spray_val = 0xf0005;
		break;
	case NBL_SRP_NIC_SPRAY_MODE_QP_RANGE_ALL:
		rf->sc_dev.srp_nic_spray_val = 0x1;
		break;
	case NBL_SRP_NIC_SPRAY_MODE_GLOBAL_RANGE_ALL:
		rf->sc_dev.srp_nic_spray_val = 0x5;
		break;
	default:
		nbl_pr_err("%d is not supported, and the supported range is 0-%d\n",
					mode, NBL_SRP_NIC_SPRAY_MODE_MAX - 1);
		return;
	}

	nbl_pr_info("srp_nic_spray_mode:%d, reg_value:0x%x\n", mode, rf->sc_dev.srp_nic_spray_val);
	wr32(&rf->hw,
	     NBL_TXP_REG_ADDR(NBL_REG_TXP_BASE(&rf->hw),
			       NBL_TXP_CC_NIC_SPRAY_EN_OFF),
	     rf->sc_dev.srp_nic_spray_val);
}

static void nbl_set_slow_path_en(struct nbl_pci_f *rf, u32 var)
{
	u64 reg_addr = NBL_RXP_REG_ADDR(NBL_REG_RXP_BASE(&rf->hw),
					NBL_RXP_SET_SLOW_PATH_EN_OFF);
	u32 reg_val;

	if (!nbl_product_cap_enabled(rf, NBL_PRODUCT_CAP_SLOW_PATH))
		return;

	reg_val = rd32(&rf->hw, reg_addr);
	reg_val |= (!!var) << 15;
	nbl_pr_info("set_slow_path_en:%d, reg_val:%d\n", !!var, reg_val);
	wr32(&rf->hw, reg_addr, reg_val);
}

int nbl_handle_fun_dbg_set(struct nbl_device *nbl_dev, int offset, u32 var)
{
	struct nbl_pci_f *rf = nbl_dev->rf;
	int ret = 0;

	switch (offset) {
	case NBL_FUN_DBG_CACHE_QPC:
		/* init func file */
		ret = nbl_debugfs_dump_func_file_init(
			&nbl_dev->func_dump_info->dump_func_file,
			NBL_DEBUGFS_DUMP_QPC_SIZE);
		if (ret)
			return ret;
		nbl_dev->func_dump_info->fun_type = NBL_FUN_DBG_CACHE_QPC;
		nbl_dump_hw_cache(nbl_dev, var, NBL_CACHE_QPCC);
		break;
	case NBL_FUN_DBG_CACHE_CQC:
		/* init func file */
		ret = nbl_debugfs_dump_func_file_init(
			&nbl_dev->func_dump_info->dump_func_file,
			NBL_DEBUGFS_DUMP_CQC_SIZE);
		if (ret)
			return ret;
		nbl_dev->func_dump_info->fun_type = NBL_FUN_DBG_CACHE_CQC;
		nbl_dump_hw_cache(nbl_dev, var, NBL_CACHE_CQCC);
		break;
	case NBL_FUN_DBG_CACHE_MRTE:
		/* init func file */
		ret = nbl_debugfs_dump_func_file_init(
			&nbl_dev->func_dump_info->dump_func_file,
			NBL_DEBUGFS_DUMP_MRT_SIZE);
		if (ret)
			return ret;
		nbl_dev->func_dump_info->fun_type = NBL_FUN_DBG_CACHE_MRTE;
		nbl_dump_hw_cache(nbl_dev, var, NBL_CACHE_MRTC);
		break;
	case NBL_FUN_DBG_CACHE_PBLE:
		nbl_dump_hw_cache(nbl_dev, var, NBL_CACHE_PBLC);
		break;
	case NBL_FUN_DBG_CACHE_SQRQE:
		nbl_dump_hw_cache(nbl_dev, var, NBL_CACHE_SQRQEC);
		break;
	case NBL_FUN_DBG_CACHE_IRQE:
		nbl_dump_hw_cache(nbl_dev, var, NBL_CACHE_IRQEC);
		break;
	case NBL_FUN_DBG_CACHE_RAQE:
		nbl_dump_hw_cache(nbl_dev, var, NBL_CACHE_RAQEC);
		break;
	case NBL_FUN_DBG_CACHE_SRQC:
		nbl_dump_hw_cache(nbl_dev, var, NBL_CACHE_SRQC);
		break;
	case NBL_FUN_DBG_CACHE_PDC:
		nbl_dump_hw_cache(nbl_dev, var, NBL_CACHE_PDC);
		break;
	case NBL_FUN_DBG_HMC_QPC:
		/* init func file */
		ret = nbl_debugfs_dump_func_file_init(
			&nbl_dev->func_dump_info->dump_func_file,
			NBL_DEBUGFS_DUMP_QPC_SIZE);
		if (ret)
			return ret;
		nbl_dev->func_dump_info->fun_type = NBL_FUN_DBG_HMC_QPC;
		nbl_dump_hmc_qpc(nbl_dev, var);
		break;
	case NBL_FUN_DBG_HMC_SRQC:
		nbl_dump_hmc_srqc(nbl_dev, var);
		break;
	case NBL_FUN_DBG_HMC_CQC:
		/* init func file */
		ret = nbl_debugfs_dump_func_file_init(
			&nbl_dev->func_dump_info->dump_func_file,
			NBL_DEBUGFS_DUMP_CQC_SIZE);
		if (ret)
			return ret;
		nbl_dev->func_dump_info->fun_type = NBL_FUN_DBG_HMC_CQC;
		nbl_dump_hmc_cqc(nbl_dev, var);
		break;
	case NBL_FUN_DBG_HMC_SD:
		nbl_hmc_query_sd(rf, var);
		break;
	case NBL_FUN_DBG_QUERY_GLO_SD:
		nbl_query_global_sd(rf, var);
		break;
	case NBL_FUN_DBG_HMC_PBLE:
		nbl_dump_hmc_pble(rf, var);
		break;
	case NBL_FUN_DBG_HMC_MRT:
		/* init func file */
		ret = nbl_debugfs_dump_func_file_init(
			&nbl_dev->func_dump_info->dump_func_file,
			NBL_DEBUGFS_DUMP_MRT_SIZE);
		if (ret)
			return ret;
		nbl_dev->func_dump_info->fun_type = NBL_FUN_DBG_HMC_MRT;
		nbl_dump_hmc_mrt(nbl_dev, var);
		break;
	case NBL_FUN_DBG_QUERY_AEQ:
		nbl_query_aeq(rf);
		break;
	case NBL_FUN_DBG_QUERY_AEQE:
		nbl_dump_aeqe(rf, var);
		break;
	case NBL_FUN_DBG_QUERY_CEQ:
		nbl_query_ceq(rf);
		break;
	case NBL_FUN_DBG_QUERY_CEQE:
		nbl_dump_ceq(rf, var);
		break;
	case NBL_FUN_DBG_CREATE_QP:
		nbl_dbg_create_qp(rf, var);
		break;
	case NBL_FUN_DBG_DESTROY_QP:
		nbl_dbg_destroy_qp(rf, var);
		break;
	case NBL_FUN_DBG_CREATE_CQ:
		rf->cqp_ops->cqp_dbg_create_cq(rf, var);
		break;
	case NBL_FUN_DBG_DESTROY_CQ:
		rf->cqp_ops->cqp_dbg_destroy_cq(rf, var);
		break;
	case NBL_FUN_DBG_QUERY_VSI:
		nbl_pr_info("function id:%d vsi id:%d\n",
			    rf->sc_dev.function_id, rf->vsi_id);
		break;
	case NBL_FUN_DBG_SET_FWD:
		if (var > 3)
			return -EINVAL;
		nbl_pr_info("function id:%d set fwd:%d\n",
			    rf->sc_dev.function_id, var);
		rf->sc_dev.fwd = var;
		break;
	case NBL_FUN_DBG_SET_DPORT:
		if (var > 3)
			return -EINVAL;
		nbl_pr_info("function id:%d set dport:%d\n",
			    rf->sc_dev.function_id, var);
		rf->sc_dev.dport = var;
		break;
	case NBL_FUN_DBG_SET_DPORT_ID:
		nbl_pr_info("function id:%d set dport id:%d\n",
			    rf->sc_dev.function_id, var);
		rf->sc_dev.dport_id = var;
		if (nbl_product_cap_enabled(rf, NBL_PRODUCT_CAP_DSCH_DPORT_UPDATE))
			nbl_rdma_update_dsch_info(rf);
		break;
	case NBL_FUN_DBG_SET_STAT_ID:
		if (var > 127)
			return -EINVAL;
		nbl_pr_info("function id:%d set stat id:%d\n",
			    rf->sc_dev.function_id, var);
		rf->sc_dev.stat_id = var;
		break;
	case NBL_FUN_DBG_LAG_EN:
		nbl_pr_info("function id:%d lag en:%d\n",
			    rf->sc_dev.function_id, var);
		rf->sc_dev.rss_lag_en = var;
		break;
	case NBL_FUN_DBG_TUNNEL_EN:
		nbl_pr_info("function id:%d tunnel en:%d\n",
			    rf->sc_dev.function_id, var);
		rf->sc_dev.tunnel_en = var;
		break;
	case NBL_FUN_DBG_ACKREQ_TH:
		if (var > 0xff)
			return -EINVAL;
		nbl_pr_info("function id:%d ackreq_th:%d\n",
			    rf->sc_dev.function_id, var);
		rf->sc_dev.ackreq_th = var;
		break;
	case NBL_FUN_DBG_QUERY_PBLE_CNT:
		nbl_dump_pble_cnt(rf);
		break;
	case NBL_FUN_DBG_FMR_NOFENCE_DBG:
		rf->sc_dev.nvme_fmr_en = var;
		nbl_pr_info("function id:%d set nofence:%x\n",
			    rf->sc_dev.function_id, var);
		break;
	case NBL_FUN_DBG_DUMP_SQE:
		nbl_dump_sqe(nbl_dev, var);
		break;
	case NBL_FUN_DBG_SET_DWQE_EN:
		/*TODO dwqe v1 dwqe v2 use same en*/
		rf->sc_dev.dwqe_en = var;
		break;
	case NBL_FUN_DBG_SET_DEBUG_ERRCODE:
		rf->sc_dev.debug_errcdoe = var;
		nbl_pr_info("function id:%d debug errcode:%x\n",
			    rf->sc_dev.function_id, var);
		break;
	case NBL_FUN_DBG_CACHE_ORQE:
		nbl_dump_hw_cache(nbl_dev, var, NBL_CACHE_ORQEC);
		break;
	case NBL_FUN_DBG_CACHE_UNAQE:
		nbl_dump_hw_cache(nbl_dev, var, NBL_CACHE_UNAQC);
		break;
	case NBL_FUN_DBG_LLC:
		nbl_rdma_set_llc(nbl_dev, var);
		break;
	case NBL_FUN_DBG_UMR_REVOKE:
		nbl_umr_dbgfs_handle(nbl_dev, var, NBL_UMR_OP_REVOKE);
		break;
	case NBL_FUN_DBG_UMR_FLDPBL:
		nbl_umr_dbgfs_handle(nbl_dev, var, NBL_UMR_OP_FLDPBL);
		break;
	case NBL_FUN_DBG_LOCAL_RD_NO_PKT:
		nbl_pr_info("function id:%d local rd no pkt:%u\n",
			    rf->sc_dev.function_id, var);
		rf->sc_dev.local_rd_no_pkt = var;
		break;
	case NBL_FUN_DBG_RESET_RDMA:
		if (var == 2)
			rf->rdma_reset = 1;
		else {
			if (nbl_dev->rf->rdma_reset)
				nbl_pr_info("rdma already reset!");
			else {
				nbl_pr_info("rdma reset!");
				nbl_reset_same_pci_dev(nbl_dev);
			}
		}
		break;
	case NBL_FUN_DBG_SRP_EN:
		if (nbl_product_cap_enabled(rf, NBL_PRODUCT_CAP_SRP)) {
			nbl_pr_info("srp_en %d\n", var);
			rf->sc_dev.srp_en = !!var;
			if (!rf->sc_dev.srp_en && rf->sc_dev.cc_mode &&
			    rf->sc_dev.cc_mode != NBL_QCN)
				nbl_rdma_set_txm_sq_raq_separate(&rf->hw,
								 false);
			else
				nbl_rdma_set_txm_sq_raq_separate(&rf->hw, true);
		}
		break;
	case NBL_FUN_DBG_SRP_SPRAY_EN:
		if (nbl_product_cap_enabled(rf, NBL_PRODUCT_CAP_SRP)) {
			nbl_pr_info("srp_spray_en %d\n", var);
			rf->sc_dev.srp_spray_en = !!var;
		}
		break;
	case NBL_FUN_DBG_SRP_NIC_SPRAY_MODE:
		nbl_set_nic_spray_mode(rf, var);
		break;
	case NBL_FUN_DBG_SRP_SRACK_TIMER:
		if (nbl_product_cap_enabled(rf, NBL_PRODUCT_CAP_SRP)) {
			if (var > NBL_SRP_SRACK_TIMER_VALUE_MAX) {
				nbl_pr_err(
					"srp_srack_timer %d is greater than max(%d), use default %d\n",
					var, NBL_SRP_SRACK_TIMER_VALUE_MAX,
					NBL_SRP_SRACK_TIMER_VALUE_DEFAULT);
				rf->sc_dev.srp_srack_timer =
					NBL_SRP_SRACK_TIMER_VALUE_DEFAULT;
			} else {
				nbl_pr_info("srp_srack_timer %d\n", var);
				rf->sc_dev.srp_srack_timer = var;
			}
		}
		break;
	case NBL_FUN_DBG_RDMA_DPORT:
		if (nbl_product_cap_enabled(rf,
					    NBL_PRODUCT_CAP_CHG_PKT_UDP_PORT)) {
			if (var >= NBL_RDMA_DPORT_MIN &&
			    var <= NBL_RDMA_DPORT_MAX) {
				nbl_pr_info("set rdma dport 0x%x\n", var);
				nbl_rdma_set_rdma_dport(nbl_dev, var);
			} else
				nbl_pr_err(
					"rdma dport 0x%x must in 0x%x, 0x%x\n",
					var, NBL_RDMA_DPORT_MIN,
					NBL_RDMA_DPORT_MAX);
		}
		break;
	case NBL_FUN_DBG_PSN_OST:
		if (nbl_product_cap_enabled(rf, NBL_PRODUCT_CAP_CHG_PSN_OST)) {
			if (var >= NBL_RDMA_PSN_OST_MIN &&
			    var <= NBL_RDMA_PSN_OST_MAX) {
				nbl_pr_info("set rdma psn ost 0x%x\n", var);
				nbl_rdma_set_psn_ost(nbl_dev, var);
				if (var < rf->sc_dev.ackreq_th)
					rf->sc_dev.ackreq_th = var;
			} else
				nbl_pr_err(
					"rdma psn ost 0x%x must in 0x%x, 0x%x\n",
					var, NBL_RDMA_PSN_OST_MIN,
					NBL_RDMA_PSN_OST_MAX);
		}
		break;
	case NBL_FUN_DBG_SRP_RETRY_TIMER:
		if (nbl_product_cap_enabled(rf, NBL_PRODUCT_CAP_SRP)) {
			if (var > NBL_TLP_RETRY_TIMER_MAX) {
				nbl_pr_err(
					"srp_retry_timer is greater than max(%d), use default %d\n",
					NBL_TLP_RETRY_TIMER_MAX,
					NBL_TLP_RETRY_TIMER_DEFAULT);
				rf->sc_dev.tlp_timer =
					NBL_TLP_RETRY_TIMER_DEFAULT;
			} else {
				nbl_pr_info("set srp_retry_timer %d\n", var);
				rf->sc_dev.tlp_timer = var;
			}
		}
		break;
	case NBL_FUN_DBG_SRP_RETRY_TH:
		if (nbl_product_cap_enabled(rf, NBL_PRODUCT_CAP_SRP)) {
			if (var > NBL_TLP_RETRY_TH_MAX) {
				nbl_pr_err(
					"srp_retry_th is greater than max(%d), use default %d\n",
					NBL_TLP_RETRY_TH_MAX,
					NBL_TLP_RETRY_TH_DEFAULT);
				rf->sc_dev.tlp_retry_th =
					NBL_TLP_RETRY_TH_DEFAULT;
			} else {
				nbl_pr_info("set srp_retry_th %d\n", var);
				rf->sc_dev.tlp_retry_th = var;
			}
		}
		break;
	case NBL_FUN_DBG_SRP_EXT_BITMAP_EN:
		if (nbl_product_cap_enabled(rf, NBL_PRODUCT_CAP_SRP)) {
			nbl_pr_info("set srp_ext_bitmap_en %d\n", var);
			nbl_set_srp_cfg(nbl_dev, !!var,
					NBL_SRP_CONFIG_BITMAP_EN);
		}
		break;
	case NBL_FUN_DBG_SRP_OOO_TH:
		if (nbl_product_cap_enabled(rf, NBL_PRODUCT_CAP_SRP)) {
			if (var > NBL_SRP_EPSN_RTH_MAX) {
				nbl_pr_err("srp_ooo_th %d must in %d\n", var,
					   NBL_SRP_EPSN_RTH_MAX);
			} else {
				nbl_pr_info("set srp_ooo_th %d\n", var);
				nbl_set_srp_cfg(nbl_dev, var,
						NBL_SRP_CONFIG_EPSN_RTH);
			}
		}
		break;
	case NBL_FUN_DBG_SRP_RETRY_PKT_TH:
		if (nbl_product_cap_enabled(rf, NBL_PRODUCT_CAP_SRP)) {
			nbl_pr_info("set srp_retry_pkt_th %d\n", var);
			nbl_set_srp_cfg(nbl_dev, var,
					NBL_FUN_DBG_SRP_RETRY_PKT_TH);
		}
		break;
	case NBL_FUN_DBG_QPN_ALLOC_INTERVAL:
		if (nbl_product_cap_enabled(rf,
					    NBL_PRODUCT_CAP_QPN_ALLOC_INTERVAL)) {
			nbl_pr_info("set qpn_interval %u us\n", var);
			rf->sc_dev.qpn_interval = var;
		}
		break;
	case NBL_FUN_DBG_CHECK_CC_PARAM:
			rf->sc_dev.check_cc_param = var;
		break;
	case NBL_FUN_DBG_CEM_EN:
		if (rf->product->cq_ops->cq_moderation_supported) {
			nbl_pr_info("set cem %u\n", var);
			rf->sc_dev.cem_enable = (!!var);
			nbl_ibdev_set_dim(&nbl_dev->ibdev,
				rf->sc_dev.cem_enable ? 1 : 0);
		}
		break;
	case NBL_FUN_DBG_WRITE_ATOMIC_FENCE:
		if (nbl_product_cap_enabled(rf,
					    NBL_PRODUCT_CAP_WRITE_ATOMIC_FENCE)) {
			rf->sc_dev.write_atomic_fence = var;
			nbl_pr_info("set rxm write atomic fence %u\n", var);
			nbl_rdma_rxm_write_atomic_fence(
				nbl_dev, rf->sc_dev.write_atomic_fence);
		}
		break;
	case NBL_FUN_DBG_CLEAR_CACHE_QPC:
		nbl_clear_hw_cache(rf, NBL_CACHE_QPCC);
		break;
	case NBL_FUN_DBG_CLEAR_CACHE_CQC:
		nbl_clear_hw_cache(rf, NBL_CACHE_CQCC);
		break;
	case NBL_FUN_DBG_CLEAR_CACHE_MRTE:
		nbl_clear_hw_cache(rf, NBL_CACHE_MRTC);
		break;
	case NBL_FUN_DBG_CLEAR_CACHE_SRQC:
		nbl_clear_hw_cache(rf, NBL_CACHE_SRQC);
		break;
	case NBL_FUN_DBG_CLEAR_CACHE_SQRQE:
		nbl_clear_hw_cache(rf, NBL_CACHE_SQRQEC);
		break;
	case NBL_FUN_DBG_SLOW_PATH_EN:
		nbl_set_slow_path_en(rf, var);
		break;
	case NBL_FUN_DBG_PRINT_GRC_SRC_ADDR_TBL:
		nbl_print_grc_src_addr_tbl(rf, var);
		break;
	case NBL_FUN_DBG_MP_EN:
		if (nbl_product_cap_enabled(rf, NBL_PRODUCT_CAP_MPLANE_SPRAY)) {
			nbl_pr_info("mp_en %d\n", var);
			nbl_set_rdma_mp_en(rf, !!var);
		}
		break;
	default:
		nbl_pr_err("[debugfun] unknown cmd\n");
		break;
	}

	rf->sc_dev.fundbg_params[offset] = var;
	return ret;
}

static ssize_t set_fun_param(struct file *filp, const char __user *buf,
			     size_t count, loff_t *pos)
{
	struct nbl_ib_dbg_param *param = filp->private_data;
	struct nbl_device *nbl_dev = param->dev;
	int offset = param->offset;
	int ret;
	char lbuf[32] = {};
	u64 var64;
	u32 var;

	if (count > sizeof(lbuf))
		return -EINVAL;

	if (copy_from_user(lbuf, buf, count))
		return -EFAULT;

	lbuf[sizeof(lbuf) - 1] = '\0';

	if (offset == NBL_FUN_DBG_MEM_READ) {
		if (kstrtou64(lbuf, 0, &var64))
			return -EINVAL;
		nbl_pr_info("mem read PA 0x%llx\n", var64);
		nbl_dbg_mem_read(nbl_dev, var64);

		return count;
	}

	if (kstrtou32(lbuf, 0, &var))
		return -EINVAL;

	ret = nbl_handle_fun_dbg_set(nbl_dev, offset, var);

	return ret ? ret : count;
}

static ssize_t get_fun_param(struct file *filp, char __user *buf, size_t count,
			 loff_t *pos)
{
	struct nbl_ib_dbg_param *param = filp->private_data;
	struct nbl_device *nbl_dev = param->dev;
	struct nbl_pci_f *rf = nbl_dev->rf;
	struct nbl_func_file *func_file = NULL;

	int offset = param->offset;
	u32 var = 0;
	int ret;
	char lbuf[NBL_FUNDBG_READ_BUF_SIZE];
	ssize_t ret_data;

	switch (offset) {
	case NBL_FUN_DBG_QUERY_VSI:
		var = rf->vsi_id;
		break;
	case NBL_FUN_DBG_SET_FWD:
		var = rf->sc_dev.fwd;
		break;
	case NBL_FUN_DBG_SET_DPORT:
		var = rf->sc_dev.dport;
		break;
	case NBL_FUN_DBG_SET_DPORT_ID:
		var = rf->sc_dev.dport_id;
		break;
	case NBL_FUN_DBG_SET_STAT_ID:
		var = rf->sc_dev.stat_id;
		break;
	case NBL_FUN_DBG_LAG_EN:
		var = rf->sc_dev.rss_lag_en;
		break;
	case NBL_FUN_DBG_TUNNEL_EN:
		var = rf->sc_dev.tunnel_en;
		break;
	case NBL_FUN_DBG_ACKREQ_TH:
		var = rf->sc_dev.ackreq_th;
		break;
	case NBL_FUN_DBG_GET_ARM_QUTR:
	case NBL_FUN_DBG_GET_ARM_LIMT:
	case NBL_FUN_DBG_GET_ARM_FIFONZ:
	case NBL_FUN_DBG_GET_ARM_FIFORD:
		break;
	case NBL_FUN_DBG_QUERY_VOA:
		return nbl_query_voa(buf, count, pos, rf);
	case NBL_FUN_DBG_FMR_NOFENCE_DBG:
		var = rf->sc_dev.nvme_fmr_en;
		break;
	case NBL_FUN_DBG_SET_DWQE_EN:
		var = rf->sc_dev.dwqe_en;
		break;
	case NBL_FUN_DBG_LOCAL_RD_NO_PKT:
		var = rf->sc_dev.local_rd_no_pkt;
		break;
	case NBL_FUN_DBG_RDMA_DPORT:
		if (nbl_product_cap_enabled(rf,
					    NBL_PRODUCT_CAP_CHG_PKT_UDP_PORT))
			nbl_rdma_get_rdma_dport(nbl_dev, &var);
		break;
	case NBL_FUN_DBG_PSN_OST:
		if (nbl_product_cap_enabled(rf, NBL_PRODUCT_CAP_CHG_PSN_OST))
			nbl_rdma_get_psn_ost(nbl_dev, &var);
		break;
	case NBL_FUN_DBG_WRITE_ATOMIC_FENCE:
		if (nbl_product_cap_enabled(rf,
					    NBL_PRODUCT_CAP_WRITE_ATOMIC_FENCE))
			var = rf->sc_dev.write_atomic_fence;
		break;
	default:
		var = rf->sc_dev.fundbg_params[offset];
		break;
	}

	if (nbl_dev->func_dump_info)
		func_file = &nbl_dev->func_dump_info->dump_func_file;

	ret = snprintf(lbuf, sizeof(lbuf), "%u\n", var);
	if (ret < 0)
		return ret;

	if (func_file && func_file->buf && nbl_dev->func_dump_info->fun_type == offset) {
		nbl_pr_dbg("copy from [%lld/%zu]\n", *pos, func_file->used_len);
		ret_data = simple_read_from_buffer(
			buf, count, pos, func_file->buf, func_file->used_len);
		nbl_pr_dbg("copy end [%lld/%zu]\n", *pos, func_file->used_len);
		if ((uint64_t)*pos == (uint64_t)func_file->used_len)
			nbl_debugfs_dump_func_file_deinit(func_file);
	} else
		ret_data = simple_read_from_buffer(buf, count, pos, lbuf, ret);
	return ret_data;
}

static const struct file_operations dbg_fun_fops = {
	.owner	= THIS_MODULE,
	.open	= simple_open,
	.write	= set_fun_param,
	.read	= get_fun_param,
};

static void nbl_debugfs_dump_info_deinit(struct nbl_device *dev)
{
	nbl_debugfs_dump_func_file_deinit(&dev->func_dump_info->dump_func_file);
	kfree(dev->func_dump_info);
}

static void nbl_ib_cleanup_func_debugfs(struct nbl_device *dev)
{
	if (!dev->func_dbg_dir || !dev->dbg_fun_params)
		return;

	nbl_debugfs_dump_info_deinit(dev);
	debugfs_remove_recursive(dev->dbg_fun_params->root);
	kfree(dev->dbg_fun_params);
}

static void nbl_debugfs_dump_info_init(struct nbl_device *dev)
{
	dev->func_dump_info = kzalloc(sizeof(struct nbl_dump_info), GFP_KERNEL);
	if (!dev->func_dump_info)
		return;
}

static bool nbl_dbg_fun_supported(struct nbl_device *dev, int offset)
{
	switch (offset) {
	case NBL_FUN_DBG_UMR_REVOKE:
	case NBL_FUN_DBG_UMR_FLDPBL:
		return nbl_product_cap_enabled(dev->rf, NBL_PRODUCT_CAP_UMR);
	case NBL_FUN_DBG_MP_EN:
		return nbl_product_cap_enabled(dev->rf, NBL_PRODUCT_CAP_MPLANE_SPRAY);
	default:
		return true;
	}
}

static void nbl_ib_init_func_debugfs(struct nbl_device *dev)
{
	struct nbl_ib_dbg_fun_params *dbg_fun_params;
	int i;

	if (!dev->func_dbg_dir)
		return;

	dbg_fun_params = kzalloc(sizeof(*dbg_fun_params), GFP_KERNEL);
	if (!dbg_fun_params)
		goto err;

	dev->dbg_fun_params = dbg_fun_params;

	dbg_fun_params->root = debugfs_create_dir("fun_dbg",
				dev->func_dbg_dir);
	if (!dbg_fun_params->root) {
		nbl_pr_err("init debug_fun directory failed\n");
		goto err;
	}

	for (i = 0; i < NBL_FUN_DBG_TYPE_MAX; i++) {
		if (!nbl_dbg_fun_supported(dev, i))
			continue;

		dbg_fun_params->params[i].offset = i;
		dbg_fun_params->params[i].dev = dev;
		dbg_fun_params->params[i].dentry =
			debugfs_create_file(nbl_dbg_fun_name[i],
					    0600, dbg_fun_params->root,
					    &dbg_fun_params->params[i],
					    &dbg_fun_fops);
	}

	nbl_debugfs_dump_info_init(dev);

	nbl_pr_dbg("init fun_debug debugfs successfully\n");
	return;

err:
	nbl_pr_err("fun_debug debugfs failure\n");
	nbl_ib_cleanup_func_debugfs(dev);
}

void nbl_dbgfs_func_init(struct nbl_device *dev)
{
	nbl_ib_init_func_debugfs(dev);
}

void nbl_dbgfs_func_deinit(struct nbl_device *dev)
{
	nbl_ib_cleanup_func_debugfs(dev);
}
