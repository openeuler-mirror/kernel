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
#include "dbgfs.h"
#include "grc.h"
#include "umr.h"

static const char *const nbl_dbg_fun_name[] = {
	"query_voa",	  "cache_qpc",
	"cache_cqc",	  "cache_mrte",
	"cache_pble",	  "cache_sqrqe",
	"cache_irqe",	  "cache_raqe",
	"hmc_qpc",	  "hmc_cqc",
	"hmc_sd",	  "hmc_pble",
	"hmc_mrt",	  "query_aeq",
	"query_ceq",	  "create_qp",
	"destroy_qp",	  "create_cq",
	"destroy_cq",	  "dump_aeqe",
	"dump_ceqe0",	  "dump_ceqe1",
	"query_vsi",	  "set_fwd",
	"set_dport",	  "set_dport_id",
	"set_stat_id",	  "lag_en",
	"tunnel_en",	  "ackreq_th",
	"query_pble_cnt", "arm_fifoqutr",
	"arm_fifolimit",  "arm_fifonz",
	"arm_fiford",	  "qeury_fmr_nofence",
	"set_dwqe_en",	  "set_debug_errcode",
	"batch_wqe_th",	  "set_dif_vf_en",
	"umr_revoke",
	"qpn_alloc_interval",	"clear_cache_qpc",
	"clear_cache_cqc",	"clear_cache_mrte",
	"clear_cache_sqrqe",
};

int fundbg_params[NBL_FUN_DBG_TYPE_MAX] = {0};

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

static ssize_t set_fun_param(struct file *filp, const char __user *buf,
			 size_t count, loff_t *pos)
{
	struct nbl_ib_dbg_param *param = filp->private_data;
	struct nbl_device *nbl_dev = param->dev;
	struct nbl_pci_f *rf = nbl_dev->rf;
	int offset = param->offset;
	int ret;
	char lbuf[32] = { };
	u32 var;

	if (count > sizeof(lbuf))
		return -EINVAL;

	if (copy_from_user(lbuf, buf, count))
		return -EFAULT;

	lbuf[sizeof(lbuf) - 1] = '\0';

	if (kstrtou32(lbuf, 0, &var))
		return -EINVAL;

	switch (offset) {
	case NBL_FUN_DBG_CACHE_QPC:
		/* init func file */
		ret = nbl_debugfs_dump_func_file_init(
			&nbl_dev->func_dump_info->dump_func_file, NBL_DEBUGFS_DUMP_QPC_SIZE);
		if (ret)
			return ret;
		nbl_dev->func_dump_info->fun_type = NBL_FUN_DBG_CACHE_QPC;
		nbl_dump_hw_cache(nbl_dev, var, NBL_CACHE_QPCC);
		break;
	case NBL_FUN_DBG_CACHE_CQC:
		nbl_dump_hw_cache(nbl_dev, var, NBL_CACHE_CQCC);
		break;
	case NBL_FUN_DBG_CACHE_MRTE:
		/* init func file */
		ret = nbl_debugfs_dump_func_file_init(
			&nbl_dev->func_dump_info->dump_func_file, NBL_DEBUGFS_DUMP_MRT_SIZE);
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
	case NBL_FUN_DBG_HMC_QPC:
		/* init func file */
		ret = nbl_debugfs_dump_func_file_init(
			&nbl_dev->func_dump_info->dump_func_file, NBL_DEBUGFS_DUMP_QPC_SIZE);
		if (ret)
			return ret;
		nbl_dev->func_dump_info->fun_type = NBL_FUN_DBG_HMC_QPC;
		nbl_dump_hmc_qpc(nbl_dev, var);
		break;
	case NBL_FUN_DBG_HMC_CQC:
		nbl_dump_hmc_cqc(rf, var);
		break;
	case NBL_FUN_DBG_HMC_SD:
		nbl_hmc_query_sd(rf, var);
		break;
	case NBL_FUN_DBG_HMC_PBLE:
		nbl_dump_hmc_pble(rf, var);
		break;
	case NBL_FUN_DBG_HMC_MRT:
		/* init func file */
		ret = nbl_debugfs_dump_func_file_init(
			&nbl_dev->func_dump_info->dump_func_file, NBL_DEBUGFS_DUMP_MRT_SIZE);
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
	case NBL_FUN_DBG_QUERY_CEQE0:
		nbl_dump_ceqe(rf, 0, var);
		break;
	case NBL_FUN_DBG_QUERY_CEQE1:
		nbl_dump_ceqe(rf, 1, var);
		break;
	case NBL_FUN_DBG_CREATE_QP:
		nbl_dbg_create_qp(rf, var);
		break;
	case NBL_FUN_DBG_DESTROY_QP:
		nbl_dbg_destroy_qp(rf, var);
		break;
	case NBL_FUN_DBG_CREATE_CQ:
		nbl_dbg_create_cq(rf, var);
		break;
	case NBL_FUN_DBG_DESTROY_CQ:
		nbl_dbg_destroy_cq(rf, var);
		break;
	case NBL_FUN_DBG_QUERY_VSI:
		nbl_pr_info("function id:%d vsi id:%d\n", rf->sc_dev.function_id, rf->vsi_id);
		break;
	case NBL_FUN_DBG_SET_FWD:
		if (var != 3 && var != 1)
			return -EINVAL;
		nbl_pr_info("function id:%d set fwd:%d\n", rf->sc_dev.function_id, var);
		rf->sc_dev.fwd = var;
		if (var == 3) {
			nbl_rdma_update_dsch_info(rf);
			ret = nbl_grc_write_reg(nbl_dev->rf, NBL_REG_PP0_RDMA_BYPASS, 0x6A);
			if (ret) {
				nbl_pr_err("failed to write pp0 rdma_bypass into reg:%#x\n",
					NBL_REG_PP0_RDMA_BYPASS);
				nbl_pr_err("set low latency channel failed\n");
				return -EINVAL;
			}
		} else if (var == 1) {
			nbl_rdma_update_dsch_info(rf);
			ret = nbl_grc_write_reg(nbl_dev->rf, NBL_REG_PP0_RDMA_BYPASS, 0x0);
			if (ret) {
				nbl_pr_err("failed to reinit pp0 rdma_bypass into reg:%#x\n",
					NBL_REG_PP0_RDMA_BYPASS);
				return -EINVAL;
			}
		}
		break;
	case NBL_FUN_DBG_SET_DPORT:
		if (var > 3)
			return -EINVAL;
		nbl_pr_info("function id:%d set dport:%d\n", rf->sc_dev.function_id, var);
		rf->sc_dev.dport = var;
		break;
	case NBL_FUN_DBG_SET_DPORT_ID:
		nbl_pr_info("function id:%d set dport id:%d\n", rf->sc_dev.function_id, var);
		rf->sc_dev.dport_id = var;
		nbl_rdma_update_dsch_info(rf);
		break;
	case NBL_FUN_DBG_SET_STAT_ID:
		if (var > 127)
			return -EINVAL;
		nbl_pr_info("function id:%d set stat id:%d\n", rf->sc_dev.function_id, var);
		rf->sc_dev.stat_id = var;
		break;
	case NBL_FUN_DBG_LAG_EN:
		nbl_pr_info("function id:%d lag en:%d\n", rf->sc_dev.function_id, var);
		rf->sc_dev.rss_lag_en = var;
		break;
	case NBL_FUN_DBG_TUNNEL_EN:
		nbl_pr_info("function id:%d tunnel en:%d\n", rf->sc_dev.function_id, var);
		rf->sc_dev.tunnel_en = var;
		break;
	case NBL_FUN_DBG_ACKREQ_TH:
		if (var > 0xff)
			return -EINVAL;
		nbl_pr_info("function id:%d ackreq_th:%d\n", rf->sc_dev.function_id, var);
		rf->sc_dev.ackreq_th = var;
		break;
	case NBL_FUN_DBG_QUERY_PBLE_CNT:
		nbl_dump_pble_cnt(rf);
		break;
	case NBL_FUN_DBG_SET_DWQE_EN:
		rf->sc_dev.dwqe_en = var;
		break;
	case NBL_FUN_DBG_SET_DEBUG_ERRCODE:
		rf->sc_dev.debug_errcdoe = var;
		nbl_pr_info("function id:%d debug errcode:%x\n",
			    rf->sc_dev.function_id, var);
		break;
	case NBL_FUN_DBG_BATCH_WQE_TH:
		if (var > 0xff)
			return -EINVAL;
		rf->sc_dev.batch_wqe_th = var;
		break;
	case NBL_FUN_SET_DIF_VF_EN:
		nbl_set_dif_vf_en(rf, var ? true : false);
		break;
	case NBL_UMR_REVOKE:
		nbl_test_umr_revoke(nbl_dev, var);
		break;
	case NBL_FUN_DBG_QPN_ALLOC_INTERVAL:
		nbl_pr_info("set qpn_interval %u us\n", var);
		rf->sc_dev.qpn_interval = var;
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
	case NBL_FUN_DBG_CLEAR_CACHE_SQRQE:
		nbl_clear_hw_cache(rf, NBL_CACHE_SQRQEC);
		break;
	default:
		nbl_pr_err("[debugfun] unknown cmd\n");
		break;
	}

	fundbg_params[offset] = var;

	return count;
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
		var = rf->armc.fifo_quarter;
		break;
	case NBL_FUN_DBG_GET_ARM_LIMT:
		var = rf->armc.free;
		break;
	case NBL_FUN_DBG_GET_ARM_FIFONZ:
		var = rf->armc.fifo_nz;
		break;
	case NBL_FUN_DBG_GET_ARM_FIFORD:
		var = rf->armc.fifo_rdcnt;
		break;
	case NBL_FUN_DBG_CACHE_QPC:
		func_file = &nbl_dev->func_dump_info->dump_func_file;
		var = fundbg_params[offset];
		break;
	case NBL_FUN_DBG_HMC_QPC:
		func_file = &nbl_dev->func_dump_info->dump_func_file;
		var = fundbg_params[offset];
		break;
	case NBL_FUN_DBG_CACHE_MRTE:
		func_file = &nbl_dev->func_dump_info->dump_func_file;
		var = fundbg_params[offset];
		break;
	case NBL_FUN_DBG_HMC_MRT:
		func_file = &nbl_dev->func_dump_info->dump_func_file;
		var = fundbg_params[offset];
		break;
	case NBL_FUN_DBG_QUERY_VOA:
		return nbl_query_voa(buf, count, pos, rf);
	case NBL_FUN_DBG_QUERY_FMR_NOFENCE:
		var = rf->sc_dev.fmr_nofence;
		break;
	case NBL_FUN_DBG_BATCH_WQE_TH:
		var = rf->sc_dev.batch_wqe_th;
		break;
	case NBL_FUN_DBG_QPN_ALLOC_INTERVAL:
		var = rf->sc_dev.qpn_interval;
		break;
	default:
		var = fundbg_params[offset];
		break;
	}

	ret = snprintf(lbuf, sizeof(lbuf), "%u\n", var);
	if (ret < 0)
		return ret;

	if (func_file && func_file->buf && nbl_dev->func_dump_info->fun_type == offset) {
		nbl_pr_dbg("copy from [%lld/%ld]\n", *pos, func_file->used_len);
		ret_data = simple_read_from_buffer(
			buf, count, pos, func_file->buf, func_file->used_len);
		nbl_pr_dbg("copy end [%lld/%ld]\n", *pos, func_file->used_len);
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
	dev->dbg_fun_params = NULL;
}

static void nbl_debugfs_dump_info_init(struct nbl_device *dev)
{
	dev->func_dump_info = kzalloc(sizeof(struct nbl_dump_info), GFP_KERNEL);
	if (!dev->func_dump_info)
		return;
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
	if (!dbg_fun_params->root)
		nbl_pr_err("init debug_fun directory failed\n");

	for (i = 0; i < NBL_FUN_DBG_TYPE_MAX; i++) {
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

void nbl_debug_function_init(struct nbl_device *dev)
{
	nbl_ib_init_func_debugfs(dev);
}

void nbl_debug_function_deinit(struct nbl_device *dev)
{
	nbl_ib_cleanup_func_debugfs(dev);
}
