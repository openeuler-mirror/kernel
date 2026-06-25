// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_cc_debugfs.c
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/debugfs.h>
#include "sxe2_drv_rdma_log.h"
#include "sxe2_drv_cc_debugfs.h"
#include "sxe2_drv_qp.h"
#include "sxe2_drv_rdma_debugfs.h"
#include "sxe2_drv_aux.h"

#ifdef SXE2_CFG_DEBUG

static ssize_t drv_rdma_cc_np_write(struct file *filp, const char __user *buf,
									 size_t count, loff_t *off)
{
	ssize_t ret = SXE2_OK;
	char cmd[CC_DEBUGFS_WRITE_BUF_MAX_LEN] = {0};
	struct sxe2_rdma_device *rdma_dev;
	u32 np_enable;

	if (*off != 0)
		goto end;

	if (count >= CC_DEBUGFS_WRITE_BUF_MAX_LEN) {
		ret = -ENOSPC;
		DRV_RDMA_LOG_ERROR("cc debugfs:cmd exceeded length limit err\n");
		goto end;
	}

	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR("cc debugfs:dev find failed err\n");
		goto end;
	}

	if (copy_from_user(cmd, buf, count)) {
		ret = -EFAULT;
		DRV_RDMA_LOG_ERROR_BDF("cc debugfs:cmd copy from user failed err\n");
		goto end;
	}

	ret = sscanf(cmd, "%u", &np_enable);
	if (ret != 1) {
		ret = -ENODATA;
		DRV_RDMA_LOG_ERROR_BDF("cc debugfs:analyze cmd err please input 1/0\n");
		goto end;
	}
	DRV_RDMA_LOG_DEBUG_BDF("cc debugfs:input ecn enable %u\n", np_enable);
	if (!rdma_dev->rdma_func->cc_params.dcqcn_enable) {
		ret = -EINVAL;
		DRV_RDMA_LOG_ERROR_BDF("cc debugfs:cc dcqcn is disable\n");
	}

	if (np_enable) {
		rdma_dev->rdma_func->cc_params.cnp_ecn = SXE2_QP_CC_CNP_ECN_ENABLE;
		rdma_dev->rdma_func->cc_params.ecn     = SXE2_QP_CC_CNP_ECN_ENABLE;
	} else {
		rdma_dev->rdma_func->cc_params.cnp_ecn = SXE2_QP_CC_CNP_ECN_DISABLE;
		rdma_dev->rdma_func->cc_params.ecn     = SXE2_QP_CC_CNP_ECN_DISABLE;
	}

	ret  = count;
	*off = count;

end:
	return ret;
}

static ssize_t drv_rdma_cc_np_read(struct file *filp,
			char __user *buf, size_t count, loff_t *off)
{
	ssize_t ret	  = SXE2_OK;
	u32 len_total = 0;
	char *rsp	  = NULL;
	char *rsp_end;
	struct sxe2_rdma_device *rdma_dev;

	if (*off != 0)
		goto end;

	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR(
			"cc debugfs:find dev struct from private_data failed err\n");
		goto end;
	}

	rsp = kzalloc(sizeof(char) * SXE2_DEBUG_DUMP_BUF_SIZE, GFP_KERNEL);
	if (!rsp) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_ERROR("cc debugfs:cc info rsp kmalloc failed err\n");
		goto end;
	}
	rsp_end = rsp;

	if (rdma_dev->rdma_func->cc_params.dcqcn_enable) {
		if (rdma_dev->rdma_func->cc_params.cnp_ecn)
			len_total += dbg_vsnprintf(rsp_end, len_total, "np enable\n");
		else
			len_total += dbg_vsnprintf(rsp_end, len_total, "np disable\n");

	} else {
		len_total += dbg_vsnprintf(rsp_end, len_total, "please enable cc dcqcn\n");
	}

	ret = simple_read_from_buffer(buf, count, off, rsp, (ssize_t)len_total);
	if (ret < 0)
		DRV_RDMA_LOG_ERROR("cc debugfs:simple read error %zu\n", ret);

	kfree(rsp);
	rsp = NULL;

end:
	return ret;
}

static const struct file_operations sxe2_rdma_cc_np_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read  = drv_rdma_cc_np_read,
	.write = drv_rdma_cc_np_write,
};

#endif
static ssize_t drv_rdma_cc_qp_dfx_write(struct file *filp, const char __user *buf,
									 size_t count, loff_t *off)
{
	ssize_t ret = SXE2_OK;
	char cmd[CC_DEBUGFS_WRITE_BUF_MAX_LEN] = {0};
	struct sxe2_rdma_device *rdma_dev;
	u32 cc_qp_idx;

	if (*off != 0)
		goto end;

	if (count >= CC_DEBUGFS_WRITE_BUF_MAX_LEN) {
		ret = -ENOSPC;
		DRV_RDMA_LOG_ERROR("cc debugfs:cmd exceeded length limit err\n");
		goto end;
	}

	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR("cc debugfs:dev find failed err\n");
		goto end;
	}

	if (copy_from_user(cmd, buf, count)) {
		ret = -EFAULT;
		DRV_RDMA_LOG_ERROR_BDF("cc debugfs:cmd copy from user failed err\n");
		goto end;
	}

	ret = sscanf(cmd, "%u", &cc_qp_idx);
	if (ret != 1) {
		ret = -ENODATA;
		DRV_RDMA_LOG_ERROR_BDF("cc debugfs:analyze cmd err please input 1/0\n");
		goto end;
	}
	if (cc_qp_idx > CC_MAX_CC_QP_IDX) {
		ret = -EINVAL;
		DRV_RDMA_LOG_ERROR_BDF("cc debugfs:max cc qp idx is 4096\n");
		goto end;
	}

	rdma_dev->rdma_func->cc_params.cc_qp_idx = cc_qp_idx;

	ret  = count;
	*off = count;

end:
	return ret;
}

static ssize_t drv_rdma_cc_qp_dfx_read(struct file *filp,
		char __user *buf, size_t count, loff_t *off)
{
	ssize_t ret	  = SXE2_OK;
	u32 len_total = 0;
	char *rsp	  = NULL;
	char *rsp_end;
	struct sxe2_rdma_device *rdma_dev;
	struct cc_sw_entry cc_entry;
	struct aux_core_dev_info *cdev_info;
	struct sxe2_get_cc_qp_dfx_cmd_info cmd_info;
	struct cc_timely_entry *timely;
	struct cc_dcqcn_entry *dcqcn;

	if (*off != 0)
		goto end;
	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR(
			"cc debugfs:find dev struct from private_data failed err\n");
		goto end;
	}
	cdev_info = rdma_dev->rdma_func->cdev;
	cmd_info.cc_qp_idx = cpu_to_le32(rdma_dev->rdma_func->cc_params.cc_qp_idx);
	rsp = kzalloc(sizeof(char) * SXE2_DEBUG_DUMP_BUF_SIZE, GFP_KERNEL);
	if (!rsp) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_ERROR("cc debugfs:cc info rsp kmalloc failed err\n");
		goto end;
	}
	rsp_end = rsp;
	ret = sxe2_rdma_adminq_send(cdev_info, SXE2_CMD_RDMA_GET_CC_QP_DFX, (u8 *)(&cmd_info),
		(u16)sizeof(cmd_info), (u8 *)(&cc_entry),  (u16)sizeof(cc_entry));
	if (ret) {
		DRV_RDMA_LOG_ERROR("cc debugfs:rdma send cme err\n");
		goto end;
	}
	timely = &(cc_entry.timely);
	dcqcn  =  &(cc_entry.dcqcn);
	len_total += dbg_vsnprintf(rsp_end, len_total, "cc qp idx %u dfx:\n", cmd_info.cc_qp_idx);
	len_total += dbg_vsnprintf(rsp_end, len_total,
		"------------------timely entry--------------------\n");
	len_total += dbg_vsnprintf(rsp_end, len_total, "timey_min_rtt             :%u\n",
		timely->min_rtt_h << TIMELY_MIN_RTT_H_SHIFT | timely->min_rtt_l);
	len_total += dbg_vsnprintf(rsp_end, len_total,
		"timey_alpha               :%u\n", timely->alpha);
	len_total += dbg_vsnprintf(rsp_end, len_total, "timey_thigh               :%u\n",
		timely->high_h << TIMELY_THIGH_H_SHIFT | timely->high_l);
	len_total += dbg_vsnprintf(rsp_end, len_total,
		"timey_tlow                :%u\n", timely->low);
	len_total += dbg_vsnprintf(rsp_end, len_total, "timey_pre_rtt             :%u\n",
		timely->pre_rtt_h << TIMELY_PRE_RTT_H_SHIFT | timely->pre_rtt_l);
	len_total += dbg_vsnprintf(rsp_end, len_total,
		"timey_beta                :%u\n", timely->beta);
	len_total += dbg_vsnprintf(rsp_end, len_total,
		"timey_rtt_diff_symbol     :%u\n", timely->rtt_diff_symbol);
	len_total += dbg_vsnprintf(rsp_end, len_total,
		"timey_rtt_diff            :%u\n", timely->rtt_diff);
	len_total += dbg_vsnprintf(rsp_end, len_total,
		"timey_rtt_event_cnt       :%u\n",
		timely->rtt_event_h << RTT_DFX_H_SHIFIT | dcqcn->rtt_event_l);

	len_total += dbg_vsnprintf(rsp_end, len_total,
		"-------------------dcqcn entry---------------------\n");
	len_total += dbg_vsnprintf(rsp_end, len_total, "dcqcn_t                   :%u\n",
		dcqcn->t_h << DCQCN_T_INTERVAL_H_SHIFT | dcqcn->t_l);
	len_total += dbg_vsnprintf(rsp_end, len_total,
		"dcqcn_g                   :%u\n", dcqcn->g);
	len_total += dbg_vsnprintf(rsp_end, len_total, "dcqcn_rhai                :%u\n",
		dcqcn->rhai_h << DCQCN_RHAI_H_SHIFT | dcqcn->rhai_l);
	len_total += dbg_vsnprintf(rsp_end, len_total,
		"dcqcn_rai                 :%u\n", dcqcn->rai);
	len_total += dbg_vsnprintf(rsp_end, len_total,
		"dcqcn_f                   :%u\n", dcqcn->f);
	len_total += dbg_vsnprintf(rsp_end, len_total, "dcqcn_rreduce_mperiod     :%u\n",
		dcqcn->rreduce_mperiod_h << DCQCN_RREDUCE_MPERIOD_H_SHIFT
		| dcqcn->rreduce_mperiod_l);
	len_total += dbg_vsnprintf(rsp_end, len_total,
		"dcqcn_k                   :%u\n", dcqcn->k);
	len_total += dbg_vsnprintf(rsp_end, len_total,
		"dcqcn_min_dec_factor      :%u\n", dcqcn->min_dec_factor);
	len_total += dbg_vsnprintf(rsp_end, len_total, "dcqcn_rc                  :%u\n",
		dcqcn->rc_h << DCQCN_RC_H_SHIFT | dcqcn->rc_l);
	len_total += dbg_vsnprintf(rsp_end, len_total,
		"dcqcn_alpha               :%u\n", dcqcn->alpha);
	len_total += dbg_vsnprintf(rsp_end, len_total,
		"dcqcn_min_rate            :%u\n", dcqcn->min_rate);
	len_total += dbg_vsnprintf(rsp_end, len_total, "dcqcn_rt                  :%u\n",
		dcqcn->rt_h << DCQCN_RT_H_SHIFT | dcqcn->rt_l);
	len_total += dbg_vsnprintf(rsp_end, len_total,
		"dcqcn_func_id             :%u\n", dcqcn->func_id);
	len_total += dbg_vsnprintf(rsp_end, len_total,
		"dcqcn_t_counter           :%u\n", dcqcn->t_counter);
	len_total += dbg_vsnprintf(rsp_end, len_total,
		"dcqcn_byte_counter        :%u\n", dcqcn->byte_counter);
	len_total += dbg_vsnprintf(rsp_end, len_total,
		"dcqcn_decrease_rate_valid :%u\n", dcqcn->decrease_rate_valid);
	len_total += dbg_vsnprintf(rsp_end, len_total,
		"dcqcn_qpn                 :%u\n", dcqcn->qpn);
	len_total += dbg_vsnprintf(rsp_end, len_total,
		"dcqcn_cc_en               :%u\n", dcqcn->ccEn);
	len_total += dbg_vsnprintf(rsp_end, len_total,
		"dcqcn_bc                  :%u\n", dcqcn->bc);
	len_total += dbg_vsnprintf(rsp_end, len_total,
		"dcqcn_increase_event_cnt  :%u\n", dcqcn->increase_rate_cnt);
	len_total += dbg_vsnprintf(rsp_end, len_total,
		"dcqcn_decrease_event_cnt  :%u\n", dcqcn->decrease_rate_cnt);

	ret = simple_read_from_buffer(buf, count, off, rsp, (ssize_t)len_total);
	if (ret < 0)
		DRV_RDMA_LOG_ERROR("cc debugfs:simple read error %zu\n", ret);

	kfree(rsp);
	rsp = NULL;
end:
	return ret;
}

static const struct file_operations sxe2_rdma_cc_qp_dfx_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read  = drv_rdma_cc_qp_dfx_read,
	.write = drv_rdma_cc_qp_dfx_write,
};

int drv_rdma_debug_cc_add(struct sxe2_rdma_device *rdma_dev)
{
	int ret = SXE2_OK;

	if (!sxe2_rdma_debugfs_get_dev_root(rdma_dev)) {
		ret = -EINVAL;
		DRV_RDMA_LOG_ERROR_BDF("cc debugfs:debugfs root dir not exist ret=%d\n",
				ret);
		goto end;
	}

	if (!rdma_dev->hdl->cc_debugfs) {
		ret = -EINVAL;
		DRV_RDMA_LOG_ERROR_BDF("cc debugfs:dir not exist ret=%d\n",
				ret);
		goto end;
	}

#ifdef SXE2_CFG_DEBUG
	debugfs_create_file("np", SXE2_DEBUG_FILE_READ_WRITE,
			rdma_dev->hdl->cc_debugfs, rdma_dev, &sxe2_rdma_cc_np_fops);
#endif
	debugfs_create_file("cc_qp_dfx", SXE2_DEBUG_FILE_READ_WRITE,
				rdma_dev->hdl->cc_debugfs, rdma_dev, &sxe2_rdma_cc_qp_dfx_fops);

end:
	return ret;
}

