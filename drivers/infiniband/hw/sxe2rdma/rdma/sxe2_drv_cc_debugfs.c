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
		goto end;
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
		DRV_RDMA_LOG_ERROR("cc debugfs:simple read error %zd\n", ret);

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
		goto free_rsp;
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
		DRV_RDMA_LOG_ERROR("cc debugfs:simple read error %zd\n", ret);
free_rsp:
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

static ssize_t drv_rdma_cc_hw_dcqcn_min_rate_write(struct file *filp, const char __user *buf,
									 size_t count, loff_t *off)
{
	ssize_t ret = SXE2_OK;
	int tmpRet = SXE2_OK;
	char cmd[CC_DEBUGFS_WRITE_BUF_MAX_LEN] = {0};
	struct sxe2_rdma_device *rdma_dev;
	struct aux_core_dev_info *cdev_info;
	struct sxe2_hw_cc_dcqcn_param_info *hw_cc_p;
	struct sxe2_hw_cc_dcqcn_param_info hw_cc_tmp;
	u32 hw_dcqcn_min_rate;

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
	cdev_info = rdma_dev->rdma_func->cdev;
	hw_cc_p = &rdma_dev->rdma_func->cc_params.hw_cc_params;

	if (copy_from_user(cmd, buf, count)) {
		ret = -EFAULT;
		DRV_RDMA_LOG_ERROR_BDF("cc debugfs:cmd copy from user failed err\n");
		goto end;
	}

	ret = sscanf(cmd, "%u", &hw_dcqcn_min_rate);
	if (ret != 1) {
		ret = -ENODATA;
		DRV_RDMA_LOG_ERROR_BDF("cc debugfs:analyze cmd err please input 2-100\n");
		goto end;
	}
	if (hw_dcqcn_min_rate > SXE2_HW_CC_DCQCN_MIN_RATE_MAX ||
		hw_dcqcn_min_rate < SXE2_HW_CC_DCQCN_MIN_RATE_MIN) {
		ret = -EINVAL;
		DRV_RDMA_LOG_ERROR_BDF("cc debugfs:min min_rate is %u, max min_rate is %u.\n",
				SXE2_HW_CC_DCQCN_MIN_RATE_MIN, SXE2_HW_CC_DCQCN_MIN_RATE_MAX);
		goto end;
	}
	hw_cc_tmp = *hw_cc_p;
	hw_cc_tmp.minTh = hw_dcqcn_min_rate;

	tmpRet = sxe2_rdma_adminq_send(cdev_info, SXE2_CMD_RDMA_SET_HW_CC_PARAM,
						(u8 *)&hw_cc_tmp, (u16)sizeof(hw_cc_tmp),
						NULL, 0);
	if (tmpRet) {
		ret = -EIO;
		DRV_RDMA_LOG_DEV_ERR(
			"debugfs cc:aq send set hw cc param err ret=%d\n", tmpRet);
		goto end;
	}
	hw_cc_p->minTh = hw_dcqcn_min_rate;
	DRV_RDMA_LOG_DEV_INFO("cc debugfs:set hw cc param success, minTh(%u), rdPeriod(%u),\n"
	"\tt(%u), bc(%u), alphaCnt(%u), rateCnt(%u), f(%u), rai(%u), rhai(%u)\n",
	hw_cc_p->minTh, hw_cc_p->rdPeriod, hw_cc_p->t, hw_cc_p->bc,
	hw_cc_p->alphaCnt, hw_cc_p->rateCnt, hw_cc_p->f, hw_cc_p->rai, hw_cc_p->rhai);

	ret  = count;
	*off = count;

end:
	return ret;
}

static ssize_t drv_rdma_cc_hw_dcqcn_min_rate_read(struct file *filp,
					char __user *buf, size_t count, loff_t *off)
{
	ssize_t ret	  = SXE2_OK;
	u32 len_total = 0;
	char *rsp	  = NULL;
	char *rsp_end;
	struct sxe2_rdma_device *rdma_dev;
	u32 hw_dcqcn_min_rate;

	if (*off != 0)
		goto end;
	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR(
			"cc debugfs:find dev struct from private_data failed err\n");
		goto end;
	}
	hw_dcqcn_min_rate = rdma_dev->rdma_func->cc_params.hw_cc_params.minTh;
	rsp = kzalloc(sizeof(char) * SXE2_DEBUG_DUMP_BUF_SIZE, GFP_KERNEL);
	if (!rsp) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_ERROR("cc debugfs:cc info rsp kmalloc failed err\n");
		goto end;
	}
	rsp_end = rsp;

	len_total += dbg_vsnprintf(rsp_end, len_total, "hw_dcqcn_min_rate:%u\n", hw_dcqcn_min_rate);

	ret = simple_read_from_buffer(buf, count, off, rsp, (ssize_t)len_total);
	if (ret < 0)
		DRV_RDMA_LOG_ERROR("cc debugfs:simple read error %zd\n", ret);

	kfree(rsp);
	rsp = NULL;
end:
	return ret;
}

static const struct file_operations sxe2_rdma_cc_hw_dcqcn_min_rate_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read  = drv_rdma_cc_hw_dcqcn_min_rate_read,
	.write = drv_rdma_cc_hw_dcqcn_min_rate_write,
};

static ssize_t drv_rdma_cc_hw_dcqcn_rreduce_mperiod_write(struct file *filp, const char __user *buf,
									 size_t count, loff_t *off)
{
	ssize_t ret = SXE2_OK;
	int tmpRet = SXE2_OK;
	char cmd[CC_DEBUGFS_WRITE_BUF_MAX_LEN] = {0};
	struct sxe2_rdma_device *rdma_dev;
	struct aux_core_dev_info *cdev_info;
	struct sxe2_hw_cc_dcqcn_param_info *hw_cc_p;
	struct sxe2_hw_cc_dcqcn_param_info hw_cc_tmp;
	u32 hw_dcqcn_rreduce_mperiod;

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
	cdev_info = rdma_dev->rdma_func->cdev;
	hw_cc_p = &rdma_dev->rdma_func->cc_params.hw_cc_params;

	if (copy_from_user(cmd, buf, count)) {
		ret = -EFAULT;
		DRV_RDMA_LOG_ERROR_BDF("cc debugfs:cmd copy from user failed err\n");
		goto end;
	}

	ret = sscanf(cmd, "%u", &hw_dcqcn_rreduce_mperiod);
	if (ret != 1) {
		ret = -ENODATA;
		DRV_RDMA_LOG_ERROR_BDF("cc debugfs:analyze cmd err please input 4096-61440\n");
		goto end;
	}
	if (hw_dcqcn_rreduce_mperiod > SXE2_HW_CC_DCQCN_RREDUCE_MPERIOD_MAX ||
		hw_dcqcn_rreduce_mperiod < SXE2_HW_CC_DCQCN_RREDUCE_MPERIOD_MIN ||
		hw_dcqcn_rreduce_mperiod < hw_cc_p->t/2 ||
		hw_dcqcn_rreduce_mperiod > hw_cc_p->t) {
		ret = -EINVAL;
		DRV_RDMA_LOG_ERROR_BDF("cc debugfs:min rreduce is %u, max rreduce is %u.\n",
					SXE2_HW_CC_DCQCN_RREDUCE_MPERIOD_MIN,
					SXE2_HW_CC_DCQCN_RREDUCE_MPERIOD_MAX);
		goto end;
	}
	hw_cc_tmp = *hw_cc_p;
	hw_cc_tmp.rdPeriod = hw_dcqcn_rreduce_mperiod;

	tmpRet = sxe2_rdma_adminq_send(cdev_info, SXE2_CMD_RDMA_SET_HW_CC_PARAM,
						(u8 *)&hw_cc_tmp, (u16)sizeof(hw_cc_tmp),
						NULL, 0);
	if (tmpRet) {
		ret = -EIO;
		DRV_RDMA_LOG_DEV_ERR(
			"debugfs cc:aq send set hw cc param err ret=%d\n", tmpRet);
		goto end;
	}
	hw_cc_p->rdPeriod = hw_dcqcn_rreduce_mperiod;
	DRV_RDMA_LOG_DEV_INFO("cc debugfs:set hw cc param success, minTh(%u), rdPeriod(%u),\n"
	"\tt(%u), bc(%u), alphaCnt(%u), rateCnt(%u), f(%u), rai(%u), rhai(%u)\n",
	hw_cc_p->minTh, hw_cc_p->rdPeriod, hw_cc_p->t, hw_cc_p->bc,
	hw_cc_p->alphaCnt, hw_cc_p->rateCnt, hw_cc_p->f, hw_cc_p->rai, hw_cc_p->rhai);

	ret  = count;
	*off = count;

end:
	return ret;
}

static ssize_t drv_rdma_cc_hw_dcqcn_rreduce_mperiod_read(struct file *filp,
					char __user *buf, size_t count, loff_t *off)
{
	ssize_t ret	  = SXE2_OK;
	u32 len_total = 0;
	char *rsp	  = NULL;
	char *rsp_end;
	struct sxe2_rdma_device *rdma_dev;
	u32 hw_dcqcn_rreduce_mperiod;

	if (*off != 0)
		goto end;
	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR(
			"cc debugfs:find dev struct from private_data failed err\n");
		goto end;
	}
	hw_dcqcn_rreduce_mperiod = rdma_dev->rdma_func->cc_params.hw_cc_params.rdPeriod;
	rsp = kzalloc(sizeof(char) * SXE2_DEBUG_DUMP_BUF_SIZE, GFP_KERNEL);
	if (!rsp) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_ERROR("cc debugfs:cc info rsp kmalloc failed err\n");
		goto end;
	}
	rsp_end = rsp;

	len_total += dbg_vsnprintf(rsp_end, len_total, "hw_dcqcn_rreduce_mperiod:%u\n",
						hw_dcqcn_rreduce_mperiod);

	ret = simple_read_from_buffer(buf, count, off, rsp, (ssize_t)len_total);
	if (ret < 0)
		DRV_RDMA_LOG_ERROR("cc debugfs:simple read error %zd\n", ret);

	kfree(rsp);
	rsp = NULL;
end:
	return ret;
}

static const struct file_operations sxe2_rdma_cc_hw_dcqcn_rreduce_mperiod_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read  = drv_rdma_cc_hw_dcqcn_rreduce_mperiod_read,
	.write = drv_rdma_cc_hw_dcqcn_rreduce_mperiod_write,
};

static ssize_t drv_rdma_cc_hw_dcqcn_T_write(struct file *filp, const char __user *buf,
									 size_t count, loff_t *off)
{
	ssize_t ret = SXE2_OK;
	int tmpRet = SXE2_OK;
	char cmd[CC_DEBUGFS_WRITE_BUF_MAX_LEN] = {0};
	struct sxe2_rdma_device *rdma_dev;
	struct aux_core_dev_info *cdev_info;
	struct sxe2_hw_cc_dcqcn_param_info *hw_cc_p;
	struct sxe2_hw_cc_dcqcn_param_info hw_cc_tmp;
	u32 hw_dcqcn_T;

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
	cdev_info = rdma_dev->rdma_func->cdev;
	hw_cc_p = &rdma_dev->rdma_func->cc_params.hw_cc_params;

	if (copy_from_user(cmd, buf, count)) {
		ret = -EFAULT;
		DRV_RDMA_LOG_ERROR_BDF("cc debugfs:cmd copy from user failed err\n");
		goto end;
	}

	ret = sscanf(cmd, "%u", &hw_dcqcn_T);
	if (ret != 1) {
		ret = -ENODATA;
		DRV_RDMA_LOG_ERROR_BDF("cc debugfs:analyze cmd err please input 8192-61440\n");
		goto end;
	}
	if (hw_dcqcn_T > SXE2_HW_CC_DCQCN_T_MAX || hw_dcqcn_T < SXE2_HW_CC_DCQCN_T_MIN ||
		hw_dcqcn_T < hw_cc_p->rdPeriod || hw_dcqcn_T > 2*(hw_cc_p->rdPeriod)) {
		ret = -EINVAL;
		DRV_RDMA_LOG_ERROR_BDF("cc debugfs:min hw_dcqcn_T is %u, max hw_dcqcn_T is %u.\n",
					SXE2_HW_CC_DCQCN_T_MIN, SXE2_HW_CC_DCQCN_T_MAX);
		goto end;
	}
	hw_cc_tmp = *hw_cc_p;
	hw_cc_tmp.t = hw_dcqcn_T;

	tmpRet = sxe2_rdma_adminq_send(cdev_info, SXE2_CMD_RDMA_SET_HW_CC_PARAM,
						(u8 *)&hw_cc_tmp, (u16)sizeof(hw_cc_tmp),
						NULL, 0);
	if (tmpRet) {
		ret = -EIO;
		DRV_RDMA_LOG_DEV_ERR(
			"debugfs cc:aq send set hw cc param err ret=%d\n", tmpRet);
		goto end;
	}
	hw_cc_p->t = hw_dcqcn_T;
	DRV_RDMA_LOG_DEV_INFO("cc debugfs:set hw cc param success, minTh(%u), rdPeriod(%u),\n"
	"\tt(%u), bc(%u), alphaCnt(%u), rateCnt(%u), f(%u), rai(%u), rhai(%u)\n",
	hw_cc_p->minTh, hw_cc_p->rdPeriod, hw_cc_p->t, hw_cc_p->bc,
	hw_cc_p->alphaCnt, hw_cc_p->rateCnt, hw_cc_p->f, hw_cc_p->rai, hw_cc_p->rhai);

	ret  = count;
	*off = count;

end:
	return ret;
}

static ssize_t drv_rdma_cc_hw_dcqcn_T_read(struct file *filp,
					char __user *buf, size_t count, loff_t *off)
{
	ssize_t ret	  = SXE2_OK;
	u32 len_total = 0;
	char *rsp	  = NULL;
	char *rsp_end;
	struct sxe2_rdma_device *rdma_dev;
	u32 hw_dcqcn_T;

	if (*off != 0)
		goto end;
	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR(
			"cc debugfs:find dev struct from private_data failed err\n");
		goto end;
	}
	hw_dcqcn_T = rdma_dev->rdma_func->cc_params.hw_cc_params.t;
	rsp = kzalloc(sizeof(char) * SXE2_DEBUG_DUMP_BUF_SIZE, GFP_KERNEL);
	if (!rsp) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_ERROR("cc debugfs:cc info rsp kmalloc failed err\n");
		goto end;
	}
	rsp_end = rsp;

	len_total += dbg_vsnprintf(rsp_end, len_total, "hw_dcqcn_T:%u\n", hw_dcqcn_T);

	ret = simple_read_from_buffer(buf, count, off, rsp, (ssize_t)len_total);
	if (ret < 0)
		DRV_RDMA_LOG_ERROR("cc debugfs:simple read error %zd\n", ret);

	kfree(rsp);
	rsp = NULL;
end:
	return ret;
}

static const struct file_operations sxe2_rdma_cc_hw_dcqcn_T_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read  = drv_rdma_cc_hw_dcqcn_T_read,
	.write = drv_rdma_cc_hw_dcqcn_T_write,
};

static ssize_t drv_rdma_cc_hw_dcqcn_B_write(struct file *filp, const char __user *buf,
									 size_t count, loff_t *off)
{
	ssize_t ret = SXE2_OK;
	int tmpRet = SXE2_OK;
	char cmd[CC_DEBUGFS_WRITE_BUF_MAX_LEN] = {0};
	struct sxe2_rdma_device *rdma_dev;
	struct aux_core_dev_info *cdev_info;
	struct sxe2_hw_cc_dcqcn_param_info *hw_cc_p;
	struct sxe2_hw_cc_dcqcn_param_info hw_cc_tmp;
	u32 hw_dcqcn_B;

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
	cdev_info = rdma_dev->rdma_func->cdev;
	hw_cc_p = &rdma_dev->rdma_func->cc_params.hw_cc_params;

	if (copy_from_user(cmd, buf, count)) {
		ret = -EFAULT;
		DRV_RDMA_LOG_ERROR_BDF("cc debugfs:cmd copy from user failed err\n");
		goto end;
	}

	ret = sscanf(cmd, "%u", &hw_dcqcn_B);
	if (ret != 1) {
		ret = -ENODATA;
		DRV_RDMA_LOG_ERROR_BDF("cc debugfs:analyze cmd err please input 0-7\n");
		goto end;
	}
	if (hw_dcqcn_B > SXE2_HW_CC_DCQCN_B_MAX) {
		ret = -EINVAL;
		DRV_RDMA_LOG_ERROR_BDF("cc debugfs:min hw_dcqcn_B is %u, max hw_dcqcn_B is %u.\n",
					SXE2_HW_CC_DCQCN_B_MIN, SXE2_HW_CC_DCQCN_B_MAX);
		goto end;
	}
	hw_cc_tmp = *hw_cc_p;
	hw_cc_tmp.bc = hw_dcqcn_B;

	tmpRet = sxe2_rdma_adminq_send(cdev_info, SXE2_CMD_RDMA_SET_HW_CC_PARAM,
						(u8 *)&hw_cc_tmp, (u16)sizeof(hw_cc_tmp),
						NULL, 0);
	if (tmpRet) {
		ret = -EIO;
		DRV_RDMA_LOG_DEV_ERR(
			"debugfs cc:aq send set hw cc param err ret=%d\n", tmpRet);
		goto end;
	}
	hw_cc_p->bc = hw_dcqcn_B;
	DRV_RDMA_LOG_DEV_INFO("cc debugfs:set hw cc param success, minTh(%u), rdPeriod(%u),\n"
	"\tt(%u), bc(%u), alphaCnt(%u), rateCnt(%u), f(%u), rai(%u), rhai(%u)\n",
	hw_cc_p->minTh, hw_cc_p->rdPeriod, hw_cc_p->t, hw_cc_p->bc,
	hw_cc_p->alphaCnt, hw_cc_p->rateCnt, hw_cc_p->f, hw_cc_p->rai, hw_cc_p->rhai);

	ret  = count;
	*off = count;

end:
	return ret;
}

static ssize_t drv_rdma_cc_hw_dcqcn_B_read(struct file *filp,
					char __user *buf, size_t count, loff_t *off)
{
	ssize_t ret	  = SXE2_OK;
	u32 len_total = 0;
	char *rsp	  = NULL;
	char *rsp_end;
	struct sxe2_rdma_device *rdma_dev;
	u32 hw_dcqcn_B;

	if (*off != 0)
		goto end;
	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR(
			"cc debugfs:find dev struct from private_data failed err\n");
		goto end;
	}
	hw_dcqcn_B = rdma_dev->rdma_func->cc_params.hw_cc_params.bc;
	rsp = kzalloc(sizeof(char) * SXE2_DEBUG_DUMP_BUF_SIZE, GFP_KERNEL);
	if (!rsp) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_ERROR("cc debugfs:cc info rsp kmalloc failed err\n");
		goto end;
	}
	rsp_end = rsp;

	len_total += dbg_vsnprintf(rsp_end, len_total, "hw_dcqcn_B:%u\n", hw_dcqcn_B);

	ret = simple_read_from_buffer(buf, count, off, rsp, (ssize_t)len_total);
	if (ret < 0)
		DRV_RDMA_LOG_ERROR("cc debugfs:simple read error %zd\n", ret);

	kfree(rsp);
	rsp = NULL;
end:
	return ret;
}

static const struct file_operations sxe2_rdma_cc_hw_dcqcn_B_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read  = drv_rdma_cc_hw_dcqcn_B_read,
	.write = drv_rdma_cc_hw_dcqcn_B_write,
};

static ssize_t drv_rdma_cc_hw_dcqcn_alpha_cnt_write(struct file *filp, const char __user *buf,
									 size_t count, loff_t *off)
{
	ssize_t ret = SXE2_OK;
	int tmpRet = SXE2_OK;
	char cmd[CC_DEBUGFS_WRITE_BUF_MAX_LEN] = {0};
	struct sxe2_rdma_device *rdma_dev;
	struct aux_core_dev_info *cdev_info;
	struct sxe2_hw_cc_dcqcn_param_info *hw_cc_p;
	struct sxe2_hw_cc_dcqcn_param_info hw_cc_tmp;
	u32 hw_dcqcn_alpha_cnt;

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
	cdev_info = rdma_dev->rdma_func->cdev;
	hw_cc_p = &rdma_dev->rdma_func->cc_params.hw_cc_params;

	if (copy_from_user(cmd, buf, count)) {
		ret = -EFAULT;
		DRV_RDMA_LOG_ERROR_BDF("cc debugfs:cmd copy from user failed err\n");
		goto end;
	}

	ret = sscanf(cmd, "%u", &hw_dcqcn_alpha_cnt);
	if (ret != 1) {
		ret = -ENODATA;
		DRV_RDMA_LOG_ERROR_BDF("cc debugfs:analyze cmd err please input 0-1023\n");
		goto end;
	}
	if (hw_dcqcn_alpha_cnt > SXE2_HW_CC_DCQCN_ALPHA_CNT_MAX) {
		ret = -EINVAL;
		DRV_RDMA_LOG_ERROR_BDF("cc debugfs:min alpha_cnt is %u, max alpha_cnt is %u.\n",
				SXE2_HW_CC_DCQCN_ALPHA_CNT_MIN, SXE2_HW_CC_DCQCN_ALPHA_CNT_MAX);
		goto end;
	}
	hw_cc_tmp = *hw_cc_p;
	hw_cc_tmp.alphaCnt = hw_dcqcn_alpha_cnt;

	tmpRet = sxe2_rdma_adminq_send(cdev_info, SXE2_CMD_RDMA_SET_HW_CC_PARAM,
						(u8 *)&hw_cc_tmp, (u16)sizeof(hw_cc_tmp),
						NULL, 0);
	if (tmpRet) {
		ret = -EIO;
		DRV_RDMA_LOG_DEV_ERR(
			"debugfs cc:aq send set hw cc param err ret=%d\n", tmpRet);
		goto end;
	}
	hw_cc_p->alphaCnt = hw_dcqcn_alpha_cnt;
	DRV_RDMA_LOG_DEV_INFO("cc debugfs:set hw cc param success, minTh(%u), rdPeriod(%u),\n"
	"\tt(%u), bc(%u), alphaCnt(%u), rateCnt(%u), f(%u), rai(%u), rhai(%u)\n",
	hw_cc_p->minTh, hw_cc_p->rdPeriod, hw_cc_p->t, hw_cc_p->bc,
	hw_cc_p->alphaCnt, hw_cc_p->rateCnt, hw_cc_p->f, hw_cc_p->rai, hw_cc_p->rhai);

	ret  = count;
	*off = count;

end:
	return ret;
}

static ssize_t drv_rdma_cc_hw_dcqcn_alpha_cnt_read(struct file *filp,
				char __user *buf, size_t count, loff_t *off)
{
	ssize_t ret	  = SXE2_OK;
	u32 len_total = 0;
	char *rsp	  = NULL;
	char *rsp_end;
	struct sxe2_rdma_device *rdma_dev;
	u32 hw_dcqcn_alpha_cnt;

	if (*off != 0)
		goto end;
	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR(
			"cc debugfs:find dev struct from private_data failed err\n");
		goto end;
	}
	hw_dcqcn_alpha_cnt = rdma_dev->rdma_func->cc_params.hw_cc_params.alphaCnt;
	rsp = kzalloc(sizeof(char) * SXE2_DEBUG_DUMP_BUF_SIZE, GFP_KERNEL);
	if (!rsp) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_ERROR("cc debugfs:cc info rsp kmalloc failed err\n");
		goto end;
	}
	rsp_end = rsp;

	len_total += dbg_vsnprintf(rsp_end, len_total, "hw_dcqcn_alpha_cnt:%u\n",
						hw_dcqcn_alpha_cnt);

	ret = simple_read_from_buffer(buf, count, off, rsp, (ssize_t)len_total);
	if (ret < 0)
		DRV_RDMA_LOG_ERROR("cc debugfs:simple read error %zd\n", ret);

	kfree(rsp);
	rsp = NULL;
end:
	return ret;
}

static const struct file_operations sxe2_rdma_cc_hw_dcqcn_alpha_cnt_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read  = drv_rdma_cc_hw_dcqcn_alpha_cnt_read,
	.write = drv_rdma_cc_hw_dcqcn_alpha_cnt_write,
};

static ssize_t drv_rdma_cc_hw_dcqcn_rate_cnt_write(struct file *filp, const char __user *buf,
									 size_t count, loff_t *off)
{
	ssize_t ret = SXE2_OK;
	int tmpRet = SXE2_OK;
	char cmd[CC_DEBUGFS_WRITE_BUF_MAX_LEN] = {0};
	struct sxe2_rdma_device *rdma_dev;
	struct aux_core_dev_info *cdev_info;
	struct sxe2_hw_cc_dcqcn_param_info *hw_cc_p;
	struct sxe2_hw_cc_dcqcn_param_info hw_cc_tmp;
	u32 hw_dcqcn_rate_cnt;

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
	cdev_info = rdma_dev->rdma_func->cdev;
	hw_cc_p = &rdma_dev->rdma_func->cc_params.hw_cc_params;

	if (copy_from_user(cmd, buf, count)) {
		ret = -EFAULT;
		DRV_RDMA_LOG_ERROR_BDF("cc debugfs:cmd copy from user failed err\n");
		goto end;
	}

	ret = sscanf(cmd, "%u", &hw_dcqcn_rate_cnt);
	if (ret != 1) {
		ret = -ENODATA;
		DRV_RDMA_LOG_ERROR_BDF("cc debugfs:analyze cmd err please input 0-1023\n");
		goto end;
	}
	if (hw_dcqcn_rate_cnt > SXE2_HW_CC_DCQCN_RATE_CNT_MAX) {
		ret = -EINVAL;
		DRV_RDMA_LOG_ERROR_BDF("cc debugfs:min rate_cnt is %u, max rate_cnt is %u.\n",
				SXE2_HW_CC_DCQCN_RATE_CNT_MIN, SXE2_HW_CC_DCQCN_RATE_CNT_MAX);
		goto end;
	}
	hw_cc_tmp = *hw_cc_p;
	hw_cc_tmp.rateCnt = hw_dcqcn_rate_cnt;

	tmpRet = sxe2_rdma_adminq_send(cdev_info, SXE2_CMD_RDMA_SET_HW_CC_PARAM,
						(u8 *)&hw_cc_tmp, (u16)sizeof(hw_cc_tmp),
						NULL, 0);
	if (tmpRet) {
		ret = -EIO;
		DRV_RDMA_LOG_DEV_ERR(
			"debugfs cc:aq send set hw cc param err ret=%d\n", tmpRet);
		goto end;
	}
	hw_cc_p->rateCnt = hw_dcqcn_rate_cnt;
	DRV_RDMA_LOG_DEV_INFO("cc debugfs:set hw cc param success, minTh(%u), rdPeriod(%u),\n"
	"\tt(%u), bc(%u), alphaCnt(%u), rateCnt(%u), f(%u), rai(%u), rhai(%u)\n",
	hw_cc_p->minTh, hw_cc_p->rdPeriod, hw_cc_p->t, hw_cc_p->bc,
	hw_cc_p->alphaCnt, hw_cc_p->rateCnt, hw_cc_p->f, hw_cc_p->rai, hw_cc_p->rhai);

	ret  = count;
	*off = count;

end:
	return ret;
}

static ssize_t drv_rdma_cc_hw_dcqcn_rate_cnt_read(struct file *filp,
					char __user *buf, size_t count, loff_t *off)
{
	ssize_t ret	  = SXE2_OK;
	u32 len_total = 0;
	char *rsp	  = NULL;
	char *rsp_end;
	struct sxe2_rdma_device *rdma_dev;
	u32 hw_dcqcn_rate_cnt;

	if (*off != 0)
		goto end;
	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR(
			"cc debugfs:find dev struct from private_data failed err\n");
		goto end;
	}
	hw_dcqcn_rate_cnt = rdma_dev->rdma_func->cc_params.hw_cc_params.rateCnt;
	rsp = kzalloc(sizeof(char) * SXE2_DEBUG_DUMP_BUF_SIZE, GFP_KERNEL);
	if (!rsp) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_ERROR("cc debugfs:cc info rsp kmalloc failed err\n");
		goto end;
	}
	rsp_end = rsp;

	len_total += dbg_vsnprintf(rsp_end, len_total, "hw_dcqcn_rate_cnt:%u\n", hw_dcqcn_rate_cnt);

	ret = simple_read_from_buffer(buf, count, off, rsp, (ssize_t)len_total);
	if (ret < 0)
		DRV_RDMA_LOG_ERROR("cc debugfs:simple read error %zd\n", ret);

	kfree(rsp);
	rsp = NULL;
end:
	return ret;
}

static const struct file_operations sxe2_rdma_cc_hw_dcqcn_rate_cnt_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read  = drv_rdma_cc_hw_dcqcn_rate_cnt_read,
	.write = drv_rdma_cc_hw_dcqcn_rate_cnt_write,
};

static ssize_t drv_rdma_cc_hw_dcqcn_F_write(struct file *filp, const char __user *buf,
									 size_t count, loff_t *off)
{
	ssize_t ret = SXE2_OK;
	int tmpRet = SXE2_OK;
	char cmd[CC_DEBUGFS_WRITE_BUF_MAX_LEN] = {0};
	struct sxe2_rdma_device *rdma_dev;
	struct aux_core_dev_info *cdev_info;
	struct sxe2_hw_cc_dcqcn_param_info *hw_cc_p;
	struct sxe2_hw_cc_dcqcn_param_info hw_cc_tmp;
	u32 hw_dcqcn_F;

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
	cdev_info = rdma_dev->rdma_func->cdev;
	hw_cc_p = &rdma_dev->rdma_func->cc_params.hw_cc_params;

	if (copy_from_user(cmd, buf, count)) {
		ret = -EFAULT;
		DRV_RDMA_LOG_ERROR_BDF("cc debugfs:cmd copy from user failed err\n");
		goto end;
	}

	ret = sscanf(cmd, "%u", &hw_dcqcn_F);
	if (ret != 1) {
		ret = -ENODATA;
		DRV_RDMA_LOG_ERROR_BDF("cc debugfs:analyze cmd err please input 0-7\n");
		goto end;
	}
	if (hw_dcqcn_F > SXE2_HW_CC_DCQCN_F_MAX) {
		ret = -EINVAL;
		DRV_RDMA_LOG_ERROR_BDF("cc debugfs:min hw_dcqcn_F is %u, max hw_dcqcn_F is %u.\n",
					SXE2_HW_CC_DCQCN_F_MIN, SXE2_HW_CC_DCQCN_F_MAX);
		goto end;
	}
	hw_cc_tmp = *hw_cc_p;
	hw_cc_tmp.f = hw_dcqcn_F;

	tmpRet = sxe2_rdma_adminq_send(cdev_info, SXE2_CMD_RDMA_SET_HW_CC_PARAM,
						(u8 *)&hw_cc_tmp, (u16)sizeof(hw_cc_tmp),
						NULL, 0);
	if (tmpRet) {
		ret = -EIO;
		DRV_RDMA_LOG_DEV_ERR(
			"debugfs cc:aq send set hw cc param err ret=%d\n", tmpRet);
		goto end;
	}
	hw_cc_p->f = hw_dcqcn_F;
	DRV_RDMA_LOG_DEV_INFO("cc debugfs:set hw cc param success, minTh(%u), rdPeriod(%u),\n"
	"\tt(%u), bc(%u), alphaCnt(%u), rateCnt(%u), f(%u), rai(%u), rhai(%u)\n",
	hw_cc_p->minTh, hw_cc_p->rdPeriod, hw_cc_p->t, hw_cc_p->bc,
	hw_cc_p->alphaCnt, hw_cc_p->rateCnt, hw_cc_p->f, hw_cc_p->rai, hw_cc_p->rhai);

	ret  = count;
	*off = count;

end:
	return ret;
}

static ssize_t drv_rdma_cc_hw_dcqcn_F_read(struct file *filp,
					char __user *buf, size_t count, loff_t *off)
{
	ssize_t ret	  = SXE2_OK;
	u32 len_total = 0;
	char *rsp	  = NULL;
	char *rsp_end;
	struct sxe2_rdma_device *rdma_dev;
	u32 hw_dcqcn_F;

	if (*off != 0)
		goto end;
	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR(
			"cc debugfs:find dev struct from private_data failed err\n");
		goto end;
	}
	hw_dcqcn_F = rdma_dev->rdma_func->cc_params.hw_cc_params.f;
	rsp = kzalloc(sizeof(char) * SXE2_DEBUG_DUMP_BUF_SIZE, GFP_KERNEL);
	if (!rsp) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_ERROR("cc debugfs:cc info rsp kmalloc failed err\n");
		goto end;
	}
	rsp_end = rsp;

	len_total += dbg_vsnprintf(rsp_end, len_total, "hw_dcqcn_F:%u\n", hw_dcqcn_F);

	ret = simple_read_from_buffer(buf, count, off, rsp, (ssize_t)len_total);
	if (ret < 0)
		DRV_RDMA_LOG_ERROR("cc debugfs:simple read error %zd\n", ret);

	kfree(rsp);
	rsp = NULL;
end:
	return ret;
}

static const struct file_operations sxe2_rdma_cc_hw_dcqcn_F_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read  = drv_rdma_cc_hw_dcqcn_F_read,
	.write = drv_rdma_cc_hw_dcqcn_F_write,
};

static ssize_t drv_rdma_cc_hw_dcqcn_rai_factor_write(struct file *filp, const char __user *buf,
									 size_t count, loff_t *off)
{
	ssize_t ret = SXE2_OK;
	int tmpRet = SXE2_OK;
	char cmd[CC_DEBUGFS_WRITE_BUF_MAX_LEN] = {0};
	struct sxe2_rdma_device *rdma_dev;
	struct aux_core_dev_info *cdev_info;
	struct sxe2_hw_cc_dcqcn_param_info *hw_cc_p;
	struct sxe2_hw_cc_dcqcn_param_info hw_cc_tmp;
	u32 hw_dcqcn_rai_factor;

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
	cdev_info = rdma_dev->rdma_func->cdev;
	hw_cc_p = &rdma_dev->rdma_func->cc_params.hw_cc_params;

	if (copy_from_user(cmd, buf, count)) {
		ret = -EFAULT;
		DRV_RDMA_LOG_ERROR_BDF("cc debugfs:cmd copy from user failed err\n");
		goto end;
	}

	ret = sscanf(cmd, "%u", &hw_dcqcn_rai_factor);
	if (ret != 1) {
		ret = -ENODATA;
		DRV_RDMA_LOG_ERROR_BDF("cc debugfs:analyze cmd err please input 1-14\n");
		goto end;
	}
	if (hw_dcqcn_rai_factor > SXE2_HW_CC_DCQCN_RAI_MAX ||
		hw_dcqcn_rai_factor < SXE2_HW_CC_DCQCN_RAI_MIN ||
		hw_dcqcn_rai_factor >= hw_cc_p->rhai) {
		ret = -EINVAL;
		DRV_RDMA_LOG_ERROR_BDF("cc debugfs:min rai is %u, max rai is %u.\n",
					SXE2_HW_CC_DCQCN_RAI_MIN, SXE2_HW_CC_DCQCN_RAI_MAX);
		goto end;
	}
	hw_cc_tmp = *hw_cc_p;
	hw_cc_tmp.rai = hw_dcqcn_rai_factor;

	tmpRet = sxe2_rdma_adminq_send(cdev_info, SXE2_CMD_RDMA_SET_HW_CC_PARAM,
						(u8 *)&hw_cc_tmp, (u16)sizeof(hw_cc_tmp),
						NULL, 0);
	if (tmpRet) {
		ret = -EIO;
		DRV_RDMA_LOG_DEV_ERR(
			"debugfs cc:aq send set hw cc param err ret=%d\n", tmpRet);
		goto end;
	}
	hw_cc_p->rai = hw_dcqcn_rai_factor;
	DRV_RDMA_LOG_DEV_INFO("cc debugfs:set hw cc param success, minTh(%u), rdPeriod(%u),\n"
	"\tt(%u), bc(%u), alphaCnt(%u), rateCnt(%u), f(%u), rai(%u), rhai(%u)\n",
	hw_cc_p->minTh, hw_cc_p->rdPeriod, hw_cc_p->t, hw_cc_p->bc,
	hw_cc_p->alphaCnt, hw_cc_p->rateCnt, hw_cc_p->f, hw_cc_p->rai, hw_cc_p->rhai);

	ret  = count;
	*off = count;

end:
	return ret;
}

static ssize_t drv_rdma_cc_hw_dcqcn_rai_factor_read(struct file *filp,
					char __user *buf, size_t count, loff_t *off)
{
	ssize_t ret	  = SXE2_OK;
	u32 len_total = 0;
	char *rsp	  = NULL;
	char *rsp_end;
	struct sxe2_rdma_device *rdma_dev;
	u32 hw_dcqcn_rai_factor;

	if (*off != 0)
		goto end;
	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR(
			"cc debugfs:find dev struct from private_data failed err\n");
		goto end;
	}
	hw_dcqcn_rai_factor = rdma_dev->rdma_func->cc_params.hw_cc_params.rai;
	rsp = kzalloc(sizeof(char) * SXE2_DEBUG_DUMP_BUF_SIZE, GFP_KERNEL);
	if (!rsp) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_ERROR("cc debugfs:cc info rsp kmalloc failed err\n");
		goto end;
	}
	rsp_end = rsp;

	len_total += dbg_vsnprintf(rsp_end, len_total, "hw_dcqcn_rai_factor:%u\n",
						hw_dcqcn_rai_factor);

	ret = simple_read_from_buffer(buf, count, off, rsp, (ssize_t)len_total);
	if (ret < 0)
		DRV_RDMA_LOG_ERROR("cc debugfs:simple read error %zd\n", ret);

	kfree(rsp);
	rsp = NULL;
end:
	return ret;
}

static const struct file_operations sxe2_rdma_cc_hw_dcqcn_rai_factor_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read  = drv_rdma_cc_hw_dcqcn_rai_factor_read,
	.write = drv_rdma_cc_hw_dcqcn_rai_factor_write,
};

static ssize_t drv_rdma_cc_hw_dcqcn_rhai_factor_write(struct file *filp, const char __user *buf,
									 size_t count, loff_t *off)
{
	ssize_t ret = SXE2_OK;
	int tmpRet = SXE2_OK;
	char cmd[CC_DEBUGFS_WRITE_BUF_MAX_LEN] = {0};
	struct sxe2_rdma_device *rdma_dev;
	struct aux_core_dev_info *cdev_info;
	struct sxe2_hw_cc_dcqcn_param_info *hw_cc_p;
	struct sxe2_hw_cc_dcqcn_param_info hw_cc_tmp;
	u32 hw_dcqcn_rhai_factor;

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
	cdev_info = rdma_dev->rdma_func->cdev;
	hw_cc_p = &rdma_dev->rdma_func->cc_params.hw_cc_params;

	if (copy_from_user(cmd, buf, count)) {
		ret = -EFAULT;
		DRV_RDMA_LOG_ERROR_BDF("cc debugfs:cmd copy from user failed err\n");
		goto end;
	}

	ret = sscanf(cmd, "%u", &hw_dcqcn_rhai_factor);
	if (ret != 1) {
		ret = -ENODATA;
		DRV_RDMA_LOG_ERROR_BDF("cc debugfs:analyze cmd err please input 2-15\n");
		goto end;
	}
	if (hw_dcqcn_rhai_factor > SXE2_HW_CC_DCQCN_RHAI_MAX ||
		hw_dcqcn_rhai_factor < SXE2_HW_CC_DCQCN_RHAI_MIN ||
		hw_dcqcn_rhai_factor <= hw_cc_p->rai) {
		ret = -EINVAL;
		DRV_RDMA_LOG_ERROR_BDF("cc debugfs:min rhai is %u, max rhai is %u.\n",
					SXE2_HW_CC_DCQCN_RHAI_MIN, SXE2_HW_CC_DCQCN_RHAI_MAX);
		goto end;
	}
	hw_cc_tmp = *hw_cc_p;
	hw_cc_tmp.rhai = hw_dcqcn_rhai_factor;

	tmpRet = sxe2_rdma_adminq_send(cdev_info, SXE2_CMD_RDMA_SET_HW_CC_PARAM,
						(u8 *)&hw_cc_tmp, (u16)sizeof(hw_cc_tmp),
						NULL, 0);
	if (tmpRet) {
		ret = -EIO;
		DRV_RDMA_LOG_DEV_ERR(
			"debugfs cc:aq send set hw cc param err ret=%d\n", tmpRet);
		goto end;
	}
	hw_cc_p->rhai = hw_dcqcn_rhai_factor;
	DRV_RDMA_LOG_DEV_INFO("cc debugfs:set hw cc param success, minTh(%u), rdPeriod(%u),\n"
	"\tt(%u), bc(%u), alphaCnt(%u), rateCnt(%u), f(%u), rai(%u), rhai(%u)\n",
	hw_cc_p->minTh, hw_cc_p->rdPeriod, hw_cc_p->t, hw_cc_p->bc,
	hw_cc_p->alphaCnt, hw_cc_p->rateCnt, hw_cc_p->f, hw_cc_p->rai, hw_cc_p->rhai);

	ret  = count;
	*off = count;

end:
	return ret;
}

static ssize_t drv_rdma_cc_hw_dcqcn_rhai_factor_read(struct file *filp,
								char __user *buf,
								size_t count, loff_t *off)
{
	ssize_t ret	  = SXE2_OK;
	u32 len_total = 0;
	char *rsp	  = NULL;
	char *rsp_end;
	struct sxe2_rdma_device *rdma_dev;
	u32 hw_dcqcn_rhai_factor;

	if (*off != 0)
		goto end;
	rdma_dev = (struct sxe2_rdma_device *)filp->private_data;
	if (!rdma_dev) {
		ret = -ENXIO;
		DRV_RDMA_LOG_ERROR(
			"cc debugfs:find dev struct from private_data failed err\n");
		goto end;
	}
	hw_dcqcn_rhai_factor = rdma_dev->rdma_func->cc_params.hw_cc_params.rhai;
	rsp = kzalloc(sizeof(char) * SXE2_DEBUG_DUMP_BUF_SIZE, GFP_KERNEL);
	if (!rsp) {
		ret = -ENOMEM;
		DRV_RDMA_LOG_ERROR("cc debugfs:cc info rsp kmalloc failed err\n");
		goto end;
	}
	rsp_end = rsp;

	len_total += dbg_vsnprintf(rsp_end, len_total, "hw_dcqcn_rhai_factor:%u\n",
						hw_dcqcn_rhai_factor);

	ret = simple_read_from_buffer(buf, count, off, rsp, (ssize_t)len_total);
	if (ret < 0)
		DRV_RDMA_LOG_ERROR("cc debugfs:simple read error %zd\n", ret);

	kfree(rsp);
	rsp = NULL;
end:
	return ret;
}

static const struct file_operations sxe2_rdma_cc_hw_dcqcn_rhai_factor_fops = {
	.owner = THIS_MODULE,
	.open  = simple_open,
	.read  = drv_rdma_cc_hw_dcqcn_rhai_factor_read,
	.write = drv_rdma_cc_hw_dcqcn_rhai_factor_write,
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
				rdma_dev->hdl->cc_debugfs, rdma_dev,
				&sxe2_rdma_cc_qp_dfx_fops);
	debugfs_create_file("hw_dcqcn_min_rate", SXE2_DEBUG_FILE_READ_WRITE,
				rdma_dev->hdl->cc_debugfs, rdma_dev,
				&sxe2_rdma_cc_hw_dcqcn_min_rate_fops);
	debugfs_create_file("hw_dcqcn_rreduce_mperiod", SXE2_DEBUG_FILE_READ_WRITE,
				rdma_dev->hdl->cc_debugfs, rdma_dev,
				&sxe2_rdma_cc_hw_dcqcn_rreduce_mperiod_fops);
	debugfs_create_file("hw_dcqcn_T", SXE2_DEBUG_FILE_READ_WRITE,
				rdma_dev->hdl->cc_debugfs, rdma_dev,
				&sxe2_rdma_cc_hw_dcqcn_T_fops);
	debugfs_create_file("hw_dcqcn_B", SXE2_DEBUG_FILE_READ_WRITE,
				rdma_dev->hdl->cc_debugfs, rdma_dev,
				&sxe2_rdma_cc_hw_dcqcn_B_fops);
	debugfs_create_file("hw_dcqcn_alpha_cnt", SXE2_DEBUG_FILE_READ_WRITE,
				rdma_dev->hdl->cc_debugfs, rdma_dev,
				&sxe2_rdma_cc_hw_dcqcn_alpha_cnt_fops);
	debugfs_create_file("hw_dcqcn_rate_cnt", SXE2_DEBUG_FILE_READ_WRITE,
				rdma_dev->hdl->cc_debugfs, rdma_dev,
				&sxe2_rdma_cc_hw_dcqcn_rate_cnt_fops);
	debugfs_create_file("hw_dcqcn_F", SXE2_DEBUG_FILE_READ_WRITE,
				rdma_dev->hdl->cc_debugfs, rdma_dev,
				&sxe2_rdma_cc_hw_dcqcn_F_fops);
	debugfs_create_file("hw_dcqcn_rai_factor", SXE2_DEBUG_FILE_READ_WRITE,
				rdma_dev->hdl->cc_debugfs, rdma_dev,
				&sxe2_rdma_cc_hw_dcqcn_rai_factor_fops);
	debugfs_create_file("hw_dcqcn_rhai_factor", SXE2_DEBUG_FILE_READ_WRITE,
				rdma_dev->hdl->cc_debugfs, rdma_dev,
				&sxe2_rdma_cc_hw_dcqcn_rhai_factor_fops);

end:
	return ret;
}

