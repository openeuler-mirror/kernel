// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2022, nebula-matrix Limited */

#include <linux/debugfs.h>

#include "cqp.h"
#include "qp.h"
#include "grc.h"
#include "main.h"
#include "dbgfs.h"

#define NBL_CFG_CC_ENABLE_MASK			0x1
#define NBL_CFG_CC_TC_MASK				0x7
#define NBL_CFG_CC_OAM_BLK_TH_MASK		0xFF
#define NBL_CFG_CC_WIN_MASK				0xFFFFF
#define NBL_CFG_CC_MODE_MASK			0x3
#define NBL_CFG_CC_RTTMINTH_COE_FRACTION_MASK	0xF
#define NBL_CFG_CC_RTTMINTH_COE_INT_MASK	0x4
#define NBL_CFG_CC_TARWINTH_MASK		0xFFFFF
#define NBL_CFG_QCN_MID_SENDBLK_MASK	0xFFF
#define NBL_CFG_QCN_MID_SENDTIME_MASK	0xFFFF
#define NBL_CFG_QCN_RR_TH_MASK			0xF
#define NBL_CFG_QCN_AI_RP_MASK			0x3F
#define NBL_CFG_QCN_HAI_RP_MASK			0xFF
#define NBL_CFG_QCN_RATE_RP_MASK		0x3FFFF
#define NBL_CFG_QCN_SEND_CNP_TIME_MASK	0xFFF
#define NBL_CFG_QCN_MODE_MASK			0x3
#define NBL_CFG_RTT_OFFSET_MASK			0x3FF
#define NBL_CFG_RTT_PROBE_INVL_MASK		0xFF
#define NBL_CFG_HIGH_PRI_RTT_INVL_MASK	0xFF
#define NBL_CFG_RST_WIN_MASK			0xFFFFF
#define NBL_CFG_TXP_SENDREQ_DB_CFG_MASK 0xFFFF
#define NBL_CFG_DCQCN_START_RATE_MASK	100000 /* 100000 Mbps */

#define NBL_RDMA_CC_CFG_DEFAULT_DENTRY "/etc/nebulamatrix/rdma/cc_params/."
#define NBL_RDMA_QCN_CFG_DEFAULT_DENTRY "/etc/nebulamatrix/rdma/qcn_params/."

enum nbl_ib_dbg_cc_cfg_type {
	NBL_CC_QPC = 1,
	NBL_CC_REG = 2,
	NBL_CC_OTHER = 3,
};

static const char *const nbl_dbg_cc_name[] = {
	/* global */
	"cc_mode",
	"cc_en",
	/* nbl-cc */
	"save",
	"cc_oamreq_tc_en",
	"cc_oamreq_net_tc",
	"cc_oamack_tc_en",
	"cc_oamack_net_tc",
	"cc_oamack_blk_th",
	"cc_targetwin_min",
	"cc_pkt_num_en",
	"cc_high_rtt_fraction",
	"cc_low_rtt_fraction",
	"cc_inc_tarwinth",
	"cc_dec_tarwinth",
	"cc_targetwin",
	"cc_rtt_offset", /* 0x0110 cc_ai_rttminth */
	"cc_rtt_probe_invl", /* 0x011c cc_rttmid_oamack_cnt_th */
	"cc_high_pri_rtt_invl", /* 0x0120 cc_high_priorrtt_midcnt_th */
	"cc_high_pri_rtt_en", /* 0x0124 cc_high_priorrtt_en */
	"cc_rst_win_high", /* 0x0128 cc_rst_targetwin_high */
	"cc_rst_win_en", /* 0x012c cc_rst_targetwin_en */
	"cc_rst_win_low", /* 0x0130 cc_rst_targetwin_low */
	"cc_rst_win_rtt_int", /* 0x0134 cc_rst_targetwin_rttcoe */
	"cc_rst_win_rtt_fraction", /* 0x0134 cc_rst_targetwin_rttcoe */
	"cc_dyn_rtt_offset_en", /* 0x0138 cc_dynamic_airttminth_en */
	"cc_remove_remote_time", /* 0x013c cc_remove_rmt_handlertt_en */
	"cc_high_rtt_int",
	"cc_low_rtt_int",
	"cc_rdma_time_sel",
	"cc_cmp_rtt_qp_mult",
	"cc_low_rtt_offset",
	"cc_high_rtt_offset",
	"cc_rst_win_rtt_offset",
	"cc_txp_sendreq_db_cfg",

	/* nbl-qcn */
	"save",
	"qcn_rr_mode",
	"qcn_mid_sendblk_th_high",
	"qcn_mid_sendblk_th_low",
	"qcn_mid_sendtime_th_high",
	"qcn_mid_sendtime_th_low",
	"qcn_rr_th",
	"qcn_ai_rp",
	"qcn_hai_rp",
	"qcn_min_rate_rp",
	"qcn_max_rate_rp",
	"qcn_quick_start_flag",
	"qcn_sendcnp_flag",
	"qcn_sendcnp_time_th",
	"qcn_start_rate",
	"qcn_extra_quanta",
	"qcn_fast_reduce_mode",
	"qcn_reduce_coe",
};

static enum nbl_ib_dbg_cc_cfg_type
nbl_ib_param_to_cfg_type(enum nbl_ib_dbg_cc_param_types param_offset)
{
	switch (param_offset) {
	case NBL_CFG_CC_MODE:
	case NBL_CFG_CC_OAMREQ_TC_EN:
	case NBL_CFG_CC_OAMREQ_NET_TC:
	case NBL_CFG_CC_OAMACK_TC_EN:
	case NBL_CFG_CC_OAMACK_NET_TC:
	case NBL_CFG_CC_OAMACK_BLK_TH:
	case NBL_CFG_CC_TARGETWIN_MIN:
	case NBL_CFG_CC_TARGETWIN:
	case NBL_CFG_CC_PKT_NUM_EN:
	case NBL_CFG_CC_CMP_RTT_QP_MULT:
	case NBL_CFG_QCN_START_RATE:
		return NBL_CC_QPC;
	case NBL_CFG_CC_EN:
	case NBL_CFG_CC_HIGH_RTT_FRACTION:
	case NBL_CFG_CC_LOW_RTT_FRACTION:
	case NBL_CFG_CC_INC_TARWINTH:
	case NBL_CFG_CC_DEC_TARWINTH:
	case NBL_CFG_CC_TXP_SENDREQ_DB_CFG:
	case NBL_CFG_QCN_RR_MODE:
	case NBL_CFG_QCN_MID_SENDBLK_TH_HIGH:
	case NBL_CFG_QCN_MID_SENDBLK_TH_LOW:
	case NBL_CFG_QCN_MID_SENDTIME_TH_HIGH:
	case NBL_CFG_QCN_MID_SENDTIME_TH_LOW:
	case NBL_CFG_QCN_RR_TH:
	case NBL_CFG_QCN_AI_RP:
	case NBL_CFG_QCN_HAI_RP:
	case NBL_CFG_QCN_MIN_RATE_RP:
	case NBL_CFG_QCN_MAX_RATE_RP:
	case NBL_CFG_QCN_QUICK_START_FLAG:
	case NBL_CFG_QCN_SENDCNP_FLAG:
	case NBL_CFG_QCN_SENDCNP_TIME_TH:
	case NBL_CFG_QCN_EXTRA_QUANTA:
	case NBL_CFG_QCN_FAST_REDUCE_MODE:
	case NBL_CFG_QCN_REDUCE_COE:
	case NBL_CFG_CC_RTT_OFFSET:
	case NBL_CFG_CC_RTT_PROBE_INVL:
	case NBL_CFG_CC_HIGH_PRI_RTT_INVL:
	case NBL_CFG_CC_HIGH_PRI_RTT_EN:
	case NBL_CFG_CC_RST_WIN_HIGH:
	case NBL_CFG_CC_RST_WIN_EN:
	case NBL_CFG_CC_RST_WIN_LOW:
	case NBL_CFG_CC_RST_WIN_RTT_INT:
	case NBL_CFG_CC_RST_WIN_RTT_FRACTION:
	case NBL_CFG_CC_DYN_RTT_OFFSET_EN:
	case NBL_CFG_CC_REMOVE_REMOTE_TIME:
	case NBL_CFG_CC_HIGH_RTT_INT:
	case NBL_CFG_CC_LOW_RTT_INT:
	case NBL_CFG_CC_RDMA_TIME_SEL:
	case NBL_CFG_CC_LOW_RTT_OFFSET:
	case NBL_CFG_CC_HIGH_RTT_OFFSET:
	case NBL_CFG_CC_RST_WIN_RTT_OFFSET:
		return NBL_CC_REG;
	case NBL_CFG_CC_SAVE:
	case NBL_CFG_CC_QCN_SAVE:
		return NBL_CC_OTHER;
	default:
		return NBL_CC_OTHER;
	}
}

static enum nbl_qpc_mask nbl_cc_param_types_to_qpc_mask(int offset)
{
	switch (offset) {
	case NBL_CFG_CC_MODE:
		return NBL_QPC_CC_MODE_MASK;
	case NBL_CFG_CC_OAMREQ_TC_EN:
		return NBL_QPC_OAMREQ_TC_EN_MASK;
	case NBL_CFG_CC_OAMREQ_NET_TC:
		return NBL_QPC_OAMREQ_NET_TC_MASK;
	case NBL_CFG_CC_OAMACK_TC_EN:
		return NBL_QPC_OAMACK_TC_EN_MASK;
	case NBL_CFG_CC_OAMACK_NET_TC:
		return NBL_QPC_OAMACK_NET_TC_MASK;
	case NBL_CFG_CC_OAMACK_BLK_TH:
		return NBL_QPC_OAMACK_BLK_TH_MASK;
	case NBL_CFG_CC_TARGETWIN_MIN:
		return NBL_QPC_TARGETWIN_MIN_MASK;
	case NBL_CFG_CC_TARGETWIN:
		return NBL_QPC_TARGETWIN_MASK;
	case NBL_CFG_CC_PKT_NUM_EN:
		return NBL_QPC_CC_PKT_NUM_EN_MASK;
	case NBL_CFG_CC_CMP_RTT_QP_MULT:
		return NBL_QPC_CC_CMP_RTT_QP_MULT_MASK;
	case NBL_CFG_QCN_START_RATE:
		return NBL_QPC_QCN_START_RATE_MASK;
	default:
		return NBL_QPC_MAX_MASK;
	}
}

static int nbl_ib_check_cc_param_val(struct nbl_pci_f *rf, int offset, u32 var)
{
	int ret = 0;

	switch (offset) {
	case NBL_CFG_CC_MODE:
	case NBL_CFG_QCN_RR_MODE:
	case NBL_CFG_CC_CMP_RTT_QP_MULT:
	case NBL_CFG_CC_RDMA_TIME_SEL:
		if (var > NBL_CFG_CC_MODE_MASK)
			ret = -EINVAL;
		break;
	case NBL_CFG_CC_EN:
	case NBL_CFG_CC_SAVE:
	case NBL_CFG_CC_QCN_SAVE:
	case NBL_CFG_CC_OAMREQ_TC_EN:
	case NBL_CFG_CC_OAMACK_TC_EN:
	case NBL_CFG_CC_PKT_NUM_EN:
	case NBL_CFG_QCN_QUICK_START_FLAG:
	case NBL_CFG_QCN_SENDCNP_FLAG:
		if (var > NBL_CFG_CC_ENABLE_MASK)
			ret = -EINVAL;
		break;
	case NBL_CFG_CC_OAMREQ_NET_TC:
	case NBL_CFG_CC_OAMACK_NET_TC:
		if (var > NBL_CFG_CC_TC_MASK)
			ret = -EINVAL;
		break;
	case NBL_CFG_CC_OAMACK_BLK_TH:
		if (var > NBL_CFG_CC_OAM_BLK_TH_MASK || var == 0)
			ret = -EINVAL;
		break;
	case NBL_CFG_CC_TARGETWIN_MIN:
	case NBL_CFG_CC_TARGETWIN:
		if (var > NBL_CFG_CC_TARWINTH_MASK)
			ret = -EINVAL;
		break;
	case NBL_CFG_CC_HIGH_RTT_FRACTION:
	case NBL_CFG_CC_LOW_RTT_FRACTION:
		if (var > NBL_CFG_CC_RTTMINTH_COE_FRACTION_MASK ||
		    (var && (rf->sc_dev.cc_dbgfs_params[NBL_CFG_CC_HIGH_RTT_INT] ||
		    rf->sc_dev.cc_dbgfs_params[NBL_CFG_CC_LOW_RTT_INT])))
			ret = -EINVAL;
		break;
	case NBL_CFG_CC_RST_WIN_RTT_FRACTION:
		if (var > NBL_CFG_CC_RTTMINTH_COE_FRACTION_MASK)
			ret = -EINVAL;
		break;
	case NBL_CFG_CC_HIGH_RTT_INT:
	case NBL_CFG_CC_LOW_RTT_INT:
		if (var > NBL_CFG_CC_RTTMINTH_COE_INT_MASK ||
		    (var && (rf->sc_dev.cc_dbgfs_params[NBL_CFG_CC_HIGH_RTT_FRACTION] ||
		    rf->sc_dev.cc_dbgfs_params[NBL_CFG_CC_LOW_RTT_FRACTION])))
			ret = -EINVAL;
		break;
	case NBL_CFG_CC_RST_WIN_RTT_INT:
		if (var > NBL_CFG_CC_RTTMINTH_COE_INT_MASK)
			ret = -EINVAL;
		break;
	case NBL_CFG_CC_INC_TARWINTH:
	case NBL_CFG_CC_DEC_TARWINTH:
		if (var > NBL_CFG_CC_TARWINTH_MASK)
			ret = -EINVAL;
		break;

	case NBL_CFG_QCN_MID_SENDBLK_TH_HIGH:
	case NBL_CFG_QCN_MID_SENDBLK_TH_LOW:
		if (var > NBL_CFG_QCN_MID_SENDBLK_MASK)
			ret = -EINVAL;
		break;
	case NBL_CFG_QCN_MID_SENDTIME_TH_HIGH:
	case NBL_CFG_QCN_MID_SENDTIME_TH_LOW:
		if (var > NBL_CFG_QCN_MID_SENDTIME_MASK)
			ret = -EINVAL;
		break;
	case NBL_CFG_QCN_RR_TH:
		if (var > NBL_CFG_QCN_RR_TH_MASK)
			ret = -EINVAL;
		break;
	case NBL_CFG_QCN_AI_RP:
		if (var > NBL_CFG_QCN_AI_RP_MASK)
			ret = -EINVAL;
		break;
	case NBL_CFG_QCN_HAI_RP:
		if (var > NBL_CFG_QCN_HAI_RP_MASK)
			ret = -EINVAL;
		break;
	case NBL_CFG_QCN_MIN_RATE_RP:
	case NBL_CFG_QCN_MAX_RATE_RP:
		if (var > NBL_CFG_QCN_RATE_RP_MASK)
			ret = -EINVAL;
		break;
	case NBL_CFG_QCN_SENDCNP_TIME_TH:
		if (var > NBL_CFG_QCN_SEND_CNP_TIME_MASK)
			ret = -EINVAL;
		break;
	case NBL_CFG_CC_TXP_SENDREQ_DB_CFG:
		if (var > NBL_CFG_TXP_SENDREQ_DB_CFG_MASK)
			ret = -EINVAL;
		break;
	case NBL_CFG_CC_RTT_OFFSET:
	case NBL_CFG_CC_LOW_RTT_OFFSET:
	case NBL_CFG_CC_HIGH_RTT_OFFSET:
	case NBL_CFG_CC_RST_WIN_RTT_OFFSET:
		if (var > NBL_CFG_RTT_OFFSET_MASK)
			ret = -EINVAL;
		break;
	case NBL_CFG_CC_RTT_PROBE_INVL:
		if (var == 0 || var > NBL_CFG_RTT_PROBE_INVL_MASK)
			ret = -EINVAL;
		break;
	case NBL_CFG_CC_HIGH_PRI_RTT_INVL:
		if (var == 0 || var > NBL_CFG_HIGH_PRI_RTT_INVL_MASK)
			ret = -EINVAL;
		break;
	case NBL_CFG_CC_RST_WIN_HIGH:
	case NBL_CFG_CC_RST_WIN_LOW:
		if (var > NBL_CFG_RST_WIN_MASK)
			ret = -EINVAL;
		break;
	case NBL_CFG_CC_RST_WIN_EN:
	case NBL_CFG_CC_DYN_RTT_OFFSET_EN:
	case NBL_CFG_CC_HIGH_PRI_RTT_EN:
	case NBL_CFG_CC_REMOVE_REMOTE_TIME:
		if (var != 0 && var != 1)
			ret = -EINVAL;
		break;
	case NBL_CFG_QCN_EXTRA_QUANTA:
	case NBL_CFG_QCN_FAST_REDUCE_MODE:
	case NBL_CFG_QCN_REDUCE_COE:
		if (var >= NBL_CFG_QCN_MODE_MASK)
			ret = -EINVAL;
		break;
	case NBL_CFG_QCN_START_RATE:
		if (var > NBL_CFG_DCQCN_START_RATE_MASK)
			return -EINVAL;
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

bool nbl_dentry_is_exist(char *dentry)
{
	struct file *f;
	bool ret = true;

	f = filp_open(dentry, O_RDONLY, 0);
	if (IS_ERR(f))
		ret = false;
	else
		filp_close(f, NULL);

	return ret;
}

int nbl_ib_get_debugfs_absolute_path(struct nbl_device *dev,
				     struct dentry *dentry_path,
				     char *absolute_path)
{
	int ret = 0;
	char *full_path;
	char *buf;

	buf = __getname();
	if (!buf)
		return -ENOMEM;

	full_path = dentry_path_raw(dentry_path, buf, NBL_RDMA_DENTRY_LEN);
	if (IS_ERR(full_path)) {
		__putname(buf);
		return -ENOENT;
	}

	ret = snprintf(absolute_path, NBL_RDMA_DENTRY_LEN,
		"/sys/kernel/debug%s/.", full_path);
	__putname(buf);

	return ret;
}

int nbl_ib_copy_dentry(char *src_dir, char *dst_dir)
{
	/* 3. cp -r src_dir dst_dir */
	char *path = "/bin/cp";
	char *argv[5] = {path, "-r", src_dir, dst_dir, NULL};
	char *envp[1] = {NULL};

	return call_usermodehelper(path, argv, envp, UMH_WAIT_PROC);
}


static int nbl_ib_save_process(struct nbl_device *dev,
	enum nbl_ib_cc_mode_types type)
{
	int ret = 0;
	char src_dir[NBL_RDMA_DENTRY_LEN];
	char dst_dir[NBL_RDMA_DENTRY_LEN];
	struct dentry *dentry_path = NULL;

	/* 1. dst_dir */
	if (dev->ibdev.name[0] == '\0')
		return 0;

	if (type == NBL_CC) {
		dentry_path = dev->dbg_cc_params->cc_root;
		ret = snprintf(dst_dir, sizeof(dst_dir),
			"/etc/nebulamatrix/rdma/%s/cc_params", dev->ibdev.name);
	} else if (type == NBL_QCN) {
		dentry_path = dev->dbg_cc_params->qcn_root;
		ret = snprintf(dst_dir, sizeof(dst_dir),
			"/etc/nebulamatrix/rdma/%s/qcn_params", dev->ibdev.name);
	} else {
		return 0;
	}

	if (ret < 0)
		return ret;
	nbl_pr_info("dst_dir=%s\n", dst_dir);

	if (!nbl_dentry_is_exist(dst_dir)) {
		char *path = "/bin/mkdir";
		char *argv[4] = {path, "-p", dst_dir, NULL};
		char *envp[1] = {NULL};

		ret = call_usermodehelper(path, argv, envp, UMH_WAIT_PROC);
		if (ret) {
			nbl_pr_err("failed to mkdir dst_dir:%s, ret=%d\n",
				dst_dir, ret);
			return ret;
		}
	}

	/* 2. src_dir */
	ret = nbl_ib_get_debugfs_absolute_path(dev, dentry_path, src_dir);
	if (ret < 0)
		return ret;
	nbl_pr_info("src_dir=%s\n", src_dir);

	/* 3. cp -r src_dir dst_dir */
	ret = nbl_ib_copy_dentry(src_dir, dst_dir);

	return ret;
}

static int nbl_ib_save_cc_cfg(struct nbl_device *dev, int offset, u32 var)
{
	if (var == 0)
		return 0;

	if (offset == NBL_CFG_CC_SAVE)
		return nbl_ib_save_process(dev, NBL_CC);
	else if (offset == NBL_CFG_CC_QCN_SAVE)
		return nbl_ib_save_process(dev, NBL_QCN);
	else
		return -EINVAL;
}

static int nbl_load_cc_cfg(struct nbl_device *dev)
{
	int ret;
	char func_default_dir[NBL_RDMA_DENTRY_LEN];
	char src_dir[NBL_RDMA_DENTRY_LEN];
	char dst_dir[NBL_RDMA_DENTRY_LEN];

	/* 1. src_dir */
	ret = snprintf(func_default_dir, sizeof(func_default_dir),
		"/etc/nebulamatrix/rdma/%s/cc_params/.", dev->ibdev.name);
	if (ret < 0)
		return ret;
	if (nbl_dentry_is_exist(func_default_dir))
		strscpy(src_dir, func_default_dir, sizeof(src_dir));
	else if (nbl_dentry_is_exist(NBL_RDMA_CC_CFG_DEFAULT_DENTRY))
		strscpy(src_dir, NBL_RDMA_CC_CFG_DEFAULT_DENTRY, sizeof(src_dir));
	else {
		nbl_pr_dbg("%s doesn't have default CC cfg.\n",
			NBL_RDMA_CC_CFG_DEFAULT_DENTRY);
		return -ENOTDIR;
	}
	nbl_pr_dbg("src_dir=%s\n", src_dir);

	/* 2. dst_dir */
	ret = nbl_ib_get_debugfs_absolute_path(dev, dev->dbg_cc_params->cc_root,
			dst_dir);
	if (ret < 0)
		return ret;
	nbl_pr_dbg("dst_dir=%s\n", dst_dir);

	/* 3. cp -r src_dir dst_dir */
	ret = nbl_ib_copy_dentry(src_dir, dst_dir);

	return ret;
}

static int nbl_load_qcn_cfg(struct nbl_device *dev)
{
	int ret;
	char func_default_dir[NBL_RDMA_DENTRY_LEN];
	char src_dir[NBL_RDMA_DENTRY_LEN];
	char dst_dir[NBL_RDMA_DENTRY_LEN];

	/* 1. src_dir */
	ret = snprintf(func_default_dir, sizeof(func_default_dir),
		"/etc/nebulamatrix/rdma/%s/qcn_params/.", dev->ibdev.name);
	if (ret < 0)
		return ret;
	if (nbl_dentry_is_exist(func_default_dir))
		strscpy(src_dir, func_default_dir, sizeof(src_dir));
	else if (nbl_dentry_is_exist(NBL_RDMA_QCN_CFG_DEFAULT_DENTRY))
		strscpy(src_dir, NBL_RDMA_QCN_CFG_DEFAULT_DENTRY, sizeof(src_dir));
	else {
		nbl_pr_dbg("%s doesn't have default QCN cfg.\n",
			NBL_RDMA_QCN_CFG_DEFAULT_DENTRY);
		return -ENOTDIR;
	}
	nbl_pr_dbg("src_dir=%s\n", src_dir);

	/* 2. dst_dir */
	ret = nbl_ib_get_debugfs_absolute_path(dev, dev->dbg_cc_params->qcn_root,
		dst_dir);
	if (ret < 0)
		return ret;
	nbl_pr_dbg("dst_dir=%s\n", dst_dir);

	/* 3. cp -r src_dir dst_dir */
	ret = nbl_ib_copy_dentry(src_dir, dst_dir);

	return ret;
}

static int find_next_rsrc(struct nbl_pci_f *rf,
			      unsigned long *rsrc_array,
			      u32 max_rsrc,
			      u32 next)
{
	u32 rsrc_num;
	unsigned long flags;

	spin_lock_irqsave(&rf->rsrc_lock, flags);
	rsrc_num = find_next_bit(rsrc_array, max_rsrc, next);
	spin_unlock_irqrestore(&rf->rsrc_lock, flags);
	return (rsrc_num < max_rsrc) ? rsrc_num : -2;
}

static void nbl_cc_fill_ctx_info(struct nbl_pci_f *rf, enum nbl_qpc_mask mask, u32 var,
								struct nbl_qp_ctx *ctx_info)
{
	switch (mask) {
	case NBL_QPC_OAMREQ_TC_EN_MASK:
		ctx_info->cc_oamreq_tc_en = var;
		break;
	case NBL_QPC_OAMREQ_NET_TC_MASK:
		ctx_info->cc_oamreq_net_tc = var;
		break;
	case NBL_QPC_OAMACK_TC_EN_MASK:
		ctx_info->cc_oamack_tc_en = var;
		break;
	case NBL_QPC_OAMACK_NET_TC_MASK:
		ctx_info->cc_oamack_net_tc = var;
		break;
	case NBL_QPC_OAMACK_BLK_TH_MASK:
		ctx_info->cc_oamack_blk_th = var;
		break;
	case NBL_QPC_TARGETWIN_MIN_MASK:
		ctx_info->cc_targetwin_min = var;
		break;
	case NBL_QPC_TARGETWIN_MASK:
		ctx_info->targetwin = var;
		break;
	case NBL_QPC_CC_MODE_MASK:
		ctx_info->cc_mode = var;
		rf->sc_dev.cc_mode = var;
		break;
	case NBL_QPC_CC_PKT_NUM_EN_MASK:
		ctx_info->cc_pkt_num_en = var;
		break;
	case NBL_QPC_CC_CMP_RTT_QP_MULT_MASK:
		ctx_info->cc_rtt_qp_mult = var;
		break;
	default:
		break;
	}
}

static int nbl_ib_set_cc_param_into_reg(struct nbl_device *dev,
										int offset, u32 var)
{
	uint8_t in[64];
	uint8_t out[64];
	int data_len = 0;
	int ret;
	struct grc_cache_msg_header *head;

	head = (struct grc_cache_msg_header *)in;
	head->op_code = GRC_MSG_OP_CC_REG_SET;
	head->payload_len = sizeof(offset) + sizeof(var);
	data_len += sizeof(struct grc_cache_msg_header);

	memcpy(in + data_len, &offset, sizeof(offset));
	data_len += sizeof(offset);

	memcpy(in + data_len, &var, sizeof(var));
	data_len += sizeof(var);

	ret = nbl_exec_cmd(dev->rf, in, data_len, out, sizeof(out));
	if (ret != 0)
		nbl_pr_err("set cc reg err=%d offset:%d, var:%d\n", ret, offset, var);

	return ret;
}

static int nbl_ib_set_cc_param_into_qpc(struct nbl_device *dev,
										int offset, u32 var)
{
	struct nbl_pci_f *rf = dev->rf;
	int qp_id = NBL_QP_NUM_FOR_CM;
	int ret = 0;
	struct nbl_qp_ctx ctx_info = { 0 };
	enum nbl_qpc_mask mask;

	mask = nbl_cc_param_types_to_qpc_mask(offset);
	if (mask == NBL_QPC_MAX_MASK)
		return -EINVAL;
	/* TARGETWIN and QCN_START_RATE not support modify */
	if (mask == NBL_QPC_TARGETWIN_MASK || mask == NBL_QPC_QCN_START_RATE_MASK)
		return 0;

	nbl_cc_fill_ctx_info(rf, mask, var, &ctx_info);

	/* TODO: Does QP0/1 require special configuration? */
	do {
		++qp_id;
		qp_id = find_next_rsrc(rf, rf->allocated_qps, rf->max_qp, qp_id);
		if (qp_id < 0)
			break;
		if (!rf->qp_table[qp_id])
			break;

		/* TODO: should be based on cc_mode to modify QPC */
		ret = nbl_modify_hw_qpc(rf->qp_table[qp_id], &ctx_info, mask);
		if (ret) {
			nbl_pr_err("failed to modify field of qp:%d, ret:%d\n", qp_id, ret);
			return ret;
		}
	} while (1);

	return ret;
}

static int nbl_ib_set_cc_params(struct nbl_device *dev, int offset, u32 var)
{
	enum nbl_ib_dbg_cc_cfg_type type;
	int ret = 0;

	type = nbl_ib_param_to_cfg_type(offset);
	if (type == NBL_CC_REG) {
		ret = nbl_ib_set_cc_param_into_reg(dev, offset, var);
		if (ret)
			nbl_pr_err("failed to set cc params into reg.\n");
	} else if (type == NBL_CC_QPC) {
		/* for all qp */
		ret = nbl_ib_set_cc_param_into_qpc(dev, offset, var);
		if (ret)
			nbl_pr_err("failed to set cc params into qpc.\n");
	} else {
		/* does not work during initialization */
		if (var == NBL_CFG_CC_ENABLE_MASK && dev->dbg_cc_params->has_init) {
			ret = nbl_ib_save_cc_cfg(dev, offset, var);
			if (ret)
				nbl_pr_err("failed to save cc params\n");
		}
	}

	if (ret == 0)
		dev->rf->sc_dev.cc_dbgfs_params[offset] = var;

	return ret;
}

int config_cc_param(struct nbl_device *dev, int offset, u32 var)
{
	int ret;

	if (offset >= NBL_CFG_CC_TYPE_MAX)
		return -EINVAL;

	ret = nbl_ib_check_cc_param_val(dev->rf, offset, var);
	nbl_pr_dbg("config cc param[%d]:%s val:%u\n", offset, nbl_dbg_cc_name[offset], var);
	if (ret) {
		nbl_pr_err(
			"config cc param[%d]:%s val:%u is invalid, please check the param.\n",
			offset, nbl_dbg_cc_name[offset], var);
		return ret;
	}

	ret = nbl_ib_set_cc_params(dev, offset, var);

	return ret;
}

static ssize_t set_cc_param(struct file *filp, const char __user *buf,
			 size_t count, loff_t *pos)
{
	struct nbl_ib_dbg_param *param = filp->private_data;
	int offset = param->offset;
	char lbuf[11] = { };
	u32 var;
	int ret;

	if (count > sizeof(lbuf))
		return -EINVAL;

	if (copy_from_user(lbuf, buf, count))
		return -EFAULT;

	lbuf[sizeof(lbuf) - 1] = '\0';

	if (kstrtou32(lbuf, 0, &var))
		return -EINVAL;

	ret = config_cc_param(param->dev, offset, var);

	return ret ? ret : count;
}

u32 show_cc_param(struct nbl_device *dev, int offset)
{
	return dev->rf->sc_dev.cc_dbgfs_params[offset];
}

static ssize_t get_cc_param(struct file *filp, char __user *buf, size_t count,
			 loff_t *pos)
{
	struct nbl_ib_dbg_param *param = filp->private_data;
	struct nbl_device *nbl_dev = param->dev;
	struct nbl_pci_f *rf = nbl_dev->rf;
	int offset = param->offset;
	u32 var = 0;
	int ret;
	char lbuf[11];

	var = rf->sc_dev.cc_dbgfs_params[offset];
	ret = snprintf(lbuf, sizeof(lbuf), "%d\n", var);
	if (ret < 0)
		return ret;

	return simple_read_from_buffer(buf, count, pos, lbuf, ret);
}

static const struct file_operations dbg_cc_fops = {
	.owner	= THIS_MODULE,
	.open	= simple_open,
	.write	= set_cc_param,
	.read	= get_cc_param,
};

static void nbl_ib_cleanup_cc_debugfs(struct nbl_device *dev)
{
	if (!dev->func_dbg_dir || !dev->dbg_cc_params)
		return;

	debugfs_remove_recursive(dev->dbg_cc_params->cc_root);
	debugfs_remove_recursive(dev->dbg_cc_params->qcn_root);
	kfree(dev->dbg_cc_params);
	dev->dbg_cc_params = NULL;
}

static void nbl_ib_init_cc_debugfs(struct nbl_device *dev)
{
	struct nbl_ib_dbg_cc_params *dbg_cc_params;
	int i;

	if (!dev->func_dbg_dir)
		return;

	dbg_cc_params = kzalloc(sizeof(*dbg_cc_params), GFP_KERNEL);
	if (!dbg_cc_params) {
		dev->dbg_cc_params = NULL;
		goto err;
	}

	dev->dbg_cc_params = dbg_cc_params;

	dbg_cc_params->cc_root = debugfs_create_dir("cc_params",
				dev->func_dbg_dir);
	if (!dbg_cc_params->cc_root) {
		nbl_pr_err("init cc_params directory failed\n");
		goto err;
	}

	dbg_cc_params->qcn_root = debugfs_create_dir("qcn_params",
				dev->func_dbg_dir);
	if (!dbg_cc_params->qcn_root) {
		nbl_pr_err("init qcn_params directory failed\n");
		goto err;
	}

	for (i = 0; i < NBL_CFG_CC_TYPE_MAX; i++) {
		dbg_cc_params->params[i].offset = i;
		dbg_cc_params->params[i].dev = dev;
		if (i <= NBL_CFG_CC_EN) { /* global */
			dbg_cc_params->params[i].dentry =
				debugfs_create_file(nbl_dbg_cc_name[i],
							0600, dbg_cc_params->cc_root,
							&dbg_cc_params->params[i],
							&dbg_cc_fops);
			dbg_cc_params->params[i].dentry =
				debugfs_create_file(nbl_dbg_cc_name[i],
							0600, dbg_cc_params->qcn_root,
							&dbg_cc_params->params[i],
							&dbg_cc_fops);
		} else if (i <= NBL_CFG_CC_TXP_SENDREQ_DB_CFG) { /* nbl-cc */
			dbg_cc_params->params[i].dentry =
				debugfs_create_file(nbl_dbg_cc_name[i],
							0600, dbg_cc_params->cc_root,
							&dbg_cc_params->params[i],
							&dbg_cc_fops);
		} else { /* nbl-qcn */
			dbg_cc_params->params[i].dentry =
				debugfs_create_file(nbl_dbg_cc_name[i],
							0600, dbg_cc_params->qcn_root,
							&dbg_cc_params->params[i],
							&dbg_cc_fops);
		}
	}

	nbl_pr_dbg("init CC debugfs successfully\n");
	return;

err:
	nbl_pr_err("CC debugfs failure\n");
	nbl_ib_cleanup_cc_debugfs(dev);
}

static void nbl_cc_default_params_init(struct nbl_device *dev)
{
	int *params = &dev->rf->sc_dev.cc_dbgfs_params[0];
	int offset;

	params[NBL_CFG_CC_MODE] = NBL_DEF_CC_MODE;
	params[NBL_CFG_CC_EN] = NBL_DEF_CC_EN;
	params[NBL_CFG_CC_OAMREQ_TC_EN] = NBL_DEF_CC_OAMREQ_TC_EN;
	params[NBL_CFG_CC_OAMREQ_NET_TC] = NBL_DEF_CC_OAMREQ_NET_TC;
	params[NBL_CFG_CC_OAMACK_TC_EN] = NBL_DEF_CC_OAMACK_TC_EN;
	params[NBL_CFG_CC_OAMACK_NET_TC] = NBL_DEF_CC_OAMACK_NET_TC;

	params[NBL_CFG_CC_OAMACK_BLK_TH] = NBL_DEF_CC_OAMACK_BLK_TH;
	params[NBL_CFG_CC_TARGETWIN_MIN] = NBL_DEF_CC_TARGETWIN_MIN;
	params[NBL_CFG_CC_PKT_NUM_EN] = NBL_DEF_CC_PKT_NUM_EN;
	params[NBL_CFG_CC_HIGH_RTT_FRACTION] = NBL_DEF_CC_HIGH_RTT_FRACTION;
	params[NBL_CFG_CC_LOW_RTT_FRACTION] = NBL_DEF_CC_LOW_RTT_FRACTION;
	params[NBL_CFG_CC_INC_TARWINTH] = NBL_DEF_CC_INC_TARGET_WIN_TH;
	params[NBL_CFG_CC_DEC_TARWINTH] = NBL_DEF_CC_DEC_TARGET_WIN_TH;
	params[NBL_CFG_CC_TARGETWIN] = NBL_DEF_CC_TARGETWIN;
	params[NBL_CFG_CC_RTT_OFFSET] = NBL_DEF_CC_RTT_OFFSET;
	params[NBL_CFG_CC_RTT_PROBE_INVL] = NBL_DEF_CC_RTT_PROBE_INVL;
	params[NBL_CFG_CC_HIGH_PRI_RTT_INVL] = NBL_DEF_CC_HIGH_PRI_RTT_INVL;
	params[NBL_CFG_CC_HIGH_PRI_RTT_EN] = NBL_DEF_CC_HIGH_RPI_RTT_EN;
	params[NBL_CFG_CC_RST_WIN_HIGH] = NBL_DEF_CC_RST_WIN_H;
	params[NBL_CFG_CC_RST_WIN_EN] = NBL_DEF_CC_RST_WIN_EN;
	params[NBL_CFG_CC_RST_WIN_LOW] = NBL_DEF_CC_RST_WIN_L;
	params[NBL_CFG_CC_RST_WIN_RTT_INT] = NBL_DEF_CC_RST_WIN_RTT_INT;
	params[NBL_CFG_CC_RST_WIN_RTT_FRACTION] =
		NBL_DEF_CC_RST_WIN_RTT_FRACTION;
	params[NBL_CFG_CC_DYN_RTT_OFFSET_EN] = NBL_DEF_CC_DYN_RTT_OFFSET_EN;
	params[NBL_CFG_CC_REMOVE_REMOTE_TIME] = NBL_DEF_CC_REMOVE_REMOTE_TIME;
	params[NBL_CFG_CC_HIGH_RTT_INT] = NBL_DEF_CC_HIGH_RTT_INT;
	params[NBL_CFG_CC_LOW_RTT_INT] = NBL_DEF_CC_LOW_RTT_INT;
	params[NBL_CFG_CC_RDMA_TIME_SEL] = NBL_DEF_CC_RDMA_TIME_SEL;
	params[NBL_CFG_CC_CMP_RTT_QP_MULT] = NBL_DEF_CC_CMP_RTT_QP_MULT;
	params[NBL_CFG_CC_LOW_RTT_OFFSET] = NBL_DEF_CC_LOW_RTT_OFFSET;
	params[NBL_CFG_CC_HIGH_RTT_OFFSET] = NBL_DEF_CC_HIGH_RTT_OFFSET;
	params[NBL_CFG_CC_RST_WIN_RTT_OFFSET] = NBL_DEF_CC_RST_WIN_RTT_OFFSET;
	params[NBL_CFG_CC_TXP_SENDREQ_DB_CFG] = NBL_DEF_CC_TXP_SENDREQ_DB_CFG;
	params[NBL_CFG_QCN_RR_MODE] = NBL_DEF_QCN_RR_MODE;
	params[NBL_CFG_QCN_MID_SENDBLK_TH_HIGH] =
		NBL_DEF_QCN_MID_SENDBLK_TH_HIGH;
	params[NBL_CFG_QCN_MID_SENDBLK_TH_LOW] = NBL_DEF_QCN_MID_SENDBLK_TH_LOW;
	params[NBL_CFG_QCN_MID_SENDTIME_TH_HIGH] =
		NBL_DEF_QCN_MID_SENDTIME_TH_HIGH;
	params[NBL_CFG_QCN_MID_SENDTIME_TH_LOW] =
		NBL_DEF_QCN_MID_SENDTIME_TH_LOW;
	params[NBL_CFG_QCN_RR_TH] = NBL_DEF_QCN_RR_TH;
	params[NBL_CFG_QCN_AI_RP] = NBL_DEF_QCN_AI_RP;
	params[NBL_CFG_QCN_HAI_RP] = NBL_DEF_QCN_HAI_RP;
	params[NBL_CFG_QCN_MIN_RATE_RP] = NBL_DEF_QCN_MIN_RATE_RP;
	params[NBL_CFG_QCN_MAX_RATE_RP] = NBL_DEF_QCN_MAX_RATE_RP;
	params[NBL_CFG_QCN_QUICK_START_FLAG] = NBL_DEF_QCN_QUICK_START_FLAG;
	params[NBL_CFG_QCN_SENDCNP_FLAG] = NBL_DEF_QCN_SENDCNP_FLAG;
	params[NBL_CFG_QCN_SENDCNP_TIME_TH] = NBL_DEF_QCN_SENDCNP_TIME_TH;
	params[NBL_CFG_QCN_START_RATE] = NBL_DEF_QCN_SET_START_RATE;
	params[NBL_CFG_QCN_EXTRA_QUANTA] = NBL_DEF_QCN_EXTRA_QUANTA;
	params[NBL_CFG_QCN_FAST_REDUCE_MODE] = NBL_DEF_QCN_FAST_REDUCE_MODE;
	params[NBL_CFG_QCN_REDUCE_COE] = NBL_DEF_QCN_REDUCE_COE;

	for (offset = NBL_CFG_CC_MODE; offset < NBL_CFG_CC_TYPE_MAX; offset++)
		config_cc_param(dev, offset, params[offset]);
};

void nbl_debugfs_cc_init(struct nbl_device *dev)
{
	nbl_ib_init_cc_debugfs(dev);
	if (!dev->dbg_cc_params) {
		nbl_pr_err("CC CFG loading exited due to insufficient memory.\n");
		return;
	}

	nbl_cc_default_params_init(dev);

	nbl_load_cc_cfg(dev);
	nbl_load_qcn_cfg(dev);
	dev->dbg_cc_params->has_init = true;
}

void nbl_debugfs_cc_deinit(struct nbl_device *dev)
{
	nbl_ib_cleanup_cc_debugfs(dev);
}
