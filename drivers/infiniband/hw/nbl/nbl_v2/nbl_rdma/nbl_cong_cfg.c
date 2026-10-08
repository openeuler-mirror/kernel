// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2022, nebula-matrix Limited */

#include <linux/debugfs.h>

#include "cqp.h"
#include "qp.h"
#include "grc.h"
#include "main.h"
#include "dbgfs.h"
#include "nbl_pt_cfg.h"

#define NBL_CFG_CC_ENABLE_MASK			0x1
#define NBL_CFG_CC_TC_MASK				0x7
#define NBL_CFG_CC_OAM_BLK_TH_MASK 0xFFF
#define NBL_CFG_CC_WIN_MASK				0xFFFFF
#define NBL_CFG_CC_MODE_MASK 0x4
#define NBL_CFG_QCN_RR_MODE_MASK 0x3
#define NBL_CFG_CC_RTTMINTH_COE_FRACTION_MASK	0xF
#define NBL_CFG_CC_RTTMINTH_COE_INT_MASK	0x4
#define NBL_CFG_CC_TARWINTH_MASK		0xFFFFF
#define NBL_CFG_QCN_MID_SENDBLK_MASK	0xFFFF
#define NBL_CFG_QCN_RR_TH_MASK			0xF
#define NBL_CFG_QCN_RATE_RP_MASK		0x3FFFF
#define NBL_CFG_QCN_SEND_CNP_TIME_MASK	0xFFF
#define NBL_CFG_QCN_MODE_MASK			0x3
#define NBL_CFG_RTT_OFFSET_MASK			0x3FF
#define NBL_CFG_RTT_PROBE_INVL_MASK		0xFF
#define NBL_CFG_HIGH_PRI_RTT_INVL_MASK	0xFF
#define NBL_CFG_RST_WIN_MASK 0xFFFFF
#define NBL_CFG_TXP_SENDREQ_DB_CFG_MASK	0xFFFF

#define NBL_CFG_QCN_AI_RP_MASK_V2		0xFFFFF
#define NBL_CFG_QCN_HAI_RP_MASK_V2		0xFFFFF
#define NBL_CFG_QCN_RATE_RP_MASK_V2		0xFFFFF
#define NBL_CFG_QCN_TIME_MASK_V2	0x1FFFFFF
#define NBL_CFG_DCQCN_START_RATE_MASK 400000 /* 400000 Mbps */

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
	"cc_target_rttmin",
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
	"qcn_time_accum",
	"qcn_use_hai_en",
	"qcn_quanta_cc2txp",
	"qcn_clamp_rt",
	"qcn_alpha_g",
	"qcn_alpha_t",
	"qcn_alpha_rpg_gd",
	"qcn_ecn_mode",
	"qcn_smooth_period",
	"qcn_smooth_weight",
	"qcn_ecn_kmin",
	"qcn_ecn_kmax",
	"qcn_ecn_pmax",
	"qcn_ecn_k",
	"txp_cnp_limit_en",
	"cnp_accompanied_en",
	"bth_with_reduce_flag_en",
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
	case NBL_CFG_CC_TARGETWIN_MIN:
	case NBL_CFG_CC_TARGETWIN:
	case NBL_CFG_CC_PKT_NUM_EN:
	case NBL_CFG_CC_CMP_RTT_QP_MULT:
	case NBL_CFG_QCN_START_RATE:
		return NBL_CC_QPC;
	case NBL_CFG_CC_OAMACK_BLK_TH:
		return NBL_CC_REG;
	case NBL_CFG_CC_SAVE:
	case NBL_CFG_CC_QCN_SAVE:
		return NBL_CC_OTHER;
	default:
		return NBL_CC_REG;
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
	int max;

	switch (offset) {
	case NBL_CFG_CC_MODE:
		if (var > NBL_CFG_CC_MODE_MASK)
			ret = -EINVAL;
		break;
	case NBL_CFG_QCN_RR_MODE:
	case NBL_CFG_CC_CMP_RTT_QP_MULT:
	case NBL_CFG_CC_RDMA_TIME_SEL:
		if (var > NBL_CFG_QCN_RR_MODE_MASK)
			ret = -EINVAL;
		break;
	case NBL_CFG_CC_EN:
	case NBL_CFG_CC_SAVE:
	case NBL_CFG_CC_QCN_SAVE:
	case NBL_CFG_CC_OAMREQ_TC_EN:
	case NBL_CFG_CC_OAMACK_TC_EN:
	case NBL_CFG_CC_PKT_NUM_EN:
	case NBL_CFG_QCN_QUICK_START_FLAG:
	case NBL_CFG_QCN_CLAMP_RT:
	case NBL_CFG_QCN_SENDCNP_FLAG:
	case NBL_CFG_QCN_TIME_ACCUM:
	case NBL_CFG_QCN_USE_HAI_EN:
	case NBL_CFG_QCN_BTH_REDUCE_FLAG:
	case NBL_CFG_QCN_CNP_ACCOMPANIED:
	case NBL_CFG_QCN_TXP_R_CNP_INVL:
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
		    (var &&
		     (rf->sc_dev.cc_dbgfs_params[NBL_CFG_CC_HIGH_RTT_INT] ||
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
		    (var &&
		     (rf->sc_dev.cc_dbgfs_params[NBL_CFG_CC_HIGH_RTT_FRACTION] ||
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
	case NBL_CFG_QCN_ALPHA_T:
	case NBL_CFG_QCN_SMOOTH_PERIOD:
		max = NBL_CFG_QCN_TIME_MASK_V2;
		if (var > max)
			ret = -EINVAL;
		break;
	case NBL_CFG_QCN_RR_TH:
		if (var > NBL_CFG_QCN_RR_TH_MASK)
			ret = -EINVAL;
		break;
	case NBL_CFG_QCN_AI_RP:
		max = NBL_CFG_QCN_AI_RP_MASK_V2;
		if (var > max)
			ret = -EINVAL;
		break;
	case NBL_CFG_QCN_HAI_RP:
		max = NBL_CFG_QCN_HAI_RP_MASK_V2;
		if (var > max)
			ret = -EINVAL;
		break;
	case NBL_CFG_QCN_MIN_RATE_RP:
	case NBL_CFG_QCN_MAX_RATE_RP:
		if (var > NBL_CFG_QCN_RATE_RP_MASK_V2)
			ret = -EINVAL;
		break;
	case NBL_CFG_QCN_SENDCNP_TIME_TH:
		if (var > NBL_CFG_QCN_SEND_CNP_TIME_MASK)
			ret = -EINVAL;
		break;
	case NBL_CFG_CC_TXP_SENDREQ_DB_CFG:
	case NBL_CFG_CC_TARGET_RTTMIN:
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
		if (var > 0x1FFF)
			ret = -EINVAL;
		break;
	case NBL_CFG_QCN_ALPHA_RPG_RD:
		if (var >= NBL_CFG_QCN_RR_TH_MASK)
			ret = -EINVAL;
		break;
	case NBL_CFG_QCN_FAST_REDUCE_MODE:
	case NBL_CFG_QCN_REDUCE_COE:
		if (var >= NBL_CFG_QCN_MODE_MASK)
			ret = -EINVAL;
		break;
	case NBL_CFG_QCN_ALPHA_G:
	case NBL_CFG_QCN_SMOOTH_WEIGHT:
	case NBL_CFG_QCN_ECN_PMAX:
		if (var > 1024)
			ret = -EINVAL;
		break;
	case NBL_CFG_QCN_ECN_KMIN:
	case NBL_CFG_QCN_ECN_KMAX:
		if (var > 4096)
			ret = -EINVAL;
		break;
	case NBL_CFG_QCN_START_RATE:
		if (var > NBL_CFG_DCQCN_START_RATE_MASK)
			return -EINVAL;
		break;
	case NBL_CFG_QCN_ECN_MODE:
	case NBL_CFG_QCN_ECN_K:
	case NBL_CFG_QCN_QUANTA_CC2TXP:
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

	if (dev->rf->dev_ops && dev->rf->dev_ops->set_cc_glb_cfg)
		return dev->rf->dev_ops->set_cc_glb_cfg(dev->rf, offset, var);

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

static void nbl_update_cc_mode_v4(struct nbl_device *dev, u32 mode)
{
	struct nbl_pci_f *rf = dev->rf;

	if (!rf->sc_dev.srp_en && mode && mode != NBL_QCN)
		nbl_rdma_set_txm_sq_raq_separate(&rf->hw, false);
	else
		nbl_rdma_set_txm_sq_raq_separate(&rf->hw, true);
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

	/* not modify cc_mode */
	if (mask == NBL_QPC_CC_MODE_MASK) {
		if (var == NBL_CC) {
			/* load target_rttmin in cc mode */
			ret = nbl_ib_set_cc_param_into_reg(
				dev, NBL_CFG_CC_TARGET_RTTMIN,
				dev->rf->sc_dev.cc_dbgfs_params
					[NBL_CFG_CC_TARGET_RTTMIN]);
		} else {
			/* not set target_rttmin in not cc mode */
			ret = nbl_ib_set_cc_param_into_reg(
				dev, NBL_CFG_CC_TARGET_RTTMIN, 0);
		}

		if (rf->product->congestion_ops->update_cc_mode)
			rf->product->congestion_ops->update_cc_mode(dev, var);
		return ret;
	}

	do {
		++qp_id;
		qp_id = find_next_rsrc(rf, rf->allocated_qps, rf->max_qp, qp_id);
		if (qp_id < 0)
			break;
		if (!rf->qp_table[qp_id])
			break;

		/* CC is only supported while the service type of qp is RC/SRP/XRC */
		if (rf->qp_table[qp_id]->sc_qp.uk_qp.nbl_qp_service_type !=
				NBL_QP_SERVICE_TYPE_RC &&
			rf->qp_table[qp_id]->sc_qp.uk_qp.nbl_qp_service_type !=
				NBL_QP_SERVICE_TYPE_SRP &&
			rf->qp_table[qp_id]->sc_qp.uk_qp.nbl_qp_service_type !=
				NBL_QP_SERVICE_TYPE_XRC)
			continue;

		/* TODO: should be based on cc_mode to modify QPC */
		ret = nbl_modify_hw_qpc(rf->qp_table[qp_id], &ctx_info, mask);
		if (ret) {
			nbl_pr_err("failed to modify field of qp:%d, ret:%d\n", qp_id, ret);
			return ret;
		}
	} while (1);

	return ret;
}

static u32 nbl_ib_get_reg_offset_addr(struct nbl_hw *hw, u32 offset)
{
	const u32 cc_base = NBL_REG_CC_BASE(hw);
	const u32 txp_base = NBL_REG_TXP_BASE(hw);
	const u32 txm_base = NBL_REG_TXM_BASE(hw);

	switch (offset) {
	case NBL_CFG_CC_EN:
		return NBL_CC_REG_ADDR(cc_base, NBL_CC_EN_OFF);
	case NBL_CFG_CC_HIGH_RTT_FRACTION:
	case NBL_CFG_CC_LOW_RTT_FRACTION:
	case NBL_CFG_CC_HIGH_RTT_INT:
	case NBL_CFG_CC_LOW_RTT_INT:
		return NBL_CC_REG_ADDR(cc_base, NBL_CC_RTTMINTH_COE_OFF);
	case NBL_CFG_CC_INC_TARWINTH:
		return NBL_CC_REG_ADDR(cc_base, NBL_CC_INC_TARGET_WIN_TH_OFF);
	case NBL_CFG_CC_DEC_TARWINTH:
		return NBL_CC_REG_ADDR(cc_base, NBL_CC_DEC_TARGET_WIN_TH_OFF);
	case NBL_CFG_CC_TARGET_RTTMIN:
		return NBL_CC_REG_ADDR(cc_base, NBL_CC_TARGET_RTTMIN_OFF);
	case NBL_CFG_CC_TXP_SENDREQ_DB_CFG:
		return NBL_TXP_REG_ADDR(txp_base,
					 NBL_TXP_CC_SENDREQ_DB_CFG_OFF);
	case NBL_CFG_QCN_RR_MODE:
		return NBL_CC_REG_ADDR(cc_base, NBL_QCN_RR_MODE_OFF);
	case NBL_CFG_QCN_MID_SENDBLK_TH_HIGH:
		return NBL_CC_REG_ADDR(cc_base, NBL_QCN_MID_SENDBLK_TH_HIGH_OFF);
	case NBL_CFG_QCN_MID_SENDBLK_TH_LOW:
		return NBL_CC_REG_ADDR(cc_base, NBL_QCN_MID_SENDBLK_TH_LOW_OFF);
	case NBL_CFG_QCN_MID_SENDTIME_TH_HIGH:
		return NBL_CC_REG_ADDR(cc_base, NBL_QCN_MID_SENDTIME_TH_HIGH_OFF);
	case NBL_CFG_QCN_MID_SENDTIME_TH_LOW:
		return NBL_CC_REG_ADDR(cc_base, NBL_QCN_MID_SENDTIME_TH_LOW_OFF);
	case NBL_CFG_QCN_RR_TH:
		return NBL_CC_REG_ADDR(cc_base, NBL_QCN_RR_TH_OFF);
	case NBL_CFG_QCN_AI_RP:
		return NBL_CC_REG_ADDR(cc_base, NBL_QCN_AI_RP_OFF);
	case NBL_CFG_QCN_HAI_RP:
		return NBL_CC_REG_ADDR(cc_base, NBL_QCN_HAI_RP_OFF);
	case NBL_CFG_QCN_MIN_RATE_RP:
		return NBL_CC_REG_ADDR(cc_base, NBL_QCN_MIN_RATE_RP_OFF);
	case NBL_CFG_QCN_MAX_RATE_RP:
		return NBL_CC_REG_ADDR(cc_base, NBL_QCN_MAX_RATE_RP_OFF);
	case NBL_CFG_QCN_QUICK_START_FLAG:
		return NBL_CC_REG_ADDR(cc_base, NBL_QCN_QUICK_START_FLAG_OFF);
	case NBL_CFG_QCN_SENDCNP_FLAG:
		return NBL_CC_REG_ADDR(cc_base, NBL_QCN_SENDCNP_FLAG_OFF);
	case NBL_CFG_QCN_SENDCNP_TIME_TH:
		return NBL_CC_REG_ADDR(cc_base, NBL_QCN_SENDCNP_TIME_TH_OFF);
	case NBL_CFG_QCN_EXTRA_QUANTA:
		return NBL_CC_REG_ADDR(cc_base, NBL_QCN_EXTRA_QUANTA_OFF);
	case NBL_CFG_QCN_FAST_REDUCE_MODE:
		return NBL_CC_REG_ADDR(cc_base, NBL_QCN_FAST_REDUCE_MODE_OFF);
	case NBL_CFG_QCN_REDUCE_COE:
		return NBL_CC_REG_ADDR(cc_base, NBL_QCN_REDUCE_COE_OFF);
	case NBL_CFG_CC_RTT_OFFSET:
		return NBL_CC_REG_ADDR(cc_base, NBL_CC_RTT_OFFSET_OFF);
	case NBL_CFG_CC_RTT_PROBE_INVL:
		return NBL_CC_REG_ADDR(cc_base, NBL_CC_RTT_PROBE_INVL_OFF);
	case NBL_CFG_CC_HIGH_PRI_RTT_INVL:
		return NBL_CC_REG_ADDR(cc_base, NBL_CC_HIGH_PRI_RTT_INVL_OFF);
	case NBL_CFG_CC_HIGH_PRI_RTT_EN:
		return NBL_CC_REG_ADDR(cc_base, NBL_CC_HIGH_RPI_RTT_EN_OFF);
	case NBL_CFG_CC_RST_WIN_HIGH:
		return NBL_CC_REG_ADDR(cc_base, NBL_CC_RST_WIN_H_OFF);
	case NBL_CFG_CC_RST_WIN_EN:
		return NBL_CC_REG_ADDR(cc_base, NBL_CC_RST_WIN_EN_OFF);
	case NBL_CFG_CC_RST_WIN_LOW:
		return NBL_CC_REG_ADDR(cc_base, NBL_CC_RST_WIN_L_OFF);
	case NBL_CFG_CC_RST_WIN_RTT_INT:
	case NBL_CFG_CC_RST_WIN_RTT_FRACTION:
		return NBL_CC_REG_ADDR(cc_base, NBL_CC_RST_TARGETWIN_RTTCOE_OFF);
	case NBL_CFG_CC_DYN_RTT_OFFSET_EN:
		return NBL_CC_REG_ADDR(cc_base, NBL_CC_DYN_RTT_OFFSET_EN_OFF);
	case NBL_CFG_CC_REMOVE_REMOTE_TIME:
		return NBL_CC_REG_ADDR(cc_base, NBL_CC_REMOVE_REMOTE_TIME_OFF);
	case NBL_CFG_CC_RDMA_TIME_SEL:
		return NBL_TXM_REG_ADDR(txm_base,
					 NBL_TXM_RDMA_TIME_SEL_OFF);
	case NBL_CFG_CC_LOW_RTT_OFFSET:
		return NBL_CC_REG_ADDR(cc_base, NBL_CC_AI_LESS_RTTMINTH_OFF);
	case NBL_CFG_CC_HIGH_RTT_OFFSET:
		return NBL_CC_REG_ADDR(cc_base, NBL_CC_AI_MORE_RTTMINTH_OFF);
	case NBL_CFG_CC_RST_WIN_RTT_OFFSET:
		return NBL_CC_REG_ADDR(cc_base, NBL_CC_AI_RST_WIN_RTTMINTH_OFF);
	case NBL_CFG_CC_OAMACK_BLK_TH:
		return NBL_CC_REG_ADDR(cc_base, NBL_CC_SENDACK_BLK_CNT_TH_OFF);
	case NBL_CFG_QCN_TIME_ACCUM:
		return NBL_CC_REG_ADDR(cc_base, NBL_QCN_TIME_ACCUM_OFF);
	case NBL_CFG_QCN_USE_HAI_EN:
		return NBL_CC_REG_ADDR(cc_base, NBL_QCN_USE_HAI_EN_OFF);
	case NBL_CFG_QCN_QUANTA_CC2TXP:
		return NBL_CC_REG_ADDR(cc_base, NBL_QCN_QUANTA_CC2TXP_OFF);
	case NBL_CFG_QCN_CLAMP_RT:
		return NBL_CC_REG_ADDR(cc_base, NBL_QCN_CLAMP_RT_OFF);
	case NBL_CFG_QCN_ALPHA_G:
		return NBL_CC_REG_ADDR(cc_base, NBL_QCN_ALPHA_G_OFF);
	case NBL_CFG_QCN_ALPHA_T:
		return NBL_CC_REG_ADDR(cc_base, NBL_QCN_ALPHA_T_OFF);
	case NBL_CFG_QCN_ALPHA_RPG_RD:
		return NBL_CC_REG_ADDR(cc_base, NBL_QCN_RPG_GD_OFF);
	case NBL_CFG_QCN_ECN_MODE:
		return NBL_CC_REG_ADDR(cc_base, NBL_QCN_ECN_MODE_OFF);
	case NBL_CFG_QCN_SMOOTH_PERIOD:
		return NBL_CC_REG_ADDR(cc_base, NBL_QCN_SMOOTH_PERIOD_OFF);
	case NBL_CFG_QCN_SMOOTH_WEIGHT:
		return NBL_CC_REG_ADDR(cc_base, NBL_QCN_SMOOTH_WEIGHT_OFF);
	case NBL_CFG_QCN_ECN_KMIN:
		return NBL_CC_REG_ADDR(cc_base, NBL_QCN_ADPT_KMIN_OFF);
	case NBL_CFG_QCN_ECN_KMAX:
		return NBL_CC_REG_ADDR(cc_base, NBL_QCN_ADPT_KMAX_OFF);
	case NBL_CFG_QCN_ECN_PMAX:
		return NBL_CC_REG_ADDR(cc_base, NBL_QCN_ADPT_BUFFER_PMAX_OFF);
	case NBL_CFG_QCN_ECN_K:
		return NBL_CC_REG_ADDR(cc_base, NBL_QCN_ADPT_K_PARAM_OFF);
	case NBL_CFG_QCN_TXP_R_CNP_INVL:
		return NBL_TXP_REG_ADDR(txp_base,
					 NBL_TXP_QCN_R_CNP_INVL_OFF);
	case NBL_CFG_QCN_CNP_ACCOMPANIED:
		return NBL_TXP_REG_ADDR(txp_base,
					 NBL_TXP_QCN_CNP_ACCOMPANIED_OFF);
	case NBL_CFG_QCN_BTH_REDUCE_FLAG:
		return NBL_CC_REG_ADDR(cc_base, NBL_QCN_BTH_REDUCE_FLAG_OFF);
	default:
		return 0;
	}
}

int nbl_set_hw_cc_reg(struct nbl_hw *hw, u32 offset, u32 var)
{
	u64 reg_addr;
	u32 offset_addr;
	u32 var_old;
	u64 tmp_addr;
	u32 tmp_offset;
	u32 tmp_var;

	offset_addr = nbl_ib_get_reg_offset_addr(hw, offset);
	if (offset_addr == 0) {
		nbl_pr_err("offset:%d var:%u\n", offset, var);
		return -EINVAL;
	}

	reg_addr = offset_addr;
	switch (offset) {
	case NBL_CFG_CC_EN:
		tmp_offset = nbl_ib_get_reg_offset_addr(
			hw, NBL_CFG_CC_TXP_SENDREQ_DB_CFG);
		if (tmp_offset == 0) {
			nbl_pr_err("tmp_offset:%u\n", tmp_offset);
			return -EINVAL;
		}
		tmp_addr = tmp_offset;
		var_old = rd32(hw, tmp_addr);
		tmp_var = (var_old & 0x7FFFFFFF) | ((var << 31) & 0x80000000);
		wr32(hw, tmp_addr, tmp_var);
		break;
	case NBL_CFG_CC_HIGH_RTT_FRACTION:
	case NBL_CFG_CC_RST_WIN_RTT_FRACTION:
		var_old = rd32(hw, reg_addr);
		var = (var_old & 0xFFFFFF0F) | ((var & 0xF) << 4);
		break;
	case NBL_CFG_CC_LOW_RTT_FRACTION:
		var_old = rd32(hw, reg_addr);
		var = (var_old & 0xFFFFFFF0) | (var & 0xF);
		break;
	case NBL_CFG_CC_HIGH_RTT_INT:
	case NBL_CFG_CC_RST_WIN_RTT_INT:
		var_old = rd32(hw, reg_addr);
		var = (var_old & 0xFF0FFFFF) | ((var & 0xF) << 20);
		break;
	case NBL_CFG_CC_LOW_RTT_INT:
		var_old = rd32(hw, reg_addr);
		var = (var_old & 0xFFF0FFFF) | ((var & 0xF) << 16);
		break;
	case NBL_CFG_CC_TXP_SENDREQ_DB_CFG:
		var_old = rd32(hw, reg_addr);
		/* stop unit 1, send unit 0 */
		var = (var_old & 0xFFF00000) | (var & 0xFFFFF);
		break;
	case NBL_CFG_CC_TARGET_RTTMIN:
		/* bit 0 is enable */
		if (var)
			var = (var << 16) + 1;
		break;
	case NBL_CFG_QCN_CNP_ACCOMPANIED:
		if (var) {
			var = NBL_DEF_QCN_CNP_ACCOMPANIED_EN_VALUE;
			nbl_pr_dbg("reg_addr:0x%llx, offset:%u var:%u\n", (u64)reg_addr, offset,
				var);
		} else {
			var = NBL_DEF_QCN_CNP_ACCOMPANIED_DISABLE_VALUE;
			nbl_pr_dbg("reg_addr:0x%llx, offset:%u var:%u\n", (u64)reg_addr, offset,
				var);
		}
		break;
	case NBL_CFG_QCN_TXP_R_CNP_INVL:
		if (var) {
			var = NBL_DEF_QCN_TXP_R_CNP_INVL;
			wr32(hw, reg_addr, var);
			nbl_pr_dbg("reg_addr:0x%llx, offset:%u var:%u\n", (u64)reg_addr, offset,
				var);
			var = NBL_DEF_QCN_TXP_R_CNP_FIFO;
			offset_addr = NBL_TXP_REG_ADDR(
				NBL_REG_TXP_BASE(hw), NBL_TXP_QCN_R_CNP_FIFO_OFF);
			reg_addr = offset_addr;
		} else {
			var = NBL_DEF_QCN_TXP_R_CNP_INVL_DISABLE;
			wr32(hw, reg_addr, var);
			nbl_pr_dbg("reg_addr:0x%llx, offset:%u var:%u\n", (u64)reg_addr, offset,
				var);
			var = NBL_DEF_QCN_TXP_R_CNP_FIFO_DISABLE;
			offset_addr = NBL_TXP_REG_ADDR(
				NBL_REG_TXP_BASE(hw), NBL_TXP_QCN_R_CNP_FIFO_OFF);
			reg_addr = offset_addr;
		}
		break;
	default:
		break;
	}

	wr32(hw, reg_addr, var);
	nbl_pr_dbg("reg_addr:0x%llx, offset:%u var:%u\n", (u64)reg_addr, offset,
		   var);
	return 0;
}

int nbl_set_cc_glb_cfg(struct nbl_pci_f *rf, u32 offset, u32 var)
{
	return rf->hw.hw_ops->set_hw_cc_reg(&rf->hw, offset, var);
}

void nbl_set_hw_net_tc_tbl(struct nbl_hw *hw)
{
	void *reg_addr = hw->hw_addr + NBL_REG_TXM_BASE(hw);

	writel(0x0, NBL_TXM_NET_TC_TBL_ADDR(reg_addr, 0));
	writel(0x120, NBL_TXM_NET_TC_TBL_ADDR(reg_addr, 1));
	writel(0x240, NBL_TXM_NET_TC_TBL_ADDR(reg_addr, 2));
	writel(0x360, NBL_TXM_NET_TC_TBL_ADDR(reg_addr, 3));
	writel(0x480, NBL_TXM_NET_TC_TBL_ADDR(reg_addr, 4));
	writel(0x5A0, NBL_TXM_NET_TC_TBL_ADDR(reg_addr, 5));
	writel(0x6C0, NBL_TXM_NET_TC_TBL_ADDR(reg_addr, 6));
	writel(0x7E0, NBL_TXM_NET_TC_TBL_ADDR(reg_addr, 7));
}

void nbl_set_net_tc_tbl(struct nbl_pci_f *rf)
{
	rf->hw.hw_ops->set_hw_net_tc_tbl(&rf->hw);
}

/* remark net tc to dscp  */
static void nbl_init_net_tc_tbl(struct nbl_pci_f *rf)
{
	if (rf->dev_ops && rf->dev_ops->set_net_tc_tbl)
		rf->dev_ops->set_net_tc_tbl(rf);
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

	if (ret == 0) {
		dev->rf->sc_dev.cc_dbgfs_params[offset] = var;

		/* Update PT net tc tbl when cc_oamack_tc_en or cc_oamack_net_tc changes */
		if (offset == NBL_CFG_CC_OAMACK_TC_EN)
			nbl_try_init_net_tc_tbl_pt(dev, false, false, true, !!var);
		else if (offset == NBL_CFG_CC_OAMACK_NET_TC)
			nbl_try_init_net_tc_tbl_pt(dev, false, false, false, false);
	}

	return ret;
}

int config_cc_param(struct nbl_device *dev, int offset, u32 var)
{
	int ret;

	if (offset >= NBL_CFG_CC_TYPE_MAX)
		return -EINVAL;

	if (dev->rf->sc_dev.check_cc_param) {
		ret = nbl_ib_check_cc_param_val(dev->rf, offset, var);
		nbl_pr_dbg("config cc param[%d]:%s val:%u\n", offset, nbl_dbg_cc_name[offset], var);
		if (ret) {
			nbl_pr_err(
				"config cc param[%d]:%s val:%u is invalid, please check the param.\n",
				offset, nbl_dbg_cc_name[offset], var);
			return ret;
		}
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
}

static bool nbl_cc_debugfs_param_supported_v2(int offset)
{
	return offset != NBL_CFG_QCN_CLAMP_RT &&
		offset != NBL_CFG_QCN_ALPHA_G &&
		offset != NBL_CFG_QCN_ALPHA_T;
}

static bool nbl_cc_debugfs_param_supported_v4(int offset)
{
	return offset != NBL_CFG_QCN_QUICK_START_FLAG &&
		offset != NBL_CFG_QCN_FAST_REDUCE_MODE &&
		offset != NBL_CFG_QCN_REDUCE_COE;
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
			if (!dev->rf->product->congestion_ops->debugfs_param_supported(i))
				continue;

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

static void nbl_cc_init_default_params_v2(struct nbl_device *dev, int *params)
{
	/* only work in emu, wait for chip back to adjust */
	params[NBL_CFG_QCN_MAX_RATE_RP] = NBL_DEF_QCN_MAX_RATE_RP_V2;
	params[NBL_CFG_QCN_START_RATE] = NBL_DEF_QCN_SET_START_RATE_V2;
	params[NBL_CFG_QCN_MID_SENDBLK_TH_HIGH] =
		NBL_DEF_QCN_MID_SENDBLK_TH_HIGH_V2;
	params[NBL_CFG_QCN_MID_SENDBLK_TH_LOW] =
		NBL_DEF_QCN_MID_SENDBLK_TH_LOW_V2;
	params[NBL_CFG_QCN_MID_SENDTIME_TH_HIGH] =
		NBL_DEF_QCN_MID_SENDTIME_TH_HIGH_V2;
	params[NBL_CFG_QCN_MID_SENDTIME_TH_LOW] =
		NBL_DEF_QCN_MID_SENDTIME_TH_LOW_V2;
	params[NBL_CFG_QCN_EXTRA_QUANTA] = NBL_DEF_QCN_EXTRA_QUANTA_V2;
	params[NBL_CFG_QCN_FAST_REDUCE_MODE] =
		NBL_DEF_QCN_FAST_REDUCE_MODE_V2;
}

static void nbl_cc_init_default_params_v4(struct nbl_device *dev, int *params)
{
	if (dev->rf->sc_dev.pf_count == 1)
		params[NBL_CFG_QCN_START_RATE] = NBL_DEF_QCN_SET_START_RATE_400G_V4;
	else
		params[NBL_CFG_QCN_START_RATE] = NBL_DEF_QCN_SET_START_RATE_200G_V4;
	/* Whether it is RNIC1*400 or 2*200, qcn_max_rate must be set to 400G */
	params[NBL_CFG_QCN_MAX_RATE_RP] = NBL_DEF_QCN_MAX_RATE_RP_400G_V4;
	params[NBL_CFG_QCN_AI_RP] = NBL_DEF_QCN_AI_RP_V4;
	params[NBL_CFG_QCN_HAI_RP] = NBL_DEF_QCN_HAI_RP_V4;
	params[NBL_CFG_QCN_MID_SENDBLK_TH_HIGH] =
		NBL_DEF_QCN_MID_SENDBLK_TH_HIGH_V4;
	params[NBL_CFG_QCN_MID_SENDBLK_TH_LOW] =
		NBL_DEF_QCN_MID_SENDBLK_TH_LOW_V4;
	params[NBL_CFG_QCN_MID_SENDTIME_TH_HIGH] =
		NBL_DEF_QCN_MID_SENDTIME_TH_HIGH_V4;
	params[NBL_CFG_QCN_MID_SENDTIME_TH_LOW] =
		NBL_DEF_QCN_MID_SENDTIME_TH_LOW_V4;
	params[NBL_CFG_QCN_CLAMP_RT] = NBL_DEF_QCN_QUICK_START_FLAG;
	params[NBL_CFG_QCN_ALPHA_G] = NBL_DEF_QCN_ALPHA_G_V4;
	params[NBL_CFG_QCN_ALPHA_T] = NBL_DEF_QCN_ALPHA_T_V4;
	params[NBL_CFG_QCN_ALPHA_RPG_RD] = NBL_DEF_QCN_ALPHA_RPG_RD_V4;
	params[NBL_CFG_QCN_ECN_MODE] = NBL_DEF_QCN_ECN_MODE_V4;
	params[NBL_CFG_QCN_SMOOTH_PERIOD] = NBL_DEF_QCN_SMOOTH_PERIOD_V4;
	params[NBL_CFG_QCN_SMOOTH_WEIGHT] = NBL_DEF_QCN_SMOOTH_WEIGHT_V4;
	params[NBL_CFG_QCN_ECN_KMIN] = NBL_DEF_QCN_ECN_KMIN_V4;
	params[NBL_CFG_QCN_ECN_KMAX] = NBL_DEF_QCN_ECN_KMAX_V4;
	params[NBL_CFG_QCN_ECN_PMAX] = NBL_DEF_QCN_ECN_PMAX_V4;
	params[NBL_CFG_QCN_EXTRA_QUANTA] = NBL_DEF_QCN_EXTRA_QUANTA_V4;
	params[NBL_CFG_QCN_USE_HAI_EN] = NBL_DEF_QCN_USE_HAI_EN_V4;
	params[NBL_CFG_QCN_SENDCNP_TIME_TH] = NBL_DEF_QCN_SENDCNP_TIME_TH_V4;
	params[NBL_CFG_QCN_QUANTA_CC2TXP] = NBL_DEF_QCN_CC2TXP_QUANTA_V4;
	params[NBL_CFG_QCN_RR_TH] = NBL_DEF_QCN_RR_TH_V4;
	params[NBL_CFG_QCN_TXP_R_CNP_INVL] = NBL_DEF_QCN_TXP_R_CNP_INVL_EN;
	params[NBL_CFG_QCN_CNP_ACCOMPANIED] = NBL_DEF_QCN_CNP_ACCOMPANIED_EN;
	params[NBL_CFG_QCN_BTH_REDUCE_FLAG] = NBL_DEF_QCN_BTH_REDUCE_FLAG;
}

static bool nbl_cc_default_param_supported_v2(int offset)
{
	return offset < NBL_CFG_QCN_CLAMP_RT;
}

static bool nbl_cc_default_param_supported_v4(int offset)
{
	return offset != NBL_CFG_QCN_QUICK_START_FLAG &&
		offset != NBL_CFG_QCN_FAST_REDUCE_MODE &&
		offset != NBL_CFG_QCN_REDUCE_COE;
}

static void nbl_cc_init_default_regs_v4(struct nbl_device *dev)
{
	nbl_grc_write_reg(dev->rf,
		NBL_CC_REG_ADDR(NBL_REG_CC_BASE(&dev->rf->hw),
				NBL_QCN_DB_TIME_OUT_OFF),
		NBL_DEF_QCN_DB_TIMEOUT_V4);
	nbl_grc_write_reg(dev->rf,
		NBL_CC_REG_ADDR(NBL_REG_CC_BASE(&dev->rf->hw),
				NBL_QCN_PROC_CNP_INTERVAL_OFF),
		NBL_DEF_QCN_RP_PROC_CNP_TIME);
	nbl_grc_write_reg(dev->rf,
		NBL_CC_REG_ADDR(NBL_REG_CC_BASE(&dev->rf->hw),
				NBL_QCN_NIC_SENDCNP_EN_OFF),
		NBL_DEF_QCN_NIC_SENDCNP_EN);
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
	params[NBL_CFG_CC_RST_WIN_RTT_FRACTION] = NBL_DEF_CC_RST_WIN_RTT_FRACTION;
	params[NBL_CFG_CC_DYN_RTT_OFFSET_EN] = NBL_DEF_CC_DYN_RTT_OFFSET_EN;
	params[NBL_CFG_CC_REMOVE_REMOTE_TIME] = NBL_DEF_CC_REMOVE_REMOTE_TIME;
	params[NBL_CFG_CC_HIGH_RTT_INT] = NBL_DEF_CC_HIGH_RTT_INT;
	params[NBL_CFG_CC_LOW_RTT_INT] = NBL_DEF_CC_LOW_RTT_INT;
	params[NBL_CFG_CC_RDMA_TIME_SEL] = NBL_DEF_CC_RDMA_TIME_SEL;
	params[NBL_CFG_CC_CMP_RTT_QP_MULT] = NBL_DEF_CC_CMP_RTT_QP_MULT;
	params[NBL_CFG_CC_LOW_RTT_OFFSET] = NBL_DEF_CC_LOW_RTT_OFFSET;
	params[NBL_CFG_CC_HIGH_RTT_OFFSET] = NBL_DEF_CC_HIGH_RTT_OFFSET;
	params[NBL_CFG_CC_RST_WIN_RTT_OFFSET] = NBL_DEF_CC_RST_WIN_RTT_OFFSET;
	params[NBL_CFG_CC_TARGET_RTTMIN] = NBL_DEF_CC_TARGET_RTTMIN_CFG;
	params[NBL_CFG_CC_TXP_SENDREQ_DB_CFG] = NBL_DEF_CC_TXP_SENDREQ_DB_CFG;
	// DCQCN
	params[NBL_CFG_QCN_RR_TH] = NBL_DEF_QCN_RR_TH;
	params[NBL_CFG_QCN_MIN_RATE_RP] = NBL_DEF_QCN_MIN_RATE_RP;
	params[NBL_CFG_QCN_SENDCNP_FLAG] = NBL_DEF_QCN_SENDCNP_FLAG;
	params[NBL_CFG_QCN_SENDCNP_TIME_TH] = NBL_DEF_QCN_SENDCNP_TIME_TH;
	params[NBL_CFG_QCN_TIME_ACCUM] = NBL_DEF_QCN_TIME_ACCUM;
	params[NBL_CFG_QCN_USE_HAI_EN] = NBL_DEF_QCN_USE_HAI_EN;
	params[NBL_CFG_QCN_QUANTA_CC2TXP] = NBL_DEF_QCN_CC2TXP_QUANTA;
	params[NBL_CFG_QCN_RR_MODE] = NBL_DEF_QCN_RR_MODE;
	params[NBL_CFG_QCN_MAX_RATE_RP] = NBL_DEF_QCN_MAX_RATE_RP;
	params[NBL_CFG_QCN_START_RATE] = NBL_DEF_QCN_SET_START_RATE;
	params[NBL_CFG_QCN_EXTRA_QUANTA] = NBL_DEF_QCN_EXTRA_QUANTA;
	params[NBL_CFG_QCN_AI_RP] = NBL_DEF_QCN_AI_RP;
	params[NBL_CFG_QCN_HAI_RP] = NBL_DEF_QCN_HAI_RP;
	params[NBL_CFG_QCN_MID_SENDBLK_TH_HIGH] = NBL_DEF_QCN_MID_SENDBLK_TH_HIGH;
	params[NBL_CFG_QCN_MID_SENDBLK_TH_LOW] = NBL_DEF_QCN_MID_SENDBLK_TH_LOW;
	params[NBL_CFG_QCN_MID_SENDTIME_TH_HIGH] = NBL_DEF_QCN_MID_SENDTIME_TH_HIGH;
	params[NBL_CFG_QCN_MID_SENDTIME_TH_LOW] = NBL_DEF_QCN_MID_SENDTIME_TH_LOW;
	params[NBL_CFG_QCN_QUICK_START_FLAG] = NBL_DEF_QCN_QUICK_START_FLAG;
	params[NBL_CFG_QCN_FAST_REDUCE_MODE] = NBL_DEF_QCN_FAST_REDUCE_MODE;
	params[NBL_CFG_QCN_REDUCE_COE] = NBL_DEF_QCN_REDUCE_COE;

	if (dev->rf->product->congestion_ops->init_default_params)
		dev->rf->product->congestion_ops->init_default_params(dev, params);

	for (offset = NBL_CFG_CC_MODE; offset < NBL_CFG_CC_TYPE_MAX; offset++) {
		if (!nbl_product_flag_enabled(dev->rf, NBL_PRODUCT_F_CTRL_DEV)) {
			if (nbl_ib_param_to_cfg_type(offset) == NBL_CC_REG)
				continue;
		}

		if (!dev->rf->product->congestion_ops->default_param_supported(offset))
			continue;
		config_cc_param(dev, offset, params[offset]);
	}

	if (dev->rf->product->congestion_ops->init_default_regs)
		dev->rf->product->congestion_ops->init_default_regs(dev);
};

const struct nbl_congestion_ops nbl_df200_congestion_ops = {
	.debugfs_param_supported = nbl_cc_debugfs_param_supported_v2,
	.default_param_supported = nbl_cc_default_param_supported_v2,
};

const struct nbl_congestion_ops nbl_draco_congestion_ops = {
	.debugfs_param_supported = nbl_cc_debugfs_param_supported_v2,
	.init_default_params = nbl_cc_init_default_params_v2,
	.default_param_supported = nbl_cc_default_param_supported_v2,
};

const struct nbl_congestion_ops nbl_rnic400_congestion_ops = {
	.update_cc_mode = nbl_update_cc_mode_v4,
	.debugfs_param_supported = nbl_cc_debugfs_param_supported_v4,
	.init_default_params = nbl_cc_init_default_params_v4,
	.default_param_supported = nbl_cc_default_param_supported_v4,
	.init_default_regs = nbl_cc_init_default_regs_v4,
};

void nbl_dbgfs_cc_init(struct nbl_device *dev)
{
	nbl_ib_init_cc_debugfs(dev);
	if (!dev->dbg_cc_params) {
		nbl_pr_err("CC CFG loading exited due to insufficient memory.\n");
		return;
	}

	nbl_cc_default_params_init(dev);

	nbl_load_cc_cfg(dev);
	nbl_load_qcn_cfg(dev);

	nbl_init_net_tc_tbl(dev->rf);

	dev->dbg_cc_params->has_init = true;
}

void nbl_dbgfs_cc_deinit(struct nbl_device *dev)
{
	nbl_ib_cleanup_cc_debugfs(dev);
}
