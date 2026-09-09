// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2022, nebula-matrix Limited */

#include <linux/debugfs.h>

#include "grc.h"
#include "main.h"
#include "dbgfs.h"

#define NBL_RDMA_QOS_DENTRY_LEN 256
#define NBL_RDMA_QOS_CFG_DEFAULT_DENTRY "/etc/nebulamatrix/rdma/qos_params/."
#define NBL_RDMA_QOS_CFG_DEV_DEFAULT_DENTRY                                    \
	"/etc/nebulamatrix/rdma/%s/qos_params/."

#define NBL_QOS_DEFAULT_TC_WGT 0x04010401 /* SQ:RAQ 1:4:1:4 */
#define NBL_QOS_DEFAULT_TC2PRI 0x6D2240

const char *const nbl_dbg_qos_name[] = {
	/* golbal */
	"save",
	"tc2pri",
	"sq_pri_map",
	"raq_pri_map",
	"pri_imap",
	"pfc_imap",
	"db_to_csch_en",
	"sw_db_csch_th",
	"csch_qlen_th",
	"poll_wgt",
	/* function base */
	"sp_wrr",
	"tc_wgt",
	"set_pfc",
	"trust_dscp_en",
	"pfc_buf",
	"dscp_to_pri",
	"8021p_to_pri"
};

static void set_pri(union pkt_cos_map_table *table, u32 pri, u32 value)
{
	value &= 0x7;
	table->data[0] = (table->data[0] & ~(0x7 << (pri * 4))) | (value << (pri * 4));
}

static u32 get_pri(union pkt_cos_map_table *table, u32 pri)
{
	return (table->data[0] >> (pri * 4)) & 0x7;
}

static void nbl_fill_dpt_pfc_map(union dpt_pfc_map_rdma *map, u8 dqm_dpt,
				 u8 dsch_dpt)
{
	switch (dqm_dpt) {
	case 0:
		map->dpt0 = 1 << dsch_dpt;
		break;
	case 1:
		map->dpt1 = 1 << dsch_dpt;
		break;
	case 2:
		map->dpt2 = 1 << dsch_dpt;
		break;
	case 3:
		map->dpt3 = 1 << dsch_dpt;
		break;
	default:
		break;
	}
}
static int nbl_set_dpt_pfc_map(struct nbl_device *dev)
{
	int ret;
	union dpt_pfc_map_rdma map;
	struct nbl_core_dev_info *cdev_info =
		(struct nbl_core_dev_info *)dev->rf->cdev;

	ret = nbl_grc_read_reg(dev->rf, NBL_REG_DSCH_DPT_PFC_MAP_RDMA,
			       &map.data);
	if (ret) {
		nbl_pr_err(
			"failed to read dsch_dpt_pfc_map_rdma into reg:%#x\n",
			NBL_REG_DQM_RXMAC_TX_PORT_BP_EN);
		return ret;
	}

	if (cdev_info->is_lag) {
		int i;

		for (i = 0; i < cdev_info->lag_info.lag_num; i++) {
			nbl_fill_dpt_pfc_map(
				&map, cdev_info->lag_info.lag_mem[i].eth_id,
				cdev_info->eth_id);
		}
	} else
		nbl_fill_dpt_pfc_map(&map, cdev_info->eth_id,
				     cdev_info->eth_id);

	ret = nbl_grc_write_reg(dev->rf, NBL_REG_DSCH_DPT_PFC_MAP_RDMA,
				map.data);
	if (ret) {
		nbl_pr_err(
			"failed to write dsch_dpt_pfc_map_rdma into reg:%#x val:%#x\n",
			NBL_REG_DSCH_DPT_PFC_MAP_RDMA, map.data);
		return ret;
	}
	nbl_pr_dbg("write dsch_dpt_pfc_map_rdma into reg:%#x val:%#x\n",
		   NBL_REG_DSCH_DPT_PFC_MAP_RDMA, map.data);
	return 0;
}

static int nbl_set_pfc_en_one(struct nbl_device *dev, u32 *var, u32 dport_id)
{
	int i, ret;
	u32 reg_offset;
	u32 enable = 0;
	u32 cos_en = 0;
	union dqm_rxmac_tx_port_bp_en_table dqm_port_bp = {0};
	union dqm_rxmac_tx_cos_bp_en_table dqm_cos_bp = {0};
	union ustore_fc_th_table ustore_port_fc = {0};
	union ustore_fc_th_table ustore_cos_fc;

	for (i = 0; i < NBL_PRI_NUM; i++) {
		if (var[i])
			enable = 1;
		cos_en |= var[i] << i;
	}

	/* 1 rx pfc */
	/* 1.1 dqm_rxmac_tx_port_bp_en */
	/* 1.2 dqm_rxmac_tx_cos_bp_en */
	ret = nbl_grc_read_reg(dev->rf, NBL_REG_DQM_RXMAC_TX_PORT_BP_EN, &dqm_port_bp.data[0]);
	if (ret) {
		nbl_pr_err("failed to read dqm_port_bp_en[eth:%d] into reg:%#x val:%#x\n",
			dport_id, NBL_REG_DQM_RXMAC_TX_PORT_BP_EN, dqm_port_bp.data[0]);
		return ret;
	}

	ret = nbl_grc_read_reg(dev->rf, NBL_REG_DQM_RXMAC_TX_COS_BP_EN, &dqm_cos_bp.data[0]);
	if (ret) {
		nbl_pr_err("failed to read dqm_cos_bp_en[eth:%d] into reg:%#x val:%#x\n",
			dport_id, NBL_REG_DQM_RXMAC_TX_COS_BP_EN, dqm_cos_bp.data[0]);
		return ret;
	}

	switch (dport_id) {
	case 0:
		dqm_port_bp.eth0 = !enable;
		dqm_cos_bp.eth0 = cos_en;
		break;
	case 1:
		dqm_port_bp.eth1 = !enable;
		dqm_cos_bp.eth1 = cos_en;
		break;
	case 2:
		dqm_port_bp.eth2 = !enable;
		dqm_cos_bp.eth2 = cos_en;
		break;
	case 3:
		dqm_port_bp.eth3 = !enable;
		dqm_cos_bp.eth3 = cos_en;
		break;
	default:
		return 0;
	}

	ret = nbl_grc_write_reg(dev->rf, NBL_REG_DQM_RXMAC_TX_PORT_BP_EN, dqm_port_bp.data[0]);
	if (ret) {
		nbl_pr_err("failed to write dqm_port_bp_en[eth:%d] into reg:%#x val:%#x\n",
			dport_id, NBL_REG_DQM_RXMAC_TX_PORT_BP_EN, dqm_port_bp.data[0]);
		return ret;
	}

	ret = nbl_grc_write_reg(dev->rf, NBL_REG_DQM_RXMAC_TX_COS_BP_EN, dqm_cos_bp.data[0]);
	if (ret) {
		nbl_pr_err("failed to write dqm_cos_bp_en[eth:%d] into reg:%#x val:%#x\n",
			dport_id, NBL_REG_DQM_RXMAC_TX_COS_BP_EN, dqm_cos_bp.data[0]);
		return ret;
	}

	/* 2 tx pfc */
	/* 2.1 ustore_pfc_merge */
	reg_offset = NBL_REG_USTORE_PFC_MERGE;
	ret = nbl_grc_write_reg(dev->rf, reg_offset, 0);
	if (ret) {
		nbl_pr_err("failed to write ustore_pfc_merge into reg:%#x\n", reg_offset);
		return ret;
	}

	/* 2.2 ustore_port_fc_th */
	reg_offset = NBL_REG_USTORE_PORT_FC_TH(dport_id);
	ret = nbl_grc_read_reg(dev->rf, reg_offset, &ustore_port_fc.data[0]);
	if (ret) {
		nbl_pr_err("failed to read ustore_port_fc[eth:%d] into reg:%#x val:%#x\n",
			dport_id, reg_offset, ustore_port_fc.data[0]);
		return ret;
	}

	ustore_port_fc.fc_en = !enable;
	ret = nbl_grc_write_reg(dev->rf, reg_offset, ustore_port_fc.data[0]);
	if (ret) {
		nbl_pr_err("failed to write ustore_port_fc[eth:%d] into reg:%#x val:%#x\n",
			dport_id, reg_offset, ustore_port_fc.data[0]);
		return ret;
	}

	/* 2.3 ustore_cos_fc_th */
	for (i = 0; i < NBL_PRI_NUM; i++) {
		memset(&ustore_cos_fc, 0, sizeof(ustore_cos_fc));
		reg_offset = NBL_REG_USTORE_COS_FC_TH(dport_id) + 4 * i;
		ret = nbl_grc_read_reg(dev->rf, reg_offset, &ustore_cos_fc.data[0]);
		if (ret) {
			nbl_pr_err("failed to read ustore_cos_fc[eth:%d][pri:%d] into reg:%#x val:%#x\n",
				dport_id, i, reg_offset, ustore_cos_fc.data[0]);
			return ret;
		}

		ustore_cos_fc.fc_en = var[i];
		ret = nbl_grc_write_reg(dev->rf, reg_offset, ustore_cos_fc.data[0]);
		if (ret) {
			nbl_pr_err("failed to write ustore_cos_fc[eth:%d][pri:%d] into reg:%#x val:%#x\n",
				dport_id, i, reg_offset, ustore_cos_fc.data[0]);
			return ret;
		}
	}

	return ret;
}

static int nbl_set_pfc_en(struct nbl_device *dev, u32 *var)
{
	int i;
	int ret_val = 0;
	struct nbl_core_dev_info *cdev_info =
		(struct nbl_core_dev_info *)dev->rf->cdev;

	if (!cdev_info->is_lag) {
		ret_val =
			nbl_set_pfc_en_one(dev, var, dev->rf->sc_dev.dport_id);
		if (ret_val) {
			nbl_pr_err("nbl_set_pfc_en_one error:%d\n", ret_val);
			return ret_val;
		}
	} else {
		for (i = 0; i < cdev_info->lag_info.lag_num; i++) {
			ret_val = nbl_set_pfc_en_one(
				dev, var,
				cdev_info->lag_info.lag_mem[i].eth_id);
			if (ret_val) {
				nbl_pr_err("nbl_set_pfc_en_one error:%d\n",
					   ret_val);
				return ret_val;
			}
		}
	}

	ret_val = nbl_set_dpt_pfc_map(dev);
	if (ret_val) {
		nbl_pr_err("nbl_set_dpt_pfc_map error:%d\n", ret_val);
		return ret_val;
	}

	return 0;
}

static int nbl_trust_dscp_en_one(struct nbl_device *dev, u32 enable,
				 u32 dport_id)
{
	int i, ret;
	u32 reg_offset;
	union upa_pri_sel_conf pri_sel = {0};
	union upa_pri_conf_table pri_conf = {0};

	/* 1.set upa_pri_sel_conf */
	pri_sel.in_in_vlan = !enable;
	pri_sel.in_out_vlan = !enable;
	pri_sel.out_in_vlan = !enable;
	pri_sel.out_out_vlan = !enable;
	pri_sel.trust_vlan = !enable;
	reg_offset = NBL_REG_UPA_PRI_SEL_CONF(dport_id);
	ret = nbl_grc_write_reg(dev->rf, reg_offset, pri_sel.data[0]);
	if (ret) {
		nbl_pr_err("failed to set upa_pri_sel_conf[%#x] into reg:%#x val:%#x\n",
			dport_id, reg_offset, pri_sel.data[0]);
		return ret;
	}

	/* 2.set upa_pri_conf_table */
	reg_offset = NBL_REG_UPA_PRI_CONF_TABLE(dport_id);
	if (enable) { /* set dscp */
		pri_conf.data[0] = 0x00000000;
		pri_conf.data[1] = 0x11111111;
		pri_conf.data[2] = 0x22222222;
		pri_conf.data[3] = 0x33333333;
		pri_conf.data[4] = 0x44444444;
		pri_conf.data[5] = 0x55555555;
		pri_conf.data[6] = 0x66666666;
		pri_conf.data[7] = 0x77777777;
		for (i = 0; i < NBL_PRI_NUM; i++) {
			ret += nbl_grc_write_reg(dev->rf, reg_offset + 4 * i, pri_conf.data[i]);
			if (ret)
				nbl_pr_err("failed to set upa_pri_conf_table[%#x] into reg:%#x val:%#x\n",
					dport_id, reg_offset + 4 * i, pri_conf.data[i]);
		}
	} else { /* set 8021p */
		pri_conf.pri0 = 0;
		pri_conf.pri1 = 1;
		pri_conf.pri2 = 2;
		pri_conf.pri3 = 3;
		pri_conf.pri4 = 4;
		pri_conf.pri5 = 5;
		pri_conf.pri6 = 6;
		pri_conf.pri7 = 7;
		ret += nbl_grc_write_reg(dev->rf, reg_offset, pri_conf.data[0]);
		if (ret)
			nbl_pr_err("failed to set upa_pri_conf_table[%#x] into reg:%#x val:%#x\n",
				dport_id, reg_offset, pri_conf.data[0]);
	}

	return ret;
}

static int nbl_trust_dscp_en(struct nbl_device *dev, u32 enable)
{
	int i;
	int ret_val = 0;
	struct nbl_core_dev_info *cdev_info =
		(struct nbl_core_dev_info *)dev->rf->cdev;

	if (!cdev_info->is_lag)
		ret_val = nbl_trust_dscp_en_one(dev, enable,
						dev->rf->sc_dev.dport_id);
	else {
		for (i = 0; i < cdev_info->lag_info.lag_num; i++) {
			ret_val = nbl_trust_dscp_en_one(
				dev, enable,
				cdev_info->lag_info.lag_mem[i].eth_id);
			if (ret_val)
				return ret_val;
		}
	}
	return 0;
}

static int nbl_set_pfc_buf(struct nbl_device *dev, u32 *var)
{
	u32 ret = 0;
	u32 reg_offset;
	union ustore_fc_th_table ustore_pfc_buf = {0};
	u32 dport_id = dev->rf->sc_dev.dport_id;

	reg_offset = NBL_REG_USTORE_COS_FC_TH(dport_id) + 4 * var[NBL_PFC_CFG_PRI_OFFSET];
	ret = nbl_grc_read_reg(dev->rf, reg_offset, &ustore_pfc_buf.data[0]);
	if (ret) {
		nbl_pr_err("failed to read ustore_pfc_buf before write :%#x val:%#x\n",
			reg_offset, ustore_pfc_buf.data[0]);
		return ret;
	}

	ustore_pfc_buf.xoff_th = var[NBL_PFC_CFG_XOFF_OFFSET];
	ustore_pfc_buf.xon_th = var[NBL_PFC_CFG_XON_OFFSET];

	ret = nbl_grc_write_reg(dev->rf, reg_offset, ustore_pfc_buf.data[0]);
	if (ret)
		nbl_pr_err("failed to write ustore_pfc_buf into reg:%#x val:%#x\n",
			reg_offset, ustore_pfc_buf.data[0]);

	return ret;
}

static int nbl_set_pkt2pri_one(struct nbl_device *dev, bool is_dscp, u32 *var, u32 dport_id)
{

	u32 ret;
	u32 idx;
	int pkt = var[NBL_PKT2PRI_CFG_PKT_OFFSET];
	int pri = var[NBL_PKT2PRI_CFG_PRI_OFFSET];
	u32 reg_offset;
	union pkt_cos_map_table pkt_cos_map = {0};

	idx =  pkt / NBL_PRI_NUM;
	reg_offset = NBL_REG_UPA_PRI_CONF_TABLE(dport_id) + 4 * idx;

	ret = nbl_grc_read_reg(dev->rf, reg_offset, &pkt_cos_map.data[0]);
	if (ret) {
		nbl_pr_err("failed to read up_pkt_cos_map[%d] reg:%#x val:%#x\n",
			idx, reg_offset, pkt_cos_map.data[0]);
		return ret;
	}

	set_pri(&pkt_cos_map, pkt % NBL_PRI_NUM, pri);
	ret = nbl_grc_write_reg(dev->rf, reg_offset, pkt_cos_map.data[0]);
	if (ret) {
		nbl_pr_err("failed to write up_pkt_cos_map[%d] into reg:%#x val:%#x\n",
			idx, reg_offset, pkt_cos_map.data[0]);
		return ret;
	}

	return 0;
}

static int nbl_set_pkt2pri(struct nbl_device *dev, bool is_dscp, u32 *var)
{
	int i;
	int ret_val = 0;
	struct nbl_core_dev_info *cdev_info = (struct nbl_core_dev_info *)dev->rf->cdev;

	if (!cdev_info->is_lag)
		ret_val = nbl_set_pkt2pri_one(dev, is_dscp, var, dev->rf->sc_dev.dport_id);
	else {
		for (i = 0; i < cdev_info->lag_info.lag_num; i++) {
			ret_val = nbl_set_pkt2pri_one(dev, is_dscp, var,
				cdev_info->lag_info.lag_mem[i].eth_id);
			if (ret_val)
				return ret_val;
		}
	}

	return ret_val;
}

static int nbl_ib_save_process(struct nbl_device *dev)
{
	int ret = 0;
	char src_dir[NBL_RDMA_DENTRY_LEN];
	char dst_dir[NBL_RDMA_DENTRY_LEN];
	struct dentry *dentry_path = NULL;

	/* 1. dst_dir */
	if (dev->ibdev.name[0] == '\0')
		return 0;

	dentry_path = dev->qos_params->qos_root;
	ret = snprintf(dst_dir, sizeof(dst_dir),
		       NBL_RDMA_QOS_CFG_DEV_DEFAULT_DENTRY, dev->ibdev.name);
	if (ret < 0)
		return ret;
	nbl_pr_info("dst_dir=%s\n", dst_dir);

	if (!nbl_dentry_is_exist(dst_dir)) {
		char *path = "/bin/mkdir";
		char *argv[4] = { path, "-p", dst_dir, NULL };
		char *envp[1] = { NULL };

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

static int nbl_load_qos_dev_cfg(struct nbl_device *dev)
{
	int ret;
	char func_default_dir[NBL_RDMA_DENTRY_LEN];
	char src_dir[NBL_RDMA_DENTRY_LEN];
	char dst_dir[NBL_RDMA_DENTRY_LEN];

	/* 1. src_dir */
	ret = snprintf(func_default_dir, sizeof(func_default_dir),
		       NBL_RDMA_QOS_CFG_DEV_DEFAULT_DENTRY, dev->ibdev.name);
	if (ret < 0)
		return ret;
	if (nbl_dentry_is_exist(func_default_dir))
		strscpy(src_dir, func_default_dir, sizeof(src_dir));
	else if (nbl_dentry_is_exist(NBL_RDMA_QOS_CFG_DEFAULT_DENTRY))
		strscpy(src_dir, NBL_RDMA_QOS_CFG_DEFAULT_DENTRY, sizeof(src_dir));
	else {
		nbl_pr_dbg("%s doesn't have default qos cfg.\n",
			   NBL_RDMA_QOS_CFG_DEFAULT_DENTRY);
		return -ENOTDIR;
	}
	nbl_pr_dbg("src_dir=%s\n", src_dir);

	/* 2. dst_dir */
	ret = nbl_ib_get_debugfs_absolute_path(dev, dev->qos_params->qos_root,
					       dst_dir);
	if (ret < 0)
		return ret;
	nbl_pr_dbg("dst_dir=%s\n", dst_dir);

	/* 3. cp -r src_dir dst_dir */
	ret = nbl_ib_copy_dentry(src_dir, dst_dir);

	return ret;
}

static u32 nbl_get_qos_reg_offset(struct nbl_pci_f *rf, int offset)
{
	switch (offset) {
	case NBL_CFG_SQ_PRI_MAP:
		return NBL_REG_DSCH_SQ_PRI_MAP_CFG;
	case NBL_CFG_RAQ_PRI_MAP:
		return NBL_REG_DSCH_RAQ_PRI_MAP_CFG;
	case NBL_CFG_TC_PRI:
	case NBL_CFG_PRI_IMAP:
		return NBL_REG_DSCH_IMAP_CFG;
	case NBL_CFG_PFC_IMAP:
		return NBL_REG_DSCH_PRI03_MAP_CFG;
	case NBL_CFG_DB_TO_CSCH_EN:
		return NBL_REG_DSCH_DB_TO_CSCH_EN;
	case NBL_CFG_SW_DB_CSCH_TH:
		return NBL_REG_DSCH_SW_DB_IN_CSCH_TH;
	case NBL_CFG_CSCH_QLEN_TH:
		return NBL_REG_DSCH_CSCH_QLEN_TH;
	case NBL_CFG_POLL_WGT:
		return NBL_REG_DSCH_POLL_WGT;
	case NBL_CFG_SPWRR:
		return NBL_REG_DSCH_SPWRR_CFG;
	case NBL_CFG_TC_WGT:
		/* get the tc0 for base reg addr */
		return NBL_REG_DSCH_TC_WGT_CFG_TBL(rf->sc_dev.function_id, 0);
	default:
		return 0;
	}
}

static int nbl_get_pfc_cfg(struct nbl_device *dev, char *lbuf)
{
	u32 i, ret;
	u32 reg_offset;
	u32 pfc_en[NBL_PRI_NUM] = {0};
	union ustore_fc_th_table ustore_cos_fc[NBL_PRI_NUM];
	union ustore_fc_th_table ustore_pfc_buf[NBL_PRI_NUM] = {0};
	u32 dport_id = dev->rf->sc_dev.dport_id;

	for (i = 0; i < NBL_PRI_NUM; i++) {
		reg_offset = NBL_REG_USTORE_COS_FC_TH(dport_id) + 4 * i;
		ret = nbl_grc_read_reg(dev->rf, reg_offset, &ustore_cos_fc[i].data[0]);
		if (ret) {
			nbl_pr_err("failed to read ustore_cos_fc[eth:%d][pri:%d] into reg:%#x\n",
				dport_id, i, reg_offset);
			return ret;
		}
		pfc_en[i] = ustore_cos_fc[i].fc_en;
	}

	for (i = 0; i < NBL_PRI_NUM; i++) {
		reg_offset = NBL_REG_USTORE_COS_FC_TH(dport_id);

		ret = nbl_grc_read_reg(dev->rf, (reg_offset + i * 4), &ustore_pfc_buf[i].data[0]);
		if (ret) {
			nbl_pr_err("failed to read ustore_pfc_buf[%d] form reg:%#x val:%#x\n",
				i, reg_offset, ustore_pfc_buf[i].data[0]);
			return ret;
		}
	}
	ret = snprintf(lbuf, NBL_PARAM_LEN, "PFC configuration:\n");
	ret += snprintf(lbuf + ret, NBL_PARAM_LEN - ret,
		"priority     0    1    2    3    4    5    6    7\n");
	ret += snprintf(lbuf + ret, NBL_PARAM_LEN - ret,
		"enable   %5d%5d%5d%5d%5d%5d%5d%5d\n",
		pfc_en[0], pfc_en[1], pfc_en[2], pfc_en[3],
		pfc_en[4], pfc_en[5], pfc_en[6], pfc_en[7]);
		ret += snprintf(lbuf + ret, NBL_PARAM_LEN - ret,
		"xoff     %5d%5d%5d%5d%5d%5d%5d%5d\n",
		ustore_pfc_buf[0].xoff_th, ustore_pfc_buf[1].xoff_th,
		ustore_pfc_buf[2].xoff_th, ustore_pfc_buf[3].xoff_th,
		ustore_pfc_buf[4].xoff_th, ustore_pfc_buf[5].xoff_th,
		ustore_pfc_buf[6].xoff_th, ustore_pfc_buf[7].xoff_th);
	ret += snprintf(lbuf + ret, NBL_PARAM_LEN - ret,
		"xon      %5d%5d%5d%5d%5d%5d%5d%5d\n",
		ustore_pfc_buf[0].xon_th, ustore_pfc_buf[1].xon_th,
		ustore_pfc_buf[2].xon_th, ustore_pfc_buf[3].xon_th,
		ustore_pfc_buf[4].xon_th, ustore_pfc_buf[5].xon_th,
		ustore_pfc_buf[6].xon_th, ustore_pfc_buf[7].xon_th);

	return ret;
}

static int nbl_get_pkt2pri_cfg(struct nbl_device *dev, char *lbuf)
{
	u32 i, cnt, ret, len;
	u32 reg_offset;
	bool is_dscp = false;
	u32 dport_id = dev->rf->sc_dev.dport_id;
	union pkt_cos_map_table pkt_cos_map[NBL_PRI_NUM] = {0};
	union upa_pri_sel_conf pri_sel = {0};

	ret = nbl_grc_read_reg(dev->rf, NBL_REG_UPA_PRI_SEL_CONF(dport_id), &pri_sel.data[0]);
	if (ret) {
		nbl_pr_err("failed to read upa_pri_sel_conf[%#x] into reg:%#x\n",
		dport_id, NBL_REG_UPA_PRI_SEL_CONF(dport_id));
	}

	if (pri_sel.trust_vlan) { /* 8021p */
		len = snprintf(lbuf, NBL_PARAM_LEN, "priority trust stat: 8021p\n");
		len += snprintf(lbuf+len, NBL_PARAM_LEN-len, "8021p pri\n");
	} else { /* DSCP */
		len = snprintf(lbuf, NBL_PARAM_LEN, "priority trust stat: dscp\n");
		len += snprintf(lbuf+len, NBL_PARAM_LEN-len, "dscp pri\n");
		is_dscp = true;
	}
	reg_offset = NBL_REG_UPA_PRI_CONF_TABLE(dport_id);
	cnt = is_dscp ? NBL_PRI_NUM : 1;
	for (i = 0; i < cnt; i++) {
		ret = nbl_grc_read_reg(dev->rf, reg_offset + 4 * i, &pkt_cos_map[i].data[0]);
		if (ret) {
			nbl_pr_err("failed to read upa_pri_sel_conf[%#x] into reg:%#x\n",
				dport_id, NBL_REG_UPA_PRI_SEL_CONF(dport_id));
		}
	}

	cnt = is_dscp ? NBL_DSCP_NUM : NBL_PRI_NUM;
	for (i = 0; i < cnt; i++) {
		len += snprintf(lbuf + len, NBL_PARAM_LEN - len,
		"%-3d%1d\n", i,
		get_pri(&pkt_cos_map[i/NBL_PRI_NUM], i%NBL_PRI_NUM));
	}

	return len;
}

static int nbl_ib_check_qos_param_val(int offset, u32 *var_arr, int var_cnt)
{
	int ret = 0;
	int i;
	int pkt_max;

	switch (offset) {
	case NBL_CFG_TC_PRI:
		if (var_cnt != NBL_PRI_NUM) {
			nbl_pr_err("qos params %s var_cnt:%d is invalid.\n",
				   nbl_dbg_qos_name[offset], var_cnt);
			return -EINVAL;
		}
		for (i = 0; i < NBL_PRI_NUM; i++) {
			if (var_arr[i] > SCH_NET_TC_MAX) {
				nbl_pr_err(
					"qos params %s val[%d]:%d(%#x) is invalid.\n",
					nbl_dbg_qos_name[offset], i, var_arr[i],
					var_arr[i]);
				return -EINVAL;
			}
		}
		break;
	case NBL_CFG_SPWRR:
		if (var_arr[0] > NBL_SPWRR_CFG_MAX)
			return -EINVAL;
		break;
	case NBL_CFG_SQ_PRI_MAP:
	case NBL_CFG_RAQ_PRI_MAP:
	case NBL_CFG_PRI_IMAP:
	case NBL_CFG_TC_WGT:
	case NBL_CFG_PFC_IMAP:
		if (var_cnt != NBL_PRI_NUM) {
			nbl_pr_err("qos params %s var_cnt:%d is invalid.\n",
				   nbl_dbg_qos_name[offset], var_cnt);
			return -EINVAL;
		}
		for (i = 0; i < NBL_PRI_NUM; i++) {
			if (((offset == NBL_CFG_TC_WGT ||
			      offset == NBL_CFG_PFC_IMAP) &&
			     var_arr[i] > NBL_WGT_PFC_IMAP_MAX_VAL) ||
			    (offset != NBL_CFG_TC_WGT &&
			     offset != NBL_CFG_PFC_IMAP &&
			     var_arr[i] > NBL_PRI_MAX_VAL)) {
				nbl_pr_err(
					"qos params %s val[%d]:%d(%#x) is invalid.\n",
					nbl_dbg_qos_name[offset], i, var_arr[i],
					var_arr[i]);
				return -EINVAL;
			}
		}
		break;
	case NBL_CFG_DB_TO_CSCH_EN:
		if (var_arr[0] > NBL_DB_TO_CSCH_EN_MASK)
			return -EINVAL;
		break;
	case NBL_CFG_SW_DB_CSCH_TH:
	case NBL_CFG_CSCH_QLEN_TH:
		if (var_arr[0] > NBL_SW_DB_CSCH_TH_MAX)
			return -EINVAL;
		break;
	case NBL_CFG_POLL_WGT:
		if (var_cnt != NBL_POLL_WGT_NUM) {
			nbl_pr_err("qos params %s var_cnt:%d is invalid.\n",
				   nbl_dbg_qos_name[offset], var_cnt);
			return -EINVAL;
		}
		for (i = 0; i < NBL_POLL_WGT_NUM; i++) {
			if (var_arr[i] > NBL_WGT_PFC_IMAP_MAX_VAL) {
				nbl_pr_err(
					"qos params %s val[%d]:%d(%#x) is invalid.\n",
					nbl_dbg_qos_name[offset], i, var_arr[i],
					var_arr[i]);
				return -EINVAL;
			}
		}
		break;
	case NBL_CFG_SET_PFC:
		if (var_cnt != NBL_PRI_NUM) {
			nbl_pr_err("qos params %s var_cnt:%d is invalid.\n",
				   nbl_dbg_qos_name[offset], var_cnt);
			return -EINVAL;
		}
		for (i = 0; i < NBL_PRI_NUM; i++) {
			if (var_arr[i] > NBL_ENABLE_MASK) {
				nbl_pr_err(
					"qos params %s val[%d]:%d(%#x) is invalid.\n",
					nbl_dbg_qos_name[offset], i, var_arr[i],
					var_arr[i]);
				return -EINVAL;
			}
		}
		break;
	case NBL_CFG_TRUST_DSCP_EN:
		if (var_arr[0] > NBL_ENABLE_MASK)
			return -EINVAL;
		break;
	case NBL_CFG_SET_PFC_BUF:
		if (var_cnt != NBL_PFC_CFG_NUM) {
			nbl_pr_err("qos params %s var_cnt:%d is invalid.\n",
				   nbl_dbg_qos_name[offset], var_cnt);
			return -EINVAL;
		}

		if (var_arr[NBL_PFC_CFG_PRI_OFFSET] > NBL_PRI_NUM) {
			nbl_pr_err("qos params %s val[%d]:%d(%#x) is invalid.\n",
				nbl_dbg_qos_name[offset], NBL_PFC_CFG_PRI_OFFSET,
				var_arr[NBL_PFC_CFG_PRI_OFFSET], var_arr[NBL_PFC_CFG_PRI_OFFSET]);
			return -EINVAL;
		}

		if (var_arr[NBL_PFC_CFG_XOFF_OFFSET] < var_arr[NBL_PFC_CFG_XON_OFFSET]) {
			nbl_pr_err("qos params %s xoff[%d] < xon[%d] is invalid.\n",
				nbl_dbg_qos_name[offset], var_arr[NBL_PFC_CFG_XOFF_OFFSET],
				var_arr[NBL_PFC_CFG_XON_OFFSET]);
			return -EINVAL;
		}

		if (var_arr[NBL_PFC_CFG_XOFF_OFFSET] > NBL_PFC_BUF_MAX_VAL ||
			var_arr[NBL_PFC_CFG_XON_OFFSET] > NBL_PFC_BUF_MAX_VAL) {
			nbl_pr_err("qos params %s xoff or xon should be less than 1620.\n",
				nbl_dbg_qos_name[offset]);
			return -EINVAL;
		}
		break;
	case NBL_CFG_SET_DSCP_TO_PRI:
	case NBL_CFG_SET_8021P_TO_PRI:
		if (var_cnt != NBL_PKT2PRI_CFG_NUM) {
			nbl_pr_err("qos params %s var_cnt:%d is invalid.\n",
				   nbl_dbg_qos_name[offset], var_cnt);
			return -EINVAL;
		}

		pkt_max = offset == NBL_CFG_SET_DSCP_TO_PRI ? NBL_DSCP_NUM : NBL_PRI_NUM;
		if (var_arr[NBL_PKT2PRI_CFG_PKT_OFFSET] > pkt_max) {
			nbl_pr_err("qos params %s. the 1st param[%d] should be less than %d\n",
				nbl_dbg_qos_name[offset],
				var_arr[NBL_PKT2PRI_CFG_PRI_OFFSET], pkt_max);
			return -EINVAL;
		}

		if (var_arr[NBL_PKT2PRI_CFG_PRI_OFFSET] > NBL_PRI_NUM) {
			nbl_pr_err("qos params %s. the 2nd param[%d] should be less than %d\n",
				nbl_dbg_qos_name[offset],
				var_arr[NBL_PKT2PRI_CFG_PRI_OFFSET], NBL_PRI_NUM);
			return -EINVAL;
		}
		break;
	case NBL_CFG_QOS_SAVE:
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

static int nbl_ib_set_qos_param_into_reg(struct nbl_device *dev, int offset,
					 u32 *var)
{
	int ret;
	u32 reg_offset;
	union rdma_sq_raq_pri_map_cfg pri_map;
	union rdma_tc_wgt_cfg_tbl tc_wgt_map;
	union rdma_pfc_imap_cfg pfc_imap;
	union rdma_poll_wgt_cfg poll_wgt;

	reg_offset = nbl_get_qos_reg_offset(dev->rf, offset);
	if (!reg_offset && (offset < NBL_CFG_SET_PFC))
		return -EINVAL;
	switch (offset) {
	case NBL_CFG_TC_PRI:
	case NBL_CFG_SQ_PRI_MAP:
	case NBL_CFG_RAQ_PRI_MAP:
	case NBL_CFG_PRI_IMAP:
		pri_map.pri0 = var[0];
		pri_map.pri1 = var[1];
		pri_map.pri2 = var[2];
		pri_map.pri3 = var[3];
		pri_map.pri4 = var[4];
		pri_map.pri5 = var[5];
		pri_map.pri6 = var[6];
		pri_map.pri7 = var[7];
		ret = nbl_grc_write_reg(dev->rf, reg_offset, pri_map.data[0]);
		if (ret)
			nbl_pr_err(
				"failed to set qos params %s into reg:%#x val:%#x\n",
				nbl_dbg_qos_name[offset], reg_offset,
				pri_map.data[0]);
		if (offset == NBL_CFG_TC_PRI)
			dev->rf->sc_dev.tc2pri = pri_map.data[0];
		break;

	case NBL_CFG_TC_WGT:
		tc_wgt_map.tc0_wgt = var[0];
		tc_wgt_map.tc1_wgt = var[1];
		tc_wgt_map.tc2_wgt = var[2];
		tc_wgt_map.tc3_wgt = var[3];
		tc_wgt_map.tc4_wgt = var[4];
		tc_wgt_map.tc5_wgt = var[5];
		tc_wgt_map.tc6_wgt = var[6];
		tc_wgt_map.tc7_wgt = var[7];
		/* 64bit wide reg, split two write op */
		ret = nbl_grc_write_reg(dev->rf, reg_offset,
					tc_wgt_map.data[0]);
		ret += nbl_grc_write_reg(dev->rf, reg_offset + 4,
					 tc_wgt_map.data[1]);
		if (ret)
			nbl_pr_err(
				"failed to set qos params %s into reg:%#x val:%#x %#x\n",
				nbl_dbg_qos_name[offset], reg_offset,
				tc_wgt_map.data[0], tc_wgt_map.data[1]);
		break;
	case NBL_CFG_PFC_IMAP:
		pfc_imap.pri0_map = var[0];
		pfc_imap.pri1_map = var[1];
		pfc_imap.pri2_map = var[2];
		pfc_imap.pri3_map = var[3];
		pfc_imap.pri4_map = var[4];
		pfc_imap.pri5_map = var[5];
		pfc_imap.pri6_map = var[6];
		pfc_imap.pri7_map = var[7];
		/* 64bit wide reg, split two write op */
		ret = nbl_grc_write_reg(dev->rf, reg_offset, pfc_imap.data[0]);
		ret += nbl_grc_write_reg(dev->rf, reg_offset + 4,
					 pfc_imap.data[1]);
		if (ret)
			nbl_pr_err(
				"failed to set qos params %s into reg:%#x val:%#x %#x\n",
				nbl_dbg_qos_name[offset], reg_offset,
				pfc_imap.data[0], pfc_imap.data[1]);
		break;
	case NBL_CFG_DB_TO_CSCH_EN:
	case NBL_CFG_SW_DB_CSCH_TH:
	case NBL_CFG_CSCH_QLEN_TH:
	case NBL_CFG_SPWRR:
		ret = nbl_grc_write_reg(dev->rf, reg_offset, var[0]);
		if (ret)
			nbl_pr_err(
				"failed to set qos params %s into reg:%#x val:%#x\n",
				nbl_dbg_qos_name[offset], reg_offset, var[0]);
		break;
	case NBL_CFG_POLL_WGT:
		poll_wgt.csch = var[0];
		poll_wgt.sch = var[1];
		poll_wgt.rnr = var[2];
		poll_wgt.rto = var[3];
		ret = nbl_grc_write_reg(dev->rf, reg_offset, poll_wgt.data[0]);
		if (ret)
			nbl_pr_err(
				"failed to set qos params %s into reg:%#x val:%#x\n",
				nbl_dbg_qos_name[offset], reg_offset,
				poll_wgt.data[0]);
		break;
	case NBL_CFG_SET_PFC:
		ret = nbl_set_pfc_en(dev, var);
		break;
	case NBL_CFG_TRUST_DSCP_EN:
		ret = nbl_trust_dscp_en(dev, var[0]);
		break;
	case NBL_CFG_SET_PFC_BUF:
		ret = nbl_set_pfc_buf(dev, var);
		break;
	case NBL_CFG_SET_DSCP_TO_PRI:
	case NBL_CFG_SET_8021P_TO_PRI:
		ret = nbl_set_pkt2pri(dev, (offset == NBL_CFG_SET_DSCP_TO_PRI), var);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

static int nbl_ib_set_qos_params(struct nbl_device *dev, int offset, u32 *var)
{
	int ret;

	/* does not work during initialization */
	if (offset == NBL_CFG_QOS_SAVE) {
		ret = nbl_ib_save_process(dev);
		if (ret)
			nbl_pr_err("failed to save qos params\n");
	} else {
		ret = nbl_ib_set_qos_param_into_reg(dev, offset, var);
		if (ret)
			nbl_pr_err("failed to set qos params into reg.\n");
	}

	return ret;
}

static ssize_t set_qos_param(struct file *filp, const char __user *buf,
			     size_t count, loff_t *pos)
{
	struct nbl_ib_dbg_param *param = filp->private_data;
	int offset = param->offset;
	char lbuf[256] = {};
	char save_buf[256] = {};
	char *s = lbuf;
	int ret;
	int i;
	int eth_id;
	u32 var_arr[NBL_PRI_NUM];
	int var_cnt = 0;
	struct nbl_device *nbl_dev = param->dev;
	struct nbl_pci_f *rf = nbl_dev->rf;
	union rdma_tc_wgt_cfg_tbl *tc_wgt = &rf->sc_dev.tc_wgt;
	struct nbl_core_dev_info *cdev_info = (struct nbl_core_dev_info *)rf->cdev;

	if (count > sizeof(lbuf))
		return -EINVAL;

	if (copy_from_user(lbuf, buf, count))
		return -EFAULT;

	nbl_pr_dbg("config qos param:%s val:%s count:%ld\n",
		   param->dentry->d_iname, lbuf, count);
	strscpy(save_buf, lbuf, sizeof(save_buf));
	while (s && *s) {
		char *str = strsep(&s, ",");
		u32 var;

		if (!str)
			continue;

		if (kstrtou32(str, 0, &var))
			goto err;

		if (var_cnt >= NBL_PRI_NUM)
			goto err;

		var_arr[var_cnt] = var;
		nbl_pr_dbg("var[%d]:%d(%#x)\n", var_cnt, var, var);
		var_cnt++;
	}

	ret = nbl_ib_check_qos_param_val(offset, var_arr, var_cnt);
	if (ret) {
		nbl_pr_err(
			"config qos param:%s is invalid, please check the param.\n",
			param->dentry->d_iname);
		return ret;
	}

	ret = nbl_ib_set_qos_params(param->dev, offset, var_arr);
	if (ret != 0)
		return count;

	switch (offset) {
	case NBL_CFG_TC_WGT:
		tc_wgt->tc0_wgt = var_arr[0];
		tc_wgt->tc1_wgt = var_arr[1];
		tc_wgt->tc2_wgt = var_arr[2];
		tc_wgt->tc3_wgt = var_arr[3];
		tc_wgt->tc4_wgt = var_arr[4];
		tc_wgt->tc5_wgt = var_arr[5];
		tc_wgt->tc6_wgt = var_arr[6];
		tc_wgt->tc7_wgt = var_arr[7];
		break;
	case NBL_CFG_SET_PFC:
	case NBL_CFG_TRUST_DSCP_EN:
		if (!cdev_info->is_lag) {
			eth_id = rf->sc_dev.dport_id;
			strscpy(rf->qos_eth_dbgfs_params[eth_id][offset], save_buf,
				sizeof(rf->qos_eth_dbgfs_params[eth_id][offset]));
			nbl_pr_dbg("save %s:%s\n", nbl_dbg_qos_name[offset],
				rf->qos_eth_dbgfs_params[eth_id][offset]);
		} else {
			for (i = 0; i < cdev_info->lag_info.lag_num; i++) {
				eth_id = cdev_info->lag_info.lag_mem[i].eth_id;
				strscpy(rf->qos_eth_dbgfs_params[eth_id][offset], save_buf,
					sizeof(rf->qos_eth_dbgfs_params[eth_id][offset]));
				nbl_pr_dbg("save %s:%s\n", nbl_dbg_qos_name[offset],
					rf->qos_eth_dbgfs_params[eth_id][offset]);
			}
		}
		break;
	default:
		strscpy(rf->sc_dev.qos_dbgfs_params[offset], save_buf,
			sizeof(rf->sc_dev.qos_dbgfs_params[offset]));
		nbl_pr_dbg("save %s:%s\n", nbl_dbg_qos_name[offset],
				rf->sc_dev.qos_dbgfs_params[offset]);
		break;
	}

	return ret ? ret : count;
err:
	nbl_pr_err("config qos param:%s is invalid, please check the param.\n",
		   param->dentry->d_iname);
	return -EINVAL;
}

static int nbl_get_tc2pri_cfg(struct nbl_device *dev, char *lbuf)
{
	int ret;
	u32 reg_offset;
	u32 tc2pri;
	struct nbl_pci_f *rf = dev->rf;

	reg_offset = nbl_get_qos_reg_offset(rf, NBL_CFG_PRI_IMAP);
	ret = nbl_grc_read_reg(rf, reg_offset, &tc2pri);
	if (ret) {
		nbl_pr_err("failed to read tc2pri into reg:%#x\n", reg_offset);
		return ret;
	}

	rf->sc_dev.tc2pri = tc2pri;

	memset(lbuf, '\0', NBL_PARAM_LEN);
	ret = snprintf(lbuf, NBL_PARAM_LEN,
			"%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu\n",
			NBL_GET_PRI_FROM_T2P(rf->sc_dev.tc2pri, 0),
			NBL_GET_PRI_FROM_T2P(rf->sc_dev.tc2pri, 1),
			NBL_GET_PRI_FROM_T2P(rf->sc_dev.tc2pri, 2),
			NBL_GET_PRI_FROM_T2P(rf->sc_dev.tc2pri, 3),
			NBL_GET_PRI_FROM_T2P(rf->sc_dev.tc2pri, 4),
			NBL_GET_PRI_FROM_T2P(rf->sc_dev.tc2pri, 5),
			NBL_GET_PRI_FROM_T2P(rf->sc_dev.tc2pri, 6),
			NBL_GET_PRI_FROM_T2P(rf->sc_dev.tc2pri, 7));
	return ret;
}

static ssize_t get_qos_param(struct file *filp, char __user *buf, size_t count,
			     loff_t *pos)
{
	struct nbl_ib_dbg_param *param = filp->private_data;
	struct nbl_device *nbl_dev = param->dev;
	struct nbl_pci_f *rf = nbl_dev->rf;
	int offset = param->offset;
	union rdma_tc_wgt_cfg_tbl *tc_wgt;
	int ret;
	char lbuf[NBL_PARAM_LEN];
	struct nbl_core_dev_info *cdev_info = (struct nbl_core_dev_info *)param->dev->rf->cdev;

	switch (offset) {
	case NBL_CFG_TC_PRI:
		ret = nbl_get_tc2pri_cfg(nbl_dev, lbuf);
		break;
	case NBL_CFG_TC_WGT:
		tc_wgt = &rf->sc_dev.tc_wgt;
		memset(lbuf, '\0', NBL_PARAM_LEN);
		ret = snprintf(lbuf, sizeof(lbuf), "%d,%d,%d,%d,%d,%d,%d,%d\n",
			       tc_wgt->tc0_wgt, tc_wgt->tc1_wgt,
			       tc_wgt->tc2_wgt, tc_wgt->tc3_wgt,
			       tc_wgt->tc4_wgt, tc_wgt->tc5_wgt,
			       tc_wgt->tc6_wgt, tc_wgt->tc7_wgt);
		break;
	case NBL_CFG_SET_PFC:
	case NBL_CFG_TRUST_DSCP_EN:
		if (!cdev_info->is_lag)
			ret = snprintf(lbuf, sizeof(lbuf), "%s",
			    rf->qos_eth_dbgfs_params[rf->sc_dev.dport_id][offset]);
		else
			ret = snprintf(lbuf, sizeof(lbuf), "%s",
			rf->qos_eth_dbgfs_params[cdev_info->lag_info.lag_mem[0].eth_id][offset]);
		break;
	case NBL_CFG_SET_PFC_BUF:
		ret = nbl_get_pfc_cfg(nbl_dev, lbuf);
		break;
	case NBL_CFG_SET_DSCP_TO_PRI:
	case NBL_CFG_SET_8021P_TO_PRI:
		ret = nbl_get_pkt2pri_cfg(nbl_dev, lbuf);
		break;
	default:
		ret = snprintf(lbuf, sizeof(lbuf), "%s",
			       rf->sc_dev.qos_dbgfs_params[offset]);
		break;
	}
	return simple_read_from_buffer(buf, count, pos, lbuf, ret);
}

ssize_t config_qos_param(struct nbl_device *nbldev, int offset, char *lbuf)
{
	char save_buf[NBL_PARAM_LEN] = {0};
	char *s = lbuf;
	int ret;
	int i;
	int eth_id;
	u32 var_arr[NBL_PRI_NUM];
	int var_cnt = 0;
	struct nbl_pci_f *rf = nbldev->rf;
	union rdma_tc_wgt_cfg_tbl *tc_wgt = &rf->sc_dev.tc_wgt;
	struct nbl_core_dev_info *cdev_info = (struct nbl_core_dev_info *)rf->cdev;

	strscpy(save_buf, lbuf, sizeof(save_buf));
	while (s && *s) {
		char *str = strsep(&s, ",");
		u32 var;

		if (!str)
			continue;

		if (kstrtou32(str, 0, &var))
			goto err;

		if (var_cnt >= NBL_PRI_NUM)
			goto err;

		var_arr[var_cnt] = var;
		nbl_pr_dbg("var[%d]:%d(%#x)\n", var_cnt, var, var);
		var_cnt++;
	}

	ret = nbl_ib_check_qos_param_val(offset, var_arr, var_cnt);
	if (ret) {
		nbl_pr_err(
			"config qos param:%s is invalid, please check the param.\n",
			nbl_dbg_qos_name[offset]);
		return ret;
	}

	ret = nbl_ib_set_qos_params(nbldev, offset, var_arr);
	if (ret != 0)
		return ret;

	switch (offset) {
	case NBL_CFG_TC_WGT:
		tc_wgt->tc0_wgt = var_arr[0];
		tc_wgt->tc1_wgt = var_arr[1];
		tc_wgt->tc2_wgt = var_arr[2];
		tc_wgt->tc3_wgt = var_arr[3];
		tc_wgt->tc4_wgt = var_arr[4];
		tc_wgt->tc5_wgt = var_arr[5];
		tc_wgt->tc6_wgt = var_arr[6];
		tc_wgt->tc7_wgt = var_arr[7];
		break;
	case NBL_CFG_SET_PFC:
	case NBL_CFG_TRUST_DSCP_EN:
		if (!cdev_info->is_lag) {
			eth_id = rf->sc_dev.dport_id;
			strscpy(rf->qos_eth_dbgfs_params[eth_id][offset], save_buf,
				sizeof(rf->qos_eth_dbgfs_params[eth_id][offset]));
			nbl_pr_dbg("save %s:%s\n", nbl_dbg_qos_name[offset],
				rf->qos_eth_dbgfs_params[eth_id][offset]);
		} else {
			for (i = 0; i < cdev_info->lag_info.lag_num; i++) {
				eth_id = cdev_info->lag_info.lag_mem[i].eth_id;
				strscpy(rf->qos_eth_dbgfs_params[eth_id][offset], save_buf,
					sizeof(rf->qos_eth_dbgfs_params[eth_id][offset]));
				nbl_pr_dbg("save %s:%s\n", nbl_dbg_qos_name[offset],
					rf->qos_eth_dbgfs_params[eth_id][offset]);
			}
		}
		break;
	default:
		strscpy(rf->sc_dev.qos_dbgfs_params[offset], save_buf,
			sizeof(rf->sc_dev.qos_dbgfs_params[offset]));
		nbl_pr_dbg("save %s:%s\n", nbl_dbg_qos_name[offset],
				rf->sc_dev.qos_dbgfs_params[offset]);
		break;
	}

	return ret;
err:
	nbl_pr_err("config qos param:%s is invalid, please check the param.\n",
		   nbl_dbg_qos_name[offset]);
	return -EINVAL;
}

int show_qos_param(struct nbl_device *nbldev, int offset, char *lbuf)
{
	struct nbl_pci_f *rf = nbldev->rf;
	union rdma_tc_wgt_cfg_tbl *tc_wgt;
	struct nbl_core_dev_info *cdev_info = (struct nbl_core_dev_info *)rf->cdev;
	int ret;

	switch (offset) {
	case NBL_CFG_TC_PRI:
		ret = nbl_get_tc2pri_cfg(nbldev, lbuf);
		break;
	case NBL_CFG_TC_WGT:
		tc_wgt = &rf->sc_dev.tc_wgt;
		memset(lbuf, '\0', NBL_PARAM_LEN);
		ret = snprintf(lbuf, NBL_PARAM_LEN, "%d,%d,%d,%d,%d,%d,%d,%d\n",
			       tc_wgt->tc0_wgt, tc_wgt->tc1_wgt,
			       tc_wgt->tc2_wgt, tc_wgt->tc3_wgt,
			       tc_wgt->tc4_wgt, tc_wgt->tc5_wgt,
			       tc_wgt->tc6_wgt, tc_wgt->tc7_wgt);
		break;
	case NBL_CFG_SET_PFC:
	case NBL_CFG_TRUST_DSCP_EN:
		if (!cdev_info->is_lag)
			ret = snprintf(lbuf, NBL_PARAM_LEN, "%s",
			    rf->qos_eth_dbgfs_params[rf->sc_dev.dport_id][offset]);
		else
			ret = snprintf(lbuf, NBL_PARAM_LEN, "%s",
			rf->qos_eth_dbgfs_params[cdev_info->lag_info.lag_mem[0].eth_id][offset]);
		break;
	case NBL_CFG_SET_PFC_BUF:
		ret = nbl_get_pfc_cfg(nbldev, lbuf);
		break;
	case NBL_CFG_SET_DSCP_TO_PRI:
	case NBL_CFG_SET_8021P_TO_PRI:
		ret = nbl_get_pkt2pri_cfg(nbldev, lbuf);
		break;
	default:
		ret = snprintf(lbuf, NBL_PARAM_LEN, "%s",
			       rf->sc_dev.qos_dbgfs_params[offset]);
		break;
	}

	return ret;
}

static const struct file_operations dbg_qos_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.write = set_qos_param,
	.read = get_qos_param,
};

static void nbl_ib_cleanup_qos_debugfs(struct nbl_device *dev)
{
	if (!dev->func_dbg_dir || !dev->qos_params)
		return;
	/* just for debug, not return */
	if (!dev->qos_params->qos_root)
		pr_err("before debugfs_remove_recursive(dev->qos_params->qos_root)\r\n");

	debugfs_remove_recursive(dev->qos_params->qos_root);
	kfree(dev->qos_params);
	dev->qos_params = NULL;
}

ssize_t nbl_qos_cfg_store(struct auxiliary_device *adev, int offset, const char *buf, size_t count)
{
	struct nbl_device *nbl_dev = dev_get_drvdata(&adev->dev);
	char save_buf[NBL_PARAM_LEN] = {0};
	ssize_t ret;

	nbl_pr_dbg("recv qos_cfg_store cb,offset=%d,buf=%s\n", offset, buf);
	strscpy(save_buf, buf, sizeof(save_buf));
	ret = config_qos_param(nbl_dev, offset, save_buf);

	return ret ? ret : count;
}

ssize_t nbl_qos_cfg_show(struct auxiliary_device *adev, int offset, char *buf)
{
	struct nbl_device *nbl_dev = dev_get_drvdata(&adev->dev);
	char lbuf[NBL_PARAM_LEN];
	int ret;

	nbl_pr_dbg("recv qos_cfg_show cb,offset=%d\n", offset);
	ret = show_qos_param(nbl_dev, offset, lbuf);
	return ret < 0 ? ret : sprintf(buf, "%s\n", lbuf);
}

static int nbl_ib_init_qos_debugfs(struct nbl_device *dev)
{
	struct nbl_ib_dbg_qos_params *qos_params;
	int i;

	if (!dev->func_dbg_dir)
		return -EINVAL;

	qos_params = kzalloc(sizeof(*qos_params), GFP_KERNEL);
	if (!qos_params) {
		dev->qos_params = NULL;
		return -ENOMEM;
	}

	dev->qos_params = qos_params;
	qos_params->qos_root =
		debugfs_create_dir("qos_params", dev->func_dbg_dir);
	if (!qos_params->qos_root) {
		nbl_pr_err("init qos_params directory failed\n");
		kfree(dev->qos_params);
		dev->qos_params = NULL;
		return -ENOMEM;
	}

	for (i = NBL_CFG_QOS_SAVE; i < NBL_CFG_QOS_TYPE_MAX; i++) {
		qos_params->params[i].offset = i;
		qos_params->params[i].dev = dev;
		qos_params->params[i].dentry = debugfs_create_file(
			nbl_dbg_qos_name[i], 0600, qos_params->qos_root,
			&qos_params->params[i], &dbg_qos_fops);
	}

	return 0;
}

static void nbl_qos_default_cfg(struct nbl_device *dev)
{
	dev->rf->sc_dev.tc2pri = NBL_QOS_DEFAULT_TC2PRI;
	nbl_grc_write_reg(
		dev->rf,
		NBL_REG_DSCH_TC_WGT_CFG_TBL(dev->rf->sc_dev.function_id, 0),
		NBL_QOS_DEFAULT_TC_WGT);

	nbl_grc_write_reg(
		dev->rf,
		NBL_REG_DSCH_TC_WGT_CFG_TBL(dev->rf->sc_dev.function_id, 4),
		NBL_QOS_DEFAULT_TC_WGT);
}

void nbl_debugfs_qos_dev_init(struct nbl_device *dev)
{
	if (nbl_ib_init_qos_debugfs(dev)) {
		nbl_pr_err("nbl_ib_init_qos_debugfs failed.\n");
		return;
	}

	nbl_qos_default_cfg(dev);

	nbl_load_qos_dev_cfg(dev);
}

void nbl_debugfs_qos_dev_deinit(struct nbl_device *dev)
{
	nbl_ib_cleanup_qos_debugfs(dev);
}
