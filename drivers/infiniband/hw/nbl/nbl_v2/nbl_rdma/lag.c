// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2023, NEBULARMATRIX */

#include "main.h"
#include "lag.h"
#include "grc.h"
#include "qp.h"

static void nbl_set_rdma_lag_qpc_fwd_info(struct nbl_pci_f *rf, u8 lag_id,
					  bool lag_en)
{
	struct nbl_core_export *core_info = rf->cdev;

	nbl_ib_dbg(&rf->sc_dev, "set lag_en[%d]\n", lag_en);
	if (lag_en) {
		/* set fwd info to lag */
		rf->sc_dev.fwd = NBL_CPU_FWD;
		rf->sc_dev.dport = NBL_ETH_DPORT;
		rf->sc_dev.dport_id = lag_id; /* BIT 0-3 for DF50 */
		rf->sc_dev.dport_id |= rf->sc_dev.dport_id
				       << 4; /* BIT 4-7 for ASIC V1 */
		rf->sc_dev.rss_lag_en = true;
	} else {
		/* disable holb */
		if (rf->sc_dev.lag_ops)
			rf->sc_dev.lag_ops->nbl_holb_set(rf, false);
		/* recover fwd info */
		nbl_set_default_fwd(rf);
		rf->sc_dev.dport = NBL_DEFAULT_DPORT;
		rf->sc_dev.dport_id = core_info->eth_id;
		rf->sc_dev.rss_lag_en = NBL_DEFAULT_RSS_LAG_EN;
	}
}

static void nbl_set_rdma_lag_en(struct nbl_pci_f *rf, u8 lag_id, bool lag_en)
{
	uintptr_t reg = NBL_TXP_REG_ADDR(NBL_REG_TXP_BASE(&rf->hw),
					 NBL_TXP_LAG_EN_OFF);

	if (lag_id > NBL_MAX_LAG_ID)
		return;

	if (nbl_grc_write_reg(rf, reg, lag_en))
		return;

	nbl_set_rdma_lag_qpc_fwd_info(rf, lag_id, lag_en);

	nbl_ib_dbg(&rf->sc_dev, "set lag_en[%d] dport_id[%d].\n", lag_en,
		   rf->sc_dev.dport_id);
}

/* multi plane en for 4pf bond, mp_en needs the related lag_en bits set together */
void nbl_set_rdma_mp_en(struct nbl_pci_f *rf, bool mp_en)
{
	uintptr_t reg = NBL_TXP_REG_ADDR(NBL_REG_TXP_BASE(&rf->hw),
					 NBL_TXP_LAG_EN_OFF);
	union nbl_rdma_lag_en lag_en;

	if (nbl_grc_read_reg(rf, reg, lag_en.data))
		return;
	lag_en.glb_mp_en = mp_en;
	lag_en.eth_link_fc = mp_en;
	lag_en.eth_pfc = mp_en;
	lag_en.qm_link_fc = mp_en;
	lag_en.qm_pfc = mp_en;
	lag_en.db_mpbp_en = mp_en;
	lag_en.wqe_mpbp_en = mp_en;
	lag_en.plb_en = mp_en;
	if (nbl_grc_write_reg(rf, reg, lag_en.data[0]))
		return;

	reg = NBL_DSCH_REG_ADDR(NBL_REG_DSCH_BASE(&rf->hw),
				NBL_DSCH_MP_EN_OFF);
	if (nbl_grc_write_reg(rf, reg, mp_en ? 1 : 0))
		return;

	rf->sc_dev.mp_en = mp_en;

	/* mp_en change affects holb and dqm bp resp cfg in bond */
	if (rf->sc_dev.lag_ops)
		rf->sc_dev.lag_ops->nbl_holb_set(rf, rf->sc_dev.muti_active_port);

	nbl_ib_dbg(&rf->sc_dev, "set mp_en[%d].\n", mp_en);
}

static void nbl_set_rdma_lag_cfg_v4_reg(struct nbl_pci_f *rf, u8 lag_id,
					unsigned long active_ports,
					int num_ports)
{
	uintptr_t reg;
	struct nbl_rdma_lag_cfg_v4 lag_cfg = {0};
	union nbl_rdma_lag_en lag_en;
	u8 port_list[NBL_RDMA_LAG_MBRS_MAX];
	int port_idx = 0;
	int idx;
	int bit_id;
	int i;

	for_each_set_bit(bit_id, &active_ports, NBL_MAX_PORT_ID + 1)
		port_list[port_idx++] = (u8)bit_id;

	/* fill 128bit lag_cfg, 2bit per entry, round-robin active ports, */
	for (idx = 0; idx < NBL_LAG_CFG_NUM; idx++)
		nbl_lag_cfg_set(&lag_cfg, idx, port_list[idx % num_ports]);

	nbl_ib_dbg(&rf->sc_dev,
		"set lag[%d] active_ports[%#lx] num_ports:%d\n"
		"lag_cfg:%#x %#x %#x %#x %#x %#x %#x %#x\n",
		lag_id, active_ports, num_ports,
		lag_cfg.data[0], lag_cfg.data[1],
		lag_cfg.data[2], lag_cfg.data[3],
		lag_cfg.data[4], lag_cfg.data[5],
		lag_cfg.data[6], lag_cfg.data[7]);

	if (lag_id == NBL_MAX_LAG_ID)
		reg = NBL_TXP_REG_ADDR(NBL_REG_TXP_BASE(&rf->hw),
				       NBL_TXP_LAG_CFG_1_OFF_V4);
	else
		reg = NBL_TXP_REG_ADDR(NBL_REG_TXP_BASE(&rf->hw),
				       NBL_TXP_LAG_CFG_0_OFF_V4);

	for (i = 0; i < NBL_LAG_CFG_REG_NUM; i++)
		nbl_grc_write_reg(rf, reg + i * sizeof(u32), lag_cfg.data[i]);

	/* active_ports to lag_en reg lag_cfg_bm0 for lag0, lag_cfg_bm1 for lag1 */
	reg = NBL_TXP_REG_ADDR(NBL_REG_TXP_BASE(&rf->hw), NBL_TXP_LAG_EN_OFF);
	if (!nbl_grc_read_reg(rf, reg, lag_en.data)) {
		if (lag_id == NBL_MAX_LAG_ID)
			lag_en.lag_cfg_bm1 = (u32)active_ports;
		else
			lag_en.lag_cfg_bm0 = (u32)active_ports;
		nbl_grc_write_reg(rf, reg, lag_en.data[0]);
	}

	if (rf->sc_dev.lag_ops)
		rf->sc_dev.lag_ops->nbl_holb_set(rf, rf->sc_dev.muti_active_port);
}

static void nbl_set_rdma_lag_cfg_reg(struct nbl_pci_f *rf,
				     struct nbl_core_export *core_info)
{
	uintptr_t reg;
	u32 port_bits;
	u8 tmp_bits;
	unsigned long active_ports = 0;
	int num_ports, min_port, max_port;
	int i;
	u8 lag_id = core_info->lag_info.lag_id;

	for (i = 0; i < NBL_RDMA_LAG_MBRS_MAX; i++) {
		if (core_info->lag_info.mbr[i].active)
			active_ports |=
				BIT(core_info->lag_info.mbr[i].eth_id);
	}

	num_ports = bitmap_weight(&active_ports, NBL_MAX_PORT_ID + 1);
	/* if no active port, keep lag_cfg */
	if (num_ports > NBL_RDMA_LAG_MBRS_MAX || num_ports == 0)
		return;
	rf->sc_dev.muti_active_port = num_ports > 1 ? true : false;

	/* for B3xx. LAG_CFG0/1_TABLE=128bit */
	if (nbl_product_cap_enabled(rf, NBL_PRODUCT_CAP_MPLANE_SPRAY)) {
		nbl_set_rdma_lag_cfg_v4_reg(rf, lag_id, active_ports, num_ports);
		return;
	}

	/* only for B1xx. LAG_CFG0/1_TABLE=32bit */
	min_port = find_first_bit(&active_ports, NBL_MAX_PORT_ID + 1);
	if (num_ports == core_info->lag_info.mbr_num)
		max_port = find_next_bit(&active_ports, NBL_MAX_PORT_ID + 1,
					 min_port + 1);
	else
		max_port = min_port;

	/* max 2 ports for lag, max 4 port id[0-3] */
	if (max_port > NBL_MAX_PORT_ID ||
		lag_id > NBL_MAX_LAG_ID) {
		nbl_ib_err(
			&rf->sc_dev,
			"error lag config lag_id:%d num_ports:%d min_port:%d max_port:%d active_ports:%#lx\n",
			lag_id, num_ports, min_port,
			max_port, active_ports);
		return;
	}

	tmp_bits = min_port; /* bit 0-1 */
	tmp_bits |= max_port << 2; /* bit 2-3 */
	tmp_bits |= tmp_bits << 4; /* bit 4-7 */
	memset(&port_bits, tmp_bits, sizeof(u32));

	nbl_dev_dbg(
		&rf->pcidev->dev,
		"num_ports:%d min_port:%d max_port:%d tmp_bits:%#x port_bits:%#x\n",
		num_ports, min_port, max_port, tmp_bits, port_bits);

	if (rf->sc_dev.lag_ops)
		rf->sc_dev.lag_ops->nbl_holb_set(rf, rf->sc_dev.muti_active_port);

	if (lag_id == NBL_MAX_LAG_ID)
		reg = NBL_TXP_REG_ADDR(NBL_REG_TXP_BASE(&rf->hw),
					NBL_TXP_LAG_CFG_1_OFF);
	else
		reg = NBL_TXP_REG_ADDR(NBL_REG_TXP_BASE(&rf->hw),
					NBL_TXP_LAG_CFG_0_OFF);

	nbl_grc_write_reg(rf, reg, port_bits);

	nbl_ib_dbg(&rf->sc_dev,
		   "set lag[%d] active_ports[%#lx], port_bits[%#x].\n",
		   lag_id, active_ports, port_bits);
}

static void nbl_set_rdma_lag_link_chng(struct nbl_pci_f *rf,
				       struct nbl_core_export *core_info)
{
	nbl_set_rdma_lag_cfg_reg(rf, core_info);

	nbl_set_qm_vfid_vsi_map(rf, true);
}

static int nbl_lag_mbr_event(struct notifier_block *notifier,
			     unsigned long event, void *data)
{
	struct nbl_device *nbl_dev = container_of(notifier, struct nbl_device,
						  lag_mbr_nb);
	struct nbl_core_export *core_info = nbl_dev->rf->cdev;
	int i;

	if (event != NBL_CORE_EVT_LAG_MBR)
		return NOTIFY_DONE;

	nbl_pr_info("master eth:%d lag_id:%d lag_num:%d\n",
		core_info->eth_id,
		core_info->lag_info.lag_id,
		core_info->lag_info.mbr_num);
	for (i = 0; i < core_info->lag_info.mbr_num; i++) {
		nbl_pr_info(
			"vsi[%d]:%d eth[%d]:%d active:%d\n",
			i, core_info->lag_info.mbr[i].vsi_id,
			i, core_info->lag_info.mbr[i].eth_id,
			core_info->lag_info.mbr[i].active);
	}
	nbl_set_rdma_lag_link_chng(nbl_dev->rf, core_info);
	return NOTIFY_OK;
}

static int nbl_ovs_offld_event(struct notifier_block *notifier,
			       unsigned long event, void *data)
{
	struct nbl_device *nbl_dev = container_of(notifier, struct nbl_device,
						  ovs_offld_nb);
	bool status;

	if (event != NBL_CORE_EVT_OVS_OFFLD || !data)
		return NOTIFY_DONE;

	status = *(bool *)data;

	nbl_pr_info("offload_status:%d", status);
	nbl_set_rdma_lag_qpc_fwd_info(nbl_dev->rf, 0, false);
	return NOTIFY_OK;
}

/* while rnic400, holb and dscp respond to dqm bp cfg depends on
 * bond state and mp_en:
 * 1: holb en, dqm bp resp dis
 *		A: bond && mp_en=0 && muti_active_port
 * 2、holb dis, dqm bp resp en
 *		B: non-bond
 *		C: bond && mp_en=1
 *		D: bond && mp_en=0 && !muti_active_port
 */
static int nbl_holb_set_rnic_4ports(struct nbl_pci_f *rf, bool muti_active_port)
{
	uintptr_t reg = NBL_DDMUX_REG_ADDR(NBL_REG_DDMUX_BASE(&rf->hw),
					  NBL_DDMUX_HOLB_OFF);
	bool holb_en = rf->sc_dev.rss_lag_en && !rf->sc_dev.mp_en && muti_active_port;
	u32 var = holb_en ? NBL_DDMUX_HOLB_ENABLE : NBL_DDMUX_HOLB_DISABLE;

	if (nbl_grc_write_reg(rf, reg, var)) {
		nbl_pr_err("set ddmux holb reg faile\n");
		return -EFAULT;
	}

	reg = NBL_DSCH_REG_ADDR(NBL_REG_DSCH_BASE(&rf->hw),
				NBL_DSCH_BP_RESP_OFF);
	var = holb_en ? NBL_DSCH_BP_RESP_DQM_DISABLE :
			 NBL_DSCH_BP_RESP_DQM_ENABLE;

	if (nbl_grc_write_reg(rf, reg, var)) {
		nbl_pr_err("set dsch bp resp faile\n");
		return -EINVAL;
	}

	return 0;
}

static int nbl_holb_set_rnic(struct nbl_pci_f *rf, bool muti_active_port)
{
	uintptr_t reg = NBL_DDMUX_REG_ADDR(NBL_REG_DDMUX_BASE(&rf->hw),
					  NBL_DDMUX_HOLB_OFF);
	u32 var = muti_active_port ? NBL_DDMUX_HOLB_ENABLE : NBL_DDMUX_HOLB_DISABLE;

	if (nbl_grc_write_reg(rf, reg, var)) {
		nbl_pr_err("set ddmux holb reg faile\n");
		return -EFAULT;
	}

	reg = NBL_DSCH_REG_ADDR(NBL_REG_DSCH_BASE(&rf->hw),
				NBL_DSCH_BP_RESP_OFF);
	var = muti_active_port ? NBL_DSCH_BP_RESP_DPT_DISABLE :
				 NBL_DSCH_BP_RESP_ALL_ENABLE;

	if (nbl_grc_write_reg(rf, reg, var)) {
		nbl_pr_err("set dsch bp resp faile\n");
		return -EINVAL;
	}

	return 0;
}

static const struct nbl_lag_ops nbl_lag_ops_rnic_4ports = {
	.nbl_holb_set = nbl_holb_set_rnic_4ports,
};

static const struct nbl_lag_ops nbl_lag_ops_rnic = {
	.nbl_holb_set = nbl_holb_set_rnic,
};

static int nbl_register_lag_notifiers(struct nbl_device *nbl_dev,
				      struct nbl_core_export *core_info)
{
	int err;

	nbl_dev->lag_mbr_nb.notifier_call = nbl_lag_mbr_event;
	err = blocking_notifier_chain_register(&core_info->lag_mbr_nh,
					       &nbl_dev->lag_mbr_nb);
	if (err)
		goto register_lag_mbr_err;

	nbl_dev->ovs_offld_nb.notifier_call = nbl_ovs_offld_event;
	err = blocking_notifier_chain_register(&core_info->ovs_offld_nh,
					       &nbl_dev->ovs_offld_nb);
	if (err)
		goto register_ovs_offld_err;

	return 0;

register_ovs_offld_err:
	nbl_dev->ovs_offld_nb.notifier_call = NULL;
	blocking_notifier_chain_unregister(&core_info->lag_mbr_nh,
					 &nbl_dev->lag_mbr_nb);
register_lag_mbr_err:
	nbl_dev->lag_mbr_nb.notifier_call = NULL;
	return err;
}

int nbl_init_lag(struct nbl_device *nbl_dev, struct nbl_core_export *core_info)
{
	struct nbl_pci_f *rf = nbl_dev->rf;
	int ret;
	u8 mirror_id = (u8)NBL_GET_MIRROR_ID(rf->sc_dev.function_id);

	/* RNIC lag ops
	 * sub_type 1 (B1xx 1X400) no lag ops
	 * sub_type 2 (B1xx 2X200) nbl_lag_ops_rnic
	 * sub_type 4 (B3xx 4X100) nbl_lag_ops_rnic_4ports
	 * sub_type 5 (B3xx 2X200) nbl_lag_ops_rnic_4ports
	 * sub_type 6 (B3xx 1X400) no lag ops
	 */
	rf->sc_dev.lag_ops = NULL;
	if (core_info->is_lag) {
		if (nbl_product_get_sub_type(rf) == RNIC_SUB_TYPE_B300_2X200 ||
			nbl_product_get_sub_type(rf) == RNIC_SUB_TYPE_B300_4X100) {
			nbl_set_rdma_mp_en(rf, false);
			rf->sc_dev.lag_ops = &nbl_lag_ops_rnic_4ports;
		} else if (nbl_product_get_sub_type(rf) == RNIC_SUB_TYPE_2X200)
			rf->sc_dev.lag_ops = &nbl_lag_ops_rnic;

		ret = nbl_register_lag_notifiers(nbl_dev, core_info);
		if (ret)
			return ret;

		nbl_core_rcv_rdma_driver_probed(core_info->pdev, true);
		nbl_set_rdma_lag_en(rf, core_info->lag_info.lag_id, true);
		nbl_set_rdma_lag_cfg_reg(rf, core_info);
		if (nbl_product_flag_enabled(rf,
					     NBL_PRODUCT_F_LAG_MIRROR_CFG)) {
			ret = nbl_core_rcv_rdma_mirror_cfg(&rf->adev->adev,
						       mirror_id);
			if (ret)
				nbl_ib_warn(&rf->sc_dev,
					    "config mirror_id=%u for lag ret=%d",
					    mirror_id, ret);
		}
	}
	/* if disable lag, qpc.rss_lag_en will be zero, so not need to recover txp rdma_lag_en */
	return 0;
}

void nbl_deinit_lag(struct nbl_device *nbl_dev,
		    struct nbl_core_export *core_info)
{
	if (nbl_dev->ovs_offld_nb.notifier_call) {
		blocking_notifier_chain_unregister(&core_info->ovs_offld_nh,
						   &nbl_dev->ovs_offld_nb);
		nbl_dev->ovs_offld_nb.notifier_call = NULL;
	}

	if (nbl_dev->lag_mbr_nb.notifier_call) {
		blocking_notifier_chain_unregister(&core_info->lag_mbr_nh,
						   &nbl_dev->lag_mbr_nb);
		nbl_dev->lag_mbr_nb.notifier_call = NULL;
	}

	nbl_core_rcv_rdma_driver_probed(core_info->pdev, false);
}
