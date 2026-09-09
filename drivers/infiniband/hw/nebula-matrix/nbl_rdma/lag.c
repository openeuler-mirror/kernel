// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2023, NEBULARMATRIX */

#include"main.h"
#include"lag.h"
#include"grc.h"
#include"qp.h"

static void nbl_set_rdma_lag_qpc_fwd_info(struct nbl_pci_f *rf, u8 lag_id,
					  bool lag_en)
{
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
		struct nbl_core_dev_info *cdev_info = rf->cdev;
		/* recover fwd info */
		rf->sc_dev.fwd = NBL_DEFAULT_FWD;
		rf->sc_dev.dport = NBL_DEFAULT_DPORT;
		rf->sc_dev.dport_id = cdev_info->eth_id;
		rf->sc_dev.rss_lag_en = NBL_DEFAULT_RSS_LAG_EN;
	}
}

static void nbl_set_rdma_lag_en(struct nbl_pci_f *rf, u8 lag_id, bool lag_en)
{
	uintptr_t reg = NBL_REG_TXP_LAG_EN;

	if (lag_id > NBL_MAX_LAG_ID)
		return;

	/* need the lag_en debugfs configure */
	if (nbl_grc_write_reg(rf, reg, lag_en))
		return;

	nbl_set_rdma_lag_qpc_fwd_info(rf, lag_id, lag_en);

	nbl_ib_dbg(&rf->sc_dev, "set lag_en[%d] dport_id[%d].\n", lag_en,
		   rf->sc_dev.dport_id);
}

static void nbl_set_rdma_lag_cfg_reg(struct nbl_pci_f *rf,
		struct nbl_core_dev_info *cdev_info)
{
	uintptr_t reg;
	u32 port_bits;
	u8 tmp_bits;
	unsigned long active_ports = 0;
	int num_ports, min_port, max_port;
	int i;

	for (i = 0; i < NBL_RDMA_LAG_MAX_PORTS; i++) {
		if (cdev_info->lag_info.lag_mem[i].active)
			active_ports |=
				BIT(cdev_info->lag_info.lag_mem[i].eth_id);
	}

	num_ports = bitmap_weight(&active_ports, NBL_MAX_PORT_ID + 1);
	/* if no active port, keep lag_cfg */
	if (num_ports > NBL_RDMA_LAG_MAX_PORTS || num_ports == 0)
		return;

	min_port = find_first_bit(&active_ports, NBL_MAX_PORT_ID + 1);
	if (num_ports == NBL_RDMA_LAG_MAX_PORTS)
		max_port = find_next_bit(&active_ports, NBL_MAX_PORT_ID + 1,
					 min_port + 1);
	else
		max_port = min_port;

	/* max 2 ports for lag, max 4 port id[0-3] */
	if (max_port > NBL_MAX_PORT_ID ||
	    cdev_info->lag_info.lag_id > NBL_MAX_LAG_ID) {
		nbl_ib_err(
			&rf->sc_dev,
			"error lag config lag_id:%d num_ports:%d min_port:%d max_port:%d active_ports:%#lx\n",
			cdev_info->lag_info.lag_id, num_ports, min_port,
			max_port, active_ports);
		return;
	}

	tmp_bits = min_port; /* bit 0-1 */
	tmp_bits |= max_port << 2; /* bit 2-3 */
	tmp_bits |= tmp_bits << 4; /* bit 4-7 */
	memset(&port_bits, tmp_bits, sizeof(u32));

	nbl_ib_dbg(
		&rf->sc_dev,
		"num_ports:%d min_port:%d max_port:%d tmp_bits:%#x port_bits:%#x\n",
		num_ports, min_port, max_port, tmp_bits, port_bits);

	if (cdev_info->lag_info.lag_id == NBL_MAX_LAG_ID)
		reg = NBL_REG_TXP_LAG_CFG_1;
	else
		reg = NBL_REG_TXP_LAG_CFG_0;

	nbl_grc_write_reg(rf, reg, port_bits);

	nbl_ib_dbg(&rf->sc_dev,
		   "set lag[%d] active_ports[%#lx], port_bits[%#x].\n",
		   cdev_info->lag_info.lag_id, active_ports, port_bits);
}

static void nbl_set_rdma_lag_link_chng(struct nbl_pci_f *rf,
				struct nbl_core_dev_info *cdev_info)
{
	nbl_set_rdma_lag_cfg_reg(rf, cdev_info);
	nbl_set_vfid_vsi_map(rf, true);
}

static int nbl_lag_mem_notify(struct auxiliary_device *adev,
			      struct nbl_core_dev_lag_info *lag_info)
{
	struct nbl_aux_dev *nbl_adev =
		container_of(adev, struct nbl_aux_dev, adev);
	struct nbl_core_dev_info *cdev_info = nbl_adev->cdev_info;
	struct nbl_device *nbl_dev = dev_get_drvdata(&adev->dev);

	nbl_pr_info(
		"master eth:%d lag_id:%d lag_num:%d vsi[0]:%d eth[0]:%d active:%d vsi[1]:%d eth[1]:%d active:%d\n",
		cdev_info->eth_id, cdev_info->lag_info.lag_id,
		cdev_info->lag_info.lag_num,
		cdev_info->lag_info.lag_mem[0].vsi_id,
		cdev_info->lag_info.lag_mem[0].eth_id,
		cdev_info->lag_info.lag_mem[0].active,
		cdev_info->lag_info.lag_mem[1].vsi_id,
		cdev_info->lag_info.lag_mem[1].eth_id,
		cdev_info->lag_info.lag_mem[1].active);
	nbl_set_rdma_lag_link_chng(nbl_dev->rf, cdev_info);
	return 0;
}

static int nbl_offload_status_notify(struct auxiliary_device *adev, bool status)
{
	struct nbl_device *nbl_dev = dev_get_drvdata(&adev->dev);

	nbl_set_rdma_lag_qpc_fwd_info(nbl_dev->rf, 0, false);
	return 0;
}

void nbl_init_lag(struct nbl_device *nbl_dev, struct nbl_core_dev_info *cdev_info)
{
	struct nbl_pci_f *rf = nbl_dev->rf;

	if (cdev_info->is_lag) {
		cdev_info->lag_mem_notify = nbl_lag_mem_notify;
		cdev_info->offload_status_notify = nbl_offload_status_notify;
		if (cdev_info->register_bond)
			cdev_info->register_bond(cdev_info->pdev, true);
		nbl_set_rdma_lag_en(rf, cdev_info->lag_info.lag_id, true);
		nbl_set_rdma_lag_cfg_reg(rf, cdev_info);
	}
	/* if disable lag, qpc.rss_lag_en will be zero, so not need to recover txp rdma_lag_en */
}

void nbl_deinit_lag(struct nbl_core_dev_info *cdev_info)
{
	cdev_info->lag_mem_notify = NULL;
	cdev_info->offload_status_notify = NULL;
	if (cdev_info->register_bond)
		cdev_info->register_bond(cdev_info->pdev, false);
}

