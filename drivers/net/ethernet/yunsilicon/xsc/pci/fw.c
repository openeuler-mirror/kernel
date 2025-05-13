// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include "common/driver.h"
#include <linux/module.h>
#include "eswitch.h"

static struct xsc_board_info *board_info[MAX_BOARD_NUM];

static struct xsc_board_info *xsc_get_board_info(char *board_sn)
{
	int i;

	for (i = 0; i < MAX_BOARD_NUM; i++) {
		if (!board_info[i])
			continue;
		if (!strncmp(board_info[i]->board_sn, board_sn, XSC_BOARD_SN_LEN))
			return board_info[i];
	}
	return NULL;
}

static struct xsc_board_info *xsc_alloc_board_info(void)
{
	int i;

	for (i = 0; i < MAX_BOARD_NUM; i++) {
		if (!board_info[i])
			break;
	}
	if (i == MAX_BOARD_NUM)
		return NULL;
	board_info[i] = vmalloc(sizeof(*board_info[i]));
	if (!board_info[i])
		return NULL;
	memset(board_info[i], 0, sizeof(*board_info[i]));
	board_info[i]->board_id = i;
	rwlock_init(&board_info[i]->mr_sync_lock);
	INIT_LIST_HEAD(&board_info[i]->func_list);
	return board_info[i];
}

void xsc_free_board_info(void)
{
	int i;

	for (i = 0; i < MAX_BOARD_NUM; i++)
		vfree(board_info[i]);
}

int xsc_cmd_query_hca_cap(struct xsc_core_device *dev,
			  struct xsc_caps *caps)
{
	struct xsc_cmd_query_hca_cap_mbox_out *out;
	struct xsc_cmd_query_hca_cap_mbox_in in;
	int err;
	u16 t16;
	struct xsc_board_info *board_info = NULL;

	out = kzalloc(sizeof(*out), GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	memset(&in, 0, sizeof(in));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_QUERY_HCA_CAP);
	in.hdr.ver = cpu_to_be16(CMD_QUERY_HCA_CAP_V2);
	in.cpu_num = cpu_to_be16(num_online_cpus());

	err = xsc_cmd_exec(dev, &in, sizeof(in), out, sizeof(*out));
	if (err)
		goto out_out;

	if (out->hdr.status) {
		err = xsc_cmd_status_to_err(&out->hdr);
		goto out_out;
	}

	dev->glb_func_id = be32_to_cpu(out->hca_cap.glb_func_id);
	if (be16_to_cpu(out->hdr.ver) >= CMD_QUERY_HCA_CAP_V1) {
		caps->max_mr_size = be64_to_cpu(out->hca_cap.max_mr_size);
		caps->max_cmd_in_len = be16_to_cpu(out->hca_cap.max_cmd_in_len);
		caps->max_cmd_out_len = be16_to_cpu(out->hca_cap.max_cmd_out_len);
	} else {
		caps->max_mr_size = (1ull << 32) - 1;
		caps->max_cmd_in_len = 10240;
		caps->max_cmd_out_len = 2048;
	}
	if (be16_to_cpu(out->hdr.ver) >= CMD_QUERY_HCA_CAP_V2) {
		caps->max_qp = be32_to_cpu(out->hca_cap.max_qp);
		caps->max_cq = be32_to_cpu(out->hca_cap.max_cq);
		caps->max_pd = be32_to_cpu(out->hca_cap.max_pd);
		caps->max_mtt = be32_to_cpu(out->hca_cap.max_mtt);
	} else {
		caps->max_qp = 1 << (out->hca_cap.log_max_qp & 0x1f);
		caps->max_cq = 1 << (out->hca_cap.log_max_cq & 0x1f);
		caps->max_pd = 1 << (out->hca_cap.log_max_pd & 0x1f);
		caps->max_mtt = 1 << (out->hca_cap.log_max_mtt);
	}

	if (be16_to_cpu(out->hdr.ver) >= CMD_QUERY_HCA_CAP_V3) {
		caps->mpt_tbl_addr = be32_to_cpu(out->hca_cap.mpt_tbl_addr);
		caps->mpt_tbl_depth = be32_to_cpu(out->hca_cap.mpt_tbl_depth);
		caps->mpt_tbl_width = be32_to_cpu(out->hca_cap.mpt_tbl_width);
		caps->mtt_inst_base_addr = be32_to_cpu(out->hca_cap.mtt_inst_base_addr);
		caps->mtt_inst_stride = be32_to_cpu(out->hca_cap.mtt_inst_stride);
		caps->mtt_inst_num_log = be32_to_cpu(out->hca_cap.mtt_inst_num_log);
		caps->mtt_inst_depth = be32_to_cpu(out->hca_cap.mtt_inst_depth);
		xsc_set_mtt_info(dev);
	}
	if (be16_to_cpu(out->hdr.ver) >= CMD_QUERY_HCA_CAP_V4) {
		dev->pcie_no = out->hca_cap.pcie_no;
		dev->pf_id = out->hca_cap.pf_id;
		dev->vf_id = be16_to_cpu(out->hca_cap.vf_id);
		dev->pcie_host_num = out->hca_cap.pcie_host_num;
		dev->pf_num_per_pcie = out->hca_cap.pf_num_per_pcie;
		caps->pf0_vf_funcid_base =
			be16_to_cpu(out->hca_cap.vf_funcid_base[dev->pcie_no][0]);
		caps->pf0_vf_funcid_top = be16_to_cpu(out->hca_cap.vf_funcid_top[dev->pcie_no][0]);
		caps->pf1_vf_funcid_base =
			be16_to_cpu(out->hca_cap.vf_funcid_base[dev->pcie_no][1]);
		caps->pf1_vf_funcid_top = be16_to_cpu(out->hca_cap.vf_funcid_top[dev->pcie_no][1]);
		caps->pcie0_pf_funcid_base = be16_to_cpu(out->hca_cap.pf_funcid_base[0]);
		caps->pcie0_pf_funcid_top = be16_to_cpu(out->hca_cap.pf_funcid_top[0]);
		caps->pcie1_pf_funcid_base = be16_to_cpu(out->hca_cap.pf_funcid_base[1]);
		caps->pcie1_pf_funcid_top = be16_to_cpu(out->hca_cap.pf_funcid_top[1]);
	} else {
		caps->pf0_vf_funcid_base = be16_to_cpu(out->hca_cap.pf0_vf_funcid_base);
		caps->pf0_vf_funcid_top = be16_to_cpu(out->hca_cap.pf0_vf_funcid_top);
		caps->pf1_vf_funcid_base = be16_to_cpu(out->hca_cap.pf1_vf_funcid_base);
		caps->pf1_vf_funcid_top = be16_to_cpu(out->hca_cap.pf1_vf_funcid_top);
		caps->pcie0_pf_funcid_base = be16_to_cpu(out->hca_cap.pcie0_pf_funcid_base);
		caps->pcie0_pf_funcid_top = be16_to_cpu(out->hca_cap.pcie0_pf_funcid_top);
		caps->pcie1_pf_funcid_base = be16_to_cpu(out->hca_cap.pcie1_pf_funcid_base);
		caps->pcie1_pf_funcid_top = be16_to_cpu(out->hca_cap.pcie1_pf_funcid_top);

		funcid_to_pf_vf_index(&dev->caps, dev->glb_func_id, &dev->pcie_no,
				      &dev->pf_id, &dev->vf_id);
	}
	caps->funcid_to_logic_port = be16_to_cpu(out->hca_cap.funcid_to_logic_port);
	if (xsc_core_is_pf(dev)) {
		xsc_core_dbg(dev, "pf0_vf_range(%4u, %4u), pf1_vf_range(%4u, %4u)\n",
			     caps->pf0_vf_funcid_base, caps->pf0_vf_funcid_top,
			     caps->pf1_vf_funcid_base, caps->pf1_vf_funcid_top);
		xsc_core_dbg(dev, "pcie0_pf_range=(%4u, %4u), pcie1_pf_range=(%4u, %4u)\n",
			     caps->pcie0_pf_funcid_base, caps->pcie0_pf_funcid_top,
			     caps->pcie1_pf_funcid_base, caps->pcie1_pf_funcid_top);
	}
	caps->pcie_host = out->hca_cap.pcie_host;
	caps->nif_port_num = out->hca_cap.nif_port_num;
	caps->hw_feature_flag = be32_to_cpu(out->hca_cap.hw_feature_flag);

	caps->raweth_qp_id_base = be16_to_cpu(out->hca_cap.raweth_qp_id_base);
	caps->raweth_qp_id_end = be16_to_cpu(out->hca_cap.raweth_qp_id_end);
	caps->raweth_rss_qp_id_base = be16_to_cpu(out->hca_cap.raweth_rss_qp_id_base);
	caps->raw_tpe_qp_num = be16_to_cpu(out->hca_cap.raw_tpe_qp_num);
	caps->max_cqes = 1 << out->hca_cap.log_max_cq_sz;
	caps->max_wqes = 1 << out->hca_cap.log_max_qp_sz;
	caps->max_sq_desc_sz = be16_to_cpu(out->hca_cap.max_desc_sz_sq);
	caps->max_rq_desc_sz = be16_to_cpu(out->hca_cap.max_desc_sz_rq);
	caps->flags = be64_to_cpu(out->hca_cap.flags);
	caps->stat_rate_support = be16_to_cpu(out->hca_cap.stat_rate_support);
	caps->log_max_msg = out->hca_cap.log_max_msg & 0x1f;
	caps->num_ports = out->hca_cap.num_ports & 0xf;
	caps->log_max_eq = out->hca_cap.log_max_eq & 0xf;
	caps->log_max_msix = out->hca_cap.log_max_msix & 0xf;
	caps->mac_port = out->hca_cap.mac_port & 0xff;
	dev->mac_port = caps->mac_port;
	if (caps->num_ports > XSC_MAX_FW_PORTS) {
		xsc_core_err(dev, "device has %d ports while the driver supports max %d ports\n",
			     caps->num_ports, XSC_MAX_FW_PORTS);
		err = -EINVAL;
		goto out_out;
	}
	caps->send_ds_num = out->hca_cap.send_seg_num;
	caps->send_wqe_shift = out->hca_cap.send_wqe_shift;
	caps->recv_ds_num = out->hca_cap.recv_seg_num;
	caps->recv_wqe_shift = out->hca_cap.recv_wqe_shift;

	caps->embedded_cpu = 0;
	caps->ecpf_vport_exists = 0;
	caps->eswitch_manager = 1;
	caps->vport_group_manager = 1;
	caps->log_max_current_uc_list = 0;
	caps->log_max_current_mc_list = 0;
	caps->log_max_vlan_list = 8;
	caps->log_max_mkey = out->hca_cap.log_max_mkey & 0x3f;
	caps->log_max_srq = out->hca_cap.log_max_srqs & 0x1f;
	caps->local_ca_ack_delay = out->hca_cap.local_ca_ack_delay & 0x1f;
	caps->log_max_mcg = out->hca_cap.log_max_mcg;
	caps->log_max_tso = out->hca_cap.log_max_tso;
	caps->hca_core_clock = be32_to_cpu(out->hca_cap.hca_core_clock);
	caps->max_rwq_indirection_tables =
		be32_to_cpu(out->hca_cap.max_rwq_indirection_tables);
	caps->max_rwq_indirection_table_size =
		be32_to_cpu(out->hca_cap.max_rwq_indirection_table_size);
	caps->max_qp_mcg = be16_to_cpu(out->hca_cap.max_qp_mcg);
	caps->max_ra_res_qp = 1 << (out->hca_cap.log_max_ra_res_qp & 0x3f);
	caps->max_ra_req_qp = 1 << (out->hca_cap.log_max_ra_req_qp & 0x3f);
	caps->max_srq_wqes = 1 << out->hca_cap.log_max_srq_sz;
	caps->rx_pkt_len_max = be32_to_cpu(out->hca_cap.rx_pkt_len_max);
	caps->max_vfs = be16_to_cpu(out->hca_cap.max_vfs);
	caps->qp_rate_limit_min = be32_to_cpu(out->hca_cap.qp_rate_limit_min);
	caps->qp_rate_limit_max = be32_to_cpu(out->hca_cap.qp_rate_limit_max);

	caps->msix_enable = 1;

	caps->msix_base = be16_to_cpu(out->hca_cap.msix_base);
	caps->msix_num = be16_to_cpu(out->hca_cap.msix_num);

	t16 = be16_to_cpu(out->hca_cap.bf_log_bf_reg_size);
	if (t16 & 0x8000) {
		caps->bf_reg_size = 1 << (t16 & 0x1f);
		caps->bf_regs_per_page = XSC_BF_REGS_PER_PAGE;
	} else {
		caps->bf_reg_size = 0;
		caps->bf_regs_per_page = 0;
	}
	caps->min_page_sz = ~(u32)((1 << PAGE_SHIFT) - 1);

	caps->dcbx = 1;
	caps->qos = 1;
	caps->ets = 1;
	caps->dscp = 1;
	caps->max_tc = out->hca_cap.max_tc;
	caps->log_max_qp_depth = out->hca_cap.log_max_qp_depth & 0xff;
	caps->mac_bit = out->hca_cap.mac_bit;
	caps->lag_logic_port_ofst = out->hca_cap.lag_logic_port_ofst;

	dev->chip_ver_h = be32_to_cpu(out->hca_cap.chip_ver_h);
	dev->chip_ver_m = be32_to_cpu(out->hca_cap.chip_ver_m);
	dev->chip_ver_l = be32_to_cpu(out->hca_cap.chip_ver_l);
	dev->hotfix_num = be32_to_cpu(out->hca_cap.hotfix_num);
	dev->feature_flag = be32_to_cpu(out->hca_cap.feature_flag);
	dev->reg_mr_via_cmdq = out->hca_cap.reg_mr_via_cmdq;

	board_info = xsc_get_board_info(out->hca_cap.board_sn);
	if (!board_info) {
		board_info = xsc_alloc_board_info();
		if (!board_info)
			return -ENOMEM;

		memcpy(board_info->board_sn, out->hca_cap.board_sn, sizeof(out->hca_cap.board_sn));
	}
	dev->board_info = board_info;

	xsc_set_pf_db_addr(dev, be64_to_cpu(out->hca_cap.tx_db),
			   be64_to_cpu(out->hca_cap.rx_db),
			   be64_to_cpu(out->hca_cap.complete_db),
			   be64_to_cpu(out->hca_cap.complete_reg),
			   be64_to_cpu(out->hca_cap.event_db));

	dev->fw_version_major = out->hca_cap.fw_ver.fw_version_major;
	dev->fw_version_minor = out->hca_cap.fw_ver.fw_version_minor;
	dev->fw_version_patch = be16_to_cpu(out->hca_cap.fw_ver.fw_version_patch);
	dev->fw_version_tweak = be32_to_cpu(out->hca_cap.fw_ver.fw_version_tweak);
	dev->fw_version_extra_flag = out->hca_cap.fw_ver.fw_version_extra_flag;

	xsc_cmd_query_read_flush(dev);
out_out:
	kfree(out);

	return err;
}

int xsc_cmd_enable_hca(struct xsc_core_device *dev, u16 vf_num, u16 max_msix)
{
	struct xsc_cmd_enable_hca_mbox_in in;
	struct xsc_cmd_enable_hca_mbox_out out;
	int err;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_ENABLE_HCA);

	in.vf_num = cpu_to_be16(vf_num);
	in.max_msix_vec = cpu_to_be16(max_msix);
	in.cpu_num = cpu_to_be16(num_online_cpus());
	in.pp_bypass = xsc_get_pp_bypass_res(dev, false);
	in.esw_mode = XSC_ESWITCH_LEGACY;

	err = xsc_cmd_exec(dev, &in, sizeof(in), &out, sizeof(out));
	if (err || out.hdr.status) {
		xsc_core_err(dev,
			     "cpu's msix vec(%u) not enough for all %u vfs, err=%d, status=%d\n",
			     max_msix, vf_num, err, out.hdr.status);
		return -EINVAL;
	}

	return err;
}

int xsc_cmd_disable_hca(struct xsc_core_device *dev, u16 vf_num)
{
	struct xsc_cmd_disable_hca_mbox_in in;
	struct xsc_cmd_disable_hca_mbox_out out;
	int err;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_DISABLE_HCA);
	in.vf_num = cpu_to_be16(vf_num);
	in.pp_bypass = xsc_get_pp_bypass_res(dev, false);
	in.esw_mode = XSC_ESWITCH_NONE;

	err = xsc_cmd_exec(dev, &in, sizeof(in), &out, sizeof(out));
	if (err || out.hdr.status) {
		xsc_core_err(dev, "failed to disable hca, err=%d, status=%d\n",
			     err, out.hdr.status);
		return -EINVAL;
	}

	return err;
}

int xsc_cmd_modify_hca(struct xsc_core_device *dev)
{
	struct xsc_cmd_modify_hca_mbox_in in;
	struct xsc_cmd_modify_hca_mbox_out out;
	int err;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_MODIFY_HCA);
	in.pp_bypass = xsc_get_pp_bypass_res(dev, true);
	in.esw_mode = xsc_get_eswitch_mode(dev);

	err = xsc_cmd_exec(dev, &in, sizeof(in), &out, sizeof(out));
	if (err)
		return err;

	if (out.hdr.status)
		err = xsc_cmd_status_to_err(&out.hdr);

	return err;
}

int xsc_cmd_query_read_flush(struct xsc_core_device *dev)
{
	struct xsc_cmd_read_flush_hw_config_mbox_in in;
	struct xsc_cmd_read_flush_hw_config_mbox_out out;
	int err = 0;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	in.hdr.opcode = cpu_to_be16(XSC_CMD_OP_QUERY_READ_FLUSH);
	err = xsc_cmd_exec(dev, &in, sizeof(in), &out, sizeof(out));
	if (err)
		return err;

	if (out.hdr.status)
		xsc_cmd_status_to_err(&out.hdr);

	dev->read_flush = out.read_flush;
	return 0;
}

