// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
#include <linux/bitfield.h>
#include <linux/bitops.h>
#include "main.h"
#include "qp.h"
#include "rdma_dump_hw.h"

static void nbl_set_uqm_dump_tbl(struct nbl_hw *hw, u16 vsi_id, u16 function_id, bool enable)
{
	u64 reg_addr;
	union uqm_dump_tbl dump_map = {};

	dump_map.vfid = function_id;
	dump_map.qpn = NBL_QP_NUM_FOR_DUMP;
	dump_map.vld = (enable ? 1 : 0);

	reg_addr = NBL_UQM_DUMP_TBL_ADDR(NBL_REG_QM_BASE(hw),
		GET_MIRROR_ID_FROM_VFID(function_id));
	nbl_pr_dbg(
		"UQM_DUMP_TBL addr=0x%llx for function_id:%d vsi_id:%d enable:%d\n",
		reg_addr, function_id, vsi_id, enable);
	wr32(hw, reg_addr, dump_map.data[0]);
}

static void nbl_set_uepro_mirror_tbl(struct nbl_hw *hw, u16 vsi_id,
				     u16 function_id, u8 host)
{
	u64 reg_addr;
	union nbl_uepro_mirror_tbl_reg umirror_tbl = {};

	umirror_tbl.dport = host;
	umirror_tbl.dport_id = vsi_id;

	reg_addr = NBL_UEPRO_MIRROR_TBL_ADDR(NBL_REG_UEPRO_BASE(hw),
		GET_MIRROR_ID_FROM_VFID(function_id));
	nbl_pr_dbg(
		"UEPRO_MIRROR_TBL addr=0x%llx for vsi_id:%d\n", reg_addr, vsi_id);
	wr32(hw, reg_addr, umirror_tbl.data);
}

static void nbl_set_uepro_vsi_port_tbl(struct nbl_hw *hw,
	u16 vsi_id, u16 function_id, bool enable)
{
	u64 reg_addr;
	union nbl_uepro_vsi_port_tbl_reg u_vsi_port = {};

	reg_addr = NBL_UEPRO_VSI_PORT_TBL_ADDR(NBL_REG_UEPRO_BASE(hw), vsi_id);
	nbl_hw_read_regs(hw, reg_addr, (u8 *)&u_vsi_port, sizeof(u_vsi_port));

	u_vsi_port.mirror = (enable ? 1 : 0);
	u_vsi_port.mirror_id = GET_MIRROR_ID_FROM_VFID(function_id);
	u_vsi_port.rdma_dump_en = (enable ? 1 : 0);

	nbl_pr_dbg(
		"UEPRO_VSI_PORT_TBL addr=0x%llx for vsi_id:%d\n", reg_addr, vsi_id);
	wr32(hw, reg_addr, u_vsi_port.data);
}

static void nbl_set_depro_mirror_tbl(struct nbl_hw *hw, u16 vsi_id,
				     u16 function_id, u8 host)
{
	u64 reg_addr;
	union nbl_depro_mirror_tbl_reg dmirror_tbl = {};

	dmirror_tbl.dport = host;
	dmirror_tbl.dport_id = vsi_id;

	reg_addr = NBL_DEPRO_MIRROR_TBL_ADDR(NBL_REG_DEPRO_BASE(hw),
		GET_MIRROR_ID_FROM_VFID(function_id));
	nbl_pr_dbg(
		"DEPRO_MIRROR_TBL addr=0x%llx for vsi_id:%d\n", reg_addr, vsi_id);
	wr32(hw, reg_addr, dmirror_tbl.data);
}

static void nbl_set_dipro_vsi_port_tbl(struct nbl_hw *hw,
	u16 vsi_id, u16 function_id, bool enable)
{
	u64 reg_addr;
	union nbl_dipro_vsi_port_tbl_reg d_vsi_port = {};

	reg_addr = NBL_DIPRO_VSI_PORT_TBL_ADDR(NBL_REG_DIPRO_BASE(hw), vsi_id);
	nbl_hw_read_regs(hw, reg_addr, (u8 *)&d_vsi_port, sizeof(d_vsi_port));

	d_vsi_port.mirror = (enable ? 1 : 0);
	d_vsi_port.mirror_id = GET_MIRROR_ID_FROM_VFID(function_id);
	d_vsi_port.rdma_dump_en = (enable ? 1 : 0);

	nbl_pr_dbg(
		"DIPRO_VSI_PORT_TBL addr=0x%llx for vsi_id:%d\n", reg_addr, vsi_id);
	wr32(hw, reg_addr, d_vsi_port.data);
}

void nbl_set_dump_rdma_cfg_v4(struct nbl_hw *hw, u16 vsi_id,
	u16 function_id, u8 host, bool enable_flag)
{
	if (enable_flag) {
		/* 1. set uqm dump table, vld qpn/vfid and mirror id */
		nbl_set_uqm_dump_tbl(hw, vsi_id, function_id, true);
		/* 2. set uepro mirror table, dport, dport_id, mirror_type */
		nbl_set_uepro_mirror_tbl(hw, vsi_id, function_id, host);
		/* 3. set uepro vsi port table, rdma dump en, mirror id, mirror en  */
		nbl_set_uepro_vsi_port_tbl(hw, vsi_id, function_id, true);
		/* 4. set depro mirror table, dport, dport id , mirror type */
		nbl_set_depro_mirror_tbl(hw, vsi_id, function_id, host);
		/* 5. set dipro vsi port table, rdma dump en, mirror id, mirror en */
		nbl_set_dipro_vsi_port_tbl(hw, vsi_id, function_id, true);
	} else {
		/* 1. set dipro vsi port table, clear rdma dump en, mirror en */
		nbl_set_dipro_vsi_port_tbl(hw, vsi_id, function_id, false);
		/* 2. set uepro vsi port table, clear rdma dump en, mirror en */
		nbl_set_uepro_vsi_port_tbl(hw, vsi_id, function_id, false);
		/* 3. set uqm dump table, clear vld */
		nbl_set_uqm_dump_tbl(hw, vsi_id, function_id, false);
	}
}

void nbl_set_dump_rdma_cfg_v3(struct nbl_hw *hw, u16 vsi_id, bool enable_flag)
{
	/* TODO, DF200 dump */
}
