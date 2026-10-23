// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2024 NEBULARMATRIX */

#include "main.h"
#include "hw.h"
#include "fpga_ver.h"

static const u64 nbl_rnic_sub_type_caps[RNIC_SUB_TYPE_MAX] = {
	[RNIC_SUB_TYPE_1X400] = 0,
	[RNIC_SUB_TYPE_2X200] = 0,
	[RNIC_SUB_TYPE_B300_4X100] = NBL_PRODUCT_CAP_PT |
					NBL_PRODUCT_CAP_MPLANE_SPRAY,
	[RNIC_SUB_TYPE_B300_2X200] = NBL_PRODUCT_CAP_PT |
					NBL_PRODUCT_CAP_MPLANE_SPRAY,
	[RNIC_SUB_TYPE_B300_1X400] = NBL_PRODUCT_CAP_PT,
};

static bool nbl_rnic_sub_type_valid(u8 sub_type)
{
	switch (sub_type) {
	case RNIC_SUB_TYPE_1X400:
	case RNIC_SUB_TYPE_2X200:
	case RNIC_SUB_TYPE_B300_4X100:
	case RNIC_SUB_TYPE_B300_2X200:
	case RNIC_SUB_TYPE_B300_1X400:
		return true;
	default:
		return false;
	}
}

static void nbl_hw_cap_disable_fw_caps(struct nbl_pci_f *rf)
{
	nbl_product_apply_fw_caps(rf, 0);
}

void nbl_rnic400_detect_caps(struct nbl_pci_f *rf)
{
	struct nbl_hw *hw = &rf->hw;
	union nbl_rnic_dyn_version rnic_ver = {};
	u32 reg_addr = NBL_TOP_DYN_VERSION_ADDR(NBL_REG_TOP_V4);

	rf->product_runtime.sub_type = RNIC_SUB_TYPE_NONE;

	rnic_ver.data[0] = readl(hw->hw_addr + reg_addr);

	if (!nbl_rnic_sub_type_valid(rnic_ver.sub_type)) {
		nbl_pr_err("detect: invalid sub_type %u, disable firmware caps\n",
			   rnic_ver.sub_type);
		nbl_hw_cap_disable_fw_caps(rf);
		return;
	}

	rf->product_runtime.sub_type = rnic_ver.sub_type;
	nbl_product_apply_fw_caps(rf,
				  nbl_rnic_sub_type_caps[rnic_ver.sub_type]);
	nbl_pr_info("FPGA sub type=%02u effective_caps=%#llx\n",
		    rnic_ver.sub_type, rf->effective_caps);
}
