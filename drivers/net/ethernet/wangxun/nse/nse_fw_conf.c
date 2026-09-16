// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#include "nse.h"
#include "nse_type.h"
#include "nse_hw_conf.h"

bool nse_is_fw_fea_set(struct nse_hw *hw, unsigned int f)
{
	if (f > NSE_FW_FEA_FLAGS_NBITS)
		return false;

	return test_bit(f, hw->fw_conf.fw_fea);
}

static void nse_init_fw_conf_amber(struct nse_hw *hw)
{
	struct nse_fw_conf *conf = &hw->fw_conf;

	set_bit(NSE_FW_FEA_SUPPORT_DDP, conf->fw_fea);

	if (hw->hw_conf.hw_platform == NSE_HW_PLATFORM_ASIC && !nse_palladium_debug) {
		/* all current NSE_DEV_ID_AMBER_XXX support FW-LLDP */
		set_bit(NSE_FW_FEA_SUPPORT_LLDP, conf->fw_fea);
	}

	if (nse_fw_lldp)	/* force, just for debug */
		set_bit(NSE_FW_FEA_SUPPORT_LLDP, conf->fw_fea);
}

static void nse_init_fw_conf_moonstone(struct nse_hw *hw)
{
	struct nse_fw_conf *conf = &hw->fw_conf;

	clear_bit(NSE_FW_FEA_SUPPORT_DDP, conf->fw_fea);
}

enum nse_status nse_init_fw_conf(struct nse_hw *hw)
{
	if (hw->mac_type == NSE_MAC_TYPE_AMBER)
		nse_init_fw_conf_amber(hw);
	else if (hw->mac_type == NSE_MAC_TYPE_MOONSTONE)
		nse_init_fw_conf_moonstone(hw);

	return NSE_SUCCESS;
}

