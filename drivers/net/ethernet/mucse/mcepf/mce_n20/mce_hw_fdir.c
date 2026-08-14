// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024-2026 Mucse Corporation. */

#include "../mce.h"
#include "../mce_lib.h"
#include "../mce_base.h"
#include "mce_hw_n20.h"
#include "mce_hw_fdir.h"
#include "../mce_fdir_flow.h"

#if IS_ENABLED(CONFIG_NET_CLS_FLOWER)

int n20_fd_update_entry_table(struct mce_hw *hw, int loc, u32 *meta)
{
	u32 i;

	mce_wait_status(hw, MCE_FDIR_CMD_CTRL, !(_v & MCE_FDIR_HW_RD), 2000,
			"wait fdir cmd ctrl ready failed");

	wr32(hw, MCE_FDIR_ENTRY_ID_EDIT, loc);
	for (i = 0; i < MCE_FDIR_META_LEN; i++) {
		if (meta)
			wr32(hw, MCE_FDIR_ENTRY_META_EDIT(i), meta[i]);
		else
			wr32(hw, MCE_FDIR_ENTRY_META_EDIT(i), 0);
	}
	wr32(hw, MCE_FDIR_CMD_CTRL, MCE_FDIR_WR_CMD);
	return 0;
}

int n20_fd_query_entry_table(struct mce_hw *hw, int loc)
{
	struct device *dev = mce_hw_to_dev(hw);
	u32 i;

	mce_wait_status(hw, MCE_FDIR_CMD_CTRL, !(_v & MCE_FDIR_HW_RD), 2000,
			"wait fdir cmd ctrl ready failed");

	wr32(hw, MCE_FDIR_ENTRY_ID_EDIT, loc);
	wr32(hw, MCE_FDIR_CMD_CTRL, MCE_FDIR_RD_CMD);
	dev_info(dev, "print fdir entry loc:%d\n", loc);
	for (i = 0; i < MCE_FDIR_META_LEN; i++)
		dev_info(dev, "\ti:%d data:0x%08x\n", i,
			 rd32(hw, MCE_FDIR_ENTRY_META_EDIT(i)));
	return 0;
}

int n20_fd_update_hash_table(struct mce_hw *hw, bool en, u16 loc, u32 fdir_hash)
{
	u32 hw_code = 0;

	mce_wait_status(hw, MCE_FDIR_HASH_CMD_CTRL, !(_v & MCE_FDIR_HW_RD),
			2000, "wait fdir hash cmd ctrl ready failed");

	wr32(hw, MCE_FDIR_HASH_ADDR_W, fdir_hash);
	if (en)
		hw_code = MCE_HASH_ENTRY_EN | loc;
	wr32(hw, MCE_FDIR_HASH_LOC, hw_code);
	wr32(hw, MCE_FDIR_HASH_CMD_CTRL, MCE_FDIR_WR_CMD);
	return 0;
}

int n20_fd_query_hash_table(struct mce_hw *hw, u32 fdir_hash)
{
	struct device *dev = mce_hw_to_dev(hw);
	u32 hw_code = 0;

	mce_wait_status(hw, MCE_FDIR_HASH_CMD_CTRL, !(_v & MCE_FDIR_HW_RD),
			2000, "wait fdir hash cmd ctrl ready failed");

	wr32(hw, MCE_FDIR_HASH_ENTRY_R, fdir_hash);
	wr32(hw, MCE_FDIR_HASH_CMD_CTRL, MCE_FDIR_RD_CMD);
	hw_code = rd32(hw, MCE_FDIR_HASH_ENTRY_V);
	dev_info(dev, "print fdir entry hash:0x%x loc:0x%x\n", fdir_hash,
		 hw_code);
	return 0;
}

int n20_fd_update_ex_hash_table(struct mce_hw *hw, bool en, u16 loc,
				u32 fdir_hash)
{
	u32 hw_code = 0;

	mce_wait_status(hw, MCE_FDIR_EX_HASH_CTRL, !(_v & MCE_FDIR_HW_RD), 2000,
			"wait fdir ex hash ctrl ready failed");

	wr32(hw, MCE_FDIR_EX_HASH_ADDR_W, fdir_hash);
	if (en)
		hw_code = MCE_HASH_ENTRY_EN | loc;
	wr32(hw, MCE_FDIR_EX_HASH_DATA_W, hw_code);
	wr32(hw, MCE_FDIR_EX_HASH_CTRL, MCE_FDIR_WR_CMD);
	return 0;
}

int n20_fd_query_ex_hash_table(struct mce_hw *hw, u32 fdir_hash)
{
	struct device *dev = mce_hw_to_dev(hw);
	u32 hw_code = 0;

	mce_wait_status(hw, MCE_FDIR_EX_HASH_CTRL, !(_v & MCE_FDIR_HW_RD), 2000,
			"wait fdir ex hash ctrl ready failed");

	wr32(hw, MCE_FDIR_EX_HASH_ADDR_R, fdir_hash);
	wr32(hw, MCE_FDIR_EX_HASH_CTRL, MCE_FDIR_RD_CMD);
	hw_code = rd32(hw, MCE_FDIR_EX_HASH_DATA_R);
	dev_info(dev, "print fdir ex entry hash:0x%x loc:%d\n", fdir_hash,
		 hw_code);
	return 0;
}

int n20_fd_verificate_sign_rule(struct mce_hw *hw,
				struct mce_fdir_filter *filter, u16 loc,
				u32 fdir_hash)
{
	u32 hw_code = 0;

	mce_wait_status(hw, MCE_FDIR_CMD_CTRL, !(_v & MCE_FDIR_HW_RD), 2000,
			"wait fdir cmd ctrl ready failed");

	wr32(hw, MCE_FDIR_ENTRY_ID_READ, loc);
	wr32(hw, MCE_FDIR_CMD_CTRL, MCE_FDIR_RD_CMD);
	/* edit hw quick find hash table */
	if (filter->hash_child == 0) {
		mce_wait_status(hw, MCE_FDIR_HASH_CMD_CTRL,
				!(_v & MCE_FDIR_HW_RD), 2000,
				"wait fdir hash cmd ctrl ready failed");
		wr32(hw, MCE_FDIR_HASH_ADDR_W, fdir_hash);
		hw_code = MCE_HASH_ENTRY_EN | loc;
		wr32(hw, MCE_FDIR_HASH_LOC, hw_code);
		wr32(hw, MCE_FDIR_HASH_CMD_CTRL, MCE_FDIR_WR_CMD);
	}
	mce_wait_status(hw, MCE_FDIR_HASH_CMD_CTRL, !(_v & MCE_FDIR_HW_RD),
			2000, "wait fdir hash cmd ctrl ready failed");
	wr32(hw, MCE_FDIR_HASH_ENTRY_R, fdir_hash);
	wr32(hw, MCE_FDIR_HASH_CMD_CTRL, MCE_FDIR_RD_CMD);

	dev_info(hw->dev, "dump hash entry table offset 0x4c=> 0x%.2x\n",
		 rd32(hw, MCE_FDIR_HASH_ENTRY_R));
	dev_info(hw->dev, "dump hash entry table offset 0x44=> 0x%.2x\n",
		 rd32(hw, MCE_FDIR_HASH_ADDR_W));
	dev_info(hw->dev, "dump hash entry table offset 0x50=> 0x%.2x\n",
		 rd32(hw, MCE_FDIR_HASH_ENTRY_V));
	return 0;
}

int n20_fd_clear_sign_rule(struct mce_hw *hw, u32 fdir_hash)
{
	mce_wait_status(hw, MCE_FDIR_HASH_CMD_CTRL, !(_v & MCE_FDIR_HW_RD),
			2000, "wait fdir hash cmd ctrl ready failed");
	wr32(hw, MCE_FDIR_HASH_ADDR_W, fdir_hash);
	wr32(hw, MCE_FDIR_HASH_LOC, 0);
	wr32(hw, MCE_FDIR_HASH_CMD_CTRL, MCE_FDIR_WR_CMD);
	return 0;
}

void n20_fd_field_bitmask_setup(struct mce_hw *hw,
				struct mce_fdir_field_mask *options,
				u16 loc)
{
	u32 ctrl = 0;

	ctrl |= options->key_off / 2;
	ctrl |= options->mask << MCE_FIELD_VECTOR_MASK_S;
	wr32(hw, MCE_FIELD_VECTOR_MASK(loc), ctrl);
}

void n20_fd_profile_field_bitmask_update(struct mce_hw *hw, u16 profile_id,
					 u32 options)
{
	wr32(hw, MCE_PROFILE_MASK_SEL(profile_id), options);
}

int n20_fd_profile_update(struct mce_hw *hw,
			  struct mce_hw_profile *profile, bool add)
{
	u64 addr_base;
	u32 cfg_shift;
	u32 reg;

	addr_base = MCE_PROFILE_FIELD_MASK_SELECT(profile->profile_id);
	cfg_shift = MCE_PROFILE_FIELD_LOC_SHIFT(profile->profile_id);

	if (add) {
		reg = rd32(hw, addr_base);
		reg &= ~(0XFF << cfg_shift);
		reg |= (profile->fied_mask << cfg_shift);
	} else {
		reg = rd32(hw, addr_base);
		reg &= ~(0XFF << cfg_shift);
	}
	wr32(hw, addr_base, reg);
	reg = rd32(hw, addr_base);

	return 0;
}

int n20_fd_init_hw(struct mce_hw *hw, struct mce_fdir_handle *fdir_handle)
{
	struct mce_pf *pf = container_of(hw, struct mce_pf, hw);
	u32 reg = 0;

	/* init fdir hash key */
	wr32(hw, MCE_FDIR_LK_KEY, MCE_ATR_BUCKET_HASH_KEY);
	wr32(hw, MCE_FDIR_SIGN_LK_KEY, MCE_ATR_SIGNATURE_HASH_KEY);
	if (fdir_handle->mode == MCE_FDIR_SIGN_M_MODE)
		reg |= MCE_FDIR_SIGN_M_EN;
	reg |= MCE_FDIR_HASH_PORT;
	reg |= MCE_FDIR_PRF_MASK_EN;
	reg |= MCE_FDIR_TUN_TYPE_HASH_EN;

	if (pf->fdir_mode == MCE_FDIR_EXACT_MACVLAN_MODE ||
	    pf->fdir_mode == MCE_FDIR_SIGN_MACVLAN_MODE) {
		reg |= MCE_FDIR_L2_M_MAC << MCE_FDIR_L2_M_S;
	} else {
		reg |= MCE_FDIR_UDP_ESP_SPI_EN;
		reg |= MCE_FDIR_IP_DSCP_EN;
		reg |= MCE_FDIR_PAY_PROTO_EN;
	}
	wr32(hw, MCE_FDIR_CTRL, reg);

	/* init hw age engine */
	wr32(hw, MCE_FDIR_RULE_AGE, MCE_FDIR_AGE_EN);
	msleep(100);
#define MCE_AUTO_AGE_TM (10)
	reg = MCE_AUTO_AGE_TM << MCE_FDIR_AGE_TM_VAL_S |
	      MCE_FDIR_AGE_AUTO_EN;
	wr32(hw, MCE_FDIR_RULE_AGE, reg);

	reg = rd32(hw, N20_ETH_RQA_CTRL);
	reg |= F_FD_EN;
	wr32(hw, N20_ETH_RQA_CTRL, reg);
	return 0;
}

int n20_fd_deinit_hw(struct mce_hw *hw)
{
	u32 val;

	val = rd32(hw, N20_ETH_RQA_CTRL);
	val &= ~F_FD_EN;
	wr32(hw, N20_ETH_RQA_CTRL, val);
	return 0;
}

int n20_fd_clear_hw(struct mce_hw *hw)
{
	int i;

	for (i = 0; i < 4096; i++)
		hw->ops->fd_update_entry_table(hw, i, NULL);

	for (i = 0; i < 4096; i++)
		hw->ops->fd_update_ex_hash_table(hw, false, 0, i);

	for (i = 0; i < 8192; i++)
		hw->ops->fd_update_hash_table(hw, false, 0, i);
	return 0;
}
#endif /* CONFIG_NET_CLS_FLOWER */
