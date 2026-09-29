/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2024-2026 Mucse Corporation. */

#ifndef _MCE_HW_FDIR_H_
#define _MCE_HW_FDIR_H_
#include "../mce.h"
#include "../mce_fdir.h"
#include "../mce_fdir_flow.h"
#include "../mce_pattern.h"
#include "../mce_profile_mask.h"
#include "mce_hw_n20.h"

#if IS_ENABLED(CONFIG_NET_CLS_FLOWER)

#define _E_FDIR_F(off) ((off) + 0xf0000)
#define BIT_TO_BYTES(bit) ((bit) / 8)

#define MCE_FDIR_HASH_CMD_CTRL _E_FDIR_F(0x40)
#define MCE_FDIR_HASH_ADDR_W _E_FDIR_F(0x44)
#define MCE_FIDR_HASH_DATA_W _E_FDIR_F(0x48)
#define MCE_FDIR_HASH_ENTRY_R _E_FDIR_F(0x4c)
#define MCE_FDIR_HASH_ENTRY_V _E_FDIR_F(0x50)
#define MCE_FDIR_HASH_LOC _E_FDIR_F(0x48)
#define MCE_HASH_ENTRY_EN BIT(13)

#define MCE_FDIR_EX_HASH_CTRL _E_FDIR_F(0x80)
#define MCE_FDIR_EX_HASH_ADDR_W _E_FDIR_F(0x84)
#define MCE_FDIR_EX_HASH_DATA_W _E_FDIR_F(0x88)
#define MCE_FDIR_EX_HASH_ADDR_R _E_FDIR_F(0x8c)
#define MCE_FDIR_EX_HASH_DATA_R _E_FDIR_F(0x90)
#define MCE_FDIR_EX_DATA_VLD BIT(13)

#define MCE_FDIR_CTRL _E_FDIR_F(0x0)
#define MCE_FDIR_MAX_LEN GENMASK(21, 16)
#define MCE_FDIR_MAX_LEN_S (16)
#define MCE_FDIR_L2_M_NONE (0)
#define MCE_FDIR_L2_M_VLAN (1)
#define MCE_FDIR_L2_M_MAC (2)
#define MCE_FDIR_MATCH_L2_EN GENMASK(12, 11)
#define MCE_FDIR_L2_M_S (11)
#define MCE_FDIR_TUN_TYPE_HASH_EN BIT(22)
#define MCE_FDIR_PRF_MASK_EN BIT(13)
#define MCE_FDIR_HASH_PORT BIT(10)
#define MCE_FDIR_SIGN_M_EN BIT(9)
#define MCE_FDIR_GL_MASK_EN BIT(8)
#define MCE_FDIR_PAY_PROTO_EN BIT(7)
#define MCE_FDIR_IP_DSCP_EN BIT(6)
#define MCE_FDIR_UDP_ESP_SPI_EN BIT(5)
#define MCE_FDIR_TCP_MODE_SYNC BIT(4)
#define MCE_FDIR_TUNPE_MODE GENMASK(3, 0)

#define MCE_FDIR_LK_KEY _E_FDIR_F(0x08)
#define MCE_FDIR_SIGN_LK_KEY _E_FDIR_F(0x0c)
#define MCE_FDIR_CMD_CTRL _E_FDIR_F(0xc0)
#define MCE_FDIR_HW_RD BIT(31)
#define MCE_FDIR_WR_CMD BIT(0)
#define MCE_FDIR_RD_CMD BIT(1)

#define MCE_FDIR_ENTRY_ID_EDIT _E_FDIR_F(0xc4)
#define MCE_FDIR_ENTRY_META_EDIT(n) \
	_E_FDIR_F(0xc8 + ((n) * BIT_TO_BYTES(32)))
#define MCE_FDIR_ENTRY_ID_READ _E_FDIR_F(0xe0)
#define MCE_FDIR_ENTRY_META_READ(n) \
	_E_FDIR_F(0xe4 + ((n) * BIT_TO_BYTES(32)))

#define MCE_FDIR_META_LEN (BIT_TO_BYTES(384) / 4)
/* fdir rule age */
#define MCE_FDIR_RULE_AGE _E_FDIR_F(0x0018)
#define MCE_FDIR_AGE_EN BIT(31)
#define MCE_FDIR_AGE_AUTO_EN BIT(30)
/* 1bit == 1ms, max auto age time 8181ms  */
#define MCE_FDIR_AGE_TM_VAL GENMASK(28, 16)
#define MCE_FDIR_AGE_TM_VAL_S (16)
#define MCE_FDIR_AGE_TM_READ BIT(12)
#define MCE_FDIR_AGE_TM_WRITE BIT(13)
#define MCE_FIDR_RULE_AGE_STATE _E_FDIR_F(0x001c)

#define MCE_FIDR_MASK_TUN_START_ADDR _E_FDIR_F(0x00100)
#define MCE_FIDR_MASK_TUN_END_ADDR _E_FDIR_F(0x0017c)
#define MCE_FIDR_MASK_TUN_UDP_PORT _E_FDIR_F(0x00168)

#define MCE_PROFILE_MASK_DB_CTRL(n) \
	_E_FDIR_F(0x01c0 + ((n) * BIT_TO_BYTES(32)))
#define MCE_PROFILE_MASK_LOC GENMASK(4, 0)
#define MCE_PROFILE_MASK_VALID_MASK GENMASK(31, 16)
#define MCE_PROFILE_MASK_SELECT(n) \
	_E_FDIR_F(0x01c0 + ((n) * BIT_TO_BYTES(32)))
#define MCE_PROFILE_FIELD_MASK_SELECT(id) \
	_E_FDIR_F(0x0340 + (((id) / 4) * 0x4))
#define MCE_PROFILE_FIELD_LOC_SHIFT(id) (((id) % 4) * 8)

#define MCE_FIELD_VECTOR_MASK(n) _E_FDIR_F(0x02c0 + ((0x4 * (n))))
#define MCE_FIELD_VECTOR_MASK_S (16)
#define MCE_PROFILE_MASK_SEL(n) _E_FDIR_F(0x01c0 + ((0x4 * (n))))

int n20_fd_update_entry_table(struct mce_hw *hw, int loc, u32 *meta);
int n20_fd_query_entry_table(struct mce_hw *hw, int loc);
int n20_fd_update_hash_table(struct mce_hw *hw, bool en, u16 loc,
			     u32 fdir_hash);
int n20_fd_query_hash_table(struct mce_hw *hw, u32 fdir_hash);
int n20_fd_update_ex_hash_table(struct mce_hw *hw, bool en, u16 loc,
				u32 fdir_hash);
int n20_fd_query_ex_hash_table(struct mce_hw *hw, u32 fdir_hash);
int n20_fd_verificate_sign_rule(struct mce_hw *hw,
				struct mce_fdir_filter *filter, u16 loc,
				u32 fdir_hash);
int n20_fd_clear_sign_rule(struct mce_hw *hw, u32 fdir_hash);
void n20_fd_field_bitmask_setup(struct mce_hw *hw,
				struct mce_fdir_field_mask *options,
				u16 loc);
void n20_fd_profile_field_bitmask_update(struct mce_hw *hw, u16 profile_id,
					 u32 options);
int n20_fd_profile_update(struct mce_hw *hw,
			  struct mce_hw_profile *profile, bool add);
int n20_fd_init_hw(struct mce_hw *hw, struct mce_fdir_handle *fdir_handle);
int n20_fd_deinit_hw(struct mce_hw *hw);
int n20_fd_clear_hw(struct mce_hw *hw);
#endif /* CONFIG_NET_CLS_FLOWER */

#endif /*_MCE_HW_FDIR_H_*/
