/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2015 - 2025 Beijing WangXun Technology Co., Ltd. */

#ifndef _TXGBE_BP_BASE_H_
#define _TXGBE_BP_BASE_H_

#include "txgbe.h"
#include "txgbe_type.h"
#include "txgbe_hw.h"

#define TXGBE_PCS_AN_TXDIS	BIT(3)
#define TXGBE_PCS_AN_PG_RCV	BIT(2)
#define TXGBE_PCS_AN_INC_LINK	BIT(1)
#define TXGBE_PCS_AN_INT_CMPLT	BIT(0)

#define KR_MODE			0

#ifndef AN_TRAINNING_MODE
#define AN_TRAINNING_MODE	0
#endif

#ifndef AN73_TRAINNING_MODE
#define AN73_TRAINNING_MODE	2
#endif

#ifndef CTLE_BYPASS
#define CTLE_BYPASS		0
#endif

#ifndef CL74_KRTR_TRAINNING_TIMEOUT
#define CL74_KRTR_TRAINNING_TIMEOUT	6000
#endif

#ifndef KR_TRAINNING_MODE
#define KR_TRAINNING_MODE	2	/* 0 PRESET 2 INITIALIZE */
#endif

#ifndef SW_OEM_EPHY
#define SW_OEM_EPHY		0
#endif

#ifndef SW_CTRL_EPHY_FORCE
#define SW_CTRL_EPHY_FORCE	0
#endif

#ifndef TXGBE_STORM_INTERVAL
#define TXGBE_STORM_INTERVAL	100
#endif

#ifndef TXGBE_STORM_UC
#define TXGBE_STORM_UC		0
#endif

#ifndef TXGBE_STORM_BC
#define TXGBE_STORM_BC		0
#endif

#ifndef TXGBE_STORM_BC_THRE
#define TXGBE_STORM_BC_THRE	100
#endif

#ifndef TXGBE_STORM_MC
#define TXGBE_STORM_MC		0
#endif

#ifndef TXGBE_STORM_MC_THRE
#define TXGBE_STORM_MC_THRE	100
#endif

#ifndef AUTO
#define AUTO			1
#endif

#define TXGBE_10G_FEC_REQ	BIT(15)
#define TXGBE_10G_FEC_ABL	BIT(14)
#define TXGBE_25G_BASE_FEC_REQ	BIT(13)
#define TXGBE_25G_RS_FEC_REQ	BIT(12)

#define S10G_TX_FFE_CFG_MAIN        0x2c2c2c2c
#define S10G_TX_FFE_CFG_PRE1        0x0
#define S10G_TX_FFE_CFG_PRE2        0x0
#define S10G_TX_FFE_CFG_POST        0x6060606
#define S25G_TX_FFE_CFG_MAIN        49
#define S25G_TX_FFE_CFG_PRE1        4
#define S25G_TX_FFE_CFG_PRE2        1
#define S25G_TX_FFE_CFG_POST        9

/* for dac test*/
#define S25G_TX_FFE_CFG_DAC_MAIN    0x2a2a2a2a
#define S25G_TX_FFE_CFG_DAC_PRE1    0x03030303
#define S25G_TX_FFE_CFG_DAC_PRE2    0x0
#define S25G_TX_FFE_CFG_DAC_POST    0x11111111

#define SFI_SET     0
#define SFI_MAIN    24
#define SFI_PRE     4
#define SFI_POST    16

#define KR_SET      0
#define KR_MAIN     27
#define KR_PRE      8
#define KR_POST     44

#define KX4_SET     0
#define KX4_MAIN    40
#define KX4_PRE     0
#define KX4_POST    0

#define KX_SET      0
#define KX_MAIN     24
#define KX_PRE      4
#define KX_POST     16

struct bkpan73ability {
	unsigned int next_page;		/* Next Page (bit0) */
	unsigned int link_ability;	/* Link Ability (bit[7:0]) */
	unsigned int fec_ability;	/* FEC Request (bit1), FEC Enable (bit0) */
	unsigned int cu_linkmode;	/* current link mode for local device */
};

enum ability_filed_encding {
	ABILITY_1000BASE_KX,
	ABILITY_10GBASE_KX4,
	ABILITY_10GBASE_KR,
	ABILITY_40GBASE_KR4,
	ABILITY_40GBASE_CR4,
	ABILITY_100GBASE_CR10,
	ABILITY_100GBASE_KP4,
	ABILITY_100GBASE_KR4,
	ABILITY_100GBASE_CR4,
	ABILITY_25GBASE_KRCR_S,
	ABILITY_25GBASE_KRCR,
	ABILITY_MAX,
};

#define __bf_shf_m(x) (__builtin_ffsll(x) - 1)

#define FIELD_PREP_M(_mask, _val)					\
	({								\
		((typeof(_mask))(_val) << __bf_shf_m(_mask)) & (_mask);	\
	})

/**
 * FIELD_GET_M() - extract a bitfield element
 * @_mask: shifted mask defining the field's length and position
 * @_reg:  value of entire bitfield
 *
 * FIELD_GET_M() extracts the field specified by @_mask from the
 * bitfield passed in as @_reg by masking and shifting it down.
 */
#define FIELD_GET_M(_mask, _reg)					\
	({								\
		(typeof(_mask))(((_reg) & (_mask)) >> __bf_shf_m(_mask));	\
	})

#define kr_dbg(KR_MODE, fmt, arg...)				\
	do {							\
		if (KR_MODE)					\
			e_dev_info(fmt, ##arg);			\
	} while (0)

u32 rd32_ephy(struct txgbe_hw *hw, u32 addr);
u32 txgbe_rd32_epcs(struct txgbe_hw *hw, u32 addr);
void txgbe_wr32_ephy(struct txgbe_hw *hw, u32 addr, u32 data);
void txgbe_wr32_epcs(struct txgbe_hw *hw, u32 addr, u32 data);
void txgbe_field_set(u32 *psrcdata, u32 bithigh, u32 bitlow, u32 setvalue);
int txgbe_is_dac_cable(struct txgbe_hw *hw);
int txgbe_xpcs_an_enabled(struct txgbe_hw *hw);
void txgbe_bp_mode_setting(struct txgbe_adapter *adapter);
void txgbe_xpcs_txffe_set(struct txgbe_adapter *adapter);
void txgbe_xlgpcs_txffe_set(struct txgbe_adapter *adapter, u32 speed);
int txgbe_chk_bkp_ability(struct txgbe_adapter *adapter,
			  struct bkpan73ability bkp_an73_ability,
			  struct bkpan73ability lpbkp_an73_ability);

#endif /* _TXGBE_BP_BASE_H_ */
