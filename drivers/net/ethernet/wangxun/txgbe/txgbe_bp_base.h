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

#define TXGBE_10G_FEC_REQ	BIT(15)
#define TXGBE_10G_FEC_ABL	BIT(14)
#define TXGBE_25G_BASE_FEC_REQ	BIT(13)
#define TXGBE_25G_RS_FEC_REQ	BIT(12)

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

void txgbe_field_set(u32 *psrcdata, u32 bithigh, u32 bitlow, u32 setvalue);
void txgbe_bp_mode_setting(struct txgbe_adapter *adapter);
int txgbe_chk_bkp_ability(struct txgbe_adapter *adapter,
			  struct bkpan73ability bkp_an73_ability,
			  struct bkpan73ability lpbkp_an73_ability);

#endif /* _TXGBE_BP_BASE_H_ */
