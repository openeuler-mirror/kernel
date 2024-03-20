// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2022 - 2024 Mucse Corporation. */

#include "rnpm_pcs.h"
#include "rnpm_regs.h"
#include "rnpm_common.h"

static u32 rnpm_read_pcs(struct rnpm_hw *hw, int num, u32 addr)
{
	u32 reg_hi, reg_lo;
	u32 value;

	reg_hi = addr >> 8;
	reg_lo = (addr & 0xff) << 2;

	wr32(hw, RNPM_PCS_BASE(num) + (0xff << 2), reg_hi);
	value = rd32(hw, RNPM_PCS_BASE(num) + reg_lo);
	return value;
}

static void rnpm_write_pcs(struct rnpm_hw *hw, int num, u32 addr, u32 value)
{
	u32 reg_hi, reg_lo;

	reg_hi = addr >> 8;
	reg_lo = (addr & 0xff) << 2;

	wr32(hw, RNPM_PCS_BASE(num) + (0xff << 2), reg_hi);
	wr32(hw, RNPM_PCS_BASE(num) + reg_lo, value);
}

struct rnpm_pcs_operations pcs_ops_generic = {
	.read = rnpm_read_pcs,
	.write = rnpm_write_pcs,
};
