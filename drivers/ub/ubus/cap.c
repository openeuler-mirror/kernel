// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#define pr_fmt(fmt)	"ubus cap: " fmt

#include "ubus.h"
#include "decoder.h"
#include "interrupt.h"
#include "cap.h"

#define DW_CHECK 3

void ub_set_cap_bitmap(struct ub_entity *uent)
{
	int ret;
	u32 i;

	for (i = 0; i < SZ_8; i++) {
		ret = ub_cfg_read_dword(uent, UB_CFG1_CAP_BITMAP + (i << SZ_2),
					&uent->cfg1_bitmap[i]);
		if (ret)
			ub_err(uent, "Read cfg1 cap bitmap failed, ret=%d\n",
			       ret);
	}

	if (is_p_device(uent))
		return;

	for (i = 0; i < SZ_8; i++) {
		ret = ub_cfg_read_dword(uent, UB_CFG0_CAP_BITMAP + (i << SZ_2),
					&uent->cfg0_bitmap[i]);
		if (ret)
			ub_err(uent, "Read cfg0 cap bitmap failed, ret=%d\n",
			       ret);
	}
}

/* Check whether the capability register is implemented. */
static bool ub_cap_reg_implemented(struct ub_entity *uent, u32 cap)
{
	u32 i = (cap & 0xFF) / SZ_32;
	u32 val = (cap >> SZ_8) ? uent->cfg1_bitmap[i] : uent->cfg0_bitmap[i];

	return val & BIT((cap & 0xFF) % SZ_32);
}

/* find the start address of capability */
u32 ub_find_capability(u32 cap)
{
	return (cap << BITS_PER_BYTE) << SZ_2;
}

int ub_cap_read_byte(struct ub_entity *uent, u32 cap, u32 off, u8 *val)
{
	int ret;

	*val = 0;
	if (off >= SZ_1K)
		return -EFAULT;

	if (!ub_cap_reg_implemented(uent, cap))
		return -ENXIO;

	ret = ub_cfg_read_byte(uent, ub_find_capability(cap) + off, val);
	if (ret)
		*val = 0;

	return ret;
}

int ub_cap_read_word(struct ub_entity *uent, u32 cap, u32 off, u16 *val)
{
	int ret;

	*val = 0;
	if (off & 1 || off >= SZ_1K)
		return -EFAULT;

	if (!ub_cap_reg_implemented(uent, cap))
		return -ENXIO;

	ret = ub_cfg_read_word(uent, ub_find_capability(cap) + off, val);
	if (ret)
		*val = 0;

	return ret;
}

int ub_cap_read_dword(struct ub_entity *uent, u32 cap, u32 off, u32 *val)
{
	int ret;

	*val = 0;
	if (off & DW_CHECK || off >= SZ_1K)
		return -EFAULT;

	if (!ub_cap_reg_implemented(uent, cap))
		return -ENXIO;

	ret = ub_cfg_read_dword(uent, ub_find_capability(cap) + off, val);
	if (ret)
		*val = 0;

	return ret;
}

int ub_cap_write_byte(struct ub_entity *uent, u32 cap, u32 off, u8 val)
{
	if (off >= SZ_1K)
		return -EFAULT;

	if (!ub_cap_reg_implemented(uent, cap))
		return -ENXIO;

	return ub_cfg_write_byte(uent, ub_find_capability(cap) + off, val);
}

int ub_cap_write_word(struct ub_entity *uent, u32 cap, u32 off, u16 val)
{
	if (off & 1 || off >= SZ_1K)
		return -EFAULT;

	if (!ub_cap_reg_implemented(uent, cap))
		return -ENXIO;

	return ub_cfg_write_word(uent, ub_find_capability(cap) + off, val);
}

int ub_cap_write_dword(struct ub_entity *uent, u32 cap, u32 off, u32 val)
{
	if (off & DW_CHECK || off >= SZ_1K)
		return -EFAULT;

	if (!ub_cap_reg_implemented(uent, cap))
		return -ENXIO;

	return ub_cfg_write_dword(uent, ub_find_capability(cap) + off, val);
}

int ub_cap_clear_and_set_word(struct ub_entity *dev, u32 cap, u32 off,
			      u16 clear, u16 set)
{
	u16 val;
	int ret;

	ret = ub_cap_read_word(dev, cap, off, &val);
	if (!ret) {
		val &= ~clear;
		val |= set;
		ret = ub_cap_write_word(dev, cap, off, val);
	}

	return ret;
}

int ub_cap_clear_and_set_dword(struct ub_entity *dev, u32 cap, u32 off,
			       u32 clear, u32 set)
{
	u32 val;
	int ret;

	ret = ub_cap_read_dword(dev, cap, off, &val);
	if (!ret) {
		val &= ~clear;
		val |= set;
		ret = ub_cap_write_dword(dev, cap, off, val);
	}

	return ret;
}

static inline int ub_cap_set_word(struct ub_entity *dev, u32 cap, u32 off,
				  u16 set)
{
	return ub_cap_clear_and_set_word(dev, cap, off, 0, set);
}

static inline int ub_cap_set_dword(struct ub_entity *dev, u32 cap, u32 off,
				   u32 set)
{
	return ub_cap_clear_and_set_dword(dev, cap, off, 0, set);
}

static inline int ub_cap_clear_word(struct ub_entity *dev, u32 cap, u32 off,
				    u16 clear)
{
	return ub_cap_clear_and_set_word(dev, cap, off, clear, 0);
}

static inline int ub_cap_clear_dword(struct ub_entity *dev, u32 cap, u32 off,
				     u32 clear)
{
	return ub_cap_clear_and_set_dword(dev, cap, off, clear, 0);
}

static int ub_sf_init(struct ub_entity *uent)
{
	u32 support_feature = 0;
	int ret;

	ret = ub_cfg_read_dword(uent, UB_FEATURE_SUPPORT_0, &support_feature);
	if (ret) {
		ub_err(uent, "Read support feature0 failed, ret=%d\n", ret);
		return ret;
	}

	uent->support_feature = support_feature;
	return 0;
}

static void ub_sw_init(struct ub_entity *uent)
{
	if (!uent || !uent->ubc)
		return;

	if (!is_ibus_controller(uent))
		return;

	if (uent->support_feature & UB_SW_SUPPORT)
		uent->sw_cap = true;
	else
		uent->sw_cap = false;
}

void ub_init_capabilities(struct ub_entity *uent)
{
	/* cfg0 caps */
	if (ub_sf_init(uent))
		goto init_cfg1_cap;

	ub_sw_init(uent);

init_cfg1_cap:
	/* cfg1 caps */
	ub_decoder_init(uent);
	ub_intr_init(uent);

	uent->reset_fn = 1;
}

void ub_uninit_capabilities(struct ub_entity *uent)
{
	/* cfg1 cap */
	ub_decoder_uninit(uent);

	uent->reset_fn = 0;
}
