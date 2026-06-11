// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#include "../../ubus.h"
#include "../../port.h"
#include "hotplug.h"

/**
 * arrange of SHP cap
 *
 * +-------------+---------------+---------------+
 * | reg(s) name | start address | end address   |
 * | slice header| 0x00          | 0x00          |
 * | slot number | 0x01          | 0x01          |
 * | slot1 regs  | 0x02          | 0x0F          |
 * | slot2 regs  | 0x12          | 0x1F          |
 * ...
 * | slotN regs  | 0x2 + 10(N-1) | 0xF + 10(N-1) |
 */

/**
 * for any given reg in slot regs of slotN, it's pos can be get by:
 * SHP cap pos + 10(N-1) + reg pos in slot regs
 * the fronter two elements is represented as following UB_SLOT_BASE macro
 */
#define UB_SLOT_BASE(slot) (UB_SLOT_START + (slot)->slot_id * UB_SLOT_POS)

static void ub_slot_read_byte(struct ub_slot *slot, u32 pos, u8 *val)
{
	int ret = ub_cfg_read_byte(slot->uent, UB_SLOT_BASE(slot) + pos, val);

	if (unlikely(ret)) {
		ub_err(slot->uent, "ub slot%u read %#x failed, ret=%d\n",
		       slot->slot_id, pos, ret);
		*val = 0;
	}
}

int ub_slot_read_dword(struct ub_slot *slot, u32 pos, u32 *val)
{
	int ret = ub_cfg_read_dword(slot->uent, UB_SLOT_BASE(slot) + pos, val);

	if (unlikely(ret))
		ub_err(slot->uent, "ub slot%u read %#x failed, ret=%d\n",
		       slot->slot_id, pos, ret);

	return ret;
}

static void ub_slot_write_byte(struct ub_slot *slot, u32 pos, u8 val)
{
	int ret = ub_cfg_write_byte(slot->uent, UB_SLOT_BASE(slot) + pos, val);

	if (unlikely(ret))
		ub_err(slot->uent, "ub slot%u write %#x failed, ret=%d\n",
		       slot->slot_id, pos, ret);
}

void ubhp_set_indicators(struct ub_slot *slot, u8 power, u8 work)
{
	u8 val;

	/**
	 * power state indicator:
	 * OFF:      slot is power off, card can be inserted or removed
	 * ON:       slot is power on, card can't be inserted or removed
	 * BLINKING: slot is under operation performed by user,
	 *	card can't be inserted or removed
	 */
	if (power >= INDICATOR_NOOP || !PWR_LED(slot))
		goto set_wl;

	ub_slot_read_byte(slot, UB_SLOT_PL_CTRL, &val);
	val &= ~UB_SLOT_PL_CTRL_MASK;
	val |= power;
	ub_slot_write_byte(slot, UB_SLOT_PL_CTRL, val);

set_wl:
	/**
	 * card work state indicator:
	 * OFF:      card is running normally
	 * ON:       card is out of service or faulty.
	 * BLINKING: card is under operation performed by user
	 */
	if (work >= INDICATOR_NOOP || !WORK_LED(slot))
		return;

	ub_slot_read_byte(slot, UB_SLOT_WL_CTRL, &val);
	val &= ~UB_SLOT_WL_CTRL_MASK;
	val |= work;
	ub_slot_write_byte(slot, UB_SLOT_WL_CTRL, val);
}

void ubhp_set_slot_power(struct ub_slot *slot, enum power_state power)
{
	if (PWR(slot))
		ub_slot_write_byte(slot, UB_SLOT_PW_CTRL, power);
}

bool ubhp_card_present(struct ub_slot *slot)
{
	u8 val;

	/* always present if no present ctrl */
	if (!PRESENT(slot))
		return true;

	ub_slot_read_byte(slot, UB_SLOT_PD_STA, &val);

	return !!(val & UB_SLOT_PD_STA_MASK);
}

bool ubhp_wait_linkup(struct ub_slot *slot)
{
#define TOTAL_WAIT_TIME 100 /* wait 100ms for linkup */
	u64 timeout = get_jiffies_64() + msecs_to_jiffies(TOTAL_WAIT_TIME);
	struct ub_port *port;

	do {
		/* only need one port link up */
		for_each_slot_port(port, slot)
			if (ub_port_check_link_up(port))
				return true;
	} while (time_is_after_jiffies64(timeout));

	return false;
}

/* check config space and clear status regs */
bool ubhp_confirm_event(struct ub_slot *slot, enum hotplug_event event)
{
	u32 pos, mask;
	u8 val;

	switch (event) {
	case HPE_BUTTON_PRESSED:
		pos = UB_SLOT_PP_STA;
		mask = UB_SLOT_PP_STA_MASK;
		break;
	case HPE_PRESENCE_DETECT:
		pos = UB_SLOT_PDSC_STA;
		mask = UB_SLOT_PDSC_STA_MASK;
		break;
	default:
		return false;
	}

	ub_slot_read_byte(slot, pos, &val);
	if (!(val & mask)) {
		ub_err(slot->uent, "confirm hotplug event %d failed\n", event);
		return false;
	}

	val &= ~mask;
	ub_slot_write_byte(slot, pos, val);
	return true;
}

static void ubhp_enable(struct ub_slot *slot, u32 pos, u32 mask, bool flag)
{
	u8 val;

	if (!flag)
		return;

	ub_slot_read_byte(slot, pos, &val);
	val |= mask;
	ub_slot_write_byte(slot, pos, val);
}

static void ubhp_disable(struct ub_slot *slot, u32 pos, u32 mask, bool flag)
{
	u8 val;

	if (!flag)
		return;

	ub_slot_read_byte(slot, pos, &val);
	val &= ~mask;
	ub_slot_write_byte(slot, pos, val);
}

static void ubhp_start_slot(struct ub_slot *slot)
{
	/* enable PP */
	ubhp_enable(slot, UB_SLOT_PP_CTRL, UB_SLOT_PP_CTRL_MASK, BUTTON(slot));
	/* enable PD */
	ubhp_enable(slot, UB_SLOT_PD_CTRL, UB_SLOT_PD_CTRL_MASK, PRESENT(slot));
	/* enable PDS */
	ubhp_enable(slot, UB_SLOT_PDS_CTRL, UB_SLOT_PDS_CTRL_MASK, PRESENT(slot));
	/* enable MS */
	ubhp_enable(slot, UB_SLOT_MS_CTRL, UB_SLOT_MS_CTRL_MASK, true);
}

static void ubhp_stop_slot(struct ub_slot *slot)
{
	/* disable MS */
	ubhp_disable(slot, UB_SLOT_MS_CTRL, UB_SLOT_MS_CTRL_MASK, true);
	/* disable PDS */
	ubhp_disable(slot, UB_SLOT_PDS_CTRL, UB_SLOT_PDS_CTRL_MASK, PRESENT(slot));
	/* disable PD */
	ubhp_disable(slot, UB_SLOT_PD_CTRL, UB_SLOT_PD_CTRL_MASK, PRESENT(slot));
	/* disable PP */
	ubhp_disable(slot, UB_SLOT_PP_CTRL, UB_SLOT_PP_CTRL_MASK, BUTTON(slot));
}

void ubhp_start_slots(struct ub_entity *uent)
{
	struct ub_slot *slot;

	list_for_each_entry(slot, &uent->slot_list, node)
		ubhp_start_slot(slot);
}

void ubhp_stop_slots(struct ub_entity *uent)
{
	struct ub_slot *slot;

	list_for_each_entry(slot, &uent->slot_list, node)
		ubhp_stop_slot(slot);
}
