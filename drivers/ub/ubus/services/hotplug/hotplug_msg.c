// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#define pr_fmt(fmt)	"ubus hp msg: " fmt

#include "../../ubus.h"
#include "../../msg.h"
#include "../../link.h"
#include "hotplug.h"

static struct ub_slot *ub_find_slot(struct ub_entity *uent, u16 slot_id)
{
	struct ub_slot *slot;

	list_for_each_entry(slot, &uent->slot_list, node)
		if (slot->slot_id == slot_id)
			return slot;

	return NULL;
}

static struct ub_slot *ubhp_get_slot_from_msg(void *pkt)
{
	struct msg_pkt_header *header = (struct msg_pkt_header *)pkt;
	struct ubhp_msg_payload *payload;
	struct ub_slot *slot;
	struct ub_entity *uent;
	u32 seid;

	seid = eid_gen(header->seid_h, header->seid_l);
	uent = ub_get_ent_by_eid(seid);
	if (!uent) {
		pr_warn("get no device by eid %#05x\n", seid);
		return NULL;
	}

	payload = (struct ubhp_msg_payload *)header->payload;
	slot = ubhp_get_slot(ub_find_slot(uent, payload->slot_id));
	if (!slot)
		pr_err("can not find slot with id %u\n", payload->slot_id);

	ub_entity_put(uent);
	return slot;
}

static void ubhp_handle_event(struct ub_slot *slot, enum hotplug_event event)
{
	bool queued = false;
	u32 flag;

	if (!ubhp_confirm_event(slot, event))
		return;

	/**
	 * get slot if work is queued
	 * queue_work: return false if work already exists
	 * mod_delayed_work: return true if work exists, with its timer modified
	 */
	if (event == HPE_BUTTON_PRESSED) {
		queued = queue_work(get_rx_msg_wq(UB_MSG_CODE_LINK),
				    &slot->button_work);
	} else if (event == HPE_PRESENCE_DETECT) {
		flag = work_busy(&slot->present_work.work);
		if (!(flag & WORK_BUSY_RUNNING))
			queued = !mod_delayed_work(
					get_rx_msg_wq(UB_MSG_CODE_LINK),
					&slot->present_work, 0);
	}
	if (queued)
		ubhp_get_slot(slot);
}

void ubhp_event_handler(struct ub_bus_controller *ubc, void *pkt, u16 len)
{
	struct msg_pkt_header *header = (struct msg_pkt_header *)pkt;
	struct ub_slot *slot;

	if (len < UB_HP_MSG_SIZE) {
		dev_err(&ubc->dev, "hp msg len[%#x] invalid\n", len);
		return;
	}

	slot = ubhp_get_slot_from_msg(pkt);
	if (!slot)
		return;

	ubhp_handle_event(slot,
			  (enum hotplug_event)header->msgetah.sub_msg_code);
	ubhp_put_slot(slot);
}
