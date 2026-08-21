/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#ifndef __HOTPLUG_H__
#define __HOTPLUG_H__

/**
 * struct ub_slot - UB hotplug slot
 * @uent: pointer to the ub dev who has this slot
 * @r_uent: pointer to the ub dev who is plugged in this slot
 * @ports: port array slice of uent's port array
 * @kobj: kobject of slot to provide sysfs
 * @node: node of slot in uent slot_list;
 *
 * @slot_id: id of this slot
 * @port_start: start port_idx of ports belong to this slot
 * @port_num: number of ports belong to this slot
 *
 * @button_work: work to queue for button pressed event
 * @present_work: work to queue for card present event
 * @power_work: work to queue for power state update
 * @state: current state machine position
 * @state_lock: mutex lock for slot state
 */
struct ub_slot {
	/* slot info */
	struct ub_entity *uent;
	struct ub_entity *r_uent;
	struct ub_port *ports;
	struct kobject kobj;
	struct list_head node;

	/* cap info */
	u8 slot_id;
	u16 port_start;
	u16 port_num;
	u32 slot_cap;

	/* hotplug info */
	struct work_struct button_work;
	struct delayed_work present_work;
	struct delayed_work power_work;
	u8 state;
	struct mutex state_lock;
};

#define for_each_slot_port(p, s) \
	for ((p) = (s)->ports; ((p) - (s)->ports) < (s)->port_num; (p)++)

#define BUTTON(slot)		((slot)->slot_cap & UB_SLOT_PPS)
#define WORK_LED(slot)		((slot)->slot_cap & UB_SLOT_WLPS)
#define PWR_LED(slot)		((slot)->slot_cap & UB_SLOT_PLPS)
#define PRESENT(slot)		((slot)->slot_cap & UB_SLOT_PDSS)
#define PWR(slot)		((slot)->slot_cap & UB_SLOT_PWCS)

struct ubhp_msg_payload {
	u16 slot_id;
	u16 rsv0;
	u32 rsv1;
};

#define UB_HP_MSG_SIZE 40

enum power_state {
	POWER_OFF,
	POWER_ON
};

enum indicator_state {
	INDICATOR_OFF, /* set indicator off */
	INDICATOR_ON, /* set indicator on */
	INDICATOR_BLINKING, /* set indicator blinking */
	INDICATOR_NOOP /* left indicator unchanged */
};

enum hotplug_event {
	HPE_BUTTON_PRESSED = 2,
	HPE_PRESENCE_DETECT,
	HPE_OTHER
};

/**
 * a slot must be get before any of its work is queued into workqueue
 * and must be put after the work is end
 * so that when a slot is released, its works are idle and don't need to cancel
 */
static inline struct ub_slot *ubhp_get_slot(struct ub_slot *slot)
{
	if (slot)
		kobject_get(&slot->kobj);

	return slot;
}

static inline void ubhp_put_slot(struct ub_slot *slot)
{
	if (slot)
		kobject_put(&slot->kobj);
}

/* ctrl */
int ub_slot_read_dword(struct ub_slot *slot, u32 pos, u32 *val);
void ubhp_set_indicators(struct ub_slot *slot, u8 power, u8 work);
void ubhp_set_slot_power(struct ub_slot *slot, enum power_state power);
bool ubhp_confirm_event(struct ub_slot *slot, enum hotplug_event event);
bool ubhp_wait_linkup(struct ub_slot *slot);
bool ubhp_card_present(struct ub_slot *slot);
void ubhp_start_slots(struct ub_entity *uent);
void ubhp_stop_slots(struct ub_entity *uent);

/* msg */
void ubhp_event_handler(struct ub_bus_controller *ubc, void *pkt, u16 len);

/* core */
void ubhp_handle_power(struct ub_slot *slot, bool power_on);
void ubhp_cancel_all_work(void);

/* route */
int ubhp_update_route_link_up(struct ub_slot *slot);
void ubhp_update_route_link_down(struct ub_slot *slot);
void ubhp_mark_detached_entities(struct ub_entity *root, struct list_head *dev_list);
void ubhp_stop_entities(struct list_head *dev_list);
void ubhp_remove_entities(struct list_head *dev_list);

#endif /* __HOTPLUG_H__ */
