/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */
#ifndef __UBUS_H__
#define __UBUS_H__

#include <ub/ubfi/ubfi.h>
#include <ub/ubus/ubus.h>

#define UB_CP_UPI 0x7FFF

enum ub_mgmt_state {
	MGMT_STATE_IDLE = 0,
	MGMT_STATE_REGISTERING = 1,
	MGMT_STATE_UNREGISTERING = 2
};

#define ent_in_unregistering(uent) \
	(atomic_read(&(uent)->ent_mgmt_state) == MGMT_STATE_UNREGISTERING)

enum ub_entity_type {
	UB_ENT_BUS_CONTROLLER,
	UB_ENT_IBUS_CONTROLLER,
	UB_ENT_SWITCH,
	UB_ENT_DEVICE,
	UB_ENT_IDEVICE,
	UB_ENT_P_DEVICE,
	UB_ENT_P_IDEVICE,
	UB_ENT_UNKNOWN
};

#define is_primary(uent) ((uent)->entity_idx == 0)
#define is_ibus_controller(uent) ((uent)->ent_type == UB_ENT_IBUS_CONTROLLER)
#define is_bus_controller(uent) ((uent)->ent_type == UB_ENT_BUS_CONTROLLER)
#define is_controller(uent) (is_ibus_controller(uent) || is_bus_controller(uent))
#define is_switch(uent) ((uent)->ent_type == UB_ENT_SWITCH)
#define is_device(uent) ((uent)->ent_type == UB_ENT_DEVICE)
#define is_p_device(uent) ((uent)->ent_type == UB_ENT_P_DEVICE)
#define is_dev(uent) (is_device(uent) || is_p_device(uent))
#define is_idevice(uent) ((uent)->ent_type == UB_ENT_IDEVICE)
#define is_p_idevice(uent) ((uent)->ent_type == UB_ENT_P_IDEVICE)
#define is_idev(uent) (is_idevice(uent) || is_p_idevice(uent))

#define ONE_CNA(uent) (is_switch(uent) || (uent)->port_nums == 1)

#define UB_COMPACT_EID_MASK GENMASK(19, 0)
#define UB_UPI_MASK GENMASK(14, 0)

/* ub_entity priv_flags */
#define UB_ENTITY_START 0 /* Flag indicate uent can match with driver */
#define UB_ENTITY_DETACHED 1 /* Flag indicate uent is detached */
#define UB_ENTITY_ROUTE_UPDATED 2 /* Flag indicate uent's route is updated */
#define UB_ENTITY_SETUP 4 /* Flag indicate uent is setup */
#define UB_ENTITY_ACTIVE 5 /* Flag indicate uent is in normal or disable state */
#define UB_ENTITY_DISCONNECTED 6 /* Flag indicate uent is disconnected */
#define UB_ENTITY_PROBED 7 /* Flag indicate uent is probed driver */

static inline void ub_entity_assign_priv_flag(struct ub_entity *uent, int bit,
					      bool flag)
{
	assign_bit(bit, &uent->priv_flags, flag);
}

static inline bool ub_entity_test_priv_flag(struct ub_entity *uent, int bit)
{
	return test_bit(bit, &uent->priv_flags);
}

struct ub_bus_controller *ub_find_bus_controller(u32 ctl_no);

struct ub_manage_subsystem_ops {
	u32 vendor;
	int (*controller_probe)(struct ub_bus_controller *ubc);
	void (*controller_remove)(struct ub_bus_controller *ubc);
	int (*ras_handler_probe)(void);
	void (*ras_handler_remove)(void);

#ifndef __GENKSYMS__
	void (*vdm_delay_work)(struct work_struct *work);
	unsigned long long (*feature_get)(void);
#else
	KABI_RESERVE(1)
	KABI_RESERVE(2)
#endif
	KABI_RESERVE(3)
	KABI_RESERVE(4)
};
int register_ub_manage_subsystem_ops(const struct ub_manage_subsystem_ops *ops);
void unregister_ub_manage_subsystem_ops(const struct ub_manage_subsystem_ops *ops);
const struct ub_manage_subsystem_ops *get_ub_manage_subsystem_ops(void);
struct ub_entity *ub_find_entity(struct ub_entity *parent, bool mue, int idx);

#endif /* __UBUS_H__ */
