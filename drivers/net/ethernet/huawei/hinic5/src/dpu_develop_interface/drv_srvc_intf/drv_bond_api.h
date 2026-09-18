/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : drv_bond_api.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/09/16
 * Description   : nic driver semi-offload bond interface definition
 */

#ifndef DRV_BOND_API
#define DRV_BOND_API

#include <net/bonding.h>
#include <linux/netdevice.h>
#include <linux/types.h>
#include "bond_common_defs.h"

/**
 * @brief struct hinic5_bond_info_s
 * @details bond information struct obtained by user
 */
struct hinic5_bond_info_s {
	u8 slaves;			/**< bond port slave bitmap */
	u8 cnt;				/**< count of bond slaves */
	u8 rsvd[2];
	char slaves_name[BOND_PORT_MAX_NUM][BOND_NAME_MAX_LEN]; /**< slave device name */
};

/**
 * @brief struct netdev_lower_state_info
 * @details ndev status information
 */
struct netdev_lower_state_info {
	u8 link_up : 1;			/**< slave device link up status */
	u8 tx_enabled : 1;		/**< slave device available for transmitting data */
	u8 rsvd : 6;
} __attribute__((__packed__));

/**
 * @brief struct bond_tracker
 * @details bond device information struct
 */
struct bond_tracker {
	struct netdev_lower_state_info netdev_state[BOND_PORT_MAX_NUM]; /**< bond slave device information */
	struct net_device *ndev[BOND_PORT_MAX_NUM]; /**< bond slave device pointer */
	u8 cnt;	/**< bond slave device count */
	bool is_bonded; /**< whether bond can be sent to mpu to create and activate bond */
};

/**
 * @brief struct bond_attr
 * @details bond basic attributes
 */
struct bond_attr {
	u16 bond_mode;	/**< bond mode */
	u16 bond_id;	/**< bond id */
	u16 up_delay;	/**< delay time before bond starts working after bond up */
	u16 down_delay; /**< delay time when bond down is unavailable */
	u8 active_slaves;	/**< active available slave bitmap */
	u8 slaves;			/**< original slave bitmap when composing bond */
	u8 lacp_collect_slaves; /**< slave bitmap configured by lacp protocol */
	u8 xmit_hash_policy;	/**< hash policy for bond routing */
	u32 first_roce_func;	/**< first func in bond, roce only */
	u32 bond_pf_bitmap;	/**< func composing bond */
	u32 user_bitmap;	/**< user bitmap currently using bond */
};

/**
 * @brief bond binding processing interface registered by user
 * @param[in] bond: bonding struct pointer in kernel protocol
 * @details After user registers this interface, when protocol stack bond triggers bond events
 * (add/delete slave, etc.), this interface will be called to determine whether bond can be bound.
 * If it can be bound, the bond driver will try to bind bond for the user
 * @attention N/A
 * @return	If returns true, bond can be bound; if returns false, bond cannot be bound
 **/
typedef bool (*attach_func)(struct bonding *bond);

/**
 * @brief bond event processing interface registered by user
 * @param[in] bond_name: bond name
 * @param[in] attr: bond attributes
 * @param[in] err: processing result after bond activation/modification/deactivation, 0 for success, non-0 for failure
 * @details User registers this interface. Before/after bond creation/deletion/update, the bond driver
 * will call it for the service to do its own processing
 * @attention N/A
 * @return void
 **/
typedef void (*event_func)(const char *bond_name, struct bond_attr *attr, int err);

/**
 * @brief struct bond_srv_func
 * @details bond processing interface set registered by service
 */
struct bond_srv_func {
	event_func before_active; /**< srv processing before bond activation */
	event_func after_active; /**< srv processing after bond activation */
	event_func before_modify; /**< srv processing before bond modification */
	event_func after_modify; /**< srv processing after bond modification */
	event_func before_deactive; /**< srv processing before bond deactivation */
	event_func after_deactive; /**< srv processing after bond deactivation */
	attach_func can_attach; /**< registering this interface means when protocol stack bond updates CFM will bind bond for srv */
};

/**
 * @brief user binds protocol stack bonding
 * @param[in] name bond device name
 * @param[in] user binding user
 * @param[out] bond_id bound bond id
 * @details After the protocol stack bonding is created, the user can issue this interface to bind
 * the bond corresponding to the bond name, and return the bond id managed internally by the chip
 * @attention N/A
 * @return	returns binding result, 0 for success, non-0 for failure
 **/
int hinic5_bond_attach(const char *name, enum hinic5_bond_user user, u16 *bond_id);

/**
 * @brief user unbinds protocol stack bonding
 * @param[in] bond_id bond id
 * @param[in] user binding user
 * @details User unbinds protocol stack bonding. If no user is using it, the bond device in the nic driver will be destroyed
 * @attention N/A
 * @return	returns unbinding result, 0 for success, non-0 for failure
 **/
int hinic5_bond_detach(u16 bond_id, enum hinic5_bond_user user);

/**
 * @brief unbind all bonds bound by this user
 * @param[in] user user
 * @details unbind this user from all bond devices
 * @attention N/A
 * @return	void
 **/
void hinic5_bond_clean_user(enum hinic5_bond_user user);

/**
 * @brief get BDF identifier of bond device
 * @param[in] bond_id bond id
 * @param[out] uplink_id returned bdf id
 * @details get BDF identifier of bond device, supports pci/ub devices
 * @attention N/A
 * @return	returns get result, 0 for success, non-0 for failure
 **/
int hinic5_bond_get_uplink_id(u16 bond_id, u32 *uplink_id);

/**
 * @brief bond user registers processing interface
 * @param[in] user user
 * @param[in] func processing interface set, including event processing and binding processing
 * @details User registers processing interface, see interface definitions in bond_srv_func struct
 * @attention N/A
 * @return	returns registration result, 0 for success, non-0 for failure
 **/
int hinic5_bond_register_service_func(enum hinic5_bond_user user, struct bond_srv_func *func);

/**
 * @brief bond user unregisters processing interface
 * @param[in] user user
 * @details User unregisters processing interface, see interface definitions in bond_srv_func struct
 * @attention N/A
 * @return	returns unregistration result, 0 for success, non-0 for failure
 **/
int hinic5_bond_unregister_service_func(enum hinic5_bond_user user);

/**
 * @brief get bond slave information
 * @param[in] bond_id bond id
 * @param[in] info bond slave information, see hinic5_bond_info_s for details
 * @details get bond slave information
 * @attention N/A
 * @return	returns get result, 0 for success, non-0 for failure
 **/
int hinic5_bond_get_slaves(u16 bond_id, struct hinic5_bond_info_s *info);

/**
 * @brief get ndev device of bond slave
 * @param[in] bond_name bond name
 * @param[in] port_id port id
 * @details get ndev device pointer corresponding to port id in bond
 * @attention N/A
 * @return returns ndev pointer, non-NULL for success, NULL for failure
 **/
struct net_device *hinic5_bond_get_netdev_by_portid(const char *bond_name, u8 port_id);

/**
 * @brief get device information of bond slave
 * @param[in] bond_name bond name
 * @param[out] tracker bond device information, see bond_tracker
 * @details get device information of all slave devices in bond
 * @attention N/A
 * @return returns get result, 0 for success, non-0 for failure
 **/
int hinic5_get_bond_tracker_by_name(const char *name, struct bond_tracker *tracker);

#endif