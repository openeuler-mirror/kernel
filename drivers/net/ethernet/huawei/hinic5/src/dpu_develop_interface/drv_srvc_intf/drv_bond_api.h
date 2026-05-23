/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : drv_bond_api.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   : NIC driver half-offload bond interface definition
 */

#ifndef DRV_BOND_API
#define DRV_BOND_API

#include <net/bonding.h>
#include <linux/netdevice.h>
#include <linux/types.h>
#include "bond_common_defs.h"

/**
 * @brief struct hinic5_bond_info_s
 * @details Bond information structure obtained by user
 */
struct hinic5_bond_info_s {
	u8 slaves;			/**< bond port slave bitmap */
	u8 cnt;				/**< Number of bond slaves */
	u8 rsvd[2];
	char slaves_name[BOND_PORT_MAX_NUM][BOND_NAME_MAX_LEN]; /**< Slave device name */
};

/**
 * @brief struct netdev_lower_state_info
 * @details Ndev status information
 */
struct netdev_lower_state_info {
	u8 link_up : 1;			/**< Slave device link up status */
	u8 tx_enabled : 1;		/**< Slave device available for transmitting data */
	u8 rsvd : 6;
} __attribute__((__packed__));

/**
 * @brief struct bond_tracker
 * @details Bond device information structure
 */
struct bond_tracker {
	struct netdev_lower_state_info netdev_state[BOND_PORT_MAX_NUM]; /**< Bond slave device information */
	struct net_device *ndev[BOND_PORT_MAX_NUM]; /**< Bond slave device pointer */
	u8 cnt;	/**< Number of bond slave devices */
	bool is_bonded; /**< Whether bond can be sent to mpu to create and activate bond */
};

/**
 * @brief struct bond_attr
 * @details Bond basic attributes
 */
struct bond_attr {
	u16 bond_mode;	/**< Bond mode */
	u16 bond_id;	/**< bond id */
	u16 up_delay;	/**< Delay time before bond starts working when up */
	u16 down_delay; /**< Delay time before bond is unavailable when down */
	u8 active_slaves;	/**< Active available slave bitmap */
	u8 slaves;			/**< Original slave bitmap when creating bond */
	u8 lacp_collect_slaves; /**< Slave bitmap configured for LACP protocol */
	u8 xmit_hash_policy;	/**< Hash policy for bond routing */
	u32 first_roce_func;	/**< First func in bond, used only by RoCE */
	u32 bond_pf_bitmap;	/**< Func for creating bond */
	u32 user_bitmap;	/**< Current user bitmap using bond */
};

/**
 * @brief User-registered bond binding processing interface
 * @param[in] bond: Pointer to bonding structure in kernel protocol
 * @details After user registers this interface, when protocol stack bond triggers bond events (adding/removing slaves, etc.),
 * this interface will be called to determine if binding is possible. If yes, bond driver will try to bind bond for user.
 * @attention N/A
 * @return	If returns true, bond can be bound; if returns false, bond cannot be bound
 **/
typedef bool (*attach_func)(struct bonding *bond);

/**
 * @brief User-registered bond event processing interface
 * @param[in] bond_name: Bond name
 * @param[in] attr: Bond attributes
 * @param[in] err: Processing result after bond activation/modification/deactivation, 0 for success, non-0 for failure
 * @details User registers this interface, and bond driver will call it for service's own processing before/after bond creation/deletion/update
 * @attention N/A
 * @return void
 **/
typedef void (*event_func)(const char *bond_name, struct bond_attr *attr, int err);

/**
 * @brief struct bond_srv_func
 * @details Service-registered bond processing interface collection
 */
struct bond_srv_func {
	event_func before_active; /**< Srv processing before bond activation */
	event_func after_active; /**< Srv processing after bond activation */
	event_func before_modify; /**< Srv processing before bond modification */
	event_func after_modify; /**< Srv processing after bond modification */
	event_func before_deactive; /**< Srv processing before bond deactivation */
	event_func after_deactive; /**< Srv processing after bond deactivation */
	attach_func can_attach; /**< Register this interface to indicate that when protocol stack bond updates CFM, it will bind bond for srv */
};

/**
 * @brief User binds protocol stack bonding
 * @param[in] name Bond device name
 * @param[in] user User to bind
 * @param[out] bond_id Bound bond id
 * @details After user creates protocol stack bonding, they can issue this interface to bind bond with corresponding bond name,
 * and it returns the bond id managed internally by chip
 * @attention N/A
 * @return	Returns binding result, 0 for success, non-0 for failure
 **/
int hinic5_bond_attach(const char *name, enum hinic5_bond_user user, u16 *bond_id);

/**
 * @brief User unbinds protocol stack bonding
 * @param[in] bond_id Bond id
 * @param[in] user User to unbind
 * @details User unbinds protocol stack bonding. If there is no user using it, bond device in nic driver will be destroyed
 * @attention N/A
 * @return	Returns unbinding result, 0 for success, non-0 for failure
 **/
int hinic5_bond_detach(u16 bond_id, enum hinic5_bond_user user);

/**
 * @brief Unbind all bonds bound by this user
 * @param[in] user User
 * @details Unbind this user from all bond devices
 * @attention N/A
 * @return	void
 **/
void hinic5_bond_clean_user(enum hinic5_bond_user user);

/**
 * @brief Get BDF identifier of bond device
 * @param[in] bond_id Bond id
 * @param[out] uplink_id Returned BDF id
 * @details Get BDF identifier of bond device, supports pci/ub devices
 * @attention N/A
 * @return	Returns get result, 0 for success, non-0 for failure
 **/
int hinic5_bond_get_uplink_id(u16 bond_id, u32 *uplink_id);

/**
 * @brief Bond user registers processing interface
 * @param[in] user User
 * @param[in] func Processing interface collection, including event processing and binding processing
 * @details User registers processing interface, see interface definition in bond_srv_func structure
 * @attention N/A
 * @return	Returns registration result, 0 for success, non-0 for failure
 **/
int hinic5_bond_register_service_func(enum hinic5_bond_user user, struct bond_srv_func *func);

/**
 * @brief Bond user unregisters processing interface
 * @param[in] user User
 * @details User unregisters processing interface, see interface definition in bond_srv_func structure
 * @attention N/A
 * @return	Returns unregistration result, 0 for success, non-0 for failure
 **/
int hinic5_bond_unregister_service_func(enum hinic5_bond_user user);

/**
 * @brief Get bond slave information
 * @param[in] bond_id Bond id
 * @param[in] info Bond slave information, see hinic5_bond_info_s for details
 * @details Get bond slave information
 * @attention N/A
 * @return	Returns get result, 0 for success, non-0 for failure
 **/
int hinic5_bond_get_slaves(u16 bond_id, struct hinic5_bond_info_s *info);

/**
 * @brief Get bond slave's ndev device
 * @param[in] bond_name Bond name
 * @param[in] port_id Port id
 * @details Get ndev device pointer corresponding to portid in bond
 * @attention N/A
 * @return Returns ndev pointer, returns non-NULL on success, returns NULL on failure
 **/
struct net_device *hinic5_bond_get_netdev_by_portid(const char *bond_name, u8 port_id);

/**
 * @brief Get bond slave's device information
 * @param[in] name Bond name
 * @param[out] tracker Bond device information, see bond_tracker
 * @details Get device information of all slave devices in bond
 * @attention N/A
 * @return Returns get result, 0 for success, non-0 for failure
 **/
int hinic5_get_bond_tracker_by_name(const char *name, struct bond_tracker *tracker);

#endif