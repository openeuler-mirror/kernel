/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_srv_nic.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/09/16
 * Description   : nic service interface
 */

#ifndef HINIC5_SRV_NIC_H
#define HINIC5_SRV_NIC_H

#include "nic_cfg_comm.h"
#include "drv_nic_api.h"
#if !defined(__UEFI__) && !defined(__WIN__)
#include <linux/netdevice.h>
#include "hinic5_lld.h"
#endif

/**
 * @brief struct hinic5_event_link_info port link event information
 * @details Port link information obtained after link event is reported
 */
struct hinic5_event_link_info {
	u8 valid; /**< Whether struct data is valid */
	u8 port_type; /**< Port type */
	u8 autoneg_cap; /**< Auto-negotiation capability */
	u8 autoneg_state; /**< Auto-negotiation state */
	u8 duplex;  /**< Duplex mode */
	u8 speed; /**< Port speed */
};

enum link_err_type {
	LINK_ERR_MODULE_UNRECOGENIZED, /**< Unrecognized module error type */
	LINK_ERR_NUM,
};

enum port_module_event_type {
	HINIC5_PORT_MODULE_CABLE_PLUGGED, /**< Port cable plugged event */
	HINIC5_PORT_MODULE_CABLE_UNPLUGGED, /**< Port cable unplugged event */
	HINIC5_PORT_MODULE_LINK_ERR, /**< Port link error event */
	HINIC5_PORT_MODULE_MAX_EVENT,
};

/**
 * @brief struct hinic5_port_module_event port event information
 * @details DCB information reported by DCB event
 */
struct hinic5_port_module_event {
	enum port_module_event_type type; /**< Port cable event type */
	enum link_err_type err_type; /**< Link error event type */
};

/**
 * @brief struct hinic5_dcb_info DCB information
 * @details DCB information reported by DCB event
 */
struct hinic5_dcb_info {
	u8 dcb_on; /**< DCB enable status */
	u8 default_cos; /**< Default cos */
	u8 up_cos[NIC_DCB_COS_MAX]; /**< Priority to cos mapping */
};

enum hinic5_nic_event_type {
	EVENT_NIC_LINK_DOWN, /**< Link down event */
	EVENT_NIC_LINK_UP, /**< Link up event */
	EVENT_NIC_PORT_MODULE_EVENT, /**< Cable plug/unplug event */
	EVENT_NIC_DCB_STATE_CHANGE,  /**< DCB state change event */
};

#if !defined(__UEFI__) && !defined(__VMWARE__)
/**
 * @brief Get lld_dev struct pointer by netdev
 *
 * @param netdev netdev struct pointer
 *
 * @details Match and find lld_dev by netdev
 *
 * @attention: This interface does not increment the lld_dev reference count. If lld_dev is freed during use, it may cause a dangling pointer access
 *
 * @return: Returns lld_dev struct pointer when netdev is successfully matched, otherwise returns NULL
 */
struct hinic5_lld_dev *hinic5_get_lld_dev_by_netdev(struct net_device *netdev);
#endif

/**
 * @brief Delete device MAC interface
 *
 * @param hwdev device pointer to hwdev
 * @param mac_addr MAC address
 * @param vlan_id vlan id range [0~4095]
 * @param func_id global function index
 * @param channel channel id, channel id used for mailbox sending
 *
 * @details Delete the MAC address of the corresponding function
 *
 * @attention: This function involves sending mailbox messages and will sleep. It is forbidden to call it in interrupt context or other contexts where sleeping is not allowed
 *
 * @return: Returns success or failure of deleting MAC.
 *     @retval 0 success
 *     @retval non-0 failure
 */
int hinic5_del_mac(void *hwdev, const u8 *mac_addr, u16 vlan_id, u16 func_id, u16 channel);

/**
 * @brief Get device DCB status
 *
 * @param hwdev device pointer to hwdev
 * @param dcb_state: DCB status information
 *
 * @details Get device DCB status
 *
 * @attention: NA
 * @return: Returns success or failure of getting DCB status
 *     @retval 0 success
 *     @retval non-0 failure
 */
int hinic5_get_dcb_state(void *hwdev, struct hinic5_dcb_state *dcb_state);

/**
 * @brief Get PF DCB status
 *
 * @param hwdev device pointer to hwdev
 * @param dcb_state: DCB status information
 *
 * @details VF sends mailbox message to PF to get PF DCB status information
 *
 * @attention: Only supported by VF, PF call returns failure; This function involves sending mailbox messages and will sleep. It is forbidden to call it in interrupt context or other contexts where sleeping is not allowed
 *
 * @return: Returns success or failure of VF getting PF DCB status
 *     @retval 0 success
 *     @retval non-0 failure
 */
int hinic5_get_pf_dcb_state(void *hwdev, struct hinic5_dcb_state *dcb_state);

/**
 * @brief Get corresponding cos value by priority
 *
 * @param hwdev device pointer to hwdev
 * @param pri priority, PCP mode [0~7], DSCP mode [0~63]
 * @param cos output cos value [0~7]
 *
 * @details Query the corresponding cos value by user-input pri. In PCP mode, valid pri range is 0~7. In DSCP mode, valid pri range is 0~63
 *
 * @attention: NA
 *
 * @return: Returns success or failure of pri-to-cos mapping query.
 *     @retval 0 success
 *     @retval non-0 failure
 */
int hinic5_get_cos_by_pri(void *hwdev, u8 pri, u8 *cos);

/**
 * @brief Get corresponding valid dscp value by cos value
 *
 * @param hwdev device pointer to hwdev
 * @param cos input cos value [0~7]
 * @param dscp output dscp value [0~63]
 *
 * @details Query the corresponding dscp value by cos, taking the first dscp value mapped to this cos. Only valid when dcb is enabled and dscp mode is used.
 *
 * @attention: NA
 *
 * @return: Returns success or failure of cos-to-dscp mapping query.
 *     @retval 0 success
 *     @retval non-0 failure
 */
int hinic5_get_dscp_by_cos(void *hwdev, u8 cos, u8 *dscp);

/* TO DO The following interfaces are to be deleted */
#if !defined(__UEFI__) && !defined(__VMWARE__)
typedef u8 (*hinic5_cqe_cb)(void *lld_dev, void *data);

int hinic5_register_cqe_cb(struct hinic5_lld_dev *lld_dev, enum hinic5_service_type event,
			   hinic5_cqe_cb cqe_cb);
void hinic5_unregister_cqe_cb(struct hinic5_lld_dev *lld_dev, enum hinic5_service_type event);
#endif

enum hinic5_bonding_en {
		HINIC5_BONDING_OFFLOAD_DISABLE = 0,
		HINIC5_BONDING_OFFLOAD_ENABLE
};

enum hinic5_bonding_event_e {
		BOND_EVENT_LINK_DOWN = 0,
		BOND_EVENT_LINK_UP = 1,
		BOND_EVENT_OPEN = 2,
		BOND_EVENT_CLOSE = 3
};
/* *
 * @brief hinic5_bonding_register_service_func - bonding event register
 * @param type: hinic5 service type
 * @param func: register function
 * @retval zero: success
 * @retval non-zero: failure
 */
int hinic5_bonding_register_service_func(enum hinic5_service_type type, void (*func)(void *netdev,
									     u32 bond_id, u8 new_slaves, enum hinic5_bonding_event_e event));

/* *
 * @brief hinic5_bonding_unregister_service_func - bonding event unregister
 * @param type: hinic5 service type
 * @retval zero: success
 * @retval non-zero: failure
 */
int hinic5_bonding_unregister_service_func(enum hinic5_service_type type);

/* *
 * @brief hinic5_offload_bond_en_get - get bonding offload status
 * @param type: void
 * @retval zero: bonding offload disable
 * @retval non-zero: bonding offload enable
 */
int hinic5_offload_bond_en_get(void);

/* *
 * @brief hinic5_bond_offload_get_uplink_id - get bonding uplink id
 * @param type: u16 bond_id, u32 *uplink_id
 * @retval zero success
 * @retval non-zero failure
 */
int hinic5_bond_offload_get_uplink_id(u16 bond_id, u32 *uplink_id);

/* *
 * @brief hinic5_bond_offload_get_slaves - get bonding slaves info
 * @param type: u16 bond_id, void *drv_msg, u8 *slaves
 * @retval zero success
 * @retval non-zero failure
 */
int hinic5_bond_offload_get_slaves(u16 bond_id, void *drv_msg, u8 *slaves);

#if !defined(__UEFI__) && !defined(__WIN__) && !defined(__VMWARE__)
int hinic5_get_phy_port_id_by_netdev(struct net_device *netdev, uint8_t *phy_port_id);
#endif

/* *
 * @brief hinic5_get_phy_port_stats - get port stats
 * @param hwdev: device pointer to hwdev
 * @param stats: port stats
 * @retval zero: success
 * @retval non-zero: failure
 */
int hinic5_get_phy_port_stats(void *hwdev, struct mag_cmd_port_stats *stats);

/* *
 * @brief hinic5_set_veb_offload - set veb offload
 * @param hwdev: device pointer to hwdev
 * @param veb_offload_status:  veb offload status
 * @retval zero: success
 * @retval non-zero: failure
 */
int hinic5_set_veb_offload(void *hwdev, u16 veb_offload_status);
#endif
