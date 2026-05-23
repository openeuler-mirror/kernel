/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : drv_nic_api.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef DRV_NIC_API_H
#define DRV_NIC_API_H

#include "base_type.h"
#if !defined(__UEFI__) && !defined(__VMWARE__)
#include <linux/netdevice.h>
#include <linux/ethtool.h>
#include "hinic5_lld.h"
#endif

/**
 * @brief PF sets VF link state
 *
 * @param hwdev device pointer to hwdev
 * @param vf_link_forced VF forced link state, false--Link state follows PF, true--link state depends on link_state value
 * @param link_state link state, false--Link down, true--link up
 * @details PF sets link state for all VFs under this PF. PF saves VF's link state.
 *     If not set, VF link state follows PF by default. After user setting, user's setting takes precedence.
 *
 * @attention: Only PF supports this
 *
 * @return: VF link state setting success or failure.
 *     @retval 0 Success
 *     @retval non-0 Failure
 */
int hinic5_pf_set_vf_link_state(void *hwdev, bool vf_link_forced, bool link_state);

/**
 * @brief Add device mac interface
 *
 * @param hwdev device pointer to hwdev
 * @param mac_addr MAC address
 * @param vlan_id VLAN id range [0~4095]
 * @param func_id Global function index
 * @param channel Channel id, channel id used for mailbox sending
 *
 * @details Add MAC address for corresponding function
 *
 * @attention: This function involves sending mailbox messages and may sleep. Do not call in interrupt context or other contexts that do not allow sleeping.
 *
 * @return: Add MAC returns success or failure.
 *     @retval 0 Success
 *     @retval non-0 Failure
 */
int hinic5_set_mac(void *hwdev, const u8 *mac_addr, u16 vlan_id, u16 func_id, u16 channel);

#if !defined(__UEFI__) && !defined(__VMWARE__)
/**
 * @brief Get network device handle netdev structure pointer according to lld_dev
 *
 * @param lld_dev device pointer to lld_dev
 *
 * @details Find nic uld device according to lld_dev to get netdev
 *
 * @attention: This interface returns without incrementing netdev reference count. If netdev is freed during use, it may lead to wild pointer access.
*
 * @return: Returns netdev structure pointer when successfully matching lld_dev, otherwise returns NULL
 */
struct net_device *hinic5_get_netdev_by_lld(struct hinic5_lld_dev *lld_dev);

/**
 * @brief Register device private data
 *
 * @param dev device pointer to net_device
 * @param priv Private data
 *
 * @details Register device private data through net_device
 *
 * @return: Private data registration success or failure.
 *     @retval 0 Success
 *     @retval non-0 Failure
 */
int hinic5_netdev_priv_set(const struct net_device *dev, void *priv);

/**
 * @brief Get device private data
 *
 * @param dev device pointer to net_device
 *
 * @details Get device private data through net_device
 *
 * @attention: Need to call hinic5_netdev_priv_set interface to register device private data first
 *
 * @return: Private data.
 *     @retval NULL Failure
 *     @retval non-NULL Success
 */
void *hinic5_netdev_priv_get(const struct net_device *dev);

/**
 * @brief NIC driver load hook function
 *
 * @param netdev device pointer to net_device
 *
 * @details Overloaded by product, can implement functions like registering filesystem files, modifying netdev name, etc.
 *
 * @return: Hook function execution result.
 *     @retval 0 Success
 *     @retval non-0 Failure
 */
int hinic5_probe_extend_hook(struct net_device *netdev);

/**
 * @brief NIC driver unload hook
 *
 * @param netdev device pointer to net_device
 *
 * @details Overloaded by product
 *
 * @return: Hook function execution result.
 *     @retval 0 Success
 *     @retval non-0 Failure
 */
void hinic5_remove_extend_hook(struct net_device *netdev);

struct hinic5_nt_msg {
	void *buf_in;
	void *buf_out;
	u32 in_size;
	u32 out_size;
};

/**
 * @brief NIC driver command hook function
 *
 * @param netdev device pointer to net_device
 * @param cmd Command word
 * @param nt_msg Command content
 * @param support Whether the command is supported, product needs to determine support based on command word
 *
 * @details Overloaded by product
 *
 * @return: Command execution result.
 *     @retval 0 Success
 *     @retval non-0 Failure
 */
int hinic5_tool_cmd_extend_handle(struct net_device *netdev, u32 cmd,
				  struct hinic5_nt_msg *nt_msg, bool *support);

/**
 * @brief Product side interface to set user-space qps number
 *
 * @param netdev device pointer to net_device
 * @param usr_qps_num Expected user-space qps number
 * @details Called by product
 *
 * @return: Command execution result.
 *    @retval 0 Success
 *    @retval non-0 Failure
 */
int hinic5_set_usr_qps_num(struct net_device *netdev, u16 usr_qps_num);

/**
 * @brief NIC related skip MAC setting function
 *
  * @param dev device pointer to net_device
 *  @param addr MAC address
 *
 * @details Overloaded by product, can implement skip related settings after user-space queue is enabled
 *
 * @return: Hook function execution result.
 *     @retval 0 Do not skip
 *     @retval non-0 Skip
 */
int hinic5_set_mac_addr_pre_hook(struct net_device *netdev, void *addr);

/**
 * @brief NIC related skip MTU setting function
 *
 * @param netdev device pointer to net_device
 * @param new_mtu New MTU value
 *
 * @details Overloaded by product, can implement skip related settings after user-space queue is enabled
 *
 * @return: Hook function execution result.
 *     @retval 0 Do not skip
 *     @retval non-0 Skip
 */
int hinic5_change_mtu_pre_hook(struct net_device *netdev, int new_mtu);

/**
 * @brief NIC related skip ringparam setting function
 *
 * @param netdev device pointer to net_device
 * @param ring Queue depth related parameters
 *
 * @details Overloaded by product, can implement skip related settings after user-space queue is enabled
 *
 * @return: Hook function execution result.
 *     @retval 0 Do not skip
 *     @retval non-0 Skip
 */
int hinic5_set_ringparam_pre_hook(struct net_device *netdev, struct ethtool_ringparam *ring);

/**
 * @brief Product side interface to set flow bifurcation enabled group number
 *
 * @param netdev device pointer to net_device
 * @param group_num Expected group number
 * @details Called by product, group_num range is 1~8. 1: disable flow bifurcation, other values: enable flow bifurcation.
 * @attention When flow bifurcation is enabled, the actual effective value of group_num will be rounded up to power of 2.
 *
 * @return: Command execution result.
 *    @retval 0 Success
 *    @retval non-0 Failure
 */
int hinic5_set_flow_bifurcation_group_num(struct net_device *netdev, u8 group_num);

/**
 * @brief Product side query/set indirect table corresponding to groupId when flow bifurcation is enabled
 *
 * @param netdev device pointer to net_device
 * @param op_code 0: query; 1: set
 * @param group_id Group id used by device
 * @param indir Indirect table
 * @param indir_length Indirect table length
 * @details Called by product
 *
 * @return: Command execution result.
 *    @retval 0 Success
 *    @retval non-0 Failure
 */
int hinic5_cfg_flow_bifurcation_paras(struct net_device *netdev, u8 op_code,
				      u8 group_id, u32 *indir, u16 indir_length);
#endif /* !defined(__UEFI__) && !defined(__VMWARE__) */
#endif
