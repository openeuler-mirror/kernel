/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : drv_nic_api.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/09/16
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
 * @param vf_link_forced VF forced link state, false--link state follows PF, true--link state according to link_state value
 * @param link_state link state, false--Link down, true--link up
 * @details PF sets link state of all VFs under this PF, PF saves VF link state,
 *     if not set, VF link state follows PF by default, after user sets it, user setting prevails
 *
 * @attention: PF only
 *
 * @return: VF link state setting success or failure.
 *     @retval 0 success
 *     @retval non-0 failure
 */
int hinic5_pf_set_vf_link_state(void *hwdev, bool vf_link_forced, bool link_state);

/**
 * @brief add device mac interface
 *
 * @param hwdev device pointer to hwdev
 * @param mac_addr mac address
 * @param vlan_id vlan id range [0~4095]
 * @param func_id global function index
 * @param channel channel id, channel id used for mailbox sending
 *
 * @details add mac address of the corresponding function
 *
 * @attention: This function involves sending mailbox messages and will sleep, do not call in interrupt context or other processes that do not allow sleep
 *
 * @return: add MAC returns success or failure.
 *     @retval 0 success
 *     @retval non-0 failure
 */
int hinic5_set_mac(void *hwdev, const u8 *mac_addr, u16 vlan_id, u16 func_id, u16 channel);

#if !defined(__UEFI__) && !defined(__VMWARE__)
/**
 * @brief get network device handle netdev struct pointer according to lld_dev
 *
 * @param lld_dev device pointer to lld_dev
 *
 * @details find nic uld device according to lld_dev to get netdev
 *
 * @attention: this interface return will not increment netdev reference count, if netdev is freed during use, it may cause wild pointer access
*
 * @return: returns netdev struct pointer when lld_dev is successfully matched, otherwise returns NULL
 */
struct net_device *hinic5_get_netdev_by_lld(struct hinic5_lld_dev *lld_dev);

/**
 * @brief register device private data
 *
 * @param dev device pointer to net_device
 * @param priv private data
 *
 * @details register device private data through net_device
 *
 * @return: private data registration success or failure.
 *     @retval 0 success
 *     @retval non-0 failure
 */
int hinic5_netdev_priv_set(const struct net_device *dev, void *priv);

/**
 * @brief get device private data
 *
 * @param dev device pointer to net_device
 *
 * @details register device private data through net_device
 *
 * @attention: need to call hinic5_netdev_priv_set interface first to register device private data
 *
 * @return: private data.
 *     @retval NULL failure
 *     @retval non-NULL success
 */
void *hinic5_netdev_priv_get(const struct net_device *dev);

/**
 * @brief NIC driver load hook function
 *
 * @param netdev device pointer to net_device
 *
 * @details overloaded by product, can implement functions such as registering file system files, modifying netdev name, etc.
 *
 * @return: hook function execution result.
 *     @retval 0 success
 *     @retval non-0 failure
 */
int hinic5_probe_extend_hook(struct net_device *netdev);

/**
 * @brief NIC driver unload hook
 *
 * @param netdev device pointer to net_device
 *
 * @details overloaded by product
 *
 * @return: hook function execution result.
 *     @retval 0 success
 *     @retval non-0 failure
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
 * @param cmd command word
 * @param nt_msg command content
 * @param support whether this command is supported, product needs to determine whether it is supported according to the command word
 *
 * @details overloaded by product
 *
 * @return: command execution result.
 *     @retval 0 success
 *     @retval non-0 failure
 */
int hinic5_tool_cmd_extend_handle(struct net_device *netdev, u32 cmd,
				  struct hinic5_nt_msg *nt_msg, bool *support);

/**
 * @brief interface for product to set user-space qps count
 *
 * @param netdev device pointer to net_device
 * @param usr_qps_num expected user-space qps count
 * @details called by product
 *
 * @return: command execution result.
 *    @retval 0 success
 *    @retval non-0 failure
 */
int hinic5_set_usr_qps_num(struct net_device *netdev, u16 usr_qps_num);

/**
 * @brief NIC related skip MAC setting function
 *
  * @param dev device pointer to net_device
 *  @param addr MAC address
 *
 * @details overloaded by product, can implement the function of skipping related settings after user-space queue is enabled
 *
 * @return: hook function execution result.
 *     @retval 0 do not skip
 *     @retval non-0 skip
 */
int hinic5_set_mac_addr_pre_hook(struct net_device *netdev, void *addr);

/**
 * @brief NIC related skip MTU setting function
 *
 * @param netdev device pointer to net_device
 * @param new_mtu new mtu value
 *
 * @details overloaded by product, can implement the function of skipping related settings after user-space queue is enabled
 *
 * @return: hook function execution result.
 *     @retval 0 do not skip
 *     @retval non-0 skip
 */
int hinic5_change_mtu_pre_hook(struct net_device *netdev, int new_mtu);

/**
 * @brief NIC related skip MTU setting function
 *
 * @param netdev device pointer to net_device
 * @param ring queue depth related parameters
 *
 * @details overloaded by product, can implement the function of skipping related settings after user-space queue is enabled
 *
 * @return: hook function execution result.
 *     @retval 0 do not skip
 *     @retval non-0 skip
 */
int hinic5_set_ringparam_pre_hook(struct net_device *netdev, struct ethtool_ringparam *ring);

/**
 * @brief interface for product to set flow bifurcation enabled group count
 *
 * @param netdev device pointer to net_device
 * @param group_num expected group count
 * @details called by product, group_num range is 1~8. 1: disable flow bifurcation, other values: enable flow bifurcation.
 * @attention when flow bifurcation is enabled, the actual effective value of group_num will be rounded up to a power of 2.
 *
 * @return: command execution result.
 *    @retval 0 success
 *    @retval non-0 failure
 */
int hinic5_set_flow_bifurcation_group_num(struct net_device *netdev, u8 group_num);

/**
 * @brief interface for product to query/set the indirect table corresponding to groupId when flow bifurcation is enabled
 *
 * @param netdev device pointer to net_device
 * @param op_code 0 query; 1 set
 * @param group_id group id used by the device
 * @param indir indirect table
 * @param indir_length indirect table length
 * @details called by product
 *
 * @return: command execution result.
 *    @retval 0 success
 *    @retval non-0 failure
 */
int hinic5_cfg_flow_bifurcation_paras(struct net_device *netdev, u8 op_code,
				      u8 group_id, u32 *indir, u16 indir_length);
#endif /* !defined(__UEFI__) && !defined(__VMWARE__) */
#endif
