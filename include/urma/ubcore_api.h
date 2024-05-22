/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 * Description: API definition provided by ubcore to ubep device driver
 * Author: Qian Guoxin
 * Create: 2022-1-25
 * Note:
 * History: 2022-1-25: Create file
 */

#ifndef UBCORE_API_H
#define UBCORE_API_H

#include <urma/ubcore_types.h>

/**
 * Register a device to ubcore
 * @param[in] dev: the ubcore device;
 * @return: 0 on success, other value on error
 */
int ubcore_register_device(struct ubcore_device *dev);
/**
 * Unregister a device from ubcore
 * @param[in] dev: the ubcore device;
 */
void ubcore_unregister_device(struct ubcore_device *dev);
/**
 * Dispatch an asynchronous event to all registered handlers
 * @param[in] event: asynchronous event;
 */
void ubcore_dispatch_async_event(struct ubcore_event *event);

/**
 * Allocate physical memory and do DMA mapping
 * @param[in] dev: the ubcore device;
 * @param[in] va: the VA address to be mapped.
 * @param[in] len: Length of the address space to be allocated and mapped by DMA.
 * @param[in] flag: Attribute flags
 * Return: umem ptr on success, ERR_PTR on error
 */
struct ubcore_umem *ubcore_umem_get(struct ubcore_device *dev, uint64_t va, uint64_t len,
				    union ubcore_umem_flag flag);

/**
 * Find best HW page size to use for this segment
 * @param[in] umem: umem struct, return of ubcore_umem_get;
 * @param[in] page_size_bitmap: bitmap of HW supported page sizes, must include PAGE_SIZE;
 * @param[in] va: Initial address of this segment.
 * Return: before kernel 5.3: return 4K;
 * kernel 5.3 and later: Returns 0 if the umem requires page sizes not supported by the
 * driver to be mapped; returns non-zero on the best page size.
 */
uint64_t ubcore_umem_find_best_page_size(struct ubcore_umem *umem, uint64_t page_size_bitmap,
	uint64_t va);

/**
 * Release umem allocated
 * @param[in] umem: the ubcore umem created before
 */
void ubcore_umem_release(struct ubcore_umem *umem);

/**
 * Invoke get mtu value, called only by driver
 * @param[in] mtu: specifies the MTU value of the NIC interface.
 * @return: The MTU of the UB protocol, this value removes the length of the network layer,
 * transport layer, transaction layer header and ICRC.
 */
enum ubcore_mtu ubcore_get_mtu(int mtu);

/**
 * TPF receives msg from VF or PF, called only by driver.
 * @param[in] dev: TPF device;
 * @param[in] req: received msg;
 * @return: 0 on success, other value on error
 */
int ubcore_recv_req(struct ubcore_device *dev, struct ubcore_req_host *req);

/**
 * VF or PF receives msg from TPF, called only by driver.
 * @param[in] dev: VF or PF device;
 * @param[in] resp: received msg;
 * @return: 0 on success, other value on error
 */
int ubcore_recv_resp(struct ubcore_device *dev, struct ubcore_resp *resp);

/**
 * Invoke ndev bind port_id, called only by driver
 * @param[in] dev: the ubcore device;
 * @param[in] ndev: The netdev corresponding to the initial port
 * @param[in] port_id: The physical port_id is the same as the port_id presented in the sysfs file,
 * and port_id is configured in TP during link establishment.
 * @return: 0 on success, other value on error
 */
int ubcore_set_port_netdev(struct ubcore_device *dev, struct net_device *ndev,
	unsigned int port_id);

/**
 * Invoke ndev unbind port_id, called only by driver
 * @param[in] dev: the ubcore device;
 * @param[in] ndev: The netdev corresponding to the initial port
 * @param[in] port_id: The physical port_id is the same as the port_id presented in the sysfs file,
 * and port_id is configured in TP during link establishment.
 * @return: 0 on success, other value on error
 */
int ubcore_unset_port_netdev(struct ubcore_device *dev, struct net_device *ndev,
	unsigned int port_id);

/**
 * Invoke ndev unbind port_id, called only by driver
 * @param[in] dev: the ubcore device;
 * @return: void
 */
void ubcore_put_port_netdev(struct ubcore_device *dev);

/**
 * Invoke The management system calls ubcore interface through uvs_admin to set the device name
 * and add sip information used for link establishment.
 * @param[in] sip: Specify the sip information used to establish the link, including device name,
 * sip, mac, vlan, physical port list.
 * @return: 0 on success, other value on error
 */
int ubcore_add_sip(struct ubcore_sip_info *sip, uint32_t *sip_idx);

/**
 * Invoke The management system calls ubcore interface through UVS to delete the sip information.
 * @param[in] sip: Specify the sip information used to establish the link, including device name,
 * sip, mac, vlan, physical port list.
 * @return: 0 on success, other value on error
 */
int ubcore_delete_sip(struct ubcore_sip_info *sip);

/**
 * Invoke get eid list
 * @param[in] dev: the ubcore device;
 * @param[out] cnt: eid cnt
 * @return: eid info on success, NULL on error
 */
struct ubcore_eid_info *ubcore_get_eid_list(struct ubcore_device *dev, uint32_t *cnt);

/**
 * Release umem allocated
 * @param[in] eid_list: the eid list to be freed
 */
void ubcore_free_eid_list(struct ubcore_eid_info *eid_list);

#endif
