/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
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
 * Description: Types definition provided by ubcore to client and ubep device
 * Author: Qian Guoxin, Ouyang Changchun
 * Create: 2021-8-3
 * Note:
 * History: 2021-8-3: Create file
 * History: 2021-11-23: Add segment and jetty management
 */

#ifndef UBCORE_TYPES_H
#define UBCORE_TYPES_H

#include <linux/list.h>
#include <linux/device.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/scatterlist.h>
#include <linux/mm.h>

#define UBCORE_MAX_DEV_NAME 64
#define UBCORE_MAX_DRIVER_NAME 64
#define UBCORE_HASH_TABLE_SIZE 64
#define UBCORE_NET_ADDR_BYTES (16)
#define UBCORE_MAC_BYTES 6
#define UBCORE_MAX_ATTR_GROUP 3
#define UBCORE_EID_SIZE (16)
#define UBCORE_EID_STR_LEN (39)
#define EID_FMT                                                                                    \
	"%2.2x%2.2x:%2.2x%2.2x:%2.2x%2.2x:%2.2x%2.2x:%2.2x%2.2x:%2.2x%2.2x:%2.2x%2.2x:%2.2x%2.2x"
#define EID_UNPACK(...) __VA_ARGS__
#define EID_RAW_ARGS(eid) EID_UNPACK(eid[0], eid[1], eid[2], eid[3], eid[4], eid[5], eid[6],	\
	eid[7], eid[8], eid[9], eid[10], eid[11], eid[12], eid[13], eid[14], eid[15])
#define EID_ARGS(eid) EID_RAW_ARGS((eid).raw)

enum ubcore_transport_type {
	UBCORE_TRANSPORT_INVALID = -1,
	UBCORE_TRANSPORT_UB,
	UBCORE_TRANSPORT_IB,
	UBCORE_TRANSPORT_IP,
	UBCORE_TRANSPORT_MAX
};

union ubcore_eid {
	uint8_t raw[UBCORE_EID_SIZE];
	struct {
		uint64_t resv;
		uint32_t prefix;
		uint32_t addr;
	} in4;
	struct {
		uint64_t subnet_prefix;
		uint64_t interface_id;
	} in6;
};

struct ubcore_device_attr {
	union ubcore_eid eid; // RW
	uint32_t max_eid_cnt;
};

struct ubcore_net_addr {
	union {
		uint8_t raw[UBCORE_NET_ADDR_BYTES];
		struct {
			uint64_t resv1;
			uint32_t resv2;
			uint32_t addr;
		} in4;
		struct {
			uint64_t subnet_prefix;
			uint64_t interface_id;
		} in6;
	} net_addr;
	uint64_t vlan; /* available for UBOE */
	uint8_t mac[UBCORE_MAC_BYTES]; /* available for UBOE */
};

enum ubcore_stats_key_type {
	UBCORE_STATS_KEY_TP = 1,
	UBCORE_STATS_KEY_TPG = 2,
	UBCORE_STATS_KEY_JFS = 3,
	UBCORE_STATS_KEY_JFR = 4,
	UBCORE_STATS_KEY_JETTY = 5,
	UBCORE_STATS_KEY_JETTY_GROUP = 6
};

struct ubcore_stats_key {
	uint8_t type; /* stats type, refer to enum ubcore_stats_key_type */
	uint32_t key; /* key can be tpn/tpgn/jetty_id/token_id/ctx_id/etc */
};

struct ubcore_stats_com_val {
	uint64_t tx_pkt;
	uint64_t rx_pkt;
	uint64_t tx_bytes;
	uint64_t rx_bytes;
	uint64_t tx_pkt_err;
	uint64_t rx_pkt_err;
};

struct ubcore_stats_val {
	uint64_t addr; /* this addr is alloc and free by ubcore,
			* refer to struct ubcore_stats_com_val
			*/

	uint32_t len;	/* [in/out] real length filled when success
			 * to query and buffer length enough;
			 * expected length filled and return failure when buffer length not enough
			 */
};

struct ubcore_device;
struct ubcore_ops {
	struct module *owner; /* kernel driver module */
	char driver_name[UBCORE_MAX_DRIVER_NAME]; /* user space driver name */
	uint32_t abi_version; /* abi version of kernel driver */
	/**
	 * set function entity id for ub device. must be called before alloc context
	 * @param[in] dev: the ub device handle;
	 * @param[in] eid: function entity id (eid) to set;
	 * @return: 0 on success, other value on error
	 */
	int (*set_eid)(struct ubcore_device *dev, union ubcore_eid eid);
	/**
	 * query device attributes
	 * @param[in] dev: the ub device handle;
	 * @param[out] attr: attributes for the driver to fill in
	 * @return: 0 on success, other value on error
	 */
	int (*query_device_attr)(struct ubcore_device *dev, struct ubcore_device_attr *attr);
	/**
	 * set ub network address
	 * @param[in] dev: the ub device handle;
	 * @param[in] net_addr: net_addr to set
	 * @return: 0 on success, other value on error
	 */
	int (*set_net_addr)(struct ubcore_device *dev, const struct ubcore_net_addr *net_addr);
	/**
	 * unset ub network address
	 * @param[in] dev: the ub device handle;
	 * @param[in] net_addr: net_addr to unset
	 * @return: 0 on success, other value on error
	 */
	int (*unset_net_addr)(struct ubcore_device *dev, const struct ubcore_net_addr *net_addr);
	/**
	 * query_stats. success to query and buffer length is enough
	 * @param[in] dev: the ub device handle;
	 * @param[in] key: type and key value of the ub device to query;
	 * @param[in/out] val: address and buffer length of query results
	 * @return: 0 on success, other value on error
	 */
	int (*query_stats)(const struct ubcore_device *dev, struct ubcore_stats_key *key,
			   struct ubcore_stats_val *val);
};

struct ubcore_device {
	struct list_head list_node; /* add to device list */

	/* driver fills start */
	char dev_name[UBCORE_MAX_DEV_NAME];

	struct device *dma_dev;
	struct device dev;
	struct net_device *netdev;
	struct ubcore_ops *ops;
	enum ubcore_transport_type transport_type;
	int num_comp_vectors; /* Number of completion interrupt vectors for the device */
	struct ubcore_device_attr attr;
	struct attribute_group *group[UBCORE_MAX_ATTR_GROUP]; /* driver may fill group [1] */
	/* driver fills end */

	/* port management */
	struct kobject *ports_parent; /* kobject parent of the ports in the port list */
	struct list_head port_list;

	/* For ubcore client */
	spinlock_t client_ctx_lock;
	struct list_head client_ctx_list;
	struct list_head event_handler_list;
	spinlock_t event_handler_lock;

	/* protect from unregister device */
	atomic_t use_cnt;
	struct completion comp;
};

struct ubcore_client {
	struct list_head list_node;
	char *client_name;
	int (*add)(struct ubcore_device *dev);
	void (*remove)(struct ubcore_device *dev, void *client_ctx);
};

struct ubcore_client_ctx {
	struct list_head list_node;
	void *data; // Each ubep device create some data on the client, such as uburma_device.
	struct ubcore_client *client;
};

#endif
