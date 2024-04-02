/* SPDX-License-Identifier: GPL-2.0+ */
// Copyright (c) 2022 Hisilicon Limited.

#ifndef __CORE_H__
#define __CORE_H__

#include <linux/types.h>
#include <linux/workqueue.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>

#define ROH_DEVICE_NAME_MAX 64
#define MAX_DEVICE_REFCOUNT 2

enum roh_dev_tx {
	ROHDEV_TX_MIN = INT_MIN, /* make sure enum is signed */
	ROHDEV_TX_OK = 0x00, /* driver took care of packet */
	ROHDEV_TX_BUSY = 0x10, /* driver tx path was busy */
	ROHDEV_TX_LOCKED = 0x20 /* driver tx lock was already taken */
};

enum roh_link_status { ROH_LINK_DOWN = 0, ROH_LINK_UP };

enum roh_mib_type { ROH_MIB_PUBLIC = 0, ROH_MIB_PRIVATE };

static inline void convert_eid_to_mac(u8 *mac, u32 eid)
{
	u64_to_ether_addr((u64)eid, mac);
}

struct roh_eid_attr {
	u32 base;
	u32 num;
};

struct roh_mib_stats {
	struct mutex lock; /* Protect values[] */
	const char * const *names;
	u32 num_counters;
	u64 value[];
};

struct roh_device;
struct roh_device_ops {
	int (*set_eid)(struct roh_device *device, struct roh_eid_attr *attr);
	struct roh_mib_stats *(*alloc_hw_stats)(struct roh_device *device, enum roh_mib_type);
	int (*get_hw_stats)(struct roh_device *device,
			    struct roh_mib_stats *stats, enum roh_mib_type);
};

struct roh_device {
	struct device dev;
	char name[ROH_DEVICE_NAME_MAX];
	struct roh_device_ops ops;
	u32 abi_ver;

	struct rcu_head rcu_head;
	struct rw_semaphore client_data_rwsem;
	struct xarray client_data;

	struct module *owner;
	struct net_device *netdev;

	u32 index;
	/*
	 * Positive refcount indicates that the device is currently
	 * registered and cannot be unregistered.
	 */
	refcount_t refcount;
	struct completion unreg_completion;
	struct mutex unregistration_lock; /* lock for unregiste */

	struct roh_eid_attr eid;
	struct mutex eid_mutex; /* operate eid needs to be mutexed */
	u32 link_status;
	struct notifier_block nb;

	struct attribute_group *hw_stats_ag;
	struct roh_mib_stats *hw_public_stats;
	struct roh_mib_stats *hw_private_stats;
};

enum roh_event_type {
	ROH_EVENT_LINK_DOWN = 0,
	ROH_EVENT_LINK_UP
};

struct roh_event {
	struct roh_device *device;
	enum roh_event_type type;
};

static inline bool roh_device_try_get(struct roh_device *device)
{
	return refcount_inc_not_zero(&device->refcount);
}

struct roh_device *__roh_device_get_by_name(const char *name);

struct roh_device *roh_alloc_device(size_t size);
void roh_dealloc_device(struct roh_device *device);

int roh_register_device(struct roh_device *device);
void roh_unregister_device(struct roh_device *device);

void roh_event_notify(struct roh_event *event);

int roh_core_init(void);
void roh_core_cleanup(void);

#endif /* __CORE_H__ */
