/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#ifndef __UNIC_LOG_H__
#define __UNIC_LOG_H__

#include <linux/jiffies.h>
#include <linux/ratelimit.h>
#include <linux/ratelimit_types.h>

#define unic_dbg(_unic_dev, fmt, ...) do {                                    \
		if (unic_dbg_log())                                           \
			netdev_info((_unic_dev)->comdev.netdev,               \
				    "(pid %d) " fmt, current->pid,            \
				    ##__VA_ARGS__);                           \
	} while (0)

#define unic_err(_unic_dev, fmt, ...)                                         \
	netdev_err((_unic_dev)->comdev.netdev, "(pid %d) " fmt,               \
		   current->pid, ##__VA_ARGS__)

#define unic_info(_unic_dev, fmt, ...)                                        \
	netdev_info((_unic_dev)->comdev.netdev, "(pid %d) " fmt,              \
		    current->pid, ##__VA_ARGS__)

#define unic_warn(_unic_dev, fmt, ...)                                        \
	netdev_warn((_unic_dev)->comdev.netdev, "(pid %d) " fmt,              \
		    current->pid, ##__VA_ARGS__)

#define unic_err_rl(_unic_dev, name, fmt, ...) do {                           \
	if (__ratelimit(&(_unic_dev)->log_rs.name##_rs)) {                    \
		unic_err(_unic_dev, fmt, ##__VA_ARGS__);                      \
	} else {                                                              \
		(_unic_dev)->log_rs.name##_cnt++;                             \
		unic_dbg(_unic_dev, fmt, ##__VA_ARGS__);                      \
	}                                                                     \
} while (0)

#define unic_info_rl(_unic_dev, name, fmt, ...) do {                          \
	if (__ratelimit(&(_unic_dev)->log_rs.name##_rs)) {                    \
		unic_info(_unic_dev, fmt, ##__VA_ARGS__);                     \
	} else {                                                              \
		(_unic_dev)->log_rs.name##_cnt++;                             \
		unic_dbg(_unic_dev, fmt, ##__VA_ARGS__);                      \
	}                                                                     \
} while (0)

#define unic_warn_rl(_unic_dev, name, fmt, ...) do {                          \
	if (__ratelimit(&(_unic_dev)->log_rs.name##_rs)) {                    \
		unic_warn(_unic_dev, fmt, ##__VA_ARGS__);                     \
	} else {                                                              \
		(_unic_dev)->log_rs.name##_cnt++;                             \
		unic_dbg(_unic_dev, fmt, ##__VA_ARGS__);                      \
	}                                                                     \
} while (0)

#define unic_err_rl_hr(_unic_dev, name, fmt, ...) do {                        \
	if (__ratelimit(&(_unic_dev)->log_rs.name##_rs) &&                    \
		__ratelimit(&(_unic_dev)->log_rs.name##_hr_rs)) {             \
		unic_err(_unic_dev, fmt, ##__VA_ARGS__);                      \
	} else {                                                              \
		(_unic_dev)->log_rs.name##_cnt++;                             \
		unic_dbg(_unic_dev, fmt, ##__VA_ARGS__);                      \
	}                                                                     \
} while (0)

#define unic_info_rl_hr(_unic_dev, name, fmt, ...) do {                       \
	if (__ratelimit(&(_unic_dev)->log_rs.name##_rs) &&                    \
		__ratelimit(&(_unic_dev)->log_rs.name##_hr_rs)) {             \
		unic_info(_unic_dev, fmt, ##__VA_ARGS__);                     \
	} else {                                                              \
		(_unic_dev)->log_rs.name##_cnt++;                             \
		unic_dbg(_unic_dev, fmt, ##__VA_ARGS__);                      \
	}                                                                     \
} while (0)

#define unic_warn_rl_hr(_unic_dev, name, fmt, ...) do {                       \
	if (__ratelimit(&(_unic_dev)->log_rs.name##_rs) &&                    \
		__ratelimit(&(_unic_dev)->log_rs.name##_hr_rs)) {             \
		unic_warn(_unic_dev, fmt, ##__VA_ARGS__);                     \
	} else {                                                              \
		(_unic_dev)->log_rs.name##_cnt++;                             \
		unic_dbg(_unic_dev, fmt, ##__VA_ARGS__);                      \
	}                                                                     \
} while (0)

#define UNIC_RATELIMIT_INTERVAL     (1 * HZ)
#define UNIC_RATELIMIT_BURST        2

#define UNIC_RATELIMIT_INTERVAL_HR  (60 * 60 * HZ)
#define UNIC_RATELIMIT_BURST_HR     50

#define UNIC_RATELIMIT_INIT(unic_dev, name) do {                              \
	raw_spin_lock_init(&(unic_dev)->log_rs.name##_rs.lock);               \
	(unic_dev)->log_rs.name##_rs.interval = UNIC_RATELIMIT_INTERVAL;      \
	(unic_dev)->log_rs.name##_rs.burst = UNIC_RATELIMIT_BURST;            \
} while (0)

#define UNIC_RATELIMIT_INIT_HR(unic_dev, name) do {                           \
	UNIC_RATELIMIT_INIT(unic_dev, name);                                  \
	(unic_dev)->log_rs.name##_rs.flags |= RATELIMIT_MSG_ON_RELEASE;       \
	raw_spin_lock_init(&(unic_dev)->log_rs.name##_hr_rs.lock);            \
	(unic_dev)->log_rs.name##_hr_rs.interval =                            \
		UNIC_RATELIMIT_INTERVAL_HR;                                   \
	(unic_dev)->log_rs.name##_hr_rs.burst = UNIC_RATELIMIT_BURST_HR;      \
} while (0)

#define UNIC_DEFINE_RATELIMIT(name)                                           \
	struct ratelimit_state name##_rs;                                     \
	u32 name##_cnt

#define UNIC_DEFINE_RATELIMIT_HR(name)                                        \
	UNIC_DEFINE_RATELIMIT(name);                                          \
	struct ratelimit_state name##_hr_rs

struct unic_log_rs {
	UNIC_DEFINE_RATELIMIT_HR(query_link_status_fail);
	UNIC_DEFINE_RATELIMIT_HR(set_promisc_fail);
	UNIC_DEFINE_RATELIMIT_HR(set_vlan_fail);
	UNIC_DEFINE_RATELIMIT_HR(set_stack_ip_fail);
	UNIC_DEFINE_RATELIMIT_HR(alloc_skb_fail);
	UNIC_DEFINE_RATELIMIT_HR(fill_netlink_ip_req_fail);
	UNIC_DEFINE_RATELIMIT_HR(rm_mac_fail);
	UNIC_DEFINE_RATELIMIT_HR(uc_mac_exists);
	UNIC_DEFINE_RATELIMIT_HR(add_mac_fail);
	UNIC_DEFINE_RATELIMIT_HR(notify_bond_ip_fail);
	UNIC_DEFINE_RATELIMIT_HR(send_ctrlq_bond_status_fail);
	UNIC_DEFINE_RATELIMIT_HR(tx_timeout);
};

#endif /* __UNIC_LOG_H__ */
