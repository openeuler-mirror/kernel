/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#ifndef __UBASE_LOG_H__
#define __UBASE_LOG_H__

#include <linux/dev_printk.h>
#include <linux/ratelimit_types.h>

#define ubase_dbg(_udev, fmt, ...) do {                                       \
	if (ubase_dbg_log())                                                  \
		dev_info(_udev->dev, "(pid %d) " fmt,                         \
			 current->pid, ##__VA_ARGS__);                        \
	} while (0)

#define ubase_err(_udev, fmt, ...)                                            \
	dev_err(_udev->dev, "(pid %d) " fmt,                                  \
		current->pid, ##__VA_ARGS__)

#define ubase_info(_udev, fmt, ...)                                           \
	dev_info(_udev->dev, "(pid %d) " fmt,                                 \
		 current->pid, ##__VA_ARGS__)

#define ubase_warn(_udev, fmt, ...)                                           \
	dev_warn(_udev->dev, "(pid %d) " fmt,                                 \
		 current->pid, ##__VA_ARGS__)

#define ubase_err_rl(_udev, name, fmt, ...) do {                              \
	if (__ratelimit(&(_udev->log_rs.name##_rs))) {                        \
		ubase_err(_udev, fmt, ##__VA_ARGS__);                         \
	} else {                                                              \
		(_udev->log_rs.name##_cnt)++;                                 \
		ubase_dbg(_udev, fmt, ##__VA_ARGS__);                         \
	}                                                                     \
} while (0)

#define ubase_info_rl(_udev, name, fmt, ...) do {                             \
	if (__ratelimit(&(_udev->log_rs.name##_rs))) {                        \
		ubase_info(_udev, fmt, ##__VA_ARGS__);                        \
	} else {                                                              \
		(_udev->log_rs.name##_cnt)++;                                 \
		ubase_dbg(_udev, fmt, ##__VA_ARGS__);                         \
	}                                                                     \
} while (0)

#define ubase_warn_rl(_udev, name, fmt, ...) do {                             \
	if (__ratelimit(&(_udev->log_rs.name##_rs))) {                        \
		ubase_warn(_udev, fmt, ##__VA_ARGS__);                        \
	} else {                                                              \
		(_udev->log_rs.name##_cnt)++;                                 \
		ubase_dbg(_udev, fmt, ##__VA_ARGS__);                         \
	}                                                                     \
} while (0)

#define UBASE_RATELIMIT_INTERVAL (1 * HZ)
#define UBASE_RATELIMIT_BURST 2

#define UBASE_RATELIMIT_INIT(udev, name) do {                                 \
	raw_spin_lock_init(&udev->log_rs.name##_rs.lock);                     \
	udev->log_rs.name##_rs.interval = UBASE_RATELIMIT_INTERVAL;           \
	udev->log_rs.name##_rs.burst    = UBASE_RATELIMIT_BURST;              \
} while (0)

#define UBASE_DEFINE_RATELIMIT(name)                                          \
	struct ratelimit_state name##_rs;                                     \
	u32	name##_cnt

struct ubase_log_rs {
	UBASE_DEFINE_RATELIMIT(ctrlq_other_seq_invalid);
	UBASE_DEFINE_RATELIMIT(ctrlq_wait_resp_timeout);
	UBASE_DEFINE_RATELIMIT(ctrlq_crq_pi_invalid);
	UBASE_DEFINE_RATELIMIT(ctrlq_space_insuffice);
	UBASE_DEFINE_RATELIMIT(ue_send_ctrlq_to_cmdq_fail);
	UBASE_DEFINE_RATELIMIT(ctrlq_is_disabled);
	UBASE_DEFINE_RATELIMIT(ctrlq_msg_queue_wait_timeout);
	UBASE_DEFINE_RATELIMIT(ctrlq_seq_insuffice);
	UBASE_DEFINE_RATELIMIT(send_ctrlq_unsup_resp_fail);
	UBASE_DEFINE_RATELIMIT(send_ue_ctrlq_msg_to_cmdq_fail);
	UBASE_DEFINE_RATELIMIT(mbx_buff_not_empty);
	UBASE_DEFINE_RATELIMIT(cmdq_is_disable);
	UBASE_DEFINE_RATELIMIT(mailbox_cmd_timeout);
	UBASE_DEFINE_RATELIMIT(cmdq_space_insuffice);
	UBASE_DEFINE_RATELIMIT(post_mailbox_fail);
	UBASE_DEFINE_RATELIMIT(wait_mbox_fail);
	UBASE_DEFINE_RATELIMIT(aeq_event_type_exceed_max);
	UBASE_DEFINE_RATELIMIT(arq_queue_full);
	UBASE_DEFINE_RATELIMIT(send_ue_ctrlq_msg_fail);
	UBASE_DEFINE_RATELIMIT(proxy_resp_seq_invalid);
	UBASE_DEFINE_RATELIMIT(err_msn_in_act_resp);
};

#endif /* __UBASE_LOG_H__ */
