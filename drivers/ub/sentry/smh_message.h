/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
 * Description: Header File for Sentry Msg Helper
 * Author: Luckky
 * Create: 2025-02-17
 */

#ifndef SMH_MESSAGE_H
#define SMH_MESSAGE_H

#include <uapi/ub/sentry/smh_common_type.h>

uint64_t smh_get_new_msg_id(void);
int smh_message_send(struct sentry_msg_helper_msg *msg, bool ack);
ssize_t smh_message_get(void __user *buf);
int smh_message_ack(struct sentry_msg_helper_msg *msg);
int smh_message_get_ack(struct sentry_msg_helper_msg *msg);

int smh_message_init(void);
void smh_message_exit(void);
#endif
