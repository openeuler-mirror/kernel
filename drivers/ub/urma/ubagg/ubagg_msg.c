// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 *
 * Description: ubagg bonding message dispatch implementation
 * Author: Wang Hang
 * Create: 2026-06-12
 * Note:
 * History: 2026-06-12: create file
 */

#include <linux/spinlock.h>

#include "ubagg_log.h"
#include "ubagg_types.h"

#include "ubagg_msg.h"

struct ubagg_msg_slot {
	ubagg_msg_handler_t handler;
	uint16_t msg_len;
};

static DEFINE_SPINLOCK(g_msg_lock);
static struct ubagg_msg_slot g_msg_slots[UBAGG_COMM_MSG_MAX];

static void handle_bonding_msg(struct ubcore_device *dev,
			       struct ubcore_comm_msg *msg, void *conn);

int ubagg_msg_init(void)
{
	return ubcore_register_comm_msg_handler(UBAGG_COMM_PROTOCOL,
						handle_bonding_msg);
}

void ubagg_msg_uninit(void)
{
	ubcore_unregister_comm_msg_handler(UBAGG_COMM_PROTOCOL);
}

int ubagg_msg_register_handlers(const struct ubagg_msg_desc *msg_descs,
				uint32_t num_descs)
{
	unsigned long flags;
	uint32_t i;
	int ret;

	if (msg_descs == NULL)
		return num_descs == 0 ? 0 : -EINVAL;

	spin_lock_irqsave(&g_msg_lock, flags);
	for (i = 0; i < num_descs; i++) {
		if (msg_descs[i].type >= UBAGG_COMM_MSG_MAX ||
		    msg_descs[i].handler == NULL) {
			ret = -EINVAL;
			goto rollback;
		}
		if (g_msg_slots[msg_descs[i].type].handler != NULL) {
			ret = -EEXIST;
			goto rollback;
		}

		g_msg_slots[msg_descs[i].type].handler = msg_descs[i].handler;
		g_msg_slots[msg_descs[i].type].msg_len =
			msg_descs[i].expected_len;
	}
	spin_unlock_irqrestore(&g_msg_lock, flags);

	return 0;

rollback:
	while (i > 0) {
		i--;
		g_msg_slots[msg_descs[i].type].handler = NULL;
		g_msg_slots[msg_descs[i].type].msg_len = 0;
	}
	spin_unlock_irqrestore(&g_msg_lock, flags);
	return ret;
}

void ubagg_msg_unregister_handlers(const struct ubagg_msg_desc *msg_descs,
				   uint32_t num_descs)
{
	unsigned long flags;

	if (msg_descs == NULL)
		return;

	spin_lock_irqsave(&g_msg_lock, flags);
	while (num_descs > 0) {
		num_descs--;
		if (msg_descs[num_descs].type >= UBAGG_COMM_MSG_MAX)
			continue;
		g_msg_slots[msg_descs[num_descs].type].handler = NULL;
		g_msg_slots[msg_descs[num_descs].type].msg_len = 0;
	}
	spin_unlock_irqrestore(&g_msg_lock, flags);
}

static void handle_bonding_msg(struct ubcore_device *dev,
			       struct ubcore_comm_msg *msg, void *conn)
{
	struct ubagg_msg_slot slot;
	unsigned long flags;

	if (!msg) {
		ubagg_log_err("Invalid param: msg is null");
		return;
	}
	if (msg->version != UBAGG_BONDING_MSG_CUR_VERSION) {
		ubagg_log_err_rl("Unsupported msg version %u, expected %u",
				 msg->version, UBAGG_BONDING_MSG_CUR_VERSION);
		return;
	}
	if (msg->type >= UBAGG_COMM_MSG_MAX) {
		ubagg_log_err("Unhandled msg type %u in bonding service",
			      msg->type);
		return;
	}

	spin_lock_irqsave(&g_msg_lock, flags);
	slot = g_msg_slots[msg->type];
	spin_unlock_irqrestore(&g_msg_lock, flags);

	if (slot.handler == NULL) {
		ubagg_log_err("No handler registered for msg type %u",
			      msg->type);
		return;
	}
	if (slot.msg_len != 0 && msg->len != slot.msg_len) {
		ubagg_log_err("Invalid param: msg type %u len %u, expected %u",
			      msg->type, msg->len, slot.msg_len);
		return;
	}

	slot.handler(dev, msg, conn);
}
