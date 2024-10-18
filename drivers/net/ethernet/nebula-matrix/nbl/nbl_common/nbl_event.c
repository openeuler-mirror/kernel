// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#include "nbl_event.h"

static struct nbl_event_mgt *event_mgt;

void nbl_event_notify(enum nbl_event_type type, void *event_data, u16 src_vsi_id, u16 board_id)
{
	struct nbl_event_notifier_list *notifier_list = &event_mgt->notifier_list[type];
	struct nbl_event_notifier *notifier = NULL;

	mutex_lock(&notifier_list->notifier_lock);

	list_for_each_entry(notifier, &notifier_list->list, node) {
		if (src_vsi_id != notifier->src_vsi_id || board_id != notifier->board_id)
			continue;

		mutex_lock(&notifier->callback_lock);
		notifier->callback.callback(type, event_data, notifier->callback.callback_data);
		mutex_unlock(&notifier->callback_lock);
	}

	mutex_unlock(&notifier_list->notifier_lock);
}

int nbl_event_register(enum nbl_event_type type, struct nbl_event_callback *callback,
		       u16 src_vsi_id, u16 board_id)
{
	struct nbl_event_notifier_list *notifier_list = &event_mgt->notifier_list[type];
	struct nbl_event_notifier *notifier = NULL;

	notifier = kzalloc(sizeof(*notifier), GFP_KERNEL);
	if (!notifier)
		return -ENOMEM;

	notifier->src_vsi_id = src_vsi_id;
	notifier->board_id = board_id;
	notifier->callback.callback = callback->callback;
	notifier->callback.callback_data = callback->callback_data;

	mutex_init(&notifier->callback_lock);

	mutex_lock(&notifier_list->notifier_lock);
	list_add_tail(&notifier->node, &notifier_list->list);
	mutex_unlock(&notifier_list->notifier_lock);

	return 0;
}

void nbl_event_unregister(enum nbl_event_type type, struct nbl_event_callback *callback,
			  u16 src_vsi_id, u16 board_id)
{
	struct nbl_event_notifier_list *notifier_list = &event_mgt->notifier_list[type];
	struct nbl_event_notifier *notifier = NULL;

	mutex_lock(&notifier_list->notifier_lock);

	list_for_each_entry(notifier, &notifier_list->list, node) {
		if (notifier->callback.callback == callback->callback &&
		    notifier->callback.callback_data == callback->callback_data &&
		    notifier->src_vsi_id == src_vsi_id && notifier->board_id == board_id) {
			list_del(&notifier->node);
			kfree(notifier);
			break;
		}
	}

	mutex_unlock(&notifier_list->notifier_lock);
}

int nbl_event_init(void)
{
	int i = 0;

	event_mgt = kzalloc(sizeof(*event_mgt), GFP_KERNEL);
	if (!event_mgt)
		return -ENOMEM;

	for (i = 0; i < NBL_EVENT_MAX; i++) {
		INIT_LIST_HEAD(&event_mgt->notifier_list[i].list);
		mutex_init(&event_mgt->notifier_list[i].notifier_lock);
	}

	return 0;
}

void nbl_event_remove(void)
{
	struct nbl_event_notifier *notifier = NULL, *notifier_safe = NULL;
	int i = 0;

	for (i = 0; i < NBL_EVENT_MAX; i++) {
		list_for_each_entry_safe(notifier, notifier_safe,
					 &event_mgt->notifier_list[i].list, node) {
			list_del(&notifier->node);
			kfree(notifier);
		}
	}

	kfree(event_mgt);
	event_mgt = NULL;
}
