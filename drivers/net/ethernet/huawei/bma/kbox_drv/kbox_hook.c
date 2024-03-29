// SPDX-License-Identifier: GPL-2.0
/* Huawei iBMA driver.
 * Copyright (c) 2017, Huawei Technologies Co., Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/notifier.h>
#include <linux/panic_notifier.h>
#include "kbox_include.h"
#include "kbox_dump.h"
#include "kbox_hook.h"

int panic_notify(struct notifier_block *this,
		 unsigned long event, void *msg);

static int die_notify(struct notifier_block *self,
		      unsigned long val, void *data);

static struct notifier_block g_panic_nb = {
	.notifier_call = panic_notify,
	.priority = 100,
};

static struct notifier_block g_die_nb = {
	.notifier_call = die_notify,
};

int panic_notify(struct notifier_block *pthis, unsigned long event, void *msg)
{
	UNUSED(pthis);
	UNUSED(event);

	kbox_dump_event(KBOX_PANIC_EVENT, DUMPSTATE_PANIC_RESET,
			(const char *)msg);

	return NOTIFY_OK;
}

int die_notify(struct notifier_block *self, unsigned long val, void *data)
{
	struct kbox_die_args *args = (struct kbox_die_args *)data;

	if (!args)
		return NOTIFY_OK;

	switch (val) {
	case 1:
		break;
	case 5:
		if (strcmp(args->str, "nmi") == 0)
			return NOTIFY_OK;
#ifdef CONFIG_X86
		kbox_dump_event(KBOX_MCE_EVENT, DUMPSTATE_MCE_RESET, args->str);
#endif
		break;

	default:
		break;
	}

	return NOTIFY_OK;
}

int kbox_register_hook(void)
{
	int ret = 0;

	ret = atomic_notifier_chain_register(&panic_notifier_list, &g_panic_nb);
	if (ret)
		KBOX_MSG("atomic_notifier_chain_register g_panic_nb failed!\n");

	ret = register_die_notifier(&g_die_nb);
	if (ret)
		KBOX_MSG("register_die_notifier g_die_nb failed!\n");

	return ret;
}

void kbox_unregister_hook(void)
{
	int ret = 0;

	ret =
	    atomic_notifier_chain_unregister(&panic_notifier_list, &g_panic_nb);
	if (ret < 0) {
		KBOX_MSG
		    ("atomic_notifier_chain_unregister g_panic_nb failed!\n");
	}

	ret = unregister_die_notifier(&g_die_nb);
	if (ret < 0)
		KBOX_MSG("unregister_die_notifier g_die_nb failed!\n");
}
