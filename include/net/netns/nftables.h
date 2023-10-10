/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _NETNS_NFTABLES_H_
#define _NETNS_NFTABLES_H_

#include <linux/list.h>
#include <linux/kabi.h>

struct netns_nftables {
	KABI_DEPRECATE(struct list_head, tables)
	KABI_DEPRECATE(struct list_head, commit_list)
	KABI_DEPRECATE(struct list_head, module_list)
	KABI_DEPRECATE(struct list_head, notify_list)
	KABI_DEPRECATE(struct mutex, commit_mutex)
	KABI_DEPRECATE(unsigned int, base_seq)
	u8			gencursor;
	KABI_DEPRECATE(u8, validate_state)

	KABI_RESERVE(1)
};

#endif
