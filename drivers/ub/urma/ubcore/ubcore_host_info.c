// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 *
 * Description: ubcore host info map
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/in6.h>
#include <linux/slab.h>
#include <linux/rcupdate.h>
#include <linux/mutex.h>
#include <linux/errno.h>
#include <ub/urma/ubcore_types.h>

#include "ubcore_host_trie.h"
#include "ubcore_host_info.h"

static struct ubcore_host_trie g_ubcore_host_trie = {
	.root = RCU_INITIALIZER(NULL),
	.lock = __MUTEX_INITIALIZER(g_ubcore_host_trie.lock)
};

static bool ubcore_eid_is_zero(const union ubcore_eid *eid)
{
	u32 i;

	if (!eid)
		return true;

	for (i = 0; i < UBCORE_EID_SIZE; i++) {
		if (eid->raw[i] != 0)
			return false;
	}

	return true;
}

int ubcore_insert_host_info(const union ubcore_eid *eid,
			    const struct ubcore_host_info *host_info)
{
	int ret;

	if (ubcore_eid_is_zero(eid))
		return -EINVAL;

	if (!host_info)
		return -EINVAL;

	mutex_lock(&g_ubcore_host_trie.lock);
	ret = ubcore_host_trie_insert(&g_ubcore_host_trie, eid, host_info);
	mutex_unlock(&g_ubcore_host_trie.lock);

	return ret;
}

int ubcore_delete_host_info(const union ubcore_eid *eid)
{
	int ret;

	if (ubcore_eid_is_zero(eid))
		return -EINVAL;

	mutex_lock(&g_ubcore_host_trie.lock);
	ret = ubcore_host_trie_delete(&g_ubcore_host_trie, eid);
	mutex_unlock(&g_ubcore_host_trie.lock);

	return ret;
}

int ubcore_lookup_host_info(const union ubcore_eid *eid,
			    struct ubcore_host_info *host_info)
{
	if (ubcore_eid_is_zero(eid))
		return -EINVAL;

	if (!host_info)
		return -EINVAL;

	return ubcore_host_trie_lookup(&g_ubcore_host_trie, eid, host_info);
}

void ubcore_flush_host_info(void)
{
	mutex_lock(&g_ubcore_host_trie.lock);
	ubcore_host_trie_destroy(&g_ubcore_host_trie);
	mutex_unlock(&g_ubcore_host_trie.lock);
}
