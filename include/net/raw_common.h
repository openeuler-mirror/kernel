/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _RAW_COMMON_H
#define _RAW_COMMON_H

#define RAW_HTABLE_SIZE	MAX_INET_PROTOS

struct raw_hashinfo_new {
	spinlock_t lock;
	struct hlist_nulls_head ht[RAW_HTABLE_SIZE];
};

static inline void raw_hashinfo_init(struct raw_hashinfo_new *hashinfo)
{
	int i;

	spin_lock_init(&hashinfo->lock);
	for (i = 0; i < RAW_HTABLE_SIZE; i++)
		INIT_HLIST_NULLS_HEAD(&hashinfo->ht[i], i);
}

#endif	/* _RAW_COMMON_H */
