/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2024-2026 Mucse Corporation. */

#ifndef _MCE_ESWITCH_H_
#define _MCE_ESWITCH_H_
#if IS_ENABLED(CONFIG_NET_DEVLINK)
#include <net/devlink.h>
#include "mce.h"

bool mce_is_support_eswitch(struct mce_pf *pf);
int mce_eswitch_alloc_vfs(struct mce_pf *pf);
int mce_eswitch_configure(struct mce_pf *pf);
void mce_eswitch_release(struct mce_pf *pf);
bool mce_is_eswitch_mode_switchdev(struct mce_pf *pf);
int mce_eswitch_mode_get(struct devlink *devlink, u16 *mode);
int mce_eswitch_free_vfs(struct mce_pf *pf);
static inline int mce_eswitch_mode_set(struct devlink __always_unused *devlink,
				       u16 __always_unused mode)
{
	return -EOPNOTSUPP;
}
#else
struct devlink;
static inline bool mce_is_support_eswitch(struct mce_pf *pf)
{
	return 0;
}

static inline int mce_eswitch_alloc_vfs(struct mce_pf *pf)
{
	return 0;
}

static inline int mce_eswitch_configure(struct mce_pf *pf)
{
	return 0;
}

static inline void mce_eswitch_release(struct mce_pf *pf)
{
}

static inline bool mce_is_eswitch_mode_switchdev(struct mce_pf *pf)
{
	return false;
}

static inline int mce_eswitch_mode_get(struct devlink *devlink, u16 *mode)
{
	return 0;
}

static inline int mce_eswitch_free_vfs(struct mce_pf *pf)
{
	return 0;
}

#endif /* CONFIG_NET_DEVLINK */

#endif /* _MCE_ESWITCH_H_ */
