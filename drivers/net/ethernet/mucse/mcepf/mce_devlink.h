/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2024-2026 Mucse Corporation. */

#ifndef _MCE_DEVLINK_H_
#define _MCE_DEVLINK_H_

#include "mce.h"

#if IS_ENABLED(CONFIG_NET_DEVLINK)

enum mce_devlink_param_id {
	MCE_DEVLINK_PARAM_ID_BASE = DEVLINK_PARAM_GENERIC_ID_MAX,
	MCE_DEVLINK_PARAM_ID_VF_MAX_RING,
};

struct mce_pf *mce_allocate_pf(struct device *dev);

void mce_devlink_register(struct mce_pf *pf);
void mce_devlink_unregister(struct mce_pf *pf);
int mce_devlink_register_params(struct mce_pf *pf);
void mce_devlink_unregister_params(struct mce_pf *pf);
int mce_devlink_create_vf_port(struct mce_pf *pf, int vfid);
void mce_devlink_destroy_vf_port(struct mce_pf *pf, int vfid);
#else /* CONFIG_NET_DEVLINK */
static inline struct mce_pf *mce_allocate_pf(struct device *dev)
{
	return devm_kzalloc(dev, sizeof(struct mce_pf), GFP_KERNEL);
}

static inline void mce_devlink_register(struct mce_pf *pf) { }
static inline void mce_devlink_unregister(struct mce_pf *pf) { }

static inline int mce_devlink_register_params(struct mce_pf *pf)
{
	return 0;
}

static inline void mce_devlink_unregister_params(struct mce_pf *pf)
{
}
#endif /* !CONFIG_NET_DEVLINK */

#endif /* _MCE_DEVLINK_H_ */
