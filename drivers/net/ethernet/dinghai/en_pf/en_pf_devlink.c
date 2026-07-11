// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include <linux/dinghai/driver.h>
#include <net/devlink.h>
#include "en_pf_devlink.h"

struct devlink_ops dh_pf_devlink_ops = {

};

enum {
	DH_PF_PARAMS_MAX,
};

static s32 __maybe_unused sample_check(struct dh_core_dev *dev)
{
	return 1;
}

enum dh_pf_devlink_param_id {
	DH_PF_DEVLINK_PARAM_ID_BASE = DEVLINK_PARAM_GENERIC_ID_MAX,
	DH_PF_DEVLINK_PARAM_ID_SAMPLE,
};

static s32 dh_devlink_sample_set(struct devlink *devlink, u32 id,
				 struct devlink_param_gset_ctx *ctx)
{
	struct dh_core_dev *__maybe_unused dev = devlink_priv(devlink);

	return 0;
}

static s32 dh_devlink_sample_get(struct devlink *devlink, u32 id,
				 struct devlink_param_gset_ctx *ctx)
{
	struct dh_core_dev *__maybe_unused dev = devlink_priv(devlink);

	return 0;
}

#ifdef HAVE_DEVLINK_PARAM_REGISTER
static const struct devlink_params {
	const char *name;
	s32 (*check)(struct dh_core_dev *dev);
	struct devlink_param param;
} devlink_params[] = { [DH_PF_PARAMS_MAX] = {
			       .name = "sample",
			       .check = &sample_check,
			       .param = DEVLINK_PARAM_DRIVER(
				       DH_PF_DEVLINK_PARAM_ID_SAMPLE, "sample",
				       DEVLINK_PARAM_TYPE_BOOL, BIT(DEVLINK_PARAM_CMODE_RUNTIME),
				       dh_devlink_sample_get, dh_devlink_sample_set, NULL),
		       } };

static s32 params_register(struct devlink *devlink)
{
	s32 i = 0;
	s32 err = 0;
	struct dh_core_dev *dh_dev = devlink_priv(devlink);

	for (i = 0; i < ARRAY_SIZE(devlink_params); i++) {
		if (devlink_params[i].check(dh_dev)) {
			err = devlink_param_register(devlink, &devlink_params[i].param);
			if (err)
				goto rollback;
		}
	}

	return 0;

rollback:
	if (i == 0)
		return err;

	for (; i > 0; i--)
		devlink_param_unregister(devlink, &devlink_params[i].param);

	return err;
}

static s32 params_unregister(struct devlink *devlink)
{
	s32 i = 0;

	for (i = 0; i < ARRAY_SIZE(devlink_params); i++)
		devlink_param_unregister(devlink, &devlink_params[i].param);

	return 0;
}
#else
static struct devlink_param devlink_params[] = {
	[DH_PF_PARAMS_MAX] =
		DEVLINK_PARAM_DRIVER(DH_PF_DEVLINK_PARAM_ID_SAMPLE, "sample",
				     DEVLINK_PARAM_TYPE_BOOL, BIT(DEVLINK_PARAM_CMODE_RUNTIME),
				     dh_devlink_sample_get, dh_devlink_sample_set, NULL),
};

static s32 params_register(struct devlink *devlink)
{
	struct dh_core_dev *__maybe_unused dh_dev = devlink_priv(devlink);
	s32 err = 0;

	err = devlink_params_register(devlink, devlink_params, ARRAY_SIZE(devlink_params));

	return err;
}
static s32 params_unregister(struct devlink *devlink)
{
	devlink_params_unregister(devlink, devlink_params, ARRAY_SIZE(devlink_params));

	return 0;
}
#endif

struct dh_core_devlink_ops dh_pf_core_devlink_ops = { .params_register = params_register,
						      .params_unregister = params_unregister };
