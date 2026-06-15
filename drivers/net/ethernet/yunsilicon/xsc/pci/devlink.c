// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include "common/xsc_core.h"
#include "devlink.h"
#include "eswitch.h"

static const struct devlink_ops xsc_devlink_ops = {
	.eswitch_mode_set = xsc_devlink_eswitch_mode_set,
	.eswitch_mode_get = xsc_devlink_eswitch_mode_get,
};

static int xsc_devlink_rep_mode_validate(struct devlink *devlink, u32 id,
					 union devlink_param_value val
					, struct netlink_ext_ack *extack
					)
{
	struct xsc_core_device *dev = devlink_priv(devlink);
	struct xsc_eswitch *eswitch = dev->priv.eswitch;
	char *value = val.vstr;
	u8 eswitch_mode = xsc_get_eswitch_mode(dev);
	int ret = 0;

	if (eswitch_mode != XSC_ESWITCH_LEGACY) {
		xsc_core_err(dev, "rep mode is changed when eswitch is not in legacy mode\n");
		return -EOPNOTSUPP;
	}

	if (!strcmp(value, "kernel"))
		eswitch->offloads.rep_mode = XSC_REP_MODE_KERNEL;
	else if (!strcmp(value, "dpdk"))
		eswitch->offloads.rep_mode = XSC_REP_MODE_DPDK;
	else
		ret = -EINVAL;

	if (ret)
		xsc_core_err(dev, "Bad parameter: supported values are [\"kernel\", \"dpdk\"]");

	return ret;
}

static int xsc_devlink_rep_mode_set(struct devlink *devlink, u32 id,
				    struct devlink_param_gset_ctx *ctx
			    )
{
	struct xsc_core_device *dev = devlink_priv(devlink);
	struct xsc_eswitch *eswitch = dev->priv.eswitch;
	enum xsc_rep_mode mode;

	if (!strcmp(ctx->val.vstr, "kernel"))
		mode = XSC_REP_MODE_KERNEL;
	else
		mode = XSC_REP_MODE_DPDK;

	eswitch->offloads.rep_mode = mode;

	return 0;
}

static int xsc_devlink_rep_mode_get(struct devlink *devlink, u32 id,
				    struct devlink_param_gset_ctx *ctx)
{
	struct xsc_core_device *dev = devlink_priv(devlink);
	struct xsc_eswitch	*eswitch = dev->priv.eswitch;

	if (eswitch->offloads.rep_mode == XSC_REP_MODE_KERNEL)
		strscpy(ctx->val.vstr, "kernel", sizeof(ctx->val.vstr));
	else
		strscpy(ctx->val.vstr, "dpdk", sizeof(ctx->val.vstr));

	return 0;
}

static const struct devlink_param xsc_eswitch_params[] = {
	DEVLINK_PARAM_DRIVER(XSC_DEVLINK_PARAM_ID_REP_MODE,
			     "rep_mode", DEVLINK_PARAM_TYPE_STRING,
			     BIT(DEVLINK_PARAM_CMODE_RUNTIME),
			     xsc_devlink_rep_mode_get,
			     xsc_devlink_rep_mode_set,
			     xsc_devlink_rep_mode_validate),
};

struct devlink *xsc_devlink_alloc(struct device *dev)
{
	return devlink_alloc(&xsc_devlink_ops, sizeof(struct xsc_core_device), dev);
}

void xsc_devlink_free(struct devlink *devlink)
{
	devlink_free(devlink);
}

int xsc_devlink_register(struct devlink *devlink, struct device *dev)
{
	int err = 0;

	if (XSC_VPORT_MANAGER(devlink_priv(devlink))) {
		err = devlink_params_register(devlink, xsc_eswitch_params,
					      ARRAY_SIZE(xsc_eswitch_params));
		if (err)
			return err;
	}

	devlink_register(devlink);
	if (err)
		goto params_reg_err;

	return 0;

params_reg_err:
	if (XSC_VPORT_MANAGER(devlink_priv(devlink)))
		devlink_params_unregister(devlink, xsc_eswitch_params,
					  ARRAY_SIZE(xsc_eswitch_params));

	return err;
}

void xsc_devlink_unregister(struct devlink *devlink)
{
	struct xsc_core_device *xdev = devlink_priv(devlink);

	devlink_unregister(devlink);

	if (XSC_VPORT_MANAGER(xdev))
		devlink_params_unregister(devlink, xsc_eswitch_params,
					  ARRAY_SIZE(xsc_eswitch_params));
}
