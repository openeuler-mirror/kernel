// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 *
 * Description: ubagg jetty ops implementation
 * Author: Wang Hang
 * Create: 2025-08-13
 * Note:
 * History: 2025-08-13: Create file
 */

#include "ubagg_topo_info.h"
#include "ubagg_log.h"

#include "ubagg_jetty.h"

struct ubagg_target_jetty {
	struct ubcore_tjetty base;
};

struct ubagg_import_jetty_udata {
	struct ubagg_jetty_exchange_info exinfo;
	bool connected[UBAGG_DEV_MAX_NUM][UBAGG_DEV_MAX_NUM];
};

static int fill_udata(struct ubcore_tjetty_cfg *cfg, struct ubcore_udata *udata)
{
	struct ubagg_import_jetty_udata *udata_typed;
	bool connected[UBAGG_DEV_MAX_NUM][UBAGG_DEV_MAX_NUM] = { 0 };
	int ret;

	ret = find_linked_port(&cfg->id.eid, connected);
	if (ret != 0) {
		ubagg_log_err("Failed to find linked port\n");
		return ret;
	}
	udata_typed =
		(struct ubagg_import_jetty_udata *)udata->udrv_data->out_addr;
	if (udata->udrv_data->out_len <
	    sizeof(struct ubagg_import_jetty_udata)) {
		ubagg_log_err("Invalid udrv_data out_len: %u.\n",
			      udata->udrv_data->out_len);
		return -EINVAL;
	}

	ret = copy_to_user((void __user *)udata_typed->connected,
			   (void *)connected, sizeof(udata_typed->connected));
	if (ret != 0) {
		ubagg_log_err("Failed to copy to user, ret:%d", ret);
		return ret;
	}
	return 0;
}

struct ubcore_tjetty *ubagg_import_jfr(struct ubcore_device *dev,
				       struct ubcore_tjetty_cfg *cfg,
				       struct ubcore_udata *udata)
{
	struct ubagg_target_jetty *tjfr;
	int ret;

	if (cfg == NULL || dev == NULL || udata == NULL ||
	    udata->udrv_data == NULL)
		return NULL;

	ret = fill_udata(cfg, udata);
	if (ret != 0) {
		ubagg_log_err("Failed to fill udata, ret:%d\n", ret);
		return NULL;
	}

	tjfr = kzalloc(sizeof(struct ubagg_target_jetty), GFP_KERNEL);
	if (tjfr == NULL)
		return NULL;
	ubagg_log_info("Import jfr successfully, is:%u.\n", cfg->id.id);
	return &tjfr->base;
}

int ubagg_unimport_jfr(struct ubcore_tjetty *tjfr)
{
	struct ubagg_target_jetty *ubagg_tjfr;

	if (tjfr == NULL || tjfr->ub_dev == NULL || tjfr->uctx == NULL) {
		ubagg_log_err("Invalid parameter.\n");
		return -EINVAL;
	}
	ubagg_tjfr = (struct ubagg_target_jetty *)tjfr;
	ubagg_log_info("Unimport jfr successfully, id:%u.\n",
		       ubagg_tjfr->base.cfg.id.id);
	kfree(ubagg_tjfr);
	return 0;
}

struct ubcore_tjetty *ubagg_import_jetty(struct ubcore_device *dev,
					 struct ubcore_tjetty_cfg *cfg,
					 struct ubcore_udata *udata)
{
	struct ubagg_target_jetty *tjetty;
	int ret;

	if (cfg == NULL || dev == NULL || udata == NULL ||
	    udata->udrv_data == NULL)
		return NULL;

	ret = fill_udata(cfg, udata);
	if (ret != 0) {
		ubagg_log_err("Failed to fill udata, ret:%d\n", ret);
		return NULL;
	}

	tjetty = kzalloc(sizeof(struct ubagg_target_jetty), GFP_KERNEL);
	if (tjetty == NULL)
		return NULL;
	ubagg_log_info("Import jetty successfully, %u\n", cfg->id.id);
	return &tjetty->base;
}

int ubagg_unimport_jetty(struct ubcore_tjetty *tjetty)
{
	struct ubagg_target_jetty *ubagg_tjetty;

	if (tjetty == NULL || tjetty->ub_dev == NULL || tjetty->uctx == NULL)
		return -EINVAL;
	ubagg_tjetty = (struct ubagg_target_jetty *)tjetty;
	ubagg_log_info("Unimport jetty successfully, id:%u.\n",
		       tjetty->cfg.id.id);
	kfree(ubagg_tjetty);
	return 0;
}
