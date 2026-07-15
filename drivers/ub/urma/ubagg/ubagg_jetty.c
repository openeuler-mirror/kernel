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
#include "ubagg_connect.h"
#include "ubagg_jetty.h"

struct ubagg_target_jetty {
	struct ubcore_tjetty base;
};

struct ubagg_import_jetty_udata {
	struct ubagg_jetty_exchange_info exinfo;
	bool connected[UBAGG_DEV_MAX_NUM][UBAGG_DEV_MAX_NUM];
};

static int parse_ue_idx_from_udata(struct ubcore_udata *udata, uint32_t *ue_idx)
{
	unsigned long byte;

	if (!udata->udrv_data->in_addr ||
	    udata->udrv_data->in_len < sizeof(*ue_idx)) {
		ubagg_log_err("invalid udata in_addr or in_len:%u.\n",
			      udata->udrv_data->in_len);
		return -EINVAL;
	}

	byte = copy_from_user(
		ue_idx, (void __user *)(uintptr_t)udata->udrv_data->in_addr,
		sizeof(*ue_idx));
	if (byte != 0) {
		ubagg_log_err("failed to copy ue_idx from user, byte:%lu.\n",
			      byte);
		return -EFAULT;
	}

	if (*ue_idx >= IODIE_NUM) {
		ubagg_log_err("invalid ue_idx:%u.\n", *ue_idx);
		return -EINVAL;
	}

	return 0;
}

static int write_jetty_udata(struct ubcore_tjetty_cfg *cfg,
			     struct ubcore_udata *udata,
			     struct ubagg_jetty_exchange_info *jetty_info)
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

	ret = copy_to_user((void __user *)&udata_typed->exinfo, jetty_info,
			   sizeof(udata_typed->exinfo));
	if (ret != 0) {
		ubagg_log_err("Failed to copy jetty info to user, ret:%d", ret);
		return -EFAULT;
	}

	ret = copy_to_user((void __user *)udata_typed->connected,
			   (void *)connected, sizeof(udata_typed->connected));
	if (ret != 0) {
		ubagg_log_err("Failed to copy to user, ret:%d", ret);
		return -EFAULT;
	}
	return 0;
}

struct ubcore_tjetty *ubagg_import_jfr(struct ubcore_device *dev,
				       struct ubcore_tjetty_cfg *cfg,
				       struct ubcore_udata *udata)
{
	struct ubagg_target_jetty *tjfr;
	struct ubagg_jetty_exchange_info jetty_info = { 0 };
	uint32_t ue_idx;
	int ret;

	if (cfg == NULL || dev == NULL || udata == NULL ||
	    udata->udrv_data == NULL)
		return NULL;

	ret = parse_ue_idx_from_udata(udata, &ue_idx);
	if (ret != 0) {
		ubagg_log_err("Failed to parse udata, ret:%d\n", ret);
		return ERR_PTR(ret);
	}

	if (ubagg_connect_xchg_jetty(cfg, ue_idx, true, dev, &jetty_info) !=
	    0) {
		ubagg_log_err("failed to exchange udata when import jfr\n");
		return ERR_PTR(-ENOEXEC);
	}

	ret = write_jetty_udata(cfg, udata, &jetty_info);
	if (ret != 0) {
		ubagg_log_err("Failed to fill udata, ret:%d\n", ret);
		return ERR_PTR(ret);
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
	struct ubagg_jetty_exchange_info jetty_info = { 0 };
	uint32_t ue_idx;
	int ret;

	if (cfg == NULL || dev == NULL || udata == NULL ||
	    udata->udrv_data == NULL)
		return NULL;

	ret = parse_ue_idx_from_udata(udata, &ue_idx);
	if (ret != 0) {
		ubagg_log_err("Failed to parse udata, ret:%d\n", ret);
		return ERR_PTR(ret);
	}

	if (ubagg_connect_xchg_jetty(cfg, ue_idx, false, dev, &jetty_info) !=
	    0) {
		ubagg_log_err("failed to exchange udata when import jetty\n");
		return ERR_PTR(-ENOEXEC);
	}

	ret = write_jetty_udata(cfg, udata, &jetty_info);
	if (ret != 0) {
		ubagg_log_err("Failed to fill udata, ret:%d\n", ret);
		return ERR_PTR(ret);
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
