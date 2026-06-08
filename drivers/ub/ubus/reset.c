// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#define pr_fmt(fmt)	"ubus reset: " fmt

#include <linux/delay.h>

#include "ubus.h"
#include "port.h"
#include "route.h"
#include "ubus_controller.h"
#include "ubus_config.h"
#include "ubus_entity.h"
#include "reset.h"

enum elr_type {
	ELR_PREPARE = 0,
	ELR_DONE = 1,
};

enum SAVED_CFG_SPACE_NUM {
	DEV_TOKEN_ID = 0,
};

static u32 saved_cfg_offset[] = {
	[DEV_TOKEN_ID] = UB_CFG1_BASIC + 0xb4,
};

/**
 * ub_elr - Initiate an UB entity level reset
 * @dev: UB entity to reset
 */
static int ub_elr(struct ub_entity *dev)
{
	u8 command;
	u8 val = 0;
	int ret;

	/* enable ELR */
	command = 0x01;
	ret = ub_cfg_write_byte(dev, UB_ELR, command);
	if (ret) {
		ub_err(dev, "dev elr failed, write byte error, ret=%d", ret);
		return ret;
	}

	/*
	 * ub entity must complete an ELR within 100ms,
	 * but may silently discard requests while the ELR is in
	 * progress. Wait 100ms before trying to access the device.
	 */
	msleep(100);

	ret = ub_cfg_read_byte(dev, UB_ELR_DONE, &val);
	if (ret || !val) {
		ub_err(dev, "dev elr failed, ret=%d, ELR_DONE=%u\n", ret, val);
		return -EINVAL;
	}

	ub_info(dev, "dev elr success\n");

	return 0;
}

/**
 * ub_device_reset - Initiate a UB entity reset
 * @ent: UB entity.
 */
int ub_device_reset(struct ub_entity *ent)
{
	u16 command;
	int ret;

	if (!ent) {
		pr_err("device which will be reset is NULL\n");
		return -EINVAL;
	}

	if (is_ibus_controller(ent)) {
		ub_warn(ent, "ub bus controller do not support reset.\n");
		return -EINVAL;
	}

	/* device reset only support Entity0 */
	if (ent->entity_idx) {
		ub_err(ent, "device is not entity0, entity_idx=%u\n", ent->entity_idx);
		return -EINVAL;
	}

	device_lock(&ent->dev);

	/* enable device reset */
	command = 0x01;
	ret = ub_send_cfg(ent, (u8)sizeof(u16), UB_ENTITY_RST, (u32 *)&command);
	if (ret) {
		ub_err(ent, "device reset failed, ret=%d\n", ret);
		device_unlock(&ent->dev);
		return -EIO;
	}

	ub_entity_assign_priv_flag(ent, UB_ENTITY_DISCONNECTED, true);
	ub_info(ent, "reset, mark disconnect\n");

	device_unlock(&ent->dev);
	ub_info(ent, "device reset success\n");

	return 0;
}
EXPORT_SYMBOL_GPL(ub_device_reset);

static void ub_save_token_state(struct ub_entity *dev)
{
	int ret;
	int i;

	for (i = DEV_TOKEN_ID; i <= DEV_TOKEN_ID; i++) {
		ret = ub_cfg_read_dword(dev, saved_cfg_offset[i],
					&dev->saved_config_space[i]);
		if (ret) {
			ub_err(dev, "ub cfg read dword failed, save cfg offset: %#x.\n",
				saved_cfg_offset[i]);
			continue;
		}
		ub_info(dev, "saving config space at address %#x (reading %#x)\n",
			saved_cfg_offset[i], dev->saved_config_space[i]);
	}
}

static int ub_save_state(struct ub_entity *dev)
{
	const struct ub_error_handlers *err_handler =
			dev->driver ? dev->driver->err_handler : NULL;
	int ret;

	if (err_handler) {
		if (err_handler->ub_reset_prepare_return) {
			ret = err_handler->ub_reset_prepare_return(dev);
			if (ret) {
				ub_err(dev, "ub reset prepare failed, ret[%d]\n", ret);
				return ret;
			}
		} else if (err_handler->ub_reset_prepare) {
			err_handler->ub_reset_prepare(dev);
		}
	}

	ub_save_token_state(dev);

	dev->state_saved = true;

	return 0;
}

static void ub_restore_config_dword(struct ub_entity *dev, u32 pos, u32 saved_val)
{
	int retry = 10;
	u32 val;
	int ret;

	ret = ub_cfg_read_dword(dev, pos, &val);
	if (ret || val == saved_val)
		return;
	while (retry-- > 0) {
		ub_info(dev, "restoring config space at address %#x (was %#x, writing %#x)\n",
			pos, val, saved_val);
		ub_cfg_write_dword(dev, pos, saved_val);

		if (ub_cfg_read_dword(dev, pos, &val))
			continue;

		if (val == saved_val)
			return;

#define RESTORE_RETRY_SLEEP_MS 1
		msleep(RESTORE_RETRY_SLEEP_MS);
	}
}

static void ub_restore_state(struct ub_entity *dev, int pret)
{
	const struct ub_error_handlers *err_handler =
			dev->driver ? dev->driver->err_handler : NULL;
	int i, ret;

	if (!dev->state_saved)
		return;

	for (i = DEV_TOKEN_ID; i <= DEV_TOKEN_ID; i++)
		ub_restore_config_dword(dev, saved_cfg_offset[i],
					dev->saved_config_space[i]);

	dev->state_saved = false;

	if (!err_handler)
		return;

	if (err_handler->ub_reset_done_with_pret) {
		ret = err_handler->ub_reset_done_with_pret(dev, pret);
		if (ret)
			ub_err(dev, "reset done with pret failed, ret[%d]\n",
			       ret);
	} else if (err_handler->ub_reset_done) {
		err_handler->ub_reset_done(dev);
	}
}

static int ub_reset_check(struct ub_entity *dev)
{
	if (is_ibus_controller(dev)) {
		ub_err(dev, "UB Bus Controller does not support ELR!\n");
		return -EINVAL;
	}

	if (!dev->reset_fn)
		return -ENOTTY;

	return 0;
}

int ub_reset_entity(struct ub_entity *uent)
{
	int ret;

	if (!uent) {
		pr_err("device is NULL\n");
		return -EINVAL;
	}

	ret = ub_reset_check(uent);
	if (ret)
		return ret;

	if (!device_trylock(&uent->dev))
		return -EBUSY;

	ret = ub_save_state(uent);
	if (ret)
		goto unlock;

	mutex_lock(&uent->active_mutex);
	ret = ub_entity_enable_force(uent, 0);
	if (ret)
		goto restore;

	ret = ub_elr(uent);

restore:
	mutex_unlock(&uent->active_mutex);
	ub_restore_state(uent, ret);
unlock:
	device_unlock(&uent->dev);
	return ret;
}
EXPORT_SYMBOL_GPL(ub_reset_entity);

int ub_port_reset_check(struct ub_entity *dev, int port_id)
{
	struct ub_port *port = NULL;

	if (!dev)
		return -EINVAL;

	if (is_idev(dev)) {
		ub_err(dev, "IDEV does not support port reset!\n");
		return -EINVAL;
	}

	if (port_id >= dev->port_nums) {
		ub_err(dev, "Can't reset port because port(%d) is over port_nums(%u)!\n",
			port_id, dev->port_nums);
		return -EINVAL;
	}

	port = dev->ports + port_id;

	if (port->type == VIRTUAL) {
		ub_err(dev, "vport reset is not supported now!\n");
		return -EINVAL;
	}

	return 0;
}

static bool ub_wait_port_complete(struct ub_port *port)
{
	u64 timeout = 0;

#define TOTAL_WAIT_CNT 150 /* wait 15s for port reset */
#define WAIT_TIME 100

	do {
		if (port->link_state == LINK_STATE_DONE)
			return true;

		msleep(WAIT_TIME);
		timeout++;
	} while (timeout < TOTAL_WAIT_CNT);

	return false;
}

int ub_port_reset(struct ub_entity *dev, int port_id)
{
	struct ub_port *port = NULL;
	int ret;

	if (ub_port_reset_check(dev, port_id))
		return -EINVAL;

	device_lock(&dev->dev);
	port = dev->ports + port_id;
	if (port->link_state != LINK_STATE_NORMAL) {
		ub_err(dev, "port reset is not complete last time!\n");
		device_unlock(&dev->dev);
		return -EINVAL;
	}

	ub_notify_share_port(port, UB_PORT_EVENT_RESET_PREPARE);

	/* enable port reset */
	ret = ub_port_write_dword(port, UB_PORT_RST, 0x01);
	if (ret) {
		ub_err(port->uent, "port reset failed, dev_eid=%u, port_id=%d, ret=%d\n",
				dev->eid, port_id, ret);
		device_unlock(&dev->dev);
		return -EIO;
	}

	port->link_state = LINK_STATE_RESETING;

	device_unlock(&dev->dev);

	if (ub_wait_port_complete(port)) {
		ub_notify_share_port(port, UB_PORT_EVENT_RESET_DONE);
		port->link_state = LINK_STATE_NORMAL;
		ub_info(dev, "port(%d) reset success!\n", port_id);
		return ret;
	}

	port->link_state = LINK_STATE_NORMAL;
	ub_err(dev, "port(%d) reset timeout!\n", port_id);
	return -ETIME;
}
EXPORT_SYMBOL_GPL(ub_port_reset);

int ub_port_reset_function(struct ub_port *port)
{
	return ub_port_reset(port->uent, port->index);
}
