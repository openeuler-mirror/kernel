// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 * Description: kmod ub data path API
 * Author: sunfang
 * Create: 2023-05-09
 * Note:
 * History: 2023-05-09
 */
#include <stddef.h>
#include "ubcore_log.h"
#include <urma/ubcore_api.h>
#include <urma/ubcore_opcode.h>
#include <urma/ubcore_types.h>

int ubcore_post_jetty_send_wr(struct ubcore_jetty *jetty, const struct ubcore_jfs_wr *wr,
			      struct ubcore_jfs_wr **bad_wr)
{
	struct ubcore_ops *dev_ops;

	if (jetty == NULL || jetty->ub_dev == NULL || jetty->ub_dev->ops == NULL ||
	    jetty->ub_dev->ops->post_jetty_send_wr == NULL || wr == NULL || bad_wr == NULL) {
		ubcore_log_err("Invalid parameter");
		return -EINVAL;
	}

	dev_ops = jetty->ub_dev->ops;
	return dev_ops->post_jetty_send_wr(jetty, wr, bad_wr);
}
EXPORT_SYMBOL(ubcore_post_jetty_send_wr);

int ubcore_post_jetty_recv_wr(struct ubcore_jetty *jetty, const struct ubcore_jfr_wr *wr,
			      struct ubcore_jfr_wr **bad_wr)
{
	struct ubcore_ops *dev_ops;

	if (jetty == NULL || jetty->ub_dev == NULL || jetty->ub_dev->ops == NULL ||
	    jetty->ub_dev->ops->post_jetty_recv_wr == NULL || wr == NULL || bad_wr == NULL) {
		ubcore_log_err("Invalid parameter");
		return -EINVAL;
	}

	dev_ops = jetty->ub_dev->ops;
	return dev_ops->post_jetty_recv_wr(jetty, wr, bad_wr);
}
EXPORT_SYMBOL(ubcore_post_jetty_recv_wr);

int ubcore_post_jfs_wr(struct ubcore_jfs *jfs, const struct ubcore_jfs_wr *wr,
		       struct ubcore_jfs_wr **bad_wr)
{
	struct ubcore_ops *dev_ops;

	if (jfs == NULL || jfs->ub_dev == NULL || jfs->ub_dev->ops == NULL ||
	    jfs->ub_dev->ops->post_jfs_wr == NULL || wr == NULL || bad_wr == NULL) {
		ubcore_log_err("Invalid parameter");
		return -EINVAL;
	}

	dev_ops = jfs->ub_dev->ops;
	return dev_ops->post_jfs_wr(jfs, wr, bad_wr);
}
EXPORT_SYMBOL(ubcore_post_jfs_wr);

int ubcore_post_jfr_wr(struct ubcore_jfr *jfr, const struct ubcore_jfr_wr *wr,
		       struct ubcore_jfr_wr **bad_wr)
{
	struct ubcore_ops *dev_ops;

	if (jfr == NULL || jfr->ub_dev == NULL || jfr->ub_dev->ops == NULL ||
	    jfr->ub_dev->ops->post_jfr_wr == NULL || wr == NULL || bad_wr == NULL) {
		ubcore_log_err("Invalid parameter");
		return -EINVAL;
	}

	dev_ops = jfr->ub_dev->ops;
	return dev_ops->post_jfr_wr(jfr, wr, bad_wr);
}
EXPORT_SYMBOL(ubcore_post_jfr_wr);

int ubcore_poll_jfc(struct ubcore_jfc *jfc, int cr_cnt, struct ubcore_cr *cr)
{
	struct ubcore_ops *dev_ops;

	if (jfc == NULL || jfc->ub_dev == NULL || jfc->ub_dev->ops == NULL ||
	    jfc->ub_dev->ops->poll_jfc == NULL || cr == NULL) {
		ubcore_log_err("Invalid parameter");
		return -EINVAL;
	}

	dev_ops = jfc->ub_dev->ops;
	return dev_ops->poll_jfc(jfc, cr_cnt, cr);
}
EXPORT_SYMBOL(ubcore_poll_jfc);

int ubcore_rearm_jfc(struct ubcore_jfc *jfc, bool solicited_only)
{
	struct ubcore_ops *dev_ops;

	if (jfc == NULL || jfc->ub_dev == NULL || jfc->ub_dev->ops == NULL ||
	    jfc->ub_dev->ops->rearm_jfc == NULL) {
		ubcore_log_err("Invalid parameter");
		return -EINVAL;
	}

	dev_ops = jfc->ub_dev->ops;
	return dev_ops->rearm_jfc(jfc, solicited_only);
}
EXPORT_SYMBOL(ubcore_rearm_jfc);
