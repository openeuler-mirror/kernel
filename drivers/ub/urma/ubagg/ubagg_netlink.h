/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 *
 * Description: ubagg netlink head file
 */

#ifndef UBAGG_NETLINK_H
#define UBAGG_NETLINK_H

#include <ub/urma/ubcore_uapi.h>

void ubagg_nl_bonding_user_msg_handler(struct ubcore_device *dev,
	struct ubcore_comm_msg *msg, void *conn);

int ubagg_genl_register_family(void);
void ubagg_genl_unregister_family(void);

#endif /* UBAGG_NETLINK_H */
