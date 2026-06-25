/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 *
 * Description: ubagg netlink head file
 */

#ifndef UBAGG_NETLINK_H
#define UBAGG_NETLINK_H

#include <net/genetlink.h>
#include <ub/urma/ubcore_uapi.h>

#define UBAGG_GENL_FAMILY_NAME "UBAGG_GENL"
#define UBAGG_GENL_FAMILY_VERSION 1

enum ubagg_genl_attr {
	UBAGG_ATTR_UNSPEC = 0,
	UBAGG_HDR_ARGS_ADDR = 4,
	UBAGG_ATTR_EID = 5,
	UBAGG_ATTR_BONDING_PHYSICAL_DEVICE = 6,
	UBAGG_ATTR_PAYLOAD = 7,
	UBAGG_ATTR_MAX = 8,
};

enum ubagg_genl_cmd {
	UBAGG_NL_CMD_UNSPEC = 0,
	UBAGG_NL_CMD_GET_TOPO = 1,
	UBAGG_NL_CMD_GET_SLAVE_EID = 2,
	UBAGG_NL_CMD_GET_PHYSICAL_DEVICE = 4,
	UBAGG_NL_CMD_GET_V2P_RES = 5,
	UBAGG_NL_CMD_FAILBACK_START = 6,
	UBAGG_NL_CMD_FAILBACK_NOTIFY = 7,
	UBAGG_NL_CMD_FAILBACK_RESULT = 8,
	UBAGG_NL_CMD_FAILBACK_DONE = 9,
	UBAGG_NL_CMD_MAX,
};

int ubagg_nl_broadcast(uint8_t cmd, uint16_t attr_type,
		       const void *data, uint16_t data_len);
int ubagg_nl_parse_attr(struct genl_info *info, uint16_t attr_type,
			void *data_out, uint32_t data_size);
int ubagg_genl_register_family(void);
void ubagg_genl_unregister_family(void);

#endif /* UBAGG_NETLINK_H */
