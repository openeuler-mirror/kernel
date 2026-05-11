// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
 *
 * Description: ipourma error description
 */

#include "ipourma_err.h"

static char *err_desc[IPOURMA_MAX_ERRNO] = {
	"IPoURMA status OK",
	"IPoURMA invalid IPv6 address",
	"IPoURMA unsupported ether protocol",
	"IPoURMA alloc netdev object failed",
	"IPoURMA alloc dev private data failed",
	"IPoURMA alloc TX ring table failed",
	"IPoURMA alloc RX ring table failed",
	"IPoURMA alloc TX ring failed",
	"IPoURMA alloc RX ring failed",
	"IPoURMA TX ring is full",
	"IPoURMA register segment failed",
	"IPoURMA initialize urma resources failed",
	"IPoURMA post send failed",
	"IPoURMA post receive failed",
	"IPoURMA allocate receive socket buffer failed",
	"IPoURMA URMA post receive failed",
	"IPoURMA rearm JFC failed",
	"IPoURMA incorrect completion record status",
	"IPoURMA incorrect WQE jetty id in the completion record",
	"IPoURMA incorrect WQE index in the completion record",
	"IPoURMA poll JFC failed",
	"IPoURMA create JFR table failed",
	"IPoURMA create Jetty table failed",
	"IPoURMA create JFC failed",
	"IPoURMA create JFR failed",
	"IPoURMA create Jetty failed",
	"IPoURMA source IP address doesn't match the source EID",
	"IPoURMA doesn't support GSO or TSO",
	"IPoURMA doesn't support giant packets",
	"IPoURMA cannot support so many fragments",
	"IPoURMA import jetty failed",
	"IPoURMA TX CQE error",
	"IPoURMA insufficient memory",
	"IPoURMA the allocated memory address is not properly aligned",
	"IPoURMA skb linear data exceeds the TX buffer size",
	"IPoURMA replenish RX segment failed",
	"IPoURMA construct Netlink Message failed",
	"IPoURMA construct Netlink Data failed",
	"IPoURMA send Netlink Message failed",
	"IPoURMA received data length exceeds the skb length",
	"IPoURMA initialize tjetty_hmap failed",
	"IPoURMA ipourma alloc TX ring locks failed",
	"IPoURMA ipourma alloc tjetty node failed",
	"IPoURMA alloc cr failed",
	"IPoURMA flush jetty failed",
	"IPoURMA modify jetty failed",
	"IPoURMA modify jfr failed",
	"IPoURMA init rings table failed",
	"IPoURMA invalid device name",
};

char *ipourma_err_desc(int err_num)
{
	if (err_num < 0 || err_num >= IPOURMA_MAX_ERRNO)
		return "IPoURMA unknown error";

	return err_desc[err_num];
}
