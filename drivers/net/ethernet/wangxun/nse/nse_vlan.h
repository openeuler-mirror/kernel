/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_VLAN_H_
#define _NSE_VLAN_H_

#include <linux/types.h>
#include "nse_type.h"

struct nse_vlan {
	u16 tpid;
	u16 vid;
	u8 prio;
	enum nse_sw_fwd_act_type fwd_act;
};

#define NSE_VLAN(tpid, vid, prio, fwd_action)	\
	((struct nse_vlan){ tpid, vid, prio, fwd_action })
#endif /* _NSE_VLAN_H_ */
