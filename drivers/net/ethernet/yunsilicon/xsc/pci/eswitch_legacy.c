// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/etherdevice.h>
#include <linux/mutex.h>
#include <linux/idr.h>
#include "common/vport.h"
#include "eswitch.h"
#include "eswitch_legacy.h"

#define XSC_LEGACY_SRIOV_VPORT_EVENTS (XSC_VPORT_UC_ADDR_CHANGE | \
					XSC_VPORT_MC_ADDR_CHANGE | \
					XSC_VPORT_PROMISC_CHANGE | \
					XSC_VPORT_VLAN_CHANGE)

int esw_legacy_enable(struct xsc_eswitch *esw)
{
	struct xsc_vport *vport;
	unsigned long i;
	int err;

	xsc_esw_for_each_vf_vport(esw, i, vport, esw->num_vfs)
		vport->info.link_state = XSC_VPORT_ADMIN_STATE_AUTO;

	err = xsc_eswitch_enable_pf_vf_vports(esw, XSC_LEGACY_SRIOV_VPORT_EVENTS);

	return err;
}

void esw_legacy_disable(struct xsc_eswitch *esw)
{
	return xsc_eswitch_disable_pf_vf_vports(esw);
}

