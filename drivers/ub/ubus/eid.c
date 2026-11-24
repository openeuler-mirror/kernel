// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#define pr_fmt(fmt)	"ubus eid: " fmt

#include "ubus.h"
#include "eid.h"

static DEFINE_IDA(ub_eid_ida);

int ub_eid_request(guid_t *id, u32 *eid)
{
	int ida;

	if (!id || !eid)
		return -EINVAL;

	ida = ida_alloc_range(&ub_eid_ida, ubc_eid_start, ubc_eid_end, GFP_KERNEL);
	if (ida < 0)
		return ida;

	*eid = (u32)ida;

	return 0;
}

void ub_eid_release(u32 eid)
{
	ida_free(&ub_eid_ida, eid);
}

int ub_eid_alloc(struct ub_entity *uent)
{
	struct device *dev;
	u32 eid = 0;
	int ret;

	if (is_p_device(uent))
		return 0;

	if (uent->eid) {
		ub_warn(uent, "uent eid not 0, eid=%#05x\n", uent->eid);
		return -EPERM;
	}

	if (is_ibus_controller(uent) && uent->ubc->cluster) {
		dev = &uent->ubc->dev;
		ret = ub_cfg_read_dword(uent, UB_EID_0, &eid);
		if (ret) {
			dev_err(dev, "query cluster ubc, ret=%d\n", ret);
			return ret;
		}

		eid &= UB_COMPACT_EID_MASK;
		if (eid)
			dev_dbg(dev, "update cluster ubc eid, eid=%#x\n", eid);

		uent->eid = eid;
		return 0;
	}

	ret = ub_eid_request(&uent->guid.id, &eid);
	if (!ret)
		uent->eid = eid;

	return ret;
}

void ub_eid_free(struct ub_entity *uent)
{
	u32 eid = uent->eid;

	if (is_p_device(uent))
		return;

	if (!eid) {
		ub_warn(uent, "eid free 0\n");
		return;
	}

	if (is_ibus_controller(uent) && uent->ubc->cluster)
		return;

	uent->eid = 0;
	ub_eid_release(eid);
}
