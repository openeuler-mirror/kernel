// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include "zxic_common.h"
#include "dpp_module.h"
#include "dpp_dev.h"
#include "dpp_ppu.h"
#include "dpp_se.h"
#include "dpp_dtb.h"
#include "dpp_init.h"
#include "dpp_drv_init.h"
DPP_STATUS dpp_init(u32 dev_id)
{
	DPP_STATUS rt = 0;
	u32 dev_id_array[DPP_DEV_CHANNEL_MAX] = { 0 };

	ZXIC_COMM_CHECK_DEV_INDEX(dev_id, dev_id, 0, DPP_DEV_CHANNEL_MAX - 1);

	rt = dpp_dev_init();
	ZXIC_COMM_CHECK_DEV_RC(dev_id, rt, "dpp_dev_init");

	rt = dpp_dev_add(dev_id, DPP_DEV_TYPE_CHIP, DPP_DEV_ACCESS_TYPE_PCIE, 0, 0, 0, 0, NULL,
			 NULL, NULL, NULL);
	ZXIC_COMM_CHECK_DEV_RC(dev_id, rt, "dpp_dev_add");

	dev_id_array[0] = dev_id;
	rt = dpp_sdt_init(1, dev_id_array);
	ZXIC_COMM_CHECK_DEV_RC(dev_id, rt, "dpp_sdt_init");

	rt = dpp_ppu_parse_cls_bitmap(dev_id, DPP_PPU_CLS_ALL_START);
	ZXIC_COMM_CHECK_DEV_RC(dev_id, rt, "dpp_ppu_parse_cls_bitmap");

	dpp_flow_init_status_init();

	return DPP_OK;
}
