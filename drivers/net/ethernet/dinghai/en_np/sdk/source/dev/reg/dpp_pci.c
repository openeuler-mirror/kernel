// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include <linux/io.h>
#include "zxic_common.h"
#include "dpp_type_api.h"
#include "dpp_pci.h"
#include "dpp_dev.h"
u32 dpp_pci_write32(struct dpp_dev_t *dev, ZXIC_ADDR_T abs_addr, u32 *p_data)
{
	/* u32 rtn  = 0; */
	u32 data = 0;
	u64 addr = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_POINT(p_data);

	data = *p_data;

	if (zxic_comm_is_big_endian())
		data = ZXIC_COMM_CONVERT32(data);

	addr = abs_addr + SYS_VF_NP_BASE_OFFSET;
	writel(data, (void __iomem *)(unsigned long)addr);
	//writel(data, addr);

	return DPP_OK;
}
u32 dpp_pci_read32(struct dpp_dev_t *dev, ZXIC_ADDR_T abs_addr, u32 *p_data)
{
	u32 data = 0;
	u64 addr = 0;

	ZXIC_COMM_CHECK_POINT(dev);
	ZXIC_COMM_CHECK_POINT(p_data);

	addr = abs_addr + SYS_VF_NP_BASE_OFFSET;
	data = readl((void __iomem *)(unsigned long)addr);

	if (zxic_comm_is_big_endian())
		data = ZXIC_COMM_CONVERT32(data);
	*p_data = data;

	if (*p_data == 0xdadedade)
		ZXIC_COMM_TRACE_DEBUG("PCIE time out err happening at addr[0x%llx]\n", abs_addr);

	return DPP_OK;
}
