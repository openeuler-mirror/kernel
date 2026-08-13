// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024-2026 Mucse Corporation. */

#include "../mce.h"
#include "../mce_lib.h"
#include "mce_hw_n20.h"
#include "mce_hw_npu.h"
#include "../mce_npu.h"
#include "mce_npu_firmware.h"

int n20_npu_download_firmware(struct mce_hw *hw)
{
	u32 val = 0, i;

	val = npu_rd(hw, 0x6060);
	dev_info(mce_hw_to_dev(hw), "npu version 0x%x\n", val);
	npu_wr(hw, N20_NPU_START_REG + 0x6000, 0x0);
	npu_wr(hw, N20_CLUSTER_OFFSET + 0x10, 0x1);
	npu_wr(hw, N20_CLUSTER_OFFSET + 0x20, 0x0);
	npu_wr(hw, N20_SWITCH_OFFSET + 0x8028, 0x1);

	npu_wr(hw, N20_CLUSTER_OFFSET + 0x18, 0x7b);
	val = npu_rd(hw, N20_CLUSTER_OFFSET + 0x18);
	dev_info(mce_hw_to_dev(hw), "npu addr:0x%x val:0x%x\n",
		 N20_CLUSTER_OFFSET + 0x18, val);

	npu_wr(hw, N20_CLUSTER_OFFSET + 0x1c, 0x7c);
	val = npu_rd(hw, N20_CLUSTER_OFFSET + 0x1c);
	dev_info(mce_hw_to_dev(hw), "npu addr:0x%x val:0x%x\n",
		 N20_CLUSTER_OFFSET + 0x1c, val);

	MCE_NPU_IOWRITE32_CFG_ARRAY(N20_RPU_FW_BOARD_OFFSET, cfg_inst,
				    INST_SIZE);
	MCE_NPU_CHECK_CFG_ARRAY(N20_RPU_FW_CHECK_OFFSET, cfg_inst,
				INST_SIZE);

	npu_wr(hw, N20_RPU_FW_BOARD_OFFSET + 0x0, 0xa3b1bac6);
	npu_wr(hw, N20_RPU_FW_BOARD_OFFSET + 0x4, 0x56aa3350);
	npu_wr(hw, N20_RPU_FW_BOARD_OFFSET + 0x8, 0x677d9197);
	npu_wr(hw, N20_RPU_FW_BOARD_OFFSET + 0xc, 0xb27022dc);
	npu_wr(hw, N20_RPU_FW_BOARD_OFFSET + 0x10 + 0x0, 0x7380166f);
	npu_wr(hw, N20_RPU_FW_BOARD_OFFSET + 0x10 + 0x4, 0x4914b2b9);
	npu_wr(hw, N20_RPU_FW_BOARD_OFFSET + 0x10 + 0x8, 0x172442d7);
	npu_wr(hw, N20_RPU_FW_BOARD_OFFSET + 0x10 + 0xc, 0xda8a0600);
	npu_wr(hw, N20_RPU_FW_BOARD_OFFSET + 0x20 + 0x0, 0xa96f30bc);
	npu_wr(hw, N20_RPU_FW_BOARD_OFFSET + 0x20 + 0x4, 0x163138aa);
	npu_wr(hw, N20_RPU_FW_BOARD_OFFSET + 0x20 + 0x8, 0xe38dee4d);
	npu_wr(hw, N20_RPU_FW_BOARD_OFFSET + 0x20 + 0xc, 0xb0fb0e4e);
	npu_wr(hw, N20_RPU_FW_BOARD_OFFSET + 0x30 + 0x0, 0x36363636);
	npu_wr(hw, N20_RPU_FW_BOARD_OFFSET + 0x30 + 0x4, 0x5c5c5c5c);

	npu_wr(hw, N20_RPU_FW_BOARD_OFFSET + 0x30 + 0xc, 0x67452301);
	npu_wr(hw, N20_RPU_FW_BOARD_OFFSET + 0x40 + 0x0, 0xefcdab89);
	npu_wr(hw, N20_RPU_FW_BOARD_OFFSET + 0x40 + 0x4, 0x98badcfe);
	npu_wr(hw, N20_RPU_FW_BOARD_OFFSET + 0x40 + 0x8, 0x10325476);
	npu_wr(hw, N20_RPU_FW_BOARD_OFFSET + 0x40 + 0xc, 0xc3d2e1f0);
	npu_wr(hw, N20_RPU_FW_BOARD_OFFSET + 0x50 + 0x0, 0x5a827999);
	npu_wr(hw, N20_RPU_FW_BOARD_OFFSET + 0x50 + 0x4, 0x6ed9eba1);
	npu_wr(hw, N20_RPU_FW_BOARD_OFFSET + 0x50 + 0x8, 0x8f1bbcdc);
	npu_wr(hw, N20_RPU_FW_BOARD_OFFSET + 0x50 + 0xc, 0xca62c1d6);
	npu_wr(hw, N20_RPU_FW_BOARD_OFFSET + 0x60 + 0x0, 0xa96f30bc);
	npu_wr(hw, N20_RPU_FW_BOARD_OFFSET + 0x60 + 0x4, 0x163138aa);
	npu_wr(hw, N20_RPU_FW_BOARD_OFFSET + 0x60 + 0x8, 0xe38dee4d);
	npu_wr(hw, N20_RPU_FW_BOARD_OFFSET + 0x60 + 0xc, 0xb0fb0e4e);

	npu_wr(hw, N20_CLUSTER_OFFSET + 0xc, 0x3);
	npu_wr(hw, N20_NPU_START_REG + 0x6000, 0x1);

	for (i = 0; i < 512 * 1024; i++) {
		npu_wr(hw, 0x800000 + i * 16 + 0x0, i * 16 + 0x0);
		npu_wr(hw, 0x800000 + i * 16 + 0x4, i * 16 + 0x4);
		npu_wr(hw, 0x800000 + i * 16 + 0x8, i * 16 + 0x8);
		npu_wr(hw, 0x800000 + i * 16 + 0xc, i * 16 + 0xc);
	}
	return 0;
}
