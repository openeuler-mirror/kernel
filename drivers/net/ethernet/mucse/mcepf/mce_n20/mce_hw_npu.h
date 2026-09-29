/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2024-2026 Mucse Corporation. */

#ifndef _MCE_HW_NPU_H_
#define _MCE_HW_NPU_H_

#define N20_NPU_START_REG 0x400000
#define N20_RPU_FW_BOARD_OFFSET 0x400000
#define N20_RPU_FW_CHECK_OFFSET 0x000000
#define N20_CLUSTER_OFFSET 0x490000
#define N20_SWITCH_OFFSET 0x520000
#define N20_CORE_OFFSET 0x00000

int n20_npu_download_firmware(struct mce_hw *hw);
#endif /*_MCE_HW_NPU_H_*/
