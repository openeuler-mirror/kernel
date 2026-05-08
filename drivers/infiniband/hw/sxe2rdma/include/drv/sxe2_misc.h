/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_misc.h
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */
#ifndef __SXE2_MISC_H__
#define __SXE2_MISC_H__

#define REG_FW_MISC_MASK_MODE    (0xF)
#define REG_FW_MISC_MASK_RSV0    (0xF0)
#define REG_FW_MISC_MASK_RSV1    (0xF00)
#define REG_FW_MISC_MASK_RSV2    (0xF000)
#define REG_FW_MISC_MASK_POP     (0x80000000)

#define REG_FW_MISC_MASK_MODE_OFST (0)
#define REG_FW_MISC_MASK_RSV0_OFST (4)
#define REG_FW_MISC_MASK_RSV1_OFST (8)
#define REG_FW_MISC_MASK_RSV2_OFST (12)
#define REG_FW_MISC_MASK_POP_OFST  (31)

enum sxe2_nic_mode {
	SXE2_NIC_MODE_NORMAL     = 0,
	SXE2_NIC_MODE_NCD		  = 1,

	SXE2_NIC_MODE_MAX   = 0xF,
};

#endif
