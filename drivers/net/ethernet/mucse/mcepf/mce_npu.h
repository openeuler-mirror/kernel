/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2024-2026 Mucse Corporation. */

#ifndef _MCE_NPU_H_
#define _MCE_NPU_H_
#define MCE_NPU_IOWRITE32_CFG_ARRAY(offset, array, size)    \
	do {                                                \
		u32 i = 0;                                  \
		for (i = 0; i < (size);) {                  \
			npu_wr(hw, (offset) + (array)[i + 0], \
			       (u32)(array)[i + 1]);         \
			i += 2;                             \
		}                                           \
	} while (0)

#define MCE_NPU_CHECK_CFG_ARRAY(offset, array, size)                                    \
	do {                                                                            \
		u32 i = 0;                                                              \
		for (i = 0; i < (size);) {                                              \
			u32 tmp = 0;                                                    \
			tmp = npu_rd(hw, (offset) + (array)[i + 0]);                    \
			if ((array)[i + 1] != tmp) {                                    \
				dev_err(mce_hw_to_dev(hw),                              \
					"npu addr %08x: val_base=%08x val_read=%08x\n", \
					(offset) + (array)[i + 0],                      \
					(array)[i + 1], tmp);                           \
				break;                                                  \
			}                                                               \
			i += 2;                                                         \
		}                                                                       \
	} while (0)
int mce_npu_download_firmware(struct mce_hw *hw);
#endif /*_MCE_NPU_H_*/
