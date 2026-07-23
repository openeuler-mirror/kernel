/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _DPP_HASH_CRC_H_
#define _DPP_HASH_CRC_H_

#define MAX_CRC_WIDTH (20)

u32 dpp_crc32_calc(u8 *pInputKey, u32 dwByteNum, u32 dwCrcPoly);

u16 dpp_crc16_calc(u8 *pInputKey, u32 dwByteNum, u16 dwCrcPoly);

u16 dpp_crc16_get_idx(u16 crc_val);

u16 dpp_crc16_table_lookup(u8 *pInputKey, u32 dwByteNum, u16 dwCrcPoly);

#endif
