/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 3snic Technologies Co., Ltd */

#ifndef SSS_HWIF_ADM_H
#define SSS_HWIF_ADM_H

#include <linux/types.h>

int sss_sync_send_adm_msg(void *hwdev, u8 mod, u16 cmd, void *buf_in,
			  u16 in_size, void *buf_out, u16 *out_size, u32 timeout);

#endif
