/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : fast_msg_common_define.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   : fast msg common define, for driver&micro_code usage, common struct defined
 */


#ifndef FAST_MSG_COMMON_DEFINE_H
#define FAST_MSG_COMMON_DEFINE_H

#if defined(__LINUX__) || defined(__VMWARE__)
#include <linux/types.h>
#else
#include "typedef.h"
#endif

#define FW_UBCORE_MSG_NOTIFY_FASTMSG_DRAIN 0x16
#define MAX_FAST_MSG_LEN 2032

typedef struct hisdk5_fast_msg_header {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
	u8 cmd;
	u8 mod;
	u16 status;

	u16 src_func_id;
	u16 dst_func_id;

	u16 rsvd : 10;
	u16 ulp_format : 4;
	u16 nack : 1;
	u16 send : 1;
	u16 data_len;
#else
	u16 status;
	u8 mod;
	u8 cmd;

	u16 dst_func_id;
	u16 src_func_id;

	u16 data_len;
	u16 send : 1;
	u16 nack : 1;
	u16 ulp_format : 4;
	u16 rsvd : 10;
#endif
	u32 rsvd1;
} hisdk5_fast_msg_header;

typedef struct hisdk5_fast_msg_buf {
	union {
		hisdk5_fast_msg_header fast_msg_header;
		u32 rq_offset;
	};
	u8 fast_msg_data[MAX_FAST_MSG_LEN];
} hisdk5_fast_msg_buf;

#endif /* FAST_MSG_COMMON_DEFINE_H */