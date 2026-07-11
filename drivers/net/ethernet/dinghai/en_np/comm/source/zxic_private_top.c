// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include "zxic_private_top.h"
#include "zxic_common.h"
#include <linux/ctype.h>
//#include <stdlib.h>
//#include <stdio.h>
#include <linux/stddef.h>
#include <linux/string.h>
#include <linux/errno.h>
//#include <assert.h>
//#include <linux/stdarg.h>
//#include <linux/math.h>
#include <linux/stat.h>

#ifdef ZXIC_OS_WIN
#include <Windows.h>
#include <time.h>
#include <direct.h>
#include <io.h>
#pragma warning(disable : 4996)
#else
//#include <unistd.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/selection.h>
#include <linux/time.h>
#include <linux/wait.h>
#include <linux/kthread.h>
#include <linux/fcntl.h>
#endif

#if ZXIC_REAL("")
u32 zxic_comm_index_check(u32 val, u32 min, u32 max)
{
	if (min <= max) {
		if (min == 0) {
			if ((val) > (max))
				return ZXIC_PAR_CHK_INVALID_INDEX;
		} else {
			if ((val) < (min) || (val) > (max))
				return ZXIC_PAR_CHK_INVALID_INDEX;
		}
	} else {
		return ZXIC_PAR_CHK_INVALID_RANGE;
	}

	return ZXIC_OK;
}
u32 zxic_comm_dev_index_check(u32 dev_id, u32 val, u32 min, u32 max)
{
	if (min <= max) {
		if (min == 0) {
			if ((val) > (max)) {
				ZXIC_COMM_TRACE_DEV_ERROR(
					dev_id,
					"ZXIC %s:%d[Error:VALUE[0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION :%s !\n",
					__FILE__, __LINE__, val, min, max, __func__);
				return ZXIC_PAR_CHK_INVALID_INDEX;
			}
		} else {
			if ((val) < (min) || (val) > (max)) {
				ZXIC_COMM_TRACE_DEV_ERROR(
					dev_id,
					"ZXIC %s:%d[Error:VALUE[0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION :%s !\n",
					__FILE__, __LINE__, val, min, max, __func__);
				return ZXIC_PAR_CHK_INVALID_INDEX;
			}
		}
	} else {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id,
			"ZXIC %s:%d[Error:RANGE INVALID] [val=0x%x,min=0x%x,max=0x%x] ! FUNCTION :%s !\n",
			__FILE__, __LINE__, val, min, max, __func__);
		return ZXIC_PAR_CHK_INVALID_RANGE;
	}

	return ZXIC_OK;
}
u32 zxic_comm_errcode_check(u32 error_code)
{
	if ((error_code == ZXIC_PAR_CHK_BAR_ABNORMAL) ||
	    (error_code == ZXIC_PAR_CHK_DEV_STATUS_OFF)) {
		return ZXIC_OK;
	}

	return ZXIC_PAR_CHK_INVALID_INDEX;
}

#endif
