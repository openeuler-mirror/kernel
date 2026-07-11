/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef __ZXIC_PRIVATE_H__
#define __ZXIC_PRIVATE_H__

#if ZXIC_REAL("")
#include <linux/mutex.h>
#include <linux/semaphore.h>
#include <linux/fs.h>

#define ZXIC_TRACE_LOG_FILE_GZ_MAX_CNT (50)

struct zxic_log_file_info {
	char fname[50];
	struct file *p_log_fp;
	unsigned int f_size;
};

#endif

#if ZXIC_REAL("")
enum ZXIC_TRACE_LEVEL {
	ZXIC_TRACE_PRINT = 0,
	ZXIC_TRACE_ERROR_PRINT = 1,
	ZXIC_TRACE_NOTICE_PRINT,
	ZXIC_TRACE_INFO_PRINT,
	ZXIC_TRACE_DEBUG_PRINT,
	ZXIC_TRACE_ALL_PRINT,
	ZXIC_TRACE_INVALID_PRINT
};

enum zxic_log_file_type_e {
	ZXIC_LOG_SDK = 0,
	ZXIC_LOG_INIT = 1,
	ZXIC_LOG_LIF = 2,
	ZXIC_LOG_SERDES = 3,
	ZXIC_LOG_SE_ERAM = 4,
	ZXIC_LOG_SE_HBM = 5,
	ZXIC_LOG_SE_OTHER = 6,
	ZXIC_LOG_REG = 7,
	ZXIC_LOG_DEBUG = 8,
	ZXIC_LOG_DUMP = 9,
	ZXIC_LOG_SE_LPM_SAMPLE_V4 = 10,
	ZXIC_LOG_SE_LPM_SAMPLE_V6 = 11,
	ZXIC_LOG_UT_DETAIL = 12,
	ZXIC_LOG_UT_RESULT = 13,
	ZXIC_LOG_SE_HASH = 14,
	ZXIC_LOG_SE_ACL = 15,
	ZXIC_LOG_SLT = 16,
	ZXIC_LOG_SDS_COMM = 17,
	ZXIC_LOG_THREAD = 31,
	ZXIC_LOG_MAX,
};

#define ZXIC_THREAD_ID_NUM_MAX (2048)

#define ZXIC_MALLOC_MAX_B_SIZE (0xC800000U) /* 200M */

#endif

#if ZXIC_REAL("")
struct zxic_mutex_t {
#ifdef ZXIC_OS_WIN
	HANDLE mutex;
#else
	struct mutex mutex;

#endif
};
#endif

#if ZXIC_REAL("")
struct zxic_sem_t {
#ifdef ZXIC_OS_WIN
	HANDLE sem;
#else
	struct semaphore sem;
#endif
};
#endif

void *ic_comm_sdk_print_regist(void);
unsigned int ic_comm_callback_print_get(void *pExcCall);
unsigned int ic_comm_callback_err_log_get(void *pExcCall);
void ic_comm_set_os_callback(struct _zxic_os_callback *p_os_cb);
void ic_comm_malloc_record(unsigned int size);
void ic_comm_free_record(void);
int zxic_system(const char *path_name, char *const argv[]);

#endif /* end __ZXIC_COMMON_TOP_H__ */
