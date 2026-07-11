/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef __ZXIC_PRIVATE_TOP_H__
#define __ZXIC_PRIVATE_TOP_H__

#include <linux/stddef.h>
#include <linux/string.h>
#include <linux/dinghai/zxdh_compat.h>
#include <linux/stdarg.h>
#include <linux/stat.h>
#include <linux/semaphore.h>

#define ZXIC_REAL(x) (1U)
#define ZXIC_NOREAL(x) (0U)

#ifndef ZXIC_OS_WIN
#define ZXIC_OS_LINUX
#endif

#if ZXIC_REAL("")
typedef void *(*ZXIC_OS_MEM_MALLOC)(unsigned int mem_size);
typedef void (*ZXIC_OS_MEM_FREE)(void *p_free);

struct _zxic_os_callback {
	ZXIC_OS_MEM_MALLOC p_mem_malloc;
	ZXIC_OS_MEM_FREE p_mem_free;
};
#endif

#if ZXIC_REAL("")

union zxic_endian_u {
	unsigned int a;
	unsigned char b;
};
#endif

#if ZXIC_REAL("")
#define ZXIC_RC_BASE (0x1000U)

/* bit_stream */
#define ZXIC_BIT_STREAM_BASE (ZXIC_RC_BASE | 0x100)
#define ZXIC_BIT_STREAM_INDEX_ERR (ZXIC_BIT_STREAM_BASE | 0x001)
#define ZXIC_BIT_STREAM_DATA_TOO_BIG (ZXIC_BIT_STREAM_BASE | 0x002)

/* parameter check */
#define ZXIC_PARAMETER_CHK_BASE (ZXIC_RC_BASE | 0x200)
#define ZXIC_PAR_CHK_POINT_NULL (ZXIC_PARAMETER_CHK_BASE | 0x001)
#define ZXIC_PAR_CHK_ARGIN_ZERO (ZXIC_PARAMETER_CHK_BASE | 0x002)
#define ZXIC_PAR_CHK_ARGIN_OVERFLOW (ZXIC_PARAMETER_CHK_BASE | 0x003)
#define ZXIC_PAR_CHK_ARGIN_ERROR (ZXIC_PARAMETER_CHK_BASE | 0x004)
#define ZXIC_PAR_CHK_INVALID_INDEX (ZXIC_PARAMETER_CHK_BASE | 0x005)
#define ZXIC_PAR_CHK_INVALID_RANGE (ZXIC_PARAMETER_CHK_BASE | 0x006)
#define ZXIC_PAR_CHK_INVALID_DEV_ID (ZXIC_PARAMETER_CHK_BASE | 0x007)
#define ZXIC_PAR_CHK_INVALID_PARA (ZXIC_PARAMETER_CHK_BASE | 0x008)
#define ZXIC_PAR_CHK_BAR_ABNORMAL (ZXIC_PARAMETER_CHK_BASE | 0x009)
#define ZXIC_PAR_CHK_DEV_STATUS_OFF (ZXIC_PARAMETER_CHK_BASE | 0x00A)

/* mutex lock */
#define ZXIC_MUTEX_LOCK_BASE (ZXIC_RC_BASE | 0x300)
#define ZXIC_MUTEX_LOCK_INIT_FAIL (ZXIC_MUTEX_LOCK_BASE | 0x001)
#define ZXIC_MUTEX_LOCK_LOCK_FAIL (ZXIC_MUTEX_LOCK_BASE | 0x002)
#define ZXIC_MUTEX_LOCK_ULOCK_FAIL (ZXIC_MUTEX_LOCK_BASE | 0X003)
#define ZXIC_MUTEX_LOCK_DESTROY_FAIL (ZXIC_MUTEX_LOCK_BASE | 0X004)

/* thread */
#define ZXIC_THREAD_BASE (ZXIC_RC_BASE | 0x400)
#define ZXIC_THREAD_INFO_ADD_FAIL (ZXIC_THREAD_BASE | 0x001)
#define ZXIC_THREAD_CREATE_FAIL (ZXIC_THREAD_BASE | 0x002)

/* socket */
#define ZXIC_SOCKET_BASE (ZXIC_RC_BASE | 0x400)
#define ZXIC_SOKET_SERVICE_START_FAIL (ZXIC_THREAD_BASE | 0x001)
#define ZXIC_SOKET_SERVICE_CLOSE_FAIL (ZXIC_THREAD_BASE | 0x002)
#define ZXIC_SOKET_SET_PARA_FAIL (ZXIC_THREAD_BASE | 0x003)
#define ZXIC_SOKET_CREATE_FAIL (ZXIC_THREAD_BASE | 0x004)
#define ZXIC_SOKET_BIND_LISTEN_FAIL (ZXIC_THREAD_BASE | 0x005)
#define ZXIC_SOKET_CONNECT_FAIL (ZXIC_THREAD_BASE | 0x006)
#define ZXIC_SOKET_CLOSE_FAIL (ZXIC_THREAD_BASE | 0x007)
#define ZXIC_SOKET_GET_PARA_FAIL (ZXIC_THREAD_BASE | 0x008)

/* double link */
#define ZXIC_DOUBLE_LINK_BASE (ZXIC_RC_BASE | 0x500)
#define ZXIC_DOUBLE_LINK_ELEMENT_NUM_ERR (ZXIC_DOUBLE_LINK_BASE | 0x001)
#define ZXIC_DOUBLE_LINK_MALLOC_FAIL (ZXIC_DOUBLE_LINK_BASE | 0x002)
#define ZXIC_DOUBLE_LINK_POINT_NULL (ZXIC_DOUBLE_LINK_BASE | 0x003)
#define ZXIC_DOUBLE_LINK_CHK_SUM_ERR (ZXIC_DOUBLE_LINK_BASE | 0x004)
#define ZXIC_DOUBLE_LINK_NO_EXIST_FREENODE (ZXIC_DOUBLE_LINK_BASE | 0x005)
#define ZXIC_DOUBLE_LINK_FREE_INDX_INVALID (ZXIC_DOUBLE_LINK_BASE | 0x006)
#define ZXIC_DOUBLE_LINK_NO_EXIST_PRENODE (ZXIC_DOUBLE_LINK_BASE | 0x007)
#define ZXIC_DOUBLE_LINK_INPUT_INDX_INVALID (ZXIC_DOUBLE_LINK_BASE | 0x008)
#define ZXIC_DOUBLE_LINK_INIT_ELEMENT_NUM_ERR (ZXIC_DOUBLE_LINK_BASE | 0x009)

/* index ctrl */
#define ZXIC_INDEX_CTRL_BASE (ZXIC_RC_BASE | 0x600)
#define ZXIC_INDEX_CTRL_TREE_FULL (ZXIC_INDEX_CTRL_BASE | 0x001)
#define ZXIC_INDEX_CTRL_SAME_RECORD (ZXIC_INDEX_CTRL_BASE | 0x002)
#define ZXIC_INDEX_CTRL_OPER_MODE_ERR (ZXIC_INDEX_CTRL_BASE | 0x003)

/* index reverse */
#define ZXIC_INDEX_RSV_BASE (ZXIC_RC_BASE | 0x700)
#define ZXIC_INDEX_RESERVE_GET_INDX_FAIL (ZXIC_INDEX_RSV_BASE | 0x001)
#define ZXIC_INDEX_RESERVE_BORROW_HIG_FAIL (ZXIC_INDEX_RSV_BASE | 0x002)
#define ZXIC_INDEX_RESERVE_BORROW_LOW_FAIL (ZXIC_INDEX_RSV_BASE | 0x003)
#define ZXIC_INDEX_RESERVE_ALLOCI_INDX_FAIL (ZXIC_INDEX_RSV_BASE | 0x004)
#define ZXIC_INDEX_RESERVE_FREE_INDX_FAIL (ZXIC_INDEX_RSV_BASE | 0x005)
#define ZXIC_INDEX_RESERVE_RESET_INDX_FAIL (ZXIC_INDEX_RSV_BASE | 0x006)

/* list stack */
#define ZXIC_LIST_STACK_BASE (ZXIC_RC_BASE | 0x800)
#define ZXIC_LIST_STACK_ELEMENT_NUM_ERR (ZXIC_LIST_STACK_BASE | 0x001)
#define ZXIC_LIST_STACK_POINT_NULL (ZXIC_LIST_STACK_BASE | 0x002)
#define ZXIC_LIST_STACK_ALLOC_MEMORY_FAIL (ZXIC_LIST_STACK_BASE | 0x003)
#define ZXIC_LIST_STACK_ISEMPTY_ERR (ZXIC_LIST_STACK_BASE | 0x004)
#define ZXIC_LIST_STACK_FREE_INDEX_INVALID (ZXIC_LIST_STACK_BASE | 0x005)
#define ZXIC_LIST_STACK_ALLOC_INDEX_INVALID (ZXIC_LIST_STACK_BASE | 0x006)
#define ZXIC_LIST_STACK_ALLOC_INDEX_USED (ZXIC_LIST_STACK_BASE | 0x007)

/* avl tree */
#define ZXIC_AVL_TREE_BASE (ZXIC_RC_BASE | 0x900)
#define ZXIC_AVL_TREE_INVALID_INDEX (ZXIC_AVL_TREE_BASE | 0x001)
#define ZXIC_AVL_TREE_SORT_INIT_INPUT_PARA_ERR (ZXIC_AVL_TREE_BASE | 0x002)
#define ZXIC_AVL_TREE_SORT_ISEMPTY_ERR (ZXIC_AVL_TREE_BASE | 0x003)
#define ZXIC_AVL_TREE_SORT_INSERT_SAME_KEY (ZXIC_AVL_TREE_BASE | 0x004)
#define ZXIC_AVL_TREE_SORT_IS_FULL (ZXIC_AVL_TREE_BASE | 0x005)
#define ZXIC_AVL_TREE_KEY_SIZE_ERR (ZXIC_AVL_TREE_BASE | 0x006)

/* index fill */
#define ZXIC_INDEX_FILL_BASE (ZXIC_RC_BASE | 0xA00)
#define ZXIC_INDEX_FILL_FULL (ZXIC_INDEX_FILL_BASE | 0x001)
#define ZXIC_INDEX_DEL_FAIL (ZXIC_INDEX_FILL_BASE | 0x002)

#define ZXIC_COMM_LOG_BASE (ZXIC_RC_BASE | 0xB00)
#define ZXIC_COMM_LOG_MUTEX_CREATE_FAIL (ZXIC_COMM_LOG_BASE | 0x001)
#define ZXIC_COMM_LOG_MUTEX_LOCK_FAIL (ZXIC_COMM_LOG_BASE | 0x002)
#define ZXIC_COMM_LOG_FILE_RENAME_FAIL (ZXIC_COMM_LOG_BASE | 0x003)
#define ZXIC_COMM_LOG_FILE_DELETE_FAIL (ZXIC_COMM_LOG_BASE | 0x004)

/* index fill type */
#define ZXIC_INDEX_FILL_TYPE_BASE (ZXIC_RC_BASE | 0xC00)
#define ZXIC_INDEX_FILL_TYPE_FULL (ZXIC_INDEX_FILL_TYPE_BASE | 0x001)
#define ZXIC_INDEX_DEL_TYPE_FAIL (ZXIC_INDEX_FILL_TYPE_BASE | 0x002)

#define ZXIC_COMM_C_INVALID_PARAM (ZXIC_COMM_LOG_BASE | 0x005)

#define ZXIC_E_LLT_CHECK (25)
#define ZXIC_E_LLT_ASSERT (26)

#endif

#if ZXIC_REAL("")
signed int ic_comm_snprintf_s(char *buffer, size_t sizeofbuf, size_t count, const char *format,
			      ...);
signed int ic_comm_vsnprintf_s(char *buffer, size_t sizeofbuf, size_t count, const char *format,
			       va_list ap);
signed int ic_comm_sscanf(const char *src, const char *format, ...);
char *ic_comm_strcpy_s(char *pcDst, size_t dwMaxSize, const char *pcSrc);
char *ic_comm_strncpy_s(char *pcDst, size_t dwMaxSize, const char *pcSrc, size_t dwCount);
unsigned int ic_comm_memcpy(void *dest, const void *src, size_t n);
unsigned int ic_comm_memcpy_s(void *dest, size_t dest_len, const void *src, size_t n);
char *ic_comm_strcat_s(char *pcDst, size_t dwMaxSize, const char *pcSrc);
char *ic_comm_strncat_s(char *pcDst, size_t dwMaxSize, const char *pcSrc, size_t dwCount);
size_t ic_comm_strnlen_s(const char *str, size_t MaxCount);
char *ic_comm_strtok_s(char *string_org, const char *demial, char **context);
struct _zxic_os_callback *zxic_comm_get_os_callback(void);
void *ic_comm_malloc_memory(unsigned int size);
void ic_comm_free_record(void);
void *ic_comm_vmalloc_memory(unsigned int size);
void ic_comm_vfree_record(void);
unsigned int zxic_comm_index_check(unsigned int val, unsigned int min, unsigned int max);
unsigned int zxic_comm_dev_index_check(unsigned int dev_id, unsigned int val, unsigned int min,
				       unsigned int max);
unsigned int zxic_comm_index_check(unsigned int val, unsigned int min, unsigned int max);
unsigned int zxic_comm_errcode_check(unsigned int error_code);
#endif

#endif /* end __ZXIC_COMMON_TOP_H__ */
