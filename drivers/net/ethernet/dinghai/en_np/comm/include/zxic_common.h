/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef __ZXIC_COMMON_H__
#define __ZXIC_COMMON_H__

#include "zxic_private_top.h"
#include "zxic_private.h"
#include <linux/stddef.h>
#include <linux/string.h>
#include <linux/stdarg.h>
#include <linux/stat.h>

#ifdef ZXIC_OS_WIN
#include <Windows.h>
#include <time.h>
#include <direct.h>
#include <io.h>
#pragma warning(disable : 4996)
#else
#include <linux/unistd.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/time.h>
#include <linux/wait.h>
#include <linux/kthread.h>
#include <linux/fcntl.h>
#include <linux/semaphore.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/delay.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/dma-mapping.h>
#endif

#if ZXIC_REAL("")

#ifdef MACRO_CPU64
#define ZXIC_ADDR_T u64
#define ZXIC_SIZEOF(x) (sizeof(x) & 0xFFFFFFFFU)
#define ZXIC_SIZEOF_T(x) ((u32)(sizeof(x) & 0xFFFFFFFF))

#else
#define ZXIC_ADDR_T u32
#define ZXIC_SIZEOF(x) (sizeof(x))
#define ZXIC_SIZEOF_T(x) (sizeof(x))
#endif

#define ZXIC_NULL (0)
#define ZXIC_OK (0U)
#define ZXIC_ERR (1U)
#define ZXIC_TRUE (1U)
#define ZXIC_FALSE (0U)
#define ZXIC_UINT8_MAX (0xFFU)
#define ZXIC_UINT32_MAX (0xFFFFFFFFU)
#define ZXIC_ULONG_MAX (0xFFFFFFFFFFFFFFFFUL)
#define ZXIC_SINT_MAX (0x7FFFFFFF)
#define ZXIC_SINT_MIN (-ZXIC_SINT_MAX - 1)

#define ZXIC_UINT64_MASK (0xFFFFFFFFFFFFFFFFULL)
#define ZXIC_UINT32_MASK (0xFFFFFFFFU)
#define ZXIC_UINT16_MASK (0xFFFFU)
#define ZXIC_UINT8_MASK (0xFFU)
#endif

#if ZXIC_REAL("")
#define ZXIC_COMM_MEMCMP ic_comm_memcmp
#define ZXIC_COMM_MEMSET memset
#define ZXIC_COMM_MEMMOVE memmove
#define ZXIC_COMM_MEMSET_S ic_comm_memset_s
#define ZXIC_COMM_MEMCPY ic_comm_memcpy
#define ZXIC_COMM_MEMCPY_S ic_comm_memcpy_s
#define ZXIC_COMM_STRLEN strlen
#define ZXIC_COMM_STRNLEN strnlen
#define ZXIC_COMM_STRNLEN_S ic_comm_strnlen_s
#define ZXIC_COMM_STRCPY strcpy
#define ZXIC_COMM_STRCPY_S ic_comm_strcpy_s
#define ZXIC_COMM_STRNCPY strncpy
#define ZXIC_COMM_STRNCPY_S ic_comm_strncpy_s
#define ZXIC_COMM_STRCMP strcmp
#define ZXIC_COMM_STRNCMP ic_comm_strncmp
#define ZXIC_COMM_STRTOK strtok
#define ZXIC_COMM_STRTOK_S ic_comm_strtok_s
#define ZXIC_COMM_STRCAT_S ic_comm_strcat_s
#define ZXIC_COMM_STRNCAT_S ic_comm_strncat_s

//#define ZXIC_COMM_FOPEN fopen
#define ZXIC_COMM_FOPEN filp_open
//#define ZXIC_COMM_FCLOSE fclose
#define ZXIC_COMM_FCLOSE(a) filp_close(a, NULL)
#define ZXIC_COMM_FGETS fgets
#define ZXIC_COMM_FPUTS fputs
#define ZXIC_COMM_FREAD fread

// #define ZXIC_COMM_FPRINTF fprintf
// #define ZXIC_COMM_FPRINTF(a,b,c) pr_info(b,c)
#define ZXIC_COMM_SSCANF ic_comm_sscanf
#define ZXIC_COMM_FSCANF ((void)fscanf)
#define ZXIC_COMM_SNPRINTF_S ic_comm_snprintf_s
#define ZXIC_COMM_VSNPRINTF_S ic_comm_vsnprintf_s

#define ZXIC_COMM_TIME time
#define ZXIC_COMM_ATOI atoi

#ifdef ZXIC_OS_WIN
#define ZXIC_COMM_ACCESS _access
#define ZXIC_COMM_SNPRINTF _snprintf
#define ZXIC_COMM_VSNPRINTF _vsnprintf
#define ZXIC_COMM_GETPID _getpid
#else
#define ZXIC_COMM_ACCESS kern_path
/*#define ZXIC_COMM_SNPRINTF snprintf*/
#define ZXIC_COMM_SNPRINTF(a, b, c...) __snprintf_chk(a, b, 0, b, c)
#define ZXIC_COMM_VSNPRINTF vsnprintf
#define ZXIC_COMM_GETPID getpid
#endif

#ifdef MACRO_CPU64
#define ZXIC_COMM_PTR_TO_VAL(p) ((u64)(p))
#define ZXIC_COMM_VAL_TO_PTR(v) ((void *)((u64)(v)))
#define ZXIC_SSIZE_T s64
#else
#define ZXIC_COMM_PTR_TO_VAL(p) ((u32)(p))
#define ZXIC_COMM_VAL_TO_PTR(v) ((void *)(long)((u32)(v)))
#define ZXIC_SSIZE_T s32

#endif

#ifdef ZXIC_OS_WIN
#define ZXIC_COMM_STRCASECMP stricmp
#else
#define ZXIC_COMM_STRCASECMP strcasecmp
#endif

#define ZXIC_COMM_FFLUSH ((void)fflush)
#define ZXIC_COMM_SPRINTF ((void)sprintf)

#ifdef ZXIC_RELEASE
#define ZXIC_COMM_ASSERT(x)
#else
#ifdef ZXIC_FOR_FUZZER
#define ZXIC_COMM_ASSERT(x)
#else
#define ZXIC_COMM_ASSERT(x)
#endif
#endif

#endif

#define ZXIC_COMM_MEMORY_MAX_B_SIZE (200 * 1024 * 1024) /* 200M */
#define ZXIC_COMM_STRNLEN_MAX (0xffffffff)

#if ZXIC_REAL("-print")
#if ZXIC_REAL("")
void zxic_comm_set_print_en(u32 enable);
u32 zxic_comm_get_print_en(void);
void zxic_comm_set_print_level(enum ZXIC_TRACE_LEVEL debug_level);
u32 zxic_comm_get_print_level(void);
#endif
#if ZXIC_REAL("")
void ZXIC_COMM_PRINT(const char *format, ...);
void ZXIC_COMM_TRACE_ERROR(const char *format, ...);
void ZXIC_COMM_TRACE_NOTICE(const char *format, ...);
void ZXIC_COMM_TRACE_INFO(const char *format, ...);
void ZXIC_COMM_TRACE_DEBUG(const char *format, ...);
void ZXIC_COMM_TRACE_ALL(const char *format, ...);

void ZXIC_COMM_TRACE_DEV_ERROR(u32 dev_id, const char *format, ...);
void ZXIC_COMM_TRACE_DEV_NOTICE(u32 dev_id, const char *format, ...);
void ZXIC_COMM_TRACE_DEV_INFO(u32 dev_id, const char *format, ...);
void ZXIC_COMM_TRACE_DEV_DEBUG(u32 dev_id, const char *format, ...);
void ZXIC_COMM_TRACE_DEV_ALL(u32 dev_id, const char *format, ...);

void ZXIC_COMM_DBGCNT64_PRINT(const char *name, u64 value);
void ZXIC_COMM_DBGCNT32_PRINT(const char *name, u32 value);
void ZXIC_COMM_DBGCNT32_PAR_PRINT(const char *name, u32 parm, u32 value);

#endif
#endif

#if ZXIC_REAL("")
u32 zxic_comm_mutex_create(struct zxic_mutex_t *p_mutex);
u32 zxic_comm_mutex_lock(struct zxic_mutex_t *p_mutex);
u32 zxic_comm_mutex_unlock(struct zxic_mutex_t *p_mutex);
u32 zxic_comm_mutex_destroy(struct zxic_mutex_t *p_mutex);
#endif

#if ZXIC_REAL("")
u32 zxic_comm_sem_create(struct zxic_sem_t *p_sem, s32 share, s32 IniCount, s32 MaxCount);
u32 zxic_comm_sem_release(struct zxic_sem_t *p_sem);
u32 zxic_comm_sem_wait(struct zxic_sem_t *p_sem);
#endif

#if ZXIC_REAL("")

#define ZXIC_COMM_FREE(p_data)                 \
	do {                                   \
		if (p_data) {                  \
			ic_comm_free_record(); \
			kfree(p_data);         \
			p_data = ZXIC_NULL;    \
		}                              \
	} while (0)

#define ZXIC_COMM_VFREE(p_data)                 \
	do {                                    \
		if (p_data) {                   \
			ic_comm_vfree_record(); \
			vfree(p_data);          \
			p_data = ZXIC_NULL;     \
		}                               \
	} while (0)

u32 zxic_comm_channel_max_get(void);
void zxic_comm_ut_detail_trace_dev_error(u32 dev_id, const char *format, ...);

#if ZXIC_REAL("NO DEV_ID & ASSERT")

static inline u32 zxic_comm_check_rc_impl(u32 rc, const char *becall)
{
	if (rc != ZXIC_OK) {
		if (zxic_comm_errcode_check(rc) != ZXIC_OK)
			ZXIC_COMM_TRACE_ERROR("ZXIC [ErrorCode:0x%x] Call %s Fail", rc, becall);
		ZXIC_COMM_ASSERT(0);
		return rc;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_RC(rc, becall) zxic_comm_check_rc_impl((rc), (becall))

static inline u32 zxic_comm_check_rc_memory_free_impl(u32 rc, const char *becall, void *ptr)
{
	if (rc != ZXIC_OK) {
		if (zxic_comm_errcode_check(rc) != ZXIC_OK)
			ZXIC_COMM_TRACE_ERROR("ZXICP [ErrorCode:0x%x] Call %s Fail", rc, becall);
		ZXIC_COMM_FREE(ptr);
		ZXIC_COMM_ASSERT(0);
		return rc;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_RC_MEMORY_FREE(rc, becall, ptr) \
	zxic_comm_check_rc_memory_free_impl((rc), (becall), (ptr))

static inline u32 zxic_comm_check_rc_memory_free_no_assert_impl(u32 rc, const char *becall,
								void *ptr)
{
	if (rc != ZXIC_OK) {
		if (zxic_comm_errcode_check(rc) != ZXIC_OK)
			ZXIC_COMM_TRACE_ERROR("ZXICP [ErrorCode:0x%x] Call %s Fail", rc, becall);
		ZXIC_COMM_FREE(ptr);
		return rc;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_RC_MEMORY_FREE_NO_ASSERT(rc, becall, ptr) \
	zxic_comm_check_rc_memory_free_no_assert_impl((rc), (becall), (ptr))

static inline u32 zxic_comm_check_rc_memory_free_unlock_no_assert_impl(u32 rc, const char *becall,
								       void *ptr,
								       struct zxic_mutex_t *mutex)
{
	if (rc != ZXIC_OK) {
		if (zxic_comm_errcode_check(rc) != ZXIC_OK)
			ZXIC_COMM_TRACE_ERROR("ZXICP [ErrorCode:0x%x] Call %s Fail", rc, becall);
		ZXIC_COMM_FREE(ptr);
		(void)zxic_comm_mutex_unlock(mutex);
		return rc;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_RC_MEMORY_FREE_UNLOCK_NO_ASSERT(rc, becall, ptr, mutex) \
	zxic_comm_check_rc_memory_free_unlock_no_assert_impl((rc), (becall), (ptr), (mutex))

static inline u32 zxic_comm_check_rc_memory_free2ptr_no_assert_impl(u32 rc, const char *becall,
								    void *ptr1, void *ptr2)
{
	if (rc != ZXIC_OK) {
		if (zxic_comm_errcode_check(rc) != ZXIC_OK)
			ZXIC_COMM_TRACE_ERROR("ZXICP [ErrorCode:0x%x] Call %s Fail", rc, becall);
		ZXIC_COMM_FREE(ptr1);
		ZXIC_COMM_FREE(ptr2);
		return rc;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_RC_MEMORY_FREE2PTR_NO_ASSERT(rc, becall, ptr1, ptr2) \
	zxic_comm_check_rc_memory_free2ptr_no_assert_impl((rc), (becall), (ptr1), (ptr2))

static inline u32
zxic_comm_check_rc_memory_free2ptr_unlock_no_assert_impl(u32 rc, const char *becall, void *ptr1,
							 void *ptr2, struct zxic_mutex_t *mutex)
{
	if (rc != ZXIC_OK) {
		if (zxic_comm_errcode_check(rc) != ZXIC_OK)
			ZXIC_COMM_TRACE_ERROR("ZXICP [ErrorCode:0x%x] Call %s Fail", rc, becall);
		ZXIC_COMM_FREE(ptr1);
		ZXIC_COMM_FREE(ptr2);
		(void)zxic_comm_mutex_unlock(mutex);
		return rc;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_RC_MEMORY_FREE2PTR_UNLOCK_NO_ASSERT(rc, becall, ptr1, ptr2, mutex)       \
	zxic_comm_check_rc_memory_free2ptr_unlock_no_assert_impl((rc), (becall), (ptr1), (ptr2), \
								 (mutex))

static inline u32 zxic_comm_check_rc_memory_free3ptr_no_assert_impl(u32 rc, const char *becall,
								    void *ptr1, void *ptr2,
								    void *ptr3)
{
	if (rc != ZXIC_OK) {
		if (zxic_comm_errcode_check(rc) != ZXIC_OK)
			ZXIC_COMM_TRACE_ERROR("ZXICP [ErrorCode:0x%x] Call %s Fail", rc, becall);
		ZXIC_COMM_FREE(ptr1);
		ZXIC_COMM_FREE(ptr2);
		ZXIC_COMM_FREE(ptr3);
		return rc;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_RC_MEMORY_FREE3PTR_NO_ASSERT(rc, becall, ptr1, ptr2, ptr3) \
	zxic_comm_check_rc_memory_free3ptr_no_assert_impl((rc), (becall), (ptr1), (ptr2), (ptr3))

static inline u32 zxic_comm_check_rc_memory_free3ptr_unlock_no_assert_impl(
	u32 rc, const char *becall, void *ptr1, void *ptr2, void *ptr3, struct zxic_mutex_t *mutex)
{
	if (rc != ZXIC_OK) {
		if (zxic_comm_errcode_check(rc) != ZXIC_OK)
			ZXIC_COMM_TRACE_ERROR("ZXICP [ErrorCode:0x%x] Call %s Fail", rc, becall);
		ZXIC_COMM_FREE(ptr1);
		ZXIC_COMM_FREE(ptr2);
		ZXIC_COMM_FREE(ptr3);
		(void)zxic_comm_mutex_unlock(mutex);
		return rc;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_RC_MEMORY_FREE3PTR_UNLOCK_NO_ASSERT(rc, becall, ptr1, ptr2, ptr3, mutex) \
	zxic_comm_check_rc_memory_free3ptr_unlock_no_assert_impl((rc), (becall), (ptr1), (ptr2), \
								 (ptr3), (mutex))

static inline u32 zxic_comm_check_rc_memory_vfree_impl(u32 rc, const char *becall, void *ptr)
{
	if (rc != ZXIC_OK) {
		if (zxic_comm_errcode_check(rc) != ZXIC_OK)
			ZXIC_COMM_TRACE_ERROR("ZXICP [ErrorCode:0x%x] Call %s Fail", rc, becall);
		ZXIC_COMM_VFREE(ptr);
		ZXIC_COMM_ASSERT(0);
		return rc;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_RC_MEMORY_VFREE(rc, becall, ptr) \
	zxic_comm_check_rc_memory_vfree_impl((rc), (becall), (ptr))

static inline u32 zxic_comm_check_rc_memory_vfree_no_assert_impl(u32 rc, const char *becall,
								 void *ptr)
{
	if (rc != ZXIC_OK) {
		if (zxic_comm_errcode_check(rc) != ZXIC_OK)
			ZXIC_COMM_TRACE_ERROR("ZXICP [ErrorCode:0x%x] Call %s Fail", rc, becall);
		ZXIC_COMM_VFREE(ptr);
		return rc;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_RC_MEMORY_VFREE_NO_ASSERT(rc, becall, ptr) \
	zxic_comm_check_rc_memory_vfree_no_assert_impl((rc), (becall), (ptr))

static inline u32 zxic_comm_check_rc_memory_vfree_unlock_no_assert_impl(u32 rc, const char *becall,
									void *ptr,
									struct zxic_mutex_t *mutex)
{
	if (rc != ZXIC_OK) {
		if (zxic_comm_errcode_check(rc) != ZXIC_OK)
			ZXIC_COMM_TRACE_ERROR("ZXICP [ErrorCode:0x%x] Call %s Fail", rc, becall);
		ZXIC_COMM_VFREE(ptr);
		(void)zxic_comm_mutex_unlock(mutex);
		return rc;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_RC_MEMORY_VFREE_UNLOCK_NO_ASSERT(rc, becall, ptr, mutex) \
	zxic_comm_check_rc_memory_vfree_unlock_no_assert_impl((rc), (becall), (ptr), (mutex))

static inline u32 zxic_comm_check_rc_memory_vfree2ptr_no_assert_impl(u32 rc, const char *becall,
								     void *ptr1, void *ptr2)
{
	if (rc != ZXIC_OK) {
		if (zxic_comm_errcode_check(rc) != ZXIC_OK)
			ZXIC_COMM_TRACE_ERROR("ZXICP [ErrorCode:0x%x] Call %s Fail", rc, becall);
		ZXIC_COMM_VFREE(ptr1);
		ZXIC_COMM_VFREE(ptr2);
		return rc;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_RC_MEMORY_VFREE2PTR_NO_ASSERT(rc, becall, ptr1, ptr2) \
	zxic_comm_check_rc_memory_vfree2ptr_no_assert_impl((rc), (becall), (ptr1), (ptr2))

static inline u32
zxic_comm_check_rc_memory_vfree2ptr_unlock_no_assert_impl(u32 rc, const char *becall, void *ptr1,
							  void *ptr2, struct zxic_mutex_t *mutex)
{
	if (rc != ZXIC_OK) {
		if (zxic_comm_errcode_check(rc) != ZXIC_OK)
			ZXIC_COMM_TRACE_ERROR("ZXICP [ErrorCode:0x%x] Call %s Fail", rc, becall);
		ZXIC_COMM_VFREE(ptr1);
		ZXIC_COMM_VFREE(ptr2);
		(void)zxic_comm_mutex_unlock(mutex);
		return rc;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_RC_MEMORY_VFREE2PTR_UNLOCK_NO_ASSERT(rc, becall, ptr1, ptr2, mutex)       \
	zxic_comm_check_rc_memory_vfree2ptr_unlock_no_assert_impl((rc), (becall), (ptr1), (ptr2), \
								  (mutex))

static inline u32 zxic_comm_check_rc_memory_vfree3ptr_no_assert_impl(u32 rc, const char *becall,
								     void *ptr1, void *ptr2,
								     void *ptr3)
{
	if (rc != ZXIC_OK) {
		if (zxic_comm_errcode_check(rc) != ZXIC_OK)
			ZXIC_COMM_TRACE_ERROR("ZXICP [ErrorCode:0x%x] Call %s Fail", rc, becall);
		ZXIC_COMM_VFREE(ptr1);
		ZXIC_COMM_VFREE(ptr2);
		ZXIC_COMM_VFREE(ptr3);
		return rc;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_RC_MEMORY_VFREE3PTR_NO_ASSERT(rc, becall, ptr1, ptr2, ptr3) \
	zxic_comm_check_rc_memory_vfree3ptr_no_assert_impl((rc), (becall), (ptr1), (ptr2), (ptr3))

static inline u32 zxic_comm_check_rc_unlock_impl(u32 rc, const char *becall,
						 struct zxic_mutex_t *mutex)
{
	if (rc != ZXIC_OK) {
		if (zxic_comm_errcode_check(rc) != ZXIC_OK)
			ZXIC_COMM_TRACE_ERROR("ZXIC [ErrorCode:0x%x] !-- %s Call %s Fail", rc,
					      becall);
		(void)zxic_comm_mutex_unlock(mutex);
		ZXIC_COMM_ASSERT(0);
		return rc;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_RC_UNLOCK(rc, becall, mutex) \
	zxic_comm_check_rc_unlock_impl((rc), (becall), (mutex))

static inline u32 zxic_comm_check_rc_no_assert_unlock_impl(u32 rc, const char *becall,
							   struct zxic_mutex_t *mutex)
{
	if (rc != ZXIC_OK) {
		if (zxic_comm_errcode_check(rc) != ZXIC_OK)
			ZXIC_COMM_TRACE_ERROR("ZXIC [ErrorCode:0x%x] !-- %s Call %s Fail", rc,
					      becall);
		(void)zxic_comm_mutex_unlock(mutex);
		return rc;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_RC_NO_ASSERT_UNLOCK(rc, becall, mutex) \
	zxic_comm_check_rc_no_assert_unlock_impl((rc), (becall), (mutex))

static inline u32 zxic_comm_check_rc_close_fp_impl(u32 rc, const char *becall, void *fp)
{
	if (rc != ZXIC_OK) {
		if (zxic_comm_errcode_check(rc) != ZXIC_OK)
			ZXIC_COMM_TRACE_ERROR("ZXIC [ErrorCode:0x%x] !-- %s Call %s Fail", rc,
					      becall);
		if (ZXIC_COMM_FCLOSE(fp))
			ZXIC_COMM_TRACE_ERROR("ZXIC !-- %s close file Fail", becall);
		ZXIC_COMM_ASSERT(0);
		return rc;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_RC_CLOSE_FP(rc, becall, fp) \
	zxic_comm_check_rc_close_fp_impl((rc), (becall), (fp))

static inline u32 zxic_comm_check_point_impl(const void *point)
{
	if (point == ZXIC_NULL) {
		ZXIC_COMM_TRACE_ERROR("ZXIC [Error:POINT NULL] ! FUNCTION");
		ZXIC_COMM_ASSERT(0);
		return ZXIC_PAR_CHK_POINT_NULL;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_POINT(point) zxic_comm_check_point_impl((point))

static inline u32 zxic_comm_check_point_memory_free_impl(const void *point, void *ptr)
{
	if (point == ZXIC_NULL) {
		ZXIC_COMM_TRACE_ERROR("ZXIC [Error:POINT NULL] ! FUNCTION");
		ZXIC_COMM_FREE(ptr);
		ZXIC_COMM_ASSERT(0);
		return ZXIC_PAR_CHK_POINT_NULL;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_POINT_MEMORY_FREE(point, ptr) \
	zxic_comm_check_point_memory_free_impl((point), (ptr))

static inline u32 zxic_comm_check_point_memory_vfree_impl(const void *point, void *ptr)
{
	if (point == ZXIC_NULL) {
		ZXIC_COMM_TRACE_ERROR("ZXIC [Error:POINT NULL] ! FUNCTION");
		ZXIC_COMM_VFREE(ptr);
		ZXIC_COMM_ASSERT(0);
		return ZXIC_PAR_CHK_POINT_NULL;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_POINT_MEMORY_VFREE(point, ptr) \
	zxic_comm_check_point_memory_vfree_impl((point), (ptr))

static inline u32 zxic_comm_check_point_ememory_free2ptr_impl(const void *point, void *ptr0,
							      void *ptr1)
{
	if (point == ZXIC_NULL) {
		ZXIC_COMM_TRACE_ERROR("ZXIC [Error:POINT NULL] ! FUNCTION");
		ZXIC_COMM_FREE(ptr0);
		ZXIC_COMM_FREE(ptr1);
		ZXIC_COMM_ASSERT(0);
		return ZXIC_PAR_CHK_POINT_NULL;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_POINT_EMEMORY_FREE2PTR(point, ptr0, ptr1) \
	zxic_comm_check_point_ememory_free2ptr_impl((point), (ptr0), (ptr1))

static inline u32 zxic_comm_check_point_no_assert_impl(const void *point)
{
	if (point == ZXIC_NULL) {
		ZXIC_COMM_TRACE_ERROR("ZXIC [Error:POINT NULL] ! FUNCTION");
		return ZXIC_PAR_CHK_POINT_NULL;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_POINT_NO_ASSERT(point) zxic_comm_check_point_no_assert_impl((point))

static inline u32 zxic_comm_check_point_memory_free_no_assert_impl(const void *point, void *ptr)
{
	if (point == ZXIC_NULL) {
		ZXIC_COMM_TRACE_ERROR("ZXIC [Error:POINT NULL] ! FUNCTION");
		ZXIC_COMM_FREE(ptr);
		return ZXIC_PAR_CHK_POINT_NULL;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_POINT_MEMORY_FREE_NO_ASSERT(point, ptr) \
	zxic_comm_check_point_memory_free_no_assert_impl((point), (ptr))

static inline u32 zxic_comm_check_point_memory_vfree_no_assert_impl(const void *point, void *ptr)
{
	if (point == ZXIC_NULL) {
		ZXIC_COMM_TRACE_ERROR("ZXIC [Error:POINT NULL] ! FUNCTION");
		ZXIC_COMM_VFREE(ptr);
		return ZXIC_PAR_CHK_POINT_NULL;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_POINT_MEMORY_VFREE_NO_ASSERT(point, ptr) \
	zxic_comm_check_point_memory_vfree_no_assert_impl((point), (ptr))

static inline u32 zxic_comm_check_point_memory_free2ptr_no_assert_impl(const void *point,
								       void *ptr1, void *ptr2)
{
	if (point == ZXIC_NULL) {
		ZXIC_COMM_TRACE_ERROR("ZXIC [Error:POINT NULL] ! FUNCTION");
		ZXIC_COMM_FREE(ptr1);
		ZXIC_COMM_FREE(ptr2);
		return ZXIC_PAR_CHK_POINT_NULL;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_POINT_MEMORY_FREE2PTR_NO_ASSERT(point, ptr1, ptr2) \
	zxic_comm_check_point_memory_free2ptr_no_assert_impl((point), (ptr1), (ptr2))

static inline u32 zxic_comm_check_point_memory_vfree2ptr_no_assert_impl(const void *point,
									void *ptr1, void *ptr2)
{
	if (point == ZXIC_NULL) {
		ZXIC_COMM_TRACE_ERROR("ZXIC [Error:POINT NULL] ! FUNCTION");
		ZXIC_COMM_VFREE(ptr1);
		ZXIC_COMM_VFREE(ptr2);
		return ZXIC_PAR_CHK_POINT_NULL;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_POINT_MEMORY_VFREE2PTR_NO_ASSERT(point, ptr1, ptr2) \
	zxic_comm_check_point_memory_vfree2ptr_no_assert_impl((point), (ptr1), (ptr2))

static inline u32 zxic_comm_check_point_memory_free3ptr_no_assert_impl(const void *point,
								       void *ptr1, void *ptr2,
								       void *ptr3)
{
	if (point == ZXIC_NULL) {
		ZXIC_COMM_TRACE_ERROR("ZXIC [Error:POINT NULL] ! FUNCTION");
		ZXIC_COMM_FREE(ptr1);
		ZXIC_COMM_FREE(ptr2);
		ZXIC_COMM_FREE(ptr3);
		return ZXIC_PAR_CHK_POINT_NULL;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_POINT_MEMORY_FREE3PTR_NO_ASSERT(point, ptr1, ptr2, ptr3) \
	zxic_comm_check_point_memory_free3ptr_no_assert_impl((point), (ptr1), (ptr2), (ptr3))

static inline u32 zxic_comm_check_point_close_fp_impl(const void *point, void *fp)
{
	if (point == ZXIC_NULL) {
		ZXIC_COMM_TRACE_ERROR("ZXIC [Error:POINT NULL] ! FUNCTION");
		if (ZXIC_COMM_FCLOSE(fp))
			ZXIC_COMM_TRACE_ERROR("ZXIC !-- close file Fail");
		ZXIC_COMM_ASSERT(0);
		return ZXIC_PAR_CHK_POINT_NULL;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_POINT_CLOSE_FP(point, fp) zxic_comm_check_point_close_fp_impl((point), (fp))

static inline u32 zxic_comm_check_point_close_fp_no_assert_impl(const void *point, void *fp)
{
	if (point == ZXIC_NULL) {
		ZXIC_COMM_TRACE_ERROR("ZXIC [Error:POINT NULL] ! FUNCTION");
		if (ZXIC_COMM_FCLOSE(fp))
			ZXIC_COMM_TRACE_ERROR("ZXIC !-- close file Fail");
		return ZXIC_PAR_CHK_POINT_NULL;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_POINT_CLOSE_FP_NO_ASSERT(point, fp) \
	zxic_comm_check_point_close_fp_no_assert_impl((point), (fp))

static inline u32 zxic_comm_check_point_no_print_impl(const void *point)
{
	if (point == ZXIC_NULL) {
		ZXIC_COMM_ASSERT(0);
		return ZXIC_PAR_CHK_POINT_NULL;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_POINT_NO_PRINT(point) zxic_comm_check_point_no_print_impl((point))

static inline u32 zxic_comm_check_point_no_print_unlock_impl(const void *point,
							     struct zxic_mutex_t *p_mutex)
{
	if (point == ZXIC_NULL) {
		(void)zxic_comm_mutex_unlock(p_mutex);
		ZXIC_COMM_ASSERT(0);
		return ZXIC_PAR_CHK_POINT_NULL;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_POINT_NO_PRINT_UNLOCK(point, p_mutex) \
	zxic_comm_check_point_no_print_unlock_impl((point), (p_mutex))

static inline void zxic_comm_check_point_none_impl(const void *point)
{
	if (point == ZXIC_NULL) {
		ZXIC_COMM_TRACE_ERROR("ZXIC [Error:POINT NULL] ! FUNCTION");
		ZXIC_COMM_ASSERT(0);
	}
}

#define ZXIC_COMM_CHECK_POINT_NONE(point) zxic_comm_check_point_none_impl((point))

static inline void zxic_comm_check_point_return_none_impl(const void *point)
{
	if (point == ZXIC_NULL) {
		ZXIC_COMM_TRACE_ERROR("ZXIC [Error:POINT NULL] ! FUNCTION");
		ZXIC_COMM_ASSERT(0);
	}
}

#define ZXIC_COMM_CHECK_POINT_RETURN_NONE(point) zxic_comm_check_point_return_none_impl((point))

static inline void zxic_comm_check_point_return_none_no_assert_impl(const void *point)
{
	if (point == ZXIC_NULL)
		ZXIC_COMM_TRACE_ERROR("ZXIC [Error:POINT NULL] ! FUNCTION");
}

#define ZXIC_COMM_CHECK_POINT_RETURN_NONE_NO_ASSERT(point) \
	zxic_comm_check_point_return_none_no_assert_impl((point))

static inline void *zxic_comm_check_point_return_null_impl(const void *point)
{
	if (point == ZXIC_NULL) {
		ZXIC_COMM_TRACE_ERROR("ZXIC [Error:POINT NULL] ! FUNCTION");
		ZXIC_COMM_ASSERT(0);
		return NULL;
	}
	return (void *)point;
}

#define ZXIC_COMM_CHECK_POINT_RETURN_NULL(point) zxic_comm_check_point_return_null_impl((point))

static inline u32 zxic_comm_check_index_impl(u32 val, u32 min, u32 max)
{
	if (zxic_comm_index_check(val, min, max) == ZXIC_PAR_CHK_INVALID_INDEX) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION", val, min,
			max);
		ZXIC_COMM_ASSERT(0);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	if (zxic_comm_index_check(val, min, max) == ZXIC_PAR_CHK_INVALID_RANGE) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION", val, min,
			max);
		ZXIC_COMM_ASSERT(0);
		return ZXIC_PAR_CHK_INVALID_RANGE;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_INDEX(val, min, max) zxic_comm_check_index_impl((val), (min), (max))

static inline u32 zxic_comm_check_index_equal_impl(u32 val, u32 equal)
{
	if (val == equal) {
		ZXIC_COMM_TRACE_ERROR("ZXIC [Error:VALUE[0x%x] INVALID] [equal=0x%x] ! FUNCTION",
				      val, equal);
		ZXIC_COMM_ASSERT(0);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_INDEX_EQUAL(val, equal) zxic_comm_check_index_equal_impl((val), (equal))

static inline u32 zxic_comm_check_index_equal_return_ok_impl(u32 val, u32 equal)
{
	if (val == equal)
		return ZXIC_OK;
	return ZXIC_PAR_CHK_INVALID_INDEX;
}

#define ZXIC_COMM_CHECK_INDEX_EQUAL_RETURN_OK(val, equal) \
	zxic_comm_check_index_equal_return_ok_impl((val), (equal))

static inline u32 zxic_comm_check_index_not_equal_impl(u32 val, u32 equal)
{
	if (val != equal) {
		ZXIC_COMM_TRACE_ERROR("ZXIC [Error:VALUE[0x%x] INVALID] [equal=0x%x] ! FUNCTION",
				      val, equal);
		ZXIC_COMM_ASSERT(0);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_INDEX_NOT_EQUAL(val, equal) \
	zxic_comm_check_index_not_equal_impl((val), (equal))

static inline u32 zxic_comm_check_index_upper_impl(u32 val, u32 max)
{
	if (val > max) {
		ZXIC_COMM_TRACE_ERROR("ZXIC [Error:VALUE[0x%x] INVALID] [max=0x%x] ! FUNCTION", val,
				      max);
		ZXIC_COMM_ASSERT(0);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_INDEX_UPPER(val, max) zxic_comm_check_index_upper_impl((val), (max))

static inline u32 zxic_comm_check_index_lower_impl(u32 val, u32 min)
{
	if (val < min) {
		ZXIC_COMM_TRACE_ERROR("ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x] ! FUNCTION", val,
				      min);
		ZXIC_COMM_ASSERT(0);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_INDEX_LOWER(val, min) zxic_comm_check_index_lower_impl((val), (min))

static inline u32 zxic_comm_check_index_lower_unlock_impl(u32 val, u32 min,
							  struct zxic_mutex_t *mutex)
{
	if (val < min) {
		ZXIC_COMM_TRACE_ERROR("ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x] ! FUNCTION", val,
				      min);
		(void)zxic_comm_mutex_unlock(mutex);
		ZXIC_COMM_ASSERT(0);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_INDEX_LOWER_UNLOCK(val, min, mutex) \
	zxic_comm_check_index_lower_unlock_impl((val), (min), (mutex))

static inline u32 zxic_comm_check_index_both_impl(u32 val, u32 min, u32 max)
{
	if (val < min || val > max) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION", val, min,
			max);
		ZXIC_COMM_ASSERT(0);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_INDEX_BOTH(val, min, max) \
	zxic_comm_check_index_both_impl((val), (min), (max))

static inline u32 zxic_comm_check_index_not_equal_unlock_impl(u32 val, u32 equal,
							      struct zxic_mutex_t *mutex)
{
	if (val != equal) {
		ZXIC_COMM_TRACE_ERROR("ZXIC [Error:VALUE[0x%x] INVALID] [equal=0x%x] ! FUNCTION",
				      val, equal);
		(void)zxic_comm_mutex_unlock(mutex);
		ZXIC_COMM_ASSERT(0);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_INDEX_NOT_EQUAL_UNLOCK(val, equal, mutex) \
	zxic_comm_check_index_not_equal_unlock_impl((val), (equal), (mutex))

static inline u32 zxic_comm_check_index_add_overflow_impl(u32 val0, u32 val1)
{
	if ((ZXIC_UINT32_MAX - val0) < val1) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error:VALUE[val0=0x%x] INVALID] [val1=0x%x] ! FUNCTION", val0, val1);
		ZXIC_COMM_ASSERT(0);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_INDEX_ADD_OVERFLOW(val0, val1) \
	zxic_comm_check_index_add_overflow_impl((val0), (val1))

static inline u32 zxic_comm_check_index_add_overflow_64_impl(u64 val0, u64 val1)
{
	if ((ZXIC_ULONG_MAX - val0) < val1) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error:VALUE[val0=0x%llx] INVALID] [val1=0x%llx] ! FUNCTION", val0,
			val1);
		ZXIC_COMM_ASSERT(0);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_INDEX_ADD_OVERFLOW_64(val0, val1) \
	zxic_comm_check_index_add_overflow_64_impl((val0), (val1))

static inline u32 zxic_comm_check_index_add_overflow_unlock_impl(u32 val0, u32 val1,
								 struct zxic_mutex_t *mutex)
{
	if ((ZXIC_UINT32_MAX - val0) < val1) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error:VALUE[val0=0x%x] INVALID] [val1=0x%x] ! FUNCTION", val0, val1);
		(void)zxic_comm_mutex_unlock(mutex);
		ZXIC_COMM_ASSERT(0);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_INDEX_ADD_OVERFLOW_UNLOCK(val0, val1, mutex) \
	zxic_comm_check_index_add_overflow_unlock_impl((val0), (val1), (mutex))

static inline u32 zxic_comm_check_index_sub_overflow_impl(u32 val0, u32 val1)
{
	if (val0 < val1) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error:VALUE[val0=0x%x] INVALID] [val1=0x%x] ! FUNCTION", val0, val1);
		ZXIC_COMM_ASSERT(0);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_INDEX_SUB_OVERFLOW(val0, val1) \
	zxic_comm_check_index_sub_overflow_impl((val0), (val1))

static inline u32 zxic_comm_check_index_sub_overflow_64_impl(u64 val0, u64 val1)
{
	if (val0 < val1) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error:VALUE[val0=0x%llx] INVALID] [val1=0x%llx] ! FUNCTION", val0,
			val1);
		ZXIC_COMM_ASSERT(0);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_INDEX_SUB_OVERFLOW_64(val0, val1) \
	zxic_comm_check_index_sub_overflow_64_impl((val0), (val1))

static inline u32 zxic_comm_check_index_sub_overflow_unlock_impl(u32 val0, u32 val1,
								 struct zxic_mutex_t *mutex)
{
	if (val0 < val1) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error:VALUE[val0=0x%x] INVALID] [val1=0x%x] ! FUNCTION", val0, val1);
		(void)zxic_comm_mutex_unlock(mutex);
		ZXIC_COMM_ASSERT(0);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_INDEX_SUB_OVERFLOW_UNLOCK(val0, val1, mutex) \
	zxic_comm_check_index_sub_overflow_unlock_impl((val0), (val1), (mutex))

static inline u32 zxic_comm_check_index_mul_overflow_impl(u32 val0, u32 val1)
{
	if (val0 > 0 && (ZXIC_UINT32_MAX / val0) < val1) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error:VALUE[val0=0x%x] INVALID] [val1=0x%x] ! FUNCTION", val0, val1);
		ZXIC_COMM_ASSERT(0);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_INDEX_MUL_OVERFLOW(val0, val1) \
	zxic_comm_check_index_mul_overflow_impl((val0), (val1))

static inline u32 zxic_comm_check_index_mul_overflow_64_impl(u64 val0, u64 val1)
{
	if (val0 > 0 && (ZXIC_ULONG_MAX / val0) < val1) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error:VALUE[val0=0x%llx] INVALID] [val1=0x%llx] ! FUNCTION", val0,
			val1);
		ZXIC_COMM_ASSERT(0);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_INDEX_MUL_OVERFLOW_64(val0, val1) \
	zxic_comm_check_index_mul_overflow_64_impl((val0), (val1))

static inline u32 zxic_comm_check_index_mul_overflow_unlock_impl(u32 val0, u32 val1,
								 struct zxic_mutex_t *mutex)
{
	if (val0 > 0 && (ZXIC_UINT32_MAX / val0) < val1) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error:VALUE[val0=0x%x] INVALID] [val1=0x%x] ! FUNCTION", val0, val1);
		(void)zxic_comm_mutex_unlock(mutex);
		ZXIC_COMM_ASSERT(0);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_INDEX_MUL_OVERFLOW_UNLOCK(val0, val1, mutex) \
	zxic_comm_check_index_mul_overflow_unlock_impl((val0), (val1), (mutex))

static inline u32 zxic_comm_check_index_no_assert_impl(u32 val, u32 min, u32 max)
{
	if (zxic_comm_index_check(val, min, max) == ZXIC_PAR_CHK_INVALID_INDEX) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION", val, min,
			max);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	if (zxic_comm_index_check(val, min, max) == ZXIC_PAR_CHK_INVALID_RANGE) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION", val, min,
			max);
		return ZXIC_PAR_CHK_INVALID_RANGE;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_INDEX_NO_ASSERT(val, min, max) \
	zxic_comm_check_index_no_assert_impl((val), (min), (max))

static inline u32 zxic_comm_check_index_no_assert_unlock_impl(u32 val, u32 min, u32 max,
							      struct zxic_mutex_t *mutex)
{
	if (zxic_comm_index_check(val, min, max) == ZXIC_PAR_CHK_INVALID_INDEX) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION", val, min,
			max);
		(void)zxic_comm_mutex_unlock(mutex);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	if (zxic_comm_index_check(val, min, max) == ZXIC_PAR_CHK_INVALID_RANGE) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION", val, min,
			max);
		(void)zxic_comm_mutex_unlock(mutex);
		return ZXIC_PAR_CHK_INVALID_RANGE;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_INDEX_NO_ASSERT_UNLOCK(val, min, max, mutex) \
	zxic_comm_check_index_no_assert_unlock_impl((val), (min), (max), (mutex))

static inline u32 zxic_comm_check_index_upper_no_assert_impl(u32 val, u32 max)
{
	if (val > max) {
		ZXIC_COMM_TRACE_ERROR("ZXIC [Error:VALUE[0x%x] INVALID] [max=0x%x] ! FUNCTION", val,
				      max);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_INDEX_UPPER_NO_ASSERT(val, max) \
	zxic_comm_check_index_upper_no_assert_impl((val), (max))

static inline u32 zxic_comm_check_index_upper_no_assert_unlock_impl(u32 val, u32 max,
								    struct zxic_mutex_t *mutex)
{
	if (val > max) {
		ZXIC_COMM_TRACE_ERROR("ZXIC [Error:VALUE[0x%x] INVALID] [max=0x%x] ! FUNCTION", val,
				      max);
		(void)zxic_comm_mutex_unlock(mutex);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_INDEX_UPPER_NO_ASSERT_UNLOCK(val, max, mutex) \
	zxic_comm_check_index_upper_no_assert_unlock_impl((val), (max), (mutex))

static inline u32 zxic_comm_check_index_lower_no_assert_impl(u32 val, u32 min)
{
	if (val < min) {
		ZXIC_COMM_TRACE_ERROR("ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x] ! FUNCTION", val,
				      min);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_INDEX_LOWER_NO_ASSERT(val, min) \
	zxic_comm_check_index_lower_no_assert_impl((val), (min))

static inline u32 zxic_comm_check_index_lower_no_assert_unlock_impl(u32 val, u32 min,
								    struct zxic_mutex_t *mutex)
{
	if (val < min) {
		ZXIC_COMM_TRACE_ERROR("ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x] ! FUNCTION", val,
				      min);
		(void)zxic_comm_mutex_unlock(mutex);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_INDEX_LOWER_NO_ASSERT_UNLOCK(val, min, mutex) \
	zxic_comm_check_index_lower_no_assert_unlock_impl((val), (min), (mutex))

static inline u32 zxic_comm_check_index_both_no_assert_impl(u32 val, u32 min, u32 max)
{
	if (val < min || val > max) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION", val, min,
			max);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_INDEX_BOTH_NO_ASSERT(val, min, max) \
	zxic_comm_check_index_both_no_assert_impl((val), (min), (max))

static inline u32 zxic_comm_check_index_both_no_assert_unlock_impl(u32 val, u32 min, u32 max,
								   struct zxic_mutex_t *mutex)
{
	if (val < min || val > max) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION", val, min,
			max);
		(void)zxic_comm_mutex_unlock(mutex);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_INDEX_BOTH_NO_ASSERT_UNLOCK(val, min, max, mutex) \
	zxic_comm_check_index_both_no_assert_unlock_impl((val), (min), (max), (mutex))

static inline u32 zxic_comm_check_dev_rc_impl(u32 dev_id, u32 rc, const char *becall)
{
	if (rc != ZXIC_OK) {
		if (zxic_comm_errcode_check(rc) != ZXIC_OK)
			ZXIC_COMM_TRACE_DEV_ERROR(
				dev_id, "ZXIC [ErrorCode:0x%x] !-- %s Call %s Fail", rc, becall);
		ZXIC_COMM_ASSERT(0);
		return rc;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_RC(dev_id, rc, becall) \
	zxic_comm_check_dev_rc_impl((dev_id), (rc), (becall))

static inline void *zxic_comm_check_dev_rc_null_impl(u32 dev_id, u32 rc, const char *becall)
{
	if (rc != ZXIC_OK) {
		if (zxic_comm_errcode_check(rc) != ZXIC_OK)
			ZXIC_COMM_TRACE_DEV_ERROR(
				dev_id, "ZXIC [ErrorCode:0x%x] !-- %s Call %s Fail", rc, becall);
		ZXIC_COMM_ASSERT(0);
		return NULL;
	}
	return (void *)(long)rc;
}

#define ZXIC_COMM_CHECK_DEV_RC_NULL(dev_id, rc, becall) \
	zxic_comm_check_dev_rc_null_impl((dev_id), (rc), (becall))

static inline u32 zxic_comm_check_dev_rc_memory_free_impl(u32 dev_id, u32 rc, const char *becall,
							  void *ptr)
{
	if (rc != ZXIC_OK) {
		if (zxic_comm_errcode_check(rc) != ZXIC_OK)
			ZXIC_COMM_TRACE_DEV_ERROR(dev_id, "ZXICP [ErrorCode:0x%x] Call %s Fail", rc,
						  becall);
		ZXIC_COMM_FREE(ptr);
		ZXIC_COMM_ASSERT(0);
		return rc;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_RC_MEMORY_FREE(dev_id, rc, becall, ptr) \
	zxic_comm_check_dev_rc_memory_free_impl((dev_id), (rc), (becall), (ptr))

static inline u32 zxic_comm_check_dev_rc_no_assert_impl(u32 dev_id, u32 rc, const char *becall)
{
	if (rc != ZXIC_OK) {
		if (zxic_comm_errcode_check(rc) != ZXIC_OK)
			ZXIC_COMM_TRACE_DEV_ERROR(
				dev_id, "ZXIC [ErrorCode:0x%x] !-- %s Call %s Fail", rc, becall);
		return rc;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT(dev_id, rc, becall) \
	zxic_comm_check_dev_rc_no_assert_impl((dev_id), (rc), (becall))

static inline u32 zxic_comm_check_dev_rc_unlock_impl(u32 dev_id, u32 rc, const char *becall,
						     struct zxic_mutex_t *mutex)
{
	if (rc != ZXIC_OK) {
		if (zxic_comm_errcode_check(rc) != ZXIC_OK)
			ZXIC_COMM_TRACE_DEV_ERROR(
				dev_id, "ZXIC [ErrorCode:0x%x] !-- %s Call %s Fail", rc, becall);
		(void)zxic_comm_mutex_unlock(mutex);
		ZXIC_COMM_ASSERT(0);
		return rc;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_RC_UNLOCK(dev_id, rc, becall, mutex) \
	zxic_comm_check_dev_rc_unlock_impl((dev_id), (rc), (becall), (mutex))

static inline u32 zxic_comm_check_dev_rc_no_assert_unlock_impl(u32 dev_id, u32 rc,
							       const char *becall,
							       struct zxic_mutex_t *mutex)
{
	if (rc != ZXIC_OK) {
		if (zxic_comm_errcode_check(rc) != ZXIC_OK)
			ZXIC_COMM_TRACE_DEV_ERROR(
				dev_id, "ZXIC [ErrorCode:0x%x] !-- %s Call %s Fail", rc, becall);
		(void)zxic_comm_mutex_unlock(mutex);
		return rc;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_RC_NO_ASSERT_UNLOCK(dev_id, rc, becall, mutex) \
	zxic_comm_check_dev_rc_no_assert_unlock_impl((dev_id), (rc), (becall), (mutex))

static inline u32 zxic_comm_check_dev_rc_close_fp_impl(u32 dev_id, u32 rc, const char *becall,
						       void *fp)
{
	if (rc != ZXIC_OK) {
		if (zxic_comm_errcode_check(rc) != ZXIC_OK)
			ZXIC_COMM_TRACE_DEV_ERROR(
				dev_id, "ZXIC [ErrorCode:0x%x] !-- %s Call %s Fail", rc, becall);
		if (ZXIC_COMM_FCLOSE(fp))
			ZXIC_COMM_TRACE_ERROR("ZXIC !-- close file Fail");
		ZXIC_COMM_ASSERT(0);
		return rc;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_RC_CLOSE_FP(dev_id, rc, becall, fp) \
	zxic_comm_check_dev_rc_close_fp_impl((dev_id), (rc), (becall), (fp))

static inline u32 zxic_comm_check_dev_rc_close_fp_no_assert_impl(u32 dev_id, u32 rc,
								 const char *becall, void *fp)
{
	if (rc != ZXIC_OK) {
		if (zxic_comm_errcode_check(rc) != ZXIC_OK)
			ZXIC_COMM_TRACE_DEV_ERROR(
				dev_id, "ZXIC [ErrorCode:0x%x] !-- %s Call %s Fail", rc, becall);
		if (ZXIC_COMM_FCLOSE(fp))
			ZXIC_COMM_TRACE_ERROR("ZXIC !-- close file Fail");
		return rc;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_RC_CLOSE_FP_NO_ASSERT(dev_id, rc, becall, fp) \
	zxic_comm_check_dev_rc_close_fp_no_assert_impl((dev_id), (rc), (becall), (fp))

static inline u32 zxic_comm_check_dev_rc_int_impl(u32 dev_id, s32 check_rc, u32 rc,
						  const char *becall)
{
	if (check_rc < 0) {
		ZXIC_COMM_TRACE_DEV_ERROR(dev_id,
					  "ICM [ErrorCode:0x%x] [rc:0x%x] !-- %s Call %s Fail",
					  check_rc, rc, becall);
		ZXIC_COMM_ASSERT(0);
		return rc;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_RC_INT(dev_id, check_rc, rc, becall) \
	zxic_comm_check_dev_rc_int_impl((dev_id), (check_rc), (rc), (becall))

static inline void zxic_comm_check_dev_rc_return_none_impl(u32 dev_id, u32 rc, const char *becall)
{
	if (rc != ZXIC_OK) {
		if (zxic_comm_errcode_check(rc) != ZXIC_OK)
			ZXIC_COMM_TRACE_DEV_ERROR(
				dev_id, "ZXIC [ErrorCode:0x%x] !-- %s Call %s Fail", rc, becall);
		ZXIC_COMM_ASSERT(0);
	}
}

#define ZXIC_COMM_CHECK_DEV_RC_RETURN_NONE(dev_id, rc, becall) \
	zxic_comm_check_dev_rc_return_none_impl((dev_id), (rc), (becall))

static inline void zxic_comm_check_dev_rc_return_none_no_assert_impl(u32 dev_id, u32 rc,
								     const char *becall)
{
	if (rc != ZXIC_OK) {
		if (zxic_comm_errcode_check(rc) != ZXIC_OK)
			ZXIC_COMM_TRACE_DEV_ERROR(
				dev_id, "ZXIC [ErrorCode:0x%x] !-- %s Call %s Fail", rc, becall);
	}
}

#define ZXIC_COMM_CHECK_DEV_RC_RETURN_NONE_NO_ASSERT(dev_id, rc, becall) \
	zxic_comm_check_dev_rc_return_none_no_assert_impl((dev_id), (rc), (becall))

static inline u32 zxic_comm_check_dev_rc_memory_free_no_assert_impl(u32 dev_id, u32 rc,
								    const char *becall, void *ptr)
{
	if (rc != ZXIC_OK) {
		if (zxic_comm_errcode_check(rc) != ZXIC_OK)
			ZXIC_COMM_TRACE_DEV_ERROR(dev_id, "ZXICP [ErrorCode:0x%x] Call %s Fail", rc,
						  becall);
		ZXIC_COMM_FREE(ptr);
		return rc;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_RC_MEMORY_FREE_NO_ASSERT(dev_id, rc, becall, ptr) \
	zxic_comm_check_dev_rc_memory_free_no_assert_impl((dev_id), (rc), (becall), (ptr))

static inline u32 zxic_comm_check_dev_rc_memory_free2ptr_no_assert_impl(u32 dev_id, u32 rc,
									const char *becall,
									void *ptr1, void *ptr2)
{
	if (rc != ZXIC_OK) {
		if (zxic_comm_errcode_check(rc) != ZXIC_OK)
			ZXIC_COMM_TRACE_DEV_ERROR(dev_id, "ZXICP [ErrorCode:0x%x] Call %s Fail", rc,
						  becall);
		ZXIC_COMM_FREE(ptr1);
		ZXIC_COMM_FREE(ptr2);
		return rc;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_RC_MEMORY_FREE2PTR_NO_ASSERT(dev_id, rc, becall, ptr1, ptr2)        \
	zxic_comm_check_dev_rc_memory_free2ptr_no_assert_impl((dev_id), (rc), (becall), (ptr1), \
							      (ptr2))

static inline u32 zxic_comm_check_dev_rc_memory_free3ptr_no_assert_impl(u32 dev_id, u32 rc,
									const char *becall,
									void *ptr1, void *ptr2,
									void *ptr3)
{
	if (rc != ZXIC_OK) {
		if (zxic_comm_errcode_check(rc) != ZXIC_OK)
			ZXIC_COMM_TRACE_DEV_ERROR(dev_id, "ZXICP [ErrorCode:0x%x] Call %s Fail", rc,
						  becall);
		ZXIC_COMM_FREE(ptr1);
		ZXIC_COMM_FREE(ptr2);
		ZXIC_COMM_FREE(ptr3);
		return rc;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_RC_MEMORY_FREE3PTR_NO_ASSERT(dev_id, rc, becall, ptr1, ptr2, ptr3)  \
	zxic_comm_check_dev_rc_memory_free3ptr_no_assert_impl((dev_id), (rc), (becall), (ptr1), \
							      (ptr2), (ptr3))

static inline u32 zxic_comm_check_dev_rc_memory_vfree3ptr_no_assert_impl(u32 dev_id, u32 rc,
									 const char *becall,
									 void *ptr1, void *ptr2,
									 void *ptr3)
{
	if (rc != ZXIC_OK) {
		if (zxic_comm_errcode_check(rc) != ZXIC_OK)
			ZXIC_COMM_TRACE_DEV_ERROR(dev_id, "ZXICP [ErrorCode:0x%x] Call %s Fail", rc,
						  becall);
		ZXIC_COMM_VFREE(ptr1);
		ZXIC_COMM_VFREE(ptr2);
		ZXIC_COMM_VFREE(ptr3);
		return rc;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_RC_MEMORY_VFREE3PTR_NO_ASSERT(dev_id, rc, becall, ptr1, ptr2, ptr3)  \
	zxic_comm_check_dev_rc_memory_vfree3ptr_no_assert_impl((dev_id), (rc), (becall), (ptr1), \
							       (ptr2), (ptr3))

static inline u32 zxic_comm_check_dev_point_impl(u32 dev_id, const void *point)
{
	if (point == ZXIC_NULL) {
		ZXIC_COMM_TRACE_DEV_ERROR(dev_id, "ZXIC [Error:POINT NULL] ! FUNCTION");
		ZXIC_COMM_ASSERT(0);
		return ZXIC_PAR_CHK_POINT_NULL;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_POINT(dev_id, point) zxic_comm_check_dev_point_impl((dev_id), (point))

static inline u32 zxic_comm_check_dev_point_unlock_impl(u32 dev_id, const void *point,
							struct zxic_mutex_t *mutex)
{
	if (point == ZXIC_NULL) {
		ZXIC_COMM_TRACE_DEV_ERROR(dev_id, "ZXIC [Error:POINT NULL] ! FUNCTION");
		(void)zxic_comm_mutex_unlock(mutex);
		ZXIC_COMM_ASSERT(0);
		return ZXIC_PAR_CHK_POINT_NULL;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_POINT_UNLOCK(dev_id, point, mutex) \
	zxic_comm_check_dev_point_unlock_impl((dev_id), (point), (mutex))

static inline u32 zxic_comm_check_dev_point_memory_free_impl(u32 dev_id, const void *point,
							     void *ptr)
{
	if (point == ZXIC_NULL) {
		ZXIC_COMM_TRACE_DEV_ERROR(dev_id, "ZXIC [Error:POINT NULL] ! FUNCTION");
		ZXIC_COMM_FREE(ptr);
		ZXIC_COMM_ASSERT(0);
		return ZXIC_PAR_CHK_POINT_NULL;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_POINT_MEMORY_FREE(dev_id, point, ptr) \
	zxic_comm_check_dev_point_memory_free_impl((dev_id), (point), (ptr))

static inline u32 zxic_comm_check_dev_point_ememory_free2ptr_impl(u32 dev_id, const void *point,
								  void *ptr0, void *ptr1)
{
	if (point == ZXIC_NULL) {
		ZXIC_COMM_TRACE_DEV_ERROR(dev_id, "ZXIC [Error:POINT NULL] ! FUNCTION");
		ZXIC_COMM_FREE(ptr0);
		ZXIC_COMM_FREE(ptr1);
		ZXIC_COMM_ASSERT(0);
		return ZXIC_PAR_CHK_POINT_NULL;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_POINT_EMEMORY_FREE2PTR(dev_id, point, ptr0, ptr1) \
	zxic_comm_check_dev_point_ememory_free2ptr_impl((dev_id), (point), (ptr0), (ptr1))

static inline u32 zxic_comm_check_dev_point_no_assert_impl(u32 dev_id, const void *point)
{
	if (point == ZXIC_NULL) {
		ZXIC_COMM_TRACE_DEV_ERROR(dev_id, "ZXIC [Error:POINT NULL] ! FUNCTION");
		return ZXIC_PAR_CHK_POINT_NULL;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_POINT_NO_ASSERT(dev_id, point) \
	zxic_comm_check_dev_point_no_assert_impl((dev_id), (point))

static inline u32 zxic_comm_check_dev_point_memory_free_no_assert_impl(u32 dev_id,
								       const void *point, void *ptr)
{
	if (point == ZXIC_NULL) {
		ZXIC_COMM_TRACE_DEV_ERROR(dev_id, "ZXIC [Error:POINT NULL] ! FUNCTION");
		ZXIC_COMM_FREE(ptr);
		return ZXIC_PAR_CHK_POINT_NULL;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_POINT_MEMORY_FREE_NO_ASSERT(dev_id, point, ptr) \
	zxic_comm_check_dev_point_memory_free_no_assert_impl((dev_id), (point), (ptr))

static inline u32 zxic_comm_check_dev_point_memory_free2ptr_no_assert_impl(u32 dev_id,
									   const void *point,
									   void *ptr1, void *ptr2)
{
	if (point == ZXIC_NULL) {
		ZXIC_COMM_TRACE_DEV_ERROR(dev_id, "ZXIC [Error:POINT NULL] ! FUNCTION");
		ZXIC_COMM_FREE(ptr1);
		ZXIC_COMM_FREE(ptr2);
		return ZXIC_PAR_CHK_POINT_NULL;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_POINT_MEMORY_FREE2PTR_NO_ASSERT(dev_id, point, ptr1, ptr2) \
	zxic_comm_check_dev_point_memory_free2ptr_no_assert_impl((dev_id), (point), (ptr1), (ptr2))

static inline u32 zxic_comm_check_dev_point_memory_free3ptr_no_assert_impl(u32 dev_id,
									   const void *point,
									   void *ptr1, void *ptr2,
									   void *ptr3)
{
	if (point == ZXIC_NULL) {
		ZXIC_COMM_TRACE_DEV_ERROR(dev_id, "ZXIC [Error:POINT NULL] ! FUNCTION");
		ZXIC_COMM_FREE(ptr1);
		ZXIC_COMM_FREE(ptr2);
		ZXIC_COMM_FREE(ptr3);
		return ZXIC_PAR_CHK_POINT_NULL;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_POINT_MEMORY_FREE3PTR_NO_ASSERT(dev_id, point, ptr1, ptr2, ptr3) \
	zxic_comm_check_dev_point_memory_free3ptr_no_assert_impl((dev_id), (point), (ptr1),  \
								 (ptr2), (ptr3))

static inline u32 zxic_comm_check_dev_point_close_fp_impl(u32 dev_id, const void *point, void *fp)
{
	if (point == ZXIC_NULL) {
		ZXIC_COMM_TRACE_DEV_ERROR(dev_id, "ZXIC [Error:POINT NULL] ! FUNCTION");
		if (ZXIC_COMM_FCLOSE(fp))
			ZXIC_COMM_TRACE_ERROR("ZXIC !-- close file Fail");
		ZXIC_COMM_ASSERT(0);
		return ZXIC_PAR_CHK_POINT_NULL;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_POINT_CLOSE_FP(dev_id, point, fp) \
	zxic_comm_check_dev_point_close_fp_impl((dev_id), (point), (fp))

static inline u32 zxic_comm_check_dev_point_close_fp_no_assert_impl(u32 dev_id, const void *point,
								    void *fp)
{
	if (point == ZXIC_NULL) {
		ZXIC_COMM_TRACE_DEV_ERROR(dev_id, "ZXIC [Error:POINT NULL] ! FUNCTION");
		if (ZXIC_COMM_FCLOSE(fp))
			ZXIC_COMM_TRACE_ERROR("ZXIC !-- close file Fail");
		return ZXIC_PAR_CHK_POINT_NULL;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_POINT_CLOSE_FP_NO_ASSERT(dev_id, point, fp) \
	zxic_comm_check_dev_point_close_fp_no_assert_impl((dev_id), (point), (fp))

static inline void zxic_comm_check_dev_point_return_none_impl(u32 dev_id, const void *point)
{
	if (point == ZXIC_NULL) {
		ZXIC_COMM_TRACE_DEV_ERROR(dev_id, "ZXIC [Error:POINT NULL] ! FUNCTION");
		ZXIC_COMM_ASSERT(0);
	}
}

#define ZXIC_COMM_CHECK_DEV_POINT_RETURN_NONE(dev_id, point) \
	zxic_comm_check_dev_point_return_none_impl((dev_id), (point))

static inline void zxic_comm_check_dev_point_return_none_no_assert_impl(u32 dev_id,
									const void *point)
{
	if (point == ZXIC_NULL)
		ZXIC_COMM_TRACE_DEV_ERROR(dev_id, "ZXIC [Error:POINT NULL] ! FUNCTION");
}

#define ZXIC_COMM_CHECK_DEV_POINT_RETURN_NONE_NO_ASSERT(dev_id, point) \
	zxic_comm_check_dev_point_return_none_no_assert_impl((dev_id), (point))

static inline void *zxic_comm_check_dev_point_return_null_impl(u32 dev_id, const void *point)
{
	if (point == ZXIC_NULL) {
		ZXIC_COMM_TRACE_DEV_ERROR(dev_id, "ZXIC [Error:POINT NULL] ! FUNCTION");
		ZXIC_COMM_ASSERT(0);
		return NULL;
	}
	return (void *)point;
}

#define ZXIC_COMM_CHECK_DEV_POINT_RETURN_NULL(dev_id, point) \
	zxic_comm_check_dev_point_return_null_impl((dev_id), (point))

static inline void *zxic_comm_check_dev_point_return_null_no_assert_impl(u32 dev_id,
									 const void *point)
{
	if (point == ZXIC_NULL) {
		ZXIC_COMM_TRACE_DEV_ERROR(dev_id, "ZXIC [Error:POINT NULL] ! FUNCTION");
		return NULL;
	}
	return (void *)point;
}

#define ZXIC_COMM_CHECK_DEV_POINT_RETURN_NULL_NO_ASSERT(dev_id, point) \
	zxic_comm_check_dev_point_return_null_no_assert_impl((dev_id), (point))

static inline u32 zxic_comm_check_dev_id_impl(u32 dev_id)
{
	if (zxic_comm_index_check(dev_id, 0, zxic_comm_channel_max_get() - 1) ==
	    ZXIC_PAR_CHK_INVALID_INDEX) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION", dev_id,
			0, zxic_comm_channel_max_get() - 1);
		ZXIC_COMM_ASSERT(0);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	if (zxic_comm_index_check(dev_id, 0, zxic_comm_channel_max_get() - 1) ==
	    ZXIC_PAR_CHK_INVALID_RANGE) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION", dev_id,
			0, zxic_comm_channel_max_get() - 1);
		ZXIC_COMM_ASSERT(0);
		return ZXIC_PAR_CHK_INVALID_RANGE;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_ID(dev_id) zxic_comm_check_dev_id_impl((dev_id))

static inline u32 zxic_comm_check_dev_id_no_assert_impl(u32 dev_id)
{
	if (zxic_comm_index_check(dev_id, 0, zxic_comm_channel_max_get() - 1) ==
	    ZXIC_PAR_CHK_INVALID_INDEX) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION", dev_id,
			0, zxic_comm_channel_max_get() - 1);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	if (zxic_comm_index_check(dev_id, 0, zxic_comm_channel_max_get() - 1) ==
	    ZXIC_PAR_CHK_INVALID_RANGE) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION", dev_id,
			0, zxic_comm_channel_max_get() - 1);
		return ZXIC_PAR_CHK_INVALID_RANGE;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_ID_NO_ASSERT(dev_id) zxic_comm_check_dev_id_no_assert_impl((dev_id))

static inline void *zxic_comm_check_dev_id_return_null_no_assert_impl(u32 dev_id)
{
	if (zxic_comm_index_check(dev_id, 0, zxic_comm_channel_max_get() - 1) ==
	    ZXIC_PAR_CHK_INVALID_INDEX) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION", dev_id,
			0, zxic_comm_channel_max_get() - 1);
		return NULL;
	}
	if (zxic_comm_index_check(dev_id, 0, zxic_comm_channel_max_get() - 1) ==
	    ZXIC_PAR_CHK_INVALID_RANGE) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION", dev_id,
			0, zxic_comm_channel_max_get() - 1);
		return NULL;
	}
	return (void *)(long)dev_id;
}

#define ZXIC_COMM_CHECK_DEV_ID_RETURN_NULL_NO_ASSERT(dev_id) \
	zxic_comm_check_dev_id_return_null_no_assert_impl((dev_id))

static inline u32 zxic_check_dev_ut_rc_impl(u32 dev_id, u32 rc, u32 val, const char *becall)
{
	if (val != rc) {
		ZXIC_COMM_PRINT("ZXICP [ErrorCode:0x%x], %s Call %s Fail", rc, becall);
		zxic_comm_ut_detail_trace_dev_error(
			dev_id, "ZXICP [ErrorCode:0x%x], %s Call %s Fail", rc, becall);
		return ZXIC_E_LLT_CHECK;
	}
	return ZXIC_OK;
}

#define ZXIC_CHECK_DEV_UT_RC(dev_id, rc, val, becall) \
	zxic_check_dev_ut_rc_impl((dev_id), (rc), (val), (becall))

static inline u32 zxic_comm_check_dev_index_upper_impl(u32 dev_id, u32 val, u32 max)
{
	if (val > max) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[0x%x] INVALID] [max=0x%x] ! FUNCTION", val, max);
		ZXIC_COMM_ASSERT(0);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_INDEX_UPPER(dev_id, val, max) \
	zxic_comm_check_dev_index_upper_impl((dev_id), (val), (max))

static inline u32 zxic_comm_check_dev_index_lower_impl(u32 dev_id, u32 val, u32 min)
{
	if (val < min) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x] ! FUNCTION", val, min);
		ZXIC_COMM_ASSERT(0);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_INDEX_LOWER(dev_id, val, min) \
	zxic_comm_check_dev_index_lower_impl((dev_id), (val), (min))

static inline u32 zxic_comm_check_dev_index_both_impl(u32 dev_id, u32 val, u32 min, u32 max)
{
	if (val < min || val > max) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION",
			val, min, max);
		ZXIC_COMM_ASSERT(0);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_INDEX_BOTH(dev_id, val, min, max) \
	zxic_comm_check_dev_index_both_impl((dev_id), (val), (min), (max))

static inline u32 zxic_comm_check_dev_index_no_assert_impl(u32 dev_id, u32 val, u32 min, u32 max)
{
	if (zxic_comm_dev_index_check(dev_id, val, min, max) == ZXIC_PAR_CHK_INVALID_INDEX) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION",
			val, min, max);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	if (zxic_comm_dev_index_check(dev_id, val, min, max) == ZXIC_PAR_CHK_INVALID_RANGE) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION",
			val, min, max);
		return ZXIC_PAR_CHK_INVALID_RANGE;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT(dev_id, val, min, max) \
	zxic_comm_check_dev_index_no_assert_impl((dev_id), (val), (min), (max))

static inline u32 zxic_comm_check_dev_index_no_assert_unlock_impl(u32 dev_id, u32 val, u32 min,
								  u32 max,
								  struct zxic_mutex_t *mutex)
{
	if (zxic_comm_dev_index_check(dev_id, val, min, max) == ZXIC_PAR_CHK_INVALID_INDEX) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION",
			val, min, max);
		(void)zxic_comm_mutex_unlock(mutex);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	if (zxic_comm_dev_index_check(dev_id, val, min, max) == ZXIC_PAR_CHK_INVALID_RANGE) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION",
			val, min, max);
		(void)zxic_comm_mutex_unlock(mutex);
		return ZXIC_PAR_CHK_INVALID_RANGE;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_INDEX_NO_ASSERT_UNLOCK(dev_id, val, min, max, mutex) \
	zxic_comm_check_dev_index_no_assert_unlock_impl((dev_id), (val), (min), (max), (mutex))

static inline u32 zxic_comm_check_dev_index_upper_no_assert_impl(u32 dev_id, u32 val, u32 max)
{
	if (val > max) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[0x%x] INVALID] [max=0x%x] ! FUNCTION", val, max);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_INDEX_UPPER_NO_ASSERT(dev_id, val, max) \
	zxic_comm_check_dev_index_upper_no_assert_impl((dev_id), (val), (max))

static inline u32 zxic_comm_check_dev_index_upper_no_assert_unlock_impl(u32 dev_id, u32 val,
									u32 max,
									struct zxic_mutex_t *mutex)
{
	if (val > max) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[0x%x] INVALID] [max=0x%x] ! FUNCTION", val, max);
		(void)zxic_comm_mutex_unlock(mutex);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_INDEX_UPPER_NO_ASSERT_UNLOCK(dev_id, val, max, mutex) \
	zxic_comm_check_dev_index_upper_no_assert_unlock_impl((dev_id), (val), (max), (mutex))

static inline u32 zxic_comm_check_dev_index_lower_no_assert_impl(u32 dev_id, u32 val, u32 min)
{
	if (val < min) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x] ! FUNCTION", val, min);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_INDEX_LOWER_NO_ASSERT(dev_id, val, min) \
	zxic_comm_check_dev_index_lower_no_assert_impl((dev_id), (val), (min))

static inline u32 zxic_comm_check_dev_index_lower_no_assert_unlock_impl(u32 dev_id, u32 val,
									u32 min,
									struct zxic_mutex_t *mutex)
{
	if (val < min) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x] ! FUNCTION", val, min);
		(void)zxic_comm_mutex_unlock(mutex);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_INDEX_LOWER_NO_ASSERT_UNLOCK(dev_id, val, min, mutex) \
	zxic_comm_check_dev_index_lower_no_assert_unlock_impl((dev_id), (val), (min), (mutex))

static inline u32 zxic_comm_check_dev_index_both_no_assert_impl(u32 dev_id, u32 val, u32 min,
								u32 max)
{
	if (val < min || val > max) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION",
			val, min, max);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_INDEX_BOTH_NO_ASSERT(dev_id, val, min, max) \
	zxic_comm_check_dev_index_both_no_assert_impl((dev_id), (val), (min), (max))

static inline u32 zxic_comm_check_dev_index_both_no_assert_unlock_impl(u32 dev_id, u32 val, u32 min,
								       u32 max,
								       struct zxic_mutex_t *mutex)
{
	if (val < min || val > max) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION",
			val, min, max);
		(void)zxic_comm_mutex_unlock(mutex);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_INDEX_BOTH_NO_ASSERT_UNLOCK(dev_id, val, min, max, mutex) \
	zxic_comm_check_dev_index_both_no_assert_unlock_impl((dev_id), (val), (min), (max), (mutex))

static inline void *zxic_comm_check_dev_index_return_null_impl(u32 dev_id, u32 val, u32 min,
							       u32 max)
{
	if (zxic_comm_dev_index_check(dev_id, val, min, max) == ZXIC_PAR_CHK_INVALID_INDEX) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION",
			val, min, max);
		ZXIC_COMM_ASSERT(0);
		return NULL;
	}
	if (zxic_comm_dev_index_check(dev_id, val, min, max) == ZXIC_PAR_CHK_INVALID_RANGE) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION",
			val, min, max);
		ZXIC_COMM_ASSERT(0);
		return NULL;
	}
	return (void *)(long)val;
}

#define ZXIC_COMM_CHECK_DEV_INDEX_RETURN_NULL(dev_id, val, min, max) \
	zxic_comm_check_dev_index_return_null_impl((dev_id), (val), (min), (max))

static inline void *zxic_comm_check_dev_index_return_null_no_assert_impl(u32 dev_id, u32 val,
									 u32 min, u32 max)
{
	if (zxic_comm_dev_index_check(dev_id, val, min, max) == ZXIC_PAR_CHK_INVALID_INDEX) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION",
			val, min, max);
		return NULL;
	}
	if (zxic_comm_dev_index_check(dev_id, val, min, max) == ZXIC_PAR_CHK_INVALID_RANGE) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION",
			val, min, max);
		return NULL;
	}
	return (void *)(long)val;
}

#define ZXIC_COMM_CHECK_DEV_INDEX_RETURN_NULL_NO_ASSERT(dev_id, val, min, max) \
	zxic_comm_check_dev_index_return_null_no_assert_impl((dev_id), (val), (min), (max))

static inline u32 zxic_comm_check_dev_index_add_overflow_impl(u32 dev_id, u32 val0, u32 val1)
{
	if ((ZXIC_UINT32_MAX - val0) < val1) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[val0=0x%x] INVALID] [val1=0x%x] ! FUNCTION",
			val0, val1);
		ZXIC_COMM_ASSERT(0);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_INDEX_ADD_OVERFLOW(dev_id, val0, val1) \
	zxic_comm_check_dev_index_add_overflow_impl((dev_id), (val0), (val1))

static inline u32 zxic_comm_check_dev_index_add_overflow_64_impl(u32 dev_id, u64 val0, u64 val1)
{
	if ((ZXIC_ULONG_MAX - val0) < val1) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[val0=0x%llx] INVALID] [val1=0x%llx] ! FUNCTION",
			val0, val1);
		ZXIC_COMM_ASSERT(0);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_INDEX_ADD_OVERFLOW_64(dev_id, val0, val1) \
	zxic_comm_check_dev_index_add_overflow_64_impl((dev_id), (val0), (val1))

static inline u32 zxic_comm_check_dev_index_sub_overflow_impl(u32 dev_id, u32 val0, u32 val1)
{
	if (val0 < val1) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[val0=0x%x] INVALID] [val1=0x%x] ! FUNCTION",
			val0, val1);
		ZXIC_COMM_ASSERT(0);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_INDEX_SUB_OVERFLOW(dev_id, val0, val1) \
	zxic_comm_check_dev_index_sub_overflow_impl((dev_id), (val0), (val1))

static inline u32 zxic_comm_check_dev_index_mul_overflow_impl(u32 dev_id, u32 val0, u32 val1)
{
	if (val0 > 0 && (ZXIC_UINT32_MAX / val0) < val1) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[val0=0x%x] INVALID] [val1=0x%x] ! FUNCTION",
			val0, val1);
		ZXIC_COMM_ASSERT(0);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_INDEX_MUL_OVERFLOW(dev_id, val0, val1) \
	zxic_comm_check_dev_index_mul_overflow_impl((dev_id), (val0), (val1))

static inline u32 zxic_comm_check_dev_index_upper_memory_free_impl(u32 dev_id, u32 val, u32 max,
								   void *ptr)
{
	if (val > max) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[0x%x] INVALID] [max=0x%x] ! FUNCTION", val, max);
		ZXIC_COMM_FREE(ptr);
		ZXIC_COMM_ASSERT(0);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_INDEX_UPPER_MEMORY_FREE(dev_id, val, max, ptr) \
	zxic_comm_check_dev_index_upper_memory_free_impl((dev_id), (val), (max), (ptr))

static inline u32 zxic_comm_check_dev_index_lower_memory_free_impl(u32 dev_id, u32 val, u32 min,
								   void *ptr)
{
	if (val < min) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x] ! FUNCTION", val, min);
		ZXIC_COMM_FREE(ptr);
		ZXIC_COMM_ASSERT(0);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_INDEX_LOWER_MEMORY_FREE(dev_id, val, min, ptr) \
	zxic_comm_check_dev_index_lower_memory_free_impl((dev_id), (val), (min), (ptr))

static inline u32 zxic_comm_check_dev_index_both_memory_free_impl(u32 dev_id, u32 val, u32 min,
								  u32 max, void *ptr)
{
	if (val < min || val > max) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION",
			val, min, max);
		ZXIC_COMM_FREE(ptr);
		ZXIC_COMM_ASSERT(0);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_INDEX_BOTH_MEMORY_FREE(dev_id, val, min, max, ptr) \
	zxic_comm_check_dev_index_both_memory_free_impl((dev_id), (val), (min), (max), (ptr))

static inline u32 zxic_comm_check_dev_index_upper_memory_free_no_assert_impl(u32 dev_id, u32 val,
									     u32 max, void *ptr)
{
	if (val > max) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[0x%x] INVALID] [max=0x%x] ! FUNCTION", val, max);
		ZXIC_COMM_FREE(ptr);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_INDEX_UPPER_MEMORY_FREE_NO_ASSERT(dev_id, val, max, ptr) \
	zxic_comm_check_dev_index_upper_memory_free_no_assert_impl((dev_id), (val), (max), (ptr))

static inline u32 zxic_comm_check_dev_index_lower_memory_free_no_assert_impl(u32 dev_id, u32 val,
									     u32 min, void *ptr)
{
	if (val < min) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x] ! FUNCTION", val, min);
		ZXIC_COMM_FREE(ptr);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_INDEX_LOWER_MEMORY_FREE_NO_ASSERT(dev_id, val, min, ptr) \
	zxic_comm_check_dev_index_lower_memory_free_no_assert_impl((dev_id), (val), (min), (ptr))

static inline u32 zxic_comm_check_dev_index_both_memory_free_no_assert_impl(u32 dev_id, u32 val,
									    u32 min, u32 max,
									    void *ptr)
{
	if (val < min || val > max) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION",
			val, min, max);
		ZXIC_COMM_FREE(ptr);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_INDEX_BOTH_MEMORY_FREE_NO_ASSERT(dev_id, val, min, max, ptr)         \
	zxic_comm_check_dev_index_both_memory_free_no_assert_impl((dev_id), (val), (min), (max), \
								  (ptr))

static inline u32 zxic_comm_check_dev_index_memory_free2ptr_no_assert_impl(u32 dev_id, u32 val,
									   u32 min, u32 max,
									   void *ptr1, void *ptr2)
{
	if (val < min || val > max) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION",
			val, min, max);
		ZXIC_COMM_FREE(ptr1);
		ZXIC_COMM_FREE(ptr2);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_INDEX_MEMORY_FREE2PTR_NO_ASSERT(dev_id, val, min, max, ptr1, ptr2)  \
	zxic_comm_check_dev_index_memory_free2ptr_no_assert_impl((dev_id), (val), (min), (max), \
								 (ptr1), (ptr2))

static inline u32 zxic_comm_check_dev_index_memory_free3ptr_no_assert_impl(u32 dev_id, u32 val,
									   u32 min, u32 max,
									   void *ptr1, void *ptr2,
									   void *ptr3)
{
	if (val < min || val > max) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION",
			val, min, max);
		ZXIC_COMM_FREE(ptr1);
		ZXIC_COMM_FREE(ptr2);
		ZXIC_COMM_FREE(ptr3);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_INDEX_MEMORY_FREE3PTR_NO_ASSERT(dev_id, val, min, max, ptr1, ptr2,  \
							    ptr3)                               \
	zxic_comm_check_dev_index_memory_free3ptr_no_assert_impl((dev_id), (val), (min), (max), \
								 (ptr1), (ptr2), (ptr3))

static inline u32 zxic_comm_check_dev_index_memory_free_no_assert_impl(u32 dev_id, u32 val, u32 min,
								       u32 max, void *ptr)
{
	if (val < min || val > max) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION",
			val, min, max);
		ZXIC_COMM_FREE(ptr);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_INDEX_MEMORY_FREE_NO_ASSERT(dev_id, val, min, max, ptr) \
	zxic_comm_check_dev_index_memory_free_no_assert_impl((dev_id), (val), (min), (max), (ptr))

static inline u32 zxic_comm_check_dev_index_add_overflow_no_assert_impl(u32 dev_id, u32 val0,
									u32 val1)
{
	if ((ZXIC_UINT32_MAX - val0) < val1) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[val0=0x%x] INVALID] [val1=0x%x] ! FUNCTION",
			val0, val1);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_INDEX_ADD_OVERFLOW_NO_ASSERT(dev_id, val0, val1) \
	zxic_comm_check_dev_index_add_overflow_no_assert_impl((dev_id), (val0), (val1))

static inline u32
zxic_comm_check_dev_index_add_overflow_no_assert_unlock_impl(u32 dev_id, u32 val0, u32 val1,
							     struct zxic_mutex_t *mutex)
{
	if ((ZXIC_UINT32_MAX - val0) < val1) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[val0=0x%x] INVALID] [val1=0x%x] ! FUNCTION",
			val0, val1);
		(void)zxic_comm_mutex_unlock(mutex);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_INDEX_ADD_OVERFLOW_NO_ASSERT_UNLOCK(dev_id, val0, val1, mutex)     \
	zxic_comm_check_dev_index_add_overflow_no_assert_unlock_impl((dev_id), (val0), (val1), \
								     (mutex))

static inline u32 zxic_comm_check_dev_index_add_overflow_64_no_assert_impl(u32 dev_id, u64 val0,
									   u64 val1)
{
	if ((ZXIC_ULONG_MAX - val0) < val1) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[val0=0x%llx] INVALID] [val1=0x%llx] ! FUNCTION",
			val0, val1);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_INDEX_ADD_OVERFLOW_64_NO_ASSERT(dev_id, val0, val1) \
	zxic_comm_check_dev_index_add_overflow_64_no_assert_impl((dev_id), (val0), (val1))

static inline u32 zxic_comm_check_dev_index_add_overflow_close_fp_no_assert_impl(u32 dev_id,
										 u32 val0, u32 val1,
										 void *fp)
{
	if ((ZXIC_UINT32_MAX - val0) < val1) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[val0=0x%x] INVALID] [val1=0x%x] ! FUNCTION",
			val0, val1);
		if (ZXIC_COMM_FCLOSE(fp))
			ZXIC_COMM_TRACE_ERROR("ZXIC !-- close file Fail");
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_INDEX_ADD_OVERFLOW_CLOSE_FP_NO_ASSERT(dev_id, val0, val1, fp)        \
	zxic_comm_check_dev_index_add_overflow_close_fp_no_assert_impl((dev_id), (val0), (val1), \
								       (fp))

static inline u32 zxic_comm_check_dev_index_sub_overflow_no_assert_impl(u32 dev_id, u32 val0,
									u32 val1)
{
	if (val0 < val1) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[val0=0x%x] INVALID] [val1=0x%x] ! FUNCTION",
			val0, val1);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_INDEX_SUB_OVERFLOW_NO_ASSERT(dev_id, val0, val1) \
	zxic_comm_check_dev_index_sub_overflow_no_assert_impl((dev_id), (val0), (val1))

static inline u32
zxic_comm_check_dev_index_sub_overflow_no_assert_unlock_impl(u32 dev_id, u32 val0, u32 val1,
							     struct zxic_mutex_t *mutex)
{
	if (val0 < val1) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[val0=0x%x] INVALID] [val1=0x%x] ! FUNCTION",
			val0, val1);
		(void)zxic_comm_mutex_unlock(mutex);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_INDEX_SUB_OVERFLOW_NO_ASSERT_UNLOCK(dev_id, val0, val1, mutex)     \
	zxic_comm_check_dev_index_sub_overflow_no_assert_unlock_impl((dev_id), (val0), (val1), \
								     (mutex))

static inline u32 zxic_comm_check_dev_index_mul_overflow_no_assert_impl(u32 dev_id, u32 val0,
									u32 val1)
{
	if (val0 > 0 && (ZXIC_UINT32_MAX / val0) < val1) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[val0=0x%x] INVALID] [val1=0x%x] ! FUNCTION",
			val0, val1);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_INDEX_MUL_OVERFLOW_NO_ASSERT(dev_id, val0, val1) \
	zxic_comm_check_dev_index_mul_overflow_no_assert_impl((dev_id), (val0), (val1))

static inline u32
zxic_comm_check_dev_index_mul_overflow_no_assert_unlock_impl(u32 dev_id, u32 val0, u32 val1,
							     struct zxic_mutex_t *mutex)
{
	if (val0 > 0 && (ZXIC_UINT32_MAX / val0) < val1) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[val0=0x%x] INVALID] [val1=0x%x] ! FUNCTION",
			val0, val1);
		(void)zxic_comm_mutex_unlock(mutex);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_INDEX_MUL_OVERFLOW_NO_ASSERT_UNLOCK(dev_id, val0, val1, mutex)     \
	zxic_comm_check_dev_index_mul_overflow_no_assert_unlock_impl((dev_id), (val0), (val1), \
								     (mutex))

static inline u32 zxic_comm_check_dev_index_mul_overflow_64_no_assert_impl(u32 dev_id, u64 val0,
									   u64 val1)
{
	if (val0 > 0 && (ZXIC_ULONG_MAX / val0) < val1) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[val0=0x%llx] INVALID] [val1=0x%llx] ! FUNCTION",
			val0, val1);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_INDEX_MUL_OVERFLOW_64_NO_ASSERT(dev_id, val0, val1) \
	zxic_comm_check_dev_index_mul_overflow_64_no_assert_impl((dev_id), (val0), (val1))

static inline u32 zxic_comm_check_dev_index_mul_overflow_close_fp_no_assert_impl(u32 dev_id,
										 u32 val0, u32 val1,
										 void *fp)
{
	if (val0 > 0 && (ZXIC_UINT32_MAX / val0) < val1) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[val0=0x%x] INVALID] [val1=0x%x] ! FUNCTION",
			val0, val1);
		if (ZXIC_COMM_FCLOSE(fp))
			ZXIC_COMM_TRACE_ERROR("ZXIC !-- close file Fail");
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_INDEX_MUL_OVERFLOW_CLOSE_FP_NO_ASSERT(dev_id, val0, val1, fp)        \
	zxic_comm_check_dev_index_mul_overflow_close_fp_no_assert_impl((dev_id), (val0), (val1), \
								       (fp))

static inline void zxic_comm_check_index_add_overflow_return_impl(u32 val0, u32 val1)
{
	ZXIC_COMM_TRACE_ERROR("ZXIC [Error:VALUE[val0=0x%x] INVALID] [val1=0x%x] ! FUNCTION", val0,
			      val1);
}

#define ZXIC_COMM_CHECK_INDEX_ADD_OVERFLOW_RETURN(val0, val1) \
	zxic_comm_check_index_add_overflow_return_impl((val0), (val1))

static inline void zxic_comm_check_index_add_overflow_return_none_impl(u32 val0, u32 val1)
{
	if ((ZXIC_UINT32_MAX - val0) < val1) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error:VALUE[val0=0x%x] INVALID] [val1=0x%x] ! FUNCTION", val0, val1);
	}
}

#define ZXIC_COMM_CHECK_INDEX_ADD_OVERFLOW_RETURN_NONE(val0, val1) \
	zxic_comm_check_index_add_overflow_return_none_impl((val0), (val1))

static inline void zxic_comm_check_index_add_overflow_return_none_no_assert_impl(u32 val0, u32 val1)
{
	if ((ZXIC_UINT32_MAX - val0) < val1) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error:VALUE[val0=0x%x] INVALID] [val1=0x%x] ! FUNCTION", val0, val1);
	}
}

#define ZXIC_COMM_CHECK_INDEX_ADD_OVERFLOW_RETURN_NONE_NO_ASSERT(val0, val1) \
	zxic_comm_check_index_add_overflow_return_none_no_assert_impl((val0), (val1))

static inline void zxic_comm_check_index_sub_overflow_return_impl(u32 val0, u32 val1)
{
	ZXIC_COMM_TRACE_ERROR("ZXIC [Error:VALUE[val0=0x%x] INVALID] [val1=0x%x] ! FUNCTION", val0,
			      val1);
}

#define ZXIC_COMM_CHECK_INDEX_SUB_OVERFLOW_RETURN(val0, val1) \
	zxic_comm_check_index_sub_overflow_return_impl((val0), (val1))

static inline void zxic_comm_check_index_sub_overflow_return_none_impl(u32 val0, u32 val1)
{
	if (val0 < val1) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error:VALUE[val0=0x%x] INVALID] [val1=0x%x] ! FUNCTION", val0, val1);
	}
}

#define ZXIC_COMM_CHECK_INDEX_SUB_OVERFLOW_RETURN_NONE(val0, val1) \
	zxic_comm_check_index_sub_overflow_return_none_impl((val0), (val1))

static inline void zxic_comm_check_index_sub_overflow_return_none_no_assert_impl(u32 val0, u32 val1)
{
	if (val0 < val1) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error:VALUE[val0=0x%x] INVALID] [val1=0x%x] ! FUNCTION", val0, val1);
	}
}

#define ZXIC_COMM_CHECK_INDEX_SUB_OVERFLOW_RETURN_NONE_NO_ASSERT(val0, val1) \
	zxic_comm_check_index_sub_overflow_return_none_no_assert_impl((val0), (val1))

static inline void zxic_comm_check_index_mul_overflow_return_none_impl(u32 val0, u32 val1)
{
	if (val0 > 0 && (ZXIC_UINT32_MAX / val0) < val1) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error:VALUE[val0=0x%x] INVALID] [val1=0x%x] ! FUNCTION", val0, val1);
	}
}

#define ZXIC_COMM_CHECK_INDEX_MUL_OVERFLOW_RETURN_NONE(val0, val1) \
	zxic_comm_check_index_mul_overflow_return_none_impl((val0), (val1))

static inline void zxic_comm_check_index_mul_overflow_return_none_no_assert_impl(u32 val0, u32 val1)
{
	if (val0 > 0 && (ZXIC_UINT32_MAX / val0) < val1) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error:VALUE[val0=0x%x] INVALID] [val1=0x%x] ! FUNCTION", val0, val1);
	}
}

#define ZXIC_COMM_CHECK_INDEX_MUL_OVERFLOW_RETURN_NONE_NO_ASSERT(val0, val1) \
	zxic_comm_check_index_mul_overflow_return_none_no_assert_impl((val0), (val1))

static inline void zxic_comm_check_index_upper_return_none_impl(u32 val, u32 max)
{
	if (val > max) {
		ZXIC_COMM_TRACE_ERROR("ZXIC [Error:VALUE[0x%x] INVALID] [max=0x%x] ! FUNCTION", val,
				      max);
	}
}

#define ZXIC_COMM_CHECK_INDEX_UPPER_RETURN_NONE(val, max) \
	zxic_comm_check_index_upper_return_none_impl((val), (max))

static inline void zxic_comm_check_index_upper_return_none_no_assert_impl(u32 val, u32 max)
{
	if (val > max) {
		ZXIC_COMM_TRACE_ERROR("ZXIC [Error:VALUE[0x%x] INVALID] [max=0x%x] ! FUNCTION", val,
				      max);
	}
}

#define ZXIC_COMM_CHECK_INDEX_UPPER_RETURN_NONE_NO_ASSERT(val, max) \
	zxic_comm_check_index_upper_return_none_no_assert_impl((val), (max))

static inline void zxic_comm_check_index_lower_return_none_impl(u32 val, u32 min)
{
	if (val < min) {
		ZXIC_COMM_TRACE_ERROR("ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x] ! FUNCTION", val,
				      min);
	}
}

#define ZXIC_COMM_CHECK_INDEX_LOWER_RETURN_NONE(val, min) \
	zxic_comm_check_index_lower_return_none_impl((val), (min))

static inline void zxic_comm_check_index_lower_return_none_no_assert_impl(u32 val, u32 min)
{
	if (val < min) {
		ZXIC_COMM_TRACE_ERROR("ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x] ! FUNCTION", val,
				      min);
	}
}

#define ZXIC_COMM_CHECK_INDEX_LOWER_RETURN_NONE_NO_ASSERT(val, min) \
	zxic_comm_check_index_lower_return_none_no_assert_impl((val), (min))

static inline void zxic_comm_check_index_both_return_none_impl(u32 val, u32 min, u32 max)
{
	if (val < min || val > max) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error[VAL=0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION", val, min,
			max);
	}
}

#define ZXIC_COMM_CHECK_INDEX_BOTH_RETURN_NONE(val, min, max) \
	zxic_comm_check_index_both_return_none_impl((val), (min), (max))

static inline void zxic_comm_check_index_both_return_none_no_assert_impl(u32 val, u32 min, u32 max)
{
	if (val < min || val > max) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error[VAL=0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION", val, min,
			max);
	}
}

#define ZXIC_COMM_CHECK_INDEX_BOTH_RETURN_NONE_NO_ASSERT(val, min, max) \
	zxic_comm_check_index_both_return_none_no_assert_impl((val), (min), (max))

static inline u32 zxic_comm_check_index_return_null_impl(u32 val, u32 min, u32 max)
{
	if (zxic_comm_index_check(val, min, max) == ZXIC_PAR_CHK_INVALID_INDEX) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION", val, min,
			max);
		ZXIC_COMM_ASSERT(0);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	if (zxic_comm_index_check(val, min, max) == ZXIC_PAR_CHK_INVALID_RANGE) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION", val, min,
			max);
		ZXIC_COMM_ASSERT(0);
		return ZXIC_PAR_CHK_INVALID_RANGE;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_INDEX_RETURN_NULL(val, min, max) \
	zxic_comm_check_index_return_null_impl((val), (min), (max))

static inline u32 zxic_comm_check_index_return_null_no_assert_impl(u32 val, u32 min, u32 max)
{
	if (zxic_comm_index_check(val, min, max) == ZXIC_PAR_CHK_INVALID_INDEX) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION", val, min,
			max);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	if (zxic_comm_index_check(val, min, max) == ZXIC_PAR_CHK_INVALID_RANGE) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION", val, min,
			max);
		return ZXIC_PAR_CHK_INVALID_RANGE;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_INDEX_RETURN_NULL_NO_ASSERT(val, min, max) \
	zxic_comm_check_index_return_null_no_assert_impl((val), (min), (max))

static inline void zxic_comm_check_index_return_void_no_assert_impl(u32 val, u32 min, u32 max)
{
	if (zxic_comm_index_check(val, min, max) == ZXIC_PAR_CHK_INVALID_INDEX) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION", val, min,
			max);
		return;
	}
	if (zxic_comm_index_check(val, min, max) == ZXIC_PAR_CHK_INVALID_RANGE) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION", val, min,
			max);
		return;
	}
}

#define ZXIC_COMM_CHECK_INDEX_RETURN_VOID_NO_ASSERT(val, min, max) \
	zxic_comm_check_index_return_void_no_assert_impl((val), (min), (max))

static inline u32 zxic_comm_check_index_upper_memory_free_impl(u32 val, u32 max, void *ptr)
{
	if (val > max) {
		ZXIC_COMM_TRACE_ERROR("ZXIC [Error:VALUE[0x%x] INVALID] [max=0x%x] ! FUNCTION", val,
				      max);
		ZXIC_COMM_FREE(ptr);
		ZXIC_COMM_ASSERT(0);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_INDEX_UPPER_MEMORY_FREE(val, max, ptr) \
	zxic_comm_check_index_upper_memory_free_impl((val), (max), (ptr))

static inline u32 zxic_comm_check_index_lower_memory_free_impl(u32 val, u32 min, void *ptr)
{
	if (val < min) {
		ZXIC_COMM_TRACE_ERROR("ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x] ! FUNCTION", val,
				      min);
		ZXIC_COMM_FREE(ptr);
		ZXIC_COMM_ASSERT(0);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_INDEX_LOWER_MEMORY_FREE(val, min, ptr) \
	zxic_comm_check_index_lower_memory_free_impl((val), (min), (ptr))

static inline u32 zxic_comm_check_index_both_memory_free_impl(u32 val, u32 min, u32 max, void *ptr)
{
	if (val < min || val > max) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION", val, min,
			max);
		ZXIC_COMM_FREE(ptr);
		ZXIC_COMM_ASSERT(0);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_INDEX_BOTH_MEMORY_FREE(val, min, max, ptr) \
	zxic_comm_check_index_both_memory_free_impl((val), (min), (max), (ptr))

static inline u32 zxic_comm_check_index_add_overflow_memory_free_impl(u32 val0, u32 val1, void *ptr)
{
	if ((ZXIC_UINT32_MAX - val0) < val1) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error:VALUE[val0=0x%x] INVALID] [val1=0x%x] ! FUNCTION", val0, val1);
		ZXIC_COMM_FREE(ptr);
		ZXIC_COMM_ASSERT(0);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_INDEX_ADD_OVERFLOW_MEMORY_FREE(val0, val1, ptr) \
	zxic_comm_check_index_add_overflow_memory_free_impl((val0), (val1), (ptr))

static inline u32 zxic_comm_check_index_upper_memory_free_no_assert_impl(u32 val, u32 max,
									 void *ptr)
{
	if (val > max) {
		ZXIC_COMM_TRACE_ERROR("ZXIC [Error:VALUE[0x%x] INVALID] [max=0x%x] ! FUNCTION", val,
				      max);
		ZXIC_COMM_FREE(ptr);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_INDEX_UPPER_MEMORY_FREE_NO_ASSERT(val, max, ptr) \
	zxic_comm_check_index_upper_memory_free_no_assert_impl((val), (max), (ptr))

static inline u32 zxic_comm_check_index_lower_memory_free_no_assert_impl(u32 val, u32 min,
									 void *ptr)
{
	if (val < min) {
		ZXIC_COMM_TRACE_ERROR("ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x] ! FUNCTION", val,
				      min);
		ZXIC_COMM_FREE(ptr);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_INDEX_LOWER_MEMORY_FREE_NO_ASSERT(val, min, ptr) \
	zxic_comm_check_index_lower_memory_free_no_assert_impl((val), (min), (ptr))

static inline u32 zxic_comm_check_index_both_memory_free_no_assert_impl(u32 val, u32 min, u32 max,
									void *ptr)
{
	if (val < min || val > max) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION", val, min,
			max);
		ZXIC_COMM_FREE(ptr);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_INDEX_BOTH_MEMORY_FREE_NO_ASSERT(val, min, max, ptr) \
	zxic_comm_check_index_both_memory_free_no_assert_impl((val), (min), (max), (ptr))

static inline u32 zxic_comm_check_index_add_overflow_64_no_assert_impl(u64 val0, u64 val1)
{
	if ((ZXIC_ULONG_MAX - val0) < val1) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error:VALUE[val0=0x%x] INVALID] [val1=0x%x] ! FUNCTION", val0, val1);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_INDEX_ADD_OVERFLOW_64_NO_ASSERT(val0, val1) \
	zxic_comm_check_index_add_overflow_64_no_assert_impl((val0), (val1))

static inline u32
zxic_comm_check_index_add_overflow_no_assert_unlock_impl(u32 val0, u32 val1,
							 struct zxic_mutex_t *mutex)
{
	if ((ZXIC_UINT32_MAX - val0) < val1) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error:VALUE[val0=0x%x] INVALID] [val1=0x%x] ! FUNCTION", val0, val1);
		(void)zxic_comm_mutex_unlock(mutex);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_INDEX_ADD_OVERFLOW_NO_ASSERT_UNLOCK(val0, val1, mutex) \
	zxic_comm_check_index_add_overflow_no_assert_unlock_impl((val0), (val1), (mutex))

static inline u32
zxic_comm_check_index_sub_overflow_no_assert_unlock_impl(u32 val0, u32 val1,
							 struct zxic_mutex_t *mutex)
{
	if (val0 < val1) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error:VALUE[val0=0x%x] INVALID] [val1=0x%x] ! FUNCTION", val0, val1);
		(void)zxic_comm_mutex_unlock(mutex);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_INDEX_SUB_OVERFLOW_NO_ASSERT_UNLOCK(val0, val1, mutex) \
	zxic_comm_check_index_sub_overflow_no_assert_unlock_impl((val0), (val1), (mutex))

static inline u32
zxic_comm_check_index_mul_overflow_no_assert_unlock_impl(u32 val0, u32 val1,
							 struct zxic_mutex_t *mutex)
{
	if (val0 > 0 && (ZXIC_UINT32_MAX / val0) < val1) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error:VALUE[val0=0x%x] INVALID] [val1=0x%x] ! FUNCTION", val0, val1);
		(void)zxic_comm_mutex_unlock(mutex);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_INDEX_MUL_OVERFLOW_NO_ASSERT_UNLOCK(val0, val1, mutex) \
	zxic_comm_check_index_mul_overflow_no_assert_unlock_impl((val0), (val1), (mutex))

static inline u32 zxic_comm_check_dev_index_impl(u32 dev_id, u32 val, u32 min, u32 max)
{
	if (zxic_comm_dev_index_check(dev_id, val, min, max) == ZXIC_PAR_CHK_INVALID_INDEX) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION",
			val, min, max);
		ZXIC_COMM_ASSERT(0);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	if (zxic_comm_dev_index_check(dev_id, val, min, max) == ZXIC_PAR_CHK_INVALID_RANGE) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION",
			val, min, max);
		ZXIC_COMM_ASSERT(0);
		return ZXIC_PAR_CHK_INVALID_RANGE;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_INDEX(dev_id, val, min, max) \
	zxic_comm_check_dev_index_impl((dev_id), (val), (min), (max))

static inline u32 zxic_comm_check_dev_index_mul_overflow_64_impl(u32 dev_id, u64 val0, u64 val1)
{
	if (val0 > 0 && (ZXIC_ULONG_MAX / val0) < val1) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[val0=0x%llx] INVALID] [val1=0x%llx] ! FUNCTION",
			val0, val1);
		ZXIC_COMM_ASSERT(0);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_DEV_INDEX_MUL_OVERFLOW_64(dev_id, val0, val1) \
	zxic_comm_check_dev_index_mul_overflow_64_impl((dev_id), (val0), (val1))

static inline void zxic_comm_check_index_upper_memory_free_return_none_impl(u32 val, u32 max,
									    void *ptr)
{
	if (val > max) {
		ZXIC_COMM_TRACE_ERROR("ZXIC [Error:VALUE[0x%x] INVALID] [max=0x%x] ! FUNCTION", val,
				      max);
		ZXIC_COMM_FREE(ptr);
		ZXIC_COMM_ASSERT(0);
	}
}

#define ZXIC_COMM_CHECK_INDEX_UPPER_MEMORY_FREE_RETURN_NONE(val, max, ptr) \
	zxic_comm_check_index_upper_memory_free_return_none_impl((val), (max), (ptr))

static inline void zxic_comm_check_index_lower_memory_free_return_none_impl(u32 val, u32 min,
									    void *ptr)
{
	if (val < min) {
		ZXIC_COMM_TRACE_ERROR("ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x] ! FUNCTION", val,
				      min);
		ZXIC_COMM_FREE(ptr);
		ZXIC_COMM_ASSERT(0);
	}
}

#define ZXIC_COMM_CHECK_INDEX_LOWER_MEMORY_FREE_RETURN_NONE(val, min, ptr) \
	zxic_comm_check_index_lower_memory_free_return_none_impl((val), (min), (ptr))

static inline void zxic_comm_check_index_both_memory_free_return_none_impl(u32 val, u32 min,
									   u32 max, void *ptr)
{
	if (val < min || val > max) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION", val, min,
			max);
		ZXIC_COMM_FREE(ptr);
		ZXIC_COMM_ASSERT(0);
	}
}

#define ZXIC_COMM_CHECK_INDEX_BOTH_MEMORY_FREE_RETURN_NONE(val, min, max, ptr) \
	zxic_comm_check_index_both_memory_free_return_none_impl((val), (min), (max), (ptr))

static inline void
zxic_comm_check_index_upper_memory_free_return_none_no_assert_impl(u32 val, u32 max, void *ptr)
{
	if (val > max) {
		ZXIC_COMM_TRACE_ERROR("ZXIC [Error:VALUE[0x%x] INVALID] [max=0x%x] ! FUNCTION", val,
				      max);
		ZXIC_COMM_FREE(ptr);
	}
}

#define ZXIC_COMM_CHECK_INDEX_UPPER_MEMORY_FREE_RETURN_NONE_NO_ASSERT(val, max, ptr) \
	zxic_comm_check_index_upper_memory_free_return_none_no_assert_impl((val), (max), (ptr))

static inline void
zxic_comm_check_index_lower_memory_free_return_none_no_assert_impl(u32 val, u32 min, void *ptr)
{
	if (val < min) {
		ZXIC_COMM_TRACE_ERROR("ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x] ! FUNCTION", val,
				      min);
		ZXIC_COMM_FREE(ptr);
	}
}

#define ZXIC_COMM_CHECK_INDEX_LOWER_MEMORY_FREE_RETURN_NONE_NO_ASSERT(val, min, ptr) \
	zxic_comm_check_index_lower_memory_free_return_none_no_assert_impl((val), (min), (ptr))

static inline void zxic_comm_check_index_both_memory_free_return_none_no_assert_impl(u32 val,
										     u32 min,
										     u32 max,
										     void *ptr)
{
	if (val < min || val > max) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION", val, min,
			max);
		ZXIC_COMM_FREE(ptr);
	}
}

#define ZXIC_COMM_CHECK_INDEX_BOTH_MEMORY_FREE_RETURN_NONE_NO_ASSERT(val, min, max, ptr)       \
	zxic_comm_check_index_both_memory_free_return_none_no_assert_impl((val), (min), (max), \
									  (ptr))

static inline void
zxic_comm_check_dev_index_upper_memory_free_return_none_no_assert_impl(u32 dev_id, u32 val, u32 max,
								       void *ptr)
{
	if (val > max) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[0x%x] INVALID] [max=0x%x] ! FUNCTION", val, max);
		ZXIC_COMM_FREE(ptr);
	}
}

#define ZXIC_COMM_CHECK_DEV_INDEX_UPPER_MEMORY_FREE_RETURN_NONE_NO_ASSERT(dev_id, val, max, ptr) \
	zxic_comm_check_dev_index_upper_memory_free_return_none_no_assert_impl((dev_id), (val),  \
									       (max), (ptr))

static inline void
zxic_comm_check_dev_index_lower_memory_free_return_none_no_assert_impl(u32 dev_id, u32 val, u32 min,
								       void *ptr)
{
	if (val < min) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x] ! FUNCTION", val, min);
		ZXIC_COMM_FREE(ptr);
	}
}

#define ZXIC_COMM_CHECK_DEV_INDEX_LOWER_MEMORY_FREE_RETURN_NONE_NO_ASSERT(dev_id, val, min, ptr) \
	zxic_comm_check_dev_index_lower_memory_free_return_none_no_assert_impl((dev_id), (val),  \
									       (min), (ptr))

static inline u32 zxic_comm_check_rc_unlock_no_print_impl(u32 rc, struct zxic_mutex_t *p_mutex,
							  u32 error_code)
{
	if (rc != ZXIC_OK) {
		(void)zxic_comm_mutex_unlock(p_mutex);
		ZXIC_COMM_ASSERT(0);
		return error_code;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_RC_UNLOCK_NO_PRINT(rc, p_mutex, error_code) \
	zxic_comm_check_rc_unlock_no_print_impl((rc), (p_mutex), (error_code))

static inline u32 zxic_comm_check_index_no_print_unlock_impl(u32 val, u32 min, u32 max,
							     struct zxic_mutex_t *p_mutex)
{
	if (zxic_comm_index_check(val, min, max) == ZXIC_PAR_CHK_INVALID_INDEX) {
		(void)zxic_comm_mutex_unlock(p_mutex);
		ZXIC_COMM_ASSERT(0);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	if (zxic_comm_index_check(val, min, max) == ZXIC_PAR_CHK_INVALID_RANGE) {
		(void)zxic_comm_mutex_unlock(p_mutex);
		ZXIC_COMM_ASSERT(0);
		return ZXIC_PAR_CHK_INVALID_RANGE;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_INDEX_NO_PRINT_UNLOCK(val, min, max, p_mutex) \
	zxic_comm_check_index_no_print_unlock_impl((val), (min), (max), (p_mutex))

static inline u32
zxic_comm_check_index_sub_overflow_no_print_unlock_impl(u32 val0, u32 val1,
							struct zxic_mutex_t *mutex)
{
	if (val0 < val1) {
		if (zxic_comm_mutex_unlock(mutex) != 0) {
			ZXIC_COMM_ASSERT(0);
			return ZXIC_PAR_CHK_INVALID_PARA;
		}
		ZXIC_COMM_ASSERT(0);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_INDEX_SUB_OVERFLOW_NO_PRINT_UNLOCK(val0, val1, mutex) \
	zxic_comm_check_index_sub_overflow_no_print_unlock_impl((val0), (val1), (mutex))

static inline void zxic_comm_check_dev_index_add_overflow_return_none_impl(u32 dev_id, u32 val0,
									   u32 val1)
{
	if ((ZXIC_UINT32_MAX - val0) < val1) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[val0=0x%x] INVALID] [val1=0x%x] ! FUNCTION",
			val0, val1);
		ZXIC_COMM_ASSERT(0);
	}
}

#define ZXIC_COMM_CHECK_DEV_INDEX_ADD_OVERFLOW_RETURN_NONE(dev_id, val0, val1) \
	zxic_comm_check_dev_index_add_overflow_return_none_impl((dev_id), (val0), (val1))

static inline void
zxic_comm_check_dev_index_add_overflow_return_none_no_assert_impl(u32 dev_id, u32 val0, u32 val1)
{
	if ((ZXIC_UINT32_MAX - val0) < val1) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[val0=0x%x] INVALID] [val1=0x%x] ! FUNCTION",
			val0, val1);
	}
}

#define ZXIC_COMM_CHECK_DEV_INDEX_ADD_OVERFLOW_RETURN_NONE_NO_ASSERT(dev_id, val0, val1) \
	zxic_comm_check_dev_index_add_overflow_return_none_no_assert_impl((dev_id), (val0), (val1))

static inline void zxic_comm_check_dev_index_add_overflow_64_return_none_impl(u32 dev_id, u64 val0,
									      u64 val1)
{
	if ((ZXIC_ULONG_MAX - val0) < val1) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[val0=0x%llx] INVALID] [val1=0x%llx] ! FUNCTION",
			val0, val1);
		ZXIC_COMM_ASSERT(0);
	}
}

#define ZXIC_COMM_CHECK_DEV_INDEX_ADD_OVERFLOW_64_RETURN_NONE(dev_id, val0, val1) \
	zxic_comm_check_dev_index_add_overflow_64_return_none_impl((dev_id), (val0), (val1))

static inline void zxic_comm_check_dev_index_sub_overflow_return_none_impl(u32 dev_id, u32 val0,
									   u32 val1)
{
	if (val0 < val1) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[val0=0x%x] INVALID] [val1=0x%x] ! FUNCTION",
			val0, val1);
		ZXIC_COMM_ASSERT(0);
	}
}

#define ZXIC_COMM_CHECK_DEV_INDEX_SUB_OVERFLOW_RETURN_NONE(dev_id, val0, val1) \
	zxic_comm_check_dev_index_sub_overflow_return_none_impl((dev_id), (val0), (val1))

static inline void
zxic_comm_check_dev_index_sub_overflow_return_none_no_assert_impl(u32 dev_id, u32 val0, u32 val1)
{
	if (val0 < val1) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[val0=0x%x] INVALID] [val1=0x%x] ! FUNCTION",
			val0, val1);
	}
}

#define ZXIC_COMM_CHECK_DEV_INDEX_SUB_OVERFLOW_RETURN_NONE_NO_ASSERT(dev_id, val0, val1) \
	zxic_comm_check_dev_index_sub_overflow_return_none_no_assert_impl((dev_id), (val0), (val1))

static inline void zxic_comm_check_dev_index_mul_overflow_return_none_impl(u32 dev_id, u32 val0,
									   u32 val1)
{
	if (val0 > 0 && (ZXIC_UINT32_MAX / val0) < val1) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[val0=0x%x] INVALID] [val1=0x%x] ! FUNCTION",
			val0, val1);
		ZXIC_COMM_ASSERT(0);
	}
}

#define ZXIC_COMM_CHECK_DEV_INDEX_MUL_OVERFLOW_RETURN_NONE(dev_id, val0, val1) \
	zxic_comm_check_dev_index_mul_overflow_return_none_impl((dev_id), (val0), (val1))

static inline void
zxic_comm_check_dev_index_mul_overflow_return_none_no_assert_impl(u32 dev_id, u32 val0, u32 val1)
{
	if (val0 > 0 && (ZXIC_UINT32_MAX / val0) < val1) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[val0=0x%x] INVALID] [val1=0x%x] ! FUNCTION",
			val0, val1);
	}
}

#define ZXIC_COMM_CHECK_DEV_INDEX_MUL_OVERFLOW_RETURN_NONE_NO_ASSERT(dev_id, val0, val1) \
	zxic_comm_check_dev_index_mul_overflow_return_none_no_assert_impl((dev_id), (val0), (val1))

static inline void zxic_comm_check_dev_index_upper_return_none_impl(u32 dev_id, u32 val, u32 max)
{
	if (val > max) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[0x%x] INVALID] [max=0x%x] ! FUNCTION", val, max);
		ZXIC_COMM_ASSERT(0);
	}
}

#define ZXIC_COMM_CHECK_DEV_INDEX_UPPER_RETURN_NONE(dev_id, val, max) \
	zxic_comm_check_dev_index_upper_return_none_impl((dev_id), (val), (max))

static inline void zxic_comm_check_dev_index_upper_return_none_no_assert_impl(u32 dev_id, u32 val,
									      u32 max)
{
	if (val > max) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[0x%x] INVALID] [max=0x%x] ! FUNCTION", val, max);
	}
}

#define ZXIC_COMM_CHECK_DEV_INDEX_UPPER_RETURN_NONE_NO_ASSERT(dev_id, val, max) \
	zxic_comm_check_dev_index_upper_return_none_no_assert_impl((dev_id), (val), (max))

static inline void zxic_comm_check_dev_index_lower_return_none_impl(u32 dev_id, u32 val, u32 min)
{
	if (val < min) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x] ! FUNCTION", val, min);
		ZXIC_COMM_ASSERT(0);
	}
}

#define ZXIC_COMM_CHECK_DEV_INDEX_LOWER_RETURN_NONE(dev_id, val, min) \
	zxic_comm_check_dev_index_lower_return_none_impl((dev_id), (val), (min))

static inline void zxic_comm_check_dev_index_lower_return_none_no_assert_impl(u32 dev_id, u32 val,
									      u32 min)
{
	if (val < min) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x] ! FUNCTION", val, min);
	}
}

#define ZXIC_COMM_CHECK_DEV_INDEX_LOWER_RETURN_NONE_NO_ASSERT(dev_id, val, min) \
	zxic_comm_check_dev_index_lower_return_none_no_assert_impl((dev_id), (val), (min))

static inline void zxic_comm_check_dev_index_both_return_none_impl(u32 dev_id, u32 val, u32 min,
								   u32 max)
{
	if (val < min || val > max) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION",
			val, min, max);
		ZXIC_COMM_ASSERT(0);
	}
}

#define ZXIC_COMM_CHECK_DEV_INDEX_BOTH_RETURN_NONE(dev_id, val, min, max) \
	zxic_comm_check_dev_index_both_return_none_impl((dev_id), (val), (min), (max))

static inline void zxic_comm_check_dev_index_both_return_none_no_assert_impl(u32 dev_id, u32 val,
									     u32 min, u32 max)
{
	if (val < min || val > max) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION",
			val, min, max);
	}
}

#define ZXIC_COMM_CHECK_DEV_INDEX_BOTH_RETURN_NONE_NO_ASSERT(dev_id, val, min, max) \
	zxic_comm_check_dev_index_both_return_none_no_assert_impl((dev_id), (val), (min), (max))

static inline void zxic_comm_check_dev_index_upper_memory_free_return_none_impl(u32 dev_id, u32 val,
										u32 max, void *ptr)
{
	if (val > max) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[0x%x] INVALID] [max=0x%x] ! FUNCTION", val, max);
		ZXIC_COMM_FREE(ptr);
		ZXIC_COMM_ASSERT(0);
	}
}

#define ZXIC_COMM_CHECK_DEV_INDEX_UPPER_MEMORY_FREE_RETURN_NONE(dev_id, val, max, ptr) \
	zxic_comm_check_dev_index_upper_memory_free_return_none_impl((dev_id), (val), (max), (ptr))

static inline void zxic_comm_check_dev_index_lower_memory_free_return_none_impl(u32 dev_id, u32 val,
										u32 min, void *ptr)
{
	if (val < min) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x] ! FUNCTION", val, min);
		ZXIC_COMM_FREE(ptr);
		ZXIC_COMM_ASSERT(0);
	}
}

#define ZXIC_COMM_CHECK_DEV_INDEX_LOWER_MEMORY_FREE_RETURN_NONE(dev_id, val, min, ptr) \
	zxic_comm_check_dev_index_lower_memory_free_return_none_impl((dev_id), (val), (min), (ptr))

static inline void zxic_comm_check_dev_index_both_memory_free_return_none_impl(u32 dev_id, u32 val,
									       u32 min, u32 max,
									       void *ptr)
{
	if (val < min || val > max) {
		ZXIC_COMM_TRACE_DEV_ERROR(
			dev_id, "ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION",
			val, min, max);
		ZXIC_COMM_FREE(ptr);
		ZXIC_COMM_ASSERT(0);
	}
}

#define ZXIC_COMM_CHECK_DEV_INDEX_BOTH_MEMORY_FREE_RETURN_NONE(dev_id, val, min, max, ptr)         \
	zxic_comm_check_dev_index_both_memory_free_return_none_impl((dev_id), (val), (min), (max), \
								    (ptr))

static inline u32 zxic_comm_check_index_memory_free_no_assert_impl(u32 val, u32 min, u32 max,
								   void *ptr)
{
	if (zxic_comm_index_check(val, min, max) == ZXIC_PAR_CHK_INVALID_INDEX) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION", val, min,
			max);
		ZXIC_COMM_FREE(ptr);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	if (zxic_comm_index_check(val, min, max) == ZXIC_PAR_CHK_INVALID_RANGE) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION", val, min,
			max);
		ZXIC_COMM_FREE(ptr);
		return ZXIC_PAR_CHK_INVALID_RANGE;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_INDEX_MEMORY_FREE_NO_ASSERT(val, min, max, ptr) \
	zxic_comm_check_index_memory_free_no_assert_impl((val), (min), (max), (ptr))

static inline u32 zxic_comm_check_index_memory_free2ptr_no_assert_impl(u32 val, u32 min, u32 max,
								       void *ptr1, void *ptr2)
{
	if (zxic_comm_index_check(val, min, max) == ZXIC_PAR_CHK_INVALID_INDEX) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION", val, min,
			max);
		ZXIC_COMM_FREE(ptr1);
		ZXIC_COMM_FREE(ptr2);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	if (zxic_comm_index_check(val, min, max) == ZXIC_PAR_CHK_INVALID_RANGE) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION", val, min,
			max);
		ZXIC_COMM_FREE(ptr1);
		ZXIC_COMM_FREE(ptr2);
		return ZXIC_PAR_CHK_INVALID_RANGE;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_INDEX_MEMORY_FREE2PTR_NO_ASSERT(val, min, max, ptr1, ptr2) \
	zxic_comm_check_index_memory_free2ptr_no_assert_impl((val), (min), (max), (ptr1), (ptr2))

static inline u32 zxic_comm_check_index_memory_free3ptr_no_assert_impl(u32 val, u32 min, u32 max,
								       void *ptr1, void *ptr2,
								       void *ptr3)
{
	if (zxic_comm_index_check(val, min, max) == ZXIC_PAR_CHK_INVALID_INDEX) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION", val, min,
			max);
		ZXIC_COMM_FREE(ptr1);
		ZXIC_COMM_FREE(ptr2);
		ZXIC_COMM_FREE(ptr3);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	if (zxic_comm_index_check(val, min, max) == ZXIC_PAR_CHK_INVALID_RANGE) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION", val, min,
			max);
		ZXIC_COMM_FREE(ptr1);
		ZXIC_COMM_FREE(ptr2);
		ZXIC_COMM_FREE(ptr3);
		return ZXIC_PAR_CHK_INVALID_RANGE;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_INDEX_MEMORY_FREE3PTR_NO_ASSERT(val, min, max, ptr1, ptr2, ptr3)          \
	zxic_comm_check_index_memory_free3ptr_no_assert_impl((val), (min), (max), (ptr1), (ptr2), \
							     (ptr3))

static inline u32 zxic_comm_check_index_add_overflow_no_assert_impl(u32 val0, u32 val1)
{
	if ((ZXIC_UINT32_MAX - val0) < val1) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error:VALUE[val0=0x%x] INVALID] [val1=0x%x] ! FUNCTION", val0, val1);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_INDEX_ADD_OVERFLOW_NO_ASSERT(val0, val1) \
	zxic_comm_check_index_add_overflow_no_assert_impl((val0), (val1))

static inline u32 zxic_comm_check_index_sub_overflow_no_assert_impl(u32 val0, u32 val1)
{
	if (val0 < val1) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error:VALUE[val0=0x%x] INVALID] [val1=0x%x] ! FUNCTION", val0, val1);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_INDEX_SUB_OVERFLOW_NO_ASSERT(val0, val1) \
	zxic_comm_check_index_sub_overflow_no_assert_impl((val0), (val1))

static inline u32 zxic_comm_check_index_mul_overflow_no_assert_impl(u32 val0, u32 val1)
{
	if (val0 > 0 && (ZXIC_UINT32_MAX / val0) < val1) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error:VALUE[val0=0x%x] INVALID] [val1=0x%x] ! FUNCTION", val0, val1);
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_INDEX_MUL_OVERFLOW_NO_ASSERT(val0, val1) \
	zxic_comm_check_index_mul_overflow_no_assert_impl((val0), (val1))

static inline u32 zxic_comm_check_index_close_fp_no_assert_impl(u32 val, u32 min, u32 max, void *fp)
{
	if (zxic_comm_index_check(val, min, max) == ZXIC_PAR_CHK_INVALID_INDEX) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION", val, min,
			max);
		if (ZXIC_COMM_FCLOSE(fp))
			ZXIC_COMM_TRACE_ERROR("ZXIC !-- close file Fail");
		return ZXIC_PAR_CHK_INVALID_INDEX;
	}
	if (zxic_comm_index_check(val, min, max) == ZXIC_PAR_CHK_INVALID_RANGE) {
		ZXIC_COMM_TRACE_ERROR(
			"ZXIC [Error:VALUE[0x%x] INVALID] [min=0x%x,max=0x%x] ! FUNCTION", val, min,
			max);
		if (ZXIC_COMM_FCLOSE(fp))
			ZXIC_COMM_TRACE_ERROR("ZXIC !-- close file Fail");
		return ZXIC_PAR_CHK_INVALID_RANGE;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_INDEX_CLOSE_FP_NO_ASSERT(val, min, max, fp) \
	zxic_comm_check_index_close_fp_no_assert_impl((val), (min), (max), (fp))

static inline u32 zxic_comm_check_rc_no_assert_impl(u32 rc, const char *becall)
{
	if (rc != ZXIC_OK) {
		if (zxic_comm_errcode_check(rc) != ZXIC_OK)
			ZXIC_COMM_TRACE_ERROR("ZXIC [ErrorCode:0x%x] !-- %s Call %s Fail", rc,
					      becall);
		return rc;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_RC_NO_ASSERT(rc, becall) zxic_comm_check_rc_no_assert_impl((rc), (becall))

static inline void zxic_comm_check_rc_return_none_impl(u32 rc, const char *becall)
{
	if (rc != ZXIC_OK) {
		if (zxic_comm_errcode_check(rc) != ZXIC_OK)
			ZXIC_COMM_TRACE_ERROR("ZXIC [ErrorCode:0x%x] !-- %s Call %s Fail", rc,
					      becall);
		ZXIC_COMM_ASSERT(0);
	}
}

#define ZXIC_COMM_CHECK_RC_RETURN_NONE(rc, becall) \
	zxic_comm_check_rc_return_none_impl((rc), (becall))

static inline void zxic_comm_check_rc_return_none_no_assert_impl(u32 rc, const char *becall)
{
	if (rc != ZXIC_OK) {
		if (zxic_comm_errcode_check(rc) != ZXIC_OK)
			ZXIC_COMM_TRACE_ERROR("ZXIC [ErrorCode:0x%x] !-- %s Call %s Fail", rc,
					      becall);
	}
}

#define ZXIC_COMM_CHECK_RC_RETURN_NONE_NO_ASSERT(rc, becall) \
	zxic_comm_check_rc_return_none_no_assert_impl((rc), (becall))

static inline void zxic_comm_check_rc_none_impl(u32 rc, const char *becall)
{
	if (rc != ZXIC_OK) {
		if (zxic_comm_errcode_check(rc) != ZXIC_OK)
			ZXIC_COMM_TRACE_ERROR("ZXIC [ErrorCode:0x%x] !-- %s Call %s Fail", rc,
					      becall);
		ZXIC_COMM_ASSERT(0);
	}
}

#define ZXIC_COMM_CHECK_RC_NONE(rc, becall) zxic_comm_check_rc_none_impl((rc), (becall))

static inline u32 zxic_comm_check_rc_no_print_impl(u32 rc, u32 error_code)
{
	if (rc != ZXIC_OK) {
		ZXIC_COMM_ASSERT(0);
		return error_code;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_RC_NO_PRINT(rc, error_code) \
	zxic_comm_check_rc_no_print_impl((rc), (error_code))

static inline char *zxic_comm_check_rc_point_no_print_impl(const void *point, char *rc)
{
	if (point == ZXIC_NULL) {
		ZXIC_COMM_ASSERT(0);
		return rc;
	}
	return ZXIC_OK;
}

#define ZXIC_COMM_CHECK_RC_POINT_NO_PRINT(point, rc) \
	zxic_comm_check_rc_point_no_print_impl((point), (rc))

#endif

#if ZXIC_REAL("NO DEV_ID & NO ASSERT")

#endif

#if ZXIC_REAL("DEV_ID & ASSERT")

#endif

#if ZXIC_REAL("DEV_ID & NO ASSERT")

#endif
#if ZXIC_REAL("return no code")

#endif

#if ZXIC_REAL("return no code & no assert")

#endif

#if ZXIC_REAL("no return")
#define ZXIC_COMM_CHECK_INDEX_NONE(val, min, max)	\
	do {		\
		if (zxic_comm_index_check(val, min, max) != ZXIC_OK)	\
			;		\
		{			\
			ZXIC_COMM_TRACE_ERROR(             \
				"\n %s:%d Error:0x%x INVALID min=0x%x,max=0x%x FUNCTION :%s\n", \
				__FILE__, __LINE__, val, min, max, __func__); \
		}	\
	} while (0)
#define ZXIC_COMM_CHECK_INDEX_UPPER_NONE(val, max)	\
	do {	\
		if ((val) > (max)) {	\
			ZXIC_COMM_TRACE_ERROR(    \
				"\n %s:%d Error:0x%x INVALID max=0x%x FUNCTION :%s\n", \
				__FILE__, __LINE__, val, max, __func__); \
		}                                 \
	} while (0)
#define ZXIC_COMM_CHECK_INDEX_ADD_OVERFLOW_NONE(val0, val1)		\
	do {	\
		if ((ZXIC_UINT32_MAX - (val0)) < (val1)) {	\
			ZXIC_COMM_TRACE_ERROR(	\
				"\n %s:%d Error:val0=0x%x INVALID val1=0x%x FUNCTION :%s\n", \
				__FILE__, __LINE__, val0, val1, __func__);	\
			ZXIC_COMM_ASSERT(0);	\
		}				\
	} while (0)
#define ZXIC_COMM_CHECK_INDEX_SUB_OVERFLOW_NONE(val0, val1)		\
	do {	\
		if ((val0) < (val1)) {	\
			ZXIC_COMM_TRACE_ERROR(	\
				"\n %s:%d Error:val0=0x%x INVALID val1=0x%x FUNCTION :%s\n", \
				__FILE__, __LINE__, val0, val1, __func__);	\
			ZXIC_COMM_ASSERT(0);	\
		}	\
	} while (0)
#define ZXIC_COMM_CHECK_INDEX_MUL_OVERFLOW_NONE(val0, val1)	\
	do {	\
		if (((val0) > 0) && ((ZXIC_UINT32_MAX / (val0)) < (val1))) {   \
			ZXIC_COMM_TRACE_ERROR( \
				"\n %s:%d Error:val0=0x%x INVALID val1=0x%x FUNCTION :%s\n", \
				__FILE__, __LINE__, val0, val1, __func__); \
			ZXIC_COMM_ASSERT(0); \
		}           \
	} while (0)
#define ZXIC_COMM_CHECK_INDEX_LOWER_NONE(val, min)\
	do { \
		if ((val) < (min)) { \
			ZXIC_COMM_TRACE_ERROR(    \
				"\n %s:%d Error:0x%x INVALID min=0x%x FUNCTION :%s\n", \
				__FILE__, __LINE__, val, min, __func__); \
		}     \
	} while (0)
#define ZXIC_COMM_CHECK_INDEX_BOTH_NONE(val, min, max) \
	do { \
		if (((val) < (min)) || ((val) > (max))) {  \
			ZXIC_COMM_TRACE_ERROR(             \
				"\n %s:%d Error:0x%x INVALID min=0x%x,max=0x%x FUNCTION :%s\n", \
				__FILE__, __LINE__, val, min, max, __func__);     \
		}              \
	} while (0)

#define ZXIC_COMM_CHECK_DEV_RC_NONE(dev_id, rc, becall)              \
	do {      \
		if (rc != ZXIC_OK) {          \
			if (zxic_comm_errcode_check(rc) != ZXIC_OK) {\
				ZXIC_COMM_TRACE_DEV_ERROR(           \
					dev_id,                      \
					"\n ZXIC %s:%d [ErrorCode:0x%x] %s Call %s Fail!\n", \
					__FILE__, __LINE__, rc, __func__, becall);               \
			}                     \
			ZXIC_COMM_ASSERT(0);  \
		} \
	} while (0)

#define ZXIC_COMM_CHECK_DEV_POINT_NONE(dev_id, point)             \
	do {   \
		if (NULL == (point)) {     \
			ZXIC_COMM_TRACE_DEV_ERROR(                \
				dev_id, "\n ZXIC %s:%d[Error:POINT NULL] FUNCTION : %s\n", \
				__FILE__, __LINE__, __func__);    \
			ZXIC_COMM_ASSERT(0);                      \
		} \
	} while (0)

#define ZXIC_COMM_CHECK_DEV_INDEX_NONE(dev_id, val, min, max) \
	do {                   \
		if (ZXIC_PAR_CHK_INVALID_INDEX ==          \
		    zxic_comm_dev_index_check(dev_id, val, min, max)) {  \
			ZXIC_COMM_TRACE_DEV_ERROR(         \
				dev_id,                    \
				"\n %s:%d Error:0x%x INVALID min=0x%x,max=0x%x FUNCTION :%s\n", \
				__FILE__, __LINE__, val, min, max, __func__);     \
		} else if (ZXIC_PAR_CHK_INVALID_RANGE ==   \
			   zxic_comm_dev_index_check(dev_id, val, min, max)) {    \
			ZXIC_COMM_TRACE_DEV_ERROR(         \
				dev_id,                    \
				"\n %s:%d Error:0x%x INVALID min=0x%x,max=0x%x FUNCTION :%s\n", \
				__FILE__, __LINE__, val, min, max, __func__);     \
		}              \
	} while (0)
#define ZXIC_COMM_CHECK_DEV_INDEX_UPPER_NONE(dev_id, val, max) \
	do {          \
		if ((val) > (max)) {              \
			ZXIC_COMM_TRACE_DEV_ERROR(\
				dev_id,           \
				"\n %s:%d Error:0x%x INVALID max=0x%x FUNCTION :%s !\n", \
				__FILE__, __LINE__, val, max, __func__); \
		}     \
	} while (0)
#define ZXIC_COMM_CHECK_DEV_INDEX_LOWER_NONE(dev_id, val, min) \
	do {          \
		if ((val) < (min)) {              \
			ZXIC_COMM_TRACE_DEV_ERROR(\
				dev_id,           \
				"\n %s:%d Error:0x%x INVALID min=0x%x FUNCTION :%s\n", \
				__FILE__, __LINE__, val, min, __func__); \
		}     \
	} while (0)
#define ZXIC_COMM_CHECK_DEV_INDEX_BOTH_NONE(dev_id, val, min, max) \
	do {                   \
		if (((val) < (min)) || ((val) > (max))) {  \
			ZXIC_COMM_TRACE_DEV_ERROR(         \
				dev_id,                    \
				"\n %s:%d Error:0x%x INVALID min=0x%x,max=0x%x FUNCTION :%s\n", \
				__FILE__, __LINE__, val, min, max, __func__);     \
		}              \
	} while (0)

#endif
#if ZXIC_REAL("no print")

#endif
#endif

//#ifdef ZXIC_FOR_LLT
#if ZXIC_REAL("UT_TEST")

#endif

#if ZXIC_REAL("")

#define ZXIC_COMM_CONVERT32(dw_data)       \
	((((dw_data)&0xff) << 24) | (((dw_data)&0xff00) << 8) | (((dw_data)&0xff0000) >> 8) | \
	 (((dw_data)&0xff000000) >> 24))

#define ZXIC_COMM_CONVERT16(w_data) ((((w_data)&0xff) << 8) | (((w_data)&0xff00) >> 8))

#define ZXIC_COMM_CONVERT32_16b(w_data) ((((w_data)&0xffff) << 16) | (((w_data)&0xffff0000) >> 16))

void zxic_comm_swap_en_set(u32 enable);
u32 zxic_comm_swap_en_get(void);
u32 zxic_comm_is_big_endian(void);
u32 zxic_comm_endian_prt(void);
void zxic_comm_swap(u8 *p_uc_data, u32 dw_byte_len);
void zxic_comm_swap_16b(u8 *p_uc_data, u32 dw_byte_len);
u64 ZXIC_COMM_COUNTER64_BUILD(u32 hi, u32 lo);
#endif

#if ZXIC_REAL("")
u32 zxic_comm_get_malloc_num(void);
u32 zxic_comm_get_malloc_size(void);
void zxic_clr_malloc_num(void);

#define ZXIC_COMM_MALLOC(size) ic_comm_malloc_memory(size)

#define ZXIC_COMM_VMALLOC(size) ic_comm_vmalloc_memory(size)

#define ZXIC_COMM_ALLOC_MEMORY(ptr, size)         \
	do {          \
		(ptr) = ZXIC_COMM_MALLOC(size);   \
		ZXIC_COMM_CHECK_POINT(ptr);       \
		ZXIC_COMM_MEMSET((ptr), 0, size); \
	} while (0)
#define ZXIC_COMM_ALLOC_MEMORY_DEV(dev_id, ptr, size)   \
	do {                \
		(ptr) = ZXIC_COMM_MALLOC(size);         \
		ZXIC_COMM_CHECK_DEV_POINT(dev_id, ptr); \
		ZXIC_COMM_MEMSET((ptr), 0, size);       \
	} while (0)

#endif

#if ZXIC_REAL("")
// void zxic_comm_sleep(u32 milliseconds);
void zxic_comm_msleep(u32 millisecond);
void zxic_comm_udelay(u32 microseconds);
void zxic_comm_delay(u32 milliseconds);
long zxic_comm_get_ticks_s(void);
long zxic_comm_get_ticks_ms(void);
long zxic_get_ticks_uses(void);
#endif

#if ZXIC_REAL("bit")

#define ZXIC_COMM_MASK_BIT(intType, _bitNum_) ((intType)(0x1U << (_bitNum_)))

#define ZXIC_COMM_GET_BIT_MASK(_intType_, _bitQnt_)                  \
	((_intType_)(((_bitQnt_) < 32) ?      \
	((_intType_)ZXIC_COMM_MASK_BIT(_intType_, ((_bitQnt_)&0x1F)) - 1) : \
	((_intType_)(0xffffffff))))

#define ZXIC_COMM_UINT32_WRITE_BITS(_uiDst_, _uiSrc_, _uiStartPos_, _uiLen_)                     \
	((_uiDst_) = ((_uiDst_) & ~(ZXIC_COMM_GET_BIT_MASK(u32, (_uiLen_)) << (_uiStartPos_))) | \
		     (((_uiSrc_)&ZXIC_COMM_GET_BIT_MASK(u32, (_uiLen_))) << (_uiStartPos_)))

#define ZXIC_COMM_UINT32_WRITE_BITS_ZERO(_uiDst_, _uiStartPos_, _uiLen_) \
	((_uiDst_) = ((_uiDst_) & ~(ZXIC_COMM_GET_BIT_MASK(u32, (_uiLen_)) << (_uiStartPos_))))

#define ZXIC_COMM_UINT32_GET_BITS(_uiDst_, _uiSrc_, _uiStartPos_, _uiLen_) \
	((_uiDst_) = (((_uiSrc_) >> (_uiStartPos_)) & (ZXIC_COMM_GET_BIT_MASK(u32, (_uiLen_)))))

#define ZXIC_COMM_UINT32_GET_RETURN_BITS(_uiSrc_, _uiStartPos_, _uiLen_) \
	(((_uiSrc_) >> (_uiStartPos_)) & (ZXIC_COMM_GET_BIT_MASK(u32, (_uiLen_))))

#define ZXIC_COMM_MASK_BIT_64(intType, _bitNum_) ((intType)(0x1ULL << (_bitNum_)))

#define ZXIC_COMM_GET_64_BIT_MASK(_intType_, _bitQnt_)             \
	((_intType_)(                       \
	((_bitQnt_) < 64) ?         \
	((_intType_)ZXIC_COMM_MASK_BIT_64(_intType_, ((_bitQnt_)&0x3F)) - 1) : \
	((_intType_)(0xFFFFFFFFFFFFFFFFULL))))

#define ZXIC_COMM_UINT64_WRITE_BITS(_uiDst_, _uiSrc_, _uiStartPos_, _uiLen_)                    \
	((_uiDst_) =                         \
	((_uiDst_) & ~(ZXIC_COMM_GET_64_BIT_MASK(u64, (_uiLen_)) << (_uiStartPos_))) | \
	(((_uiSrc_)&ZXIC_COMM_GET_64_BIT_MASK(u64, (_uiLen_))) << (_uiStartPos_)))

/* Base type for declarations */
#define ZXIC_COMM_BITDCL u32
#define ZXIC_COMM_BITWID (32)

/* (internal) Number of ZXICP_BITDCLs needed to contain _max bits */
#define NPE_BITDCLSIZE(_max) (((_max) + ZXIC_COMM_BITWID - 1) / ZXIC_COMM_BITWID)

/* Size for giving to malloc and memset to handle _max bits */
#define ZXIC_COMM_BITALLOCSIZE(_max) (NPE_BITDCLSIZE(_max) * sizeof(ZXIC_COMM_BITDCL))

/* (internal) Generic operation macro on bit array _a, with bit _b */
#define NPE_BITOP(_a, _b, _op) \
	(((_a)[(_b) / ZXIC_COMM_BITWID]) _op(1U << ((_b) % ZXIC_COMM_BITWID)))

/* Specific operations */
#define ZXIC_COMM_BITGET(_a, _b) NPE_BITOP(_a, _b, &)
#define ZXIC_COMM_BITSET(_a, _b) NPE_BITOP(_a, _b, |=)
#define ZXIC_COMM_BITCLR(_a, _b) NPE_BITOP(_a, _b, &= ~)

u32 zxic_comm_bit_count(u32 data);
u32 zxic_comm_read_bits(u8 *p_base, u32 base_size_bit, u32 *p_data, u32 start_bit, u32 end_bit);
u32 zxic_comm_write_bits(u8 *p_base, u32 base_size_bit, u32 data, u32 start_bit, u32 end_bit);
u32 zxic_comm_write_bits_ex(u8 *p_base, u32 base_size_bit, u32 data, u32 msb_start_pos, u32 len);
u32 zxic_comm_read_bits_ex(u8 *p_base, u32 base_size_bit, u32 *p_data, u32 msb_start_pos, u32 len);
u32 zxic_comm_write_bits_op(u8 *p_src_dat, u32 src_size_bit, u32 input_data, u32 start_bit,
			    u32 end_bit);
u32 zxic_comm_read_bits_op(u8 *p_src_dat, u32 src_size_bit, u32 *p_out_data, u32 start_bit,
			   u32 end_bit);
#endif

#if ZXIC_REAL("")
u64 zxic_comm_get_gcd(u64 a, u64 b);
u32 zxic_comm_multi_big_integer(const char *num1, const char *num2, char *str_num);
u32 zxic_comm_div_big_integer(const char *num1, const char *num2, u32 *quo_val);
s32 zxic_comm_sub_stract(s32 *p1, s32 *p2, s32 len1, s32 len2);
s32 zxic_comm_cmpm_calc(u64 cm_cal, u64 pm_cal, u32 *cm, u32 *pm);
void zxic_comm_pm_cm_cal(u64 cm_y, u64 pm_y, u32 *cm, u32 *pm);
#endif

#if ZXIC_REAL("")
u32 zxic_comm_strcasecmp(char *str1, char *str2);
u8 zxic_comm_char_to_hex(u8 c);
ulong zxic_comm_ipaddr_to_dword(const char *p_addr);
u32 zxic_comm_char_to_number(char a, char b, u8 *number);
char *zxic_comm_strlower(char *str);
u32 ic_comm_check_str_size(char *str);
size_t ic_comm_getAbsValue(u8 *dest, const u8 *src);
void ic_comm_memset_s(void *dest, size_t dmax, u8 c, size_t n);
s32 ic_comm_memcmp(void *str1, const void *str2, size_t n);
s32 ic_comm_strncmp(const char *str1, const char *str2, size_t n);

#endif

#if ZXIC_REAL("dma")
#define ZXIC_DMA_PHY_ADDR dma_addr_t
u32 zxic_comm_dma_mem_malloc(ZXIC_ADDR_T *vir_addr, ZXIC_ADDR_T *phy_addr, u32 dma_size);
u32 zxic_comm_dma_mem_free(ZXIC_ADDR_T vir_addr, ZXIC_ADDR_T phy_addr, u32 dma_size);
#endif

#if ZXIC_REAL("OTHER")
#define MIN_VAL(x, y) ((x) <= (y) ? (x) : (y))
#define MAX_VAL(x, y) ((x) <= (y) ? (y) : (x))
#define ZXIC_COMM_DM_TO_X(d, m) ((d) & ~(m))
#define ZXIC_COMM_DM_TO_Y(d, m) (~(d) & ~(m))
#define ZXIC_COMM_XY_TO_MASK(x, y) (~(x) & ~(y))
#define ZXIC_COMM_XY_TO_DATA(x, y) (x) /* valid only when mask is 0 */
#define ZXIC_RD_CNT_MAX (50)

#define ZXIC_COMM_WORD64_MASK (0xFFFFFFFFFFFFFFFFULL)
#define ZXIC_COMM_WORD32_MASK (0xFFFFFFFFU)
#define ZXIC_COMM_WORD16_MASK (0xFFFFU)
#define ZXIC_COMM_BYTE_MASK (0xFFU)

u32 ZXIC_COMM_GET_MASK_VALUE(u32 total, u32 masklen);
u32 zxic_comm_random(void);
void zxic_comm_channel_max_set(u32 dev_max);

//u32 zxic_comm_channel_max_get(void);

void zxic_comm_dbgcnt64_select_print(const char *name, u64 value, u32 prt_mode);

void zxic_comm_dbgcnt64_select_par_print(const char *name, u32 parm, u64 value, u32 prt_mode);

void zxic_comm_dbgcnt32_select_print(const char *name, u32 value, u32 prt_mode);

void zxic_comm_dbgcnt32_select_par_print(const char *name, u32 parm, u32 value, u32 prt_mode);

#define ZXIC_COMM_CHECK_ADD_CNT(x, y) \
	(((0xffffffff - (x)) < (y)) ? ((y) - (0xffffffff - (x)) - 1) : ((x) + (y)))
#define ZXIC_COMM_CHECK_ADD_CNT_WORD64(x, y) \
	(((0xffffffffffffffff - (x)) < (y)) ? ((y) - (0xffffffffffffffff - (x)) - 1) : ((x) + (y)))
#endif

#if ZXIC_REAL("UT_TEST")

void zxic_comm_ut_detail_info_trace(const char *format, ...);

void zxic_comm_ut_result_info_trace(const char *format, ...);

void zxic_comm_ut_detail_trace_error(const char *format, ...);

//void zxic_comm_ut_detail_trace_dev_error(u32 dev_id, const char *format, ...);

#endif

#if ZXIC_REAL("")
#include "zxic_comm_double_link.h"
#include "zxic_comm_doublelink_index.h"
#include "zxic_comm_liststack.h"
#include "zxic_comm_avl_tree.h"
#include "zxic_comm_rb_tree.h"
#include "zxic_comm_index_ctrl.h"
#include "zxic_comm_index_reserve.h"
#include "zxic_comm_index_fill.h"
#endif

#endif /* end __ZXIC_COMMON_H__ */
