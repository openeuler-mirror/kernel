// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include "zxic_common.h"
#include "zxic_private.h"

#ifdef ZXIC_OS_WIN
#define ZXIC_MUTEX_WAITTIME_MAX (INFINITE)
#else
#define ZXIC_MUTEX_WAITTIME_MAX (5000)
#endif
u32 zxic_comm_mutex_create(struct zxic_mutex_t *p_mutex)
{
	// s32 rc = 0;

	ZXIC_COMM_CHECK_POINT(p_mutex);

#ifdef ZXIC_OS_WIN
	p_mutex->mutex = CreateMutex(ZXIC_NULL, ZXIC_FALSE, ZXIC_NULL);
	if (p_mutex->mutex == 0) {
		ZXIC_COMM_TRACE_ERROR("\nErrCode[ 0x%x ]: Create mutex failed.",
				      ZXIC_MUTEX_LOCK_INIT_FAIL);
		return ZXIC_MUTEX_LOCK_INIT_FAIL;
	}
#else
	mutex_init(&p_mutex->mutex);

#endif

	return ZXIC_OK;
}
u32 zxic_comm_mutex_lock(struct zxic_mutex_t *p_mutex)
{
	s32 rc = 0;
#ifndef ZXIC_FOR_FUZZER
	ZXIC_COMM_CHECK_POINT(p_mutex);

#ifdef ZXIC_OS_WIN
	switch (WaitForSingleObject(p_mutex->mutex, ZXIC_MUTEX_WAITTIME_MAX)) {
	case (WAIT_OBJECT_0): {
		/* wait mutex success. */
		break;
	}
	default: {
		ZXIC_COMM_TRACE_ERROR("\nErrCode[ 0x%x ]: WaitForSingleObject failed.",
				      ZXIC_MUTEX_LOCK_LOCK_FAIL);
		ZXIC_COMM_ASSERT(0);
		return ZXIC_MUTEX_LOCK_LOCK_FAIL;
	}
	}
#else
	mutex_lock(&p_mutex->mutex);
#endif
#endif

	return rc;
}
u32 zxic_comm_mutex_unlock(struct zxic_mutex_t *p_mutex)
{
	s32 rc = 0;
#ifndef ZXIC_FOR_FUZZER

	ZXIC_COMM_CHECK_POINT(p_mutex);

#ifdef ZXIC_OS_WIN
	if (!ReleaseMutex(p_mutex->mutex)) {
		ZXIC_COMM_TRACE_ERROR("\nErrCode[ 0x%x ]: ReleaseMutex failed.",
				      ZXIC_MUTEX_LOCK_ULOCK_FAIL);
		return ZXIC_MUTEX_LOCK_ULOCK_FAIL;
	}
#else
	mutex_unlock(&p_mutex->mutex);
#endif
#endif

	return rc;
}
u32 zxic_comm_mutex_destroy(struct zxic_mutex_t *p_mutex)
{
	// s32 rc = 0;

	ZXIC_COMM_CHECK_POINT(p_mutex);

#ifdef ZXIC_OS_WIN
	if (p_mutex->mutex == 0) {
		ZXIC_COMM_TRACE_ERROR("\nErrCode[ 0x%x ]: Destroy mutex failed.",
				      ZXIC_MUTEX_LOCK_DESTROY_FAIL);
		return ZXIC_MUTEX_LOCK_DESTROY_FAIL;
	}
	CloseHandle(p_mutex->mutex);
#else
	mutex_destroy(&p_mutex->mutex);
#endif

	return ZXIC_OK;
}
