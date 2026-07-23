/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _ZXIC_COMM_THREAD_H_
#define _ZXIC_COMM_THREAD_H_
#ifdef ZXIC_OS_LINUX
#include <linux/sched.h>
#include <linux/limits.h>
#endif

#define THREAD_NAME_MAX (64)
#define ZXIC_THREAD_TIME_INFINITE (0xFFFFFFFF) /* Infinite timeout */

typedef void *(*ZXIC_THREAD_FUNC)(void *);

/* Thread ID */
struct zxic_comm_thread_id_t {
#ifdef ZXIC_OS_WIN
	HANDLE id;
#else
	//pthread_t id;
	int id;
#endif
};

/* Thread CreateFlag */
#define ZXIC_THREAD_FLAG_DETACH (1 << 0)
#define ZXIC_THREAD_FLAG_EXPLICIT_SCHED (1 << 1)

struct zxic_comm_thread_info_t {
	char name[THREAD_NAME_MAX];
	u32 priority;
	u32 stack_size;
	u32 create_flag;
	struct zxic_comm_thread_id_t id;
	ZXIC_THREAD_FUNC thread_func;
	void *p_arg;
	u32 is_valid;
};

/* API */
u32 zxic_comm_thread_info_init(void);
u32 zxic_comm_thread_info_add(struct zxic_comm_thread_id_t *p_thread_id, const char *p_name,
			      u32 priority, u32 stack_size, u32 create_flag,
			      ZXIC_THREAD_FUNC p_thread_func, void *p_arg, u32 *p_info_index);
u32 zxic_comm_thread_info_del(struct zxic_comm_thread_id_t *p_thread_id);
u32 zxic_comm_thread_info_print(void);

u32 zxic_comm_thread_create(const char *p_name, u32 priority, u32 stack_size, u32 create_flag,
			    ZXIC_THREAD_FUNC thread_func, void *p_arg,
			    struct zxic_comm_thread_id_t *p_thread_id);

u32 zxic_comm_thread_exit(void);
u32 zxic_comm_thread_wait(struct zxic_comm_thread_id_t *p_thread_id, ulong wait_time);
u32 zxic_comm_thread_close_handle(struct zxic_comm_thread_id_t *p_thread_id);

#endif
