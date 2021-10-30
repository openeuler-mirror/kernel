/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef UNF_EVENT_H
#define UNF_EVENT_H

#include "unf_type.h"

#define UNF_MAX_EVENT_NODE 256

enum unf_event_type {
	UNF_EVENT_TYPE_ALARM = 0, /* Alarm */
	UNF_EVENT_TYPE_REQUIRE,	  /* Require */
	UNF_EVENT_TYPE_RECOVERY,  /* Recovery */
	UNF_EVENT_TYPE_BUTT
};

struct unf_cm_event_report {
	/* event type */
	u32 event;

	/* ASY flag */
	u32 event_asy_flag;

	/* Delay times,must be async event */
	u32 delay_times;

	struct list_head list_entry;

	void *lport;

	/* parameter */
	void *para_in;
	void *para_out;
	u32 result;

	/* recovery strategy */
	int (*unf_event_task)(void *arg_in, void *arg_out);

	struct completion event_comp;
};

struct unf_event_mgr {
	spinlock_t port_event_lock;
	u32 free_event_count;

	struct list_head list_free_event;

	struct completion *emg_completion;

	void *mem_add;
	struct unf_cm_event_report *(*unf_get_free_event_func)(void *lport);
	void (*unf_release_event)(void *lport, void *event_node);
	void (*unf_post_event_func)(void *lport, void *event_node);
};

struct unf_global_event_queue {
	void *global_event_add;
	u32 list_number;
	struct list_head global_event_list;
	spinlock_t global_event_list_lock;
};

struct unf_event_list {
	struct list_head list_head;
	spinlock_t fc_event_list_lock;
	u32 list_num; /* list node number */
};

void unf_handle_event(struct unf_cm_event_report *event_node);
u32 unf_init_global_event_msg(void);
void unf_destroy_global_event_msg(void);
u32 unf_schedule_global_event(void *para_in, u32 event_asy_flag,
			      int (*unf_event_task)(void *arg_in, void *arg_out));
struct unf_cm_event_report *unf_get_one_event_node(void *lport);
void unf_post_one_event_node(void *lport, struct unf_cm_event_report *event);
u32 unf_event_center_destroy(void *lport);
u32 unf_init_event_center(void *lport);

extern struct task_struct *event_task_thread;
extern struct unf_global_event_queue global_event_queue;
extern struct unf_event_list fc_event_list;
#endif
