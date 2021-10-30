// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#include "unf_event.h"
#include "unf_log.h"
#include "unf_common.h"
#include "unf_lport.h"

struct unf_event_list fc_event_list;
struct unf_global_event_queue global_event_queue;

/* Max global event node */
#define UNF_MAX_GLOBAL_ENENT_NODE 24

u32 unf_init_event_msg(struct unf_lport *lport)
{
	struct unf_event_mgr *event_mgr = NULL;
	struct unf_cm_event_report *event_node = NULL;
	u32 ret = RETURN_OK;
	u32 index = 0;
	ulong flag = 0;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	event_mgr = &lport->event_mgr;

	/* Get and Initial Event Node resource */
	event_mgr->mem_add = vmalloc((size_t)event_mgr->free_event_count *
				     sizeof(struct unf_cm_event_report));
	if (!event_mgr->mem_add) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
			     "[warn]Port(0x%x) allocate event manager failed",
			     lport->port_id);

		return UNF_RETURN_ERROR;
	}
	memset(event_mgr->mem_add, 0,
	       ((size_t)event_mgr->free_event_count * sizeof(struct unf_cm_event_report)));

	event_node = (struct unf_cm_event_report *)(event_mgr->mem_add);

	spin_lock_irqsave(&event_mgr->port_event_lock, flag);
	for (index = 0; index < event_mgr->free_event_count; index++) {
		INIT_LIST_HEAD(&event_node->list_entry);
		list_add_tail(&event_node->list_entry, &event_mgr->list_free_event);
		event_node++;
	}
	spin_unlock_irqrestore(&event_mgr->port_event_lock, flag);

	return ret;
}

static void unf_del_event_center_fun_op(struct unf_lport *lport)
{
	struct unf_event_mgr *event_mgr = NULL;

	FC_CHECK_RETURN_VOID(lport);

	event_mgr = &lport->event_mgr;
	event_mgr->unf_get_free_event_func = NULL;
	event_mgr->unf_release_event = NULL;
	event_mgr->unf_post_event_func = NULL;
}

void unf_init_event_node(struct unf_cm_event_report *event_node)
{
	FC_CHECK_RETURN_VOID(event_node);

	event_node->event = UNF_EVENT_TYPE_REQUIRE;
	event_node->event_asy_flag = UNF_EVENT_ASYN;
	event_node->delay_times = 0;
	event_node->para_in = NULL;
	event_node->para_out = NULL;
	event_node->result = 0;
	event_node->lport = NULL;
	event_node->unf_event_task = NULL;
}

struct unf_cm_event_report *unf_get_free_event_node(void *lport)
{
	struct unf_event_mgr *event_mgr = NULL;
	struct unf_cm_event_report *event_node = NULL;
	struct list_head *list_node = NULL;
	struct unf_lport *unf_lport = NULL;
	ulong flags = 0;

	FC_CHECK_RETURN_VALUE(lport, NULL);
	unf_lport = (struct unf_lport *)lport;
	unf_lport = unf_lport->root_lport;

	if (unlikely(atomic_read(&unf_lport->lport_no_operate_flag) == UNF_LPORT_NOP))
		return NULL;

	event_mgr = &unf_lport->event_mgr;

	spin_lock_irqsave(&event_mgr->port_event_lock, flags);
	if (list_empty(&event_mgr->list_free_event)) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
			     "[warn]Port(0x%x) have no event node anymore",
			     unf_lport->port_id);

		spin_unlock_irqrestore(&event_mgr->port_event_lock, flags);
		return NULL;
	}

	list_node = UNF_OS_LIST_NEXT(&event_mgr->list_free_event);
	list_del(list_node);
	event_mgr->free_event_count--;
	event_node = list_entry(list_node, struct unf_cm_event_report, list_entry);

	unf_init_event_node(event_node);
	spin_unlock_irqrestore(&event_mgr->port_event_lock, flags);

	return event_node;
}

void unf_post_event(void *lport, void *event_node)
{
	struct unf_cm_event_report *cm_event_node = NULL;
	struct unf_chip_manage_info *card_thread_info = NULL;
	struct unf_lport *unf_lport = NULL;
	ulong flags = 0;

	FC_CHECK_RETURN_VOID(event_node);
	cm_event_node = (struct unf_cm_event_report *)event_node;

	/* If null, post to global event center */
	if (!lport) {
		spin_lock_irqsave(&fc_event_list.fc_event_list_lock, flags);
		fc_event_list.list_num++;
		list_add_tail(&cm_event_node->list_entry, &fc_event_list.list_head);
		spin_unlock_irqrestore(&fc_event_list.fc_event_list_lock, flags);

		wake_up_process(event_task_thread);
	} else {
		unf_lport = (struct unf_lport *)lport;
		unf_lport = unf_lport->root_lport;
		card_thread_info = unf_lport->chip_info;

		/* Post to global event center */
		if (!card_thread_info) {
			FC_DRV_PRINT(UNF_LOG_EVENT, UNF_WARN,
				     "[warn]Port(0x%x) has strange event with type(0x%x)",
				     unf_lport->nport_id, cm_event_node->event);

			spin_lock_irqsave(&fc_event_list.fc_event_list_lock, flags);
			fc_event_list.list_num++;
			list_add_tail(&cm_event_node->list_entry, &fc_event_list.list_head);
			spin_unlock_irqrestore(&fc_event_list.fc_event_list_lock, flags);

			wake_up_process(event_task_thread);
		} else {
			spin_lock_irqsave(&card_thread_info->chip_event_list_lock, flags);
			card_thread_info->list_num++;
			list_add_tail(&cm_event_node->list_entry, &card_thread_info->list_head);
			spin_unlock_irqrestore(&card_thread_info->chip_event_list_lock, flags);

			wake_up_process(card_thread_info->thread);
		}
	}
}

void unf_check_event_mgr_status(struct unf_event_mgr *event_mgr)
{
	ulong flag = 0;

	FC_CHECK_RETURN_VOID(event_mgr);

	spin_lock_irqsave(&event_mgr->port_event_lock, flag);
	if (event_mgr->emg_completion && event_mgr->free_event_count == UNF_MAX_EVENT_NODE)
		complete(event_mgr->emg_completion);

	spin_unlock_irqrestore(&event_mgr->port_event_lock, flag);
}

void unf_release_event(void *lport, void *event_node)
{
	struct unf_event_mgr *event_mgr = NULL;
	struct unf_lport *unf_lport = NULL;
	struct unf_cm_event_report *cm_event_node = NULL;
	ulong flags = 0;

	FC_CHECK_RETURN_VOID(lport);
	FC_CHECK_RETURN_VOID(event_node);

	cm_event_node = (struct unf_cm_event_report *)event_node;
	unf_lport = (struct unf_lport *)lport;
	unf_lport = unf_lport->root_lport;
	event_mgr = &unf_lport->event_mgr;

	spin_lock_irqsave(&event_mgr->port_event_lock, flags);
	event_mgr->free_event_count++;
	unf_init_event_node(cm_event_node);
	list_add_tail(&cm_event_node->list_entry, &event_mgr->list_free_event);
	spin_unlock_irqrestore(&event_mgr->port_event_lock, flags);

	unf_check_event_mgr_status(event_mgr);
}

void unf_release_global_event(void *event_node)
{
	ulong flag = 0;
	struct unf_cm_event_report *cm_event_node = NULL;

	FC_CHECK_RETURN_VOID(event_node);
	cm_event_node = (struct unf_cm_event_report *)event_node;

	unf_init_event_node(cm_event_node);

	spin_lock_irqsave(&global_event_queue.global_event_list_lock, flag);
	global_event_queue.list_number++;
	list_add_tail(&cm_event_node->list_entry, &global_event_queue.global_event_list);
	spin_unlock_irqrestore(&global_event_queue.global_event_list_lock, flag);
}

u32 unf_init_event_center(void *lport)
{
	struct unf_event_mgr *event_mgr = NULL;
	u32 ret = RETURN_OK;
	struct unf_lport *unf_lport = NULL;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	unf_lport = (struct unf_lport *)lport;

	/* Initial Disc manager */
	event_mgr = &unf_lport->event_mgr;
	event_mgr->free_event_count = UNF_MAX_EVENT_NODE;
	event_mgr->unf_get_free_event_func = unf_get_free_event_node;
	event_mgr->unf_release_event = unf_release_event;
	event_mgr->unf_post_event_func = unf_post_event;

	INIT_LIST_HEAD(&event_mgr->list_free_event);
	spin_lock_init(&event_mgr->port_event_lock);
	event_mgr->emg_completion = NULL;

	ret = unf_init_event_msg(unf_lport);

	return ret;
}

void unf_wait_event_mgr_complete(struct unf_event_mgr *event_mgr)
{
	struct unf_event_mgr *event_mgr_temp = NULL;
	bool wait = false;
	ulong mg_flag = 0;

	struct completion fc_event_completion;

	init_completion(&fc_event_completion);
	FC_CHECK_RETURN_VOID(event_mgr);
	event_mgr_temp = event_mgr;

	spin_lock_irqsave(&event_mgr_temp->port_event_lock, mg_flag);
	if (event_mgr_temp->free_event_count != UNF_MAX_EVENT_NODE) {
		event_mgr_temp->emg_completion = &fc_event_completion;
		wait = true;
	}
	spin_unlock_irqrestore(&event_mgr_temp->port_event_lock, mg_flag);

	if (wait)
		wait_for_completion(event_mgr_temp->emg_completion);

	spin_lock_irqsave(&event_mgr_temp->port_event_lock, mg_flag);
	event_mgr_temp->emg_completion = NULL;
	spin_unlock_irqrestore(&event_mgr_temp->port_event_lock, mg_flag);
}

u32 unf_event_center_destroy(void *lport)
{
	struct unf_event_mgr *event_mgr = NULL;
	struct list_head *list = NULL;
	struct list_head *list_tmp = NULL;
	struct unf_cm_event_report *event_node = NULL;
	u32 ret = RETURN_OK;
	ulong flag = 0;
	ulong list_lock_flag = 0;
	struct unf_lport *unf_lport = NULL;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	unf_lport = (struct unf_lport *)lport;
	event_mgr = &unf_lport->event_mgr;

	spin_lock_irqsave(&fc_event_list.fc_event_list_lock, list_lock_flag);
	if (!list_empty(&fc_event_list.list_head)) {
		list_for_each_safe(list, list_tmp, &fc_event_list.list_head) {
			event_node = list_entry(list, struct unf_cm_event_report, list_entry);

			if (event_node->lport == unf_lport) {
				list_del_init(&event_node->list_entry);
				if (event_node->event_asy_flag == UNF_EVENT_SYN) {
					event_node->result = UNF_RETURN_ERROR;
					complete(&event_node->event_comp);
				}

				spin_lock_irqsave(&event_mgr->port_event_lock, flag);
				event_mgr->free_event_count++;
				list_add_tail(&event_node->list_entry,
					      &event_mgr->list_free_event);
				spin_unlock_irqrestore(&event_mgr->port_event_lock, flag);
			}
		}
	}
	spin_unlock_irqrestore(&fc_event_list.fc_event_list_lock, list_lock_flag);

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
		     "[info]Port(0x%x) begin to wait event",
		     unf_lport->port_id);

	unf_wait_event_mgr_complete(event_mgr);

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
		     "[info]Port(0x%x) wait event process end",
		     unf_lport->port_id);

	unf_del_event_center_fun_op(unf_lport);

	vfree(event_mgr->mem_add);
	event_mgr->mem_add = NULL;
	unf_lport->destroy_step = UNF_LPORT_DESTROY_STEP_3_DESTROY_EVENT_CENTER;

	return ret;
}

static void unf_procee_asyn_event(struct unf_cm_event_report *event_node)
{
	struct unf_lport *lport = NULL;
	u32 ret = UNF_RETURN_ERROR;

	lport = (struct unf_lport *)event_node->lport;

	FC_CHECK_RETURN_VOID(lport);
	if (event_node->unf_event_task) {
		ret = (u32)event_node->unf_event_task(event_node->para_in,
							  event_node->para_out);
	}

	if (lport->event_mgr.unf_release_event)
		lport->event_mgr.unf_release_event(lport, event_node);

	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_EVENT, UNF_WARN,
			     "[warn]Port(0x%x) handle event(0x%x) failed",
			     lport->port_id, event_node->event);
	}
}

void unf_handle_event(struct unf_cm_event_report *event_node)
{
	u32 ret = UNF_RETURN_ERROR;
	u32 event = 0;
	u32 event_asy_flag = UNF_EVENT_ASYN;

	FC_CHECK_RETURN_VOID(event_node);

	event = event_node->event;
	event_asy_flag = event_node->event_asy_flag;

	switch (event_asy_flag) {
	case UNF_EVENT_SYN: /* synchronous event node */
	case UNF_GLOBAL_EVENT_SYN:
		if (event_node->unf_event_task)
			ret = (u32)event_node->unf_event_task(event_node->para_in,
								  event_node->para_out);

		event_node->result = ret;
		complete(&event_node->event_comp);
		break;

	case UNF_EVENT_ASYN: /* asynchronous event node */
		unf_procee_asyn_event(event_node);
		break;

	case UNF_GLOBAL_EVENT_ASYN:
		if (event_node->unf_event_task) {
			ret = (u32)event_node->unf_event_task(event_node->para_in,
								  event_node->para_out);
		}

		unf_release_global_event(event_node);

		if (ret != RETURN_OK) {
			FC_DRV_PRINT(UNF_LOG_EVENT, UNF_WARN,
				     "[warn]handle global event(0x%x) failed", event);
		}
		break;

	default:
		FC_DRV_PRINT(UNF_LOG_EVENT, UNF_WARN,
			     "[warn]Unknown event(0x%x)", event);
		break;
	}
}

u32 unf_init_global_event_msg(void)
{
	struct unf_cm_event_report *event_node = NULL;
	u32 ret = RETURN_OK;
	u32 index = 0;
	ulong flag = 0;

	INIT_LIST_HEAD(&global_event_queue.global_event_list);
	spin_lock_init(&global_event_queue.global_event_list_lock);
	global_event_queue.list_number = 0;

	global_event_queue.global_event_add = vmalloc(UNF_MAX_GLOBAL_ENENT_NODE *
						      sizeof(struct unf_cm_event_report));
	if (!global_event_queue.global_event_add) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Can't allocate global event queue");

		return UNF_RETURN_ERROR;
	}
	memset(global_event_queue.global_event_add, 0,
	       (UNF_MAX_GLOBAL_ENENT_NODE * sizeof(struct unf_cm_event_report)));

	event_node = (struct unf_cm_event_report *)(global_event_queue.global_event_add);

	spin_lock_irqsave(&global_event_queue.global_event_list_lock, flag);
	for (index = 0; index < UNF_MAX_GLOBAL_ENENT_NODE; index++) {
		INIT_LIST_HEAD(&event_node->list_entry);
		list_add_tail(&event_node->list_entry, &global_event_queue.global_event_list);

		global_event_queue.list_number++;
		event_node++;
	}
	spin_unlock_irqrestore(&global_event_queue.global_event_list_lock, flag);

	return ret;
}

void unf_destroy_global_event_msg(void)
{
	if (global_event_queue.list_number != UNF_MAX_GLOBAL_ENENT_NODE) {
		FC_DRV_PRINT(UNF_LOG_EVENT, UNF_CRITICAL,
			     "[warn]Global event release not complete with remain nodes(0x%x)",
			     global_event_queue.list_number);
	}

	vfree(global_event_queue.global_event_add);
}

u32 unf_schedule_global_event(void *para_in, u32 event_asy_flag,
			      int (*unf_event_task)(void *arg_in, void *arg_out))
{
	struct list_head *list_node = NULL;
	struct unf_cm_event_report *event_node = NULL;
	ulong flag = 0;
	u32 ret = UNF_RETURN_ERROR;
	spinlock_t *event_list_lock = NULL;

	FC_CHECK_RETURN_VALUE(unf_event_task, UNF_RETURN_ERROR);

	if (event_asy_flag != UNF_GLOBAL_EVENT_ASYN && event_asy_flag != UNF_GLOBAL_EVENT_SYN) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
			     "[warn]Event async flag(0x%x) abnormity",
			     event_asy_flag);

		return UNF_RETURN_ERROR;
	}

	event_list_lock = &global_event_queue.global_event_list_lock;
	spin_lock_irqsave(event_list_lock, flag);
	if (list_empty(&global_event_queue.global_event_list)) {
		spin_unlock_irqrestore(event_list_lock, flag);

		return UNF_RETURN_ERROR;
	}

	list_node = UNF_OS_LIST_NEXT(&global_event_queue.global_event_list);
	list_del_init(list_node);
	global_event_queue.list_number--;
	event_node = list_entry(list_node, struct unf_cm_event_report, list_entry);
	spin_unlock_irqrestore(event_list_lock, flag);

	/* Initial global event */
	unf_init_event_node(event_node);
	init_completion(&event_node->event_comp);
	event_node->event_asy_flag = event_asy_flag;
	event_node->unf_event_task = unf_event_task;
	event_node->para_in = (void *)para_in;
	event_node->para_out = NULL;

	unf_post_event(NULL, event_node);

	if (event_asy_flag == UNF_GLOBAL_EVENT_SYN) {
		/* must wait for complete */
		wait_for_completion(&event_node->event_comp);
		ret = event_node->result;
		unf_release_global_event(event_node);
	} else {
		ret = RETURN_OK;
	}

	return ret;
}

struct unf_cm_event_report *unf_get_one_event_node(void *lport)
{
	struct unf_lport *unf_lport = (struct unf_lport *)lport;

	FC_CHECK_RETURN_VALUE(lport, NULL);
	FC_CHECK_RETURN_VALUE(unf_lport->event_mgr.unf_get_free_event_func, NULL);

	return unf_lport->event_mgr.unf_get_free_event_func((void *)unf_lport);
}

void unf_post_one_event_node(void *lport, struct unf_cm_event_report *event)
{
	struct unf_lport *unf_lport = (struct unf_lport *)lport;

	FC_CHECK_RETURN_VOID(lport);
	FC_CHECK_RETURN_VOID(event);

	FC_CHECK_RETURN_VOID(unf_lport->event_mgr.unf_post_event_func);
	FC_CHECK_RETURN_VOID(event);

	unf_lport->event_mgr.unf_post_event_func((void *)unf_lport, event);
}
