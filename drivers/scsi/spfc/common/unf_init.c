// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#include "unf_type.h"
#include "unf_log.h"
#include "unf_scsi_common.h"
#include "unf_event.h"
#include "unf_exchg.h"
#include "unf_portman.h"
#include "unf_rport.h"
#include "unf_service.h"
#include "unf_io.h"
#include "unf_io_abnormal.h"

#define UNF_PID 12
#define MY_PID UNF_PID

#define RPORT_FEATURE_POOL_SIZE 4096
struct task_struct *event_task_thread;
struct workqueue_struct *unf_wq;

atomic_t fc_mem_ref;

struct unf_global_card_thread card_thread_mgr;
u32 unf_dgb_level = UNF_MAJOR;
u32 log_print_level = UNF_INFO;
u32 log_limited_times = UNF_LOGIN_ATT_PRINT_TIMES;

static struct unf_esgl_page *unf_get_one_free_esgl_page
	(void *lport, struct unf_frame_pkg *pkg)
{
	struct unf_lport *unf_lport = NULL;
	struct unf_xchg *unf_xchg = NULL;

	FC_CHECK_RETURN_VALUE(lport, NULL);
	FC_CHECK_RETURN_VALUE(pkg, NULL);

	unf_lport = (struct unf_lport *)lport;
	unf_xchg = (struct unf_xchg *)pkg->xchg_contex;

	return unf_get_and_add_one_free_esgl_page(unf_lport, unf_xchg);
}

static int unf_get_cfg_parms(char *section_name, struct unf_cfg_item *cfg_itm,
			     u32 *cfg_value, u32 itemnum)
{
	/* Maximum length of a configuration item value, including the end
	 * character
	 */
#define UNF_MAX_ITEM_VALUE_LEN (256)

	u32 *unf_cfg_value = NULL;
	struct unf_cfg_item *unf_cfg_itm = NULL;
	u32 i = 0;

	unf_cfg_itm = cfg_itm;
	unf_cfg_value = cfg_value;

	for (i = 0; i < itemnum; i++) {
		if (!unf_cfg_itm || !unf_cfg_value) {
			FC_DRV_PRINT(UNF_LOG_REG_ATT,
				     UNF_ERR,
				     "[err]Config name or value is NULL");

			return UNF_RETURN_ERROR;
		}

		if (strcmp("End", unf_cfg_itm->puc_name) == 0x0)
			break;

		if (strcmp("fw_path", unf_cfg_itm->puc_name) == 0x0) {
			unf_cfg_itm++;
			unf_cfg_value += UNF_MAX_ITEM_VALUE_LEN / sizeof(u32);
			continue;
		}

		*unf_cfg_value = unf_cfg_itm->default_value;
		unf_cfg_itm++;
		unf_cfg_value++;
	}

	return RETURN_OK;
}

struct unf_cm_handle_op unf_cm_handle_ops = {
	.unf_alloc_local_port = unf_lport_create_and_init,
	.unf_release_local_port = unf_release_local_port,
	.unf_receive_ls_gs_pkg = unf_receive_ls_gs_pkg,
	.unf_receive_bls_pkg = unf_receive_bls_pkg,
	.unf_send_els_done = unf_send_els_done,
	.unf_receive_ini_response = unf_ini_scsi_completed,
	.unf_get_cfg_parms = unf_get_cfg_parms,
	.unf_receive_marker_status = unf_recv_tmf_marker_status,
	.unf_receive_abts_marker_status = unf_recv_abts_marker_status,

	.unf_process_fcp_cmnd = NULL,
	.unf_tgt_cmnd_xfer_or_rsp_echo = NULL,
	.unf_cm_get_sgl_entry = unf_ini_get_sgl_entry,
	.unf_cm_get_dif_sgl_entry = unf_ini_get_dif_sgl_entry,
	.unf_get_one_free_esgl_page = unf_get_one_free_esgl_page,
	.unf_fc_port_event = unf_fc_port_link_event,
};

u32 unf_get_cm_handle_ops(struct unf_cm_handle_op *cm_handle)
{
	FC_CHECK_RETURN_VALUE(cm_handle, UNF_RETURN_ERROR);

	memcpy(cm_handle, &unf_cm_handle_ops, sizeof(struct unf_cm_handle_op));

	return RETURN_OK;
}

static void unf_deinit_cm_handle_ops(void)
{
	memset(&unf_cm_handle_ops, 0, sizeof(struct unf_cm_handle_op));
}

int unf_event_process(void *worker_ptr)
{
	struct list_head *event_list = NULL;
	struct unf_cm_event_report *event_node = NULL;
	struct completion *create_done = (struct completion *)worker_ptr;
	ulong flags = 0;

	set_user_nice(current, UNF_OS_THRD_PRI_LOW);
	recalc_sigpending();

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_INFO,
		     "[event]Enter event thread");

	if (create_done)
		complete(create_done);

	do {
		spin_lock_irqsave(&fc_event_list.fc_event_list_lock, flags);
		if (list_empty(&fc_event_list.list_head)) {
			spin_unlock_irqrestore(&fc_event_list.fc_event_list_lock, flags);

			set_current_state(TASK_INTERRUPTIBLE);
			schedule_timeout((long)msecs_to_jiffies(UNF_S_TO_MS));
		} else {
			event_list = UNF_OS_LIST_NEXT(&fc_event_list.list_head);
			list_del_init(event_list);
			fc_event_list.list_num--;
			event_node = list_entry(event_list,
						struct unf_cm_event_report,
						list_entry);
			spin_unlock_irqrestore(&fc_event_list.fc_event_list_lock, flags);

			/* Process event node */
			unf_handle_event(event_node);
		}
	} while (!kthread_should_stop());

	FC_DRV_PRINT(UNF_LOG_EVENT, UNF_MAJOR,
		     "[event]Event thread exit");

	return RETURN_OK;
}

static int unf_creat_event_center(void)
{
	struct completion create_done;

	init_completion(&create_done);
	INIT_LIST_HEAD(&fc_event_list.list_head);
	fc_event_list.list_num = 0;
	spin_lock_init(&fc_event_list.fc_event_list_lock);

	event_task_thread = kthread_run(unf_event_process, &create_done, "spfc_event");
	if (IS_ERR(event_task_thread)) {
		complete_and_exit(&create_done, 0);

		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Create event thread failed(0x%p)",
			     event_task_thread);

		return UNF_RETURN_ERROR;
	}
	wait_for_completion(&create_done);
	return RETURN_OK;
}

static void unf_cm_event_thread_exit(void)
{
	if (event_task_thread)
		kthread_stop(event_task_thread);
}

static void unf_init_card_mgr_list(void)
{
	/* So far, do not care */
	INIT_LIST_HEAD(&card_thread_mgr.card_list_head);

	spin_lock_init(&card_thread_mgr.global_card_list_lock);

	card_thread_mgr.card_num = 0;
}

int unf_port_feature_pool_init(void)
{
	u32 index = 0;
	u32 rport_feature_pool_size = 0;
	struct unf_rport_feature_recard *rport_feature = NULL;
	unsigned long flags = 0;

	rport_feature_pool_size = sizeof(struct unf_rport_feature_pool);
	port_feature_pool = vmalloc(rport_feature_pool_size);
	if (!port_feature_pool) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]cannot allocate rport feature pool");

		return UNF_RETURN_ERROR;
	}
	memset(port_feature_pool, 0, rport_feature_pool_size);
	spin_lock_init(&port_feature_pool->port_fea_pool_lock);
	INIT_LIST_HEAD(&port_feature_pool->list_busy_head);
	INIT_LIST_HEAD(&port_feature_pool->list_free_head);

	port_feature_pool->port_feature_pool_addr =
	    vmalloc((size_t)(RPORT_FEATURE_POOL_SIZE * sizeof(struct unf_rport_feature_recard)));
	if (!port_feature_pool->port_feature_pool_addr) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]cannot allocate rport feature pool address");

		vfree(port_feature_pool);
		port_feature_pool = NULL;

		return UNF_RETURN_ERROR;
	}

	memset(port_feature_pool->port_feature_pool_addr, 0,
	       RPORT_FEATURE_POOL_SIZE * sizeof(struct unf_rport_feature_recard));
	rport_feature = (struct unf_rport_feature_recard *)
				   port_feature_pool->port_feature_pool_addr;

	spin_lock_irqsave(&port_feature_pool->port_fea_pool_lock, flags);
	for (index = 0; index < RPORT_FEATURE_POOL_SIZE; index++) {
		list_add_tail(&rport_feature->entry_feature, &port_feature_pool->list_free_head);
		rport_feature++;
	}
	spin_unlock_irqrestore(&port_feature_pool->port_fea_pool_lock, flags);

	return RETURN_OK;
}

void unf_free_port_feature_pool(void)
{
	if (port_feature_pool->port_feature_pool_addr) {
		vfree(port_feature_pool->port_feature_pool_addr);
		port_feature_pool->port_feature_pool_addr = NULL;
	}

	vfree(port_feature_pool);
	port_feature_pool = NULL;
}

int unf_common_init(void)
{
	int ret = RETURN_OK;

	unf_dgb_level = UNF_MAJOR;
	log_print_level = UNF_KEVENT;

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_KEVENT,
		     "UNF Driver Version:%s.", SPFC_DRV_VERSION);

	atomic_set(&fc_mem_ref, 0);
	ret = unf_port_feature_pool_init();
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Port Feature Pool init failed");
		return ret;
	}

	ret = (int)unf_register_ini_transport();
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]INI interface init failed");
		goto REG_INITRANSPORT_FAIL;
	}

	unf_port_mgmt_init();
	unf_init_card_mgr_list();
	ret = (int)unf_init_global_event_msg();
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Create global event center failed");
		goto CREAT_GLBEVENTMSG_FAIL;
	}

	ret = (int)unf_creat_event_center();
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Create event center (thread) failed");
		goto CREAT_EVENTCENTER_FAIL;
	}

	unf_wq = create_workqueue("unf_wq");
	if (!unf_wq) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Create work queue failed");
		goto CREAT_WORKQUEUE_FAIL;
	}

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
		     "[info]Init common layer succeed");
	return ret;
CREAT_WORKQUEUE_FAIL:
	unf_cm_event_thread_exit();
CREAT_EVENTCENTER_FAIL:
	unf_destroy_global_event_msg();
CREAT_GLBEVENTMSG_FAIL:
	unf_unregister_ini_transport();
REG_INITRANSPORT_FAIL:
	unf_free_port_feature_pool();
	return UNF_RETURN_ERROR;
}

static void unf_destroy_dirty_port(void)
{
	u32 ditry_port_num = 0;

	unf_show_dirty_port(false, &ditry_port_num);

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
		     "[info]Sys has %u dirty L_Port(s)", ditry_port_num);
}

void unf_common_exit(void)
{
	unf_free_port_feature_pool();

	unf_destroy_dirty_port();

	flush_workqueue(unf_wq);
	destroy_workqueue(unf_wq);
	unf_wq = NULL;

	unf_cm_event_thread_exit();

	unf_destroy_global_event_msg();

	unf_deinit_cm_handle_ops();

	unf_port_mgmt_deinit();

	unf_unregister_ini_transport();

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_KEVENT,
		     "[info]SPFC module remove succeed, memory reference count is %d",
		     atomic_read(&fc_mem_ref));
}
