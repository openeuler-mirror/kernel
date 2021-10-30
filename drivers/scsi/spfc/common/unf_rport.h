/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef UNF_RPORT_H
#define UNF_RPORT_H

#include "unf_type.h"
#include "unf_common.h"
#include "unf_lport.h"

extern struct unf_rport_feature_pool *port_feature_pool;

#define UNF_MAX_SCSI_ID 2048
#define UNF_LOSE_TMO 30
#define UNF_RPORT_INVALID_INDEX 0xffff

/* RSCN compare DISC list with local RPort macro */
#define UNF_RPORT_NEED_PROCESS 0x1
#define UNF_RPORT_ONLY_IN_DISC_PROCESS 0x2
#define UNF_RPORT_ONLY_IN_LOCAL_PROCESS 0x3
#define UNF_RPORT_IN_DISC_AND_LOCAL_PROCESS 0x4
#define UNF_RPORT_NOT_NEED_PROCESS 0x5

#define UNF_ECHO_SEND_MAX_TIMES 1

/* csctrl level value */
#define UNF_CSCTRL_LOW 0x81
#define UNF_CSCTRL_MIDDLE 0x82
#define UNF_CSCTRL_HIGH 0x83
#define UNF_CSCTRL_INVALID 0x0

enum unf_rport_login_state {
	UNF_RPORT_ST_INIT = 0x1000, /* initialized */
	UNF_RPORT_ST_PLOGI_WAIT,    /* waiting for PLOGI completion */
	UNF_RPORT_ST_PRLI_WAIT,	    /* waiting for PRLI completion */
	UNF_RPORT_ST_READY,	    /* ready for use */
	UNF_RPORT_ST_LOGO,	    /* port logout sent */
	UNF_RPORT_ST_CLOSING,	    /* being closed */
	UNF_RPORT_ST_DELETE,	    /* port being deleted */
	UNF_RPORT_ST_BUTT
};

enum unf_rport_event {
	UNF_EVENT_RPORT_NORMAL_ENTER = 0x9000,
	UNF_EVENT_RPORT_ENTER_PLOGI = 0x9001,
	UNF_EVENT_RPORT_ENTER_PRLI = 0x9002,
	UNF_EVENT_RPORT_READY = 0x9003,
	UNF_EVENT_RPORT_LOGO = 0x9004,
	UNF_EVENT_RPORT_CLS_TIMEOUT = 0x9005,
	UNF_EVENT_RPORT_RECOVERY = 0x9006,
	UNF_EVENT_RPORT_RELOGIN = 0x9007,
	UNF_EVENT_RPORT_LINK_DOWN = 0x9008,
	UNF_EVENT_RPORT_BUTT
};

/* RPort local link state */
enum unf_port_state {
	UNF_PORT_STATE_LINKUP = 0x1001,
	UNF_PORT_STATE_LINKDOWN = 0x1002
};

enum unf_rport_reuse_flag {
	UNF_RPORT_REUSE_ONLY = 0x1001,
	UNF_RPORT_REUSE_INIT = 0x1002,
	UNF_RPORT_REUSE_RECOVER = 0x1003
};

struct unf_disc_rport {
	/* RPort entry */
	struct list_head entry_rport;

	u32 nport_id;  /* Remote port NPortID */
	u32 disc_done; /* 1:Disc done */
};

struct unf_rport_feature_pool {
	struct list_head list_busy_head;
	struct list_head list_free_head;
	void *port_feature_pool_addr;
	spinlock_t port_fea_pool_lock;
};

struct unf_rport_feature_recard {
	struct list_head entry_feature;
	u64 wwpn;
	u32 port_feature;
	u32 reserved;
};

struct unf_os_thread_private_data {
	struct list_head list;
	spinlock_t spin_lock;
	struct task_struct *thread;
	unsigned int in_process;
	unsigned int cpu_id;
	atomic_t user_count;
};

/* Remote Port struct */
struct unf_rport {
	u32 max_frame_size;
	u32 supported_classes;

	/* Dynamic Attributes */
	/* Remote Port loss timeout in seconds. */
	u32 dev_loss_tmo;

	u64 node_name;
	u64 port_name;
	u32 nport_id; /* Remote port NPortID */
	u32 local_nport_id;

	u32 roles;

	/* Remote port local INI state */
	enum unf_port_state lport_ini_state;
	enum unf_port_state last_lport_ini_state;

	/* Remote port local TGT state */
	enum unf_port_state lport_tgt_state;
	enum unf_port_state last_lport_tgt_state;

	/* Port Type,fc or fcoe */
	u32 port_type;

	/* RPort reference counter */
	atomic_t rport_ref_cnt;

	/* Pending IO count */
	atomic_t pending_io_cnt;

	/* RPort entry */
	struct list_head entry_rport;

	/* Port State,delay reclaim  when uiRpState == complete. */
	enum unf_rport_login_state rp_state;
	u32 disc_done; /* 1:Disc done */

	struct unf_lport *lport;
	void *rport;
	spinlock_t rport_state_lock;

	/* Port attribution */
	u32 ed_tov;
	u32 ra_tov;
	u32 options; /* ini or tgt */
	u32 last_report_link_up_options;
	u32 fcp_conf_needed;	 /* INI Rport send FCP CONF flag */
	u32 tape_support_needed; /* INI tape support flag */
	u32 retries;		 /* special req retry times */
	u32 logo_retries;	 /* logo error recovery retry times */
	u32 max_retries;	 /* special req retry times */
	u64 rport_alloc_jifs;	 /* Rport alloc jiffies */

	void *session;

	/* binding with SCSI */
	u32 scsi_id;

	/* disc list compare flag */
	u32 rscn_position;

	u32 rport_index;

	u32 sqn_base;
	enum unf_rport_qos_level qos_level;

	/* RPort timer,closing status */
	struct work_struct closing_work;

	/* RPort timer,rport linkup */
	struct work_struct start_work;

	/* RPort timer,recovery */
	struct delayed_work recovery_work;

	/* RPort timer,TGT mode,PRLI waiting */
	struct delayed_work open_work;

	struct semaphore task_sema;
	/* Callback after rport Ready/delete.[with state:ok/fail].Creat/free TGT session here */
	/* input : L_Port,R_Port,state:ready --creat session/delete--free session */
	void (*unf_rport_callback)(void *rport, void *lport, u32 result);

	struct unf_os_thread_private_data *data_thread;
};

#define UNF_IO_RESULT_CNT(scsi_table, scsi_id, io_result)                      \
	do {                                                                   \
		if (likely(((io_result) < UNF_MAX_IO_RETURN_VALUE) &&          \
			((scsi_id) < UNF_MAX_SCSI_ID) &&                       \
			((scsi_table)->wwn_rport_info_table) &&                \
			(((scsi_table)->wwn_rport_info_table[scsi_id].dfx_counter)))) {\
			atomic64_inc(&((scsi_table)->wwn_rport_info_table[scsi_id]   \
				.dfx_counter->io_done_cnt[(io_result)]));      \
		} else {                                                       \
			FC_DRV_PRINT(UNF_LOG_EQUIP_ATT, \
				     UNF_ERR,                                  \
				     "[err] io return value(0x%x) or "         \
				     "scsi id(0x%x) is invalid",               \
				     io_result, scsi_id);                      \
		}                                                              \
	} while (0)

#define UNF_SCSI_CMD_CNT(scsi_table, scsi_id, io_type)                         \
	do {                                                                   \
		if (likely(((io_type) < UNF_MAX_SCSI_CMD) &&                   \
			((scsi_id) < UNF_MAX_SCSI_ID) &&                       \
			((scsi_table)->wwn_rport_info_table) &&                \
			(((scsi_table)->wwn_rport_info_table[scsi_id].dfx_counter)))) {  \
			atomic64_inc(&(((scsi_table)->wwn_rport_info_table[scsi_id])    \
				.dfx_counter->scsi_cmd_cnt[io_type]));         \
		} else {                                                       \
			FC_DRV_PRINT(UNF_LOG_EQUIP_ATT, \
				     UNF_ERR,                                  \
				     "[err] scsi_cmd(0x%x) or scsi id(0x%x) "  \
				     "is invalid",                             \
				     io_type, scsi_id);                        \
		}                                                              \
	} while (0)

#define UNF_SCSI_ERROR_HANDLE_CNT(scsi_table, scsi_id, io_type)                \
	do {                                                                   \
		if (likely(((io_type) < UNF_SCSI_ERROR_HANDLE_BUTT) &&         \
			((scsi_id) < UNF_MAX_SCSI_ID) &&                       \
			((scsi_table)->wwn_rport_info_table) &&                \
			(((scsi_table)->wwn_rport_info_table[scsi_id]	\
				.dfx_counter)))) {			\
			atomic_inc(&((scsi_table)->wwn_rport_info_table[scsi_id] \
				.dfx_counter->error_handle[io_type]));         \
		} else {                                                       \
			FC_DRV_PRINT(UNF_LOG_EQUIP_ATT, \
				     UNF_ERR,                                  \
				     "[err] scsi_cmd(0x%x) or scsi id(0x%x) "  \
				     "is invalid",                             \
				     (io_type), (scsi_id));                    \
		}                                                              \
	} while (0)

#define UNF_SCSI_ERROR_HANDLE_RESULT_CNT(scsi_table, scsi_id, io_type)         \
	do {                                                                   \
		if (likely(((io_type) < UNF_SCSI_ERROR_HANDLE_BUTT) &&         \
			((scsi_id) < UNF_MAX_SCSI_ID) &&                       \
			((scsi_table)->wwn_rport_info_table) &&\
			(((scsi_table)->				       \
			wwn_rport_info_table[scsi_id].dfx_counter)))) {        \
			atomic_inc(&(                                   \
			    (scsi_table)                                       \
				->wwn_rport_info_table[scsi_id]                \
				.dfx_counter->error_handle_result[io_type]));  \
		} else {                                                       \
			FC_DRV_PRINT(UNF_LOG_EQUIP_ATT, \
				     UNF_ERR,                                  \
				     "[err] scsi_cmd(0x%x) or scsi id(0x%x) "  \
				     "is invalid",                             \
				     io_type, scsi_id);                        \
		}                                                              \
	} while (0)

void unf_rport_state_ma(struct unf_rport *rport, enum unf_rport_event event);
void unf_update_lport_state_by_linkup_event(struct unf_lport *lport,
					    struct unf_rport *rport,
					    u32 rport_att);

void unf_set_rport_state(struct unf_rport *rport, enum unf_rport_login_state states);
void unf_rport_enter_closing(struct unf_rport *rport);
u32 unf_release_rport_res(struct unf_lport *lport, struct unf_rport *rport);
u32 unf_initrport_mgr_temp(struct unf_lport *lport);
void unf_clean_linkdown_rport(struct unf_lport *lport);
void unf_rport_error_recovery(struct unf_rport *rport);
struct unf_rport *unf_get_rport_by_nport_id(struct unf_lport *lport, u32 nport_id);
struct unf_rport *unf_get_rport_by_wwn(struct unf_lport *lport, u64 wwpn);
void unf_rport_enter_logo(struct unf_lport *lport, struct unf_rport *rport);
u32 unf_rport_ref_inc(struct unf_rport *rport);
void unf_rport_ref_dec(struct unf_rport *rport);

struct unf_rport *unf_rport_set_qualifier_key_reuse(struct unf_lport *lport,
						    struct unf_rport *rport_by_nport_id,
						    struct unf_rport *rport_by_wwpn,
						    u64 wwpn, u32 sid);
void unf_rport_delay_login(struct unf_rport *rport);
struct unf_rport *unf_find_valid_rport(struct unf_lport *lport, u64 wwpn,
				       u32 sid);
void unf_rport_linkdown(struct unf_lport *lport, struct unf_rport *rport);
void unf_apply_for_session(struct unf_lport *lport, struct unf_rport *rport);
struct unf_rport *unf_get_safe_rport(struct unf_lport *lport,
				     struct unf_rport *rport,
				     enum unf_rport_reuse_flag reuse_flag,
				     u32 nport_id);
void *unf_rport_get_free_and_init(void *lport, u32 port_type, u32 nport_id);

void unf_set_device_state(struct unf_lport *lport, u32 scsi_id, int scsi_state);
u32 unf_get_scsi_id_by_wwpn(struct unf_lport *lport, u64 wwpn);
u32 unf_get_device_state(struct unf_lport *lport, u32 scsi_id);
u32 unf_free_scsi_id(struct unf_lport *lport, u32 scsi_id);
void unf_schedule_closing_work(struct unf_lport *lport, struct unf_rport *rport);
void unf_sesion_loss_timeout(struct work_struct *work);
u32 unf_get_port_feature(u64 wwpn);
void unf_update_port_feature(u64 wwpn, u32 port_feature);

#endif
