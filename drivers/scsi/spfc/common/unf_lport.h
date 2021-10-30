/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef UNF_LPORT_H
#define UNF_LPORT_H

#include "unf_type.h"
#include "unf_disc.h"
#include "unf_event.h"
#include "unf_common.h"

#define UNF_PORT_TYPE_FC 0
#define UNF_PORT_TYPE_DISC 1
#define UNF_FW_UPDATE_PATH_LEN_MAX 255
#define UNF_EXCHG_MGR_NUM (4)
#define UNF_ERR_CODE_PRINT_TIME 10  /* error code print times */
#define UNF_MAX_IO_TYPE_STAT_NUM 48 /* IO abnormal max counter */
#define UNF_MAX_IO_RETURN_VALUE 0x12
#define UNF_MAX_SCSI_CMD 0xFF
#define UNF_MAX_LPRT_SCSI_ID_MAP 2048

enum unf_scsi_error_handle_type {
	UNF_SCSI_ABORT_IO_TYPE = 0,
	UNF_SCSI_DEVICE_RESET_TYPE,
	UNF_SCSI_TARGET_RESET_TYPE,
	UNF_SCSI_BUS_RESET_TYPE,
	UNF_SCSI_HOST_RESET_TYPE,
	UNF_SCSI_VIRTUAL_RESET_TYPE,
	UNF_SCSI_ERROR_HANDLE_BUTT
};

enum unf_lport_destroy_step {
	UNF_LPORT_DESTROY_STEP_0_SET_REMOVING = 0,
	UNF_LPORT_DESTROY_STEP_1_REPORT_PORT_OUT,
	UNF_LPORT_DESTROY_STEP_2_CLOSE_ROUTE,
	UNF_LPORT_DESTROY_STEP_3_DESTROY_EVENT_CENTER,
	UNF_LPORT_DESTROY_STEP_4_DESTROY_EXCH_MGR,
	UNF_LPORT_DESTROY_STEP_5_DESTROY_ESGL_POOL,
	UNF_LPORT_DESTROY_STEP_6_DESTROY_DISC_MGR,
	UNF_LPORT_DESTROY_STEP_7_DESTROY_XCHG_MGR_TMP,
	UNF_LPORT_DESTROY_STEP_8_DESTROY_RPORT_MG_TMP,
	UNF_LPORT_DESTROY_STEP_9_DESTROY_LPORT_MG_TMP,
	UNF_LPORT_DESTROY_STEP_10_DESTROY_SCSI_TABLE,
	UNF_LPORT_DESTROY_STEP_11_UNREG_TGT_HOST,
	UNF_LPORT_DESTROY_STEP_12_UNREG_SCSI_HOST,
	UNF_LPORT_DESTROY_STEP_13_DESTROY_LW_INTERFACE,
	UNF_LPORT_DESTROY_STEP_BUTT
};

enum unf_lport_enhanced_feature {
	/* Enhance GFF feature connect even if fail to get GFF feature */
	UNF_LPORT_ENHANCED_FEATURE_ENHANCED_GFF = 0x0001,
	UNF_LPORT_ENHANCED_FEATURE_IO_TRANSFERLIST = 0x0002, /* Enhance IO balance */
	UNF_LPORT_ENHANCED_FEATURE_IO_CHECKPOINT = 0x0004, /* Enhance IO check */
	UNF_LPORT_ENHANCED_FEATURE_CLOSE_FW_ROUTE = 0x0008, /* Close FW ROUTE */
	/* lowest frequency read SFP information */
	UNF_LPORT_ENHANCED_FEATURE_READ_SFP_ONCE = 0x0010,
	UNF_LPORT_ENHANCED_FEATURE_BUTT
};

enum unf_lport_login_state {
	UNF_LPORT_ST_ONLINE = 0x2000, /* uninitialized */
	UNF_LPORT_ST_INITIAL,	      /* initialized and LinkDown */
	UNF_LPORT_ST_LINK_UP,	      /* initialized and Link UP */
	UNF_LPORT_ST_FLOGI_WAIT,      /* waiting for FLOGI completion */
	UNF_LPORT_ST_PLOGI_WAIT,      /* waiting for PLOGI completion */
	UNF_LPORT_ST_RNN_ID_WAIT,     /* waiting for RNN_ID completion */
	UNF_LPORT_ST_RSNN_NN_WAIT,    /* waiting for RSNN_NN completion */
	UNF_LPORT_ST_RSPN_ID_WAIT,    /* waiting for RSPN_ID completion */
	UNF_LPORT_ST_RPN_ID_WAIT,     /* waiting for RPN_ID completion */
	UNF_LPORT_ST_RFT_ID_WAIT,     /* waiting for RFT_ID completion */
	UNF_LPORT_ST_RFF_ID_WAIT,     /* waiting for RFF_ID completion */
	UNF_LPORT_ST_SCR_WAIT,	      /* waiting for SCR completion */
	UNF_LPORT_ST_READY,	      /* ready for use */
	UNF_LPORT_ST_LOGO,	      /* waiting for LOGO completion */
	UNF_LPORT_ST_RESET,	      /* being reset and will restart */
	UNF_LPORT_ST_OFFLINE,	      /* offline */
	UNF_LPORT_ST_BUTT
};

enum unf_lport_event {
	UNF_EVENT_LPORT_NORMAL_ENTER = 0x8000, /* next state enter */
	UNF_EVENT_LPORT_ONLINE = 0x8001,       /* LPort link up */
	UNF_EVENT_LPORT_LINK_UP = 0x8002,      /* LPort link up */
	UNF_EVENT_LPORT_LINK_DOWN = 0x8003,    /* LPort link down */
	UNF_EVENT_LPORT_OFFLINE = 0x8004,      /* lPort bing stopped */
	UNF_EVENT_LPORT_RESET = 0x8005,
	UNF_EVENT_LPORT_REMOTE_ACC = 0x8006,	 /* next state enter */
	UNF_EVENT_LPORT_REMOTE_RJT = 0x8007,	 /* rport reject */
	UNF_EVENT_LPORT_REMOTE_TIMEOUT = 0x8008, /* rport time out */
	UNF_EVENT_LPORT_READY = 0x8009,
	UNF_EVENT_LPORT_REMOTE_BUTT
};

struct unf_cm_disc_mg_template {
	/* start input:L_Port,return:ok/fail */
	u32 (*unf_disc_start)(void *lport);
	/* stop input: L_Port,return:ok/fail */
	u32 (*unf_disc_stop)(void *lport);

	/* Callback after disc complete[with event:ok/fail]. */
	void (*unf_disc_callback)(void *lport, u32 result);
};

struct unf_chip_manage_info {
	struct list_head list_chip_thread_entry;
	struct list_head list_head;
	spinlock_t chip_event_list_lock;
	struct task_struct *thread;
	u32 list_num;
	u32 slot_id;
	u8 chip_id;
	u8 rsv;
	u8 sfp_9545_fault;
	u8 sfp_power_fault;
	atomic_t ref_cnt;
	u32 thread_exit;
	struct unf_chip_info chip_info;
	atomic_t card_loop_test_flag;
	spinlock_t card_loop_back_state_lock;
	char update_path[UNF_FW_UPDATE_PATH_LEN_MAX];
};

enum unf_timer_type {
	UNF_TIMER_TYPE_TGT_IO,
	UNF_TIMER_TYPE_INI_IO,
	UNF_TIMER_TYPE_REQ_IO,
	UNF_TIMER_TYPE_TGT_RRQ,
	UNF_TIMER_TYPE_INI_RRQ,
	UNF_TIMER_TYPE_SFS,
	UNF_TIMER_TYPE_INI_ABTS
};

struct unf_cm_xchg_mgr_template {
	void *(*unf_xchg_get_free_and_init)(void *lport, u32 xchg_type);
	void *(*unf_look_up_xchg_by_id)(void *lport, u16 ox_id, u32 oid);
	void *(*unf_look_up_xchg_by_tag)(void *lport, u16 hot_pool_tag);
	void (*unf_xchg_release)(void *lport, void *xchg);
	void (*unf_xchg_mgr_io_xchg_abort)(void *lport, void *rport, u32 sid, u32 did,
					   u32 extra_io_state);
	void (*unf_xchg_mgr_sfs_xchg_abort)(void *lport, void *rport, u32 sid, u32 did);
	void (*unf_xchg_add_timer)(void *xchg, ulong time_ms, enum unf_timer_type time_type);
	void (*unf_xchg_cancel_timer)(void *xchg);
	void (*unf_xchg_abort_all_io)(void *lport, u32 xchg_type, bool clean);
	void *(*unf_look_up_xchg_by_cmnd_sn)(void *lport, u64 command_sn,
					     u32 world_id, void *pinitiator);
	void (*unf_xchg_abort_by_lun)(void *lport, void *rport, u64 lun_id, void *xchg,
				      bool abort_all_lun_flag);

	void (*unf_xchg_abort_by_session)(void *lport, void *rport);
};

struct unf_cm_lport_template {
	void *(*unf_look_up_vport_by_index)(void *lport, u16 vp_index);
	void *(*unf_look_up_vport_by_port_id)(void *lport, u32 port_id);
	void *(*unf_look_up_vport_by_wwpn)(void *lport, u64 wwpn);
	void *(*unf_look_up_vport_by_did)(void *lport, u32 did);
	void (*unf_vport_remove)(void *vport);
};

struct unf_lport_state_ma {
	enum unf_lport_login_state lport_state;
	enum unf_lport_login_state (*lport_state_ma)(enum unf_lport_login_state old_state,
						     enum unf_lport_event event);
};

struct unf_rport_pool {
	u32 rport_pool_count;
	void *rport_pool_add;
	struct list_head list_rports_pool;
	spinlock_t rport_free_pool_lock;
	/* for synchronous reuse RPort POOL completion */
	struct completion *rport_pool_completion;
	ulong *rpi_bitmap;
};

struct unf_vport_pool {
	u16 vport_pool_count;
	void *vport_pool_addr;
	struct list_head list_vport_pool;
	spinlock_t vport_pool_lock;
	struct completion *vport_pool_completion;
	u16 slab_next_index; /* Next free vport */
	u16 slab_total_sum; /* Total Vport num */
	struct unf_lport *vport_slab[ARRAY_INDEX_0];
};

struct unf_esgl_pool {
	u32 esgl_pool_count;
	void *esgl_pool_addr;
	struct list_head list_esgl_pool;
	spinlock_t esgl_pool_lock;
	struct buf_describe esgl_buff_list;
};

/* little endium */
struct unf_port_id_page {
	struct list_head list_node_rscn;
	u8 port_id_port;
	u8 port_id_area;
	u8 port_id_domain;
	u8 addr_format : 2;
	u8 event_qualifier : 4;
	u8 reserved : 2;
};

struct unf_rscn_mgr {
	spinlock_t rscn_id_list_lock;
	u32 free_rscn_count;
	struct list_head list_free_rscn_page;
	struct list_head list_using_rscn_page;
	void *rscn_pool_add;
	struct unf_port_id_page *(*unf_get_free_rscn_node)(void *rscn_mg);
	void (*unf_release_rscn_node)(void *rscn_mg, void *rscn_node);
};

struct unf_disc_rport_mg {
	void *disc_pool_add;
	struct list_head list_disc_rports_pool;
	struct list_head list_disc_rports_busy;
};

struct unf_disc_manage_info {
	struct list_head list_head;
	spinlock_t disc_event_list_lock;
	atomic_t disc_contrl_size;

	u32 thread_exit;
	struct task_struct *thread;
};

struct unf_disc {
	u32 retry_count;
	u32 max_retry_count;
	u32 disc_flag;

	struct completion *disc_completion;
	atomic_t disc_ref_cnt;

	struct list_head list_busy_rports;
	struct list_head list_delete_rports;
	struct list_head list_destroy_rports;

	spinlock_t rport_busy_pool_lock;

	struct unf_lport *lport;
	enum unf_disc_state states;
	struct delayed_work disc_work;

	/* Disc operation template */
	struct unf_cm_disc_mg_template disc_temp;

	/* UNF_INIT_DISC/UNF_RSCN_DISC */
	u32 disc_option;

	/* RSCN list */
	struct unf_rscn_mgr rscn_mgr;
	struct unf_disc_rport_mg disc_rport_mgr;
	struct unf_disc_manage_info disc_thread_info;

	u64 last_disc_jiff;
};

enum unf_service_item {
	UNF_SERVICE_ITEM_FLOGI = 0,
	UNF_SERVICE_ITEM_PLOGI,
	UNF_SERVICE_ITEM_PRLI,
	UNF_SERVICE_ITEM_RSCN,
	UNF_SERVICE_ITEM_ABTS,
	UNF_SERVICE_ITEM_PDISC,
	UNF_SERVICE_ITEM_ADISC,
	UNF_SERVICE_ITEM_LOGO,
	UNF_SERVICE_ITEM_SRR,
	UNF_SERVICE_ITEM_RRQ,
	UNF_SERVICE_ITEM_ECHO,
	UNF_SERVICE_BUTT
};

/* Link service counter */
struct unf_link_service_collect {
	u64 service_cnt[UNF_SERVICE_BUTT];
};

struct unf_pcie_error_count {
	u32 pcie_error_count[UNF_PCIE_BUTT];
};

#define INVALID_WWPN 0

enum unf_device_scsi_state {
	UNF_SCSI_ST_INIT = 0,
	UNF_SCSI_ST_OFFLINE,
	UNF_SCSI_ST_ONLINE,
	UNF_SCSI_ST_DEAD,
	UNF_SCSI_ST_BUTT
};

struct unf_wwpn_dfx_counter_info {
	atomic64_t io_done_cnt[UNF_MAX_IO_RETURN_VALUE];
	atomic64_t scsi_cmd_cnt[UNF_MAX_SCSI_CMD];
	atomic64_t target_busy;
	atomic64_t host_busy;
	atomic_t error_handle[UNF_SCSI_ERROR_HANDLE_BUTT];
	atomic_t error_handle_result[UNF_SCSI_ERROR_HANDLE_BUTT];
	atomic_t device_alloc;
	atomic_t device_destroy;
};

#define UNF_MAX_LUN_PER_TARGET 256
struct unf_wwpn_rport_info {
	u64 wwpn;
	struct unf_rport *rport; /* Rport which linkup */
	void *lport;		 /* Lport */
	u32 target_id;		 /* target_id distribute by scsi */
	u32 las_ten_scsi_state;
	atomic_t scsi_state;
	struct unf_wwpn_dfx_counter_info *dfx_counter;
	struct delayed_work loss_tmo_work;
	bool need_scan;
	struct list_head fc_lun_list;
	u8 *lun_qos_level;
};

struct unf_rport_scsi_id_image {
	spinlock_t scsi_image_table_lock;
	struct unf_wwpn_rport_info
	    *wwn_rport_info_table;
	u32 max_scsi_id;
};

enum unf_lport_dirty_flag {
	UNF_LPORT_DIRTY_FLAG_NONE = 0,
	UNF_LPORT_DIRTY_FLAG_XCHGMGR_DIRTY = 0x100,
	UNF_LPORT_DIRTY_FLAG_RPORT_POOL_DIRTY = 0x200,
	UNF_LPORT_DIRTY_FLAG_DISC_DIRTY = 0x400,
	UNF_LPORT_DIRTY_FLAG_BUTT
};

typedef struct unf_rport *(*unf_rport_set_qualifier)(struct unf_lport *lport,
							 struct unf_rport *rport_by_nport_id,
							 struct unf_rport *rport_by_wwpn,
							 u64 wwpn, u32 sid);

typedef u32 (*unf_tmf_status_recovery)(void *rport, void *xchg);

enum unf_start_work_state {
	UNF_START_WORK_STOP,
	UNF_START_WORK_BEGIN,
	UNF_START_WORK_COMPLETE
};

struct unf_qos_info {
	u64 wwpn;
	u32 nport_id;
	enum unf_rport_qos_level qos_level;
	struct list_head entry_qos_info;
};

struct unf_ini_private_info {
	u32 driver_type; /* Driver Type */
	void *lower;	 /* driver private pointer */
};

struct unf_product_host_info {
	void *tgt_host;
	struct Scsi_Host *host;
	struct unf_ini_private_info drv_private_info;
	struct Scsi_Host scsihost;
};

struct unf_lport {
	u32 port_type;		    /* Port Type, fc or fcoe */
	atomic_t port_ref_cnt; /* LPort reference counter */
	void *fc_port;		    /* hard adapter hba pointer */
	void *rport, *drport;	    /* Used for SCSI interface */
	void *vport;
	ulong system_io_bus_num;

	struct unf_product_host_info host_info; /* scsi host mg */
	struct unf_rport_scsi_id_image rport_scsi_table;
	bool port_removing;
	bool io_allowed;
	bool port_dirt_exchange;

	spinlock_t xchg_mgr_lock;
	struct list_head list_xchg_mgr_head;
	struct list_head list_drty_xchg_mgr_head;
	void *xchg_mgr[UNF_EXCHG_MGR_NUM];
	bool qos_cs_ctrl;
	bool priority;
	enum unf_rport_qos_level qos_level;
	spinlock_t qos_mgr_lock;
	struct list_head list_qos_head;
	struct list_head list_vports_head;	 /* Vport Mg */
	struct list_head list_intergrad_vports; /* Vport intergrad list */
	struct list_head list_destroy_vports; /* Vport destroy list */

	struct list_head entry_vport; /* VPort entry, hook in list_vports_head */

	struct list_head entry_lport;	  /* LPort entry */
	spinlock_t lport_state_lock; /* UL Port Lock */
	struct unf_disc disc;		/* Disc and rport Mg */
	struct unf_rport_pool rport_pool; /* rport pool,Vport share Lport pool */
	struct unf_esgl_pool esgl_pool; /* external sgl pool */
	u32 port_id;			/* Port Management ,0x11000 etc. */
	enum unf_lport_login_state states;
	u32 link_up;
	u32 speed;

	u64 node_name;
	u64 port_name;
	u64 fabric_node_name;
	u32 nport_id;
	u32 max_frame_size;
	u32 ed_tov;
	u32 ra_tov;
	u32 class_of_service;
	u32 options; /* ini or tgt */
	u32 retries;
	u32 max_retry_count;
	enum unf_act_topo act_topo;
	bool switch_state;	/* TRUE---->ON,false---->OFF */
	bool last_switch_state; /* TRUE---->ON,false---->OFF */
	bool bbscn_support;	/* TRUE---->ON,false---->OFF */

	enum unf_start_work_state start_work_state;
	struct unf_cm_xchg_mgr_template xchg_mgr_temp; /* Xchg Mg operation template */
	struct unf_cm_lport_template lport_mgr_temp; /* Xchg LPort operation template */
	struct unf_low_level_functioon_op low_level_func;
	struct unf_event_mgr event_mgr; /* Disc and rport Mg */
	struct delayed_work retry_work; /* poll work or delay work */

	struct workqueue_struct *link_event_wq;
	struct workqueue_struct *xchg_wq;
	atomic64_t io_stat[UNF_MAX_IO_TYPE_STAT_NUM];
	struct unf_err_code err_code_sum; /* Error code counter */
	struct unf_port_dynamic_info port_dynamic_info;
	struct unf_link_service_collect link_service_info;
	struct unf_pcie_error_count pcie_error_cnt;
	unf_rport_set_qualifier unf_qualify_rport; /* Qualify Rport */

	unf_tmf_status_recovery unf_tmf_abnormal_recovery;    /* tmf marker recovery */

	struct delayed_work route_timer_work; /* L_Port timer route */

	u16 vp_index; /* Vport Index, Lport:0 */
	u16 path_id;
	struct unf_vport_pool *vport_pool; /* Only for Lport */
	void *lport_mgr[UNF_MAX_LPRT_SCSI_ID_MAP];
	bool vport_remove_flags;

	void *root_lport; /* Point to physic Lport */

	struct completion *lport_free_completion; /* Free LPort Completion */

#define UNF_LPORT_NOP 1
#define UNF_LPORT_NORMAL 0

	atomic_t lport_no_operate_flag;

	bool loop_back_test_mode;
	bool switch_state_before_test_mode; /* TRUE---->ON,false---->OFF */
	u32 enhanced_features;		   /* Enhanced Features */

	u32 destroy_step;
	u32 dirty_flag;
	struct unf_chip_manage_info *chip_info;

	u8 unique_position;
	u8 sfp_power_fault_count;
	u8 sfp_9545_fault_count;
	u64 last_tx_fault_jif; /* SFP last tx fault jiffies */
	u32 target_cnt;
	/* Server card: UNF_FC_SERVER_BOARD_32_G(6) for 32G mode,
	 * UNF_FC_SERVER_BOARD_16_G(7) for 16G mode
	 */
	u32 card_type;
	atomic_t scsi_session_add_success;
	atomic_t scsi_session_add_failed;
	atomic_t scsi_session_del_success;
	atomic_t scsi_session_del_failed;
	atomic_t add_start_work_failed;
	atomic_t add_closing_work_failed;
	atomic_t device_alloc;
	atomic_t device_destroy;
	atomic_t session_loss_tmo;
	atomic_t alloc_scsi_id;
	atomic_t resume_scsi_id;
	atomic_t reuse_scsi_id;
	atomic64_t last_exchg_mgr_idx;
	atomic_t host_no;
	atomic64_t exchg_index;
	int scan_world_id;
	struct semaphore wmi_task_sema;
	bool ready_to_remove;
	u32 pcie_link_down_cnt;
	bool pcie_link_down;
	u8 fw_version[SPFC_VER_LEN];
	atomic_t link_lose_tmo;
	u32 max_ssq_num;
};

void unf_lport_state_ma(struct unf_lport *lport, enum unf_lport_event lport_event);
void unf_lport_error_recovery(struct unf_lport *lport);
void unf_set_lport_state(struct unf_lport *lport, enum unf_lport_login_state state);
void unf_init_port_parms(struct unf_lport *lport);
u32 unf_lport_enter_flogi(struct unf_lport *lport);
void unf_lport_enter_sns_plogi(struct unf_lport *lport);
u32 unf_init_disc_mgr(struct unf_lport *lport);
u32 unf_init_lport_route(struct unf_lport *lport);
void unf_destroy_lport_route(struct unf_lport *lport);
void unf_reset_lport_params(struct unf_lport *lport);
void unf_cm_mark_dirty_mem(struct unf_lport *lport, enum unf_lport_dirty_flag type);
struct unf_lport *unf_cm_lookup_vport_by_vp_index(struct unf_lport *lport, u16 vp_index);
struct unf_lport *unf_cm_lookup_vport_by_did(struct unf_lport *lport, u32 did);
struct unf_lport *unf_cm_lookup_vport_by_wwpn(struct unf_lport *lport, u64 wwpn);
void unf_cm_vport_remove(struct unf_lport *vport);

#endif
