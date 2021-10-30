/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef UNF_EXCHG_H
#define UNF_EXCHG_H

#include "unf_type.h"
#include "unf_fcstruct.h"
#include "unf_lport.h"
#include "unf_scsi_common.h"

enum unf_ioflow_id {
	XCHG_ALLOC = 0,
	TGT_RECEIVE_ABTS,
	TGT_ABTS_DONE,
	TGT_IO_SRR,
	SFS_RESPONSE,
	SFS_TIMEOUT,
	INI_SEND_CMND,
	INI_RESPONSE_DONE,
	INI_EH_ABORT,
	INI_EH_DEVICE_RESET,
	INI_EH_BLS_DONE,
	INI_IO_TIMEOUT,
	INI_REQ_TIMEOUT,
	XCHG_CANCEL_TIMER,
	XCHG_FREE_XCHG,
	SEND_ELS,
	IO_XCHG_WAIT,
	XCHG_BUTT
};

enum unf_xchg_type {
	UNF_XCHG_TYPE_INI = 0, /* INI IO */
	UNF_XCHG_TYPE_SFS = 1,
	UNF_XCHG_TYPE_INVALID
};

enum unf_xchg_mgr_type {
	UNF_XCHG_MGR_TYPE_RANDOM = 0,
	UNF_XCHG_MGR_TYPE_FIXED = 1,
	UNF_XCHG_MGR_TYPE_INVALID
};

enum tgt_io_send_stage {
	TGT_IO_SEND_STAGE_NONE = 0,
	TGT_IO_SEND_STAGE_DOING = 1, /* xfer/rsp into queue */
	TGT_IO_SEND_STAGE_DONE = 2,  /* xfer/rsp into queue complete */
	TGT_IO_SEND_STAGE_ECHO = 3,  /* driver handled TSTS */
	TGT_IO_SEND_STAGE_INVALID
};

enum tgt_io_send_result {
	TGT_IO_SEND_RESULT_OK = 0,   /* xfer/rsp enqueue succeed */
	TGT_IO_SEND_RESULT_FAIL = 1, /* xfer/rsp enqueue fail */
	TGT_IO_SEND_RESULT_INVALID
};

struct unf_io_flow_id {
	char *stage;
};

#define unf_check_oxid_matched(ox_id, oid, xchg)                      \
	(((ox_id) == (xchg)->oxid) && ((oid) == (xchg)->oid) && \
	 (atomic_read(&(xchg)->ref_cnt) > 0))

#define UNF_CHECK_ALLOCTIME_VALID(lport, xchg_tag, exchg, pkg_alloc_time,      \
				  xchg_alloc_time)                             \
	do {                                                                   \
		if (unlikely(((pkg_alloc_time) != 0) &&                        \
			     ((pkg_alloc_time) != (xchg_alloc_time)))) {       \
			FC_DRV_PRINT(UNF_LOG_NORMAL, UNF_ERR,                  \
			    "Lport(0x%x_0x%x_0x%x_0x%p) AllocTime is not "     \
			    "equal,PKG "                                       \
			    "AllocTime:0x%x,Exhg AllocTime:0x%x",              \
			    (lport)->port_id, (lport)->nport_id, xchg_tag,     \
			    exchg, pkg_alloc_time, xchg_alloc_time);           \
			return UNF_RETURN_ERROR;                               \
		};                                                             \
		if (unlikely((pkg_alloc_time) == 0)) {                         \
			FC_DRV_PRINT(UNF_LOG_NORMAL, UNF_MAJOR,                \
			    "Lport(0x%x_0x%x_0x%x_0x%p) pkgtime err,PKG "      \
			    "AllocTime:0x%x,Exhg AllocTime:0x%x",              \
			    (lport)->port_id, (lport)->nport_id, xchg_tag,     \
			    exchg, pkg_alloc_time, xchg_alloc_time);           \
		};                                                             \
	} while (0)

#define UNF_SET_SCSI_CMND_RESULT(xchg, cmnd_result) \
	((xchg)->scsi_cmnd_info.result = (cmnd_result))

#define UNF_GET_GS_SFS_XCHG_TIMER(lport) (3 * (ulong)(lport)->ra_tov)

#define UNF_GET_BLS_SFS_XCHG_TIMER(lport) (2 * (ulong)(lport)->ra_tov)

#define UNF_GET_ELS_SFS_XCHG_TIMER(lport) (2 * (ulong)(lport)->ra_tov)

#define UNF_ELS_ECHO_RESULT_OK 0
#define UNF_ELS_ECHO_RESULT_FAIL 1

struct unf_xchg;
/* Xchg hot pool, busy IO lookup Xchg */
struct unf_xchg_hot_pool {
	/* Xchg sum, in hot pool */
	u16 total_xchges;
	bool wait_state;

	/* pool lock */
	spinlock_t xchg_hotpool_lock;

	/* Xchg posiontion list */
	struct list_head sfs_busylist;
	struct list_head ini_busylist;
	struct list_head list_destroy_xchg;

	/* Next free hot point */
	u16 slab_next_index;
	u16 slab_total_sum;
	u16 base;

	struct unf_lport *lport;

	struct unf_xchg *xchg_slab[ARRAY_INDEX_0];
};

/* Xchg's FREE POOL */
struct unf_xchg_free_pool {
	spinlock_t xchg_freepool_lock;

	u32 fcp_xchg_sum;

	/* IO used Xchg */
	struct list_head list_free_xchg_list;
	u32 total_fcp_xchg;

	/* SFS used Xchg */
	struct list_head list_sfs_xchg_list;
	u32 total_sfs_xchg;
	u32 sfs_xchg_sum;

	struct completion *xchg_mgr_completion;
};

struct unf_big_sfs {
	struct list_head entry_bigsfs;
	void *addr;
	u32 size;
};

struct unf_big_sfs_pool {
	void *big_sfs_pool;
	u32 free_count;
	struct list_head list_freepool;
	struct list_head list_busypool;
	spinlock_t big_sfs_pool_lock;
};

/* Xchg Manager for vport Xchg */
struct unf_xchg_mgr {
	/* MG  type */
	u32 mgr_type;

	/* MG entry */
	struct list_head xchg_mgr_entry;

	/* MG attribution */
	u32 mem_szie;

	/* MG alloced resource */
	void *fcp_mm_start;

	u32 sfs_mem_size;
	void *sfs_mm_start;
	dma_addr_t sfs_phy_addr;

	struct unf_xchg_free_pool free_pool;
	struct unf_xchg_hot_pool *hot_pool;

	struct unf_big_sfs_pool big_sfs_pool;

	struct buf_describe big_sfs_buf_list;
};

struct unf_seq {
	/* Seq ID */
	u8 seq_id;

	/* Seq Cnt */
	u16 seq_cnt;

	/* Seq state and len,maybe used for fcoe */
	u16 seq_stat;
	u32 rec_data_len;
};

union unf_xchg_fcp_sfs {
	struct unf_sfs_entry sfs_entry;
	struct unf_fcp_rsp_iu_entry fcp_rsp_entry;
};

#define UNF_IO_STATE_NEW 0
#define TGT_IO_STATE_SEND_XFERRDY (1 << 2) /* succeed to send XFer rdy */
#define TGT_IO_STATE_RSP (1 << 5)	   /* chip send rsp */
#define TGT_IO_STATE_ABORT (1 << 7)

#define INI_IO_STATE_UPTASK \
	(1 << 15) /* INI Upper-layer Task Management Commands */
#define INI_IO_STATE_UPABORT                                                  \
	(1 << 16)			/* INI Upper-layer timeout Abort flag \
					 */
#define INI_IO_STATE_DRABORT (1 << 17)	/* INI driver Abort flag */
#define INI_IO_STATE_DONE (1 << 18)	/* INI complete flag */
#define INI_IO_STATE_WAIT_RRQ (1 << 19) /* INI wait send rrq */
#define INI_IO_STATE_UPSEND_ERR (1 << 20) /* INI send fail flag */
/* INI only clear firmware resource flag */
#define INI_IO_STATE_ABORT_RESOURCE (1 << 21)
/* ioc abort:INI send ABTS ,5S timeout Semaphore,than set 1 */
#define INI_IO_STATE_ABORT_TIMEOUT (1 << 22)
#define INI_IO_STATE_RRQSEND_ERR (1 << 23) /* INI send RRQ fail flag */
#define INI_IO_STATE_LOGO (1 << 24)	   /* INI busy IO session logo status */
#define INI_IO_STATE_TMF_ABORT (1 << 25)   /* INI TMF ABORT IO flag */
#define INI_IO_STATE_REC_TIMEOUT_WAIT (1 << 26) /* INI REC TIMEOUT WAIT */
#define INI_IO_STATE_REC_TIMEOUT (1 << 27)	/* INI REC TIMEOUT */

#define TMF_RESPONSE_RECEIVED (1 << 0)
#define MARKER_STS_RECEIVED (1 << 1)
#define ABTS_RESPONSE_RECEIVED (1 << 2)

struct unf_scsi_cmd_info {
	ulong time_out;
	ulong abort_time_out;
	void *scsi_cmnd;
	void (*done)(struct unf_scsi_cmnd *scsi_cmd);
	ini_get_sgl_entry_buf unf_get_sgl_entry_buf;
	struct unf_ini_error_code *err_code_table; /* error code table */
	char *sense_buf;
	u32 err_code_table_cout; /* Size of the error code table */
	u32 buf_len;
	u32 entry_cnt;
	u32 result; /* Stores command execution results */
	u32 port_id;
/* Re-search for rport based on scsiid during retry. Otherwise,
 *data inconsistency will occur
 */
	u32 scsi_id;
	void *sgl;
	uplevel_cmd_done uplevel_done;
};

struct unf_req_sgl_info {
	void *sgl;
	void *sgl_start;
	u32 req_index;
	u32 entry_index;
};

struct unf_els_echo_info {
	u64 response_time;
	struct semaphore echo_sync_sema;
	u32 echo_result;
};

struct unf_xchg {
	/* Mg resource relative */
	/* list delete from HotPool */
	struct unf_xchg_hot_pool *hot_pool;

	/* attach to FreePool */
	struct unf_xchg_free_pool *free_pool;
	struct unf_xchg_mgr *xchg_mgr;
	struct unf_lport *lport;      /* Local LPort/VLPort */
	struct unf_rport *rport;      /* Rmote Port */
	struct unf_rport *disc_rport; /* Discover Rmote Port */
	struct list_head list_xchg_entry;
	struct list_head list_abort_xchg_entry;
	spinlock_t xchg_state_lock;

	/* Xchg reference */
	atomic_t ref_cnt;
	atomic_t esgl_cnt;
	bool debug_hook;
	/* Xchg attribution */
	u16 hotpooltag;
	u16 abort_oxid;
	u32 xchg_type;	/* LS,TGT CMND ,REQ,or SCSI Cmnd */
	u16 oxid;
	u16 rxid;
	u32 sid;
	u32 did;
	u32 oid;	 /* ID of the exchange initiator */
	u32 disc_portid; /* Send GNN_ID/GFF_ID NPortId */
	u8 seq_id;
	u8 byte_orders; /* Byte order */
	struct unf_seq seq;

	u32 cmnd_code;
	u32 world_id;
	/* Dif control */
	struct unf_dif_control_info dif_control;
	struct dif_info dif_info;
	/* IO status Abort,timer out */
	u32 io_state;  /* TGT_IO_STATE_E */
	u32 tmf_state; /* TMF STATE */
	u32 ucode_abts_state;
	u32 abts_state;

	/* IO Enqueuing */
	enum tgt_io_send_stage io_send_stage; /* tgt_io_send_stage */
	/* IO Enqueuing result, success or failure */
	enum tgt_io_send_result io_send_result; /* tgt_io_send_result */

	u8 io_send_abort; /* is or not send io abort */
	/*result of io abort cmd(succ:true; fail:false)*/
	u8 io_abort_result;
	/* for INI,Indicates the length of the data transmitted over the PCI
	 * link
	 */
	u32 data_len;
	/* ResidLen,greater than 0 UnderFlow or Less than Overflow */
	int resid_len;
	/* +++++++++++++++++IO  Special++++++++++++++++++++ */
	/* point to tgt cmnd/req/scsi cmnd */
	/* Fcp cmnd */
	struct unf_fcp_cmnd fcp_cmnd;

	struct unf_scsi_cmd_info scsi_cmnd_info;

	struct unf_req_sgl_info req_sgl_info;

	struct unf_req_sgl_info dif_sgl_info;

	u64 cmnd_sn;
	void *pinitiator;

	/* timestamp */
	u64 start_jif;
	u64 alloc_jif;

	u64 io_front_jif;

	u32 may_consume_res_cnt;
	u32 fast_consume_res_cnt;

	/* scsi req info */
	u32 data_direction;

	struct unf_big_sfs *big_sfs_buf;

	/* scsi cmnd sense_buffer pointer */
	union unf_xchg_fcp_sfs fcp_sfs_union;

	/* One exchange may use several External Sgls */
	struct list_head list_esgls;
	struct unf_els_echo_info echo_info;
	struct semaphore task_sema;

	/* for RRQ ,IO Xchg add to SFS Xchg */
	void *io_xchg;

	/* Xchg delay work */
	struct delayed_work timeout_work;

	void (*xfer_or_rsp_echo)(struct unf_xchg *xchg, u32 status);

	/* wait list XCHG send function */
	int (*scsi_or_tgt_cmnd_func)(struct unf_xchg *xchg);

	/* send result callback */
	void (*ob_callback)(struct unf_xchg *xchg);

	/* Response IO callback */
	void (*callback)(void *lport, void *rport, void *xchg);

	/* Xchg release function */
	void (*free_xchg)(struct unf_xchg *xchg);

	/* +++++++++++++++++low level  Special++++++++++++++++++++ */
	/* private data,provide for low level */
	u32 private_data[PKG_MAX_PRIVATE_DATA_SIZE];

	u64 rport_bind_jifs;

	/* sfs exchg ob callback status */
	u32 ob_callback_sts;
	u32 scsi_id;
	u32 qos_level;
	void *ls_rsp_addr;
	void *ls_req;
	u32 status;
	atomic_t delay_flag;
	void *upper_ct;
};

struct unf_esgl_page *
unf_get_and_add_one_free_esgl_page(struct unf_lport *lport,
				   struct unf_xchg *xchg);
void unf_release_xchg_mgr_temp(struct unf_lport *lport);
u32 unf_init_xchg_mgr_temp(struct unf_lport *lport);
u32 unf_alloc_xchg_resource(struct unf_lport *lport);
void unf_free_all_xchg_mgr(struct unf_lport *lport);
void unf_xchg_mgr_destroy(struct unf_lport *lport);
u32 unf_xchg_ref_inc(struct unf_xchg *xchg, enum unf_ioflow_id io_stage);
void unf_xchg_ref_dec(struct unf_xchg *xchg, enum unf_ioflow_id io_stage);
struct unf_xchg_mgr *unf_get_xchg_mgr_by_lport(struct unf_lport *lport,
					       u32 mgr_idx);
struct unf_xchg_hot_pool *unf_get_hot_pool_by_lport(struct unf_lport *lport,
						    u32 mgr_idx);
void unf_free_lport_ini_xchg(struct unf_xchg_mgr *xchg_mgr, bool done_ini_flag);
struct unf_xchg *unf_cm_lookup_xchg_by_cmnd_sn(void *lport, u64 command_sn,
					       u32 world_id, void *pinitiator);
void *unf_cm_lookup_xchg_by_id(void *lport, u16 ox_id, u32 oid);
void unf_cm_xchg_abort_by_lun(struct unf_lport *lport, struct unf_rport *rport,
			      u64 lun_id, void *tm_xchg,
			      bool abort_all_lun_flag);
void unf_cm_xchg_abort_by_session(struct unf_lport *lport,
				  struct unf_rport *rport);

void unf_cm_xchg_mgr_abort_io_by_id(struct unf_lport *lport,
				    struct unf_rport *rport, u32 sid, u32 did,
				    u32 extra_io_stat);
void unf_cm_xchg_mgr_abort_sfs_by_id(struct unf_lport *lport,
				     struct unf_rport *rport, u32 sid, u32 did);
void unf_cm_free_xchg(void *lport, void *xchg);
void *unf_cm_get_free_xchg(void *lport, u32 xchg_type);
void *unf_cm_lookup_xchg_by_tag(void *lport, u16 hot_pool_tag);
void unf_release_esgls(struct unf_xchg *xchg);
void unf_show_all_xchg(struct unf_lport *lport, struct unf_xchg_mgr *xchg_mgr);
void unf_destroy_dirty_xchg(struct unf_lport *lport, bool show_only);
void unf_wake_up_scsi_task_cmnd(struct unf_lport *lport);
void unf_set_hot_pool_wait_state(struct unf_lport *lport, bool wait_state);
void unf_free_lport_all_xchg(struct unf_lport *lport);
extern u32 unf_get_up_level_cmnd_errcode(struct unf_ini_error_code *err_table,
					 u32 err_table_count, u32 drv_err_code);
bool unf_busy_io_completed(struct unf_lport *lport);

#endif
