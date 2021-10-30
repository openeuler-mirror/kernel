/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef SPFC_HW_WQE_H
#define SPFC_HW_WQE_H

#define FC_ICQ_EN
#define FC_SCSI_CMDIU_LEN 48
#define FC_NVME_CMDIU_LEN 96
#define FC_LS_GS_USERID_CNT_MAX 10
#define FC_SENSEDATA_USERID_CNT_MAX 2
#define FC_INVALID_MAGIC_NUM 0xFFFFFFFF
#define FC_INVALID_HOTPOOLTAG 0xFFFF

/* TASK TYPE: in order to compatible wiht EDA, please add new type before BUTT. */
enum spfc_task_type {
	SPFC_TASK_T_EMPTY = 0, /* SCQE TYPE: means task type not initialize */

	SPFC_TASK_T_IWRITE = 1, /* SQE  TYPE: ini send FCP Write Command */
	SPFC_TASK_T_IREAD = 2,	/* SQE  TYPE: ini send FCP Read Command */
	SPFC_TASK_T_IRESP = 3, /* SCQE TYPE: ini recv fcp rsp for IREAD/IWRITE/ITMF */
	SPFC_TASK_T_TCMND = 4, /* NA */
	SPFC_TASK_T_TREAD = 5, /* SQE  TYPE: tgt send FCP Read Command */
	SPFC_TASK_T_TWRITE = 6, /* SQE  TYPE: tgt send FCP Write Command (XFER_RDY) */
	SPFC_TASK_T_TRESP = 7, /* SQE  TYPE: tgt send fcp rsp of Read/Write */
	SPFC_TASK_T_TSTS = 8,  /* SCQE TYPE: tgt sts for TREAD/TWRITE/TRESP */
	SPFC_TASK_T_ABTS = 9,  /* SQE  TYPE: ini send abts request Command */
	SPFC_TASK_T_IELS = 10, /* NA */
	SPFC_TASK_T_ITMF = 11, /* SQE  TYPE: ini send tmf request Command */
	SPFC_TASK_T_CLEAN_UP = 12,	/* NA */
	SPFC_TASK_T_CLEAN_UP_ALL = 13,	/* NA */
	SPFC_TASK_T_UNSOLICITED = 14,	/* NA */
	SPFC_TASK_T_ERR_WARN = 15,	/* NA */
	SPFC_TASK_T_SESS_EN = 16,	/* CMDQ TYPE: enable session */
	SPFC_TASK_T_SESS_DIS = 17,	/* NA */
	SPFC_TASK_T_SESS_DEL = 18,	/* NA */
	SPFC_TASK_T_RQE_REPLENISH = 19, /* NA */

	SPFC_TASK_T_RCV_TCMND = 20,	/* SCQE TYPE: tgt recv fcp cmd */
	SPFC_TASK_T_RCV_ELS_CMD = 21,	/* SCQE TYPE: tgt recv els cmd */
	SPFC_TASK_T_RCV_ABTS_CMD = 22,	/* SCQE TYPE: tgt recv abts cmd */
	SPFC_TASK_T_RCV_IMMEDIATE = 23, /* SCQE TYPE: tgt recv immediate data */
	/* SQE  TYPE: send ESL rsp. PLOGI_ACC, PRLI_ACC will carry the parent
	 *context parameter indication.
	 */
	SPFC_TASK_T_ELS_RSP = 24,
	SPFC_TASK_T_ELS_RSP_STS = 25, /* SCQE TYPE: ELS rsp sts */
	SPFC_TASK_T_ABTS_RSP = 26,     /* CMDQ TYPE: tgt send abts rsp */
	SPFC_TASK_T_ABTS_RSP_STS = 27, /* SCQE TYPE: tgt abts rsp sts */

	SPFC_TASK_T_ABORT = 28,	    /* CMDQ TYPE: tgt send Abort Command */
	SPFC_TASK_T_ABORT_STS = 29, /* SCQE TYPE: Abort sts */

	SPFC_TASK_T_ELS = 30,	      /* SQE  TYPE: send ELS request Command */
	SPFC_TASK_T_RCV_ELS_RSP = 31, /* SCQE TYPE: recv ELS response */

	SPFC_TASK_T_GS = 32,	     /* SQE  TYPE: send GS request Command */
	SPFC_TASK_T_RCV_GS_RSP = 33, /* SCQE TYPE: recv GS response */

	SPFC_TASK_T_SESS_EN_STS = 34,  /* SCQE TYPE: enable session sts */
	SPFC_TASK_T_SESS_DIS_STS = 35, /* NA */
	SPFC_TASK_T_SESS_DEL_STS = 36, /* NA */

	SPFC_TASK_T_RCV_ABTS_RSP = 37, /* SCQE TYPE: ini recv abts rsp */

	SPFC_TASK_T_BUFFER_CLEAR = 38,	   /* CMDQ TYPE: Buffer Clear */
	SPFC_TASK_T_BUFFER_CLEAR_STS = 39, /* SCQE TYPE: Buffer Clear sts */
	SPFC_TASK_T_FLUSH_SQ = 40,	   /* CMDQ TYPE: flush sq */
	SPFC_TASK_T_FLUSH_SQ_STS = 41,	   /* SCQE TYPE: flush sq sts */

	SPFC_TASK_T_SESS_RESET = 42,	    /* SQE  TYPE: Reset session */
	SPFC_TASK_T_SESS_RESET_STS = 43,    /* SCQE TYPE: Reset session sts */
	SPFC_TASK_T_RQE_REPLENISH_STS = 44, /* NA */
	SPFC_TASK_T_DUMP_EXCH = 45,	    /* CMDQ TYPE: dump exch */
	SPFC_TASK_T_INIT_SRQC = 46,	    /* CMDQ TYPE: init SRQC */
	SPFC_TASK_T_CLEAR_SRQ = 47,	    /* CMDQ TYPE: clear SRQ */
	SPFC_TASK_T_CLEAR_SRQ_STS = 48,	    /* SCQE TYPE: clear SRQ sts */
	SPFC_TASK_T_INIT_SCQC = 49,	    /* CMDQ TYPE: init SCQC */
	SPFC_TASK_T_DEL_SCQC = 50,	    /* CMDQ TYPE: delete SCQC */
	SPFC_TASK_T_TMF_RESP = 51,	    /* SQE  TYPE: tgt send tmf rsp */
	SPFC_TASK_T_DEL_SRQC = 52,	    /* CMDQ TYPE: delete SRQC */
	SPFC_TASK_T_RCV_IMMI_CONTINUE = 53, /* SCQE TYPE: tgt recv continue immediate data */

	SPFC_TASK_T_ITMF_RESP = 54,	  /* SCQE TYPE: ini recv tmf rsp */
	SPFC_TASK_T_ITMF_MARKER_STS = 55, /* SCQE TYPE: tmf marker sts */
	SPFC_TASK_T_TACK = 56,
	SPFC_TASK_T_SEND_AEQERR = 57,
	SPFC_TASK_T_ABTS_MARKER_STS = 58,    /* SCQE TYPE: abts marker sts */
	SPFC_TASK_T_FLR_CLEAR_IO = 59,	     /* FLR clear io type */
	SPFC_TASK_T_CREATE_SSQ_CONTEXT = 60,
	SPFC_TASK_T_CLEAR_SSQ_CONTEXT = 61,
	SPFC_TASK_T_EXCH_ID_FREE = 62,
	SPFC_TASK_T_DIFX_RESULT_STS = 63,
	SPFC_TASK_T_EXCH_ID_FREE_ABORT = 64,
	SPFC_TASK_T_EXCH_ID_FREE_ABORT_STS = 65,
	SPFC_TASK_T_PARAM_CHECK_FAIL = 66,
	SPFC_TASK_T_TGT_UNKNOWN = 67,
	SPFC_TASK_T_NVME_LS = 70,	  /* SQE TYPE: Snd Ls Req */
	SPFC_TASK_T_RCV_NVME_LS_RSP = 71, /* SCQE TYPE: Rcv Ls Rsp */

	SPFC_TASK_T_NVME_LS_RSP = 72,	      /* SQE TYPE: Snd Ls Rsp */
	SPFC_TASK_T_RCV_NVME_LS_RSP_STS = 73, /* SCQE TYPE: Rcv Ls Rsp sts */

	SPFC_TASK_T_RCV_NVME_LS_CMD = 74, /* SCQE TYPE: Rcv ls cmd */

	SPFC_TASK_T_NVME_IREAD = 75,  /* SQE TYPE: Ini Snd Nvme Read Cmd */
	SPFC_TASK_T_NVME_IWRITE = 76, /* SQE TYPE: Ini Snd Nvme write Cmd */

	SPFC_TASK_T_NVME_TREAD = 77,  /* SQE TYPE: Tgt Snd Nvme Read Cmd */
	SPFC_TASK_T_NVME_TWRITE = 78, /* SQE TYPE: Tgt Snd Nvme write Cmd */

	SPFC_TASK_T_NVME_IRESP = 79, /* SCQE TYPE: Ini recv nvme rsp for NVMEIREAD/NVMEIWRITE */

	SPFC_TASK_T_INI_IO_ABORT = 80,	   /* SQE type: INI Abort Cmd */
	SPFC_TASK_T_INI_IO_ABORT_STS = 81, /* SCQE type: INI Abort sts */

	SPFC_TASK_T_INI_LS_ABORT = 82,	     /* SQE type: INI ls abort Cmd */
	SPFC_TASK_T_INI_LS_ABORT_STS = 83,   /* SCQE type: INI ls abort sts */
	SPFC_TASK_T_EXCHID_TIMEOUT_STS = 84, /* SCQE TYPE: EXCH_ID TIME OUT */
	SPFC_TASK_T_PARENT_ERR_STS = 85,     /* SCQE TYPE: PARENT ERR */

	SPFC_TASK_T_NOP = 86,
	SPFC_TASK_T_NOP_STS = 87,

	SPFC_TASK_T_DFX_INFO = 126,
	SPFC_TASK_T_BUTT
};

/* error code for error report */

enum spfc_err_code {
	FC_CQE_COMPLETED = 0,		 /* Successful */
	FC_SESS_HT_INSERT_FAIL = 1,	 /* Offload fail: hash insert fail */
	FC_SESS_HT_INSERT_DUPLICATE = 2, /* Offload fail: duplicate offload */
	FC_SESS_HT_BIT_SET_FAIL = 3, /* Offload fail: bloom filter set fail */
	FC_SESS_HT_DELETE_FAIL = 4, /* Offload fail: hash delete fail(duplicate delete) */
	FC_CQE_BUFFER_CLEAR_IO_COMPLETED = 5, /* IO done in buffer clear */
	FC_CQE_SESSION_ONLY_CLEAR_IO_COMPLETED =  6, /* IO done in session rst mode=1 */
	FC_CQE_SESSION_RST_CLEAR_IO_COMPLETED = 7, /* IO done in session rst mode=3 */
	FC_CQE_TMF_RSP_IO_COMPLETED = 8,    /* IO done in tgt tmf rsp */
	FC_CQE_TMF_IO_COMPLETED = 9,	    /* IO done in ini tmf */
	FC_CQE_DRV_ABORT_IO_COMPLETED = 10, /* IO done in tgt abort */
	/*
	 *IO done in fcp rsp process. Used for the sceanrio: 1.abort before cmd 2.
	 *send fcp rsp directly after recv cmd.
	 */
	FC_CQE_DRV_ABORT_IO_IN_RSP_COMPLETED = 11,
	/*
	 *IO done in fcp cmd process. Used for the sceanrio: 1.abort before cmd 2.child setup fail.
	 */
	FC_CQE_DRV_ABORT_IO_IN_CMD_COMPLETED = 12,
	FC_CQE_WQE_FLUSH_IO_COMPLETED = 13, /* IO done in FLUSH SQ */
	FC_ERROR_CODE_DATA_DIFX_FAILED = 14, /* fcp data format check: DIFX check error */
	/* fcp data format check: task_type is not read */
	FC_ERROR_CODE_DATA_TASK_TYPE_INCORRECT = 15,
	FC_ERROR_CODE_DATA_OOO_RO = 16, /* fcp data format check: data offset is not continuous */
	FC_ERROR_CODE_DATA_EXCEEDS_DATA2TRNS = 17, /* fcp data format check: data is over run */
	/* fcp rsp format check: payload is too short */
	FC_ERROR_CODE_FCP_RSP_INVALID_LENGTH_FIELD = 18,
	/* fcp rsp format check: fcp_conf need, but exch don't hold seq initiative */
	FC_ERROR_CODE_FCP_RSP_CONF_REQ_NOT_SUPPORTED_YET = 19,
	/* fcp rsp format check: fcp_conf is required, but it's the last seq */
	FC_ERROR_CODE_FCP_RSP_OPENED_SEQ = 20,
	/* xfer rdy format check: payload is too short */
	FC_ERROR_CODE_XFER_INVALID_PAYLOAD_SIZE = 21,
	/* xfer rdy format check: last data out havn't finished */
	FC_ERROR_CODE_XFER_PEND_XFER_SET = 22,
	/* xfer rdy format check: data offset is not continuous */
	FC_ERROR_CODE_XFER_OOO_RO = 23,
	FC_ERROR_CODE_XFER_NULL_BURST_LEN = 24, /* xfer rdy format check: burst len is 0 */
	FC_ERROR_CODE_REC_TIMER_EXPIRE = 25,   /* Timer expire: REC_TIMER */
	FC_ERROR_CODE_E_D_TIMER_EXPIRE = 26,   /* Timer expire: E_D_TIMER */
	FC_ERROR_CODE_ABORT_TIMER_EXPIRE = 27, /* Timer expire: Abort timer */
	FC_ERROR_CODE_ABORT_MAGIC_NUM_NOT_MATCH = 28, /* Abort IO magic number mismatch */
	FC_IMMI_CMDPKT_SETUP_FAIL = 29, /* RX immediate data cmd pkt child setup fail */
	FC_ERROR_CODE_DATA_SEQ_ID_NOT_EQUAL = 30, /* RX fcp data sequence id not equal */
	FC_ELS_GS_RSP_EXCH_CHECK_FAIL = 31,  /* ELS/GS exch info check fail */
	FC_CQE_ELS_GS_SRQE_GET_FAIL = 32,    /* ELS/GS process get SRQE fail */
	FC_CQE_DATA_DMA_REQ_FAIL = 33,	     /* SMF soli-childdma rsp error */
	FC_CQE_SESSION_CLOSED = 34,	     /* Session is closed */
	FC_SCQ_IS_FULL = 35,		     /* SCQ is full */
	FC_SRQ_IS_FULL = 36,		     /* SRQ is full */
	FC_ERROR_DUCHILDCTX_SETUP_FAIL = 37, /* dpchild ctx setup fail */
	FC_ERROR_INVALID_TXMFS = 38,	     /* invalid txmfs */
	FC_ERROR_OFFLOAD_LACKOF_SCQE_FAIL = 39, /* offload fail,lack of SCQE,through AEQ */
	FC_ERROR_INVALID_TASK_ID = 40, /* tx invlaid task id */
	FC_ERROR_INVALID_PKT_LEN = 41, /* tx els gs pakcet len check */
	FC_CQE_ELS_GS_REQ_CLR_IO_COMPLETED = 42, /* IO done in els gs tx */
	FC_CQE_ELS_RSP_CLR_IO_COMPLETED = 43,	 /* IO done in els rsp tx */
	FC_ERROR_CODE_RESID_UNDER_ERR = 44,	 /* FCP RSP RESID ERROR */
	FC_ERROR_EXCH_ID_FREE_ERR = 45,		 /* Abnormal free xid failed */
	FC_ALLOC_EXCH_ID_FAILED = 46, /* ucode alloc EXCH ID failed */
	FC_ERROR_DUPLICATE_IO_RECEIVED = 47, /* Duplicate tcmnd or tmf rsp received */
	FC_ERROR_RXID_MISCOMPARE = 48,
	FC_ERROR_FAILOVER_CLEAR_VALID_HOST = 49, /* Failover cleared valid host io */
	FC_ERROR_EXCH_ID_NOT_MATCH = 50,   /* SCQ TYPE: xid not match */
	FC_ERROR_ABORT_FAIL = 51,	   /* SCQ TYPE: abort fail */
	FC_ERROR_SHARD_TABLE_OP_FAIL = 52, /* SCQ TYPE: shard table OP fail */
	FC_ERROR_E0E1_FAIL = 53,
	FC_INSERT_EXCH_ID_HASH_FAILED = 54, /* ucode INSERT EXCH ID HASH failed */
	FC_ERROR_CODE_FCP_RSP_UPDMA_FAILED = 55, /* up dma req failed,while fcp rsp is rcving */
	FC_ERROR_CODE_SID_DID_NOT_MATCH = 56, /* sid or did not match */
	FC_ERROR_DATA_NOT_REL_OFF = 57,	      /* data not rel off */
	FC_ERROR_CODE_EXCH_ID_TIMEOUT = 58,   /* exch id timeout */
	FC_ERROR_PARENT_CHECK_FAIL = 59,
	FC_ERROR_RECV_REC_REJECT = 60, /* RECV REC RSP REJECT */
	FC_ERROR_RECV_SRR_REJECT = 61, /* RECV REC SRR REJECT */
	FC_ERROR_REC_NOT_FIND_EXID_INVALID = 62,
	FC_ERROR_RECV_REC_NO_ERR = 63,
	FC_ERROR_PARENT_CTX_ERR = 64
};

/* AEQ EVENT TYPE */
enum spfc_aeq_evt_type {
	/* SCQ and SRQ not enough, HOST will initiate a operation to associated SCQ/SRQ */
	FC_AEQ_EVENT_QUEUE_ERROR = 48,
	FC_AEQ_EVENT_WQE_FATAL_ERROR = 49, /* WQE MSN check error,HOST will reset port */
	FC_AEQ_EVENT_CTX_FATAL_ERROR = 50, /* serious chip error, HOST will reset chip */
	FC_AEQ_EVENT_OFFLOAD_ERROR = 51,
	FC_FC_AEQ_EVENT_TYPE_LAST
};

enum spfc_protocol_class {
	FC_PROTOCOL_CLASS_3 = 0x0,
	FC_PROTOCOL_CLASS_2 = 0x1,
	FC_PROTOCOL_CLASS_1 = 0x2,
	FC_PROTOCOL_CLASS_F = 0x3,
	FC_PROTOCOL_CLASS_OTHER = 0x4
};

enum spfc_aeq_evt_err_code {
	/* detail type of resource lack */
	FC_SCQ_IS_FULL_ERR = 0,
	FC_SRQ_IS_FULL_ERR,

	/* detail type of FC_AEQ_EVENT_WQE_FATAL_ERROR */
	FC_SQE_CHILD_SETUP_WQE_MSN_ERR = 2,
	FC_SQE_CHILD_SETUP_WQE_GPA_ERR,
	FC_CMDPKT_CHILD_SETUP_INVALID_WQE_ERR_1,
	FC_CMDPKT_CHILD_SETUP_INVALID_WQE_ERR_2,
	FC_CLEAEQ_WQE_ERR,
	FC_WQEFETCH_WQE_MSN_ERR,
	FC_WQEFETCH_QUINFO_ERR,

	/* detail type of FC_AEQ_EVENT_CTX_FATAL_ERROR */
	FC_SCQE_ERR_BIT_ERR = 9,
	FC_UPDMA_ADDR_REQ_SRQ_ERR,
	FC_SOLICHILDDMA_ADDR_REQ_ERR,
	FC_UNSOLICHILDDMA_ADDR_REQ_ERR,
	FC_SQE_CHILD_SETUP_QINFO_ERR_1,
	FC_SQE_CHILD_SETUP_QINFO_ERR_2,
	FC_CMDPKT_CHILD_SETUP_QINFO_ERR_1,
	FC_CMDPKT_CHILD_SETUP_QINFO_ERR_2,
	FC_CMDPKT_CHILD_SETUP_PMSN_ERR,
	FC_CLEAEQ_CTX_ERR,
	FC_WQEFETCH_CTX_ERR,
	FC_FLUSH_QPC_ERR_LQP,
	FC_FLUSH_QPC_ERR_SMF,
	FC_PREFETCH_QPC_ERR_PCM_MHIT_LQP,
	FC_PREFETCH_QPC_ERR_PCM_MHIT_FQG,
	FC_PREFETCH_QPC_ERR_PCM_ABM_FQG,
	FC_PREFETCH_QPC_ERR_MAP_FQG,
	FC_PREFETCH_QPC_ERR_MAP_LQP,
	FC_PREFETCH_QPC_ERR_SMF_RTN,
	FC_PREFETCH_QPC_ERR_CFG,
	FC_PREFETCH_QPC_ERR_FLSH_HIT,
	FC_PREFETCH_QPC_ERR_FLSH_ACT,
	FC_PREFETCH_QPC_ERR_ABM_W_RSC,
	FC_PREFETCH_QPC_ERR_RW_ABM,
	FC_PREFETCH_QPC_ERR_DEFAULT,
	FC_CHILDHASH_INSERT_SW_ERR,
	FC_CHILDHASH_LOOKUP_SW_ERR,
	FC_CHILDHASH_DEL_SW_ERR,
	FC_EXCH_ID_FREE_SW_ERR,
	FC_FLOWHASH_INSERT_SW_ERR,
	FC_FLOWHASH_LOOKUP_SW_ERR,
	FC_FLOWHASH_DEL_SW_ERR,
	FC_FLUSH_QPC_ERR_USED,
	FC_FLUSH_QPC_ERR_OUTER_LOCK,
	FC_SETUP_SESSION_ERR,

	FC_AEQ_EVT_ERR_CODE_BUTT

};

/* AEQ data structure */
struct spfc_aqe_data {
	union {
		struct {
			u32 conn_id : 16;
			u32 rsvd : 8;
			u32 evt_code : 8;
		} wd0;

		u32 data0;
	};

	union {
		struct {
			u32 xid : 20;
			u32 rsvd : 12;
		} wd1;

		u32 data1;
	};
};

/* Control Section: Common Header */
struct spfc_wqe_ctrl_ch {
	union {
		struct {
			u32 bdsl : 8;
			u32 drv_sl : 2;
			u32 rsvd0 : 4;
			u32 wf : 1;
			u32 cf : 1;
			u32 tsl : 5;
			u32 va : 1;
			u32 df : 1;
			u32 cr : 1;
			u32 dif_sl : 3;
			u32 csl : 2;
			u32 ctrl_sl : 2;
			u32 owner : 1;
		} wd0;

		u32 ctrl_ch_val;
	};
};

/* Control Section: Queue Specific Field */
struct spfc_wqe_ctrl_qsf {
	u32 wqe_sn : 16;
	u32 dump_wqe_sn : 16;
};

/* DIF info definition in WQE */
struct spfc_fc_dif_info {
	struct {
		u32 app_tag_ctrl : 3; /* DIF/DIX APP TAG Control */
		/* Bit 0: scenario of the reference tag verify mode.
		 *Bit 1: scenario of the reference tag insert/replace mode.
		 */
		u32 ref_tag_mode : 2;
		/* 0: fixed; 1: increasement; */
		u32 ref_tag_ctrl : 3; /* The DIF/DIX Reference tag control */
		u32 grd_agm_ini_ctrl : 3;
		u32 grd_agm_ctrl : 2; /* Bit 0: DIF/DIX guard verify algorithm control */
		/* Bit 1: DIF/DIX guard replace or insert algorithm control */
		u32 grd_ctrl : 3;	 /* The DIF/DIX Guard control */
		u32 dif_verify_type : 2; /* verify type */
		u32 difx_ref_esc : 1;	/* Check blocks whose reference tag contains 0xFFFF flag */
		u32 difx_app_esc : 1;/* Check blocks whose application tag contains 0xFFFF flag */
		u32 rsvd : 8;
		u32 sct_size : 1; /* Sector size, 1: 4K; 0: 512 */
		u32 smd_tp : 2;
		u32 difx_en : 1;
	} wd0;

	struct {
		u32 cmp_app_tag_msk : 16;
		u32 rsvd : 7;
		u32 lun_qos_en : 2;
		u32 vpid : 7;
	} wd1;

	u16 cmp_app_tag;
	u16 rep_app_tag;

	u32 cmp_ref_tag;
	u32 rep_ref_tag;
};

/* Task Section: TMF SQE for INI */
struct spfc_tmf_info {
	union {
		struct {
			u32 reset_exch_end : 16;
			u32 reset_exch_start : 16;
		} bs;
		u32 value;
	} w0;

	union {
		struct {
			u32 reset_did : 24;
			u32 reset_type : 2;
			u32 marker_sts : 1;
			u32 rsvd0 : 5;
		} bs;
		u32 value;
	} w1;

	union {
		struct {
			u32 reset_sid : 24;
			u32 rsvd0 : 8;
		} bs;
		u32 value;
	} w2;

	u8 reset_lun[8];
};

/* Task Section: CMND SQE for INI */
struct spfc_sqe_icmnd {
	u8 fcp_cmnd_iu[FC_SCSI_CMDIU_LEN];
	union {
		struct spfc_fc_dif_info dif_info;
		struct spfc_tmf_info tmf;
	} info;
};

/* Task Section: ABTS SQE */
struct spfc_sqe_abts {
	u32 fh_parm_abts;
	u32 hotpooltag;
	u32 release_timer;
};

struct spfc_keys {
	struct {
		u32 smac1 : 8;
		u32 smac0 : 8;
		u32 rsv : 16;
	} wd0;

	u8 smac[4];

	u8 dmac[6];
	u8 sid[3];
	u8 did[3];

	struct {
		u32 port_id : 3;
		u32 host_id : 2;
		u32 rsvd : 27;
	} wd5;
	u32 rsvd;
};

/* BDSL: Session Enable WQE.keys field only use 26 bytes room */
struct spfc_cmdqe_sess_en {
	struct {
		u32 rx_id : 16;
		u32 port_id : 8;
		u32 task_type : 8;
	} wd0;

	struct {
		u32 cid : 20;
		u32 rsvd1 : 12;
	} wd1;

	struct {
		u32 conn_id : 16;
		u32 scqn : 16;
	} wd2;

	struct {
		u32 xid_p : 20;
		u32 rsvd3 : 12;
	} wd3;

	u32 context_gpa_hi;
	u32 context_gpa_lo;
	struct spfc_keys keys;
	u32 context[64];
};

/* Control Section */
struct spfc_wqe_ctrl {
	struct spfc_wqe_ctrl_ch ch;
	struct spfc_wqe_ctrl_qsf qsf;
};

struct spfc_sqe_els_rsp {
	struct {
		u32 echo_flag : 16;
		u32 data_len : 16;
	} wd0;

	struct {
		u32 rsvd1 : 27;
		u32 offload_flag : 1;
		u32 lp_bflag : 1;
		u32 clr_io : 1;
		u32 para_update : 2;
	} wd1;

	struct {
		u32 seq_cnt : 1;
		u32 e_d_tov : 1;
		u32 rsvd2 : 6;
		u32 class_mode : 8; /* 0:class3, 1:class2*/
		u32 tx_mfs : 16;
	} wd2;

	u32 e_d_tov_timer_val;

	struct {
		u32 conf : 1;
		u32 rec : 1;
		u32 xfer_dis : 1;
		u32 immi_taskid_cnt : 13;
		u32 immi_taskid_start : 16;
	} wd4;

	u32 first_burst_len;

	struct {
		u32 reset_exch_end : 16;
		u32 reset_exch_start : 16;
	} wd6;

	struct {
		u32 scqn : 16;
		u32 hotpooltag : 16;
	} wd7;

	u32 magic_local;
	u32 magic_remote;
	u32 ts_rcv_echo_req;
	u32 sid;
	u32 did;
	u32 context_gpa_hi;
	u32 context_gpa_lo;
};

struct spfc_sqe_reset_session {
	struct {
		u32 reset_exch_end : 16;
		u32 reset_exch_start : 16;
	} wd0;

	struct {
		u32 reset_did : 24;
		u32 mode : 2;
		u32 rsvd : 6;
	} wd1;

	struct {
		u32 reset_sid : 24;
		u32 rsvd : 8;
	} wd2;

	struct {
		u32 scqn : 16;
		u32 rsvd : 16;
	} wd3;
};

struct spfc_sqe_nop_sq {
	struct {
		u32 scqn : 16;
		u32 rsvd : 16;
	} wd0;
	u32 magic_num;
};

struct spfc_sqe_t_els_gs {
	u16 echo_flag;
	u16 data_len;

	struct {
		u32 rsvd1 : 9;
		u32 offload_flag : 1;
		u32 origin_hottag : 16;
		u32 rec_flag : 1;
		u32 rec_support : 1;
		u32 lp_bflag : 1;
		u32 clr_io : 1;
		u32 para_update : 2;
	} wd4;

	struct {
		u32 seq_cnt : 1;
		u32 e_d_tov : 1;
		u32 rsvd2 : 14;
		u32 tx_mfs : 16;
	} wd5;

	u32 e_d_tov_timer_val;

	struct {
		u32 reset_exch_end : 16;
		u32 reset_exch_start : 16;
	} wd6;

	struct {
		u32 scqn : 16;
		u32 hotpooltag : 16; /* used for send ELS rsp */
	} wd7;

	u32 sid;
	u32 did;
	u32 context_gpa_hi;
	u32 context_gpa_lo;
	u32 origin_magicnum;
};

struct spfc_sqe_els_gs_elsrsp_comm {
	u16 rsvd;
	u16 data_len;
};

struct spfc_sqe_lpb_msg {
	struct {
		u32 reset_exch_end : 16;
		u32 reset_exch_start : 16;
	} w0;

	struct {
		u32 reset_did : 24;
		u32 reset_type : 2;
		u32 rsvd0 : 6;
	} w1;

	struct {
		u32 reset_sid : 24;
		u32 rsvd0 : 8;
	} w2;

	u16 tmf_exch_id;
	u16 rsvd1;

	u8 reset_lun[8];
};

/* SQE Task Section's Contents except Common Header */
union spfc_sqe_ts_cont {
	struct spfc_sqe_icmnd icmnd;
	struct spfc_sqe_abts abts;
	struct spfc_sqe_els_rsp els_rsp;
	struct spfc_sqe_t_els_gs t_els_gs;
	struct spfc_sqe_els_gs_elsrsp_comm els_gs_elsrsp_comm;
	struct spfc_sqe_reset_session reset_session;
	struct spfc_sqe_lpb_msg lpb_msg;
	struct spfc_sqe_nop_sq nop_sq;
	u32 value[17];
};

struct spfc_sqe_nvme_icmnd_part2 {
	u8 nvme_cmnd_iu_part2_data[FC_NVME_CMDIU_LEN - FC_SCSI_CMDIU_LEN];
};

union spfc_sqe_ts_ex {
	struct spfc_sqe_nvme_icmnd_part2 nvme_icmnd_part2;
	u32 value[12];
};

struct spfc_sqe_ts {
	/* SQE Task Section's Common Header */
	u32 local_xid : 16; /* local exch_id, icmnd/els send used for hotpooltag */
	u32 crc_inj : 1;
	u32 immi_std : 1;
	u32 cdb_type : 1; /* cdb_type = 0:CDB_LEN = 16B, cdb_type = 1:CDB_LEN = 32B */
	u32 rsvd : 5;	  /* used for loopback saving bdsl's num */
	u32 task_type : 8;

	struct {
		u16 conn_id;
		u16 remote_xid;
	} wd0;

	u32 xid : 20;
	u32 sqn : 12;
	u32 cid;
	u32 magic_num;
	union spfc_sqe_ts_cont cont;
};

struct spfc_constant_sge {
	u32 buf_addr_hi;
	u32 buf_addr_lo;
};

struct spfc_variable_sge {
	u32 buf_addr_hi;
	u32 buf_addr_lo;

	struct {
		u32 buf_len : 31;
		u32 r_flag : 1;
	} wd0;

	struct {
		u32 buf_addr_gpa : 16;
		u32 xid : 14;
		u32 extension_flag : 1;
		u32 last_flag : 1;
	} wd1;
};

#define FC_WQE_SIZE 256
/* SQE, should not be over 256B */
struct spfc_sqe {
	struct spfc_wqe_ctrl ctrl_sl;
	u32 sid;
	u32 did;
	u64 wqe_gpa; /* gpa shift 6 bit  to right*/
	u64 db_val;
	union spfc_sqe_ts_ex ts_ex;
	struct spfc_variable_sge esge[3];
	struct spfc_wqe_ctrl ectrl_sl;
	struct spfc_sqe_ts ts_sl;
	struct spfc_variable_sge sge[2];
};

struct spfc_rqe_ctrl {
	struct spfc_wqe_ctrl_ch ch;

	struct {
		u16 wqe_msn;
		u16 dump_wqe_msn;
	} wd0;
};

struct spfc_rqe_drv {
	struct {
		u32 rsvd0 : 16;
		u32 user_id : 16;
	} wd0;

	u32 rsvd1;
};

/* RQE,should not be over 32B */
struct spfc_rqe {
	struct spfc_rqe_ctrl ctrl_sl;
	u32 cqe_gpa_h;
	u32 cqe_gpa_l;
	struct spfc_constant_sge bds_sl;
	struct spfc_rqe_drv drv_sl;
};

struct spfc_cmdqe_abort {
	struct {
		u32 rx_id : 16;
		u32 rsvd0 : 8;
		u32 task_type : 8;
	} wd0;

	struct {
		u32 ox_id : 16;
		u32 rsvd1 : 12;
		u32 trsp_send : 1;
		u32 tcmd_send : 1;
		u32 immi : 1;
		u32 reply_sts : 1;
	} wd1;

	struct {
		u32 conn_id : 16;
		u32 scqn : 16;
	} wd2;

	struct {
		u32 xid : 20;
		u32 rsvd : 12;
	} wd3;

	struct {
		u32 cid : 20;
		u32 rsvd : 12;
	} wd4;
	struct {
		u32 hotpooltag : 16;
		u32 rsvd : 16;
	} wd5; /* v6 new define */
	/* abort time out. Used for abort and io cmd reach ucode in different path
	 * and io cmd will not arrive.
	 */
	u32 time_out;
	u32 magic_num;
};

struct spfc_cmdqe_abts_rsp {
	struct {
		u32 rx_id : 16;
		u32 rsvd0 : 8;
		u32 task_type : 8;
	} wd0;

	struct {
		u32 ox_id : 16;
		u32 rsvd1 : 4;
		u32 port_id : 4;
		u32 payload_len : 7;
		u32 rsp_type : 1;
	} wd1;

	struct {
		u32 conn_id : 16;
		u32 scqn : 16;
	} wd2;

	struct {
		u32 xid : 20;
		u32 rsvd : 12;
	} wd3;

	struct {
		u32 cid : 20;
		u32 rsvd : 12;
	} wd4;

	struct {
		u32 req_rx_id : 16;
		u32 hotpooltag : 16;
	} wd5;

	/* payload length is according to rsp_type:1DWORD or 3DWORD */
	u32 payload[3];
};

struct spfc_cmdqe_buffer_clear {
	struct {
		u32 rsvd1 : 16;
		u32 rsvd0 : 8;
		u32 wqe_type : 8;
	} wd0;

	struct {
		u32 rx_id_end : 16;
		u32 rx_id_start : 16;
	} wd1;

	u32 scqn;
	u32 wd3;
};

struct spfc_cmdqe_flush_sq {
	struct {
		u32 entry_count : 16;
		u32 rsvd : 8;
		u32 wqe_type : 8;
	} wd0;

	struct {
		u32 scqn : 16;
		u32 port_id : 4;
		u32 pos : 11;
		u32 last_wqe : 1;
	} wd1;

	struct {
		u32 rsvd : 4;
		u32 clr_pos : 12;
		u32 pkt_ptr : 16;
	} wd2;

	struct {
		u32 first_sq_xid : 24;
		u32 sqqid_start_per_session : 4;
		u32 sqcnt_per_session : 4;
	} wd3;
};

struct spfc_cmdqe_dump_exch {
	struct {
		u32 rsvd1 : 16;
		u32 rsvd0 : 8;
		u32 task_type : 8;
	} wd0;

	u16 oqid_wr;
	u16 oqid_rd;

	u32 host_id;
	u32 func_id;
	u32 cache_id;
	u32 exch_id;
};

struct spfc_cmdqe_creat_srqc {
	struct {
		u32 rsvd1 : 16;
		u32 rsvd0 : 8;
		u32 task_type : 8;
	} wd0;

	u32 srqc_gpa_h;
	u32 srqc_gpa_l;

	u32 srqc[16]; /* srqc_size=64B */
};

struct spfc_cmdqe_delete_srqc {
	struct {
		u32 rsvd1 : 16;
		u32 rsvd0 : 8;
		u32 task_type : 8;
	} wd0;

	u32 srqc_gpa_h;
	u32 srqc_gpa_l;
};

struct spfc_cmdqe_clr_srq {
	struct {
		u32 rsvd1 : 16;
		u32 rsvd0 : 8;
		u32 task_type : 8;
	} wd0;

	struct {
		u32 scqn : 16;
		u32 srq_type : 16;
	} wd1;

	u32 srqc_gpa_h;
	u32 srqc_gpa_l;
};

struct spfc_cmdqe_creat_scqc {
	struct {
		u32 rsvd1 : 16;
		u32 rsvd0 : 8;
		u32 task_type : 8;
	} wd0;

	struct {
		u32 scqn : 16;
		u32 rsvd2 : 16;
	} wd1;

	u32 scqc[16]; /* scqc_size=64B */
};

struct spfc_cmdqe_delete_scqc {
	struct {
		u32 rsvd1 : 16;
		u32 rsvd0 : 8;
		u32 task_type : 8;
	} wd0;

	struct {
		u32 scqn : 16;
		u32 rsvd2 : 16;
	} wd1;
};

struct spfc_cmdqe_creat_ssqc {
	struct {
		u32 rsvd1 : 4;
		u32 xid : 20;
		u32 task_type : 8;
	} wd0;

	struct {
		u32 scqn : 16;
		u32 rsvd2 : 16;
	} wd1;
	u32 context_gpa_hi;
	u32 context_gpa_lo;

	u32 ssqc[64]; /* ssqc_size=256B */
};

struct spfc_cmdqe_delete_ssqc {
	struct {
		u32 entry_count : 4;
		u32 xid : 20;
		u32 task_type : 8;
	} wd0;

	struct {
		u32 scqn : 16;
		u32 rsvd2 : 16;
	} wd1;
	u32 context_gpa_hi;
	u32 context_gpa_lo;
};

/* add xid free via cmdq */
struct spfc_cmdqe_exch_id_free {
	struct {
		u32 task_id : 16;
		u32 port_id : 8;
		u32 rsvd0 : 8;
	} wd0;

	u32 magic_num;

	struct {
		u32 scqn : 16;
		u32 hotpool_tag : 16;
	} wd2;
	struct {
		u32 rsvd1 : 31;
		u32 clear_abort_flag : 1;
	} wd3;
	u32 sid;
	u32 did;
	u32 type; /* ELS/ELS RSP/IO */
};

struct spfc_cmdqe_cmdqe_dfx {
	struct {
		u32 rsvd1 : 4;
		u32 xid : 20;
		u32 task_type : 8;
	} wd0;

	struct {
		u32 qid_crclen : 12;
		u32 cid : 20;
	} wd1;
	u32 context_gpa_hi;
	u32 context_gpa_lo;
	u32 dfx_type;

	u32 rsv[16];
};

struct spfc_sqe_t_rsp {
	struct {
		u32 rsvd1 : 16;
		u32 fcp_rsp_len : 8;
		u32 busy_rsp : 3;
		u32 immi : 1;
		u32 mode : 1;
		u32 conf : 1;
		u32 fill : 2;
	} wd0;

	u32 hotpooltag;

	union {
		struct {
			u32 addr_h;
			u32 addr_l;
		} gpa;

		struct {
			u32 data[23]; /* FCP_RESP payload buf, 92B rsvd */
		} buf;
	} payload;
};

struct spfc_sqe_tmf_t_rsp {
	struct {
		u32 scqn : 16;
		u32 fcp_rsp_len : 8;
		u32 pkt_nosnd_flag : 3; /* tmf rsp snd flag, 0:snd, 1: not snd,  Driver ignore */
		u32 reset_type : 2;
		u32 conf : 1;
		u32 fill : 2;
	} wd0;

	struct {
		u32 reset_exch_end : 16;
		u32 reset_exch_start : 16;
	} wd1;

	struct {
		u16 hotpooltag; /*tmf rsp hotpooltag, Driver ignore */
		u16 rsvd;
	} wd2;

	u8 lun[8];    /* Lun ID */
	u32 data[20]; /* FCP_RESP payload buf, 80B rsvd */
};

struct spfc_sqe_tresp_ts {
	/* SQE Task Section's Common Header */
	u16 local_xid;
	u8 rsvd0;
	u8 task_type;

	struct {
		u16 conn_id;
		u16 remote_xid;
	} wd0;

	u32 xid : 20;
	u32 sqn : 12;
	u32 cid;
	u32 magic_num;
	struct spfc_sqe_t_rsp t_rsp;
};

struct spfc_sqe_tmf_resp_ts {
	/* SQE Task Section's Common Header */
	u16 local_xid;
	u8 rsvd0;
	u8 task_type;

	struct {
		u16 conn_id;
		u16 remote_xid;
	} wd0;

	u32 xid : 20;
	u32 sqn : 12;
	u32 cid;
	u32 magic_num; /* magic num */
	struct spfc_sqe_tmf_t_rsp tmf_rsp;
};

/* SQE for fcp response, max TSL is 120B */
struct spfc_sqe_tresp {
	struct spfc_wqe_ctrl ctrl_sl;
	u64 taskrsvd;
	u64 wqe_gpa;
	u64 db_val;
	union spfc_sqe_ts_ex ts_ex;
	struct spfc_variable_sge esge[3];
	struct spfc_wqe_ctrl ectrl_sl;
	struct spfc_sqe_tresp_ts ts_sl;
};

/* SQE for tmf response, max TSL is 120B */
struct spfc_sqe_tmf_rsp {
	struct spfc_wqe_ctrl ctrl_sl;
	u64 taskrsvd;
	u64 wqe_gpa;
	u64 db_val;
	union spfc_sqe_ts_ex ts_ex;
	struct spfc_variable_sge esge[3];
	struct spfc_wqe_ctrl ectrl_sl;
	struct spfc_sqe_tmf_resp_ts ts_sl;
};

/* SCQE Common Header */
struct spfc_scqe_ch {
	struct {
		u32 task_type : 8;
		u32 sqn : 13;
		u32 cqe_remain_cnt : 3;
		u32 err_code : 7;
		u32 owner : 1;
	} wd0;
};

struct spfc_scqe_type {
	struct spfc_scqe_ch ch;

	u32 rsvd0;

	u16 conn_id;
	u16 rsvd4;

	u32 rsvd1[12];

	struct {
		u32 done : 1;
		u32 rsvd : 23;
		u32 dif_vry_rst : 8;
	} wd0;
};

struct spfc_scqe_sess_sts {
	struct spfc_scqe_ch ch;

	struct {
		u32 xid_qpn : 20;
		u32 rsvd1 : 12;
	} wd0;

	struct {
		u32 conn_id : 16;
		u32 rsvd3 : 16;
	} wd1;

	struct {
		u32 cid : 20;
		u32 rsvd2 : 12;
	} wd2;

	u64 rsvd3;
};

struct spfc_scqe_comm_rsp_sts {
	struct spfc_scqe_ch ch;

	struct {
		u32 rx_id : 16;
		u32 ox_id : 16;
	} wd0;

	struct {
		u32 conn_id : 16;
		u32 hotpooltag : 16; /* ucode return hotpooltag to drv */
	} wd1;

	u32 magic_num;
};

struct spfc_scqe_iresp {
	struct spfc_scqe_ch ch;

	struct {
		u32 rx_id : 16;
		u32 ox_id : 16;
	} wd0;

	struct {
		u32 conn_id : 16;
		u32 rsvd0 : 3;
		u32 user_id_num : 8;
		u32 dif_info : 5;
	} wd1;

	struct {
		u32 scsi_status : 8;
		u32 fcp_flag : 8;
		u32 hotpooltag : 16; /* ucode return hotpooltag to drv */
	} wd2;

	u32 fcp_resid;
	u32 fcp_sns_len;
	u32 fcp_rsp_len;
	u32 magic_num;
	u16 user_id[FC_SENSEDATA_USERID_CNT_MAX];
	u32 rsv1;
};

struct spfc_scqe_nvme_iresp {
	struct spfc_scqe_ch ch;

	struct {
		u32 rx_id : 16;
		u32 ox_id : 16;
	} wd0;

	struct {
		u32 conn_id : 16;
		u32 eresp_flag : 8;
		u32 user_id_num : 8;
	} wd1;

	struct {
		u32 scsi_status : 8;
		u32 fcp_flag : 8;
		u32 hotpooltag : 16; /* ucode return hotpooltag to drv */
	} wd2;
	u32 magic_num;
	u32 eresp[8];
};

#pragma pack(1)
struct spfc_dif_result {
	u8 vrd_rpt;
	u16 pad;
	u8 rcv_pi_vb;
	u32 rcv_pi_h;
	u32 rcv_pi_l;
	u16 vrf_agm_imm;
	u16 ri_agm_imm;
};

#pragma pack()

struct spfc_scqe_dif_result {
	struct spfc_scqe_ch ch;

	struct {
		u32 rx_id : 16;
		u32 ox_id : 16;
	} wd0;

	struct {
		u32 conn_id : 16;
		u32 rsvd0 : 11;
		u32 dif_info : 5;
	} wd1;

	struct {
		u32 scsi_status : 8;
		u32 fcp_flag : 8;
		u32 hotpooltag : 16; /* ucode return hotpooltag to drv */
	} wd2;

	u32 fcp_resid;
	u32 fcp_sns_len;
	u32 fcp_rsp_len;
	u32 magic_num;

	u32 rsv1[3];
	struct spfc_dif_result difinfo;
};

struct spfc_scqe_rcv_abts_rsp {
	struct spfc_scqe_ch ch;

	struct {
		u32 rx_id : 16;
		u32 ox_id : 16;
	} wd0;

	struct {
		u32 conn_id : 16;
		u32 hotpooltag : 16;
	} wd1;

	struct {
		u32 fh_rctrl : 8;
		u32 rsvd0 : 24;
	} wd2;

	struct {
		u32 did : 24;
		u32 rsvd1 : 8;
	} wd3;

	struct {
		u32 sid : 24;
		u32 rsvd2 : 8;
	} wd4;

	/* payload length is according to fh_rctrl:1DWORD or 3DWORD */
	u32 payload[3];
	u32 magic_num;
};

struct spfc_scqe_fcp_rsp_sts {
	struct spfc_scqe_ch ch;

	struct {
		u32 rx_id : 16;
		u32 ox_id : 16;
	} wd0;

	struct {
		u32 conn_id : 16;
		u32 rsvd0 : 10;
		u32 immi : 1;
		u32 dif_info : 5;
	} wd1;

	u32 magic_num;
	u32 hotpooltag;
	u32 xfer_rsp;
	u32 rsvd[5];

	u32 dif_tmp[4]; /* HW will overwrite it */
};

struct spfc_scqe_rcv_els_cmd {
	struct spfc_scqe_ch ch;

	struct {
		u32 did : 24;
		u32 class_mode : 8; /* 0:class3, 1:class2 */
	} wd0;

	struct {
		u32 sid : 24;
		u32 rsvd1 : 8;
	} wd1;

	struct {
		u32 rx_id : 16;
		u32 ox_id : 16;
	} wd2;

	struct {
		u32 user_id_num : 16;
		u32 data_len : 16;
	} wd3;
	/* User ID of SRQ SGE, used for drvier buffer release */
	u16 user_id[FC_LS_GS_USERID_CNT_MAX];
	u32 ts;
};

struct spfc_scqe_param_check_scq {
	struct spfc_scqe_ch ch;

	u8 rsvd0[3];
	u8 port_id;

	u16 scqn;
	u16 check_item;

	u16 exch_id_load;
	u16 exch_id;

	u16 historty_type;
	u16 entry_count;

	u32 xid;

	u32 gpa_h;
	u32 gpa_l;

	u32 magic_num;
	u32 hotpool_tag;

	u32 payload_len;
	u32 sub_err;

	u32 rsvd2[3];
};

struct spfc_scqe_rcv_abts_cmd {
	struct spfc_scqe_ch ch;

	struct {
		u32 did : 24;
		u32 rsvd0 : 8;
	} wd0;

	struct {
		u32 sid : 24;
		u32 rsvd1 : 8;
	} wd1;

	struct {
		u32 rx_id : 16;
		u32 ox_id : 16;
	} wd2;
};

struct spfc_scqe_rcv_els_gs_rsp {
	struct spfc_scqe_ch ch;

	struct {
		u32 rx_id : 16;
		u32 ox_id : 16;
	} wd1;

	struct {
		u32 conn_id : 16;
		u32 data_len : 16; /* ELS/GS RSP Payload length */
	} wd2;

	struct {
		u32 did : 24;
		u32 rsvd : 6;
		u32 echo_rsp : 1;
		u32 end_rsp : 1;
	} wd3;

	struct {
		u32 sid : 24;
		u32 user_id_num : 8;
	} wd4;

	struct {
		u32 rsvd : 16;
		u32 hotpooltag : 16;
	} wd5;

	u32 magic_num;
	u16 user_id[FC_LS_GS_USERID_CNT_MAX];
};

struct spfc_scqe_rcv_flush_sts {
	struct spfc_scqe_ch ch;

	struct {
		u32 rsvd0 : 4;
		u32 clr_pos : 12;
		u32 port_id : 8;
		u32 last_flush : 8;
	} wd0;
};

struct spfc_scqe_rcv_clear_buf_sts {
	struct spfc_scqe_ch ch;

	struct {
		u32 rsvd0 : 24;
		u32 port_id : 8;
	} wd0;
};

struct spfc_scqe_clr_srq_rsp {
	struct spfc_scqe_ch ch;

	struct {
		u32 srq_type : 16;
		u32 cur_wqe_msn : 16;
	} wd0;
};

struct spfc_scqe_itmf_marker_sts {
	struct spfc_scqe_ch ch;

	struct {
		u32 rx_id : 16;
		u32 ox_id : 16;
	} wd1;

	struct {
		u32 did : 24;
		u32 end_rsp : 8;
	} wd2;

	struct {
		u32 sid : 24;
		u32 rsvd1 : 8;
	} wd3;

	struct {
		u32 hotpooltag : 16;
		u32 rsvd : 16;
	} wd4;

	u32 magic_num;
};

struct spfc_scqe_abts_marker_sts {
	struct spfc_scqe_ch ch;

	struct {
		u32 rx_id : 16;
		u32 ox_id : 16;
	} wd1;

	struct {
		u32 did : 24;
		u32 end_rsp : 8;
	} wd2;

	struct {
		u32 sid : 24;
		u32 io_state : 8;
	} wd3;

	struct {
		u32 hotpooltag : 16;
		u32 rsvd : 16;
	} wd4;

	u32 magic_num;
};

struct spfc_scqe_ini_abort_sts {
	struct spfc_scqe_ch ch;

	struct {
		u32 rx_id : 16;
		u32 ox_id : 16;
	} wd1;

	struct {
		u32 did : 24;
		u32 rsvd : 8;
	} wd2;

	struct {
		u32 sid : 24;
		u32 io_state : 8;
	} wd3;

	struct {
		u32 hotpooltag : 16;
		u32 rsvd : 16;
	} wd4;

	u32 magic_num;
};

struct spfc_scqe_sq_nop_sts {
	struct spfc_scqe_ch ch;
	struct {
		u32 rsvd : 16;
		u32 sqn : 16;
	} wd0;
	struct {
		u32 rsvd : 16;
		u32 conn_id : 16;
	} wd1;
	u32 magic_num;
};

/* SCQE, should not be over 64B */
#define FC_SCQE_SIZE 64
union spfc_scqe {
	struct spfc_scqe_type common;
	struct spfc_scqe_sess_sts sess_sts; /* session enable/disable/delete sts */
	struct spfc_scqe_comm_rsp_sts comm_sts; /* aborts/abts_rsp/els rsp sts */
	struct spfc_scqe_rcv_clear_buf_sts clear_sts; /* clear buffer sts */
	struct spfc_scqe_rcv_flush_sts flush_sts;     /* flush sq sts */
	struct spfc_scqe_iresp iresp;
	struct spfc_scqe_rcv_abts_rsp rcv_abts_rsp; /* recv abts rsp */
	struct spfc_scqe_fcp_rsp_sts fcp_rsp_sts;   /* Read/Write/Rsp sts */
	struct spfc_scqe_rcv_els_cmd rcv_els_cmd;   /* recv els cmd */
	struct spfc_scqe_rcv_abts_cmd rcv_abts_cmd; /* recv abts cmd */
	struct spfc_scqe_rcv_els_gs_rsp rcv_els_gs_rsp; /* recv els/gs rsp */
	struct spfc_scqe_clr_srq_rsp clr_srq_sts;
	struct spfc_scqe_itmf_marker_sts itmf_marker_sts; /* tmf marker */
	struct spfc_scqe_abts_marker_sts abts_marker_sts; /* abts marker */
	struct spfc_scqe_dif_result dif_result;
	struct spfc_scqe_param_check_scq param_check_sts;
	struct spfc_scqe_nvme_iresp nvme_iresp;
	struct spfc_scqe_ini_abort_sts ini_abort_sts;
	struct spfc_scqe_sq_nop_sts sq_nop_sts;
};

struct spfc_cmdqe_type {
	struct {
		u32 rx_id : 16;
		u32 rsvd0 : 8;
		u32 task_type : 8;
	} wd0;
};

struct spfc_cmdqe_send_ack {
	struct {
		u32 rx_id : 16;
		u32 immi_stand : 1;
		u32 rsvd0 : 7;
		u32 task_type : 8;
	} wd0;

	u32 xid;
	u32 cid;
};

struct spfc_cmdqe_send_aeq_err {
	struct {
		u32 errorevent : 8;
		u32 errortype : 8;
		u32 portid : 8;
		u32 task_type : 8;
	} wd0;
};

/* CMDQE, variable length */
union spfc_cmdqe {
	struct spfc_cmdqe_type common;
	struct spfc_cmdqe_sess_en session_enable;
	struct spfc_cmdqe_abts_rsp snd_abts_rsp;
	struct spfc_cmdqe_abort snd_abort;
	struct spfc_cmdqe_buffer_clear buffer_clear;
	struct spfc_cmdqe_flush_sq flush_sq;
	struct spfc_cmdqe_dump_exch dump_exch;
	struct spfc_cmdqe_creat_srqc create_srqc;
	struct spfc_cmdqe_delete_srqc delete_srqc;
	struct spfc_cmdqe_clr_srq clear_srq;
	struct spfc_cmdqe_creat_scqc create_scqc;
	struct spfc_cmdqe_delete_scqc delete_scqc;
	struct spfc_cmdqe_send_ack send_ack;
	struct spfc_cmdqe_send_aeq_err send_aeqerr;
	struct spfc_cmdqe_creat_ssqc createssqc;
	struct spfc_cmdqe_delete_ssqc deletessqc;
	struct spfc_cmdqe_cmdqe_dfx dfx_info;
	struct spfc_cmdqe_exch_id_free xid_free;
};

#endif
