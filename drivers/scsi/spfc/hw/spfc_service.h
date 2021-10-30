/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef SPFC_SERVICE_H
#define SPFC_SERVICE_H

#include "unf_type.h"
#include "unf_common.h"
#include "unf_scsi_common.h"
#include "spfc_hba.h"

#define SPFC_HAVE_OFFLOAD (0)

/* FC txmfs */
#define SPFC_DEFAULT_TX_MAX_FREAM_SIZE (256)

#define SPFC_GET_NETWORK_PORT_ID(hba)                         \
	(((hba)->port_index > 1) ? ((hba)->port_index + 2) : (hba)->port_index)

#define SPFC_GET_PRLI_PAYLOAD_LEN \
	(UNF_PRLI_PAYLOAD_LEN - UNF_PRLI_SIRT_EXTRA_SIZE)
/* Start addr of the header/payloed of the cmnd buffer in the pkg */
#define SPFC_FC_HEAD_LEN (sizeof(struct unf_fc_head))
#define SPFC_PAYLOAD_OFFSET (sizeof(struct unf_fc_head))
#define SPFC_GET_CMND_PAYLOAD_ADDR(pkg) UNF_GET_FLOGI_PAYLOAD(pkg)
#define SPFC_GET_CMND_HEADER_ADDR(pkg) \
	((pkg)->unf_cmnd_pload_bl.buffer_ptr)
#define SPFC_GET_RSP_HEADER_ADDR(pkg) \
	((pkg)->unf_rsp_pload_bl.buffer_ptr)
#define SPFC_GET_RSP_PAYLOAD_ADDR(pkg) \
	((pkg)->unf_rsp_pload_bl.buffer_ptr + SPFC_PAYLOAD_OFFSET)
#define SPFC_GET_CMND_FC_HEADER(pkg) \
	(&(UNF_GET_SFS_ENTRY(pkg)->sfs_common.frame_head))
#define SPFC_PKG_IS_ELS_RSP(cmd_type) \
	(((cmd_type) == ELS_ACC) || ((cmd_type) == ELS_RJT))
#define SPFC_XID_IS_VALID(exid, base, exi_count) \
	(((exid) >= (base)) && ((exid) < ((base) + (exi_count))))
#define SPFC_CHECK_NEED_OFFLOAD(cmd_code, cmd_type, offload_state)   \
	(((cmd_code) == ELS_PLOGI) && ((cmd_type) != ELS_RJT) && \
	 ((offload_state) == SPFC_QUEUE_STATE_INITIALIZED))

#define UNF_FC_PAYLOAD_ELS_MASK (0xFF000000)
#define UNF_FC_PAYLOAD_ELS_SHIFT (24)
#define UNF_FC_PAYLOAD_ELS_DWORD (0)

/* Note: this pfcpayload is little endian */
#define UNF_GET_FC_PAYLOAD_ELS_CMND(pfcpayload)                      \
	UNF_GET_SHIFTMASK(((u32 *)(void *)(pfcpayload))[UNF_FC_PAYLOAD_ELS_DWORD], \
	    UNF_FC_PAYLOAD_ELS_SHIFT, UNF_FC_PAYLOAD_ELS_MASK)

/* Note: this pfcpayload is big endian */
#define SPFC_GET_FC_PAYLOAD_ELS_CMND(pfcpayload)                          \
	UNF_GET_SHIFTMASK(be32_to_cpu(((u32 *)(void *)(pfcpayload))[UNF_FC_PAYLOAD_ELS_DWORD]), \
	    UNF_FC_PAYLOAD_ELS_SHIFT, UNF_FC_PAYLOAD_ELS_MASK)

#define UNF_FC_PAYLOAD_RX_SZ_MASK (0x00000FFF)
#define UNF_FC_PAYLOAD_RX_SZ_SHIFT (16)
#define UNF_FC_PAYLOAD_RX_SZ_DWORD (2)

/* Note: this pfcpayload is little endian */
#define UNF_GET_FC_PAYLOAD_RX_SZ(pfcpayload)                               \
	((u16)(((u32 *)(void *)(pfcpayload))[UNF_FC_PAYLOAD_RX_SZ_DWORD] & \
	       UNF_FC_PAYLOAD_RX_SZ_MASK))

/* Note: this pfcpayload is big endian */
#define SPFC_GET_FC_PAYLOAD_RX_SZ(pfcpayload)                                  \
	(be32_to_cpu((u16)(((u32 *)(void *)(pfcpayload))[UNF_FC_PAYLOAD_RX_SZ_DWORD]) & \
	    UNF_FC_PAYLOAD_RX_SZ_MASK))

#define SPFC_GET_RA_TOV_FROM_PAYLOAD(pfcpayload)          \
	(((struct unf_flogi_fdisc_payload *)(pfcpayload))->fabric_parms.co_parms.r_a_tov)
#define SPFC_GET_RT_TOV_FROM_PAYLOAD(pfcpayload)          \
	(((struct unf_flogi_fdisc_payload *)(pfcpayload))->fabric_parms.co_parms.r_t_tov)
#define SPFC_GET_E_D_TOV_FROM_PAYLOAD(pfcpayload)         \
	(((struct unf_flogi_fdisc_payload *)(pfcpayload))->fabric_parms.co_parms.e_d_tov)
#define SPFC_GET_E_D_TOV_RESOLUTION_FROM_PAYLOAD(pfcpayload) \
	(((struct unf_flogi_fdisc_payload *)(pfcpayload))->fabric_parms.co_parms.e_d_tov_resolution)
#define SPFC_GET_BB_SC_N_FROM_PAYLOAD(pfcpayload)         \
	(((struct unf_flogi_fdisc_payload *)(pfcpayload))->fabric_parms.co_parms.bbscn)
#define SPFC_GET_BB_CREDIT_FROM_PAYLOAD(pfcpayload)       \
	(((struct unf_flogi_fdisc_payload *)(pfcpayload))->fabric_parms.co_parms.bb_credit)

#define SPFC_GET_RA_TOV_FROM_PARAMS(pfcparams) \
	(((struct unf_fabric_parm *)(pfcparams))->co_parms.r_a_tov)
#define SPFC_GET_RT_TOV_FROM_PARAMS(pfcparams) \
	(((struct unf_fabric_parm *)(pfcparams))->co_parms.r_t_tov)
#define SPFC_GET_E_D_TOV_FROM_PARAMS(pfcparams) \
	(((struct unf_fabric_parm *)(pfcparams))->co_parms.e_d_tov)
#define SPFC_GET_E_D_TOV_RESOLUTION_FROM_PARAMS(pfcparams) \
	(((struct unf_fabric_parm *)(pfcparams))->co_parms.e_d_tov_resolution)
#define SPFC_GET_BB_SC_N_FROM_PARAMS(pfcparams) \
	(((struct unf_fabric_parm *)(pfcparams))->co_parms.bbscn)
#define SPFC_GET_BB_CREDIT_FROM_PARAMS(pfcparams) \
	(((struct unf_fabric_parm *)(pfcparams))->co_parms.bb_credit)
#define SPFC_CHECK_NPORT_FPORT_BIT(pfcparams) \
	(((struct unf_fabric_parm *)(pfcparams))->co_parms.nport)

#define UNF_FC_RCTL_BLS_MASK (0x80)
#define SPFC_UNSOLICITED_FRAME_IS_BLS(hdr) (UNF_GET_FC_HEADER_RCTL(hdr) & UNF_FC_RCTL_BLS_MASK)

#define SPFC_LOW_SEQ_CNT (0)
#define SPFC_HIGH_SEQ_CNT (0xFFFF)

/* struct unf_frame_pkg.cmnd meaning:
 * The least significant 16 bits indicate whether to send ELS CMND or ELS RSP
 * (ACC or RJT). The most significant 16 bits indicate the corresponding ELS
 * CMND when the lower 16 bits are ELS RSP.
 */
#define SPFC_ELS_CMND_MASK (0xffff)
#define SPFC_ELS_CMND__RELEVANT_SHIFT (16UL)
#define SPFC_GET_LS_GS_CMND_CODE(cmnd) ((u16)((cmnd) & SPFC_ELS_CMND_MASK))
#define SPFC_GET_ELS_RSP_TYPE(cmnd) ((u16)((cmnd) & SPFC_ELS_CMND_MASK))
#define SPFC_GET_ELS_RSP_CODE(cmnd)                      \
	((u16)((cmnd) >> SPFC_ELS_CMND__RELEVANT_SHIFT & SPFC_ELS_CMND_MASK))

/* ELS CMND Request */
#define ELS_CMND (0)

/* fh_f_ctl - Frame control flags. */
#define SPFC_FC_EX_CTX BIT(23)     /* sent by responder to exchange */
#define SPFC_FC_SEQ_CTX BIT(22)    /* sent by responder to sequence */
#define SPFC_FC_FIRST_SEQ BIT(21)  /* first sequence of this exchange */
#define SPFC_FC_LAST_SEQ BIT(20)   /* last sequence of this exchange */
#define SPFC_FC_END_SEQ BIT(19)    /* last frame of sequence */
#define SPFC_FC_END_CONN BIT(18)   /* end of class 1 connection pending */
#define SPFC_FC_RES_B17 BIT(17)    /* reserved */
#define SPFC_FC_SEQ_INIT BIT(16)   /* transfer of sequence initiative */
#define SPFC_FC_X_ID_REASS BIT(15) /* exchange ID has been changed */
#define SPFC_FC_X_ID_INVAL BIT(14) /* exchange ID invalidated */
#define SPFC_FC_ACK_1 BIT(12)	     /* 13:12 = 1: ACK_1 expected */
#define SPFC_FC_ACK_N (2 << 12)	     /* 13:12 = 2: ACK_N expected */
#define SPFC_FC_ACK_0 (3 << 12)	     /* 13:12 = 3: ACK_0 expected */
#define SPFC_FC_RES_B11 BIT(11)    /* reserved */
#define SPFC_FC_RES_B10 BIT(10)    /* reserved */
#define SPFC_FC_RETX_SEQ BIT(9)    /* retransmitted sequence */
#define SPFC_FC_UNI_TX BIT(8)	     /* unidirectional transmit (class 1) */
#define SPFC_FC_CONT_SEQ(i) ((i) << 6)
#define SPFC_FC_ABT_SEQ(i) ((i) << 4)
#define SPFC_FC_REL_OFF BIT(3) /* parameter is relative offset */
#define SPFC_FC_RES2 BIT(2)	 /* reserved */
#define SPFC_FC_FILL(i) ((i) & 3)	 /* 1:0: bytes of trailing fill */

#define SPFC_FCTL_REQ (SPFC_FC_FIRST_SEQ | SPFC_FC_END_SEQ | SPFC_FC_SEQ_INIT)
#define SPFC_FCTL_RESP \
	(SPFC_FC_EX_CTX | SPFC_FC_LAST_SEQ | SPFC_FC_END_SEQ | SPFC_FC_SEQ_INIT)
#define SPFC_RCTL_BLS_REQ (0x81)
#define SPFC_RCTL_BLS_ACC (0x84)
#define SPFC_RCTL_BLS_RJT (0x85)

#define PHY_PORT_TYPE_FC 0x1   /* Physical port type of FC */
#define PHY_PORT_TYPE_FCOE 0x2 /* Physical port type of FCoE */
#define SPFC_FC_COS_VALUE (0X4)

#define SPFC_CDB16_LBA_MASK 0xffff
#define SPFC_CDB16_TRANSFERLEN_MASK 0xff
#define SPFC_RXID_MASK 0xffff
#define SPFC_OXID_MASK 0xffff0000

enum spfc_fc_fh_type {
	SPFC_FC_TYPE_BLS = 0x00, /* basic link service */
	SPFC_FC_TYPE_ELS = 0x01, /* extended link service */
	SPFC_FC_TYPE_IP = 0x05,	 /* IP over FC, RFC 4338 */
	SPFC_FC_TYPE_FCP = 0x08, /* SCSI FCP */
	SPFC_FC_TYPE_CT = 0x20,	 /* Fibre Channel Services (FC-CT) */
	SPFC_FC_TYPE_ILS = 0x22	 /* internal link service */
};

enum spfc_fc_fh_rctl {
	SPFC_FC_RCTL_DD_UNCAT = 0x00,	   /* uncategorized information */
	SPFC_FC_RCTL_DD_SOL_DATA = 0x01,   /* solicited data */
	SPFC_FC_RCTL_DD_UNSOL_CTL = 0x02,  /* unsolicited control */
	SPFC_FC_RCTL_DD_SOL_CTL = 0x03,	   /* solicited control or reply */
	SPFC_FC_RCTL_DD_UNSOL_DATA = 0x04, /* unsolicited data */
	SPFC_FC_RCTL_DD_DATA_DESC = 0x05,  /* data descriptor */
	SPFC_FC_RCTL_DD_UNSOL_CMD = 0x06,  /* unsolicited command */
	SPFC_FC_RCTL_DD_CMD_STATUS = 0x07, /* command status */

#define SPFC_FC_RCTL_ILS_REQ SPFC_FC_RCTL_DD_UNSOL_CTL /* ILS request */
#define SPFC_FC_RCTL_ILS_REP SPFC_FC_RCTL_DD_SOL_CTL   /* ILS reply */

	/*
	 * Extended Link_Data
	 */
	SPFC_FC_RCTL_ELS_REQ = 0x22,  /* extended link services request */
	SPFC_FC_RCTL_ELS_RSP = 0x23,  /* extended link services reply */
	SPFC_FC_RCTL_ELS4_REQ = 0x32, /* FC-4 ELS request */
	SPFC_FC_RCTL_ELS4_RSP = 0x33, /* FC-4 ELS reply */
	/*
	 * Optional Extended Headers
	 */
	SPFC_FC_RCTL_VFTH = 0x50, /* virtual fabric tagging header */
	SPFC_FC_RCTL_IFRH = 0x51, /* inter-fabric routing header */
	SPFC_FC_RCTL_ENCH = 0x52, /* encapsulation header */
	/*
	 * Basic Link Services fh_r_ctl values.
	 */
	SPFC_FC_RCTL_BA_NOP = 0x80,  /* basic link service NOP */
	SPFC_FC_RCTL_BA_ABTS = 0x81, /* basic link service abort */
	SPFC_FC_RCTL_BA_RMC = 0x82,  /* remove connection */
	SPFC_FC_RCTL_BA_ACC = 0x84,  /* basic accept */
	SPFC_FC_RCTL_BA_RJT = 0x85,  /* basic reject */
	SPFC_FC_RCTL_BA_PRMT = 0x86, /* dedicated connection preempted */
	/*
	 * Link Control Information.
	 */
	SPFC_FC_RCTL_ACK_1 = 0xc0,  /* acknowledge_1 */
	SPFC_FC_RCTL_ACK_0 = 0xc1,  /* acknowledge_0 */
	SPFC_FC_RCTL_P_RJT = 0xc2,  /* port reject */
	SPFC_FC_RCTL_F_RJT = 0xc3,  /* fabric reject */
	SPFC_FC_RCTL_P_BSY = 0xc4,  /* port busy */
	SPFC_FC_RCTL_F_BSY = 0xc5,  /* fabric busy to data frame */
	SPFC_FC_RCTL_F_BSYL = 0xc6, /* fabric busy to link control frame */
	SPFC_FC_RCTL_LCR = 0xc7,    /* link credit reset */
	SPFC_FC_RCTL_END = 0xc9	    /* end */
};

struct spfc_fc_frame_header {
	u8 rctl;	       /* routing control */
	u8 did[ARRAY_INDEX_3]; /* Destination ID */

	u8 cs_ctrl;	       /* class of service control / pri */
	u8 sid[ARRAY_INDEX_3]; /* Source ID */

	u8 type;		      /* see enum fc_fh_type below */
	u8 frame_ctrl[ARRAY_INDEX_3]; /* frame control */

	u8 seq_id;   /* sequence ID */
	u8 df_ctrl;  /* data field control */
	u16 seq_cnt; /* sequence count */

	u16 oxid;	  /* originator exchange ID */
	u16 rxid;	  /* responder exchange ID */
	u32 param_offset; /* parameter or relative offset */
};

u32 spfc_recv_els_cmnd(const struct spfc_hba_info *hba,
		       struct unf_frame_pkg *pkg, u8 *els_pld, u32 pld_len,
		       bool first);
u32 spfc_rcv_ls_gs_rsp(const struct spfc_hba_info *hba,
		       struct unf_frame_pkg *pkg, u32 hot_tag);
u32 spfc_rcv_els_rsp_sts(const struct spfc_hba_info *hba,
			 struct unf_frame_pkg *pkg, u32 hot_tag);
u32 spfc_rcv_bls_rsp(const struct spfc_hba_info *hba, struct unf_frame_pkg *pkg,
		     u32 hot_tag);
u32 spfc_rsv_bls_rsp_sts(const struct spfc_hba_info *hba,
			 struct unf_frame_pkg *pkg, u32 rx_id);
void spfc_save_login_parms_in_sq_info(struct spfc_hba_info *hba,
				      struct unf_port_login_parms *login_params);
u32 spfc_handle_aeq_off_load_err(struct spfc_hba_info *hba,
				 struct spfc_aqe_data *aeq_msg);
u32 spfc_free_xid(void *handle, struct unf_frame_pkg *pkg);
u32 spfc_scq_free_xid_sts(struct spfc_hba_info *hba, union spfc_scqe *scqe);
u32 spfc_scq_exchg_timeout_sts(struct spfc_hba_info *hba, union spfc_scqe *scqe);
u32 spfc_scq_rcv_sq_nop_sts(struct spfc_hba_info *hba, union spfc_scqe *scqe);
u32 spfc_send_els_via_default_session(struct spfc_hba_info *hba, struct spfc_sqe *io_sqe,
				      struct unf_frame_pkg *pkg,
				      struct spfc_parent_queue_info *prt_queue_info);
u32 spfc_send_ls_gs_cmnd(void *handle, struct unf_frame_pkg *pkg);
u32 spfc_send_bls_cmnd(void *handle, struct unf_frame_pkg *pkg);

/* Receive Frame from SCQ */
u32 spfc_rcv_scq_entry_from_scq(struct spfc_hba_info *hba,
				union spfc_scqe *scqe, u32 scqn);
void *spfc_get_els_buf_by_user_id(struct spfc_hba_info *hba, u16 user_id);

#define SPFC_CHECK_PKG_ALLOCTIME(pkg)                                       \
	do {                                                                   \
		if (unlikely(UNF_GETXCHGALLOCTIME(pkg) == 0)) {             \
			FC_DRV_PRINT(UNF_LOG_NORMAL,   \
				     UNF_WARN,                                 \
				     "[warn]Invalid MagicNum,S_ID(0x%x) "      \
				     "D_ID(0x%x) OXID(0x%x) "                  \
				     "RX_ID(0x%x) Pkg type(0x%x) hot "         \
				     "pooltag(0x%x)",                          \
				     UNF_GET_SID(pkg), UNF_GET_DID(pkg),   \
				     UNF_GET_OXID(pkg), UNF_GET_RXID(pkg), \
				     ((struct unf_frame_pkg *)(pkg))->type, \
				     UNF_GET_XCHG_TAG(pkg));                \
		}                                                              \
	} while (0)

#endif
