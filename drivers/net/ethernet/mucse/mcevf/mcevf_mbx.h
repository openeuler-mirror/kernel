/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2020-2026 Mucse Corporation. */

#ifndef _MCEVF_MBX_H_
#define _MCEVF_MBX_H_

struct mcevf_mbx_info;

enum VF_STATUS_F {
	VF_FCS_BIT = 0,
	VF_SPOOF_BIT,
	VF_TRUST_BIT,
	VF_RDMA_BIT,
	VF_PFC_BIT,
	VF_DSCP_BIT
};

/* PF<->VF mailbox  fields */
enum F_VF_RESET_DATA_RESP {
	F_VF_MAC_ADDR = 0,
	F_VF_RESET_RING_MAX_CNT = 2,
	F_VF_RESET_FW_VERSION,
	F_VF_RESET_VLAN,
	F_VF_RESET_LINK_ST,
	F_VF_RESET_AXI_MHZ,
	F_VF_NR_PF,
	//F_VF_FCS_STATE,
	//F_VF_SPOOF_STATE,
	//F_VF_TRUST_STATE,
	//F_VF_RDMA_STATE,
	F_VF_STATE,
	//F_VF_PFC_BASE,
	F_VF_RESET_RESP_CNT
};

enum F_VF_GET_QOS_DATA_RESP {
	F_VF_PFC_BASE = 0,
	F_VF_PFC_COUNT = 4,
	F_VF_VALID_PRIO = 8,
	F_VF_QOS_RESP_CNT,
};

#define MCEVF_PF_LINK_UP BIT(31)

enum PF2VF_MBX_REQ {
	MCE_PF2VF_SET_VLAN = 1,
	MCE_PF2VF_SET_DSCP,
};

enum VF2PF_MBX_REQ_CMD {
	MCE_VF_RESET = 1,
	MCE_VF_REMOVED,
	MCE_VF_SET_VLAN,
	MCE_VF_SET_VLAN_STRIP,
	MCE_VF_SET_MAC_ADDR,
	MCE_VF_SET_PROMISC_MODE,
	MCE_VF_SET_MACVLAN_ADDR,
	MCE_VF_DEL_MACVLAN_ADDR,
	MCE_VF_NOTIFY_RING_CNT,
	MCE_VF_GET_QOS,
	MCE_VF_GET_DSCP_LOW,
	MCE_VF_GET_DSCP_HIGH,
	MCE_VF_SET_IPV4_ADDR, /* VF set IPv4 address to PF */
	/* VF checks whether its IPv4 address conflicts with other VFs. */
	MCE_VF_CHECK_IPV4_ADDR_CONFLICT,
};

union req_cmd {
	unsigned int v;

	struct {
		unsigned short opcode;

		unsigned char err_code	   : 6;
		/* Return immediately without waiting for the command to complete */
		unsigned char flag_no_wait : 1;
		unsigned char flag_no_resp : 1;

		/* req: arg cnts, response: value cnts */
		unsigned char arg_cnts : 4;
		/*pf to cm3/vf req, peer is cm3 or vf */
		unsigned char flag_pf2peer_req : 1;
		/*  VF/CM3 to PF req */
		unsigned char flag_peer2pf_req : 1;
		unsigned char flag_vf2cm3_req : 1; /* VF->CM3 req */
		unsigned char flag_cm32vf_req : 1; /* CM3->VF req */
	};
} __aligned(4) __packed;

struct mbx_req {
	union req_cmd cmd;
	unsigned int data[(64 - sizeof(union req_cmd)) / 4];
} __aligned(4) __packed;

struct mbx_resp {
	union req_cmd cmd;
	unsigned int data[(64 - sizeof(union req_cmd)) / 4];
} __aligned(4) __packed;

enum PF2VF_EVENT_ID {
	EVT_PF_LINK_CHANGED = 1,
	EVT_PF_RESET_VF = 2,
	EVT_PF_DRV_REMOVE = 3,
	EVT_PF_FORCE_VF_LINK_UP = 4,
	EVT_PF_FORCE_VF_LINK_DOWN = 5,
	EVT_PF_FORECE_VF_OPEN = 6,
	EVT_PF_FORECE_VF_CLOESE = 7,
	EVT_PF_FORECE_FCS_ON = 8,
	EVT_PF_FORECE_FCS_OFF = 9,
	EVT_PF_FORECE_SPOOF_ON = 10,
	EVT_PF_FORECE_SPOOF_OFF = 11,
	EVT_PF_TRUST_ON = 12,
	EVT_PF_TRUST_OFF = 13,
	EVT_PF_DSCP_ON = 14,
	EVT_PF_DSCP_OFF = 15,
};

enum VF2PF_EVENT_ID {
	EVT_VF_INIT_DONE = 1,
	EVT_VF_DRV_REMOVED = 2,
};

enum MBX_REQ_STAT {
	HAS_ERR = 0,
	REQ_WITH_DATA = 1,
	EVENT_REQ = 2,
	RESP_OR_ACK = 3,
};

enum MBX_PF_STAT {
	PF_SPEED,
	PF_LINKUP,
};

int mcevf_mbx_get_pf_stat(struct mcevf_mbx_info *fw_mbx, enum MBX_PF_STAT stat);
void mcevf_mbx_set_vf_stat(struct mcevf_mbx_info *pf_mbx);

int mcevf_mbx_send_req(struct mcevf_mbx_info *mbx,
		       int opcode,
		       int *data,
		       int data_bytes,
		       struct mbx_resp *resp,
		       int timeout_us);

typedef void(mbx_event_req_cb)(struct mcevf_mbx_info *mbx, int event_id);
typedef void(mbx_req_with_data_cb)(struct mcevf_mbx_info *mbx, struct mbx_req *req);

int mcevf_mbx_clean_all_incoming_req(struct mcevf_hw *hw,
				     mbx_event_req_cb *event_cb,
				      mbx_req_with_data_cb *req_cb);
int mcevf_mbx_send_resp_isr(struct mcevf_mbx_info *mbx, struct mbx_resp *resp);
int mcevf_mbx_send_event(struct mcevf_mbx_info *mbx, int event_id, int timeout_us);
int mcevf_mbx_vector_set(struct mcevf_mbx_info *mbx, int nr_vector, bool enable);
void mcevf_mbx_set_vf_stat(struct mcevf_mbx_info *pf_mbx);
void mcevf_mbx_reset(struct mcevf_hw *hw);
int mcevf_mbx_init_configure(struct mcevf_mbx_info *mbx);
void mcevf_mbx_clear_peer_req_irq_with_stat(struct mcevf_mbx_info *mbx, enum MBX_REQ_STAT stat);
#endif /*_MCEVF_MBX_H_*/
