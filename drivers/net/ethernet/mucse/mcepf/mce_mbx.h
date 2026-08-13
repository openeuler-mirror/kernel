/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2024-2026 Mucse Corporation. */

#ifndef _MCE_MBX_H_
#define _MCE_MBX_H_
#include <linux/wait.h>
#include <linux/sem.h>
#include <linux/semaphore.h>
#include <linux/mutex.h>
#include "mce_type.h"
#include "mce.h"

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
	F_VF_STATE,
	F_VF_RESET_RESP_CNT, /* must be the last */
};

enum F_VF_GET_QOS_DATA_RESP {
	F_VF_PFC_BASE = 0,
	F_VF_PFC_COUNT = 4,
	F_VF_VALID_PRIO = 8,
	F_VF_QOS_RESP_CNT,
};

#define MCE_PF_LINK_UP BIT(31)

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
	MCE_VF_CHECK_IPV4_ADDR_CONFLICT, /* VF check if the IPv4 address conflicts with other VFs */
};

enum PF2VF_MBX_REQ {
	MCE_PF2VF_SET_VLAN = 1,
};

union req_cmd {
	unsigned int v;

	struct {
		unsigned short opcode;

		unsigned char err_code : 6;
		/* Return immediately without waiting for the command to complete */
		unsigned char flag_no_wait : 1;
		unsigned char flag_no_resp : 1;
		/* req: arg cnts, response: value cnts */
		unsigned char arg_cnts : 4;
		/*pf to cm3/vf req, peer is cm3 or vf */
		unsigned char flag_pf2peer_req : 1;
		unsigned char flag_peer2pf_req : 1;
		unsigned char flag_vf2cm3_req : 1; /* VF->CM3 req */
		unsigned char flag_cm32vf_req : 1; /* CM3->VF req */
	};
} __packed __aligned(4);

struct mbx_req {
	union req_cmd cmd;
	unsigned int data[(64 - sizeof(union req_cmd)) / 4];
} __packed __aligned(4);

struct mbx_resp {
	union req_cmd cmd;
	unsigned int data[(64 - sizeof(union req_cmd)) / 4];
} __packed __aligned(4);

enum MBX_ERR_CODE {
	MBX_EOK = 0, /* There is no error */
	MBX_EPERM = 1, /* Operation not permitted */
	MBX_ENOENT = 2, /* No entry */
	MBX_EFULL = 3, /* The resource is full */
	MBX_EEMPTY = 4, /* The resource is empty */
	MBX_EIO = 5, /* IO error */
	MBX_ENOMEM = 12, /* No memory */
	MBX_EFAULT = 14, /* Bad address */
	MBX_EBUSY = 16, /* Busy */
	MBX_EINVAL = 22, /* Invalid argument */
	MBX_ENOSPC = 28, /* No space left */
	MBX_ERROR = 40, /* A generic/unknown error happens */
	MBX_ENOSUPPORTED = 41, /* not implemented */
	MBX_ENOSYS = 42, /* Function not implemented */
	MBX_ETIMEOUT = 43, /* Timed out */
	MBX_EINTERNAL = 44, /* internal error */
	MBX_ENOBUFS = 45, /* No buffer space is available */
	MBX_EVERIFY = 46, /* verify failed */
	MBX_ERANGE = 47, /* range invalid */
	MBX_ENODEV = 48 /* invalid arg, not find device */
};

enum MBX_ID {
	MBX_VF0 = 0,
	MBX_VF1,
	MBX_VF2,
	MBX_VF3,
	MBX_VF4,
	/* vf5 ... vf126*/
	MBX_VF127 = 126,
	MBX_FW,
	MBX_CNT
};

enum MBX_REQ_STAT {
	HAS_ERR = 0,
	REQ_WITH_DATA = 1,
	EVENT_REQ = 2,
	RESP_OR_ACK = 3,
};

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

enum FW2PF_EVENT_ID {
	EVT_PORT_LINK_UP = 1,
	EVT_SFP_PLUGIN_IN = 2,
	EVT_PTP = 3,
	EVT_PORT_LINK_DOWN = 4,
	EVT_SFP_PLUGIN_OUT = 5,
	EVT_SFP_SPEED_CHANGED = 6,
};

enum PF2FW_EVENT_ID {
	EVT_NIC_RESET = 1,
	EVT_DRV_REMOVE = 4,
	EVT_REG_OP = 5,
};

enum MBX_FW_STAT {
	FW_LINK_STAT,
	FW_NIC_RESET_DONE_STAT,
	FW_NR_PF,
};

enum MBX_VF_STAT {
	VF_RESET_DONE,
	VF_MBX_IRQ_INIT_DONE,
};

struct mce_mbx_info;

int mce_mbx_send_event(struct mce_mbx_info *mbx, int event_id, int timeout_us);
int mce_mbx_set_pf_stat_reg(struct mce_hw *hw);
int mce_mbx_get_fw_stat(struct mce_mbx_info *fw_mbx, enum MBX_FW_STAT stat);
void mce_mbx_clear_fw_nic_reset_done_flag(struct mce_mbx_info *fw_mbx);
int mce_mbx_get_vf_stat(struct mce_mbx_info *fw_mbx, enum MBX_VF_STAT stat);
void mce_mbx_clear_vf_reset_done_stat(struct mce_mbx_info *fw_mbx);
int mce_mbx_send_req(struct mce_mbx_info *mbx, int opcode, int *data,
		     int data_bytes, struct mbx_resp *resp, int timeout_us);

int mce_mbx_req_read_resp_out(struct mce_mbx_info *mbx, struct mbx_resp *resp);

typedef void(mbx_event_req_cb)(struct mce_mbx_info *mbx, int event_id);
typedef void(mbx_req_with_data_cb)(struct mce_mbx_info *mbx,
				   struct mbx_req *req);
int mce_mbx_clean_all_incoming_req(struct mce_hw *hw,
				   mbx_event_req_cb *event_cb,
				    mbx_req_with_data_cb *req_cb);
int mce_mbx_send_resp_isr(struct mce_mbx_info *mbx, struct mbx_resp *resp);
int mce_mbx_vector_set(struct mce_mbx_info *mbx, int nr_vector, bool enable);
int mce_mbx_init_configure(struct mce_mbx_info *mbx);
void mce_mbx_clear_peer_req_irq_with_stat(struct mce_mbx_info *mbx,
					  enum MBX_REQ_STAT stat);
void mce_mbx_clear_peer_req_irq_with_no_stat_change(struct mce_mbx_info *mbx);
void mce_mbx_reset(struct mce_hw *hw);
void mce_mbx_set_pf_stat_vf(struct mce_mbx_info *vf_mbx);
void mce_mbx_set_pf_stat_fw(struct mce_mbx_info *fw_mbx);
void mce_mbx_link_state_change_notify_en(struct mce_hw *hw, int enable);
void mce_mbx_sfp_plug_inout_notify_en(struct mce_hw *hw, int enable);
void mce_mbx_sfp_plug_notify_en(struct mce_hw *hw, int enable);

void mce_mbx_drv_send_uninstall_notify_fw(struct mce_hw *hw);
void mce_mbx_send_nic_reset_event_to_fw(struct mce_hw *hw);

#endif /*_MCE_MBX_H_*/
