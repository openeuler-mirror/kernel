/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#ifndef __VDM_H__
#define __VDM_H__

/* VDM message opcode */
enum vdm_opcode {
	VDM_OPCODE_FM2UB_COMM_MSG = 0, /* FM To UB node Communication Message */
	VDM_OPCODE_UB2FM_COMM_MSG = 0x1, /* UB node To FM Communication Message */
	VDM_OPCODE_UB2UB_COMM_MSG = 0x2, /* UB node To UB node Communication Message */
	VDM_OPCODE_FW_COMM_MSG = 0x3, /* Firmware Communication Message */
};

enum vdm_fm2ub_sub_opcode {
	VDM_SUB_OPCODE_MUE_REG  = 0x1,
	VDM_SUB_OPCODE_MUE_RLS  = 0x2,
	VDM_SUB_OPCODE_UE_REG  = 0x3,
	VDM_SUB_OPCODE_UE_RLS  = 0x4,
	VDM_BI_CREATE_BYPASS_UMMU = 0x5,
	VDM_FM2UB_SUB_PORT_MGMT = 0x7,
};

enum vdm_ub2fm_sub_opcode {
	VDM_SUB_OPCODE_ENTITY_ENABLE = 0x1,
	VDM_SUB_OPCODE_PORT_RESET = 0x2,
};

enum ub_task_src_vdm {
	TASK_SRC_VPORT = 8,
	TASK_SRC_VDM = 9,
};

struct msg_pkt_dw0 {
	/* DW0 */
	u32 rsvd0 : 16;
	u32 opcode : 6;
	u32 sub_opcode : 10;
};
#define VDM_MSG_DW0_PLD_SIZE 4

/* send entity enable msg payload */
struct entity_enable_pld {
	/* DW1 */
	u32 entity_type : 1;
	u32 enable : 1;
	u32 rsvd1 : 30;
	/* DW2~DW5 */
	u32 eid[4];
	/* DW6~DW9 */
	u32 guid[UB_GUID_DW_NUM];
	/* DW10 */
	u16 entity_idx;
	u16 rsvd2;
};
#define ENTITY_ENABLE_PLD_SIZE 52

#define ENTITY_ENABLE_MSG_PKT_SIZE (MSG_PKT_HEADER_SIZE + ENTITY_ENABLE_PLD_SIZE)

enum entity_type {
	ENTITY_TYPE_IDEV = 0,
	ENTITY_TYPE_DEV = 1,
};

struct idev_pue_reg_pld {
	/* DW1~DW4 */
	u32 guid[UB_GUID_DW_NUM];
	/* DW5 */
	u16 pue_entity_idx;
	u16 ue_cnt;
	/* DW6 */
	u16 start_ue_entity_idx;
	u16 end_ue_entity_idx;
	/* DW7~DW10 */
	u32 user_eid[4];
};
#define IDEV_MUE_REG_PLD_TOTAL_SIZE 52

struct idev_pue_rls_pld {
	/* DW1~DW4 */
	u32 guid[UB_GUID_DW_NUM];
	/* DW5 */
	u16 pue_entity_idx;
	u16 rls_reason;
};
#define IDEV_MUE_RLS_PLD_TOTAL_SIZE 32

struct idev_ue_reg_pld {
	/* DW1~DW4 */
	u32 guid[UB_GUID_DW_NUM];
	/* DW5 */
	u16 pue_entity_idx;
	u16 ue_entity_idx;
	/* DW6~DW9 */
	u32 user_eid[4];
};
#define IDEV_UE_REG_PLD_TOTAL_SIZE 48

struct idev_ue_rls_pld {
	/* DW1~DW4 */
	u32 guid[UB_GUID_DW_NUM];
	/* DW5 */
	u16 pue_entity_idx;
	u16 ue_entity_idx;
	/* DW6 */
	u16 rls_reason;
	u16 rsvd1;
};
#define IDEV_UE_RLS_PLD_TOTAL_SIZE 36

struct create_bi_bypass_pld {
	/* DW1~DW4 */
	u32 guid[UB_GUID_DW_NUM];
	/* DW5~DW8 */
	u32 eid[4];
	/* DW9 */
	u32 upi : 15;
	u32 m : 1;
	u32 rsvd2 : 16;
};
#define VDM_BI_CREATE_BYPASS_UMMU_PLD_SIZE 48

struct port_mgmt_pld {
	/* DW1 */
	u16 rsvd0;
	u16 subcmd;
	/* DW2 */
	u32 en : 1;
	u32 flag : 1;
	u32 rsvd : 14;
	u32 port_idx : 16;
};
#define VDM_PORT_MGMT_PLD_SIZE 20

struct port_reset_pld {
	/* DW1 */
	u16 rsvd;
	u16 port_idx;
};
#define VDM_PORT_RESET_PLD_SIZE 16

#define MSG_IDEV_MUE_REG_SIZE \
	(MSG_PKT_HEADER_SIZE + IDEV_MUE_REG_PLD_TOTAL_SIZE)
#define MSG_IDEV_MUE_RLS_SIZE \
	(MSG_PKT_HEADER_SIZE + IDEV_MUE_RLS_PLD_TOTAL_SIZE)
#define MSG_IDEV_UE_REG_SIZE \
	(MSG_PKT_HEADER_SIZE + IDEV_UE_REG_PLD_TOTAL_SIZE)
#define MSG_IDEV_UE_RLS_SIZE \
	(MSG_PKT_HEADER_SIZE + IDEV_UE_RLS_PLD_TOTAL_SIZE)
#define VDM_BI_CREATE_BYPASS_SIZE \
	(MSG_PKT_HEADER_SIZE + VDM_BI_CREATE_BYPASS_UMMU_PLD_SIZE)
#define VDM_PORT_MGMT_SIZE \
	(MSG_PKT_HEADER_SIZE + VDM_PORT_MGMT_PLD_SIZE)
#define VDM_PORT_RESET_SIZE \
	(MSG_PKT_HEADER_SIZE + VDM_PORT_RESET_PLD_SIZE)

#define VENDOR_GUID_PLD_SIZE 8

struct vdm_msg_pkt {
	struct msg_pkt_header header;
	u64 guid_high;
	struct msg_pkt_dw0 pld_dw0;
	union {
		struct port_reset_pld reset_pld;
		struct entity_enable_pld enable_pld;
		struct idev_pue_reg_pld pd_reg_pld;
		struct idev_pue_rls_pld pd_rls_pld;
		struct idev_ue_reg_pld vd_reg_pld;
		struct idev_ue_rls_pld vd_rls_pld;
		struct port_mgmt_pld mgmt_pld;
		struct create_bi_bypass_pld bi_bypass_pld;
	};
};

void hi_vdm_rx_msg_handler(struct ub_bus_controller *ubc, void *pkt, u16 len);

#endif /* __VDM_H__ */
