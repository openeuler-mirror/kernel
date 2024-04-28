/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef ROCE_XQE_FORMAT_H
#define ROCE_XQE_FORMAT_H

/* * SQ DB Format start */
struct roce_sq_db_seg {
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 type : 5;
			u32 cos : 3;
			u32 cp_flag : 1;
			u32 rsvd : 1;
			u32 ctx_size : 2;
			u32 qpn : 20;
#else
			u32 qpn : 20;
			/* RoCE QPC size, 512B */
			u32 ctx_size : 2;
			u32 rsvd : 1;
			/* control plane flag */
			u32 cp_flag : 1;
			/* Scheduling priority. The value source is SL. */
			u32 cos : 3;
			/* Set RoCE SQ Doorbell to 2 and RoCE Arm CQ Doorbell to 3. */
			u32 type : 5;
#endif
		} bs;
		u32 value;
	} dw0;

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 sub_type : 4;
			/* gid index */
			u32 sgid_index : 7;
			/* 256B:0;512B:1;1024B:2;2048B:3;4096B:4 */
			u32 mtu_shift : 3;
			u32 rsvd : 1;
			/* 1:XRC service type */
			u32 xrc_vld : 1;
			u32 resv : 8;
			/* host sw write the sq produce index high 8bit to this section; */
			u32 pi : 8;
#else
			/* host sw write the sq produce index high 8bit to this section; */
			u32 pi : 8;
			u32 resv : 8;
			u32 xrc_vld : 1;
			u32 rsvd : 1;
			u32 mtu_shift : 3;
			u32 sgid_index : 7;
			u32 sub_type : 4;
#endif
		} bs;
		u32 value;
	} dw1;
};

union roce_sq_db {
	struct roce_sq_db_seg sq_db_seg;
	union {
		u64 sq_db_val;
		struct {
			u32 sq_db_val_h32;
			u32 sq_db_val_l32;
		} dw2;
	};
};

/* *SQ DB Format end */

/* * ARM CQ DB Format start */
struct roce_db_cq_arm {
	/* DW0 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			/* dB type. The value of RoCE ARM CQ DB is 3. */
			u32 type : 5;
			/* ARM CQ DB Not required */
			u32 cos : 3;
			/* the control plane flag of a DB */
			u32 cp : 1;
			u32 non_filter : 1;
			/* Cq type, 0: RDMA/1:T/IFOE/2.3: Rsv */
			u32 cqc_type : 2;
			u32 cqn : 20;
#else
			u32 cqn : 20;
			/* Cq type, 0: RDMA/1:T/IFOE/2.3: Rsv */
			u32 cqc_type : 2;
			u32 non_filter : 1;
			/* the control plane flag of a DB */
			u32 cp : 1;
			/* ARM CQ DB Not required */
			u32 cos : 3;
			/* dB type. The value of RoCE ARM CQ DB is 3. */
			u32 type : 5;
#endif
		} bs;
		u32 value;
	} dw0;

	/* DW1 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			/*
			 * The ArmCQ DB carries the CmdSn, which is compared with the CmdSn in the
			 * chip. If the values are different, the is valid. If the values are the
			 * same, the needs to be checked. -- Each time a CEQE is generated,
			 * the CmdSn of the chip is updated to the CmdSn of the latest ArmCq DB.
			 */
			u32 cmd_sn : 2;
			/*
			 * Run the Arm command. 0-non-Arm After receiving the next CQE with the SE,
			 * the 1-ARM SOLICITED generates the CEQE. The * 2-ARM NEXT generates the
			 * CEQE after receiving the next CQE.
			 */
			u32 cmd : 2;
			u32 rsv1 : 4;
			/* Consumer pointer */
			u32 ci : 24;
#else
			/* Consumer pointer */
			u32 ci : 24;
			u32 rsv1 : 4;
			/*
			 * Run the Arm command. 0-non-Arm After receiving the next CQE with the SE,
			 * the 1-ARM SOLICITED generates the CEQE. The * 2-ARM NEXT generates the
			 * CEQE after receiving the next CQE.
			 */
			u32 cmd : 2;
			/*
			 * The ArmCQ DB carries the CmdSn, which is compared with the CmdSn in the
			 * chip. If the values are different, the is valid. If the values are the
			 * same, the needs to be checked. -- Each time a CEQE is generated,
			 * the CmdSn of the chip is updated to the CmdSn of the latest ArmCq DB.
			 */
			u32 cmd_sn : 2;
#endif
		} bs;
		u32 value;
	} dw1;
};
/* * ARM CQ DB Format end */

/* * CQE Format start */
struct roce_cqe {
	/* DW0 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			/*
			 * Owner bit. During initialization, 0 indicates all hardware,
			 * and 1 indicates all software.
			 * This bit is modified when the hardware writes the CQE.
			 * The meaning of each queue owner bit is reversed.
			 */
			u32 owner : 1;
			/* For roce, this field is reserved. */
			u32 size : 2;
			/* For roce, this field is reserved. */
			u32 dif_en : 1;
			/* For roce, this field is reserved. */
			u32 wq_id : 4;
			/* For roce, this field is reserved. */
			u32 error_code : 4;
			/*
			 * Local QPN, which is used in all cases.
			 * The driver finds the software QPC based on the QPN.
			 */
			u32 qpn : 20;
#else
			/*
			 * Local QPN, which is used in all cases.
			 * The driver finds the software QPC based on the QPN.
			 */
			u32 qpn : 20;
			/* For roce, this field is reserved. */
			u32 error_code : 4;
			/* For roce, this field is reserved. */
			u32 wq_id : 4;
			/* For roce, this field is reserved. */
			u32 dif_en : 1;
			/* For roce, this field is reserved. */
			u32 size : 2;
			/*
			 * Owner bit. During initialization, 0 indicates all hardware,
			 * and 1 indicates all software.
			 * This bit is modified when the hardware writes the CQE.
			 * The meaning of each queue owner bit is reversed.
			 */
			u32 owner : 1;
#endif
		} bs;
		u32 value;
	} dw0;

	/* DW1 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			/*
			 * The same as what is for SQ WQE. For details,
			 * see the enumeration roce_cqe_opcode
			 */
			u32 op_type : 5;
			/* Indicates SQ CQE or RQ CQE. 1-Send Completion; 0-Receive Completion */
			u32 s_r : 1;
			/* Indicates whether RQ inline; SQ ignores this bit */
			u32 inline_r : 1;
			u32 flush_op : 1;
			/*
			 * Indicates whether the CQE is a fake one.
			 * When fake, optype & syndronme should be 0
			 */
			u32 fake : 1;
			u32 rsvd : 3;
			/* The WQEBB index and SQ/RQ/SRQ are valid. */
			u32 wqebb_cnt : 20;
#else
			/* The WQEBB index and SQ/RQ/SRQ are valid. */
			u32 wqebb_cnt : 20;
			u32 rsvd : 3;
			/*
			 * Indicates whether the CQE is a fake one.
			 * When fake, optype & syndronme should be 0
			 */
			u32 fake : 1;
			u32 flush_op : 1;
			/* Indicates whether RQ inline; SQ ignores this bit */
			u32 inline_r : 1;
			/* Indicates SQ CQE or RQ CQE. 1-Send Completion; 0-Receive Completion */
			u32 s_r : 1;
			/*
			 * The same as what is for SQ WQE. For details,
			 * see the enumeration roce_cqe_opcode
			 */
			u32 op_type : 5;
#endif
		} bs;
		u32 value;
	} dw1;

	/* DW2 */
	/*
	 * Indicates the number of transmitted bytes. This field is valid
	 * for the RDMA read and receive
	 * operations. For the recv of RDMA write imm, the value is 0.
	 */
	u32 byte_cnt;

	/* DW3 */
	u32 imm_invalid_rkey; /* The receiving is complete and valid. */

	/* DW4 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 vlan_id : 12;
			u32 rsvd : 1;
			u32 vlan_pri : 3;
			u32 smac_h : 16;
#else
			u32 smac_h : 16;
			u32 vlan_pri : 3;
			u32 rsvd : 1;
			u32 vlan_id : 12;
#endif
		} bs; /* for ud only */
		u32 value;
	} dw4;

	/* DW5 */
	u32 smac_l;

	/* DW6 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			/*
			 * The for ud only:UD receive end is valid.
			 * The 00-packet does not contain a VLAN ID. The
			 * 01-packet contains a VLAN ID.
			 */
			u32 vlan_pre : 2;
			/* This field is valid only for UD. Force loopback */
			u32 fl : 1;
			u32 stp : 2;
			u32 rsvd : 3;
			/*
			 * The XRC at the receive end is valid. When the XRCSRQ at
			 * the receive end is received, the ;UD at the remote end
			 * refers to the QPN at the remote end.
			 */
			u32 srqn_rqpn : 24;
#else
			/*
			 * The XRC at the receive end is valid. When the XRCSRQ at
			 * the receive end is received, the ;UD at the remote end
			 * refers to the QPN at the remote end.
			 */
			u32 srqn_rqpn : 24;
			u32 rsvd : 3;
			u32 stp : 2;
			/* This field is valid only for UD. Force loopback */
			u32 fl : 1;
			/*
			 * The for ud only:UD receive end is valid.
			 * The 00-packet does not contain a VLAN ID. The
			 * 01-packet contains a VLAN ID.
			 */
			u32 vlan_pre : 2;
#endif
		} bs;
		u32 value;
	} dw6;

	/* DW7 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 wqe_cnt : 16;   /* WQE index, valid SQ */
			u32 rsvd : 8;
			/*
			 * 0 indicates that the operation is complete. This parameter
			 * is valid when Op_type is set to ROCE_OPCODE_ERR.
			 * For details about the definition, see the enumeration
			 * roce_cqe_syndrome.
			 */
			u32 syndrome : 8;
#else
			/*
			 * 0 indicates that the operation is complete. This parameter
			 * is valid when Op_type is set to ROCE_OPCODE_ERR.
			 * For details about the definition, see the enumeration
			 * roce_cqe_syndrome.
			 */
			u32 syndrome : 8;
			u32 rsvd : 8;
			u32 wqe_cnt : 16; /* WQE index, valid SQ */
#endif
		} bs;
		u32 value;
	} dw7;

	u32 timestamp_h;
	u32 timestamp_l;
	u32 common_rsvd[6];
};

struct roce_resize_cqe {
	/* DW0 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			/*
			 * Owner bit. During initialization, 0 indicates all hardware,
			 * and 1 indicates all software.
			 * This bit is overwritten when the hardware writes the CQE.
			 * The meaning of the queue owner
			 * bit is reversed every time the queue owner is traversed.
			 */
			u32 owner : 1;
			u32 rsvd : 31;
#else
			u32 rsvd : 31;
			/*
			 * Owner bit. During initialization, 0 indicates all hardware,
			 * and 1 indicates all software.
			 * This bit is overwritten when the hardware writes the CQE.
			 * The meaning of the queue owner
			 * bit is reversed every time the queue owner is traversed.
			 */
			u32 owner : 1;
#endif
		} bs;
		u32 value;
	} dw0;

	/* DW1 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			/*
			 * The operation type is the same as that of SQ WQE.
			 * For details, see the enumeration
			 * roce_cqe_opcode.
			 */
			u32 op_type : 5;
			/*
			 * Indicates whether SQ CQE or RQ CQE is used.
			 * 1-Send Completion; 0-Receive Completion
			 */
			u32 s_r : 1;
			u32 rsvd : 26;
#else
			u32 rsvd : 26;
			/*
			 * Indicates whether SQ CQE or RQ CQE is used.
			 * 1-Send Completion; 0-Receive Completion
			 */
			u32 s_r : 1;
			/*
			 * The operation type is the same as that of SQ WQE.
			 * For details, see the enumeration
			 * roce_cqe_opcode.
			 */
			u32 op_type : 5;
#endif
		} bs;
		u32 value;
	} dw1;

	/* DW2~7 */
	u32 rsvd[6];

	u32 common_rsvd[8];
};

struct roce_err_cqe {
	/* DW0 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			/*
			 * Owner bit. During initialization, 0 indicates all hardware,
			 * and 1 indicates all software. This bit is overwritten when
			 * the hardware writes the CQE. The meaning of the queue owner
			 * bit is reversed every time the queue owner is traversed.
			 */
			u32 owner : 1;
			u32 rsvd : 11; /* For RoCE, this field is reserved. */
			/*
			 * Local QPN, which is used in all cases.
			 * The driver finds the software QPC based on the QPN.
			 */
			u32 qpn : 20;
#else
			/*
			 * Local QPN, which is used in all cases.
			 * The driver finds the software QPC based on the QPN.
			 */
			u32 qpn : 20;
			u32 rsvd : 11; /* For roce, this field is reserved. */
			/*
			 * Owner bit. During initialization, 0 indicates all hardware,
			 * and 1 indicates all software.
			 * This bit is overwritten when the hardware writes the CQE.
			 * The meaning of the queue owner
			 * bit is reversed every time the queue owner is traversed.
			 */
			u32 owner : 1;
#endif
		} bs;
		u32 value;
	} dw0;

	/* DW1 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			/*
			 * The operation type is the same as that of SQ WQE.
			 * For details, see roce_cqe_opcode.
			 */
			u32 op_type : 5;
			/*
			 * Indicates the SQ CQE or RQ CQE. 1-Send Completion;
			 * 0-Receive Completion
			 */
			u32 s_r : 1;
			u32 inline_r : 1;
			u32 flush_op : 1;
			u32 fake : 1;
			u32 rsvd : 3;
			u32 wqebb_cnt : 20; /* The WQEBB index and SQ/RQ/SRQ are valid. */
#else
			u32 wqebb_cnt : 20; /* The WQEBB index and SQ/RQ/SRQ are valid. */
			u32 rsvd : 3;
			u32 fake : 1;
			/*
			 * Indicates whether this CQE is a fake cqe or not.when fake = 1,
			 * optype & syndronme should be 0
			 */
			u32 flush_op : 1;
			u32 inline_r : 1;
			/*
			 * Indicates the SQ CQE or RQ CQE. 1-Send Completion;
			 * 0-Receive Completion
			 */
			u32 s_r : 1;
			/*
			 * The operation type is the same as that of SQ WQE.
			 * For details, see roce_cqe_opcode.
			 */
			u32 op_type : 5;
#endif
		} bs;
		u32 value;
	} dw1;

	/* DW2~5 */
	u32 rsvd[3];

	u32 wqe_num;

	/* DW6 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd : 8;
			/* The XRC at the receive end is valid, which is XRCSRQ. */
			u32 srqn : 24;
#else
			/* The XRC at the receive end is valid, which is the XRCSRQ number. */
			u32 srqn : 24;
			u32 rsvd : 8;
#endif
		} bs;
		u32 value;
	} dw6;

	/* DW7 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 wqe_cnt : 16; /* WQE index: Indicates that the SQ is valid. */
			u32 vendor_err : 8;
			/*
			 * 0 indicates that the operation is successful. The value is
			 * valid when Op_type is ROCE_OPCODE_ERR. For details, see the
			 * enumeration roce_cqe_syndrome.
			 */
			u32 syndrome : 8;
#else
			/*
			 * 0 indicates that the operation is complete. This parameter
			 * is valid when Op_type is set to ROCE_OPCODE_ERR. For details
			 * about the definition, see the enumeration
			 * roce_cqe_syndrome.
			 */
			u32 syndrome : 8;
			u32 vendor_err : 8;
			u32 wqe_cnt : 16; /* WQE index, valid SQ */
#endif
		} bs;
		u32 value;
	} dw7;

	u32 timestamp_h;
	u32 timestamp_l;
	u32 common_rsvd[6];
};


struct roce_vbs_cqe {
	/* DW0 */
	union {
		struct {
			u32 owner : 1;
			u32 size : 2;
			u32 dif_en : 1;
			u32 wq_id : 4;
			u32 error_code : 4;
			u32 qpn : 20;
		} bs;
		u32 value;
	} dw0;

	/* DW1 */
	union {
		struct {
			/*
			 * The operation type is the same as that of SQ WQE.
			 * For details, see the enumeration roce_cqe_opcode.
			 */
			u32 op_type : 5;
			/*
			 * Indicates whether SQ CQE or RQ CQE is used.
			 * 1-Send Completion; 0-Receive Completion
			 */
			u32 s_r : 1;
			u32 inline_r : 1; /* Indicates whether the RQ inline;SQ ignores this bit. */
			u32 rsvd : 5;
			u32 msg_fst_wqe_ci : 20;
		} bs;
		u32 value;
	} dw1;

	/* DW2 */
	/*
	 * Indicates the number of transmitted bytes. This field is valid
	 * for the RDMA read and receive
	 * operations. For the recv of RDMA write imm, the value is 0.
	 */
	u32 byte_cnt;

	/* DW3 */
	u32 imm_invalid_rkey; /* The receiving is complete and valid. */

	/* DW4 */
	u32 rsvd;

	/* DW5 */
	u32 wqe_num;

	/* DW6 */
	union {
		struct {
			/*
			 * The for ud only:UD receive end is valid. The 00-packet does
			 * not contain a VLAN ID. The
			 * 01-packet contains a VLAN ID.
			 */
			u32 vlan_pre : 2;
			u32 fl : 1;	   /* This field is valid only for UD. Force loopback */
			u32 stp : 2;
			u32 rsvd : 3;
			/*
			 * The XRC at the receive end is valid. When the XRCSRQ at
			 * the receive end is received,
			 * the ;UD at the remote end refers to the QPN at the remote end.
			 */
			u32 srqn_rqpn : 24;
		} bs;
		u32 value;
	} dw6;

	/* DW7 */
	union {
		struct {
			u32 wqe_cnt : 16; /* WQE index, valid SQ */
			u32 vendor_err : 8;
			/*
			 * 0 indicates that the operation is complete. This parameter is
			 * valid when Op_type is set to ROCE_OPCODE_ERR.
			 * For details about the definition, see the enumeration
			 * roce_cqe_syndrome.
			 */
			u32 syndrome : 8;
		} bs;
		u32 value;
	} dw7;

	u16 srq_container_idx[16];
};

struct roce_nofaa_cqe {
	/* DW0 */
	u32 common_dw0;

	/* DW1 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			/*
			 * The operation type is the same as that of SQ WQE.
			 * For details, see the enumeration
			 * roce_cqe_opcode.
			 */
			u32 op_type : 5;
			/*
			 * Indicates whether SQ CQE or RQ CQE is used.
			 * 1-Send Completion; 0-Receive Completion
			 */
			u32 s_r : 1;
			/* Indicates whether the RQ inline;SQ ignores this bit. */
			u32 inline_r : 1;
			u32 flush_op : 1;
			u32 fake : 1;
			u32 repeat : 1;
			u32 host_id : 2;
			/* The WQEBB index and SQ/RQ/SRQ are valid. */
			u32 wqebb_cnt : 20;
#else
			/* The WQEBB index and SQ/RQ/SRQ are valid. */
			u32 wqebb_cnt : 20;
			u32 host_id : 2;
			u32 repeat : 1;
			/*
			 * Indicates whether this CQE is a fake cqe or not.
			 * when fake = 1, optype & syndronme should be 0
			 */
			u32 fake : 1;
			u32 flush_op : 1;
			/* Indicates whether RQ inline;SQ ignores this bit. */
			u32 inline_r : 1;
			/*
			 * Indicates the SQ CQE or RQ CQE. 1-Send Completion;
			 * 0-Receive Completion
			 */
			u32 s_r : 1;
			/*
			 * The operation type is the same as that of SQ WQE.
			 * For details, see the enumeration roce_cqe_opcode.
			 */
			u32 op_type : 5;
#endif
		} bs;
		u32 value;
	} dw1;

	u32 common_rsvd[13];

	union {
		struct {
			u32 rsvd : 4;
			u32 sw_times : 2;
			u32 sw_slave_id : 6;
			u32 io_time : 20;
		} bs;
		u32 value;
	} io_status;
};

#endif // RDMA_XQE_FORMAT_H
