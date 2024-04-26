/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef ROCE_WQE_FORMAT_H
#define ROCE_WQE_FORMAT_H

/* **************************************************************** */
struct roce3_wqe_ctrl_seg {
	/* DW0 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 owner : 1;
			u32 ctrlsl : 2;
			u32 csl : 2;
			u32 difsl : 3;
			u32 cr : 1;
			u32 df : 1;
			u32 va : 1;
			u32 tsl : 5;
			u32 cf : 1;
			u32 wf : 1;
			u32 rsvd : 4;
			u32 drvsl : 2;
			u32 bdsl : 8;
#else
			/*
			 * Data segment length, in the unit of 1B. When inline is used,
			 * the length of inline is described. The total length of the
			 * data segment must be aligned to 8B.
			 */
			u32 bdsl : 8;
			/*
			 * Indicates the length of the driver section. The value is
			 * counted by 8B, and the value of RoCE is 0.
			 */
			u32 drvsl : 2;
			u32 rsvd : 4;
			/* 0-Normal WQE, 1-link WQE */
			u32 wf : 1;
			/*
			 * Complete segment format flag. The 0-complete segment directly
			 * contains the status information. 1: SGL
			 */
			u32 cf : 1;
			/*
			 * Length of the task segment. The value ranges from 8 to 48.
			 * The value of RoCE ranges from 8 to 48.
			 */
			u32 tsl : 5;
			/*
			 * SGE address format flag. The 0-SGE contains the physical
			 * address and length. The 1-SGE contains the virtual address,
			 * length, and key. The value of RoCE is 1.
			 */
			u32 va : 1;
			/*
			 * Data segment format flag bit. 0-describes data in SGE format.
			 * 1: Data is described in inline format.
			 */
			u32 df : 1;
			/*
			 * The CQE generates the request flag. The 0-does not
			 * generate the CQE. 1: Generate CQE
			 */
			u32 cr : 1;
			/*
			 * DIF segment length. The value is counted by 8 bytes.
			 * The value of RoCE is 0.
			 */
			u32 difsl : 3;
			/*
			 * Length of the completed segment. The value is counted by 8B.
			 * The value of RoCE is 0.
			 */
			u32 csl : 2;
			/*
			 * Length of the control segment. The value is 8 bytes
			 * and the value of RoCE is 16.
			 */
			u32 ctrlsl : 2;
			/*
			 * Owner bit. The value 1 indicates all hardware, and the value 0
			 * indicates all software. The meaning of the queue owner bit is
			 * reversed every time the queue owner is traversed.
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
			u32 cl : 4;
			u32 signature : 8;
			u32 rsvd : 4;
			u32 mask_pi : 16;
#else
			/*
			 * Pi is the value of the queue depth mask.
			 * It is valid when direct wqe.
			 */
			u32 mask_pi : 16;
			u32 rsvd : 4;
			u32 signature : 8;
			u32 cl : 4; /* The length of CQE is generated in the task segment. */
#endif
		} bs;
		u32 value;
	} dw1;

	/* DW2 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 type : 2;
			u32 rsvd1 : 3;
			u32 cos : 3;
			u32 cp_flag : 1;
			u32 rsvd : 1;
			u32 ctx_size : 2;
			u32 qpn : 20;
#else
			u32 qpn : 20;
			u32 ctx_size : 2; /* RoCE QPC size, 512B */
			u32 rsvd : 1;
			u32 cp_flag : 1; /* control plane flag */
			u32 cos : 3;	 /* Scheduling priority. The value source is SL. */
			u32 rsvd1 : 3;
			u32 type : 2; /* Set RoCE SQ Doorbell to 2 and RoCE Arm CQ Doorbell to 3. */
#endif
		} bs;
		u32 value;
	} dw2;

	/* DW3 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 sub_type : 4;   /*  */
			u32 sgid_index : 7; /* gid index */
			/* 256B:0;512B:1;1024B:2;2048B:3;4096B:4 */
			u32 mtu_shift : 3;
			u32 rsvd : 1;
			/* 1:XRC service type */
			u32 xrc_vld : 1;
			/* host sw write the sq produce index high 8bit to this section; */
			u32 pi : 16;
#else
			/* host sw write the sq produce index high 8bit to this section; */
			u32 pi : 16;
			u32 xrc_vld : 1;
			u32 rsvd : 1;
			u32 mtu_shift : 3;
			u32 sgid_index : 7;
			u32 sub_type : 4;
#endif
		} bs;
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 queue_id : 4;
			u32 rsvd : 12;
			u32 pi : 16;
#else
			u32 pi : 16;
			u32 rsvd : 12;
			u32 queue_id : 4;
#endif
		} bs1;
		u32 value;
	} dw3;
};

union roce3_wqe_tsk_com_seg {
	struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
		u32 se : 1;
		u32 f : 1;
		u32 c : 1;
		u32 op_type : 5;
		u32 so : 1;
		u32 cs_len_mul : 3;
		u32 dif_en : 1;
		u32 ext_vld : 1;
		u32 xrc_srqn : 18;
#else
		/* The XRC is valid, and the remote SRQN is specified. */
		u32 xrc_srqn : 18;
		u32 ext_vld : 1;
		u32 dif_en : 1;
		/* * atomic cmp swap N len:atomic datalen=8*(cs_len_mul + 1) */
		u32 cs_len_mul : 3;
		/*
		 * Strong order-preserving flag, valid only for Local invalidate\Type
		 * 2 Bind MW and FRPMR (consider the implementation at the bottom layer)
		 */
		u32 so : 1;
		/*
		 * Operation type of the SQ WQE.
		 * 8'h00-Send
		 * 8'h01-Send with Invalidate
		 * 8'h02-Send with Immediate Data
		 * 8'h03-rsvd
		 * 8'h04-RDMA Write
		 * 8'h05-RDMA Write with Immediate Data
		 * 8'h06-RDMA WRITE CMD64
		 * 8'h07-rsvd
		 * 8'h08-RDMA READ
		 * 8'h09-ATOMIC WRITE
		 * 8'h0a-FLUSH
		 * 8'h0b-rsvd
		 * 8'h0c-Atomic compare & swap
		 * 8'h0d-Atomic Fetch & ADD
		 * 8'h0e-Atomic Masked Compare & Swap (Extended Atomic operation)
		 * 8'h0f-Atomic Masked Fetch & Add (Extended Atomic operation)
		 * 8'h10-Fast Register PMR
		 * 8'h11-Local Invalidate
		 * 8'h12-Bind Memory Window Type1/2
		 * 8'h13-Local operation(extended for further local operation)
		 * other-Reserved
		 */
		u32 op_type : 5;
		/*
		 * Indicates whether the SQ generates the CQE,
		 * which is required by the microcode.
		 */
		u32 c : 1;
		/* Indicates whether the SQ requires order-preserving. */
		u32 f : 1;
		/* Indicates whether the packet carries the SE flag. */
		u32 se : 1;
#endif
	} bs;
	struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
		u32 se : 1;
		u32 f : 1;
		u32 c : 1;
		u32 op_type : 5;
		u32 so : 1;
		u32 rsvd : 2;
		u32 vbs_vld : 1;
		u32 dif_en : 1;
		u32 ext_vld : 1;
		u32 xrc_srqn : 18;
#else
		u32 xrc_srqn : 18;
		u32 ext_vld : 1;
		u32 dif_en : 1;
		u32 vbs_vld : 1;
		u32 rsvd : 2;
		u32 so : 1;
		u32 op_type : 5;
		u32 c : 1;
		u32 f : 1;
		u32 se : 1;
#endif
	} bs1;
	struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
		u32 rsvd : 14;
		u32 sticky : 1;
		u32 repeat : 1;
		u32 cmdid : 16;
#else
		u32 cmdid : 16;
		u32 repeat : 1;
		u32 sticky : 1;
		u32 rsvd : 14;
#endif
	} nofaa;
	u32 value;
};

union roce3_wqe_tsk_misc_seg {
	struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
		u32 ext_last : 1;
		u32 nxt_ext_hdr : 7;
		u32 cmd_len : 8;
		u32 rsvd : 8;
		u32 last_ext_len : 8;
#else
		u32 last_ext_len : 8;
		u32 rsvd : 8;
		u32 cmd_len : 8;
		u32 nxt_ext_hdr : 7;
		u32 ext_last : 1;
#endif
	} bs;

	u32 value;
};

struct roce3_wqe_tsk_rdma_sge_seg {
	/* DW4~5 */
	union {
		u64 va;
		struct {
			u32 va_h32;
			u32 va_l32;
		} dw4;
	};

	/* DW6 */
	u32 rkey;

	/* DW7 */
	u32 sig_key;
};

/* *
 * Struct name:	  sq_wqe_task_remote_common.
 * @brief :		  SQ WQE common.
 * Description:
 */
struct tag_sq_wqe_task_remote_common {
	union roce3_wqe_tsk_com_seg common;

	u32 data_len; /* SQ WQE DMA LEN */

	u32 immdata_invkey; /* SEND invalidate or immediate */

	union roce3_wqe_tsk_misc_seg dw3;
};

/* Send WQE/Send with imme WQE/Send with invalid(inline or not inline) */
struct roce3_wqe_send_tsk_seg {
	union roce3_wqe_tsk_com_seg common;

	/* DW1 */
	u32 data_len; /* Length of the data sent by the SQ WQE */

	/* DW2 */
	/*
	 * This parameter is valid for the immediate
	 * data operation or SEND invalidate.
	 */
	u32 immdata_invkey;

	/* DW3 */
	union roce3_wqe_tsk_misc_seg dw3;
};

/* RDMA Read WQE/RDMA Write WQE/RDMA Write with imme WQE(inline or non-inline) */
struct roce3_wqe_rdma_tsk_seg {
	union roce3_wqe_tsk_com_seg common;

	/* DW1 */
	u32 data_len;

	/* DW2 */
	u32 imm_data;

	/* DW3 */
	union roce3_wqe_tsk_misc_seg dw3;

	/* DW4~5 */
	union {
		u64 va;
		struct {
			u32 va_h32;
			u32 va_l32;
		} dw4;
	};

	/* DW6 */
	u32 rkey;

	/* DW7 */
	u32 sig_key;
};

/* RDMA Read WQE/RDMA Write WQE/RDMA Write with imme WQE(inline or non-inline) */
struct roce3_wqe_rdma_ext_tsk_seg {
	union roce3_wqe_tsk_com_seg common;

	/* DW1 */
	u32 data_len;

	/* DW2 */
	u32 imm_data;

	/* DW3 */
	union roce3_wqe_tsk_misc_seg dw3;

	/* DW4~5 */
	struct roce3_wqe_tsk_rdma_sge_seg rdma;

	u32 ulp_cmd[24];
};

/* Atomic WQE */
struct roce3_wqe_atomic_tsk_seg {
	union roce3_wqe_tsk_com_seg common;

	/* DW1 */
	u32 key;

	/* DW2~3 */
	union {
		u64 va;
		struct {
			u32 va_h32;
			u32 va_l32;
		} dw2;
	};

	/* DW4~5 */
	union {
		u64 swap_add_data;
		struct {
			u32 swap_add_data_h32;
			u32 swap_add_data_l32;
		} dw4;
	};

	/* DW6~7 */
	union {
		u64 cmp_data;
		struct {
			u32 cmp_data_h32;
			u32 cmp_data_l32;
		} dw6;
	};
};

/* ext Atomic WQE */
#define ROCE_WQE_ATOMIC_DATA_SIZE 32
#define ROCE_WQE_ATOMIC_DATA_SIZE_2B_ALIGN (ROCE_WQE_ATOMIC_DATA_SIZE >> 1)
struct roce3_wqe_ext_atomic_tsk_seg {
	union roce3_wqe_tsk_com_seg common;

	/* DW1 */
	u32 key;

	/* DW2~3 */
	union {
		u64 va;
		struct {
			u32 va_h32;
			u32 va_l32;
		} dw2;
	};

	u32 atomic_data[ROCE_WQE_ATOMIC_DATA_SIZE];
};

/* Mask Atomic WQE */
struct roce3_wqe_mask_atomic_tsk_seg {
	union roce3_wqe_tsk_com_seg common;

	/* DW1 */
	u32 rkey;

	/* DW2~3 */
	union {
		u64 va;
		struct {
			u32 va_h32;
			u32 va_l32;
		} dw2;
	};

	/* DW4~5 */
	union {
		u64 swap_add_data;
		struct {
			u32 swap_add_data_h32;
			u32 swap_add_data_l32;
		} dw4;
	};

	/* DW6~7 */
	union {
		u64 cmp_data;
		struct {
			u32 cmp_data_h32;
			u32 cmp_data_l32;
		} dw6;
	};

	/* DW8~9 */
	union {
		u64 swap_msk;
		struct {
			u32 swap_msk_h32;
			u32 swap_msk_l32;
		} dw8;
	};

	/* DW9~10 */
	union {
		u64 cmp_msk;
		struct {
			u32 cmp_msk_h32;
			u32 cmp_msk_l32;
		} dw10;
	};
};

/* UD send WQE */
struct roce3_wqe_ud_tsk_seg {
	union roce3_wqe_tsk_com_seg common;

	/* DW1 */
	u32 data_len;

	/* DW2 */
	u32 immdata_invkey;

	union roce3_wqe_tsk_misc_seg dw2;

	/* DW4 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 fl : 1;
			/* DB cos or Path cos or MQM cos */
			u32 wqe_cos : 3;
			u32 stat_rate : 4;
			u32 rsvd : 6;
			u32 pd : 18;
#else
			u32 pd : 18; /* Used to verify the PD in the QPC. */
			u32 rsvd : 6;
			/* Maximum static rate control 0:
			 * No limit on the static rate (100% port speed)
			 * 1-6: reserved
			 * 7: 2.5 Gb/s.  8: 10 Gb/s.  9: 30 Gb/s. 10: 5 Gb/s. 11: 20 Gb/s.
			 * 12: 40 Gb/s. 13: 60 Gb/s. 14: 80 Gb/s.15: 120 Gb/s.
			 */
			u32 stat_rate : 4;
			/* DB cos or Path cos or MQM cos */
			u32 wqe_cos : 3;
			u32 fl : 1;
#endif
		} bs;
		u32 value;
	} dw3;

	/* DW4 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 tc : 8;
			u32 rsvd : 4;
			u32 port : 4;
			u32 vlan_en : 1;
			u32 sgid_idx : 7;
			u32 hop_limit : 8;
#else
			u32 hop_limit : 8;
			u32 sgid_idx : 7;
			u32 vlan_en : 1;
			u32 port : 4;
			u32 rsvd : 4;
			u32 tc : 8;
#endif
		} bs;
		u32 value;
	} dw4;

	/* DW5 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd : 2;
			u32 smac_index : 10;
			u32 flow_label : 20;
#else
			u32 flow_label : 20;
			u32 smac_index : 10;
			u32 rsvd : 2;
#endif
		} bs;
		u32 value;
	} dw5;

	/* DW6~9 */
	u8 dgid[16];

	/* DW10 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd : 8;
			u32 dst_qp : 24;
#else
			u32 dst_qp : 24;
			u32 rsvd : 8;
#endif
		} bs;
		u32 value;
	} dw10;

	/* DW11 */
	u32 qkey;

	/* DW12 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 vlan_pri : 3; /* send pkt pri */
			u32 cfi : 1;
			u32 vlan_id : 12;
			u32 dmac_h16 : 16;
#else
			u32 dmac_h16 : 16;
			u32 vlan_id : 12;
			u32 cfi : 1;
			u32 vlan_pri : 3; /* send pkt pri */
#endif
		} bs;
		u32 value;
	} dw12;

	/* DW14 */
	u32 dmac_l32;

	/* DW15 */
	u32 rsvd;
};

struct roce3_wqe_data_seg {
	/* DW0~1 */
	union {
		u64 addr;
		struct {
			u32 addr_h32;
			u32 addr_l32;
		} bs;
	};

	/* DW2~3 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rsvd : 1;
			u32 len : 31;
#else
			u32 len : 31;
			u32 rsvd : 1;
#endif
		} bs;
		u32 value;
	} dw2;

	/* DW4 */
	u32 key;
};

/* Type1/2 MW Bind WQE */
struct roce3_wqe_bind_tsk_seg {
	union roce3_wqe_tsk_com_seg common;

	/* DW0~2 */
	u32 rsvd0[3];

	/* DW3 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rae : 1;
			u32 rwe : 1;
			u32 rre : 1;
			u32 type : 1;
			u32 rsvd : 28;
#else
			u32 rsvd : 28;
			/* MW type: 0-Type1 Window 1-Type2B Window */
			u32 type : 1;
			u32 rre : 1;  /* Remote read enable */
			u32 rwe : 1;  /* Remote write enable */
			/* Indicates whether remote Atomic is enabled. */
			u32 rae : 1;
#endif
		} bs;
		u32 value;
	} dw3;

	/* DW4 */
	/*
	 * The MW corresponds to the MPT key and is indexed to the MPT
	 * through the New_Rkey. For the type1 MW, This parameter is
	 * valid only when the value of New_Rkey is the same as the
	 * value of mem_key in the MPT. For type 2 MW, it is valid only
	 * when New_Rkey is equal to mem_key+1 in MPT. If this parameter
	 * is valid, the corresponding field in the MPT is replaced with
	 * the entire section.
	 */
	u32 new_rkey;

	/* DW5 */
	/* Indicates the mem_key of the MR bound to the MW. */
	u32 lkey;

	/* DW6 */
	u32 rsvd1;

	/* DW7~8 */
	union {
		/* Indicates the start virtual IP address of the MW. */
		u64 va;
		struct {
			u32 va_h32;
			u32 va_l32;
		} bs;
	} dw7;

	/* DW9~10 */
	union {
		/* Indicates the length of the data corresponding to the MW. */
		u64 len;
		struct {
			u32 len_h32;
			u32 len_l32;
		} bs;
	} dw9;
};

/* Fast Register PMR WQE */
struct roce3_wqe_frmr_tsk_seg {
	union roce3_wqe_tsk_com_seg common;

	/* DW0~1 */
	u32 rsvd[2];

	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 fbo : 22;
			u32 rsvd : 10;
#else
			u32 rsvd : 10;
			/* This parameter is valid when ZERO_BASE is set to 1. */
			u32 fbo : 22;
#endif
		} bs;
		u32 value;
	} dw2;

	/* DW3 */
	union {
		struct {
#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && ((BYTE_ORDER == BIG_ENDIAN))
			u32 rae : 1;
			u32 rwe : 1;
			u32 rre : 1;
			u32 lwe : 1;
			u32 lre : 1;
			u32 be : 1;
			u32 zbva : 1;
			u32 block : 1;
			u32 rsvd : 2;
			u32 page_size : 6;
			u32 pa_num : 16;
#else
			/*
			 * Number of registered PAs, which is calculated
			 * by the length/page_size.
			 */
			u32 pa_num : 16;
			u32 page_size : 6; /* Memory Region page size */
			u32 rsvd : 2;
			u32 block : 1;
			u32 zbva : 1; /* ZERO_BASED Permission */
			/* Indicates whether the binding operation is enabled. */
			u32 be : 1;
			u32 lre : 1;  /* Local read enable */
			u32 lwe : 1;  /* Local write enable */
			u32 rre : 1;  /* Remote read enable */
			u32 rwe : 1;  /* Remote write enable */
			/* Indicates whether remote Atomic is enabled. */
			u32 rae : 1;
#endif
		} bs;
		u32 value;
	} dw3;

	/* DW4 */
	u32 m_key; /* Key of the Memory Region. */

	/* DW5~6 */
	union {
		/*
		 * Start virtual address of Memory Region.
		 * This parameter is valid only when ZBVA is not set to 1.
		 */
		u64 va;
		struct {
			u32 va_h32;
			u32 va_l32;
		} bs;
	} dw5;

	/* DW7~8 */
	union {
		u64 len; /* Length of Memory Region */
		struct {
			u32 len_h32;
			u32 len_l32;
		} bs;
	} dw7;

	/* DW9~10 */
	union {
		/* Physical address for storing the cache of the PA table. */
		u64 pbl_addr;
		struct {
			u32 pbl_addr_h32;
			u32 pbl_addr_l32;
		} bs;
	} dw9;
};

struct roce3_sge_info {
	union {
		u64 sge_vaddr;
		struct {
			u32 sge_vaddr_hi;
			u32 sge_vaddr_lo;
		} bs;
	} dw0;

	u32 sge_length;
	u32 sge_key;
};


/* Local Invalidate WQE */
struct roce3_wqe_local_inv_tsk_seg {
	union roce3_wqe_tsk_com_seg common;

	/* DW0 */
	u32 rsvd;

	/* DW1 */
	u32 inv_key; /* Mem_Key for invalidate */

	/* DW2 */
	u32 rsvd1;
};

/* * SRQ Data Format start */
struct roce3_wqe_srq_data_seg {
	/* DW0~1 */
	union {
		u64 addr;

		struct {
			u32 addr_h32;
			u32 addr_l32;
		} bs;
	};

	/* DW2 */
	union {
		struct {
			/* Reserved field */
			u32 rsv : 1;
			/* Data length. The value can be [0 or 2G-1]. */
			u32 len : 31;
		} bs;
		u32 length;
	} dw2;

	/* DW3 */
	union {
		struct {
			/*
			 * Last flag. The 0-also has the next SGE.
			 * 1: The current SGE is the last one.
			 */
			u32 last : 1;
			/*
			 * Extended flag. The value 0-is normal and does not need to be extended.
			 * 1: Extended mode. The address of the current SGE points to SGL.
			 * The key and len are invalid. For RoCE, the value is fixed to 0.
			 */
			u32 ext : 1;
			/*
			 * Local_key. The least significant eight bits are keys,
			 * and the most significant 22 bits are
			 * indexes. The most significant two bits are reserved and only
			 * 20 bits are used.
			 */
			u32 key : 30;
		} bs;
		u32 lkey;
	} dw3;
};
/* * SRQ Data Format end */

struct roce_osd_srq_link_wqe {
	u32 cont_gpa_h;

	union {
		struct {
			u32 cont_gpa_l : 24;
			u32 rsvd : 8;
		} bs;
		u32 value;
	} dw1;

	u32 rsvd;

	union {
		struct {
			u32 rsvd : 1;
			u32 link_flag : 1;
			u32 rsvd1 : 30;
		} bs;
		u32 value;
	} dw3;

	union {
		struct {
			u32 cur_container_idx : 16;
			u32 container_idx : 16;
		} bs;
		u32 value;
	} dw4;
};


#endif // ROCE_WQE_FORMAT_H
