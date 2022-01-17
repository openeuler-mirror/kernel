/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef SPHW_HW_CFG_H
#define SPHW_HW_CFG_H

#include <linux/types.h>

#define CFG_MAX_CMD_TIMEOUT     30000 /* ms */

enum {
	CFG_FREE = 0,
	CFG_BUSY = 1
};

/* start position for CEQs allocation, Max number of CEQs is 32 */
enum {
	CFG_RDMA_CEQ_BASE       = 0
};

enum {
	SF_SVC_FT_BIT = (1 << 0),
	SF_SVC_RDMA_BIT = (1 << 1),
};

/* RDMA resource */
#define K_UNIT              BIT(10)
#define M_UNIT              BIT(20)
#define G_UNIT              BIT(30)

/* L2NIC */
#define SPHW_CFG_MAX_QP	256

/* RDMA */
#define RDMA_RSVD_QPS       2
#define ROCE_MAX_WQES       (32 * K_UNIT - 1)
#define IWARP_MAX_WQES      (8 * K_UNIT)

#define RDMA_MAX_SQ_SGE     32

#define ROCE_MAX_RQ_SGE     16

#define RDMA_MAX_SQ_DESC_SZ (1 * K_UNIT)

/* (256B(cache_line_len) - 16B(ctrl_seg_len) - 64B(max_task_seg_len)) */
#define ROCE_MAX_SQ_INLINE_DATA_SZ   912

#define ROCE_MAX_RQ_DESC_SZ     256

#define ROCE_QPC_ENTRY_SZ       512

#define WQEBB_SZ                64

#define ROCE_RDMARC_ENTRY_SZ    32
#define ROCE_MAX_QP_INIT_RDMA   128
#define ROCE_MAX_QP_DEST_RDMA   128

#define ROCE_MAX_SRQ_WQES       (16 * K_UNIT - 1)
#define ROCE_RSVD_SRQS          0
#define ROCE_MAX_SRQ_SGE        15
#define ROCE_SRQC_ENTERY_SZ     64

#define RDMA_MAX_CQES       (8 * M_UNIT - 1)
#define RDMA_RSVD_CQS       0

#define RDMA_CQC_ENTRY_SZ   128

#define RDMA_CQE_SZ         64
#define RDMA_RSVD_MRWS      128
#define RDMA_MPT_ENTRY_SZ   64
#define RDMA_NUM_MTTS       (1 * G_UNIT)
#define LOG_MTT_SEG         5
#define MTT_ENTRY_SZ        8
#define LOG_RDMARC_SEG      3

#define LOCAL_ACK_DELAY     15
#define RDMA_NUM_PORTS      1
#define ROCE_MAX_MSG_SZ     (2 * G_UNIT)

#define DB_PAGE_SZ          (4 * K_UNIT)
#define DWQE_SZ             256

#define NUM_PD              (128 * K_UNIT)
#define RSVD_PD             0

#define MAX_XRCDS           (64 * K_UNIT)
#define RSVD_XRCDS          0

#define MAX_GID_PER_PORT    128
#define GID_ENTRY_SZ        32
#define RSVD_LKEY           ((RDMA_RSVD_MRWS - 1) << 8)
#define NUM_COMP_VECTORS    32
#define PAGE_SZ_CAP         ((1UL << 12) | (1UL << 16) | (1UL << 21))
#define ROCE_MODE           1

#define MAX_FRPL_LEN        511
#define MAX_PKEYS           1

/* ToE */
#define TOE_PCTX_SZ         1024
#define TOE_CQC_SZ          64

/* IoE */
#define IOE_PCTX_SZ         512

/* FC */
#define FC_PCTX_SZ          256
#define FC_CCTX_SZ          256
#define FC_SQE_SZ           128
#define FC_SCQC_SZ          64
#define FC_SCQE_SZ          64
#define FC_SRQC_SZ          64
#define FC_SRQE_SZ          32

/* OVS */
#define OVS_PCTX_SZ         512

/* IPsec */
#define IPSEC_SACTX_SZ      512

struct dev_sf_svc_attr {
	bool ft_en;     /* business enable flag (not include RDMA) */
	bool ft_pf_en;  /* In FPGA Test VF resource is in PF or not,
			 * 0 - VF, 1 - PF, VF doesn't need this bit.
			 */
	bool rdma_en;
	bool rdma_pf_en;/* In FPGA Test VF RDMA resource is in PF or not,
			 * 0 - VF, 1 - PF, VF doesn't need this bit.
			 */
};

struct host_shared_resource_cap {
	u32 host_pctxs; /* Parent Context max 1M, IOE and FCoE max 8K flows */
	u32 host_cctxs; /* Child Context: max 8K */
	u32 host_scqs;  /* shared CQ, chip interface module uses 1 SCQ
			 * TOE/IOE/FCoE each uses 1 SCQ
			 * RoCE/IWARP uses multiple SCQs
			 * So 6 SCQ least
			 */
	u32 host_srqs; /* SRQ number: 256K */
	u32 host_mpts; /* MR number:1M */
};

enum intr_type {
	INTR_TYPE_MSIX,
	INTR_TYPE_MSI,
	INTR_TYPE_INT,
	INTR_TYPE_NONE,
	/* PXE,OVS need single thread processing,
	 * synchronization messages must use poll wait mechanism interface
	 */
};

/* service type relates define */
enum cfg_svc_type_en {
	CFG_SVC_NIC_BIT0    = (1 << 0),
	CFG_SVC_ROCE_BIT1   = (1 << 1),
	CFG_SVC_VBS_BIT2    = (1 << 2),
	CFG_SVC_TOE_BIT3    = (1 << 3),
	CFG_SVC_IPSEC_BIT4  = (1 << 4),
	CFG_SVC_FC_BIT5     = (1 << 5),
	CFG_SVC_VIRTIO_BIT6 = (1 << 6),
	CFG_SVC_OVS_BIT7    = (1 << 7),
	CFG_SVC_RSV2_BIT8   = (1 << 8),
	CFG_SVC_IOE_BIT9    = (1 << 9),

	CFG_SVC_FT_EN       = (CFG_SVC_VBS_BIT2 | CFG_SVC_TOE_BIT3 |
			       CFG_SVC_IPSEC_BIT4 | CFG_SVC_FC_BIT5 |
				   CFG_SVC_VIRTIO_BIT6 | CFG_SVC_OVS_BIT7 |
				   CFG_SVC_IOE_BIT9),
	CFG_SVC_RDMA_EN     = CFG_SVC_ROCE_BIT1
};

/* device capability */
struct service_cap {
	struct dev_sf_svc_attr sf_svc_attr;
	enum cfg_svc_type_en svc_type;      /* user input service type */
	enum cfg_svc_type_en chip_svc_type; /* HW supported service type */

	u8 host_id;
	u8 ep_id;
	u8 er_id;       /* PF/VF's ER */
	u8 port_id;     /* PF/VF's physical port */

	/* Host global resources */
	u16 host_total_function;
	u8 pf_num;
	u8 pf_id_start;
	u16 vf_num;	/* max numbers of vf in current host */
	u16 vf_id_start;
	u8 host_oq_id_mask_val;

	u8 flexq_en;
	u8 cos_valid_bitmap;
	u16 max_vf;      /* max VF number that PF supported */

	/* DO NOT get interrupt_type from firmware */
	enum intr_type interrupt_type;

	bool sf_en;     /* stateful business status */
	u8 timer_en;    /* 0:disable, 1:enable */
	u8 bloomfilter_en; /* 0:disable, 1:enable*/

	u8 lb_mode;
	u8 smf_pg;

	/* For test */
	u32 test_mode;
	u32 test_qpc_num;
	u32 test_qpc_resvd_num;
	u32 test_page_size_reorder;
	bool test_xid_alloc_mode;
	bool test_gpa_check_enable;
	u8 test_qpc_alloc_mode;
	u8 test_scqc_alloc_mode;

	u32 test_max_conn_num;
	u32 test_max_cache_conn_num;
	u32 test_scqc_num;
	u32 test_mpt_num;
	u32 test_scq_resvd_num;
	u32 test_mpt_recvd_num;
	u32 test_hash_num;
	u32 test_reorder_num;

	u32 max_connect_num; /* PF/VF maximum connection number(1M) */
	/* The maximum connections which can be stick to cache memory, max 1K */
	u16 max_stick2cache_num;
	/* Starting address in cache memory for bloom filter, 64Bytes aligned */
	u16 bfilter_start_addr;
	/* Length for bloom filter, aligned on 64Bytes. The size is length*64B.
	 * Bloom filter memory size + 1 must be power of 2.
	 * The maximum memory size of bloom filter is 4M
	 */
	u16 bfilter_len;
	/* The size of hash bucket tables, align on 64 entries.
	 * Be used to AND (&) the hash value. Bucket Size +1 must be power of 2.
	 * The maximum number of hash bucket is 4M
	 */
	u16 hash_bucket_num;

	struct host_shared_resource_cap shared_res_cap; /* shared capability */
	struct nic_service_cap      nic_cap;            /* NIC capability */
	struct rdma_service_cap     rdma_cap;           /* RDMA capability */
	struct fc_service_cap       fc_cap;             /* FC capability */
	struct toe_service_cap      toe_cap;            /* ToE capability */
	struct ovs_service_cap      ovs_cap;            /* OVS capability */
	struct ipsec_service_cap    ipsec_cap;          /* IPsec capability */
};

struct cfg_eq {
	enum sphw_service_type type;
	int eqn;
	int free; /* 1 - alocated, 0- freed */
};

struct cfg_eq_info {
	struct cfg_eq *eq;

	u8 num_ceq;

	u8 num_ceq_remain;

	/* mutex used for allocate EQs */
	struct mutex eq_mutex;
};

struct irq_alloc_info_st {
	enum sphw_service_type type;
	int free;                /* 1 - alocated, 0- freed */
	struct irq_info info;
};

struct cfg_irq_info {
	struct irq_alloc_info_st *alloc_info;
	u16 num_total;
	u16 num_irq_remain;
	u16 num_irq_hw;          /* device max irq number */

	/* mutex used for allocate EQs */
	struct mutex irq_mutex;
};

#define VECTOR_THRESHOLD	2

struct cfg_mgmt_info {
	struct sphw_hwdev *hwdev;
	struct service_cap  svc_cap;
	struct cfg_eq_info  eq_info;        /* EQ */
	struct cfg_irq_info irq_param_info; /* IRQ */
	u32 func_seq_num;                   /* temporary */
};

#define IS_NIC_TYPE(dev) \
	(((u32)(dev)->cfg_mgmt->svc_cap.chip_svc_type) & CFG_SVC_NIC_BIT0)
#define IS_ROCE_TYPE(dev) \
	(((u32)(dev)->cfg_mgmt->svc_cap.chip_svc_type) & CFG_SVC_ROCE_BIT1)
#define IS_FCOE_TYPE(dev) \
	(((u32)(dev)->cfg_mgmt->svc_cap.chip_svc_type) & CFG_SVC_FCOE_BIT2)
#define IS_TOE_TYPE(dev) \
	(((u32)(dev)->cfg_mgmt->svc_cap.chip_svc_type) & CFG_SVC_TOE_BIT3)
#define IS_IPSEC_TYPE(dev) \
	(((u32)(dev)->cfg_mgmt->svc_cap.chip_svc_type) & CFG_SVC_IPSEC_BIT4)
#define IS_FC_TYPE(dev) \
	(((u32)(dev)->cfg_mgmt->svc_cap.chip_svc_type) & CFG_SVC_FC_BIT5)
#define IS_FIC_TYPE(dev) \
	(((u32)(dev)->cfg_mgmt->svc_cap.chip_svc_type) & CFG_SVC_FIC_BIT6)
#define IS_OVS_TYPE(dev) \
	(((u32)(dev)->cfg_mgmt->svc_cap.chip_svc_type) & CFG_SVC_OVS_BIT7)
#define IS_ACL_TYPE(dev) \
	(((u32)(dev)->cfg_mgmt->svc_cap.chip_svc_type) & CFG_SVC_ACL_BIT8)
#define IS_IOE_TYPE(dev) \
	(((u32)(dev)->cfg_mgmt->svc_cap.chip_svc_type) & CFG_SVC_IOE_BIT9)
#define IS_FT_TYPE(dev) \
	(((u32)(dev)->cfg_mgmt->svc_cap.chip_svc_type) & CFG_SVC_FT_EN)
#define IS_RDMA_TYPE(dev) \
	(((u32)(dev)->cfg_mgmt->svc_cap.chip_svc_type) & CFG_SVC_RDMA_EN)
#define IS_RDMA_ENABLE(dev) \
	((dev)->cfg_mgmt->svc_cap.sf_svc_attr.rdma_en)

int init_cfg_mgmt(struct sphw_hwdev *dev);

void free_cfg_mgmt(struct sphw_hwdev *dev);

int init_capability(struct sphw_hwdev *dev);

void free_capability(struct sphw_hwdev *dev);

#endif
