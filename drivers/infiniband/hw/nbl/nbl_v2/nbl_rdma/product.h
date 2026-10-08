/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2026, NEBULARMATRIX */

#ifndef NBL_PRODUCT_H
#define NBL_PRODUCT_H

#include <linux/bitops.h>
#include <linux/types.h>

enum host_id_type {
	HOST_ID_TYPE_HOST = 1,
	HOST_ID_TYPE_ECPU = 2,
	HOST_ID_TYPE_MAX,
};

enum nbl_product_type {
	PRODUCT_TYPE_SNIC = 0,
	PRODUCT_TYPE_DPU = 1,
	PRODUCT_TYPE_MAX,
};

enum nbl_product_function_type {
	NBL_PRODUCT_FUNCTION_PF,
	NBL_PRODUCT_FUNCTION_VF,
	NBL_PRODUCT_FUNCTION_MAX,
};

enum nbl_rnic_sub_type {
	RNIC_SUB_TYPE_NONE = 0x0,
	RNIC_SUB_TYPE_1X400 = 0x1,
	RNIC_SUB_TYPE_2X200 = 0x2,
	/* 0x3 not used */
	RNIC_SUB_TYPE_B300_4X100 = 0x4,
	RNIC_SUB_TYPE_B300_2X200 = 0x5,
	RNIC_SUB_TYPE_B300_1X400 = 0x6,
	RNIC_SUB_TYPE_MAX,
};

enum nbl_product_id {
	NBL_PRODUCT_ID_DF200_ECPU,
	NBL_PRODUCT_ID_DF200_HOST,
	NBL_PRODUCT_ID_DRACO_PF,
	NBL_PRODUCT_ID_DRACO_VF,
	NBL_PRODUCT_ID_RNIC400_PF,
	NBL_PRODUCT_ID_ORION_PF,
	NBL_PRODUCT_ID_ORION_VF,
	NBL_PRODUCT_ID_MAX,
};

enum nbl_product_flags {
	NBL_PRODUCT_F_RESV_RES = BIT(0),
	NBL_PRODUCT_F_CTRL_DEV = BIT(1),
	NBL_PRODUCT_F_INIT_SD_DIRECT = BIT(2),
	NBL_PRODUCT_F_RX_VLAN_VSI_MAP = BIT(3),
	NBL_PRODUCT_F_ABNORMAL_EVENT = BIT(4),
	NBL_PRODUCT_F_FW_VER_REG = BIT(5),
	NBL_PRODUCT_F_DIRECT_RW_REG = BIT(6),
	NBL_PRODUCT_F_CPU_FWD_DEFAULT = BIT(7),
	NBL_PRODUCT_F_LAG_MIRROR_CFG = BIT(8),
};

enum nbl_product_cap {
	NBL_PRODUCT_CAP_PT = BIT_ULL(0),
	NBL_PRODUCT_CAP_MPLANE_SPRAY = BIT_ULL(1),
	NBL_PRODUCT_CAP_SRQ = BIT_ULL(2),
	NBL_PRODUCT_CAP_UMR = BIT_ULL(3),
	NBL_PRODUCT_CAP_ATOMIC = BIT_ULL(4),
	NBL_PRODUCT_CAP_SHARED_CQP = BIT_ULL(5),
	NBL_PRODUCT_CAP_BAR4_NOTIFY = BIT_ULL(6),
	NBL_PRODUCT_CAP_PF_NOTIFY = BIT_ULL(7),
	NBL_PRODUCT_CAP_MR_BRANCH = BIT_ULL(8),
	NBL_PRODUCT_CAP_DEVX = BIT_ULL(9),
	NBL_PRODUCT_CAP_SRP = BIT_ULL(10),
	NBL_PRODUCT_CAP_SLOW_PATH = BIT_ULL(11),
	NBL_PRODUCT_CAP_DSCH_DPORT_UPDATE = BIT_ULL(12),
	NBL_PRODUCT_CAP_CHG_PKT_UDP_PORT = BIT_ULL(13),
	NBL_PRODUCT_CAP_CHG_PSN_OST = BIT_ULL(14),
	NBL_PRODUCT_CAP_QPN_ALLOC_INTERVAL = BIT_ULL(15),
	NBL_PRODUCT_CAP_WRITE_ATOMIC_FENCE = BIT_ULL(16),
};

#define NBL_PRODUCT_CAPS_MASK		(NBL_PRODUCT_CAP_PT | \
					 NBL_PRODUCT_CAP_MPLANE_SPRAY | \
					 NBL_PRODUCT_CAP_SRQ | \
					 NBL_PRODUCT_CAP_UMR | \
					 NBL_PRODUCT_CAP_ATOMIC | \
					 NBL_PRODUCT_CAP_SHARED_CQP | \
					 NBL_PRODUCT_CAP_BAR4_NOTIFY | \
					 NBL_PRODUCT_CAP_PF_NOTIFY | \
					 NBL_PRODUCT_CAP_MR_BRANCH | \
					 NBL_PRODUCT_CAP_DEVX | \
					 NBL_PRODUCT_CAP_SRP | \
					 NBL_PRODUCT_CAP_SLOW_PATH | \
					 NBL_PRODUCT_CAP_DSCH_DPORT_UPDATE | \
					 NBL_PRODUCT_CAP_CHG_PKT_UDP_PORT | \
					 NBL_PRODUCT_CAP_CHG_PSN_OST | \
					 NBL_PRODUCT_CAP_QPN_ALLOC_INTERVAL | \
					 NBL_PRODUCT_CAP_WRITE_ATOMIC_FENCE)
#define NBL_PRODUCT_FW_CAPS_MASK	(NBL_PRODUCT_CAP_PT | \
					 NBL_PRODUCT_CAP_MPLANE_SPRAY)

struct nbl_product_limits {
	u64 max_mr_size;
	/* Hardware ceilings before per-function VOA resource distribution. */
	u32 max_total_qps;
	u32 max_total_cqs;
	u32 max_total_pbls;
	u32 max_total_mrs;
	u32 max_total_srqs;
	u32 max_pds;
	u32 max_ahs;
	u32 max_qp_wr;
	u32 max_srq_wr;
	u32 max_aeq_entries;
	u32 max_ceq_entries;
	u16 min_aeq_entries;
	u16 min_ceq_entries;
	u16 min_cq_size;
	u32 max_cq_size;
	u16 min_ceqs;
	u16 max_ceqs;
	u16 gid_per_function;
	u16 qpcc_depth;
	u16 cqcc_depth;
	u16 mrtc_depth;
	u16 srqc_depth;
	u16 pblc_depth;
	u16 sqrqec_depth;
	u16 irqec_depth;
	u16 raqec_depth;
	u16 unaqec_depth;
	u16 pdc_depth;
	u16 orqec_depth;
	u16 max_inline_data;
	u16 max_ud_inline_data;
	u16 sq_ost_count;
	u8 max_wqe_quanta;
	u8 max_sge;
	u8 max_read_sge;
	u8 rd_atomic_shift;
	u8 max_rd_atomic;
	u8 pble_count_align;
};

struct nbl_dsch_layout {
	u32 net_en_offset;
	u16 min_net_shaping_id;
	u16 min_grp_shaping_id;
	u16 dport_table_depth;
	bool direct_init;
};

struct nbl_stats_layout {
	u32 group_count;
	u32 entry_count;
	u32 opcode_count;
	u32 error_count;
	bool extended_opcode;
};

struct nbl_debug_layout {
	bool ext_qpc_v4; /* new version qpc ext some fields */
};

struct nbl_pci_f;
struct nbl_cq;
struct nbl_device;
struct nbl_qp_ctx;
struct nbl_register_layout;
struct nbl_resource_ops;

/* set_cq_moderation is required exactly when cq_moderation_supported is true. */
struct nbl_cq_ops {
	int (*set_cq_moderation)(struct nbl_pci_f *rf, struct nbl_cq *cq,
				 u16 cq_count, u16 cq_period);
	bool cq_moderation_supported;
};

/*
 * Required callbacks: update_p2s_cfg, set_pfc_en, set_pfc_buf, get_pfc_cfg,
 * trust_dscp_en, get_reg_offset, debugfs_param_supported and default_cfg.
 * Optional callbacks: set_tc_pri, check_spwrr_cfg, set_pkt2pri and
 * get_pkt2pri_cfg may be NULL.
 */
struct nbl_qos_ops {
	int (*update_p2s_cfg)(struct nbl_device *dev, const u32 *p2s_map);
	int (*set_tc_pri)(struct nbl_device *dev, u32 *var);
	int (*set_pfc_en)(struct nbl_device *dev, u32 *var);
	int (*check_spwrr_cfg)(struct nbl_device *dev, u32 *var);
	int (*set_pfc_buf)(struct nbl_device *dev, u32 *var);
	int (*set_pkt2pri)(struct nbl_device *dev, bool is_dscp,
			   u32 *var, u32 dport_id);
	int (*get_pfc_cfg)(struct nbl_device *dev, char *buf);
	int (*get_pkt2pri_cfg)(struct nbl_device *dev, char *buf);
	int (*trust_dscp_en)(struct nbl_device *dev, u32 enable,
			     u32 dport_id);
	u32 (*get_reg_offset)(struct nbl_pci_f *rf, int offset);
	bool (*debugfs_param_supported)(int offset);
	void (*default_cfg)(struct nbl_device *dev);
};

/*
 * Required callbacks: debugfs_param_supported and default_param_supported.
 * Optional callbacks: update_cc_mode, init_default_params and
 * init_default_regs may be NULL.
 */
struct nbl_congestion_ops {
	void (*update_cc_mode)(struct nbl_device *dev, u32 mode);
	bool (*debugfs_param_supported)(int offset);
	void (*init_default_params)(struct nbl_device *dev, int *params);
	bool (*default_param_supported)(int offset);
	void (*init_default_regs)(struct nbl_device *dev);
};

/* Both QPC callbacks are required. iorqe_size and default_raq_wqe_cap must be set. */
struct nbl_qpc_ops {
	void (*set_rxp_req_pre_hwqpc)(__be64 *qp_ctx, u32 opcode);
	void (*set_qcn_hwqpc)(__be64 *qp_ctx, const struct nbl_qp_ctx *ctx_info);
	u32 iorqe_size;
	u8 default_raq_wqe_cap;
	u8 rnr_timer_when_set_zero;
};

/*
 * The ops table is required. Each callback pair is required exactly when its
 * matching UMR or PT capability is set; otherwise both callbacks must be NULL.
 */
struct nbl_feature_ops {
	int (*umr_resource_init)(struct nbl_device *dev);
	void (*umr_resource_cleanup)(struct nbl_device *dev);
	int (*pt_debugfs_init)(struct nbl_device *dev);
	void (*pt_debugfs_cleanup)(struct nbl_device *dev);
};

/* set_cfg is required. */
struct nbl_dump_ops {
	int (*set_cfg)(struct nbl_pci_f *rf, bool enable);
};

/* All GID callbacks are required. */
struct nbl_gid_ops {
	int (*alloc_index)(struct nbl_device *dev, u16 *src_addr_index);
	int (*free_index)(struct nbl_device *dev, u16 sgid_index,
			  u16 src_addr_index);
	int (*get_info)(const struct nbl_device *dev, u16 gid_index,
			u16 *src_addr_index, u8 *src_ip, u8 *seq_num);
	int (*set_entry)(struct nbl_device *dev, u16 src_addr_index,
			 u16 sgid_index, const u8 *gid, const u8 *mac,
			 u8 seq_num);
	void (*fill_table)(struct nbl_device *dev, u16 src_addr_index,
			   u16 sgid_index, const u8 *gid, u8 *seq_num);
	int (*clear_table)(const struct nbl_device *dev, u16 sgid_index,
			   u16 src_addr_index);
	void (*update_index)(struct nbl_pci_f *rf, u16 src_addr_index,
			     u16 sgid_index);
};

/*
 * Required callbacks: get_global_msix_idx, aeq_qp_event_valid, nbl_dis_irq
 * and nbl_en_irq. nbl_umask_irq is optional and may be NULL.
 */
struct nbl_irq_ops {
	void (*get_global_msix_idx)(struct nbl_pci_f *rf,
				    u16 *global_msix_idx, u16 msix_cnt);
	bool (*aeq_qp_event_valid)(u8 event_seq, int qp_seq);
	void (*nbl_dis_irq)(struct nbl_pci_f *rf, u32 idx);
	void (*nbl_en_irq)(struct nbl_pci_f *rf, u32 idx);
	void (*nbl_umask_irq)(struct nbl_pci_f *rf, u32 idx);
};

/* set_mtu is required. */
struct nbl_fun_ops {
	void (*set_mtu)(struct nbl_device *dev, int vsi_id, int mtu);
};

/* All lifecycle callbacks are required; none may be NULL. */
struct nbl_lifecycle_ops {
	void (*init_global_cfg)(struct nbl_pci_f *rf);
	void (*detect_caps)(struct nbl_pci_f *rf);
	int (*channel_init)(struct nbl_pci_f *rf);
	void (*channel_exit)(struct nbl_pci_f *rf);
	int (*get_function_id)(struct nbl_pci_f *rf);
	int (*free_function_id)(struct nbl_pci_f *rf);
	int (*register_client)(struct nbl_pci_f *rf, bool is_register);
	int (*set_notify)(struct nbl_pci_f *rf, bool valid);
	void (*reset_rdma)(struct nbl_pci_f *rf);
};

struct nbl_product_desc {
	const char *name;
	enum nbl_product_id id;
	u8 hw_rev;
	enum host_id_type host_id;
	enum nbl_product_type product_type;
	enum nbl_product_function_type function_type;
	u32 flags;
	u64 base_caps;
	const struct nbl_product_limits *limits;
	const struct nbl_register_layout *regs;
	struct nbl_dsch_layout dsch_layout;
	const struct nbl_stats_layout *stats;
	struct nbl_debug_layout debug_layout;
	/* All ops-table pointers below are required. */
	const struct nbl_gid_ops *gid_ops;
	const struct nbl_lifecycle_ops *lifecycle_ops;
	const struct nbl_fun_ops *fun_ops;
	const struct nbl_resource_ops *resource_ops;
	const struct nbl_irq_ops *irq_ops;
	const struct nbl_feature_ops *feature_ops;
	const struct nbl_dump_ops *dump_ops;
	const struct nbl_cq_ops *cq_ops;
	const struct nbl_qpc_ops *qpc_ops;
	const struct nbl_qos_ops *qos_ops;
	const struct nbl_congestion_ops *congestion_ops;
};

struct nbl_product_runtime_info {
	enum nbl_rnic_sub_type sub_type;
};

struct nbl_cqp_ops;
struct nbl_rdma_dev_ops;

bool nbl_product_cap_enabled(const struct nbl_pci_f *rf,
			     enum nbl_product_cap cap);
bool nbl_product_flag_enabled(const struct nbl_pci_f *rf,
			      enum nbl_product_flags flag);
enum nbl_rnic_sub_type nbl_product_get_sub_type(const struct nbl_pci_f *rf);
void nbl_product_set_cap(struct nbl_pci_f *rf,
			 enum nbl_product_cap cap, bool enable);
void nbl_product_apply_fw_caps(struct nbl_pci_f *rf, u64 fw_caps);

#endif /* NBL_PRODUCT_H */
