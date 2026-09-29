/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2015 - 2022 Wangxun Corporation */
#ifndef NSER_TYPE_H
#define NSER_TYPE_H

#include "osdep.h"
#include "nser.h"
#include "user.h"
#include "hmc.h"
#include "uda.h"
#include "vf.h"
#include "ws.h"
#include "virtchnl.h"
#define NSER_DEBUG_ERR		"ERR"
#define NSER_DEBUG_INIT	"INIT"
#define NSER_DEBUG_DEV		"DEV"
#define NSER_DEBUG_VERBS	"VERBS"
#define NSER_DEBUG_QP		"QP"
#define NSER_DEBUG_CQ		"CQ"
#define NSER_DEBUG_MR		"MR"
#define NSER_DEBUG_PBLE	"PBLE"
#define NSER_DEBUG_WQE		"WQE"
#define NSER_DEBUG_AEQ		"AEQ"
#define NSER_DEBUG_CQP		"CQP"
#define NSER_DEBUG_HMC		"HMC"
#define NSER_DEBUG_USER	"USER"
#define NSER_DEBUG_VIRT	"VIRT"
#define NSER_DEBUG_DCB		"DCB"
#define	NSER_DEBUG_CQE		"CQE"
#define NSER_DEBUG_CLNT	"CLNT"
#define NSER_DEBUG_WS		"WS"
#define NSER_DEBUG_STATS	"STATS"

enum nser_page_size {
	NSER_PAGE_SIZE_4K = 0,
	NSER_PAGE_SIZE_2M,
	NSER_PAGE_SIZE_1G,
};

enum nser_qp_event_type {
	NSER_QP_EVENT_CATASTROPHIC,
	NSER_QP_EVENT_ACCESS_ERR,
	NSER_QP_EVENT_REQ_ERR,
};

enum nser_hw_stats_index {

	NSER_HW_STAT_INDEX_RX_VLAN_ERR			= 0,

	NSER_HW_STAT_INDEX_IPV4_RX_OCTS			= 1,
	NSER_HW_STAT_INDEX_IPV4_RX_PKTS			= 2,
	NSER_HW_STAT_INDEX_IPV4_RX_DISCARD		= 3,
	NSER_HW_STAT_INDEX_IPV4_RX_MCOCTS		= 4,
	NSER_HW_STAT_INDEX_IPV4_RX_MCPKTS		= 5,

	NSER_HW_STAT_INDEX_IPV6_RX_OCTS			= 6,
	NSER_HW_STAT_INDEX_IPV6_RX_PKTS			= 7,
	NSER_HW_STAT_INDEX_IPV6_RX_DISCARD		= 8,
	NSER_HW_STAT_INDEX_IPV6_RX_MCOCTS		= 9,
	NSER_HW_STAT_INDEX_IPV6_RX_MCPKTS		= 10,

	NSER_HW_STAT_INDEX_IPV4_TX_OCTS			= 11,
	NSER_HW_STAT_INDEX_IPV4_TX_PKTS			= 12,
	NSER_HW_STAT_INDEX_IPV4_TX_MCOTS		= 13,
	NSER_HW_STAT_INDEX_IPV4_TX_MCPKTS		= 14,

	NSER_HW_STAT_INDEX_IPV6_TX_OCTS			= 15,
	NSER_HW_STAT_INDEX_IPV6_TX_PKTS			= 16,
	NSER_HW_STAT_INDEX_IPV6_TX_MCOTS		= 17,
	NSER_HW_STAT_INDEX_IPV6_TX_MCPKTS		= 18,

	NSER_HW_STAT_INDEX_RDMA_RX_WRS			= 19,
	NSER_HW_STAT_INDEX_RDMA_RX_RDS			= 20,
	NSER_HW_STAT_INDEX_RDMA_RX_SNDS			= 21,

	NSER_HW_STAT_INDEX_RDMA_TX_WRS			= 22,
	NSER_HW_STAT_INDEX_RDMA_TX_RDS			= 23,
	NSER_HW_STAT_INDEX_RDMA_TX_SNDS			= 24,

	NSER_HW_STAT_INDEX_RX_ECN_MARKED_PKTS		= 25,
	NSER_HW_STAT_INDEX_TX_REPKTS			= 26,

	NSER_HW_STAT_INDEX_RDMA_RX_ACK_PKT		= 27,
	NSER_HW_STAT_INDEX_RDMA_RX_NAK_PKT		= 28,
	NSER_HW_STAT_INDEX_RDMA_RX_RNR_PKT		= 29,
	NSER_HW_STAT_INDEX_RDMA_RX_DUP_PKT		= 30,
	NSER_HW_STAT_INDEX_RDMA_RX_INV_PKT		= 31,
	NSER_HW_STAT_INDEX_RDMA_TX_ACK_PKT		= 32,
	NSER_HW_STAT_INDEX_RDMA_TX_NAK_PKT		= 33,
	NSER_HW_STAT_INDEX_RDMA_TX_RNR_PKT		= 34,

	NSER_HW_STAT_INDEX_RDMA_RX_UDDROP		= 35,
	NSER_HW_STAT_INDEX_RX_CNP_IGNORED		= 36,
	NSER_HW_STAT_INDEX_RX_CNP_HANDLED		= 37,

	NSER_HW_STAT_INDEX_TX_CNPSENT			= 38,

	NSER_HW_STAT_INDEX_VBND					= 39,
	NSER_HW_STAT_INDEX_VINV					= 40,
	NSER_HW_STAT_INDEX_FRM					= 41,

	NSER_HW_STAT_INDEX_MAX					= 42,
};

#define NSER_MIN_FEATURES 2

enum nser_feature_type {
	NSER_FEATURE_FW_INFO = 0,
	NSER_HW_VERSION_INFO = 1,
	NSER_QSETS_MAX       = 26,
	NSER_MAX_FEATURES, /* Must be last entry */
};

enum nser_sched_prio_type {
	NSER_PRIO_WEIGHTED_RR     = 1,
	NSER_PRIO_STRICT	   = 2,
	NSER_PRIO_WEIGHTED_STRICT = 3,
};

enum nser_vm_vf_type {
	NSER_VF_TYPE = 0,
	NSER_VM_TYPE,
	NSER_PF_TYPE,
};

enum nser_cqp_hmc_profile {
	NSER_HMC_PROFILE_0, // pf:2, vf:0
	NSER_HMC_PROFILE_1, // pf:1, vf:0
	NSER_HMC_PROFILE_2, // pf:2, vf:2*8, favor mode
	NSER_HMC_PROFILE_3, // pf:2, vf:2*8, equal mode
	NSER_HMC_PROFILE_4, // pf:2, vf:2*16, favor mode
	NSER_HMC_PROFILE_5, // pf:2, vf:2*16, equal mode
	NSER_HMC_PROFILE_6, // pf:4, vf:0
	NSER_HMC_PROFILE_7, // pf:4, vf:4*16, favor mode
	NSER_HMC_PROFILE_8, // pf:4, vf:4*16, equal mode
};

enum nser_queue_type {
	NSER_QUEUE_TYPE_SQ_RQ = 0,
	NSER_QUEUE_TYPE_CQP,
};

struct nser_sc_dev;
struct nser_vsi_pestat;

struct nser_dcqcn_cc_params {
	u8 cc_cfg_valid;
	u8 dcqcn_f;
	u16 dcqcn_t;
	u32 dcqcn_b;
	u32 rreduce_mperiod;
	u16 dcqcn_alpha_min;
	u16 dcqcn_alpha_init_value;
	u16 dcqcn_alpha;
	u16 dcqcn_recovery_bcnt_period;
	u16 dcqcn_g;
	u8 dcqcn_rpg_gd;
	bool dcqcn_clamp_tar_rate:1;
	u32 dcqcn_alpha_period;
	u32 dcqcn_recovery_time_period;
	u32 dcqcn_tar_work_rate;
};

struct nser_timely_cc_params {
	//set in cqp ctx
	u8 cc_cfg_valid;
	u16 timely_beta;
	u16 timely_alpha;

	//set in qp ctx
	u32 timely_min_rtt;
	u32 timely_tlow;
	u32 timely_thigh;
};

struct nser_cc_params {
	u8 cc_min_dec;
	u8 cc_max_dec;
	u8 cc_f;
	u32 rai_factor;
	u32 hai_factor;
	u32 cc_working_rate;
	u32 cc_min_work_rate;
	u32 cc_max_work_rate;
	struct nser_dcqcn_cc_params dcqcn_params;
	struct nser_timely_cc_params timely_params;
};


struct nser_cqp_init_info {
	u64 cqp_compl_ctx;
	u64 host_ctx_pa;
	u64 sq_pa;
	struct nser_sc_dev *dev;
	struct nser_cqp_quanta *sq;
	struct nser_cc_params cc_params;
	__le64 *host_ctx;
	u64 *scratch_array;
	u32 sq_size;
	u16 hw_maj_ver;
	u16 hw_min_ver;
	u8 struct_ver;
	u8 hmc_profile;
	u8 ena_vf_count;
	u8 ceqs_per_vf;
	bool en_datacenter_tcp:1;
	bool disable_packed:1;
	bool rocev2_rto_policy:1;
	bool dcqcn_ena:1;
	bool timely_ena:1;
	bool hmc_on_chip:1;
	bool mirror_ena:1;
};

struct nser_cqp_sq_wqe {
	__le64 buf[NSER_CQP_WQE_SIZE];
};

struct nser_sc_aeqe {
	__le64 buf[NSER_AEQE_SIZE];
};

struct nser_ceqe {
	__le64 buf[NSER_CEQE_SIZE];
};

struct nser_cqp_ctx {
	__le64 buf[NSER_CQP_CTX_SIZE];
	__le64 rsvd_for_fw[NSER_CQP_RSVD_SIZE];
};

struct nser_cq_shadow_area {
	__le64 buf[NSER_SHADOW_AREA_SIZE];
};

struct nser_dev_hw_stats_offsets {
	u32 stats_offset[NSER_HW_STAT_INDEX_MAX];
};

struct nser_dev_hw_stats {
	u64 stats_val[NSER_GATHER_STATS_BUF_SIZE / sizeof(u64)];
};

struct nser_gather_stats {
	u64 val[NSER_GATHER_STATS_BUF_SIZE / sizeof(u64)];
};

struct nser_hw_stat_map {
	u16 byteoff;
	u8 bitoff;
	u64 bitmask;
};

struct nser_stats_gather_info {
	bool use_hmc_fcn_index:1;
	bool use_stats_inst:1;
	u8 hmc_fcn_index;
	u8 stats_inst_index;
	struct nser_dma_mem stats_buff_mem;
	void *gather_stats_va;
	void *last_gather_stats_va;
};

struct nser_vsi_pestat {
	struct nser_hw *hw;
	struct nser_dev_hw_stats hw_stats;
	struct nser_stats_gather_info gather_info;
	struct timer_list stats_timer;
	struct nser_sc_vsi *vsi;
	spinlock_t lock; /* rdma stats lock */
};

struct nser_hw {
	u8 __iomem *hw_addr;
	u8 __iomem *priv_hw_addr;
	struct device *device;
	struct nser_hmc_info hmc;
};

struct nser_sc_pd {
	struct nser_sc_dev *dev;
	u32 pd_id;
	int abi_ver;
};

struct nser_cqp_quanta {
	__le64 elem[NSER_CQP_WQE_SIZE];
};

struct nser_sc_cqp {
	u32 size;
	u64 sq_pa;
	u64 host_ctx_pa;
	void *back_cqp;
	struct nser_sc_dev *dev;
	int (*process_cqp_sds)(struct nser_sc_dev *dev,
			       struct nser_update_sds_info *info);
	struct nser_dma_mem sdbuf;
	struct nser_ring sq_ring;
	struct nser_cqp_quanta *sq_base;
	struct nser_cc_params cc_params;
	__le64 *host_ctx;
	u64 *scratch_array;
	u32 cqp_id;
	u32 sq_size;
	u32 hw_sq_size;
	u16 hw_maj_ver;
	u16 hw_min_ver;
	u8 struct_ver;
	u8 polarity;
	u8 hmc_profile;
	u8 ena_vf_count;
	u8 timeout_count;
	u8 ceqs_per_vf;
	bool en_datacenter_tcp:1;
	bool disable_packed:1;
	bool rocev2_rto_policy:1;
	bool dcqcn_ena:1;
	bool timely_ena:1;
	bool hmc_on_chip:1;
	bool mirror_ena:1;
};

struct nser_sc_aeq {
	u32 size;
	u64 aeq_elem_pa;
	struct nser_sc_dev *dev;
	struct nser_sc_aeqe *aeqe_base;
	void *pbl_list;
	u32 elem_cnt;
	struct nser_ring aeq_ring;
	u8 pbl_chunk_size;
	u32 first_pm_pbl_idx;
	u32 msix_idx;
	u8 polarity;
	bool virtual_map:1;
};

struct nser_sc_ceq {
	u32 size;
	u64 ceq_elem_pa;
	struct nser_sc_dev *dev;
	struct nser_ceqe *ceqe_base;
	void *pbl_list;
	u32 ceq_id;
	u32 elem_cnt;
	struct nser_ring ceq_ring;
	u8 pbl_chunk_size;
	u8 tph_val;
	u32 first_pm_pbl_idx;
	u8 polarity;
	struct nser_sc_vsi *vsi;
	struct nser_sc_cq **reg_cq;
	u32 reg_cq_size;
	spinlock_t req_cq_lock; /* protect access to reg_cq array */
	bool virtual_map:1;
	bool tph_en:1;
	bool itr_no_expire:1;
	bool int_en:1;
	u16  msix_idx;
};

struct nser_sc_cq {
	struct nser_cq_uk cq_uk;
	u64 cq_pa;
	u64 shadow_area_pa;
	struct nser_sc_dev *dev;
	struct nser_sc_vsi *vsi;
	void *pbl_list;
	void *back_cq;
	u32 ceq_id;
	u32 shadow_read_threshold;
	u8 pbl_chunk_size;
	u8 cq_type;
	u8 tph_val;
	u32 first_pm_pbl_idx;
	bool ceqe_mask:1;
	bool virtual_map:1;
	bool check_overflow:1;
	bool ceq_id_valid:1;
	bool tph_en;
};

struct nser_sc_qp {
	struct nser_qp_uk qp_uk;
	u64 sq_pa;
	u64 rq_pa;
	u64 hw_host_ctx_pa;
	u64 shadow_area_pa;
	struct nser_sc_dev *dev;
	struct nser_sc_vsi *vsi;
	struct nser_sc_pd *pd;
	__le64 *hw_host_ctx;
	u64 qp_compl_ctx;
	u16 qs_handle;
	u8 flush_wqes_count;
	u8 sq_tph_val;
	u8 rq_tph_val;
	u8 qp_state;
	u8 hw_sq_size;
	u8 hw_rq_size;
	u8 src_mac_addr_idx;
	bool on_qoslist:1;
	bool ieq_pass_thru:1;
	bool sq_tph_en:1;
	bool rq_tph_en:1;
	bool rcv_tph_en:1;
	bool xmit_tph_en:1;
	bool virtual_map:1;
	bool flush_sq:1;
	bool flush_rq:1;
	bool sq_flush_code:1;
	bool rq_flush_code:1;
	enum nser_flush_opcode flush_code;
	enum nser_qp_event_type event_type;
	u8 user_pri;
	struct list_head list;
};

struct nser_stats_inst_info {
	bool use_hmc_fcn_index;
	u8 hmc_fn_id;
	u8 stats_idx;
};

struct nser_up_info {
	u8 map[8];
	u8 cnp_up_override;
	u8 hmc_fcn_idx;
	bool use_vlan:1;
	bool use_cnp_up_override:1;
};

struct nser_cnp_info {
	u8 cnp_dscp;
	u8 cnp_802p_prio;
};

#define NSER_MAX_WS_NODES	0x3FF
#define NSER_WS_NODE_INVALID	0xFFFF

struct nser_ws_node_info {
	u16 id;
	u16 vsi;
	u16 parent_id;
	u16 qs_handle;
	bool type_leaf:1;
	bool enable:1;
	u8 prio_type;
	u8 tc;
	u8 weight;
};

struct nser_hmc_fpm_misc {
	u32 max_ceqs;
	u32 max_sds;
	u32 xf_block_size;
	u32 q1_block_size;
	u32 ht_multiplier;
	u32 timer_bucket;
	u32 rrf_block_size;
	u32 ooiscf_block_size;
};

struct nser_vchnl_if {
	int (*vchnl_recv)(struct nser_sc_dev *dev, u16 vf_id, u8 *msg, u16 len);
	int (*vchnl_send)(struct nser_sc_dev *dev, u16 vf_id, u8 *msg, u16 len);
	int (*vchnl_send_sync)(struct nser_sc_dev *dev, u8 *msg, u16 len,
			       u8 *recv_msg, u16 *recv_len);
};

#define NSER_VCHNL_MAX_VF_MSG_SIZE 512
#define NSER_LEAF_DEFAULT_REL_BW		64
#define NSER_PARENT_DEFAULT_REL_BW		1

struct nser_qos {
	struct list_head qplist;
	struct mutex qos_mutex; /* protect QoS attributes per QoS level */
	u64 lan_qos_handle;
	u32 l2_sched_node_id;
	u16 qs_handle;
	u8 traffic_class;
	u8 rel_bw;
	u8 prio_type;
	bool valid;
};

struct nser_config_check {
	bool config_ok:1;
	bool lfc_set:1;
	bool pfc_set:1;
	u8 traffic_class;
	u16 qs_handle;
};

struct nser_vfdev {
	struct nser_sc_dev *pf_dev;
	struct nser_sc_vsi *vf_vsi;
	u8 *hmc_info_mem;
	u8 vf_msg_buf[NSER_VCHNL_MAX_VF_MSG_SIZE];
	struct nser_hmc_info hmc_info;
	struct nser_hmc_fpm_misc hmc_fpm_misc;
	u64 fpm_query_buf_pa;
	u64 *fpm_query_buf;
	refcount_t refcnt;
	u16 pmf_index;
	u16 vf_id;
	u16 iw_vf_idx;
	bool stats_initialized:1;
	bool pf_hmc_initialized:1;
	bool reset_en:1;
	bool port_vlan_en:1;
};

#define NSER_INVALID_STATS_IDX 0xff
struct nser_sc_vsi {
	u16 vsi_idx;
	struct nser_sc_dev *dev;
	struct nser_vfdev *vf_dev;
	void *back_vsi;
	u16 mtu;
	u16 vf_id;
	enum nser_vm_vf_type vm_vf_type;
	bool stats_inst_alloc:1;
	bool tc_change_pending:1;
	bool mtu_change_pending:1;
	struct nser_vsi_pestat *pestat;
	atomic_t qp_suspend_reqs;
	int (*register_qset)(struct nser_sc_vsi *vsi,
			     struct nser_ws_node *tc_node);
	void (*unregister_qset)(struct nser_sc_vsi *vsi,
				struct nser_ws_node *tc_node);
	struct nser_config_check cfg_check[NSER_MAX_USER_PRIORITY];
	bool tc_print_warning[IEEE_8021QAZ_MAX_TCS];
	u8 qos_rel_bw;
	u8 qos_prio_type;
	u8 stats_idx;
	u8 dscp_map[NSER_DSCP_NUM_VAL];
	struct nser_qos qos[NSER_MAX_USER_PRIORITY];
	u64 hw_stats_regs[NSER_HW_STAT_INDEX_MAX];
	bool dscp_mode:1;
};

struct nser_sc_dev {
	struct list_head cqp_cmd_head; /* head of the CQP command list */
	spinlock_t cqp_lock; /* protect CQP list access */
	bool stats_idx_array[NSER_MAX_STATS_COUNT_GEN1];
	struct nser_dma_mem vf_fpm_query_buf[NSER_MAX_PE_ENA_VF_COUNT];
	u64 fpm_query_buf_pa;
	u64 fpm_commit_buf_pa;
	__le64 *fpm_query_buf;
	__le64 *fpm_commit_buf;
	struct nser_hw *hw;
	u8 __iomem *db_addr;
	u32 __iomem *wqe_alloc_db;
	u32 __iomem *cq_arm_db;
	u32 __iomem *aeq_alloc_db;
	u32 __iomem *cqp_db;
	u32 __iomem *cq_ack_db;
	u32 __iomem *ceq_itr_mask_db;
	u32 __iomem *aeq_itr_mask_db;
	u32 __iomem *hw_regs[NSER_MAX_REGS];
	u32 ceq_itr;   /* Interrupt throttle, usecs between interrupts: 0 disabled. 2 - 8160 */
	u64 hw_masks[NSER_MAX_MASKS];
	u8 hw_shifts[NSER_MAX_SHIFTS];
	const struct nser_hw_stat_map *hw_stats_map;
	u64 hw_stats_regs[NSER_HW_STAT_INDEX_MAX];
	u64 hw_stats_vf_regs[NSER_HW_STAT_INDEX_MAX];
	u64 feature_info[NSER_MAX_FEATURES];
	u64 cqp_cmd_stats[NSER_MAX_CQP_OPS];
	struct nser_hw_attrs hw_attrs;
	struct nser_hmc_info *hmc_info;
	struct nser_vfdev *vf_dev[NSER_MAX_PE_ENA_VF_COUNT];
	u8 vf_recv_buf[NSER_VCHNL_MAX_VF_MSG_SIZE];
	u16 vf_recv_len;
	spinlock_t vf_dev_lock;  /* sync vf_dev usage with async events like reset */
	struct workqueue_struct *vchnl_wq;
	struct nser_sc_cqp *cqp;
	struct nser_sc_aeq *aeq;
	struct nser_sc_ceq *ceq[NSER_CEQ_MAX_COUNT];
	struct nser_sc_cq *ccq;
	const struct nser_irq_ops *irq_ops;
	struct nser_vchnl_if *vchnl_if;
	struct nser_hmc_fpm_misc hmc_fpm_misc;
	struct nser_ws_node *ws_tree_root;
	struct mutex ws_mutex; /* ws tree mutex */
	u16 num_vfs;
	u8 hmc_fn_id;
	u8 vf_id;
	u16 vsi_num;
	bool vchnl_up:1;
	bool ceq_valid:1;
	bool privileged:1;
	bool double_vlan_en:1;
	struct mutex vchnl_mutex;
	u8 pci_rev;
	u8 __iomem *hmc_va;
	u8 __iomem *pble_start_va;
	int (*ws_add)(struct nser_sc_vsi *vsi, u8 user_pri);
	void (*ws_remove)(struct nser_sc_vsi *vsi, u8 user_pri);
	void (*ws_reset)(struct nser_sc_vsi *vsi);
};

struct nser_modify_cq_info {
	u64 cq_pa;
	struct nser_cqe *cq_base;
	u32 cq_size;
	u32 shadow_read_threshold;
	u8 pbl_chunk_size;
	u32 first_pm_pbl_idx;
	bool virtual_map:1;
	bool check_overflow;
	bool cq_resize:1;
};

struct nser_create_qp_info {
	bool ord_valid:1;
	bool cq_num_valid:1;
	bool arp_cache_idx_valid:1;
	bool mac_valid:1;
	bool force_lpb;
	u8 next_rdma_state;
};

struct nser_modify_qp_info {
	u64 rx_win0;
	u64 rx_win1;
	u16 new_mss;
	u8 next_rdma_state;
	u8 curr_rdma_state;
	u8 termlen;
	bool ord_valid:1;
	bool udp_ctx_valid:1;
	bool cq_num_valid:1;
	bool arp_cache_idx_valid:1;
	bool reset_tcp_conn:1;
	bool remove_hash_idx:1;
	bool dont_send_term:1;
	bool dont_send_fin:1;
	bool cached_var_valid:1;
	bool mss_change:1;
	bool force_lpb:1;
	bool mac_valid:1;
	u32 attr_mask;
};

struct nser_ccq_cqe_info {
	struct nser_sc_cqp *cqp;
	u64 scratch;
	u32 op_ret_val;
	u16 maj_err_code;
	u16 min_err_code;
	u8 op_code;
	bool error;
};

struct nser_qos_tc_info {
	u64 tc_ctx;
	u8 rel_bw;
	u8 prio_type;
	u8 egress_virt_up;
	u8 ingress_virt_up;
};

struct nser_l2params {
	struct nser_qos_tc_info tc_info[NSER_MAX_USER_PRIORITY];
	u32 num_apps;
	u16 qs_handle_list[NSER_MAX_USER_PRIORITY];
	u16 mtu;
	u8 up2tc[NSER_MAX_USER_PRIORITY];
	u8 dscp_map[NSER_DSCP_NUM_VAL];
	u8 num_tc;
	u8 vsi_rel_bw;
	u8 vsi_prio_type;
	bool mtu_changed:1;
	bool tc_changed:1;
	bool dscp_mode:1;
};

struct nser_vsi_init_info {
	struct nser_sc_dev *dev;
	void *back_vsi;
	struct nser_l2params *params;
	u16 exception_lan_q;
	u16 pf_data_vsi_num;
	enum nser_vm_vf_type vm_vf_type;
	int (*register_qset)(struct nser_sc_vsi *vsi,
			     struct nser_ws_node *tc_node);
	void (*unregister_qset)(struct nser_sc_vsi *vsi,
				struct nser_ws_node *tc_node);
};

struct nser_vsi_stats_info {
	struct nser_vsi_pestat *pestat;
	u8 fcn_id;
	bool alloc_stats_inst;
};

struct nser_device_init_info {
	u64 fpm_query_buf_pa;
	u64 fpm_commit_buf_pa;
	__le64 *fpm_query_buf;
	__le64 *fpm_commit_buf;
	struct nser_hw *hw;
	void __iomem *bar0;
	struct workqueue_struct *vchnl_wq;
	u16 max_vfs;
	u16 vsi_num;
	u8 hmc_fn_id;
	u8 __iomem *hmc_va;
	bool privileged;
};

struct nser_ceq_init_info {
	u64 ceqe_pa;
	struct nser_sc_dev *dev;
	u64 *ceqe_base;
	void *pbl_list;
	u32 elem_cnt;
	u32 ceq_id;
	bool virtual_map:1;
	bool tph_en:1;
	bool itr_no_expire:1;
	u8 pbl_chunk_size;
	u8 tph_val;
	u32 first_pm_pbl_idx;
	struct nser_sc_vsi *vsi;
	struct nser_sc_cq **reg_cq;
	u32 reg_cq_idx;
	bool int_en:1;
	u16 msix_idx;
};

struct nser_aeq_init_info {
	u64 aeq_elem_pa;
	struct nser_sc_dev *dev;
	u32 *aeqe_base;
	void *pbl_list;
	u32 elem_cnt;
	bool virtual_map;
	u8 pbl_chunk_size;
	u32 first_pm_pbl_idx;
	u32 msix_idx;
};

struct nser_ccq_init_info {
	u64 cq_pa;
	u64 shadow_area_pa;
	struct nser_sc_dev *dev;
	struct nser_cqe *cq_base;
	__le64 *shadow_area;
	void *pbl_list;
	u32 num_elem;
	u32 ceq_id;
	u32 shadow_read_threshold;
	bool ceqe_mask:1;
	bool ceq_id_valid:1;
	bool avoid_mem_cflct:1;
	bool virtual_map:1;
	bool tph_en:1;
	u8 tph_val;
	u8 pbl_chunk_size;
	u32 first_pm_pbl_idx;
	struct nser_sc_vsi *vsi;
};

struct nser_udp_offload_info {
	bool ipv4:1;
	bool insert_vlan_tag:1;
	u8 ttl;
	u8 tos;
	u16 src_port;
	u16 dst_port;
	u32 dest_ip_addr[4];
	u32 snd_mss;
	u16 vlan_tag;
	u16 arp_idx;
	u32 flow_label;
	u8 udp_state;
	u32 psn_nxt;
	u32 lsn;
	u32 epsn;
	u32 psn_max;
	u32 psn_una;
	u32 local_ipaddr[4];
	u32 cwnd;
	u8 rexmit_thresh;
	u8 rnr_nak_thresh;
	u8 min_rnr_timer;
};

struct nser_roce_offload_info {
	u16 p_key;
	u32 err_rq_idx;
	u32 qkey;
	u32 dest_qp;
	u8 roce_tver;
	u8 ack_credits;
	u8 err_rq_idx_valid;
	u32 pd_id;
	u16 ord_size;
	u16 ird_size;
	bool is_qp1:1;
	bool udprivcq_en:1;
	bool dcqcn_en:1;
	bool rcv_no_icrc:1;
	bool wr_rdresp_en:1;
	bool bind_en:1;
	bool fast_reg_en:1;
	bool priv_mode_en:1;
	bool rd_en:1;
	bool timely_en:1;
	bool ecn_en:1;
	bool fw_cc_enable:1;
	bool use_stats_inst:1;
	u32 t_high;
	u32 t_low;
	u32 timely_min_rtt;
	u32 cc_working_rate;
	u32 cc_max_work_rate;
	u32 cc_min_work_rate;
	u8 mac_addr[ETH_ALEN];
	u8 rtomin;

	u16 dcqcn_alpha;
	u16 dcqcn_recovery_bcnt_period;
	u16 dcqcn_g;
	u8 dcqcn_rpg_gd;
	bool dcqcn_clamp_tar_rate:1;
	u32 dcqcn_alpha_period;
	u32 dcqcn_recovery_time_period;
	u32 dcqcn_tar_work_rate;
};

struct nser_qp_host_ctx_info {
	u64 qp_compl_ctx;
	struct nser_udp_offload_info *udp_info;
	struct nser_roce_offload_info *roce_info;
	u32 send_cq_num;
	u32 rcv_cq_num;
	u32 rem_endpoint_idx;
	u8 stats_idx;
	bool remote_atomics_en:1;
	bool stats_idx_valid:1;
	u8 user_pri;
};

struct nser_aeqe_info {
	u64 compl_ctx;
	u32 qp_cq_id;
	u32 wqe_idx;
	u16 ae_id;
	u8 rdma_state;
	bool qp:1;
	bool cq:1;
	bool sq:1;
	bool rq:1;
	bool in_rdrsp_wr:1;
	bool out_rdrsp:1;
	bool aeqe_overflow:1;
	u8 ae_src;
};

struct nser_allocate_stag_info {
	u64 total_len;
	u64 first_pm_pbl_idx;
	u32 chunk_size;
	u32 stag_idx;
	u32 page_size;
	u32 pd_id;
	u16 access_rights;
	bool remote_access:1;
	bool use_hmc_fcn_index:1;
	bool use_pf_rid:1;
	bool all_memory:1;
	u8 hmc_fcn_index;
};

struct nser_mw_alloc_info {
	u32 mw_stag_index;
	u32 page_size;
	u32 pd_id;
	bool remote_access:1;
	bool mw_wide:1;
	bool mw1_bind_dont_vldt_key:1;
	u8 remote_atomics_en;
};

struct nser_reg_ns_stag_info {
	u64 reg_addr_pa;
	u64 va;
	u64 total_len;
	u32 page_size;
	u32 chunk_size;
	u32 first_pm_pbl_index;
	enum nser_addressing_type addr_type;
	nser_stag_index stag_idx;
	u16 access_rights;
	u32 pd_id;
	nser_stag_key stag_key;
	bool use_hmc_fcn_index:1;
	u8 hmc_fcn_index;
	bool use_pf_rid:1;
	bool all_memory:1;
	u8 remote_atomics_en;
};

struct nser_fast_reg_stag_info {
	u64 wr_id;
	u64 reg_addr_pa;
	u64 fbo;
	void *va;
	u64 total_len;
	u32 page_size;
	u32 chunk_size;
	u32 first_pm_pbl_index;
	enum nser_addressing_type addr_type;
	nser_stag_index stag_idx;
	u16 access_rights;
	u32 pd_id;
	nser_stag_key stag_key;
	bool local_fence:1;
	bool read_fence:1;
	bool signaled:1;
	bool push_wqe:1;
	bool use_hmc_fcn_index:1;
	u8 hmc_fcn_index;
	bool use_pf_rid:1;
	bool defer_flag:1;
	bool remote_atomics_en:1;
};

struct nser_dealloc_stag_info {
	u32 stag_idx;
	u32 pd_id;
	bool mr:1;
	bool dealloc_pbl:1;
};

struct nser_register_shared_stag {
	u64 va;
	enum nser_addressing_type addr_type;
	nser_stag_index new_stag_idx;
	nser_stag_index parent_stag_idx;
	u32 access_rights;
	u32 pd_id;
	u32 page_size;
	nser_stag_key new_stag_key;
	u8 remote_atomics_en;
};

struct nser_qp_init_info {
	struct nser_qp_uk_init_info qp_uk_init_info;
	struct nser_sc_pd *pd;
	struct nser_sc_vsi *vsi;
	__le64 *host_ctx;
	u8 *q2;
	u64 sq_pa;
	u64 rq_pa;
	u64 host_ctx_pa;
	u64 q2_pa;
	u64 shadow_area_pa;
	u8 sq_tph_val;
	u8 rq_tph_val;
	bool sq_tph_en:1;
	bool rq_tph_en:1;
	bool rcv_tph_en:1;
	bool xmit_tph_en:1;
	bool virtual_map:1;
};

struct nser_cq_init_info {
	struct nser_sc_dev *dev;
	u64 cq_base_pa;
	u64 shadow_area_pa;
	u32 ceq_id;
	u32 shadow_read_threshold;
	u8 pbl_chunk_size;
	u32 first_pm_pbl_idx;
	bool virtual_map:1;
	bool ceqe_mask:1;
	bool ceq_id_valid:1;
	bool tph_en:1;
	u8 tph_val;
	u8 type;
	struct nser_cq_uk_init_info cq_uk_init_info;
	struct nser_sc_vsi *vsi;
};

struct nser_upload_context_info {
	u64 buf_pa;
	u32 qp_id;
	u8 qp_type;
	bool freeze_qp:1;
	bool raw_format:1;
};

struct nser_local_mac_entry_info {
	u8 mac_addr[6];
	u16 entry_idx;
};

struct nser_add_arp_cache_entry_info {
	u8 mac_addr[ETH_ALEN];
	u32 reach_max;
	u16 arp_index;
	bool permanent;
};

struct nser_qp_flush_info {
	u16 sq_minor_code;
	u16 sq_major_code;
	u16 rq_minor_code;
	u16 rq_major_code;
	u16 ae_code;
	u8 ae_src;
	bool sq:1;
	bool rq:1;
	bool userflushcode:1;
	bool generate_ae:1;
};

struct nser_gen_ae_info {
	u16 ae_code;
	u8 ae_src;
};

struct nser_cqp_timeout {
	u64 compl_cqp_cmds;
	u32 count;
};

struct nser_irq_ops {
	void (*nser_dis_irq)(struct nser_sc_dev *dev, u32 idx);
	void (*nser_en_irq)(struct nser_sc_dev *dev, u32 idx);
};

void nser_sc_ccq_arm(struct nser_sc_cq *ccq);
int nser_sc_ccq_create(struct nser_sc_cq *ccq, u64 scratch,
			bool check_overflow, bool post_sq);
int nser_sc_ccq_destroy(struct nser_sc_cq *ccq, u64 scratch, bool post_sq);
int nser_sc_vsi_reset(struct nser_sc_dev *dev, u64 scratch, bool post_sq);
int nser_sc_ccq_get_cqe_info(struct nser_sc_cq *ccq,
			      struct nser_ccq_cqe_info *info);
int nser_sc_ccq_init(struct nser_sc_cq *ccq,
		      struct nser_ccq_init_info *info);

int nser_sc_cceq_create(struct nser_sc_ceq *ceq);
int nser_sc_cceq_destroy_done(struct nser_sc_ceq *ceq);

int nser_sc_ceq_destroy(struct nser_sc_ceq *ceq, u64 scratch, bool post_sq);
int nser_sc_ceq_init(struct nser_sc_ceq *ceq,
		      struct nser_ceq_init_info *info);
void nser_sc_cleanup_ceqes(struct nser_sc_cq *cq, struct nser_sc_ceq *ceq);
void *nser_sc_process_ceq(struct nser_sc_dev *dev, struct nser_sc_ceq *ceq);

int nser_sc_aeq_init(struct nser_sc_aeq *aeq,
		      struct nser_aeq_init_info *info);
int nser_sc_get_next_aeqe(struct nser_sc_aeq *aeq,
			   struct nser_aeqe_info *info);
int nser_sc_repost_aeq_entries(struct nser_sc_dev *dev, u32 count);

void nser_sc_pd_init(struct nser_sc_dev *dev, struct nser_sc_pd *pd, u32 pd_id,
		      int abi_ver);
void nser_cfg_aeq(struct nser_sc_dev *dev, u32 idx, bool enable);
void nser_check_cqp_progress(struct nser_cqp_timeout *cqp_timeout,
			      struct nser_sc_dev *dev);
int nser_sc_cqp_create(struct nser_sc_cqp *cqp, u16 *maj_err, u16 *min_err);
int nser_sc_cqp_destroy(struct nser_sc_cqp *cqp, bool free_hwcqp);
int nser_sc_cqp_init(struct nser_sc_cqp *cqp,
		      struct nser_cqp_init_info *info);
void nser_sc_cqp_post_sq(struct nser_sc_cqp *cqp);
int nser_sc_poll_for_cqp_op_done(struct nser_sc_cqp *cqp, u8 opcode,
				  struct nser_ccq_cqe_info *cmpl_info);
int nser_sc_qp_create(struct nser_sc_qp *qp,
		       struct nser_create_qp_info *info, u64 scratch,
		       bool post_sq);
int nser_sc_qp_destroy(struct nser_sc_qp *qp, u64 scratch,
			bool remove_hash_idx, bool ignore_mw_bnd, bool post_sq);
int nser_sc_qp_flush_wqes(struct nser_sc_qp *qp,
			   struct nser_qp_flush_info *info, u64 scratch,
			   bool post_sq);
int nser_sc_qp_init(struct nser_sc_qp *qp, struct nser_qp_init_info *info);
int nser_sc_qp_modify(struct nser_sc_qp *qp,
		       struct nser_modify_qp_info *info, u64 scratch,
		       bool post_sq);

void nser_sc_qp_setctx(struct nser_sc_qp *qp, __le64 *qp_ctx,
			struct nser_qp_host_ctx_info *info);
void nser_sc_qp_setctx_roce(struct nser_sc_qp *qp, __le64 *qp_ctx,
			     struct nser_qp_host_ctx_info *info);
int nser_sc_cq_destroy(struct nser_sc_cq *cq, u64 scratch, bool post_sq);
int nser_sc_cq_init(struct nser_sc_cq *cq, struct nser_cq_init_info *info);
void nser_sc_cq_resize(struct nser_sc_cq *cq, struct nser_modify_cq_info *info);
int nser_sc_aeq_destroy(struct nser_sc_aeq *aeq, u64 scratch, bool post_sq);
int nser_sc_static_hmc_pages_allocated(struct nser_sc_cqp *cqp, u64 scratch,
					u8 hmc_fn_id, bool post_sq,
					bool poll_registers);

void sc_vsi_update_stats(struct nser_sc_vsi *vsi);
struct cqp_info {
	union {
		struct {
			struct nser_sc_qp *qp;
			struct nser_create_qp_info info;
			u64 scratch;
		} qp_create;

		struct {
			struct nser_sc_qp *qp;
			struct nser_modify_qp_info info;
			u64 scratch;
		} qp_modify;

		struct {
			struct nser_sc_qp *qp;
			u64 scratch;
			bool remove_hash_idx;
			bool ignore_mw_bnd;
		} qp_destroy;

		struct {
			struct nser_sc_cq *cq;
			u64 scratch;
			bool check_overflow;
		} cq_create;

		struct {
			struct nser_sc_cq *cq;
			struct nser_modify_cq_info info;
			u64 scratch;
		} cq_modify;

		struct {
			struct nser_sc_cq *cq;
			u64 scratch;
		} cq_destroy;

		struct {
			struct nser_sc_dev *dev;
			struct nser_allocate_stag_info info;
			u64 scratch;
		} alloc_stag;

		struct {
			struct nser_sc_dev *dev;
			struct nser_mw_alloc_info info;
			u64 scratch;
		} mw_alloc;

		struct {
			struct nser_sc_dev *dev;
			struct nser_reg_ns_stag_info info;
			u64 scratch;
		} mr_reg_non_shared;

		struct {
			struct nser_sc_dev *dev;
			struct nser_dealloc_stag_info info;
			u64 scratch;
		} dealloc_stag;

		struct {
			struct nser_sc_cqp *cqp;
			struct nser_add_arp_cache_entry_info info;
			u64 scratch;
		} add_arp_cache_entry;

		struct {
			struct nser_sc_cqp *cqp;
			u64 scratch;
			u16 arp_index;
		} del_arp_cache_entry;

		struct {
			struct nser_sc_cqp *cqp;
			struct nser_local_mac_entry_info info;
			u64 scratch;
		} add_local_mac_entry;

		struct {
			struct nser_sc_cqp *cqp;
			u64 scratch;
			u8 entry_idx;
			u8 ignore_ref_count;
		} del_local_mac_entry;

		struct {
			struct nser_sc_cqp *cqp;
			u64 scratch;
		} alloc_local_mac_entry;

		struct {
			struct nser_sc_cqp *cqp;
			struct nser_manage_vf_pble_info info;
			u64 scratch;
		} manage_vf_pble_bp;

		struct {
			struct nser_sc_dev *dev;
			struct nser_upload_context_info info;
			u64 scratch;
		} qp_upload_context;

		struct {
			struct nser_sc_dev *dev;
			struct nser_hmc_fcn_info info;
			u64 scratch;
		} manage_hmc_pm;

		struct {
			struct nser_sc_ceq *ceq;
			u64 scratch;
		} ceq_create;

		struct {
			struct nser_sc_ceq *ceq;
			u64 scratch;
		} ceq_destroy;

		struct {
			struct nser_sc_aeq *aeq;
			u64 scratch;
		} aeq_create;

		struct {
			struct nser_sc_aeq *aeq;
			u64 scratch;
		} aeq_destroy;

		struct {
			struct nser_sc_qp *qp;
			struct nser_qp_flush_info info;
			u64 scratch;
		} qp_flush_wqes;

		struct {
			struct nser_sc_qp *qp;
			struct nser_gen_ae_info info;
			u64 scratch;
		} gen_ae;

		struct {
			struct nser_sc_cqp *cqp;
			void *fpm_val_va;
			u64 fpm_val_pa;
			u8 hmc_fn_id;
			u64 scratch;
		} query_fpm_val;

		struct {
			struct nser_sc_cqp *cqp;
			void *fpm_val_va;
			u64 fpm_val_pa;
			u8 hmc_fn_id;
			u64 scratch;
		} commit_fpm_val;

		struct {
			struct nser_sc_dev *dev;
			struct nser_update_sds_info info;
			u64 scratch;
		} update_pe_sds;

		struct {
			struct nser_sc_cqp *cqp;
			struct nser_sc_qp *qp;
			u64 scratch;
		} suspend_resume;

		struct {
			struct nser_sc_cqp *cqp;
			struct nser_ah_info info;
			u64 scratch;
		} ah_create;

		struct {
			struct nser_sc_cqp *cqp;
			struct nser_ah_info info;
			u64 scratch;
		} ah_destroy;

		struct {
			struct nser_sc_cqp *cqp;
			struct nser_mcast_grp_info info;
			u64 scratch;
		} mc_create;

		struct {
			struct nser_sc_cqp *cqp;
			struct nser_mcast_grp_info info;
			u64 scratch;
		} mc_destroy;

		struct {
			struct nser_sc_cqp *cqp;
			struct nser_mcast_grp_info info;
			u64 scratch;
		} mc_modify;

		struct {
			struct nser_sc_cqp *cqp;
			struct nser_stats_inst_info info;
			u64 scratch;
		} stats_manage;

		struct {
			struct nser_sc_cqp *cqp;
			struct nser_stats_gather_info info;
			u64 scratch;
		} stats_gather;

		struct {
			struct nser_sc_cqp *cqp;
			struct nser_ws_node_info info;
			u64 scratch;
		} ws_node;

		struct {
			struct nser_sc_cqp *cqp;
			struct nser_up_info info;
			u64 scratch;
		} up_map;

		struct {
			struct nser_sc_cqp *cqp;
			struct nser_cnp_info info;
			u64 scratch;
		} cnp;

		struct {
			struct nser_sc_cqp *cqp;
			struct nser_dma_mem query_buff_mem;
			u64 scratch;
		} query_rdma;
	} u;
};

struct cqp_cmds_info {
	struct list_head cqp_cmd_entry;
	u8 cqp_cmd;
	u8 post_sq;
	struct cqp_info in;
};

struct nser_virtchnl_work {
	struct work_struct work;
	u8 vf_msg_buf[NSER_VCHNL_MAX_VF_MSG_SIZE];
	struct nser_sc_dev *dev;
	u16 vf_id;
	u16 len;
};

__le64 *nser_sc_cqp_get_next_send_wqe_idx(struct nser_sc_cqp *cqp, u64 scratch,
					   u32 *wqe_idx);

/**
 * nser_sc_cqp_get_next_send_wqe - get next wqe on cqp sq
 * @cqp: struct for cqp hw
 * @scratch: private data for CQP WQE
 */
static inline __le64 *nser_sc_cqp_get_next_send_wqe(struct nser_sc_cqp *cqp, u64 scratch)
{
	u32 wqe_idx;

	return nser_sc_cqp_get_next_send_wqe_idx(cqp, scratch, &wqe_idx);
}
#endif /* NSER_TYPE_H */
