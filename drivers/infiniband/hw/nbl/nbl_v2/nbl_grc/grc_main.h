/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_GRC_MAIN_H
#define NBL_GRC_MAIN_H

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/pci.h>
#include <linux/version.h>
#include "nbl_core_common.h"
#include "grc_common_v2.h"
#include "shared.h"
#include "nbl_bit_op.h"
#include "nbl_cqp_fmt_v2.h"
#include "regs_v2/nbl_reg_cqpp.h"

#define NBL_RDMA_CQP_MAX_FUN_ID (NBL_RDMA_TOTAL_FUNCTION_NUM - 1)

#define FUNCTION_ID_TBL_SIZE DIV_ROUND_UP(NBL_RDMA_TOTAL_FUNCTION_NUM, BITS_PER_LONG)

extern const struct nbl_grc_resource_ops grc_resource_ops;
extern const struct nbl_grc_dsch_ops grc_dsch_ops;
extern const struct nbl_grc_stat_ops grc_stat_ops;
extern const struct nbl_grc_global_ops grc_global_ops;

#define NBL_SD_VALID 1
#define NBL_DBQ_SIZE SZ_4M
#define NBL_TQ_RTO_SIZE SZ_4M
#define NBL_TQ_RNR_SIZE SZ_4M
#define NBL_RQDB_ARM_SIZE SZ_4M
#define NBL_HW_MAX_GLO_QUEUE_SIZE SZ_16M
#define NBL_HW_GLO_SD_SIZE SZ_2M
#define NBL_HW_MAX_GLO_QUEUE_SD_NUM (NBL_HW_MAX_GLO_QUEUE_SIZE / NBL_HW_GLO_SD_SIZE)

#define NBL_GRC_CACHE_MSG_RESP_BUSY EBUSY
#define NBL_GRC_MSG_RESP_ERR 1
#define NBL_GRC_MSG_RESP_OK 0
#define NBL_GRC_ABNORMAL_EVENT_BITS 32

enum nbl_grc_err_code {
	NBL_GRC_NO_MEM = 0x100,
	NBL_GRC_FUNC_ID_EXIST = 0x101,
	NBL_GRC_FUNC_ID_OVERFLOW = 0x102,
	NBL_GRC_THREAD_CREATE_FAIL = 0x103,
	NBL_GRC_CACHE_MSG_NO_SUPP = 0x104,
	NBL_GRC_CACHE_MSG_EXIST = 0x105,
	NBL_GRC_CACHE_MSG_NOT_FOUND = 0x106,
	NBL_GRC_CACHE_MSG_BUF_LEN_ERR = 0x107,
	NBL_GRC_CQP_INIT_ERR = 0x108,
	NBL_GRC_SRC_ADDR_INDEX_OVERFLOW = 0x109,
	NBL_GRC_CQP_CMD_ERR = 0x10A,
	NBL_GRC_NO_FUNCTION_ID = 0x10B,
	NBL_GRC_SET_EOT_ERR = 0x10C,
	NBL_GRC_SET_PF0_BDF_MAP_ERR = 0x10D,
};

enum nbl_gl_sd_type {
	NBL_SD_TYPE_RQDB_ARM = 0,
	NBL_SD_TYPE_TQ_RTO = 1,
	NBL_SD_TYPE_DBQ = 2,
	NBL_SD_TYPE_TQ_RNR = 3,
	NBL_SD_TYPE_MAX,
};

struct nbl_dma_mem {
	void *va;
	dma_addr_t pa;
	u32 size;
} __packed;

struct nbl_gl_sdtbl_info {
	u32 cnt;
	u32 max_num;   /* total count of list */
	struct nbl_dma_mem *list;
};

enum nbl_hmc_sd_addr_mode {
	NBL_HMC_PROFILE_HUGEPAGE = 0,
	NBL_HMC_PROFILE_LOW_SPEC_HIGH_EFFICIENCY = 1,
	NBL_HMC_PROFILE_FULL_SPEC_LOW_EFFICIENCY = 2,
};

enum nbl_pf_vf_spec {
	NBL_RDMA_MULTI_PF_VF = 0,
	NBL_RDMA_ONLY_ONE_FUNCTION = 1,
};

struct nbl_hbf_entry {
	u32 host_id;
	u32 bdf_num;
	u16 func_id;
	bool valid;
};

struct nbl_hbf_tbl {
	u16 tbl_size;
	struct nbl_hbf_entry entries[NBL_RDMA_TOTAL_FUNCTION_NUM];
};

enum nbl_hmc_rsrc_type {
	NBL_HMC_QP = 0,
	NBL_HMC_CQ = 1,
	NBL_HMC_PBL = 2,
	NBL_HMC_MR = 3,
	NBL_HMC_SRQ = 4,
	NBL_HMC_MAX, /* must be last entry */
};

#define NBL_HMC_OBJ_SD_CNT 32
#define NBL_HMC_ADDRESS_LEVEL0 0
#define NBL_HMC_ADDRESS_LEVEL1 1
#define NBL_HMC_HUGEPAGE 1
#define NBL_HMC_STANDARD_PAGE 0

#define NBL_HMC_QPC_SZ 512
#define NBL_HMC_CQC_SZ 64
#define NBL_HMC_PBL_SZ 8
#define NBL_HMC_MRTE_SZ 64
#define NBL_HMC_SRQC_SZ 64

#define NBL_HMC_MAX_SD_CNT  SZ_2K
#define NBL_HMC_SD_CNT_PER_CMD 64
#define NBL_RDMA_HMC_SD_MAX_CNT 2048

struct nbl_grc;

struct nbl_cmd {
	struct nbl_grc *grc;
	void *cmd_alloc_buf;
	dma_addr_t alloc_dma;
	int alloc_size;
	void *cmd_buf;
	dma_addr_t dma;
	spinlock_t alloc_lock; /* protect command queue tail/head */
	char wq_name[NBL_CMD_WQ_MAX_NAME];
	struct workqueue_struct *wq;
#if NBL_CMD_INT_USE_WQ
	char cmpl_wq_name[NBL_CMD_WQ_MAX_NAME];
	struct workqueue_struct *cmpl_wq; /* interrupt mode use, wq to save time */
#endif
	struct semaphore sem;
	struct nbl_cmd_work_ent *ent_arr[NBL_CMD_ENTRY_MAX_NUM];
	unsigned long *bit_mask; /* cmd put back use */
	u32 cmd_max_num; /* cmd entry max num      , 32   */
	u32 cmd_tail; /* cmd queue tail pointer , 0-31 */
	u32 cmd_head; /* cmd queue head pointer , 0-31 */
	u32 cmd_entry_size; /* cmd entry size in bytes, 128B */
	int mode;
	u8 cmd_entry_size_log; /* cmd entry size in log2 , 7 */
	u8 valid_val; /* 0 for first circle, wqe_valid should set */
	u8 rsvd[2]; /* 4B match */

	/* CQP statis */
	struct mutex cmd_stat_lock; /* lock protect static */
	u64 cmd_total; /* cqp cmd total num   */
	u64 cmd_succ; /* cqp cmd back success */
	u64 cmd_fail; /* cqp cmd back failed  */
};

union nbl_pcomp_fid_tbl_reg;
struct nbl_grc;

struct nbl_grc_resource_ops {
	void (*set_sd_range)(struct nbl_grc *grc, u16 function_id,
			     u32 sd_start, u32 sd_cnt, bool valid);
	void (*get_sd_range)(struct nbl_grc *grc, u16 function_id,
			     u32 *sd_start, u32 *sd_cnt);
	void (*set_bdf_func_id_map)(struct nbl_grc *grc, bool host_en,
				    u32 bdf_num, u16 func_id);
	void (*set_hw_pf_tbl)(struct nbl_grc *grc, u16 function_id, u16 pf_id);
	void (*set_src_addr_info)(struct nbl_grc *grc, const u8 *smac, const u8 *sip,
				  u16 src_addr_index, u8 seq_num);
	void (*set_cqp_info)(struct nbl_grc *grc, u16 function_id,
			     u64 cqp_ba, u32 cqp_len, bool enable);
	void (*set_cqp_pi)(struct nbl_grc *grc, u32 cur_pi, u8 odd_even);
	void (*set_rdma_pfid_map_tbl)(struct nbl_grc *grc,
				      u16 idx, u16 rdma_fn_id, bool valid);

	void (*set_cc_params)(struct nbl_grc *grc, u32 offset, u32 var);
	void (*set_vf_enable)(struct nbl_grc *grc, u16 function_id, u8 enable);
	void (*set_vfid_vsi_map)(struct nbl_grc *grc,
				 u16 function_id, u16 vsi_id, u8 valid);
	void (*ena_rdma_intrl)(struct nbl_grc *grc, u16 global_msix_idx,
			       u8 devfn, u8 bus, u8 valid);
	void (*get_abnormal_event)(struct nbl_grc *grc);
	int (*get_hw_inst_id)(struct nbl_grc *grc, u8 inst_type, u16 *inst_id);
	int (*put_hw_inst_id)(struct nbl_grc *grc, u8 inst_type, u16 inst_id);
	int (*hw_get_flush_status)(struct nbl_grc *grc,
				   u16 function_id, u32 check_base);
	void (*set_hw_dump_cfg)(struct nbl_grc *grc, u16 vsi_id, u16 *rx_vlan_vsi_id,
				u16 vsi_num, u16 function_id, bool enable_flag, bool is_lag);
	void (*clear_hw_cache)(struct nbl_grc *grc, u32 cache_type);
};

struct nbl_grc_dsch_ops {
	void (*set_rdma_dsch)(struct nbl_grc *grc,
			      u16 function_id, u32 host_id, u16 dport_id, u8 vld);
	void (*update_rdma_dsch)(struct nbl_grc *grc, u16 function_id,
				 u32 host_id, u16 dport_id, u8 vld);
};

struct nbl_grc_stat_ops {
	void (*set_hw_stat)(struct nbl_grc *grc, u32 op_info);
	void (*get_hw_stat)(struct nbl_grc *grc, u32 op_info,
			    u32 pa_l, u32 pa_h, u16 func_id);
	void (*enable_errcode_hw_stat)(struct nbl_grc *grc, u32 enable);
	void (*get_hw_status)(struct nbl_grc *grc, u32 *status);
};

struct nbl_grc_global_ops {
	u32 (*get_hw_global_cfg_flag)(struct nbl_grc *grc);
	void (*set_hw_global_cfg)(struct nbl_grc *grc);
};

enum nbl_grc_product_id {
	NBL_GRC_PRODUCT_DRACO,
	NBL_GRC_PRODUCT_ORION,
	NBL_GRC_PRODUCT_MAX,
};

struct nbl_grc_abnormal_module {
	const char *name;
	u32 status_addr;
};

struct nbl_grc_cache_layout {
	u32 type;
	u32 low_threshold_addr;
	u32 high_threshold_addr;
	u32 almost_full_threshold_addr;
	u32 depth;
};

struct nbl_grc_register_layout {
	u32 rdma_top_base;
	u32 cqpp_base;
	u32 hdma_base;
	u32 txp_base;
	u32 txmr_base;
	u32 txm_base;
	u32 rxp_base;
	u32 raqp_base;
	u32 ceaq_base;
	u32 qpcc_base;
	u32 cqcc_base;
	u32 mrtc_base;
	u32 sqrqec_base;
	u32 stat_base;
	u32 srqc_base;
	u32 cc_base;
	u32 ntfqp_base;
	u32 dsch_base;
	u32 uqm_base;
	u32 pcomp_base;
	u32 ped_base;
	u32 epro_base;
	u32 ipro_base;
	u32 top_ctrl_base;
	const struct nbl_grc_abnormal_module *abnormal_modules;
	u32 abnormal_module_count;
	const struct nbl_grc_cache_layout *caches;
	u32 cache_count;
};

struct nbl_grc_product_desc {
	const char *name;
	enum nbl_grc_product_id id;
	const struct nbl_grc_register_layout *regs;
	const struct nbl_grc_resource_ops *resource_ops;
	const struct nbl_grc_dsch_ops *dsch_ops;
	const struct nbl_grc_stat_ops *stat_ops;
	const struct nbl_grc_global_ops *global_ops;
};

#define GRC_MBX_WQ_NAME_LEN 32
struct nbl_hmc_sd_range {
	u32 start;
	u32 cnt;
};

#define VOA_TBL_STR_LEN 600
#define VOA_TBL_ENTRY_FORMAT_NEW ("\nvoa_ent[%u]:vld=%u,obj_base_ba=0x%x,obj_max_num=0x%x," \
	"obj_idx_start=0x%x,obj_sz=%u,page_sz=%u,page_mode=%u\n")
union nbl_hmc_voa_entry {
	struct nbl_hmc_voa_entry_key {
		u32 page_mode : 1;
		u32 page_sz : 1;
		u32 obj_idx_start : 29; /* object global index start num */
		u32 rsv : 1;

		u32 obj_max_cnt : 29; /* max object num per function */
		u32 rsv2 : 3;

		u32 obj_ba : 23;
		u32 obj_sz : 4;
		u32 rsv1 : 4;
		u32 valid : 1;
	} key;

#define VOA_TBL_KEY_REG_DW_SIZE (sizeof(struct nbl_hmc_voa_entry_key) / sizeof(u32))
	u32 data[VOA_TBL_KEY_REG_DW_SIZE];
};

struct nbl_hmc_spec {
	u32 qp_num;
	u32 cq_num;
	u32 pble_num;
	u32 mr_num;
};

#define SD_TBL_SIZE DIV_ROUND_UP(NBL_RDMA_HMC_SD_MAX_CNT, BITS_PER_LONG)

enum nbl_resource_profile {
	PF_ONLY,
	PF_VF_EVEN_DISTRIBUTION,
};

struct nbl_grc_res_cfg {
	u32 qpn_start;
	u32 qpn_end;
	u8 addr_mode;
	u16 vf_cnt;
	u32 total_qp_cnt;
	u32 qp_per_vf;
};

struct nbl_obj_cnt {
	u32 qp_num;
	u32 cq_num;
	u32 pble_num;
	u32 mr_num;
	u32 srq_num;
};

#define DSCH_RDMA_NET_NODE_NUM NBL_RDMA_TOTAL_FUNCTION_NUM
#define DSCH_RDMA_GRP_NODE_NUM NBL_RDMA_TOTAL_FUNCTION_NUM
struct rdma_grp_node {
	u16 count;
	DECLARE_BITMAP(net_id_list, DSCH_RDMA_NET_NODE_NUM);
};

struct nbl_grc {
	struct nbl_adev *grc_dev;
	const struct nbl_grc_product_desc *product;
	struct notifier_block grc_ch_rcv_nb;
	struct notifier_block grc_abn_nb;
	struct notifier_block grc_flr_nb;
	struct nbl_hmc_sd_range hmc_sd_range[NBL_RDMA_TOTAL_FUNCTION_NUM];
	union nbl_hmc_voa_entry voa_tbl[NBL_RDMA_TOTAL_FUNCTION_NUM][NBL_HMC_MAX];
	u32 nbl_hmc_obj_spec[NBL_RDMA_TOTAL_FUNCTION_NUM][NBL_HMC_MAX];
	struct nbl_hbf_tbl *hbf_tbl;
	const struct nbl_grc_resource_ops *resource_ops;
	const struct nbl_grc_dsch_ops *dsch_ops;
	const struct nbl_grc_stat_ops *stat_ops;
	const struct nbl_grc_global_ops *global_ops;
	struct nbl_cmd cmd;
	struct nbl_core_export core_dev;
	struct nbl_hmc_spec fn_objs[NBL_RDMA_TOTAL_FUNCTION_NUM];
	unsigned long allocated_sds[SD_TBL_SIZE];
	u8 pf_num;
	u8 res_prof;
	u32 qp_limits;
	u32 qp_max_cnt;
	u32 available_qps;
	struct workqueue_struct *admin_wq;
	struct work_struct abnormal_task;
	u8 sd_addr_mode;
	struct nbl_grc_res_cfg res_cfg;
	struct nbl_gl_sdtbl_info glo_sd_res[NBL_SD_TYPE_MAX];
	struct nbl_obj_cnt dev_objs[NBL_RDMA_TOTAL_FUNCTION_NUM];
	struct nbl_src_addr_rsrc src_addr_rsrc;
	enum ib_atomic_cap atomic_cap;
	struct mutex dev_info_lock;
	struct list_head dev_info_head;
	struct rdma_grp_node grp_list[DSCH_RDMA_GRP_NODE_NUM];
	spinlock_t grp_list_lock;
	u32 devx_umem_num;
};

enum host_id_type {
	HOST_ID_TYPE_HOST = 1,
	HOST_ID_TYPE_ECPU = 2,
	HOST_ID_TYPE_ICPU = 3,
	HOST_ID_TYPE_MAX,
};

#define NBL_GRC_MIN_NET_SHAPING_ID 276
#define NBL_GRC_MAX_NET_SHAPING_ID 339

struct grc_dsch_spec {
	u16 min_net_shaping_id;
	u16 max_net_shaping_id;
	u16 min_grp_shaping_id;
	u16 max_grp_shaping_id;
};

struct cqp_init_req {
	u16 function_id;
	u16 enable;
	u32 cmd_max_num;
	u64 phys_addr;
};

#define GRC_READ_REG_STUB 1
#define NBL_GRC_DEBUG_STUB 1

struct get_function_id_req {
	u32 host_id;
	u32 bdf_num;
	u8 is_pf;
};

struct free_function_id_req {
	u32 host_id;
	u32 bdf_num;
	u16 function_id;
	u8 is_pf;
};

struct set_hdma_vf_enable_req {
	u16 function_id;
	u8 enable;
	u8 rsv;
};

struct set_rdma_dsch_req {
	u16 function_id;
	u8 is_valid;
	u8 rsv;
	u32 host_id;
	u16 dport_id;
	u16 rsv1;
};

struct set_vfid_vsi_map_req {
	u16 function_id;
	u16 vsi_id;
	u8 valid;
	u8 rsv[3];
};

struct nbl_init_params {
	u8 sd_addr_mode;
	u8 resv;
	enum ib_atomic_cap atomic_cap;
	u32 devx_umem_num;
};

struct rw_dw_reg {
	u32 offset; /* Absolute byte offset in BAR0. */
	u32 data;
};

static_assert(sizeof(struct rw_dw_reg) == 2 * sizeof(u32));

#define GRC_RESP_MSG_LEN 128
struct grc_resp_msg {
	u8 msg[GRC_RESP_MSG_LEN];
	u8 msg_len;
};

struct nbl_ena_rdma_intrl_req {
	u16 msix_global_idx;
	u8 devfn;
	u8 bus;
	u8 valid;
	u8 rsv[3];
};

enum nbl_flush_status {
	ASIC_ARMCQ_L_STATUS,
	ASIC_ARMCQ_H_STATUS,
	DF200_ARMCQ_STATUS,
	RNIC_ARMCQ_STATUS,
	RQ_DB_STATUS,
	FLUSH_STATUS_MAX,
};

struct get_armcq_flush_status_req {
	u16 function_id;
};

#define grc_pr_err(format, arg...)                                             \
	pr_err("[grc]%s:%d: " format, __func__, __LINE__, ##arg)

#define grc_pr_warn(format, arg...)                                            \
	pr_warn("[grc]%s:%d: " format, __func__, __LINE__, ##arg)

#define grc_pr_notice(format, arg...)                                            \
	pr_notice("[grc]%s:%d: " format, __func__, __LINE__, ##arg)

#define grc_pr_debug(format, arg...)                                            \
	pr_debug("[grc]%s:%d: " format, __func__, __LINE__, ##arg)

void grc_mbx_msg_process(struct nbl_grc *grc, void *msg, u16 msg_len,
			 struct nbl_chan_rdma_resp *mbx_resp);

bool nbl_func_id_valid(struct nbl_grc *grc, u16 function_id);
#endif /* NBL_GRC_MAIN_H */
