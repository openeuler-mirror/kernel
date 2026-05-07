/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef NBL_GRC_MAIN_H
#define NBL_GRC_MAIN_H

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/pci.h>
#include <linux/iommu.h>
#include <linux/iova.h>
#include <linux/version.h>
#include "rdma_common.h"
#include "grc_common.h"

#define NBL_RDMA_TOTAL_FUNCTION_NUM 64
#define NBL_RDMA_ADMIN_CQP_FUNCTION_NUM (NBL_RDMA_TOTAL_FUNCTION_NUM - 1)
#define NBL_RDMA_CQP_MAX_FUN_ID (NBL_RDMA_ADMIN_CQP_FUNCTION_NUM - 1)

#define FUNCTION_ID_TBL_SIZE DIV_ROUND_UP(NBL_RDMA_TOTAL_FUNCTION_NUM, BITS_PER_LONG)

extern struct nbl_hw_rdma_ops hw_rdma_ops;

#define NBL_SD_VALID 1
#define NBL_DBQ_SIZE SZ_8M
#define NBL_TQ_RTO_SIZE SZ_8M
#define NBL_TQ_RNR_SIZE SZ_4M

#define NBL_GRC_CACHE_MSG_RESP_BUSY EBUSY
#define NBL_GRC_MSG_RESP_ERR 1
#define NBL_GRC_MSG_RESP_OK 0
#define NBL_RDMA_MAX_PF 8
#define NBL_RDMA_MIN_PF 2

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
	NBL_SD_TYPE_DBQ = 0,
	NBL_SD_TYPE_TQ_RTO = 1,
	NBL_SD_TYPE_TQ_RNR = 2,
	NBL_SD_TYPE_MAX,
};

enum nbl_tm_algorithm {
	nbl_tm_algorithm_dwrr,
	nbl_tm_algorithm_sp,
	nbl_tm_algorithm_max
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

enum nbl_fmr_nofence_en {
	NBL_FMR_NOFENCE_DISABLE = 0,
	NBL_FMR_NOFENCE_ENABLE = 1,
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
	struct nbl_hbf_entry entries[];
};

enum nbl_hmc_rsrc_type {
	NBL_HMC_QP = 0,
	NBL_HMC_CQ = 1,
	NBL_HMC_PBL = 2,
	NBL_HMC_MR = 3,
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
#define NBL_HMC_MRTE_SZ 32

#define NBL_HMC_MAX_SD_CNT  SZ_2K
#define NBL_HMC_SD_CNT_PER_CMD 64
#define NBL_CMD_INT_USE_WQ 1 /* 1- use wq when interrupt mode, save time, 0- not use wq */
#define NBL_CMD_WQ_MAX_NAME 32
#define NBL_ADAPTER_PAGE_SHIFT 12
#define NBL_ADAPTER_PAGE_SIZE BIT(NBL_ADAPTER_PAGE_SHIFT)
#define NBL_CMD_ENTRY_SIZE 128
#define NBL_CMD_ENTRY_SIZE_LOG 7
#define NBL_CMD_ENTRY_MAX_NUM (NBL_ADAPTER_PAGE_SIZE / NBL_CMD_ENTRY_SIZE)
#define NBL_RDMA_TOTAL_FUNCTION_NUM 64
#define NBL_RDMA_FIRST_FUNCTION_ID 0
#define NBL_HMC_MAX_OBJ_LOG_SZ 9   /* qpc log size (1 << 9) */
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

union nbl_rdma_pfid_map_tbl_reg;
struct nbl_hw_rdma_ops {
	void (*set_sd_range)(struct nbl_core_dev_info *core_dev, u16 function_id,
			     u32 sd_start, u32 sd_cnt, bool valid);
	void (*get_sd_range)(struct nbl_core_dev_info *core_dev, u16 function_id,
			     u32 *sd_start, u32 *sd_cnt);
	void (*set_bdf_func_id_map)(struct nbl_core_dev_info *core_dev, u32 host_id,
				    u32 bdf_num, u16 func_id);
	void (*set_src_addr_info)(struct nbl_core_dev_info *core_dev, u8 *smac, u8 *sip,
				  u8 insert_vlan_ipv4_valid, u16 src_addr_index);
	void (*set_cqp_info)(struct nbl_core_dev_info *core_dev, u16 function_id,
			     u64 cqp_ba, u32 cqp_len, bool enable);
	void (*set_cqp_base_reg)(struct nbl_core_dev_info *core_dev, u16 max_vfid);
	void (*set_cqp_pi)(struct nbl_core_dev_info *core_dev, u32 cur_pi, u8 odd_even);
	void (*set_pcomplete_ecpu)(struct nbl_core_dev_info *core_dev, u16 function_id,
				   u16 valid);
	void (*set_eot_table)(struct nbl_core_dev_info *core_dev, bool valid);
	void (*set_hw_stat)(struct nbl_core_dev_info *core_dev, u32 op_info);
	void (*get_hw_stat)(struct nbl_core_dev_info *core_dev, u32 op_info,
			    u32 pa_l, u32 pa_h, u16 func_id);
	void (*enable_errcode_hw_stat)(struct nbl_core_dev_info *core_dev,
				       u32 enable);
	void (*get_hw_status)(struct nbl_core_dev_info *core_dev, u32 *status);
	void (*set_rdma_dsch)(struct nbl_core_dev_info *core_dev,
			      u16 function_id, u32 host_id, u16 dport_id, u8 vld);
	void (*set_rdma_pfid_map_tbl)(struct nbl_core_dev_info *core_dev,
				      u16 idx, union nbl_rdma_pfid_map_tbl_reg *map);
	void (*set_rdma_tbl_sel)(struct nbl_core_dev_info *core_dev, u16 sel);
	void (*set_rdma_tbl_ready)(struct nbl_core_dev_info *core_dev, u16 ready);

	void (*set_cc_params)(struct nbl_core_dev_info *core_dev, u32 offset, u32 var);
	void (*set_vf_enable)(struct nbl_core_dev_info *core_dev, u16 function_id, u8 enable);
	void (*set_vfid_vsi_map)(struct nbl_core_dev_info *core_dev,
				 u16 function_id, u16 vsi_id, u8 valid);
	void (*ena_rdma_intrl)(struct nbl_core_dev_info *core_dev, u16 global_msix_idx,
			       u8 devfn, u8 bus, u8 valid);
	void (*init_net_tc_tbl)(struct nbl_core_dev_info *core_dev);
	void (*update_rdma_dsch)(struct nbl_core_dev_info *core_dev, u16 function_id,
				 u32 host_id, u16 dport_id, u8 vld);
	void (*set_epro_cfg_err)(struct nbl_core_dev_info *core_dev, u8 mask);
	void (*set_hdma_dif_vfid)(struct nbl_core_dev_info *core_dev, u16 function_id);
	void (*get_abnormal_event)(struct nbl_core_dev_info *core_dev);
	void (*set_rqdb_int_mask)(struct nbl_core_dev_info *core_dev);
	void (*set_qos_default_cfg)(struct nbl_core_dev_info *core_dev);
	void (*set_dif_vf_off)(struct nbl_core_dev_info *core_dev, bool is_off);
	void (*set_sw_db_wqe_cap)(struct nbl_core_dev_info *core_dev);
	void (*clear_hw_cache)(struct nbl_core_dev_info *core_dev, u32 cache_type);
};

#define GRC_MBX_WQ_NAME_LEN 32
struct nbl_hmc_sd_range {
	u32 start;
	u32 cnt;
};

struct nbl_hmc_voa_entry {
	u64 addr_mode : 1;
	u64 page_sz : 1;
	u64 obj_sz : 4;
	u64 rsv : 5;
	u64 obj_max_cnt : 29;
	u64 obj_ba : 23;
	u64 valid : 1;
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

#define MAX_SRC_ADDR_SIZE 256
struct nbl_src_addr_tbl {
	u16 function_id;
	u16 sgid_index;
	u8 sgid[16];
};

struct nbl_src_addr_rsrc {
	spinlock_t idx_lock; /* protect idx_bitmap */
	unsigned long idx_bitmap[MAX_SRC_ADDR_SIZE / BITS_PER_LONG + 1];
	struct nbl_src_addr_tbl addr_tbl[MAX_SRC_ADDR_SIZE];
};

#define NBL_STATS_GROUP_NUM 128
struct nbl_rdma_stat_info {
	u32 stat_id_used_cnt[NBL_STATS_GROUP_NUM];
	struct list_head stat_head[NBL_STATS_GROUP_NUM];
	spinlock_t stat_head_lock[NBL_STATS_GROUP_NUM]; /* protect stat_head */
};

#define DSCH_RDMA_GRP_NODE_NUM NBL_RDMA_TOTAL_FUNCTION_NUM
#define DSCH_RDMA_NET_NODE_NUM NBL_RDMA_TOTAL_FUNCTION_NUM
struct rdma_grp_node {
	u16 count;
	DECLARE_BITMAP(net_id_list, DSCH_RDMA_NET_NODE_NUM);
};

struct nbl_grc {
	unsigned long function_id_tbl[FUNCTION_ID_TBL_SIZE];
	struct nbl_hmc_sd_range hmc_sd_range[NBL_RDMA_TOTAL_FUNCTION_NUM];
	struct nbl_hmc_voa_entry voa_tbl[NBL_RDMA_TOTAL_FUNCTION_NUM][NBL_HMC_MAX];
	u32 nbl_hmc_obj_spec[NBL_RDMA_TOTAL_FUNCTION_NUM][NBL_HMC_MAX];
	struct nbl_hbf_tbl *hbf_tbl;
	struct nbl_hw_rdma_ops *ops;
	struct nbl_cmd cmd;
	struct rdma_host_notify *host_notify;
	struct nbl_core_dev_info core_dev;
	struct nbl_hmc_spec fn_objs[NBL_RDMA_TOTAL_FUNCTION_NUM];
	unsigned long allocated_sds[SD_TBL_SIZE];
	u8 pf_num;
	u32 qps_per_rf;
	u32 available_qps;
	struct workqueue_struct *admin_wq;
	struct work_struct abnormal_task;
	spinlock_t dev_info_lock;
	struct list_head dev_info_head;
	struct nbl_src_addr_rsrc src_addr_rsrc;
	/* nbl statistical resource management */
	struct nbl_rdma_stat_info stat_info;
	spinlock_t stat_lock; /* protect g_stat_info */
	struct nbl_gl_sdtbl_info sd_res[NBL_SD_TYPE_MAX];
	struct rdma_grp_node grp_list[DSCH_RDMA_GRP_NODE_NUM];
	spinlock_t grp_list_lock;
	u16 total_rf_num;
	u8 sd_addr_mode;
	bool has_high_temp_alarm;
	int active_rf_num;
};

struct dev_info {
	u16 vsi_id;
	u16 real_bdf;
	u16 function_id;
	u8 eth_id;
};
struct dev_info_node {
	struct list_head list;
	struct dev_info info;
};

struct nbl_grc_flr_work {
	struct work_struct work;
	struct nbl_grc *grc;
	u16 vsi_id;
};

enum host_id_type {
	HOST_ID_TYPE_HOST = 1,
	HOST_ID_TYPE_ECPU = 2,
	HOST_ID_TYPE_ICPU = 3,
	HOST_ID_TYPE_MAX,
};

#define NBL_GRC_MIN_NET_SHAPING_ID 448
#define NBL_GRC_MAX_NET_SHAPING_ID 511
#define NBL_GRC_MIN_GRP_SHAPING_ID 192
#define NBL_GRC_MAX_GRP_SHAPING_ID 255

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

#define NBL_CQPSQ_OPCODE GENMASK_ULL(52, 48)
#define NBL_CQPSQ_SD_TYPE GENMASK_ULL(47, 45)
#define NBL_CQPSQ_SD_NUM GENMASK_ULL(44, 38)
#define NBL_CQPSQ_SD_START GENMASK_ULL(37, 25)
#define NBL_CQPSQ_VF_ID GENMASK_ULL(47, 39)

/* CQPP REG */
#define NBL_REG_CQPP_INFO_TABLE_RAM_PI_ODD BIT_ULL(5)
#define NBL_REG_CQPP_INFO_TABLE_RAM_PI GENMASK_ULL(4, 0)

#define NBL_CQP_OP_UPDATE_SD 0xC
#define NBL_CQP_OP_QUERY_SD 0xD
#define NBL_CQP_OP_UPDATE_VOA 0xE
#define NBL_CQP_OP_QUERY_VOA 0xF

#define GRC_READ_REG_STUB 1
#define NBL_GRC_DEBUG_STUB 1

struct get_function_id_req {
	u32 host_id;
	u32 bdf_num;
};

struct free_function_id_req {
	u32 host_id;
	u32 bdf_num;
	u16 function_id;
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
};

struct rw_dw_reg {
	u32 offset;
	u32 data;
};

#define GRC_RESP_MSG_LEN 128
struct grc_resp_msg {
	u8 msg[GRC_RESP_MSG_LEN];
	u8 msg_len;
};

struct notify_info_req {
	u32 host_id;
	u16 function_id;
	u16 valid;
	u64 bar0_phy_addr;
	u16 product_type;
	u16 rsv;
};

struct nbl_ena_rdma_intrl_req {
	u16 msix_global_idx;
	u8 devfn;
	u8 bus;
	u8 valid;
	u8 rsv[3];
};

#define grc_pr_err(format, arg...)                                             \
	pr_err("[grc]%s:%d: " format, __func__, __LINE__, ##arg)

#define grc_pr_warn(format, arg...)                                            \
	pr_warn("[grc]%s:%d: " format, __func__, __LINE__, ##arg)

#define grc_pr_notice(format, arg...)                                            \
	pr_notice("[grc]%s:%d: " format, __func__, __LINE__, ##arg)

#define grc_pr_debug(format, arg...)                                            \
	pr_debug("[grc]%s:%d: " format, __func__, __LINE__, ##arg)

static inline void set_64bit_val(__be64 *wqe_words, u32 byte_index, u64 val)
{
	wqe_words[byte_index >> 3] = cpu_to_be64(val);
}

static inline void get_64bit_val(__be64 *wqe_words, u32 byte_index, u64 *val)
{
	*val = be64_to_cpu(wqe_words[byte_index >> 3]);
}

void grc_mbx_msg_process(struct auxiliary_device *aux_dev, void *msg, u16 msg_len,
			 struct nbl_chan_rdma_resp *mbx_resp);
void grc_abnormal_event_process(struct auxiliary_device *aux_dev);

#define NBL_RESERVE_START_IOVA 0x1000
#define NBL_RESERVE_END_IOVA 0x10000
#define NBL_RESERVE_RANGE_IOVA (NBL_RESERVE_END_IOVA - NBL_RESERVE_START_IOVA)

#endif /* NBL_GRC_MAIN_H */
