/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_cqm_main.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_CQM_MAIN_H
#define HINIC5_CQM_MAIN_H

#include "hinic5_crm.h"
#include "hinic5_cqm_bloomfilter.h"
#include "hinic5_hwif_inner.h"
#include "hinic5_cqm_bat_cla.h"

#define GET_MAX(a, b) ((a) > (b) ? (a) : (b))
#define GET_MIN(a, b) ((a) < (b) ? (a) : (b))
#define HINIC5_CQM_DW_SHIFT       2
#define HINIC5_CQM_QW_SHIFT       3

#define CHIPIF_SUCCESS     0
#define CHIPIF_FAIL        (-1)

#define HINIC5_CQM_TIMER_ENABLE   1
#define HINIC5_CQM_TIMER_DISABLE  0

#define HINIC5_CQM_HANDLE_STATE_INIT		0
#define HINIC5_CQM_HANDLE_STATE_READY		1
#define HINIC5_CQM_HANDLE_STATE_REMOVE		2

/* The value must be the same as that of hinic5_service_type in hinic5_crm.h. */
#define HINIC5_CQM_SERVICE_T_NIC    SERVICE_T_NIC
#define HINIC5_CQM_SERVICE_T_OVS    SERVICE_T_OVS
#define HINIC5_CQM_SERVICE_T_ROCE   SERVICE_T_ROCE
#define HINIC5_CQM_SERVICE_T_TOE    SERVICE_T_TOE
#define HINIC5_CQM_SERVICE_T_IOE    SERVICE_T_IOE
#define HINIC5_CQM_SERVICE_T_FC     SERVICE_T_FC
#define HINIC5_CQM_SERVICE_T_VBS    SERVICE_T_VBS
#define HINIC5_CQM_SERVICE_T_IPSEC  SERVICE_T_IPSEC
#define HINIC5_CQM_SERVICE_T_VIRTIO SERVICE_T_VIRTIO
#define HINIC5_CQM_SERVICE_T_PPA    SERVICE_T_PPA
#define HINIC5_CQM_SERVICE_T_UB     SERVICE_T_UB
#define HINIC5_CQM_SERVICE_T_JBOF   SERVICE_T_JBOF
#define HINIC5_CQM_SERVICE_T_VROCE   SERVICE_T_VROCE
#define HINIC5_CQM_SERVICE_T_DMMU   SERVICE_T_DMMU
#define HINIC5_CQM_SERVICE_T_CFM    SERVICE_T_CFM
#define HINIC5_CQM_SERVICE_T_MAX    SERVICE_T_MAX

struct tag_hinic5_cqm_service {
	bool valid;	   /* Whether to enable this service on the function. */
	bool has_register; /* Registered or Not */
	u64 hardware_db_paddr;
	void __iomem *hardware_db_vaddr;
	u64 dwqe_paddr;
	void __iomem *dwqe_vaddr;
	u32 buf_order;     /* The size of each buf node is 2^buf_order pages. */
	struct tag_service_register_template service_template;
};

struct tag_hinic5_cqm_fake_cfg {
	u32 parent_func;       /* The parent func_id of the fake vfs. */
	u32 child_func_start;  /* The start func_id of the child fake vfs. */
	u32 child_func_number; /* The number of the child fake vfs. */

	bool fake_vf_lazy_init;

	u32 fake_vf_max_pctx;
	u32 fake_vf_max_scqc_ctx;
	u32 fake_vf_max_srqc_ctx;
	u32 fake_vf_max_gid_ctx;
	u32 fake_vf_max_mpt_ctx;
	u32 fake_vf_max_childc_ctx;

	u8  fake_vf_qpc_basic_size;

	u16 fake_vf_bfilter_start_addr;
	u16 fake_vf_bfilter_len;
};

typedef struct tag_hinic5_cqm_func_capability {
	/* BAT_PTR table(SMLC) */
	bool ft_enable; /* BAT for flow table enable: support toe/ioe/fc service
			 */
	bool rdma_enable; /* BAT for rdma enable: support RoCE */
	/* VAT table(SMIR) */
	bool ft_pf_enable; /* Same as ft_enable. BAT entry for toe/ioe/fc on pf
			    */
	bool rdma_pf_enable; /* Same as rdma_enable. BAT entry for rdma on pf */

	u8 gpa_spu_en;

	/* Dynamic or static memory allocation during the application of
	 * specified QPC/SCQC for each service.
	 */
	bool qpc_alloc_static;
	bool scqc_alloc_static;
	bool srqc_alloc_static;

	u8 timer_enable;       /* Whether the timer function is enabled */
	u8 bloomfilter_enable; /* Whether the bloomgfilter function is enabled
				*/
	u32 flow_table_based_conn_number; /* Maximum number of connections for
					   * toe/ioe/fc, whitch cannot excedd
					   * qpc_number
					   */
	u32 flow_table_based_conn_cache_number; /* Maximum number of sticky
						 * caches
						 */
	u32 bloomfilter_length; /* Size of the bloomfilter table, 64-byte
				 * aligned
				 */
	u32 bloomfilter_addr; /* Start position of the bloomfilter table in the
			       * SMF main cache.
			       */
	u32 qpc_reserved;     /* Reserved bit in bitmap */
	u32 qpc_reserved_back; /* Reserved back bit in bitmap */
	u32 mpt_reserved;     /* The ROCE/IWARP MPT also has a reserved bit. */
	u32 mpt_reserved_back; /* Reserved back bit in bitmap */

	/* All basic_size must be 2^n-aligned. */
	u32 hash_number; /* The number of hash bucket. The size of BAT table is
			  * aliaed with 64 bucket. At least 64 buckets is
			  * required.
			  */
	u32 hash_basic_size; /* THe basic size of hash bucket is 64B, including
			      * 5 valid entry and one next entry.
			      */
	u32 qpc_number;
	u32 qpc_basic_size;

	/* Number of PFs/VFs on the current host only for timer resource used */
	u32 pf_num;
	u32 pf_id_start;
	u32 vf_num;
	u32 vf_id_start;

	u8 timer_pf_id_start;
	u8 timer_pf_num;
	u16 timer_vf_id_start;
	u16 timer_vf_num;
	u16 timer_vf_num_actual;
	bool timer_vf_deploy_with_segs;
	struct timer_vf_info_seg timer_vf_segs[TIMER_VF_SEGS_NUM];

	bool use_fake_parent_cla;

	/* SMF capabilities */
	u32 lb_mode;
	/* A bitmap indicating which SMFs are enabled.
	 * For example, 0101B indicates that SMF0 and SMF2 are enabled.
	 * The valid length of this bitmap is smf_max_num.
	 */
	u32 smf_pg;
	u32 smf_max_num;
	u32 smf_enabled_num;

	/* SMF BAT capabilities */
	u8 bat_cid_index_bit_width;

	/* Fake VF capabilities */
	u32 fake_func_type;  /* Whether the current function belongs to the fake
			      * group (parent or child)
			      */
	struct tag_hinic5_cqm_fake_cfg fake_cfg;

	/* Note: for hinic5_cqm specail test */
	u32 pagesize_reorder;
	bool xid_alloc_mode;
	bool gpa_check_enable;
	u32 scq_reserved;
	u32 scq_reserved_back;
	u32 srq_reserved;
	u32 srq_reserved_back;

	u32 mpt_number;
	u32 mpt_basic_size;
	u32 scqc_number;
	u32 scqc_basic_size;
	u32 srqc_number;
	u32 srqc_basic_size;

	u32 gid_number;
	u32 gid_basic_size;
	u32 lun_number;
	u32 lun_basic_size;
	u32 taskmap_number;
	u32 taskmap_basic_size;
	u32 l3i_number;
	u32 l3i_basic_size;
	u32 childc_number;
	u32 childc_basic_size;
	u32 child_qpc_id_start; /* FC service Child CTX is global addressing. */
	u32 childc_number_all_function; /* The chip supports a maximum of 8096
					 * child CTXs.
					 */
	u32 timer_number;
	u32 timer_basic_size;
	u32 xid2cid_number;
	u32 xid2cid_basic_size;
	u32 reorder_number;
	u32 reorder_basic_size;
} hinic5_cqm_func_capability_s;

#define HINIC5_CQM_PF                             TYPE_PF
#define HINIC5_CQM_VF                             TYPE_VF
#define HINIC5_CQM_PPF                            TYPE_PPF
#define HINIC5_CQM_UNKNOWN                        TYPE_UNKNOWN
#define HINIC5_CQM_MAX_PF_NUM                     32

#define HINIC5_CQM_LB_MODE_NORMAL                 0xff
#define HINIC5_CQM_LB_MODE_0                      0
#define HINIC5_CQM_LB_MODE_1                      1
#define HINIC5_CQM_LB_MODE_2                      2

#define HINIC5_CQM_FPGA_MODE                      0
#define HINIC5_CQM_EMU_MODE                       1

#define HINIC5_CQM_FAKE_FUNC_UNUSED            0U /* The HINIC5_CQM handle does not use Fake VF. */
#define HINIC5_CQM_FAKE_FUNC_PARENT            1U /* The HINIC5_CQM handle is responsible for
					      initializing some VF's resouces. */
#define HINIC5_CQM_FAKE_FUNC_CHILD_AGENT       2U /* An agent handle created by a Fake VF
					      Parent that acts as a Fake VF Child
					      in Fake VF Parent's process. */
#define HINIC5_CQM_FAKE_FUNC_CHILD             3U /* Some resources of this HINIC5_CQM handle
					      are managed by a Fake VF Parent. */

#define HINIC5_CQM_FAKE_FUNC_MAX                  32

#define HINIC5_CQM_QPC_ROCE_PER_DRCT              12
#define HINIC5_CQM_QPC_ROCE_NORMAL   0
#define HINIC5_CQM_QPC_ROCE_VBS_MODE 2

struct tag_hinic5_cqm_toe_private_capability {
	/* TOE srq is different from other services
	 * and does not need to be managed by the CLA table.
	 */
	u32 toe_srqc_number;
	u32 toe_srqc_basic_size;
	u32 toe_srqc_start_id;

	struct tag_hinic5_cqm_bitmap srqc_bitmap;
};

struct hinic5_cqm_cmdq_ops;
struct tag_hinic5_cqm_handle {
	struct hinic5_hwdev *ex_handle;
	struct device *dev;
	struct hinic5_func_attr func_attribute; /* vf/pf attributes */
	struct tag_hinic5_cqm_func_capability func_capability; /* function capability set */
	struct tag_hinic5_cqm_service service[HINIC5_CQM_SERVICE_T_MAX]; /* Service-related structure */
	struct tag_hinic5_cqm_bat_table bat_table;
	struct tag_hinic5_cqm_bloomfilter_table bloomfilter_table;

	atomic_t handle_state;          /* see HINIC5_CQM_HANDLE_STATE_XXX */

	/* fake-vf-related structure */
	struct tag_hinic5_cqm_handle *fake_hinic5_cqm_handle[HINIC5_CQM_FAKE_FUNC_MAX];
	struct tag_hinic5_cqm_handle *parent_hinic5_cqm_handle;

	struct tag_hinic5_cqm_toe_private_capability toe_own_capability; /* TOE service-related
								   * capability set
								   */

	char name[HINIC5_VRAM_NAME_MAX_LEN];
	struct hinic5_cqm_cmdq_ops *cmdq_ops;
};

#define HINIC5_CQM_FUNC_TYPE(hinic5_cqm_handle)      ((hinic5_cqm_handle)->func_attribute.func_type)
#define HINIC5_CQM_FAKE_FUNC_TYPE(hinic5_cqm_handle) ((hinic5_cqm_handle)->func_capability.fake_func_type)

#define HINIC5_CQM_IS_FAKE_PARENT(hinic5_cqm_handle) \
	(HINIC5_CQM_FAKE_FUNC_TYPE(hinic5_cqm_handle) == HINIC5_CQM_FAKE_FUNC_PARENT)
#define HINIC5_CQM_IS_FAKE_CHILD(hinic5_cqm_handle) \
	(HINIC5_CQM_FAKE_FUNC_TYPE(hinic5_cqm_handle) == HINIC5_CQM_FAKE_FUNC_CHILD)
#define HINIC5_CQM_IS_FAKE_CHILD_AGENT(hinic5_cqm_handle) \
	(HINIC5_CQM_FAKE_FUNC_TYPE(hinic5_cqm_handle) == HINIC5_CQM_FAKE_FUNC_CHILD_AGENT)

#define HINIC5_CQM_IS_PPF(hinic5_cqm_handle)       (HINIC5_CQM_FUNC_TYPE(hinic5_cqm_handle) == HINIC5_CQM_PPF)
#define HINIC5_CQM_IS_VF(hinic5_cqm_handle)        (HINIC5_CQM_FUNC_TYPE(hinic5_cqm_handle) == HINIC5_CQM_VF && \
				      HINIC5_CQM_FAKE_FUNC_TYPE(hinic5_cqm_handle) == HINIC5_CQM_FAKE_FUNC_UNUSED)

#define HINIC5_CQM_CLA_IS_SECURE_MEM(type)  ((type) == HINIC5_CQM_BAT_ENTRY_T_QPC || (type) == HINIC5_CQM_BAT_ENTRY_T_MPT || \
				      (type) == HINIC5_CQM_BAT_ENTRY_T_SCQC || (type) == HINIC5_CQM_BAT_ENTRY_T_SRQC)

#define HINIC5_CQM_IS_LB_MODE_NORMAL(hinic5_cqm_handle) ((hinic5_cqm_handle)->func_capability.lb_mode == HINIC5_CQM_LB_MODE_NORMAL)
#define HINIC5_CQM_IS_LB_MODE_0(hinic5_cqm_handle)	  ((hinic5_cqm_handle)->func_capability.lb_mode == HINIC5_CQM_LB_MODE_0)
#define HINIC5_CQM_IS_LB_MODE_1(hinic5_cqm_handle)	  ((hinic5_cqm_handle)->func_capability.lb_mode == HINIC5_CQM_LB_MODE_1)
#define HINIC5_CQM_IS_LB_MODE_2(hinic5_cqm_handle)	  ((hinic5_cqm_handle)->func_capability.lb_mode == HINIC5_CQM_LB_MODE_2)
#define HINIC5_CQM_IS_LB_MODE_1_OR_2(hinic5_cqm_handle) (HINIC5_CQM_IS_LB_MODE_1(hinic5_cqm_handle) || HINIC5_CQM_IS_LB_MODE_2(hinic5_cqm_handle))

#define HINIC5_CQM_CQN_FROM_CEQE(data)      ((data) & 0xfffff)
#define HINIC5_CQM_XID_FROM_CEQE(data)      ((data) & 0xfffff)
#define HINIC5_CQM_QID_FROM_CEQE(data)      (((data) >> 20) & 0x7)
#define HINIC5_CQM_TYPE_FROM_CEQE(data)     (((data) >> 23) & 0x7)

#define HINIC5_CQM_HASH_BUCKET_SIZE_64      64

#define HINIC5_CQM_MAX_QPC_NUM              0x100000
#define HINIC5_CQM_MAX_SCQC_NUM             0x100000
#define HINIC5_CQM_MAX_SRQC_NUM             0x100000
#define HINIC5_CQM_MAX_CHILDC_NUM           0x100000

#define HINIC5_CQM_QPC_SIZE_256             256
#define HINIC5_CQM_QPC_SIZE_512             512
#define HINIC5_CQM_QPC_SIZE_1024            1024

#define HINIC5_CQM_SCQC_SIZE_32             32
#define HINIC5_CQM_SCQC_SIZE_64             64
#define HINIC5_CQM_SCQC_SIZE_128            128

#define HINIC5_CQM_SRQC_SIZE_32             32
#define HINIC5_CQM_SRQC_SIZE_64             64
#define HINIC5_CQM_SRQC_SIZE_128            128

#define HINIC5_CQM_MPT_SIZE_64              64

#define HINIC5_CQM_GID_SIZE_32              32

#define HINIC5_CQM_LUN_SIZE_8               8

#define HINIC5_CQM_L3I_SIZE_8               8

#define HINIC5_CQM_TIMER_SIZE_32            32

#define HINIC5_CQM_XID2CID_SIZE_8           8

#define HINIC5_CQM_REORDER_SIZE_256         256

#define HINIC5_CQM_CHILDC_SIZE_256          256

#define HINIC5_CQM_XID2CID_VBS_NUM          (2 * 1024) /* 2K nvme Q */

#define HINIC5_CQM_VBS_QPC_SIZE             512

#define HINIC5_CQM_VBS_SCQC_SIZE            128

/* Default number of VirtIO VQs.
 * Future models should get this value from the MGMT.
 */
#define HINIC5_CQM_VIRTIO_VQ_NUM_DEFAULT    (16 * 1024)
#define HINIC5_CQM_VIRTIO_FC_SIZE           256                /* VirtIO Function Context size */

#define HINIC5_CQM_GID_RDMA_NUM             128

#define HINIC5_CQM_LUN_FC_NUM               64

#define HINIC5_CQM_TASKMAP_FC_NUM           4

#define HINIC5_CQM_L3I_COMM_NUM             64

#define HINIC5_CQM_CHILDC_OVS_VBS_NUM       (8 * 1024)
#define HINIC5_CQM_CHILDC_VBS_NUM           (2 * 1024)

#define HINIC5_CQM_TIMER_SCALE_NUM          (2 * 1024)
#define HINIC5_CQM_TIMER_ALIGN_WHEEL_NUM    8
#define HINIC5_CQM_TIMER_ALIGN_SCALE_NUM \
	(HINIC5_CQM_TIMER_SCALE_NUM * HINIC5_CQM_TIMER_ALIGN_WHEEL_NUM)

#define HINIC5_CQM_QPC_OVS_RSVD             (1024 * 1024)
#define HINIC5_CQM_QPC_ROCE_RSVD            2
#define HINIC5_CQM_QPC_ROCEAA_SWITCH_QP_NUM 4
#define HINIC5_CQM_QPC_ROCEAA_RSVD \
	(4 * 1024 + HINIC5_CQM_QPC_ROCEAA_SWITCH_QP_NUM) /* 4096 Normal QP +
						   * 4 Switch QP
						   */
#define HINIC5_CQM_CQ_ROCE_RSVD           16
#define HINIC5_CQM_CQ_UB_RSVD             131072 // 128K
#define HINIC5_CQM_SRQ_ROCE_RSVD          16

#define HINIC5_CQM_CQ_ROCEAA_RSVD           64
#define HINIC5_CQM_SRQ_ROCEAA_RSVD          64
#define HINIC5_CQM_QPC_ROCE_VBS_RSVD_BACK   204800  /* 200K */
#define HINIC5_CQM_CQ_VBS_VOLQ_RSVD         (2 + 2048)
#define HINIC5_CQM_CQ_ROCE_VBS_RSVD         GET_MAX(HINIC5_CQM_QPC_ROCE_VBS_RSVD_BACK, HINIC5_CQM_CQ_VBS_VOLQ_RSVD)

#define HINIC5_CQM_OVS_MAX_TIMER_FUNC       48

#define HINIC5_CQM_HASH_BUCKET_NUM_UNIT_4_TO_64      4
#define HINIC5_CQM_CRYPT_HASH_BUCKET_NUM(tbl_num)   ((tbl_num) >> HINIC5_CQM_HASH_BUCKET_NUM_UNIT_4_TO_64)

#define HINIC5_CQM_PPA_PAGESIZE_ORDER       8

#if defined(__WIN__) && defined(__HIFC__)
#define HINIC5_CQM_FC_PAGESIZE_ORDER 8
#else
#define HINIC5_CQM_FC_PAGESIZE_ORDER 0
#endif

#define HINIC5_CQM_QHEAD_ALIGN_ORDER 6

typedef void (*serv_cap_init_cb)(struct tag_hinic5_cqm_handle *, void *);

struct hinic5_cqm_srv_cap_init {
	u32 service_type;
	serv_cap_init_cb serv_cap_proc;
};

/* Only for llt test */
s32 hinic5_cqm_capability_init(void *ex_handle);
/* Can be defined as static */
s32 hinic5_cqm_mem_init(void *ex_handle);
void hinic5_cqm_mem_uninit(void *ex_handle);
s32 hinic5_cqm_event_init(void *ex_handle);
void hinic5_cqm_event_uninit(void *ex_handle);
void hinic5_cqm_scq_callback(void *ex_handle, u32 ceqe_data);
void hinic5_cqm_ecq_callback(void *ex_handle, u32 ceqe_data);
void hinic5_cqm_nocq_callback(void *ex_handle, u32 ceqe_data);
u8 hinic5_cqm_aeq_callback(void *ex_handle, u8 event, u8 *data);

s32 hinic5_cqm_init(void *ex_handle);
void hinic5_cqm_uninit(void *ex_handle);
s32 hinic5_cqm_service_register(void *ex_handle, struct tag_service_register_template *service_template);
void hinic5_cqm_service_unregister(void *ex_handle, u32 service_type);

s32 hinic5_cqm_fake_vf_num_set(void *ex_handle, u16 fake_vf_num_cfg);

#define HINIC5_CQM_LOG_ID 0

#define HINIC5_CQM_PTR_NULL(x)      "%s: " #x " is null\n", __func__
#define HINIC5_CQM_ALLOC_FAIL(x)    "%s: " #x " alloc fail\n", __func__
#define HINIC5_CQM_MAP_FAIL(x)      "%s: " #x " map fail\n", __func__
#define HINIC5_CQM_FUNCTION_FAIL(x) "%s: " #x " return failure\n", __func__
#define HINIC5_CQM_WRONG_VALUE(x)   "%s: " #x " %u is wrong\n", __func__, (u32)(x)

#define hinic5_cqm_err(dev, format, ...)  dev_err(dev, "[HINIC5_CQM]" format, ##__VA_ARGS__)
#define hinic5_cqm_warn(dev, format, ...) dev_warn(dev, "[HINIC5_CQM]" format, ##__VA_ARGS__)
#define hinic5_cqm_notice(dev, format, ...) \
	dev_notice(dev, "[HINIC5_CQM]" format, ##__VA_ARGS__)
#define hinic5_cqm_info(dev, format, ...) dev_info(dev, "[HINIC5_CQM]" format, ##__VA_ARGS__)

#ifdef __HINIC5_CQM_DEBUG__
extern bool hinic5_cqm_verbose;

#define hinic5_cqm_dbg(dev, format, ...) dev_info(dev, "[HINIC5_CQM]" format, ##__VA_ARGS__)
#define hinic5_cqm_dbg_on(condition, dev, format, ...)			\
	({							\
		if (condition)					\
			hinic5_cqm_dbg(dev, format, ##__VA_ARGS__);	\
	})

#define hinic5_cqm_dbg_pr(format, ...) pr_info("[HINIC5_CQM]" format, ##__VA_ARGS__)
#define hinic5_cqm_dbg_pr_on(condition, format, ...)				\
	({							\
		if (condition)					\
			hinic5_cqm_dbg_pr(format, ##__VA_ARGS__);	\
	})

static inline void hinic5_cqm_dbg_byte_print(struct device *dev, u32 *ptr, u32 len)
{
	u32 i;
	for (i = 0; i < (len >> 0x2); i += 0x4)
		hinic5_cqm_dbg(dev, "%.8x %.8x %.8x %.8x\n",
			ptr[i], ptr[i + 0x1], ptr[i + 0x2], ptr[i + 0x3]);
}
#else
#define hinic5_cqm_dbg(format, ...)
#define hinic5_cqm_dbg_on(condition, format, ...)
#define hinic5_cqm_dbg_pr(format, ...)
#define hinic5_cqm_dbg_pr_on(condition, format, ...)
#define hinic5_cqm_dbg_byte_print(dev, ptr, len)
#endif

#define HINIC5_CQM_PTR_CHECK_ERR(desc) pr_err("[HINIC5_CQM]" desc)

static inline u32 hinic5_cqm_get_child_func_start(struct tag_hinic5_cqm_handle *hinic5_cqm_handle)
{
	struct tag_hinic5_cqm_func_capability *func_cap = &hinic5_cqm_handle->func_capability;
	return func_cap->fake_cfg.child_func_start;
}

/*
 * Get the number of child functions.
 * The number of child functions can be zero.
 */
static inline u32 hinic5_cqm_get_child_func_number(struct tag_hinic5_cqm_handle *hinic5_cqm_handle)
{
	struct tag_hinic5_cqm_func_capability *func_cap = &hinic5_cqm_handle->func_capability;
	return func_cap->fake_cfg.child_func_number;
}

static inline bool hinic5_cqm_is_fake_vf_lazy_init(struct tag_hinic5_cqm_handle *hinic5_cqm_handle)
{
	struct tag_hinic5_cqm_func_capability *func_cap = &hinic5_cqm_handle->func_capability;
	return func_cap->fake_cfg.fake_vf_lazy_init;
}

/**
 * SMF support to use acs_spu_en to determine whether to send data over the HVA
 * interface or API ring.
 * @ref 'SPU ACCESS' in SM FS
 * @return 1: over HVA, 0 over API ring
 */
static inline u8 hinic5_cqm_get_acs_spu_en(struct tag_hinic5_cqm_handle *hinic5_cqm_handle)
{
	struct hinic5_hwdev *hwdev = hinic5_cqm_handle->ex_handle;

	if (hinic5_cqm_handle->func_capability.gpa_spu_en == FUNC_GPA_SPU_DIS)
		return 0;
	if (hinic5_cqm_handle->func_capability.gpa_spu_en == FUNC_GPA_SPU_EN)
		return 0x1;

	if (!hinic5_in_spu(hwdev))
		return 0;

	/* Load balancing from the SMF to the CPI, depending on the func ID. */
	return hinic5_global_func_id(hwdev) & 0x1;
}

#endif /* HINIC5_CQM_MAIN_H */
