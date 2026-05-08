/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_main.h
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_DRV_MAIN_H__
#define __SXE2_DRV_MAIN_H__

#include "sxe2_compat.h"
#ifdef NOT_SUPPORT_AUXILIARY_BUS
#include "auxiliary_bus.h"
#else
#include <linux/auxiliary_bus.h>
#endif
#include "sxe2_drv_rdma_common.h"

extern u32 g_sxe2_rdma_dmesg_level;
extern struct list_head sxe2_handlers;
extern spinlock_t sxe2_handler_lock;
#define SXE2_RDMA_MCQ_HW_PAGE_SIZE	   8192
#define SXE2_SQ_RSVD		   8
#define SXE2_CPU_ID_GET_VENDOR_ID  (0x0)
#define SXE2_VENDOR_ID_SIZE	   (0x13)
#define SXE2_MAX_PKEY_CNT	   (32)
#define SXE2_DEFAULT_PKEY_VAL	   (0xFFFF)
#define SXE2_PEKY_REG_INVALID_VAL  (0x0)
#define SXE2_BAR_REG_AUTO_RESP_VAL (0xFFFFFFFF)
#define SXE2_BAR_REG_INVALID_VAL   (0xDEADBEEF)
#define SXE2_MAX_PORT_CNT	   (4)
#define SXE2_LIMITS_SEL_DEFAULT 3
#define SXE2_LIMITS_SEL_MAX 7

#define SXE2_FRAGCNT_LIMIT_DEFAULT 6
#define SXE2_FRAGCNT_LIMIT_MIN 2
#define SXE2_FRAGCNT_LIMIT_MAX 13

#define SXE2_RCMS_MODE_2M 1
#define SXE2_RCMS_MODE_4K 2

#define SXE2_PKEY_TBLE_BAR_ADDR(base_addr, idx) (base_addr + idx)

#define SXE2_MAX_QP_WRS(max_quanta_per_wr)                                     \
	((SXE2_QP_SW_MAX_WQ_QUANTA - SXE2_SQ_RSVD) / (max_quanta_per_wr))
#define SXE2_CC_DCQCN_T_DEFAULT 120
#define SXE2_CC_DCQCN_T_MAX	0xFFFF
#define SXE2_CC_DCQCN_T_MIN	1

#define SXE2_CC_DCQCN_B_DEFAULT 131072
#define SXE2_CC_DCQCN_B_MAX	0xFFFFFF
#define SXE2_CC_DCQCN_B_MIN	0

#define SXE2_CC_DCQCN_F_DEFAULT 5
#define SXE2_CC_DCQCN_F_MAX	15
#define SXE2_CC_DCQCN_F_MIN	0

#define SXE2_CC_DCQCN_TIMELY_RAI_DEFAULT 18
#define SXE2_CC_DCQCN_TIMELY_RAI_MAX	 100
#define SXE2_CC_DCQCN_TIMELY_RAI_MIN	 2

#define SXE2_CC_DCQCN_RHAI_DEFAULT 34
#define SXE2_CC_DCQCN_RHAI_MAX	   100
#define SXE2_CC_DCQCN_RHAI_MIN	   2

#define SXE2_CC_DCQCN_RREDUCE_MPERIOD_DEFAULT 60
#define SXE2_CC_DCQCN_RREDUCE_MPERIOD_MAX     0xFFFF
#define SXE2_CC_DCQCN_RREDUCE_MPERIOD_MIN     1

#define SXE2_CC_DCQCN_MIN_DEC_FACTOR_DEFAULT 2
#define SXE2_CC_DCQCN_MIN_DEC_FACTOR_MAX     100
#define SXE2_CC_DCQCN_MIN_DEC_FACTOR_MIN     2

#define SXE2_CC_DCQCN_MIN_RATE_DEFAULT 2
#define SXE2_CC_DCQCN_MIN_RATE_MAX     100
#define SXE2_CC_DCQCN_MIN_RATE_MIN     2
#define SXE2_CC_DCQCN_K_VAL			 1280
#define SXE2_CC_DCQCN_BC_VAL			 0
#define SXE2_CC_DCQCN_TC_VAL			 0
#define SXE2_CC_DCQCN_G_VAL			 62
#define SXE2_CC_DCQCN_RT_VAL			 0
#define SXE2_CC_DCQCN_RC_VAL			 49
#define SXE2_CC_DCQCN_ALPHA_VAL			 0
#define SXE2_CC_DCQCN_RREDUCE_NEXT_NODE_INFO_VAL 0
#define SXE2_CC_DCQCN_DECREASE_RATE_VALID_VAL	 1
#define SXE2_CC_DCQCN_T_NEXT_NODE_INFO_VAL	 0
#define SXE2_CC_DCQCN_BYTE_COUNTER_VAL		 0
#define SXE2_CC_TIMELY_MIN_RTT_DEFAULT 500
#define SXE2_CC_TIMELY_MIN_RTT_MAX     0xFFFF
#define SXE2_CC_TIMELY_MIN_RTT_MIN     1

#define SXE2_CC_TIMELY_TLOW_DEFAULT 300
#define SXE2_CC_TIMELY_TLOW_MAX	    0xFFFF
#define SXE2_CC_TIMELY_TLOW_MIN	    1

#define SXE2_CC_TIMELY_THIGH_DEFAULT 1000
#define SXE2_CC_TIMELY_THIGH_MAX     0xFFFF
#define SXE2_CC_TIMELY_THIGH_MIN     1
#define SXE2_CC_TIMELY_PRE_RTT_VAL  0
#define SXE2_CC_TIMELY_BETA_VAL	    620
#define SXE2_CC_TIMELY_ALPHA_VAL    500
#define SXE2_CC_TIMELY_RTT_DIFF_VAL 0
#define RDMA_DRIVER_SXE2     20

struct sxe2_rdma_device_init_info {
	u64 fpm_query_buf_pa;
	u64 fpm_commit_buf_pa;
	__le32 *fpm_query_buf;
	__le32 *fpm_commit_buf;
	struct sxe2_rdma_hw *hw;
	void __iomem *bar0;
	u16 max_vfs;
	u16 rcms_fn_id;
};

struct sxe2_pf_func_table_init_info {
	u32 pf_id;
};

#define STAGE_CREATE(_stage, _init, _cleanup)                                  \
	.stage[_stage] = { .init = _init, .cleanup = _cleanup }

enum sxe2_rdma_stages {
	SXE2_RDMA_STAGE_SETUP_INITINFO,
	SXE2_RDMA_STAGE_DEBUG,
	SXE2_RDMA_STAGE_CREATE_MQ,
	SXE2_RDMA_STAGE_GET_FEATURES,
	SXE2_RDMA_STAGE_RCMS_SETUP,
	SXE2_RDMA_STAGE_PBLE,
	SXE2_RDMA_STAGE_HW_RSRC,
	SXE2_RDMA_STAGE_DB_INIT,
	SXE2_RDMA_STAGE_CREATE_MCQ,
	SXE2_RDMA_STAGE_CREATE_MCEQ,
	SXE2_RDMA_STAGE_MQ_HDL,
	SXE2_RDMA_STAGE_SET_ATTR,
	SXE2_RDMA_STAGE_VSI,
	SXE2_RDMA_STAGE_VSI_STATS,
	SXE2_RDMA_STAGE_CREATE_CEQS,
	SXE2_RDMA_STAGE_CREATE_AEQ,
	SXE2_RDMA_STAGE_RCRC_WQ,
	SXE2_RDMA_STAGE_MAX,
};

union sxe2_rdma_cfg_pkey_bar {
	struct cfg_pkey_bar {
		u32 pkey : 16;
		u32 pkey_port : 2;
		u32 pkey_vld : 1;
		u32 rsv : 13;
	} pkey_bar;
	u32 bar_val;
};

struct sxe2_rdma_stage {
	int (*init)(struct sxe2_rdma_device *dev);
	void (*cleanup)(struct sxe2_rdma_device *dev);
};

struct sxe2_rdma_profile {
	struct sxe2_rdma_stage stage[SXE2_RDMA_STAGE_MAX];
};

enum sxe2_rdma_status {
	SXE2_RDMA_PROBE,
	SXE2_RDMA_REMOVE,
	SXE2_RDMA_MAX,
};
struct sxe2_rdma_notify_status_info {
	u32 rdma_status;
};

void sxe2_rdma_set_qos_info(struct sxe2_rdma_ctx_vsi *vsi,
			    struct sxe2_rdma_l2params *l2p);

bool sxe2_rdma_get_cpu_vendor(struct sxe2_rdma_device *rdma_dev);

#ifdef RDMA_AUX_GET_SET_DRV_DATA
static inline void *auxiliary_get_drvdata(struct auxiliary_device *auxdev)
{
	return dev_get_drvdata(&auxdev->dev);
}

static inline void auxiliary_set_drvdata(struct auxiliary_device *auxdev,
					 void *data)
{
	dev_set_drvdata(&auxdev->dev, data);
}
#endif

void sxe2_rdma_update_qos_info(struct sxe2_rdma_ctx_vsi *vsi,
			       struct sxe2_rdma_l2params *l2p);

void sxe2_rdma_qos_move_qset(struct sxe2_rdma_ctx_vsi *vsi,
			     struct sxe2_rdma_l2params *l2params);

void sxe2_rdma_free_one_vf(struct sxe2_rdma_vchnl_dev *vc_dev);

#ifdef SXE2_SUPPORT_CONFIGFS
int sxe2_configfs_init(void);
void sxe2_configfs_exit(void);
#endif
void sxe2_rdma_cc_dcqcn_set_params(struct sxe2_rdma_pci_f *rdma_func);

void sxe2_rdma_cc_timely_set_params(struct sxe2_rdma_pci_f *rdma_func);

void sxe2_rdma_init_cc_params(struct sxe2_rdma_pci_f *rdma_func);

void
sxe2_rdma_set_func_user_cfg_params(struct sxe2_rdma_pci_f *rdma_func);

int sxe2_rdma_save_msix_info(struct sxe2_rdma_pci_f *rdma_func);

int sxe2_rdma_init_ctx_dev(struct sxe2_rdma_ctx_dev *dev,
				  struct sxe2_rdma_device_init_info *info);

int sxe2_rdma_initialize_dev(struct sxe2_rdma_pci_f *rdma_func);

int sxe2_rdma_setup_init_state(struct sxe2_rdma_device *rdma_dev);

void sxe2_kunregister_notifiers(struct sxe2_rdma_device *rdma_dev);
void sxe2_rdma_disassociate_ucontext(struct ib_ucontext *ibctx);

#endif
