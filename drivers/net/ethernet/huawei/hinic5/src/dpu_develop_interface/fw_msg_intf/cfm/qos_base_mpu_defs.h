/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : qos_base_mpu_defs.h
 * Version       : Initial Draft
 * Created       : 2025/9/1
 * Last Modified : 2026/09/16
 * Description   : qos_base_mpu_defs.h header file
 */

#ifndef QOS_BASE_MPU_DEFS_H
#define QOS_BASE_MPU_DEFS_H

/**< max func/VM number */
#ifdef RESOURCE_MODE_CLIP
#define CFM_FUNC_MAX_NUM  64 /**< 8 PFs (followed by 24 reserved for PF expansion) + 32 VFs */
#define CFM_VM_MAX_NUM    96
#else /**< 1823V200/1825V100 both use the following specifications */
#define CFM_FUNC_MAX_NUM  4096
#define CFM_VM_MAX_NUM    1024
#endif

/**< 1825 chip generation, CAR maximum bucket depth does not follow xQM, so defined separately */
#define CFM_QOS_CAR_XBS_MAX_VALUE   (320 * 8 * 1000) /* *< unit:kbps, 2560Mbps */

/**< macro for qos */
#ifndef HI1825V100
#define CFM_QOS_CIR_MIN_VALUE       1000
#define CFM_QOS_CIR_MAX_VALUE       (400 * 1000 * 1000) /**< unit:kbps, 400Gbps */
#define CFM_QOS_PIR_MIN_VALUE       1000
#define CFM_QOS_PIR_MAX_VALUE       (400 * 1000 * 1000) /**< unit:kbps, 400Gbps */

#define CFM_QOS_CBS_MIN_VALUE       1000
#define CFM_QOS_CBS_MAX_VALUE       (320 * 8 * 1000)    /**< unit:kbps, 2560Mbps */
#define CFM_QOS_PBS_MIN_VALUE       1000
#define CFM_QOS_PBS_MAX_VALUE       (320 * 8 * 1000)    /**< unit:kbps, 2560Mbps */

#define CFM_QOS_P_CIR_MIN_VALUE     1000
#define CFM_QOS_P_CIR_MAX_VALUE     (128 * 1000 * 1000) /**< unit:pps, 128Mpps */
#define CFM_QOS_P_PIR_MIN_VALUE     1000
#define CFM_QOS_P_PIR_MAX_VALUE     (128 * 1000 * 1000) /**< unit:pps, 128Mpps */

#define CFM_QOS_P_CBS_MIN_VALUE     1000
#define CFM_QOS_P_CBS_MAX_VALUE     (1000 * 1000)       /**< unit:pps, 1Mpps */
#define CFM_QOS_P_PBS_MIN_VALUE     1000
#define CFM_QOS_P_PBS_MAX_VALUE     (1000 * 1000)       /**< unit:pps, 1Mpps */
#else
#define CFM_QOS_CIR_MIN_VALUE       1000
#define CFM_QOS_CIR_MAX_VALUE       (800 * 1000 * 1000) /**< unit:kbps, 800Gbps */
#define CFM_QOS_PIR_MIN_VALUE       1000
#define CFM_QOS_PIR_MAX_VALUE       (800 * 1000 * 1000) /**< unit:kbps, 800Gbps */

#define CFM_QOS_CBS_MIN_VALUE       1000
#define CFM_QOS_CBS_MAX_VALUE       (4 * 1000 * 1000)    /**< unit:kbps, 4Gbps */
#define CFM_QOS_PBS_MIN_VALUE       1000
#define CFM_QOS_PBS_MAX_VALUE       (4 * 1000 * 1000)    /**< unit:kbps, 4Gbps */

#define CFM_QOS_P_CIR_MIN_VALUE     1000
#define CFM_QOS_P_CIR_MAX_VALUE     (300 * 1000 * 1000) /**< unit:pps, 300Mpps */
#define CFM_QOS_P_PIR_MIN_VALUE     1000
#define CFM_QOS_P_PIR_MAX_VALUE     (300 * 1000 * 1000) /**< unit:pps, 300Mpps */

#define CFM_QOS_P_CBS_MIN_VALUE     1000
#define CFM_QOS_P_CBS_MAX_VALUE     (1000 * 1000)       /**< unit:pps, 1Mpps */
#define CFM_QOS_P_PBS_MIN_VALUE     1000
#define CFM_QOS_P_PBS_MAX_VALUE     (1000 * 1000)       /**< unit:pps, 1Mpps */
#endif

#define CFM_QOS_GET_VM_LIMIT_EN_BW(cir, pir) ((((cir) == CFM_QOS_CIR_MAX_VALUE) && \
	((pir) == CFM_QOS_PIR_MAX_VALUE)) ? CFM_QOS_DISABLE : CFM_QOS_ENABLE)

#define CFM_QOS_GET_VM_LIMIT_EN_PPS(cir, pir) ((((cir) == CFM_QOS_P_CIR_MAX_VALUE) && \
	((pir) == CFM_QOS_P_PIR_MAX_VALUE)) ? CFM_QOS_DISABLE : CFM_QOS_ENABLE)

#define CFM_QOS_PARAM_ILGL_BPS(cir, xir, cbs, xbs) \
	(((cir) < CFM_QOS_CIR_MIN_VALUE) || ((cir) > CFM_QOS_CIR_MAX_VALUE) || \
	((xir) < CFM_QOS_PIR_MIN_VALUE) || ((xir) > CFM_QOS_PIR_MAX_VALUE) || \
	((cbs) < CFM_QOS_CBS_MIN_VALUE) || ((cbs) > CFM_QOS_CBS_MAX_VALUE) || \
	((xbs) < CFM_QOS_PBS_MIN_VALUE) || ((xbs) > CFM_QOS_PBS_MAX_VALUE))

#define CFM_QOS_PARAM_ILGL_PPS(cir, xir, cbs, xbs) \
	(((cir) < CFM_QOS_P_CIR_MIN_VALUE) || ((cir) > CFM_QOS_P_CIR_MAX_VALUE) || \
	((xir) < CFM_QOS_P_PIR_MIN_VALUE) || ((xir) > CFM_QOS_P_PIR_MAX_VALUE) || \
	((cbs) < CFM_QOS_P_CBS_MIN_VALUE) || ((cbs) > CFM_QOS_P_CBS_MAX_VALUE) || \
	((xbs) < CFM_QOS_P_PBS_MIN_VALUE) || ((xbs) > CFM_QOS_P_PBS_MAX_VALUE))

#define CFM_QOS_PARAM_ILGL_FUNC_ID(func_id) ((func_id) >= CFM_FUNC_MAX_NUM)

#define CFM_QOS_PARAM_ILGL_VM_ID(vm_id) ((vm_id) >= CFM_VM_MAX_NUM)

typedef enum tag_cfm_qos_enable {
	CFM_QOS_DISABLE = 0,
	CFM_QOS_ENABLE
} cfm_qos_enable_e;

typedef enum tag_cfm_qos_apply_mode {
	CFM_QOS_APPLY_MODE_TX_BW = 0,
	CFM_QOS_APPLY_MODE_TX_PPS,
	CFM_QOS_APPLY_MODE_TX_BW_WITH_MQM_PRF, /**< deprecated */
	CFM_QOS_APPLY_MODE_RX_BW,
	CFM_QOS_APPLY_MODE_RX_PPS
} cfm_qos_apply_mode_e;

typedef struct tag_cfm_qos_policing_cmd {
	u32 index;      /**< index reuse, vm_id/vnicgpp_id/func_id/vnic_id */
	u32 apply_mode; /**< 0:TX_BW; 1:TX_PPS; 3:RX_BW; 4:RX_PPS */
	u32 profile_id; /**< deprecated */
	u32 cir;
	u32 cbs;
	u32 pir;
	u32 pbs;
} cfm_qos_policing_cmd_s;

#endif /* QOS_BASE_MPU_DEFS_H */
