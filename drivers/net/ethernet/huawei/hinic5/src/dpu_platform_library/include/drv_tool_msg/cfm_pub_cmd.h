/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : cfm_pub_cmd.h
 * Version       : Initial Draft
 * Created       : 2025/11/05
 * Last Modified : 2026/09/16
 * Description   : Shared header between tool and MPU, NPU
 */

#ifndef CFM_PUB_CMD_H
#define CFM_PUB_CMD_H

#include "mpu_cmd_base_defs.h"
#include "qos_base_mpu_defs.h"

typedef enum tag_cfm_qos_vport_shaper_set_type {
	CFM_QOS_VPORT_SHAPER_SET_BW_INGRESS = 0,
	CFM_QOS_VPORT_SHAPER_SET_PPS_INGRESS
} cfm_qos_vport_shaper_set_type_e;

/* DFT_QOS message send */
typedef struct tag_qos_vport_req {
	struct mgmt_msg_head head; /* DFT message response header */
	cfm_qos_policing_cmd_s shaper;
} qos_vport_req_s;

/* DFT_QOS message return */
typedef struct tag_qos_vport_rsp {
	struct mgmt_msg_head head; /* DFT message response header */
	cfm_qos_policing_cmd_s bps;
	cfm_qos_policing_cmd_s pps;
} qos_vport_rsp_s;

#endif /* CFM_PUB_CMD_H */