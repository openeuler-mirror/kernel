/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_DCB_H_
#define _NSE_DCB_H_

#include "nse_type.h"
#include "nse_common.h"
#include <scsi/iscsi_proto.h>

#define NSE_FW_DCBX_STATUS_NOT_STARTED		0
#define NSE_FW_DCBX_STATUS_IN_PROGRESS		1
#define NSE_FW_DCBX_STATUS_DONE				2
#define NSE_FW_DCBX_STATUS_MULTIPLE_PEERS	3
#define NSE_FW_DCBX_STATUS_DIS				7

enum nse_status nse_get_dcb_cfg(struct nse_port_info *pi);
enum nse_status nse_set_dcb_cfg(struct nse_port_info *pi, bool set_all_or_this_lan);
enum nse_status nse_set_dcb_cfg_lw(struct nse_port_info *pi, u32 cfg_chg_type);

void nse_save_dcbx_cfg_from_aqc(struct nse_hw *hw, struct nse_dcbx_cfg *dst,
				struct nse_aqc_qos_db_cfg *db_cfg,
				bool local_or_remote);

enum nse_status
nse_set_dcb_up_enforcement(struct nse_hw *hw, struct nse_dcbx_cfg *dcbcfg);

enum nse_status
nse_set_dcb_up_enforcement_force_off(struct nse_hw *hw);

#endif /* _NSE_DCB_H_ */

