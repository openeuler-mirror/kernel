/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef __ZXDH_PF_MSG_FUNC_H__
#define __ZXDH_PF_MSG_FUNC_H__
#include <linux/types.h>
#include "../en_np/flow/api/include/dpp_tbl_fd_cfg.h"
#include "../en_np/driver/include/dpp_drv_sdt.h"
#define RD_CLR_MODE_UNCLR 0
#define RD_CLR_MODE_CLR 1

enum vf_call_np_num {
	PTP_PORT_VFID_SET,
	PTP_TC_ENABLE_SET,

	MAX_VF_CALL_NP_NUM,
};

s32 dh_pf_msg_recv_func_register(void);
void dh_pf_msg_recv_func_unregister(void);
void zxdh_vf_item_mac_add(struct zxdh_vf_item *vf_item, u8 *mac_addr, u8 dhtool_mac_set_flag);
void zxdh_vf_item_mac_del(struct zxdh_vf_item *vf_item, u8 *mac_addr);
void zxdh_flow_table_add(struct ethtool_rx_flow_spec *fs, struct zxdh_fd_cfg_t *p_fd_cfg,
			 struct dpp_pf_info_t *pf_info);

#endif /* __ZXDH_PF_MSG_FUNC_H__ */
