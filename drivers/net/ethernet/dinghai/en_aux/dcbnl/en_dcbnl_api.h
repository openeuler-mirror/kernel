/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef __ZXDH_EN_DCBNL_API_H__
#define __ZXDH_EN_DCBNL_API_H__
#include <linux/device.h>

struct zxdh_en_priv;

u32 zxdh_dcbnl_init_port_speed(struct zxdh_en_priv *en_priv);
u32 zxdh_dcbnl_init_ets_scheduling_tree(struct zxdh_en_priv *en_priv);
u32 zxdh_dcbnl_printk_ets_tree(struct zxdh_en_priv *en_priv);
u32 zxdh_dcbnl_pfc_init(struct zxdh_en_priv *en_priv);

u32 zxdh_dcbnl_free_flow_resources(struct zxdh_en_priv *en_priv);
u32 zxdh_dcbnl_free_se_resources(struct zxdh_en_priv *en_priv);

u32 zxdh_dcbnl_set_tc_scheduling(struct zxdh_en_priv *en_priv, u8 *tc_type, u8 *tc_tx_bw);
u32 zxdh_dcbnl_set_ets_up_tc_map(struct zxdh_en_priv *en_priv, u8 *prio_tc);
u32 zxdh_dcbnl_set_tc_maxrate(struct zxdh_en_priv *en_priv, u32 *maxrate);
u32 zxdh_dcbnl_set_ets_trust(struct zxdh_en_priv *en_priv, u32 trust);
u32 zxdh_dcbnl_set_dscp2prio(struct zxdh_en_priv *en_priv, u16 dscp, u8 prio);

u32 zxdh_dcbnl_set_tm_gate(struct zxdh_en_priv *en_priv, u32 mode);
u32 zxdh_dcbnl_set_flow_td_th(struct zxdh_en_priv *en_priv, u32 *tc_td_th);
u32 zxdh_dcbnl_set_single_td_th(struct zxdh_en_priv *en_priv, u32 tc, u32 tc_td_th);
u32 zxdh_dcbnl_get_flow_td_th(struct zxdh_en_priv *en_priv, u32 *tc_td_th);
u32 zxdh_dcbnl_clear_flow_td_th(struct zxdh_en_priv *en_priv);
u32 zxdh_dcbnl_enable_debug(struct zxdh_en_priv *en_priv);
u32 zxdh_dcbnl_disable_debug(struct zxdh_en_priv *en_priv);

#endif
