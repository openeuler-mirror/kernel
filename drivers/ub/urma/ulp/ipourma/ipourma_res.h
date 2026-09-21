/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.
 *
 * Description: Functions definition of ipourma_res
 */

#ifndef _IPOURMA_RES_H
#define _IPOURMA_RES_H

#include "ipourma_types.h"

extern int ipourma_ctp_sl;
extern int ipourma_utp_sl;

void ipourma_uninit_rings_by_jetty(struct ipourma_dev_priv *priv, u32 jetty_idx);
void ipourma_uninit_rx_bufs(struct ipourma_dev_priv *priv, u32 jetty_idx);
int ipourma_restart_rings(struct ipourma_dev_priv *priv);
int ipourma_init_rings(struct net_device *dev);
void ipourma_uninit_rings(struct net_device *dev);
int ipourma_init_tjetty_hmap(struct net_device *dev);
void ipourma_uninit_tjetty_hmap(struct net_device *dev);
void ipourma_uninit_urma_resources(struct net_device *dev);
void ipourma_reset_rings(struct ipourma_dev_priv *priv);
int ipourma_init_rings_by_jetty(struct ipourma_dev_priv *priv, u32 jetty_idx);
void ipourma_uninit_urma_resources_by_jetty(struct ipourma_dev_priv *priv, u32 jetty_idx);
int ipourma_init_urma_resources_by_jetty(struct ipourma_dev_priv *priv, u32 jetty_idx);
int ipourma_init_urma_resources(struct net_device *dev);

#endif
