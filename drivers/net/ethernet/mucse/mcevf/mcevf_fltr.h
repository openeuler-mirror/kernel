/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2020-2026 Mucse Corporation. */

#ifndef _MCEVF_FLTR_H_
#define _MCEVF_FLTR_H_

int mcevf_add_uc_filter(struct net_device *netdev, const u8 *addr);
int mcevf_del_uc_filter(struct net_device *netdev, const u8 *addr);
int mcevf_add_mc_filter(struct net_device *netdev, const u8 *addr);
int mcevf_del_mc_filter(struct net_device *netdev, const u8 *addr);

#endif /* _MCEVF_FLTR_H_ */
