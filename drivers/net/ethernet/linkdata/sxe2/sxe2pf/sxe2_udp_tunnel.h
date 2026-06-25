/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_udp_tunnel.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */
#ifndef __SXE2_UDP_TUNNEL_H__
#define __SXE2_UDP_TUNNEL_H__

#include <net/geneve.h>
#include <net/gre.h>
#include <net/udp_tunnel.h>
#include <net/vxlan.h>
#include "sxe2_ioctl_chnl.h"
#include "sxe2_com_cdev.h"

struct sxe2_adapter;
struct sxe2_vsi;

enum sxe2_udp_tunnel_status {
	SXE2_UDP_TUNNEL_DISABLE = 0x0,
	SXE2_UDP_TUNNEL_ENABLE,
};

struct sxe2_udp_tunnel_cfg {
	u8 protocol;
	u8 dev_status;
	u16 dev_port;
	u16 dev_ref_cnt;
	u8 flags;

	u16 fw_port;
	u8 fw_status;
	u8 fw_dst_en;
	u8 fw_src_en;
	u8 fw_used;
};

#ifdef HAVE_UDP_TUNNEL_NIC_INFO
s32 sxe2_udp_tunnel_set_port(struct net_device *netdev, u32 table_idx, u32 idx,
			     struct udp_tunnel_info *ti);

s32 sxe2_udp_tunnel_unset_port(struct net_device *netdev, u32 table_idx, u32 idx,
			       struct udp_tunnel_info *ti);
#endif

s32 sxe2_com_udptunnel_handler(struct sxe2_adapter *adapter, struct sxe2_obj *obj,
			       struct sxe2_drv_cmd_params *cmd_buf);

void sxe2_udptunnel_vsi_init(struct sxe2_vsi *vsi);

void sxe2_udptunnel_vsi_deinit(struct sxe2_vsi *vsi);

#endif
