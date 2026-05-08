/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_mc.h
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_DRV_MC_H__
#define __SXE2_DRV_MC_H__

#include <linux/if_ether.h>
#include "sxe2_drv_rdma_common.h"

#define SXE2_RDMA_DRV_MC_ETH_ALEN (6)
#define SXE2_RDMA_DRV_MC_IP_LEN	  (4)

#pragma pack(4)
struct sxe2_mcast_cmd_info {
	u8 dest_mac_addr[SXE2_RDMA_DRV_MC_ETH_ALEN];
	u8 rsv0[2];
	u16 vlan_id;
	u16 pf_id;
	u32 dest_ip_addr[SXE2_RDMA_DRV_MC_IP_LEN];
	u8 ipv4_valid;
	u8 vlan_valid;
	u8 pf_valid;
	u8 rsv2[1];
	u32 qpn;
	u16 vsi_index;
	u16 vf_id;
};
#pragma pack()

enum sxe2_mcast_type {
	SXE2_MCAST_ATTACH_FIRST_QP = 1,
	SXE2_MCAST_ATTACH_NOT_FIRST_QP =
		2,
	SXE2_MCAST_DETACH_LAST_QP = 3,
	SXE2_MCAST_DETACH_NOT_LAST_QP =
		4,
};

struct sxe2_acttach_mcast_cmd_resp {
	u8 attach_flag;
};

struct sxe2_detach_mcast_cmd_resp {
	u8 detach_flag;
};

static inline void mcast_kfill_mac_v6(u32 *ip_addr, u8 *mac)
{
	u8 *ip			     = (u8 *)ip_addr;
	unsigned char mac6[ETH_ALEN] = {};

	mac6[0] = 0x33;
	mac6[1] = 0x33;
	mac6[2] = ip[3];
	mac6[3] = ip[2];
	mac6[4] = ip[1];
	mac6[5] = ip[0];

	ether_addr_copy(mac, mac6);
}

static inline void mcast_kfill_mac_v4(u32 *ip_addr, u8 *mac)
{
	u8 *ip			     = (u8 *)ip_addr;
	unsigned char mac4[ETH_ALEN] = {};

	mac4[0] = 0x01;
	mac4[1] = 0x00;
	mac4[2] = 0x5E;
	mac4[3] = ip[2] & 0x7F;
	mac4[4] = ip[1];
	mac4[5] = ip[0];

	ether_addr_copy(mac, mac4);
}

int sxe2_kattach_mcast(struct ib_qp *ibqp, union ib_gid *ibgid, u16 lid);

int sxe2_kdetach_mcast(struct ib_qp *ibqp, union ib_gid *ibgid, u16 lid);

#endif
