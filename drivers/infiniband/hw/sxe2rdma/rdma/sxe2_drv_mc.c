// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_mc.c
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/err.h>
#include <linux/sizes.h>
#include <linux/rcupdate.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/etherdevice.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_addr.h>
#include <net/addrconf.h>
#include "sxe2_drv_aux.h"
#include "sxe2_drv_rdma_log.h"
#include "sxe2_drv_mc.h"

#define SXE2_RDMA_MC_VALID_TRUE	 (1)
#define SXE2_RDMA_MC_VALID_FALSE (0)

static void mcast_kget_vlan_mac_ipv6(u32 *addr, u16 *vlan_id, u8 *mac)
{
	struct net_device *ip_dev = NULL;
	struct in6_addr laddr6;

	sxe2_copy_ip_ntohl(laddr6.in6_u.u6_addr32, addr);
	if (vlan_id)
		*vlan_id = 0xFFFF;

	if (mac)
		eth_zero_addr(mac);

	rcu_read_lock();
	for_each_netdev_rcu(&init_net, ip_dev) {
		if (ipv6_chk_addr(&init_net, &laddr6, ip_dev, 1)) {
			if (vlan_id)
				*vlan_id = rdma_vlan_dev_vlan_id(ip_dev);
			if (mac)
				ether_addr_copy(mac, ip_dev->dev_addr);
			break;
		}
	}
	rcu_read_unlock();
}

static u16 mcast_kget_vlan_ipv4(u32 *addr)
{
	struct net_device *netdev;
	u16 vlan_id = 0xFFFF;

	netdev = ip_dev_find(&init_net, htonl(addr[0]));
	if (netdev) {
		vlan_id = rdma_vlan_dev_vlan_id(netdev);
		dev_put(netdev);
	}

	return vlan_id;
}

static int mcast_kdetach_qp(struct sxe2_rdma_device *rdma_dev,
			    struct sxe2_mcast_cmd_info *detach_info)
{
	struct sxe2_detach_mcast_cmd_resp recv_msg = { 0 };
	struct aux_core_dev_info *cdev_info	   = rdma_dev->rdma_func->cdev;
	int ret					   = 0;
	int i					   = 0;

	if (rdma_dev->rdma_func->reset) {
		DRV_RDMA_LOG_DEV_INFO("reset is set, mcast detach qp skip\n");
		goto end;
	}

	detach_info->vlan_id = cpu_to_le16(detach_info->vlan_id);
	for (i = 0; i < SXE2_RDMA_DRV_MC_IP_LEN; i++) {
		detach_info->dest_ip_addr[i] =
			cpu_to_le32(detach_info->dest_ip_addr[i]);
	}
	detach_info->qpn       = cpu_to_le32(detach_info->qpn);
	detach_info->vsi_index = cpu_to_le16(detach_info->vsi_index);
	detach_info->pf_id     = cpu_to_le16(detach_info->pf_id);
	detach_info->vf_id     = cpu_to_le16(detach_info->vf_id);

	ret = sxe2_rdma_adminq_send(cdev_info, SXE2_CMD_RDMA_QP_DETACH_MC,
					    (u8 *)detach_info,
					    (u16)sizeof(*detach_info),
					    (u8 *)(&recv_msg),
					    (u16)sizeof(recv_msg));
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR("Send msg:detach mcast failed, ret %d\n",
				     ret);
		goto end;
	}

	if (recv_msg.detach_flag == SXE2_MCAST_DETACH_LAST_QP) {
		ret = cdev_info->ops->rdma_drv_config(
			cdev_info, RDMA_MAC_RULE_DELETE,
			detach_info->dest_mac_addr);
		if (ret) {
			DRV_RDMA_LOG_DEV_ERR(
				"Send msg:delete mac rule failed, ret %d\n",
				ret);
		}
	} else if (recv_msg.detach_flag != SXE2_MCAST_DETACH_NOT_LAST_QP) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR(
			"Send msg:detach mcast recv_msg %d, ret %d\n",
			recv_msg.detach_flag, ret);
	}

	if (detach_info->ipv4_valid) {
		DRV_RDMA_LOG_DEV_INFO(
			"DETACH MCAST:MAC %pM, VLAN_ID %#x, IP %pI4, IPv4 valid %u,\n"
			"\tVLAN valid %u, QPN %#x, VSI Index %#x, recv_msg %d\n"
			"\tpf_id %#x, pf_valid %u, vf_id %#x\n",
			detach_info->dest_mac_addr, detach_info->vlan_id,
			detach_info->dest_ip_addr, detach_info->ipv4_valid,
			detach_info->vlan_valid, detach_info->qpn,
			detach_info->vsi_index, recv_msg.detach_flag,
			detach_info->pf_id, detach_info->pf_valid,
			detach_info->vf_id);
	} else {
		DRV_RDMA_LOG_DEV_INFO(
			"DETACH MCAST:MAC %pM, VLAN_ID %#x, IP %pI6, IPv4 valid %u,\n"
			"\tVLAN valid %u, QPN %#x, VSI Index %#x, recv_msg %d\n"
			"\tpf_id %#x, pf_valid %u, vf_id %#x\n",
			detach_info->dest_mac_addr, detach_info->vlan_id,
			detach_info->dest_ip_addr, detach_info->ipv4_valid,
			detach_info->vlan_valid, detach_info->qpn,
			detach_info->vsi_index, recv_msg.detach_flag,
			detach_info->pf_id, detach_info->pf_valid,
			detach_info->vf_id);
	}

end:
	return ret;
}

static int mcast_kattach_qp(struct sxe2_rdma_device *rdma_dev,
			    struct sxe2_mcast_cmd_info *attach_info)
{
	struct sxe2_acttach_mcast_cmd_resp recv_msg = { 0 };
	struct aux_core_dev_info *cdev_info	    = rdma_dev->rdma_func->cdev;
	int ret					    = 0;
	int detach_ret				    = 0;
	int i					    = 0;

	if (rdma_dev->rdma_func->reset) {
		DRV_RDMA_LOG_DEV_INFO("reset is set, mcast attach qp skip\n");
		ret = -EBUSY;
		goto end;
	}

	attach_info->vlan_id = cpu_to_le16(attach_info->vlan_id);
	for (i = 0; i < SXE2_RDMA_DRV_MC_IP_LEN; i++) {
		attach_info->dest_ip_addr[i] =
			cpu_to_le32(attach_info->dest_ip_addr[i]);
	}
	attach_info->qpn       = cpu_to_le32(attach_info->qpn);
	attach_info->vsi_index = cpu_to_le16(attach_info->vsi_index);
	attach_info->pf_id     = cpu_to_le16(attach_info->pf_id);
	attach_info->vf_id     = cpu_to_le16(attach_info->vf_id);

	ret = sxe2_rdma_adminq_send(cdev_info, SXE2_CMD_RDMA_QP_ATTACH_MC,
					    (u8 *)attach_info,
					    (u16)sizeof(*attach_info),
					    (u8 *)(&recv_msg),
					    (u16)sizeof(recv_msg));
	if (ret) {
		DRV_RDMA_LOG_DEV_ERR("Send msg:attach mcast failed, ret %d\n",
				     ret);
		goto end;
	}

	if (recv_msg.attach_flag == SXE2_MCAST_ATTACH_FIRST_QP) {
		ret = cdev_info->ops->rdma_drv_config(
			cdev_info, RDMA_MAC_RULE_ADD,
			attach_info->dest_mac_addr);
		if (ret) {
			DRV_RDMA_LOG_DEV_ERR(
				"Send msg:add mac rule failed, ret %d\n", ret);
			goto detach_qp;
		}
	} else if (recv_msg.attach_flag != SXE2_MCAST_ATTACH_NOT_FIRST_QP) {
		ret = -EINVAL;
		DRV_RDMA_LOG_DEV_ERR(
			"Send msg:attach mcast recv_msg %d, ret %d\n",
			recv_msg.attach_flag, ret);
		goto detach_qp;
	}

	if (attach_info->ipv4_valid) {
		DRV_RDMA_LOG_DEV_INFO(
			"ATTACH MCAST:MAC %pM, VLAN_ID %#x, IP %pI4, IPv4 valid %d,\n"
			"\tVLAN valid %d, QPN %#x, VSI Index %#x, recv_msg %d\n"
			"\tpf_id %#x, pf_valid %u, vf_id %#x\n",
			attach_info->dest_mac_addr, attach_info->vlan_id,
			attach_info->dest_ip_addr, attach_info->ipv4_valid,
			attach_info->vlan_valid, attach_info->qpn,
			attach_info->vsi_index, recv_msg.attach_flag,
			attach_info->pf_id, attach_info->pf_valid,
			attach_info->vf_id);
	} else {
		DRV_RDMA_LOG_DEV_INFO(
			"ATTACH MCAST:MAC %pM, VLAN_ID %#x, IP %pI6, IPv4 valid %d,\n"
			"\tVLAN valid %d, QPN %#x, VSI Index %#x, recv_msg %d\n"
			"\tpf_id %#x, pf_valid %u, vf_id %#x\n",
			attach_info->dest_mac_addr, attach_info->vlan_id,
			attach_info->dest_ip_addr, attach_info->ipv4_valid,
			attach_info->vlan_valid, attach_info->qpn,
			attach_info->vsi_index, recv_msg.attach_flag,
			attach_info->pf_id, attach_info->pf_valid,
			attach_info->vf_id);
	}
	goto end;

detach_qp:
	detach_ret = mcast_kdetach_qp(rdma_dev, attach_info);
	if (detach_ret) {
		DRV_RDMA_LOG_DEV_ERR("Detach mcast failed, ret %d\n",
				     detach_ret);
	}
end:
	return ret;
}

int sxe2_kattach_mcast(struct ib_qp *ibqp, union ib_gid *ibgid, u16 lid)
{
	struct sxe2_rdma_qp *qp		       = to_qp(ibqp);
	struct sxe2_rdma_device *rdma_dev      = qp->dev;
	struct sxe2_rdma_ctx_dev *dev	       = &rdma_dev->rdma_func->ctx_dev;
	struct sxe2_mcast_cmd_info attach_info = {};
	union sxe2_sockaddr sgid_addr;
	int ret = 0;

	rdma_gid2ip((struct sockaddr *)&sgid_addr, ibgid);

	if (!ipv6_addr_v4mapped((struct in6_addr *)ibgid)) {
		sxe2_copy_ip_ntohl(
			attach_info.dest_ip_addr,
			sgid_addr.saddr_in6.sin6_addr.in6_u.u6_addr32);
		mcast_kget_vlan_mac_ipv6(attach_info.dest_ip_addr,
					 &attach_info.vlan_id, NULL);
		attach_info.ipv4_valid = SXE2_RDMA_MC_VALID_FALSE;
		mcast_kfill_mac_v6(&attach_info.dest_ip_addr[3],
				   attach_info.dest_mac_addr);
	} else {
		attach_info.dest_ip_addr[0] =
			ntohl(sgid_addr.saddr_in.sin_addr.s_addr);
		attach_info.ipv4_valid = SXE2_RDMA_MC_VALID_TRUE;
		attach_info.vlan_id =
			mcast_kget_vlan_ipv4(attach_info.dest_ip_addr);
		mcast_kfill_mac_v4(attach_info.dest_ip_addr,
				   attach_info.dest_mac_addr);
	}

	if (attach_info.vlan_id < VLAN_N_VID)
		attach_info.vlan_valid = SXE2_RDMA_MC_VALID_TRUE;

	attach_info.qpn	      = qp->ibqp.qp_num;
	attach_info.vsi_index = rdma_dev->vsi.vsi_idx;
	attach_info.pf_id     = (u16)rdma_dev->rdma_func->pf_id;
	attach_info.pf_valid  = (u8)dev->privileged;
	attach_info.vf_id     = dev->rcms_info->pmf_index;

	DRV_RDMA_LOG_DEV_DEBUG(
		"ATTACH INFO:MAC %pM, VLAN_ID %#x, IP %pI4, IPv4 valid %u,\n"
		"\tVLAN valid %u, QPN %#x, VSI Index %#x\n"
		"\tpf_id %#x, pf_valid %u, vf_id %#x\n",
		attach_info.dest_mac_addr, attach_info.vlan_id,
		attach_info.dest_ip_addr, attach_info.ipv4_valid,
		attach_info.vlan_valid, attach_info.qpn, attach_info.vsi_index,
		attach_info.pf_id, attach_info.pf_valid, attach_info.vf_id);

	ret = mcast_kattach_qp(rdma_dev, &attach_info);

	return ret;
}

int sxe2_kdetach_mcast(struct ib_qp *ibqp, union ib_gid *ibgid, u16 lid)
{
	struct sxe2_rdma_qp *qp		       = to_qp(ibqp);
	struct sxe2_rdma_device *rdma_dev      = qp->dev;
	struct sxe2_rdma_ctx_dev *dev	       = &rdma_dev->rdma_func->ctx_dev;
	struct sxe2_mcast_cmd_info detach_info = {};
	union sxe2_sockaddr sgid_addr;
	int ret = 0;

	rdma_gid2ip((struct sockaddr *)&sgid_addr, ibgid);
	if (!ipv6_addr_v4mapped((struct in6_addr *)ibgid)) {
		sxe2_copy_ip_ntohl(
			detach_info.dest_ip_addr,
			sgid_addr.saddr_in6.sin6_addr.in6_u.u6_addr32);
		mcast_kget_vlan_mac_ipv6(detach_info.dest_ip_addr,
					 &detach_info.vlan_id, NULL);
		detach_info.ipv4_valid = SXE2_RDMA_MC_VALID_FALSE;
		mcast_kfill_mac_v6(&detach_info.dest_ip_addr[3],
				   detach_info.dest_mac_addr);
	} else {
		detach_info.dest_ip_addr[0] =
			ntohl(sgid_addr.saddr_in.sin_addr.s_addr);
		detach_info.ipv4_valid = SXE2_RDMA_MC_VALID_TRUE;
		detach_info.vlan_id =
			mcast_kget_vlan_ipv4(detach_info.dest_ip_addr);
		mcast_kfill_mac_v4(detach_info.dest_ip_addr,
				   detach_info.dest_mac_addr);
	}

	if (detach_info.vlan_id < VLAN_N_VID)
		detach_info.vlan_valid = SXE2_RDMA_MC_VALID_TRUE;

	detach_info.qpn	      = qp->ibqp.qp_num;
	detach_info.vsi_index = rdma_dev->vsi.vsi_idx;
	detach_info.pf_id     = (u16)rdma_dev->rdma_func->pf_id;
	detach_info.pf_valid  = (u8)dev->privileged;
	detach_info.vf_id     = dev->rcms_info->pmf_index;

	DRV_RDMA_LOG_DEV_DEBUG(
		"DETACH INFO:MAC %pM, VLAN_ID %#x, IP %pI4, IPv4 valid %d\n"
		"\tVLAN valid %d, QPN %#x, VSI Index %#x\n"
		"\tpf_id %#x, pf_valid %u, vf_id %#x\n",
		detach_info.dest_mac_addr, detach_info.vlan_id,
		detach_info.dest_ip_addr, detach_info.ipv4_valid,
		detach_info.vlan_valid, detach_info.qpn, detach_info.vsi_index,
		detach_info.pf_id, detach_info.pf_valid, detach_info.vf_id);

	ret = mcast_kdetach_qp(rdma_dev, &detach_info);

	return ret;
}
