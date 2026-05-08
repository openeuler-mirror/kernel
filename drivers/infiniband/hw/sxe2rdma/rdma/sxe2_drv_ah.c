// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_ah.c
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/rcupdate.h>
#include <linux/delay.h>
#include <linux/string.h>
#include <net/route.h>
#include <rdma/ib_addr.h>
#include <rdma/ib_cache.h>

#include "sxe2-abi.h"
#include "sxe2_drv_rdma_common.h"
#include "sxe2_drv_mq.h"
#include "sxe2_drv_main.h"
#include "sxe2_drv_mr.h"
#include "sxe2_drv_ah.h"
#include "sxe2_drv_rdma_log.h"
#include "sxe2_drv_ah_debugfs.h"

static bool sxe2_ipv4_is_lpb(u32 loc_addr, u32 rem_addr)
{
	return ipv4_is_loopback(htonl(rem_addr)) || (loc_addr == rem_addr);
}

static bool sxe2_ipv6_is_lpb(u32 *loc_addr, u32 *rem_addr)
{
	struct in6_addr raddr6;

	sxe2_copy_ip_htonl(raddr6.in6_u.u6_addr32, rem_addr);

	return !memcmp(loc_addr, rem_addr, 16) || ipv6_addr_loopback(&raddr6);
}
static inline void sxe2_mcast_mac_v4(u32 *ip_addr, u8 *mac)
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

static inline void sxe2_mcast_mac_v6(u32 *ip_addr, u8 *mac)
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

static u8 sxe2_get_vlan_prio(struct net_device __rcu *ndev_rcu, u8 prio)
{
	struct net_device *ndev;

	rcu_read_lock();
	ndev = rcu_dereference(ndev_rcu);
	if (!ndev)
		goto exit;
	if (is_vlan_dev(ndev)) {
		u16 vlan_qos = vlan_dev_get_egress_qos_mask(ndev, prio);

		prio = (vlan_qos & VLAN_PRIO_MASK) >> VLAN_PRIO_SHIFT;
	}
exit:
	rcu_read_unlock();
	return prio;
}

static void sxe2_fill_ah_info(struct sxe2_rdma_device *rdma_dev,
			      struct rdma_ah_attr *attr,
			      union sxe2_ah_info *ah_info, u8 net_type)
{
	union sxe2_sockaddr sgid_addr, dgid_addr;
	u8 dmac[ETH_ALEN];
	u16 vlan_prio;
	int i;
	int j;
	u32 tmp_ip[4] = {};

	rdma_gid2ip((struct sockaddr *)&sgid_addr, &attr->grh.sgid_attr->gid);
	rdma_gid2ip((struct sockaddr *)&dgid_addr, &attr->grh.dgid);
	ether_addr_copy(dmac, attr->roce.dmac);

	if (attr->ah_flags & IB_AH_GRH) {
		ah_info->field.flow_label = attr->grh.flow_label;
		ah_info->field.hop_ttl	  = attr->grh.hop_limit;
		ah_info->field.tc_tos	  = attr->grh.traffic_class;
	}

	if (net_type == RDMA_NETWORK_IPV4) {
		ah_info->field.ipv4_valid = true;
		ah_info->field.dest_ip_addr[0] =
			ntohl(dgid_addr.saddr_in.sin_addr.s_addr);
		ah_info->field.src_ip_addr[0] =
			ntohl(sgid_addr.saddr_in.sin_addr.s_addr);
		ah_info->field.do_lpbk =
			sxe2_ipv4_is_lpb(ah_info->field.src_ip_addr[0],
					 ah_info->field.dest_ip_addr[0]);
		if (ipv4_is_multicast(dgid_addr.saddr_in.sin_addr.s_addr))
			sxe2_mcast_mac_v4(ah_info->field.dest_ip_addr, dmac);
	} else {
		sxe2_copy_ip_ntohl(
			ah_info->field.dest_ip_addr,
			dgid_addr.saddr_in6.sin6_addr.in6_u.u6_addr32);
		sxe2_copy_ip_ntohl(
			ah_info->field.src_ip_addr,
			sgid_addr.saddr_in6.sin6_addr.in6_u.u6_addr32);
		ah_info->field.do_lpbk =
			sxe2_ipv6_is_lpb(ah_info->field.src_ip_addr,
					 ah_info->field.dest_ip_addr);
		if (rdma_is_multicast_addr(&dgid_addr.saddr_in6.sin6_addr))
			sxe2_mcast_mac_v6(&ah_info->field.dest_ip_addr[3],
					  dmac);
		DRV_RDMA_LOG_DEV_DEBUG("mc0, SIP6=%pI6, DIP6=%pI6, MAC=%pM\n",
				       ah_info->field.src_ip_addr,
				       ah_info->field.dest_ip_addr, dmac);

		DRV_RDMA_LOG_DEV_DEBUG(
			"mc0, SIP6=%u.%u.%u.%u, DIP6=%u.%u.%u.%u",
			ah_info->field.src_ip_addr[0],
			ah_info->field.src_ip_addr[1],
			ah_info->field.src_ip_addr[2],
			ah_info->field.src_ip_addr[3],
			ah_info->field.dest_ip_addr[0],
			ah_info->field.dest_ip_addr[1],
			ah_info->field.dest_ip_addr[2],
			ah_info->field.dest_ip_addr[3]);

		memset(tmp_ip, 0, sizeof(tmp_ip[0]) * 4);
		memcpy(tmp_ip, ah_info->field.dest_ip_addr,
		       sizeof(tmp_ip[0]) * 4);
		for (i = 0, j = 3; (i < 4) && (j >= 0); i++, j--)
			ah_info->field.dest_ip_addr[i] = tmp_ip[j];
		memset(tmp_ip, 0, sizeof(tmp_ip[0]) * 4);
		memcpy(tmp_ip, ah_info->field.src_ip_addr,
		       sizeof(tmp_ip[0]) * 4);
		for (i = 0, j = 3; (i < 4) && (j >= 0); i++, j--)
			ah_info->field.src_ip_addr[i] = tmp_ip[j];
		DRV_RDMA_LOG_DEV_DEBUG("mc1, SIP6=%pI6, DIP6=%pI6, MAC=%pM\n",
				       ah_info->field.src_ip_addr,
				       ah_info->field.dest_ip_addr, dmac);

		DRV_RDMA_LOG_DEV_DEBUG(
			"mc1, SIP6=%u.%u.%u.%u, DIP6=%u.%u.%u.%u",
			ah_info->field.src_ip_addr[0],
			ah_info->field.src_ip_addr[1],
			ah_info->field.src_ip_addr[2],
			ah_info->field.src_ip_addr[3],
			ah_info->field.dest_ip_addr[0],
			ah_info->field.dest_ip_addr[1],
			ah_info->field.dest_ip_addr[2],
			ah_info->field.dest_ip_addr[3]);
	}

	if (ah_info->field.vlan_tag >= VLAN_N_VID && rdma_dev->dcb_vlan_mode)
		ah_info->field.vlan_tag = 0;
	if (ah_info->field.vlan_tag < VLAN_N_VID) {
		ah_info->field.insert_vlan_tag = true;
		vlan_prio		       = (u16)sxe2_get_vlan_prio(
			     attr->grh.sgid_attr->ndev,
			     rt_tos2priority(ah_info->field.tc_tos));
		ah_info->field.vlan_tag |= vlan_prio << VLAN_PRIO_SHIFT;
	}

	for (i = 0, j = ETH_ALEN - 1; (i < ETH_ALEN) && (j >= 0); i++, j--)
		ah_info->field.dest_mac[i] = dmac[j];

	if (rdma_dev->roce_dcqcn_en) {
		ah_info->field.tc_tos &= ~ECN_CODE_PT_MASK;
		ah_info->field.tc_tos |= ECN_CODE_PT_VAL;
	}
}

static bool sxe2_ah_exists(struct sxe2_rdma_device *rdma_dev,
			   struct sxe2_ah *new_ah)
{
	struct sxe2_ah *ah = NULL;
	u32 save_ah_id	   = new_ah->ctx_ah.ah_info.field.ah_idx;
	u32 key = new_ah->ctx_ah.ah_info.field.dest_ip_addr[0] ^
		  new_ah->ctx_ah.ah_info.field.dest_ip_addr[1] ^
		  new_ah->ctx_ah.ah_info.field.dest_ip_addr[2] ^
		  new_ah->ctx_ah.ah_info.field.dest_ip_addr[3];

	hash_for_each_possible(rdma_dev->ah_hash_tbl, ah, list, key) {
		new_ah->ctx_ah.ah_info.field.ah_idx =
			ah->ctx_ah.ah_info.field.ah_idx;
		DRV_RDMA_LOG_DEV_DEBUG(
			"AH CMP: oldinfo == newinfo\n"
			"dmac %d:%d:%d:%d:%d:%d == %d:%d:%d:%d:%d:%d\n"
			"vlan_tag %u == %u\n"
			"tc_tos %u == %u\n"
			"pd_idx %u == %u\n"
			"flow_label %u == %u\n"
			"hop_ttl %u == %u\n"
			"arp_idx %u == %u\n"
			"ah_idx %u == %u\n"
			"op %d == %d\n"
			"ipv4_valid %d == %d\n"
			"insert_vlan_tag %d == %d\n"
			"do_lpbk %d == %d\n"
			"wqe_valid %d == %d\n"
			"dip %d:%d:%d:%d == %d:%d:%d:%d\n"
			"sip %d:%d:%d:%d == %d:%d:%d:%d\n",
			ah->ctx_ah.ah_info.field.dest_mac[0],
			ah->ctx_ah.ah_info.field.dest_mac[1],
			ah->ctx_ah.ah_info.field.dest_mac[2],
			ah->ctx_ah.ah_info.field.dest_mac[3],
			ah->ctx_ah.ah_info.field.dest_mac[4],
			ah->ctx_ah.ah_info.field.dest_mac[5],
			new_ah->ctx_ah.ah_info.field.dest_mac[0],
			new_ah->ctx_ah.ah_info.field.dest_mac[1],
			new_ah->ctx_ah.ah_info.field.dest_mac[2],
			new_ah->ctx_ah.ah_info.field.dest_mac[3],
			new_ah->ctx_ah.ah_info.field.dest_mac[4],
			new_ah->ctx_ah.ah_info.field.dest_mac[5],
			ah->ctx_ah.ah_info.field.vlan_tag,
			new_ah->ctx_ah.ah_info.field.vlan_tag,
			ah->ctx_ah.ah_info.field.tc_tos,
			new_ah->ctx_ah.ah_info.field.tc_tos,
			ah->ctx_ah.ah_info.field.pd_idx,
			new_ah->ctx_ah.ah_info.field.pd_idx,
			ah->ctx_ah.ah_info.field.flow_label,
			new_ah->ctx_ah.ah_info.field.flow_label,
			ah->ctx_ah.ah_info.field.hop_ttl,
			new_ah->ctx_ah.ah_info.field.hop_ttl,
			ah->ctx_ah.ah_info.field.arp_index,
			new_ah->ctx_ah.ah_info.field.arp_index,
			ah->ctx_ah.ah_info.field.ah_idx,
			new_ah->ctx_ah.ah_info.field.ah_idx,
			ah->ctx_ah.ah_info.field.op,
			new_ah->ctx_ah.ah_info.field.op,
			ah->ctx_ah.ah_info.field.ipv4_valid,
			new_ah->ctx_ah.ah_info.field.ipv4_valid,
			ah->ctx_ah.ah_info.field.insert_vlan_tag,
			new_ah->ctx_ah.ah_info.field.insert_vlan_tag,
			ah->ctx_ah.ah_info.field.do_lpbk,
			new_ah->ctx_ah.ah_info.field.do_lpbk,
			ah->ctx_ah.ah_info.field.wqe_valid,
			new_ah->ctx_ah.ah_info.field.wqe_valid,
			ah->ctx_ah.ah_info.field.dest_ip_addr[0],
			ah->ctx_ah.ah_info.field.dest_ip_addr[1],
			ah->ctx_ah.ah_info.field.dest_ip_addr[2],
			ah->ctx_ah.ah_info.field.dest_ip_addr[3],
			new_ah->ctx_ah.ah_info.field.dest_ip_addr[0],
			new_ah->ctx_ah.ah_info.field.dest_ip_addr[1],
			new_ah->ctx_ah.ah_info.field.dest_ip_addr[2],
			new_ah->ctx_ah.ah_info.field.dest_ip_addr[3],
			ah->ctx_ah.ah_info.field.src_ip_addr[0],
			ah->ctx_ah.ah_info.field.src_ip_addr[1],
			ah->ctx_ah.ah_info.field.src_ip_addr[2],
			ah->ctx_ah.ah_info.field.src_ip_addr[3],
			new_ah->ctx_ah.ah_info.field.src_ip_addr[0],
			new_ah->ctx_ah.ah_info.field.src_ip_addr[1],
			new_ah->ctx_ah.ah_info.field.src_ip_addr[2],
			new_ah->ctx_ah.ah_info.field.src_ip_addr[3]);
		if (!memcmp(&ah->ctx_ah.ah_info, &new_ah->ctx_ah.ah_info,
			    sizeof(ah->ctx_ah.ah_info))) {
			refcount_inc(&ah->refcnt);
			new_ah->parent_ah = ah;
			return true;
		}
	}
	new_ah->ctx_ah.ah_info.field.ah_idx = save_ah_id;
	ah = kmemdup(new_ah, sizeof(*new_ah), GFP_KERNEL);
	if (!ah)
		return false;
	new_ah->parent_ah = ah;
	hash_add(rdma_dev->ah_hash_tbl, &ah->list, key);
	rdma_dev->ah_list_cnt++;
	if (rdma_dev->ah_list_cnt > rdma_dev->ah_list_hwm)
		rdma_dev->ah_list_hwm = rdma_dev->ah_list_cnt;
	refcount_set(&ah->refcnt, 1);

	return false;
}

static int sxe2_post_ah_mqinfo(struct sxe2_rdma_pci_f *rf,
			       struct sxe2_ctx_ah *ctx_ah, u8 cmd, bool wait,
			       void (*callback_fcn)(struct sxe2_mq_request *),
			       void *cb_param)
{
	struct sxe2_mq_request *mq_request;
	struct mq_cmds_info *cmd_info;
	struct sxe2_rdma_device *rdma_dev;
	int status;

	rdma_dev = rf->rdma_dev;
	if ((cmd != SXE2_MQ_OP_CREATE_ADDR_HANDLE) &&
	    (cmd != SXE2_MQ_OP_DESTROY_ADDR_HANDLE)) {
		DRV_RDMA_LOG_DEV_DEBUG("AH:ah mq cmd type error.\n");
		return -EINVAL;
	}

	mq_request = sxe2_kalloc_and_get_mq_request(&rf->mq, wait);
	if (!mq_request) {
		DRV_RDMA_LOG_DEV_DEBUG("AH:failed get ah mq msg.\n");
		return -ENOMEM;
	}

	cmd_info = &mq_request->info;
	if (cmd == SXE2_MQ_OP_CREATE_ADDR_HANDLE) {
		cmd_info->mq_cmd = MQ_OP_CREATE_ADDR_HANDLE;
	} else if (cmd == SXE2_MQ_OP_DESTROY_ADDR_HANDLE) {
		cmd_info->mq_cmd  = MQ_OP_DESTROY_ADDR_HANDLE;
		cmd_info->destroy = true;
	}

	cmd_info->post_mq = 1;

	if (cmd == SXE2_MQ_OP_CREATE_ADDR_HANDLE) {
		if (!wait)
			sxe2_kget_mq_request(mq_request);
		ctx_ah->mq_request = mq_request;
	}

#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
	INJECT_START(rdma_dev->rdma_func, "mq_rcs_wqe_ah",
		     &rdma_dev->rdma_func->mq.err_cqe_val, ctx_ah);
	INJECT_DEACTIVE(rdma_dev->rdma_func, "mq_rcs_wqe_ah");
#endif

	cmd_info->in.u.ah_info.ctx_dev = &rf->ctx_dev;
	cmd_info->in.u.ah_info.info    = ctx_ah->ah_info;
	cmd_info->in.u.ah_info.scratch = (uintptr_t)mq_request;

	if (!wait) {
		mq_request->callback_fcn = callback_fcn;
		mq_request->param	 = cb_param;
	}
	status = sxe2_khandle_mq_cmd(rf, mq_request);
	sxe2_kput_mq_request(&rf->mq, mq_request);
	if (status) {
		DRV_RDMA_LOG_DEV_DEBUG("AH:failed proc ah mq cmd, ret %d.\n",
				       status);
		return status;
	}

	if (wait)
		ctx_ah->ah_valid = (cmd == SXE2_MQ_OP_CREATE_ADDR_HANDLE);

	return 0;
}

static int sxe2_create_ah_wait(struct sxe2_rdma_pci_f *rf,
			       struct sxe2_ctx_ah *ctx_ah, bool sleep)
{
	struct sxe2_rdma_device *rdma_dev = rf->rdma_dev;
	int ret				  = 0;
	bool mq_error			  = false;
	u16 maj_err			  = 0;
	u16 min_err			  = 0;

	if (!sleep) {
		u32 cnt = rf->ctx_dev.hw_attrs.max_mq_compl_wait_time_ms *
			  CQP_TIMEOUT_THRESHOLD;
		struct sxe2_mq_request *mq_request = ctx_ah->mq_request;

		do {
			sxe2_khandler_mcqe(rf, &rf->mcq.ctx_cq, false);
			mdelay(1);
		} while (!READ_ONCE(mq_request->request_done) && --cnt);

		if (cnt && !mq_request->cmpl_info.op_ret_val) {
			sxe2_kput_mq_request(&rf->mq, mq_request);
			ctx_ah->ah_valid = true;

			if (mq_request->cmpl_info.error)
				mq_error = mq_request->cmpl_info.error;
			if (mq_error) {
				maj_err = mq_request->cmpl_info.maj_err_code;
				min_err = mq_request->cmpl_info.min_err_code;
				ret	= -EIO;
			}
			if ((maj_err == MQ_CRIERR_MAJ_ERRCODE) &&
			    ((min_err == MQ_CRIERR_MQC_NOT_CREATED) ||
			     (min_err == MQ_CRIERR_MQ_BASE_ERR) ||
			     (min_err == MQ_CRIERR_MQC_ECC_ERR) ||
			     ((min_err == MQ_CRIERR_QP_DESTROY_ABORT)))) {
				if (!rf->reset) {
					DRV_RDMA_LOG_DEV_ERR(
						"Critical Err:Request Reset, maj_err %#04X\n"
						"min_err %#04X, AH cmd\n",
						maj_err, min_err);
					rf->reset = true;
					rf->gen_ops.request_reset(rf);
				}
			}
		} else {
			ret = !cnt ? -ETIMEDOUT : -EINVAL;
			sxe2_kput_mq_request(&rf->mq, mq_request);
			if (!cnt && !rf->reset) {
				rf->reset = true;
				rf->gen_ops.request_reset(rf);
			}
		}
	}

	return ret;
}

static void sxe2_err_inject_ah_id(struct sxe2_rdma_device *rdma_dev,
				  union sxe2_ah_info *ah_info, u32 ah_id)
{
#if defined(SXE2_CFG_DEBUG) && defined(SXE2_SUPPORT_INJECT)
	INJECT_START(rdma_dev->rdma_func, "ah_err_idx", ah_info);

	switch (rdma_dev->rdma_func->mq.err_cqe_val.rsc_wqe_err_type) {
	case AH_ID_DEBUGFS:
		ah_info->field.ah_idx =
			rdma_dev->rdma_func->mq.err_cqe_val.rsc_wqe_err_val;
		DRV_RDMA_LOG_DEBUG_BDF(
			"MQ DEBUGFS:inject rsc_err_type:%#x,rsc_err_val\n"
			"\t%#llx,ori ah_id %#llx,err ah_id %#llx\n",
			rdma_dev->rdma_func->mq.err_cqe_val.rsc_wqe_err_type,
			rdma_dev->rdma_func->mq.err_cqe_val.rsc_wqe_err_val,
			(u64)ah_id, (u64)ah_info->field.ah_idx);
		break;
	default:
		break;
	}
#endif
}

static void sxe2_process_create_ah_err(struct sxe2_rdma_device *rdma_dev,
				       struct sxe2_ah *vendor_ah)
{
	if (vendor_ah->parent_ah) {
		hash_del(&vendor_ah->parent_ah->list);
		kfree(vendor_ah->parent_ah);
		vendor_ah->parent_ah = NULL;
		rdma_dev->ah_list_cnt--;
	}
}

#ifdef CREATE_AH_VER_3
struct ib_ah *sxe2_kcreate_ah(struct ib_pd *ibpd, struct rdma_ah_attr *attr,
		    struct ib_udata *udata)
{
	u32 flags		  = attr->ah_flags;
	struct sxe2_rdma_pd *pd	  = ibpd_to_vendor_pd(ibpd);
	struct sxe2_ah *vendor_ah = NULL;
	struct sxe2_rdma_device *rdma_dev = ibdev_to_rdmadev(ibpd->device);
	struct sxe2_rdma_pci_f *rf	  = rdma_dev->rdma_func;
	struct sxe2_ctx_ah *ctx_ah;
	u32 ah_id = 0;
	union sxe2_ah_info *ah_info;
	struct sxe2_create_ah_resp uresp = {};
	int err;
	u16 vlan_id;
	bool sleep = (flags & RDMA_CREATE_AH_SLEEPABLE) != 0;

	DRV_RDMA_LOG_DEV_DEBUG("AH:kcreate enter, sleep %d.\n", sleep);

	if (udata && udata->outlen < sizeof(uresp)) {
		DRV_RDMA_LOG_DEV_ERR("AH: invalid udata.\n");
		return ERR_PTR(-EINVAL);
	}
	if (rf->reset) {
		DRV_RDMA_LOG_DEV_ERR("AH: function has reset!\n");
		return ERR_PTR(-EINVAL);
	}
	err = sxe2_kalloc_rsrc(rf, rf->allocated_ahs, rf->max_ah, &ah_id,
			       &rf->next_ah);
	if (err) {
		DRV_RDMA_LOG_DEV_ERR("AH: failed alloc ah idx, ret %d\n", err);
		return ERR_PTR(err);
	}

	vendor_ah =  kzalloc(sizeof(*vendor_ah), GFP_KERNEL);
	if (!vendor_ah) {
		DRV_RDMA_LOG_DEV_ERR("vendor_ah kzalloc failed\n");
		err = -ENOMEM;
		goto err_gid_l2;
	}

	ctx_ah		    = &vendor_ah->ctx_ah;
	ctx_ah->dev	    = &rf->ctx_dev;
	vendor_ah->av.attrs = *attr;
	vendor_ah->av.net_type =
		rdma_gid_attr_network_type(attr->grh.sgid_attr);
	ah_info = &ctx_ah->ah_info;
	vlan_id = rdma_vlan_dev_vlan_id(attr->grh.sgid_attr->ndev);
	if (err) {
		DRV_RDMA_LOG_DEV_ERR("AH: failed read vlan_id, ret %d\n", err);
		goto err_kalloc_ah;
	}
	ah_info->field.pd_idx	= pd->pd_ctx.pd_id;
	ah_info->field.vlan_tag = vlan_id;
	ah_info->field.ah_idx	= ah_id;

	sxe2_err_inject_ah_id(rdma_dev, ah_info, ah_id);

	sxe2_fill_ah_info(rdma_dev, attr, ah_info, vendor_ah->av.net_type);
	if (sleep) {
		mutex_lock(&rdma_dev->ah_tbl_lock);
		if (sxe2_ah_exists(rdma_dev, vendor_ah)) {
			sxe2_kfree_rsrc(rdma_dev->rdma_func,
					rdma_dev->rdma_func->allocated_ahs,
					ah_id);
			ah_id = 0;
#ifdef CONFIG_DEBUG_FS
			rdma_dev->ah_reused++;
#endif
			goto exit;
		}
	}
	err = sxe2_post_ah_mqinfo(rdma_dev->rdma_func, ctx_ah,
				  SXE2_MQ_OP_CREATE_ADDR_HANDLE, sleep, NULL,
				  ctx_ah);
	if (err) {
		DRV_RDMA_LOG_DEV_ERR("AH: failed post ah mq, ret %d\n", err);
		goto err_ah_create;
	}
	err = sxe2_create_ah_wait(rf, ctx_ah, sleep);
	if (err) {
		DRV_RDMA_LOG_DEV_ERR("AH: failed proc ah mq, ret %d\n", err);
		goto err_unlock;
	}
#ifdef SXE2_CFG_DEBUG
	(void)sxe2_debbugfs_ah_add(rdma_dev, vendor_ah);
#endif
exit:
	if (udata) {
		uresp.ah_id = ah_info->field.ah_idx;
		err	    = ib_copy_to_udata(udata, &uresp,
				       min(sizeof(uresp), udata->outlen));
		if (err) {
			DRV_RDMA_LOG_DEV_ERR("AH: failed copy udata, ret %d\n",
					     err);
			if (!vendor_ah->parent_ah ||
			    (vendor_ah->parent_ah &&
			     refcount_dec_and_test(
				     &vendor_ah->parent_ah->refcnt))) {
				sxe2_post_ah_mqinfo(
					rdma_dev->rdma_func, &vendor_ah->ctx_ah,
					SXE2_MQ_OP_DESTROY_ADDR_HANDLE, false,
					NULL, vendor_ah);
				ah_id = vendor_ah->ctx_ah.ah_info.field.ah_idx;
				goto err_ah_create;
			}
			goto err_unlock;
		}
	}
	if (sleep)
		mutex_unlock(&rdma_dev->ah_tbl_lock);
	return &vendor_ah->ibah;
err_ah_create:
	sxe2_process_create_ah_err(rdma_dev, vendor_ah);
err_unlock:
	if (sleep)
		mutex_unlock(&rdma_dev->ah_tbl_lock);
err_kalloc_ah:
	kfree(vendor_ah);
err_gid_l2:
	if (ah_id)
		sxe2_kfree_rsrc(rdma_dev->rdma_func,
				rdma_dev->rdma_func->allocated_ahs, ah_id);

	DRV_RDMA_LOG_DEV_ERR("AH: failed create ah, ret %d\n", err);

	return ERR_PTR(err);
}
#else
#ifdef CREATE_AH_VER_2
int sxe2_kcreate_ah(struct ib_ah *ibah, struct rdma_ah_attr *attr, u32 flags,
		    struct ib_udata *udata)
#else
int sxe2_kcreate_ah(struct ib_ah *ibah, struct rdma_ah_init_attr *init_attr,
		    struct ib_udata *udata)
#endif
{
#ifndef CREATE_AH_VER_2
	struct rdma_ah_attr *attr = init_attr->ah_attr;
	u32 flags		  = init_attr->flags;
#endif

	struct sxe2_rdma_pd *pd	  = ibpd_to_vendor_pd(ibah->pd);
	struct sxe2_ah *vendor_ah = container_of(ibah, struct sxe2_ah, ibah);
	struct sxe2_rdma_device *rdma_dev = ibdev_to_rdmadev(ibah->pd->device);
	struct sxe2_rdma_pci_f *rf	  = rdma_dev->rdma_func;
	struct sxe2_ctx_ah *ctx_ah;
	u32 ah_id = 0;
	union sxe2_ah_info *ah_info;
	struct sxe2_create_ah_resp uresp = {};
	int err;
	u16 vlan_id;
	bool sleep = (flags & RDMA_CREATE_AH_SLEEPABLE) != 0;

	DRV_RDMA_LOG_DEV_DEBUG("AH:kcreate ah(%p) enter, sleep %d.\n",
			       vendor_ah, sleep);

	if (udata && udata->outlen < sizeof(uresp)) {
		DRV_RDMA_LOG_DEV_ERR("AH: invalid udata.\n");
		return -EINVAL;
	}
	if (rf->reset) {
		DRV_RDMA_LOG_DEV_ERR("AH: function has reset!\n");
		return -EINVAL;
	}
	err = sxe2_kalloc_rsrc(rf, rf->allocated_ahs, rf->max_ah, &ah_id,
			       &rf->next_ah);
	if (err) {
		DRV_RDMA_LOG_DEV_ERR("AH: failed alloc ah idx, ret %d\n", err);
		return err;
	}
	ctx_ah		    = &vendor_ah->ctx_ah;
	ctx_ah->dev	    = &rf->ctx_dev;
	vendor_ah->av.attrs = *attr;
	vendor_ah->av.net_type =
		rdma_gid_attr_network_type(attr->grh.sgid_attr);
	ah_info = &ctx_ah->ah_info;
	err	= rdma_read_gid_l2_fields(attr->grh.sgid_attr, &vlan_id, NULL);
	if (err) {
		DRV_RDMA_LOG_DEV_ERR("AH: failed read vlan_id, ret %d\n", err);
		goto err_gid_l2;
	}
	ah_info->field.pd_idx	= pd->pd_ctx.pd_id;
	ah_info->field.vlan_tag = vlan_id;
	ah_info->field.ah_idx	= ah_id;

	sxe2_err_inject_ah_id(rdma_dev, ah_info, ah_id);

	sxe2_fill_ah_info(rdma_dev, attr, ah_info, vendor_ah->av.net_type);
	if (sleep) {
		mutex_lock(&rdma_dev->ah_tbl_lock);
		if (sxe2_ah_exists(rdma_dev, vendor_ah)) {
			sxe2_kfree_rsrc(rdma_dev->rdma_func,
					rdma_dev->rdma_func->allocated_ahs,
					ah_id);
			ah_id = 0;
#ifdef CONFIG_DEBUG_FS
			rdma_dev->ah_reused++;
#endif
			goto exit;
		}
	}
	err = sxe2_post_ah_mqinfo(rdma_dev->rdma_func, ctx_ah,
				  SXE2_MQ_OP_CREATE_ADDR_HANDLE, sleep, NULL,
				  ctx_ah);
	if (err) {
		DRV_RDMA_LOG_DEV_ERR("AH: failed post ah mq, ret %d\n", err);
		goto err_ah_create;
	}
	err = sxe2_create_ah_wait(rf, ctx_ah, sleep);
	if (err) {
		DRV_RDMA_LOG_DEV_ERR("AH: failed proc ah mq, ret %d\n", err);
		goto err_unlock;
	}
#ifdef SXE2_CFG_DEBUG
	(void)sxe2_debbugfs_ah_add(rdma_dev, vendor_ah);
#endif
exit:
	if (udata) {
		uresp.ah_id = ah_info->field.ah_idx;
		err	    = ib_copy_to_udata(udata, &uresp,
				       min(sizeof(uresp), udata->outlen));
		if (err) {
			DRV_RDMA_LOG_DEV_ERR("AH: failed copy udata, ret %d\n",
					     err);
			if (!vendor_ah->parent_ah ||
			    (vendor_ah->parent_ah &&
			     refcount_dec_and_test(
				     &vendor_ah->parent_ah->refcnt))) {
				sxe2_post_ah_mqinfo(
					rdma_dev->rdma_func, &vendor_ah->ctx_ah,
					SXE2_MQ_OP_DESTROY_ADDR_HANDLE, false,
					NULL, vendor_ah);
				ah_id = vendor_ah->ctx_ah.ah_info.field.ah_idx;
				goto err_ah_create;
			}
			goto err_unlock;
		}
	}
	if (sleep)
		mutex_unlock(&rdma_dev->ah_tbl_lock);
	return 0;
err_ah_create:
	sxe2_process_create_ah_err(rdma_dev, vendor_ah);
err_unlock:
	if (sleep)
		mutex_unlock(&rdma_dev->ah_tbl_lock);
err_gid_l2:
	if (ah_id)
		sxe2_kfree_rsrc(rdma_dev->rdma_func,
				rdma_dev->rdma_func->allocated_ahs, ah_id);

	DRV_RDMA_LOG_DEV_ERR("AH: failed create ah, ret %d\n", err);

	return err;
}
#endif
#ifdef DESTROY_AH_VER_3
void sxe2_kdestroy_ah(struct ib_ah *ibah, u32 ah_flags)
{
	struct sxe2_rdma_device *rdma_dev = ibdev_to_rdmadev(ibah->device);
	struct sxe2_ah *vendor_ah	  = ibah_to_vendor_ah(ibah);

	DRV_RDMA_LOG_DEBUG_BDF("AH:destroy ah enter(%p).\n", vendor_ah);
#ifdef SXE2_CFG_DEBUG
	if (vendor_ah->dbg_node)
		sxe2_debugfs_ah_remove(rdma_dev, vendor_ah);
#endif
	if (vendor_ah->parent_ah) {
		mutex_lock(&rdma_dev->ah_tbl_lock);
		if (!refcount_dec_and_test(&vendor_ah->parent_ah->refcnt)) {
			mutex_unlock(&rdma_dev->ah_tbl_lock);
			return;
		}
		hash_del(&vendor_ah->parent_ah->list);
		kfree(vendor_ah->parent_ah);
		vendor_ah->parent_ah = NULL;
		rdma_dev->ah_list_cnt--;
		mutex_unlock(&rdma_dev->ah_tbl_lock);
	}
	sxe2_post_ah_mqinfo(rdma_dev->rdma_func, &vendor_ah->ctx_ah,
			    SXE2_MQ_OP_DESTROY_ADDR_HANDLE, false, NULL,
			    vendor_ah);

	sxe2_kfree_rsrc(rdma_dev->rdma_func, rdma_dev->rdma_func->allocated_ahs,
			vendor_ah->ctx_ah.ah_info.field.ah_idx);
}
#elif defined DESTROY_AH_VER_4
int sxe2_kdestroy_ah(struct ib_ah *ibah)
{
	struct sxe2_rdma_device *rdma_dev = ibdev_to_rdmadev(ibah->device);
	struct sxe2_ah *vendor_ah = ibah_to_vendor_ah(ibah);

	DRV_RDMA_LOG_DEV_DEBUG("AH:destroy ah enter(%p).\n", vendor_ah);
#ifdef SXE2_CFG_DEBUG
	if (vendor_ah->dbg_node)
		sxe2_debugfs_ah_remove(rdma_dev, vendor_ah);
#endif
	if (vendor_ah->parent_ah) {
		mutex_lock(&rdma_dev->ah_tbl_lock);
		if (!refcount_dec_and_test(&vendor_ah->parent_ah->refcnt)) {
			mutex_unlock(&rdma_dev->ah_tbl_lock);
			return 0;
		}
		hash_del(&vendor_ah->parent_ah->list);
		kfree(vendor_ah->parent_ah);
		vendor_ah->parent_ah = NULL;
		rdma_dev->ah_list_cnt--;
		mutex_unlock(&rdma_dev->ah_tbl_lock);
	}
	sxe2_post_ah_mqinfo(rdma_dev->rdma_func, &vendor_ah->ctx_ah,
			    SXE2_MQ_OP_DESTROY_ADDR_HANDLE, false, NULL,
			    vendor_ah);

	sxe2_kfree_rsrc(rdma_dev->rdma_func, rdma_dev->rdma_func->allocated_ahs,
			vendor_ah->ctx_ah.ah_info.field.ah_idx);
	return 0;
}
#else
int sxe2_kdestroy_ah(struct ib_ah *ibah, u32 ah_flags)
{
	struct sxe2_rdma_device *rdma_dev = ibdev_to_rdmadev(ibah->device);
	struct sxe2_ah *vendor_ah = ibah_to_vendor_ah(ibah);

	DRV_RDMA_LOG_DEV_DEBUG("AH:destroy ah enter(%p).\n", vendor_ah);
#ifdef SXE2_CFG_DEBUG
	if (vendor_ah->dbg_node)
		sxe2_debugfs_ah_remove(rdma_dev, vendor_ah);
#endif
	if (vendor_ah->parent_ah) {
		mutex_lock(&rdma_dev->ah_tbl_lock);
		if (!refcount_dec_and_test(&vendor_ah->parent_ah->refcnt)) {
			mutex_unlock(&rdma_dev->ah_tbl_lock);
			return 0;
		}
		hash_del(&vendor_ah->parent_ah->list);
		kfree(vendor_ah->parent_ah);
		vendor_ah->parent_ah = NULL;
		rdma_dev->ah_list_cnt--;
		mutex_unlock(&rdma_dev->ah_tbl_lock);
	}
	sxe2_post_ah_mqinfo(rdma_dev->rdma_func, &vendor_ah->ctx_ah,
			    SXE2_MQ_OP_DESTROY_ADDR_HANDLE, false, NULL,
			    vendor_ah);

	sxe2_kfree_rsrc(rdma_dev->rdma_func, rdma_dev->rdma_func->allocated_ahs,
			vendor_ah->ctx_ah.ah_info.field.ah_idx);
	return 0;
}
#endif

int sxe2_kquery_ah(struct ib_ah *ibah, struct rdma_ah_attr *ah_attr)
{
	struct sxe2_rdma_device *rdma_dev = ibdev_to_rdmadev(ibah->device);
	struct sxe2_ah *vendor_ah	  = ibah_to_vendor_ah(ibah);

	DRV_RDMA_LOG_DEV_ERR("AH:kquery ah enter\n");

	(void)vendor_ah;
	memset(ah_attr, 0, sizeof(*ah_attr));
	if (vendor_ah->av.attrs.ah_flags & IB_AH_GRH) {
		ah_attr->ah_flags	= IB_AH_GRH;
		ah_attr->grh.flow_label = vendor_ah->av.attrs.grh.flow_label;
		ah_attr->grh.traffic_class =
			vendor_ah->av.attrs.grh.traffic_class;
		ah_attr->grh.hop_limit	= vendor_ah->av.attrs.grh.hop_limit;
		ah_attr->grh.sgid_index = vendor_ah->av.attrs.grh.sgid_index;
		memcpy(&ah_attr->grh.dgid, &vendor_ah->av.attrs.grh.dgid,
		       sizeof(ah_attr->grh.dgid));
	}

	return 0;
}

int sxe2_ah_set_mq_wqe(struct sxe2_rdma_ctx_dev *dev,
		       struct mq_cmds_info *pcmdinfo)
{
	__le64 *wqe;
	void *wqe_info;
	u64 scratch;
	struct sxe2_mq_ctx *mq;
	struct sxe2_rdma_device *rdma_dev;

	mq	 = dev->mq;
	rdma_dev = to_rdmadev(dev);

	switch (pcmdinfo->mq_cmd) {
	case MQ_OP_CREATE_ADDR_HANDLE:
		pcmdinfo->in.u.ah_info.info.field.op =
			SXE2_MQ_OP_CREATE_ADDR_HANDLE;
		pcmdinfo->in.u.ah_info.info.field.wqe_valid = mq->polarity;
		scratch	 = pcmdinfo->in.u.ah_info.scratch;
		wqe_info = (void *)&pcmdinfo->in.u.ah_info.info;
		break;
	case MQ_OP_MODIFY_ADDR_HANDLE:
		pcmdinfo->in.u.ah_info.info.field.op =
			SXE2_MQ_OP_MODIFY_ADDR_HANDLE;
		pcmdinfo->in.u.ah_info.info.field.wqe_valid = mq->polarity;
		scratch	 = pcmdinfo->in.u.ah_info.scratch;
		wqe_info = (void *)&pcmdinfo->in.u.ah_info.info;
		break;
	case MQ_OP_DESTROY_ADDR_HANDLE:
		pcmdinfo->in.u.ah_info.info.field.op =
			SXE2_MQ_OP_DESTROY_ADDR_HANDLE;
		pcmdinfo->in.u.ah_info.info.field.wqe_valid = mq->polarity;
		scratch	 = pcmdinfo->in.u.ah_info.scratch;
		wqe_info = (void *)&pcmdinfo->in.u.ah_info.info;
		break;
	default:
		return -EOPNOTSUPP;
	}

	wqe = sxe2_kget_next_mq_wqe(mq, scratch);
	if (!wqe) {
		DRV_RDMA_LOG_ERROR_BDF("AH:get next mq wqe failed.\n");
		return -ENOMEM;
	}

	sxe2_print_wqe_info(dev, wqe_info, pcmdinfo->mq_cmd);

	sxe2_set_mq_wqe(dev, wqe, wqe_info);

	if (pcmdinfo->post_mq)
		sxe2_kpost_mq(mq);

	return 0;
}
