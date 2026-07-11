// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include "main.h"
#include "icrdma_hw.h"
#include <linux/inet.h>

#ifndef SPEED_200000
#define SPEED_200000 200000
#endif

int zxdh_get_eth_speed(struct ib_device *dev, struct net_device *netdev, u32 port_num, u16 *speed,
		       u8 *width)
{
	int rc;
	u32 netdev_speed;
	struct ethtool_link_ksettings lksettings;

	if (rdma_port_get_link_layer(dev, port_num) != IB_LINK_LAYER_ETHERNET)
		return -EINVAL;

	rtnl_lock();
	rc = __ethtool_get_link_ksettings(netdev, &lksettings);
	rtnl_unlock();

	// dev_put(netdev);

	if (!rc && lksettings.base.speed != (u32)SPEED_UNKNOWN)
		netdev_speed = lksettings.base.speed;
	else
		netdev_speed = SPEED_1000;

	if (netdev_speed <= SPEED_1000) {
		*width = IB_WIDTH_1X;
		*speed = IB_SPEED_SDR;
	} else if (netdev_speed <= SPEED_10000) {
		*width = IB_WIDTH_1X;
		*speed = IB_SPEED_FDR10;
	} else if (netdev_speed <= SPEED_20000) {
		*width = IB_WIDTH_4X;
		*speed = IB_SPEED_DDR;
	} else if (netdev_speed <= SPEED_25000) {
		*width = IB_WIDTH_1X;
		*speed = IB_SPEED_EDR;
	} else if (netdev_speed <= SPEED_40000) {
		*width = IB_WIDTH_4X;
		*speed = IB_SPEED_FDR10;
	} else if (netdev_speed <= SPEED_100000) {
		*width = IB_WIDTH_4X;
		*speed = IB_SPEED_EDR;
	} else if (netdev_speed <= SPEED_200000) {
		*width = IB_WIDTH_4X;
		*speed = IB_SPEED_HDR;
	} else {
		*width = IB_WIDTH_8X;
		*speed = IB_SPEED_HDR;
	}

	return 0;
}

#ifdef IB_FW_VERSION_NAME_MAX
void zxdh_get_dev_fw_str(struct ib_device *dev, char *str)
{
	struct zxdh_device *iwdev = to_iwdev(dev);
	struct ethtool_drvinfo info;
	char extracted_version[16];
	struct net_device *slave = NULL;
	struct list_head *iter;

	memset(&info, 0, sizeof(info));
	if (iwdev->netdev->priv_flags & IFF_BONDING) {
		rtnl_lock();
		netdev_for_each_lower_dev(iwdev->netdev, slave, iter) {
			if (slave->ethtool_ops && slave->ethtool_ops->get_drvinfo) {
				slave->ethtool_ops->get_drvinfo(slave, &info);
				break;
			}
		}
		rtnl_unlock();
		if (!slave && iwdev->netdev->ethtool_ops
			&& iwdev->netdev->ethtool_ops->get_drvinfo)
			iwdev->netdev->ethtool_ops->get_drvinfo(iwdev->netdev, &info);
		extract_version(info.fw_version, extracted_version);
		snprintf(str, IB_FW_VERSION_NAME_MAX, "%s", extracted_version);
		return;
	}
	if (iwdev->netdev->ethtool_ops && iwdev->netdev->ethtool_ops->get_drvinfo)
		iwdev->netdev->ethtool_ops->get_drvinfo(iwdev->netdev, &info);
	extract_version(info.fw_version, extracted_version);
	snprintf(str, IB_FW_VERSION_NAME_MAX, "%s", extracted_version);
}
#else
void zxdh_get_dev_fw_str(struct ib_device *dev, char *str, size_t str_len)
{
	struct zxdh_device *iwdev = to_iwdev(dev);
	struct ethtool_drvinfo info;
	char extracted_version[16];
	struct net_device *slave = NULL;
	struct list_head *iter;

	memset(&info, 0, sizeof(info));
	if (iwdev->netdev->priv_flags & IFF_BONDING) {
		rtnl_lock();
		netdev_for_each_lower_dev(iwdev->netdev, slave, iter) {
			if (slave->ethtool_ops && slave->ethtool_ops->get_drvinfo) {
				slave->ethtool_ops->get_drvinfo(slave, &info);
				break;
			}
		}
		rtnl_unlock();
		if (!slave && iwdev->netdev->ethtool_ops
			&& iwdev->netdev->ethtool_ops->get_drvinfo)
			iwdev->netdev->ethtool_ops->get_drvinfo(iwdev->netdev, &info);
		extract_version(info.fw_version, extracted_version);
		snprintf(str, str_len, "%s", extracted_version);
		return;
	}
	if (iwdev->netdev->ethtool_ops && iwdev->netdev->ethtool_ops->get_drvinfo)
		iwdev->netdev->ethtool_ops->get_drvinfo(iwdev->netdev, &info);
	extract_version(info.fw_version, extracted_version);
	snprintf(str, str_len, "%s", extracted_version);
}
#endif /* IB_FW_VERSION_NAME_MAX */

/**
 * zxdh_alloc_mr - register stag for fast memory registration
 * @pd: ibpd pointer
 * @mr_type: memory for stag registrion
 * @max_num_sg: man number of pages
 */
struct ib_mr *zxdh_alloc_mr(struct ib_pd *pd, enum ib_mr_type mr_type, u32 max_num_sg)
{
	struct zxdh_device *iwdev = to_iwdev(pd->device);
	struct zxdh_pble_alloc *palloc;
	struct zxdh_pbl *iwpbl;
	struct zxdh_mr *iwmr;
	int status;
	u32 stag;
	int err_code = -ENOMEM;

	iwmr = kzalloc(sizeof(*iwmr), GFP_KERNEL);
	if (!iwmr)
		return ERR_PTR(-ENOMEM);

	stag = zxdh_create_stag(iwdev);
	if (!stag) {
		err_code = -ENOMEM;
		goto err;
	}

	iwmr->stag = stag;
	iwmr->ibmr.rkey = stag;
	iwmr->ibmr.lkey = stag;
	iwmr->ibmr.pd = pd;
	iwmr->ibmr.device = pd->device;
	iwpbl = &iwmr->iwpbl;
	iwpbl->iwmr = iwmr;
	iwmr->type = ZXDH_MEMREG_TYPE_MEM;
	palloc = &iwpbl->pble_alloc;
	iwmr->page_cnt = max_num_sg;
	iwmr->sc_dev = &iwdev->rf->sc_dev;
	status = zxdh_get_pble(iwdev->rf->pble_mr_rsrc, palloc, iwmr->page_cnt, true);
	if (status)
		goto err_get_pble;

	err_code = zxdh_hw_alloc_stag(iwdev, iwmr);
	if (err_code)
		goto err_alloc_stag;

	iwpbl->pbl_allocated = true;

	return &iwmr->ibmr;
err_alloc_stag:
	zxdh_free_pble(iwdev->rf->pble_mr_rsrc, palloc);
err_get_pble:
	zxdh_free_stag(iwdev, stag);
err:
	kfree(iwmr);

	return ERR_PTR(err_code);
}

/**
 * zxdh_alloc_ucontext - Allocate the user context data structure
 * @uctx: context
 * @udata: user data
 *
 * This keeps track of all objects associated with a particular
 * user-mode client.
 */
int zxdh_alloc_ucontext(struct ib_ucontext *uctx, struct ib_udata *udata)
{
	struct ib_device *ibdev = uctx->device;
	struct zxdh_device *iwdev = to_iwdev(ibdev);
	struct zxdh_alloc_ucontext_req req;
	struct zxdh_alloc_ucontext_resp uresp = { 0 };
	struct zxdh_ucontext *ucontext = to_ucontext(uctx);
	struct zxdh_uk_attrs *uk_attrs;
	u64 sq_db_bar_off, cq_db_bar_off;
	struct zxdh_pci_f *rf = NULL;
	u64 srq_db_bar_off = 0;
	bool kernel_srq_use_l2d = false;

	if (ib_copy_from_udata(&req, udata, min(sizeof(req), udata->inlen)))
		return -EINVAL;

	rf = iwdev->rf;
	pr_debug(
		"%s[%d]: req.userspace_ver=%d rf=0x%llx srq_l2d_base_paddr=0x%llx srq_l2d_size=0x%x\n",
		__func__, __LINE__, req.userspace_ver, (u64)rf, rf->srq_l2d_base_paddr,
		rf->srq_l2d_size);
	if (rf->srq_l2d_base_paddr != 0 && rf->srq_l2d_size != 0) {
		kernel_srq_use_l2d = true;
		pr_debug("%s[%d]: srq use l2d mem. srq_l2d_base_paddr=0x%llx srq_l2d_size=0x%x\n",
			 __func__, __LINE__, rf->srq_l2d_base_paddr, rf->srq_l2d_size);
	}

	if (req.userspace_ver != ZXDH_CONTEXT_VER_V1 && req.userspace_ver != ZXDH_CONTEXT_VER_V2) {
		pr_err("%s[%d]: Invalid version  Detected version %d, should be %d or %d\n",
		       __func__, __LINE__, req.userspace_ver, (u32)ZXDH_CONTEXT_VER_V1,
		       (u32)ZXDH_CONTEXT_VER_V2);
		goto ver_error;
	} else if (req.userspace_ver == ZXDH_CONTEXT_VER_V2 && kernel_srq_use_l2d == true) {
		rf->rdma_srq_mem_type = USER_L2D_KERNEL_L2D;
		pr_debug("%s[%d]: srq use l2d mem!\n", __func__, __LINE__);
	} else if (req.userspace_ver == ZXDH_CONTEXT_VER_V2 && kernel_srq_use_l2d == false) {
		rf->rdma_srq_mem_type = USER_L2D_KERNEL_DDR;
		pr_debug(
			"%s[%d]: rdma kernel srq use ddr, but userspace driver not! userspace_ver=%d.\n",
			__func__, __LINE__, req.userspace_ver);
	} else if (req.userspace_ver == ZXDH_CONTEXT_VER_V1 && kernel_srq_use_l2d == true) {
		rf->rdma_srq_mem_type = USER_DDR_KERNEL_L2D;
		pr_debug(
			"%s[%d]: rdma kernel srq use l2d, but userspace driver not! userspace_ver=%d.\n",
			__func__, __LINE__, req.userspace_ver);
	} else if (req.userspace_ver == ZXDH_CONTEXT_VER_V1 && kernel_srq_use_l2d == false) {
		rf->rdma_srq_mem_type = USER_DDR_KERNEL_DDR;
		pr_debug("%s[%d]: srq use ddr mem!\n", __func__, __LINE__);
	}

	ucontext->iwdev = iwdev;
	ucontext->abi_ver = req.userspace_ver;

	uk_attrs = &rf->sc_dev.hw_attrs.uk_attrs;

	sq_db_bar_off = C_RDMA_TX_VHCA_PF_PAGE + rf->base_bar_offset;
	cq_db_bar_off = C_RDMA_RX_VHCA_PF_PAGE + rf->base_bar_offset;
	if (rf->rdma_srq_mem_type == USER_L2D_KERNEL_L2D)
		srq_db_bar_off = rf->rdma_ext_bar_offset;

	ucontext->sq_db_mmap_entry = zxdh_user_mmap_entry_insert(
		ucontext, sq_db_bar_off, ZXDH_MMAP_IO_NC, &uresp.sq_db_mmap_key);
	if (!ucontext->sq_db_mmap_entry)
		return -ENOMEM;

	ucontext->cq_db_mmap_entry = zxdh_user_mmap_entry_insert(
		ucontext, cq_db_bar_off, ZXDH_MMAP_IO_NC, &uresp.cq_db_mmap_key);
	if (!ucontext->cq_db_mmap_entry) {
		rdma_user_mmap_entry_remove(ucontext->sq_db_mmap_entry);
		return -ENOMEM;
	}

	if (rf->rdma_srq_mem_type == USER_L2D_KERNEL_L2D) {
		ucontext->srq_db_mmap_entry = zxdh_user_mmap_entry_insert(
			ucontext, srq_db_bar_off, ZXDH_MMAP_IO_NC, &uresp.srq_db_mmap_key);
		if (!ucontext->srq_db_mmap_entry) {
			rdma_user_mmap_entry_remove(ucontext->sq_db_mmap_entry);
			rdma_user_mmap_entry_remove(ucontext->cq_db_mmap_entry);
			pr_err("%s[%d]: srq_db_mmap_entry is NULL!\n", __func__, __LINE__);
			return -ENOMEM;
		}
	}

	uresp.kernel_ver = ZXDH_CONTEXT_VER_V1;
	uresp.hw_rev = uk_attrs->hw_rev;
	uresp.chip_rev = iwdev->rf->sc_dev.chip_version;
	uresp.rdma_tool_flags = ZXDH_QP_EXTEND_OP | ZXDH_CAPTURE | ZXDH_GET_HW_DATA |
				ZXDH_GET_HW_OBJECT_DATA | ZXDH_CHECK_HW_HEALTH |
				ZXDH_RDMA_TOOL_CFG_DEV_PARAM | ZXDH_RDMA_TOOL_READ_RAM;

	uresp.feature_flags = uk_attrs->feature_flags;
	uresp.max_hw_wq_frags = uk_attrs->max_hw_wq_frags;
	uresp.max_hw_read_sges = uk_attrs->max_hw_read_sges;
	uresp.max_hw_inline = uk_attrs->max_hw_inline;
	uresp.max_hw_srq_wr = uk_attrs->max_hw_srq_wr;
	uresp.max_hw_rq_quanta = uk_attrs->max_hw_rq_quanta;
	uresp.max_hw_srq_quanta = uk_attrs->max_hw_srq_quanta;
	uresp.max_hw_wq_quanta = uk_attrs->max_hw_wq_quanta;
	uresp.max_hw_sq_chunk = uk_attrs->max_hw_sq_chunk;
	uresp.max_hw_cq_size = uk_attrs->max_hw_cq_size;
	uresp.min_hw_cq_size = uk_attrs->min_hw_cq_size;
	uresp.db_addr_type = ZXDH_DB_ADDR_BAR;
	if (ib_copy_to_udata(udata, &uresp, min(sizeof(uresp), udata->outlen))) {
		rdma_user_mmap_entry_remove(ucontext->sq_db_mmap_entry);
		rdma_user_mmap_entry_remove(ucontext->cq_db_mmap_entry);
		if (rf->rdma_srq_mem_type == USER_L2D_KERNEL_L2D)
			rdma_user_mmap_entry_remove(ucontext->srq_db_mmap_entry);
		return -EFAULT;
	}

	INIT_LIST_HEAD(&ucontext->cq_reg_mem_list);
	spin_lock_init(&ucontext->cq_reg_mem_list_lock);
	INIT_LIST_HEAD(&ucontext->qp_reg_mem_list);
	spin_lock_init(&ucontext->qp_reg_mem_list_lock);
	INIT_LIST_HEAD(&ucontext->srq_reg_mem_list);
	spin_lock_init(&ucontext->srq_reg_mem_list_lock);

	return 0;

ver_error:
	return -EINVAL;
}

static void free_cap_mmap_entry(struct zxdh_cap_addr_info *cap_addr_info)
{
	if (cap_addr_info->entry_info.cap_mmap_entry != NULL) {
		pr_info("%s rdma_user_mmap_entry_remove!\n", __func__);
		rdma_user_mmap_entry_remove(cap_addr_info->entry_info.cap_mmap_entry);
		cap_addr_info->entry_info.cap_mmap_entry = NULL;
	}
}

static void zxdh_cap_data_free(struct zxdh_device *iwdev)
{
	int i;

	if (!iwdev)
		return;
	free_cap_mmap_entry(&iwdev->hw_data_cap.mp_cap);
	free_cap_mmap_entry(&iwdev->hw_data_cap.hw_object_mmap);

	for (i = 0; i < CAP_NODE_NUM; i++) {
		free_cap_mmap_entry(&iwdev->hw_data_cap.cap_tx_use_direct_dma[i]);
		free_cap_mmap_entry(&iwdev->hw_data_cap.cap_rx_use_direct_dma[i]);
		free_cap_mmap_entry(&iwdev->hw_data_cap.cap_txrx_use_iova[i]);
	}
}

/**
 * zxdh_dealloc_ucontext - deallocate the user context data structure
 * @context: user context created during alloc
 */
void zxdh_dealloc_ucontext(struct ib_ucontext *context)
{
	struct zxdh_ucontext *ucontext = to_ucontext(context);
	struct ib_device *ib_dev;
	struct zxdh_device *iwdev;

	ib_dev = context->device;
	if (!ib_dev)
		return;
	iwdev = to_iwdev(ib_dev);
	if (!iwdev)
		return;

	rdma_user_mmap_entry_remove(ucontext->sq_db_mmap_entry);
	rdma_user_mmap_entry_remove(ucontext->cq_db_mmap_entry);
	if (iwdev->rf->rdma_srq_mem_type == USER_L2D_KERNEL_L2D)
		rdma_user_mmap_entry_remove(ucontext->srq_db_mmap_entry);
	zxdh_cap_data_free(iwdev);
}

/**
 * zxdh_alloc_pd - allocate protection domain
 * @pd: protection domain
 * @udata: user data
 */
int zxdh_alloc_pd(struct ib_pd *pd, struct ib_udata *udata)
{
	struct zxdh_pd *iwpd = to_iwpd(pd);
	struct zxdh_device *iwdev = to_iwdev(pd->device);
	struct zxdh_sc_dev *dev = &iwdev->rf->sc_dev;
	struct zxdh_pci_f *rf = iwdev->rf;
	struct zxdh_alloc_pd_resp uresp = {};
	struct zxdh_sc_pd *sc_pd;
	u32 pd_id = 0;
	int err;

	err = zxdh_alloc_rsrc(rf, rf->allocated_pds, rf->max_pd, &pd_id, &rf->next_pd);
	if (err)
		return err;

	sc_pd = &iwpd->sc_pd;
	if (udata) {
		struct zxdh_ucontext *ucontext =
			rdma_udata_to_drv_context(udata, struct zxdh_ucontext, ibucontext);

		zxdh_sc_pd_init(dev, sc_pd, pd_id, ucontext->abi_ver);
		uresp.pd_id = pd_id;
		if (ib_copy_to_udata(udata, &uresp, min(sizeof(uresp), udata->outlen))) {
			err = -EFAULT;
			goto error;
		}
	} else {
		zxdh_sc_pd_init(dev, sc_pd, pd_id, ZXDH_ABI_VER);
	}

	return 0;

error:

	zxdh_free_rsrc(rf, rf->allocated_pds, pd_id);

	return err;
}

int zxdh_dealloc_pd(struct ib_pd *ibpd, struct ib_udata *udata)
{
	struct zxdh_pd *iwpd = to_iwpd(ibpd);
	struct zxdh_device *iwdev = to_iwdev(ibpd->device);

	zxdh_free_rsrc(iwdev->rf, iwdev->rf->allocated_pds, iwpd->sc_pd.pd_id);
	return 0;
}

static void zxdh_fill_ah_info(struct zxdh_ah_info *ah_info, const struct ib_gid_attr *sgid_attr,
			      struct sockaddr *sgid_addr, struct sockaddr *dgid_addr, u8 net_type)
{
	if (net_type == RDMA_NETWORK_IPV4) {
		ah_info->ipv4_valid = true;
		ah_info->dest_ip_addr[0] =
			ntohl(((struct sockaddr_in *)dgid_addr)->sin_addr.s_addr);
		ah_info->src_ip_addr[0] = ntohl(((struct sockaddr_in *)sgid_addr)->sin_addr.s_addr);
		ah_info->do_lpbk =
			zxdh_ipv4_is_lpb(ah_info->src_ip_addr[0], ah_info->dest_ip_addr[0]);
		if (ipv4_is_multicast(((struct sockaddr_in *)dgid_addr)->sin_addr.s_addr))
			zxdh_mcast_mac_v4(ah_info->dest_ip_addr, ah_info->dmac);
	} else {
		zxdh_copy_ip_ntohl(ah_info->dest_ip_addr,
				   ((struct sockaddr_in6 *)dgid_addr)->sin6_addr.in6_u.u6_addr32);
		zxdh_copy_ip_ntohl(ah_info->src_ip_addr,
				   ((struct sockaddr_in6 *)sgid_addr)->sin6_addr.in6_u.u6_addr32);
		ah_info->do_lpbk = zxdh_ipv6_is_lpb(ah_info->src_ip_addr, ah_info->dest_ip_addr);
		if (rdma_is_multicast_addr(&((struct sockaddr_in6 *)dgid_addr)->sin6_addr))
			zxdh_mcast_mac_v6(ah_info->dest_ip_addr, ah_info->dmac);
	}
}

static int zxdh_create_ah_vlan_tag(struct zxdh_device *iwdev, struct zxdh_ah_info *ah_info,
				   const struct ib_gid_attr *sgid_attr)
{
	if (ah_info->vlan_tag >= VLAN_N_VID && iwdev->dcb_vlan_mode)
		ah_info->vlan_tag = 0;

	if (ah_info->vlan_tag < VLAN_N_VID) {
		ah_info->insert_vlan_tag = true;
		ah_info->vlan_tag |= rt_tos2priority(ah_info->tc_tos) << VLAN_PRIO_SHIFT;
	}
	return 0;
}

static int zxdh_create_ah_wait(struct zxdh_pci_f *rf, struct zxdh_sc_ah *sc_ah, bool sleep)
{
	if (!sleep) {
		int cnt = rf->sc_dev.hw_attrs.max_cqp_compl_wait_time_ms *
			  rf->sc_dev.hw_attrs.cqp_timeout_threshold;

		do {
			zxdh_cqp_ce_handler(rf, &rf->ccq.sc_cq);
			udelay(20);
		} while (!sc_ah->ah_info.ah_valid && --cnt);
		if (sc_ah->ah_info.ah_valid)
			mdelay(1);
		if (!cnt)
			return -ETIMEDOUT;
	}
	return 0;
}

#ifndef CREATE_AH_VER_0
static bool zxdh_ah_exists(struct zxdh_device *iwdev, struct zxdh_ah *new_ah)
{
	struct zxdh_ah *ah;
	u32 save_ah_id = new_ah->sc_ah.ah_info.ah_idx;

	list_for_each_entry(ah, &iwdev->ah_list, list) {
		/* Set ah_id the same so memcp can work */
		new_ah->sc_ah.ah_info.ah_idx = ah->sc_ah.ah_info.ah_idx;
		if (!memcmp(&ah->sc_ah.ah_info, &new_ah->sc_ah.ah_info,
			    sizeof(ah->sc_ah.ah_info))) {
			refcount_inc(&ah->refcnt);
			new_ah->parent_ah = ah;
			return true;
		}
	}
	new_ah->sc_ah.ah_info.ah_idx = save_ah_id;
	/* Add new AH to list */
	if (iwdev->ah_list_cnt >= ZXDH_MAX_AH_LIST)
		return false;
	ah = kmemdup(new_ah, sizeof(*new_ah), GFP_KERNEL);
	if (!ah)
		return false;
	new_ah->parent_ah = ah;
	list_add(&ah->list, &iwdev->ah_list);
	iwdev->ah_list_cnt++;
	if (iwdev->ah_list_cnt > iwdev->ah_list_hwm)
		iwdev->ah_list_hwm = iwdev->ah_list_cnt;
	refcount_set(&ah->refcnt, 1);

	return false;
}
#endif

int zxdh_create_ah_v2(struct ib_ah *ib_ah, struct rdma_ah_attr *attr, u32 flags,
		      struct ib_udata *udata)
{
	struct zxdh_pd *pd = to_iwpd(ib_ah->pd);
	struct zxdh_ah *ah = container_of(ib_ah, struct zxdh_ah, ibah);
	struct zxdh_device *iwdev = to_iwdev(ib_ah->pd->device);
	const struct ib_gid_attr *sgid_attr;
	struct zxdh_pci_f *rf = iwdev->rf;
	struct zxdh_sc_ah *sc_ah;
	u32 ah_id = 0;
	struct zxdh_ah_info *ah_info;
	struct zxdh_create_ah_resp uresp = {};
	union {
		struct sockaddr saddr;
		struct sockaddr_in saddr_in;
		struct sockaddr_in6 saddr_in6;
	} sgid_addr, dgid_addr;
	int err;
	bool sleep = flags & RDMA_CREATE_AH_SLEEPABLE;

	err = zxdh_alloc_rsrc(rf, rf->allocated_ahs, rf->max_ah, &ah_id, &rf->next_ah);

	if (err)
		return err;

	ah->pd = pd;
	sc_ah = &ah->sc_ah;
	sc_ah->ah_info.ah_idx = ah_id;
	sc_ah->ah_info.vsi = &iwdev->vsi;
	zxdh_sc_init_ah(&rf->sc_dev, sc_ah);
	ah->sgid_index = attr->grh.sgid_index;
	memcpy(&ah->dgid, &attr->grh.dgid, sizeof(ah->dgid));
	sgid_attr = attr->grh.sgid_attr;

	rdma_gid2ip((struct sockaddr *)&sgid_addr, &sgid_attr->gid);
	rdma_gid2ip((struct sockaddr *)&dgid_addr, &attr->grh.dgid);
	ah->av.attrs = *attr;
	ah->av.net_type = rdma_gid_attr_network_type(sgid_attr);

	ah->av.sgid_addr.saddr = sgid_addr.saddr;
	ah->av.dgid_addr.saddr = dgid_addr.saddr;
	ah_info = &sc_ah->ah_info;
	ah_info->ah_idx = ah_id;
	ah_info->pd_idx = pd->sc_pd.pd_id;
	err = rdma_read_gid_l2_fields(sgid_attr, &ah_info->vlan_tag, ah_info->mac_addr);

	if (err)
		goto err_gid_l2;

	if (attr->ah_flags & IB_AH_GRH) {
		ah_info->flow_label = attr->grh.flow_label;
		ah_info->hop_ttl = attr->grh.hop_limit;
		ah_info->tc_tos = attr->grh.traffic_class;
	}

	ether_addr_copy(ah_info->dmac, attr->roce.dmac);

	zxdh_fill_ah_info(ah_info, sgid_attr, &sgid_addr.saddr, &dgid_addr.saddr, ah->av.net_type);

	zxdh_create_ah_vlan_tag(iwdev, ah_info, sgid_attr);

	if (sleep) {
		mutex_lock(&iwdev->ah_list_lock);
		if (zxdh_ah_exists(iwdev, ah)) {
			zxdh_free_rsrc(iwdev->rf, iwdev->rf->allocated_ahs, ah_id);
			ah_id = 0;

			goto exit;
		}
	}

	err = zxdh_ah_cqp_op(iwdev->rf, sc_ah, ZXDH_OP_AH_CREATE, sleep, zxdh_gsi_ud_qp_ah_cb,
			     sc_ah);
	if (err) {
		zxdh_dbg(iwdev_to_idev(iwdev), "VERBS: CQP-OP Create AH fail");
		goto err_ah_create;
	}

	err = zxdh_create_ah_wait(rf, sc_ah, sleep);
	if (err) {
		zxdh_dbg(iwdev_to_idev(iwdev), "VERBS: CQP create AH timed out");
		goto err_gid_l2;
	}

exit:
	if (udata) {
		uresp.ah_id = ah->sc_ah.ah_info.ah_idx;
		err = ib_copy_to_udata(udata, &uresp, sizeof(uresp));
		if (err) {
			if (!ah->parent_ah ||
			    (ah->parent_ah && refcount_dec_and_test(&ah->parent_ah->refcnt))) {
				zxdh_ah_cqp_op(iwdev->rf, &ah->sc_ah, ZXDH_OP_AH_DESTROY, false,
					       NULL, ah);
				ah_id = ah->sc_ah.ah_info.ah_idx;
				goto err_ah_create;
			}
			goto err_unlock;
		}
	}
	if (sleep)
		mutex_unlock(&iwdev->ah_list_lock);

	return 0;
err_ah_create:
	if (ah->parent_ah) {
		list_del(&ah->parent_ah->list);
		kfree(ah->parent_ah);
		iwdev->ah_list_cnt--;
	}
err_unlock:
	if (sleep)
		mutex_unlock(&iwdev->ah_list_lock);
err_gid_l2:
	if (ah_id)
		zxdh_free_rsrc(iwdev->rf, iwdev->rf->allocated_ahs, ah_id);

	return err;
}

/**
 * zxdh_create_ah - create address handle
 * @ibah: ptr to AH
 * @init_attr: address handle attributes
 * @udata: user data
 *
 * returns a pointer to an address handle
 */
int zxdh_create_ah(struct ib_ah *ibah, struct rdma_ah_init_attr *init_attr, struct ib_udata *udata)
{
	return zxdh_create_ah_v2(ibah, init_attr->ah_attr, init_attr->flags, udata);
}

static void zxdh_store_free_qp(struct zxdh_pci_f *rf, u32 qp_num)
{
	unsigned long flags;

	if ((qp_num == 0) || (qp_num >= rf->max_qp))
		return;
	spin_lock_irqsave(&rf->rsrc_lock, flags);
	rf->qp_buf[rf->qp_index] = qp_num;
	rf->qp_index++;
	rf->qp_index %= ZXDH_RDMA_QP_BUF_LEN;
	spin_unlock_irqrestore(&rf->rsrc_lock, flags);
}

/**
 * zxdh_free_qp_rsrc - free up memory resources for qp
 * @iwqp: qp ptr (user or kernel)
 */
void zxdh_free_qp_rsrc(struct zxdh_qp *iwqp)
{
	struct zxdh_device *iwdev = iwqp->iwdev;
	struct zxdh_pci_f *rf = iwdev->rf;
	int qp_index;

	if (iwqp->ibqp.qp_num <= 1)
		qp_index = iwqp->ibqp.qp_num;
	else
		qp_index = iwqp->ibqp.qp_num - rf->sc_dev.base_qpn;

	if (qp_index > 0 && qp_index < rf->max_qp) {
		if (iwqp->sc_qp.dev)
			zxdh_qp_rem_qos(&iwqp->sc_qp);
		zxdh_free_rsrc(rf, rf->allocated_qps, qp_index);
		if (!iwqp->user_mode) {
			dma_free_coherent(rf->sc_dev.hw->device, iwqp->kqp.dma_mem.size,
					  iwqp->kqp.dma_mem.va, iwqp->kqp.dma_mem.pa);
			iwqp->kqp.dma_mem.va = NULL;
			kfree(iwqp->kqp.sq_wrid_mem);
			kfree(iwqp->kqp.rq_wrid_mem);
		}
	}

	if (iwqp->host_ctx.va) {
		dma_free_coherent(rf->sc_dev.hw->device, iwqp->host_ctx.size, iwqp->host_ctx.va,
				  iwqp->host_ctx.pa);
		iwqp->host_ctx.va = NULL;
	}
	kfree(iwqp->sg_list);
}

/**
 * zxdh_create_qp - create qp
 * @ibqp: ptr of qp
 * @init_attr: attributes for qp
 * @udata: user data for create qp
 */
int zxdh_create_qp(struct ib_qp *ibqp, struct ib_qp_init_attr *init_attr, struct ib_udata *udata)
{
	struct ib_pd *ibpd = ibqp->pd;
	struct zxdh_pd *iwpd = to_iwpd(ibpd);
	struct zxdh_device *iwdev = to_iwdev(ibpd->device);
	struct zxdh_pci_f *rf = iwdev->rf;
	struct zxdh_qp *iwqp = to_iwqp(ibqp);
	struct zxdh_create_qp_req req;
	struct zxdh_create_qp_resp uresp = {};
	u32 qp_num = 0;
	u32 qp_ctx_num = 0;
	u8 qp_ret;
	int ret;
	int err_code;
	int sq_size;
	int rq_size;
	struct zxdh_srq *iwsrq;
	struct zxdh_sc_qp *qp;
	struct zxdh_sc_dev *dev = &rf->sc_dev;
	struct zxdh_uk_attrs *uk_attrs = &dev->hw_attrs.uk_attrs;
	struct zxdh_qp_init_info init_info = {};
	struct zxdh_qp_host_ctx_info *ctx_info;
	unsigned long flags;

	err_code = zxdh_validate_qp_attrs(init_attr, iwdev);
	if (err_code)
		return err_code;

	sq_size = init_attr->cap.max_send_wr;
	rq_size = init_attr->cap.max_recv_wr;
#ifdef Z_CONFIG_RDMA_VSI
	init_info.vsi = &iwdev->vsi;
#endif
	init_info.dev = dev;
	init_info.qp_uk_init_info.uk_attrs = uk_attrs;
	init_info.qp_uk_init_info.sq_size = sq_size;
	init_info.qp_uk_init_info.rq_size = rq_size;
	init_info.qp_uk_init_info.max_sq_frag_cnt = init_attr->cap.max_send_sge;
	init_info.qp_uk_init_info.max_rq_frag_cnt = init_attr->cap.max_recv_sge;
	init_info.qp_uk_init_info.max_inline_data = init_attr->cap.max_inline_data;

	qp = &iwqp->sc_qp;
	qp->dev = NULL;
	qp->qp_uk.back_qp = iwqp;
	qp->qp_uk.lock = &iwqp->lock;

	iwqp->is_srq = false;
	if (init_attr->srq != NULL) {
		iwqp->is_srq = true;
		iwsrq = to_iwsrq(init_attr->srq);
		iwqp->iwsrq = iwsrq;
		iwqp->sc_qp.srq = &iwsrq->sc_srq;
	}
	qp->is_srq = iwqp->is_srq;

	iwqp->sg_list = kcalloc(uk_attrs->max_hw_wq_frags, sizeof(*iwqp->sg_list), GFP_KERNEL);
	if (!iwqp->sg_list)
		return -ENOMEM;

	iwqp->iwdev = iwdev;
	iwqp->host_ctx.va = NULL;
	iwqp->host_ctx.size = ALIGN(ZXDH_QP_CTX_SIZE, ZXDH_QPC_ALIGNMENT);
	iwqp->host_ctx.va = dma_alloc_coherent(dev->hw->device, iwqp->host_ctx.size,
					       &iwqp->host_ctx.pa, GFP_KERNEL);
	if (!iwqp->host_ctx.va) {
		kfree(iwqp->sg_list);
		return -ENOMEM;
	}

	init_info.host_ctx = iwqp->host_ctx.va;
	init_info.host_ctx_pa = iwqp->host_ctx.pa;

	err_code = zxdh_alloc_rsrc_qp(rf, rf->allocated_qps, rf->max_qp, &qp_ctx_num, &rf->next_qp,
				      &qp_ret);
	if (err_code)
		goto error;
	qp_ctx_num += dev->base_qpn;
	if (init_attr->qp_type == IB_QPT_GSI)
		qp_num = 1;
	else
		qp_num = qp_ctx_num;

	iwqp->iwpd = iwpd;
	iwqp->ibqp.qp_num = qp_num;
	qp = &iwqp->sc_qp;
	iwqp->sc_qp.qp_ctx_num = qp_ctx_num;
	iwqp->iwscq = to_iwcq(init_attr->send_cq);
	iwqp->iwrcq = to_iwcq(init_attr->recv_cq);

	init_info.pd = &iwpd->sc_pd;
	init_info.qp_uk_init_info.qp_id = iwqp->ibqp.qp_num;
	iwqp->ctx_info.qp_compl_ctx = (uintptr_t)qp;
	init_waitqueue_head(&iwqp->mod_qp_waitq);

	if (udata) {
		err_code = ib_copy_from_udata(&req, udata, min(sizeof(req), udata->inlen));
		if (err_code) {
			zxdh_dbg(iwdev_to_idev(iwdev), "VERBS: ib_copy_from_data fail\n");
			goto error;
		}

		iwqp->ctx_info.qp_compl_ctx = req.user_compl_ctx;
		iwqp->user_mode = 1;
		if (req.user_wqe_bufs) {
			struct zxdh_ucontext *ucontext =
				rdma_udata_to_drv_context(udata, struct zxdh_ucontext, ibucontext);

			init_info.qp_uk_init_info.legacy_mode = ucontext->legacy_mode;
			spin_lock_irqsave(&ucontext->qp_reg_mem_list_lock, flags);
			iwqp->iwpbl = zxdh_get_pbl((unsigned long)req.user_wqe_bufs,
						   &ucontext->qp_reg_mem_list);
			spin_unlock_irqrestore(&ucontext->qp_reg_mem_list_lock, flags);

			if (!iwqp->iwpbl) {
				err_code = -ENODATA;
				zxdh_dbg(iwdev_to_idev(iwdev), "VERBS: no pbl info\n");
				goto error;
			}
		}
		init_info.qp_uk_init_info.abi_ver = iwpd->sc_pd.abi_ver;
		zxdh_setup_virt_qp(iwdev, iwqp, &init_info);
	} else {
		INIT_DELAYED_WORK(&iwqp->dwork_flush, zxdh_flush_worker);
		init_info.qp_uk_init_info.abi_ver = ZXDH_ABI_VER;
		err_code = zxdh_setup_kmode_qp(iwdev, iwqp, &init_info, init_attr);
	}

	if (err_code) {
		zxdh_dbg(iwdev_to_idev(iwdev), "VERBS: setup qp failed\n");
		goto error;
	}

	if (init_attr->qp_type == IB_QPT_RC) {
		init_info.qp_uk_init_info.type = ZXDH_QP_TYPE_ROCE_RC;
		init_info.qp_uk_init_info.qp_caps = ZXDH_SEND_WITH_IMM | ZXDH_WRITE_WITH_IMM |
						    ZXDH_ROCE;
	} else {
		init_info.qp_uk_init_info.type = ZXDH_QP_TYPE_ROCE_UD;
		init_info.qp_uk_init_info.qp_caps = ZXDH_SEND_WITH_IMM | ZXDH_ROCE;
	}

	ret = zxdh_sc_qp_init(qp, &init_info);
	if (ret) {
		err_code = -EPROTO;
		zxdh_dbg(iwdev_to_idev(iwdev), "VERBS: qp_init fail\n");
		goto error;
	}

	ctx_info = &iwqp->ctx_info;
	ctx_info->send_cq_num = iwqp->iwscq->sc_cq.cq_uk.cq_id;
	ctx_info->rcv_cq_num = iwqp->iwrcq->sc_cq.cq_uk.cq_id;

	if (iwqp->is_srq == true)
		ctx_info->use_srq = true;
	else
		ctx_info->use_srq = false;

	zxdh_roce_fill_and_set_qpctx_info(iwqp, ctx_info);
	if (qp_ret == ZXDH_RDMA_QP_EXIST)
		mdelay(2);
	err_code = zxdh_cqp_create_qp_cmd(iwqp);
	if (err_code)
		goto error;

	refcount_set(&iwqp->refcnt, 1);
	spin_lock_init(&iwqp->lock);
	spin_lock_init(&iwqp->sc_qp.pfpdu.lock);
	iwqp->sig_all = (init_attr->sq_sig_type == IB_SIGNAL_ALL_WR) ? 1 : 0;
	rf->qp_table[qp_ctx_num - dev->base_qpn] = iwqp;
	iwqp->max_send_wr = sq_size;
	iwqp->max_recv_wr = rq_size;

	zxdh_qp_add_qos(&iwqp->sc_qp);

	if (udata) {
		uresp.lsmm = 1;
		uresp.actual_sq_size = sq_size;
		uresp.actual_rq_size = rq_size;
		uresp.qp_id = qp_num;
		uresp.qp_caps = qp->qp_uk.qp_caps;

		err_code = ib_copy_to_udata(udata, &uresp, min(sizeof(uresp), udata->outlen));
		if (err_code) {
			zxdh_dbg(iwdev_to_idev(iwdev), "VERBS: copy_to_udata failed\n");
			zxdh_destroy_qp(&iwqp->ibqp, udata);
			return err_code;
		}
	}
	if (refcount_read(&iwdev->trace_switch.t_switch)) {
		ibdev_notice(
			&iwdev->ibdev,
			"create new QP, type %d, ib qpn 0x%X, max_send_wr %d, max_recv_wr %d\n",
			iwqp->ibqp.qp_type, iwqp->ibqp.qp_num, iwqp->max_send_wr,
			iwqp->max_recv_wr);
	}
	init_completion(&iwqp->free_qp);
	if (init_attr->qp_type == IB_QPT_GSI)
		iwdev->qp1 = iwqp;
	return 0;

error:
	zxdh_free_qp_rsrc(iwqp);

	return err_code;
}

/**
 * zxdh_destroy_qp - destroy qp
 * @ibqp: qp's ib pointer also to get to device's qp address
 * @udata: user data
 */
int zxdh_destroy_qp(struct ib_qp *ibqp, struct ib_udata *udata)
{
	struct zxdh_qp *iwqp = to_iwqp(ibqp);
	struct zxdh_device *iwdev = iwqp->iwdev;
	u32 qp_index;
	struct iidc_core_dev_info *cdev_info = (struct iidc_core_dev_info *)iwdev->rf->cdev;
	struct zxdh_av *av = &iwqp->roce_ah.av;
	struct zxdh_udp_offload_info *udp_info = &iwqp->udp_info;
	char s_straddr[INET6_ADDRSTRLEN + 20] = { 0 };
	char d_straddr[INET6_ADDRSTRLEN + 20] = { 0 };
	u32 dual_tor_switch = 0xFFFF;
	int ret = 0;

	if (iwqp->sc_qp.qp_uk.destroy_pending)
		goto free_rsrc;
	iwqp->sc_qp.qp_uk.destroy_pending = true;

	zxdh_modify_qp_to_err(&iwqp->sc_qp);

	dual_tor_switch = readl(cdev_info->hw_addr + ZXDH_DUAL_TOR_SWITCH_OFFSET);
	pr_debug("%s[%d]: qp_type=%d, hw_addr=0x%llx, dual_tor_switch=0x%x\n", __func__, __LINE__,
		 iwqp->sc_qp.qp_uk.qp_type, (u64)(uintptr_t)cdev_info->hw_addr, dual_tor_switch);
	if (remote_ip_update_hook && (dual_tor_switch == ZXDH_DUAL_TOR_SWITCH_OPEN) &&
	    (iwqp->sc_qp.qp_uk.qp_type == ZXDH_QP_TYPE_ROCE_RC)) {
		if (av->sgid_addr.saddr.sa_family == AF_INET6) {
			scnprintf(s_straddr, sizeof(s_straddr), ", src_ip: %pI6", &av->sgid_addr.saddr_in6.sin6_addr);
			scnprintf(d_straddr, sizeof(d_straddr), ", dest_ip: %pI6", &av->dgid_addr.saddr_in6.sin6_addr);
		} else {
			scnprintf(s_straddr, sizeof(s_straddr), ", src_ip: %pI4", &av->sgid_addr.saddr_in.sin_addr);
			scnprintf(d_straddr, sizeof(d_straddr), ", dest_ip: %pI4", &av->dgid_addr.saddr_in.sin_addr);
		}
		ret = qp_remote_ip_info_process(ibqp, RDMA_DEL_REMOTE_IP);
		if (ret) {
			pr_err("%s[%d]:ipv4=%d,name=%s,op_type=%d,sport=0x%x,dport=0x%x,saddr=%s,daddr=%s\n",
			       __func__, __LINE__, udp_info->ipv4, iwdev->netdev->name,
			       RDMA_DEL_REMOTE_IP, udp_info->src_port, udp_info->dst_port,
			       s_straddr, d_straddr);
			pr_err("%s[%d]:src_ip=0x%x-0x%x-0x%x-0x%x, dst_ip=0x%x-0x%x-0x%x-0x%x\n",
			       __func__, __LINE__, udp_info->local_ipaddr[0],
			       udp_info->local_ipaddr[1], udp_info->local_ipaddr[2],
			       udp_info->local_ipaddr[3], udp_info->dest_ip_addr[0],
			       udp_info->dest_ip_addr[1], udp_info->dest_ip_addr[2],
			       udp_info->dest_ip_addr[3]);
		} else {
			pr_debug(
				"%s[%d]: ipv4=%d,name=%s,op_type=%d,sport=0x%x,dport=0x%x,saddr=%s,daddr=%s\n",
				__func__, __LINE__, udp_info->ipv4, iwdev->netdev->name,
				RDMA_DEL_REMOTE_IP, udp_info->src_port, udp_info->dst_port,
				s_straddr, d_straddr);
			pr_debug("%s[%d]:src_ip=0x%x-0x%x-0x%x-0x%x, dst_ip=0x%x-0x%x-0x%x-0x%x\n",
				 __func__, __LINE__, udp_info->local_ipaddr[0],
				 udp_info->local_ipaddr[1], udp_info->local_ipaddr[2],
				 udp_info->local_ipaddr[3], udp_info->dest_ip_addr[0],
				 udp_info->dest_ip_addr[1], udp_info->dest_ip_addr[2],
				 udp_info->dest_ip_addr[3]);
		}
	}

	if (!iwqp->user_mode)
		cancel_delayed_work_sync(&iwqp->dwork_flush);

	zxdh_qp_rem_ref(&iwqp->ibqp);
	wait_for_completion(&iwqp->free_qp);

	zxdh_sc_qp_resetctx_roce(&iwqp->sc_qp, iwqp->host_ctx.va);

	if (!iwdev->rf->reset && zxdh_cqp_qp_destroy_cmd(&iwdev->rf->sc_dev, &iwqp->sc_qp))
		return iwqp->user_mode ? -ENOTRECOVERABLE : 0;
free_rsrc:
	if (!iwqp->user_mode) {
		if (iwqp->iwscq) {
			zxdh_clean_cqes(iwqp, iwqp->iwscq);
			if (iwqp->iwrcq != iwqp->iwscq)
				zxdh_clean_cqes(iwqp, iwqp->iwrcq);
		}
	}
	if (refcount_read(&iwdev->trace_switch.t_switch)) {
		ibdev_notice(&iwdev->ibdev,
			     "destroy QP, type %d, ib qpn 0x%X, max_send_wr %d, max_recv_wr %d\n",
			     iwqp->ibqp.qp_type, iwqp->ibqp.qp_num, iwqp->max_send_wr,
			     iwqp->max_recv_wr);
	}
	if (iwqp->ibqp.qp_num <= 1)
		qp_index = iwqp->ibqp.qp_num;
	else
		qp_index = iwqp->ibqp.qp_num - iwdev->rf->sc_dev.base_qpn;
	zxdh_store_free_qp(iwdev->rf, qp_index);
	zxdh_free_qp_rsrc(iwqp);
	return 0;
}

/**
 * zxdh_cq_round_up - return round up cq wq depth
 * @wqdepth: wq depth in quanta to round up
 */
int zxdh_cq_round_up(u32 wqdepth)
{
	int scount = 1;

	for (wqdepth--; scount <= 16; scount *= 2)
		wqdepth |= wqdepth >> scount;

	return ++wqdepth;
}

int zxdh_create_cq(struct ib_cq *ibcq, const struct ib_cq_init_attr *attr, struct ib_udata *udata)
{
	struct ib_device *ibdev = ibcq->device;
	struct zxdh_device *iwdev = to_iwdev(ibdev);
	struct zxdh_pci_f *rf = iwdev->rf;
	struct zxdh_cq *iwcq = to_iwcq(ibcq);
	u32 cq_num = 0;
	struct zxdh_sc_cq *cq;
	struct zxdh_sc_dev *dev = &rf->sc_dev;
	struct zxdh_cq_init_info info = {};
	int status;
	struct zxdh_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	struct zxdh_cq_uk_init_info *ukinfo = &info.cq_uk_init_info;
	unsigned long flags;
	int err_code;
	int entries = attr->cqe;

	if (attr->cqe < ZXDH_MIN_CQ_SIZE || attr->cqe > ZXDH_MAX_CQ_SIZE) {
		err_code = -ENOMEM;
		goto cq_free_rsrc;
	}

	err_code = cq_validate_flags(attr->flags, dev->hw_attrs.uk_attrs.hw_rev);
	if (err_code)
		return err_code;

	err_code = zxdh_alloc_rsrc(rf, rf->allocated_cqs, rf->max_cq, &cq_num, &rf->next_cq);
	if (err_code)
		return err_code;

	cq_num += dev->base_cqn;
	cq = &iwcq->sc_cq;
	cq->back_cq = iwcq;
	iwcq->cq_num = cq_num;
	refcount_set(&iwcq->refcnt, 1);
	spin_lock_init(&iwcq->lock);
	INIT_LIST_HEAD(&iwcq->resize_list);
	INIT_LIST_HEAD(&iwcq->cmpl_generated);
	info.dev = dev;
	ukinfo->cq_size = max(entries, 4); /* Depth of CQ */
	ukinfo->cq_size = zxdh_cq_round_up(ukinfo->cq_size);
	ukinfo->cq_id = cq_num;
	ukinfo->cqe_size = ZXDH_CQE_SIZE_64;
	ukinfo->cq_log_size = zxdh_num_to_log(ukinfo->cq_size);
	iwcq->ibcq.cqe = info.cq_uk_init_info.cq_size;
	info.ceq_id = dev->base_ceqn + 1;
	info.ceq_index = 1;
	if (attr->comp_vector < rf->ceqs_count) {
		if (attr->comp_vector == 0) {
			info.ceq_id = dev->base_ceqn + 1;
		} else {
			info.ceq_id = dev->base_ceqn +
				      attr->comp_vector; /* attr->comp_vector default value is 0 */
			info.ceq_index = attr->comp_vector;
		}
	}
	info.ceq_id_valid = true;
	info.ceqe_mask = 1;
	info.type = ZXDH_CQ_TYPE_IO;

	if (udata) {
		struct zxdh_ucontext *ucontext;
		struct zxdh_create_cq_req req = {};
		struct zxdh_cq_mr *cqmr;
		struct zxdh_pbl *iwpbl;
		struct zxdh_pbl *iwpbl_shadow;
		struct zxdh_cq_mr *cqmr_shadow;

		iwcq->user_mode = true;
		ucontext = rdma_udata_to_drv_context(udata, struct zxdh_ucontext, ibucontext);
		if (ib_copy_from_udata(&req, udata, min(sizeof(req), udata->inlen))) {
			err_code = -EFAULT;
			goto cq_free_rsrc;
		}

		spin_lock_irqsave(&ucontext->cq_reg_mem_list_lock, flags);
		iwpbl = zxdh_get_pbl((unsigned long)req.user_cq_buf, &ucontext->cq_reg_mem_list);
		spin_unlock_irqrestore(&ucontext->cq_reg_mem_list_lock, flags);
		if (!iwpbl) {
			err_code = -EPROTO;
			goto cq_free_rsrc;
		}
		iwcq->iwpbl = iwpbl;
		iwcq->cq_mem_size = 0;
		cqmr = &iwpbl->cq_mr;

		if (rf->sc_dev.hw_attrs.uk_attrs.feature_flags & ZXDH_FEATURE_CQ_RESIZE &&
		    !ucontext->legacy_mode) {
			spin_lock_irqsave(&ucontext->cq_reg_mem_list_lock, flags);
			iwpbl_shadow = zxdh_get_pbl((unsigned long)req.user_shadow_area,
						    &ucontext->cq_reg_mem_list);
			spin_unlock_irqrestore(&ucontext->cq_reg_mem_list_lock, flags);

			if (!iwpbl_shadow) {
				err_code = -EPROTO;
				goto cq_free_rsrc;
			}
			iwcq->iwpbl_shadow = iwpbl_shadow;
			cqmr_shadow = &iwpbl_shadow->cq_mr;
			info.shadow_area_pa = cqmr_shadow->cq_pbl.addr;
			cqmr->split = true;
		} else {
			info.shadow_area_pa = cqmr->shadow;
		}
		if (iwpbl->pbl_allocated) {
			info.virtual_map = true;
			info.pbl_chunk_size = 1;
			info.first_pm_pbl_idx = cqmr->cq_pbl.idx;
		} else {
			info.cq_base_pa = cqmr->cq_pbl.addr;
		}
	} else {
		/* Kmode allocations */
		int rsize;

		if (entries < 1 || entries > rf->max_cqe) {
			err_code = -EINVAL;
			goto cq_free_rsrc;
		}

		entries++;
		ukinfo->cq_size = zxdh_cq_round_up(entries);
		ukinfo->cq_log_size = zxdh_num_to_log(ukinfo->cq_size);

		rsize = info.cq_uk_init_info.cq_size * sizeof(struct zxdh_extended_cqe);

		iwcq->kmem.size = ALIGN(round_up(rsize, ZXDH_HW_PAGE_SIZE), ZXDH_HW_PAGE_SIZE);
		iwcq->kmem.va = dma_alloc_coherent(dev->hw->device, iwcq->kmem.size, &iwcq->kmem.pa,
						   GFP_KERNEL);
		if (!iwcq->kmem.va) {
			err_code = -ENOMEM;
			goto cq_free_rsrc;
		}

		iwcq->kmem_shadow.size = ALIGN(ZXDH_SHADOW_AREA_SIZE << 3, 64);
		iwcq->kmem_shadow.va = dma_alloc_coherent(dev->hw->device, iwcq->kmem_shadow.size,
							  &iwcq->kmem_shadow.pa, GFP_KERNEL);

		if (!iwcq->kmem_shadow.va) {
			err_code = -ENOMEM;
			goto cq_free_rsrc;
		}
		info.shadow_area_pa = iwcq->kmem_shadow.pa;
		ukinfo->shadow_area = iwcq->kmem_shadow.va;
		ukinfo->cq_base = iwcq->kmem.va;
		info.cq_base_pa = iwcq->kmem.pa;
	}

	info.shadow_read_threshold =
		min(info.cq_uk_init_info.cq_size / 2, (u32)ZXDH_MAX_CQ_READ_THRESH);
	if (zxdh_sc_cq_init(cq, &info)) {
		pr_err("VERBS: init cq fail\n");
		err_code = -EPROTO;
		goto cq_free_rsrc;
	}

	cqp_request = zxdh_alloc_and_get_cqp_request(&rf->cqp, true);
	if (!cqp_request) {
		err_code = -ENOMEM;
		goto cq_free_rsrc;
	}
	cqp_info = &cqp_request->info;
	cqp_info->cqp_cmd = ZXDH_OP_CQ_CREATE;
	cqp_info->post_sq = 1;
	cqp_info->in.u.cq_create.cq = cq;
	cqp_info->in.u.cq_create.scratch = (uintptr_t)cqp_request;
	status = zxdh_handle_cqp_op(rf, cqp_request);
	zxdh_put_cqp_request(&rf->cqp, cqp_request);
	if (status) {
		err_code = -ENOMEM;
		goto cq_free_rsrc;
	}

	if (udata) {
		struct zxdh_create_cq_resp resp = {};

		resp.cq_id = info.cq_uk_init_info.cq_id;
		resp.cq_size = info.cq_uk_init_info.cq_size;
		if (ib_copy_to_udata(udata, &resp, min(sizeof(resp), udata->outlen))) {
			zxdh_dbg(iwdev_to_idev(iwdev), "VERBS: copy to user data\n");
			err_code = -EPROTO;
			goto cq_destroy;
		}
	}

	rf->cq_table[cq_num - dev->base_cqn] = iwcq;
	init_completion(&iwcq->free_cq);

	return 0;

cq_destroy:
	zxdh_cq_wq_destroy(rf, cq);
cq_free_rsrc:
	zxdh_cq_free_rsrc(rf, iwcq);
	return err_code;
}

/**
 * zxdh_copy_user_pgaddrs - copy user page address to pble's os locally
 * @iwmr: iwmr for IB's user page addresses
 * @pblpar: ple pointer to save 1 level or 0 level pble
 * @pbleinfo: pble info
 * @level: indicated level 0, 1 or 2
 * @use_pbles: ple pointer to save 1 level or 0 level pble
 * @pble_type: ple pointer to save 1 level or 0 level pble
 */
void zxdh_copy_user_pgaddrs(struct zxdh_mr *iwmr, u64 *pblpar, struct zxdh_pble_info **pbleinfo,
			    enum zxdh_pble_level level, bool use_pbles, bool pble_type)
{
	struct ib_umem *region = NULL;
	struct zxdh_pbl *iwpbl = NULL;
	struct ib_block_iter biter;
	struct zxdh_pble_alloc *palloc = NULL;
	struct zxdh_pble_info *pinfo = NULL;
	struct zxdh_sc_dev *dev = NULL;

	u32 idx = 0;
	u32 pbl_cnt = 0;
	u64 *pbl = NULL;
	u32 l2_pinfo_cnt = 0;
	int j;

	region = iwmr->region;
	iwpbl = &iwmr->iwpbl;
	palloc = &iwpbl->pble_alloc;

	if (use_pbles) {
		if (!(*pbleinfo))
			return;
		dev = (*pbleinfo)->chunkinfo.pchunk->dev;
		pbl = (*pbleinfo)->addr;
	} else {
		pbl = pblpar;
	}

	pinfo = (level == PBLE_LEVEL_1) ? NULL : palloc->level2.leaf;
	if (iwmr->type == ZXDH_MEMREG_TYPE_QP)
		iwpbl->qp_mr.sq_page = sg_page(region->sgt_append.sgt.sgl);
	rdma_umem_for_each_dma_block(region, &biter, iwmr->page_size) {
		*pbl = rdma_block_iter_dma_address(&biter);
		if (++pbl_cnt == palloc->total_cnt)
			break;
		pbl = zxdh_next_pbl_addr(pbl, &pinfo, &idx, &l2_pinfo_cnt);
	}

	if (use_pbles) {
		if (true == (*pbleinfo)->pble_copy) {
			if (level == PBLE_LEVEL_1) {
				zxdh_cqp_config_pble_table_cmd(dev, (*pbleinfo),
							       palloc->total_cnt << 3, pble_type);
			} else if (level == PBLE_LEVEL_2) {
				if ((palloc->total_cnt % 512) == 0)
					l2_pinfo_cnt = palloc->total_cnt >> 9;
				else
					l2_pinfo_cnt = (palloc->total_cnt >> 9) + 1;

				pinfo = palloc->level2.leaf;
				for (j = 0; j < l2_pinfo_cnt; j++) {
					zxdh_cqp_config_pble_table_cmd(dev, pinfo, pinfo->cnt << 3,
								       pble_type);
					pinfo++;
				}
			}
		}
	}
}

/**
 * zxdh_destroy_ah - Destroy address handle
 * @ibah: pointer to address handle
 * @ah_flags: destroy flags
 */
int zxdh_destroy_ah(struct ib_ah *ibah, u32 ah_flags)
{
	struct zxdh_device *iwdev = to_iwdev(ibah->device);
	struct zxdh_ah *ah = to_iwah(ibah);

	if (ah->parent_ah) {
		mutex_lock(&iwdev->ah_list_lock);
		if (!refcount_dec_and_test(&ah->parent_ah->refcnt)) {
			mutex_unlock(&iwdev->ah_list_lock);
			return 0;
		}
		list_del(&ah->parent_ah->list);
		kfree(ah->parent_ah);
		iwdev->ah_list_cnt--;
		mutex_unlock(&iwdev->ah_list_lock);
	}
	zxdh_ah_cqp_op(iwdev->rf, &ah->sc_ah, ZXDH_OP_AH_DESTROY, false, NULL, ah);

	zxdh_free_rsrc(iwdev->rf, iwdev->rf->allocated_ahs, ah->sc_ah.ah_info.ah_idx);

	return 0;
}

int zxdh_dereg_mr(struct ib_mr *ib_mr, struct ib_udata *udata)
{
	struct zxdh_mr *iwmr = to_iwmr(ib_mr);
	struct zxdh_device *iwdev = to_iwdev(ib_mr->device);
	struct zxdh_pbl *iwpbl = &iwmr->iwpbl;
	int ret;

	if (iwmr->type != ZXDH_MEMREG_TYPE_MEM) {
		if (iwmr->region) {
			struct zxdh_ucontext *ucontext;

			ucontext =
				rdma_udata_to_drv_context(udata, struct zxdh_ucontext, ibucontext);
			zxdh_del_memlist(iwmr, ucontext);
		}
		goto done;
	}

	ret = zxdh_hwdereg_mr(ib_mr);
	if (ret)
		return ret;

	zxdh_free_stag(iwdev, iwmr->stag);
done:
	if (iwpbl->pbl_allocated) {
		if (iwmr->type != ZXDH_MEMREG_TYPE_MEM) {
			if (iwmr->region)
				zxdh_free_pble(iwdev->rf->pble_rsrc, &iwpbl->pble_alloc);
		} else {
			zxdh_free_pble(iwdev->rf->pble_mr_rsrc, &iwpbl->pble_alloc);
		}
	}

	if (iwmr->region)
		ib_umem_release(iwmr->region);

	kfree(iwmr);

	return 0;
}

/*
 *  zxdh_rereg_user_mr - Re-Register a user memory region
 *  @ibmr: ib mem to access iwarp mr pointer
 *  @flags: bit mask to indicate which of the attr's of MR modified
 *  @start: virtual start address
 *  @len: length of mr
 *  @virt: virtual address
 *  @new access flags: bit mask of access flags
 *  @new_pd: ptr of pd
 *  @udata: user data
 */
struct ib_mr *zxdh_rereg_user_mr(struct ib_mr *ib_mr, int flags, u64 start, u64 len, u64 virt,
				 int new_access, struct ib_pd *new_pd, struct ib_udata *udata)
{
	struct zxdh_device *iwdev = to_iwdev(ib_mr->device);
	struct zxdh_mr *iwmr = to_iwmr(ib_mr);
	struct zxdh_pbl *iwpbl = &iwmr->iwpbl;
	int ret;

	if (len > iwdev->rf->sc_dev.hw_attrs.max_mr_size)
		return ERR_PTR(-EINVAL);

	if (flags & ~(IB_MR_REREG_TRANS | IB_MR_REREG_PD | IB_MR_REREG_ACCESS))
		return ERR_PTR(-EOPNOTSUPP);

	ret = zxdh_hwdereg_mr(ib_mr);
	if (ret)
		return ERR_PTR(ret);

	if (flags & IB_MR_REREG_ACCESS)
		iwmr->access = new_access;

	if (flags & IB_MR_REREG_PD) {
		iwmr->ibmr.pd = new_pd;
		iwmr->ibmr.device = new_pd->device;
	}

	if (flags & IB_MR_REREG_TRANS) {
		if (iwpbl->pbl_allocated) {
			zxdh_free_pble(iwdev->rf->pble_rsrc, &iwpbl->pble_alloc);
			iwpbl->pbl_allocated = false;
		}
		if (iwmr->region) {
			ib_umem_release(iwmr->region);
			iwmr->region = NULL;
		}

		ib_mr = zxdh_rereg_mr_trans(iwmr, start, len, virt, udata);
	} else {
		ret = zxdh_hwreg_mr(iwdev, iwmr, iwmr->access);
		if (ret)
			return ERR_PTR(ret);
	}

	return ib_mr;
}
int kc_zxdh_set_roce_cm_info(struct zxdh_qp *iwqp, struct ib_qp_attr *attr, u16 *vlan_id)
{
	const struct ib_gid_attr *sgid_attr;
	int ret;
	struct zxdh_av *av = &iwqp->roce_ah.av;

	sgid_attr = attr->ah_attr.grh.sgid_attr;
	if (kc_deref_sgid_attr(sgid_attr)) {
		ret = rdma_read_gid_l2_fields(sgid_attr, vlan_id,
					      iwqp->ctx_info.roce_info->mac_addr);
		if (ret)
			return ret;
	}

	rdma_gid2ip((struct sockaddr *)&av->sgid_addr, &sgid_attr->gid);
	return 0;
}

/**
 * zxdh_destroy_cq - destroy cq
 * @ib_cq: cq pointer
 * @udata: user data
 */
int zxdh_destroy_cq(struct ib_cq *ib_cq, struct ib_udata *udata)
{
	struct zxdh_device *iwdev = to_iwdev(ib_cq->device);
	struct zxdh_cq *iwcq = to_iwcq(ib_cq);
	struct zxdh_sc_cq *cq = &iwcq->sc_cq;
	struct zxdh_sc_dev *dev = cq->dev;
	struct zxdh_sc_ceq *ceq = dev->ceq[cq->ceq_index];
	struct zxdh_ceq *iwceq = container_of(ceq, struct zxdh_ceq, sc_ceq);
	unsigned long flags;

	cq->cq_type = 0;
	cq->back_cq = NULL;

	spin_lock_irqsave(&iwcq->lock, flags);
	cq->cq_uk.valid_cq = false;
	if (!list_empty(&iwcq->cmpl_generated))
		zxdh_remove_cmpls_list(iwcq);
	if (!list_empty(&iwcq->resize_list))
		zxdh_process_resize_list(iwcq, iwdev, NULL);
	spin_unlock_irqrestore(&iwcq->lock, flags);

	if (ib_cq->comp_wq) {
		usleep_range(5000, 6000);
		cancel_work_sync(&ib_cq->work);
	}

	zxdh_cq_rem_ref(ib_cq);
	wait_for_completion(&iwcq->free_cq);

	zxdh_cq_wq_destroy(iwdev->rf, cq);
	zxdh_cq_free_rsrc(iwdev->rf, iwcq);

	spin_lock_irqsave(&iwceq->ce_lock, flags);
	zxdh_sc_cleanup_ceqes(cq, ceq);
	spin_unlock_irqrestore(&iwceq->ce_lock, flags);

	return 0;
}

/**
 * zxdh_alloc_mw - Allocate memory window
 * @ibmw: Memory Window
 * @udata: user data pointer
 */
int zxdh_alloc_mw(struct ib_mw *ibmw, struct ib_udata *udata)
{
	struct zxdh_device *iwdev = to_iwdev(ibmw->device);
	struct zxdh_mr *iwmr = to_iwmw(ibmw);
	int err_code;
	u32 stag;

	stag = zxdh_create_stag(iwdev);
	if (!stag)
		return -ENOMEM;

	iwmr->stag = stag;
	ibmw->rkey = stag;

	err_code = zxdh_hw_alloc_mw(iwdev, iwmr);
	if (err_code) {
		zxdh_free_stag(iwdev, stag);
		return err_code;
	}

	return 0;
}

/**
 * zxdh_disassociate_ucontext - Disassociate user context
 * @context: ib user context
 */
void zxdh_disassociate_ucontext(struct ib_ucontext *context)
{
}

struct zxdh_device *zxdh_device_get_by_source_netdev(struct net_device *netdev)
{
	struct zxdh_device *iwdev;
	struct zxdh_handler *hdl;
	unsigned long flags;

	spin_lock_irqsave(&zxdh_handler_lock, flags);
	list_for_each_entry(hdl, &zxdh_handlers, list) {
		iwdev = hdl->iwdev;
		if (netdev == iwdev->source_netdev) {
			spin_unlock_irqrestore(&zxdh_handler_lock, flags);
			return iwdev;
		}
	}
	spin_unlock_irqrestore(&zxdh_handler_lock, flags);

	return NULL;
}
/**
 * zxdh_query_gid_roce - Query port GID for Roce
 * @ibdev: device pointer from stack
 * @port: port number
 * @index: Entry index
 * @gid: Global ID
 */
int zxdh_query_gid_roce(struct ib_device *ibdev, u32 port, int index, union ib_gid *gid)
{
	int ret;

	ret = rdma_query_gid(ibdev, port, index, gid);
	if (ret == -EAGAIN) {
		memcpy(gid, &zgid, sizeof(*gid));
		return 0;
	}

	return ret;
}

/**
 * zxdh_modify_port - modify port attributes
 * @ibdev: device pointer from stack
 * @port: port number for query
 * @mask: Property mask
 * @props: returning device attributes
 */
int zxdh_modify_port(struct ib_device *ibdev, u32 port, int mask, struct ib_port_modify *props)
{
	if (port > 1)
		return -EINVAL;

	return 0;
}

/**
 * zxdh_query_pkey - Query partition key
 * @ibdev: device pointer from stack
 * @port: port number
 * @index: index of pkey
 * @pkey: pointer to store the pkey
 */
int zxdh_query_pkey(struct ib_device *ibdev, u32 port, u16 index, u16 *pkey)
{
	if (index >= ZXDH_PKEY_TBL_SZ)
		return -EINVAL;

	*pkey = ZXDH_DEFAULT_PKEY;
	return 0;
}

int zxdh_roce_port_immutable(struct ib_device *ibdev, u32 port_num,
			     struct ib_port_immutable *immutable)
{
	struct ib_port_attr attr;
	int err;

	immutable->core_cap_flags = RDMA_CORE_PORT_IBA_ROCE_UDP_ENCAP | RDMA_CORE_CAP_PROT_ROCE;
	err = ib_query_port(ibdev, port_num, &attr);
	if (err)
		return err;

	immutable->max_mad_size = IB_MGMT_MAD_SIZE;
	immutable->pkey_tbl_len = attr.pkey_tbl_len;
	immutable->gid_tbl_len = attr.gid_tbl_len;

	return 0;
}

/**
 * zxdh_query_port - get port attributes
 * @ibdev: device pointer from stack
 * @port: port number for query
 * @props: returning device attributes
 */
int zxdh_query_port(struct ib_device *ibdev, u32 port, struct ib_port_attr *props)
{
	struct zxdh_device *iwdev = to_iwdev(ibdev);
	struct net_device *netdev = iwdev->netdev;
	u32 val = 0;

	/* no need to zero out pros here. done by caller */

	props->max_mtu = IB_MTU_4096;
	props->active_mtu = zxdh_mtu_int_to_enum(netdev->mtu);
	props->lid = 0;
	props->lmc = 0;
	props->sm_lid = 0;
	props->sm_sl = 0;
	if (netif_carrier_ok(netdev) && netif_running(netdev)) {
		props->state = IB_PORT_ACTIVE;
		props->phys_state = IB_PORT_PHYS_STATE_LINK_UP;
	} else {
		props->state = IB_PORT_DOWN;
		props->phys_state = IB_PORT_PHYS_STATE_DISABLED;
	}
	zxdh_get_eth_speed(ibdev, netdev, port, &props->active_speed, &props->active_width);
	if (rdma_protocol_roce(ibdev, 1)) {
		props->gid_tbl_len = 255;
		kc_set_props_ip_gid_caps(props);
		props->pkey_tbl_len = ZXDH_PKEY_TBL_SZ;
	} else {
		props->gid_tbl_len = 1;
	}
	props->qkey_viol_cntr = 0;
	props->port_cap_flags |= IB_PORT_CM_SUP;
	props->max_msg_sz = iwdev->rf->sc_dev.hw_attrs.max_hw_outbound_msg_size;
	val = rd32(iwdev->rf->sc_dev.hw, RDMARX_PRI_BASE_RD);
	props->qkey_viol_cntr = (u32)FIELD_GET(ZXDH_PRI_BASE_RD_BAD_QKEY_COUNTER, val);
	return 0;
}

extern const struct rdma_stat_desc zxdh_hw_stat_descs[];

/**
 * zxdh_alloc_hw_port_stats - Allocate a hw stats structure
 * @ibdev: device pointer from stack
 * @port_num: port number
 */
struct rdma_hw_stats *zxdh_alloc_hw_port_stats(struct ib_device *ibdev, u32 port_num)
{
	struct zxdh_device *iwdev = to_iwdev(ibdev);
	struct zxdh_sc_dev *dev = &iwdev->rf->sc_dev;

	int num_counters = dev->hw_attrs.max_stat_idx;
	unsigned long lifespan = RDMA_HW_STATS_DEFAULT_LIFESPAN;

	/* We support only per port stats */
	if (port_num == 0)
		return NULL;

	if (!dev->privileged)
		lifespan = 1000;

	return rdma_alloc_hw_stats_struct(zxdh_hw_stat_descs, num_counters, lifespan);
}

/**
 * zxdh_get_hw_stats - Populates the rdma_hw_stats structure
 * @ibdev: device pointer from stack
 * @stats: stats pointer from stack
 * @port_num: port number
 * @index: which hw counter the stack is requesting we update
 */
int zxdh_get_hw_stats(struct ib_device *ibdev, struct rdma_hw_stats *stats, u32 port_num, int index)
{
	struct zxdh_device *iwdev = to_iwdev(ibdev);
	int ret;
	int i;
	struct zxdh_sc_dev *dev;
	struct zxdh_rdma_stats_get rdma_stats;
	struct zxdh_hw_stats *stats_entry;

	stats_entry = &iwdev->rf->sc_dev.stats_entry;
	dev = &iwdev->rf->sc_dev;
	memset(&rdma_stats, 0, sizeof(struct zxdh_rdma_stats_get));

	ret = zxdh_rdma_stats_read(dev, &rdma_stats);
	if (ret)
		return ret;
	for (i = 0; i < ZXDH_HW_STAT_INDEX_MAX; i++) {
		if (rdma_stats.rdma_stats_entry_sta[i] == ZXDH_HW_STATS_VALID)
			stats_entry->rdma_stats_entry[i] = rdma_stats.rdma_stats_entry[i];
	}
	memcpy(&stats->value[0], &stats_entry->rdma_stats_entry, sizeof(u64) * stats->num_counters);
	return stats->num_counters;
}

/*
 * zxdh_process_mad - process an incoming MAD packet
 * @ibdev: the infiniband device this packet came in on
 * @mad_flags: MAD flags
 * @port_num: the port number this packet came in on
 * @in_wc: the work completion entry for this packet
 * @in_grh: the global route header for this packet
 * @in_mad: the incoming MAD
 * @out_mad: any outgoing MAD reply
 * @out_mad_size:outgoing MAD size
 * @out_mad_pkey_index:outgoing MAD pkey index
 */
int zxdh_process_mad(struct ib_device *ibdev, int mad_flags, u32 port_num,
		     const struct ib_wc *in_wc, const struct ib_grh *in_grh,
		     const struct ib_mad *in_mad, struct ib_mad *out_mad, size_t *out_mad_size,
		     u16 *out_mad_pkey_index)
{
	struct zxdh_device *iwdev = to_iwdev(ibdev);
	struct zxdh_sc_dev *dev;
	u8 mgmt_class;
	int ret;

	ret = IB_MAD_RESULT_FAILURE;
	dev = &iwdev->rf->sc_dev;
	mgmt_class = in_mad->mad_hdr.mgmt_class;
	pr_debug("%s %d vhca_id:%d mgmt_class:%d base_version:0x%x method:0x%x\n", __func__,
		 __LINE__, dev->vhca_id, mgmt_class, in_mad->mad_hdr.base_version,
		 in_mad->mad_hdr.method);
	if (in_mad->mad_hdr.base_version != IB_MGMT_BASE_VERSION)
		return -EINVAL;
	if (in_mad->mad_hdr.method != IB_MGMT_METHOD_GET)
		return -EINVAL;
	switch (mgmt_class) {
	case IB_MGMT_CLASS_PERF_MGMT:
		ret = zxdh_process_pma_cmd(dev, port_num, in_mad, out_mad);
		break;
	default:
		ret = IB_MAD_RESULT_SUCCESS | IB_MAD_RESULT_REPLY;
		break;
	}
	return ret;
}

/**
 * zxdh_query_gid - Query port GID
 * @ibdev: device pointer from stack
 * @port: port number
 * @index: Entry index
 * @gid: Global ID
 */
int zxdh_query_gid(struct ib_device *ibdev, u32 port, int index, union ib_gid *gid)
{
	struct zxdh_device *iwdev = to_iwdev(ibdev);

	memset(gid->raw, 0, sizeof(gid->raw));
	ether_addr_copy(gid->raw, iwdev->netdev->dev_addr);

	return 0;
}

/**
 * zxdh_query_qpc - query qpc
 * @qp: points to qp
 * @qpc_buf: qpc buffer
 */
int zxdh_query_qpc(struct zxdh_sc_qp *qp, struct zxdh_dma_mem *qpc_buf)
{
	struct zxdh_sc_dev *dev = qp->dev;
	struct zxdh_pci_f *rf = container_of(dev, struct zxdh_pci_f, sc_dev);
	struct zxdh_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	int err_code = 0;
	int status;

	cqp_request = zxdh_alloc_and_get_cqp_request(&rf->cqp, true);
	if (!cqp_request) {
		err_code = -ENOMEM;
		goto free_rsrc;
	}
	cqp_info = &cqp_request->info;
	cqp_info->cqp_cmd = ZXDH_OP_QUERY_QPC;
	cqp_info->post_sq = 1;
	cqp_info->in.u.query_qpc.dev = dev;
	cqp_info->in.u.query_qpc.qpn = qp->qp_ctx_num;
	cqp_info->in.u.query_qpc.qpc_buf_pa = qpc_buf->pa;
	cqp_info->in.u.query_qpc.scratch = (uintptr_t)cqp_request;
	status = zxdh_handle_cqp_op(rf, cqp_request);
	zxdh_put_cqp_request(&rf->cqp, cqp_request);
	if (status) {
		err_code = -ENOMEM;
		goto free_rsrc;
	}
	return 0;

free_rsrc:
	return err_code;
}

void zxdh_print_hw_qpc(__le64 *qp_ctx)
{
	u64 temp;
	u64 lsn_bit0, rnr_retry_time_bits_l30, ssn_bits_low20;
	u64 hw_sq_tail_bits_low11, rdwqe_pyld_length_bits_low5;
	u64 vhca_id_bits_low6;

	pr_info("******TX Part******\n");

	get_64bit_val(qp_ctx, 0, &temp);
	pr_info("txwindow_waddr[7:0]:0x%llx\n", FIELD_GET(GENMASK_ULL(7, 0), temp));
	pr_info("Retry_Count:0x%llx\n", FIELD_GET(GENMASK_ULL(10, 8), temp));
	pr_info("Cur_Retry_Count:0x%llx\n", FIELD_GET(GENMASK_ULL(13, 11), temp));
	pr_info("read_retry_flag:0x%llx\n", FIELD_GET(BIT_ULL(14), temp));
	pr_info("tx_Last_Ack_PSN:0x%llx\n", FIELD_GET(GENMASK_ULL(38, 15), temp));
	pr_info("ACK_MSN:0x%llx\n", FIELD_GET(GENMASK_ULL(62, 39), temp));
	lsn_bit0 = (u64)FIELD_GET(BIT_ULL(63), temp);

	get_64bit_val(qp_ctx, 8, &temp);
	pr_info("LSN:0x%llx\n", (FIELD_GET(GENMASK_ULL(22, 0), temp) << 1) + lsn_bit0);
	pr_info("tx_Ack_Credits:0x%llx\n", FIELD_GET(GENMASK_ULL(27, 23), temp));
	pr_info("rnr_retry_flag:0x%llx\n", FIELD_GET(BIT_ULL(28), temp));
	pr_info("rnr_retry_threshold:0x%llx\n", FIELD_GET(GENMASK_ULL(33, 29), temp));
	rnr_retry_time_bits_l30 = (u64)FIELD_GET(GENMASK_ULL(63, 34), temp);

	get_64bit_val(qp_ctx, 16, &temp);
	pr_info("rnr_retry_time:0x%llx\n",
		(FIELD_GET(GENMASK_ULL(1, 0), temp) << 30) + rnr_retry_time_bits_l30);
	pr_info("wqe_offset:0x%llx\n", FIELD_GET(GENMASK_ULL(33, 2), temp));
	pr_info("fence flag:0x%llx\n", FIELD_GET(GENMASK_ULL(35, 34), temp));
	pr_info("cur_ord_cnt:0x%llx\n", FIELD_GET(GENMASK_ULL(43, 36), temp));
	ssn_bits_low20 = (u64)FIELD_GET(GENMASK_ULL(63, 44), temp);

	get_64bit_val(qp_ctx, 24, &temp);
	pr_info("SSN:0x%llx\n", (FIELD_GET(GENMASK_ULL(3, 0), temp) << 20) + ssn_bits_low20);
	pr_info("first_packet_done_flag:0x%llx\n", FIELD_GET(BIT_ULL(4), temp));
	pr_info("PSN MAX:0x%llx\n", FIELD_GET(GENMASK_ULL(28, 5), temp));
	pr_info("PSN_Next:0x%llx\n", FIELD_GET(GENMASK_ULL(52, 29), temp));
	hw_sq_tail_bits_low11 = (u64)FIELD_GET(GENMASK_ULL(63, 53), temp);

	get_64bit_val(qp_ctx, 32, &temp);
	pr_info("HW_SQ_Tail:0x%llx\n",
		(FIELD_GET(GENMASK_ULL(6, 0), temp) << 11) + hw_sq_tail_bits_low11);
	pr_info("last_packet_time:0x%llx\n", FIELD_GET(GENMASK_ULL(38, 7), temp));
	pr_info("incast_fragment_cnt:0x%llx\n", FIELD_GET(GENMASK_ULL(56, 39), temp));
	pr_info("local_ack_timeout:0x%llx\n", FIELD_GET(GENMASK_ULL(61, 57), temp));
	pr_info("retry_flag:0x%llx\n", FIELD_GET(BIT_ULL(62), temp));

	get_64bit_val(qp_ctx, 40, &temp);
	pr_info("HW_SQ_Tail_una:0x%llx\n", FIELD_GET(GENMASK_ULL(15, 0), temp));
	pr_info("last_ack_wqe_offset:0x%llx\n", FIELD_GET(GENMASK_ULL(46, 16), temp));
	pr_info("err_flag:0x%llx\n", FIELD_GET(BIT_ULL(47), temp));
	pr_info("ack_err_flag:0x%llx\n", FIELD_GET(BIT_ULL(48), temp));
	pr_info("in_flight:0x%llx\n", FIELD_GET(GENMASK_ULL(58, 49), temp));
	rdwqe_pyld_length_bits_low5 = (u64)FIELD_GET(GENMASK_ULL(63, 59), temp);

	get_64bit_val(qp_ctx, 48, &temp);
	pr_info("rdwqe_pyld_length:0x%llx\n",
		(FIELD_GET(GENMASK_ULL(26, 0), temp) << 5) + rdwqe_pyld_length_bits_low5);
	pr_info("package_err_flag:0x%llx\n", FIELD_GET(BIT_ULL(27), temp));
	pr_info("txwindow_waddr[9:8]:0x%llx\n", FIELD_GET(GENMASK_ULL(29, 28), temp));
	pr_info("txwindow_raddr:0x%llx\n", FIELD_GET(GENMASK_ULL(39, 30), temp));
	pr_info("rd_msg_loss_err_flag:0x%llx\n", FIELD_GET(BIT_ULL(40), temp));
	pr_info("pktchk_rd_msg_loss_err_cnt:0x%llx\n", FIELD_GET(GENMASK_ULL(42, 41), temp));
	pr_info("recv_rd_msg_loss_err_cnt:0x%llx\n", FIELD_GET(GENMASK_ULL(44, 43), temp));
	pr_info("recv_rd_msg_loss_err_flag:0x%llx\n", FIELD_GET(BIT_ULL(45), temp));
	pr_info("recv_err_flag:0x%llx\n", FIELD_GET(GENMASK_ULL(47, 46), temp));
	pr_info("recv_read_flag:0x%llx\n", FIELD_GET(BIT_ULL(48), temp));

	get_64bit_val(qp_ctx, 56, &temp);
	pr_info("retry_cqe_sq_opcode:0x%llx\n", FIELD_GET(GENMASK_ULL(5, 0), temp));

	get_64bit_val(qp_ctx, 64, &temp);
	pr_info("Service_Type:0x%llx\n", FIELD_GET(GENMASK_ULL(2, 0), temp));
	pr_info("SQ_Virtually_Mapped:0x%llx\n", FIELD_GET(BIT_ULL(3), temp));
	pr_info("SQ_Leaf_PBL_Size:0x%llx\n", FIELD_GET(GENMASK_ULL(5, 4), temp));
	pr_info("is_QP1:0x%llx\n", FIELD_GET(BIT_ULL(6), temp));
	pr_info("IPv4:0x%llx\n", FIELD_GET(BIT_ULL(7), temp));
	pr_info("FastRegisterEnable:0x%llx\n", FIELD_GET(BIT_ULL(8), temp));
	pr_info("BindEnable:0x%llx\n", FIELD_GET(BIT_ULL(9), temp));
	pr_info("Insert_VLAN_Tag:0x%llx\n", FIELD_GET(BIT_ULL(10), temp));
	pr_info("VLAN_Tag:0x%llx\n", FIELD_GET(GENMASK_ULL(26, 11), temp));
	pr_info("PD_Index:0x%llx\n", FIELD_GET(GENMASK_ULL(50, 27), temp));
	pr_info("rev_l_key_en:0x%llx\n", FIELD_GET(BIT_ULL(51), temp));
	pr_info("ECN_enable:0x%llx\n", FIELD_GET(BIT_ULL(63), temp));

	get_64bit_val(qp_ctx, 72, &temp);
	pr_info("SQ_Address:0x%llx\n", FIELD_GET(GENMASK_ULL(63, 0), temp));

	get_64bit_val(qp_ctx, 80, &temp);
	pr_info("Dest_IP_Address_lo:0x%llx\n", FIELD_GET(GENMASK_ULL(63, 0), temp));

	get_64bit_val(qp_ctx, 88, &temp);
	pr_info("Dest_IP_Address_hi:0x%llx\n", FIELD_GET(GENMASK_ULL(63, 0), temp));

	get_64bit_val(qp_ctx, 96, &temp);
	pr_info("Source_Port_Number:0x%llx\n", FIELD_GET(GENMASK_ULL(15, 0), temp));
	pr_info("Dest_Port_Number:0x%llx\n", FIELD_GET(GENMASK_ULL(31, 16), temp));
	pr_info("Flow_Label:0x%llx\n", FIELD_GET(GENMASK_ULL(51, 32), temp));
	pr_info("Hop_Limit_or_TTL:0x%llx\n", FIELD_GET(GENMASK_ULL(59, 52), temp));
	pr_info("ROCE_Tver:0x%llx\n", FIELD_GET(GENMASK_ULL(63, 60), temp));

	get_64bit_val(qp_ctx, 104, &temp);
	pr_info("Q_Key:0x%llx\n", FIELD_GET(GENMASK_ULL(31, 0), temp));
	pr_info("Dest_QPN:0x%llx\n", FIELD_GET(GENMASK_ULL(55, 32), temp));
	pr_info("ORD_Size:0x%llx\n", FIELD_GET(GENMASK_ULL(63, 56), temp));

	get_64bit_val(qp_ctx, 112, &temp);
	pr_info("P_Key:0x%llx\n", FIELD_GET(GENMASK_ULL(15, 0), temp));
	pr_info("Dest_MAC:0x%llx\n", FIELD_GET(GENMASK_ULL(63, 16), temp));

	get_64bit_val(qp_ctx, 120, &temp);
	pr_info("QP_Completion_Context:0x%llx\n", FIELD_GET(GENMASK_ULL(63, 0), temp));

	get_64bit_val(qp_ctx, 128, &temp);
	pr_info("S_IP_low:0x%llx\n", FIELD_GET(GENMASK_ULL(63, 0), temp));

	get_64bit_val(qp_ctx, 136, &temp);
	pr_info("S_IP_high:0x%llx\n", FIELD_GET(GENMASK_ULL(63, 0), temp));

	get_64bit_val(qp_ctx, 144, &temp);
	pr_info("Src_MAC:0x%llx\n", FIELD_GET(GENMASK_ULL(47, 0), temp));
	pr_info("PMTU:0x%llx\n", FIELD_GET(GENMASK_ULL(50, 48), temp));
	pr_info("ack_timeout:0x%llx\n", FIELD_GET(GENMASK_ULL(55, 51), temp));
	pr_info("Log_SQ_Size:0x%llx\n", FIELD_GET(GENMASK_ULL(59, 56), temp));

	get_64bit_val(qp_ctx, 152, &temp);
	pr_info("TxCmpQueueNum:0x%llx\n", FIELD_GET(GENMASK_ULL(20, 0), temp));
	pr_info("NVME_OF_QID:0x%llx\n", FIELD_GET(GENMASK_ULL(30, 21), temp));
	pr_info("Is_NVME_OF_Target:0x%llx\n", FIELD_GET(BIT_ULL(31), temp));
	pr_info("Is_NVME_OF_IOQ:0x%llx\n", FIELD_GET(BIT_ULL(32), temp));
	pr_info("GQP_id:0x%llx\n", FIELD_GET(GENMASK_ULL(43, 33), temp));
	pr_info("DCQCN_enable:0x%llx\n", FIELD_GET(BIT_ULL(49), temp));
	pr_info("queue_Tc:0x%llx\n", FIELD_GET(GENMASK_ULL(52, 50), temp));

	get_64bit_val(qp_ctx, 160, &temp);
	pr_info("QPN:0x%llx\n", FIELD_GET(GENMASK_ULL(19, 0), temp));
	pr_info("rtt_first_index:0x%llx\n", FIELD_GET(GENMASK_ULL(35, 22), temp));
	pr_info("rtt_last_index:0x%llx\n", FIELD_GET(GENMASK_ULL(49, 36), temp));
	pr_info("Traffic_Class_or_TOS:0x%llx\n", FIELD_GET(GENMASK_ULL(57, 50), temp));
	vhca_id_bits_low6 = (u64)FIELD_GET(GENMASK_ULL(63, 58), temp);

	get_64bit_val(qp_ctx, 168, &temp);
	pr_info("VHCA_ID:0x%llx\n", (FIELD_GET(GENMASK_ULL(3, 0), temp) << 6) + vhca_id_bits_low6);
	pr_info("8k_index:0x%llx\n", FIELD_GET(GENMASK_ULL(16, 4), temp));
	pr_info("RDMA_State:0x%llx\n", FIELD_GET(GENMASK_ULL(19, 17), temp));
	pr_info("debug_set:0x%llx\n", FIELD_GET(GENMASK_ULL(29, 20), temp));
	pr_info("qp_link_in:0x%llx\n", FIELD_GET(BIT_ULL(30), temp));
	pr_info("128k_index:0x%llx\n", FIELD_GET(GENMASK_ULL(47, 31), temp));

	pr_info("******RX Part******\n");

	get_64bit_val(qp_ctx, 256, &temp);
	pr_info("Wr_Dma_Len:0x%llx\n", FIELD_GET(GENMASK_ULL(31, 0), temp));
	pr_info("Wr_R_Key:0x%llx\n", FIELD_GET(GENMASK_ULL(55, 32), temp));
	pr_info("Last_Opcode:0x%llx\n", FIELD_GET(GENMASK_ULL(63, 56), temp));

	get_64bit_val(qp_ctx, 264, &temp);
	pr_info("Wr_Virt_Addr/Q_Key:0x%llx\n", FIELD_GET(GENMASK_ULL(63, 0), temp));

	get_64bit_val(qp_ctx, 272, &temp);
	pr_info("send_psn:0x%llx\n", FIELD_GET(GENMASK_ULL(23, 0), temp));
	pr_info("HW_RQ_Tail/Rnr_Wqe_Index:0x%llx\n", FIELD_GET(GENMASK_ULL(39, 24), temp));
	pr_info("E_PSN/Rnr_Nak_Psn:0x%llx\n", FIELD_GET(GENMASK_ULL(63, 40), temp));

	get_64bit_val(qp_ctx, 280, &temp);
	pr_info("HW_RQ_Tail_credit[14:14]:0x%llx\n", FIELD_GET(BIT_ULL(0), temp));
	pr_info("nof_check_state:0x%llx\n", FIELD_GET(BIT_ULL(1), temp));
	pr_info("qp_check_state:0x%llx\n", FIELD_GET(BIT_ULL(2), temp));
	pr_info("R_MSN:0x%llx\n", FIELD_GET(GENMASK_ULL(26, 3), temp));
	pr_info("ack_nack_flag:0x%llx\n", FIELD_GET(BIT_ULL(27), temp));
	pr_info("HW_RQ_Tail_credit[15:15]:0x%llx\n", FIELD_GET(BIT_ULL(28), temp));
	pr_info("nak_syn:0x%llx\n", FIELD_GET(GENMASK_ULL(36, 29), temp));
	pr_info("ird_tx_num0/ird_tx_num1:0x%llx\n", FIELD_GET(GENMASK_ULL(45, 37), temp));
	pr_info("ird_rx_num0/ird_rx_num1:0x%llx\n", FIELD_GET(GENMASK_ULL(54, 46), temp));
	pr_info("cnp_pending:0x%llx\n", FIELD_GET(BIT_ULL(55), temp));
	pr_info("is_in_list:0x%llx\n", FIELD_GET(BIT_ULL(56), temp));
	pr_info("mr_hit_flag:0x%llx\n", FIELD_GET(BIT_ULL(57), temp));
	pr_info("ack_nak_rsv:0x%llx\n", FIELD_GET(GENMASK_ULL(62, 58), temp));
	pr_info("Rnr_Nak_Signal:0x%llx\n", FIELD_GET(BIT_ULL(63), temp));

	get_64bit_val(qp_ctx, 288, &temp);
	pr_info("SW_RQ_Tail:0x%llx\n", FIELD_GET(GENMASK_ULL(15, 0), temp));
	pr_info("psn_seq_error_signal:0x%llx\n", FIELD_GET(BIT_ULL(21), temp));
	pr_info("prifield_check_error_signal:0x%llx\n", FIELD_GET(BIT_ULL(22), temp));
	pr_info("read_tail[0:0]:0x%llx\n", FIELD_GET(BIT_ULL(23), temp));
	pr_info("tx_send_length:0x%llx\n", FIELD_GET(GENMASK_ULL(63, 24), temp));

	get_64bit_val(qp_ctx, 296, &temp);
	pr_info("read_tail[8:1]:0x%llx\n", FIELD_GET(GENMASK_ULL(7, 0), temp));
	pr_info("last_read_psn:0x%llx\n", FIELD_GET(GENMASK_ULL(31, 8), temp));
	pr_info("ird_send_offset:0x%llx\n", FIELD_GET(GENMASK_ULL(55, 32), temp));
	pr_info("HW_RQ_Tail_credit[13:6]:0x%llx\n", FIELD_GET(GENMASK_ULL(63, 56), temp));

	get_64bit_val(qp_ctx, 304, &temp);
	pr_info("Comm Esta sig:0x%llx\n", FIELD_GET(BIT_ULL(0), temp));
	pr_info("rtt:0x%llx\n", FIELD_GET(GENMASK_ULL(16, 1), temp));
	pr_info("cq_overflow:0x%llx\n", FIELD_GET(BIT_ULL(17), temp));
	pr_info("rq:sec_index[27:12] /\n");
	pr_info("srq:wqe_index[15:0]:0x%llx\n", FIELD_GET(GENMASK_ULL(33, 18), temp));
	pr_info("last_expected_sent_read_psn:0x%llx\n", FIELD_GET(GENMASK_ULL(57, 34), temp));
	pr_info("HW_RQ_Tail_credit[5:0]:0x%llx\n", FIELD_GET(GENMASK_ULL(63, 58), temp));

	get_64bit_val(qp_ctx, 312, &temp);
	pr_info("rq:sec_index[11:0]+first index[63:12] /\n");
	pr_info("srq:wqe_addr:0x%llx\n", FIELD_GET(GENMASK_ULL(63, 0), temp));

	get_64bit_val(qp_ctx, 320, &temp);
	pr_info("S_IP_low:0x%llx\n", FIELD_GET(GENMASK_ULL(63, 0), temp));

	get_64bit_val(qp_ctx, 328, &temp);
	pr_info("Src_MAC[47:32]:0x%llx\n", FIELD_GET(GENMASK_ULL(15, 0), temp));
	pr_info("Dest_MAC:0x%llx\n", FIELD_GET(GENMASK_ULL(63, 16), temp));

	get_64bit_val(qp_ctx, 336, &temp);
	pr_info("Is_NVME_OF_IOQ:0x%llx\n", FIELD_GET(BIT_ULL(0), temp));
	pr_info("Insert_VLAN_Tag:0x%llx\n", FIELD_GET(BIT_ULL(1), temp));
	pr_info("PMTU:0x%llx\n", FIELD_GET(GENMASK_ULL(4, 2), temp));
	pr_info("Service_Type:0x%llx\n", FIELD_GET(GENMASK_ULL(7, 5), temp));
	pr_info("IPv4:0x%llx\n", FIELD_GET(BIT_ULL(8), temp));
	pr_info("PD_Index:0x%llx\n", FIELD_GET(GENMASK_ULL(28, 9), temp));
	pr_info("RDMA_State:0x%llx\n", FIELD_GET(GENMASK_ULL(31, 29), temp));
	pr_info("Src_MAC[31:0]:0x%llx\n", FIELD_GET(GENMASK_ULL(63, 32), temp));

	get_64bit_val(qp_ctx, 344, &temp);
	pr_info("Dest_QPN[23:12]:0x%llx\n", FIELD_GET(GENMASK_ULL(11, 0), temp));
	pr_info("Flow_Label:0x%llx\n", FIELD_GET(GENMASK_ULL(31, 12), temp));
	pr_info("Hop_Limit_or_TTL:0x%llx\n", FIELD_GET(GENMASK_ULL(39, 32), temp));
	pr_info("Traffic_Class_or_TOS:0x%llx\n", FIELD_GET(GENMASK_ULL(47, 40), temp));
	pr_info("VLAN_Tag:0x%llx\n", FIELD_GET(GENMASK_ULL(63, 48), temp));

	get_64bit_val(qp_ctx, 352, &temp);
	pr_info("srqn[18:0]:0x%llx /\n", FIELD_GET(GENMASK_ULL(18, 0), temp));
	pr_info("is_nvme_of_target[10:10]+nvme_of_qid[9:0] /\n");
	pr_info("rq_address[63:0]:0x%llx\n", FIELD_GET(GENMASK_ULL(63, 0), temp));

	get_64bit_val(qp_ctx, 360, &temp);
	pr_info("db_address:0x%llx\n", FIELD_GET(GENMASK_ULL(63, 0), temp));

	get_64bit_val(qp_ctx, 368, &temp);
	pr_info("header length:0x%llx\n", FIELD_GET(GENMASK_ULL(9, 0), temp));
	pr_info("P_Key:0x%llx\n", FIELD_GET(GENMASK_ULL(47, 32), temp));
	pr_info("Source_Port_Number:0x%llx\n", FIELD_GET(GENMASK_ULL(63, 48), temp));

	get_64bit_val(qp_ctx, 376, &temp);
	pr_info("wqe_sign_enbale:0x%llx\n", FIELD_GET(BIT_ULL(1), temp));
	pr_info("RQ_Virtually_Mapped:0x%llx\n", FIELD_GET(BIT_ULL(2), temp));
	pr_info("IRD_Size:0x%llx\n", FIELD_GET(GENMASK_ULL(6, 3), temp));
	pr_info("Log_RQ_Size:0x%llx\n", FIELD_GET(GENMASK_ULL(10, 7), temp));
	pr_info("Rse_Enable:0x%llx\n", FIELD_GET(BIT_ULL(11), temp));
	pr_info("Rwr_Enable:0x%llx\n", FIELD_GET(BIT_ULL(12), temp));
	pr_info("Rre_Enable:0x%llx\n", FIELD_GET(BIT_ULL(13), temp));
	pr_info("Log_RQ_WQE_Size:0x%llx\n", FIELD_GET(GENMASK_ULL(16, 14), temp));
	pr_info("rq_type:0x%llx\n", FIELD_GET(BIT_ULL(17), temp));
	pr_info("RxCmpQueueNum:0x%llx\n", FIELD_GET(GENMASK_ULL(38, 18), temp));
	pr_info("Dest_QPN[11:0]:0x%llx\n", FIELD_GET(GENMASK_ULL(50, 39), temp));
	pr_info("RQ_Leaf_PBL_Size:0x%llx\n", FIELD_GET(GENMASK_ULL(52, 51), temp));
	pr_info("rsv_lkey_enable:0x%llx\n", FIELD_GET(BIT_ULL(53), temp));
	pr_info("t_ver:0x%llx\n", FIELD_GET(GENMASK_ULL(57, 54), temp));
	pr_info("RQ_Rnr_Nak_Timer:0x%llx\n", FIELD_GET(GENMASK_ULL(62, 58), temp));
	pr_info("rx_Ack_Credits:0x%llx\n", FIELD_GET(BIT_ULL(63), temp));

	get_64bit_val(qp_ctx, 384, &temp);
	pr_info("global_qp_num:0x%llx\n", FIELD_GET(GENMASK_ULL(10, 0), temp));
	pr_info("8k_qp_index:0x%llx\n", FIELD_GET(GENMASK_ULL(23, 11), temp));
	pr_info("debug_set:0x%llx\n", FIELD_GET(GENMASK_ULL(49, 40), temp));
	pr_info("vHCA:0x%llx\n", FIELD_GET(GENMASK_ULL(59, 50), temp));
	pr_info("queue_tc:0x%llx\n", FIELD_GET(GENMASK_ULL(62, 59), temp));

	get_64bit_val(qp_ctx, 392, &temp);
	pr_info("cq_context:0x%llx\n", FIELD_GET(GENMASK_ULL(63, 0), temp));

	get_64bit_val(qp_ctx, 400, &temp);
	pr_info("Dest_IP_Address_hi:0x%llx\n", FIELD_GET(GENMASK_ULL(63, 0), temp));

	get_64bit_val(qp_ctx, 408, &temp);
	pr_info("Dest_IP_Address_lo:0x%llx\n", FIELD_GET(GENMASK_ULL(63, 0), temp));

	get_64bit_val(qp_ctx, 416, &temp);
	pr_info("S_IP_high:0x%llx\n", FIELD_GET(GENMASK_ULL(63, 0), temp));
}

enum rdma_link_layer zxdh_get_link_layer(struct ib_device *ibdev, u32 port_num)
{
	return IB_LINK_LAYER_ETHERNET;
}

enum ib_mtu zxdh_mtu_int_to_enum(int mtu)
{
	mtu = mtu - ZXDH_MTU_HEADER_RSV;

	if (mtu >= 4096)
		return IB_MTU_4096;
	else if (mtu >= 2048)
		return IB_MTU_2048;
	else if (mtu >= 1024)
		return IB_MTU_1024;
	else if (mtu >= 512)
		return IB_MTU_512;
	else
		return IB_MTU_256;
}

int zxdh_fill_qpc(struct zxdh_sc_dev *dev, u32 qpn, struct zxdh_dma_mem *qpc_buf)
{
	struct zxdh_pci_f *rf = container_of(dev, struct zxdh_pci_f, sc_dev);
	struct zxdh_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	int err_code = 0;
	int status;

	cqp_request = zxdh_alloc_and_get_cqp_request(&rf->cqp, true);
	if (!cqp_request) {
		err_code = -ENOMEM;
		return err_code;
	}
	cqp_info = &cqp_request->info;
	cqp_info->cqp_cmd = ZXDH_OP_QUERY_QPC;
	cqp_info->post_sq = 1;
	cqp_info->in.u.query_qpc.dev = dev;
	cqp_info->in.u.query_qpc.qpn = qpn;
	cqp_info->in.u.query_qpc.qpc_buf_pa = qpc_buf->pa;
	cqp_info->in.u.query_qpc.scratch = (uintptr_t)cqp_request;
	status = zxdh_handle_cqp_op(rf, cqp_request);
	zxdh_put_cqp_request(&rf->cqp, cqp_request);
	if (status) {
		err_code = -ENOMEM;
		return err_code;
	}
	return 0;
}

int zxdh_fill_cqc(struct zxdh_sc_dev *dev, u32 cqn, struct zxdh_dma_mem *cqc_buf)
{
	struct zxdh_pci_f *rf = container_of(dev, struct zxdh_pci_f, sc_dev);
	struct zxdh_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	int err_code = 0;
	int status;

	cqp_request = zxdh_alloc_and_get_cqp_request(&rf->cqp, true);
	if (!cqp_request) {
		err_code = -ENOMEM;
		return err_code;
	}
	cqp_info = &cqp_request->info;
	cqp_info->cqp_cmd = ZXDH_OP_QUERY_CQC;
	cqp_info->post_sq = 1;
	cqp_info->in.u.query_cqc.dev = dev;
	cqp_info->in.u.query_cqc.cqn = cqn;
	cqp_info->in.u.query_cqc.cqc_buf_pa = cqc_buf->pa;
	cqp_info->in.u.query_cqc.scratch = (uintptr_t)cqp_request;
	status = zxdh_handle_cqp_op(rf, cqp_request);
	zxdh_put_cqp_request(&rf->cqp, cqp_request);
	if (status)
		err_code = -ENOMEM;

	return err_code;
}

int zxdh_fill_ceqc(struct zxdh_sc_dev *dev, u32 ceqn, struct zxdh_dma_mem *ceqc_buf)
{
	struct zxdh_pci_f *rf = container_of(dev, struct zxdh_pci_f, sc_dev);
	struct zxdh_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	int err_code = 0;
	int status;

	cqp_request = zxdh_alloc_and_get_cqp_request(&rf->cqp, true);
	if (!cqp_request) {
		err_code = -ENOMEM;
		return err_code;
	}
	cqp_info = &cqp_request->info;
	cqp_info->cqp_cmd = ZXDH_OP_QUERY_CEQC;
	cqp_info->post_sq = 1;
	cqp_info->in.u.query_ceqc.dev = dev;
	cqp_info->in.u.query_ceqc.ceqn = ceqn;
	cqp_info->in.u.query_ceqc.ceqc_buf_pa = ceqc_buf->pa;
	cqp_info->in.u.query_ceqc.scratch = (uintptr_t)cqp_request;
	status = zxdh_handle_cqp_op(rf, cqp_request);
	zxdh_put_cqp_request(&rf->cqp, cqp_request);
	if (status)
		err_code = -ENOMEM;

	return err_code;
}

int zxdh_fill_aeqc(struct zxdh_sc_dev *dev, struct zxdh_dma_mem *aeqc_buf)
{
	struct zxdh_pci_f *rf = container_of(dev, struct zxdh_pci_f, sc_dev);
	struct zxdh_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	int err_code = 0;
	int status;

	cqp_request = zxdh_alloc_and_get_cqp_request(&rf->cqp, true);
	if (!cqp_request) {
		err_code = -ENOMEM;
		return err_code;
	}
	cqp_info = &cqp_request->info;
	cqp_info->cqp_cmd = ZXDH_OP_QUERY_AEQC;
	cqp_info->post_sq = 1;
	cqp_info->in.u.query_aeqc.dev = dev;
	cqp_info->in.u.query_aeqc.aeqn = dev->vhca_id;
	cqp_info->in.u.query_aeqc.aeqc_buf_pa = aeqc_buf->pa;
	cqp_info->in.u.query_aeqc.scratch = (uintptr_t)cqp_request;
	status = zxdh_handle_cqp_op(rf, cqp_request);
	zxdh_put_cqp_request(&rf->cqp, cqp_request);
	if (status)
		err_code = -ENOMEM;

	return err_code;
}

int zxdh_fill_srqc(struct zxdh_sc_dev *dev, u32 srqn, struct zxdh_dma_mem *srqc_buf)
{
	struct zxdh_pci_f *rf = container_of(dev, struct zxdh_pci_f, sc_dev);
	struct zxdh_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	int err_code = 0;
	int status;

	cqp_request = zxdh_alloc_and_get_cqp_request(&rf->cqp, true);
	if (!cqp_request) {
		err_code = -ENOMEM;
		return err_code;
	}
	cqp_info = &cqp_request->info;
	cqp_info->cqp_cmd = ZXDH_OP_QUERY_SRQC;
	cqp_info->post_sq = 1;
	cqp_info->in.u.query_srqc.dev = dev;
	cqp_info->in.u.query_srqc.srqn = srqn;
	cqp_info->in.u.query_srqc.srqc_buf_pa = srqc_buf->pa;
	cqp_info->in.u.query_srqc.scratch = (uintptr_t)cqp_request;
	status = zxdh_handle_cqp_op(rf, cqp_request);
	zxdh_put_cqp_request(&rf->cqp, cqp_request);
	if (status)
		err_code = -ENOMEM;

	return err_code;
}
