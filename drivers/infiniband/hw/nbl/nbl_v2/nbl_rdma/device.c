// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/*
 * device information module
 * Copyright (c) 2021 nebula-matrix Limited.
 * Author: Peter.Pan <peter.pan@nebula-matrix.com>
 */

#include <rdma/nbl-v2-abi.h>
#include <net/addrconf.h>
#include <linux/ethtool.h>
#include <rdma/ib_addr.h>
#include "shared.h"
#include "main.h"
#include "device.h"
#include "debug.h"
#include "qp.h"
#include "ib_core_compat.h"
#include "nbl_rdma_module.h"

static const char *const process_names[] = { "ib_write_lat", "ib_send_lat",
					     "ib_read_lat", NULL };

struct rdma_user_mmap_entry *
nbl_user_mmap_entry_insert(struct nbl_ucontext *nbl_uctx, u64 bar_offset,
			   enum nbl_mmap_flag mmap_flag, u64 *mmap_offset)
{
	struct nbl_user_mmap_entry *entry;
	int ret;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return NULL;

	entry->bar_offset = bar_offset;
	entry->mmap_flag = mmap_flag;

	ret = rdma_user_mmap_entry_insert(&nbl_uctx->ibucontext,
					  &entry->rdma_entry, PAGE_SIZE);
	if (ret) {
		kfree(entry);
		return NULL;
	}

	*mmap_offset = rdma_user_mmap_get_offset(&entry->rdma_entry);
	return &entry->rdma_entry;
}

static inline int nbl_shadow_hash(u64 phy_addr)
{
	u64 hash = 0;

	hash = hash_64(phy_addr, NBL_SHADOW_HASH_SHIFT);

	return (hash & NBL_SHADOW_HASH_MASK);
}

int nbl_add_shadow_mmap(struct nbl_ucontext *uctx, void *va, u64 phy_addr,
			unsigned long len)
{
	struct shadow_node *list_node;
	int ix;

	list_node = kzalloc(sizeof(struct shadow_node), GFP_KERNEL);
	if (list_node == NULL)
		return -ENOMEM;

	list_node->p_addr = phy_addr;
	list_node->va = va;
	list_node->len = len;

	/* calc hash value */
	ix = nbl_shadow_hash(phy_addr);

	mutex_lock(&uctx->shadow_list_lock);
	hlist_add_head(&(list_node->node), &uctx->shadow_head.head[ix]);
	mutex_unlock(&uctx->shadow_list_lock);

	return 0;
}

struct shadow_node *nbl_find_shadow_mmap(struct nbl_ucontext *uctx, u64 dma_addr,
					 unsigned long len)
{
	int ix;
	struct shadow_node *s_node = NULL;

	/* calc hash value */
	ix = nbl_shadow_hash(dma_addr);

	mutex_lock(&uctx->shadow_list_lock);
	hlist_for_each_entry(s_node, &uctx->shadow_head.head[ix], node) {
		if (s_node->p_addr == dma_addr && s_node->len == len)
			break;
	}
	mutex_unlock(&uctx->shadow_list_lock);
	return s_node;
}

static void nbl_init_shadow_mmap(struct nbl_ucontext *uctx)
{
	int ix;

	for (ix = 0; ix < NBL_SHADOW_HASH_SIZE; ix++)
		INIT_HLIST_HEAD(&uctx->shadow_head.head[ix]);
	mutex_init(&uctx->shadow_list_lock);
}

static void nbl_clear_shadow_mmap(struct nbl_ucontext *uctx)
{
	int ix;
	struct hlist_node *pos, *n;
	struct shadow_node *p;

	for (ix = 0; ix < NBL_SHADOW_HASH_SIZE; ix++) {
		hlist_for_each_safe(pos, n, &uctx->shadow_head.head[ix]) {
			hlist_del(pos); /* del hash node */
			p = hlist_entry(pos, struct shadow_node, node);
			kfree(p);
		}
	}
}

static int is_lat_process(void)
{
	int i;

	for (i = 0; process_names[i] != NULL; i++) {
		if (strncmp(current->comm, process_names[i], TASK_COMM_LEN) ==
		    0)
			return 1;
	}
	return 0;
}

int nbl_ib_alloc_ucontext(struct ib_ucontext *uctx, struct ib_udata *udata)
{
	struct ib_device *ibdev = uctx->device;
	struct nbl_device *nbl_dev = to_nbl_dev(ibdev);
	struct nbl_ib_alloc_ucontext_resp uresp = {};
	struct nbl_ucontext *ucontext = to_ucontext(uctx);
	struct nbl_uk_attrs *uk_attrs;
	u64 bar_off;

	nbl_init_shadow_mmap(ucontext);
	ucontext->nbl_dev = nbl_dev;

	uk_attrs = &nbl_dev->rf->sc_dev.hw_attrs.uk_attrs;

	uresp.feature_flags = uk_attrs->feature_flags;
	uresp.max_hw_wq_sges = uk_attrs->max_hw_wq_sges;
	uresp.max_hw_read_sges = uk_attrs->max_hw_read_sges;
	uresp.max_hw_inline = uk_attrs->max_hw_inline;
	uresp.max_hw_ud_inline = uk_attrs->max_hw_ud_inline;
	uresp.max_hw_rq_quanta = uk_attrs->max_hw_rq_quanta;
	uresp.max_hw_wq_quanta = uk_attrs->max_hw_wq_quanta;
	uresp.min_hw_cq_size = uk_attrs->min_hw_cq_size;
	uresp.max_hw_cq_size = uk_attrs->max_hw_cq_size;
	uresp.max_hw_sq_chunk = uk_attrs->max_hw_sq_chunk;
	uresp.qp_table_size = nbl_dev->rf->max_qp;
	uresp.max_hw_srq_wr = uk_attrs->max_hw_srq_wr;
	uresp.hw_rev = uk_attrs->hw_rev;

	bar_off = (uintptr_t)nbl_dev->rf->sc_dev.hw_regs[NBL_NOTIFY_OFFSET];
	uresp.notify_offset = (bar_off & (PAGE_SIZE - 1));
	bar_off = bar_off & PAGE_MASK;
	ucontext->db_mmap_entry = nbl_user_mmap_entry_insert(
		ucontext, bar_off, NBL_MMAP_IO_NC, &uresp.db_mmap_key);
	if (!ucontext->db_mmap_entry)
		return -ENOMEM;

	/* ext sqdb init */
	mutex_init(&ucontext->ext_sqdb_mutex);
	if (NBL_RF_TO_HW_VER(nbl_dev->rf) == NBL_VER_4) {
		ucontext->ext_sqdb_offset_first =
			((uintptr_t)nbl_dev->rf->sc_dev.hw_regs[NBL_NOTIFY_OFFSET]
			+ PAGE_SIZE);
		ucontext->ext_sqdb_offset_last =
			((uintptr_t)nbl_dev->rf->sc_dev.hw_regs[NBL_NOTIFY_OFFSET]
			+ NBL_RDMA_NORMAL_NOTF_WIDTH - PAGE_SIZE);
		ucontext->ext_sqdb_alloced_num = 0;
	}

	if (ib_copy_to_udata(udata, &uresp,
			     min(sizeof(uresp), udata->outlen))) {
		rdma_user_mmap_entry_remove(ucontext->db_mmap_entry);
		return -EFAULT;
	}

	ucontext->is_lat_process = is_lat_process();
	return 0;
}

void nbl_ib_dealloc_ucontext(struct ib_ucontext *ibcontext)
{
	struct nbl_ucontext *ucontext = to_ucontext(ibcontext);

	nbl_clear_shadow_mmap(ucontext);
	/* do some other thing maybe */
	rdma_user_mmap_entry_remove(ucontext->db_mmap_entry);
}

void nbl_ib_disassociate_ucontext(struct ib_ucontext *ibctx)
{
	/* nothing to do, just return, maybe add some work in the future */
}

static void nbl_get_dev_fw_str_by_ethtool(struct ib_device *dev, char *str)
{
	struct nbl_device *nbl_dev = to_nbl_dev(dev);
	struct nbl_pci_f *rf = nbl_dev->rf;

	if (NBL_RF_TO_HW_VER(rf) != NBL_VER_2)
		return;

	if (nbl_dev->netdev->ethtool_ops &&
	    nbl_dev->netdev->ethtool_ops->get_drvinfo) {
		struct ethtool_drvinfo info;

		nbl_dev->netdev->ethtool_ops->get_drvinfo(nbl_dev->netdev,
							  &info);
		snprintf(str, EMP_FW_VERSION_NAME_MAX, "%s", info.fw_version);
	} else {
		snprintf(str, IB_FW_VERSION_NAME_MAX, "%u.%u",
			 NBL_RDMA_FW_MAJOR_VER, NBL_RDMA_FW_MINOR_VER);
	}
}

void nbl_ib_get_dev_fw_str(struct ib_device *dev, char *str)
{
	struct nbl_device *nbl_dev = to_nbl_dev(dev);
	struct nbl_pci_f *rf = nbl_dev->rf;
	__u32 major, minor;

	if (NBL_RF_TO_HW_VER(rf) >= NBL_VER_3) {
		major = rf->sc_dev.fw_ver >> 32;
		minor = rf->sc_dev.fw_ver;
		snprintf(str, IB_FW_VERSION_NAME_MAX, "%08x-%08x", major, minor);
	} else {
		nbl_get_dev_fw_str_by_ethtool(dev, str);
	}
}

int nbl_ib_query_pkey(struct ib_device *dev, u32 port, u16 index, u16 *pkey)
{
	if (index >= NBL_PKEY_TBL_SZ)
		return -EINVAL;

	*pkey = NBL_DEFAULT_PKEY;
	return 0;
}

int nbl_ib_get_port_immutable(struct ib_device *dev, u32 port_num,
			      struct ib_port_immutable *immutable)
{
	struct ib_port_attr attr;
	int err;

	err = ib_query_port(dev, port_num, &attr);
	if (err)
		return err;

	immutable->core_cap_flags = RDMA_CORE_PORT_IBA_NBL;
	immutable->max_mad_size = IB_MGMT_MAD_SIZE;
	immutable->pkey_tbl_len = attr.pkey_tbl_len;
	immutable->gid_tbl_len = attr.gid_tbl_len;

	return 0;
}

enum rdma_link_layer nbl_ib_get_link_layer(struct ib_device *dev, u32 port_num)
{
	return IB_LINK_LAYER_ETHERNET;
}

int nbl_ib_modify_port(struct ib_device *dev, u32 port, int mask,
			struct ib_port_modify *props)
{
	/* For ethernet ports, qkey violation and port capabilities are meaningless */
	return 0;
}

static void nbl_get_fw_ver_string_to_u64(struct ib_device *dev, u64 *fw_ver)
{
	struct nbl_device *nbl_dev = to_nbl_dev(dev);
	struct nbl_pci_f *rf = nbl_dev->rf;
	char fw_ver_str[IB_FW_VERSION_NAME_MAX] = {0};

	if (NBL_RF_TO_HW_VER(rf) == NBL_VER_2) {
		nbl_get_dev_fw_str_by_ethtool(dev, fw_ver_str);
		rf->sc_dev.fw_ver = *(u64 *)fw_ver_str;
	}
	*fw_ver = nbl_dev->rf->sc_dev.fw_ver;
}

int nbl_ib_query_device(struct ib_device *dev, struct ib_device_attr *props,
			struct ib_udata *udata)
{
	struct nbl_device *nbl_dev = to_nbl_dev(dev);
	struct nbl_pci_f *rf = nbl_dev->rf;
	struct pci_dev *pcidev = nbl_dev->rf->pcidev;
	struct nbl_hw_attrs *hw_attrs = &rf->sc_dev.hw_attrs;

	memset(props, 0, sizeof(*props));
	addrconf_addr_eui48((u8 *)&props->sys_image_guid,
			    nbl_dev->netdev->dev_addr);
	nbl_get_fw_ver_string_to_u64(dev, &props->fw_ver);

	props->device_cap_flags = nbl_dev->device_cap_flags;
	props->vendor_id = pcidev->vendor;
	props->vendor_part_id = pcidev->device;

	props->hw_ver = pcidev->revision;
	props->page_size_cap = SZ_4K | SZ_2M;
	props->max_mr_size = hw_attrs->max_mr_size;
	props->max_qp = rf->max_qp - rf->used_qps - NBL_UMR_QP_RSV;
	if (rf->internal_cfg & NBL_DEV_MAX_QP_FLAG)
		props->max_qp = DRACO_POC_MAX_QP_NUM;
	props->max_qp_wr = hw_attrs->max_qp_wr;
	set_max_sge(props, rf);
	props->max_cq = rf->max_cq - rf->used_cqs;
	props->max_mr = rf->max_mr - atomic_read(&rf->used_mrs_a);
	props->max_mw = props->max_mr;
	props->max_pd = rf->max_pd - rf->used_pds;
	props->max_sge_rd = hw_attrs->uk_attrs.max_hw_read_sges;
	props->max_qp_rd_atom = hw_attrs->max_qp_dest_rd_atom; /*max recv read/atomic ost*/
	props->max_qp_init_rd_atom = hw_attrs->max_qp_rd_atom;/*max send read/atomic ost*/
	props->max_res_rd_atom = props->max_qp_rd_atom * props->max_qp;

	props->max_pkeys = NBL_PKEY_TBL_SZ;
	props->max_ah = rf->max_ah;
	props->atomic_cap = nbl_product_cap_enabled(nbl_dev->rf,
					    NBL_PRODUCT_CAP_ATOMIC) ?
			    IB_ATOMIC_GLOB : IB_ATOMIC_NONE;
	props->masked_atomic_cap = props->atomic_cap;
	/* TODO, if need
	 * add max_mcast_grp, max_mcast_qp_attach,
	 * max_total_mcast_qp_attach,
	 * timestamp_mask
	 */
	props->max_fast_reg_page_list_len = NBL_MAX_PAGES_PER_FMR;

	props->max_srq = rf->max_srq;
	props->max_srq_wr = hw_attrs->uk_attrs.max_hw_srq_wr;
	props->max_srq_sge = hw_attrs->uk_attrs.max_hw_wq_sges;
	props->max_cqe = rf->max_cqe - NBL_CQ_LOAD_RSVD_V2;

	return 0;
}

static struct net_device *nbl_device_get_netdev(struct ib_device *ib_dev,
						u32 port)
{
	struct net_device *res;

	if (!rdma_is_port_valid(ib_dev, port))
		return NULL;


	/*
	 * New drivers should use ib_device_set_netdev() not the legacy
	 * get_netdev().
	 */
	if (ib_dev->ops.get_netdev)
		res = ib_dev->ops.get_netdev(ib_dev, port);

	/*
	 * If we are starting to unregister expedite things by preventing
	 * propagation of an unregistering netdev.
	 */
	if (res && res->reg_state != NETREG_REGISTERED) {
		dev_put(res);
		return NULL;
	}

	return res;
}

static int nbl_get_eth_speed(struct ib_device *dev, u32 port_num, u16 *speed,
			     u8 *width)
{
	int rc;
	u32 netdev_speed;
	struct net_device *netdev;
	struct ethtool_link_ksettings lksettings;

	if (rdma_port_get_link_layer(dev, port_num) != IB_LINK_LAYER_ETHERNET)
		return -EINVAL;

	netdev = nbl_device_get_netdev(dev, port_num);
	if (!netdev) {
		nbl_pr_dbg(
			"not find netdev use default speed(EDR 4X) , port_num=%u\n",
			port_num);
		*width = IB_WIDTH_4X;
		*speed = IB_SPEED_EDR;
		return 0;
	}

	rtnl_lock();
	rc = __ethtool_get_link_ksettings(netdev, &lksettings);
	rtnl_unlock();

	dev_put(netdev);

	if (!rc && lksettings.base.speed != (u32)SPEED_UNKNOWN)
		netdev_speed = lksettings.base.speed;
	else
		netdev_speed = SPEED_1000;

	nbl_pr_dbg("%s rc:%d, speed is %u\n", netdev->name, rc, netdev_speed);

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
		*width = IB_WIDTH_4X;
		*speed = IB_SPEED_NDR;
	}
	return 0;
}

int nbl_ib_query_port(struct ib_device *dev, u32 port,
		      struct ib_port_attr *props)
{
	struct nbl_device *nbl_dev = to_nbl_dev(dev);
	struct net_device *net_dev = nbl_dev->netdev;

	props->max_mtu = IB_MTU_4096;
	props->active_mtu = iboe_get_mtu(net_dev->mtu);
	props->lid = NBL_PORT_BASE_LID;
	props->lmc = NBL_DEF_LID_MASK_CNT;
	props->sm_lid = NBL_DEF_SM_LID;
	props->sm_sl = NBL_DEF_SM_SL;

	if (netif_carrier_ok(net_dev) && netif_running(net_dev)) {
		props->state = IB_PORT_ACTIVE;
		props->phys_state = IB_PORT_PHYS_STATE_LINK_UP;
	} else {
		props->state = IB_PORT_DOWN;
		props->phys_state = IB_PORT_PHYS_STATE_DISABLED;
	}

	if (nbl_dev->rf->product->product_type == PRODUCT_TYPE_SNIC ||
	    nbl_dev->rf->product->host_id == HOST_ID_TYPE_ECPU) {
		if (nbl_dev->active_speed) {
			props->active_speed = nbl_dev->active_speed;
			props->active_width = nbl_dev->active_width;
		} else {
			props->active_width     = IB_WIDTH_4X;
			props->active_speed     = IB_SPEED_QDR;
			nbl_get_eth_speed(dev, port, (u16 *)&props->active_speed,
									&props->active_width);
			if (props->active_speed != IB_SPEED_SDR) {
				nbl_dev->active_speed = props->active_speed;
				nbl_dev->active_width = props->active_width;
			}
		}
	}

	props->gid_tbl_len = nbl_dev->rf->product->limits->gid_per_function;
	props->ip_gids = true;
	props->port_cap_flags |= IB_PORT_CM_SUP;
	props->pkey_tbl_len = NBL_PKEY_TBL_SZ;
	props->qkey_viol_cntr = 0;
	props->max_msg_sz = nbl_dev->rf->sc_dev.hw_attrs.max_hw_outbound_msg_size;

	return 0;
}



struct net_device *nbl_ib_get_netdev(struct ib_device *ibdev, u32 port_num)
{
	struct nbl_device *nbl_dev = to_nbl_dev(ibdev);

	if (nbl_dev->netdev) {
		dev_hold(nbl_dev->netdev);
		return nbl_dev->netdev;
	}

	nbl_ib_warn(&nbl_dev->rf->sc_dev, "the nbl net_device is NULL.\n");
	return NULL;
}
