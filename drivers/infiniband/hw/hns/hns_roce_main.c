/*
 * Copyright (c) 2016 Hisilicon Limited.
 * Copyright (c) 2007, 2008 Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include <linux/acpi.h>
#include <linux/module.h>
#include <rdma/ib_addr.h>
#include <rdma/ib_smi.h>
#include <rdma/ib_user_verbs.h>
#include <rdma/ib_cache.h>
#include <rdma/uverbs_ioctl.h>

#include "hnae3.h"
#include "hns_roce_common.h"
#include "hns_roce_device.h"
#include "hns_roce_hem.h"
#include "hns_roce_hw_v2.h"
#include "hns_roce_dca.h"

static struct net_device *hns_roce_get_netdev(struct ib_device *ib_dev,
					      u8 port_num)
{
	struct hns_roce_dev *hr_dev = to_hr_dev(ib_dev);
	struct net_device *ndev;

	if (port_num < 1 || port_num > hr_dev->caps.num_ports)
		return NULL;

	ndev = hr_dev->hw->get_bond_netdev(hr_dev);

	rcu_read_lock();

	if (!ndev)
		ndev = get_hr_netdev(hr_dev, port_num - 1);

	dev_hold(ndev);

	rcu_read_unlock();

	return ndev;
}

static int hns_roce_set_mac(struct hns_roce_dev *hr_dev, u32 port,
			    const u8 *addr)
{
	u8 phy_port;
	u32 i;

	if (hr_dev->pci_dev->revision >= PCI_REVISION_ID_HIP09)
		return 0;

	if (!memcmp(hr_dev->dev_addr[port], addr, ETH_ALEN))
		return 0;

	for (i = 0; i < ETH_ALEN; i++)
		hr_dev->dev_addr[port][i] = addr[i];

	phy_port = hr_dev->iboe.phy_port[port];
	return hr_dev->hw->set_mac(hr_dev, phy_port, addr);
}

static int hns_roce_add_gid(const struct ib_gid_attr *attr, void **context)
{
	struct hns_roce_dev *hr_dev = to_hr_dev(attr->device);
	u8 port = attr->port_num - 1;
	int ret;

	if (port >= hr_dev->caps.num_ports)
		return -EINVAL;

	ret = hr_dev->hw->set_gid(hr_dev, attr->index, &attr->gid, attr);

	return ret;
}

static int hns_roce_del_gid(const struct ib_gid_attr *attr, void **context)
{
	struct hns_roce_dev *hr_dev = to_hr_dev(attr->device);
	u8 port = attr->port_num - 1;
	int ret;

	if (port >= hr_dev->caps.num_ports)
		return -EINVAL;

	ret = hr_dev->hw->set_gid(hr_dev, attr->index, NULL, NULL);

	return ret;
}

static enum ib_port_state get_upper_port_state(struct hns_roce_dev *hr_dev)
{
	struct net_device *net_dev = get_hr_netdev(hr_dev, 0);
	struct hns_roce_bond_group *bond_grp;
	u8 bus_num = get_hr_bus_num(hr_dev);
	struct net_device *upper;

	bond_grp = hns_roce_get_bond_grp(net_dev, bus_num);
	upper = bond_grp ? bond_grp->upper_dev : NULL;
	if (upper)
		return get_port_state(upper);

	return IB_PORT_ACTIVE;
}

static int handle_en_event(struct net_device *netdev,
			   struct hns_roce_dev *hr_dev,
			   u32 port, unsigned long dev_event)
{
	struct device *dev = hr_dev->dev;
	enum ib_port_state port_state;
	struct ib_event event;
	unsigned long flags;
	int ret = 0;

	if (!netdev) {
		dev_err(dev, "Can't find netdev on port(%u)!\n", port);
		return -ENODEV;
	}

	switch (dev_event) {
	case NETDEV_REGISTER:
	case NETDEV_CHANGEADDR:
		ret = hns_roce_set_mac(hr_dev, port, netdev->dev_addr);
		break;
	case NETDEV_UP:
	case NETDEV_CHANGE:
		ret = hns_roce_set_mac(hr_dev, port, netdev->dev_addr);
		if (ret)
			return ret;
		fallthrough;
	case NETDEV_DOWN:
		port_state = get_port_state(netdev);

		spin_lock_irqsave(&hr_dev->iboe.lock, flags);
		if (hr_dev->iboe.port_state[port] == port_state) {
			spin_unlock_irqrestore(&hr_dev->iboe.lock, flags);
			return NOTIFY_DONE;
		}
		hr_dev->iboe.port_state[port] = port_state;
		spin_unlock_irqrestore(&hr_dev->iboe.lock, flags);

		event.device = &hr_dev->ib_dev;
		event.event = (port_state == IB_PORT_ACTIVE) ?
			      IB_EVENT_PORT_ACTIVE : IB_EVENT_PORT_ERR;
		event.element.port_num = to_rdma_port_num(port);
		ib_dispatch_event(&event);
		break;
	case NETDEV_UNREGISTER:
		break;
	default:
		dev_dbg(dev, "NETDEV event = 0x%x!\n", (u32)(dev_event));
		break;
	}

	return ret;
}

static int hns_roce_netdev_event(struct notifier_block *self,
				 unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct hns_roce_bond_group *bond_grp;
	struct hns_roce_ib_iboe *iboe = NULL;
	struct hns_roce_dev *hr_dev = NULL;
	struct net_device *upper = NULL;
	int ret;
	u8 port;

	hr_dev = container_of(self, struct hns_roce_dev, iboe.nb);
	iboe = &hr_dev->iboe;
	if (hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_BOND) {
		bond_grp = hns_roce_get_bond_grp(get_hr_netdev(hr_dev, 0),
						 get_hr_bus_num(hr_dev));
		upper = bond_grp ? bond_grp->upper_dev : NULL;
	}

	for (port = 0; port < hr_dev->caps.num_ports; port++) {
		if ((!upper && dev == iboe->netdevs[port]) ||
		    (upper && dev == upper)) {
			ret = handle_en_event(dev, hr_dev, port, event);
			if (ret)
				return NOTIFY_DONE;
			break;
		}
	}

	return NOTIFY_DONE;
}

static int hns_roce_setup_mtu_mac(struct hns_roce_dev *hr_dev)
{
	struct net_device *net_dev;
	int ret;
	u8 i;

	for (i = 0; i < hr_dev->caps.num_ports; i++) {
		hr_dev->iboe.port_state[i] = IB_PORT_DOWN;
		net_dev = get_hr_netdev(hr_dev, i);
		ret = hns_roce_set_mac(hr_dev, i, net_dev->dev_addr);
		if (ret)
			return ret;
	}

	return 0;
}

static int set_attrx(struct hns_roce_dev *hr_dev, struct ib_udata *uhw)
{
	struct hns_roce_ib_query_device_resp resp = {};
	size_t uhw_outlen;

	if (!uhw || !uhw->outlen)
		return 0;

	uhw_outlen = uhw->outlen;
	resp.len = sizeof(resp.comp_mask) + sizeof(resp.len);
	if (uhw_outlen < resp.len)
		return -EINVAL;

	if (uhw->inlen && !ib_is_udata_cleared(uhw, 0, uhw->inlen))
		return -EINVAL;

	if (uhw_outlen >= offsetofend(typeof(resp), hw_id)) {
		resp.len += sizeof(resp.hw_id);
		resp.hw_id.chip_id = hr_dev->chip_id;
		resp.hw_id.die_id = hr_dev->die_id;
		resp.hw_id.func_id = hr_dev->func_id;
	}

	return ib_copy_to_udata(uhw, &resp, resp.len);
}

static int hns_roce_query_device(struct ib_device *ib_dev,
				 struct ib_device_attr *props,
				 struct ib_udata *uhw)
{
	struct hns_roce_dev *hr_dev = to_hr_dev(ib_dev);

	memset(props, 0, sizeof(*props));

	props->fw_ver = hr_dev->caps.fw_ver;
	props->sys_image_guid = cpu_to_be64(hr_dev->sys_image_guid);
	props->max_mr_size = (u64)(~(0ULL));
	props->page_size_cap = hr_dev->caps.page_size_cap;
	props->vendor_id = hr_dev->vendor_id;
	props->vendor_part_id = hr_dev->vendor_part_id;
	props->hw_ver = hr_dev->hw_rev;
	props->max_qp = hr_dev->caps.num_qps;
	props->max_qp_wr = hr_dev->caps.max_wqes;
	props->device_cap_flags = IB_DEVICE_PORT_ACTIVE_EVENT |
				  IB_DEVICE_RC_RNR_NAK_GEN;
	props->max_send_sge = hr_dev->caps.max_sq_sg;
	props->max_recv_sge = hr_dev->caps.max_rq_sg;
	props->max_sge_rd = 1;
	props->max_cq = hr_dev->caps.num_cqs;
	props->max_cqe = hr_dev->caps.max_cqes;
	props->max_mr = hr_dev->caps.num_mtpts;
	props->max_pd = hr_dev->caps.num_pds;
	props->max_qp_rd_atom = hr_dev->caps.max_qp_dest_rdma;
	props->max_qp_init_rd_atom = hr_dev->caps.max_qp_init_rdma;
	props->atomic_cap = hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_ATOMIC ?
			    IB_ATOMIC_HCA : IB_ATOMIC_NONE;
	props->max_pkeys = 1;
	props->local_ca_ack_delay = hr_dev->caps.local_ca_ack_delay;
	props->max_ah = INT_MAX;
	props->cq_caps.max_cq_moderation_period = HNS_ROCE_MAX_CQ_PERIOD;
	props->cq_caps.max_cq_moderation_count = HNS_ROCE_MAX_CQ_COUNT;
	if (hr_dev->pci_dev->revision == PCI_REVISION_ID_HIP08)
		props->cq_caps.max_cq_moderation_period = HNS_ROCE_MAX_CQ_PERIOD_HIP08;

	if (hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_SRQ) {
		props->max_srq = hr_dev->caps.num_srqs;
		props->max_srq_wr = hr_dev->caps.max_srq_wrs;
		props->max_srq_sge = hr_dev->caps.max_srq_sges;
	}

	if (hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_LIMIT_BANK) {
		props->max_cq >>= 1;
		props->max_qp >>= 1;
	}

	if (hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_FRMR &&
	    hr_dev->pci_dev->revision >= PCI_REVISION_ID_HIP09) {
		props->device_cap_flags |= IB_DEVICE_MEM_MGT_EXTENSIONS;
		props->max_fast_reg_page_list_len = HNS_ROCE_FRMR_MAX_PA;
	}

	if (hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_XRC)
		props->device_cap_flags |= IB_DEVICE_XRC;

	return set_attrx(hr_dev, uhw);
}

static int hns_roce_query_port(struct ib_device *ib_dev, u8 port_num,
			       struct ib_port_attr *props)
{
	struct hns_roce_dev *hr_dev = to_hr_dev(ib_dev);
	struct device *dev = hr_dev->dev;
	struct net_device *net_dev;
	unsigned long flags;
	enum ib_mtu mtu;
	u8 port;
	int ret;

	port = port_num - 1;

	/* props being zeroed by the caller, avoid zeroing it here */

	props->max_mtu = hr_dev->caps.max_mtu;
	props->gid_tbl_len = hr_dev->caps.gid_table_len[port];
	props->port_cap_flags = IB_PORT_CM_SUP | IB_PORT_REINIT_SUP |
				IB_PORT_VENDOR_CLASS_SUP |
				IB_PORT_BOOT_MGMT_SUP;
	props->max_msg_sz = HNS_ROCE_MAX_MSG_LEN;
	props->pkey_tbl_len = 1;
	ret = ib_get_eth_speed(ib_dev, port_num, &props->active_speed,
			       &props->active_width);
	if (ret)
		ibdev_warn(ib_dev, "failed to get speed, ret = %d.\n", ret);

	net_dev = hr_dev->hw->get_bond_netdev(hr_dev);

	spin_lock_irqsave(&hr_dev->iboe.lock, flags);

	if (!net_dev)
		net_dev = get_hr_netdev(hr_dev, port);
	if (!net_dev) {
		spin_unlock_irqrestore(&hr_dev->iboe.lock, flags);
		dev_err(dev, "Find netdev %u failed!\n", port);
		return -EINVAL;
	}

	mtu = iboe_get_mtu(net_dev->mtu);
	props->active_mtu = mtu ? min(props->max_mtu, mtu) : IB_MTU_256;
	props->state = get_port_state(net_dev);

	if (hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_BOND &&
	    props->state == IB_PORT_ACTIVE)
		props->state = get_upper_port_state(hr_dev);

	props->phys_state = props->state == IB_PORT_ACTIVE ?
				    IB_PORT_PHYS_STATE_LINK_UP :
				    IB_PORT_PHYS_STATE_DISABLED;

	spin_unlock_irqrestore(&hr_dev->iboe.lock, flags);

	return 0;
}

static enum rdma_link_layer hns_roce_get_link_layer(struct ib_device *device,
						    u8 port_num)
{
	return IB_LINK_LAYER_ETHERNET;
}

static int hns_roce_query_pkey(struct ib_device *ib_dev, u8 port, u16 index,
			       u16 *pkey)
{
	if (index > 0)
		return -EINVAL;

	*pkey = PKEY_ID;

	return 0;
}

static int hns_roce_modify_device(struct ib_device *ib_dev, int mask,
				  struct ib_device_modify *props)
{
	unsigned long flags;

	if (mask & ~IB_DEVICE_MODIFY_NODE_DESC)
		return -EOPNOTSUPP;

	if (mask & IB_DEVICE_MODIFY_NODE_DESC) {
		spin_lock_irqsave(&to_hr_dev(ib_dev)->sm_lock, flags);
		memcpy(ib_dev->node_desc, props->node_desc, NODE_DESC_SIZE);
		spin_unlock_irqrestore(&to_hr_dev(ib_dev)->sm_lock, flags);
	}

	return 0;
}

struct hns_user_mmap_entry *
hns_roce_user_mmap_entry_insert(struct ib_ucontext *ucontext, u64 address,
				size_t length,
				enum hns_roce_mmap_type mmap_type)
{
	struct hns_user_mmap_entry *entry;
	int ret;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return NULL;

	entry->address = address;
	entry->mmap_type = mmap_type;

	switch (mmap_type) {
	/* pgoff 0 must be used by DB for compatibility */
	case HNS_ROCE_MMAP_TYPE_DB:
		ret = rdma_user_mmap_entry_insert_exact(
				ucontext, &entry->rdma_entry, length, 0);
		break;
	case HNS_ROCE_MMAP_TYPE_DWQE:
	case HNS_ROCE_MMAP_TYPE_DCA:
	case HNS_ROCE_MMAP_TYPE_RESET:
		ret = rdma_user_mmap_entry_insert_range(
				ucontext, &entry->rdma_entry, length, 1,
				U32_MAX);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	if (ret) {
		kfree(entry);
		return NULL;
	}

	return entry;
}

static void hns_roce_dealloc_uar_entry(struct hns_roce_ucontext *context)
{
	if (context->db_mmap_entry)
		rdma_user_mmap_entry_remove(
			&context->db_mmap_entry->rdma_entry);
	if (context->dca_ctx.dca_mmap_entry)
		rdma_user_mmap_entry_remove(
			&context->dca_ctx.dca_mmap_entry->rdma_entry);
}

static int hns_roce_alloc_uar_entry(struct ib_ucontext *uctx)
{
	struct hns_roce_ucontext *context = to_hr_ucontext(uctx);
	u64 address;

	address = context->uar.pfn << PAGE_SHIFT;
	context->db_mmap_entry = hns_roce_user_mmap_entry_insert(
		uctx, address, PAGE_SIZE, HNS_ROCE_MMAP_TYPE_DB);
	if (!context->db_mmap_entry)
		return -ENOMEM;

	return 0;
}

static void hns_roce_dealloc_reset_entry(struct hns_roce_ucontext *context)
{
	if (context->reset_mmap_entry)
		rdma_user_mmap_entry_remove(&context->reset_mmap_entry->rdma_entry);
}

static int hns_roce_alloc_reset_entry(struct ib_ucontext *uctx)
{
	struct hns_roce_ucontext *context = to_hr_ucontext(uctx);
	struct hns_roce_dev *hr_dev = to_hr_dev(uctx->device);

	context->reset_mmap_entry = hns_roce_user_mmap_entry_insert(uctx,
		(u64)hr_dev->reset_kaddr, PAGE_SIZE, HNS_ROCE_MMAP_TYPE_RESET);

	if (!context->reset_mmap_entry)
		return -ENOMEM;

	return 0;
}

static void ucontext_set_resp(struct ib_ucontext *uctx,
			      struct hns_roce_ib_alloc_ucontext_resp *resp)
{
	struct hns_roce_ucontext *context = to_hr_ucontext(uctx);
	struct hns_roce_dev *hr_dev = to_hr_dev(uctx->device);
	struct rdma_user_mmap_entry *rdma_entry;

	resp->qp_tab_size = hr_dev->caps.num_qps;
	resp->srq_tab_size = hr_dev->caps.num_srqs;
	resp->cqe_size = hr_dev->caps.cqe_sz;
	resp->mac_type = hr_dev->mac_type;

	if (hr_dev->pci_dev->revision >= PCI_REVISION_ID_HIP09)
		resp->congest_type = hr_dev->caps.congest_type;

	if (context->dca_ctx.dca_mmap_entry) {
		resp->dca_qps = context->dca_ctx.max_qps;
		resp->dca_mmap_size = PAGE_SIZE * context->dca_ctx.status_npage;
		rdma_entry = &context->dca_ctx.dca_mmap_entry->rdma_entry;
		resp->dca_mmap_key = rdma_user_mmap_get_offset(rdma_entry);
	}

	if (context->reset_mmap_entry) {
		rdma_entry = &context->reset_mmap_entry->rdma_entry;
		resp->reset_mmap_key = rdma_user_mmap_get_offset(rdma_entry);
	}
}

static u32 get_udca_max_qps(struct hns_roce_dev *hr_dev,
			    struct hns_roce_ib_alloc_ucontext *ucmd)
{
	u32 qp_num;

	if (ucmd->comp & HNS_ROCE_ALLOC_UCTX_COMP_DCA_MAX_QPS) {
		qp_num = ucmd->dca_max_qps;
		if (!qp_num)
			qp_num = hr_dev->caps.num_qps;
	} else {
		qp_num = 0;
	}

	return qp_num;
}

static void hns_roce_get_uctx_config(struct hns_roce_dev *hr_dev,
				struct hns_roce_ucontext *context,
				struct hns_roce_ib_alloc_ucontext *ucmd,
				struct hns_roce_ib_alloc_ucontext_resp *resp)
{
	if (hr_dev->pci_dev->revision >= PCI_REVISION_ID_HIP09)
		context->config = ucmd->config & HNS_ROCE_EXSGE_FLAGS;

	if (context->config & HNS_ROCE_EXSGE_FLAGS) {
		resp->config |= HNS_ROCE_RSP_EXSGE_FLAGS;
		resp->max_inline_data = hr_dev->caps.max_sq_inline;
	}

	if (hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_RQ_INLINE) {
		context->config |= ucmd->config & HNS_ROCE_RQ_INLINE_FLAGS;
		if (context->config & HNS_ROCE_RQ_INLINE_FLAGS)
			resp->config |= HNS_ROCE_RSP_RQ_INLINE_FLAGS;
	}

	if (hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_CQE_INLINE) {
		context->config |= ucmd->config & HNS_ROCE_CQE_INLINE_FLAGS;
		if (context->config & HNS_ROCE_CQE_INLINE_FLAGS)
			resp->config |= HNS_ROCE_RSP_CQE_INLINE_FLAGS;
	}

	if (hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_DCA_MODE) {
		context->config |= ucmd->config & HNS_ROCE_UCTX_CONFIG_DCA;
		if (context->config & HNS_ROCE_UCTX_CONFIG_DCA)
			resp->config |= HNS_ROCE_UCTX_RSP_DCA_FLAGS;
	}

	if (ucmd->config & HNS_ROCE_UCTX_DYN_QP_PGSZ) {
		context->config |= HNS_ROCE_UCTX_DYN_QP_PGSZ;
		resp->config |=  HNS_ROCE_UCTX_RSP_DYN_QP_PGSZ;
	}
}

static int hns_roce_alloc_ucontext(struct ib_ucontext *uctx,
				   struct ib_udata *udata)
{
	struct hns_roce_ucontext *context = to_hr_ucontext(uctx);
	struct hns_roce_dev *hr_dev = to_hr_dev(uctx->device);
	struct hns_roce_ib_alloc_ucontext_resp resp = {};
	struct hns_roce_ib_alloc_ucontext ucmd = {};
	int ret = -EAGAIN;

	if (!hr_dev->active)
		goto error_fail_uar_alloc;

	context->pid = current->pid;
	INIT_LIST_HEAD(&context->list);

	ret = ib_copy_from_udata(&ucmd, udata,
				 min(udata->inlen, sizeof(ucmd)));
	if (ret)
		goto error_fail_uar_alloc;

	hns_roce_get_uctx_config(hr_dev, context, &ucmd, &resp);

	ret = hns_roce_uar_alloc(hr_dev, &context->uar);
	if (ret)
		goto error_fail_uar_alloc;

	ret = hns_roce_alloc_uar_entry(uctx);
	if (ret)
		goto error_fail_uar_entry;

	if (hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_CQ_RECORD_DB ||
	    hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_QP_RECORD_DB) {
		INIT_LIST_HEAD(&context->page_list);
		mutex_init(&context->page_mutex);
	}

	hns_roce_register_udca(hr_dev, get_udca_max_qps(hr_dev, &ucmd),
			       context);

	ret = hns_roce_alloc_reset_entry(uctx);
	if (ret)
		goto error_fail_reset_entry;

	ucontext_set_resp(uctx, &resp);
	ret = ib_copy_to_udata(udata, &resp, min(udata->outlen, sizeof(resp)));
	if (ret)
		goto error_fail_copy_to_udata;

	mutex_lock(&hr_dev->uctx_list_mutex);
	list_add(&context->list, &hr_dev->uctx_list);
	mutex_unlock(&hr_dev->uctx_list_mutex);

	hns_roce_register_uctx_debugfs(hr_dev, context);
	hns_roce_get_cq_bankid_for_uctx(context);

	return 0;

error_fail_copy_to_udata:
	hns_roce_unregister_udca(hr_dev, context);
	hns_roce_dealloc_reset_entry(context);

error_fail_reset_entry:
	if (hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_CQ_RECORD_DB ||
	    hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_QP_RECORD_DB)
		mutex_destroy(&context->page_mutex);
	hns_roce_dealloc_uar_entry(context);

error_fail_uar_entry:
	ida_free(&hr_dev->uar_ida.ida, (int)context->uar.logic_idx);

error_fail_uar_alloc:
	atomic64_inc(&hr_dev->dfx_cnt[HNS_ROCE_DFX_UCTX_ALLOC_ERR_CNT]);

	return ret;
}

static void hns_roce_dealloc_ucontext(struct ib_ucontext *ibcontext)
{
	struct hns_roce_ucontext *context = to_hr_ucontext(ibcontext);
	struct hns_roce_dev *hr_dev = to_hr_dev(ibcontext->device);

	mutex_lock(&hr_dev->uctx_list_mutex);
	list_del(&context->list);
	mutex_unlock(&hr_dev->uctx_list_mutex);

	hns_roce_unregister_uctx_debugfs(context);

	hns_roce_unregister_udca(hr_dev, context);
	if (hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_CQ_RECORD_DB ||
	    hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_QP_RECORD_DB)
		mutex_destroy(&context->page_mutex);

	hns_roce_put_cq_bankid_for_uctx(context);
	hns_roce_dealloc_uar_entry(context);
	hns_roce_dealloc_reset_entry(context);

	ida_free(&hr_dev->uar_ida.ida, (int)context->uar.logic_idx);
}

static int mmap_dca(struct ib_ucontext *context, struct vm_area_struct *vma)
{
	struct hns_roce_ucontext *uctx = to_hr_ucontext(context);
	struct hns_roce_dca_ctx *ctx = &uctx->dca_ctx;
	struct page **pages;
	unsigned long num;
	int ret;

	if ((vma->vm_end - vma->vm_start != (ctx->status_npage * PAGE_SIZE) ||
	     !(vma->vm_flags & VM_SHARED)))
		return -EINVAL;

	if (!(vma->vm_flags & VM_WRITE) || (vma->vm_flags & VM_EXEC))
		return -EPERM;

	if (!ctx->buf_status)
		return -EOPNOTSUPP;

	pages = kcalloc(ctx->status_npage, sizeof(struct page *), GFP_KERNEL);
	if (!pages)
		return -ENOMEM;

	for (num = 0; num < ctx->status_npage; num++)
		pages[num] = virt_to_page(ctx->buf_status + num * PAGE_SIZE);

	ret = vm_insert_pages(vma, vma->vm_start, pages, &num);
	kfree(pages);
	return ret;
}

static int hns_roce_mmap(struct ib_ucontext *uctx, struct vm_area_struct *vma)
{
	struct hns_roce_dev *hr_dev = to_hr_dev(uctx->device);
	struct rdma_user_mmap_entry *rdma_entry;
	struct hns_user_mmap_entry *entry;
	phys_addr_t pfn;
	pgprot_t prot;
	int ret;

	rdma_entry = rdma_user_mmap_entry_get_pgoff(uctx, vma->vm_pgoff);
	if (!rdma_entry) {
		atomic64_inc(&hr_dev->dfx_cnt[HNS_ROCE_DFX_MMAP_ERR_CNT]);
		return -EINVAL;
	}

	entry = to_hns_mmap(rdma_entry);
	pfn = entry->address >> PAGE_SHIFT;

	switch (entry->mmap_type) {
	case HNS_ROCE_MMAP_TYPE_DB:
	case HNS_ROCE_MMAP_TYPE_DWQE:
		prot = pgprot_device(vma->vm_page_prot);
		break;
	case HNS_ROCE_MMAP_TYPE_DCA:
		ret = mmap_dca(uctx, vma);
		goto out;
	case HNS_ROCE_MMAP_TYPE_RESET:
		if (vma->vm_flags & (VM_WRITE | VM_EXEC)) {
			ret = -EINVAL;
			goto out;
		}

		prot = vma->vm_page_prot;
		pfn = page_to_pfn(hr_dev->reset_page);
		break;
	default:
		ret = -EINVAL;
		goto out;
	}

	ret = rdma_user_mmap_io(uctx, vma, pfn, rdma_entry->npages * PAGE_SIZE,
				prot, rdma_entry);

out:
	rdma_user_mmap_entry_put(rdma_entry);
	if (ret)
		atomic64_inc(&hr_dev->dfx_cnt[HNS_ROCE_DFX_MMAP_ERR_CNT]);

	return ret;
}

static void hns_roce_free_mmap(struct rdma_user_mmap_entry *rdma_entry)
{
	struct hns_user_mmap_entry *entry = to_hns_mmap(rdma_entry);

	kfree(entry);
}

static int hns_roce_port_immutable(struct ib_device *ib_dev, u8 port_num,
				   struct ib_port_immutable *immutable)
{
	struct ib_port_attr attr;
	int ret;

	ret = ib_query_port(ib_dev, port_num, &attr);
	if (ret)
		return ret;

	immutable->pkey_tbl_len = attr.pkey_tbl_len;
	immutable->gid_tbl_len = attr.gid_tbl_len;

	immutable->max_mad_size = IB_MGMT_MAD_SIZE;

	if (to_hr_dev(ib_dev)->mac_type == HNAE3_MAC_ROH)
		immutable->core_cap_flags = RDMA_CORE_PORT_IBA_ROCE_UDP_ENCAP;
	else if (to_hr_dev(ib_dev)->pci_dev->device == HNAE3_DEV_ID_RDMA_OVER_UBL_VF)
		immutable->core_cap_flags = RDMA_CORE_PORT_IBA_ROCE_UDP_ENCAP;
	else if (to_hr_dev(ib_dev)->caps.flags & HNS_ROCE_CAP_FLAG_ROCE_V1_V2)
		immutable->core_cap_flags = RDMA_CORE_PORT_IBA_ROCE |
					    RDMA_CORE_PORT_IBA_ROCE_UDP_ENCAP;
	else
		immutable->core_cap_flags = RDMA_CORE_PORT_IBA_ROCE;

	return 0;
}

static void hns_roce_disassociate_ucontext(struct ib_ucontext *ibcontext)
{
}

static void hns_roce_get_fw_ver(struct ib_device *device, char *str)
{
	u64 fw_ver = to_hr_dev(device)->caps.fw_ver;
	unsigned int major, minor, sub_minor;

	major = upper_32_bits(fw_ver);
	minor = high_16_bits(lower_32_bits(fw_ver));
	sub_minor = low_16_bits(fw_ver);

	snprintf(str, IB_FW_VERSION_NAME_MAX, "%u.%u.%04u", major, minor,
		 sub_minor);
}

#define HNS_ROCE_HW_CNT(ename, cname) \
	[HNS_ROCE_HW_##ename##_CNT] = cname

static const char *const hns_roce_port_stats_descs[] = {
	HNS_ROCE_HW_CNT(RX_RC_PKT, "rx_rc_pkt"),
	HNS_ROCE_HW_CNT(RX_UC_PKT, "rx_uc_pkt"),
	HNS_ROCE_HW_CNT(RX_UD_PKT, "rx_ud_pkt"),
	HNS_ROCE_HW_CNT(RX_XRC_PKT, "rx_xrc_pkt"),
	HNS_ROCE_HW_CNT(RX_PKT, "rx_pkt"),
	HNS_ROCE_HW_CNT(RX_ERR_PKT, "rx_err_pkt"),
	HNS_ROCE_HW_CNT(RX_CNP_PKT, "rx_cnp_pkt"),
	HNS_ROCE_HW_CNT(TX_RC_PKT, "tx_rc_pkt"),
	HNS_ROCE_HW_CNT(TX_UC_PKT, "tx_uc_pkt"),
	HNS_ROCE_HW_CNT(TX_UD_PKT, "tx_ud_pkt"),
	HNS_ROCE_HW_CNT(TX_XRC_PKT, "tx_xrc_pkt"),
	HNS_ROCE_HW_CNT(TX_PKT, "tx_pkt"),
	HNS_ROCE_HW_CNT(TX_ERR_PKT, "tx_err_pkt"),
	HNS_ROCE_HW_CNT(TX_CNP_PKT, "tx_cnp_pkt"),
	HNS_ROCE_HW_CNT(TRP_GET_MPT_ERR_PKT, "trp_get_mpt_err_pkt"),
	HNS_ROCE_HW_CNT(TRP_GET_IRRL_ERR_PKT, "trp_get_irrl_err_pkt"),
	HNS_ROCE_HW_CNT(ECN_DB, "ecn_doorbell"),
	HNS_ROCE_HW_CNT(RX_BUF, "rx_buffer"),
	HNS_ROCE_HW_CNT(TRP_RX_SOF, "trp_rx_sof"),
	HNS_ROCE_HW_CNT(CQ_CQE, "cq_cqe"),
	HNS_ROCE_HW_CNT(CQ_POE, "cq_poe"),
	HNS_ROCE_HW_CNT(CQ_NOTIFY, "cq_notify"),
};

static struct rdma_hw_stats *hns_roce_alloc_hw_port_stats(struct ib_device *device,
							  u8 port_num)
{
	struct hns_roce_dev *hr_dev = to_hr_dev(device);

	if (port_num > hr_dev->caps.num_ports) {
		ibdev_err(device, "invalid port num.\n");
		return NULL;
	}

	return rdma_alloc_hw_stats_struct(hns_roce_port_stats_descs,
					  ARRAY_SIZE(hns_roce_port_stats_descs),
					  RDMA_HW_STATS_DEFAULT_LIFESPAN);
}

static int hns_roce_get_hw_stats(struct ib_device *device,
				 struct rdma_hw_stats *stats,
				 u8 port, int index)
{
	struct hns_roce_dev *hr_dev = to_hr_dev(device);
	int num_counters = HNS_ROCE_HW_CNT_TOTAL;
	int ret;

	if (port == 0)
		return 0;

	if (port > hr_dev->caps.num_ports)
		return -EINVAL;

	ret = hr_dev->hw->query_hw_counter(hr_dev, stats->value, port,
					   &num_counters);
	if (ret) {
		ibdev_err(device, "failed to query hw counter, ret = %d.\n",
			  ret);
		return ret;
	}

	return num_counters;
}

static void hns_roce_unregister_device(struct hns_roce_dev *hr_dev,
				       bool bond_cleanup)
{
	struct net_device *net_dev = get_hr_netdev(hr_dev, 0);
	struct hns_roce_ib_iboe *iboe = &hr_dev->iboe;
	struct hns_roce_v2_priv *priv = hr_dev->priv;
	struct hns_roce_bond_group *bond_grp;
	u8 bus_num = get_hr_bus_num(hr_dev);
	int i;

	if (!(hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_BOND))
		goto normal_unregister;

	bond_grp = hns_roce_get_bond_grp(net_dev, bus_num);
	if (!bond_grp)
		goto normal_unregister;

	if (bond_cleanup) {
		/* To avoid the loss of other slave devices when main_hr_dev
		 * is unregistered, re-initialized the remaining slaves before
		 * the bond resources cleanup.
		 */
		cancel_delayed_work_sync(&bond_grp->bond_work);
		mutex_lock(&bond_grp->bond_mutex);
		bond_grp->bond_state = HNS_ROCE_BOND_NOT_BONDED;
		mutex_unlock(&bond_grp->bond_mutex);
		for (i = 0; i < ROCE_BOND_FUNC_MAX; i++) {
			net_dev = bond_grp->bond_func_info[i].net_dev;
			if (net_dev && net_dev != iboe->netdevs[0])
				hns_roce_bond_init_client(bond_grp, i);
		}
		hns_roce_cleanup_bond(bond_grp);
	} else if (priv->handle->rinfo.reset_state ==
		   HNS_ROCE_STATE_RST_UNINIT) {
		bond_grp->main_hr_dev = NULL;
	}

normal_unregister:
	hr_dev->active = false;
	unregister_netdevice_notifier(&iboe->nb);
	ib_unregister_device(&hr_dev->ib_dev);
}

static const struct uapi_definition hns_roce_uapi_defs[] = {
	UAPI_DEF_CHAIN(hns_roce_dca_uapi_defs),
	{}
};

static const struct ib_device_ops hns_roce_dev_ops = {
	.owner = THIS_MODULE,
	.driver_id = RDMA_DRIVER_HNS,
	.uverbs_abi_ver = 1,
	.uverbs_no_driver_id_binding = 1,

	.get_dev_fw_str = hns_roce_get_fw_ver,
	.add_gid = hns_roce_add_gid,
	.alloc_pd = hns_roce_alloc_pd,
	.alloc_ucontext = hns_roce_alloc_ucontext,
	.create_ah = hns_roce_create_ah,
	.create_cq = hns_roce_create_cq,
	.create_qp = hns_roce_create_qp,
	.dealloc_pd = hns_roce_dealloc_pd,
	.dealloc_ucontext = hns_roce_dealloc_ucontext,
	.del_gid = hns_roce_del_gid,
	.dereg_mr = hns_roce_dereg_mr,
	.destroy_ah = hns_roce_destroy_ah,
	.destroy_cq = hns_roce_destroy_cq,
	.disassociate_ucontext = hns_roce_disassociate_ucontext,
	.get_dma_mr = hns_roce_get_dma_mr,
	.get_link_layer = hns_roce_get_link_layer,
	.get_netdev = hns_roce_get_netdev,
	.get_port_immutable = hns_roce_port_immutable,
	.mmap = hns_roce_mmap,
	.mmap_free = hns_roce_free_mmap,
	.modify_device = hns_roce_modify_device,
	.modify_qp = hns_roce_modify_qp,
	.query_ah = hns_roce_query_ah,
	.query_device = hns_roce_query_device,
	.query_pkey = hns_roce_query_pkey,
	.query_port = hns_roce_query_port,
	.reg_user_mr = hns_roce_reg_user_mr,
	.init_port = hns_roce_create_port_files,

	INIT_RDMA_OBJ_SIZE(ib_ah, hns_roce_ah, ibah),
	INIT_RDMA_OBJ_SIZE(ib_cq, hns_roce_cq, ib_cq),
	INIT_RDMA_OBJ_SIZE(ib_pd, hns_roce_pd, ibpd),
	INIT_RDMA_OBJ_SIZE(ib_ucontext, hns_roce_ucontext, ibucontext),
};

static const struct ib_device_ops hns_roce_dev_hw_stats_ops = {
	.alloc_hw_stats = hns_roce_alloc_hw_port_stats,
	.get_hw_stats = hns_roce_get_hw_stats,
};

static const struct ib_device_ops hns_roce_dev_mr_ops = {
	.rereg_user_mr = hns_roce_rereg_user_mr,
};

static const struct ib_device_ops hns_roce_dev_mw_ops = {
	.alloc_mw = hns_roce_alloc_mw,
	.dealloc_mw = hns_roce_dealloc_mw,

	INIT_RDMA_OBJ_SIZE(ib_mw, hns_roce_mw, ibmw),
};

static const struct ib_device_ops hns_roce_dev_frmr_ops = {
	.alloc_mr = hns_roce_alloc_mr,
	.map_mr_sg = hns_roce_map_mr_sg,
};

static const struct ib_device_ops hns_roce_dev_srq_ops = {
	.create_srq = hns_roce_create_srq,
	.destroy_srq = hns_roce_destroy_srq,

	INIT_RDMA_OBJ_SIZE(ib_srq, hns_roce_srq, ibsrq),
};

static const struct ib_device_ops hns_roce_dev_xrcd_ops = {
	.alloc_xrcd = hns_roce_alloc_xrcd,
	.dealloc_xrcd = hns_roce_dealloc_xrcd,

	INIT_RDMA_OBJ_SIZE(ib_xrcd, hns_roce_xrcd, ibxrcd),
};

static const struct ib_device_ops hns_roce_dev_restrack_ops = {
	.fill_res_cq_entry = hns_roce_fill_res_cq_entry,
	.fill_res_cq_entry_raw = hns_roce_fill_res_cq_entry_raw,
	.fill_res_qp_entry = hns_roce_fill_res_qp_entry,
	.fill_res_qp_entry_raw = hns_roce_fill_res_qp_entry_raw,
	.fill_res_mr_entry = hns_roce_fill_res_mr_entry,
	.fill_res_mr_entry_raw = hns_roce_fill_res_mr_entry_raw,
};

static int hns_roce_register_device(struct hns_roce_dev *hr_dev)
{
	struct hns_roce_ib_iboe *iboe = NULL;
	struct device *dev = hr_dev->dev;
	struct ib_device *ib_dev = NULL;
	struct net_device *net_dev;
	unsigned int i;
	int ret;

	iboe = &hr_dev->iboe;
	spin_lock_init(&iboe->lock);

	ib_dev = &hr_dev->ib_dev;

	ib_dev->node_type = RDMA_NODE_IB_CA;
	ib_dev->dev.parent = dev;

	ib_dev->phys_port_cnt = hr_dev->caps.num_ports;
	ib_dev->local_dma_lkey = hr_dev->caps.reserved_lkey;
	ib_dev->num_comp_vectors = hr_dev->caps.num_comp_vectors;
	ib_dev->uverbs_cmd_mask =
		(1ULL << IB_USER_VERBS_CMD_GET_CONTEXT) |
		(1ULL << IB_USER_VERBS_CMD_QUERY_DEVICE) |
		(1ULL << IB_USER_VERBS_CMD_QUERY_PORT) |
		(1ULL << IB_USER_VERBS_CMD_ALLOC_PD) |
		(1ULL << IB_USER_VERBS_CMD_DEALLOC_PD) |
		(1ULL << IB_USER_VERBS_CMD_REG_MR) |
		(1ULL << IB_USER_VERBS_CMD_DEREG_MR) |
		(1ULL << IB_USER_VERBS_CMD_CREATE_COMP_CHANNEL) |
		(1ULL << IB_USER_VERBS_CMD_CREATE_CQ) |
		(1ULL << IB_USER_VERBS_CMD_DESTROY_CQ) |
		(1ULL << IB_USER_VERBS_CMD_CREATE_QP) |
		(1ULL << IB_USER_VERBS_CMD_MODIFY_QP) |
		(1ULL << IB_USER_VERBS_CMD_QUERY_QP) |
		(1ULL << IB_USER_VERBS_CMD_DESTROY_QP) |
		(1ULL << IB_USER_VERBS_CMD_CREATE_AH) |
		(1ULL << IB_USER_VERBS_CMD_DESTROY_AH);

	ib_dev->uverbs_ex_cmd_mask |=
				(1ULL << IB_USER_VERBS_EX_CMD_QUERY_DEVICE) |
				(1ULL << IB_USER_VERBS_EX_CMD_MODIFY_CQ) |
				(1ULL << IB_USER_VERBS_EX_CMD_CREATE_CQ) |
				(1ULL << IB_USER_VERBS_EX_CMD_MODIFY_QP) |
				(1ULL << IB_USER_VERBS_EX_CMD_CREATE_QP);

	if (hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_REREG_MR) {
		ib_dev->uverbs_cmd_mask |= (1ULL << IB_USER_VERBS_CMD_REREG_MR);
		ib_set_device_ops(ib_dev, &hns_roce_dev_mr_ops);
	}

	/* MW */
	if (hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_MW) {
		ib_dev->uverbs_cmd_mask |=
					(1ULL << IB_USER_VERBS_CMD_ALLOC_MW) |
					(1ULL << IB_USER_VERBS_CMD_DEALLOC_MW);
		ib_set_device_ops(ib_dev, &hns_roce_dev_mw_ops);
	}

	/* FRMR */
	if (hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_FRMR)
		ib_set_device_ops(ib_dev, &hns_roce_dev_frmr_ops);

	/* SRQ */
	if (hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_SRQ) {
		ib_dev->uverbs_cmd_mask |=
				(1ULL << IB_USER_VERBS_CMD_CREATE_SRQ) |
				(1ULL << IB_USER_VERBS_CMD_MODIFY_SRQ) |
				(1ULL << IB_USER_VERBS_CMD_QUERY_SRQ) |
				(1ULL << IB_USER_VERBS_CMD_DESTROY_SRQ) |
				(1ULL << IB_USER_VERBS_CMD_POST_SRQ_RECV);
		ib_set_device_ops(ib_dev, &hns_roce_dev_srq_ops);
		ib_set_device_ops(ib_dev, hr_dev->hw->hns_roce_dev_srq_ops);
	}

	if (hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_XRC) {
		ib_dev->uverbs_cmd_mask |=
				(1ULL << IB_USER_VERBS_CMD_OPEN_XRCD) |
				(1ULL << IB_USER_VERBS_CMD_CLOSE_XRCD) |
				(1ULL << IB_USER_VERBS_CMD_CREATE_XSRQ) |
				(1ULL << IB_USER_VERBS_CMD_OPEN_QP);
		ib_set_device_ops(ib_dev, &hns_roce_dev_xrcd_ops);
	}

	if (hr_dev->pci_dev->revision >= PCI_REVISION_ID_HIP09 &&
	    !hr_dev->is_vf)
		ib_set_device_ops(ib_dev, &hns_roce_dev_hw_stats_ops);

	ib_set_device_ops(ib_dev, hr_dev->hw->hns_roce_dev_ops);
	ib_set_device_ops(ib_dev, &hns_roce_dev_ops);
	ib_set_device_ops(ib_dev, &hns_roce_dev_restrack_ops);

	if (IS_ENABLED(CONFIG_INFINIBAND_USER_ACCESS))
		ib_dev->driver_def = hns_roce_uapi_defs;

	for (i = 0; i < hr_dev->caps.num_ports; i++) {
		net_dev = get_hr_netdev(hr_dev, i);
		if (!net_dev)
			continue;

		ret = ib_device_set_netdev(ib_dev, net_dev, i + 1);
		if (ret)
			return ret;
	}
	dma_set_max_seg_size(dev, SZ_2G);

	if ((hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_BOND) &&
	    (hr_dev->hw->bond_is_active(hr_dev)))
		ret = ib_register_device(ib_dev, "hns_bond_%d", dev);
	else
		ret = ib_register_device(ib_dev, "hns_%d", dev);
	if (ret) {
		dev_err(dev, "ib_register_device failed!\n");
		return ret;
	}

	ret = hns_roce_setup_mtu_mac(hr_dev);
	if (ret) {
		dev_err(dev, "setup_mtu_mac failed!\n");
		goto error_failed_setup_mtu_mac;
	}

	iboe->nb.notifier_call = hns_roce_netdev_event;
	ret = register_netdevice_notifier(&iboe->nb);
	if (ret) {
		dev_err(dev, "register_netdevice_notifier failed!\n");
		goto error_failed_setup_mtu_mac;
	}

	if (hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_BOND) {
		ret = hr_dev->hw->bond_init(hr_dev);
		if (ret) {
			dev_err(dev, "roce bond init failed, ret = %d\n", ret);
			/* For non-bond devices, the failure of bond_init does
			 * not affect other functions.
			 */
			if (hr_dev->hw->bond_is_active(hr_dev))
				goto error_bond_init;
			else
				ret = 0;
		}
	}

	hr_dev->active = true;

	return ret;

error_bond_init:
	unregister_netdevice_notifier(&iboe->nb);
error_failed_setup_mtu_mac:
	ib_unregister_device(ib_dev);

	return ret;
}

static int hns_roce_init_hem(struct hns_roce_dev *hr_dev)
{
	struct device *dev = hr_dev->dev;
	int ret;

	ret = hns_roce_init_hem_table(hr_dev, &hr_dev->mr_table.mtpt_table,
				      HEM_TYPE_MTPT, hr_dev->caps.mtpt_entry_sz,
				      hr_dev->caps.num_mtpts);
	if (ret) {
		dev_err(dev, "Failed to init MTPT context memory, aborting.\n");
		return ret;
	}

	ret = hns_roce_init_hem_table(hr_dev, &hr_dev->qp_table.qp_table,
				      HEM_TYPE_QPC, hr_dev->caps.qpc_sz,
				      hr_dev->caps.num_qps);
	if (ret) {
		dev_err(dev, "Failed to init QP context memory, aborting.\n");
		goto err_unmap_dmpt;
	}

	ret = hns_roce_init_hem_table(hr_dev, &hr_dev->qp_table.irrl_table,
				      HEM_TYPE_IRRL,
				      hr_dev->caps.irrl_entry_sz *
				      hr_dev->caps.max_qp_init_rdma,
				      hr_dev->caps.num_qps);
	if (ret) {
		dev_err(dev, "Failed to init irrl_table memory, aborting.\n");
		goto err_unmap_qp;
	}

	if (hr_dev->caps.trrl_entry_sz) {
		ret = hns_roce_init_hem_table(hr_dev,
					      &hr_dev->qp_table.trrl_table,
					      HEM_TYPE_TRRL,
					      hr_dev->caps.trrl_entry_sz *
					      hr_dev->caps.max_qp_dest_rdma,
					      hr_dev->caps.num_qps);
		if (ret) {
			dev_err(dev,
				"Failed to init trrl_table memory, aborting.\n");
			goto err_unmap_irrl;
		}
	}

	ret = hns_roce_init_hem_table(hr_dev, &hr_dev->cq_table.table,
				      HEM_TYPE_CQC, hr_dev->caps.cqc_entry_sz,
				      hr_dev->caps.num_cqs);
	if (ret) {
		dev_err(dev, "Failed to init CQ context memory, aborting.\n");
		goto err_unmap_trrl;
	}

	if (hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_SRQ) {
		ret = hns_roce_init_hem_table(hr_dev, &hr_dev->srq_table.table,
					      HEM_TYPE_SRQC,
					      hr_dev->caps.srqc_entry_sz,
					      hr_dev->caps.num_srqs);
		if (ret) {
			dev_err(dev,
				"Failed to init SRQ context memory, aborting.\n");
			goto err_unmap_cq;
		}
	}

	if (hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_QP_FLOW_CTRL) {
		ret = hns_roce_init_hem_table(hr_dev,
					      &hr_dev->qp_table.sccc_table,
					      HEM_TYPE_SCCC,
					      hr_dev->caps.sccc_sz,
					      hr_dev->caps.num_qps);
		if (ret) {
			dev_err(dev,
				"Failed to init SCC context memory, aborting.\n");
			goto err_unmap_srq;
		}
	}

	if (hr_dev->caps.qpc_timer_entry_sz) {
		ret = hns_roce_init_hem_table(hr_dev, &hr_dev->qpc_timer_table,
					      HEM_TYPE_QPC_TIMER,
					      hr_dev->caps.qpc_timer_entry_sz,
					      hr_dev->caps.qpc_timer_bt_num);
		if (ret) {
			dev_err(dev,
				"Failed to init QPC timer memory, aborting.\n");
			goto err_unmap_ctx;
		}
	}

	if (hr_dev->caps.cqc_timer_entry_sz) {
		ret = hns_roce_init_hem_table(hr_dev, &hr_dev->cqc_timer_table,
					      HEM_TYPE_CQC_TIMER,
					      hr_dev->caps.cqc_timer_entry_sz,
					      hr_dev->caps.cqc_timer_bt_num);
		if (ret) {
			dev_err(dev,
				"Failed to init CQC timer memory, aborting.\n");
			goto err_unmap_qpc_timer;
		}
	}

	if (hr_dev->caps.gmv_entry_sz) {
		ret = hns_roce_init_hem_table(hr_dev, &hr_dev->gmv_table,
					      HEM_TYPE_GMV,
					      hr_dev->caps.gmv_entry_sz,
					      hr_dev->caps.gmv_entry_num);
		if (ret) {
			dev_err(dev,
				"failed to init gmv table memory, ret = %d\n",
				ret);
			goto err_unmap_cqc_timer;
		}
	}

	return 0;

err_unmap_cqc_timer:
	if (hr_dev->caps.cqc_timer_entry_sz)
		hns_roce_cleanup_hem_table(hr_dev, &hr_dev->cqc_timer_table);

err_unmap_qpc_timer:
	if (hr_dev->caps.qpc_timer_entry_sz)
		hns_roce_cleanup_hem_table(hr_dev, &hr_dev->qpc_timer_table);

err_unmap_ctx:
	if (hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_QP_FLOW_CTRL)
		hns_roce_cleanup_hem_table(hr_dev,
					   &hr_dev->qp_table.sccc_table);
err_unmap_srq:
	if (hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_SRQ)
		hns_roce_cleanup_hem_table(hr_dev, &hr_dev->srq_table.table);

err_unmap_cq:
	hns_roce_cleanup_hem_table(hr_dev, &hr_dev->cq_table.table);

err_unmap_trrl:
	if (hr_dev->caps.trrl_entry_sz)
		hns_roce_cleanup_hem_table(hr_dev,
					   &hr_dev->qp_table.trrl_table);

err_unmap_irrl:
	hns_roce_cleanup_hem_table(hr_dev, &hr_dev->qp_table.irrl_table);

err_unmap_qp:
	hns_roce_cleanup_hem_table(hr_dev, &hr_dev->qp_table.qp_table);

err_unmap_dmpt:
	hns_roce_cleanup_hem_table(hr_dev, &hr_dev->mr_table.mtpt_table);

	return ret;
}

static void hns_roce_teardown_hca(struct hns_roce_dev *hr_dev)
{
	if (hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_DCA_MODE)
		hns_roce_cleanup_dca(hr_dev);

	hns_roce_cleanup_bitmap(hr_dev);
	mutex_destroy(&hr_dev->umem_unfree_list_mutex);
	mutex_destroy(&hr_dev->mtr_unfree_list_mutex);
	mutex_destroy(&hr_dev->uctx_list_mutex);

	if (hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_CQ_RECORD_DB ||
	    hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_QP_RECORD_DB)
		mutex_destroy(&hr_dev->pgdir_mutex);
}

/**
 * hns_roce_setup_hca - setup host channel adapter
 * @hr_dev: pointer to hns roce device
 * Return : int
 */
static int hns_roce_setup_hca(struct hns_roce_dev *hr_dev)
{
	struct device *dev = hr_dev->dev;
	int ret;

	spin_lock_init(&hr_dev->sm_lock);

	INIT_LIST_HEAD(&hr_dev->qp_list);
	spin_lock_init(&hr_dev->qp_list_lock);
	INIT_LIST_HEAD(&hr_dev->dip_list);
	spin_lock_init(&hr_dev->dip_list_lock);

	INIT_LIST_HEAD(&hr_dev->uctx_list);
	mutex_init(&hr_dev->uctx_list_mutex);

	INIT_LIST_HEAD(&hr_dev->mtr_unfree_list);
	mutex_init(&hr_dev->mtr_unfree_list_mutex);

	INIT_LIST_HEAD(&hr_dev->umem_unfree_list);
	mutex_init(&hr_dev->umem_unfree_list_mutex);

	if (hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_CQ_RECORD_DB ||
	    hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_QP_RECORD_DB) {
		INIT_LIST_HEAD(&hr_dev->pgdir_list);
		mutex_init(&hr_dev->pgdir_mutex);
	}

	hns_roce_init_uar_table(hr_dev);

	ret = hns_roce_uar_alloc(hr_dev, &hr_dev->priv_uar);
	if (ret) {
		dev_err(dev, "Failed to allocate priv_uar.\n");
		goto err_uar_table_free;
	}

	ret = hns_roce_init_qp_table(hr_dev);
	if (ret) {
		dev_err(dev, "Failed to init qp_table.\n");
		goto err_uar_table_free;
	}

	hns_roce_init_pd_table(hr_dev);

	if (hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_XRC)
		hns_roce_init_xrcd_table(hr_dev);

	hns_roce_init_mr_table(hr_dev);

	hns_roce_init_cq_table(hr_dev);

	if (hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_SRQ) {
		hns_roce_init_srq_table(hr_dev);
	}

	if (hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_DCA_MODE)
		hns_roce_init_dca(hr_dev);

	return 0;

err_uar_table_free:
	ida_destroy(&hr_dev->uar_ida.ida);
	mutex_destroy(&hr_dev->umem_unfree_list_mutex);
	mutex_destroy(&hr_dev->mtr_unfree_list_mutex);
	mutex_destroy(&hr_dev->uctx_list_mutex);

	if (hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_CQ_RECORD_DB ||
	    hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_QP_RECORD_DB)
		mutex_destroy(&hr_dev->pgdir_mutex);

	return ret;
}

static void check_and_get_armed_cq(struct list_head *cq_list, struct ib_cq *cq)
{
	struct hns_roce_cq *hr_cq = to_hr_cq(cq);
	unsigned long flags;

	spin_lock_irqsave(&hr_cq->lock, flags);
	if (cq->comp_handler) {
		if (!hr_cq->is_armed) {
			hr_cq->is_armed = 1;
			list_add_tail(&hr_cq->node, cq_list);
		}
	}
	spin_unlock_irqrestore(&hr_cq->lock, flags);
}

void hns_roce_handle_device_err(struct hns_roce_dev *hr_dev)
{
	struct hns_roce_qp *hr_qp, *hr_qp_next;
	struct hns_roce_cq *hr_cq;
	struct list_head cq_list;
	unsigned long flags_qp;
	unsigned long flags;

	INIT_LIST_HEAD(&cq_list);

	spin_lock_irqsave(&hr_dev->qp_list_lock, flags);
	list_for_each_entry_safe(hr_qp, hr_qp_next, &hr_dev->qp_list, node) {
		spin_lock_irqsave(&hr_qp->sq.lock, flags_qp);
		if (hr_qp->sq.tail != hr_qp->sq.head)
			check_and_get_armed_cq(&cq_list, hr_qp->ibqp.send_cq);
		spin_unlock_irqrestore(&hr_qp->sq.lock, flags_qp);

		spin_lock_irqsave(&hr_qp->rq.lock, flags_qp);
		if ((!hr_qp->ibqp.srq) && (hr_qp->rq.tail != hr_qp->rq.head))
			check_and_get_armed_cq(&cq_list, hr_qp->ibqp.recv_cq);
		spin_unlock_irqrestore(&hr_qp->rq.lock, flags_qp);
	}

	list_for_each_entry(hr_cq, &cq_list, node)
		hns_roce_cq_completion(hr_dev, hr_cq->cqn);

	spin_unlock_irqrestore(&hr_dev->qp_list_lock, flags);
}

static void hns_roce_register_poe_ch(struct hns_roce_dev *hr_dev)
{
	struct hns_roce_poe_ch *poe_ch;

	if (!poe_is_supported(hr_dev) || hr_dev->caps.poe_ch_num <= 0)
		goto out;

	poe_ch = kvcalloc(hr_dev->caps.poe_ch_num,
			  sizeof(struct hns_roce_poe_ch), GFP_KERNEL);
	if (!poe_ch)
		goto out;

	hr_dev->poe_ctx.poe_num = hr_dev->caps.poe_ch_num;
	hr_dev->poe_ctx.poe_ch = poe_ch;
	return;

out:
	hr_dev->poe_ctx.poe_num = 0;
	hr_dev->poe_ctx.poe_ch = NULL;

}

static void hns_roce_unregister_poe_ch(struct hns_roce_dev *hr_dev)
{
	if (!poe_is_supported(hr_dev) || hr_dev->caps.poe_ch_num <= 0)
		return;

	kvfree(hr_dev->poe_ctx.poe_ch);
}

static int hns_roce_alloc_dfx_cnt(struct hns_roce_dev *hr_dev)
{
	hr_dev->dfx_cnt = kvcalloc(HNS_ROCE_DFX_CNT_TOTAL, sizeof(atomic64_t),
				   GFP_KERNEL);
	if (!hr_dev->dfx_cnt)
		return -ENOMEM;

	return 0;
}

static void hns_roce_dealloc_dfx_cnt(struct hns_roce_dev *hr_dev)
{
	kvfree(hr_dev->dfx_cnt);
}

static void hns_roce_free_dca_safe_buf(struct hns_roce_dev *hr_dev)
{
	if (!hr_dev->dca_safe_buf)
		return;

	dma_free_coherent(hr_dev->dev, PAGE_SIZE, hr_dev->dca_safe_buf,
			  hr_dev->dca_safe_page);
	hr_dev->dca_safe_page = 0;
	hr_dev->dca_safe_buf = NULL;
}

int hns_roce_init(struct hns_roce_dev *hr_dev)
{
	struct device *dev = hr_dev->dev;
	int ret;

	hr_dev->is_reset = false;

	ret = hns_roce_alloc_dfx_cnt(hr_dev);
	if (ret) {
		dev_err(dev, "Alloc dfx_cnt failed!\n");
		return ret;
	}

	if (hr_dev->hw->cmq_init) {
		ret = hr_dev->hw->cmq_init(hr_dev);
		if (ret) {
			dev_err(dev, "Init RoCE Command Queue failed!\n");
			goto error_failed_alloc_dfx_cnt;
		}
	}

	ret = hr_dev->hw->hw_profile(hr_dev);
	if (ret) {
		dev_err(dev, "Get RoCE engine profile failed!\n");
		goto error_failed_cmd_init;
	}

	ret = hns_roce_cmd_init(hr_dev);
	if (ret) {
		dev_err(dev, "cmd init failed!\n");
		goto error_failed_cmd_init;
	}

	/* EQ depends on poll mode, event mode depends on EQ */
	ret = hr_dev->hw->init_eq(hr_dev);
	if (ret) {
		dev_err(dev, "eq init failed!\n");
		goto error_failed_eq_table;
	}

	if (hr_dev->cmd_mod) {
		ret = hns_roce_cmd_use_events(hr_dev);
		if (ret)
			dev_warn(dev,
				 "Cmd event  mode failed, set back to poll!\n");
	}

	ret = hns_roce_init_hem(hr_dev);
	if (ret) {
		dev_err(dev, "init HEM(Hardware Entry Memory) failed!\n");
		goto error_failed_init_hem;
	}

	ret = hns_roce_setup_hca(hr_dev);
	if (ret) {
		dev_err(dev, "setup hca failed!\n");
		goto error_failed_setup_hca;
	}

	if (hr_dev->hw->hw_init) {
		ret = hr_dev->hw->hw_init(hr_dev);
		if (ret) {
			dev_err(dev, "hw_init failed!\n");
			goto error_failed_engine_init;
		}
	}

	hns_roce_register_poe_ch(hr_dev);
	ret = hns_roce_register_device(hr_dev);
	if (ret)
		goto error_failed_register_device;

	hns_roce_register_debugfs(hr_dev);

	return 0;

error_failed_register_device:
	if (hr_dev->hw->hw_exit)
		hr_dev->hw->hw_exit(hr_dev);

error_failed_engine_init:
	hns_roce_teardown_hca(hr_dev);

error_failed_setup_hca:
	hns_roce_cleanup_hem(hr_dev);

error_failed_init_hem:
	if (hr_dev->cmd_mod)
		hns_roce_cmd_use_polling(hr_dev);
	hr_dev->hw->cleanup_eq(hr_dev);

error_failed_eq_table:
	hns_roce_cmd_cleanup(hr_dev);

error_failed_cmd_init:
	if (hr_dev->hw->cmq_exit)
		hr_dev->hw->cmq_exit(hr_dev);

error_failed_alloc_dfx_cnt:
	hns_roce_dealloc_dfx_cnt(hr_dev);

	return ret;
}

void hns_roce_exit(struct hns_roce_dev *hr_dev, bool bond_cleanup)
{
	hns_roce_unregister_sysfs(hr_dev);
	hns_roce_unregister_device(hr_dev, bond_cleanup);
	hns_roce_unregister_debugfs(hr_dev);
	hns_roce_unregister_poe_ch(hr_dev);
	hns_roce_free_dca_safe_buf(hr_dev);

	if (hr_dev->hw->hw_exit)
		hr_dev->hw->hw_exit(hr_dev);
	hns_roce_free_unfree_umem(hr_dev);
	hns_roce_free_unfree_mtr(hr_dev);
	hns_roce_teardown_hca(hr_dev);
	hns_roce_cleanup_hem(hr_dev);

	if (hr_dev->cmd_mod)
		hns_roce_cmd_use_polling(hr_dev);

	hr_dev->hw->cleanup_eq(hr_dev);
	hns_roce_cmd_cleanup(hr_dev);
	if (hr_dev->hw->cmq_exit)
		hr_dev->hw->cmq_exit(hr_dev);
	hns_roce_dealloc_dfx_cnt(hr_dev);
	if (hr_dev->notify_tbl)
		kvfree(hr_dev->notify_tbl);
}

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Wei Hu <xavier.huwei@huawei.com>");
MODULE_AUTHOR("Nenglong Zhao <zhaonenglong@hisilicon.com>");
MODULE_AUTHOR("Lijun Ou <oulijun@huawei.com>");
MODULE_DESCRIPTION("HNS RoCE Driver");
