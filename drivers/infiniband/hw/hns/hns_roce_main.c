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
#include "roce_k_compat.h"

#include <linux/acpi.h>
#include <linux/of_platform.h>
#include <linux/module.h>
#include <linux/sched.h>
#ifdef HAVE_LINUX_MM_H
#include <linux/mm.h>
#else
#include <linux/sched/mm.h>
#endif
#ifdef HAVE_LINUX_SCHED_H
#include <linux/sched.h>
#else
#include <linux/sched/task.h>
#endif
#include <rdma/ib_addr.h>
#include <rdma/ib_smi.h>
#include <rdma/ib_user_verbs.h>
#include <rdma/ib_cache.h>
#include "hns_roce_common.h"
#include "hns_roce_device.h"
#include <rdma/hns-abi.h>
#include "hns_roce_hem.h"

/**
 * hns_get_gid_index - Get gid index.
 * @hr_dev: pointer to structure hns_roce_dev.
 * @port:  port, value range: 0 ~ MAX
 * @gid_index:  gid_index, value range: 0 ~ MAX
 * Description:
 *    N ports shared gids, allocation method as follow:
 *		GID[0][0], GID[1][0],.....GID[N - 1][0],
 *		GID[0][0], GID[1][0],.....GID[N - 1][0],
 *		And so on
 */
int hns_get_gid_index(struct hns_roce_dev *hr_dev, u8 port, int gid_index)
{
	return gid_index * hr_dev->caps.num_ports + port;
}
EXPORT_SYMBOL_GPL(hns_get_gid_index);

static int hns_roce_set_mac(struct hns_roce_dev *hr_dev, u8 port, u8 *addr)
{
	u8 phy_port;
	u32 i = 0;

	if (!memcmp(hr_dev->dev_addr[port], addr, ETH_ALEN))
		return 0;

	for (i = 0; i < ETH_ALEN; i++)
		hr_dev->dev_addr[port][i] = addr[i];

	phy_port = hr_dev->iboe.phy_port[port];
	return hr_dev->hw->set_mac(hr_dev, phy_port, addr);
}

#ifdef CONFIG_NEW_KERNEL
#ifdef CONFIG_KERNEL_419
static int hns_roce_add_gid(const struct ib_gid_attr *attr, void **context)
#else
static int hns_roce_add_gid(const union ib_gid *gid,
			    const struct ib_gid_attr *attr, void **context)
#endif
{
	struct hns_roce_dev *hr_dev = to_hr_dev(attr->device);
	u8 port = attr->port_num - 1;
	int ret;

	if (port >= hr_dev->caps.num_ports ||
	    attr->index > hr_dev->caps.gid_table_len[port]) {
		dev_err(hr_dev->dev, "add gid failed. port - %u, index - %u\n",
			port, attr->index);
		return -EINVAL;
	}

#ifdef CONFIG_KERNEL_419
	ret = hr_dev->hw->set_gid(hr_dev, port, attr->index, &attr->gid, attr);
#else
	ret = hr_dev->hw->set_gid(hr_dev, port, attr->index,
				  (union ib_gid *)gid, attr);
#endif

	if (ret)
		dev_err(hr_dev->dev, "set gid failed(%d), index = %u", ret,
			attr->index);

	return ret;
}

static int hns_roce_del_gid(const struct ib_gid_attr *attr, void **context)
{
	struct hns_roce_dev *hr_dev = to_hr_dev(attr->device);
	struct ib_gid_attr zattr = { };
	u8 port = attr->port_num - 1;
	int ret;

	if (port >= hr_dev->caps.num_ports) {
		dev_err(hr_dev->dev,
			"Port num %u id large than max port num %u.\n",
			port, hr_dev->caps.num_ports);
		return -EINVAL;
	}

	ret = hr_dev->hw->set_gid(hr_dev, port, attr->index, &zgid, &zattr);
	if (ret)
		dev_warn(hr_dev->dev, "del gid failed(%d), index = %u", ret,
			 attr->index);

	return ret;
}
#else
static int hns_roce_add_gid(struct ib_device *device, u8 port_num,
			    unsigned int index, const union ib_gid *gid,
			    const struct ib_gid_attr *attr, void **context)
{
	struct hns_roce_dev *hr_dev = to_hr_dev(device);
	u8 port = port_num - 1;
	int ret;

	rdfx_func_cnt(hr_dev, RDFX_FUNC_ADD_GID);

	if (port >= hr_dev->caps.num_ports ||
	    index > hr_dev->caps.gid_table_len[port]) {
		dev_err(hr_dev->dev, "add gid failed. port - %u, index - %u\n",
			port, index);
		return -EINVAL;
	}

	ret = hr_dev->hw->set_gid(hr_dev, port, index, (union ib_gid *)gid,
				   attr);
	if (ret)
		dev_err(hr_dev->dev, "set gid failed(%d), index = %u",
			ret, index);

	return ret;
}

static int hns_roce_del_gid(struct ib_device *device, u8 port_num,
			    unsigned int index, void **context)
{
	struct hns_roce_dev *hr_dev = to_hr_dev(device);
	struct ib_gid_attr zattr = { };
	union ib_gid zgid = { {0} };
	u8 port = port_num - 1;
	int ret;

	rdfx_func_cnt(hr_dev, RDFX_FUNC_DEL_GID);

	if (port >= hr_dev->caps.num_ports) {
		dev_err(hr_dev->dev,
			"Port num %u id large than max port num %u.\n",
			port, hr_dev->caps.num_ports);
		return -EINVAL;
	}

	ret = hr_dev->hw->set_gid(hr_dev, port, index, &zgid, &zattr);
	if (ret)
		dev_warn(hr_dev->dev, "del gid failed(%d), index = %u", ret,
			 index);

	return ret;
}
#endif

static int handle_en_event(struct hns_roce_dev *hr_dev, u8 port,
			   unsigned long dev_event)
{
	struct device *dev = hr_dev->dev;
	enum ib_port_state port_state;
	struct net_device *netdev;
	struct ib_event event;
	unsigned long flags;
	int ret = 0;

	netdev = hr_dev->iboe.netdevs[port];
	if (!netdev) {
		dev_err(dev, "port(%u) can't find netdev\n", port);
		return -ENODEV;
	}

	switch (dev_event) {
	case NETDEV_REGISTER:
	case NETDEV_CHANGEADDR:
		ret = hns_roce_set_mac(hr_dev, port, netdev->dev_addr);
		if (ret)
			dev_err(dev, "set mac failed(%d), event = 0x%x\n", ret,
				(u32)dev_event);
		break;
	case NETDEV_UP:
	case NETDEV_CHANGE:
		ret = hns_roce_set_mac(hr_dev, port, netdev->dev_addr);
		if (ret)
			dev_err(dev, "set mac failed(%d), event = 0x%x\n", ret,
				(u32)dev_event);
		/* fallthrough */
	case NETDEV_DOWN:
		port_state = get_port_state(netdev);

		spin_lock_irqsave(&hr_dev->iboe.lock, flags);
		if (hr_dev->iboe.last_port_state[port] == port_state) {
			spin_unlock_irqrestore(&hr_dev->iboe.lock, flags);
			return NOTIFY_DONE;
		}
		hr_dev->iboe.last_port_state[port] = port_state;
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
	struct hns_roce_ib_iboe *iboe;
	struct hns_roce_dev *hr_dev;
	u8 port;
	int ret;

	hr_dev = container_of(self, struct hns_roce_dev, iboe.nb);
	iboe = &hr_dev->iboe;

	for (port = 0; port < hr_dev->caps.num_ports; port++) {
		if (dev == iboe->netdevs[port]) {
			ret = handle_en_event(hr_dev, port, event);
			if (ret)
				return NOTIFY_DONE;
			break;
		}
	}

	return NOTIFY_DONE;
}

static int hns_roce_setup_mtu_mac_state(struct hns_roce_dev *hr_dev)
{
	int ret;
	u8 i;

	for (i = 0; i < hr_dev->caps.num_ports; i++) {
		hr_dev->iboe.last_port_state[i] = IB_PORT_DOWN;
		if (hr_dev->hw->set_mtu)
			hr_dev->hw->set_mtu(hr_dev, hr_dev->iboe.phy_port[i],
					    hr_dev->caps.max_mtu);
		ret = hns_roce_set_mac(hr_dev, i,
				       hr_dev->iboe.netdevs[i]->dev_addr);
		if (ret) {
			dev_err(hr_dev->dev, "set mac failed(%d)\n", ret);
			return ret;
		}
	}

	return 0;
}

static int hns_roce_query_device(struct ib_device *ib_dev,
				 struct ib_device_attr *props,
				 struct ib_udata *uhw)
{
	struct hns_roce_dev *hr_dev = to_hr_dev(ib_dev);

	rdfx_func_cnt(hr_dev, RDFX_FUNC_QUERY_DEVICE);

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
	if (hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_XRC)
		props->device_cap_flags |= IB_DEVICE_XRC;
#ifdef CONFIG_KERNEL_419
	props->max_send_sge = hr_dev->caps.max_sq_sg;
	props->max_recv_sge = hr_dev->caps.max_rq_sg;
#else
	props->max_sge = min(hr_dev->caps.max_sq_sg, hr_dev->caps.max_rq_sg);
#endif
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

	if (hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_SRQ) {
		props->max_srq = hr_dev->caps.num_srqs;
		props->max_srq_wr = hr_dev->caps.max_srq_wrs;
		props->max_srq_sge = hr_dev->caps.max_srq_sges;
	}

	if (hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_MW) {
		props->max_mw = hr_dev->caps.num_mtpts;
		props->device_cap_flags |= IB_DEVICE_MEM_WINDOW |
					   IB_DEVICE_MEM_WINDOW_TYPE_2B;
	}

	if (hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_FRMR) {
		props->device_cap_flags |= IB_DEVICE_MEM_MGT_EXTENSIONS;
		props->max_fast_reg_page_list_len = HNS_ROCE_FRMR_MAX_PA;
	}

	return 0;
}

static struct net_device *hns_roce_get_netdev(struct ib_device *ib_dev,
					      u8 port_num)
{
	struct hns_roce_dev *hr_dev = to_hr_dev(ib_dev);
	struct net_device *ndev;

	rdfx_func_cnt(hr_dev, RDFX_FUNC_GET_NETDEV);

	if (port_num < 1 || port_num > hr_dev->caps.num_ports)
		return NULL;

	rcu_read_lock();

	ndev = hr_dev->iboe.netdevs[port_num - 1];
	if (ndev)
		dev_hold(ndev);

	rcu_read_unlock();
	return ndev;
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

	rdfx_func_cnt(hr_dev, RDFX_FUNC_QUERY_PORT);

	if (port_num < 1) {
		dev_err(dev, "invalid port num!\n");
		return -EINVAL;
	}

	port = port_num - 1;

	/* props being zeroed by the caller, avoid zeroing it here */

	props->max_mtu = hr_dev->caps.max_mtu;
	props->gid_tbl_len = hr_dev->caps.gid_table_len[port];
	props->port_cap_flags = IB_PORT_CM_SUP | IB_PORT_REINIT_SUP |
				IB_PORT_VENDOR_CLASS_SUP |
				IB_PORT_BOOT_MGMT_SUP;
	props->max_msg_sz = HNS_ROCE_MAX_MSG_LEN;
	props->pkey_tbl_len = 1;
	props->active_width = IB_WIDTH_4X;
	props->active_speed = 1;

	spin_lock_irqsave(&hr_dev->iboe.lock, flags);

	net_dev = hr_dev->iboe.netdevs[port];
	if (!net_dev) {
		spin_unlock_irqrestore(&hr_dev->iboe.lock, flags);
		dev_err(dev, "find netdev %u failed!\r\n", port);
		return -EINVAL;
	}

	mtu = iboe_get_mtu(net_dev->mtu);
	props->active_mtu = mtu ? min(props->max_mtu, mtu) : IB_MTU_256;
	props->state = get_port_state(net_dev);
	props->phys_state = (props->state == IB_PORT_ACTIVE) ?
			     HNS_ROCE_PHY_LINKUP : HNS_ROCE_PHY_DISABLED;

	spin_unlock_irqrestore(&hr_dev->iboe.lock, flags);

	return 0;
}

static enum rdma_link_layer hns_roce_get_link_layer(struct ib_device *device,
						    u8 port_num)
{
	rdfx_func_cnt(to_hr_dev(device), RDFX_FUNC_GET_LINK_LAYER);

	return IB_LINK_LAYER_ETHERNET;
}

static int hns_roce_query_gid(struct ib_device *ib_dev, u8 port_num, int index,
			      union ib_gid *gid)
{
	rdfx_func_cnt(to_hr_dev(ib_dev), RDFX_FUNC_QUERY_GID);

	return 0;
}

static int hns_roce_query_pkey(struct ib_device *ib_dev, u8 port, u16 index,
			       u16 *pkey)
{
	*pkey = PKEY_ID;

	rdfx_func_cnt(to_hr_dev(ib_dev), RDFX_FUNC_QUERY_PKEY);

	return 0;
}

static int hns_roce_modify_device(struct ib_device *ib_dev, int mask,
				  struct ib_device_modify *props)
{
	unsigned long flags;

	rdfx_func_cnt(to_hr_dev(ib_dev), RDFX_FUNC_MODIFY_DEVICE);

	if (mask & ~IB_DEVICE_MODIFY_NODE_DESC)
		return -EOPNOTSUPP;

	if (mask & IB_DEVICE_MODIFY_NODE_DESC) {
		spin_lock_irqsave(&to_hr_dev(ib_dev)->sm_lock, flags);
		memcpy(ib_dev->node_desc, props->node_desc, NODE_DESC_SIZE);
		spin_unlock_irqrestore(&to_hr_dev(ib_dev)->sm_lock, flags);
	}

	return 0;
}

static int hns_roce_modify_port(struct ib_device *ib_dev, u8 port_num, int mask,
				struct ib_port_modify *props)
{
	rdfx_func_cnt(to_hr_dev(ib_dev), RDFX_FUNC_MODIFY_PORT);

	return 0;
}

static struct ib_ucontext *hns_roce_alloc_ucontext(struct ib_device *ib_dev,
						   struct ib_udata *udata)
{
	int ret;
	struct hns_roce_ucontext *context;
	struct hns_roce_ib_alloc_ucontext_resp resp = {};
	struct hns_roce_dev *hr_dev = to_hr_dev(ib_dev);

	if (!hr_dev->active) {
		dev_err(hr_dev->dev,
			"alloc uncontext failed, hr_dev is not active\n");
		return ERR_PTR(-EAGAIN);
	}

	rdfx_func_cnt(hr_dev, RDFX_FUNC_ALLOC_UCONTEXT);

	resp.qp_tab_size = hr_dev->caps.num_qps;

	context = kzalloc(sizeof(*context), GFP_KERNEL);
	if (!context)
		return ERR_PTR(-ENOMEM);

	ret = hns_roce_uar_alloc(hr_dev, &context->uar);
	if (ret)
		goto error_fail_uar_alloc;

	INIT_LIST_HEAD(&context->vma_list);
	mutex_init(&context->vma_list_mutex);
	if (hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_RECORD_DB) {
		INIT_LIST_HEAD(&context->page_list);
		mutex_init(&context->page_mutex);
	}

	ret = ib_copy_to_udata(udata, &resp, min(udata->outlen, sizeof(resp)));
	if (ret)
		goto error_fail_copy_to_udata;

	kref_init(&context->uctx_ref);

	return &context->ibucontext;

error_fail_copy_to_udata:
	hns_roce_uar_free(hr_dev, &context->uar);

error_fail_uar_alloc:
	kfree(context);

	return ERR_PTR(ret);
}

static inline void release_ucontext(struct kref *kref)
{
	struct hns_roce_ucontext *context =
			container_of(kref, struct hns_roce_ucontext, uctx_ref);

	kfree(context);
}

static int hns_roce_dealloc_ucontext(struct ib_ucontext *ibcontext)
{
	struct hns_roce_ucontext *context = to_hr_ucontext(ibcontext);

	rdfx_func_cnt(to_hr_dev(ibcontext->device),
				     RDFX_FUNC_DEALLOC_UCONTEXT);

	hns_roce_uar_free(to_hr_dev(ibcontext->device), &context->uar);

	kref_put(&context->uctx_ref, release_ucontext);

	return 0;
}

static void hns_roce_vma_open(struct vm_area_struct *vma)
{
	vma->vm_ops = NULL;
}

static void hns_roce_vma_close(struct vm_area_struct *vma)
{
	struct hns_roce_vma_data *vma_data;
	struct hns_roce_ucontext *context;

	vma_data = (struct hns_roce_vma_data *)vma->vm_private_data;
	context = container_of(vma_data->vma_list_mutex,
			       struct hns_roce_ucontext, vma_list_mutex);

	vma_data->vma = NULL;
	mutex_lock(vma_data->vma_list_mutex);
	list_del(&vma_data->list);
	mutex_unlock(vma_data->vma_list_mutex);
	kfree(vma_data);

	kref_put(&context->uctx_ref, release_ucontext);
}

static const struct vm_operations_struct hns_roce_vm_ops = {
	.open = hns_roce_vma_open,
	.close = hns_roce_vma_close,
};

static int hns_roce_set_vma_data(struct vm_area_struct *vma,
				 struct hns_roce_ucontext *context)
{
	struct list_head *vma_head = &context->vma_list;
	struct hns_roce_vma_data *vma_data;

	kref_get(&context->uctx_ref);

	vma_data = kzalloc(sizeof(*vma_data), GFP_KERNEL);
	if (!vma_data)
		return -ENOMEM;

	vma_data->vma = vma;
	vma_data->vma_list_mutex = &context->vma_list_mutex;
	vma->vm_private_data = vma_data;
	vma->vm_ops = &hns_roce_vm_ops;

	mutex_lock(&context->vma_list_mutex);
	list_add(&vma_data->list, vma_head);
	mutex_unlock(&context->vma_list_mutex);

	return 0;
}

static int hns_roce_mmap(struct ib_ucontext *context,
			 struct vm_area_struct *vma)
{
	struct hns_roce_dev *hr_dev = to_hr_dev(context->device);

	rdfx_func_cnt(hr_dev, RDFX_FUNC_MMAP);

	if (((vma->vm_end - vma->vm_start) % PAGE_SIZE) != 0) {
		dev_err(hr_dev->dev, "mmap failed, unexpected vm area size.\n");
		return -EINVAL;
	}

	if (vma->vm_pgoff == 0) {
		vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
		if (io_remap_pfn_range(vma, vma->vm_start,
				       to_hr_ucontext(context)->uar.pfn,
				       PAGE_SIZE, vma->vm_page_prot))
			return -EAGAIN;
	} else if (vma->vm_pgoff == 1) {
		/* vm_pgoff: 1 -- TPTR(hw v1), reset_page(hw v2) */
		if (hr_dev->tptr_dma_addr && hr_dev->tptr_size) {
			if (io_remap_pfn_range(vma, vma->vm_start,
					 hr_dev->tptr_dma_addr >> PAGE_SHIFT,
					 hr_dev->tptr_size, vma->vm_page_prot)){
				dev_err(hr_dev->dev,
					"mmap tptr page failed.\n");
				return -EAGAIN;
			}
		}

		if (hr_dev->reset_page)
			if (remap_pfn_range(vma, vma->vm_start,
				  page_to_pfn(virt_to_page(hr_dev->reset_page)),
				  PAGE_SIZE, vma->vm_page_prot)) {
				dev_err(hr_dev->dev,
					"mmap reset page failed.\n");
				return -EAGAIN;
			}
	} else {
		dev_err(hr_dev->dev, "mmap failed, vm_pgoff is unsupported.\n");
		return -EINVAL;
	}

	return hns_roce_set_vma_data(vma, to_hr_ucontext(context));
}

static int hns_roce_port_immutable(struct ib_device *ib_dev, u8 port_num,
				   struct ib_port_immutable *immutable)
{
	struct ib_port_attr attr;
	int ret;

	rdfx_func_cnt(to_hr_dev(ib_dev), RDFX_FUNC_PORT_IMMUTABLE);

	ret = ib_query_port(ib_dev, port_num, &attr);
	if (ret) {
		dev_err(to_hr_dev(ib_dev)->dev, "ib_query_port failed(%d)!\n",
			ret);
		return ret;
	}

	immutable->pkey_tbl_len = attr.pkey_tbl_len;
	immutable->gid_tbl_len = attr.gid_tbl_len;

	immutable->max_mad_size = IB_MGMT_MAD_SIZE;
	immutable->core_cap_flags = RDMA_CORE_PORT_IBA_ROCE;
	if (to_hr_dev(ib_dev)->caps.flags & HNS_ROCE_CAP_FLAG_ROCE_V1_V2)
		immutable->core_cap_flags |= RDMA_CORE_PORT_IBA_ROCE_UDP_ENCAP;

	return 0;
}

static void hns_roce_disassociate_ucontext(struct ib_ucontext *ibcontext)
{
	struct hns_roce_ucontext *context = to_hr_ucontext(ibcontext);
	struct hns_roce_vma_data *vma_data, *n;
	struct vm_area_struct *vma;

	mutex_lock(&context->vma_list_mutex);
	list_for_each_entry_safe(vma_data, n, &context->vma_list, list) {
		vma = vma_data->vma;
		zap_vma_ptes(vma, vma->vm_start, PAGE_SIZE);

		vma->vm_flags &= ~(VM_SHARED | VM_MAYSHARE);
		vma->vm_ops = NULL;
		list_del(&vma_data->list);
		kfree(vma_data);

		kref_put(&context->uctx_ref, release_ucontext);
	}
	mutex_unlock(&context->vma_list_mutex);
}

static const char * const hns_roce_hw_stats_name[] = {
	"pd_alloc",
	"pd_dealloc",
	"pd_active_max",
	"mr_alloc",
	"mr_dealloc",
	"mr_active_max",
	"cq_alloc",
	"cq_dealloc",
	"qp_alloc",
	"qp_dealloc",
	"pd_active",
	"mr_active",
	"cq_active",
	"cq_active_max",
	"qp_active",
	"qp_active_max",
	"srq_active",
	"srq_active_max",
	"uar_active",
	"uar_active_max",
	"mr_rereg",
	"aeqe",
	"ceqe",
};

/**
 *port 0:/sys/devices/../infiniband/hnsethX/hw_counters
 *port 1:/sys/devices/../infiniband/hnsethX/ports/1/hw_counters
 */
static struct rdma_hw_stats *hns_roce_alloc_hw_stats(struct ib_device *device,
						     u8 port_num)
{
	BUILD_BUG_ON(ARRAY_SIZE(hns_roce_hw_stats_name) != HW_STATS_TOTAL);

	if (port_num != 0)
		return NULL; /* nothing to do for port */

	return rdma_alloc_hw_stats_struct(hns_roce_hw_stats_name,
					  ARRAY_SIZE(hns_roce_hw_stats_name),
					  RDMA_HW_STATS_DEFAULT_LIFESPAN);
}
static int hns_roce_get_hw_stats_for_armci(struct ib_device *device,
				 struct rdma_hw_stats *stats,
				 u8 port, int index)
{
	struct hns_roce_dev *hr_dev = to_hr_dev(device);
	unsigned long *table;
	unsigned long max;

	switch (index) {
	case HW_STATS_PD_ACTIVE:
		table = hr_dev->pd_bitmap.table;
		max = hr_dev->pd_bitmap.max;
		stats->value[index] = bitmap_weight(table, max) -
				      hr_dev->caps.reserved_pds;
		break;
	case HW_STATS_MR_ACTIVE:
		table = hr_dev->mr_table.mtpt_bitmap.table;
		max = hr_dev->mr_table.mtpt_bitmap.max;
		stats->value[index] = bitmap_weight(table, max) -
				      hr_dev->caps.reserved_mrws;
		break;
	case HW_STATS_CQ_ACTIVE:
		table = hr_dev->cq_table.bitmap.table;
		max = hr_dev->cq_table.bitmap.max;
		stats->value[index] = bitmap_weight(table, max) -
				      hr_dev->caps.reserved_cqs;
		break;
	case HW_STATS_CQ_ACTIVE_MAX:
		table = hr_dev->cq_table.bitmap.table;
		max = hr_dev->cq_table.bitmap.max;
		stats->value[index] = find_last_bit(table, max);
		break;
	case HW_STATS_QP_ACTIVE:
		table = hr_dev->qp_table.bitmap.table;
		max = hr_dev->qp_table.bitmap.max;
		stats->value[index] = bitmap_weight(table, max) -
				      hr_dev->caps.reserved_qps;
		break;
	case HW_STATS_QP_ACTIVE_MAX:
		table = hr_dev->qp_table.bitmap.table;
		max = hr_dev->qp_table.bitmap.max;
		stats->value[index] = find_last_bit(table, max);
		break;
	case HW_STATS_SRQ_ACTIVE:
		table = hr_dev->srq_table.bitmap.table;
		max = hr_dev->srq_table.bitmap.max;
		stats->value[index] = bitmap_weight(table, max) -
				      hr_dev->caps.reserved_srqs;
		break;
	case HW_STATS_SRQ_ACTIVE_MAX:
		table = hr_dev->srq_table.bitmap.table;
		max = hr_dev->srq_table.bitmap.max;
		stats->value[index] = find_last_bit(table, max);
		break;
	case HW_STATS_UAR_ACTIVE:
		table = hr_dev->uar_table.bitmap.table;
		max = hr_dev->uar_table.bitmap.max;
		stats->value[index] = bitmap_weight(table, max);
		break;
	case HW_STATS_UAR_ACTIVE_MAX:
		table = hr_dev->uar_table.bitmap.table;
		max = hr_dev->uar_table.bitmap.max;
		stats->value[index] = find_last_bit(table, max);
		break;
	case HW_STATS_AEQE:
		stats->value[index] = hr_dev->dfx_cnt[HNS_ROCE_DFX_AEQE];
		break;
	case HW_STATS_CEQE:
		stats->value[index] = hr_dev->dfx_cnt[HNS_ROCE_DFX_CEQE];
		break;
	default:
		break;
	}

	return index;
}

static int hns_roce_get_hw_stats(struct ib_device *device,
				 struct rdma_hw_stats *stats,
				 u8 port, int index)
{
	struct hns_roce_dev *hr_dev = to_hr_dev(device);
	unsigned long *table;
	unsigned long max;

	if (port != 0)
		return 0; /* nothing to do for port */

	switch (index) {
	case HW_STATS_PD_ACTIVE_MAX:
		table = hr_dev->pd_bitmap.table;
		max = hr_dev->pd_bitmap.max;
		stats->value[index] = find_last_bit(table, max);
		break;
	case HW_STATS_MR_ACTIVE_MAX:
		table = hr_dev->mr_table.mtpt_bitmap.table;
		max = hr_dev->mr_table.mtpt_bitmap.max;
		stats->value[index] = find_last_bit(table, max);
		break;
	default:
		hns_roce_get_hw_stats_for_armci(device, stats, port, index);
		break;
	}

	return index;
}


static void hns_roce_unregister_device(struct hns_roce_dev *hr_dev)
{
	struct hns_roce_ib_iboe *iboe = &hr_dev->iboe;

	hr_dev->active = false;
	unregister_netdevice_notifier(&iboe->nb);
	ib_unregister_device(&hr_dev->ib_dev);
}

static int hns_roce_register_device(struct hns_roce_dev *hr_dev)
{
	struct device *dev = hr_dev->dev;
	struct hns_roce_ib_iboe *iboe;
	struct ib_device *ib_dev;
	int ret;

	iboe = &hr_dev->iboe;
	spin_lock_init(&iboe->lock);

	ib_dev = &hr_dev->ib_dev;
	if (!strlen(ib_dev->name))
		strlcpy(ib_dev->name, "hns_%d", IB_DEVICE_NAME_MAX);

	ib_dev->owner			= THIS_MODULE;
	ib_dev->node_type		= RDMA_NODE_IB_CA;
	ib_dev->dev.parent		= dev;

	ib_dev->phys_port_cnt		= hr_dev->caps.num_ports;
	ib_dev->local_dma_lkey		= hr_dev->caps.reserved_lkey;
	ib_dev->num_comp_vectors	= hr_dev->caps.num_comp_vectors;
	ib_dev->uverbs_abi_ver		= 1;
	ib_dev->uverbs_cmd_mask		=
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
		(1ULL << IB_USER_VERBS_CMD_CREATE_SRQ) |
		(1ULL << IB_USER_VERBS_CMD_MODIFY_SRQ) |
		(1ULL << IB_USER_VERBS_CMD_QUERY_SRQ) |
		(1ULL << IB_USER_VERBS_CMD_DESTROY_SRQ) |
		(1ULL << IB_USER_VERBS_CMD_POST_SRQ_RECV) |
		(1ULL << IB_USER_VERBS_CMD_CREATE_XSRQ);

#ifdef MODIFY_CQ_MASK
	ib_dev->uverbs_ex_cmd_mask |=
		(1ULL << IB_USER_VERBS_EX_CMD_MODIFY_CQ);
#endif
	/* HCA||device||port */
	ib_dev->modify_device		= hns_roce_modify_device;
	ib_dev->query_device		= hns_roce_query_device;
	ib_dev->query_port		= hns_roce_query_port;
	ib_dev->modify_port		= hns_roce_modify_port;
	ib_dev->get_link_layer		= hns_roce_get_link_layer;
	ib_dev->get_netdev		= hns_roce_get_netdev;
	ib_dev->query_gid		= hns_roce_query_gid;
	ib_dev->add_gid			= hns_roce_add_gid;
	ib_dev->del_gid			= hns_roce_del_gid;
	ib_dev->query_pkey		= hns_roce_query_pkey;
	ib_dev->alloc_ucontext		= hns_roce_alloc_ucontext;
	ib_dev->dealloc_ucontext	= hns_roce_dealloc_ucontext;
	ib_dev->mmap			= hns_roce_mmap;

	/* PD */
	ib_dev->alloc_pd		= hns_roce_alloc_pd;
	ib_dev->dealloc_pd		= hns_roce_dealloc_pd;

	/* AH */
	ib_dev->create_ah		= hns_roce_create_ah;
	ib_dev->query_ah		= hns_roce_query_ah;
	ib_dev->destroy_ah		= hns_roce_destroy_ah;
	/* SRQ */
	ib_dev->create_srq		= hns_roce_create_srq;
	ib_dev->modify_srq		= hr_dev->hw->modify_srq;
	ib_dev->query_srq		= hr_dev->hw->query_srq;
	ib_dev->destroy_srq		= hns_roce_destroy_srq;
	ib_dev->post_srq_recv		= hr_dev->hw->post_srq_recv;

	/* QP */
	ib_dev->create_qp		= hns_roce_create_qp;
	ib_dev->modify_qp		= hns_roce_modify_qp;
	ib_dev->query_qp		= hr_dev->hw->query_qp;
	ib_dev->destroy_qp		= hr_dev->hw->destroy_qp;
	ib_dev->post_send		= hr_dev->hw->post_send;
	ib_dev->post_recv		= hr_dev->hw->post_recv;

	/* CQ */
	ib_dev->create_cq		= hns_roce_ib_create_cq;
	ib_dev->modify_cq		= hr_dev->hw->modify_cq;
	ib_dev->destroy_cq		= hns_roce_ib_destroy_cq;
	ib_dev->req_notify_cq		= hr_dev->hw->req_notify_cq;
	ib_dev->poll_cq			= hr_dev->hw->poll_cq;

	/* MR */
	ib_dev->get_dma_mr		= hns_roce_get_dma_mr;
	ib_dev->reg_user_mr		= hns_roce_reg_user_mr;
	ib_dev->dereg_mr		= hns_roce_dereg_mr;
	if (hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_REREG_MR) {
		ib_dev->rereg_user_mr	= hns_roce_rereg_user_mr;
		ib_dev->uverbs_cmd_mask |= (1ULL << IB_USER_VERBS_CMD_REREG_MR);
	}

	/* MW */
	if (hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_MW) {
		ib_dev->alloc_mw	= hns_roce_alloc_mw;
		ib_dev->dealloc_mw	= hns_roce_dealloc_mw;
		ib_dev->uverbs_cmd_mask |=
					(1ULL << IB_USER_VERBS_CMD_ALLOC_MW) |
					(1ULL << IB_USER_VERBS_CMD_DEALLOC_MW);
	}

	/* FRMR */
	if (hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_FRMR) {
		ib_dev->alloc_mr		= hns_roce_alloc_mr;
		ib_dev->map_mr_sg		= hns_roce_map_mr_sg;
	}

	/* OTHERS */
	ib_dev->get_port_immutable	= hns_roce_port_immutable;
	ib_dev->disassociate_ucontext	= hns_roce_disassociate_ucontext;
	ib_dev->res.fill_res_entry	= hns_roce_fill_res_entry;
	ib_dev->alloc_hw_stats		= hns_roce_alloc_hw_stats;
	ib_dev->get_hw_stats		= hns_roce_get_hw_stats;

	if (hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_XRC) {
		ib_dev->alloc_xrcd	= hns_roce_ib_alloc_xrcd;
		ib_dev->dealloc_xrcd	= hns_roce_ib_dealloc_xrcd;
		ib_dev->uverbs_cmd_mask |=
					(1ULL << IB_USER_VERBS_CMD_OPEN_XRCD) |
					(1ULL << IB_USER_VERBS_CMD_CLOSE_XRCD);
	}

	if (hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_UD) {
		ib_dev->uverbs_cmd_mask |=
					(1ULL << IB_USER_VERBS_CMD_CREATE_AH) |
					(1ULL << IB_USER_VERBS_CMD_DESTROY_AH);
	}

#ifdef CONFIG_NEW_KERNEL
	ib_dev->driver_id = RDMA_DRIVER_HNS;
#endif
	ret = ib_register_device(ib_dev, NULL);
	if (ret) {
		dev_err(dev, "ib_register_device failed(%d)!\n", ret);
		return ret;
	}

	ret = hns_roce_setup_mtu_mac_state(hr_dev);
	if (ret) {
		dev_err(dev, "setup_mtu_mac_state failed, ret = %d\n", ret);
		goto error_failed_setup_mtu_mac_state;
	}

	iboe->nb.notifier_call = hns_roce_netdev_event;
	ret = register_netdevice_notifier(&iboe->nb);
	if (ret) {
		iboe->nb.notifier_call = NULL;
		dev_err(dev, "register_netdevice_notifier failed(%d)!\n", ret);
		goto error_failed_setup_mtu_mac_state;
	}

	hr_dev->active = true;
	return 0;

error_failed_setup_mtu_mac_state:
	ib_unregister_device(ib_dev);

	return ret;
}

static int hns_roce_init_hem(struct hns_roce_dev *hr_dev)
{
	int ret;
	struct device *dev = hr_dev->dev;

	ret = hns_roce_init_hem_table(hr_dev, &hr_dev->mr_table.mtt_table,
				      HEM_TYPE_MTT, hr_dev->caps.mtt_entry_sz,
				      hr_dev->caps.num_mtt_segs, 1);
	if (ret) {
		dev_err(dev, "Init MTT context memory failed(%d).\n", ret);
		return ret;
	}

	if (hns_roce_check_whether_mhop(hr_dev, HEM_TYPE_CQE)) {
		ret = hns_roce_init_hem_table(hr_dev,
				      &hr_dev->mr_table.mtt_cqe_table,
				      HEM_TYPE_CQE, hr_dev->caps.mtt_entry_sz,
				      hr_dev->caps.num_cqe_segs, 1);
		if (ret) {
			dev_err(dev, "Init MTT CQE context memory failed(%d).\n",
				ret);
			goto err_unmap_cqe;
		}
	}

	ret = hns_roce_init_hem_table(hr_dev, &hr_dev->mr_table.mtpt_table,
				      HEM_TYPE_MTPT, hr_dev->caps.mtpt_entry_sz,
				      hr_dev->caps.num_mtpts, 1);
	if (ret) {
		dev_err(dev, "Init MTPT context memory failed(%d).\n", ret);
		goto err_unmap_mtt;
	}

	ret = hns_roce_init_hem_table(hr_dev, &hr_dev->qp_table.qp_table,
				      HEM_TYPE_QPC, hr_dev->caps.qpc_entry_sz,
				      hr_dev->caps.num_qps, 1);
	if (ret) {
		dev_err(dev, "Init QP context memory failed(%d).\n", ret);
		goto err_unmap_dmpt;
	}

	ret = hns_roce_init_hem_table(hr_dev, &hr_dev->qp_table.irrl_table,
				      HEM_TYPE_IRRL,
				      hr_dev->caps.irrl_entry_sz *
				      hr_dev->caps.max_qp_init_rdma,
				      hr_dev->caps.num_qps, 1);
	if (ret) {
		dev_err(dev, "Init irrl_table memory failed(%d).\n", ret);
		goto err_unmap_qp;
	}

	if (hr_dev->caps.trrl_entry_sz) {
		ret = hns_roce_init_hem_table(hr_dev,
					      &hr_dev->qp_table.trrl_table,
					      HEM_TYPE_TRRL,
					      hr_dev->caps.trrl_entry_sz *
					      hr_dev->caps.max_qp_dest_rdma,
					      hr_dev->caps.num_qps, 1);
		if (ret) {
			dev_err(dev, "Init trrl_table memory failed(%d).\n",
				ret);
			goto err_unmap_irrl;
		}
	}

	ret = hns_roce_init_hem_table(hr_dev, &hr_dev->cq_table.table,
				      HEM_TYPE_CQC, hr_dev->caps.cqc_entry_sz,
				      hr_dev->caps.num_cqs, 1);
	if (ret) {
		dev_err(dev, "Init CQ context memory failed(%d).\n", ret);
		goto err_unmap_trrl;
	}

	if (hr_dev->caps.scc_ctx_entry_sz) {
		ret = hns_roce_init_hem_table(hr_dev,
					      &hr_dev->qp_table.scc_ctx_table,
					      HEM_TYPE_SCC_CTX,
					      hr_dev->caps.scc_ctx_entry_sz,
					      hr_dev->caps.num_qps, 1);
		if (ret) {
			dev_err(dev, "Init SCC context memory failed(%d).\n",
				ret);
			goto err_unmap_cq;
		}
	}

	if (hr_dev->caps.qpc_timer_entry_sz) {
		ret = hns_roce_init_hem_table(hr_dev,
					      &hr_dev->qpc_timer_table.table,
					      HEM_TYPE_QPC_TIMER,
					      hr_dev->caps.qpc_timer_entry_sz,
					      hr_dev->caps.num_qpc_timer, 1);
		if (ret) {
			dev_err(dev, "Init QPC timer memory failed(%d).\n",
				ret);
			goto err_unmap_ctx;
		}
	}

	if (hr_dev->caps.cqc_timer_entry_sz) {
		ret = hns_roce_init_hem_table(hr_dev,
					      &hr_dev->cqc_timer_table.table,
					      HEM_TYPE_CQC_TIMER,
					      hr_dev->caps.cqc_timer_entry_sz,
					      hr_dev->caps.num_cqc_timer, 1);
		if (ret) {
			dev_err(dev, "Init CQC timer memory failed(%d).\n",
				ret);
			goto err_unmap_qpc_timer;
		}
	}

	if (hr_dev->caps.srqc_entry_sz) {
		ret = hns_roce_init_hem_table(hr_dev, &hr_dev->srq_table.table,
					      HEM_TYPE_SRQC,
					      hr_dev->caps.srqc_entry_sz,
					      hr_dev->caps.num_srqs, 1);
		if (ret) {
			dev_err(dev, "Init SRQ context memory failed(%d).\n",
				ret);
			goto err_unmap_cqc_timer;
		}
	}

	if (hr_dev->caps.num_srqwqe_segs) {
		ret = hns_roce_init_hem_table(hr_dev,
					     &hr_dev->mr_table.mtt_srqwqe_table,
					     HEM_TYPE_SRQWQE,
					     hr_dev->caps.mtt_entry_sz,
					     hr_dev->caps.num_srqwqe_segs, 1);
		if (ret) {
			dev_err(dev, "Init MTT srqwqe memory failed(%d).\n",
				ret);
			goto err_unmap_srq;
		}
	}

	if (hr_dev->caps.num_idx_segs) {
		ret = hns_roce_init_hem_table(hr_dev,
					      &hr_dev->mr_table.mtt_idx_table,
					      HEM_TYPE_IDX,
					      hr_dev->caps.idx_entry_sz,
					      hr_dev->caps.num_idx_segs, 1);
		if (ret) {
			dev_err(dev, "Init MTT idx memory failed(%d).\n", ret);
			goto err_unmap_srqwqe;
		}
	}

	return 0;

err_unmap_srqwqe:
	if (hr_dev->caps.num_srqwqe_segs)
		hns_roce_cleanup_hem_table(hr_dev,
					   &hr_dev->mr_table.mtt_srqwqe_table);

err_unmap_srq:
	if (hr_dev->caps.srqc_entry_sz)
		hns_roce_cleanup_hem_table(hr_dev, &hr_dev->srq_table.table);

err_unmap_cqc_timer:
	if (hr_dev->caps.cqc_timer_entry_sz)
		hns_roce_cleanup_hem_table(hr_dev,
					   &hr_dev->cqc_timer_table.table);
err_unmap_qpc_timer:
	if (hr_dev->caps.qpc_timer_entry_sz)
		hns_roce_cleanup_hem_table(hr_dev,
					   &hr_dev->qpc_timer_table.table);

err_unmap_ctx:
	if (hr_dev->caps.scc_ctx_entry_sz)
		hns_roce_cleanup_hem_table(hr_dev,
					   &hr_dev->qp_table.scc_ctx_table);

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

err_unmap_mtt:
	if (hns_roce_check_whether_mhop(hr_dev, HEM_TYPE_CQE))
		hns_roce_cleanup_hem_table(hr_dev,
					   &hr_dev->mr_table.mtt_cqe_table);

err_unmap_cqe:
	hns_roce_cleanup_hem_table(hr_dev, &hr_dev->mr_table.mtt_table);

	return ret;
}

/**
 * hns_roce_setup_hca - setup host channel adapter
 * @hr_dev: pointer to hns roce device
 * Return : int
 */
static int hns_roce_setup_hca(struct hns_roce_dev *hr_dev)
{
	int ret;
	struct device *dev = hr_dev->dev;

	spin_lock_init(&hr_dev->sm_lock);
	spin_lock_init(&hr_dev->bt_cmd_lock);

	if (hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_RECORD_DB) {
		INIT_LIST_HEAD(&hr_dev->pgdir_list);
		mutex_init(&hr_dev->pgdir_mutex);
	}

	ret = hns_roce_init_uar_table(hr_dev);
	if (ret) {
		dev_err(dev, "Failed to init uar table(%d). aborting\n", ret);
		return ret;
	}

	ret = hns_roce_uar_alloc(hr_dev, &hr_dev->priv_uar);
	if (ret) {
		dev_err(dev, "Failed to allocate priv_uar(%d).\n", ret);
		goto err_uar_table_free;
	}

	ret = hns_roce_init_pd_table(hr_dev);
	if (ret) {
		dev_err(dev, "Failed to init pd table(%d).\n", ret);
		goto err_uar_alloc_free;
	}

	if (hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_XRC) {
		ret = hns_roce_init_xrcd_table(hr_dev);
		if (ret) {
			dev_err(dev, "Failed to init xrcd table(%d).\n", ret);
			goto err_pd_table_free;
		}
	}

	ret = hns_roce_init_mr_table(hr_dev);
	if (ret) {
		dev_err(dev, "Failed to init mr table(%d).\n", ret);
		goto err_xrcd_table_free;
	}

	ret = hns_roce_init_cq_table(hr_dev);
	if (ret) {
		dev_err(dev, "Failed to init cq table(%d).\n", ret);
		goto err_mr_table_free;
	}

	ret = hns_roce_init_qp_table(hr_dev);
	if (ret) {
		dev_err(dev, "Failed to init qp table(%d).\n", ret);
		goto err_cq_table_free;
	}

	if (hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_SRQ) {
		ret = hns_roce_init_srq_table(hr_dev);
		if (ret) {
			dev_err(dev,
				"Failed to init srq table(%d).\n", ret);
			goto err_qp_table_free;
		}
	}

	return 0;

err_qp_table_free:
	if (hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_SRQ)
		hns_roce_cleanup_qp_table(hr_dev);

err_cq_table_free:
	hns_roce_cleanup_cq_table(hr_dev);

err_mr_table_free:
	hns_roce_cleanup_mr_table(hr_dev);

err_xrcd_table_free:
	if (hr_dev->caps.flags & HNS_ROCE_CAP_FLAG_XRC)
		hns_roce_cleanup_xrcd_table(hr_dev);

err_pd_table_free:
	hns_roce_cleanup_pd_table(hr_dev);

err_uar_alloc_free:
	hns_roce_uar_free(hr_dev, &hr_dev->priv_uar);

err_uar_table_free:
	hns_roce_cleanup_uar_table(hr_dev);
	return ret;
}

static int hns_roce_reset(struct hns_roce_dev *hr_dev)
{
	int ret;

	if (hr_dev->hw->reset) {
		ret = hr_dev->hw->reset(hr_dev, true);
		if (ret)
			return ret;
	}
	hr_dev->is_reset = false;

	return 0;
}

static void hns_roce_find_armed_cq(struct list_head *cq_list, struct ib_cq *cq)
{
	struct hns_roce_cq *hr_cq = to_hr_cq(cq);
	unsigned long flags;

	spin_lock_irqsave(&hr_cq->lock, flags);
	if (hr_cq->comp && cq->comp_handler) {
		if (!hr_cq->comp_state) {
			hr_cq->comp_state = 1;
			list_add_tail(&hr_cq->list, cq_list);
		}
	}
	spin_unlock_irqrestore(&hr_cq->lock, flags);
}

/*
 * We need set device state before handle device err. So, sq/rq lock will be
 * effect to return error or involve cq.
 */
void hns_roce_handle_device_err(struct hns_roce_dev *hr_dev)
{
	struct hns_roce_qp *hr_qp;
	struct hns_roce_cq *hr_cq;
	struct list_head cq_list;
	unsigned long flags_qp;
	unsigned long flags;

	INIT_LIST_HEAD(&cq_list);

	spin_lock_irqsave(&hr_dev->qp_lock, flags);
	list_for_each_entry(hr_qp, &hr_dev->qp_list, list) {
		spin_lock_irqsave(&hr_qp->sq.lock, flags_qp);
		if (hr_qp->sq.tail != hr_qp->sq.head)
			hns_roce_find_armed_cq(&cq_list, hr_qp->ibqp.send_cq);
		spin_unlock_irqrestore(&hr_qp->sq.lock, flags_qp);

		spin_lock_irqsave(&hr_qp->rq.lock, flags_qp);
		if ((!hr_qp->ibqp.srq) && (hr_qp->rq.tail != hr_qp->rq.head))
			hns_roce_find_armed_cq(&cq_list, hr_qp->ibqp.recv_cq);
		spin_unlock_irqrestore(&hr_qp->rq.lock, flags_qp);
	}

	list_for_each_entry(hr_cq, &cq_list, list)
		hr_cq->comp(hr_cq);

	spin_unlock_irqrestore(&hr_dev->qp_lock, flags);
}
EXPORT_SYMBOL_GPL(hns_roce_handle_device_err);

int hns_roce_init(struct hns_roce_dev *hr_dev)
{
	int ret;
	struct device *dev = hr_dev->dev;

	ret = alloc_rdfx_info(hr_dev);
	if (ret) {
		dev_err(dev, "Alloc RoCE DFX failed(%d)!\n", ret);
		return ret;
	}
	ret = hns_roce_reset(hr_dev);
	if (ret) {
		free_rdfx_info(hr_dev);
		dev_err(dev, "Reset RoCE engine failed(%d)!\n", ret);
		return ret;
	}

	if (hr_dev->hw->cmq_init) {
		ret = hr_dev->hw->cmq_init(hr_dev);
		if (ret) {
			dev_err(dev, "Init RoCE cmq failed(%d)!\n", ret);
			goto error_failed_cmq_init;
		}
	}

	ret = hr_dev->hw->hw_profile(hr_dev);
	if (ret) {
		dev_err(dev, "Get RoCE engine profile failed(%d)!\n", ret);
		goto error_failed_cmd_init;
	}

	ret = hns_roce_cmd_init(hr_dev);
	if (ret) {
		dev_err(dev, "Cmd init failed(%d)!\n", ret);
		goto error_failed_cmd_init;
	}

	ret = hr_dev->hw->init_eq(hr_dev);
	if (ret) {
		dev_err(dev, "Eq init failed(%d)!\n", ret);
		goto error_failed_eq_table;
	}

	if (hr_dev->cmd_mod) {
		ret = hns_roce_cmd_use_events(hr_dev);
		if (ret) {
			dev_warn(dev,
				 "Cmd event  mode failed(%d), set back to poll!\n",
				 ret);
			hns_roce_cmd_use_polling(hr_dev);
		}
	}

	ret = hns_roce_init_hem(hr_dev);
	if (ret) {
		dev_err(dev, "Init HEM(Hardware Entry Memory) failed(%d)!\n",
			ret);
		goto error_failed_init_hem;
	}

	ret = hns_roce_setup_hca(hr_dev);
	if (ret) {
		dev_err(dev, "Setup hca failed(%d)!\n", ret);
		goto error_failed_setup_hca;
	}

	ret = hr_dev->hw->hw_init(hr_dev);
	if (ret) {
		dev_err(dev, "Hw_init failed(%d)!\n", ret);
		goto error_failed_engine_init;
	}

	INIT_LIST_HEAD(&hr_dev->qp_list);
	spin_lock_init(&hr_dev->qp_lock);

	ret = hns_roce_register_device(hr_dev);
	if (ret)
		goto error_failed_register_device;

	if (hr_dev->hw->create_workq) {
		ret = hr_dev->hw->create_workq(hr_dev);
		if (ret)
			goto error_failed_create_workq;
	}

	(void)hns_roce_register_sysfs(hr_dev);
	rdfx_set_dev_name(hr_dev);
	return 0;

error_failed_create_workq:
	hns_roce_unregister_device(hr_dev);

error_failed_register_device:
	if (hr_dev->hw->hw_exit)
		hr_dev->hw->hw_exit(hr_dev);

error_failed_engine_init:
	hns_roce_cleanup_bitmap(hr_dev);

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

error_failed_cmq_init:
	if (hr_dev->hw->reset) {
		if (hr_dev->hw->reset(hr_dev, false))
			dev_err(dev, "Dereset RoCE engine failed!\n");
	}

	free_rdfx_info(hr_dev);

	return ret;
}
EXPORT_SYMBOL_GPL(hns_roce_init);

void hns_roce_exit(struct hns_roce_dev *hr_dev)
{
	hns_roce_unregister_device(hr_dev);

	if (hr_dev->hw->destroy_workq)
		hr_dev->hw->destroy_workq(hr_dev);

	if (hr_dev->hw->hw_exit)
		hr_dev->hw->hw_exit(hr_dev);
	hns_roce_cleanup_bitmap(hr_dev);
	hns_roce_cleanup_hem(hr_dev);

	if (hr_dev->cmd_mod)
		hns_roce_cmd_use_polling(hr_dev);

	hr_dev->hw->cleanup_eq(hr_dev);
	hns_roce_cmd_cleanup(hr_dev);
	if (hr_dev->hw->cmq_exit)
		hr_dev->hw->cmq_exit(hr_dev);
	if (hr_dev->hw->reset)
		hr_dev->hw->reset(hr_dev, false);

	free_rdfx_info(hr_dev);
}
EXPORT_SYMBOL_GPL(hns_roce_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Huawei Tech. Co., Ltd.");
MODULE_DESCRIPTION("HNS RoCE Driver");
