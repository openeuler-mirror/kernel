// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */
#include "nbl_dev.h"
#include "nbl_service.h"

#define VENDOR_PHYTIUM	0x70
#define VENDOR_MASK	0xFF
#define VENDOR_OFFSET	24

static struct nbl_userdev {
	struct cdev cdev;
	struct class *cls;
	struct idr cidr;
	dev_t cdevt;
	struct mutex clock; /* lock character device */
	struct list_head glist;
	struct mutex glock; /* lock iommu group list */
	bool success;
} nbl_userdev;

#if (IS_ENABLED(CONFIG_VFIO) && IS_ENABLED(CONFIG_VFIO_MDEV))
struct nbl_vfio_batch {
	unsigned long *pages_out;
	unsigned long *pages_in;
	int size;
	int offset;
	struct page **h_page;
};

struct nbl_userdev_dma {
	struct rb_node node;
	dma_addr_t iova;
	unsigned long vaddr;
	size_t size;
	unsigned long pfn;
};
#endif /* !(CONFIG_VFIO&&CONFIG_VFIO_MDEV) */

bool nbl_dma_iommu_status(struct pci_dev *pdev)
{
	struct device *dev = &pdev->dev;

	if (dev->iommu_group && iommu_get_domain_for_dev(dev))
		return 1;

	return 0;
}

bool nbl_dma_remap_status(struct pci_dev *pdev, u64 *dma_limit)
{
	struct device *dev = &pdev->dev;
	struct iommu_domain *domain;
	dma_addr_t dma_mask = dma_get_mask(dev);

	/* get dma_limit references iommu_dma_alloc_iova */
	*dma_limit = min_not_zero(dma_mask, dev->bus_dma_limit);

	domain = iommu_get_domain_for_dev(dev);
	if (!domain)
		return 0;

	if (domain->geometry.force_aperture)
		*dma_limit = min_t(u64, *dma_limit, domain->geometry.aperture_end);

	if (domain->type & IOMMU_DOMAIN_IDENTITY)
		return 0;

	return 1;
}

static char *user_cdevnode(const struct device *dev, umode_t *mode)
{
	return kasprintf(GFP_KERNEL, "nbl_userdev/%s", dev_name(dev));
}

static void nbl_user_change_kernel_network(struct nbl_dev_user *user)
{
	struct nbl_adapter *adapter = user->adapter;
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_dev_net *net_dev = NBL_DEV_MGT_TO_NET_DEV(dev_mgt);
	struct net_device *netdev = net_dev->netdev;
	int ret;

	if (user->network_type == NBL_KERNEL_NETWORK)
		return;

	ret = serv_ops->switch_traffic_default_dest(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
						    NBL_DEV_USER_TO_KERNEL);
	if (ret) {
		netdev_err(netdev, "network changes to kernel space failed %d\n", ret);
		return;
	}

	user->network_type = NBL_KERNEL_NETWORK;
	netdev_info(netdev, "network changes to kernel space\n");
}

static int nbl_user_change_user_network(struct nbl_dev_user *user)
{
	struct nbl_adapter *adapter = user->adapter;
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_dev_net *net_dev = NBL_DEV_MGT_TO_NET_DEV(dev_mgt);
	struct net_device *netdev = net_dev->netdev;
	int ret = 0;

	if (user->network_type == NBL_USER_NETWORK)
		return 0;

	ret = serv_ops->switch_traffic_default_dest(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
						    NBL_DEV_KERNEL_TO_USER);

	if (ret) {
		netdev_err(netdev, "network changes to user space failed %u\n", ret);
		return ret;
	}

	user->network_type = NBL_USER_NETWORK;
	netdev_info(netdev, "network changes to user\n");

	return ret;
}

static void nbl_restore_cfg(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);

	serv_ops->unregister_upcall_port(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt));
}

static int nbl_cdev_open(struct inode *inode, struct file *filep)
{
	struct nbl_adapter *p;
	struct nbl_dev_mgt *dev_mgt;
	struct nbl_dev_user *user;
	int opened;

	mutex_lock(&nbl_userdev.clock);
	p = idr_find(&nbl_userdev.cidr, iminor(inode));
	mutex_unlock(&nbl_userdev.clock);

	if (!p)
		return -ENODEV;

	if (test_bit(NBL_FATAL_ERR, p->state))
		return -EIO;

	dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(p);
	user = NBL_DEV_MGT_TO_USER_DEV(dev_mgt);
	opened = atomic_cmpxchg(&user->open_cnt, 0, 1);
	if (opened)
		return -EBUSY;

	rtnl_lock();
	if (test_bit(NBL_XDP, p->state)) {
		atomic_set(&user->open_cnt, 0);
		rtnl_unlock();
		return -EIO;
	}

	set_bit(NBL_USER, p->state);
	rtnl_unlock();

	filep->private_data = p;

	return 0;
}

static void nbl_uservsi_release(struct nbl_dev_mgt *dev_mgt)
{
	struct nbl_channel_ops *chan_ops = NBL_DEV_MGT_TO_CHAN_OPS(dev_mgt);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_dev_user *user = NBL_DEV_MGT_TO_USER_DEV(dev_mgt);

	chan_ops->clear_listener_info(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt));
	nbl_restore_cfg(dev_mgt);
	nbl_user_change_kernel_network(user);
	serv_ops->config_fd_flow_state(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
				       NBL_CHAN_FDIR_RULE_ISOLATE, NBL_FD_STATE_FLUSH);
	serv_ops->clear_flow(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), user->user_vsi);
	if (user->dsch_status) {
		serv_ops->vsi_hw_stop(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), user->user_vsi);
		user->dsch_status = false;
	}
	atomic_set(&user->open_cnt, 0);
	user->user_promisc_mode = 0;
}

static int nbl_cdev_release(struct inode *inode, struct file *filp)
{
	struct nbl_adapter *adapter = filp->private_data;
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);

	nbl_uservsi_release(dev_mgt);
	clear_bit(NBL_USER, adapter->state);

	return 0;
}

static int nbl_userdev_common_mmap(struct nbl_adapter *adapter, struct vm_area_struct *vma)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_dev_user *user = NBL_DEV_MGT_TO_USER_DEV(dev_mgt);
	struct pci_dev *pdev = adapter->pdev;
	unsigned int index;
	u64 phys_len, req_len, req_start, pgoff;
	int ret;

	index = vma->vm_pgoff >> (NBL_DEV_USER_PCI_OFFSET_SHIFT - PAGE_SHIFT);
	pgoff = vma->vm_pgoff & ((1U << (NBL_DEV_USER_PCI_OFFSET_SHIFT - PAGE_SHIFT)) - 1);

	/* index is derived from userspace mmap offset, and is used to
	 * index pdev->resource[] through pci_resource_len()/pci_resource_start(),
	 * so it must be validated before use.
	 */
	if (index >= DEVICE_COUNT_RESOURCE)
		return -EINVAL;

	req_len = vma->vm_end - vma->vm_start;
	req_start = pgoff << PAGE_SHIFT;

	if (index == NBL_DEV_SHM_MSG_RING_INDEX)
		phys_len = NBL_USER_DEV_SHMMSGRING_SIZE;
	else
		phys_len = PAGE_ALIGN(pci_resource_len(pdev, index));

	if (req_start + req_len > phys_len)
		return -EINVAL;

	if (index == NBL_DEV_SHM_MSG_RING_INDEX) {
		struct page *page = virt_to_page((char *)user->shm_msg_ring +
					(pgoff << PAGE_SHIFT));
		vma->vm_pgoff = pgoff;
		ret = remap_pfn_range(vma, vma->vm_start, page_to_pfn(page),
				      req_len, vma->vm_page_prot);
		return ret;
	}

	vma->vm_private_data = adapter;
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	vma->vm_pgoff = (pci_resource_start(pdev, index) >> PAGE_SHIFT) + pgoff;

	vm_flags_set(vma, VM_IO | VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP);
	ret = io_remap_pfn_range(vma, vma->vm_start, vma->vm_pgoff,
				 vma->vm_end - vma->vm_start, vma->vm_page_prot);
	return ret;
}

static int nbl_cdev_mmap(struct file *filep, struct vm_area_struct *vma)
{
	struct nbl_adapter *adapter = filep->private_data;

	return nbl_userdev_common_mmap(adapter, vma);
}

static int nbl_userdev_register_net(struct nbl_adapter *adapter, void *resp,
				    struct nbl_chan_send_info *chan_send)
{
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_dev_net *net_dev = NBL_DEV_MGT_TO_NET_DEV(dev_mgt);
	struct nbl_register_net_result *result = (struct nbl_register_net_result *)resp;
	struct nbl_dev_vsi *vsi;
	int ret = 0;

	vsi = net_dev->vsi_ctrl.vsi_list[NBL_VSI_USER];

	memset(result, 0, sizeof(*result));
	result->tx_queue_num = vsi->queue_num;
	result->rx_queue_num = vsi->queue_num;
	result->rdma_enable = 0;
	result->queue_offset = vsi->queue_offset;
	result->trusted = 1;

	if (vsi->queue_num == 0)
		ret = -ENOSPC;

	chan_send->ack_len = sizeof(struct nbl_register_net_result);

	return ret;
}

static int nbl_userdev_alloc_txrx_queues(struct nbl_adapter *adapter,
					 struct nbl_chan_send_info *chan_send)
{
	chan_send->ack_len = 0;

	return 0;
}

static int nbl_userdev_get_vsi_id(struct nbl_adapter *adapter, void *resp,
				  struct nbl_chan_send_info *chan_send)
{
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_dev_net *net_dev = NBL_DEV_MGT_TO_NET_DEV(dev_mgt);
	struct nbl_ch_prm_get_vsi *result;
	struct nbl_dev_vsi *vsi;

	vsi = net_dev->vsi_ctrl.vsi_list[NBL_VSI_USER];
	result = (struct nbl_ch_prm_get_vsi *)resp;
	result->vsi_id = vsi->vsi_id;

	chan_send->ack_len = sizeof(struct nbl_ch_prm_get_vsi);

	return 0;
}

static void nbl_userdev_translate_register_vsi2q(struct nbl_chan_send_info *chan_send)
{
	struct nbl_chan_param_register_vsi2q *param = chan_send->arg;

	param->vsi_index = NBL_VSI_USER;
}

static void nbl_userdev_translate_clear_queues(struct nbl_chan_send_info *chan_send)
{
	chan_send->msg_type = NBL_CHAN_MSG_REMOVE_RSS;
}

static bool nbl_userdev_get_dsch_cfg(struct nbl_chan_send_info *chan_send)
{
	struct nbl_chan_param_cfg_dsch *param = chan_send->arg;

	return param->vld;
}

static int nbl_userdev_get_firmware_version(struct nbl_adapter *adapter, void *resp,
					    struct nbl_chan_send_info *chan_send)
{
	struct nbl_common_info *common = NBL_ADAPTER_TO_COMMON(adapter);

	memcpy(resp, common->firmware_version, NBL_FRIMWARE_VERSION_LEN);
	chan_send->ack_len = NBL_FRIMWARE_VERSION_LEN;

	return 0;
}

static long nbl_userdev_channel_ioctl(struct nbl_adapter *adapter, unsigned long arg)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_dev_user *user = NBL_DEV_MGT_TO_USER_DEV(dev_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DEV_MGT_TO_CHAN_OPS(dev_mgt);
	struct nbl_chan_send_info chan_send = {0};
	struct nbl_dev_user_channel_msg *msg;
	void *resp;
	int ret = 0;

	msg = vmalloc(sizeof(*msg));
	if (!msg)
		return -ENOMEM;

	if (copy_from_user(msg, (void __user *)arg, sizeof(*msg))) {
		vfree(msg);
		return -EFAULT;
	}

	resp = (unsigned char *)msg->data + msg->arg_len;
	resp = (void *)ALIGN((uintptr_t)resp, 4);
	NBL_CHAN_SEND(chan_send, msg->dst_id, msg->msg_type, msg->data, msg->arg_len,
		      resp, msg->ack_length, msg->ack);

	dev_dbg(&adapter->pdev->dev, "msg_type %u, arg_len %u, request %llx, resp %llx\n",
		msg->msg_type, msg->arg_len, (u64)(uintptr_t)msg->data, (u64)(uintptr_t)resp);

	switch (msg->msg_type) {
	case NBL_CHAN_MSG_REGISTER_NET:
		ret = nbl_userdev_register_net(adapter, resp, &chan_send);
		break;
	case NBL_CHAN_MSG_ALLOC_TXRX_QUEUES:
		ret = nbl_userdev_alloc_txrx_queues(adapter, &chan_send);
		break;
	case NBL_CHAN_MSG_GET_VSI_ID:
		ret = nbl_userdev_get_vsi_id(adapter, resp, &chan_send);
		break;
	case NBL_CHAN_MSG_UNREGISTER_NET:
	case NBL_CHAN_MSG_ADD_MULTI_RULE:
	case NBL_CHAN_MSG_DEL_MULTI_RULE:
	case NBL_CHAN_MSG_FREE_TXRX_QUEUES:
	case NBL_CHAN_MSG_CLEAR_FLOW:
		break;
	case NBL_CHAN_MSG_CFG_DSCH:
		user->dsch_status = nbl_userdev_get_dsch_cfg(&chan_send);
		ret = chan_ops->send_msg(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt), &chan_send);
		break;
	case NBL_CHAN_MSG_CLEAR_QUEUE:
		nbl_userdev_translate_clear_queues(&chan_send);
		ret = chan_ops->send_msg(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt), &chan_send);
		break;
	case NBL_CHAN_MSG_REGISTER_VSI2Q:
		nbl_userdev_translate_register_vsi2q(&chan_send);
		ret = chan_ops->send_msg(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt), &chan_send);
		break;
	case NBL_CHAN_MSG_GET_FIRMWARE_VERSION:
		ret = nbl_userdev_get_firmware_version(adapter, resp, &chan_send);
		break;
	default:
		ret = chan_ops->send_msg(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt), &chan_send);
		break;
	}

	msg->ack_length = chan_send.ack_len;
	msg->ack_err = ret;
	ret = copy_to_user((void __user *)arg, msg, sizeof(*msg));

	vfree(msg);

	return ret;
}

static long nbl_userdev_switch_network(struct nbl_adapter *adapter, unsigned long arg)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_dev_user *user = NBL_DEV_MGT_TO_USER_DEV(dev_mgt);
	struct nbl_dev_net *net_dev = NBL_DEV_MGT_TO_NET_DEV(dev_mgt);
	struct nbl_dev_vsi *vsi;
	struct nbl_ch_prm_cfg_multi_mcast mcast;
	struct nbl_ch_prm_set_promisc_mode promisc_prm = {0};
	int timeout = 50;
	int type;

	if (get_user(type, (unsigned long __user *)arg)) {
		dev_err(NBL_ADAPTER_TO_DEV(adapter),
			"switch network get type failed\n");
		return -EFAULT;
	}

	if (type == user->network_type)
		return 0;

	while (test_bit(NBL_RESETTING, adapter->state)) {
		timeout--;
		if (!timeout) {
			dev_err(NBL_ADAPTER_TO_DEV(adapter),
				"Timeout while resetting in user change state\n");
			return -EBUSY;
		}
		usleep_range(1000, 2000);
	}

	/* todolist: concurreny about adapter->state */
	vsi = net_dev->vsi_ctrl.vsi_list[NBL_VSI_USER];
	if (type == NBL_USER_NETWORK) {
		nbl_user_change_user_network(user);
		promisc_prm.vsi_id = vsi->vsi_id;
		promisc_prm.mode = user->user_promisc_mode;
		serv_ops->set_promisc_mode(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), &promisc_prm);
		mcast.vsi = vsi->vsi_id;
		mcast.enable = user->user_mcast_mode;
		serv_ops->cfg_multi_mcast(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), &mcast);
	} else {
		nbl_user_change_kernel_network(user);
	}

	return 0;
}

static long nbl_userdev_get_ifindex(struct nbl_adapter *adapter, unsigned long arg)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_dev_net *net_dev = NBL_DEV_MGT_TO_NET_DEV(dev_mgt);
	struct net_device *netdev = net_dev->netdev;
	int ifindex, ret;

	ifindex = netdev->ifindex;
	ret = copy_to_user((void __user *)arg, &ifindex, sizeof(ifindex));
	return ret;
}

static long nbl_userdev_clear_eventfd(struct nbl_adapter *adapter, unsigned long arg)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_channel_ops *chan_ops = NBL_DEV_MGT_TO_CHAN_OPS(dev_mgt);

	chan_ops->clear_listener_info(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt));

	return 0;
}

static long nbl_userdev_set_listener(struct nbl_adapter *adapter, unsigned long arg)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_channel_ops *chan_ops = NBL_DEV_MGT_TO_CHAN_OPS(dev_mgt);
	int msgtype;

	if (get_user(msgtype, (unsigned long __user *)arg)) {
		dev_err(NBL_ADAPTER_TO_DEV(adapter), "get listener msgtype failed\n");
		return -EFAULT;
	}

	chan_ops->set_listener_msgtype(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt), msgtype);

	return 0;
}

static long nbl_userdev_set_eventfd(struct nbl_adapter *adapter, unsigned long arg)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_dev_user *user = NBL_DEV_MGT_TO_USER_DEV(dev_mgt);
	struct nbl_channel_ops *chan_ops = NBL_DEV_MGT_TO_CHAN_OPS(dev_mgt);
	struct eventfd_ctx *ctx;
	struct fd eventfd;
	int fd;
	long ret = 0;

	if (get_user(fd, (unsigned long __user *)arg)) {
		dev_err(NBL_ADAPTER_TO_DEV(adapter), "get user fd failed\n");
		return -EFAULT;
	}

	eventfd = fdget(fd);
	if (!eventfd.file) {
		dev_err(NBL_ADAPTER_TO_DEV(adapter), "get eventfd failed\n");
		return -EBADF;
	}

	ctx = eventfd_ctx_fileget(eventfd.file);
	if (IS_ERR(ctx)) {
		ret = PTR_ERR(ctx);
		dev_err(NBL_ADAPTER_TO_DEV(adapter), "get eventfd ctx failed\n");
		return ret;
	}

	chan_ops->set_listener_info(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt), user->shm_msg_ring, ctx);

	return ret;
}

static long nbl_userdev_get_bar_size(struct nbl_adapter *adapter, unsigned long arg)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	size_t size = pci_resource_len(adapter->pdev, 0);
	u8 __iomem *hw_addr;
	int ret;

	hw_addr = serv_ops->get_hw_addr(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt), &size);
	ret = copy_to_user((void __user *)arg, &size, sizeof(size));

	return ret;
}

static long nbl_userdev_get_dma_limit(struct nbl_adapter *adapter, unsigned long arg)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_dev_user *user = NBL_DEV_MGT_TO_USER_DEV(dev_mgt);

	/**
	 * Linux kernel perfers to use 32-bit IOVAs, when 32-bit address space has been used.
	 * Then attempt to use high address space.
	 * The order of allocation is from high address to low address.
	 *
	 * DPDK setting the starting address at 4GB, please reference eal_get_baseaddr.
	 * So dpdk iova almost not conflict with kernel.
	 * Like heap-stack, kernel alloc iova from high to low, dpdk alloc iova from low to high.
	 *
	 * But in the scene, linux kernel config is passthrough,
	 * nbl device has been modify to DMA by sysfs,
	 * concurrent dpdk attach a device base uio, now dpdk use pa as iova.
	 * Now pa maybe below 4G, and iommu map(iova(pa)->pa) may conflict with kernel.
	 *
	 * So dpdk remap policy is when dpdk use iova, not set iova msb.
	 * when dpdk use pa as iova, set iova msb.
	 * The best way is call reserve_iova to keep consistent between dpdk and kernel.
	 * But struct iommu_dma_cookie not export symbols, we cannot get struct iova_domain
	 * by struct iommu_domain->iova_cookie->iovad except define struct iommu_dma_cookie
	 * in driver code.
	 */

	return copy_to_user((void __user *)arg, &user->dma_limit, sizeof(user->dma_limit));
}

static long nbl_userdev_set_multi_mode(struct nbl_adapter *adapter, unsigned int cmd,
				       unsigned long arg)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_service_ops *serv_ops = NBL_DEV_MGT_TO_SERV_OPS(dev_mgt);
	struct nbl_dev_user *user = NBL_DEV_MGT_TO_USER_DEV(dev_mgt);
	struct nbl_dev_net *net_dev = NBL_DEV_MGT_TO_NET_DEV(dev_mgt);
	struct nbl_dev_vsi *vsi;
	struct nbl_ch_prm_cfg_multi_mcast mcast;
	struct nbl_ch_prm_set_promisc_mode promisc_prm = {0};
	u16 user_multi_mode;
	int ret = 0;

	if (get_user(user_multi_mode, (unsigned long __user *)arg)) {
		dev_err(NBL_ADAPTER_TO_DEV(adapter),
			"set promic mode get mode failed\n");
		return -EFAULT;
	}

	if (cmd == NBL_DEV_USER_SET_PROMISC_MODE && user_multi_mode == user->user_promisc_mode)
		return 0;

	if (cmd == NBL_DEV_USER_SET_MCAST_MODE && user_multi_mode == user->user_mcast_mode)
		return 0;

	vsi = net_dev->vsi_ctrl.vsi_list[NBL_VSI_USER];
	if (user->network_type == NBL_USER_NETWORK) {
		if (cmd == NBL_DEV_USER_SET_PROMISC_MODE) {
			promisc_prm.vsi_id = vsi->vsi_id;
			promisc_prm.mode = user_multi_mode;
			ret = serv_ops->set_promisc_mode(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
							 &promisc_prm);
		} else {
			mcast.vsi = vsi->vsi_id;
			mcast.enable = user_multi_mode;
			ret = serv_ops->cfg_multi_mcast(NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt),
							&mcast);
		}
	}

	if (cmd == NBL_DEV_USER_SET_PROMISC_MODE)
		user->user_promisc_mode = user_multi_mode;
	else
		user->user_mcast_mode = user_multi_mode;

	return ret;
}

static long nbl_userdev_common_ioctl(struct nbl_adapter *adapter, unsigned int cmd,
				     unsigned long arg)
{
	int ret = -EINVAL;

	switch (cmd) {
	case NBL_DEV_USER_CHANNEL:
		ret = nbl_userdev_channel_ioctl(adapter, arg);
		break;
	case NBL_DEV_USER_MAP_DMA:
	case NBL_DEV_USER_UNMAP_DMA:
		break;
	case NBL_DEV_USER_SWITCH_NETWORK:
		ret = nbl_userdev_switch_network(adapter, arg);
		break;
	case NBL_DEV_USER_GET_IFINDEX:
		ret = nbl_userdev_get_ifindex(adapter, arg);
		break;
	case NBL_DEV_USER_SET_EVENTFD:
		ret = nbl_userdev_set_eventfd(adapter, arg);
		break;
	case NBL_DEV_USER_CLEAR_EVENTFD:
		ret = nbl_userdev_clear_eventfd(adapter, arg);
		break;
	case NBL_DEV_USER_SET_LISTENER:
		ret = nbl_userdev_set_listener(adapter, arg);
		break;
	case NBL_DEV_USER_GET_BAR_SIZE:
		ret = nbl_userdev_get_bar_size(adapter, arg);
		break;
	case NBL_DEV_USER_GET_DMA_LIMIT:
		ret = nbl_userdev_get_dma_limit(adapter, arg);
		break;
	case NBL_DEV_USER_SET_PROMISC_MODE:
	case NBL_DEV_USER_SET_MCAST_MODE:
		ret = nbl_userdev_set_multi_mode(adapter, cmd, arg);
		break;
	default:
		break;
	}

	return ret;
}

static long nbl_cdev_unlock_ioctl(struct file *filep, unsigned int cmd,
				  unsigned long arg)
{
	struct nbl_adapter *adapter = filep->private_data;

	return nbl_userdev_common_ioctl(adapter, cmd, arg);
}

static const struct file_operations nbl_cdev_fops = {
	.owner = THIS_MODULE,
	.open = nbl_cdev_open,
	.unlocked_ioctl = nbl_cdev_unlock_ioctl,
	.compat_ioctl = compat_ptr_ioctl,
	.release = nbl_cdev_release,
	.mmap = nbl_cdev_mmap,
};

#if (IS_ENABLED(CONFIG_VFIO) && IS_ENABLED(CONFIG_VFIO_MDEV))
static ssize_t nbl_vfio_read(struct vfio_device *vdev, char __user *buf,
			     size_t count, loff_t *ppos)
{
	return -EFAULT;
}

static ssize_t nbl_vfio_write(struct vfio_device *vdev, const char __user *buf,
			      size_t count, loff_t *ppos)
{
	return count;
}

#define NBL_VFIO_BATCH_MAX_CAPACITY	(PAGE_SIZE / sizeof(unsigned long))

static int nbl_vfio_batch_init(struct nbl_vfio_batch *batch)
{
	batch->offset = 0;
	batch->size = 0;

	batch->pages_in = (unsigned long *)__get_free_page(GFP_KERNEL);
	if (!batch->pages_in)
		return -ENOMEM;

	batch->pages_out = (unsigned long *)__get_free_page(GFP_KERNEL);
	if (!batch->pages_out) {
		free_page((unsigned long)batch->pages_in);
		return -ENOMEM;
	}

	batch->h_page = kzalloc(NBL_VFIO_BATCH_MAX_CAPACITY * sizeof(struct page *), GFP_KERNEL);
	if (!batch->h_page) {
		free_page((unsigned long)batch->pages_in);
		free_page((unsigned long)batch->pages_out);
		return -ENOMEM;
	}

	return 0;
}

static void nbl_vfio_batch_fini(struct nbl_vfio_batch *batch)
{
	if (batch->pages_in)
		free_page((unsigned long)batch->pages_in);

	if (batch->pages_out)
		free_page((unsigned long)batch->pages_out);

	kfree(batch->h_page);
}

static struct nbl_userdev_dma *nbl_userdev_find_dma(struct nbl_dev_user_iommu_group *group,
						    dma_addr_t start, size_t size)
{
	struct rb_node *node = group->dma_tree.rb_node;

	while (node) {
		struct nbl_userdev_dma *dma = rb_entry(node, struct nbl_userdev_dma, node);

		if (start + size <= dma->vaddr)
			node = node->rb_left;
		else if (start >= dma->vaddr + dma->size)
			node = node->rb_right;
		else
			return dma;
	}

	return NULL;
}

static struct rb_node *nbl_userdev_find_dma_first_node(struct nbl_dev_user_iommu_group *group,
						       dma_addr_t start, size_t size)
{
	struct rb_node *res = NULL;
	struct rb_node *node = group->dma_tree.rb_node;
	struct nbl_userdev_dma *dma_res = NULL;

	while (node) {
		struct nbl_userdev_dma *dma = rb_entry(node, struct nbl_userdev_dma, node);

		if (start < dma->vaddr + dma->size) {
			res = node;
			dma_res = dma;
			if (start >= dma->vaddr)
				break;
			node = node->rb_left;
		} else {
			node = node->rb_right;
		}
	}
	if (res && size && dma_res->vaddr >= start + size)
		res = NULL;
	return res;
}

/**
 * check dma conflict when multi devices in one iommu group, That is, when ACS not support.
 * return -1 means multi devices conflict.
 * return 1 means mapping exist and not conflict.
 * return 0 means mapping not existed.
 */
static int nbl_userdev_check_dma_conflict(struct nbl_dev_user *user,
					  unsigned long vaddr, dma_addr_t iova, size_t size)
{
	struct nbl_dev_user_iommu_group *group = user->group;
	struct nbl_userdev_dma *dma;
	struct rb_node *n;
	struct page *h_page;
	size_t unmapped = 0;
	unsigned long vfn, pfn, vaddr_new;
	dma_addr_t iova_new;
	int ret;

	dma = nbl_userdev_find_dma(group, vaddr, 1);
	if (dma && dma->vaddr != vaddr)
		return -1;

	dma = nbl_userdev_find_dma(group, vaddr + size - 1, 0);
	if (dma && dma->vaddr + dma->size != vaddr + size)
		return -1;

	if (!nbl_userdev_find_dma(group, vaddr, size))
		return 0;

	n = nbl_userdev_find_dma_first_node(group, vaddr, size);
	vaddr_new = vaddr;
	iova_new = iova;
	while (n) {
		dma = rb_entry(n, struct nbl_userdev_dma, node);
		if (dma->iova >= iova + size)
			break;

		if (dma->vaddr >= vaddr + size)
			break;

		if (dma->vaddr != vaddr_new || dma->iova != iova_new)
			break;

		vfn = vaddr_new >> PAGE_SHIFT;
		ret = vfio_pin_pages(NBL_USERDEV_TO_VFIO_DEV(user),
				     vaddr_new, 1, IOMMU_READ | IOMMU_WRITE, &h_page);
		if (ret <= 0)
			break;

		pfn = page_to_pfn(h_page);
		vfio_unpin_pages(NBL_USERDEV_TO_VFIO_DEV(user), vaddr_new, 1);
		if (pfn != dma->pfn)
			break;

		n = rb_next(n);
		unmapped += dma->size;
		vaddr_new += dma->size;
		iova_new += dma->size;
	}

	if (unmapped != size)
		return -1;

	return 1;
}

static void nbl_userdev_link_dma(struct nbl_dev_user_iommu_group *group,
				 struct nbl_userdev_dma *new)
{
	struct rb_node **link = &group->dma_tree.rb_node, *parent = NULL;
	struct nbl_userdev_dma *dma;

	while (*link) {
		parent = *link;
		dma = rb_entry(parent, struct nbl_userdev_dma, node);

		if (new->vaddr + new->size <= dma->vaddr)
			link = &(*link)->rb_left;
		else
			link = &(*link)->rb_right;
	}

	rb_link_node(&new->node, parent, link);
	rb_insert_color(&new->node, &group->dma_tree);
}

#ifdef CONFIG_ARM64
static int check_phytium_cpu(void)
{
	u32 midr = read_cpuid_id();
	u32 vendor = (midr >> VENDOR_OFFSET) & VENDOR_MASK;

	if (vendor == VENDOR_PHYTIUM)
		return 1;

	return 0;
}
#endif

static void nbl_userdev_remove_dma(struct nbl_dev_user_iommu_group *group,
				   struct nbl_userdev_dma *dma)
{
	struct nbl_vfio_batch batch;
	size_t unmmaped;
	long npage, batch_pages;
	unsigned long vaddr;
	int ret, caps;
	unsigned long *ppfn, pfn;
	int i = 0;

	dev_dbg(group->dev, "dma remove: vaddr 0x%lx, iova 0x%llx, size 0x%zx\n",
		dma->vaddr, (u64)dma->iova, dma->size);
	unmmaped = iommu_unmap(iommu_get_domain_for_dev(group->dev), dma->iova, dma->size);
	WARN_ON(unmmaped != dma->size);
	/**
	 * For kylin + FT Server, Exist dma invalid content when smmu translate mode.
	 * We can flush iommu tlb force to avoid the problem.
	 */
#ifdef CONFIG_ARM64
	if (check_phytium_cpu())
		iommu_flush_iotlb_all(iommu_get_domain_for_dev(group->dev));
#endif

	ret = nbl_vfio_batch_init(&batch);
	if (ret) {
		caps = 1;
		ppfn = &pfn;
	} else {
		caps = NBL_VFIO_BATCH_MAX_CAPACITY;
		ppfn = batch.pages_in;
	}

	npage = dma->size >> PAGE_SHIFT;
	vaddr = dma->vaddr;

	while (npage) {
		if (npage >= caps)
			batch_pages = caps;
		else
			batch_pages = npage;

		ppfn[0] = vaddr >> PAGE_SHIFT;
		for (i = 1; i < batch_pages; i++)
			ppfn[i] =  ppfn[i - 1] + 1;

		vfio_unpin_pages(group->vdev, vaddr, batch_pages);
		dev_dbg(group->dev, "unpin pages 0x%lx, npages %ld, ret %d\n",
			ppfn[0], batch_pages, ret);
		npage -= batch_pages;
		vaddr += (batch_pages << PAGE_SHIFT);
	}

	nbl_vfio_batch_fini(&batch);
	rb_erase(&dma->node, &group->dma_tree);
	kfree(dma);
}

static long nbl_userdev_dma_map_ioctl(struct nbl_dev_user *user, unsigned long arg)
{
	struct nbl_dev_user_dma_map map;
	struct nbl_adapter *adapter = user->adapter;
	struct pci_dev *pdev = adapter->pdev;
	struct device *dev = &pdev->dev;
	struct nbl_vfio_batch batch;
	struct nbl_userdev_dma *dma;
	unsigned long minsz, pfn_base = 0, pfn;
	unsigned long vaddr;
	dma_addr_t iova;
	u32 mask = NBL_DEV_USER_DMA_MAP_FLAG_READ | NBL_DEV_USER_DMA_MAP_FLAG_WRITE;
	size_t size;
	long npage, batch_pages, pinned = 0;
	int i, ret = 0;
	phys_addr_t phys;

	minsz = offsetofend(struct nbl_dev_user_dma_map, size);

	if (copy_from_user(&map, (void __user *)arg, minsz))
		return -EFAULT;

	if (map.argsz < minsz || map.flags & ~mask)
		return -EINVAL;

	npage = map.size >> PAGE_SHIFT;
	vaddr = map.vaddr;
	iova = map.iova;

	if (!npage)
		return ret;
	mutex_lock(&user->group->dma_tree_lock);
	ret = nbl_userdev_check_dma_conflict(user, vaddr, iova, map.size);
	if (ret < 0) {
		dev_err(dev, "multiple dma not equal\n");
		ret = -EINVAL;
		goto mutext_unlock;
	}

	if (ret) {
		ret = 0;
		goto mutext_unlock;
	}

	dma = kzalloc(sizeof(*dma), GFP_KERNEL);
	if (!dma) {
		ret = -ENOMEM;
		goto mutext_unlock;
	}

	if (nbl_vfio_batch_init(&batch)) {
		kfree(dma);
		ret = -ENOMEM;
		goto mutext_unlock;
	}

	while (npage) {
		if (batch.size == 0) {
			if (npage >= NBL_VFIO_BATCH_MAX_CAPACITY)
				batch_pages = NBL_VFIO_BATCH_MAX_CAPACITY;
			else
				batch_pages = npage;
			batch.pages_in[0] = vaddr >> PAGE_SHIFT;
			for (i = 1; i < batch_pages; i++)
				batch.pages_in[i] = batch.pages_in[i - 1] + 1;
			ret = vfio_pin_pages(NBL_USERDEV_TO_VFIO_DEV(user), vaddr, batch_pages,
					     IOMMU_READ | IOMMU_WRITE, batch.h_page);

			dev_dbg(dev, "page %ld pages, return %d\n", batch_pages, batch.size);
			if (ret <= 0) {
				dev_err(dev, "pin page failed\n");
				goto unwind;
			}

			for (i = 0; i < batch_pages; i++)
				batch.pages_out[i] = page_to_pfn(batch.h_page[i]);
			batch.offset = 0;
			batch.size = ret;
			if (!pfn_base) {
				pfn_base = batch.pages_out[batch.offset];
				dma->pfn = batch.pages_out[batch.offset];
			}
		}

		while (batch.size) {
			pfn = batch.pages_out[batch.offset];
			if (pfn == (pfn_base + pinned)) {
				pinned++;
				vaddr += PAGE_SIZE;
				batch.offset++;
				batch.size--;
				npage--;
				continue;
			}

			size = pinned << PAGE_SHIFT;
			phys = pfn_base << PAGE_SHIFT;
			ret = iommu_map(iommu_get_domain_for_dev(dev), iova, phys,
					size, IOMMU_READ | IOMMU_WRITE | IOMMU_CACHE, GFP_KERNEL);
			if (ret) {
				dev_err(dev, "iommu_map failed\n");
				goto unwind;
			}
			dev_dbg(dev, "iommu map succeed, iova 0x%llx, phys 0x%llx, size 0x%llx\n",
				(u64)iova, (u64)phys, (u64)size);
			pfn_base = pfn;
			pinned = 0;
			iova += size;
		}
	}

	if (pinned) {
		size = pinned << PAGE_SHIFT;
		phys = pfn_base << PAGE_SHIFT;
		ret = iommu_map(iommu_get_domain_for_dev(dev), iova, phys,
				size, IOMMU_READ | IOMMU_WRITE | IOMMU_CACHE, GFP_KERNEL);
		if (ret) {
			dev_err(dev, "iommu_map failed\n");
			goto unwind;
		}
		dev_dbg(dev, "iommu map succeed, iova 0x%llx, phys 0x%llx, size 0x%llx\n",
			(u64)iova, (u64)phys, (u64)size);
	}
	nbl_vfio_batch_fini(&batch);

	dma->iova = map.iova;
	dma->size = map.size;
	dma->vaddr = map.vaddr;
	nbl_userdev_link_dma(user->group, dma);

	dev_info(dev, "dma map info: vaddr=0x%llx, iova=0x%llx, size=0x%llx\n",
		 (u64)map.vaddr, (u64)map.iova, (u64)map.size);
	mutex_unlock(&user->group->dma_tree_lock);

	return ret;

unwind:
	if (iova > map.iova)
		iommu_unmap(iommu_get_domain_for_dev(dev), map.iova, iova - map.iova);

	if (batch.size)
		vfio_unpin_pages(NBL_USERDEV_TO_VFIO_DEV(user), vaddr, batch.size);

	npage = (vaddr - map.vaddr) >> PAGE_SHIFT;
	vaddr = map.vaddr;

	while (npage) {
		if (npage >= NBL_VFIO_BATCH_MAX_CAPACITY)
			batch_pages = NBL_VFIO_BATCH_MAX_CAPACITY;
		else
			batch_pages = npage;

		batch.pages_in[0] = vaddr >> PAGE_SHIFT;
		for (i = 1; i < batch_pages; i++)
			batch.pages_in[i] =  batch.pages_in[i - 1] + 1;

		vfio_unpin_pages(NBL_USERDEV_TO_VFIO_DEV(user), vaddr, batch_pages);
		npage -= batch_pages;
		vaddr += (batch_pages << PAGE_SHIFT);
	}
	nbl_vfio_batch_fini(&batch);

mutext_unlock:
	mutex_unlock(&user->group->dma_tree_lock);

	return ret;
}

static long nbl_userdev_dma_unmap_ioctl(struct nbl_dev_user *user, unsigned long arg)
{
	struct nbl_adapter *adapter = user->adapter;
	struct pci_dev *pdev = adapter->pdev;
	struct device *dev = &pdev->dev;
	struct nbl_dev_user_dma_unmap unmap;
	struct nbl_userdev_dma *dma;
	unsigned long minsz;
	size_t unmapped = 0;
	struct rb_node *n;
	int ret = 0;

	minsz = offsetofend(struct nbl_dev_user_dma_unmap, size);

	if (copy_from_user(&unmap, (void __user *)arg, minsz))
		return -EFAULT;

	if (unmap.argsz < minsz)
		return -EINVAL;

	dev_info(dev, "dma unmap info: vaddr=0x%llx, iova=0x%llx, size=0x%llx\n",
		 (u64)unmap.vaddr, (u64)unmap.iova, (u64)unmap.size);

	mutex_lock(&user->group->dma_tree_lock);
	user->group->vdev = NBL_USERDEV_TO_VFIO_DEV(user);
	user->group->mdev = &user->mdev;
	dma = nbl_userdev_find_dma(user->group, unmap.vaddr, 1);
	if (dma && dma->vaddr != unmap.vaddr) {
		ret = -EINVAL;
		goto unlock;
	}

	dma = nbl_userdev_find_dma(user->group, unmap.vaddr + unmap.size - 1, 0);
	if (dma && dma->vaddr + dma->size != unmap.vaddr + unmap.size) {
		ret = -EINVAL;
		goto unlock;
	}

	n = nbl_userdev_find_dma_first_node(user->group, unmap.vaddr, unmap.size);
	while (n) {
		size_t dma_size;

		dma = rb_entry(n, struct nbl_userdev_dma, node);
		if (dma->vaddr >= unmap.vaddr + unmap.size)
			break;

		n = rb_next(n);
		dma_size = dma->size;
		nbl_userdev_remove_dma(user->group, dma);
		unmapped += dma_size;
	}
unlock:
	mutex_unlock(&user->group->dma_tree_lock);
	unmap.size = unmapped;

	return ret;
}

static long nbl_vfio_ioctl(struct vfio_device *vdev, unsigned int cmd, unsigned long arg)
{
	struct nbl_dev_user *user;
	long ret;

	user = NBL_VFIO_DEV_TO_USERDEV(vdev);
	switch (cmd) {
	case NBL_DEV_USER_MAP_DMA:
		ret = nbl_userdev_dma_map_ioctl(user, arg);
		break;
	case NBL_DEV_USER_UNMAP_DMA:
		ret = nbl_userdev_dma_unmap_ioctl(user, arg);
		break;
	default:
		ret = nbl_userdev_common_ioctl(user->adapter, cmd, arg);
		break;
	}

	return ret;
}

static int nbl_vfio_mmap(struct vfio_device *vdev, struct vm_area_struct *vma)
{
	struct nbl_dev_user *user;

	user = NBL_VFIO_DEV_TO_USERDEV(vdev);
	return nbl_userdev_common_mmap(user->adapter, vma);
}

static void nbl_vfio_dma_unmap(struct vfio_device *vdev, u64 iova, u64 length)
{
	struct nbl_dev_user *user = NBL_VFIO_DEV_TO_USERDEV(vdev);
	struct nbl_userdev_dma *dma;

	dev_info(user->group->dev, "vdev notifyier iova 0x%llx, size 0x%llx\n",
		 iova, length);

	mutex_lock(&user->group->dma_tree_lock);
	user->group->vdev = vdev;
	dma = nbl_userdev_find_dma(user->group, (dma_addr_t)iova, (size_t)length);
	if (dma)
		nbl_userdev_remove_dma(user->group, dma);
	mutex_unlock(&user->group->dma_tree_lock);
}

static void nbl_userdev_group_get(struct nbl_dev_user_iommu_group *group)
{
	kref_get(&group->kref);
}

static void nbl_userdev_release_group(struct kref *kref)
{
	struct nbl_dev_user_iommu_group *group;
	struct rb_node *node;

	group = container_of(kref, struct nbl_dev_user_iommu_group, kref);
	list_del(&group->group_next);
	mutex_unlock(&nbl_userdev.glock);
	mutex_lock(&group->dma_tree_lock);
	while ((node = rb_first(&group->dma_tree)))
		nbl_userdev_remove_dma(group, rb_entry(node, struct nbl_userdev_dma, node));

	iommu_group_put(group->iommu_group);
	mutex_unlock(&group->dma_tree_lock);
	kfree(group);
}

static void nbl_userdev_group_put(struct nbl_dev_user *user, struct nbl_dev_user_iommu_group *group)
{
	group->vdev = NBL_USERDEV_TO_VFIO_DEV(user);

	group->mdev = &user->mdev;
	kref_put_mutex(&group->kref, nbl_userdev_release_group, &nbl_userdev.glock);
}

static struct nbl_dev_user_iommu_group *
	nbl_userdev_group_get_from_iommu(struct iommu_group *iommu_group)
{
	struct nbl_dev_user_iommu_group *group;

	mutex_lock(&nbl_userdev.glock);
	list_for_each_entry(group, &nbl_userdev.glist, group_next) {
		if (group->iommu_group == iommu_group) {
			nbl_userdev_group_get(group);
			mutex_unlock(&nbl_userdev.glock);
			return group;
		}
	}

	mutex_unlock(&nbl_userdev.glock);

	return NULL;
}

static
struct nbl_dev_user_iommu_group *nbl_userdev_create_group(struct iommu_group *iommu_group,
							  struct device *dev,
							  struct device *mdev,
							  struct vfio_device *vdev)
{
	struct nbl_dev_user_iommu_group *group, *tmp;

	group = kzalloc(sizeof(*group), GFP_KERNEL);
	if (!group)
		return ERR_PTR(-ENOMEM);

	kref_init(&group->kref);
	mutex_init(&group->dma_tree_lock);
	group->iommu_group = iommu_group;
	group->dma_tree = RB_ROOT;
	group->dev = dev;
	group->vdev = vdev;
	group->mdev = mdev;

	mutex_lock(&nbl_userdev.glock);
	list_for_each_entry(tmp, &nbl_userdev.glist, group_next) {
		if (tmp->iommu_group == iommu_group) {
			nbl_userdev_group_get(tmp);
			mutex_unlock(&nbl_userdev.glock);
			kfree(group);
			return tmp;
		}
	}

	list_add(&group->group_next, &nbl_userdev.glist);
	mutex_unlock(&nbl_userdev.glock);

	return group;
}

static int nbl_vfio_open(struct vfio_device *vdev)
{
	struct nbl_dev_user *user;
	struct nbl_dev_user_iommu_group *group;
	struct iommu_group *iommu_group;
	struct nbl_adapter *adapter;
	struct pci_dev *pdev;
	struct device *mdev;
	int ret = 0, opened;

	user = NBL_VFIO_DEV_TO_USERDEV(vdev);
	adapter = user->adapter;
	pdev = adapter->pdev;
	mdev = &user->mdev;

	if (test_bit(NBL_FATAL_ERR, adapter->state))
		return -EIO;

	opened = atomic_cmpxchg(&user->open_cnt, 0, 1);
	if (opened)
		return -EBUSY;

	rtnl_lock();
	if (test_bit(NBL_XDP, adapter->state)) {
		atomic_set(&user->open_cnt, 0);
		rtnl_unlock();
		return -EIO;
	}

	set_bit(NBL_USER, adapter->state);
	rtnl_unlock();

	/* add iommu group list */
	iommu_group = iommu_group_get(&pdev->dev);
	if (!iommu_group) {
		dev_err(&pdev->dev, "nbl vfio open failed\n");
		ret = -EINVAL;
		goto clear_open_cnt;
	}

	group = nbl_userdev_group_get_from_iommu(iommu_group);
	if (!group) {
		group = nbl_userdev_create_group(iommu_group, &pdev->dev, mdev, vdev);
		if (IS_ERR(group)) {
			iommu_group_put(iommu_group);
			ret = PTR_ERR(group);
			goto clear_open_cnt;
		}
	} else {
		iommu_group_put(iommu_group);
	}

	user->group = group;

	dev_info(&pdev->dev, "nbl vfio open\n");

	return ret;

clear_open_cnt:
	atomic_set(&user->open_cnt, 0);
	clear_bit(NBL_USER, adapter->state);

	return ret;
}

static void nbl_vfio_close(struct vfio_device *vdev)
{
	struct nbl_dev_user *user;
	struct nbl_adapter *adapter;
	struct pci_dev *pdev;
	struct nbl_dev_mgt *dev_mgt;

	user = NBL_VFIO_DEV_TO_USERDEV(vdev);
	adapter = user->adapter;
	pdev = adapter->pdev;
	dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);

	if (user->group)
		nbl_userdev_group_put(user, user->group);
	user->group = NULL;

	nbl_uservsi_release(dev_mgt);
	clear_bit(NBL_USER, adapter->state);

	dev_info(&pdev->dev, "nbl vfio close\n");
}

static void nbl_vfio_release(struct vfio_device *vdev)
{
}

static int nbl_vfio_init(struct vfio_device *vdev)
{
	return 0;
}

static struct vfio_device_ops nbl_vfio_dev_ops = {
	.name = "vfio-nbl",
	.open_device = nbl_vfio_open,
	.close_device = nbl_vfio_close,
	.init = nbl_vfio_init,
	.release = nbl_vfio_release,
	.read = nbl_vfio_read,
	.write = nbl_vfio_write,
	.ioctl = nbl_vfio_ioctl,
	.mmap = nbl_vfio_mmap,
	.dma_unmap = nbl_vfio_dma_unmap,
	.bind_iommufd = vfio_iommufd_emulated_bind,
	.unbind_iommufd = vfio_iommufd_emulated_unbind,
	.attach_ioas = vfio_iommufd_emulated_attach_ioas,
	.detach_ioas = vfio_iommufd_emulated_detach_ioas,
};

static int nbl_bus_probe(struct device *dev)
{
	struct nbl_dev_user *user = container_of(dev, struct nbl_dev_user, mdev);
	struct nbl_vfio_device *vdev;
	int ret;

	vdev = vfio_alloc_device(nbl_vfio_device, vdev, dev, &nbl_vfio_dev_ops);
	if (IS_ERR(vdev))
		return PTR_ERR(vdev);
	user->vdev = &vdev->vdev;
	vdev->user = user;

	ret = vfio_register_emulated_iommu_dev(NBL_USERDEV_TO_VFIO_DEV(user));
	if (ret) {
		dev_err(dev, "vfio register iommu failed, ret %d\n", ret);
		vfio_put_device(NBL_USERDEV_TO_VFIO_DEV(user));
	}

	return ret;
}

static void nbl_bus_remove(struct device *dev)
{
	struct nbl_dev_user *user = container_of(dev, struct nbl_dev_user, mdev);

	vfio_unregister_group_dev(NBL_USERDEV_TO_VFIO_DEV(user));
	vfio_put_device(NBL_USERDEV_TO_VFIO_DEV(user));
}

static int nbl_bus_match(struct device *dev, struct device_driver *drv)
{
	return 0;
}

static struct bus_type nbl_bus_type = {
	.name = "nbl_bus_type",
	.probe = nbl_bus_probe,
	.remove = nbl_bus_remove,
	.match = nbl_bus_match,
};

static struct device_driver nbl_userdev_driver = {
	.bus = &nbl_bus_type,
	.name = "nbl_userdev",
	.owner = THIS_MODULE,
	.mod_name = KBUILD_MODNAME,
};

static void nbl_mdev_device_release(struct device *dev)
{
	dev_info(dev, "nbl mdev device release\n");
}
#endif /* !(CONFIG_VFIO&&CONFIG_VFIO_MDEV) */

void nbl_dev_setup_user_dev(struct nbl_adapter *adapter)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_common_info *common = NBL_ADAPTER_TO_COMMON(adapter);
	struct device *dev = NBL_COMMON_TO_DEV(common);
	struct device *cdev = NULL;
	struct pci_dev *pdev = NBL_COMMON_TO_PDEV(common);
	struct nbl_dev_user *user;
#if (IS_ENABLED(CONFIG_VFIO) && IS_ENABLED(CONFIG_VFIO_MDEV))
	struct device *mdev;
	struct device_driver *drv;
#endif
	void *shm_msg_ring;
	struct nbl_dev_vsi *user_vsi, *xdp_vsi;
	u64 dma_limit;
	bool iommu_status = 0, remap_status = 0;
	int minor = 0, ret;

	if (!nbl_userdev.success)
		return;
	if (!dev_is_dma_coherent(dev))
		return;
	/* xdp and user vsi share same queue range */
	user_vsi = nbl_dev_vsi_select(dev_mgt, NBL_VSI_USER);
	xdp_vsi = nbl_dev_vsi_select(dev_mgt, NBL_VSI_XDP);
	if (xdp_vsi) {
		user_vsi->queue_offset = xdp_vsi->queue_offset;
	} else {
		ret = user_vsi->ops->setup(dev_mgt, &adapter->init_param, user_vsi);
		if (ret) {
			dev_err(NBL_DEV_MGT_TO_DEV(dev_mgt), "User-vsi setup failed");
			return;
		}
	}

	iommu_status = nbl_dma_iommu_status(pdev);
	remap_status = nbl_dma_remap_status(pdev, &dma_limit);
	/* 39bits with 3-level paging, 48bits with 4-level paging, 57bits with 5-level paging */
	WARN_ON(fls64(dma_limit) < 39);
	/* iommu passthrough must keep dpdk iova pa mode */
	shm_msg_ring = kzalloc(NBL_USER_DEV_SHMMSGRING_SIZE, GFP_KERNEL);
	if (!shm_msg_ring)
		return;

	user = devm_kzalloc(dev, sizeof(struct nbl_dev_user), GFP_KERNEL);
	if (!user) {
		kfree(shm_msg_ring);
		return;
	}

	if (remap_status) {
#if (IS_ENABLED(CONFIG_VFIO) && IS_ENABLED(CONFIG_VFIO_MDEV))
		/* mdev init */
		mdev = &user->mdev;
		mdev->bus = &nbl_bus_type;
		drv = &nbl_userdev_driver;
		device_initialize(mdev);
		mdev->parent = dev;
		mdev->release = nbl_mdev_device_release;

		ret = dev_set_name(mdev, pci_name(pdev));
		if (ret) {
			dev_err(dev, "mdev set name failed\n");
			goto free_dev;
		}

		ret = device_add(mdev);
		if (ret) {
			dev_err(dev, "mdev add failed\n");
			goto free_dev;
		}
		dev_info(dev, "MDEV: created\n");

		ret = device_driver_attach(drv, mdev);
		if (ret) {
			dev_err(dev, "driver attach failed %d\n", ret);
			device_del(mdev);
			put_device(mdev);
			goto free_dev;
		}
#else /* !(CONFIG_VFIO&&CONFIG_VFIO_MDEV) */

		dev_info(dev, "Cannot support translate mode for NO vfio/mdev/vfio emulator driver\n");
		goto free_dev;
#endif /* !(CONFIG_VFIO&&CONFIG_VFIO_MDEV) */
	} else {
		mutex_lock(&nbl_userdev.clock);
		minor = idr_alloc(&nbl_userdev.cidr, adapter, 1, MINORMASK + 1, GFP_KERNEL);
		if (minor < 0) {
			dev_err(dev, "alloc userdev dev minor failed\n");
			mutex_unlock(&nbl_userdev.clock);
			goto free_dev;
		}

		cdev = device_create(nbl_userdev.cls, NULL, MKDEV(MAJOR(nbl_userdev.cdevt), minor),
				     NULL, pci_name(pdev));
		if (IS_ERR(cdev)) {
			dev_err(dev, "device create failed\n");
			idr_remove(&nbl_userdev.cidr, minor);
			mutex_unlock(&nbl_userdev.clock);
			goto free_dev;
		}
		mutex_unlock(&nbl_userdev.clock);
		user->dev = cdev;
		user->minor = minor;
	}

	user->shm_msg_ring = shm_msg_ring;
	user->adapter = adapter;
	user->iommu_status = iommu_status;
	user->remap_status = remap_status;
	user->dma_limit = dma_limit;
	atomic_set(&user->open_cnt, 0);
	user->network_type = NBL_KERNEL_NETWORK;
	user->user_promisc_mode = 0;
	user->user_mcast_mode = 0;
	user->user_vsi = user_vsi->vsi_id;
	user->dsch_status = false;

	NBL_DEV_MGT_TO_USER_DEV(dev_mgt) = user;

	return;

free_dev:
	devm_kfree(dev, user);
	kfree(shm_msg_ring);
}

void nbl_dev_remove_user_dev(struct nbl_adapter *adapter)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_dev_user *user = NBL_DEV_MGT_TO_USER_DEV(dev_mgt);
	struct nbl_common_info *common = NBL_ADAPTER_TO_COMMON(adapter);
	struct device *dev = NBL_COMMON_TO_DEV(common);
#if (IS_ENABLED(CONFIG_VFIO) && IS_ENABLED(CONFIG_VFIO_MDEV))
	struct device *mdev;
#endif

	if (!user)
		return;

	while (atomic_read(&user->open_cnt)) {
		dev_info(dev, "userdev application need quit!\n");
		msleep(2000);
	}

	kfree(user->shm_msg_ring);

	if (user->remap_status) {
#if (IS_ENABLED(CONFIG_VFIO) && IS_ENABLED(CONFIG_VFIO_MDEV))
		mdev = &user->mdev;

		device_del(mdev);
		put_device(mdev);
		devm_kfree(dev, user);
#endif
	} else if (user->dev) {
		mutex_lock(&nbl_userdev.clock);
		device_destroy(nbl_userdev.cls, MKDEV(MAJOR(nbl_userdev.cdevt), user->minor));
		user->dev = NULL;
		mutex_unlock(&nbl_userdev.clock);
		devm_kfree(dev, user);
	}

	NBL_DEV_MGT_TO_USER_DEV(dev_mgt) = NULL;
}

void nbl_dev_user_module_init(void)
{
	int ret;

	idr_init(&nbl_userdev.cidr);
	mutex_init(&nbl_userdev.clock);
	mutex_init(&nbl_userdev.glock);
	INIT_LIST_HEAD(&nbl_userdev.glist);

#if (IS_ENABLED(CONFIG_VFIO) && IS_ENABLED(CONFIG_VFIO_MDEV))
	ret = bus_register(&nbl_bus_type);
	if (ret) {
		pr_err("nbl bus type register failed\n");
		return;
	}
	ret = driver_register(&nbl_userdev_driver);
	if (ret) {
		pr_err("nbl userdev driver register failed\n");
		bus_unregister(&nbl_bus_type);
		return;
	}
#endif /* !(CONFIG_VFIO&&CONFIG_VFIO_MDEV) */

	nbl_userdev.cls = class_create("nbl_userdev");
	if (IS_ERR(nbl_userdev.cls)) {
		pr_err("nbl_userdev class alloc failed\n");
		goto err_create_cls;
	}

	nbl_userdev.cls->devnode = user_cdevnode;

	ret = alloc_chrdev_region(&nbl_userdev.cdevt, 0, MINORMASK + 1, "nbl_userdev");
	if (ret) {
		pr_err("nbl_userdev alloc chrdev region failed\n");
		goto err_alloc_chrdev;
	}

	cdev_init(&nbl_userdev.cdev, &nbl_cdev_fops);
	ret = cdev_add(&nbl_userdev.cdev, nbl_userdev.cdevt, MINORMASK + 1);
	if (ret) {
		pr_err("nbl_userdev cdev add failed\n");
		goto err_cdev_add;
	}

	nbl_userdev.success = 1;
	pr_info("user_module init success\n");

	return;

err_cdev_add:
	unregister_chrdev_region(nbl_userdev.cdevt, MINORMASK + 1);
err_alloc_chrdev:
	class_destroy(nbl_userdev.cls);
	nbl_userdev.cls = NULL;
err_create_cls:
#if (IS_ENABLED(CONFIG_VFIO) && IS_ENABLED(CONFIG_VFIO_MDEV))
	driver_unregister(&nbl_userdev_driver);
	bus_unregister(&nbl_bus_type);
#endif
}

void nbl_dev_user_module_destroy(void)
{
	if (nbl_userdev.success) {
		idr_destroy(&nbl_userdev.cidr);
		cdev_del(&nbl_userdev.cdev);
		unregister_chrdev_region(nbl_userdev.cdevt, MINORMASK + 1);
		class_destroy(nbl_userdev.cls);
		nbl_userdev.cls = NULL;
#if (IS_ENABLED(CONFIG_VFIO) && IS_ENABLED(CONFIG_VFIO_MDEV))
		driver_unregister(&nbl_userdev_driver);
		bus_unregister(&nbl_bus_type);
#endif
		nbl_userdev.success = 0;
	}
}

