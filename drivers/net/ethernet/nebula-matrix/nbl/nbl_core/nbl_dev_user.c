// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */
#include "nbl_dev.h"
#include "nbl_service.h"

extern int device_driver_attach(struct device_driver *drv, struct device *dev);

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
	unsigned int ref_cnt;
};

bool nbl_dma_iommu_status(struct pci_dev *pdev)
{
	struct device *dev = &pdev->dev;

	if (dev->iommu_group && iommu_get_domain_for_dev(dev))
		return 1;

	return 0;
}

bool nbl_dma_remap_status(struct pci_dev *pdev)
{
	struct device *dev = &pdev->dev;
	struct iommu_domain *domain;

	domain = iommu_get_domain_for_dev(dev);
	if (!domain)
		return 0;

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
	struct nbl_dev_net *net_dev = NBL_DEV_MGT_TO_NET_DEV(dev_mgt);
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	struct nbl_event_dev_mode_switch_data data = {0};
	struct net_device *netdev = net_dev->netdev;

	if (user->network_type == NBL_KERNEL_NETWORK)
		return;

	rtnl_lock();
	clear_bit(NBL_USER, adapter->state);

	data.op = NBL_DEV_USER_TO_KERNEL;
	nbl_event_notify(NBL_EVENT_DEV_MODE_SWITCH, &data, NBL_COMMON_TO_ETH_ID(common),
			 NBL_COMMON_TO_BOARD_ID(common));
	if (data.ret)
		goto unlock;

	user->network_type = NBL_KERNEL_NETWORK;
	netdev_info(netdev, "network changes to kernel space\n");

unlock:
	rtnl_unlock();
}

static int nbl_user_change_user_network(struct nbl_dev_user *user)
{
	struct nbl_adapter *adapter = user->adapter;
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_dev_net *net_dev = NBL_DEV_MGT_TO_NET_DEV(dev_mgt);
	struct nbl_common_info *common = NBL_DEV_MGT_TO_COMMON(dev_mgt);
	struct net_device *netdev = net_dev->netdev;
	struct nbl_event_dev_mode_switch_data data = {0};
	int ret = 0;

	rtnl_lock();

	data.op = NBL_DEV_KERNEL_TO_USER;
	nbl_event_notify(NBL_EVENT_DEV_MODE_SWITCH, &data, NBL_COMMON_TO_ETH_ID(common),
			 NBL_COMMON_TO_BOARD_ID(common));
	if (data.ret)
		goto unlock;

	set_bit(NBL_USER, adapter->state);
	user->network_type = NBL_USER_NETWORK;
	netdev_info(netdev, "network changes to user\n");

unlock:
	rtnl_unlock();

	return ret;
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

	dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(p);
	user = NBL_DEV_MGT_TO_USER_DEV(dev_mgt);
	opened = atomic_cmpxchg(&user->open_cnt, 0, 1);
	if (opened)
		return -EBUSY;

	filep->private_data = p;

	return 0;
}

static int nbl_cdev_release(struct inode *inode, struct file *filp)
{
	struct nbl_adapter *adapter = filp->private_data;
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_channel_ops *chan_ops = NBL_DEV_MGT_TO_CHAN_OPS(dev_mgt);
	struct nbl_dev_user *user = NBL_DEV_MGT_TO_USER_DEV(dev_mgt);

	chan_ops->clear_listener_info(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt));
	nbl_user_change_kernel_network(user);
	atomic_set(&user->open_cnt, 0);

	return 0;
}

static void nbl_userdev_mmap_open(struct vm_area_struct *vma)
{
	zap_vma_ptes(vma, vma->vm_start, vma->vm_end - vma->vm_start);
}

static void nbl_userdev_mmap_close(struct vm_area_struct *vma)
{
}

static vm_fault_t nbl_userdev_mmap_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	vm_fault_t ret = VM_FAULT_NOPAGE;

	if (io_remap_pfn_range(vma, vma->vm_start, vma->vm_pgoff,
			       vma->vm_end - vma->vm_start, vma->vm_page_prot))
		ret = VM_FAULT_SIGBUS;

	return ret;
}

static const struct vm_operations_struct nbl_userdev_mmap_ops = {
	.open = nbl_userdev_mmap_open,
	.close = nbl_userdev_mmap_close,
	.fault = nbl_userdev_mmap_fault,
};

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

	req_len = vma->vm_end - vma->vm_start;
	req_start = pgoff << PAGE_SHIFT;

	if (index == NBL_DEV_SHM_MSG_RING_INDEX)
		phys_len = NBL_USER_DEV_SHMMSGRING_SIZE;
	else
		phys_len = PAGE_ALIGN(pci_resource_len(pdev, 0));

	if (req_start + req_len > phys_len)
		return -EINVAL;

	if (index == NBL_DEV_SHM_MSG_RING_INDEX) {
		struct page *page = virt_to_page((void *)((unsigned long)user->shm_msg_ring +
				(pgoff << PAGE_SHIFT)));
		vma->vm_pgoff = pgoff;
		ret = remap_pfn_range(vma, vma->vm_start, page_to_pfn(page),
				      req_len, vma->vm_page_prot);
		return ret;
	}

	vma->vm_private_data = adapter;
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	vma->vm_pgoff = (pci_resource_start(pdev, 0) >> PAGE_SHIFT) + pgoff;

	vm_flags_set(vma, VM_IO | VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP);
	vma->vm_ops = &nbl_userdev_mmap_ops;

	return 0;
}

static int nbl_cdev_mmap(struct file *filep, struct vm_area_struct *vma)
{
	struct nbl_adapter *adapter = filep->private_data;

	return nbl_userdev_common_mmap(adapter, vma);
}

static int nbl_userdev_register_net(struct nbl_adapter *adapter, void *resp)
{
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_dev_net *net_dev = NBL_DEV_MGT_TO_NET_DEV(dev_mgt);
	struct nbl_register_net_result *result = (struct nbl_register_net_result *)resp;
	struct nbl_dev_vsi *vsi;

	vsi = net_dev->vsi_ctrl.vsi_list[NBL_VSI_USER];

	result->tx_queue_num = vsi->queue_num;
	result->rx_queue_num = vsi->queue_num;
	result->rdma_enable = 0;
	result->queue_offset = vsi->queue_offset;

	return 0;
}

static int nbl_userdev_alloc_txrx_queues(struct nbl_adapter *adapter, void *resp)
{
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_dev_net *net_dev = NBL_DEV_MGT_TO_NET_DEV(dev_mgt);
	struct nbl_chan_param_alloc_txrx_queues *result;
	struct nbl_dev_vsi *vsi;

	vsi = net_dev->vsi_ctrl.vsi_list[NBL_VSI_USER];
	result = (struct nbl_chan_param_alloc_txrx_queues *)resp;
	result->queue_num = vsi->queue_num;

	return 0;
}

static int nbl_userdev_get_vsi_id(struct nbl_adapter *adapter, void *resp)
{
	struct nbl_dev_mgt *dev_mgt = NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_dev_net *net_dev = NBL_DEV_MGT_TO_NET_DEV(dev_mgt);
	struct nbl_chan_param_get_vsi_id *result;
	struct nbl_dev_vsi *vsi;

	vsi = net_dev->vsi_ctrl.vsi_list[NBL_VSI_USER];
	result = (struct nbl_chan_param_get_vsi_id *)resp;
	result->vsi_id = vsi->vsi_id;

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

static long nbl_userdev_channel_ioctl(struct nbl_adapter *adapter, unsigned long arg)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);
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
	resp = (void *)ALIGN((u64)resp, 4);
	NBL_CHAN_SEND(chan_send, msg->dst_id, msg->msg_type, msg->data, msg->arg_len,
		      resp, msg->ack_length, msg->ack);

	dev_dbg(&adapter->pdev->dev, "msg_type %u, arg_len %u, request %llx, resp %llx\n",
		msg->msg_type, msg->arg_len, (u64)msg->data, (u64)resp);

	switch (msg->msg_type) {
	case NBL_CHAN_MSG_REGISTER_NET:
		ret = nbl_userdev_register_net(adapter, resp);
		break;
	case NBL_CHAN_MSG_ALLOC_TXRX_QUEUES:
		ret = nbl_userdev_alloc_txrx_queues(adapter, resp);
		break;
	case NBL_CHAN_MSG_GET_VSI_ID:
		ret = nbl_userdev_get_vsi_id(adapter, resp);
		break;
	case NBL_CHAN_MSG_ADD_MACVLAN:
		WARN_ON(1);
		break;
	case NBL_CHAN_MSG_DEL_MACVLAN:
	case NBL_CHAN_MSG_UNREGISTER_NET:
	case NBL_CHAN_MSG_ADD_MULTI_RULE:
	case NBL_CHAN_MSG_DEL_MULTI_RULE:
	case NBL_CHAN_MSG_FREE_TXRX_QUEUES:
	case NBL_CHAN_MSG_CLEAR_FLOW:
		break;
	case NBL_CHAN_MSG_CLEAR_QUEUE:
		nbl_userdev_translate_clear_queues(&chan_send);
		ret = chan_ops->send_msg(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt), &chan_send);
		break;
	case NBL_CHAN_MSG_REGISTER_VSI2Q:
		nbl_userdev_translate_register_vsi2q(&chan_send);
		ret = chan_ops->send_msg(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt), &chan_send);
		break;
	default:
		ret = chan_ops->send_msg(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt), &chan_send);
		break;
	}

	msg->ack_err = ret;
	ret = copy_to_user((void __user *)arg, msg, sizeof(*msg));

	vfree(msg);

	return ret;
}

static long nbl_userdev_switch_network(struct nbl_adapter *adapter, unsigned long arg)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_dev_user *user = NBL_DEV_MGT_TO_USER_DEV(dev_mgt);
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
	if (type == NBL_USER_NETWORK)
		nbl_user_change_user_network(user);
	else
		nbl_user_change_kernel_network(user);

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

static long nbl_userdev_common_ioctl(struct nbl_adapter *adapter, unsigned int cmd,
				     unsigned long arg)
{
	int ret = 0;

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

static void nbl_userdev_remove_dma(struct nbl_dev_user_iommu_group *group,
				   struct nbl_userdev_dma *dma)
{
	struct nbl_vfio_batch batch;
	long npage, batch_pages;
	unsigned long vaddr;
	int ret, caps;
	unsigned long *ppfn, pfn;
	int i = 0;

	dev_dbg(group->dev, "dma remove: vaddr 0x%lx, iova 0x%llx, size 0x%lx\n",
		dma->vaddr, dma->iova, dma->size);
	iommu_unmap(iommu_get_domain_for_dev(group->dev), dma->iova, dma->size);

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
	struct page *h_page;
	unsigned long minsz, pfn_base = 0, pfn;
	unsigned long vaddr, vfn;
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
	/* rb-tree find */
	dma = nbl_userdev_find_dma(user->group, vaddr, map.size);
	if (dma && dma->iova == iova && dma->size == map.size) {
		vfn = vaddr >> PAGE_SHIFT;
		ret = vfio_pin_pages(&user->vdev, vaddr, 1, IOMMU_READ | IOMMU_WRITE, &h_page);
		if (ret <= 0) {
			dev_err(dev, "vfio_pin_pages failed %d\n", ret);
			goto mutext_unlock;
		}

		pfn = page_to_pfn(h_page);
		ret = 0;
		vfio_unpin_pages(&user->vdev, vaddr, 1);

		if (pfn != dma->pfn) {
			dev_err(dev, "multiple dma pfn not equal, new pfn %lu, dma pfn %lu\n",
				pfn, dma->pfn);
			ret = -EINVAL;
			goto mutext_unlock;
		}

		dev_info(dev, "existing dma info, ref_cnt++\n");
		dma->ref_cnt++;
		goto mutext_unlock;
	} else if (dma) {
		dev_info(dev, "multiple dma not equal\n");
		ret = -EINVAL;
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

			ret = vfio_pin_pages(&user->vdev, vaddr, batch_pages,
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
			dev_dbg(dev, "iommu map succeed, iova 0x%llx, phys 0x%llx,\n"
				"size 0x%llx\n", (u64)iova, (u64)phys, (u64)size);
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
		dev_dbg(dev, "iommu map succeed, iova 0x%llx, phys 0x%llx,\n"
			"size 0x%llx\n", (u64)iova, (u64)phys, (u64)size);
	}
	nbl_vfio_batch_fini(&batch);

	dma->iova = map.iova;
	dma->size = map.size;
	dma->vaddr = map.vaddr;
	dma->ref_cnt = 1;
	nbl_userdev_link_dma(user->group, dma);

	dev_info(dev, "dma map info: vaddr=0x%llx, iova=0x%llx, size=0x%llx\n",
		 (u64)map.vaddr, (u64)map.iova, (u64)map.size);
	mutex_unlock(&user->group->dma_tree_lock);

	return ret;

unwind:
	if (iova > map.iova)
		iommu_unmap(iommu_get_domain_for_dev(dev), map.iova, iova - map.iova);

	if (batch.size)
		vfio_unpin_pages(&user->vdev, vaddr, batch.size);

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

		vfio_unpin_pages(&user->vdev, vaddr, batch_pages);
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

	minsz = offsetofend(struct nbl_dev_user_dma_unmap, size);

	if (copy_from_user(&unmap, (void __user *)arg, minsz))
		return -EFAULT;

	if (unmap.argsz < minsz)
		return -EINVAL;

	dev_info(dev, "dma unmap info: vaddr=0x%llx, iova=0x%llx, size=0x%llx\n",
		 (u64)unmap.vaddr, (u64)unmap.iova, (u64)unmap.size);

	mutex_lock(&user->group->dma_tree_lock);
	dma = nbl_userdev_find_dma(user->group, unmap.vaddr, unmap.size);
	/* unmmap pages: rb-tree lock */
	if (dma) {
		if (dma->vaddr != unmap.vaddr || dma->iova != unmap.iova || dma->size != unmap.size)
			dev_err(dev, "dma unmap not equal, unmap vaddr 0x%llx, iova 0x%llx,\n"
				"size 0x%llx, dma rbtree vaddr 0x%lx, iova 0x%llx, size 0x%lx\n",
				unmap.vaddr, unmap.iova, unmap.size,
				dma->vaddr, dma->iova, dma->size);
		dma->ref_cnt--;
		if (!dma->ref_cnt)
			nbl_userdev_remove_dma(user->group, dma);
	}
	mutex_unlock(&user->group->dma_tree_lock);

	return 0;
}

static long nbl_vfio_ioctl(struct vfio_device *vdev, unsigned int cmd, unsigned long arg)
{
	struct nbl_dev_user *user;
	long ret;

	user = container_of(vdev, struct nbl_dev_user, vdev);
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

	user = container_of(vdev, struct nbl_dev_user, vdev);
	return nbl_userdev_common_mmap(user->adapter, vma);
}

static void nbl_vfio_dma_unmap(struct vfio_device *vdev, u64 iova, u64 length)
{
	struct nbl_dev_user *user = container_of(vdev, struct nbl_dev_user, vdev);
	struct nbl_userdev_dma *dma;

	dev_info(user->group->dev, "vdev notifyier iova 0x%llx, size 0x%llx\n",
		 iova, length);

	mutex_lock(&user->group->dma_tree_lock);
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
	while ((node = rb_first(&group->dma_tree)))
		nbl_userdev_remove_dma(group, rb_entry(node, struct nbl_userdev_dma, node));

	iommu_group_put(group->iommu_group);
	kfree(group);
}

static void nbl_userdev_group_put(struct nbl_dev_user_iommu_group *group)
{
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
	int ret = 0, opened;

	user = container_of(vdev, struct nbl_dev_user, vdev);
	adapter = user->adapter;
	pdev = adapter->pdev;

	opened = atomic_cmpxchg(&user->open_cnt, 0, 1);
	if (opened)
		return -EBUSY;

	/* add iommu group list */
	iommu_group = iommu_group_get(&pdev->dev);
	if (!iommu_group) {
		dev_err(&pdev->dev, "nbl vfio open failed\n");
		ret = -EINVAL;
		goto clear_open_cnt;
	}

	group = nbl_userdev_group_get_from_iommu(iommu_group);
	if (!group) {
		group = nbl_userdev_create_group(iommu_group, &pdev->dev, vdev);
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
	return ret;
}

static void nbl_vfio_close(struct vfio_device *vdev)
{
	struct nbl_dev_user *user;
	struct nbl_adapter *adapter;
	struct pci_dev *pdev;
	struct nbl_dev_mgt *dev_mgt;
	struct nbl_channel_ops *chan_ops;

	user = container_of(vdev, struct nbl_dev_user, vdev);
	adapter = user->adapter;
	pdev = adapter->pdev;
	dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);
	chan_ops = NBL_DEV_MGT_TO_CHAN_OPS(dev_mgt);

	if (user->group)
		nbl_userdev_group_put(user->group);
	user->group = NULL;

	chan_ops->clear_listener_info(NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt));
	nbl_user_change_kernel_network(user);
	atomic_set(&user->open_cnt, 0);

	dev_info(&pdev->dev, "nbl vfio close\n");
}

static const struct vfio_device_ops nbl_vfio_dev_ops = {
	.name = "vfio-nbl",
	.open_device = nbl_vfio_open,
	.close_device = nbl_vfio_close,
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

static const struct file_operations nbl_cdev_fops = {
	.owner = THIS_MODULE,
	.open = nbl_cdev_open,
	.unlocked_ioctl = nbl_cdev_unlock_ioctl,
	.compat_ioctl = compat_ptr_ioctl,
	.release = nbl_cdev_release,
	.mmap = nbl_cdev_mmap,
};

static struct mdev_driver nbl_mdev_driver = {
	.device_api = VFIO_DEVICE_API_PCI_STRING,
	.driver = {
		.name = "nbl_mdev",
		.owner = THIS_MODULE,
		.mod_name = KBUILD_MODNAME,
	},
};

static int nbl_bus_probe(struct device *dev)
{
	struct mdev_driver *drv =
		container_of(dev->driver, struct mdev_driver, driver);

	if (!drv->probe)
		return 0;
	return drv->probe(to_mdev_device(dev));
}

static void nbl_bus_remove(struct device *dev)
{
	struct mdev_driver *drv =
		container_of(dev->driver, struct mdev_driver, driver);

	if (drv->remove)
		drv->remove(to_mdev_device(dev));
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

static void nbl_mdev_device_release(struct device *dev)
{
	dev_info(dev, "nbl mdev device release\n");
}

void nbl_dev_start_user_dev(struct nbl_adapter *adapter)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_common_info *common = NBL_ADAPTER_TO_COMMON(adapter);
	struct device *dev = NBL_COMMON_TO_DEV(common);
	struct device *cdev = NULL, *mdev;
	struct pci_dev *pdev = NBL_COMMON_TO_PDEV(common);
	struct nbl_dev_user *user;
	void *shm_msg_ring;
	bool iommu_status = 0, remap_status = 0;
	int minor = 0, ret;

	if (!nbl_userdev.success)
		return;

	if (!dev_is_dma_coherent(dev))
		return;

	if (dma_get_mask(dev) != DMA_BIT_MASK(64))
		return;

	iommu_status = nbl_dma_iommu_status(pdev);
	remap_status = nbl_dma_remap_status(pdev);

	/* iommu passthrough */
	if (iommu_status && !remap_status) {
		if (common->dma_dev == common->dev)
			return;
		remap_status = 1;
	}

	shm_msg_ring = kzalloc(NBL_USER_DEV_SHMMSGRING_SIZE, GFP_KERNEL);
	if (!shm_msg_ring)
		return;

	user = devm_kzalloc(dev, sizeof(struct nbl_dev_user), GFP_KERNEL);
	if (!user) {
		kfree(shm_msg_ring);
		return;
	}

	if (remap_status) {
		/* mdev init */
		mdev = devm_kzalloc(dev, sizeof(struct device), GFP_KERNEL);
		if (!mdev) {
			kfree(shm_msg_ring);
			return;
		}

		device_initialize(mdev);
		mdev->parent = dev;

		mdev->bus = &nbl_bus_type;

		mdev->release = nbl_mdev_device_release;

		ret = dev_set_name(mdev, pci_name(pdev));
		if (ret) {
			dev_info(dev, "mdev set name failed\n");
			goto free_dev;
		}

		ret = device_add(mdev);
		if (ret) {
			dev_err(dev, "mdev add failed\n");
			goto free_dev;
		}
		dev_info(dev, "MDEV: created\n");

		devm_kfree(dev, user);

		user = vfio_alloc_device(nbl_dev_user, vdev, mdev, &nbl_vfio_dev_ops);
		if (IS_ERR(user)) {
			device_del(mdev);
			goto free_dev;
		}

		ret = vfio_register_emulated_iommu_dev(&user->vdev);
		if (ret) {
			vfio_put_device(&user->vdev);
			device_del(mdev);
			goto free_dev;
		}

		user->mdev = mdev;
		mdev->driver = &nbl_mdev_driver.driver;
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
	atomic_set(&user->open_cnt, 0);
	user->network_type = NBL_KERNEL_NETWORK;

	NBL_DEV_MGT_TO_USER_DEV(dev_mgt) = user;

	return;

free_dev:
	devm_kfree(dev, mdev);
	kfree(shm_msg_ring);
}

void nbl_dev_stop_user_dev(struct nbl_adapter *adapter)
{
	struct nbl_dev_mgt *dev_mgt = (struct nbl_dev_mgt *)NBL_ADAPTER_TO_DEV_MGT(adapter);
	struct nbl_dev_user *user = NBL_DEV_MGT_TO_USER_DEV(dev_mgt);
	struct nbl_common_info *common = NBL_ADAPTER_TO_COMMON(adapter);
	struct device *dev = NBL_COMMON_TO_DEV(common);
	struct device *mdev;

	if (!user)
		return;

	while (atomic_read(&user->open_cnt)) {
		dev_info(dev, "userdev application need quit!\n");
		msleep(2000);
	}

	kfree(user->shm_msg_ring);

	if (user->remap_status) {
		mdev = user->mdev;
		vfio_unregister_group_dev(&user->vdev);
		vfio_put_device(&user->vdev);
		mdev->driver = NULL;
		device_del(mdev);
		devm_kfree(dev, mdev);
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
	return;
}

void nbl_dev_user_module_destroy(void)
{
	if (nbl_userdev.success) {
		idr_destroy(&nbl_userdev.cidr);
		cdev_del(&nbl_userdev.cdev);
		unregister_chrdev_region(nbl_userdev.cdevt, MINORMASK + 1);
		class_destroy(nbl_userdev.cls);
		nbl_userdev.cls = NULL;
		nbl_userdev.success = 0;
	}
}
