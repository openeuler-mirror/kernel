// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/*
 * Copyright (c) 2021 nebula-matrix Limited.
 * Author: lewis.liu <lewis.liu@nebula-matrix.com>
 */

#include <linux/if_vlan.h>
#include <net/addrconf.h>
#include <rdma/ib_cache.h>
#include <rdma/ib_addr.h>
#include <asm-generic/errno-base.h>
#include <linux/inetdevice.h>

#include "debug.h"
#include "device.h"
#include "ah.h"
#include "grc.h"
#include "qp.h"
#include "gid.h"
#include "dbgfs.h"

void nbl_init_src_addr(struct nbl_pci_f *rf)
{
	spin_lock_init(&rf->src_addr_rsrc.addr_tbl_lock);

	spin_lock_init(&rf->addr_tbl_lock);
	INIT_LIST_HEAD(&rf->src_addr_list);
}

void nbl_deinit_src_addr(struct nbl_pci_f *rf)
{
	struct nbl_src_addr_node *node, *tmp;
	unsigned long flags;
	unsigned long flags2;

	spin_lock_irqsave(&rf->addr_tbl_lock, flags);
	list_for_each_entry_safe(node, tmp, &rf->src_addr_list, list) {
		list_del(&node->list);
		kfree(node);
	}
	spin_unlock_irqrestore(&rf->addr_tbl_lock, flags);

	/* deinit global src addr rsrc */
	spin_lock_irqsave(&rf->src_addr_rsrc.addr_tbl_lock, flags2);
	memset(rf->src_addr_rsrc.addr_tbl, 0,
	       sizeof(rf->src_addr_rsrc.addr_tbl));
	spin_unlock_irqrestore(&rf->src_addr_rsrc.addr_tbl_lock, flags2);
}

static void nbl_del_src_addr_node(struct nbl_pci_f *rf, u16 src_addr_index)
{
	unsigned long flags;
	struct nbl_src_addr_node *node, *tmp;

	spin_lock_irqsave(&rf->addr_tbl_lock, flags);
	list_for_each_entry_safe(node, tmp, &rf->src_addr_list, list) {
		if (node->info.src_addr_index == src_addr_index) {
			list_del(&node->list);
			kfree(node);
		}
	}
	spin_unlock_irqrestore(&rf->addr_tbl_lock, flags);
}

static int nbl_update_src_addr_node(struct nbl_pci_f *rf, u16 src_addr_index,
				    u16 sgid_index, const u8 *sgid)
{
	unsigned long flags;
	struct nbl_src_addr_node *node, *tmp;

	spin_lock_irqsave(&rf->addr_tbl_lock, flags);
	list_for_each_entry_safe(node, tmp, &rf->src_addr_list, list) {
		if (node->info.src_addr_index == src_addr_index) {
			nbl_dev_dbg(
				&rf->pcidev->dev,
				"found exist node of src_addr_index:%d, update it.\n",
				src_addr_index);

			node->info.sgid_index = sgid_index;
			memcpy(node->info.sgid, sgid, NBL_SRC_IP_SIZE);
			spin_unlock_irqrestore(&rf->addr_tbl_lock, flags);
			return 0;
		}
	}
	spin_unlock_irqrestore(&rf->addr_tbl_lock, flags);
	return -ENOKEY;
}

static int nbl_add_src_addr_node(struct nbl_pci_f *rf, u16 src_addr_index,
	const struct ib_gid_attr *attr)
{
	unsigned long flags;
	struct nbl_src_addr_node *node;
	u16 sgid_index = attr->index;
	const u8 *sgid = attr->gid.raw;

	if (!nbl_update_src_addr_node(rf, src_addr_index, sgid_index, sgid))
		return 0;

	node = kzalloc(sizeof(*node), GFP_ATOMIC);
	if (!node)
		return -ENOMEM;

	node->info.src_addr_index = src_addr_index;
	node->info.sgid_index = sgid_index;
	node->info.netdev = attr->ndev;
	memcpy(node->info.sgid, sgid, NBL_SRC_IP_SIZE);

	spin_lock_irqsave(&rf->addr_tbl_lock, flags);
	list_add(&node->list, &rf->src_addr_list);
	spin_unlock_irqrestore(&rf->addr_tbl_lock, flags);

	return 0;
}

static int nbl_alloc_src_addr_index_direct(struct nbl_device *dev,
					   u16 *src_addr_index)
{
	int ret_val;
	struct nbl_pci_f *rf = dev->rf;

	ret_val = rf->hw.hw_ops->get_hw_inst_id(&rf->hw, NBL_INST_SMAC_IP_INDEX, src_addr_index);
	if (ret_val)
		nbl_dev_err(&rf->pcidev->dev, "get smac_sip_index err=%d\n", ret_val);

	return ret_val;
}

/**
 * nbl_alloc_src_addr_index - alloc src addr index for gid
 * @dev:nbl device
 * @src_addr_index:pointer contains returned src addr index
 *
 * Return 0, if the operation performed successfully
 * otherwise return error
 */
static int nbl_alloc_src_addr_index_bygrc(struct nbl_device *dev,
					  u16 *src_addr_index)
{
	int ret_val;
	u8 in[NBL_GRC_INPUT_SIZE] = {0};
	u8 out[NBL_GRC_OUTPUT_SIZE] = {0};
	u8 data_len = 0;
	struct grc_cache_msg_header *head;

	head = (struct grc_cache_msg_header *)in;

	head->op_code = GRC_MSG_OP_ADD_SRC_ADDR_INFO;
	head->payload_len = 0;
	data_len += sizeof(struct grc_cache_msg_header);

	ret_val = nbl_exec_cmd(dev->rf, in, data_len, out, sizeof(out));
	if (ret_val) {
		nbl_pr_err("get src addr index cmd err=%d", ret_val);
		return ret_val;
	}

	memcpy(src_addr_index, out + 1, sizeof(*src_addr_index));
	nbl_pr_dbg("get src_addr_index=%u", *src_addr_index);
	return 0;
}

static int nbl_alloc_src_addr_index(struct nbl_device *dev,
				    u16 *src_addr_index)
{
	return dev->rf->product->gid_ops->alloc_index(dev, src_addr_index);
}

static bool check_gid_in_src_addr_table_direct(const struct nbl_device *dev,
	const union ib_gid *ib_gid)
{
	struct nbl_src_addr_tbl *addr_tbl = dev->rf->src_addr_rsrc.addr_tbl;
	u16 function_id = dev->rf->sc_dev.function_id;
	u16 max_src_addr_size = MAX_SRC_ADDR_SIZE_V2;
	unsigned long flags;
	int i;

	spin_lock_irqsave(&dev->rf->src_addr_rsrc.addr_tbl_lock, flags);
	for (i = 0; i < max_src_addr_size; i++) {
		if (addr_tbl[i].function_id == function_id &&
			!memcmp(addr_tbl[i].sgid, ib_gid->raw, NBL_SRC_IP_SIZE)) {
			break;
		}
	}
	spin_unlock_irqrestore(&dev->rf->src_addr_rsrc.addr_tbl_lock, flags);

	if (i < max_src_addr_size)
		return true;

	return false;
}

bool nbl_gid_in_src_addr_table(const struct nbl_device *dev,
	const union ib_gid *ib_gid)
{
	return check_gid_in_src_addr_table_direct(dev, ib_gid);
}

/**
 * nbl_get_src_addr_info_direct - get the src addr info include src_addr_info adn src_ip
 * @dev:nbl device
 * @gid_idx:source gid index
 * @src_addr_index:pointer contains returned src addr index
 * @src_ip:pointer contains returned src ip
 * @seq_num:pointer contains returned sequence num of src_addr_index
 *
 * Return 0, if the operation performed successfully
 * otherwise return error
 */
static int nbl_get_src_addr_info_direct(struct nbl_pci_f *rf, u16 function_id,
					u16 gid_idx, u16 *src_addr_index,
					u8 *src_ip, u8 *seq_num)
{
	struct nbl_src_addr_tbl *addr_tbl = rf->src_addr_rsrc.addr_tbl;
	u16 sgid_index = gid_idx;
	u16 max_src_addr_size = MAX_SRC_ADDR_SIZE_V2;
	unsigned long flags;
	int i;

	spin_lock_irqsave(&rf->src_addr_rsrc.addr_tbl_lock, flags);
	for (i = 0; i < max_src_addr_size; i++) {
		if (addr_tbl[i].function_id == function_id &&
		    addr_tbl[i].sgid_index == sgid_index) {
			break;
		}
	}
	spin_unlock_irqrestore(&rf->src_addr_rsrc.addr_tbl_lock, flags);

	if (i == max_src_addr_size) {
		nbl_dev_err(&rf->pcidev->dev,
			"can not find valid src_addr_index, the function_id=%u, the sgid_idx=%u\n",
			function_id, sgid_index);
		return -EINVAL;
	}

	*src_addr_index = i;
	if (src_ip)
		memcpy(src_ip, addr_tbl[i].sgid, NBL_SRC_IP_SIZE);

	if (seq_num)
		*seq_num = addr_tbl[i].seq_num;

	return 0;
}

static int nbl_get_src_addr_info_direct_ops(const struct nbl_device *dev,
					    u16 gid_idx,
					    u16 *src_addr_index,
					    u8 *src_ip, u8 *seq_num)
{
	struct nbl_pci_f *rf = dev->rf;

	return nbl_get_src_addr_info_direct(rf, rf->sc_dev.function_id, gid_idx,
					    src_addr_index, src_ip, seq_num);
}

static int nbl_get_src_addr_info_from_buf(struct nbl_pci_f *rf,
	u16 gid_idx, u16 *src_addr_index, u8 *src_ip)
{
	unsigned long flags;
	struct nbl_src_addr_node *node;

	spin_lock_irqsave(&rf->addr_tbl_lock, flags);
	list_for_each_entry(node, &rf->src_addr_list, list) {
		if (node->info.sgid_index == gid_idx) {
			*src_addr_index = node->info.src_addr_index;
			if (src_ip)
				memcpy(src_ip, node->info.sgid,
				       NBL_SRC_IP_SIZE);
			nbl_dev_dbg(
				&rf->pcidev->dev,
				"found exist node of gid_idx:%u src_addr_index:%u %pI6\n",
				gid_idx, *src_addr_index, node->info.sgid);
			spin_unlock_irqrestore(&rf->addr_tbl_lock, flags);
			return 0;
		}
	}
	spin_unlock_irqrestore(&rf->addr_tbl_lock, flags);

	nbl_dev_err(&rf->pcidev->dev,
		    "can not find valid src_addr_index, the gid_idx=%u\n",
		    gid_idx);
	return -EINVAL;
}

static int nbl_get_src_addr_info_bygrc(const struct nbl_device *dev,
				       u16 gid_idx, u16 *src_addr_index,
				       u8 *src_ip, u8 *seq_num)
{
	struct nbl_pci_f *rf = dev->rf;
	int data_len = 0;
	int ret_val = 0;
	u8 in[NBL_GRC_INPUT_SIZE];
	u8 out[NBL_GRC_OUTPUT_SIZE];
	struct grc_cache_msg_header *head;
	struct nbl_get_src_addr_info_req req = {0};
	struct nbl_get_src_addr_info_resp resp = {0};

	/* As create ah will query src add table, and creat ah is interrupt
	 * context, we must not use mbx. Fortunately in this situation it do
	 * not need seq_num. So we use local buf when seq num not needed.
	 */

	/* Draco use mbx only seq num is needed. */
	if (!seq_num)
		return nbl_get_src_addr_info_from_buf(rf, gid_idx,
							src_addr_index, src_ip);

	req.function_id = rf->sc_dev.function_id;
	req.sgid_idx = gid_idx;

	/* fill opcode */
	head = (struct grc_cache_msg_header *)in;
	head->op_code = GRC_MSG_OP_GET_SRC_ADDR_INFO;
	head->payload_len = sizeof(req);
	data_len += sizeof(struct grc_cache_msg_header);

	/* fill info_req */
	memcpy(in + data_len, &req, sizeof(req));
	data_len += sizeof(req);

	ret_val = nbl_exec_cmd(dev->rf, in, data_len, out, sizeof(out));
	if (ret_val) {
		nbl_dev_err(&dev->rf->pcidev->dev, "del src addr info cmd err=%d", ret_val);
		goto err_get_src_addr_info;
	}

	memcpy(&resp, out + 1, sizeof(resp));
	*src_addr_index = resp.src_addr_index;
	if (src_ip)
		memcpy(src_ip, resp.sip, sizeof(resp.sip));

	if (seq_num)
		*seq_num = resp.seq_num;

err_get_src_addr_info:
	return ret_val;
}

int nbl_get_src_addr_info(const struct nbl_device *dev,
			  u16 gid_idx, u16 *src_addr_index,
			  u8 *src_ip, u8 *seq_num)
{
	return dev->rf->product->gid_ops->get_info(dev, gid_idx, src_addr_index,
						   src_ip, seq_num);
}

static int nbl_free_src_addr_index_direct(struct nbl_device *dev,
					  u16 sgid_idx,
					  u16 src_addr_index)
{
	int ret_val;
	struct nbl_pci_f *rf = dev->rf;

	(void)sgid_idx;
	ret_val = rf->hw.hw_ops->put_hw_inst_id(&rf->hw, NBL_INST_SMAC_IP_INDEX, src_addr_index);
	if (ret_val)
		nbl_dev_err(&rf->pcidev->dev, "free smac_sip index err=%d\n", ret_val);

	return ret_val;
}

/**
 * nbl_free_src_addr_index - free src addr index of src addr info tbl
 * @dev:nbl device
 * @sgid_idx sgid index
 * @src_addr_index: src addr index
 *
 * Return 0, if the operation performed successfully
 * otherwise return error
 */
static int nbl_free_src_addr_index_bygrc(struct nbl_device *dev,
					 u16 sgid_idx,
					 u16 src_addr_index)
{
	u8 in[NBL_GRC_INPUT_SIZE];
	u8 out[NBL_GRC_OUTPUT_SIZE];
	int data_len = 0;
	int ret_val;
	struct grc_cache_msg_header *head;
	struct nbl_grc_del_src_addr_info_req info_req = {0};

	info_req.src_addr_index = src_addr_index;
	info_req.function_id = dev->rf->sc_dev.function_id;
	info_req.sgid_idx = sgid_idx;

	/* fill opcode */
	head = (struct grc_cache_msg_header *)in;
	head->op_code = GRC_MSG_OP_DEL_SRC_ADDR_INFO;
	head->payload_len = sizeof(info_req);
	data_len += sizeof(struct grc_cache_msg_header);

	/* fill info_req */
	memcpy(in + data_len, &info_req, sizeof(info_req));
	data_len += sizeof(info_req);

	ret_val = nbl_exec_cmd(dev->rf, in, data_len, out, sizeof(out));
	if (ret_val)
		nbl_dev_err(&dev->rf->pcidev->dev, "del src addr info cmd err=%d", ret_val);

	return ret_val;
}

static int nbl_free_src_addr_index(struct nbl_device *dev, u16 sgid_idx,
				   u16 src_addr_index)
{
	return dev->rf->product->gid_ops->free_index(dev, sgid_idx,
						     src_addr_index);
}

static int nbl_set_roce_addr_direct(struct nbl_device *dev,
				    u16 src_addr_index, u16 sgid_index,
				    const u8 *gid, const u8 *mac,
				    u8 seq_num)
{
	(void)sgid_index;
	dev->rf->hw.hw_ops->set_src_addr_info(&dev->rf->hw, mac, gid, src_addr_index, seq_num);

	return 0;
}

static int nbl_set_roce_addr_bygrc(struct nbl_device *dev,
				   u16 src_addr_index, u16 sgid_index,
				   const u8 *gid, const u8 *mac, u8 seq_num)
{
	u8 in[NBL_GRC_INPUT_SIZE];
	u8 out[NBL_GRC_OUTPUT_SIZE];
	int data_len = 0;
	int ret_val;
	struct grc_cache_msg_header *head;
	struct nbl_grc_send_src_addr_info_req info_req;

	(void)seq_num;

	head = (struct grc_cache_msg_header *)in;
	head->op_code = GRC_MSG_OP_SEND_SRC_ADDR_INFO;
	head->payload_len = sizeof(info_req);
	data_len += sizeof(struct grc_cache_msg_header);

	/* fill info req */
	memcpy(&info_req.sip, gid, sizeof(info_req.sip));
	memcpy(&info_req.smac, mac, sizeof(info_req.smac));
	info_req.function_id = dev->rf->sc_dev.function_id;
	info_req.src_addr_index = src_addr_index;
	info_req.sgid_idx = sgid_index;

	/* fill info req */
	memcpy(in + data_len, &info_req, sizeof(info_req));
	data_len += sizeof(info_req);

	ret_val = nbl_exec_cmd(dev->rf, in, data_len, out, sizeof(out));
	if (ret_val) {
		nbl_dev_err(&dev->rf->pcidev->dev, "send src addr info cmd err=%d.\n", ret_val);
		return ret_val;
	}

	return 0;
}

static int nbl_set_roce_addr(struct nbl_device *dev, u8 port_num,
			     u16 src_addr_index, const union ib_gid *gid,
			     const struct ib_gid_attr *attr, u8 seq_num)
{
	u8 mac[ETH_ALEN] = {0};

	(void)port_num;
	if (!gid) {
		nbl_ib_err(&dev->rf->sc_dev, "gid is null.\n");
		return -EINVAL;
	}

	if (attr->gid_type != IB_GID_TYPE_ROCE_UDP_ENCAP) {
		nbl_ib_err(&dev->rf->sc_dev,
			   "gid type is not ROCE_UDP_ENCAP, the gid type is %u.\n",
			   attr->gid_type);
		return -EINVAL;
	}

	if (attr->ndev)
		ether_addr_copy(mac, attr->ndev->dev_addr);

	return dev->rf->product->gid_ops->set_entry(dev, src_addr_index,
						    attr->index, gid->raw,
						    mac, seq_num);
}

static void nbl_fill_src_addr_tbl_direct(struct nbl_device *dev,
					 u16 src_addr_index,
					 u16 sgid_index, const u8 *gid,
					 u8 *seq_num)
{
	u8 tmp_seq_num;
	unsigned long flags;

	spin_lock_irqsave(&dev->rf->src_addr_rsrc.addr_tbl_lock, flags);
	tmp_seq_num = dev->rf->src_addr_rsrc.addr_tbl[src_addr_index].seq_num + 1;
	if (tmp_seq_num == NBL_SRC_ADDR_INDEX_SEQ_NUM_MAX)
		tmp_seq_num = 0;

	/* fill src addr tbl info */
	dev->rf->src_addr_rsrc.addr_tbl[src_addr_index].function_id =
			dev->rf->sc_dev.function_id;
	dev->rf->src_addr_rsrc.addr_tbl[src_addr_index].sgid_index =
			sgid_index;
	memcpy(dev->rf->src_addr_rsrc.addr_tbl[src_addr_index].sgid,
		gid, NBL_SRC_IP_SIZE);
	dev->rf->src_addr_rsrc.addr_tbl[src_addr_index].seq_num = tmp_seq_num;

	spin_unlock_irqrestore(&dev->rf->src_addr_rsrc.addr_tbl_lock, flags);
	*seq_num = tmp_seq_num;
}

static void nbl_fill_src_addr_tbl_noop(struct nbl_device *dev,
				       u16 src_addr_index,
				       u16 sgid_index, const u8 *gid,
				       u8 *seq_num)
{
	(void)dev;
	(void)src_addr_index;
	(void)sgid_index;
	(void)gid;
	(void)seq_num;
}

static void nbl_fill_src_addr_tbl(struct nbl_device *dev,
				  const struct ib_gid_attr *attr,
				  u16 src_addr_index, u8 *seq_num)
{
	dev->rf->product->gid_ops->fill_table(dev, src_addr_index, attr->index,
						  attr->gid.raw, seq_num);
}

static int nbl_del_src_addr_entry_direct(struct nbl_pci_f *rf, u16 function_id,
			   u16 sgid_index, u16 src_addr_index)
{
	struct  nbl_src_addr_tbl *entry = NULL;
	u8 tmp_seq_num;
	unsigned long flags;

	entry = &rf->src_addr_rsrc.addr_tbl[src_addr_index];
	if (entry->sgid_index != sgid_index || entry->function_id != function_id) {
		nbl_ib_err(&rf->sc_dev, "the sgid_index or function_id is not same as addr_tbl.\n");
		nbl_ib_err(&rf->sc_dev, "the sgid_index is %u, function_id is %u.\n",
			sgid_index, function_id);
		nbl_ib_err(&rf->sc_dev, "the addr_tbl sgid_index is %u, function_id is %u.\n",
			entry->sgid_index, entry->function_id);
		return -EINVAL;
	}

	/* del src addr tbl info */
	spin_lock_irqsave(&rf->src_addr_rsrc.addr_tbl_lock, flags);
	tmp_seq_num = rf->src_addr_rsrc.addr_tbl[src_addr_index].seq_num;
	memset(entry, 0, sizeof(*entry));
	rf->src_addr_rsrc.addr_tbl[src_addr_index].seq_num = tmp_seq_num;
	spin_unlock_irqrestore(&rf->src_addr_rsrc.addr_tbl_lock, flags);

	return 0;
}

static int nbl_del_src_addr_tbl_info(const struct nbl_device *dev,
				      u16 sgid_index, u16 src_addr_index)
{
	return dev->rf->product->gid_ops->clear_table(dev, sgid_index,
						      src_addr_index);
}

static int nbl_clear_src_addr_tbl_direct(const struct nbl_device *dev,
					 u16 sgid_index,
					 u16 src_addr_index)
{
	struct nbl_pci_f *rf = dev->rf;

	return nbl_del_src_addr_entry_direct(rf, rf->sc_dev.function_id,
					     sgid_index, src_addr_index);
}

static int nbl_clear_src_addr_tbl_noop(const struct nbl_device *dev,
				       u16 sgid_index,
				       u16 src_addr_index)
{
	(void)dev;
	(void)sgid_index;
	(void)src_addr_index;
	return 0;
}

static bool nbl_is_ipv4_in_net_device(struct net_device *netdev, const struct ib_gid_attr *attr)
{
	union ib_gid gid = attr->gid;
	union ib_gid tmp_gid;
	struct in_ifaddr *ifa;
	struct in_device *in_dev;
	struct sockaddr_in ip_in;

	if (!netdev)
		return false;

	rcu_read_lock();
	in_dev = __in_dev_get_rcu(netdev);
	if (!in_dev) {
		rcu_read_unlock();
		return false;
	}

	for (ifa = rcu_dereference(in_dev->ifa_list); ifa != NULL;
	     ifa = rcu_dereference(ifa->ifa_next)) {
		ip_in.sin_family = AF_INET;
		ip_in.sin_addr.s_addr = ifa->ifa_address;
		rdma_ip2gid((struct sockaddr *)&ip_in, &tmp_gid);
		if (memcmp(&gid, &tmp_gid, sizeof(union ib_gid)) == 0) {
			nbl_pr_dbg("ipv4, ip is same. ifa_address:%pI4\r\n", &ifa->ifa_address);
			rcu_read_unlock();
			return true;
		}
	}

	nbl_pr_dbg("ipv4, not found ipv4:%pI6,netdev=%s\r\n", gid.raw, netdev->name);
	rcu_read_unlock();

	return false;
}

static bool nbl_is_ipv6_in_net_device(struct net_device *netdev, const struct ib_gid_attr *attr)
{
	union ib_gid gid = attr->gid;
	union ib_gid tmp_gid;
	struct inet6_ifaddr *ifp;
	struct inet6_dev *in6_dev;
	struct sockaddr_in6	sin6;

	if (!netdev)
		return false;

	in6_dev = in6_dev_get(netdev);
	if (!in6_dev)
		return false;

	read_lock_bh(&in6_dev->lock);
	list_for_each_entry(ifp, &in6_dev->addr_list, if_list) {
		sin6.sin6_family = AF_INET6;
		sin6.sin6_addr = ifp->addr;
		rdma_ip2gid((struct sockaddr *)&sin6, &tmp_gid);
		if (memcmp(&gid, &tmp_gid, sizeof(union ib_gid)) == 0) {
			nbl_pr_dbg("ipv6, ip is same. ifp->addr:%pI6\r\n", &ifp->addr);
			read_unlock_bh(&in6_dev->lock);
			in6_dev_put(in6_dev);
			return true;
		}
	}

	nbl_pr_dbg("ipv6, not found ipv6.\r\n");
	read_unlock_bh(&in6_dev->lock);
	in6_dev_put(in6_dev);
	return false;
}

static bool nbl_is_ip_in_net_device(struct net_device *netdev, const struct ib_gid_attr *attr)
{
	if (ipv6_addr_v4mapped((struct in6_addr *)&attr->gid))
		return nbl_is_ipv4_in_net_device(netdev, attr);
	else
		return nbl_is_ipv6_in_net_device(netdev, attr);
}

static void nbl_update_gid_index_direct(struct nbl_pci_f *rf,
					u16 src_addr_index,
					u16 sgid_index)
{
	struct nbl_src_addr_tbl *entry;
	unsigned long flags;

	spin_lock_irqsave(&rf->src_addr_rsrc.addr_tbl_lock, flags);
	entry = &rf->src_addr_rsrc.addr_tbl[src_addr_index];
	entry->sgid_index = sgid_index;
	spin_unlock_irqrestore(&rf->src_addr_rsrc.addr_tbl_lock, flags);
}

static void nbl_update_gid_index_bygrc(struct nbl_pci_f *rf,
				       u16 src_addr_idx, u16 sgid_idx)
{
	u8 in[NBL_GRC_INPUT_SIZE];
	u8 out[NBL_GRC_OUTPUT_SIZE];
	int data_len = 0;
	int ret_val;
	struct grc_cache_msg_header *head;
	struct nbl_grc_update_idx_src_addr_info_req info_req;

	head = (struct grc_cache_msg_header *)in;
	head->op_code = GRC_MSG_OP_UPDATE_IDX_SRC_ADDR;
	head->payload_len = sizeof(info_req);
	data_len += sizeof(struct grc_cache_msg_header);

	/* fill info req */
	info_req.src_addr_index = src_addr_idx;
	info_req.sgid_idx = sgid_idx;

	/* fill info req */
	memcpy(in + data_len, &info_req, sizeof(info_req));
	data_len += sizeof(info_req);

	ret_val = nbl_exec_cmd(rf, in, data_len, out, sizeof(out));
	if (ret_val)
		nbl_dev_err(&rf->pcidev->dev, "err, update src addr cmd err=%d.\n", ret_val);
}

static void nbl_update_gid_index(struct nbl_pci_f *rf, u16 src_addr_idx,
				 u16 sgid_idx)
{
	rf->product->gid_ops->update_index(rf, src_addr_idx, sgid_idx);
}

const struct nbl_gid_ops nbl_direct_gid_ops = {
	.alloc_index = nbl_alloc_src_addr_index_direct,
	.free_index = nbl_free_src_addr_index_direct,
	.get_info = nbl_get_src_addr_info_direct_ops,
	.set_entry = nbl_set_roce_addr_direct,
	.fill_table = nbl_fill_src_addr_tbl_direct,
	.clear_table = nbl_clear_src_addr_tbl_direct,
	.update_index = nbl_update_gid_index_direct,
};

const struct nbl_gid_ops nbl_draco_gid_ops = {
	.alloc_index = nbl_alloc_src_addr_index_bygrc,
	.free_index = nbl_free_src_addr_index_bygrc,
	.get_info = nbl_get_src_addr_info_bygrc,
	.set_entry = nbl_set_roce_addr_bygrc,
	.fill_table = nbl_fill_src_addr_tbl_noop,
	.clear_table = nbl_clear_src_addr_tbl_noop,
	.update_index = nbl_update_gid_index_bygrc,
};

const struct nbl_gid_ops nbl_orion_gid_ops = {
	.alloc_index = nbl_alloc_src_addr_index_bygrc,
	.free_index = nbl_free_src_addr_index_bygrc,
	.get_info = nbl_get_src_addr_info_bygrc,
	.set_entry = nbl_set_roce_addr_bygrc,
	.fill_table = nbl_fill_src_addr_tbl_noop,
	.clear_table = nbl_clear_src_addr_tbl_noop,
	.update_index = nbl_update_gid_index_bygrc,
};

static bool nbl_ib_gid_is_exist_while_add(const struct ib_gid_attr *attr)
{
	struct nbl_device *nbl_dev = to_nbl_dev(attr->device);
	struct nbl_pci_f *rf = nbl_dev->rf;
	struct nbl_core_export *core_info = (struct nbl_core_export *)rf->cdev;
	struct nbl_src_addr_node *node, *tmp;
	unsigned long flags;
	u16 src_addr_idx;
	bool found = false;

	if (!core_info->is_lag)
		return false;

	spin_lock_irqsave(&rf->addr_tbl_lock, flags);
	list_for_each_entry_safe(node, tmp, &rf->src_addr_list, list) {
		if (node->info.netdev == attr->ndev &&
			memcmp(node->info.sgid, attr->gid.raw, NBL_SRC_IP_SIZE) == 0) {
			nbl_dev_dbg(&rf->pcidev->dev,
				"found! ndev:%s, gid:%pI6, index:%u, info.sgid_index:%u\n",
				node->info.netdev->name, attr->gid.raw,
				attr->index, node->info.sgid_index);
			node->info.sgid_index = attr->index;
			src_addr_idx = node->info.src_addr_index;
			found = true;
			break;
		}
	}
	spin_unlock_irqrestore(&rf->addr_tbl_lock, flags);

	if (found)
		nbl_update_gid_index(rf, src_addr_idx, attr->index);

	return found;
}

static bool nbl_ib_gid_is_exist_while_del(const struct ib_gid_attr *attr)
{
	struct nbl_device *nbl_dev = to_nbl_dev(attr->device);
	struct nbl_pci_f *rf = nbl_dev->rf;
	struct nbl_core_export *core_info = (struct nbl_core_export *)rf->cdev;
	unsigned long flags;
	struct nbl_src_addr_node *node, *tmp;

	if (!core_info->is_lag)
		return false;

	spin_lock_irqsave(&rf->addr_tbl_lock, flags);
	list_for_each_entry_safe(node, tmp, &rf->src_addr_list, list) {
		if (node->info.sgid_index == attr->index &&
			memcmp(node->info.sgid, attr->gid.raw, NBL_SRC_IP_SIZE) == 0 &&
			nbl_is_ip_in_net_device(node->info.netdev, attr)) {
			spin_unlock_irqrestore(&rf->addr_tbl_lock, flags);
			nbl_dev_dbg(&rf->pcidev->dev,
				"found! ndev:%s, gid:%pI6, index:%u, info.sgid_index:%u\n",
				node->info.netdev->name, attr->gid.raw,
				attr->index, node->info.sgid_index);
			return true;
		}
	}

	spin_unlock_irqrestore(&rf->addr_tbl_lock, flags);
	return false;
}

int nbl_ib_add_gid(const struct ib_gid_attr *attr, void **context)
{
	struct nbl_device *dev = to_nbl_dev(attr->device);
	u16 src_addr_index;
	u8 seq_num = 0;
	int ret;

	nbl_pr_dbg("Entry add_gid. name:%s\r\n", dev->ibdev.name);
	if (nbl_ib_gid_is_exist_while_add(attr))
		return 0;

	ret = nbl_alloc_src_addr_index(dev, &src_addr_index);
	if (ret) {
		nbl_ib_err(&dev->rf->sc_dev, "set nbl src addr info failed, result[%d].\n", ret);
		return ret;
	}

	/* Draco send src info to grc and calc seq num in grc */
	nbl_fill_src_addr_tbl(dev, attr, src_addr_index, &seq_num);

	ret = nbl_set_roce_addr(dev, attr->port_num, src_addr_index, &attr->gid,
				attr, seq_num);
	if (ret) {
		nbl_ib_err(&dev->rf->sc_dev, "nbl_set_roce_addr failed, result[%d].\n", ret);
		(void)nbl_free_src_addr_index(dev, attr->index, src_addr_index);
		(void)nbl_del_src_addr_tbl_info(dev, attr->index, src_addr_index);
		return ret;
	}

	nbl_add_src_addr_node(dev->rf, src_addr_index, attr);
	nbl_pr_dbg("add src addr index: %u, gid index:%u gid:%pI6\n",
		   src_addr_index, attr->index, attr->gid.raw);

	return 0;
}

int nbl_ib_del_gid(const struct ib_gid_attr *attr, void **context)
{
	struct nbl_device *dev = to_nbl_dev(attr->device);
	u16 src_addr_index;
	u8 src_ip[NBL_SRC_IP_SIZE];
	int ret = 0;

	nbl_pr_dbg("Entry del_gid:%pI6,gid index=%u. name:%s\r\n", attr->gid.raw, attr->index,
		   dev->ibdev.name);
	if (nbl_ib_gid_is_exist_while_del(attr))
		return 0;

	/* release the resource corresponding to the index of global src addr table */
	ret = nbl_get_src_addr_info(dev, attr->index, &src_addr_index, src_ip, NULL);
	if (ret) {
		nbl_ib_err(&dev->rf->sc_dev,
			"get nbl src addr index failed, the function_id: %u, the sgid_index: %u.\n",
			dev->rf->sc_dev.function_id, attr->index);
		return ret;
	}

	/* Draco send to grc free src addr index and clear src table */
	ret = nbl_free_src_addr_index(dev, attr->index, src_addr_index);
	if (ret) {
		nbl_ib_err(&dev->rf->sc_dev,
			"del nbl src addr info failed, the src_addr_index[%u], result[%d].\n",
			src_addr_index, ret);
		return ret;
	}

	ret = nbl_del_src_addr_tbl_info(dev, attr->index, src_addr_index);
	if (ret) {
		nbl_ib_err(&dev->rf->sc_dev,
			"del nbl src addr tbl info failed, the src_addr_index: %u.\n",
			src_addr_index);
		return ret;
	}

	nbl_del_src_addr_node(dev->rf, src_addr_index);

	return 0;
}

int nbl_ib_query_gid(struct ib_device *ibdev, u32 port, int index,
		  union ib_gid *gid)
{
	struct nbl_device *dev = to_nbl_dev(ibdev);
	u16 src_addr_index;
	u8 src_ip[NBL_SRC_IP_SIZE];
	int ret;

	nbl_pr_dbg("Entry query_gid. name:%s\r\n", dev->ibdev.name);
	ret = nbl_get_src_addr_info(dev, index, &src_addr_index, src_ip, NULL);
	if (ret) {
		nbl_ib_err(&dev->rf->sc_dev,
			"get nbl src addr index failed, the function_id: %u, the sgid_index: %u.\n",
			dev->rf->sc_dev.function_id, index);
		return ret;
	}

	memcpy(gid->raw, src_ip, sizeof(src_ip));
	return 0;
}

void nbl_print_grc_src_addr_tbl(struct nbl_pci_f *rf, u32 var)
{
	int ret_val;
	uint8_t in[NBL_GRC_INPUT_SIZE];
	uint8_t out[NBL_GRC_OUTPUT_SIZE];
	u8 data_len = 0;
	struct grc_cache_msg_header *head;
	struct print_grc_src_addr_tbl_req req = {};

	if (NBL_RF_TO_HW_VER(rf) != NBL_VER_2)
		return;

	req.print_cnt = var;
	head = (struct grc_cache_msg_header *)in;
	head->op_code = GRC_MSG_OP_PRINT_SRC_ADDR_TBL;
	head->payload_len = sizeof(req);
	data_len += sizeof(struct grc_cache_msg_header);

	memcpy(in + data_len, &req, sizeof(req));
	data_len += sizeof(req);
	ret_val = nbl_exec_cmd(rf, in, data_len, out, sizeof(out));
	if (ret_val)
		nbl_dev_err(&rf->adev->adev.dev, "print grc src_addr tbl cmd err=%d", ret_val);
}
