// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/*
 * Copyright (c) 2021 nebula-matrix Limited.
 * Author: lewis.liu <lewis.liu@nebula-matrix.com>
 */

#include <rdma/ib_cache.h>
#include <asm-generic/errno-base.h>

#include "debug.h"
#include "device.h"
#include "ah.h"
#include "grc.h"
#include "qp.h"
#include "gid.h"

void nbl_init_src_addr_list(struct nbl_pci_f *rf)
{
	spin_lock_init(&rf->addr_tbl_lock);
	INIT_LIST_HEAD(&rf->src_addr_list);
}

void nbl_del_all_src_addr_node(struct nbl_pci_f *rf)
{
	unsigned long flags;
	struct nbl_src_addr_node *node, *tmp;

	spin_lock_irqsave(&rf->addr_tbl_lock, flags);
	list_for_each_entry_safe(node, tmp, &rf->src_addr_list, list) {
		list_del(&node->list);
		kfree(node);
	}
	spin_unlock_irqrestore(&rf->addr_tbl_lock, flags);
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
				 u16 sgid_index, const u8 *sgid)
{
	unsigned long flags;
	struct nbl_src_addr_node *node;

	if (!nbl_update_src_addr_node(rf, src_addr_index, sgid_index, sgid))
		return 0;

	node = kzalloc(sizeof(*node), GFP_ATOMIC);
	if (!node)
		return -ENOMEM;

	node->info.src_addr_index = src_addr_index;
	node->info.sgid_index = sgid_index;
	memcpy(node->info.sgid, sgid, NBL_SRC_IP_SIZE);

	spin_lock_irqsave(&rf->addr_tbl_lock, flags);
	list_add(&node->list, &rf->src_addr_list);
	spin_unlock_irqrestore(&rf->addr_tbl_lock, flags);

	return 0;
}

/**
 * nbl_add_src_addr_info - add  the src addr info include function_id, sgid_index and src_ip to grc
 * @dev:nbl device
 * @ib_gid_attr:source gid info
 * @src_addr_index:pointer contains returned src addr index
 *
 * Return 0, if the operation performed successfully
 * otherwise return error
 */
static int nbl_add_src_addr_info(struct nbl_device *dev,
	const struct ib_gid_attr *attr, u16 *src_addr_index)
{
	struct nbl_grc_add_src_addr_info_req info_req;
	uint8_t in[64];
	uint8_t out[64];
	int data_len = 0;
	int ret_val;
	uint8_t resp_rst;
	struct grc_cache_msg_header *head;

	memset(&info_req, 0, sizeof(info_req));
	info_req.function_id = dev->rf->sc_dev.function_id;
	info_req.sgid_index = attr->index;
	memcpy(info_req.sgid, attr->gid.raw, NBL_SRC_IP_SIZE);

	/* fill opcode */
	head = (struct grc_cache_msg_header *)in;
	head->op_code = GRC_MSG_OP_ADD_SRC_ADDR_INFO;
	head->payload_len = sizeof(info_req);
	data_len += sizeof(struct grc_cache_msg_header);

	/* fill src add addr info req */
	memcpy(in + data_len, &info_req, sizeof(info_req));
	data_len += sizeof(info_req);

	ret_val = nbl_exec_cmd(dev->rf, in, data_len, out, sizeof(out));
	if (ret_val) {
		nbl_pr_warn("add src addr info cmd ret=%d.\n", ret_val);
		return ret_val;
	}

	/* get operation result */
	memcpy(&resp_rst, out, sizeof(resp_rst));
	if (resp_rst) {
		nbl_pr_err("the returned rst of add src addr info is error.\n");
		return -ENODATA;
	}

	memcpy(src_addr_index, out + 1, sizeof(u16));
	nbl_add_src_addr_node(dev->rf, *src_addr_index, attr->index,
			      attr->gid.raw);
	nbl_pr_dbg("add src addr index: %u, gid index:%u gid:%pI6\n",
		   *src_addr_index, attr->index, attr->gid.raw);

	return 0;
}

/**
 * nbl_get_src_addr_info - get the src addr info include src_addr_info adn src_ip from grc
 * @dev:nbl device
 * @gid_idx:source gid index
 * @src_addr_index:pointer contains returned src addr index
 * @src_ip:pointer contains returned src ip
 *
 * Return 0, if the operation performed successfully
 * otherwise return error
 */
int nbl_get_src_addr_info(const struct nbl_device *dev, u16 gid_idx,
			  u16 *src_addr_index, u8 *src_ip)
{
	struct nbl_pci_f *rf = dev->rf;
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

static int nbl_del_src_addr_info(struct nbl_device *dev,
	u16 gid_idx, u16 src_addr_index)
{
	struct nbl_grc_del_src_addr_info_req info_req;
	uint8_t in[64];
	uint8_t out[64];
	int data_len = 0;
	int ret_val;
	uint8_t resp_rst;
	struct grc_cache_msg_header *head;

	memset(&info_req, 0, sizeof(info_req));
	info_req.src_addr_index = src_addr_index;
	info_req.sgid_index = gid_idx;
	info_req.function_id = dev->rf->sc_dev.function_id;

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
		nbl_pr_err("del src addr info cmd err=%d", ret_val);

	/* get operation result */
	memcpy(&resp_rst, out, sizeof(resp_rst));
	if (resp_rst)
		nbl_pr_err("the returned rst of del src addr info is error.\n");

	nbl_del_src_addr_node(dev->rf, src_addr_index);
	return resp_rst;
}

static int nbl_core_roce_gid_set(struct nbl_device *dev, u16 src_addr_index,
				 const u8 *gid, const u8 *mac,
				 u8 insert_vlan_ipv4_valid)
{
	struct nbl_grc_send_src_addr_info_req info_req;
	uint8_t in[64];
	uint8_t out[64];
	int data_len = 0;
	int ret_val;
	uint8_t resp_rst;
	struct grc_cache_msg_header *head;

	memset(&info_req, 0, sizeof(info_req));
	info_req.src_addr_index = src_addr_index;
	info_req.insert_vlan_ipv4_valid = insert_vlan_ipv4_valid;
	memcpy(info_req.smac, mac, ETH_ALEN);
	memcpy(info_req.sip, gid, NBL_SRC_IP_SIZE);

	/* fill opcode */
	head = (struct grc_cache_msg_header *)in;
	head->op_code = GRC_MSG_OP_SEND_SRC_ADDR_INFO;
	head->payload_len = sizeof(info_req);
	data_len += sizeof(struct grc_cache_msg_header);

	/* fill info req */
	memcpy(in + data_len, &info_req, sizeof(info_req));
	data_len += sizeof(info_req);

	ret_val = nbl_exec_cmd(dev->rf, in, data_len, out, sizeof(out));
	if (ret_val) {
		nbl_pr_err("send src addr info cmd err=%d.\n", ret_val);
		return ret_val;
	}

	/* get operation result */
	memcpy(&resp_rst, out, sizeof(resp_rst));
	if (resp_rst) {
		nbl_pr_err("the returned rst of send src addr info is error.\n");
		return -ENODATA;
	}

	return 0;
}

static int nbl_set_roce_addr(struct nbl_device *dev, u8 port_num, u16 src_addr_index,
			     const union ib_gid *gid,
			     const struct ib_gid_attr *attr)
{
	u8 mac[ETH_ALEN] = {0};
	u8 insert_vlan_ipv4_valid = 0;
	int rst;

	if (gid == NULL) {
		nbl_ib_err(&dev->rf->sc_dev, "gid is null.\n");
		return -EINVAL;
	}

	if (attr->ndev) {
		ether_addr_copy(mac, attr->ndev->dev_addr);
		if (is_vlan_dev(attr->ndev))
			insert_vlan_ipv4_valid |= NBL_AH_VECTOR_VLAN_TAG;
	}

	if (attr->gid_type != IB_GID_TYPE_ROCE_UDP_ENCAP) {
		nbl_ib_err(
			&dev->rf->sc_dev,
			"gid type is not ROCE_UDP_ENCAP, the gid type is %u.\n",
			attr->gid_type);
		return -EINVAL;
	}

	if (ipv6_addr_v4mapped((struct in6_addr *)&attr->gid))
		insert_vlan_ipv4_valid |= NBL_AH_VECTOR_IPV4_VALID;

	rst = nbl_core_roce_gid_set(dev, src_addr_index, gid->raw, mac,
				    insert_vlan_ipv4_valid);
	if (rst) {
		nbl_ib_err(&dev->rf->sc_dev, "nbl_core_roce_gid_set failed.\n");
		return rst;
	}

	return 0;
}

int nbl_ib_add_gid(const struct ib_gid_attr *attr, void **context)
{
	struct nbl_device *dev = to_nbl_dev(attr->device);
	u16 src_addr_index;
	int ret;

	ret = nbl_add_src_addr_info(dev, attr, &src_addr_index);
	if (ret) {
		nbl_ib_warn(&dev->rf->sc_dev, "can not save src addr info to grc.\n");
		return ret;
	}

	ret = nbl_set_roce_addr(dev, attr->port_num, src_addr_index, &attr->gid,
				attr);
	if (ret) {
		nbl_ib_warn(&dev->rf->sc_dev, "nbl_set_roce_addr ret=%d.\n", ret);
		(void)nbl_del_src_addr_info(dev, src_addr_index, attr->index);
		return ret;
	}

	return 0;
}

int nbl_ib_del_gid(const struct ib_gid_attr *attr, void **context)
{
	struct nbl_device *dev = to_nbl_dev(attr->device);
	u16 src_addr_index;
	u8 src_ip[NBL_SRC_IP_SIZE];
	int ret = 0;

	/* release the resource corresponding to the index of global src addr table */
	ret = nbl_get_src_addr_info(dev, attr->index, &src_addr_index, src_ip);
	if (ret) {
		nbl_ib_err(&dev->rf->sc_dev,
			"get nbl src addr index failed, the function_id: %u, the sgid_index: %u.\n",
			dev->rf->sc_dev.function_id, attr->index);
		return ret;
	}

	ret = nbl_del_src_addr_info(dev, attr->index, src_addr_index);
	if (ret) {
		nbl_ib_err(&dev->rf->sc_dev,
			"del nbl src addr info failed, the src_addr_index: %u.\n", src_addr_index);
		return ret;
	}
	return 0;
}

int nbl_ib_query_gid(struct ib_device *ibdev, u32 port, int index,
		  union ib_gid *gid)
{
	struct nbl_device *dev = to_nbl_dev(ibdev);
	u16 src_addr_index;
	u8 src_ip[NBL_SRC_IP_SIZE];
	int ret;

	ret = nbl_get_src_addr_info(dev, index, &src_addr_index, src_ip);
	if (ret) {
		nbl_ib_err(&dev->rf->sc_dev,
			"get nbl src addr index failed, the function_id: %u, the sgid_index: %u.\n",
			dev->rf->sc_dev.function_id, index);
		return ret;
	}

	memcpy(gid->raw, src_ip, sizeof(src_ip));
	return 0;
}
