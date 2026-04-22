// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#include <net/ipv6.h>
#include <linux/etherdevice.h>
#include <linux/inet.h>
#include <linux/in6.h>
#include <linux/netlink.h>
#include <ub/ubase/ubase_comm_ctrlq.h>

#include "unic_comm_addr.h"
#include "unic_trace.h"
#include "unic_ip.h"

static void unic_update_addr_state(struct unic_vport *vport,
				   struct unic_comm_addr_node *addr_node,
				   enum UNIC_COMM_ADDR_STATE state,
				   const u8 *addr)
{
	struct auxiliary_device *adev = vport->back->comdev.adev;
	struct unic_dev *unic_dev = dev_get_drvdata(&adev->dev);
	char format_masked_ip_addr[UNIC_MASKED_FORMAT_IP_LEN];

	/* update the state of address node by stack in rack server.
	 * if ip node exist in ip_list and receive the ack form stack,
	 * update_addr_state and handle accidental deletion.
	 */
	switch (state) {
	case UNIC_COMM_ADDR_TO_ADD:
		if (addr_node->state == UNIC_COMM_ADDR_TO_ADD)
			addr_node->state = UNIC_COMM_ADDR_ACTIVE;
		break;
	case UNIC_COMM_ADDR_TO_DEL:
		if (addr_node->state == UNIC_COMM_ADDR_TO_DEL) {
			list_del(&addr_node->node);
			kfree(addr_node);
		} else if (addr_node->state == UNIC_COMM_ADDR_ACTIVE) {
			addr_node->state = UNIC_COMM_ADDR_TO_ADD;
			unic_format_masked_ip_addr(format_masked_ip_addr, addr);
			unic_info(unic_dev,
				  "stack deleted an planned ip %s, need to re-add it.\n",
				  format_masked_ip_addr);
		}
		break;
	default:
		break;
	}
}

static int unic_update_stack_ip_addr(struct unic_vport *vport,
				     enum UNIC_COMM_ADDR_STATE state,
				     const u8 *addr, u16 ip_mask)
{
	spinlock_t *addr_list_lock = &vport->addr_tbl.ip_list_lock;
	struct auxiliary_device *adev = vport->back->comdev.adev;
	struct unic_dev *unic_dev = dev_get_drvdata(&adev->dev);
	char format_masked_ip_addr[UNIC_MASKED_FORMAT_IP_LEN];
	struct list_head *list = &vport->addr_tbl.ip_list;
	struct unic_comm_addr_node *addr_node, *tmp;
	int ret = 0;

	clear_bit(UNIC_VPORT_STATE_IP_TBL_CHANGE, &vport->state);

	spin_lock_bh(addr_list_lock);

	addr_node = unic_comm_find_addr_node(list, addr, ip_mask);
	if (addr_node) {
		unic_update_addr_state(vport, addr_node, state, addr);
		goto finish_update_state;
	}

	if (state == UNIC_COMM_ADDR_TO_DEL) {
		ret = -ENOENT;
		goto finish_update_state;
	}

	/* handle accidental addition, create addr node for deleting*/
	addr_node = kzalloc(sizeof(*addr_node), GFP_ATOMIC);
	if (!addr_node) {
		ret = -ENOMEM;
		goto finish_update_state;
	}

	addr_node->state = UNIC_COMM_ADDR_TO_DEL;
	addr_node->node_mask = ip_mask;
	memcpy(addr_node->unic_addr, addr, UNIC_ADDR_LEN);
	list_add_tail(&addr_node->node, list);
	unic_format_masked_ip_addr(format_masked_ip_addr, addr);
	unic_info(unic_dev,
		  "stack added a non-planned ip %s, need to delete it.\n",
		  format_masked_ip_addr);
	set_bit(UNIC_VPORT_STATE_IP_TBL_CHANGE, &vport->state);
	goto unlock_and_exit;

finish_update_state:
	list_for_each_entry(tmp, list, node) {
		if (tmp->state != UNIC_COMM_ADDR_ACTIVE) {
			set_bit(UNIC_VPORT_STATE_IP_TBL_CHANGE, &vport->state);
			break;
		}
	}
unlock_and_exit:
	spin_unlock_bh(addr_list_lock);

	return ret;
}

int unic_handle_stack_ip_feedback(struct unic_vport *vport,
				  enum UNIC_COMM_ADDR_STATE state,
				  struct sockaddr *addr, u16 ip_mask)
{
	struct auxiliary_device *adev = vport->back->comdev.adev;
	struct unic_dev *unic_dev = dev_get_drvdata(&adev->dev);
	char format_masked_ip_addr[UNIC_MASKED_FORMAT_IP_LEN];
	struct in6_addr ip_addr;
	int ret;

	ret = unic_convert_ip_addr(addr, &ip_addr);
	if (ret)
		unic_info(unic_dev,
			  "invalid IP protocol type, ret = %d.\n", ret);

	ret = unic_update_stack_ip_addr(vport, state,
					(const unsigned char *)&ip_addr,
					ip_mask);
	if (ret) {
		unic_format_masked_ip_addr(format_masked_ip_addr, (u8 *)&ip_addr);
		unic_err(unic_dev, "failed to %s IP %s from ip list, ret = %d.\n",
			 state == UNIC_COMM_ADDR_TO_ADD ? "add" : "delete",
			 format_masked_ip_addr, ret);
	}

	return ret;
}

static bool unic_is_ipv4(struct unic_stack_ip_info *ip_info)
{
	if (ip_info->ip_addr[0] == 0x0 && ip_info->ip_addr[1] == 0x0 &&
	    ip_info->ip_addr[2] == UNIC_IPV4_PREFIX)
		return true;
	else
		return false;
}

static int unic_fill_rtattr_pack(struct nlmsghdr *nh, size_t req_sz,
				 unsigned short rta_type, const void *payload,
				 size_t size)
{
	size_t nl_size = RTA_ALIGN(nh->nlmsg_len) + RTA_LENGTH(size);
	struct rtattr *attr = (struct rtattr *)((char *)(nh) +
			       RTA_ALIGN(nh->nlmsg_len));

	if (req_sz < nl_size)
		return -EINVAL;

	nh->nlmsg_len = nl_size;
	attr->rta_len = RTA_LENGTH(size);
	attr->rta_type = rta_type;
	memcpy(RTA_DATA(attr), payload, size);

	return 0;
}

static int unic_fill_netlink_ip_req(struct unic_netlink_ip_req *req,
				    struct sk_buff *skb, struct net_device *dev,
				    struct unic_stack_ip_info *ip_info,
				    sa_family_t sa_family)
{
	int ret;

	NETLINK_CB(skb).portid = 0;
	NETLINK_CB(skb).dst_group = 0;
	NETLINK_CB(skb).flags = NETLINK_SKB_DST;
	memset(req, 0, sizeof(*req));

	if (ip_info->ip_cmd == UNIC_COMM_ADDR_TO_ADD) {
		req->nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_EXCL | NLM_F_CREATE;
		req->nh.nlmsg_type = RTM_NEWADDR;
	} else {
		req->nh.nlmsg_flags = NLM_F_REQUEST;
		req->nh.nlmsg_type = RTM_DELADDR;
	}

	req->nh.nlmsg_len = NLMSG_LENGTH(sizeof(req->info));
	req->info.ifa_family = sa_family;
	req->info.ifa_flags = IFA_F_PERMANENT;
	req->info.ifa_scope = RT_SCOPE_UNIVERSE;
	req->info.ifa_prefixlen = (u8)ip_info->ip_mask;
	req->info.ifa_index = dev->ifindex;

	if (sa_family == AF_INET) {
		ret = unic_fill_rtattr_pack(&req->nh, sizeof(*req), IFA_LOCAL,
					    &ip_info->ip_addr[UNIC_IP_FOURTH_PART],
					    sizeof(ip_info->ip_addr[UNIC_IP_FOURTH_PART]));
		if (ret)
			return ret;

		ret = unic_fill_rtattr_pack(&req->nh, sizeof(*req), IFA_ADDRESS,
					    &ip_info->ip_addr[UNIC_IP_FOURTH_PART],
					    sizeof(ip_info->ip_addr[UNIC_IP_FOURTH_PART]));
	} else {
		ret = unic_fill_rtattr_pack(&req->nh, sizeof(*req), IFA_LOCAL,
					    ip_info->ip_addr,
					    sizeof(ip_info->ip_addr));
		if (ret)
			return ret;

		ret = unic_fill_rtattr_pack(&req->nh, sizeof(*req), IFA_ADDRESS,
					    ip_info->ip_addr,
					    sizeof(ip_info->ip_addr));
	}

	return ret;
}

static int unic_set_stack_ip(struct net_device *dev,
			     struct unic_stack_ip_info *ip_info)
{
	struct unic_dev *unic_dev = netdev_priv(dev);
	struct net *tmpdev = dev_net(dev);
	struct unic_netlink_ip_req *req;
	struct sock *sk = tmpdev->rtnl;
	sa_family_t sa_family;
	struct sk_buff *skb;
	int ret;

	skb = alloc_skb(NLMSG_ALIGN(sizeof(*req)), GFP_KERNEL);
	if (!skb) {
		unic_err(unic_dev,
			 "failed to alloc skb, unic stop setting stack ip.\n");
		return -ENOMEM;
	}

	req = skb_put(skb, sizeof(*req));
	sa_family = unic_is_ipv4(ip_info) ? AF_INET : AF_INET6;
	ret = unic_fill_netlink_ip_req(req, skb, dev, ip_info, sa_family);
	if (ret) {
		unic_err(unic_dev,
			 "failed to fill netlink ip req, ret = %d.\n", ret);
		goto failed_packet_seq;
	}

	trace_unic_ip_req_skb(dev, skb, &req->nh, &req->info, req->attrbuf);
	netlink_unicast(sk, skb, 0, 0);

	return 0;

failed_packet_seq:
	kfree_skb(skb);

	return ret;
}

static int unic_sync_stack_ip(struct unic_vport *vport,
			      struct unic_comm_addr_node *ip_node, u16 ip_cmd)
{
	struct net_device *netdev = vport->back->comdev.netdev;
	struct unic_dev *unic_dev = netdev_priv(netdev);
	struct unic_stack_ip_info ip_info;
	int ret;

	ip_info.ip_cmd = ip_cmd;
	ip_info.ip_mask = ip_node->node_mask;
	memcpy(&ip_info.ip_addr, &ip_node->ip_addr, sizeof(ip_info.ip_addr));

	ret = unic_set_stack_ip(netdev, &ip_info);
	if (ret)
		unic_err(unic_dev,
			 "failed to set ip to stack, ret = %d.\n", ret);

	return ret;
}

static void unic_sync_ip_list(struct unic_vport *vport, struct list_head *list,
			      enum unic_ctrlq_ip_event state)
{
	struct unic_comm_addr_node *ip_node, *tmp;
	int ret;

	list_for_each_entry_safe(ip_node, tmp, list, node) {
		ret = unic_sync_stack_ip(vport, ip_node, state);
		if (ret)
			set_bit(UNIC_VPORT_STATE_IP_TBL_CHANGE, &vport->state);

		list_del(&ip_node->node);
		kfree(ip_node);
	}
}

static void unic_sync_addr_table(struct unic_vport *vport,
				 struct list_head *list,
				 spinlock_t *addr_list_lock)
{
	struct auxiliary_device *adev = vport->back->comdev.adev;
	struct unic_comm_addr_node *addr_node, *tmp, *new_node;
	struct list_head tmp_add_list, tmp_del_list;

	INIT_LIST_HEAD(&tmp_add_list);
	INIT_LIST_HEAD(&tmp_del_list);

	/* move the addr to the tmp_add_list and tmp_del_list, then
	 * we can add/delete these addr outside the spin lock
	 */
	spin_lock_bh(addr_list_lock);

	list_for_each_entry_safe(addr_node, tmp, list, node) {
		if (addr_node->state == UNIC_COMM_ADDR_ACTIVE)
			continue;

		new_node = kzalloc(sizeof(*new_node), GFP_ATOMIC);
		if (!new_node) {
			dev_err_ratelimited(&adev->dev,
					    "failed to alloc memory for new node.\n");
			goto stop_traverse;
		}
		memcpy(new_node->unic_addr, addr_node->unic_addr, UNIC_ADDR_LEN);
		new_node->state = addr_node->state;
		new_node->node_mask = addr_node->node_mask;

		if (new_node->state == UNIC_COMM_ADDR_TO_DEL)
			list_add_tail(&new_node->node, &tmp_del_list);
		else
			list_add_tail(&new_node->node, &tmp_add_list);
	}

stop_traverse:
	spin_unlock_bh(addr_list_lock);

	unic_sync_ip_list(vport, &tmp_del_list, UNIC_CTRLQ_DEL_IP);
	unic_sync_ip_list(vport, &tmp_add_list, UNIC_CTRLQ_ADD_IP);
}

void unic_sync_ip_table(struct unic_dev *unic_dev)
{
	struct unic_vport *vport = &unic_dev->vport;

	if (!test_bit(UNIC_VPORT_STATE_IP_TBL_CHANGE, &vport->state))
		return;

	unic_sync_addr_table(vport, &vport->addr_tbl.ip_list,
			     &vport->addr_tbl.ip_list_lock);
}

static void unic_build_stack_ip_info(struct unic_ctrlq_ip_notify_req *req,
				     struct unic_stack_ip_info *st_ip)
{
#define le32_to_be32(x) cpu_to_be32(le32_to_cpu(x))

	st_ip->ip_cmd = le16_to_cpu(req->ip_cmd);
	st_ip->ip_mask = le16_to_cpu(req->ip_mask);
	st_ip->ip_addr[0] = le32_to_be32(req->ip_addr[3]);
	st_ip->ip_addr[1] = le32_to_be32(req->ip_addr[2]);
	st_ip->ip_addr[2] = le32_to_be32(req->ip_addr[1]);
	st_ip->ip_addr[3] = le32_to_be32(req->ip_addr[0]);
}

static int unic_update_addr_list(struct list_head *list,
				 spinlock_t *addr_list_lock,
				 enum UNIC_COMM_ADDR_STATE state,
				 const u8 *addr, u16 ip_mask)
{
	struct unic_comm_addr_node *addr_node;

	spin_lock_bh(addr_list_lock);

	/* if the addr is already in the addr list, no need to add a new
	 * one into it, just check the addr state, convert it to a new
	 * state, or just remove it, or do nothing.
	 */
	addr_node = unic_comm_find_addr_node(list, addr, ip_mask);
	if (addr_node) {
		unic_comm_update_addr_state(addr_node, state);
		spin_unlock_bh(addr_list_lock);
		return 0;
	}

	/* if this addr is never added, unnecessary to delete */
	if (state == UNIC_COMM_ADDR_TO_DEL) {
		spin_unlock_bh(addr_list_lock);
		return -ENOENT;
	}

	addr_node = kzalloc(sizeof(*addr_node), GFP_ATOMIC);
	if (!addr_node) {
		spin_unlock_bh(addr_list_lock);
		return -ENOMEM;
	}

	addr_node->state = state;
	addr_node->node_mask = ip_mask;
	memcpy(addr_node->unic_addr, addr, UNIC_ADDR_LEN);
	list_add_tail(&addr_node->node, list);

	spin_unlock_bh(addr_list_lock);

	return 0;
}

static void unic_send_notify_ip_resp(struct auxiliary_device *adev, u16 seq,
				     u8 result)
{
	struct unic_dev *unic_dev = dev_get_drvdata(&adev->dev);
	struct unic_ctrlq_ip_notify_resp resp = {0};
	struct ubase_ctrlq_msg msg = {0};
	int ret;

	msg.service_ver = UBASE_CTRLQ_SER_VER_01;
	msg.service_type = UBASE_CTRLQ_SER_TYPE_IP_ACL;
	msg.opcode = UBASE_CTRLQ_OPC_NOTIFY_IP;
	msg.in_size = sizeof(resp);
	msg.in = &resp;
	msg.is_resp = 1;
	msg.resp_seq = seq;
	msg.resp_ret = result;

	ret = ubase_ctrlq_send_msg(adev, &msg);
	if (ret)
		unic_err(unic_dev,
			 "failed to notify ip resp by ctrlq, ret = %d.\n", ret);
}

static int unic_update_tmp_ip_list(struct unic_dev *unic_dev,
				   struct list_head *list,
				   struct unic_stack_ip_info *st_ip)
{
	struct unic_comm_addr_node *addr_node;
	enum UNIC_COMM_ADDR_STATE state;

	if (st_ip->ip_cmd == UNIC_CTRLQ_ADD_IP) {
		state = UNIC_COMM_ADDR_TO_ADD;
	} else if (st_ip->ip_cmd == UNIC_CTRLQ_DEL_IP) {
		state = UNIC_COMM_ADDR_TO_DEL;
	} else {
		unic_err(unic_dev, "invalid ip cmd by ctrlq, ip cmd = %u.\n",
			 st_ip->ip_cmd);
		return -EINVAL;
	}

	addr_node = unic_comm_find_addr_node(list, (u8 *)&st_ip->ip_addr,
					     st_ip->ip_mask);
	if (addr_node) {
		addr_node->state = state;
		return 0;
	}

	addr_node = kzalloc(sizeof(*addr_node), GFP_ATOMIC);
	if (!addr_node)
		return -ENOMEM;

	addr_node->state = state;
	addr_node->node_mask = st_ip->ip_mask;
	memcpy(addr_node->unic_addr, (u8 *)&st_ip->ip_addr, UNIC_ADDR_LEN);
	list_add_tail(&addr_node->node, list);

	return 0;
}

int unic_handle_notify_ip_event(struct auxiliary_device *adev, u8 service_ver,
				void *data, u16 len, u16 seq)
{
	struct unic_dev *priv = (struct unic_dev *)dev_get_drvdata(&adev->dev);
	char format_ip[UNIC_MASKED_FORMAT_IP_LEN];
	struct unic_vport *vport = &priv->vport;
	struct unic_ctrlq_ip_notify_req *req;
	struct unic_stack_ip_info st_ip;
	int ret;

	if (!unic_dev_ubl_supported(priv))
		return -EOPNOTSUPP;

	if (service_ver != UBASE_CTRLQ_SER_VER_01)
		return -EOPNOTSUPP;

	if (len < sizeof(*req)) {
		unic_err(priv, "failed to verify ip info size, len = %u.\n", len);
		ret = -EINVAL;
		goto send_resp;
	}

	req = (struct unic_ctrlq_ip_notify_req *)data;

	unic_build_stack_ip_info(req, &st_ip);

	spin_lock_bh(&vport->addr_tbl.tmp_ip_lock);
	if (test_bit(UNIC_VPORT_STATE_IP_QUERYING, &vport->state)) {
		ret = unic_update_tmp_ip_list(priv, &vport->addr_tbl.tmp_ip_list,
					      &st_ip);
		goto unlock;
	}

	if (st_ip.ip_cmd == UNIC_CTRLQ_ADD_IP) {
		ret = unic_update_addr_list(&vport->addr_tbl.ip_list,
					    &vport->addr_tbl.ip_list_lock,
					    UNIC_COMM_ADDR_TO_ADD,
					    (u8 *)&st_ip.ip_addr,
					    st_ip.ip_mask);
	} else if (st_ip.ip_cmd == UNIC_CTRLQ_DEL_IP) {
		ret = unic_update_addr_list(&vport->addr_tbl.ip_list,
					    &vport->addr_tbl.ip_list_lock,
					    UNIC_COMM_ADDR_TO_DEL,
					    (u8 *)&st_ip.ip_addr,
					    st_ip.ip_mask);
	} else {
		unic_err(priv, "invalid ip cmd by ctrlq, cmd = %u.\n", st_ip.ip_cmd);
		ret = -EINVAL;
		goto unlock;
	}

	if (ret == -ENOENT) {
		unic_format_masked_ip_addr(format_ip, (u8 *)&st_ip.ip_addr);
		unic_err(priv, "failed to delete IP %s from ip list.\n",
			 format_ip);
		ret = 0;
		goto unlock;
	}

	if (!ret)
		set_bit(UNIC_VPORT_STATE_IP_TBL_CHANGE, &vport->state);

unlock:
	spin_unlock_bh(&vport->addr_tbl.tmp_ip_lock);
send_resp:
	unic_send_notify_ip_resp(adev, seq, (u8)(-ret));

	return ret;
}

static int unic_update_ctrlq_ip_list(struct unic_ip_info *ip_info,
				     struct unic_vport *vport,
				     struct list_head *list)
{
#define le32_to_be32(x) cpu_to_be32(le32_to_cpu(x))

	struct unic_comm_addr_node *ip_node, *new_node, *tmp_node;
	struct unic_stack_ip_info st_ip;

	st_ip.ip_mask = le16_to_cpu(ip_info->ip_mask);
	st_ip.ip_addr[0] = le32_to_be32(ip_info->ip_addr[3]);
	st_ip.ip_addr[1] = le32_to_be32(ip_info->ip_addr[2]);
	st_ip.ip_addr[2] = le32_to_be32(ip_info->ip_addr[1]);
	st_ip.ip_addr[3] = le32_to_be32(ip_info->ip_addr[0]);

	ip_node = kzalloc(sizeof(*ip_node), GFP_ATOMIC);
	if (!ip_node)
		return -ENOMEM;

	ip_node->state = UNIC_COMM_ADDR_TO_ADD;
	ip_node->node_mask = st_ip.ip_mask;
	memcpy(ip_node->unic_addr, &st_ip.ip_addr, UNIC_ADDR_LEN);

	new_node = unic_comm_find_addr_node(&vport->addr_tbl.ip_list,
					    ip_node->unic_addr,
					    ip_node->node_mask);
	if (new_node) {
		if (new_node->state != UNIC_COMM_ADDR_TO_ADD)
			new_node->state = UNIC_COMM_ADDR_ACTIVE;

		kfree(ip_node);
	} else {
		list_add_tail(&ip_node->node, &vport->addr_tbl.ip_list);
	}

	tmp_node = kzalloc(sizeof(*tmp_node), GFP_ATOMIC);
	if (!tmp_node)
		return -ENOMEM;

	tmp_node->state = UNIC_COMM_ADDR_TO_ADD;
	tmp_node->node_mask = st_ip.ip_mask;
	memcpy(tmp_node->unic_addr, &st_ip.ip_addr, UNIC_ADDR_LEN);
	list_add_tail(&tmp_node->node, list);

	return 0;
}

static int unic_ctrlq_query_ip(struct auxiliary_device *adev, u16 *ip_index,
			       u8 *get_count, struct unic_vport *vport,
			       struct list_head *list)
{
	struct unic_dev *unic_dev = dev_get_drvdata(&adev->dev);
	struct unic_ctrlq_query_ip_resp resp = {0};
	struct unic_ctrlq_query_ip_req req = {0};
	struct ubase_ctrlq_msg msg = {0};
	int ret;
	u8 i;

	req.ip_index = cpu_to_le16(*ip_index);

	msg.service_ver = UBASE_CTRLQ_SER_VER_01;
	msg.service_type = UBASE_CTRLQ_SER_TYPE_IP_ACL;
	msg.opcode = UBASE_CTRLQ_OPC_QUERY_IP;
	msg.need_resp = 1;
	msg.is_resp = 0;
	msg.in_size = sizeof(req);
	msg.in = &req;
	msg.out_size = sizeof(resp);
	msg.out = &resp;

	ret = ubase_ctrlq_send_msg(adev, &msg);
	if (ret) {
		unic_err(unic_dev,
			 "failed to query ip by ctrlq, ret = %d.\n", ret);
		return ret;
	}

	spin_lock_bh(&vport->addr_tbl.ip_list_lock);

	for (i = 0; i < resp.get_count; i++) {
		ret = unic_update_ctrlq_ip_list(&resp.ip_info[i], vport, list);
		if (ret)
			goto out;
	}

	*get_count = resp.get_count;
	*ip_index = le16_to_cpu(resp.ip_index);

out:
	spin_unlock_bh(&vport->addr_tbl.ip_list_lock);

	return ret;
}

static void unic_update_ip_list(struct unic_vport *vport,
				struct list_head *list)
{
	struct unic_comm_addr_node *ip_node, *tmp, *new_node;

	spin_lock_bh(&vport->addr_tbl.ip_list_lock);

	/* If the ip exists in ip list but does not exist in tmp list, the ip has
	 * been deleted from the manager. If the ip has not been added to the
	 * protocol stack, the node is directly removed. If the ip has been added
	 * to the protocol stack, the node status is set to TO_DEL.
	 */
	list_for_each_entry_safe(ip_node, tmp, &vport->addr_tbl.ip_list, node) {
		new_node = unic_comm_find_addr_node(list, ip_node->unic_addr,
						    ip_node->node_mask);
		if (!new_node) {
			if (ip_node->state == UNIC_COMM_ADDR_ACTIVE) {
				ip_node->state = UNIC_COMM_ADDR_TO_DEL;
			} else if (ip_node->state == UNIC_COMM_ADDR_TO_ADD) {
				list_del(&ip_node->node);
				kfree(ip_node);
			}
		}
	}

	/* During the query, the ip added or deleted by the manager are saved in
	 * the tmp ip list. After the query is complete, the tmp ip list is
	 * synchronized to the ip list.
	 */
	list_for_each_entry_safe(ip_node, tmp, &vport->addr_tbl.tmp_ip_list, node) {
		new_node = unic_comm_find_addr_node(&vport->addr_tbl.ip_list,
						    ip_node->unic_addr,
						    ip_node->node_mask);
		if (new_node) {
			unic_comm_update_addr_state(new_node, ip_node->state);
		} else {
			if (ip_node->state == UNIC_COMM_ADDR_TO_ADD)
				list_move_tail(&ip_node->node,
					       &vport->addr_tbl.ip_list);
		}
	}

	list_for_each_entry_safe(ip_node, tmp, &vport->addr_tbl.ip_list, node) {
		if (ip_node->state != UNIC_COMM_ADDR_ACTIVE) {
			set_bit(UNIC_VPORT_STATE_IP_TBL_CHANGE, &vport->state);
			break;
		}
	}

	spin_unlock_bh(&vport->addr_tbl.ip_list_lock);
}

void unic_query_ip_addr(struct auxiliary_device *adev)
{
#define UNIC_LOOP_COUNT(total_size, size) ((total_size) / (size) + 1)

	struct unic_dev *priv = (struct unic_dev *)dev_get_drvdata(&adev->dev);
	struct unic_comm_addr_node *ip_node, *tmp;
	struct unic_vport *vport = &priv->vport;
	struct list_head tmp_list;
	u16 ip_index = 0, cnt = 0;
	u8 get_count = 0;
	int ret;

	if (!unic_dev_ubl_supported(priv))
		return;

	set_bit(UNIC_VPORT_STATE_IP_QUERYING, &priv->vport.state);
	INIT_LIST_HEAD(&tmp_list);

	while (ip_index < UNIC_IP_TABLE_SIZE &&
	       cnt < UNIC_LOOP_COUNT(UNIC_IP_TABLE_SIZE, UNIC_CTRLQ_IP_REQ_SIZE)) {
		ret = unic_ctrlq_query_ip(adev, &ip_index, &get_count, vport,
					  &tmp_list);
		if (ret) {
			unic_err(priv,
				 "failed to query ip info by ctrlq, ret = %d.\n",
				 ret);
			break;
		}

		if (get_count != UNIC_CTRLQ_IP_REQ_SIZE)
			break;

		ip_index++;
		cnt++;
	}

	spin_lock_bh(&vport->addr_tbl.tmp_ip_lock);

	unic_update_ip_list(vport, &tmp_list);
	clear_bit(UNIC_VPORT_STATE_IP_QUERYING, &vport->state);

	list_for_each_entry_safe(ip_node, tmp, &vport->addr_tbl.tmp_ip_list, node) {
		list_del(&ip_node->node);
		kfree(ip_node);
	}

	spin_unlock_bh(&vport->addr_tbl.tmp_ip_lock);

	list_for_each_entry_safe(ip_node, tmp, &tmp_list, node) {
		list_del(&ip_node->node);
		kfree(ip_node);
	}
}

void unic_uninit_ip_table(struct unic_dev *unic_dev)
{
	struct unic_vport *vport = &unic_dev->vport;
	struct list_head *list = &vport->addr_tbl.ip_list;
	struct unic_comm_addr_node *ip_node, *tmp;

	spin_lock_bh(&vport->addr_tbl.ip_list_lock);

	list_for_each_entry_safe(ip_node, tmp, list, node) {
		list_del(&ip_node->node);
		kfree(ip_node);
	}

	spin_unlock_bh(&vport->addr_tbl.ip_list_lock);
}

int unic_add_ip_addr(struct unic_dev *unic_dev, struct sockaddr *addr,
		     u16 ip_mask)
{
	return unic_handle_stack_ip_feedback(&unic_dev->vport,
					     UNIC_COMM_ADDR_TO_ADD,
					     addr, ip_mask);
}

int unic_rm_ip_addr(struct unic_dev *unic_dev, struct sockaddr *addr,
		    u16 ip_mask)
{
	return unic_handle_stack_ip_feedback(&unic_dev->vport,
					     UNIC_COMM_ADDR_TO_DEL,
					     addr, ip_mask);
}
