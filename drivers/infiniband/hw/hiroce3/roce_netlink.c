// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2024 Huawei Technologies Co., Ltd

#include <net/net_namespace.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/netlink.h>

#include "roce_mix.h"
#include "roce_cmd.h"
#include "roce_netlink.h"

#ifdef ROCE_BONDING_EN
#include "roce_bond.h"
#endif

#ifdef ROCE_EXTEND
#include "roce_qp_extension.h"
#endif

#ifdef ROCE_NETLINK_EN

static struct hiroce_netlink_dev  g_roce_adapter = {0, 0};

struct hiroce_netlink_dev *hiroce_get_adp(void)
{
	return &g_roce_adapter;
}

int roce3_drv_cmd_execute(struct sk_buff *skb, struct genl_info *nl_info);

static void roce3_nlahdr_push(struct sk_buff *skb, u16 type)
{
	u16 attrlen = (u16)skb->len;
	struct nlattr *nlahdr;
	u32 padlen = nla_padlen(attrlen);

	nlahdr = (struct nlattr *)skb_push(skb, NLA_HDRLEN);
	nlahdr->nla_len = (u16)nla_attr_size(attrlen);
	nlahdr->nla_type = type;

	if ((skb->end - skb->tail) >= padlen)
		(void)skb_put(skb, padlen);
}

static struct nlmsghdr *nlmsg_push(struct sk_buff *skb, u32 portid, u32 seq,
	int type, int len, int flags)
{
	struct nlmsghdr *nlh;
	u32 size = (u32)nlmsg_msg_size(len);

	nlh = (struct nlmsghdr *)skb_push(skb, NLMSG_ALIGN(size));
	if (nlh == NULL)
		return NULL;

	nlh->nlmsg_type = (u16)type;
	nlh->nlmsg_len = skb->len;
	nlh->nlmsg_flags = (u16)flags;
	nlh->nlmsg_pid = portid;
	nlh->nlmsg_seq = seq;

	if (!__builtin_constant_p(size) || NLMSG_ALIGN(size) - size != 0)
		memset((char *)nlmsg_data(nlh) + len, 0, NLMSG_ALIGN(size) - size);

	return nlh;
}

static inline struct nlmsghdr *roce3_nlmsg_push(struct sk_buff *skb, u32 portid,
	u32 seq, int type, int payload, int flags)
{
	if (unlikely(skb_headroom(skb) < (unsigned int)nlmsg_total_size(payload)))
		return NULL;

	return nlmsg_push(skb, portid, seq, type, payload, flags);
}

static void *roce3_genlmsg_push(struct sk_buff *skb, u32 portid, u32 seq,
	const struct genl_family *family, int flags, u8 cmd)
{
	struct nlmsghdr *nlh;
	struct genlmsghdr *hdr = NULL;

	nlh = roce3_nlmsg_push(skb, portid, seq, (int)family->id,
		(int)(GENL_HDRLEN + family->hdrsize), flags);
	if (nlh == NULL)
		return NULL;

	hdr = nlmsg_data(nlh);
	hdr->cmd = cmd;
	hdr->version = (u8)family->version;
	hdr->reserved = 0;

	return (void *)nlh;
}

static long roce3_netlink_query_dcb(struct roce3_device *rdev, union roce3_query_dcb_buf *buf_in,
	union roce3_query_dcb_buf *dcb_buf)
{
	int ret;
	int get_group_id;
	struct roce_group_id group_id = {0};
	struct roce3_get_cos_inbuf in_buf;
	u8 cos;

#ifdef ROCE_BONDING_EN
	if (roce3_bond_get_dcb_info(rdev) != 0) {
		pr_err("[ROCE, ERR] %s: Failed to get dcb info\n", __func__);
		return (-EINVAL);
	}
#endif
	in_buf.port_num = buf_in->cmd.port;
	in_buf.sl = buf_in->cmd.sl;
	in_buf.sgid_index = buf_in->cmd.sgid_idx;
	in_buf.traffic_class = buf_in->cmd.traffic_class;
	ret = roce3_get_dcb_cfg_cos(rdev, &in_buf, &cos);
	if (ret != 0) {
		pr_err("[ROCE, ERR] %s: Failed to get cos from dcb info, ret:%d\n", __func__, ret);
		return ret;
	}

	dcb_buf->resp.cos = cos;

	if (rdev->is_vroce) {
		get_group_id = roce3_get_group_id(rdev->glb_func_id, rdev->hwdev, &group_id);
		if (get_group_id != 0) {
			pr_warn("Failed to get group id, ret(%d)", get_group_id);
		} else {
			rdev->group_rc_cos = group_id.group_rc_cos;
			rdev->group_ud_cos = group_id.group_ud_cos;
			rdev->group_xrc_cos = group_id.group_xrc_cos;
		}
		if (buf_in->cmd.dscp_type == (u8)IB_QPT_RC)
			dcb_buf->resp.cos = rdev->group_rc_cos & MAX_COS_NUM;
		else if (buf_in->cmd.dscp_type == (u8)IB_QPT_UD)
			dcb_buf->resp.cos = rdev->group_ud_cos & MAX_COS_NUM;
		else
			dcb_buf->resp.cos = rdev->group_xrc_cos & MAX_COS_NUM;
	}

	return 0;
}

int roce3_drv_dcb_info_get(void *buf_in, void *buf_out, u32 *out_size)
{
	struct hiroce_dev_dcbinfo_get *cmd;
	struct hiroce_dev_dcbinfo_rsp *rsp;
	struct roce3_device *rdev = NULL;
	int offset = 0;
	int ret;

	cmd = (struct hiroce_dev_dcbinfo_get *)buf_in;
	rsp = (struct hiroce_dev_dcbinfo_rsp *)buf_out;
	offset = get_instance_of_func_id(cmd->func_id);
	rdev = hiroce_get_adp()->netlink->rdev[offset];
	if (rdev == NULL) {
		pr_err("[ROCE, ERR]: offset is invild, please check\n");
		return -EINVAL;
	}
	ret = roce3_netlink_query_dcb(rdev, &cmd->dcb_info, &rsp->dcb_info);
	if (ret != 0) {
		pr_err("[ROCE, ERR] %s: Failed to get dcb info, ret:%d\n", __func__, ret);
		return ret;
	}
	rsp->hdr.cmd = HIROCE_DRV_CMD_DCB_GET;
	rsp->hdr.msg_len = (u32)sizeof(*rsp);
	rsp->hdr.err_code = 0;
	*out_size = (u32)sizeof(*rsp);

	return 0;
}

static long roce3_netlink_create_ah(struct roce3_device *rdev,  union roce3_create_ah_buf *buf,
	union roce3_create_ah_buf *rsp)
{
	struct rdma_ah_attr attr;
	struct ib_udata udata;

	attr.sl = buf->cmd.attr.sl;
	attr.static_rate = buf->cmd.attr.static_rate;
	attr.ah_flags = (buf->cmd.attr.is_global != 0) ? IB_AH_GRH : 0;
	attr.port_num = buf->cmd.attr.port_num;
	attr.grh.flow_label = buf->cmd.attr.grh.flow_label;
	attr.grh.sgid_index = buf->cmd.attr.grh.sgid_index;
	attr.grh.hop_limit = buf->cmd.attr.grh.hop_limit;
	attr.grh.traffic_class = buf->cmd.attr.grh.traffic_class;
	memset(attr.roce.dmac, 0, sizeof(attr.roce.dmac));
	memcpy(attr.grh.dgid.raw, buf->cmd.attr.grh.dgid, ROCE_GID_LEN);

	memset(&udata, 0, sizeof(struct ib_udata));
	if (roce3_resolve_grh(rdev, &attr, &buf->resp.vlan_id, &udata) != 0) {
		pr_err("[ROCE, ERR] %s: Failed to resolve grh\n", __func__);
		return -EINVAL;
	}

	memcpy(buf->resp.dmac, attr.roce.dmac, ETH_ALEN);
	memcpy(rsp, buf, sizeof(*buf));

	return 0;
}

int roce3_drv_create_ah(void *buf_in, void *buf_out, u32 *out_size)
{
	struct hiroce_dev_ah_info *cmd;
	struct hiroce_dev_ah_info *rsp;
	struct roce3_device *rdev = NULL;
	int offset;
	int ret;

	cmd = (struct hiroce_dev_ah_info *)buf_in;
	rsp = (struct hiroce_dev_ah_info *)buf_out;
	offset = get_instance_of_func_id(cmd->func_id);
	rdev = hiroce_get_adp()->netlink->rdev[offset];
	if (rdev == NULL) {
		pr_err("[ROCE, ERR]: offset is invild, please check\n");
		return -EINVAL;
	}
	ret = roce3_netlink_create_ah(rdev, &cmd->ah_info, &rsp->ah_info);
	if (ret != 0) {
		pr_err("[ROCE, ERR] %s: Failed to create ah, ret:%d\n", __func__, ret);
		return ret;
	}
	rsp->hdr.cmd = HIROCE_DRV_CMD_CREATE_AH;
	rsp->hdr.msg_len = (u32)sizeof(*rsp);
	rsp->hdr.err_code = 0;
	*out_size = (u32)sizeof(*rsp);

	return 0;
}

static int roce3_drv_cmd_process(usrnl_drv_msg_hdr_s *hdr, struct sk_buff *reply, u32 *out_size)
{
	int ret = 0;
	void *buf_out = (void *)reply->data;
	void *buf_in = (void *)hdr;

	switch (hdr->cmd) {
	case HIROCE_DRV_CMD_DCB_GET:
		ret = roce3_drv_dcb_info_get(buf_in, buf_out, out_size);
		break;
	case HIROCE_DRV_CMD_CREATE_AH:
		ret = roce3_drv_create_ah(buf_in, buf_out, out_size);
		break;
	default:
		pr_err("invalid drv cmd:0x%x", hdr->cmd);
		ret = -EINVAL;
		break;
	}
	return ret;
}

static const struct nla_policy roce3_policy[USRNL_GENL_ATTR_MAX + 1] = {
	[USRNL_GENL_ATTR] = { .type = NLA_UNSPEC }, //lint !e26
};

static const struct genl_ops roce3_genl_ops[] = {
	{ .cmd = USRNL_DEV_DRV_CMD_EXECUTE,
	  .flags = CAP_NET_ADMIN, /* Requires CAP_NET_ADMIN privilege. */
	  .policy = roce3_policy,
	  .doit = roce3_drv_cmd_execute,
	  .validate = GENL_DONT_VALIDATE_STRICT
	},
};

/*
 * Netlink Ops
 */
#define ROCE_GENL_OPS_ARRAY_SIZE 1

static struct genl_family roce3_genl_family = {
	.hdrsize = 0,
	.name = ROCE3_FAMILY,
	.version = ROCE3_VERSION,
	.maxattr = USRNL_GENL_ATTR_MAX,
	.netnsok = true,
	.parallel_ops = true,
	.ops = roce3_genl_ops,
	.n_ops = ROCE_GENL_OPS_ARRAY_SIZE,
};

struct genl_family *roce3_genl_families[] = {
	&roce3_genl_family,
};

int roce3_drv_cmd_execute(struct sk_buff *skb, struct genl_info *nl_info)
{
	u8 cmd;
	int rc;
	u32 out_size = 0;
	struct sk_buff *reply = NULL;
	struct nlattr *cmd_attr;
	usrnl_drv_msg_hdr_s *hdr = NULL;
	struct nlattr **ppstAttr = nl_info->attrs;

	cmd_attr = ppstAttr[USRNL_GENL_ATTR];
	if (cmd_attr == NULL) {
		pr_err("[ROCE, ERR] %s: Do drv cmd failed for NULL attr!", __func__);
		return -ENOMEM;
	}

	hdr = (usrnl_drv_msg_hdr_s *)nla_data(cmd_attr);

	reply = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (reply == NULL) {
		pr_err("Alloc reply buf for drv cmd:%d failed!", hdr->cmd);
		return -ENOMEM;
	}
	skb_reserve(reply, NLMSG_HDRLEN + GENL_HDRLEN + NLA_HDRLEN);

	cmd = hdr->cmd;
	rc = roce3_drv_cmd_process(hdr, reply, &out_size);
	if (rc != 0) {
		pr_err("Do drv cmd:%u failed, errcode %d", cmd, rc);
		nlmsg_free(reply);
		return -EIO;
	}

	hdr = (usrnl_drv_msg_hdr_s *)reply->data;
	hdr->msg_len = out_size;
	hdr->cmd = cmd;
	(void)skb_put(reply, out_size);

	roce3_nlahdr_push(reply, USRNL_GENL_ATTR);
	roce3_genlmsg_push(reply, nl_info->snd_portid, nl_info->snd_seq,
		&roce3_genl_family, 0, USRNL_DEV_DRV_CMD_EXECUTE);
	genlmsg_reply(reply, nl_info);

	return rc;
}

/* pf use 32, vf use 96 */
int get_instance_of_func_id(int glb_func_id)
{
	return glb_func_id > PF_MAX_SIZE ? glb_func_id % VF_USE_SIZE + PF_MAX_SIZE :
		glb_func_id;
}

int roce3_netlink_init(void)
{
	int err;

	err = genl_register_family(&roce3_genl_family);

	return err;
}

void roce3_netlink_unit(void)
{
	genl_unregister_family(&roce3_genl_family);
}

#endif
