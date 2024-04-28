/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef _ROCE_NETLINK_H_
#define _ROCE_NETLINK_H_
#ifdef ROCE_NETLINK_EN
#include <net/netlink.h>
#include <net/net_namespace.h>
#include <linux/netlink.h>

#include "udk_usrnl.h"
#include "roce_k_ioctl.h"
#include "roce.h"

#define USRNL_GENL_ATTR_MAX (__USRNL_GENL_ATTR_MAX - 1)

/* netlink server info in roce ko */
#define ROCE3_FAMILY	 "ROCE"
#define ROCE3_VERSION	0x1
#define ROCE_MAX_FUNCTION 128
#define PF_MAX_SIZE 32
#define VF_USE_SIZE 96

#define P2PCOS_MAX_VALUE 2
#define MAX_COS_NUM 0x7

#ifndef __NET_GENERIC_NETLINK_H
/* 解决genentlink 头文件冲突问题 */
struct genlmsghdr {
	u8 cmd;
	u8 version;
	u16 reserved;
};
#define USER_PTR_SIZE 2

/* length of family name */

#define GENL_NAMSIZ	16
#define GENL_HDRLEN	NLMSG_ALIGN(sizeof(struct genlmsghdr))

struct genl_info {
	u32 snd_seq;
	u32 snd_portid;
	struct nlmsghdr *nlhdr;
	struct genlmsghdr *genlhdr;
	void *userhdr;
	struct nlattr **attrs;
	possible_net_t	_net;
	void *user_ptr[USER_PTR_SIZE];
	struct netlink_ext_ack *extack;
};

struct genl_ops {
	int (*doit)(struct sk_buff *skb, struct genl_info *info);
	int (*start)(struct netlink_callback *cb);
	int (*dumpit)(struct sk_buff *skb, struct netlink_callback *cb);
	int (*done)(struct netlink_callback *cb);
	const struct nla_policy *policy;
	unsigned int maxattr;
	u8 cmd;
	u8 internal_flags;
	u8 flags;
	u8 validate;
};

struct genl_small_ops {
	int (*doit)(struct sk_buff *skb, struct genl_info *info);
	int (*dumpit)(struct sk_buff *skb, struct netlink_callback *cb);
	u8 cmd;
	u8 internal_flags;
	u8 flags;
	u8 validate;
};

struct genl_multicast_group {
	char name[GENL_NAMSIZ];
};

struct genl_family {
/* private */
	int id;
	unsigned int hdrsize;
	char name[GENL_NAMSIZ];
	unsigned int version;
	unsigned int maxattr;
	unsigned int mcgrp_offset;
	u8 netnsok : 1;
	u8 parallel_ops : 1;
	u8 n_ops;
	u8 n_small_ops;
	u8 n_mcgrps;
	const struct nla_policy *policy;
	int (*pre_doit)(const struct genl_ops *ops,
		struct sk_buff *skb,
		struct genl_info *info);
	void (*post_doit)(const struct genl_ops *ops,
		struct sk_buff *skb,
		struct genl_info *info);
	const struct genl_ops *ops;
	const struct genl_small_ops *small_ops;
	const struct genl_multicast_group *mcgrps;
	struct module *module;
};

static inline int genlmsg_unicast(struct net *net, struct sk_buff *skb, u32 portid)
{
	return nlmsg_unicast(net->genl_sock, skb, portid);
}

static inline struct net *genl_info_net(struct genl_info *info)
{
	return read_pnet(&info->_net);
}

static inline int genlmsg_reply(struct sk_buff *skb, struct genl_info *info)
{
	return genlmsg_unicast(genl_info_net(info), skb, info->snd_portid);
}
extern int genl_register_family(struct genl_family *family);
extern int genl_unregister_family(const struct genl_family *family);

#endif
enum hiroce_drv_cmd_type {
	HIROCE_DRV_CMD_DCB_GET = 100,
	HIROCE_DRV_CMD_CREATE_AH,
	HIROCE_DRV_CMD_MAX
};

struct hiroce_dev_dcbinfo_get {
	usrnl_drv_msg_hdr_s hdr;
	union roce3_query_dcb_buf dcb_info;
	uint16_t func_id;
	uint16_t rsvd;
};

struct hiroce_dev_dcbinfo_rsp {
	usrnl_drv_msg_hdr_s hdr;
	union roce3_query_dcb_buf dcb_info;
};

struct hiroce_dev_ah_info {
	usrnl_drv_msg_hdr_s hdr;
	union roce3_create_ah_buf ah_info;
	uint16_t func_id;
	uint16_t rsvd;
};

struct netlink_dev {
	struct roce3_device *rdev[ROCE_MAX_FUNCTION];
};

struct hiroce_netlink_dev {
	int used_dev_num;
	struct hiroce_netlink_dev *netlink;
	struct mutex mutex_dev;
};

int get_instance_of_func_id(int glb_func_id);
struct hiroce_netlink_dev *hiroce_get_adp(void);
int roce3_netlink_init(void);
void roce3_netlink_unit(void);

#endif // ROCE_NETLINK_EN
#endif
