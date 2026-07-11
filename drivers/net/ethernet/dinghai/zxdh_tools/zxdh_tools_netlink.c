// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include <net/sock.h>
#include <net/genetlink.h>
#include <linux/dinghai/zxdh_compat.h>
#include "../en_aux.h"
#include "zxdh_tools_ioctl.h"
#include "zxdh_tools_netlink.h"

/* operation definition */
static struct nla_policy zxdh_tools_genl_policy[ZXDH_TOOLS_A_MAX + 1] = {
	[ZXDH_TOOLS_A_MSG] = { .type = NLA_NUL_STRING },
};

s32 zxdh_tools_genl_recv_doit(struct sk_buff *skb, struct genl_info *info)
{
	DHTOOLS_LOG_INFO("is called!\n");
	return 0;
}

struct genl_ops zxdh_tools_gnl_ops[] = { {
	.cmd = ZXDH_TOOLS_C_ECHO,
	.flags = 0,
	.policy = zxdh_tools_genl_policy,
	.doit = zxdh_tools_genl_recv_doit,
	.dumpit = NULL,
} };

static struct genl_family zxdh_tools_msg_family = {
	.hdrsize = 0,
	.name = ZXDH_TOOLS_NETLINK_NAME,
	.version = 1,
	.maxattr = ZXDH_TOOLS_A_MAX,
	.ops = zxdh_tools_gnl_ops,
	.n_ops = 1,
};

s32 zxdh_tools_genl_msg_prepare_usr_msg(u8 cmd, size_t size, u32 pid, struct sk_buff **skbp)
{
	void *ptr = NULL;
	struct sk_buff *skb;
	//DHTOOLS_LOG_INFO("is called!\n");
	/* create a new netlink msg */
	skb = genlmsg_new(size, GFP_KERNEL);
	if (!skb) {
		DHTOOLS_LOG_ERR("genlmsg_new failed!!!\n");
		return -1;
	}
	/* Add a new netlink message to an skb */
	ptr = genlmsg_put(skb, pid, 0, &zxdh_tools_msg_family, 0, cmd);
	if (!ptr) {
		DHTOOLS_LOG_ERR("genlmsg_put failed!!!\n");
		return -1;
	}
	*skbp = skb;
	return 0;
}

s32 zxdh_tools_genl_msg_mk_usr_msg(struct sk_buff *skb, int type, void *data, int len)
{
	int ret = 0;

	ret = nla_put(skb, type, len, data);
	if (ret != 0) {
		DHTOOLS_LOG_ERR("nla_put failed, ret=%d!!!\n", ret);
		return -1;
	}
	return 0;
}

s32 zxdh_tools_genl_msg_send_to_user(void *data, u16 len, u32 pid)
{
	struct sk_buff *skb;
	u16 size;
	int ret = 0;

	ret = nla_total_size(len);
	if (ret <= 0) {
		DHTOOLS_LOG_ERR("nla_total_size failed, ret=%d!\n", ret);
		return -1;
	}
	size = ret;

	ret = zxdh_tools_genl_msg_prepare_usr_msg(ZXDH_TOOLS_C_ECHO, size, pid, &skb);
	if (ret) {
		DHTOOLS_LOG_ERR("zxdh_tools_genl_msg_prepare_usr_msg failed, ret=%d!!!\n", ret);
		return -1;
	}

	ret = zxdh_tools_genl_msg_mk_usr_msg(skb, ZXDH_TOOLS_A_MSG, data, len);
	if (ret) {
		DHTOOLS_LOG_ERR("zxdh_tools_genl_msg_mk_usr_msg failed, ret=%d!!!\n", ret);
		kfree_skb(skb);
		return -1;
	}

	ret = genlmsg_unicast(&init_net, skb, pid);
	if (ret != 0) {
		struct task_struct *task = NULL;

		task = pid_task(find_vpid(pid), PIDTYPE_PID);
		if (!task)
			DHTOOLS_LOG_ERR("dhtool with pid %d has exited!\n", pid);

		DHTOOLS_LOG_ERR("genlmsg_unicast failed, ret=%d!!!\n", ret);
		return -1;
	}
	return 0;
}

extern struct dhtool_eventpid_devbdf_array eventpid_devbdf_array[MAX_DHTOOL_PID_NUMS];
s32 dhtool_find_eventpid_of_devbdf(u32 dev_bdf, u32 *event_pid)
{
	int i = 0;

	for (i = 0; i < ARRAY_SIZE(eventpid_devbdf_array); i++) {
		if (eventpid_devbdf_array[i].is_valid) {
			if (dev_bdf == eventpid_devbdf_array[i].dev_bdf) {
				*event_pid = eventpid_devbdf_array[i].event_pid;
				return 0;
			}
		}
	}

	DHTOOLS_LOG_ERR("can not found the event_pid of dev_bdf %d.\n", dev_bdf);
	return -1;
}

s32 zxdh_tools_sendto_user_netlink(void *pay_load, u16 len, void *reps_buffer, u16 *reps_len,
				   void *dev)
{
	struct zxdh_en_device *en_dev = (struct zxdh_en_device *)dev;
	s32 ret = 0;
	u32 event_pid = 0;
	struct pci_dev *pdev = NULL;
	u32 domain_no = 0;
	u32 bus_no = 0;
	u32 device_no = 0;
	u32 func_no = 0;
	u32 dev_bdf = 0;

	if (!en_dev) {
		DHTOOLS_LOG_ERR("dev is NULL\n");
		return -1;
	}

	if (en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_VF)
		return 0;

	if ((!pay_load) || (len == 0)) {
		DHTOOLS_LOG_ERR("invalid para, pay_load = 0x%llx, len = %d\n", (u64)pay_load,
				len);
		return -1;
	}

	pdev = en_dev->ops->get_pdev(en_dev->parent);
	if (!pdev) {
		DHTOOLS_LOG_ERR("pdev is NULL\n");
		return -1;
	}

	ret = sscanf(pci_name(pdev), "%x:%x:%x.%u", &domain_no, &bus_no, &device_no, &func_no);
	if (ret != 4) {
		DHTOOLS_LOG_ERR(
			"could not get dev domain_no、bus_no、device_no、func_no from pci_name(pdev)\n");
		return -1;
	}

	dev_bdf = DBDF_ECAM(domain_no, bus_no, device_no, func_no);

	ret = dhtool_find_eventpid_of_devbdf(dev_bdf, &event_pid);
	if (ret != 0)
		return -1;

	if ((*(u32 *)pay_load) == EVENT_OP_CODE_LOG_GET_FINISH_TO_H)

		ret = zxdh_tools_genl_msg_send_to_user(pay_load, len, event_pid);
	if (ret) {
		DHTOOLS_LOG_ERR("zxdh_tools_genl_msg_send_to_user failed, ret=%d!!!\n", ret);
		return -1;
	}

	return 0;
}

s32 zxdh_tools_netlink_register(void)
{
	int ret = 0;

	ret = genl_register_family(&zxdh_tools_msg_family);
	if (ret) {
		DHTOOLS_LOG_ERR("zxdh_tools_netlink_family register failed, ret=%d!!!\n", ret);
		return -1;
	}

	return 0;
}

void zxdh_tools_netlink_unregister(void)
{
	genl_unregister_family(&zxdh_tools_msg_family);
}
