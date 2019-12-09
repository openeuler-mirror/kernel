// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2016-2019 Hisilicon Limited.

#include <linux/module.h>

#ifdef CONFIG_HNS3_TEST
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/netdevice.h>
#include <linux/interrupt.h>
#include <linux/pci.h>
#include <net/sock.h>
#include <net/rtnetlink.h>

#include "hnae3.h"
#include "hns3_enet.h"
#include "hclge_cmd.h"
#include "hclge_main.h"
#include "hns3_cae_lib.h"
#include "hns3_cae_cmd.h"
#include "hns3_cae_tm.h"
#include "hns3_cae_dcb.h"
#include "hns3_cae_pkt.h"
#include "hns3_cae_mac.h"
#include "hns3_cae_dfx.h"
#include "hns3_cae_vlan.h"
#include "hns3_cae_qos.h"
#include "hns3_cae_qinfo.h"
#include "hns3_cae_promisc.h"
#include "hns3_cae_fd.h"
#include "hns3_cae_rss.h"
#include "hns3_cae_common.h"
#include "hns3_cae_qres.h"
#include "hns3_cae_stat.h"
#include "hns3_cae_irq.h"
#include "hns3_cae_lamp.h"
#include "hns3_cae_ext.h"
#include "hns3_cae_pfc_storm.h"
#include "hns3_cae_xsfp.h"
#include "hns3_cae_port.h"
#include "hns3_cae_hilink_param.h"
#include "hns3_cae_version.h"
#include "hns3_cae_checksum.h"
#include "hns3_cae_dcqcn.h"
#include "hns3_cae_reset.h"
#include "hns3_cae_gro.h"
#include "hns3_cae_mactbl.h"

#define MAX_MSG_OUT_SIZE	(1024U * 2048U)
#define MAX_MSG_IN_SIZE		(1024U * 2048U)

static dev_t g_dev_id = {0};

struct class *g_hns3_cae_class;
struct cdev g_hns3_cae_cdev;
static const char hns3_driver_name[] = "hns3";

int g_hns3_cae_init_flag;
int g_hns3_cae_ref_cnt;

typedef int (*driv_module) (struct hns3_nic_priv *nic_dev, void *buf_in,
			    u32 in_size, void *buf_out, u32 out_size);

struct drv_module_handle {
	enum driver_cmd_type driv_cmd_name;
	driv_module driv_func;
};

static void free_buff_in(void *buf_in)
{
	if (!buf_in)
		return;

	kfree(buf_in);
}

static int alloc_buff_in(struct msg_module *nt_msg, u32 in_size, void **buf_in)
{
	void *msg_buf;

	if (!in_size)
		return 0;

	if (in_size > MAX_MSG_IN_SIZE) {
		pr_err("msg in size(%u) more than %u\n",
		       in_size, MAX_MSG_IN_SIZE);
		return -ENOMEM;
	}

	msg_buf = kzalloc((unsigned long)in_size, GFP_KERNEL);
	*buf_in = msg_buf;
	if (ZERO_OR_NULL_PTR(*buf_in)) {
		pr_err("alloc buf_in failed\n");
		return -ENOMEM;
	}

	if (copy_from_user(msg_buf, nt_msg->in_buff, (unsigned long)in_size)) {
		pr_err("Copy from user failed in %s function\n", __func__);
		kfree(msg_buf);
		return -EFAULT;
	}

	return 0;
}

static void free_buff_out(void *buf_out)
{
	if (!buf_out)
		return;

	kfree(buf_out);
}

static int alloc_buff_out(u32 out_size, void **buf_out)
{
	if (!out_size)
		return 0;

	if (out_size > MAX_MSG_OUT_SIZE) {
		pr_err("msg out size(%u) more than %u\n",
		       out_size, MAX_MSG_OUT_SIZE);
		return -ENOMEM;
	}

	*buf_out = kzalloc((unsigned long)out_size, GFP_KERNEL);
	if (ZERO_OR_NULL_PTR(*buf_out)) {
		pr_err("alloc buf_out failed\n");
		return -ENOMEM;
	}

	return 0;
}

static int copy_buf_out_to_user(struct msg_module *nt_msg, u32 out_size,
				void **buf_out)
{
	int ret = 0;
	void *msg_out = buf_out;

	if (copy_to_user(nt_msg->out_buf, msg_out, out_size))
		ret = -EFAULT;

	return ret;
}

static int hns3_cae_netdev_match_check(struct net_device *netdev)
{
	struct ethtool_drvinfo drv_info;

	if (netdev->ethtool_ops->get_drvinfo)
		netdev->ethtool_ops->get_drvinfo(netdev, &drv_info);

	if (!strncmp(drv_info.driver, hns3_driver_name,
		     strlen(hns3_driver_name)))
		return 0;

	netdev_err(netdev, "match hns3 driver name(%s) failed\n",
		   drv_info.driver);
	return -1;
}

#if (KERNEL_VERSION(4, 16, 0) < LINUX_VERSION_CODE)
static int kernel_sock_ioctl(struct socket *sock, int cmd, unsigned long arg)
{
	mm_segment_t oldfs = get_fs();
	int err;

	set_fs(KERNEL_DS);
	err = sock->ops->ioctl(sock, cmd, arg);
	set_fs(oldfs);

	return err;
}
#endif

static struct net_device *get_netdev_by_ifname(char *ifname)
{
	struct socket *temp_sock = NULL;
	struct net_device *netdev = NULL;
	struct ifreq ifr;
	int err;

	err = sock_create(PF_INET, SOCK_DGRAM, 0, &temp_sock);
	if (err < 0) {
		pr_err("fail to enter sock_create, err = %d\n", err);
		return NULL;
	}

	strncpy(ifr.ifr_ifrn.ifrn_name, ifname, (unsigned long)IFNAMSIZ);
	kernel_sock_ioctl(temp_sock, SIOCSIFNAME, (unsigned long)&ifr);
	netdev = dev_get_by_name(sock_net(temp_sock->sk), ifname);
	if (!netdev)
		goto out;

	dev_put(netdev);

out:
	sock_release(temp_sock);
	return netdev;
}

static int hns3_cae_k_get_netdev_by_ifname(char *ifname,
					   struct hns3_nic_priv **nic_dev)
{
	struct net_device *netdev = NULL;

	netdev = get_netdev_by_ifname(ifname);
	if (!netdev) {
		pr_err("not find the netdevice(%s)!\n", ifname);
		return -EFAULT;
	}

	if (hns3_cae_netdev_match_check(netdev)) {
		netdev_err(netdev, "netdevice is not hns device.\n");
		return -EFAULT;
	}

	*nic_dev = (struct hns3_nic_priv *)netdev_priv(netdev);
	if (!(*nic_dev)) {
		netdev_err(netdev, "no private data\n");
		return -EFAULT;
	}

	return 0;
}

struct drv_module_handle driv_module_cmd_handle[] = {
	{FW_VER, hns3_cae_get_fw_ver},
	{DRIVER_VER, hns3_cae_get_driver_ver},
	{CHECKSUM_CFG, hns3_cae_chs_cfg},
	{TM_QUEUE_CFG, hns3_cae_queue_cfg},
	{TM_QSET_CFG, hns3_cae_qs_cfg},
	{TM_PRI_CFG, hns3_cae_pri_cfg},
	{TM_PG_CFG, hns3_cae_pg_cfg},
	{TM_PORT_CFG, hns3_cae_port_cfg},
	{TM_ETS_CFG, hns3_cae_ets_cfg},
	{DCB_MODE_CFG, hns3_cae_dcb_cfg},
	{ETS_MODE_CFG, hns3_cae_dcb_ets_cfg},
	{PFC_MODE_CFG, hns3_cae_dcb_pfc_cfg},
	{MAC_LOOP_CFG, hns3_cae_mac_loop_cfg},
	{DFX_INFO_CMD, hns3_cae_get_dfx_info},
	{DFX_READ_CMD, hns3_cae_read_dfx_info},
	{EVENT_INJECTION_CMD, hns3_cae_event_injection},
	{SEND_PKT, hns3_cae_send_pkt},
	{RX_PRIV_BUFF_WL_CFG, hns3_cae_rx_priv_buff_wl_cfg},
	{RX_COMMON_THRD_CFG, hns3_cae_common_thrd_cfg},
	{RX_COMMON_WL_CFG, hns3_cae_common_wl_cfg},
	{SHOW_RX_PRIV_WL, hns3_cae_show_rx_priv_wl},
	{SHOW_RX_COMM_THRES, hns3_cae_show_comm_thres},
	{QCN_EN_CFG, hns3_cae_qcn_cfg},
	{RX_BUFF_CFG, hns3_cae_rx_buff_cfg},
	{TX_BUFF_CFG, hns3_cae_tx_buff_cfg},
	{RESET_CFG, hns3_cae_nic_reset},
	{TIMEOUT_CFG, hns3_cae_nic_timeout_cfg},
	{PROMISC_MODE_CFG, hns3_promisc_mode_cfg},
	{QINFO_CFG, hns3_cae_qinfo_cfg},
#ifdef CONFIG_IT_VALIDATION
	{MACTABLE_CFG, hns3_cae_opt_mactbl},
#endif
	{CLEAN_STATS, hns3_cae_clean_stats},
	{FD_CFG, hns3_cae_fd_cfg},
	{RSS_GENERIC_CFG, hns3_cae_rss_cfg},
	{REG_CFG, hns3_cae_reg_cfg},
	{COM_REG_CFG, hns3_cae_common_cmd_send},
	{GRO_CFG, hns3_gro_age_handle},
	{M7_CMD_MODE_CFG, hns3_m7_cmd_handle},
	{QRES_CFG, hns3_cae_qres_cfg},
	{STAT_CFG, hns3_stat_mode_cfg},
	{IRQ_CFG, hns3_irq_lli_cfg},
	{VLAN_UPMAPPING, hns3_cae_upmapping_cfg},
#ifdef CONFIG_EXT_TEST
	{LAMP_CFG, hns3_lamp_cfg},
	{EXTERN_INTERFACE_CFG, hns3_ext_interface_test},
#else
	{EXTERN_INTERFACE_CFG, hns3_cae_pfc_storm_cfg},
#endif
	{XSFP_CFG, hns3_xsfp_cfg},
	{SHOW_PORT_INFO, hns3_get_port_info},
	{SHOW_HILINK_PARAM, hns3_get_hilink_param},
	{DCQCN_PARM_CFG, hns3_nic_dcqcn},
	{DCQCN_GET_MSG_CNT_CMD, hns3_dcqcn_get_msg_cnt}
};

static int send_to_driver(struct hns3_nic_priv *nic_dev,
			  struct msg_module *nt_msg,
			  void *buf_in, u32 in_size,
			  void *buf_out, u32 out_size)
{
	u32 num_cmds = ARRAY_SIZE(driv_module_cmd_handle);
	enum driver_cmd_type cmd_type =
	    (enum driver_cmd_type)(nt_msg->msg_formate);
	driv_module fn;
	int err = -EOPNOTSUPP;
	u32 index;

	for (index = 0; index < num_cmds; index++) {
		if (cmd_type == driv_module_cmd_handle[index].driv_cmd_name) {
			fn = driv_module_cmd_handle[index].driv_func;
			err = fn(nic_dev, buf_in, in_size, buf_out, out_size);
			break;
		}
	}

	return err;
}

static long hns3_cae_k_unlocked_ioctl(struct file *pfile, unsigned int cmd,
				      unsigned long arg)
{
	struct hns3_nic_priv *nic_dev = NULL;
	struct msg_module nt_msg;
	void *buf_out = NULL;
	void *buf_in = NULL;
	u32 out_size;
	u32 in_size;
	int cmd_raw;
	int ret;

	memset(&nt_msg, 0, sizeof(nt_msg));

	if (copy_from_user(&nt_msg, (void *)arg, sizeof(nt_msg))) {
		pr_err("copy from user failed in unlocked_ioctl function\n");
		return -EFAULT;
	}

	cmd_raw = nt_msg.module;
	out_size = nt_msg.len_info.out_buff_len;
	in_size = nt_msg.len_info.in_buff_len;

	ret = alloc_buff_in(&nt_msg, in_size, &buf_in);
	if (ret) {
		pr_err("alloc in buffer failed\n");
		return -EFAULT;
	}

	ret = alloc_buff_out(out_size, &buf_out);
	if (ret) {
		pr_err("alloc out buffer failed\n");
		goto out_free_buf_in;
	}
#ifndef CONFIG_EXT_TEST
	/**
	 * After decoupling with driver, the scenario of hns driver unregister
	 * must be considered. In this scenario, driver unregister may happened
	 * between hns3_cae_k_get_netdev_by_ifname and send_to_driver,
	 * which may cause access null pointer or other exception.
	 * When CONFIG_EXT_TEST was defined, we haven't decoupled the tool
	 * code yet, so we don't need lock.
	 */
	rtnl_lock();
#endif
	ret = hns3_cae_k_get_netdev_by_ifname(nt_msg.device_name, &nic_dev);
	if (ret) {
		pr_err("can not get the netdevice correctly\n");
		ret = -EINVAL;
		goto out_invalid;
	}

	if (nic_dev->ae_handle->flags & HNAE3_SUPPORT_VF) {
		pr_err("VF is not supported.\n");
		ret = -EINVAL;
		goto out_invalid;
	}

	switch (cmd_raw) {
	case SEND_TO_DRIVER:
		ret = send_to_driver(nic_dev, &nt_msg, buf_in, in_size, buf_out,
				     out_size);
		if (ret) {
			pr_err("send buffer to driver failed, ret = %d\n", ret);
			goto out_invalid;
		}
		break;
	default:
		pr_err("module err!\n");
		ret = -EINVAL;
		goto out_invalid;
	}
#ifndef CONFIG_EXT_TEST
	rtnl_unlock();
#endif
	ret = copy_buf_out_to_user(&nt_msg, out_size, buf_out);
	if (ret)
		pr_err("copy buf to user failed\n");
	goto out_free_buf_out;

out_invalid:
#ifndef CONFIG_EXT_TEST
	rtnl_unlock();
#endif
out_free_buf_out:
	free_buff_out(buf_out);
out_free_buf_in:
	free_buff_in(buf_in);

	return (long)ret;
}

static int hns3_cae_k_open(struct inode *pnode, struct file *pfile)
{
	return 0;
}

static ssize_t hns3_cae_k_read(struct file *pfile, char __user *ubuf,
			       size_t size, loff_t *ppos)
{
	pr_info("%s read *ppos:%lld size = %d\n", __func__, *ppos, (int)size);
	return 0;
}

static ssize_t hns3_cae_k_write(struct file *pfile, const char __user *ubuf,
				size_t size, loff_t *ppos)
{
	pr_info("%s write *ppos:%lld size = %d\n", __func__, *ppos, (int)size);
	return 0;
}

static int hns3_cae_k_mmap(struct file *filp, struct vm_area_struct *vma)
{
	int ret;

	vma->vm_flags |= VM_IO;
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	ret = remap_pfn_range(vma, vma->vm_start, vma->vm_pgoff,
			      vma->vm_end - vma->vm_start, vma->vm_page_prot);
	if (ret)
		return -EIO;

	return 0;
}

static const struct file_operations fifo_operations = {
	.owner = THIS_MODULE,
	.open = hns3_cae_k_open,
	.read = hns3_cae_k_read,
	.write = hns3_cae_k_write,
	.unlocked_ioctl = hns3_cae_k_unlocked_ioctl,
	.mmap = hns3_cae_k_mmap,
};

static int if_hns3_cae_exist(void)
{
	struct file *fp = NULL;
	int exist = 0;

	fp = filp_open("/dev/nic_dev", O_RDONLY, 0);
	if (IS_ERR(fp)) {
		exist = 0;
	} else {
		(void)filp_close(fp, NULL);
		exist = 1;
	}

	return exist;
}

static int hns3_cae_k_init(void)
{
	int ret;
	struct device *pdevice;

	if (g_hns3_cae_init_flag) {
		g_hns3_cae_ref_cnt++;
		return 0;
	}

	if (if_hns3_cae_exist()) {
		pr_info("dev/nic_dev is existed!\n");
		return 0;
	}

	ret = alloc_chrdev_region(&g_dev_id, 0, 1, "nic_dev");
	if (ret < 0) {
		pr_err("alloc_chrdev_region fail, ret = %d.\n", ret);
		return ret;
	}

	g_hns3_cae_class = class_create(THIS_MODULE, "nic_class");
	if (IS_ERR(g_hns3_cae_class)) {
		pr_err("class create fail.\n");
		ret = -EFAULT;
		goto class_create_err;
	}

	cdev_init(&g_hns3_cae_cdev, &fifo_operations);
	ret = cdev_add(&g_hns3_cae_cdev, g_dev_id, 1);
	if (ret < 0) {
		pr_err("cdev_add fail, ret = %d.\n", ret);
		goto cdev_add_err;
	}

	pdevice = device_create(g_hns3_cae_class, NULL, g_dev_id, NULL,
				"nic_dev");
	if (IS_ERR(pdevice)) {
		pr_err("device_create fail.\n");
		ret = -EPERM;
		goto device_create_err;
	}

	g_hns3_cae_init_flag = 1;
	g_hns3_cae_ref_cnt = 1;
	pr_info("register hns3_cae_dev to system, ok!\n");

	return 0;

device_create_err:
	cdev_del(&g_hns3_cae_cdev);

cdev_add_err:
	class_destroy(g_hns3_cae_class);

class_create_err:
	g_hns3_cae_class = NULL;
	unregister_chrdev_region(g_dev_id, 1);

	return ret;
}

static void hns3_cae_k_uninit(void)
{
	if (g_hns3_cae_init_flag) {
		if ((--g_hns3_cae_ref_cnt))
			return;
	}

	if (!g_hns3_cae_class || IS_ERR(g_hns3_cae_class))
		return;

	cdev_del(&g_hns3_cae_cdev);
	device_destroy(g_hns3_cae_class, g_dev_id);
	class_destroy(g_hns3_cae_class);
	g_hns3_cae_class = NULL;
	unregister_chrdev_region(g_dev_id, 1);
	pr_info("unregister hns3_cae_dev ok!\n");
}
#endif

static int __init hns3_cae_init(void)
{
#ifdef CONFIG_HNS3_TEST
	int ret;

	pr_err("%s enter!\n", __func__);

	ret = hns3_cae_k_init();
	if (ret)
		return ret;
#endif
	return 0;
}

static void __exit hns3_cae_exit(void)
{
#ifdef CONFIG_HNS3_TEST
	pr_err("%s exit!\n", __func__);
	hns3_cae_k_uninit();
#endif
}

module_init(hns3_cae_init);
module_exit(hns3_cae_exit);
MODULE_LICENSE("GPL");
