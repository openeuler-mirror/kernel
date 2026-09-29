// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024-2026 Mucse Corporation. */

#include "mce.h"
#include "mce_base.h"
#include "mce_irq.h"
#include "mce_lib.h"
#include "mce_netdev.h"
#include "mce_txrx_lib.h"
#if IS_ENABLED(CONFIG_SYSFS)
#include <linux/module.h>
#include <linux/types.h>
#include <linux/hwmon.h>
#include <linux/hwmon-sysfs.h>
#include <linux/ctype.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/device.h>
#include <linux/netdevice.h>
#include <linux/time.h>
#include "mce_vf_lib.h"
#include "mce_fwchnl.h"
#include "mce_virtchnl.h"
#include "mucse_auxiliary/mce_idc.h"
#include "mce_n20/mce_hw_n20.h"
#include "mce_dcbnl.h"

#define to_pci_device(n) container_of(n, struct pci_dev, dev)
#define to_net_device(n) container_of(n, struct net_device, dev)

static struct mce_pf *mce_sysfs_dev_to_pf(struct device *dev)
{
	struct net_device *netdev = mce_device_to_netdev(dev);

	return mce_netdev_to_pf(netdev);
}

static void mce_hwmon_exit(struct mce_pf *pf)
{
}

static int mce_hwmon_init(struct mce_pf *pf)
{
	return 0;
}

static ssize_t cdev_name_show(struct device *dev, struct device_attribute *attr,
			      char *buf)
{
	struct mce_pf *pf = mce_sysfs_dev_to_pf(dev);
	int ret = 0;

	ret += sprintf(buf, "%s", pf->name);
	buf[ret] = 0;

	return ret;
}

static void to_binary(u16 num, char *binary_str, int bits)
{
	int i;

	for (i = bits - 1; i >= 0; i--)
		binary_str[bits - 1 - i] = (num & (1 << i)) ? '1' : '0';

	binary_str[bits] = '\0';
}

static ssize_t nic_prio_show(struct device *dev, struct device_attribute *attr,
			     char *buf)
{
	struct mce_pf *pf = mce_sysfs_dev_to_pf(dev);
	struct mce_vsi *vsi = mce_get_main_vsi(pf);
	char string[30];
	int ret = 0;

	to_binary(vsi->valid_prio, string, 8);

	ret = sprintf(buf, " nic prio %s\n", string);
	return ret;
}

static ssize_t nic_prio_store(struct device *dev, struct device_attribute *attr,
			      const char *buf, size_t count)
{
	struct mce_pf *pf = mce_sysfs_dev_to_pf(dev);
	struct iidc_core_dev_info *cdev_info = pf->cdev_infos;
	struct mce_vsi *vsi = mce_get_main_vsi(pf);
	struct net_device *netdev;
	struct iidc_event *event;
	u16 valid = 0;

	netdev = mce_get_main_net_dev(pf);

	if (kstrtos16(buf, 2, &valid))
		return -EINVAL;
	/* should never 0 */
	if (valid == 0)
		return -EINVAL;
	/* if all zero, should return */
	if ((valid & 0xff) == 0)
		return -EINVAL;
	if (!cdev_info)
		return -ENODEV;
	/* if mrdma driver on, we must reseve prio7 */
	if (pf->m_status == MRDMA_INSMOD) {
		if (valid & 0x80) {
			dev_err(mce_pf_to_dev(pf),
				"never use prio 7 if MRDMA_INSMOD\n");
			return -EINVAL;
		}
	}

	vsi->valid_prio = valid & 0xff;
	/* nic valid prio, should mask rdma, not use prio7 */
	cdev_info->valid_prio = (~vsi->valid_prio) & 0x7f;

	mce_force_close_dcb(pf);
	event = kzalloc(sizeof(*event), GFP_KERNEL);

	set_bit(IIDC_EVENT_PRIO_CHNG, event->type);
	mce_send_event_to_auxs(pf, event);
	kfree(event);
	/* echo all valid_prio to all vfs */
	mce_recover_dcb(pf);
	mce_reset_vf(netdev);

	return count;
}

static ssize_t rdma_prio_show(struct device *dev, struct device_attribute *attr,
			      char *buf)
{
	struct mce_pf *pf = mce_sysfs_dev_to_pf(dev);
	struct iidc_core_dev_info *cdev_info = pf->cdev_infos;
	char string[30];
	int ret = 0;

	if (!cdev_info)
		return -ENODEV;

	to_binary(cdev_info->valid_prio, string, 8);

	ret = sprintf(buf, "rdma prio %s\n", string);
	return ret;
}

static ssize_t rdma_prio_store(struct device *dev,
			       struct device_attribute *attr, const char *buf,
			       size_t count)
{
	struct mce_pf *pf = mce_sysfs_dev_to_pf(dev);
	struct iidc_core_dev_info *cdev_info = pf->cdev_infos;
	struct mce_vsi *vsi = mce_get_main_vsi(pf);
	struct net_device *netdev;
	struct iidc_event *event;
	u16 valid = 0;

	netdev = mce_get_main_net_dev(pf);
	if (!cdev_info)
		return -ENODEV;

	if (kstrtos16(buf, 2, &valid))
		return -EINVAL;
	if (valid == 0xff)
		return -EINVAL;
	if (valid == 0x7f) {
		dev_err(mce_pf_to_dev(pf), "at least 1 for nic\n");
		return -EINVAL;
	}

	if (valid & 0x80) {
		dev_err(mce_pf_to_dev(pf),
			"never use prio 7, reserved for qp1\n");
		return -EINVAL;
	}

	cdev_info->valid_prio = valid & 0xff;

	vsi->valid_prio = (~cdev_info->valid_prio);

	/* if mrdma insmod, should never use prio7 */
	if (pf->m_status == MRDMA_INSMOD)
		vsi->valid_prio &= 0x7f;

	mce_force_close_dcb(pf);
	event = kzalloc(sizeof(*event), GFP_KERNEL);

	set_bit(IIDC_EVENT_PRIO_CHNG, event->type);
	mce_send_event_to_auxs(pf, event);
	kfree(event);
	mce_recover_dcb(pf);
	mce_reset_vf(netdev);

	return count;
}

static ssize_t rqa_tcpsync_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct mce_pf *pf = mce_sysfs_dev_to_pf(dev);
	struct mce_hw *hw = &pf->hw;
	struct mce_vf *vf = NULL;
	int vfidx = 0, ret = 0;
	int cnt = 0;
	int vfnum;

	vf = mce_pf_to_vf(pf);

	if (!vf->vfinfo) {
		if (!test_bit(MCE_FLAG_SRIOV_ENA, pf->flags)) {
			ret += sprintf(buf + ret,
				"No pf or vf rules have been setuped!\n");
			return ret;
		}
		ret += sprintf(buf + ret,
			       "error: vfinfo is NULL, show none!\n");
		return ret;
	}

	mce_for_each_pf_vf_id(pf, vfidx) {
		if (!vf->vfinfo[vfidx].tcpsync.valid)
			continue;
		if (test_bit(MCE_FLAG_SRIOV_ENA, pf->flags))
			vfnum = (vfidx == PFINFO_IDX) ? -1 : vfidx;
		else
			vfnum = -1;
		ret += sprintf(buf + ret, "vf:%d rid:%d pri:%d drop:%d\n", vfnum,
			vf->vfinfo[vfidx].tcpsync.pri.bits.ring_num,
			vf->vfinfo[vfidx].tcpsync.acl.bits.sync_tuple_pri,
			vf->vfinfo[vfidx].tcpsync.pri.bits.drop);
		cnt++;
	}

	if (!cnt)
		ret += sprintf(buf + ret,
			       "No pf or vf rules have been setuped!\n");
	return ret;
}

static ssize_t rqa_tcpsync_store(struct device *dev,
				 struct device_attribute *attr, const char *buf,
				 size_t count)
{
	struct mce_pf *pf = mce_sysfs_dev_to_pf(dev);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	struct mce_vsi *vsi = pf->vsi[0];
	struct mce_hw *hw = &pf->hw;
	struct net_device *netdev;
	int cnt, set, vfnum;
	int sync_tuple_pri;
	int ring_num;
	int drop;

	netdev = mce_get_main_net_dev(pf);
	/**
	 * set|clear + vfnum + ring_num + sync_tuple_pri + drop
	 * vfnum: in this command, the vfnum of pf is -1,
	 * the vfnum of vf need plus 1.
	 * sync_tuple_pri: 1 tcpsync prio large then tuple
	 */
	cnt = sscanf(buf, "%d %d %d %d %d", &set, &vfnum, &ring_num,
		     &sync_tuple_pri, &drop);
	if (cnt != 5)
		return -EINVAL;

	if (vfnum >= pf->num_vfs || vfnum < -1)
		return -EINVAL;

	if (test_bit(MCE_FLAG_SRIOV_ENA, pf->flags)) {
		if (!vf->vfinfo)
			return -EINVAL;
		if (vfnum == -1) {
			vfnum = PFINFO_IDX;
			if (ring_num >= vsi->num_rxq) {
				netdev_warn(netdev,
					    "Tcpsync redir ring cannot exceed pf ring nums:%d\n",
					vsi->num_rxq);
				return -EINVAL;
			}
		} else {
			if (mce_check_vf_no_ready_for_cfg(&vf->vfinfo[vfnum])) {
				netdev_warn(netdev,
					    "Tcpsync vf:%d cannot config, maybe vf not probed.\n",
					vfnum);
				return -EINVAL;
			}

			if (ring_num >= vf->vfinfo[vfnum].ring_cnt) {
				netdev_warn(netdev,
					    "Tcpsync redir ring cannot exceed vf:%d ring nums:%d\n",
					vfnum, vf->vfinfo[vfnum].ring_cnt);
				return -EINVAL;
			}
		}
	} else {
		vf->vfinfo = &pf->pfinfo;
		vfnum = 0;
		if (ring_num >= vsi->num_rxq) {
			netdev_warn(netdev,
				    "Tcpsync redir ring cannot exceed pf ring nums:%d\n",
				vsi->num_rxq);
			return -EINVAL;
		}
	}

	memset(&vf->vfinfo[vfnum].tcpsync, 0, sizeof(struct mce_tcpsync));
	if (!!set) {
		vf->vfinfo[vfnum].tcpsync.acl.bits.enum_en = !!set;
		vf->vfinfo[vfnum].tcpsync.acl.bits.sync_tuple_pri =
			!!sync_tuple_pri;
		vf->vfinfo[vfnum].tcpsync.pri.bits.ring_num = ring_num;
		vf->vfinfo[vfnum].tcpsync.pri.bits.ring_valid = 1;
		vf->vfinfo[vfnum].tcpsync.pri.bits.drop = !!drop;
	}
	vf->vfinfo[vfnum].tcpsync.valid = !!set;

	if (!test_bit(MCE_FLAG_SRIOV_ENA, pf->flags)) {
		if (!!set)
			set_bit(MCE_FLAG_PF_RQA_TCPSYNC_ENA, pf->flags);
		else
			clear_bit(MCE_FLAG_PF_RQA_TCPSYNC_ENA, pf->flags);
	}

	hw->vf.ops->set_vf_rqa_tcp_sync_remapping(hw, vfnum,
						  &vf->vfinfo[vfnum].tcpsync);
	return count;
}

static void do_pma_rx2tx_loopback(struct mce_hw *hw, int en)
{
	if (en) {
		if (hw->is_sgmii) {
			/* 0x1f */
			wr32(hw, CESOC_LP_RESET,
			     MII_LP_RX_TO_TX_FIFO_RESET | PMA_LOOPBACK_RESET);

			wr32(hw, CESOC_LP_EN,
			     (31 << 16) /* mii loopback rx fifo */
				     | MII_RX2TX_EN);

			/* 0x10 */
			wr32(hw, CESOC_LP_RESET,
			     MII_LP_RX_TO_TX_FIFO_RESET |
				     PMA_LOOPBACK_RESET_RELEASE);
		} else {
			pma_iowrite16(hw, SERDES_LOOPBACK_FIFO, 0x8000);
		}
	} else {
		if (hw->is_sgmii)
			wr32(hw, CESOC_LP_EN, 0);
		else
			pma_iowrite16(hw, SERDES_LOOPBACK_FIFO, 0);
	}
}

static ssize_t pma_rx2tx_loopback_store(struct device *dev,
					struct device_attribute *attr,
					const char *buf, size_t count)
{
	struct mce_pf *pf = mce_sysfs_dev_to_pf(dev);
	struct net_device *netdev = mce_get_main_net_dev(pf);
	struct mce_hw *hw = &pf->hw;
	s32 en;

	if (kstrtos32(buf, 10, &en))
		return -EINVAL;

	do_pma_rx2tx_loopback(hw, en);

	netdev_info(netdev, "%s:%s pma rx2tx loopback:%d\n", __func__,
		    netdev->name, en);

	return count;
}

static void do_pcs_tx2rx_loopback(struct mce_hw *hw, int en)
{
	if (en) {
		/* 0x1f */
		wr32(hw, CESOC_LP_RESET,
		     MII_LP_RX_TO_TX_FIFO_RESET | PMA_LOOPBACK_RESET);

		if (hw->is_sgmii) {
			wr32(hw, CESOC_LP_EN, MII_TX2RX_EN);
		} else {
			/* 0x1f */
			wr32(hw, CESOC_LP_EN,
			     MII_LOOPBACK_RX_USE_TX_CLK | PMA_LOOPBACK_ENABLE);
		}
		/* 0x10 */
		wr32(hw, CESOC_LP_RESET,
		     MII_LP_RX_TO_TX_FIFO_RESET | PMA_LOOPBACK_RESET_RELEASE);
	} else {
		wr32(hw, CESOC_LP_EN, 0);
	}
}

static ssize_t pcs_tx2rx_loopback_store(struct device *dev,
					struct device_attribute *attr,
					const char *buf, size_t count)
{
	struct mce_pf *pf = mce_sysfs_dev_to_pf(dev);
	struct net_device *netdev = mce_get_main_net_dev(pf);
	struct mce_hw *hw = &pf->hw;
	s32 en;

	if (kstrtos32(buf, 10, &en))
		return -EINVAL;

	do_pcs_tx2rx_loopback(hw, en);

	netdev_info(netdev, "%s:%s pcs tx2rx loopback:%d\n", __func__,
		    netdev->name, en);

	return count;
}

static void do_mac_tx2rx_loopback(struct mce_hw *hw, int en)
{
	u32 v;

	if (en) {
		v = rd32(hw, N20_M_CFG);
		v |= BIT(3);
		wr32(hw, N20_M_CFG, v);
	} else {
		v = rd32(hw, N20_M_CFG);
		v &= ~BIT(3);
		wr32(hw, N20_M_CFG, v);
	}
}

static ssize_t mac_tx2rx_loopback_store(struct device *dev,
					struct device_attribute *attr,
					const char *buf, size_t count)
{
	struct mce_pf *pf = mce_sysfs_dev_to_pf(dev);
	struct net_device *netdev = mce_get_main_net_dev(pf);
	struct mce_hw *hw = &pf->hw;
	s32 en = 0;

	if (kstrtos32(buf, 10, &en))
		return -EINVAL;

	do_mac_tx2rx_loopback(hw, en);

	netdev_info(netdev, "%s:%s mac tx2rx loopback:%d\n", __func__,
		    netdev->name, en);

	return count;
}

static ssize_t vf_true_promisc_show(struct device *dev,
				    struct device_attribute *attr, char *buf)
{
	struct mce_pf *pf = mce_sysfs_dev_to_pf(dev);
	struct mce_vf *vf = NULL;
	int vfidx = 0, ret = 0;

	vf = mce_pf_to_vf(pf);
	if (!vf || !vf->vfinfo) {
		ret += sprintf(buf + ret, "error: vfinfo is NULL\n");
		return ret;
	}
	mce_for_each_pf_vf_id(pf, vfidx) {
		ret += sprintf(buf + ret, "vfnum: %d enable: %d\n", vfidx,
			       vf->vfinfo[vfidx].vf_true_promsic_en);
	}

	return ret;
}

static ssize_t vf_true_promisc_store(struct device *dev,
				     struct device_attribute *attr,
				     const char *buf, size_t count)
{
	struct mce_pf *pf = mce_sysfs_dev_to_pf(dev);
	struct mce_vf *vf = mce_pf_to_vf(pf);
	struct mce_hw *hw = &pf->hw;
	int cnt, set, vfnum;

	/* set|clear + vfnum */
	cnt = sscanf(buf, "%d %d", &set, &vfnum);
	if (cnt != 2)
		return -EINVAL;

	if (vfnum >= pf->num_vfs || vfnum < -1)
		return -EINVAL;

	if (!vf || !vf->vfinfo)
		return -EINVAL;

	vf->vfinfo[vfnum].vf_true_promsic_en = !!set;
	hw->vf.ops->set_vf_true_promisc(hw, vfnum,
					vf->vfinfo[vfnum].vf_true_promsic_en);
	return count;
}

static ssize_t rss_mode_order_show(struct device *dev,
				   struct device_attribute *attr, char *buf)
{
	struct mce_pf *pf = mce_sysfs_dev_to_pf(dev);
	int ret = 0;
	bool on;

	on = !!test_bit(MCE_FLAG_PF_RSS_MODE_ORDER, pf->flags);
	ret += sprintf(buf, "rss mode order: %s\n", on ? "yes" : "no");
	return ret;
}

static ssize_t rss_mode_order_store(struct device *dev,
				    struct device_attribute *attr,
				    const char *buf, size_t count)
{
	struct mce_pf *pf = mce_sysfs_dev_to_pf(dev);
	struct mce_hw *hw = &pf->hw;
	struct net_device *netdev;
	int on;

	if (kstrtos32(buf, 10, &on))
		return -EINVAL;

	if (!!on)
		set_bit(MCE_FLAG_PF_RSS_MODE_ORDER, pf->flags);
	else
		clear_bit(MCE_FLAG_PF_RSS_MODE_ORDER, pf->flags);
	netdev = mce_get_main_net_dev(pf);
	hw->ops->set_rss_hash(hw, netdev->features);
	return count;
}

#define MCE_SYSFS_RSS_MISC_TYPE_PTP_BIT_MSK BIT(0)
#define MCE_SYSFS_RSS_MISC_TYPE_IPV4_SPI_BIT_MSK BIT(1)
#define MCE_SYSFS_RSS_MISC_TYPE_IPV6_SPI_BIT_MSK BIT(2)
#define MCE_SYSFS_RSS_MISC_TYPE_IPV4_TEID_BIT_MSK BIT(3)
#define MCE_SYSFS_RSS_MISC_TYPE_IPV6_TEID_BIT_MSK BIT(4)

static ssize_t rss_misc_type_show(struct device *dev,
				  struct device_attribute *attr, char *buf)
{
	struct mce_pf *pf = mce_sysfs_dev_to_pf(dev);
	int ret = 0;
	bool on;

	ret += sprintf(buf + ret, "rss misc type bitmask:\n");
	ret += sprintf(buf + ret, "\tptp:       bit0\n");
	ret += sprintf(buf + ret, "\tipv4 spi:  bit1\n");
	ret += sprintf(buf + ret, "\tipv6 spi:  bit2\n");
	ret += sprintf(buf + ret, "\tipv4 teid: bit3\n");
	ret += sprintf(buf + ret, "\tipv6 teid: bit4\n");

	ret += sprintf(buf + ret, "\nrss misc type status:\n");
	on = !!test_bit(MCE_FLAG_RSS_MISC_TYPE_PTP, pf->flags);
	ret += sprintf(buf + ret, "ptp: %s\n", on ? "yes" : "no");

	on = !!test_bit(MCE_FLAG_RSS_MISC_TYPE_IPV4_SPI, pf->flags);
	ret += sprintf(buf + ret, "ipv4 spi: %s\n", on ? "yes" : "no");

	on = !!test_bit(MCE_FLAG_RSS_MISC_TYPE_IPV6_SPI, pf->flags);
	ret += sprintf(buf + ret, "ipv6 spi: %s\n", on ? "yes" : "no");

	on = !!test_bit(MCE_FLAG_RSS_MISC_TYPE_IPV4_TEID, pf->flags);
	ret += sprintf(buf + ret, "ipv4 teid: %s\n", on ? "yes" : "no");

	on = !!test_bit(MCE_FLAG_RSS_MISC_TYPE_IPV6_TEID, pf->flags);
	ret += sprintf(buf + ret, "ipv6 teid: %s\n", on ? "yes" : "no");
	return ret;
}

static ssize_t rss_misc_type_store(struct device *dev,
				   struct device_attribute *attr,
				   const char *buf, size_t count)
{
	struct mce_pf *pf = mce_sysfs_dev_to_pf(dev);
	struct mce_hw *hw = &pf->hw;
	int bit_msk;

	if (kstrtos32(buf, 10, &bit_msk))
		return -EINVAL;

	if (bit_msk & MCE_SYSFS_RSS_MISC_TYPE_PTP_BIT_MSK)
		set_bit(MCE_FLAG_RSS_MISC_TYPE_PTP, pf->flags);
	else
		clear_bit(MCE_FLAG_RSS_MISC_TYPE_PTP, pf->flags);

	if (bit_msk & MCE_SYSFS_RSS_MISC_TYPE_IPV4_SPI_BIT_MSK)
		set_bit(MCE_FLAG_RSS_MISC_TYPE_IPV4_SPI, pf->flags);
	else
		clear_bit(MCE_FLAG_RSS_MISC_TYPE_IPV4_SPI, pf->flags);

	if (bit_msk & MCE_SYSFS_RSS_MISC_TYPE_IPV6_SPI_BIT_MSK)
		set_bit(MCE_FLAG_RSS_MISC_TYPE_IPV6_SPI, pf->flags);
	else
		clear_bit(MCE_FLAG_RSS_MISC_TYPE_IPV6_SPI, pf->flags);

	if (bit_msk & MCE_SYSFS_RSS_MISC_TYPE_IPV4_TEID_BIT_MSK)
		set_bit(MCE_FLAG_RSS_MISC_TYPE_IPV4_TEID, pf->flags);
	else
		clear_bit(MCE_FLAG_RSS_MISC_TYPE_IPV4_TEID, pf->flags);

	if (bit_msk & MCE_SYSFS_RSS_MISC_TYPE_IPV6_TEID_BIT_MSK)
		set_bit(MCE_FLAG_RSS_MISC_TYPE_IPV6_TEID, pf->flags);
	else
		clear_bit(MCE_FLAG_RSS_MISC_TYPE_IPV6_TEID, pf->flags);

	hw->ops->set_rss_hash_type(hw);
	return count;
}

static ssize_t vf_ipv4_addr_show(struct device *dev,
				 struct device_attribute *attr, char *buf)
{
	struct mce_pf *pf = mce_sysfs_dev_to_pf(dev);
	struct mce_hw *hw = &pf->hw;
	int vfidx, ret = 0;
	struct mce_vf *vf;
	char ip_str[16];

	vf = mce_pf_to_vf(pf);
	if (!vf || !vf->vfinfo)
		return sprintf(buf, "VF info not available (SR-IOV not enabled)\n");

	ret += sprintf(buf + ret, "%-6s %-16s %s\n", "PF", "IPv4", "PF_VLAN");
	if (vf->vfinfo[PFINFO_IDX].vf_ipv4_addr)
		snprintf(ip_str, sizeof(ip_str), "%pI4",
			 &vf->vfinfo[PFINFO_IDX].vf_ipv4_addr);
	else
		snprintf(ip_str, sizeof(ip_str), "N/A");
	ret += sprintf(buf + ret, "%-6s %-16s %u\n", "-", ip_str,
		       vf->vfinfo[PFINFO_IDX].pf_vlan);
	ret += sprintf(buf + ret, "%-6s %-16s %s\n", "VF", "IPv4", "PF_VLAN");
	mce_for_each_vf_id(pf, vfidx) {
		if (vf->vfinfo[vfidx].vf_ipv4_addr)
			snprintf(ip_str, sizeof(ip_str), "%pI4",
				 &vf->vfinfo[vfidx].vf_ipv4_addr);
		else
			snprintf(ip_str, sizeof(ip_str), "N/A");
		ret += sprintf(buf + ret, "%-6d %-16s %u\n", vfidx, ip_str,
			       vf->vfinfo[vfidx].pf_vlan);
	}
	return ret;
}

static ssize_t vf_max_ring_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct mce_pf *pf = mce_sysfs_dev_to_pf(dev);
	struct mce_hw *hw = &pf->hw;
	int ret = 0;

	ret += sprintf(buf + ret, "vf max support ring:%d\n", hw->vf_max_ring);
	return ret;
}

static ssize_t vf_max_ring_store(struct device *dev,
				 struct device_attribute *attr, const char *buf,
				 size_t count)
{
	struct mce_pf *pf = mce_sysfs_dev_to_pf(dev);
	struct net_device *netdev = mce_get_main_net_dev(pf);
	struct mce_hw *hw = &pf->hw;
	int ring_cnt, cnt, err;

	if (test_bit(MCE_FLAG_SRIOV_ENA, pf->flags)) {
		netdev_err(netdev,
			   "need turn off sriov before modify vf max support rings!\n");
		return -EPERM;
	}

	cnt = sscanf(buf, "%d", &ring_cnt);
	if (cnt != 1 || ring_cnt == hw->vf_max_ring) {
		netdev_err(netdev,
			   "params error or new max ring equal to the previous, do nothing.\n");
		return -EINVAL;
	}

	if (!(ring_cnt == 4 || ring_cnt == 8 || ring_cnt == 16 ||
	      ring_cnt == 32 || ring_cnt == 64)) {
		netdev_err(netdev, "new max ring must be 4/8/16/32/64.");
		return -EINVAL;
	}

	err = mce_mbx_set_vf_max_queue_cnt(hw, ring_cnt);
	if (!err)
		hw->vf.ops->init_vf_pcie_totalvfs(hw, hw->vf_max_ring);
	return !!err ? err : count;
}

static ssize_t pxe_enable_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	struct mce_pf *pf = mce_sysfs_dev_to_pf(dev);
	struct mce_hw *hw = &pf->hw;
	int ret = 0;

	hw->ops->update_fw_stat(hw);

	ret += sprintf(buf + ret, "pxe ability:%d, %s, pxe %s\n",
		       hw->fw_stat.stat0.pxe_ablity,
		       hw->fw_stat.stat0.pxe_fw_available ?
			       "pxe firmware available" :
			       "no pxe firmware",
		       hw->fw_stat.stat0.pxe_enabled ? "enabled" : "disabled");
	return ret;
}

static ssize_t pxe_enable_store(struct device *dev,
				struct device_attribute *attr, const char *buf,
				size_t count)
{
	struct mce_pf *pf = mce_sysfs_dev_to_pf(dev);
	struct net_device *netdev = mce_get_main_net_dev(pf);
	int enable_pxe = 1, err;
	struct mce_hw *hw = &pf->hw;

	if (kstrtoint(buf, 10, &enable_pxe) ||
	    (enable_pxe != 0 && enable_pxe != 1)) {
		netdev_err(netdev, "params error: available value: 0 , 1\n");
		return -EINVAL;
	}

	err = mce_mbx_set_dump(hw, 0x01440000 | (enable_pxe ? 1 : 0));
	if (enable_pxe) {
		/* wait 4s for pxe bin sync to flash */
		mdelay(3000);
	}

	return !!err ? err : count;
}

static DEVICE_ATTR_RO(cdev_name);
static DEVICE_ATTR_RW(rqa_tcpsync);
static DEVICE_ATTR_RW(nic_prio);
static DEVICE_ATTR_RW(rdma_prio);
static DEVICE_ATTR_WO(pma_rx2tx_loopback);
static DEVICE_ATTR_WO(pcs_tx2rx_loopback);
static DEVICE_ATTR_WO(mac_tx2rx_loopback);
static DEVICE_ATTR_RW(vf_true_promisc);
static DEVICE_ATTR_RW(rss_mode_order);
static DEVICE_ATTR_RW(rss_misc_type);
static DEVICE_ATTR_RO(vf_ipv4_addr);
static DEVICE_ATTR_RW(vf_max_ring);
static DEVICE_ATTR_RW(pxe_enable);

static struct attribute *qos_dev_attrs[] = {
	NULL,
};

static const struct attribute_group qos_attr_grp = {
	.name = "qos",
	.attrs = qos_dev_attrs,
};

static struct attribute *vendor_dev_attrs[] = {
	&dev_attr_nic_prio.attr,
	&dev_attr_rdma_prio.attr,
	&dev_attr_rqa_tcpsync.attr,
	&dev_attr_cdev_name.attr,
	/*  */
	&dev_attr_pma_rx2tx_loopback.attr,
	&dev_attr_pcs_tx2rx_loopback.attr,
	&dev_attr_mac_tx2rx_loopback.attr,
	&dev_attr_vf_true_promisc.attr,
	&dev_attr_rss_mode_order.attr,
	&dev_attr_rss_misc_type.attr,
	&dev_attr_vf_ipv4_addr.attr,
	&dev_attr_vf_max_ring.attr,
	&dev_attr_pxe_enable.attr,
	NULL,
};

static const struct attribute_group vendor_attr_grp = {
	.name = "vendor-ctrl",
	.attrs = vendor_dev_attrs,
};

static const struct attribute_group *attr_grps[] = {
	&vendor_attr_grp,
	&qos_attr_grp,
	NULL,
};

void mce_sysfs_exit(struct mce_pf *pf)
{
	struct net_device *netdev = mce_get_main_net_dev(pf);
	struct device *dev = &netdev->dev;

	sysfs_remove_groups(&dev->kobj, attr_grps);
	mce_hwmon_exit(pf);
}

int mce_sysfs_init(struct mce_pf *pf)
{
	struct net_device *netdev = mce_get_main_net_dev(pf);
	struct device *dev = &netdev->dev;
	int err = 0;

	err = mce_hwmon_init(pf);
	if (err) {
		dev_err(mce_pf_to_dev(pf), "Failed to create hwmon group\n");
		return err;
	}

	err = sysfs_create_groups(&dev->kobj, attr_grps);
	if (err)
		dev_err(mce_pf_to_dev(pf), "Failed to create sysfs group\n");

	return err;
}

#endif /* CONFIG_SYSFS */
