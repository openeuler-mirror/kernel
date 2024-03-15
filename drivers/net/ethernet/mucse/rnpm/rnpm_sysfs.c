// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2022 - 2023 Mucse Corporation. */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/sysfs.h>
#include <linux/firmware.h>
#include <linux/kobject.h>
#include <linux/device.h>
#include <linux/netdevice.h>
#include <linux/hwmon.h>
#include <linux/ctype.h>
#include "rnpm.h"
#include "rnpm_common.h"
#include "rnpm_type.h"
#include "rnpm_mbx.h"
#include "rnpm_mbx_fw.h"

struct maintain_req {
	int magic;
#define MAINTAIN_MAGIC 0xa6a7a8a9

	int cmd;
	int arg0;
	int req_data_bytes;
	int reply_bytes;
	char data[0];
} __packed;

struct ucfg_mac_sn {
	unsigned char macaddr[64];
	unsigned char sn[32];
	int magic;
#define MAC_SN_MAGIC 0x87654321
	char rev[52];
	unsigned char pn[32];
} __packed __aligned(4);

u32 bar4_reg_val;
u32 bar4_reg_addr;
u32 pcs_phy_num;
int pcs_cnt;

#define to_net_device(n) container_of(n, struct net_device, dev)

#define PHY_EXT_REG_FLAG 0x80000000
static u32 is_phy_ext_reg;
static u32 phy_reg;
#ifndef NO_BIT_ATTRS
static ssize_t maintain_read(struct file *filp, struct kobject *kobj,
			     struct bin_attribute *attr, char *buf, loff_t off,
			     size_t count)
{
	struct device *dev = kobj_to_dev(kobj);
	struct net_device *netdev = to_net_device(dev);
	struct rnpm_adapter *adapter = netdev_priv(netdev);
	// struct rnpm_hw *hw = &adapter->hw;
	int rbytes = count;

	if (adapter->maintain_buf == NULL)
		return 0;

	if (off + count > adapter->maintain_buf_len)
		rbytes = adapter->maintain_buf_len - off;
	memcpy(buf, adapter->maintain_buf + off, rbytes);

	// end-of-buf
	if ((off + rbytes) >= adapter->maintain_buf_len) {
		kfree(adapter->maintain_buf);
		adapter->maintain_buf = NULL;
		adapter->maintain_buf_len = 0;
	}

	return rbytes;
}

static ssize_t maintain_write(struct file *filp, struct kobject *kobj,
			      struct bin_attribute *attr, char *buf, loff_t off,
			      size_t count)
{
	struct device *dev = kobj_to_dev(kobj);
	// int ret;
	int err = -EINVAL;
	struct net_device *netdev = to_net_device(dev);
	struct rnpm_adapter *adapter = netdev_priv(netdev);
	struct rnpm_hw *hw = &adapter->hw;
	struct maintain_req *req;
	void *dma_buf = NULL;
	dma_addr_t dma_phy;
	int bytes;

	if (off == 0) {
		if (count < sizeof(*req))
			return -EINVAL;
		req = (struct maintain_req *)buf;
		if (req->magic != MAINTAIN_MAGIC)
			return -EINVAL;
		bytes = max_t(int, req->req_data_bytes, req->reply_bytes);
		bytes += sizeof(*req);
		kfree(adapter->maintain_buf);
		adapter->maintain_buf = NULL;
		adapter->maintain_buf_len = 0;
		// alloc buf
		//dma_buf = pci_alloc_consistent(hw->pdev, bytes, &dma_phy);
		dma_buf = dma_alloc_coherent(&hw->pdev->dev, bytes, &dma_phy,
					     GFP_ATOMIC);
		if (!dma_buf)
			return -ENOMEM;

		adapter->maintain_dma_buf = dma_buf;
		adapter->maintain_dma_phy = dma_phy;
		adapter->maintain_dma_size = bytes;
		adapter->maintain_in_bytes = req->req_data_bytes + sizeof(*req);

		memcpy(dma_buf + off, buf, count);

		if (count < adapter->maintain_in_bytes)
			return count;
	}

	dma_buf = adapter->maintain_dma_buf;
	dma_phy = adapter->maintain_dma_phy;
	req = (struct maintain_req *)dma_buf;

	memcpy(dma_buf + off, buf, count);

	// all data got, send req
	if ((off + count) >= adapter->maintain_in_bytes) {
		int reply_bytes = req->reply_bytes;
		// send req
		err = rnpm_maintain_req(hw, req->cmd, req->arg0,
					req->req_data_bytes, req->reply_bytes,
					dma_phy);
		if (err != 0)
			goto err_quit;
		// req can't be acces, a
		// copy data for read
		if (reply_bytes > 0) {
			adapter->maintain_buf_len = reply_bytes;
			adapter->maintain_buf =
				kmalloc(adapter->maintain_buf_len, GFP_KERNEL);
			if (!adapter->maintain_buf) {
				netdev_err(netdev,
					   "No Memory for maintain buf:%d\n",
					   adapter->maintain_buf_len);
				err = -ENOMEM;

				goto err_quit;
			}
			memcpy(adapter->maintain_buf, dma_buf, reply_bytes);
			// buf_dump("rx", adapter->maintain_buf, reply_bytes);
		}

		if (dma_buf) {
			//pci_free_consistent(
			dma_free_coherent(&hw->pdev->dev,
					  adapter->maintain_dma_size, dma_buf,
					  dma_phy);
		}
		adapter->maintain_dma_buf = NULL;
	}

	return count;
err_quit:
	if (dma_buf) {
		//pci_free_consistent(
		dma_free_coherent(&hw->pdev->dev, adapter->maintain_dma_size,
				  dma_buf, dma_phy);
		adapter->maintain_dma_buf = NULL;
	}
	return err;
}

/* some centos kernel maybe error use BIN_ATTR_RW */
//static BIN_ATTR_RW(maintain, 1 * 1024 * 1024);
static BIN_ATTR(maintain, 0644, maintain_read, maintain_write, 1 * 1024 * 1024);
#endif

static ssize_t active_vid_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	u16 current_vid = 0;
	u16 vid = 0;
	int ret = 0;
	struct net_device *netdev = to_net_device(dev);
	struct rnpm_adapter *adapter = netdev_priv(netdev);
	struct rnpm_hw *hw = &adapter->hw;
	u8 vfnum = RNPM_MAX_VF_CNT - 1; //use last-vf's table entry. the las

	if ((adapter->flags & RNPM_FLAG_SRIOV_ENABLED)) {
		current_vid = rd32(hw, RNPM_DMA_PORT_VEB_VID_TBL(adapter->port,
								 vfnum));
	}
	for_each_set_bit(vid, adapter->active_vlans, VLAN_N_VID) {
		ret += sprintf(buf + ret, "%u%s ", vid,
			       (current_vid == vid ? "*" : ""));
	}
	ret += sprintf(buf + ret, "\n");

	return ret;
}

static ssize_t active_vid_store(struct device *dev,
				struct device_attribute *attr, const char *buf,
				size_t count)
{
	u16 vid;
	int err = -EINVAL;
	struct net_device *netdev = to_net_device(dev);
	struct rnpm_adapter *adapter = netdev_priv(netdev);
	struct rnpm_hw __maybe_unused *hw = &adapter->hw;
	u8 __maybe_unused vfnum =
		RNPM_MAX_VF_CNT - 1; // use last-vf's table entry. the las
	int __maybe_unused port = 0;

	if (!(adapter->flags & RNPM_FLAG_SRIOV_ENABLED))
		return -EIO;

	if (kstrtou16(buf, 0, &vid) != 0)
		return -EINVAL;
	if ((vid < 4096) && test_bit(vid, adapter->active_vlans)) {
		if (rd32(hw, RNPM_DMA_VERSION) >= 0x20201231) {
			for (port = 0; port < 4; port++)
				wr32(hw, RNPM_DMA_PORT_VEB_VID_TBL(port, vfnum),
				     vid);
		} else {
			wr32(hw,
			     RNPM_DMA_PORT_VEB_VID_TBL(adapter->port, vfnum),
			     vid);
		}
		err = 0;
	}

	return err ? err : count;
}
static DEVICE_ATTR_RW(active_vid);
static ssize_t pf_reset_store(struct device *dev, struct device_attribute *attr,
			      const char *buf, size_t count)
{
	struct net_device *netdev = to_net_device(dev);
	struct rnpm_adapter *adapter = netdev_priv(netdev);
	struct rnpm_pf_adapter *pf_adapter = adapter->pf_adapter;

	set_bit(RNPM_PF_RESET, &pf_adapter->flags);

	return count;
}
static DEVICE_ATTR_WO(pf_reset);

static inline int pn_sn_dlen(char *v, int v_len)
{
	int i, len = 0;

	for (i = 0; i < v_len; i++) {
		if (isascii(v[i]))
			len++;
		else
			break;
	}
	return len;
}

int rnpm_mbx_get_pn_sn(struct rnpm_hw *hw, char pn[33], char sn[33])
{
	struct maintain_req *req;
	void *dma_buf = NULL;
	dma_addr_t dma_phy;
	struct ucfg_mac_sn *cfg;
	int err = 0, bytes = sizeof(*req) + sizeof(struct ucfg_mac_sn);

	memset(pn, 0, 33);
	memset(sn, 0, 33);

	dma_buf =
		dma_alloc_coherent(&hw->pdev->dev, bytes, &dma_phy, GFP_ATOMIC);
	if (!dma_buf)
		return -ENOMEM;

	req = (struct maintain_req *)dma_buf;
	memset(dma_buf, 0, bytes);
	cfg = (struct ucfg_mac_sn *)(req + 1);
	req->magic = MAINTAIN_MAGIC;
	req->cmd = 0; // READ
	req->arg0 = 3; // PARTION 3
	req->req_data_bytes = 0;
	req->reply_bytes = bytes - sizeof(*req);

	err = rnpm_maintain_req(hw, req->cmd, req->arg0, req->req_data_bytes,
				req->reply_bytes, dma_phy);
	if (err != 0)
		goto err_quit;

	if (cfg->magic == MAC_SN_MAGIC) {
		int sz = pn_sn_dlen(cfg->pn, 32);

		if (sz) {
			memcpy(pn, cfg->pn, sz);
			pn[sz] = 0;
		}
		sz = pn_sn_dlen(cfg->sn, 32);
		if (sz) {
			memcpy(sn, cfg->sn, sz);
			sn[sz] = 0;
		}
	}

err_quit:
	if (dma_buf) {
		// pci_free_consistent(
		dma_free_coherent(&hw->pdev->dev, bytes, dma_buf, dma_phy);
	}

	return 0;
}

static ssize_t vpd_show(struct device *dev, struct device_attribute *attr,
			char *buf)
{
	int ret = 0;
	struct net_device *netdev = to_net_device(dev);
	struct rnpm_adapter *adapter = netdev_priv(netdev);
	struct rnpm_hw *hw = &adapter->hw;
	char pn[33] = { 0 }, sn[33] = { 0 };
	char *prod_name;

	rnpm_mbx_get_pn_sn(hw, pn, sn);

	if ((adapter->pdev->device & 0xff) == 0x20) {
		prod_name =
			"Ethernet Controller N10 Series for 10GbE (Quad-port)";
	} else if ((adapter->pdev->device & 0xff) == 0x21) {
		prod_name =
			"Ethernet Controller N400 Series for 1GbE (Quad-port)";
	} else if ((adapter->pdev->device & 0xff) == 0x60) {
		prod_name =
			"Ethernet Controller N10 Series for 10GbE (Oct-port)";
	} else {
		prod_name = "Ethernet Controller N10 Series for 10GbE";
	}

	ret += sprintf(buf + ret, "Product Name: %s\n", prod_name);

	ret += sprintf(buf + ret, "[PN] Part number: %s\n", pn);
	ret += sprintf(buf + ret, "[SN] Serial number: %s\n", sn);

	return ret;
}
static DEVICE_ATTR_RO(vpd);

//==========

/* show logical and physical ring num correspondence */
static ssize_t ring_num_show(struct device *dev, struct device_attribute *attr,
			     char *buf)
{
	struct net_device *netdev = to_net_device(dev);
	struct rnpm_adapter *adapter = netdev_priv(netdev);
	struct rnpm_ring *ring;
	int ret = 0, i;

	ret += sprintf(
		buf + ret,
		"show %s logical <-> physical ring num (Decimal) correspondence:\n",
		netdev->name);
	for (i = 0; i < netdev->real_num_tx_queues; i++) {
		ring = adapter->tx_ring[i];
		ret += sprintf(buf + ret, "%03d           %03d\n", i,
			       ring->rnpm_queue_idx);
	}
	return ret;
}
static DEVICE_ATTR_RO(ring_num);

static ssize_t port_idx_show(struct device *dev, struct device_attribute *attr,
			     char *buf)
{
	int ret = 0;
	struct net_device *netdev = to_net_device(dev);
	struct rnpm_adapter *adapter = netdev_priv(netdev);
	// struct rnpm_hw *hw = &adapter->hw;

	ret += sprintf(buf, "%d\n", adapter->portid_of_card);
	return ret;
}
static DEVICE_ATTR_RO(port_idx);

static ssize_t nr_lane_show(struct device *dev, struct device_attribute *attr,
			    char *buf)
{
	int ret = 0;
	struct net_device *netdev = to_net_device(dev);
	struct rnpm_adapter *adapter = netdev_priv(netdev);
	// struct rnpm_hw *hw = &adapter->hw;

	ret += sprintf(buf, "%d\n", adapter->lane);
	return ret;
}
static DEVICE_ATTR_RO(nr_lane);

static ssize_t debug_linkstat_show(struct device *dev,
				   struct device_attribute *attr, char *buf)
{
	int ret = 0;
	struct net_device *netdev = to_net_device(dev);
	struct rnpm_adapter *adapter = netdev_priv(netdev);
	struct rnpm_hw *hw = &adapter->hw;

	ret += sprintf(buf, "%d %d dumy:0x%x up-flag:%d carry:%d\n",
		       adapter->link_up, adapter->hw.link, rd32(hw, 0xc),
		       adapter->flags & RNPM_FLAG_NEED_LINK_UPDATE,
		       netif_carrier_ok(netdev));
	return ret;
}
static DEVICE_ATTR_RO(debug_linkstat);

static ssize_t debug_aptstat_show(struct device *dev,
				  struct device_attribute *attr, char *buf)
{
	int ret = 0;
	struct net_device *netdev = to_net_device(dev);
	struct rnpm_adapter *adapter = netdev_priv(netdev);
	struct rnpm_hw *hw = &adapter->hw;

	ret += sprintf(
		buf,
		"stat:%d %d dumy:0x%x up-flag:%d carry:%d\n"
		"apt:flags:0x%x flags2:0x%x state:0x%lx timercnt:%u service cnt:%u\n"
		"pf_apt:flags:0x%lx state:0x%lx timercnt:%u\n",
		adapter->link_up, adapter->hw.link, rd32(hw, 0xc),
		adapter->flags & RNPM_FLAG_NEED_LINK_UPDATE,
		netif_carrier_ok(netdev), adapter->flags, adapter->flags2,
		adapter->state, adapter->timer_count, adapter->service_count,
		adapter->pf_adapter->flags, adapter->pf_adapter->state,
		adapter->pf_adapter->timer_count);
	return ret;
}
static DEVICE_ATTR_RO(debug_aptstat);

static ssize_t sfp_show(struct device *dev, struct device_attribute *attr,
			char *buf)
{
	int ret = 0;
	struct net_device *netdev = to_net_device(dev);
	struct rnpm_adapter *adapter = netdev_priv(netdev);
	struct rnpm_hw *hw = &adapter->hw;

	if (rnpm_mbx_get_lane_stat(hw) != 0) {
		ret += sprintf(buf, " IO Error\n");
	} else {
		ret += sprintf(
			buf, "mod-abs:%d\ntx-fault:%d\ntx-dis:%d\nrx-los:%d\n",
			adapter->sfp.mod_abs, adapter->sfp.fault,
			adapter->sfp.tx_dis, adapter->sfp.los);
	}

	return ret;
}
static DEVICE_ATTR_RO(sfp);

static ssize_t pci_store(struct device *dev, struct device_attribute *attr,
			 const char *buf, size_t count)
{
	int err = -EINVAL;
	struct net_device *netdev = to_net_device(dev);
	struct rnpm_adapter *adapter = netdev_priv(netdev);
	struct rnpm_hw *hw = &adapter->hw;
	int gen = 3, lanes = 8;

	if (count > 30)
		return -EINVAL;

	if (sscanf(buf, "gen%dx%d", &gen, &lanes) != 2) {
		e_dev_info("Error: invalid input. example: gen3x8\n");
		return -EINVAL;
	}
	if (gen > 3 || lanes > 8)
		return -EINVAL;

	err = rnpm_set_lane_fun(hw, LANE_FUN_PCI_LANE, gen, lanes, 0, 0);

	return err ? err : count;
}

static ssize_t pci_show(struct device *dev, struct device_attribute *attr,
			char *buf)
{
	int ret = 0;
	struct net_device *netdev = to_net_device(dev);
	struct rnpm_adapter *adapter = netdev_priv(netdev);
	struct rnpm_hw *hw = &adapter->hw;

	if (rnpm_mbx_get_lane_stat(hw) != 0)
		ret += sprintf(buf, " IO Error\n");
	else
		ret += sprintf(buf, "gen%dx%d\n", hw->pci_gen, hw->pci_lanes);

	return ret;
}
static DEVICE_ATTR_RW(pci);

static ssize_t prbs_store(struct device *dev, struct device_attribute *attr,
			  const char *buf, size_t count)
{
	int err = -EINVAL;
	struct net_device *netdev = to_net_device(dev);
	struct rnpm_adapter *adapter = netdev_priv(netdev);
	struct rnpm_hw *hw = &adapter->hw;
	long prbs = 0;

	if (kstrtol(buf, 10, &prbs))
		return -EINVAL;

	err = rnpm_set_lane_fun(hw, LANE_FUN_PRBS, prbs, 0, 0, 0);

	return err ? err : count;
}
static DEVICE_ATTR_WO(prbs);

static ssize_t sfp_tx_disable_store(struct device *dev,
				    struct device_attribute *attr,
				    const char *buf, size_t count)
{
	int err = -EINVAL;
	struct net_device *netdev = to_net_device(dev);
	struct rnpm_adapter *adapter = netdev_priv(netdev);
	struct rnpm_hw *hw = &adapter->hw;
	long enable = 0;

	if (kstrtol(buf, 10, &enable))
		return -EINVAL;

	err = rnpm_set_lane_fun(hw, LANE_FUN_SFP_TX_DISABLE, !!enable, 0, 0, 0);

	return err ? err : count;
}

static ssize_t sfp_tx_disable_show(struct device *dev,
				   struct device_attribute *attr, char *buf)
{
	int ret = 0;
	struct net_device *netdev = to_net_device(dev);
	struct rnpm_adapter *adapter = netdev_priv(netdev);
	struct rnpm_hw *hw = &adapter->hw;

	if (rnpm_mbx_get_lane_stat(hw) != 0)
		ret += sprintf(buf, " IO Error\n");
	else
		ret += sprintf(buf, "%d\n", adapter->sfp.tx_dis);

	return ret;
}
static DEVICE_ATTR_RW(sfp_tx_disable);

static ssize_t link_traing_store(struct device *dev,
				 struct device_attribute *attr, const char *buf,
				 size_t count)
{
	int err = -EINVAL;
	struct net_device *netdev = to_net_device(dev);
	struct rnpm_adapter *adapter = netdev_priv(netdev);
	struct rnpm_hw *hw = &adapter->hw;
	long enable = 0;

	if (kstrtol(buf, 10, &enable))
		return -EINVAL;

	err = rnpm_set_lane_fun(hw, LANE_FUN_LINK_TRAING, !!enable, 0, 0, 0);

	return err ? err : count;
}

static ssize_t link_traing_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	int ret = 0;
	struct net_device *netdev = to_net_device(dev);
	struct rnpm_adapter *adapter = netdev_priv(netdev);
	struct rnpm_hw *hw = &adapter->hw;

	if (rnpm_mbx_get_lane_stat(hw) != 0)
		ret += sprintf(buf, " IO Error\n");
	else
		ret += sprintf(buf, "%d\n", adapter->link_traing);

	return ret;
}
static DEVICE_ATTR_RW(link_traing);

static ssize_t fec_store(struct device *dev, struct device_attribute *attr,
			 const char *buf, size_t count)
{
	int err = -EINVAL;
	struct net_device *netdev = to_net_device(dev);
	struct rnpm_adapter *adapter = netdev_priv(netdev);
	struct rnpm_hw *hw = &adapter->hw;
	long enable = 0;

	if (kstrtol(buf, 10, &enable))
		return -EINVAL;

	err = rnpm_set_lane_fun(hw, LANE_FUN_FEC, !!enable, 0, 0, 0);

	return err ? err : count;
}

static ssize_t fec_show(struct device *dev, struct device_attribute *attr,
			char *buf)
{
	int ret = 0;
	struct net_device *netdev = to_net_device(dev);
	struct rnpm_adapter *adapter = netdev_priv(netdev);
	struct rnpm_hw *hw = &adapter->hw;

	if (rnpm_mbx_get_lane_stat(hw) != 0)
		ret += sprintf(buf, " IO Error\n");
	else
		ret += sprintf(buf, "%d\n", adapter->fec);

	return ret;
}
static DEVICE_ATTR_RW(fec);

static ssize_t autoneg_store(struct device *dev, struct device_attribute *attr,
			     const char *buf, size_t count)
{
	int err = -EINVAL;
	struct net_device *netdev = to_net_device(dev);
	struct rnpm_adapter *adapter = netdev_priv(netdev);
	struct rnpm_hw *hw = &adapter->hw;
	long enable = 0;

	if (kstrtol(buf, 10, &enable))
		return -EINVAL;

	err = rnpm_set_lane_fun(hw, LANE_FUN_AN, !!enable, 0, 0, 0);

	return err ? err : count;
}

static ssize_t autoneg_show(struct device *dev, struct device_attribute *attr,
			    char *buf)
{
	int ret = 0;
	struct net_device *netdev = to_net_device(dev);
	struct rnpm_adapter *adapter = netdev_priv(netdev);
	struct rnpm_hw *hw = &adapter->hw;

	if (rnpm_mbx_get_lane_stat(hw) != 0)
		ret += sprintf(buf, " IO Error\n");
	else
		ret += sprintf(buf, "%d\n", adapter->an);

	return ret;
}
static DEVICE_ATTR_RW(autoneg);

static ssize_t si_store(struct device *dev, struct device_attribute *attr,
			const char *buf, size_t count)
{
	int err = -EINVAL;
	struct net_device *netdev = to_net_device(dev);
	struct rnpm_adapter *adapter = netdev_priv(netdev);
	struct rnpm_hw *hw = &adapter->hw;
	int si_main = -1, si_pre = -1, si_post = -1, si_txboost = -1;
	int cnt;

	if (count > 100) {
		e_dev_info("Error: Input size >100: too large\n");
		return -EINVAL;
	}
	cnt = sscanf(buf, "%u %u %u %u", &si_main, &si_pre, &si_post,
		     &si_txboost);
	if (cnt != 4) {
		e_dev_info(
			"Error: Invalid Input: <main> <pre> <post> <tx_boost>\n");
		return -EINVAL;
	}
	if (si_main > 63 || si_pre > 63 || si_post > 63) {
		e_dev_info("Error: Invalid value. should in 0~63\n");
		return -EINVAL;
	}
	if (si_txboost > 16) {
		e_dev_info("Error: Invalid txboost. should in 0~15\n");
		return -EINVAL;
	}
	err = rnpm_set_lane_fun(hw, LANE_FUN_SI, si_main, si_pre, si_post,
				si_txboost);

	return err ? err : count;
}

static ssize_t si_show(struct device *dev, struct device_attribute *attr,
		       char *buf)
{
	int ret = 0;
	struct net_device *netdev = to_net_device(dev);
	struct rnpm_adapter *adapter = netdev_priv(netdev);
	struct rnpm_hw *hw = &adapter->hw;

	if (rnpm_mbx_get_lane_stat(hw) != 0) {
		ret += sprintf(buf, " IO Error\n");
	} else {
		ret += sprintf(buf, "main:%u pre:%u post:%u tx_boost:%u\n",
			       adapter->si.main, adapter->si.pre,
			       adapter->si.post, adapter->si.tx_boost);
	}

	return ret;
}
static DEVICE_ATTR_RW(si);

static ssize_t temperature_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct net_device *netdev = to_net_device(dev);
	struct rnpm_adapter *adapter = netdev_priv(netdev);
	struct rnpm_hw *hw = &adapter->hw;
	int ret = 0, temp = 0, voltage = 0;

	temp = rnpm_mbx_get_temp(hw, &voltage);

	ret += sprintf(buf, "temp:%d oC  volatage:%d mV\n", temp, voltage);
	return ret;
}
static DEVICE_ATTR_RO(temperature);

static ssize_t tx_counter_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	u32 val = 0;
	int ret = 0;
	struct net_device *netdev = to_net_device(dev);
	struct rnpm_adapter *adapter = netdev_priv(netdev);
	struct rnpm_hw *hw = &adapter->hw;

	ret += sprintf(buf + ret, "tx counters\n");
	ret += sprintf(buf + ret, "ring0-tx:\n");

	val = rd32(hw, RNPM_DMA_REG_TX_DESC_BUF_LEN(0));
	ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
		       "len:", RNPM_DMA_REG_TX_DESC_BUF_LEN(0), val);

	val = rd32(hw, RNPM_DMA_REG_TX_DESC_BUF_HEAD(0));
	ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
		       "head:", RNPM_DMA_REG_TX_DESC_BUF_HEAD(0), val);

	val = rd32(hw, RNPM_DMA_REG_TX_DESC_BUF_TAIL(0));
	ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
		       "tail:", RNPM_DMA_REG_TX_DESC_BUF_TAIL(0), val);

	ret += sprintf(buf + ret, "ring1-tx:\n");

	val = rd32(hw, RNPM_DMA_REG_TX_DESC_BUF_LEN(1));
	ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
		       "len:", RNPM_DMA_REG_TX_DESC_BUF_LEN(1), val);

	val = rd32(hw, RNPM_DMA_REG_TX_DESC_BUF_HEAD(1));
	ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
		       "head:", RNPM_DMA_REG_TX_DESC_BUF_HEAD(1), val);

	val = rd32(hw, RNPM_DMA_REG_TX_DESC_BUF_TAIL(1));
	ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
		       "tail:", RNPM_DMA_REG_TX_DESC_BUF_TAIL(1), val);

	ret += sprintf(buf + ret, "to_1to4_p1:\n");

	val = rd32(hw, RNPM_ETH_1TO4_INST0_IN_PKTS);
	ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
		       "emac_in:", RNPM_ETH_1TO4_INST0_IN_PKTS, val);

	val = rd32(hw, RNPM_ETH_IN_0_TX_PKT_NUM(0));
	ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
		       "emac_send:", RNPM_ETH_IN_0_TX_PKT_NUM(0), val);

	ret += sprintf(buf + ret, "to_1to4_p2:\n");

	val = rd32(hw, RNPM_ETH_IN_1_TX_PKT_NUM(0));
	ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
		       "sop_pkt:", RNPM_ETH_IN_1_TX_PKT_NUM(0), val);

	val = rd32(hw, RNPM_ETH_IN_2_TX_PKT_NUM(0));
	ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
		       "eop_pkt:", RNPM_ETH_IN_2_TX_PKT_NUM(0), val);

	val = rd32(hw, RNPM_ETH_IN_3_TX_PKT_NUM(0));
	ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
		       "send_terr:", RNPM_ETH_IN_3_TX_PKT_NUM(0), val);

	ret += sprintf(buf + ret, "to_tx_trans(phy):\n");

	val = rd32(hw, RNPM_ETH_EMAC_TX_TO_PHY_PKTS(0));
	ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
		       "in:", RNPM_ETH_EMAC_TX_TO_PHY_PKTS(0), val);

	val = rd32(hw, RNPM_ETH_TXTRANS_PTP_PKT_NUM(0));
	ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
		       "out:", RNPM_ETH_TXTRANS_PTP_PKT_NUM(0), val);

	ret += sprintf(buf + ret, "mac:\n");

	val = rd32(hw, 0x1081c);
	ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n", "tx:", 0x1081c,
		       val);

	val = rd32(hw, 0x1087c);
	ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
		       "underflow_err:", 0x1087c, val);

	val = rd32(hw, RNPM_ETH_TX_DEBUG_PORT0_SOP);
	ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
		       "port0_txtrans_sop:", RNPM_ETH_TX_DEBUG_PORT0_SOP, val);

	val = rd32(hw, RNPM_ETH_TX_DEBUG_PORT0_EOP);
	ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
		       "port0_txtrans_eop:", RNPM_ETH_TX_DEBUG_PORT0_EOP, val);

	val = rd32(hw, RNPM_ETH_TX_DEBUG_PORT1_SOP);
	ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
		       "port1_txtrans_sop:", RNPM_ETH_TX_DEBUG_PORT1_SOP, val);

	val = rd32(hw, RNPM_ETH_TX_DEBUG_PORT1_EOP);
	ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
		       "port1_txtrans_eop:", RNPM_ETH_TX_DEBUG_PORT1_EOP, val);

	val = rd32(hw, RNPM_ETH_TX_DEBUG_PORT2_SOP);
	ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
		       "port2_txtrans_sop:", RNPM_ETH_TX_DEBUG_PORT2_SOP, val);

	val = rd32(hw, RNPM_ETH_TX_DEBUG_PORT2_EOP);
	ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
		       "port2_txtrans_eop:", RNPM_ETH_TX_DEBUG_PORT2_EOP, val);

	val = rd32(hw, RNPM_ETH_TX_DEBUG_PORT3_SOP);
	ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
		       "port3_txtrans_sop:", RNPM_ETH_TX_DEBUG_PORT3_SOP, val);

	val = rd32(hw, RNPM_ETH_TX_DEBUG_PORT3_EOP);
	ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
		       "port3_txtrans_eop:", RNPM_ETH_TX_DEBUG_PORT3_EOP, val);

	val = rd32(hw, RNPM_ETH_TX_DEBUG_EMPTY);
	ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
		       "tx_empty:", RNPM_ETH_TX_DEBUG_EMPTY, val);

	val = rd32(hw, RNPM_ETH_TX_DEBUG_PROG_FULL);
	ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
		       "tx_prog_full:", RNPM_ETH_TX_DEBUG_PROG_FULL, val);

	val = rd32(hw, RNPM_ETH_TX_DEBUG_FULL);
	ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
		       "tx_full:", RNPM_ETH_TX_DEBUG_FULL, val);

	return ret;
}
static DEVICE_ATTR_RO(tx_counter);

static ssize_t rx_counter_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	u32 val = 0, port = 0;
	int ret = 0;
	struct net_device *netdev = to_net_device(dev);
	struct rnpm_adapter *adapter = netdev_priv(netdev);
	struct rnpm_hw *hw = &adapter->hw;

	ret += sprintf(buf + ret, "rx counters\n");
	for (port = 0; port < 4; port++) {
		ret += sprintf(buf + ret, "emac_rx_trans (port:%d):\n", port);

		val = rd32(hw, RNPM_RXTRANS_RX_PKTS(port));
		ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
			       "pkts:", RNPM_RXTRANS_RX_PKTS(port), val);

		val = rd32(hw, RNPM_RXTRANS_DROP_PKTS(port));
		ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
			       "drop:", RNPM_RXTRANS_DROP_PKTS(port), val);

		val = rd32(hw, RNPM_RXTRANS_WDT_ERR_PKTS(port));
		ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
			       "wdt_err:", RNPM_RXTRANS_WDT_ERR_PKTS(port),
			       val);

		val = rd32(hw, RNPM_RXTRANS_CODE_ERR_PKTS(port));
		ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
			       "code_err:", RNPM_RXTRANS_CODE_ERR_PKTS(port),
			       val);

		val = rd32(hw, RNPM_RXTRANS_CRC_ERR_PKTS(port));
		ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
			       "crc_err:", RNPM_RXTRANS_CRC_ERR_PKTS(port),
			       val);

		val = rd32(hw, RNPM_RXTRANS_SLEN_ERR_PKTS(port));
		ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
			       "slen_err:", RNPM_RXTRANS_SLEN_ERR_PKTS(port),
			       val);

		val = rd32(hw, RNPM_RXTRANS_GLEN_ERR_PKTS(port));
		ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
			       "glen_err:", RNPM_RXTRANS_GLEN_ERR_PKTS(port),
			       val);

		val = rd32(hw, RNPM_RXTRANS_IPH_ERR_PKTS(port));
		ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
			       "iph_err:", RNPM_RXTRANS_IPH_ERR_PKTS(port),
			       val);

		val = rd32(hw, RNPM_RXTRANS_CSUM_ERR_PKTS(port));
		ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
			       "csum_err:", RNPM_RXTRANS_CSUM_ERR_PKTS(port),
			       val);

		val = rd32(hw, RNPM_RXTRANS_LEN_ERR_PKTS(port));
		ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
			       "len_err:", RNPM_RXTRANS_LEN_ERR_PKTS(port),
			       val);

		val = rd32(hw, RNPM_RXTRANS_CUT_ERR_PKTS(port));
		ret += sprintf(
			buf + ret, "\t %16s 0x%08x: 0x%x\n",
			"trans_cut_err:", RNPM_RXTRANS_CUT_ERR_PKTS(port), val);

		val = rd32(hw, RNPM_RXTRANS_EXCEPT_BYTES(port));
		ret += sprintf(
			buf + ret, "\t %16s 0x%08x: 0x%x\n",
			"expt_byte_err:", RNPM_RXTRANS_EXCEPT_BYTES(port), val);

		val = rd32(hw, RNPM_RXTRANS_G1600_BYTES_PKTS(port));
		ret += sprintf(
			buf + ret, "\t %16s 0x%08x: 0x%x\n",
			">1600Byte:", RNPM_RXTRANS_G1600_BYTES_PKTS(port), val);
	}

	ret += sprintf(buf + ret, "gather:\n");
	val = rd32(hw, RNPM_ETH_TOTAL_GAT_RX_PKT_NUM);
	ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
		       "total_in_pkts:", RNPM_ETH_TOTAL_GAT_RX_PKT_NUM, val);

	port = 0;
	val = rd32(hw, RNPM_ETH_RX_PKT_NUM(port));
	ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
		       "to_nxt_mdodule:", RNPM_ETH_RX_PKT_NUM(port), val);

	for (port = 0; port < 4; port++) {
		u8 pname[16] = { 0 };

		val = rd32(hw, RNPM_ETH_RX_PKT_NUM(port));
		sprintf(pname, "p%d-rx:", port);
		ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n", pname,
			       RNPM_ETH_RX_PKT_NUM(port), val);
	}

	for (port = 0; port < 4; port++) {
		u8 pname[16] = { 0 };

		val = rd32(hw, RNPM_ETH_RX_DROP_PKT_NUM(port));
		sprintf(pname, "p%d-drop:", port);
		ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n", pname,
			       RNPM_ETH_RX_DROP_PKT_NUM(port), val);
	}

	ret += sprintf(buf + ret, "ip-parse:\n");

	val = rd32(hw, RNPM_ETH_PKT_EGRESS_NUM);
	ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
		       "pkg_egree:", RNPM_ETH_PKT_EGRESS_NUM, val);

	val = rd32(hw, RNPM_ETH_PKT_IP_HDR_LEN_ERR_NUM);
	ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
		       "L3_len_err:", RNPM_ETH_PKT_IP_HDR_LEN_ERR_NUM, val);

	val = rd32(hw, RNPM_ETH_PKT_IP_PKT_LEN_ERR_NUM);
	ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
		       "ip_hdr_err:", RNPM_ETH_PKT_IP_PKT_LEN_ERR_NUM, val);

	val = rd32(hw, RNPM_ETH_PKT_L3_HDR_CHK_ERR_NUM);
	ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
		       "l3-csum-err:", RNPM_ETH_PKT_L3_HDR_CHK_ERR_NUM, val);

	val = rd32(hw, RNPM_ETH_PKT_L4_HDR_CHK_ERR_NUM);
	ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
		       "l4-csum-err:", RNPM_ETH_PKT_L4_HDR_CHK_ERR_NUM, val);

	val = rd32(hw, RNPM_ETH_PKT_SCTP_CHK_ERR_NUM);
	ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
		       "sctp-err:", RNPM_ETH_PKT_SCTP_CHK_ERR_NUM, val);

	val = rd32(hw, RNPM_ETH_PKT_VLAN_ERR_NUM);
	ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
		       "vlan-err:", RNPM_ETH_PKT_VLAN_ERR_NUM, val);

	val = rd32(hw, RNPM_ETH_PKT_EXCEPT_SHORT_NUM);
	ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
		       "except_short_num:", RNPM_ETH_PKT_EXCEPT_SHORT_NUM, val);

	val = rd32(hw, RNPM_ETH_PKT_PTP_NUM);
	ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
		       "ptp:", RNPM_ETH_PKT_PTP_NUM, val);

	ret += sprintf(buf + ret, "to-indecap:\n");

	val = rd32(hw, RNPM_ETH_DECAP_PKT_IN_NUM);
	ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
		       "*in engin*:", RNPM_ETH_DECAP_PKT_IN_NUM, val);

	val = rd32(hw, RNPM_ETH_DECAP_PKT_OUT_NUM);
	ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
		       "*out engin*:", RNPM_ETH_DECAP_PKT_OUT_NUM, val);

	val = rd32(hw, RNPM_ETH_DECAP_DMAC_OUT_NUM);
	ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
		       "to-dma/host:", RNPM_ETH_DECAP_DMAC_OUT_NUM, val);

	val = rd32(hw, RNPM_ETH_DECAP_BMC_OUT_NUM);
	ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
		       "to-bmc:", RNPM_ETH_DECAP_BMC_OUT_NUM, val);

	val = rd32(hw, RNPM_ETH_DECAP_SW_OUT_NUM);
	ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
		       "to-switch:", RNPM_ETH_DECAP_SW_OUT_NUM, val);

	val = rd32(hw, RNPM_ETH_DECAP_MIRROR_OUT_NUM);
	ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
		       "bmc+host:", RNPM_ETH_DECAP_MIRROR_OUT_NUM, val);

	val = rd32(hw, RNPM_ETH_DECAP_PKT_DROP_NUM(0x0));
	ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
		       "err_drop:", RNPM_ETH_DECAP_PKT_DROP_NUM(0x0), val);

	val = rd32(hw, RNPM_ETH_DECAP_PKT_DROP_NUM(1));
	ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
		       "plicy_drop:", RNPM_ETH_DECAP_PKT_DROP_NUM(1), val);

	val = rd32(hw, RNPM_ETH_DECAP_PKT_DROP_NUM(2));
	ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
		       "dmac_drop:", RNPM_ETH_DECAP_PKT_DROP_NUM(2), val);

	val = rd32(hw, RNPM_ETH_DECAP_PKT_DROP_NUM(3));
	ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
		       "bmc_drop:", RNPM_ETH_DECAP_PKT_DROP_NUM(3), val);

	val = rd32(hw, RNPM_ETH_DECAP_PKT_DROP_NUM(4));
	ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
		       "sw_drop:", RNPM_ETH_DECAP_PKT_DROP_NUM(4), val);

	val = rd32(hw, RNPM_ETH_DECAP_PKT_DROP_NUM(5));
	ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
		       "rm_vlane_num:", RNPM_ETH_DECAP_PKT_DROP_NUM(5), val);

	ret += sprintf(buf + ret, "dma-2-host:\n");

	val = rd32(hw, 0x264);
	ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n", "fifo equ:", 0x264,
		       val);

	val = rd32(hw, 0x268);
	ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n", "fifo deq:", 0x268,
		       val);

	val = rd32(hw, 0x114);
	ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
		       "unexpt_abtring:", 0x114, val);

	val = rd32(hw, 0x288);
	ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n", "pci2host:", 0x288,
		       val);

	for (port = 0; port < 4; port++) {
		ret += sprintf(buf + ret, "rx-ring%d:\n", port);

		val = rd32(hw, RNPM_DMA_REG_RX_DESC_BUF_HEAD(port));
		ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
			       "head:", RNPM_DMA_REG_RX_DESC_BUF_HEAD(port),
			       val);

		val = rd32(hw, RNPM_DMA_REG_RX_DESC_BUF_TAIL(port));
		ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
			       "tail:", RNPM_DMA_REG_RX_DESC_BUF_TAIL(port),
			       val);

		val = rd32(hw, RNPM_DMA_REG_RX_DESC_BUF_LEN(port));
		ret += sprintf(buf + ret, "\t %16s 0x%08x: 0x%x\n",
			       "len:", RNPM_DMA_REG_RX_DESC_BUF_LEN(port), val);
	}

	return ret;
}

static DEVICE_ATTR_RO(rx_counter);

static ssize_t bar4_reg_show(struct device *dev, struct device_attribute *attr,
			     char *buf)
{
	int ret = 0;

	ret += sprintf(buf + ret, "addr=0x%x, val=0x%x\n", bar4_reg_addr,
		       bar4_reg_val);
	return ret;
}

static ssize_t bar4_reg_store(struct device *dev, struct device_attribute *attr,
			      const char *buf, size_t count)
{
	struct net_device *netdev = to_net_device(dev);
	struct rnpm_adapter *adapter = netdev_priv(netdev);
	struct rnpm_hw *hw = &adapter->hw;
	int rc;

	rc = kstrtou32(buf, 0, &bar4_reg_addr);
	if (rc)
		return -EINVAL;
	bar4_reg_val = rd32(hw, bar4_reg_addr);

	return count;
}
static DEVICE_ATTR_RW(bar4_reg);

static struct pci_dev *pcie_find_root_port_old(struct pci_dev *dev)
{
	while (1) {
		if (!pci_is_pcie(dev))
			break;
		if (pci_pcie_type(dev) == PCI_EXP_TYPE_ROOT_PORT)
			return dev;
		if (!dev->bus->self)
			break;
		dev = dev->bus->self;
	}
	return NULL;
}
static ssize_t root_slot_info_show(struct device *dev,
				   struct device_attribute *attr, char *buf)
{
	struct net_device *netdev = to_net_device(dev);
	struct rnpm_adapter *adapter = netdev_priv(netdev);
	int ret = 0;
	struct pci_dev *root_pdev = pcie_find_root_port_old(adapter->pdev);

	if (root_pdev) {
		ret += sprintf(buf + ret, "%02x:%02x.%x\n",
			       root_pdev->bus->number,
			       PCI_SLOT(root_pdev->devfn),
			       PCI_FUNC(root_pdev->devfn));
	}
	return ret;
}
static DEVICE_ATTR_RO(root_slot_info);

static ssize_t phy_statistics_show(struct device *dev,
				   struct device_attribute *attr, char *buf)
{
	int ret = 0;
	struct net_device *netdev = to_net_device(dev);
	struct rnpm_adapter *adapter = netdev_priv(netdev);
	struct rnpm_hw *hw = &adapter->hw;
	struct phy_statistics ps;

	memset(&ps, 0, sizeof(ps));

	if (rnpm_mbx_get_phy_statistics(hw, (u8 *)&ps) != 0)
		return 0;

	ret += sprintf(buf + ret, "RX crc good   (64~1518) : %u\n",
		       ps.yt.pkg_ib_valid);
	ret += sprintf(buf + ret, "RX crc good   (>1518)   : %u\n",
		       ps.yt.pkg_ib_os_good);
	ret += sprintf(buf + ret, "RX crc good   (<64)     : %u\n",
		       ps.yt.pkg_ib_us_good);
	ret += sprintf(buf + ret, "RX crc wrong  (64~1518) : %u\n",
		       ps.yt.pkg_ib_err);
	ret += sprintf(buf + ret, "RX crc wrong  (>1518)   : %u\n",
		       ps.yt.pkg_ib_os_bad);
	ret += sprintf(buf + ret, "RX crc wrong  (<64)     : %u\n",
		       ps.yt.pkg_ib_frag);
	ret += sprintf(buf + ret, "RX SFD missed (nosfd)   : %u\n",
		       ps.yt.pkg_ib_nosfd);
	ret += sprintf(buf + ret, "TX crc good   (64~1518) : %u\n",
		       ps.yt.pkg_ob_valid);
	ret += sprintf(buf + ret, "TX crc good   (>1518)   : %u\n",
		       ps.yt.pkg_ob_os_good);
	ret += sprintf(buf + ret, "TX crc good   (<64)     : %u\n",
		       ps.yt.pkg_ob_us_good);
	ret += sprintf(buf + ret, "TX crc wrong  (64~1518) : %u\n",
		       ps.yt.pkg_ob_err);
	ret += sprintf(buf + ret, "TX crc wrong  (>1518)   : %u\n",
		       ps.yt.pkg_ob_os_bad);
	ret += sprintf(buf + ret, "TX crc wrong  (<64)     : %u\n",
		       ps.yt.pkg_ob_frag);
	ret += sprintf(buf + ret, "TX SFD missed (nosfd)   : %u\n",
		       ps.yt.pkg_ob_nosfd);

	return ret;
}
static DEVICE_ATTR_RO(phy_statistics);

static ssize_t pcs_reg_store(struct device *dev, struct device_attribute *attr,
			     const char *buf, size_t count)
{
	// eg: echo "phy reg val" > pcs_reg
	// sscanf
	u32 pcs_phy_regs[] = {
		0x00040000, 0x00041000, 0x00042000, 0x00043000,
		0x00040000, 0x00041000, 0x00042000, 0x00043000,
	};

	struct net_device *netdev = to_net_device(dev);
	struct rnpm_adapter *adapter = netdev_priv(netdev);
	struct rnpm_hw *hw = &adapter->hw;
	u32 reg_hi = 0, reg_lo = 0, pcs_base_regs = 0;

	if (count > 64) {
		e_dev_info("Error: Input size >100: too large\n");
		return -EINVAL;
	}

	pcs_cnt = sscanf(buf, "%u %x %x", &pcs_phy_num, &bar4_reg_addr,
			 &bar4_reg_val);

	if (pcs_cnt != 2 && pcs_cnt != 3) {
		e_dev_info(
			"Error: Invalid Input: read phy x reg 0xXXX or write phy x reg ");
		e_dev_info("0xXXX val 0xXXX\n");
		return -EINVAL;
	}

	if (pcs_phy_num > 8) {
		e_dev_info("Error: Invalid value. should in 0~7\n");
		return -EINVAL;
	}

	switch (pcs_cnt) {
	case 2:
		reg_hi = bar4_reg_addr >> 8;
		reg_lo = (bar4_reg_addr & 0xff) << 2;
		pcs_base_regs = pcs_phy_regs[pcs_phy_num];
		wr32(hw, pcs_base_regs + (0xff << 2), reg_hi);
		bar4_reg_val = rd32(hw, pcs_base_regs + reg_lo);
		break;
	case 3:
		reg_hi = bar4_reg_addr >> 8;
		reg_lo = (bar4_reg_addr & 0xff) << 2;
		pcs_base_regs = pcs_phy_regs[pcs_phy_num];
		wr32(hw, pcs_base_regs + (0xff << 2), reg_hi);
		wr32(hw, pcs_base_regs + reg_lo, bar4_reg_val);
		break;
	default:
		e_dev_info("Error: Invalid value. pcs_cnt=%d\n", pcs_cnt);
		break;
	}

	return count;
}

static ssize_t pcs_reg_show(struct device *dev, struct device_attribute *attr,
			    char *buf)
{
	int ret = 0;
	struct net_device *netdev = to_net_device(dev);
	struct rnpm_adapter *adapter = netdev_priv(netdev);

	switch (pcs_cnt) {
	case 2:
		ret += sprintf(buf, "read phy %u reg 0x%x val 0x%x\n",
			       pcs_phy_num, bar4_reg_addr, bar4_reg_val);
		break;
	case 3:
		ret += sprintf(buf, "write phy %u reg 0x%x val 0x%x\n",
			       pcs_phy_num, bar4_reg_addr, bar4_reg_val);
		break;
	default:
		e_dev_info("Error: Invalid pcs_cnt value =%d\n", pcs_cnt);
		break;
	}

	return ret;
}
static DEVICE_ATTR_RW(pcs_reg);

static ssize_t phy_reg_show(struct device *dev, struct device_attribute *attr,
			    char *buf)
{
	struct net_device *netdev = to_net_device(dev);
	struct rnpm_adapter *adapter = netdev_priv(netdev);
	struct rnpm_hw *hw = &adapter->hw;
	int val = 0;
	int err = -EINVAL;

	if (hw) {
		if (is_phy_ext_reg) {
			err = rnpm_mbx_phy_read(hw, phy_reg | PHY_EXT_REG_FLAG,
						&val);
		} else {
			err = rnpm_mbx_phy_read(hw, phy_reg, &val);
		}
	}

	if (err) {
		return 0;
	} else {
		return sprintf(buf, "phy %s 0x%04x : 0x%04x\n",
			       is_phy_ext_reg ? "ext reg" : "reg", phy_reg,
			       val & 0xffff);
	}
}

static ssize_t phy_reg_store(struct device *dev, struct device_attribute *attr,
			     const char *buf, size_t count)
{
	int i = 0, argc = 0, err = -EINVAL;
	char argv[3][16];
	unsigned long val[3] = { 0 };

	struct net_device *netdev = to_net_device(dev);
	struct rnpm_adapter *adapter = netdev_priv(netdev);
	struct rnpm_hw *hw = &adapter->hw;

	memset(argv, 0, sizeof(argv));
	argc = sscanf(buf, "%15s %15s %15s", argv[0], argv[1], argv[2]);

	if (argc < 1)
		return -EINVAL;

	is_phy_ext_reg = 0;

	if (strcmp(argv[0], "ext") == 0) {
		is_phy_ext_reg = 1;
	} else {
		if (kstrtoul(argv[0], 0, &val[0]))
			return -EINVAL;
	}

	for (i = 1; i < argc; i++) {
		if (kstrtoul(argv[i], 0, &val[i]))
			return -EINVAL;
	}

	if (argc == 1) {
		if (is_phy_ext_reg)
			return -EINVAL;
		/* set phy reg index */
		phy_reg = val[0];
		err = 0;
	}

	if (argc == 2) {
		if (is_phy_ext_reg) {
			/* set ext phy reg index */
			phy_reg = val[1];
			err = 0;
		} else {
			/* write phy reg */
			phy_reg = val[0];
			err = rnpm_mbx_phy_write(hw, phy_reg, val[1]);
		}
	}

	if (argc == 3) {
		if (is_phy_ext_reg) {
			/* write ext phy reg */
			phy_reg = val[1];
			err = rnpm_mbx_phy_write(hw, phy_reg | PHY_EXT_REG_FLAG,
						 val[2]);
		} else {
			return -EINVAL;
		}
	}

	return err ? err : count;
}
static DEVICE_ATTR_RW(phy_reg);

static ssize_t pma_rx2tx_loopback_store(struct device *dev,
					struct device_attribute *attr,
					const char *buf, size_t count)
{
	struct net_device *netdev = to_net_device(dev);
	struct rnpm_adapter *adapter = netdev_priv(netdev);
	struct rnpm_hw *hw = &adapter->hw;
	int v, en_loopback, rc;
	int nr_lane = adapter->lane % 4;

	rc = kstrtou32(buf, 0, &en_loopback);
	if (rc)
		return -EINVAL;
	e_dev_info("%s: nr_lane:%d lp:%d\n", __func__, nr_lane, en_loopback);

	if (!hw->pcs.ops.write || !hw->pcs.ops.read)
		return -EOPNOTSUPP;

	// pma-rx2tx_loopback
	v = hw->pcs.ops.read(hw, nr_lane, 0x18090);
	if (en_loopback)
		v |= 0xf << 4;
	else
		v &= ~(0xf << 4);
	hw->pcs.ops.write(hw, nr_lane, 0x18090, v);

	// mac tx-disable
	v = rd32(hw, RNPM_MAC_TX_CFG(nr_lane));
	if (en_loopback)
		v &= ~(BIT(0)); // disable mac-tx
	else
		v |= (BIT(0)); // enable mac-tx
	wr32(hw, RNPM_MAC_TX_CFG(nr_lane), v);

	// mac rx-disable
	v = rd32(hw, RNPM_MAC_RX_CFG(nr_lane));
	if (en_loopback)
		v &= ~(BIT(0)); // disable mac-rx
	else
		v |= (BIT(0)); // enable mac-rx
	wr32(hw, RNPM_MAC_RX_CFG(nr_lane), v);

	return count;
}
static DEVICE_ATTR_WO(pma_rx2tx_loopback);

static ssize_t pcs_rx2tx_loopback_store(struct device *dev,
					struct device_attribute *attr,
					const char *buf, size_t count)
{
	struct net_device *netdev = to_net_device(dev);
	struct rnpm_adapter *adapter = netdev_priv(netdev);
	struct rnpm_hw *hw = &adapter->hw;
	int v, en_loopback, rc;
	int nr_lane = adapter->lane % 4;

	rc = kstrtou32(buf, 0, &en_loopback);
	if (rc)
		return -EINVAL;
	e_dev_info("%s: nr_lane:%d lp:%d\n", __func__, nr_lane, en_loopback);

	if (!hw->pcs.ops.write || !hw->pcs.ops.read)
		return -EOPNOTSUPP;

	// pma-rx2tx_loopback
	v = hw->pcs.ops.read(hw, nr_lane, 0x38000);
	if (en_loopback)
		v |= BIT(14); // RX2TX_LB_EN
	else
		v &= ~BIT(14); // RX2TX_LB_EN
	hw->pcs.ops.write(hw, nr_lane, 0x38000, v);

	// mac tx-disable
	v = rd32(hw, RNPM_MAC_TX_CFG(nr_lane));
	if (en_loopback)
		v &= ~(BIT(0)); // disable mac-tx
	else
		v |= (BIT(0)); // enable mac-tx
	wr32(hw, RNPM_MAC_TX_CFG(nr_lane), v);

	// mac rx-disable
	v = rd32(hw, RNPM_MAC_RX_CFG(nr_lane));
	if (en_loopback)
		v &= ~(BIT(0)); // disable mac-rx
	else
		v |= (BIT(0)); // enable mac-rx
	wr32(hw, RNPM_MAC_RX_CFG(nr_lane), v);

	return count;
}
static DEVICE_ATTR_WO(pcs_rx2tx_loopback);

static int do_switch_loopback_set(struct rnpm_adapter *adapter, int en,
				  int sport_lane, int dst_switch_port)
{
	int v;
	struct rnpm_hw *hw = &adapter->hw;

	e_dev_info("%s: %s %d -> %d en:%d\n", __func__,
		   netdev_name(adapter->netdev), sport_lane, dst_switch_port,
		   en);

	if (en)
		adapter->flags |= RNPM_FLAG_SWITCH_LOOPBACK_EN;
	else
		adapter->flags &= ~RNPM_FLAG_SWITCH_LOOPBACK_EN;

	// redir pkgs to peer
	wr32(hw, RNPM_ETH_INPORT_POLICY_REG(sport_lane),
	     BIT(29) | (dst_switch_port << 16));

	// enable/disable policy
	v = rd32(hw, RNPM_ETH_INPORT_POLICY_VAL);
	if (en)
		v |= BIT(sport_lane); // enable this-port-policy
	else
		v &= ~BIT(sport_lane);
	wr32(hw, RNPM_ETH_INPORT_POLICY_VAL, v);

	// mac promisc
	v = rd32(hw, RNPM_MAC_PKT_FLT(sport_lane));
	if (en)
		v |= (RNPM_RX_ALL | RNPM_RX_ALL_MUL);
	else
		v &= ~(RNPM_RX_ALL | RNPM_RX_ALL_MUL);
	wr32(hw, RNPM_MAC_PKT_FLT(sport_lane), v);

	return 0;
}

static int to_switch_port(struct rnpm_adapter *adapter)
{
	int switch_port = adapter->lane;

	if (rnpm_is_pf1(adapter->pdev))
		switch_port += 4;

	if (adapter->hw.mode == MODE_NIC_MODE_2PORT)
		if (adapter->lane != 0)
			switch_port += 1;

	return switch_port;
}

static ssize_t _switch_loopback(struct rnpm_adapter *adapter,
				const char *peer_eth, int en)
{
	struct net_device *peer_netdev = NULL;
	struct rnpm_adapter *peer_adapter = NULL;
	int i;
	char name[100];

	strncpy(name, peer_eth, sizeof(name));
	strim(name);

	peer_netdev = dev_get_by_name(&init_net, name);
	if (!peer_netdev) {
		e_dev_info("canot' find [%s]\n", name);
		return -EINVAL;
	}
	peer_adapter = netdev_priv(peer_netdev);

	// check if in same slot
	if (PCI_SLOT(peer_adapter->pdev->devfn) !=
	    PCI_SLOT(adapter->pdev->devfn)) {
		e_dev_info("%s %s not in same slot\n",
			   netdev_name(adapter->netdev),
			   netdev_name(peer_adapter->netdev));
		dev_put(peer_netdev);
		return -EINVAL;
	}

	e_dev_info("%s: %s(%d,%d) <-> %s(%d,%d) en:%d\n", __func__,
		   netdev_name(adapter->netdev), adapter->lane, adapter->port,
		   netdev_name(peer_adapter->netdev), peer_adapter->lane,
		   peer_adapter->port, en);

	/* clear pf0/pf1 input port policy eth reg */
	for (i = 0; i < MAX_PORT_NUM; i++) {
		wr32(&adapter->hw, RNPM_ETH_INPORT_POLICY_REG(i), 0);
		wr32(&peer_adapter->hw, RNPM_ETH_INPORT_POLICY_REG(i), 0);
	}

	wr32(&adapter->hw, RNPM_ETH_INPORT_POLICY_VAL, 0);
	wr32(&peer_adapter->hw, RNPM_ETH_INPORT_POLICY_VAL, 0);

	do_switch_loopback_set(adapter, en, adapter->lane,
			       to_switch_port(peer_adapter));

	do_switch_loopback_set(peer_adapter, en, peer_adapter->lane,
			       to_switch_port(adapter));

	if (peer_netdev)
		dev_put(peer_netdev);

	return 0;
}
static ssize_t switch_loopback_on_store(struct device *dev,
					struct device_attribute *attr,
					const char *buf, size_t count)
{
	struct rnpm_adapter *adapter = netdev_priv(to_net_device(dev));

	return _switch_loopback(adapter, buf, 1) == 0 ? count : -EINVAL;
}
static DEVICE_ATTR_WO(switch_loopback_on);

static ssize_t switch_loopback_off_store(struct device *dev,
					 struct device_attribute *attr,
					 const char *buf, size_t count)
{
	struct rnpm_adapter *adapter = netdev_priv(to_net_device(dev));

	return _switch_loopback(adapter, buf, 0) == 0 ? count : -EINVAL;
}
static DEVICE_ATTR_WO(switch_loopback_off);

static struct attribute *dev_attrs[] = {
	&dev_attr_root_slot_info.attr,
	&dev_attr_active_vid.attr,
	&dev_attr_pf_reset.attr,
	&dev_attr_ring_num.attr,
	&dev_attr_port_idx.attr,
	&dev_attr_vpd.attr,
	&dev_attr_nr_lane.attr,
	&dev_attr_temperature.attr,
	&dev_attr_si.attr,
	&dev_attr_sfp.attr,
	&dev_attr_autoneg.attr,
	&dev_attr_sfp_tx_disable.attr,
	&dev_attr_fec.attr,
	&dev_attr_link_traing.attr,
	&dev_attr_pci.attr,
	&dev_attr_prbs.attr,
	&dev_attr_debug_linkstat.attr,
	&dev_attr_debug_aptstat.attr,
	&dev_attr_tx_counter.attr,
	&dev_attr_rx_counter.attr,
	&dev_attr_bar4_reg.attr,
	&dev_attr_phy_statistics.attr,
	&dev_attr_pcs_reg.attr,
	&dev_attr_phy_reg.attr,
	&dev_attr_pma_rx2tx_loopback.attr,
	&dev_attr_pcs_rx2tx_loopback.attr,
	&dev_attr_switch_loopback_off.attr,
	&dev_attr_switch_loopback_on.attr,
	NULL,
};

#ifndef NO_BIT_ATTRS
static struct bin_attribute *dev_bin_attrs[] = {
	&bin_attr_maintain,
	NULL,
};
#endif
static struct attribute_group dev_attr_grp = {
	.attrs = dev_attrs,
#ifndef NO_BIT_ATTRS
	.bin_attrs = dev_bin_attrs,
#endif
};

/* hwmon callback functions */
static ssize_t rnpm_hwmon_show_location(struct device __always_unused *dev,
					struct device_attribute *attr,
					char *buf)
{
	struct hwmon_attr *rnpm_attr =
		container_of(attr, struct hwmon_attr, dev_attr);

	return snprintf(buf, PAGE_SIZE, "loc%u\n", rnpm_attr->sensor->location);
}

static ssize_t rnpm_hwmon_show_name(struct device __always_unused *dev,
				    struct device_attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "rnpm\n");
}

static ssize_t rnpm_hwmon_show_temp(struct device __always_unused *dev,
				    struct device_attribute *attr, char *buf)
{
	struct hwmon_attr *rnpm_attr =
		container_of(attr, struct hwmon_attr, dev_attr);
	unsigned int value;

	/* reset the temp field */
	rnpm_attr->hw->mac.ops.get_thermal_sensor_data(rnpm_attr->hw);

	value = rnpm_attr->sensor->temp;
	/* display millidegree */
	value *= 1000;

	return snprintf(buf, PAGE_SIZE, "%u\n", value);
}

static ssize_t rnpm_hwmon_show_cautionthresh(struct device __always_unused *dev,
					     struct device_attribute *attr,
					     char *buf)
{
	struct hwmon_attr *rnpm_attr =
		container_of(attr, struct hwmon_attr, dev_attr);
	unsigned int value = rnpm_attr->sensor->caution_thresh;
	/* display millidegree */
	value *= 1000;

	return snprintf(buf, PAGE_SIZE, "%u\n", value);
}

static ssize_t rnpm_hwmon_show_maxopthresh(struct device __always_unused *dev,
					   struct device_attribute *attr,
					   char *buf)
{
	struct hwmon_attr *rnpm_attr =
		container_of(attr, struct hwmon_attr, dev_attr);
	unsigned int value = rnpm_attr->sensor->max_op_thresh;

	/* display millidegree */
	value *= 1000;

	return snprintf(buf, PAGE_SIZE, "%u\n", value);
}

/**
 * rnpm_add_hwmon_attr - Create hwmon attr table for a hwmon sysfs file.
 * @adapter: pointer to the adapter structure
 * @offset: offset in the eeprom sensor data table
 * @type: type of sensor data to display
 *
 * For each file we want in hwmon's sysfs interface we need a device_attribute
 * This is included in our hwmon_attr struct that contains the references to
 * the data structures we need to get the data to display.
 */
static int rnpm_add_hwmon_attr(struct rnpm_adapter *adapter,
			       unsigned int offset, int type)
{
	unsigned int n_attr;
	struct hwmon_attr *rnpm_attr;

	n_attr = adapter->rnpm_hwmon_buff->n_hwmon;
	rnpm_attr = &adapter->rnpm_hwmon_buff->hwmon_list[n_attr];

	switch (type) {
	case RNPM_HWMON_TYPE_LOC:
		rnpm_attr->dev_attr.show = rnpm_hwmon_show_location;
		snprintf(rnpm_attr->name, sizeof(rnpm_attr->name),
			 "temp%u_label", offset + 1);

		break;
	case RNPM_HWMON_TYPE_NAME:
		rnpm_attr->dev_attr.show = rnpm_hwmon_show_name;
		snprintf(rnpm_attr->name, sizeof(rnpm_attr->name), "name");

		break;
	case RNPM_HWMON_TYPE_TEMP:
		rnpm_attr->dev_attr.show = rnpm_hwmon_show_temp;
		snprintf(rnpm_attr->name, sizeof(rnpm_attr->name),
			 "temp%u_input", offset + 1);

		break;
	case RNPM_HWMON_TYPE_CAUTION:
		rnpm_attr->dev_attr.show = rnpm_hwmon_show_cautionthresh;
		snprintf(rnpm_attr->name, sizeof(rnpm_attr->name), "temp%u_max",
			 offset + 1);

		break;
	case RNPM_HWMON_TYPE_MAX:
		rnpm_attr->dev_attr.show = rnpm_hwmon_show_maxopthresh;
		snprintf(rnpm_attr->name, sizeof(rnpm_attr->name),
			 "temp%u_crit", offset + 1);

		break;
	default:
		return -EPERM;
	}

	/* These always the same regardless of type */
	rnpm_attr->sensor = &adapter->hw.mac.thermal_sensor_data.sensor[offset];
	rnpm_attr->hw = &adapter->hw;
	rnpm_attr->dev_attr.store = NULL;
	rnpm_attr->dev_attr.attr.mode = 0444;
	rnpm_attr->dev_attr.attr.name = rnpm_attr->name;

	sysfs_attr_init(&rnpm_attr->dev_attr.attr);

	adapter->rnpm_hwmon_buff->attrs[n_attr] = &rnpm_attr->dev_attr.attr;

	++adapter->rnpm_hwmon_buff->n_hwmon;

	return 0;
}

static void rnpm_sysfs_del_adapter(struct rnpm_adapter __maybe_unused *adapter)
{
}

/* called from rnpm_main.c */
void rnpm_sysfs_exit(struct rnpm_adapter *adapter)
{
	rnpm_sysfs_del_adapter(adapter);
	sysfs_remove_group(&adapter->netdev->dev.kobj, &dev_attr_grp);
}

/* called from rnpm_main.c */
int rnpm_sysfs_init(struct rnpm_adapter *adapter, int port)
{
	int err, rc = 0;
	struct hwmon_buff *rnpm_hwmon;
	struct device *hwmon_dev;
	unsigned int i;

	err = sysfs_create_group(&adapter->netdev->dev.kobj, &dev_attr_grp);
	if (err != 0) {
		dev_err(&adapter->netdev->dev,
			"sysfs_create_group faild:err:%d\n", err);
		return err;
	}
	/* only  port0 and pcie devfn all both 0 register temperature hwmon */
	if (!!port || !!adapter->pdev->devfn)
		goto exit;

	/* If this method isn't defined we don't support thermals */
	if (adapter->hw.mac.ops.init_thermal_sensor_thresh == NULL)
		goto no_thermal;

	/* Don't create thermal hwmon interface if no sensors present */
	if (adapter->hw.mac.ops.init_thermal_sensor_thresh(&adapter->hw))
		goto no_thermal;

	rnpm_hwmon = devm_kzalloc(&adapter->pdev->dev, sizeof(*rnpm_hwmon),
				  GFP_KERNEL);

	if (!rnpm_hwmon) {
		rc = -ENOMEM;
		goto exit;
	}

	adapter->rnpm_hwmon_buff = rnpm_hwmon;

	/* TODO: Only support one sensor now */
	for (i = 0; i < RNPM_MAX_SENSORS; i++) {
		/*
		 * Only create hwmon sysfs entries for sensors that have
		 * meaningful data for.
		 */
		if (adapter->hw.mac.thermal_sensor_data.sensor[i].location == 0)
			continue;

		/* Bail if any hwmon attr struct fails to initialize */
		rc = rnpm_add_hwmon_attr(adapter, i, RNPM_HWMON_TYPE_CAUTION);
		if (rc)
			goto err;
		rc = rnpm_add_hwmon_attr(adapter, i, RNPM_HWMON_TYPE_TEMP);
		if (rc)
			goto err;
		rc = rnpm_add_hwmon_attr(adapter, i, RNPM_HWMON_TYPE_MAX);
		if (rc)
			goto err;
	}

	rnpm_hwmon->groups[0] = &rnpm_hwmon->group;
	rnpm_hwmon->group.attrs = rnpm_hwmon->attrs;

	hwmon_dev = devm_hwmon_device_register_with_groups(
		&adapter->pdev->dev, "rnpm", rnpm_hwmon, rnpm_hwmon->groups);

	if (IS_ERR(hwmon_dev)) {
		rc = PTR_ERR(hwmon_dev);
		goto exit;
	}
no_thermal:
	goto exit;
err:
	rnpm_sysfs_del_adapter(adapter);
exit:
	return rc;
}
