// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2020 - 2026 Mucse Corporation. */
#include "mcevf.h"
#include "mcevf_netdev.h"
#include "mcevf_txrx_lib.h"
#include "mcevf_lib.h"
#include <linux/module.h>
#include <linux/types.h>
#include <linux/ctype.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/device.h>
#include <linux/netdevice.h>
#include <linux/time.h>
#include <linux/inet.h>

#define mcevf_dev_to_netdev(n) container_of(n, struct net_device, dev)

static ssize_t pf_vlan_show(struct device *dev, struct device_attribute *attr,
			    char *buf)
{
	struct net_device *netdev = mcevf_dev_to_netdev(dev);
	struct mcevf_pf *pf = mcevf_netdev_to_pf(netdev);
	int ret = 0;

	ret = sprintf(buf, "pf set vf vlan:%d\n", pf->vf_vlan);
	return ret;
}

static int __print_desc(char *buf, size_t size, void *data, int len)
{
	u8 *ptr = (u8 *)data;
	int ret = 0;
	int i;

	for (i = 0; i < len; i++)
		ret += scnprintf(buf + ret, size - ret, "%02x ", *(ptr + i));

	return ret;
}

static struct netdev_queue *__mcevf_txring_txq(const struct mcevf_ring *ring)
{
	return netdev_get_tx_queue(ring->netdev, ring->q_index);
}

static ssize_t txring_info_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct net_device *netdev = mcevf_dev_to_netdev(dev);
	struct mcevf_pf *pf = mcevf_netdev_to_pf(netdev);
	struct mcevf_vsi *vsi = mcevf_get_main_vsi(pf);
	struct mcevf_ring *tx_ring = NULL;
	struct mcevf_tx_buf *tx_buf = NULL;
	struct mcevf_tx_desc *eop_desc;
	int s_id, e_id;
	int ret = 0, i;
#define __DMA_REG_TX_DESC_HEAD (0x6c)
#define __DMA_REG_TX_DESC_TAIL (0x70)

	if (!pf->d_ringinfo.txring_valid)
		return scnprintf(buf, PAGE_SIZE,
				 "error: need setup debug tx ring num range first\n");

	if (!vsi || !vsi->tx_rings)
		return -ENODEV;

	s_id = pf->d_ringinfo.txring_start;
	e_id = pf->d_ringinfo.txring_end;
	for (i = s_id; i <= e_id; i++) {
		struct netdev_queue *q;
		struct dql *dql;

		if (i < 0 || i >= vsi->num_txq) {
			ret += scnprintf(buf + ret, PAGE_SIZE - ret,
					 "error: tx queue id:%d larger than num_txq:%d, exit!\n",
					 i, vsi->num_txq);
			break;
		}

		tx_ring = vsi->tx_rings[i];
		if (!tx_ring)
			continue;
		q = __mcevf_txring_txq(tx_ring);
		dql = &q->dql;
		ret += scnprintf(buf + ret, PAGE_SIZE - ret,
				 "====== tx ring num %d info: ======\n", i);
		ret += scnprintf(buf + ret, PAGE_SIZE - ret,
				 "BQL queue state:0x%lx:\n", q->state);
		ret += scnprintf(buf + ret, PAGE_SIZE - ret,
				 "1: num_queued:%u adj_limit:%u limit:%u\n",
				 dql->num_queued, dql->adj_limit, dql->limit);
		ret += scnprintf(buf + ret, PAGE_SIZE - ret,
				 "2: num_completed:%u p_ovlimit:%u p_num_queued:%u\n",
				 dql->num_completed, dql->prev_ovlimit,
				 dql->prev_num_queued);
		ret += scnprintf(buf + ret, PAGE_SIZE - ret,
				 "3: max_limit:%u min_limit:%u\n",
				 dql->max_limit, dql->min_limit);
		ret += scnprintf(buf + ret, PAGE_SIZE - ret,
				 "next_to_use: %d\n", tx_ring->next_to_use);
		ret += scnprintf(buf + ret, PAGE_SIZE - ret,
				 "next_to_clean: %d\n",
				 tx_ring->next_to_clean);
		ret += scnprintf(buf + ret, PAGE_SIZE - ret,
				 "hw_head: %d   hw_tail: %d\n",
				 ring_rd32(tx_ring, __DMA_REG_TX_DESC_HEAD),
				 ring_rd32(tx_ring, __DMA_REG_TX_DESC_TAIL));
		tx_buf = &tx_ring->tx_buf[tx_ring->next_to_clean];
		eop_desc = tx_buf->next_to_watch;
		if (eop_desc) {
			ret += scnprintf(buf + ret, PAGE_SIZE - ret,
					 "next_to_watch:\n");
			ret += __print_desc(buf + ret, PAGE_SIZE - ret,
					    eop_desc, sizeof(*eop_desc));
			ret += scnprintf(buf + ret, PAGE_SIZE - ret, "\n");
		} else {
			ret += scnprintf(buf + ret, PAGE_SIZE - ret,
					 "next_to_watch: no\n");
		}
		if (ret >= PAGE_SIZE - 1)
			break;
	}

	return ret;
}

static ssize_t txring_info_store(struct device *dev,
				 struct device_attribute *attr, const char *buf,
				 size_t count)
{
	struct net_device *netdev = mcevf_dev_to_netdev(dev);
	struct mcevf_pf *pf = mcevf_netdev_to_pf(netdev);
	struct mcevf_vsi *vsi = mcevf_get_main_vsi(pf);
	int s_id, e_id, cnt;

	if (!vsi)
		return -ENODEV;

	/* start ring id + end ring id */
	cnt = sscanf(buf, "%d %d", &s_id, &e_id);
	if (cnt != 2 || s_id < 0 || s_id > e_id)
		return -EINVAL;
	if (e_id >= vsi->num_txq)
		return -EINVAL;
	pf->d_ringinfo.txring_start = s_id;
	pf->d_ringinfo.txring_end = e_id;
	pf->d_ringinfo.txring_valid = true;
	return count;
}

static ssize_t rxring_info_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct net_device *netdev = mcevf_dev_to_netdev(dev);
	struct mcevf_pf *pf = mcevf_netdev_to_pf(netdev);
	struct mcevf_vsi *vsi = mcevf_get_main_vsi(pf);
	struct mcevf_ring *rx_ring = NULL;
	struct mcevf_rx_desc_up *rx_desc = NULL;
	int s_id, e_id;
	int ret = 0, i;
#define __DMA_REG_RX_DESC_HEAD (0x3c)
#define __DMA_REG_RX_DESC_TAIL (0x40)

	if (!pf->d_ringinfo.rxring_valid)
		return scnprintf(buf, PAGE_SIZE,
				 "error: need setup debug rx ring num range first\n");

	if (!vsi || !vsi->rx_rings)
		return -ENODEV;

	s_id = pf->d_ringinfo.rxring_start;
	e_id = pf->d_ringinfo.rxring_end;
	for (i = s_id; i <= e_id; i++) {
		if (i < 0 || i >= vsi->num_rxq) {
			ret += scnprintf(buf + ret, PAGE_SIZE - ret,
					 "error: rx queue id:%d larger than num_rxq:%d, exit!\n",
					 i, vsi->num_rxq);
			break;
		}

		rx_ring = vsi->rx_rings[i];
		if (!rx_ring)
			continue;
		ret += scnprintf(buf + ret, PAGE_SIZE - ret,
				 "====== rx ring num %d info: ======\n", i);
		ret += scnprintf(buf + ret, PAGE_SIZE - ret,
				 "next_to_use: %d\n", rx_ring->next_to_use);
		ret += scnprintf(buf + ret, PAGE_SIZE - ret,
				 "next_to_clean: %d\n",
				 rx_ring->next_to_clean);
		ret += scnprintf(buf + ret, PAGE_SIZE - ret,
				 "hw_head: %d   hw_tail: %d\n",
				 ring_rd32(rx_ring, __DMA_REG_RX_DESC_HEAD),
				 ring_rd32(rx_ring, __DMA_REG_RX_DESC_TAIL));
		rx_desc = MCEVF_RXDESC_UP(rx_ring, rx_ring->next_to_clean);
		if (rx_desc) {
			ret += scnprintf(buf + ret, PAGE_SIZE - ret,
					 "next_to_clean desc:\n");
			ret += __print_desc(buf + ret, PAGE_SIZE - ret,
					    rx_desc, sizeof(*rx_desc));
			ret += scnprintf(buf + ret, PAGE_SIZE - ret, "\n");
		} else {
			ret += scnprintf(buf + ret, PAGE_SIZE - ret,
					 "next_to_clean desc: no\n");
		}
		ret += scnprintf(buf + ret, PAGE_SIZE - ret,
				 "unused desc: %d\n",
				 MCEVF_DESC_UNUSED(rx_ring));
		if (ret >= PAGE_SIZE - 1)
			break;
	}
	return ret;
}

static ssize_t rxring_info_store(struct device *dev,
				 struct device_attribute *attr, const char *buf,
				 size_t count)
{
	struct net_device *netdev = mcevf_dev_to_netdev(dev);
	struct mcevf_pf *pf = mcevf_netdev_to_pf(netdev);
	struct mcevf_vsi *vsi = mcevf_get_main_vsi(pf);
	int s_id, e_id, cnt;

	if (!vsi)
		return -ENODEV;

	/* start ring id + end ring id */
	cnt = sscanf(buf, "%d %d", &s_id, &e_id);
	if (cnt != 2 || s_id < 0 || s_id > e_id)
		return -EINVAL;
	if (e_id >= vsi->num_rxq)
		return -EINVAL;
	pf->d_ringinfo.rxring_start = s_id;
	pf->d_ringinfo.rxring_end = e_id;
	pf->d_ringinfo.rxring_valid = true;
	return count;
}

static ssize_t txring_trig_intr_store(struct device *dev,
				      struct device_attribute *attr,
				      const char *buf, size_t count)
{
	struct net_device *netdev = mcevf_dev_to_netdev(dev);
	struct mcevf_pf *pf = mcevf_netdev_to_pf(netdev);
	struct mcevf_hw *hw = &pf->hw;
	struct mcevf_vsi *vsi = mcevf_get_main_vsi(pf);
	int ring_id, i;

	/* start ring id + end ring id */
	if (kstrtoint(buf, 10, &ring_id) || ring_id >= vsi->num_txq ||
	    ring_id < 0)
		return -EINVAL;
	mcevf_for_each_q_vector(vsi, i) {
		struct mcevf_q_vector *q_vector = vsi->q_vectors[i];
		struct mcevf_ring *tx_ring;

		if (i != ring_id)
			continue;
		mcevf_rc_for_each_ring(tx_ring, q_vector->tx) {
			hw->ops->set_txring_trig_intr(tx_ring);
		}
	}
	return count;
}

static ssize_t pf_reset_store(struct device *dev, struct device_attribute *attr,
			      const char *buf, size_t count)
{
	struct net_device *netdev = mcevf_dev_to_netdev(dev);
	struct mcevf_pf *pf = mcevf_netdev_to_pf(netdev);

	mcevf_pf_flags_reset_set(pf);
	return count;
}

static ssize_t rss_mode_order_show(struct device *dev,
				   struct device_attribute *attr, char *buf)
{
	struct net_device *netdev = mcevf_dev_to_netdev(dev);
	struct mcevf_pf *pf = mcevf_netdev_to_pf(netdev);
	int ret = 0;
	bool on;

	on = !!test_bit(MCEVF_FLAG_RSS_MODE_ORDER, pf->flags);
	ret += sprintf(buf, "rss mode order: %s\n", on ? "yes" : "no");
	return ret;
}

static ssize_t rss_mode_order_store(struct device *dev,
				    struct device_attribute *attr,
				    const char *buf, size_t count)
{
	struct net_device *netdev = mcevf_dev_to_netdev(dev);
	struct mcevf_pf *pf = mcevf_netdev_to_pf(netdev);
	struct mcevf_hw *hw = &pf->hw;
	int on;

	if (kstrtos32(buf, 10, &on))
		return -EINVAL;

	if (!!on)
		set_bit(MCEVF_FLAG_RSS_MODE_ORDER, pf->flags);
	else
		clear_bit(MCEVF_FLAG_RSS_MODE_ORDER, pf->flags);
	hw->ops->set_rss_hash(hw, netdev->features);
	return count;
}

static const char *const logd_lvl_names[LOG_NET_MAX] = {
	[LOG_MBX_IN_REQ] = "MBX_IN_REQ", /* 0 */
	[LOG_MBX_REQ_OUT] = "MBX_REQ_OUT", /* 1 */
	[LOG_VECTOR_ALLOC] = "VECTOR_ALLOC", /* 2 */
	[LOG_MISC_IRQ] = "MISC_IRQ", /* 3*/
	[LOG_QUEUE_INFO] = "QUEUE_INFO", /* 4*/
};

//BUILD_BUG_ON(ARRAY_SIZE(logd_lvl_names) != LOG_NET_MAX);

static ssize_t logd_lvl_show(struct device *dev, struct device_attribute *attr,
			     char *buf)
{
	int ret = 0, i;

	ret += sprintf(buf + ret, "logd_lvl:0x%x\n", mcevf_loglevel);
	for (i = 0; i < LOG_NET_MAX; i++) {
		ret += sprintf(buf + ret, "i:%d %s %s\n", i, logd_lvl_names[i],
			       !!(mcevf_loglevel & BIT(i)) ? "on" : "off");
	}

	return ret;
}

static ssize_t logd_lvl_store(struct device *dev, struct device_attribute *attr,
			      const char *buf, size_t count)
{
	struct net_device *netdev = mcevf_dev_to_netdev(dev);
	int logd_idx, en, cnt;

	cnt = sscanf(buf, "%d %d", &logd_idx, &en);
	if (cnt != 2 || logd_idx >= LOG_NET_MAX) {
		netdev_info(netdev, "logd_lvl: logd_idx <en 0|1>\n");
		return -EINVAL;
	}

	if (en)
		mcevf_loglevel |= BIT(logd_idx);
	else
		mcevf_loglevel &= ~BIT(logd_idx);
	return count;
}

static ssize_t ipv4_conflict_show(struct device *dev,
				  struct device_attribute *attr, char *buf)
{
	struct net_device *netdev = mcevf_dev_to_netdev(dev);
	struct mcevf_pf *pf = mcevf_netdev_to_pf(netdev);
	char ip_str[16];
	int ret = 0;

	snprintf(ip_str, sizeof(ip_str), "%pI4", &pf->ipv4_addr);

	ret += sprintf(buf + ret,
		       "%s %s conflicted with other vf IPv4 addresses\n",
		       ip_str, pf->ipv4_addr_conflict ? "is" : "not");
	return ret;
}

static ssize_t ipv4_conflict_store(struct device *dev,
				   struct device_attribute *attr,
				   const char *buf, size_t count)
{
	struct net_device *netdev = mcevf_dev_to_netdev(dev);
	struct mcevf_pf *pf = mcevf_netdev_to_pf(netdev);
	struct mcevf_hw *hw = &pf->hw;
	__be32 ipv4_addr = 0;
	u32 addr[4], cnt;
	int err;

	/* Parse IPv4 address - accept format like "192.168.10.0" */
	cnt = sscanf(buf, "%u.%u.%u.%u", &addr[0], &addr[1], &addr[2],
		     &addr[3]);
	if (cnt != 4) {
		netdev_info(netdev,
			    "Invalid IPv4 address format, expected: x.x.x.x\n");
		return -EINVAL;
	}

	/* Validate each octet is in valid range */
	if (addr[0] > 255 || addr[1] > 255 || addr[2] > 255 || addr[3] > 255) {
		netdev_info(netdev,
			    "IPv4 address octet out of range (0-255)\n");
		return -EINVAL;
	}

	/* Store as 32-bit integer in network byte order */
	ipv4_addr = (addr[0] << 24) | (addr[1] << 16) | (addr[2] << 8) |
		    addr[3];
	ipv4_addr = htonl(ipv4_addr);
	err = hw->virtchnl.ops->check_mbx_ipv4_addr_conflict(hw, ipv4_addr);
	pf->ipv4_addr_conflict = !!err;
	pf->ipv4_addr = ipv4_addr;
	netdev_info(netdev, "IPv4 address: %pI4 conflict:%d\n", &pf->ipv4_addr,
		    pf->ipv4_addr_conflict);

	return count;
}

#define MCEVF_SYSFS_RSS_MISC_TYPE_PTP_BIT_MSK BIT(0)
#define MCEVF_SYSFS_RSS_MISC_TYPE_IPV4_SPI_BIT_MSK BIT(1)
#define MCEVF_SYSFS_RSS_MISC_TYPE_IPV6_SPI_BIT_MSK BIT(2)
#define MCEVF_SYSFS_RSS_MISC_TYPE_IPV4_TEID_BIT_MSK BIT(3)
#define MCEVF_SYSFS_RSS_MISC_TYPE_IPV6_TEID_BIT_MSK BIT(4)

static ssize_t rss_misc_type_show(struct device *dev,
				  struct device_attribute *attr, char *buf)
{
	struct net_device *netdev = mcevf_dev_to_netdev(dev);
	struct mcevf_pf *pf = mcevf_netdev_to_pf(netdev);
	int ret = 0;
	bool on;

	ret += sprintf(buf + ret, "rss misc type bitmask:\n");
	ret += sprintf(buf + ret, "\tptp:       bit0\n");
	ret += sprintf(buf + ret, "\tipv4 spi:  bit1\n");
	ret += sprintf(buf + ret, "\tipv6 spi:  bit2\n");
	ret += sprintf(buf + ret, "\tipv4 teid: bit3\n");
	ret += sprintf(buf + ret, "\tipv6 teid: bit4\n");

	ret += sprintf(buf + ret, "\nrss misc type status:\n");
	on = !!test_bit(MCEVF_FLAG_RSS_MISC_TYPE_PTP, pf->flags);
	ret += sprintf(buf + ret, "ptp: %s\n", on ? "yes" : "no");

	on = !!test_bit(MCEVF_FLAG_RSS_MISC_TYPE_IPV4_SPI, pf->flags);
	ret += sprintf(buf + ret, "ipv4 spi: %s\n", on ? "yes" : "no");

	on = !!test_bit(MCEVF_FLAG_RSS_MISC_TYPE_IPV6_SPI, pf->flags);
	ret += sprintf(buf + ret, "ipv6 spi: %s\n", on ? "yes" : "no");

	on = !!test_bit(MCEVF_FLAG_RSS_MISC_TYPE_IPV4_TEID, pf->flags);
	ret += sprintf(buf + ret, "ipv4 teid: %s\n", on ? "yes" : "no");

	on = !!test_bit(MCEVF_FLAG_RSS_MISC_TYPE_IPV6_TEID, pf->flags);
	ret += sprintf(buf + ret, "ipv6 teid: %s\n", on ? "yes" : "no");
	return ret;
}

static ssize_t rss_misc_type_store(struct device *dev,
				   struct device_attribute *attr,
				   const char *buf, size_t count)
{
	struct net_device *netdev = mcevf_dev_to_netdev(dev);
	struct mcevf_pf *pf = mcevf_netdev_to_pf(netdev);
	struct mcevf_hw *hw = &pf->hw;
	int bit_msk;

	if (kstrtos32(buf, 10, &bit_msk))
		return -EINVAL;

	if (bit_msk & MCEVF_SYSFS_RSS_MISC_TYPE_PTP_BIT_MSK)
		set_bit(MCEVF_FLAG_RSS_MISC_TYPE_PTP, pf->flags);
	else
		clear_bit(MCEVF_FLAG_RSS_MISC_TYPE_PTP, pf->flags);

	if (bit_msk & MCEVF_SYSFS_RSS_MISC_TYPE_IPV4_SPI_BIT_MSK)
		set_bit(MCEVF_FLAG_RSS_MISC_TYPE_IPV4_SPI, pf->flags);
	else
		clear_bit(MCEVF_FLAG_RSS_MISC_TYPE_IPV4_SPI, pf->flags);

	if (bit_msk & MCEVF_SYSFS_RSS_MISC_TYPE_IPV6_SPI_BIT_MSK)
		set_bit(MCEVF_FLAG_RSS_MISC_TYPE_IPV6_SPI, pf->flags);
	else
		clear_bit(MCEVF_FLAG_RSS_MISC_TYPE_IPV6_SPI, pf->flags);

	if (bit_msk & MCEVF_SYSFS_RSS_MISC_TYPE_IPV4_TEID_BIT_MSK)
		set_bit(MCEVF_FLAG_RSS_MISC_TYPE_IPV4_TEID, pf->flags);
	else
		clear_bit(MCEVF_FLAG_RSS_MISC_TYPE_IPV4_TEID, pf->flags);

	if (bit_msk & MCEVF_SYSFS_RSS_MISC_TYPE_IPV6_TEID_BIT_MSK)
		set_bit(MCEVF_FLAG_RSS_MISC_TYPE_IPV6_TEID, pf->flags);
	else
		clear_bit(MCEVF_FLAG_RSS_MISC_TYPE_IPV6_TEID, pf->flags);

	hw->ops->set_rss_hash_type(hw);
	return count;
}

static DEVICE_ATTR_RO(pf_vlan);
static DEVICE_ATTR_RW(txring_info);
static DEVICE_ATTR_RW(rxring_info);
static DEVICE_ATTR_WO(txring_trig_intr);
static DEVICE_ATTR_WO(pf_reset);
static DEVICE_ATTR_RW(rss_mode_order);
static DEVICE_ATTR_RW(rss_misc_type);
static DEVICE_ATTR_RW(logd_lvl);
static DEVICE_ATTR_RW(ipv4_conflict);

static struct attribute *dev_attrs[] = {
	&dev_attr_pf_vlan.attr,
	// &dev_attr_set_dvlan.attr,
	&dev_attr_txring_info.attr,
	&dev_attr_rxring_info.attr,
	&dev_attr_txring_trig_intr.attr,
	&dev_attr_pf_reset.attr,
	&dev_attr_rss_mode_order.attr,
	/* ptp/spi/teid */
	&dev_attr_rss_misc_type.attr,
	&dev_attr_logd_lvl.attr,
	&dev_attr_ipv4_conflict.attr,
	NULL,
};

static struct attribute_group dev_attr_grp = {
	.attrs = dev_attrs,
};

void mcevf_sysfs_exit(struct mcevf_pf *pf)
{
	struct net_device *netdev = pf->vsi[0]->netdev;

	sysfs_remove_group(&netdev->dev.kobj, &dev_attr_grp);
}

int mcevf_sysfs_init(struct mcevf_pf *pf)
{
	struct net_device *netdev = pf->vsi[0]->netdev;
	int err = 0;

	err = sysfs_create_group(&netdev->dev.kobj, &dev_attr_grp);
	if (err)
		dev_err(mcevf_pf_to_dev(pf), "Failed to create sysfs group\n");
	return err;
}
