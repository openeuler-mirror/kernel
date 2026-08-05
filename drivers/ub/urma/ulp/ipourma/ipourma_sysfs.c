// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
 *
 * Description: ipourma sysfs support
 */
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/kernel.h>

#include "ipourma_sysfs.h"

// sysfs support for hard_header_len
static ssize_t hard_header_len_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct net_device *ndev = to_net_dev(dev);

	return sysfs_emit(buf, "%u\n", ndev->hard_header_len);
}

static DEVICE_ATTR_RO(hard_header_len);

// sysfs support for urma_mtu
static ssize_t urma_mtu_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct net_device *ndev = to_net_dev(dev);
	struct ipourma_dev_priv *priv = netdev_priv(ndev);

	return sysfs_emit(buf, "%u\n", priv->urma_mtu);
}

static DEVICE_ATTR_RO(urma_mtu);

// sysfs support for ipourma_tx_ring_size
static ssize_t ipourma_tx_ring_size_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%d\n", ipourma_tx_ring_size);
}

static DEVICE_ATTR_RO(ipourma_tx_ring_size);

// sysfs support for ipourma_rx_ring_size
static ssize_t ipourma_rx_ring_size_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%d\n", ipourma_rx_ring_size);
}

static DEVICE_ATTR_RO(ipourma_rx_ring_size);

/*
 * Description of status_name:
 * The size of this array must be equal to IPOURMA_MAX_CR_STATUS
 * The order of strings must be consistent with the members of ubcore_cr_status in ubcore_opcode.h
 */
static const char * const status_names[] = {
	"SUCCESS",
	"UNSUPPORTED_OPCODE_ERR",
	"LOC_LEN_ERR",
	"LOC_OPERATION_ERR",
	"LOC_ACCESS_ERR",
	"REM_RESP_LEN_ERR",
	"REM_UNSUPPORTED_REQ_ERR",
	"REM_OPERATION_ERR",
	"REM_ACCESS_ABORT_ERR",
	"ACK_TIMEOUT_ERR",
	"RNR_RETRY_CNT_EXC_ERR",
	"FLUSH_ERR",
	"WR_SUSPEND_DONE",
	"WR_FLUSH_ERR_DONE",
	"WR_UNHANDLED",
	"LOC_DATA_POISON",
	"REM_DATA_POISON"
};
_Static_assert(ARRAY_SIZE(status_names) == IPOURMA_MAX_CR_STATUS,
		"ipourma: the length of status_names mismatch with IPOURMA_MAX_CR_STATUS!");

/*
 * Sysfs_emit is used to format the attribute string to the buffer and the
 * return value is checked.Returns of Sysfs_emit in formmer functions are
 * not checked because there only outputs one attribute.
 * Here, dozens of attributes are output to one buffer, which may exceed the
 * value of PAGE_SIZE.Therefore, the return value ret needs to be determined.
 */
static ssize_t format_stats(char *buf, struct ipourma_dev_priv *priv, ssize_t buf_size)
{
	ssize_t len = 0;
	ssize_t ret;

	struct ipourma_tx_stats *ptx = &priv->runtime_stats.tx_stats;
	struct ipourma_rx_stats *prx = &priv->runtime_stats.rx_stats;
	/*
	 * The sysfs_emit batch accumulation feature is used to write multiple
	 * attributes in batches,reducing the number of function invoking times
	 * and the number of return value judgment.Note that the cqe_status is
	 * an array whose size is dynamically controlled.Therefore, the cqe_status
	 * attribute is implemented by cyclic writing.
	 */
	ret = sysfs_emit(buf,
			"==tx_stats==\n"
			"/* start xmit */\n"
			"num_recv_pkts_from_kernel: %llu\n"
			"post_send_enque: %llu\n"
			"post_send_bypass: %llu\n"
			"gso_not_support: %llu\n"
			"packet_size_error: %llu\n"
			"frag_error: %llu\n"
			"not_ipv6_proto: %llu\n"
			"not_ipv6_addr: %llu\n"
			"ip_eid_not_equal: %llu\n"
			"tx_ring_full: %llu\n\n"
			"/* post send */\n"
			"post_send_start: %llu\n"
			"num_import_jetty_real: %llu\n"
			"num_import_jetty_bypass: %llu\n"
			"num_tjetty_hash_hit: %llu\n"
			"linear_len_oversize: %llu\n"
			"import_jetty_failed: %llu\n"
			"send_wr_failed: %llu\n\n"
			"/* pass to ub */\n"
			"pass_to_ub: %llu\n\n"
			"/* tx cqe notify */\n"
			"cqe_notify: %llu\n\n"
			"/* tx poll */\n"
			"num_napi_tx: %llu\n"
			"cqe_recved: %llu\n"
			"cqe_success: %llu\n"
			"cqe_err: %llu\n"
			"flush_jetty_success: %llu\n"
			"+-cqe_status\n",
			ptx->num_recv_pkts_from_kernel,
			ptx->post_send_enque,
			ptx->post_send_bypass,
			ptx->gso_not_support,
			ptx->packet_size_error,
			ptx->frag_error,
			ptx->not_ipv6_proto,
			ptx->not_ipv6_addr,
			ptx->ip_eid_not_equal,
			ptx->tx_ring_full,
			ptx->post_send_start,
			ptx->num_import_jetty_real,
			ptx->num_import_jetty_bypass,
			ptx->num_tjetty_hash_hit,
			ptx->linear_len_oversize,
			ptx->import_jetty_failed,
			ptx->send_wr_failed,
			ptx->pass_to_ub,
			ptx->cqe_notify,
			ptx->num_napi_tx,
			ptx->cqe_recved,
			ptx->cqe_success,
			ptx->cqe_err,
			ptx->flush_jetty_success);
	if (ret < 0 || ret >= buf_size)
		goto FORMAT_ERR;

	len += ret;
	for (int i = 0; i < IPOURMA_MAX_CR_STATUS; i++) {
		ret = sysfs_emit_at(buf, len, "--%s: %llu\n", status_names[i], ptx->cqe_stats[i]);
		if (ret < 0 || ret + len >= buf_size)
			goto FORMAT_ERR;
		len += ret;
	}

	ret = sysfs_emit_at(buf, len,
			"poll_jfc_success: %llu\n"
			"poll_jfc_failed: %llu\n"
			"rearm_success: %llu\n"
			"rearm_failed: %llu\n\n\n"
			"==rx_stats==\n"
			"/* rx cqe notify */\n"
			"cqe_notify: %llu\n\n"
			"/* rx poll */\n"
			"num_napi_rx: %llu\n"
			"rx_enque: %llu\n"
			"rx_deque: %llu\n"
			"cqe_recved: %llu\n"
			"cqe_success: %llu\n"
			"cqe_err: %llu\n"
			"+-cqe_status\n",
			ptx->poll_jfc_success,
			ptx->poll_jfc_failed,
			ptx->rearm_success,
			ptx->rearm_failed,
			prx->cqe_notify,
			prx->num_napi_rx,
			prx->rx_enque,
			prx->rx_deque,
			prx->cqe_recved,
			prx->cqe_success,
			prx->cqe_err);
	if (ret < 0 || ret + len >= buf_size)
		goto FORMAT_ERR;
	len += ret;

	for (int i = 0; i < IPOURMA_MAX_CR_STATUS; i++) {
		ret = sysfs_emit_at(buf, len, "--%s: %llu\n", status_names[i], prx->cqe_stats[i]);
		if (ret < 0 || ret + len >= buf_size)
			goto FORMAT_ERR;
		len += ret;
	}

	ret = sysfs_emit_at(buf, len,
		"poll_jfc_success: %llu\n"
		"poll_jfc_failed: %llu\n"
		"rearm_success: %llu\n"
		"rearm_failed: %llu\n"
		"cr_len_err: %llu\n"
		"replenish_enque: %llu\n\n\n"
		"/* pass to kernel */\n"
		"pass_to_kernel: %llu\n\n"
		"/* replenish */\n"
		"replenish_deque: %llu\n"
		"num_post_wr: %llu\n"
		"alloc_skb_failed: %llu\n"
		"register_seg_failed: %llu\n"
		"post_wr_failed: %llu\n"
		"alloc_skb_retry: %llu\n",
		prx->poll_jfc_success,
		prx->poll_jfc_failed,
		prx->rearm_success,
		prx->rearm_failed,
		prx->cr_len_err,
		prx->replenish_enque,
		prx->pass_to_kernel,
		prx->replenish_deque,
		prx->num_post_wr,
		prx->alloc_skb_failed,
		prx->register_seg_failed,
		prx->post_wr_failed,
		prx->alloc_skb_retry);
	if (ret < 0 || ret + len >= buf_size)
		goto FORMAT_ERR;

	len += ret;
	return len;

FORMAT_ERR:
	pr_err("%s: format stats failed\n", __func__);
	return 0;
}

static ssize_t query_ipourma_stats_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct net_device *ndev = to_net_dev(dev);
	struct ipourma_dev_priv *priv = netdev_priv(ndev);
	ssize_t len;

	spin_lock(&priv->runtime_stats.lock);
	len = format_stats(buf, priv, (ssize_t)PAGE_SIZE);
	spin_unlock(&priv->runtime_stats.lock);

	return len;
}

static DEVICE_ATTR_RO(query_ipourma_stats);


#define INPUT_BUF_SIZE (sizeof(RESET_CMD) + 1)

static ssize_t reset_ipourma_stats_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	char input_buf[INPUT_BUF_SIZE] = {0};
	const size_t reset_cmd_len = INPUT_BUF_SIZE - 2;

	strscpy(input_buf, buf, INPUT_BUF_SIZE);
	input_buf[INPUT_BUF_SIZE - 1] = '\0';

	char *newline = strchr(input_buf, '\n');

	if (newline != NULL)
		*newline = '\0';
	const size_t input_len = strlen(input_buf);
	/* judge the input length to exclude the case where the prefix is the same */
	if (input_len == reset_cmd_len && strncmp(input_buf, RESET_CMD, reset_cmd_len) == 0) {
		struct net_device *ndev = to_net_dev(dev);
		struct ipourma_dev_priv *priv = netdev_priv(ndev);

		spin_lock(&priv->runtime_stats.lock);
		memset(&priv->runtime_stats.tx_stats, 0, sizeof(struct ipourma_tx_stats));
		memset(&priv->runtime_stats.rx_stats, 0, sizeof(struct ipourma_rx_stats));
		spin_unlock(&priv->runtime_stats.lock);
		return count;
	}
	return -EINVAL;
}
static DEVICE_ATTR_WO(reset_ipourma_stats);

static ssize_t max_concurrent_conn_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct net_device *ndev = to_net_dev(dev);
	struct ipourma_dev_priv *priv = netdev_priv(ndev);
	int ret, current_cap;

	spin_lock(&priv->tjetty_lru.lock);
	current_cap = priv->tjetty_lru.tjetty_capacity;
	spin_unlock(&priv->tjetty_lru.lock);

	ret = sysfs_emit(buf, "%d\n", current_cap);

	return ret;
}

static ssize_t max_concurrent_conn_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	struct net_device *ndev = to_net_dev(dev);
	struct ipourma_dev_priv *priv = netdev_priv(ndev);
	int new_capacity = 0;
	int ret;

	/*
	 * The input para '0' means the system automatically indentifies the number entered
	 * prefix: '0x'--hexadecimal, '0'--octal, others--decimal format
	 */
	ret = kstrtoint(buf, 0, &new_capacity);
	/* The new value must be between ipourma_jfs_depth and ipourma_tx_jfc_depth */
	if (ret != 0 || new_capacity < ipourma_jfs_depth || new_capacity > ipourma_tx_jfc_depth) {
		pr_err("%s: invalid input!\n", __func__);
		return -EINVAL;
	}

	spin_lock(&priv->tjetty_lru.lock);
	priv->tjetty_lru.tjetty_capacity = new_capacity;
	spin_unlock(&priv->tjetty_lru.lock);

	return count;
}
static DEVICE_ATTR_RW(max_concurrent_conn);

static ssize_t tjetty_aging_timeout_s_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct net_device *ndev = to_net_dev(dev);
	struct ipourma_dev_priv *priv = netdev_priv(ndev);
	uint16_t current_timeout;
	int ret;

	spin_lock(&priv->tjetty_lru.lock);
	current_timeout = priv->tjetty_lru.tjetty_aging_timeout_s;
	spin_unlock(&priv->tjetty_lru.lock);

	ret = sysfs_emit(buf, "%hu\n", current_timeout);

	return ret;
}

static ssize_t tjetty_aging_timeout_s_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	struct net_device *ndev = to_net_dev(dev);
	struct ipourma_dev_priv *priv = netdev_priv(ndev);
	uint16_t current_timeout, current_interval;
	int ret;

	ret = kstrtou16(buf, 0, &current_timeout);
	if (ret != 0) {
		pr_err("%s: invalid input! ret = %d\n", __func__, ret);
		return -EINVAL;
	}

	spin_lock(&priv->tjetty_lru.lock);
	current_interval = priv->tjetty_lru.tjetty_aging_interval_s;
	spin_unlock(&priv->tjetty_lru.lock);
	if (current_timeout < current_interval) {
		pr_err("%s: invalid input! tjetty_aging_timeout_s should be in [%u,%d]\n",
			__func__, current_interval, IPOURMA_TJETTY_TIMEOUT_MAX);
		return -EINVAL;
	}

	spin_lock(&priv->tjetty_lru.lock);
	priv->tjetty_lru.tjetty_aging_timeout_s = current_timeout;
	spin_unlock(&priv->tjetty_lru.lock);

	return count;
}
static DEVICE_ATTR_RW(tjetty_aging_timeout_s);

static ssize_t tjetty_aging_interval_s_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct net_device *ndev = to_net_dev(dev);
	struct ipourma_dev_priv *priv = netdev_priv(ndev);
	uint16_t current_interval;
	int ret;

	spin_lock(&priv->tjetty_lru.lock);
	current_interval = priv->tjetty_lru.tjetty_aging_interval_s;
	spin_unlock(&priv->tjetty_lru.lock);

	ret = sysfs_emit(buf, "%hu\n", current_interval);

	return ret;
}

static ssize_t tjetty_aging_interval_s_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	struct net_device *ndev = to_net_dev(dev);
	struct ipourma_dev_priv *priv = netdev_priv(ndev);
	struct delayed_work *work = &priv->tjetty_lru.tjetty_aging_work;
	uint16_t current_interval, current_timeout;
	int ret;

	ret = kstrtou16(buf, 0, &current_interval);
	if (ret != 0) {
		pr_err("%s: invalid input! ret = %d\n", __func__, ret);
		return -EINVAL;
	}

	spin_lock(&priv->tjetty_lru.lock);
	current_timeout = priv->tjetty_lru.tjetty_aging_timeout_s;
	spin_unlock(&priv->tjetty_lru.lock);
	if (current_interval < 1 || current_interval > current_timeout) {
		pr_err("%s: invalid input! tjetty_aging_interval_s should be in [%d,%u]\n",
			__func__, 1, current_timeout);
		return -EINVAL;
	}

	spin_lock(&priv->tjetty_lru.lock);
	priv->tjetty_lru.tjetty_aging_interval_s = current_interval;
	spin_unlock(&priv->tjetty_lru.lock);

	cancel_delayed_work_sync(work);
	schedule_delayed_work(work, msecs_to_jiffies((u32)current_interval * MSEC_PER_SEC));

	return count;
}
static DEVICE_ATTR_RW(tjetty_aging_interval_s);

static struct device_attribute *ipourma_attrs[] = {
	&dev_attr_hard_header_len,
	&dev_attr_urma_mtu,
	&dev_attr_ipourma_tx_ring_size,
	&dev_attr_ipourma_rx_ring_size,
	&dev_attr_query_ipourma_stats,
	&dev_attr_reset_ipourma_stats,
	&dev_attr_max_concurrent_conn,
	&dev_attr_tjetty_aging_timeout_s,
	&dev_attr_tjetty_aging_interval_s,
	NULL
};

void ipourma_register_sysfs(struct ipourma_dev_priv *pos)
{
	int i, ret;

	for (i = 0; ipourma_attrs[i] != NULL; i++) {
		ret = device_create_file(&pos->dev->dev, ipourma_attrs[i]);
		if (ret) {
			pr_err("%s: Failed to create sysfs attribute:%d\n", __func__, i);
			// delete former created attributes
			while (--i >= 0)
				device_remove_file(&pos->dev->dev, ipourma_attrs[i]);
			break;
		}
	}
}

void ipourma_unregister_sysfs(struct ipourma_dev_priv *pos)
{
	int i;

	for (i = 0; ipourma_attrs[i] != NULL; i++)
		device_remove_file(&pos->dev->dev, ipourma_attrs[i]);
}
