// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2vf_main.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/aer.h>
#include <linux/moduleparam.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <net/devlink.h>
#include <linux/if_vlan.h>
#include <linux/wait.h>
#include <linux/workqueue.h>

#include "sxe2_compat.h"
#include "sxe2_version.h"
#include "sxe2_log.h"
#include "sxe2vf_pci.h"
#include "sxe2vf.h"
#include "sxe2vf_mbx_msg.h"
#include "sxe2_mbx_public.h"
#include "sxe2vf_netdev.h"
#include "sxe2vf_rx.h"
#include "sxe2vf_tx.h"
#include "sxe2vf_l2_filter.h"
#include "sxe2vf_vsi.h"
#include "sxe2vf_aux_drv.h"
#include "sxe2vf_ethtool.h"
#include "sxe2vf_rxft.h"
#include "sxe2vf_debugfs.h"
#include "sxe2vf_com_ioctl.h"

#define CREATE_TRACE_POINTS
#include "sxe2vf_trace.h"
#undef CREATE_TRACE_POINTS

#ifdef SXE2_CFG_DEBUG
int vf_reg_log;
module_param(vf_reg_log, int, 0644);
MODULE_PARM_DESC(vf_reg_log, "reg read/write log, 0-off 1-on.");

int g_vf_switch_stats = 1;
module_param(g_vf_switch_stats, int, 0644);
MODULE_PARM_DESC(g_vf_switch_stats, "stats open/close, 0-off 1-on.");

#endif

static int com_mode = SXE2_COM_MODULE_UNDEFINED;
module_param(com_mode, uint, 0644);
MODULE_PARM_DESC(com_mode, "driver mode. kernel:0, dpdk:1, mixed:2(default)");

STATIC int msg_debug = -1;
module_param(msg_debug, int, 0644);
#ifndef CONFIG_DYNAMIC_DEBUG
MODULE_PARM_DESC(msg_debug,
		 "netif level (0=none,...,16=all), debug_mask (0x8XXXXXXXX)");
#else
MODULE_PARM_DESC(msg_debug, "netif level (0=none,...,16=all)");
#endif

#ifndef SXE2VF_DRV_NAME
#define SXE2VF_DRV_NAME "SXE2VF"
#endif

#ifndef SXE2VF_DRV_DESCRIPTION
#define SXE2VF_DRV_DESCRIPTION "LD 1160-2X Virtual Function"
#endif

#define SXE2VF_STOP_DROP_TIMEOUT 1000
#define SXE2VF_STOP_DROP_DONE_INTERVAL 1

int sxe2vf_com_mode_get(void *adapter)
{
	return ((struct sxe2vf_adapter *)adapter)->drv_mode;
}

int sxe2vf_g_com_mode_get(void)
{
	return com_mode;
}

static inline u32 sxe2vf_readl(void __iomem *reg)
{
	return readl(reg);
}

static inline void sxe2vf_writel(u32 value, void __iomem *reg)
{
	writel(value, reg);
}

static void sxe2vf_com_ctxt_fill(void *adapter)
{
	struct sxe2vf_adapter *vf_adapter = adapter;

	vf_adapter->com_ctxt.pdev = vf_adapter->pdev;
	vf_adapter->com_ctxt.func_type = SXE2_VF;
	vf_adapter->com_ctxt.pf_id = vf_adapter->pf_id;
	vf_adapter->com_ctxt.vf_id = vf_adapter->vf_id_in_dev;
}

struct sxe2_com_ops g_com_ops = {
		.cmd_exec = sxe2vf_com_cmd_send,
		.get_irq_num = sxe2vf_dpdk_irq_cnt_get,
		.get_vector = sxe2vf_dpdk_irq_vector_idx_get,
		.release = sxe2vf_dpdk_resource_release,
		.com_ctxt_fill = sxe2vf_com_ctxt_fill,
		.com_mode_get = sxe2vf_com_mode_get,
};

struct workqueue_struct *sxe2vf_wq;
struct workqueue_struct *sxe2vf_mbx_wq;
struct workqueue_struct *sxe2vf_msg_handle_wq;
struct workqueue_struct *sxe2vf_health_wq;

STATIC const struct pci_device_id sxe2vf_pci_tbl[] = {
		{SXE2VF_PCI_VENDOR_ID_1, SXE2VF_PCI_DEVICE_ID_1, PCI_ANY_ID,
		 PCI_ANY_ID, 0, 0, 0},
		{SXE2VF_PCI_VENDOR_ID_2, SXE2VF_PCI_DEVICE_ID_2, PCI_ANY_ID,
		 PCI_ANY_ID, 0, 0, 0},
		{SXE2VF_PCI_VENDOR_ID_1, SXE2VF_PCI_DEVICE_ID_10B4, PCI_ANY_ID,
		 PCI_ANY_ID, 0, 0, 0},
		{SXE2VF_PCI_VENDOR_ID_206F, SXE2VF_PCI_DEVICE_ID_1, PCI_ANY_ID,
		 PCI_ANY_ID, 0, 0, 0},
		{
				0,
		}};

s32 sxe2vf_dpdk_caps_get(struct sxe2vf_adapter *adapter,
			 struct sxe2vf_res_caps *caps)
{
	s32 ret = 0;

	if (!adapter || !caps) {
		ret = -EINVAL;
		LOG_ERROR_BDF("param invalid.\n");
		goto l_end;
	}

	caps->txq_base = adapter->q_ctxt.dpdk_offset;
	caps->txq_cnt = adapter->q_ctxt.dpdk_q_cnt;

	caps->rxq_base = adapter->q_ctxt.dpdk_offset;
	caps->rxq_cnt = adapter->q_ctxt.dpdk_q_cnt;

	caps->irq_base = adapter->irq_ctxt.dpdk_offset;
	caps->irq_cnt = adapter->irq_ctxt.dpdk_irq_cnt;

	caps->rss_key_size = adapter->rss_ctxt.rss_key_size;
	caps->rss_lut_size = adapter->rss_ctxt.rss_lut_size;
	caps->rss_lut_type = adapter->rss_ctxt.rss_lut_type;

	LOG_INFO_BDF("dpdk vf txq base:%d cnt:%d rxq base:%d cnt:%d irq base:%d\t"
		     "cnt:%d\n"
		     "\t rss_key_size:%u lut_size:%u lut_type:%u.\n",
		     caps->txq_base, caps->txq_cnt, caps->rxq_base, caps->rxq_cnt,
		     caps->irq_base, caps->irq_cnt, caps->rss_key_size,
		     caps->rss_lut_size, caps->rss_lut_type);

l_end:
	return ret;
}

STATIC struct sxe2vf_adapter *sxe2vf_adapter_create(struct pci_dev *pdev)
{
	struct net_device *netdev;
	struct sxe2vf_adapter *adapter = NULL;
	const char *device_name = dev_name(&pdev->dev);

	netdev = alloc_etherdev_mq(sizeof(struct sxe2vf_adapter),
				   SXE2VF_QUEUES_CNT_MAX);
	if (!netdev) {
		LOG_ERROR("queue max:%d device[pci_id %u] net device alloc failed\n",
			  SXE2VF_QUEUES_CNT_MAX, pdev->dev.id);
		return adapter;
	}

	adapter = netdev_priv(netdev);

	adapter->pdev = pdev;
	adapter->netdev = netdev;
	SET_NETDEV_DEV(netdev, &adapter->pdev->dev);

	(void)SXE2_STRCPY(adapter->dev_name, device_name,
			  min_t(u32, (strlen(device_name) + 1), DEV_NAME_LEN));

	LOG_INFO_BDF("adapter:0x%pK netdev:0x%pK pdev:0x%pK\n", adapter, netdev,
		     pdev);

	return adapter;
}

STATIC int sxe2vf_pci_init(struct sxe2vf_adapter *adapter)
{
	int ret;
	struct pci_dev *pdev = adapter->pdev;
	resource_size_t bar;
	unsigned long len;

	ret = pci_enable_device(pdev);
	if (ret) {
		LOG_DEV_ERR("device[pci_id %u] enable device failed\n",
			    adapter->pdev->dev.id);
		return ret;
	}

	ret = dma_set_mask_and_coherent(&adapter->pdev->dev,
					DMA_BIT_MASK(SXE2VF_DMA_BIT_WIDTH_64));
	if (ret) {
		LOG_DEV_ERR("device[pci_id %u] set dma bit mask failed\n",
			    adapter->pdev->dev.id);
		goto l_pci_disable;
	}

	ret = pci_request_regions(pdev, SXE2VF_DRV_NAME);
	if (ret) {
		LOG_DEV_ERR("device[pci_id %u] request IO memory failed\n",
			    pdev->dev.id);
		goto l_pci_disable;
	}

#ifdef HAVE_PCI_ENABLE_PCIE_ERROR_REPORTING
	pci_enable_pcie_error_reporting(pdev);
#endif

	pci_set_master(pdev);

	bar = pci_resource_start(pdev, 0);
	len = pci_resource_len(pdev, 0);

	adapter->hw.reg_base_addr = ioremap(bar, len);
	if (!adapter->hw.reg_base_addr) {
		ret = -EIO;
		LOG_DEV_ERR("device[pci_id %u] \t"
			    "ioremap[bar:0x%llx, len:%zu] failed\n",
			    pdev->dev.id, (u64)bar, len);
		goto l_pci_release_regions;
	}

	pci_set_drvdata(pdev, adapter->netdev);

	(void)pci_save_state(pdev);

	LOG_INFO_BDF("bar_base_paddr = 0x%llx, \t"
		     "bar len:%zu, reg_base_addr:%pK\n",
		     (u64)bar, len, adapter->hw.reg_base_addr);
	return 0;

l_pci_release_regions:
	pci_release_regions(pdev);
l_pci_disable:
	pci_disable_device(pdev);
	return ret;
}

STATIC void sxe2vf_msg_level_init(struct sxe2vf_adapter *adapter)
{
	adapter->log_level_ctxt.msg_enable =
			netif_msg_init(msg_debug, SXE2VF_DFLT_NETIF_M);
}

STATIC void sxe2vf_hw_base_init(struct sxe2vf_adapter *adapter)
{
	struct sxe2vf_hw *hw;

	hw = &adapter->hw;
	hw->adapter = adapter;

	hw->reg_read = sxe2vf_readl;
	hw->reg_write = sxe2vf_writel;
}

void sxe2vf_post_state_update(struct sxe2vf_work_context *work_ctxt,
			      enum sxe2vf_probe_post_state post_state)
{
	work_ctxt->post_state = post_state;
	LOG_INFO("post state update to %u.\n", post_state);
}

STATIC void sxe2vf_queue_work(struct sxe2vf_adapter *adapter,
			      struct workqueue_struct *wq, struct work_struct *dwork)
{
	if (!queue_work(wq, dwork))
		LOG_WARN_BDF("work was already on a queue.\n");
}

STATIC void sxe2vf_queue_delayed_work(struct sxe2vf_adapter *adapter,
				      struct workqueue_struct *wq,
				      struct delayed_work *dwork,
				      unsigned long delay)
{
	if (!queue_delayed_work(wq, dwork, delay))
		LOG_WARN_BDF("work was already on a queue.\n");
}

void sxe2vf_wkq_schedule(struct sxe2vf_adapter *adapter, enum sxe2vf_wk_type type,
			 const u32 delay)
{
	switch (type) {
	case SXE2VF_WK_MONITOR:
		if (!test_bit(SXE2VF_MONITOR_WORK_DISABLED,
			      &adapter->work_ctxt.state))
			sxe2vf_queue_delayed_work(adapter, sxe2vf_wq,
						  &adapter->work_ctxt.monitor_wk,
						  msecs_to_jiffies(delay));
		break;

	case SXE2VF_WK_MONITOR_IM:
		if (!test_bit(SXE2VF_MONITOR_WORK_DISABLED,
			      &adapter->work_ctxt.state))
			sxe2vf_queue_work(adapter, sxe2vf_wq,
					  &adapter->work_ctxt.monitor_wk.work);
		break;

	case SXE2VF_WK_MBX:
		if (!test_bit(SXE2VF_FLAG_EVENT_IRQ_DISABLED, adapter->flags))
			sxe2vf_queue_work(adapter, sxe2vf_mbx_wq,
					  &adapter->work_ctxt.mbx_wk);
		break;

	case SXE2VF_WK_NOTIFY_MSG:
		if (!test_bit(SXE2VF_FLAG_EVENT_IRQ_DISABLED, adapter->flags))
			sxe2vf_queue_work(adapter, sxe2vf_msg_handle_wq,
					  &adapter->work_ctxt.msg_handle_wk);
		break;

	case SXE2VF_WK_HEALTH:
		if (!test_bit(SXE2VF_HEALTH_WORK_DISABLED,
			      &adapter->work_ctxt.state))
			sxe2vf_queue_delayed_work(adapter,
						  adapter->work_ctxt.health_wq,
						  &adapter->work_ctxt.health_wk,
						  msecs_to_jiffies(delay));
		break;
	}
}

void sxe2vf_wkq_cancel(struct sxe2vf_adapter *adapter, enum sxe2vf_wk_type type)
{
	struct sxe2vf_work_context *work_ctxt = &adapter->work_ctxt;

	switch (type) {
	case SXE2VF_WK_MONITOR:
	case SXE2VF_WK_MONITOR_IM:
		set_bit(SXE2VF_MONITOR_WORK_DISABLED, &work_ctxt->state);
		if (work_ctxt->monitor_wk.work.func)
			cancel_delayed_work_sync(&work_ctxt->monitor_wk);
		break;

	case SXE2VF_WK_MBX:
		if (work_ctxt->mbx_wk.func)
			cancel_work_sync(&work_ctxt->mbx_wk);
		break;

	case SXE2VF_WK_NOTIFY_MSG:
		if (work_ctxt->msg_handle_wk.func)
			cancel_work_sync(&work_ctxt->msg_handle_wk);
		break;

	case SXE2VF_WK_HEALTH:
		set_bit(SXE2VF_HEALTH_WORK_DISABLED, &work_ctxt->state);
		if (work_ctxt->health_wk.work.func)
			cancel_delayed_work_sync(&work_ctxt->health_wk);
		break;
	}

	LOG_INFO_BDF("work state:0x%lx type:%u %s.\n", work_ctxt->state, type,
		     current->comm);
}

STATIC void sxe2vf_wkq_cancel_all(struct sxe2vf_adapter *adapter)
{
	sxe2vf_wkq_cancel(adapter, SXE2VF_WK_HEALTH);
	sxe2vf_wkq_cancel(adapter, SXE2VF_WK_MONITOR);
	sxe2vf_wkq_cancel(adapter, SXE2VF_WK_MBX);
	sxe2vf_wkq_cancel(adapter, SXE2VF_WK_NOTIFY_MSG);
}

static void sxe2vf_mac_addr_init(struct sxe2vf_adapter *adapter)
{
	u8 *cur_mac = (u8 *)&adapter->switch_ctxt.filter_ctxt.mac_filter
				      .cur_mac_addr;
	struct net_device *netdev = adapter->netdev;

	if (!is_valid_ether_addr(cur_mac)) {
		eth_hw_addr_random(netdev);
		LOG_DEV_INFO("current mac addr:%pM invalid, using random mac:%pM\n",
			     cur_mac, netdev->dev_addr);
		ether_addr_copy(cur_mac, netdev->dev_addr);
	} else {
		LOG_INFO_BDF(" current mac addr:%pM.\n", cur_mac);
		eth_hw_addr_set(netdev, cur_mac);
		ether_addr_copy(netdev->perm_addr, cur_mac);
	}
}

static void sxe2vf_eth_deinit(struct sxe2vf_adapter *adapter)
{
	if (sxe2vf_com_mode_get(adapter) == SXE2_COM_MODULE_DPDK)
		return;

	sxe2vf_auxdrv_deinit(adapter);

	sxe2vf_netdev_unregister(adapter);

	sxe2vf_ipsec_deinit(adapter);

	sxe2vf_rss_deinit(adapter);

	sxe2vf_fnav_deinit(adapter);

	sxe2vf_vsi_destroy(adapter);
}

static void sxe2vf_irq_queue_decfg_pre(struct sxe2vf_adapter *adapter)
{
	if (adapter->com_work.func)
		(void)cancel_work_sync(&adapter->com_work);

	sxe2_com_deinit(&adapter->com_ctxt);

	sxe2vf_eth_deinit(adapter);
}

static void sxe2vf_irq_queue_decfg_post(struct sxe2vf_adapter *adapter)
{
	sxe2vf_irq_deinit(adapter);
}

STATIC void sxe2vf_probe_post_deinit(struct sxe2vf_adapter *adapter,
				     enum sxe2vf_probe_post_state state)
{
	switch (state) {
	case SXE2VF_PROBE_POST_INIT_DONE:
	case SXE2VF_PROBE_POST_IRQ_QUEUE_CFG:
		sxe2vf_debugfs_vf_exit(adapter);
		sxe2vf_irq_queue_decfg_pre(adapter);
		fallthrough;

	case SXE2VF_PROBE_POST_CAPS_INIT:
		sxe2vf_func_caps_deinit(adapter);
		fallthrough;

	case SXE2VF_PROBE_POST_VER_MATCH:
	case SXE2VF_PROBE_POST_INIT_STARTED:
	case SXE2VF_PROBE_POST_VER_CHK_FAIL:
		sxe2vf_mbx_channel_deinit(adapter);
		sxe2vf_irq_queue_decfg_post(adapter);
		break;

	default:
		LOG_ERROR_BDF("invalid post state:0x%x.\n", state);
		break;
	}

	LOG_INFO_BDF("probe post deinit from state %d.\n", state);
}

static s32 sxe2vf_eth_init(struct sxe2vf_adapter *adapter)
{
	s32 ret = 0;

	if (sxe2vf_com_mode_get(adapter) == SXE2_COM_MODULE_DPDK)
		return ret;

	sxe2vf_netdev_init(adapter);

	sxe2vf_mac_addr_init(adapter);

	ret = sxe2vf_main_vsi_create(adapter);
	if (ret) {
		LOG_ERROR_BDF("create main vsi failed, ret=%d\n", ret);
		return ret;
	}

	ret = sxe2vf_rss_init(adapter);
	if (ret)
		goto l_vsi_destroy;

	ret = sxe2vf_fnav_init(adapter);
	if (ret)
		goto l_rss_deinit;

	ret = sxe2vf_ipsec_init(adapter);
	if (ret) {
		LOG_DEV_ERR("ipsec initial failed.\n");
		goto l_fnav_deinit;
	}

	ret = sxe2vf_vlan_cfg(adapter);
	if (ret)
		goto l_ipsec_deinit;

	ret = sxe2vf_netdev_register(adapter);
	if (ret)
		goto l_ipsec_deinit;

	sxe2vf_auxdrv_init(adapter);
	return ret;

l_ipsec_deinit:
	sxe2vf_ipsec_deinit(adapter);

l_fnav_deinit:
	sxe2vf_fnav_deinit(adapter);

l_rss_deinit:
	sxe2vf_rss_deinit(adapter);

l_vsi_destroy:
	sxe2vf_vsi_destroy(adapter);

	return ret;
}

STATIC s32 sxe2vf_irq_queue_cfg(struct sxe2vf_adapter *adapter)
{
	s32 ret;

	ret = sxe2vf_irq_init(adapter);
	if (ret) {
		LOG_ERROR_BDF("init irq failed, ret=%d\n", ret);
		return ret;
	}

	ret = sxe2vf_queue_init(adapter);
	if (ret) {
		LOG_ERROR_BDF("queue init failed, ret=%d\n", ret);
		goto l_irq_deinit;
	}

	(void)sxe2vf_vsi_hw_decfg(adapter);

	ret = sxe2vf_eth_init(adapter);
	if (ret) {
		LOG_ERROR_BDF("eth init failed, ret=%d\n", ret);
		goto l_queue_deinit;
	}

	(void)schedule_work(&adapter->com_work);

	return ret;

l_queue_deinit:
	sxe2vf_queue_deinit(adapter);

l_irq_deinit:
	sxe2vf_irq_deinit(adapter);

	return ret;
}

STATIC bool sxe2vf_reset_is_detected(struct sxe2vf_adapter *adapter)
{
	u32 i;
	enum sxe2vf_dev_state state;
	enum sxe2vf_reset_type reset_type;

	for (i = 0; i < SXE2VF_REMOVE_RESET_DETECT_COUNT; i++) {
		sxe2vf_dev_state_get(adapter, &state, &reset_type);

		if ((state != SXE2VF_DEVSTATE_RUNNING &&
		     state != SXE2VF_DEVSTATE_VFR_REQUEST &&
		     state != SXE2VF_DEVSTATE_VFR_NOTIFY) ||
		    sxe2vf_reset_detect(adapter) ||
		    (sxe2vf_reg_read(&adapter->hw, SXE2VF_MBX_RQ_LEN) ==
				     SXE2VF_REG_INVAL_VALUE &&
		     pci_wait_for_pending_transaction(adapter->pdev))) {
			LOG_INFO_BDF("detected reset_type:0x%x state:0x%x reg:0x%x\t"
				     "value:0x%x.\n",
				     reset_type, state, SXE2VF_MBX_RQ_LEN,
				     sxe2vf_reg_read(&adapter->hw,
						     SXE2VF_MBX_RQ_LEN));
			return true;
		}
		msleep(SXE2VF_ACTIVE_WAIT_INTERVAL);
	}

	LOG_DEV_ERR("reset detect fail.reset_type:0x%x state:0x%x.\n", reset_type,
		    state);
	sxe2vf_hw_mbx_regs_dump(&adapter->hw);

	return false;
}

static s32 sxe2vf_dev_cfg_clear(struct sxe2vf_adapter *adapter)
{
	if (sxe2vf_mbx_channel_init(adapter)) {
		LOG_ERROR_BDF("mbx channel init failed.\n");
		goto l_error;
	}

	(void)sxe2vf_reset_msg_send(adapter);

	sxe2vf_mbx_channel_deinit(adapter);

	adapter->work_ctxt.is_send = true;
	sxe2vf_dev_state_set(adapter, SXE2VF_DEVSTATE_VFR_REQUEST,
			     SXE2VF_RESET_NONE);

	return 0;

l_error:
	sxe2vf_mbx_channel_deinit(adapter);
	return -EIO;
}

static s32 sxe2vf_probe_post_prepare(struct sxe2vf_adapter *adapter)
{
	sxe2vf_event_irq_disable(adapter);

	if (sxe2vf_mbx_channel_init(adapter)) {
		LOG_DEV_ERR("mbx channel init failed.\n");
		goto l_error;
	}

	return 0;

l_error:
	sxe2vf_mbx_channel_deinit(adapter);
	return -EIO;
}

STATIC void sxe2vf_probe_post_build(struct sxe2vf_adapter *adapter)
{
	u32 new;
	s32 ret = 0;
	struct sxe2vf_work_context *work_ctxt = &adapter->work_ctxt;

	switch (work_ctxt->post_state) {
	case SXE2VF_PROBE_POST_INIT_STARTED:
		if (sxe2vf_probe_post_prepare(adapter))
			goto l_retry;

		new = SXE2VF_PROBE_POST_VER_MATCH;
		break;

	case SXE2VF_PROBE_POST_VER_MATCH:
		ret = sxe2vf_drv_ver_match(adapter);
		if (ret) {
			if (ret == -ETIMEDOUT)
				goto l_retry;
			new = SXE2VF_PROBE_POST_VER_CHK_FAIL;
		} else {
			new = SXE2VF_PROBE_POST_CAPS_INIT;
		}
		break;

	case SXE2VF_PROBE_POST_CAPS_INIT:

		ret = sxe2vf_drv_mode_get(adapter, SXE2VF_MSG_RESP_WAIT_POLLING);
		if (ret) {
			adapter->drv_mode = SXE2_COM_MODULE_MIXED;
			LOG_ERROR_BDF("get drv mode failed, ret=%d\n", ret);
		}

		if (sxe2vf_func_caps_init(adapter))
			goto l_retry;

		new = SXE2VF_PROBE_POST_IRQ_QUEUE_CFG;
		break;

	case SXE2VF_PROBE_POST_IRQ_QUEUE_CFG:
		if (sxe2vf_irq_queue_cfg(adapter))
			goto l_retry;

		sxe2vf_post_state_update(work_ctxt, SXE2VF_PROBE_POST_INIT_DONE);

		set_bit(SXE2VF_FLAG_DRV_PROBE_DONE, adapter->flags);

		LOG_INFO_BDF("probe post done.\n");

		sxe2vf_debugfs_vf_init(adapter);

		return;

	case SXE2VF_PROBE_POST_VER_CHK_FAIL:
		return;
	default:
		LOG_ERROR_BDF("invalid probe post state:0x%x.\n",
			      work_ctxt->post_state);
		SXE2_BUG();
		goto l_retry;
	}

	sxe2vf_post_state_update(work_ctxt, new);
	return;

l_retry:
	return;
}

static s32 sxe2vf_hw_caps_recfg(struct sxe2vf_adapter *adapter)
{
	s32 ret;

	ret = sxe2vf_func_caps_init(adapter);
	if (ret) {
		LOG_ERROR_BDF("hw caps get fail during reset.\n");
		return ret;
	}

	sxe2vf_event_irq_enable(adapter);

	return ret;
}

static void sxe2vf_eth_stop(struct sxe2vf_adapter *adapter)
{
	struct sxe2vf_vsi *vsi = adapter->vsi_ctxt.vf_vsi;
	s32 ret;

	if (sxe2vf_com_mode_get(adapter) == SXE2_COM_MODULE_DPDK)
		return;

	sxe2vf_auxdrv_send_reset_event(adapter);

	(void)sxe2vf_ipsec_stop(adapter);

	mutex_lock(&adapter->vsi_ctxt.lock);
	ret = sxe2vf_vsi_disable(vsi);
	if (ret)
		LOG_INFO_BDF("vsi:%d disable failed.(err:%d)\n", vsi->vsi_id, ret);
	mutex_unlock(&adapter->vsi_ctxt.lock);
}

static s32 sxe2vf_rebuild_prepare(struct sxe2vf_adapter *adapter)
{
	s32 ret;

	sxe2vf_event_irq_disable(adapter);

	ret = sxe2vf_mbx_channel_init(adapter);
	if (ret) {
		LOG_ERROR_BDF("mbx channel init failed after reset.(err:%d)\n", ret);
		goto l_end;
	}

	ret = sxe2vf_hw_caps_recfg(adapter);
	if (ret) {
		LOG_ERROR_BDF("irq queue recfg failed.(err:%d)\n", ret);
		sxe2vf_mbx_channel_deinit(adapter);
		goto l_caps_get_fail;
	}

	return ret;

l_caps_get_fail:
	sxe2vf_mbx_channel_deinit(adapter);

l_end:
	return ret;
}

STATIC void __sxe2vf_vf_stop(struct sxe2vf_adapter *adapter)
{
	mutex_lock(&adapter->dev_ctxt.vf_lock);

	if (!test_and_set_bit(SXE2VF_VF_DISABLE, adapter->dev_ctxt.state)) {
		sxe2_com_disable(&adapter->com_ctxt);

		sxe2vf_eth_stop(adapter);

		sxe2vf_mbx_channel_deinit(adapter);

		sxe2vf_event_irq_disable(adapter);
	}
	mutex_unlock(&adapter->dev_ctxt.vf_lock);
}

STATIC void sxe2vf_vf_stop(struct sxe2vf_adapter *adapter)
{
	if (!sxe2vf_post_probe_is_start(adapter))
		return;

	if (sxe2vf_post_probe_is_done(adapter)) {
		__sxe2vf_vf_stop(adapter);
		adapter->work_ctxt.failed_cnt = 0;
	} else {
		sxe2vf_probe_post_deinit(adapter, adapter->work_ctxt.post_state);
		sxe2vf_post_state_update(&adapter->work_ctxt,
					 SXE2VF_PROBE_POST_INIT_STARTED);
	}
}

static s32 sxe2vf_eth_rebuild(struct sxe2vf_adapter *adapter)
{
	s32 ret = 0;
	struct sxe2vf_vsi *vsi = adapter->vsi_ctxt.vf_vsi;

	if (sxe2vf_com_mode_get(adapter) == SXE2_COM_MODULE_DPDK)
		return ret;

	mutex_lock(&adapter->vsi_ctxt.lock);
	ret = sxe2vf_vsi_rebuild(vsi);
	mutex_unlock(&adapter->vsi_ctxt.lock);
	if (ret) {
		LOG_ERROR_BDF("vsi:%u rebuild failed.(err:%d)\n", vsi->vsi_id, ret);
		goto l_out;
	}

	(void)sxe2vf_ipsec_rebuild(adapter);

	sxe2vf_auxdrv_init(adapter);

	rtnl_lock();
	ret = sxe2vf_vlan_cfg_rebuild(adapter);
	if (ret) {
		rtnl_unlock();
		goto l_out;
	}

	set_bit(SXE2VF_FLAG_UPDATE_NETDEV_FEATURES, adapter->flags);

	sxe2vf_adv_cfg_restore(adapter);

	(void)netif_set_real_num_rx_queues(adapter->netdev, vsi->rxqs.q_cnt);
	(void)netif_set_real_num_tx_queues(adapter->netdev, vsi->txqs.q_cnt);
	rtnl_unlock();

	mutex_lock(&adapter->vsi_ctxt.lock);
	if (test_bit(SXE2VF_FLAG_DRV_UP, adapter->flags)) {
		ret = __sxe2vf_vsi_open(vsi, false, true);
		if (ret) {
			mutex_unlock(&adapter->vsi_ctxt.lock);
			LOG_ERROR_BDF("vsi:%d open failed.(err:%d)\n", vsi->vsi_id,
				      ret);
			goto l_out;
		}
	}
	clear_bit(SXE2VF_VSI_DISABLE, vsi->state);
	mutex_unlock(&adapter->vsi_ctxt.lock);

l_out:
	return ret;
}

STATIC s32 __sxe2vf_vf_rebuild(struct sxe2vf_adapter *adapter)
{
	s32 ret = 0;

	mutex_lock(&adapter->dev_ctxt.vf_lock);

	sxe2vf_auxdrv_deinit(adapter);

	ret = sxe2vf_rebuild_prepare(adapter);
	if (ret) {
		LOG_ERROR_BDF("vf enable failed during vfr.ret:%d\n", ret);
		goto l_err;
	}

	ret = sxe2vf_eth_rebuild(adapter);
	if (ret) {
		LOG_ERROR_BDF("vf enable failed during vfr.ret:%d\n", ret);
		goto l_eth_rebuild_failed;
	}

	sxe2_com_enable(&adapter->com_ctxt);

	clear_bit(SXE2VF_VF_DISABLE, adapter->dev_ctxt.state);
	mutex_unlock(&adapter->dev_ctxt.vf_lock);

	LOG_INFO_BDF("vf rebuild done.\n");

	return ret;

l_eth_rebuild_failed:
	sxe2vf_mbx_channel_deinit(adapter);
	sxe2vf_event_irq_disable(adapter);

l_err:
	mutex_unlock(&adapter->dev_ctxt.vf_lock);
	return ret;
}

STATIC s32 sxe2vf_vf_rebuild(struct sxe2vf_adapter *adapter)
{
	if (sxe2vf_post_probe_is_done(adapter)) {
		if (__sxe2vf_vf_rebuild(adapter))
			return -EIO;
	} else {
		adapter->work_ctxt.post_state =
				adapter->work_ctxt.post_state
						?: SXE2VF_PROBE_POST_INIT_STARTED;
		sxe2vf_probe_post_build(adapter);
	}

	return 0;
}

STATIC s32 sxe2vf_update_features(struct sxe2vf_adapter *adapter)
{
	if (test_bit(SXE2VF_FLAG_UPDATE_NETDEV_FEATURES, adapter->flags)) {
		if (!rtnl_trylock())
			return -EBUSY;

		netdev_update_features(adapter->netdev);
		rtnl_unlock();
		clear_bit(SXE2VF_FLAG_UPDATE_NETDEV_FEATURES, adapter->flags);
	}
	return 0;
}

void sxe2vf_dev_state_get(struct sxe2vf_adapter *adapter,
			  enum sxe2vf_dev_state *state,
			  enum sxe2vf_reset_type *reset_type)
{
	struct sxe2vf_work_context *work_ctxt = &adapter->work_ctxt;
	unsigned long flags;

	spin_lock_irqsave(&work_ctxt->state_lock, flags);

	if (state)
		*state = work_ctxt->dev_state;
	if (reset_type)
		*reset_type = work_ctxt->reset_type;

	spin_unlock_irqrestore(&work_ctxt->state_lock, flags);
}

void sxe2vf_dev_state_set(struct sxe2vf_adapter *adapter,
			  enum sxe2vf_dev_state new_state,
			  enum sxe2vf_reset_type new_reset_type)
{
	enum sxe2vf_dev_state cur_state;
	enum sxe2vf_reset_type cur_reset_type;
	unsigned long flags;
	struct sxe2vf_work_context *work_ctxt = &adapter->work_ctxt;

	spin_lock_irqsave(&work_ctxt->state_lock, flags);

	cur_state = work_ctxt->dev_state;
	cur_reset_type = work_ctxt->reset_type;

	if (cur_state == SXE2VF_DEVSTATE_FAULT)
		goto l_unlock;

	switch (new_state) {
	case SXE2VF_DEVSTATE_STOPPED:
		if (cur_state == SXE2VF_DEVSTATE_RESETTING &&
		    cur_reset_type == SXE2VF_RESET_CORER) {
			work_ctxt->dev_state = new_state;
			work_ctxt->reset_type = SXE2VF_RESET_NONE;
		}
		break;

	case SXE2VF_DEVSTATE_UNACTIVED:
		if ((cur_state == SXE2VF_DEVSTATE_RESETTING &&
		     new_reset_type == SXE2VF_RESET_VFR) ||
		    cur_state == SXE2VF_DEVSTATE_INITIAL ||
		    cur_state == SXE2VF_DEVSTATE_STOPPED) {
			work_ctxt->dev_state = new_state;
			work_ctxt->reset_type = SXE2VF_RESET_NONE;
		}
		break;

	case SXE2VF_DEVSTATE_ACTIVATED:
		if (cur_state == SXE2VF_DEVSTATE_UNACTIVED) {
			work_ctxt->dev_state = new_state;
			work_ctxt->reset_type = SXE2VF_RESET_NONE;
		}
		break;

	case SXE2VF_DEVSTATE_RUNNING:
		if (cur_state == SXE2VF_DEVSTATE_ACTIVATED) {
			work_ctxt->dev_state = new_state;
			work_ctxt->reset_type = SXE2VF_RESET_NONE;
		}
		break;

	case SXE2VF_DEVSTATE_VFR_REQUEST:
		if (cur_state == SXE2VF_DEVSTATE_RUNNING ||
		    cur_state == SXE2VF_DEVSTATE_ACTIVATED) {
			work_ctxt->dev_state = new_state;
			work_ctxt->reset_type = SXE2VF_RESET_NONE;
		}
		break;
	case SXE2VF_DEVSTATE_VFR_NOTIFY:
		if (cur_state == SXE2VF_DEVSTATE_RUNNING) {
			work_ctxt->dev_state = new_state;
			work_ctxt->reset_type = SXE2VF_RESET_NONE;
		}
		break;

	case SXE2VF_DEVSTATE_RESETTING:
		if (cur_state != SXE2VF_DEVSTATE_STOPPED &&
		    (new_reset_type == SXE2VF_RESET_VFR ||
		     new_reset_type == SXE2VF_RESET_CORER)) {
			work_ctxt->dev_state = new_state;
			work_ctxt->reset_type = new_reset_type;
		}
		break;

	case SXE2VF_DEVSTATE_INITIAL:
	case SXE2VF_DEVSTATE_FAULT:
		work_ctxt->dev_state = new_state;
		LOG_DEBUG_BDF("new state:0x%x\n", new_state);
		break;

	default:
		LOG_ERROR_BDF("Invalid device state %d\n", new_state);
		break;
	}

l_unlock:
	spin_unlock_irqrestore(&work_ctxt->state_lock, flags);
	LOG_DEBUG_BDF("cur_state:%u cur_reset_type:%u,\t"
		      "new_state:%u new_reset_type:%u, final state:%u\t"
		      "reset_type:%u\n",
		      cur_state, cur_reset_type, new_state, new_reset_type,
		      work_ctxt->dev_state, work_ctxt->reset_type);
}

static bool sxe2vf_hw_corer_check_lock(struct sxe2vf_hw *hw)
{
	struct sxe2vf_adapter *adapter = (struct sxe2vf_adapter *)hw->adapter;
	bool ret;

	mutex_lock(&adapter->work_ctxt.reset_detect_lock);
	ret = sxe2vf_hw_corer_check(hw);
	mutex_unlock(&adapter->work_ctxt.reset_detect_lock);

	return ret;
}

static bool sxe2vf_hw_vfr_is_checked_lock(struct sxe2vf_hw *hw)
{
	struct sxe2vf_adapter *adapter = hw->adapter;
	bool ret = false;

	mutex_lock(&adapter->work_ctxt.reset_detect_lock);
	ret = sxe2vf_hw_vfr_is_checked(hw);
	mutex_unlock(&adapter->work_ctxt.reset_detect_lock);

	return ret;
}

s32 sxe2vf_reset_detect(struct sxe2vf_adapter *adapter)
{
	s32 ret = false;

	if (sxe2vf_hw_corer_check_lock(&adapter->hw)) {
		sxe2vf_dev_state_set(adapter, SXE2VF_DEVSTATE_RESETTING,
				     SXE2VF_RESET_CORER);
		ret = true;
	} else if (sxe2vf_hw_vfr_is_checked_lock(&adapter->hw)) {
		sxe2vf_dev_state_set(adapter, SXE2VF_DEVSTATE_RESETTING,
				     SXE2VF_RESET_VFR);
		ret = true;
	}
	return ret;
}

STATIC s32 sxe2vf_pci_drop_stop(struct sxe2vf_adapter *adapter)
{
	u32 cnt;
	struct sxe2vf_hw *hw = &adapter->hw;

	sxe2vf_hw_corer_stop_drop(hw);

	for (cnt = 0; cnt < SXE2VF_STOP_DROP_TIMEOUT; cnt++) {
		msleep(SXE2VF_STOP_DROP_DONE_INTERVAL);
		if (sxe2vf_hw_corer_stop_drop_done(hw))
			break;
	}

	if (cnt == SXE2VF_STOP_DROP_TIMEOUT) {
		LOG_ERROR_BDF("stop PCIe drop timeout\n");
		return -ETIMEDOUT;
	}

	return 0;
}

static s32 sxe2vf_stopped_state_proc(struct sxe2vf_adapter *adapter)
{
	s32 ret = 0;

	sxe2vf_vf_stop(adapter);

	ret = sxe2vf_pci_drop_stop(adapter);
	if (!ret)
		sxe2vf_dev_state_set(adapter, SXE2VF_DEVSTATE_UNACTIVED,
				     SXE2VF_RESET_NONE);

	return ret;
}

static void sxe2vf_common_err_handle(struct sxe2vf_adapter *adapter,
				     u32 fail_max_cnt, enum sxe2vf_dev_state state)
{
	struct sxe2vf_work_context *work_ctxt = &adapter->work_ctxt;

	work_ctxt->failed_cnt++;

	LOG_WARN_BDF("post state:%u dev_state:%u reset_type:%u \t"
		     "fail cnt:%u max:%u\n",
		     work_ctxt->post_state, work_ctxt->dev_state,
		     work_ctxt->reset_type, work_ctxt->failed_cnt, fail_max_cnt);

	if (work_ctxt->failed_cnt > fail_max_cnt ||
	    work_ctxt->post_state == SXE2VF_PROBE_POST_VER_CHK_FAIL)
		sxe2vf_dev_state_set(adapter, state, SXE2VF_RESET_NONE);
}

static s32 sxe2vf_unactive_state_proc(struct sxe2vf_adapter *adapter)
{
	u32 i;

	for (i = 0; i < SXE2VF_RESET_ACTIVE_WAIT_COUNT; i++) {
		if (sxe2vf_hw_vf_is_active(&adapter->hw)) {
			adapter->work_ctxt.failed_cnt = 0;
			sxe2vf_dev_state_set(adapter, SXE2VF_DEVSTATE_ACTIVATED,
					     SXE2VF_RESET_NONE);
			return 0;
		}
		msleep(SXE2VF_ACTIVE_WAIT_INTERVAL);
	}

	LOG_ERROR_BDF("wait vf dev active timeout failed_cnt:%d.\n",
		      adapter->work_ctxt.failed_cnt);
	return -ETIMEDOUT;
}

static s32 sxe2vf_active_state_proc(struct sxe2vf_adapter *adapter)
{
	pci_set_master(adapter->pdev);
	pci_restore_msi_state(adapter->pdev);

	if (!adapter->work_ctxt.is_clear) {
		if (!sxe2vf_dev_cfg_clear(adapter)) {
			adapter->work_ctxt.is_clear = true;
			LOG_INFO_BDF("vf hw cfg clear msg send done\n");
		}
		return 0;
	}

	if (sxe2vf_vf_rebuild(adapter))
		return -EIO;

	adapter->work_ctxt.failed_cnt = 0;
	if (sxe2vf_post_probe_is_done(adapter))
		sxe2vf_dev_state_set(adapter, SXE2VF_DEVSTATE_RUNNING,
				     SXE2VF_RESET_NONE);

	return 0;
}

STATIC void sxe2vf_mtu_changed_handler(struct sxe2vf_adapter *adapter)
{
	if (test_and_clear_bit(SXE2VF_FLAG_MTU_CHANGED, adapter->flags))
		(void)sxe2vf_rdma_aux_send_mtu_changed_event(adapter);
}

STATIC s32 sxe2vf_running_state_proc(struct sxe2vf_adapter *adapter)
{
	s32 ret = 0;

	if (sxe2vf_com_mode_get(adapter) == SXE2_COM_MODULE_DPDK)
		return ret;

	ret = sxe2vf_l2_filter_cfg_sync(adapter);
	if (ret)
		goto l_out;

	ret = sxe2vf_update_features(adapter);
	if (ret)
		goto l_out;

#ifdef SXE2_CFG_DEBUG
	if (g_vf_switch_stats)
		ret = sxe2vf_stats_push_sync(adapter);
#else
	ret = sxe2vf_stats_push_sync(adapter);
#endif

	sxe2vf_mtu_changed_handler(adapter);

l_out:
	return ret;
}

static s32 sxe2vf_vfr_req_state_proc(struct sxe2vf_adapter *adapter)
{
	if (!adapter->work_ctxt.is_send && sxe2vf_reset_msg_send(adapter))
		return -EIO;

	adapter->work_ctxt.is_send = true;

	return 0;
}

static s32 sxe2vf_corer_done(struct sxe2vf_adapter *adapter)
{
	u32 i;

	for (i = 0; i < SXE2VF_CORER_WAIT_DONE_COUNT; i++) {
		if (sxe2vf_hw_corer_done(&adapter->hw))
			break;
		msleep(SXE2VF_CORER_DONE_WAIT_INTERVAL);
	}

	if (i == SXE2VF_RESET_DETEC_WAIT_COUNT) {
		LOG_ERROR_BDF("wait core reset done failed.\n");
		return -ETIMEDOUT;
	}

	return 0;
}

static s32 sxe2vf_resetting_state_proc(struct sxe2vf_adapter *adapter)
{
	s32 ret = 0;

	adapter->work_ctxt.is_send = false;
	adapter->work_ctxt.failed_cnt = 0;
	adapter->work_ctxt.is_clear = true;

	if (adapter->work_ctxt.reset_type == SXE2VF_RESET_CORER) {
		sxe2vf_waitq_entry_cancel(adapter);

		ret = sxe2vf_corer_done(adapter);
		if (!ret) {
			sxe2vf_dev_state_set(adapter, SXE2VF_DEVSTATE_STOPPED,
					     SXE2VF_RESET_CORER);
			sxe2vf_auxdrv_send_reset_event(adapter);
		}
	} else if (adapter->work_ctxt.reset_type == SXE2VF_RESET_VFR) {
		sxe2vf_waitq_entry_cancel(adapter);

		sxe2vf_vf_stop(adapter);

		sxe2vf_dev_state_set(adapter, SXE2VF_DEVSTATE_UNACTIVED,
				     SXE2VF_RESET_VFR);
	} else {
		ret = -EINVAL;
		LOG_ERROR_BDF("dev state:%u invalid reset type:%u.\n",
			      adapter->work_ctxt.dev_state,
			      adapter->work_ctxt.reset_type);
	}

	return ret;
}

static s32 sxe2vf_fault_state_proc(struct sxe2vf_adapter *adapter)
{
	sxe2vf_vf_stop(adapter);
	set_bit(SXE2VF_MONITOR_WORK_DISABLED, &adapter->work_ctxt.state);

	return 0;
}

static s32 sxe2vf_reset_notify_state_proc(struct sxe2vf_adapter *adapter)
{
	sxe2vf_auxdrv_send_reset_event(adapter);

	return 0;
}

STATIC s32 sxe2vf_dev_state_proc(struct sxe2vf_adapter *adapter, u32 *delay)
{
	s32 ret = 0;
	enum sxe2vf_dev_state state;
	enum sxe2vf_reset_type reset_type;

	*delay = SXE2VF_WOKER_DELAY_10MS;

	(void)sxe2vf_reset_detect(adapter);

	sxe2vf_dev_state_get(adapter, &state, &reset_type);

	switch (state) {
	case SXE2VF_DEVSTATE_INITIAL:
	case SXE2VF_DEVSTATE_STOPPED:
		ret = sxe2vf_stopped_state_proc(adapter);
		break;

	case SXE2VF_DEVSTATE_UNACTIVED:
		ret = sxe2vf_unactive_state_proc(adapter);
		break;

	case SXE2VF_DEVSTATE_ACTIVATED:
		ret = sxe2vf_active_state_proc(adapter);
		break;

	case SXE2VF_DEVSTATE_RUNNING:
		if (!sxe2vf_running_state_proc(adapter))
			*delay = SXE2VF_WOKER_DELAY_2S;
		break;

	case SXE2VF_DEVSTATE_VFR_REQUEST:
		ret = sxe2vf_vfr_req_state_proc(adapter);
		break;

	case SXE2VF_DEVSTATE_RESETTING:
		ret = sxe2vf_resetting_state_proc(adapter);
		break;

	case SXE2VF_DEVSTATE_FAULT:
		ret = sxe2vf_fault_state_proc(adapter);
		break;

	case SXE2VF_DEVSTATE_VFR_NOTIFY:
		(void)sxe2vf_reset_notify_state_proc(adapter);
		*delay = SXE2VF_WOKER_DELAY_5MS;
		LOG_WARN_BDF("rcv vf reset notify.\n");
		break;

	default:
		LOG_ERROR_BDF("Invalid device state %d\n", state);
		break;
	}

	if (ret)
		sxe2vf_common_err_handle(adapter, SXE2VF_DEVSTATE_PROC_FAIL_CNT,
					 SXE2VF_DEVSTATE_FAULT);

	return ret;
}

STATIC void sxe2vf_monitor_wk_cb(struct work_struct *work)
{
	struct sxe2vf_work_context *work_ctxt =
			container_of(to_delayed_work(work),
				     struct sxe2vf_work_context, monitor_wk);
	struct sxe2vf_adapter *adapter =
			container_of(work_ctxt, struct sxe2vf_adapter, work_ctxt);
	u32 delay = SXE2VF_WOKER_DELAY_2S;

	LOG_DEBUG_BDF("monitor work scheduled by %s.\n", current->comm);

	if (test_bit(SXE2VF_MONITOR_WORK_DISABLED, &work_ctxt->state)) {
		LOG_INFO_BDF("monitor work disabled no need rescheduled.\n");
		return;
	}

	if (!mutex_trylock(&work_ctxt->monitor_lock)) {
		LOG_INFO_BDF("state lock occupied, probe post work delay\t"
			     "scheduled.\n");
		goto l_reschedule;
	}

	(void)sxe2vf_dev_state_proc(adapter, &delay);

	mutex_unlock(&work_ctxt->monitor_lock);

l_reschedule:
	sxe2vf_wkq_schedule(adapter, SXE2VF_WK_MONITOR, delay);
}

STATIC void sxe2vf_mbx_wk_cb(struct work_struct *work)
{
	struct sxe2vf_work_context *wk =
			container_of(work, struct sxe2vf_work_context, mbx_wk);
	struct sxe2vf_adapter *adapter =
			container_of(wk, struct sxe2vf_adapter, work_ctxt);

	(void)wk;

	(void)sxe2vf_mbx_msg_rcv(adapter);

	sxe2vf_hw_event_irq_enable(&adapter->hw);
}

STATIC int sxe2vf_wait_config_space_accessible(struct sxe2vf_adapter *adapter)
{
	u32 delay = 1;
	u32 val;
	u32 timeout = SXE2VF_WAIT_CONFIG_ACCESSIBLE_TIMEOUT_MS;

	(void)pci_read_config_dword(adapter->pdev, SXE2VF_PCIE_SYS_READY, &val);
	while (val == SXE2VF_REG_INVAL_VALUE) {
		if (delay > timeout) {
			LOG_DEV_ERR("configuration space inaccessible. please check\t"
				    "the device.\n");
			return -ENOTTY;
		}

		msleep(delay);
		delay *= 2;
		(void)pci_read_config_dword(adapter->pdev, PCI_COMMAND, &val);
	}

	return 0;
}

STATIC void sxe2vf_health_wk_cb(struct work_struct *health_wk)
{
	struct sxe2vf_work_context *work_ctxt =
			container_of(to_delayed_work(health_wk),
				     struct sxe2vf_work_context, health_wk);
	struct sxe2vf_adapter *adapter =
			container_of(work_ctxt, struct sxe2vf_adapter, work_ctxt);
	enum sxe2vf_dev_state state;

	if (test_bit(SXE2VF_HEALTH_WORK_DISABLED, &work_ctxt->state)) {
		LOG_INFO_BDF("health work disabled no need rescheduled.\n");
		return;
	}

	if (sxe2vf_wait_config_space_accessible(adapter)) {
		sxe2vf_dev_state_set(adapter, SXE2VF_DEVSTATE_FAULT,
				     SXE2VF_RESET_NONE);
		sxe2vf_waitq_entry_cancel(adapter);
		sxe2vf_wkq_schedule(adapter, SXE2VF_WK_MONITOR_IM, 0);
		return;
	}

	if (sxe2vf_reset_detect(adapter)) {
		sxe2vf_waitq_entry_cancel(adapter);
		sxe2vf_wkq_schedule(adapter, SXE2VF_WK_MONITOR_IM, 0);
	}

	sxe2vf_dev_state_get(adapter, &state, SXE2VF_RESET_NONE);
	if (state != SXE2VF_DEVSTATE_FAULT)
		sxe2vf_wkq_schedule(adapter, SXE2VF_WK_HEALTH,
				    SXE2VF_WOKER_DELAY_2S);
}

STATIC void sxe2vf_mbx_waitq_init(struct sxe2vf_adapter *adapter)
{
	struct sxe2vf_mbx_waitq *waitq = &adapter->channel_ctxt.waitq;

	spin_lock_init(&waitq->lock);
	init_waitqueue_head(&waitq->wq);
	hash_init(waitq->table);
}

static s32 sxe2vf_health_init(struct sxe2vf_adapter *adapter)
{
	char *name;
	s32 ret = 0;
	struct device *dev = SXE2VF_ADAPTER_TO_DEV(adapter);

	name = kmalloc(SXE2VF_WORKQUEUE_NAME_LEN, GFP_KERNEL);
	if (!name) {
		LOG_DEV_ERR("sxe2vf health workqueue name alloc failed.\n");
		goto l_out;
	}

	snprintf(name, SXE2VF_WORKQUEUE_NAME_LEN, "sxe2vf_health%s", dev_name(dev));

	adapter->work_ctxt.health_wq = create_singlethread_workqueue(name);
	kfree(name);
	if (!adapter->work_ctxt.health_wq) {
		LOG_PR_ERR("failed to create health workqueue\n");
		ret = -EIO;
		goto l_out;
	}

	INIT_DELAYED_WORK(&adapter->work_ctxt.health_wk, sxe2vf_health_wk_cb);

l_out:
	return ret;
}

static void sxe2vf_health_deinit(struct sxe2vf_adapter *adapter)
{
	if (adapter->work_ctxt.health_wq)
		destroy_workqueue(adapter->work_ctxt.health_wq);
}

STATIC void sxe2vf_com_wk_cb(struct work_struct *work)
{
	s32 ret;
	struct sxe2vf_adapter *adapter =
			container_of(work, struct sxe2vf_adapter, com_work);

	ret = sxe2_com_init(&adapter->com_ctxt, adapter, &g_com_ops);
	if (ret)
		LOG_DEV_ERR("sxe2_com_init failed: %d.\n", ret);
}

STATIC void sxe2vf_sw_base_deinit(struct sxe2vf_adapter *adapter)
{
	sxe2vf_health_deinit(adapter);

	mutex_destroy(&adapter->aux_ctxt.adev_mutex);

	sxe2vf_filter_list_destroy(adapter);

	mutex_destroy(&adapter->vsi_ctxt.lock);

	mutex_destroy(&adapter->work_ctxt.monitor_lock);
	mutex_destroy(&adapter->dev_ctxt.vf_lock);

	mutex_destroy(&adapter->channel_ctxt.rxq.lock);
	mutex_destroy(&adapter->channel_ctxt.txq.lock);
	mutex_destroy(&adapter->channel_ctxt.list.lock);

	mutex_destroy(&adapter->link_ctxt.link_lock);
	mutex_destroy(&adapter->switch_ctxt.filter_ctxt.vlan_info.vlan_lock);
	mutex_destroy(&adapter->switch_ctxt.user_fltr_ctxt.vlan_info.vlan_lock);
	mutex_destroy(&adapter->switch_ctxt.flag_lock);
	mutex_destroy(&adapter->switch_ctxt.mac_addr_lock);

	mutex_destroy(&adapter->rss_ctxt.rss_cfgs_lock);

	mutex_destroy(&adapter->work_ctxt.reset_detect_lock);
}

STATIC s32 sxe2vf_sw_base_init(struct sxe2vf_adapter *adapter)
{
	s32 ret = 0;

	mutex_init(&adapter->link_ctxt.link_lock);

	mutex_init(&adapter->vsi_ctxt.lock);
	mutex_init(&adapter->dev_ctxt.vf_lock);

	mutex_init(&adapter->channel_ctxt.rxq.lock);
	mutex_init(&adapter->channel_ctxt.txq.lock);
	mutex_init(&adapter->channel_ctxt.list.lock);

	mutex_init(&adapter->switch_ctxt.mac_addr_lock);
	mutex_init(&adapter->switch_ctxt.flag_lock);
	mutex_init(&adapter->switch_ctxt.filter_ctxt.vlan_info.vlan_lock);
	mutex_init(&adapter->switch_ctxt.user_fltr_ctxt.vlan_info.vlan_lock);

	mutex_init(&adapter->work_ctxt.reset_detect_lock);

	INIT_LIST_HEAD(&adapter->switch_ctxt.filter_ctxt.mac_filter.mac_addr_list);
	INIT_LIST_HEAD(&adapter->switch_ctxt.filter_ctxt.vlan_info.vlan_list);
	INIT_LIST_HEAD(&adapter->switch_ctxt.user_fltr_ctxt.mac_filter
					.mac_addr_list);
	INIT_LIST_HEAD(&adapter->switch_ctxt.user_fltr_ctxt.vlan_info.vlan_list);
	INIT_LIST_HEAD(&adapter->channel_ctxt.list.head);

	init_waitqueue_head(&adapter->msg_ctxt.reply_waitqueue);

	mutex_init(&adapter->rss_ctxt.rss_cfgs_lock);
	INIT_LIST_HEAD(&adapter->rss_ctxt.rss_cfgs);

	INIT_DELAYED_WORK(&adapter->aux_ctxt.init_task, sxe2vf_aux_init_task);
	adapter->aux_ctxt.vfadapter = adapter;
	mutex_init(&adapter->aux_ctxt.adev_mutex);

	mutex_init(&adapter->work_ctxt.monitor_lock);

	INIT_DELAYED_WORK(&adapter->work_ctxt.monitor_wk, sxe2vf_monitor_wk_cb);
	INIT_WORK(&adapter->work_ctxt.mbx_wk, sxe2vf_mbx_wk_cb);
	INIT_WORK(&adapter->work_ctxt.msg_handle_wk, sxe2vf_notify_msg_wk_cb);

	INIT_WORK(&adapter->com_work, sxe2vf_com_wk_cb);
	ATOMIC_INIT_NOTIFIER_HEAD(&adapter->com_ctxt.irqs.irq_nh);

	sxe2vf_mbx_waitq_init(adapter);

	spin_lock_init(&adapter->work_ctxt.state_lock);

	sxe2vf_trace_id_init();

	sxe2vf_cmd_session_id_init();

	ret = sxe2vf_health_init(adapter);
	if (ret)
		sxe2vf_sw_base_deinit(adapter);

	return ret;
}

STATIC void sxe2vf_pci_deinit(struct sxe2vf_adapter *adapter)
{
	struct pci_dev *pdev = adapter->pdev;
	struct net_device *netdev = adapter->netdev;

	iounmap(adapter->hw.reg_base_addr);

#ifdef HAVE_PCI_ENABLE_PCIE_ERROR_REPORTING
	pci_disable_pcie_error_reporting(adapter->pdev);
#endif

	free_netdev(netdev);

	pci_set_drvdata(pdev, NULL);

	pci_release_regions(pdev);

	pci_disable_device(pdev);
}

STATIC int sxe2vf_probe(struct pci_dev *pdev,
			const struct pci_device_id __always_unused *ent)
{
	int ret;
	struct sxe2vf_adapter *adapter;

	adapter = sxe2vf_adapter_create(pdev);
	if (!adapter) {
		LOG_ERROR("can't probe virtual\n");
		return -ENOMEM;
	}

	sxe2vf_msg_level_init(adapter);

	ret = sxe2vf_pci_init(adapter);
	if (ret) {
		LOG_DEV_ERR("pci init failed, ret=%d\n", ret);
		free_netdev(adapter->netdev);
		goto l_out;
	}

	sxe2vf_hw_base_init(adapter);

	ret = sxe2vf_sw_base_init(adapter);
	if (ret) {
		LOG_DEV_ERR("sw base init failed. ret:%d.\n", ret);
		goto l_sw_base_init_fail;
	}

	sxe2vf_dev_state_set(adapter, SXE2VF_DEVSTATE_INITIAL, SXE2VF_RESET_NONE);

	sxe2vf_wkq_schedule(adapter, SXE2VF_WK_MONITOR,
			    SXE2VF_WOKER_DELAY_5MS * (adapter->pdev->devfn &
						      SXE2VF_DEV_FUNC_MASK));

	sxe2vf_wkq_schedule(adapter, SXE2VF_WK_HEALTH, SXE2VF_WOKER_DELAY_5MS);

	return ret;

l_sw_base_init_fail:
	sxe2vf_pci_deinit(adapter);

l_out:
	return ret;
}

STATIC void sxe2vf_remove(struct pci_dev *pdev)
{
	struct sxe2vf_adapter *adapter = SXE2VF_DEV_TO_ADAPTER(pdev);

	if (!adapter) {
		LOG_WARN("adapter NULL, skip vf remove oper.\n");
		return;
	}

	LOG_INFO_BDF("vf driver remove start.\n");

	sxe2vf_wkq_cancel(adapter, SXE2VF_WK_MONITOR);

	adapter->dev_ctxt.remove = true;
	sxe2vf_auxdrv_deinit(adapter);

	(void)sxe2vf_reset_msg_send(adapter);

	if (sxe2vf_reset_is_detected(adapter)) {
		set_bit(SXE2VF_FLAG_DRV_REMOVING, adapter->flags);
		sxe2vf_waitq_entry_cancel(adapter);
	}

	sxe2vf_probe_post_deinit(adapter, adapter->work_ctxt.post_state);

	sxe2vf_wkq_cancel_all(adapter);

	sxe2vf_sw_base_deinit(adapter);

	LOG_INFO_BDF("vf remove done.\n");

	sxe2vf_pci_deinit(adapter);
}

STATIC bool sxe2vf_wait_reset_done(struct sxe2vf_adapter *adapter)
{
	u32 i;

	for (i = 0; i < SXE2VF_RESET_COMPLETE_WAIT_COUNT; i++) {
		if (sxe2vf_hw_vfr_is_complete(&adapter->hw)) {
			sxe2vf_hw_vfr_clear(&adapter->hw);
			LOG_INFO_BDF("wait vf reset done success\n");
			return true;
		}
		msleep(SXE2VF_ACTIVE_WAIT_INTERVAL);
	}
	LOG_WARN_BDF("wait vf reset done timeout\n");
	return false;
}

STATIC pci_ers_result_t sxe2vf_pci_err_detected(struct pci_dev *pdev,
						pci_channel_state_t state)
{
	struct net_device *netdev = (struct net_device *)pdev->dev.driver_data;
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);

	pci_ers_result_t ret = PCI_ERS_RESULT_DISCONNECT;

	LOG_DEV_WARN("pci err:%u detected begin.\n", state);

	if (!adapter) {
		LOG_DEV_ERR("%s failed, device is unrecoverable pci err:0x%x\n",
			    __func__, state);
		goto l_out;
	}

	if (!test_bit(SXE2VF_FLAG_SUSPEND, adapter->flags)) {
		sxe2vf_wkq_cancel(adapter, SXE2VF_WK_MONITOR);
		sxe2vf_vf_stop(adapter);
	}

	pci_disable_device(pdev);

	ret = state == pci_channel_io_perm_failure ? PCI_ERS_RESULT_DISCONNECT
						   : PCI_ERS_RESULT_NEED_RESET;

l_out:
	LOG_DEV_WARN("pci err:%u detected end ret:%d.\n", state, ret);

	return ret;
}

STATIC pci_ers_result_t sxe2vf_pci_err_slot_reset(struct pci_dev *pdev)
{
	struct net_device *netdev = (struct net_device *)pdev->dev.driver_data;
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);

	pci_ers_result_t pci_ret = PCI_ERS_RESULT_DISCONNECT;
	s32 ret;
	bool reset_done = false;

	LOG_DEV_WARN("pci err slot reset begin.\n");

	if (!adapter) {
		LOG_DEV_ERR("%s failed, device is unrecoverable\n", __func__);
		goto l_out;
	}

	ret = pci_enable_device_mem(pdev);
	if (ret) {
		LOG_DEV_ERR("Cannot re-enable PCI device after reset, error %d\n",
			    ret);
		goto l_out;
	}

	pci_set_master(pdev);
	pci_restore_state(pdev);
	(void)pci_save_state(pdev);
	(void)pci_wake_from_d3(pdev, false);

	reset_done = sxe2vf_wait_reset_done(adapter);
	if (reset_done)
		pci_ret = PCI_ERS_RESULT_RECOVERED;

l_out:
	LOG_DEV_WARN("pci err slot reset end(%d) ret:%d.\n", reset_done, pci_ret);
	return pci_ret;
}

STATIC void sxe2vf_pci_err_resume(struct pci_dev *pdev)
{
	struct net_device *netdev = (struct net_device *)pdev->dev.driver_data;
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);

	LOG_DEV_WARN("pci err resume begin.\n");

	if (!adapter) {
		LOG_DEV_ERR("%s failed, device is unrecoverable\n", __func__);
		goto l_out;
	}

	if (test_bit(SXE2VF_FLAG_SUSPEND, adapter->flags)) {
		LOG_DEV_ERR("%s failed to resume normal operations!\n", __func__);
		goto l_out;
	}

	pci_restore_msi_state(pdev);

	sxe2vf_dev_state_set(adapter, SXE2VF_DEVSTATE_INITIAL, SXE2VF_RESET_NONE);
	clear_bit(SXE2VF_MONITOR_WORK_DISABLED, &adapter->work_ctxt.state);
	sxe2vf_wkq_schedule(adapter, SXE2VF_WK_MONITOR_IM, 0);
l_out:
	LOG_DEV_WARN("pci err resume end.\n");
}

#ifdef CONFIG_PM
static int __maybe_unused sxe2vf_pm_suspend(struct device *dev)
{
	s32 ret = 0;
	struct pci_dev *pdev = to_pci_dev(dev);
	struct net_device *netdev = (struct net_device *)pdev->dev.driver_data;
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);

	LOG_DEBUG_BDF("vf pm suspend was called\n");

	if (test_and_set_bit(SXE2VF_FLAG_SUSPEND, adapter->flags))
		goto l_end;

	sxe2vf_wkq_cancel(adapter, SXE2VF_WK_MONITOR);

	sxe2vf_vf_stop(adapter);

	sxe2vf_irq_deinit(adapter);

l_end:
	LOG_DEBUG_BDF("vf pm suspend end msix_enabled:%u current_state:%d ret=%d\n",
		      adapter->pdev->msix_enabled, adapter->pdev->current_state,
		      ret);
	return ret;
}

static int __maybe_unused sxe2vf_pm_resume(struct device *dev)
{
	s32 ret = 0;
	struct pci_dev *pdev = to_pci_dev(dev);
	struct net_device *netdev = (struct net_device *)pdev->dev.driver_data;
	struct sxe2vf_adapter *adapter = netdev_priv(netdev);

	LOG_DEBUG_BDF("vf pm resume was called\n");

	if (!test_bit(SXE2VF_FLAG_SUSPEND, adapter->flags))
		goto l_end;

	pci_set_master(pdev);

	ret = pci_set_power_state(pdev, PCI_D0);
	if (ret) {
		LOG_ERROR_BDF("pci_set_power_state with error code:%d\n", ret);
		goto l_end;
	}

	pci_restore_state(pdev);
	ret = pci_save_state(pdev);
	if (ret) {
		LOG_ERROR_BDF("pci_save_state with error code:%d.\n", ret);
		goto l_end;
	}

	LOG_DEBUG_BDF("pm resume msix_enabled:%u current_state:%d.\n",
		      adapter->pdev->msix_enabled, adapter->pdev->current_state);

	if (test_bit(SXE2VF_FLAG_DRV_PROBE_DONE, adapter->flags)) {
		ret = sxe2vf_msix_init(adapter);
		if (ret) {
			LOG_ERROR_BDF("sxe2vf_msix_init resume failed %d.\n", ret);
			goto l_end;
		}
		ret = sxe2vf_event_irq_request(adapter);
		if (ret) {
			LOG_ERROR_BDF("sxe2vf_irq_init resume failed %d.\n", ret);
			sxe2vf_msix_deinit(adapter);
			goto l_end;
		}
	}

	sxe2vf_dev_state_set(adapter, SXE2VF_DEVSTATE_INITIAL, SXE2VF_RESET_NONE);
	clear_bit(SXE2VF_MONITOR_WORK_DISABLED, &adapter->work_ctxt.state);
	sxe2vf_wkq_schedule(adapter, SXE2VF_WK_MONITOR_IM, 0);

	clear_bit(SXE2VF_FLAG_SUSPEND, adapter->flags);

l_end:
	LOG_DEBUG_BDF("vf pm resume end, ret=%d\n", ret);
	return ret;
}
#endif

static int __maybe_unused sxe2vf_pm_resume(struct device *dev);
static int __maybe_unused sxe2vf_pm_suspend(struct device *dev);

static __maybe_unused SIMPLE_DEV_PM_OPS(sxe2vf_pm_ops, sxe2vf_pm_suspend,
					sxe2vf_pm_resume);

STATIC const struct pci_error_handlers sxe2vf_pci_err_handler = {
		.error_detected = sxe2vf_pci_err_detected,
		.slot_reset = sxe2vf_pci_err_slot_reset,
		.resume = sxe2vf_pci_err_resume,
};

static struct pci_driver sxe2vf_pci_driver = {
		.name = SXE2VF_DRV_NAME,
		.id_table = sxe2vf_pci_tbl,
		.probe = sxe2vf_probe,
		.remove = sxe2vf_remove,
#ifdef CONFIG_PM
		.driver.pm = &sxe2vf_pm_ops,
#endif
		.err_handler = &sxe2vf_pci_err_handler,
};

STATIC s32 sxe2vf_wq_create(void)
{
	s32 ret = 0;

	sxe2vf_wq = alloc_workqueue("%s-MONITOR", WQ_UNBOUND, 0, SXE2VF_DRV_NAME);
	if (!sxe2vf_wq) {
		LOG_PR_ERR("failed to create %s driver workqueue\n",
			   SXE2VF_DRV_NAME);
		ret = -ENOMEM;
	}

	sxe2vf_mbx_wq = alloc_workqueue("%s-MBX", WQ_UNBOUND, 0, SXE2VF_DRV_NAME);
	if (!sxe2vf_mbx_wq) {
		LOG_PR_ERR("failed to create %s driver workqueue\n",
			   SXE2VF_DRV_NAME);
		goto l_monitor_wq_destroy;
	}

	sxe2vf_msg_handle_wq =
			alloc_workqueue("%s-MSG-HANDLE", 0, 0, SXE2VF_DRV_NAME);
	if (!sxe2vf_msg_handle_wq) {
		LOG_PR_ERR("failed to create msg handle workqueue\n");
		goto l_mbx_wq_destroy;
	}

	return ret;

l_mbx_wq_destroy:
	destroy_workqueue(sxe2vf_mbx_wq);
	sxe2vf_mbx_wq = NULL;

l_monitor_wq_destroy:
	destroy_workqueue(sxe2vf_wq);
	sxe2vf_wq = NULL;

	return ret;
}

STATIC void sxe2vf_wq_destroy(void)
{
	destroy_workqueue(sxe2vf_wq);
	sxe2vf_wq = NULL;

	destroy_workqueue(sxe2vf_mbx_wq);
	sxe2vf_mbx_wq = NULL;

	destroy_workqueue(sxe2vf_msg_handle_wq);
	sxe2vf_msg_handle_wq = NULL;
}

STATIC int __init sxe2vf_init(void)
{
	int ret;

	LOG_PR_INFO("%s init start, version[%s], commit_id[%s], branch[%s],\t"
		    "build_time[%s]\n",
		    SXE2VF_DRV_DESCRIPTION, SXE2_VERSION, SXE2_COMMIT_ID,
		    SXE2_BRANCH, SXE2_BUILD_TIME);

#ifndef SXE2_CFG_RELEASE
	ret = sxe2_log_init(true);
	if (ret < 0) {
		LOG_PR_ERR("sxe2 log init fail.(err:%d)\n", ret);
		return ret;
	}
#endif

	ret = sxe2vf_wq_create();
	if (ret)
		goto l_log_exit;

	ret = sxe2_com_adapter_register(SXE2_VF);
	if (ret) {
		LOG_ERROR("register dpdk char dev failed\n");
		goto l_wq_destroy;
	}

	sxe2vf_debugfs_init();

	ret = pci_register_driver(&sxe2vf_pci_driver);
	if (ret) {
		LOG_PR_ERR("register pci driver:%s failed\n", SXE2VF_DRV_NAME);
		goto l_com_unregister;
	}

	return 0;

l_com_unregister:
	sxe2vf_debugfs_exit();
	sxe2_com_adapter_unregister();
l_wq_destroy:
	sxe2vf_wq_destroy();
l_log_exit:
#ifndef SXE2_CFG_RELEASE
	sxe2_log_exit();
#endif
	return ret;
}

STATIC void __exit sxe2vf_exit(void)
{
	pci_unregister_driver(&sxe2vf_pci_driver);

	sxe2vf_debugfs_exit();

	sxe2_com_adapter_unregister();

	sxe2vf_wq_destroy();

#ifndef SXE2_CFG_RELEASE
	sxe2_log_exit();
#endif
}

MODULE_DEVICE_TABLE(pci, sxe2vf_pci_tbl);
MODULE_INFO(build_time, SXE2_BUILD_TIME);
MODULE_INFO(branch, SXE2_BRANCH);
MODULE_INFO(arch, SXE2_DRV_ARCH);
MODULE_INFO(commit_id, SXE2_COMMIT_ID);
MODULE_DESCRIPTION(SXE2VF_DRV_DESCRIPTION);
MODULE_AUTHOR(SXE2_DRV_AUTHOR);
MODULE_VERSION(SXE2_VERSION);
MODULE_LICENSE(SXE2_DRV_LICENSE);

module_init(sxe2vf_init);
module_exit(sxe2vf_exit);
