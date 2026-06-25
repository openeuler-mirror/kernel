// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_main.c
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/pci.h>

#include "sxe2_compat.h"
#include "sxe2.h"
#include "sxe2_hw.h"
#include "sxe2_log.h"
#include "sxe2_devlink.h"
#include "sxe2_version.h"
#include "sxe2_common.h"
#include "sxe2_netdev.h"
#include "sxe2_queue.h"
#include "sxe2_monitor.h"
#include "sxe2_sriov.h"
#include "sxe2_log_export.h"
#include "sxe2_debugfs.h"
#include "sxe2_event.h"
#include "sxe2_dcb.h"
#include "sxe2_rss.h"
#include "sxe2_fnav.h"
#include "sxe2_txsched.h"
#include "sxe2_ipsec.h"
#include "sxe2_macsec.h"
#include "sxe2_ddp.h"
#include "sxe2_ethtool.h"
#include "sxe2_lag.h"
#include "sxe2_xsk.h"
#include "sxe2_udp_tunnel.h"
#include "sxe2_com_ioctl.h"
#include "sxe2_irq.h"
#include "sxe2_vsi.h"

#define CREATE_TRACE_POINTS
#include "sxe2_trace.h"
#undef CREATE_TRACE_POINTS

#define SXE2_DMA_BIT_WIDTH_64 64

STATIC const struct pci_device_id sxe2_pci_tbl[] = {
		{SXE2_PCI_VENDOR_ID_1, SXE2_PCI_DEVICE_ID_1, PCI_ANY_ID, PCI_ANY_ID,
		 0, 0, 0},
		{SXE2_PCI_VENDOR_ID_2, SXE2_PCI_DEVICE_ID_2, PCI_ANY_ID, PCI_ANY_ID,
		 0, 0, 0},
		{SXE2_PCI_VENDOR_ID_1, SXE2_PCI_DEVICE_ID_10B3, PCI_ANY_ID,
		 PCI_ANY_ID, 0, 0, 0},
		{SXE2_PCI_VENDOR_ID_206F, SXE2_PCI_DEVICE_ID_1, PCI_ANY_ID,
		 PCI_ANY_ID, 0, 0, 0},
		{
				0,
		}};

STATIC int com_mode = SXE2_COM_MODULE_UNDEFINED;
module_param(com_mode, uint, 0644);
MODULE_PARM_DESC(com_mode, "driver mode. kernel:0, mixed:2(default)");

STATIC int debug = -1;
module_param(debug, int, 0644);
#ifndef CONFIG_DYNAMIC_DEBUG
MODULE_PARM_DESC(debug, "netif level (0=none,...,16=all), debug_mask (0x8XXXXXXXX)");
#else
MODULE_PARM_DESC(debug, "netif level (0=none,...,16=all)");
#endif

#ifdef SXE2_CFG_DEBUG
int reg_log;
module_param(reg_log, int, 0644);
MODULE_PARM_DESC(reg_log, "reg read/write log, 0-off 1-on.");

int switch_heart_check = 1;
module_param(switch_heart_check, int, 0644);
MODULE_PARM_DESC(switch_heart_check,
		 "heart check switch on/off. switch off:0. switch on:1. default: 1");

s32 g_pf_switch_stats = 1;
module_param(g_pf_switch_stats, int, 0644);
MODULE_PARM_DESC(g_pf_switch_stats,
		 "pf switch  stats open/close. open:1. close:1. default: 1");
#endif

int allow_inval_mac;
module_param(allow_inval_mac, int, 0644);
MODULE_PARM_DESC(allow_inval_mac,
		 "Indicates device can be probed successfully or \t"
		 "not when mac addr invalid.");

static void sxe2_com_ctxt_fill(void *adapter)
{
	struct sxe2_adapter *pf_adapter = adapter;

	pf_adapter->com_ctxt.pdev = pf_adapter->pdev;
	pf_adapter->com_ctxt.func_type = SXE2_PF;
	pf_adapter->com_ctxt.pf_id = pf_adapter->pf_idx;
}

int sxe2_com_mode_get(void *adapter)
{
	return ((struct sxe2_adapter *)adapter)->drv_mode;
}

int sxe2_g_com_mode_get(void)
{
	return com_mode;
}

static struct sxe2_com_ops g_com_ops = {
		.com_ctxt_fill = sxe2_com_ctxt_fill,
		.cmd_exec = sxe2_com_cmd_send,
		.get_irq_num = sxe2_dpdk_irq_cnt_get,
		.get_vector = sxe2_dpdk_irq_vector_idx_get,
		.release = sxe2_dpdk_resource_release,
		.com_mode_get = sxe2_com_mode_get,
};

static inline u32 sxe2_readl(const __iomem void *reg)
{
	return readl(reg);
}

static inline void sxe2_writel(u32 value, __iomem void *reg)
{
	writel(value, reg);
}

STATIC int sxe2_pci_init(struct sxe2_adapter *adapter)
{
	int ret;
	struct pci_dev *pdev = adapter->pdev;

	ret = pcim_enable_device(pdev);
	if (ret)
		goto l_end;

	ret = dma_set_mask_and_coherent(&adapter->pdev->dev,
					DMA_BIT_MASK(SXE2_DMA_BIT_WIDTH_64));
	if (ret) {
		LOG_DEV_ERR("device[pci_id %u] 64 dma mask and coherent set failed\n",
			    adapter->pdev->dev.id);
		goto l_end;
	}

#ifdef HAVE_PCI_ENABLE_PCIE_ERROR_REPORTING
	pci_enable_pcie_error_reporting(pdev);
#endif

	pci_set_master(pdev);

	(void)pci_save_state(pdev);
	pci_set_drvdata(pdev, adapter);

l_end:
	return ret;
}

void sxe2_pci_deinit(struct sxe2_adapter *adapter)
{
	struct pci_dev *pdev = adapter->pdev;

#ifdef HAVE_PCI_ENABLE_PCIE_ERROR_REPORTING
	pci_disable_pcie_error_reporting(adapter->pdev);
#endif

	pci_set_drvdata(pdev, NULL);
}

s32 sxe2_hw_cfg_info_get(struct sxe2_adapter *adapter)
{
	s32 ret = 0;
	u32 value;

	value = sxe2_hw_irq_gran_info_get(&adapter->hw);
	if (value == SXE2_REG_INVALID_VALUE)
		return -EIO;

	adapter->hw.hw_cfg.credit_interval_gran =
			value & SXE2_PFG_INT_CTL_CREDIT_GRAN
					? SXE2_PFG_INT_CTL_CREDIT_GRAN_1
					: SXE2_PFG_INT_CTL_CREDIT_GRAN_0;
	adapter->hw.hw_cfg.itr_gran =
			(u16)FIELD_GET(SXE2_PFG_INT_CTL_ITR_GRAN, value);
	if (!adapter->hw.hw_cfg.itr_gran)
		adapter->hw.hw_cfg.itr_gran = SXE2_PFG_INT_CTL_ITR_GRAN_0;

	LOG_DEBUG_BDF("hw cfg info: itr_gran %d, intrl_gran %d.\n",
		      adapter->hw.hw_cfg.itr_gran,
		      adapter->hw.hw_cfg.credit_interval_gran);

	return ret;
}

STATIC s32 sxe2_bar_region_map(struct pci_dev *pdev, struct sxe2_map_info *map)
{
	resource_size_t size, base;
	void __iomem *addr;

	if (WARN_ON(map->end <= map->start)) {
		LOG_ERROR("map end:0x%llx start:0x%llx invalid.\n", map->end,
			  map->start);
		return -EIO;
	}

	size = map->end - map->start;
	base = pci_resource_start(pdev, map->bar_idx) + map->start;
	addr = ioremap(base, size);
	if (!addr) {
		LOG_ERROR("%s: remap at offset:%llu size:%llu failed\n", __func__,
			  map->start, size);
		return -EIO;
	}

	map->addr = addr;
	LOG_INFO("start:0x%llx end:0x%llx size:0x%llx map success addr:%pK.\n",
		 map->start, map->end, size, addr);

	return 0;
}

STATIC s32 sxe2_bar_addr_map(struct sxe2_adapter *adapter)
{
	struct pci_dev *pdev = adapter->pdev;
	struct device *dev = &pdev->dev;
	struct sxe2_hw_map *map_info;
	resource_size_t bar_len;
	u32 nr_maps;
	u32 i;
	s32 ret;

	bar_len = pci_resource_len(pdev, 0);
	if (bar_len > SXE2_BAR_RDMA_WB_END)
		nr_maps = 2;
	else
		nr_maps = 1;

	map_info = kzalloc(struct_size(map_info, maps, nr_maps), GFP_KERNEL);
	if (!map_info) {
		LOG_ERROR_BDF("nr_maps:%u bar_len:%llu map info memory alloc fail.\n",
			      nr_maps, bar_len);
		return -ENOMEM;
	}

	map_info->map_cnt = nr_maps;

	ret = pci_request_mem_regions(pdev, dev_driver_string(dev));
	if (ret) {
		LOG_DEV_ERR("nr_maps:%u bar_len:%llu pci_request_mem_regions failed.\n",
			    nr_maps, bar_len);
		goto err_free_hw_addr;
	}

	for (i = 0; i < nr_maps; i++) {
		map_info->maps[i].bar_idx = 0;
		if (i == 0) {
			map_info->maps[0].start = 0;
			map_info->maps[0].end = min_t(resource_size_t, bar_len,
						      SXE2_BAR_RDMA_WB_START);
		} else if (i == 1) {
			map_info->maps[1].start = SXE2_BAR_RDMA_WB_END;
			map_info->maps[1].end = bar_len;
		}
		ret = sxe2_bar_region_map(pdev, &map_info->maps[i]);
		if (ret)
			goto err_release_mem_regions;
	}

	adapter->hw.hw_map = (typeof(adapter->hw.hw_map))map_info;

	LOG_INFO_BDF("bar_len:0x%llx map_cnt:%u map_info:%pK.\n", bar_len, nr_maps,
		     map_info);
	return 0;

err_release_mem_regions:
	if (i == 1)
		iounmap(map_info->maps[0].addr);
	pci_release_mem_regions(pdev);
err_free_hw_addr:
	kfree(map_info);
	return ret;
}

STATIC void sxe2_bar_addr_unmap(struct sxe2_adapter *adapter)
{
	struct sxe2_hw_map *hw_map = (struct sxe2_hw_map *)adapter->hw.hw_map;
	struct pci_dev *pdev = adapter->pdev;
	u32 i;

	if (WARN_ON(!hw_map))
		return;

	adapter->hw.hw_map = NULL;
	for (i = 0; i < hw_map->map_cnt; i++)
		iounmap(hw_map->maps[i].addr);
	kfree(hw_map);

	pci_release_mem_regions(pdev);
}

STATIC s32 sxe2_request_fw(struct sxe2_adapter *adapter,
			   const struct firmware **firmware)
{
	s32 err = 0;
	struct device *dev = &adapter->pdev->dev;

	err = request_firmware(firmware, SXE2_DDP_PKG_FILE, dev);
	if (err)
		LOG_DEV_ERR("the DDP package file was not found or could not be read.\t"
			    "Entering Safe Mode\n");

	return err;
}

STATIC s32 sxe2_init_ddp_config(struct sxe2_adapter *adapter)
{
	const struct firmware *firmware = NULL;
	s32 err;

	err = sxe2_request_fw(adapter, &firmware);
	if (err)
		return err;

	sxe2_load_pkg(firmware, adapter);
	release_firmware(firmware);
	return err;
}

void sxe2_fw_version_get(struct sxe2_adapter *adapter)
{
	u32 fw_ver;
	struct sxe2_hw *hw = &adapter->hw;

	fw_ver = sxe2_fw_ver_get(hw);
	hw->fw_ver.build_id = fw_ver & SXE2_FW_VER_BUILD_M;
	hw->fw_ver.fix_version_id =
			(fw_ver & SXE2_FW_VER_FIX_M) >> SXE2_FW_VER_FIX_SHIFT;
	hw->fw_ver.sub_version_id =
			(fw_ver & SXE2_FW_VER_SUB_M) >> SXE2_FW_VER_SUB_SHIFT;
	hw->fw_ver.main_version_id =
			(fw_ver & SXE2_FW_VER_MAIN_M) >> SXE2_FW_VER_MAIN_SHIFT;
}

static void sxe2_link_status_sync(struct sxe2_adapter *adapter)
{
	s32 ret;
	struct sxe2_cmd_params cmd = {};

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_FLM_LINK_STATUS_SYNC, NULL, 0, NULL,
				  0);
	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret)
		LOG_DEV_ERR("sync link status failed, ret=%d\n", ret);
}

STATIC void sxe2_hw_board_type_get(struct sxe2_adapter *adapter)
{
	struct sxe2_hw *hw = &adapter->hw;
	u32 value;

	value = sxe2_fw_pop_get(hw);
	LOG_INFO_BDF("pop type reg value=%d.\n", value);
	if (!!value)
		hw->is_pop_type = true;
	else
		hw->is_pop_type = false;
}

STATIC s32 sxe2_hw_base_init(struct sxe2_adapter *adapter)
{
	s32 ret;
	struct sxe2_hw *hw;

	hw = &adapter->hw;
	hw->adapter = adapter;

	sxe2_dev_ctrl_init_once(adapter);

#if !defined(SXE2_TEST) && !defined(SXE2VF_TEST)
	ret = sxe2_wait_reset_done(adapter, SXE2_RESET_CORER);
	if (ret)
		goto l_end;
#endif
	ret = sxe2_stop_drop(adapter);
	if (ret)
		goto l_end;

	adapter->dev_ctrl_ctxt.dev_state = SXE2_DEVSTATE_ACCESSIBLE;

	ret = sxe2_bar_addr_map(adapter);
	if (ret) {
		LOG_DEV_ERR("pci bar map fail, ret=%d\n", ret);
		goto l_end;
	}

	sxe2_hw_reg_handle_init(hw, sxe2_readl, sxe2_writel);

	ret = sxe2_wait_fw_init(adapter);
	if (ret)
		goto l_unmap;

	ret = sxe2_reset_sync(adapter, SXE2_RESET_PFR);
	if (ret) {
		LOG_DEV_ERR("PFR failed, ret=%d\n", ret);
		goto l_unmap;
	}

	sxe2_fw_version_get(adapter);

	ret = sxe2_cmd_channels_init(adapter);
	if (ret) {
		LOG_DEV_ERR("init cmd channel failed, ret=%d\n", ret);
		goto l_unmap;
	}

	if (sxe2_drv_mode_get(adapter)) {
		LOG_ERROR_BDF("get drv mode failed, ret=%d\n", ret);
		adapter->drv_mode = SXE2_COM_MODULE_MIXED;
	}

	ret = sxe2_fwc_clear_pf_cfg(adapter);
	if (ret) {
		LOG_DEV_ERR("clear pf cfg failed, ret=%d\n", ret);
		goto l_cmd_channel_release;
	}

	ret = sxe2_fwc_pxe_disable(adapter);
	if (ret) {
		LOG_DEV_ERR("pxe mode disable failed, ret=%d\n", ret);
		goto l_unmap;
	}

	sxe2_hw_board_type_get(adapter);

	ret = sxe2_hw_cfg_info_get(adapter);
	if (ret) {
		LOG_DEV_ERR("get hw cfg failed, ret=%d\n", ret);
		goto l_cmd_channel_release;
	}

	set_bit(SXE2_FLAG_SWITCHDEV_CAPABLE, adapter->flags);

	ret = sxe2_hw_mtu_init(adapter, SXE2_MAX_FRAME_SIZE, true);
	if (ret) {
		LOG_DEV_ERR("hw mtu init failed, ret=%d\n", ret);
		goto l_cmd_channel_release;
	}
	(void)sxe2_init_ddp_config(adapter);

	ret = sxe2_caps_get(adapter);
	if (ret) {
		LOG_DEV_ERR("get device and function caps failed, ret=%d\n", ret);
		goto l_cmd_channel_release;
	}
	sxe2_hw_pf_stats_update(adapter);

	sxe2_link_status_sync(adapter);

	return ret;

l_cmd_channel_release:
	sxe2_cmd_channels_deinit(adapter);
l_unmap:
	sxe2_bar_addr_unmap(adapter);
l_end:
	sxe2_dev_ctrl_deinit_once(adapter);
	return ret;
}

STATIC void sxe2_hw_base_deinit(struct sxe2_adapter *adapter)
{
	sxe2_cmd_channels_deinit(adapter);

	if (!sxe2_hw_is_fault(&adapter->hw)) {
		if (sxe2_reset_sync(adapter, SXE2_RESET_PFR))
			LOG_ERROR_BDF("PFR failed.\n");
	}

	sxe2_bar_addr_unmap(adapter);

	sxe2_free_seg(adapter);

	sxe2_dev_ctrl_deinit_once(adapter);
}

STATIC void sxe2_sw_lock_init(struct sxe2_adapter *adapter)
{
	mutex_init(&adapter->irq_ctxt.lock);
	mutex_init(&adapter->q_ctxt.lock);
	mutex_init(&adapter->vsi_ctxt.lock);
	mutex_init(&adapter->dcb_ctxt.tc_mutex);
	mutex_init(&adapter->aux_ctxt.adev_mutex);
	mutex_init(&adapter->switch_ctxt.lldp_rule_lock);
	spin_lock_init(&adapter->monitor_ctxt.lock);
}

STATIC void sxe2_sw_lock_deinit(struct sxe2_adapter *adapter)
{
	mutex_destroy(&adapter->switch_ctxt.lldp_rule_lock);
	mutex_destroy(&adapter->irq_ctxt.lock);
	mutex_destroy(&adapter->q_ctxt.lock);
	mutex_destroy(&adapter->vsi_ctxt.lock);
	mutex_destroy(&adapter->dcb_ctxt.tc_mutex);
	mutex_destroy(&adapter->aux_ctxt.adev_mutex);
	mutex_destroy(&adapter->udp_tunnel_ctxt.lock);
}

STATIC s32 sxe2_sw_vsi_array_alloc(struct sxe2_adapter *adapter)
{
	s32 ret = 0;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);

	adapter->vsi_ctxt.vsi =
			devm_kcalloc(dev, adapter->vsi_ctxt.max_cnt,
				     sizeof(*adapter->vsi_ctxt.vsi), GFP_KERNEL);
	if (!adapter->vsi_ctxt.vsi) {
		ret = -ENOMEM;
		LOG_DEV_ERR("alloc vsis failed, count: %d, size: %zu.\n",
			    adapter->vsi_ctxt.max_cnt,
			    sizeof(*adapter->vsi_ctxt.vsi));
	}

	return ret;
}

STATIC void sxe2_link_ctxt_init(struct sxe2_adapter *adapter)
{
	memset(&adapter->link_ctxt, 0, sizeof(struct sxe2_cmd_link_context));
	mutex_init(&adapter->link_ctxt.link_status_lock);
}

STATIC void sxe2_link_ctxt_deinit(struct sxe2_adapter *adapter)
{
	mutex_destroy(&adapter->link_ctxt.link_status_lock);
	memset(&adapter->link_ctxt, 0, sizeof(struct sxe2_cmd_link_context));
}

STATIC s32 sxe2_sw_init_once(struct sxe2_adapter *adapter)
{
	s32 ret = 0;
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);

	sxe2_link_ctxt_init(adapter);

	sxe2_sw_lock_init(adapter);

	ret = sxe2_sw_vsi_array_alloc(adapter);
	if (ret)
		goto l_vsis_alloc_failed;

	sxe2_vf_init(adapter);

	ret = sxe2_switch_context_init(adapter);
	if (ret) {
		LOG_ERROR_BDF("init switch ctx failed, ret=%d\n", ret);
		goto l_switch_ctx_init_failed;
	}
	sxe2_fnav_ctxt_init(adapter);
	(void)sxe2_arfs_init(adapter);

	ret = sxe2_acl_init(adapter);
	if (ret) {
		LOG_ERROR_BDF("init acl failed, ret=%d\n", ret);
		goto l_acl_init_failed;
	}

	sxe2_rss_flow_ctxt_init(adapter);

	(void)sxe2_ddp_params_store(adapter);

	ATOMIC_INIT_NOTIFIER_HEAD(&adapter->com_ctxt.irqs.irq_nh);

	return 0;

l_acl_init_failed:
	sxe2_arfs_deinit(adapter);
	sxe2_fnav_ctxt_deinit(adapter);
	sxe2_switch_context_deinit(adapter);
l_switch_ctx_init_failed:
	sxe2_vf_deinit(adapter);
	if (adapter->vsi_ctxt.vsi) {
		devm_kfree(dev, adapter->vsi_ctxt.vsi);
		adapter->vsi_ctxt.vsi = NULL;
	}

l_vsis_alloc_failed:
	sxe2_sw_lock_deinit(adapter);
	sxe2_link_ctxt_deinit(adapter);
	return ret;
}

STATIC void sxe2_sw_deinit_once(struct sxe2_adapter *adapter)
{
	struct device *dev = SXE2_ADAPTER_TO_DEV(adapter);

	sxe2_rss_flow_ctxt_deinit(adapter);

	sxe2_arfs_deinit(adapter);
	sxe2_fnav_ctxt_deinit(adapter);
	sxe2_acl_deinit(adapter);

	sxe2_vf_deinit(adapter);

	if (adapter->vsi_ctxt.vsi) {
		devm_kfree(dev, adapter->vsi_ctxt.vsi);
		adapter->vsi_ctxt.vsi = NULL;
	}

	sxe2_switch_context_deinit(adapter);

	sxe2_sw_lock_deinit(adapter);
	sxe2_link_ctxt_deinit(adapter);
}

STATIC s32 sxe2_mac_addr_init(struct sxe2_vsi *vsi)
{
	s32 ret = 0;
	struct sxe2_adapter *adapter = vsi->adapter;
	struct sxe2_hw *hw = &adapter->hw;
	u8 broadcast[ETH_ALEN];

	ret = sxe2_default_mac_addr_get(vsi, hw->mac_info.perm_addr);
	if (ret)
		return ret;

	ret = sxe2_cur_mac_addr_set(vsi, hw->mac_info.perm_addr);
	if (ret)
		return ret;

	if (!is_valid_ether_addr(hw->mac_info.perm_addr)) {
		LOG_DEV_INFO("current mac addr:%pM invalid.\n",
			     hw->mac_info.perm_addr);
	}

	eth_hw_addr_set(vsi->netdev, hw->mac_info.perm_addr);

	if (allow_inval_mac == 0) {
		(void)mutex_lock(&adapter->vsi_ctxt.lock);
		ret = sxe2_mac_addr_add(vsi, hw->mac_info.perm_addr,
					SXE2_MAC_OWNER_NETDEV);
		(void)mutex_unlock(&adapter->vsi_ctxt.lock);
		if (ret)
			return ret;
	}

	eth_broadcast_addr(broadcast);
	ret = sxe2_mac_rule_add(vsi, broadcast);

	return ret;
}

STATIC void sxe2_log_pkg_init(struct sxe2_adapter *adapter, s32 err)
{
	switch (err) {
	case SXE2_DDP_PKG_SUCCESS:
		LOG_DEV_INFO("the DDP package was successfully loaded\n");
		break;
	case -SXE2_DDP_PKG_SAME_VERSION_ALREADY_LOADED:
		LOG_DEV_INFO("DDP package already present on device.\n");
		break;
	case -SXE2_DDP_PKG_ALREADY_LOADED_NOT_SUPPORTED:
		LOG_DEV_ERR("the device has a DDP package that is not supported by\t"
			    "the driver.\n");
		break;
	case -SXE2_DDP_PKG_COMPATIBLE_ALREADY_LOADED:
		LOG_DEV_INFO("the driver could not load the DDP package file.\t"
			     "because a compatible DDP package is already present\t"
			     "on the device.\n");
		break;
	case -SXE2_DDP_PKG_FW_MISMATCH:
		LOG_DEV_ERR("the firmware loaded on the device is not compatible\t"
			    "with the DDP package. Please update the device's NVM.\t"
			    "Entering safe mode.\n");
		break;
	case -SXE2_DDP_PKG_INVALID_FILE:
		LOG_DEV_ERR("the DDP package file is invalid. Entering Safe\t"
			    "Mode.\n");
		break;
	case -SXE2_DDP_PKG_FILE_VERSION_TOO_HIGH:
		LOG_DEV_ERR("the DDP package file version is higher than the driver\t"
			    "supports. Please use an updated driver. Entering Safe\t"
			    "Mode.\n");
		break;
	case -SXE2_DDP_PKG_FILE_VERSION_TOO_LOW:
		LOG_DEV_ERR("the DDP package file version is lower than the driver\t"
			    "supports.\n");
		break;
	case -SXE2_DDP_PKG_NO_SEC_MANIFEST:
		LOG_DEV_ERR("the DDP package could not be loaded because its\t"
			    "security manifest is missing. Please use a valid DDP\t"
			    "Package. Entering Safe Mode.\n");
		break;
	case -SXE2_DDP_PKG_MANIFEST_INVALID:
	case -SXE2_DDP_PKG_BUFFER_INVALID:
		LOG_DEV_ERR("an error occurred on the device while loading the DDP package.\n"
			    "The device will be reset.\n");
		break;
	case -SXE2_DDP_PKG_ERR:
	default:
		LOG_DEV_ERR("an unknown error occurred when loading the DDP package.\n"
			    "Entering Safe Mode.\n");
		break;
	}
}

void sxe2_load_pkg(const struct firmware *firmware, struct sxe2_adapter *adapter)
{
	s32 ret = SXE2_DDP_PKG_ERR;
	struct sxe2_hw *hw = &adapter->hw;

	if (firmware && !hw->pkg_copy) {
		ret = sxe2_copy_and_init_pkg(adapter, firmware->data,
					     firmware->size);
		sxe2_log_pkg_init(adapter, ret);
	} else if (!firmware && hw->pkg_copy) {
		ret = sxe2_init_pkg(adapter, hw->pkg_copy, hw->pkg_size);
	} else {
		LOG_DEV_WARN("The DDP package file failed to load. Entering Safe Mode.\n");
	}

	if (!sxe2_is_init_pkg_successful(ret)) {
		clear_bit(SXE2_FLAG_ADVANCE_MODE, adapter->flags);
		return;
	}

	set_bit(SXE2_FLAG_ADVANCE_MODE, adapter->flags);
}

STATIC s32 sxe2_serial_num_get(struct sxe2_adapter *adapter)
{
	s32 ret = 0;
	struct sxe2_fwc_serial_num_resp resp = {};
	struct sxe2_cmd_params cmd = {};

	sxe2_cmd_params_dflt_fill(&cmd, SXE2_CMD_PF_SERIAL_GET, NULL, 0, &resp,
				  sizeof(resp));
	ret = sxe2_cmd_fw_exec(adapter, &cmd);
	if (ret) {
		LOG_DEV_ERR("get serial num failed, ret=%d\n", ret);
		ret = -EIO;
	}

	memcpy(adapter->serial_num, resp.serial_num, SXE2_SERIAL_NUM_LEN);

	return ret;
}

STATIC s32 sxe2_init_eth(struct sxe2_adapter *adapter)
{
	s32 ret;
	struct sxe2_vsi *pf_vsi;

	ret = sxe2_txsched_init(adapter);
	if (ret) {
		LOG_DEV_ERR("txsched failed, ret=%d\n", ret);
		goto l_sched_init_failed;
	}

	ret = sxe2_irq_init(adapter);
	if (ret) {
		LOG_DEV_ERR("init irq failed, ret=%d\n", ret);
		goto l_irq_init_failed;
	}

	sxe2_queue_init(adapter);

	if (sxe2_com_mode_get(adapter) != SXE2_COM_MODULE_DPDK) {
		ret = sxe2_main_vsi_create(adapter);
		if (ret) {
			LOG_DEV_ERR("create main vsi failed, ret=%d\n", ret);
			goto l_main_vsi_failed;
		}

		pf_vsi = adapter->vsi_ctxt.main_vsi;
		ret = sxe2_netdev_init(pf_vsi);
		if (ret) {
			LOG_DEV_ERR("netdev init failed, ret=%d\n", ret);
			goto l_netdev_init_failed;
		}
		ret = sxe2_mac_addr_init(pf_vsi);
		if (ret) {
			LOG_DEV_ERR("mac filter config failed, ret=%d\n", ret);
			goto l_netdev_fltr_failed;
		}
		sxe2_napi_add(pf_vsi);
	}

	ret = sxe2_serial_num_get(adapter);
	if (ret) {
		LOG_DEV_ERR("get serial num failed, ret=%d\n", ret);
		goto l_netdev_fltr_failed;
	}

	ret = sxe2_lldp_agent_event_init(adapter);
	if (ret) {
		LOG_ERROR_BDF("init lldp event failed, ret=%d\n", ret);
		goto l_netdev_fltr_failed;
	}

	return 0;

l_netdev_fltr_failed:
	sxe2_netdev_deinit(adapter->vsi_ctxt.main_vsi);
l_netdev_init_failed:
	sxe2_vsi_destroy(adapter->vsi_ctxt.main_vsi);
	adapter->vsi_ctxt.main_vsi = NULL;
l_main_vsi_failed:
	sxe2_irq_deinit(adapter);
l_irq_init_failed:
l_sched_init_failed:
	sxe2_txsched_deinit(adapter);

	return ret;
}

STATIC void sxe2_deinit_eth(struct sxe2_adapter *adapter)
{
	if (sxe2_com_mode_get(adapter) != SXE2_COM_MODULE_DPDK) {
		sxe2_napi_del(adapter->vsi_ctxt.main_vsi);
		sxe2_netdev_deinit(adapter->vsi_ctxt.main_vsi);
		sxe2_vsi_destroy(adapter->vsi_ctxt.main_vsi);
		adapter->vsi_ctxt.main_vsi = NULL;
	}
	sxe2_irq_deinit(adapter);
	sxe2_txsched_deinit(adapter);
}

STATIC s32 sxe2_init_aux(struct sxe2_adapter *adapter)
{
	s32 ret = 0;

	if (!sxe2_is_safe_mode(adapter)) {
		ret = sxe2_rdma_aux_init(adapter);
		if (ret) {
			LOG_DEV_ERR("rdma aux init failed, ret=%d\n", ret);
			goto l_end;
		}

		ret = sxe2_rdma_aux_add(adapter);
		if (ret) {
			LOG_DEV_ERR("rdma aux add failed, ret=%d\n", ret);
			ret = 0;
		}
	} else {
		LOG_DEV_INFO("running in safe mode,rdma is not supported\n");
	}

l_end:
	return ret;
}

STATIC s32 sxe2_init_feature_with_netdev(struct sxe2_adapter *adapter)
{
	s32 ret;

#ifdef HAVE_MACSEC_SUPPORT
	ret = sxe2_macsec_init(adapter);
	if (ret) {
		LOG_DEV_ERR("macsec initial failed.\n");
		goto l_macsec_init_failed;
	}
#endif

	ret = sxe2_ipsec_init(adapter);
	if (ret) {
		LOG_DEV_ERR("ipsec initial failed.\n");
		goto l_ipsec_init_failed;
	}

	ret = sxe2_lag_init(adapter);
	if (ret) {
		LOG_DEV_ERR("lag init failed.\n");
		goto l_lag_init_failed;
	}

	ret = sxe2_cli_cdev_create(adapter);
	if (ret) {
		LOG_DEV_ERR("cli char dev create failed, ret=%d\n", ret);
		goto l_cdev_create_failed;
	}

#ifdef HAVE_TC_INDIR_BLOCK
	ret = sxe2_tc_indir_block_register(adapter->vsi_ctxt.main_vsi);
	if (ret) {
		LOG_DEV_ERR("register netdev notifier failed, ret=%d\n", ret);
		goto l_tc_block_register_failed;
	}
#endif
	return 0;

#ifdef HAVE_TC_INDIR_BLOCK
l_tc_block_register_failed:
	sxe2_cli_cdev_delete(adapter);
#endif
l_cdev_create_failed:
	sxe2_lag_deinit(adapter);
l_lag_init_failed:
	sxe2_ipsec_deinit(adapter);
l_ipsec_init_failed:
#ifdef HAVE_MACSEC_SUPPORT
	sxe2_macsec_deinit(adapter);
l_macsec_init_failed:
#endif
	return ret;
}

STATIC void sxe2_deinit_feature_with_netdev(struct sxe2_adapter *adapter)
{
#ifdef HAVE_TC_INDIR_BLOCK
	sxe2_tc_indir_block_unregister(adapter->vsi_ctxt.main_vsi);
#endif
	sxe2_cli_cdev_delete(adapter);

	sxe2_lag_deinit(adapter);

	sxe2_ipsec_deinit(adapter);

#ifdef HAVE_MACSEC_SUPPORT
	sxe2_macsec_deinit(adapter);
#endif
}

STATIC s32 sxe2_init_feature_without_netdev(struct sxe2_adapter *adapter)
{
	s32 ret = 0;

	ret = sxe2_pf_eth_fnav_init(adapter);
	if (ret) {
		LOG_DEV_ERR("ctrl vsi init failed, ret=%d\n", ret);
		goto l_fnav_init_failed;
	}

	ret = sxe2_ptp_init(adapter);
	if (ret) {
		LOG_DEV_ERR("ptp init failed, ret=%d\n", ret);
		goto l_ptp_init_failed;
	}
	clear_bit(SXE2_FLAG_FW_DCBX_AGENT, adapter->flags);

	ret = sxe2_dcb_init(adapter, false);
	if (ret) {
		LOG_DEV_ERR("dcb init failed\n");
		goto l_dcb_init_failed;
	}
	return ret;

l_dcb_init_failed:
	sxe2_ptp_deinit(adapter);
l_ptp_init_failed:
	sxe2_pf_eth_fnav_deinit(adapter);
l_fnav_init_failed:
	return ret;
}

STATIC void sxe2_deinit_feature_without_netdev(struct sxe2_adapter *adapter)
{
	sxe2_dcb_deinit(adapter, false);

	sxe2_ptp_deinit(adapter);

	sxe2_pf_eth_fnav_deinit(adapter);
}

STATIC void sxe2_init_work_tasks(struct sxe2_adapter *adapter)
{
	sxe2_monitor_init(adapter);
	sxe2_dev_ctrl_init(adapter);
}

STATIC void sxe2_deinit_work_tasks(struct sxe2_adapter *adapter)
{
	sxe2_dev_ctrl_deinit(adapter);

	sxe2_monitor_stop(adapter);
}

STATIC void sxe2_start_work_tasks(struct sxe2_adapter *adapter)
{
	sxe2_monitor_start(adapter);

	sxe2_dev_state_set(adapter, SXE2_DEVSTATE_RUNNING, 0);

	sxe2_dev_ctrl_work_start(adapter);
}

#ifdef HAVE_UDP_TUNNEL_NIC_INFO
static struct udp_tunnel_nic_info sxe2_udp_tunnels = {
		.set_port = sxe2_udp_tunnel_set_port,
		.unset_port = sxe2_udp_tunnel_unset_port,
#ifdef HAVE_UDP_TUNNEL_NIC_INFO_MAY_SLEEP
		.flags = UDP_TUNNEL_NIC_INFO_MAY_SLEEP,
#endif
		.tables = {
				{
					.n_entries = 1,
					.tunnel_types = UDP_TUNNEL_TYPE_VXLAN,
				},
				{
					.n_entries = 1,
					.tunnel_types = UDP_TUNNEL_TYPE_GENEVE,
				},
				{
					.n_entries = 1,
					.tunnel_types = UDP_TUNNEL_TYPE_VXLAN_GPE,
				},
			},
};
#endif

static void sxe2_udp_tunnel_init(struct sxe2_adapter *adapter)
{
	struct sxe2_udp_tunnel_context *udp_tunnel_ctxt = &adapter->udp_tunnel_ctxt;

#ifdef HAVE_UDP_TUNNEL_NIC_INFO
	adapter->udp_tunnel_nic = &sxe2_udp_tunnels;
#ifdef HAVE_UDP_TUNNEL_NIC_SHARED
	adapter->udp_tunnel_nic->shared = &adapter->udp_tunnel_shared;
#endif
#endif

	memset(udp_tunnel_ctxt, 0, sizeof(struct sxe2_udp_tunnel_context));
	mutex_init(&udp_tunnel_ctxt->lock);
	bitmap_zero(udp_tunnel_ctxt->vsi_map, SXE2_MAX_VSI_NUM);
}

STATIC s32 sxe2_sw_base_init(struct sxe2_adapter *adapter)
{
	s32 ret;
	struct sxe2_vsi *pf_vsi;

	ret = sxe2_sw_init_once(adapter);
	if (ret)
		return ret;

	sxe2_init_work_tasks(adapter);

	ret = sxe2_init_eth(adapter);
	if (ret) {
		LOG_DEV_ERR("init eth device failed, ret=%d\n", ret);
		goto l_eth_init_failed;
	}

	ret = sxe2_log_export_init(adapter);
	if (ret) {
		LOG_DEV_ERR("log export init failed, ret=%d\n", ret);
		goto l_dump_init_failed;
	}

	if (sxe2_is_safe_mode(adapter))
		goto l_probe_dev_regist;

	ret = sxe2_init_feature_without_netdev(adapter);
	if (ret)
		goto l_init_feature_without_netdev_failed;

l_probe_dev_regist:
	pf_vsi = adapter->vsi_ctxt.main_vsi;
	ret = sxe2_netdev_register(pf_vsi);
	if (ret) {
		LOG_DEV_ERR("netdev register failed, ret=%d\n", ret);
		goto l_netdev_reg_failed;
	}

	ret = sxe2_init_feature_with_netdev(adapter);
	if (ret)
		goto l_init_feature_with_netdev_failed;

	ret = sxe2_init_aux(adapter);
	if (ret)
		goto l_aux_init_failed;

	if (!sxe2_is_safe_mode(adapter)) {
		ret = sxe2_com_init(&adapter->com_ctxt, adapter, &g_com_ops);
		if (ret)
			goto l_com_init_failed;
	}

	sxe2_debugfs_pf_init(adapter);

	sxe2_start_work_tasks(adapter);

	sxe2_udp_tunnel_init(adapter);

	return ret;

l_com_init_failed:
	sxe2_rdma_aux_deinit(adapter);
l_aux_init_failed:
	sxe2_deinit_feature_with_netdev(adapter);
l_init_feature_with_netdev_failed:
	unregister_netdev(pf_vsi->netdev);
l_netdev_reg_failed:
	sxe2_deinit_feature_without_netdev(adapter);
l_init_feature_without_netdev_failed:
	sxe2_log_export_deinit(adapter);
l_dump_init_failed:
	sxe2_deinit_eth(adapter);
l_eth_init_failed:
	sxe2_deinit_work_tasks(adapter);
	sxe2_sw_deinit_once(adapter);

	return ret;
}

STATIC void sxe2_sw_base_deinit(struct sxe2_adapter *adapter)
{
	if (test_bit(SXE2_PF_STOPPED, &adapter->dev_ctrl_ctxt.flag)) {
		if (sxe2_cmd_channels_enable(adapter))
			LOG_DEV_WARN("cmd channel enable failed.\n");
		sxe2_event_irq_enable(adapter);
	}

	sxe2_lldp_agent_event_deinit(adapter);

	sxe2_stop_lfc(adapter);
	sxe2_dcb_deinit(adapter, false);

	sxe2_monitor_stop(adapter);

	sxe2_dev_ctrl_deinit(adapter);

	sxe2_com_deinit(&adapter->com_ctxt);

	sxe2_vf_deinit(adapter);

	sxe2_cli_cdev_delete(adapter);

	sxe2_rdma_aux_deinit(adapter);

#ifdef HAVE_TC_INDIR_BLOCK
	sxe2_tc_indir_block_unregister(adapter->vsi_ctxt.main_vsi);
#endif
	sxe2_ptp_deinit(adapter);

	sxe2_lag_deinit(adapter);

	unregister_netdev(adapter->vsi_ctxt.main_vsi->netdev);

	sxe2_netdev_deinit(adapter->vsi_ctxt.main_vsi);

	sxe2_ctrl_vsi_deinit(adapter);

#ifdef HAVE_MACSEC_SUPPORT
	sxe2_macsec_deinit(adapter);
#endif

	sxe2_ipsec_deinit(adapter);

	sxe2_vsi_destroy_all(adapter);

	sxe2_switch_fltr_restore_clean(adapter);

	sxe2_switch_context_deinit(adapter);

	sxe2_txsched_deinit(adapter);

	sxe2_irq_deinit(adapter);

	sxe2_sw_deinit_once(adapter);

	sxe2_debugfs_pf_exit(adapter);
}

#ifdef CONFIG_PM
static int __maybe_unused sxe2_pm_suspend(struct device *dev)
{
	s32 ret = 0;
	struct pci_dev *pdev = to_pci_dev(dev);
	struct sxe2_adapter *adapter = pci_get_drvdata(pdev);

	LOG_DEBUG_BDF("suspend was called\n");

	if (test_and_set_bit(SXE2_FLAG_SUSPEND, adapter->flags))
		goto out;

	sxe2_dev_ctrl_work_stop(adapter);

	sxe2_pf_stop(adapter, SXE2_PF_STOP_NORMAL);

	sxe2_rdma_aux_delete(&adapter->aux_ctxt.cdev_info);

	sxe2_irq_deinit(adapter);

	ret = pci_save_state(pdev);
	if (ret) {
		LOG_DEV_ERR("pci_save_state failed with error code:%d\n", ret);
		goto out;
	}

	ret = pci_set_power_state(pdev, PCI_D3hot);
	if (ret)
		LOG_DEV_ERR("pci_set_power_state with error code:%d\n", ret);

out:
	LOG_DEV_DEBUG("suspend end, ret=%d\n", ret);
	return ret;
}

static int __maybe_unused sxe2_pm_resume(struct device *dev)
{
	s32 ret = 0;
	struct pci_dev *pdev = to_pci_dev(dev);
	struct sxe2_adapter *adapter = pci_get_drvdata(pdev);

	LOG_DEBUG_BDF("resume was called\n");

	if (!test_bit(SXE2_FLAG_SUSPEND, adapter->flags))
		goto out;

	ret = pci_set_power_state(pdev, PCI_D0);
	if (ret) {
		LOG_DEV_ERR("pci_set_power_state with error code:%d\n", ret);
		goto out;
	}
	pci_restore_state(pdev);
	ret = pci_save_state(pdev);
	if (ret) {
		LOG_DEV_ERR("pci_save_state with error code:%d\n", ret);
		goto out;
	}

	if (!pci_device_is_present(pdev)) {
		LOG_DEV_ERR("pci device has been lost\n");
		ret = -ENODEV;
		goto out;
	}

	ret = pci_enable_device_mem(pdev);
	if (ret) {
		LOG_DEV_ERR("cannot enable device after resume\n");
		goto out;
	}

	ret = sxe2_irq_resume(adapter);
	if (ret) {
		LOG_DEV_ERR("irq resume err, ret=%d\n", ret);
		goto out;
	}

	ret = sxe2_reset_async(adapter, SXE2_RESET_PFR);
	if (ret) {
		LOG_DEV_ERR("PFR failed during resume, ret=%d\n", ret);
		goto out;
	}
	sxe2_dev_ctrl_work_start(adapter);

	clear_bit(SXE2_FLAG_SUSPEND, adapter->flags);

out:
	LOG_DEV_DEBUG("resume end, ret=%d\n", ret);
	return ret;
}
#endif

STATIC void sxe2_msg_level_init(struct sxe2_adapter *adapter)
{
	adapter->msglvl_ctxt.msg_enable = netif_msg_init(debug, SXE2_DFLT_NETIF_M);
#ifndef CONFIG_DYNAMIC_DEBUG
	if (debug < -1)
		adapter->msglvl_ctxt.debug_mask = (u64)debug;
#endif
}

STATIC int sxe2_probe(struct pci_dev *pdev,
		      const struct pci_device_id __always_unused *ent)
{
	int ret;
	struct sxe2_adapter *adapter;

	adapter = sxe2_adapter_create(pdev);
	if (!adapter) {
		ret = -ENOMEM;
		LOG_ERROR("can't probe virtual\n");
		goto l_end;
	}

	sxe2_msg_level_init(adapter);

	sxe2_devlink_register(adapter);
	ret = sxe2_pci_init(adapter);
	if (ret) {
		LOG_DEV_ERR("pci init failed, ret=%d\n", ret);
		goto l_create;
	}

	ret = sxe2_hw_base_init(adapter);
	if (ret) {
		LOG_DEV_ERR("hardware base init failed.(ret:%d)\n", ret);
		goto l_pci_deinit;
	}

	ret = sxe2_sw_base_init(adapter);
	if (ret) {
		LOG_DEV_ERR("software base init failed.(ret:%d)\n", ret);
		goto l_sw_base_init_failed;
	}

	return ret;

l_sw_base_init_failed:
	sxe2_hw_base_deinit(adapter);
l_pci_deinit:
	sxe2_pci_deinit(adapter);
l_create:
	sxe2_devlink_unregister(adapter);
l_end:
	return ret;
}

STATIC void sxe2_remove(struct pci_dev *pdev)
{
	struct sxe2_adapter *adapter = pci_get_drvdata(pdev);

	if (!adapter) {
		LOG_WARN("adapter NULL, skip remove oper.\n");
		return;
	}

	LOG_DEBUG_BDF("sxe2 driver remove start.\n");

	sxe2_dev_ctrl_deinit(adapter);

	(void)sxe2_fnav_switch(adapter, false);

	if (adapter->vf_ctxt.num_vfs)
		(void)sxe2_vfs_disable(adapter, true);

	(void)sxe2_pf_stop(adapter, SXE2_PF_STOP_RESET_NOTICE_RDMA);
	sxe2_sw_base_deinit(adapter);
	sxe2_hw_base_deinit(adapter);

	LOG_DEBUG_BDF("sxe2 driver remove end.\n");

	(void)pci_wait_for_pending_transaction(pdev);
#ifdef HAVE_PCI_ENABLE_PCIE_ERROR_REPORTING
	pci_disable_pcie_error_reporting(adapter->pdev);
#endif

	sxe2_pci_deinit(adapter);

	sxe2_devlink_unregister(adapter);
}

STATIC void sxe2_shutdown(struct pci_dev *pdev)
{
	sxe2_remove(pdev);
}

STATIC void __sxe2_pci_err_reset_prepare(struct sxe2_adapter *adapter)
{
	if (!test_bit(SXE2_FLAG_SUSPEND, adapter->flags)) {
		sxe2_dev_ctrl_work_stop(adapter);
		sxe2_pf_stop(adapter, SXE2_PF_STOP_RESET_NOTICE_RDMA);
	}
}

STATIC void sxe2_pci_err_reset_prepare(struct pci_dev *pdev)
{
	struct sxe2_adapter *adapter = pci_get_drvdata(pdev);

	LOG_DEBUG_BDF("pflr trigger.\n");

	__sxe2_pci_err_reset_prepare(adapter);
}

STATIC void sxe2_restore_all_vfs_msi_state(struct pci_dev *pdev)
{
	u16 vf_id;
	int pos;

	if (!pci_num_vf(pdev))
		return;

	pos = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_SRIOV);
	if (pos) {
		struct pci_dev *vfdev;

		(void)pci_read_config_word(pdev, pos + PCI_SRIOV_VF_DID, &vf_id);
		vfdev = pci_get_device(pdev->vendor, vf_id, NULL);
		while (vfdev) {
			if (vfdev->is_virtfn && vfdev->physfn == pdev)
				pci_restore_msi_state(vfdev);
			vfdev = pci_get_device(pdev->vendor, vf_id, vfdev);
		}
	}
}

STATIC pci_ers_result_t sxe2_pci_err_detected(struct pci_dev *pdev,
					      pci_channel_state_t error)
{
	struct sxe2_adapter *adapter = pci_get_drvdata(pdev);
	pci_ers_result_t ret;

	LOG_DEV_WARN("pci err:%u detected.\n", error);

	if (!adapter) {
		LOG_DEV_ERR("%s failed, device is unrecoverable pci err:0x%x\n",
			    __func__, error);
		ret = PCI_ERS_RESULT_DISCONNECT;
		goto l_out;
	}

	__sxe2_pci_err_reset_prepare(adapter);

	pci_disable_device(pdev);
	ret = error == pci_channel_io_perm_failure ? PCI_ERS_RESULT_DISCONNECT
						   : PCI_ERS_RESULT_NEED_RESET;

l_out:
	LOG_DEV_WARN("pci err:%u detected done ret:%d.\n", error, ret);

	return ret;
}

STATIC pci_ers_result_t sxe2_pci_err_slot_reset(struct pci_dev *pdev)
{
	struct sxe2_adapter *adapter = pci_get_drvdata(pdev);
	pci_ers_result_t result;
	s32 ret;

	LOG_DEV_WARN("pci err slot reset\n");

	ret = pci_enable_device_mem(pdev);
	if (ret) {
		LOG_DEV_ERR("Cannot re-enable PCI device after reset, error %d\n",
			    ret);
		result = PCI_ERS_RESULT_DISCONNECT;
	} else {
		pci_set_master(pdev);
		pci_restore_state(pdev);
		(void)pci_save_state(pdev);
		(void)pci_wake_from_d3(pdev, false);

		ret = sxe2_wait_reset_done(adapter, SXE2_RESET_PFR);
		if (!ret)
			result = PCI_ERS_RESULT_RECOVERED;
		else
			result = PCI_ERS_RESULT_DISCONNECT;
	}

	ret = pci_aer_clear_nonfatal_status(pdev);
	if (ret)
		LOG_DEV_ERR("pci_aer_clear_nonfatal_status failed, error %d\n", ret);

	LOG_DEV_WARN("pci err slot reset done %d.\n", ret);

	return result;
}

STATIC void sxe2_pci_err_resume(struct pci_dev *pdev)
{
	struct sxe2_adapter *adapter = pci_get_drvdata(pdev);

	LOG_DEV_WARN("pci err resume\n");

	if (!adapter) {
		LOG_DEV_ERR("%s failed, device is unrecoverable\n", __func__);
		return;
	}

	if (test_bit(SXE2_FLAG_SUSPEND, adapter->flags)) {
		LOG_DEV_ERR("%s failed to resume normal operations!\n", __func__);
		return;
	}

	sxe2_restore_all_vfs_msi_state(pdev);

	if (sxe2_reset_sync(adapter, SXE2_RESET_PFR))
		LOG_ERROR_BDF("PFR failed.\n");

	sxe2_rdma_aux_delete(&adapter->aux_ctxt.cdev_info);

	if (sxe2_pf_rebuild(adapter))
		LOG_DEV_ERR("rebuild pf failed.\n");

	sxe2_dev_ctrl_work_start(adapter);
	LOG_DEV_WARN("pci err resume done\n");
}

#ifdef HAVE_PCI_ERROR_HANDLER_RESET_PREPARE
STATIC void sxe2_pci_err_reset_done(struct pci_dev *pdev)
{
	struct sxe2_adapter *adapter = pci_get_drvdata(pdev);
	s32 ret;

	if (!adapter) {
		LOG_DEV_ERR("%s failed, device is unrecoverable\n", __func__);
		return;
	}

	if (test_bit(SXE2_FLAG_SUSPEND, adapter->flags)) {
		LOG_DEV_ERR("%s failed to resume normal operations!\n", __func__);
		return;
	}

	sxe2_restore_all_vfs_msi_state(pdev);

	ret = sxe2_wait_reset_done(adapter, SXE2_RESET_PFR);
	if (ret)
		LOG_DEV_ERR("wait pflr done failed: %d.\n", ret);

	sxe2_rdma_aux_delete(&adapter->aux_ctxt.cdev_info);

	ret = sxe2_pf_rebuild(adapter);
	if (ret) {
		LOG_DEV_ERR("rebuild pf failed: %d.\n", ret);
		goto work_start;
	}

	ret = sxe2_reset_all_vfs(adapter);
	if (ret)
		LOG_DEV_ERR("reset all vfs failed %d.\n", ret);

work_start:
	sxe2_dev_ctrl_work_start(adapter);
}
#endif

static int __maybe_unused sxe2_pm_resume(struct device *dev);
static int __maybe_unused sxe2_pm_suspend(struct device *dev);

static __maybe_unused SIMPLE_DEV_PM_OPS(sxe2_pm_ops, sxe2_pm_suspend,
					sxe2_pm_resume);

STATIC const struct pci_error_handlers sxe2_pci_err_handler = {
#ifdef HAVE_PCI_ERROR_HANDLER_RESET_PREPARE
		.reset_prepare = sxe2_pci_err_reset_prepare,
		.reset_done = sxe2_pci_err_reset_done,
#endif
		.error_detected = sxe2_pci_err_detected,
		.slot_reset = sxe2_pci_err_slot_reset,
		.resume = sxe2_pci_err_resume,
};

STATIC struct pci_driver sxe2_pci_driver = {
		.name = SXE2_DRV_NAME,
		.id_table = sxe2_pci_tbl,
		.probe = sxe2_probe,
		.remove = sxe2_remove,
#ifdef CONFIG_PM
		.driver.pm = &sxe2_pm_ops,
#endif
		.shutdown = sxe2_shutdown,
		.sriov_configure = sxe2_sriov_configure,
		.err_handler = &sxe2_pci_err_handler,
};

STATIC int __init sxe2_init(void)
{
	int ret;

	LOG_PR_INFO("%s init start, version[%s], commit_id[%s], branch[%s], build_time[%s]\n",
		    SXE2_DRV_DESCRIPTION, SXE2_VERSION, SXE2_COMMIT_ID, SXE2_BRANCH,
		    SXE2_BUILD_TIME);

#ifndef SXE2_CFG_RELEASE
	ret = sxe2_log_init(false);
	if (ret < 0) {
		LOG_PR_ERR("sxe2 log init fail.(err:%d)\n", ret);
		goto l_end;
	}
#endif

	ret = sxe2_monitor_create();
	if (ret)
		goto l_log_init_rollback;

	ret = sxe2_cmd_work_create();
	if (ret)
		goto l_workqueue_rollback;

	ret = sxe2_dev_ctrl_work_create();
	if (ret)
		goto l_cmd_workqueue_rollback;

	ret = sxe2_cli_cdev_register();
	if (ret) {
		LOG_ERROR("register cli char dev failed\n");
		goto l_dev_ctrl_workqueue_rollback;
	}

	ret = sxe2_com_adapter_register(SXE2_PF);
	if (ret) {
		LOG_ERROR("register dpdk char dev failed\n");
		goto l_cdev_create_rollback;
	}

	sxe2_lag_init_once();

	sxe2_ptp_owner_init_once();

	sxe2_debugfs_init();

	ret = pci_register_driver(&sxe2_pci_driver);
	if (ret) {
		LOG_PR_ERR("register pci driver failed\n");
		goto l_com_register_rollback;
	}

	return 0;

l_com_register_rollback:
	sxe2_debugfs_exit();
	sxe2_ptp_owner_deinit_once();
	sxe2_lag_deinit_once();
	sxe2_com_adapter_unregister();
l_cdev_create_rollback:
	sxe2_cli_cdev_unregister();
l_dev_ctrl_workqueue_rollback:
	sxe2_dev_ctrl_work_destroy();
l_cmd_workqueue_rollback:
	sxe2_cmd_work_destroy();
l_workqueue_rollback:
	sxe2_monitor_destroy();
l_log_init_rollback:
#ifndef SXE2_CFG_RELEASE
	sxe2_log_exit();
l_end:
#endif

	return ret;
}

STATIC void __exit sxe2_exit(void)
{
	pci_unregister_driver(&sxe2_pci_driver);

	sxe2_debugfs_exit();

	sxe2_lag_deinit_once();

	sxe2_com_adapter_unregister();

	sxe2_cli_cdev_unregister();

	sxe2_cmd_work_destroy();

	sxe2_monitor_destroy();

	sxe2_dev_ctrl_work_destroy();

	sxe2_ptp_owner_deinit_once();

#ifndef SXE2_CFG_RELEASE
	sxe2_log_exit();
#endif
}

MODULE_DEVICE_TABLE(pci, sxe2_pci_tbl);
MODULE_INFO(build_time, SXE2_BUILD_TIME);
MODULE_INFO(branch, SXE2_BRANCH);
MODULE_INFO(commit_id, SXE2_COMMIT_ID);
MODULE_DESCRIPTION(SXE2_DRV_DESCRIPTION);
MODULE_AUTHOR(SXE2_DRV_AUTHOR);
MODULE_VERSION(SXE2_VERSION);
MODULE_LICENSE(SXE2_DRV_LICENSE);
MODULE_ALIAS(SXE2_DRV_NAME);

module_init(sxe2_init);
module_exit(sxe2_exit);
