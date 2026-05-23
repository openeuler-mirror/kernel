/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_macsec_main.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   : macsec main
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": [MACsec]" fmt

#include <net/rtnetlink.h>
#include <linux/module.h>
#include <linux/netdev_features.h>
#include <linux/netlink.h>
#include <linux/netdevice.h>
#include <linux/rculist.h>

#include "ossl_knl.h"
#include "hinic5_hw.h"
#include "hinic5_srv_nic.h"

#include "hinic5_macsec_dfx.h"
#include "hinic5_macsec_common.h"
#include "hinic5_macsec_dev.h"

// TODO: This parameter is for 4SA mode adaptation, to be removed after config file is ready
static u8 macsec_sc_mode = HIMACSEC_SC_MODE_FOUR_SA;
module_param(macsec_sc_mode, byte, 0444);
MODULE_PARM_DESC(macsec_sc_mode, "MACsec SC mode, 0: 2SA, 1: 4SA (default=1)");

struct macsec_port_res g_macsec_port_res[MACSEC_PORT_NUM] = {0};

#define HIMACSEC_DRV_DESC      "Huawei(R) Intelligent Network Interface Card, MACsec driver"
#define HIMACSEC_AUTHOR        "Huawei Technologies CO., Ltd"

struct himacsec_sc *get_g_macsec_port_res(u32 mode, u32 port_id)
{
	if (port_id >= MACSEC_PORT_NUM) {
		pr_err("MACsec param port_id(0x%x) invalid", port_id);
		return NULL;
	}
	if (mode == MACSEC_OUTBOUND)
		return &g_macsec_port_res[port_id].enc_sc;
	else
		return &g_macsec_port_res[port_id].dec_sc;
}

int himacsec_init_dev_spec(struct macsec_resource *macsec_res,
			   struct hinic5_lld_dev *lld_dev, struct himacsec_spec *spec)
{
	macsec_res->spec.macsec_support = spec->macsec_support;
	macsec_res->spec.max_port = spec->max_port;

	if (macsec_sc_mode >= HIMACSEC_SC_MODE_MAX) {
		macsec_err(lld_dev->dev, "MACsec param macsec_sc_mode(0x%x) invalid",
			   macsec_sc_mode);
		return -EINVAL;
	}

	macsec_res->spec.max_sa = (macsec_sc_mode + 1) << 0x1; // macsec_sc_mode=0: 2SA mode
							       // macsec_sc_mode=1: 4SA mode
	macsec_res->spec.max_port_sc = spec->max_port_sc; // Port SC count: 2SA mode - 8 SCs
							  // 4SA mode - 4 SCs

	return 0;
}

int himacsec_init_resource(struct hinic5_nic_dev *nic_dev, struct hinic5_lld_dev *lld_dev,
			   struct himacsec_spec *spec, u64 feature_bitmap)
{
	struct macsec_resource *macsec_res = NULL;
	int ret;
	u16 func_id = hinic5_global_func_id(lld_dev->hwdev);
	u8 port = hinic5_physical_port_id(lld_dev->hwdev);

	macsec_res = kzalloc(sizeof(struct macsec_resource), GFP_KERNEL);
	if (!macsec_res)
		return -ENOMEM;

	/* 1. Initialize spec */
	ret = himacsec_init_dev_spec(macsec_res, lld_dev, spec);
	if (ret != 0) {
		kfree(macsec_res);
		return ret;
	}

	/* 3. Private data callback */
	macsec_res->function_port = port;
	macsec_res->offload_dev_num = 0;
	macsec_res->himacsec_feature[0] = feature_bitmap;
	nic_dev->macsec_res = macsec_res; // Callback to nic_dev

	macsec_info(lld_dev->dev, "Func 0x%x macsec capability: sc_mode(0:2sa, 1:4sa): %u, func_port: %u, feature: 0x%llx",
		    func_id, macsec_sc_mode, port, feature_bitmap);

	return ret;
}

void himacsec_release_resource(struct hinic5_nic_dev *nic_dev)
{
	struct macsec_resource *macsec_res = NULL;

	if (!nic_dev)
		return;

	macsec_res = nic_dev->macsec_res;
	if (!macsec_res)
		return;

	// 2. Clean up MACsec resources
	kfree(macsec_res);
	nic_dev->macsec_res = NULL;
}

int macsec_init_offload(struct hinic5_nic_dev *nic_dev)
{
	u64 feature_bitmap = 0;
	int ret;
	struct himacsec_spec spec = {0};
	struct hinic5_lld_dev *lld_dev = NULL;
	u8 macsec_flag = MACSEC_GLOBAL_SWITCH_IS_DISABLE;

	if (!nic_dev || !nic_dev->lld_dev || !nic_dev->netdev) {
		pr_err("lld device is NULL, MACsec init failed");
		return -ENODEV;
	}

	lld_dev = nic_dev->lld_dev;

	/* 1. Confirm MACsec enable status */
	if (!hinic5_support_macsec(lld_dev->hwdev)) {
		macsec_info(lld_dev->dev, "HW don't support macsec");
		return 0;
	}

	/* 2. Feature negotiation */
	if (himacsec_cmd_exec_get_feature_nego(lld_dev, &feature_bitmap, 1) != 0) {
		macsec_err(lld_dev->dev, "Feature negotiation failed");
		return -EBUSY;
	}

	/* 3. Global configuration fetch */
	if (himacsec_cmd_exec_get_spec(lld_dev->hwdev, &spec) != 0) {
		macsec_err(lld_dev->dev, "Get chip spec failed");
		return -EBUSY;
	}

	/* 4. Initialize MACsec private data in nic_dev */
	ret = himacsec_init_resource(nic_dev, lld_dev, &spec, feature_bitmap);
	if (ret != 0) {
		macsec_err(lld_dev->dev, "Init MACsec private data failed, ret:%d", ret);
		return ret;
	}

	/* 5. Initialize MACsec function offload in kernel protocol stack */
	himacsec_offload_init(nic_dev);

	/* 6. Enable MACsec, initialization operation required (only once) */
	ret = himacsec_cmd_exec_macsec_enable(lld_dev, MACSEC_CMD_SERVICE_OP_MACSEC_ENABLE,
					      &macsec_flag);
	if (ret != 0) {
		macsec_err(lld_dev->dev, "Enable macsec failed, ret:%d", ret);
		goto enable_macsec_fail;
	}

	macsec_info(lld_dev->dev, "Macsec resource init successfully");
	return ret;

enable_macsec_fail:
	himacsec_offload_deinit(nic_dev);
	himacsec_release_resource(nic_dev);
	if (macsec_flag == MACSEC_GLOBAL_SWITCH_IS_DISABLE)
		return 0;
	return ret;
}

void macsec_cleanup_offload(struct hinic5_nic_dev *nic_dev)
{
	struct macsec_resource *macsec_res = NULL;
	struct hinic5_lld_dev *lld_dev = NULL;
	int ret;

	if (!nic_dev || !nic_dev->lld_dev || !nic_dev->netdev) {
		pr_err("lld device is NULL, MACsec resource release failed");
		return;
	}

	lld_dev = nic_dev->lld_dev;
	macsec_res = nic_dev->macsec_res;

	if (!macsec_res || macsec_res->spec.macsec_support == 0)
		return;

	ret = himacsec_cmd_exec_macsec_enable(lld_dev, MACSEC_CMD_SERVICE_OP_MACSEC_DISABLE, NULL);
	if (ret != 0)
		macsec_err(lld_dev->dev, "Disable macsec failed, ret:%d", ret);

	himacsec_offload_deinit(nic_dev);

	himacsec_release_resource(nic_dev);
	macsec_info(lld_dev->dev, "Macsec resource release successfully");
}
