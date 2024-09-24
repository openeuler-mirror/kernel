/* SPDX-License-Identifier: GPL-2.0*/
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#ifndef _NBL_CORE_H_
#define _NBL_CORE_H_

#include "nbl_product_base.h"
#include "nbl_def_common.h"
#include "nbl_def_phy.h"
#include "nbl_def_resource.h"
#include "nbl_def_dispatch.h"
#include "nbl_def_service.h"
#include "nbl_def_dev.h"
#include "nbl_def_channel.h"

#define NBL_ADAPTER_TO_PDEV(adapter)		((adapter)->pdev)
#define NBL_ADAPTER_TO_DEV(adapter)		(&((adapter)->pdev->dev))
#define NBL_ADAPTER_TO_COMMON(adapter)		(&((adapter)->common))
#define NBL_ADAPTER_TO_RPDUCT_BASE_OPS(adapter)	((adapter)->product_base_ops)

#define NBL_ADAPTER_TO_PHY_MGT(adapter)		((adapter)->core.phy_mgt)
#define NBL_ADAPTER_TO_RES_MGT(adapter)		((adapter)->core.res_mgt)
#define NBL_ADAPTER_TO_DISP_MGT(adapter)	((adapter)->core.disp_mgt)
#define NBL_ADAPTER_TO_SERV_MGT(adapter)	((adapter)->core.serv_mgt)
#define NBL_ADAPTER_TO_DEV_MGT(adapter)		((adapter)->core.dev_mgt)
#define NBL_ADAPTER_TO_CHAN_MGT(adapter)	((adapter)->core.chan_mgt)
#define NBL_ADAPTER_TO_DEBUGFS_MGT(adapter)	((adapter)->core.debugfs_mgt)

#define NBL_ADAPTER_TO_PHY_OPS_TBL(adapter)	((adapter)->intf.phy_ops_tbl)
#define NBL_ADAPTER_TO_RES_OPS_TBL(adapter)	((adapter)->intf.resource_ops_tbl)
#define NBL_ADAPTER_TO_DISP_OPS_TBL(adapter)	((adapter)->intf.dispatch_ops_tbl)
#define NBL_ADAPTER_TO_SERV_OPS_TBL(adapter)	((adapter)->intf.service_ops_tbl)
#define NBL_ADAPTER_TO_DEV_OPS_TBL(adapter)	((adapter)->intf.dev_ops_tbl)
#define NBL_ADAPTER_TO_CHAN_OPS_TBL(adapter)	((adapter)->intf.channel_ops_tbl)

#define NBL_ADAPTER_TO_RES_PT_OPS(adapter)	(&(NBL_ADAPTER_TO_SERV_OPS_TBL(adapter)->pt_ops))

#define NBL_NETDEV_PRIV_TO_ADAPTER(priv)	((priv)->adapter)

#define NBL_NETDEV_TO_ADAPTER(netdev) \
	(NBL_NETDEV_PRIV_TO_ADAPTER((struct nbl_netdev_priv *)netdev_priv(netdev)))

#define NBL_NETDEV_TO_SERV_MGT(netdev) \
	(NBL_ADAPTER_TO_SERV_MGT(NBL_NETDEV_PRIV_TO_ADAPTER(\
		(struct nbl_netdev_priv *)netdev_priv(netdev))))

#define NBL_NETDEV_TO_DEV_MGT(netdev) \
	(NBL_ADAPTER_TO_DEV_MGT(NBL_NETDEV_TO_ADAPTER(netdev)))

#define NBL_NETDEV_TO_COMMON(netdev) \
	(NBL_ADAPTER_TO_COMMON(NBL_NETDEV_PRIV_TO_ADAPTER(\
		(struct nbl_netdev_priv *)netdev_priv(netdev))))

#define NBL_CAP_SET_BIT(loc)			(1 << (loc))
#define NBL_CAP_TEST_BIT(val, loc)		(((val) >> (loc)) & 0x1)

#define NBL_CAP_IS_CTRL(val)			NBL_CAP_TEST_BIT(val, NBL_CAP_HAS_CTRL_BIT)
#define NBL_CAP_IS_NET(val)			NBL_CAP_TEST_BIT(val, NBL_CAP_HAS_NET_BIT)
#define NBL_CAP_IS_VF(val)			NBL_CAP_TEST_BIT(val, NBL_CAP_IS_VF_BIT)
#define NBL_CAP_SUPPORT_LAG(val)		NBL_CAP_TEST_BIT(val, NBL_CAP_SUPPORT_LAG_BIT)
#define NBL_CAP_IS_NIC(val)			NBL_CAP_TEST_BIT(val, NBL_CAP_IS_NIC_BIT)
#define NBL_CAP_IS_USER(val)			NBL_CAP_TEST_BIT(val, NBL_CAP_HAS_USER_BIT)
#define NBL_CAP_IS_GRC(val)			NBL_CAP_TEST_BIT(val, NBL_CAP_HAS_GRC_BIT)
#define NBL_CAP_IS_BLK(val)			NBL_CAP_TEST_BIT(val, NBL_CAP_IS_BLK_BIT)
#define NBL_CAP_IS_DPU_HOST(val)		({ typeof(val) _val = (val);			\
						!NBL_CAP_TEST_BIT(_val, NBL_CAP_IS_NIC_BIT) &&	\
						NBL_CAP_TEST_BIT(_val, NBL_CAP_DPU_IS_HOST_BIT); })
#define NBL_CAP_IS_DPU_ECPU(val)		({ typeof(val) _val = (val);			\
						!NBL_CAP_TEST_BIT(_val, NBL_CAP_IS_NIC_BIT) &&	\
						!NBL_CAP_TEST_BIT(_val, NBL_CAP_DPU_IS_HOST_BIT); })
#define NBL_CAP_IS_LEONIS(val)			NBL_CAP_TEST_BIT(val, NBL_CAP_IS_LEONIS_BIT)
#define NBL_CAP_IS_BOOTIS(val)			NBL_CAP_TEST_BIT(val, NBL_CAP_IS_BOOTIS_BIT)
#define NBL_CAP_IS_VIRTIO(val)			NBL_CAP_TEST_BIT(val, NBL_CAP_IS_VIRTIO_BIT)
#define NBL_CAP_IS_FACTORY_CTRL(val)		NBL_CAP_TEST_BIT(val, NBL_CAP_HAS_FACTORY_CTRL_BIT)

enum {
	NBL_CAP_HAS_CTRL_BIT = 0,
	NBL_CAP_HAS_NET_BIT,
	NBL_CAP_IS_VF_BIT,
	NBL_CAP_SUPPORT_LAG_BIT,
	NBL_CAP_IS_NIC_BIT,
	NBL_CAP_DPU_IS_HOST_BIT,
	NBL_CAP_IS_LEONIS_BIT,
	NBL_CAP_IS_BOOTIS_BIT,
	NBL_CAP_IS_VIRTIO_BIT,
	NBL_CAP_IS_BLK_BIT,
	NBL_CAP_HAS_USER_BIT,
	NBL_CAP_HAS_GRC_BIT,
	NBL_CAP_HAS_FACTORY_CTRL_BIT,
};

enum nbl_adapter_state {
	NBL_DOWN,
	NBL_RESETTING,
	NBL_RESET_REQUESTED,
	NBL_INITING,
	NBL_INIT_FAILED,
	NBL_RUNNING,
	NBL_TESTING,
	NBL_USER,
	NBL_STATE_NBITS
};

enum {
	NBL_ESWITCH_NONE,
	NBL_ESWITCH_LEGACY,
	NBL_ESWITCH_OFFLOADS
};

struct nbl_interface {
	struct nbl_phy_ops_tbl *phy_ops_tbl;
	struct nbl_resource_ops_tbl *resource_ops_tbl;
	struct nbl_dispatch_ops_tbl *dispatch_ops_tbl;
	struct nbl_service_ops_tbl *service_ops_tbl;
	struct nbl_dev_ops_tbl *dev_ops_tbl;
	struct nbl_utils_ops_tbl *utils_ops_tbl;
	struct nbl_channel_ops_tbl *channel_ops_tbl;
};

struct nbl_core {
	void *phy_mgt;
	void *res_mgt;
	void *disp_mgt;
	void *serv_mgt;
	void *dev_mgt;
	void *chan_mgt;
	void *debugfs_mgt;
};

struct nbl_adapter {
	struct pci_dev *pdev;
	struct nbl_core core;
	struct nbl_interface intf;
	struct nbl_common_info common;
	struct nbl_product_base_ops *product_base_ops;
	struct nbl_init_param init_param;
	DECLARE_BITMAP(state, NBL_STATE_NBITS);
};

struct nbl_netdev_priv {
	struct nbl_adapter *adapter;
	struct net_device *netdev;
	u16 tx_queue_num;
	u16 rx_queue_num;
	u16 queue_size;
	/* default traffic destination in kernel/dpdk/coexist scene */
	u16 default_vsi_index;
	u16 default_vsi_id;
	s64 last_st_time;
};

struct nbl_indr_dev_priv {
	struct net_device *indr_dev;
	struct nbl_netdev_priv *dev_priv;
	struct list_head list;
	int binder_type;
};

struct nbl_devlink_priv {
	void *priv;
	void *dev_mgt;
};

struct nbl_software_tool_id_entry {
	struct list_head node;
	u16 bus;
	u16 id;
	u8 refcount;
};

#define NBL_ST_MAX_DEVICE_NUM			64
struct nbl_software_tool_table {
	DECLARE_BITMAP(devid, NBL_ST_MAX_DEVICE_NUM);
	int major;
	dev_t devno;
	struct class *cls;
};

struct nbl_adapter *nbl_core_init(struct pci_dev *pdev, struct nbl_init_param *param);
void nbl_core_remove(struct nbl_adapter *adapter);
int nbl_core_start(struct nbl_adapter *adapter, struct nbl_init_param *param);
void nbl_core_stop(struct nbl_adapter *adapter);

int nbl_st_init(struct nbl_software_tool_table *st_table);
void nbl_st_remove(struct nbl_software_tool_table *st_table);
struct nbl_software_tool_table *nbl_get_st_table(void);
struct dentry *nbl_get_debugfs_root(void);

#endif
