/* SPDX-License-Identifier: GPL-2.0*/
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#ifndef _NBL_DEV_H_
#define _NBL_DEV_H_

#include "nbl_core.h"
#include "nbl_dev_user.h"

#define NBL_DEV_MGT_TO_COMMON(dev_mgt)		((dev_mgt)->common)
#define NBL_DEV_MGT_TO_DEV(dev_mgt)		NBL_COMMON_TO_DEV(NBL_DEV_MGT_TO_COMMON(dev_mgt))
#define NBL_DEV_MGT_TO_COMMON_DEV(dev_mgt)	((dev_mgt)->common_dev)
#define NBL_DEV_MGT_TO_CTRL_DEV(dev_mgt)	((dev_mgt)->ctrl_dev)
#define NBL_DEV_MGT_TO_NET_DEV(dev_mgt)		((dev_mgt)->net_dev)
#define NBL_DEV_MGT_TO_USER_DEV(dev_mgt)	((dev_mgt)->user_dev)
#define NBL_DEV_COMMON_TO_MSIX_INFO(dev_common)	(&(dev_common)->msix_info)
#define NBL_DEV_CTRL_TO_TASK_INFO(dev_ctrl)	(&(dev_ctrl)->task_info)
#define NBL_DEV_MGT_TO_NETDEV_OPS(dev_mgt)	((dev_mgt)->net_dev->ops)

#define NBL_DEV_MGT_TO_SERV_OPS_TBL(dev_mgt)	((dev_mgt)->serv_ops_tbl)
#define NBL_DEV_MGT_TO_SERV_OPS(dev_mgt)	(NBL_DEV_MGT_TO_SERV_OPS_TBL(dev_mgt)->ops)
#define NBL_DEV_MGT_TO_SERV_PRIV(dev_mgt)	(NBL_DEV_MGT_TO_SERV_OPS_TBL(dev_mgt)->priv)
#define NBL_DEV_MGT_TO_RES_PT_OPS(adapter)	(&(NBL_DEV_MGT_TO_SERV_OPS_TBL(dev_mgt)->pt_ops))
#define NBL_DEV_MGT_TO_CHAN_OPS_TBL(dev_mgt)	((dev_mgt)->chan_ops_tbl)
#define NBL_DEV_MGT_TO_CHAN_OPS(dev_mgt)	(NBL_DEV_MGT_TO_CHAN_OPS_TBL(dev_mgt)->ops)
#define NBL_DEV_MGT_TO_CHAN_PRIV(dev_mgt)	(NBL_DEV_MGT_TO_CHAN_OPS_TBL(dev_mgt)->priv)

#define DEFAULT_MSG_ENABLE (NETIF_MSG_DRV | NETIF_MSG_PROBE | NETIF_MSG_LINK | \
			    NETIF_MSG_IFDOWN | NETIF_MSG_IFUP)

#define NBL_STRING_NAME_LEN			(32)
#define NBL_DEFAULT_MTU				(1500)

#define NBL_MAX_CARDS				16

#define NBL_KEEPALIVE_TIME_CYCLE		(10 * HZ)

enum nbl_dev_mode_switch_op {
	NBL_DEV_KERNEL_TO_USER,
	NBL_DEV_USER_TO_KERNEL,
};

struct nbl_task_info {
	struct nbl_adapter *adapter;
	struct nbl_dev_mgt *dev_mgt;
	struct work_struct fw_hb_task;
	struct delayed_work fw_reset_task;
	struct work_struct clean_adminq_task;
	struct work_struct adapt_desc_gother_task;
	struct work_struct clean_abnormal_irq_task;
	struct work_struct recovery_abnormal_task;

	struct timer_list serv_timer;
	unsigned long serv_timer_period;

	bool fw_resetting;
	bool timer_setup;
};

enum nbl_msix_serv_type {
	/* virtio_dev has a config vector_id, and the vector_id need is 0 */
	NBL_MSIX_VIRTIO_TYPE = 0,
	NBL_MSIX_NET_TYPE,
	NBL_MSIX_MAILBOX_TYPE,
	NBL_MSIX_ABNORMAL_TYPE,
	NBL_MSIX_ADMINDQ_TYPE,
	NBL_MSIX_RDMA_TYPE,
	NBL_MSIX_TYPE_MAX

};

struct nbl_msix_serv_info {
	u16 num;
	u16 base_vector_id;
	/* true: hw report msix, hw need to mask actively */
	bool hw_self_mask_en;
};

struct nbl_msix_info {
	struct nbl_msix_serv_info serv_info[NBL_MSIX_TYPE_MAX];
	struct msix_entry *msix_entries;
};

struct nbl_dev_common {
	struct nbl_dev_mgt *dev_mgt;
	struct device *hwmon_dev;
	struct nbl_msix_info msix_info;
	char mailbox_name[NBL_STRING_NAME_LEN];
	// for ctrl-dev/net-dev mailbox recv msg
	struct work_struct clean_mbx_task;

	struct devlink_ops *devlink_ops;
	struct devlink *devlink;
};

struct nbl_dev_ctrl {
	struct nbl_task_info task_info;
};

struct nbl_dev_vsi_controller {
	u16 queue_num;
	u16 queue_free_offset;
	void *vsi_list[NBL_VSI_MAX];
};

struct nbl_dev_net_ops {
	int (*setup_netdev_ops)(void *priv, struct net_device *netdev,
				struct nbl_init_param *param);
	int (*setup_ethtool_ops)(void *priv, struct net_device *netdev,
				 struct nbl_init_param *param);
};

struct nbl_dev_net {
	struct net_device *netdev;
	struct nbl_dev_net_ops *ops;
	struct nbl_dev_vsi_controller vsi_ctrl;
	u16 total_queue_num;
	u16 kernel_queue_num;
	u16 user_queue_num;
	u8 eth_id;
	u8 resv;
};

struct nbl_dev_user_iommu_group {
	struct mutex dma_tree_lock; /* lock dma tree */
	struct list_head group_next;
	struct kref     kref;
	struct rb_root dma_tree;
	struct iommu_group *iommu_group;
	struct device *dev;
	struct vfio_device *vdev;
};

struct nbl_dev_user {
	struct vfio_device vdev;
	struct device *mdev;
	struct notifier_block iommu_notifier;
	struct device *dev;
	struct nbl_adapter *adapter;
	struct nbl_dev_user_iommu_group *group;
	void *shm_msg_ring;
	int minor;
	bool iommu_status;
	bool remap_status;
	int network_type;
	atomic_t open_cnt;
};

struct nbl_dev_mgt {
	struct nbl_common_info *common;
	struct nbl_service_ops_tbl *serv_ops_tbl;
	struct nbl_channel_ops_tbl *chan_ops_tbl;
	struct nbl_dev_common *common_dev;
	struct nbl_dev_ctrl *ctrl_dev;
	struct nbl_dev_net *net_dev;
	struct nbl_dev_user *user_dev;
};

struct nbl_dev_vsi_feature {
	u16 has_lldp:1;
	u16 has_lacp:1;
	u16 rsv:14;
};

struct nbl_dev_vsi_ops {
	int (*register_vsi)(struct nbl_dev_mgt *dev_mgt, struct nbl_init_param *param,
			    void *vsi_data);
	int (*setup)(struct nbl_dev_mgt *dev_mgt, struct nbl_init_param *param,
		     void *vsi_data);
	void (*remove)(struct nbl_dev_mgt *dev_mgt, void *vsi_data);
	int (*start)(struct nbl_dev_mgt *dev_mgt, struct net_device *netdev, void *vsi_data);
	void (*stop)(struct nbl_dev_mgt *dev_mgt, void *vsi_data);
	int (*netdev_build)(struct nbl_dev_mgt *dev_mgt, struct nbl_init_param *param,
			    struct net_device *netdev, void *vsi_data);
	void (*netdev_destroy)(struct nbl_dev_mgt *dev_mgt, void *vsi_data);
};

struct nbl_dev_vsi {
	struct nbl_dev_vsi_ops *ops;
	struct net_device *netdev;
	struct net_device *napi_netdev;
	struct nbl_register_net_result register_result;
	struct nbl_dev_vsi_feature feature;
	u16 vsi_id;
	u16 queue_offset;
	u16 queue_num;
	u16 queue_size;
	u16 in_kernel;
	u8 index;
	bool enable;
};

struct nbl_dev_vsi_tbl {
	struct nbl_dev_vsi_ops vsi_ops;
	bool vf_support;
	bool only_nic_support;
	u16 in_kernel;
};

#define NBL_DEV_BOARD_ID_MAX			NBL_DRIVER_DEV_MAX
struct nbl_dev_board_id_entry {
	u16 bus;
	u8 refcount;
	bool valid;
};

struct nbl_dev_board_id_table {
	struct nbl_dev_board_id_entry entry[NBL_DEV_BOARD_ID_MAX];
};

int nbl_dev_setup_hwmon(struct nbl_adapter *adapter);
void nbl_dev_remove_hwmon(struct nbl_adapter *adapter);

#endif
