/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#ifndef _NBL_CORE_COMMON_H_
#define _NBL_CORE_COMMON_H_

#include <linux/types.h>
#include <linux/notifier.h>

#define NBL_DRIVER_VERSION				"26.03-2.192.99"

enum nbl_core_reset_event {
	NBL_CORE_FATAL_ERR_EVENT,  /* Most hw module is not work nomal exclude pcie/emp */
	NBL_CORE_RESET_MAX_EVENT
};

enum nbl_adev_type {
	NBL_AUX_DEV_GRC = 0,
	NBL_AUX_DEV_ROCE,
	NBL_AUX_DEV_BOND,
};

enum nbl_devshr_index_type {
	NBL_DEVSHR_INDEX_RDMA_BEGIN,
/* the value max no modify, to support rdma driver version decouple */
	NBL_DEVSHR_INDEX_RDMA_END = 50,
	NBL_DEVSHR_INDEX_MAC,
	NBL_DEVSHR_INDEX_IP,
	NBL_DEVSHR_INDEX_MCC,
	NBL_DEVSHR_INDEX_DECAP_VTEP,
	NBL_DEVSHR_INDEX_ENCAP_TNL,
	NBL_DEVSHR_INDEX_ENCAP_VTEP,
	NBL_DEVSHR_INDEX_MAX,
};

enum nbl_core_evt_type {
	NBL_CORE_EVT_MTU_CHANGE,
	NBL_CORE_EVT_OVS_OFFLD,
	NBL_CORE_EVT_LAG_MBR,
	NBL_CORE_EVT_GRC_CHAN_RCV,
	NBL_CORE_EVT_ABN,
	NBL_CORE_EVT_FLR,
	NBL_CORE_EVT_RESET,
	NBL_CORE_EVT_QOS_CFG,
	NBL_CORE_EVT_QOS_SHOW,
	NBL_CORE_EVT_MIRROR_CFG,
	NBL_CORE_EVT_ECPU_BOND,
};

struct nbl_core_lag_mbr {
	u16 vsi_id;
	u8 eth_id;
	bool active;
};

#define NBL_RDMA_LAG_MBRS_MAX			8
struct nbl_core_lag_info {
	struct net_device *bond_netdev;
	u8 lag_id;
	u8 mbr_num;
	u16 rsv;
	struct nbl_core_lag_mbr mbr[NBL_RDMA_LAG_MBRS_MAX];
};

struct nbl_core_export {
	struct pci_dev *pdev;
	struct net_device *netdev;
	struct device *dma_dev;

	u8 __iomem *hw_addr;
	u64 real_hw_addr; /* get from hw pcie ip */

	struct msix_entry *msix_entries;
	u16 *global_vector_id;
	u16 msix_count;

	u16 vsi_id;
	u8 real_bus;
	u8 real_dev;
	u8 real_function;
	u8 rsv;

	u8 eth_mode;
	u8 eth_id;
	/**
	 * hw unified PCIe function ID does not change regardless of the OS or
	 * passthrough vm.
	 */
	u16 function_id;

	bool is_lag;
	struct nbl_core_lag_info lag_info;

	struct blocking_notifier_head lag_mbr_nh;
	struct blocking_notifier_head ovs_offld_nh;
	struct blocking_notifier_head mtu_nh;
	struct blocking_notifier_head grc_ch_rcv_nh;
	struct blocking_notifier_head grc_abn_nh;
	struct blocking_notifier_head grc_flr_nh;
	struct blocking_notifier_head reset_nh;
	struct blocking_notifier_head qos_cfg_nh;
	struct blocking_notifier_head qos_show_nh;
	struct blocking_notifier_head mirror_cfg_nh;
	struct blocking_notifier_head ecpu_bond_nh;

	u32 rdma_mem_type;
	u16 rdma_cap_num;
	u16 rdma_cap_my_num; /* only include the pf and my vf */
	bool mirror_enable;
	u8 __iomem *rdma_hw_addr; /* for virtio rdma bar */
	#define NBL_RDMA_MAX_FLOW_ID_IN			131071
	#define NBL_RDMA_MAX_FLOW_ID_NUM		4
	u32 ecn_fs_id[NBL_RDMA_MAX_FLOW_ID_NUM];
	u32 internal_cfg; /* from fw flash */
	u16 rx_vlan_vsi_id[4];

};

int nbl_devshr_alloc_idx(enum nbl_devshr_index_type type, struct pci_dev *pdev,
			 u32 *idx);
int nbl_devshr_free_idx(enum nbl_devshr_index_type type, struct pci_dev *pdev,
			u32 idx);
void nbl_devshr_free_func_idxs(enum nbl_devshr_index_type type,
			       struct pci_dev *pdev);

#include <linux/auxiliary_bus.h>

#define RDMA_MSG_MAX_SIZE 256
#define NBL_COREDEV_TO_DMA_DEV(core)		((core)->dma_dev)

struct nbl_chan_rdma_req {
	u8 req_data[RDMA_MSG_MAX_SIZE];
	u16 data_len;
};

struct nbl_chan_rdma_resp {
	u8 resp_data[RDMA_MSG_MAX_SIZE];
	u16 data_len;
};

struct nbl_chan_rdma_prm {
	struct nbl_chan_rdma_req *req;
	struct nbl_chan_rdma_resp *resp;
};

struct nbl_qos_cfg {
	int offset;
	const char *buf;
	size_t count;
	ssize_t return_size;
};

struct nbl_qos_show {
	int offset;
	char *buf;
	ssize_t return_size;
};

struct nbl_adev {
	struct auxiliary_device adev;
	int adev_idx;
	enum nbl_adev_type adev_type;
	struct nbl_core_export *core_info;
};

int nbl_core_send_chan_msg_to_grc(struct pci_dev *pdev, u8 *req_args,
				  u8 req_len, void *resp, u16 resp_len);
int nbl_core_rcv_rdma_driver_probed(struct pci_dev *pdev, bool enable);
int nbl_core_rcv_rdma_mirror_cfg(struct auxiliary_device *adev, u8 mirror_id);
int nbl_core_rcv_rdma_up_rdma_bypass(struct auxiliary_device *grc_adev,
				     u16 vsi_id, bool enable);
#endif
