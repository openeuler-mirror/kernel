/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 * Description: vdpa vmstate header file
 * Author: jiangdongxu
 * Create: 2023-12-3
 * Note:
 * History: 2023-12-3: Create file
 */

#ifndef VDPA_VMSTATE_H
#define VDPA_VMSTATE_H

#include <linux/virtio_net.h>
#include <linux/virtio_scsi.h>


#define VIRTIO_MIG_STATE_TYPE_DEVICE 0
#define VIRTIO_MIG_STATE_TYPE_VQ 1
#define VIRTIO_MIG_STATE_TYPE_CONFIG 2
#define VIRTIO_MIG_STATE_TYPE_FEATURE 3
#define VIRTIO_MIG_STATE_TYPE_PLATFORM 4
#define VIRTIO_MIG_STATE_TYPE_VENDOR 255

#define VIRTIO_MIG_DEVICE_T_COMMON 0
#define VIRTIO_MIG_DEVICE_T_NET 1
#define VIRTIO_MIG_DEVICE_T_BLK 2
#define VIRTIO_MIG_DEVICE_T_SCSI 8

#define VIRTIO_MIG_CONFIG_T_NET 1
#define VIRTIO_MIG_CONFIG_T_BLK 2
#define VIRTIO_MIG_CONFIG_T_SCSI 8

#define MAC_LEN 6

struct virtio_mig_state_header {
	le32 type;
	le32 len;
};

struct virtio_mig_dev_common_data {
	le32 vendor_id;
	le32 device_id;
	le32 device_features_l;
	le32 device_features_h;
	le32 driver_features_l;
	le32 driver_features_h;
	le32 status;
	le32 generation;
	le32 msix_en;
};

struct virtio_mig_dev_common_state {
	struct virtio_mig_state_header hdr;
	struct virtio_mig_dev_common_data data;
};

struct virtio_mig_vq_split_state {
	le16 avail_index;
	le16 used_index;
};
struct virtio_mig_vq_packed_state {
	le16 avail_wrapped : 1;
	le16 avail_index : 15;
	le16 used_wrapped : 1;
	le16 used_index : 15;
};

struct virtio_mig_per_vq_data {
	le32 qsize;

	u8 qenabled;
	le16 msix_vector;

	le32 desc_l;
	le32 desc_h;
	le32 avail_l;
	le32 avail_h;
	le32 used_l;
	le32 used_h;
	union {
		struct virtio_mig_vq_split_state split;
		struct virtio_mig_vq_packed_state packed;
	} version;
};

/* vq state */
struct virtio_mig_vq_state {
	struct virtio_mig_state_header hdr;

	le16 msix_config;
	le16 valid_queues;

	le16 num_queues;

	struct virtio_mig_per_vq_data vq_state[];
};

/* config space */
struct virtio_mig_config_state {
	struct virtio_mig_state_header hdr;
	union {
		struct virtio_net_config net;
		struct virtio_blk_config blk;
		struct virtio_scsi_config scsi;
	} dev;
};

struct virtio_mig_cfg_blk_features {

};

struct virtio_mig_cfg_scsi_features {

};

struct virtio_mig_cfg_net_ctrl_guest_offloads {
	struct virtio_mig_state_header hdr;
	le64 offloads;
	le64 reserved;
};

struct virtio_mig_cfg_net_ctrl_mq_vq_pairs {
	struct virtio_mig_state_header hdr;
	le16 cur_virtqueue_pairs;
};

struct virtio_mig_cfg_net_ctrl_mac_table {
	struct virtio_mig_state_header hdr;
	le16 num_unicast;
	/* TODO: need to be implemented later */
	// u8 unicast_macs[][6];
	le16 num_multicast;
	/* TODO: need to be implemented later */
	// u8 multicast_macs[][6];
};

struct virtio_mig_cfg_net_ctrl_vlan {
	struct virtio_mig_state_header hdr;
	le32 vlans[128];
};

struct virtio_mig_cfg_net_data {
	le32 nfeatures;
	struct virtio_mig_cfg_net_ctrl_guest_offloads offloads;
	struct virtio_mig_cfg_net_ctrl_mq_vq_pairs mq_pairs;
	struct virtio_mig_cfg_net_ctrl_mac_table mac_table;
	struct virtio_mig_cfg_net_ctrl_vlan vlan_table;
};

struct virtio_mig_cfg_net_features {
	struct virtio_mig_state_header hdr;
	struct virtio_mig_cfg_net_data data;
};

/* feature */
struct virtio_mig_feat_state {
	union {
		struct virtio_mig_cfg_net_features net;
		struct virtio_mig_cfg_blk_features blk;
		struct virtio_mig_cfg_scsi_features scsi;
	};
};

struct vdpa_mig_state {
	struct virtio_mig_dev_common_state dev_state;
	struct virtio_mig_config_state cfg_state;
	struct virtio_mig_feat_state feat_state;
	struct virtio_mig_vq_state vq_state;
};

#endif /* VDPA_VMSTATE_H */
