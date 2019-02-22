// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2016-2017 Hisilicon Limited.

#ifndef __HCLGE_MDIO_H
#define __HCLGE_MDIO_H

struct hclge_mdio_cfg_cmd {
	u8 ctrl_bit;
	u8 phyid;
	u8 phyad;
	u8 rsvd;
	__le16 reserve;
	__le16 data_wr;
	__le16 data_rd;
	__le16 sta;
};

int hclge_mac_mdio_config(struct hclge_dev *hdev);
int hclge_mac_connect_phy(struct hnae3_handle *handle);
void hclge_mac_disconnect_phy(struct hnae3_handle *handle);
void hclge_mac_start_phy(struct hclge_dev *hdev);
void hclge_mac_stop_phy(struct hclge_dev *hdev);

#endif
