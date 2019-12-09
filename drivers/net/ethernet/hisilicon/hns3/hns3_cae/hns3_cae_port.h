/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2016-2019 Hisilicon Limited. */

#ifndef __HNS3_CAE_PORT_H__
#define __HNS3_CAE_PORT_H__

#define HCLGE_OPC_QUERY_PORTINFO_BD_NUM		0x0380
#define HCLGE_OPC_DUMP_PORT_INFO		 0x0381

struct port_cfg {
	u8 an;
	u8 fec;
	u16 speed;
};

struct port_param_info {
	/* BD7:24 byte */
	u8 chip_id;
	u8 lane_id;
	u8 lane_num;
	u8 rsvd1;
	struct port_cfg default_cfg;
	struct port_cfg bios_cfg;
	struct port_cfg user_cfg;
	struct port_cfg final_cfg;
	u8 adapt_default_en;
	u8 adapt_cur_en;
	u8 adapt_speed;
	u8 rsvd2;
};

struct hclge_port_info {
	/* BD0:24 Byte */
	u8 vendor_name[16];
	u32 port_type;
	u32 port_sub_type;

	/* BD1:24 Byte */
	u32 cable_length;
	u8 cable_temp;
	u8 max_speed;
	u8 sfp_type;
	u8 rsvd2;
	u32 power[4];

	/* BD2:24 Byte */
	u8 an_state;
	u8 fec;
	u16 speed;

	u8 gpio_insert;
	u8 alos;
	u8 rx_los;
	u8 pma_ctrl;

	u32 pma_fifo_reg;
	u32 pma_signal_ok_reg;
	u32 pcs_64_66b_reg;
	u32 rf_lf;

	/* BD3 - BD4:24*2 Byte */
	u8 pcs_link;
	u8 pcs_mac_link;
	u8 tx_enable;
	u8 rx_enable;
	u32 pcs_err_cnt;

	u8 eq_data[38];
	u8 rsvd5[2];

	/* BD5-BD6 */
	u32 his_link_machine_state;
	u32 cur_link_machine_state;

	u8 his_machine_state_data[128];
	u8 cur_machine_state_data[128];

	u8 his_machine_state_length;
	u8 cur_machine_state_length;

	struct port_param_info param_info;

	u8 rsvd6[488];
};

struct hclge_lsport_info {
	u32 portinfo[6];
};

int hns3_get_port_info(struct hns3_nic_priv *net_priv,
		       void *buf_in, u32 in_size,
		       void *buf_out, u32 out_size);

#endif
