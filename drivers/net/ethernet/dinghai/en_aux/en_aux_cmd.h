/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _EN_AUX_CMD_H_
#define _EN_AUX_CMD_H_

#include <linux/ethtool.h>
#include "../msg_common.h"

#define ZXDH_QRES_TBL_LEN (300)
#define ZXDH_QS_PAIRS (2)

#define INVALID_PHY_PORT 0xff
#define ZXDH_PHY_PORT_MAX 9
#define ZXDH_MAX_HASH_INDEX 6

/* HASH_FUNC TYPE */
#define ZXDH_FUNC_TOP 0x04
#define ZXDH_FUNC_XOR 0x02
#define ZXDH_FUNC_CRC32 0x01

/* RX_NFC */
#define ZXDH_NET_RX_FLOW_HASH_MV 4
#define ZXDH_NET_RX_FLOW_HASH_SDT 2
#define ZXDH_NET_RX_FLOW_HASH_SDFNT 1

/* RISCV OPCODE */
#define RISC_TYPE_READ 0
#define RISC_FIELD_PANEL_ID 5
#define RISC_FIELD_PHYPORT_CHANNEL 6
#define RISC_FIELD_HASHID_CHANNEL 10
#define RISC_SERVER_TIME 0xF0

#define MAX_PANEL_ID 9

/* SPM STATS */
#define ZXDH_SPM_STATS_OFFSET (0x24000 + 0x1000 + 408)
#define ZXDH_SPM_BYTES_OFFSET (0x24000 + 0xb000)

/* ZF bar address bit[16:63] needs to be shifted left by 4 bits */
#define TO_ZF_ADDR(addr) (((addr & 0xFFFFFFFFFFFF0000) << 4) | (addr & 0xFFFF))

#define ZXDH_NP_GLOBAL_PSN_ENABLE_BIT (28)

//#define MAC_CONFIG_DEBUG 1
enum riscv_op_code {
	OP_CODE_WRITE = 1,
	OP_CODE_MSGQ_CHAN = 2,
	OP_CODE_DATA_CHAN = 3,
	OP_CODE_MAX,
};

#define OP_CODE_TBL_STAT (0xaa)
#define MSG_STRUCT_HD_LEN 8

struct queue_index_message {
	u8 type;
	u8 field;
	u16 ep_bdf;
	u16 write_bytes;
	u16 rsv;
	u16 write_data[];
} __packed;

struct cmd_hdr_recv {
	u8 check;
	u8 rsv;
	u16 data_len_bytes;
};

struct cmd_tbl_ack {
	struct cmd_hdr_recv hdr;
	u8 phy_port;
	u8 rsv[3];
} __packed;

enum zxdh_msg_chan_opc {
	ZXDH_VPORT_GET = 4,
	ZXDH_PHYPORT_GET = 6,
};

struct zxdh_debug_msg {
	u8 opcode;
	u8 phyport;
	bool lldp_enable;
} __packed;

struct zxdh_debug_rcv_msg {
	u8 reps_states;
	u8 lldp_enable;
} __packed;

enum zxdh_en_link_speed_bit_indices {
	SPM_SPEED_1X_1G = 2,
	SPM_SPEED_1X_10G = 5,
	SPM_SPEED_1X_25G = 6,
	SPM_SPEED_1X_50G = 7,
	SPM_SPEED_2X_100G = 8,
	SPM_SPEED_4X_40G = 9,
	SPM_SPEED_4X_100G = 10,
	SPM_SPEED_4X_200G = 11,
};

enum zxdh_en_fec_mode_bit_indices {
	SPM_FEC_NONE = 0,
	SPM_FEC_BASER = 1,
	SPM_FEC_RS528 = 2,
	SPM_FEC_RS544 = 3,
};

enum zxdh_en_fc_mode_bit_indices {
	SPM_FC_NONE = 0,
	SPM_FC_PAUSE_RX = 1,
	SPM_FC_PAUSE_TX = 2,
	SPM_FC_PAUSE_FULL = 3,
	SPM_FC_PFC_FULL = 4,
};

struct zxdh_en_module_eeprom_param {
	u8 i2c_addr;
	u8 bank;
	u8 page;
	u8 offset;
	u8 length;
};

#define SFF_I2C_ADDRESS_LOW (0x50)
#define SFF_I2C_ADDRESS_HIGH (0x51)

enum zxdh_module_id {
	ZXDH_MODULE_ID_SFP = 0x3,
	ZXDH_MODULE_ID_QSFP = 0xC,
	ZXDH_MODULE_ID_QSFP_PLUS = 0xD,
	ZXDH_MODULE_ID_QSFP28 = 0x11,
	ZXDH_MODULE_ID_QSFP_DD = 0x18,
	ZXDH_MODULE_ID_OSFP = 0x19,
	ZXDH_MODULE_ID_DSFP = 0x1B,
	ZXDH_MODULE_ID_QSFP_PLUS_WITH_CMIS = 0x1E,
	ZXDH_MODULE_ID_SFP_DD_WITH_CMIS = 0x1F,
	ZXDH_MODULE_ID_SFP_PLUS_WITH_CMIS = 0x20,
};

#define SPEED_MODES_TO_SPEED(speed_modes, speed)                                               \
	do {                                                                                   \
		if (((speed_modes)&BIT(SPM_SPEED_1X_1G)) == BIT(SPM_SPEED_1X_1G)) {            \
			(speed) = SPEED_1000;                                                  \
		} else if (((speed_modes)&BIT(SPM_SPEED_1X_10G)) == BIT(SPM_SPEED_1X_10G)) {   \
			(speed) = SPEED_10000;                                                 \
		} else if (((speed_modes)&BIT(SPM_SPEED_1X_25G)) == BIT(SPM_SPEED_1X_25G)) {   \
			(speed) = SPEED_25000;                                                 \
		} else if (((speed_modes)&BIT(SPM_SPEED_4X_40G)) == BIT(SPM_SPEED_4X_40G)) {   \
			(speed) = SPEED_40000;                                                 \
		} else if (((speed_modes)&BIT(SPM_SPEED_1X_50G)) == BIT(SPM_SPEED_1X_50G)) {   \
			(speed) = SPEED_50000;                                                 \
		} else if (((speed_modes)&BIT(SPM_SPEED_2X_100G)) == BIT(SPM_SPEED_2X_100G)) { \
			(speed) = SPEED_100000;                                                \
		} else if (((speed_modes)&BIT(SPM_SPEED_4X_100G)) == BIT(SPM_SPEED_4X_100G)) { \
			(speed) = SPEED_100000;                                                \
		} else if (((speed_modes)&BIT(SPM_SPEED_4X_200G)) == BIT(SPM_SPEED_4X_200G)) { \
			(speed) = SPEED_200000;                                                \
		} else {                                                                       \
			(speed) = SPEED_UNKNOWN;                                               \
		}                                                                              \
	} while (0)

#define GET_VFID(vport)                                                     \
	((en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_PF) ? \
		       (PF_VQM_VFID_OFFSET + EPID(vport) * 8 + FUNC_NUM(vport)) : \
		       (EPID(vport) * 256 + VFUNC_NUM(vport)))

#define DH_AUX_PF_ID_OFFSET(vport) (EPID(vport) * 8 + FUNC_NUM(vport))

#define NP_GET_PKT_CNT 0
#define NP_CLEAR_PKT_CNT 1

struct zxdh_en_device;
s32 get_common_table_msg(struct zxdh_en_device *en_dev, u16 pcie_id, u8 field, void *ack);
s32 zxdh_common_tbl_init(struct net_device *netdev, union zxdh_msg *old_msg);
s32 zxdh_en_phyport_init(struct zxdh_en_device *en_dev);
s32 zxdh_en_autoneg_set(struct zxdh_en_device *en_dev, u8 enable, u32 speed_modes);
s32 zxdh_vport_stats_get(struct zxdh_en_device *en_dev);
s32 zxdh_en_vport_pre_stats_get(struct zxdh_en_device *en_dev);
s32 zxdh_mac_stats_get(struct zxdh_en_device *en_dev);
s32 zxdh_en_udp_pkt_stats_get(struct zxdh_en_device *en_dev);
s32 zxdh_mac_stats_clear(struct zxdh_en_device *en_dev);
s32 zxdh_hash_id_get(struct zxdh_en_device *en_dev);
s32 zxdh_en_fec_mode_set(struct zxdh_en_device *en_dev, u32 fec_cfg);
s32 zxdh_en_fec_mode_get(struct zxdh_en_device *en_dev, u32 *fec_cap, u32 *fec_cfg,
			 u32 *fec_active);
s32 zxdh_en_fc_mode_set(struct zxdh_en_device *en_dev, u32 fc_mode);
s32 zxdh_en_fc_mode_get(struct zxdh_en_device *en_dev, u32 *fc_mode);
u32 zxdh_en_module_eeprom_read(struct zxdh_en_device *en_dev,
			       struct zxdh_en_module_eeprom_param *query, u8 *data);
s32 zxdh_lldp_enable_set(struct zxdh_en_device *en_dev, bool lldp_enable);
s32 zxdh_sshd_enable_set(struct zxdh_en_device *en_dev, bool sshd_enable);
s32 zxdh_vf_dpp_add_mac(struct zxdh_en_device *en_dev, const u8 *dev_addr, u8 filter_flag);
s32 zxdh_vf_dpp_del_mac(struct zxdh_en_device *en_dev, const u8 *dev_addr, u8 filter_flag,
			bool mac_flag);
s32 zxdh_vf_dpp_dump_mac(struct zxdh_en_device *en_dev, const u8 *dev_addr);
void zxdh_vport_uninit(struct net_device *netdev);
s32 zxdh_pf_port_init(struct zxdh_en_device *en_dev, bool boot);
s32 zxdh_vf_dpp_port_init(struct zxdh_en_device *en_dev);
s32 zxdh_port_init(struct net_device *netdev);
s32 zxdh_vf_egr_port_attr_set(struct zxdh_en_device *en_dev, u32 mode, u32 value, u8 fow);
s32 zxdh_vf_egr_port_attr_get(struct zxdh_en_device *en_dev,
			      struct zxdh_sriov_vport_t *port_attr_entry);
s32 zxdh_vf_rss_en_set(struct zxdh_en_device *en_dev, u32 enable);
s32 zxdh_num_channels_changed(struct zxdh_en_device *en_dev, u16 num_changed);
s32 zxdh_pf_macpcs_num_get(struct zxdh_en_device *en_dev);
s32 zxdh_lldp_enable_get(struct zxdh_en_device *en_dev, u32 *lldp_enable);
s32 zxdh_indir_to_queue_map(struct zxdh_en_device *en_dev, const u32 *indir);
s32 zxdh_rxfh_set(struct zxdh_en_device *en_dev, u32 *queue_map);
void zxdh_rxfh_del(struct zxdh_en_device *en_dev);
void zxdh_u32_array_print(u32 *array, u16 size);
s32 zxdh_en_firmware_version_get(struct zxdh_en_device *en_dev, u8 *fw_version, u8 *fw_version_len);
s32 zxdh_panel_id_init(struct zxdh_en_device *en_dev);
s32 zxdh_vf_port_promisc_set(struct zxdh_en_device *en_dev, u8 mode, u8 value, u8 fow);
s32 zxdh_phyport_get(struct zxdh_en_device *en_dev);
s32 zxdh_vf_1588_call_np_interface(struct zxdh_en_device *en_dev);
s32 zxdh_aux_alloc_pannel(struct zxdh_en_device *en_dev);
int8_t zxdh_debug_ip_get(struct zxdh_en_device *en_dev, int8_t *ip);
s32 zxdh_vf_dpp_add_ipv6_mac(struct zxdh_en_device *en_dev, const u8 *mac_addr);
s32 zxdh_vf_dpp_del_ipv6_mac(struct zxdh_en_device *en_dev, const u8 *mac_addr);
s32 zxdh_vf_dpp_add_lacp_mac(struct zxdh_en_device *en_dev, const u8 *mac_addr);
s32 zxdh_vf_dpp_del_lacp_mac(struct zxdh_en_device *en_dev, const u8 *mac_addr);
s32 zxdh_spm_port_enable_cfg(struct zxdh_en_device *en_dev, u32 enable);
u32 zxdh_uplink_phy_attr_set(struct dpp_pf_info_t *pf_info, u8 phy_port, u32 attr, u32 value);
bool zxdh_en_is_panel_port(struct zxdh_en_device *en_dev);
s32 zxdh_get_vf_err_stats(struct zxdh_en_device *en_dev, struct zxdh_get_sw_stats *payload,
			  struct zxdh_sw_stats_reply *reply);
s32 zxdh_cfg_misx_mode(struct zxdh_en_device *en_dev, u16 rx_msix_mode, u16 tx_msix_mode);
s32 zxdh_get_misx_mode(struct zxdh_en_device *en_dev, u16 *rx_msix_mode, u16 *tx_msix_mode);
s32 zxdh_get_coalesce_usecs(struct zxdh_en_device *en_dev, u32 *rx_coalesce_usecs,
			    u32 *tx_coalesce_usecs);
s32 zxdh_cfg_coalesce_usecs(struct zxdh_en_device *en_dev, u32 rx_coalesce_usecs,
			    u32 tx_coalesce_usecs);
s32 zxdh_dual_tor_switch(struct zxdh_en_device *en_dev, bool state);
s32 zxdh_dual_tor_label_get(struct zxdh_en_device *en_dev);
s32 zxdh_en_hash_key_recover(struct zxdh_en_device *en_dev);
s32 zxdh_vf_add_fd(struct zxdh_en_device *en_dev, struct ethtool_rx_flow_spec *fs, u32 *index);
s32 zxdh_vf_get_fd(struct zxdh_en_device *en_dev, u32 index);
s32 zxdh_vf_del_fd(struct zxdh_en_device *en_dev, u32 index);
s32 zxdh_vf_fd_en_set(struct zxdh_en_device *en_dev, u32 enable);

#endif /* END __ZXDH_EN_COMMAND_H_ */
