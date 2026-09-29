/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2024-2026 Mucse Corporation. */

#ifndef __MCE_FWCHNL_H__
#define __MCE_FWCHNL_H__
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/wait.h>
#include "mce_type.h"

enum SERDES_SPEED {
	SERDES_25G_100G,
	SERDES_10G_40G,
	SERDES_1G,
	SERDERS_SPEED_CNT
};

enum PF2FW_OPCODE {
	GET_PORT_ABALITY = 1,
	FW_EEPROM = 2,

	READ_REG = 3,
	WRITE_REG = 4,
	MODIFY_REG = 5,

	IFUP_DOWN = 6,

	SET_PHY_FUNC = 10,

	SET_LOOPBACK_MODE = 14,

	GET_FLASH_SI = 16,
	SET_PMA_SI = 17,
	GET_PMA_SI = 18,

	DUMP_EEPROM = 19,

	SFP_MODULE_READ = 20,
	SFP_MODULE_WRITE = 21,

	GET_DUMP = 24,
	SET_DUMP = 25,

	LLDP_TX_CTL = 27,
	SET_DDR_CSL = 28,

	SET_VF_MAX_QUEUE = 29,

	SRIOV_SET = 32,
	GET_ENABLED_VF_NUM_STATUS = 37,

	WRITE_SGMII_PHY_REG = 40,
	READ_SGMII_PHY_REG = 41,
	MODIFY_SGMII_PHY_REG = 42,
};

struct port_abilities {
	unsigned int fw_version;
	unsigned short axi_mhz;
	unsigned short phy_type;

	unsigned int vf_isolation_disabled : 1;
	unsigned int vf_max_ring	   : 7;
	unsigned int nr_pf		   : 1;
	unsigned int link_stat		   : 1;
	unsigned int max_speed		   : 3;
	unsigned int wol_supported	   : 1;
	unsigned int wol_enabled	   : 1;
	unsigned int is_sgmii		   : 1;
	unsigned int is_10g_phy		   : 1;
	unsigned int rpu_available	   : 1;
	unsigned int only_1g : 1;
	unsigned int has_rdma : 1;
	unsigned int rdma_disabled : 1;
	unsigned int rpu_en : 1;
	unsigned int ncsi_en : 1;
} __packed __aligned(4);

union mbx_fw_cmd_req_data {
	int data[0];

	struct {
		int whoami;
#define I_AM_DPDK 0xa1
#define I_AM_DRV  0xa2
#define I_AM_PXE  0xa3
	} get_port_ablity;

	int rev2[32 / 4];

	struct {
		unsigned int max_cnt;
		int vf_isolation_disable;
	} vf_max_queue_cnt;

	struct {
		unsigned int addr;
		unsigned int bytes;
	} r_reg;

	struct {
		unsigned int addr;
		unsigned int bytes;
		unsigned int data[4];
	} w_reg;

	struct {
		unsigned int addr;
		unsigned int data;
		unsigned int mask;
	} modify_reg;

	struct {
		unsigned short nr_phy;
		unsigned char nr_serdes_speed;
		unsigned char loaded_si;
	} get_flash_si;

	struct {
		int value;
	} sriov_vf_enabled_status;

	struct {
		int cmd;
		int partition;
		int bytes;
		unsigned int ddr_lo;
		unsigned int ddr_hi;
	} eeprom;

	struct {
		unsigned int lanes;
	} ptp;

	struct {
		int up;
	} ifup;

	struct {
		int nr_lane;
#define LLDP_TX_ALL_LANES 0xFF
		int op;
#define LLDP_TX_SET 0x0
#define LLDP_TX_GET 0x1
		int enable;
	} lldp_tx;

	struct {
		int nr_lane;
	} get_lane_st;

	struct {
		int func;
#define PHY_FUN_AN 0
#define PHY_FUN_LINK_TRAING 1
#define PHY_FUN_FEC 2
#define PHY_FUN_SI 3
#define PHY_FUN_SFP_TX_DISABLE 4
#define PHY_FUN_PCI_LANE 5
#define PHY_FUN_PRBS 6
#define PHY_FUN_SPEED_CHANGE 7
#define PHY_FUN_AN_RESTART 8
#define PHY_FUN_LINK_TRAING_RESTART 9
#define PHY_FUN_WOL_SET 10
#define PHY_FUN_LED_IDENTIFY 11
#define PHY_FUN_FORCE_SPEED 12
#define PHY_FUN_SET_SGMII_DUPLEX 13
#define PHY_FUN_FORCE_LINK_ON_CLOSE 14

		int value0;
		int value1;
	} set_phy_fun;

	struct {
		int flag;
	} set_dump;

	struct {
		unsigned int bytes;
		unsigned int bin_phy_lo;
		unsigned int bin_phy_hi;
	} get_dump;

	struct {
		int offset;
		int bytes;

		unsigned int ddr_lo;
		unsigned int ddr_hi;
	} dump_eeprom;

	struct {
		int action;
#define LED_IDENTIFY_INACTIVE 0
#define LED_IDENTIFY_ACTIVE   1
#define LED_IDENTIFY_ON	      2
#define LED_IDENTIFY_OFF      3
	} led_set;

	struct {
		unsigned int adv_speed_mask;
		unsigned int autoneg;
		unsigned int speed;
		unsigned int duplex;
		int nr_lane;
		unsigned int tp_mdix_ctrl;
	} phy_link_set;

	struct {
		int nr_phy;
		/* 4:nr_lane:0-3 */
		/* 6:[0]=main,[1]=pre,[2]=post1,[3]=post2,[4]=post3,[5]=boost | valid */
		s8 v[4][6];
	} si;

	struct {
		unsigned int pause_mode;
		int nr_lane;
	} phy_pause_set;

	struct {
		unsigned int nr_phy;
		unsigned int sfp_i2c_adr;
		unsigned int reg;
		unsigned int cnt;
	} sfp_read;

	struct {
		unsigned int nr_phy;
		unsigned int sfp_i2c_adr;
		unsigned int reg;
		unsigned int val;
	} sfp_write;

	struct { /* set loopback */
		unsigned char loopback_level;
		unsigned char loopback_type;
		unsigned char loopback_force_speed;
		unsigned char loopback_force_speed_enable : 1;
	} loopback;

	struct {
		int cmd;
		int arg0;
		int req_bytes;
		int reply_bytes;
		int ddr_lo;
		int ddr_hi;
	} fw_update;

	struct { /* set phy register */
		char phy_interface;
		union {
			char page_num;
			char external_phy_addr;
		};
		int phy_reg_addr;
		int phy_w_data;
		int reg_addr;
		int w_data;
		/* 1 = ignore page_num, use last QSFP */
		unsigned char recall_qsfp_page : 1;
	} set_phy_reg;

	struct {
		char phy_interface;
		union {
			char page_num;
			char external_phy_addr;
		};
		int phy_reg_addr;
		char nr_lane;
	} get_phy_reg;

	struct {
		unsigned int nr_lane;
	} phy_statistics;

} __packed __aligned(4);

/* firmware -> driver */
union mbx_fw_cmd_resp_data {
	int data[0];

	struct port_abilities ablity;

	struct {
		unsigned int value[4];
	} r_reg;

	struct {
		unsigned int new_value;
	} modify_reg;

	struct {
#define MBX_SFP_READ_MAX_CNT 32
		char value[MBX_SFP_READ_MAX_CNT];
	} sfp_read;

	struct {
		int value;
	} sriov_vf_enabled_status;

	struct get_dump_reply {
		int flags;
		int version;
		int bytes;
		int data[4];
	} get_dump;

	struct {
		signed char v[4][6];
	} port_si;

	struct {
		signed char v[2][4][6];
	} port_flash_si;

} __packed __aligned(4);

enum MBX_ID;
int mce_fw_get_capability(struct mce_hw *hw, struct port_abilities *ablity);
int mce_mbx_get_lane_stat(struct mce_hw *hw);
int mce_mbx_set_vf_max_queue_cnt(struct mce_hw *hw, u32 val);

void mce_mbx_fw_req_isr(struct mce_mbx_info *mbx, struct mbx_req *req);
void mce_mbx_fw_event_req_isr(struct mce_mbx_info *mbx, int event_id);

int mce_fw_update_firmware(struct mce_hw *hw, int partition, const u8 *fw_bin,
			   int bytes);

int mce_soc_modify32(struct mce_hw *hw, int soc_addr, unsigned int mask,
		     unsigned int value);
int mce_soc_iowrite32(struct mce_hw *hw, int soc_addr, unsigned int value);
int mce_soc_ioread32(struct mce_hw *hw, int soc_addr, unsigned int *value);

enum LED_ACTION {
	LED_INACTIVE,
	LED_ACTIVE,
	LED_ACT_ON,
	LED_ACT_OFF,
	LED_ACT_KEEP_BLINK,
};

int mce_read_sfp_module_eeprom(struct mce_hw *hw, int sfp_i2c_addr, int sfp_reg,
			       char *buf, int bytes);

int mce_write_sfp_module_eeprom(struct mce_hw *hw, int sfp_i2c_addr,
				int sfp_reg, short val);

int mce_mbx_wol_set(struct mce_hw *hw, bool enable);
int mce_mbx_set_link_restart_autoneg(struct mce_hw *hw);

enum FEC_TYPE {
	FEC_NONE,
	FEC_BASER,
	FEC_RS,
	FEC_AUTO,
};

int mce_mbx_set_link_traning_en(struct mce_hw *hw, int enable);
int mce_mbx_set_autoneg(struct mce_hw *hw, int enable);
int mce_mbx_set_fec(struct mce_hw *hw, enum FEC_TYPE fec_type);
int mce_fw_set_led(struct mce_hw *hw, enum LED_ACTION action);
int mce_mbx_set_phy_func(struct mce_hw *hw, int func, int arg0, int arg1);

int mce_mbx_set_dump(struct mce_hw *hw, int dump_v);
int mce_mbx_get_dump(struct mce_hw *hw, int dump_v, void *buf, int buflen,
		     int *flag, int *version);

#define EEPROM_MAX_SIZE (1 * 1024 * 1024)
int mce_mbx_dump_eeprom(struct mce_hw *hw, int offset, char *buf, int bytes);

#define MCE_LG_SOC_BASE 0x3f000000
#define MCE_LG_SOC_VOLTAGE_REG (MCE_LG_SOC_BASE + 0x0)
#define MCE_LG_SOC_PCI_SPEED (MCE_LG_SOC_BASE + 0x8)
#define MCE_LG_SOC_AXI_MHZ (MCE_LG_SOC_BASE + 0xc)

/* shared memory */
#define MCE_SOC_PCIE_RESTORE_CNT_REG 0x28

int mce_soc_ioread32_noshm(struct mce_hw *hw, int soc_reg);
int mce_soc_iowrite32_noshm(struct mce_hw *hw, int soc_reg, int v);

int mce_get_port_si(struct mce_hw *hw, signed char port_si[4][6]);
int mce_set_port_si(struct mce_hw *hw, int port_si[4][6]);

int mce_mbx_set_force_speed(struct mce_hw *hw, enum FORCE_SPEED speed);
int mce_mbx_set_duplex(struct mce_hw *hw, int full);
int mce_mbx_ifup_down(struct mce_hw *hw, bool up);
int mce_mbx_set_force_link_on_close(struct mce_hw *hw, bool force);

int mce_get_flash_si(struct mce_hw *hw, enum SERDES_SPEED serdes_type,
		     signed char port_si[4][6]);
int mce_get_pf_sriov_en_status(struct mce_hw *hw, int *status);
int mce_mbx_axi_mhz_set(struct mce_hw *hw, int axi_mhz);
int mce_mbx_axi_mhz_get(struct mce_hw *hw);
#endif /* _MCE_FWCHNL_H_ */
