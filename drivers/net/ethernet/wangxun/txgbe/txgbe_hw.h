/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2015 - 2022 Beijing WangXun Technology Co., Ltd. */

#ifndef _TXGBE_HW_H_
#define _TXGBE_HW_H_

#define TXGBE_SP_MAX_TX_QUEUES  128
#define TXGBE_SP_MAX_RX_QUEUES  128

#define TXGBE_SP_RAR_ENTRIES    128
#define TXGBE_SP_MC_TBL_SIZE    128
#define TXGBE_SP_VFT_TBL_SIZE   128
#define TXGBE_SP_RX_PB_SIZE     512

#define TXGBE_EMC_INTERNAL_DATA         0x00
#define TXGBE_EMC_INTERNAL_THERM_LIMIT  0x20
#define TXGBE_EMC_DIODE1_DATA           0x01
#define TXGBE_EMC_DIODE1_THERM_LIMIT    0x19
#define TXGBE_EMC_DIODE2_DATA           0x23
#define TXGBE_EMC_DIODE2_THERM_LIMIT    0x1A
#define TXGBE_EMC_DIODE3_DATA           0x2A
#define TXGBE_EMC_DIODE3_THERM_LIMIT    0x30

#define SPI_CLK_DIV                        2

#define SPI_CMD_ERASE_CHIP                 4  // SPI erase chip command
#define SPI_CMD_ERASE_SECTOR               3  // SPI erase sector command
#define SPI_CMD_WRITE_DWORD                0  // SPI write a dword command
#define SPI_CMD_READ_DWORD                 1  // SPI read a dword command
#define SPI_CMD_USER_CMD                   5  // SPI user command
#define SPI_CLK_CMD_OFFSET                28  // SPI command field offset in Command register
#define SPI_CLK_DIV_OFFSET                25  // SPI clock divide field offset in Command register

#define SPI_TIME_OUT_VALUE             10000
#define SPI_SECTOR_SIZE          (4 * 1024)  // FLASH sector size is 64KB
#define SPI_H_CMD_REG_ADDR           0x10104  // SPI Command register address
#define SPI_H_DAT_REG_ADDR           0x10108  // SPI Data register address
#define SPI_H_STA_REG_ADDR           0x1010c  // SPI Status register address
#define SPI_H_USR_CMD_REG_ADDR       0x10110  // SPI User Command register address
#define SPI_CMD_CFG1_ADDR            0x10118  // Flash command configuration register 1
#define MISC_RST_REG_ADDR            0x1000c  // Misc reset register address
#define MGR_FLASH_RELOAD_REG_ADDR    0x101a0  // MGR reload flash read
#define PRB_CTL                      0x10200  // used to check whether has been upgraded
#define PRB_SCRATCH                  0x10230  // used to check whether has been upgraded

#define MAC_ADDR0_WORD0_OFFSET_1G    0x006000c  // MAC Address for LAN0, stored in external FLASH
#define MAC_ADDR0_WORD1_OFFSET_1G    0x0060014
#define MAC_ADDR1_WORD0_OFFSET_1G    0x007000c  // MAC Address for LAN1, stored in external FLASH
#define MAC_ADDR1_WORD1_OFFSET_1G    0x0070014

#define AMLITE_MAC_ADDR0_WORD0_OFFSET 0x00f010c // MAC Address for LAN0, stored in external FLASH
#define AMLITE_MAC_ADDR0_WORD1_OFFSET 0x00f0114
#define AMLITE_MAC_ADDR1_WORD0_OFFSET 0x00f020c // MAC Address for LAN1, stored in external FLASH
#define AMLITE_MAC_ADDR1_WORD1_OFFSET 0x00f0214

#define PRODUCT_SERIAL_NUM_OFFSET_1G    0x00f0000
#define TXGBE_VPD_OFFSET    0x500
#define TXGBE_VPD_END    0x600

#ifndef TXGBE_STORM_INTERVAL
#define TXGBE_STORM_INTERVAL	100
#endif

#ifndef TXGBE_STORM_UC
#define TXGBE_STORM_UC		0
#endif

#ifndef TXGBE_STORM_BC
#define TXGBE_STORM_BC		0
#endif

#ifndef TXGBE_STORM_BC_THRE
#define TXGBE_STORM_BC_THRE	100
#endif

#ifndef TXGBE_STORM_MC
#define TXGBE_STORM_MC		0
#endif

#ifndef TXGBE_STORM_MC_THRE
#define TXGBE_STORM_MC_THRE	100
#endif

struct txgbe_hic_read_cab {
	union txgbe_hic_hdr2 hdr;
	union {
		u8 d8[252];
		u16 d16[126];
		u32 d32[63];
	} dbuf;
};

/**
 * Packet Type decoding
 **/
/* txgbe_dec_ptype.mac: outer mac */
enum txgbe_dec_ptype_mac {
	TXGBE_DEC_PTYPE_MAC_IP = 0,
	TXGBE_DEC_PTYPE_MAC_L2 = 2,
	TXGBE_DEC_PTYPE_MAC_FCOE = 3,
};

/* txgbe_dec_ptype.[e]ip: outer&encaped ip */
#define TXGBE_DEC_PTYPE_IP_FRAG (0x4)
enum txgbe_dec_ptype_ip {
	TXGBE_DEC_PTYPE_IP_NONE = 0,
	TXGBE_DEC_PTYPE_IP_IPV4 = 1,
	TXGBE_DEC_PTYPE_IP_IPV6 = 2,
	TXGBE_DEC_PTYPE_IP_FGV4 =
		(TXGBE_DEC_PTYPE_IP_FRAG | TXGBE_DEC_PTYPE_IP_IPV4),
	TXGBE_DEC_PTYPE_IP_FGV6 =
		(TXGBE_DEC_PTYPE_IP_FRAG | TXGBE_DEC_PTYPE_IP_IPV6),
};

/* txgbe_dec_ptype.etype: encaped type */
enum txgbe_dec_ptype_etype {
	TXGBE_DEC_PTYPE_ETYPE_NONE = 0,
	TXGBE_DEC_PTYPE_ETYPE_IPIP = 1, /* IP+IP */
	TXGBE_DEC_PTYPE_ETYPE_IG = 2, /* IP+GRE */
	TXGBE_DEC_PTYPE_ETYPE_IGM = 3, /* IP+GRE+MAC */
	TXGBE_DEC_PTYPE_ETYPE_IGMV = 4, /* IP+GRE+MAC+VLAN */
};

/* txgbe_dec_ptype.proto: payload proto */
enum txgbe_dec_ptype_prot {
	TXGBE_DEC_PTYPE_PROT_NONE = 0,
	TXGBE_DEC_PTYPE_PROT_UDP = 1,
	TXGBE_DEC_PTYPE_PROT_TCP = 2,
	TXGBE_DEC_PTYPE_PROT_SCTP = 3,
	TXGBE_DEC_PTYPE_PROT_ICMP = 4,
	TXGBE_DEC_PTYPE_PROT_TS = 5, /* time sync */
};

/* txgbe_dec_ptype.layer: payload layer */
enum txgbe_dec_ptype_layer {
	TXGBE_DEC_PTYPE_LAYER_NONE = 0,
	TXGBE_DEC_PTYPE_LAYER_PAY2 = 1,
	TXGBE_DEC_PTYPE_LAYER_PAY3 = 2,
	TXGBE_DEC_PTYPE_LAYER_PAY4 = 3,
};

struct txgbe_dec_ptype {
	u32 ptype:8;
	u32 known:1;
	u32 mac:2; /* outer mac */
	u32 ip:3; /* outer ip*/
	u32 etype:3; /* encaped type */
	u32 eip:3; /* encaped ip */
	u32 prot:4; /* payload proto */
	u32 layer:3; /* payload layer */
};

extern struct txgbe_dec_ptype txgbe_ptype_lookup[256];


void txgbe_dcb_get_rtrup2tc(struct txgbe_hw *hw, u8 *map);
int txgbe_init_hw(struct txgbe_hw *hw);
int txgbe_start_hw(struct txgbe_hw *hw);
int txgbe_clear_hw_cntrs(struct txgbe_hw *hw);
int txgbe_read_pba_string(struct txgbe_hw *hw, u8 *pba_num,
			  u32 pba_num_size);
int txgbe_get_mac_addr(struct txgbe_hw *hw, u8 *mac_addr);
int txgbe_get_bus_info(struct txgbe_hw *hw);
void txgbe_set_lan_id_multi_port_pcie(struct txgbe_hw *hw);
int txgbe_stop_adapter(struct txgbe_hw *hw);

int txgbe_led_on(struct txgbe_hw *hw, u32 index);
int txgbe_led_off(struct txgbe_hw *hw, u32 index);

int txgbe_set_rar(struct txgbe_hw *hw, u32 index, u8 *addr, u64 pools,
		  u32 enable_addr);
int txgbe_clear_rar(struct txgbe_hw *hw, u32 index);
int txgbe_init_rx_addrs(struct txgbe_hw *hw);
int txgbe_update_mc_addr_list(struct txgbe_hw *hw, u8 *mc_addr_list,
			      u32 mc_addr_count,
				      txgbe_mc_addr_itr func, bool clear);
int txgbe_disable_sec_rx_path(struct txgbe_hw *hw);
int txgbe_enable_sec_rx_path(struct txgbe_hw *hw);
int txgbe_disable_sec_tx_path(struct txgbe_hw *hw);
int txgbe_enable_sec_tx_path(struct txgbe_hw *hw);

#ifndef read_poll_timeout
#define read_poll_timeout(op, val, cond, sleep_us, timeout_us, \
				sleep_before_read, args...) \
({ \
	u64 __timeout_us = (timeout_us); \
	unsigned long __sleep_us = (sleep_us); \
	ktime_t __timeout = ktime_add_us(ktime_get(), __timeout_us); \
	might_sleep_if((__sleep_us) != 0); \
	if (sleep_before_read && __sleep_us) \
		usleep_range((__sleep_us >> 2) + 1, __sleep_us); \
	for (;;) { \
		(val) = op(args); \
		if (cond) \
			break; \
		if (__timeout_us && \
		    ktime_compare(ktime_get(), __timeout) > 0) { \
			(val) = op(args); \
			break; \
		} \
		if (__sleep_us) \
			usleep_range((__sleep_us >> 2) + 1, __sleep_us); \
		cpu_relax(); \
	} \
	(cond) ? 0 : -ETIMEDOUT; \
})
#endif

int txgbe_fc_enable(struct txgbe_hw *hw);
bool txgbe_device_supports_autoneg_fc(struct txgbe_hw *hw);
int txgbe_setup_fc(struct txgbe_hw *hw);

int txgbe_acquire_swfw_sync(struct txgbe_hw *hw, u32 mask);
void txgbe_release_swfw_sync(struct txgbe_hw *hw, u32 mask);
int txgbe_disable_pcie_master(struct txgbe_hw *hw);

int txgbe_set_vmdq_san_mac(struct txgbe_hw *hw, u32 vmdq);
int txgbe_init_uta_tables(struct txgbe_hw *hw);
int txgbe_set_vfta(struct txgbe_hw *hw, u32 vlan,
		   u32 vind, bool vlan_on);
int txgbe_clear_vfta(struct txgbe_hw *hw);

void txgbe_set_vlan_anti_spoofing(struct txgbe_hw *hw, bool enable, int vf);
void txgbe_set_ethertype_anti_spoofing(struct txgbe_hw *hw,
				       bool enable, int vf);
void txgbe_set_rxpba(struct txgbe_hw *hw, int num_pb, u32 headroom,
		     int strategy);
int txgbe_reset_hostif(struct txgbe_hw *hw);
bool txgbe_mng_present(struct txgbe_hw *hw);
bool txgbe_check_mng_access(struct txgbe_hw *hw);

int txgbe_get_thermal_sensor_data(struct txgbe_hw *hw);
int txgbe_init_thermal_sensor_thresh(struct txgbe_hw *hw);
void txgbe_enable_rx(struct txgbe_hw *hw);
void txgbe_disable_rx(struct txgbe_hw *hw);
int txgbe_setup_mac_link_multispeed_fiber(struct txgbe_hw *hw,
					  u32 speed,
					  bool autoneg_wait_to_complete);
int txgbe_check_flash_load(struct txgbe_hw *hw, u32 check_bit);

/* @txgbe_api.h */
int txgbe_reinit_fdir_tables(struct txgbe_hw *hw);
int txgbe_init_fdir_signature(struct txgbe_hw *hw, u32 fdirctrl);
int txgbe_init_fdir_perfect(struct txgbe_hw *hw, u32 fdirctrl);
int txgbe_fdir_add_signature_filter(struct txgbe_hw *hw,
				    union txgbe_atr_hash_dword input,
					  union txgbe_atr_hash_dword common,
					  u8 queue);
int txgbe_fdir_set_input_mask(struct txgbe_hw *hw,
			      union txgbe_atr_input *input_mask);
int txgbe_fdir_set_flex_conf(struct txgbe_hw *hw,
			     struct txgbe_fdir_filter *input,
			     union txgbe_atr_input *input_mask);
int txgbe_fdir_write_perfect_filter(struct txgbe_hw *hw,
				    union txgbe_atr_input *input,
				    u16 soft_id, u8 queue);
int txgbe_fdir_erase_perfect_filter(struct txgbe_hw *hw,
				    union txgbe_atr_input *input,
					  u16 soft_id);
void txgbe_atr_compute_perfect_hash(union txgbe_atr_input *input,
				    union txgbe_atr_input *mask);
int txgbe_check_reset_blocked(struct txgbe_hw *hw);

void txgbe_disable_tx_laser_multispeed_fiber(struct txgbe_hw *hw);
void txgbe_enable_tx_laser_multispeed_fiber(struct txgbe_hw *hw);
void txgbe_flap_tx_laser_multispeed_fiber(struct txgbe_hw *hw);
void txgbe_set_hard_rate_select_speed(struct txgbe_hw *hw, u32 speed);

int txgbe_init_shared_code(struct txgbe_hw *hw);
int txgbe_get_invariants_generic(struct txgbe_hw *hw);
void txgbe_release_hw_control(struct txgbe_hw *hw);
void txgbe_get_hw_control(struct txgbe_hw *hw);
int txgbe_reset_hw_generic(struct txgbe_hw *hw);
int txgbe_identify_phy_generic(struct txgbe_hw *hw);
int txgbe_enable_rx_dma(struct txgbe_hw *hw, u32 regval);
int txgbe_setup_eee(struct txgbe_hw *hw, bool enable_eee);
int txgbe_reconfig_mac(struct txgbe_hw *hw);

int txgbe_write_flash_buffer(struct txgbe_hw *hw, u32 offset,
			     u32 dwords, u32 *data);

int txgbe_init_eeprom_params(struct txgbe_hw *hw);
int txgbe_update_eeprom_checksum(struct txgbe_hw *hw);
int txgbe_validate_eeprom_checksum(struct txgbe_hw *hw,
				   u16 *checksum_val);
int txgbe_upgrade_flash(struct txgbe_hw *hw, u32 region,
			const u8 *data, u32 size);
int txgbe_write_ee_hostif_buffer(struct txgbe_hw *hw,
				 u16 offset, u16 words, u16 *data);
int txgbe_read_ee_hostif_buffer(struct txgbe_hw *hw,
				u16 offset, u16 words, u16 *data);
int txgbe_read_ee_hostif(struct txgbe_hw *hw, u16 offset, u16 *data);

int txgbe_upgrade_flash_hostif(struct txgbe_hw *hw,  u32 region,
			       const u8 *data, u32 size);

int txgbe_flash_read_dword(struct txgbe_hw *hw, u32 addr, u32 *data);
int txgbe_hic_write_lldp(struct txgbe_hw *hw, u32 open);
int txgbe_is_lldp(struct txgbe_hw *hw);
int txgbe_set_pps(struct txgbe_hw *hw, bool enable, u64 nsec, u64 cycles);
void txgbe_hic_write_autoneg_status(struct txgbe_hw *hw, bool autoneg);
int txgbe_enable_rx_adapter(struct txgbe_hw *hw);

void txgbe_set_queue_rate_limit(struct txgbe_hw *hw, int queue, u16 max_tx_rate);

int txgbe_hic_notify_led_active(struct txgbe_hw *hw, int active_flag);
bool txgbe_is_backplane(struct txgbe_hw *hw);
bool txgbe_gpio_ext_check(struct txgbe_hw *hw, u8 gpio_ext_mask);

int txgbe_host_interface_command(struct txgbe_hw *hw, u32 *buffer,
				 u32 length, u32 timeout, bool return_data);
int txgbe_is_10g_fiber_sfp(struct txgbe_hw *hw);
void txgbe_ephy_oem_config(struct txgbe_hw *hw, u32 *speed, bool *autoneg);
#endif /* _TXGBE_HW_H_ */
