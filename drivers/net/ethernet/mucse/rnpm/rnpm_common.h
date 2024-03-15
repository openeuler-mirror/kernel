/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2022 - 2023 Mucse Corporation. */

#ifndef _RNPM_COMMON_H_
#define _RNPM_COMMON_H_

#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/highmem.h>
#include "rnpm_type.h"
#include "rnpm.h"
#include "rnpm_regs.h"

struct rnpm_adapter;

void rnpm_free_msix_vectors(struct rnpm_adapter *adapter);
int rnpm_acquire_msix_vectors(struct rnpm_adapter *adapter, int vectors);
s32 rnpm_init_eeprom_params_generic(struct rnpm_hw *hw);
// u16 rnpm_get_pcie_msix_count_generic(struct rnpm_hw *hw);
s32 rnpm_init_ops_generic(struct rnpm_hw *hw);
s32 rnpm_init_hw_generic(struct rnpm_hw *hw);
void rnpm_reset_msix_table_generic(struct rnpm_hw *hw);
s32 rnpm_start_hw_generic(struct rnpm_hw *hw);
s32 rnpm_start_hw_gen2(struct rnpm_hw *hw);
s32 rnpm_clear_hw_cntrs_generic(struct rnpm_hw *hw);
s32 rnpm_read_pba_string_generic(struct rnpm_hw *hw, u8 *pba_num,
				 u32 pba_num_size);
s32 rnpm_get_mac_addr_generic(struct rnpm_hw *hw, u8 *mac_addr);
s32 rnpm_get_permtion_mac_addr(struct rnpm_hw *hw, u8 *mac_addr);
enum rnpm_bus_width rnpm_convert_bus_width(u16 link_status);
enum rnpm_bus_speed rnpm_convert_bus_speed(u16 link_status);
s32 rnpm_get_bus_info_generic(struct rnpm_hw *hw);
void rnpm_set_lan_id_multi_port_pcie(struct rnpm_hw *hw);
s32 rnpm_stop_adapter_generic(struct rnpm_hw *hw);
s32 rnpm_led_on_generic(struct rnpm_hw *hw, u32 index);
s32 rnpm_led_off_generic(struct rnpm_hw *hw, u32 index);
s32 rnpm_init_eeprom_params_generic(struct rnpm_hw *hw);
s32 rnpm_write_eeprom_generic(struct rnpm_hw *hw, u16 offset, u16 data);
s32 rnpm_write_eeprom_buffer_bit_bang_generic(struct rnpm_hw *hw, u16 offset,
					      u16 words, u16 *data);
s32 rnpm_read_eerd_generic(struct rnpm_hw *hw, u16 offset, u16 *data);
s32 rnpm_read_eerd_buffer_generic(struct rnpm_hw *hw, u16 offset, u16 words,
				  u16 *data);
s32 rnpm_write_eewr_generic(struct rnpm_hw *hw, u16 offset, u16 data);
s32 rnpm_write_eewr_buffer_generic(struct rnpm_hw *hw, u16 offset, u16 words,
				   u16 *data);
s32 rnpm_read_eeprom_bit_bang_generic(struct rnpm_hw *hw, u16 offset,
				      u16 *data);
s32 rnpm_read_eeprom_buffer_bit_bang_generic(struct rnpm_hw *hw, u16 offset,
					     u16 words, u16 *data);
u16 rnpm_calc_eeprom_checksum_generic(struct rnpm_hw *hw);
s32 rnpm_validate_eeprom_checksum_generic(struct rnpm_hw *hw,
					  u16 *checksum_val);
s32 rnpm_update_eeprom_checksum_generic(struct rnpm_hw *hw);
s32 rnpm_set_rar_generic(struct rnpm_hw *hw, u32 index, u8 *addr, u32 vmdq,
			 u32 enable_addr);
s32 rnpm_set_rar_mac(struct rnpm_hw *hw, u32 index, u8 *addr, u32 vmdq,
		     u32 port);
s32 rnpm_clear_rar_generic(struct rnpm_hw *hw, u32 index);
s32 rnpm_clear_rar_mac(struct rnpm_hw *hw, u32 index, u32 port);
s32 rnpm_init_rx_addrs_generic(struct rnpm_hw *hw);
s32 rnpm_update_mc_addr_list_generic(struct rnpm_hw *hw,
				     struct net_device *netdev);
s32 rnpm_update_mutiport_mc_addr_list_generic(struct rnpm_hw *hw,
					      struct net_device *netdev);
s32 rnpm_enable_mc_generic(struct rnpm_hw *hw);
s32 rnpm_disable_mc_generic(struct rnpm_hw *hw);
s32 rnpm_disable_rx_buff_generic(struct rnpm_hw *hw);
s32 rnpm_enable_rx_buff_generic(struct rnpm_hw *hw);
s32 rnpm_enable_rx_dma_generic(struct rnpm_hw *hw, u32 regval);
s32 rnpm_fc_enable_generic(struct rnpm_hw *hw);
s32 rnpm_setup_fc(struct rnpm_hw *hw);
bool rnpm_device_supports_autoneg_fc(struct rnpm_hw *hw);
void rnpm_fc_autoneg(struct rnpm_hw *hw);
s32 rnpm_acquire_swfw_sync(struct rnpm_hw *hw, u16 mask);
void rnpm_release_swfw_sync(struct rnpm_hw *hw, u16 mask);
s32 rnpm_get_san_mac_addr_generic(struct rnpm_hw *hw, u8 *san_mac_addr);
s32 rnpm_set_vmdq_generic(struct rnpm_hw *hw, u32 rar, u32 vmdq);
s32 rnpm_set_vmdq_san_mac_generic(struct rnpm_hw *hw, u32 vmdq);
s32 rnpm_clear_vmdq_generic(struct rnpm_hw *hw, u32 rar, u32 vmdq);
s32 rnpm_init_uta_tables_generic(struct rnpm_hw *hw);
s32 rnpm_set_vfta_generic(struct rnpm_hw *hw, u32 vlan, u32 vind, bool vlan_on);
s32 rnpm_set_vfta_mac_generic(struct rnpm_hw *hw, u32 vlan, u32 vind,
			      bool vlan_on);
void rnpm_ncsi_set_mc_mta_generic(struct rnpm_hw *hw);
void rnpm_ncsi_set_vfta_mac_generic(struct rnpm_hw *hw);
void rnpm_ncsi_set_uc_addr_generic(struct rnpm_hw *hw);

s32 rnpm_clear_vfta_generic(struct rnpm_hw *hw);
s32 rnpm_check_mac_link_generic(struct rnpm_hw *hw, rnpm_link_speed *speed,
				bool *link_up, bool link_up_wait_to_complete);
s32 rnpm_get_wwn_prefix_generic(struct rnpm_hw *hw, u16 *wwnn_prefix,
				u16 *wwpn_prefix);
s32 rnpm_blink_led_start_generic(struct rnpm_hw *hw, u32 index);
s32 rnpm_blink_led_stop_generic(struct rnpm_hw *hw, u32 index);
void rnpm_set_mac_anti_spoofing(struct rnpm_hw *hw, bool enable, int pf);
void rnpm_set_vlan_anti_spoofing(struct rnpm_hw *hw, bool enable, int vf);
s32 rnpm_get_device_caps_generic(struct rnpm_hw *hw, u16 *device_caps);
s32 rnpm_set_fw_drv_ver_generic(struct rnpm_hw *hw, u8 maj, u8 min, u8 build,
				u8 ver);
void rnpm_clear_tx_pending(struct rnpm_hw *hw);
void rnpm_set_rxpba_generic(struct rnpm_hw *hw, int num_pb, u32 headroom,
			    int strategy);
s32 rnpm_reset_pipeline_82599(struct rnpm_hw *hw);

s32 rnpm_get_thermal_sensor_data_generic(struct rnpm_hw *hw);
s32 rnpm_init_thermal_sensor_thresh_generic(struct rnpm_hw *hw);

/*================= registers  read/write helper ===== */
#define p_rnpm_wr_reg(reg, val)                                                \
	do {                                                                   \
		printk(KERN_DEBUG "wr-reg: %p <== 0x%08x \t#%-4d %s\n", (reg), \
		       (val), __LINE__, __FILE__);                             \
		iowrite32((val), (void *)(reg));                               \
	} while (0)

static inline int prnp_rd_reg(void *reg)
{
	int v = ioread32((void *)(reg));

	printk(KERN_DEBUG "rd-reg: %p ==> 0x%08x\n", reg, v);
	return v;
}

#ifdef IO_PRINT
static inline unsigned int rnpm_rd_reg(void *reg)
{
	unsigned int v = ioread32((void *)(reg));

	printk(KERN_DEBUG "rd-reg: %p ==> 0x%08x\n", reg, v);
	return v;
}

#define rnpm_wr_reg(reg, val)                                                  \
	do {                                                                   \
		printk(KERN_DEBUG "wr-reg: %p <== 0x%08x \t#%-4d %s\n", (reg), \
		       (val), __LINE__, __FILE__);                             \
		iowrite32((val), (void *)(reg));                               \
	} while (0)
#else
#define rnpm_rd_reg(reg) readl((void *)(reg))
#define rnpm_wr_reg(reg, val) writel((val), (void *)(reg))
#endif

#define rd32(hw, off) rnpm_rd_reg((hw)->hw_addr + (off))
#define wr32(hw, off, val) rnpm_wr_reg((hw)->hw_addr + (off), (val))

#define ring_rd32(ring, off) rnpm_rd_reg((ring)->dma_hw_addr + (off))
#define ring_wr32(ring, off, val) rnpm_wr_reg((ring)->dma_hw_addr + (off), val)

#define pwr32(hw, off, val) p_rnpm_wr_reg((hw)->hw_addr + (off), (val))
#define rnpm_mbx_rd(hw, off) rnpm_rd_reg((hw)->ring_msix_base + (off))
#define rnpm_mbx_wr(hw, off, val) rnpm_wr_reg((hw)->ring_msix_base + (off), val)

static inline void hw_queue_strip_rx_vlan(struct rnpm_hw *hw, u8 ring_num,
					  bool enable)
{
	u32 reg = RNPM_ETH_VLAN_VME_REG(ring_num / 32);
	u32 offset = ring_num % 32;
	u32 data = rd32(hw, reg);

	if (enable == true)
		data |= (1 << offset);
	else
		data &= ~(1 << offset);
	wr32(hw, reg, data);
}

#define rnpm_set_reg_bit(hw, reg_def, bit)                                     \
	do {                                                                   \
		u32 reg = reg_def;                                             \
		u32 value = rd32(hw, reg);                                     \
		dbg("before set  %x %x\n", reg, value);                        \
		value |= (0x01 << bit);                                        \
		dbg("after set %x %x\n", reg, value);                          \
		wr32(hw, reg, value);                                          \
	} while (0)

#define rnpm_clr_reg_bit(hw, reg_def, bit)                                     \
	do {                                                                   \
		u32 reg = reg_def;                                             \
		u32 value = rd32(hw, reg);                                     \
		dbg("before clr %x %x\n", reg, value);                         \
		value &= (~(0x01 << bit));                                     \
		dbg("after clr %x %x\n", reg, value);                          \
		wr32(hw, reg, value);                                          \
	} while (0)

#define rnpm_vlan_filter_on(hw)                                                \
	rnpm_set_reg_bit(hw, RNPM_ETH_VLAN_FILTER_ENABLE, 30)
#define rnpm_vlan_filter_off(hw)                                               \
	rnpm_clr_reg_bit(hw, RNPM_ETH_VLAN_FILTER_ENABLE, 30)

#define DPRINTK(nlevel, klevel, fmt, args...)                                  \
	((NETIF_MSG_##nlevel & adapter->msg_enable) ?                          \
		 (void)(netdev_printk(KERN_##klevel, adapter->netdev, fmt,     \
				      ##args)) :                               \
		 NULL)

//==== log helper ===
#ifdef HW_DEBUG
#define hw_dbg(hw, fmt, args...) printk(KERN_DEBUG "hw-dbg : " fmt, ##args)
#else
#define hw_dbg(hw, fmt, args...)
#endif

#ifdef PTP_DEBUG
#define ptp_dbg(fmt, args...) printk(KERN_DEBUG "ptp-dbg : " fmt, ##args)
#else
#define ptp_dbg(fmt, args...)
#endif

//	netdev_dbg(((struct rnpm_adapter *)((hw)->back))->netdev, format, ##arg)
#ifdef RNP_DEBUG_OPEN
#define rnpm_dbg(fmt, args...) printk(KERN_DEBUG fmt, ##args)
#else
#define rnpm_dbg(fmt, args...)
#endif

#define rnpm_info(fmt, args...) printk(KERN_DEBUG "rnpm-info: " fmt, ##args)
#define rnpm_warn(fmt, args...) printk(KERN_DEBUG "rnpm-warn: " fmt, ##args)
#define rnpm_err(fmt, args...) printk(KERN_DEBUG "rnpm-err : " fmt, ##args)

#define e_info(msglvl, format, arg...)                                         \
	netif_info(adapter, msglvl, adapter->netdev, format, ##arg)
#define e_err(msglvl, format, arg...)                                          \
	netif_err(adapter, msglvl, adapter->netdev, format, ##arg)
#define e_warn(msglvl, format, arg...)                                         \
	netif_warn(adapter, msglvl, adapter->netdev, format, ##arg)
#define e_crit(msglvl, format, arg...)                                         \
	netif_crit(adapter, msglvl, adapter->netdev, format, ##arg)

#define e_dev_info(format, arg...) dev_info(&adapter->pdev->dev, format, ##arg)
#define e_dev_warn(format, arg...) dev_warn(&adapter->pdev->dev, format, ##arg)
#define e_dev_err(format, arg...) dev_err(&adapter->pdev->dev, format, ##arg)

#ifdef CONFIG_RNPM_TX_DEBUG
static inline void buf_dump_line(const char *msg, int line, void *buf, int len)
{
	int i, offset = 0;
	int msg_len = 1024;
	u8 msg_buf[1024];
	u8 *ptr = (u8 *)buf;

	offset += snprintf(msg_buf + offset, msg_len,
			   "=== %s #%d line:%d buf:%p==\n000: ", msg, len, line,
			   buf);
	for (i = 0; i < len; ++i) {
		if ((i != 0) && (i % 16) == 0 && (offset >= (1024 - 10 * 16))) {
			printk(KERN_DEBUG "%s\n", msg_buf);
			offset = 0;
		}
		if ((i != 0) && (i % 16) == 0)
			offset += snprintf(msg_buf + offset, msg_len,
					   "\n%03x: ", i);

		offset += snprintf(msg_buf + offset, msg_len, "%02x ", ptr[i]);
	}

	offset += snprintf(msg_buf + offset, msg_len, "\n");
	printk(KERN_DEBUG "%s\n", msg_buf);
}
#else
#define buf_dump_line(msg, line, buf, len)
#endif

static inline void buf_dump(const char *msg, void *buf, int len)
{
	int i, offset = 0;
	int msg_len = 512;
	u8 msg_buf[512];
	u8 *ptr = (u8 *)buf;

	offset += snprintf(msg_buf + offset, msg_len,
			   "=== %s #%d ==\n000: ", msg, len);

	for (i = 0; i < len; ++i) {
		if ((i != 0) && (i % 16) == 0 && (offset >= (512 - 10 * 16))) {
			printk(KERN_DEBUG "%s\n", msg_buf);
			offset = 0;
		}
		if ((i != 0) && (i % 16) == 0)
			offset += snprintf(msg_buf + offset, msg_len,
					   "\n%03x: ", i);

		offset += snprintf(msg_buf + offset, msg_len, "%02x ", ptr[i]);
	}
	offset += snprintf(msg_buf + offset, msg_len, "\n=== done ==\n");
	printk(KERN_DEBUG "%s\n", msg_buf);
}

#ifdef CONFIG_RNPM_TX_DEBUG
static inline void _rnpm_skb_dump(const struct sk_buff *skb, bool full_pkt)
{
	static atomic_t can_dump_full = ATOMIC_INIT(5);
	struct skb_shared_info *sh = skb_shinfo(skb);
	struct net_device *dev = skb->dev;
	struct sock *sk = skb->sk;
	struct sk_buff *list_skb;
	bool has_mac, has_trans;
	int headroom, tailroom;
	int i, len, seg_len;
	const char *level = KERN_WARNING;

	if (full_pkt)
		full_pkt = atomic_dec_if_positive(&can_dump_full) >= 0;

	if (full_pkt)
		len = skb->len;
	else
		len = min_t(int, skb->len, MAX_HEADER + 128);

	headroom = skb_headroom(skb);
	tailroom = skb_tailroom(skb);

	has_mac = skb_mac_header_was_set(skb);
	has_trans = skb_transport_header_was_set(skb);

	printk(KERN_DEBUG
	       "%sskb len=%u headroom=%u headlen=%u tailroom=%u\n"
	       "mac=(%d,%d) net=(%d,%d) trans=%d\n"
	       "shinfo(txflags=%u nr_frags=%u gso(size=%hu type=%u segs=%hu))\n"
	       "csum(0x%x ip_summed=%u complete_sw=%u valid=%u level=%u)\n"
	       "hash(0x%x sw=%u l4=%u) proto=0x%04x pkttype=%u iif=%d\n",
	       level, skb->len, headroom, skb_headlen(skb), tailroom,
	       has_mac ? skb->mac_header : -1,
	       has_mac ? (skb->network_header - skb->mac_header) : -1,
	       skb->network_header,
	       has_trans ? skb_network_header_len(skb) : -1,
	       has_trans ? skb->transport_header : -1, sh->tx_flags,
	       sh->nr_frags, sh->gso_size, sh->gso_type, sh->gso_segs,
	       skb->csum, skb->ip_summed, skb->csum_complete_sw,
	       skb->csum_valid, skb->csum_level, skb->hash, skb->sw_hash,
	       skb->l4_hash, ntohs(skb->protocol), skb->pkt_type, skb->skb_iif);

	if (dev)
		printk(KERN_DEBUG "%sdev name=%s feat=0x%pNF\n", level,
		       dev->name, &dev->features);

	seg_len = min_t(int, skb_headlen(skb), len);
	if (seg_len)
		print_hex_dump(level, "skb linear:   ", DUMP_PREFIX_OFFSET, 16,
			       1, skb->data, seg_len, false);
	len -= seg_len;

	for (i = 0; len && i < skb_shinfo(skb)->nr_frags; i++) {
		skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
		u32 p_off, p_len, copied;
		struct page *p;
		u8 *vaddr;

		p = skb_frag_address(frag);
		p_len = skb_frag_size(frag);
		seg_len = min_t(int, p_len, len);
		vaddr = kmap_atomic(p);
		print_hex_dump(level, "skb frag:     ", DUMP_PREFIX_OFFSET, 16,
			       1, vaddr, seg_len, false);
		kunmap_atomic(vaddr);
		len -= seg_len;
		if (!len)
			break;
	}

	if (full_pkt && skb_has_frag_list(skb)) {
		printk(KERN_DEBUG "skb fraglist:\n");
		skb_walk_frags(skb, list_skb) _rnpm_skb_dump(list_skb, true);
	}
}
#endif
#define TRACE() printk(KERN_DEBUG "==[ %s %d ] ==\n", __func__, __LINE__)

#ifdef CONFIG_RNPM_RX_DEBUG
#define rx_debug_printk printk
#define rx_buf_dump buf_dump
#define rx_dbg(fmt, args...)                                                   \
	printk(KERN_DEBUG "KERN_DEBUG [ %s:%d ] " fmt, __func__, __LINE__,     \
	       ##args)
#else /* CONFIG_RNPM_RX_DEBUG */
#define rx_debug_printk(fmt, args...)
#define rx_buf_dump(a, b, c)
#define rx_dbg(fmt, args...)
#endif /* CONFIG_RNPM_RX_DEBUG */

#ifdef CONFIG_RNPM_TX_DEBUG
#define desc_hex_dump(msg, buf, len)                                           \
	print_hex_dump(KERN_DEBUG, msg, DUMP_PREFIX_OFFSET, 16, 1, (buf),      \
		       (len), false)
#define rnpm_skb_dump _rnpm_skb_dump
#define tx_dbg(fmt, args...)                                                   \
	printk(KERN_DEBUG "KERN_DEBUG [ %s:%d ] " fmt, __func__, __LINE__,     \
	       ##args)
#else /* CONFIG_RNPM_TX_DEBUG */
#define desc_hex_dump(msg, buf, len)
#define rnpm_skb_dump(skb, full_pkt)
#define tx_dbg(fmt, args...)
#endif /* CONFIG_RNPM_TX_DEBUG */

#ifdef DEBUG
#define dbg(fmt, args...)                                                      \
	printk(KERN_DEBUG "[ %s:%d ] " fmt, __func__, __LINE__, ##args)
#else
#define dbg(fmt, args...)                                                      \
	do {                                                                   \
	} while (0)
#endif

#ifdef DEBUG_DRECTION
#define drection_dbg(fmt, arg...)                                              \
	printk(KERN_DEBUG "[ %s:%d ] " fmt, __func__, __LINE__, ##args)
#else
#define drection_dbg(fmt, arg...)
#endif

enum RNP_LOG_EVT {
	LOG_MBX_IN,
	LOG_MBX_OUT,
	LOG_MBX_MSG_IN,
	LOG_MBX_MSG_OUT,
	LOG_LINK_EVENT,
	LOG_ADPT_STAT,
	LOG_MBX_ABLI,
	LOG_MBX_LINK_STAT,
	LOG_MBX_IFUP_DOWN,
	LOG_FUNC_ENTER,
	LOG_SET_LANE_FUN,
	LOG_PTP_EVT,
	LOG_MBX_REQ,
	LOG_MBX_LOCK,
	LOG_ETHTOOL,
	LOG_PHY,
};

extern unsigned int rnpm_loglevel;

#define rnpm_logd(evt, fmt, args...)                                           \
	do {                                                                   \
		if (BIT(evt) & rnpm_loglevel)                                  \
			printk(KERN_DEBUG fmt, ##args);                        \
	} while (0)

#define rnpm_logd_level(bit) ((1 << (bit)) & rnpm_loglevel)

static inline u64 rnpm_recalculate_err_pkts(u64 now, u64 *init, bool is_u64)
{
	u64 data = 0;

	if (now >= *init)
		data = now - *init;
	else
		data = is_u64 ? (u64)-1 - *init + now : (u32)-1 - *init + now;
	*init = now;

	return data;
}

static inline uint32_t rnpm_vid_crc32_le(uint16_t vid_le)
{
	uint8_t *data = (unsigned char *)&vid_le;
	uint8_t data_byte = 0;
	uint32_t crc = ~0x0;
	uint32_t temp = 0;
	int i, bits;
#define RNPM_VLAN_VID_MASK (0x0fff)

	bits = get_bitmask_order(RNPM_VLAN_VID_MASK);
	for (i = 0; i < bits; i++) {
		if ((i % 8) == 0)
			data_byte = data[i / 8];

		temp = ((crc & 1) ^ data_byte) & 1;
		crc >>= 1;
		data_byte >>= 1;

		if (temp)
			crc ^= 0xedb88320;
	}

	return crc;
}

#endif /* RNPM_COMMON */
