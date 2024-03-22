/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2022 - 2024 Mucse Corporation. */

#ifndef _RNPGBEVF_DEFINES_H_
#define _RNPGBEVF_DEFINES_H_
#include <linux/skbuff.h>
#include <linux/highmem.h>

#define RNPGBE_VF_IRQ_CLEAR_MASK 7
#define RNPGBE_VF_MAX_TX_QUEUES 8
#define RNPGBE_VF_MAX_RX_QUEUES 8

/* DCB define */
#define RNPGBE_VF_MAX_TRAFFIC_CLASS 8

/* Link speed */
typedef u32 rnp_link_speed;
#define RNPGBE_LINK_SPEED_UNKNOWN 0
#define RNPGBE_LINK_SPEED_10_FULL BIT(2)
#define RNPGBE_LINK_SPEED_100_FULL BIT(3)
#define RNPGBE_LINK_SPEED_1GB_FULL BIT(4)
#define RNPGBE_LINK_SPEED_10GB_FULL BIT(5)
#define RNPGBE_LINK_SPEED_40GB_FULL BIT(6)
#define RNPGBE_LINK_SPEED_25GB_FULL BIT(7)
#define RNPGBE_LINK_SPEED_50GB_FULL BIT(8)
#define RNPGBE_LINK_SPEED_100GB_FULL BIT(9)
#define RNPGBE_LINK_SPEED_10_HALF BIT(10)
#define RNPGBE_LINK_SPEED_100_HALF BIT(11)
#define RNPGBE_LINK_SPEED_1GB_HALF BIT(12)
#define RNPGBE_SFP_MODE_10G_LR BIT(13)
#define RNPGBE_SFP_MODE_10G_SR BIT(14)
#define RNPGBE_SFP_MODE_10G_LRM BIT(15)
#define RNPGBE_SFP_MODE_1G_T BIT(16)
#define RNPGBE_SFP_MODE_1G_KX BIT(17)
#define RNPGBE_SFP_MODE_1G_SX BIT(18)
#define RNPGBE_SFP_MODE_1G_LX BIT(19)
#define RNPGBE_SFP_MODE_40G_SR4 BIT(20)
#define RNPGBE_SFP_MODE_40G_CR4 BIT(21)
#define RNPGBE_SFP_MODE_40G_LR4 BIT(22)
#define RNPGBE_SFP_MODE_1G_CX BIT(23)

/* Number of Transmit and Receive Descriptors must be a multiple of 8 */
#define RNPGBE_REQ_TX_DESCRIPTOR_MULTIPLE 8
#define RNPGBE_REQ_RX_DESCRIPTOR_MULTIPLE 8
#define RNPGBE_REQ_TX_BUFFER_GRANULARITY 1024

/* Interrupt Vector Allocation Registers */
#define RNPGBE_IVAR_ALLOC_VAL 0x80 /* Interrupt Allocation valid */

#define RNPGBE_VF_INIT_TIMEOUT 200 /* Number of retries to clear RSTI */

/* Transmit Descriptor - Advanced */
struct rnp_tx_desc {
	union {
		__le64 pkt_addr; /* Packet buffer address */
		struct {
			__le32 adr_lo;
			__le32 adr_hi;
		};
	};
	__le16 blen;
	union {
		struct {
			__le16 ip_len : 9;
			__le16 mac_len : 7;
		};
		__le16 mac_ip_len; /* used only in  tso & csum */
	};
	__le16 vlan;
#define RNPGBE_TXD_FLAGS_VLAN_PRIO_MASK 0xe000
#define RNPGBE_TX_FLAGS_VLAN_PRIO_SHIFT 13
#define RNPGBE_TX_FLAGS_VLAN_CFI_SHIFT 12

	__le16 cmd;
#define RNPGBE_TXD_VLAN_VALID (0x1 << 15)
#define RNPGBE_TXD_SVLAN_TYPE (0x1 << 9)
#define RNPGBE_TXD_VLAN_CTRL_NOP (0x00 << 13)
#define RNPGBE_TXD_VLAN_CTRL_RM_VLAN (0x01 << 13)
#define RNPGBE_TXD_VLAN_CTRL_INSERT_VLAN (0x02 << 13)
#define RNPGBE_TXD_L4_CSUM (0x1 << 12)
#define RNPGBE_TXD_IP_CSUM (0x1 << 11)
#define RNPGBE_TXD_TUNNEL_MASK (0x3000000)
#define RNPGBE_TXD_TUNNEL_VXLAN (0x01 << 8)
#define RNPGBE_TXD_TUNNEL_NVGRE (0x02 << 8)
#define RNPGBE_TXD_L4_TYPE_UDP (0x03 << 6)
#define RNPGBE_TXD_L4_TYPE_TCP (0x01 << 6)
#define RNPGBE_TXD_L4_TYPE_SCTP (0x02 << 6)
#define RNPGBE_TXD_FLAG_IPV4 (0x0 << 5)
#define RNPGBE_TXD_FLAG_IPV6 (0x1 << 5)
#define RNPGBE_TXD_FLAG_TSO (0x1 << 4)
#define RNPGBE_TXD_CMD_RS (0x1 << 2)
#define RNPGBE_TXD_STAT_DD (0x1 << 1)
#define RNPGBE_TXD_CMD_EOP (0x1 << 0)
} __packed;

struct rnp_tx_ctx_desc {
	__le16 mss_len;
	u8 vfnum;
	u8 l4_hdr_len;
	u8 tunnel_hdr_len;
	__le16 inner_vlan;
	u8 vf_veb_flags;
#define VF_IGNORE_VLAN (0x1 << 1) /* bit 57 */
#define VF_VEB_MARK (0x1 << 0) /* bit 56 */
	u32 rev;
	__le16 rev1;
	__le16 cmd;
#define RNPGBE_TXD_FLAG_TO_RPU (0x1 << 15)
#define RNPGBE_TXD_SMAC_CTRL_NOP (0x00 << 12)
#define RNPGBE_TXD_SMAC_CTRL_REPLACE_MACADDR0 (0x02 << 12)
#define RNPGBE_TXD_SMAC_CTRL_REPLACE_MACADDR1 (0bx06 << 12)
#define RNPGBE_TXD_CTX_VLAN_CTRL_NOP (0x00 << 10)
#define RNPGBE_TXD_CTX_VLAN_CTRL_RM_VLAN (0x01 << 10)
#define RNPGBE_TXD_CTX_VLAN_CTRL_INSERT_VLAN (0x02 << 10)
#define RNPGBE_TXD_MTI_CRC_PAD_CTRL (0x01000000)
#define RNPGBE_TXD_CTX_CTRL_DESC (0x1 << 3)
#define RNPGBE_TXD_CTX_CMD_RS (0x1 << 2)
#define RNPGBE_TXD_STAT_DD (0x1 << 1)
} __packed;

/* Receive Descriptor - Advanced */
union rnp_rx_desc {
	struct {
		union {
			__le64 pkt_addr; /* Packet buffer address */
			struct {
				__le32 addr_lo;
				__le32 addr_hi;
			};
		};
		u8 dumy[6];
		__le16 cmd; /* DD back */
#define RNPGBE_RXD_FLAG_RS (0x1 << 2)
	};

	struct {
		__le32 rss_hash;
		__le16 mark;
		__le16 rev1;
#define RNPGBE_RX_L3_TYPE_MASK (0x1 << 15)
#define VEB_VF_PKG (0x1 << 1)
#define VEB_VF_IGNORE_VLAN (0x1 << 0)
		__le16 len;
		__le16 padding_len;
		__le16 vlan;
		__le16 cmd;
#define RNPGBE_RXD_STAT_VLAN_VALID (0x1 << 15)
#define RNPGBE_RXD_STAT_STAG (0x01 << 14)
#define RNPGBE_RXD_STAT_TUNNEL_NVGRE (0x02 << 13)
#define RNPGBE_RXD_STAT_TUNNEL_VXLAN (0x01 << 13)
#define RNPGBE_RXD_STAT_ERR_MASK (0x1f << 8)
#define RNPGBE_RXD_STAT_TUNNEL_MASK (0x03 << 13)

#define RNPGBE_RXD_STAT_SCTP_MASK (0x04 << 8)
#define RNPGBE_RXD_STAT_L4_MASK (0x02 << 8)
#define RNPGBE_RXD_STAT_ERR_MASK_NOSCTP (0x1b << 8)

#define RNPGBE_RXD_STAT_L4_SCTP (0x02 << 6)
#define RNPGBE_RXD_STAT_L4_TCP (0x01 << 6)
#define RNPGBE_RXD_STAT_L4_UDP (0x03 << 6)
#define RNPGBE_RXD_STAT_IPV6 (0x1 << 5)
#define RNPGBE_RXD_STAT_IPV4 (0 << 5)
#define RNPGBE_RXD_STAT_PTP (0x1 << 4)
#define RNPGBE_RXD_STAT_DD (0x1 << 1)
#define RNPGBE_RXD_STAT_EOP (0x1 << 0)
	} wb;
} __packed;

/* Interrupt register bitmasks */
#define RNPGBE_EITR_CNT_WDIS 0x80000000
#define RNPGBE_MAX_EITR 0x00000FF8
#define RNPGBE_MIN_EITR 8

/* Error Codes */
#define RNPGBE_ERR_INVALID_MAC_ADDR -1
#define RNPGBE_ERR_RESET_FAILED -2
#define RNPGBE_ERR_INVALID_ARGUMENT -3

#ifdef DEBUG
#define dbg(fmt, args...)                                                      \
	printk(KERN_DEBUG "[ %s:%d ] " fmt, __func__, __LINE__, ##args)
#else
#define dbg(fmt, args...)
#endif

#define rnpgbevf_dbg(fmt, args...) printk(KERN_DEBUG fmt, ##args)
#define rnpgbevf_info(fmt, args...)                                            \
	printk(KERN_DEBUG "rnpvf-info: " fmt, ##args)
#define rnpgbevf_warn(fmt, args...)                                            \
	printk(KERN_DEBUG "rnpvf-warn: " fmt, ##args)
#define rnpgbevf_err(fmt, args...) printk(KERN_ERR "rnpvf-err : " fmt, ##args)

#define DPRINTK(nlevel, klevel, fmt, args...)                                  \
	((NETIF_MSG_##nlevel & adapter->msg_enable) ?                          \
		 (void)(netdev_printk(KERN_##klevel, adapter->netdev, fmt,     \
				      ##args)) :                               \
		 NULL)

#ifdef CONFIG_RNPGBE_TX_DEBUG
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
		if (i != 0 && (i % 16) == 0 && (offset >= (1024 - 10 * 16))) {
			printk(KERN_DEBUG "%s\n", msg_buf);
			offset = 0;
		}

		if (i != 0 && (i % 16) == 0) {
			offset += snprintf(msg_buf + offset, msg_len,
					   "\n%03x: ", i);
		}
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
	int msg_len = 1024;
	u8 msg_buf[1024];
	u8 *ptr = (u8 *)buf;

	offset += snprintf(msg_buf + offset, msg_len,
			   "=== %s #%d ==\n000: ", msg, len);

	for (i = 0; i < len; ++i) {
		if (i != 0 && (i % 16) == 0 && (offset >= (1024 - 10 * 16))) {
			printk(KERN_DEBUG "%s\n", msg_buf);
			offset = 0;
		}

		if (i != 0 && (i % 16) == 0) {
			offset += snprintf(msg_buf + offset, msg_len,
					   "\n%03x: ", i);
		}
		offset += snprintf(msg_buf + offset, msg_len, "%02x ", ptr[i]);
	}

	offset += snprintf(msg_buf + offset, msg_len, "\n=== done ==\n");
	printk(KERN_DEBUG "%s\n", msg_buf);
}

#ifndef NO_SKB_DUMP
static inline void _rnp_skb_dump(const struct sk_buff *skb, bool full_pkt)
{
	static atomic_t can_dump_full = ATOMIC_INIT(5);
	struct net_device *dev = skb->dev;
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
		u32 p_len;
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
		skb_walk_frags(skb, list_skb) _rnp_skb_dump(list_skb, true);
	}
}
#endif

#define TRACE() printk(KERN_DEBUG "=[%s] %d == \n", __func__, __LINE__)

#ifdef CONFIG_RNPGBE_TX_DEBUG
#define desc_hex_dump(msg, buf, len)                                           \
	print_hex_dump(KERN_WARNING, msg, DUMP_PREFIX_OFFSET, 16, 1, (buf),    \
		       (len), false)
#define rnpgbevf_skb_dump _rnp_skb_dump
#else
#define desc_hex_dump(msg, buf, len)
#define rnpgbevf_skb_dump(skb, full_pkt)
#endif

#ifdef CONFIG_RNPGBE_RX_DEBUG
#define rx_debug_printk printk
#define rx_buf_dump buf_dump
#else
#define rx_debug_printk(fmt, args...)
#define rx_buf_dump(a, b, c)
#endif

#endif /* _RNPGBEVF_DEFINES_H_ */
