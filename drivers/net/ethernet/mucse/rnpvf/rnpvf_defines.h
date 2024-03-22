/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2022 - 2024 Mucse Corporation. */

#ifndef _RNPVF_DEFINES_H_
#define _RNPVF_DEFINES_H_
#include <linux/skbuff.h>
#include <linux/highmem.h>
/* Device IDs */
#define RNP_DEV_ID_N10_PF0_VF 0x8001
#define RNP_DEV_ID_N10_PF1_VF 0x8002
#define RNP_DEV_ID_N10_PF0_VF_N 0x1010
#define RNP_DEV_ID_N10_PF1_VF_N 0x1011
#define RNP_VF_IRQ_CLEAR_MASK 7
#define RNP_VF_MAX_TX_QUEUES 8
#define RNP_VF_MAX_RX_QUEUES 8

/* DCB define */
#define RNP_VF_MAX_TRAFFIC_CLASS 8

/* Link speed */
typedef u32 rnp_link_speed;
#define RNP_LINK_SPEED_UNKNOWN 0
#define RNP_LINK_SPEED_10_FULL BIT(2)
#define RNP_LINK_SPEED_100_FULL BIT(3)
#define RNP_LINK_SPEED_1GB_FULL BIT(4)
#define RNP_LINK_SPEED_10GB_FULL BIT(5)
#define RNP_LINK_SPEED_40GB_FULL BIT(6)
#define RNP_LINK_SPEED_25GB_FULL BIT(7)
#define RNP_LINK_SPEED_50GB_FULL BIT(8)
#define RNP_LINK_SPEED_100GB_FULL BIT(9)
#define RNP_LINK_SPEED_10_HALF BIT(10)
#define RNP_LINK_SPEED_100_HALF BIT(11)
#define RNP_LINK_SPEED_1GB_HALF BIT(12)
#define RNP_SFP_MODE_10G_LR BIT(13)
#define RNP_SFP_MODE_10G_SR BIT(14)
#define RNP_SFP_MODE_10G_LRM BIT(15)
#define RNP_SFP_MODE_1G_T BIT(16)
#define RNP_SFP_MODE_1G_KX BIT(17)
#define RNP_SFP_MODE_1G_SX BIT(18)
#define RNP_SFP_MODE_1G_LX BIT(19)
#define RNP_SFP_MODE_40G_SR4 BIT(20)
#define RNP_SFP_MODE_40G_CR4 BIT(21)
#define RNP_SFP_MODE_40G_LR4 BIT(22)
#define RNP_SFP_MODE_1G_CX BIT(23)

/* Number of Transmit and Receive Descriptors must be a multiple of 8 */
#define RNP_REQ_TX_DESCRIPTOR_MULTIPLE 8
#define RNP_REQ_RX_DESCRIPTOR_MULTIPLE 8
#define RNP_REQ_TX_BUFFER_GRANULARITY 1024

/* Interrupt Vector Allocation Registers */
#define RNP_IVAR_ALLOC_VAL 0x80 /* Interrupt Allocation valid */

#define RNP_VF_INIT_TIMEOUT 200 /* Number of retries to clear RSTI */

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
#define RNP_TXD_FLAGS_VLAN_PRIO_MASK 0xe000
#define RNP_TX_FLAGS_VLAN_PRIO_SHIFT 13
#define RNP_TX_FLAGS_VLAN_CFI_SHIFT 12

	__le16 cmd;
#define RNP_TXD_VLAN_VALID (0x1 << 15)
#define RNP_TXD_SVLAN_TYPE (0x1 << 14)
#define RNP_TXD_VLAN_CTRL_NOP (0x00 << 13)
#define RNP_TXD_VLAN_CTRL_RM_VLAN (0x01 << 13)
#define RNP_TXD_VLAN_CTRL_INSERT_VLAN (0x02 << 13)
#define RNP_TXD_L4_CSUM (0x1 << 12) /* udp tcp sctp csum */
#define RNP_TXD_IP_CSUM (0x1 << 11)
#define RNP_TXD_TUNNEL_MASK (0x3000000)
#define RNP_TXD_TUNNEL_VXLAN (0x01 << 8)
#define RNP_TXD_TUNNEL_NVGRE (0x02 << 8)
#define RNP_TXD_L4_TYPE_UDP (0x03 << 6)
#define RNP_TXD_L4_TYPE_TCP (0x01 << 6)
#define RNP_TXD_L4_TYPE_SCTP (0x02 << 6)
#define RNP_TXD_FLAG_IPV4 (0 << 5)
#define RNP_TXD_FLAG_IPV6 (0x1 << 5)
#define RNP_TXD_FLAG_TSO (0x1 << 4)
#define RNP_TXD_CMD_RS (0x1 << 2)
#define RNP_TXD_STAT_DD (0x1 << 1)
#define RNP_TXD_CMD_EOP (0x1 << 0)
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
	__le32 res;
	__le16 rev1;
	__le16 cmd;
#define RNP_TXD_FLAG_TO_RPU (0x1 << 15)
#define RNP_TXD_SMAC_CTRL_NOP (0x00 << 12)
#define RNP_TXD_SMAC_CTRL_REPLACE_MACADDR0 (0x02 << 12)
#define RNP_TXD_SMAC_CTRL_REPLACE_MACADDR1 (0bx06 << 12)
#define RNP_TXD_CTX_VLAN_CTRL_NOP (0x00 << 10)
#define RNP_TXD_CTX_VLAN_CTRL_RM_VLAN (0x01 << 10)
#define RNP_TXD_CTX_VLAN_CTRL_INSERT_VLAN (0x02 << 10)
#define RNP_TXD_MTI_CRC_PAD_CTRL (0x01000000)
#define RNP_TXD_CTX_CTRL_DESC (0x1 << 3)
#define RNP_TXD_CTX_CMD_RS (0x1 << 2)
#define RNP_TXD_STAT_DD (0x1 << 1)
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
		__le16 cmd;
#define RNP_RXD_FLAG_RS (0x1 << 2)
	};

	struct {
		__le32 rss_hash;
		__le16 mark;
		__le16 rev1;
#define RNP_RX_L3_TYPE_MASK (0x1 << 15) /* 1 is ipv4 */
#define VEB_VF_PKG (0x1 << 0) /* bit 48 */
#define VEB_VF_IGNORE_VLAN (0x1 << 1) /* bit 49 */
		__le16 len;
		__le16 padding_len;
		__le16 vlan;
		__le16 cmd;
#define RNP_RXD_STAT_VLAN_VALID (0x1 << 15)
#define RNP_RXD_STAT_STAG (0x01 << 14)
#define RNP_RXD_STAT_TUNNEL_NVGRE (0x02 << 13)
#define RNP_RXD_STAT_TUNNEL_VXLAN (0x01 << 13)
#define RNP_RXD_STAT_ERR_MASK (0x1f << 8)
#define RNP_RXD_STAT_TUNNEL_MASK (0x03 << 13)
#define RNP_RXD_STAT_SCTP_MASK (0x04 << 8)
#define RNP_RXD_STAT_L4_MASK (0x02 << 8)
#define RNP_RXD_STAT_ERR_MASK_NOSCTP (0x1b << 8)
#define RNP_RXD_STAT_L4_SCTP (0x02 << 6)
#define RNP_RXD_STAT_L4_TCP (0x01 << 6)
#define RNP_RXD_STAT_L4_UDP (0x03 << 6)
#define RNP_RXD_STAT_IPV6 (0x1 << 5)
#define RNP_RXD_STAT_IPV4 (0x0 << 5)
#define RNP_RXD_STAT_PTP (0x1 << 4)
#define RNP_RXD_STAT_DD (0x1 << 1)
#define RNP_RXD_STAT_EOP (0x1 << 0)
	} wb;
} __packed;

/* Interrupt register bitmasks */
#define RNP_EITR_CNT_WDIS 0x80000000
#define RNP_MAX_EITR 0x00000FF8
#define RNP_MIN_EITR 8

/* Error Codes */
#define RNP_ERR_INVALID_MAC_ADDR -1
#define RNP_ERR_RESET_FAILED -2
#define RNP_ERR_INVALID_ARGUMENT -3

#ifdef DEBUG
#define dbg(fmt, args...) \
	printk(KERN_DEBUG "[ %s:%d ] " fmt, __func__, __LINE__, ##args)
#else
#define dbg(fmt, args...)
#endif

#define rnpvf_dbg(fmt, args...) printk(KERN_DEBUG fmt, ##args)
#define rnpvf_info(fmt, args...) \
	printk(KERN_DEBUG "rnpvf-info: " fmt, ##args)
#define rnpvf_warn(fmt, args...) \
	printk(KERN_DEBUG "rnpvf-warn: " fmt, ##args)
#define rnpvf_err(fmt, args...) printk(KERN_ERR "rnpvf-err : " fmt, ##args)

#define DPRINTK(nlevel, klevel, fmt, args...)                         \
	((NETIF_MSG_##nlevel & adapter->msg_enable) ?                 \
		 (void)(netdev_printk(KERN_##klevel, adapter->netdev, \
				      fmt, ##args)) :                 \
		 NULL)

#ifdef CONFIG_RNP_TX_DEBUG
static inline void buf_dump_line(const char *msg, int line, void *buf,
				 int len)
{
	int i, offset = 0;
	int msg_len = 1024;
	//u8 msg_buf[msg_len];
	u8 msg_buf[1024];
	u8 *ptr = (u8 *)buf;

	offset += snprintf(msg_buf + offset, msg_len,
			   "=== %s #%d line:%d buf:%p==\n000: ", msg, len,
			   line, buf);

	for (i = 0; i < len; ++i) {
		if (i != 0 && (i % 16) == 0 &&
		    (offset >= (1024 - 10 * 16))) {
			printk("%s\n", msg_buf);
			offset = 0;
		}

		if (i != 0 && (i % 16) == 0) {
			offset += snprintf(msg_buf + offset, msg_len,
					   "\n%03x: ", i);
		}
		offset += snprintf(msg_buf + offset, msg_len, "%02x ",
				   ptr[i]);
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
		if (i != 0 && (i % 16) == 0 &&
		    (offset >= (1024 - 10 * 16))) {
			printk("%s\n", msg_buf);
			offset = 0;
		}

		if (i != 0 && (i % 16) == 0) {
			offset += snprintf(msg_buf + offset, msg_len,
					   "\n%03x: ", i);
		}
		offset += snprintf(msg_buf + offset, msg_len, "%02x ",
				   ptr[i]);
	}

	offset += snprintf(msg_buf + offset, msg_len, "\n=== done ==\n");
	printk(KERN_DEBUG "%s\n", msg_buf);
}

static inline void _rnp_skb_dump(const struct sk_buff *skb, bool full_pkt)
{
	static atomic_t can_dump_full = ATOMIC_INIT(5);
	struct skb_shared_info *sh = skb_shinfo(skb);
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

	printk(KERN_DEBUG
	       "%sskb len=%u headroom=%u headlen=%u tailroom=%u\n"
	       "mac=(%d,%d) net=(%d,%d) trans=%d\n"
	       "shinfo(txflags=%u nr_frags=%u gso(size=%u type=%u segs=%u))\n"
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
	       skb->l4_hash, ntohs(skb->protocol), skb->pkt_type,
	       skb->skb_iif);

	if (dev)
		printk(KERN_DEBUG "%sdev name=%s feat=0x%pNF\n", level,
		       dev->name, &dev->features);

	seg_len = min_t(int, skb_headlen(skb), len);
	if (seg_len)
		print_hex_dump(level, "skb linear:   ", DUMP_PREFIX_OFFSET,
			       16, 1, skb->data, seg_len, false);
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
		print_hex_dump(level, "skb frag:     ", DUMP_PREFIX_OFFSET,
			       16, 1, vaddr, seg_len, false);
		kunmap_atomic(vaddr);
		len -= seg_len;
		if (!len)
			break;
	}

	if (full_pkt && skb_has_frag_list(skb)) {
		printk(KERN_DEBUG "skb fraglist:\n");
		skb_walk_frags(skb, list_skb)
			_rnp_skb_dump(list_skb, true);
	}
}

#define TRACE() printk(KERN_DEBUG "=[%s] %d == \n", __func__, __LINE__)

#ifdef CONFIG_RNP_TX_DEBUG
#define desc_hex_dump(msg, buf, len)                                 \
	print_hex_dump(KERN_WARNING, msg, DUMP_PREFIX_OFFSET, 16, 1, \
		       (buf), (len), false)
#define rnpvf_skb_dump _rnp_skb_dump
#else
#define desc_hex_dump(msg, buf, len)
#define rnpvf_skb_dump(skb, full_pkt)
#endif

#ifdef CONFIG_RNP_RX_DEBUG
#define rx_debug_printk printk
#define rx_buf_dump buf_dump
#else
#define rx_debug_printk(fmt, args...)
#define rx_buf_dump(a, b, c)
#endif /* CONFIG_RNP_RX_DEBUG */

#endif /* _RNPVF_DEFINES_H_ */
