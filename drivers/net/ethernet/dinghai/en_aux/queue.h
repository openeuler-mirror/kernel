/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef __ZXDH_QUEUE_H__
#define __ZXDH_QUEUE_H__
#include <linux/netdevice.h>
#include <linux/filter.h>
#include <linux/average.h>
#include <linux/mm_types_task.h>
#include <linux/compiler.h>
#include <linux/bpf.h>
#include <linux/bpf_trace.h>
#include <net/xdp.h>
#include <linux/printk.h>
#include <linux/dinghai/queue.h>
#include <linux/dinghai/zxdh_compat.h>
#include <linux/dinghai/driver.h>

#define ZXDH_CONFIG_SPECIAL_SQ_EN

#define CHECK_EQUAL_ERR(a, b, c, fmt, arg...) \
	do {                                  \
		if (unlikely(a == b)) {       \
			LOG_ERR(fmt, ##arg);  \
			return c;             \
		}                             \
	} while (0)

#define CHECK_UNEQUAL_ERR(a, b, c, fmt, arg...) \
	do {                                    \
		if (unlikely(a != b)) {         \
			LOG_ERR(fmt, ##arg);    \
			return c;               \
		}                               \
	} while (0)

#define ZXDH_MQ_PAIRS_NUM 8
#define ZXDH_PQ_PAIRS_NUM 1
#define ZXDH_MAX_PAIRS_NUM 128
#define ZXDH_BOND_ETH_MQ_PAIRS_NUM 1
#define ZXDH_MAX_QUEUES_NUM 4096
#define ZXDH_SEC_QUEUES_NUM(en_dev) \
	(((256 - en_dev->max_queue_pairs * 2) >= 128) ? 128 : (256 - en_dev->max_queue_pairs * 2))
#define ZXDH_PF_MAX_BAR_VAL 0x5
#define ZXDH_PF_BAR0 0
#define ZXDH_PF_MAX_DESC_NUM(en_dev) ((en_dev->board_type == DH_INICD) ? 1024 : (16 * 1024))
#define ZXDH_PF_DEFAULT_DESC_NUM(en_dev) ((en_dev->board_type == DH_INICD) ? 1024 : (8 * 1024))
#define ZXDH_PF_MIN_DESC_NUM (64)
#define ZXDH_SEC_MIN_DESC_NUM 1024
#define ZXDH_INDIR_RQT_SIZE 256
#define ZXDH_NET_HASH_KEY_SIZE 40
#define ZXDH_HAS_PI_FLAG 19 //38B, 2B unit, consider the receiving scenario of max 1588 packet
#define ZXDH_TYPE_FLAG_LEN 2
#define ZXDH_DESC_EXTRA_SIZE 512

#define VQM_HOST_BAR_OFFSET 0x0
#define ZXDH_VQ_TLB_OFFSET 0x1bf8
#define PHY_VQ_REG_OFFSET 0x5000
#define LOCK_VQ_REG_OFFSET 0x90
#define ZXDH_PHY_REG_BITS 32
#define ZXDH_PF_LOCK_ENABLE_MASK 0x1
#define ZXDH_PF_RELEASE_LOCK_VAL 0
#define ZXDH_PF_GET_PHY_INDEX_DONE 1
#define ZXDH_PF_GET_PHY_INDEX_BIT 1
#define ZXDH_PF_WAIT_COUNT 6000
#define ZXDH_PF_DELAY_US 100
#define ZXDH_PF_RQ_TYPE 0
#define ZXDH_PF_TQ_TYPE 1
#define ZXDH_PF_POWER_INDEX2 2

#define MSG_PAYLOAD_FIX_FIELD 8
#define MSG_CHAN_PF_MODULE_ID 0
#define MSG_PAYLOAD_TYPE_WRITE 1
#define MSG_PAYLOAD_FIELD_MSG_CHL 2
#define MSG_PAYLOAD_FIELD_DATA_CHL 3
#define MSG_PAYLOAD_MSG_CHL_SLEN 4
#define MSG_RECV_BUF_LEN 6

#define ZXDH_MAC_NUM 6
#define ZXDH_MAX_MTU 13500
#define ZXDH_DEFAULT_MTU 1500
#define DH_SKB_FRAG_PAGE_ORDER get_order(32768)
#define DH_BUFF_LEN 2048

/* The feature bitmap for zxdh net */
#define ZXDH_NET_F_CSUM 0 /* Host handles pkts w/ partial csum */
#define ZXDH_NET_F_GUEST_CSUM 1 /* Guest handles pkts w/ partial csum */
#define ZXDH_NET_F_CTRL_GUEST_OFFLOADS 2 /* Dynamic offload configuration. */
#define ZXDH_NET_F_MTU 3 /* Initial MTU advice */
#define ZXDH_NET_F_MAC 5 /* Host has given MAC address. */
#define ZXDH_NET_F_GUEST_TSO4 7 /* Guest can handle TSOv4 in. */
#define ZXDH_NET_F_GUEST_TSO6 8 /* Guest can handle TSOv6 in. */
#define ZXDH_NET_F_GUEST_ECN 9 /* Guest can handle TSO[6] w/ ECN in. */
#define ZXDH_NET_F_GUEST_UFO 10 /* Guest can handle UFO in. */
#define ZXDH_NET_F_HOST_TSO4 11 /* Host can handle TSOv4 in. */
#define ZXDH_NET_F_HOST_TSO6 12 /* Host can handle TSOv6 in. */
#define ZXDH_NET_F_HOST_ECN 13 /* Host can handle TSO[6] w/ ECN in. */
#define ZXDH_NET_F_HOST_UFO 14 /* Host can handle UFO in. */
#define ZXDH_NET_F_MRG_RXBUF 15 /* Host can merge receive buffers. */
#define ZXDH_NET_F_STATUS 16 /* net_config.status available */
#define ZXDH_NET_F_CTRL_VQ 17 /* Control channel available */
#define ZXDH_NET_F_MQ 22 /* Device supports Receive Flow Steering */
#define ZXDH_F_ANY_LAYOUT 27 /* Can the device handle any descriptor layout? */
#define ZXDH_RING_F_INDIRECT_DESC 28 /* We support indirect buffer descriptors */

/* The Guest publishes the used index for which it expects an interrupt
 * at the end of the avail ring. Host should ignore the avail->flags field.
 */
/* The Host publishes the avail index for which it expects a kick
 * at the end of the used ring. Guest should ignore the used->flags field.
 */
#define ZXDH_RING_F_EVENT_IDX 29

#define ZXDH_F_VERSION_1 32 /* v1.0 compliant */

/* If clear - device has the platform DMA (e.g. IOMMU) bypass quirk feature.
 * If set - use platform DMA tools to access the memory.
 *
 * Note the reverse polarity (compared to most other features),
 * this is for compatibility with legacy systems.
 */
#define ZXDH_F_ACCESS_PLATFORM 33

/* This feature indicates support for the packed virtqueue layout. */
#define ZXDH_F_RING_PACKED 34

/* This feature indicates that memory accesses by the driver and the
 * device are ordered in a way described by the platform.
 */
#define ZXDH_F_ORDER_PLATFORM 36

/* This marks a buffer as continuing via the next field. */
#define VRING_DESC_F_NEXT 1
/* This marks a buffer as write-only (otherwise read-only). */
#define VRING_DESC_F_WRITE 2
/* This means the buffer contains a list of buffer descriptors. */
#define VRING_DESC_F_INDIRECT 4

/* Mark a descriptor as available or used in packed ring.
 * Notice: they are defined as shifts instead of shifted values.
 */
#define VRING_PACKED_DESC_F_AVAIL 7
#define VRING_PACKED_DESC_F_USED 15

/* The Host uses this in used->flags to advise the Guest: don't kick me when
 * you add a buffer.  It's unreliable, so it's simply an optimization.  Guest
 * will still kick if it's out of buffers.
 */
#define VRING_USED_F_NO_NOTIFY 1
/* The Guest uses this in avail->flags to advise the Host: don't interrupt me
 * when you consume a buffer.  It's unreliable, so it's simply an
 * optimization.
 */
#define VRING_AVAIL_F_NO_INTERRUPT 1

/* Enable events in packed ring. */
#define VRING_PACKED_EVENT_FLAG_ENABLE 0x0
/* Disable events in packed ring. */
#define VRING_PACKED_EVENT_FLAG_DISABLE 0x1
/* Enable events for a specific descriptor in packed ring.
 * (as specified by Descriptor Ring Change Event Offset/Wrap Counter).
 * Only valid if ZXDH_RING_F_EVENT_IDX has been negotiated.
 */
#define VRING_PACKED_EVENT_FLAG_DESC 0x2

/* Wrap counter bit shift in event suppression structure
 * of packed ring.
 */
#define VRING_PACKED_EVENT_F_WRAP_CTR 15

/* Alignment requirements for vring elements */
#define VRING_AVAIL_ALIGN_SIZE 2
#define VRING_USED_ALIGN_SIZE 4
#define VRING_DESC_ALIGN_SIZE 16

#define MRG_CTX_HEADER_SHIFT 22

/* FIXME: MTU in config. */
#define GOOD_PACKET_LEN (ETH_HLEN + VLAN_HLEN + ETH_DATA_LEN)
#define GOOD_COPY_LEN 128

#define TX_PORT_NP 0x00
#define TX_PORT_DRS 0x01
#define TX_PORT_DTP 0x02
#define HDR_2B_UNIT 2
#define ENABLE_PI_FLAG_32B 0x1
#define DISABLE_PI_FIELD_PARSE 0x80
#define IPV4_TYPE 0x0
#define IPV6_TYPE 0x1
#define NOT_IP_TYPE 0x2
#define PKT_SRC_NP 0x0
#define PKT_SRC_CPU 0x1
#define PCODE_IP 0x1
#define PCODE_TCP 0x2
#define PCODE_UDP 0x3
#define PCODE_NO_IP 0x9
#define INVALID_ETH_PORT_ID 0xff
#define ETH_MTU_4B_UNIT 4
#define IP_FRG_CSUM_FLAG 0x8000
#define NOT_IP_FRG_CSUM_FLAG 0x6000
#define TCP_FRG_CSUM_FLAG 0x24
#define NOT_TCP_FRG_CSUM_FLAG 0x30
#define HDR_2B_UNIT 2

#define HDR_BUFFER_LEN 100
#define IP_BASE_HLEN 20
#define IPV6_BASE_HLEN 40
#define TCP_BASE_HLEN 20

#define OUTER_IP_CHECKSUM_OFFSET (12)
#define INNER_IP_CHECKSUM_OFFSET (15)
#define INNER_L4_CHECKSUM_OFFSET (2)
//#define PI_HDR_L3_CHKSUM_ERROR_CODE (0xff)
//#define PI_HDR_L4_CHKSUM_ERROR_CODE (0xff)
#define OUTER_IP_CHKSUM_ERROR_CODE (0x20)
#define NP_VXLAN_UDP_CHCKSUM_ENABLE (6)
#define NP_IS_VXLAN_FLAG (5)

#define RX_VLAN_STRIPED_MASK (1 << 4)
#define RX_QINQ_STRIPED_MASK (1 << 14)
#define RX_IS_QINQ_PKT_MASK (1 << 12)
#define RX_TPID_VLAN_ID_MASK (0xfff)

/* PD header offload flags */
#define PANELID_EN (1 << 15)
#define LB_EN (1 << 11)

/* PD header sk_prio */
#define ZXDH_DCBNL_SET_SK_PRIO(sk_prio) ((0x7 & sk_prio) << 8)

/* __vqm{16,32,64} have the following meaning:
 * - __u{16,32,64} for zxdh devices in legacy mode, accessed in native endian
 * - __le{16,32,64} for standard-compliant zxdh devices
 */
typedef __u16 __bitwise __vqm16;
typedef __u32 __bitwise __vqm32;
typedef __u64 __bitwise __vqm64;

/* Constants for MSI-X */
/* Use first vector for configuration changes, second and the rest for
 * virtqueues Thus, we need at least 2 vectors for MSI.
 */
enum {
	VP_MSIX_CONFIG_VECTOR = 0,
	VP_MSIX_VQ_VECTOR = 1,
};

struct vring_packed_desc_event {
	/* Descriptor Ring Change Event Offset/Wrap Counter. */
	__le16 off_wrap;
	/* Descriptor Ring Change Event Flags. */
	__le16 flags;
};

struct vring_packed_desc {
	/* Buffer Address. */
	__le64 addr;
	/* Buffer Length. */
	__le32 len;
	/* Buffer ID. */
	__le16 id;
	/* The flags depending on descriptor type. */
	__le16 flags;
};

struct vring_desc_state_packed {
	void *data; /* Data for callback. */
	struct vring_packed_desc *indir_desc; /* Indirect descriptor, if any. */
	u16 num; /* Descriptor list length. */
	u16 last; /* The last desc state in a list. */
};

struct vring_desc_extra {
	dma_addr_t addr; /* Buffer DMA addr. */
	u32 len; /* Buffer length. */
	u16 flags; /* Descriptor flags. */
	u16 next; /* The next desc state in a list. */
};

union pkt_type_t {
	u8 pkt_type;
	struct {
		u8 pkt_code : 5;
		u8 pkt_src : 1;
		u8 ip_type : 2;
	} type_ctx;
} __packed;

struct pi_hdr {
	u8 bttl_pi_len;
	union pkt_type_t pt;
	u16 vlan_id;
	u32 ipv6_exp_flags;
	u16 hdr_l3_offset;
	u16 hdr_l4_offset;
	u8 eth_port_id;
	u8 pkt_action_flag2;
	u16 pkt_action_flag1;
	u8 sa_index[8];
	u8 error_code[2];
	u8 rsv[6];
} __packed;

struct pd_net_hdr_tx {
#define TXCAP_STAG_INSERT_EN_BIT (1 << 14)
#define TXCAP_CTAG_INSERT_EN_BIT (1 << 13)
#define DELAY_STATISTICS_INSERT_EN_BIT (1 << 7)
	u16 ol_flag;
	u8 rsv;
	u8 panel_id;
	u16 stci;
	u16 ctci;
	u8 tag_idx;
	u8 tag_data;
	u16 vfid;
} __packed;

struct pd_net_hdr_rx {
#define RX_PD_HEAD_VLAN_STRIP_BIT (1 << 28)
	u32 flags;
	u32 rss_hash;
	u32 fd;
	u16 striped_stci;
	u16 striped_ctci;
	u16 outer_pkt_type;
	u16 inner_pkt_type;
	u16 pkt_len;
	u8 tag_idx;
	u8 tag_data;
	u16 src_port;
} __packed;

/* zxdh net header */
struct pipd_net_hdr_tx {
	struct pi_hdr pi_hdr; //32B
	struct pd_net_hdr_tx pd_hdr; //12B
} __packed;

struct zxdh_net_hdr_tx {
	u8 tx_port; //bit7:2 rsv; bit1:0 00:np, 01:DRS, 10:DTP
	u8 pd_len;
	u8 num_buffers;
	u8 rsv;

	union {
		struct pd_net_hdr_tx pd_hdr; //12B
		struct pipd_net_hdr_tx pipd_hdr; //44B
	};
} __packed;

struct zxdh_1588_pd_tx {
	u8 ptp_type[3];
	u8 ts_offset;
	u32 cpu_tx;
	u8 port;
	u8 rsv1[4];
	u8 sec_1588_key[3];
};

struct zxdh_net_1588_hdr {
	u8 tx_port; //bit7:2 rsv; bit1:0 00:np, 01:DRS, 10:DTP
	u8 pd_len;
	u8 num_buffers;
	u8 rsv;

	struct pi_hdr pi_hdr;
	struct pd_net_hdr_tx pd_hdr;

	// u8 ts_offset;
	// u32 cpu_tx;

	// u8 rsv1[4];
	// u8 sec_1588_key[3];
	struct zxdh_1588_pd_tx pd_1588;
} __packed;

struct zxdh_net_1588_nopi_hdr {
	u8 tx_port; //bit7:2 rsv; bit1:0 00:np, 01:DRS, 10:DTP
	u8 pd_len;
	u8 num_buffers;
	u8 rsv;

	struct pd_net_hdr_tx pd_hdr;

	// u8 ts_offset;
	// u32 cpu_tx;

	// u8 rsv1[4];
	// u8 sec_1588_key[3];
	struct zxdh_1588_pd_tx pd_1588;
} __packed;

struct pipd_net_hdr_rx {
	struct pi_hdr pi_hdr; //32B
	struct pd_net_hdr_rx pd_hdr; //26B
} __packed;

struct zxdh_net_hdr_rx {
	u8 tx_port; //bit7:2 rsv; bit1:0 00:np, 01:DRS, 10:DTP
	u8 pd_len;
	u8 num_buffers;
	u8 rsv;

	union {
		struct pd_net_hdr_rx pd_hdr; //26B
		struct pipd_net_hdr_rx pipd_hdr; //58B
	};
} __packed;

struct zxdh_1588_pd_rx {
	u8 egress_port;
	u8 ptp_type[2];
	u8 ts_offset;
	u32 rx_ts;
};
struct zxdh_net_1588_hdr_rcv {
	u8 tx_port; //bit7:2 rsv; bit1:0 00:np, 01:DRS, 10:DTP
	u8 pd_len;
	u8 num_buffers;
	u8 rsv;

	struct pi_hdr pi_hdr;
	struct pd_net_hdr_rx pd_hdr;

	// u8 egress_port;

	// u8 ts_offset;
	// u32 rx_ts;
	struct zxdh_1588_pd_rx pd_1588;
} __packed;

struct zxdh_net_1588_nopi_hdr_rcv {
	u8 tx_port; //bit7:2 rsv; bit1:0 00:np, 01:DRS, 10:DTP
	u8 pd_len;
	u8 num_buffers;
	u8 rsv;

	struct pd_net_hdr_rx pd_hdr;

	// u8 egress_port;

	// u8 ts_offset;
	// u32 rx_ts;
	struct zxdh_1588_pd_rx pd_1588;
} __packed;

#ifdef DEBUG
/* For development, we want to crash whenever the ring is screwed. */
#define BAD_RING(_vq, fmt, args...)                         \
	do {                                                \
		LOG_ERR("%s:" fmt, (_vq)->vq.name, ##args); \
		WARN_ON(1);                                      \
	} while (0)
/* Caller is supposed to guarantee no reentry. */
#define START_USE(_vq)		\
	do {					\
		if ((_vq)->in_use)	\
			BAD_RING(_vq, "in_use = %i\n", (_vq)->in_use); \
		(_vq)->in_use = __LINE__;	\
	} while (0)
#define END_USE(_vq)	\
	do {				\
		WARN_ON(!(_vq)->in_use); \
		(_vq)->in_use = 0;      \
	} while (0)
#define LAST_ADD_TIME_UPDATE(_vq)		\
	do {								\
		ktime_t now = ktime_get();		\
										\
		if ((_vq)->last_add_time_valid)	\
			WARN_ON(ktime_to_ms(ktime_sub(now, (_vq)->last_add_time)) > 100); \
		(_vq)->last_add_time = now;			\
		(_vq)->last_add_time_valid = true;	\
	} while (0)
#define LAST_ADD_TIME_CHECK(_vq)	\
	do {							\
		if ((_vq)->last_add_time_valid) {	\
			WARN_ON(ktime_to_ms(ktime_sub(ktime_get(), (_vq)->last_add_time)) > 100); \
		}	\
	} while (0)
#define LAST_ADD_TIME_INVALID(_vq) ((_vq)->last_add_time_valid = false)
#else
#define BAD_RING(_vq, fmt, args...)                         \
	do {                                                \
		LOG_ERR("%s:" fmt, (_vq)->vq.name, ##args); \
		(_vq)->broken = true;                       \
	} while (0)
#define START_USE(vq)
#define END_USE(vq)
#define LAST_ADD_TIME_UPDATE(vq)
#define LAST_ADD_TIME_CHECK(vq)
#define LAST_ADD_TIME_INVALID(vq)
#endif

#define vqm_store_mb(weak_barriers, p, v)                        \
	do {                                                     \
		if (weak_barriers) {                             \
			virt_store_mb(*p, v); /* 内存屏障 */ \
		} else {                                         \
			WRITE_ONCE(*p, v);                       \
			mb(); /* 内存屏障 */                 \
		}                                                \
	} while (0)

/* This is the PCI capability header: */
struct zxdh_pci_cap {
	__u8 cap_vndr; /* Generic PCI field: PCI_CAP_ID_VNDR */
	__u8 cap_next; /* Generic PCI field: next ptr. */
	__u8 cap_len; /* Generic PCI field: capability length */
	__u8 cfg_type; /* Identifies the structure. */
	__u8 bar; /* Where to find it. */
	__u8 id; /* Multiple capabilities of the same type */
	__u8 padding[2]; /* Pad to full dword. */
	__le32 offset; /* Offset within bar. */
	__le32 length; /* Length of the structure, in bytes. */
};

struct zxdh_pci_notify_cap {
	struct zxdh_pci_cap cap;
	__le32 notify_off_multiplier; /* Multiplier for queue_notify_off. */
};

struct virtqueue {
	struct list_head list;
	void (*callback)(struct virtqueue *vq);
	const char *name;
	struct zxdh_en_device *en_dev;
	u32 index;
	u32 phy_index;
	u32 num_free;
	void *priv;
};

/* custom queue ring descriptors: 16 bytes. These can chain together via "next". */
struct vring_desc {
	/* Address (guest-physical). */
	uint64_t addr;
	/* Length. */
	u32 len;
	/* The flags as indicated above. */
	u16 flags;
	/* We chain unused descriptors via this, too */
	u16 next;
};

struct vring_avail {
	u16 flags;
	u16 idx;
	u16 ring[];
};

/* u32 is used here for ids for padding reasons. */
struct vring_used_elem {
	/* Index of start of used descriptor chain. */
	u32 id;
	/* Total length of the descriptor chain which was used (written to) */
	u32 len;
};

struct vring_used_elem __aligned(4);

struct vring_used {
	u16 flags;
	u16 idx;
	struct vring_used_elem __aligned(VRING_USED_ALIGN_SIZE) ring[];
};

struct vring_desc __aligned(16);
struct vring_avail __aligned(2);
struct vring_used __aligned(4);

struct vring {
	u32 num;

	struct vring_desc __aligned(VRING_DESC_ALIGN_SIZE) * desc;

	struct vring_avail __aligned(VRING_AVAIL_ALIGN_SIZE) * avail;

	struct vring_used __aligned(VRING_USED_ALIGN_SIZE) * used;
};

struct vring_virtqueue {
	struct virtqueue vq;

	/* Is this a packed ring? */
	bool packed_ring;

	/* Is DMA API used? */
	bool use_dma_api;

	/* Can we use weak barriers? */
	bool weak_barriers;

	/* Other side has made a mess, don't try any more. */
	bool broken;

	/* Host supports indirect buffers */
	bool indirect;

	/* Host publishes avail event idx */
	bool event;

	/* Head of free buffer list. */
	u32 free_head;
	/* Number we've added since last sync. */
	u32 num_added;

	/* Last used index  we've seen.
	 * for split ring, it just contains last used index
	 * for packed ring:
	 * bits up to VRING_PACKED_EVENT_F_WRAP_CTR include the last used index.
	 * bits from VRING_PACKED_EVENT_F_WRAP_CTR include the used wrap counter.
	 */
	u16 last_used_idx;

	/* Hint for event idx: already triggered no need to disable. */
	bool event_triggered;

	/* Available for packed ring */
	struct {
		/* Actual memory layout for this queue. */
		struct {
			u32 num;
			struct vring_packed_desc *desc;
			struct vring_packed_desc_event *driver;
			struct vring_packed_desc_event *device;
		} vring;

		/* Driver ring wrap counter. */
		bool avail_wrap_counter;

		/* Avail used flags. */
		u16 avail_used_flags;

		/* Index of the next avail descriptor. */
		u16 next_avail_idx;

		/* Last written value to driver->flags in
		 * guest byte order.
		 */
		u16 event_flags_shadow;

		/* Per-descriptor state. */
		struct vring_desc_state_packed *desc_state;
		struct vring_desc_extra *desc_extra;

		/* DMA address and size information */
		dma_addr_t ring_dma_addr;
		dma_addr_t driver_event_dma_addr;
		dma_addr_t device_event_dma_addr;
		size_t ring_size_in_bytes;
		size_t event_size_in_bytes;
	} packed;

	/* How to notify other side. FIXME: commonalize hcalls! */
	bool (*notify)(struct virtqueue *vq);

	/* DMA, allocation, and size information */
	bool we_own_ring;

#ifdef DEBUG
	/* They're supposed to lock for us. */
	u32 in_use;

	/* Figure out if their kicks are too delayed. */
	bool last_add_time_valid;
	ktime_t last_add_time;
#endif
};

struct zxdh_pci_vq_info {
	/* the actual virtqueue */
	struct virtqueue *vq;

	/* the list node for the virtqueues list */
	struct list_head node;

	/* channel num map 1-1 to vector*/
	unsigned int channel_num;
};

struct virtnet_stat_desc {
	char desc[ETH_GSTRING_LEN];
	size_t offset;
};

struct virtnet_sq_stats {
	struct u64_stats_sync syncp;
	uint64_t packets;
	uint64_t bytes;
	uint64_t xdp_tx;
	uint64_t xdp_tx_drops;
	uint64_t kicks;
	uint64_t tx_timeouts;
};

struct virtnet_rq_stats {
	struct u64_stats_sync syncp;
	uint64_t packets;
	uint64_t bytes;
	uint64_t drops;
	uint64_t xdp_packets;
	uint64_t xdp_tx;
	uint64_t xdp_redirects;
	uint64_t xdp_drops;
	uint64_t kicks;
	uint64_t rx_csum_offload_good;
	uint64_t rx_removed_vlan_packets;
};
#define VIRTNET_SQ_STAT(m) offsetof(struct virtnet_sq_stats, m)
#define VIRTNET_RQ_STAT(m) offsetof(struct virtnet_rq_stats, m)

#ifdef ZXDH_CONFIG_SPECIAL_SQ_EN
struct zxdh_sq_flow_map {
	struct hlist_node hlist;
	u32 dst_ip;
	u16 dst_port;
	u16 queue_index;
};
#endif

static const struct virtnet_stat_desc virtnet_sq_stats_desc[] = {
	{ "packets", VIRTNET_SQ_STAT(packets) }, { "bytes", VIRTNET_SQ_STAT(bytes) },
	{ "xdp_tx", VIRTNET_SQ_STAT(xdp_tx) },	 { "xdp_tx_drops", VIRTNET_SQ_STAT(xdp_tx_drops) },
	{ "kicks", VIRTNET_SQ_STAT(kicks) },	 { "tx_timeouts", VIRTNET_SQ_STAT(tx_timeouts) },
};

static const struct virtnet_stat_desc virtnet_rq_stats_desc[] = {
	{ "packets", VIRTNET_RQ_STAT(packets) },
	{ "bytes", VIRTNET_RQ_STAT(bytes) },
	{ "drops", VIRTNET_RQ_STAT(drops) },
	{ "xdp_packets", VIRTNET_RQ_STAT(xdp_packets) },
	{ "xdp_tx", VIRTNET_RQ_STAT(xdp_tx) },
	{ "xdp_redirects", VIRTNET_RQ_STAT(xdp_redirects) },
	{ "xdp_drops", VIRTNET_RQ_STAT(xdp_drops) },
	{ "kicks", VIRTNET_RQ_STAT(kicks) },
	{ "rx_csum_offload_good", VIRTNET_RQ_STAT(rx_csum_offload_good) },
	{ "rx_removed_vlan_packets", VIRTNET_RQ_STAT(rx_removed_vlan_packets) },
};

#define VIRTNET_SQ_STATS_LEN ARRAY_SIZE(virtnet_sq_stats_desc)
#define VIRTNET_RQ_STATS_LEN ARRAY_SIZE(virtnet_rq_stats_desc)

/* RX packet size EWMA. The average packet size is used to determine the packet
 * buffer size when refilling RX rings. As the entire RX ring may be refilled
 * at once, the weight is chosen so that the EWMA will be insensitive to short-
 * term, transient changes in packet size.
 */
DECLARE_EWMA(pkt_len, 0, 64)

/* Internal representation of a send virtqueue */
struct send_queue {
	/* Virtqueue associated with this send _queue */
	struct virtqueue *vq;

	/* TX: fragments + linear part + custom queue header */
	struct scatterlist sg[MAX_SKB_FRAGS + 2];

	/* Name of the send queue: output.$index */
	char name[40];

	struct virtnet_sq_stats stats;

	struct napi_struct napi;

	u8 *hdr_buf;
	u16 hdr_idx;

#ifdef ZXDH_CONFIG_SPECIAL_SQ_EN
	struct zxdh_sq_flow_map flow_map;
#endif
};

/* Internal representation of a receive virtqueue */
struct receive_queue {
	/* Virtqueue associated with this receive_queue */
	struct virtqueue *vq;

	struct napi_struct napi;

	struct bpf_prog __rcu *xdp_prog;

	struct virtnet_rq_stats stats;

	/* Chain pages by the private ptr. */
	struct page *pages;

	/* Average packet length for mergeable receive buffers. */
	struct ewma_pkt_len mrg_avg_pkt_len;

	/* Page frag for packet buffer allocation. */
	struct page_frag alloc_frag;

	/* RX: fragments + linear part + custom queue header */
	struct scatterlist sg[MAX_SKB_FRAGS + 2];

	/* Min single buffer size for mergeable buffers case. */
	u32 min_buf_len;

	/* Name of this receive queue: input.$index */
	char name[40];

	struct xdp_rxq_info xdp_rxq;
};

#define to_vvq(_vq) container_of(_vq, struct vring_virtqueue, vq)

typedef void vq_callback_t(struct virtqueue *);

void zxdh_set_default_xps_cpumasks(struct zxdh_en_device *en_dev);
void zxdh_print_vring_info(struct virtqueue *vq, u32 desc_index, u32 desc_num);
void virtnet_napi_enable(struct virtqueue *vq, struct napi_struct *napi);
void virtnet_napi_tx_enable(struct net_device *netdev, struct virtqueue *vq,
			    struct napi_struct *napi);
void virtnet_napi_tx_disable(struct napi_struct *napi);
void refill_work(struct work_struct *work);
int virtnet_poll(struct napi_struct *napi, int budget);
int virtnet_poll_tx(struct napi_struct *napi, int budget);
s32 txq2vq(s32 txq);
s32 rxq2vq(s32 rxq);
u16 vqm16_to_cpu(struct zxdh_en_device *en_dev, __vqm16 val);
u8 vp_get_status(struct net_device *netdev);
void vp_set_status(struct net_device *netdev, u8 status);
void vp_set_reset_status(struct net_device *netdev, u8 status);
void zxdh_add_status(struct net_device *netdev, u32 status);
void zxdh_vp_enable_cbs(struct net_device *netdev);
void zxdh_vp_disable_cbs(struct net_device *netdev);
void zxdh_vp_reset(struct net_device *netdev);
void vring_free_queue(struct zxdh_en_device *en_dev, size_t size, void *queue,
		      dma_addr_t dma_handle);
netdev_tx_t start_xmit(struct sk_buff *skb, struct net_device *netdev);
bool try_fill_recv(struct receive_queue *rq, gfp_t gfp);
inline struct zxdh_net_hdr_rx *skb_vnet_hdr(struct sk_buff *skb);
s32 zxdh_virtqueue_add_outbuf(struct virtqueue *vq, struct scatterlist *sg, u32 num, void *data,
			      gfp_t gfp);
void zxdh_virtqueue_disable_cb(struct virtqueue *_vq);
void free_old_xmit_skbs(struct net_device *netdev, struct send_queue *sq, bool in_napi);
bool zxdh_virtqueue_enable_cb_delayed(struct virtqueue *_vq);
bool virtqueue_kick_prepare_packed(struct virtqueue *_vq);
bool zxdh_virtqueue_notify(struct virtqueue *_vq);
void zxdh_pf_features_init(struct net_device *netdev);
bool zxdh_has_feature(struct zxdh_en_device *en_dev, u32 fbit);
bool zxdh_has_status(struct net_device *netdev, u32 sbit);
void zxdh_free_unused_bufs(struct net_device *netdev);
void zxdh_free_receive_bufs(struct net_device *netdev);
void zxdh_free_receive_page_frags(struct net_device *netdev);
void zxdh_virtnet_del_vqs(struct net_device *netdev);
void zxdh_vqs_uninit(struct net_device *netdev);
s32 zxdh_vqs_init(struct net_device *netdev);
s32 dh_eq_vqs_vring_int(struct notifier_block *nb, unsigned long action, void *data);
s32 vq2rxq(struct virtqueue *vq);
void *zxdh_virtqueue_get_buf(struct virtqueue *_vq, u32 *len);
void *virtqueue_get_buf_ctx_packed(struct virtqueue *_vq, u32 *len, void **ctx);
u32 zxdh_virtqueue_get_vring_size(struct virtqueue *_vq);
void virtqueue_napi_complete(struct napi_struct *napi, struct virtqueue *vq, s32 processed);
s32 zxdh_virtqueue_add_inbuf_ctx(struct virtqueue *vq, struct scatterlist *sg, u32 num, void *data,
				 void *ctx, gfp_t gfp);
bool dh_skb_page_frag_refill(unsigned int sz, struct page_frag *pfrag, gfp_t gfp);

s32 zxdh_sec_vqs_init(struct net_device *netdev);
void zxdh_sec_vqs_uninit(struct net_device *netdev, u8 qidx);
void zxdh_vvq_reset(struct zxdh_en_device *en_dev);
bool is_flow_stopped(struct zxdh_en_device *en_dev);
int zxdh_en_xdp(struct net_device *dev, struct netdev_bpf *xdp);
int zxdh_en_xdp_xmit(struct net_device *dev, int n, struct xdp_frame **frames, u32 flags);

#endif
