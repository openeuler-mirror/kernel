/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2025. All rights reserved.
 *
 * Description: Types definition for ipourma
 */

#ifndef _IPOURMA_TYPES_H
#define _IPOURMA_TYPES_H

#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/jhash.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/timer.h>
#include "ub/urma/ubcore_types.h"

static inline int eid_is_empty(union ubcore_eid *eid)
{
	return (eid->in6.interface_id == 0 && eid->in6.subnet_prefix == 0);
}

static inline bool ipourma_are_eids_equal(union ubcore_eid *eid1,
	union ubcore_eid *eid2)
{
	if (memcmp(eid1, eid2, sizeof(union ubcore_eid)) == 0)
		return true;
	return false;
}

/*
 * It's controlled by ipourma itself, no need to comply with any public protocol
 * For now, we just use "ether type" as ipourma link header
 */
struct ipourma_header {
	__be16 proto;
};

enum {
	IPOURMA_DEV_ADMIN_UP        = 1,
	IPOURMA_DEV_OP_UP           = 2,
	IPOURMA_JFS_DEPTH           = 128,
	IPOURMA_JFR_DEPTH           = 256,
	IPOURMA_TX_JFC_DEPTH        = 1024,
	IPOURMA_RX_JFC_DEPTH        = 2048,
	IPOURMA_SEGMENT_ALIGN_SIZE  = 4096,
	IPOURMA_MIN_PAGE_LEVEL      = 12,
	IPOURMA_DEF_PAGE_LEVEL      = 16,
	IPOURMA_MAX_PAGE_LEVEL      = 21,
	IPOURMA_REGISTER_SEG_SIZE   = 65536,
	IPOURMA_MAX_URMA_SEND_SGES  = 13,
	IPOURMA_MAX_URMA_RECV_SGES  = 1,
	IPOURMA_WELL_KNOWN_JETTY_ID = 32,
	IPOURMA_MAX_RX_SGES         = 1,
	IPOURMA_TJETTY_HMAP_SIZE    = 1024,
	/* additional 1 for linear data, normally 18 */
	IPOURMA_MAX_TX_SGES         = MAX_SKB_FRAGS + 1,
	IPOURMA_NAPI_RX_WEIGHT      = 4,
	IPOURMA_NAPI_TX_WEIGHT      = 16,
	IPOURMA_TX_RING_SIZE        = 16,
	IPOURMA_RX_RING_SIZE        = 32,
	IPOURMA_MIN_TX_RING_SIZE    = 16,
	IPOURMA_MAX_TX_RING_SIZE    = 2048,
	IPOURMA_MIN_RX_RING_SIZE    = 16,
	IPOURMA_MAX_RX_RING_SIZE    = 4096,
	IPOURMA_URMA_MAX_MTU        = 4096,
	IPOURMA_MAX_MTU             = (IPOURMA_URMA_MAX_MTU -
					sizeof(struct ipourma_header)),
	IPOURMA_MIN_MTU             = 1280,
	IPOURMA_DEFAULT_MTU         = IPOURMA_MAX_MTU,
	IPOURMA_ALEN                = 6,
	IPOURMA_DEFAULT_TJETTY_CAP  = 256,
	IPOURMA_MAX_EID_CNT         = 128,
	IPOURMA_TJETTY_CB_S         = 10,
	IPOURMA_TJETTY_TIMEOUT_S    = 60,
	IPOURMA_TJETTY_TIMEOUT_MAX  = 65535,
	IPOURMA_MAX_DEV_NAME        = 50,
	IPOURMA_DEFAULT_CTP_SL      = 3,
	IPOURMA_DEFAULT_UTP_SL      = 0,
};

enum {
	IPOURMA_OK = 0,
	IPOURMA_INVALID_IPV6_ADDR,
	IPOURMA_UNSUPPORTED_ETH_PROTO,
	IPOURMA_ALLOC_NETDEV_FAILED,
	IPOURMA_ALLOC_DEV_PRIV_FAILED,
	IPOURMA_ALLOC_TX_RING_TABLE_FAILED,
	IPOURMA_ALLOC_RX_RING_TABLE_FAILED,
	IPOURMA_ALLOC_TX_RING_FAILED,
	IPOURMA_ALLOC_RX_RING_FAILED,
	IPOURMA_TX_RING_FULL,
	IPOURMA_REGISTER_SEG_FAILED,
	IPOURMA_INIT_URMA_RES_FAILED,
	IPOURMA_POST_SEND_FAILED,
	IPOURMA_POST_RECV_FAILED,
	IPOURMA_ALLOC_RX_SKB_FAILED,
	IPOURMA_URMA_POST_RECV_FAILED,
	IPOURMA_REARM_JFC_FAILED,
	IPOURMA_INCORRECT_CR_STATUS,
	IPOURMA_INCORRECT_WQE_JETTY_IDX,
	IPOURMA_INCORRECT_WQE_IDX,
	IPOURMA_POLL_JFC_FAILED,
	IPOURMA_CREATE_JFR_TABLE_FAILED,
	IPOURMA_CREATE_JETTY_TABLE_FAILED,
	IPOURMA_CREATE_JFC_FAILED,
	IPOURMA_CREATE_JFR_FAILED,
	IPOURMA_CREATE_JETTY_FAILED,
	IPOURMA_SRC_IP_ADDR_EID_MISMATCH,
	IPOURMA_NOT_SUPPORT_GSO,
	IPOURMA_GIANT_PACKET,
	IPOURMA_TOO_MANY_FRAGS,
	IPOURMA_IMPORT_JETTY_FAILED,
	IPOURMA_TX_CQE_ERR,
	IPOURMA_INSUFFICIENT_MEMORY,
	IPOURMA_ADDRESS_NOT_ALIGNED,
	IPOURMA_UNSUPPORTED_LINEAR_DATA_LEN,
	IPOURMA_REPLENISH_RX_SEG_FAILED,
	IPOURMA_NLMSG_ERR,
	IPOURMA_NLDATA_ERR,
	IPOURMA_NL_SEND_ERR,
	IPOURMA_EXCEED_SKB_LENGTH,
	IPOURMA_INIT_TJETTY_HMAP_FAILED,
	IPOURMA_ALLOC_TX_RING_LOCKS_FAILED,
	IPOURMA_TJETTY_NODE_ALLOC_FAILED,
	IPOURMA_ALLOC_CR_FAILED,
	IPOURMA_FLUSH_JETTY_FAILED,
	IPOURMA_MODIFY_JETTY_FAILED,
	IPOURMA_MODIFY_JFR_FAILED,
	IPOURMA_INIT_RINGS_TABLE_FAILED,
	IPOURMA_INVALID_DEV_NAME,
	IPOURMA_MAX_ERRNO
};

enum {
	IFLA_IPOURMA_UNSPEC,
	IFLA_IPOURMA_OP_MODE,
	IFLA_IPOURMA_TRANSPORT_MODE,
	IFLA_IPOURMA_MAX_SEND_SGE,
	IFLA_IPOURMA_XMTU,
	__IFLA_IPOURMA_MAX,
};

#define IFLA_IPOURMA_MAX (__IFLA_IPOURMA_MAX - 1)
extern u32 ipourma_tx_ring_size;
extern u32 ipourma_rx_ring_size;
extern u32 ipourma_jfs_depth;
extern u32 ipourma_tx_jfc_depth;
extern u32 ipourma_register_seg_size;

/* IPOURMA_MAX_CR_STATUS should be as same as the length of the enum ubcore_cr_status. Since
 * ubcore_cr_status is contiguous and starts from 0, we can use the value of the last item
 * plus one to represent the length of ubcore_cr_status.
 */

#define IPOURMA_MAX_CR_STATUS (UBCORE_CR_REM_DATA_POISON + 1)

struct ipourma_tx_stats {
	/* start xmit */
	uint64_t num_recv_pkts_from_kernel;
	uint64_t post_send_enque;
	uint64_t post_send_bypass;
	uint64_t gso_not_support;
	uint64_t packet_size_error;
	uint64_t frag_error;
	uint64_t not_ipv6_proto;
	uint64_t not_ipv6_addr;
	uint64_t ip_eid_not_equal;
	uint64_t tx_ring_full;
	/* post send */
	uint64_t post_send_start;
	uint64_t num_import_jetty_real;
	uint64_t num_import_jetty_bypass;
	uint64_t num_tjetty_hash_hit;
	uint64_t linear_len_oversize;
	uint64_t import_jetty_failed;
	uint64_t send_wr_failed;
	/* pass to ub */
	uint64_t pass_to_ub;
	/* tx cqe notify */
	uint64_t cqe_notify;
	/* tx poll */
	uint64_t num_napi_tx;
	uint64_t cqe_recved;
	uint64_t cqe_success;
	uint64_t cqe_err;
	uint64_t cqe_stats[IPOURMA_MAX_CR_STATUS];
	uint64_t poll_jfc_success;
	uint64_t poll_jfc_failed;
	uint64_t rearm_success;
	uint64_t rearm_failed;
	uint64_t flush_jetty_success;
};

struct ipourma_rx_stats {
	/* rx cqe notify */
	uint64_t cqe_notify;
	/* rx poll */
	uint64_t num_napi_rx;
	uint64_t rx_enque;
	uint64_t rx_deque;
	uint64_t cqe_recved;
	uint64_t cqe_success;
	uint64_t cqe_err;
	uint64_t cqe_stats[IPOURMA_MAX_CR_STATUS];
	uint64_t poll_jfc_success;
	uint64_t poll_jfc_failed;
	uint64_t rearm_success;
	uint64_t rearm_failed;
	uint64_t cr_len_err;
	uint64_t replenish_enque;
	/* pass to kernel */
	uint64_t pass_to_kernel;
	/* replenish */
	uint64_t replenish_deque;
	uint64_t num_post_wr;
	uint64_t alloc_skb_failed;
	uint64_t register_seg_failed;
	uint64_t post_wr_failed;
};

struct ipourma_runtime_stats {
	struct ipourma_tx_stats tx_stats;
	struct ipourma_rx_stats rx_stats;
	spinlock_t lock;
};

struct ipourma_rx_buf {
	struct ipourma_dev_priv *priv;
	struct sk_buff *skb_pass_up;
	u8 *buf_aligned;
	struct ubcore_target_seg *seg[IPOURMA_MAX_RX_SGES];
	u32 idx;
	/* eid_index = jetty id - IPOURMA_WELL_KNOWN_JETTY_ID */
	u32 eid_index;
	struct work_struct work;
	struct ubcore_jfr_wr rx_wr;
	struct ubcore_sge rx_sge[IPOURMA_MAX_RX_SGES];
};

struct ipourma_tx_buf {
	struct ipourma_dev_priv *priv;
	/* for skb linear data */
	u8 *buf_aligned;
	struct ubcore_target_seg *seg[IPOURMA_MAX_TX_SGES];
	u32 idx;
	u32 eid_index;
	struct work_struct work;
	/* dynamic fields */
	struct sk_buff *skb;
	union ubcore_eid dst_eid;
	u8 tx_buf_in_use;
	struct ubcore_jfs_wr tx_wr;
	struct ubcore_sge tx_sge[IPOURMA_MAX_TX_SGES];
	struct ubcore_tjetty *tjetty;
};

struct ipourma_ethtool_st {
	u16     coalesce_usecs;
	u16     max_coalesced_frames;
};

struct ipourma_tjetty_hash_node {
	struct hlist_node hlist;
	struct list_head lru_list;
	union ubcore_eid key[2];
	struct ubcore_tjetty *tjetty;
	struct work_struct unimport_work;
	struct ipourma_tjetty_lru *tjetty_lru;
	u64 last_jiffies;
};

struct ipourma_tjetty_hmap {
	struct hlist_head *buckets;
	u32 hash_seed;
};

struct ipourma_tjetty_lru {
	struct ipourma_tjetty_hmap tjetty_hmap;
	struct list_head list;
	spinlock_t lock;
	uint16_t count;
	uint16_t tjetty_capacity;
	struct delayed_work tjetty_aging_work;
	struct workqueue_struct *tjetty_wq;
	uint16_t tjetty_aging_interval_s;
	uint16_t tjetty_aging_timeout_s;
};

struct ipourma_dev_priv {
	struct net_device *dev;
	struct net_device *parent;
	/* ipourma device */
	struct ubcore_device *urma_dev;
	struct ipourma_tx_buf **tx_ring;
	struct ipourma_rx_buf **rx_ring;
	u32 tx_ring_size;
	u32 rx_ring_size;
	u32 tx_buf_size;
	u32 *tx_head;
	u32 *tx_tail;
	u32 *tx_count;
	struct napi_struct napi_send;
	struct napi_struct napi_recv;
	struct workqueue_struct *tx_wq;
	struct workqueue_struct *rx_wq;
	unsigned long flags;
	struct ipourma_ethtool_st ethtool;
	u8 route_tbl_idx;
	spinlock_t lock;
	spinlock_t *tx_ring_locks;
	struct dentry *address_dentry;
	bool need_restart_ring;
	struct workqueue_struct *net_config_wq;
	struct work_struct set_dev_up;
	struct work_struct set_ip;
	struct work_struct set_route;
	struct work_struct unset_route;
	struct work_struct set_route_entry;
	struct work_struct rx_cr_event;
	/* register netdev */
	struct workqueue_struct *register_wq;
	struct work_struct register_netdev;
	/* urma device */
	struct ubcore_eid_info *eid_info;
	struct ubcore_eid_info eid_info_exist[IPOURMA_MAX_EID_CNT];
	uint32_t eid_count;
	struct ubcore_jetty **jetty;
	struct ubcore_jfc *tx_jfc;
	struct ubcore_jfc *rx_jfc;
	struct ubcore_jfr **jfr;
	struct ubcore_cr tx_cr[IPOURMA_NAPI_TX_WEIGHT];
	struct ubcore_cr rx_cr[IPOURMA_NAPI_RX_WEIGHT];
	enum ubcore_opcode urma_op_mode;
	enum ubcore_transport_mode urma_transport_mode;
	u32 max_send_sge;
	u32 urma_mtu;
	struct ubcore_event_handler eid_change_handler;
	atomic_t rx_jfr_ref;
	bool *tx_ring_is_full;
	atomic_t tx_ring_blocked;
	/* tjetty lru */
	struct ipourma_tjetty_lru tjetty_lru;
	/* runtime stats statistics */
	struct ipourma_runtime_stats runtime_stats;
	/* memory pool */
	struct ubcore_target_seg **ipourma_ub_tx_seg[IPOURMA_MAX_EID_CNT];
	struct ubcore_target_seg **ipourma_ub_rx_seg[IPOURMA_MAX_EID_CNT];
	u8 **tx_buf_aligned[IPOURMA_MAX_EID_CNT];
	u8 **rx_buf_aligned[IPOURMA_MAX_EID_CNT];
	size_t tx_buf_num;
	size_t rx_buf_num;
	u32 skb_buf_size;
};

/* iterator for debugfs-eid */
struct ipourma_address_iter {
	struct ipourma_dev_priv *priv;
	uint32_t index;
};

#define IPOURMA_HARD_LEN ((unsigned short)sizeof(struct ipourma_header))

#endif
