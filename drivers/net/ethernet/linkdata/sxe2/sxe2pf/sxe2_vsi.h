/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2_vsi.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_VSI_H__
#define __SXE2_VSI_H__

#include <linux/netdevice.h>
#include <linux/types.h>
#include <linux/irqreturn.h>

#include "sxe2_compat.h"
#include "sxe2_irq.h"
#include "sxe2_cmd.h"
#include "sxe2_flow.h"
#include "sxe2_mbx_public.h"
#include "sxe2_udp_tunnel.h"

#ifdef SXE2_TEST
#define STATIC
#else
#define STATIC static
#endif

struct sxe2_vf_node;

#define SXE2_VSI_DFLT_TC BIT(0)
#define SXE2_VSI_ID_INVALID (0xFFFF)

#define sxe2_for_each_array_element(type, start, max_size)                        \
	for ((type) = (start); (type) < (max_size); (type)++) \

#define sxe2_for_each_vsi(vsi_ctxt, i)                                         \
	sxe2_for_each_array_element(i, 0, (vsi_ctxt)->max_cnt)

#define sxe2_for_each_vsi_txq(vsi, i)                                          \
	sxe2_for_each_array_element(i, 0, (vsi)->txqs.q_cnt)

#define sxe2_for_each_vsi_rxq(vsi, i)                                          \
	sxe2_for_each_array_element(i, 0, (vsi)->rxqs.q_cnt)

#define sxe2_for_each_vsi_alloc_txq(vsi, i)                                    \
	sxe2_for_each_array_element(i, 0, (vsi)->txqs.q_alloc)

#define sxe2_for_each_vsi_alloc_rxq(vsi, i)                                    \
	sxe2_for_each_array_element(i, 0, (vsi)->rxqs.q_alloc)

#define sxe2_for_each_vsi_irq(vsi, i)                                          \
	sxe2_for_each_array_element(i, 0, (vsi)->irqs.cnt)

#define sxe2_for_each_tc(i) \
	sxe2_for_each_array_element(i, 0, IEEE_8021QAZ_MAX_TCS)

#define sxe2_for_each_vsi_q_maxcnt(vsi, i)                                     \
	sxe2_for_each_array_element(i, 0, (vsi)->vsi_qs_stats.vsi_qs_stats_maxcnt)

#ifdef SXE2_TEST
#define SXE2_REALLOC(p, new_n, new_size, gfp, old_n)                           \
	sxe2_krealloc_array(p, new_n, new_size, gfp, old_n)
#else
#define SXE2_REALLOC(p, new_n, new_size, gfp)                                  \
	krealloc_array(p, new_n, new_size, gfp)
#endif

enum sxe2_vsi_type {
	SXE2_VSI_T_PF = 0,
	SXE2_VSI_T_VF,
	SXE2_VSI_T_CTRL,
	SXE2_VSI_T_LB,
	SXE2_VSI_T_MACVLAN,
	SXE2_VSI_T_ESW,
	SXE2_VSI_T_RDMA,
	SXE2_VSI_T_DPDK_PF,
	SXE2_VSI_T_DPDK_VF,
	SXE2_VSI_T_DPDK_ESW,
	SXE2_VSI_T_NR,
};

enum sxe2_vsi_state {
	SXE2_VSI_S_DOWN = 0,
	SXE2_VSI_S_NEEDS_RESTART,
	SXE2_VSI_S_NETDEV_ALLOCED,
	SXE2_VSI_S_MAC_FLTR_CHANGED,
	SXE2_VSI_S_DISABLE,
	SXE2_VSI_S_CLOSE,
	SXE2_VSI_S_NAPI_ADDED,
	SXE2_VSI_S_MACVLAN_DEL,
	SXE2_VSI_S_MAX,
};

struct sxe2_vsi_irqs {
	u16 cnt;
	u16 base_idx_in_pf;
	u16 base_idx_in_feature;
	struct sxe2_irq_data **irq_data;
	irqreturn_t (*proc)(int irq, void *data);
	struct sxe2_vsi_coalesce
		*coalesce;
};

struct sxe2_txsched_q_bw_info {
	u8 rl_type;
	u32 cir_bw;
	u32 pir_bw;
};

struct sxe2_vsi_txsched_queue {
	u32 teid;
	u16 idx_in_dev;
	struct sxe2_txsched_q_bw_info bw_info;
};

struct sxe2_vsi_txsched {
	u16 q_cnt[IEEE_8021QAZ_MAX_TCS];
	u16 vsi_teid;
	u16 vsi_node_cnt;
	struct sxe2_txsched_node *node;
	struct sxe2_txsched_q_bw_info vsi_bw_info;
	struct sxe2_vsi_txsched_queue *q[IEEE_8021QAZ_MAX_TCS];
};

struct sxe2_vsi_queues {
	u16 base_idx_in_feature;
	u16 q_cnt;
	u16 q_alloc;
	u16 depth;
	u16 rx_buf_len;
	u16 max_frame;
	struct sxe2_queue **q;
	u16 req_q_cnt;
};

struct sxe2_tc_info {
	u16 rxq_offset;
	u16 txq_offset;
	u16 txq_cnt;
	u16 rxq_cnt;
};

struct sxe2_vsi_tc {
	u8 tc_cnt;
	u8 tc_map;
	u16 rxq_pow;
	struct sxe2_tc_info info[IEEE_8021QAZ_MAX_TCS];
};

struct sxe2_vsi_rss {
	u16 lut_size;
	u16 queue_size;
	u8 *lut;
	u8 *hkey;
	u8 lut_type;
	u8 hash_type;
	u8 global_lut_id;
};

#define SXE2_FNAV_MAX_FILTERS (16 * 1024)

struct sxe2_vsi_fnav {
	/* in order to protect the data */
	struct mutex flow_cfg_lock;
	u16 space_gsize;
	u16 space_bsize;
	struct list_head flow_cfg_list;

	DECLARE_BITMAP(flow_ids, SXE2_FNAV_MAX_FILTERS);
	struct list_head filter_list;
	u32 filter_cnt;
};

#define SXE2_ACL_MAX_FILTERS (2048)
struct sxe2_vsi_acl {
	/* in order to protect the data */
	struct mutex flow_cfg_lock;
	struct list_head flow_cfg_list;

	DECLARE_BITMAP(filter_ids, SXE2_ACL_MAX_FILTERS);
	struct list_head filter_list;
	u32 filter_cnt;
};

struct sxe2_vsi_udp_tunnel {
#define SXE2_UDP_TUNNEL_MAX_PROTO  (13)
	struct sxe2_udp_tunnel_cfg cfgs[SXE2_UDP_TUNNEL_MAX_PROTO];
};

struct sxe2_vsi_sw_stats {
	u64 rx_packets;
	u64 rx_bytes;
	u64 rx_csum_unnecessary;
	u64 rx_csum_none;
	u64 rx_csum_complete;
	u64 rx_csum_unnecessary_inner;
	u64 rx_lro_packets;
	u64 rx_lro_bytes;
	u64 rx_vlan_strip;
	u64 rx_pkts_sw_drop;
	u64 rx_buff_alloc_err;
	u64 rx_pg_alloc_fail;
	u64 rx_csum_err;
	u64 rx_lro_count;
	u64 rx_page_alloc;
	u64 rx_non_eop_descs;
	u64 rx_xdp_pkts;
	u64 rx_xdp_bytes;
	u64 rx_xdp_pass;
	u64 rx_xdp_drop;
	u64 rx_xdp_unknown;
	u64 rx_xdp_redirect;
	u64 rx_xdp_redirect_fail;
	u64 rx_xdp_tx_xmit;
	u64 rx_xdp_tx_xmit_fail;
	u64 rx_xsk_drop;
	u64 rx_xsk_redirect;
	u64 rx_xsk_redirect_fail;
	u64 rx_xsk_packets;
	u64 rx_xsk_bytes;
	u64 rx_xsk_pass;
	u64 rx_xsk_unknown;
	u64 rx_xsk_tx_xmit;
	u64 rx_xsk_tx_xmit_fail;
	u64 rx_pa_err;

	u64 tx_packets;
	u64 tx_bytes;
	u64 tx_tso_packets;
	u64 tx_tso_bytes;
	u64 tx_vlan_insert;
	u64 tx_csum_none;
	u64 tx_csum_partial;
	u64 tx_csum_partial_inner;
	u64 tx_queue_dropped;
	u64 tx_xmit_more;
	u64 tx_linearize;
	u64 tx_busy;
	u64 tx_restart;
	u64 tx_tso_linearize_chk;
};

struct sxe2_vsi_qs_stats {
	struct sxe2_queue_stats *txqs_stats;
	struct sxe2_queue_stats *rxqs_stats;
	struct sxe2_queue_stats **xdp_stats;
	u16 vsi_qs_stats_maxcnt;
};

struct sxe2_vsi_stats {
	struct sxe2_vsi_hw_stats vsi_hw_stats;
	struct sxe2_vsi_hw_stats parse_vsi_hw_stats;
	struct sxe2_vsi_sw_stats vsi_sw_stats;
};

enum sxe2_vsi_flags {
	SXE2_VSI_FLAG_LRO_ENABLE = 0,
	SXE2_VSI_FLAG_RXFCS_ENABLE = 1,
	SXE2_VSI_FLAG_FC_ON,
	SXE2_VSI_FLAGS_NBITS
};

enum sxe2_mac_owner {
	SXE2_MAC_OWNER_NETDEV = 0,
	SXE2_MAC_OWNER_UC_MC,
	SXE2_MAC_OWNER_ROCE,
};

struct sxe2_addr_node {
	struct list_head list;
	u8 mac_addr[ETH_ALEN];
	unsigned long usage;
};

struct sxe2_mac_filter {
	struct list_head mac_addr_list;
	struct list_head tmp_sync_list;
	struct list_head tmp_unsync_list;
	/* in order to protect the data */
	struct mutex sync_lock;
};

struct sxe2_vsi_cfg_params {
	enum sxe2_vsi_type type;
	struct sxe2_vf_node *vf;
	u16 txq_base_idx;
	u16 txq_cnt;
	u16 rxq_base_idx;
	u16 rxq_cnt;
	u16 irq_base_idx;
	u16 irq_cnt;
	u16 vsi_id;
};

struct sxe2_user_vlan_offload_cfg {
	u8 outer_insert;
	u8 outer_strip;
	u8 inner_insert;
	u8 inner_strip;
};

struct sxe2_vlan {
	u16 tpid;
	u16 vid;
	u8 prio;
	u8 rsv[3];
};

struct sxe2_vsi_user_vlan_info {
	struct sxe2_vlan port_vlan;
	u8 port_vlan_exsit;
	u8 rsv[3];
	struct sxe2_user_vlan_offload_cfg vlan_offload;
};

struct sxe2_vsilist_prune_info {
	u16 vsi_id_u;
	u16 vsi_id_k;
};

struct sxe2_vsi {
	struct sxe2_adapter *adapter;
	struct net_device *netdev;
	u16 id_in_pf;
	u16 idx_in_dev;
	u8 is_from_pool;
	enum sxe2_vsi_type type;
	DECLARE_BITMAP(state, SXE2_VSI_S_MAX);
	struct sxe2_vsi_irqs irqs;
	struct sxe2_vsi_queues txqs;
	struct sxe2_vsi_txsched txsched;
	struct sxe2_vsi_queues rxqs;
	struct sxe2_queue *
		*origin_txqs;
	struct sxe2_vsi_tc tc;
	struct sxe2_mac_filter mac_filter;
	struct sxe2_vsi_rss rss_ctxt;
	struct sxe2_vsi_fnav fnav;
	struct sxe2_vsi_acl acl;
	struct sxe2_vf_node *vf_node;
	struct sxe2_vsi_qs_stats vsi_qs_stats;
	struct sxe2_vsi_stats vsi_stats;
	struct sxe2_vsi_user_vlan_info user_vlan;
	struct sxe2_vsi_udp_tunnel udp_tunnel;
	struct sxe2_vsilist_prune_info src_prune;

	struct bpf_prog *xdp_prog;
	struct sxe2_vsi_queues xdp_rings;
	unsigned long *af_xdp_zc_qps;
	DECLARE_BITMAP(flags, SXE2_VSI_FLAGS_NBITS);
	u16 num_xdp_txq;
#ifdef HAVE_AF_XDP_ZC_SUPPORT
#ifndef HAVE_AF_XDP_NETDEV_UMEM
	struct xdp_umem **xsk_umems;
	u16 num_xsk_umems_used;
	u16 num_xsk_umems;
#endif
#endif
};

struct sxe2_vsi_context {
	struct sxe2_vsi **vsi;
	u16 next_vsi_id;
	u16 cnt;
	u16 max_cnt;
	u16 base_idx_in_dev;
	/* in order to protect the data */
	struct mutex lock;
	struct sxe2_vsi *main_vsi;
	struct sxe2_vsi *ctrl_vsi;
};

s32 sxe2_main_vsi_create(struct sxe2_adapter *adapter);

s32 sxe2_ctrl_vsi_init(struct sxe2_adapter *adapter);

void sxe2_ctrl_vsi_deinit(struct sxe2_adapter *adapter);

struct sxe2_vsi *sxe2_loopback_vsi_create(struct sxe2_adapter *adapter);

s32 sxe2_vsi_recfg(struct sxe2_vsi *vsi);

void sxe2_vsi_destroy(struct sxe2_vsi *vsi);

void sxe2_vsi_destroy_unlock(struct sxe2_vsi *vsi);

void sxe2_vsi_destroy_all(struct sxe2_adapter *adapter);

s32 sxe2_vsi_open(struct sxe2_vsi *vsi);

s32 sxe2_vsi_up(struct sxe2_vsi *vsi);

s32 sxe2_vsi_close(struct sxe2_vsi *vsi);

s32 sxe2_vsi_down(struct sxe2_vsi *vsi);

s32 sxe2_vsi_down_up_unlock(struct sxe2_vsi *vsi);

s32 sxe2_vsi_down_up(struct sxe2_vsi *vsi);

void sxe2_napi_add(struct sxe2_vsi *vsi);

void sxe2_napi_del(struct sxe2_vsi *vsi);

void sxe2_vsi_rxq_clean(struct sxe2_vsi *vsi);

void sxe2_vsi_tc_cfg(struct sxe2_vsi *vsi);

void sxe2_vsi_queues_irqs_map(struct sxe2_vsi *vsi);

s32 sxe2_vsi_disable_all(struct sxe2_adapter *adapter);

s32 sxe2_vsi_disable_unlock(struct sxe2_vsi *vsi);

s32 sxe2_esw_vsi_disable_unlock(struct sxe2_vsi *vsi);

s32 sxe2_vsi_enable_unlock(struct sxe2_vsi *vsi);

s32 sxe2_vsi_rebuild_by_type(struct sxe2_adapter *adapter,
			     enum sxe2_vsi_type type, bool init);

s32 sxe2_vsi_enable_by_type(struct sxe2_adapter *adapter,
			    enum sxe2_vsi_type type);

void sxe2_vsis_irqs_deinit(struct sxe2_adapter *adapter);

s32 sxe2_vsis_irqs_init(struct sxe2_adapter *adapter);

s32 __sxe2_vf_vsi_create(struct sxe2_vf_node *vf_node);

void sxe2_queue_add(struct sxe2_queue *queue, struct sxe2_list *head);

void sxe2_vsi_queues_irqs_unmap(struct sxe2_vsi *vsi);

void sxe2_vsi_irqs_setup(struct sxe2_vsi *vsi);

void sxe2_vsi_irqs_release(struct sxe2_vsi *vsi);

struct sxe2_vsi *sxe2_macvlan_vsi_create(struct sxe2_adapter *adapter);

s32 sxe2_eswitch_vsi_create(struct sxe2_adapter *adapter);

s32 sxe2_vsi_rebuild(struct sxe2_vsi *vsi, bool init);

void sxe2_vsi_id_in_dev_clear(struct sxe2_adapter *adapter);

s32 sxe2_vsi_enable_unlock(struct sxe2_vsi *vsi);
s32 sxe2_rdma_vsi_create(struct sxe2_adapter *adapter);
void sxe2_rdma_vsi_destroy(struct sxe2_adapter *adapter);

s32 sxe2_vsi_queues_get(struct sxe2_vsi *vsi, u8 q_type);

void sxe2_irq_rxqs_cause_setup(struct sxe2_irq_data *irq_data);

void sxe2_irq_txqs_cause_setup(struct sxe2_irq_data *irq_data);

int sxe2_mac_addr_add(struct sxe2_vsi *vsi, const u8 *addr,
		      enum sxe2_mac_owner owner);

int sxe2_mac_addr_del(struct sxe2_vsi *vsi, const u8 *addr,
		      enum sxe2_mac_owner owner);

s32 sxe2_main_vsi_disable_unlock(struct sxe2_vsi *vsi);

s32 sxe2_ctrl_vsi_disable_unlock(struct sxe2_vsi *vsi);

s32 sxe2_macvlan_vsi_disable(struct sxe2_vsi *vsi);

s32 sxe2_main_vsi_open(struct sxe2_vsi *vsi);

s32 sxe2_main_vsi_enable_unlock(struct sxe2_vsi *vsi);

s32 sxe2_ctrl_vsi_enable_unlock(struct sxe2_vsi *vsi);

s32 sxe2_macvlan_vsi_enable_unlock(struct sxe2_vsi *vsi);

s32 sxe2_esw_vsi_enable_unlock(struct sxe2_vsi *vsi);

s32 sxe2_vsi_irqs_request(struct sxe2_vsi *vsi);

void sxe2_irq_txqs_cause_clear(struct sxe2_irq_data *irq_data);

void sxe2_irq_rxqs_cause_clear(struct sxe2_irq_data *irq_data);

void sxe2_vsi_irqs_disable(struct sxe2_vsi *vsi);

void sxe2_vsi_irqs_clear_free(struct sxe2_vsi *vsi);

s32 sxe2_vsi_irqs_configure(struct sxe2_vsi *vsi);

s32 sxe2_vsi_check(struct sxe2_vsi *vsi);

struct sxe2_vsi *sxe2_vsi_get_by_idx(struct sxe2_adapter *adapter,
				     u16 idx_in_dev);

struct sxe2_addr_node *sxe2_mac_addr_find(struct sxe2_vsi *vsi,
					  const u8 *macaddr);

struct sxe2_vsi *sxe2_vsi_get_by_type_unlock(struct sxe2_adapter *adapter,
					     enum sxe2_vsi_type target_type);

u16 sxe2_vsi_get(struct sxe2_vsi_context *vsi_ctxt);

void sxe2_vsi_put(struct sxe2_vsi_context *vsi_ctxt, u16 vsi_id);

struct sxe2_vsi *sxe2_vsi_create(struct sxe2_adapter *adapter,
				 struct sxe2_vsi_cfg_params *vsi_create);

void sxe2_vsi_destroy(struct sxe2_vsi *vsi);

bool sxe2_vsi_id_is_valid(struct sxe2_adapter *adapter, u16 vsi_id);

s32 sxe2_dpdk_resource_release(void *adapter, struct sxe2_obj *obj);

s32 sxe2_dpdk_vsi_create(struct sxe2_adapter *adapter, struct sxe2_vsi_cfg_params *params,
			 struct sxe2_fwc_vsi_crud_resp *resp);

s32 sxe2_dpdk_vsi_destroy(struct sxe2_adapter *adapter, struct sxe2_vsi_cfg_params *params);

bool sxe2_vsi_rxft_support_get(struct sxe2_vsi *vsi);

s32 sxe2_user_vsi_info_get(struct sxe2_adapter *adapter, u16 vsi_id,
			   struct sxe2_fwc_func_caps *caps);

#endif
