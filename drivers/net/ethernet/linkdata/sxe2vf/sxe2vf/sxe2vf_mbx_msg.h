/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, Linkdata Technologies Co., Ltd.
 *
 * @file: sxe2vf_mbx_msg.h
 * @author: Linkdata
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2VF_MBX_MSG_H__
#define __SXE2VF_MBX_MSG_H__

#include "sxe2vf_mbx_channel.h"
#include "sxe2_mbx_public.h"
#include "sxe2vf_l2_filter.h"
#include "sxe2vf_aux_drv.h"
#include "sxe2vf_ipsec.h"
#include "sxe2_cmd.h"
#include "sxe2_com_cdev.h"

struct sxe2vf_adapter;

struct sxe2vf_mbx_msg_table {
	u32 opcode;
	s32 (*func)(struct sxe2vf_adapter *adapter, void *body);
};

struct sxe2vf_msg_req_table {
	s32 (*func)(struct sxe2vf_adapter *adapter);
};

union sxe2vf_trace_info {
	u64 id;
	struct {
		u64 count : 50;
		u64 cpu_id : 10;
		u64 type : 4;
	} sxe2vf_trace_id_param;
};

struct sxe2vf_mbx_msg_table *sxe2vf_mbx_msg_table_get(void);

s32 sxe2vf_drv_ver_match(struct sxe2vf_adapter *adapter);

void sxe2vf_trace_id_init(void);

s32 sxe2vf_promisc_set_msg_send(struct sxe2vf_adapter *adapter);

s32 sxe2vf_mac_msg_send(struct sxe2vf_adapter *adapter,
			struct sxe2vf_mac *mac_info, bool add, bool is_user,
			u16 vsi_id);

s32 sxe2vf_mac_clear_msg_send(struct sxe2vf_adapter *adapter);

s32 sxe2vf_vlan_msg_send(struct sxe2vf_adapter *adapter, struct sxe2vf_vlan *vlan, bool add);

s32 sxe2vf_vlan_clear_msg_send(struct sxe2vf_adapter *adapter);

s32 sxe2vf_vlan_filter_msg_send(struct sxe2vf_adapter *adapter, bool is_user);

s32 sxe2vf_vlan_offload_msg_send(struct sxe2vf_adapter *adapter);

s32 sxe2vf_res_msg_send(struct sxe2vf_adapter *adapter);

s32 sxe2vf_rdma_msg_send(struct sxe2vf_adapter *adapter, u8 *msg,
			 u16 len, u8 *recv_msg, u16 recv_len);

s32 sxe2vf_txq_cfg_msg_send(struct sxe2vf_adapter *adapter, struct sxe2vf_vsi *vsi);

s32 sxe2vf_txq_stop_msg_send(struct sxe2vf_adapter *adapter, struct sxe2vf_queue *txq);

s32 sxe2vf_reset_msg_send(struct sxe2vf_adapter *adapter);

s32 sxe2vf_stats_get_msg_send(struct sxe2vf_adapter *adapter);

s32 sxe2vf_stats_push_msg_send(struct sxe2vf_adapter *adapter);

s32 sxe2vf_qv_map_msg_send(struct sxe2vf_adapter *adapter,
			   struct aux_qvlist_info *qv_info, bool map);

s32 sxe2vf_aux_mgr_msg_send(struct sxe2vf_adapter *adapter, u32 opcode,
			    u8 *req_msg, u16 req_len, u8 *recv_msg,
			    u16 recv_len);

s32 sxe2vf_ipsec_get_capa_msg_send(struct sxe2vf_adapter *adapter);

s32 sxe2vf_ipsec_add_txsa_msg_send(struct sxe2vf_adapter *adapter,
				   struct sxe2vf_tx_sa *sa_info, bool is_restore);

s32 sxe2vf_ipsec_add_rxsa_msg_send(struct sxe2vf_adapter *adapter,
				   struct sxe2vf_rx_sa *sa_info, bool is_restore);

s32 sxe2vf_ipsec_clear_sa_msg_send(struct sxe2vf_adapter *adapter, u8 direction, u32 sa_index);

void sxe2vf_mbx_msg_dflt_params_fill(struct sxe2vf_msg_params *params,
				     enum sxe2vf_resp_wait_mode mode,
				     enum sxe2_vf_opcode opc, void *in_data,
				     u32 in_len, void *out_data, u32 out_len);

s32 sxe2vf_irq_map_setup(struct sxe2vf_vsi *vsi);

s32 sxe2vf_irq_map_clear(struct sxe2vf_vsi *vsi);

s32 sxe2vf_func_caps_init(struct sxe2vf_adapter *adapter);

void sxe2vf_func_caps_deinit(struct sxe2vf_adapter *adapter);

s32 sxe2vf_txq_cfg_request(struct sxe2vf_adapter *adapter);

s32 sxe2vf_rxq_cfg_request(struct sxe2vf_adapter *adapter);

s32 sxe2vf_txrxq_dis_request(struct sxe2vf_adapter *adapter, bool is_close);

s32 sxe2vf_ethtool_info_request(struct sxe2vf_adapter *adapter,
				struct sxe2_msg_ethtool_info *link_cfg);

s32 sxe2vf_link_status_request(struct sxe2vf_adapter *adapter);

s32 sxe2vf_mbx_common_msg_send(struct sxe2vf_adapter *adapter,
			       enum sxe2_vf_opcode opcode, u8 *msg, u16 len);

s32 sxe2vf_rdma_dump_pcap_msg_send(struct sxe2vf_adapter *adapter, u8 *mac, bool is_add);

u16 sxe2vf_irq_cnt_min_get(struct sxe2vf_adapter *adapter);

s32 sxe2vf_mac_update_msg_send(struct sxe2vf_adapter *adapter, const u8 *macaddr, bool to_user);

s32 sxe2vf_user_promisc_update_msg_send(struct sxe2vf_adapter *adapter,
					u16 vsi_id, bool to_user, bool is_promisc);

s32 sxe2vf_user_promisc_set_msg_send(struct sxe2vf_adapter *adapter, u16 vsi_id);

s32 sxe2vf_user_vlan_msg_send(struct sxe2vf_adapter *adapter,
			      u16 vsi_id, struct sxe2vf_vlan *vlan, bool is_add);

s32 sxe2vf_com_link_info_request(struct sxe2vf_adapter *adapter, u8 *link_state, u32 *link_speed);
#ifdef SXE2_SUPPORT_ACL
s32 sxe2vf_acl_filter_clear_msg_send(struct sxe2vf_adapter *adapter);
#endif

s32 sxe2vf_drv_mode_set(struct sxe2vf_adapter *adapter, enum sxe2_com_module type);

s32 __sxe2vf_drv_mode_get(struct sxe2vf_adapter *adapter,
			  struct sxe2_vf_drv_mode_resp *vf_resp, u32 resp_len,
			  enum sxe2vf_resp_wait_mode mode);

s32 sxe2vf_drv_mode_get(struct sxe2vf_adapter *adapter, enum sxe2vf_resp_wait_mode mode);

void sxe2vf_wait_in_resetting(struct sxe2vf_adapter *adapter, bool is_close);
#endif
