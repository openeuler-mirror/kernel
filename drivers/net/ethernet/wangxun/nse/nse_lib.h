/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_LIB_H_
#define _NSE_LIB_H_

#include "nse.h"

const char *nse_vsi_type_str(enum nse_vsi_type vsi_type);

bool nse_pf_state_is_nominal(struct nse_pf *pf);

bool nse_is_hw_static_fea_set(struct nse_hw *hw, unsigned int f);
bool nse_is_hw_dyn_fea_set(struct nse_hw *hw, unsigned int f);

bool nse_is_fw_fea_set(struct nse_hw *hw, unsigned int f);

void nse_vsi_reset_stats(struct nse_vsi *vsi);

void nse_update_vsi_hw_stats(struct nse_vsi *vsi);

int nse_vsi_cfg_single_rxq(struct nse_vsi *vsi, u16 q_idx);

int nse_vsi_cfg_single_txq(struct nse_vsi *vsi, struct nse_ring **tx_rings, u16 q_idx);

int nse_vsi_cfg_rxqs(struct nse_vsi *vsi);

int nse_vsi_cfg_lan_txqs(struct nse_vsi *vsi);

void nse_vsi_cfg_msix(struct nse_vsi *vsi);

int nse_vsi_start_all_rx_rings(struct nse_vsi *vsi);

void nse_vsi_sync_tail_all_rx_rings(struct nse_vsi *vsi);

int nse_vsi_stop_all_rx_rings(struct nse_vsi *vsi, bool rdm_stopped);

int
nse_vsi_start_lan_tx_rings(struct nse_vsi *vsi);

int
nse_vsi_stop_lan_tx_rings(struct nse_vsi *vsi, bool tdm_stopped);

int nse_vsi_cfg_xdp_txqs(struct nse_vsi *vsi);

int nse_vsi_start_xdp_tx_rings(struct nse_vsi *vsi);

int nse_vsi_stop_xdp_tx_rings(struct nse_vsi *vsi);

int nse_vsi_cfg_lan_txcqs(struct nse_vsi *vsi);

int nse_vsi_start_lan_txcq_rings(struct nse_vsi *vsi);

int nse_vsi_stop_lan_txcq_rings(struct nse_vsi *vsi);

bool nse_vsi_is_vlan_pruning_ena(struct nse_vsi *vsi);

int nse_nonvf_vsi_lan_rxq_res_owner_id(struct nse_vsi *vsi, u16 *res_owner_id);
int nse_nonvf_vsi_lan_txq_res_owner_id(struct nse_vsi *vsi, bool is_xdp_txq, u16 *res_owner_id);
int nse_nonvf_vsi_lan_txcq_res_owner_id(struct nse_vsi *vsi, u16 *res_owner_id);

void nse_cfg_sw_lldp(struct nse_vsi *vsi, bool tx, bool create);

int nse_set_link(struct nse_vsi *vsi, bool ena);

void nse_vsi_delete(struct nse_vsi *vsi);
int nse_vsi_clear(struct nse_vsi *vsi);
void nse_vsi_put_qs(struct nse_vsi *vsi);

void nse_vsi_cfg_netdev_tc(struct nse_vsi *vsi, u8 ena_tc);

int nse_vsi_cfg_tc(struct nse_vsi *vsi, u8 ena_tc);

struct nse_vsi *
nse_vsi_setup(struct nse_pf *pf, struct nse_port_info *pi,
	      enum nse_vsi_type vsi_type, struct nse_vf *vf,
	      u8 tc);

int nse_vsi_init(struct nse_vsi *vsi, bool init_vsi);

void nse_napi_del(struct nse_vsi *vsi);

int nse_vsi_release(struct nse_vsi *vsi);

void nse_vsi_close(struct nse_vsi *vsi);

int nse_ena_vsi_under_pf_drv(struct nse_hw *hw, struct nse_vsi *vsi, bool locked);

void nse_dis_vsi_under_pf_drv(struct nse_hw *hw, struct nse_vsi *vsi, bool locked);

int nse_free_res(struct nse_res_tracker *res, u16 index, u16 id);

u16 nse_get_free_res_count(struct nse_res_tracker *res);

u16 nse_get_free_res_count_max_contig(struct nse_res_tracker *res);

u16 nse_get_free_res_count_contig_from_offset(struct nse_res_tracker *res, u16 offset);
u16 nse_get_free_res_count_contig_before_offset(struct nse_res_tracker *res, u16 offset);

u16 nse_get_free_res_count_tail_contig(struct nse_res_tracker *res);

u16 nse_get_valid_res_count(struct nse_res_tracker *res);

int
nse_get_res(struct nse_pf *pf, struct nse_res_tracker *res, u16 needed, u16 id);

int
nse_get_res_backward(struct nse_pf *pf, struct nse_res_tracker *res, u16 needed, u16 id);

void
nse_dump_res_tracker(struct nse_pf *pf, struct nse_res_tracker *res);

int nse_vsi_rebuild(struct nse_hw *hw, struct nse_vsi *vsi, bool init_vsi);

bool nse_is_reset_in_progress(unsigned long *state);
bool nse_is_high_reset_in_progress(unsigned long *state);

int nse_wait_for_reset(struct nse_pf *pf, unsigned long timeout);

void nse_vsi_dis_irq(struct nse_vsi *vsi);

void nse_vsi_free_irq(struct nse_vsi *vsi);

void nse_vsi_free_rx_rings(struct nse_vsi *vsi);

void nse_vsi_free_tx_rings(struct nse_vsi *vsi);

void nse_vsi_free_lan_txcq_rings(struct nse_vsi *vsi);

void nse_update_tx_ring_stats(struct nse_ring *ring, u64 pkts, u64 bytes);

void nse_update_rx_ring_stats(struct nse_ring *ring, u64 pkts, u64 bytes);

void nse_update_txcq_ring_stats(struct nse_txcq_ring *ring, u64 pkts, u64 bytes, u64 txqe_cnt);

void nse_vsi_cfg_frame_size(struct nse_vsi *vsi);

int nse_vsi_cfg_rx_max(struct nse_vsi *vsi, u32 rxmax);

int nse_status_to_errno(enum nse_status err);
enum nse_status nse_aq_err_to_status(enum nse_aq_err aq_err);

irqreturn_t nse_msix_clean_rings(int __always_unused irq, void *data);

void nse_write_intrl(struct nse_q_vector *q_vector, u8 intrl);
void nse_write_itr(struct nse_q_vector *q_vector, u16 itr);
void nse_set_q_vector_intrl(struct nse_q_vector *q_vector);

enum nse_status
nse_vsi_cfg_mac_fltr(struct nse_vsi *vsi, const u8 *macaddr, bool set);
bool nse_is_aux_ena(struct nse_pf *pf);
bool nse_is_vsi_dflt_vsi(struct nse_vsi *vsi);
int nse_set_dflt_vsi(struct nse_vsi *vsi);
int nse_clear_dflt_vsi(struct nse_vsi *vsi);
int nse_set_min_bw_limit(struct nse_vsi *vsi, u32 min_tx_rate);
int nse_set_max_bw_limit(struct nse_vsi *vsi, u32 max_tx_rate);

void nse_set_dflt_vsi_ctx(struct nse_hw *hw, struct nse_vsi *vsi, struct nse_vsi_ctx *ctxt);

int nse_vsi_update_switch(struct nse_vsi *vsi,
			    void (*fill)(struct nse_vsi_ctx *));
void nse_vsi_ctx_set_antispoof(struct nse_vsi_ctx *ctx);
void nse_vsi_ctx_clear_antispoof(struct nse_vsi_ctx *ctx);
void nse_vsi_ctx_set_mac_antispoof(struct nse_vsi_ctx *ctx);
void nse_vsi_ctx_clear_mac_antispoof(struct nse_vsi_ctx *ctx);
void nse_vsi_ctx_set_vlan_antispoof(struct nse_vsi_ctx *ctx);
void nse_vsi_ctx_clear_vlan_antispoof(struct nse_vsi_ctx *ctx);
void nse_vsi_ctx_set_vlan_rx_filter(struct nse_vsi_ctx *ctx);
void nse_vsi_ctx_clear_vlan_rx_filter(struct nse_vsi_ctx *ctx);
void nse_vsi_ctx_set_tx_ovs_miss(struct nse_vsi_ctx *ctx);
void nse_vsi_ctx_clear_tx_ovs_miss(struct nse_vsi_ctx *ctx);
void nse_vsi_ctx_set_rx_ovs_miss(struct nse_vsi_ctx *ctx);
void nse_vsi_ctx_clear_rx_ovs_miss(struct nse_vsi_ctx *ctx);
void nse_vsi_ctx_set_rx_dflt_vsi(struct nse_vsi_ctx *ctx);
void nse_vsi_ctx_clear_rx_dflt_vsi(struct nse_vsi_ctx *ctx);
void nse_vsi_ctx_set_src_prune_rx(struct nse_vsi_ctx *ctx);
void nse_vsi_ctx_clear_src_prune_rx(struct nse_vsi_ctx *ctx);
void nse_vsi_ctx_set_src_prune_tx(struct nse_vsi_ctx *ctx);
void nse_vsi_ctx_clear_src_prune_tx(struct nse_vsi_ctx *ctx);
void nse_vsi_ctx_set_allow_override(struct nse_vsi_ctx *ctx);
void nse_vsi_ctx_clear_allow_override(struct nse_vsi_ctx *ctx);
void nse_vsi_l2_ctrl_set_rx_upe(struct nse_vsi_ctx *ctx);
void nse_vsi_l2_ctrl_clear_rx_upe(struct nse_vsi_ctx *ctx);
void nse_vsi_l2_ctrl_set_rx_mpe(struct nse_vsi_ctx *ctx);
void nse_vsi_l2_ctrl_clear_rx_mpe(struct nse_vsi_ctx *ctx);
void nse_vsi_l2_ctrl_set_rx_bam(struct nse_vsi_ctx *ctx);
void nse_vsi_l2_ctrl_clear_rx_bam(struct nse_vsi_ctx *ctx);
void nse_vsi_l2_ctrl_set_rx_vpe(struct nse_vsi_ctx *ctx);
void nse_vsi_l2_ctrl_clear_rx_vpe(struct nse_vsi_ctx *ctx);
void nse_vsi_l2_ctrl_set_rx_vaccept(struct nse_vsi_ctx *ctx);
void nse_vsi_l2_ctrl_clear_rx_vaccept(struct nse_vsi_ctx *ctx);
void nse_vsi_l2_ctrl_set_rx_aupe(struct nse_vsi_ctx *ctx);
void nse_vsi_l2_ctrl_clear_rx_aupe(struct nse_vsi_ctx *ctx);
void nse_vsi_l2_ctrl_set_rx_def(struct nse_vsi_ctx *ctx);
void nse_vsi_l2_ctrl_clear_rx_def(struct nse_vsi_ctx *ctx);
int nse_check_mtu_valid(struct net_device *netdev, int new_mtu);
int nse_vsi_add_vlan_zero(struct nse_vsi *vsi);
int nse_vsi_del_vlan_zero(struct nse_vsi *vsi);
bool nse_vsi_has_non_zero_vlans(struct nse_vsi *vsi);
u16 nse_vsi_num_non_zero_vlans(struct nse_vsi *vsi);

int nse_init_vsi_scheme(struct nse_pf *pf);
void nse_clear_vsi_scheme(struct nse_pf *pf);

int nse_init_lanq_scheme(struct nse_pf *pf);
void nse_clear_lanq_scheme(struct nse_pf *pf);

int nse_init_rss_scheme(struct nse_pf *pf);
void nse_clear_rss_scheme(struct nse_pf *pf);

int nse_vsi_cfg_rss_key(struct nse_vsi *vsi);
int nse_vsi_cfg_rss_lut(struct nse_vsi *vsi);
int nse_vsi_cfg_rss_ctl(struct nse_vsi *vsi);
int nse_vsi_cfg_rss(struct nse_vsi *vsi);

void nse_vsi_manage_rss_lut(struct nse_vsi *vsi, bool ena);

int nse_get_valid_rss_size(struct nse_hw *hw, int new_size);
int nse_vsi_set_dflt_rss_lut(struct nse_vsi *vsi, int num_rxq);

int nse_msgbox_init(struct nse_pf *pf);
void nse_msgbox_exit(struct nse_pf *pf);
void nse_msgbox_reset(struct nse_pf *pf);
void nse_msgbox_clean_v2p_subtask(struct nse_pf *pf);
void nse_msgbox_debugfs_init(struct nse_pf *pf);

void nse_msgbox_dis_interrupt(struct nse_hw *hw);
void nse_msgbox_ena_interrupt(struct nse_hw *hw, u32 reg_idx);

int nse_fdir_init_pre(struct nse_pf *pf);
int nse_fdir_init_post(struct nse_pf *pf);
void nse_fdir_deinit(struct nse_pf *pf);

enum nse_status nse_fdir_init_utilq(struct nse_hw *hw);
void nse_fdir_shutdown_utilq(struct nse_hw *hw);

void nse_fdir_main_vsi_init(struct nse_hw *hw, struct nse_vsi *main_vsi);
void nse_fdir_main_vsi_deinit(struct nse_hw *hw, struct nse_vsi *main_vsi);

void nse_fdir_vf_vsi_init(struct nse_hw *hw, struct nse_vsi *vf_vsi, struct nse_vf *vf);

enum nse_status nse_init_hw_conf(struct nse_hw *hw);
enum nse_status nse_init_fw_conf(struct nse_hw *hw);
void nse_download_ddp(struct nse_pf *pf);

void nse_shutdown_ctrlq(struct nse_hw *hw, enum nse_ctl_q q_type, bool drv_unloading);

extern int wd_subtask_check_temp_chip_high_thres;
extern int wd_subtask_check_temp_chip_low_thres;
extern int wd_subtask_check_temp_ephy_high_thres;
extern int wd_subtask_check_temp_ephy_low_thres;

void nse_set_rx_tstamp(struct nse_pf *pf, bool on);
void nse_set_tx_tstamp(struct nse_pf *pf, bool on);

void nse_dump_vsi_props(struct nse_hw *hw, struct nse_aqc_vsi_props *props);

int nse_get_link_ksettings(struct net_device *netdev, struct ethtool_link_ksettings *cmd);
int nse_set_link_ksettings(struct net_device *netdev, const struct ethtool_link_ksettings *cmd);
int nse_set_fecparam(struct net_device *netdev, struct ethtool_fecparam *fecparam);
int nse_get_fecparam(struct net_device *netdev, struct ethtool_fecparam *fecparam);

void nse_init_pf_fw_opt_features(struct nse_pf *pf);
void nse_deinit_pf_fw_opt_features(struct nse_pf *pf);
void nse_rebuild_pf_fw_ot_features(struct nse_pf *pf, enum nse_reset_req reset_type);

#if defined(NSE_DEBUG_EXT)
void nse_test_suite_rss(struct nse_ring *rx_ring, union nse_32b_rx_desc *rx_desc,
			struct sk_buff *skb, u8 rx_ptype);
void nse_test_suite_fdir(struct nse_ring *rx_ring, union nse_32b_rx_desc *rx_desc,
			 struct sk_buff *skb, u8 rx_ptype);
void nse_test_suite_rcsum(struct nse_ring *rx_ring, union nse_32b_rx_desc *rx_desc,
			  struct sk_buff *skb, u8 rx_ptype);
#endif

#endif /* !_NSE_LIB_H_ */

