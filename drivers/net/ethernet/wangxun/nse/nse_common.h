/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_COMMON_H_
#define _NSE_COMMON_H_

#include "nse_type.h"
#include "nse_fdir.h"
#include "nse_switch.h"
#include "nse_txrx.h"

#include "virtchnl.h"

#define NSE_SQ_SEND_DELAY_TIME_US	100000		/* 100 ms */
#define NSE_SQ_SEND_MAX_EXECUTE		3
#define NSE_MAX_LAN_PORT_NUM		4

void nse_set_umac_shared(struct nse_hw *hw);
enum nse_status nse_init_hw(struct nse_hw *hw);
void nse_deinit_hw(struct nse_hw *hw);

enum nse_status nse_reset(struct nse_hw *hw, enum nse_reset_req req);

enum nse_status nse_create_all_ctrlq(struct nse_hw *hw);
enum nse_status nse_init_all_ctrlq(struct nse_hw *hw);
void nse_shutdown_all_ctrlq(struct nse_hw *hw, bool drv_unloading);
void nse_destroy_all_ctrlq(struct nse_hw *hw, bool drv_unloading);
enum nse_status
nse_clean_rq_elem(struct nse_hw *hw, struct nse_ctl_q_info *cq,
		  struct nse_rq_event_info *e, u16 *pending);

void nse_shutdown_vsi_mbxq(struct nse_hw *hw, u16 vsi_rel_id);
void nse_shutdown_vsi_utilq(struct nse_hw *hw, u16 vsi_rel_id);

enum nse_status
nse_sq_send_cmd(struct nse_hw *hw, struct nse_ctl_q_info *cq,
		struct nse_aq_desc *desc, void *buf, u16 buf_size,
		struct nse_sq_cd *cd);

enum nse_status
nse_sq_send_cmd_with_flags(struct nse_hw *hw, struct nse_ctl_q_info *cq,
		struct nse_aq_desc *desc, void *buf, u16 buf_size,
		struct nse_sq_cd *cd, unsigned int sq_send_cmd_flags);

enum nse_status
nse_sq_send_cmd_retry(struct nse_hw *hw, struct nse_ctl_q_info *cq,
		      struct nse_aq_desc *desc, void *buf, u16 buf_size,
		      struct nse_sq_cd *cd);

enum nse_status
nse_aq_get_internal_data(struct nse_hw *hw, u8 cluster_id, u16 table_id,
			 u32 start, void *buf, u16 buf_size, u16 *ret_buf_size,
			 u16 *ret_next_table, u32 *ret_next_index,
			 struct nse_sq_cd *cd);

struct nse_vsi;	/* forward declaration */

void
nse_stat_update64(u64 new_data, bool prev_stat_loaded,
		  u64 *prev_stat, u64 *cur_stat);

void
nse_stat_update48(u64 new_data, bool prev_stat_loaded,
		  u64 *prev_stat, u64 *cur_stat);

void
nse_stat_update32(u64 new_data, bool prev_stat_loaded,
		  u64 *prev_stat, u64 *cur_stat);

void
nse_stat_update16(u64 new_data, bool prev_stat_loaded,
		  u64 *prev_stat, u64 *cur_stat);

enum nse_status
nse_write_rxq_ctx(struct nse_hw *hw, struct nse_vsi *vsi, struct nse_lan_rxq_ctx *rlan_ctx,
		  u16 rxq_abs_id);
enum nse_status nse_clear_rxq_ctx(struct nse_hw *hw, u32 rxq_index);

enum nse_status
nse_write_txq_ctx(struct nse_hw *hw, struct nse_vsi *vsi, struct nse_lan_txq_ctx *tlan_ctx,
		  u16 txq_abs_id);

enum nse_status
nse_aq_lan_disable_rxq(struct nse_hw *hw, u16 rxq_abs_id, u16 irqll_msix);

enum nse_status
nse_aq_lan_disable_txq(struct nse_hw *hw, u16 txq_abs_id, u16 irqll_msix);

enum nse_status
nse_aq_lan_enable_rxq(struct nse_hw *hw, u16 rxq_abs_id, u16 irqll_msix);

enum nse_status
nse_aq_lan_enable_txq(struct nse_hw *hw, u16 txq_abs_id, u16 irqll_msix);

enum nse_status
__nse_aq_lan_ena_dis_rxq_txq_many(struct nse_hw *hw, u32 ena_or_dis, u32 qtype,
						u16 firstq_abs_id, u16 lastq_abs_id,
							u16 *irqll_msix);

enum nse_status
nse_aq_lan_ena_rxq_many(struct nse_hw *hw, u16 firstq_abs_id, u16 lastq_abs_id, u16 *irqll_msix);

enum nse_status
nse_aq_lan_dis_rxq_many(struct nse_hw *hw, u16 firstq_abs_id, u16 lastq_abs_id, u16 *irqll_msix);

enum nse_status
nse_aq_lan_ena_txq_many(struct nse_hw *hw, u16 firstq_abs_id, u16 lastq_abs_id, u16 *irqll_msix);

enum nse_status
nse_aq_lan_dis_txq_many(struct nse_hw *hw, u16 firstq_abs_id, u16 lastq_abs_id, u16 *irqll_msix);

enum nse_status
nse_aq_lan_read_rxq_status(struct nse_hw *hw, u16 rxq_abs_id, u16 *q_stat);

enum nse_status
nse_aq_lan_read_txq_status(struct nse_hw *hw, u16 txq_abs_id, u16 *q_stat);

enum nse_status
nse_read_rxq_ctx(struct nse_hw *hw, struct nse_lan_rxq_ctx *rlan_ctx,
		  u16 rxq_abs_id);

enum nse_status
nse_read_txq_ctx(struct nse_hw *hw, struct nse_lan_txq_ctx *tlan_ctx,
		  u16 txq_abs_id);

void nse_lan_rxq_ctx_dump(struct nse_hw *hw, u16 qid_pf, u16 qid_abs,
			  struct nse_lan_rxq_ctx *rlan_ctx, unsigned int dump_dword_bitmap);
void nse_lan_rxq_ctx_compare(struct nse_hw *hw, struct nse_lan_rxq_ctx *ctx_0,
			     struct nse_lan_rxq_ctx *ctx_1, unsigned int dword_num);

void nse_lan_txq_ctx_dump(struct nse_hw *hw, u16 qid_pf, u16 qid_abs,
			  struct nse_lan_txq_ctx *tlan_ctx, unsigned int dump_dword_bitmap);
void nse_lan_txq_ctx_compare(struct nse_hw *hw, struct nse_lan_txq_ctx *ctx_0,
			     struct nse_lan_txq_ctx *ctx_1, unsigned int dword_num);

enum nse_status
nse_read_lan_txcq_ctx(struct nse_hw *hw, struct nse_lan_txcq_ctx *cq_ctx,
		  u16 cq_abs_id);

enum nse_status
nse_write_lan_txcq_ctx(struct nse_hw *hw, struct nse_vsi *vsi, struct nse_lan_txcq_ctx *cq_ctx,
		  u16 cq_abs_id);

enum nse_status
nse_disable_lan_txcq(struct nse_hw *hw, struct nse_vsi *vsi, u16 cq_abs_id, u16 irqll_msix);

enum nse_status
nse_enable_lan_txcq(struct nse_hw *hw, struct nse_vsi *vsi, u16 cq_abs_id, u16 irqll_msix);

enum nse_status
nse_read_lan_txcq_status(struct nse_hw *hw, struct nse_vsi *vsi, u16 cq_abs_id, u16 *q_stat);

void nse_lan_txcq_ctx_dump(struct nse_hw *hw, u16 qid_pf, u16 qid_abs,
			   struct nse_lan_txcq_ctx *cq_ctx, unsigned int dump_dword_bitmap);
void nse_lan_txcq_ctx_compare(struct nse_hw *hw, struct nse_lan_txcq_ctx *ctx_0,
			      struct nse_lan_txcq_ctx *ctx_1, unsigned int dword_num);

enum nse_status
nse_conf_irqll_lanq(struct nse_hw *hw, u8 op, u8 qtype, u16 qid, u16 msix);

enum nse_status
nse_aq_request_reset_rdma(struct nse_hw *hw, bool reset_vsi, u16 vsi_abs_num);

enum nse_status
nse_aq_write_ddp(struct nse_hw *hw, const unsigned char *data, unsigned int data_len);

enum nse_status
nse_aq_lan_set_tso_hsb(struct nse_hw *hw, dma_addr_t dma_addr);

enum nse_status
nse_aq_read_or_clear_dma_chan_total_stats(struct nse_hw *hw, u8 read_or_clear,
					  struct nse_aqc_rc_dma_chan_total_stats *total_stats);

enum nse_status
nse_aq_read_or_clear_dma_chan_per_vsi_stats(struct nse_hw *hw, u16 vsi_abs_id, u8 read_or_clear,
					    struct nse_aqc_rc_dma_chan_per_vsi_stats *vsi_stats);

enum nse_status
nse_read_dma_chan_total_stats(struct nse_hw *hw,
			      struct nse_aqc_rc_dma_chan_total_stats *total_stats);

enum nse_status
nse_clear_dma_chan_total_stats(struct nse_hw *hw);

void
nse_dump_dma_chan_total_stats(struct nse_hw *hw, struct nse_aqc_rc_dma_chan_total_stats *stats);

enum nse_status
nse_read_dma_chan_per_vsi_stats(struct nse_hw *hw, u16 vsi_abs_id,
				struct nse_aqc_rc_dma_chan_per_vsi_stats *vsi_stats);

enum nse_status
nse_clear_dma_chan_per_vsi_stats(struct nse_hw *hw, u16 vsi_abs_id);

enum nse_status
nse_lan_set_rsc_ctrl(struct nse_hw *hw, u32 rsc_ctrl);

enum nse_status
nse_aqc_lan_set_logall(struct nse_hw *hw, struct nse_aqc_set_logall *ctrl_data);

enum nse_status
nse_lan_set_tdm_legacy_wb_mode(struct nse_hw *hw, u32 val);

bool nse_check_sq_alive(struct nse_hw *hw, struct nse_ctl_q_info *cq, u32 *sq_len_val);
bool nse_check_rq_alive(struct nse_hw *hw, struct nse_ctl_q_info *cq, u32 *rq_len_val);
void nse_fill_dflt_direct_cmd_desc(struct nse_aq_desc *desc, u8 opc_category, u8 opc_subcode);

enum nse_status
nse_aq_send_cmd(struct nse_hw *hw, struct nse_aq_desc *desc,
		void *buf, u16 buf_size, struct nse_sq_cd *cd);

enum nse_status
nse_aq_xchg_sw_fw_ver(struct nse_hw *hw);

enum nse_status
nse_aq_ping_fw(struct nse_hw *hw);

enum nse_status
nse_aq_adminq_shutdown(struct nse_hw *hw, bool drv_unloading);

enum nse_status
nse_aq_discover_func_caps(struct nse_hw *hw, void *buf, u16 buf_size);

enum nse_status
nse_get_caps(struct nse_hw *hw);

enum nse_status
nse_sanity_check_caps(struct nse_hw *hw);

enum nse_status
nse_aq_set_sriov_res(struct nse_hw *hw);

enum nse_status
nse_aq_unset_sriov_res(struct nse_hw *hw);

enum nse_status
nse_aq_query_stag_type(struct nse_hw *hw, u16 *stag_ethertype);

enum nse_status
nse_determine_stag_type(struct nse_hw *hw);

enum nse_status
nse_aq_read_chip_temperature(struct nse_hw *hw, int *temperature);

enum nse_status
nse_aq_fw_lldp_agent_get_status(struct nse_hw *hw, u32 *status);

enum nse_status
nse_aq_fw_lldp_agent_start_stop(struct nse_hw *hw, bool start_or_stop);

enum nse_status
nse_aq_fw_lldp_dcbx_subagent_get_status(struct nse_hw *hw, u32 *status);

enum nse_status
nse_aq_fw_lldp_dcbx_subagent_start_stop(struct nse_hw *hw, bool start_or_stop);

enum nse_status
nse_aq_qos_db_set_cfg(struct nse_hw *hw, struct nse_aqc_qos_db_cfg *cfg);

enum nse_status
nse_aq_qos_db_get_cfg(struct nse_hw *hw, struct nse_aqc_qos_db_cfg *cfg);

enum nse_status
nse_aq_qos_db_flush_disable(struct nse_hw *hw, struct nse_aqc_qos_db_flush_disable *fdis);

void
nse_dump_dcbcfg_and_dbcfg(struct nse_hw *hw,
						struct nse_dcbx_cfg *dcbcfg,
						struct nse_aqc_qos_db_cfg *dbcfg);

enum nse_status
nse_qos_db_flush_disable_this_lan(struct nse_hw *hw);

enum nse_status
nse_qos_db_flush_disable_this_channel(struct nse_hw *hw);

enum nse_status
nse_qos_db_flush_disable(struct nse_hw *hw);

enum nse_status
nse_aq_qos_db_get_stat_cnt(struct nse_hw *hw, struct nse_aqc_qos_db_stat_cnt *db_stat_cnt);

void
nse_qos_db_dump_stat_cnt(struct nse_hw *hw, struct nse_aqc_qos_db_stat_cnt *db_stat_cnt);

void
nse_dcbcfg_to_up_enforcement_registers(struct nse_hw *hw,
						struct nse_dcbx_cfg *dcbcfg,
						struct nse_aqc_qos_db_conf_up_enforcement *upe);

void
nse_dump_up_enforcement(struct nse_hw *hw,
						struct nse_aqc_qos_db_conf_up_enforcement *upe);

enum nse_status
nse_aq_qos_db_read_up_enforcement(struct nse_hw *hw,
				  struct nse_aqc_qos_db_conf_up_enforcement *cmd_data);

enum nse_status
nse_aq_qos_db_write_up_enforcement(struct nse_hw *hw,
				   struct nse_aqc_qos_db_conf_up_enforcement *cmd_data);

void nse_clear_pxe_mode(struct nse_hw *hw);

enum nse_status
nse_aq_set_itr_interval(struct nse_hw *hw, u16 irq_abs_id, u32 interval);

enum nse_status
nse_aq_set_intrl_interval(struct nse_hw *hw, u16 irq_abs_id, u32 interval);

enum nse_status
nse_aq_ptp_get_sys_time(struct nse_hw *hw, u32 *sec, u32 *nsec, u64 *ns);

enum nse_status
nse_aq_ptp_set_sys_time_by_nsec(struct nse_hw *hw, u64 ns);

enum nse_status
nse_aq_ptp_set_sys_time_by_sec_nsec(struct nse_hw *hw, u32 sec, u32 nsec);

enum nse_status
nse_aq_ptp_adj_sys_time_amber(struct nse_hw *hw, u32 sec, u32 nsec);

enum nse_status
nse_aq_ptp_adj_sys_time_ms(struct nse_hw *hw, u32 val_h, u32 val_l);

enum nse_status
nse_aq_ptp_get_control(struct nse_hw *hw, u32 *control);

enum nse_status
nse_aq_ptp_set_control(struct nse_hw *hw, u32 control);

enum nse_status
nse_aq_ptp_get_incval(struct nse_hw *hw, u32 *incval);

enum nse_status
nse_aq_ptp_set_incval(struct nse_hw *hw, u32 incval);

enum nse_status
nse_aq_ptp_get_addend(struct nse_hw *hw, u32 *addend);

enum nse_status
nse_aq_ptp_set_addend(struct nse_hw *hw, u32 addend);

enum nse_status
nse_aq_ptp_init(struct nse_hw *hw, struct nse_aqc_ptp_init *cmd_buf);

enum nse_status
nse_aq_ptp_read_tx_ts(struct nse_hw *hw, struct nse_aqc_ptp_rd_clr_tx_ts *cmd_buf);

enum nse_status
nse_aq_ptp_clear_tx_ts(struct nse_hw *hw, struct nse_aqc_ptp_rd_clr_tx_ts *cmd_buf);

enum nse_status
nse_aq_psr_set_ctrl(struct nse_hw *hw, struct nse_aqc_psr_set_ctrl *cmd_buf);

enum nse_status
nse_aq_manage_mac_read(struct nse_hw *hw, struct nse_aqc_manage_mac *buf);

enum nse_status
nse_manage_mac_read(struct nse_hw *hw, void *factory_addr, void *lmac_addr, void *wol_addr);

enum nse_status
nse_aq_manage_mac_write(struct nse_hw *hw, const u8 *addr, u16 wflags, u8 wol_mpe);

enum nse_status
nse_aq_set_port_params(struct nse_hw *hw, u16 bad_frame_vsi,
		       bool save_bad_pac, bool pad_short_pac);

enum nse_status
nse_aq_rss_get_ctl(struct nse_vsi *vsi, u32 *rssctl);

enum nse_status
nse_aq_rss_set_ctl(struct nse_vsi *vsi, u32 rssctl);

enum nse_status
nse_aq_rss_get_key(struct nse_vsi *vsi, u8 *key);

enum nse_status
nse_aq_rss_set_key(struct nse_vsi *vsi, u8 *key);

enum nse_status
nse_aq_rss_get_lut(struct nse_vsi *vsi, u16 lut_start, u16 lut_size, u16 *lut_data);

enum nse_status
nse_aq_rss_set_lut(struct nse_vsi *vsi, u16 lut_start, u16 lut_size, u16 *lut_data);

enum nse_status nse_clear_pf_cfg(struct nse_hw *hw);

enum nse_status
nse_aq_lmac_get_basic_cfg(struct nse_hw *hw, struct nse_aqc_lmac_get_set_basic_cfg *basic_cfg);

enum nse_status
nse_aq_lmac_set_basic_cfg(struct nse_hw *hw, struct nse_aqc_lmac_get_set_basic_cfg *basic_cfg);

enum nse_status
nse_aq_lmac_read_stats(struct nse_hw *hw, struct nse_aqc_lmac_stats *lmac_stats);

enum nse_status
nse_lmac_set_basic_cfg(struct nse_hw *hw);

enum nse_status
nse_lmac_set_basic_cfg_lm(struct nse_hw *hw, bool lb_ena);

void
nse_lmac_dump_stats(struct nse_hw *hw, struct nse_aqc_lmac_stats *lmac_stats);

enum nse_status
nse_lmac_phy_init_early(struct nse_hw *hw);

void
nse_lmac_phy_prepare_for_reset(struct nse_hw *hw, enum nse_reset_req reset_type);

enum nse_status
nse_lmac_phy_rebuild(struct nse_hw *hw, enum nse_reset_req reset_type);

void nse_lmac_phy_handle_event(struct nse_pf *pf, struct nse_rq_event_info *event);
void nse_test_phy_handle_link_event(struct nse_pf *pf, struct nse_rq_event_info *event);

void nse_lmac_phy_subtask(struct nse_pf *pf);

static inline bool nse_lmac_phy_ephy_type_supported(u32 ephy_type)	/* by this driver version */
{
	if (ephy_type == EPHY_TYPE_SFP || ephy_type == EPHY_TYPE_QSFP ||
	    ephy_type == EPHY_TYPE_GEN_1G)
		return true;
	else
		return false;
}

void nse_lmac_phy_ephy_reset_info(struct nse_hw *hw);

static inline void nse_lmac_phy_lock(struct nse_hw *hw)
{
	mutex_lock(&hw->port_info->lmac_phy_info.mtx);
}

static inline void nse_lmac_phy_unlock(struct nse_hw *hw)
{
	mutex_unlock(&hw->port_info->lmac_phy_info.mtx);
}

enum nse_status
nse_aq_test_phy_startup(struct nse_hw *hw);

enum nse_status
nse_aq_test_phy_get_link_status(struct nse_hw *hw, u32 *ls, u32 *speed);

enum nse_status
nse_aq_test_phy_set_loopback(struct nse_hw *hw, u32 lb);

enum nse_status
nse_aq_test_phy_get_lfc_adv(struct nse_hw *hw, struct nse_aqc_fpga_phy_get_lfc_adv *adv);

enum nse_status
nse_aq_test_phy_set_lfc_adv(struct nse_hw *hw, struct nse_aqc_fpga_phy_set_lfc_adv *adv);

enum nse_status
nse_test_phy_set_lfc_adv(struct nse_hw *hw, enum nse_fc_mode req_mode, bool force_an, bool wait_an);

enum nse_status
nse_aq_eth_get_link_status(struct nse_hw *hw, struct nse_aqc_eth_get_link_status *lk_sts);

unsigned int nse_get_link_speed_kbps(struct nse_hw *hw);
unsigned int nse_get_link_speed_mbps(struct nse_hw *hw);

enum nse_status
nse_lmac_phy_ephy_read_temperature(struct nse_hw *hw, int *temperature);

void nse_lmac_phy_ephy_dump_info(struct nse_hw *hw);

void nse_dump_caps(struct nse_hw *hw);

struct nse_q_ctx *
nse_get_lan_q_ctx(struct nse_hw *hw, u16 vsi_handle, u8 tc, u16 q_handle);

enum nse_status
nse_cfg_vsi_lan(struct nse_port_info *pi, u16 vsi_handle, u16 tc_bitmap,
		u16 *max_lanqs);

enum nse_status
nse_cfg_vsi_rdma(struct nse_port_info *pi, u16 vsi_handle, u16 tc_bitmap,
		 u16 *max_rdmaqs);

enum nse_status
nse_ena_vsi_txq(struct nse_port_info *pi, u16 vsi_handle, u8 tc, struct nse_ring *tx_ring,
		u32 *leaf_node_tnid);

enum nse_status
nse_dis_vsi_txq(struct nse_port_info *pi, u16 vsi_handle, u8 tc,
		u16 q_handle, u16 q_abs_id, u32 q_tnid);

enum nse_status
nse_ena_vsi_rdma_qset(struct nse_port_info *pi, u16 vsi_handle, u8 tc,
		      u16 rdma_qset_abs_id, u32 *leaf_node_tnid);

enum nse_status
nse_dis_vsi_rdma_qset(struct nse_port_info *pi, u32 leaf_node_tnid,
		      u16 rdma_qset_abs_id);

void
nse_replay_pre_init(struct nse_hw *hw,
					enum nse_reset_req reset_type);
void
nse_replay_post(struct nse_hw *hw,
				enum nse_reset_req reset_type);

enum nse_status
nse_replay_vsi(struct nse_hw *hw,
				u16 vsi_handle,
				enum nse_reset_req reset_type);

bool nse_fw_supports_lldp_fltr_ctrl(struct nse_hw *hw);
enum nse_status nse_lldp_fltr_add_remove(struct nse_hw *hw, u16 vsi_num, bool add);

enum nse_status
nse_aq_dbg_ping_fw_with_buf(struct nse_hw *hw, u8 *cmd_buf, u32 buf_len);

enum nse_status
nse_aq_dbg_ping_fw_rq_req(struct nse_hw *hw, u8 *cmd_buf, u32 buf_len);

void
nse_aq_handle_dbg_ping_fw_rq_rsp(struct nse_hw *hw, struct nse_rq_event_info *event);

enum nse_status
nse_aq_dbg_req_dummy_event(struct nse_hw *hw, u32 times, u32 interval);

void
nse_aq_handle_dbg_dummy_event(struct nse_hw *hw, struct nse_rq_event_info *event);

enum nse_status
nse_aq_dbg_rw_registers(struct nse_hw *hw, u32 reg_base_addr, u16 reg_cnt,
			u16 rw_flag, u32 *reg_values, unsigned int sq_send_cmd_flags);

enum nse_status
nse_switch_rpp_set_bypass(struct nse_hw *hw, bool en, u16 vsi_abs_num, u8 ll_tc_map);

void nse_high_reset_detect_on_oicr_swint(struct nse_hw *hw);
void nse_high_reset_detect_on_oicr_core_reset(struct nse_hw *hw);
enum nse_status nse_reset_wait_complete(struct nse_hw *hw, bool fwmng_locked,
					unsigned int wait_flags);

bool nse_is_two_lan_ports(struct nse_hw *hw);

/* aq-event from PF driver's viewpoint */
extern u16 nse_aqc_opc_test_phy_lse;

extern u16 nse_aqc_opc_event_lan_overflow;
extern u16 nse_aqc_opc_send_msg_to_pf;
extern u16 nse_aqc_opc_qos_dcbx_cfg_chg_event;
extern u16 nse_aqc_opc_dbg_ping_fw_rq_rsp;
extern u16 nse_aqc_opc_dbg_dummy_event;
extern u16 nse_aqc_opc_fdir_reinit_event;
extern u16 nse_aqc_opc_ptp_tx_ts_event;
extern u16 nse_aqc_opc_vflr_event;

#endif /* _NSE_COMMON_H_ */

