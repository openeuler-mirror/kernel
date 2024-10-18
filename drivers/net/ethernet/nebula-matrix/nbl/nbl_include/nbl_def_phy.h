/* SPDX-License-Identifier: GPL-2.0*/
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#ifndef _NBL_DEF_PHY_H_
#define _NBL_DEF_PHY_H_

#include "nbl_include.h"

#define NBL_PHY_OPS_TBL_TO_OPS(phy_ops_tbl)		((phy_ops_tbl)->ops)
#define NBL_PHY_OPS_TBL_TO_PRIV(phy_ops_tbl)		((phy_ops_tbl)->priv)

struct nbl_phy_ops {
	int (*init_chip_module)(void *priv, u8 eth_speed, u8 eth_num);
	int (*get_firmware_version)(void *priv, char *firmware_verion);
	int (*flow_init)(void *priv);
	int (*init_qid_map_table)(void *priv);
	int (*set_qid_map_table)(void *priv, void *data, int qid_map_select);
	int (*set_qid_map_ready)(void *priv, bool ready);
	int (*cfg_ipro_queue_tbl)(void *priv, u16 queue_id, u16 vsi_id, u8 enable);
	int (*cfg_ipro_dn_sport_tbl)(void *priv, u16 vsi_id, u16 dst_eth_id, u16 bmode, bool binit);
	int (*set_vnet_queue_info)(void *priv, struct nbl_vnet_queue_info_param *param,
				   u16 queue_id);
	int (*clear_vnet_queue_info)(void *priv, u16 queue_id);
	int (*cfg_vnet_qinfo_log)(void *priv, u16 queue_id, bool vld);
	int (*reset_dvn_cfg)(void *priv, u16 queue_id);
	int (*reset_uvn_cfg)(void *priv, u16 queue_id);
	int (*restore_dvn_context)(void *priv, u16 queue_id, u16 split, u16 last_avail_index);
	int (*restore_uvn_context)(void *priv, u16 queue_id, u16 split, u16 last_avail_index);
	int (*get_tx_queue_cfg)(void *priv, void *data, u16 queue_id);
	int (*get_rx_queue_cfg)(void *priv, void *data, u16 queue_id);
	int (*cfg_tx_queue)(void *priv, void *data, u16 queue_id);
	int (*cfg_rx_queue)(void *priv, void *data, u16 queue_id);
	bool (*check_q2tc)(void *priv, u16 queue_id);
	int (*cfg_q2tc_netid)(void *priv, u16 queue_id, u16 netid, u16 vld);
	int (*cfg_q2tc_tcid)(void *priv, u16 queue_id, u16 tcid);
	int (*set_tc_wgt)(void *priv, u16 func_id, u8 *weight, u16 num_tc);
	int (*set_tc_spwrr)(void *priv, u16 func_id, u8 spwrr);
	int (*set_shaping)(void *priv, u16 func_id, u64 total_tx_rate, u8 vld, bool active);
	void (*active_shaping)(void *priv, u16 func_id);
	void (*deactive_shaping)(void *priv, u16 func_id);
	int (*cfg_dsch_net_to_group)(void *priv, u16 func_id, u16 group_id, u16 vld);
	int (*cfg_dsch_group_to_port)(void *priv, u16 group_id, u16 dport, u16 vld);
	int (*init_epro_rss_key)(void *priv);
	void (*read_rss_key)(void *priv, u8 *rss_key);
	void (*read_rss_indir)(void *priv, u16 vsi_id, u32 *rss_indir,
			       u16 rss_ret_base, u16 rss_entry_size);
	void (*get_rss_alg_sel)(void *priv, u8 eth_id, u8 *rss_alg_sel);
	int (*init_epro_vpt_tbl)(void *priv, u16 vsi_id);
	int (*set_epro_rss_default)(void *priv, u16 vsi_id);
	int (*cfg_epro_rss_ret)(void *priv, u32 index, u8 size_type, u32 q_num, u16 *queue_list);
	int (*set_epro_rss_pt)(void *priv, u16 vsi_id, u16 rss_ret_base, u16 rss_entry_size);
	int (*clear_epro_rss_pt)(void *priv, u16 vsi_id);
	int (*disable_dvn)(void *priv, u16 queue_id);
	int (*disable_uvn)(void *priv, u16 queue_id);
	int (*lso_dsch_drain)(void *priv, u16 queue_id);
	int (*rsc_cache_drain)(void *priv, u16 queue_id);
	u16 (*save_dvn_ctx)(void *priv, u16 queue_id, u16 split);
	u16 (*save_uvn_ctx)(void *priv, u16 queue_id, u16 split, u16 queue_size);
	void (*get_rx_queue_err_stats)(void *priv, u16 queue_id,
				       struct nbl_queue_err_stats *queue_err_stats);
	void (*get_tx_queue_err_stats)(void *priv, u16 queue_id,
				       struct nbl_queue_err_stats *queue_err_stats);
	void (*setup_queue_switch)(void *priv, u16 eth_id);
	void (*init_pfc)(void *priv, u8 ether_ports);
	u32 (*get_chip_temperature)(void *priv);

	int (*cfg_epro_vpt_tbl)(void *priv, u16 vsi_id);
	void (*set_promisc_mode)(void *priv, u16 vsi_id, u16 eth_id, u16 mode);
	void (*configure_msix_map)(void *priv, u16 func_id, bool valid, dma_addr_t dma_addr,
				   u8 bus, u8 devid, u8 function);
	void (*configure_msix_info)(void *priv, u16 func_id, bool valid, u16 interrupt_id,
				    u8 bus, u8 devid, u8 function, bool net_msix_mask_en);
	void (*get_msix_resource)(void *priv, u16 func_id, u16 *msix_base, u16 *msix_max);
	void (*get_coalesce)(void *priv, u16 interrupt_id, u16 *pnum, u16 *rate);
	void (*set_coalesce)(void *priv, u16 interrupt_id, u16 pnum, u16 rate);

	void (*update_mailbox_queue_tail_ptr)(void *priv, u16 tail_ptr, u8 txrx);
	void (*config_mailbox_rxq)(void *priv, dma_addr_t dma_addr, int size_bwid);
	void (*config_mailbox_txq)(void *priv, dma_addr_t dma_addr, int size_bwid);
	void (*stop_mailbox_rxq)(void *priv);
	void (*stop_mailbox_txq)(void *priv);
	u16 (*get_mailbox_rx_tail_ptr)(void *priv);
	bool (*check_mailbox_dma_err)(void *priv, bool tx);
	u32 (*get_host_pf_mask)(void *priv);
	u32 (*get_host_pf_fid)(void *priv, u8 func_id);
	void (*cfg_mailbox_qinfo)(void *priv, u16 func_id, u16 bus, u16 devid, u16 function);
	void (*enable_mailbox_irq)(void *priv, u16 func_id, bool enable_msix, u16 global_vector_id);
	void (*enable_abnormal_irq)(void *priv, bool enable_msix, u16 global_vector_id);
	void (*enable_msix_irq)(void *priv, u16 global_vector_id);
	u8 *(*get_msix_irq_enable_info)(void *priv, u16 global_vector_id, u32 *irq_data);
	void (*config_adminq_rxq)(void *priv, dma_addr_t dma_addr, int size_bwid);
	void (*config_adminq_txq)(void *priv, dma_addr_t dma_addr, int size_bwid);
	void (*stop_adminq_rxq)(void *priv);
	void (*stop_adminq_txq)(void *priv);
	void (*cfg_adminq_qinfo)(void *priv, u16 bus, u16 devid, u16 function);
	void (*enable_adminq_irq)(void *priv, bool enable_msix, u16 global_vector_id);
	void (*update_adminq_queue_tail_ptr)(void *priv, u16 tail_ptr, u8 txrx);
	u16 (*get_adminq_rx_tail_ptr)(void *priv);
	bool (*check_adminq_dma_err)(void *priv, bool tx);

	void (*update_tail_ptr)(void *priv, struct nbl_notify_param *param);
	u8* (*get_tail_ptr)(void *priv);

	int (*set_spoof_check_addr)(void *priv, u16 vsi_id, u8 *mac);
	int (*set_spoof_check_enable)(void *priv, u16 vsi_id, u8 enable);

	u8 __iomem * (*get_hw_addr)(void *priv, size_t *size);

	/* For leonis */
	int (*set_ht)(void *priv, u16 hash, u16 hash_other, u8 ht_table,
		      u8 bucket, u32 key_index, u8 valid);
	int (*set_kt)(void *priv, u8 *key, u32 key_index, u8 key_type);
	int (*search_key)(void *priv, u8 *key, u8 key_type);
	int (*add_tcam)(void *priv, u32 index, u8 *key, u32 *action, u8 key_type, u8 pp_type);
	void (*del_tcam)(void *priv, u32 index, u8 key_type, u8 pp_type);
	int (*add_mcc)(void *priv, u16 mcc_id, u16 prev_mcc_id, u16 action);
	void (*del_mcc)(void *priv, u16 mcc_id, u16 prev_mcc_id, u16 next_mcc_id);
	int (*init_fem)(void *priv);

	unsigned long (*get_fw_ping)(void *priv);
	void (*set_fw_ping)(void *priv, unsigned long ping);
	unsigned long (*get_fw_pong)(void *priv);
	void (*set_fw_pong)(void *priv, unsigned long pong);

	void (*get_reg_dump)(void *priv, u32 *data, u32 len);
	int (*get_reg_dump_len)(void *priv);
	int (*process_abnormal_event)(void *priv, struct nbl_abnormal_event_info *abnomal_info);
	u32 (*get_uvn_desc_entry_stats)(void *priv);
	void (*set_uvn_desc_wr_timeout)(void *priv, u16 timeout);

	int (*setup_loopback)(void *priv, u32 eth_id, u32 enable);
	int (*ctrl_port_led)(void *priv, u8 eth_id, enum nbl_led_reg_ctrl led_ctrl, u32 *led_reg);

	/* for board cfg */
	u32 (*get_fw_eth_num)(void *priv);
	u32 (*get_fw_eth_map)(void *priv);
	void (*get_board_info)(void *priv, struct nbl_board_port_info *board);
};

struct nbl_phy_ops_tbl {
	struct nbl_phy_ops *ops;
	void *priv;
};

int nbl_phy_init_leonis(void *p, struct nbl_init_param *param);
void nbl_phy_remove_leonis(void *p);

#endif
