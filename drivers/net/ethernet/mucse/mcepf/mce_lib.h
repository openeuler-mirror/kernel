/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2024-2026 Mucse Corporation. */

#ifndef _MCE_LIB_H_
#define _MCE_LIB_H_

#include "mce.h"

#define __VLAN_ALLOWED(protocol)                          \
	(!!((protocol) == htons(ETH_P_8021Q) || \
	    (protocol) == htons(ETH_P_8021AD)))

#define MCE_INSERT_VLAN_CNT(pf) ((pf)->dvlan_ctrl.cnt)

/* VM RULE */
enum mce_misc_irq_act_type {
	__MISC_IRQ_TYPE_REGISTER_INTR_VEC,
	__MISC_IRQ_TYPE_SET_INTR_MASK,
	__MISC_IRQ_TYPE_GET_INTR_STAT,
	__MISC_IRQ_TYPE_CLR_INTR_STAT,
};

struct mce_res_tracker;

struct mce_vsi *mce_vsi_alloc(struct mce_pf *pf,
			      enum mce_vsi_type vsi_type);
void mce_vsi_free_stats(struct mce_vsi *vsi);
int mce_vsi_clear(struct mce_vsi *vsi);
void mce_vsi_cfg_netdev_tc(struct mce_vsi *vsi, struct mce_dcb *dcb);
void mce_vsi_dcb_default(struct mce_vsi *vsi);
int mce_vsi_recfg_qs(struct mce_vsi *vsi, int new_rx, int new_tx);
struct mce_vsi *mce_vsi_setup(struct mce_pf *pf,
			      enum mce_vsi_type vsi_type);
int mce_get_num_local_cpus(struct device *dev);
int mce_normalize_cpu_count(int num_cpus, struct mce_pf *pf);
const char *mce_vsi_type_str(enum mce_vsi_type vsi_type);
int mce_get_irq_res(struct mce_pf *pf, struct mce_res_tracker *res,
		    u16 needed, u16 start);
int mce_free_irq_res(struct mce_res_tracker *res, u16 needed, u16 start);
void mce_vsi_cfg_frame_size(struct mce_vsi *vsi);
int mce_vsi_release(struct mce_vsi *vsi);
void mce_vsi_release_all(struct mce_pf *pf);
void mce_vsi_get_q_vector_q_base(struct mce_vsi *vsi, u16 vector_id,
				 u16 *txq, u16 *rxq);
int mce_vsi_open(struct mce_vsi *vsi);
void mce_vsi_close(struct mce_vsi *vsi);
int mce_down(struct mce_vsi *vsi);
int mce_up(struct mce_vsi *vsi);
void mce_update_tx_ring_stats(struct mce_ring *tx_ring, u64 pkts,
			      u64 bytes);
void mce_update_rx_ring_stats(struct mce_ring *rx_ring, u64 pkts,
			      u64 bytes);
void mce_vsi_reapply_xps(struct mce_vsi *vsi);
void mce_vsi_free_tx_rings(struct mce_vsi *vsi);
void mce_vsi_free_rx_rings(struct mce_vsi *vsi);
int mce_vsi_rebuild(struct mce_vsi *vsi);
void mce_update_pf_stats(struct mce_pf *pf);
void mce_update_mac_stats(struct mce_pf *pf);
void mce_setup_L2_filter(struct mce_pf *pf);
int mce_set_bw_limit_init(struct mce_pf *pf);
int mce_set_max_bw_limit(struct mce_pf *pf, int vf_id, u64 max_tx_rate,
			 u16 ring_cnt);
int mce_set_rss_table(struct mce_hw *hw, u16 vf_id, u16 q_cnt);
void mce_realloc_and_fill_pfinfo(struct mce_pf *pf, bool sriov_on);
int mce_get_queue_affinity_cpu(struct device *dev, u16 q_index);
void mce_set_queue_affinity_mask(struct device *dev, u16 q_index,
				 struct cpumask *mask);

u64 mce_int_pow(u64 base, unsigned int exp);
#ifdef THREAD_POLL
int mce_poll_thread_handler(void *data);
#endif
bool mce_get_misc_irq_evt(struct mce_hw *hw, enum mce_misc_irq_type type);
int mce_setup_misc_irq(struct mce_hw *hw, bool en, int nr_vec);
int mce_pre_handle_misc_irq(struct mce_hw *hw,
			    enum mce_misc_irq_type type);
u16 mce_calc_mac_hash_val(struct mce_hw *hw, const u8 *addr, bool s_low);
void mce_vsi_close_hw_transmit(struct mce_vsi *vsi);
void mce_vsi_start_hw_transmit(struct mce_vsi *vsi);
bool mce_wait_rdma_script_done(struct mce_hw *hw);

#endif /* _MCE_LIB_H_ */
