/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_DCB_LIB_H_
#define _NSE_DCB_LIB_H_

#include "nse.h"
#include "nse_base.h"
#include "nse_lib.h"

#ifdef CONFIG_DCB
#define NSE_TC_MAX_BW		100 /* Default Max BW percentage */
#define NSE_DCB_HW_CHG_RST	0 /* DCB configuration changed with reset */
#define NSE_DCB_NO_HW_CHG	1 /* DCB configuration did not change */
#define NSE_DCB_HW_CHG		2 /* DCB configuration changed, no reset */

bool nse_dcb_sanity_check_tc(struct nse_pf *pf, struct nse_dcbx_cfg *dcbcfg);
u8 nse_dcb_get_num_tc(struct nse_dcbx_cfg *dcbcfg);
u8 nse_dcb_get_ena_tc(struct nse_dcbx_cfg *dcbcfg);

void nse_dcb_rebuild(struct nse_pf *pf, enum nse_reset_req reset_type);
int nse_dcb_sw_dflt_cfg(struct nse_pf *pf, bool ets_willing, bool set_all, bool locked);
void nse_vsi_set_dcb_tc_cfg(struct nse_vsi *vsi);
bool nse_is_pfc_causing_hung_q(struct nse_pf *pf, unsigned int txqueue);
u8 nse_dcb_get_tc(struct nse_vsi *vsi, int queue_index);

u32 nse_dcb_need_recfg(struct nse_pf *pf, struct nse_dcbx_cfg *old_cfg,
		   struct nse_dcbx_cfg *new_cfg);

int nse_pf_dcb_cfg(struct nse_pf *pf, struct nse_dcbx_cfg *new_cfg, bool set_all, bool locked);
int nse_pf_dcb_cfg_lw(struct nse_pf *pf, struct nse_dcbx_cfg *new_cfg,
		      u32 cfg_chg_type, bool locked);

int nse_dcb_bwchk(struct nse_pf *pf, struct nse_dcbx_cfg *dcbcfg);
void nse_pf_dcb_recfg(struct nse_pf *pf);
void nse_vsi_cfg_dcb_rings(struct nse_vsi *vsi);
int nse_init_pf_dcb(struct nse_pf *pf, bool set_all, bool locked);
void nse_update_dcb_stats(struct nse_pf *pf);
void
nse_tx_prepare_vlan_flags_dcb(struct nse_ring *tx_ring,
			      struct nse_tx_buf *first);
void
nse_setup_dcb_qos_info(struct nse_pf *pf, struct iidc_qos_params *qos_info);
void
nse_dcb_process_dcbx_cfg_chg_event(struct nse_pf *pf,
				    struct nse_rq_event_info *event);

/**
 * nse_find_q_in_range
 * @low: start of queue range for a TC i.e. offset of TC
 * @high: start of queue for next TC
 * @tx_q: hung_queue/tx_queue
 *
 * finds if queue 'tx_q' falls between the two offsets of any given TC
 */
static inline bool nse_find_q_in_range(u16 low, u16 high, unsigned int tx_q)
{
	return (tx_q >= low) && (tx_q < high);
}

static inline bool nse_is_dcb_active(struct nse_pf *pf)
{
	return test_bit(NSE_FLAG_DCB_ENA, pf->flags);
}

#else
static inline void nse_dcb_rebuild(struct nse_pf *pf, enum nse_reset_req reset_type) { }
static inline void nse_vsi_set_dcb_tc_cfg(struct nse_vsi *vsi)
{
	vsi->tc_cfg.ena_tc = NSE_DFLT_TRAFFIC_CLASS;
	vsi->tc_cfg.numtc = 1;
}

static inline u8 nse_get_first_droptc(struct nse_vsi __always_unused *vsi)
{
	return 0;
}

static inline u8
nse_dcb_get_tc(struct nse_vsi __always_unused *vsi,
	       int __always_unused queue_index)
{
	return 0;
}

static inline int
nse_init_pf_dcb(struct nse_pf *pf, bool set_all, bool __always_unused locked)
{
	dev_dbg(nse_pf_to_dev(pf), "DCB not supported\n");
	return -EOPNOTSUPP;
}

static inline int
nse_pf_dcb_cfg(struct nse_pf __always_unused *pf,
	       struct nse_dcbx_cfg __always_unused *new_cfg,
	       bool set_all, bool __always_unused locked)
{
	return -EOPNOTSUPP;
}

static inline int
nse_tx_prepare_vlan_flags_dcb(struct nse_ring __always_unused *tx_ring,
			      struct nse_tx_buf __always_unused *first)
{
	return 0;
}

static inline bool nse_is_dcb_active(struct nse_pf __always_unused *pf)
{
	return false;
}

static inline bool
nse_is_pfc_causing_hung_q(struct nse_pf __always_unused *pf,
			  unsigned int __always_unused txqueue)
{
	return false;
}

static inline void nse_pf_dcb_recfg(struct nse_pf *pf) { }
static inline void nse_vsi_cfg_dcb_rings(struct nse_vsi *vsi) { }
static inline void nse_update_dcb_stats(struct nse_pf *pf) { }
static inline void
nse_setup_dcb_qos_info(struct nse_pf *pf, struct iidc_qos_params *qos_info) { }
static inline void
nse_dcb_process_dcbx_cfg_chg_event(struct nse_pf *pf,
				    struct nse_rq_event_info *event) { }
#endif /* CONFIG_DCB */

#define NSE_DCB_CFG_CHG_TYPE_TC				BIT(0)	/* enabled TC changes */
/* enabled TC not change, but up2tc mapping changes */
#define NSE_DCB_CFG_CHG_TYPE_UP2TC			BIT(1)
#define NSE_DCB_CFG_CHG_TYPE_TC_TSA_BW		BIT(2)	/* TC's TSA or ets bandwidth change */
#define NSE_DCB_CFG_CHG_TYPE_PFC			BIT(3)	/* PFC change */

/* lightweight changes --- no need to close / re-open VSI to renew Q/TX mapping
 *
 *		no enabled TC number change
 *
 *		only:
 *			up2tc mapping changes
 *			TC's TSA or ets bandwidth change
 *			PFC change
 */
#define NSE_DCB_CFG_CHG_TYPE_LIGHTWEIGHT_SET	\
	(NSE_DCB_CFG_CHG_TYPE_UP2TC | NSE_DCB_CFG_CHG_TYPE_TC_TSA_BW | \
	 NSE_DCB_CFG_CHG_TYPE_PFC)

#define NSE_DCB_CFG_CHG_ALL					0xFFFFFFFF

#endif /* _NSE_DCB_LIB_H_ */
