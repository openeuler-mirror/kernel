// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024-2026 Mucse Corporation. */

#include "mce.h"
#include "mce_dcb.h"
#include "mce_n20/mce_hw_n20.h"
/**
 * mce_dcb_tc_default - Set the default configuration for the tc
 * @tccfg: traffic class configuration to initialize
 */
void mce_dcb_tc_default(struct mce_tc_cfg *tccfg)
{
	memset(tccfg, 0, sizeof(*tccfg));
}

void mce_dcb_pfc_default(struct mce_pfc_cfg *pfccfg)
{
	u32 head = 0;
	/* fifo deep = tail - head + 1 */
	u32 tail = 0;
	u32 val;
	int i;

	pfccfg->pfccap = MCE_MAX_PRIORITY;
	pfccfg->pfcena = 0;
	/* setup default head and tail */
	val = 0;
	head = 0;
	tail = N20_FIFO0_DFT_DEEP - 1;
	MODIFY_BITFIELD(val, head, 16, 16);
	MODIFY_BITFIELD(val, tail, 16, 0);
	pfccfg->fifo_head[0] = head;
	pfccfg->fifo_tail[0] = tail;
	pfccfg->fifo_depth[0] = tail - head + 1;
	/* Configure the size of space used for FIFO 1-7 */
	for (i = 1; i < 8; i++) {
		u32 tmp_deep = 16;

		head = tail + 1;
		tail = head + tmp_deep - 1;
		MODIFY_BITFIELD(val, head, 16, 16);
		MODIFY_BITFIELD(val, tail, 16, 0);

		pfccfg->fifo_head[i] = head;
		pfccfg->fifo_tail[i] = tail;
		pfccfg->fifo_depth[i] = tail - head + 1;
	}
}

/**
 * mce_dcb_ets_default - Set the default configuration for the ets
 * @etscfg: ETS configuration to initialize
 */
void mce_dcb_ets_default(struct mce_ets_cfg *etscfg)
{
	u8 def_prio_tc[MCE_MAX_PRIORITY] = {
		0, 0, 0, 0, 0, 0, 0, 0
	};
	u8 i = 0;

	etscfg->ets_cap = MCE_MAX_TC_CNT;

	for (i = 0; i < MCE_MAX_PRIORITY; i++)
		etscfg->prio_table[i] = def_prio_tc[i];

	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++) {
		etscfg->tcbwtable[i] = 0;
		etscfg->tsatable[i] = IEEE_8021QAZ_TSA_STRICT;
		clear_bit(i, etscfg->etc_state);
	}

	etscfg->tcbwtable[0] = 100;
	etscfg->tsatable[0] = IEEE_8021QAZ_TSA_ETS;
	etscfg->curtcs = 1;
	set_bit(0, etscfg->etc_state);
}

#ifdef CONFIG_DCB

bool is_default_etscfg(struct mce_ets_cfg *etscfg)
{
	u8 i = 0;

	for (i = 0; i < MCE_MAX_PRIORITY; i++) {
		if (etscfg->prio_table[i] != 0)
			return false;
	}

	/* test stop ets */
	if (etscfg->tcbwtable[0] == 100 &&
	    etscfg->tsatable[0] == IEEE_8021QAZ_TSA_ETS)
		return true;

	for (i = 0; i < MCE_MAX_PRIORITY; i++) {
		if (etscfg->tcbwtable[i] != 0 &&
		    etscfg->tsatable[0] != IEEE_8021QAZ_TSA_STRICT)
			return false;
	}

	return true;
}

int mce_dcb_update_swetscfg(struct mce_dcb *dcb)
{
	struct mce_ets_cfg *etscfg = &dcb->new_etscfg;
	struct mce_tc_cfg *tccfg = &dcb->new_tccfg;
	struct mce_pf *pf = dcb->back;
	struct mce_vsi *vsi = mce_get_main_vsi(pf);
	struct mce_hw *hw = &pf->hw;
	bool pfc_info_update = false;
	u16 i = 0, j = 0, k = 0;
	bool flag = false;
	u16 txq_rem = 0;
	int qg_base = 0;
	u16 q_base = 0;

	if (!test_bit(MCE_ETS_EN, dcb->flags)) {
		bool tmp_flag = false;

		/* pfc open before */
		if (test_bit(MCE_PFC_EN, dcb->flags)) {
			memcpy(&dcb->new_pfccfg,
			       &dcb->cur_pfccfg,
			       sizeof(dcb->cur_pfccfg));
			mce_dcb_update_swpfccfg(dcb);
			/* update pfc config to hw */
			tmp_flag = true;
		}

		if (test_bit(MCE_MQPRIO_CHANNEL, dcb->flags)) {
			memcpy(&dcb->new_tccfg,
			       &dcb->cur_tccfg,
			       sizeof(dcb->cur_tccfg));
			tmp_flag = true;
		}

		/* no ets or pfc */
		if (!tmp_flag)
			mce_dcb_tc_default(tccfg);

		return 0;
	}

	if (test_bit(MCE_PFC_EN, dcb->flags))
		pfc_info_update = true;

	memset(tccfg, 0, sizeof(*tccfg));

	etscfg->curtcs = 0;
	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++) {
		clear_bit(i, etscfg->etc_state);

		switch (etscfg->tsatable[i]) {
		case (IEEE_8021QAZ_TSA_ETS):
			set_bit(i, etscfg->etc_state);
			etscfg->curtcs++;
			break;
		case (IEEE_8021QAZ_TSA_STRICT):
			flag = false;

			/* don't set this to avoid set it too more */
			/* strict mode only valid if prio_table use this tc */
			for (j = 0; j < MCE_MAX_PRIORITY; j++) {
				if (etscfg->prio_table[j] == i)
					flag = true;
			}
			if (flag) {
				set_bit(i, etscfg->etc_state);
				etscfg->curtcs++;
			}

			break;
		default:
			return -EOPNOTSUPP;
		}
	}

	if (etscfg->curtcs > pf->num_max_tc) {
		dev_err(mce_pf_to_dev(pf),
			"out of range tc valid %d, only %d\n",
			etscfg->curtcs, pf->num_max_tc);
		return -EOPNOTSUPP;
	}

	/* ets used tc number */
	tccfg->tc_cnt = etscfg->curtcs;
	/* fixme */
	tccfg->ntc_cnt = etscfg->curtcs;

	/* Map TCS used by ets to the local device and
	 * set the percentage of local TCS
	 */
	/* map to local tc , consider only tc 0 3 valid ? no this case? */
	/* map 0 3  to local  0  1 */
	j = 0;
	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++) {
		if (test_bit(i, etscfg->etc_state)) {
			tccfg->etc_tc[i] = j;
			/* to check tsatable mode here */
			if (etscfg->tsatable[i] == IEEE_8021QAZ_TSA_STRICT)
				tccfg->tc_bw[j] = 0;
			else
				tccfg->tc_bw[j] = etscfg->tcbwtable[i];
			j++;
		}
	}

	/* Set priority i to correspond to the local tc.
	 * Calculate how many priorities there are in each tc
	 */
	for (i = 0; i < MCE_MAX_PRIORITY; i++) {
		u8 t = etscfg->prio_table[i];

		tccfg->prio_tc[i] = tccfg->etc_tc[t];
		tccfg->prio_ntc[i] = tccfg->etc_tc[t];
		tccfg->tc_prios_bit[tccfg->etc_tc[t]] |= (1 << i);
	}

	tccfg->qg_cnt = 0;

	/* Ensure that each tc has one QG */
	/* each tc min has one qg */
	/* should skip base */
	for (i = 0; i < tccfg->tc_cnt; i++) {
		/* only use vsi->num_txq_real is ok for each tc */
		tccfg->tc_qgs[i] = (u16)DIV_ROUND_UP(vsi->num_txq_real, MCE_MAX_QCNT_IN_QG);
		tccfg->qg_cnt += tccfg->tc_qgs[i];
	}
	tccfg->qg_base_off = (u16)DIV_ROUND_UP(vsi->num_tc_offset, MCE_MAX_QCNT_IN_QG);

	/* only do this if pfc enabled */
	if (pfc_info_update) {
		struct mce_pfc_cfg *pfccfg = &dcb->cur_pfccfg;

		for (i = 0; i < tccfg->tc_cnt; i++) {
			u16 min_queue = 0;
			u16 prio_cnt = 0;

			for (j = 0; j < IEEE_8021QAZ_MAX_TCS; j++) {
				if ((tccfg->tc_prios_bit[i] & (1 << j)) != 0) {
					if (vsi->valid_prio & (1 << j))
						prio_cnt++;
				}
				if ((tccfg->tc_prios_bit[i] & vsi->valid_prio) &
				    pfccfg->pfcena & (1 << j))
					min_queue++;
			}
			/* not all pro enabled pfc, add 1 for default */
			if (min_queue && prio_cnt != min_queue)
				min_queue++;

			tccfg->tc_prios_cnt[i] = prio_cnt;

			if (min_queue > vsi->num_txq_real) {
				dev_err(mce_pf_to_dev(pf),
					"The current number of queues is %u, "
						"which is not enough %d.(Priority-QG)\n",
						vsi->num_txq_real, min_queue);

				return -EINVAL;
			}
		}
	} else {
		for (i = 0; i < tccfg->tc_cnt; i++) {
			u16 prio_cnt = 0;

			for (j = 0; j < IEEE_8021QAZ_MAX_TCS; j++) {
				if ((tccfg->tc_prios_bit[i] & (1 << j)) != 0)
					if (vsi->valid_prio & (1 << j))
						prio_cnt++;
			}
			/* update for later use */
			tccfg->tc_prios_cnt[i] = prio_cnt;
		}
	}
	/* cal for qg_cnt */
	qg_base = 0;
	/* Calculate the number of queues in each QG */
	for (j = 0; j < tccfg->tc_cnt; j++) {
		/* for each tc */
		txq_rem = vsi->num_txq_real;
		for (i = 0; i < tccfg->tc_qgs[j]; i++) {
			tccfg->qg_qs[i + qg_base] = min_t(u16, MCE_MAX_QCNT_IN_QG,
							  txq_rem);
			txq_rem -= MCE_MAX_QCNT_IN_QG;
		}
		qg_base += tccfg->tc_qgs[j];
	}
	/* now all qgs is ok */

	/* Calculate the number of queues in each priority */
	k = 0;
	q_base = 0;
	for (i = 0; i < tccfg->tc_cnt; i++) {
		u16 qcnt_in_tc = 0;

		/* start from 0 qg */
		for (j = 0; j < tccfg->tc_qgs[i]; j++) {
			qcnt_in_tc += tccfg->qg_qs[k];
			k++;
		}

		/* only do this if pfc on */
		if (pfc_info_update) {
			if (tccfg->tc_prios_cnt[i] > qcnt_in_tc) {
				dev_err(mce_pf_to_dev(pf),
					"The current number of queues is %u, "
						"which is not enough.(Priority-Txq)\n",
						vsi->num_txq);
				dev_err(mce_pf_to_dev(pf),
					"%d tc prios_cnt %d qcnt_in_tc %d\n", i,
					tccfg->tc_prios_cnt[i], qcnt_in_tc);
				return -EINVAL;
			}
		}
		/* setup q_base and q_cnt */
		/* this is tc base and cunt */
		tccfg->ntc_txq_base[i] = q_base;
		tccfg->ntc_txq_cunt[i] = qcnt_in_tc;

		/* should also update pfc info for use if PFC open */
		/* for each prio in this tc, found prio base */
		if (pfc_info_update) {
			struct mce_pfc_cfg *pfccfg = &dcb->cur_pfccfg;
			u16 pfc_q_rem = qcnt_in_tc;
			u16 pfc_q_base = q_base;
			u16 pfc_q_count = 0;
			u16 pfc_en_c = 0;
			int z;

			for (j = 0; j < MCE_MAX_PRIORITY; j++) {
				/* if this prio is valid in this tc and enabled pfc */
				if (tccfg->tc_prios_bit[i] & (1 << j) &&
				    (pfccfg->pfcena & (1 << j))) {
					if (vsi->valid_prio & (1 << j))
						pfc_en_c++;
				}
			}
			/* if not all pro enable pfc in this tc, add 1 for default */
			if (pfc_en_c != tccfg->tc_prios_cnt[i])
				pfc_en_c++;

			for (j = 0; j < pfc_en_c; j++) {
				/* setup prio to queue map */
				pfc_q_count = (u16)DIV_ROUND_UP(pfc_q_rem,
						(pfc_en_c - j));

				tccfg->pfc_txq_base_temp[j] = pfc_q_base;
				tccfg->pfc_txq_count_temp[j] = pfc_q_count;

				/* if not the last one */
				if (j != (pfc_en_c - 1)) {
					pfc_q_rem  -= pfc_q_count;
					pfc_q_base += pfc_q_count;
				}
			}
			for (; j < MCE_MAX_PRIORITY; j++) {
				/* no used prio use the last queues */
				tccfg->pfc_txq_base_temp[j] = pfc_q_base;
				tccfg->pfc_txq_count_temp[j] = pfc_q_count;
			}

			z = 0;
			/* map to the real prio */
			for (j = 0; j < MCE_MAX_PRIORITY; j++) {
				/* prio valid in this tc */
				if (tccfg->tc_prios_bit[i] & (1 << j)) {
					if ((pfccfg->pfcena & vsi->valid_prio) &
					    (1 << j)) {
						tccfg->pfc_txq_base[i][j] =
							tccfg->pfc_txq_base_temp[z];
						tccfg->pfc_txq_count[i][j] =
							tccfg->pfc_txq_count_temp[z];
						z++;
					} else if (vsi->valid_prio & (1 << j)) {
						tccfg->pfc_txq_base[i][j] =
						tccfg->pfc_txq_base_temp[MCE_MAX_PRIORITY - 1];
						tccfg->pfc_txq_count[i][j] =
						tccfg->pfc_txq_count_temp[MCE_MAX_PRIORITY - 1];
					} else {
						tccfg->pfc_txq_base[i][j] = 0;
						tccfg->pfc_txq_count[i][j] = 0;
					}
				} else {
					/* should not used */
					tccfg->pfc_txq_base[i][j] = 0;
					tccfg->pfc_txq_count[i][j] = 0;
				}
			}
		}
	}

	/* Set the minimum and maximum bandwidth for each QG.
	 * The minimum bandwidth of ETS is divided equally into each QG
	 * by multiplying the current rate by the percentage of the tc.
	 * ETS has a maximum bandwidth of 0
	 */
	for (i = 0; i < MCE_MAX_QGS; i++) {
		tccfg->min_rate[i] = 0;
		tccfg->max_rate[i] = 0;
	}
	k = 0;
	/* cal each pg speed setup */
	/* skip this if in mqprio mode */
	if (test_bit(MCE_MQPRIO_CHANNEL, dcb->flags))
		goto skip_qg;
	for (i = 0; i < tccfg->tc_cnt; i++) {
		u32 min_per_qg = 0;
		u16 qg_per_tc = 0;
		u32 rate_rem = 0;

		qg_per_tc = tccfg->tc_qgs[i];
		/* update link speed */
		hw->qos.link_speed_old = hw->qos.link_speed;

		/* no limit speed */
		if (tccfg->tc_bw[i] == 0) {
				/* The maximum bandwidth of the SP type
				 * is the current rate
				 */
			for (j = 0; j < qg_per_tc; j++) {
				tccfg->min_rate[k] = max_t(int, hw->qos.link_speed / 25, 10);
				tccfg->max_rate[k] = 0;
				++k;
			}
			continue;
		}

		/* tccfg->tc_bw[i] in % of link_speed */
		rate_rem = (u32)(tccfg->tc_bw[i]) *
				(hw->qos.link_speed / 100);
		for (j = 0; j < qg_per_tc; j++) {
			min_per_qg = (u32)DIV_ROUND_UP(rate_rem,
						(qg_per_tc - j));
			/* should keep mqprio setup here */
			/* todo */
			tccfg->min_rate[k] = min_per_qg;
			tccfg->max_rate[k] = 0;
			++k;

			rate_rem -= min_per_qg;
		}
	}
skip_qg:
	return 0;
}

void mce_dcb_update_hwetscfg(struct mce_dcb *dcb)
{
	struct mce_pf *pf = dcb->back;
	struct mce_hw *hw = &pf->hw;
	struct mce_hw_operations *hw_ops = hw->ops;

	/* if close ets */
	if (!test_bit(MCE_ETS_EN, dcb->flags)) {
		hw_ops->disable_tc(hw);
		hw_ops->clr_q_to_tc(hw);
		hw_ops->disable_rdma_tc(hw);

		if (test_bit(MCE_PFC_EN, dcb->flags))
			mce_dcb_update_hwpfccfg(dcb);

		return;
	}

	hw_ops->disable_tc(hw);
	hw_ops->disable_rdma_tc(hw);
	hw_ops->set_qg_rate(hw, dcb);
	hw_ops->set_qg_ctrl(hw, dcb);
	hw_ops->set_tc_bw(hw, dcb);
	hw_ops->set_tc_bw_rdma(hw, dcb);
	hw_ops->enable_tc(hw, dcb);
	hw_ops->enable_rdma_tc(hw, dcb);
	hw_ops->set_q_to_tc(hw, dcb);
}

bool is_default_pfccfg(struct mce_pfc_cfg *pfccfg)
{
	if (pfccfg->pfcena != 0)
		return false;

	return true;
}

static int mce_dcb_update_swpfccfg_withets(struct mce_dcb *dcb)
{
	struct mce_pfc_cfg *pfccfg = &dcb->new_pfccfg;
	struct mce_tc_cfg *tccfg = &dcb->cur_tccfg;
	struct mce_pf *pf = dcb->back;
	struct mce_vsi *vsi = mce_get_main_vsi(pf);
	int k, q_base, j, i;
	u16 pfc_q_count = 0;
	int tc_prios_cnt_t;
	u16 pfc_en_c = 0;
	u16 pfc_q_base;
	u16 pfc_q_rem;
	int z;
	/* Calculate the number of queues in each priority */
	k = 0;
	q_base = 0;

	for (i = 0; i < tccfg->tc_cnt; i++) {
		u16 qcnt_in_tc = 0;

		/* start from 0 qg */
		for (j = 0; j < tccfg->tc_qgs[i]; j++) {
			qcnt_in_tc += tccfg->qg_qs[k];
			k++;
		}

		if (tccfg->tc_prios_cnt[i] > qcnt_in_tc) {
			dev_err(mce_pf_to_dev(pf),
				"The tc %d queues is %u, need %d "
				"which is not enough.(Priority-Txq)\n",
				i, vsi->num_txq_real, tccfg->tc_prios_cnt[i]);
			return -EINVAL;
		}
		/* setup q_base and q_cnt */

		pfc_q_rem = qcnt_in_tc;
		pfc_q_base = q_base;
		/* should also update pfc info for use if PFC open */
		/* for each prio in this tc, found prio base */
		pfc_en_c = 0;
		tc_prios_cnt_t = 0;

		for (j = 0; j < MCE_MAX_PRIORITY; j++) {
			/* if this prio is valid in this tc and enabled pfc */
			if ((tccfg->tc_prios_bit[i] & (1 << j)) && (pfccfg->pfcena & (1 << j))) {
				/* it is nic valid prio */
				if (vsi->valid_prio & (1 << j))
					pfc_en_c++;
			}
			if ((tccfg->tc_prios_bit[i] & vsi->valid_prio) & (1 << j))
				tc_prios_cnt_t++;
		}
		/* if not all pro enable pfc in this tc, add 1 for default */
		if (pfc_en_c != tc_prios_cnt_t)
			pfc_en_c++;

		for (j = 0; j < pfc_en_c; j++) {
			/* setup prio to queue map */
			pfc_q_count = (u16)DIV_ROUND_UP(pfc_q_rem,
					(pfc_en_c - j));
			tccfg->pfc_txq_base_temp[j] = pfc_q_base;
			tccfg->pfc_txq_count_temp[j] = pfc_q_count;

			/* if not the last one */
			if (j != (pfc_en_c - 1)) {
				pfc_q_rem  -= pfc_q_count;
				pfc_q_base += pfc_q_count;
			}
		}
		for (; j < MCE_MAX_PRIORITY; j++) {
			/* no used prio use the last queues */
			tccfg->pfc_txq_base_temp[j] = pfc_q_base;
			tccfg->pfc_txq_count_temp[j] = pfc_q_count;
		}

		z = 0;
		/* map to the real prio */
		for (j = 0; j < MCE_MAX_PRIORITY; j++) {
			/* prio valid in this tc */
			if (tccfg->tc_prios_bit[i] & (1 << j)) {
				if ((pfccfg->pfcena & vsi->valid_prio) & (1 << j)) {
					tccfg->pfc_txq_base[i][j] = tccfg->pfc_txq_base_temp[z];
					tccfg->pfc_txq_count[i][j] = tccfg->pfc_txq_count_temp[z];
					z++;
				} else if (vsi->valid_prio & (1 << j)) {
					tccfg->pfc_txq_base[i][j] =
						tccfg->pfc_txq_base_temp[MCE_MAX_PRIORITY - 1];
					tccfg->pfc_txq_count[i][j] =
						tccfg->pfc_txq_count_temp[MCE_MAX_PRIORITY - 1];
				} else {
					tccfg->pfc_txq_base[i][j] = 0;
					tccfg->pfc_txq_count[i][j] = 0;
				}
			} else {
				/* should not used */
				tccfg->pfc_txq_base[i][j] = 0;
				tccfg->pfc_txq_count[i][j] = 0;
			}
		}
	}
	return 0;
}

void mce_dcb_update_swpfccfg(struct mce_dcb *dcb)
{
	struct mce_pfc_cfg *pfccfg = &dcb->new_pfccfg;
	struct mce_tc_cfg *tccfg = &dcb->new_tccfg;
	struct mce_pf *pf = dcb->back;
	struct mce_vsi *vsi = mce_get_main_vsi(pf);
	u16 qcnt_per_prio = 0;
	u16 qcnt_base = 0;
	u16 qcnt_rem  = 0;
	u16 i = 0, j = 0;
	int enacnt_t = 0;
	int pfc_c;

	pfccfg->enacnt = 0;
	for (i = 0; i < MCE_MAX_PRIORITY; i++) {
		if (((pfccfg->pfcena & vsi->valid_prio) & (1 << i)) != 0)
			enacnt_t++;
		if ((pfccfg->pfcena & (1 << i)) != 0)
			pfccfg->enacnt++;
	}
	/* If ETS or MQPRIO is already enabled,
	 * there is no need to reassign queues.
	 */
	/* we should use ets setup */
	if (test_bit(MCE_ETS_EN, dcb->flags) ||
	    test_bit(MCE_MQPRIO_CHANNEL, dcb->flags)) {
		/* we only update pfc for each tc */
		mce_dcb_update_swpfccfg_withets(dcb);
		return;
	}
	/* should check queue number later */
	mce_dcb_tc_default(tccfg);

	/* if no pfc nothing todo */
	if (!test_bit(MCE_PFC_EN, dcb->flags))
		return;

	memset(tccfg, 0, sizeof(*tccfg));
	/* setup prio_ntc map */

	/* only pfc, we no need to open tc */

	/* All queues are divided into eight priorities */
	qcnt_rem = vsi->num_txq_real;

	/* qcnt_per_prio start from all */
	qcnt_per_prio = qcnt_rem;

	pfc_c = enacnt_t;

	/* add for 1 default */
	/* if not all nic prio pfc is on */
	if ((pfccfg->pfcena & vsi->valid_prio) != vsi->valid_prio) {
		if (pfc_c && pfc_c < MCE_MAX_PRIORITY)
			pfc_c++;
	}

	for (i = 0; i < pfc_c; i++) {
		/* setup prio to queue map */
		qcnt_per_prio = (u16)DIV_ROUND_UP(qcnt_rem,
					(pfc_c - i));
		tccfg->pfc_txq_base_temp[i] = qcnt_base;
		tccfg->pfc_txq_count_temp[i] = qcnt_per_prio;

		/* if not the last one */
		if (i != (pfc_c - 1)) {
			qcnt_rem  -= qcnt_per_prio;
			qcnt_base += qcnt_per_prio;
		}
	}

	for (; i < MCE_MAX_PRIORITY; i++) {
		/* no used prio use the last queues */
		tccfg->pfc_txq_base_temp[i] = qcnt_base;
		tccfg->pfc_txq_count_temp[i] = qcnt_per_prio;
	}

	j = 0;
	/* map to real prio */
	for (i = 0; i < MCE_MAX_PRIORITY; i++) {
		if (((pfccfg->pfcena & vsi->valid_prio) & (1 << i)) != 0) {
			tccfg->pfc_txq_base[0][i] = tccfg->pfc_txq_base_temp[j];
			tccfg->pfc_txq_count[0][i] = tccfg->pfc_txq_count_temp[j];
			j++;
		} else if (vsi->valid_prio & (1 << i)) {
			/* nic valid prio not open pfc */
			tccfg->pfc_txq_base[0][i] = tccfg->pfc_txq_base_temp[MCE_MAX_PRIORITY - 1];
			tccfg->pfc_txq_count[0][i] =
				tccfg->pfc_txq_count_temp[MCE_MAX_PRIORITY - 1];
		} else {
			/* nic not valid prio, no queue needed  */
			tccfg->pfc_txq_base[0][i] = 0;
			tccfg->pfc_txq_count[0][i] = 0;
		}
	}
	/* if not valid prio, we use other queues */
}

void mce_dcb_update_hwpfccfg(struct mce_dcb *dcb)
{
	struct mce_pf *pf = dcb->back;
	struct mce_hw *hw = &pf->hw;
	struct mce_hw_operations *hw_ops = hw->ops;

	if (!test_bit(MCE_PFC_EN, dcb->flags)) {
		hw_ops->disable_pfc(hw);
		hw_ops->clr_q_to_pfc(hw);
		return;
	}

	hw_ops->enable_pfc(hw, dcb);
	hw_ops->set_q_to_pfc(hw, dcb);
}

#endif /* CONFIG_DCB */
