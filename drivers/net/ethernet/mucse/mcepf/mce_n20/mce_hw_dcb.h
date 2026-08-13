/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2024-2026 Mucse Corporation. */

#ifndef _MCE_HW_DCBNL_H_
#define _MCE_HW_DCBNL_H_

void n20_enable_tc(struct mce_hw *hw, struct mce_dcb *dcb);
void n20_disable_tc(struct mce_hw *hw);
void n20_enable_rdma_tc(struct mce_hw *hw, struct mce_dcb *dcb);
void n20_disable_rdma_tc(struct mce_hw *hw);
void n20_set_tc_bw(struct mce_hw *hw,
		   struct mce_dcb *dcb);
void n20_set_tc_bw_rdma(struct mce_hw *hw,
			struct mce_dcb *dcb);
void n20_set_qg_ctrl(struct mce_hw *hw,
		     struct mce_dcb *dcb);
void n20_set_qg_rate(struct mce_hw *hw,
		     struct mce_dcb *dcb);
void n20_set_q_to_tc(struct mce_hw *hw,
		     struct mce_dcb *dcb);
void n20_clr_q_to_tc(struct mce_hw *hw);
void n20_set_dft_fifo_space(struct mce_hw *hw);
void n20_enable_pfc(struct mce_hw *hw, struct mce_dcb *dcb);
void n20_setup_rx_buffer(struct mce_hw *hw);
void n20_disable_pfc(struct mce_hw *hw);
void n20_set_q_to_pfc(struct mce_hw *hw,
		      struct mce_dcb *dcb);
void n20_clr_q_to_pfc(struct mce_hw *hw);
void n20_set_dscp(struct mce_hw *hw, struct mce_dcb *dcb);

#endif /* _MCE_HW_DCBNL_H_ */
