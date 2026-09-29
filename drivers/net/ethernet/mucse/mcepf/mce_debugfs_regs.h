/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2024-2026 Mucse Corporation. */

#ifndef MCE_DEBUGFS_REGS_H
#define MCE_DEBUGFS_REGS_H

int sprint_n20_rx_queue_states(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			       int buf_sz);

int debugfs_rx_states_show(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			   int buf_sz);
int debugfs_tx_states_show(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			   int buf_sz);
int debugfs_tx_queue_show(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			  int buf_sz);

int debugfs_rx_queue_show(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			  int buf_sz);
int mce_debugfs_queue_write(struct mce_pf *pf, struct mce_hw *hw, char *buf,
			    size_t count);

int fd_rx_debug_show(struct mce_pf *pf, struct mce_hw *hw, char *buf,
		     int buf_sz);
int fd_query_rule_show(struct mce_pf *pf, struct mce_hw *hw, char *buf,
		       int buf_sz);
int tc_states_show(struct mce_pf *pf, struct mce_hw *hw, char *buf,
		   int buf_sz);
int hwpfc_states_show(struct mce_pf *pf, struct mce_hw *hw, char *buf,
		      int buf_sz);
int hwets_states_show(struct mce_pf *pf, struct mce_hw *hw, char *buf,
		      int buf_sz);

#endif /* MCE_DEBUGFS_REGS_H */
