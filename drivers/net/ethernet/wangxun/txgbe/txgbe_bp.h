/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2015 - 2025 Beijing WangXun Technology Co., Ltd. */

#ifndef _TXGBE_BP_H_
#define _TXGBE_BP_H_

#include "txgbe.h"
#include "txgbe_type.h"
#include "txgbe_hw.h"
#include "txgbe_bp_base.h"

void txgbe_bp_down_event(struct txgbe_adapter *adapter);
void txgbe_bp_watchdog_event(struct txgbe_adapter *adapter);
void txgbe_bp_close_protect(struct txgbe_adapter *adapter);
int handle_bkp_an73_flow(unsigned char bp_link_mode, struct txgbe_adapter *adapter);
int get_bkp_an73_ability(struct bkpan73ability *pt_bkp_an73_ability,
				 unsigned char by_link_partner,
							struct txgbe_adapter *adapter);
#endif
