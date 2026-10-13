/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2015 - 2025 Beijing WangXun Technology Co., Ltd. */
#ifndef _TXGBE_SP_H_
#define _TXGBE_SP_H_

int txgbe_set_sgmii_an37_ability(struct txgbe_hw *hw);
int txgbe_set_link_to_kr(struct txgbe_hw *hw, bool autoneg);
int txgbe_set_link_to_kx4(struct txgbe_hw *hw, bool autoneg);
int txgbe_set_link_to_kx(struct txgbe_hw *hw, u32 speed, bool autoneg);

#endif
