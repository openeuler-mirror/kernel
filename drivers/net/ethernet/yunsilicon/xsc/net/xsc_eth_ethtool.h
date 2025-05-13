/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_ETH_ETHTOOL_H
#define XSC_ETH_ETHTOOL_H

void eth_set_ethtool_ops(struct net_device *dev);

/* EEPROM Standards for plug in modules */
#ifndef ETH_MODULE_SFF_8436_MAX_LEN
#define ETH_MODULE_SFF_8636_MAX_LEN     640
#define ETH_MODULE_SFF_8436_MAX_LEN     640
#endif

#define LED_ACT_ON_HW 0xff

#endif /* XSC_ETH_ETHTOOL_H */
