/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __YS_DEBUG_H_
#define __YS_DEBUG_H_

#include <linux/netdevice.h>
#include <linux/pci.h>
#include <linux/skbuff.h>

#define YS_HW_TYPE "CONFIG_YSHW_K2"
/* need add module_param */

#define ys_err(f, arg...) pr_err("%s: " f, YS_HW_TYPE, ##arg)
#define ys_info(f, arg...) pr_info("%s: " f, YS_HW_TYPE, ##arg)
#define ys_warn(f, arg...) pr_warn("%s: " f, YS_HW_TYPE, ##arg)
#define ys_debug(f, arg...) pr_debug("%s: " f, YS_HW_TYPE, ##arg)

#define ys_net_err(f, arg...) \
	netdev_err(ndev_priv->ndev, "%s: " f, YS_HW_TYPE, ##arg)
#define ys_net_info(f, arg...) \
	netdev_info(ndev_priv->ndev, "%s: " f, YS_HW_TYPE, ##arg)
#define ys_net_warn(f, arg...) \
	netdev_warn(ndev_priv->ndev, "%s: " f, YS_HW_TYPE, ##arg)
#define ys_net_debug(f, arg...) \
	netdev_dbg(ndev_priv->ndev, "%s: " f, YS_HW_TYPE, ##arg)

#define ys_dev_err(f, arg...) \
	dev_err(pdev_priv->dev, "%s: " f, YS_HW_TYPE, ##arg)
#define ys_dev_info(f, arg...) \
	dev_info(pdev_priv->dev, "%s: " f, YS_HW_TYPE, ##arg)
#define ys_dev_warn(f, arg...) \
	dev_warn(pdev_priv->dev, "%s: " f, YS_HW_TYPE, ##arg)
#define ys_dev_dbg(f, arg...) \
	dev_dbg(pdev_priv->dev, "%s: " f, YS_HW_TYPE, ##arg)

#define ys_dump_skb(skb, ndev)

#endif /* __YS_DEBUG_H_ */
