/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2024-2026 Mucse Corporation. */

#ifndef _MCE_DCBNL_H_
#define _MCE_DCBNL_H_

#ifdef CONFIG_DCB
void mce_set_dcbnl_ops(struct net_device *netdev);
void mce_dcbnl_set_app(struct mce_dcb *dcb,
		       struct net_device *netdev);
void mce_dcbnl_del_app(struct mce_dcb *dcb,
		       struct net_device *netdev);
int mce_dcbnl_getets(struct net_device *netdev,
		     struct ieee_ets *ets);
int mce_dcbnl_getpfc(struct net_device *netdev,
		     struct ieee_pfc *pfc);
void mce_recover_dcb(struct mce_pf *pf);
void mce_force_close_dcb(struct mce_pf *pf);
#else
static inline void mce_set_dcbnl_ops(struct net_device *netdev)
{
}

static inline void mce_dcbnl_set_app(struct mce_dcb *dcb,
				     struct net_device *netdev)
{
}

static inline void mce_dcbnl_del_app(struct mce_dcb *dcb,
				     struct net_device *netdev)
{
}

static inline int mce_dcbnl_getets(struct net_device *netdev,
				   struct ieee_ets *ets)
{
	return -1;
}

static inline int mce_dcbnl_getpfc(struct net_device *netdev,
				   struct ieee_pfc *pfc)
{
	return -1;
}

static inline void mce_recover_dcb(struct mce_pf *pf)
{
}

static inline void mce_force_close_dcb(struct mce_pf *pf)
{
}
#endif /* CONFIG_DCB */

#endif /* _MCE_DCBNL_H_ */
