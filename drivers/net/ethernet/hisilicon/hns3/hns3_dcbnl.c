// SPDX-License-Identifier: GPL-2.0+
// Copyright (c) 2016-2017 Hisilicon Limited.

#include "hnae3.h"
#include "hns3_enet.h"

static int hns3_dcbnl_ieee_getets(struct net_device *ndev, struct ieee_ets *ets)
{
	struct hnae3_handle *h = hns3_get_handle(ndev);

	if (hns3_nic_resetting(ndev))
		return -EBUSY;

	if (h->kinfo.dcb_ops->ieee_getets)
		return h->kinfo.dcb_ops->ieee_getets(h, ets);

	return -EOPNOTSUPP;
}

static int hns3_dcbnl_ieee_setets(struct net_device *ndev, struct ieee_ets *ets)
{
	struct hnae3_handle *h = hns3_get_handle(ndev);

	if (hns3_nic_resetting(ndev))
		return -EBUSY;

	if (h->kinfo.dcb_ops->ieee_setets)
		return h->kinfo.dcb_ops->ieee_setets(h, ets);

	return -EOPNOTSUPP;
}

static int hns3_dcbnl_ieee_getpfc(struct net_device *ndev, struct ieee_pfc *pfc)
{
	struct hnae3_handle *h = hns3_get_handle(ndev);

	if (hns3_nic_resetting(ndev))
		return -EBUSY;

	if (h->kinfo.dcb_ops->ieee_getpfc)
		return h->kinfo.dcb_ops->ieee_getpfc(h, pfc);

	return -EOPNOTSUPP;
}

static int hns3_dcbnl_ieee_setpfc(struct net_device *ndev, struct ieee_pfc *pfc)
{
	struct hnae3_handle *h = hns3_get_handle(ndev);

	if (hns3_nic_resetting(ndev))
		return -EBUSY;

	if (h->kinfo.dcb_ops->ieee_setpfc)
		return h->kinfo.dcb_ops->ieee_setpfc(h, pfc);

	return -EOPNOTSUPP;
}

static int hns3_dcbnl_ieee_setapp(struct net_device *ndev, struct dcb_app *app)
{
	struct hnae3_handle *h = hns3_get_handle(ndev);

	if (hns3_nic_resetting(ndev))
		return -EBUSY;

	if (h->kinfo.dcb_ops->ieee_setapp)
		return h->kinfo.dcb_ops->ieee_setapp(h, app);

	return -EOPNOTSUPP;
}

static int hns3_dcbnl_ieee_delapp(struct net_device *ndev, struct dcb_app *app)
{
	struct hnae3_handle *h = hns3_get_handle(ndev);

	if (hns3_nic_resetting(ndev))
		return -EBUSY;

	if (h->kinfo.dcb_ops->ieee_delapp)
		return h->kinfo.dcb_ops->ieee_delapp(h, app);

	return -EOPNOTSUPP;
}

/* DCBX configuration */
static u8 hns3_dcbnl_getdcbx(struct net_device *ndev)
{
	struct hnae3_handle *h = hns3_get_handle(ndev);

	if (h->kinfo.dcb_ops->getdcbx)
		return h->kinfo.dcb_ops->getdcbx(h);

	return 0;
}

/* return 0 if successful, otherwise fail */
static u8 hns3_dcbnl_setdcbx(struct net_device *ndev, u8 mode)
{
	struct hnae3_handle *h = hns3_get_handle(ndev);

	if (h->kinfo.dcb_ops->setdcbx)
		return h->kinfo.dcb_ops->setdcbx(h, mode);

	return 1;
}

static int hns3_dcbnl_ieee_setmaxrate(struct net_device *netdev,
				      struct ieee_maxrate *maxrate)
{
	struct hnae3_handle *h = hns3_get_handle(netdev);

	if (h->kinfo.dcb_ops->ieee_setmaxrate)
		return h->kinfo.dcb_ops->ieee_setmaxrate(h, maxrate);

	return -EOPNOTSUPP;
}

static int hns3_dcbnl_ieee_getmaxrate(struct net_device *netdev,
				      struct ieee_maxrate *maxrate)
{
	struct hnae3_handle *h = hns3_get_handle(netdev);

	if (h->kinfo.dcb_ops->ieee_getmaxrate)
		return h->kinfo.dcb_ops->ieee_getmaxrate(h, maxrate);

	return -EOPNOTSUPP;
}

static int hns3_dcbnl_setbuffer(struct net_device *ndev, struct dcbnl_buffer *buffer)
{
	struct hnae3_handle *h = hns3_get_handle(ndev);

	if (hns3_nic_resetting(ndev))
		return -EBUSY;

	if (h->kinfo.dcb_ops->setbuffer)
		return h->kinfo.dcb_ops->setbuffer(h, buffer);

	return -EOPNOTSUPP;
}

static int hns3_dcbnl_getbuffer(struct net_device *ndev, struct dcbnl_buffer *buffer)
{
	struct hnae3_handle *h = hns3_get_handle(ndev);

	if (h->kinfo.dcb_ops->getbuffer)
		return h->kinfo.dcb_ops->getbuffer(h, buffer);

	return -EOPNOTSUPP;
}

static const struct dcbnl_rtnl_ops hns3_dcbnl_ops = {
	.ieee_getets	= hns3_dcbnl_ieee_getets,
	.ieee_setets	= hns3_dcbnl_ieee_setets,
	.ieee_getpfc	= hns3_dcbnl_ieee_getpfc,
	.ieee_setpfc	= hns3_dcbnl_ieee_setpfc,
	.ieee_setapp    = hns3_dcbnl_ieee_setapp,
	.ieee_delapp    = hns3_dcbnl_ieee_delapp,
	.ieee_setmaxrate    = hns3_dcbnl_ieee_setmaxrate,
	.ieee_getmaxrate    = hns3_dcbnl_ieee_getmaxrate,
	.getdcbx	= hns3_dcbnl_getdcbx,
	.setdcbx	= hns3_dcbnl_setdcbx,
	.dcbnl_getbuffer	= hns3_dcbnl_getbuffer,
	.dcbnl_setbuffer	= hns3_dcbnl_setbuffer,
};

static const struct dcbnl_rtnl_ops hns3_unic_dcbnl_ops = {
	.ieee_getets	= hns3_dcbnl_ieee_getets,
	.ieee_setets	= hns3_dcbnl_ieee_setets,
	.ieee_setapp	= hns3_dcbnl_ieee_setapp,
	.ieee_delapp	= hns3_dcbnl_ieee_delapp,
	.ieee_setmaxrate    = hns3_dcbnl_ieee_setmaxrate,
	.ieee_getmaxrate    = hns3_dcbnl_ieee_getmaxrate,
	.getdcbx	= hns3_dcbnl_getdcbx,
	.setdcbx	= hns3_dcbnl_setdcbx,
	.dcbnl_getbuffer	= hns3_dcbnl_getbuffer,
	.dcbnl_setbuffer	= hns3_dcbnl_setbuffer,
};

/* hclge_dcbnl_setup - DCBNL setup
 * @handle: the corresponding vport handle
 * Set up DCBNL
 */
void hns3_dcbnl_setup(struct hnae3_handle *handle)
{
	struct net_device *dev = handle->kinfo.netdev;

	if (!handle->kinfo.dcb_ops)
		return;

#ifdef CONFIG_HNS3_UBL
	if (hns3_ubl_supported(handle))
		dev->dcbnl_ops = &hns3_unic_dcbnl_ops;
	else
		dev->dcbnl_ops = &hns3_dcbnl_ops;
#else
	dev->dcbnl_ops = &hns3_dcbnl_ops;
#endif
}
