// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2021, NEBULARMATRIX */

#include <rdma/nbl-abi.h>
#include "debug.h"
#include "pd.h"
#include "umr.h"

/*
 * initialize sc_pd struct
 */
static void nbl_sc_pd_init(struct nbl_sc_dev *dev, struct nbl_sc_pd *pd,
			   u32 pd_id)
{
	pd->pd_id = pd_id;
	pd->dev = dev;
}

/*
 * allocate protection domain
 */
int nbl_ib_alloc_pd(struct ib_pd *pd, struct ib_udata *udata)
{
	struct nbl_pd *nbl_pd = to_nbl_pd(pd);
	struct nbl_device *nbl_dev = to_nbl_dev(pd->device);
	struct nbl_sc_dev *dev = &nbl_dev->rf->sc_dev;
	struct nbl_pci_f *rf = nbl_dev->rf;
	struct nbl_ib_alloc_pd_resp resp = {};
	struct nbl_sc_pd *sc_pd = &nbl_pd->sc_pd;
	struct nbl_ucontext *uctx = rdma_udata_to_drv_context(udata, struct nbl_ucontext,
					 ibucontext);

	u32 pd_id = 0;
	int err;

	/* alloc pd id resource */
	err = nbl_alloc_rsrc(&rf->rsrc_lock, rf->allocated_pds, rf->max_pd, &pd_id,
			     &rf->next_pd);

	if (err) {
		nbl_ib_err(dev, "alloc pd id resource failed.\n");
		return err;
	}

	nbl_sc_pd_init(dev, sc_pd, pd_id);

	if (udata) {
		resp.pd_id = pd_id;

		/* copy data of resp to udata */
		if (ib_copy_to_udata(udata, &resp,
				     min(sizeof(resp), udata->outlen))) {
			err = -EFAULT;
			nbl_ib_err(dev, "copy data failed.\n");
			nbl_free_rsrc(&rf->rsrc_lock, rf->allocated_pds, pd_id);
			return err;
		}

		nbl_pd->uctx = uctx;
	}

	err = nbl_create_umr_qp(nbl_dev, nbl_pd);
	if (err) {
		nbl_ib_err(dev, "create umr qp failed\n");
		nbl_free_rsrc(&rf->rsrc_lock, rf->allocated_pds, pd_id);
		err = -EFAULT;
		return err;
	}

	return 0;
}

/*
 * free a protection domain
 */
int nbl_ib_dealloc_pd(struct ib_pd *pd, struct ib_udata *udata)
{
	const struct nbl_pd *nbl_pd = to_nbl_pd(pd);
	struct nbl_device *nbl_dev = to_nbl_dev(pd->device);

	nbl_destroy_umr_qp(nbl_pd);

	nbl_free_rsrc(&nbl_dev->rf->rsrc_lock, nbl_dev->rf->allocated_pds,
		      nbl_pd->sc_pd.pd_id);

	return 0;
}
