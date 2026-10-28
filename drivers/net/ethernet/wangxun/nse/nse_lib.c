// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#include "nse.h"
#include "nse_base.h"
#include "nse_lib.h"
#include "nse_fltr.h"
#include "nse_dcb_lib.h"
#include "nse_devlink.h"
#include "nse_vsi_vlan_ops.h"
#include "nse_irq.h"
#include "nse_txrx_lib.h"

const char *nse_vsi_type_str(enum nse_vsi_type vsi_type)
{
	switch (vsi_type) {
	case NSE_VSI_PF:
		return "NSE_VSI_PF";
	case NSE_VSI_VF:
		return "NSE_VSI_VF";
	case NSE_VSI_OFFLOAD_MACVLAN:
		return "NSE_VSI_OFFLOAD_MACVLAN";
	case NSE_VSI_SWITCHDEV_CTRL:
		return "NSE_VSI_SWITCHDEV_CTRL";
	case NSE_VSI_LB:
		return "NSE_VSI_LB";
	case NSE_VSI_ADI:
		return "NSE_VSI_ADI";
	default:
		return "unknown";
	}
}

/**
 * nse_vsi_requires_vf - Does this VSI type always require a VF?
 * @vsi_type: the VSI type
 *
 * Returns true if the VSI type *must* have a VF pointer. Returns false
 * otherwise. In particular, VSI types which may *optionally* have a VF
 * pointer return false.
 *
 * Used to WARN in cases where we always expect a VF pointer to be non-NULL.
 */
static int nse_vsi_requires_vf(enum nse_vsi_type vsi_type)
{
	switch (vsi_type) {
	case NSE_VSI_ADI:
	case NSE_VSI_VF:
		return true;
	default:
		return false;
	}
}

/**
 * nse_vsi_setup_q_map - Setup a VSI queue map
 * @vsi: the VSI being configured
 * @ctxt: VSI context structure
 */
static int nse_vsi_setup_q_map(struct nse_vsi *vsi)
{
	struct nse_hw *hw = &vsi->back->hw;
	struct device *dev = nse_pf_to_dev(vsi->back);
	u16 offset = 0, tx_count = 0, rx_count = 0;
	u16 num_txq_per_tc, num_rxq_per_tc;
	u16 qcount_tx = vsi->alloc_txq;	/* VSI txq space size */
	u16 qcount_rx = vsi->alloc_rxq;	/* VSI txq space size */
	u8 netdev_tc = 0;
	int i;

	if (!vsi->tc_cfg.numtc) {
		/* at least TC0 should be enabled by default */
		vsi->tc_cfg.numtc = 1;
		vsi->tc_cfg.ena_tc = 1;
	}

	/* For VF VSI, all queues should be mapped to TC0 and other TCs are
	 * assigned to queue 0 by default
	 */
	if (vsi->type == NSE_VSI_VF) {
		num_rxq_per_tc = qcount_rx;
		num_txq_per_tc = qcount_tx;
	} else {
		num_rxq_per_tc = min_t(u16, qcount_rx / vsi->tc_cfg.numtc,
				       NSE_MAX_RXQS_PER_TC);
		if (!num_rxq_per_tc)
			num_rxq_per_tc = 1;
		num_txq_per_tc = qcount_tx / vsi->tc_cfg.numtc;
		if (!num_txq_per_tc)
			num_txq_per_tc = 1;
	}

	/* TC mapping is a function of the number of Rx queues assigned to the
	 * VSI for each traffic class and the offset of these queues.
	 * The first 10 bits are for queue offset for TC0, next 4 bits for no:of
	 * queues allocated to TC0. No:of queues is a power-of-2.
	 *
	 * If TC is not enabled, the queue offset is set to 0, and allocate one
	 * queue, this way, traffic for the given TC will be sent to the default
	 * queue.
	 *
	 * Setup number and offset of Rx queues for all TCs for the VSI
	 */
	nse_for_each_traffic_class(i) {
		if (!(vsi->tc_cfg.ena_tc & BIT(i)) ||
		    (i != 0 && vsi->type == NSE_VSI_VF)) {
			vsi->tc_cfg.tc_info[i].qoffset = 0;
			vsi->tc_cfg.tc_info[i].qcount_rx = 1;
			vsi->tc_cfg.tc_info[i].qcount_tx = 1;
			vsi->tc_cfg.tc_info[i].netdev_tc = 0;
			continue;
		}

		/* TC is enabled */
		vsi->tc_cfg.tc_info[i].qoffset = offset;
		vsi->tc_cfg.tc_info[i].qcount_rx = num_rxq_per_tc;
		vsi->tc_cfg.tc_info[i].qcount_tx = num_txq_per_tc;
		vsi->tc_cfg.tc_info[i].netdev_tc = netdev_tc++;

		offset += num_rxq_per_tc;
		tx_count += num_txq_per_tc;
	}

	/* if offset is non-zero, means it is calculated correctly based on
	 * enabled TCs for a given VSI otherwise qcount_rx will always
	 * be correct and non-zero because it is based off - VSI's
	 * allocated Rx queues which is at least 1 (hence qcount_tx will be
	 * at least 1)
	 */
	if (offset)
		rx_count = offset;
	else
		rx_count = num_rxq_per_tc;

	if (rx_count > vsi->alloc_rxq) {
		dev_err(dev, "Trying to use more Rx queues (%u), than were allocated (%u)!\n",
			rx_count, vsi->alloc_rxq);
		return -EINVAL;
	}

	if (tx_count > vsi->alloc_txq) {
		dev_err(dev, "Trying to use more Tx queues (%u), than were allocated (%u)!\n",
			vsi->num_txq, vsi->alloc_txq);
		return -EINVAL;
	}

	if (rx_count != vsi->num_rxq ||
		tx_count != vsi->num_txq) {
		dev_info(dev, "VSI->num_rxq,txq (enabled RXQ/TXQ count) changes, may due to DCB TC changes\n");
		dev_info(dev, "\t old num_rxq=%u, num_txq=%u", vsi->num_rxq, vsi->num_txq);
		dev_info(dev, "\t new num_rxq=%u, num_txq=%u", rx_count, tx_count);
	}

	vsi->num_rxq = rx_count;
	vsi->num_txq = tx_count;

	if (vsi->type == NSE_VSI_VF && vsi->num_txq != vsi->num_rxq) {
		dev_warn(dev, "VF VSI should have same number of Tx and Rx queues. Hence making them equal\n");
		/* since there is a chance that num_rxq could have been changed
		 * in the above for loop, make num_txq equal to num_rxq.
		 */
		vsi->num_txq = vsi->num_rxq;
	}

	if (vsi->sw_conf.lan_tx_use_cq) {
		/* would update in nse_vsi_map_txcq_rings_to_vectors() */
		vsi->num_txcq = vsi->alloc_txcq;
		if (vsi->num_txcq > vsi->num_q_vectors)
			vsi->num_txcq = vsi->num_q_vectors;
	}

	nse_debug(hw, NSE_DBG_SYS, "%s: VSI: type=%s, alloc_rxq=%u, num_rxq=%u, alloc_txq=%u, num_txq=%u\n",
				__func__,
				nse_vsi_type_str(vsi->type),
				vsi->alloc_rxq, vsi->num_rxq, vsi->alloc_txq, vsi->num_txq);

	return 0;
}

/**
 * nse_vsi_init - Create and initialize a VSI
 * @vsi: the VSI being configured
 * @init_vsi: is this call creating a VSI
 *
 * This initializes a VSI context depending on the VSI type to be added and
 * passes it down to the add_vsi aq command to create a new VSI.
 */
int nse_vsi_init(struct nse_vsi *vsi, bool init_vsi)
{
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	struct nse_vsi_ctx *ctxt;
	struct device *dev;
	int ret = 0;

	nse_debug(hw, NSE_DBG_SYS, "[%s] vsi(rel_id=%d, abs_id=%d), init_vsi=%d\n",
								__func__, vsi->vsi_rel_num,
									vsi->vsi_abs_num, init_vsi);

	dev = nse_pf_to_dev(pf);
	ctxt = kzalloc(sizeof(*ctxt), GFP_KERNEL);
	if (!ctxt)
		return -ENOMEM;

	nse_set_dflt_vsi_ctx(hw, vsi, ctxt);

	ret = nse_vsi_setup_q_map(vsi);
	if (ret)
		goto out;

	if (init_vsi) {
		ret = nse_add_vsi(hw, vsi->idx, ctxt, NULL);
		if (ret) {
			dev_err(dev, "Add VSI failed, err %d (%s)\n", ret, nse_stat_str(ret));
			ret = -EIO;
			goto out;
		}
	} else {
		ret = nse_update_vsi(hw, vsi->idx, ctxt, NULL);
		if (ret) {
			dev_err(dev, "Update VSI failed, err %d (%s)\n", ret, nse_stat_str(ret));
			ret = -EIO;
			goto out;
		}
	}

	/* keep context for update VSI operations */
	vsi->info = ctxt->info;

out:
	kfree(ctxt);
	return ret;
}

/**
 * nse_free_res - free a block of resources
 * @res: pointer to the resource
 * @index: starting index previously returned by nse_get_res
 * @id: identifier to track owner
 *
 * Returns number of resources freed
 */
int nse_free_res(struct nse_res_tracker *res, u16 index, u16 id)
{
	int count = 0;
	int i;

	if (!res || index >= res->end)
		return -EINVAL;

	id |= NSE_RES_VALID_BIT;
	for (i = index; i < res->end && res->list[i] == id; i++) {
		res->list[i] = 0;
		count++;
	}

	return count;
}

/**
 * nse_search_res - Search the tracker for a block of resources
 * @res: pointer to the resource
 * @needed: size of the block needed
 * @id: identifier to track owner
 *
 * Returns the base item index of the block, or -ENOMEM for error
 */
static int nse_search_res(struct nse_res_tracker *res, u16 needed, u16 id)
{
	u16 start = 0, end = 0;

	if (needed > res->end)
		return -ENOMEM;

	id |= NSE_RES_VALID_BIT;

	do {
		/* skip already allocated entries */
		if (res->list[end++] & NSE_RES_VALID_BIT) {
			start = end;
			if ((start + needed) > res->end)
				break;
		}

		if (end == (start + needed)) {
			int i = start;

			/* there was enough, so assign it to the requestor */
			while (i != end)
				res->list[i++] = id;

			return start;
		}
	} while (end < res->end);

	return -ENOMEM;
}

/**
 * nse_get_free_res_count - Get free count from a resource tracker
 * @res: Resource tracker instance
 */
u16 nse_get_free_res_count(struct nse_res_tracker *res)
{
	u16 i, count = 0;

	for (i = 0; i < res->end; i++)
		if (!(res->list[i] & NSE_RES_VALID_BIT))
			count++;

	return count;
}

u16 nse_get_free_res_count_max_contig(struct nse_res_tracker *res)
{
	u16 i, cur_count = 0, max_count = 0;

	for (i = 0; i < res->end; i++) {
		if (!(res->list[i] & NSE_RES_VALID_BIT)) {
			cur_count++;
		} else {
			if (cur_count > max_count)
				max_count = cur_count;

			cur_count = 0;
		}
	}

	if (cur_count > max_count)	//for all valid case
		max_count = cur_count;

	return max_count;
}

u16 nse_get_free_res_count_contig_from_offset(struct nse_res_tracker *res, u16 offset)
{
	int i;
	u16 cur_count = 0;

	if (offset >= res->end)
		return 0;

	for (i = offset; i < res->end; i++) {
		if (!(res->list[i] & NSE_RES_VALID_BIT))
			cur_count++;
		else
			break;
	}

	return cur_count;
}

u16 nse_get_free_res_count_contig_before_offset(struct nse_res_tracker *res, u16 offset)
{
	int i;
	u16 cur_count = 0;

	if (offset >= res->end)
		return 0;

	for (i = (offset - 1); i >= 0; i++) {
		if (!(res->list[i] & NSE_RES_VALID_BIT))
			cur_count++;
		else
			break;
	}

	return cur_count;
}

u16 nse_get_free_res_count_tail_contig(struct nse_res_tracker *res)
{
	int i = 0;
	u16 count = 0;

	for (i = res->end - 1; i >= 0; i--) {
		if (!(res->list[i] & NSE_RES_VALID_BIT))
			count++;
		else
			break;
	}

	return count;
}

/**
 * nse_get_valid_res_count - Get in-use count from a resource tracker
 * @res: Resource tracker instance
 */
u16 nse_get_valid_res_count(struct nse_res_tracker *res)
{
	return res->end - nse_get_free_res_count(res);
}

/**
 * nse_get_res - get a block of resources
 * @pf: board private structure
 * @res: pointer to the resource
 * @needed: size of the block needed
 * @id: identifier to track owner
 *
 * Returns the base item index of the block, or negative for error
 */
int
nse_get_res(struct nse_pf *pf, struct nse_res_tracker *res, u16 needed, u16 id)
{
	if (!res || !pf)
		return -EINVAL;

	if (!needed || needed > res->num_entries || id >= NSE_RES_VALID_BIT) {
		dev_err(nse_pf_to_dev(pf), "param err: needed=%d, num_entries = %d id=0x%04x\n",
			needed, res->num_entries, id);
		return -EINVAL;
	}

	return nse_search_res(res, needed, id);
}

static int nse_search_res_backward(struct nse_res_tracker *res, u16 needed, u16 id)
{
	/* Note: don't use u16, otherwise start >= 0 below would never fails, cause deadloop */
	int start = res->end - 1;
	int end = res->end;
	int i = 0;

	if (needed > res->end)
		return -ENOMEM;

	id |= NSE_RES_VALID_BIT;

	for (start = res->end - 1; start >= 0; start--) {
		if (res->list[start] & NSE_RES_VALID_BIT) {	/* already occupied */

			end = start;

			/* no enough even from the beginning */
			if (start <= (needed - 1))
				break;
		}

		if ((start + needed) == end) {
			i = start;

			/* there was enough, so assign it to the requestor */
			while (i != end)
				res->list[i++] = id;

			return start;
		}
	}

	return -ENOMEM;
}

/**
 * nse_get_res_backward - get a block of resources ** from TAIL **
 *
 * Returns the base item index of the block, or negative for error
 */
int
nse_get_res_backward(struct nse_pf *pf, struct nse_res_tracker *res, u16 needed, u16 id)
{
	if (!res || !pf)
		return -EINVAL;

	if (!needed || needed > res->num_entries || id >= NSE_RES_VALID_BIT) {
		dev_err(nse_pf_to_dev(pf), "param err: needed=%d, num_entries = %d id=0x%04x\n",
			needed, res->num_entries, id);
		return -EINVAL;
	}

	return nse_search_res_backward(res, needed, id);
}

void
nse_dump_res_tracker(struct nse_pf *pf, struct nse_res_tracker *res)
{
	struct device *dev = nse_pf_to_dev(pf);
	u16 i, user = 0, start = 0, count = 0;

	dev_info(dev, "total=%d\n", res->num_entries);
	dev_info(dev, "free=%d\n", nse_get_free_res_count(res));
	dev_info(dev, "used=%d\n", nse_get_valid_res_count(res));

	/* dump detailed usage */
	for (i = 0; i < res->end; i++) {
		if (res->list[i] & NSE_RES_VALID_BIT) {
			if ((user | NSE_RES_VALID_BIT) != (res->list[i])) {
			/* a new user region */

				if (count) {	/* dump previous user region */
					dev_info(dev, "\tuser=0x%X, start=%d, count=%d\n",
								user, start, count);
				}

				/* check new user region */
				start = i;
				count = 1;
				user = (res->list[i] & ~NSE_RES_VALID_BIT);
			} else {
			/* still old uesr region */
				count++;
			}
		} else {
			if (count) {		/* dump previous user region */
				dev_info(dev, "\tuser=0x%X, start=%d, count=%d\n",
							user, start, count);
			}
			/* check next user region */
			start = i;
			count = 0;
			user = 0;
		}
	}

	/* dump the last */
	if (count) {
		dev_info(dev, "\tuser=0x%X, start=%d, count=%d\n",
					user, start, count);
	}
}

/**
 * nse_vsi_setup_vector_base - Set up the base vector for the given VSI
 * @vsi: ptr to the VSI
 * @tc: traffic class. Used for VF ADQ
 *
 * This should only be called after nse_vsi_alloc() which allocates the
 * corresponding SW VSI structure and initializes num_queue_pairs for the
 * newly allocated VSI.
 *
 * Returns 0 on success or negative on failure
 */
static int nse_vsi_setup_vector_base(struct nse_vsi *vsi, u8 __maybe_unused tc)
{
	struct nse_pf *pf = vsi->back;
	struct device *dev = nse_pf_to_dev(pf);
	u16 num_q_vectors;
	int base = 0;

	/* SRIOV doesn't grab irq_tracker entries for each VSI */
	if (vsi->type == NSE_VSI_VF) {
		/* Assign the base_vector to allow determining the vector
		 * index. Note that VF VSIs MSI-X index is relative to the VF
		 * space and does not get tracked individually in the software
		 * IRQ tracker.
		 *
		 * VF lanq-irq-vectors is also behind its misc-irq-vector, like PF.
		 */
		vsi->base_vector = NSE_NONQ_VECS_VF;

		return 0;
	}

	if (vsi->base_vector != NSE_INVAL_IRQ_ID) {
		dev_dbg(dev, "VSI (abs_id=%d) has existing valid base vector %d\n",
			vsi->vsi_abs_num, vsi->base_vector);
		return -EEXIST;
	}

	num_q_vectors = vsi->num_q_vectors;

	/* reserve slots from OS requested IRQs */
	base = nse_get_res(pf, pf->irq_tracker_self_region, num_q_vectors,
				   NSE_RES_IRQ_ID_NONVF_VSI_BASE + vsi->idx);

	if (base < 0) {
		dev_err(dev, "%d MSI-X interrupts available. %s %d failed to get %d MSI-X vectors\n",
			nse_get_free_res_count(pf->irq_tracker_self_region),
			nse_vsi_type_str(vsi->type), vsi->idx, num_q_vectors);
		return -ENOENT;
	}
	vsi->base_vector = (u16)base;
	pf->num_avail_sw_msix -= num_q_vectors;

	return 0;
}

static void nse_vsi_release_vector_base(struct nse_vsi *vsi)
{
	struct nse_pf *pf = vsi->back;
	int ret = 0;

	/* SRIOV doesn't grab irq_tracker entries for each VSI */
	if (vsi->type == NSE_VSI_VF)
		return;

	ret = nse_free_res(pf->irq_tracker_self_region, vsi->base_vector,
					NSE_RES_IRQ_ID_NONVF_VSI_BASE + vsi->idx);
	if (ret > 0) {
		/* in fact, += ret should be better */
		pf->num_avail_sw_msix += vsi->num_q_vectors;
	}

	vsi->base_vector = NSE_INVAL_IRQ_ID;
}

/**
 * nse_vsi_clear_rings - Deallocates the Tx and Rx rings for VSI
 * @vsi: the VSI having rings deallocated
 */
static void nse_vsi_clear_rings(struct nse_vsi *vsi)
{
	int i;

	/* Avoid stale references by clearing map from vector to ring */
	if (vsi->q_vectors) {
		nse_for_each_q_vector(vsi, i) {
			struct nse_q_vector *q_vector = vsi->q_vectors[i];

			if (q_vector) {
				q_vector->tx.ring = NULL;
				q_vector->rx.ring = NULL;
				q_vector->txcq = NULL;
			}
		}
	}

	if (vsi->tx_rings) {
		for (i = 0; i < vsi->alloc_txq; i++) {
			if (vsi->tx_rings[i]) {
				kfree_rcu(vsi->tx_rings[i], rcu);
				WRITE_ONCE(vsi->tx_rings[i], NULL);
			}
		}
	}
	if (vsi->rx_rings) {
		for (i = 0; i < vsi->alloc_rxq; i++) {
			if (vsi->rx_rings[i]) {
				kfree_rcu(vsi->rx_rings[i], rcu);
				WRITE_ONCE(vsi->rx_rings[i], NULL);
			}
		}
	}

	if (vsi->txcq_rings) {
		for (i = 0; i < vsi->alloc_txcq; i++) {
			if (vsi->txcq_rings[i]) {
				kfree_rcu(vsi->txcq_rings[i], rcu);
				WRITE_ONCE(vsi->txcq_rings[i], NULL);
			}
		}
	}
}

/**
 * nse_vsi_alloc_rings - Allocates Tx and Rx rings for the VSI
 * @vsi: VSI which is having rings allocated
 */
static int nse_vsi_alloc_rings(struct nse_vsi *vsi)
{
	struct nse_pf *pf = vsi->back;
	struct device *dev = nse_pf_to_dev(pf);
	u16 i;

	/* Allocate Tx rings */
	for (i = 0; i < vsi->alloc_txq; i++) {
		struct nse_ring *ring;

		/* allocate with kzalloc(), free with kfree_rcu() */
		ring = kzalloc(sizeof(*ring), GFP_KERNEL);

		if (!ring)
			goto err_out;

		ring->q_index = i;
		ring->reg_idx = vsi->vsi_txq_space_start + i;
		ring->abs_id = ring->reg_idx + pf->lan_txq_space_start;
		ring->vsi = vsi;
		ring->pf = vsi->back;
		ring->dev = dev;
		ring->netdev = vsi->netdev;
		ring->tx_tstamps = &pf->ptp.port.tx;
		ring->count = vsi->num_tx_desc;
		ring->txq_tnid = NSE_SCHED_INVAL_TNID;

		if (nse_is_hw_static_fea_set(&pf->hw, NSE_HW_STATIC_FEA_TDM_ONLY_HANDLE_L2TAG1))
			/* then NSE_TX_FLAGS_VLAN_TAG_LOC_L2TAG2 is not used in packet path */
			ring->flags |= NSE_TXRX_FLAGS_VLAN_TAG_LOC_L2TAG1;
		else
			ring->flags |= NSE_TX_FLAGS_VLAN_TAG_LOC_L2TAG2;

		ring->need_irqll = false;
		ring->irqll_msix = NSE_AQC_CONF_IRQLL_INVALID_MSIX;

		WRITE_ONCE(vsi->tx_rings[i], ring);
	}

	/* Allocate Rx rings */
	for (i = 0; i < vsi->alloc_rxq; i++) {
		struct nse_ring *ring;

		/* allocate with kzalloc(), free with kfree_rcu() */
		ring = kzalloc(sizeof(*ring), GFP_KERNEL);
		if (!ring)
			goto err_out;

		ring->q_index = i;
		ring->reg_idx = vsi->vsi_rxq_space_start + i;
		ring->abs_id = ring->reg_idx + pf->lan_rxq_space_start;
		ring->vsi = vsi;
		ring->pf = vsi->back;
		ring->netdev = vsi->netdev;
		ring->dev = dev;
		ring->count = vsi->num_rx_desc;

		if (!nse_is_hw_static_fea_set(&pf->hw, NSE_HW_STATIC_FEA_RDM_SUPPORT_FLEX_RXDID))
			ring->flags |= NSE_RX_FLAGS_ALWAYS_HAVE_RXHASH;

		ring->need_irqll = false;
		ring->irqll_msix = NSE_AQC_CONF_IRQLL_INVALID_MSIX;

		WRITE_ONCE(vsi->rx_rings[i], ring);
	}

	/* Allocate CQ rings */
	for (i = 0; i < vsi->alloc_txcq; i++) {
		struct nse_txcq_ring *cq_ring;

		/* allocate with kzalloc(), free with kfree_rcu() */
		cq_ring = kzalloc(sizeof(*cq_ring), GFP_KERNEL);
		if (!cq_ring)
			goto err_out;

		cq_ring->q_index = i;
		cq_ring->vsi = vsi;
		cq_ring->pf = vsi->back;
		cq_ring->netdev = vsi->netdev;
		cq_ring->dev = dev;
		cq_ring->count = vsi->num_txcq_desc;

		cq_ring->cq_rel_id = vsi->vsi_txcq_space_start + i;
		cq_ring->cq_abs_id = cq_ring->cq_rel_id + pf->lan_txcq_space_start;

		cq_ring->need_irqll = false;
		cq_ring->irqll_msix = NSE_AQC_CONF_IRQLL_INVALID_MSIX;

		WRITE_ONCE(vsi->txcq_rings[i], cq_ring);
	}

	return 0;

err_out:
	nse_vsi_clear_rings(vsi);
	return -ENOMEM;
}

/**
 * nse_vsi_reset_stats - Reset all stats of a given VSI
 * @vsi: the VSI whose stats needs to be cleared
 */
void nse_vsi_reset_stats(struct nse_vsi *vsi)
{
	int i;

	if (!vsi)
		return;

	memset(&vsi->hw_stats_prev, 0, sizeof(vsi->hw_stats_prev));
	memset(&vsi->hw_stats_new, 0, sizeof(vsi->hw_stats_new));
	memset(&vsi->hw_stats_raw, 0, sizeof(vsi->hw_stats_raw));
	vsi->hw_stats_prev_loaded = false;

	memset(&vsi->sw_stats_prev, 0, sizeof(vsi->sw_stats_prev));
	memset(&vsi->sw_stats_new, 0, sizeof(vsi->sw_stats_new));
	vsi->sw_stats_prev_loaded = false;

	if (vsi->tx_rings) {
		nse_for_each_txq(vsi, i) {
			if (vsi->tx_rings[i]) {
				memset(&vsi->tx_rings[i]->stats, 0,
				       sizeof(vsi->tx_rings[i]->stats));
				memset(&vsi->tx_rings[i]->tx_stats, 0,
				       sizeof(vsi->tx_rings[i])->tx_stats);
			}
		}
	}

	if (vsi->xdp_rings) {
		nse_for_each_xdp_txq(vsi, i) {
			if (vsi->xdp_rings[i]) {
				memset(&vsi->xdp_rings[i]->stats, 0,
				       sizeof(vsi->xdp_rings[i]->stats));
				memset(&vsi->xdp_rings[i]->tx_stats, 0,
				       sizeof(vsi->xdp_rings[i])->tx_stats);
			}
		}
	}

	if (vsi->rx_rings) {
		nse_for_each_rxq(vsi, i) {
			if (vsi->rx_rings[i]) {
				memset(&vsi->rx_rings[i]->stats, 0,
				       sizeof(vsi->rx_rings[i]->stats));
				memset(&vsi->rx_rings[i]->rx_stats, 0,
				       sizeof(vsi->rx_rings[i])->rx_stats);
			}
		}
	}

	if (vsi->sw_conf.lan_tx_use_cq && vsi->txcq_rings) {
		nse_for_each_lan_txcq(vsi, i) {
			if (vsi->txcq_rings[i]) {
				memset(&vsi->txcq_rings[i]->stats, 0,
						sizeof(vsi->txcq_rings[i]->stats));
			}
		}
	}
}

/**
 * nse_pf_state_is_nominal - checks the PF for nominal state
 * @pf: pointer to PF to check
 *
 * Check the PF's state for a collection of bits that would indicate
 * the PF is in a state that would inhibit normal operation for
 * driver functionality.
 *
 * Returns true if PF is in a nominal state, false otherwise
 */
bool nse_pf_state_is_nominal(struct nse_pf *pf)
{
	DECLARE_BITMAP(check_bits, NSE_STATE_NBITS) = { 0 };

	if (!pf)
		return false;

	bitmap_set(check_bits, 0, NSE_STATE_NOMINAL_CHECK_BITS);
	if (bitmap_intersects(pf->state, check_bits, NSE_STATE_NBITS))
		return false;

	return true;
}

static void nse_per_vsi_hw_stats_raw_2_normalized(struct nse_vsi_hw_stats *dst,
						  struct nse_vsi_hw_stats_raw *src_raw)
{
	struct nse_aqc_rc_dma_chan_per_vsi_stats *src = &src_raw->raw_vsi_stats;

	dst->rx_drop_err = ((le32_to_cpu(src->rdm_vsi_drop_err) & RDM_VSI_DROP_ERR_CNT_M)
								>> RDM_VSI_DROP_ERR_CNT_S);
	dst->rx_drop_no_desc = ((le32_to_cpu(src->rdm_vsi_drop_err) &
				RDM_VSI_DROP_ERR_NO_DESC_CNT_M)
								>> RDM_VSI_DROP_ERR_NO_DESC_CNT_S);
	dst->rx_dpkt = ((u64)le32_to_cpu(src->rdm_vsi_dpkt_lo)) |
					((u64)le32_to_cpu(src->rdm_vsi_dpkt_hi) << 32);
	dst->rx_goct = ((u64)le32_to_cpu(src->rdm_vsi_goct_lo)) |
					((u64)le32_to_cpu(src->rdm_vsi_goct_hi) << 32);
	dst->rx_gpkt = ((u64)le32_to_cpu(src->rdm_vsi_gpkt_lo)) |
					((u64)le32_to_cpu(src->rdm_vsi_gpkt_hi) << 32);
	dst->rx_mpkt = ((u64)le32_to_cpu(src->rdm_vsi_mpkt_lo)) |
					((u64)le32_to_cpu(src->rdm_vsi_mpkt_hi) << 32);
	dst->rx_bpkt = ((u64)le32_to_cpu(src->rdm_vsi_bpkt_lo)) |
					((u64)le32_to_cpu(src->rdm_vsi_bpkt_hi) << 32);

	if (dst->rx_gpkt > (dst->rx_mpkt + dst->rx_bpkt))
		dst->rx_upkt = (dst->rx_gpkt - dst->rx_mpkt - dst->rx_bpkt);

	dst->tx_gptc = ((u64)le32_to_cpu(src->tdm_vsi_gptc_lo)) |
					((u64)le32_to_cpu(src->tdm_vsi_gptc_hi) << 32);
	dst->tx_gotc = ((u64)le32_to_cpu(src->tdm_vsi_gotc_lo)) |
					((u64)le32_to_cpu(src->tdm_vsi_gotc_hi) << 32);
	dst->tx_dptc = ((u64)le32_to_cpu(src->tdm_vsi_dptc_lo)) |
					((u64)le32_to_cpu(src->tdm_vsi_dptc_hi) << 32);
	dst->tx_mptc = ((u64)le32_to_cpu(src->tdm_vsi_mptc_lo)) |
					((u64)le32_to_cpu(src->tdm_vsi_mptc_hi) << 32);
	dst->tx_bptc = ((u64)le32_to_cpu(src->tdm_vsi_bptc_lo)) |
					((u64)le32_to_cpu(src->tdm_vsi_bptc_hi) << 32);

	if (dst->tx_gptc > (dst->tx_mptc + dst->tx_bptc))
		dst->tx_uptc = (dst->tx_gptc - dst->tx_mptc - dst->tx_bptc);
}

/**
 * nse_update_vsi_hw_stats - Update VSI hw_stats counters
 * @vsi: the VSI to be updated
 */
void nse_update_vsi_hw_stats(struct nse_vsi *vsi)
{
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	struct nse_vsi_hw_stats *cur_hs, *prev_hs, *new_hs;
	enum nse_status status;

	if (!in_task() || preempt_count() != 0 || rcu_preempt_depth()) {
		nse_debug(hw, NSE_DBG_MISC_DETAIL, "[%s] in atomic or rcu critical section, don't update_vsi_hw_stat() for now, leaving for watchdog_task\n", __func__);
		nse_debug(hw, NSE_DBG_MISC_DETAIL, "\t in_task()=%d, in_atomic()=%d, rcu_preempt_depth()=%d\n",
			  in_task(), (preempt_count() != 0), rcu_preempt_depth());

		vsi->wd_subtask_update_vsi_stats_now = true;

		pf->wd_subtask_flags |= WD_SUBTASK_FLAG_UPDATE_VSI_STATS_NOW;

		return;
	}

	cur_hs = &vsi->hw_stats;
	prev_hs = &vsi->hw_stats_prev;
	new_hs = &vsi->hw_stats_new;

	status = nse_read_dma_chan_per_vsi_stats(hw, vsi->vsi_abs_num,
						 &vsi->hw_stats_raw.raw_vsi_stats);
	if (status) {
		dev_info(nse_hw_to_dev(hw), "[%s, %d] read_lan_per_vsi_stats() fails, %d(%s)\n",
					__func__, __LINE__,
					status, nse_stat_str(status));
		return;
	}

	nse_per_vsi_hw_stats_raw_2_normalized(new_hs, &vsi->hw_stats_raw);

	nse_stat_update16(new_hs->rx_drop_err, vsi->hw_stats_prev_loaded,
			&prev_hs->rx_drop_err, &cur_hs->rx_drop_err);
	nse_stat_update16(new_hs->rx_drop_no_desc, vsi->hw_stats_prev_loaded,
			&prev_hs->rx_drop_no_desc, &cur_hs->rx_drop_no_desc);
	nse_stat_update64(new_hs->rx_dpkt, vsi->hw_stats_prev_loaded,
			&prev_hs->rx_dpkt, &cur_hs->rx_dpkt);
	nse_stat_update64(new_hs->rx_goct, vsi->hw_stats_prev_loaded,
			&prev_hs->rx_goct, &cur_hs->rx_goct);
	nse_stat_update48(new_hs->rx_gpkt, vsi->hw_stats_prev_loaded,
			&prev_hs->rx_gpkt, &cur_hs->rx_gpkt);
	nse_stat_update48(new_hs->rx_mpkt, vsi->hw_stats_prev_loaded,
			&prev_hs->rx_mpkt, &cur_hs->rx_mpkt);
	nse_stat_update48(new_hs->rx_bpkt, vsi->hw_stats_prev_loaded,
			&prev_hs->rx_bpkt, &cur_hs->rx_bpkt);
	nse_stat_update48(new_hs->rx_upkt, vsi->hw_stats_prev_loaded,
			&prev_hs->rx_upkt, &cur_hs->rx_upkt);

	nse_stat_update48(new_hs->tx_gptc, vsi->hw_stats_prev_loaded,
			&prev_hs->tx_gptc, &cur_hs->tx_gptc);
	nse_stat_update64(new_hs->tx_gotc, vsi->hw_stats_prev_loaded,
			&prev_hs->tx_gotc, &cur_hs->tx_gotc);
	nse_stat_update48(new_hs->tx_dptc, vsi->hw_stats_prev_loaded,
			&prev_hs->tx_dptc, &cur_hs->tx_dptc);
	nse_stat_update48(new_hs->tx_mptc, vsi->hw_stats_prev_loaded,
			&prev_hs->tx_mptc, &cur_hs->tx_mptc);
	nse_stat_update48(new_hs->tx_bptc, vsi->hw_stats_prev_loaded,
			&prev_hs->tx_bptc, &cur_hs->tx_bptc);
	nse_stat_update48(new_hs->tx_uptc, vsi->hw_stats_prev_loaded,
			&prev_hs->tx_uptc, &cur_hs->tx_uptc);

	vsi->hw_stats_prev_loaded = true;
}

/**
 * nse_vsi_cfg_frame_size - setup max frame size and Rx buffer length
 * @vsi: VSI
 */
void nse_vsi_cfg_frame_size(struct nse_vsi *vsi)
{
	if (!vsi->netdev || test_bit(NSE_FLAG_LEGACY_RX, vsi->back->flags)) {
		vsi->max_frame = NSE_AQ_SET_MAC_FRAME_SIZE_MAX;
		vsi->rx_buf_len = NSE_RXBUF_2048;
#if (PAGE_SIZE < 8192)
	} else if (!NSE_2K_TOO_SMALL_WITH_PADDING &&
		   (vsi->netdev->mtu <= ETH_DATA_LEN)) {
		vsi->max_frame = NSE_RXBUF_1536 - NET_IP_ALIGN;
		vsi->rx_buf_len = NSE_RXBUF_1536 - NET_IP_ALIGN;
#endif
	} else {
		vsi->max_frame = NSE_AQ_SET_MAC_FRAME_SIZE_MAX;
#if (PAGE_SIZE < 8192)
		vsi->rx_buf_len = NSE_RXBUF_3072;
#else
		vsi->rx_buf_len = NSE_RXBUF_2048;
#endif
	}
}

int nse_vsi_cfg_rx_max(struct nse_vsi *vsi, u32 rxmax)
{
	struct nse_hw *hw = &vsi->back->hw;
	struct nse_vsi_ctx *ctxt;
	enum nse_status status;
	int err = 0;

	nse_debug(hw, NSE_DBG_LAN, "[%s] vsi abs id=%d, rxmax=%d\n",
		  __func__, vsi->vsi_abs_num, rxmax);

	ctxt = kzalloc(sizeof(*ctxt), GFP_KERNEL);
	if (!ctxt)
		return -ENOMEM;

	ctxt->vsi_abs_num = vsi->vsi_abs_num;

	memcpy(&ctxt->info, &vsi->info, sizeof(ctxt->info));

	ctxt->info.rxmax = cpu_to_le32(rxmax);

	ctxt->info.valid_sections = cpu_to_le16(NSE_AQ_VSI_PROP_SECTION_RXMAX_VALID);

	status = nse_update_vsi(hw, vsi->idx, ctxt, NULL);
	if (status) {
		dev_err(nse_pf_to_dev(vsi->back), "update VSI rxmax failed, err %s aq_err %s\n",
			nse_stat_str(status),
			nse_aq_str(hw->adminq.sq_last_status));
		err = -EIO;
		goto out;
	}

	/* save temp ctxt->info changed content, into vsi->info */
	vsi->info.rxmax = ctxt->info.rxmax;

out:
	kfree(ctxt);
	return err;
}

/**
 * nse_vsi_alloc_arrays - Allocate queue and vector pointer arrays for the VSI
 * @vsi: VSI pointer
 *
 * On error: returns error code (negative)
 * On success: returns 0
 */
static int nse_vsi_alloc_arrays(struct nse_vsi *vsi)
{
	struct nse_pf *pf = vsi->back;
	struct device *dev = nse_pf_to_dev(pf);
	int i;

	/* allocate memory for both Tx and Rx ring pointers */
	vsi->tx_rings = devm_kcalloc(dev, vsi->alloc_txq,
				     sizeof(*vsi->tx_rings), GFP_KERNEL);
	if (!vsi->tx_rings)
		goto err_rings;

	if (vsi->type == NSE_VSI_SWITCHDEV_CTRL) {
		vsi->tx_rings_locks = devm_kcalloc(dev, vsi->alloc_txq,
								sizeof(spinlock_t), GFP_KERNEL);
		if (!vsi->tx_rings_locks)
			goto err_rings;

		nse_for_each_alloc_txq(vsi, i) {
			spin_lock_init(&vsi->tx_rings_locks[i]);
		}
	}

	if (vsi->alloc_txcq) {
		vsi->txcq_rings = devm_kcalloc(dev, vsi->alloc_txcq,
				     sizeof(*vsi->txcq_rings), GFP_KERNEL);

		if (!vsi->txcq_rings) {
			dev_err(dev, "[%s] FAIL: alloc txcq_rings\n", __func__);
			goto err_rings;
		}
	}

	vsi->rx_rings = devm_kcalloc(dev, vsi->alloc_rxq,
				     sizeof(*vsi->rx_rings), GFP_KERNEL);
	if (!vsi->rx_rings)
		goto err_rings;

	/* There is no need to allocate q_vectors for a loopback VSI. */
	if (vsi->type == NSE_VSI_LB)
		return 0;

	/* allocate memory for q_vector pointers */
	vsi->q_vectors = devm_kcalloc(dev, vsi->num_q_vectors,
				      sizeof(*vsi->q_vectors), GFP_KERNEL);
	if (!vsi->q_vectors)
		goto err_rings;

	vsi->af_xdp_zc_qps = bitmap_zalloc(max_t(int, vsi->alloc_txq, vsi->alloc_rxq), GFP_KERNEL);
	if (!vsi->af_xdp_zc_qps) {
		dev_err(dev, "[%s] FAIL: alloc af_xdp_zc_qps\n", __func__);
		goto err_zc_qps;
	}

	vsi->af_xdp_zc_qps_bitmap_size = max_t(int, vsi->alloc_txq, vsi->alloc_rxq);

	return 0;

err_zc_qps:
	if (vsi->q_vectors != NULL) {
		devm_kfree(dev, vsi->q_vectors);
		vsi->q_vectors = NULL;
	}
err_rings:
	if (vsi->rx_rings != NULL) {
		devm_kfree(dev, vsi->rx_rings);
		vsi->rx_rings = NULL;
	}
	if (vsi->txcq_rings != NULL) {
		devm_kfree(dev, vsi->txcq_rings);
		vsi->txcq_rings = NULL;
	}
	if (vsi->tx_rings != NULL) {
		devm_kfree(dev, vsi->tx_rings);
		vsi->tx_rings = NULL;
	}
	if (vsi->tx_rings_locks != NULL) {
		devm_kfree(dev, vsi->tx_rings_locks);
		vsi->tx_rings_locks = NULL;
	}

	return -ENOMEM;
}

/**
 * nse_vsi_free_arrays - De-allocate queue and vector pointer arrays for the VSI
 * @vsi: pointer to VSI being cleared
 */
static void nse_vsi_free_arrays(struct nse_vsi *vsi)
{
	struct nse_pf *pf = vsi->back;
	struct device *dev;

	dev = nse_pf_to_dev(pf);

	if (vsi->af_xdp_zc_qps) {
		bitmap_free(vsi->af_xdp_zc_qps);
		vsi->af_xdp_zc_qps = NULL;
		vsi->af_xdp_zc_qps_bitmap_size = 0;
	}
	/* free the ring and vector containers */
	if (vsi->q_vectors) {
		devm_kfree(dev, vsi->q_vectors);
		vsi->q_vectors = NULL;
	}
	if (vsi->tx_rings) {
		devm_kfree(dev, vsi->tx_rings);
		vsi->tx_rings = NULL;
	}
	if (vsi->tx_rings_locks) {
		devm_kfree(dev, vsi->tx_rings_locks);
		vsi->tx_rings_locks = NULL;
	}
	if (vsi->rx_rings) {
		devm_kfree(dev, vsi->rx_rings);
		vsi->rx_rings = NULL;
	}

	if (vsi->txcq_rings) {
		devm_kfree(dev, vsi->txcq_rings);
		vsi->txcq_rings = NULL;
	}
}

/**
 * nse_vsi_set_num_desc - Set number of descriptors for queues on this VSI
 * @vsi: the VSI being configured
 */
static void nse_vsi_set_num_desc(struct nse_vsi *vsi)
{
	struct nse_pf *pf = vsi->back;

	switch (vsi->type) {
	case NSE_VSI_PF:
	case NSE_VSI_OFFLOAD_MACVLAN:
	case NSE_VSI_ADI:
	case NSE_VSI_SWITCHDEV_CTRL:
	case NSE_VSI_LB:
		/* a user could change the values of num_[tr]x_desc using
		 * ethtool -G so we should keep those values instead of
		 * overwriting them with the defaults.
		 */
		if (!vsi->num_rx_desc)
			vsi->num_rx_desc = pf->sw_conf.lan_rxq_dflt_len;
		if (!vsi->num_tx_desc)
			vsi->num_tx_desc = pf->sw_conf.lan_txq_dflt_len;

		vsi->num_txcq_desc = NSE_DFLT_NUM_CQ_DESC;

		break;
	default:
		dev_dbg(nse_pf_to_dev(vsi->back), "Not setting number of Tx/Rx descriptors for VSI type %d\n",
			vsi->type);
		break;
	}
}

/**
 * nse_vsi_set_num_qs - Set number of queues, descriptors and vectors for a VSI
 * @vsi: the VSI being configured
 * @vf: the VF associated with this VSI, if any
 *
 * Return 0 on success and a negative value on error
 */
static void nse_vsi_set_num_qs(struct nse_vsi *vsi, struct nse_vf *vf)
{
	enum nse_vsi_type vsi_type = vsi->type;
	struct nse_pf *pf = vsi->back;
	u16 val16;

	if (WARN_ON(!vf && nse_vsi_requires_vf(vsi_type)))
		return;

	switch (vsi_type) {
	case NSE_VSI_PF:

		if (nse_main_vsi_max_lanq_num) {
			vsi->alloc_txq = min_t(u16, nse_main_vsi_max_lanq_num,
									pf->main_vsi_lan_txqs_max);
		} else {
			/* default to 1 Tx queue per MSI-X to not hurt our performance */
			vsi->alloc_txq = min3(pf->num_lan_msix,
									pf->main_vsi_lan_txqs_max,
									pf->main_vsi_lan_qps_dflt);
		}

		if (vsi->req_txq) {
			vsi->alloc_txq = vsi->req_txq;
			vsi->num_txq = vsi->req_txq;
		}

		pf->num_lan_tx = vsi->alloc_txq;

		/* only 1 Rx queue unless RSS is enabled */
		if (!test_bit(NSE_FLAG_RSS_CAPABLE, pf->flags)) {
			vsi->alloc_rxq = 1;
		} else {
			if (nse_main_vsi_max_lanq_num) {
				vsi->alloc_rxq = min_t(u16, nse_main_vsi_max_lanq_num,
						       pf->main_vsi_lan_rxqs_max);
			} else {
				/* default to 1 Rx queue per MSI-X to not hurt our performance */
				vsi->alloc_rxq = min3(pf->num_lan_msix,
						      pf->main_vsi_lan_rxqs_max,
						      pf->main_vsi_lan_qps_dflt);
			}

			if (vsi->req_rxq) {
				vsi->alloc_rxq = vsi->req_rxq;
				vsi->num_rxq = vsi->req_rxq;
			}
		}

		pf->num_lan_rx = vsi->alloc_rxq;

		vsi->num_q_vectors = min_t(int, pf->num_lan_msix,
					   max_t(int, vsi->alloc_rxq, vsi->alloc_txq));

		if (nse_main_vsi_max_lanirq_num &&
		    vsi->num_q_vectors > nse_main_vsi_max_lanirq_num) {
			vsi->num_q_vectors = nse_main_vsi_max_lanirq_num;
		}

		break;
	case NSE_VSI_OFFLOAD_MACVLAN:
		vsi->alloc_txq = NSE_DFLT_TXQ_VMDQ_VSI;
		vsi->alloc_rxq = NSE_DFLT_RXQ_VMDQ_VSI;
		vsi->num_q_vectors = NSE_DFLT_VEC_VMDQ_VSI;
		break;
	case NSE_VSI_ADI:
		vsi->alloc_txq = pf->vfs.num_qps_per;
		vsi->alloc_rxq = pf->vfs.num_qps_per;

		/* For SIOV VFs, we reserve vectors required for Qs and 1 extra
		 * for OICR.
		 */
		vsi->num_q_vectors = pf->vfs.num_msix_per;
		break;
	case NSE_VSI_SWITCHDEV_CTRL:

		val16 = nse_get_num_vfs(pf);

		val16 = (val16 + 7) / 8;
		if (!val16)
			val16 = 1;

		vsi->alloc_txq = val16;
		vsi->alloc_rxq = vsi->alloc_txq;
		vsi->num_q_vectors = val16;
		break;
	case NSE_VSI_VF:
		/* pf->vfs.num_msix_per includes (VF miscellaneous vector +
		 * data queue interrupts). Since vsi->num_q_vectors is number
		 * of queues vectors, subtract 1 (NSE_NONQ_VECS_VF) from the
		 * original vector count
		 */
		vsi->alloc_txq = pf->vfs.vf_tx_qbase_numq;
		vsi->alloc_rxq = pf->vfs.vf_rx_qbase_numq;
		vsi->num_q_vectors = pf->vfs.num_msix_per - NSE_NONQ_VECS_VF;

		break;

	case NSE_VSI_LB:
		vsi->alloc_txq = 1;
		vsi->alloc_rxq = 1;
		vsi->num_q_vectors = 1;
		break;
	default:
		dev_warn(nse_pf_to_dev(pf), "Unknown VSI type %d\n", vsi_type);
		break;
	}

	if (vsi->sw_conf.lan_tx_use_cq) {
		if (vsi_type == NSE_VSI_VF)
			vsi->alloc_txcq = pf->vfs.num_txcq_per;
		else
			vsi->alloc_txcq = vsi->num_q_vectors;
	}

	nse_vsi_set_num_desc(vsi);
}

/**
 * nse_get_free_slot - get the next available free slot in array
 * @array: array to search
 * @size: size of the array
 * @curr: last known occupied index to be used as a search hint
 *
 * void * is being used to keep the functionality generic. This lets us use this
 * function on any array of pointers.
 */
static int nse_get_free_slot(void *array, int size, int curr)
{
	int **tmp_array = (int **)array;
	int next;
	int i = 0;

	while ((i < size) && (tmp_array[i]))
		i++;
	if (i == size)
		next = NSE_NO_VSI;
	else
		next = i;

	return next;
}

/**
 * nse_vsi_delete - delete a VSI from the switch
 * @vsi: pointer to VSI being removed
 */
void nse_vsi_delete(struct nse_vsi *vsi)
{
	struct nse_pf *pf = vsi->back;
	struct nse_vsi_ctx *ctxt;
	enum nse_status status;

	ctxt = kzalloc(sizeof(*ctxt), GFP_KERNEL);
	if (!ctxt)
		return;

	ctxt->vsi_abs_num = vsi->vsi_abs_num;

	memcpy(&ctxt->info, &vsi->info, sizeof(ctxt->info));

	status = nse_free_vsi(&pf->hw, vsi->idx, ctxt, NULL);
	if (status)
		dev_err(nse_pf_to_dev(pf), "Failed to delete VSI(abs_id=%d, rel_id=%d) in FW - error: %s\n",
			vsi->vsi_abs_num, vsi->vsi_rel_num, nse_stat_str(status));

	kfree(ctxt);
}

/**
 * nse_msix_clean_rings - MSIX mode Interrupt Handler
 * @irq: interrupt number
 * @data: pointer to a q_vector
 */
irqreturn_t nse_msix_clean_rings(int __always_unused irq, void *data)
{
	struct nse_q_vector *q_vector = (struct nse_q_vector *)data;

	if (!q_vector->tx.ring && !q_vector->rx.ring)
		return IRQ_HANDLED;

	q_vector->total_events++;

#if defined(NSE_DEBUG_EXT)
	q_vector->dbg_stats.hardirq_total_cnt++;
#endif

	napi_schedule(&q_vector->napi);

	return IRQ_HANDLED;
}

static irqreturn_t nse_eswitch_msix_clean_rings(int __always_unused irq, void *data)
{
	struct nse_q_vector *q_vector = (struct nse_q_vector *)data;
	struct nse_pf *pf = q_vector->vsi->back;
	struct nse_vf *vf;
	unsigned int bkt;

	if (!q_vector->tx.ring && !q_vector->rx.ring)
		return IRQ_HANDLED;

	q_vector->total_events++;

#if defined(NSE_DEBUG_EXT)
	q_vector->dbg_stats.hardirq_total_cnt++;
#endif

	rcu_read_lock();
	nse_for_each_vf_rcu(pf, bkt, vf) {
		/* in nse_eswitch_remap_rings_to_vectors()
		 *
		 *		not actually mapped to a real_q_vector
		 *
		 *		or actually mapped, but not to this real_q_vector
		 */
		if (vf->repr->real_q_vector != q_vector)
			continue;

		napi_schedule(&vf->repr->q_vector->napi);
	}
	rcu_read_unlock();

	return IRQ_HANDLED;
}

int nse_nonvf_vsi_lan_rxq_res_owner_id(struct nse_vsi *vsi, u16 *res_owner_id)
{
	int ret = 0;
	struct nse_pf *pf = vsi->back;

	if (vsi->type == NSE_VSI_PF) {						/* only 1 PF VSI */
		*res_owner_id = NSE_RES_LAN_RXQ_ID_PF;
	} else if (vsi->type == NSE_VSI_OFFLOAD_MACVLAN) {
		*res_owner_id = NSE_RES_LAN_RXQ_ID_OFFLOAD_MACVLAN_BASE + vsi->idx;
	/* only 1 switchdev ctrl VSI */
	} else if (vsi->type == NSE_VSI_SWITCHDEV_CTRL) {
		*res_owner_id = NSE_RES_LAN_RXQ_ID_SWITCHDEV_CTRL;
	/* should be only 1 LB VSI */
	} else if (vsi->type == NSE_VSI_LB) {
		*res_owner_id = NSE_RES_LAN_RXQ_ID_LB;
	} else if (vsi->type == NSE_VSI_ADI) {
		*res_owner_id = NSE_RES_LAN_RXQ_ID_ADI_BASE + vsi->idx;
	} else {
		dev_err(nse_pf_to_dev(pf), "[%s, %d] unsupported vsi->type = %d\n",
									__func__, __LINE__,
									(int)vsi->type);
		ret = -EOPNOTSUPP;
	}

	return ret;
}

int nse_nonvf_vsi_lan_txq_res_owner_id(struct nse_vsi *vsi, bool is_xdp_txq, u16 *res_owner_id)
{
	int ret = 0;
	struct nse_pf *pf = vsi->back;

	if (vsi->type == NSE_VSI_PF) {						/* only 1 PF VSI */
		if (!is_xdp_txq)
			*res_owner_id = NSE_RES_LAN_TXQ_ID_PF;
		else
			*res_owner_id = NSE_RES_LAN_TXQ_ID_PF_XDP;
	} else if (vsi->type == NSE_VSI_OFFLOAD_MACVLAN) {
		*res_owner_id = NSE_RES_LAN_TXQ_ID_OFFLOAD_MACVLAN_BASE + vsi->idx;
	/* only 1 switchdev ctrl VSI */
	} else if (vsi->type == NSE_VSI_SWITCHDEV_CTRL) {
		*res_owner_id = NSE_RES_LAN_TXQ_ID_SWITCHDEV_CTRL;
	/* should be only 1 LB VSI */
	} else if (vsi->type == NSE_VSI_LB) {
		*res_owner_id = NSE_RES_LAN_TXQ_ID_LB;
	} else if (vsi->type == NSE_VSI_ADI) {
		*res_owner_id = NSE_RES_LAN_TXQ_ID_ADI_BASE + vsi->idx;
	} else {
		dev_err(nse_pf_to_dev(pf), "[%s, %d] unsupported vsi->type = %d\n",
									__func__, __LINE__,
									(int)vsi->type);
		ret = -EOPNOTSUPP;
	}

	return ret;
}

int nse_nonvf_vsi_lan_txcq_res_owner_id(struct nse_vsi *vsi, u16 *res_owner_id)
{
	int ret = 0;

	if (vsi->type == NSE_VSI_VF) {
		dev_err(nse_pf_to_dev(vsi->back), "[%s, %d] unsupported vsi->type = %d\n",
									__func__, __LINE__,
									(int)vsi->type);
		ret = -EOPNOTSUPP;

	} else {
		*res_owner_id = NSE_RES_LAN_TXCQ_ID_NONVF_VSI_BASE + vsi->idx;
	}

	return ret;
}

/**
 * nse_vsi_get_qs - Assign queues from PF to VSI
 * @vsi: the VSI to assign queues to
 *
 * Returns 0 on success and a negative value on error
 */
static int nse_vsi_get_qs(struct nse_vsi *vsi)
{
	struct nse_pf *pf = vsi->back;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_vfs *vfs = &pf->vfs;
	struct nse_vf *vf = vsi->vf;
	u16 rxq_owner_id = 0, txq_owner_id = 0, txcq_owner_id = 0;
	int ret = 0;

	/* for VF VSI, its qs already determined in set_per_vf_res() and plan_vf_res() */
	if (vsi->type == NSE_VSI_VF) {
		vsi->vsi_rxq_space_start = vfs->vf_rx_qbase_firstq +
			(vfs->vf_rx_qbase_numq * vf->vf_id);
		vsi->vsi_txq_space_start = vfs->vf_tx_qbase_firstq +
			(vfs->vf_tx_qbase_numq * vf->vf_id);

		if (pf->sw_conf.lan_tx_use_cq_for_vf)
			vsi->vsi_txcq_space_start = vfs->vf_txcq_qbase_firstq +
				(vfs->num_txcq_per * vf->vf_id);
		else
			vsi->vsi_txcq_space_start = NSE_INVAL_Q_ID;

		return 0;

	} else {		/* for nonVF VSI */

		mutex_lock(&pf->lan_rxq_tracker_mutex);
		mutex_lock(&pf->lan_txq_tracker_mutex);
		mutex_lock(&pf->lan_txcq_tracker_mutex);

		if (nse_nonvf_vsi_lan_rxq_res_owner_id(vsi, &rxq_owner_id) ||
			nse_nonvf_vsi_lan_txq_res_owner_id(vsi, false, &txq_owner_id) ||
			nse_nonvf_vsi_lan_txcq_res_owner_id(vsi, &txcq_owner_id)) {
			dev_err(dev, "[%s] FAIL: get res_owner_id, VSI(idx=%d)\n",
				__func__, vsi->idx);

			ret = -EOPNOTSUPP;
			goto out;
		}

		vsi->vsi_rxq_space_start = NSE_INVAL_Q_ID;
		vsi->vsi_txq_space_start = NSE_INVAL_Q_ID;
		vsi->vsi_txcq_space_start = NSE_INVAL_Q_ID;

		/* alloc txcq if needed */
		if (vsi->sw_conf.lan_tx_use_cq) {
			ret = nse_get_res(pf, pf->lan_txcq_tracker, vsi->alloc_txcq, txcq_owner_id);

			if (ret < 0) {
				dev_err(dev, "[%s] FAIL: get_res(txcq), VSI(idx=%d, type=%d), need=%d, avail_max_contig=%d, avail_total=%d\n",
					 __func__, vsi->idx, vsi->type,
					 vsi->alloc_txcq,
					 nse_get_free_res_count_max_contig(pf->lan_txcq_tracker),
					 nse_get_free_res_count(pf->lan_txcq_tracker));

				goto fail_alloc;
			}

			vsi->vsi_txcq_space_start = ret;
		}

		/* alloc txq */
		ret = nse_get_res(pf, pf->lan_txq_tracker, vsi->alloc_txq, txq_owner_id);
		if (ret < 0) {
			dev_err(dev, "[%s] FAIL: get_res(txq), VSI(idx=%d, type=%d), need=%d, avail_max_contig=%d, avail_total=%d\n",
				 __func__, vsi->idx, vsi->type, vsi->alloc_txq,
				 nse_get_free_res_count_max_contig(pf->lan_txq_tracker),
				 nse_get_free_res_count(pf->lan_txq_tracker));
			goto fail_alloc;
		}

		vsi->vsi_txq_space_start = ret;

		/* alloc rxq */
		ret = nse_get_res(pf, pf->lan_rxq_tracker, vsi->alloc_rxq, rxq_owner_id);

		if (ret < 0) {
			dev_err(dev, "[%s] FAIL: get_res(rxq), VSI(idx=%d, type=%d), need=%d, avail_max_contig=%d, avail_total=%d\n",
				 __func__, vsi->idx, vsi->type, vsi->alloc_rxq,
				 nse_get_free_res_count_max_contig(pf->lan_rxq_tracker),
				 nse_get_free_res_count(pf->lan_rxq_tracker));

			goto fail_alloc;
		}

		vsi->vsi_rxq_space_start = ret;

		ret = 0;	/* success */

out:
		mutex_unlock(&pf->lan_txcq_tracker_mutex);
		mutex_unlock(&pf->lan_rxq_tracker_mutex);
		mutex_unlock(&pf->lan_txq_tracker_mutex);

		return ret;

fail_alloc:
		ret = -ENOSPC;

		if (vsi->sw_conf.lan_tx_use_cq && vsi->vsi_txcq_space_start != NSE_INVAL_Q_ID)
			(void)nse_free_res(pf->lan_txcq_tracker,
					   vsi->vsi_txcq_space_start, txcq_owner_id);

		if (vsi->vsi_txq_space_start != NSE_INVAL_Q_ID)
			(void)nse_free_res(pf->lan_txq_tracker,
					   vsi->vsi_txq_space_start, txq_owner_id);

		if (vsi->vsi_rxq_space_start != NSE_INVAL_Q_ID)
			(void)nse_free_res(pf->lan_rxq_tracker,
					   vsi->vsi_rxq_space_start, rxq_owner_id);

		vsi->vsi_rxq_space_start = NSE_INVAL_Q_ID;
		vsi->vsi_txq_space_start = NSE_INVAL_Q_ID;
		vsi->vsi_txcq_space_start = NSE_INVAL_Q_ID;

		goto out;
	}
}

/**
 * nse_vsi_put_qs - Release queues from VSI to PF
 * @vsi: the VSI that is going to release queues
 */
void nse_vsi_put_qs(struct nse_vsi *vsi)
{
	struct nse_pf *pf = vsi->back;
	u16 rxq_owner_id, txq_owner_id, txcq_owner_id;

	/* the whole VF-rxq/txq region would be put as a whole, not per-VF */
	if (vsi->type == NSE_VSI_VF)
		return;

	/* the following logic only handle nonVF VSI */

	/* Note, vsi->vsi_xdp_txq_start is not put here, but in nse_destroy_xdp_rings()
	 */
	if (nse_nonvf_vsi_lan_rxq_res_owner_id(vsi, &rxq_owner_id) ||
		nse_nonvf_vsi_lan_txq_res_owner_id(vsi, false, &txq_owner_id) ||
		nse_nonvf_vsi_lan_txcq_res_owner_id(vsi, &txcq_owner_id))
		return;

	mutex_lock(&pf->lan_rxq_tracker_mutex);
	mutex_lock(&pf->lan_txq_tracker_mutex);
	mutex_lock(&pf->lan_txcq_tracker_mutex);

	if (vsi->sw_conf.lan_tx_use_cq && vsi->vsi_txcq_space_start != NSE_INVAL_Q_ID)
		(void)nse_free_res(pf->lan_txcq_tracker, vsi->vsi_txcq_space_start, txcq_owner_id);

	if (vsi->vsi_txq_space_start != NSE_INVAL_Q_ID)
		(void)nse_free_res(pf->lan_txq_tracker, vsi->vsi_txq_space_start, txq_owner_id);

	if (vsi->vsi_rxq_space_start != NSE_INVAL_Q_ID)
		(void)nse_free_res(pf->lan_rxq_tracker, vsi->vsi_rxq_space_start, rxq_owner_id);

	vsi->vsi_rxq_space_start = NSE_INVAL_Q_ID;
	vsi->vsi_txq_space_start = NSE_INVAL_Q_ID;
	vsi->vsi_txcq_space_start = NSE_INVAL_Q_ID;

	mutex_unlock(&pf->lan_txcq_tracker_mutex);
	mutex_unlock(&pf->lan_txq_tracker_mutex);
	mutex_unlock(&pf->lan_rxq_tracker_mutex);
}

static unsigned int simple_log2(unsigned int v)
{
	unsigned int r;
	unsigned int shift;

	r = (v > 0xFFFF) << 4; v >>= r;
	shift = (v > 0xFF) << 3; v >>= shift; r |= shift;
	shift = (v > 0xF) << 2; v >>= shift; r |= shift;
	shift = (v > 0x3) << 1; v >>= shift; r |= shift;
	r |= (v >> 1);
	return r;
}

static int nse_vsi_rss_init(struct nse_vsi *vsi)
{
	struct nse_pf *pf = vsi->back;
	int ret = 0;

	if (!vsi->alloc_rxq)
		return -EINVAL;

	vsi->rss_lut_size = vsi->alloc_rxq * NSE_RXQ_RSS_LUT_SCALE;
	vsi->rss_lut_size_log2 = simple_log2((unsigned int)vsi->rss_lut_size);
	vsi->rss_lut_size_aligned = (1 << vsi->rss_lut_size_log2);

	vsi->rss_ctl_user_req_alg = (NSE_VSI_RSS_CTL_ALG_IPV4_TCP |
		NSE_VSI_RSS_CTL_ALG_IPV4 |
		NSE_VSI_RSS_CTL_ALG_IPV6 |
		NSE_VSI_RSS_CTL_ALG_IPV6_TCP);

	mutex_lock(&pf->rss_lut_tracker_mutex);

	/* here use vsi->idx as ID, since it is unique inside [0, 255]*/
	ret = nse_get_res(pf, pf->rss_lut_tracker, vsi->rss_lut_size, vsi->idx);
	if (ret < 0)
		goto out;

	vsi->rss_lut_start = ret;

	ret = 0;	/* success */

	/* we leave rss_ctl setting when vsi open */

out:
	mutex_unlock(&pf->rss_lut_tracker_mutex);

	return ret;
}

static void nse_vsi_rss_deinit(struct nse_vsi *vsi)
{
	struct nse_pf *pf = vsi->back;
	struct device *dev = nse_pf_to_dev(pf);

	if (!vsi->rss_lut_size)	/* not init yet */
		return;

	mutex_lock(&pf->rss_lut_tracker_mutex);

	(void)nse_free_res(pf->rss_lut_tracker, vsi->rss_lut_start, vsi->idx);

	mutex_unlock(&pf->rss_lut_tracker_mutex);

	vsi->rss_lut_size = 0;

	if (vsi->rss_hkey_user)
		devm_kfree(dev, vsi->rss_hkey_user);

	if (vsi->rss_lut_user)
		devm_kfree(dev, vsi->rss_lut_user);
}

/* similar to nse_vsi_rss_deinit(), but less */
void nse_vsi_rss_rebuild_pre(struct nse_vsi *vsi)
{
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;

	nse_debug(hw, NSE_DBG_RCF, "[%s] vsi(abs_id=%d), rss_lut_size=%d\n",
								__func__, vsi->vsi_abs_num,
									vsi->rss_lut_size);

	if (!vsi->rss_lut_size)	/* not init yet */
		return;

	mutex_lock(&pf->rss_lut_tracker_mutex);

	(void)nse_free_res(pf->rss_lut_tracker, vsi->rss_lut_start, vsi->idx);

	mutex_unlock(&pf->rss_lut_tracker_mutex);

	vsi->rss_lut_size = 0;

	/* keep rss_hkey_user and rss_lut_user */
}

/* similar to nse_vsi_rss_init() */
int nse_vsi_rss_rebuild_post(struct nse_vsi *vsi)
{
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	u16 old_rss_lut_size_aligned = vsi->rss_lut_size_aligned;
	u16 copy_rss_lut_size_aligned;
	u16 *new_rss_lut_user = NULL;
	int ret = 0;

	nse_debug(hw, NSE_DBG_RCF, "[%s] vsi(abs_id=%d), alloc_rxq=%d\n",
								__func__, vsi->vsi_abs_num,
									vsi->alloc_rxq);

	if (!vsi->alloc_rxq) {
		ret = -EINVAL;
		goto out;
	}

	vsi->rss_lut_size = vsi->alloc_rxq * NSE_RXQ_RSS_LUT_SCALE;
	vsi->rss_lut_size_log2 = simple_log2((unsigned int)vsi->rss_lut_size);
	vsi->rss_lut_size_aligned = (1 << vsi->rss_lut_size_log2);

	/* copy old rss_lut_user to new rss_lut_user */
	if (vsi->rss_lut_user) {
		new_rss_lut_user = devm_kzalloc(dev, sizeof(u16) * vsi->rss_lut_size_aligned,
						GFP_KERNEL);
		if (!new_rss_lut_user) {
			ret = -ENOMEM;
			goto out;
		}

		copy_rss_lut_size_aligned = (old_rss_lut_size_aligned < vsi->rss_lut_size_aligned) ?
		old_rss_lut_size_aligned : vsi->rss_lut_size_aligned;

		memcpy(new_rss_lut_user, vsi->rss_lut_user,
		       sizeof(u16) * copy_rss_lut_size_aligned);

		devm_kfree(dev, vsi->rss_lut_user);
		vsi->rss_lut_user = new_rss_lut_user;
	}

	mutex_lock(&pf->rss_lut_tracker_mutex);

	/* here use vsi->idx as ID, since it is unique inside [0, 255]*/
	ret = nse_get_res(pf, pf->rss_lut_tracker, vsi->rss_lut_size, vsi->idx);
	if (ret < 0) {
		mutex_unlock(&pf->rss_lut_tracker_mutex);

		dev_err(dev, "[%s, %d] nse_get_res(rss_lut_tracker, rss_lut_size=%d) fails. vsi->idx = %d\n",
				__func__, __LINE__,
				vsi->rss_lut_size,
				vsi->idx);

		goto out;
	}

	mutex_unlock(&pf->rss_lut_tracker_mutex);

	vsi->rss_lut_start = ret;

	ret = nse_vsi_cfg_rss(vsi);	/* recfg RSS */
	if (ret < 0) {
		dev_err(dev, "[%s, %d] vsi_cfg_rss() fails. vsi->idx = %d\n",
				__func__, __LINE__,
				vsi->idx);
		goto out;
	}

	ret = 0;	/* success */

out:

	return ret;
}

/**
 * nse_is_aux_ena
 * @pf: pointer to the PF struct
 *
 * returns true if peer devices/drivers are supported, false otherwise
 */
bool nse_is_aux_ena(struct nse_pf *pf)
{
	return test_bit(NSE_FLAG_AUX_ENA, pf->flags);
}

/**
 * nse_vsi_clear - clean up and deallocate the provided VSI
 * @vsi: pointer to VSI being cleared
 *
 * This deallocates the VSI's queue resources, removes it from the PF's
 * VSI array if necessary, and deallocates the VSI
 *
 * Returns 0 on success, negative on failure
 */
int nse_vsi_clear(struct nse_vsi *vsi)
{
	struct nse_pf *pf = NULL;
	struct device *dev;

	if (!vsi)
		return 0;

	if (!vsi->back)
		return -EINVAL;

	pf = vsi->back;
	dev = nse_pf_to_dev(pf);

	if (!pf->vsi[vsi->idx] || pf->vsi[vsi->idx] != vsi) {
		dev_dbg(dev, "vsi does not exist at pf->vsi[%d]\n", vsi->idx);
		return -EINVAL;
	}

	mutex_lock(&pf->sw_mutex);
	mutex_lock(&pf->vsi_tracker_mutex);

	/* updates the PF for this cleared VSI */

	pf->vsi[vsi->idx] = NULL;
	if (vsi->type != NSE_VSI_VF) {
		pf->next_nonvf_vsi = vsi->idx;

		if (vsi->vsi_rel_num != NSE_VSI_INVAL_ID)
			nse_free_res(pf->vsi_tracker, vsi->vsi_rel_num,
				     vsi->nonvf_vsi_res_owner_id);
	}

	mutex_unlock(&pf->vsi_tracker_mutex);
	mutex_unlock(&pf->sw_mutex);

	nse_vsi_free_arrays(vsi);

	devm_kfree(dev, vsi);

	return 0;
}

static int nse_nonvf_vsi_owner_id(struct nse_pf *pf, enum nse_vsi_type type,
				  int idx, u16 *res_owner_id)
{
	int ret = 0;

	if (type == NSE_VSI_PF) {						/* only 1 PF VSI */
		*res_owner_id = NSE_RES_VSI_ID_PF;
	} else if (type == NSE_VSI_OFFLOAD_MACVLAN) {
		*res_owner_id = NSE_RES_VSI_ID_OFFLOAD_MACVLAN_BASE + idx;
	} else if (type == NSE_VSI_SWITCHDEV_CTRL) {		/* only 1 switchdev ctrl VSI */
		*res_owner_id = NSE_RES_VSI_ID_SWITCHDEV_CTRL;
	/* should be only 1 LB VSI */
	} else if (type == NSE_VSI_LB) {
		*res_owner_id = NSE_RES_VSI_ID_LB;
	} else if (type == NSE_VSI_ADI) {
		*res_owner_id = NSE_RES_VSI_ID_ADI + idx;
	} else {
		dev_err(nse_pf_to_dev(pf), "[%s, %d] unsupported vsi->type = %d\n",
									__func__, __LINE__,
									(int)type);
		ret = -EOPNOTSUPP;
	}

	return ret;
}
/**
 * nse_vsi_alloc - Allocates the next available struct VSI in the PF
 * @pf: board private structure
 * @vsi_type: type of VSI
 * @ch: ptr to channel
 * @tc: traffic class number for VF ADQ
 * @vf: VF for NSE_VSI_VF and NSE_VSI_CTRL
 *
 * The VF pointer is used for NSE_VSI_VF and NSE_VSI_CTRL. For NSE_VSI_CTRL,
 * it may be NULL in the case there is no association with a VF. For
 * NSE_VSI_VF the VF pointer *must not* be NULL.
 *
 * returns a pointer to a VSI on success, NULL on failure.
 */
static struct nse_vsi *
nse_vsi_alloc(struct nse_pf *pf, enum nse_vsi_type vsi_type,
	      struct nse_vf *vf, u8 tc)
{
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_vsi *vsi = NULL;
	int vsi_res_id;	/* idx in vsi_tracker, only used for nonVF VSI */

	if (WARN_ON(!vf && nse_vsi_requires_vf(vsi_type)))
		return NULL;

	/* Need to protect the allocation of the VSIs at the PF level */
	mutex_lock(&pf->sw_mutex);
	mutex_lock(&pf->vsi_tracker_mutex);

	if (vsi_type != NSE_VSI_VF && pf->next_nonvf_vsi == NSE_NO_VSI) {
		dev_dbg(dev, "out of VSI slots!\n");
		goto err;
	}

	vsi = devm_kzalloc(dev, sizeof(*vsi), GFP_KERNEL);
	if (!vsi)
		goto err;

	vsi->base_vector = NSE_INVAL_IRQ_ID;

	vsi->type = vsi_type;
	vsi->back = pf;
	/* For VSIs which don't have a connected VF, this will be NULL */
	vsi->vf = vf;

	set_bit(NSE_VSI_DOWN, vsi->state);

	/* set fixed right after vsi allocated */
	if (nse_vsi_requires_vf(vsi_type))
		vsi->sw_conf.lan_tx_use_cq = pf->sw_conf.lan_tx_use_cq_for_vf;
	else
		vsi->sw_conf.lan_tx_use_cq = pf->sw_conf.lan_tx_use_cq;

	/* SW allocate VSI from vsi_tracker.
	 */
	vsi->vsi_rel_num = NSE_VSI_INVAL_ID;
	vsi->vsi_abs_num = NSE_VSI_INVAL_ID;

	if (vsi_type == NSE_VSI_VF) {
		if (pf->sriov_res_planned) {
			vsi->vsi_rel_num = pf->vfs.vf_vsialloc_firstvsi + vf->vf_id;
			vsi->vsi_abs_num = pf->vsi_space_start + vsi->vsi_rel_num;
		} else {	/* !pf->sriov_res_planned ? */
			goto err;
		}
	} else {
		/* here we peek pf->next_nonvf_vsi, cauz we are sure gonna use it */
		if (nse_nonvf_vsi_owner_id(pf, vsi_type,
		    pf->next_nonvf_vsi, &vsi->nonvf_vsi_res_owner_id))
			goto err;

		vsi_res_id = nse_get_res(pf, pf->vsi_tracker, 1, vsi->nonvf_vsi_res_owner_id);
		if (vsi_res_id < 0)
			goto err;

		vsi->vsi_rel_num = vsi_res_id;
		vsi->vsi_abs_num = pf->vsi_space_start + vsi->vsi_rel_num;
	}

	vsi->rxdid = NSE_RXDID_FLEX_NIC;
#if defined(NSE_DEBUG_EXT)
	if (nse_lan_rx_force_rxdid && nse_lan_rx_force_rxdid < NSE_RXDID_MAX)
		vsi->rxdid = nse_lan_rx_force_rxdid;
#endif

	/* later we will set in nse_vsi_get_qs() */
	vsi->vsi_rxq_space_start = NSE_INVAL_Q_ID;
	vsi->vsi_txq_space_start = NSE_INVAL_Q_ID;
	vsi->vsi_txcq_space_start = NSE_INVAL_Q_ID;

	nse_vsi_set_num_qs(vsi, vf);

	switch (vsi->type) {
	case NSE_VSI_OFFLOAD_MACVLAN:
	case NSE_VSI_ADI:
	case NSE_VSI_PF:
		if (nse_vsi_alloc_arrays(vsi))
			goto err;

		/* Setup default MSIX irq handler for VSI */
		vsi->irq_handler = nse_msix_clean_rings;
		break;
	case NSE_VSI_SWITCHDEV_CTRL:
		if (nse_vsi_alloc_arrays(vsi))
			goto err;

		/* Setup eswitch MSIX irq handler for VSI */
		vsi->irq_handler = nse_eswitch_msix_clean_rings;

		vsi->rxdid = NSE_RXDID_FLEX_SWITCHDEV;

		break;
	case NSE_VSI_VF:
		if (nse_vsi_alloc_arrays(vsi))
			goto err;
		break;

	case NSE_VSI_LB:
		if (nse_vsi_alloc_arrays(vsi))
			goto err;
		break;
	default:
		dev_warn(dev, "Unknown VSI type %d\n", vsi->type);
		goto err;
	}

	/* fill slot and make note of the index */
	if (vsi_type == NSE_VSI_VF) {	/* for VF VSI */
		/* nonvf_vsi_region_size = vfs.vf_vsialloc_firstvsi */
		vsi->idx = pf->nonvf_vsi_region_size + vf->vf_id;
		pf->vsi[vsi->idx] = vsi;
	} else {							/* for nonVF VSI */
		vsi->idx = pf->next_nonvf_vsi;
		pf->vsi[vsi->idx] = vsi;

		/* prepare pf->next_vsi for next use */
		pf->next_nonvf_vsi = nse_get_free_slot(pf->vsi, pf->nonvf_vsi_region_size,
							 pf->next_nonvf_vsi);
	}

	goto unlock_pf_and_out;

err:
	if (vsi && vsi_type != NSE_VSI_VF && vsi->vsi_rel_num != NSE_VSI_INVAL_ID)
		nse_free_res(pf->vsi_tracker, vsi->vsi_rel_num, vsi->nonvf_vsi_res_owner_id);

	if (vsi) {
		devm_kfree(dev, vsi);
		vsi = NULL;
	}

unlock_pf_and_out:
	mutex_unlock(&pf->vsi_tracker_mutex);
	mutex_unlock(&pf->sw_mutex);
	return vsi;
}

/**
 * nse_pf_rxq_wait - Wait for a PF's Rx queue to be enabled or disabled
 * @pf: the PF being configured
 * @pf_q: the PF queue
 * @ena: enable or disable state of the queue
 *
 * This routine will wait for the given Rx queue of the PF to reach the
 * enabled or disabled state.
 * Returns -ETIMEDOUT in case of failing to reach the requested state after
 * multiple retries; else will return 0 in case of success.
 */
static int nse_pf_rxq_wait(struct nse_pf *pf, int rxq_abs_id, bool ena)
{
	int i;
	u16 rxq_status;

	for (i = 0; i < NSE_Q_WAIT_MAX_RETRY; i++) {
		if (nse_aq_lan_read_rxq_status(&pf->hw, rxq_abs_id, &rxq_status)) {
			usleep_range(20, 40);
			continue;
		}

		if ((ena && (rxq_status & BIT(NSE_LANQ_STAT_BIT_IDX_Q_EN))) ||
			(!ena && !(rxq_status & BIT(NSE_LANQ_STAT_BIT_IDX_Q_EN))))
			return 0;

		usleep_range(20, 40);
	}

	return -ETIMEDOUT;
}

/**
 * nse_vsi_wait_one_rx_ring - wait for a VSI's Rx ring to be stopped/started
 * @vsi: the VSI being configured
 * @ena: true/false to verify Rx ring has been enabled/disabled respectively
 * @rxq_idx: 0-based Rx queue index for the VSI passed in
 *
 * This routine will wait for the given Rx queue of the VSI to reach the
 * enabled or disabled state. Returns -ETIMEDOUT in case of failing to reach
 * the requested state after multiple retries; else will return 0 in case of
 * success.
 */
int nse_vsi_wait_one_rx_ring(struct nse_vsi *vsi, bool ena, u16 rxq_idx)
{
	struct nse_pf *pf = vsi->back;
	u16 rxq_abs_id = pf->lan_rxq_space_start + vsi->vsi_rxq_space_start + rxq_idx;

	return nse_pf_rxq_wait(pf, rxq_abs_id, ena);
}

/**
 * nse_vsi_ctrl_one_rx_ring - start/stop VSI's Rx ring with no busy wait
 * @vsi: the VSI being configured
 * @ena: start or stop the Rx ring
 * @rxq_idx: 0-based Rx queue index for the VSI passed in
 * @wait: wait or don't wait for configuration to finish in hardware
 *
 * Return 0 on success and negative on error.
 */
int nse_vsi_ctrl_one_rx_ring(struct nse_vsi *vsi, bool ena, u16 rxq_idx)
{
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_ring *ring = vsi->rx_rings[rxq_idx];
	u16 rxq_abs_id = pf->lan_rxq_space_start + vsi->vsi_rxq_space_start + rxq_idx;
	enum nse_status status;
	int ret = 0;

	nse_debug(hw, NSE_DBG_LAN, "[%s] vsi (rel_id=%d, abs_id=%d), rxq (idx=%d), ena=%d\n",
								__func__, vsi->vsi_rel_num,
									vsi->vsi_abs_num,
									rxq_idx, ena);

	if (!ring) {
		dev_err(dev, "[%s] BAD: vsi (rel_id=%d, abs_id=%d), rxq (idx=%d) not exist\n",
					__func__, vsi->vsi_rel_num, vsi->vsi_abs_num, rxq_idx);
		ret = -EINVAL;
		goto out;
	}

	nse_debug(hw, NSE_DBG_LAN, "\t need_irqll=%d, already_in_irqll=%d, irqll_msix=%d\n",
								ring->need_irqll,
									ring->already_in_irqll,
									ring->irqll_msix);

	/* turn on/off the queue */
	if (ena)
		status = nse_aq_lan_enable_rxq(hw, rxq_abs_id, ring->irqll_msix);
	else
		status = nse_aq_lan_disable_rxq(hw, rxq_abs_id,
						ring->already_in_irqll ? ring->irqll_msix :
							NSE_AQC_CONF_IRQLL_INVALID_MSIX);

	if (status) {
		dev_err(dev, "[%s] FAIL: aq_lan_%s_rxq(), vsi (rel_id=%d, abs_id=%d), rxq (idx=%d, abs_id=%d)\n",
					__func__,
					ena ? "enable" : "disable",
					vsi->vsi_rel_num, vsi->vsi_abs_num, rxq_idx, rxq_abs_id);
		ret = -EIO;
		goto out;
	}

	if (ena & ring->need_irqll)
		ring->already_in_irqll = true;
	else
		ring->already_in_irqll = false;

	ret = 0;

out:
	return ret;
}

/**
 * nse_vsi_ctrl_all_rx_rings - Start or stop a VSI's Rx rings
 * @vsi: the VSI being configured
 * @ena: start or stop the Rx rings
 *
 * First enable/disable all of the Rx rings, flush any remaining writes, and
 * then verify that they have all been enabled/disabled successfully. This will
 * let all of the register writes complete when enabling/disabling the Rx rings
 * before waiting for the change in hardware to complete.
 */
int nse_vsi_ctrl_all_rx_rings(struct nse_vsi *vsi, bool ena)
{
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	int ret = 0;
	u16 i;

	nse_debug(hw, NSE_DBG_LAN, "[%s] vsi=(rel_id:%d, abs_id=%d), ena=%d\n",
								__func__, vsi->vsi_rel_num,
									vsi->vsi_abs_num, ena);

	for (i = 0; i < vsi->num_rxq; i++) {
		ret = nse_vsi_ctrl_one_rx_ring(vsi, ena, i);
		if (ret) {
			dev_err(dev, "[%s] FAIL: vsi_ctrl_one_rx_ring(ena=%d, i=%d), ret=%d\n",
						__func__, ena, i, ret);
			break;
		}
	}

	return ret;
}

int nse_vsi_ctrl_all_rx_rings_bulk(struct nse_vsi *vsi, bool ena)
{
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_ring *ring = NULL;
	u16 firstq, lastq;
	u16 *irqll = NULL;
	u16 i;
	enum nse_status status;
	int ret = 0;

	nse_debug(hw, NSE_DBG_LAN, "[%s] vsi=(rel_id:%d, abs_id=%d), ena=%d, num_rxq=%d\n",
								__func__, vsi->vsi_rel_num,
									vsi->vsi_abs_num,
									ena, vsi->num_rxq);

	if (!vsi->num_rxq)
		goto out;

	irqll = kzalloc((sizeof(u16) * vsi->num_rxq), GFP_KERNEL);
	if (irqll == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	firstq = vsi->vsi_rxq_space_start + pf->lan_rxq_space_start;
	lastq = (vsi->vsi_rxq_space_start + vsi->num_rxq - 1);

	nse_for_each_rxq(vsi, i) {
		ring = vsi->rx_rings[i];
		irqll[i] = NSE_AQC_CONF_IRQLL_INVALID_MSIX;

		if (!ring)
			continue;

		if (ring->need_irqll) {
			/* if to enable Q && already_in_irqll == 0, then need to add to irqll.
			 *
			 * if to disable Q && already_in_irqll == 1, then need to del from irqll
			 */
			if ((ena && !ring->already_in_irqll) ||
				(!ena && ring->already_in_irqll))
				irqll[i] = ring->irqll_msix;
		}
	}

	if (ena)
		status = nse_aq_lan_ena_rxq_many(&pf->hw, firstq, lastq, irqll);
	else
		status = nse_aq_lan_dis_rxq_many(&pf->hw, firstq, lastq, irqll);

	if (!status) {
		nse_for_each_rxq(vsi, i) {
			ring = vsi->rx_rings[i];

			if (!ring)
				continue;

			if (ena && ring->need_irqll)
				ring->already_in_irqll = true;
			else
				ring->already_in_irqll = false;
		}

	} else {
		dev_err(dev, "[%s] FAIL: aq_lan_ena/dis_rxq_many(firstq=%d, lastq=%d), status=%d\n",
						__func__, firstq, lastq, status);
		ret = -EIO;
	}

out:
	kfree(irqll);

	return ret;
}

static int nse_pf_txq_wait(struct nse_pf *pf, int txq_abs_id, bool ena)
{
	int i;
	u16 txq_status;

	for (i = 0; i < NSE_Q_WAIT_MAX_RETRY; i++) {
		if (nse_aq_lan_read_txq_status(&pf->hw, txq_abs_id, &txq_status)) {
			usleep_range(20, 40);
			continue;
		}

		if ((ena && (txq_status & BIT(NSE_LANQ_STAT_BIT_IDX_Q_EN))) ||
			(!ena && !(txq_status & BIT(NSE_LANQ_STAT_BIT_IDX_Q_EN))))
			return 0;

		usleep_range(20, 40);
	}

	return -ETIMEDOUT;
}

int nse_vsi_wait_one_tx_ring(struct nse_vsi *vsi, bool ena, u16 txq_idx)
{
	struct nse_pf *pf = vsi->back;
	u16 txq_abs_id = pf->lan_txq_space_start + vsi->vsi_txq_space_start + txq_idx;

	return nse_pf_txq_wait(pf, txq_abs_id, ena);
}

int nse_vsi_ctrl_one_tx_ring(struct nse_vsi *vsi, bool ena, u16 txq_idx)
{
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_ring *ring = vsi->tx_rings[txq_idx];
	u16 txq_abs_id = pf->lan_txq_space_start + vsi->vsi_txq_space_start + txq_idx;
	u16 txq_status;
	enum nse_status status;
	int ret = 0;

	nse_debug(hw, NSE_DBG_LAN, "[%s] vsi (rel_id=%d, abs_id=%d), txq (idx=%d), ena=%d\n",
								__func__, vsi->vsi_rel_num,
									vsi->vsi_abs_num,
									txq_idx, ena);

	if (!ring) {
		dev_err(dev, "[%s] BAD: vsi (rel_id=%d, abs_id=%d), txq (idx=%d) not exist\n",
					__func__, vsi->vsi_rel_num, vsi->vsi_abs_num, txq_idx);
		ret = -EINVAL;
		goto out;
	}

	nse_debug(hw, NSE_DBG_LAN, "\t need_irqll=%d, already_in_irqll=%d, irqll_msix=%d\n",
								ring->need_irqll,
									ring->already_in_irqll,
									ring->irqll_msix);

	/* Skip if the queue is already in the requested state */
	if ((nse_aq_lan_read_txq_status(hw, txq_abs_id, &txq_status) == NSE_SUCCESS) &&
		((ena && (txq_status & BIT(NSE_LANQ_STAT_BIT_IDX_Q_EN))) ||
		(!ena && !(txq_status & BIT(NSE_LANQ_STAT_BIT_IDX_Q_EN))))) {
		nse_debug(hw, NSE_DBG_LAN, "[%s] already in requested state\n", __func__);

		goto out;
	}

	/* turn on/off the queue */
	if (ena)
		status = nse_aq_lan_enable_txq(hw, txq_abs_id, ring->irqll_msix);
	else
		status = nse_aq_lan_disable_txq(hw, txq_abs_id,
						ring->already_in_irqll ? ring->irqll_msix :
							NSE_AQC_CONF_IRQLL_INVALID_MSIX);

	if (status) {
		dev_err(dev, "[%s] FAIL: aq_lan_%s_txq(), vsi (rel_id=%d, abs_id=%d), txq (idx=%d, abs_id=%d)\n",
					__func__,
					ena ? "enable" : "disable",
					vsi->vsi_rel_num, vsi->vsi_abs_num, txq_idx, txq_abs_id);
		ret = -EIO;
		goto out;
	}

	if (ena && ring->need_irqll)
		ring->already_in_irqll = true;
	else
		ring->already_in_irqll = false;

	ret = 0;

out:
	return ret;
}

static int nse_pf_lan_txcq_wait(struct nse_pf *pf, u16 cq_abs_id, bool ena)
{
	int i;
	u16 cq_status;

	for (i = 0; i < NSE_Q_WAIT_MAX_RETRY; i++) {
		if (nse_read_lan_txcq_status(&pf->hw, NULL, cq_abs_id, &cq_status)) {
			usleep_range(20, 40);
			continue;
		}

		if ((ena && (cq_status & BIT(NSE_LANQ_STAT_BIT_IDX_Q_EN))) ||
			(!ena && !(cq_status & BIT(NSE_LANQ_STAT_BIT_IDX_Q_EN))))
			return 0;

		usleep_range(20, 40);
	}

	return -ETIMEDOUT;
}

int nse_vsi_wait_one_txcq_ring(struct nse_vsi *vsi, bool ena, u16 q_idx)
{
	struct nse_pf *pf = vsi->back;
	u16 cq_abs_id;

	if (!vsi->sw_conf.lan_tx_use_cq)
		return 0;

	if (q_idx >= vsi->num_txcq)
		return -EINVAL;

	cq_abs_id = vsi->txcq_rings[q_idx]->cq_abs_id;

	return nse_pf_lan_txcq_wait(pf, cq_abs_id, ena);
}

int nse_vsi_ctrl_one_txcq_ring(struct nse_vsi *vsi, bool ena, u16 q_idx)
{
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_txcq_ring *ring = NULL;
	int cq_abs_id;
	u16 cq_status;
	enum nse_status status;
	int ret = 0;

	if (!vsi->sw_conf.lan_tx_use_cq)
		goto out;

	nse_debug(hw, NSE_DBG_LAN, "[%s] vsi (rel_id=%d, abs_id=%d), cq (idx=%d), ena=%d, use_lan_txcq=%d\n",
								__func__, vsi->vsi_rel_num,
									vsi->vsi_abs_num, q_idx,
									ena,
									vsi->sw_conf.lan_tx_use_cq);

	if (q_idx >= vsi->num_txcq) {
		dev_err(dev, "[%s] BAD: vsi (rel_id=%d, abs_id=%d), txcq (idx=%d) > actual_lan_txcq_num(%d)\n",
						__func__,
						vsi->vsi_rel_num, vsi->vsi_abs_num,
						q_idx, vsi->num_txcq);
		ret = -EINVAL;
		goto out;
	}

	ring = vsi->txcq_rings[q_idx];
	if (!ring) {
		dev_err(dev, "[%s] BAD: vsi (rel_id=%d, abs_id=%d), txcq (idx=%d) not exist\n",
						__func__, vsi->vsi_rel_num,
							vsi->vsi_abs_num, q_idx);
		ret = -EINVAL;
		goto out;
	}

	cq_abs_id = vsi->txcq_rings[q_idx]->cq_abs_id;

	/* Skip if the queue is already in the requested state */
	if ((nse_read_lan_txcq_status(hw, vsi, cq_abs_id, &cq_status) == NSE_SUCCESS) &&
		((ena && (cq_status & BIT(NSE_LANQ_STAT_BIT_IDX_Q_EN))) ||
		(!ena && !(cq_status & BIT(NSE_LANQ_STAT_BIT_IDX_Q_EN)))))
		goto out;

	/* turn on/off the queue */
	if (ena)
		status = nse_enable_lan_txcq(hw, vsi, cq_abs_id, ring->irqll_msix);
	else
		status = nse_disable_lan_txcq(hw, vsi, cq_abs_id,
					ring->already_in_irqll ? ring->irqll_msix :
						NSE_AQC_CONF_IRQLL_INVALID_MSIX);

	if (status) {
		dev_err(dev, "[%s] FAIL: %s_lan_txcq(), vsi (rel_id=%d, abs_id=%d), txcq (idx=%d, abs_id=%d)\n",
					__func__,
					ena ? "enable" : "disable",
					vsi->vsi_rel_num, vsi->vsi_abs_num, q_idx, cq_abs_id);
		ret = -EIO;
		goto out;
	}

	if (ena && ring->need_irqll)
		ring->already_in_irqll = true;
	else
		ring->already_in_irqll = false;

	ret = 0;

out:
	return ret;
}

int nse_vsi_ctrl_all_txcq_rings(struct nse_vsi *vsi, bool ena)
{
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	int ret = 0;
	u16 i;

	if (!vsi->sw_conf.lan_tx_use_cq)
		return 0;

	nse_debug(hw, NSE_DBG_LAN, "[%s]: vsi=(rel_id:%d, abs_id=%d), ena=%d, lan_tx_use_cq=%d\n",
								__func__, vsi->vsi_rel_num,
									vsi->vsi_abs_num, ena,
									vsi->sw_conf.lan_tx_use_cq);

	for (i = 0; i < vsi->num_txcq; i++) {
		ret = nse_vsi_ctrl_one_txcq_ring(vsi, ena, i);
		if (ret) {
			dev_err(dev, "[%s] WARN: vsi_ctrl_one_txcq_ring(ena=%d, i=%d), ret=%d\n",
						__func__, ena, i, ret);
			if (!ena)	/* if ena=false, ignore error */
				ret = 0;
			else
				break;
		}
	}

	return ret;
}

/**
 * nse_write_intrl - write throttle rate limit to interrupt specific register
 * @q_vector: pointer to interrupt specific structure
 * @intrl: throttle rate limit in microseconds to write
 */
void nse_write_intrl(struct nse_q_vector *q_vector, u8 intrl)
{
	struct nse_pf *pf = q_vector->vsi->back;
	struct nse_hw *hw = &pf->hw;
	int ret = 0;

	ret = nse_set_intrl_interval(hw, q_vector->reg_idx, (u32)intrl);
	if (ret) {
		dev_warn(nse_pf_to_dev(pf), "%s fails: qvec->reg_idx: %d, intrl: %d\n",
					__func__,
					q_vector->reg_idx, intrl);
	}
}

/**
 * nse_write_itr - write throttle rate to queue specific register
 * @rc: pointer to ring container
 * @itr: throttle rate in microseconds to write
 */
void nse_write_itr(struct nse_q_vector *q_vector, u16 itr)
{
	struct nse_pf *pf = q_vector->vsi->back;
	struct nse_hw *hw = &pf->hw;
	int ret = 0;

	ret = nse_set_itr_interval(hw, q_vector->reg_idx, (u32)itr);
	if (ret) {
		dev_warn(nse_pf_to_dev(pf), "%s fails: qvec->reg_idx: %d, itr: %d\n",
					__func__,
					q_vector->reg_idx, itr);
	}
}

/**
 * nse_set_q_vector_intrl - set up interrupt rate limiting
 * @q_vector: the vector to be configured
 *
 * Interrupt rate limiting is local to the vector, not per-queue so we must
 * detect if either ring container has dynamic enabled to decide what to set
 * the interrupt rate limit to via INTRL settings. In the case of dynamic
 * disabled on both, write the value with the cached setting to make sure
 * INTRL matches user visible value.
 */
void nse_set_q_vector_intrl(struct nse_q_vector *q_vector)
{
	if (ITR_IS_DYNAMIC(q_vector)) {
		/* in the case of dynamic enabled, cap each vector to no more
		 * than (4 us) 250,000 ints/sec, which allows low latency
		 * but still less than 500,000 interrupts per second, which
		 * reduces CPU a bit in the case of the lowest latency
		 * setting. The 4 here is a value in microseconds.
		 */
		nse_write_intrl(q_vector, 4);
	} else {
		nse_write_intrl(q_vector, q_vector->intrl);
	}
}

/**
 * nse_vsi_cfg_msix - MSIX mode Interrupt Config in the HW
 * @vsi: the VSI being configured
 *
 * This configures MSIX mode interrupts for the PF VSI, and should not be used
 * for the VF VSI.
 */
void nse_vsi_cfg_msix(struct nse_vsi *vsi)
{
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	u16 txq = 0, rxq = 0;
	int i, q;

	for (i = 0; i < vsi->num_q_vectors; i++) {
		struct nse_q_vector *q_vector = vsi->q_vectors[i];
		u16 reg_idx = q_vector->reg_idx;

		nse_cfg_itr(hw, q_vector);

		/* Both Transmit Queue Interrupt Cause Control register
		 * and Receive Queue Interrupt Cause control register
		 * expects MSIX_INDX field to be the vector index
		 * within the function space and not the absolute
		 * vector index across PF or across device.
		 * For SR-IOV VF VSIs queue vector index always starts
		 * with 1 since first vector index(0) is used for OICR
		 * in VF space. Since VMDq and other PF VSIs are within
		 * the PF function space, use the vector index that is
		 * tracked for this PF.
		 */
		for (q = 0; q < q_vector->num_ring_tx; q++) {
			nse_cfg_txq_interrupt(vsi, txq, reg_idx);
			txq++;
		}

		for (q = 0; q < q_vector->num_ring_rx; q++) {
			nse_cfg_rxq_interrupt(vsi, rxq, reg_idx);
			rxq++;
		}
	}
}

/**
 * nse_vsi_start_all_rx_rings - start/enable all of a VSI's Rx rings
 * @vsi: the VSI whose rings are to be enabled
 *
 * Returns 0 on success and a negative value on error
 */
int nse_vsi_start_all_rx_rings(struct nse_vsi *vsi)
{
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;

	nse_debug(hw, NSE_DBG_LAN, "[%s] vsi=(rel_id:%d, abs_id=%d)\n",
								__func__, vsi->vsi_rel_num,
									vsi->vsi_abs_num);

	if (nse_lan_bulk_ena_dis)
		return nse_vsi_ctrl_all_rx_rings_bulk(vsi, true);
	else
		return nse_vsi_ctrl_all_rx_rings(vsi, true);
}

void nse_vsi_sync_tail_all_rx_rings(struct nse_vsi *vsi)
{
	u16 i = 0;
	struct nse_ring *rx_ring;

	for (i = 0; i < vsi->num_rxq; i++) {
		rx_ring = vsi->rx_rings[i];
		if (rx_ring)
			nse_rx_ring_sync_tail_after_enable(rx_ring);
	}
}

/**
 * nse_vsi_stop_all_rx_rings - stop/disable all of a VSI's Rx rings
 * @vsi: the VSI whose rings are to be disabled
 *
 * Returns 0 on success and a negative value on error
 */
int nse_vsi_stop_all_rx_rings(struct nse_vsi *vsi, bool rdm_stopped)
{
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;

	nse_debug(hw, NSE_DBG_LAN, "[%s] vsi=(rel_id:%d, abs_id=%d), rdm_stopped=%d\n",
								__func__, vsi->vsi_rel_num,
									vsi->vsi_abs_num,
									rdm_stopped);

	if (rdm_stopped)
		return 0;

	if (nse_lan_bulk_ena_dis)
		return nse_vsi_ctrl_all_rx_rings_bulk(vsi, false);
	else
		return nse_vsi_ctrl_all_rx_rings(vsi, false);
}

/**
 * nse_vsi_start_tx_rings - Enable Tx rings
 *
 *	This MUST be called after nse_setup_tx_ctx() properly setting the TXQ context for these TXQ.
 */
int
nse_vsi_start_tx_rings(struct nse_vsi *vsi, struct nse_ring **rings)
{
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	u16 q_idx;
	int ret = 0;

	nse_debug(hw, NSE_DBG_LAN, "[%s] vsi=(rel_id:%d, abs_id=%d)\n",
								__func__, vsi->vsi_rel_num,
									vsi->vsi_abs_num);

	if (vsi->num_txq > NSE_LAN_TXQ_MAX_QDIS) {
		dev_err(dev, "[%s] BAD: vsi->num_txq=%d, > max: %d\n",
						__func__, vsi->num_txq, NSE_LAN_TXQ_MAX_QDIS);
		ret = -EINVAL;
		goto out;
	}

	if (!rings) {
		dev_err(dev, "[%s] BAD: rings = NULL ?\n", __func__);
		ret = -EINVAL;
		goto out;
	}

	for (q_idx = 0; q_idx < vsi->num_txq; q_idx++) {
		if (!rings[q_idx]) {
			dev_err(dev, "[%s] BAD: rings[q_idx=%d] = NULL ?\n", __func__, q_idx);
			ret = -EINVAL;
			goto out;
		}
	}

	for (q_idx = 0; q_idx < vsi->num_txq; q_idx++) {
		ret = nse_vsi_start_tx_ring(vsi, rings[q_idx]);

		if (ret) {
			dev_err(dev, "[%s] FAIL: vsi_start_tx_ring(rings[q_idx=%d]), ret=%d\n",
				__func__, q_idx, ret);
			goto out;
		}
	}

out:
	return ret;
}

int
nse_vsi_start_tx_rings_bulk(struct nse_vsi *vsi, u16 firstq_abs_id, u16 lastq_abs_id, u16 *irqll)
{
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	enum nse_status status;

	nse_debug(hw, NSE_DBG_LAN, "[%s] vsi=(rel_id:%d, abs_id=%d), firstq_abs_id=%d, lastq_abs_id=%d\n",
								__func__, vsi->vsi_rel_num,
									vsi->vsi_abs_num,
								firstq_abs_id, lastq_abs_id);

	status = nse_aq_lan_ena_txq_many(&pf->hw, firstq_abs_id, lastq_abs_id, irqll);
	if (status)
		return -EIO;
	else
		return 0;
}

/**
 * nse_vsi_stop_tx_rings - Disable Tx rings
 * @vsi: the VSI being configured
 * @rst_src: reset source
 * @rel_vmvf_num: Relative ID of VF/VM
 * @rings: Tx ring array to be stopped
 */
int
nse_vsi_stop_tx_rings(struct nse_vsi *vsi,
		      struct nse_ring **rings, bool tdm_stopped)
{
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	int q_idx;
	int ret = 0;

	nse_debug(hw, NSE_DBG_LAN, "[%s] vsi=(rel_id:%d, abs_id=%d), num_txq=%d\n",
								__func__, vsi->vsi_rel_num,
									vsi->vsi_abs_num,
									vsi->num_txq);

	if (!vsi->num_txq)
		goto out;

	if (vsi->num_txq > NSE_LAN_TXQ_MAX_QDIS) {
		dev_err(dev, "[%s] BAD: vsi->num_txq=%d, > max: %d\n",
						__func__, vsi->num_txq, NSE_LAN_TXQ_MAX_QDIS);
		ret = -EINVAL;
		goto out;
	}

	if (!rings) {
		dev_err(dev, "[%s] BAD: rings = NULL ?\n", __func__);
		ret = -EINVAL;
		goto out;
	}

	for (q_idx = (vsi->num_txq - 1); q_idx >= 0; q_idx--) {
		if (!rings[q_idx]) {
			dev_err(dev, "[%s] BAD: rings[q_idx=%d] = NULL ?\n", __func__, q_idx);
			ret = -EINVAL;
			goto out;
		}
	}

	for (q_idx = (vsi->num_txq - 1); q_idx >= 0; q_idx--) {
		struct nse_txq_meta txq_meta = { };

		nse_fill_txq_meta(vsi, rings[q_idx], &txq_meta);

		ret = nse_vsi_stop_tx_ring(vsi, rings[q_idx], &txq_meta, tdm_stopped);

		if (ret) {
			dev_err(dev, "[%s] FAIL: vsi_stop_tx_ring(rings[q_idx=%d]), ret=%d\n",
				__func__, q_idx, ret);
			goto out;
		}
	}

out:
	return ret;
}

static int
nse_vsi_stop_tx_rings_bulk_tdm_only(struct nse_vsi *vsi, u16 firstq_abs_id,
				    u16 lastq_abs_id, u16 *irqll)
{
	struct nse_pf *pf = vsi->back;
	enum nse_status status;

	status = nse_aq_lan_dis_txq_many(&pf->hw, firstq_abs_id, lastq_abs_id, irqll);
	if (status)
		return -EIO;
	else
		return 0;
}

/**
 * nse_vsi_stop_lan_tx_rings - Enable LAN Tx rings
 * @vsi: the VSI being configured
 *
 *	This MUST be called after nse_setup_tx_ctx() properly setting the TXQ context for these TXQ.
 */
int
nse_vsi_start_lan_tx_rings(struct nse_vsi *vsi)
{
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_ring *ring = NULL;
	u16 firstq, lastq, i;
	u16 *irqll = NULL;
	int ret = 0;

	nse_debug(hw, NSE_DBG_LAN, "[%s] vsi=(rel_id:%d, abs_id=%d), num_txq=%d\n",
								__func__, vsi->vsi_rel_num,
									vsi->vsi_abs_num,
									vsi->num_txq);

	if (!vsi->num_txq)
		goto out;

	if (nse_lan_bulk_ena_dis) {
		irqll = kzalloc((sizeof(u16) * vsi->num_txq), GFP_KERNEL);
		if (!irqll) {
			ret = -ENOMEM;
			goto out;
		}

		firstq = vsi->vsi_txq_space_start + pf->lan_txq_space_start;
		lastq = firstq + vsi->num_txq - 1;

		nse_for_each_txq(vsi, i) {
			ring = vsi->tx_rings[i];
			irqll[i] = NSE_AQC_CONF_IRQLL_INVALID_MSIX;

			/* if to enable Q && already_in_irqll == 0, then need to add to irqll. */
			if (ring && ring->need_irqll && !ring->already_in_irqll)
				irqll[i] = ring->irqll_msix;
		}

		ret = nse_vsi_start_tx_rings_bulk(vsi, firstq, lastq, irqll);

		if (!ret) {
			nse_for_each_txq(vsi, i) {
				ring = vsi->tx_rings[i];

				if (ring && ring->need_irqll)
					ring->already_in_irqll = true;
			}

		} else {
			dev_err(dev, "[%s] FAIL: vsi_start_tx_rings_bulk(firstq_abs_id=%d, lastq_abs_id=%d), ret=%d\n",
							__func__, firstq, lastq, ret);
		}
	} else {
		ret = nse_vsi_start_tx_rings(vsi, vsi->tx_rings);
		if (ret)
			dev_err(dev, "[%s] FAIL: vsi_start_tx_rings(vsi->tx_rings), ret=%d\n",
							__func__, ret);
	}

out:
	kfree(irqll);

	return ret;
}

/**
 * nse_vsi_stop_lan_tx_rings - Disable LAN Tx rings
 * @vsi: the VSI being configured
 * @rst_src: reset source
 * @rel_vmvf_num: Relative ID of VF/VM
 */
int
nse_vsi_stop_lan_tx_rings(struct nse_vsi *vsi, bool tdm_stopped)
{
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_ring *ring = NULL;
	u16 *irqll = NULL;
	u16 firstq, lastq, i;
	int ret = 0;

	nse_debug(hw, NSE_DBG_LAN, "[%s] vsi=(rel_id:%d, abs_id=%d), num_txq=%d, tdm_stopped=%d\n",
								__func__, vsi->vsi_rel_num,
									vsi->vsi_abs_num,
									vsi->num_txq, tdm_stopped);

	if (!vsi->num_txq)
		goto out;

	if (vsi->num_txq > NSE_LAN_TXQ_MAX_QDIS) {
		dev_err(dev, "[%s] BAD: vsi->num_txq=%d, > max: %d\n",
						__func__, vsi->num_txq, NSE_LAN_TXQ_MAX_QDIS);
		ret = -EINVAL;
		goto out;
	}

	if (!tdm_stopped && nse_lan_bulk_ena_dis) {
		irqll = kzalloc((sizeof(u16) * vsi->num_txq), GFP_KERNEL);
		if (!irqll) {
			ret = -ENOMEM;
			goto out;
		}

		firstq = vsi->vsi_txq_space_start + pf->lan_txq_space_start;
		lastq = firstq + vsi->num_txq - 1;

		nse_for_each_txq(vsi, i) {
			ring = vsi->tx_rings[i];
			irqll[i] = NSE_AQC_CONF_IRQLL_INVALID_MSIX;

			/* if to disable Q && already_in_irqll == 1, then need to del from irqll */
			if (ring && ring->need_irqll && ring->already_in_irqll)
				irqll[i] = ring->irqll_msix;
		}

		ret = nse_vsi_stop_tx_rings_bulk_tdm_only(vsi, firstq, lastq, irqll);

		if (!ret) {
			nse_for_each_txq(vsi, i) {
				ring = vsi->tx_rings[i];

				if (ring && ring->need_irqll)
					ring->already_in_irqll = false;
			}
		} else {
			dev_err(dev, "[%s] FAIL: vsi_stop_tx_rings_bulk_tdm_only(firstq_abs_id=%d, lastq_abs_id=%d), ret=%d\n",
							__func__, firstq, lastq, ret);
			goto out;
		}

		tdm_stopped = true;
	}

	/* even TDM stopped, we still need to destroy LEAF-nodes, one by one */
	ret = nse_vsi_stop_tx_rings(vsi, vsi->tx_rings, tdm_stopped);
	if (ret)
		dev_err(dev, "[%s] FAIL: vsi_stop_tx_rings(firstq_abs_id=%d, lastq_abs_id=%d), ret=%d\n",
						__func__, firstq, lastq, ret);

out:
	kfree(irqll);

	return ret;
}

/**
 * nse_vsi_start_xdp_tx_rings - Enable XDP Tx rings
 * @vsi: the VSI being configured
 *
 *	This MUST be called after nse_setup_tx_ctx() properly setting the TXQ context for these TXQ.
 */
int nse_vsi_start_xdp_tx_rings(struct nse_vsi *vsi)
{
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_ring *ring = NULL;
	u16 firstq, lastq, i;
	u16 *irqll = NULL;
	int ret = 0;

	nse_debug(hw, NSE_DBG_LAN, "[%s] vsi=(rel_id:%d, abs_id=%d), num_xdp_txq=%d\n",
								__func__, vsi->vsi_rel_num,
									vsi->vsi_abs_num,
									vsi->num_xdp_txq);

	if (!vsi->num_xdp_txq)
		goto out;

	if (nse_lan_bulk_ena_dis) {
		irqll = kzalloc((sizeof(u16) * vsi->num_txq), GFP_KERNEL);
		if (!irqll) {
			ret = -ENOMEM;
			goto out;
		}

		firstq = vsi->vsi_xdp_txq_start + pf->lan_txq_space_start;
		lastq = firstq + vsi->num_txq - 1;

		nse_for_each_xdp_txq(vsi, i) {
			ring = vsi->xdp_rings[i];
			irqll[i] = NSE_AQC_CONF_IRQLL_INVALID_MSIX;

			/* if to enable Q && already_in_irqll == 0, then need to add to irqll. */
			if (ring && ring->need_irqll && !ring->already_in_irqll)
				irqll[i] = ring->irqll_msix;
		}

		ret = nse_vsi_start_tx_rings_bulk(vsi, firstq, lastq, irqll);

		if (!ret) {
			nse_for_each_xdp_txq(vsi, i) {
				ring = vsi->xdp_rings[i];

				if (ring && ring->need_irqll)
					ring->already_in_irqll = true;
			}

		} else {
			dev_err(dev, "[%s] FAIL: vsi_start_tx_rings_bulk(firstq_abs_id=%d, lastq_abs_id=%d), ret=%d\n",
							__func__, firstq, lastq, ret);
		}
	} else {
		ret = nse_vsi_start_tx_rings(vsi, vsi->xdp_rings);
		if (ret)
			dev_err(dev, "[%s] FAIL: vsi_start_tx_rings(vsi->xdp_rings), ret=%d\n",
							__func__, ret);
	}

out:
	kfree(irqll);

	return ret;
}

/**
 * nse_vsi_stop_xdp_tx_rings - Disable XDP Tx rings
 * @vsi: the VSI being configured
 */
int nse_vsi_stop_xdp_tx_rings(struct nse_vsi *vsi)
{
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_ring *ring = NULL;
	u16 *irqll = NULL;
	u16 firstq, lastq, i;
	bool tdm_stopped = false;
	int ret = 0;

	nse_debug(hw, NSE_DBG_LAN, "[%s] vsi=(rel_id:%d, abs_id=%d), num_xdp_txq=%d\n",
								__func__, vsi->vsi_rel_num,
									vsi->vsi_abs_num,
									vsi->num_xdp_txq);

	if (!vsi->num_xdp_txq)
		goto out;

	if (nse_lan_bulk_ena_dis) {
		irqll = kzalloc((sizeof(u16) * vsi->num_xdp_txq), GFP_KERNEL);
		if (!irqll) {
			ret = -ENOMEM;
			goto out;
		}

		firstq = vsi->vsi_xdp_txq_start + pf->lan_txq_space_start;
		lastq = firstq + vsi->num_xdp_txq - 1;

		nse_for_each_xdp_txq(vsi, i) {
			ring = vsi->xdp_rings[i];
			irqll[i] = NSE_AQC_CONF_IRQLL_INVALID_MSIX;

			/* if to disable Q && already_in_irqll == 1, then need to del from irqll */
			if (ring && ring->need_irqll && ring->already_in_irqll)
				irqll[i] = ring->irqll_msix;
		}

		ret = nse_vsi_stop_tx_rings_bulk_tdm_only(vsi, firstq, lastq, irqll);

		if (!ret) {
			nse_for_each_xdp_txq(vsi, i) {
				ring = vsi->xdp_rings[i];

				if (ring && ring->need_irqll)
					ring->already_in_irqll = false;
			}
		} else {
			dev_err(dev, "[%s] FAIL: vsi_stop_tx_rings_bulk_tdm_only(firstq_abs_id=%d, lastq_abs_id=%d), ret=%d\n",
							__func__, firstq, lastq, ret);
			goto out;
		}

		tdm_stopped = true;
	}

	/* even TDM stopped, we still need to destroy LEAF-nodes, one by one */
	ret = nse_vsi_stop_tx_rings(vsi, vsi->xdp_rings, tdm_stopped);
	if (ret)
		dev_err(dev, "[%s] FAIL: vsi_stop_tx_rings(firstq_abs_id=%d, lastq_abs_id=%d), ret=%d\n",
						__func__, firstq, lastq, ret);

out:
	kfree(irqll);

	return ret;
}

int nse_vsi_cfg_single_rxq(struct nse_vsi *vsi, u16 q_idx)
{
	if (q_idx >= vsi->num_rxq)
		return -EINVAL;

	return nse_vsi_cfg_rxq(vsi->rx_rings[q_idx]);
}

int nse_vsi_cfg_single_txq(struct nse_vsi *vsi, struct nse_ring **tx_rings, u16 q_idx)
{
	if (q_idx >= vsi->alloc_txq || !tx_rings || !tx_rings[q_idx])
		return -EINVAL;

	return nse_vsi_cfg_txq(tx_rings[q_idx]);
}

/**
 * nse_vsi_cfg_rxqs - Configure the VSI for Rx
 * @vsi: the VSI being configured
 *
 * Return 0 on success and a negative value on error
 * Configure the Rx VSI for operation.
 */
int nse_vsi_cfg_rxqs(struct nse_vsi *vsi)
{
	u32 vsi_rxmax;
	u16 i;
	int err;

	if (vsi->type == NSE_VSI_VF)
		goto setup_rings;

	nse_vsi_cfg_frame_size(vsi);

	if (nse_vsi_is_any_xdp_enabled(vsi))
		vsi_rxmax = vsi->rx_buf_len;
	else
		vsi_rxmax = vsi->max_frame;

	err = nse_vsi_cfg_rx_max(vsi, vsi_rxmax);
	if (err)
		return err;

setup_rings:
	/* set up individual rings */
	nse_for_each_rxq(vsi, i) {
		err = nse_vsi_cfg_rxq(vsi->rx_rings[i]);

		if (err)
			return err;
	}

	return 0;
}

/**
 * nse_vsi_cfg_txqs - Configure the VSI for Tx
 * @vsi: the VSI being configured
 * @tx_rings: Tx ring array to be configured
 *
 * Return 0 on success and a negative value on error
 * Configure the Tx VSI for operation.
 */
static int
nse_vsi_cfg_txqs(struct nse_vsi *vsi, struct nse_ring **tx_rings)
{
	int q_idx = 0;
	int err = 0;

	for (q_idx = 0; q_idx < vsi->num_txq; q_idx++) {
		err = nse_vsi_cfg_txq(tx_rings[q_idx]);
		if (err)
			goto fail_cleanup;
	}

out:
	return err;

fail_cleanup:
	/* here not use: q_idx >= 0, because below we use: q_idx - 1 */
	for (; q_idx > 0; q_idx--) {
		struct nse_txq_meta txq_meta = { };

		nse_fill_txq_meta(vsi, tx_rings[q_idx - 1], &txq_meta);

		(void)nse_vsi_stop_tx_ring(vsi, tx_rings[q_idx - 1], &txq_meta, true);
	}

	goto out;
}

/**
 * nse_vsi_cfg_lan_txqs - Configure the VSI for Tx
 * @vsi: the VSI being configured
 *
 * Return 0 on success and a negative value on error
 * Configure the Tx VSI for operation.
 */
int nse_vsi_cfg_lan_txqs(struct nse_vsi *vsi)
{
	return nse_vsi_cfg_txqs(vsi, vsi->tx_rings);
}

/**
 * nse_vsi_cfg_xdp_txqs - Configure Tx queues dedicated for XDP in given VSI
 * @vsi: the VSI being configured
 *
 * Return 0 on success and a negative value on error
 * Configure the Tx queues dedicated for XDP in given VSI for operation.
 */
int nse_vsi_cfg_xdp_txqs(struct nse_vsi *vsi)
{
	int ret;
	int i;

	ret = nse_vsi_cfg_txqs(vsi, vsi->xdp_rings);
	if (ret)
		return ret;

	for (i = 0; i < vsi->num_xdp_txq; i++)
		vsi->xdp_rings[i]->xsk_pool = nse_xsk_umem(vsi->xdp_rings[i]);

	return ret;
}

int nse_vsi_cfg_lan_txcqs(struct nse_vsi *vsi)
{
	int err;
	u16 i;

	if (!vsi->sw_conf.lan_tx_use_cq)
		return 0;

	nse_for_each_lan_txcq(vsi, i) {
		err = nse_vsi_cfg_lan_txcq(vsi->txcq_rings[i]);
		if (err)
			return err;
	}

	return err;
}

int nse_vsi_start_lan_txcq_rings(struct nse_vsi *vsi)
{
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;

	nse_debug(hw, NSE_DBG_LAN, "[%s]: vsi=(rel_id:%d, abs_id=%d), lan_tx_use_cq=%d\n",
								__func__, vsi->vsi_rel_num,
									vsi->vsi_abs_num,
									vsi->sw_conf.lan_tx_use_cq);

	if (!vsi->sw_conf.lan_tx_use_cq)
		return 0;

	return nse_vsi_ctrl_all_txcq_rings(vsi, true);
}

int nse_vsi_stop_lan_txcq_rings(struct nse_vsi *vsi)
{
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;

	if (!vsi->sw_conf.lan_tx_use_cq)
		return 0;

	nse_debug(hw, NSE_DBG_LAN, "[%s] vsi=(rel_id:%d, abs_id=%d), lan_tx_use_cq=%d\n",
								__func__, vsi->vsi_rel_num,
									vsi->vsi_abs_num,
									vsi->sw_conf.lan_tx_use_cq);

	return nse_vsi_ctrl_all_txcq_rings(vsi, false);
}

static void nse_vsi_set_tc_cfg(struct nse_vsi *vsi)
{
	if (!test_bit(NSE_FLAG_DCB_ENA, vsi->back->flags)) {
		vsi->tc_cfg.ena_tc = NSE_DFLT_TRAFFIC_CLASS;
		vsi->tc_cfg.numtc = 1;
		return;
	}

	/* set VSI TC information based on DCB config */
	nse_vsi_set_dcb_tc_cfg(vsi);
}

/**
 * nse_vsi_set_q_vectors_reg_idx - set the HW register index for all q_vectors
 * @vsi: VSI to set the q_vectors register index on
 * @tc: traffic class for VF ADQ
 */
static int nse_vsi_set_q_vectors_reg_idx(struct nse_vsi *vsi,
					 u8 __maybe_unused tc)
{
	u16 i;

	if (!vsi || !vsi->q_vectors)
		return -EINVAL;

	nse_for_each_q_vector(vsi, i) {
		struct nse_q_vector *q_vector = vsi->q_vectors[i];

		if (!q_vector) {
			dev_err(nse_pf_to_dev(vsi->back), "Failed to set reg_idx on q_vector %d VSI %d\n",
				i, vsi->vsi_abs_num);
			goto clear_reg_idx;
		}

		if (vsi->type == NSE_VSI_VF) {
			struct nse_vf *vf = vsi->vf;

			q_vector->reg_idx =
					nse_calc_vf_reg_idx(vf, q_vector, tc);
		} else {
			q_vector->reg_idx =
				q_vector->v_idx + vsi->base_vector;
		}
	}

	return 0;

clear_reg_idx:
	nse_for_each_q_vector(vsi, i) {
		struct nse_q_vector *q_vector = vsi->q_vectors[i];

		if (q_vector)
			q_vector->reg_idx = 0;
	}

	return -EINVAL;
}

/**
 * nse_cfg_sw_lldp - Config switch rules for LLDP packet handling
 * @vsi: the VSI being configured
 * @tx: bool to determine Tx or Rx rule
 * @create: bool to determine create or remove Rule
 */
void nse_cfg_sw_lldp(struct nse_vsi *vsi, bool tx, bool create)
{
	enum nse_status (*eth_fltr)(struct nse_vsi *v, u16 type, u16 flag,
				    enum nse_sw_fwd_act_type act);
	struct nse_pf *pf = vsi->back;
	enum nse_status status;
	struct device *dev;

	dev = nse_pf_to_dev(pf);
	eth_fltr = create ? nse_fltr_add_eth : nse_fltr_remove_eth;

	if (tx) {
		status = eth_fltr(vsi, ETH_P_LLDP, NSE_FLTR_TX,
				  NSE_DROP_PACKET);
	} else {
		if (nse_fw_supports_lldp_fltr_ctrl(&pf->hw)) {
			status = nse_lldp_fltr_add_remove(&pf->hw, vsi->vsi_abs_num,
							  create);
		} else {
			status = eth_fltr(vsi, ETH_P_LLDP, NSE_FLTR_RX,
					  NSE_FWD_TO_VSI);
		}
	}

	if (status)
		dev_dbg(dev, "Fail %s %s LLDP rule on VSI %i error: %s\n",
			create ? "adding" : "removing", tx ? "TX" : "RX",
			vsi->vsi_abs_num, nse_stat_str(status));
}

/**
 * nse_vsi_setup - Set up a VSI by a given type
 * @pf: board private structure
 * @pi: pointer to the port_info instance
 * @vsi_type: VSI type
 * @vf: pointer to the VF associated with this VSI, if any. VSIs not
 *      connected to a VF should pass NULL.
 * @ch: ptr to channel
 * @tc: traffic class for VF ADQ
 *
 * This allocates the sw VSI structure and its queue resources.
 *
 * Returns pointer to the successfully allocated and configured VSI sw struct on
 * success, NULL on failure.
 */
struct nse_vsi *
nse_vsi_setup(struct nse_pf *pf, struct nse_port_info *pi,
	      enum nse_vsi_type vsi_type, struct nse_vf *vf,
	      u8 tc)
{
	u16 max_txqs[NSE_MAX_TRAFFIC_CLASS] = { 0 };
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	enum nse_status status;
	struct nse_vsi *vsi;
	int ret, i;

	vsi = nse_vsi_alloc(pf, vsi_type, vf, tc);

	if (!vsi) {
		dev_err(dev, "[%s] FAIL: vsi_alloc\n", __func__);
		return NULL;
	}

	vsi->port_info = pi;
	vsi->vsw = pf->first_sw;

	if (nse_vsi_get_qs(vsi)) {
		dev_err(dev, "[%s] FAIL: vsi_get_qs(), vsi->idx=%d\n", __func__, vsi->idx);
		goto unroll_vsi_alloc;
	}

	if (nse_vsi_rss_init(vsi)) {
		dev_err(dev, "[%s] FAIL: rss_init(), vsi->idx=%d\n", __func__, vsi->idx);
		goto unroll_get_qs;
	}

	/* set TC configuration */
	nse_vsi_set_tc_cfg(vsi);

	/* create the VSI */
	ret = nse_vsi_init(vsi, true);
	if (ret)
		goto unroll_rss_init;

	nse_vsi_init_vlan_ops(vsi);

	switch (vsi->type) {
	case NSE_VSI_OFFLOAD_MACVLAN:
	case NSE_VSI_ADI:
	case NSE_VSI_SWITCHDEV_CTRL:
	case NSE_VSI_PF:
		ret = nse_vsi_alloc_q_vectors(vsi);
		if (ret)
			goto unroll_vsi_init;

		ret = nse_vsi_setup_vector_base(vsi, 0);
		if (ret)
			goto unroll_alloc_q_vector;

		ret = nse_vsi_set_q_vectors_reg_idx(vsi, 0);
		if (ret)
			goto unroll_vector_base;

		ret = nse_vsi_alloc_rings(vsi);
		if (ret)
			goto unroll_vector_base;

		ret = nse_vsi_map_rings_to_vectors(vsi);
		if (ret)
			goto unroll_clear_rings;

		nse_vsi_reset_stats(vsi);

		if (vsi->type == NSE_VSI_PF)
			nse_fdir_main_vsi_init(hw, vsi);

		break;

	case NSE_VSI_VF:
		/* VF driver will take care of creating netdev for this type and
		 * map queues to vectors through Virtchnl, PF driver only
		 * creates a VSI and corresponding structures for bookkeeping
		 * purpose
		 */
		ret = nse_vsi_alloc_q_vectors(vsi);
		if (ret)
			goto unroll_vsi_init;

		ret = nse_vsi_alloc_rings(vsi);
		if (ret)
			goto unroll_alloc_q_vector;

		ret = nse_vsi_setup_vector_base(vsi, tc);
		if (ret)
			goto unroll_alloc_q_vector;

		ret = nse_vsi_set_q_vectors_reg_idx(vsi, tc);
		if (ret)
			goto unroll_vector_base;

		nse_fdir_vf_vsi_init(hw, vsi, vf);

		break;
	case NSE_VSI_LB:
		ret = nse_vsi_alloc_rings(vsi);
		if (ret)
			goto unroll_vsi_init;
		break;
	default:
		/* clean up the resources and exit */
		goto unroll_vsi_init;
	}

	/* configure VSI nodes based on number of queues and TC's */
	nse_for_each_traffic_class(i) {
		if (!(vsi->tc_cfg.ena_tc & BIT(i)))
			continue;

		max_txqs[i] = vsi->alloc_txq;
	}

	ret = nse_vsi_cfg_rss(vsi);
	if (ret) {
		dev_err(dev, "VSI(abs_id=%d, rel_id=%d) failed at vsi_cfg_rss(), ret=%d\n",
			vsi->vsi_abs_num, vsi->vsi_rel_num, ret);
		goto unroll_clear_rings;
	}

	dev_dbg(dev, "vsi->tc_cfg.ena_tc = %d\n", vsi->tc_cfg.ena_tc);

	status = nse_cfg_vsi_lan(vsi->port_info, vsi->idx, vsi->tc_cfg.ena_tc,
				 max_txqs);
	if (status) {
		dev_err(dev, "FAIL: cfg_vsi_lan(): VSI(abs_id=%d, rel_id=%d), error %d(%s)\n",
			vsi->vsi_abs_num, vsi->vsi_rel_num, status, nse_stat_str(status));
		goto unroll_clear_rings;
	}

	/* Add switch rule to drop all Tx Flow Control Frames, of look up
	 * type ETHERTYPE from VSIs, and restrict malicious VF from sending
	 * out PAUSE or PFC frames. If enabled, FW can still send FC frames.
	 * The rule is added once for PF VSI in order to create appropriate
	 * recipe, since VSI/VSI list is ignored with drop action...
	 * Also add rules to handle LLDP Tx packets.  Tx LLDP packets need to
	 * be dropped so that VFs cannot send LLDP packets to reconfig DCB
	 * settings in the HW.
	 */
	if (vsi->type == NSE_VSI_PF) {
		(void)nse_fltr_add_eth(vsi, ETH_P_PAUSE, NSE_FLTR_TX,
					 NSE_DROP_PACKET);
		nse_cfg_sw_lldp(vsi, true, true);
	}

	nse_debugfs_vsi_init(vsi);

#if defined(NSE_DEBUG_EXT)
	vsi->debug_lan_no_xmit = nse_lan_no_xmit;
#endif

	return vsi;

unroll_clear_rings:
	nse_vsi_clear_rings(vsi);
unroll_vector_base:
	/* reclaim SW interrupts back to the common pool */
	nse_vsi_release_vector_base(vsi);
unroll_alloc_q_vector:
	nse_vsi_free_q_vectors(vsi);
unroll_vsi_init:
	nse_vsi_delete(vsi);
unroll_rss_init:
	nse_vsi_rss_deinit(vsi);
unroll_get_qs:
	nse_vsi_put_qs(vsi);
unroll_vsi_alloc:
	nse_vsi_clear(vsi);

	return NULL;
}

/**
 * nse_vsi_release_msix - Clear the queue to Interrupt mapping in HW
 * @vsi: the VSI being cleaned up
 */
static void nse_vsi_release_msix(struct nse_vsi *vsi)
{
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	int i;

	for (i = 0; i < vsi->num_q_vectors; i++) {
		struct nse_q_vector *q_vector = vsi->q_vectors[i];

		nse_write_intrl(q_vector, 0);
		nse_write_itr(q_vector, 0);
	}

	nse_flush(hw);
}

/**
 * nse_vsi_free_irq - Free the IRQ association with the OS
 * @vsi: the VSI being configured
 */
void nse_vsi_free_irq(struct nse_vsi *vsi)
{
	struct nse_pf *pf = vsi->back;
	int base = vsi->base_vector;
	int i;

	if (!vsi->q_vectors || !vsi->irqs_ready)
		return;

	nse_vsi_release_msix(vsi);
	if (vsi->type == NSE_VSI_VF)
		return;

	vsi->irqs_ready = false;

	if (nse_no_irq)
		return;

	nse_for_each_q_vector(vsi, i) {
		u16 vector = i + base;
		int irq_num;

		irq_num = nse_get_irq_num(pf, vector);

		/* free only the irqs that were actually requested */
		if (!vsi->q_vectors[i] ||
		    !(vsi->q_vectors[i]->num_ring_tx ||
		      vsi->q_vectors[i]->num_ring_rx))
			continue;

		/* clear the affinity notifier in the IRQ descriptor */
		irq_set_affinity_notifier(irq_num, NULL);

		/* clear the affinity_mask in the IRQ descriptor */
		irq_set_affinity_hint(irq_num, NULL);
		synchronize_irq(irq_num);
		devm_free_irq(nse_pf_to_dev(pf), irq_num, vsi->q_vectors[i]);
	}
}

/**
 * nse_vsi_free_tx_rings - Free Tx resources for VSI queues
 * @vsi: the VSI having resources freed
 */
void nse_vsi_free_tx_rings(struct nse_vsi *vsi)
{
	int i;

	if (!vsi->tx_rings)
		return;

	nse_for_each_txq(vsi, i)
		if (vsi->tx_rings[i] && vsi->tx_rings[i]->desc)
			nse_free_tx_ring(vsi->tx_rings[i]);
}

/**
 * nse_vsi_free_rx_rings - Free Rx resources for VSI queues
 * @vsi: the VSI having resources freed
 */
void nse_vsi_free_rx_rings(struct nse_vsi *vsi)
{
	int i;

	if (!vsi->rx_rings)
		return;

	nse_for_each_rxq(vsi, i)
		if (vsi->rx_rings[i] && vsi->rx_rings[i]->desc)
			nse_free_rx_ring(vsi->rx_rings[i]);
}

void nse_vsi_free_lan_txcq_rings(struct nse_vsi *vsi)
{
	int i;

	if (!vsi->txcq_rings)
		return;

	nse_for_each_lan_txcq(vsi, i)
		if (vsi->txcq_rings[i] && vsi->txcq_rings[i]->desc)
			nse_free_lan_txcq_ring(vsi->txcq_rings[i]);
}

/**
 * nse_vsi_close - Shut down a VSI
 * @vsi: the VSI being shut down
 */
void nse_vsi_close(struct nse_vsi *vsi)
{
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;

	nse_debug(hw, NSE_DBG_LAN, "[%s] vsi=(rel_id:%d, abs_id=%d)\n",
								__func__, vsi->vsi_rel_num,
									vsi->vsi_abs_num);

	if (!test_and_set_bit(NSE_VSI_DOWN, vsi->state))
		nse_down(vsi);
	nse_vsi_free_irq(vsi);
	nse_vsi_free_tx_rings(vsi);
	nse_vsi_free_rx_rings(vsi);
	nse_vsi_free_lan_txcq_rings(vsi);
}

/**
 * nse_ena_vsi - resume a VSI
 * @vsi: the VSI being resume
 * @locked: is the rtnl_lock already held
 */
int nse_ena_vsi_under_pf_drv(struct nse_hw *hw, struct nse_vsi *vsi, bool locked)
{
	int err = 0;

	nse_debug(hw, NSE_DBG_SYS, "[%s] vsi (rel_id=%d, abs_id=%d)\n",
					__func__, vsi->vsi_rel_num, vsi->vsi_abs_num);

	if (!nse_is_vsi_type_under_pf_drv(vsi->type))
		return 0;

	if (!test_bit(NSE_VSI_NEEDS_RESTART, vsi->state))
		return 0;

	clear_bit(NSE_VSI_NEEDS_RESTART, vsi->state);

	if (vsi->netdev && vsi->type == NSE_VSI_PF) {
		if (vsi->netdev->flags & IFF_UP) {
			if (!locked)
				rtnl_lock();

			err = nse_open_internal(vsi->netdev);

			if (!locked)
				rtnl_unlock();
		}

		if (err)
			return err;

		if (test_bit(NSE_FLAG_MACVLAN_ENA, vsi->back->flags))
			err = nse_vsi_cfg_netdev_tc0(vsi);
	} else if (vsi->type == NSE_VSI_SWITCHDEV_CTRL) {
		err = nse_vsi_open(vsi);
	} else if (vsi->type == NSE_VSI_OFFLOAD_MACVLAN) {
		err = nse_vsi_open(vsi);
	}

	return err;
}

/**
 * nse_dis_vsi - pause a VSI
 * @vsi: the VSI being paused
 * @locked: is the rtnl_lock already held
 */
void nse_dis_vsi_under_pf_drv(struct nse_hw *hw, struct nse_vsi *vsi, bool locked)
{
	struct nse_pf *pf = vsi->back;
	struct device *dev = nse_pf_to_dev(pf);

	nse_debug(hw, NSE_DBG_SYS, "[%s] vsi (rel_id=%d, abs_id=%d), vsi_type=%s\n",
								__func__, vsi->vsi_rel_num,
									vsi->vsi_abs_num,
								nse_vsi_type_str(vsi->type));

	if (!nse_is_vsi_type_under_pf_drv(vsi->type))
		return;

	if (test_bit(NSE_VSI_DOWN, vsi->state))
		return;

	set_bit(NSE_VSI_NEEDS_RESTART, vsi->state);

	if (vsi->type == NSE_VSI_PF && vsi->netdev) {
		if (vsi->netdev->flags & IFF_UP) {
			if (!locked)
				rtnl_lock();

			nse_vsi_close(vsi);

			if (!locked)
				rtnl_unlock();
		} else {
			nse_vsi_close(vsi);
		}
	} else if (vsi->type == NSE_VSI_OFFLOAD_MACVLAN ||
			vsi->type == NSE_VSI_SWITCHDEV_CTRL ||
			vsi->type == NSE_VSI_LB) {
		nse_vsi_close(vsi);
	} else {
		dev_info(dev, "[%s] unknown vsi_type (%d) under pf drv, just try vsi_close()\n",
						__func__, vsi->type);
		nse_vsi_close(vsi);
	}
}

/**
 * nse_vsi_dis_irq - Mask off queue interrupt generation on the VSI
 * @vsi: the VSI being un-configured
 */
void nse_vsi_dis_irq(struct nse_vsi *vsi)
{
	int base = vsi->base_vector;
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	int i;

	/* disable each interrupt */
	nse_for_each_q_vector(vsi, i) {
		if (!vsi->q_vectors[i])
			continue;

		/* mask it: INTMSK_VLD=1, INTMSK=1 */
		wr32(hw, NSE_REG_INT_DYN_CTLN(vsi->q_vectors[i]->reg_idx),
				(NSE_REG_INT_DYN_CTLN_INTMSK_VLD_M |
				 NSE_REG_INT_DYN_CTLN_INTMSK_M));
	}

	nse_flush(hw);

	/* don't call synchronize_irq() for VF's from the host */
	if (nse_is_vsi_type_under_vf_drv(vsi->type))
		return;

	if (nse_no_irq)
		return;

	nse_for_each_q_vector(vsi, i)
		synchronize_irq(nse_get_irq_num(pf, i + base));
}

/**
 * nse_vsi_release - Delete a VSI and free its resources
 * @vsi: the VSI being removed
 *
 * Returns 0 on success or < 0 on error
 */
int nse_vsi_release(struct nse_vsi *vsi)
{
	struct nse_pf *pf;
	int err;

	if (!vsi->back)
		return -ENODEV;
	pf = vsi->back;

	nse_debugfs_vsi_exit(vsi);

	/* do not unregister while driver is in the reset recovery pending
	 * state. Since reset/rebuild happens through PF service task workqueue,
	 * it's not a good idea to unregister netdev that is associated to the
	 * PF that is running the work queue items currently. This is done to
	 * avoid check_flush_dependency() warning on this wq
	 */
	if (vsi->netdev && !nse_is_reset_in_progress(pf->state) &&
	    (test_bit(NSE_VSI_NETDEV_REGISTERED, vsi->state))) {
		unregister_netdev(vsi->netdev);
		clear_bit(NSE_VSI_NETDEV_REGISTERED, vsi->state);

		if (vsi->type == NSE_VSI_PF)
			nse_devlink_destroy_pf_port(pf);
	}

	if (vsi->type == NSE_VSI_PF)
		nse_fdir_main_vsi_deinit(&pf->hw, vsi);

	/* Disable VSI and free resources */
	if (vsi->type != NSE_VSI_LB)
		nse_vsi_dis_irq(vsi);

	nse_vsi_close(vsi);

	/* SR-IOV determines needed MSIX resources all at once instead of per
	 * VSI since when VFs are spawned we know how many VFs there are and how
	 * many interrupts each VF needs. SR-IOV MSIX resources are also
	 * cleared in the same manner.
	 */
	if (vsi->type != NSE_VSI_VF) {
		/* reclaim SW interrupts back to the common pool */
		nse_free_res(pf->irq_tracker_self_region, vsi->base_vector,
			     NSE_RES_IRQ_ID_NONVF_VSI_BASE + vsi->idx);
		pf->num_avail_sw_msix += vsi->num_q_vectors;

		vsi->base_vector = NSE_INVAL_IRQ_ID;
	}

	if (vsi->type == NSE_VSI_PF) {
		nse_fltr_remove_eth(vsi, ETH_P_PAUSE, NSE_FLTR_TX,
				    NSE_DROP_PACKET);
		nse_cfg_sw_lldp(vsi, true, false);
		/* The Rx rule will only exist to remove if the LLDP FW
		 * engine is currently stopped
		 */
		if (!test_bit(NSE_FLAG_FW_LLDP_AGENT_ENA, pf->flags))
			nse_cfg_sw_lldp(vsi, false, false);
	}

	nse_fltr_remove_all(vsi);

	nse_rm_vsi_lan_cfg(vsi->port_info, vsi->idx);
	err = nse_rm_vsi_rdma_cfg(vsi->port_info, vsi->idx);
	if (err)
		dev_info(nse_pf_to_dev(vsi->back), "Failed to remove RDMA scheduler config for VSI %u, err %d\n",
			 vsi->vsi_abs_num, err);

	nse_vsi_delete(vsi);

	nse_vsi_free_q_vectors(vsi);

	if (vsi->netdev && !nse_is_reset_in_progress(pf->state)) {
		if (test_bit(NSE_VSI_NETDEV_REGISTERED, vsi->state)) {
			unregister_netdev(vsi->netdev);
			clear_bit(NSE_VSI_NETDEV_REGISTERED, vsi->state);
		}
		if (test_bit(NSE_VSI_NETDEV_ALLOCD, vsi->state)) {
			free_netdev(vsi->netdev);
			vsi->netdev = NULL;
			clear_bit(NSE_VSI_NETDEV_ALLOCD, vsi->state);
		}
	}

	nse_vsi_clear_rings(vsi);

	nse_vsi_put_qs(vsi);

	nse_vsi_rss_deinit(vsi);

	/* retain SW VSI data structure since it is needed to unregister and
	 * free VSI netdev when PF is not in reset recovery pending state,\
	 * for ex: during rmmod.
	 */
	if (!nse_is_reset_in_progress(pf->state))
		nse_vsi_clear(vsi);

	return 0;
}

/**
 * nse_vsi_rebuild_get_coalesce - get coalesce from all q_vectors
 * @vsi: VSI connected with q_vectors
 * @coalesce: array of struct with stored coalesce
 *
 * Returns array size.
 */
static int
nse_vsi_rebuild_get_coalesce(struct nse_vsi *vsi,
			     struct nse_coalesce_stored *coalesce)
{
	int i;

	nse_for_each_q_vector(vsi, i) {
		struct nse_q_vector *q_vector = vsi->q_vectors[i];

		coalesce[i].itr_settings = q_vector->itr_settings;
		coalesce[i].intrl = q_vector->intrl;
		coalesce[i].valid = true;
	}

	return vsi->num_q_vectors;
}

/**
 * nse_vsi_rebuild_set_coalesce - set coalesce from earlier saved arrays
 * @vsi: VSI connected with q_vectors
 * @coalesce: pointer to array of struct with stored coalesce
 * @size: size of coalesce array
 *
 * Before this function, nse_vsi_rebuild_get_coalesce should be called to save
 * ITR params in arrays. If size is 0 or coalesce wasn't stored set coalesce
 * to default value.
 */
static void
nse_vsi_rebuild_set_coalesce(struct nse_vsi *vsi,
			     struct nse_coalesce_stored *coalesce, int size)
{
	struct nse_q_vector *q_vector;
	int i;

	if ((size && !coalesce) || !vsi)
		return;

	/* There are a couple of cases that have to be handled here:
	 *   1. The case where the number of queue vectors stays the same, but
	 *      the number of Tx or Rx rings changes (the first for loop)
	 *   2. The case where the number of queue vectors increased (the
	 *      second for loop)
	 */
	for (i = 0; i < size && i < vsi->num_q_vectors; i++) {
		q_vector = vsi->q_vectors[i];

		/* There are 2 cases to handle here and they are the same for
		 * both Tx and Rx:
		 *   if the entry was valid previously (coalesce[i].[tr]x_valid
		 *   and the loop variable is less than the number of rings
		 *   allocated, then write the previous values
		 *
		 *   if the entry was not valid previously, but the number of
		 *   rings is less than are allocated (this means the number of
		 *   rings increased from previously), then write out the
		 *   values in the first element
		 *
		 *   Also, always write the ITR, even if in ITR_IS_DYNAMIC
		 *   as there is no harm because the dynamic algorithm
		 *   will just overwrite.
		 */
		if ((i < vsi->alloc_rxq || i < vsi->alloc_txq) && coalesce[i].valid) {
			q_vector->itr_settings = coalesce[i].itr_settings;
			nse_write_itr(q_vector, q_vector->itr_setting);
		} else if ((i < vsi->alloc_rxq || i < vsi->alloc_txq)) {
			q_vector->itr_settings = coalesce[0].itr_settings;
			nse_write_itr(q_vector, q_vector->itr_setting);
		}

		q_vector->intrl = coalesce[i].intrl;
		nse_set_q_vector_intrl(vsi->q_vectors[i]);
	}

	/* the number of queue vectors increased so write whatever is in
	 * the first element
	 */
	for (; i < vsi->num_q_vectors; i++) {
		q_vector = vsi->q_vectors[i];

		q_vector->itr_settings = coalesce[0].itr_settings;
		nse_write_itr(q_vector, q_vector->itr_setting);

		q_vector->intrl = coalesce[0].intrl;
		nse_set_q_vector_intrl(vsi->q_vectors[i]);
	}
}

/**
 * nse_vsi_rebuild - Rebuild VSI after reset
 * @vsi: VSI to be rebuild
 * @init_vsi: is this an initialization or a reconfigure of the VSI
 *
 * Returns 0 on success and negative value on failure
 */
int nse_vsi_rebuild(struct nse_hw *hw, struct nse_vsi *vsi, bool init_vsi)
{
	u16 max_txqs[NSE_MAX_TRAFFIC_CLASS] = { 0 };
	struct nse_coalesce_stored *coalesce;
	int prev_num_q_vectors = 0;
	enum nse_vsi_type vtype = vsi->type;
	enum nse_status status;
	struct nse_pf *pf = vsi->back;
	struct device *dev = nse_pf_to_dev(pf);
	int ret, i;

	if (!vsi)
		return -EINVAL;

	nse_debug(hw, NSE_DBG_SYS, "[%s] vsi (rel_id=%d, abs_id=%d), type=%s, init_vsi=%d\n",
					__func__, vsi->vsi_rel_num, vsi->vsi_abs_num,
					nse_vsi_type_str(vsi->type), init_vsi);

	if (WARN_ON(nse_vsi_requires_vf(vtype) && !vsi->vf))
		return -EINVAL;

	nse_vsi_init_vlan_ops(vsi);

	coalesce = kcalloc(vsi->num_q_vectors,
			   sizeof(struct nse_coalesce_stored), GFP_KERNEL);
	if (!coalesce)
		return -ENOMEM;

	prev_num_q_vectors = nse_vsi_rebuild_get_coalesce(vsi, coalesce);

	nse_rm_vsi_lan_cfg(vsi->port_info, vsi->idx);
	ret = nse_rm_vsi_rdma_cfg(vsi->port_info, vsi->idx);
	if (ret)
		dev_info(dev, "Failed to remove RDMA scheduler config for VSI %u, err %d\n",
			 vsi->vsi_abs_num, ret);

	nse_vsi_free_q_vectors(vsi);

	/* SR-IOV determines needed MSIX resources all at once instead of per
	 * VSI since when VFs are spawned we know how many VFs there are and how
	 * many interrupts each VF needs. SR-IOV MSIX resources are also
	 * cleared in the same manner.
	 */
	if (vtype != NSE_VSI_VF) {
		/* reclaim SW interrupts back to the common pool */
		nse_free_res(pf->irq_tracker_self_region, vsi->base_vector,
			     NSE_RES_IRQ_ID_NONVF_VSI_BASE + vsi->idx);
		pf->num_avail_sw_msix += vsi->num_q_vectors;

		vsi->base_vector = NSE_INVAL_IRQ_ID;
	}

	if (nse_is_xdp_ena_vsi(vsi))
		/* return value check can be skipped here, it always returns
		 * 0 if reset is in progress
		 */
		nse_destroy_xdp_rings(vsi);

	nse_vsi_put_qs(vsi);

	nse_vsi_clear_rings(vsi);
	nse_vsi_free_arrays(vsi);

	nse_vsi_set_num_qs(vsi, vsi->vf);

	ret = nse_vsi_alloc_arrays(vsi);
	if (ret < 0) {
		dev_err(dev, "FAIL: vsi_alloc_arrays (vsi->idx = %d)\n", vsi->idx);
		goto err_vsi;
	}

	nse_vsi_rss_rebuild_pre(vsi);

	ret = nse_vsi_get_qs(vsi);
	if (ret < 0) {
		dev_err(dev, "FAIL: vsi_get_qs (vsi->idx = %d)\n", vsi->idx);
		goto err_vsi;
	}

	ret = nse_vsi_rss_rebuild_post(vsi);	/* including nse_vsi_cfg_rss() inside */
	if (ret < 0) {
		dev_err(dev, "[%s, %d] vsi_rss_rebuild_post() fails. vsi->idx = %d\n",
						__func__, __LINE__, vsi->idx);
		goto err_vsi;
	}

	nse_vsi_set_tc_cfg(vsi);

	/* Initialize VSI struct elements and create VSI in FW */
	ret = nse_vsi_init(vsi, init_vsi);
	if (ret < 0)
		goto err_vsi;

	switch (vtype) {
	case NSE_VSI_OFFLOAD_MACVLAN:
	case NSE_VSI_ADI:
	case NSE_VSI_SWITCHDEV_CTRL:
	case NSE_VSI_PF:
		ret = nse_vsi_alloc_q_vectors(vsi);
		if (ret)
			goto err_rings;

		ret = nse_vsi_setup_vector_base(vsi, 0);
		if (ret)
			goto err_vectors;

		ret = nse_vsi_set_q_vectors_reg_idx(vsi, 0);
		if (ret)
			goto err_vectors;

		ret = nse_vsi_alloc_rings(vsi);
		if (ret)
			goto err_vectors;

		ret = nse_vsi_map_rings_to_vectors(vsi);
		if (ret)
			goto err_vectors;

		if (nse_is_xdp_ena_vsi(vsi)) {
			vsi->num_xdp_txq = vsi->alloc_rxq;
			ret = nse_prepare_xdp_rings(vsi, vsi->xdp_prog);
			if (ret)
				goto err_vectors;
		}

		nse_vsi_reset_stats(vsi);

		break;
	case NSE_VSI_VF:
		ret = nse_vsi_alloc_q_vectors(vsi);
		if (ret)
			goto err_rings;

		ret = nse_vsi_set_q_vectors_reg_idx(vsi, 0);
		if (ret)
			goto err_vectors;

		ret = nse_vsi_alloc_rings(vsi);
		if (ret)
			goto err_vectors;

		nse_vsi_reset_stats(vsi);
		break;

	default:
		break;
	}

	for (i = 0; i < vsi->tc_cfg.numtc; i++) {
		max_txqs[i] = vsi->alloc_txq;

		if (nse_is_xdp_ena_vsi(vsi))
			max_txqs[i] += vsi->num_xdp_txq;
	}

	status = nse_cfg_vsi_lan(vsi->port_info, vsi->idx,
					 vsi->tc_cfg.ena_tc, max_txqs);

	if (status) {
		dev_err(nse_pf_to_dev(pf), "VSI %d failed lan queue config, error %s\n",
			vsi->vsi_abs_num, nse_stat_str(status));
		if (init_vsi) {
			ret = -EIO;
			goto err_vectors;
		} else {
			return nse_schedule_reset(pf, NSE_RESET_PFR);
		}
	}

	nse_vsi_rebuild_set_coalesce(vsi, coalesce, prev_num_q_vectors);
	kfree(coalesce);

	return 0;

err_vectors:
	nse_vsi_free_q_vectors(vsi);
err_rings:
	nse_vsi_clear_rings(vsi);
err_vsi:
	if (init_vsi)
		nse_vsi_delete(vsi);

	nse_vsi_put_qs(vsi);

	nse_vsi_rss_deinit(vsi);

	set_bit(NSE_RESET_FAILED, pf->state);
	kfree(coalesce);
	return ret;
}

/**
 * nse_is_reset_in_progress - check for a reset in progress
 * @state: PF state field
 */
bool nse_is_reset_in_progress(unsigned long *state)
{
	return test_bit(NSE_RESET_OICR_RECV, state) ||
	       test_bit(NSE_PFR_REQ, state) ||
	       test_bit(NSE_HIGH_RESET_CORER_REQ, state);
}

bool nse_is_high_reset_in_progress(unsigned long *state)
{
	return test_bit(NSE_RESET_OICR_RECV, state) ||
	       test_bit(NSE_HIGH_RESET_CORER_REQ, state);
}

/**
 * nse_wait_for_reset - Wait for driver to finish reset and rebuild
 * @pf: pointer to the PF structure
 * @timeout: length of time to wait, in jiffies
 *
 * Wait (sleep) for a short time until the driver finishes cleaning up from
 * a device reset. The caller must be able to sleep. Use this to delay
 * operations that could fail while the driver is cleaning up after a device
 * reset.
 *
 * Returns 0 on success, -EBUSY if the reset is not finished within the
 * timeout, and -ERESTARTSYS if the thread was interrupted.
 */
int nse_wait_for_reset(struct nse_pf *pf, unsigned long timeout)
{
	struct nse_hw *hw = &pf->hw;
	long ret;

	nse_debug(hw, NSE_DBG_SYS, "[%s] timeout = %ld\n", __func__, timeout);

#ifdef __CHECKER__
	/* Suppress sparse warning from kernel macro:
	 * warning: symbol '__ret' shadows an earlier one
	 */
	ret = timeout;
#else
	ret = wait_event_interruptible_timeout(pf->reset_wait_queue,
					       !nse_is_reset_in_progress(pf->state),
					       timeout);
#endif

	nse_debug(hw, NSE_DBG_SYS, "[%s] ret = %ld\n", __func__, ret);

	if (ret < 0)
		return ret;
	else if (!ret)
		return -EBUSY;
	else
		return 0;
}

/**
 * nse_vsi_cfg_netdev_tc - Setup the netdev TC configuration
 * @vsi: the VSI being configured
 * @ena_tc: TC map to be enabled
 */
void nse_vsi_cfg_netdev_tc(struct nse_vsi *vsi, u8 ena_tc)
{
	struct net_device *netdev = vsi->netdev;
	struct nse_pf *pf = vsi->back;
	int numtc = vsi->tc_cfg.numtc;
	struct nse_dcbx_cfg *dcbcfg;
	u8 netdev_tc;
	int i;

	if (!netdev)
		return;

	if (!ena_tc) {
		netdev_reset_tc(netdev);
		return;
	}

	if (netdev_set_num_tc(netdev, numtc))
		return;

	dcbcfg = &pf->hw.port_info->qos_cfg.local_dcbx_cfg;

	nse_for_each_traffic_class(i)
		if (vsi->tc_cfg.ena_tc & BIT(i))
			netdev_set_tc_queue(netdev,
					    vsi->tc_cfg.tc_info[i].netdev_tc,
					    vsi->tc_cfg.tc_info[i].qcount_tx,
					    vsi->tc_cfg.tc_info[i].qoffset);

	for (i = 0; i < NSE_MAX_USER_PRIORITY; i++) {
		u8 ets_tc = dcbcfg->etscfg.prio_table[i];

		/* Get the mapped netdev TC# for the UP */
		netdev_tc = vsi->tc_cfg.tc_info[ets_tc].netdev_tc;
		netdev_set_prio_tc_map(netdev, i, netdev_tc);
	}
}

/**
 * nse_vsi_cfg_tc - Configure VSI Tx Sched for given TC map
 * @vsi: VSI to be configured
 * @ena_tc: TC bitmap
 *
 * VSI queues expected to be quiesced before calling this function
 */
int nse_vsi_cfg_tc(struct nse_vsi *vsi, u8 ena_tc)
{
	u16 max_txqs[NSE_MAX_TRAFFIC_CLASS] = { 0 };
	struct nse_pf *pf = vsi->back;
	enum nse_status status;
	struct device *dev;
	int i, ret = 0;
	u8 num_tc = 0;

	dev = nse_pf_to_dev(pf);

	if (vsi->tc_cfg.ena_tc == ena_tc)
		return 0;

	nse_for_each_traffic_class(i) {
		/* build bitmap of enabled TCs */
		if (ena_tc & BIT(i))
			num_tc++;
		/* populate max_txqs per TC */
		max_txqs[i] = vsi->alloc_txq;
	}

	vsi->tc_cfg.ena_tc = ena_tc;
	vsi->tc_cfg.numtc = num_tc;

	ret = nse_vsi_setup_q_map(vsi);
	if (ret)
		goto out;

	/* reinit RSS LUT because nse_vsi_setup_q_map() may change num_rxq */
	if (vsi->rss_lut_user) {
		devm_kfree(dev, vsi->rss_lut_user);
		vsi->rss_lut_user = NULL;
	}

	ret = nse_vsi_set_dflt_rss_lut(vsi, vsi->num_rxq);
	if (ret) {
		dev_err(dev, "FAIL: re-init RSS LUT for VSI %d, ret=%d\n",
					vsi->vsi_abs_num, ret);
		goto out;
	}

	status = nse_cfg_vsi_lan(vsi->port_info, vsi->idx,
					 vsi->tc_cfg.ena_tc, max_txqs);

	if (status) {
		dev_err(dev, "VSI %d failed TC config, error %s\n",
			vsi->vsi_abs_num, nse_stat_str(status));
		ret = -EIO;
		goto out;
	}

	nse_vsi_cfg_netdev_tc(vsi, ena_tc);

out:
	return ret;
}

/**
 * nse_update_ring_stats - Update ring statistics
 * @ring: ring to update
 * @pkts: number of processed packets
 * @bytes: number of processed bytes
 *
 * This function assumes that caller has acquired a u64_stats_sync lock.
 */
static void nse_update_ring_stats(struct nse_ring *ring, u64 pkts, u64 bytes)
{
	ring->stats.bytes += bytes;
	ring->stats.pkts += pkts;
}

/**
 * nse_update_tx_ring_stats - Update Tx ring specific counters
 * @tx_ring: ring to update
 * @pkts: number of processed packets
 * @bytes: number of processed bytes
 */
void nse_update_tx_ring_stats(struct nse_ring *tx_ring, u64 pkts, u64 bytes)
{
	u64_stats_update_begin(&tx_ring->syncp);
	nse_update_ring_stats(tx_ring, pkts, bytes);
	u64_stats_update_end(&tx_ring->syncp);
}

void nse_update_txcq_ring_stats(struct nse_txcq_ring *ring, u64 pkts, u64 bytes, u64 txqe_cnt)
{
	u64_stats_update_begin(&ring->syncp);
	ring->stats.pkts += pkts;
	ring->stats.bytes += bytes;
	ring->stats.cqe_cnt++;
	ring->stats.txqe_cnt += txqe_cnt;
	u64_stats_update_end(&ring->syncp);
}

/**
 * nse_update_rx_ring_stats - Update Rx ring specific counters
 * @rx_ring: ring to update
 * @pkts: number of processed packets
 * @bytes: number of processed bytes
 */
void nse_update_rx_ring_stats(struct nse_ring *rx_ring, u64 pkts, u64 bytes)
{
	u64_stats_update_begin(&rx_ring->syncp);
	nse_update_ring_stats(rx_ring, pkts, bytes);
	u64_stats_update_end(&rx_ring->syncp);
}

/**
 * nse_is_vsi_dflt_vsi - check if the VSI passed in is the default VSI
 * @vsi: VSI to compare against default forwarding VSI
 *
 * If this VSI passed in is the default forwarding VSI then return true, else
 * return false
 */
static bool nse_is_vsi_dflt_vsi_flex(struct nse_vsi *vsi)
{
	return vsi->info.rpp_per_vsi_ctxt &
		cpu_to_le32(NSE_AQ_VSI_SW_FLAG_RPP_DFLT_VSI);
}

static bool nse_is_vsi_dflt_vsi_legacy(struct nse_vsi *vsi)
{
	return vsi->info.rpp_per_vsi_ctxt &
		cpu_to_le32(NSE_AQ_VSI_L2_CTRL_FLAG_RSW_RX_DEF);
}

bool nse_is_vsi_dflt_vsi(struct nse_vsi *vsi)
{
	struct nse_hw *hw = &vsi->back->hw;
	bool ret = false;

	if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_FLEX))
		ret = nse_is_vsi_dflt_vsi_flex(vsi);
	else if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_LEGACY))
		ret = nse_is_vsi_dflt_vsi_legacy(vsi);

	return ret;
}

/**
 * nse_set_dflt_vsi - set the default forwarding VSI
 * @vsi: VSI getting set as the default forwarding VSI on the switch
 *
 * If the VSI passed in is already the default VSI, just return success.
 *
 * Otherwise try to set the VSI passed in as the switch's default VSI and
 * return the result.
 */
static int nse_set_dflt_vsi_flex(struct nse_vsi *vsi)
{
	struct device *dev;
	int err;

	if (!vsi)
		return NSE_ERR_BAD_PTR;

	dev = nse_pf_to_dev(vsi->back);

	/* the VSI passed in is already the default VSI */
	if (nse_is_vsi_dflt_vsi(vsi)) {
		dev_dbg(dev, "VSI %d passed in is already the default VSI, nothing to do\n",
			vsi->vsi_abs_num);
		return 0;
	}

	err = nse_vsi_update_switch(vsi, nse_vsi_ctx_set_rx_dflt_vsi);
	if (err) {
		dev_err(dev, "Failed to set VSI %d as the default VSI, error %d\n",
			vsi->vsi_abs_num, err);
		return err;
	}

	return 0;
}

static int nse_set_dflt_vsi_legacy(struct nse_vsi *vsi)
{
	struct device *dev;
	int err;

	if (!vsi)
		return NSE_ERR_BAD_PTR;

	dev = nse_pf_to_dev(vsi->back);

	/* the VSI passed in is already the default VSI */
	if (nse_is_vsi_dflt_vsi(vsi)) {
		dev_dbg(dev, "VSI %d passed in is already the default VSI, nothing to do\n",
			vsi->vsi_abs_num);
		return 0;
	}

	err = nse_vsi_update_switch(vsi, nse_vsi_l2_ctrl_set_rx_def);
	if (err) {
		dev_err(dev, "Failed to set VSI %d as the default VSI, error %d\n",
			vsi->vsi_abs_num, err);
		return err;
	}

	return 0;
}

int nse_set_dflt_vsi(struct nse_vsi *vsi)
{
	struct nse_hw *hw = &vsi->back->hw;
	int	err = 0;

	nse_debug(hw, NSE_DBG_SW, "[%s] vsi->idx=%d\n", __func__, vsi->idx);

	if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_FLEX))
		err = nse_set_dflt_vsi_flex(vsi);
	else if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_LEGACY))
		err = nse_set_dflt_vsi_legacy(vsi);

	return err;
}

/**
 * nse_clear_dflt_vsi - clear the default forwarding VSI
 * @vsi: VSI to remove from filter list
 *
 * If the VSI passed in is not the default VSI, just return success.
 *
 * Otherwise try to clear the default VSI and return the result.
 */
static int nse_clear_dflt_vsi_flex(struct nse_vsi *vsi)
{
	struct device *dev;
	int err;

	if (!vsi)
		return NSE_ERR_BAD_PTR;

	dev = nse_pf_to_dev(vsi->back);

	/* the VSI passed in is not a default VSI */
	if (!nse_is_vsi_dflt_vsi(vsi)) {
		dev_dbg(dev, "VSI %d passed in is not the default VSI, nothing to do\n",
			vsi->vsi_abs_num);
		return 0;
	}

	err = nse_vsi_update_switch(vsi, nse_vsi_ctx_clear_rx_dflt_vsi);
	if (err) {
		dev_err(dev, "Failed to clear VSI %d as the default VSI, error %d\n",
			vsi->vsi_abs_num, err);
		return err;
	}

	return 0;
}

static int nse_clear_dflt_vsi_legacy(struct nse_vsi *vsi)
{
	struct device *dev;
	int err;

	if (!vsi)
		return NSE_ERR_BAD_PTR;

	dev = nse_pf_to_dev(vsi->back);

	/* the VSI passed in is not a default VSI */
	if (!nse_is_vsi_dflt_vsi(vsi)) {
		dev_dbg(dev, "VSI %d passed in is not the default VSI, nothing to do\n",
			vsi->vsi_abs_num);
		return 0;
	}

	err = nse_vsi_update_switch(vsi, nse_vsi_l2_ctrl_clear_rx_def);
	if (err) {
		dev_err(dev, "Failed to clear VSI %d as the default VSI, error %d\n",
			vsi->vsi_abs_num, err);
		return err;
	}

	return 0;
}

int nse_clear_dflt_vsi(struct nse_vsi *vsi)
{
	struct nse_hw *hw = &vsi->back->hw;
	int err = 0;

	nse_debug(hw, NSE_DBG_SW, "[%s] vsi->idx=%d\n", __func__, vsi->idx);

	if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_FLEX))
		err = nse_clear_dflt_vsi_flex(vsi);
	else if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_LEGACY))
		err = nse_clear_dflt_vsi_legacy(vsi);

	return err;
}

/**
 * nse_status_to_errno - convert from enum nse_status to Linux errno
 * @err: nse_status value to convert
 */
int nse_status_to_errno(enum nse_status err)
{
	switch (err) {
	case NSE_SUCCESS:
		return 0;
	case NSE_ERR_DOES_NOT_EXIST:
		return -ENOENT;
	case NSE_ERR_OUT_OF_RANGE:
		return -ENOTTY;
	case NSE_ERR_PARAM:
		return -EINVAL;
	case NSE_ERR_NO_MEMORY:
		return -ENOMEM;
	case NSE_ERR_MAX_LIMIT:
		return -EAGAIN;
	default:
		return -EINVAL;
	}
}

enum nse_status nse_aq_err_to_status(enum nse_aq_err aq_err)
{
	switch (aq_err) {
	case NSE_AQ_RC_OK:
		return NSE_SUCCESS;
	case NSE_AQ_RC_EIO:
		return NSE_ERR_CFG;
	case NSE_AQ_RC_EINVAL:
		return NSE_ERR_PARAM;
	case NSE_AQ_RC_ERANGE:
		return NSE_ERR_OUT_OF_RANGE;
	case NSE_AQ_RC_EPERM:
		return NSE_ERR_EPERM;
	case NSE_AQ_RC_EFAULT:
		return NSE_ERR_BAD_PTR;
	case NSE_AQ_RC_ENOENT:
		return NSE_ERR_DOES_NOT_EXIST;
	case NSE_AQ_RC_EEXIST:
		return NSE_ERR_ALREADY_EXISTS;
	case NSE_AQ_RC_EAGAIN:
		return NSE_ERR_AGAIN;
	case NSE_AQ_RC_EBUSY:
		return NSE_ERR_BUSY;
	case NSE_AQ_RC_EINPROGRESS:
		return NSE_ERR_IN_PROGRESS;
	case NSE_AQ_RC_ENOMEM:
		return NSE_ERR_NO_MEMORY;
	case NSE_AQ_RC_ENOSPC:
		return NSE_ERR_MAX_LIMIT;
	case NSE_AQ_RC_ENOTSUPP:
		return NSE_ERR_NOT_SUPPORTED;

	case NSE_AQ_RC_EACCES_FW_IN_UPDATE:
		return NSE_ERR_FW_IN_UPDATE;

	default:
		return NSE_ERR_CFG;
	}
}

/**
 * nse_set_min_bw_limit - setup minimum BW limit for Tx based on min_tx_rate
 * @vsi: VSI to be configured
 * @min_tx_rate: min Tx rate in Kbps to be configured as BW limit
 *
 * If the min_tx_rate is specified as 0 that means to clear the minimum BW limit
 * profile, otherwise a non-zero value will force a minimum BW limit for the VSI
 * on TC 0.
 */
int nse_set_min_bw_limit(struct nse_vsi *vsi, u32 min_tx_rate)
{
	struct nse_pf *pf = vsi->back;
	enum nse_status status;
	struct device *dev = nse_pf_to_dev(pf);
	u32 speed;

	if (!vsi->port_info) {
		dev_err(dev, "VSI %d, type %u specified doesn't have valid port_info\n",
			vsi->idx, vsi->type);
		return -EINVAL;
	}

	speed = nse_get_link_speed_kbps(&pf->hw);
	if (min_tx_rate > speed) {
		dev_err(dev, "invalid min Tx rate %u Kbps specified for %s %d is greater than current link speed %u Kbps\n",
			min_tx_rate, nse_vsi_type_str(vsi->type), vsi->idx,
			speed);
		return -EINVAL;
	}

	status = nse_sched_set_vsi_cir_per_tc(vsi->port_info, vsi->idx, 0, min_tx_rate);
	if (status) {
		dev_err(dev, "failed to set min Tx rate(%u Kbps) for %s %d\n",
				min_tx_rate, nse_vsi_type_str(vsi->type),
				vsi->idx);
		return -EIO;
	}

	return 0;
}

/**
 * nse_set_max_bw_limit - setup maximum BW limit for Tx based on max_tx_rate
 * @vsi: VSI to be configured
 * @max_tx_rate: max Tx rate in Kbps to be configured as BW limit
 *
 * If the max_tx_rate is specified as 0 that means to clear the maximum BW limit
 * profile, otherwise a non-zero value will force a maximum BW limit for the VSI
 * on TC 0.
 */
int nse_set_max_bw_limit(struct nse_vsi *vsi, u32 max_tx_rate)
{
	struct nse_pf *pf = vsi->back;
	enum nse_status status;
	struct device *dev = nse_pf_to_dev(pf);
	u32 speed;

	if (!vsi->port_info) {
		dev_err(dev, "VSI %d, type %u specified doesn't have valid port_info\n",
			vsi->idx, vsi->type);
		return -EINVAL;
	}

	speed = nse_get_link_speed_kbps(&pf->hw);
	if (max_tx_rate > speed) {
		dev_err(dev, "invalid max Tx rate %u Kbps specified for %s %d is greater than current link speed %u Kbps\n",
			max_tx_rate, nse_vsi_type_str(vsi->type), vsi->idx,
			speed);
		return -EINVAL;
	}

	status = nse_sched_set_vsi_pir_per_tc(vsi->port_info, vsi->idx, 0, max_tx_rate);
	if (status) {
		dev_err(dev, "failed to set max Tx rate(%u Kbps) for %s %d\n",
				max_tx_rate, nse_vsi_type_str(vsi->type),
				vsi->idx);
		return -EIO;
	}

	return 0;
}

/**
 * nse_set_link - turn on/off physical link
 * @vsi: VSI to modify physical link on
 * @ena: turn on/off physical link
 */
int nse_set_link(struct nse_vsi *vsi, bool ena)
{
	return 0;
}

/**
 * nse_vsi_update_switch - update switch block in VSI context
 * @vsi: pointer to VSI structure
 * @fill: function pointer to fill ctx
 */
int nse_vsi_update_switch(struct nse_vsi *vsi,
			    void (*fill)(struct nse_vsi_ctx *))
{
	struct nse_vsi_ctx ctx = { 0 };

	if (nse_bypass_switch)
		return 0;

	ctx.vsi_abs_num = vsi->vsi_abs_num;

	ctx.info = vsi->info;
	ctx.info.valid_sections = cpu_to_le16(NSE_AQ_VSI_PROP_SECTION_SW_VALID);
	fill(&ctx);

	if (nse_update_vsi(&vsi->back->hw, vsi->idx, &ctx, NULL))
		return -ENODEV;

	vsi->info.rpp_per_vsi_ctxt = ctx.info.rpp_per_vsi_ctxt;
	vsi->info.tpp_per_vsi_ctxt = ctx.info.tpp_per_vsi_ctxt;
	return 0;
}

/**
 * nse_vsi_ctx_set_antispoof - set antispoof function in VSI ctx
 * @ctx: pointer to VSI ctx structure
 */
void nse_vsi_ctx_set_antispoof(struct nse_vsi_ctx *ctx)
{
	ctx->info.tpp_per_vsi_ctxt |= cpu_to_le32(NSE_AQ_VSI_SW_FLAG_TPP_MAC_ANTI_SPOOF |
			NSE_AQ_VSI_SW_FLAG_TPP_VLAN_ANTI_SPOOF);
}

/**
 * nse_vsi_ctx_clear_antispoof - clear antispoof function in VSI ctx
 * @ctx: pointer to VSI ctx structure
 */
void nse_vsi_ctx_clear_antispoof(struct nse_vsi_ctx *ctx)
{
	ctx->info.tpp_per_vsi_ctxt &= cpu_to_le32(~NSE_AQ_VSI_SW_FLAG_TPP_MAC_ANTI_SPOOF &
		~NSE_AQ_VSI_SW_FLAG_TPP_VLAN_ANTI_SPOOF);
}

/**
 * nse_vsi_ctx_set_mac_antispoof - set mac antispoof function in VSI ctx
 * @ctx: pointer to VSI ctx structure
 */
void nse_vsi_ctx_set_mac_antispoof(struct nse_vsi_ctx *ctx)
{
	ctx->info.tpp_per_vsi_ctxt |= cpu_to_le32(NSE_AQ_VSI_SW_FLAG_TPP_MAC_ANTI_SPOOF);
}

/**
 * nse_vsi_ctx_clear_mac_antispoof - clear mac antispoof function in VSI ctx
 * @ctx: pointer to VSI ctx structure
 */
void nse_vsi_ctx_clear_mac_antispoof(struct nse_vsi_ctx *ctx)
{
	ctx->info.tpp_per_vsi_ctxt &= cpu_to_le32(~NSE_AQ_VSI_SW_FLAG_TPP_MAC_ANTI_SPOOF);
}

/**
 * nse_vsi_ctx_set_vlan_antispoof - set vlan antispoof function in VSI ctx
 * @ctx: pointer to VSI ctx structure
 */
void nse_vsi_ctx_set_vlan_antispoof(struct nse_vsi_ctx *ctx)
{
	ctx->info.tpp_per_vsi_ctxt |= cpu_to_le32(NSE_AQ_VSI_SW_FLAG_TPP_VLAN_ANTI_SPOOF);
}

/**
 * nse_vsi_ctx_clear_vlan_antispoof - clear vlan antispoof function in VSI ctx
 * @ctx: pointer to VSI ctx structure
 */
void nse_vsi_ctx_clear_vlan_antispoof(struct nse_vsi_ctx *ctx)
{
	ctx->info.tpp_per_vsi_ctxt &= cpu_to_le32(~NSE_AQ_VSI_SW_FLAG_TPP_VLAN_ANTI_SPOOF);
}

/**
 * nse_vsi_ctx_set_vlan_rx_filter - set vlan rx filter function in VSI ctx
 * @ctx: pointer to VSI ctx structure
 */
void nse_vsi_ctx_set_vlan_rx_filter(struct nse_vsi_ctx *ctx)
{
	ctx->info.rpp_per_vsi_ctxt |= cpu_to_le32(NSE_AQ_VSI_SW_FLAG_RPP_RX_PRUNE);
	ctx->info.tpp_per_vsi_ctxt |= cpu_to_le32(NSE_AQ_VSI_SW_FLAG_TPP_RX_PRUNE);
}

/**
 * nse_vsi_ctx_clear_vlan_rx_filter - clear vlan rx filter function in VSI ctx
 * @ctx: pointer to VSI ctx structure
 */
void nse_vsi_ctx_clear_vlan_rx_filter(struct nse_vsi_ctx *ctx)
{
	ctx->info.rpp_per_vsi_ctxt &= cpu_to_le32(~NSE_AQ_VSI_SW_FLAG_RPP_RX_PRUNE);
	ctx->info.tpp_per_vsi_ctxt &= cpu_to_le32(~NSE_AQ_VSI_SW_FLAG_TPP_RX_PRUNE);
}

/**
 * nse_vsi_ctx_set_tx_ovs_miss - set tpp ovs miss on VSI
 * @ctx: pointer to VSI ctx structure
 */
void nse_vsi_ctx_set_tx_ovs_miss(struct nse_vsi_ctx *ctx)
{
	ctx->info.tpp_per_vsi_ctxt |= cpu_to_le32(NSE_AQ_VSI_SW_FLAG_TPP_OVS_MISS);
}

/**
 * nse_vsi_ctx_clear_tx_ovs_miss - turn off tpp ovs miss on VSI
 * @ctx: pointer to VSI ctx structure
 */
void nse_vsi_ctx_clear_tx_ovs_miss(struct nse_vsi_ctx *ctx)
{
	ctx->info.tpp_per_vsi_ctxt &= cpu_to_le32(~NSE_AQ_VSI_SW_FLAG_TPP_OVS_MISS);
}

/**
 * nse_vsi_ctx_set_rx_ovs_miss - set rpp ovs miss on VSI
 * @ctx: pointer to VSI ctx structure
 */
void nse_vsi_ctx_set_rx_ovs_miss(struct nse_vsi_ctx *ctx)
{
	ctx->info.rpp_per_vsi_ctxt |= cpu_to_le32(NSE_AQ_VSI_SW_FLAG_RPP_OVS_MISS);
}

/**
 * nse_vsi_ctx_clear_rx_ovs_miss - turn off rpp ovs miss on VSI
 * @ctx: pointer to VSI ctx structure
 */
void nse_vsi_ctx_clear_rx_ovs_miss(struct nse_vsi_ctx *ctx)
{
	ctx->info.rpp_per_vsi_ctxt &= cpu_to_le32(~NSE_AQ_VSI_SW_FLAG_RPP_OVS_MISS);
}

/**
 * nse_vsi_ctx_set_rx_dflt_vsi - set rpp default vsi on VSI
 * @ctx: pointer to VSI ctx structure
 */
void nse_vsi_ctx_set_rx_dflt_vsi(struct nse_vsi_ctx *ctx)
{
	ctx->info.rpp_per_vsi_ctxt |= cpu_to_le32(NSE_AQ_VSI_SW_FLAG_RPP_DFLT_VSI);
}

/**
 * nse_vsi_ctx_clear_rx_dflt_vsi - turn off rpp default vsi on VSI
 * @ctx: pointer to VSI ctx structure
 */
void nse_vsi_ctx_clear_rx_dflt_vsi(struct nse_vsi_ctx *ctx)
{
	ctx->info.rpp_per_vsi_ctxt &= cpu_to_le32(~NSE_AQ_VSI_SW_FLAG_RPP_DFLT_VSI);
}

/**
 * nse_vsi_ctx_set_src_prune_rx - set rpp src_prune on VSI
 * @ctx: pointer to VSI ctx structure
 */
void nse_vsi_ctx_set_src_prune_rx(struct nse_vsi_ctx *ctx)
{
	ctx->info.rpp_per_vsi_ctxt |= cpu_to_le32(NSE_AQ_VSI_SW_FLAG_RPP_SRC_PRUNE);
}

/**
 * nse_vsi_ctx_clear_src_prune_rx - turn off rpp src_prune on VSI
 * @ctx: pointer to VSI ctx structure
 */
void nse_vsi_ctx_clear_src_prune_rx(struct nse_vsi_ctx *ctx)
{
	ctx->info.rpp_per_vsi_ctxt &= cpu_to_le32(~NSE_AQ_VSI_SW_FLAG_RPP_SRC_PRUNE);
}

/**
 * nse_vsi_ctx_set_src_prune_tx - set tpp src_prune on VSI
 * @ctx: pointer to VSI ctx structure
 */
void nse_vsi_ctx_set_src_prune_tx(struct nse_vsi_ctx *ctx)
{
	ctx->info.tpp_per_vsi_ctxt |= cpu_to_le32(NSE_AQ_VSI_SW_FLAG_TPP_SRC_PRUNE);
}

/**
 * nse_vsi_ctx_clear_src_prune_tx - turn off tpp src_prune on VSI
 * @ctx: pointer to VSI ctx structure
 */
void nse_vsi_ctx_clear_src_prune_tx(struct nse_vsi_ctx *ctx)
{
	ctx->info.tpp_per_vsi_ctxt &= cpu_to_le32(~NSE_AQ_VSI_SW_FLAG_TPP_SRC_PRUNE);
}

/**
 * nse_vsi_ctx_set_allow_override - allow destination override on VSI
 * @ctx: pointer to VSI ctx structure
 */
void nse_vsi_ctx_set_allow_override(struct nse_vsi_ctx *ctx)
{
	ctx->info.tpp_per_vsi_ctxt |= cpu_to_le32(NSE_AQ_VSI_SW_FLAG_TPP_ALLOW_DEST_OVRD);
}

/**
 * nse_vsi_ctx_clear_allow_override - turn off destination override on VSI
 * @ctx: pointer to VSI ctx structure
 */
void nse_vsi_ctx_clear_allow_override(struct nse_vsi_ctx *ctx)
{
	ctx->info.tpp_per_vsi_ctxt &= cpu_to_le32(~NSE_AQ_VSI_SW_FLAG_TPP_ALLOW_DEST_OVRD);
}

/**
 * nse_vsi_l2_ctrl_set_rx_upe - turn on UPE in hardware legacy switcher mode
 * @ctx: pointer to VSI ctx structure
 */
void nse_vsi_l2_ctrl_set_rx_upe(struct nse_vsi_ctx *ctx)
{
	ctx->info.rsw_per_vsi_l2ctxt |= cpu_to_le32(NSE_AQ_VSI_L2_CTRL_FLAG_RSW_UPE);
}

/**
 * nse_vsi_l2_ctrl_clear_rx_upe - turn off UPE in hardware legacy switcher mode
 * @ctx: pointer to VSI ctx structure
 */
void nse_vsi_l2_ctrl_clear_rx_upe(struct nse_vsi_ctx *ctx)
{
	ctx->info.rsw_per_vsi_l2ctxt &= cpu_to_le32(~NSE_AQ_VSI_L2_CTRL_FLAG_RSW_UPE);
}

/**
 * nse_vsi_l2_ctrl_set_rx_mpe - turn on MPE in hardware legacy switcher mode
 * @ctx: pointer to VSI ctx structure
 */
void nse_vsi_l2_ctrl_set_rx_mpe(struct nse_vsi_ctx *ctx)
{
	ctx->info.rsw_per_vsi_l2ctxt |= cpu_to_le32(NSE_AQ_VSI_L2_CTRL_FLAG_RSW_MPE);
}

/**
 * nse_vsi_l2_ctrl_clear_rx_upe - turn off MPE in hardware legacy switcher mode
 * @ctx: pointer to VSI ctx structure
 */
void nse_vsi_l2_ctrl_clear_rx_mpe(struct nse_vsi_ctx *ctx)
{
	ctx->info.rsw_per_vsi_l2ctxt &= cpu_to_le32(~NSE_AQ_VSI_L2_CTRL_FLAG_RSW_MPE);
}

/**
 * nse_vsi_l2_ctrl_set_rx_bam - turn on BAM in hardware legacy switcher mode
 * @ctx: pointer to VSI ctx structure
 */
void nse_vsi_l2_ctrl_set_rx_bam(struct nse_vsi_ctx *ctx)
{
	ctx->info.rsw_per_vsi_l2ctxt |= cpu_to_le32(NSE_AQ_VSI_L2_CTRL_FLAG_RSW_BAM);
}

/**
 * nse_vsi_l2_ctrl_clear_rx_bam - turn off BAM in hardware legacy switcher mode
 * @ctx: pointer to VSI ctx structure
 */
void nse_vsi_l2_ctrl_clear_rx_bam(struct nse_vsi_ctx *ctx)
{
	ctx->info.rsw_per_vsi_l2ctxt &= cpu_to_le32(~NSE_AQ_VSI_L2_CTRL_FLAG_RSW_BAM);
}

/**
 * nse_vsi_l2_ctrl_set_rx_vpe - turn on VPE in hardware legacy switcher mode
 * @ctx: pointer to VSI ctx structure
 */
void nse_vsi_l2_ctrl_set_rx_vpe(struct nse_vsi_ctx *ctx)
{
	ctx->info.rsw_per_vsi_l2ctxt |= cpu_to_le32(NSE_AQ_VSI_L2_CTRL_FLAG_RSW_VPE);
}

/**
 * nse_vsi_l2_ctrl_clear_rx_vpe - turn off VPE in hardware legacy switcher mode
 * @ctx: pointer to VSI ctx structure
 */
void nse_vsi_l2_ctrl_clear_rx_vpe(struct nse_vsi_ctx *ctx)
{
	ctx->info.rsw_per_vsi_l2ctxt &= cpu_to_le32(~NSE_AQ_VSI_L2_CTRL_FLAG_RSW_VPE);
}

/**
 * nse_vsi_l2_ctrl_set_rx_vaccept - turn on VACCEPT in hardware legacy switcher mode
 * @ctx: pointer to VSI ctx structure
 */
void nse_vsi_l2_ctrl_set_rx_vaccept(struct nse_vsi_ctx *ctx)
{
	ctx->info.rsw_per_vsi_l2ctxt |= cpu_to_le32(NSE_AQ_VSI_L2_CTRL_FLAG_RSW_VACCEPT);
}

/**
 * nse_vsi_l2_ctrl_clear_rx_vaccept - turn off VACCEPT in hardware legacy switcher mode
 * @ctx: pointer to VSI ctx structure
 */
void nse_vsi_l2_ctrl_clear_rx_vaccept(struct nse_vsi_ctx *ctx)
{
	ctx->info.rsw_per_vsi_l2ctxt &= cpu_to_le32(~NSE_AQ_VSI_L2_CTRL_FLAG_RSW_VACCEPT);
}

/**
 * nse_vsi_l2_ctrl_set_rx_aupe - turn on AUPE in hardware legacy switcher mode
 * @ctx: pointer to VSI ctx structure
 */
void nse_vsi_l2_ctrl_set_rx_aupe(struct nse_vsi_ctx *ctx)
{
	ctx->info.rsw_per_vsi_l2ctxt |= cpu_to_le32(NSE_AQ_VSI_L2_CTRL_FLAG_RSW_AUPE);
}

/**
 * nse_vsi_l2_ctrl_clear_rx_aupe - turn off AUPE in hardware legacy switcher mode
 * @ctx: pointer to VSI ctx structure
 */
void nse_vsi_l2_ctrl_clear_rx_aupe(struct nse_vsi_ctx *ctx)
{
	ctx->info.rsw_per_vsi_l2ctxt &= cpu_to_le32(~NSE_AQ_VSI_L2_CTRL_FLAG_RSW_AUPE);
}

/**
 * nse_vsi_l2_ctrl_set_rx_def - turn on default vsi in hardware legacy switcher mode
 * @ctx: pointer to VSI ctx structure
 */
void nse_vsi_l2_ctrl_set_rx_def(struct nse_vsi_ctx *ctx)
{
	ctx->info.rsw_per_vsi_l2ctxt |= cpu_to_le32(NSE_AQ_VSI_L2_CTRL_FLAG_RSW_RX_DEF);
}

/**
 * nse_vsi_l2_ctrl_clear_rx_def - turn off default vsi  in hardware legacy switcher mode
 * @ctx: pointer to VSI ctx structure
 */
void nse_vsi_l2_ctrl_clear_rx_def(struct nse_vsi_ctx *ctx)
{
	ctx->info.rsw_per_vsi_l2ctxt &= cpu_to_le32(~NSE_AQ_VSI_L2_CTRL_FLAG_RSW_RX_DEF);
}

/**
 * nse_vsi_add_vlan_zero - add VLAN 0 filter(s) for this VSI
 * @vsi: VSI used to add VLAN filters
 *
 * In Single VLAN Mode (SVM), single VLAN filters via NSE_SW_LKUP_VLAN are based
 * on the inner VLAN ID, so the VLAN TPID (i.e. 0x8100 or 0x888a8) doesn't
 * matter. In Double VLAN Mode (DVM), outer/single VLAN filters via
 * NSE_SW_LKUP_VLAN are based on the outer/single VLAN ID + VLAN TPID.
 *
 * For both modes add a VLAN 0 + no VLAN TPID filter to handle untagged traffic
 * when VLAN pruning is enabled. Also, this handles VLAN 0 priority tagged
 * traffic in SVM, since the VLAN TPID isn't part of filtering.
 *
 * If DVM is enabled then an explicit VLAN 0 + VLAN TPID filter needs to be
 * added to allow VLAN 0 priority tagged traffic in DVM, since the VLAN TPID is
 * part of filtering.
 */
static int nse_vsi_add_vlan_zero_flex(struct nse_vsi *vsi)
{
	struct nse_hw *hw = &vsi->back->hw;
	struct nse_vsi_vlan_ops *vlan_ops = nse_get_compat_vsi_vlan_ops(vsi);
	struct nse_vlan vlan;
	int err;

	vlan = NSE_VLAN(hw->stag_ethertype, 0, 0, NSE_FWD_TO_VSI);
	err = vlan_ops->add_vlan(vsi, &vlan);
	if (err && err != -EEXIST)
		return err;

	return 0;
}

static int nse_vsi_add_vlan_zero_legacy(struct nse_vsi *vsi)
{
	return nse_vsi_update_switch(vsi, nse_vsi_l2_ctrl_set_rx_aupe);
}

int nse_vsi_add_vlan_zero(struct nse_vsi *vsi)
{
	struct nse_hw *hw = &vsi->back->hw;
	int err = 0;

	if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_FLEX))
		err = nse_vsi_add_vlan_zero_flex(vsi);
	else if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_LEGACY))
		err = nse_vsi_add_vlan_zero_legacy(vsi);

	return err;
}

/**
 * nse_vsi_del_vlan_zero - delete VLAN 0 filter(s) for this VSI
 * @vsi: VSI used to add VLAN filters
 *
 * Delete the VLAN 0 filters in the same manner that they were added in
 * nse_vsi_add_vlan_zero.
 */
static int nse_vsi_del_vlan_zero_flex(struct nse_vsi *vsi)
{
	struct nse_hw *hw = &vsi->back->hw;
	struct nse_vsi_vlan_ops *vlan_ops = nse_get_compat_vsi_vlan_ops(vsi);
	struct nse_vlan vlan;
	int err;

	vlan = NSE_VLAN(hw->stag_ethertype, 0, 0, NSE_FWD_TO_VSI);
	err = vlan_ops->del_vlan(vsi, &vlan);
	if (err && err != -EEXIST)
		return err;

	/* when deleting the last VLAN filter, make sure to disable the VLAN
	 * promisc mode so the filter isn't left by accident
	 */
	err = nse_clear_vsi_promisc(&vsi->back->hw, vsi->idx,
				    NSE_MCAST_VLAN_PROMISC_BITS, 0);
	if (err)
		return err;

	return 0;
}

static int nse_vsi_del_vlan_zero_legacy(struct nse_vsi *vsi)
{
	int err;

	err = nse_vsi_update_switch(vsi, nse_vsi_l2_ctrl_clear_rx_aupe);
	if (err)
		return err;
	return 0;
}

int nse_vsi_del_vlan_zero(struct nse_vsi *vsi)
{
	struct nse_hw *hw = &vsi->back->hw;
	int err = 0;

	if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_FLEX))
		err = nse_vsi_del_vlan_zero_flex(vsi);
	else if (nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_SWITCH_LEGACY))
		err = nse_vsi_del_vlan_zero_legacy(vsi);

	return err;
}

/**
 * nse_vsi_num_zero_vlans - get number of VLAN 0 filters based on VLAN mode
 * @vsi: VSI used to get the VLAN mode
 *
 */
static u16 nse_vsi_num_zero_vlans(struct nse_vsi *vsi)
{
#define NSE_DVM_NUM_ZERO_VLAN_FLTRS	1
	/* no VLAN 0 filter is created when a port VLAN is active */
	if (vsi->type == NSE_VSI_VF) {
		if (WARN_ON(!vsi->vf))
			return 0;

		if (nse_vf_is_port_vlan_ena(vsi->vf))
			return 0;
	}

	return NSE_DVM_NUM_ZERO_VLAN_FLTRS;
}

/**
 * nse_vsi_has_non_zero_vlans - check if VSI has any non-zero VLANs
 * @vsi: VSI used to determine if any non-zero VLANs have been added
 */
bool nse_vsi_has_non_zero_vlans(struct nse_vsi *vsi)
{
	return (vsi->num_vlan > nse_vsi_num_zero_vlans(vsi));
}

/**
 * nse_vsi_num_non_zero_vlans - get the number of non-zero VLANs for this VSI
 * @vsi: VSI used to get the number of non-zero VLANs added
 */
u16 nse_vsi_num_non_zero_vlans(struct nse_vsi *vsi)
{
	return (vsi->num_vlan - nse_vsi_num_zero_vlans(vsi));
}

int nse_init_vsi_scheme(struct nse_pf *pf)
{
	int i;
	u32 vsi_abs_id;
	struct nse_hw *hw = &pf->hw;

	mutex_init(&pf->vsi_tracker_mutex);

	pf->nonvf_vsi_region_size = pf->vsi_space_size;

	pf->vsi_tracker = devm_kzalloc(nse_pf_to_dev(pf),
					struct_size(pf->vsi_tracker, list, pf->vsi_space_size),
					GFP_KERNEL);
	if (!pf->vsi_tracker)
		goto err;

	pf->vsi_tracker->num_entries = pf->vsi_space_size;
	pf->vsi_tracker->end = pf->vsi_space_size;

	pf->vsi = devm_kcalloc(nse_pf_to_dev(pf),
						pf->vsi_space_size, sizeof(*pf->vsi),
						GFP_KERNEL);
	if (!pf->vsi)
		goto err;

#if defined(NSE_DEBUG_EXT)
	for (i = 0; i < pf->vsi_space_size; i++) {
		vsi_abs_id = pf->vsi_space_start + i;

		vsi_abs_id &= NSE_REG_VMBX_ARQLEN_LEN_M;

		wr32(hw, NSE_REG_VMBX_ARQLEN(i), vsi_abs_id);
		wr32(hw, NSE_REG_VMBX_ATQLEN(i), vsi_abs_id);
	}
#endif

	return 0;

err:
	nse_clear_vsi_scheme(pf);

	return -ENOMEM;
}

void nse_clear_vsi_scheme(struct nse_pf *pf)
{
	struct device *dev = nse_pf_to_dev(pf);

	if (pf->vsi_tracker) {
		devm_kfree(dev, pf->vsi_tracker);
		pf->vsi_tracker = NULL;
	}

	if (pf->vsi) {
		devm_kfree(dev, pf->vsi);
		pf->vsi = NULL;
	}

	mutex_destroy(&pf->vsi_tracker_mutex);
}

int nse_init_lanq_scheme(struct nse_pf *pf)
{
	mutex_init(&pf->lan_rxq_tracker_mutex);
	mutex_init(&pf->lan_txq_tracker_mutex);
	mutex_init(&pf->lan_txcq_tracker_mutex);

	pf->lan_rxq_tracker = devm_kzalloc(nse_pf_to_dev(pf),
					   struct_size(pf->lan_rxq_tracker, list,
						       pf->lan_rxq_space_size),
									GFP_KERNEL);

	pf->lan_txq_tracker = devm_kzalloc(nse_pf_to_dev(pf),
					   struct_size(pf->lan_txq_tracker, list,
						       pf->lan_txq_space_size),
									GFP_KERNEL);

	if (!pf->lan_rxq_tracker || !pf->lan_txq_tracker)
		goto err;

	pf->lan_rxq_tracker->num_entries = pf->lan_rxq_space_size;
	pf->lan_rxq_tracker->end = pf->lan_rxq_space_size;

	pf->lan_txq_tracker->num_entries = pf->lan_txq_space_size;
	pf->lan_txq_tracker->end = pf->lan_txq_space_size;

	if (pf->lan_txcq_space_valid && pf->sw_conf.lan_tx_use_cq) {
		pf->lan_txcq_tracker = devm_kzalloc(nse_pf_to_dev(pf),
						    struct_size(pf->lan_txcq_tracker, list,
								pf->lan_txcq_space_size),
									GFP_KERNEL);
		if (!pf->lan_txcq_tracker)
			goto err;

		pf->lan_txcq_tracker->num_entries = pf->lan_txcq_space_size;
		pf->lan_txcq_tracker->end = pf->lan_txcq_space_size;
	}

	return 0;

err:
	nse_clear_lanq_scheme(pf);

	return -ENOMEM;
}

void nse_clear_lanq_scheme(struct nse_pf *pf)
{
	struct device *dev = nse_pf_to_dev(pf);

	if (pf->lan_rxq_tracker) {
		devm_kfree(dev, pf->lan_rxq_tracker);
		pf->lan_rxq_tracker = NULL;
	}

	if (pf->lan_txq_tracker) {
		devm_kfree(dev, pf->lan_txq_tracker);
		pf->lan_txq_tracker = NULL;
	}

	if (pf->lan_txcq_tracker) {
		devm_kfree(dev, pf->lan_txcq_tracker);
		pf->lan_txcq_tracker = NULL;
	}

	mutex_destroy(&pf->lan_rxq_tracker_mutex);
	mutex_destroy(&pf->lan_txq_tracker_mutex);
	mutex_destroy(&pf->lan_txcq_tracker_mutex);
}

int nse_init_rss_scheme(struct nse_pf *pf)
{
	mutex_init(&pf->rss_lut_tracker_mutex);

	pf->rss_lut_tracker = devm_kzalloc(nse_pf_to_dev(pf),
					   struct_size(pf->rss_lut_tracker, list, pf->rss_lut_size),
									GFP_KERNEL);
	if (!pf->rss_lut_tracker)
		goto err;

	pf->rss_lut_tracker->num_entries = pf->rss_lut_size;
	pf->rss_lut_tracker->end = pf->rss_lut_size;

	return 0;

err:
	nse_clear_rss_scheme(pf);

	return -ENOMEM;
}

void nse_clear_rss_scheme(struct nse_pf *pf)
{
	if (pf->rss_lut_tracker) {
		devm_kfree(nse_pf_to_dev(pf), pf->rss_lut_tracker);
		pf->rss_lut_tracker = NULL;
	}

	mutex_destroy(&pf->rss_lut_tracker_mutex);
}

int nse_vsi_cfg_rss_key(struct nse_vsi *vsi)
{
	struct nse_pf *pf = vsi->back;
	struct device *dev = nse_pf_to_dev(pf);
	u8 *key = NULL;
	int ret;

	key = kzalloc(NSE_RSS_KEY_SIZE, GFP_KERNEL);
	if (!key) {
		ret = -ENOMEM;
		goto out;
	}

	if (vsi->rss_hkey_user)
		memcpy(key, vsi->rss_hkey_user, NSE_RSS_KEY_SIZE);
	else
		netdev_rss_key_fill((void *)key, NSE_RSS_KEY_SIZE);

	ret = nse_set_rss_key(vsi, key);
	if (ret)
		nse_dev_err_errno(dev, ret, "cfg_rss_key failed");

out:
	kfree(key);

	return ret;
}

int nse_vsi_cfg_rss_lut(struct nse_vsi *vsi)
{
	struct nse_pf *pf = vsi->back;
	struct device *dev = nse_pf_to_dev(pf);
	u16 *lut = NULL;
	int ret;

	lut = kcalloc(vsi->rss_lut_size_aligned, sizeof(u16), GFP_KERNEL);
	if (!lut) {
		ret = -ENOMEM;
		goto out;
	}

	if (vsi->rss_lut_user)
		memcpy(lut, vsi->rss_lut_user, sizeof(u16) * vsi->rss_lut_size_aligned);
	else
		nse_fill_rss_lut(lut, vsi->rss_lut_size_aligned, vsi->num_rxq);

	ret = nse_set_rss_lut(vsi, lut, vsi->rss_lut_size_aligned);
	if (ret)
		nse_dev_err_errno(dev, ret, "cfg_rss_lut failed");

out:
	kfree(lut);

	return ret;
}

int nse_vsi_cfg_rss_ctl(struct nse_vsi *vsi)
{
	struct nse_pf *pf = vsi->back;
	struct nse_hw *hw = &pf->hw;
	struct device *dev = nse_pf_to_dev(pf);
	int ret;
	enum nse_status status;

	vsi->rss_ctl = 0;

	if (!vsi->rss_lut_size) {	/* not init yet */
		ret = -EIO;
		goto out;
	}

	/* construct rss_ctl */

	vsi->rss_ctl |= NSE_VSI_RSS_CTL_EN_M;

	vsi->rss_ctl |= ((vsi->rss_lut_size_log2 <<
			 NSE_VSI_RSS_CTL_RSSBIT_S) & NSE_VSI_RSS_CTL_RSSBIT_M);

	vsi->rss_ctl |= (((vsi->rss_lut_start + pf->rss_lut_start)<<
			 NSE_VSI_RSS_CTL_FIRST_LUT_S) & NSE_VSI_RSS_CTL_FIRST_LUT_M);

	status = nse_aq_rss_set_ctl(vsi, (vsi->rss_ctl | vsi->rss_ctl_user_req_alg));
	if (status) {
		dev_err(nse_pf_to_dev(pf), "Cannot set RSS CTL, err %s aq_err %s\n",
			nse_stat_str(status),
			nse_aq_str(hw->adminq.sq_last_status));
		ret = -EIO;
		goto out;
	}

	vsi->rss_ctl |= vsi->rss_ctl_user_req_alg;	/* save alg in rss_ctl only after success */

	ret = 0;

out:
	if (ret)
		nse_dev_err_errno(dev, ret, "cfg_rss_ctl failed");

	return ret;
}

int nse_vsi_cfg_rss(struct nse_vsi *vsi)
{
	struct nse_pf *pf = vsi->back;
	int ret;

	nse_debug(&pf->hw, NSE_DBG_RCF, "[%s] vsi(abs_id=%d)\n", __func__, vsi->vsi_abs_num);

	ret = nse_vsi_cfg_rss_ctl(vsi);
	if (ret)
		goto out;

	ret = nse_vsi_cfg_rss_key(vsi);
	if (ret)
		goto out;

	ret = nse_vsi_cfg_rss_lut(vsi);

out:
	return ret;
}

int nse_vsi_set_dflt_rss_lut(struct nse_vsi *vsi, int num_rxq)
{
	struct nse_pf *pf = vsi->back;
	struct device *dev;
	struct nse_hw *hw;
	int err;
	u16 *lut;

	dev = nse_pf_to_dev(pf);
	hw = &pf->hw;

	if (!num_rxq)
		return -EINVAL;

	lut = kcalloc(vsi->rss_lut_size_aligned, sizeof(u16), GFP_KERNEL);
	if (!lut)
		return -ENOMEM;

	/* create/set RSS LUT */
	nse_fill_rss_lut(lut, vsi->rss_lut_size_aligned, num_rxq);
	err = nse_set_rss_lut(vsi, lut, vsi->rss_lut_size_aligned);
	if (err)
		nse_dev_err_errno(dev, err, "Cannot set RSS lut, aq_err %s",
				  nse_aq_str(hw->adminq.sq_last_status));

	kfree(lut);
	return err;
}

/**
 * nse_vsi_manage_rss_lut - disable/enable RSS
 * @vsi: the VSI being changed
 * @ena: boolean value indicating if this is an enable or disable request
 *
 * In the event of disable request for RSS, this function will zero out RSS
 * LUT, while in the event of enable request for RSS, it will reconfigure RSS
 * LUT.
 */
void nse_vsi_manage_rss_lut(struct nse_vsi *vsi, bool ena)
{
	u16 *lut;

	lut = kcalloc(vsi->rss_lut_size_aligned, sizeof(u16), GFP_KERNEL);
	if (!lut)
		return;

	if (ena) {
		if (vsi->rss_lut_user)
			memcpy(lut, vsi->rss_lut_user, sizeof(u16) * vsi->rss_lut_size_aligned);
		else
			nse_fill_rss_lut(lut, vsi->rss_lut_size_aligned, vsi->num_rxq);
	}

	(void)nse_set_rss_lut(vsi, lut, vsi->rss_lut_size_aligned);

	kfree(lut);
}

void nse_aqc_dump_generic_common_hdr(struct nse_hw *hw, struct nse_aqc_generic_common_hdr *hdr)
{
	struct device *dev = nse_hw_to_dev(hw);

	dev_info(dev, "hdr->magic = 0x%X\n", hdr->magic);

	dev_info(dev, "hdr->pcore_id = %d\n", hdr->pcore_id);
	dev_info(dev, "hdr->pcore_pf_id = %d\n", hdr->pcore_pf_id);

	dev_info(dev, "hdr->dma_id = %d\n", hdr->dma_id);
	dev_info(dev, "hdr->dma_pf_id = %d\n", hdr->dma_pf_id);

	dev_info(dev, "hdr->chan_id = %d\n", hdr->chan_id);
	dev_info(dev, "hdr->chan_pf_id = %d\n", hdr->chan_pf_id);

	dev_info(dev, "hdr->lan_id = %d\n", hdr->lan_id);

	dev_info(dev, "hdr->vsi_abs_id = %d\n", le16_to_cpu(hdr->vsi_abs_id));
}

