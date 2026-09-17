// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2020 - 2026 Mucse Corporation. */

#include "mcevf_base.h"
#include "mcevf_lib.h"
#include "mcevf_irq.h"

unsigned int mcevf_loglevel =
	0 /*BIT(LOG_MBX_REQ_OUT) | BIT(LOG_MBX_IN_REQ) | BIT(LOG_MISC_IRQ)*/;
module_param(mcevf_loglevel, uint, 0600);

static int speed_map[] = {
	0,
	SPEED_10,
	SPEED_100,
	SPEED_1000,
	SPEED_10000,
	SPEED_25000,
	SPEED_40000,
	SPEED_100000,
};

int speed_zip_to_bit3(int speed)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(speed_map); i++)
		if (speed_map[i] == speed)
			return i;
	return 0;
}

int speed_unzip(int speed_3bit)
{
	if (speed_3bit > ARRAY_SIZE(speed_map))
		return 0;
	return speed_map[speed_3bit];
}

/**
 * mcevf_free_q_vector - Free memory allocated for a specific interrupt vector
 * @vsi: VSI having the memory freed
 * @v_idx: index of the vector to be freed
 */
static void mcevf_free_q_vector(struct mcevf_vsi *vsi, int v_idx)
{
	struct mcevf_q_vector *q_vector;
	struct mcevf_pf *pf = vsi->back;
	struct mcevf_ring *ring;
	struct device *dev;

	dev = mcevf_pf_to_dev(pf);
	if (!vsi->q_vectors[v_idx]) {
		dev_dbg(dev, "Queue vector at index %d not found\n",
			v_idx);
		return;
	}
	q_vector = vsi->q_vectors[v_idx];

	mcevf_for_each_ring(ring, q_vector->tx)
		ring->q_vector = NULL;
	mcevf_for_each_ring(ring, q_vector->rx)
		ring->q_vector = NULL;

	/* only VSI with an associated netdev is set up with NAPI */
	if (vsi->netdev)
		netif_napi_del(&q_vector->napi);

	devm_kfree(dev, q_vector);
	vsi->q_vectors[v_idx] = NULL;
}

/**
 * mcevf_vsi_free_q_vectors - Free memory allocated for interrupt vectors
 * @vsi: the VSI having memory freed
 */
void mcevf_vsi_free_q_vectors(struct mcevf_vsi *vsi)
{
	int v_idx;

	mcevf_for_each_q_vector(vsi, v_idx)
		mcevf_free_q_vector(vsi, v_idx);
}

/**
 * mcevf_vsi_alloc_q_vector - Allocate memory for a single interrupt vector
 * @vsi: the VSI being configured
 * @v_idx: index of the vector in the VSI struct
 *
 * We allocate one q_vector and set default value for ITR setting associated
 * with this q_vector. If allocation fails we return -ENOMEM.
 */
static int mcevf_vsi_alloc_q_vector(struct mcevf_vsi *vsi, u16 v_idx)
{
	struct mcevf_pf *pf = vsi->back;
	struct mcevf_q_vector *q_vector;
	int node;

	/* allocate q_vector */
	q_vector = devm_kzalloc(mcevf_pf_to_dev(pf), sizeof(*q_vector),
				GFP_KERNEL);
	if (!q_vector)
		return -ENOMEM;

	q_vector->vsi = vsi;
	q_vector->v_idx = v_idx;
	q_vector->tx.type = MCEVF_TX_CONTAINER;
	q_vector->rx.type = MCEVF_RX_CONTAINER;

	if (!test_bit(MCEVF_FLAG_HW_DIM_ENA, pf->flags)) {
		if (test_bit(MCEVF_FLAG_SW_DIM_ENA, pf->flags)) {
			q_vector->tx.dim_params.mode = ITR_SW_DYNAMIC;
			q_vector->rx.dim_params.mode = ITR_SW_DYNAMIC;
		} else {
			q_vector->tx.dim_params.mode = ITR_STATIC;
			q_vector->rx.dim_params.mode = ITR_STATIC;
		}
	} else {
		q_vector->tx.dim_params.mode = ITR_HW_DYNAMIC;
		q_vector->rx.dim_params.mode = ITR_HW_DYNAMIC;
	}

	q_vector->rx.dim_params.usecs = MCEVF_RX_INT_DELAY_TIME;
	q_vector->rx.dim_params.frames = MCEVF_RX_INT_DELAY_PKTS;
	q_vector->tx.dim_params.usecs = MCEVF_TX_INT_DELAY_TIME;
	q_vector->tx.dim_params.frames = MCEVF_TX_INT_DELAY_PKTS;

	node = dev_to_node(&pf->pdev->dev);
	q_vector->cpu = cpumask_local_spread(v_idx, node);
	cpumask_clear(&q_vector->affinity_mask);
	cpumask_set_cpu(q_vector->cpu, &q_vector->affinity_mask);

	/* This will not be called in the driver load path because the netdev
	 * will not be created yet. All other cases with register the NAPI
	 * handler here (i.e. resume, reset/rebuild, etc.)
	 */
	if (vsi->netdev)
		netif_napi_add(vsi->netdev, &q_vector->napi,
			       mcevf_napi_poll, NAPI_POLL_WEIGHT);

	/* tie q_vector and VSI together */
	vsi->q_vectors[v_idx] = q_vector;

	return 0;
}

/**
 * mcevf_vsi_alloc_q_vectors - Allocate memory for interrupt vectors
 * @vsi: the VSI being configured
 *
 * We allocate one q_vector per queue interrupt. If allocation fails we
 * return -ENOMEM.
 */
int mcevf_vsi_alloc_q_vectors(struct mcevf_vsi *vsi)
{
	struct device *dev = mcevf_pf_to_dev(vsi->back);
	u16 v_idx = 0;
	int err = 0;

	if (vsi->q_vectors[0]) {
		dev_dbg(dev, "VSI %d has existing q_vectors\n", vsi->idx);
		return -EEXIST;
	}

	for (v_idx = 0; v_idx < vsi->num_q_vectors; v_idx++) {
		err = mcevf_vsi_alloc_q_vector(vsi, v_idx);
		if (err)
			goto err_out;
	}

	return 0;

err_out:
	while (v_idx--)
		mcevf_free_q_vector(vsi, v_idx);

	dev_err(dev, "Failed to allocate %d q_vector for VSI %d",
		vsi->num_q_vectors, vsi->idx);
	vsi->num_q_vectors = 0;
	return err;
}
