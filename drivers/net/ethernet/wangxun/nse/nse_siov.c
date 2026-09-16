// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

/* WangXun(R) Ethernet Connection AM Series Linux Driver */

#include "nse.h"

#ifdef HAVE_PASID_SUPPORT

#include "nse_lib.h"
#include "nse_virtchnl_allowlist.h"
#include "nse_fltr.h"
#include "nse_siov_regs.h"
#include "nse_irq.h"
#include "nse_vf_lib_private.h"

struct nse_mbx {
	u32 mbx_asqh;
	u32 mbx_asqt;
	u32 mbx_asqbal;
	u32 mbx_asqbah;
	u32 mbx_arqh;
	u32 mbx_arqt;
	u32 mbx_arqbal;
	u32 mbx_arqbah;
};

struct nse_adi_priv {
	struct nse_adi adi;
	struct nse_vf vf;
	u32 pasid;
	void *token;
	struct work_struct update_hash_entry;
//	enum virtchnl_vfr_states reset_state;
	struct nse_mbx nse_adi_mbx;
};

static struct nse_adi_priv *adi_priv(struct nse_adi *adi)
{
	return (struct nse_adi_priv *)
		container_of(adi, struct nse_adi_priv, adi);
}

static struct nse_adi_priv *vf_to_adi_priv(struct nse_vf *vf)
{
	return (struct nse_adi_priv *)
		container_of(vf, struct nse_adi_priv, vf);
}

struct nse_adi_sparse_mmap_info {
	u64 start;
	u64 end;
	u64 cnt;
	u64 phy_addr;
};

enum nse_adi_sparse_mmap_type {
	NSE_ADI_SPARSE_MBX = 0,
	NSE_ADI_SPARSE_RXQ,
	NSE_ADI_SPARSE_TXQ,
//	NSE_ADI_SPARSE_DYN_CTL01,
	NSE_ADI_SPARSE_DYN_CTL,
	NSE_ADI_SPARSE_MAX,
};

/**
 * ice_adi_close - close ADI
 * @adi: ADI pointer
 *
 * Return 0 for success, negative for failure
 */
static int nse_adi_close(struct nse_adi *adi)
{
	struct nse_adi_priv *priv = adi_priv(adi);
	struct nse_vf *vf = &priv->vf;
	struct nse_pf *pf = vf->pf;
	struct nse_vsi *vsi;

	vsi = nse_get_vf_vsi(vf);
	if (!vsi) {
		dev_err(nse_pf_to_dev(pf), "Invalid VSI pointer");
		return -EFAULT;
	}

	nse_vsi_stop_lan_tx_rings(vsi, false);
	nse_vsi_stop_all_rx_rings(vsi, false);

	nse_set_vf_state_qs_dis(vf);

	return 0;
}

/**
 * ice_adi_reset - reset ADI
 * @adi: ADI pointer
 *
 * Return 0 for success, negative for failure
 */
static int nse_adi_reset(struct nse_adi *adi)
{
	struct nse_adi_priv *priv;
	struct nse_vf *vf;

	priv = adi_priv(adi);
	vf = &priv->vf;

	return nse_reset_vf(vf, NSE_VF_RESET_NOTIFY | NSE_VF_RESET_LOCK);
}

/**
 * ice_vsi_configure_pasid - config pasid for VSI
 * @vf: VF pointer
 * @pasid: pasid value
 * @ena: enable
 *
 * Return 0 for success, negative for failure
 */
static int nse_vsi_configure_pasid(struct nse_vf *vf, u32 pasid, bool ena)
{
	struct nse_adi_priv *priv = vf_to_adi_priv(vf);
	struct nse_vsi_ctx *ctxt;
	struct nse_vsi *vsi;
	struct device *dev;
	struct nse_hw *hw;
	int status;

	hw = &vf->pf->hw;
	dev = nse_pf_to_dev(vf->pf);

	if (!nse_is_hw_static_fea_set(hw, NSE_HW_STATIC_FEA_MISC_SUPPORT_SIOV)) {
		dev_err(dev, "[%s] NOT support\n", __func__);
		return -EOPNOTSUPP;
	}

	vsi = nse_get_vf_vsi(vf);
	if (!vsi)
		return -EINVAL;

	ctxt = kzalloc(sizeof(*ctxt), GFP_KERNEL);
	if (!ctxt)
		return -ENOMEM;

	ctxt->vsi_abs_num = vsi->vsi_abs_num;

	ctxt->info.valid_sections =
		cpu_to_le16(NSE_AQ_VSI_PROP_SECTION_PASID_VALID);
	pasid &= NSE_AQ_VSI_PASID_ID_M;
	if (ena)
		pasid |= NSE_AQ_VSI_PASID_ID_VALID;
	else
		pasid &= ~NSE_AQ_VSI_PASID_ID_VALID;
	ctxt->info.pasid_id = cpu_to_le32(pasid);
	status = nse_update_vsi(hw, vsi->idx, ctxt, NULL);
	if (status) {
		dev_err(dev, "Failed to update pasid id in VSI context, err %d aq_err %s\n",
			status, nse_aq_str(hw->adminq.sq_last_status));
	} else {
		vsi->info.pasid_id = cpu_to_le32(pasid);
		priv->pasid = pasid;
	}

	kfree(ctxt);
	return status;
}

/**
 * ice_adi_cfg_pasid - config pasid for ADI
 * @adi: ADI pointer
 * @pasid: pasid value
 * @ena: enable
 *
 * Return 0 for success, negative for failure
 */
static int nse_adi_cfg_pasid(struct nse_adi *adi, u32 pasid, bool ena)
{
	struct nse_adi_priv *priv;
	struct nse_vf *vf;
	int ret;

	priv = adi_priv(adi);
	vf = &priv->vf;
	ret = nse_vsi_configure_pasid(vf, pasid, ena);
	return ret;
}

/**
 * ice_dis_siov_vf_mapping - disable SIOV VF MSIX mapping
 * @vf: pointer to the VF structure
 *
 * Return 0 for success, negative for failure
 */
static int nse_dis_siov_vf_mapping(struct nse_vf *vf)
{
	struct nse_hw *hw = &vf->pf->hw;
	struct nse_vsi *vsi;

	vsi = nse_get_vf_vsi(vf);
	if (!vsi)
		return -EINVAL;

//PFVSI_UPINT(@0x1000108 + [0..255 * 0x1000])
//	wr32(hw, VPINT_MBX_CTL(vsi->vsi_num), 0);
	wr32(hw, NSE_REG_VMBX_CTL(vsi->vsi_abs_num), 0);

	return 0;
}

/**
 * ice_free_adi - Free a ADI
 * @priv: pointer to ADI private structure
 */
static void nse_free_adi(struct nse_adi_priv *priv)
{
	struct nse_vf *vf = &priv->vf;
	struct nse_vfs *vfs;

	WARN_ON(!hash_hashed(&vf->entry));

	vfs = &vf->pf->vfs;

	/* Remove the VF from the hash table, and then release its main
	 * reference with ice_put_vf(). Once the last reference is dropped it
	 * will be freed via ice_siov_free_vf.
	 */
	mutex_lock(&vfs->table_lock);
	hash_del_rcu(&vf->entry);
	mutex_unlock(&vfs->table_lock);

	cancel_work_sync(&priv->update_hash_entry);
	nse_put_vf(vf);
}

/**
 * ice_adi_vsi_setup - Set up a VSI for the ADI
 * @vf: pointer to VF structure
 *
 * Returns pointer to the successfully allocated VSI struct on success,
 * otherwise returns NULL on failure.
 */
static struct nse_vsi *nse_adi_vsi_setup(struct nse_vf *vf)
{
	struct nse_pf *pf = vf->pf;
	struct nse_port_info *pi = nse_vf_get_port_info(vf);
	struct nse_vsi *vsi;
	struct device *dev;
	int err;

	dev = nse_pf_to_dev(pf);

	vsi = nse_vsi_setup(pf, pi, NSE_VSI_ADI, vf, 0);
	if (!vsi) {
		dev_err(dev, "ADI VSI setup failed\n");
		nse_vf_invalidate_vsi(vf);
		return NULL;
	}
	vf->lan_vsi_idx = vsi->idx;
	/* TODO */
	vf->vf_id = vsi->vsi_abs_num;

	vf->vf_vsi_abs_id = vsi->vsi_abs_num;
	vf->vf_vsi_rel_id = vsi->vsi_rel_num;

	err = nse_vf_init_host_cfg(vf, vsi);
	if (err) {
		dev_err(dev, "Failed to initialize host configuration\n");
		goto release_vsi;
	}

	return vsi;

release_vsi:
	nse_vsi_release(vsi);
	nse_vf_invalidate_vsi(vf);
	return NULL;
}

/**
 * nse_siov_free_vf - Free VF memory after all references are dropped
 * @vf: the VF to free
 *
 * Called by nse_put_vf through ice_release_vf when the last VF reference is
 * dropped. Do not call this or the .free function directly. Instead, use
 * ice_put_vf to ensure that the memory is only released once all references
 * are finished.
 */
static void nse_siov_free_vf(struct nse_vf *vf)
{
	struct nse_adi_priv *priv = vf_to_adi_priv(vf);
	struct nse_vsi *vsi;

	/* ice_free_adi() takes care of removing the VF from the hash table */
	nse_dis_siov_vf_mapping(vf);
	vsi = nse_get_vf_vsi(vf);
	if (vsi)
		nse_vsi_release(vsi);
	mutex_destroy(&vf->cfg_lock);
	kfree_rcu(priv, vf.rcu);
}

/**
 * ice_siov_clear_reset_state - clears S-IOV VF Reset status indication
 * @vf: the vf to configure
 */
static void nse_siov_clear_reset_state(struct nse_vf *vf)
{
//	struct nse_adi_priv *priv = vf_to_adi_priv(vf);

	/* Clear the reset status so that VF does not get a mistaken
	 * indication of an active VF when reading VFGEN_RSTAT.
	 */
/* TODO */
//	priv->reset_state = VIRTCHNL_VFR_INPROGRESS;
}

/**
 * ice_siov_clear_mbx_register - clears S-IOV VF's mailbox registers
 * @vf: the vf to configure
 */
static void nse_siov_clear_mbx_register(struct nse_vf *vf)
{
	struct nse_adi_priv *priv = vf_to_adi_priv(vf);
	struct nse_hw *hw = &vf->pf->hw;

	/* Save mailbox registers. MBX_ARQLEN and MBX_ATQLEN won't
	 * be saved and restored because AVF driver will check
	 * ARQLEN to determine whether reset has been triggered.
	 */
	priv->nse_adi_mbx.mbx_asqh = rd32(hw, NSE_REG_VMBX_ATQH(vf->vf_id));
	priv->nse_adi_mbx.mbx_asqt = rd32(hw, NSE_REG_VMBX_ATQT(vf->vf_id));
	priv->nse_adi_mbx.mbx_asqbal = rd32(hw, NSE_REG_VMBX_ATQBAL(vf->vf_id));
	priv->nse_adi_mbx.mbx_asqbah = rd32(hw, NSE_REG_VMBX_ATQBAH(vf->vf_id));
	priv->nse_adi_mbx.mbx_arqh = rd32(hw, NSE_REG_VMBX_ARQH(vf->vf_id));
	priv->nse_adi_mbx.mbx_arqt = rd32(hw, NSE_REG_VMBX_ARQT(vf->vf_id));
	priv->nse_adi_mbx.mbx_arqbal = rd32(hw, NSE_REG_VMBX_ARQBAL(vf->vf_id));
	priv->nse_adi_mbx.mbx_arqbah = rd32(hw, NSE_REG_VMBX_ARQBAH(vf->vf_id));

	wr32(hw, NSE_REG_VMBX_ARQLEN(vf->vf_id), 0);
	wr32(hw, NSE_REG_VMBX_ATQLEN(vf->vf_id), 0);

	wr32(hw, NSE_REG_VMBX_ATQH(vf->vf_id), 0);
	wr32(hw, NSE_REG_VMBX_ATQT(vf->vf_id), 0);
	wr32(hw, NSE_REG_VMBX_ATQBAL(vf->vf_id), 0);
	wr32(hw, NSE_REG_VMBX_ATQBAH(vf->vf_id), 0);
	wr32(hw, NSE_REG_VMBX_ARQH(vf->vf_id), 0);
	wr32(hw, NSE_REG_VMBX_ARQT(vf->vf_id), 0);
	wr32(hw, NSE_REG_VMBX_ARQBAL(vf->vf_id), 0);
	wr32(hw, NSE_REG_VMBX_ARQBAH(vf->vf_id), 0);
}

/**
 * ice_siov_poll_reset_status - poll S-IOV VF reset status
 * @vf: pointer to VF structure
 *
 * Returns true when reset is successful, else returns false
 */
static bool nse_siov_poll_reset_status(struct nse_vf *vf)
{
	return true;
/* TODO */
}

/**
 * ice_siov_trigger_reset_register - trigger VF reset for S-IOV VF
 * @vf: pointer to VF structure
 * @is_vflr: true if reset occurred due to VFLR
 *
 * Trigger and cleanup a reset for a Scalable IOV VF.
 */
//static void nse_siov_trigger_reset_register(struct nse_vf *vf, bool is_vflr)

static void nse_siov_trigger_reset_register(struct nse_vf *vf)
{
/* TODO */
}

/**
 * ice_siov_irq_close - Close any IRQ data prior to resetting the VF
 * @vf: the VF to process
 *
 * Called by generic virtualization code during reset to close any previous
 * IRQ configuration before rebuilding a new VSI.
 */
static void nse_siov_irq_close(struct nse_vf *vf)
{
	struct nse_adi_priv *priv = vf_to_adi_priv(vf);

	/* Release the previous VSI IRQ context */
	nse_vdcm_pre_rebuild_irqctx(priv->token);
}

/**
 * ice_siov_create_vsi - Create a new S-IOV VSI after a reset
 * @vf: pointer to VF structure
 *
 * Called by ice_vf_recreate_vsi to create a new VSI after the old VSI has
 * been removed.
 *
 * Returns 0 on success, else returns a negative value;
 */
static int nse_siov_create_vsi(struct nse_vf *vf)
{
	struct nse_vsi *vsi;

	/* Make sure the old mapping is disabled */
	nse_dis_siov_vf_mapping(vf);

	vsi = nse_adi_vsi_setup(vf);
	if (!vsi)
		return -ENOMEM;

	return 0;
}

/**
 * ice_ena_siov_vf_mapping - enable SIOV VF MSIX mapping
 * @vf: pointer to the VF structure
 *
 * Returns 0 on success, else returns a negative value;
 */
static int nse_ena_siov_vf_mapping(struct nse_vf *vf)
{
	struct nse_hw *hw = &vf->pf->hw;
	struct nse_q_vector *q_vector;
	struct nse_vsi *vsi;
	u32 reg;

	vsi = nse_get_vf_vsi(vf);
	if (!vsi || !vsi->q_vectors)
		return -EINVAL;

	q_vector = vsi->q_vectors[0];
	if (!q_vector)
		return -EINVAL;

	reg = ((u32)q_vector->reg_idx << NSE_REG_VMBX_CTL_MSIX_IDX_S) | NSE_REG_VMBX_CTL_CAUSE_EN_M;

	wr32(hw, NSE_REG_VMBX_CTL(vsi->vsi_abs_num), reg);

	return 0;
}

/**
 * ice_siov_post_vsi_rebuild - post S-IOV VSI rebuild operations
 * @vf: pointer to VF structure
 *
 * After a VSI is re-created or rebuilt, perform the necessary operations to
 * complete the VSI rebuild. This function is called after an individual VF
 * reset or after a global PF reset.
 */
static void nse_siov_post_vsi_rebuild(struct nse_vf *vf)
{
	struct nse_adi_priv *priv = vf_to_adi_priv(vf);
	bool update_hash_entry;
	struct nse_vsi *vsi;
	struct device *dev;
	struct nse_hw *hw;
	int err;

	vsi = nse_get_vf_vsi(vf);
	if (!vsi)
		return;

	dev = nse_pf_to_dev(vf->pf);
	hw = &vf->pf->hw;

	/* If the VSI number has changed after the rebuild, we need to update
	 * the VF ID and move the entry in the hash table
	 */
	if (vsi->vsi_abs_num != vf->vf_id) {
		vf->vf_id = vsi->vsi_abs_num;
		update_hash_entry = true;
	} else {
		update_hash_entry = false;
	}

	err = nse_vdcm_rebuild_irqctx(priv->token);
	if (err)
		dev_err(dev, "failed to rebuild irq context, error %d\n", err);

	/* Make sure to zap all the pages only after the new VSI is setup.
	 * When ice_siov_vsi_rebuild is called by VF_RESET virtchnl, this
	 * function is scheduled in a kernel thread. At the same time, VM
	 * will keep accessing old VSI's mbx register set.
	 *
	 * If we zapped the pages before the new VSI was setup, the VF might
	 * read the mailbox register while we're still setting up the new VSI.
	 * This would trigger a page fault that generates a new GPA to HPA
	 * mapping, but with the old VSI registers.
	 *
	 * By zapping the pages only after the new VSI is setup, we avoid
	 * this possibility.
	 */
	nse_vdcm_zap(priv->token);

	err = nse_vsi_configure_pasid(vf, priv->pasid, true);
	if (err)
		dev_err(dev, "failed to reconfigure PASID for VF %u, error %d\n",
			vf->vf_id, err);

	if (nse_ena_siov_vf_mapping(vf))
		dev_err(dev, "Failed to map SIOV VF\n");

	/* If the VSI number has changed after the rebuild, we need to update
	 * the hash table. This can't be done immediately in this thread
	 * because we might be iterating the hash table in this thread, and we
	 * can't take the table lock without causing a deadlock here. Schedule
	 * a thread to update the hash table.
	 *
	 * If we don't need to update the hash entry, its safe to let the VF
	 * driver activate. Otherwise, delay this until we finish updating the
	 * hash entry.
	 */
	if (update_hash_entry)
		queue_work(nse_wq, &priv->update_hash_entry);

/* TODO */
//	else
//		priv->reset_state = VIRTCHNL_VFR_VFACTIVE;

	/* Restore mailbox values. Don't restore MBX_ARQLEN and
	 * MBX_ATQLEN as explained in ice_siov_clear_mbx_register.
	 */
	wr32(hw, NSE_REG_VMBX_ATQH(vf->vf_id), priv->nse_adi_mbx.mbx_asqh);
	wr32(hw, NSE_REG_VMBX_ATQT(vf->vf_id), priv->nse_adi_mbx.mbx_asqt);
	wr32(hw, NSE_REG_VMBX_ATQBAL(vf->vf_id), priv->nse_adi_mbx.mbx_asqbal);
	wr32(hw, NSE_REG_VMBX_ATQBAH(vf->vf_id), priv->nse_adi_mbx.mbx_asqbah);
	wr32(hw, NSE_REG_VMBX_ARQH(vf->vf_id), priv->nse_adi_mbx.mbx_arqh);
	wr32(hw, NSE_REG_VMBX_ARQT(vf->vf_id), priv->nse_adi_mbx.mbx_arqt);
	wr32(hw, NSE_REG_VMBX_ARQBAL(vf->vf_id), priv->nse_adi_mbx.mbx_arqbal);
	wr32(hw, NSE_REG_VMBX_ARQBAH(vf->vf_id), priv->nse_adi_mbx.mbx_arqbah);
}

/**
 * ice_siov_clear_reset_trigger - enable VF to access hardware
 * @vf: VF to enabled hardware access for
 */
static void nse_siov_clear_reset_trigger(struct nse_vf *vf)
{
/* TODO */
}

static struct nse_q_vector *nse_siov_get_q_vector(struct nse_vf *vf,
						  struct nse_vsi *vsi, u16 vector_id)
{
	if (!vsi || !vsi->q_vectors)
		return NULL;

	/* don't subtract OICR vector since SIOV VF stores the corresponding
	 * vector_id in the vsi's q_vector array.
	 */
	return vsi->q_vectors[vector_id];
}

static const struct nse_vf_ops nse_siov_vf_ops = {
	.free = nse_siov_free_vf,
	.clear_reset_state = nse_siov_clear_reset_state,
	.clear_mbx_register = nse_siov_clear_mbx_register,
	.trigger_reset_register = nse_siov_trigger_reset_register,
	.poll_reset_status = nse_siov_poll_reset_status,
	.clear_reset_trigger = nse_siov_clear_reset_trigger,
	.irq_close = nse_siov_irq_close,
	.reinit_vsi = nse_siov_create_vsi,
	.post_vsi_rebuild = nse_siov_post_vsi_rebuild,
	.get_q_vector = nse_siov_get_q_vector,
};

/**
 * ice_siov_update_hash_entry - work task to fix VF hash entry
 * @work: the work task structure
 *
 * Work item scheduled to fix the VF hash entry after a rebuild. Called when
 * the VSI number, and thus the VF ID has changed. This update cannot be done
 * in the same thread because it cannot guarantee a safe method of acquiring
 * the table lock mutex, and because the calling thread might be iterating the
 * hash table using the standard iterator which is not protected against hash
 * table modification.
 */
static void nse_siov_update_hash_entry(struct work_struct *work)
{
	struct nse_adi_priv *priv = container_of(work, struct nse_adi_priv,
						 update_hash_entry);
	struct nse_vf *vf = &priv->vf;
	struct nse_vfs *vfs;

	vfs = &vf->pf->vfs;

	mutex_lock(&vfs->table_lock);
	mutex_lock(&vf->cfg_lock);

	hash_del_rcu(&vf->entry);
	hash_add_rcu(vfs->table, &vf->entry, vf->vf_id);

	/* We've finished cleaning up in software. Update the reset
	 * state, allowing the VF to detect that its safe to proceed.
	 */
	/* TODO */
//	priv->reset_state = VIRTCHNL_VFR_VFACTIVE;

	mutex_unlock(&vf->cfg_lock);
	mutex_unlock(&vfs->table_lock);
}

/**
 * nse_create_adi - Set up the VF structure and create VSI
 * @pf: pointer to PF structure
 *
 * Returns pointer to the successfully allocated VSI struct on success,
 * otherwise returns NULL on failure.
 */
static struct nse_adi_priv *nse_create_adi(struct nse_pf *pf)
{
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_vfs *vfs = &pf->vfs;
	struct nse_adi_priv *priv;
	struct nse_vsi *vsi;
	struct nse_vf *vf;

	/* Disable global interrupts */
	wr32(&pf->hw, NSE_REG_INT_DYN_CTLN(pf->misc_irq_idx),
	     (NSE_REG_INT_DYN_CTLN_INTMSK_VLD_M | NSE_REG_INT_DYN_CTLN_INTMSK_M));
	set_bit(NSE_OICR_INTR_DIS, pf->state);
	nse_flush(&pf->hw);
	if (nse_get_avail_txq_count(pf) < NSE_DFLT_QS_PER_SIOV_VF ||
	    nse_get_avail_rxq_count(pf) < NSE_DFLT_QS_PER_SIOV_VF)
		return NULL;

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return NULL;
	vf = &priv->vf;
	kref_init(&vf->refcnt);
	vf->pf = pf;

	/* set S-IOV specific vf ops for VFs created during S-IOV flow */
	vf->vf_ops = &nse_siov_vf_ops;
	nse_initialize_vf_entry(vf);
	INIT_WORK(&priv->update_hash_entry, nse_siov_update_hash_entry);

	vf->vf_sw_id = pf->first_sw;
	vsi = nse_adi_vsi_setup(vf);
	if (!vsi) {
		dev_err(dev, "Failed to initialize VSI resources for SIOV VF\n");
		goto init_vf_err;
	}

	if (nse_ena_siov_vf_mapping(vf)) {
		dev_err(dev, "Failed to map SIOV VF\n");
		goto vf_mapping_err;
	}

	mutex_init(&vf->cfg_lock);

	set_bit(NSE_VF_STATE_INIT, vf->vf_states);
	/* TODO */
//	wr32(&pf->hw, VSIGEN_RSTAT(vf->vf_id), VIRTCHNL_VFR_VFACTIVE);
	nse_flush(&pf->hw);
	clear_bit(NSE_VF_DIS, pf->state);

	/* re-enable interrupts */
	if (test_and_clear_bit(NSE_OICR_INTR_DIS, pf->state))
		nse_irq_dynamic_ena(&pf->hw, NULL, NULL);

	mutex_lock(&pf->vfs.table_lock);
	hash_add_rcu(vfs->table, &vf->entry, vf->vf_id);
	mutex_unlock(&pf->vfs.table_lock);

	return priv;

vf_mapping_err:
	nse_vsi_release(vsi);
	nse_vf_invalidate_vsi(vf);
init_vf_err:
	kfree_rcu(priv, vf.rcu);
	return NULL;
}

/**
 * ice_adi_get_vector_num - get number of vectors assigned to this ADI
 * @adi: ADI pointer
 *
 * Return 0 or postive for success, negative for failure
 */
static int nse_adi_get_vector_num(struct nse_adi *adi)
{
	struct nse_adi_priv *priv = adi_priv(adi);
	struct nse_vf *vf = &priv->vf;
	struct nse_pf *pf = vf->pf;
	struct nse_vsi *vsi;

	vsi = nse_get_vf_vsi(vf);
	if (!vsi) {
		dev_err(nse_pf_to_dev(pf), "Invalid VSI pointer");
		return -EFAULT;
	}

	return vsi->num_q_vectors;
}

/**
 * ice_adi_get_vector_irq - get OS IRQ number per vector
 * @adi: ADI pointer
 * @vector: IRQ vector index
 *
 * Return 0 or postive for success, negative for failure
 */
static int nse_adi_get_vector_irq(struct nse_adi *adi, u32 vector)
{
	struct nse_adi_priv *priv = adi_priv(adi);
	struct nse_vf *vf = &priv->vf;
	struct nse_pf *pf = vf->pf;
	struct nse_vsi *vsi;

	vsi = nse_get_vf_vsi(vf);
	if (!vsi) {
		dev_err(nse_pf_to_dev(pf), "Invalid VSI pointer");
		return -EFAULT;
	}

	if (vector >= vsi->num_q_vectors)
		return -EINVAL;

	return nse_get_irq_num(pf, vsi->base_vector + vector);
}

/**
 * ice_adi_read_reg32 - read ADI register
 * @adi: ADI pointer
 * @offs: register offset
 *
 * Return register value at the offset
 */
static u32 nse_adi_read_reg32(struct nse_adi *adi, size_t offs)
{
	struct nse_adi_priv *priv = adi_priv(adi);
	struct nse_vf *vf = &priv->vf;
	struct nse_pf *pf = vf->pf;
	struct nse_vsi *vsi;
	u32 index, reg_val;
	struct nse_hw *hw;

	if (test_bit(NSE_VF_STATE_DIS, vf->vf_states)) {
/* TODO */
//		if (offs == VFGEN_RSTAT1)
//			return VIRTCHNL_VFR_INPROGRESS;
//		else
		return 0xdeadbeef;
	}

	hw = &pf->hw;
	vsi = nse_get_vf_vsi(vf);
	if (!vsi) {
		dev_err(nse_pf_to_dev(pf), "Invalid VSI pointer");
		return 0xdeadbeef;
	}

	/* check for 4-byte aligned register access */
	if (!IS_ALIGNED(offs, 4))
		return 0xdeadbeef;

	switch (offs) {
/* TODO */
	/* compare to vf driver */
	case NSEVF_MBX_ATQBAL1:
		return rd32(hw, NSE_REG_VMBX_ATQBAL(vsi->vsi_abs_num));
	case NSEVF_MBX_ATQBAH1:
		return rd32(hw, NSE_REG_VMBX_ATQBAH(vsi->vsi_abs_num));
	case NSEVF_MBX_ATQLEN1:
		return rd32(hw, NSE_REG_VMBX_ATQLEN(vsi->vsi_abs_num));
	case NSEVF_MBX_ATQH1:
		return rd32(hw, NSE_REG_VMBX_ATQH(vsi->vsi_abs_num));
	case NSEVF_MBX_ATQT1:
		return rd32(hw, NSE_REG_VMBX_ATQT(vsi->vsi_abs_num));
	case NSEVF_MBX_ARQBAL1:
		return rd32(hw, NSE_REG_VMBX_ARQBAL(vsi->vsi_abs_num));
	case NSEVF_MBX_ARQBAH1:
		return rd32(hw, NSE_REG_VMBX_ARQBAH(vsi->vsi_abs_num));
	case NSEVF_MBX_ARQLEN1:
		return rd32(hw, NSE_REG_VMBX_ARQLEN(vsi->vsi_abs_num));
	case NSEVF_MBX_ARQH1:
		return rd32(hw, NSE_REG_VMBX_ARQH(vsi->vsi_abs_num));
	case NSEVF_MBX_ARQT1:
		return rd32(hw, NSE_REG_VMBX_ARQT(vsi->vsi_abs_num));
/* TODO */
	case NSE_VFINT_DYN_CTLN(0) ... NSE_VFINT_DYN_CTLN(63):
		/* vsi's vector 0 reserved for OICR,
		 * data Q vectors start from index 1
		 */
		index = (offs - NSE_VFINT_DYN_CTLN(0)) / 4 + 1;
		if (index >= vsi->num_q_vectors || !vsi->q_vectors[index]) {
			dev_warn_once(nse_pf_to_dev(pf), "Invalid vector pointer for VSI %d\n",
				      vsi->vsi_abs_num);
			return 0xdeadbeef;
		}
		return rd32(hw, NSE_REG_INT_DYN_CTLN(vsi->q_vectors[index]->reg_idx));
	default:
		return 0xdeadbeef;
	}
}

/**
 * ice_adi_write_reg32 - write ADI register
 * @adi: ADI pointer
 * @offs: register offset
 * @data: register value
 */
static void nse_adi_write_reg32(struct nse_adi *adi, size_t offs, u32 data)
{
	struct nse_adi_priv *priv = adi_priv(adi);
	struct nse_vf *vf = &priv->vf;
	struct nse_pf *pf = vf->pf;
	struct nse_vsi *vsi;
	struct nse_hw *hw;
	u32 index;

	if (test_bit(NSE_VF_STATE_DIS, vf->vf_states))
		return;

	hw = &pf->hw;
	vsi = nse_get_vf_vsi(vf);
	if (!vsi) {
		dev_err(nse_pf_to_dev(pf), "Invalid VSI pointer");
		return;
	}

	/* check for 4-byte aligned register access */
	if (!IS_ALIGNED(offs, 4))
		return;

	switch (offs) {
	case NSEVF_MBX_ATQBAL1:
		wr32(hw, NSE_REG_VMBX_ATQBAL(vsi->vsi_abs_num), data);
		break;
	case NSEVF_MBX_ATQBAH1:
		wr32(hw, NSE_REG_VMBX_ATQBAH(vsi->vsi_abs_num), data);
		break;
	case NSEVF_MBX_ATQLEN1:
		wr32(hw, NSE_REG_VMBX_ATQLEN(vsi->vsi_abs_num), data);
		break;
	case NSEVF_MBX_ATQH1:
		wr32(hw, NSE_REG_VMBX_ATQH(vsi->vsi_abs_num), data);
		break;
	case NSEVF_MBX_ATQT1:
		wr32(hw, NSE_REG_VMBX_ATQT(vsi->vsi_abs_num), data);
		break;
	case NSEVF_MBX_ARQBAL1:
		wr32(hw, NSE_REG_VMBX_ARQBAL(vsi->vsi_abs_num), data);
		break;
	case NSEVF_MBX_ARQBAH1:
		wr32(hw, NSE_REG_VMBX_ARQBAH(vsi->vsi_abs_num), data);
		break;
	case NSEVF_MBX_ARQLEN1:
		wr32(hw, NSE_REG_VMBX_ARQLEN(vsi->vsi_abs_num), data);
		break;
	case NSEVF_MBX_ARQH1:
		wr32(hw, NSE_REG_VMBX_ARQH(vsi->vsi_abs_num), data);
		break;
	case NSEVF_MBX_ARQT1:
		wr32(hw, NSE_REG_VMBX_ARQT(vsi->vsi_abs_num), data);
		break;
/* TODO */
	case NSE_VFINT_DYN_CTLN(0) ... NSE_VFINT_DYN_CTLN(63):
		/* vsi's vector 0 reserved for OICR,
		 * data Q vectors start from index 1
		 */
		index = (offs - NSE_VFINT_DYN_CTLN(0)) / 4 + 1;
		if (index >= vsi->num_q_vectors || !vsi->q_vectors[index])
			goto err_resource;
		wr32(hw, NSE_REG_INT_DYN_CTLN(vsi->q_vectors[index]->reg_idx), data);
		break;
	case NSEVF_QTX_TAIL(0) ... NSEVF_QRX_TAIL(1023):
		if ((offs % 8) == 0) {
			index = (offs - NSEVF_QTX_TAIL(0)) / 8;
			if (!vsi->tx_rings[index] || index >= vsi->alloc_txq)
				goto err_resource;
			wr32(hw, NSE_REG_QTX_DBELL(vsi->tx_rings[index]->reg_idx), data);
			break;
		} else if ((offs % 4) == 0) {
			index = (offs - NSEVF_QRX_TAIL(0)) / 8;
			if (!vsi->rx_rings[index] || index >= vsi->alloc_rxq)
				goto err_resource;
			wr32(hw, NSE_REG_QRX_TAIL(vsi->rx_rings[index]->reg_idx), data);
			break;
		}
	default:
		break;
	}
	return;

err_resource:
	dev_warn_once(nse_pf_to_dev(pf), "Invalid resource access for VF VSI %d\n",
		      vsi->vsi_abs_num);
}

/**
 * ice_adi_get_sparse_mmap_hpa - get VDEV HPA
 * @adi: pointer to assignable device interface
 * @index: VFIO BAR index
 * @vm_pgoff: page offset of virtual memory area
 * @addr: VDEV address
 *
 * Return 0 if success, negative for failure.
 */
static int
nse_adi_get_sparse_mmap_hpa(struct nse_adi *adi, u32 index,
			    u64 vm_pgoff, u64 *addr)
{
	struct nse_adi_priv *priv;
	struct pci_dev *pdev;
	struct nse_vsi *vsi;
	struct nse_vf *vf;
	u64 reg_off;
	int q_idx;

	if (!addr || index != VFIO_PCI_BAR0_REGION_INDEX)
		return -EINVAL;

	priv = adi_priv(adi);
	vf = &priv->vf;
	vsi = nse_get_vf_vsi(vf);
	if (!vsi)
		return -EINVAL;

	pdev = vf->pf->pdev;
	switch (vm_pgoff) {
	case PHYS_PFN(VDEV_MBX_START):
		/* MBX Registers */
		reg_off = NSE_REG_VMBX_ATQBAL(vsi->vsi_abs_num);
		break;
	case PHYS_PFN(VDEV_QRX_TAIL_START) ...
				(PHYS_PFN(VDEV_INT_DYN_CTLN_START) - 1):
		/* RXQ tail register */
		q_idx = vm_pgoff - PHYS_PFN(VDEV_QRX_TAIL_START);
		if (q_idx >= vsi->alloc_rxq)
			return -EINVAL;
		reg_off = NSE_REG_QRX_TAIL(vsi->rx_rings[q_idx]->reg_idx);
		break;
	case PHYS_PFN(VDEV_QTX_DBELL_START) ...
				(PHYS_PFN(VDEV_QRX_TAIL_START) - 1):
		/* TXQ tail register */
		q_idx = vm_pgoff - PHYS_PFN(VDEV_QTX_DBELL_START);
		if (q_idx >= vsi->alloc_txq)
			return -EINVAL;
		reg_off = NSE_REG_QTX_DBELL(vsi->tx_rings[q_idx]->reg_idx);
		break;

/* TODO */
	case PHYS_PFN(VDEV_INT_DYN_CTLN(0)) ...
					(PHYS_PFN(NSE_VDCM_BAR0_SIZE) - 1):
		/* INT DYN CTL, ITR0/1/2
		 * the first several vectors in q_vectors[] is for mailbox,
		 * mailbox vector's number is defined with ICE_NONQ_VECS_VF
		 */
		q_idx = vm_pgoff - PHYS_PFN(VDEV_INT_DYN_CTLN(0))
			+ NSE_NONQ_VECS_VF;
		if (q_idx >= vsi->num_q_vectors)
			return -EINVAL;
		reg_off = NSE_REG_INT_DYN_CTLN(vsi->q_vectors[q_idx]->reg_idx);
		break;
	default:
		return -EFAULT;
	}

	/* add BAR0 start address */
	*addr = pci_resource_start(pdev, 0) + reg_off;
	return 0;
}

/**
 * ice_adi_get_sparse_mmap_num - get number of sparse memory
 * @adi: pointer to assignable device interface
 *
 * Return number of sparse memory areas.
 */
static int
nse_adi_get_sparse_mmap_num(struct nse_adi *adi)
{
	struct nse_adi_priv *priv;
	struct nse_vsi *vsi;
	struct nse_vf *vf;

	priv = adi_priv(adi);
	vf = &priv->vf;
	vsi = nse_get_vf_vsi(vf);
	if (!vsi)
		return -EINVAL;

	/**
	 * Besides tx/rx queue registers, INT DYN CTL, ITR0/1/2 registers,
	 * we also need to reserve for MBX registers, which is defined
	 * with ICE_NONQ_VECS_VF
	 */
	return vsi->alloc_txq + vsi->alloc_rxq
		+ vsi->num_q_vectors + NSE_NONQ_VECS_VF;
}

/**
 * ice_adi_get_sparse_mmap_area - get sparse memory layout for mmap
 * @adi: pointer to assignable device interface
 * @index: index of sparse memory
 * @offset: pointer to sparse memory areas offset
 * @size: pointer to sparse memory areas size
 *
 * Return 0 if success, negative for failure.
 */
static int
nse_adi_get_sparse_mmap_area(struct nse_adi *adi, int index,
			     u64 *offset, u64 *size)
{
	struct nse_adi_sparse_mmap_info pattern[NSE_ADI_SPARSE_MAX];
	struct nse_adi_priv *priv;
	struct nse_vsi *vsi;
	struct nse_vf *vf;
	int nr_areas = 0;
	u64 ai;
	int i;

	memset(pattern, 0, sizeof(pattern[0]) * NSE_ADI_SPARSE_MAX);

	priv = adi_priv(adi);
	vf = &priv->vf;
	vsi = nse_get_vf_vsi(vf);
	if (!vsi)
		return -EINVAL;

	nr_areas = nse_adi_get_sparse_mmap_num(adi);

	if (index < 0 || (index > (nr_areas - 1)))
		return -EINVAL;

	ai = (u64)index;

	i = NSE_ADI_SPARSE_MBX;
	pattern[i].start = 0;
	pattern[i].cnt = 1;
	pattern[i].end = pattern[i].start + pattern[i].cnt;
	pattern[i].phy_addr = VDEV_MBX_START;

	i = NSE_ADI_SPARSE_RXQ;
	pattern[i].start = pattern[i - 1].end;
	pattern[i].cnt = vsi->alloc_rxq;
	pattern[i].end = pattern[i].start + pattern[i].cnt;
	pattern[i].phy_addr = VDEV_QRX_TAIL_START;

	i = NSE_ADI_SPARSE_TXQ;
	pattern[i].start = pattern[i - 1].end;
	pattern[i].cnt = vsi->alloc_txq;
	pattern[i].end = pattern[i].start + pattern[i].cnt;
	pattern[i].phy_addr = VDEV_QTX_DBELL_START;

/* TODO */

	i = NSE_ADI_SPARSE_DYN_CTL;
	pattern[i].start = pattern[i - 1].end;
	/* the first q_vector is for mailbox, which has been allocated */
	if (vsi->num_q_vectors > 1)
		pattern[i].cnt = vsi->num_q_vectors - 1;
	pattern[i].end = pattern[i].start + pattern[i].cnt;
	pattern[i].phy_addr = VDEV_INT_DYN_CTLN(0);

	for (i = 0; i < NSE_ADI_SPARSE_MAX; i++) {
		if (ai >= pattern[i].start && ai < pattern[i].end) {
			*offset = pattern[i].phy_addr +
					PAGE_SIZE * (ai - pattern[i].start);
			*size   = PAGE_SIZE;
			break;
		}
	}

	return (i == NSE_ADI_SPARSE_MAX) ? -EINVAL : 0;
}

/**
 * ice_vdcm_alloc_adi - alloc one ADI
 * @dev: linux device associated with ADI
 * @token: pointer to VDCM
 *
 * Return Non zero pointer for success, NULL for failure
 */
struct nse_adi *nse_vdcm_alloc_adi(struct device *dev, void *token)
{
	struct nse_adi_priv *priv;
	struct nse_adi *adi;
	struct nse_pf *pf;

	pf = pci_get_drvdata(to_pci_dev(dev));

	priv = nse_create_adi(pf);
	if (!priv)
		return NULL;

	adi = &priv->adi;
	priv->token = token;
	adi->cfg_pasid = nse_adi_cfg_pasid;
	adi->close = nse_adi_close;
	adi->reset = nse_adi_reset;
	adi->get_vector_num = nse_adi_get_vector_num;
	adi->get_vector_irq = nse_adi_get_vector_irq;
	adi->read_reg32 = nse_adi_read_reg32;
	adi->write_reg32 = nse_adi_write_reg32;
	adi->get_sparse_mmap_hpa = nse_adi_get_sparse_mmap_hpa;
	adi->get_sparse_mmap_num = nse_adi_get_sparse_mmap_num;
	adi->get_sparse_mmap_area = nse_adi_get_sparse_mmap_area;

	return adi;
}

/**
 * ice_vdcm_free_adi - free ADI
 * @adi: ADI pointer
 */
void nse_vdcm_free_adi(struct nse_adi *adi)
{
	struct nse_adi_priv *priv = adi_priv(adi);

	nse_free_adi(priv);
}

/**
 * ice_is_siov_capable - Check if device and platform support Scalable IOV
 * @pf: pointer to the device private structure
 *
 * Note that there is no way to check whether the platform supports the IOMMU
 * auxiliary domain without enabling the feature, so this has a side effect of
 * enabling it when returning true.
 */
bool nse_is_siov_capable(struct nse_pf *pf)
{
	struct pci_dev *pdev = pf->pdev;
	struct device *dev = &pdev->dev;
	int err;

	/* The device must have the PASID extended PCI capability, and its
	 * BAR0 size must be at least 128MB.
	 */
	if (!pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_PASID) ||
	    pci_resource_len(pdev, NSE_BAR0) < SZ_128M)
		return false;

	/* Enable the IOMMU auxiliary domain now. If we fail, this means the
	 * platform doesn't support Scalable IOV and we should fall back to
	 * defaults
	 */
	err = iommu_dev_enable_feature(dev, IOMMU_DEV_FEAT_AUX);

	return err ? false : true;
}

/**
 * ice_restore_pasid_config - restore PASID mbx support
 * @pf: PF pointer structure
 * @reset_type: type of reset
 *
 * On CORER/GLOBER, the global PASID mbx support bit gets
 * cleared. For successful restoration of Scalable IOV VFs
 * on these kind of resets, we need to reenable PASID mbx
 * support.
 */
void nse_restore_pasid_config(struct nse_pf *pf, enum nse_reset_req reset_type)
{
/* TODO */
}

/**
 * ice_initialize_siov_res - initialize SIOV related resources
 * @pf: PF pointer structure
 */
void nse_initialize_siov_res(struct nse_pf *pf)
{
	struct device *dev = nse_pf_to_dev(pf);
	int err;

	err = nse_vdcm_init(pf->pdev);
	if (err) {
		dev_err(dev, "Error enabling Scalable IOV\n");

		/* Disable the IOMMU auxiliary domain since we're no longer
		 * going to enable Scalable IOV support. It's already enabled
		 * when checking whether the device is capable of supporting
		 * Scalable IOV.
		 */
		iommu_dev_disable_feature(dev, IOMMU_DEV_FEAT_AUX);
		return;
	}
	/* enable PASID mailbox support */
/* TODO */
//wr32(&pf->hw, GL_MBX_PASID, GL_MBX_PASID_PASID_MODE_M);
	set_bit(NSE_FLAG_SIOV_ENA, pf->flags);

	/* set default SIOV VF resources */
	pf->vfs.num_msix_per = NSE_NUM_VF_MSIX_SMALL;
	pf->vfs.num_qps_per = min_t(int, pf->vfs.num_msix_per,
				    NSE_DFLT_QS_PER_SIOV_VF);

	/* ensure mutual exclusivity of SRIOV and SIOV */
	clear_bit(NSE_FLAG_SRIOV_CAPABLE, pf->flags);
	dev_info(dev, "Scalable IOV has been enabled, disabling SRIOV\n");

/* TODO */
//	nse_dcf_init_sw_rule_mgmt(pf);
}

/**
 * ice_deinit_siov_res - Deinitialize Scalable IOV related resources
 * @pf: pointer to the PF private structure
 */
void nse_deinit_siov_res(struct nse_pf *pf)
{
	struct device *dev = nse_pf_to_dev(pf);
	u32 reg;

	if (!test_bit(NSE_FLAG_SIOV_ENA, pf->flags))
		return;

	nse_vdcm_deinit(pf->pdev);

	iommu_dev_disable_feature(dev, IOMMU_DEV_FEAT_AUX);

/* TODO */
	clear_bit(NSE_FLAG_SIOV_ENA, pf->flags);
}

#endif /* HAVE_PASID_SUPPORT */

