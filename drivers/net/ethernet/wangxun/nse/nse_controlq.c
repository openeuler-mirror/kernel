// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#include "nse.h"
#include "nse_common.h"
#include "nse_lib.h"

static inline void nse_aq_wait(unsigned int usec, bool force_delay)
{
	unsigned int msec = usec / 1000;
	unsigned int usec_remain = usec % 1000;

	if (!nse_aq_cmd_wait_method && !force_delay) {
		if (msec)
			msleep(msec);

		if (usec_remain)
			usleep_range(usec_remain, usec_remain + 50);

	} else {
		/*  not directly use udelay(usec), otherwise if > MAX_UDELAY_MS then complains with
		 * __bad_udelay()
		 */

		if (msec)
			mdelay(msec);

		if (usec_remain)
			udelay(usec_remain);
	}
}

static inline void nse_aq_sq_lock(struct nse_ctl_q_info *cq)
{
	mutex_lock(&cq->sq_lock);
}

static inline void nse_aq_sq_unlock(struct nse_ctl_q_info *cq)
{
	mutex_unlock(&cq->sq_lock);
}

static inline void nse_aq_rq_lock(struct nse_ctl_q_info *cq)
{
	if (nse_aq_rq_rx_method)
		spin_lock_bh(&cq->rq_lock.spl);
	else
		mutex_lock(&cq->rq_lock.mtx);
}

static inline void nse_aq_rq_unlock(struct nse_ctl_q_info *cq)
{
	if (nse_aq_rq_rx_method)
		spin_unlock_bh(&cq->rq_lock.spl);
	else
		mutex_unlock(&cq->rq_lock.mtx);
}

#define NSE_CQ_INIT_REGS(qinfo, prefix)				\
do {								\
	(qinfo)->sq.head = prefix##_ATQH;			\
	(qinfo)->sq.tail = prefix##_ATQT;			\
	(qinfo)->sq.len = prefix##_ATQLEN;			\
	(qinfo)->sq.bah = prefix##_ATQBAH;			\
	(qinfo)->sq.bal = prefix##_ATQBAL;			\
	(qinfo)->sq.len_mask = prefix##_ATQLEN_LEN_M;	\
	(qinfo)->sq.len_crit_mask = prefix##_ATQLEN_CRIT_M;	\
	(qinfo)->sq.head_mask = prefix##_ATQH_HEAD_M;		\
	(qinfo)->rq.head = prefix##_ARQH;			\
	(qinfo)->rq.tail = prefix##_ARQT;			\
	(qinfo)->rq.len = prefix##_ARQLEN;			\
	(qinfo)->rq.bah = prefix##_ARQBAH;			\
	(qinfo)->rq.bal = prefix##_ARQBAL;			\
	(qinfo)->rq.len_mask = prefix##_ARQLEN_LEN_M;	\
	(qinfo)->rq.len_crit_mask = prefix##_ARQLEN_CRIT_M;	\
	(qinfo)->rq.head_mask = prefix##_ARQH_HEAD_M;		\
} while (0)

/**
 * nse_adminq_write_context() - Write Adminq context.
 * @hw: pointer to the hardware structure
 * @msix_idx: irq vector which adminq is bound to.
 * @cause_en: enable adminq as irq cause to irq vector.
 */
static void nse_adminq_write_context(struct nse_hw *hw, u16 msix_idx, bool cause_en, u8 pf_idx)
{
	u32 reg = 0;

	reg = ((u32)msix_idx << NSE_REG_PMBX_CTL_MSIX_IDX_S) & NSE_REG_PMBX_CTL_MSIX_IDX_M;

	if (cause_en)
		reg |= NSE_REG_PMBX_CTL_CAUSE_EN_M;

	reg |= (((u32)pf_idx << NSE_REG_PMBX_CTL_PF_IDX_S) & NSE_REG_PMBX_CTL_PF_IDX_M);

	wr32(hw, NSE_REG_PMBX_CTL, reg);
}

/**
 * nse_adminq_init_regs - Initialize AdminQ registers
 * @hw: pointer to the hardware structure
 *
 * This assumes the alloc_sq and alloc_rq functions have already been called
 */
static void nse_adminq_init_regs(struct nse_hw *hw)
{
	struct nse_ctl_q_info *cq = &hw->adminq;

	NSE_CQ_INIT_REGS(cq, NSE_REG_PMBX);
}

/**
 * nse_check_sq_alive
 * @hw: pointer to the HW struct
 * @cq: pointer to the specific Control queue
 *
 * Returns true if Queue is enabled else false.
 */
bool nse_check_sq_alive(struct nse_hw *hw, struct nse_ctl_q_info *cq, u32 *sq_len_val)
{
	u32 sq_len;
	u32 q_stat_mask = (NSE_REG_AQM_QLEN_STAT_Q_PAUSE_N_M | NSE_REG_AQM_QLEN_STAT_Q_EN_M);

	if (sq_len_val)
		*sq_len_val = 0;

	if (hw->high_reset_ongoing)
		return false;

	/* check both queue-length and queue-enable fields */
	if (cq->sq.len && cq->sq.len_mask) {
		sq_len = rd32(hw, cq->sq.len);

		if (sq_len_val)
			*sq_len_val = sq_len;

		if (nse_is_regval_reset_magic(sq_len))
			return false;

		return (sq_len & (cq->sq.len_mask |
			q_stat_mask)) == (cq->num_sq_entries | q_stat_mask);
	}

	return false;
}

bool nse_check_rq_alive(struct nse_hw *hw, struct nse_ctl_q_info *cq, u32 *rq_len_val)
{
	u32 rq_len;
	u32 q_stat_mask = (NSE_REG_AQM_QLEN_STAT_Q_PAUSE_N_M | NSE_REG_AQM_QLEN_STAT_Q_EN_M);

	if (rq_len_val)
		*rq_len_val = 0;

	if (hw->high_reset_ongoing)
		return false;

	/* check both queue-length and queue-enable fields */
	if (cq->rq.len && cq->rq.len_mask) {
		rq_len = rd32(hw, cq->rq.len);

		if (rq_len_val)
			*rq_len_val = rq_len;

		if (nse_is_regval_reset_magic(rq_len))
			return false;

		return (rq_len & (cq->rq.len_mask |
			q_stat_mask)) == (cq->num_rq_entries | q_stat_mask);
	}

	return false;
}

/**
 * nse_alloc_ctrlq_sq_ring - Allocate Control Transmit Queue (ATQ) rings
 * @hw: pointer to the hardware structure
 * @cq: pointer to the specific Control queue
 */
static enum nse_status
nse_alloc_ctrlq_sq_ring(struct nse_hw *hw, struct nse_ctl_q_info *cq)
{
	size_t size = cq->num_sq_entries * sizeof(struct nse_aq_desc);

	cq->sq.desc_buf.va = dmam_alloc_coherent(nse_hw_to_dev(hw), size,
						 &cq->sq.desc_buf.pa,
						 GFP_KERNEL | __GFP_ZERO);
	if (!cq->sq.desc_buf.va)
		return NSE_ERR_NO_MEMORY;
	cq->sq.desc_buf.size = size;

	cq->sq.cmd_buf = devm_kcalloc(nse_hw_to_dev(hw), cq->num_sq_entries,
				      sizeof(struct nse_sq_cd), GFP_KERNEL);
	if (!cq->sq.cmd_buf) {
		dmam_free_coherent(nse_hw_to_dev(hw), cq->sq.desc_buf.size,
				   cq->sq.desc_buf.va, cq->sq.desc_buf.pa);
		cq->sq.desc_buf.va = NULL;
		cq->sq.desc_buf.pa = 0;
		cq->sq.desc_buf.size = 0;
		return NSE_ERR_NO_MEMORY;
	}

	return 0;
}

/**
 * nse_alloc_ctrlq_rq_ring - Allocate Control Receive Queue (ARQ) rings
 * @hw: pointer to the hardware structure
 * @cq: pointer to the specific Control queue
 */
static enum nse_status
nse_alloc_ctrlq_rq_ring(struct nse_hw *hw, struct nse_ctl_q_info *cq)
{
	size_t size = cq->num_rq_entries * sizeof(struct nse_aq_desc);

	cq->rq.desc_buf.va = dmam_alloc_coherent(nse_hw_to_dev(hw), size,
						 &cq->rq.desc_buf.pa,
						 GFP_KERNEL | __GFP_ZERO);
	if (!cq->rq.desc_buf.va)
		return NSE_ERR_NO_MEMORY;
	cq->rq.desc_buf.size = size;
	return 0;
}

/**
 * nse_free_cq_ring - Free control queue ring
 * @hw: pointer to the hardware structure
 * @ring: pointer to the specific control queue ring
 *
 * This assumes the posted buffers have already been cleaned
 * and de-allocated
 */
static void nse_free_cq_ring(struct nse_hw *hw, struct nse_ctl_q_ring *ring)
{
	dmam_free_coherent(nse_hw_to_dev(hw), ring->desc_buf.size,
			   ring->desc_buf.va, ring->desc_buf.pa);
	ring->desc_buf.va = NULL;
	ring->desc_buf.pa = 0;
	ring->desc_buf.size = 0;
}

/**
 * nse_alloc_rq_bufs - Allocate pre-posted buffers for the ARQ
 * @hw: pointer to the hardware structure
 * @cq: pointer to the specific Control queue
 */
static enum nse_status
nse_alloc_rq_bufs(struct nse_hw *hw, struct nse_ctl_q_info *cq)
{
	int i;

	/* We'll be allocating the buffer info memory first, then we can
	 * allocate the mapped buffers for the event processing
	 */
	cq->rq.dma_head = devm_kcalloc(nse_hw_to_dev(hw), cq->num_rq_entries,
				       sizeof(cq->rq.desc_buf), GFP_KERNEL);
	if (!cq->rq.dma_head)
		return NSE_ERR_NO_MEMORY;
	cq->rq.r.rq_bi = (struct nse_dma_mem *)cq->rq.dma_head;

	/* allocate the mapped buffers */
	for (i = 0; i < cq->num_rq_entries; i++) {
		struct nse_aq_desc *desc;
		struct nse_dma_mem *bi;

		bi = &cq->rq.r.rq_bi[i];
		bi->va = dmam_alloc_coherent(nse_hw_to_dev(hw),
					     cq->rq_buf_size, &bi->pa,
					     GFP_KERNEL | __GFP_ZERO);
		if (!bi->va)
			goto unwind_alloc_rq_bufs;
		bi->size = cq->rq_buf_size;

		/* now configure the descriptors for use */
		desc = NSE_CTL_Q_DESC(cq->rq, i);

		desc->flags = cpu_to_le16(NSE_AQ_FLAG_BUF);
		if (cq->rq_buf_size > NSE_AQ_LG_BUF)
			desc->flags |= cpu_to_le16(NSE_AQ_FLAG_LB);
		desc->opcode = 0;
		/* This is in accordance with Admin queue design, there is no
		 * register for buffer size configuration
		 */
		desc->datalen = cpu_to_le16(bi->size);
		desc->addr_high =
			cpu_to_le32(upper_32_bits(bi->pa));
		desc->addr_low =
			cpu_to_le32(lower_32_bits(bi->pa));
	}
	return 0;

unwind_alloc_rq_bufs:
	/* don't try to free the one that failed... */
	i--;
	for (; i >= 0; i--) {
		dmam_free_coherent(nse_hw_to_dev(hw), cq->rq.r.rq_bi[i].size,
				   cq->rq.r.rq_bi[i].va, cq->rq.r.rq_bi[i].pa);
		cq->rq.r.rq_bi[i].va = NULL;
		cq->rq.r.rq_bi[i].pa = 0;
		cq->rq.r.rq_bi[i].size = 0;
	}
	cq->rq.r.rq_bi = NULL;
	devm_kfree(nse_hw_to_dev(hw), cq->rq.dma_head);
	cq->rq.dma_head = NULL;

	return NSE_ERR_NO_MEMORY;
}

/**
 * nse_alloc_sq_bufs - Allocate empty buffer structs for the ATQ
 * @hw: pointer to the hardware structure
 * @cq: pointer to the specific Control queue
 */
static enum nse_status
nse_alloc_sq_bufs(struct nse_hw *hw, struct nse_ctl_q_info *cq)
{
	int i;

	/* No mapped memory needed yet, just the buffer info structures */
	cq->sq.dma_head = devm_kcalloc(nse_hw_to_dev(hw), cq->num_sq_entries,
				       sizeof(cq->sq.desc_buf), GFP_KERNEL);
	if (!cq->sq.dma_head)
		return NSE_ERR_NO_MEMORY;
	cq->sq.r.sq_bi = (struct nse_dma_mem *)cq->sq.dma_head;

	/* allocate the mapped buffers */
	for (i = 0; i < cq->num_sq_entries; i++) {
		struct nse_dma_mem *bi;

		bi = &cq->sq.r.sq_bi[i];
		bi->va = dmam_alloc_coherent(nse_hw_to_dev(hw),
					     cq->sq_buf_size, &bi->pa,
					     GFP_KERNEL | __GFP_ZERO);
		if (!bi->va)
			goto unwind_alloc_sq_bufs;
		bi->size = cq->sq_buf_size;
	}
	return 0;

unwind_alloc_sq_bufs:
	/* don't try to free the one that failed... */
	i--;
	for (; i >= 0; i--) {
		dmam_free_coherent(nse_hw_to_dev(hw), cq->sq.r.sq_bi[i].size,
				   cq->sq.r.sq_bi[i].va, cq->sq.r.sq_bi[i].pa);
		cq->sq.r.sq_bi[i].va = NULL;
		cq->sq.r.sq_bi[i].pa = 0;
		cq->sq.r.sq_bi[i].size = 0;
	}
	cq->sq.r.sq_bi = NULL;
	devm_kfree(nse_hw_to_dev(hw), cq->sq.dma_head);
	cq->sq.dma_head = NULL;

	return NSE_ERR_NO_MEMORY;
}

static enum nse_status
nse_cfg_cq_regs(struct nse_hw *hw, struct nse_ctl_q_ring *ring, u16 num_entries, bool asq_or_arq)
{
	struct device *dev = nse_hw_to_dev(hw);
	u32 reg;
	u32 wait_timeout;
	u32 wait_timeout_tick = NSE_CTL_Q_SQ_CMD_USEC;
	u32 total_wait = 0;
	enum nse_status status = 0;

	wait_timeout = (NSE_CTL_Q_SQ_CMD_TIMEOUT_BASE * nse_timeout_scale);

	/* Clear Head and Tail */
	wr32(hw, ring->head, 0);
	wr32(hw, ring->tail, 0);

	/* set starting point */
	wr32(hw, ring->bal, lower_32_bits(ring->desc_buf.pa));
	wr32(hw, ring->bah, upper_32_bits(ring->desc_buf.pa));

	nse_flush(hw);

	/* enable
	 */
	wmb();

	reg = (num_entries |
			(NSE_CTLQ_STAT_BIT_IDX_Q_EN << NSE_REG_AQM_QLEN_STAT_BIT_S) |
			NSE_REG_AQM_QLEN_EXEC_M |
			(NSE_REG_AQM_QLEN_OP_SET_STAT << NSE_REG_AQM_QLEN_OP_S));

	wr32(hw, ring->len, reg);

	nse_flush(hw);

	total_wait = 0;

	do {
		nse_aq_wait(wait_timeout_tick, false);

		reg = rd32(hw, ring->len);

		if (nse_is_regval_reset_magic(reg) ||
		    (reg & NSE_REG_AQM_QLEN_LEN_M) != num_entries) {
			dev_err(dev, "[%s] SW try to set q_en, but readback value: 0x%X",
				__func__, reg);

			goto fail_enable;
		}

		if (reg & NSE_REG_AQM_QLEN_STAT_Q_EN_M)
			break;

		total_wait++;

	} while (total_wait < wait_timeout);

	if (!(reg & NSE_REG_AQM_QLEN_STAT_Q_EN_M)) {
		dev_err(dev, "[%s] timeout wait for q_en, readback value: 0x%X", __func__, reg);

		goto fail_enable;
	}

	/* un-pause
	 */
	wmb();

	reg = (num_entries |
			(NSE_CTLQ_STAT_BIT_IDX_Q_PAUSE_N << NSE_REG_AQM_QLEN_STAT_BIT_S) |
			NSE_REG_AQM_QLEN_EXEC_M |
			(NSE_REG_AQM_QLEN_OP_SET_STAT << NSE_REG_AQM_QLEN_OP_S));

	wr32(hw, ring->len, reg);

	nse_flush(hw);

	total_wait = 0;

	do {
		nse_aq_wait(wait_timeout_tick, false);

		reg = rd32(hw, ring->len);

		if (nse_is_regval_reset_magic(reg) ||
		    (reg & NSE_REG_AQM_QLEN_LEN_M) != num_entries) {
			dev_err(dev, "[%s] SW try to set q_pause_n, but readback value: 0x%X",
				__func__, reg);

			goto fail_unpause;
		}

		if (reg & NSE_REG_AQM_QLEN_STAT_Q_PAUSE_N_M)
			break;

		total_wait++;

	} while (total_wait < wait_timeout);

	if (!(reg & NSE_REG_AQM_QLEN_STAT_Q_PAUSE_N_M)) {
		dev_err(dev, "[%s] timeout wait for q_pause_n, readback value: 0x%X",
			__func__, reg);

		goto fail_unpause;
	}

	/* Check one register to verify that config was applied */
	reg = rd32(hw, ring->bal);
	if (reg != lower_32_bits(ring->desc_buf.pa)) {
		dev_err(dev, "[%s] FAIL: SW set BAL value (0x%X), but readback value (0x%X) not expect\n",
						__func__,
							lower_32_bits(ring->desc_buf.pa), reg);

		status = NSE_ERR_AQ_ERROR;
	}

out:
	if (hw->debug_mask & NSE_DBG_AQM_MSG) {
		dev_info(dev, "ring->head [BAR0 reg: %X, value: %X], expect: %X\n",
					ring->head,
					rd32(hw, ring->head), 0);

		dev_info(dev, "ring->tail [BAR0 reg: %X, value: %X], expect: %X\n",
					ring->tail,
					rd32(hw, ring->tail), 0);

		dev_info(dev, "ring->len [BAR0 reg: %X, value: %X], expect: %lX\n",
					ring->len,
					rd32(hw, ring->len), (num_entries |
							      NSE_REG_AQM_QLEN_STAT_Q_PAUSE_N_M |
						NSE_REG_AQM_QLEN_STAT_Q_EN_M));

		dev_info(dev, "ring->bal [BAR0 reg: %X, value: %X], expect: %X\n",
					ring->bal,
					rd32(hw, ring->bal), lower_32_bits(ring->desc_buf.pa));

		dev_info(dev, "ring->bah [BAR0 reg: %X, value: %X], expect: %X\n",
					ring->bah,
					rd32(hw, ring->bah), upper_32_bits(ring->desc_buf.pa));
	}

	return status;

fail_enable:

	dev_err(dev, "[%s] FAIL: SW enable ctlq-%s\n", __func__, asq_or_arq ? "sq" : "rq");

	status = NSE_ERR_AQ_ERROR;

	goto out;

fail_unpause:

	dev_err(dev, "[%s] FAIL: SW unpause ctlq-%s\n", __func__, asq_or_arq ? "sq" : "rq");

	status = NSE_ERR_AQ_ERROR;

	goto out;
}

/**
 * nse_cfg_sq_regs - configure Control ATQ registers
 * @hw: pointer to the hardware structure
 * @cq: pointer to the specific Control queue
 *
 * Configure base address and length registers for the transmit queue
 */
static enum nse_status
nse_cfg_sq_regs(struct nse_hw *hw, struct nse_ctl_q_info *cq)
{
	return nse_cfg_cq_regs(hw, &cq->sq, cq->num_sq_entries, true);
}

/**
 * nse_cfg_rq_regs - configure Control ARQ register
 * @hw: pointer to the hardware structure
 * @cq: pointer to the specific Control queue
 *
 * Configure base address and length registers for the receive (event queue)
 */
static enum nse_status
nse_cfg_rq_regs(struct nse_hw *hw, struct nse_ctl_q_info *cq)
{
	enum nse_status status;

	status = nse_cfg_cq_regs(hw, &cq->rq, cq->num_rq_entries, false);
	if (status)
		return status;

	/* Update tail in the HW to post pre-allocated buffers */
	wr32(hw, cq->rq.tail, (u32)(cq->num_rq_entries - 1));

	nse_debug(hw, NSE_DBG_AQM_MSG, "cq->rq.tail [BAR0 reg: %X, value: %X], expect: %X\n",
				cq->rq.tail,
				rd32(hw, cq->rq.tail), (u32)(cq->num_rq_entries - 1));

	return 0;
}

#define NSE_FREE_CQ_BUFS(hw, qi, ring)					\
do {									\
	/* free descriptors */						\
	if ((qi)->ring.r.ring##_bi) {					\
		int i;							\
									\
		for (i = 0; i < (qi)->num_##ring##_entries; i++)	\
			if ((qi)->ring.r.ring##_bi[i].pa) {		\
				dmam_free_coherent(nse_hw_to_dev(hw),	\
					(qi)->ring.r.ring##_bi[i].size,	\
					(qi)->ring.r.ring##_bi[i].va,	\
					(qi)->ring.r.ring##_bi[i].pa);	\
					(qi)->ring.r.ring##_bi[i].va = NULL;\
					(qi)->ring.r.ring##_bi[i].pa = 0;\
					(qi)->ring.r.ring##_bi[i].size = 0;\
		}							\
	}								\
	/* free the buffer info list */					\
	if ((qi)->ring.cmd_buf)						\
		devm_kfree(nse_hw_to_dev(hw), (qi)->ring.cmd_buf);	\
	/* free DMA head */						\
	devm_kfree(nse_hw_to_dev(hw), (qi)->ring.dma_head);		\
} while (0)

/**
 * nse_init_sq - main initialization routine for Control ATQ
 * @hw: pointer to the hardware structure
 * @cq: pointer to the specific Control queue
 *
 * This is the main initialization routine for the Control Send Queue
 * Prior to calling this function, the driver *MUST* set the following fields
 * in the cq->structure:
 *     - cq->num_sq_entries
 *     - cq->sq_buf_size
 *
 * Do *NOT* hold the lock when calling this as the memory allocation routines
 * called are not going to be atomic context safe
 */
static enum nse_status nse_init_sq(struct nse_hw *hw, struct nse_ctl_q_info *cq)
{
	enum nse_status ret_code;

	if (cq->sq.count > 0) {
		/* queue already initialized */
		ret_code = NSE_ERR_NOT_READY;
		goto init_ctrlq_exit;
	}

	/* verify input for valid configuration */
	if (!cq->num_sq_entries || !cq->sq_buf_size) {
		ret_code = NSE_ERR_CFG;
		goto init_ctrlq_exit;
	}

	cq->sq.next_to_use = 0;
	cq->sq.next_to_clean = 0;

	/* allocate the ring memory */
	ret_code = nse_alloc_ctrlq_sq_ring(hw, cq);
	if (ret_code)
		goto init_ctrlq_exit;

	/* allocate buffers in the rings */
	ret_code = nse_alloc_sq_bufs(hw, cq);
	if (ret_code)
		goto init_ctrlq_free_rings;

	/* initialize base registers */
	ret_code = nse_cfg_sq_regs(hw, cq);
	if (ret_code)
		goto init_ctrlq_free_rings;

	/* success! */
	cq->sq.count = cq->num_sq_entries;
	goto init_ctrlq_exit;

init_ctrlq_free_rings:
	NSE_FREE_CQ_BUFS(hw, cq, sq);
	nse_free_cq_ring(hw, &cq->sq);

init_ctrlq_exit:
	return ret_code;
}

/**
 * nse_init_rq - initialize ARQ
 * @hw: pointer to the hardware structure
 * @cq: pointer to the specific Control queue
 *
 * The main initialization routine for the Admin Receive (Event) Queue.
 * Prior to calling this function, the driver *MUST* set the following fields
 * in the cq->structure:
 *     - cq->num_rq_entries
 *     - cq->rq_buf_size
 *
 * Do *NOT* hold the lock when calling this as the memory allocation routines
 * called are not going to be atomic context safe
 */
static enum nse_status nse_init_rq(struct nse_hw *hw, struct nse_ctl_q_info *cq)
{
	enum nse_status ret_code;

	if (cq->rq.count > 0) {
		/* queue already initialized */
		ret_code = NSE_ERR_NOT_READY;
		goto init_ctrlq_exit;
	}

	/* verify input for valid configuration */
	if (!cq->num_rq_entries || !cq->rq_buf_size) {
		ret_code = NSE_ERR_CFG;
		goto init_ctrlq_exit;
	}

	cq->rq.next_to_use = 0;
	cq->rq.next_to_clean = 0;

	/* allocate the ring memory */
	ret_code = nse_alloc_ctrlq_rq_ring(hw, cq);
	if (ret_code)
		goto init_ctrlq_exit;

	/* allocate buffers in the rings */
	ret_code = nse_alloc_rq_bufs(hw, cq);
	if (ret_code)
		goto init_ctrlq_free_rings;

	/* initialize base registers */
	ret_code = nse_cfg_rq_regs(hw, cq);
	if (ret_code)
		goto init_ctrlq_free_rings;

	/* success! */
	cq->rq.count = cq->num_rq_entries;
	goto init_ctrlq_exit;

init_ctrlq_free_rings:
	NSE_FREE_CQ_BUFS(hw, cq, rq);
	nse_free_cq_ring(hw, &cq->rq);

init_ctrlq_exit:
	return ret_code;
}

/**
 * nse_shutdown_sq - shutdown the Control ATQ
 * @hw: pointer to the hardware structure
 * @cq: pointer to the specific Control queue
 *
 * The main shutdown routine for the Control Transmit Queue
 */
enum nse_status
nse_shutdown_sq(struct nse_hw *hw, struct nse_ctl_q_info *cq, unsigned int flags)
{
	struct device *dev = nse_hw_to_dev(hw);
	u32 len;
	u32 wait_timeout;
	u32 wait_timeout_tick = NSE_CTL_Q_SQ_CMD_USEC;
	u32 total_wait = 0;
	enum nse_status ret_code = 0;
	bool dealloc_mem = true;

	wait_timeout = (NSE_CTL_Q_SQ_CMD_TIMEOUT_BASE * nse_timeout_scale);

	nse_debug(hw, NSE_DBG_SYS, "[%s] - enter: wait_timeout=%d, wait_timeout_tick=%d, qtype=%d, flags=0x%X\n",
								__func__, wait_timeout,
									wait_timeout_tick,
									cq->qtype, flags);

	nse_aq_sq_lock(cq);

	if (!cq->sq.count) {
		dealloc_mem = false;
		ret_code = NSE_ERR_NOT_READY;
		goto shutdown_sq_out;
	}

	len = rd32(hw, cq->sq.len);
	if (nse_is_regval_reset_magic(len) || hw->high_reset_ongoing) {
		nse_debug(hw, NSE_DBG_SYS, "[%s, %d] sq.len is: 0x%X or high_reset_ongoing = %d, maybe in reset, return early\n",
			  __func__, __LINE__, len, hw->high_reset_ongoing);
		goto skip_sw_shutdown;
	}

	if (cq->qtype == NSE_CTL_Q_UTIL ||
		!(flags & NSE_SHUTDOWN_CTLQ_FLAG_WAIT_FW_SHUTDOWN))
		goto skip_wait_fw_shutdown;

	total_wait = 0;

	do {
		nse_aq_wait(wait_timeout_tick, false);

		len = rd32(hw, cq->sq.len);

		if (!(len & (NSE_REG_AQM_QLEN_STAT_Q_PAUSE_N_M | NSE_REG_AQM_QLEN_STAT_Q_EN_M)))
			break;

		if (nse_is_regval_reset_magic(len) || hw->high_reset_ongoing) {
			nse_debug(hw, NSE_DBG_SYS, "[%s, %d] sq.len is: 0x%X or high_reset_ongoing = %d, maybe in reset, return early\n",
				  __func__, __LINE__, len, hw->high_reset_ongoing);
			goto skip_sw_shutdown;
		}

		total_wait++;

	} while (total_wait < wait_timeout);

skip_wait_fw_shutdown:

	len = rd32(hw, cq->sq.len);

	if (len & (NSE_REG_AQM_QLEN_STAT_Q_PAUSE_N_M | NSE_REG_AQM_QLEN_STAT_Q_EN_M)) {
		if (cq->qtype == NSE_CTL_Q_ADMIN) {
			hw->controlq_stats.aq_sq_wait_for_fw_pause_disable_fail_cnt++;
			hw->controlq_stats.aq_sq_wait_for_fw_pause_disable_fail_time =
				ktime_to_ns(ktime_get());

			dev_info(dev, "WARN: aq_sq may not be paused + disabled in time by FW --- FW should do that by aq-cmd: NSE_AQ_OPC_Q_SHUTDOWN\n");
			dev_info(dev, "\t cmd: SHUTDOWN was sent at %ld ns, now is: %ld ns\n",
				 (unsigned long)hw->controlq_stats.aq_cmd_shutdown_time,
						(unsigned long)hw->controlq_stats.aq_sq_wait_for_fw_pause_disable_fail_time);
		} else if (cq->qtype == NSE_CTL_Q_MAILBOX) {
			hw->controlq_stats.mq_sq_wait_for_fw_pause_disable_fail_cnt++;
			hw->controlq_stats.mq_sq_wait_for_fw_pause_disable_fail_time =
				ktime_to_ns(ktime_get());

			dev_info(dev, "WARN: mq_sq may not be paused + disabled in time by FW --- FW should do that by aq-cmd: NSE_AQ_OPC_Q_SHUTDOWN\n");
			dev_info(dev, "\t cmd: SHUTDOWN was sent at %ld ns, now is: %ld ns\n",
				 (unsigned long)hw->controlq_stats.mq_cmd_shutdown_time,
						(unsigned long)hw->controlq_stats.mq_sq_wait_for_fw_pause_disable_fail_time);
		}

		dev_info(dev, "\t SW try pause + disable itself --- sq_len=0x%X\n", len);

		/* Keep the SW pause sequence below from being reordered ahead
		 * of the operations above.
		 */
		wmb();

		/* SW pause
		 */
		len = rd32(hw, cq->sq.len);

		if (len & NSE_REG_AQM_QLEN_STAT_Q_PAUSE_N_M) {
			len &= ~(NSE_REG_AQM_QLEN_STAT_BIT_M |
				 NSE_REG_AQM_QLEN_EXEC_M | NSE_REG_AQM_QLEN_OP_M);

			len |= ((NSE_CTLQ_STAT_BIT_IDX_Q_PAUSE_N << NSE_REG_AQM_QLEN_STAT_BIT_S) |
					NSE_REG_AQM_QLEN_EXEC_M |
					(NSE_REG_AQM_QLEN_OP_CLR_STAT << NSE_REG_AQM_QLEN_OP_S));

			wr32(hw, cq->sq.len, len);

			nse_flush(hw);

			total_wait = 0;

			do {
				nse_aq_wait(wait_timeout_tick, false);

				len = rd32(hw, cq->sq.len);

				if (!(len & NSE_REG_AQM_QLEN_STAT_Q_PAUSE_N_M)) {
					nse_debug(hw, NSE_DBG_SYS, "[%s] DONE: SW clear sq q_pause_n, wait times=%d\n",
						  __func__, total_wait);
					break;
				}

				if (nse_is_regval_reset_magic(len) || hw->high_reset_ongoing) {
					nse_debug(hw, NSE_DBG_SYS, "[%s, %d] sq.len is: 0x%X or high_reset_ongoing = %d, maybe in reset, return early\n",
						  __func__, __LINE__, len,
							  hw->high_reset_ongoing);
					goto skip_sw_shutdown;
				}

				total_wait++;

			} while (total_wait < wait_timeout);

			len = rd32(hw, cq->sq.len);

			if (len & NSE_REG_AQM_QLEN_STAT_Q_PAUSE_N_M) {
				if (cq->qtype == NSE_CTL_Q_ADMIN) {
					hw->controlq_stats.aq_sq_wait_for_sw_pause_fail_cnt++;
					hw->controlq_stats.aq_sq_wait_for_sw_pause_fail_time =
						ktime_to_ns(ktime_get());

					dev_info(dev,
				"WARN: timeout: SW clear aq_sq q_pause_n, sq_len=0x%X\n", len);
					dev_info(dev, "\t now is: %ld ns\n",
								(unsigned long)hw->controlq_stats.aq_sq_wait_for_sw_pause_fail_time);
				} else if (cq->qtype == NSE_CTL_Q_MAILBOX) {
					hw->controlq_stats.mq_sq_wait_for_sw_pause_fail_cnt++;
					hw->controlq_stats.mq_sq_wait_for_sw_pause_fail_time =
						ktime_to_ns(ktime_get());

					dev_info(dev,
				"WARN: timeout: SW clear mq_sq q_pause_n, sq_len=0x%X\n", len);
					dev_info(dev, "\t now is: %ld ns\n",
								(unsigned long)hw->controlq_stats.mq_sq_wait_for_sw_pause_fail_time);
				} else if (cq->qtype == NSE_CTL_Q_UTIL) {
					hw->controlq_stats.uq_sq_wait_for_sw_pause_fail_cnt++;
					hw->controlq_stats.uq_sq_wait_for_sw_pause_fail_time =
						ktime_to_ns(ktime_get());

					dev_info(dev,
				"WARN: timeout: SW clear uq_sq q_pause_n, sq_len=0x%X\n", len);
					dev_info(dev, "\t now is: %ld ns\n",
								(unsigned long)hw->controlq_stats.uq_sq_wait_for_sw_pause_fail_time);
				}
			}
		}

		/* Keep the SW disable sequence below from being reordered ahead
		 * of the SW pause above.
		 */
		wmb();

		/* SW disable
		 *
		 * even SW pause timeout, continue anyway to disable procedure....
		 */

		len = rd32(hw, cq->sq.len);

		if (len & NSE_REG_AQM_QLEN_STAT_Q_EN_M) {
			len &= ~(NSE_REG_AQM_QLEN_STAT_BIT_M |
				 NSE_REG_AQM_QLEN_EXEC_M | NSE_REG_AQM_QLEN_OP_M);

			len |= ((NSE_CTLQ_STAT_BIT_IDX_Q_EN << NSE_REG_AQM_QLEN_STAT_BIT_S) |
					NSE_REG_AQM_QLEN_EXEC_M |
					(NSE_REG_AQM_QLEN_OP_CLR_STAT << NSE_REG_AQM_QLEN_OP_S));

			wr32(hw, cq->sq.len, len);

			nse_flush(hw);

			total_wait = 0;

			do {
				nse_aq_wait(wait_timeout_tick, false);

				len = rd32(hw, cq->sq.len);

				if (!(len & NSE_REG_AQM_QLEN_STAT_Q_EN_M)) {
					nse_debug(hw, NSE_DBG_SYS, "[%s] DONE: SW clear sq q_en, wait times=%d\n",
						  __func__, total_wait);
					break;
				}

				if (nse_is_regval_reset_magic(len) || hw->high_reset_ongoing) {
					nse_debug(hw, NSE_DBG_SYS, "[%s, %d] sq.len is: 0x%X or high_reset_ongoing = %d, maybe in reset, return early\n",
						  __func__, __LINE__, len,
							  hw->high_reset_ongoing);
					goto skip_sw_shutdown;
				}

				total_wait++;

			} while (total_wait < wait_timeout);

			len = rd32(hw, cq->sq.len);

			if (len & NSE_REG_AQM_QLEN_STAT_Q_EN_M) {
				if (cq->qtype == NSE_CTL_Q_ADMIN) {
					hw->controlq_stats.aq_sq_wait_for_sw_disable_fail_cnt++;
					hw->controlq_stats.aq_sq_wait_for_sw_disable_fail_time =
						ktime_to_ns(ktime_get());

					dev_info(dev,
					"WARN: timeout: SW clear aq_sq q_en, sq_len=0x%X\n", len);
					dev_info(dev, "\t now is: %ld ns\n",
								(unsigned long)hw->controlq_stats.aq_sq_wait_for_sw_disable_fail_time);
				} else if (cq->qtype == NSE_CTL_Q_MAILBOX) {
					hw->controlq_stats.mq_sq_wait_for_sw_disable_fail_cnt++;
					hw->controlq_stats.mq_sq_wait_for_sw_disable_fail_time =
						ktime_to_ns(ktime_get());

					dev_info(dev,
					"WARN: timeout: SW clear mq_sq q_en, sq_len=0x%X\n", len);
					dev_info(dev, "\t now is: %ld ns\n",
								(unsigned long)hw->controlq_stats.mq_sq_wait_for_sw_disable_fail_time);
				} else if (cq->qtype == NSE_CTL_Q_UTIL) {
					hw->controlq_stats.uq_sq_wait_for_sw_disable_fail_cnt++;
					hw->controlq_stats.uq_sq_wait_for_sw_disable_fail_time =
						ktime_to_ns(ktime_get());

					dev_info(dev,
					"WARN: timeout: SW clear uq_sq q_en, sq_len=0x%X\n", len);
					dev_info(dev, "\t now is: %ld ns\n",
								(unsigned long)hw->controlq_stats.uq_sq_wait_for_sw_disable_fail_time);
				}
			}
		}
	}

	/* Keep the queue register reset below from being reordered
	 * ahead of the SW disable sequence above.
	 */
	wmb();

	wr32(hw, cq->sq.len, 0);

	nse_flush(hw);

	wr32(hw, cq->sq.head, 0);

	wr32(hw, cq->sq.tail, 0);

skip_sw_shutdown:

	nse_aq_wait((100 * 1000), false);	/* 100 ms */

	cq->sq.count = 0;	/* to indicate uninitialized queue */

shutdown_sq_out:

	wr32(hw, cq->sq.bal, NSE_REG_AQM_BA_MAGIC_DEINIT);
	wr32(hw, cq->sq.bah, NSE_REG_AQM_BA_MAGIC_DEINIT);

	nse_aq_sq_unlock(cq);

	/* dealloc mem after unlock */
	if (dealloc_mem) {
		/* free ring buffers and the ring itself */
		NSE_FREE_CQ_BUFS(hw, cq, sq);
		nse_free_cq_ring(hw, &cq->sq);
	}

	nse_debug(hw, NSE_DBG_SYS, "[%s] - exit: ret=%d\n", __func__, ret_code);

	return ret_code;
}

/**
 * nse_shutdown_rq - shutdown Control ARQ
 * @hw: pointer to the hardware structure
 * @cq: pointer to the specific Control queue
 *
 * The main shutdown routine for the Control Receive Queue
 */
enum nse_status
nse_shutdown_rq(struct nse_hw *hw, struct nse_ctl_q_info *cq, unsigned int flags)
{
	struct device *dev = nse_hw_to_dev(hw);
	u32 len;
	u32 wait_timeout;
	u32 wait_timeout_tick = NSE_CTL_Q_SQ_CMD_USEC;
	u32 total_wait = 0;
	enum nse_status ret_code = 0;
	bool dealloc_mem = true;

	wait_timeout = (NSE_CTL_Q_SQ_CMD_TIMEOUT_BASE * nse_timeout_scale);

	nse_debug(hw, NSE_DBG_SYS, "[%s] - enter: wait_timeout=%d, wait_timeout_tick=%d, qtype=%d, flags=0x%X\n",
								__func__, wait_timeout,
									wait_timeout_tick,
									cq->qtype, flags);

	nse_aq_rq_lock(cq);

	if (!cq->rq.count) {
		dealloc_mem = false;
		ret_code = NSE_ERR_NOT_READY;
		goto shutdown_rq_out;
	}

	len = rd32(hw, cq->rq.len);
	if (nse_is_regval_reset_magic(len) || hw->high_reset_ongoing) {
		nse_debug(hw, NSE_DBG_SYS, "[%s, %d] rq.len is: 0x%X or high_reset_ongoing = %d, maybe in reset, return early\n",
			  __func__, __LINE__, len, hw->high_reset_ongoing);
		goto skip_sw_shutdown;
	}

	if (!(flags & NSE_SHUTDOWN_CTLQ_FLAG_WAIT_FW_SHUTDOWN))
		goto skip_wait_fw_shutdown;

	total_wait = 0;

	do {
		nse_aq_wait(wait_timeout_tick, !!nse_aq_rq_rx_method);

		len = rd32(hw, cq->rq.len);

		if (!(len & (NSE_REG_AQM_QLEN_STAT_Q_PAUSE_N_M | NSE_REG_AQM_QLEN_STAT_Q_EN_M)))
			break;

		if (nse_is_regval_reset_magic(len) || hw->high_reset_ongoing) {
			nse_debug(hw, NSE_DBG_SYS, "[%s, %d] rq.len is: 0x%X or high_reset_ongoing = %d, maybe in reset, return early\n",
				  __func__, __LINE__, len, hw->high_reset_ongoing);
			goto skip_sw_shutdown;
		}

		total_wait++;

	} while (total_wait < wait_timeout);

skip_wait_fw_shutdown:

	len = rd32(hw, cq->rq.len);

	if (len & (NSE_REG_AQM_QLEN_STAT_Q_PAUSE_N_M | NSE_REG_AQM_QLEN_STAT_Q_EN_M)) {
		if (cq->qtype == NSE_CTL_Q_ADMIN) {
			hw->controlq_stats.aq_rq_wait_for_fw_pause_disable_fail_cnt++;
			hw->controlq_stats.aq_rq_wait_for_fw_pause_disable_fail_time =
				ktime_to_ns(ktime_get());

			dev_info(dev, "WARN: aq_rq may not be paused + disabled in time by FW --- FW should do that by aq-cmd: NSE_AQ_OPC_Q_SHUTDOWN\n");
			dev_info(dev, "\t cmd: SHUTDOWN was sent at %ld ns, now is: %ld ns\n",
				 (unsigned long)hw->controlq_stats.aq_cmd_shutdown_time,
						(unsigned long)hw->controlq_stats.aq_rq_wait_for_fw_pause_disable_fail_time);
		} else if (cq->qtype == NSE_CTL_Q_MAILBOX) {
			hw->controlq_stats.mq_rq_wait_for_fw_pause_disable_fail_cnt++;
			hw->controlq_stats.mq_rq_wait_for_fw_pause_disable_fail_time =
				ktime_to_ns(ktime_get());

			dev_info(dev, "WARN: mq_rq may not be paused + disabled in time by FW --- FW should do that by aq-cmd: NSE_AQ_OPC_Q_SHUTDOWN\n");
			dev_info(dev, "\t cmd: SHUTDOWN was sent at %ld ns, now is: %ld ns\n",
				 (unsigned long)hw->controlq_stats.mq_cmd_shutdown_time,
						(unsigned long)hw->controlq_stats.mq_rq_wait_for_fw_pause_disable_fail_time);
		}

		dev_info(dev, "\t SW try pause + disable itself --- rq_len=0x%X\n", len);

		/* Keep the SW pause sequence below from being reordered ahead
		 * of the operations above.
		 */
		wmb();

		/* SW pause
		 */
		len = rd32(hw, cq->rq.len);

		if (len & NSE_REG_AQM_QLEN_STAT_Q_PAUSE_N_M) {
			len &= ~(NSE_REG_AQM_QLEN_STAT_BIT_M |
				 NSE_REG_AQM_QLEN_EXEC_M | NSE_REG_AQM_QLEN_OP_M);

			len |= ((NSE_CTLQ_STAT_BIT_IDX_Q_PAUSE_N << NSE_REG_AQM_QLEN_STAT_BIT_S) |
					NSE_REG_AQM_QLEN_EXEC_M |
					(NSE_REG_AQM_QLEN_OP_CLR_STAT << NSE_REG_AQM_QLEN_OP_S));

			wr32(hw, cq->rq.len, len);

			nse_flush(hw);

			total_wait = 0;

			do {
				nse_aq_wait(wait_timeout_tick, !!nse_aq_rq_rx_method);

				len = rd32(hw, cq->rq.len);

				if (!(len & NSE_REG_AQM_QLEN_STAT_Q_PAUSE_N_M)) {
					nse_debug(hw, NSE_DBG_SYS, "[%s] DONE: SW clear rq q_pause_n, wait times=%d\n",
						  __func__, total_wait);
					break;
				}

				if (nse_is_regval_reset_magic(len) || hw->high_reset_ongoing) {
					nse_debug(hw, NSE_DBG_SYS, "[%s, %d] rq.len is: 0x%X or high_reset_ongoing = %d, maybe in reset, return early\n",
						  __func__, __LINE__, len,
							  hw->high_reset_ongoing);
					goto skip_sw_shutdown;
				}

				total_wait++;

			} while (total_wait < wait_timeout);

			len = rd32(hw, cq->rq.len);

			if (len & NSE_REG_AQM_QLEN_STAT_Q_PAUSE_N_M) {
				if (cq->qtype == NSE_CTL_Q_ADMIN) {
					hw->controlq_stats.aq_rq_wait_for_sw_pause_fail_cnt++;
					hw->controlq_stats.aq_rq_wait_for_sw_pause_fail_time =
						ktime_to_ns(ktime_get());

					dev_info(dev,
				"WARN: timeout: SW clear aq_rq q_pause_n, rq_len=0x%X\n", len);
					dev_info(dev, "\t now is: %ld\n",
								(unsigned long)hw->controlq_stats.aq_rq_wait_for_sw_pause_fail_time);
				} else if (cq->qtype == NSE_CTL_Q_MAILBOX) {
					hw->controlq_stats.mq_rq_wait_for_sw_pause_fail_cnt++;
					hw->controlq_stats.mq_rq_wait_for_sw_pause_fail_time =
						ktime_to_ns(ktime_get());

					dev_info(dev,
				"WARN: timeout: SW clear mq_rq q_pause_n, rq_len=0x%X\n", len);
					dev_info(dev, "\t now is: %ld\n",
								(unsigned long)hw->controlq_stats.mq_rq_wait_for_sw_pause_fail_time);
				}
			}
		}

		/* Keep the SW disable sequence below from being reordered ahead
		 * of the SW pause above.
		 */
		wmb();

		/* SW disable
		 */
		len = rd32(hw, cq->rq.len);

		if (len & NSE_REG_AQM_QLEN_STAT_Q_EN_M) {
			len &= ~(NSE_REG_AQM_QLEN_STAT_BIT_M |
				 NSE_REG_AQM_QLEN_EXEC_M | NSE_REG_AQM_QLEN_OP_M);

			len |= ((NSE_CTLQ_STAT_BIT_IDX_Q_EN << NSE_REG_AQM_QLEN_STAT_BIT_S) |
					NSE_REG_AQM_QLEN_EXEC_M |
					(NSE_REG_AQM_QLEN_OP_CLR_STAT << NSE_REG_AQM_QLEN_OP_S));

			wr32(hw, cq->rq.len, len);

			nse_flush(hw);

			total_wait = 0;

			do {
				nse_aq_wait(wait_timeout_tick, !!nse_aq_rq_rx_method);

				len = rd32(hw, cq->rq.len);

				if (!(len & NSE_REG_AQM_QLEN_STAT_Q_EN_M)) {
					nse_debug(hw, NSE_DBG_SYS, "[%s] DONE: SW clear rq q_en, wait times=%d\n",
						  __func__, total_wait);
					break;
				}

				if (nse_is_regval_reset_magic(len) || hw->high_reset_ongoing) {
					nse_debug(hw, NSE_DBG_SYS, "[%s, %d] rq.len is: 0x%X or high_reset_ongoing = %d, maybe in reset, return early\n",
						  __func__, __LINE__, len,
							  hw->high_reset_ongoing);
					goto skip_sw_shutdown;
				}

				total_wait++;

			} while (total_wait < wait_timeout);

			len = rd32(hw, cq->rq.len);

			if (len & NSE_REG_AQM_QLEN_STAT_Q_EN_M) {
				if (cq->qtype == NSE_CTL_Q_ADMIN) {
					hw->controlq_stats.aq_rq_wait_for_sw_disable_fail_cnt++;
					hw->controlq_stats.aq_rq_wait_for_sw_disable_fail_time =
						ktime_to_ns(ktime_get());

					dev_info(dev,
					"WARN: timeout: SW clear aq_rq q_en, rq_len=0x%X\n", len);
					dev_info(dev, "\t now is: %ld\n",
								(unsigned long)hw->controlq_stats.aq_rq_wait_for_sw_disable_fail_time);
				} else if (cq->qtype == NSE_CTL_Q_MAILBOX) {
					hw->controlq_stats.mq_rq_wait_for_sw_disable_fail_cnt++;
					hw->controlq_stats.mq_rq_wait_for_sw_disable_fail_time =
						ktime_to_ns(ktime_get());

					dev_info(dev,
					"WARN: timeout: SW clear mq_rq q_en, rq_len=0x%X\n", len);
					dev_info(dev, "\t now is: %ld\n",
								(unsigned long)hw->controlq_stats.mq_rq_wait_for_sw_disable_fail_time);
				}
			}
		}
	}

	/* Keep the queue register reset below from being reordered
	 * ahead of the SW disable sequence above.
	 */
	wmb();

	wr32(hw, cq->rq.len, 0);

	nse_flush(hw);

	wr32(hw, cq->rq.head, 0);

	wr32(hw, cq->rq.tail, 0);

skip_sw_shutdown:

	nse_aq_wait((100 * 1000), !!nse_aq_rq_rx_method);	/* 100 ms */

	/* set rq.count to 0 to indicate uninitialized queue */
	cq->rq.count = 0;

shutdown_rq_out:

	wr32(hw, cq->rq.bal, NSE_REG_AQM_BA_MAGIC_DEINIT);
	wr32(hw, cq->rq.bah, NSE_REG_AQM_BA_MAGIC_DEINIT);

	nse_aq_rq_unlock(cq);

	/* dealloc mem after unlock */
	if (dealloc_mem) {
		/* free ring buffers and the ring itself */
		NSE_FREE_CQ_BUFS(hw, cq, rq);
		nse_free_cq_ring(hw, &cq->rq);
	}

	nse_debug(hw, NSE_DBG_SYS, "[%s] - exit: ret=%d\n", __func__, ret_code);

	return ret_code;
}

static void shutdown_vsi_aqm_rq_or_sq(struct nse_hw *hw, u16 vsi_rel_id,
				      u32 qlen_reg, u32 qbal, const char *qname)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct device *dev = nse_pf_to_dev(pf);
	unsigned int reset_wait_flags;
	u32 len;
	u32 wait_timeout = 100;	/* don't wait NSE_CTL_Q_SQ_CMD_TIMEOUT(1000 times ) that many */
	/* don't wait NSE_CTL_Q_SQ_CMD_USEC (1000 usec) that long interval */
	u32 wait_timeout_tick = 10;
	u32 total_wait = 0;

	if (hw->high_reset_ongoing) {
		nse_debug(hw, NSE_DBG_SYS,
			  "[%s, %d] high_reset_ongoing=true, wait for its complete\n",
			__func__, __LINE__);

		reset_wait_flags = (NSE_RESET_WAIT_FLAG_WAIT_FWMNG |
				    NSE_RESET_WAIT_FLAG_WAIT_FRTRIG);

		/* must wait for FW/HW cleanup completely */
		(void)nse_reset_wait_complete(hw, false, reset_wait_flags);

		goto clear;
	}

	len = rd32(hw, qlen_reg);
	if (!(len & (NSE_REG_AQM_QLEN_STAT_Q_PAUSE_N_M | NSE_REG_AQM_QLEN_STAT_Q_EN_M)))
		goto clear;

	/* clear q_pause_n */
	if (len & NSE_REG_AQM_QLEN_STAT_Q_PAUSE_N_M) {
		len &= ~(NSE_REG_AQM_QLEN_STAT_BIT_M |
			 NSE_REG_AQM_QLEN_EXEC_M | NSE_REG_AQM_QLEN_OP_M);

		len |= ((NSE_CTLQ_STAT_BIT_IDX_Q_PAUSE_N << NSE_REG_AQM_QLEN_STAT_BIT_S) |
				NSE_REG_AQM_QLEN_EXEC_M |
				(NSE_REG_AQM_QLEN_OP_CLR_STAT << NSE_REG_AQM_QLEN_OP_S));

		wr32(hw, qlen_reg, len);

		nse_flush(hw);

		total_wait = 0;

		do {
			len = rd32(hw, qlen_reg);

			if (!(len & NSE_REG_AQM_QLEN_STAT_Q_PAUSE_N_M)) {
				nse_debug(hw, NSE_DBG_SYS, "[%s] DONE: SW clear Q_PAUSE_N - VSI(rel_id=%d) qname: %s, wait times=%d\n",
					  __func__, vsi_rel_id, qname, total_wait);
				break;
			}

			if (nse_is_regval_reset_magic(len) || hw->high_reset_ongoing) {
				nse_debug(hw, NSE_DBG_SYS, "[%s, %d] q.len is: 0x%X or high_reset_ongoing = %d, maybe in reset, return early\n",
					  __func__, __LINE__, len, hw->high_reset_ongoing);
				goto clear;
			}

			nse_aq_wait(wait_timeout_tick, false);

			total_wait++;

		} while (total_wait < wait_timeout);

		if (total_wait >= wait_timeout)
			dev_info(dev, "[%s]: timeout: SW clear Q_PAUSE_N - VSI(rel_id=%d) qname: %s,qlen=0x%X\n",
										__func__,
											vsi_rel_id,
											qname, len);
	}

	/* clear q_en */
	len = rd32(hw, qlen_reg);

	if (len & NSE_REG_AQM_QLEN_STAT_Q_EN_M) {
		len &= ~(NSE_REG_AQM_QLEN_STAT_BIT_M |
			 NSE_REG_AQM_QLEN_EXEC_M | NSE_REG_AQM_QLEN_OP_M);

		len |= ((NSE_CTLQ_STAT_BIT_IDX_Q_EN << NSE_REG_AQM_QLEN_STAT_BIT_S) |
				NSE_REG_AQM_QLEN_EXEC_M |
				(NSE_REG_AQM_QLEN_OP_CLR_STAT << NSE_REG_AQM_QLEN_OP_S));

		wr32(hw, qlen_reg, len);

		nse_flush(hw);

		total_wait = 0;

		do {
			len = rd32(hw, qlen_reg);

			if (!(len & NSE_REG_AQM_QLEN_STAT_Q_EN_M)) {
				nse_debug(hw, NSE_DBG_SYS, "[%s] DONE: SW clear Q_EN - VSI(rel_id=%d) qname: %s, wait times=%d\n",
					  __func__, vsi_rel_id, qname, total_wait);

				break;
			}

			if (nse_is_regval_reset_magic(len) || hw->high_reset_ongoing) {
				nse_debug(hw, NSE_DBG_SYS, "[%s, %d] q.len is: 0x%X or high_reset_ongoing = %d, maybe in reset, return early\n",
					  __func__, __LINE__, len, hw->high_reset_ongoing);
				goto clear;
			}

			nse_aq_wait(wait_timeout_tick, false);

			total_wait++;

		} while (total_wait < wait_timeout);

		if (total_wait >= wait_timeout)
			dev_info(dev, "[%s]: timeout: SW clear Q_EN - VSI(rel_id=%d) qname: %s, qlen=0x%X\n",
										__func__,
											vsi_rel_id,
											qname, len);
	}

clear:	/* clear the whole len register (including length field), anyway */

	wr32(hw, qlen_reg, 0);
	/* later PF drv must set it to be NSE_REG_VMBX_ARQBAL_MAGIC_PF_INIT */
	wr32(hw, qbal, NSE_REG_AQM_BA_MAGIC_DEINIT);
}

/* not using aq-cmd, but from BAR, shutdown VSI VMBXQ RQ and SQ:
 *
 *			clear QLEN register: q_pause_n and q_en bits
 *
 *			reset the QLEN register to 0 (mainly for length field)
 */
void nse_shutdown_vsi_mbxq(struct nse_hw *hw, u16 vsi_rel_id)
{
	nse_debug(hw, NSE_DBG_SYS, "[%s] vsi_rel_id=%d", __func__, vsi_rel_id);

	shutdown_vsi_aqm_rq_or_sq(hw, vsi_rel_id,
							NSE_REG_VMBX_ARQLEN(vsi_rel_id),
								NSE_REG_VMBX_ARQBAL(vsi_rel_id),
							"VSI-VMBXQ-RQ");

	shutdown_vsi_aqm_rq_or_sq(hw, vsi_rel_id,
							NSE_REG_VMBX_ATQLEN(vsi_rel_id),
								NSE_REG_VMBX_ATQBAL(vsi_rel_id),
							"VSI-VMBXQ-TQ");
}

void nse_shutdown_vsi_utilq(struct nse_hw *hw, u16 vsi_rel_id)
{
	nse_debug(hw, NSE_DBG_SYS, "[%s] vsi_rel_id=%d", __func__, vsi_rel_id);

	shutdown_vsi_aqm_rq_or_sq(hw, vsi_rel_id,
							NSE_REG_UTI_ATQLEN(vsi_rel_id),
								NSE_REG_UTI_ATQBAL(vsi_rel_id),
							"VSI-UTILQ-TQ");
}

/**
 * nse_aq_ver_check - Check if SW and FW's version can be work right together.
 * @hw: pointer to the hardware structure
 *
 * This function should be called only after nse_aq_xchg_sw_fw_ver()
 */
static bool nse_aq_ver_check(struct nse_hw *hw)
{
	/* check if FW refuse us */
	if (hw->refused_by_fw)
		return false;

	/* now check if we refuse FW, by SW / FW version
	 *
	 * but now, we don't refuse at all.
	 */

	return true;
}

/**
 * nse_init_check_adminq - Check version for Admin Queue to know if its alive
 * @hw: pointer to the hardware structure
 */
static enum nse_status nse_init_check_adminq(struct nse_hw *hw)
{
	enum nse_status status;

	status = nse_aq_xchg_sw_fw_ver(hw);
	if (status) {
		dev_err(nse_hw_to_dev(hw), "nse_aq_xchg_sw_fw_ver() fail: %d (%s)\n",
					status, nse_stat_str(status));
		goto init_ctrlq_free_rq;
	}

	if (!nse_aq_ver_check(hw)) {
		status = NSE_ERR_FW_API_VER;
		dev_err(nse_hw_to_dev(hw), "nse_aq_ver_check() fail: %d (%s)\n",
					status, nse_stat_str(status));
		goto init_ctrlq_free_rq;
	}

	return 0;

init_ctrlq_free_rq:
	nse_shutdown_ctrlq(hw, NSE_CTL_Q_ADMIN, false);
	return status;
}

/**
 * nse_init_ctrlq - main initialization routine for any control Queue
 * @hw: pointer to the hardware structure
 * @q_type: specific Control queue type
 *
 * Prior to calling this function, the driver *MUST* set the following fields
 * in the cq->structure:
 *     - cq->num_sq_entries
 *     - cq->num_rq_entries
 *     - cq->rq_buf_size
 *     - cq->sq_buf_size
 * Which is already done in nse_set_ctrlq_len()
 *
 * NOTE: this function does not initialize the controlq locks
 */
static enum nse_status nse_init_ctrlq(struct nse_hw *hw, enum nse_ctl_q q_type)
{
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_ctl_q_info *cq;
	enum nse_status ret_code;

	switch (q_type) {
	case NSE_CTL_Q_ADMIN:
		nse_adminq_init_regs(hw);
		nse_adminq_write_context(hw, 0, false, hw->pcore_pf_id);
		cq = &hw->adminq;
		break;
	case NSE_CTL_Q_MAILBOX:		/* xzhao: use adminq to acchieve mailboxq */
	case NSE_CTL_Q_UTIL:
	default:
		return NSE_ERR_PARAM;
	}
	cq->qtype = q_type;

	/* verify input for valid configuration */
	if (!cq->num_rq_entries || !cq->num_sq_entries ||
	    !cq->rq_buf_size || !cq->sq_buf_size) {
		return NSE_ERR_CFG;
	}

	/* setup SQ command write back timeout */
	cq->sq_cmd_timeout = (NSE_CTL_Q_SQ_CMD_TIMEOUT_BASE * nse_timeout_scale);

	/* allocate the ATQ */
	ret_code = nse_init_sq(hw, cq);
	if (ret_code) {
		dev_err(dev, "nse_init_sq() fail: %d (%s)\n",
						ret_code, nse_stat_str(ret_code));
		return ret_code;
	}

	/* allocate the ARQ */
	ret_code = nse_init_rq(hw, cq);
	if (ret_code) {
		dev_err(dev, "nse_init_rq() fail: %d (%s)\n",
						ret_code, nse_stat_str(ret_code));
		goto init_ctrlq_free_sq;
	}

	/* success! */
	return 0;

init_ctrlq_free_sq:
	(void)nse_shutdown_sq(hw, cq, 0);
	return ret_code;
}

/**
 * nse_shutdown_ctrlq - shutdown routine for any control queue
 * @hw: pointer to the hardware structure
 * @q_type: specific Control queue type
 *
 * NOTE: this function does not destroy the control queue locks.
 */
void nse_shutdown_ctrlq(struct nse_hw *hw, enum nse_ctl_q q_type, bool drv_unloading)
{
	struct nse_ctl_q_info *cq;
	bool adminq_sq_alive = false;

	switch (q_type) {
	case NSE_CTL_Q_ADMIN:
		cq = &hw->adminq;

		adminq_sq_alive = nse_check_sq_alive(hw, cq, NULL);

		nse_debug(hw, NSE_DBG_SYS, "[%s] qtype=%d, adminq_sq_alive=%d\n",
			  __func__, q_type, adminq_sq_alive);

		/* Order the adminq shutdown below after the aliveness check above. */
		wmb();

		if (adminq_sq_alive)
			(void)nse_aq_adminq_shutdown(hw, drv_unloading);
		break;
	case NSE_CTL_Q_MAILBOX:		/* xzhao: use adminq to acchieve mailboxq */
	/* utilq is handled using nse_fdir_shutdown_utilq() because it only have sq, no rq */
	case NSE_CTL_Q_UTIL:
	default:
		return;
	}

	/* Order the queue shutdown below after the adminq shutdown above. */
	wmb();

	(void)nse_shutdown_sq(hw, cq, adminq_sq_alive ?
			      NSE_SHUTDOWN_CTLQ_FLAG_WAIT_FW_SHUTDOWN : 0);
	(void)nse_shutdown_rq(hw, cq, adminq_sq_alive ?
			      NSE_SHUTDOWN_CTLQ_FLAG_WAIT_FW_SHUTDOWN : 0);
}

/**
 * nse_shutdown_all_ctrlq - shutdown routine for all control queues
 * @hw: pointer to the hardware structure
 *
 * NOTE: this function does not destroy the control queue locks. The driver
 * may call this at runtime to shutdown and later restart control queues, such
 * as in response to a reset event.
 */
void nse_shutdown_all_ctrlq(struct nse_hw *hw, bool drv_unloading)
{
	/* Shutdown FW admin queue */
	nse_shutdown_ctrlq(hw, NSE_CTL_Q_ADMIN, drv_unloading);
}

/**
 * nse_init_all_ctrlq - main initialization routine for all control queues
 * @hw: pointer to the hardware structure
 *
 * Prior to calling this function, the driver MUST* set the following fields
 * in the cq->structure for all control queues:
 *     - cq->num_sq_entries
 *     - cq->num_rq_entries
 *     - cq->rq_buf_size
 *     - cq->sq_buf_size
 * Which is already done in nse_set_ctrlq_len()
 *
 * NOTE: this function does not initialize the controlq locks.
 */
enum nse_status nse_init_all_ctrlq(struct nse_hw *hw)
{
	struct device *dev = nse_hw_to_dev(hw);
	enum nse_status status;
	u32 retry = 0;

	/* Init FW admin queue */
	do {
		status = nse_init_ctrlq(hw, NSE_CTL_Q_ADMIN);
		if (status) {
			dev_err(dev, "nse_init_ctrlq( adminq ) fail: %d (%s)\n",
								status, nse_stat_str(status));
			return status;
		}

		status = nse_init_check_adminq(hw);
		if (status != NSE_ERR_AQ_FW_CRITICAL)
			break;

		dev_info(dev, "Retry Admin Queue init due to FW critical error\n");
		nse_shutdown_ctrlq(hw, NSE_CTL_Q_ADMIN, false);
		msleep(NSE_CTL_Q_ADMIN_INIT_MSEC);
	} while (retry++ < NSE_CTL_Q_ADMIN_INIT_TIMEOUT);

	return status;
}

/**
 * nse_init_ctrlq_locks - Initialize locks for a control queue
 * @cq: pointer to the control queue
 *
 * Initializes the send and receive queue locks for a given control queue.
 */
static void nse_init_ctrlq_locks(struct nse_ctl_q_info *cq)
{
	mutex_init(&cq->sq_lock);

	if (nse_aq_rq_rx_method)
		spin_lock_init(&cq->rq_lock.spl);
	else
		mutex_init(&cq->rq_lock.mtx);

	INIT_LIST_HEAD(&cq->rq_evt_list);
	spin_lock_init(&cq->rq_evt_list_lock);
}

/**
 * nse_create_all_ctrlq - main initialization routine for all control queues
 * @hw: pointer to the hardware structure
 *
 * Prior to calling this function, the driver *MUST* set the following fields
 * in the cq->structure for all control queues:
 *     - cq->num_sq_entries
 *     - cq->num_rq_entries
 *     - cq->rq_buf_size
 *     - cq->sq_buf_size
 * Which is already done in nse_set_ctrlq_len()
 *
 * This function creates all the control queue locks and then calls
 * nse_init_all_ctrlq. It should be called once during driver load. If the
 * driver needs to re-initialize control queues at run time it should call
 * nse_init_all_ctrlq instead.
 */
enum nse_status nse_create_all_ctrlq(struct nse_hw *hw)
{
	nse_init_ctrlq_locks(&hw->adminq);

	/* no better place to init utilq mutex */
	nse_init_ctrlq_locks(&hw->fdir_cb.utilq);

	return nse_init_all_ctrlq(hw);
}

/**
 * nse_destroy_ctrlq_locks - Destroy locks for a control queue
 * @cq: pointer to the control queue
 *
 * Destroys the send and receive queue locks for a given control queue.
 */
static void nse_destroy_ctrlq_locks(struct nse_ctl_q_info *cq)
{
	mutex_destroy(&cq->sq_lock);

	if (!nse_aq_rq_rx_method)
		mutex_destroy(&cq->rq_lock.mtx);
}

/**
 * nse_destroy_all_ctrlq - exit routine for all control queues
 * @hw: pointer to the hardware structure
 *
 * This function shuts down all the control queues and then destroys the
 * control queue locks. It should be called once during driver unload. The
 * driver should call nse_shutdown_all_ctrlq if it needs to shut down and
 * reinitialize control queues, such as in response to a reset event.
 */
void nse_destroy_all_ctrlq(struct nse_hw *hw, bool drv_unloading)
{
	/* shut down all the control queues first */
	nse_shutdown_all_ctrlq(hw, drv_unloading);

	nse_destroy_ctrlq_locks(&hw->adminq);

	/* no better place to destroy utilq mutex */
	nse_destroy_ctrlq_locks(&hw->fdir_cb.utilq);
}

/**
 * nse_clean_sq - cleans Admin send queue (ATQ)
 * @hw: pointer to the hardware structure
 * @cq: pointer to the specific Control queue
 *
 * returns the number of free desc
 */
static u16 nse_clean_sq(struct nse_hw *hw, struct nse_ctl_q_info *cq)
{
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_ctl_q_ring *sq = &cq->sq;
	u16 ntc = sq->next_to_clean;
	struct nse_sq_cd *details;
	struct nse_aq_desc *desc;
	u16 head_val;

	desc = NSE_CTL_Q_DESC(*sq, ntc);
	details = NSE_CTL_Q_DETAILS(*sq, ntc);

	while ((head_val = rd32(hw, cq->sq.head)) != ntc) {
		if (head_val >= cq->num_sq_entries || nse_is_regval_reset_magic(head_val)) {
			dev_err(dev, "[%s, %d] head overrun at: %d (%X) or reset detected in the Control Send Queue ring\n",
							__func__, __LINE__,
							head_val, head_val);
			break;
		}

		memset(desc, 0, sizeof(*desc));
		memset(details, 0, sizeof(*details));
		ntc++;
		if (ntc == sq->count)
			ntc = 0;
		desc = NSE_CTL_Q_DESC(*sq, ntc);
		details = NSE_CTL_Q_DETAILS(*sq, ntc);
	}

	sq->next_to_clean = ntc;

	return NSE_CTL_Q_DESC_UNUSED(sq);
}

/**
 * nse_clean_sq_by_dd - cleans Admin send queue (ATQ)
 * @hw: pointer to the hardware structure
 * @cq: pointer to the specific Control queue
 *
 * returns the number of free desc
 */
static u16 nse_clean_sq_by_dd(struct nse_hw *hw, struct nse_ctl_q_info *cq)
{
	struct nse_ctl_q_ring *sq = &cq->sq;
	u16 ntc = sq->next_to_clean;
	struct nse_sq_cd *details;
	struct nse_aq_desc *desc;

	desc = NSE_CTL_Q_DESC(*sq, ntc);
	details = NSE_CTL_Q_DETAILS(*sq, ntc);

	while (1) {
		if (le16_to_cpu(desc->flags) & NSE_AQ_FLAG_DD) {
			memset(desc, 0, sizeof(*desc));
			memset(details, 0, sizeof(*details));
			ntc++;
			if (ntc == sq->count)
				ntc = 0;
			desc = NSE_CTL_Q_DESC(*sq, ntc);
			details = NSE_CTL_Q_DETAILS(*sq, ntc);
		} else {	/* !DD */
			break;
		}
	}

	sq->next_to_clean = ntc;

	return NSE_CTL_Q_DESC_UNUSED(sq);
}

/**
 * nse_debug_cq
 * @hw: pointer to the hardware structure
 * @desc: pointer to control queue descriptor
 * @buf: pointer to command buffer
 * @buf_len: max length of buf
 *
 * Dumps debug log about control command with descriptor contents.
 */
static void nse_debug_cq(struct nse_hw *hw, void *desc, void *buf, u16 buf_len)
{
	struct nse_aq_desc *cq_desc = desc;
	u16 datalen, flags;

	if (!((NSE_DBG_AQM_DESC | NSE_DBG_AQM_BUF) & hw->debug_mask))
		return;

	if (!desc)
		return;

	datalen = le16_to_cpu(cq_desc->datalen);
	flags = le16_to_cpu(cq_desc->flags);

	nse_debug(hw, NSE_DBG_AQM_DESC, "CQ CMD: opcode 0x%04X, flags 0x%04X, datalen 0x%04X, retval 0x%04X\n",
		  le16_to_cpu(cq_desc->opcode), (flags & ~NSE_AQ_FLAG_RETVAL_M), datalen,
		 ((flags & NSE_AQ_FLAG_RETVAL_M) >> NSE_AQ_FLAG_RETVAL_S));
	nse_debug(hw, NSE_DBG_AQM_DESC, "\t param (0,1)  0x%08X 0x%08X\n",
		  le32_to_cpu(cq_desc->param0),
		  le32_to_cpu(cq_desc->param1));
	nse_debug(hw, NSE_DBG_AQM_DESC, "\t addr (h,l)   0x%08X 0x%08X\n",
		  le32_to_cpu(cq_desc->addr_high),
		  le32_to_cpu(cq_desc->addr_low));
	/* Dump buffer iff 1) one exists and 2) is either a response indicated
	 * by the DD and/or CMP flag set or a command with the RD flag set.
	 */
	if (buf && cq_desc->datalen != 0 &&
	    (flags & NSE_AQ_FLAG_DD || flags & NSE_AQ_FLAG_RD)) {
		nse_debug(hw, NSE_DBG_AQM_BUF, "Buffer:\n");
		nse_debug_array(hw, NSE_DBG_AQM_BUF, 16, 1, buf,
				min_t(u16, buf_len, datalen));
	}
}

/**
 * nse_sq_done - check if FW has processed the Admin Send Queue (ATQ)
 * @hw: pointer to the HW struct
 * @cq: pointer to the specific Control queue
 *
 * Returns true if the firmware has processed all descriptors on the
 * admin send queue. Returns false if there are still requests pending.
 */
static bool nse_sq_done(struct nse_hw *hw, struct nse_ctl_q_info *cq,
			struct nse_aq_desc *desc_on_ring)
{
	if (nse_aq_cmd_check_dd)
		return (le16_to_cpu(desc_on_ring->flags) & NSE_AQ_FLAG_DD);
	else
		return rd32(hw, cq->sq.head) == cq->sq.next_to_use;
}

static bool nse_sq_send_cmd_detect_reset_in_wait(struct nse_hw *hw, struct nse_ctl_q_info *cq)
{
	u32 sq_len_val = 0;

	if (hw->high_reset_ongoing) {
		nse_debug(hw, NSE_DBG_SYS, "[%s, %d] high_reset_ongoing = true\n",
			  __func__, __LINE__);
		goto detect;
	}

	if (!nse_check_sq_alive(hw, cq, &sq_len_val)) {
		nse_debug(hw, NSE_DBG_SYS, "[%s, %d] sq_alive() = false, sq_len=%X\n",
			  __func__, __LINE__, sq_len_val);
		goto detect;
	}

	return false;

detect:
	return true;
}

/**
 * nse_sq_send_cmd_nolock - send command to Control Queue (ATQ)
 * @hw: pointer to the HW struct
 * @cq: pointer to the specific Control queue
 * @desc: prefilled descriptor describing the command (non DMA mem)
 * @buf: buffer to use for indirect commands (or NULL for direct commands)
 * @buf_size: size of buffer for indirect commands (or 0 for direct commands)
 * @cd: pointer to command details structure
 *
 * This is the main send command routine for the ATQ. It runs the queue,
 * cleans the queue, etc.
 */
enum nse_status
nse_sq_send_cmd_nolock(struct nse_hw *hw, struct nse_ctl_q_info *cq,
		       struct nse_aq_desc *desc, void *buf, u16 buf_size,
		       struct nse_sq_cd *cd, unsigned int sq_send_cmd_flags)
{
	struct device *dev = nse_hw_to_dev(hw);
	struct nse_dma_mem *dma_buf = NULL;
	struct nse_aq_desc *desc_on_ring;
	bool cmd_completed = false;
	enum nse_status status = 0;
	struct nse_sq_cd *details;
	u32 total_delay;
	u8 retval = 0;
	u32 val = 0;
	u16 free_slot;
	u32 sq_cmd_timeout;
	u32 sq_cmd_timeout_tick = NSE_CTL_Q_SQ_CMD_USEC;
	u64 pre_ns, post_ns, delta_ns = 0;
	bool no_wait = false;

	nse_debug(hw, NSE_DBG_AQM_MSG, "[%s, %d] 1 - send aq-cmd: opcode(%X, category=%X, subcode=%X)\n",
						__func__, __LINE__,
						le16_to_cpu(desc->opcode),
						desc->opc_category, desc->opc_subcode);

	if (sq_send_cmd_flags & NSE_CTLQ_SQ_SEND_CMD_FLAG_NO_WAIT)
		no_wait = true;

	if (nse_sq_cmd_is_no_wait(desc->opc_category, desc->opc_subcode))
		no_wait = true;

	/* if reset is in progress return a soft error */
	if (hw->high_reset_ongoing)
		return NSE_SUCCESS;

	sq_cmd_timeout = (NSE_CTL_Q_SQ_CMD_TIMEOUT_BASE * nse_timeout_scale);

	pre_ns = ktime_to_ns(ktime_get());

	cq->sq_last_status = NSE_AQ_RC_OK;

	if (!cq->sq.count) {
		dev_err(dev, "Control Send queue not initialized.\n");
		status = NSE_ERR_AQ_EMPTY;
		goto sq_send_command_error;
	}

	if ((buf && !buf_size) || (!buf && buf_size)) {
		status = NSE_ERR_PARAM;
		goto sq_send_command_error;
	}

	if (buf) {
		if (buf_size > cq->sq_buf_size) {
			dev_err(dev, "Invalid buffer size for Control Send queue: %d.\n",
				  buf_size);
			status = NSE_ERR_INVAL_SIZE;
			goto sq_send_command_error;
		}

		desc->flags |= cpu_to_le16(NSE_AQ_FLAG_RD);
		desc->flags |= cpu_to_le16(NSE_AQ_FLAG_BUF);
		if (buf_size > NSE_AQ_LG_BUF)
			desc->flags |= cpu_to_le16(NSE_AQ_FLAG_LB);
	}

	val = rd32(hw, cq->sq.head);

	if (nse_is_regval_reset_magic(val)) {
		nse_debug(hw, NSE_DBG_SYS,
			  "[%s, %d] sq.head is reset magic: 0x%X, maybe in reset, return early\n",
			__func__, __LINE__, val);
		status = NSE_ERR_AQ_EMPTY;
		goto sq_send_command_error;
	}

	if (val >= cq->num_sq_entries) {
		dev_err(dev, "[%s, %d] head overrun at: %d (%X) in the Control Send Queue ring\n",
						__func__, __LINE__,
						val, val);
		status = NSE_ERR_AQ_EMPTY;
		goto sq_send_command_error;
	}

	details = NSE_CTL_Q_DETAILS(cq->sq, cq->sq.next_to_use);
	if (cd)
		*details = *cd;
	else
		memset(details, 0, sizeof(*details));

	/* Call clean and check queue available function to reclaim the
	 * descriptors that were processed by FW/MBX; the function returns the
	 * number of desc available. The clean function called here could be
	 * called in a separate thread in case of asynchronous completions.
	 */
	if (nse_aq_cmd_check_dd)
		free_slot = nse_clean_sq_by_dd(hw, cq);
	else
		free_slot = nse_clean_sq(hw, cq);

	if (free_slot == 0) {
		dev_err(dev, "Error: Control Send Queue is full.\n");
		status = NSE_ERR_AQ_FULL;
		goto sq_send_command_error;
	}

	/* initialize the temp desc pointer with the right desc */
	desc_on_ring = NSE_CTL_Q_DESC(cq->sq, cq->sq.next_to_use);

	/* if the desc is available copy the temp desc to the right place */
	memcpy(desc_on_ring, desc, sizeof(*desc_on_ring));

	/* if buf is not NULL assume indirect command */
	if (buf) {
		dma_buf = &cq->sq.r.sq_bi[cq->sq.next_to_use];
		/* copy the user buf into the respective DMA buf */
		memcpy(dma_buf->va, buf, buf_size);
		desc_on_ring->datalen = cpu_to_le16(buf_size);

		/* Update the address values in the desc with the pa value
		 * for respective buffer
		 */
		desc_on_ring->addr_high =
			cpu_to_le32(upper_32_bits(dma_buf->pa));
		desc_on_ring->addr_low =
			cpu_to_le32(lower_32_bits(dma_buf->pa));
	}

	/* Debug desc and buffer */
	nse_debug(hw, NSE_DBG_AQM_MSG, "[%s, %d] 2 - send aq-cmd: opcode(%X, category=%X, subcode=%X)\n",
						__func__, __LINE__,
						le16_to_cpu(desc_on_ring->opcode),
						desc_on_ring->opc_category,
							desc_on_ring->opc_subcode);

	nse_debug(hw, NSE_DBG_AQM_DESC, "ATQ: Control Send queue desc and buffer:\n");

	nse_debug_cq(hw, (void *)desc_on_ring, buf, buf_size);

	/* check again before actually write SQ TAIL */
	if (hw->high_reset_ongoing)
		goto sq_send_command_error;	/* status = 0 */

	(cq->sq.next_to_use)++;
	if (cq->sq.next_to_use == cq->sq.count)
		cq->sq.next_to_use = 0;
	wr32(hw, cq->sq.tail, cq->sq.next_to_use);

	if (no_wait)
		goto skip_wait;

	total_delay = 1;

	do {
		nse_aq_wait(sq_cmd_timeout_tick, false);

		if (nse_sq_done(hw, cq, desc_on_ring))
			break;

		/* detect every 16 wait, not every wait, not too often */
		if (!(total_delay & 0xF) &&
			nse_sq_send_cmd_detect_reset_in_wait(hw, cq)) {
			nse_debug(hw, NSE_DBG_SYS,
				  "[%s, %d] detect_reset_in_wait() = true, quick exit wait\n",
				__func__, __LINE__);

			if (hw->high_reset_ongoing)		/* status = 0 */
				status = NSE_SUCCESS;
			else
				status = NSE_ERR_AQ_EMPTY;

			goto sq_send_command_error;
		}

		total_delay++;
	} while (total_delay < sq_cmd_timeout);

skip_wait:

	/* if ready, copy the desc back to temp */
	if (nse_sq_done(hw, cq, desc_on_ring)) {
		memcpy(desc, desc_on_ring, sizeof(*desc));
		if (buf) {
			/* get returned length to copy */
			u16 copy_size = le16_to_cpu(desc->datalen);

			if (copy_size > buf_size) {
				dev_err(dev, "Return len %d > than buf len %d\n",
					  copy_size, buf_size);
				status = NSE_ERR_AQ_ERROR;
			} else {
				memcpy(buf, dma_buf->va, copy_size);
			}
		}
		retval = (le16_to_cpu(desc->flags) & NSE_AQ_FLAG_RETVAL_M) >> NSE_AQ_FLAG_RETVAL_S;
		if (retval) {
			dev_err(dev, "[%s, %d] Control Send Queue command: 0x%04X, completed write-back with desc->RETVAL=0x%X (%s)\n",
						__func__, __LINE__,
						le16_to_cpu(desc->opcode), retval,
							nse_aq_str((enum nse_aq_err)retval));
		}
		cmd_completed = true;
		if (!status && retval != NSE_AQ_RC_OK)
			status = NSE_ERR_AQ_ERROR;
		cq->sq_last_status = (enum nse_aq_err)retval;
	}

	nse_debug(hw, NSE_DBG_AQM_DESC, "ATQ: desc and buffer writeback:\n");

	nse_debug_cq(hw, (void *)desc, buf, buf_size);

	/* save writeback AQ if requested */
	if (details->wb_desc)
		memcpy(details->wb_desc, desc_on_ring,
		       sizeof(*details->wb_desc));

	/* update the error if time out occurred */
	if (!cmd_completed && !no_wait) {
		if (rd32(hw, cq->rq.len) & cq->rq.len_crit_mask ||
		    rd32(hw, cq->sq.len) & cq->sq.len_crit_mask) {
			dev_err(dev, "[%s, %d] Critical FW error.\n", __func__, __LINE__);
			status = NSE_ERR_AQ_FW_CRITICAL;
		} else {
			dev_err(dev, "[%s, %d] Control Send Queue Writeback timeout.\n",
				__func__, __LINE__);
			dev_err(dev, "    sq: HEAD=%X, TAIL=%X\n",
							rd32(hw, cq->sq.head),
								rd32(hw, cq->sq.tail));
			status = NSE_ERR_AQ_TIMEOUT;
		}
	}

sq_send_command_error:

	/* record some stats for debugfs display */
	post_ns = ktime_to_ns(ktime_get());
	if (post_ns > pre_ns)
		delta_ns = post_ns - pre_ns;

	hw->controlq_stats.sq_total_cnt++;
	hw->controlq_stats.sq_total_ns += delta_ns;

	if (status == NSE_SUCCESS) {
		hw->controlq_stats.sq_success_cnt++;
		hw->controlq_stats.sq_success_ns += delta_ns;
	} else {
		hw->controlq_stats.sq_fail_cnt++;
		hw->controlq_stats.sq_fail_ns += delta_ns;

		if (status == NSE_ERR_AQ_TIMEOUT) {
			hw->controlq_stats.sq_fail_timeout_cnt++;
			hw->controlq_stats.sq_fail_timeout_ns += delta_ns;
		}
	}

	return status;
}

/**
 * nse_sq_send_cmd - send command to Control Queue (ATQ)
 * @hw: pointer to the HW struct
 * @cq: pointer to the specific Control queue
 * @desc: prefilled descriptor describing the command
 * @buf: buffer to use for indirect commands (or NULL for direct commands)
 * @buf_size: size of buffer for indirect commands (or 0 for direct commands)
 * @cd: pointer to command details structure
 *
 * This is the main send command routine for the ATQ. It runs the queue,
 * cleans the queue, etc.
 */
enum nse_status
nse_sq_send_cmd(struct nse_hw *hw, struct nse_ctl_q_info *cq,
		struct nse_aq_desc *desc, void *buf, u16 buf_size,
		struct nse_sq_cd *cd)
{
	enum nse_status status = 0;

	if (hw->high_reset_ongoing)
		return NSE_SUCCESS;

	nse_aq_sq_lock(cq);
	status = nse_sq_send_cmd_nolock(hw, cq, desc, buf, buf_size, cd, 0);
	nse_aq_sq_unlock(cq);

	return status;
}

enum nse_status
nse_sq_send_cmd_with_flags(struct nse_hw *hw, struct nse_ctl_q_info *cq,
		struct nse_aq_desc *desc, void *buf, u16 buf_size,
		struct nse_sq_cd *cd, unsigned int sq_send_cmd_flags)
{
	enum nse_status status = 0;

	if (hw->high_reset_ongoing)
		return NSE_SUCCESS;

	nse_aq_sq_lock(cq);
	status = nse_sq_send_cmd_nolock(hw, cq, desc, buf, buf_size, cd, sq_send_cmd_flags);
	nse_aq_sq_unlock(cq);

	return status;
}

/**
 * nse_sq_send_cmd_retry - send command to Control Queue (ATQ)
 * @hw: pointer to the HW struct
 * @cq: pointer to the specific Control queue
 * @desc: prefilled descriptor describing the command
 * @buf: buffer to use for indirect commands (or NULL for direct commands)
 * @buf_size: size of buffer for indirect commands (or 0 for direct commands)
 * @cd: pointer to command details structure
 *
 * Retry sending the FW Admin Queue command, multiple times, to the FW Admin
 * Queue if the EBUSY AQ error is returned.
 */
enum nse_status
nse_sq_send_cmd_retry(struct nse_hw *hw, struct nse_ctl_q_info *cq,
		      struct nse_aq_desc *desc, void *buf, u16 buf_size,
		      struct nse_sq_cd *cd)
{
	struct nse_aq_desc desc_cpy;
	enum nse_status status;
	bool is_cmd_need_retry = false;
	u32 retry_times, retry_interval_us;
	u8 *buf_cpy = NULL;
	u32 idx = 0;

	is_cmd_need_retry = nse_sq_cmd_is_need_retry(desc->opc_category,
						     desc->opc_subcode, &retry_times);

	retry_times = nse_aq_cmd_timeout / NSE_CTL_Q_SQ_CMD_TIMEOUT_BASE;
	if (retry_times < NSE_SQ_SEND_MAX_EXECUTE)
		retry_times = NSE_SQ_SEND_MAX_EXECUTE;

	/* the more retry times, the more retry interval ...... */
	retry_interval_us = (retry_times / NSE_SQ_SEND_MAX_EXECUTE) * NSE_SQ_SEND_DELAY_TIME_US;
	if (retry_interval_us < NSE_SQ_SEND_DELAY_TIME_US)
		retry_interval_us = NSE_SQ_SEND_DELAY_TIME_US;

	memset(&desc_cpy, 0, sizeof(desc_cpy));

	if (is_cmd_need_retry) {
		if (buf) {
			buf_cpy = devm_kzalloc(nse_hw_to_dev(hw), buf_size,
						       GFP_KERNEL);
			if (!buf_cpy)
				return NSE_ERR_NO_MEMORY;

			memcpy(buf_cpy, buf, buf_size);
		}

		memcpy(&desc_cpy, desc, sizeof(desc_cpy));
	}

	nse_aq_sq_lock(cq);

	do {
		status = nse_sq_send_cmd_nolock(hw, cq, desc, buf, buf_size, cd, 0);

		if (!is_cmd_need_retry || !status ||
			(hw->adminq.sq_last_status != NSE_AQ_RC_EAGAIN &&
			hw->adminq.sq_last_status != NSE_AQ_RC_EBUSY))
			break;

		nse_debug(hw, NSE_DBG_AQM_MSG, "Retry %d time to send adminq cmd(0x%x, 0x%x)\n",
							idx + 1, desc->opc_category,
								desc->opc_subcode);

		if (buf_cpy)
			memcpy(buf, buf_cpy, buf_size);

		memcpy(desc, &desc_cpy, sizeof(desc_cpy));

		nse_aq_wait(retry_interval_us, false);

	} while (++idx < retry_times);

	nse_aq_sq_unlock(cq);

	if (buf_cpy)
		devm_kfree(nse_hw_to_dev(hw), buf_cpy);

	return status;
}

/**
 * nse_fill_dflt_direct_cmd_desc - AQ descriptor helper function
 * @desc: pointer to the temp descriptor (non DMA mem)
 *
 * Fill the desc with default values
 */
void nse_fill_dflt_direct_cmd_desc(struct nse_aq_desc *desc, u8 opc_category, u8 opc_subcode)
{
	/* zero out the desc */
	memset(desc, 0, sizeof(*desc));
	desc->opc_category = opc_category;
	desc->opc_subcode = opc_subcode;
	desc->flags = cpu_to_le16(NSE_AQ_FLAG_SI);	/* Do not generate IRQ on complete */

	/* by default, we send to FW mailbox, if send to VF mailbox, need to set that outside */
	desc->mailbox_id = cpu_to_le16(NSE_AQ_MAILBOX_ID_FW);
}

/**
 * nse_clean_rq_elem
 * @hw: pointer to the HW struct
 * @cq: pointer to the specific Control queue
 * @e: event info from the receive descriptor, includes any buffers
 * @pending: number of events that could be left to process
 *
 * This function cleans one Admin Receive Queue element and returns
 * the contents through e. It can also return how many events are
 * left to process through 'pending'.
 */
enum nse_status
nse_clean_rq_elem(struct nse_hw *hw, struct nse_ctl_q_info *cq,
		  struct nse_rq_event_info *e, u16 *pending)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct device *dev = nse_hw_to_dev(hw);
	u16 ntc = cq->rq.next_to_clean;
	enum nse_aq_err rq_last_status;
	enum nse_status ret_code = 0;
	struct nse_aq_desc *desc;
	struct nse_dma_mem *bi;
	u16 desc_idx;
	u16 datalen;
	u16 flags;
	u32 head_val;
	u16 ntu;

	if (nse_is_reset_in_progress(pf->state))
		return NSE_ERR_AQ_NO_WORK;

	/* pre-clean the event info */
	memset(&e->desc, 0, sizeof(e->desc));

	/* take the lock before we start messing with the ring */
	nse_aq_rq_lock(cq);

	if (!cq->rq.count) {
		dev_err(dev, "Control Receive queue not initialized.\n");
		ret_code = NSE_ERR_AQ_EMPTY;
		goto clean_rq_elem_err;
	}

	/* set next_to_use to head */
	head_val = rd32(hw, cq->rq.head);
	if (nse_is_regval_reset_magic(head_val)) {
		dev_err(dev, "[%s] reset detected, return early\n", __func__);
		ret_code = NSE_ERR_AQ_EMPTY;
		goto clean_rq_elem_err;
	}

	ntu = (u16)(head_val & cq->rq.head_mask);

	if (ntu == ntc) {
		/* nothing to do - shouldn't need to update ring's values */
		ret_code = NSE_ERR_AQ_NO_WORK;
		goto clean_rq_elem_out;
	}

	/* now clean the next descriptor */
	desc = NSE_CTL_Q_DESC(cq->rq, ntc);
	desc_idx = ntc;

	flags = le16_to_cpu(desc->flags);
	rq_last_status = (flags & NSE_AQ_FLAG_RETVAL_M) >> NSE_AQ_FLAG_RETVAL_S;
	if (rq_last_status != NSE_AQ_RC_OK) {
		ret_code = NSE_ERR_AQ_ERROR;
		dev_err(dev, "[%s, %d] Control Receive Queue Event: 0x%04X, received with desc->RETVAL = 0x%X (%s), datalen = %d\n",
						__func__, __LINE__,
						le16_to_cpu(desc->opcode), rq_last_status,
							nse_aq_str(rq_last_status),
							le16_to_cpu(desc->datalen));
	}
	memcpy(&e->desc, desc, sizeof(e->desc));
	datalen = le16_to_cpu(desc->datalen);
	e->msg_len = min_t(u16, datalen, e->buf_len);
	if (e->msg_buf && e->msg_len)
		memcpy(e->msg_buf, cq->rq.r.rq_bi[desc_idx].va, e->msg_len);

	nse_debug(hw, NSE_DBG_AQM_DESC, "ARQ: desc and buffer:\n");

	nse_debug_cq(hw, (void *)desc, e->msg_buf, cq->rq_buf_size);

	/* Restore the original datalen and buffer address in the desc,
	 * FW updates datalen to indicate the event message size
	 */
	bi = &cq->rq.r.rq_bi[ntc];
	memset(desc, 0, sizeof(*desc));

	desc->flags = cpu_to_le16(NSE_AQ_FLAG_BUF);
	if (cq->rq_buf_size > NSE_AQ_LG_BUF)
		desc->flags |= cpu_to_le16(NSE_AQ_FLAG_LB);
	desc->datalen = cpu_to_le16(bi->size);
	desc->addr_high = cpu_to_le32(upper_32_bits(bi->pa));
	desc->addr_low = cpu_to_le32(lower_32_bits(bi->pa));

	/* set tail = the last cleaned desc index. */
	wr32(hw, cq->rq.tail, ntc);
	/* ntc is updated to tail + 1 */
	ntc++;
	if (ntc == cq->num_rq_entries)
		ntc = 0;
	cq->rq.next_to_clean = ntc;
	cq->rq.next_to_use = ntu;

clean_rq_elem_out:
	/* Set pending if needed, unlock and return */
	if (pending) {
		/* re-read HW head to calculate actual pending messages */
		ntu = (u16)(rd32(hw, cq->rq.head) & cq->rq.head_mask);
		*pending = (u16)((ntc > ntu ? cq->rq.count : 0) + (ntu - ntc));
	}
clean_rq_elem_err:
	nse_aq_rq_unlock(cq);

	return ret_code;
}

/**
 * nse_aq_send_cmd - send FW Admin Queue command to FW Admin Queue
 * @hw: pointer to the HW struct
 * @desc: descriptor describing the command
 * @buf: buffer to use for indirect commands (NULL for direct commands)
 * @buf_size: size of buffer for indirect commands (0 for direct commands)
 * @cd: pointer to command details structure
 *
 * Helper function to send FW Admin Queue commands to the FW Admin Queue.
 */
enum nse_status
nse_aq_send_cmd(struct nse_hw *hw, struct nse_aq_desc *desc, void *buf,
		u16 buf_size, struct nse_sq_cd *cd)
{
	enum nse_status status;

	status = nse_sq_send_cmd_retry(hw, &hw->adminq, desc, buf, buf_size, cd);

	return status;
}

#define NSE_UTILQ_INIT_REGS(qinfo, vsi_rel_id)				\
do {								\
	(qinfo)->sq.head = NSE_REG_UTI_ATQH(vsi_rel_id);			\
	(qinfo)->sq.tail = NSE_REG_UTI_ATQT(vsi_rel_id);			\
	(qinfo)->sq.len = NSE_REG_UTI_ATQLEN(vsi_rel_id);			\
	(qinfo)->sq.bah = NSE_REG_UTI_ATQBAH(vsi_rel_id);			\
	(qinfo)->sq.bal = NSE_REG_UTI_ATQBAL(vsi_rel_id);			\
	(qinfo)->sq.len_mask = NSE_REG_UTI_ATQLEN_LEN_M;	\
	(qinfo)->sq.len_crit_mask = NSE_REG_UTI_ATQLEN_CRIT_M;	\
	(qinfo)->sq.head_mask = NSE_REG_UTI_ATQH_HEAD_M;		\
} while (0)

enum nse_status nse_fdir_init_utilq(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_fdir_cb *fdir_cb = &hw->fdir_cb;
	struct nse_ctl_q_info *cq = &fdir_cb->utilq;
	struct nse_vsi *main_vsi = nse_get_main_vsi(pf);
	u32 reg;
	enum nse_status ret = NSE_SUCCESS;

	fdir_cb->utilq_initialized = false;

	if (!pf->sw_conf.fdir_ena || !pf->sw_conf.fdir_use_utilq) {
		ret = NSE_SUCCESS;
		goto out;
	}

	if (main_vsi == NULL) {
		dev_info(dev, "pf-main-vsi not init, not init its utilq.\n");
		ret = NSE_ERR_CFG;
		goto out;
	}

	cq->qtype = NSE_CTL_Q_UTIL;

	cq->num_sq_entries = NSE_UTILQ_SQ_LEN;
	cq->sq_buf_size = NSE_AQ_MAX_BUF_LEN;

	cq->sq_cmd_timeout = (NSE_CTL_Q_SQ_CMD_TIMEOUT_BASE * nse_timeout_scale);

	NSE_UTILQ_INIT_REGS(cq, main_vsi->vsi_rel_num);

	/* allocate the ATQ */
	ret = nse_init_sq(hw, cq);
	if (ret) {
		dev_err(dev, "FAIL: utilq - init_sq()\n");
		goto out;
	}

	reg = ((u32)hw->pcore_pf_id << NSE_REG_UTI_CTL_PF_IDX_S) & NSE_REG_UTI_CTL_PF_IDX_M;

	wr32(hw, NSE_REG_UTI_CTL(main_vsi->vsi_rel_num), reg);

	fdir_cb->utilq_initialized = true;

	ret = 0;

out:
	return ret;
}

void nse_fdir_shutdown_utilq(struct nse_hw *hw)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct device *dev = nse_pf_to_dev(pf);
	struct nse_fdir_cb *fdir_cb = &hw->fdir_cb;
	struct nse_ctl_q_info *cq = &fdir_cb->utilq;

	if (!pf->sw_conf.fdir_ena || !pf->sw_conf.fdir_use_utilq)
		goto out;

	if (!fdir_cb->utilq_initialized) {
		dev_info(dev, "utilq_initialized=false, no need to shutdown_utilq.\n");
		goto out;
	}

	(void)nse_shutdown_sq(hw, cq, 0);

	fdir_cb->utilq_initialized = false;

out:
	return;
}

