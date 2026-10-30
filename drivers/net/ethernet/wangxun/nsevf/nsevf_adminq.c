// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#include "nsevf.h"
#include "nsevf_status.h"
#include "nsevf_type.h"
#include "nsevf_hw_reg.h"
#include "nsevf_adminq.h"
#include "nsevf_prototype.h"
#include "nsevf_msgbox.h"

void nsevf_aq_wait(unsigned int usec)
{
	unsigned int msec = usec / 1000;
	unsigned int usec_remain = usec % 1000;

	if (!nse_aq_cmd_wait_method) {
		if (msec)
			msleep(msec);

		if (usec_remain)
			usleep_range(usec_remain, usec_remain + 50);

	} else {
		/* Split long delays to avoid exceeding MAX_UDELAY_MS. */

		if (msec)
			mdelay(msec);

		if (usec_remain)
			udelay(usec_remain);
	}
}

/**
 *  nsevf_mailboxq_init_regs - Initialize AdminQ registers
 *  @hw: pointer to the hardware structure
 *  @aq: pointer to the control queue information
 *
 *  This assumes the alloc_asq and alloc_arq functions have already been called
 **/
static void nsevf_mailboxq_init_regs(struct nsevf_hw *hw,
				     struct nsevf_ctl_q_info *aq)
{
	/* set head and tail registers in our local struct */
	aq->asq.tail = MBX_ATQT(hw);
	aq->asq.head = MBX_ATQH(hw);
	aq->asq.len = MBX_ATQLEN(hw);
	aq->asq.bal = MBX_ATQBAL(hw);
	aq->asq.bah = MBX_ATQBAH(hw);
	aq->arq.tail = MBX_ARQT(hw);
	aq->arq.head = MBX_ARQH(hw);
	aq->arq.len = MBX_ARQLEN(hw);
	aq->arq.bal = MBX_ARQBAL(hw);
	aq->arq.bah = MBX_ARQBAH(hw);
}

static void nsevf_utilq_init_regs(struct nsevf_hw *hw,
				  struct nsevf_ctl_q_info *aq)
{
	aq->asq.tail = NSEVF_REG_UTI_ATQT;
	aq->asq.head = NSEVF_REG_UTI_ATQH;
	aq->asq.len = NSEVF_REG_UTI_ATQLEN;
	aq->asq.bal = NSEVF_REG_UTI_ATQBAL;
	aq->asq.bah = NSEVF_REG_UTI_ATQBAH;
}

/**
 *  nsevf_alloc_aq_asq_ring - Allocate Admin Queue send rings
 *  @hw: pointer to the hardware structure
 *  @aq: pointer to the control queue information
 **/
static enum nsevf_status nsevf_alloc_aq_asq_ring(struct nsevf_hw *hw,
						 struct nsevf_ctl_q_info *aq)
{
	enum nsevf_status ret_code;

	ret_code = nsevf_allocate_dma_mem(hw, &aq->asq.desc_buf, nsevf_mem_atq_ring,
					  (aq->num_asq_entries * sizeof(struct nsevf_aq_desc)),
		NSEVF_AQM_Q_DESC_ALIGNMENT);
	if (ret_code)
		return ret_code;

	ret_code = nsevf_allocate_virt_mem(hw, &aq->asq.cmd_buf,
					   aq->num_asq_entries *
					   sizeof(struct nsevf_asq_cmd_details));
	if (ret_code) {
		nsevf_free_dma_mem(hw, &aq->asq.desc_buf);
		return ret_code;
	}

	return ret_code;
}

/**
 *  nsevf_alloc_aq_arq_ring - Allocate Admin Queue receive rings
 *  @hw: pointer to the hardware structure
 *  @aq: pointer to the control queue information
 **/
static enum nsevf_status nsevf_alloc_aq_arq_ring(struct nsevf_hw *hw,
						 struct nsevf_ctl_q_info *aq)
{
	enum nsevf_status ret_code;

	ret_code = nsevf_allocate_dma_mem(hw, &aq->arq.desc_buf, nsevf_mem_arq_ring,
					  (aq->num_arq_entries * sizeof(struct nsevf_aq_desc)),
		NSEVF_AQM_Q_DESC_ALIGNMENT);

	return ret_code;
}

/**
 *  nsevf_free_aq_asq - Free Admin Queue send rings
 *  @hw: pointer to the hardware structure
 *  @aq: pointer to the control queue information
 *
 *  This assumes the posted send buffers have already been cleaned
 *  and de-allocated
 **/
static void nsevf_free_aq_asq(struct nsevf_hw *hw, struct nsevf_ctl_q_info *aq)
{
	nsevf_free_virt_mem(hw, &aq->asq.cmd_buf);
	nsevf_free_dma_mem(hw, &aq->asq.desc_buf);
}

/**
 *  nsevf_free_aq_arq - Free Admin Queue receive rings
 *  @hw: pointer to the hardware structure
 *  @aq: pointer to the control queue information
 *
 *  This assumes the posted receive buffers have already been cleaned
 *  and de-allocated
 **/
static void nsevf_free_aq_arq(struct nsevf_hw *hw, struct nsevf_ctl_q_info *aq)
{
	nsevf_free_dma_mem(hw, &aq->arq.desc_buf);
}

/**
 *  nsevf_alloc_arq_bufs - Allocate pre-posted buffers for the receive queue
 *  @hw: pointer to the hardware structure
 *  @aq: pointer to the control queue information
 **/
static enum nsevf_status nsevf_alloc_arq_bufs(struct nsevf_hw *hw,
					      struct nsevf_ctl_q_info *aq)
{
	enum nsevf_status ret_code;
	struct nsevf_aq_desc *desc;
	struct nsevf_dma_mem *bi;
	int i;

	/* We'll be allocating the buffer info memory first, then we can
	 * allocate the mapped buffers for the event processing
	 */

	/* buffer_info structures do not need alignment */
	ret_code = nsevf_allocate_virt_mem(hw, &aq->arq.dma_head,
					   (aq->num_arq_entries * sizeof(struct nsevf_dma_mem)));
	if (ret_code)
		goto alloc_arq_bufs;
	aq->arq.r.arq_bi = (struct nsevf_dma_mem *)aq->arq.dma_head.va;

	/* allocate the mapped buffers */
	for (i = 0; i < aq->num_arq_entries; i++) {
		bi = &aq->arq.r.arq_bi[i];
		ret_code = nsevf_allocate_dma_mem(hw, bi, nsevf_mem_arq_buf,
						  aq->arq_buf_size,
						  NSEVF_AQM_Q_DESC_ALIGNMENT);
		if (ret_code)
			goto unwind_alloc_arq_bufs;

		/* now configure the descriptors for use */
		desc = NSEVF_AQM_Q_DESC(aq->arq, i);

		desc->flags = cpu_to_le16(NSE_AQ_FLAG_BUF);
		if (aq->arq_buf_size > NSEVF_AQ_LARGE_BUF)
			desc->flags |= cpu_to_le16(NSE_AQ_FLAG_LB);
		desc->opcode = 0;
		/* This is in accordance with Admin queue design, there is no
		 * register for buffer size configuration
		 */
		desc->datalen = cpu_to_le16((u16)bi->size);
		desc->addr_high = cpu_to_le32(upper_32_bits(bi->pa));
		desc->addr_low = cpu_to_le32(lower_32_bits(bi->pa));
	}

alloc_arq_bufs:
	return ret_code;

unwind_alloc_arq_bufs:
	/* don't try to free the one that failed... */
	i--;
	for (; i >= 0; i--)
		nsevf_free_dma_mem(hw, &aq->arq.r.arq_bi[i]);
	nsevf_free_virt_mem(hw, &aq->arq.dma_head);

	return ret_code;
}

/**
 *  nsevf_alloc_asq_bufs - Allocate empty buffer structs for the send queue
 *  @hw: pointer to the hardware structure
 *  @aq: pointer to the control queue information
 **/
static enum nsevf_status nsevf_alloc_asq_bufs(struct nsevf_hw *hw,
					      struct nsevf_ctl_q_info *aq)
{
	enum nsevf_status ret_code;
	struct nsevf_dma_mem *bi;
	int i;

	/* No mapped memory needed yet, just the buffer info structures */
	ret_code = nsevf_allocate_virt_mem(hw, &aq->asq.dma_head,
					   (aq->num_asq_entries * sizeof(struct nsevf_dma_mem)));
	if (ret_code)
		goto alloc_asq_bufs;
	aq->asq.r.asq_bi = (struct nsevf_dma_mem *)aq->asq.dma_head.va;

	/* allocate the mapped buffers */
	for (i = 0; i < aq->num_asq_entries; i++) {
		bi = &aq->asq.r.asq_bi[i];
		ret_code = nsevf_allocate_dma_mem(hw, bi, nsevf_mem_asq_buf,
						  aq->asq_buf_size,
						  NSEVF_AQM_Q_DESC_ALIGNMENT);
		if (ret_code)
			goto unwind_alloc_asq_bufs;
	}
alloc_asq_bufs:
	return ret_code;

unwind_alloc_asq_bufs:
	/* don't try to free the one that failed... */
	i--;
	for (; i >= 0; i--)
		nsevf_free_dma_mem(hw, &aq->asq.r.asq_bi[i]);
	nsevf_free_virt_mem(hw, &aq->asq.dma_head);

	return ret_code;
}

/**
 *  nsevf_free_arq_bufs - Free receive queue buffer info elements
 *  @hw: pointer to the hardware structure
 *  @aq: pointer to the control queue information
 **/
static void nsevf_free_arq_bufs(struct nsevf_hw *hw,
				struct nsevf_ctl_q_info *aq)
{
	int i;

	/* free descriptors */
	for (i = 0; i < aq->num_arq_entries; i++)
		nsevf_free_dma_mem(hw, &aq->arq.r.arq_bi[i]);

	/* free the descriptor memory */
	nsevf_free_dma_mem(hw, &aq->arq.desc_buf);

	/* free the dma header */
	nsevf_free_virt_mem(hw, &aq->arq.dma_head);
}

/**
 *  nsevf_free_asq_bufs - Free send queue buffer info elements
 *  @hw: pointer to the hardware structure
 *  @aq: pointer to the control queue information
 **/
static void nsevf_free_asq_bufs(struct nsevf_hw *hw,
				struct nsevf_ctl_q_info *aq)
{
	int i;

	/* only unmap if the address is non-NULL */
	for (i = 0; i < aq->num_asq_entries; i++)
		if (aq->asq.r.asq_bi[i].pa)
			nsevf_free_dma_mem(hw, &aq->asq.r.asq_bi[i]);

	/* free the buffer info list */
	nsevf_free_virt_mem(hw, &aq->asq.cmd_buf);

	/* free the descriptor memory */
	nsevf_free_dma_mem(hw, &aq->asq.desc_buf);

	/* free the dma header */
	nsevf_free_virt_mem(hw, &aq->asq.dma_head);
}

static enum nsevf_status nsevf_config_aq_regs(struct nsevf_hw *hw,
					      struct nsevf_ctl_q_info *aq,
					      struct nsevf_ctl_q_ring *ring,
					      bool asq_or_arq)
{
	struct device *dev = nsevf_hw_to_dev(hw);
	u32 reg = 0;
	u32 num_entries = asq_or_arq ? aq->num_asq_entries :
				       aq->num_arq_entries;
	u32 wait_timeout;
	u32 wait_timeout_tick = NSE_CTL_Q_SQ_CMD_USEC;
	u32 total_wait = 0;
	enum nsevf_status status = 0;

	wait_timeout = (NSE_CTL_Q_SQ_CMD_TIMEOUT_BASE * nse_timeout_scale);

	/* Clear Head and Tail */
	wr32(hw, ring->head, 0);
	wr32(hw, ring->tail, 0);

	wr32(hw, ring->bal, lower_32_bits(ring->desc_buf.pa));
	wr32(hw, ring->bah, upper_32_bits(ring->desc_buf.pa));

	nsevf_flush(hw);

	/* enable
	 */
	/* Ensure queue registers are visible before enabling the queue. */
	wmb();

	reg = (num_entries |
	       (NSE_CTLQ_STAT_BIT_IDX_Q_EN << NSE_REG_AQM_QLEN_STAT_BIT_S) |
	       NSE_REG_AQM_QLEN_EXEC_M |
	       (NSE_REG_AQM_QLEN_OP_SET_STAT << NSE_REG_AQM_QLEN_OP_S));

	wr32(hw, ring->len, reg);

	nsevf_flush(hw);

	total_wait = 0;

	do {
		nsevf_aq_wait(wait_timeout_tick);

		reg = rd32(hw, ring->len);

		if (nsevf_is_regval_reset_magic(reg) ||
		    (reg & NSE_REG_AQM_QLEN_LEN_M) != num_entries) {
			dev_err(dev,
				"[%s] SW try to set q_en, but readback value: 0x%X",
				__func__, reg);

			goto fail_enable;
		}

		if (reg & NSE_REG_AQM_QLEN_STAT_Q_EN_M)
			break;

		total_wait++;

	} while (total_wait < wait_timeout);

	if (!(reg & NSE_REG_AQM_QLEN_STAT_Q_EN_M)) {
		dev_err(dev, "[%s] timeout wait for q_en, readback value: 0x%X",
			__func__, reg);

		goto fail_enable;
	}

	/* un-pause
	 */
	/* Ensure queue registers are visible before unpausing the queue. */
	wmb();

	reg = (num_entries |
	       (NSE_CTLQ_STAT_BIT_IDX_Q_PAUSE_N
		<< NSE_REG_AQM_QLEN_STAT_BIT_S) |
	       NSE_REG_AQM_QLEN_EXEC_M |
	       (NSE_REG_AQM_QLEN_OP_SET_STAT << NSE_REG_AQM_QLEN_OP_S));

	wr32(hw, ring->len, reg);

	nsevf_flush(hw);

	total_wait = 0;

	do {
		nsevf_aq_wait(wait_timeout_tick);

		reg = rd32(hw, ring->len);

		if (nsevf_is_regval_reset_magic(reg) ||
		    (reg & NSE_REG_AQM_QLEN_LEN_M) != num_entries) {
			dev_err(dev,
				"[%s] SW try to set q_pause_n, but readback value: 0x%X",
				__func__, reg);

			goto fail_unpause;
		}

		if (reg & NSE_REG_AQM_QLEN_STAT_Q_PAUSE_N_M)
			break;

		total_wait++;

	} while (total_wait < wait_timeout);

	if (!(reg & NSE_REG_AQM_QLEN_STAT_Q_PAUSE_N_M)) {
		dev_err(dev,
			"[%s] timeout wait for q_pause_n, readback value: 0x%X",
			__func__, reg);

		goto fail_unpause;
	}

	/* Check one register to verify that config was applied */
	reg = rd32(hw, ring->bal);
	if (reg != lower_32_bits(ring->desc_buf.pa)) {
		dev_err(dev,
			"[%s] FAIL: SW set BAL value (0x%X), but readback value (0x%X) not expect\n",
			__func__, lower_32_bits(ring->desc_buf.pa), reg);

		status = NSEVF_ERR_ADMIN_QUEUE_ERROR;
	}

out:
	if (hw->debug_mask & NSEVF_DBG_AQM_MSG) {
		dev_info(dev,
			 "ring->head [BAR0 reg: %X, value: %X], expect: %X\n",
			 ring->head, rd32(hw, ring->head), 0);

		dev_info(dev,
			 "ring->tail [BAR0 reg: %X, value: %X], expect: %X\n",
			 ring->tail, rd32(hw, ring->tail), 0);

		dev_info(dev,
			 "ring->len [BAR0 reg: %X, value: %X], expect: %lX\n",
			 ring->len, rd32(hw, ring->len),
			 (num_entries | NSE_REG_AQM_QLEN_STAT_Q_PAUSE_N_M |
			  NSE_REG_AQM_QLEN_STAT_Q_EN_M));

		dev_info(dev,
			 "ring->bal [BAR0 reg: %X, value: %X], expect: %X\n",
			 ring->bal, rd32(hw, ring->bal),
			 lower_32_bits(ring->desc_buf.pa));

		dev_info(dev,
			 "ring->bah [BAR0 reg: %X, value: %X], expect: %X\n",
			 ring->bah, rd32(hw, ring->bah),
			 upper_32_bits(ring->desc_buf.pa));
	}

	return status;

fail_enable:

	dev_err(dev, "[%s] FAIL: SW enable ctlq-%s\n", __func__,
		asq_or_arq ? "sq" : "rq");

	status = NSEVF_ERR_ADMIN_QUEUE_ERROR;

	goto out;

fail_unpause:

	dev_err(dev, "[%s] FAIL: SW unpause ctlq-%s\n", __func__,
		asq_or_arq ? "sq" : "rq");

	status = NSEVF_ERR_ADMIN_QUEUE_ERROR;

	goto out;
}

/**
 *  nsevf_config_asq_regs - configure ASQ registers
 *  @hw: pointer to the hardware structure
 *  @aq: pointer to the control queue information
 *
 *  Configure base address and length registers for the transmit queue
 **/
static enum nsevf_status nsevf_config_asq_regs(struct nsevf_hw *hw,
					       struct nsevf_ctl_q_info *aq)
{
	return nsevf_config_aq_regs(hw, aq, &aq->asq, true);
}

/**
 *  nsevf_config_arq_regs - ARQ register configuration
 *  @hw: pointer to the hardware structure
 *  @aq: pointer to the control queue information
 *
 * Configure base address and length registers for the receive (event queue)
 **/
static enum nsevf_status nsevf_config_arq_regs(struct nsevf_hw *hw,
					       struct nsevf_ctl_q_info *aq)
{
	enum nsevf_status status = 0;

	status = nsevf_config_aq_regs(hw, aq, &aq->arq, false);
	if (status)
		return status;

	/* Update tail in the HW to post pre-allocated buffers */
	wr32(hw, aq->arq.tail, aq->num_arq_entries - 1);

	return status;
}

/**
 *  nsevf_init_asq - main initialization routine for ASQ
 *  @hw: pointer to the hardware structure
 *  @aq: pointer to the control queue information
 *
 *  This is the main initialization routine for the Admin Send Queue
 *  Prior to calling this function, drivers *MUST* set the following fields
 *  in the hw->mailboxq structure:
 *     - hw->mailboxq.num_asq_entries
 *     - hw->mailboxq.arq_buf_size
 *
 *  Do *NOT* hold the lock when calling this as the memory allocation routines
 *  called are not going to be atomic context safe
 **/
static enum nsevf_status nsevf_init_asq(struct nsevf_hw *hw,
					struct nsevf_ctl_q_info *aq)
{
	enum nsevf_status ret_code = 0;

	if (aq->asq.count > 0) {
		/* queue already initialized */
		ret_code = NSEVF_ERR_NOT_READY;
		goto init_adminq_exit;
	}

	/* verify input for valid configuration */
	if (aq->num_asq_entries == 0 || aq->asq_buf_size == 0) {
		ret_code = NSEVF_ERR_CONFIG;
		goto init_adminq_exit;
	}

	aq->asq.next_to_use = 0;
	aq->asq.next_to_clean = 0;

	/* allocate the ring memory */
	ret_code = nsevf_alloc_aq_asq_ring(hw, aq);
	if (ret_code)
		goto init_adminq_exit;

	/* allocate buffers in the rings */
	ret_code = nsevf_alloc_asq_bufs(hw, aq);
	if (ret_code)
		goto init_adminq_free_rings;

	/* initialize base registers */
	ret_code = nsevf_config_asq_regs(hw, aq);
	if (ret_code)
		goto init_config_regs;

	/* success! */
	aq->asq.count = aq->num_asq_entries;
	goto init_adminq_exit;

init_adminq_free_rings:
	nsevf_free_aq_asq(hw, aq);
	return ret_code;

init_config_regs:
	nsevf_free_asq_bufs(hw, aq);

init_adminq_exit:
	return ret_code;
}

/**
 *  nsevf_init_arq - initialize ARQ
 *  @hw: pointer to the hardware structure
 *  @aq: pointer to the control queue information
 *
 *  The main initialization routine for the Admin Receive (Event) Queue.
 *  Prior to calling this function, drivers *MUST* set the following fields
 *  in the hw->mailboxq structure:
 *     - hw->mailboxq.num_asq_entries
 *     - hw->mailboxq.arq_buf_size
 *
 *  Do *NOT* hold the lock when calling this as the memory allocation routines
 *  called are not going to be atomic context safe
 **/
static enum nsevf_status nsevf_init_arq(struct nsevf_hw *hw,
					struct nsevf_ctl_q_info *aq)
{
	enum nsevf_status ret_code = 0;

	if (aq->arq.count > 0) {
		/* queue already initialized */
		ret_code = NSEVF_ERR_NOT_READY;
		goto init_adminq_exit;
	}

	/* verify input for valid configuration */
	if (aq->num_arq_entries == 0 || aq->arq_buf_size == 0) {
		ret_code = NSEVF_ERR_CONFIG;
		goto init_adminq_exit;
	}

	aq->arq.next_to_use = 0;
	aq->arq.next_to_clean = 0;

	/* allocate the ring memory */
	ret_code = nsevf_alloc_aq_arq_ring(hw, aq);
	if (ret_code)
		goto init_adminq_exit;

	/* allocate buffers in the rings */
	ret_code = nsevf_alloc_arq_bufs(hw, aq);
	if (ret_code)
		goto init_adminq_free_rings;

	/* initialize base registers */
	ret_code = nsevf_config_arq_regs(hw, aq);
	if (ret_code)
		goto init_adminq_free_rings;

	/* success! */
	aq->arq.count = aq->num_arq_entries;
	goto init_adminq_exit;

init_adminq_free_rings:
	nsevf_free_aq_arq(hw, aq);

init_adminq_exit:
	return ret_code;
}

/**
 *  nsevf_shutdown_asq - shutdown the ASQ
 *  @hw: pointer to the hardware structure
 *  @aq: pointer to the control queue information
 *  @flags: shutdown control flags
 *
 *  The main shutdown routine for the Admin Send Queue
 **/
static enum nsevf_status nsevf_shutdown_asq(struct nsevf_hw *hw,
					    struct nsevf_ctl_q_info *aq,
					    unsigned int flags)
{
	struct nsevf_adapter *adapter = (struct nsevf_adapter *)hw->back;
	struct device *dev = nsevf_hw_to_dev(hw);
	u32 len;
	u32 wait_timeout;
	u32 wait_timeout_tick = NSE_CTL_Q_SQ_CMD_USEC;
	u32 total_wait = 0;
	enum nsevf_status ret_code = 0;

	wait_timeout = (NSE_CTL_Q_SQ_CMD_TIMEOUT_BASE * nse_timeout_scale);

	nsevf_debug(hw, NSEVF_DBG_SYS,
		    "[%s] wait_timeout=%d, wait_timeout_tick=%d, sw_shutdown_mq_imm=%d, flags=0x%X\n",
		__func__, wait_timeout, wait_timeout_tick,
		adapter->sw_shutdown_mq_imm, flags);

	nsevf_acquire_spinlock(&aq->asq_spinlock);

	if (aq->asq.count == 0) {
		ret_code = NSEVF_ERR_NOT_READY;
		goto shutdown_asq_out;
	}

	len = rd32(hw, aq->asq.len);
	if (nsevf_is_regval_reset_magic(len)) {
		nsevf_debug(hw, NSEVF_DBG_SYS,
			    "[%s, %d] asq.len is reset magic: 0x%X, maybe in reset, return early\n",
			__func__, __LINE__, len);
		goto skip_sw_shutdown;
	}

	if (adapter->sw_shutdown_mq_imm || aq->qtype == NSEVF_CTL_Q_UTIL ||
	    !(flags & NSE_SHUTDOWN_CTLQ_FLAG_WAIT_FW_SHUTDOWN)) {
		msleep(500); /* still sleep for a while */
		goto sw_shutdown;
	}

	/* Order prior queue operations before reading the queue state. */
	wmb();

	len = rd32(hw, aq->asq.len);

	nsevf_debug(hw, NSEVF_DBG_SYS, "[%s, %d] asq.len=0x%X\n", __func__,
		    __LINE__, len);

	total_wait = 0;

	do {
		nsevf_aq_wait(wait_timeout_tick);

		len = rd32(hw, aq->asq.len);

		if (!(len & (NSE_REG_AQM_QLEN_STAT_Q_PAUSE_N_M |
			     NSE_REG_AQM_QLEN_STAT_Q_EN_M)))
			break;

		if (nsevf_is_regval_reset_magic(len)) {
			nsevf_debug(hw, NSEVF_DBG_SYS,
				    "[%s, %d] asq.len is reset magic: 0x%X, maybe in reset, return early\n",
				__func__, __LINE__, len);
			goto skip_sw_shutdown;
		}

		total_wait++;

	} while (total_wait < wait_timeout);

sw_shutdown:

	len = rd32(hw, aq->asq.len);

	if (len & (NSE_REG_AQM_QLEN_STAT_Q_PAUSE_N_M |
		   NSE_REG_AQM_QLEN_STAT_Q_EN_M)) {
		hw->controlq_stats.mq_sq_wait_for_fw_pause_disable_fail_cnt++;
		hw->controlq_stats.mq_sq_wait_for_fw_pause_disable_fail_time =
			ktime_to_ns(ktime_get());

		dev_info(dev,
			 "WARN: mq_sq may not be paused + disabled in time by FW --- FW should do that by aq-cmd: NSE_AQ_OPC_Q_SHUTDOWN\n");
		dev_info(dev,
			 "\t cmd: SHUTDOWN was sent at %ld ns, now is: %ld ns\n",
			(unsigned long)hw->controlq_stats.mq_cmd_shutdown_time,
			(unsigned long)hw->controlq_stats
				.mq_sq_wait_for_fw_pause_disable_fail_time);

		dev_info(dev,
			 "\t SW try pause + disable itself --- sq_len=0x%X\n",
			 len);

		/* Complete prior accesses before requesting a queue pause. */
		wmb();

		/* SW pause
		 */
		len = rd32(hw, aq->asq.len);

		if (len & NSE_REG_AQM_QLEN_STAT_Q_PAUSE_N_M) {
			len &= ~(NSE_REG_AQM_QLEN_STAT_BIT_M |
				 NSE_REG_AQM_QLEN_EXEC_M |
				 NSE_REG_AQM_QLEN_OP_M);

			len |= ((NSE_CTLQ_STAT_BIT_IDX_Q_PAUSE_N
				 << NSE_REG_AQM_QLEN_STAT_BIT_S) |
				NSE_REG_AQM_QLEN_EXEC_M |
				(NSE_REG_AQM_QLEN_OP_CLR_STAT
				 << NSE_REG_AQM_QLEN_OP_S));

			wr32(hw, aq->asq.len, len);

			nsevf_flush(hw);

			total_wait = 0;

			do {
				nsevf_aq_wait(wait_timeout_tick);

				len = rd32(hw, aq->asq.len);

				if (!(len &
				      NSE_REG_AQM_QLEN_STAT_Q_PAUSE_N_M)) {
					nsevf_debug(hw, NSEVF_DBG_SYS,
						    "[%s] DONE: SW clear mq_sq q_pause_n, wait times=%d\n",
						__func__, total_wait);
					break;
				}

				if (nsevf_is_regval_reset_magic(len)) {
					nsevf_debug(hw, NSEVF_DBG_SYS,
						    "[%s, %d] asq.len is reset magic: 0x%X, maybe in reset, return early\n",
						__func__, __LINE__, len);
					goto skip_sw_shutdown;
				}

				total_wait++;

			} while (total_wait < wait_timeout);

			len = rd32(hw, aq->asq.len);

			if (len & NSE_REG_AQM_QLEN_STAT_Q_PAUSE_N_M) {
				hw->controlq_stats
					.mq_sq_wait_for_sw_pause_fail_cnt++;
				hw->controlq_stats
					.mq_sq_wait_for_sw_pause_fail_time =
					ktime_to_ns(ktime_get());

				dev_info(dev,
					 "WARN: timeout: SW clear mq_sq q_pause_n, sq_len=0x%X\n",
					len);
				dev_info(dev, "\t now is: %ld ns\n",
					 (unsigned long)hw->controlq_stats
						.mq_sq_wait_for_sw_pause_fail_time);
			}
		}

		/* Complete the pause request before disabling the queue. */
		wmb();

		/* SW disable
		 *
		 * even SW pause timeout, continue anyway to disable procedure....
		 */

		len = rd32(hw, aq->asq.len);

		if (len & NSE_REG_AQM_QLEN_STAT_Q_EN_M) {
			len &= ~(NSE_REG_AQM_QLEN_STAT_BIT_M |
				 NSE_REG_AQM_QLEN_EXEC_M |
				 NSE_REG_AQM_QLEN_OP_M);

			len |= ((NSE_CTLQ_STAT_BIT_IDX_Q_EN
				 << NSE_REG_AQM_QLEN_STAT_BIT_S) |
				NSE_REG_AQM_QLEN_EXEC_M |
				(NSE_REG_AQM_QLEN_OP_CLR_STAT
				 << NSE_REG_AQM_QLEN_OP_S));

			wr32(hw, aq->asq.len, len);

			nsevf_flush(hw);

			total_wait = 0;

			do {
				nsevf_aq_wait(wait_timeout_tick);

				len = rd32(hw, aq->asq.len);

				if (!(len & NSE_REG_AQM_QLEN_STAT_Q_EN_M)) {
					nsevf_debug(hw, NSEVF_DBG_SYS,
						    "[%s] DONE: SW clear mq_sq q_en, wait times=%d\n",
						__func__, total_wait);
					break;
				}

				if (nsevf_is_regval_reset_magic(len)) {
					nsevf_debug(hw, NSEVF_DBG_SYS,
						    "[%s, %d] asq.len is reset magic: 0x%X, maybe in reset, return early\n",
						__func__, __LINE__, len);
					goto skip_sw_shutdown;
				}

				total_wait++;

			} while (total_wait < wait_timeout);

			len = rd32(hw, aq->asq.len);

			if (len & NSE_REG_AQM_QLEN_STAT_Q_EN_M) {
				hw->controlq_stats
					.mq_sq_wait_for_sw_disable_fail_cnt++;
				hw->controlq_stats
					.mq_sq_wait_for_sw_disable_fail_time =
					ktime_to_ns(ktime_get());

				dev_info(dev,
					 "WARN: timeout: SW clear mq_sq q_en, sq_len=0x%X\n",
					len);
				dev_info(dev, "\t now is: %ld ns\n",
					 (unsigned long)hw->controlq_stats
						.mq_sq_wait_for_sw_disable_fail_time);
			}
		}
	}

	/* Complete queue shutdown before clearing its configuration. */
	wmb();

	wr32(hw, aq->asq.len, 0);

	nsevf_flush(hw);
	nsevf_aq_wait(5000); /* 5 ms delay */

	wr32(hw, aq->asq.head, 0);

	wr32(hw, aq->asq.tail, 0);

skip_sw_shutdown:

	msleep(100);

	aq->asq.count = 0; /* to indicate uninitialized queue */

	/* free ring buffers */
	nsevf_free_asq_bufs(hw, aq);

shutdown_asq_out:

	nsevf_release_spinlock(&aq->asq_spinlock);

	return ret_code;
}

/**
 *  nsevf_shutdown_arq - shutdown ARQ
 *  @hw: pointer to the hardware structure
 *  @aq: pointer to the control queue information
 *  @flags: shutdown control flags
 *
 *  The main shutdown routine for the Admin Receive Queue
 **/
static enum nsevf_status nsevf_shutdown_arq(struct nsevf_hw *hw,
					    struct nsevf_ctl_q_info *aq,
					    unsigned int flags)
{
	struct nsevf_adapter *adapter = (struct nsevf_adapter *)hw->back;
	struct device *dev = nsevf_hw_to_dev(hw);
	u32 len;
	u32 wait_timeout;
	u32 wait_timeout_tick = NSE_CTL_Q_SQ_CMD_USEC;
	u32 total_wait = 0;
	enum nsevf_status ret_code = 0;

	wait_timeout = (NSE_CTL_Q_SQ_CMD_TIMEOUT_BASE * nse_timeout_scale);

	nsevf_debug(hw, NSEVF_DBG_SYS,
		    "[%s] wait_timeout=%d, wait_timeout_tick=%d, sw_shutdown_mq_imm=%d, flags=0x%X\n",
		__func__, wait_timeout, wait_timeout_tick,
		adapter->sw_shutdown_mq_imm, flags);

	nsevf_acquire_spinlock(&aq->arq_spinlock);

	if (aq->arq.count == 0) {
		ret_code = NSEVF_ERR_NOT_READY;
		goto shutdown_arq_out;
	}

	len = rd32(hw, aq->arq.len);
	if (nsevf_is_regval_reset_magic(len)) {
		nsevf_debug(hw, NSEVF_DBG_SYS,
			    "[%s, %d] arq.len is reset magic: 0x%X, maybe in reset, return early\n",
			__func__, __LINE__, len);
		goto skip_sw_shutdown;
	}

	if (adapter->sw_shutdown_mq_imm ||
	    !(flags & NSE_SHUTDOWN_CTLQ_FLAG_WAIT_FW_SHUTDOWN)) {
		msleep(500); /* still sleep for a while */
		goto sw_shutdown;
	}

	/* Order prior queue operations before reading the queue state. */
	wmb();

	len = rd32(hw, aq->arq.len);

	nsevf_debug(hw, NSEVF_DBG_SYS, "[%s, %d] arq.len=0x%X\n", __func__,
		    __LINE__, len);

	total_wait = 0;

	do {
		nsevf_aq_wait(wait_timeout_tick);

		len = rd32(hw, aq->arq.len);

		if (!(len & (NSE_REG_AQM_QLEN_STAT_Q_PAUSE_N_M |
			     NSE_REG_AQM_QLEN_STAT_Q_EN_M)))
			break;

		if (nsevf_is_regval_reset_magic(len)) {
			nsevf_debug(hw, NSEVF_DBG_SYS,
				    "[%s, %d] arq.len is reset magic: 0x%X, maybe in reset, return early\n",
				__func__, __LINE__, len);
			goto skip_sw_shutdown;
		}

		total_wait++;

	} while (total_wait < wait_timeout);

sw_shutdown:

	len = rd32(hw, aq->arq.len);

	if (len & (NSE_REG_AQM_QLEN_STAT_Q_PAUSE_N_M |
		   NSE_REG_AQM_QLEN_STAT_Q_EN_M)) {
		hw->controlq_stats.mq_rq_wait_for_fw_pause_disable_fail_cnt++;
		hw->controlq_stats.mq_rq_wait_for_fw_pause_disable_fail_time =
			ktime_to_ns(ktime_get());

		dev_info(dev,
			 "WARN: mq_rq may not be paused + disabled in time by FW --- FW should do that by aq-cmd: NSE_AQ_OPC_Q_SHUTDOWN\n");
		dev_info(dev,
			 "\t cmd: SHUTDOWN was sent at %ld ns, now is: %ld ns\n",
			(unsigned long)hw->controlq_stats.mq_cmd_shutdown_time,
			(unsigned long)hw->controlq_stats
				.mq_rq_wait_for_fw_pause_disable_fail_time);

		dev_info(dev,
			 "\t SW try pause + disable itself --- rq_len=0x%X\n",
			 len);

		/* Complete prior accesses before requesting a queue pause. */
		wmb();

		/* SW pause
		 */
		len = rd32(hw, aq->arq.len);

		if (len & NSE_REG_AQM_QLEN_STAT_Q_PAUSE_N_M) {
			len &= ~(NSE_REG_AQM_QLEN_STAT_BIT_M |
				 NSE_REG_AQM_QLEN_EXEC_M |
				 NSE_REG_AQM_QLEN_OP_M);

			len |= ((NSE_CTLQ_STAT_BIT_IDX_Q_PAUSE_N
				 << NSE_REG_AQM_QLEN_STAT_BIT_S) |
				NSE_REG_AQM_QLEN_EXEC_M |
				(NSE_REG_AQM_QLEN_OP_CLR_STAT
				 << NSE_REG_AQM_QLEN_OP_S));

			wr32(hw, aq->arq.len, len);

			nsevf_flush(hw);

			total_wait = 0;

			do {
				nsevf_aq_wait(wait_timeout_tick);

				len = rd32(hw, aq->arq.len);

				if (!(len &
				      NSE_REG_AQM_QLEN_STAT_Q_PAUSE_N_M)) {
					nsevf_debug(hw, NSEVF_DBG_SYS,
						    "[%s] DONE: SW clear mq_rq q_pause_n, wait times=%d\n",
						__func__, total_wait);
					break;
				}

				if (nsevf_is_regval_reset_magic(len)) {
					nsevf_debug(hw, NSEVF_DBG_SYS,
						    "[%s, %d] arq.len is reset magic: 0x%X, maybe in reset, return early\n",
						__func__, __LINE__, len);
					goto skip_sw_shutdown;
				}

				total_wait++;

			} while (total_wait < wait_timeout);

			len = rd32(hw, aq->arq.len);

			if (len & NSE_REG_AQM_QLEN_STAT_Q_PAUSE_N_M) {
				hw->controlq_stats
					.mq_rq_wait_for_sw_pause_fail_cnt++;
				hw->controlq_stats
					.mq_rq_wait_for_sw_pause_fail_time =
					ktime_to_ns(ktime_get());

				dev_info(dev,
					 "WARN: timeout: SW clear mq_rq q_pause_n, rq_len=0x%X\n",
					len);
				dev_info(dev, "\t now is: %ld ns\n",
					 (unsigned long)hw->controlq_stats
						.mq_rq_wait_for_sw_pause_fail_time);
			}
		}

		/* Complete the pause request before disabling the queue. */
		wmb();

		/* SW disable
		 *
		 * even SW pause timeout, continue anyway to disable procedure....
		 */

		len = rd32(hw, aq->arq.len);

		if (len & NSE_REG_AQM_QLEN_STAT_Q_EN_M) {
			len &= ~(NSE_REG_AQM_QLEN_STAT_BIT_M |
				 NSE_REG_AQM_QLEN_EXEC_M |
				 NSE_REG_AQM_QLEN_OP_M);

			len |= ((NSE_CTLQ_STAT_BIT_IDX_Q_EN
				 << NSE_REG_AQM_QLEN_STAT_BIT_S) |
				NSE_REG_AQM_QLEN_EXEC_M |
				(NSE_REG_AQM_QLEN_OP_CLR_STAT
				 << NSE_REG_AQM_QLEN_OP_S));

			wr32(hw, aq->arq.len, len);

			nsevf_flush(hw);

			total_wait = 0;

			do {
				nsevf_aq_wait(wait_timeout_tick);

				len = rd32(hw, aq->arq.len);

				if (!(len & NSE_REG_AQM_QLEN_STAT_Q_EN_M)) {
					nsevf_debug(hw, NSEVF_DBG_SYS,
						    "[%s] DONE: SW clear mq_rq q_en, wait times=%d\n",
						__func__, total_wait);
					break;
				}

				if (nsevf_is_regval_reset_magic(len)) {
					nsevf_debug(hw, NSEVF_DBG_SYS,
						    "[%s, %d] arq.len is reset magic: 0x%X, maybe in reset, return early\n",
						__func__, __LINE__, len);
					goto skip_sw_shutdown;
				}

				total_wait++;

			} while (total_wait < wait_timeout);

			len = rd32(hw, aq->arq.len);

			if (len & NSE_REG_AQM_QLEN_STAT_Q_EN_M) {
				hw->controlq_stats
					.mq_rq_wait_for_sw_disable_fail_cnt++;
				hw->controlq_stats
					.mq_rq_wait_for_sw_disable_fail_time =
					ktime_to_ns(ktime_get());

				dev_info(dev,
					 "WARN: timeout: SW clear mq_rq q_en, rq_len=0x%X\n",
					len);
				dev_info(dev, "\t now is: %ld ns\n",
					 (unsigned long)hw->controlq_stats
						.mq_rq_wait_for_sw_disable_fail_time);
			}
		}
	}

	/* Complete queue shutdown before clearing its configuration. */
	wmb();

	wr32(hw, aq->arq.len, 0);

	nsevf_flush(hw);
	nsevf_aq_wait(5000); /* 5 ms delay */

	wr32(hw, aq->arq.head, 0);

	wr32(hw, aq->arq.tail, 0);

skip_sw_shutdown:

	msleep(100);

	aq->arq.count = 0; /* to indicate uninitialized queue */

	/* free ring buffers */
	nsevf_free_arq_bufs(hw, aq);

shutdown_arq_out:

	nsevf_release_spinlock(&aq->arq_spinlock);

	return ret_code;
}

/**
 *  nsevf_init_mailboxq - main initialization routine for mailbox queue
 *  @hw: pointer to the hardware structure
 *
 *  Prior to calling this function, drivers *MUST* set the following fields
 *  in the hw->mailboxq structure:
 *     - hw->mailboxq.num_asq_entries
 *     - hw->mailboxq.num_arq_entries
 *     - hw->mailboxq.arq_buf_size
 *     - hw->mailboxq.asq_buf_size
 **/
enum nsevf_status nsevf_init_mailboxq(struct nsevf_hw *hw)
{
	struct nsevf_ctl_q_info *mq = &hw->mailboxq;
	enum nsevf_status ret_code = NSEVF_SUCCESS;

	/* verify input for valid configuration */
	if (mq->num_arq_entries == 0 || mq->num_asq_entries == 0 ||
	    mq->arq_buf_size == 0 || mq->asq_buf_size == 0) {
		ret_code = NSEVF_ERR_CONFIG;
		goto init_adminq_exit;
	}

	mq->qtype = NSEVF_CTL_Q_MAILBOX;

	nsevf_init_spinlock(&mq->asq_spinlock);
	nsevf_init_spinlock(&mq->arq_spinlock);

	/* Set up register offsets */
	nsevf_mailboxq_init_regs(hw, mq);

	/* setup ASQ command write back timeout */
	mq->asq_cmd_timeout =
		(NSE_CTL_Q_SQ_CMD_TIMEOUT_BASE * nse_timeout_scale);

	/* after nsevf_mailboxq_init_regs(), because we need to know mbx registers. */
	if (nsevf_use_msgbox)
		return nsevf_msgbox_init_mailboxq(hw);

	/* allocate the ASQ */
	ret_code = nsevf_init_asq(hw, mq);
	if (ret_code)
		goto init_adminq_destroy_spinlocks;

	/* allocate the ARQ */
	ret_code = nsevf_init_arq(hw, mq);
	if (ret_code)
		goto init_adminq_free_asq;

	/* success! */

	goto init_adminq_exit;

init_adminq_free_asq:
	nsevf_shutdown_asq(hw, mq, 0);
init_adminq_destroy_spinlocks:
	nsevf_destroy_spinlock(&mq->asq_spinlock);
	nsevf_destroy_spinlock(&mq->arq_spinlock);

init_adminq_exit:
	return ret_code;
}

/**
 *  nsevf_shutdown_mailboxq - shutdown routine for the mailbox queue
 *  @hw: pointer to the hardware structure
 **/
enum nsevf_status nsevf_shutdown_mailboxq(struct nsevf_hw *hw)
{
	struct nsevf_adapter *adapter = (struct nsevf_adapter *)hw->back;
	struct nsevf_ctl_q_info *mq = &hw->mailboxq;
	bool asq_alive = nsevf_check_asq_alive(hw, mq);
	enum nsevf_status ret_code = 0;

	nsevf_debug(hw, NSEVF_DBG_SYS, "[%s] asq_alive=%d\n", __func__,
		    asq_alive);

	if (nsevf_use_msgbox)
		return ret_code;

	/* Complete prior mailbox operations before testing ASQ state. */
	mb();

	if (asq_alive)
		(void)nsevf_aq_shutdown_mailboxq(hw);

	/* Complete firmware shutdown before releasing queue resources. */
	mb();

	nsevf_shutdown_asq(hw, mq,
			   asq_alive ? NSE_SHUTDOWN_CTLQ_FLAG_WAIT_FW_SHUTDOWN :
				       0);
	nsevf_shutdown_arq(hw, mq,
			   asq_alive ? NSE_SHUTDOWN_CTLQ_FLAG_WAIT_FW_SHUTDOWN :
				       0);
	nsevf_destroy_spinlock(&mq->asq_spinlock);
	nsevf_destroy_spinlock(&mq->arq_spinlock);

	mutex_lock(&adapter->misc_mutex);
	adapter->sw_shutdown_mq_imm = false;
	mutex_unlock(&adapter->misc_mutex);

	return ret_code;
}

enum nsevf_status nsevf_fdir_init_utilq(struct nsevf_hw *hw)
{
	struct nsevf_adapter *adapter = (struct nsevf_adapter *)hw->back;
	struct device *dev = nsevf_adapter_to_dev(adapter);
	struct nsevf_ctl_q_info *uq = &hw->utilq;
	u32 reg;
	enum nsevf_status status = NSEVF_SUCCESS;

	hw->utilq_initialized = false;

	if (!(adapter->flags & NSEVF_FLAG_FDIR_CAPABLE))
		goto out;

	uq->qtype = NSEVF_CTL_Q_UTIL;

	uq->num_asq_entries = NSEVF_UTILQ_SQ_LEN;
	uq->asq_buf_size = NSEVF_MAX_AQ_BUF_SIZE;

	uq->asq_cmd_timeout =
		(NSE_CTL_Q_SQ_CMD_TIMEOUT_BASE * nse_timeout_scale);

	nsevf_init_spinlock(&uq->asq_spinlock);

	nsevf_utilq_init_regs(hw, uq);

	status = nsevf_init_asq(hw, uq);
	if (status) {
		dev_err(dev, "[%s] FAIL: init_asq(), status=%d\n", __func__,
			status);
		goto fail;
	}

	/* Make queue initialization visible before programming utility control. */
	mb();

	reg = ((u32)adapter->vf_res->pf_id << NSEVF_REG_UTI_CTL_PF_IDX_S) &
	      NSEVF_REG_UTI_CTL_PF_IDX_M;

	wr32(hw, NSEVF_REG_UTI_CTL, reg);

	hw->utilq_initialized = true;

	status = NSEVF_SUCCESS;

out:
	return status;

fail:
	nsevf_destroy_spinlock(&uq->asq_spinlock);

	adapter->flags &= ~NSEVF_FLAG_FDIR_CAPABLE;

	goto out;
}

void nsevf_fdir_shutdown_utilq(struct nsevf_hw *hw)
{
	struct nsevf_adapter *adapter = (struct nsevf_adapter *)hw->back;
	struct nsevf_ctl_q_info *uq = &hw->utilq;

	if (!(adapter->flags & NSEVF_FLAG_FDIR_CAPABLE) ||
	    !hw->utilq_initialized)
		return;

	(void)nsevf_shutdown_asq(hw, uq, 0);

	nsevf_destroy_spinlock(&uq->asq_spinlock);

	hw->utilq_initialized = false;
}

/**
 *  nsevf_clean_asq - cleans Admin send queue
 *  @hw: pointer to the hardware structure
 *  @aq: pointer to the control queue information
 *
 *  returns the number of free desc
 **/
static u16 nsevf_clean_asq(struct nsevf_hw *hw, struct nsevf_ctl_q_info *aq)
{
	struct device *dev = nsevf_hw_to_dev(hw);
	struct nsevf_ctl_q_ring *asq = &aq->asq;
	struct nsevf_asq_cmd_details *details;
	u16 ntc = asq->next_to_clean;
	struct nsevf_aq_desc desc_cb;
	struct nsevf_aq_desc *desc;
	u16 head_val;

	desc = NSEVF_AQM_Q_DESC(*asq, ntc);
	details = NSEVF_AQM_Q_DETAILS(*asq, ntc);

	while ((head_val = rd32(hw, aq->asq.head)) != ntc) {
		if (head_val >= aq->num_asq_entries ||
		    nsevf_is_regval_reset_magic(head_val)) {
			dev_err(dev,
				"[%s, %d] head overrun at: %d (%X) or reset detected in the Control Send Queue ring\n",
				__func__, __LINE__, head_val, head_val);
			break;
		}

		if (details->callback) {
			NSEVF_ADMINQ_CALLBACK cb_func =
				(NSEVF_ADMINQ_CALLBACK)details->callback;
			memcpy(&desc_cb, desc, sizeof(struct nsevf_aq_desc));
			cb_func(hw, &desc_cb);
		}
		memset(desc, 0, sizeof(*desc));
		memset(details, 0, sizeof(*details));
		ntc++;
		if (ntc == asq->count)
			ntc = 0;
		desc = NSEVF_AQM_Q_DESC(*asq, ntc);
		details = NSEVF_AQM_Q_DETAILS(*asq, ntc);
	}

	asq->next_to_clean = ntc;

	return NSEVF_DESC_UNUSED(asq);
}

static u16 nsevf_clean_asq_by_dd(struct nsevf_hw *hw,
				 struct nsevf_ctl_q_info *aq)
{
	struct nsevf_ctl_q_ring *asq = &aq->asq;
	struct nsevf_asq_cmd_details *details;
	u16 ntc = asq->next_to_clean;
	struct nsevf_aq_desc desc_cb;
	struct nsevf_aq_desc *desc;

	desc = NSEVF_AQM_Q_DESC(*asq, ntc);
	details = NSEVF_AQM_Q_DETAILS(*asq, ntc);

	while (1) {
		if (le16_to_cpu(desc->flags) & NSE_AQ_FLAG_DD) {
			if (details->callback) {
				NSEVF_ADMINQ_CALLBACK cb_func =
					(NSEVF_ADMINQ_CALLBACK)details->callback;
				memcpy(&desc_cb, desc,
				       sizeof(struct nsevf_aq_desc));
				cb_func(hw, &desc_cb);
			}
			memset(desc, 0, sizeof(*desc));
			memset(details, 0, sizeof(*details));
			ntc++;
			if (ntc == asq->count)
				ntc = 0;
			desc = NSEVF_AQM_Q_DESC(*asq, ntc);
			details = NSEVF_AQM_Q_DETAILS(*asq, ntc);
		} else { /* !DD */
			break;
		}
	}

	asq->next_to_clean = ntc;

	return NSEVF_DESC_UNUSED(asq);
}

/**
 *  nsevf_asq_done - check if FW has processed the Admin Send Queue
 *  @hw: pointer to the hw struct
 *  @aq: pointer to the control queue information
 *  @desc_on_ring: descriptor currently on the send queue
 *
 *  Returns true if the firmware has processed all descriptors on the
 *  admin send queue. Returns false if there are still requests pending.
 **/
bool nsevf_asq_done(struct nsevf_hw *hw, struct nsevf_ctl_q_info *aq,
		    struct nsevf_aq_desc *desc_on_ring)
{
	if (nsevf_use_msgbox)
		return true;

	if (nse_aq_cmd_check_dd && desc_on_ring)
		return (le16_to_cpu(desc_on_ring->flags) & NSE_AQ_FLAG_DD);

	return rd32(hw, aq->asq.head) == aq->asq.next_to_use;
}

static bool
nsevf_asq_send_command_detect_reset_in_wait(struct nsevf_hw *hw,
					    struct nsevf_ctl_q_info *aq)
{
	struct nsevf_adapter *adapter = (struct nsevf_adapter *)hw->back;
	u32 val = 0;

	if (adapter->in_os_reset) {
		nsevf_debug(hw, NSEVF_DBG_SYS, "[%s, %d] in_os_reset = TRUE\n",
			    __func__, __LINE__);
		goto detect;
	}

	if (!nsevf_check_asq_alive(hw, aq)) {
		nsevf_debug(hw, NSEVF_DBG_SYS, "[%s, %d] asq_alive() = FALSE\n",
			    __func__, __LINE__);
		goto detect;
	}

	/* only mailboxq have this extra RQ check, utilq does not (it does not have RQ) */
	if (aq->qtype == NSEVF_CTL_Q_MAILBOX) {
		val = rd32(hw, aq->arq.bal);
		if (nsevf_is_regval_reset_magic(val) ||
		    val == NSE_REG_AQM_BA_MAGIC_DEINIT ||
		    val == NSE_REG_VMBX_ARQBAL_MAGIC_PF_INIT) {
			nsevf_debug(hw, NSEVF_DBG_SYS,
				    "[%s, %d] aq.arq.bal = %X\n", __func__,
				    __LINE__, val);
			goto detect;
		}
	}

	return false;

detect:
	return true;
}

/**
 *  nsevf_asq_send_command - send command to Admin Queue
 *  @hw: pointer to the hw struct
 *  @aq: pointer to the control queue information
 *  @desc: prefilled descriptor describing the command (non DMA mem)
 *  @buff: buffer to use for indirect commands
 *  @buff_size: size of buffer for indirect commands
 *  @cmd_details: pointer to command details structure
 *
 *  This is the main send command driver routine for the Admin Queue send
 *  queue.  It runs the queue, cleans the queue, etc
 **/
enum nsevf_status
nsevf_asq_send_command(struct nsevf_hw *hw, struct nsevf_ctl_q_info *aq,
		       struct nsevf_aq_desc *desc, void *buff, /* can be NULL */
		       u16 buff_size, struct nsevf_asq_cmd_details *cmd_details)
{
	enum nsevf_status status = 0;
	struct nsevf_adapter *adapter = (struct nsevf_adapter *)hw->back;
	struct device *dev = nsevf_adapter_to_dev(adapter);
	struct nsevf_dma_mem *dma_buff = NULL;
	struct nsevf_asq_cmd_details *details;
	struct nsevf_aq_desc *desc_on_ring;
	bool cmd_completed = false;
	u16 retval = 0;
	u32 val = 0;
	u16 free_slot;
	u32 sq_len;
	u32 sq_cmd_timeout;
	u32 sq_cmd_timeout_tick = NSE_CTL_Q_SQ_CMD_USEC;

	sq_cmd_timeout = (NSE_CTL_Q_SQ_CMD_TIMEOUT_BASE * nse_timeout_scale);

	nsevf_acquire_spinlock(&aq->asq_spinlock);

	if (adapter->in_os_reset) {
		nsevf_debug(hw, NSEVF_DBG_SYS, "[%s, %d] in_os_reset = TRUE\n",
			    __func__, __LINE__);
		status = NSEVF_ERR_NOT_READY;
		goto asq_send_command_error;
	}

	sq_len = rd32(hw, aq->asq.len);

	if (nsevf_is_regval_reset_magic(sq_len)) {
		nsevf_debug(hw, NSEVF_DBG_SYS,
			    "[%s, %d] asq.len is reset magic: 0x%X, maybe in reset, return early\n",
			__func__, __LINE__, sq_len);
		status = NSEVF_ERR_NOT_READY;
		goto asq_send_command_error;
	}

	if (!(sq_len & NSE_REG_AQM_QLEN_STAT_Q_PAUSE_N_M) ||
	    !(sq_len & NSE_REG_AQM_QLEN_STAT_Q_EN_M)) {
		nsevf_debug(hw, NSEVF_DBG_SYS,
			    "[%s, %d] VF mailboxq not ready, sq_len=0x%X\n",
			    __func__, __LINE__, sq_len);
		status = NSEVF_ERR_NOT_READY;
		goto asq_send_command_error;
	}

	aq->asq_last_status = NSE_AQ_RC_OK;

	if (aq->asq.count == 0) {
		dev_err(dev, "AQTX: Admin queue not initialized.\n");
		status = NSEVF_ERR_QUEUE_EMPTY;
		goto asq_send_command_error;
	}

	val = rd32(hw, aq->asq.head);

	if (nsevf_is_regval_reset_magic(val)) {
		nsevf_debug(hw, NSEVF_DBG_SYS,
			    "[%s, %d] asq.head is reset magic: 0x%X, maybe in reset, return early\n",
			__func__, __LINE__, val);
		status = NSEVF_ERR_QUEUE_EMPTY;
		goto asq_send_command_error;
	}

	if (val >= aq->num_asq_entries) {
		dev_err(dev,
			"[%s, %d] head overrun at: %d (%X) in the Control Send Queue ring\n",
			__func__, __LINE__, val, val);
		status = NSEVF_ERR_QUEUE_EMPTY;
		goto asq_send_command_error;
	}

	details = NSEVF_AQM_Q_DETAILS(aq->asq, aq->asq.next_to_use);
	if (cmd_details) {
		memcpy(details, cmd_details,
		       sizeof(struct nsevf_asq_cmd_details));
	} else {
		memset(details, 0, sizeof(struct nsevf_asq_cmd_details));
	}

	/* clear requested flags and then set additional flags if defined */
	desc->flags &= ~cpu_to_le16(details->flags_dis);
	desc->flags |= cpu_to_le16(details->flags_ena);

	if (buff_size > aq->asq_buf_size) {
		dev_err(dev, "AQTX: Invalid buffer size: %d.\n", buff_size);
		status = NSEVF_ERR_INVALID_SIZE;
		goto asq_send_command_error;
	}

	if (details->postpone && !details->async) {
		dev_err(dev,
			"AQTX: Async flag not set along with postpone flag");
		status = NSEVF_ERR_PARAM;
		goto asq_send_command_error;
	}

	/* call clean and check queue available function to reclaim the
	 * descriptors that were processed by FW, the function returns the
	 * number of desc available
	 */
	/* the clean function called here could be called in a separate thread
	 * in case of asynchronous completions
	 */
	if (nse_aq_cmd_check_dd)
		free_slot = nsevf_clean_asq_by_dd(hw, aq);
	else
		free_slot = nsevf_clean_asq(hw, aq);

	if (free_slot == 0) {
		dev_err(dev, "AQTX: Error queue is full.\n");
		status = NSEVF_ERR_ADMIN_QUEUE_FULL;
		goto asq_send_command_error;
	}

	/* initialize the temp desc pointer with the right desc */
	desc_on_ring = NSEVF_AQM_Q_DESC(aq->asq, aq->asq.next_to_use);

	/* if the desc is available copy the temp desc to the right place */
	memcpy(desc_on_ring, desc, sizeof(struct nsevf_aq_desc));

	/* if buff is not NULL assume indirect command */
	if (buff) {
		dma_buff = &aq->asq.r.asq_bi[aq->asq.next_to_use];
		/* copy the user buff into the respective DMA buff */
		memcpy(dma_buff->va, buff, buff_size);
		desc_on_ring->datalen = cpu_to_le16(buff_size);

		/* Update the address values in the desc with the pa value
		 * for respective buffer
		 */
		desc_on_ring->addr_high =
			cpu_to_le32(upper_32_bits(dma_buff->pa));
		desc_on_ring->addr_low =
			cpu_to_le32(lower_32_bits(dma_buff->pa));
	}

	nsevf_debug(hw, NSEVF_DBG_AQM_DESC, "AQTX: desc and buffer:\n");

	nsevf_debug_aq(hw, (void *)desc_on_ring, buff, buff_size);

	if (adapter->in_os_reset) {
		nsevf_debug(hw, NSEVF_DBG_SYS, "[%s, %d] in_os_reset = TRUE\n",
			    __func__, __LINE__);
		status = NSEVF_ERR_NOT_READY;
		goto asq_send_command_error;
	}

	/* bump the tail */
	(aq->asq.next_to_use)++;
	if (aq->asq.next_to_use == aq->asq.count)
		aq->asq.next_to_use = 0;
	if (!details->postpone)
		wr32(hw, aq->asq.tail, aq->asq.next_to_use);

	/* if cmd_details are not defined or async flag is not set,
	 * we need to wait for desc write back
	 */
	if (!details->async && !details->postpone) {
		u32 total_wait = 1;

		do {
			nsevf_aq_wait(sq_cmd_timeout_tick);

			/* though name as "no_wait", but still wait for one time. */
			if (nse_sq_cmd_is_no_wait(desc->opc_category,
						  desc->opc_subcode))
				break;

			if (nsevf_asq_done(hw, aq, desc_on_ring))
				break;

			/* detect every 16 wait, not every wait, not too often */
			if (!(total_wait & 0xF) &&
			    nsevf_asq_send_command_detect_reset_in_wait(hw,
									aq)) {
				nsevf_debug(hw, NSEVF_DBG_SYS,
					    "[%s, %d] detect_reset_in_wait() = TRUE, quick exit wait\n",
					__func__, __LINE__);
				status = NSEVF_ERR_NOT_READY;
				goto asq_send_command_error;
			}

			total_wait++;

			hw->controlq_stats.sq_total_wait_cnt++;

		} while (total_wait < sq_cmd_timeout);
	}

	/* if ready, copy the desc back to temp */
	if (nsevf_asq_done(hw, aq, desc_on_ring)) {
		memcpy(desc, desc_on_ring, sizeof(struct nsevf_aq_desc));
		if (buff)
			memcpy(buff, dma_buff->va, buff_size);
		retval = (le16_to_cpu(desc->flags) & NSE_AQ_FLAG_RETVAL_M) >>
			 NSE_AQ_FLAG_RETVAL_S;
		if (retval != 0) {
			dev_err(dev,
				"[%s, %d] Control Send Queue command 0x%04X completed write-back with desc->RETVAL=0x%X(%s)\n",
				__func__, __LINE__, le16_to_cpu(desc->opcode),
				retval,
				nsevf_aq_str(hw, (enum nse_aq_err)retval));
		}
		cmd_completed = true;
		if (retval == NSE_AQ_RC_OK)
			status = 0;
		else if (retval == NSE_AQ_RC_EBUSY)
			status = NSEVF_ERR_NOT_READY;
		else
			status = NSEVF_ERR_ADMIN_QUEUE_ERROR;
		aq->asq_last_status = retval;
	}

	nsevf_debug(hw, NSEVF_DBG_AQM_DESC,
		    "AQTX: desc and buffer writeback:\n");

	nsevf_debug_aq(hw, (void *)desc, buff, buff_size);

	/* save writeback aq if requested */
	if (details->wb_desc)
		memcpy(details->wb_desc, desc_on_ring,
		       sizeof(struct nsevf_aq_desc));

	/* update the error if time out occurred */
	if (!cmd_completed && (!details->async && !details->postpone)) {
		if (rd32(hw, aq->asq.len) & NSEVF_REG_MBX_ATQLEN_CRIT_M) {
			dev_err(dev, "AQTX: AQ Critical error.\n");
			status = NSEVF_ERR_ADMIN_QUEUE_CRITICAL_ERROR;
		} else {
			dev_err(dev, "AQTX: Writeback timeout.\n");
			status = NSEVF_ERR_ADMIN_QUEUE_TIMEOUT;
		}
	}

asq_send_command_error:
	nsevf_release_spinlock(&aq->asq_spinlock);
	return status;
}

/**
 *  nsevf_fill_default_direct_cmd_desc - AQ descriptor helper function
 *  @desc:     pointer to the temp descriptor (non DMA mem)
 *  @opc_category: command opcode category
 *  @opc_subcode: command opcode subcode
 *
 *  Fill the desc with default values
 **/
void nsevf_fill_default_direct_cmd_desc(struct nsevf_aq_desc *desc,
					u8 opc_category, u8 opc_subcode)
{
	/* zero out the desc */
	memset((void *)desc, 0, sizeof(struct nsevf_aq_desc));
	desc->opc_category = opc_category;
	desc->opc_subcode = opc_subcode;
	desc->flags = cpu_to_le16(NSE_AQ_FLAG_SI); /* Do not generate IRQ on complete */

	/* by default, we send to PF driver */
	desc->mailbox_id = cpu_to_le16(NSE_AQ_MAILBOX_ID_PF);
}

/**
 *  nsevf_clean_arq_element
 *  @hw: pointer to the hw struct
 *  @aq: pointer to the control queue information
 *  @e: event info from the receive descriptor, includes any buffers
 *  @pending: number of events that could be left to process
 *
 *  This function cleans one Admin Receive Queue element and returns
 *  the contents through e.  It can also return how many events are
 *  left to process through 'pending'
 **/
enum nsevf_status nsevf_clean_arq_element(struct nsevf_hw *hw,
					  struct nsevf_ctl_q_info *aq,
					  struct nsevf_arq_event_info *e,
					  u16 *pending)
{
	struct device *dev = nsevf_hw_to_dev(hw);
	enum nsevf_status ret_code = 0;
	u16 ntc = aq->arq.next_to_clean;
	struct nsevf_aq_desc *desc;
	struct nsevf_dma_mem *bi;
	u16 desc_idx;
	u16 datalen;
	u16 flags;
	u32 head_val;
	u16 ntu;

	/* pre-clean the event info */
	memset(&e->desc, 0, sizeof(e->desc));

	/* take the lock before we start messing with the ring */
	nsevf_acquire_spinlock(&aq->arq_spinlock);

	if (aq->arq.count == 0) {
		dev_err(dev, "AQRX: Admin queue not initialized.\n");
		ret_code = NSEVF_ERR_QUEUE_EMPTY;
		goto clean_arq_element_err;
	}

	/* set next_to_use to head */
	head_val = rd32(hw, aq->arq.head);
	if (nsevf_is_regval_reset_magic(head_val)) {
		dev_err(dev, "AQRX: reset detected, return early\n");
		ret_code = NSEVF_ERR_QUEUE_EMPTY;
		goto clean_arq_element_err;
	}

	ntu = head_val & NSEVF_REG_MBX_ARQH_HEAD_M;
	if (ntu == ntc) {
		/* nothing to do - shouldn't need to update ring's values */
		ret_code = NSEVF_ERR_ADMIN_QUEUE_NO_WORK;
		goto clean_arq_element_out;
	}

	/* now clean the next descriptor */
	desc = NSEVF_AQM_Q_DESC(aq->arq, ntc);
	desc_idx = ntc;

	flags = le16_to_cpu(desc->flags);
	aq->arq_last_status =
		(enum nse_aq_err)((flags & NSE_AQ_FLAG_RETVAL_M) >>
				  NSE_AQ_FLAG_RETVAL_S);
	if (aq->arq_last_status != NSE_AQ_RC_OK) {
		ret_code = NSEVF_ERR_ADMIN_QUEUE_ERROR;
		dev_err(dev, "AQRX: Event received with error 0x%X.\n",
			aq->arq_last_status);
	}

	memcpy(&e->desc, desc, sizeof(struct nsevf_aq_desc));
	datalen = le16_to_cpu(desc->datalen);
	e->msg_len = min(datalen, e->buf_len);
	if (e->msg_buf && e->msg_len != 0)
		memcpy(e->msg_buf, aq->arq.r.arq_bi[desc_idx].va, e->msg_len);

	nsevf_debug(hw, NSEVF_DBG_AQM_DESC, "AQRX: desc and buffer:\n");

	nsevf_debug_aq(hw, (void *)desc, e->msg_buf, aq->arq_buf_size);

	/* Restore the original datalen and buffer address in the desc,
	 * FW updates datalen to indicate the event message
	 * size
	 */
	bi = &aq->arq.r.arq_bi[ntc];
	memset((void *)desc, 0, sizeof(struct nsevf_aq_desc));

	desc->flags = cpu_to_le16(NSE_AQ_FLAG_BUF);
	if (aq->arq_buf_size > NSEVF_AQ_LARGE_BUF)
		desc->flags |= cpu_to_le16(NSE_AQ_FLAG_LB);
	desc->datalen = cpu_to_le16((u16)bi->size);
	desc->addr_high = cpu_to_le32(upper_32_bits(bi->pa));
	desc->addr_low = cpu_to_le32(lower_32_bits(bi->pa));

	/* set tail = the last cleaned desc index. */
	wr32(hw, aq->arq.tail, ntc);
	/* ntc is updated to tail + 1 */
	ntc++;
	if (ntc == aq->num_arq_entries)
		ntc = 0;
	aq->arq.next_to_clean = ntc;
	aq->arq.next_to_use = ntu;

clean_arq_element_out:
	/* Set pending if needed, unlock and return */
	if (pending)
		*pending = (ntc > ntu ? aq->arq.count : 0) + (ntu - ntc);
clean_arq_element_err:
	nsevf_release_spinlock(&aq->arq_spinlock);

	return ret_code;
}
