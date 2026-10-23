// SPDX-License-Identifier: GPL-2.0
/* Nebula-matrix DPDK user-network
 * Copyright(c) 2021-2030 nbl, Inc.
 */

#include <linux/string.h>
#include "nbl_cmdq.h"

static u8 g_seq_index;
spinlock_t nbl_tc_flow_inst_lock; /* used to protect global instance resources */

static void
nbl_draco_cmdq_debug_show_desc(const struct nbl_draco_cmd_desc *desc, u32 index,
			       struct nbl_common_info *common)
{
	nbl_err(common, NBL_DEBUG_FLOW, "DESC [0x%x: %p] {cmd_status 0x%x, cmd_type 0x%x, module:%u, table:%u, opcode 0x%x, datalen 0x%x, exe_status 0x%x, errcode 0x%x, param 0x%x-0x%x; in buffer 0x%x-0x%x, out buffer 0x%x-0x%x}\n",
		index, desc, desc->cmd_status, desc->cmd_type,
		desc->module, desc->table, desc->opcode, desc->cmd_len, desc->exe_status,
		desc->errcode, desc->param_high, desc->param_low, desc->send_low,
		desc->send_high, desc->recv_low, desc->recv_high);
}

static inline void *nbl_cmdq_alloc_dma_mem(struct device *dma_dev,
					   struct nbl_cmdq_dma_mem *mem,
					   u32 size) {
	mem->size = size;
	return dma_alloc_coherent(dma_dev, size, &mem->pa, GFP_KERNEL | __GFP_ZERO);
}

static inline void nbl_cmdq_free_dma_mem(struct device *dma_dev,
					 struct nbl_cmdq_dma_mem *mem) {
	dma_free_coherent(dma_dev, mem->size, mem->va, mem->pa);
	mem->size = 0;
	mem->va = NULL;
	mem->pa = (dma_addr_t)0;
}

static inline void
nbl_cmdq_free_queue_ring(struct device *dma_dev, struct nbl_cmd_ring *ring)
{
	nbl_cmdq_free_dma_mem(dma_dev, &ring->desc);
}

/**
 * @brief: free the buffer for the send ring
 * @cmd_queue: pointer to the command queue
 */
static enum nbl_cmd_status
nbl_cmdq_alloc_queue_bufs(const struct nbl_cmd_queue *queue,
			  struct nbl_cmd_ring *ring)
{
	int i;
	struct nbl_cmdq_dma_mem *bi;
	struct nbl_channel_mgt *chan_mgt = queue->chan_mgt;
	struct device *dma_dev = chan_mgt->common->dma_dev;

	/* No mapped memory needed yet, just the buffer info structures */
	ring->in_buffer_dma_head = kcalloc(queue->cmd_ring_depth, sizeof(struct nbl_cmdq_dma_mem),
					   GFP_ATOMIC);
	if (!ring->in_buffer_dma_head)
		return -ENOMEM;

	ring->in_buffer_info = (struct nbl_cmdq_dma_mem *)ring->in_buffer_dma_head;

	/* allocate the mapped in buffers */
	ring->in_mem.va = nbl_cmdq_alloc_dma_mem(dma_dev, &ring->in_mem,
						 queue->sq_buf_size * queue->cmd_ring_depth);
	if (!ring->in_mem.va)
		goto dealloc_cmd_queue_in_bufs;

	for (i = 0; i < queue->cmd_ring_depth; i++) {
		bi = &ring->in_buffer_info[i];
		bi->va = (char *)ring->in_mem.va + i * queue->sq_buf_size;
		bi->pa = ring->in_mem.pa + i * queue->sq_buf_size;
		bi->size = queue->sq_buf_size;
	}

	/* alloc dma_mem array for out buffers */
	ring->out_buffer_dma_head = kcalloc(queue->cmd_ring_depth, sizeof(struct nbl_cmdq_dma_mem),
					    GFP_ATOMIC);
	if (!ring->out_buffer_dma_head)
		goto dealloc_cmd_queue_in_mem;

	ring->out_buffer_info = (struct nbl_cmdq_dma_mem *)ring->out_buffer_dma_head;

	/* allocate the mapped out buffers */
	ring->out_mem.va = nbl_cmdq_alloc_dma_mem(dma_dev, &ring->out_mem,
						  queue->sq_buf_size * queue->cmd_ring_depth);
	if (!ring->out_mem.va)
		goto dealloc_cmd_queue_out_bufs;

	for (i = 0; i < queue->cmd_ring_depth; i++) {
		bi = &ring->out_buffer_info[i];
		bi->va = (char *)ring->out_mem.va + i * queue->sq_buf_size;
		bi->pa = ring->out_mem.pa + i * queue->sq_buf_size;
		bi->size = queue->sq_buf_size;
	}

	return NBL_CMDQ_SUCCESS;

dealloc_cmd_queue_out_bufs:
	ring->out_buffer_info = NULL;
	kfree(ring->out_buffer_dma_head);
	ring->out_buffer_dma_head = NULL;
dealloc_cmd_queue_in_mem:
	nbl_cmdq_free_dma_mem(dma_dev, &ring->in_mem);
	for (i = 0; i < queue->cmd_ring_depth; i++) {
		bi = &ring->in_buffer_info[i];
		bi->va = NULL;
		bi->pa = 0;
		bi->size = 0;
	}

dealloc_cmd_queue_in_bufs:
	ring->in_buffer_info = NULL;
	kfree(ring->in_buffer_dma_head);
	ring->in_buffer_dma_head = NULL;
	return -ENOMEM;
}

/**
 * @brief: allocate buffers for the send ring
 * @cmd_queue: pointer to the command queue
 */
static enum nbl_cmd_status
nbl_cmdq_alloc_queue_ring(const struct nbl_cmd_queue *queue,
			  struct nbl_cmd_ring *ring)
{
	u32 size = queue->cmd_ring_depth * sizeof(struct nbl_cmd_desc);
	struct nbl_channel_mgt *chan_mgt = queue->chan_mgt;
	struct device *dma_dev = chan_mgt->common->dma_dev;

	ring->desc.va = nbl_cmdq_alloc_dma_mem(dma_dev, &ring->desc, size);
	if (!ring->desc.va)
		return -ENOMEM;

	return NBL_CMDQ_SUCCESS;
}

/**
 * @brief: free the buffer for the send ring
 * @cmd_queue: pointer to the command queue
 */
static void
nbl_cmdq_free_queue_bufs(struct device *dma_dev, struct nbl_cmd_ring *ring)
{
	/* free in buffers */
	if (ring->in_mem.va)
		nbl_cmdq_free_dma_mem(dma_dev, &ring->in_mem);

	/* free out buffers */
	if (ring->out_mem.va)
		nbl_cmdq_free_dma_mem(dma_dev, &ring->out_mem);

	/* free in and out DMA rings */
	kfree(ring->in_buffer_dma_head);
	kfree(ring->out_buffer_dma_head);
}

/**
 * @brief: init the send ring of command queue
 * @hw: input, pointer to the hardware related properties
 * @nbl_cmd_queue: pointer to the command queue
 */
static enum nbl_cmd_status
nbl_cmdq_init_sq_ring(struct nbl_cmd_queue *queue)
{
	enum nbl_cmd_status status;
	struct nbl_cmd_ring *ring = &queue->sq_ring;
	struct nbl_channel_mgt *chan_mgt = queue->chan_mgt;
	struct device *dma_dev = chan_mgt->common->dma_dev;

	/* check if the queue is already initialized */
	if (ring->count > 0) {
		status = NBL_CMDQ_NOT_READY;
		goto init_cmd_queue_exit;
	}

	status = nbl_cmdq_alloc_queue_ring(queue, ring);
	if (status)
		goto init_cmd_queue_exit;

	status = nbl_cmdq_alloc_queue_bufs(queue, ring);
	if (status)
		goto init_cmd_queue_free_rings;

	ring->next_to_use = 0;
	ring->next_to_clean = 0;
	ring->doorbell = 0;

	/* on success */
	ring->count = queue->cmd_ring_depth;
	goto init_cmd_queue_exit;

init_cmd_queue_free_rings:
	nbl_cmdq_free_queue_bufs(dma_dev, ring);
	nbl_cmdq_free_queue_ring(dma_dev, ring);

init_cmd_queue_exit:
	return status;
}

static void
nbl_cmdq_init_queue_parameters(struct nbl_cmd_queue *cmd_queue)
{
	cmd_queue->sq_buf_size = NBL_CMDQ_BUF_SIZE;
	cmd_queue->cmd_ring_depth = NBL_CMDQ_RING_DEPTH;
	cmd_queue->sq_ring.count = 0;
}

/**
 * @brief: shutdown the queue, will free the ring
 * @hw: input, pointer to the hardware related properties
 */
static enum nbl_cmd_status
nbl_cmdq_shutdown_queue(struct nbl_cmd_queue *queue,
			struct nbl_cmd_ring *ring)
{
	struct nbl_channel_mgt *chan_mgt = queue->chan_mgt;
	struct device *dma_dev = chan_mgt->common->dma_dev;

	/* reset cmd queue related registers */
	spin_lock(&queue->sq_lock);
	ring->count = 0;

	/* free cmd queue ring */
	nbl_cmdq_free_queue_bufs(dma_dev, ring);
	nbl_cmdq_free_queue_ring(dma_dev, ring);

	spin_unlock(&queue->sq_lock);
	return NBL_CMDQ_SUCCESS;
}

static inline enum nbl_cmd_status
nbl_cmdq_check_queue(const struct nbl_cmd_ring *ring, const struct nbl_common_info *common)
{
	if (!ring->count) {
		nbl_err(common, NBL_DEBUG_FLOW, "tc flow cmdq not initialized yet.");
		return NBL_CMDQ_CQ_NOT_READY;
	}

	return NBL_CMDQ_SUCCESS;
}

static enum nbl_cmd_status
nbl_cmdq_destroy_queue(struct nbl_cmd_queue *queue)
{
	enum nbl_cmd_status status = NBL_CMDQ_SUCCESS;
	struct nbl_cmd_ring *ring = &queue->sq_ring;
	struct nbl_common_info *common = queue->chan_mgt->common;

	/* check queue status, abort destroy if queue not ready */
	status = nbl_cmdq_check_queue(ring, common);
	if (status == NBL_CMDQ_CQ_NOT_READY)
		return status;

	/* shutdown queue */
	return nbl_cmdq_shutdown_queue(queue, ring);
}

static inline bool
nbl_cmdq_flag_check_cmd_done(const struct nbl_cmd_desc *desc) {
	return (desc->flags & NBL_CMDQ_DESC_FLAG_DONE);
}

static inline bool
nbl_draco_cmdq_flag_check_cmd_done(const struct nbl_draco_cmd_desc *desc)
{
	return (desc->cmd_status == NBL_CMD_STATUS_CLEAN_READY);
}

/**
 * @brief: free command queue ring and return free count
 * @cmd_queue: input, pointer to the hardware related properties
 * @return: number of free desc in the queue
 */
static enum nbl_cmd_status
nbl_cmdq_clean_sq_ring(struct nbl_cmd_queue *cmd_queue)
{
	struct nbl_cmd_ring *ring = &cmd_queue->sq_ring;
	u16 ntc = ring->next_to_clean;
	struct nbl_cmd_desc *desc = NBL_CMDQ_GET_DESC(*ring, ntc);

	while (1) {
		if (nbl_cmdq_flag_check_cmd_done(desc))
			memset(desc, 0, sizeof(*desc));
		else
			break;

		ntc++;
		if (ntc == ring->count)
			ntc = 0;

		/* next descriptor */
		desc = NBL_CMDQ_GET_DESC(*ring, ntc);
	}

	desc = NULL;
	ring->next_to_clean = ntc;
	return (ring->next_to_clean > ring->next_to_use ? 0 : ring->count)
		+ ring->next_to_clean - ring->next_to_use - 1;
}

static enum nbl_cmd_status
nbl_draco_cmdq_clean_sq_ring(struct nbl_cmd_queue *cmd_queue)
{
	struct nbl_cmd_ring *ring = &cmd_queue->sq_ring;
	u16 ntc = ring->next_to_clean;
	struct nbl_draco_cmd_desc *desc = NBL_DRACO_CMDQ_GET_DESC(*ring, ntc);

	while (1) {
		if (nbl_draco_cmdq_flag_check_cmd_done(desc))
			memset(desc, 0, sizeof(*desc));
		else
			break;

		ntc++;
		if (ntc == ring->count)
			ntc = 0;

		/* next descriptor */
		desc = NBL_DRACO_CMDQ_GET_DESC(*ring, ntc);
	}

	desc = NULL;
	ring->next_to_clean = ntc;
	return (ring->next_to_clean > ring->next_to_use ? 0 : ring->count)
		+ ring->next_to_clean - ring->next_to_use - 1;
}

/**
 * @brief: check the command queue to see if command processed
 * @desc: input, pointer to the hardware related properties
 * @desc: use this descriptor to check the DD bit
 */
static inline bool
nbl_cmdq_flag_check_dd(const struct nbl_cmd_desc *desc)
{
	return (desc->flags & NBL_CMDQ_DESC_FLAG_DD);
}

static inline bool
nbl_draco_cmdq_flag_check_dd(const struct nbl_draco_cmd_desc *desc)
{
	return (desc->cmd_status == NBL_CMD_STATUS_SW_READY) ||
	       (desc->cmd_status == NBL_CMD_STATUS_HW_ERROR);
}

static inline bool
nbl_cmdq_flag_check_out_buffer(const struct nbl_cmd_desc *desc)
{
	return (desc->flags & NBL_CMDQ_DESC_FLAG_BUF_OUT);
}

static inline bool
nbl_draco_cmdq_flag_check_out_buffer(const struct nbl_draco_cmd_desc *desc)
{
	return (desc->cmd_type >= NBL_CMD_TYPE_HW_W);
}

static inline bool
nbl_cmdq_flag_check_error(const struct nbl_cmd_desc *desc)
{
	return (desc->flags & NBL_CMDQ_DESC_FLAG_ERR);
}

static inline bool
nbl_draco_cmdq_flag_check_error(const struct nbl_draco_cmd_desc *desc)
{
	return (desc->cmd_status == NBL_CMD_STATUS_HW_ERROR);
}

static inline bool
nbl_cmdq_flag_check_hit(const struct nbl_cmd_desc *desc)
{
	return (desc->flags & NBL_CMDQ_DESC_FLAG_HIT);
}

static inline bool
nbl_draco_cmdq_flag_check_hit(const struct nbl_draco_cmd_desc *desc)
{
	return (desc->exe_status != NBL_CMD_EXE_STATUS_NOHIT);
}

static inline void
nbl_cmdq_flag_mark_cmd_done(struct nbl_cmd_desc *desc) {
	desc->flags |= NBL_CMDQ_DESC_FLAG_DONE;
}

static inline void
nbl_draco_cmdq_flag_mark_cmd_done(struct nbl_draco_cmd_desc *desc)
{
	desc->cmd_status = NBL_CMD_STATUS_CLEAN_READY;
}

static inline bool
nbl_cmdq_flag_check_interface_error(struct nbl_cmd_desc *desc) {
	return (desc->flags & NBL_CMDQ_DESC_FLAG_IF_ERR);
}

static enum nbl_cmd_status
nbl_cmdq_execution_nolock(struct nbl_cmd_queue *queue,
			  struct nbl_cmd_ring *ring,
			  const struct nbl_cmd_hdr *hdr,
			  struct nbl_cmd_desc *desc,
			  const struct nbl_cmd_content *cmd)
{
	struct nbl_phy_ops *phy_ops = NBL_CHAN_MGT_TO_PHY_OPS(queue->chan_mgt);
	struct nbl_common_info *common = queue->chan_mgt->common;

	/* clean the cmd send queue to reclaim descriptors */
	if (nbl_cmdq_clean_sq_ring(queue) == 0) {
		nbl_err(common, NBL_DEBUG_FLOW, "tc flow cmd send queue full!");
		return NBL_CMDQ_CQ_FULL;
	}

	/* fill descriptor */
	desc->block = cpu_to_le16(hdr->block);
	desc->module = cpu_to_le16(hdr->module);
	desc->table = cpu_to_le16(hdr->table);
	desc->opcode = cpu_to_le16(hdr->opcode);
	desc->param_high = cpu_to_le32(NBL_CMDQ_HI_DWORD(cmd->in_params));
	desc->param_low = cpu_to_le32(NBL_CMDQ_LO_DWORD(cmd->in_params));
	desc->flags = 0;
	desc->seq = g_seq_index++;
	if (g_seq_index == 16)
		g_seq_index = 0;

	/* data to send */
	if (cmd->in_va && cmd->in) {
		desc->datalen = cmd->in_length + NBL_CMDQ_HALF_DESC_LENGTH;
		desc->flags |= cpu_to_le16(NBL_CMDQ_DESC_FLAG_BUF_IN);
		desc->send_high = cpu_to_le32(NBL_CMDQ_HI_DWORD(cmd->in));
		desc->send_low = cpu_to_le32(NBL_CMDQ_LO_DWORD(cmd->in));
	}

	/* data to receive */
	if (cmd->out_va && cmd->out) {
		desc->flags |= cpu_to_le16(NBL_CMDQ_DESC_FLAG_BUF_OUT);
		desc->recv_high = cpu_to_le32(NBL_CMDQ_HI_DWORD(cmd->out));
		desc->recv_low = cpu_to_le32(NBL_CMDQ_LO_DWORD(cmd->out));
	}

	/* update next_to_use */
	(ring->next_to_use)++;
	(ring->doorbell)++;
	if (ring->next_to_use == ring->count)
		ring->next_to_use = 0;

	/* write barrier to ensure command writes complete before updating the tail */
	wmb();
	phy_ops->update_cmdq_tail(NBL_CHAN_MGT_TO_PHY_PRIV(queue->chan_mgt),
				  (ring->doorbell) & NBL_CMDQ_DOORBELL_MASK);
	return NBL_CMDQ_SUCCESS;
}

static enum nbl_cmd_status
nbl_draco_cmdq_execution_nolock(struct nbl_cmd_queue *queue,
				struct nbl_cmd_ring *ring,
				const struct nbl_cmd_hdr *hdr,
				struct nbl_draco_cmd_desc *desc,
				const struct nbl_cmd_content *cmd)
{
	struct nbl_phy_ops *phy_ops = NBL_CHAN_MGT_TO_PHY_OPS(queue->chan_mgt);
	union nbl_cmdq_notify_val value;
	struct nbl_common_info *common = queue->chan_mgt->common;

	memset(&value, 0, sizeof(value));

	/* clean the cmd send queue to reclaim descriptors */
	if (nbl_draco_cmdq_clean_sq_ring(queue) == 0) {
		nbl_err(common, NBL_DEBUG_FLOW, "tc flow cmd send queue full!");
		return NBL_CMDQ_CQ_FULL;
	}

	/* fill descriptor */
	desc->module = cpu_to_le16(hdr->module);
	desc->table = cpu_to_le16(hdr->table);
	desc->opcode = cpu_to_le16(hdr->opcode);
	desc->param_high = cpu_to_le32(NBL_HI_DWORD(cmd->in_params));
	desc->param_low = cpu_to_le32(NBL_LO_DWORD(cmd->in_params));
	desc->cmd_len = cmd->in_length;
	desc->exe_status = NBL_DRACO_CMD_NOHIT;

	/* data to send */
	if (cmd->in_va && cmd->in) {
		desc->send_high = cpu_to_le32(NBL_HI_DWORD(cmd->in));
		desc->send_low = cpu_to_le32(NBL_LO_DWORD(cmd->in));
	}

	/* data to receive */
	if (cmd->out_va && cmd->out) {
		desc->recv_high = cpu_to_le32(NBL_HI_DWORD(cmd->out));
		desc->recv_low = cpu_to_le32(NBL_LO_DWORD(cmd->out));
	}

	if (cmd->in_va && cmd->out_va)
		desc->cmd_type = NBL_CMD_TYPE_HW_RW;
	else if (cmd->in_va)
		desc->cmd_type = NBL_CMD_TYPE_HW_R;
	else if (cmd->out_va)
		desc->cmd_type = NBL_CMD_TYPE_HW_W;
	else
		desc->cmd_type = NBL_CMD_TYPE_BARE;

	/* update next_to_use */
	(ring->next_to_use)++;
	(ring->doorbell)++;
	if (ring->next_to_use == ring->count)
		ring->next_to_use = 0;

	/* wmb */
	wmb();
	value.info.qid = common->mgt_pf;
	value.info.tail_ptr = (uint16_t)ring->doorbell;
	phy_ops->update_cmdq_tail(NBL_CHAN_MGT_TO_PHY_PRIV(queue->chan_mgt), value.value);

	return NBL_CMDQ_SUCCESS;
}

static inline enum nbl_cmd_status
nbl_draco_cmdq_check_content(const struct nbl_cmd_queue *queue,
			     const struct nbl_cmd_content *cmd)
{
	enum nbl_cmd_status status = NBL_CMDQ_SUCCESS;

	if ((!cmd->in_va && cmd->in_length > NBL_CMDQ_HALF_DESC_LENGTH) ||
	    (cmd->in_va && cmd->in_length > queue->sq_buf_size)) {
		status = NBL_CMDQ_CQ_ERR_PARAMS;
	}

	return status;
}

static inline enum nbl_cmd_status
nbl_cmdq_check_content(const struct nbl_cmd_queue *queue,
		       const struct nbl_cmd_hdr *hdr,
		       const struct nbl_cmd_content *cmd)
{
	enum nbl_cmd_status status = NBL_CMDQ_SUCCESS;

	if ((cmd->in_va && !cmd->in_length) ||
	    (!cmd->in_va && cmd->in_length) ||
	    (cmd->in_va && cmd->in_length > queue->sq_buf_size)) {
		status = NBL_CMDQ_CQ_ERR_PARAMS;
	}

	/* check parameters: the receiving part */
	if ((hdr->opcode == NBL_CMD_OP_READ ||
	     hdr->opcode == NBL_CMD_OP_SEARCH) && !cmd->out_va)
		status = NBL_CMDQ_CQ_ERR_PARAMS;

	return status;
}

static inline bool
nbl_draco_cmdq_flag_check_interface_error(struct nbl_draco_cmd_desc *desc)
{
	return (desc->errcode >> NBL_CMD_DESC_INTF_ERR_OFT);
}

static inline bool
nbl_draco_cmdq_flag_check_hw_full(struct nbl_draco_cmd_desc *desc)
{
	return (((desc->errcode & 0x1f) == NBL_CMDQ_ERRCODE_KEY_FULL ||
		 (desc->errcode & 0x1f) == NBL_CMDQ_ERRCODE_NO_KT_BLK) &&
		desc->exe_status == NBL_CMD_EXE_STATUS_FAIL);
}

static inline void
nbl_draco_cmdq_desc_check_errcode(const struct nbl_draco_cmd_desc *desc,
				  struct nbl_common_info *common)
{
	if (desc->exe_status != NBL_CMD_EXE_STATUS_SUCCESS)
		nbl_err(common, NBL_DEBUG_FLOW, "failed cmdq: status %d, errcode %d",
			desc->exe_status, desc->errcode);
}

static inline enum nbl_cmd_status
nbl_cmdq_check_interface_error(struct nbl_cmd_desc *desc,
			       struct nbl_common_info *common)
{
	u8 interface_err = 0;
	enum nbl_cmd_status status = NBL_CMDQ_SUCCESS;

	/* flag error bit: error in firmware cmdq interface */
	if (nbl_cmdq_flag_check_interface_error(desc)) {
		/* mark current desc as done by driver */
		nbl_cmdq_flag_mark_cmd_done(desc);

		status = NBL_CMDQ_FAILED;
		interface_err = (desc->flags >> NBL_CMDQ_DESC_FLAG_IF_ERR_OFT) &
				NBL_CMDQ_DESC_FLAG_IF_ERR_MASK;
		switch (interface_err) {
		case 0b00:
			/* dma error, re-send command */
			/* abort if failed sending command 3 times in a row */
			status = NBL_CMDQ_NEED_RESEND;
			break;
		case 0b01:
			/* driver data error, dont re-send */
			status = NBL_CMDQ_NOBUF_ERR;
			break;
		case 0b10:
		case 0b11:
			/* firmware sequence error, reset cmdq */
			status = NBL_CMDQ_NEED_RESET;
			break;
		default:
			/* unknown error */
			nbl_err(common, NBL_DEBUG_FLOW,
				"tc flow cmdq unknown error from firmware interface");
			break;
		}
	}

	return status;
}

static enum nbl_cmd_status
nbl_cmdq_fetch_response(struct nbl_cmd_queue *queue, struct nbl_cmd_desc *desc,
			struct nbl_cmd_content *cmd, struct nbl_cmdq_dma_mem *buffer)
{
	u8 error_code;
	const char *buf_start;
	enum nbl_cmd_status status = NBL_CMDQ_SUCCESS;
	struct nbl_common_info *common = queue->chan_mgt->common;

	/* check descriptor flag error bit for firmware business */
	if (nbl_cmdq_flag_check_error(desc)) {
		status = NBL_CMDQ_FAILED;
		error_code = desc->errorcode;
		if (error_code) {
			nbl_err(common, NBL_DEBUG_FLOW, "tc flow cmdq error code: %d",
				error_code);
		} else {
			nbl_err(common, NBL_DEBUG_FLOW,
				"tc flow cmdq desc error in flag but no errorcode");
		}

		goto fetch_response_end;
	}

	/* check return buffer flag bit */
	if (cmd->out_va && cmd->out && !nbl_cmdq_flag_check_out_buffer(desc)) {
		nbl_err(common, NBL_DEBUG_FLOW, "tc flow cmdq response buffer bit not matched");
		status = NBL_CMDQ_NOBUF_ERR;
		goto fetch_response_end;
	}

	/* process out buffer */
	if (cmd->out_va && cmd->out && buffer) {
		cmd->out_length = le16_to_cpu(desc->datalen) - NBL_CMDQ_HALF_DESC_LENGTH;
		if (cmd->out_length > queue->sq_buf_size) {
			nbl_err(common, NBL_DEBUG_FLOW,
				"tc flow cmdq buffer larger than allowed.\n");
			status = NBL_CMDQ_CQ_ERR_BUFFER;
			goto fetch_response_end;
		}

		if ((desc->opcode == NBL_CMD_OP_READ ||
		     desc->opcode == NBL_CMD_OP_SEARCH) && cmd->out_va) {
			buf_start = (char *)buffer->va + NBL_CMDQ_HALF_DESC_LENGTH;
			memcpy(cmd->out_va, buf_start, cmd->out_length);
		}
	}

fetch_response_end:
	queue->sq_last_status = status;
	return status;
}

static enum nbl_cmd_status
nbl_draco_cmdq_fetch_response(struct nbl_cmd_queue *queue, struct nbl_draco_cmd_desc *desc,
			      struct nbl_cmd_content *cmd, struct nbl_cmdq_dma_mem *buffer)
{
	int *va, *out_va;
	u8 errcode;
	enum nbl_cmd_status status = NBL_CMDQ_SUCCESS;
	struct nbl_common_info *common = queue->chan_mgt->common;

	/* check descriptor flag error bit for firmware business */
	if (nbl_draco_cmdq_flag_check_error(desc)) {
		status = NBL_CMDQ_FAILED;
		errcode = desc->errcode;
		if (errcode) {
			nbl_err(common, NBL_DEBUG_FLOW, "flow cmd queue error code: %d", errcode);
		} else {
			nbl_err(common, NBL_DEBUG_FLOW,
				"flow cmd desc error in flag but no errorcode");
		}

		goto fetch_response_end;
	}

	/* check return buffer flag bit */
	if (cmd->out_va && cmd->out && !nbl_draco_cmdq_flag_check_out_buffer(desc)) {
		nbl_err(common, NBL_DEBUG_FLOW, "flow cmd response buffer bit not matched");
		status = NBL_CMDQ_NOBUF_ERR;
		goto fetch_response_end;
	}

	/* process out buffer */
	if (cmd->out_va && cmd->out && buffer) {
		cmd->out_length = le16_to_cpu(desc->cmd_len) - NBL_CMDQ_HALF_DESC_LENGTH;
		if (cmd->out_length > queue->sq_buf_size) {
			nbl_err(common, NBL_DEBUG_FLOW, "flow cmd buffer larger than allowed, out_length:%u, allowed_length:%u.\n",
				cmd->out_length, queue->sq_buf_size);
			status = NBL_CMDQ_CQ_ERR_BUFFER;
			goto fetch_response_end;
		}

		memcpy((u8 *)cmd->out_va, (u8 *)&desc->param_low, NBL_CMDQ_PARAM_BYTES);
		if ((desc->cmd_type == NBL_CMD_TYPE_HW_W ||
		     desc->cmd_type == NBL_CMD_TYPE_HW_RW) && cmd->out_va) {
			memcpy((u8 *)cmd->out_va + NBL_CMDQ_PARAM_BYTES,
			       buffer->va, cmd->out_length);
		}

		va = buffer->va;
		out_va = cmd->out_va;
	}

	if (desc->cmd_type == NBL_CMD_TYPE_BARE || desc->cmd_type == NBL_CMD_TYPE_HW_R)
		memcpy((u8 *)&cmd->out_params, (u8 *)&desc->param_low, NBL_CMDQ_PARAM_BYTES);

fetch_response_end:

	if (nbl_draco_cmdq_flag_check_hw_full(desc))
		status = NBL_CMDQ_EXCEED_RANGE;

	queue->sq_last_status = status;

	return status;
}

static enum nbl_cmd_status
nbl_draco_cmdq_do_send(void *priv, const struct nbl_cmd_hdr *hdr, struct nbl_cmd_content *cmd)
{
	struct nbl_channel_mgt *chan_mgt = (struct nbl_channel_mgt *)priv;
	struct nbl_cmdq_mgt *cmdq_mgt = chan_mgt->cmdq_mgt;
	bool hit = false;
	bool completed = false;
	u32 desc_index = 0;
	u32 total_delay = 0;
	enum nbl_cmd_status status = NBL_CMDQ_SUCCESS;
	struct nbl_cmd_queue *queue = &cmdq_mgt->cmd_queue;
	struct nbl_cmd_ring *ring = &queue->sq_ring;
	struct nbl_draco_cmd_desc *desc = NULL;
	struct nbl_cmdq_dma_mem *in_buffer = NULL;
	struct nbl_cmdq_dma_mem *out_buffer = NULL;
	struct nbl_common_info *common = queue->chan_mgt->common;

	/* check cmd queue status */
	status = nbl_cmdq_check_queue(ring, common);
	if (status)
		goto abnormal_send;

	/* check parameters: the sending part */
	status = nbl_draco_cmdq_check_content(queue, cmd);
	if (status)
		goto abnormal_send;

	/* lock the ring, assign buffer and send command */
	spin_lock(&queue->sq_lock);

	desc_index = ring->next_to_use;
	/* assign pre-allocated dma for buffers */
	if (cmd->in_va) {
		in_buffer = &ring->in_buffer_info[desc_index];
		memcpy(in_buffer->va, cmd->in_va, cmd->in_length - NBL_CMDQ_HALF_DESC_LENGTH);
		cmd->in = in_buffer->pa;
	}

	if (cmd->out_va) {
		out_buffer = &ring->out_buffer_info[desc_index];
		cmd->out = out_buffer->pa;
	}

	desc = NBL_DRACO_CMDQ_GET_DESC(*ring, desc_index);
	status = nbl_draco_cmdq_execution_nolock(queue, ring, hdr, desc, cmd);

	/* check if queue is full */
	if (status == NBL_CMDQ_CQ_FULL) {
		nbl_err(common, NBL_DEBUG_FLOW, "cmdq never full cuz we wait until it get idle, cmdq full, cmdq len:%u, , next-to-use:%u, next-to-clean:%u, desc-idx:%u, opcode:%u, module:%u, table:%u.",
			ring->len, ring->next_to_use, ring->next_to_clean,
			desc_index, desc->opcode, desc->module, desc->table);
		spin_unlock(&queue->sq_lock);
		goto cmd_send_end;
	}

	do {
		if (nbl_draco_cmdq_flag_check_dd(desc)) {
			completed = true;
			break;
		}

		total_delay++;
		udelay(NBL_CMDQ_SQ_WAIT_USEC);
	} while (total_delay < queue->sq_timeout);
	if (total_delay > NBL_CMDQ_WAIT_WARN)
		nbl_err(common, NBL_DEBUG_FLOW, "cmd time: %d us",
			total_delay * NBL_CMDQ_SQ_WAIT_USEC);

	hit = nbl_draco_cmdq_flag_check_hit(desc);
	/* check interface error, while holding the lock */
	spin_unlock(&queue->sq_lock);
	prefetch(desc);
	if (completed && hit) {
		status = nbl_draco_cmdq_flag_check_interface_error(desc);
		if (status) {
			if (!hdr->is_from_tcam_eviction_cb)
				nbl_err(common, NBL_DEBUG_FLOW, "cmd exe status 0x%x, errcode: 0x%x!\n",
					desc->exe_status, desc->errcode);
			if (nbl_draco_cmdq_flag_check_hw_full(desc))
				status = NBL_CMDQ_EXCEED_RANGE;
			goto cmd_send_end;
		}
	}

	if (completed && hit) {
		/* if ready, return output */
		nbl_draco_cmdq_desc_check_errcode(desc, common);
		status = nbl_draco_cmdq_fetch_response(queue, desc, cmd, out_buffer);
	} else if (!completed) {
		/* timeout error */
		status = NBL_CMDQ_TIMEOUT_ERR;
		nbl_err(common, NBL_DEBUG_FLOW, "tc flow cmdq firmware timeout!\n");
		nbl_draco_cmdq_debug_show_desc(desc, ring->next_to_use, common);
		nbl_err(common, NBL_DEBUG_FLOW, "timeout, cmd not completed! [0x%x: %p] {cmd_status 0x%x; cmd_type 0x%x; opcode 0x%x;exe status 0x%x, errcode 0x%x}\n",
			ring->next_to_use, desc, desc->cmd_status, desc->cmd_type,
			desc->opcode, desc->exe_status, desc->errcode);
	} else {
		status = NBL_CMDQ_NOHIT_ERR;
		nbl_err(common, NBL_DEBUG_FLOW, "tc flow cmdq param error, module:%d table:%d, opcode: 0x%x, errcode: 0x%x.\n",
			desc->module, desc->table, desc->opcode, desc->errcode);
	}

cmd_send_end:
	/* mark desc as done by driver */
	nbl_draco_cmdq_flag_mark_cmd_done(desc);

abnormal_send:
	desc = NULL;
	ring = NULL;
	queue = NULL;

	return status;
}

static enum nbl_cmd_status
nbl_draco_cmdq_send(void *priv, const void *vhdr, void *vcmd)
{
	enum nbl_cmd_status status;
	const struct nbl_cmd_hdr *hdr = (const struct nbl_cmd_hdr *)vhdr;
	struct nbl_cmd_content *cmd = (struct nbl_cmd_content *)vcmd;

	/* command execution */
	status = nbl_draco_cmdq_do_send(priv, hdr, cmd);
	return status;
}

/**
 * @brief: send command to firmware, the sync version, will block and wait
 * for response.
 * @hw: input, pointer to the hardware related properties
 * @hdr: command header, including register block, module, table and opcode
 * @cmd: command content, including input and output
 */
static enum nbl_cmd_status
nbl_cmdq_do_send(void *priv, const struct nbl_cmd_hdr *hdr,
		 struct nbl_cmd_content *cmd)
{
	struct nbl_channel_mgt *chan_mgt = (struct nbl_channel_mgt *)priv;
	struct nbl_cmdq_mgt *cmdq_mgt = chan_mgt->cmdq_mgt;
	bool hit = false;
	bool completed = false;
	u32 desc_index = 0;
	u32 total_delay = 0;
	enum nbl_cmd_status status = NBL_CMDQ_SUCCESS;
	struct nbl_cmd_queue *queue = &cmdq_mgt->cmd_queue;
	struct nbl_cmd_ring *ring = &queue->sq_ring;
	struct nbl_cmd_desc *desc = NULL;
	struct nbl_cmdq_dma_mem *in_buffer = NULL;
	struct nbl_cmdq_dma_mem *out_buffer = NULL;
	struct nbl_common_info *common = queue->chan_mgt->common;

	/* check cmd queue status */
	status = nbl_cmdq_check_queue(ring, common);
	if (status)
		goto cmd_send_end;

	/* check parameters: the sending part */
	status = nbl_cmdq_check_content(queue, hdr, cmd);
	if (status)
		goto cmd_send_end;

	/* lock the ring, assign buffer and send command */
	spin_lock(&queue->sq_lock);

	desc_index = ring->next_to_use;
	/* assign pre-allocated dma for buffers */
	if (cmd->in_va) {
		in_buffer = &ring->in_buffer_info[desc_index];
		memcpy(in_buffer->va, cmd->in_va, cmd->in_length);
		cmd->in = in_buffer->pa;
	}

	if (cmd->out_va) {
		out_buffer = &ring->out_buffer_info[desc_index];
		cmd->out = out_buffer->pa;
	}

	desc = NBL_CMDQ_GET_DESC(*ring, desc_index);
	status = nbl_cmdq_execution_nolock(queue, ring, hdr, desc, cmd);

	/* check if queue is full */
	if (status == NBL_CMDQ_CQ_FULL) {
		spin_unlock(&queue->sq_lock);
		goto cmd_send_end;
	}

	do {
		if (nbl_cmdq_flag_check_dd(desc)) {
			completed = true;
			break;
		}

		total_delay++;
		udelay(NBL_CMDQ_SQ_WAIT_USEC);
	} while (total_delay < queue->sq_timeout);

	hit = nbl_cmdq_flag_check_hit(desc);
	/* check interface error, while holding the lock */
	spin_unlock(&queue->sq_lock);
	prefetch(desc);
	if (completed && hit) {
		status = nbl_cmdq_check_interface_error(desc, common);
		if (status)
			goto cmd_send_end;
	}

	if (completed && hit) {
		/* if ready, return output */
		status = nbl_cmdq_fetch_response(queue, desc, cmd, out_buffer);
	} else if (!completed) {
		/* timeout error */
		status = NBL_CMDQ_TIMEOUT_ERR;
		nbl_err(common, NBL_DEBUG_FLOW, "tc flow cmdq firmware timeout!\n");
	} else {
		status = NBL_CMDQ_NOHIT_ERR;
		nbl_err(common, NBL_DEBUG_FLOW, "tc flow cmdq param error, block:%d module:%d table:%d.\n",
			desc->block, desc->module, desc->table);
	}

	/* mark desc as done by driver */
	nbl_cmdq_flag_mark_cmd_done(desc);

cmd_send_end:
	desc = NULL;
	ring = NULL;
	queue = NULL;
	return status;
}

static enum nbl_cmd_status
nbl_cmdq_send(void *priv, const void *vhdr, void *vcmd)
{
	enum nbl_cmd_status status;
	const struct nbl_cmd_hdr *hdr = (const struct nbl_cmd_hdr *)vhdr;
	struct nbl_cmd_content *cmd = (struct nbl_cmd_content *)vcmd;

	/* command execution */
	status = nbl_cmdq_do_send(priv, hdr, cmd);
	return status;
}

static enum nbl_cmd_status
nbl_cmdq_init_ring(struct nbl_cmdq_mgt *cmdq_mgt)
{
	enum nbl_cmd_status ret_code;
	struct nbl_cmd_queue *cmd_queue = &cmdq_mgt->cmd_queue;

	/* set send queue write back timeout */
	cmd_queue->sq_timeout = NBL_CMDQ_TIMEOUT;
	ret_code = nbl_cmdq_init_sq_ring(cmd_queue);
	return ret_code;
}

/**
 * @brief: create the command queue
 * @hw: input, pointer to the hardware related properties
 */
static enum nbl_cmd_status
nbl_cmdq_init_queue(struct nbl_cmdq_mgt *cmdq_mgt)
{
	enum nbl_cmd_status ret;

	nbl_cmdq_init_queue_parameters(&cmdq_mgt->cmd_queue);

	/* init queue lock */
	spin_lock_init(&cmdq_mgt->cmd_queue.sq_lock);
	ret = nbl_cmdq_init_ring(cmdq_mgt);

	return ret;
}

static int nbl_cmdq_init(void *priv, void *param)
{
	struct nbl_channel_mgt *chan_mgt = (struct nbl_channel_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_CHAN_MGT_TO_PHY_OPS(chan_mgt);

	return phy_ops->init_cmdq(NBL_CHAN_MGT_TO_PHY_PRIV(chan_mgt), param, 0);
}

static int nbl_cmdq_destroy(void *priv)
{
	struct nbl_channel_mgt *chan_mgt = (struct nbl_channel_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_CHAN_MGT_TO_PHY_OPS(chan_mgt);

	phy_ops->destroy_cmdq(NBL_CHAN_MGT_TO_PHY_PRIV(chan_mgt));
	return 0;
}

static int nbl_cmdq_reset(void *priv)
{
	struct nbl_channel_mgt *chan_mgt = (struct nbl_channel_mgt *)priv;
	struct nbl_phy_ops *phy_ops = NBL_CHAN_MGT_TO_PHY_OPS(chan_mgt);
	struct nbl_chan_cmdq_init_info cmdq_param;

	phy_ops->reset_cmdq(NBL_CHAN_MGT_TO_PHY_PRIV(chan_mgt), &cmdq_param);
	return 0;
}

static void nbl_cmdq_get_param(void *priv, void *cmdq_param)
{
	struct nbl_channel_mgt *chan_mgt = (struct nbl_channel_mgt *)priv;
	struct nbl_cmdq_mgt *cmdq_mgt = chan_mgt->cmdq_mgt;
	struct nbl_chan_cmdq_init_info *param =
		(struct nbl_chan_cmdq_init_info *)cmdq_param;

	param->pa = cmdq_mgt->cmd_queue.sq_ring.desc.pa;
	param->len = NBL_CMDQ_RING_DEPTH;
}

static void
nbl_draco_cmdq_clean_sq_ring_all(struct nbl_cmd_queue *cmd_queue)
{
	struct nbl_cmd_ring *ring = &cmd_queue->sq_ring;
	struct nbl_draco_cmd_desc *desc;
	u16 index;

	for (index = 0; index < ring->count; ++index) {
		desc = NBL_DRACO_CMDQ_GET_DESC(*ring, index);
		memset(desc, 0, sizeof(*desc));
	}
}

static int nbl_draco_cmdq_reset(void *priv)
{
	struct nbl_channel_mgt *chan_mgt = (struct nbl_channel_mgt *)priv;
	struct nbl_common_info *common = chan_mgt->common;
	struct nbl_phy_ops *phy_ops = NBL_CHAN_MGT_TO_PHY_OPS(chan_mgt);
	struct nbl_chan_cmdq_init_info cmdq_param;
	struct nbl_cmd_queue *queue = &chan_mgt->cmdq_mgt->cmd_queue;
	struct nbl_cmd_ring *ring = &queue->sq_ring;

	memset(&cmdq_param, 0, sizeof(cmdq_param));

	spin_lock(&queue->sq_lock);
	queue->in_reset = true;
	cmdq_param.vsi_id = common->vsi_id;
	cmdq_param.bdf_num = (common->bus << 8 | common->devid << 3 |
				NBL_COMMON_TO_PCI_FUNC_ID(common));
	nbl_cmdq_get_param(chan_mgt, &cmdq_param);
	phy_ops->reset_cmdq(NBL_CHAN_MGT_TO_PHY_PRIV(chan_mgt), &cmdq_param);

	/* hardware ready, now clean all desc of the cmdq ring */
	nbl_draco_cmdq_clean_sq_ring_all(queue);

	ring->next_to_clean = 0;
	ring->next_to_use = 0;
	ring->doorbell = 0;
	queue->in_reset = false;
	spin_unlock(&queue->sq_lock);

	return 0;
}

int nbl_chan_send_cmdq(void *priv, const void *hdr, void *cmd)
{
	struct nbl_channel_mgt *chan_mgt = (struct nbl_channel_mgt *)priv;
	struct nbl_common_info *common = chan_mgt->common;
	int ret;

	if (!chan_mgt->cmdq_mgt) {
		nbl_err(common, NBL_DEBUG_FLOW, "tc flow cmdq not initialized yet");
		return NBL_CMDQ_NOT_READY;
	}

	if (common->product_type == NBL_DRACO_TYPE) {
		ret = nbl_draco_cmdq_send(priv, hdr, cmd);
		if (ret == (int)NBL_CMDQ_NEED_RESET)
			ret = nbl_draco_cmdq_reset(priv);
		else if (ret == (int)NBL_CMDQ_NEED_RESEND)
			ret = nbl_draco_cmdq_send(priv, hdr, cmd);
	} else {
		ret = nbl_cmdq_send(priv, hdr, cmd);
		if (ret == (int)NBL_CMDQ_NEED_RESET)
			ret = nbl_cmdq_reset(priv);
		else if (ret == (int)NBL_CMDQ_NEED_RESEND)
			ret = nbl_cmdq_send(priv, hdr, cmd);
	}

	return ret;
}

/* Structure starts here, adding an op should not modify anything below */
static int nbl_cmdq_setup_mgt(struct device *dev, struct nbl_cmdq_mgt **cmdq_mgt)
{
	*cmdq_mgt = devm_kzalloc(dev, sizeof(**cmdq_mgt), GFP_ATOMIC);
	if (!*cmdq_mgt)
		return -ENOMEM;

	return 0;
}

static void nbl_cmdq_remove_mgt(struct device *dev, struct nbl_cmdq_mgt **cmdq_mgt)
{
	devm_kfree(dev, *cmdq_mgt);
	*cmdq_mgt = NULL;
}

int nbl_chan_cmdq_mgt_start(struct device *dev, void *priv)
{
	struct nbl_channel_mgt *chan_mgt = (struct nbl_channel_mgt *)priv;
	struct nbl_common_info *common = chan_mgt->common;
	struct nbl_cmdq_mgt **cmdq_mgt = &chan_mgt->cmdq_mgt;
	struct nbl_chan_cmdq_init_info cmdq_param;
	u8 idx = 0;
	int ret = 0;

	memset(&cmdq_param, 0, sizeof(cmdq_param));

	/* if cmdq not ready, setup command queue */
	if (!(*cmdq_mgt)) {
		idx = nbl_tc_alloc_inst_id();
		if (idx >= NBL_TC_FLOW_INST_COUNT) {
			nbl_err(common, NBL_DEBUG_FLOW, "tc flow cmdq start failed, max tc flow instances reached!");
			return -EPERM;
		}

		common->tc_inst_id = idx;

		/* alloc memory for cmdq management */
		ret = nbl_cmdq_setup_mgt(dev, cmdq_mgt);
		if (ret) {
			nbl_tc_unset_cmdq_info(common->tc_inst_id);
			common->tc_inst_id = NBL_TC_FLOW_INST_COUNT;
			nbl_err(common, NBL_DEBUG_FLOW,
				"tc flow cmdq start failed due to failed memory allocation");
			return ret;
		}

		nbl_tc_set_cmdq_info(&nbl_chan_send_cmdq, (void *)chan_mgt, idx);
		(*cmdq_mgt)->cmd_queue.chan_mgt = chan_mgt;
		ret = nbl_cmdq_init_queue(*cmdq_mgt);

		cmdq_param.vsi_id = common->vsi_id;
		cmdq_param.bdf_num = (u16)(common->hw_bus << 8 | common->devid << 3 |
				      NBL_COMMON_TO_PCI_FUNC_ID(common));
		nbl_cmdq_get_param(chan_mgt, &cmdq_param);
		nbl_cmdq_init(chan_mgt, &cmdq_param);
		nbl_info(common, NBL_DEBUG_FLOW, "tc flow cmdq inited, vsi_id:%u, mgt_pf:%u\n",
			 common->vsi_id, common->mgt_pf);
	}

	(*cmdq_mgt)->cmdq_refcount++;
	nbl_info(common, NBL_DEBUG_FLOW,
		 "tc flow cmdq ref count: %d\n", (*cmdq_mgt)->cmdq_refcount);
	return (int)common->tc_inst_id;
}

int nbl_chan_cmdq_mgt_stop(struct device *dev, void *priv, u8 inst_id)
{
	struct nbl_channel_mgt *chan_mgt = (struct nbl_channel_mgt *)priv;
	struct nbl_cmdq_mgt **cmdq_mgt = &chan_mgt->cmdq_mgt;
	struct nbl_common_info *common = chan_mgt->common;

	if (inst_id >= NBL_TC_FLOW_INST_COUNT)
		return 0;

	if (!(*cmdq_mgt)) {
		nbl_err(common, NBL_DEBUG_FLOW, "tc flow cmdq not inited but try to deinit");
		return 0;
	} else if ((*cmdq_mgt)->cmdq_refcount == 1) {
		/* wait for inflight cmd to finish */
		mdelay(NBL_CMDQ_FLIGHT_DELAY);
		nbl_cmdq_destroy(priv);
		nbl_cmdq_destroy_queue(&(*cmdq_mgt)->cmd_queue);
		nbl_cmdq_remove_mgt(dev, cmdq_mgt);
		nbl_tc_unset_cmdq_info(inst_id);
		common->tc_inst_id = NBL_TC_FLOW_INST_COUNT;
		nbl_info(common, NBL_DEBUG_FLOW, "tc flow cmdq deinited\n");
	} else {
		(*cmdq_mgt)->cmdq_refcount--;
		nbl_info(common, NBL_DEBUG_FLOW,
			 "tc flow cmdq ref count: %d\n", (*cmdq_mgt)->cmdq_refcount);
	}

	return 0;
}
