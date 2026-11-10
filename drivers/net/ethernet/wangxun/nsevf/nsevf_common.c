// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#include "nsevf.h"
#include "nsevf_osdep.h"
#include "nsevf_type.h"
#include "nsevf_adminq.h"
#include "nsevf_prototype.h"
#include "virtchnl.h"

/**
 * nsevf_set_mac_type - Sets MAC type
 * @hw: pointer to the HW structure
 *
 * This function sets the mac type of the adapter based on the
 * vendor ID and device ID stored in the hw structure.
 **/
enum nsevf_status nsevf_set_mac_type(struct nsevf_hw *hw)
{
	enum nsevf_status status = 0;

	if (hw->vendor_id == PCI_VENDOR_ID_TRUSTNETIC) {
		switch (hw->device_id) {
		case NSEVF_DEV_ID_VF_AMBER_FPGA:
		case NSEVF_DEV_ID_VF_AMBER_FDBTACXX:
		case NSEVF_DEV_ID_VF_AMBER_FDBTACRX:
		case NSEVF_DEV_ID_VF_AMBER_FDATACRX:
		case NSEVF_DEV_ID_VF_AMBER_FDATAIRX:
		case NSEVF_DEV_ID_VF_AMBER_FQATACRX:
		case NSEVF_DEV_ID_VF_AMBER_DQATACXX:
		case NSEVF_DEV_ID_VF_MS:
		case NSEVF_DEV_ID_VDEV:
			hw->mac.type = NSEVF_MAC_VF;

			if (hw->device_id == NSEVF_DEV_ID_VF_MS)
				hw->mac.pf_mac_type =
					NSEVF_PF_MAC_TYPE_MOONSTONE;
			else
				hw->mac.pf_mac_type = NSEVF_PF_MAC_TYPE_AMBER;

			break;
		default:
			status = NSEVF_ERR_DEVICE_NOT_SUPPORTED;
			break;
		}
	} else {
		status = NSEVF_ERR_DEVICE_NOT_SUPPORTED;
	}

	hw_dbg(hw, "%s found mac: %d, returns: %d\n", __func__, hw->mac.type,
	       status);
	return status;
}

/**
 * nsevf_aq_str - convert AQ err code to a string
 * @hw: pointer to the HW structure
 * @aq_err: the AQ error code to convert
 **/
const char *nsevf_aq_str(struct nsevf_hw *hw, enum nse_aq_err aq_err)
{
	switch (aq_err) {
	case NSE_AQ_RC_OK:
		return "NSE_AQ_RC_OK";
	case NSE_AQ_RC_EIO:
		return "NSE_AQ_RC_EIO";
	case NSE_AQ_RC_EINVAL:
		return "NSE_AQ_RC_EINVAL";
	case NSE_AQ_RC_ERANGE:
		return "NSE_AQ_RC_ERANGE";
	case NSE_AQ_RC_EPERM:
		return "NSE_AQ_RC_EPERM";
	case NSE_AQ_RC_EFAULT:
		return "NSE_AQ_RC_EFAULT";
	case NSE_AQ_RC_ENOENT:
		return "NSE_AQ_RC_ENOENT";
	case NSE_AQ_RC_EEXIST:
		return "NSE_AQ_RC_EEXIST";
	case NSE_AQ_RC_EAGAIN:
		return "NSE_AQ_RC_EAGAIN";
	case NSE_AQ_RC_EBUSY:
		return "NSE_AQ_RC_EBUSY";
	case NSE_AQ_RC_EINPROGRESS:
		return "NSE_AQ_RC_EINPROGRESS";
	case NSE_AQ_RC_ENOMEM:
		return "NSE_AQ_RC_ENOMEM";
	case NSE_AQ_RC_ENOSPC:
		return "NSE_AQ_RC_ENOSPC";
	case NSE_AQ_RC_ENOTSUPP:
		return "NSE_AQ_RC_ENOTSUPP";

	case NSE_AQ_RC_EACCES_FW_IN_UPDATE:
		return "NSE_AQ_RC_EACCES_FW_IN_UPDATE";

	default:
		snprintf(hw->err_str, sizeof(hw->err_str), "%d", aq_err);
		return hw->err_str;
	}
}

/**
 * nsevf_stat_str - convert status err code to a string
 * @hw: pointer to the HW structure
 * @stat_err: the status error code to convert
 **/
const char *nsevf_stat_str(struct nsevf_hw *hw, enum nsevf_status stat_err)
{
	switch (stat_err) {
	case NSEVF_SUCCESS:
		return "OK";
	case NSEVF_ERR_NVM:
		return "NSEVF_ERR_NVM";
	case NSEVF_ERR_NVM_CHECKSUM:
		return "NSEVF_ERR_NVM_CHECKSUM";
	case NSEVF_ERR_PHY:
		return "NSEVF_ERR_PHY";
	case NSEVF_ERR_CONFIG:
		return "NSEVF_ERR_CONFIG";
	case NSEVF_ERR_PARAM:
		return "NSEVF_ERR_PARAM";
	case NSEVF_ERR_MAC_TYPE:
		return "NSEVF_ERR_MAC_TYPE";
	case NSEVF_ERR_UNKNOWN_PHY:
		return "NSEVF_ERR_UNKNOWN_PHY";
	case NSEVF_ERR_LINK_SETUP:
		return "NSEVF_ERR_LINK_SETUP";
	case NSEVF_ERR_ADAPTER_STOPPED:
		return "NSEVF_ERR_ADAPTER_STOPPED";
	case NSEVF_ERR_INVALID_MAC_ADDR:
		return "NSEVF_ERR_INVALID_MAC_ADDR";
	case NSEVF_ERR_DEVICE_NOT_SUPPORTED:
		return "NSEVF_ERR_DEVICE_NOT_SUPPORTED";
	case NSEVF_ERR_PRIMARY_REQUESTS_PENDING:
		return "NSEVF_ERR_PRIMARY_REQUESTS_PENDING";
	case NSEVF_ERR_INVALID_LINK_SETTINGS:
		return "NSEVF_ERR_INVALID_LINK_SETTINGS";
	case NSEVF_ERR_AUTONEG_NOT_COMPLETE:
		return "NSEVF_ERR_AUTONEG_NOT_COMPLETE";
	case NSEVF_ERR_RESET_FAILED:
		return "NSEVF_ERR_RESET_FAILED";
	case NSEVF_ERR_SWFW_SYNC:
		return "NSEVF_ERR_SWFW_SYNC";
	case NSEVF_ERR_NO_AVAILABLE_VSI:
		return "NSEVF_ERR_NO_AVAILABLE_VSI";
	case NSEVF_ERR_NO_MEMORY:
		return "NSEVF_ERR_NO_MEMORY";
	case NSEVF_ERR_BAD_PTR:
		return "NSEVF_ERR_BAD_PTR";
	case NSEVF_ERR_RING_FULL:
		return "NSEVF_ERR_RING_FULL";
	case NSEVF_ERR_INVALID_PD_ID:
		return "NSEVF_ERR_INVALID_PD_ID";
	case NSEVF_ERR_INVALID_QP_ID:
		return "NSEVF_ERR_INVALID_QP_ID";
	case NSEVF_ERR_INVALID_CQ_ID:
		return "NSEVF_ERR_INVALID_CQ_ID";
	case NSEVF_ERR_INVALID_CEQ_ID:
		return "NSEVF_ERR_INVALID_CEQ_ID";
	case NSEVF_ERR_INVALID_AEQ_ID:
		return "NSEVF_ERR_INVALID_AEQ_ID";
	case NSEVF_ERR_INVALID_SIZE:
		return "NSEVF_ERR_INVALID_SIZE";
	case NSEVF_ERR_INVALID_ARP_INDEX:
		return "NSEVF_ERR_INVALID_ARP_INDEX";
	case NSEVF_ERR_INVALID_FPM_FUNC_ID:
		return "NSEVF_ERR_INVALID_FPM_FUNC_ID";
	case NSEVF_ERR_QP_INVALID_MSG_SIZE:
		return "NSEVF_ERR_QP_INVALID_MSG_SIZE";
	case NSEVF_ERR_QP_TOOMANY_WRS_POSTED:
		return "NSEVF_ERR_QP_TOOMANY_WRS_POSTED";
	case NSEVF_ERR_INVALID_FRAG_COUNT:
		return "NSEVF_ERR_INVALID_FRAG_COUNT";
	case NSEVF_ERR_QUEUE_EMPTY:
		return "NSEVF_ERR_QUEUE_EMPTY";
	case NSEVF_ERR_INVALID_ALIGNMENT:
		return "NSEVF_ERR_INVALID_ALIGNMENT";
	case NSEVF_ERR_FLUSHED_QUEUE:
		return "NSEVF_ERR_FLUSHED_QUEUE";
	case NSEVF_ERR_INVALID_PUSH_PAGE_INDEX:
		return "NSEVF_ERR_INVALID_PUSH_PAGE_INDEX";
	case NSEVF_ERR_INVALID_IMM_DATA_SIZE:
		return "NSEVF_ERR_INVALID_IMM_DATA_SIZE";
	case NSEVF_ERR_TIMEOUT:
		return "NSEVF_ERR_TIMEOUT";
	case NSEVF_ERR_OPCODE_MISMATCH:
		return "NSEVF_ERR_OPCODE_MISMATCH";
	case NSEVF_ERR_CQP_COMPL_ERROR:
		return "NSEVF_ERR_CQP_COMPL_ERROR";
	case NSEVF_ERR_INVALID_VF_ID:
		return "NSEVF_ERR_INVALID_VF_ID";
	case NSEVF_ERR_INVALID_HMCFN_ID:
		return "NSEVF_ERR_INVALID_HMCFN_ID";
	case NSEVF_ERR_BACKING_PAGE_ERROR:
		return "NSEVF_ERR_BACKING_PAGE_ERROR";
	case NSEVF_ERR_NO_PBLCHUNKS_AVAILABLE:
		return "NSEVF_ERR_NO_PBLCHUNKS_AVAILABLE";
	case NSEVF_ERR_INVALID_PBLE_INDEX:
		return "NSEVF_ERR_INVALID_PBLE_INDEX";
	case NSEVF_ERR_INVALID_SD_INDEX:
		return "NSEVF_ERR_INVALID_SD_INDEX";
	case NSEVF_ERR_INVALID_PAGE_DESC_INDEX:
		return "NSEVF_ERR_INVALID_PAGE_DESC_INDEX";
	case NSEVF_ERR_INVALID_SD_TYPE:
		return "NSEVF_ERR_INVALID_SD_TYPE";
	case NSEVF_ERR_MEMCPY_FAILED:
		return "NSEVF_ERR_MEMCPY_FAILED";
	case NSEVF_ERR_INVALID_HMC_OBJ_INDEX:
		return "NSEVF_ERR_INVALID_HMC_OBJ_INDEX";
	case NSEVF_ERR_INVALID_HMC_OBJ_COUNT:
		return "NSEVF_ERR_INVALID_HMC_OBJ_COUNT";
	case NSEVF_ERR_INVALID_SRQ_ARM_LIMIT:
		return "NSEVF_ERR_INVALID_SRQ_ARM_LIMIT";
	case NSEVF_ERR_SRQ_ENABLED:
		return "NSEVF_ERR_SRQ_ENABLED";
	case NSEVF_ERR_ADMIN_QUEUE_ERROR:
		return "NSEVF_ERR_ADMIN_QUEUE_ERROR";
	case NSEVF_ERR_ADMIN_QUEUE_TIMEOUT:
		return "NSEVF_ERR_ADMIN_QUEUE_TIMEOUT";
	case NSEVF_ERR_BUF_TOO_SHORT:
		return "NSEVF_ERR_BUF_TOO_SHORT";
	case NSEVF_ERR_ADMIN_QUEUE_FULL:
		return "NSEVF_ERR_ADMIN_QUEUE_FULL";
	case NSEVF_ERR_ADMIN_QUEUE_NO_WORK:
		return "NSEVF_ERR_ADMIN_QUEUE_NO_WORK";
	case NSEVF_ERR_BAD_IWARP_CQE:
		return "NSEVF_ERR_BAD_IWARP_CQE";
	case NSEVF_ERR_NVM_BLANK_MODE:
		return "NSEVF_ERR_NVM_BLANK_MODE";
	case NSEVF_ERR_NOT_IMPLEMENTED:
		return "NSEVF_ERR_NOT_IMPLEMENTED";
	case NSEVF_ERR_PE_DOORBELL_NOT_ENABLED:
		return "NSEVF_ERR_PE_DOORBELL_NOT_ENABLED";
	case NSEVF_ERR_DIAG_TEST_FAILED:
		return "NSEVF_ERR_DIAG_TEST_FAILED";
	case NSEVF_ERR_NOT_READY:
		return "NSEVF_ERR_NOT_READY";
	case NSEVF_NOT_SUPPORTED:
		return "NSEVF_NOT_SUPPORTED";
	case NSEVF_ERR_FIRMWARE_API_VERSION:
		return "NSEVF_ERR_FIRMWARE_API_VERSION";
	case NSEVF_ERR_ADMIN_QUEUE_CRITICAL_ERROR:
		return "NSEVF_ERR_ADMIN_QUEUE_CRITICAL_ERROR";
	case NSEVF_ERR_ADMIN_QUEUE_EMPTY:
		return "NSEVF_ERR_ADMIN_QUEUE_EMPTY";
	case NSEVF_ERR_INVAL_SIZE:
		return "NSEVF_ERR_INVAL_SIZE";
	}

	snprintf(hw->err_str, sizeof(hw->err_str), "%d", stat_err);
	return hw->err_str;
}

/**
 * nsevf_debug_aq
 * @hw: debug mask related to admin queue
 * @desc: pointer to admin queue descriptor
 * @buffer: pointer to command buffer
 * @buf_len: max length of buffer
 *
 * Dumps debug log about adminq command with descriptor contents.
 **/
void nsevf_debug_aq(struct nsevf_hw *hw, void *desc, void *buffer, u16 buf_len)
{
	struct nsevf_aq_desc *aq_desc = desc;
	u8 *buf = buffer;
	u16 len;

	if (!((NSEVF_DBG_AQM_DESC | NSEVF_DBG_AQM_BUF) & hw->debug_mask) ||
	    !desc)
		return;

	len = le16_to_cpu(aq_desc->datalen);

	nsevf_debug(hw, NSEVF_DBG_AQM_DESC,
		    "AQ CMD: opcode 0x%04X, flags 0x%04X, datalen 0x%04X, mailbox_id 0x%04X\n",
		le16_to_cpu(aq_desc->opcode), le16_to_cpu(aq_desc->flags),
		le16_to_cpu(aq_desc->datalen),
		le16_to_cpu(aq_desc->mailbox_id));
	nsevf_debug(hw, NSEVF_DBG_AQM_DESC,
		    "\t param (0,1)/addr_(high, low)  0x%08X 0x%08X\n",
		    le32_to_cpu(aq_desc->addr_high),
		    le32_to_cpu(aq_desc->addr_low));

	if ((hw->debug_mask & NSEVF_DBG_AQM_BUF) && buffer &&
	    aq_desc->datalen != 0) {
		char prefix[27];

		nsevf_debug(hw, NSEVF_DBG_AQM_BUF, "AQ CMD Buffer:\n");

		if (buf_len < len)
			len = buf_len;

		/* write the full 16-byte chunks */

		snprintf(prefix, sizeof(prefix), "nsevf %02x:%02x.%x: \t0x",
			 hw->bus.bus_id, hw->bus.device, hw->bus.func);

		print_hex_dump(KERN_INFO, prefix, DUMP_PREFIX_OFFSET, 16, 1,
			       buf, len, false);
	}
}

/**
 * nsevf_check_asq_alive
 * @hw: pointer to the hw struct
 * @aq: pointer to the control queue information
 *
 * Returns true if Queue is enabled else false.
 **/
bool nsevf_check_asq_alive(struct nsevf_hw *hw, struct nsevf_ctl_q_info *aq)
{
	u32 sq_len;

	if (aq->asq.len) {
		sq_len = rd32(hw, aq->asq.len);

		if (nsevf_is_regval_reset_magic(sq_len))
			return false;

		if ((sq_len & NSE_REG_AQM_QLEN_STAT_Q_PAUSE_N_M) &&
		    (sq_len & NSE_REG_AQM_QLEN_STAT_Q_EN_M))
			return true;
	}

	return false;
}

bool nsevf_check_arq_alive(struct nsevf_hw *hw, struct nsevf_ctl_q_info *aq)
{
	u32 rq_len;

	if (aq->arq.len) {
		rq_len = rd32(hw, aq->arq.len);

		if (nsevf_is_regval_reset_magic(rq_len))
			return false;

		if ((rq_len & NSE_REG_AQM_QLEN_STAT_Q_PAUSE_N_M) &&
		    (rq_len & NSE_REG_AQM_QLEN_STAT_Q_EN_M))
			return true;
	}

	return false;
}

/**
 * nsevf_aq_shutdown_mailboxq - shut down the mailbox queue
 * @hw: pointer to the hw struct
 *
 * Tell the Firmware that we're shutting down the AdminQ and whether
 * or not the driver is unloading as well.
 **/
enum nsevf_status nsevf_aq_shutdown_mailboxq(struct nsevf_hw *hw)
{
	struct nsevf_aq_desc desc;
	enum nsevf_status status;

	nsevf_fill_default_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_BASIC,
					   NSE_AQ_OPC_Q_SHUTDOWN);

	desc.mailbox_id = cpu_to_le16(NSE_AQ_MAILBOX_ID_FW);

	status =
		nsevf_asq_send_command(hw, &hw->mailboxq, &desc, NULL, 0, NULL);

	hw->controlq_stats.mq_cmd_shutdown_time = ktime_to_ns(ktime_get());
	hw->controlq_stats.mq_cmd_shutdown_cnt++;

	return status;
}

/**
 * nsevf_aq_send_msg_to_pf
 * @hw: pointer to the hardware structure
 * @v_opcode: opcodes for VF-PF communication
 * @v_retval: return error code
 * @msg: pointer to the msg buffer
 * @msglen: msg length
 * @cmd_details: pointer to command details
 *
 * Send message to PF driver using admin queue. By default, this message
 * is sent asynchronously, i.e. nsevf_asq_send_command() does not wait for
 * completion before returning.
 **/
enum nsevf_status
nsevf_aq_send_msg_to_pf(struct nsevf_hw *hw, enum virtchnl_ops v_opcode,
			enum virtchnl_status_code v_retval, u8 *msg, u16 msglen,
			struct nsevf_asq_cmd_details *cmd_details)
{
	struct nsevf_aq_desc desc;
	struct nsevf_asq_cmd_details details;
	void *cbuf = NULL;
	size_t cbuf_len = sizeof(struct nse_aqc_mbx_cmd_buff_hdr) + msglen;
	struct nse_aqc_mbx_cmd_buff_hdr *hdr = NULL;
	enum nsevf_status status;

	cbuf = devm_kzalloc(nsevf_hw_to_dev(hw), cbuf_len, GFP_KERNEL);
	if (!cbuf)
		return NSEVF_ERR_NO_MEMORY;

	nsevf_fill_default_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_COMM,
					   NSE_AQ_OPC_SEND_MSG_TO_PF);

	desc.flags |= cpu_to_le16(NSE_AQ_FLAG_SI);

	/* always set RD and BUF flag, because always have indirect buffer  */
	desc.flags |= cpu_to_le16(NSE_AQ_FLAG_RD);
	desc.flags |= cpu_to_le16(NSE_AQ_FLAG_BUF);
	if (cbuf_len > NSEVF_AQ_LARGE_BUF)
		desc.flags |= cpu_to_le16(NSE_AQ_FLAG_LB);

	desc.datalen = cpu_to_le16(cbuf_len);

	/* set hdr */
	hdr = (struct nse_aqc_mbx_cmd_buff_hdr *)cbuf;
	hdr->cookie_high = cpu_to_le32(v_opcode);
	hdr->cookie_low = cpu_to_le32(v_retval);

	/* copy the msg */
	if (msglen) {
		memcpy(cbuf + sizeof(struct nse_aqc_mbx_cmd_buff_hdr), msg,
		       msglen);
	}

	if (!cmd_details) {
		memset(&details, 0, sizeof(details));

		details.async = false;
		cmd_details = &details;
	}

	nsevf_debug(hw, NSEVF_DBG_AQM_MSG,
		    "send vch-msg to PF (desc-opcode=%X): vch-opcode=%d(%s), vch-retval=%d(%s)\n",
		le16_to_cpu(desc.opcode), v_opcode, virtchnl_op_str(v_opcode),
		v_retval, virtchnl_stat_str(v_retval));

	status = nsevf_asq_send_command(hw, &hw->mailboxq, &desc, cbuf,
					cbuf_len, cmd_details);

	if (msg) {
		memcpy(msg, cbuf + sizeof(struct nse_aqc_mbx_cmd_buff_hdr),
		       msglen);
	}

	devm_kfree(nsevf_hw_to_dev(hw), cbuf);

	return status;
}

/**
 * nsevf_vf_parse_hw_config
 * @hw: pointer to the hardware structure
 * @msg: pointer to the virtual channel VF resource structure
 *
 * Given a VF resource message from the PF, populate the hw struct
 * with appropriate information.
 **/
void nsevf_vf_parse_hw_config(struct nsevf_hw *hw,
			      struct virtchnl_vf_resource *msg)
{
	struct virtchnl_vsi_resource *vsi_res;

	vsi_res = &msg->vsi_res;

	if (msg->platform_info ==
	    NSE_HW_PLATFORM_ASIC) /* consider PLDM for now */
		nsevf_lan_min_itr_no_intrl = 1;

	hw->dev_caps.num_vsis = msg->num_vsis;
	hw->dev_caps.num_rx_qp = msg->num_queue_pairs;
	hw->dev_caps.num_tx_qp = msg->num_queue_pairs;
	hw->dev_caps.num_msix_vectors_vf = msg->max_vectors;
	hw->dev_caps.dcb = msg->vf_cap_flags & VIRTCHNL_VF_OFFLOAD_L2;
	hw->dev_caps.max_mtu = msg->max_mtu;

	hw->dev_caps.lan_txcq_base_abs_id = msg->lan_txcq_base_abs_id;
	hw->dev_caps.lan_txcq_num = msg->lan_txcq_num;

	hw->dev_caps.lan_rxq_base_abs_id = msg->lan_rxq_base_abs_id;

	if (vsi_res->vsi_type == VIRTCHNL_VSI_SRIOV) {
		ether_addr_copy(hw->mac.perm_addr, vsi_res->default_mac_addr);
		ether_addr_copy(hw->mac.addr, vsi_res->default_mac_addr);
	}
}

int nsevf_set_itr_interval(struct nsevf_hw *hw, u16 irq, u32 interval_in_us)
{
	u32 reg = rd32(hw, NSEVF_REG_INT_DYN_CTLN(irq));

	if (interval_in_us > NSE_ITR_INTERVAL_MAX_USEC)
		return -ERANGE;

	interval_in_us >>=
		1; /* translate into 2us ( NSE_ITR_GRAN_FIXED ) unit */

	if (!interval_in_us)
		interval_in_us = 1;

	reg |= (NSEVF_REG_INT_DYN_CTLN_ITR_VALID_M |
		((interval_in_us << NSEVF_REG_INT_DYN_CTLN_ITR_INTERVAL_S) &
		 NSEVF_REG_INT_DYN_CTLN_ITR_INTERVAL_M));

	wr32(hw, NSEVF_REG_INT_DYN_CTLN(irq), reg);

	return 0;
}

int nsevf_write_itr(struct nsevf_q_vector *qvec, u32 interval_in_us)
{
	struct nsevf_adapter *adapter = qvec->adapter;
	struct nsevf_hw *hw = &adapter->hw;

	return nsevf_set_itr_interval(hw, qvec->reg_idx, interval_in_us);
}

int nsevf_set_intrl_interval(struct nsevf_hw *hw, u16 irq, u32 interval_in_us)
{
	return 0;
}

void nsevf_write_intrl(struct nsevf_q_vector *q_vector, u8 intrl)
{
}

void nsevf_set_q_vector_intrl(struct nsevf_q_vector *q_vector)
{
}

void nsevf_set_vf_virtio_mode(struct nsevf_hw *hw, bool ena)
{
	u32 val;

	if (hw->device_id == NSEVF_DEV_ID_VDEV)
		return;

	if (ena)
		val = NSEVF_REG_CTL_SET_VIRTIO_MODE_M;
	else
		val = NSEVF_REG_CTL_CLR_VIRTIO_MODE_M;

	wr32(hw, NSEVF_REG_CTL, val);
}

/**
 * nsevf_vf_reset
 * @hw: pointer to the hardware structure
 *
 * Send a VF_RESET message to the PF. Does not wait for response from PF
 * as none will be forthcoming. Immediately after calling this function,
 * the admin queue should be shut down and (optionally) reinitialized.
 **/
enum nsevf_status nsevf_vf_reset(struct nsevf_hw *hw)
{
	return nsevf_aq_send_msg_to_pf(hw, VIRTCHNL_OP_RESET_VF,
				       VIRTCHNL_STATUS_SUCCESS, NULL, 0, NULL);
}

void nsevf_stat_update64(u64 new_data, bool prev_stat_loaded, u64 *prev_stat,
			 u64 *cur_stat)
{
	if (!prev_stat_loaded) {
		*prev_stat = new_data;
		return;
	}

	/* Calculate the difference between the new and old values, and then
	 * add it to the software stat value.
	 */
	if (new_data >= *prev_stat)
		*cur_stat += new_data - *prev_stat;
	else
		/* to manage the potential roll-over */
		*cur_stat += (U64_MAX - *prev_stat) + new_data;

	/* Update the previously stored value to prepare for next read */
	*prev_stat = new_data;
}

/**
 * nsevf_is_reset - Check if reset has been triggered
 * @hw: pointer to nsevf_hw
 *
 * Return true if reset has been already triggered, false otherwise
 *
 **/
bool nsevf_is_reset(struct nsevf_hw *hw)
{
	u32 reg;

	reg = rd32(hw, NSEVF_REG_CTL);
	if ((reg & NSEVF_REG_CTL_FRTRIG_STATUS_M) ||
	    nsevf_is_regval_reset_magic(reg)) {
		nsevf_debug(hw, NSEVF_DBG_SYS,
			    "[%s, %d] detect see: ctl = 0x%X\n", __func__,
			    __LINE__, reg);
		return true;
	}

	if (nsevf_use_msgbox) {
		reg = rd32(hw, MBX_ARQBAL(hw));

		if (reg != NSEVF_REG_VMBX_ARQBAL_MAGIC_VF_MSGBOX_INIT) {
			nsevf_debug(hw, NSEVF_DBG_SYS,
				    "[%s, %d] use_msgbox, detect see: mbx_arqbal = 0x%X != init magic(0x%X)\n",
				__func__, __LINE__, reg,
				NSEVF_REG_VMBX_ARQBAL_MAGIC_VF_MSGBOX_INIT);
			return true;
		}
	} else {
		reg = rd32(hw, MBX_ARQLEN(hw));

		if (!(reg & NSE_REG_AQM_QLEN_STAT_Q_EN_M) ||
		    nsevf_is_regval_reset_magic(reg)) {
			nsevf_debug(hw, NSEVF_DBG_SYS,
				    "[%s, %d] detect see: mbx_arqlen = 0x%X\n",
				    __func__, __LINE__, reg);
			return true;
		}
	}

	return false;
}

const struct nse_rx_ptype_decoded nse_ptype_lkup[256] = {
	NSE_PTT_UNUSED_ENTRY(16),
	NSE_PTT(17, L2, NONE, NOF, NONE, NONE, NOF, NONE, PAY2),
	NSE_PTT(18, L2, NONE, NOF, NONE, NONE, NOF, NONE, NONE),
	NSE_PTT(19, L2, NONE, NOF, NONE, NONE, NOF, NONE, NONE),
	NSE_PTT(20, L2, NONE, NOF, NONE, NONE, NOF, NONE, NONE),
	NSE_PTT(21, L2, NONE, NOF, NONE, NONE, NOF, NONE, NONE),
	NSE_PTT(22, L2, NONE, NOF, NONE, NONE, NOF, NONE, NONE),
	NSE_PTT(23, L2, NONE, NOF, NONE, NONE, NOF, NONE, NONE),

	NSE_PTT_UNUSED_ENTRY(32),

	NSE_PTT(33, IP, IPV4, FRG, NONE, NONE, NOF, NONE, PAY3),
	NSE_PTT(34, IP, IPV4, NOF, NONE, NONE, NOF, NONE, PAY3),
	NSE_PTT(35, IP, IPV4, NOF, NONE, NONE, NOF, UDP, PAY4),
	NSE_PTT(36, IP, IPV4, NOF, NONE, NONE, NOF, TCP, PAY4),
	NSE_PTT(37, IP, IPV4, NOF, NONE, NONE, NOF, SCTP, PAY4),
	NSE_PTT(38, IP, IPV4, NOF, NONE, NONE, NOF, ICMP, PAY4),

	NSE_PTT_UNUSED_ENTRY(39),
	NSE_PTT_UNUSED_ENTRY(40),

	NSE_PTT(41, IP, IPV6, FRG, NONE, NONE, NOF, NONE, PAY3),
	NSE_PTT(42, IP, IPV6, NOF, NONE, NONE, NOF, NONE, PAY3),
	NSE_PTT(43, IP, IPV6, NOF, NONE, NONE, NOF, UDP, PAY4),
	NSE_PTT(44, IP, IPV6, NOF, NONE, NONE, NOF, TCP, PAY4),
	NSE_PTT(45, IP, IPV6, NOF, NONE, NONE, NOF, SCTP, PAY4),
	NSE_PTT(46, IP, IPV6, NOF, NONE, NONE, NOF, ICMP, PAY4),

	NSE_PTT_UNUSED_ENTRY(47),

	NSE_PTT(128, IP, IPV4, NOF, NONE, NONE, NOF, NONE, PAY2),

	NSE_PTT(129, IP, IPV4, NOF, IP_IP, IPV4, FRG, NONE, PAY3),
	NSE_PTT(130, IP, IPV4, NOF, IP_IP, IPV4, NOF, NONE, PAY3),
	NSE_PTT(131, IP, IPV4, NOF, IP_IP, IPV4, NOF, UDP, PAY4),
	NSE_PTT(132, IP, IPV4, NOF, IP_IP, IPV4, NOF, TCP, PAY4),
	NSE_PTT(133, IP, IPV4, NOF, IP_IP, IPV4, NOF, SCTP, PAY4),
	NSE_PTT(134, IP, IPV4, NOF, IP_IP, IPV4, NOF, ICMP, PAY4),

	NSE_PTT_UNUSED_ENTRY(135),
	NSE_PTT_UNUSED_ENTRY(136),

	NSE_PTT(137, IP, IPV4, NOF, IP_IP, IPV6, FRG, NONE, PAY3),
	NSE_PTT(138, IP, IPV4, NOF, IP_IP, IPV6, NOF, NONE, PAY3),
	NSE_PTT(139, IP, IPV4, NOF, IP_IP, IPV6, NOF, UDP, PAY4),
	NSE_PTT(140, IP, IPV4, NOF, IP_IP, IPV6, NOF, TCP, PAY4),
	NSE_PTT(141, IP, IPV4, NOF, IP_IP, IPV6, NOF, SCTP, PAY4),
	NSE_PTT(142, IP, IPV4, NOF, IP_IP, IPV6, NOF, ICMP, PAY4),

	NSE_PTT_UNUSED_ENTRY(143),

	NSE_PTT(144, IP, IPV4, NOF, IP_GRENAT, NONE, NOF, NONE, PAY2),

	NSE_PTT(145, IP, IPV4, NOF, IP_GRENAT, IPV4, FRG, NONE, PAY3),
	NSE_PTT(146, IP, IPV4, NOF, IP_GRENAT, IPV4, NOF, NONE, PAY3),
	NSE_PTT(147, IP, IPV4, NOF, IP_GRENAT, IPV4, NOF, UDP, PAY4),
	NSE_PTT(148, IP, IPV4, NOF, IP_GRENAT, IPV4, NOF, TCP, PAY4),
	NSE_PTT(149, IP, IPV4, NOF, IP_GRENAT, IPV4, NOF, SCTP, PAY4),
	NSE_PTT(150, IP, IPV4, NOF, IP_GRENAT, IPV4, NOF, ICMP, PAY4),

	NSE_PTT_UNUSED_ENTRY(151),
	NSE_PTT_UNUSED_ENTRY(152),

	NSE_PTT(153, IP, IPV4, NOF, IP_GRENAT, IPV6, FRG, NONE, PAY3),
	NSE_PTT(154, IP, IPV4, NOF, IP_GRENAT, IPV6, NOF, NONE, PAY3),
	NSE_PTT(155, IP, IPV4, NOF, IP_GRENAT, IPV6, NOF, UDP, PAY4),
	NSE_PTT(156, IP, IPV4, NOF, IP_GRENAT, IPV6, NOF, TCP, PAY4),
	NSE_PTT(157, IP, IPV4, NOF, IP_GRENAT, IPV6, NOF, SCTP, PAY4),
	NSE_PTT(158, IP, IPV4, NOF, IP_GRENAT, IPV6, NOF, ICMP, PAY4),

	NSE_PTT_UNUSED_ENTRY(159),

	NSE_PTT(160, IP, IPV4, NOF, IP_GRENAT_MAC, NONE, NOF, NONE, PAY2),

	NSE_PTT(161, IP, IPV4, NOF, IP_GRENAT_MAC, IPV4, FRG, NONE, PAY3),
	NSE_PTT(162, IP, IPV4, NOF, IP_GRENAT_MAC, IPV4, NOF, NONE, PAY3),
	NSE_PTT(163, IP, IPV4, NOF, IP_GRENAT_MAC, IPV4, NOF, UDP, PAY4),
	NSE_PTT(164, IP, IPV4, NOF, IP_GRENAT_MAC, IPV4, NOF, TCP, PAY4),
	NSE_PTT(165, IP, IPV4, NOF, IP_GRENAT_MAC, IPV4, NOF, SCTP, PAY4),
	NSE_PTT(166, IP, IPV4, NOF, IP_GRENAT_MAC, IPV4, NOF, ICMP, PAY4),

	NSE_PTT_UNUSED_ENTRY(167),
	NSE_PTT_UNUSED_ENTRY(168),

	NSE_PTT(169, IP, IPV4, NOF, IP_GRENAT_MAC, IPV6, FRG, NONE, PAY3),
	NSE_PTT(170, IP, IPV4, NOF, IP_GRENAT_MAC, IPV6, NOF, NONE, PAY3),
	NSE_PTT(171, IP, IPV4, NOF, IP_GRENAT_MAC, IPV6, NOF, UDP, PAY4),
	NSE_PTT(172, IP, IPV4, NOF, IP_GRENAT_MAC, IPV6, NOF, TCP, PAY4),
	NSE_PTT(173, IP, IPV4, NOF, IP_GRENAT_MAC, IPV6, NOF, SCTP, PAY4),
	NSE_PTT(174, IP, IPV4, NOF, IP_GRENAT_MAC, IPV6, NOF, ICMP, PAY4),

	NSE_PTT_UNUSED_ENTRY(175),

	NSE_PTT(192, IP, IPV6, NOF, NONE, NONE, NOF, NONE, PAY2),

	NSE_PTT(193, IP, IPV6, NOF, IP_IP, IPV4, FRG, NONE, PAY4),
	NSE_PTT(194, IP, IPV6, NOF, IP_IP, IPV4, NOF, NONE, PAY4),
	NSE_PTT(195, IP, IPV6, NOF, IP_IP, IPV4, NOF, UDP, PAY4),
	NSE_PTT(196, IP, IPV6, NOF, IP_IP, IPV4, NOF, TCP, PAY4),
	NSE_PTT(197, IP, IPV6, NOF, IP_IP, IPV4, NOF, SCTP, PAY4),
	NSE_PTT(198, IP, IPV6, NOF, IP_IP, IPV4, NOF, ICMP, PAY4),

	NSE_PTT_UNUSED_ENTRY(199),
	NSE_PTT_UNUSED_ENTRY(200),

	NSE_PTT(201, IP, IPV6, NOF, IP_IP, IPV6, FRG, NONE, PAY3),
	NSE_PTT(202, IP, IPV6, NOF, IP_IP, IPV6, NOF, NONE, PAY3),
	NSE_PTT(203, IP, IPV6, NOF, IP_IP, IPV6, NOF, UDP, PAY4),
	NSE_PTT(204, IP, IPV6, NOF, IP_IP, IPV6, NOF, TCP, PAY4),
	NSE_PTT(205, IP, IPV6, NOF, IP_IP, IPV6, NOF, SCTP, PAY4),
	NSE_PTT(206, IP, IPV6, NOF, IP_IP, IPV6, NOF, ICMP, PAY4),

	NSE_PTT_UNUSED_ENTRY(207),

	NSE_PTT(208, IP, IPV6, NOF, IP_GRENAT, NONE, NOF, NONE, PAY2),

	NSE_PTT(209, IP, IPV6, NOF, IP_GRENAT, IPV4, FRG, NONE, PAY3),
	NSE_PTT(210, IP, IPV6, NOF, IP_GRENAT, IPV4, NOF, NONE, PAY3),
	NSE_PTT(211, IP, IPV6, NOF, IP_GRENAT, IPV4, NOF, UDP, PAY4),
	NSE_PTT(212, IP, IPV6, NOF, IP_GRENAT, IPV4, NOF, TCP, PAY4),
	NSE_PTT(213, IP, IPV6, NOF, IP_GRENAT, IPV4, NOF, SCTP, PAY4),
	NSE_PTT(214, IP, IPV6, NOF, IP_GRENAT, IPV4, NOF, ICMP, PAY4),

	NSE_PTT_UNUSED_ENTRY(215),
	NSE_PTT_UNUSED_ENTRY(216),

	NSE_PTT(217, IP, IPV6, NOF, IP_GRENAT, IPV6, FRG, NONE, PAY3),
	NSE_PTT(218, IP, IPV6, NOF, IP_GRENAT, IPV6, NOF, NONE, PAY3),
	NSE_PTT(219, IP, IPV6, NOF, IP_GRENAT, IPV6, NOF, UDP, PAY4),
	NSE_PTT(220, IP, IPV6, NOF, IP_GRENAT, IPV6, NOF, TCP, PAY4),
	NSE_PTT(221, IP, IPV6, NOF, IP_GRENAT, IPV6, NOF, SCTP, PAY4),
	NSE_PTT(222, IP, IPV6, NOF, IP_GRENAT, IPV6, NOF, ICMP, PAY4),

	NSE_PTT_UNUSED_ENTRY(223),

	NSE_PTT(224, IP, IPV6, NOF, IP_GRENAT_MAC, NONE, NOF, NONE, PAY2),

	NSE_PTT(225, IP, IPV6, NOF, IP_GRENAT_MAC, IPV4, FRG, NONE, PAY3),
	NSE_PTT(226, IP, IPV6, NOF, IP_GRENAT_MAC, IPV4, NOF, NONE, PAY3),
	NSE_PTT(227, IP, IPV6, NOF, IP_GRENAT_MAC, IPV4, NOF, UDP, PAY4),
	NSE_PTT(228, IP, IPV6, NOF, IP_GRENAT_MAC, IPV4, NOF, TCP, PAY4),
	NSE_PTT(229, IP, IPV6, NOF, IP_GRENAT_MAC, IPV4, NOF, SCTP, PAY4),
	NSE_PTT(230, IP, IPV6, NOF, IP_GRENAT_MAC, IPV4, NOF, ICMP, PAY4),

	NSE_PTT_UNUSED_ENTRY(231),
	NSE_PTT_UNUSED_ENTRY(232),

	NSE_PTT(233, IP, IPV6, NOF, IP_GRENAT_MAC, IPV6, FRG, NONE, PAY3),
	NSE_PTT(234, IP, IPV6, NOF, IP_GRENAT_MAC, IPV6, NOF, NONE, PAY3),
	NSE_PTT(235, IP, IPV6, NOF, IP_GRENAT_MAC, IPV6, NOF, UDP, PAY4),
	NSE_PTT(236, IP, IPV6, NOF, IP_GRENAT_MAC, IPV6, NOF, TCP, PAY4),
	NSE_PTT(237, IP, IPV6, NOF, IP_GRENAT_MAC, IPV6, NOF, SCTP, PAY4),
	NSE_PTT(238, IP, IPV6, NOF, IP_GRENAT_MAC, IPV6, NOF, ICMP, PAY4),

	NSE_PTT_UNUSED_ENTRY(239),

	[240 ... 255] = { 0, 0, 0, 0, 0, 0, 0, 0, 0 }
};
