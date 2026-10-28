// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#include "nse.h"
#include "nse_common.h"
#include "nse_vf_mbx.h"
#include "nse_virtchnl.h"

/**
 * nse_aq_send_msg_to_vf
 * @hw: pointer to the hardware structure
 * @vfid: VF ID to send msg
 * @v_opcode: opcodes for VF-PF communication
 * @v_retval: return error code
 * @msg: pointer to the msg buffer
 * @msglen: msg length
 * @cd: pointer to command details
 *
 * Send message to VF driver (0x0802) using mailbox
 * queue and asynchronously sending message via
 * nse_sq_send_cmd() function
 */
enum nse_status
nse_aq_send_msg_to_vf(struct nse_hw *hw, u16 vf_vsi_abs_id, u32 v_opcode, u32 v_retval,
		      u8 *msg, u16 msglen, struct nse_sq_cd *cd)
{
	struct nse_pf *pf = (struct nse_pf *)hw->back;
	struct nse_aq_desc desc;
	void *cbuf = NULL;
	size_t cbuf_len = sizeof(struct nse_aqc_mbx_cmd_buff_hdr) + msglen;
	struct nse_aqc_mbx_cmd_buff_hdr *hdr = NULL;
	u16 vf_vsi_rel_id;
	u32 vmbx_arqlen;
	enum nse_status status;

	vf_vsi_rel_id = vf_vsi_abs_id - pf->vsi_space_start;

	if (vf_vsi_abs_id >= NSE_AQ_MAILBOX_ID_VSI_MAX ||
		vf_vsi_rel_id >= NSE_AQ_MAILBOX_ID_VSI_MAX)
		return NSE_ERR_DOES_NOT_EXIST;

	vmbx_arqlen = rd32(hw, NSE_REG_VMBX_ARQLEN(vf_vsi_rel_id));
	if (!(vmbx_arqlen & NSE_REG_VMBX_ARQLEN_STAT_Q_PAUSE_N_M) ||
		!(vmbx_arqlen & NSE_REG_VMBX_ARQLEN_STAT_Q_EN_M)) {
		nse_debug(hw, NSE_DBG_AQM_MSG, "[%s, %d] target VSI VMBX_ARQLEN=%X, not ready, no need to send_msg_to_vf\n",
									__func__, __LINE__,
										vmbx_arqlen);

		return NSE_SUCCESS;
	}

	cbuf = devm_kzalloc(nse_hw_to_dev(hw), cbuf_len, GFP_KERNEL);
	if (!cbuf)
		return NSE_ERR_NO_MEMORY;

	nse_fill_dflt_direct_cmd_desc(&desc, NSE_AQ_OPC_CATEGORY_COMM, NSE_AQ_OPC_SEND_MSG_TO_VF);

	/* overwite desc->mailbox_id to specify the actual target VSI mailbox */
	desc.mailbox_id = cpu_to_le16(vf_vsi_abs_id);

	/* always set RD and BUF flag, because always have indirect buffer  */
	desc.flags |= cpu_to_le16(NSE_AQ_FLAG_RD);
	desc.flags |= cpu_to_le16(NSE_AQ_FLAG_BUF);

	/* set hdr */
	hdr = (struct nse_aqc_mbx_cmd_buff_hdr *)cbuf;
	hdr->cookie_high = cpu_to_le32(v_opcode);
	hdr->cookie_low = cpu_to_le32(v_retval);

	/* copy the msg */
	if (msglen) {
		memcpy(cbuf + sizeof(struct nse_aqc_mbx_cmd_buff_hdr),
				msg,
				msglen);
	}

	nse_debug(hw, NSE_DBG_AQM_MSG, "send vch-msg to VF (mailbox_id=%d): vch-opcode=%d(%s), vch-retval=%d(%s)\n",
						vf_vsi_abs_id,
						v_opcode, virtchnl_op_str(v_opcode),
						v_retval, virtchnl_stat_str(v_retval));

	status = nse_sq_send_cmd(hw, &hw->adminq, &desc, cbuf, cbuf_len, cd);

	devm_kfree(nse_hw_to_dev(hw), cbuf);

	return status;
}

/**
 * nse_conv_link_speed_to_virtchnl
 * @adv_link_support: determines the format of the returned link speed
 * @link_speed: variable containing the link_speed to be converted
 *
 * Convert link speed supported by HW to link speed supported by virtchnl.
 * If adv_link_support is true, then return link speed in Mbps. Else return
 * link speed as a VIRTCHNL_LINK_SPEED_* casted to a u32. Note that the caller
 * needs to cast back to an enum virtchnl_link_speed in the case where
 * adv_link_support is false, but when adv_link_support is true the caller can
 * expect the speed in Mbps.
 */
u32 nse_conv_link_speed_to_virtchnl(struct nse_hw *hw, bool adv_link_support, u32 link_speed)
{
	u32 speed;

	if (adv_link_support) {
		switch (link_speed) {
		case NSE_AQ_LINK_SPEED_10MB:
			speed = SPEED_10;
			break;
		case NSE_AQ_LINK_SPEED_100MB:
			speed = SPEED_100;
			break;
		case NSE_AQ_LINK_SPEED_1000MB:
			speed = SPEED_1000;
			break;
		case NSE_AQ_LINK_SPEED_2500MB:
			speed = SPEED_2500;
			break;
		case NSE_AQ_LINK_SPEED_5GB:
			speed = SPEED_5000;
			break;
		case NSE_AQ_LINK_SPEED_10GB:
			speed = SPEED_10000;
			break;
		case NSE_AQ_LINK_SPEED_20GB:
			speed = SPEED_20000;
			break;
		case NSE_AQ_LINK_SPEED_25GB:
			speed = SPEED_25000;
			break;
		case NSE_AQ_LINK_SPEED_40GB:
			speed = SPEED_40000;
			break;
		case NSE_AQ_LINK_SPEED_50GB:
			speed = SPEED_50000;
			break;
		case NSE_AQ_LINK_SPEED_100GB:
			speed = SPEED_100000;
			break;
		case NSE_AQ_LINK_SPEED_200GB:
			speed = SPEED_200000;
			break;
		case NSE_AQ_LINK_SPEED_400GB:
			speed = SPEED_400000;
			break;
		case NSE_AQ_LINK_SPEED_800GB:
			speed = SPEED_800000;
			break;
		default:
			speed = 0;
			break;
		}

	} else {
		switch (link_speed) {
		case NSE_AQ_LINK_SPEED_10MB:
			speed = (u32)VIRTCHNL_LINK_SPEED_10MB;
			break;
		case NSE_AQ_LINK_SPEED_100MB:
			speed = (u32)VIRTCHNL_LINK_SPEED_100MB;
			break;
		case NSE_AQ_LINK_SPEED_1000MB:
			speed = (u32)VIRTCHNL_LINK_SPEED_1GB;
			break;
		case NSE_AQ_LINK_SPEED_2500MB:
			speed = (u32)VIRTCHNL_LINK_SPEED_2_5GB;
			break;
		case NSE_AQ_LINK_SPEED_5GB:
			speed = (u32)VIRTCHNL_LINK_SPEED_5GB;
			break;
		case NSE_AQ_LINK_SPEED_10GB:
			speed = (u32)VIRTCHNL_LINK_SPEED_10GB;
			break;
		case NSE_AQ_LINK_SPEED_20GB:
			speed = (u32)VIRTCHNL_LINK_SPEED_20GB;
			break;
		case NSE_AQ_LINK_SPEED_25GB:
			speed = (u32)VIRTCHNL_LINK_SPEED_25GB;
			break;
		case NSE_AQ_LINK_SPEED_40GB:
			speed = (u32)VIRTCHNL_LINK_SPEED_40GB;
			break;
		case NSE_AQ_LINK_SPEED_50GB:
			speed = (u32)VIRTCHNL_LINK_SPEED_50GB;
			break;
		case NSE_AQ_LINK_SPEED_100GB:
			speed = (u32)VIRTCHNL_LINK_SPEED_100GB;
			break;
		case NSE_AQ_LINK_SPEED_200GB:
			speed = (u32)VIRTCHNL_LINK_SPEED_200GB;
			break;
		case NSE_AQ_LINK_SPEED_400GB:
			speed = (u32)VIRTCHNL_LINK_SPEED_400GB;
			break;
		case NSE_AQ_LINK_SPEED_800GB:
			speed = (u32)VIRTCHNL_LINK_SPEED_800GB;
			break;
		default:
			speed = (u32)VIRTCHNL_LINK_SPEED_UNKNOWN;
			break;
		}
	}

	return speed;
}

