// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#include "nsevf.h"
#include "nsevf_prototype.h"
#include "nsevf_idc.h"
#include "nsevf_msgbox.h"

/**
 * nsevf_send_pf_msg
 * @adapter: adapter structure
 * @op: virtual channel opcode
 * @msg: pointer to message buffer
 * @len: message length
 *
 * Send message to PF and print status if failure.
 **/
static int nsevf_send_pf_msg(struct nsevf_adapter *adapter,
			     enum virtchnl_ops op, u8 *msg, u16 len)
{
	struct nsevf_hw *hw = &adapter->hw;
	enum nsevf_status status;

	if (adapter->flags & NSEVF_FLAG_PF_COMMS_FAILED)
		return 0; /* nothing to see here, move along */

	if (nsevf_use_msgbox)
		status = nse_msgbox_v2p_send_msg_to_pf(hw, op, VIRTCHNL_STATUS_SUCCESS, msg, len);
	else
		status = nsevf_aq_send_msg_to_pf(hw, op, VIRTCHNL_STATUS_SUCCESS, msg, len, NULL);
	if (status)
		dev_dbg(&adapter->pdev->dev,
			"Unable to send opcode %d to PF, status: %d (%s), aq_err %d (%s)\n",
			op, status, nsevf_stat_str(hw, status),
			hw->mailboxq.asq_last_status,
			nsevf_aq_str(hw, hw->mailboxq.asq_last_status));
	return nsevf_status_to_errno(status);
}

/**
 * nsevf_send_api_ver
 * @adapter: adapter structure
 *
 * Send API version admin queue message to the PF. The reply is not checked
 * in this function. Returns 0 if the message was successfully
 * sent, or one of the ERROR_ status if not.
 **/
int nsevf_send_api_ver(struct nsevf_adapter *adapter)
{
	struct virtchnl_version_info vvi;

	vvi.major = VIRTCHNL_VERSION_MAJOR;
	vvi.minor = VIRTCHNL_VERSION_MINOR;

	return nsevf_send_pf_msg(adapter, VIRTCHNL_OP_VERSION, (u8 *)&vvi,
				 sizeof(vvi));
}

/**
 * nsevf_poll_virtchnl_msg - poll for virtchnl msg matching the requested_op
 * @hw: HW configuration structure
 * @event: event to populate on success
 * @op_to_poll: requested virtchnl op to poll for
 *
 * Returns 0 if a message of the correct opcode is in the queue. Returns
 * -EALREADY if no message matching the op code is waiting. Returns an error
 *  code for other failures.
 */
static int nsevf_poll_virtchnl_msg(struct nsevf_hw *hw,
				   struct nsevf_arq_event_info *event,
				   enum virtchnl_ops op_to_poll)
{
	struct nsevf_adapter *adapter = (struct nsevf_adapter *)hw->back;
	struct device *dev = nsevf_hw_to_dev(hw);
	struct nse_aqc_mbx_cmd_buff_hdr *v_hdr = NULL;
	enum virtchnl_ops received_op;
	enum nsevf_status status;
	unsigned int i = 0;
	unsigned int retry_times = (nse_timeout_scale * 3);
	u32 v_retval;

	nsevf_debug(hw, NSEVF_DBG_SYS, "[%s] op_to_poll=%d\n", __func__,
		    op_to_poll);

	while (1) {
		event->vch_msg_content = NULL;
		event->vch_msg_len = 0;

		/* When the AQ is empty, nsevf_clean_arq_element will return
		 * NSEVF_ERR_AQ_NO_WORK and this loop will terminate. Callers
		 * which want to wait until a new message is received should
		 * check for -EALREADY and repeat polling attempts.
		 */
		status =
			nsevf_clean_arq_element(hw, &hw->mailboxq, event, NULL);
		if (status) {
			if (status == NSEVF_ERR_ADMIN_QUEUE_NO_WORK &&
			    ((i++) < retry_times)) {
				nsevf_debug(hw, NSEVF_DBG_AQM_MSG,
					    "[%s] not receive op_to_poll=%d yet, gonna retry %d th times (total %d times)\n",
					__func__, op_to_poll, i, retry_times);

				nsevf_aq_wait(adapter->wq_mid_interval * 1000);

				continue;
			} else {
				dev_err(dev,
					"[%s] error receive op_to_poll=%d, status=%d\n",
					__func__, op_to_poll, status);

				return nsevf_status_to_errno(status);
			}
		}

		if (event->msg_len < sizeof(struct nse_aqc_mbx_cmd_buff_hdr)) {
			nsevf_debug(hw, NSEVF_DBG_AQM_MSG,
				    "[%s] BAD msg_len for op_to_poll=%d\n",
				    __func__, op_to_poll);

			continue; /* invalid vch-msg, ignore it, and check the next one */
		}

		event->vch_msg_content =
			event->msg_buf +
			sizeof(struct nse_aqc_mbx_cmd_buff_hdr);
		event->vch_msg_len = event->msg_len -
				     sizeof(struct nse_aqc_mbx_cmd_buff_hdr);

		v_hdr = (struct nse_aqc_mbx_cmd_buff_hdr *)event->msg_buf;

		received_op =
			(enum virtchnl_ops)le32_to_cpu(v_hdr->cookie_high);

		if (received_op == VIRTCHNL_OP_EVENT) {
			struct virtchnl_pf_event *vpe =
				(struct virtchnl_pf_event *)
					event->vch_msg_content;

			if (vpe->event == VIRTCHNL_EVENT_RESET_IMPENDING) {
				dev_info(dev,
					 "[%s] Reset indication received from the PF, reset_type=%d\n",
					__func__,
					vpe->event_data.reset_event.reset_type);

				if (!(adapter->flags &
				      NSEVF_FLAG_RESET_PENDING)) {
					dev_info(dev,
						 "Scheduling reset task\n");
					adapter->external_reset_type =
						vpe->event_data.reset_event
							.reset_type;
					nsevf_schedule_reset(adapter,
							     (NSEVF_FLAG_RESET_NEEDED |
						 NSEVF_FLAG_RESET_PENDING));
				} else {
					dev_info(dev,
						 "Not Scheduling reset task, because already in reset\n");
				}

				return -EIO;
			}
		}

		if (op_to_poll == received_op)
			break;
	}

	v_retval = le32_to_cpu(v_hdr->cookie_low);
	return virtchnl_status_to_errno((enum virtchnl_status_code)v_retval);
}

/**
 * nsevf_verify_api_ver
 * @adapter: adapter structure
 *
 * Compare API versions with the PF. Must be called after admin queue is
 * initialized. Returns 0 if API versions match, -EIO if they do not,
 * NSEVF_ERR_ADMIN_QUEUE_NO_WORK if the admin queue is empty, and any errors
 * from the firmware are propagated.
 **/
int nsevf_verify_api_ver(struct nsevf_adapter *adapter)
{
	struct nsevf_arq_event_info event;
	int err;

	event.buf_len = NSEVF_MAX_AQ_BUF_SIZE;
	event.msg_buf = kzalloc(NSEVF_MAX_AQ_BUF_SIZE, GFP_KERNEL);
	if (!event.msg_buf)
		return -ENOMEM;

	if (nsevf_use_msgbox)
		err = nsevf_msgbox_p2v_poll_virtchnl_msg(&adapter->hw, &event,
							 VIRTCHNL_OP_VERSION);
	else
		err = nsevf_poll_virtchnl_msg(&adapter->hw, &event,
					      VIRTCHNL_OP_VERSION);

	if (!err) {
		struct virtchnl_version_info *pf_vvi =
			(struct virtchnl_version_info *)event.vch_msg_content;

		adapter->pf_version = *pf_vvi;

		if (pf_vvi->major > VIRTCHNL_VERSION_MAJOR ||
		    (pf_vvi->major == VIRTCHNL_VERSION_MAJOR &&
		     pf_vvi->minor > VIRTCHNL_VERSION_MINOR))
			err = -EIO;
	}

	adapter->current_op = VIRTCHNL_OP_UNKNOWN;

	kfree(event.msg_buf);
	return err;
}

/**
 * nsevf_send_vf_config_msg
 * @adapter: adapter structure
 *
 * Send VF configuration request admin queue message to the PF. The reply
 * is not checked in this function. Returns 0 if the message was
 * successfully sent, or one of the IAVF_ADMIN_QUEUE_ERROR_ statuses if not.
 **/
int nsevf_send_vf_config_msg(struct nsevf_adapter *adapter)
{
	u64 caps;

	caps = VIRTCHNL_VF_OFFLOAD_L2 | VIRTCHNL_VF_OFFLOAD_RSS_PF |
	       VIRTCHNL_VF_OFFLOAD_WB_ON_ITR |
	       VIRTCHNL_VF_OFFLOAD_BYPASS_SWITCH | VIRTCHNL_VF_OFFLOAD_ENCAP |
	       VIRTCHNL_VF_OFFLOAD_VLAN_V2 | VIRTCHNL_VF_OFFLOAD_RX_FLEX_DESC |
	       VIRTCHNL_VF_OFFLOAD_LSO | VIRTCHNL_VF_CAP_RDMA |
	       VIRTCHNL_VF_CAP_ADV_LINK_SPEED | VIRTCHNL_VF_OFFLOAD_ENCAP_CSUM;

	if (nsevf_lan_tx_use_cq)
		caps |= VIRTCHNL_VF_CAP_LAN_TX_USE_CQ;

	if (adapter->sw_conf.lan_rx_ena_rsc)
		caps |= VIRTCHNL_VF_CAP_LAN_RX_USE_RSC;

	if (nsevf_fdir_ena)
		caps |= VIRTCHNL_VF_CAP_FDIR;

	adapter->current_op = VIRTCHNL_OP_GET_VF_RESOURCES;
	adapter->aq_required &= ~NSEVF_FLAG_AQ_GET_CONFIG;

	return nsevf_send_pf_msg(adapter, VIRTCHNL_OP_GET_VF_RESOURCES,
				 (u8 *)&caps, sizeof(caps));
}

int nsevf_send_vf_offload_vlan_v2_msg(struct nsevf_adapter *adapter)
{
	adapter->aq_required &= ~NSEVF_FLAG_AQ_GET_OFFLOAD_VLAN_V2_CAPS;

	if (!VLAN_V2_ALLOWED(adapter))
		return -EOPNOTSUPP;

	adapter->current_op = VIRTCHNL_OP_GET_OFFLOAD_VLAN_V2_CAPS;

	return nsevf_send_pf_msg(adapter, VIRTCHNL_OP_GET_OFFLOAD_VLAN_V2_CAPS,
				 NULL, 0);
}

int nsevf_send_vf_supported_rxdids_msg(struct nsevf_adapter *adapter)
{
	adapter->aq_required &= ~NSEVF_FLAG_AQ_GET_SUPPORTED_RXDIDS;

	if (!RXDID_ALLOWED(adapter))
		return -EOPNOTSUPP;

	adapter->current_op = VIRTCHNL_OP_GET_SUPPORTED_RXDIDS;

	return nsevf_send_pf_msg(adapter, VIRTCHNL_OP_GET_SUPPORTED_RXDIDS,
				 NULL, 0);
}

/**
 * nsevf_validate_num_queues
 * @adapter: adapter structure
 *
 * Validate that the number of queues the PF has sent in
 * VIRTCHNL_OP_GET_VF_RESOURCES is not larger than the VF can handle.
 **/
static void nsevf_validate_num_queues(struct nsevf_adapter *adapter)
{
	if (adapter->vf_res->num_queue_pairs > NSEVF_MAX_REQ_QUEUES) {
		dev_info(&adapter->pdev->dev,
			 "Received %d queues, but can only have a max of %d\n",
			 adapter->vf_res->num_queue_pairs,
			 NSEVF_MAX_REQ_QUEUES);
		dev_info(&adapter->pdev->dev,
			 "Fixing by reducing queues to %d\n",
			 NSEVF_MAX_REQ_QUEUES);
		adapter->vf_res->num_queue_pairs = NSEVF_MAX_REQ_QUEUES;
		adapter->vf_res->vsi_res.num_queue_pairs = NSEVF_MAX_REQ_QUEUES;
	}

	if (adapter->vf_res->vf_cap_flags & VIRTCHNL_VF_CAP_LAN_TX_USE_CQ)
		adapter->sw_conf.lan_tx_use_cq = 1;
	else
		adapter->sw_conf.lan_tx_use_cq = 0;

	if (adapter->sw_conf.lan_rx_ena_rsc) {
		if (!(adapter->vf_res->vf_cap_flags &
		      VIRTCHNL_VF_CAP_LAN_RX_USE_RSC))
			adapter->sw_conf.lan_rx_ena_rsc =
				0; /* first time change, never change back */
	}
}

void dump_vf_res(struct nsevf_adapter *adapter,
		 struct virtchnl_vf_resource *vf_res)
{
	struct device *dev = nsevf_adapter_to_dev(adapter);

	dev_info(dev, "VF vf_res:\n");

	dev_info(dev, "\t num_vsis: %d\n", vf_res->num_vsis);

	dev_info(dev, "\t num_queue_pairs: %d\n", vf_res->num_queue_pairs);

	dev_info(dev, "\t max_vectors: %d\n", vf_res->max_vectors);

	dev_info(dev, "\t max_mtu: %d\n", vf_res->max_mtu);

	dev_info(dev, "\t lan_txcq_base_abs_id: %d\n",
		 vf_res->lan_txcq_base_abs_id);

	dev_info(dev, "\t lan_txcq_num: %d\n", vf_res->lan_txcq_num);

	dev_info(dev, "\t max_lan_vectors: %d\n", vf_res->max_lan_vectors);

	dev_info(dev, "\t vf_cap_flags: 0x%lX\n",
		 (unsigned long)vf_res->vf_cap_flags);

	dev_info(dev, "\t rss_key_size: 0x%x\n", vf_res->rss_key_size);

	dev_info(dev, "\t rss_lut_size: 0x%x\n", vf_res->rss_lut_size);

	dev_info(dev, "\t rss_ctl_alg: 0x%X\n", vf_res->rss_ctl_alg);

	dev_info(dev, "\t rss_hash_alg: 0x%X\n", vf_res->rss_hash_alg);

	/* fdir */
	dev_info(dev, "\t fdir_mode: 0x%X\n", vf_res->fdir_mode);

	dev_info(dev, "\t fdir_drp_rxq_abs_id: 0x%X\n",
		 vf_res->fdir_drp_rxq_abs_id);

	dev_info(dev, "\t pf_id: 0x%X\n", vf_res->pf_id);

	dev_info(dev, "\t lan_channel_pf_id: 0x%X\n",
		 vf_res->lan_channel_pf_id);

	dev_info(dev, "\t fdir_hkey: 0x%X\n", vf_res->fdir_hkey);

	dev_info(dev, "\t fdir_skey: 0x%X\n", vf_res->fdir_skey);

	dev_info(dev, "\t fdir_max_num_pfilter: 0x%X\n",
		 vf_res->fdir_max_num_pfilter);

	dev_info(dev, "\t fdir_max_num_sfilter: 0x%X\n",
		 vf_res->fdir_max_num_sfilter);

	dev_info(dev, "\t vsi_res:\n");

	dev_info(dev, "\t\t vsi_abs_id: %d\n", vf_res->vsi_res.vsi_abs_id);

	dev_info(dev, "\t\t vsi_rel_id: %d\n", vf_res->vsi_res.vsi_rel_id);

	dev_info(dev, "\t\t num_queue_pairs: %d\n",
		 vf_res->vsi_res.num_queue_pairs);

	dev_info(dev, "\t\t vsi_type: %d\n", vf_res->vsi_res.vsi_type);

	dev_info(dev, "\t\t vsi_mode: %d\n", vf_res->vsi_res.vsi_mode);

	dev_info(dev, "\t\t qset_handle: %d\n", vf_res->vsi_res.qset_handle);

	dev_info(dev, "\t\t default_mac_addr: %pM\n",
		 vf_res->vsi_res.default_mac_addr);
}

/**
 * nsevf_get_vf_config
 * @adapter: private adapter structure
 *
 * Get VF configuration from PF and populate hw structure. Must be called after
 * admin queue is initialized. Busy waits until response is received from PF,
 * with maximum timeout. Response from PF is returned in the buffer for further
 * processing by the caller.
 **/
int nsevf_get_vf_config(struct nsevf_adapter *adapter)
{
	struct nsevf_hw *hw = &adapter->hw;
	struct nsevf_arq_event_info event;
	int err;
	u16 len, vch_msg_len;

	vch_msg_len = sizeof(struct virtchnl_vf_resource);
	len = sizeof(struct nse_aqc_mbx_cmd_buff_hdr) +
	      vch_msg_len; /* need consider hdr */

	event.buf_len = len;
	event.msg_buf = kzalloc(len, GFP_KERNEL);
	if (!event.msg_buf)
		return -ENOMEM;

	if (nsevf_use_msgbox)
		err = nsevf_msgbox_p2v_poll_virtchnl_msg(hw, &event, VIRTCHNL_OP_GET_VF_RESOURCES);
	else
		err = nsevf_poll_virtchnl_msg(hw, &event,
					      VIRTCHNL_OP_GET_VF_RESOURCES);

	if (!err && event.vch_msg_content) {
		memcpy(adapter->vf_res, event.vch_msg_content,
		       min(event.vch_msg_len, vch_msg_len));

		if (hw->debug_mask & NSEVF_DBG_SYS) {
			dev_info(nsevf_adapter_to_dev(adapter),
				 "[%s, %d] receive vch-resp(get_vf_resources), dump its content.\n",
				__func__, __LINE__);

			dump_vf_res(adapter, adapter->vf_res);
		}
	}

	/* some PFs send more queues than we should have so validate that
	 * we aren't getting too many queues
	 */
	if (!err)
		nsevf_validate_num_queues(adapter);

	nsevf_vf_parse_hw_config(hw, adapter->vf_res);

	adapter->current_op = VIRTCHNL_OP_UNKNOWN;

	kfree(event.msg_buf);
	return err;
}

int nsevf_get_vf_vlan_v2_caps(struct nsevf_adapter *adapter)
{
	struct nsevf_arq_event_info event;
	int err;
	u16 len, vch_msg_len;

	vch_msg_len = sizeof(struct virtchnl_vlan_caps);
	len = sizeof(struct nse_aqc_mbx_cmd_buff_hdr) + vch_msg_len;
	event.buf_len = len;
	event.msg_buf = kzalloc(len, GFP_KERNEL);
	if (!event.msg_buf)
		return -ENOMEM;

	if (nsevf_use_msgbox)
		err = nsevf_msgbox_p2v_poll_virtchnl_msg(&adapter->hw, &event,
							 VIRTCHNL_OP_GET_OFFLOAD_VLAN_V2_CAPS);
	else
		err = nsevf_poll_virtchnl_msg(&adapter->hw, &event,
					      VIRTCHNL_OP_GET_OFFLOAD_VLAN_V2_CAPS);

	if (!err && event.vch_msg_content)
		memcpy(&adapter->vlan_v2_caps, event.vch_msg_content,
		       min(event.vch_msg_len, vch_msg_len));

	adapter->current_op = VIRTCHNL_OP_UNKNOWN;

	kfree(event.msg_buf);
	return err;
}

int nsevf_get_vf_supported_rxdids(struct nsevf_adapter *adapter)
{
	struct nsevf_arq_event_info event;
	int err;
	u16 len, vch_msg_len;

	vch_msg_len = sizeof(struct virtchnl_supported_rxdids);
	len = sizeof(struct nse_aqc_mbx_cmd_buff_hdr) + vch_msg_len;
	event.buf_len = len;
	event.msg_buf = kzalloc(len, GFP_KERNEL);
	if (!event.msg_buf)
		return -ENOMEM;

	if (nsevf_use_msgbox)
		err =
			nsevf_msgbox_p2v_poll_virtchnl_msg(&adapter->hw, &event,
							   VIRTCHNL_OP_GET_SUPPORTED_RXDIDS);
	else
		err = nsevf_poll_virtchnl_msg(&adapter->hw, &event,
					      VIRTCHNL_OP_GET_SUPPORTED_RXDIDS);

	if (!err && event.vch_msg_content)
		memcpy(&adapter->supported_rxdids, event.vch_msg_content,
		       min(event.vch_msg_len, vch_msg_len));

	adapter->current_op = VIRTCHNL_OP_UNKNOWN;

	kfree(event.msg_buf);
	return err;
}

/**
 * nsevf_configure_queues
 * @adapter: adapter structure
 *
 * Request that the PF set up our (previously allocated) queues.
 **/
void nsevf_configure_queues(struct nsevf_adapter *adapter)
{
	struct virtchnl_vsi_queue_config_info *vqci;
	struct virtchnl_queue_pair_info *vqpi;
	struct virtchnl_lan_txcq_info *vcqpi;
	int pairs = adapter->num_active_queues;
	int i, len;

	if (adapter->current_op != VIRTCHNL_OP_UNKNOWN) {
		/* bail because we already have a command pending */
		dev_err(&adapter->pdev->dev,
			"Cannot configure queues, command %d pending\n",
			adapter->current_op);
		return;
	}
	adapter->current_op = VIRTCHNL_OP_CONFIG_VSI_QUEUES;

	len = sizeof(struct virtchnl_vsi_queue_config_info) +
	      (sizeof(struct virtchnl_queue_pair_info) * pairs);
	if (adapter->sw_conf.lan_tx_use_cq) {
		len += (sizeof(struct virtchnl_lan_txcq_info) *
			adapter->vf_res->lan_txcq_num);
	}

	vqci = kzalloc(len, GFP_KERNEL);
	if (!vqci)
		return;

	vqci->vsi_abs_id = adapter->vsi_res->vsi_abs_id;
	vqci->vsi_rel_id = adapter->vsi_res->vsi_rel_id;
	vqci->num_queue_pairs = pairs;
	vqpi = vqci->qpair;
	/* Size check is not needed here - HW max is 16 queue pairs, and we
	 * can fit info for 31 of them into the AQ buffer before it overflows.
	 */
	for (i = 0; i < pairs; i++) {
		vqpi->txq.vsi_abs_id = vqci->vsi_abs_id;
		vqpi->txq.vsi_rel_id = vqci->vsi_rel_id;
		vqpi->txq.queue_id = i;
		vqpi->txq.ring_len = adapter->tx_rings[i].count;
		vqpi->txq.dma_ring_addr = adapter->tx_rings[i].dma;

		vqpi->rxq.vsi_abs_id = vqci->vsi_abs_id;
		vqpi->rxq.vsi_rel_id = vqci->vsi_rel_id;
		vqpi->rxq.queue_id = i;
		vqpi->rxq.ring_len = adapter->rx_rings[i].count;
		vqpi->rxq.dma_ring_addr = adapter->rx_rings[i].dma;
		vqpi->rxq.max_pkt_size =
			adapter->netdev->mtu + NSEVF_PACKET_HDR_PAD;
		vqpi->rxq.databuffer_size =
			ALIGN(adapter->rx_rings[i].rx_buf_len,
			      BIT_ULL(NSEVF_RXQ_CTX_DBUFF_SHIFT));
		if (RXDID_ALLOWED(adapter))
			vqpi->rxq.rxdid = adapter->rxdid;

		vqpi++;
	}

	vqci->lan_tx_use_cq = adapter->sw_conf.lan_tx_use_cq;

	if (adapter->sw_conf.lan_tx_use_cq) {
		vqci->num_txcq = adapter->vf_res->lan_txcq_num;

		/* after loop above, vqpi point right to our lan-cq part start in memory */
		vcqpi = (struct virtchnl_lan_txcq_info *)vqpi;

		for (i = 0; i < vqci->num_txcq; i++) {
			vcqpi->vsi_abs_id = vqci->vsi_abs_id;
			vcqpi->vsi_rel_id = vqci->vsi_rel_id;
			vcqpi->queue_id = i;
			vcqpi->ring_len = adapter->txcq_rings[i].count;
			vcqpi->dma_ring_addr = adapter->txcq_rings[i].dma;

			vcqpi++;
		}
	} else {
		vqci->num_txcq = 0;
	}

	adapter->aq_required &= ~NSEVF_FLAG_AQ_CONFIGURE_QUEUES;
	nsevf_send_pf_msg(adapter, VIRTCHNL_OP_CONFIG_VSI_QUEUES, (u8 *)vqci,
			  len);
	kfree(vqci);
}

/**
 * nsevf_enable_queues
 * @adapter: adapter structure
 *
 * Request that the PF enable all of our queues.
 **/
void nsevf_enable_queues(struct nsevf_adapter *adapter)
{
	struct virtchnl_queue_select vqs;

	if (adapter->current_op != VIRTCHNL_OP_UNKNOWN) {
		/* bail because we already have a command pending */
		dev_err(&adapter->pdev->dev,
			"Cannot enable queues, command %d pending\n",
			adapter->current_op);
		return;
	}
	adapter->current_op = VIRTCHNL_OP_ENABLE_QUEUES;
	vqs.vsi_abs_id = adapter->vsi_res->vsi_abs_id;
	vqs.vsi_rel_id = adapter->vsi_res->vsi_rel_id;
	vqs.tx_queues = BIT(adapter->num_active_queues) - 1;
	vqs.rx_queues = vqs.tx_queues;
	if (adapter->sw_conf.lan_tx_use_cq)
		vqs.txcq_queues = BIT(adapter->vf_res->lan_txcq_num) - 1;
	else
		vqs.txcq_queues = 0;

	adapter->aq_required &= ~NSEVF_FLAG_AQ_ENABLE_QUEUES;
	nsevf_send_pf_msg(adapter, VIRTCHNL_OP_ENABLE_QUEUES, (u8 *)&vqs,
			  sizeof(vqs));
}

/**
 * nsevf_disable_queues
 * @adapter: adapter structure
 *
 * Request that the PF disable all of our queues.
 **/
void nsevf_disable_queues(struct nsevf_adapter *adapter)
{
	struct virtchnl_queue_select vqs;

	if (adapter->current_op != VIRTCHNL_OP_UNKNOWN) {
		/* bail because we already have a command pending */
		dev_err(&adapter->pdev->dev,
			"Cannot disable queues, command %d pending\n",
			adapter->current_op);
		return;
	}
	adapter->current_op = VIRTCHNL_OP_DISABLE_QUEUES;
	vqs.vsi_abs_id = adapter->vsi_res->vsi_abs_id;
	vqs.vsi_rel_id = adapter->vsi_res->vsi_rel_id;
	vqs.tx_queues = BIT(adapter->num_active_queues) - 1;
	vqs.rx_queues = vqs.tx_queues;
	if (adapter->sw_conf.lan_tx_use_cq)
		vqs.txcq_queues = BIT(adapter->vf_res->lan_txcq_num) - 1;
	else
		vqs.txcq_queues = 0;

	adapter->aq_required &= ~NSEVF_FLAG_AQ_DISABLE_QUEUES;
	nsevf_send_pf_msg(adapter, VIRTCHNL_OP_DISABLE_QUEUES, (u8 *)&vqs,
			  sizeof(vqs));
}

/**
 * nsevf_map_queues
 * @adapter: adapter structure
 *
 * Request that the PF map queues to interrupt vectors. Misc causes, including
 * admin queue, are always mapped to vector 0.
 **/
void nsevf_map_queues(struct nsevf_adapter *adapter)
{
	struct virtchnl_irq_map_info *vimi;
	struct virtchnl_vector_map *vecmap;
	int v_idx, q_vectors, len;
	struct nsevf_q_vector *q_vector;

	if (adapter->current_op != VIRTCHNL_OP_UNKNOWN) {
		/* bail because we already have a command pending */
		dev_err(&adapter->pdev->dev,
			"Cannot map queues to vectors, command %d pending\n",
			adapter->current_op);
		return;
	}
	adapter->current_op = VIRTCHNL_OP_CONFIG_IRQ_MAP;

	q_vectors = adapter->num_msix_vectors - NONQ_VECS;

	len = sizeof(struct virtchnl_irq_map_info) +
	      (adapter->num_msix_vectors * sizeof(struct virtchnl_vector_map));
	vimi = kzalloc(len, GFP_KERNEL);
	if (!vimi)
		return;

	vimi->num_vectors = adapter->num_msix_vectors;
	/* Queue vectors first */
	for (v_idx = 0; v_idx < q_vectors; v_idx++) {
		q_vector = &adapter->q_vectors[v_idx];
		vecmap = &vimi->vecmap[v_idx];

		vecmap->vsi_abs_id = adapter->vsi_res->vsi_abs_id;
		vecmap->vsi_rel_id = adapter->vsi_res->vsi_rel_id;
		vecmap->vector_id = v_idx + NONQ_VECS;
		vecmap->txq_map = q_vector->ring_mask;
		vecmap->rxq_map = q_vector->ring_mask;
	}
	/* Misc vector last - this is only for AdminQ messages */
	vecmap = &vimi->vecmap[v_idx];
	vecmap->vsi_abs_id = adapter->vsi_res->vsi_abs_id;
	vecmap->vsi_rel_id = adapter->vsi_res->vsi_rel_id;
	vecmap->vector_id = 0;
	vecmap->txq_map = 0;
	vecmap->rxq_map = 0;

	adapter->aq_required &= ~NSEVF_FLAG_AQ_MAP_VECTORS;
	nsevf_send_pf_msg(adapter, VIRTCHNL_OP_CONFIG_IRQ_MAP, (u8 *)vimi, len);
	kfree(vimi);
}

/**
 * nsevf_set_mac_addr_type
 * @virtchnl_ether_addr: pointer to request list element
 * @filter: pointer filter being requested
 *
 * Set the correct request type.
 **/
static void
nsevf_set_mac_addr_type(struct virtchnl_ether_addr *virtchnl_ether_addr,
			struct nsevf_mac_filter *filter)
{
	virtchnl_ether_addr->type = filter->is_primary ?
					    VIRTCHNL_ETHER_ADDR_PRIMARY :
					    VIRTCHNL_ETHER_ADDR_EXTRA;
}

/**
 * nsevf_add_ether_addrs
 * @adapter: adapter structure
 *
 * Request that the PF add one or more addresses to our filters.
 **/
void nsevf_add_ether_addrs(struct nsevf_adapter *adapter)
{
	struct device *dev = nsevf_adapter_to_dev(adapter);
	struct nsevf_hw *hw = &adapter->hw;
	bool is_more = false, is_primary = false;
	struct virtchnl_ether_addr_list *veal = NULL;
	int len, i = 0, count = 0;
	struct nsevf_mac_filter *f = NULL;
	bool locked = false;

	if (adapter->current_op != VIRTCHNL_OP_UNKNOWN) {
		/* bail because we already have a command pending */
		dev_err(dev, "Cannot add filters, command %d pending\n",
			adapter->current_op);
		return;
	}

	spin_lock_bh(&adapter->mac_vlan_list_lock);

	locked = true;

	list_for_each_entry(f, &adapter->mac_filter_list, list) {
		if (f->add) {
			if (f->is_primary)
				is_primary = true;

			count++;
		}
	}

	if (is_primary) {
		if (count > 1)
			is_more = true;

		count = 1;
	}

	nsevf_debug(hw, NSEVF_DBG_SW,
		    "[%s, %d] is_primary=%d, count=%d, is_more=%d\n", __func__,
		    __LINE__, is_primary, count, is_more);

	if (!count) {
		adapter->aq_required &= ~NSEVF_FLAG_AQ_ADD_MAC_FILTER;
		goto out;
	}

	adapter->current_op = VIRTCHNL_OP_ADD_ETH_ADDR;

	len = sizeof(struct virtchnl_ether_addr_list) +
	      (count * sizeof(struct virtchnl_ether_addr));
	if (len >
	    (NSEVF_MAX_AQ_BUF_SIZE - sizeof(struct nse_aqc_mbx_cmd_buff_hdr))) {
		dev_warn(dev, "Too many add MAC changes in one request\n");
		count = (NSEVF_MAX_AQ_BUF_SIZE -
			 sizeof(struct nse_aqc_mbx_cmd_buff_hdr) -
			 sizeof(struct virtchnl_ether_addr_list)) /
			sizeof(struct virtchnl_ether_addr);
		len = sizeof(struct virtchnl_ether_addr_list) +
		      (count * sizeof(struct virtchnl_ether_addr));
		is_more = true;
	}

	veal = kzalloc(len, GFP_ATOMIC);
	if (!veal)
		goto out;

	veal->vsi_abs_id = adapter->vsi_res->vsi_abs_id;
	veal->vsi_rel_id = adapter->vsi_res->vsi_rel_id;
	veal->num_elements = count;
	list_for_each_entry(f, &adapter->mac_filter_list, list) {
		if (is_primary && !(f->is_primary && f->add))
			continue;
		if (!f->add)
			continue;

		nsevf_debug(hw, NSEVF_DBG_SW,
			    "[%s, %d]: add to list, mac_addr=%pM, is_primary=%d\n",
			__func__, __LINE__, f->macaddr, f->is_primary);

		ether_addr_copy(veal->list[i].addr, f->macaddr);
		nsevf_set_mac_addr_type(&veal->list[i], f);
		f->add = false;
		i++;

		if (i == count)
			break;
	}

	if (!is_more)
		adapter->aq_required &= ~NSEVF_FLAG_AQ_ADD_MAC_FILTER;

	spin_unlock_bh(&adapter->mac_vlan_list_lock);

	locked = false;

	nsevf_send_pf_msg(adapter, VIRTCHNL_OP_ADD_ETH_ADDR, (u8 *)veal, len);

out:
	if (locked)
		spin_unlock_bh(&adapter->mac_vlan_list_lock);

	kfree(veal);
}

/**
 * nsevf_del_ether_addrs
 * @adapter: adapter structure
 *
 * Request that the PF remove one or more addresses from our filters.
 **/
void nsevf_del_ether_addrs(struct nsevf_adapter *adapter)
{
	struct device *dev = nsevf_adapter_to_dev(adapter);
	struct nsevf_hw *hw = &adapter->hw;
	struct virtchnl_ether_addr_list *veal = NULL;
	struct nsevf_mac_filter *f, *ftmp;
	int len, i = 0, count = 0;
	bool more = false;
	bool locked = false;

	if (adapter->current_op != VIRTCHNL_OP_UNKNOWN) {
		/* bail because we already have a command pending */
		dev_err(dev, "Cannot remove filters, command %d pending\n",
			adapter->current_op);
		return;
	}

	spin_lock_bh(&adapter->mac_vlan_list_lock);

	locked = true;

	list_for_each_entry(f, &adapter->mac_filter_list, list) {
		if (f->remove)
			count++;
	}
	if (!count) {
		adapter->aq_required &= ~NSEVF_FLAG_AQ_DEL_MAC_FILTER;
		goto out;
	}
	adapter->current_op = VIRTCHNL_OP_DEL_ETH_ADDR;

	len = sizeof(struct virtchnl_ether_addr_list) +
	      (count * sizeof(struct virtchnl_ether_addr));
	if (len >
	    (NSEVF_MAX_AQ_BUF_SIZE - sizeof(struct nse_aqc_mbx_cmd_buff_hdr))) {
		dev_warn(dev, "Too many delete MAC changes in one request\n");
		count = (NSEVF_MAX_AQ_BUF_SIZE -
			 sizeof(struct nse_aqc_mbx_cmd_buff_hdr) -
			 sizeof(struct virtchnl_ether_addr_list)) /
			sizeof(struct virtchnl_ether_addr);
		len = sizeof(struct virtchnl_ether_addr_list) +
		      (count * sizeof(struct virtchnl_ether_addr));
		more = true;
	}
	veal = kzalloc(len, GFP_ATOMIC);
	if (!veal)
		goto out;

	veal->vsi_abs_id = adapter->vsi_res->vsi_abs_id;
	veal->vsi_rel_id = adapter->vsi_res->vsi_rel_id;
	veal->num_elements = count;
	list_for_each_entry_safe(f, ftmp, &adapter->mac_filter_list, list) {
		if (f->remove) {
			ether_addr_copy(veal->list[i].addr, f->macaddr);
			nsevf_set_mac_addr_type(&veal->list[i], f);

			nsevf_debug(hw, NSEVF_DBG_SW,
				    "[%s, %d]: add to list, mac_addr=%pM\n",
				    __func__, __LINE__, f->macaddr);

			i++;
			list_del(&f->list);
			kfree(f);
			if (i == count)
				break;
		}
	}
	if (!more)
		adapter->aq_required &= ~NSEVF_FLAG_AQ_DEL_MAC_FILTER;

	spin_unlock_bh(&adapter->mac_vlan_list_lock);

	locked = false;

	nsevf_send_pf_msg(adapter, VIRTCHNL_OP_DEL_ETH_ADDR, (u8 *)veal, len);

out:
	if (locked)
		spin_unlock_bh(&adapter->mac_vlan_list_lock);

	kfree(veal);
}

/**
 * nsevf_mac_add_ok
 * @adapter: adapter structure
 *
 * Submit list of filters based on PF response.
 **/
static void nsevf_mac_add_ok(struct nsevf_adapter *adapter)
{
	struct nsevf_mac_filter *f, *ftmp;

	spin_lock_bh(&adapter->mac_vlan_list_lock);
	list_for_each_entry_safe(f, ftmp, &adapter->mac_filter_list, list) {
		f->is_new_mac = false;
		if (!f->add && !f->add_handled) {
			f->add_handled = true;
			if (f->is_primary)
				netdev_info(adapter->netdev,
					    "Setting MAC Address to %pM",
					    adapter->hw.mac.addr);
		}
	}
	spin_unlock_bh(&adapter->mac_vlan_list_lock);
}

/**
 * nsevf_netdev_mc_mac_add_reject
 * @adapter: adapter structure
 *
 * Remove multicast addresses from netdev list based on PF response.
 **/
static void nsevf_netdev_mc_mac_add_reject(struct nsevf_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	struct nsevf_mac_filter *f, *ftmp, *elem;
	struct list_head tmp_del_list;

	INIT_LIST_HEAD(&tmp_del_list);
	spin_lock_bh(&adapter->mac_vlan_list_lock);
	list_for_each_entry(f, &adapter->mac_filter_list, list) {
		if (f->is_new_mac && is_multicast_ether_addr(f->macaddr)) {
			elem = kzalloc(sizeof(*elem), GFP_ATOMIC);
			if (!elem)
				goto out;
			ether_addr_copy(elem->macaddr, f->macaddr);
			list_add(&elem->list, &tmp_del_list);
		}
	}
out:
	spin_unlock_bh(&adapter->mac_vlan_list_lock);
	list_for_each_entry_safe(f, ftmp, &tmp_del_list, list) {
		dev_mc_del(netdev, f->macaddr);
		kfree(f);
	}
}

/**
 * nsevf_mac_add_reject
 * @adapter: adapter structure
 *
 * Remove filters from list based on PF response.
 **/
static void nsevf_mac_add_reject(struct nsevf_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	struct nsevf_mac_filter *f, *ftmp;

	spin_lock_bh(&adapter->mac_vlan_list_lock);
	list_for_each_entry_safe(f, ftmp, &adapter->mac_filter_list, list) {
		if (f->remove && ether_addr_equal(f->macaddr, netdev->dev_addr))
			f->remove = false;

		if (!f->add && !f->add_handled)
			f->add_handled = true;

		if (f->is_new_mac) {
			list_del(&f->list);
			kfree(f);
		}
	}
	spin_unlock_bh(&adapter->mac_vlan_list_lock);
}

/**
 * nsevf_vlan_add_reject
 * @adapter: adapter structure
 *
 * Remove VLAN filters from list based on PF response.
 **/
static void nsevf_vlan_add_reject(struct nsevf_adapter *adapter)
{
	struct nsevf_vlan_filter *f, *ftmp;

	spin_lock_bh(&adapter->mac_vlan_list_lock);
	list_for_each_entry_safe(f, ftmp, &adapter->vlan_filter_list, list) {
		if (f->is_new_vlan) {
			if (f->vlan.tpid == ETH_P_8021Q)
				clear_bit(f->vlan.vid,
					  adapter->vsi.active_cvlans);
			else
				clear_bit(f->vlan.vid,
					  adapter->vsi.active_svlans);

			list_del(&f->list);
			kfree(f);
		}
	}
	spin_unlock_bh(&adapter->mac_vlan_list_lock);
}

/**
 * nsevf_add_vlans
 * @adapter: adapter structure
 *
 * Request that the PF add one or more VLAN filters to our VSI.
 **/
void nsevf_add_vlans(struct nsevf_adapter *adapter)
{
	int len, i = 0, count = 0;
	struct nsevf_vlan_filter *f;
	bool more = false;

	if (adapter->current_op != VIRTCHNL_OP_UNKNOWN) {
		/* bail because we already have a command pending */
		dev_err(&adapter->pdev->dev,
			"Cannot add VLANs, command %d pending\n",
			adapter->current_op);
		return;
	}

	spin_lock_bh(&adapter->mac_vlan_list_lock);

	list_for_each_entry(f, &adapter->vlan_filter_list, list) {
		if (f->add)
			count++;
	}
	if (!count || !VLAN_FILTERING_ALLOWED(adapter)) {
		/* prevent endless add VLAN requests */
		adapter->aq_required &= ~NSEVF_FLAG_AQ_ADD_VLAN_FILTER;
		spin_unlock_bh(&adapter->mac_vlan_list_lock);
		return;
	}

	if (VLAN_V2_ALLOWED(adapter)) {
		u16 max_vlans = adapter->vlan_v2_caps.filtering.max_filters;
		u16 current_vlans = nsevf_get_num_vlans_added(adapter);
		struct virtchnl_vlan_filter_list_v2 *vvfl_v2;

		adapter->current_op = VIRTCHNL_OP_ADD_VLAN_V2;

		if ((count + current_vlans) > max_vlans &&
		    current_vlans < max_vlans) {
			count = max_vlans - nsevf_get_num_vlans_added(adapter);
			more = true;
		}

		len = sizeof(*vvfl_v2) +
		      ((count - 1) * sizeof(struct virtchnl_vlan_filter));
		if (len > (NSEVF_MAX_AQ_BUF_SIZE -
			   sizeof(struct nse_aqc_mbx_cmd_buff_hdr))) {
			dev_warn(&adapter->pdev->dev,
				 "Too many add VLAN changes in one request\n");
			count = (NSEVF_MAX_AQ_BUF_SIZE -
				 sizeof(struct nse_aqc_mbx_cmd_buff_hdr) -
				 sizeof(*vvfl_v2)) /
				sizeof(struct virtchnl_vlan_filter);
			len = sizeof(*vvfl_v2) +
			      ((count - 1) *
			       sizeof(struct virtchnl_vlan_filter));
			more = true;
		}

		vvfl_v2 = kzalloc(len, GFP_ATOMIC);
		if (!vvfl_v2) {
			spin_unlock_bh(&adapter->mac_vlan_list_lock);
			return;
		}

		vvfl_v2->vsi_abs_id = adapter->vsi_res->vsi_abs_id;
		vvfl_v2->vsi_rel_id = adapter->vsi_res->vsi_rel_id;
		vvfl_v2->num_elements = count;
		list_for_each_entry(f, &adapter->vlan_filter_list, list) {
			if (f->add) {
				struct virtchnl_vlan_supported_caps
					*filtering_support =
						&adapter->vlan_v2_caps.filtering
							 .filtering_support;
				struct virtchnl_vlan *vlan;

				if (i == count)
					break;
				/* give priority over outer if it's enabled */
				if (filtering_support->outer)
					vlan = &vvfl_v2->filters[i].outer;
				else
					vlan = &vvfl_v2->filters[i].inner;

				vlan->tci = f->vlan.vid;
				vlan->tpid = f->vlan.tpid;

				i++;
				f->add = false;
				f->is_new_vlan = true;
			}
		}

		if (!more)
			adapter->aq_required &= ~NSEVF_FLAG_AQ_ADD_VLAN_FILTER;

		spin_unlock_bh(&adapter->mac_vlan_list_lock);

		nsevf_send_pf_msg(adapter, VIRTCHNL_OP_ADD_VLAN_V2,
				  (u8 *)vvfl_v2, len);
		kfree(vvfl_v2);
	} else {
		dev_err(&adapter->pdev->dev,
			"HOW COME VLAN_V2_ALLOWED() is FALSE ?");

		adapter->aq_required &= ~NSEVF_FLAG_AQ_ADD_VLAN_FILTER;
		spin_unlock_bh(&adapter->mac_vlan_list_lock);
		return;
	}
}

/**
 * nsevf_del_vlans
 * @adapter: adapter structure
 *
 * Request that the PF remove one or more VLAN filters from our VSI.
 **/
void nsevf_del_vlans(struct nsevf_adapter *adapter)
{
	struct nsevf_vlan_filter *f, *ftmp;
	int len, i = 0, count = 0;
	bool more = false;

	if (adapter->current_op != VIRTCHNL_OP_UNKNOWN) {
		/* bail because we already have a command pending */
		dev_err(&adapter->pdev->dev,
			"Cannot remove VLANs, command %d pending\n",
			adapter->current_op);
		return;
	}

	spin_lock_bh(&adapter->mac_vlan_list_lock);

	list_for_each_entry_safe(f, ftmp, &adapter->vlan_filter_list, list) {
		if (f->remove && !VLAN_FILTERING_ALLOWED(adapter)) {
			list_del(&f->list);
			kfree(f);
		} else if (f->remove) {
			count++;
		}
	}
	if (!count) {
		/* prevent endless del VLAN requests */
		adapter->aq_required &= ~NSEVF_FLAG_AQ_DEL_VLAN_FILTER;
		spin_unlock_bh(&adapter->mac_vlan_list_lock);
		return;
	}

	if (VLAN_V2_ALLOWED(adapter)) {
		struct virtchnl_vlan_filter_list_v2 *vvfl_v2;

		adapter->current_op = VIRTCHNL_OP_DEL_VLAN_V2;

		len = sizeof(*vvfl_v2) +
		      ((count - 1) * sizeof(struct virtchnl_vlan_filter));
		if (len > (NSEVF_MAX_AQ_BUF_SIZE -
			   sizeof(struct nse_aqc_mbx_cmd_buff_hdr))) {
			dev_warn(&adapter->pdev->dev,
				 "Too many add VLAN changes in one request\n");
			count = (NSEVF_MAX_AQ_BUF_SIZE -
				 sizeof(struct nse_aqc_mbx_cmd_buff_hdr) -
				 sizeof(*vvfl_v2)) /
				sizeof(struct virtchnl_vlan_filter);
			len = sizeof(*vvfl_v2) +
			      ((count - 1) *
			       sizeof(struct virtchnl_vlan_filter));
			more = true;
		}

		vvfl_v2 = kzalloc(len, GFP_ATOMIC);
		if (!vvfl_v2) {
			spin_unlock_bh(&adapter->mac_vlan_list_lock);
			return;
		}

		vvfl_v2->vsi_abs_id = adapter->vsi_res->vsi_abs_id;
		vvfl_v2->vsi_rel_id = adapter->vsi_res->vsi_rel_id;
		vvfl_v2->num_elements = count;
		list_for_each_entry_safe(f, ftmp, &adapter->vlan_filter_list,
					 list) {
			if (f->remove) {
				struct virtchnl_vlan_supported_caps
					*filtering_support =
						&adapter->vlan_v2_caps.filtering
							 .filtering_support;
				struct virtchnl_vlan *vlan;

				/* give priority over outer if it's enabled */
				if (filtering_support->outer)
					vlan = &vvfl_v2->filters[i].outer;
				else
					vlan = &vvfl_v2->filters[i].inner;

				vlan->tci = f->vlan.vid;
				vlan->tpid = f->vlan.tpid;

				list_del(&f->list);
				kfree(f);
				i++;
				if (i == count)
					break;
			}
		}

		if (!more)
			adapter->aq_required &= ~NSEVF_FLAG_AQ_DEL_VLAN_FILTER;

		spin_unlock_bh(&adapter->mac_vlan_list_lock);

		nsevf_send_pf_msg(adapter, VIRTCHNL_OP_DEL_VLAN_V2,
				  (u8 *)vvfl_v2, len);
		kfree(vvfl_v2);
	} else {
		dev_err(&adapter->pdev->dev,
			"HOW COME VLAN_V2_ALLOWED() is FALSE ?");

		adapter->aq_required &= ~NSEVF_FLAG_AQ_DEL_VLAN_FILTER;
		spin_unlock_bh(&adapter->mac_vlan_list_lock);
		return;
	}
}

/**
 * nsevf_set_promiscuous
 * @adapter: adapter structure
 *
 * Request that the PF enable promiscuous mode for our VSI.
 **/
void nsevf_set_promiscuous(struct nsevf_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	struct virtchnl_promisc_info vpi;
	unsigned int flags;

	if (adapter->current_op != VIRTCHNL_OP_UNKNOWN) {
		/* bail because we already have a command pending */
		dev_err(&adapter->pdev->dev,
			"Cannot set promiscuous mode, command %d pending\n",
			adapter->current_op);
		return;
	}

	/* prevent changes to promiscuous flags */
	spin_lock_bh(&adapter->current_netdev_promisc_flags_lock);

	/* sanity check to prevent duplicate AQ calls */
	if (!nsevf_promiscuous_mode_changed(adapter)) {
		adapter->aq_required &= ~NSEVF_FLAG_AQ_CONFIGURE_PROMISC_MODE;
		dev_dbg(&adapter->pdev->dev, "No change in promiscuous mode\n");
		/* allow changes to promiscuous flags */
		spin_unlock_bh(&adapter->current_netdev_promisc_flags_lock);
		return;
	}

	/* there are 2 bits, but only 3 states */
	if (!(netdev->flags & IFF_PROMISC) && netdev->flags & IFF_ALLMULTI) {
		/* State 1  - only multicast promiscuous mode enabled
		 * - !IFF_PROMISC && IFF_ALLMULTI
		 */
		flags = FLAG_VF_MULTICAST_PROMISC;
		adapter->current_netdev_promisc_flags |= IFF_ALLMULTI;
		adapter->current_netdev_promisc_flags &= ~IFF_PROMISC;
		dev_info(&adapter->pdev->dev,
			 "Entering multicast promiscuous mode\n");
	} else if (!(netdev->flags & IFF_PROMISC) &&
		   !(netdev->flags & IFF_ALLMULTI)) {
		/* State 2 - unicast/multicast promiscuous mode disabled
		 * - !IFF_PROMISC && !IFF_ALLMULTI
		 */
		flags = 0;
		adapter->current_netdev_promisc_flags &=
			~(IFF_PROMISC | IFF_ALLMULTI);
		dev_info(&adapter->pdev->dev, "Leaving promiscuous mode\n");
	} else {
		/* State 3 - unicast/multicast promiscuous mode enabled
		 * - IFF_PROMISC && IFF_ALLMULTI
		 * - IFF_PROMISC && !IFF_ALLMULTI
		 */
		flags = FLAG_VF_UNICAST_PROMISC | FLAG_VF_MULTICAST_PROMISC;
		adapter->current_netdev_promisc_flags |= IFF_PROMISC;
		if (netdev->flags & IFF_ALLMULTI)
			adapter->current_netdev_promisc_flags |= IFF_ALLMULTI;
		else
			adapter->current_netdev_promisc_flags &= ~IFF_ALLMULTI;

		dev_info(&adapter->pdev->dev, "Entering promiscuous mode\n");
	}

	adapter->aq_required &= ~NSEVF_FLAG_AQ_CONFIGURE_PROMISC_MODE;

	/* allow changes to promiscuous flags */
	spin_unlock_bh(&adapter->current_netdev_promisc_flags_lock);

	adapter->current_op = VIRTCHNL_OP_CONFIG_PROMISCUOUS_MODE;
	vpi.vsi_abs_id = adapter->vsi_res->vsi_abs_id;
	vpi.vsi_rel_id = adapter->vsi_res->vsi_rel_id;
	vpi.flags = flags;
	nsevf_send_pf_msg(adapter, VIRTCHNL_OP_CONFIG_PROMISCUOUS_MODE,
			  (u8 *)&vpi, sizeof(vpi));
}

/**
 * nsevf_request_stats
 * @adapter: adapter structure
 *
 * Request VSI statistics from PF.
 **/
void nsevf_request_stats(struct nsevf_adapter *adapter)
{
	struct virtchnl_queue_select vqs;

	if (adapter->current_op != VIRTCHNL_OP_UNKNOWN) {
		/* no error message, this isn't crucial */
		return;
	}

	adapter->aq_required &= ~NSEVF_FLAG_AQ_REQUEST_STATS;
	adapter->current_op = VIRTCHNL_OP_GET_STATS;
	vqs.vsi_abs_id = adapter->vsi_res->vsi_abs_id;
	vqs.vsi_rel_id = adapter->vsi_res->vsi_rel_id;
	/* queue maps are ignored for this message - only the vsi is used */
	if (nsevf_send_pf_msg(adapter, VIRTCHNL_OP_GET_STATS, (u8 *)&vqs,
			      sizeof(vqs)))
		/* if the request failed, don't lock out others */
		adapter->current_op = VIRTCHNL_OP_UNKNOWN;
}

void nsevf_set_rss_alg(struct nsevf_adapter *adapter)
{
	struct virtchnl_rss_alg *vra;
	int len;

	if (adapter->current_op != VIRTCHNL_OP_UNKNOWN) {
		/* bail because we already have a command pending */
		dev_err(&adapter->pdev->dev,
			"Cannot set RSS alg, command %d pending\n",
			adapter->current_op);
		return;
	}
	len = sizeof(struct virtchnl_rss_alg);
	vra = kzalloc(len, GFP_KERNEL);
	if (!vra)
		return;
	vra->vsi_abs_id = adapter->vsi.vsi_abs_id;
	vra->vsi_rel_id = adapter->vsi.vsi_rel_id;
	vra->ctl_alg = adapter->rss_ctl_alg;
	//	vra->hash_alg = adapter->rss_hash_alg;	//not used for now.

	adapter->current_op = VIRTCHNL_OP_CONFIG_RSS_ALG;
	adapter->aq_required &= ~NSEVF_FLAG_AQ_SET_RSS_ALG;
	nsevf_send_pf_msg(adapter, VIRTCHNL_OP_CONFIG_RSS_ALG, (u8 *)vra, len);
	kfree(vra);
}

/**
 * nsevf_set_rss_key - set the RSS hash key
 * @adapter: adapter structure
 *
 * Request the PF to set our RSS hash key
 **/
void nsevf_set_rss_key(struct nsevf_adapter *adapter)
{
	struct virtchnl_rss_key *vrk;
	int len;

	if (adapter->current_op != VIRTCHNL_OP_UNKNOWN) {
		/* bail because we already have a command pending */
		dev_err(&adapter->pdev->dev,
			"Cannot set RSS key, command %d pending\n",
			adapter->current_op);
		return;
	}
	len = sizeof(struct virtchnl_rss_key) +
	      (adapter->rss_key_size * sizeof(u8)) - 1;
	vrk = kzalloc(len, GFP_KERNEL);
	if (!vrk)
		return;
	vrk->vsi_abs_id = adapter->vsi.vsi_abs_id;
	vrk->vsi_rel_id = adapter->vsi.vsi_rel_id;
	vrk->key_len = adapter->rss_key_size;
	memcpy(vrk->key, adapter->rss_key, adapter->rss_key_size);

	adapter->current_op = VIRTCHNL_OP_CONFIG_RSS_KEY;
	adapter->aq_required &= ~NSEVF_FLAG_AQ_SET_RSS_KEY;
	nsevf_send_pf_msg(adapter, VIRTCHNL_OP_CONFIG_RSS_KEY, (u8 *)vrk, len);
	kfree(vrk);
}

/**
 * nsevf_set_rss_lut
 * @adapter: adapter structure
 *
 * Request the PF to set our RSS lookup table
 **/
void nsevf_set_rss_lut(struct nsevf_adapter *adapter)
{
	struct virtchnl_rss_lut *vrl;
	int len;

	if (adapter->current_op != VIRTCHNL_OP_UNKNOWN) {
		/* bail because we already have a command pending */
		dev_err(&adapter->pdev->dev,
			"Cannot set RSS LUT, command %d pending\n",
			adapter->current_op);
		return;
	}
	len = sizeof(struct virtchnl_rss_lut) +
	      (sizeof(u16) * adapter->rss_lut_size) - 2;
	vrl = kzalloc(len, GFP_KERNEL);
	if (!vrl)
		return;
	vrl->vsi_abs_id = adapter->vsi.vsi_abs_id;
	vrl->vsi_rel_id = adapter->vsi.vsi_rel_id;
	vrl->lut_entries = adapter->rss_lut_size;
	memcpy(vrl->lut, adapter->rss_lut, sizeof(u16) * adapter->rss_lut_size);
	adapter->current_op = VIRTCHNL_OP_CONFIG_RSS_LUT;
	adapter->aq_required &= ~NSEVF_FLAG_AQ_SET_RSS_LUT;
	nsevf_send_pf_msg(adapter, VIRTCHNL_OP_CONFIG_RSS_LUT, (u8 *)vrl, len);
	kfree(vrl);
}

/**
 * nsevf_set_fdir_input_mask - set the Flow Director input mask
 * @adapter: adapter structure
 *
 * Request the PF to set the Flow Director input mask
 **/
void nsevf_set_fdir_input_mask(struct nsevf_adapter *adapter)
{
	struct nsevf_fdir_cb *cb = &adapter->fdir_cb;
	struct virtchnl_fdir_input_mask *vfim;
	int len;
	u32 val;

	if (adapter->current_op != VIRTCHNL_OP_UNKNOWN) {
		/* bail because we already have a command pending */
		dev_err(&adapter->pdev->dev,
			"Cannot set fdir input mask, command %d pending\n",
			adapter->current_op);
		return;
	}
	len = sizeof(struct virtchnl_fdir_input_mask);
	vfim = kzalloc(len, GFP_KERNEL);
	if (!vfim)
		return;

	vfim->vsi_abs_id = adapter->vsi.vsi_abs_id;
	vfim->vsi_rel_id = adapter->vsi.vsi_rel_id;

	if (cb->flex_setting.flex_fltr) /* flex_msk = 0 (unmask) */
		val = ((cb->flex_setting.flex_offset
			<< NSEVF_FDIR_FLEX_CFG_OFFSET_S) |
		       (cb->flex_setting.flex_base
			<< NSEVF_FDIR_FLEX_CFG_BASE_S));
	else
		val = NSEVF_FDIR_FLEX_CFG_MASK_M; /* flex_msk = 1 (mask) */

	vfim->flex_cfg = cpu_to_le32(val);

	vfim->mask[NSEVF_FDIR_MASK_IDX_DA4] =
		~(cb->input_stream_mask.dst_ip[0]);
	vfim->mask[NSEVF_FDIR_MASK_IDX_SA4] =
		~(cb->input_stream_mask.src_ip[0]);

	val = le16_to_cpu(cb->input_stream_mask.dst_port);
	val <<= NSEVF_FDIR_MASK_TCP_DPORT_S;
	val |= le16_to_cpu(cb->input_stream_mask.src_port);

	vfim->mask[NSEVF_FDIR_MASK_IDX_TCP] = ~(cpu_to_le32(val));
	vfim->mask[NSEVF_FDIR_MASK_IDX_UDP] = ~(cpu_to_le32(val));

	vfim->mask[NSEVF_FDIR_MASK_IDX_SCTP] =
		0xFFFFFFFF; /* don't support SCTP */

	vfim->mask[NSEVF_FDIR_MASK_IDX_IP6] =
		0xFFFFFFFF; /* don't support IPv6 address filtering */

	vfim->mask[NSEVF_FDIR_MASK_IDX_OTHER] =
		cpu_to_le32(cb->hw_ptype_mask | NSEVF_FDIR_MASK_OTHER_L4PORT_M);

	adapter->current_op = VIRTCHNL_OP_SET_FDIR_INPUT_MASK;
	adapter->aq_required &= ~NSEVF_FLAG_AQ_SET_FDIR_INPUT_MASK;
	nsevf_send_pf_msg(adapter, VIRTCHNL_OP_SET_FDIR_INPUT_MASK, (u8 *)vfim,
			  len);
	kfree(vfim);
}

/**
 * nsevf_tpid_to_vc_ethertype - transform from VLAN TPID to virtchnl ethertype
 * @tpid: VLAN TPID (i.e. 0x8100, 0x88a8, etc.)
 */
static u32 nsevf_tpid_to_vc_ethertype(u16 tpid)
{
	switch (tpid) {
	case ETH_P_8021Q:
		return VIRTCHNL_VLAN_ETHERTYPE_8100;
	case ETH_P_8021AD:
		return VIRTCHNL_VLAN_ETHERTYPE_88A8;
	}

	return 0;
}

/**
 * nsevf_set_vc_offload_ethertype - set virtchnl ethertype for offload message
 * @adapter: adapter structure
 * @msg: message structure used for updating offloads over virtchnl to update
 * @tpid: VLAN TPID (i.e. 0x8100, 0x88a8, etc.)
 * @offload_op: opcode used to determine which support structure to check
 */
static int nsevf_set_vc_offload_ethertype(struct nsevf_adapter *adapter,
					  struct virtchnl_vlan_setting *msg,
					  u16 tpid,
					  enum virtchnl_ops offload_op)
{
	struct virtchnl_vlan_supported_caps *offload_support;
	u32 vc_ethertype = nsevf_tpid_to_vc_ethertype(tpid);

	/* reference the correct offload support structure */
	switch (offload_op) {
	case VIRTCHNL_OP_ENABLE_VLAN_STRIPPING_V2:
		fallthrough;
	case VIRTCHNL_OP_DISABLE_VLAN_STRIPPING_V2:
		offload_support =
			&adapter->vlan_v2_caps.offloads.stripping_support;
		break;
	case VIRTCHNL_OP_ENABLE_VLAN_INSERTION_V2:
		fallthrough;
	case VIRTCHNL_OP_DISABLE_VLAN_INSERTION_V2:
		offload_support =
			&adapter->vlan_v2_caps.offloads.insertion_support;
		break;
	default:
		dev_err(&adapter->pdev->dev,
			"Invalid opcode %d for setting virtchnl ethertype to enable/disable VLAN offloads\n",
			offload_op);
		return -EINVAL;
	}

	/* make sure ethertype is supported */
	if ((offload_support->outer & vc_ethertype) &&
	    (offload_support->outer & VIRTCHNL_VLAN_TOGGLE)) {
		msg->outer_ethertype_setting = vc_ethertype;
	} else if ((offload_support->inner & vc_ethertype) &&
		   (offload_support->inner & VIRTCHNL_VLAN_TOGGLE)) {
		msg->inner_ethertype_setting = vc_ethertype;
	} else {
		dev_dbg(&adapter->pdev->dev,
			"opcode %d unsupported for VLAN TPID 0x%04x\n",
			offload_op, tpid);
		return -EINVAL;
	}

	return 0;
}

/**
 * nsevf_clear_offload_v2_aq_required - clear AQ required bit for offload request
 * @adapter: adapter structure
 * @tpid: VLAN TPID
 * @offload_op: opcode used to determine which AQ required bit to clear
 */
static void nsevf_clear_offload_v2_aq_required(struct nsevf_adapter *adapter,
					       u16 tpid,
					       enum virtchnl_ops offload_op)
{
	switch (offload_op) {
	case VIRTCHNL_OP_ENABLE_VLAN_STRIPPING_V2:
		if (tpid == ETH_P_8021Q)
			adapter->aq_required &=
				~NSEVF_FLAG_AQ_ENABLE_CTAG_VLAN_STRIPPING;
		else if (tpid == ETH_P_8021AD)
			adapter->aq_required &=
				~NSEVF_FLAG_AQ_ENABLE_STAG_VLAN_STRIPPING;
		break;
	case VIRTCHNL_OP_DISABLE_VLAN_STRIPPING_V2:
		if (tpid == ETH_P_8021Q)
			adapter->aq_required &=
				~NSEVF_FLAG_AQ_DISABLE_CTAG_VLAN_STRIPPING;
		else if (tpid == ETH_P_8021AD)
			adapter->aq_required &=
				~NSEVF_FLAG_AQ_DISABLE_STAG_VLAN_STRIPPING;
		break;
	case VIRTCHNL_OP_ENABLE_VLAN_INSERTION_V2:
		if (tpid == ETH_P_8021Q)
			adapter->aq_required &=
				~NSEVF_FLAG_AQ_ENABLE_CTAG_VLAN_INSERTION;
		else if (tpid == ETH_P_8021AD)
			adapter->aq_required &=
				~NSEVF_FLAG_AQ_ENABLE_STAG_VLAN_INSERTION;
		break;
	case VIRTCHNL_OP_DISABLE_VLAN_INSERTION_V2:
		if (tpid == ETH_P_8021Q)
			adapter->aq_required &=
				~NSEVF_FLAG_AQ_DISABLE_CTAG_VLAN_INSERTION;
		else if (tpid == ETH_P_8021AD)
			adapter->aq_required &=
				~NSEVF_FLAG_AQ_DISABLE_STAG_VLAN_INSERTION;
		break;
	default:
		dev_err(&adapter->pdev->dev,
			"Unsupported opcode %d specified for clearing aq_required bits for VIRTCHNL_VF_OFFLOAD_VLAN_V2 offload request\n",
			offload_op);
	}
}

/**
 * nsevf_send_vlan_offload_v2 - send offload enable/disable over virtchnl
 * @adapter: adapter structure
 * @tpid: VLAN TPID used for the command (i.e. 0x8100 or 0x88a8)
 * @offload_op: offload_op used to make the request over virtchnl
 */
static void nsevf_send_vlan_offload_v2(struct nsevf_adapter *adapter, u16 tpid,
				       enum virtchnl_ops offload_op)
{
	struct virtchnl_vlan_setting *msg;
	int len = sizeof(*msg);

	if (adapter->current_op != VIRTCHNL_OP_UNKNOWN) {
		/* bail because we already have a command pending */
		dev_err(&adapter->pdev->dev,
			"Cannot send %d, command %d pending\n", offload_op,
			adapter->current_op);
		return;
	}

	adapter->current_op = offload_op;

	msg = kzalloc(len, GFP_KERNEL);
	if (!msg)
		return;

	msg->vsi_abs_id = adapter->vsi_res->vsi_abs_id;
	msg->vsi_rel_id = adapter->vsi_res->vsi_rel_id;

	/* always clear to prevent unsupported and endless requests */
	nsevf_clear_offload_v2_aq_required(adapter, tpid, offload_op);

	/* only send valid offload requests */
	if (!nsevf_set_vc_offload_ethertype(adapter, msg, tpid, offload_op))
		nsevf_send_pf_msg(adapter, offload_op, (u8 *)msg, len);
	else
		/* since the current_op assigned in this function was never sent
		 * there will never be a completion to clear it, so do that now
		 * to allow other opcodes
		 */
		adapter->current_op = VIRTCHNL_OP_UNKNOWN;

	kfree(msg);
}

/**
 * nsevf_enable_vlan_stripping_v2 - enable VLAN stripping
 * @adapter: adapter structure
 * @tpid: VLAN TPID used to enable VLAN stripping
 */
void nsevf_enable_vlan_stripping_v2(struct nsevf_adapter *adapter, u16 tpid)
{
	nsevf_send_vlan_offload_v2(adapter, tpid,
				   VIRTCHNL_OP_ENABLE_VLAN_STRIPPING_V2);
}

/**
 * nsevf_disable_vlan_stripping_v2 - disable VLAN stripping
 * @adapter: adapter structure
 * @tpid: VLAN TPID used to disable VLAN stripping
 */
void nsevf_disable_vlan_stripping_v2(struct nsevf_adapter *adapter, u16 tpid)
{
	nsevf_send_vlan_offload_v2(adapter, tpid,
				   VIRTCHNL_OP_DISABLE_VLAN_STRIPPING_V2);
}

/**
 * nsevf_enable_vlan_insertion_v2 - enable VLAN insertion
 * @adapter: adapter structure
 * @tpid: VLAN TPID used to enable VLAN insertion
 */
void nsevf_enable_vlan_insertion_v2(struct nsevf_adapter *adapter, u16 tpid)
{
	nsevf_send_vlan_offload_v2(adapter, tpid,
				   VIRTCHNL_OP_ENABLE_VLAN_INSERTION_V2);
}

/**
 * nsevf_disable_vlan_insertion_v2 - disable VLAN insertion
 * @adapter: adapter structure
 * @tpid: VLAN TPID used to disable VLAN insertion
 */
void nsevf_disable_vlan_insertion_v2(struct nsevf_adapter *adapter, u16 tpid)
{
	nsevf_send_vlan_offload_v2(adapter, tpid,
				   VIRTCHNL_OP_DISABLE_VLAN_INSERTION_V2);
}

/**
 * nsevf_send_vc_msg - Send one queued virtchnl message
 * @adapter: adapter private structure
 *
 * De-queue one command request and send the command message to the PF.
 * Clear NSEVF_FLAG_AQ_MSG_QUEUE_PENDING if no more messages are left to send.
 */
void nsevf_send_vc_msg(struct nsevf_adapter *adapter)
{
	struct device *dev = &adapter->pdev->dev;
	struct nsevf_vc_msg *vc_msg;
	int err;

	mutex_lock(&adapter->vc_msg_queue.lock);
	vc_msg = list_first_entry_or_null(&adapter->vc_msg_queue.msgs,
					  struct nsevf_vc_msg, list);
	if (!vc_msg) {
		/* no further messages to send */
		adapter->aq_required &= ~NSEVF_FLAG_AQ_MSG_QUEUE_PENDING;
		goto out_unlock;
	}

	if (adapter->current_op != VIRTCHNL_OP_UNKNOWN) {
		/* bail because we already have a command pending */
		dev_err(dev,
			"Cannot send virtchnl command %s-%d, command %s-%d pending\n",
			virtchnl_op_str(vc_msg->v_opcode), vc_msg->v_opcode,
			virtchnl_op_str(adapter->current_op),
			adapter->current_op);
		goto out_unlock;
	}

	err = nsevf_send_pf_msg(adapter, vc_msg->v_opcode, vc_msg->msg,
				vc_msg->msglen);
	if (!err) {
		/* Command was sent without errors, so we can remove it from
		 * the list and discard it.
		 */
		list_del(&vc_msg->list);
		kfree(vc_msg);
	} else {
		/* We failed to send the command, try again next cycle */
		dev_warn(dev, "Failed to send virtchnl command %s-%d\n",
			 virtchnl_op_str(vc_msg->v_opcode), vc_msg->v_opcode);
	}

	if (list_empty(&adapter->vc_msg_queue.msgs))
		/* no further messages to send */
		adapter->aq_required &= ~NSEVF_FLAG_AQ_MSG_QUEUE_PENDING;

out_unlock:
	mutex_unlock(&adapter->vc_msg_queue.lock);
}

/**
 * nsevf_flush_vc_msg_queue - remove and delete any/all matching command(s)
 * @adapter: private adapter structure
 * @op_match: function pointer used for finding ops that match pending_op
 *
 * All commands that match based on the op_match function passed in will be
 * removed from the queue and deleted.
 */
void nsevf_flush_vc_msg_queue(struct nsevf_adapter *adapter,
			      bool (*op_match)(enum virtchnl_ops pending_op))
{
	struct nsevf_vc_msg *vc_msg, *tmp;

	/* Cancel any remaining uncompleted commands that match */
	mutex_lock(&adapter->vc_msg_queue.lock);
	list_for_each_entry_safe(vc_msg, tmp, &adapter->vc_msg_queue.msgs,
				 list) {
		if (op_match(vc_msg->v_opcode)) {
			list_del(&vc_msg->list);
			kfree(vc_msg);
		}
	}
	if (list_empty(&adapter->vc_msg_queue.msgs))
		adapter->aq_required &= ~NSEVF_FLAG_AQ_MSG_QUEUE_PENDING;
	mutex_unlock(&adapter->vc_msg_queue.lock);
}

/**
 * nsevf_alloc_vc_msg - Allocate a virtchnl message for the message queue
 * @v_opcode: the virtchnl opcode
 * @msglen: length in bytes of the associated virtchnl structure
 *
 * Allocates a virtchnl message for the message queue and pre-fills it with the
 * provided message length and opcode.
 */
struct nsevf_vc_msg *nsevf_alloc_vc_msg(enum virtchnl_ops v_opcode, u16 msglen)
{
	struct nsevf_vc_msg *vc_msg;

	vc_msg = kzalloc(struct_size(vc_msg, msg, msglen), GFP_KERNEL);
	if (!vc_msg)
		return NULL;

	vc_msg->v_opcode = v_opcode;
	vc_msg->msglen = msglen;

	return vc_msg;
}

/**
 * nsevf_queue_vc_msg - Queue message to send over virtchnl
 * @adapter: private adapter structure
 * @vc_msg: the virtchnl message to queue
 *
 * Queue the given command structure into the virtchnl message queue to
 * send to the PF.
 */
void nsevf_queue_vc_msg(struct nsevf_adapter *adapter,
			struct nsevf_vc_msg *vc_msg)
{
	mutex_lock(&adapter->vc_msg_queue.lock);
	list_add_tail(&vc_msg->list, &adapter->vc_msg_queue.msgs);
	mutex_unlock(&adapter->vc_msg_queue.lock);

	nsevf_schedule_aq_request(adapter, NSEVF_FLAG_AQ_MSG_QUEUE_PENDING);
}

#define NSEVF_MAX_SPEED_STRLEN 18

/**
 * nsevf_print_link_message - print link up or down
 * @adapter: adapter structure
 *
 * Log a message telling the world of our wonderous link status
 */
static void nsevf_print_link_message(struct nsevf_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	int link_speed_mbps;
	char *speed;

	if (!adapter->link_up) {
		netdev_info(netdev, "NIC Link is Down\n");
		return;
	}

	speed = kcalloc(1, NSEVF_MAX_SPEED_STRLEN, GFP_KERNEL);
	if (!speed)
		return;

	if (ADV_LINK_SUPPORT(adapter)) {
		link_speed_mbps = adapter->link_speed_mbps;
		goto print_link_msg;
	}

	switch (adapter->link_speed) {
	case VIRTCHNL_LINK_SPEED_40GB:
		link_speed_mbps = SPEED_40000;
		break;
	case VIRTCHNL_LINK_SPEED_25GB:
		link_speed_mbps = SPEED_25000;
		break;
	case VIRTCHNL_LINK_SPEED_20GB:
		link_speed_mbps = SPEED_20000;
		break;
	case VIRTCHNL_LINK_SPEED_10GB:
		link_speed_mbps = SPEED_10000;
		break;
	case VIRTCHNL_LINK_SPEED_5GB:
		link_speed_mbps = SPEED_5000;
		break;
	case VIRTCHNL_LINK_SPEED_2_5GB:
		link_speed_mbps = SPEED_2500;
		break;
	case VIRTCHNL_LINK_SPEED_1GB:
		link_speed_mbps = SPEED_1000;
		break;
	case VIRTCHNL_LINK_SPEED_100MB:
		link_speed_mbps = SPEED_100;
		break;
	default:
		link_speed_mbps = SPEED_UNKNOWN;
		break;
	}

print_link_msg:
	if (link_speed_mbps > SPEED_1000) {
		if (link_speed_mbps == SPEED_2500) {
			snprintf(speed, NSEVF_MAX_SPEED_STRLEN, "2.5 Gbps");
		} else {
			/* convert to Gbps inline */
			snprintf(speed, NSEVF_MAX_SPEED_STRLEN, "%d %s",
				 link_speed_mbps / 1000, "Gbps");
		}
	} else if (link_speed_mbps == SPEED_UNKNOWN) {
		snprintf(speed, NSEVF_MAX_SPEED_STRLEN, "%s", "Unknown Mbps");
	} else {
		snprintf(speed, NSEVF_MAX_SPEED_STRLEN, "%d %s",
			 link_speed_mbps, "Mbps");
	}

	netdev_info(netdev, "NIC Link is Up Speed is %s Full Duplex\n", speed);
	netdev_info(netdev,
		    "Ethtool won't report 25 Gbps Link Speed correctly on this Kernel, Time for an Upgrade\n");
	kfree(speed);
}

/**
 * nsevf_get_vpe_link_status
 * @adapter: adapter structure
 * @vpe: virtchnl_pf_event structure
 * @force_update: whether the link status update must be forced
 *
 * Helper function for determining the link status
 **/
static bool nsevf_get_vpe_link_status(struct nsevf_adapter *adapter,
				      struct virtchnl_pf_event *vpe,
				      bool *force_update)
{
	if (ADV_LINK_SUPPORT(adapter)) {
		*force_update = (vpe->event_data.link_event_adv.flags &
				 VIRTCHNL_LINK_EVENT_FLAG_FORCE_UPDATE);
		return vpe->event_data.link_event_adv.link_status;

	} else {
		*force_update = (vpe->event_data.link_event.flags &
				 VIRTCHNL_LINK_EVENT_FLAG_FORCE_UPDATE);
		return vpe->event_data.link_event.link_status;
	}
}

/**
 * nsevf_set_adapter_link_speed_from_vpe
 * @adapter: adapter structure for which we are setting the link speed
 * @vpe: virtchnl_pf_event structure that contains the link speed we are setting
 *
 * Helper function for setting nsevf_adapter link speed
 **/
static void nsevf_set_adapter_link_speed_from_vpe(struct nsevf_adapter *adapter,
						  struct virtchnl_pf_event *vpe)
{
	if (ADV_LINK_SUPPORT(adapter))
		adapter->link_speed_mbps =
			vpe->event_data.link_event_adv.link_speed;
	else
		adapter->link_speed = vpe->event_data.link_event.link_speed;
}

/**
 * nsevf_request_reset
 * @adapter: adapter structure
 *
 * Request that the PF reset this VF. No response is expected.
 **/
int nsevf_request_reset(struct nsevf_adapter *adapter)
{
	int err;

	/* Don't check CURRENT_OP - this is always higher priority */
	err = nsevf_send_pf_msg(adapter, VIRTCHNL_OP_RESET_VF, NULL, 0);
	adapter->current_op = VIRTCHNL_OP_UNKNOWN;
	return err;
}

int nsevf_request_reset_rdma(struct nsevf_adapter *adapter)
{
	struct nsevf_hw *hw = &adapter->hw;
	int err;

	/* Don't check CURRENT_OP - this is always higher priority */
	err = nsevf_send_pf_msg(adapter, VIRTCHNL_OP_RESET_VF_RDMA, NULL, 0);
	adapter->current_op = VIRTCHNL_OP_UNKNOWN;

	nsevf_debug(hw, NSEVF_DBG_SYS, "[%s] ret=%d\n", __func__, err);

	return err;
}

void nsevf_force_reset_trig(struct nsevf_hw *hw)
{
	struct device *dev = nsevf_hw_to_dev(hw);
	int ret = 0;

	wr32(hw, NSEVF_REG_CTL, NSEVF_REG_CTL_SET_FRTRIG_M);

	ret = nsevf_check_reset_complete(hw, true, false);

	if (!ret)
		dev_err(dev,
			"[%s] VF not totally reset, have to continue, but free DMA memory may cause some corruption\n",
			__func__);
}

/**
 * nsevf_virtchnl_rdma_irq_map - Handle receive of IRQ mapping message from PF
 * @adapter: private adapter structure
 * @v_retval: result of the received virtchnl message
 *
 * Called when the VF gets a VIRTCHNL_OP_RDMA_CONFIG_IRQ_MAP or
 * VIRTCHNL_OP_RDMA_RELEASE_IRQ_MAP message from the PF.
 */
static void nsevf_virtchnl_rdma_irq_map(struct nsevf_adapter *adapter,
					enum virtchnl_status_code v_retval)
{
	if (adapter->rdma.vc_op_state != NSEVF_RDMA_VC_OP_PENDING)
		dev_warn(&adapter->pdev->dev, "Unexpected vc_op_state %u\n",
			 adapter->rdma.vc_op_state);

	if (!v_retval)
		adapter->rdma.vc_op_state = NSEVF_RDMA_VC_OP_COMPLETE;
	else
		adapter->rdma.vc_op_state = NSEVF_RDMA_VC_OP_FAILED;

	wake_up(&adapter->rdma.vc_op_waitqueue);
}

/**
 * nsevf_virtchnl_completion
 * @adapter: adapter structure
 * @v_opcode: opcode sent by PF
 * @v_retval: virtchnl status code return value sent by PF
 * @msg: message sent by PF
 * @msglen: message length
 *
 * Asynchronous completion function for admin queue messages. Rather than busy
 * wait, we fire off our requests and assume that no errors will be returned.
 * This function handles the reply messages.
 **/
void nsevf_virtchnl_completion(struct nsevf_adapter *adapter,
			       enum virtchnl_ops v_opcode,
			       enum virtchnl_status_code v_retval, u8 *msg,
			       u16 msglen)
{
	struct net_device *netdev = adapter->netdev;
	struct nsevf_hw *hw = &adapter->hw;
	struct device *dev = &adapter->pdev->dev;
	bool link_up;
	bool link_change_force_update = false;

	if (v_opcode == VIRTCHNL_OP_EVENT) {
		struct virtchnl_pf_event *vpe = (struct virtchnl_pf_event *)msg;

		switch (vpe->event) {
		case VIRTCHNL_EVENT_LINK_CHANGE:

			link_up =
				nsevf_get_vpe_link_status(adapter, vpe,
							  &link_change_force_update);
			nsevf_set_adapter_link_speed_from_vpe(adapter, vpe);

			nsevf_debug(hw, NSEVF_DBG_LMAC_PHY,
				    "[%s] receive EVENT_LINK_CHANGE\n",
				    __func__);
			nsevf_debug(hw, NSEVF_DBG_LMAC_PHY,
				    "\t link_up=%d, force_update=%d\n", link_up,
				    link_change_force_update);
			nsevf_debug(hw, NSEVF_DBG_LMAC_PHY,
				    "\t ad->link_up=%d, state=%d, flags=0x%X\n",
				    adapter->link_up, adapter->state,
				    adapter->flags);

			/* we've already got the right link status, bail */
			if (adapter->link_up == link_up &&
			    !link_change_force_update)
				break;

			if (link_up) {
				/* If we get link up message and start queues
				 * before our queues are configured it will
				 * trigger a TX hang. In that case, just ignore
				 * the link status message,we'll get another one
				 * after we enable queues and actually prepared
				 * to send traffic.
				 */
				if (adapter->state != __NSEVF_RUNNING)
					break;

				/* For ADQ enabled VF, we reconfigure VSIs and
				 * re-allocate queues. Hence wait till all
				 * queues are enabled.
				 */
				if (adapter->flags & NSEVF_FLAG_QUEUES_DISABLED)
					break;
			}

			adapter->link_up = link_up;
			if (link_up) {
				if (adapter->flags &
				    NSEVF_FLAG_QUEUES_ENABLED) {
					netif_tx_start_all_queues(netdev);
					netif_carrier_on(netdev);
				}
			} else {
				netif_tx_stop_all_queues(netdev);
				netif_carrier_off(netdev);
			}
			nsevf_print_link_message(adapter);
			break;
		case VIRTCHNL_EVENT_RESET_IMPENDING:
			dev_info(dev,
				 "[%s] Reset indication received from the PF, reset_type=%d\n",
				__func__,
				vpe->event_data.reset_event.reset_type);

			if (!(adapter->flags & NSEVF_FLAG_RESET_PENDING)) {
				dev_info(dev, "Scheduling reset task\n");
				adapter->external_reset_type =
					vpe->event_data.reset_event.reset_type;
				nsevf_schedule_reset(adapter, (NSEVF_FLAG_RESET_NEEDED |
						  NSEVF_FLAG_RESET_PENDING));
			} else {
				dev_info(dev,
					 "Not Scheduling reset task, because already in reset\n");
			}
			break;
		default:
			dev_err(dev, "Unknown event %d from PF\n", vpe->event);
			break;
		}
		return;
	}

	if (v_retval) {
		switch (v_opcode) {
		case VIRTCHNL_OP_ADD_ETH_ADDR:
			dev_err(dev, "Failed to add MAC filter, error %s\n",
				virtchnl_stat_str(v_retval));
			nsevf_netdev_mc_mac_add_reject(adapter);
			nsevf_mac_add_reject(adapter);
			/* restore administratively set mac address */
			ether_addr_copy(adapter->hw.mac.addr, netdev->dev_addr);
			wake_up(&adapter->vc_waitqueue);
			break;
		case VIRTCHNL_OP_DEL_ETH_ADDR:
			dev_err(dev, "Failed to delete MAC filter, error %s\n",
				virtchnl_stat_str(v_retval));
			break;

		case VIRTCHNL_OP_ADD_VLAN_V2:
			nsevf_vlan_add_reject(adapter);
			dev_warn(dev, "Failed to add VLAN filter, error %s\n",
				 virtchnl_stat_str(v_retval));
			break;
		default:
			dev_err(dev,
				"PF returned error %d (%s) to our request %d\n",
				v_retval, virtchnl_stat_str(v_retval),
				v_opcode);

			if (v_opcode == VIRTCHNL_OP_ENABLE_QUEUES ||
			    v_opcode == VIRTCHNL_OP_CONFIG_IRQ_MAP ||
			    v_opcode == VIRTCHNL_OP_CONFIG_VSI_QUEUES) {
				dev_err(dev,
					"PF returned error %d (%s) to our request %d --- initiate VF-reset\n",
					v_retval, virtchnl_stat_str(v_retval),
					v_opcode);

				adapter->flags |= NSEVF_FLAG_REINIT_ITR_NEEDED;
				adapter->current_op = VIRTCHNL_OP_UNKNOWN;
				nsevf_schedule_reset(adapter,
						     NSEVF_FLAG_RESET_NEEDED);
				return;
			}

			break;
		}
	}

	switch (v_opcode) {
	case VIRTCHNL_OP_ADD_ETH_ADDR:
		if (!v_retval)
			nsevf_mac_add_ok(adapter);
		if (!ether_addr_equal(netdev->dev_addr, adapter->hw.mac.addr)) {
			netif_addr_lock_bh(netdev);
			eth_hw_addr_set(netdev, adapter->hw.mac.addr);
			netif_addr_unlock_bh(netdev);
		}
		wake_up(&adapter->vc_waitqueue);
		break;
	case VIRTCHNL_OP_GET_STATS: {
		struct nsevf_vsi_hw_stats *stats =
			(struct nsevf_vsi_hw_stats *)msg;

		memcpy(&adapter->hw_stats, stats, sizeof(adapter->hw_stats));

		adapter->hw_stats_last_update_time = jiffies;

		nsevf_sync_net_stats(adapter);
	} break;
	case VIRTCHNL_OP_GET_VF_RESOURCES: {
		u16 len = sizeof(struct virtchnl_vf_resource);

		memcpy(adapter->vf_res, msg, min(msglen, len));
		nsevf_validate_num_queues(adapter);
		nsevf_vf_parse_hw_config(&adapter->hw, adapter->vf_res);
		if (is_zero_ether_addr(adapter->hw.mac.addr)) {
			/* restore current mac address */
			ether_addr_copy(adapter->hw.mac.addr, netdev->dev_addr);
			eth_zero_addr(netdev->perm_addr);
		} else {
			netif_addr_lock_bh(netdev);
			/* refresh current mac address if changed */
			ether_addr_copy(netdev->perm_addr,
					adapter->hw.mac.addr);
			netif_addr_unlock_bh(netdev);
		}

		nsevf_parse_vf_resource_msg(adapter);

		/* negotiated VIRTCHNL_VF_OFFLOAD_VLAN_V2, so wait for the
		 * response to VIRTCHNL_OP_GET_OFFLOAD_VLAN_V2_CAPS to finish
		 * configuration
		 */
		if (VLAN_V2_ALLOWED(adapter))
			break;
	}
		fallthrough;
	case VIRTCHNL_OP_GET_OFFLOAD_VLAN_V2_CAPS: {
		struct nsevf_mac_filter *f;
		bool was_mac_changed;
		u64 aq_required = 0;

		if (v_opcode == VIRTCHNL_OP_GET_OFFLOAD_VLAN_V2_CAPS)
			memcpy(&adapter->vlan_v2_caps, msg,
			       min_t(u16, msglen,
				     sizeof(adapter->vlan_v2_caps)));

		nsevf_process_config(adapter);

		adapter->flags |= NSEVF_FLAG_UPDATE_NETDEV_FEATURES;

		/* Request VLAN offload settings */
		if (VLAN_V2_ALLOWED(adapter))
			nsevf_set_vlan_offload_features(adapter, 0,
							netdev->features);

		nsevf_set_queue_vlan_tag_loc(adapter);

		was_mac_changed = !ether_addr_equal(netdev->dev_addr,
						    adapter->hw.mac.addr);

		spin_lock_bh(&adapter->mac_vlan_list_lock);

		/* re-add all MAC filters */
		list_for_each_entry(f, &adapter->mac_filter_list, list) {
			if (was_mac_changed &&
			    ether_addr_equal(netdev->dev_addr, f->macaddr))
				ether_addr_copy(f->macaddr,
						adapter->hw.mac.addr);

			f->is_new_mac = true;
			f->add = true;
			f->add_handled = false;
			f->remove = false;
		}

		/* re-add all VLAN filters */
		if (VLAN_FILTERING_ALLOWED(adapter)) {
			struct nsevf_vlan_filter *vlf;

			if (!list_empty(&adapter->vlan_filter_list)) {
				list_for_each_entry(vlf, &adapter->vlan_filter_list, list)
					vlf->add = true;

				aq_required |= NSEVF_FLAG_AQ_ADD_VLAN_FILTER;
			}
		}

		spin_unlock_bh(&adapter->mac_vlan_list_lock);

		netif_addr_lock_bh(netdev);
		eth_hw_addr_set(netdev, adapter->hw.mac.addr);
		netif_addr_unlock_bh(netdev);

		adapter->aq_required |= NSEVF_FLAG_AQ_ADD_MAC_FILTER |
					aq_required;
	} break;
	case VIRTCHNL_OP_GET_SUPPORTED_RXDIDS:
		memcpy(&adapter->supported_rxdids, msg,
		       min_t(u16, msglen, sizeof(adapter->supported_rxdids)));
		break;
	case VIRTCHNL_OP_ENABLE_QUEUES:
		/* enable transmits */
		if (adapter->state == __NSEVF_RUNNING) {
			nsevf_irq_enable(adapter, true);

			/* If queues not enabled when handling link event,
			 * then set carrier on now
			 */
			if (adapter->link_up && !netif_carrier_ok(netdev)) {
				netif_tx_start_all_queues(netdev);
				netif_carrier_on(netdev);
			}
			wake_up(&adapter->reset_waitqueue);
		}

		nsevf_sync_tail_all_rx_rings(adapter);

		adapter->flags |= NSEVF_FLAG_QUEUES_ENABLED;
		adapter->flags &= ~NSEVF_FLAG_QUEUES_DISABLED;
		break;
	case VIRTCHNL_OP_DISABLE_QUEUES:
		nsevf_free_all_tx_resources(adapter);
		nsevf_free_all_rx_resources(adapter);
		nsevf_free_all_txcq_resources(adapter);
		if (adapter->state == __NSEVF_DOWN_PENDING) {
			nsevf_change_state(adapter, __NSEVF_DOWN);
			wake_up(&adapter->down_waitqueue);
		}
		adapter->flags &= ~NSEVF_FLAG_QUEUES_ENABLED;
		break;
	case VIRTCHNL_OP_VERSION:
	case VIRTCHNL_OP_CONFIG_IRQ_MAP:
		/* Don't display an error if we get these out of sequence.
		 * If the firmware needed to get kicked, we'll get these and
		 * it's no problem.
		 */
		if (v_opcode != adapter->current_op)
			return;
		break;

	case VIRTCHNL_OP_ADD_VLAN_V2: {
		struct nsevf_vlan_filter *f;

		spin_lock_bh(&adapter->mac_vlan_list_lock);
		list_for_each_entry(f, &adapter->vlan_filter_list, list) {
			if (f->is_new_vlan) {
				f->is_new_vlan = false;
				if (!f->vlan.vid)
					continue;
				if (f->vlan.tpid == ETH_P_8021Q)
					set_bit(f->vlan.vid,
						adapter->vsi.active_cvlans);
				else
					set_bit(f->vlan.vid,
						adapter->vsi.active_svlans);
			}
		}
		spin_unlock_bh(&adapter->mac_vlan_list_lock);
	} break;
	case VIRTCHNL_OP_RDMA:
		/* NSEVF_RDMA_VC_OP_PENDING is only set for the synchronous
		 * version of vc_send, so make sure we handle both cases
		 */
		if (adapter->rdma.vc_op_state == NSEVF_RDMA_VC_OP_PENDING) {
			if (v_retval == VIRTCHNL_STATUS_SUCCESS) {
				memcpy(adapter->rdma.recv_sync_msg, msg,
				       msglen);
				adapter->rdma.recv_sync_msg_size = msglen;
				adapter->rdma.vc_op_state =
					NSEVF_RDMA_VC_OP_COMPLETE;
			} else {
				adapter->rdma.vc_op_state =
					NSEVF_RDMA_VC_OP_FAILED;
				dev_err(dev,
					"PF returned error %d to our request %s-%d\n",
					v_retval, virtchnl_op_str(v_opcode),
					v_opcode);
			}

			wake_up(&adapter->rdma.vc_op_waitqueue);
		} else {
			/* asynchronous version of vc_send expects vc_receive to
			 * be called on reception of a VIRTCHNL_OP_RDMA message
			 */
			nsevf_idc_vc_receive(adapter, msg, msglen);
		}
		break;
	case VIRTCHNL_OP_CONFIG_RDMA_IRQ_MAP:
	case VIRTCHNL_OP_RELEASE_RDMA_IRQ_MAP:
		nsevf_virtchnl_rdma_irq_map(adapter, v_retval);
		break;
	default:
		if (adapter->current_op && v_opcode != adapter->current_op)
			dev_dbg(dev,
				"Expected response %d from PF, received %d\n",
				adapter->current_op, v_opcode);
		break;
	} /* switch v_opcode */
	adapter->current_op = VIRTCHNL_OP_UNKNOWN;
}
