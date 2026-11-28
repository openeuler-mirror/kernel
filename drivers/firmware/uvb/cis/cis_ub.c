// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: UVB over UB message processing module, handles CIS UB init,
 *              func register/lookup and UB message.
 * Author: mengkanglai
 * Create: 2025-12-18
 */

#define pr_fmt(fmt) "[UVB_UB]: " fmt

#include <linux/printk.h>
#include <linux/kernel.h>
#include <linux/auxiliary_bus.h>
#include <ub/ubase/ubase_comm_dev.h>
#include <ub/ubase/ubase_comm_cmd.h>
#include "cis_ub.h"
#include "cis_info_process.h"
#include "odf/odf_interface.h"
#include "odf/odf_handle.h"

enum uvb_opcode {
	CIS_OPC_SEND = 0xFA00,
	CIS_OPC_RECV = 0xFA01,
};

static struct ubase_crq_event_nb uvb_crq_events;

void ub_msg_header_init(struct msg_pkt_header *header)
{
	memset(header, 0, sizeof(struct msg_pkt_header));

	/* Fill fixed fields per UB message format spec (by_stream.jpg) */
	header->ulh.cfg = UB_COMPACT_LINK_CFG;
	header->btah.ta_opcode = TAH_OPCODE_MSG;
	header->msgetah.msg_code = UB_MSG_CODE;
	header->msgetah.sub_msg_code = UB_SUB_MSG_CODE;
	header->ctph_nlp = CTPH_NLP_UPI_40BITS_UEID;
	header->pload.type = UB_PAYLOAD_TYPE;
	header->pload.version = UB_PAYLOAD_VERSION;
}

void setup_resp_pkt(struct msg_pkt_header *resp, struct msg_pkt_header *rcv)
{
	struct compact_network_header *nth = &rcv->nth;

	ub_msg_header_init(resp);
	resp->upi = rcv->upi;
	resp->pload.message_id = ~rcv->pload.message_id;
	resp->pload.sender_id = rcv->pload.sender_id;
	resp->pload.receiver_id = rcv->pload.receiver_id;
	resp->nth.dcna = nth->scna;
	resp->deid = eid_gen(rcv->seid_h, rcv->seid_l);
	resp->nth.scna = nth->dcna;
	resp->seid_l = seid_low(rcv->deid);
	resp->seid_h = seid_high(rcv->deid);
	resp->msgetah.rsp = 0x1;
	resp->btah.ini_tassn = rcv->btah.ini_tassn;
	resp->btah.ini_rc_id = rcv->btah.ini_rc_id;
	resp->btah.ee = rcv->btah.ee;
}

static bool check_pload_valid(struct payload *pload, u32 len)
{
	if (!pload->sender_id || !pload->receiver_id) {
		pr_err("senderid or receiverid can't be null\n");
		return false;
	}

	if (UBIOS_GET_MESSAGE_FLAG(pload->message_id) != UBIOS_CALL_ID_FLAG &&
	    UBIOS_GET_MESSAGE_FLAG(pload->message_id) != UBIOS_NOTIFY_ID_FLAG) {
		pr_err("uvb over ub not a cis call or notify, message_id=0x%08x\n",
		       pload->message_id);
		return false;
	}

	if (len > sizeof(struct msg_pkt_header) && !pload->data_total_size) {
		pr_err("ub pload have data but data size is null\n");
		return false;
	}

	if (len == sizeof(struct msg_pkt_header) && pload->data_total_size) {
		pr_err("ub pload no data but data size is not null\n");
		return false;
	}

	return true;
}

/*
 * Fetch all response frames from UB and assemble into a contiguous buffer.
 * First frame is already received in resp, remaining frames are fetched
 * by incrementing pkt->pload.index.
 *
 * @pkt:      request packet (reused, only index field changes)
 * @pkt_size: request packet size
 * @resp:     first response frame (reused for subsequent frames)
 * @resp_size: response buffer size
 * @total_size: total data size reported by peer (resp->pload.data_total_size)
 * @out_buf:  output buffer provided by caller
 * @out_size: [in] caller's output buffer capacity, [out] actual data size
 *
 * Return: 0 on success, negative errno on failure.
 *         -EOVERFLOW if total_size > *out_size (out_size is set to total_size).
 *
 * Each frame carries UB_FRAME_MAX_DATA (960B) of data, per IMP agreement.
 */
static int ub_fetch_all_frames(struct msg_pkt_header *pkt, u32 pkt_size,
			       struct msg_pkt_header *resp, u32 resp_size,
			       u32 total_size,
			       u8 *out_buf, u32 *out_size)
{
	u32 offset = UB_FRAME_MAX_DATA;
	u32 copy_size;
	u16 frame_idx = 1;
	int err = 0;
	struct ubase_cmd_buf in, out;

	memcpy(out_buf, resp->pload.data, UB_FRAME_MAX_DATA);

	while (offset < total_size) {
		pkt->pload.index = frame_idx;
		ubase_fill_inout_buf(&in, CIS_OPC_SEND, false,
				     pkt_size, pkt);
		memset(resp, 0, resp_size);
		ubase_fill_inout_buf(&out, 0, true, resp_size, resp);

		err = ubase_cmd_send_inout(uvb_crq_events.back, &in, &out);
		if (err) {
			pr_err("fetch frame %u failed, err=%d\n", frame_idx, err);
			break;
		}

		copy_size = UB_FRAME_MAX_DATA;
		if (copy_size > total_size - offset)
			copy_size = total_size - offset;
		memcpy(out_buf + offset, resp->pload.data, copy_size);
		offset += copy_size;
		frame_idx++;
	}

	if (!err)
		*out_size = total_size;
	return err;
}

int cis_call_ub(struct udfi_para *para)
{
	struct msg_pkt_header *pkt;
	struct msg_pkt_header *resp;
	struct ubase_cmd_buf in, out;
	u32 pkt_size, resp_size;
	int err;

	if (!uvb_crq_events.back) {
		pr_err("ubase auxiliary device is NULL, cannot send UB message\n");
		return -ENODEV;
	}

	pkt_size = sizeof(struct msg_pkt_header) + para->input_size;
	if (pkt_size > UBASE_CMDQ_MAX_DATA_SIZE) {
		pr_err("ub message size overflow, pkt_size=%u\n", pkt_size);
		return -EOVERFLOW;
	}

	/* msgetah.plen is a 12-bit field and must not be silently truncated */
	if (para->input_size + sizeof(struct payload) > GENMASK(11, 0)) {
		pr_err("ub message plen overflow, input_size=%u\n",
		       para->input_size);
		return -EOVERFLOW;
	}

	pkt = kzalloc(pkt_size, GFP_KERNEL);
	if (!pkt)
		return -ENOMEM;

	ub_msg_header_init(pkt);
	pkt->pload.message_id = para->message_id;
	pkt->pload.sender_id = para->sender_id;
	pkt->pload.receiver_id = para->receiver_id;
	pkt->msgetah.rsp = 0;
	pkt->msgetah.plen = para->input_size + sizeof(struct payload);

	if (para->input && para->input_size) {
		pkt->pload.data_total_size = para->input_size;
		memcpy(pkt->pload.data, para->input, para->input_size);
	}

	if (para->output_size && *para->output_size)
		pkt->pload.output_buffer_size = *para->output_size;
	else
		pkt->pload.output_buffer_size = UVB_OUTPUT_SIZE_NULL;

	ubase_fill_inout_buf(&in, CIS_OPC_SEND, false, pkt_size, pkt);

	if (para->output_size && *para->output_size)
		resp_size = sizeof(struct msg_pkt_header) + *para->output_size;
	else
		resp_size = sizeof(struct msg_pkt_header);
	if (resp_size > UBASE_CMDQ_MAX_DATA_SIZE)
		resp_size = UBASE_CMDQ_MAX_DATA_SIZE;
	resp = kzalloc(resp_size, GFP_KERNEL);
	if (!resp) {
		kfree(pkt);
		return -ENOMEM;
	}
	ubase_fill_inout_buf(&out, 0, true, resp_size, resp);

	err = ubase_cmd_send_inout(uvb_crq_events.back, &in, &out);
	if (err) {
		pr_err("cis call send failed, message_id=0x%08x, err=%d\n",
		       para->message_id, err);
	} else if (para->output && para->output_size &&
		   resp->pload.data_total_size) {
		u32 total_size = resp->pload.data_total_size;

		if (total_size > *para->output_size) {
			/* Tell the caller how much it needs, copy nothing */
			*para->output_size = total_size;
			err = -EOVERFLOW;
		} else if (total_size <= UB_FRAME_MAX_DATA) {
			/* Single frame */
			memcpy(para->output, resp->pload.data, total_size);
			*para->output_size = total_size;
		} else {
			/* Multi-frame: fetch remaining frames */
			err = ub_fetch_all_frames(pkt, pkt_size, resp, resp_size,
						  total_size, para->output,
						  para->output_size);
		}
	} else if (para->output && !para->output_size &&
		   resp->pload.data_total_size) {
		/* Forwarding path: the peer declared an output buffer but no
		 * capacity for it, there is no safe way to deliver the data.
		 */
		pr_err("cis call ub: response %u bytes but no output size, message_id=0x%08x\n",
		       resp->pload.data_total_size, para->message_id);
		err = -EOVERFLOW;
	}
	kfree(resp);

	kfree(pkt);
	return err;
}

/*
 * Parse CIS extension table from UB Notify payload and add to group list.
 * Payload data format is the same as ODF call_id_service sub-table,
 * use odf_get_list_from_table() to extract group list.
 */
int cis_ext_table_add_from_ub(void *data, u32 data_size, u32 sender_id)
{
	struct ubios_od_list_info cis_list;
	struct ubios_od_header *header = (struct ubios_od_header *)data;
	int err;

	if (!data || data_size < sizeof(struct ubios_od_header)) {
		pr_err("cis ext table add from ub: buffer too small, data=%p, size=%u\n",
		       data, data_size);
		return -EINVAL;
	}

	/* The od header is self describing: total_size drives every later loop
	 * (checksum, data_length), so it must stay inside the real buffer.
	 * remaining_size is subtracted together with the header by
	 * odf_get_vs_from_file(), so bound it with the header excluded to
	 * keep that u32 subtraction from wrapping.
	 */
	if (header->total_size < sizeof(struct ubios_od_header) ||
	    header->total_size > data_size ||
	    header->remaining_size >
		header->total_size - sizeof(struct ubios_od_header)) {
		pr_err("cis ext table add from ub: invalid od header, total_size=%u, remaining=%u, buf=%u\n",
		       header->total_size, header->remaining_size, data_size);
		return -EINVAL;
	}

	err = odf_get_list_from_table((u8 *)data, ODF_NAME_CIS_GROUP, &cis_list);
	if (err) {
		pr_err("parse cis ext table from ub payload failed, err=%d\n", err);
		return err;
	}

	err = cis_ext_table_add(sender_id, &cis_list);
	if (err)
		pr_err("add cis ext table from ub failed, err=%d\n", err);

	return err;
}

int uvb_handle_cmdq_event(void *dev, void *data, u32 len)
{
	int err = 0;
	msg_handler func;
	struct cis_message msg = {};
	struct ubase_cmd_buf in;
	struct msg_pkt_header *resp;
	struct msg_pkt_header *ub_header;
	struct payload *pload;
	u32 output_size;
	u32 data_cap;

	/* The buffer must hold a full message header before any field is read */
	if (!data || len < sizeof(struct msg_pkt_header)) {
		pr_err("ub msg too short, len=%u, header=%zu\n", len,
		       sizeof(struct msg_pkt_header));
		return -EINVAL;
	}

	ub_header = (struct msg_pkt_header *)data;
	pload = &ub_header->pload;

	/* plen is a 12-bit field, subtract only after the lower bound is checked.
	 * data_total_size must not exceed the real buffer capacity either.
	 */
	data_cap = len - offsetof(struct msg_pkt_header, pload.data);
	if (ub_header->msgetah.plen < sizeof(struct payload) ||
	    (u32)ub_header->msgetah.plen - sizeof(struct payload) <
		    pload->data_total_size ||
	    pload->data_total_size > data_cap) {
		pr_err("invalid ub msg, plen=%u, data_total_size=%u, cap=%u\n",
		       ub_header->msgetah.plen, pload->data_total_size, data_cap);
		return -EINVAL;
	}

	output_size = pload->output_buffer_size == UVB_OUTPUT_SIZE_NULL ? 0 :
		pload->output_buffer_size;
	msg.input = pload->data;
	msg.input_size = pload->data_total_size;

	/* CIS table extension is handled internally by UVB driver */
	if (pload->message_id == UBIOS_NOTIFY_ID_CIS_TABLE) {
		if (!pload->sender_id) {
			pr_err("cis table notify from invalid sender_id=0\n");
			return -EINVAL;
		}
		if (pload->data_total_size == 0)
			return cis_ext_table_del(pload->sender_id);
		return cis_ext_table_add_from_ub(pload->data,
				pload->data_total_size, pload->sender_id);
	}

	/* Unified dispatch: search registered handler by message_id + receiver_id */
	if (!check_pload_valid(pload, len)) {
		pr_err("check payload param failed\n");
		return -EINVAL;
	}

	pr_info("handle msg for callid=%08x, receverid=%08x\n",
			pload->message_id, pload->receiver_id);
	func = search_local_cis_func(pload->message_id, pload->receiver_id);
	if (!func) {
		pr_err("not found registered func for %08x\n", pload->message_id);
		return -EOPNOTSUPP;
	}

	/* Notify ID is one-way, no response needed */
	if (UBIOS_GET_MESSAGE_FLAG(pload->message_id) == UBIOS_NOTIFY_ID_FLAG) {
		msg.output = NULL;
		msg.p_output_size = NULL;
		err = func(&msg);
		if (err)
			pr_err("notify handler failed for %08x, err=%d\n",
			       pload->message_id, err);
		return err;
	}

	resp = kzalloc(sizeof(struct msg_pkt_header) + output_size, GFP_KERNEL);
	if (!resp)
		return -ENOMEM;

	if (!output_size) {
		msg.p_output_size = NULL;
		msg.output = NULL;
	} else {
		resp->pload.data_total_size = output_size;
		msg.p_output_size = &resp->pload.data_total_size;
		msg.output = resp->pload.data;
	}

	err = func(&msg);
	if (err)
		pr_err("execute cis func failed for %08x, err=%d\n", pload->message_id, err);

	setup_resp_pkt(resp, ub_header);
	resp->msgetah.plen = min_t(u32,
			resp->pload.data_total_size + sizeof(struct payload),
			GENMASK(11, 0));
	resp->pload.returned_status = (u32)err;

	ubase_fill_inout_buf(&in, CIS_OPC_SEND, false,
			sizeof(struct msg_pkt_header) + resp->pload.data_total_size, resp);
	err = ubase_cmd_send_in(dev, &in);
	if (err)
		pr_err("send ubase info err, err=%d\n", err);

	kfree(resp);

	return err;
}

static struct ubase_crq_event_nb uvb_crq_events = {
	.opcode = CIS_OPC_RECV,
	.crq_handler = uvb_handle_cmdq_event,
};

int uvb_probe(struct auxiliary_device *aux_dev, const struct auxiliary_device_id *id)
{
	int ret = 0;

	uvb_crq_events.back = aux_dev;
	ret = ubase_register_crq_event(aux_dev, &uvb_crq_events);
	if (ret) {
		pr_err("register uvb crq events failed, err=%d\n", ret);
		return -1;
	}

	pr_info("register uvb crq events success\n");

	return 0;
}

void uvb_remove(struct auxiliary_device *aux_dev)
{
	ubase_unregister_crq_event(aux_dev, CIS_OPC_RECV);
}
