// SPDX-License-Identifier: GPL-2.0
/*
 * SAS Transport Layer for hst2dr (Message Passing Technology) based controllers
 *
 * This code is based on drivers/scsi/hst2dr/hst2dr_transport.c

 * Copyright (c) 2021-2026 Sage Micro Corporation
 * (mailto: driver@sage-micro.com.cn)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * NO WARRANTY
 * THE PROGRAM IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED INCLUDING, WITHOUT
 * LIMITATION, ANY WARRANTIES OR CONDITIONS OF TITLE, NON-INFRINGEMENT,
 * MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE. Each Recipient is
 * solely responsible for determining the appropriateness of using and
 * distributing the Program and assumes all risks associated with its
 * exercise of rights under this Agreement, including but not limited to
 * the risks and costs of program errors, damage to or loss of data,
 * programs or equipment, and unavailability or interruption of operations.

 * DISCLAIMER OF LIABILITY
 * NEITHER RECIPIENT NOR ANY CONTRIBUTORS SHALL HAVE ANY LIABILITY FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING WITHOUT LIMITATION LOST PROFITS), HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OR DISTRIBUTION OF THE PROGRAM OR THE EXERCISE OF ANY RIGHTS GRANTED
 * HEREUNDER, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGES

 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/workqueue.h>
#include <linux/delay.h>
#include <linux/pci.h>

#include <scsi/scsi.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_transport_sas.h>
#include <scsi/scsi_dbg.h>

#include "hst2dr_base.h"
#include "hst2dr_comm.h"
#include "hst2dr_debug.h"

/**
 * _transport_sas_node_find_by_sas_address - sas node search
 * @ioa: per adapter object
 * @sas_address: sas address of expander or sas host
 * Context: Calling function should acquire ioa->sas_node_lock.
 *
 * Search for either hba phys or expander device based on handle, then returns
 * the sas_node object.
 */
static struct _sas_node *
_transport_sas_node_find_by_sas_address(struct HST2DR_ADAPTER *ioa,
	u64 sas_address)
{
	if (ioa->sas_hba.sas_address == sas_address)
		return &ioa->sas_hba;
	else
		return hst2dr_expander_find_by_sas_address(ioa,
			sas_address);
}

/**
 * _transport_convert_phy_link_rate -
 * @link_rate: link rate returned from hst2dr firmware
 *
 * Convert link_rate from ssi  into sas_transport form.
 */
static enum sas_linkrate
_transport_convert_phy_link_rate(u8 link_rate)
{
	enum sas_linkrate rc;

	switch (link_rate) {
	case SSI2_SAS_NEG_LINK_RATE_1_5:
		rc = SAS_LINK_RATE_1_5_GBPS;
		break;
	case SSI2_SAS_NEG_LINK_RATE_3_0:
		rc = SAS_LINK_RATE_3_0_GBPS;
		break;
	case SSI2_SAS_NEG_LINK_RATE_6_0:
		rc = SAS_LINK_RATE_6_0_GBPS;
		break;
	case SSI2_SAS_NEG_LINK_RATE_12_0:
		rc = SAS_LINK_RATE_12_0_GBPS;
		break;
	case SSI2_SAS_NEG_LINK_RATE_PHY_DISABLED:
		rc = SAS_PHY_DISABLED;
		break;
	case SSI2_SAS_NEG_LINK_RATE_NEGOTIATION_FAILED:
		rc = SAS_LINK_RATE_FAILED;
		break;
	case SSI2_SAS_NEG_LINK_RATE_PORT_SELECTOR:
		rc = SAS_SATA_PORT_SELECTOR;
		break;
	case SSI2_SAS_NEG_LINK_RATE_SMP_RESET_IN_PROGRESS:
		rc = SAS_PHY_RESET_IN_PROGRESS;
		break;

	default:
	case SSI2_SAS_NEG_LINK_RATE_SATA_OOB_COMPLETE:
	case SSI2_SAS_NEG_LINK_RATE_UNKNOWN_LINK_RATE:
		rc = SAS_LINK_RATE_UNKNOWN;
		break;
	}
	return rc;
}

/**
 * _transport_set_identify - set identify for phys and end devices
 * @ioa: per adapter object
 * @handle: device handle
 * @identify: sas identify info
 *
 * Populates sas identify info.
 *
 * Returns 0 for success, non-zero for failure.
 */
static int
_transport_set_identify(struct HST2DR_ADAPTER *ioa, u16 handle,
	struct sas_identify *identify)
{
	SSI2_INQUIRY_SAS_DEV sas_dev00;
	SSI2_INQUIRY_PAGE_REPLY ssi_reply;
	u32 device_info;
	u32 ioa_status;

	if (ioa->shost_recovery || ioa->pci_error_recovery) {
		log_transport(ioa, "%s: host reset in progress!\n",
			__func__);
		return -EFAULT;
	}

	if ((hst2dr_cfg_get_sas_dev(ioa, &ssi_reply, &sas_dev00,
			SSI2_SAS_DEVICE_PGAD_FORM_HANDLE, handle))) {
		log_error(ioa, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		return -ENXIO;
	}

	ioa_status = le16_to_cpu(ssi_reply.status) &
		SSI2_IOASTATUS_MASK;
	if (ioa_status != SSI2_IOASTATUS_SUCCESS) {
		log_error(ioa,
			"handle(0x%04x), ioa_status(0x%04x)\nfailure at %s:%d/%s()!\n",
			handle, ioa_status,
			__FILE__, __LINE__, __func__);
		return -EIO;
	}

	memset(identify, 0, sizeof(struct sas_identify));
	device_info = le32_to_cpu(sas_dev00.dev_info);

	/* sas_address */
	identify->sas_address = le64_to_cpu(sas_dev00.sas_address);

	/* phy number of the parent device this device is linked to */
	identify->phy_identifier = sas_dev00.phy_num;

	/* device_type */
	switch (device_info & SSI2_SAS_DEVICE_INFO_MASK_DEVICE_TYPE) {
	case SSI2_SAS_DEVICE_INFO_NO_DEVICE:
		identify->device_type = SAS_PHY_UNUSED;
		break;
	case SSI2_SAS_DEVICE_INFO_END_DEVICE:
		identify->device_type = SAS_END_DEVICE;
		break;
	case SSI2_SAS_DEVICE_INFO_EDGE_EXPANDER:
		identify->device_type = SAS_EDGE_EXPANDER_DEVICE;
		break;
	case SSI2_SAS_DEVICE_INFO_FANOUT_EXPANDER:
		identify->device_type = SAS_FANOUT_EXPANDER_DEVICE;
		break;
	}

	/* initiator_port_protocols */
	if (device_info & SSI2_SAS_DEVICE_INFO_SSP_INITIATOR)
		identify->initiator_port_protocols |= SAS_PROTOCOL_SSP;
	if (device_info & SSI2_SAS_DEVICE_INFO_STP_INITIATOR)
		identify->initiator_port_protocols |= SAS_PROTOCOL_STP;
	if (device_info & SSI2_SAS_DEVICE_INFO_SMP_INITIATOR)
		identify->initiator_port_protocols |= SAS_PROTOCOL_SMP;
	if (device_info & SSI2_SAS_DEVICE_INFO_SATA_HOST)
		identify->initiator_port_protocols |= SAS_PROTOCOL_SATA;

	/* target_port_protocols */
	if (device_info & SSI2_SAS_DEVICE_INFO_SSP_TARGET)
		identify->target_port_protocols |= SAS_PROTOCOL_SSP;
	if (device_info & SSI2_SAS_DEVICE_INFO_STP_TARGET)
		identify->target_port_protocols |= SAS_PROTOCOL_STP;
	if (device_info & SSI2_SAS_DEVICE_INFO_SMP_TARGET)
		identify->target_port_protocols |= SAS_PROTOCOL_SMP;
	if (device_info & SSI2_SAS_DEVICE_INFO_SATA_DEVICE)
		identify->target_port_protocols |= SAS_PROTOCOL_SATA;

	return 0;
}

/**
 * hst2dr_transport_done -  internal transport layer callback handler.
 * @ioa: per adapter object
 * @cqe: completion queue entity
 *
 * Callback handler when sending internal generated transport cmds.
 * The callback index passed is `ioa->transport_cb_idx`
 *
 * Return 1 meaning mf should be freed from _base_interrupt
 *	0 means the mf is freed from this function.
 */
u8
hst2dr_transport_done(struct HST2DR_ADAPTER *ioa,
		hst2dr_nvme_completion *cqe)
{
	SSI2_DEFAULT_REPLY *ssi_reply = NULL;

	if (cqe->ctrl.description == SSI2_RPY_DESCRIPT_FLAGS_ADDRESS_REPLY)
		ssi_reply =  hst2dr_base_get_reply_virt_addr(ioa,
				cqe->reply_id);
	if (ioa->transport_cmds.status == HST2DR_CMD_NOT_USED)
		return 1;
	if (ioa->transport_cmds.host_tag_id != cqe->host_tag_id)
		return 1;
	ioa->transport_cmds.status |= HST2DR_CMD_COMPLETE;
	if (ssi_reply) {
		ssi_reply->status = cqe->ctrl.status;
		memcpy(ioa->transport_cmds.reply, ssi_reply,
			min_t(u8, ssi_reply->msg_len * 4, 128));
		debug_dump_mem("transport_cmd.reply", ssi_reply,
			min_t(u8, ssi_reply->msg_len * 4, 128));
		if (ssi_reply->msg_len == 0)
			ioa->transport_cmds.status |= HST2DR_CMD_NOT_USED;
		else
			ioa->transport_cmds.status |= HST2DR_CMD_REPLY_VALID;
	} else {
		ssi_reply = (SSI2_DEFAULT_REPLY *)ioa->transport_cmds.reply;
		ssi_reply->status = cqe->ctrl.status;
		ssi_reply->dev_handle =
			cqe->resv0; // smp passthrouth response_data_len
		ioa->transport_cmds.status |= HST2DR_CMD_REPLY_VALID;
	}
	ioa->transport_cmds.status &= ~HST2DR_CMD_PENDING;
	complete(&ioa->transport_cmds.done);
	return 1;
}

/* report manufacture request structure */
struct rep_manu_request {
	u8 smp_frame_type;
	u8 function;
	u8 reserved;
	u8 request_length;
};

/* report manufacture reply structure */
struct rep_manu_reply {
	u8 smp_frame_type; /* 0x41 */
	u8 function; /* 0x01 */
	u8 function_result;
	u8 response_length;
	u16 expander_change_count;
	u8 reserved0[2];
	u8 sas_format;
	u8 reserved2[3];
	u8 vendor_id[SAS_EXPANDER_VENDOR_ID_LEN];
	u8 product_id[SAS_EXPANDER_PRODUCT_ID_LEN];
	u8 product_rev[SAS_EXPANDER_PRODUCT_REV_LEN];
	u8 component_vendor_id[SAS_EXPANDER_COMPONENT_VENDOR_ID_LEN];
	u16 component_id;
	u8 component_revision_id;
	u8 reserved3;
	u8 vendor_specific[8];
};

/**
 * transport_expander_report_manufacture - obtain SMP report_manufacture
 * @ioa: per adapter object
 * @sas_address: expander sas address
 * @edev: the sas_expander_device object
 *
 * Fills in the sas_expander_device object when SMP port is created.
 *
 * Returns 0 for success, non-zero for failure.
 */
static int
_transport_expander_report_manufacture(struct HST2DR_ADAPTER *ioa,
	u64 sas_address, u16 handle, struct sas_expander_device *edev)
{
	SSI2_SMP_PASSTHROUGH_REQUEST *ssi_request;
	SSI2_SMP_PASSTHROUGH_REPLY *ssi_reply;
	struct rep_manu_reply *manufacture_reply;
	struct rep_manu_request *manufacture_request;
	int rc;
	u16 host_tag_id;
	u32 ioa_state;
	void *psge;
	u8 issue_reset = 0;
	void *data_out = NULL;
	dma_addr_t data_out_dma;
	dma_addr_t data_in_dma;
	size_t data_in_sz;
	size_t data_out_sz;
	u16 wait_state_count;
	hst2dr_command *scmd;

	if (ioa->shost_recovery || ioa->pci_error_recovery) {
		log_transport(ioa, "%s: host reset in progress!\n",
			__func__);
		return -EFAULT;
	}

	mutex_lock(&ioa->transport_cmds.mutex);

	if (ioa->transport_cmds.status != HST2DR_CMD_NOT_USED) {
		log_error(ioa, "%s: transport_cmds in use\n",
			__func__);
		rc = -EAGAIN;
		goto out;
	}
	ioa->transport_cmds.status = HST2DR_CMD_PENDING;

	wait_state_count = 0;
	ioa_state = hst2dr_base_get_ioastate(ioa, 1);
	while (ioa_state != SSI2_IOA_STATE_OPERATIONAL) {
		if (wait_state_count++ == 10) {
			log_error(ioa,
				"%s: failed due to ioa not operational\n",
				__func__);
			rc = -EFAULT;
			goto out;
		}
		ssleep(1);
		ioa_state = hst2dr_base_get_ioastate(ioa, 1);
		log_transport(ioa,
			"%s: waiting for operational state(count=%d)\n",
			__func__, wait_state_count);
	}
	if (wait_state_count)
		log_transport(ioa, "%s: ioa is operational\n",
			__func__);

	host_tag_id = hst2dr_base_get_host_tag_id(ioa, ioa->transport_cb_idx);
	if (host_tag_id == NO_HOST_TAG_ID) {
		log_error(ioa, "%s: failed obtaining a host_tag_id\n",
			__func__);
		rc = -EAGAIN;
		goto out;
	}

	rc = 0;
	scmd = hst2dr_base_get_msg_frame(ioa, host_tag_id);
	ssi_request = (SSI2_SMP_PASSTHROUGH_REQUEST *)scmd;
	ioa->transport_cmds.host_tag_id = host_tag_id;

	data_out_sz = sizeof(struct rep_manu_request);
	data_in_sz = sizeof(struct rep_manu_reply);
	data_out = dma_alloc_coherent(&ioa->pdev->dev,
		data_out_sz + 0x1000 + data_in_sz, &data_out_dma, GFP_KERNEL);

	if (!data_out) {
		log_error(ioa, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		rc = -ENOMEM;
		hst2dr_base_free_host_tag_id(ioa, host_tag_id);
		goto out;
	}

	data_in_dma = data_out_dma + 0x1000;

	manufacture_request = data_out;
	manufacture_request->smp_frame_type = 0x40;
	manufacture_request->function = 1;
	manufacture_request->reserved = 0;
	manufacture_request->request_length = 0;

	memset(ssi_request, 0, sizeof(SSI2_SMP_PASSTHROUGH_REQUEST));
	ssi_request->sas_address = cpu_to_le64(sas_address);
	ssi_request->handle = handle;

	ssi_request->request_data_len = cpu_to_le16(data_out_sz);
	psge = &ssi_request->sgl;

	ioa->build_sg(ioa, psge, data_out_dma, data_out_sz, data_in_dma,
		data_in_sz);

	scmd->cmd.internal.cmd.head.opcode = SSI2_FUNCTION_SMP_PASSTHROUGH;
	scmd->cmd.internal.cmd.head.opflags = cmd_flag_fw_mode_admin;
	scmd->cmd.internal.cmd.head.host_tag_id = host_tag_id;
	scmd->cmd.internal.cmd.head.host_flag = 0;

	init_completion(&ioa->transport_cmds.done);
	ioa->put_host_tag_id_default(ioa, scmd);
	wait_for_completion_timeout(&ioa->transport_cmds.done,
		SMP_PASSTHROUGH_WAITING * HZ);

	if (!(ioa->transport_cmds.status & HST2DR_CMD_COMPLETE)) {
		log_error(ioa, "%s: SSI2_FUNCTION_SMP_PASSTHROUGH timeout\n",
			__func__);
		if (!(ioa->transport_cmds.status & HST2DR_CMD_RESET))
			issue_reset = 1;
		goto issue_host_reset;
	}


	if (ioa->transport_cmds.status & HST2DR_CMD_REPLY_VALID) {
		u8 *tmp;

		ssi_reply = ioa->transport_cmds.reply;

		if (le16_to_cpu(ssi_reply->response_data_len) !=
			sizeof(struct rep_manu_reply))
			goto out;

		manufacture_reply = data_out + 0x1000;
		strncpy(edev->vendor_id, manufacture_reply->vendor_id,
			SAS_EXPANDER_VENDOR_ID_LEN);
		strncpy(edev->product_id, manufacture_reply->product_id,
			SAS_EXPANDER_PRODUCT_ID_LEN);
		strncpy(edev->product_rev, manufacture_reply->product_rev,
			SAS_EXPANDER_PRODUCT_REV_LEN);
		edev->level = manufacture_reply->sas_format & 1;
		if (edev->level) {
			strncpy(edev->component_vendor_id,
				manufacture_reply->component_vendor_id,
				SAS_EXPANDER_COMPONENT_VENDOR_ID_LEN);
			tmp = (u8 *)&manufacture_reply->component_id;
			edev->component_id = tmp[0] << 8 | tmp[1];
			edev->component_revision_id =
				manufacture_reply->component_revision_id;
		}
	}

issue_host_reset:
	if (issue_reset)
		hst2dr_base_hard_reset_handler(ioa, HARD_RESET, 20);

out:
	ioa->transport_cmds.status = HST2DR_CMD_NOT_USED;
	if (data_out)
		dma_free_coherent(&ioa->pdev->dev,
				data_out_sz + data_in_sz + 0x1000,
				data_out, data_out_dma);

	mutex_unlock(&ioa->transport_cmds.mutex);
	return rc;
}


/**
 * _transport_delete_port - helper function to removing a port
 * @ioa: per adapter object
 * @hst2dr_port: hst2dr per port object
 *
 * Returns nothing.
 */
static void
_transport_delete_port(struct HST2DR_ADAPTER *ioa,
	struct _sas_port *hst2dr_port)
{
	u64 sas_address = hst2dr_port->remote_identify.sas_address;
	enum sas_device_type device_type =
		hst2dr_port->remote_identify.device_type;

	dev_info(&hst2dr_port->port->dev,
		"remove: sas_addr(0x%016llx)\n",
		(unsigned long long) sas_address);
	if (device_type == SAS_END_DEVICE)
		hst2dr_device_remove_by_sas_address(ioa, sas_address);
	else if (device_type == SAS_EDGE_EXPANDER_DEVICE ||
		device_type == SAS_FANOUT_EXPANDER_DEVICE)
		hst2dr_expander_remove(ioa, sas_address);
}

/**
 * _transport_delete_phy - helper function to removing single phy from port
 * @ioa: per adapter object
 * @hst2dr_port: hst2dr per port object
 * @hst2dr_phy: hst2dr per phy object
 *
 * Returns nothing.
 */
static void
_transport_delete_phy(struct HST2DR_ADAPTER *ioa,
	struct _sas_port *hst2dr_port, struct _sas_phy *hst2dr_phy)
{
	u64 sas_address = hst2dr_port->remote_identify.sas_address;

	dev_info(&hst2dr_phy->phy->dev,
		"remove: sas_addr(0x%016llx), phy(%d)\n",
		(unsigned long long) sas_address, hst2dr_phy->phy_id);

	list_del_init(&hst2dr_phy->port_siblings);
	hst2dr_port->num_phys--;
	sas_port_delete_phy(hst2dr_port->port, hst2dr_phy->phy);
	hst2dr_phy->phy_belongs_to_port = 0;
}

/**
 * _transport_add_phy - helper function to adding single phy to port
 * @ioa: per adapter object
 * @hst2dr_port: hst2dr per port object
 * @hst2dr_phy: hst2dr per phy object
 *
 * Returns nothing.
 */
static void
_transport_add_phy(struct HST2DR_ADAPTER *ioa, struct _sas_port *hst2dr_port,
	struct _sas_phy *hst2dr_phy)
{
	u64 sas_address = hst2dr_port->remote_identify.sas_address;

	dev_info(&hst2dr_phy->phy->dev,
		"add: sas_addr(0x%016llx), phy(%d)\n", (unsigned long long)
		sas_address, hst2dr_phy->phy_id);

	list_add_tail(&hst2dr_phy->port_siblings, &hst2dr_port->phy_list);
	hst2dr_port->num_phys++;
	sas_port_add_phy(hst2dr_port->port, hst2dr_phy->phy);
	hst2dr_phy->phy_belongs_to_port = 1;
}

/**
 * _transport_add_phy_to_an_existing_port - adding new phy to existing port
 * @ioa: per adapter object
 * @sas_node: sas node object (either expander or sas host)
 * @hst2dr_phy: hst2dr per phy object
 * @sas_address: sas address of device/expander were phy needs to be added to
 *
 * Returns nothing.
 */
static void
_transport_add_phy_to_an_existing_port(struct HST2DR_ADAPTER *ioa,
	struct _sas_node *sas_node, struct _sas_phy *hst2dr_phy,
	u64 sas_address)
{
	struct _sas_port *hst2dr_port;
	struct _sas_phy *phy_srch;

	if (hst2dr_phy->phy_belongs_to_port == 1)
		return;

	list_for_each_entry(hst2dr_port, &sas_node->sas_port_list,
			port_list) {
		if (hst2dr_port->remote_identify.sas_address !=
				sas_address)
			continue;
		list_for_each_entry(phy_srch, &hst2dr_port->phy_list,
				port_siblings) {
			if (phy_srch == hst2dr_phy)
				return;
		}
		_transport_add_phy(ioa, hst2dr_port, hst2dr_phy);
			return;
	}

}

/**
 * _transport_del_phy_from_an_existing_port - delete phy from existing port
 * @ioa: per adapter object
 * @sas_node: sas node object (either expander or sas host)
 * @hst2dr_phy: hst2dr per phy object
 *
 * Returns nothing.
 */
static void
_transport_del_phy_from_an_existing_port(struct HST2DR_ADAPTER *ioa,
	struct _sas_node *sas_node, struct _sas_phy *hst2dr_phy)
{
	struct _sas_port *hst2dr_port, *next;
	struct _sas_phy *phy_srch;

	if (hst2dr_phy->phy_belongs_to_port == 0)
		return;

	list_for_each_entry_safe(hst2dr_port, next, &sas_node->sas_port_list,
			port_list) {
		list_for_each_entry(phy_srch, &hst2dr_port->phy_list,
				port_siblings) {
			if (phy_srch != hst2dr_phy)
				continue;

			if (hst2dr_port->num_phys == 1)
				_transport_delete_port(ioa, hst2dr_port);
			else
				_transport_delete_phy(ioa, hst2dr_port,
					hst2dr_phy);
			return;
		}
	}
}

/**
 * _transport_sanity_check - sanity check when adding a new port
 * @ioa: per adapter object
 * @sas_node: sas node object (either expander or sas host)
 * @sas_address: sas address of device being added
 *
 * See the explanation above from _transport_delete_duplicate_port
 */
static void
_transport_sanity_check(struct HST2DR_ADAPTER *ioa, struct _sas_node *sas_node,
	u64 sas_address)
{
	int i;

	for (i = 0; i < sas_node->num_phys; i++) {
		if (sas_node->phy[i].remote_identify.sas_address != sas_address)
			continue;
		if (sas_node->phy[i].phy_belongs_to_port == 1)
			_transport_del_phy_from_an_existing_port(ioa, sas_node,
				&sas_node->phy[i]);
	}
}

/**
 * hst2dr_transport_port_add - insert port to the list
 * @ioa: per adapter object
 * @handle: handle of attached device
 * @sas_address: sas address of parent expander or sas host
 * Context: This function will acquire ioa->sas_node_lock.
 *
 * Adding new port object to the sas_node->sas_port_list.
 *
 * Returns hst2dr_port.
 */
struct _sas_port *
hst2dr_transport_port_add(struct HST2DR_ADAPTER *ioa, u16 handle,
	u64 sas_address)
{
	struct _sas_phy *hst2dr_phy, *next;
	struct _sas_port *hst2dr_port;
	unsigned long flags;
	struct _sas_node *sas_node;
	struct sas_rphy *rphy;
	struct _sas_device *sas_device = NULL;
	int i;
	struct sas_port *port;

	hst2dr_port = kzalloc(sizeof(struct _sas_port),
			GFP_KERNEL);
	if (!hst2dr_port) {
		log_error(ioa, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		return NULL;
	}

	INIT_LIST_HEAD(&hst2dr_port->port_list);
	INIT_LIST_HEAD(&hst2dr_port->phy_list);
	spin_lock_irqsave(&ioa->sas_node_lock, flags);
	sas_node = _transport_sas_node_find_by_sas_address(ioa, sas_address);
	spin_unlock_irqrestore(&ioa->sas_node_lock, flags);

	if (!sas_node) {
		log_error(ioa,
			"%s: Could not find parent sas_address(0x%016llx)!\n",
			__func__, (unsigned long long)sas_address);
		goto out_fail;
	}

	if ((_transport_set_identify(ioa, handle,
			&hst2dr_port->remote_identify))) {
		log_error(ioa, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		goto out_fail;
	}

	if (hst2dr_port->remote_identify.device_type == SAS_PHY_UNUSED) {
		log_error(ioa, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		goto out_fail;
	}

	_transport_sanity_check(ioa, sas_node,
		hst2dr_port->remote_identify.sas_address);

	for (i = 0; i < sas_node->num_phys; i++) {
		if (sas_node->phy[i].remote_identify.sas_address !=
			hst2dr_port->remote_identify.sas_address)
			continue;
		list_add_tail(&sas_node->phy[i].port_siblings,
			&hst2dr_port->phy_list);
		hst2dr_port->num_phys++;
	}

	if (!hst2dr_port->num_phys) {
		log_error(ioa, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		goto out_fail;
	}

	if (!sas_node->parent_dev) {
		log_error(ioa, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		goto out_fail;
	}
	port = sas_port_alloc_num(sas_node->parent_dev);
	if ((sas_port_add(port))) {
		log_error(ioa, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		goto out_fail;
	}

	list_for_each_entry(hst2dr_phy, &hst2dr_port->phy_list,
			port_siblings) {
		sas_port_add_phy(port, hst2dr_phy->phy);
		hst2dr_phy->phy_belongs_to_port = 1;
	}

	hst2dr_port->port = port;
	if (hst2dr_port->remote_identify.device_type == SAS_END_DEVICE)
		rphy = sas_end_device_alloc(port);
	else
		rphy = sas_expander_alloc(port,
			hst2dr_port->remote_identify.device_type);

	rphy->identify = hst2dr_port->remote_identify;

	if (hst2dr_port->remote_identify.device_type == SAS_END_DEVICE) {
		sas_device = hst2dr_get_sdev_by_addr(ioa,
				hst2dr_port->remote_identify.sas_address);
		if (!sas_device)
			goto out_fail;

		sas_device->pend_sas_rphy_add = 1;
	}

	if ((sas_rphy_add(rphy))) {
		log_error(ioa, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
	}

	if (hst2dr_port->remote_identify.device_type == SAS_END_DEVICE) {
		sas_device->pend_sas_rphy_add = 0;
		sas_device_put(sas_device);
	}
	log_always(ioa,
		"add: handle(0x%04x), sas_addr(0x%016llx)\n", handle,
		(unsigned long long)hst2dr_port->remote_identify.sas_address);
	hst2dr_port->rphy = rphy;
	spin_lock_irqsave(&ioa->sas_node_lock, flags);
	list_add_tail(&hst2dr_port->port_list, &sas_node->sas_port_list);
	spin_unlock_irqrestore(&ioa->sas_node_lock, flags);

	/* fill in report manufacture */
	if (hst2dr_port->remote_identify.device_type ==
		SSI2_SAS_DEVICE_INFO_EDGE_EXPANDER ||
		hst2dr_port->remote_identify.device_type ==
		SSI2_SAS_DEVICE_INFO_FANOUT_EXPANDER)
		_transport_expander_report_manufacture(ioa,
			hst2dr_port->remote_identify.sas_address,
			handle,
			rphy_to_expander_device(rphy));
	return hst2dr_port;

 out_fail:
	list_for_each_entry_safe(hst2dr_phy, next, &hst2dr_port->phy_list,
		port_siblings)
		list_del_init(&hst2dr_phy->port_siblings);
	kfree(hst2dr_port);
	return NULL;
}

/**
 * hst2dr_transport_port_remove - remove port from the list
 * @ioa: per adapter object
 * @sas_address: sas address of attached device
 * @sas_address_parent: sas address of parent expander or sas host
 * Context: This function will acquire ioa->sas_node_lock.
 *
 * Removing object and freeing associated memory from the
 * ioa->sas_port_list.
 *
 * Return nothing.
 */
void
hst2dr_transport_port_remove(struct HST2DR_ADAPTER *ioa, u64 sas_address,
	u64 sas_address_parent)
{
	int i;
	unsigned long flags;
	struct _sas_port *hst2dr_port, *next;
	struct _sas_node *sas_node;
	u8 found = 0;
	struct _sas_phy *hst2dr_phy, *next_phy;

	spin_lock_irqsave(&ioa->sas_node_lock, flags);
	sas_node = _transport_sas_node_find_by_sas_address(ioa,
		sas_address_parent);
	if (!sas_node) {
		spin_unlock_irqrestore(&ioa->sas_node_lock, flags);
		return;
	}
	list_for_each_entry_safe(hst2dr_port, next, &sas_node->sas_port_list,
			port_list) {
		if (hst2dr_port->remote_identify.sas_address != sas_address)
			continue;
		found = 1;
		list_del_init(&hst2dr_port->port_list);
		goto out;
	}
 out:
	if (!found) {
		spin_unlock_irqrestore(&ioa->sas_node_lock, flags);
		return;
	}

	for (i = 0; i < sas_node->num_phys; i++) {
		if (sas_node->phy[i].remote_identify.sas_address == sas_address)
			memset(&sas_node->phy[i].remote_identify, 0,
				sizeof(struct sas_identify));
	}

	spin_unlock_irqrestore(&ioa->sas_node_lock, flags);

	list_for_each_entry_safe(hst2dr_phy, next_phy,
			&hst2dr_port->phy_list, port_siblings) {
		hst2dr_phy->phy_belongs_to_port = 0;
		log_always(ioa, "remove: sas_addr(0x%016llx), phy(%d)\n",
			(unsigned long long)
			hst2dr_port->remote_identify.sas_address,
			hst2dr_phy->phy_id);
		sas_port_delete_phy(hst2dr_port->port, hst2dr_phy->phy);
		list_del_init(&hst2dr_phy->port_siblings);
	}
	sas_port_delete(hst2dr_port->port);
	kfree(hst2dr_port);
}

/**
 * hst2dr_transport_add_host_phy - report sas_host phy to transport
 * @ioa: per adapter object
 * @hst2dr_phy: hst2dr per phy object
 * @phy_pg0: sas phy page 0
 * @parent_dev: parent device class object
 *
 * Returns 0 for success, non-zero for failure.
 */
int
hst2dr_transport_add_host_phy(struct HST2DR_ADAPTER *ioa, struct _sas_phy
	*hst2dr_phy, SSI2_INQUIRY_PHY phy_pg0, struct device *parent_dev)
{
	struct sas_phy *phy;
	int phy_index = hst2dr_phy->phy_id;


	INIT_LIST_HEAD(&hst2dr_phy->port_siblings);
	phy = sas_phy_alloc(parent_dev, phy_index);
	if (!phy) {
		log_error(ioa, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		return -1;
	}
	if ((_transport_set_identify(ioa, hst2dr_phy->handle,
			&hst2dr_phy->identify))) {
		log_error(ioa, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		sas_phy_free(phy);
		return -1;
	}
	phy->identify = hst2dr_phy->identify;
	hst2dr_phy->attached_handle = le16_to_cpu(phy_pg0.attached_dev_handle);
	if (hst2dr_phy->attached_handle)
		_transport_set_identify(ioa, hst2dr_phy->attached_handle,
			&hst2dr_phy->remote_identify);
	phy->identify.phy_identifier = hst2dr_phy->phy_id;
	phy->negotiated_linkrate = _transport_convert_phy_link_rate(
		phy_pg0.negotiated_linkrate &
		SSI2_SAS_NEG_LINK_RATE_MASK_PHYSICAL);
	phy->minimum_linkrate_hw = _transport_convert_phy_link_rate(
		phy_pg0.hw_linkrate & SSI2_SAS_HWRATE_MIN_RATE_MASK);
	phy->maximum_linkrate_hw = _transport_convert_phy_link_rate(
		phy_pg0.hw_linkrate >> 4);
	phy->minimum_linkrate = _transport_convert_phy_link_rate(
		phy_pg0.programmed_linkrate & SSI2_SAS_PRATE_MIN_RATE_MASK);
	phy->maximum_linkrate = _transport_convert_phy_link_rate(
		phy_pg0.programmed_linkrate >> 4);

	if ((sas_phy_add(phy))) {
		log_error(ioa, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		sas_phy_free(phy);
		return -1;
	}
	hst2dr_phy->phy = phy;
	return 0;
}


/**
 * hst2dr_transport_add_expander_phy - report expander phy to transport
 * @ioa: per adapter object
 * @hst2dr_phy: hst2dr per phy object
 * @expander_phy: expander page 1
 * @parent_dev: parent device class object
 *
 * Returns 0 for success, non-zero for failure.
 */
int
hst2dr_transport_add_expander_phy(struct HST2DR_ADAPTER *ioa, struct _sas_phy
	*hst2dr_phy, SSI2_INQUIRY_EXPANDER_PHY expander_phy,
	struct device *parent_dev)
{
	struct sas_phy *phy;
	int phy_index = hst2dr_phy->phy_id;

	INIT_LIST_HEAD(&hst2dr_phy->port_siblings);
	phy = sas_phy_alloc(parent_dev, phy_index);
	if (!phy) {
		log_error(ioa, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		return -1;
	}
	if ((_transport_set_identify(ioa, hst2dr_phy->handle,
			&hst2dr_phy->identify))) {
		log_error(ioa, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		sas_phy_free(phy);
		return -1;
	}
	phy->identify = hst2dr_phy->identify;
	hst2dr_phy->attached_handle =
		le16_to_cpu(expander_phy.attached_dev_handle);
	if (hst2dr_phy->attached_handle)
		_transport_set_identify(ioa, hst2dr_phy->attached_handle,
			&hst2dr_phy->remote_identify);
	phy->identify.phy_identifier = hst2dr_phy->phy_id;
	phy->negotiated_linkrate = _transport_convert_phy_link_rate(
		expander_phy.negotiated_linkrate &
		SSI2_SAS_NEG_LINK_RATE_MASK_PHYSICAL);
	phy->minimum_linkrate_hw = _transport_convert_phy_link_rate(
		expander_phy.hw_linkrate & SSI2_SAS_HWRATE_MIN_RATE_MASK);
	phy->maximum_linkrate_hw = _transport_convert_phy_link_rate(
		expander_phy.hw_linkrate >> 4);
	phy->minimum_linkrate = _transport_convert_phy_link_rate(
		expander_phy.programmed_linkrate &
		SSI2_SAS_PRATE_MIN_RATE_MASK);
	phy->maximum_linkrate = _transport_convert_phy_link_rate(
		expander_phy.programmed_linkrate >> 4);

	if ((sas_phy_add(phy))) {
		log_error(ioa, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		sas_phy_free(phy);
		return -1;
	}
	hst2dr_phy->phy = phy;
	return 0;
}

/**
 * hst2dr_transport_update_links - refreshing phy link changes
 * @ioa: per adapter object
 * @sas_address: sas address of parent expander or sas host
 * @handle: attached device handle
 * @phy_numberv: phy number
 * @link_rate: new link rate
 *
 * Returns nothing.
 */
void
hst2dr_transport_update_links(struct HST2DR_ADAPTER *ioa,
	u64 sas_address, u16 handle, u8 phy_number, u8 link_rate)
{
	unsigned long flags;
	struct _sas_node *sas_node;
	struct _sas_phy *hst2dr_phy;

	if (ioa->shost_recovery || ioa->pci_error_recovery)
		return;

	spin_lock_irqsave(&ioa->sas_node_lock, flags);
	sas_node = _transport_sas_node_find_by_sas_address(ioa, sas_address);
	if (!sas_node) {
		spin_unlock_irqrestore(&ioa->sas_node_lock, flags);
		return;
	}

	hst2dr_phy = &sas_node->phy[phy_number];
	hst2dr_phy->attached_handle = handle;
	spin_unlock_irqrestore(&ioa->sas_node_lock, flags);
	if (handle && (link_rate >= SSI2_SAS_NEG_LINK_RATE_1_5)) {
		_transport_set_identify(ioa, handle,
			&hst2dr_phy->remote_identify);
		_transport_add_phy_to_an_existing_port(ioa, sas_node,
			hst2dr_phy, hst2dr_phy->remote_identify.sas_address);
	} else
		memset(&hst2dr_phy->remote_identify, 0,
			sizeof(struct sas_identify));

	if (hst2dr_phy->phy)
		hst2dr_phy->phy->negotiated_linkrate =
			_transport_convert_phy_link_rate(link_rate);
}

static inline void *
phy_to_ioa(struct sas_phy *phy)
{
	struct Scsi_Host *shost = dev_to_shost(phy->dev.parent);

	return shost_priv(shost);
}

static inline void *
rphy_to_ioa(struct sas_rphy *rphy)
{
	struct Scsi_Host *shost = dev_to_shost(rphy->dev.parent->parent);

	return shost_priv(shost);
}

/* report phy error log structure */
struct phy_error_log_request {
	u8 smp_frame_type; /* 0x40 */
	u8 function; /* 0x11 */
	u8 allocated_response_length;
	u8 request_length; /* 02 */
	u8 reserved_1[5];
	u8 phy_identifier;
	u8 reserved_2[2];
};

/* report phy error log reply structure */
struct phy_error_log_reply {
	u8 smp_frame_type; /* 0x41 */
	u8 function; /* 0x11 */
	u8 function_result;
	u8 response_length;
	__be16 expander_change_count;
	u8 reserved_1[3];
	u8 phy_identifier;
	u8 reserved_2[2];
	__be32 invalid_dword;
	__be32 running_disparity_error;
	__be32 loss_of_dword_sync;
	__be32 phy_reset_problem;
};

/**
 * _transport_get_linkerrors - return phy counters for both hba and expanders
 * @phy: The sas phy object
 *
 * Returns 0 for success, non-zero for failure.
 *
 */
static int
_transport_get_linkerrors(struct sas_phy *phy)
{
	return 0;
}

/**
 * _transport_get_enclosure_identifier -
 * @phy: The sas phy object
 *
 * Obtain the enclosure logical id for an expander.
 * Returns 0 for success, non-zero for failure.
 */
static int
_transport_get_enclosure_identifier(struct sas_rphy *rphy, u64 *identifier)
{
	struct HST2DR_ADAPTER *ioa = rphy_to_ioa(rphy);
	struct _sas_device *sas_device;
	unsigned long flags;
	int rc;

	spin_lock_irqsave(&ioa->sas_device_lock, flags);
	sas_device = __hst2dr_get_sdev_by_addr(ioa,
		rphy->identify.sas_address);
	if (sas_device) {
		*identifier = sas_device->enclosure_logical_id;
		rc = 0;
		sas_device_put(sas_device);
	} else {
		*identifier = 0;
		rc = -ENXIO;
	}

	spin_unlock_irqrestore(&ioa->sas_device_lock, flags);
	return rc;
}

/**
 * _transport_get_bay_identifier -
 * @phy: The sas phy object
 *
 * Returns the slot id for a device that resides inside an enclosure.
 */
static int
_transport_get_bay_identifier(struct sas_rphy *rphy)
{
	struct HST2DR_ADAPTER *ioa = rphy_to_ioa(rphy);
	struct _sas_device *sas_device;
	unsigned long flags;
	int rc;

	spin_lock_irqsave(&ioa->sas_device_lock, flags);
	sas_device = __hst2dr_get_sdev_by_addr(ioa,
		rphy->identify.sas_address);
	if (sas_device) {
		rc = sas_device->slot;
		sas_device_put(sas_device);
	} else {
		rc = -ENXIO;
	}
	spin_unlock_irqrestore(&ioa->sas_device_lock, flags);
	return rc;
}

/* phy control request structure */
struct phy_control_request {
	u8 smp_frame_type; /* 0x40 */
	u8 function; /* 0x91 */
	u8 allocated_response_length;
	u8 request_length; /* 0x09 */
	u16 expander_change_count;
	u8 reserved_1[3];
	u8 phy_identifier;
	u8 phy_operation;
	u8 reserved_2[13];
	u64 attached_device_name;
	u8 programmed_min_physical_link_rate;
	u8 programmed_max_physical_link_rate;
	u8 reserved_3[6];
};

/* phy control reply structure */
struct phy_control_reply {
	u8 smp_frame_type; /* 0x41 */
	u8 function; /* 0x11 */
	u8 function_result;
	u8 response_length;
};


/**
 * _transport_phy_reset -
 * @phy: The sas phy object
 * @hard_reset:
 *
 * Returns 0 for success, non-zero for failure.
 */
static int
_transport_phy_reset(struct sas_phy *phy, int hard_reset)
{
	return 0;
}

/**
 * _transport_phy_enable - enable/disable phys
 * @phy: The sas phy object
 * @enable: enable phy when true
 *
 * Only support sas_host direct attached phys.
 * Returns 0 for success, non-zero for failure.
 */
static int
_transport_phy_enable(struct sas_phy *phy, int enable)
{
	return 0;
}

/**
 * _transport_phy_speed - set phy min/max link rates
 * @phy: The sas phy object
 * @rates: rates defined in sas_phy_linkrates
 *
 * Only support sas_host direct attached phys.
 * Returns 0 for success, non-zero for failure.
 */
static int
_transport_phy_speed(struct sas_phy *phy, struct sas_phy_linkrates *rates)
{
	return -EINVAL;
}
static int
_transport_map_smp_buffer(struct device *dev, struct bsg_buffer *buf,
		dma_addr_t *dma_addr, size_t *dma_len, void **p)
{
	/* Check if the request is split across multiple segments */
		*p = dma_alloc_coherent(dev, (buf->payload_len + 3) &
			0xfffffffc, dma_addr,
				GFP_KERNEL);
		if (!*p)
			return -ENOMEM;
		*dma_len = (buf->payload_len + 3) & 0xfffffffc;

	return 0;
}

static void
_transport_unmap_smp_buffer(struct device *dev, struct bsg_buffer *buf,
		dma_addr_t dma_addr, void *p)
{
	if (p)
		dma_free_coherent(dev, (buf->payload_len + 3) & 0xfffffffc,
			p, dma_addr);
	else
		dma_unmap_sg(dev, buf->sg_list, 1, DMA_BIDIRECTIONAL);
}

/**
 * _transport_smp_handler - transport portal for smp passthru
 * @shost: shost object
 * @rphy: sas transport rphy object
 * @req:
 *
 * This used primarily for smp_utils.
 * Example:
 *	smp_rep_general /sys/class/bsg/expander-5:0
 */
static void
_transport_smp_handler(struct bsg_job *job, struct Scsi_Host *shost,
		struct sas_rphy *rphy)
{
	struct HST2DR_ADAPTER *ioa = shost_priv(shost);
	SSI2_SMP_PASSTHROUGH_REQUEST *ssi_request;
	SSI2_SMP_PASSTHROUGH_REPLY *ssi_reply;
	int rc;
	u16 host_tag_id;
	u32 ioa_state;
	void *psge;
	dma_addr_t dma_addr_in;
	dma_addr_t dma_addr_out;
	void *addr_in = NULL;
	void *addr_out = NULL;
	size_t dma_len_in;
	size_t dma_len_out;
	u16 wait_state_count;
	unsigned int reslen = 0;
	hst2dr_command *scmd;
	struct _sas_node *sas_node;

	log_transport(ioa, "_transport_smp_handler");
	if (ioa->shost_recovery || ioa->pci_error_recovery) {
		log_transport(ioa, "%s: host reset in progress!\n",
			__func__);
		rc = -EFAULT;
		goto job_done;
	}

	rc = mutex_lock_interruptible(&ioa->transport_cmds.mutex);
	if (rc)
		goto job_done;

	if (ioa->transport_cmds.status != HST2DR_CMD_NOT_USED) {
		log_error(ioa, "%s: transport_cmds in use\n",
			__func__);
		rc = -EAGAIN;
		goto out;
	}
	ioa->transport_cmds.status = HST2DR_CMD_PENDING;

	rc = _transport_map_smp_buffer(&ioa->pdev->dev, &job->request_payload,
			&dma_addr_out, &dma_len_out, &addr_out);
	if (rc)
		goto out;
	if (addr_out) {
		sg_copy_to_buffer(job->request_payload.sg_list,
				job->request_payload.sg_cnt, addr_out,
				job->request_payload.payload_len);
	}

	rc = _transport_map_smp_buffer(&ioa->pdev->dev, &job->reply_payload,
			&dma_addr_in, &dma_len_in, &addr_in);
	if (rc)
		goto unmap_out;

	wait_state_count = 0;
	ioa_state = hst2dr_base_get_ioastate(ioa, 1);
	while (ioa_state != SSI2_IOA_STATE_OPERATIONAL) {
		if (wait_state_count++ == 10) {
			log_error(ioa,
				"%s: failed due to ioa not operational\n",
				__func__);
			rc = -EFAULT;
			goto unmap_in;
		}
		ssleep(1);
		ioa_state = hst2dr_base_get_ioastate(ioa, 1);
		log_transport(ioa,
			"%s: waiting for operational state(count=%d)\n",
			__func__, wait_state_count);
	}
	if (wait_state_count)
		log_transport(ioa, "%s: ioa is operational\n",
			__func__);

	host_tag_id = hst2dr_base_get_host_tag_id(ioa, ioa->transport_cb_idx);
	if (host_tag_id == NO_HOST_TAG_ID) {
		log_error(ioa,
			"%s: failed obtaining a host_tag_id\n",
			__func__);
		rc = -EAGAIN;
		goto unmap_in;
	}

	rc = 0;
	scmd = hst2dr_base_get_msg_frame(ioa, host_tag_id);
	ssi_request = (SSI2_SMP_PASSTHROUGH_REQUEST *)scmd;
	ioa->transport_cmds.host_tag_id = host_tag_id;

	memset(ssi_request, 0, sizeof(SSI2_SMP_PASSTHROUGH_REQUEST));
	ssi_request->sas_address = (rphy) ?
		cpu_to_le64(rphy->identify.sas_address) :
		cpu_to_le64(ioa->sas_hba.sas_address);
	sas_node = _transport_sas_node_find_by_sas_address(ioa,
		ssi_request->sas_address);
	if (sas_node != NULL)
		ssi_request->handle = sas_node->handle;
	else {
		log_error(ioa, "%s find sas_node fail, sas_addr:%llx\n",
			__func__, ssi_request->sas_address);
		rc = -EINVAL;
		hst2dr_base_free_host_tag_id(ioa, host_tag_id);
		goto unmap_in;

	}
	ssi_request->request_data_len = cpu_to_le16(dma_len_out - 4);
	psge = &ssi_request->sgl;

	ioa->build_sg(ioa, psge, dma_addr_out, dma_len_out - 4, dma_addr_in,
			dma_len_in - 4);

	scmd->cmd.internal.cmd.head.opcode = SSI2_FUNCTION_SMP_PASSTHROUGH;
	scmd->cmd.internal.cmd.head.opflags = cmd_flag_fw_mode_admin;
	scmd->cmd.internal.cmd.head.host_tag_id = host_tag_id;
	scmd->cmd.internal.cmd.head.host_flag = 0;

	init_completion(&ioa->transport_cmds.done);
	ioa->put_host_tag_id_default(ioa, scmd);
	wait_for_completion_timeout(&ioa->transport_cmds.done,
		SMP_PASSTHROUGH_WAITING * HZ);

	if (!(ioa->transport_cmds.status & HST2DR_CMD_COMPLETE)) {
		log_error(ioa,
			"%s : SSI2_FUNCTION_SMP_PASSTHROUGH opcode %x timeout\n",
			__func__, cmd_flag_fw_mode_admin);
		if (!(ioa->transport_cmds.status & HST2DR_CMD_RESET))
			hst2dr_base_hard_reset_handler(ioa, HARD_RESET, 23);

		rc = -ETIMEDOUT;
		goto unmap_in;
	}


	if (!(ioa->transport_cmds.status&HST2DR_CMD_REPLY_VALID)) {
		rc = -ENXIO;
		goto unmap_in;
	}

	ssi_reply = ioa->transport_cmds.reply;

	memcpy(job->reply, ssi_reply, sizeof(*ssi_reply));
	job->reply_len = sizeof(*ssi_reply);
	reslen = le16_to_cpu(ssi_reply->response_data_len);

	if (addr_in) {
		sg_copy_from_buffer(job->reply_payload.sg_list,
				job->reply_payload.sg_cnt, addr_in,
				job->reply_payload.payload_len);
		debug_dump_mem("SMP rep: ", addr_in,
			job->reply_payload.payload_len);
	}

	rc = 0;
 unmap_in:
	_transport_unmap_smp_buffer(&ioa->pdev->dev, &job->reply_payload,
			dma_addr_in, addr_in);
 unmap_out:
	_transport_unmap_smp_buffer(&ioa->pdev->dev, &job->request_payload,
			dma_addr_out, addr_out);
 out:
	ioa->transport_cmds.status = HST2DR_CMD_NOT_USED;
	mutex_unlock(&ioa->transport_cmds.mutex);
job_done:
	bsg_job_done(job, rc, reslen);
}

struct sas_function_template hst2dr_transport_functions = {
	.get_linkerrors		= _transport_get_linkerrors,
	.get_enclosure_identifier = _transport_get_enclosure_identifier,
	.get_bay_identifier	= _transport_get_bay_identifier,
	.phy_reset		= _transport_phy_reset,
	.phy_enable		= _transport_phy_enable,
	.set_phy_speed		= _transport_phy_speed,
	.smp_handler		= _transport_smp_handler,
};

struct scsi_transport_template *hst2dr_transport_template;
