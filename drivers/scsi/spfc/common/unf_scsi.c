// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#include "unf_type.h"
#include "unf_log.h"
#include "unf_scsi_common.h"
#include "unf_lport.h"
#include "unf_rport.h"
#include "unf_portman.h"
#include "unf_exchg.h"
#include "unf_exchg_abort.h"
#include "unf_npiv.h"
#include "unf_io.h"

#define UNF_LUN_ID_MASK 0x00000000ffff0000
#define UNF_CMD_PER_LUN 3

static int unf_scsi_queue_cmd(struct Scsi_Host *phost, struct scsi_cmnd *pcmd);
static int unf_scsi_abort_scsi_cmnd(struct scsi_cmnd *v_cmnd);
static int unf_scsi_device_reset_handler(struct scsi_cmnd *v_cmnd);
static int unf_scsi_bus_reset_handler(struct scsi_cmnd *v_cmnd);
static int unf_scsi_target_reset_handler(struct scsi_cmnd *v_cmnd);
static int unf_scsi_slave_alloc(struct scsi_device *sdev);
static void unf_scsi_destroy_slave(struct scsi_device *sdev);
static int unf_scsi_slave_configure(struct scsi_device *sdev);
static int unf_scsi_scan_finished(struct Scsi_Host *shost, unsigned long time);
static void unf_scsi_scan_start(struct Scsi_Host *shost);

static struct scsi_transport_template *scsi_transport_template;
static struct scsi_transport_template *scsi_transport_template_v;

struct unf_ini_error_code ini_error_code_table1[] = {
	{UNF_IO_SUCCESS, UNF_SCSI_HOST(DID_OK)},
	{UNF_IO_ABORTED, UNF_SCSI_HOST(DID_ABORT)},
	{UNF_IO_FAILED, UNF_SCSI_HOST(DID_ERROR)},
	{UNF_IO_ABORT_ABTS, UNF_SCSI_HOST(DID_ERROR)},
	{UNF_IO_ABORT_LOGIN, UNF_SCSI_HOST(DID_NO_CONNECT)},
	{UNF_IO_ABORT_REET, UNF_SCSI_HOST(DID_RESET)},
	{UNF_IO_ABORT_FAILED, UNF_SCSI_HOST(DID_ERROR)},
	{UNF_IO_OUTOF_ORDER, UNF_SCSI_HOST(DID_ERROR)},
	{UNF_IO_FTO, UNF_SCSI_HOST(DID_TIME_OUT)},
	{UNF_IO_LINK_FAILURE, UNF_SCSI_HOST(DID_ERROR)},
	{UNF_IO_OVER_FLOW, UNF_SCSI_HOST(DID_ERROR)},
	{UNF_IO_RSP_OVER, UNF_SCSI_HOST(DID_ERROR)},
	{UNF_IO_LOST_FRAME, UNF_SCSI_HOST(DID_ERROR)},
	{UNF_IO_UNDER_FLOW, UNF_SCSI_HOST(DID_OK)},
	{UNF_IO_HOST_PROG_ERROR, UNF_SCSI_HOST(DID_ERROR)},
	{UNF_IO_SEST_PROG_ERROR, UNF_SCSI_HOST(DID_ERROR)},
	{UNF_IO_INVALID_ENTRY, UNF_SCSI_HOST(DID_ERROR)},
	{UNF_IO_ABORT_SEQ_NOT, UNF_SCSI_HOST(DID_ERROR)},
	{UNF_IO_REJECT, UNF_SCSI_HOST(DID_ERROR)},
	{UNF_IO_EDC_IN_ERROR, UNF_SCSI_HOST(DID_ERROR)},
	{UNF_IO_EDC_OUT_ERROR, UNF_SCSI_HOST(DID_ERROR)},
	{UNF_IO_UNINIT_KEK_ERR, UNF_SCSI_HOST(DID_ERROR)},
	{UNF_IO_DEK_OUTOF_RANGE, UNF_SCSI_HOST(DID_ERROR)},
	{UNF_IO_KEY_UNWRAP_ERR, UNF_SCSI_HOST(DID_ERROR)},
	{UNF_IO_KEY_TAG_ERR, UNF_SCSI_HOST(DID_ERROR)},
	{UNF_IO_KEY_ECC_ERR, UNF_SCSI_HOST(DID_ERROR)},
	{UNF_IO_BLOCK_SIZE_ERROR, UNF_SCSI_HOST(DID_ERROR)},
	{UNF_IO_ILLEGAL_CIPHER_MODE, UNF_SCSI_HOST(DID_ERROR)},
	{UNF_IO_CLEAN_UP, UNF_SCSI_HOST(DID_ERROR)},
	{UNF_IO_ABORTED_BY_TARGET, UNF_SCSI_HOST(DID_ERROR)},
	{UNF_IO_TRANSPORT_ERROR, UNF_SCSI_HOST(DID_ERROR)},
	{UNF_IO_LINK_FLASH, UNF_SCSI_HOST(DID_NO_CONNECT)},
	{UNF_IO_TIMEOUT, UNF_SCSI_HOST(DID_TIME_OUT)},
	{UNF_IO_DMA_ERROR, UNF_SCSI_HOST(DID_ERROR)},
	{UNF_IO_NO_LPORT, UNF_SCSI_HOST(DID_NO_CONNECT)},
	{UNF_IO_NO_XCHG, UNF_SCSI_HOST(DID_SOFT_ERROR)},
	{UNF_IO_SOFT_ERR, UNF_SCSI_HOST(DID_SOFT_ERROR)},
	{UNF_IO_PORT_LOGOUT, UNF_SCSI_HOST(DID_NO_CONNECT)},
	{UNF_IO_ERREND, UNF_SCSI_HOST(DID_ERROR)},
	{UNF_IO_DIF_ERROR, (UNF_SCSI_HOST(DID_OK) | UNF_SCSI_STATUS(SCSI_CHECK_CONDITION))},
	{UNF_IO_INCOMPLETE, UNF_SCSI_HOST(DID_IMM_RETRY)},
	{UNF_IO_DIF_REF_ERROR, (UNF_SCSI_HOST(DID_OK) | UNF_SCSI_STATUS(SCSI_CHECK_CONDITION))},
	{UNF_IO_DIF_GEN_ERROR, (UNF_SCSI_HOST(DID_OK) | UNF_SCSI_STATUS(SCSI_CHECK_CONDITION))}
};

u32 ini_err_code_table_cnt1 = sizeof(ini_error_code_table1) / sizeof(struct unf_ini_error_code);

static void unf_set_rport_loss_tmo(struct fc_rport *rport, u32 timeout)
{
	if (timeout)
		rport->dev_loss_tmo = timeout;
	else
		rport->dev_loss_tmo = 1;
}

static void unf_get_host_port_id(struct Scsi_Host *shost)
{
	struct unf_lport *unf_lport = NULL;

	unf_lport = (struct unf_lport *)shost->hostdata[0];
	if (unlikely(!unf_lport)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR, "[err]Port is null");
		return;
	}

	fc_host_port_id(shost) = unf_lport->port_id;
}

static void unf_get_host_speed(struct Scsi_Host *shost)
{
	struct unf_lport *unf_lport = NULL;
	u32 speed = FC_PORTSPEED_UNKNOWN;

	unf_lport = (struct unf_lport *)shost->hostdata[0];
	if (unlikely(!unf_lport)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR, "[err]Port is null");
		return;
	}

	switch (unf_lport->speed) {
	case UNF_PORT_SPEED_2_G:
		speed = FC_PORTSPEED_2GBIT;
		break;
	case UNF_PORT_SPEED_4_G:
		speed = FC_PORTSPEED_4GBIT;
		break;
	case UNF_PORT_SPEED_8_G:
		speed = FC_PORTSPEED_8GBIT;
		break;
	case UNF_PORT_SPEED_16_G:
		speed = FC_PORTSPEED_16GBIT;
		break;
	case UNF_PORT_SPEED_32_G:
		speed = FC_PORTSPEED_32GBIT;
		break;
	default:
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) with unknown speed(0x%x) for FC mode",
			     unf_lport->port_id, unf_lport->speed);
		break;
	}

	fc_host_speed(shost) = speed;
}

static void unf_get_host_port_type(struct Scsi_Host *shost)
{
	struct unf_lport *unf_lport = NULL;
	u32 port_type = FC_PORTTYPE_UNKNOWN;

	unf_lport = (struct unf_lport *)shost->hostdata[0];
	if (unlikely(!unf_lport)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR, "[err]Port is null");
		return;
	}

	switch (unf_lport->act_topo) {
	case UNF_ACT_TOP_PRIVATE_LOOP:
		port_type = FC_PORTTYPE_LPORT;
		break;
	case UNF_ACT_TOP_PUBLIC_LOOP:
		port_type = FC_PORTTYPE_NLPORT;
		break;
	case UNF_ACT_TOP_P2P_DIRECT:
		port_type = FC_PORTTYPE_PTP;
		break;
	case UNF_ACT_TOP_P2P_FABRIC:
		port_type = FC_PORTTYPE_NPORT;
		break;
	default:
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) with unknown topo type(0x%x) for FC mode",
			     unf_lport->port_id, unf_lport->act_topo);
		break;
	}

	fc_host_port_type(shost) = port_type;
}

static void unf_get_symbolic_name(struct Scsi_Host *shost)
{
	u8 *name = NULL;
	struct unf_lport *unf_lport = NULL;

	unf_lport = (struct unf_lport *)(uintptr_t)shost->hostdata[0];
	if (unlikely(!unf_lport)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR, "[err]Check l_port failed");
		return;
	}

	name = fc_host_symbolic_name(shost);
	if (name)
		snprintf(name, FC_SYMBOLIC_NAME_SIZE, "SPFC_FW_RELEASE:%s SPFC_DRV_RELEASE:%s",
			 unf_lport->fw_version, SPFC_DRV_VERSION);
}

static void unf_get_host_fabric_name(struct Scsi_Host *shost)
{
	struct unf_lport *unf_lport = NULL;

	unf_lport = (struct unf_lport *)shost->hostdata[0];

	if (unlikely(!unf_lport)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR, "[err]Port is null");
		return;
	}
	fc_host_fabric_name(shost) = unf_lport->fabric_node_name;
}

static void unf_get_host_port_state(struct Scsi_Host *shost)
{
	struct unf_lport *unf_lport = NULL;
	enum fc_port_state port_state;

	unf_lport = (struct unf_lport *)shost->hostdata[0];
	if (unlikely(!unf_lport)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR, "[err]Port is null");
		return;
	}

	switch (unf_lport->link_up) {
	case UNF_PORT_LINK_DOWN:
		port_state = FC_PORTSTATE_OFFLINE;
		break;
	case UNF_PORT_LINK_UP:
		port_state = FC_PORTSTATE_ONLINE;
		break;
	default:
		port_state = FC_PORTSTATE_UNKNOWN;
		break;
	}

	fc_host_port_state(shost) = port_state;
}

static void unf_dev_loss_timeout_callbk(struct fc_rport *rport)
{
	/*
	 * NOTE: about rport->dd_data
	 * --->>> local SCSI_ID
	 * 1. Assignment during scsi rport link up
	 * 2. Released when scsi rport link down & timeout(30s)
	 * 3. Used during scsi do callback with slave_alloc function
	 */
	struct Scsi_Host *host = NULL;
	struct unf_lport *unf_lport = NULL;
	u32 scsi_id = 0;

	if (unlikely(!rport)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR, "[err]SCSI rport is null");
		return;
	}

	host = rport_to_shost(rport);
	if (unlikely(!host)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR, "[err]Host is null");
		return;
	}

	scsi_id = *(u32 *)(rport->dd_data); /* according to Local SCSI_ID */
	if (unlikely(scsi_id >= UNF_MAX_SCSI_ID)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]rport(0x%p) scsi_id(0x%x) is max than(0x%x)",
			     rport, scsi_id, UNF_MAX_SCSI_ID);
		return;
	}

	unf_lport = (struct unf_lport *)host->hostdata[0];
	if (unf_is_lport_valid(unf_lport) == RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
			     "[event]Port(0x%x_0x%x) rport(0x%p) scsi_id(0x%x) target_id(0x%x) loss timeout",
			     unf_lport->port_id, unf_lport->nport_id, rport,
			     scsi_id, rport->scsi_target_id);

		atomic_inc(&unf_lport->session_loss_tmo);

		/* Free SCSI ID & set table state with DEAD */
		(void)unf_free_scsi_id(unf_lport, scsi_id);
		unf_xchg_up_abort_io_by_scsi_id(unf_lport, scsi_id);
	} else {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(%p) is invalid", unf_lport);
	}

	*((u32 *)rport->dd_data) = INVALID_VALUE32;
}

int unf_scsi_create_vport(struct fc_vport *fc_port, bool disabled)
{
	struct unf_lport *vport = NULL;
	struct unf_lport *unf_lport = NULL;
	struct Scsi_Host *shost = NULL;
	struct vport_config vport_config = {0};

	shost = vport_to_shost(fc_port);

	unf_lport = (struct unf_lport *)shost->hostdata[0];
	if (unf_is_lport_valid(unf_lport) != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(%p) is invalid", unf_lport);

		return RETURN_ERROR;
	}

	vport_config.port_name = fc_port->port_name;

	vport_config.port_mode = fc_port->roles;

	vport = unf_creat_vport(unf_lport, &vport_config);
	if (!vport) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) Create Vport failed on lldrive",
			     unf_lport->port_id);

		return RETURN_ERROR;
	}

	fc_port->dd_data = vport;
	vport->vport = fc_port;

	return RETURN_OK;
}

int unf_scsi_delete_vport(struct fc_vport *fc_port)
{
	int ret = RETURN_ERROR;
	struct unf_lport *vport = NULL;

	vport = (struct unf_lport *)fc_port->dd_data;
	if (unf_is_lport_valid(vport) != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]VPort(%p) is invalid or is removing", vport);

		fc_port->dd_data = NULL;

		return ret;
	}

	ret = (int)unf_destroy_one_vport(vport);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]VPort(0x%x) destroy failed on drive", vport->port_id);

		return ret;
	}

	fc_port->dd_data = NULL;
	return ret;
}

struct fc_function_template function_template = {
	.show_host_node_name = 1,
	.show_host_port_name = 1,
	.show_host_supported_classes = 1,
	.show_host_supported_speeds = 1,

	.get_host_port_id = unf_get_host_port_id,
	.show_host_port_id = 1,
	.get_host_speed = unf_get_host_speed,
	.show_host_speed = 1,
	.get_host_port_type = unf_get_host_port_type,
	.show_host_port_type = 1,
	.get_host_symbolic_name = unf_get_symbolic_name,
	.show_host_symbolic_name = 1,
	.set_host_system_hostname = NULL,
	.show_host_system_hostname = 1,
	.get_host_fabric_name = unf_get_host_fabric_name,
	.show_host_fabric_name = 1,
	.get_host_port_state = unf_get_host_port_state,
	.show_host_port_state = 1,

	.dd_fcrport_size = sizeof(void *),
	.show_rport_supported_classes = 1,

	.get_starget_node_name = NULL,
	.show_starget_node_name = 1,
	.get_starget_port_name = NULL,
	.show_starget_port_name = 1,
	.get_starget_port_id = NULL,
	.show_starget_port_id = 1,

	.set_rport_dev_loss_tmo = unf_set_rport_loss_tmo,
	.show_rport_dev_loss_tmo = 0,

	.issue_fc_host_lip = NULL,
	.dev_loss_tmo_callbk = unf_dev_loss_timeout_callbk,
	.terminate_rport_io = NULL,
	.get_fc_host_stats = NULL,

	.vport_create = unf_scsi_create_vport,
	.vport_disable = NULL,
	.vport_delete = unf_scsi_delete_vport,
	.bsg_request = NULL,
	.bsg_timeout = NULL,
};

struct fc_function_template function_template_v = {
	.show_host_node_name = 1,
	.show_host_port_name = 1,
	.show_host_supported_classes = 1,
	.show_host_supported_speeds = 1,

	.get_host_port_id = unf_get_host_port_id,
	.show_host_port_id = 1,
	.get_host_speed = unf_get_host_speed,
	.show_host_speed = 1,
	.get_host_port_type = unf_get_host_port_type,
	.show_host_port_type = 1,
	.get_host_symbolic_name = unf_get_symbolic_name,
	.show_host_symbolic_name = 1,
	.set_host_system_hostname = NULL,
	.show_host_system_hostname = 1,
	.get_host_fabric_name = unf_get_host_fabric_name,
	.show_host_fabric_name = 1,
	.get_host_port_state = unf_get_host_port_state,
	.show_host_port_state = 1,

	.dd_fcrport_size = sizeof(void *),
	.show_rport_supported_classes = 1,

	.get_starget_node_name = NULL,
	.show_starget_node_name = 1,
	.get_starget_port_name = NULL,
	.show_starget_port_name = 1,
	.get_starget_port_id = NULL,
	.show_starget_port_id = 1,

	.set_rport_dev_loss_tmo = unf_set_rport_loss_tmo,
	.show_rport_dev_loss_tmo = 0,

	.issue_fc_host_lip = NULL,
	.dev_loss_tmo_callbk = unf_dev_loss_timeout_callbk,
	.terminate_rport_io = NULL,
	.get_fc_host_stats = NULL,

	.vport_create = NULL,
	.vport_disable = NULL,
	.vport_delete = NULL,
	.bsg_request = NULL,
	.bsg_timeout = NULL,
};

struct scsi_host_template scsi_host_template = {
	.module = THIS_MODULE,
	.name = "SPFC",

	.queuecommand = unf_scsi_queue_cmd,
	.eh_timed_out = fc_eh_timed_out,
	.eh_abort_handler = unf_scsi_abort_scsi_cmnd,
	.eh_device_reset_handler = unf_scsi_device_reset_handler,

	.eh_target_reset_handler = unf_scsi_target_reset_handler,
	.eh_bus_reset_handler = unf_scsi_bus_reset_handler,
	.eh_host_reset_handler = NULL,

	.slave_configure = unf_scsi_slave_configure,
	.slave_alloc = unf_scsi_slave_alloc,
	.slave_destroy = unf_scsi_destroy_slave,

	.scan_finished = unf_scsi_scan_finished,
	.scan_start = unf_scsi_scan_start,

	.this_id = -1, /* this_id: -1 */
	.cmd_per_lun = UNF_CMD_PER_LUN,
	.shost_attrs = NULL,
	.sg_tablesize = SG_ALL,
	.max_sectors = UNF_MAX_SECTORS,
	.supported_mode = MODE_INITIATOR,
};

void unf_unmap_prot_sgl(struct scsi_cmnd *cmnd)
{
	struct device *dev = NULL;

	if ((scsi_get_prot_op(cmnd) != SCSI_PROT_NORMAL) && spfc_dif_enable &&
	    (scsi_prot_sg_count(cmnd))) {
		dev = cmnd->device->host->dma_dev;
		dma_unmap_sg(dev, scsi_prot_sglist(cmnd),
			     (int)scsi_prot_sg_count(cmnd),
			     cmnd->sc_data_direction);

		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_INFO,
			     "scsi done cmd:%p op:%u, difsglcount:%u", cmnd,
			     scsi_get_prot_op(cmnd), scsi_prot_sg_count(cmnd));
	}
}

void unf_scsi_done(struct unf_scsi_cmnd *scsi_cmd)
{
	struct scsi_cmnd *cmd = NULL;

	cmd = (struct scsi_cmnd *)scsi_cmd->upper_cmnd;
	FC_CHECK_RETURN_VOID(scsi_cmd);
	FC_CHECK_RETURN_VOID(cmd);
	FC_CHECK_RETURN_VOID(cmd->scsi_done);
	scsi_set_resid(cmd, (int)scsi_cmd->resid);

	cmd->result = scsi_cmd->result;
	scsi_dma_unmap(cmd);
	unf_unmap_prot_sgl(cmd);
	return cmd->scsi_done(cmd);
}

static void unf_get_protect_op(struct scsi_cmnd *cmd,
			       struct unf_dif_control_info *dif_control_info)
{
	switch (scsi_get_prot_op(cmd)) {
	/* OS-HBA: Unprotected, HBA-Target: Protected */
	case SCSI_PROT_READ_STRIP:
		dif_control_info->protect_opcode |= UNF_DIF_ACTION_VERIFY_AND_DELETE;
		break;
	case SCSI_PROT_WRITE_INSERT:
		dif_control_info->protect_opcode |= UNF_DIF_ACTION_INSERT;
		break;

	/* OS-HBA: Protected, HBA-Target: Unprotected */
	case SCSI_PROT_READ_INSERT:
		dif_control_info->protect_opcode |= UNF_DIF_ACTION_INSERT;
		break;
	case SCSI_PROT_WRITE_STRIP:
		dif_control_info->protect_opcode |= UNF_DIF_ACTION_VERIFY_AND_DELETE;
		break;

	/* OS-HBA: Protected, HBA-Target: Protected */
	case SCSI_PROT_READ_PASS:
	case SCSI_PROT_WRITE_PASS:
		dif_control_info->protect_opcode |= UNF_DIF_ACTION_VERIFY_AND_FORWARD;
		break;

	default:
		dif_control_info->protect_opcode |= UNF_DIF_ACTION_VERIFY_AND_FORWARD;
		break;
	}
}

int unf_get_protect_mode(struct unf_lport *lport, struct scsi_cmnd *scsi_cmd,
			 struct unf_scsi_cmnd *unf_scsi_cmd)
{
	struct scsi_cmnd *cmd = NULL;
	int dif_seg_cnt = 0;
	struct unf_dif_control_info *dif_control_info = NULL;

	cmd = scsi_cmd;
	dif_control_info = &unf_scsi_cmd->dif_control;

	unf_get_protect_op(cmd, dif_control_info);

	if (dif_sgl_mode)
		dif_control_info->flags |= UNF_DIF_DOUBLE_SGL;
	dif_control_info->flags |= ((cmd->device->sector_size) == SECTOR_SIZE_4096)
				    ? UNF_DIF_SECTSIZE_4KB : UNF_DIF_SECTSIZE_512;
	dif_control_info->protect_opcode |= UNF_VERIFY_CRC_MASK | UNF_VERIFY_LBA_MASK;
	dif_control_info->dif_sge_count = scsi_prot_sg_count(cmd);
	dif_control_info->dif_sgl = scsi_prot_sglist(cmd);
	dif_control_info->start_lba = cpu_to_le32(((uint32_t)(0xffffffff & scsi_get_lba(cmd))));

	if (cmd->device->sector_size == SECTOR_SIZE_4096)
		dif_control_info->start_lba = dif_control_info->start_lba >> UNF_SHIFT_3;

	if (scsi_prot_sg_count(cmd)) {
		dif_seg_cnt = dma_map_sg(&lport->low_level_func.dev->dev, scsi_prot_sglist(cmd),
					 (int)scsi_prot_sg_count(cmd), cmd->sc_data_direction);
		if (unlikely(!dif_seg_cnt)) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
				     "[warn]Port(0x%x) cmd:%p map dif sgl err",
				     lport->port_id, cmd);
			return UNF_RETURN_ERROR;
		}
	}

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_INFO,
		     "build scsi cmd:%p op:%u,difsglcount:%u,difsegcnt:%u", cmd,
		     scsi_get_prot_op(cmd), scsi_prot_sg_count(cmd),
		     dif_seg_cnt);
	return RETURN_OK;
}

static u32 unf_get_rport_qos_level(struct scsi_cmnd *cmd, u32 scsi_id,
				   struct unf_rport_scsi_id_image *scsi_image_table)
{
	enum unf_rport_qos_level level = 0;

	if (!scsi_image_table->wwn_rport_info_table[scsi_id].lun_qos_level ||
	    cmd->device->lun >= UNF_MAX_LUN_PER_TARGET) {
		level = 0;
	} else {
		level = (scsi_image_table->wwn_rport_info_table[scsi_id]
			     .lun_qos_level[cmd->device->lun]);
	}
	return level;
}

u32 unf_get_frame_entry_buf(void *up_cmnd, void *driver_sgl, void **upper_sgl,
			    u32 *port_id, u32 *index, char **buf, u32 *buf_len)
{
#define SPFC_MAX_DMA_LENGTH (0x20000 - 1)
	struct scatterlist *scsi_sgl = *upper_sgl;

	if (unlikely(!scsi_sgl)) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_ERR,
			     "[err]Command(0x%p) can not get SGL.", up_cmnd);
		return RETURN_ERROR;
	}
	*buf = (char *)sg_dma_address(scsi_sgl);
	*buf_len = sg_dma_len(scsi_sgl);
	*upper_sgl = (void *)sg_next(scsi_sgl);
	if (unlikely((*buf_len > SPFC_MAX_DMA_LENGTH) || (*buf_len == 0))) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_ERR,
			     "[err]Command(0x%p) dmalen:0x%x is not support.",
			     up_cmnd, *buf_len);
		return RETURN_ERROR;
	}

	return RETURN_OK;
}

static void unf_init_scsi_cmnd(struct Scsi_Host *host, struct scsi_cmnd *cmd,
			       struct unf_scsi_cmnd *scsi_cmnd,
			       struct unf_rport_scsi_id_image *scsi_image_table,
			       int datasegcnt)
{
	static atomic64_t count;
	enum unf_rport_qos_level level = 0;
	u32 scsi_id = 0;

	scsi_id = (u32)((u64)cmd->device->hostdata);
	level = unf_get_rport_qos_level(cmd, scsi_id, scsi_image_table);
	scsi_cmnd->scsi_host_id = host->host_no; /* save host_no to scsi_cmnd->scsi_host_id */
	scsi_cmnd->scsi_id = scsi_id;
	scsi_cmnd->raw_lun_id = ((u64)cmd->device->lun << 16) & UNF_LUN_ID_MASK;
	scsi_cmnd->data_direction = cmd->sc_data_direction;
	scsi_cmnd->under_flow = cmd->underflow;
	scsi_cmnd->cmnd_len = cmd->cmd_len;
	scsi_cmnd->pcmnd = cmd->cmnd;
	scsi_cmnd->transfer_len = cpu_to_le32((uint32_t)scsi_bufflen(cmd));
	scsi_cmnd->sense_buflen = UNF_SCSI_SENSE_BUFFERSIZE;
	scsi_cmnd->sense_buf = cmd->sense_buffer;
	scsi_cmnd->time_out = 0;
	scsi_cmnd->upper_cmnd = cmd;
	scsi_cmnd->drv_private = (void *)(*(u64 *)shost_priv(host));
	scsi_cmnd->entry_count = datasegcnt;
	scsi_cmnd->sgl = scsi_sglist(cmd);
	scsi_cmnd->unf_ini_get_sgl_entry = unf_get_frame_entry_buf;
	scsi_cmnd->done = unf_scsi_done;
	scsi_cmnd->lun_id = (u8 *)&scsi_cmnd->raw_lun_id;
	scsi_cmnd->err_code_table_cout = ini_err_code_table_cnt1;
	scsi_cmnd->err_code_table = ini_error_code_table1;
	scsi_cmnd->world_id = INVALID_WORLD_ID;
	scsi_cmnd->cmnd_sn = atomic64_inc_return(&count);
	scsi_cmnd->qos_level = level;
	if (unlikely(scsi_cmnd->cmnd_sn == 0))
		scsi_cmnd->cmnd_sn = atomic64_inc_return(&count);
}

static void unf_io_error_done(struct scsi_cmnd *cmd,
			      struct unf_rport_scsi_id_image *scsi_image_table,
			      u32 scsi_id, u32 result)
{
	cmd->result = (int)(result << UNF_SHIFT_16);
	cmd->scsi_done(cmd);
	if (scsi_image_table)
		UNF_IO_RESULT_CNT(scsi_image_table, scsi_id, result);
}

static bool unf_scan_device_cmd(struct scsi_cmnd *cmd)
{
	return ((cmd->cmnd[0] == INQUIRY) || (cmd->cmnd[0] == REPORT_LUNS));
}

static int unf_scsi_queue_cmd(struct Scsi_Host *phost, struct scsi_cmnd *pcmd)
{
	struct Scsi_Host *host = NULL;
	struct scsi_cmnd *cmd = NULL;
	struct unf_scsi_cmnd scsi_cmd = {0};
	u32 scsi_id = 0;
	u32 scsi_state = 0;
	int ret = SCSI_MLQUEUE_HOST_BUSY;
	struct unf_lport *unf_lport = NULL;
	struct fc_rport *rport = NULL;
	struct unf_rport_scsi_id_image *scsi_image_table = NULL;
	struct unf_rport *unf_rport = NULL;
	u32 cmnd_result = 0;
	u32 rport_state_err = 0;
	bool scan_device_cmd = false;
	int datasegcnt = 0;

	host = phost;
	cmd = pcmd;
	FC_CHECK_RETURN_VALUE(host, RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(cmd, RETURN_ERROR);

	/* Get L_Port from scsi_cmd */
	unf_lport = (struct unf_lport *)host->hostdata[0];
	if (unlikely(!unf_lport)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Check l_port failed, cmd(%p)", cmd);
		unf_io_error_done(cmd, scsi_image_table, scsi_id, DID_NO_CONNECT);
		return 0;
	}

	/* Check device/session local state by device_id */
	scsi_id = (u32)((u64)cmd->device->hostdata);
	if (unlikely(scsi_id >= UNF_MAX_SCSI_ID)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) scsi_id(0x%x) is max than %d",
			     unf_lport->port_id, scsi_id, UNF_MAX_SCSI_ID);
		unf_io_error_done(cmd, scsi_image_table, scsi_id, DID_NO_CONNECT);
		return 0;
	}

	scsi_image_table = &unf_lport->rport_scsi_table;
	UNF_SCSI_CMD_CNT(scsi_image_table, scsi_id, cmd->cmnd[0]);

	/* Get scsi r_port */
	rport = starget_to_rport(scsi_target(cmd->device));
	if (unlikely(!rport)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) cmd(%p) to get scsi rport failed",
			     unf_lport->port_id, cmd);
		unf_io_error_done(cmd, scsi_image_table, scsi_id, DID_NO_CONNECT);
		return 0;
	}

	if (unlikely(!scsi_image_table->wwn_rport_info_table)) {
		FC_DRV_PRINT(UNF_LOG_ABNORMAL, UNF_WARN,
			     "[warn]LPort porid(0x%x) WwnRportInfoTable NULL",
			     unf_lport->port_id);
		unf_io_error_done(cmd, scsi_image_table, scsi_id, DID_NO_CONNECT);
		return 0;
	}

	if (unlikely(unf_lport->port_removing)) {
		FC_DRV_PRINT(UNF_LOG_ABNORMAL, UNF_WARN,
			     "[warn]Port(0x%x) scsi_id(0x%x) rport(0x%p) target_id(0x%x) cmd(0x%p) unf_lport removing",
			     unf_lport->port_id, scsi_id, rport, rport->scsi_target_id, cmd);
		unf_io_error_done(cmd, scsi_image_table, scsi_id, DID_NO_CONNECT);
		return 0;
	}

	scsi_state = atomic_read(&scsi_image_table->wwn_rport_info_table[scsi_id].scsi_state);
	if (unlikely(scsi_state != UNF_SCSI_ST_ONLINE)) {
		if (scsi_state == UNF_SCSI_ST_OFFLINE) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
				     "[warn]Port(0x%x) scsi_state(0x%x) scsi_id(0x%x) rport(0x%p) target_id(0x%x) cmd(0x%p), target is busy",
				     unf_lport->port_id, scsi_state, scsi_id, rport,
				     rport->scsi_target_id, cmd);

			scan_device_cmd = unf_scan_device_cmd(cmd);
			/* report lun or inquiry cmd, if send failed, do not
			 * retry, prevent
			 * the scan_mutex in scsi host locked up by eachother
			 */
			if (scan_device_cmd) {
				FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
					     "[warn]Port(0x%x) host(0x%x) scsi_id(0x%x) lun(0x%llx) cmd(0x%x) DID_NO_CONNECT",
					     unf_lport->port_id, host->host_no, scsi_id,
					     (u64)cmd->device->lun, cmd->cmnd[0]);
				unf_io_error_done(cmd, scsi_image_table, scsi_id, DID_NO_CONNECT);
				return 0;
			}

			if (likely(scsi_image_table->wwn_rport_info_table)) {
				if (likely(scsi_image_table->wwn_rport_info_table[scsi_id]
					   .dfx_counter)) {
					atomic64_inc(&(scsi_image_table
						->wwn_rport_info_table[scsi_id]
						.dfx_counter->target_busy));
				}
			}

			/* Target busy: need scsi retry */
			return SCSI_MLQUEUE_TARGET_BUSY;
		}
		/* timeout(DEAD): scsi_done & return 0 & I/O error */
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) scsi_id(0x%x) rport(0x%p) target_id(0x%x) cmd(0x%p), target is loss timeout",
			     unf_lport->port_id, scsi_id, rport,
			     rport->scsi_target_id, cmd);
		unf_io_error_done(cmd, scsi_image_table, scsi_id, DID_NO_CONNECT);
		return 0;
	}

	if (scsi_sg_count(cmd)) {
		datasegcnt = dma_map_sg(&unf_lport->low_level_func.dev->dev, scsi_sglist(cmd),
					(int)scsi_sg_count(cmd), cmd->sc_data_direction);
		if (unlikely(!datasegcnt)) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
				     "[warn]Port(0x%x) scsi_id(0x%x) rport(0x%p) target_id(0x%x) cmd(0x%p), dma map sg err",
				     unf_lport->port_id, scsi_id, rport,
				     rport->scsi_target_id, cmd);
			unf_io_error_done(cmd, scsi_image_table, scsi_id, DID_BUS_BUSY);
			return SCSI_MLQUEUE_HOST_BUSY;
		}
	}

	/* Construct local SCSI CMND info */
	unf_init_scsi_cmnd(host, cmd, &scsi_cmd, scsi_image_table, datasegcnt);

	if ((scsi_get_prot_op(cmd) != SCSI_PROT_NORMAL) && spfc_dif_enable) {
		ret = unf_get_protect_mode(unf_lport, cmd, &scsi_cmd);
		if (ret != RETURN_OK) {
			unf_io_error_done(cmd, scsi_image_table, scsi_id, DID_BUS_BUSY);
			scsi_dma_unmap(cmd);
			return SCSI_MLQUEUE_HOST_BUSY;
		}
	}

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
		     "[info]Port(0x%x) host(0x%x) scsi_id(0x%x) lun(0x%llx) transfer length(0x%x) cmd_len(0x%x) direction(0x%x) cmd(0x%x) under_flow(0x%x) protect_opcode is (0x%x) dif_sgl_mode is %d, sector size(%d)",
		     unf_lport->port_id, host->host_no, scsi_id, (u64)cmd->device->lun,
		     scsi_cmd.transfer_len, scsi_cmd.cmnd_len, cmd->sc_data_direction,
		     scsi_cmd.pcmnd[0], scsi_cmd.under_flow,
		     scsi_cmd.dif_control.protect_opcode, dif_sgl_mode,
		     (cmd->device->sector_size));

	/* Bind the Exchange address corresponding to scsi_cmd to
	 * scsi_cmd->host_scribble
	 */
	cmd->host_scribble = (unsigned char *)scsi_cmd.cmnd_sn;
	ret = unf_cm_queue_command(&scsi_cmd);
	if (ret != RETURN_OK) {
		unf_rport = unf_find_rport_by_scsi_id(unf_lport, ini_error_code_table1,
						      ini_err_code_table_cnt1,
						      scsi_id, &cmnd_result);
		rport_state_err = (!unf_rport) ||
		    (unf_rport->lport_ini_state != UNF_PORT_STATE_LINKUP) ||
		    (unf_rport->rp_state == UNF_RPORT_ST_CLOSING);
		scan_device_cmd = unf_scan_device_cmd(cmd);

		/* report lun or inquiry cmd if send failed, do not
		 * retry,prevent the scan_mutex in scsi host locked up by
		 * eachother
		 */
		if (rport_state_err && scan_device_cmd) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
				     "[warn]Port(0x%x) host(0x%x) scsi_id(0x%x) lun(0x%llx) cmd(0x%x) cmResult(0x%x) DID_NO_CONNECT",
				     unf_lport->port_id, host->host_no, scsi_id,
				     (u64)cmd->device->lun, cmd->cmnd[0],
				     cmnd_result);
			unf_io_error_done(cmd, scsi_image_table, scsi_id, DID_NO_CONNECT);
			scsi_dma_unmap(cmd);
			unf_unmap_prot_sgl(cmd);
			return 0;
		}

		/* Host busy: scsi need to retry */
		ret = SCSI_MLQUEUE_HOST_BUSY;
		if (likely(scsi_image_table->wwn_rport_info_table)) {
			if (likely(scsi_image_table->wwn_rport_info_table[scsi_id].dfx_counter)) {
				atomic64_inc(&(scsi_image_table->wwn_rport_info_table[scsi_id]
					     .dfx_counter->host_busy));
			}
		}
		scsi_dma_unmap(cmd);
		unf_unmap_prot_sgl(cmd);
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Port(0x%x) return(0x%x) to process INI IO falid",
			     unf_lport->port_id, ret);
	}
	return ret;
}

static void unf_init_abts_tmf_scsi_cmd(struct scsi_cmnd *cmnd,
				       struct unf_scsi_cmnd *scsi_cmd,
				       bool abort_cmd)
{
	struct Scsi_Host *scsi_host = NULL;

	scsi_host = cmnd->device->host;
	scsi_cmd->scsi_host_id = scsi_host->host_no;
	scsi_cmd->scsi_id = (u32)((u64)cmnd->device->hostdata);
	scsi_cmd->raw_lun_id = (u64)cmnd->device->lun;
	scsi_cmd->upper_cmnd = cmnd;
	scsi_cmd->drv_private = (void *)(*(u64 *)shost_priv(scsi_host));
	scsi_cmd->cmnd_sn = (u64)(cmnd->host_scribble);
	scsi_cmd->lun_id = (u8 *)&scsi_cmd->raw_lun_id;
	if (abort_cmd) {
		scsi_cmd->done = unf_scsi_done;
		scsi_cmd->world_id = INVALID_WORLD_ID;
	}
}

int unf_scsi_abort_scsi_cmnd(struct scsi_cmnd *cmnd)
{
	/* SCSI ABORT Command --->>> FC ABTS */
	struct unf_scsi_cmnd scsi_cmd = {0};
	int ret = FAILED;
	struct unf_rport_scsi_id_image *scsi_image_table = NULL;
	struct unf_lport *unf_lport = NULL;
	u32 scsi_id = 0;
	u32 err_handle = 0;

	FC_CHECK_RETURN_VALUE(cmnd, FAILED);

	unf_lport = (struct unf_lport *)cmnd->device->host->hostdata[0];
	scsi_id = (u32)((u64)cmnd->device->hostdata);

	if (unf_is_lport_valid(unf_lport) == RETURN_OK) {
		scsi_image_table = &unf_lport->rport_scsi_table;
		err_handle = UNF_SCSI_ABORT_IO_TYPE;
		UNF_SCSI_ERROR_HANDLE_CNT(scsi_image_table, scsi_id, err_handle);
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			     "[abort]Port(0x%x) scsi_id(0x%x) lun_id(0x%x) cmnd_type(0x%x)",
			     unf_lport->port_id, scsi_id,
			     (u32)cmnd->device->lun, cmnd->cmnd[0]);
	} else {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Lport(%p) is moving or null", unf_lport);
		return UNF_SCSI_ABORT_FAIL;
	}

	/* Check local SCSI_ID validity */
	if (unlikely(scsi_id >= UNF_MAX_SCSI_ID)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]scsi_id(0x%x) is max than(0x%x)", scsi_id,
			     UNF_MAX_SCSI_ID);
		return UNF_SCSI_ABORT_FAIL;
	}

	/* Block scsi (check rport state -> whether offline or not) */
	ret = fc_block_scsi_eh(cmnd);
	if (unlikely(ret != 0)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Block scsi eh failed(0x%x)", ret);
		return ret;
	}

	unf_init_abts_tmf_scsi_cmd(cmnd, &scsi_cmd, true);
	/* Process scsi Abort cmnd */
	ret = unf_cm_eh_abort_handler(&scsi_cmd);
	if (ret == UNF_SCSI_ABORT_SUCCESS) {
		if (unf_is_lport_valid(unf_lport) == RETURN_OK) {
			scsi_image_table = &unf_lport->rport_scsi_table;
			err_handle = UNF_SCSI_ABORT_IO_TYPE;
			UNF_SCSI_ERROR_HANDLE_RESULT_CNT(scsi_image_table,
							 scsi_id, err_handle);
		}
	}

	return ret;
}

int unf_scsi_device_reset_handler(struct scsi_cmnd *cmnd)
{
	/* LUN reset */
	struct unf_scsi_cmnd scsi_cmd = {0};
	struct unf_rport_scsi_id_image *scsi_image_table = NULL;
	int ret = FAILED;
	struct unf_lport *unf_lport = NULL;
	u32 scsi_id = 0;
	u32 err_handle = 0;

	FC_CHECK_RETURN_VALUE(cmnd, FAILED);

	unf_lport = (struct unf_lport *)cmnd->device->host->hostdata[0];
	if (unf_is_lport_valid(unf_lport) == RETURN_OK) {
		scsi_image_table = &unf_lport->rport_scsi_table;
		err_handle = UNF_SCSI_DEVICE_RESET_TYPE;
		UNF_SCSI_ERROR_HANDLE_CNT(scsi_image_table, scsi_id, err_handle);

		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_KEVENT,
			     "[device_reset]Port(0x%x) scsi_id(0x%x) lun_id(0x%x) cmnd_type(0x%x)",
			     unf_lport->port_id, scsi_id, (u32)cmnd->device->lun, cmnd->cmnd[0]);
	} else {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR, "[err]Port is invalid");

		return FAILED;
	}

	/* Check local SCSI_ID validity */
	scsi_id = (u32)((u64)cmnd->device->hostdata);
	if (unlikely(scsi_id >= UNF_MAX_SCSI_ID)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]scsi_id(0x%x) is max than(0x%x)", scsi_id,
			     UNF_MAX_SCSI_ID);

		return FAILED;
	}

	/* Block scsi (check rport state -> whether offline or not) */
	ret = fc_block_scsi_eh(cmnd);
	if (unlikely(ret != 0)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Block scsi eh failed(0x%x)", ret);

		return ret;
	}

	unf_init_abts_tmf_scsi_cmd(cmnd, &scsi_cmd, false);
	/* Process scsi device/LUN reset cmnd */
	ret = unf_cm_eh_device_reset_handler(&scsi_cmd);
	if (ret == UNF_SCSI_ABORT_SUCCESS) {
		if (unf_is_lport_valid(unf_lport) == RETURN_OK) {
			scsi_image_table = &unf_lport->rport_scsi_table;
			err_handle = UNF_SCSI_DEVICE_RESET_TYPE;
			UNF_SCSI_ERROR_HANDLE_RESULT_CNT(scsi_image_table,
							 scsi_id, err_handle);
		}
	}

	return ret;
}

int unf_scsi_bus_reset_handler(struct scsi_cmnd *cmnd)
{
	/* BUS Reset */
	struct unf_scsi_cmnd scsi_cmd = {0};
	struct unf_lport *unf_lport = NULL;
	struct unf_rport_scsi_id_image *scsi_image_table = NULL;
	int ret = FAILED;
	u32 scsi_id = 0;
	u32 err_handle = 0;

	FC_CHECK_RETURN_VALUE(cmnd, FAILED);

	unf_lport = (struct unf_lport *)cmnd->device->host->hostdata[0];
	if (unlikely(!unf_lport)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port is null");

		return FAILED;
	}

	/* Check local SCSI_ID validity */
	scsi_id = (u32)((u64)cmnd->device->hostdata);
	if (unlikely(scsi_id >= UNF_MAX_SCSI_ID)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]scsi_id(0x%x) is max than(0x%x)", scsi_id,
			     UNF_MAX_SCSI_ID);

		return FAILED;
	}

	if (unf_is_lport_valid(unf_lport) == RETURN_OK) {
		scsi_image_table = &unf_lport->rport_scsi_table;
		err_handle = UNF_SCSI_BUS_RESET_TYPE;
		UNF_SCSI_ERROR_HANDLE_CNT(scsi_image_table, scsi_id, err_handle);

		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			     "[info][bus_reset]Port(0x%x) scsi_id(0x%x) lun_id(0x%x) cmnd_type(0x%x)",
			     unf_lport->port_id, scsi_id, (u32)cmnd->device->lun,
			     cmnd->cmnd[0]);
	}

	/* Block scsi (check rport state -> whether offline or not) */
	ret = fc_block_scsi_eh(cmnd);
	if (unlikely(ret != 0)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Block scsi eh failed(0x%x)", ret);

		return ret;
	}

	unf_init_abts_tmf_scsi_cmd(cmnd, &scsi_cmd, false);
	/* Process scsi BUS Reset cmnd */
	ret = unf_cm_bus_reset_handler(&scsi_cmd);
	if (ret == UNF_SCSI_ABORT_SUCCESS) {
		if (unf_is_lport_valid(unf_lport) == RETURN_OK) {
			scsi_image_table = &unf_lport->rport_scsi_table;
			err_handle = UNF_SCSI_BUS_RESET_TYPE;
			UNF_SCSI_ERROR_HANDLE_RESULT_CNT(scsi_image_table, scsi_id, err_handle);
		}
	}

	return ret;
}

int unf_scsi_target_reset_handler(struct scsi_cmnd *cmnd)
{
	/* Session reset/delete */
	struct unf_scsi_cmnd scsi_cmd = {0};
	struct unf_rport_scsi_id_image *scsi_image_table = NULL;
	int ret = FAILED;
	struct unf_lport *unf_lport = NULL;
	u32 scsi_id = 0;
	u32 err_handle = 0;

	FC_CHECK_RETURN_VALUE(cmnd, RETURN_ERROR);

	unf_lport = (struct unf_lport *)cmnd->device->host->hostdata[0];
	if (unlikely(!unf_lport)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port is null");

		return FAILED;
	}

	/* Check local SCSI_ID validity */
	scsi_id = (u32)((u64)cmnd->device->hostdata);
	if (unlikely(scsi_id >= UNF_MAX_SCSI_ID)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]scsi_id(0x%x) is max than(0x%x)", scsi_id, UNF_MAX_SCSI_ID);

		return FAILED;
	}

	if (unf_is_lport_valid(unf_lport) == RETURN_OK) {
		scsi_image_table = &unf_lport->rport_scsi_table;
		err_handle = UNF_SCSI_TARGET_RESET_TYPE;
		UNF_SCSI_ERROR_HANDLE_CNT(scsi_image_table, scsi_id, err_handle);

		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_KEVENT,
			     "[target_reset]Port(0x%x) scsi_id(0x%x) lun_id(0x%x) cmnd_type(0x%x)",
			     unf_lport->port_id, scsi_id, (u32)cmnd->device->lun, cmnd->cmnd[0]);
	}

	/* Block scsi (check rport state -> whether offline or not) */
	ret = fc_block_scsi_eh(cmnd);
	if (unlikely(ret != 0)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Block scsi eh failed(0x%x)", ret);

		return ret;
	}

	unf_init_abts_tmf_scsi_cmd(cmnd, &scsi_cmd, false);
	/* Process scsi Target/Session reset/delete cmnd */
	ret = unf_cm_target_reset_handler(&scsi_cmd);
	if (ret == UNF_SCSI_ABORT_SUCCESS) {
		if (unf_is_lport_valid(unf_lport) == RETURN_OK) {
			scsi_image_table = &unf_lport->rport_scsi_table;
			err_handle = UNF_SCSI_TARGET_RESET_TYPE;
			UNF_SCSI_ERROR_HANDLE_RESULT_CNT(scsi_image_table, scsi_id, err_handle);
		}
	}

	return ret;
}

static int unf_scsi_slave_alloc(struct scsi_device *sdev)
{
	struct fc_rport *rport = NULL;
	u32 scsi_id = 0;
	struct unf_lport *unf_lport = NULL;
	struct Scsi_Host *host = NULL;
	struct unf_rport_scsi_id_image *scsi_image_table = NULL;

	/* About device */
	if (unlikely(!sdev)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]SDev is null");
		return -ENXIO;
	}

	/* About scsi rport */
	rport = starget_to_rport(scsi_target(sdev));
	if (unlikely(!rport || fc_remote_port_chkready(rport))) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR, "[err]SCSI rport is null");

		if (rport) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
				     "[err]SCSI rport is not ready(0x%x)",
				     fc_remote_port_chkready(rport));
		}

		return -ENXIO;
	}

	/* About host */
	host = rport_to_shost(rport);
	if (unlikely(!host)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR, "[err]Host is null");

		return -ENXIO;
	}

	/* About Local Port */
	unf_lport = (struct unf_lport *)host->hostdata[0];
	if (unf_is_lport_valid(unf_lport) != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR, "[err]Port is invalid");

		return -ENXIO;
	}

	/* About Local SCSI_ID */
	scsi_id =
	    *(u32 *)rport->dd_data;
	if (unlikely(scsi_id >= UNF_MAX_SCSI_ID)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]scsi_id(0x%x) is max than(0x%x)", scsi_id, UNF_MAX_SCSI_ID);

		return -ENXIO;
	}

	scsi_image_table = &unf_lport->rport_scsi_table;
	if (scsi_image_table->wwn_rport_info_table[scsi_id].dfx_counter) {
		atomic_inc(&scsi_image_table->wwn_rport_info_table[scsi_id]
			   .dfx_counter->device_alloc);
	}
	atomic_inc(&unf_lport->device_alloc);
	sdev->hostdata = (void *)(u64)scsi_id;

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_KEVENT,
		     "[event]Port(0x%x) use scsi_id(%u) to alloc device[%u:%u:%u:%u]",
		     unf_lport->port_id, scsi_id, host->host_no, sdev->channel, sdev->id,
		     (u32)sdev->lun);

	return 0;
}

static void unf_scsi_destroy_slave(struct scsi_device *sdev)
{
	/*
	 * NOTE: about sdev->hostdata
	 * --->>> pointing to local SCSI_ID
	 * 1. Assignment during slave allocation
	 * 2. Released when callback for slave destroy
	 * 3. Used during: Queue_CMND, Abort CMND, Device Reset, Target Reset &
	 * Bus Reset
	 */
	struct fc_rport *rport = NULL;
	u32 scsi_id = 0;
	struct unf_lport *unf_lport = NULL;
	struct Scsi_Host *host = NULL;
	struct unf_rport_scsi_id_image *scsi_image_table = NULL;

	/* About scsi device */
	if (unlikely(!sdev)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]SDev is null");

		return;
	}

	/* About scsi rport */
	rport = starget_to_rport(scsi_target(sdev));
	if (unlikely(!rport)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]SCSI rport is null or remote port is not ready");
		return;
	}

	/* About host */
	host = rport_to_shost(rport);
	if (unlikely(!host)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR, "[err]Host is null");

		return;
	}

	/* About L_Port */
	unf_lport = (struct unf_lport *)host->hostdata[0];
	if (unf_is_lport_valid(unf_lport) == RETURN_OK) {
		scsi_image_table = &unf_lport->rport_scsi_table;
		atomic_inc(&unf_lport->device_destroy);

		scsi_id = (u32)((u64)sdev->hostdata);
		if (scsi_id < UNF_MAX_SCSI_ID && scsi_image_table->wwn_rport_info_table) {
			if (scsi_image_table->wwn_rport_info_table[scsi_id].dfx_counter) {
				atomic_inc(&scsi_image_table->wwn_rport_info_table[scsi_id]
					   .dfx_counter->device_destroy);
			}

			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_KEVENT,
				     "[event]Port(0x%x) with scsi_id(%u) to destroy slave device[%u:%u:%u:%u]",
				     unf_lport->port_id, scsi_id, host->host_no,
				     sdev->channel, sdev->id, (u32)sdev->lun);
		} else {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
				     "[err]Port(0x%x) scsi_id(%u) is invalid and destroy device[%u:%u:%u:%u]",
				     unf_lport->port_id, scsi_id, host->host_no,
				     sdev->channel, sdev->id, (u32)sdev->lun);
		}
	} else {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(%p) is invalid", unf_lport);
	}

	sdev->hostdata = NULL;
}

static int unf_scsi_slave_configure(struct scsi_device *sdev)
{
#define UNF_SCSI_DEV_DEPTH 32
	blk_queue_update_dma_alignment(sdev->request_queue, 0x7);

	scsi_change_queue_depth(sdev, UNF_SCSI_DEV_DEPTH);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
		     "[event]Enter slave configure, set depth is %d, sdev->tagged_supported is (%d)",
		     UNF_SCSI_DEV_DEPTH, sdev->tagged_supported);

	return 0;
}

static int unf_scsi_scan_finished(struct Scsi_Host *shost, unsigned long time)
{
	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[event]Scan finished");

	return 1;
}

static void unf_scsi_scan_start(struct Scsi_Host *shost)
{
	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[event]Start scsi scan...");
}

void unf_host_init_attr_setting(struct Scsi_Host *scsi_host)
{
	struct unf_lport *unf_lport = NULL;
	u32 speed = FC_PORTSPEED_UNKNOWN;

	unf_lport = (struct unf_lport *)scsi_host->hostdata[0];
	fc_host_supported_classes(scsi_host) = FC_COS_CLASS3;
	fc_host_dev_loss_tmo(scsi_host) = (u32)unf_get_link_lose_tmo(unf_lport);
	fc_host_node_name(scsi_host) = unf_lport->node_name;
	fc_host_port_name(scsi_host) = unf_lport->port_name;

	fc_host_max_npiv_vports(scsi_host) = (u16)((unf_lport == unf_lport->root_lport) ?
						    unf_lport->low_level_func.support_max_npiv_num
						    : 0);
	fc_host_npiv_vports_inuse(scsi_host) = 0;
	fc_host_next_vport_number(scsi_host) = 0;

	/* About speed mode */
	if (unf_lport->low_level_func.fc_ser_max_speed == UNF_PORT_SPEED_32_G &&
	    unf_lport->card_type == UNF_FC_SERVER_BOARD_32_G) {
		speed = FC_PORTSPEED_32GBIT | FC_PORTSPEED_16GBIT | FC_PORTSPEED_8GBIT;
	} else if (unf_lport->low_level_func.fc_ser_max_speed == UNF_PORT_SPEED_16_G &&
		   unf_lport->card_type == UNF_FC_SERVER_BOARD_16_G) {
		speed = FC_PORTSPEED_16GBIT | FC_PORTSPEED_8GBIT | FC_PORTSPEED_4GBIT;
	} else if (unf_lport->low_level_func.fc_ser_max_speed == UNF_PORT_SPEED_8_G &&
		   unf_lport->card_type == UNF_FC_SERVER_BOARD_8_G) {
		speed = FC_PORTSPEED_8GBIT | FC_PORTSPEED_4GBIT | FC_PORTSPEED_2GBIT;
	}

	fc_host_supported_speeds(scsi_host) = speed;
}

int unf_alloc_scsi_host(struct Scsi_Host **unf_scsi_host,
			struct unf_host_param *host_param)
{
	int ret = RETURN_ERROR;
	struct Scsi_Host *scsi_host = NULL;
	struct unf_lport *unf_lport = NULL;

	FC_CHECK_RETURN_VALUE(unf_scsi_host, RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(host_param, RETURN_ERROR);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR, "[event]Alloc scsi host...");

	/* Check L_Port validity */
	unf_lport = (struct unf_lport *)(host_param->lport);
	if (unlikely(!unf_lport)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port is NULL and return directly");

		return RETURN_ERROR;
	}

	scsi_host_template.can_queue = host_param->can_queue;
	scsi_host_template.cmd_per_lun = host_param->cmnd_per_lun;
	scsi_host_template.sg_tablesize = host_param->sg_table_size;
	scsi_host_template.max_sectors = host_param->max_sectors;

	/* Alloc scsi host */
	scsi_host = scsi_host_alloc(&scsi_host_template, sizeof(u64));
	if (unlikely(!scsi_host)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR, "[err]Register scsi host failed");

		return RETURN_ERROR;
	}

	scsi_host->max_channel = host_param->max_channel;
	scsi_host->max_lun = host_param->max_lun;
	scsi_host->max_cmd_len = host_param->max_cmnd_len;
	scsi_host->unchecked_isa_dma = 0;
	scsi_host->hostdata[0] = (unsigned long)(uintptr_t)unf_lport; /* save lport to scsi */
	scsi_host->unique_id = scsi_host->host_no;
	scsi_host->max_id = host_param->max_id;
	scsi_host->transportt = (unf_lport == unf_lport->root_lport)
				    ? scsi_transport_template
				    : scsi_transport_template_v;

	/* register DIF/DIX protection */
	if (spfc_dif_enable) {
		/* Enable DIF and DIX function */
		scsi_host_set_prot(scsi_host, spfc_dif_type);

		spfc_guard = SHOST_DIX_GUARD_CRC;
		/* Enable IP checksum algorithm in DIX */
		if (dix_flag)
			spfc_guard |= SHOST_DIX_GUARD_IP;
		scsi_host_set_guard(scsi_host, spfc_guard);
	}

	/* Add scsi host */
	ret = scsi_add_host(scsi_host, host_param->pdev);
	if (unlikely(ret)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Add scsi host failed with return value %d", ret);

		scsi_host_put(scsi_host);
		return RETURN_ERROR;
	}

	/* Set scsi host attribute */
	unf_host_init_attr_setting(scsi_host);
	*unf_scsi_host = scsi_host;

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[event]Alloc and add scsi host(0x%llx) succeed",
		     (u64)scsi_host);

	return RETURN_OK;
}

void unf_free_scsi_host(struct Scsi_Host *unf_scsi_host)
{
	struct Scsi_Host *scsi_host = NULL;

	scsi_host = unf_scsi_host;
	fc_remove_host(scsi_host);
	scsi_remove_host(scsi_host);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[event]Remove scsi host(%u) succeed", scsi_host->host_no);

	scsi_host_put(scsi_host);
}

u32 unf_register_ini_transport(void)
{
	/* Register INI Transport */
	scsi_transport_template = fc_attach_transport(&function_template);

	if (!scsi_transport_template) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Register FC transport to scsi failed");

		return RETURN_ERROR;
	}

	scsi_transport_template_v = fc_attach_transport(&function_template_v);
	if (!scsi_transport_template_v) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Register FC vport transport to scsi failed");

		fc_release_transport(scsi_transport_template);

		return RETURN_ERROR;
	}

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[event]Register FC transport to scsi succeed");

	return RETURN_OK;
}

void unf_unregister_ini_transport(void)
{
	fc_release_transport(scsi_transport_template);
	fc_release_transport(scsi_transport_template_v);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[event]Unregister FC transport succeed");
}

void unf_save_sense_data(void *scsi_cmd, const char *sense, int sens_len)
{
	struct scsi_cmnd *cmd = NULL;

	FC_CHECK_RETURN_VOID(scsi_cmd);
	FC_CHECK_RETURN_VOID(sense);

	cmd = (struct scsi_cmnd *)scsi_cmd;
	memcpy(cmd->sense_buffer, sense, sens_len);
}
