// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#include "spfc_chipitf.h"
#include "sphw_hw.h"
#include "sphw_crm.h"

#define SPFC_MBOX_TIME_SEC_MAX (60)

#define SPFC_LINK_UP_COUNT 1
#define SPFC_LINK_DOWN_COUNT 2
#define SPFC_FC_DELETE_CMND_COUNT 3

#define SPFC_MBX_MAX_TIMEOUT 10000

u32 spfc_get_chip_msg(void *hba, void *mac)
{
	struct spfc_hba_info *spfc_hba = NULL;
	struct unf_get_chip_info_argout *wwn = NULL;
	struct spfc_inmbox_get_chip_info get_chip_info;
	union spfc_outmbox_generic *get_chip_info_sts = NULL;
	u32 ret = UNF_RETURN_ERROR;

	FC_CHECK_RETURN_VALUE(hba, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(mac, UNF_RETURN_ERROR);

	spfc_hba = (struct spfc_hba_info *)hba;
	wwn = (struct unf_get_chip_info_argout *)mac;

	memset(&get_chip_info, 0, sizeof(struct spfc_inmbox_get_chip_info));

	get_chip_info_sts = kmalloc(sizeof(union spfc_outmbox_generic), GFP_ATOMIC);
	if (!get_chip_info_sts) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]malloc outmbox memory failed");
		return UNF_RETURN_ERROR;
	}
	memset(get_chip_info_sts, 0, sizeof(union spfc_outmbox_generic));

	get_chip_info.header.cmnd_type = SPFC_MBOX_GET_CHIP_INFO;
	get_chip_info.header.length =
	    SPFC_BYTES_TO_DW_NUM(sizeof(struct spfc_inmbox_get_chip_info));

	if (spfc_mb_send_and_wait_mbox(spfc_hba, &get_chip_info,
				       sizeof(struct spfc_inmbox_get_chip_info),
				       get_chip_info_sts) != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]spfc can't send and wait mailbox, command type: 0x%x.",
			     get_chip_info.header.cmnd_type);

		goto exit;
	}

	if (get_chip_info_sts->get_chip_info_sts.status != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Port(0x%x) mailbox status incorrect status(0x%x) .",
			     spfc_hba->port_cfg.port_id,
			     get_chip_info_sts->get_chip_info_sts.status);

		goto exit;
	}

	if (get_chip_info_sts->get_chip_info_sts.header.cmnd_type != SPFC_MBOX_GET_CHIP_INFO_STS) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "Port(0x%x) receive mailbox type incorrect type: 0x%x.",
			     spfc_hba->port_cfg.port_id,
			     get_chip_info_sts->get_chip_info_sts.header.cmnd_type);

		goto exit;
	}

	wwn->board_type = get_chip_info_sts->get_chip_info_sts.board_type;
	spfc_hba->card_info.card_type = get_chip_info_sts->get_chip_info_sts.board_type;
	wwn->wwnn = get_chip_info_sts->get_chip_info_sts.wwnn;
	wwn->wwpn = get_chip_info_sts->get_chip_info_sts.wwpn;

	ret = RETURN_OK;
exit:
	kfree(get_chip_info_sts);

	return ret;
}

u32 spfc_get_chip_capability(void *hwdev_handle,
			     struct spfc_chip_info *chip_info)
{
	struct spfc_inmbox_get_chip_info get_chip_info;
	union spfc_outmbox_generic *get_chip_info_sts = NULL;
	u16 out_size = 0;
	u32 ret = UNF_RETURN_ERROR;

	FC_CHECK_RETURN_VALUE(hwdev_handle, UNF_RETURN_ERROR);

	memset(&get_chip_info, 0, sizeof(struct spfc_inmbox_get_chip_info));

	get_chip_info_sts = kmalloc(sizeof(union spfc_outmbox_generic), GFP_ATOMIC);
	if (!get_chip_info_sts) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "malloc outmbox memory failed");
		return UNF_RETURN_ERROR;
	}
	memset(get_chip_info_sts, 0, sizeof(union spfc_outmbox_generic));

	get_chip_info.header.cmnd_type = SPFC_MBOX_GET_CHIP_INFO;
	get_chip_info.header.length =
	    SPFC_BYTES_TO_DW_NUM(sizeof(struct spfc_inmbox_get_chip_info));
	get_chip_info.header.port_id = (u8)sphw_global_func_id(hwdev_handle);
	out_size = sizeof(union spfc_outmbox_generic);

	if (sphw_msg_to_mgmt_sync(hwdev_handle, COMM_MOD_FC, SPFC_MBOX_GET_CHIP_INFO,
				  (void *)&get_chip_info.header,
				  sizeof(struct spfc_inmbox_get_chip_info),
				  (union spfc_outmbox_generic *)(get_chip_info_sts), &out_size,
				  (SPFC_MBX_MAX_TIMEOUT), SPHW_CHANNEL_FC) != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "spfc can't send and wait mailbox, command type: 0x%x.",
			     SPFC_MBOX_GET_CHIP_INFO);

		goto exit;
	}

	if (get_chip_info_sts->get_chip_info_sts.status != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Port mailbox status incorrect status(0x%x) .",
			     get_chip_info_sts->get_chip_info_sts.status);

		goto exit;
	}

	if (get_chip_info_sts->get_chip_info_sts.header.cmnd_type != SPFC_MBOX_GET_CHIP_INFO_STS) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Port receive mailbox type incorrect type: 0x%x.",
			     get_chip_info_sts->get_chip_info_sts.header.cmnd_type);

		goto exit;
	}

	chip_info->wwnn = get_chip_info_sts->get_chip_info_sts.wwnn;
	chip_info->wwpn = get_chip_info_sts->get_chip_info_sts.wwpn;

	ret = RETURN_OK;
exit:
	kfree(get_chip_info_sts);

	return ret;
}

u32 spfc_config_port_table(struct spfc_hba_info *hba)
{
	struct spfc_inmbox_config_api config_api;
	union spfc_outmbox_generic *out_mbox = NULL;
	u32 ret = UNF_RETURN_ERROR;

	FC_CHECK_RETURN_VALUE(hba, UNF_RETURN_ERROR);

	memset(&config_api, 0, sizeof(config_api));
	out_mbox = kmalloc(sizeof(union spfc_outmbox_generic), GFP_ATOMIC);
	if (!out_mbox) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]malloc outmbox memory failed");
		return UNF_RETURN_ERROR;
	}
	memset(out_mbox, 0, sizeof(union spfc_outmbox_generic));

	config_api.header.cmnd_type = SPFC_MBOX_CONFIG_API;
	config_api.header.length = SPFC_BYTES_TO_DW_NUM(sizeof(struct spfc_inmbox_config_api));

	config_api.op_code = UNDEFINEOPCODE;

	/* change switching top cmd of CM to the cmd that up recognize */
	/* if the cmd equals UNF_TOP_P2P_MASK sending in CM  means that it
	 * should be changed into P2P top, LL using SPFC_TOP_NON_LOOP_MASK
	 */
	if (((u8)(hba->port_topo_cfg)) == UNF_TOP_P2P_MASK) {
		config_api.topy_mode = 0x2;
	/* if the cmd equals UNF_TOP_LOOP_MASK sending in CM  means that it
	 *should be changed into loop top, LL using SPFC_TOP_LOOP_MASK
	 */
	} else if (((u8)(hba->port_topo_cfg)) == UNF_TOP_LOOP_MASK) {
		config_api.topy_mode = 0x1;
	/* if the cmd equals UNF_TOP_AUTO_MASK sending in CM  means that it
	 *should be changed into loop top, LL using SPFC_TOP_AUTO_MASK
	 */
	} else if (((u8)(hba->port_topo_cfg)) == UNF_TOP_AUTO_MASK) {
		config_api.topy_mode = 0x0;
	} else {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Port(0x%x) topo cmd is error, command type: 0x%x",
			     hba->port_cfg.port_id, (u8)(hba->port_topo_cfg));

		goto exit;
	}

	/* About speed */
	config_api.sfp_speed = (u8)(hba->port_speed_cfg);
	config_api.max_speed = (u8)(hba->max_support_speed);

	config_api.rx_6432g_bb_credit = SPFC_LOWLEVEL_DEFAULT_32G_BB_CREDIT;
	config_api.rx_16g_bb_credit = SPFC_LOWLEVEL_DEFAULT_16G_BB_CREDIT;
	config_api.rx_84g_bb_credit = SPFC_LOWLEVEL_DEFAULT_8G_BB_CREDIT;
	config_api.rdy_cnt_bf_fst_frm = SPFC_LOWLEVEL_DEFAULT_LOOP_BB_CREDIT;
	config_api.esch_32g_value = SPFC_LOWLEVEL_DEFAULT_32G_ESCH_VALUE;
	config_api.esch_16g_value = SPFC_LOWLEVEL_DEFAULT_16G_ESCH_VALUE;
	config_api.esch_8g_value = SPFC_LOWLEVEL_DEFAULT_8G_ESCH_VALUE;
	config_api.esch_4g_value = SPFC_LOWLEVEL_DEFAULT_8G_ESCH_VALUE;
	config_api.esch_64g_value = SPFC_LOWLEVEL_DEFAULT_8G_ESCH_VALUE;
	config_api.esch_bust_size = SPFC_LOWLEVEL_DEFAULT_ESCH_BUST_SIZE;

	/* default value:0xFF */
	config_api.hard_alpa = 0xFF;
	memcpy(config_api.port_name, hba->sys_port_name, UNF_WWN_LEN);

	/* if only for slave, the value is 1; if participate master choosing,
	 * the value is 0
	 */
	config_api.slave = hba->port_loop_role;

	/* 1:auto negotiate, 0:fixed mode negotiate */
	if (config_api.sfp_speed == 0)
		config_api.auto_sneg = 0x1;
	else
		config_api.auto_sneg = 0x0;

	if (spfc_mb_send_and_wait_mbox(hba, &config_api, sizeof(config_api),
				       out_mbox) != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[warn]Port(0x%x) SPFC can't send and wait mailbox, command type: 0x%x",
			     hba->port_cfg.port_id,
			     config_api.header.cmnd_type);

		goto exit;
	}

	if (out_mbox->config_api_sts.status != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_EQUIP_ATT, UNF_ERR,
			     "[err]Port(0x%x) receive mailbox type(0x%x) with status(0x%x) error",
			     hba->port_cfg.port_id,
			     out_mbox->config_api_sts.header.cmnd_type,
			     out_mbox->config_api_sts.status);

		goto exit;
	}

	if (out_mbox->config_api_sts.header.cmnd_type != SPFC_MBOX_CONFIG_API_STS) {
		FC_DRV_PRINT(UNF_LOG_EQUIP_ATT, UNF_ERR,
			     "[err]Port(0x%x) receive mailbox type(0x%x) error",
			     hba->port_cfg.port_id,
			     out_mbox->config_api_sts.header.cmnd_type);

		goto exit;
	}

	ret = RETURN_OK;
exit:
	kfree(out_mbox);

	return ret;
}

u32 spfc_port_switch(struct spfc_hba_info *hba, bool turn_on)
{
	struct spfc_inmbox_port_switch port_switch;
	union spfc_outmbox_generic *port_switch_sts = NULL;
	u32 ret = UNF_RETURN_ERROR;

	FC_CHECK_RETURN_VALUE(hba, UNF_RETURN_ERROR);

	memset(&port_switch, 0, sizeof(port_switch));

	port_switch_sts = kmalloc(sizeof(union spfc_outmbox_generic), GFP_ATOMIC);
	if (!port_switch_sts) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]malloc outmbox memory failed");
		return UNF_RETURN_ERROR;
	}
	memset(port_switch_sts, 0, sizeof(union spfc_outmbox_generic));

	port_switch.header.cmnd_type = SPFC_MBOX_PORT_SWITCH;
	port_switch.header.length = SPFC_BYTES_TO_DW_NUM(sizeof(struct spfc_inmbox_port_switch));
	port_switch.op_code = (u8)turn_on;

	if (spfc_mb_send_and_wait_mbox(hba, &port_switch, sizeof(port_switch),
				       (union spfc_outmbox_generic *)((void *)port_switch_sts)) !=
				       RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[warn]Port(0x%x) SPFC can't send and wait mailbox, command type(0x%x) opcode(0x%x)",
			     hba->port_cfg.port_id,
			     port_switch.header.cmnd_type, port_switch.op_code);

		goto exit;
	}

	if (port_switch_sts->port_switch_sts.status != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_EQUIP_ATT, UNF_ERR,
			     "[err]Port(0x%x) receive mailbox type(0x%x) status(0x%x) error",
			     hba->port_cfg.port_id,
			     port_switch_sts->port_switch_sts.header.cmnd_type,
			     port_switch_sts->port_switch_sts.status);

		goto exit;
	}

	if (port_switch_sts->port_switch_sts.header.cmnd_type != SPFC_MBOX_PORT_SWITCH_STS) {
		FC_DRV_PRINT(UNF_LOG_EQUIP_ATT, UNF_ERR,
			     "[err]Port(0x%x) receive mailbox type(0x%x) error",
			     hba->port_cfg.port_id,
			     port_switch_sts->port_switch_sts.header.cmnd_type);

		goto exit;
	}

	FC_DRV_PRINT(UNF_LOG_EQUIP_ATT, UNF_MAJOR,
		     "[event]Port(0x%x) switch succeed, turns to %s",
		     hba->port_cfg.port_id, (turn_on) ? "on" : "off");

	ret = RETURN_OK;
exit:
	kfree(port_switch_sts);

	return ret;
}

u32 spfc_config_login_api(struct spfc_hba_info *hba,
			  struct unf_port_login_parms *login_parms)
{
#define SPFC_LOOP_RDYNUM 8
	int iret = RETURN_OK;
	u32 ret = UNF_RETURN_ERROR;
	struct spfc_inmbox_config_login config_login;
	union spfc_outmbox_generic *cfg_login_sts = NULL;

	FC_CHECK_RETURN_VALUE(hba, UNF_RETURN_ERROR);

	memset(&config_login, 0, sizeof(config_login));
	cfg_login_sts = kmalloc(sizeof(union spfc_outmbox_generic), GFP_ATOMIC);
	if (!cfg_login_sts) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]malloc outmbox memory failed");
		return UNF_RETURN_ERROR;
	}
	memset(cfg_login_sts, 0, sizeof(union spfc_outmbox_generic));

	config_login.header.cmnd_type = SPFC_MBOX_CONFIG_LOGIN_API;
	config_login.header.length = SPFC_BYTES_TO_DW_NUM(sizeof(struct spfc_inmbox_config_login));
	config_login.header.port_id = hba->port_index;

	config_login.op_code = UNDEFINEOPCODE;

	config_login.tx_bb_credit = hba->remote_bb_credit;

	config_login.etov = hba->compared_edtov_val;
	config_login.rtov = hba->compared_ratov_val;

	config_login.rt_tov_tag = hba->remote_rttov_tag;
	config_login.ed_tov_tag = hba->remote_edtov_tag;
	config_login.bb_credit = hba->remote_bb_credit;
	config_login.bb_scn = SPFC_LSB(hba->compared_bb_scn);

	if (config_login.bb_scn) {
		config_login.lr_flag = (login_parms->els_cmnd_code == ELS_PLOGI) ? 0 : 1;
		ret = spfc_mb_send_and_wait_mbox(hba, &config_login, sizeof(config_login),
						 (union spfc_outmbox_generic *)cfg_login_sts);
		if (ret != RETURN_OK) {
			FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
				     "[err]Port(0x%x) SPFC can't send and wait mailbox, command type: 0x%x.",
				     hba->port_cfg.port_id, config_login.header.cmnd_type);

			goto exit;
		}

		if (cfg_login_sts->config_login_sts.header.cmnd_type !=
		    SPFC_MBOX_CONFIG_LOGIN_API_STS) {
			FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_INFO,
				     "Port(0x%x) Receive mailbox type incorrect. Type: 0x%x.",
				     hba->port_cfg.port_id,
				     cfg_login_sts->config_login_sts.header.cmnd_type);

			goto exit;
		}

		if (cfg_login_sts->config_login_sts.status != STATUS_OK) {
			FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
				     "Port(0x%x) Receive mailbox type(0x%x) status incorrect. Status: 0x%x.",
				     hba->port_cfg.port_id,
				     cfg_login_sts->config_login_sts.header.cmnd_type,
				     cfg_login_sts->config_login_sts.status);

			goto exit;
		}
	} else {
		iret = sphw_msg_to_mgmt_async(hba->dev_handle, COMM_MOD_FC,
					      SPFC_MBOX_CONFIG_LOGIN_API, &config_login,
					      sizeof(config_login), SPHW_CHANNEL_FC);

		if (iret != 0) {
			SPFC_MAILBOX_STAT(hba, SPFC_SEND_CONFIG_LOGINAPI_FAIL);
			FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
				     "[err]Port(0x%x) spfc can't send config login cmd to up,ret:%d.",
				     hba->port_cfg.port_id, iret);

			goto exit;
		}

		SPFC_MAILBOX_STAT(hba, SPFC_SEND_CONFIG_LOGINAPI);
	}

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "Port(0x%x) Topo(0x%x) Config login param to up: txbbcredit(0x%x), BB_SC_N(0x%x).",
		     hba->port_cfg.port_id, hba->active_topo,
		     config_login.tx_bb_credit, config_login.bb_scn);

	ret = RETURN_OK;
exit:
	kfree(cfg_login_sts);

	return ret;
}

u32 spfc_mb_send_and_wait_mbox(struct spfc_hba_info *hba, const void *in_mbox,
			       u16 in_size,
			       union spfc_outmbox_generic *out_mbox)
{
	void *handle = NULL;
	u16 out_size = 0;
	ulong time_out = 0;
	int ret = 0;
	struct spfc_mbox_header *header = NULL;

	FC_CHECK_RETURN_VALUE(hba, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(in_mbox, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(out_mbox, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(hba->dev_handle, UNF_RETURN_ERROR);
	header = (struct spfc_mbox_header *)in_mbox;
	out_size = sizeof(union spfc_outmbox_generic);
	handle = hba->dev_handle;
	header->port_id = (u8)sphw_global_func_id(handle);

	/* Wait for las mailbox completion: */
	time_out = wait_for_completion_timeout(&hba->mbox_complete,
					       (ulong)msecs_to_jiffies(SPFC_MBOX_TIME_SEC_MAX *
					       UNF_S_TO_MS));
	if (time_out == SPFC_ZERO) {
		FC_DRV_PRINT(UNF_LOG_EQUIP_ATT, UNF_ERR,
			     "[err]Port(0x%x) wait mailbox(0x%x) completion timeout: %d sec",
			     hba->port_cfg.port_id, header->cmnd_type,
			     SPFC_MBOX_TIME_SEC_MAX);

		return UNF_RETURN_ERROR;
	}

	/* Send Msg to uP Sync: timer 10s */
	ret = sphw_msg_to_mgmt_sync(handle, COMM_MOD_FC, header->cmnd_type,
				    (void *)in_mbox, in_size,
				    (union spfc_outmbox_generic *)out_mbox,
				    &out_size, (SPFC_MBX_MAX_TIMEOUT),
				    SPHW_CHANNEL_FC);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[warn]Port(0x%x) can not send mailbox(0x%x) with ret:%d",
			     hba->port_cfg.port_id, header->cmnd_type, ret);

		complete(&hba->mbox_complete);
		return UNF_RETURN_ERROR;
	}

	complete(&hba->mbox_complete);

	return RETURN_OK;
}

void spfc_initial_dynamic_info(struct spfc_hba_info *fc_port)
{
	struct spfc_hba_info *hba = fc_port;
	ulong flag = 0;

	FC_CHECK_RETURN_VOID(hba);

	spin_lock_irqsave(&hba->hba_lock, flag);
	hba->active_port_speed = UNF_PORT_SPEED_UNKNOWN;
	hba->active_topo = UNF_ACT_TOP_UNKNOWN;
	hba->phy_link = UNF_PORT_LINK_DOWN;
	hba->queue_set_stage = SPFC_QUEUE_SET_STAGE_INIT;
	hba->loop_map_valid = LOOP_MAP_INVALID;
	hba->srq_delay_info.srq_delay_flag = 0;
	hba->srq_delay_info.root_rq_rcvd_flag = 0;
	spin_unlock_irqrestore(&hba->hba_lock, flag);
}

static u32 spfc_recv_fc_linkup(struct spfc_hba_info *hba, void *buf_in)
{
#define SPFC_LOOP_MASK 0x1
#define SPFC_LOOPMAP_COUNT 128

	u32 ret = UNF_RETURN_ERROR;
	struct spfc_link_event *link_event = NULL;

	link_event = (struct spfc_link_event *)buf_in;
	hba->phy_link = UNF_PORT_LINK_UP;
	hba->active_port_speed = link_event->speed;
	hba->led_states.green_speed_led = (u8)(link_event->green_speed_led);
	hba->led_states.yellow_speed_led = (u8)(link_event->yellow_speed_led);
	hba->led_states.ac_led = (u8)(link_event->ac_led);

	if (link_event->top_type == SPFC_LOOP_MASK &&
	    (link_event->loop_map_info[ARRAY_INDEX_1] == UNF_FL_PORT_LOOP_ADDR ||
	     link_event->loop_map_info[ARRAY_INDEX_2] == UNF_FL_PORT_LOOP_ADDR)) {
		hba->active_topo = UNF_ACT_TOP_PUBLIC_LOOP; /* Public Loop */
		hba->active_alpa = link_event->alpa_value; /* AL_PA */
		memcpy(hba->loop_map, link_event->loop_map_info, SPFC_LOOPMAP_COUNT);
		hba->loop_map_valid = LOOP_MAP_VALID;
	} else if (link_event->top_type == SPFC_LOOP_MASK) {
		hba->active_topo = UNF_ACT_TOP_PRIVATE_LOOP; /* Private Loop */
		hba->active_alpa = link_event->alpa_value;  /* AL_PA */
		memcpy(hba->loop_map, link_event->loop_map_info, SPFC_LOOPMAP_COUNT);
		hba->loop_map_valid = LOOP_MAP_VALID;
	} else {
		hba->active_topo = UNF_TOP_P2P_MASK; /* P2P_D or P2P_F */
	}

	FC_DRV_PRINT(UNF_LOG_EVENT, UNF_KEVENT,
		     "[event]Port(0x%x) receive link up event(0x%x) with speed(0x%x) uP_topo(0x%x) driver_topo(0x%x)",
		     hba->port_cfg.port_id, link_event->link_event,
		     link_event->speed, link_event->top_type, hba->active_topo);

	/* Set clear & flush state */
	spfc_set_hba_clear_state(hba, false);
	spfc_set_hba_flush_state(hba, false);
	spfc_set_rport_flush_state(hba, false);

	/* Report link up event to COM */
	UNF_LOWLEVEL_PORT_EVENT(ret, hba->lport, UNF_PORT_LINK_UP,
				&hba->active_port_speed);

	SPFC_LINK_EVENT_STAT(hba, SPFC_LINK_UP_COUNT);

	return ret;
}

static u32 spfc_recv_fc_linkdown(struct spfc_hba_info *hba, void *buf_in)
{
	u32 ret = UNF_RETURN_ERROR;
	struct spfc_link_event *link_event = NULL;

	link_event = (struct spfc_link_event *)buf_in;

	/* 1. Led state setting */
	hba->led_states.green_speed_led = (u8)(link_event->green_speed_led);
	hba->led_states.yellow_speed_led = (u8)(link_event->yellow_speed_led);
	hba->led_states.ac_led = (u8)(link_event->ac_led);

	FC_DRV_PRINT(UNF_LOG_EVENT, UNF_KEVENT,
		     "[event]Port(0x%x) receive link down event(0x%x) reason(0x%x)",
		     hba->port_cfg.port_id, link_event->link_event, link_event->reason);

	spfc_initial_dynamic_info(hba);

	/* 2. set HBA flush state */
	spfc_set_hba_flush_state(hba, true);

	/* 3. set R_Port (parent SQ) flush state */
	spfc_set_rport_flush_state(hba, true);

	/* 4. Report link down event to COM */
	UNF_LOWLEVEL_PORT_EVENT(ret, hba->lport, UNF_PORT_LINK_DOWN, 0);

	/* DFX setting */
	SPFC_LINK_REASON_STAT(hba, link_event->reason);
	SPFC_LINK_EVENT_STAT(hba, SPFC_LINK_DOWN_COUNT);

	return ret;
}

static u32 spfc_recv_fc_delcmd(struct spfc_hba_info *hba, void *buf_in)
{
	u32 ret = UNF_RETURN_ERROR;
	struct spfc_link_event *link_event = NULL;

	link_event = (struct spfc_link_event *)buf_in;

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_KEVENT,
		     "[event]Port(0x%x) receive delete cmd event(0x%x)",
		     hba->port_cfg.port_id, link_event->link_event);

	/* Send buffer clear cmnd */
	ret = spfc_clear_fetched_sq_wqe(hba);

	hba->queue_set_stage = SPFC_QUEUE_SET_STAGE_SCANNING;
	SPFC_LINK_EVENT_STAT(hba, SPFC_FC_DELETE_CMND_COUNT);

	return ret;
}

static u32 spfc_recv_fc_error(struct spfc_hba_info *hba, void *buf_in)
{
#define FC_ERR_LEVEL_DEAD 0
#define FC_ERR_LEVEL_HIGH 1
#define FC_ERR_LEVEL_LOW 2

	u32 ret = UNF_RETURN_ERROR;
	struct spfc_up_error_event *up_error_event = NULL;

	up_error_event = (struct spfc_up_error_event *)buf_in;
	if (up_error_event->error_type >= SPFC_UP_ERR_BUTT ||
	    up_error_event->error_value >= SPFC_ERR_VALUE_BUTT) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "Port(0x%x) receive a unsupported UP Error Event Type(0x%x) Value(0x%x).",
			     hba->port_cfg.port_id, up_error_event->error_type,
			     up_error_event->error_value);
		return ret;
	}

	switch (up_error_event->error_level) {
	case FC_ERR_LEVEL_DEAD:
		ret = RETURN_OK;
		break;

	case FC_ERR_LEVEL_HIGH:
		/* port reset */
		UNF_LOWLEVEL_PORT_EVENT(ret, hba->lport,
					UNF_PORT_ABNORMAL_RESET, NULL);
		break;

	case FC_ERR_LEVEL_LOW:
		ret = RETURN_OK;
		break;

	default:
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "Port(0x%x) receive a unsupported UP Error Event Level(0x%x), Can not Process.",
			     hba->port_cfg.port_id,
			     up_error_event->error_level);
		return ret;
	}
	if (up_error_event->error_value < SPFC_ERR_VALUE_BUTT)
		SPFC_UP_ERR_EVENT_STAT(hba, up_error_event->error_value);

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_KEVENT,
		     "[event]Port(0x%x) process UP Error Event Level(0x%x) Type(0x%x) Value(0x%x) %s.",
		     hba->port_cfg.port_id, up_error_event->error_level,
		     up_error_event->error_type, up_error_event->error_value,
		     (ret == UNF_RETURN_ERROR) ? "ERROR" : "OK");

	return ret;
}

static struct spfc_up2drv_msg_handle up_msg_handle[] = {
	{SPFC_MBOX_RECV_FC_LINKUP, spfc_recv_fc_linkup},
	{SPFC_MBOX_RECV_FC_LINKDOWN, spfc_recv_fc_linkdown},
	{SPFC_MBOX_RECV_FC_DELCMD, spfc_recv_fc_delcmd},
	{SPFC_MBOX_RECV_FC_ERROR, spfc_recv_fc_error}
};

void spfc_up_msg2driver_proc(void *hwdev_handle, void *pri_handle, u16 cmd,
			     void *buf_in, u16 in_size, void *buf_out,
			     u16 *out_size)
{
	u32 ret = UNF_RETURN_ERROR;
	u32 index = 0;
	struct spfc_hba_info *hba = NULL;
	struct spfc_mbox_header *mbx_header = NULL;

	FC_CHECK_RETURN_VOID(hwdev_handle);
	FC_CHECK_RETURN_VOID(pri_handle);
	FC_CHECK_RETURN_VOID(buf_in);
	FC_CHECK_RETURN_VOID(buf_out);
	FC_CHECK_RETURN_VOID(out_size);

	hba = (struct spfc_hba_info *)pri_handle;
	if (!hba) {
		FC_DRV_PRINT(UNF_LOG_EVENT, UNF_ERR, "[err]Hba is null");
		return;
	}

	mbx_header = (struct spfc_mbox_header *)buf_in;
	if (mbx_header->cmnd_type != cmd) {
		*out_size = sizeof(struct spfc_link_event);
		FC_DRV_PRINT(UNF_LOG_EVENT, UNF_ERR,
			     "[err]Port(0x%x) cmd(0x%x) is not matched with header cmd type(0x%x)",
			     hba->port_cfg.port_id, cmd, mbx_header->cmnd_type);
		return;
	}

	while (index < (sizeof(up_msg_handle) / sizeof(struct spfc_up2drv_msg_handle))) {
		if (up_msg_handle[index].cmd == cmd &&
		    up_msg_handle[index].spfc_msg_up2driver_handler) {
			ret = up_msg_handle[index].spfc_msg_up2driver_handler(hba, buf_in);
			if (ret != RETURN_OK) {
				FC_DRV_PRINT(UNF_LOG_EVENT, UNF_ERR,
					     "[warn]Port(0x%x) process up cmd(0x%x) failed",
					     hba->port_cfg.port_id, cmd);
			}
			*out_size = sizeof(struct spfc_link_event);
			return;
		}
		index++;
	}

	*out_size = sizeof(struct spfc_link_event);

	FC_DRV_PRINT(UNF_LOG_EVENT, UNF_ERR,
		     "[err]Port(0x%x) process up cmd(0x%x) failed",
		     hba->port_cfg.port_id, cmd);
}

u32 spfc_get_topo_act(void *hba, void *topo_act)
{
	struct spfc_hba_info *spfc_hba = hba;
	enum unf_act_topo *pen_topo_act = topo_act;

	FC_CHECK_RETURN_VALUE(hba, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(topo_act, UNF_RETURN_ERROR);

	/* Get topo from low_level */
	*pen_topo_act = spfc_hba->active_topo;

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
		     "[info]Get active topology: 0x%x", *pen_topo_act);

	return RETURN_OK;
}

u32 spfc_get_loop_alpa(void *hba, void *alpa)
{
	ulong flags = 0;
	struct spfc_hba_info *spfc_hba = hba;
	u8 *alpa_temp = alpa;

	FC_CHECK_RETURN_VALUE(spfc_hba, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(alpa, UNF_RETURN_ERROR);

	spin_lock_irqsave(&spfc_hba->hba_lock, flags);
	*alpa_temp = spfc_hba->active_alpa;
	spin_unlock_irqrestore(&spfc_hba->hba_lock, flags);

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_INFO,
		     "[info]Get active AL_PA(0x%x)", *alpa_temp);

	return RETURN_OK;
}

static void spfc_get_fabric_login_params(struct spfc_hba_info *hba,
					 struct unf_port_login_parms *params_addr)
{
	ulong flag = 0;

	spin_lock_irqsave(&hba->hba_lock, flag);
	hba->active_topo = params_addr->act_topo;
	hba->compared_ratov_val = params_addr->compared_ratov_val;
	hba->compared_edtov_val = params_addr->compared_edtov_val;
	hba->compared_bb_scn = params_addr->compared_bbscn;
	hba->remote_edtov_tag = params_addr->remote_edtov_tag;
	hba->remote_rttov_tag = params_addr->remote_rttov_tag;
	hba->remote_bb_credit = params_addr->remote_bb_credit;
	spin_unlock_irqrestore(&hba->hba_lock, flag);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_INFO,
		     "[info]Port(0x%x) topo(0x%x) get fabric params: R_A_TOV(0x%x) E_D_TOV(%u) BB_CREDIT(0x%x) BB_SC_N(0x%x)",
		     hba->port_cfg.port_id, hba->active_topo,
		     hba->compared_ratov_val, hba->compared_edtov_val,
		     hba->remote_bb_credit, hba->compared_bb_scn);
}

static void spfc_get_port_login_params(struct spfc_hba_info *hba,
				       struct unf_port_login_parms *params_addr)
{
	ulong flag = 0;

	spin_lock_irqsave(&hba->hba_lock, flag);
	hba->compared_ratov_val = params_addr->compared_ratov_val;
	hba->compared_edtov_val = params_addr->compared_edtov_val;
	hba->compared_bb_scn = params_addr->compared_bbscn;
	hba->remote_edtov_tag = params_addr->remote_edtov_tag;
	hba->remote_rttov_tag = params_addr->remote_rttov_tag;
	hba->remote_bb_credit = params_addr->remote_bb_credit;
	spin_unlock_irqrestore(&hba->hba_lock, flag);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "Port(0x%x) Topo(0x%x) Get Port Params: R_A_TOV(0x%x), E_D_TOV(0x%x), BB_CREDIT(0x%x), BB_SC_N(0x%x).",
		     hba->port_cfg.port_id, hba->active_topo,
		     hba->compared_ratov_val, hba->compared_edtov_val,
		     hba->remote_bb_credit, hba->compared_bb_scn);
}

u32 spfc_update_fabric_param(void *hba, void *para_in)
{
	u32 ret = RETURN_OK;
	struct spfc_hba_info *spfc_hba = hba;
	struct unf_port_login_parms *login_coparms = para_in;

	FC_CHECK_RETURN_VALUE(spfc_hba, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(para_in, UNF_RETURN_ERROR);

	spfc_get_fabric_login_params(spfc_hba, login_coparms);

	if (spfc_hba->active_topo == UNF_ACT_TOP_P2P_FABRIC ||
	    spfc_hba->active_topo == UNF_ACT_TOP_PUBLIC_LOOP) {
		if (spfc_hba->work_mode == SPFC_SMARTIO_WORK_MODE_FC)
			ret = spfc_config_login_api(spfc_hba, login_coparms);
	}

	return ret;
}

u32 spfc_update_port_param(void *hba, void *para_in)
{
	u32 ret = RETURN_OK;
	struct spfc_hba_info *spfc_hba = hba;
	struct unf_port_login_parms *login_coparms =
	    (struct unf_port_login_parms *)para_in;

	FC_CHECK_RETURN_VALUE(spfc_hba, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(para_in, UNF_RETURN_ERROR);

	if (spfc_hba->active_topo == UNF_ACT_TOP_PRIVATE_LOOP ||
	    spfc_hba->active_topo == UNF_ACT_TOP_P2P_DIRECT) {
		spfc_get_port_login_params(spfc_hba, login_coparms);
		ret = spfc_config_login_api(spfc_hba, login_coparms);
	}

	spfc_save_login_parms_in_sq_info(spfc_hba, login_coparms);

	return ret;
}

u32 spfc_get_workable_bb_credit(void *hba, void *bb_credit)
{
	u32 *bb_credit_temp = (u32 *)bb_credit;
	struct spfc_hba_info *spfc_hba = hba;

	FC_CHECK_RETURN_VALUE(spfc_hba, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(bb_credit, UNF_RETURN_ERROR);
	if (spfc_hba->active_port_speed == UNF_PORT_SPEED_32_G)
		*bb_credit_temp = SPFC_LOWLEVEL_DEFAULT_32G_BB_CREDIT;
	else if (spfc_hba->active_port_speed == UNF_PORT_SPEED_16_G)
		*bb_credit_temp = SPFC_LOWLEVEL_DEFAULT_16G_BB_CREDIT;
	else
		*bb_credit_temp = SPFC_LOWLEVEL_DEFAULT_8G_BB_CREDIT;

	return RETURN_OK;
}

u32 spfc_get_workable_bb_scn(void *hba, void *bb_scn)
{
	u32 *bb_scn_temp = (u32 *)bb_scn;
	struct spfc_hba_info *spfc_hba = (struct spfc_hba_info *)hba;

	FC_CHECK_RETURN_VALUE(hba, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(bb_scn, UNF_RETURN_ERROR);

	*bb_scn_temp = spfc_hba->port_bb_scn_cfg;

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_INFO,
		     "Return BBSCN(0x%x) to CM", *bb_scn_temp);

	return RETURN_OK;
}

u32 spfc_get_loop_map(void *hba, void *buf)
{
	ulong flags = 0;
	struct unf_buf *buf_temp = (struct unf_buf *)buf;
	struct spfc_hba_info *spfc_hba = hba;

	FC_CHECK_RETURN_VALUE(spfc_hba, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(buf_temp, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(buf_temp->buf, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(buf_temp->buf_len, UNF_RETURN_ERROR);

	if (buf_temp->buf_len > UNF_LOOPMAP_COUNT)
		return UNF_RETURN_ERROR;

	spin_lock_irqsave(&spfc_hba->hba_lock, flags);
	if (spfc_hba->loop_map_valid != LOOP_MAP_VALID) {
		spin_unlock_irqrestore(&spfc_hba->hba_lock, flags);
		return UNF_RETURN_ERROR;
	}
	memcpy(buf_temp->buf, spfc_hba->loop_map, buf_temp->buf_len);
	spin_unlock_irqrestore(&spfc_hba->hba_lock, flags);

	return RETURN_OK;
}

u32 spfc_mb_reset_chip(struct spfc_hba_info *hba, u8 sub_type)
{
	struct spfc_inmbox_port_reset port_reset;
	union spfc_outmbox_generic *port_reset_sts = NULL;
	u32 ret = UNF_RETURN_ERROR;

	FC_CHECK_RETURN_VALUE(hba, UNF_RETURN_ERROR);

	memset(&port_reset, 0, sizeof(port_reset));

	port_reset_sts = kmalloc(sizeof(union spfc_outmbox_generic), GFP_ATOMIC);
	if (!port_reset_sts) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "malloc outmbox memory failed");
		return UNF_RETURN_ERROR;
	}
	memset(port_reset_sts, 0, sizeof(union spfc_outmbox_generic));
	port_reset.header.cmnd_type = SPFC_MBOX_PORT_RESET;
	port_reset.header.length = SPFC_BYTES_TO_DW_NUM(sizeof(struct spfc_inmbox_port_reset));
	port_reset.op_code = sub_type;

	if (spfc_mb_send_and_wait_mbox(hba, &port_reset, sizeof(port_reset),
				       port_reset_sts) != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[warn]Port(0x%x) can't send and wait mailbox with command type(0x%x)",
			     hba->port_cfg.port_id, port_reset.header.cmnd_type);

		goto exit;
	}

	if (port_reset_sts->port_reset_sts.status != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_EQUIP_ATT, UNF_ERR,
			     "[warn]Port(0x%x) receive mailbox type(0x%x) status(0x%x) incorrect",
			     hba->port_cfg.port_id,
			     port_reset_sts->port_reset_sts.header.cmnd_type,
			     port_reset_sts->port_reset_sts.status);

		goto exit;
	}

	if (port_reset_sts->port_reset_sts.header.cmnd_type != SPFC_MBOX_PORT_RESET_STS) {
		FC_DRV_PRINT(UNF_LOG_EQUIP_ATT, UNF_ERR,
			     "[warn]Port(0x%x) recv mailbox type(0x%x) incorrect",
			     hba->port_cfg.port_id,
			     port_reset_sts->port_reset_sts.header.cmnd_type);

		goto exit;
	}

	FC_DRV_PRINT(UNF_LOG_EQUIP_ATT, UNF_MAJOR,
		     "[info]Port(0x%x) reset chip mailbox success",
		     hba->port_cfg.port_id);

	ret = RETURN_OK;
exit:
	kfree(port_reset_sts);

	return ret;
}

u32 spfc_clear_sq_wqe_done(struct spfc_hba_info *hba)
{
	int ret1 = RETURN_OK;
	u32 ret2 = RETURN_OK;
	struct spfc_inmbox_clear_done clear_done;

	clear_done.header.cmnd_type = SPFC_MBOX_BUFFER_CLEAR_DONE;
	clear_done.header.length = SPFC_BYTES_TO_DW_NUM(sizeof(struct spfc_inmbox_clear_done));
	clear_done.header.port_id = hba->port_index;

	ret1 = sphw_msg_to_mgmt_async(hba->dev_handle, COMM_MOD_FC,
				      SPFC_MBOX_BUFFER_CLEAR_DONE, &clear_done,
				      sizeof(clear_done), SPHW_CHANNEL_FC);

	if (ret1 != 0) {
		SPFC_MAILBOX_STAT(hba, SPFC_SEND_CLEAR_DONE_FAIL);
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]SPFC Port(0x%x) can't send clear done cmd to up, ret:%d",
			     hba->port_cfg.port_id, ret1);

		return UNF_RETURN_ERROR;
	}

	SPFC_MAILBOX_STAT(hba, SPFC_SEND_CLEAR_DONE);
	hba->queue_set_stage = SPFC_QUEUE_SET_STAGE_FLUSHDONE;
	hba->next_clear_sq = 0;

	FC_DRV_PRINT(UNF_LOG_EVENT, UNF_KEVENT,
		     "[info]Port(0x%x) clear done msg(0x%x) sent to up succeed with stage(0x%x)",
		     hba->port_cfg.port_id, clear_done.header.cmnd_type,
		     hba->queue_set_stage);

	return ret2;
}

u32 spfc_mbx_get_fw_clear_stat(struct spfc_hba_info *hba, u32 *clear_state)
{
	struct spfc_inmbox_get_clear_state get_clr_state;
	union spfc_outmbox_generic *port_clear_state_sts = NULL;
	u32 ret = UNF_RETURN_ERROR;

	FC_CHECK_RETURN_VALUE(hba, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(clear_state, UNF_RETURN_ERROR);

	memset(&get_clr_state, 0, sizeof(get_clr_state));

	port_clear_state_sts = kmalloc(sizeof(union spfc_outmbox_generic), GFP_ATOMIC);
	if (!port_clear_state_sts) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "malloc outmbox memory failed");
		return UNF_RETURN_ERROR;
	}
	memset(port_clear_state_sts, 0, sizeof(union spfc_outmbox_generic));

	get_clr_state.header.cmnd_type = SPFC_MBOX_GET_CLEAR_STATE;
	get_clr_state.header.length =
	    SPFC_BYTES_TO_DW_NUM(sizeof(struct spfc_inmbox_get_clear_state));

	if (spfc_mb_send_and_wait_mbox(hba, &get_clr_state, sizeof(get_clr_state),
				       port_clear_state_sts) != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "spfc can't send and wait mailbox, command type: 0x%x",
			     get_clr_state.header.cmnd_type);

		goto exit;
	}

	if (port_clear_state_sts->get_clr_state_sts.status != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_EQUIP_ATT, UNF_ERR,
			     "Port(0x%x) Receive mailbox type(0x%x) status incorrect. Status: 0x%x, state 0x%x.",
			     hba->port_cfg.port_id,
			     port_clear_state_sts->get_clr_state_sts.header.cmnd_type,
			     port_clear_state_sts->get_clr_state_sts.status,
			     port_clear_state_sts->get_clr_state_sts.state);

		goto exit;
	}

	if (port_clear_state_sts->get_clr_state_sts.header.cmnd_type !=
	    SPFC_MBOX_GET_CLEAR_STATE_STS) {
		FC_DRV_PRINT(UNF_LOG_EQUIP_ATT, UNF_ERR,
			     "Port(0x%x) recv mailbox type(0x%x) incorrect.",
			     hba->port_cfg.port_id,
			     port_clear_state_sts->get_clr_state_sts.header.cmnd_type);

		goto exit;
	}

	FC_DRV_PRINT(UNF_LOG_EVENT, UNF_MAJOR,
		     "Port(0x%x) get port clear state 0x%x.",
		     hba->port_cfg.port_id,
		     port_clear_state_sts->get_clr_state_sts.state);

	*clear_state = port_clear_state_sts->get_clr_state_sts.state;

	ret = RETURN_OK;
exit:
	kfree(port_clear_state_sts);

	return ret;
}

u32 spfc_mbx_config_default_session(void *hba, u32 flag)
{
	struct spfc_hba_info *spfc_hba = NULL;
	struct spfc_inmbox_default_sq_info default_sq_info;
	union spfc_outmbox_generic default_sq_info_sts;
	u32 ret = UNF_RETURN_ERROR;

	FC_CHECK_RETURN_VALUE(hba, UNF_RETURN_ERROR);

	spfc_hba = (struct spfc_hba_info *)hba;

	memset(&default_sq_info, 0, sizeof(struct spfc_inmbox_default_sq_info));
	memset(&default_sq_info_sts, 0, sizeof(union spfc_outmbox_generic));

	default_sq_info.header.cmnd_type = SPFC_MBOX_SEND_DEFAULT_SQ_INFO;
	default_sq_info.header.length =
	    SPFC_BYTES_TO_DW_NUM(sizeof(struct spfc_inmbox_default_sq_info));
	default_sq_info.func_id = sphw_global_func_id(spfc_hba->dev_handle);

	/* When flag is 1, set default SQ info when probe, when 0, clear when
	 * remove
	 */
	if (flag) {
		default_sq_info.sq_cid = spfc_hba->default_sq_info.sq_cid;
		default_sq_info.sq_xid = spfc_hba->default_sq_info.sq_xid;
		default_sq_info.valid = 1;
	}

	ret =
	    spfc_mb_send_and_wait_mbox(spfc_hba, &default_sq_info, sizeof(default_sq_info),
				       (union spfc_outmbox_generic *)(void *)&default_sq_info_sts);

	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "spfc can't send and wait mailbox, command type: 0x%x.",
			     default_sq_info.header.cmnd_type);

		return UNF_RETURN_ERROR;
	}

	if (default_sq_info_sts.default_sq_sts.status != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "Port(0x%x) mailbox status incorrect status(0x%x) .",
			     spfc_hba->port_cfg.port_id,
			     default_sq_info_sts.default_sq_sts.status);

		return UNF_RETURN_ERROR;
	}

	if (SPFC_MBOX_SEND_DEFAULT_SQ_INFO_STS !=
	    default_sq_info_sts.default_sq_sts.header.cmnd_type) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "Port(0x%x) receive mailbox type incorrect type: 0x%x.",
			     spfc_hba->port_cfg.port_id,
			     default_sq_info_sts.default_sq_sts.header.cmnd_type);

		return UNF_RETURN_ERROR;
	}

	return RETURN_OK;
}
