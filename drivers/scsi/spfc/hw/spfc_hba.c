// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#include "spfc_hba.h"
#include "spfc_module.h"
#include "spfc_utils.h"
#include "spfc_chipitf.h"
#include "spfc_io.h"
#include "spfc_lld.h"
#include "sphw_hw.h"
#include "spfc_cqm_main.h"

struct spfc_hba_info *spfc_hba[SPFC_HBA_PORT_MAX_NUM];
ulong probe_bit_map[SPFC_MAX_PROBE_PORT_NUM / SPFC_PORT_NUM_PER_TABLE];
static ulong card_num_bit_map[SPFC_MAX_PROBE_PORT_NUM / SPFC_PORT_NUM_PER_TABLE];
static struct spfc_card_num_manage card_num_manage[SPFC_MAX_CARD_NUM];
spinlock_t probe_spin_lock;
u32 max_parent_qpc_num;

static int spfc_probe(struct spfc_lld_dev *lld_dev, void **uld_dev, char *uld_dev_name);
static void spfc_remove(struct spfc_lld_dev *lld_dev, void *uld_dev);
static u32 spfc_initial_chip_access(struct spfc_hba_info *hba);
static void spfc_release_chip_access(struct spfc_hba_info *hba);
static u32 spfc_port_config_set(void *hba, enum unf_port_config_set_op opcode, void *var_in);
static u32 spfc_port_config_get(void *hba, enum unf_port_cfg_get_op opcode, void *para_out);
static u32 spfc_port_update_wwn(void *hba, void *para_in);
static u32 spfc_get_chip_info(struct spfc_hba_info *hba);
static u32 spfc_delete_scqc_via_cmdq_sync(struct spfc_hba_info *hba, u32 scqn);
static u32 spfc_delete_srqc_via_cmdq_sync(struct spfc_hba_info *hba, u64 sqrc_gpa);
static u32 spfc_get_hba_pcie_link_state(void *hba, void *link_state);
static u32 spfc_port_check_fw_ready(struct spfc_hba_info *hba);
static u32 spfc_set_port_state(void *hba, void *para_in);

struct spfc_uld_info fc_uld_info = {
	.probe = spfc_probe,
	.remove = spfc_remove,
	.resume = NULL,
	.event = NULL,
	.suspend = NULL,
	.ioctl = NULL
};

struct service_register_template service_cqm_temp = {
	.service_type = SERVICE_T_FC,
	.scq_ctx_size = SPFC_SCQ_CNTX_SIZE,
	.srq_ctx_size = SPFC_SRQ_CNTX_SIZE, /* srq, scq context_size configuration */
	.aeq_callback = spfc_process_aeqe, /* the API of asynchronous event from TILE to driver */
};

/* default configuration: auto speed, auto topology, INI+TGT */
static struct unf_cfg_item spfc_port_cfg_parm[] = {
	{"port_id", 0, 0x110000, 0xffffff},
	/* port mode:INI(0x20), TGT(0x10), BOTH(0x30) */
	{"port_mode", 0, 0x20, 0xff},
	/* port topology, 0x3: loop , 0xc:p2p, 0xf:auto, 0x10:vn2vn */
	{"port_topology", 0, 0xf, 0x20},
	{"port_alpa", 0, 0xdead, 0xffff}, /* alpa address of port */
	/* queue depth of originator registered to SCSI midlayer */
	{"max_queue_depth", 0, 128, 128},
	{"sest_num", 0, 2048, 2048},
	{"max_login", 0, 2048, 2048},
	/* nodename from 32 bit to 64 bit */
	{"node_name_high", 0, 0x1000286e, 0xffffffff},
	/* nodename from 0 bit to 31 bit */
	{"node_name_low", 0, 0xd4bbf12f, 0xffffffff},
	/* portname from 32 bit to 64 bit */
	{"port_name_high", 0, 0x2000286e, 0xffffffff},
	/* portname from 0 bit to 31 bit */
	{"port_name_low", 0, 0xd4bbf12f, 0xffffffff},
	/* port speed 0:auto 1:1Gbps 2:2Gbps 3:4Gbps 4:8Gbps 5:16Gbps */
	{"port_speed", 0, 0, 32},
	{"interrupt_delay", 0, 0, 100}, /* unit: us */
	{"tape_support", 0, 0, 1},    /* tape support */
	{"End", 0, 0, 0}
};

struct unf_low_level_functioon_op spfc_func_op = {
	.low_level_type = UNF_SPFC_FC,
	.name = "SPFC",
	.xchg_mgr_type = UNF_LOW_LEVEL_MGR_TYPE_PASSTIVE,
	.abts_xchg = UNF_NO_EXTRA_ABTS_XCHG,
	.passthrough_flag = UNF_LOW_LEVEL_PASS_THROUGH_PORT_LOGIN,
	.support_max_npiv_num = UNF_SPFC_MAXNPIV_NUM,
	.support_max_ssq_num = SPFC_MAX_SSQ_NUM - 1,
	.chip_id = 0,
	.support_max_speed = UNF_PORT_SPEED_32_G,
	.support_max_rport = UNF_SPFC_MAXRPORT_NUM,
	.sfp_type = UNF_PORT_TYPE_FC_SFP,
	.rport_release_type = UNF_LOW_LEVEL_RELEASE_RPORT_ASYNC,
	.sirt_page_mode = UNF_LOW_LEVEL_SIRT_PAGE_MODE_XCHG,

	/* Link service */
	.service_op = {
		.unf_ls_gs_send = spfc_send_ls_gs_cmnd,
		.unf_bls_send = spfc_send_bls_cmnd,
		.unf_cmnd_send = spfc_send_scsi_cmnd,
		.unf_release_rport_res = spfc_free_parent_resource,
		.unf_flush_ini_resp_que = spfc_flush_ini_resp_queue,
		.unf_alloc_rport_res = spfc_alloc_parent_resource,
		.ll_release_xid = spfc_free_xid,
	},

	/* Port Mgr */
	.port_mgr_op = {
		.ll_port_config_set = spfc_port_config_set,
		.ll_port_config_get = spfc_port_config_get,
	}
};

struct spfc_port_cfg_op {
	enum unf_port_config_set_op opcode;
	u32 (*spfc_operation)(void *hba, void *para);
};

struct spfc_port_cfg_op spfc_config_set_op[] = {
	{UNF_PORT_CFG_SET_PORT_SWITCH, spfc_sfp_switch},
	{UNF_PORT_CFG_UPDATE_WWN, spfc_port_update_wwn},
	{UNF_PORT_CFG_SET_PORT_STATE, spfc_set_port_state},
	{UNF_PORT_CFG_UPDATE_FABRIC_PARAM, spfc_update_fabric_param},
	{UNF_PORT_CFG_UPDATE_PLOGI_PARAM, spfc_update_port_param},
	{UNF_PORT_CFG_SET_BUTT, NULL}
};

struct spfc_port_cfg_get_op {
	enum unf_port_cfg_get_op opcode;
	u32 (*spfc_operation)(void *hba, void *para);
};

struct spfc_port_cfg_get_op spfc_config_get_op[] = {
	{UNF_PORT_CFG_GET_TOPO_ACT, spfc_get_topo_act},
	{UNF_PORT_CFG_GET_LOOP_MAP, spfc_get_loop_map},
	{UNF_PORT_CFG_GET_WORKBALE_BBCREDIT, spfc_get_workable_bb_credit},
	{UNF_PORT_CFG_GET_WORKBALE_BBSCN, spfc_get_workable_bb_scn},
	{UNF_PORT_CFG_GET_LOOP_ALPA, spfc_get_loop_alpa},
	{UNF_PORT_CFG_GET_MAC_ADDR, spfc_get_chip_msg},
	{UNF_PORT_CFG_GET_PCIE_LINK_STATE, spfc_get_hba_pcie_link_state},
	{UNF_PORT_CFG_GET_BUTT, NULL},
};

static u32 spfc_set_port_state(void *hba, void *para_in)
{
	u32 ret = UNF_RETURN_ERROR;
	enum unf_port_config_state port_state = UNF_PORT_CONFIG_STATE_START;


	FC_CHECK_RETURN_VALUE(hba, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(para_in, UNF_RETURN_ERROR);

	port_state = *((enum unf_port_config_state *)para_in);
	switch (port_state) {
	case UNF_PORT_CONFIG_STATE_RESET:
		ret = (u32)spfc_port_reset(hba);
		break;

	default:
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
			     "[warn]Cannot set port_state(0x%x)", port_state);
		break;
	}

	return ret;

}

static u32 spfc_port_update_wwn(void *hba, void *para_in)
{
	struct unf_port_wwn *port_wwn = NULL;
	struct spfc_hba_info *spfc_hba = hba;

	FC_CHECK_RETURN_VALUE(spfc_hba, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(para_in, UNF_RETURN_ERROR);

	port_wwn = (struct unf_port_wwn *)para_in;

	/* Update it to the hba in the later */
	*(u64 *)spfc_hba->sys_node_name = port_wwn->sys_node_name;
	*(u64 *)spfc_hba->sys_port_name = port_wwn->sys_port_wwn;

	FC_DRV_PRINT(UNF_LOG_EQUIP_ATT, UNF_INFO,
		     "[info]Port(0x%x) updates WWNN(0x%llx) WWPN(0x%llx)",
		     spfc_hba->port_cfg.port_id,
		     *(u64 *)spfc_hba->sys_node_name,
		     *(u64 *)spfc_hba->sys_port_name);

	return RETURN_OK;
}

static u32 spfc_port_config_set(void *hba, enum unf_port_config_set_op opcode,
				void *var_in)
{
	u32 op_idx = 0;

	FC_CHECK_RETURN_VALUE(hba, UNF_RETURN_ERROR);

	for (op_idx = 0; op_idx < sizeof(spfc_config_set_op) /
		sizeof(struct spfc_port_cfg_op); op_idx++) {
		if (opcode == spfc_config_set_op[op_idx].opcode) {
			if (!spfc_config_set_op[op_idx].spfc_operation) {
				FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
					     "[warn]Null operation for configuration, opcode(0x%x), operation ID(0x%x)",
					     opcode, op_idx);

				return UNF_RETURN_ERROR;
			}
			return spfc_config_set_op[op_idx].spfc_operation(hba, var_in);
		}
	}

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
		     "[warn]No operation code for configuration, opcode(0x%x)",
		     opcode);

	return UNF_RETURN_ERROR;
}

static u32 spfc_port_config_get(void *hba, enum unf_port_cfg_get_op opcode,
				void *para_out)
{
	u32 op_idx = 0;

	FC_CHECK_RETURN_VALUE(hba, UNF_RETURN_ERROR);

	for (op_idx = 0; op_idx < sizeof(spfc_config_get_op) /
		sizeof(struct spfc_port_cfg_get_op); op_idx++) {
		if (opcode == spfc_config_get_op[op_idx].opcode) {
			if (!spfc_config_get_op[op_idx].spfc_operation) {
				FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
					     "[warn]Null operation to get configuration, opcode(0x%x), operation ID(0x%x)",
					     opcode, op_idx);
				return UNF_RETURN_ERROR;
			}
			return spfc_config_get_op[op_idx].spfc_operation(hba, para_out);
		}
	}

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
		     "[warn]No operation to get configuration, opcode(0x%x)",
		     opcode);

	return UNF_RETURN_ERROR;
}

static u32 spfc_fc_mode_check(void *hw_dev_handle)
{
	FC_CHECK_RETURN_VALUE(hw_dev_handle, UNF_RETURN_ERROR);

	if (!sphw_support_fc(hw_dev_handle, NULL)) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Work mode is error");
		return UNF_RETURN_ERROR;
	}

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
		     "[info]Selected work mode is FC");

	return RETURN_OK;
}

static u32 spfc_check_port_cfg(const struct spfc_port_cfg *port_cfg)
{
	bool topo_condition = false;
	bool speed_condition = false;
	/* About Work Topology */
	topo_condition = ((port_cfg->port_topology != UNF_TOP_LOOP_MASK) &&
			  (port_cfg->port_topology != UNF_TOP_P2P_MASK) &&
			  (port_cfg->port_topology != UNF_TOP_AUTO_MASK));
	if (topo_condition) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Configured port topology(0x%x) is incorrect",
			     port_cfg->port_topology);

		return UNF_RETURN_ERROR;
	}

	/* About Work Mode */
	if (port_cfg->port_mode != UNF_PORT_MODE_INI) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Configured port mode(0x%x) is incorrect",
			     port_cfg->port_mode);

		return UNF_RETURN_ERROR;
	}

	/* About Work Speed */
	speed_condition = ((port_cfg->port_speed != UNF_PORT_SPEED_AUTO) &&
			   (port_cfg->port_speed != UNF_PORT_SPEED_2_G) &&
			   (port_cfg->port_speed != UNF_PORT_SPEED_4_G) &&
			   (port_cfg->port_speed != UNF_PORT_SPEED_8_G) &&
			   (port_cfg->port_speed != UNF_PORT_SPEED_16_G) &&
			   (port_cfg->port_speed != UNF_PORT_SPEED_32_G));
	if (speed_condition) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Configured port speed(0x%x) is incorrect",
			     port_cfg->port_speed);

		return UNF_RETURN_ERROR;
	}

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_INFO,
		     "[info]Check port configuration OK");

	return RETURN_OK;
}

static u32 spfc_get_port_cfg(struct spfc_hba_info *hba,
			     struct spfc_chip_info *chip_info, u8 card_num)
{
#define UNF_CONFIG_ITEM_LEN 15
	/* Maximum length of a configuration item name, including the end
	 * character
	 */
#define UNF_MAX_ITEM_NAME_LEN (32 + 1)

	/* Get and check parameters */
	char cfg_item[UNF_MAX_ITEM_NAME_LEN];
	u32 ret = UNF_RETURN_ERROR;
	struct spfc_hba_info *spfc_hba = hba;

	FC_CHECK_RETURN_VALUE(spfc_hba, UNF_RETURN_ERROR);
	memset((void *)cfg_item, 0, sizeof(cfg_item));

	spfc_hba->card_info.func_num = (sphw_global_func_id(hba->dev_handle)) & UNF_FUN_ID_MASK;
	spfc_hba->card_info.card_num = card_num;

	/* The range of PF of FC server is from PF1 to PF2 */
	snprintf(cfg_item, UNF_MAX_ITEM_NAME_LEN, "spfc_cfg_%1u", (spfc_hba->card_info.func_num));

	cfg_item[UNF_MAX_ITEM_NAME_LEN - 1] = 0;

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_INFO,
		     "[info]Get port configuration: %s", cfg_item);

	/* Get configuration parameters from file */
	UNF_LOWLEVEL_GET_CFG_PARMS(ret, cfg_item, &spfc_port_cfg_parm[ARRAY_INDEX_0],
				   (u32 *)(void *)(&spfc_hba->port_cfg),
				   sizeof(spfc_port_cfg_parm) / sizeof(struct unf_cfg_item));
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Port(0x%x) can't get configuration",
			     spfc_hba->port_cfg.port_id);

		return ret;
	}

	if (max_parent_qpc_num <= SPFC_MAX_PARENT_QPC_NUM) {
		spfc_hba->port_cfg.sest_num = UNF_SPFC_MAXRPORT_NUM;
		spfc_hba->port_cfg.max_login = UNF_SPFC_MAXRPORT_NUM;
	}

	spfc_hba->port_cfg.port_id &= SPFC_PORT_ID_MASK;
	spfc_hba->port_cfg.port_id |= spfc_hba->card_info.card_num << UNF_SHIFT_8;
	spfc_hba->port_cfg.port_id |= spfc_hba->card_info.func_num;
	spfc_hba->port_cfg.tape_support = (u32)chip_info->tape_support;

	/* Parameters check */
	ret = spfc_check_port_cfg(&spfc_hba->port_cfg);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Port(0x%x) check configuration incorrect",
			     spfc_hba->port_cfg.port_id);

		return ret;
	}

	/* Set configuration which is got from file */
	spfc_hba->port_speed_cfg = spfc_hba->port_cfg.port_speed;
	spfc_hba->port_topo_cfg = spfc_hba->port_cfg.port_topology;
	spfc_hba->port_mode = (enum unf_port_mode)(spfc_hba->port_cfg.port_mode);

	return ret;
}

void spfc_generate_sys_wwn(struct spfc_hba_info *hba)
{
	FC_CHECK_RETURN_VOID(hba);

	*(u64 *)hba->sys_node_name = (((u64)hba->port_cfg.node_name_hi << UNF_SHIFT_32) |
				      (hba->port_cfg.node_name_lo));
	*(u64 *)hba->sys_port_name = (((u64)hba->port_cfg.port_name_hi << UNF_SHIFT_32) |
				      (hba->port_cfg.port_name_lo));

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_INFO,
		     "[info]NodeName = 0x%llx, PortName = 0x%llx",
		     *(u64 *)hba->sys_node_name, *(u64 *)hba->sys_port_name);
}

static u32 spfc_create_queues(struct spfc_hba_info *hba)
{
	u32 ret = UNF_RETURN_ERROR;

	FC_CHECK_RETURN_VALUE(hba, UNF_RETURN_ERROR);

	SPFC_FUNCTION_ENTER;

	/* Initialize shared resources of SCQ and SRQ in parent queue */
	ret = spfc_create_common_share_queues(hba);
	if (ret != RETURN_OK)
		goto out_create_common_queue_fail;

	/* Initialize parent queue manager resources */
	ret = spfc_alloc_parent_queue_mgr(hba);
	if (ret != RETURN_OK)
		goto out_free_share_queue_resource;

	/* Initialize shared WQE page pool in parent SQ */
	ret = spfc_alloc_parent_sq_wqe_page_pool(hba);
	if (ret != RETURN_OK)
		goto out_free_parent_queue_resource;

	ret = spfc_create_ssq(hba);
	if (ret != RETURN_OK)
		goto out_free_parent_wqe_page_pool;

	/*
	 * Notice: the configuration of SQ and QID(default_sqid)
	 * must be the same in FC
	 */
	hba->next_clear_sq = 0;
	hba->default_sqid = SPFC_QID_SQ;

	SPFC_FUNCTION_RETURN;
	return RETURN_OK;
out_free_parent_wqe_page_pool:
	spfc_free_parent_sq_wqe_page_pool(hba);

out_free_parent_queue_resource:
	spfc_free_parent_queue_mgr(hba);

out_free_share_queue_resource:
	spfc_flush_scq_ctx(hba);
	spfc_flush_srq_ctx(hba);
	spfc_destroy_common_share_queues(hba);

out_create_common_queue_fail:
	SPFC_FUNCTION_RETURN;

	return ret;
}

static u32 spfc_alloc_dma_buffers(struct spfc_hba_info *hba)
{
	struct pci_dev *pci_dev = NULL;

	FC_CHECK_RETURN_VALUE(hba, UNF_RETURN_ERROR);
	pci_dev = hba->pci_dev;
	FC_CHECK_RETURN_VALUE(pci_dev, UNF_RETURN_ERROR);

	hba->sfp_buf = dma_alloc_coherent(&hba->pci_dev->dev,
					  sizeof(struct unf_sfp_err_rome_info),
					  &hba->sfp_dma_addr, GFP_KERNEL);
	if (!hba->sfp_buf) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Port(0x%x) can't allocate SFP DMA buffer",
			     hba->port_cfg.port_id);

		return UNF_RETURN_ERROR;
	}
	memset(hba->sfp_buf, 0, sizeof(struct unf_sfp_err_rome_info));

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
		     "[info]Port(0x%x) allocate sfp buffer(0x%p 0x%llx)",
		     hba->port_cfg.port_id, hba->sfp_buf,
		     (u64)hba->sfp_dma_addr);

	return RETURN_OK;
}

static void spfc_free_dma_buffers(struct spfc_hba_info *hba)
{
	struct pci_dev *pci_dev = NULL;

	FC_CHECK_RETURN_VOID(hba);
	pci_dev = hba->pci_dev;
	FC_CHECK_RETURN_VOID(pci_dev);

	if (hba->sfp_buf) {
		dma_free_coherent(&pci_dev->dev, sizeof(struct unf_sfp_err_rome_info),
				  hba->sfp_buf, hba->sfp_dma_addr);

		hba->sfp_buf = NULL;
		hba->sfp_dma_addr = 0;
	}
}

static void spfc_destroy_queues(struct spfc_hba_info *hba)
{
	/* Free ssq */
	spfc_free_ssq(hba, SPFC_MAX_SSQ_NUM);

	/* Free parent queue resource */
	spfc_free_parent_queues(hba);

	/* Free queue manager resource */
	spfc_free_parent_queue_mgr(hba);

	/* Free linked List SQ and WQE page pool resource */
	spfc_free_parent_sq_wqe_page_pool(hba);

	/* Free shared SRQ and SCQ queue resource */
	spfc_destroy_common_share_queues(hba);
}

static u32 spfc_alloc_default_session(struct spfc_hba_info *hba)
{
	struct unf_port_info rport_info = {0};
	u32 wait_sq_cnt = 0;

	rport_info.nport_id = 0xffffff;
	rport_info.rport_index = SPFC_DEFAULT_RPORT_INDEX;
	rport_info.local_nport_id = 0xffffff;
	rport_info.port_name = 0;
	rport_info.cs_ctrl = 0x81;

	if (spfc_alloc_parent_resource((void *)hba, &rport_info) != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Alloc default session resource failed");
		goto failed;
	}

	for (;;) {
		if (hba->default_sq_info.default_sq_flag == 1)
			break;

		msleep(SPFC_WAIT_SESS_ENABLE_ONE_TIME_MS);
		wait_sq_cnt++;
		if (wait_sq_cnt >= SPFC_MAX_WAIT_LOOP_TIMES) {
			hba->default_sq_info.default_sq_flag = 0xF;
			FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
				     "[err]Wait Default Session enable timeout");
			goto failed;
		}
	}

	if (spfc_mbx_config_default_session(hba, 1) != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Notify up config default session table fail");
		goto failed;
	}

	return RETURN_OK;

failed:
	spfc_sess_resource_free_sync((void *)hba, &rport_info);
	return UNF_RETURN_ERROR;
}

static u32 spfc_init_host_res(struct spfc_hba_info *hba)
{
	u32 ret = RETURN_OK;
	struct spfc_hba_info *spfc_hba = hba;

	FC_CHECK_RETURN_VALUE(spfc_hba, UNF_RETURN_ERROR);

	SPFC_FUNCTION_ENTER;

	/* Initialize spin lock */
	spin_lock_init(&spfc_hba->hba_lock);
	spin_lock_init(&spfc_hba->flush_state_lock);
	spin_lock_init(&spfc_hba->clear_state_lock);
	spin_lock_init(&spfc_hba->spin_lock);
	spin_lock_init(&spfc_hba->srq_delay_info.srq_lock);
	/* Initialize init_completion */
	init_completion(&spfc_hba->hba_init_complete);
	init_completion(&spfc_hba->mbox_complete);
	init_completion(&spfc_hba->vpf_complete);
	init_completion(&spfc_hba->fcfi_complete);
	init_completion(&spfc_hba->get_sfp_complete);
	/* Step-1: initialize the communication channel between driver and uP */
	ret = spfc_initial_chip_access(spfc_hba);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]SPFC port(0x%x) can't initialize chip access",
			     spfc_hba->port_cfg.port_id);

		goto out_unmap_memory;
	}
	/* Step-2: get chip configuration information before creating
	 * queue resources
	 */
	ret = spfc_get_chip_info(spfc_hba);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]SPFC port(0x%x) can't get chip information",
			     spfc_hba->port_cfg.port_id);

		goto out_unmap_memory;
	}

	/* Step-3: create queue resources */
	ret = spfc_create_queues(spfc_hba);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]SPFC port(0x%x) can't create queues",
			     spfc_hba->port_cfg.port_id);

		goto out_release_chip_access;
	}
	/* Allocate DMA buffer (SFP information) */
	ret = spfc_alloc_dma_buffers(spfc_hba);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]SPFC port(0x%x) can't allocate DMA buffers",
			     spfc_hba->port_cfg.port_id);

		goto out_destroy_queues;
	}
	/* Initialize status parameters */
	spfc_hba->active_port_speed = UNF_PORT_SPEED_UNKNOWN;
	spfc_hba->active_topo = UNF_ACT_TOP_UNKNOWN;
	spfc_hba->sfp_on = false;
	spfc_hba->port_loop_role = UNF_LOOP_ROLE_MASTER_OR_SLAVE;
	spfc_hba->phy_link = UNF_PORT_LINK_DOWN;
	spfc_hba->queue_set_stage = SPFC_QUEUE_SET_STAGE_INIT;

	/* Initialize parameters referring to the lowlevel */
	spfc_hba->remote_rttov_tag = 0;
	spfc_hba->port_bb_scn_cfg = SPFC_LOWLEVEL_DEFAULT_BB_SCN;

	/* Initialize timer, and the unit of E_D_TOV is ms */
	spfc_hba->remote_edtov_tag = 0;
	spfc_hba->remote_bb_credit = 0;
	spfc_hba->compared_bb_scn = 0;
	spfc_hba->compared_edtov_val = UNF_DEFAULT_EDTOV;
	spfc_hba->compared_ratov_val = UNF_DEFAULT_RATOV;
	spfc_hba->removing = false;
	spfc_hba->dev_present = true;

	/* Initialize parameters about cos */
	spfc_hba->cos_bitmap = cos_bit_map;
	memset(spfc_hba->cos_rport_cnt, 0, SPFC_MAX_COS_NUM * sizeof(atomic_t));

	/* Mailbox access completion */
	complete(&spfc_hba->mbox_complete);

	ret = spfc_alloc_default_session(spfc_hba);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]SPFC port(0x%x) can't allocate Default Session",
			     spfc_hba->port_cfg.port_id);

		goto out_destroy_dma_buff;
	}

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
		     "[info]SPFC port(0x%x) initialize host resources succeeded",
		     spfc_hba->port_cfg.port_id);

	return ret;

out_destroy_dma_buff:
	spfc_free_dma_buffers(spfc_hba);
out_destroy_queues:
	spfc_flush_scq_ctx(spfc_hba);
	spfc_flush_srq_ctx(spfc_hba);
	spfc_destroy_queues(spfc_hba);

out_release_chip_access:
	spfc_release_chip_access(spfc_hba);

out_unmap_memory:
	return ret;
}

static u32 spfc_get_chip_info(struct spfc_hba_info *hba)
{
	u32 ret = RETURN_OK;
	u32 exi_count = 0;
	u32 exi_base = 0;
	u32 exi_stride = 0;
	u32 fun_idx = 0;

	FC_CHECK_RETURN_VALUE(hba, UNF_RETURN_ERROR);

	hba->vpid_start = hba->service_cap.dev_fc_cap.vp_id_start;
	hba->vpid_end = hba->service_cap.dev_fc_cap.vp_id_end;
	fun_idx = sphw_global_func_id(hba->dev_handle);

	exi_count = (max_parent_qpc_num <= SPFC_MAX_PARENT_QPC_NUM) ?
		     exit_count >> UNF_SHIFT_1 : exit_count;
	exi_stride = (max_parent_qpc_num <= SPFC_MAX_PARENT_QPC_NUM) ?
		      exit_stride >> UNF_SHIFT_1 : exit_stride;
	exi_base = exit_base;

	exi_base += (fun_idx * exi_stride);
	hba->exi_base = SPFC_LSW(exi_base);
	hba->exi_count = SPFC_LSW(exi_count);
	hba->max_support_speed = max_speed;
	hba->port_index = SPFC_LSB(fun_idx);

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
		     "[info]Port(0x%x) base information: PortIndex=0x%x, ExiBase=0x%x, ExiCount=0x%x, VpIdStart=0x%x, VpIdEnd=0x%x, MaxSpeed=0x%x, Speed=0x%x, Topo=0x%x",
		     hba->port_cfg.port_id, hba->port_index, hba->exi_base,
		     hba->exi_count, hba->vpid_start, hba->vpid_end,
		     hba->max_support_speed, hba->port_speed_cfg, hba->port_topo_cfg);

	return ret;
}

static u32 spfc_initial_chip_access(struct spfc_hba_info *hba)
{
	int ret = RETURN_OK;

	FC_CHECK_RETURN_VALUE(hba, UNF_RETURN_ERROR);

	/* 1. Initialize cqm access related with scq, emb cq, aeq(ucode-->driver) */
	service_cqm_temp.service_handle = hba;

	ret = cqm3_service_register(hba->dev_handle, &service_cqm_temp);
	if (ret != CQM_SUCCESS)
		return UNF_RETURN_ERROR;

	/* 2. Initialize mailbox(driver-->up), aeq(up--->driver) access */
	ret = sphw_register_mgmt_msg_cb(hba->dev_handle, COMM_MOD_FC, hba,
					spfc_up_msg2driver_proc);
	if (ret != CQM_SUCCESS)
		goto out_unreg_cqm;

	return RETURN_OK;

out_unreg_cqm:
	cqm3_service_unregister(hba->dev_handle, SERVICE_T_FC);

	return UNF_RETURN_ERROR;
}

static void spfc_release_chip_access(struct spfc_hba_info *hba)
{
	FC_CHECK_RETURN_VOID(hba);
	FC_CHECK_RETURN_VOID(hba->dev_handle);

	sphw_unregister_mgmt_msg_cb(hba->dev_handle, COMM_MOD_FC);

	cqm3_service_unregister(hba->dev_handle, SERVICE_T_FC);
}

static void spfc_update_lport_config(struct spfc_hba_info *hba,
				     struct unf_low_level_functioon_op *lowlevel_func)
{
#define SPFC_MULTI_CONF_NONSUPPORT 0

	struct unf_lport_cfg_item *lport_cfg = NULL;

	lport_cfg = &lowlevel_func->lport_cfg_items;

	if (hba->port_cfg.max_login < lowlevel_func->support_max_rport)
		lport_cfg->max_login = hba->port_cfg.max_login;
	else
		lport_cfg->max_login = lowlevel_func->support_max_rport;

	if (hba->port_cfg.sest_num >> UNF_SHIFT_1 < UNF_RESERVE_SFS_XCHG)
		lport_cfg->max_io = hba->port_cfg.sest_num;
	else
		lport_cfg->max_io = hba->port_cfg.sest_num - UNF_RESERVE_SFS_XCHG;

	lport_cfg->max_sfs_xchg = UNF_MAX_SFS_XCHG;
	lport_cfg->port_id = hba->port_cfg.port_id;
	lport_cfg->port_mode = hba->port_cfg.port_mode;
	lport_cfg->port_topology = hba->port_cfg.port_topology;
	lport_cfg->max_queue_depth = hba->port_cfg.max_queue_depth;

	lport_cfg->port_speed = hba->port_cfg.port_speed;
	lport_cfg->tape_support = hba->port_cfg.tape_support;

	lowlevel_func->sys_port_name = *(u64 *)hba->sys_port_name;
	lowlevel_func->sys_node_name = *(u64 *)hba->sys_node_name;

	/* Update chip information */
	lowlevel_func->dev = hba->pci_dev;
	lowlevel_func->chip_info.chip_work_mode = hba->work_mode;
	lowlevel_func->chip_info.chip_type = hba->chip_type;
	lowlevel_func->chip_info.disable_err_flag = 0;
	lowlevel_func->support_max_speed = hba->max_support_speed;
	lowlevel_func->support_min_speed = hba->min_support_speed;

	lowlevel_func->chip_id = 0;

	lowlevel_func->sfp_type = UNF_PORT_TYPE_FC_SFP;

	lowlevel_func->multi_conf_support = SPFC_MULTI_CONF_NONSUPPORT;
	lowlevel_func->support_max_hot_tag_range = hba->port_cfg.sest_num;
	lowlevel_func->update_fw_reset_active = UNF_PORT_UNGRADE_FW_RESET_INACTIVE;
	lowlevel_func->port_type = 0; /* DRV_PORT_ENTITY_TYPE_PHYSICAL */

	if ((lport_cfg->port_id & UNF_FIRST_LPORT_ID_MASK) == lport_cfg->port_id)
		lowlevel_func->support_upgrade_report = UNF_PORT_SUPPORT_UPGRADE_REPORT;
	else
		lowlevel_func->support_upgrade_report = UNF_PORT_UNSUPPORT_UPGRADE_REPORT;
}

static u32 spfc_create_lport(struct spfc_hba_info *hba)
{
	void *lport = NULL;
	struct unf_low_level_functioon_op lowlevel_func;

	FC_CHECK_RETURN_VALUE(hba, UNF_RETURN_ERROR);
	spfc_func_op.dev = hba->pci_dev;
	memcpy(&lowlevel_func, &spfc_func_op, sizeof(struct unf_low_level_functioon_op));

	/* Update port configuration table */
	spfc_update_lport_config(hba, &lowlevel_func);

	/* Apply for lport resources */
	UNF_LOWLEVEL_ALLOC_LPORT(lport, hba, &lowlevel_func);
	if (!lport) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Port(0x%x) can't allocate Lport",
			     hba->port_cfg.port_id);

		return UNF_RETURN_ERROR;
	}
	hba->lport = lport;

	return RETURN_OK;
}

void spfc_release_probe_index(u32 probe_index)
{
	if (probe_index >= SPFC_MAX_PROBE_PORT_NUM) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
			     "[warn]Probe index(0x%x) is invalid", probe_index);

		return;
	}

	spin_lock(&probe_spin_lock);
	if (!test_bit((int)probe_index, (const ulong *)probe_bit_map)) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
			     "[warn]Probe index(0x%x) is not probed",
			     probe_index);

		spin_unlock(&probe_spin_lock);

		return;
	}

	clear_bit((int)probe_index, probe_bit_map);
	spin_unlock(&probe_spin_lock);
}

static void spfc_delete_default_session(struct spfc_hba_info *hba)
{
	struct unf_port_info rport_info = {0};

	rport_info.nport_id = 0xffffff;
	rport_info.rport_index = SPFC_DEFAULT_RPORT_INDEX;
	rport_info.local_nport_id = 0xffffff;
	rport_info.port_name = 0;
	rport_info.cs_ctrl = 0x81;

	/* Need config table to up first, then delete default session */
	(void)spfc_mbx_config_default_session(hba, 0);
	spfc_sess_resource_free_sync((void *)hba, &rport_info);
}

static void spfc_release_host_res(struct spfc_hba_info *hba)
{
	spfc_free_dma_buffers(hba);

	spfc_destroy_queues(hba);

	spfc_release_chip_access(hba);

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[info]Port(0x%x) release low level resource done",
		     hba->port_cfg.port_id);
}

static struct spfc_hba_info *spfc_init_hba(struct pci_dev *pci_dev,
					   void *hw_dev_handle,
					   struct spfc_chip_info *chip_info,
					   u8 card_num)
{
	u32 ret = RETURN_OK;
	struct spfc_hba_info *hba = NULL;

	FC_CHECK_RETURN_VALUE(pci_dev, NULL);
	FC_CHECK_RETURN_VALUE(hw_dev_handle, NULL);

	/* Allocate HBA */
	hba = kmalloc(sizeof(struct spfc_hba_info), GFP_ATOMIC);
	FC_CHECK_RETURN_VALUE(hba, NULL);
	memset(hba, 0, sizeof(struct spfc_hba_info));

	/* Heartbeat default */
	hba->heart_status = 1;
	/* Private data in pciDev */
	hba->pci_dev = pci_dev;
	hba->dev_handle = hw_dev_handle;

	/* Work mode */
	hba->work_mode = chip_info->work_mode;
	/* Create work queue */
	hba->work_queue = create_singlethread_workqueue("spfc");
	if (!hba->work_queue) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
			     "[err]Spfc creat workqueue failed");

		goto out_free_hba;
	}
	/* Init delay work */
	INIT_DELAYED_WORK(&hba->srq_delay_info.del_work, spfc_rcvd_els_from_srq_timeout);
	INIT_WORK(&hba->els_srq_clear_work, spfc_wq_destroy_els_srq);

	/* Notice: Only use FC features */
	(void)sphw_support_fc(hw_dev_handle, &hba->service_cap);
	/* Check parent context available */
	if (hba->service_cap.dev_fc_cap.max_parent_qpc_num == 0) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]FC parent context is not allocated in this function");

		goto out_destroy_workqueue;
	}
	max_parent_qpc_num = hba->service_cap.dev_fc_cap.max_parent_qpc_num;

	/* Get port configuration */
	ret = spfc_get_port_cfg(hba, chip_info, card_num);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
			     "[err]Can't get port configuration");

		goto out_destroy_workqueue;
	}
	/* Get WWN */
	spfc_generate_sys_wwn(hba);

	/* Initialize host resources */
	ret = spfc_init_host_res(hba);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]SPFC port(0x%x) can't initialize host resource",
			     hba->port_cfg.port_id);

		goto out_destroy_workqueue;
	}
	/* Local Port create */
	ret = spfc_create_lport(hba);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]SPFC port(0x%x) can't create lport",
			     hba->port_cfg.port_id);
		goto out_release_host_res;
	}
	complete(&hba->hba_init_complete);

	/* Print reference count */
	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_KEVENT,
		     "[info]Port(0x%x) probe succeeded. Memory reference is 0x%x",
		     hba->port_cfg.port_id, atomic_read(&fc_mem_ref));

	return hba;

out_release_host_res:
	spfc_delete_default_session(hba);
	spfc_flush_scq_ctx(hba);
	spfc_flush_srq_ctx(hba);
	spfc_release_host_res(hba);

out_destroy_workqueue:
	flush_workqueue(hba->work_queue);
	destroy_workqueue(hba->work_queue);
	hba->work_queue = NULL;

out_free_hba:
	kfree(hba);

	return NULL;
}

void spfc_get_total_probed_num(u32 *probe_cnt)
{
	u32 i = 0;
	u32 cnt = 0;

	spin_lock(&probe_spin_lock);
	for (i = 0; i < SPFC_MAX_PROBE_PORT_NUM; i++) {
		if (test_bit((int)i, (const ulong *)probe_bit_map))
			cnt++;
	}

	*probe_cnt = cnt;
	spin_unlock(&probe_spin_lock);

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_INFO,
		     "[info]Probed port total number is 0x%x", cnt);
}

u32 spfc_assign_card_num(struct spfc_lld_dev *lld_dev,
			 struct spfc_chip_info *chip_info, u8 *card_num)
{
	u8 i = 0;
	u64 card_index = 0;

	card_index = (!pci_is_root_bus(lld_dev->pdev->bus)) ?
		      lld_dev->pdev->bus->parent->number : lld_dev->pdev->bus->number;

	spin_lock(&probe_spin_lock);

	for (i = 0; i < SPFC_MAX_CARD_NUM; i++) {
		if (test_bit((int)i, (const ulong *)card_num_bit_map)) {
			if (card_num_manage[i].card_number ==
			    card_index && !card_num_manage[i].is_removing
			) {
				card_num_manage[i].port_count++;
				*card_num = i;
				spin_unlock(&probe_spin_lock);
				return RETURN_OK;
			}
		}
	}

	for (i = 0; i < SPFC_MAX_CARD_NUM; i++) {
		if (!test_bit((int)i, (const ulong *)card_num_bit_map)) {
			card_num_manage[i].card_number = card_index;
			card_num_manage[i].port_count = 1;
			card_num_manage[i].is_removing = false;

			*card_num = i;
			set_bit(i, card_num_bit_map);

			spin_unlock(&probe_spin_lock);

			return RETURN_OK;
		}
	}

	spin_unlock(&probe_spin_lock);

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
		     "[err]Have probe more than 0x%x port, probe failed", i);

	return UNF_RETURN_ERROR;
}

static void spfc_dec_and_free_card_num(u8 card_num)
{
	/* 2 ports per card */
	if (card_num >= SPFC_MAX_CARD_NUM) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Card number(0x%x) is invalid", card_num);

		return;
	}

	spin_lock(&probe_spin_lock);

	if (test_bit((int)card_num, (const ulong *)card_num_bit_map)) {
		card_num_manage[card_num].port_count--;
		card_num_manage[card_num].is_removing = true;

		if (card_num_manage[card_num].port_count == 0) {
			card_num_manage[card_num].card_number = 0;
			card_num_manage[card_num].is_removing = false;
			clear_bit((int)card_num, card_num_bit_map);
		}
	} else {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Can not find card number(0x%x)", card_num);
	}

	spin_unlock(&probe_spin_lock);
}

u32 spfc_assign_probe_index(u32 *probe_index)
{
	u32 i = 0;

	spin_lock(&probe_spin_lock);
	for (i = 0; i < SPFC_MAX_PROBE_PORT_NUM; i++) {
		if (!test_bit((int)i, (const ulong *)probe_bit_map)) {
			*probe_index = i;
			set_bit(i, probe_bit_map);

			spin_unlock(&probe_spin_lock);

			return RETURN_OK;
		}
	}
	spin_unlock(&probe_spin_lock);

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
		     "[err]Have probe more than 0x%x port, probe failed", i);

	return UNF_RETURN_ERROR;
}

u32 spfc_get_probe_index_by_port_id(u32 port_id, u32 *probe_index)
{
	u32 total_probe_num = 0;
	u32 i = 0;
	u32 probe_cnt = 0;

	spfc_get_total_probed_num(&total_probe_num);

	for (i = 0; i < SPFC_MAX_PROBE_PORT_NUM; i++) {
		if (!spfc_hba[i])
			continue;

		if (total_probe_num == probe_cnt)
			break;

		if (port_id == spfc_hba[i]->port_cfg.port_id) {
			*probe_index = spfc_hba[i]->probe_index;

			return RETURN_OK;
		}

		probe_cnt++;
	}

	return UNF_RETURN_ERROR;
}

static int spfc_probe(struct spfc_lld_dev *lld_dev, void **uld_dev,
		      char *uld_dev_name)
{
	struct pci_dev *pci_dev = NULL;
	struct spfc_hba_info *hba = NULL;
	u32 ret = UNF_RETURN_ERROR;
	const u8 work_mode = SPFC_SMARTIO_WORK_MODE_FC;
	u32 probe_index = 0;
	u32 probe_total_num = 0;
	u8 card_num = INVALID_VALUE8;
	struct spfc_chip_info chip_info;

	FC_CHECK_RETURN_VALUE(lld_dev, UNF_RETURN_ERROR_S32);
	FC_CHECK_RETURN_VALUE(lld_dev->hwdev, UNF_RETURN_ERROR_S32);
	FC_CHECK_RETURN_VALUE(lld_dev->pdev, UNF_RETURN_ERROR_S32);
	FC_CHECK_RETURN_VALUE(uld_dev, UNF_RETURN_ERROR_S32);
	FC_CHECK_RETURN_VALUE(uld_dev_name, UNF_RETURN_ERROR_S32);

	pci_dev = lld_dev->pdev;
	memset(&chip_info, 0, sizeof(struct spfc_chip_info));
	/* 1. Get & check Total_Probed_number */
	spfc_get_total_probed_num(&probe_total_num);
	if (probe_total_num >= allowed_probe_num) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Total probe num (0x%x) is larger than allowed number(0x%x)",
			     probe_total_num, allowed_probe_num);

		return UNF_RETURN_ERROR_S32;
	}
	/* 2. Check device work mode */
	ret = spfc_fc_mode_check(lld_dev->hwdev);
	if (ret != RETURN_OK)
		return UNF_RETURN_ERROR_S32;

	/* 3. Assign & Get new Probe index */
	ret = spfc_assign_probe_index(&probe_index);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]AssignProbeIndex fail");

		return UNF_RETURN_ERROR_S32;
	}

	ret = spfc_get_chip_capability((void *)lld_dev->hwdev, &chip_info);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]GetChipCapability fail");
		return UNF_RETURN_ERROR_S32;
	}
	chip_info.work_mode = work_mode;

	/* Assign & Get new Card number */
	ret = spfc_assign_card_num(lld_dev, &chip_info, &card_num);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]spfc_assign_card_num fail");
		spfc_release_probe_index(probe_index);

		return UNF_RETURN_ERROR_S32;
	}

	/* Init HBA resource */
	hba = spfc_init_hba(pci_dev, lld_dev->hwdev, &chip_info, card_num);
	if (!hba) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Probe HBA(0x%x) failed. Memory reference = 0x%x",
			     probe_index, atomic_read(&fc_mem_ref));

		spfc_release_probe_index(probe_index);
		spfc_dec_and_free_card_num(card_num);

		return UNF_RETURN_ERROR_S32;
	}

	/* Name by the order of probe */
	*uld_dev = hba;
	snprintf(uld_dev_name, SPFC_PORT_NAME_STR_LEN, "%s%02x%02x",
		 SPFC_PORT_NAME_LABEL, hba->card_info.card_num,
		 hba->card_info.func_num);
	memcpy(hba->port_name, uld_dev_name, SPFC_PORT_NAME_STR_LEN);
	hba->probe_index = probe_index;
	spfc_hba[probe_index] = hba;

	return RETURN_OK;
}

u32 spfc_sfp_switch(void *hba, void *para_in)
{
	struct spfc_hba_info *spfc_hba = (struct spfc_hba_info *)hba;
	bool turn_on = false;
	u32 ret = RETURN_OK;

	FC_CHECK_RETURN_VALUE(spfc_hba, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(para_in, UNF_RETURN_ERROR);

	/* Redundancy check */
	turn_on = *((bool *)para_in);
	if ((u32)turn_on == (u32)spfc_hba->sfp_on) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_INFO,
			     "[info]Port(0x%x) FC physical port is already %s",
			     spfc_hba->port_cfg.port_id, (turn_on) ? "on" : "off");

		return ret;
	}

	if (turn_on) {
		ret = spfc_port_check_fw_ready(spfc_hba);
		if (ret != RETURN_OK) {
			FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
				     "[warn]Get port(0x%x) clear state failed, turn on fail",
				     spfc_hba->port_cfg.port_id);
			return ret;
		}
		/* At first, configure port table info if necessary */
		ret = spfc_config_port_table(spfc_hba);
		if (ret != RETURN_OK) {
			FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
				     "[err]Port(0x%x) can't configurate port table",
				     spfc_hba->port_cfg.port_id);

			return ret;
		}
	}

	/* Switch physical port */
	ret = spfc_port_switch(spfc_hba, turn_on);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
			     "[err]Port(0x%x) switch failed",
			     spfc_hba->port_cfg.port_id);

		return ret;
	}

	/* Update HBA's sfp state */
	spfc_hba->sfp_on = turn_on;

	return ret;
}

static u32 spfc_destroy_lport(struct spfc_hba_info *hba)
{
	u32 ret = UNF_RETURN_ERROR;

	FC_CHECK_RETURN_VALUE(hba, UNF_RETURN_ERROR);

	UNF_LOWLEVEL_RELEASE_LOCAL_PORT(ret, hba->lport);
	hba->lport = NULL;

	FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
		     "[info]Port(0x%x) destroy L_Port done",
		     hba->port_cfg.port_id);

	return ret;
}

static u32 spfc_port_check_fw_ready(struct spfc_hba_info *hba)
{
#define SPFC_PORT_CLEAR_DONE 0
#define SPFC_PORT_CLEAR_DOING 1
#define SPFC_WAIT_ONE_TIME_MS 1000
#define SPFC_LOOP_TIMES 30

	u32 clear_state = SPFC_PORT_CLEAR_DOING;
	u32 ret = RETURN_OK;
	u32 wait_timeout = 0;

	do {
		msleep(SPFC_WAIT_ONE_TIME_MS);
		wait_timeout += SPFC_WAIT_ONE_TIME_MS;
		ret = spfc_mbx_get_fw_clear_stat(hba, &clear_state);
		if (ret != RETURN_OK)
			return UNF_RETURN_ERROR;

		/* Total time more than 30s retry more than 3 times failed */
		if (wait_timeout > SPFC_LOOP_TIMES * SPFC_WAIT_ONE_TIME_MS &&
		    clear_state != SPFC_PORT_CLEAR_DONE)
			return UNF_RETURN_ERROR;
	} while (clear_state != SPFC_PORT_CLEAR_DONE);

	return RETURN_OK;
}

u32 spfc_port_reset(struct spfc_hba_info *hba)
{
	u32 ret = RETURN_OK;
	ulong timeout = 0;
	bool sfp_before_reset = false;
	bool off_para_in = false;
	struct pci_dev *pci_dev = NULL;
	struct spfc_hba_info *spfc_hba = hba;

	FC_CHECK_RETURN_VALUE(spfc_hba, UNF_RETURN_ERROR);
	pci_dev = spfc_hba->pci_dev;
	FC_CHECK_RETURN_VALUE(pci_dev, UNF_RETURN_ERROR);

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_KEVENT,
		     "[event]Port(0x%x) reset HBA begin",
		     spfc_hba->port_cfg.port_id);

	/* Wait for last init/reset completion */
	timeout = wait_for_completion_timeout(&spfc_hba->hba_init_complete,
					      (ulong)SPFC_PORT_INIT_TIME_SEC_MAX * HZ);

	if (timeout == SPFC_ZERO) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Last HBA initialize/reset timeout: %d second",
			     SPFC_PORT_INIT_TIME_SEC_MAX);

		return UNF_RETURN_ERROR;
	}

	/* Save current port state */
	sfp_before_reset = spfc_hba->sfp_on;

	/* Inform the reset event to CM level before beginning */
	UNF_LOWLEVEL_PORT_EVENT(ret, spfc_hba->lport, UNF_PORT_RESET_START, NULL);
	spfc_hba->reset_time = jiffies;

	/* Close SFP */
	ret = spfc_sfp_switch(spfc_hba, &off_para_in);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Port(0x%x) can't close SFP",
			     spfc_hba->port_cfg.port_id);
		spfc_hba->sfp_on = sfp_before_reset;

		complete(&spfc_hba->hba_init_complete);

		return ret;
	}

	ret = spfc_port_check_fw_ready(spfc_hba);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Get port(0x%x) clear state failed, hang port and report chip error",
			     spfc_hba->port_cfg.port_id);

		complete(&spfc_hba->hba_init_complete);

		return ret;
	}

	spfc_queue_pre_process(spfc_hba, false);

	ret = spfc_mb_reset_chip(spfc_hba, SPFC_MBOX_SUBTYPE_LIGHT_RESET);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]SPFC port(0x%x) can't reset chip mailbox",
			     spfc_hba->port_cfg.port_id);

		UNF_LOWLEVEL_PORT_EVENT(ret, spfc_hba->lport, UNF_PORT_GET_FWLOG, NULL);
		UNF_LOWLEVEL_PORT_EVENT(ret, spfc_hba->lport, UNF_PORT_DEBUG_DUMP, NULL);
	}

	/* Inform the success to CM level */
	UNF_LOWLEVEL_PORT_EVENT(ret, spfc_hba->lport, UNF_PORT_RESET_END, NULL);

	/* Queue open */
	spfc_queue_post_process(spfc_hba);

	/* Open SFP */
	(void)spfc_sfp_switch(spfc_hba, &sfp_before_reset);

	complete(&spfc_hba->hba_init_complete);

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
		     "[event]Port(0x%x) reset HBA done",
		     spfc_hba->port_cfg.port_id);

	return ret;
#undef SPFC_WAIT_LINKDOWN_EVENT_MS
}

static u32 spfc_delete_scqc_via_cmdq_sync(struct spfc_hba_info *hba, u32 scqn)
{
	/* Via CMND Queue */
#define SPFC_DEL_SCQC_TIMEOUT 3000

	int ret;
	struct spfc_cmdqe_delete_scqc del_scqc_cmd;
	struct sphw_cmd_buf *cmd_buf;

	/* Alloc cmd buffer */
	cmd_buf = sphw_alloc_cmd_buf(hba->dev_handle);
	if (!cmd_buf) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_ERR,
			     "[err]cmdq in_cmd_buf alloc failed");

		SPFC_ERR_IO_STAT(hba, SPFC_TASK_T_DEL_SCQC);
		return UNF_RETURN_ERROR;
	}

	/* Build & Send Cmnd */
	memset(&del_scqc_cmd, 0, sizeof(del_scqc_cmd));
	del_scqc_cmd.wd0.task_type = SPFC_TASK_T_DEL_SCQC;
	del_scqc_cmd.wd1.scqn = SPFC_LSW(scqn);
	spfc_cpu_to_big32(&del_scqc_cmd, sizeof(del_scqc_cmd));
	memcpy(cmd_buf->buf, &del_scqc_cmd, sizeof(del_scqc_cmd));
	cmd_buf->size = sizeof(del_scqc_cmd);

	ret = sphw_cmdq_detail_resp(hba->dev_handle, COMM_MOD_FC, 0, cmd_buf,
				    NULL, NULL, SPFC_DEL_SCQC_TIMEOUT,
				    SPHW_CHANNEL_FC);

	/* Free cmnd buffer */
	sphw_free_cmd_buf(hba->dev_handle, cmd_buf);

	if (ret) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_ERR,
			     "[err]Send del scqc via cmdq failed, ret=0x%x",
			     ret);

		SPFC_ERR_IO_STAT(hba, SPFC_TASK_T_DEL_SCQC);
		return UNF_RETURN_ERROR;
	}

	SPFC_IO_STAT(hba, SPFC_TASK_T_DEL_SCQC);

	return RETURN_OK;
}

static u32 spfc_delete_srqc_via_cmdq_sync(struct spfc_hba_info *hba, u64 sqrc_gpa)
{
	/* Via CMND Queue */
#define SPFC_DEL_SRQC_TIMEOUT 3000

	int ret;
	struct spfc_cmdqe_delete_srqc del_srqc_cmd;
	struct sphw_cmd_buf *cmd_buf;

	/* Alloc Cmnd buffer */
	cmd_buf = sphw_alloc_cmd_buf(hba->dev_handle);
	if (!cmd_buf) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_ERR,
			     "[err]cmdq in_cmd_buf allocate failed");

		SPFC_ERR_IO_STAT(hba, SPFC_TASK_T_DEL_SRQC);
		return UNF_RETURN_ERROR;
	}

	/* Build & Send Cmnd */
	memset(&del_srqc_cmd, 0, sizeof(del_srqc_cmd));
	del_srqc_cmd.wd0.task_type = SPFC_TASK_T_DEL_SRQC;
	del_srqc_cmd.srqc_gpa_h = SPFC_HIGH_32_BITS(sqrc_gpa);
	del_srqc_cmd.srqc_gpa_l = SPFC_LOW_32_BITS(sqrc_gpa);
	spfc_cpu_to_big32(&del_srqc_cmd, sizeof(del_srqc_cmd));
	memcpy(cmd_buf->buf, &del_srqc_cmd, sizeof(del_srqc_cmd));
	cmd_buf->size = sizeof(del_srqc_cmd);

	ret = sphw_cmdq_detail_resp(hba->dev_handle, COMM_MOD_FC, 0, cmd_buf,
				    NULL, NULL, SPFC_DEL_SRQC_TIMEOUT,
				    SPHW_CHANNEL_FC);

	/* Free Cmnd Buffer */
	sphw_free_cmd_buf(hba->dev_handle, cmd_buf);

	if (ret) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_ERR,
			     "[err]Send del srqc via cmdq failed, ret=0x%x",
			     ret);

		SPFC_ERR_IO_STAT(hba, SPFC_TASK_T_DEL_SRQC);
		return UNF_RETURN_ERROR;
	}

	SPFC_IO_STAT(hba, SPFC_TASK_T_DEL_SRQC);

	return RETURN_OK;
}

void spfc_flush_scq_ctx(struct spfc_hba_info *hba)
{
	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
		     "[info]Start destroy total 0x%x SCQC", SPFC_TOTAL_SCQ_NUM);

	FC_CHECK_RETURN_VOID(hba);

	(void)spfc_delete_scqc_via_cmdq_sync(hba, 0);
}

void spfc_flush_srq_ctx(struct spfc_hba_info *hba)
{
	struct spfc_srq_info *srq_info = NULL;

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
		     "[info]Start destroy ELS&IMMI SRQC");

	FC_CHECK_RETURN_VOID(hba);

	/* Check state to avoid to flush SRQC again */
	srq_info = &hba->els_srq_info;
	if (srq_info->srq_type == SPFC_SRQ_ELS && srq_info->enable) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_MAJOR,
			     "[event]HBA(0x%x) flush ELS SRQC",
			     hba->port_index);

		(void)spfc_delete_srqc_via_cmdq_sync(hba, srq_info->cqm_srq_info->q_ctx_paddr);
	}
}

void spfc_set_hba_flush_state(struct spfc_hba_info *hba, bool in_flush)
{
	ulong flag = 0;

	spin_lock_irqsave(&hba->flush_state_lock, flag);
	hba->in_flushing = in_flush;
	spin_unlock_irqrestore(&hba->flush_state_lock, flag);
}

void spfc_set_hba_clear_state(struct spfc_hba_info *hba, bool clear_flag)
{
	ulong flag = 0;

	spin_lock_irqsave(&hba->clear_state_lock, flag);
	hba->port_is_cleared = clear_flag;
	spin_unlock_irqrestore(&hba->clear_state_lock, flag);
}

bool spfc_hba_is_present(struct spfc_hba_info *hba)
{
	int ret_val = RETURN_OK;
	bool present_flag = false;
	u32 vendor_id = 0;

	ret_val = pci_read_config_dword(hba->pci_dev, 0, &vendor_id);
	vendor_id &= SPFC_PCI_VENDOR_ID_MASK;
	if (ret_val == RETURN_OK && vendor_id == SPFC_PCI_VENDOR_ID_RAMAXEL) {
		present_flag = true;
	} else {
		present_flag = false;
		hba->dev_present = false;
	}

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_KEVENT,
		     "[info]Port %s remove: vender_id=0x%x, ret=0x%x",
		     present_flag ? "normal" : "surprise", vendor_id, ret_val);

	return present_flag;
}

static void spfc_exit(struct pci_dev *pci_dev, struct spfc_hba_info *hba)
{
#define SPFC_WAIT_CLR_RESOURCE_MS 1000
	u32 ret = UNF_RETURN_ERROR;
	bool sfp_switch = false;
	bool present_flag = true;

	FC_CHECK_RETURN_VOID(pci_dev);
	FC_CHECK_RETURN_VOID(hba);

	hba->removing = true;

	/* 1. Check HBA present or not */
	present_flag = spfc_hba_is_present(hba);
	if (present_flag) {
		if (hba->phy_link == UNF_PORT_LINK_DOWN)
			hba->queue_set_stage = SPFC_QUEUE_SET_STAGE_FLUSHDONE;

		/* At first, close sfp */
		sfp_switch = false;
		(void)spfc_sfp_switch((void *)hba, (void *)&sfp_switch);
	}

	/* 2. Report COM with HBA removing: delete route timer delay work */
	UNF_LOWLEVEL_PORT_EVENT(ret, hba->lport, UNF_PORT_BEGIN_REMOVE, NULL);

	/* 3. Report COM with HBA Nop, COM release I/O(s) & R_Port(s) forcely */
	UNF_LOWLEVEL_PORT_EVENT(ret, hba->lport, UNF_PORT_NOP, NULL);
	if (ret != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]PCI device(%p) remove port(0x%x) failed",
			     pci_dev, hba->port_index);
	}

	spfc_delete_default_session(hba);

	if (present_flag)
		/* 4.1 Wait for all SQ empty, free SRQ buffer & SRQC */
		spfc_queue_pre_process(hba, true);

	/* 5. Destroy L_Port */
	(void)spfc_destroy_lport(hba);

	/* 6. With HBA is present */
	if (present_flag) {
		/* Enable Queues dispatch */
		spfc_queue_post_process(hba);

		/* Need reset port if necessary */
		(void)spfc_mb_reset_chip(hba, SPFC_MBOX_SUBTYPE_HEAVY_RESET);

		/* Flush SCQ context */
		spfc_flush_scq_ctx(hba);

		/* Flush SRQ context */
		spfc_flush_srq_ctx(hba);

		sphw_func_rx_tx_flush(hba->dev_handle, SPHW_CHANNEL_FC);

		/* NOTE: while flushing txrx, hash bucket will be cached out in
		 * UP. Wait to clear resources completely
		 */
		msleep(SPFC_WAIT_CLR_RESOURCE_MS);

		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_MAJOR,
			     "[info]Port(0x%x) flush scq & srq & root context done",
			     hba->port_cfg.port_id);
	}

	/* 7. Release host resources */
	spfc_release_host_res(hba);

	/* 8. Destroy FC work queue */
	if (hba->work_queue) {
		flush_workqueue(hba->work_queue);
		destroy_workqueue(hba->work_queue);
		hba->work_queue = NULL;
	}

	/* 9. Release Probe index & Decrease card number */
	spfc_release_probe_index(hba->probe_index);
	spfc_dec_and_free_card_num((u8)hba->card_info.card_num);

	/* 10. Free HBA memory */
	kfree(hba);

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
		     "[event]PCI device(%p) remove succeed, memory reference is 0x%x",
		     pci_dev, atomic_read(&fc_mem_ref));
}

static void spfc_remove(struct spfc_lld_dev *lld_dev, void *uld_dev)
{
	struct pci_dev *pci_dev = NULL;
	struct spfc_hba_info *hba = (struct spfc_hba_info *)uld_dev;
	u32 probe_total_num = 0;
	u32 probe_index = 0;

	FC_CHECK_RETURN_VOID(lld_dev);
	FC_CHECK_RETURN_VOID(uld_dev);
	FC_CHECK_RETURN_VOID(lld_dev->hwdev);
	FC_CHECK_RETURN_VOID(lld_dev->pdev);

	pci_dev = hba->pci_dev;

	/* Get total probed port number */
	spfc_get_total_probed_num(&probe_total_num);
	if (probe_total_num < 1) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
			     "[warn]Port manager is empty and no need to remove");
		return;
	}

	/* check pci vendor id */
	if (pci_dev->vendor != SPFC_PCI_VENDOR_ID_RAMAXEL) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,
			     "[warn]Wrong vendor id(0x%x) and exit",
			     pci_dev->vendor);
		return;
	}

	/* Check function ability */
	if (!sphw_support_fc(lld_dev->hwdev, NULL)) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]FC is not enable in this function");
		return;
	}

	/* Get probe index */
	probe_index = hba->probe_index;

	/* Parent context alloc check */
	if (hba->service_cap.dev_fc_cap.max_parent_qpc_num == 0) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]FC parent context not allocate in this function");
		return;
	}

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
		     "[info]HBA(0x%x) start removing...", hba->port_index);

	/* HBA removinig... */
	spfc_exit(pci_dev, hba);

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_KEVENT,
		     "[event]Port(0x%x) pci device removed, vendorid(0x%04x) devid(0x%04x)",
		     probe_index, pci_dev->vendor, pci_dev->device);

	/* Probe index check */
	if (probe_index < SPFC_HBA_PORT_MAX_NUM) {
		spfc_hba[probe_index] = NULL;
	} else {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]Probe index(0x%x) is invalid and remove failed",
			     probe_index);
	}

	spfc_get_total_probed_num(&probe_total_num);

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_MAJOR,
		     "[event]Removed index=%u, RemainNum=%u, AllowNum=%u",
		     probe_index, probe_total_num, allowed_probe_num);
}

static u32 spfc_get_hba_pcie_link_state(void *hba, void *link_state)
{
	bool *link_state_info = link_state;
	bool present_flag = true;
	struct spfc_hba_info *spfc_hba = hba;
	int ret;
	bool last_dev_state = true;
	bool cur_dev_state = true;

	FC_CHECK_RETURN_VALUE(hba, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(link_state, UNF_RETURN_ERROR);
	last_dev_state = spfc_hba->dev_present;
	ret = sphw_get_card_present_state(spfc_hba->dev_handle, (bool *)&present_flag);
	if (ret || !present_flag) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_KEVENT,
			     "[event]port(0x%x) is not present,ret:%d, present_flag:%d",
			     spfc_hba->port_cfg.port_id, ret, present_flag);
		cur_dev_state = false;
	} else {
		cur_dev_state = true;
	}

	spfc_hba->dev_present = cur_dev_state;

	/* To prevent false alarms, the heartbeat is considered lost only
	 * when the PCIe link is down for two consecutive times.
	 */
	if (!last_dev_state && !cur_dev_state)
		spfc_hba->heart_status = false;

	*link_state_info = spfc_hba->dev_present;

	return RETURN_OK;
}
