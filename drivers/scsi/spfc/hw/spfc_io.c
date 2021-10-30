// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#include "spfc_io.h"
#include "spfc_module.h"
#include "spfc_service.h"

#define SPFC_SGE_WD1_XID_MASK 0x3fff

u32 dif_protect_opcode = INVALID_VALUE32;
u32 dif_app_esc_check = SPFC_DIF_APP_REF_ESC_CHECK;
u32 dif_ref_esc_check = SPFC_DIF_APP_REF_ESC_CHECK;
u32 grd_agm_ini_ctrl = SPFC_DIF_CRC_CS_INITIAL_CONFIG_BY_BIT0_1;
u32 ref_tag_no_increase;
u32 dix_flag;
u32 grd_ctrl;
u32 grd_agm_ctrl = SPFC_DIF_GUARD_VERIFY_ALGORITHM_CTL_T10_CRC16;
u32 cmp_app_tag_mask = 0xffff;
u32 app_tag_ctrl;
u32 ref_tag_ctrl;
u32 ref_tag_mod = INVALID_VALUE32;
u32 rep_ref_tag;
u32 rx_rep_ref_tag;
u16 cmp_app_tag;
u16 rep_app_tag;

static void spfc_dif_err_count(struct spfc_hba_info *hba, u8 info)
{
	u8 dif_info = info;

	if (dif_info & SPFC_TX_DIF_ERROR_FLAG) {
		SPFC_DIF_ERR_STAT(hba, SPFC_DIF_SEND_DIFERR_ALL);
		if (dif_info & SPFC_DIF_ERROR_CODE_CRC)
			SPFC_DIF_ERR_STAT(hba, SPFC_DIF_SEND_DIFERR_CRC);

		if (dif_info & SPFC_DIF_ERROR_CODE_APP)
			SPFC_DIF_ERR_STAT(hba, SPFC_DIF_SEND_DIFERR_APP);

		if (dif_info & SPFC_DIF_ERROR_CODE_REF)
			SPFC_DIF_ERR_STAT(hba, SPFC_DIF_SEND_DIFERR_REF);
	} else {
		SPFC_DIF_ERR_STAT(hba, SPFC_DIF_RECV_DIFERR_ALL);
		if (dif_info & SPFC_DIF_ERROR_CODE_CRC)
			SPFC_DIF_ERR_STAT(hba, SPFC_DIF_RECV_DIFERR_CRC);

		if (dif_info & SPFC_DIF_ERROR_CODE_APP)
			SPFC_DIF_ERR_STAT(hba, SPFC_DIF_RECV_DIFERR_APP);

		if (dif_info & SPFC_DIF_ERROR_CODE_REF)
			SPFC_DIF_ERR_STAT(hba, SPFC_DIF_RECV_DIFERR_REF);
	}
}

void spfc_build_no_dif_control(struct unf_frame_pkg *pkg,
			       struct spfc_fc_dif_info *info)
{
	struct spfc_fc_dif_info *dif_info = info;

	/* dif enable or disable */
	dif_info->wd0.difx_en = SPFC_DIF_DISABLE;

	dif_info->wd1.vpid = pkg->qos_level;
	dif_info->wd1.lun_qos_en = 1;
}

void spfc_dif_action_forward(struct spfc_fc_dif_info *dif_info_l1,
			     struct unf_dif_control_info *dif_ctrl_u1)
{
	dif_info_l1->wd0.grd_ctrl |=
	    (dif_ctrl_u1->protect_opcode & UNF_VERIFY_CRC_MASK)
		? SPFC_DIF_GARD_REF_APP_CTRL_VERIFY
		: SPFC_DIF_GARD_REF_APP_CTRL_NOT_VERIFY;
	dif_info_l1->wd0.grd_ctrl |=
	    (dif_ctrl_u1->protect_opcode & UNF_REPLACE_CRC_MASK)
		? SPFC_DIF_GARD_REF_APP_CTRL_REPLACE
		: SPFC_DIF_GARD_REF_APP_CTRL_FORWARD;

	dif_info_l1->wd0.ref_tag_ctrl |=
	    (dif_ctrl_u1->protect_opcode & UNF_VERIFY_LBA_MASK)
		? SPFC_DIF_GARD_REF_APP_CTRL_VERIFY
		: SPFC_DIF_GARD_REF_APP_CTRL_NOT_VERIFY;
	dif_info_l1->wd0.ref_tag_ctrl |=
	    (dif_ctrl_u1->protect_opcode & UNF_REPLACE_LBA_MASK)
		? SPFC_DIF_GARD_REF_APP_CTRL_REPLACE
		: SPFC_DIF_GARD_REF_APP_CTRL_FORWARD;

	dif_info_l1->wd0.app_tag_ctrl |=
	    (dif_ctrl_u1->protect_opcode & UNF_VERIFY_APP_MASK)
		? SPFC_DIF_GARD_REF_APP_CTRL_VERIFY
		: SPFC_DIF_GARD_REF_APP_CTRL_NOT_VERIFY;
	dif_info_l1->wd0.app_tag_ctrl |=
	    (dif_ctrl_u1->protect_opcode & UNF_REPLACE_APP_MASK)
		? SPFC_DIF_GARD_REF_APP_CTRL_REPLACE
		: SPFC_DIF_GARD_REF_APP_CTRL_FORWARD;
}

void spfc_dif_action_delete(struct spfc_fc_dif_info *dif_info_l1,
			    struct unf_dif_control_info *dif_ctrl_u1)
{
	dif_info_l1->wd0.grd_ctrl |=
	    (dif_ctrl_u1->protect_opcode & UNF_VERIFY_CRC_MASK)
		? SPFC_DIF_GARD_REF_APP_CTRL_VERIFY
		: SPFC_DIF_GARD_REF_APP_CTRL_NOT_VERIFY;
	dif_info_l1->wd0.grd_ctrl |= SPFC_DIF_GARD_REF_APP_CTRL_DELETE;

	dif_info_l1->wd0.ref_tag_ctrl |=
	    (dif_ctrl_u1->protect_opcode & UNF_VERIFY_LBA_MASK)
		? SPFC_DIF_GARD_REF_APP_CTRL_VERIFY
		: SPFC_DIF_GARD_REF_APP_CTRL_NOT_VERIFY;
	dif_info_l1->wd0.ref_tag_ctrl |= SPFC_DIF_GARD_REF_APP_CTRL_DELETE;

	dif_info_l1->wd0.app_tag_ctrl |=
	    (dif_ctrl_u1->protect_opcode & UNF_VERIFY_APP_MASK)
		? SPFC_DIF_GARD_REF_APP_CTRL_VERIFY
		: SPFC_DIF_GARD_REF_APP_CTRL_NOT_VERIFY;
	dif_info_l1->wd0.app_tag_ctrl |= SPFC_DIF_GARD_REF_APP_CTRL_DELETE;
}

static void spfc_convert_dif_action(struct unf_dif_control_info *dif_ctrl,
				    struct spfc_fc_dif_info *dif_info)
{
	struct spfc_fc_dif_info *dif_info_l1 = NULL;
	struct unf_dif_control_info *dif_ctrl_u1 = NULL;

	dif_info_l1 = dif_info;
	dif_ctrl_u1 = dif_ctrl;

	switch (UNF_DIF_ACTION_MASK & dif_ctrl_u1->protect_opcode) {
	case UNF_DIF_ACTION_VERIFY_AND_REPLACE:
	case UNF_DIF_ACTION_VERIFY_AND_FORWARD:
		spfc_dif_action_forward(dif_info_l1, dif_ctrl_u1);
		break;

	case UNF_DIF_ACTION_INSERT:
		dif_info_l1->wd0.grd_ctrl |=
		    SPFC_DIF_GARD_REF_APP_CTRL_NOT_VERIFY;
		dif_info_l1->wd0.grd_ctrl |= SPFC_DIF_GARD_REF_APP_CTRL_INSERT;
		dif_info_l1->wd0.ref_tag_ctrl |=
		    SPFC_DIF_GARD_REF_APP_CTRL_NOT_VERIFY;
		dif_info_l1->wd0.ref_tag_ctrl |=
		    SPFC_DIF_GARD_REF_APP_CTRL_INSERT;
		dif_info_l1->wd0.app_tag_ctrl |=
		    SPFC_DIF_GARD_REF_APP_CTRL_NOT_VERIFY;
		dif_info_l1->wd0.app_tag_ctrl |=
		    SPFC_DIF_GARD_REF_APP_CTRL_INSERT;
		break;

	case UNF_DIF_ACTION_VERIFY_AND_DELETE:
		spfc_dif_action_delete(dif_info_l1, dif_ctrl_u1);
		break;

	default:
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "Unknown dif protect opcode 0x%x",
			     dif_ctrl_u1->protect_opcode);
		break;
	}
}

void spfc_get_dif_info_l1(struct spfc_fc_dif_info *dif_info_l1,
			  struct unf_dif_control_info *dif_ctrl_u1)
{
	dif_info_l1->wd1.cmp_app_tag_msk = cmp_app_tag_mask;

	dif_info_l1->rep_app_tag = dif_ctrl_u1->app_tag;
	dif_info_l1->rep_ref_tag = dif_ctrl_u1->start_lba;

	dif_info_l1->cmp_app_tag = dif_ctrl_u1->app_tag;
	dif_info_l1->cmp_ref_tag = dif_ctrl_u1->start_lba;

	if (cmp_app_tag != 0)
		dif_info_l1->cmp_app_tag = cmp_app_tag;

	if (rep_app_tag != 0)
		dif_info_l1->rep_app_tag = rep_app_tag;

	if (rep_ref_tag != 0)
		dif_info_l1->rep_ref_tag = rep_ref_tag;
}

void spfc_build_dif_control(struct spfc_hba_info *hba,
			    struct unf_frame_pkg *pkg,
			    struct spfc_fc_dif_info *dif_info)
{
	struct spfc_fc_dif_info *dif_info_l1 = NULL;
	struct unf_dif_control_info *dif_ctrl_u1 = NULL;

	dif_info_l1 = dif_info;
	dif_ctrl_u1 = &pkg->dif_control;

	/* dif enable or disable */
	dif_info_l1->wd0.difx_en = SPFC_DIF_ENABLE;

	dif_info_l1->wd1.vpid = pkg->qos_level;
	dif_info_l1->wd1.lun_qos_en = 1;

	/* 512B + 8 size mode */
	dif_info_l1->wd0.sct_size = (dif_ctrl_u1->flags & UNF_DIF_SECTSIZE_4KB)
					? SPFC_DIF_SECTOR_4KB_MODE
					: SPFC_DIF_SECTOR_512B_MODE;

	/* dif type 1 */
	dif_info_l1->wd0.dif_verify_type = dif_type;

	/* Check whether the 0xffff app or ref domain is isolated */
	/* If all ff messages are displayed in type1 app, checkcheck sector
	 * dif_info_l1->wd0.difx_app_esc = SPFC_DIF_APP_REF_ESC_CHECK
	 */

	dif_info_l1->wd0.difx_app_esc = dif_app_esc_check;

	/* type1 ref tag If all ff is displayed, check sector is required */
	dif_info_l1->wd0.difx_ref_esc = dif_ref_esc_check;

	/* Currently, only t10 crc is supported */
	dif_info_l1->wd0.grd_agm_ctrl = 0;

	/* Set this parameter based on the values of bit zero and bit one.
	 * The initial value is 0, and the value is UNF_DEFAULT_CRC_GUARD_SEED
	 */
	dif_info_l1->wd0.grd_agm_ini_ctrl = grd_agm_ini_ctrl;
	dif_info_l1->wd0.app_tag_ctrl = 0;
	dif_info_l1->wd0.grd_ctrl = 0;
	dif_info_l1->wd0.ref_tag_ctrl = 0;

	/* Convert the verify operation, replace, forward, insert,
	 * and delete operations based on the actual operation code of the upper
	 * layer
	 */
	if (dif_protect_opcode != INVALID_VALUE32) {
		dif_ctrl_u1->protect_opcode =
		    dif_protect_opcode |
		    (dif_ctrl_u1->protect_opcode & UNF_DIF_ACTION_MASK);
	}

	spfc_convert_dif_action(dif_ctrl_u1, dif_info_l1);
	dif_info_l1->wd0.app_tag_ctrl |= app_tag_ctrl;

	/* Address self-increase mode */
	dif_info_l1->wd0.ref_tag_mode =
	    (dif_ctrl_u1->protect_opcode & UNF_DIF_ACTION_NO_INCREASE_REFTAG)
		? (BOTH_NONE)
		: (BOTH_INCREASE);

	if (ref_tag_mod != INVALID_VALUE32)
		dif_info_l1->wd0.ref_tag_mode = ref_tag_mod;

	/* This parameter is used only when type 3 is set to 0xffff. */
	spfc_get_dif_info_l1(dif_info_l1, dif_ctrl_u1);

	FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_MAJOR,
		     "Port(0x%x) sid_did(0x%x_0x%x) package type(0x%x) apptag(0x%x) flag(0x%x) opcode(0x%x) fcpdl(0x%x) statlba(0x%x)",
		     hba->port_cfg.port_id, pkg->frame_head.csctl_sid,
		     pkg->frame_head.rctl_did, pkg->type, pkg->dif_control.app_tag,
		     pkg->dif_control.flags, pkg->dif_control.protect_opcode,
		     pkg->dif_control.fcp_dl, pkg->dif_control.start_lba);

	FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_MAJOR,
		     "Port(0x%x) cover dif control info, app:cmp_tag(0x%x) cmp_tag_mask(0x%x) rep_tag(0x%x), ref:tag_mode(0x%x) cmp_tag(0x%x) rep_tag(0x%x).",
		     hba->port_cfg.port_id, dif_info_l1->cmp_app_tag,
		     dif_info_l1->wd1.cmp_app_tag_msk, dif_info_l1->rep_app_tag,
		     dif_info_l1->wd0.ref_tag_mode, dif_info_l1->cmp_ref_tag,
		     dif_info_l1->rep_ref_tag);
	FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_MAJOR,
		     "Port(0x%x) cover dif control info, ctrl:grd(0x%x) ref(0x%x) app(0x%x).",
		     hba->port_cfg.port_id, dif_info_l1->wd0.grd_ctrl,
		     dif_info_l1->wd0.ref_tag_ctrl,
		     dif_info_l1->wd0.app_tag_ctrl);
}

static u32 spfc_fill_external_sgl_page(struct spfc_hba_info *hba,
				       struct unf_frame_pkg *pkg,
				       struct unf_esgl_page *esgl_page,
				       u32 sge_num, int direction,
				       u32 context_id, u32 dif_flag)
{
	u32 ret = UNF_RETURN_ERROR;
	u32 index = 0;
	u32 sge_num_per_page = 0;
	u32 buffer_addr = 0;
	u32 buf_len = 0;
	char *buf = NULL;
	ulong phys = 0;
	struct unf_esgl_page *unf_esgl_page = NULL;
	struct spfc_variable_sge *sge = NULL;

	unf_esgl_page = esgl_page;
	while (sge_num > 0) {
		/* Obtains the initial address of the sge page */
		sge = (struct spfc_variable_sge *)unf_esgl_page->page_address;

		/* Calculate the number of sge on each page */
		sge_num_per_page = (unf_esgl_page->page_size) / sizeof(struct spfc_variable_sge);

		/* Fill in sgl page. The last sge of each page is link sge by
		 * default
		 */
		for (index = 0; index < (sge_num_per_page - 1); index++) {
			UNF_GET_SGL_ENTRY(ret, (void *)pkg, &buf, &buf_len, dif_flag);
			if (ret != RETURN_OK)
				return UNF_RETURN_ERROR;
			phys = (ulong)buf;
			sge[index].buf_addr_hi = UNF_DMA_HI32(phys);
			sge[index].buf_addr_lo = UNF_DMA_LO32(phys);
			sge[index].wd0.buf_len = buf_len;
			sge[index].wd0.r_flag = 0;
			sge[index].wd1.extension_flag = SPFC_WQE_SGE_NOT_EXTEND_FLAG;
			sge[index].wd1.last_flag = SPFC_WQE_SGE_NOT_LAST_FLAG;

			/* Parity bit */
			sge[index].wd1.buf_addr_gpa = (sge[index].buf_addr_lo >> UNF_SHIFT_16);
			sge[index].wd1.xid = (context_id & SPFC_SGE_WD1_XID_MASK);

			spfc_cpu_to_big32(&sge[index], sizeof(struct spfc_variable_sge));

			sge_num--;
			if (sge_num == 0)
				break;
		}

		/* sge Set the end flag on the last sge of the page if all the
		 * pages have been filled.
		 */
		if (sge_num == 0) {
			sge[index].wd1.extension_flag = SPFC_WQE_SGE_NOT_EXTEND_FLAG;
			sge[index].wd1.last_flag = SPFC_WQE_SGE_LAST_FLAG;

			/* Parity bit */
			buffer_addr = be32_to_cpu(sge[index].buf_addr_lo);
			sge[index].wd1.buf_addr_gpa = (buffer_addr >> UNF_SHIFT_16);
			sge[index].wd1.xid = (context_id & SPFC_SGE_WD1_XID_MASK);

			spfc_cpu_to_big32(&sge[index].wd1, SPFC_DWORD_BYTE);
		}
		/* If only one sge is left empty, the sge reserved on the page
		 * is used for filling.
		 */
		else if (sge_num == 1) {
			UNF_GET_SGL_ENTRY(ret, (void *)pkg, &buf, &buf_len,
					  dif_flag);
			if (ret != RETURN_OK)
				return UNF_RETURN_ERROR;
			phys = (ulong)buf;
			sge[index].buf_addr_hi = UNF_DMA_HI32(phys);
			sge[index].buf_addr_lo = UNF_DMA_LO32(phys);
			sge[index].wd0.buf_len = buf_len;
			sge[index].wd0.r_flag = 0;
			sge[index].wd1.extension_flag = SPFC_WQE_SGE_NOT_EXTEND_FLAG;
			sge[index].wd1.last_flag = SPFC_WQE_SGE_LAST_FLAG;

			/* Parity bit */
			sge[index].wd1.buf_addr_gpa = (sge[index].buf_addr_lo >> UNF_SHIFT_16);
			sge[index].wd1.xid = (context_id & SPFC_SGE_WD1_XID_MASK);

			spfc_cpu_to_big32(&sge[index], sizeof(struct spfc_variable_sge));

			sge_num--;
		} else {
			/* Apply for a new sgl page and fill in link sge */
			UNF_GET_FREE_ESGL_PAGE(unf_esgl_page, hba->lport, pkg);
			if (!unf_esgl_page) {
				FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
					     "[err]Get free esgl page failed.");
				return UNF_RETURN_ERROR;
			}
			phys = unf_esgl_page->esgl_phy_addr;
			sge[index].buf_addr_hi = UNF_DMA_HI32(phys);
			sge[index].buf_addr_lo = UNF_DMA_LO32(phys);

			/* For the cascaded wqe, you only need to enter the
			 * cascading buffer address and extension flag, and do
			 * not need to fill in other fields
			 */
			sge[index].wd0.buf_len = 0;
			sge[index].wd0.r_flag = 0;
			sge[index].wd1.extension_flag = SPFC_WQE_SGE_EXTEND_FLAG;
			sge[index].wd1.last_flag = SPFC_WQE_SGE_NOT_LAST_FLAG;

			/* parity bit */
			sge[index].wd1.buf_addr_gpa = (sge[index].buf_addr_lo >> UNF_SHIFT_16);
			sge[index].wd1.xid = (context_id & SPFC_SGE_WD1_XID_MASK);

			spfc_cpu_to_big32(&sge[index], sizeof(struct spfc_variable_sge));
		}

		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_INFO,
			     "[info]Port(0x%x) SID(0x%x) DID(0x%x) RXID(0x%x) build esgl left sge num: %u.",
			     hba->port_cfg.port_id, pkg->frame_head.csctl_sid,
			     pkg->frame_head.rctl_did,
			     pkg->frame_head.oxid_rxid, sge_num);
	}

	return RETURN_OK;
}

static u32 spfc_build_local_dif_sgl(struct spfc_hba_info *hba,
				    struct unf_frame_pkg *pkg, struct spfc_sqe *sqe,
				    int direction, u32 bd_sge_num)
{
	u32 ret = UNF_RETURN_ERROR;
	char *buf = NULL;
	u32 buf_len = 0;
	ulong phys = 0;
	u32 dif_sge_place = 0;

	/* DIF SGE must be followed by BD SGE */
	dif_sge_place = ((bd_sge_num <= pkg->entry_count) ? bd_sge_num : pkg->entry_count);

	/* The entry_count= 0 needs to be specially processed and does not need
	 * to be mounted. As long as len is set to zero, Last-bit is set to one,
	 * and E-bit is set to 0.
	 */
	if (pkg->dif_control.dif_sge_count == 0) {
		sqe->sge[dif_sge_place].buf_addr_hi = 0;
		sqe->sge[dif_sge_place].buf_addr_lo = 0;
		sqe->sge[dif_sge_place].wd0.buf_len = 0;
	} else {
		UNF_CM_GET_DIF_SGL_ENTRY(ret, (void *)pkg, &buf, &buf_len);
		if (ret != RETURN_OK) {
			FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_ERR,
				     "DOUBLE DIF Get Dif Buf Fail.");
			return UNF_RETURN_ERROR;
		}
		phys = (ulong)buf;
		sqe->sge[dif_sge_place].buf_addr_hi = UNF_DMA_HI32(phys);
		sqe->sge[dif_sge_place].buf_addr_lo = UNF_DMA_LO32(phys);
		sqe->sge[dif_sge_place].wd0.buf_len = buf_len;
	}

	/* rdma flag. If the fc is not used, enter 0. */
	sqe->sge[dif_sge_place].wd0.r_flag = 0;

	/* parity bit */
	sqe->sge[dif_sge_place].wd1.buf_addr_gpa = 0;
	sqe->sge[dif_sge_place].wd1.xid = 0;

	/* The local sgl does not use the cascading SGE. Therefore, the value of
	 * this field is always 0.
	 */
	sqe->sge[dif_sge_place].wd1.extension_flag = SPFC_WQE_SGE_NOT_EXTEND_FLAG;
	sqe->sge[dif_sge_place].wd1.last_flag = SPFC_WQE_SGE_LAST_FLAG;

	spfc_cpu_to_big32(&sqe->sge[dif_sge_place], sizeof(struct spfc_variable_sge));

	return RETURN_OK;
}

static u32 spfc_build_external_dif_sgl(struct spfc_hba_info *hba,
				       struct unf_frame_pkg *pkg,
				       struct spfc_sqe *sqe, int direction,
				       u32 bd_sge_num)
{
	u32 ret = UNF_RETURN_ERROR;
	struct unf_esgl_page *esgl_page = NULL;
	ulong phys = 0;
	u32 left_sge_num = 0;
	u32 dif_sge_place = 0;
	struct spfc_parent_ssq_info *ssq = NULL;
	u32 ssqn = 0;

	ssqn = (u16)pkg->private_data[PKG_PRIVATE_XCHG_SSQ_INDEX];
	ssq = &hba->parent_queue_mgr->shared_queue[ssqn].parent_ssq_info;

	/* DIF SGE must be followed by BD SGE */
	dif_sge_place = ((bd_sge_num <= pkg->entry_count) ? bd_sge_num : pkg->entry_count);

	/* Allocate the first page first */
	UNF_GET_FREE_ESGL_PAGE(esgl_page, hba->lport, pkg);
	if (!esgl_page) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_ERR,
			     "DOUBLE DIF Get External Page Fail.");
		return UNF_RETURN_ERROR;
	}

	phys = esgl_page->esgl_phy_addr;

	/* Configuring the Address of the Cascading Page */
	sqe->sge[dif_sge_place].buf_addr_hi = UNF_DMA_HI32(phys);
	sqe->sge[dif_sge_place].buf_addr_lo = UNF_DMA_LO32(phys);

	/* Configuring Control Information About the Cascading Page */
	sqe->sge[dif_sge_place].wd0.buf_len = 0;
	sqe->sge[dif_sge_place].wd0.r_flag = 0;
	sqe->sge[dif_sge_place].wd1.extension_flag = SPFC_WQE_SGE_EXTEND_FLAG;
	sqe->sge[dif_sge_place].wd1.last_flag = SPFC_WQE_SGE_NOT_LAST_FLAG;

	/* parity bit */
	sqe->sge[dif_sge_place].wd1.buf_addr_gpa = 0;
	sqe->sge[dif_sge_place].wd1.xid = 0;

	spfc_cpu_to_big32(&sqe->sge[dif_sge_place], sizeof(struct spfc_variable_sge));

	/* Fill in the sge information on the cascading page */
	left_sge_num = pkg->dif_control.dif_sge_count;
	ret = spfc_fill_external_sgl_page(hba, pkg, esgl_page, left_sge_num,
					  direction, ssq->context_id, true);
	if (ret != RETURN_OK)
		return UNF_RETURN_ERROR;

	return RETURN_OK;
}

static u32 spfc_build_local_sgl(struct spfc_hba_info *hba,
				struct unf_frame_pkg *pkg, struct spfc_sqe *sqe,
				int direction)
{
	u32 ret = UNF_RETURN_ERROR;
	char *buf = NULL;
	u32 buf_len = 0;
	u32 index = 0;
	ulong phys = 0;

	for (index = 0; index < pkg->entry_count; index++) {
		UNF_CM_GET_SGL_ENTRY(ret, (void *)pkg, &buf, &buf_len);
		if (ret != RETURN_OK)
			return UNF_RETURN_ERROR;

		phys = (ulong)buf;
		sqe->sge[index].buf_addr_hi = UNF_DMA_HI32(phys);
		sqe->sge[index].buf_addr_lo = UNF_DMA_LO32(phys);
		sqe->sge[index].wd0.buf_len = buf_len;

		/* rdma flag. If the fc is not used, enter 0. */
		sqe->sge[index].wd0.r_flag = 0;

		/* parity bit */
		sqe->sge[index].wd1.buf_addr_gpa = SPFC_ZEROCOPY_PCIE_TEMPLATE_VALUE;
		sqe->sge[index].wd1.xid = 0;

		/* The local sgl does not use the cascading SGE. Therefore, the
		 * value of this field is always 0.
		 */
		sqe->sge[index].wd1.extension_flag = SPFC_WQE_SGE_NOT_EXTEND_FLAG;
		sqe->sge[index].wd1.last_flag = SPFC_WQE_SGE_NOT_LAST_FLAG;

		if (index == (pkg->entry_count - 1)) {
			/* Sets the last WQE end flag 1 */
			sqe->sge[index].wd1.last_flag = SPFC_WQE_SGE_LAST_FLAG;
		}

		spfc_cpu_to_big32(&sqe->sge[index], sizeof(struct spfc_variable_sge));
	}

	/* Adjust the length of the BDSL field in the CTRL domain. */
	SPFC_ADJUST_DATA(sqe->ctrl_sl.ch.wd0.bdsl,
			 SPFC_BYTES_TO_QW_NUM((pkg->entry_count *
					      sizeof(struct spfc_variable_sge))));

	/* The entry_count= 0 needs to be specially processed and does not need
	 * to be mounted. As long as len is set to zero, Last-bit is set to one,
	 * and E-bit is set to 0.
	 */
	if (pkg->entry_count == 0) {
		sqe->sge[ARRAY_INDEX_0].buf_addr_hi = 0;
		sqe->sge[ARRAY_INDEX_0].buf_addr_lo = 0;
		sqe->sge[ARRAY_INDEX_0].wd0.buf_len = 0;

		/* rdma flag. This field is not used in fc. Set it to 0. */
		sqe->sge[ARRAY_INDEX_0].wd0.r_flag = 0;

		/* parity bit */
		sqe->sge[ARRAY_INDEX_0].wd1.buf_addr_gpa = SPFC_ZEROCOPY_PCIE_TEMPLATE_VALUE;
		sqe->sge[ARRAY_INDEX_0].wd1.xid = 0;

		/* The local sgl does not use the cascading SGE. Therefore, the
		 * value of this field is always 0.
		 */
		sqe->sge[ARRAY_INDEX_0].wd1.extension_flag = SPFC_WQE_SGE_NOT_EXTEND_FLAG;
		sqe->sge[ARRAY_INDEX_0].wd1.last_flag = SPFC_WQE_SGE_LAST_FLAG;

		spfc_cpu_to_big32(&sqe->sge[ARRAY_INDEX_0], sizeof(struct spfc_variable_sge));

		/* Adjust the length of the BDSL field in the CTRL domain. */
		SPFC_ADJUST_DATA(sqe->ctrl_sl.ch.wd0.bdsl,
				 SPFC_BYTES_TO_QW_NUM(sizeof(struct spfc_variable_sge)));
	}

	return RETURN_OK;
}

static u32 spfc_build_external_sgl(struct spfc_hba_info *hba,
				   struct unf_frame_pkg *pkg, struct spfc_sqe *sqe,
				   int direction, u32 bd_sge_num)
{
	u32 ret = UNF_RETURN_ERROR;
	char *buf = NULL;
	struct unf_esgl_page *esgl_page = NULL;
	ulong phys = 0;
	u32 buf_len = 0;
	u32 index = 0;
	u32 left_sge_num = 0;
	u32 local_sge_num = 0;
	struct spfc_parent_ssq_info *ssq = NULL;
	u16 ssqn = 0;

	ssqn = (u16)pkg->private_data[PKG_PRIVATE_XCHG_SSQ_INDEX];
	ssq = &hba->parent_queue_mgr->shared_queue[ssqn].parent_ssq_info;

	/* Ensure that the value of bd_sge_num is greater than or equal to one
	 */
	local_sge_num = bd_sge_num - 1;

	for (index = 0; index < local_sge_num; index++) {
		UNF_CM_GET_SGL_ENTRY(ret, (void *)pkg, &buf, &buf_len);
		if (unlikely(ret != RETURN_OK))
			return UNF_RETURN_ERROR;

		phys = (ulong)buf;

		sqe->sge[index].buf_addr_hi = UNF_DMA_HI32(phys);
		sqe->sge[index].buf_addr_lo = UNF_DMA_LO32(phys);
		sqe->sge[index].wd0.buf_len = buf_len;

		/* RDMA flag, which is not used by FC. */
		sqe->sge[index].wd0.r_flag = 0;
		sqe->sge[index].wd1.extension_flag = SPFC_WQE_SGE_NOT_EXTEND_FLAG;
		sqe->sge[index].wd1.last_flag = SPFC_WQE_SGE_NOT_LAST_FLAG;

		/* parity bit */
		sqe->sge[index].wd1.buf_addr_gpa = SPFC_ZEROCOPY_PCIE_TEMPLATE_VALUE;
		sqe->sge[index].wd1.xid = 0;

		spfc_cpu_to_big32(&sqe->sge[index], sizeof(struct spfc_variable_sge));
	}

	/* Calculate the number of remaining sge. */
	left_sge_num = pkg->entry_count - local_sge_num;
	/* Adjust the length of the BDSL field in the CTRL domain. */
	SPFC_ADJUST_DATA(sqe->ctrl_sl.ch.wd0.bdsl,
			 SPFC_BYTES_TO_QW_NUM((bd_sge_num * sizeof(struct spfc_variable_sge))));

	FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_INFO,
		     "alloc extended sgl page,leftsge:%d", left_sge_num);
	/* Allocating the first cascading page */
	UNF_GET_FREE_ESGL_PAGE(esgl_page, hba->lport, pkg);
	if (unlikely(!esgl_page))
		return UNF_RETURN_ERROR;

	phys = esgl_page->esgl_phy_addr;

	/* Configuring the Address of the Cascading Page */
	sqe->sge[index].buf_addr_hi = (u32)UNF_DMA_HI32(phys);
	sqe->sge[index].buf_addr_lo = (u32)UNF_DMA_LO32(phys);

	/* Configuring Control Information About the Cascading Page */
	sqe->sge[index].wd0.buf_len = 0;
	sqe->sge[index].wd0.r_flag = 0;
	sqe->sge[index].wd1.extension_flag = SPFC_WQE_SGE_EXTEND_FLAG;
	sqe->sge[index].wd1.last_flag = SPFC_WQE_SGE_NOT_LAST_FLAG;

	/* parity bit */
	sqe->sge[index].wd1.buf_addr_gpa = SPFC_ZEROCOPY_PCIE_TEMPLATE_VALUE;
	sqe->sge[index].wd1.xid = 0;

	spfc_cpu_to_big32(&sqe->sge[index], sizeof(struct spfc_variable_sge));

	/* Fill in the sge information on the cascading page. */
	ret = spfc_fill_external_sgl_page(hba, pkg, esgl_page, left_sge_num,
					  direction, ssq->context_id, false);
	if (ret != RETURN_OK)
		return UNF_RETURN_ERROR;
	/* Copy the extended data sge to the extended sge of the extended wqe.*/
	if (left_sge_num > 0) {
		memcpy(sqe->esge, (void *)esgl_page->page_address,
		       SPFC_WQE_MAX_ESGE_NUM * sizeof(struct spfc_variable_sge));
	}

	return RETURN_OK;
}

u32 spfc_build_sgl_by_local_sge_num(struct unf_frame_pkg *pkg,
				    struct spfc_hba_info *hba, struct spfc_sqe *sqe,
				    int direction, u32 bd_sge_num)
{
	u32 ret = RETURN_OK;

	if (pkg->entry_count <= bd_sge_num)
		ret = spfc_build_local_sgl(hba, pkg, sqe, direction);
	else
		ret = spfc_build_external_sgl(hba, pkg, sqe, direction, bd_sge_num);

	return ret;
}

u32 spfc_conf_dual_sgl_info(struct unf_frame_pkg *pkg,
			    struct spfc_hba_info *hba, struct spfc_sqe *sqe,
			    int direction, u32 bd_sge_num, bool double_sgl)
{
	u32 ret = RETURN_OK;

	if (double_sgl) {
		/* Adjust the length of the DIF_SL field in the CTRL domain */
		SPFC_ADJUST_DATA(sqe->ctrl_sl.ch.wd0.dif_sl,
				 SPFC_BYTES_TO_QW_NUM(sizeof(struct spfc_variable_sge)));

		if (pkg->dif_control.dif_sge_count <= SPFC_WQE_SGE_DIF_ENTRY_NUM)
			ret = spfc_build_local_dif_sgl(hba, pkg, sqe, direction, bd_sge_num);
		else
			ret = spfc_build_external_dif_sgl(hba, pkg, sqe, direction, bd_sge_num);
	}

	return ret;
}

u32 spfc_build_sgl(struct spfc_hba_info *hba, struct unf_frame_pkg *pkg,
		   struct spfc_sqe *sqe, int direction, u32 dif_flag)
{
#define SPFC_ESGE_CNT 3
	u32 ret = RETURN_OK;
	u32 bd_sge_num = SPFC_WQE_SGE_ENTRY_NUM;
	bool double_sgl = false;

	if (dif_flag != 0 && (pkg->dif_control.flags & UNF_DIF_DOUBLE_SGL)) {
		bd_sge_num = SPFC_WQE_SGE_ENTRY_NUM - SPFC_WQE_SGE_DIF_ENTRY_NUM;
		double_sgl = true;
	}

	/* Only one wqe local sge can be loaded. If more than one wqe local sge
	 * is used, use the esgl
	 */
	ret = spfc_build_sgl_by_local_sge_num(pkg, hba, sqe, direction, bd_sge_num);

	if (unlikely(ret != RETURN_OK))
		return ret;

	/* Configuring Dual SGL Information for DIF */
	ret = spfc_conf_dual_sgl_info(pkg, hba, sqe, direction, bd_sge_num, double_sgl);

	return ret;
}

void spfc_adjust_dix(struct unf_frame_pkg *pkg, struct spfc_fc_dif_info *dif_info,
		     u8 task_type)
{
	u8 tasktype = task_type;
	struct spfc_fc_dif_info *dif_info_l1 = NULL;

	dif_info_l1 = dif_info;

	if (dix_flag == 1) {
		if (tasktype == SPFC_SQE_FCP_IWRITE ||
		    tasktype == SPFC_SQE_FCP_TRD) {
			if ((UNF_DIF_ACTION_MASK & pkg->dif_control.protect_opcode) ==
			    UNF_DIF_ACTION_VERIFY_AND_FORWARD) {
				dif_info_l1->wd0.grd_ctrl |=
				SPFC_DIF_GARD_REF_APP_CTRL_REPLACE;
				dif_info_l1->wd0.grd_agm_ctrl =
				SPFC_DIF_GUARD_VERIFY_IP_CHECKSUM_REPLACE_CRC16;
			}

			if ((UNF_DIF_ACTION_MASK & pkg->dif_control.protect_opcode) ==
			    UNF_DIF_ACTION_VERIFY_AND_DELETE) {
				dif_info_l1->wd0.grd_agm_ctrl =
				SPFC_DIF_GUARD_VERIFY_IP_CHECKSUM_REPLACE_CRC16;
			}
		}

		if (tasktype == SPFC_SQE_FCP_IREAD ||
		    tasktype == SPFC_SQE_FCP_TWR) {
			if ((UNF_DIF_ACTION_MASK &
			     pkg->dif_control.protect_opcode) ==
			    UNF_DIF_ACTION_VERIFY_AND_FORWARD) {
				dif_info_l1->wd0.grd_ctrl |=
				    SPFC_DIF_GARD_REF_APP_CTRL_REPLACE;
				dif_info_l1->wd0.grd_agm_ctrl =
				SPFC_DIF_GUARD_VERIFY_CRC16_REPLACE_IP_CHECKSUM;
			}

			if ((UNF_DIF_ACTION_MASK &
			     pkg->dif_control.protect_opcode) ==
			    UNF_DIF_ACTION_INSERT) {
				dif_info_l1->wd0.grd_agm_ctrl =
				SPFC_DIF_GUARD_VERIFY_CRC16_REPLACE_IP_CHECKSUM;
			}
		}
	}

	if (grd_agm_ctrl != 0)
		dif_info_l1->wd0.grd_agm_ctrl = grd_agm_ctrl;

	if (grd_ctrl != 0)
		dif_info_l1->wd0.grd_ctrl = grd_ctrl;
}

void spfc_get_dma_direction_by_fcp_cmnd(const struct unf_fcp_cmnd *fcp_cmnd,
					int *dma_direction, u8 *task_type)
{
	if (UNF_FCP_WR_DATA & fcp_cmnd->control) {
		*task_type = SPFC_SQE_FCP_IWRITE;
		*dma_direction = DMA_TO_DEVICE;
	} else if (UNF_GET_TASK_MGMT_FLAGS(fcp_cmnd->control) != 0) {
		*task_type = SPFC_SQE_FCP_ITMF;
		*dma_direction = DMA_FROM_DEVICE;
	} else {
		*task_type = SPFC_SQE_FCP_IREAD;
		*dma_direction = DMA_FROM_DEVICE;
	}
}

static inline u32 spfc_build_icmnd_wqe(struct spfc_hba_info *hba,
				       struct unf_frame_pkg *pkg,
				       struct spfc_sqe *sge)
{
	u32 ret = RETURN_OK;
	int direction = 0;
	u8 tasktype = 0;
	struct unf_fcp_cmnd *fcp_cmnd = NULL;
	struct spfc_sqe *sqe = sge;
	u32 dif_flag = 0;

	fcp_cmnd = pkg->fcp_cmnd;
	if (unlikely(!fcp_cmnd)) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_ERR,
			     "[err]Package's FCP commond pointer is NULL.");

		return UNF_RETURN_ERROR;
	}

	spfc_get_dma_direction_by_fcp_cmnd(fcp_cmnd, &direction, &tasktype);

	spfc_build_icmnd_wqe_ts_header(pkg, sqe, tasktype, hba->exi_base, hba->port_index);

	spfc_build_icmnd_wqe_ctrls(pkg, sqe);

	spfc_build_icmnd_wqe_ts(hba, pkg, &sqe->ts_sl, &sqe->ts_ex);

	if (sqe->ts_sl.task_type != SPFC_SQE_FCP_ITMF) {
		if (pkg->dif_control.protect_opcode == UNF_DIF_ACTION_NONE) {
			dif_flag = 0;
			spfc_build_no_dif_control(pkg, &sqe->ts_sl.cont.icmnd.info.dif_info);
		} else {
			dif_flag = 1;
			spfc_build_dif_control(hba, pkg, &sqe->ts_sl.cont.icmnd.info.dif_info);
			spfc_adjust_dix(pkg,
					&sqe->ts_sl.cont.icmnd.info.dif_info,
					tasktype);
		}
	}

	ret = spfc_build_sgl(hba, pkg, sqe, direction, dif_flag);

	sqe->sid = UNF_GET_SID(pkg);
	sqe->did = UNF_GET_DID(pkg);

	return ret;
}

u32 spfc_send_scsi_cmnd(void *hba, struct unf_frame_pkg *pkg)
{
	struct spfc_hba_info *spfc_hba = NULL;
	struct spfc_parent_sq_info *parent_sq = NULL;
	u32 ret = UNF_RETURN_ERROR;
	struct spfc_sqe sqe;
	u16 ssqn;
	struct spfc_parent_queue_info *parent_queue = NULL;

	/* input param check */
	FC_CHECK_RETURN_VALUE(hba, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(pkg, UNF_RETURN_ERROR);

	SPFC_CHECK_PKG_ALLOCTIME(pkg);
	memset(&sqe, 0, sizeof(struct spfc_sqe));
	spfc_hba = hba;

	/* 1. find parent sq for scsi_cmnd(pkg) */
	parent_sq = spfc_find_parent_sq_by_pkg(spfc_hba, pkg);
	if (unlikely(!parent_sq)) {
		/* Do not need to print info */
		return UNF_RETURN_ERROR;
	}

	pkg->qos_level += spfc_hba->vpid_start;

	/* 2. build cmnd wqe (to sqe) for scsi_cmnd(pkg) */
	ret = spfc_build_icmnd_wqe(spfc_hba, pkg, &sqe);
	if (unlikely(ret != RETURN_OK)) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_ERR,
			     "[fail]Port(0x%x) Build WQE failed, SID(0x%x) DID(0x%x) pkg type(0x%x) hottag(0x%x).",
			     spfc_hba->port_cfg.port_id, pkg->frame_head.csctl_sid,
			     pkg->frame_head.rctl_did, pkg->type, UNF_GET_XCHG_TAG(pkg));

		return ret;
	}

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_INFO,
		     "Port(0x%x) RPort(0x%x) send FCP_CMND TYPE(0x%x) Local_Xid(0x%x) hottag(0x%x) LBA(0x%llx)",
		     spfc_hba->port_cfg.port_id, parent_sq->rport_index,
		     sqe.ts_sl.task_type, sqe.ts_sl.local_xid,
		     pkg->private_data[PKG_PRIVATE_XCHG_HOT_POOL_INDEX],
		     *((u64 *)pkg->fcp_cmnd->cdb));

	ssqn = (u16)pkg->private_data[PKG_PRIVATE_XCHG_SSQ_INDEX];
	if (sqe.ts_sl.task_type == SPFC_SQE_FCP_ITMF) {
		parent_queue = container_of(parent_sq, struct spfc_parent_queue_info,
					    parent_sq_info);
		ret = spfc_suspend_sqe_and_send_nop(spfc_hba, parent_queue, &sqe, pkg);
		return ret;
	}
	/* 3. En-Queue Parent SQ for scsi_cmnd(pkg) sqe */
	ret = spfc_parent_sq_enqueue(parent_sq, &sqe, ssqn);

	return ret;
}

static void spfc_ini_status_default_handler(struct spfc_scqe_iresp *iresp,
					    struct unf_frame_pkg *pkg)
{
	u8 control = 0;
	u16 com_err_code = 0;

	control = iresp->wd2.fcp_flag & SPFC_CTRL_MASK;

	if (iresp->fcp_resid != 0) {
		com_err_code = UNF_IO_FAILED;
		pkg->residus_len = iresp->fcp_resid;
	} else {
		com_err_code = UNF_IO_SUCCESS;
		pkg->residus_len = 0;
	}

	pkg->status = spfc_fill_pkg_status(com_err_code, control, iresp->wd2.scsi_status);

	FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_INFO,
		     "[info]Fill package with status: 0x%x, residus len: 0x%x",
		     pkg->status, pkg->residus_len);
}

static void spfc_check_fcp_rsp_iu(struct spfc_scqe_iresp *iresp,
				  struct spfc_hba_info *hba,
				  struct unf_frame_pkg *pkg)
{
	u8 scsi_status = 0;
	u8 control = 0;

	control = (u8)iresp->wd2.fcp_flag;
	scsi_status = (u8)iresp->wd2.scsi_status;

	/* FcpRspIU with Little End from IOB WQE to COM's pkg also */
	if (control & FCP_RESID_UNDER_MASK) {
		/* under flow: usually occurs in inquiry */
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_INFO,
			     "[info]I_STS IOB posts under flow with residus len: %u, FCP residue: %u.",
			     pkg->residus_len, iresp->fcp_resid);

		if (pkg->residus_len != iresp->fcp_resid)
			pkg->status = spfc_fill_pkg_status(UNF_IO_FAILED, control, scsi_status);
		else
			pkg->status = spfc_fill_pkg_status(UNF_IO_UNDER_FLOW, control, scsi_status);
	}

	if (control & FCP_RESID_OVER_MASK) {
		/* over flow: error happened */
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]I_STS IOB posts over flow with residus len: %u, FCP residue: %u.",
			     pkg->residus_len, iresp->fcp_resid);

		if (pkg->residus_len != iresp->fcp_resid)
			pkg->status = spfc_fill_pkg_status(UNF_IO_FAILED, control, scsi_status);
		else
			pkg->status = spfc_fill_pkg_status(UNF_IO_OVER_FLOW, control, scsi_status);
	}

	pkg->unf_rsp_pload_bl.length = 0;
	pkg->unf_sense_pload_bl.length = 0;

	if (control & FCP_RSP_LEN_VALID_MASK) {
		/* dma by chip */
		pkg->unf_rsp_pload_bl.buffer_ptr = NULL;

		pkg->unf_rsp_pload_bl.length = iresp->fcp_rsp_len;
		pkg->byte_orders |= UNF_BIT_3;
	}

	if (control & FCP_SNS_LEN_VALID_MASK) {
		/* dma by chip */
		pkg->unf_sense_pload_bl.buffer_ptr = NULL;

		pkg->unf_sense_pload_bl.length = iresp->fcp_sns_len;
		pkg->byte_orders |= UNF_BIT_4;
	}

	if (iresp->wd1.user_id_num == 1 &&
	    (pkg->unf_sense_pload_bl.length + pkg->unf_rsp_pload_bl.length > 0)) {
		pkg->unf_rsp_pload_bl.buffer_ptr =
		    (u8 *)spfc_get_els_buf_by_user_id(hba, (u16)iresp->user_id[ARRAY_INDEX_0]);
	} else if (iresp->wd1.user_id_num > 1) {
		FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_ERR,
			     "[err]receive buff num 0x%x > 1 0x%x",
			     iresp->wd1.user_id_num, control);
	}
}

u16 spfc_get_com_err_code(struct unf_frame_pkg *pkg)
{
	u16 com_err_code = UNF_IO_FAILED;
	u32 status_subcode = 0;

	status_subcode = pkg->status_sub_code;

	if (likely(status_subcode == 0))
		com_err_code = 0;
	else if (status_subcode == UNF_DIF_CRC_ERR)
		com_err_code = UNF_IO_DIF_ERROR;
	else if (status_subcode == UNF_DIF_LBA_ERR)
		com_err_code = UNF_IO_DIF_REF_ERROR;
	else if (status_subcode == UNF_DIF_APP_ERR)
		com_err_code = UNF_IO_DIF_GEN_ERROR;

	return com_err_code;
}

void spfc_process_ini_fail_io(struct spfc_hba_info *hba, union spfc_scqe *iresp,
			      struct unf_frame_pkg *pkg)
{
	u16 com_err_code = UNF_IO_FAILED;

	/* 1. error stats process */
	if (SPFC_GET_SCQE_STATUS((union spfc_scqe *)(void *)iresp) != 0) {
		switch (SPFC_GET_SCQE_STATUS((union spfc_scqe *)(void *)iresp)) {
		/* I/O not complete: 1.session reset;  2.clear buffer */
		case FC_CQE_BUFFER_CLEAR_IO_COMPLETED:
		case FC_CQE_SESSION_RST_CLEAR_IO_COMPLETED:
		case FC_CQE_SESSION_ONLY_CLEAR_IO_COMPLETED:
		case FC_CQE_WQE_FLUSH_IO_COMPLETED:
			com_err_code = UNF_IO_CLEAN_UP;

			FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_MAJOR,
				     "[warn]Port(0x%x) INI IO not complete, OX_ID(0x%x) RX_ID(0x%x) status(0x%x)",
				     hba->port_cfg.port_id,
				     ((struct spfc_scqe_iresp *)iresp)->wd0.ox_id,
				     ((struct spfc_scqe_iresp *)iresp)->wd0.rx_id,
				     com_err_code);

			break;
		/* Allocate task id(oxid) fail */
		case FC_ERROR_INVALID_TASK_ID:
			com_err_code = UNF_IO_NO_XCHG;
			break;
		case FC_ALLOC_EXCH_ID_FAILED:
			com_err_code = UNF_IO_NO_XCHG;
			FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_MAJOR,
				     "[warn]Port(0x%x) INI IO, tag 0x%x alloc oxid fail.",
				     hba->port_cfg.port_id,
				     ((struct spfc_scqe_iresp *)iresp)->wd2.hotpooltag);
			break;
		case FC_ERROR_CODE_DATA_DIFX_FAILED:
			com_err_code = pkg->status >> UNF_SHIFT_16;
			FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_MAJOR,
				     "[warn]Port(0x%x) INI IO, tag 0x%x tx dif error.",
				     hba->port_cfg.port_id,
				     ((struct spfc_scqe_iresp *)iresp)->wd2.hotpooltag);
			break;
		/* any other: I/O failed --->>> DID error */
		default:
			com_err_code = UNF_IO_FAILED;
			break;
		}

		/* fill pkg status & return directly */
		pkg->status =
			spfc_fill_pkg_status(com_err_code,
					     ((struct spfc_scqe_iresp *)iresp)->wd2.fcp_flag,
					     ((struct spfc_scqe_iresp *)iresp)->wd2.scsi_status);

		return;
	}

	/* 2. default stats process */
	spfc_ini_status_default_handler((struct spfc_scqe_iresp *)iresp, pkg);

	/* 3. FCP RSP IU check */
	spfc_check_fcp_rsp_iu((struct spfc_scqe_iresp *)iresp, hba, pkg);
}

void spfc_process_dif_result(struct spfc_hba_info *hba, union spfc_scqe *wqe,
			     struct unf_frame_pkg *pkg)
{
	u16 com_err_code = UNF_IO_FAILED;
	u8 dif_info = 0;

	dif_info = wqe->common.wd0.dif_vry_rst;
	if (dif_info == SPFC_TX_DIF_ERROR_FLAG) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[error]Port(0x%x) TGT recv tx dif result abnormal.",
			     hba->port_cfg.port_id);
	}

	pkg->status_sub_code =
	    (dif_info & SPFC_DIF_ERROR_CODE_CRC)
		? UNF_DIF_CRC_ERR
		: ((dif_info & SPFC_DIF_ERROR_CODE_REF)
		       ? UNF_DIF_LBA_ERR
		       : ((dif_info & SPFC_DIF_ERROR_CODE_APP) ? UNF_DIF_APP_ERR : 0));
	com_err_code = spfc_get_com_err_code(pkg);
	pkg->status = (u32)(com_err_code) << UNF_SHIFT_16;

	if (unlikely(com_err_code != 0)) {
		spfc_dif_err_count(hba, dif_info);

		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_INFO,
			     "[error]Port(0x%x) INI io status with dif result(0x%x),subcode(0x%x) pkg->status(0x%x)",
			     hba->port_cfg.port_id, dif_info,
			     pkg->status_sub_code, pkg->status);
	}
}

u32 spfc_scq_recv_iresp(struct spfc_hba_info *hba, union spfc_scqe *wqe)
{
#define SPFC_IRSP_USERID_LEN ((FC_SENSEDATA_USERID_CNT_MAX + 1) / 2)
	struct spfc_scqe_iresp *iresp = NULL;
	struct unf_frame_pkg pkg;
	u32 ret = RETURN_OK;
	u16 hot_tag;

	FC_CHECK_RETURN_VALUE((hba), UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE((wqe), UNF_RETURN_ERROR);

	iresp = (struct spfc_scqe_iresp *)(void *)wqe;

	/* 1. Constraints: I_STS remain cnt must be zero */
	if (unlikely(SPFC_GET_SCQE_REMAIN_CNT(wqe) != 0)) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_ERR,
			     "[err]Port(0x%x) ini_wqe(OX_ID:0x%x RX_ID:0x%x) HotTag(0x%x) remain_cnt(0x%x) abnormal, status(0x%x)",
			     hba->port_cfg.port_id, iresp->wd0.ox_id,
			     iresp->wd0.rx_id, iresp->wd2.hotpooltag,
			     SPFC_GET_SCQE_REMAIN_CNT(wqe),
			     SPFC_GET_SCQE_STATUS(wqe));

		UNF_PRINT_SFS_LIMIT(UNF_MAJOR, hba->port_cfg.port_id, wqe, sizeof(union spfc_scqe));

		/* return directly */
		return UNF_RETURN_ERROR;
	}

	spfc_swap_16_in_32((u32 *)iresp->user_id, SPFC_IRSP_USERID_LEN);

	memset(&pkg, 0, sizeof(struct unf_frame_pkg));
	pkg.private_data[PKG_PRIVATE_XCHG_ALLOC_TIME] = iresp->magic_num;
	pkg.frame_head.oxid_rxid = (((iresp->wd0.ox_id) << UNF_SHIFT_16) | (iresp->wd0.rx_id));

	hot_tag = (u16)iresp->wd2.hotpooltag & UNF_ORIGIN_HOTTAG_MASK;
	/* 2. HotTag validity check */
	if (likely(hot_tag >= hba->exi_base && (hot_tag < hba->exi_base + hba->exi_count))) {
		pkg.status = UNF_IO_SUCCESS;
		pkg.private_data[PKG_PRIVATE_XCHG_HOT_POOL_INDEX] =
		    hot_tag - hba->exi_base;
	} else {
		/* OX_ID error: return by COM */
		pkg.status = UNF_IO_FAILED;
		pkg.private_data[PKG_PRIVATE_XCHG_HOT_POOL_INDEX] = INVALID_VALUE16;

		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_ERR,
			     "[err]Port(0x%x) ini_cmnd_wqe(OX_ID:0x%x RX_ID:0x%x) ox_id invalid, status(0x%x)",
			     hba->port_cfg.port_id, iresp->wd0.ox_id, iresp->wd0.rx_id,
			     SPFC_GET_SCQE_STATUS(wqe));

		UNF_PRINT_SFS_LIMIT(UNF_MAJOR, hba->port_cfg.port_id, wqe,
				    sizeof(union spfc_scqe));
	}

	/* process dif result */
	spfc_process_dif_result(hba, wqe, &pkg);

	/* 3. status check */
	if (unlikely(SPFC_GET_SCQE_STATUS(wqe) ||
		     iresp->wd2.scsi_status != 0 || iresp->fcp_resid != 0 ||
		     ((iresp->wd2.fcp_flag & SPFC_CTRL_MASK) != 0))) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_INFO,
			     "[warn]Port(0x%x) scq_status(0x%x) scsi_status(0x%x) fcp_resid(0x%x) fcp_flag(0x%x)",
			     hba->port_cfg.port_id, SPFC_GET_SCQE_STATUS(wqe),
			     iresp->wd2.scsi_status, iresp->fcp_resid,
			     iresp->wd2.fcp_flag);

		/* set pkg status & check fcp_rsp IU */
		spfc_process_ini_fail_io(hba, (union spfc_scqe *)iresp, &pkg);
	}

	/* 4. LL_Driver ---to--->>> COM_Driver */
	UNF_LOWLEVEL_SCSI_COMPLETED(ret, hba->lport, &pkg);
	if (iresp->wd1.user_id_num == 1 &&
	    (pkg.unf_sense_pload_bl.length + pkg.unf_rsp_pload_bl.length > 0)) {
		spfc_post_els_srq_wqe(&hba->els_srq_info, (u16)iresp->user_id[ARRAY_INDEX_0]);
	}

	FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_INFO,
		     "[info]Port(0x%x) rport(0x%x) recv(%s) hottag(0x%x) OX_ID(0x%x) RX_ID(0x%x) return(%s)",
		     hba->port_cfg.port_id, iresp->wd1.conn_id,
		     (SPFC_SCQE_FCP_IRSP == (SPFC_GET_SCQE_TYPE(wqe)) ? "IRESP" : "ITMF_RSP"),
		     pkg.private_data[PKG_PRIVATE_XCHG_HOT_POOL_INDEX], iresp->wd0.ox_id,
		     iresp->wd0.rx_id, (ret == RETURN_OK) ? "OK" : "ERROR");

	return ret;
}
