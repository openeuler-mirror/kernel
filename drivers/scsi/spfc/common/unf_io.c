// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#include "unf_io.h"
#include "unf_log.h"
#include "unf_portman.h"
#include "unf_service.h"
#include "unf_io_abnormal.h"

u32 sector_size_flag;

#define UNF_GET_FCP_CTL(pkg) ((((pkg)->status) >> UNF_SHIFT_8) & 0xFF)
#define UNF_GET_SCSI_STATUS(pkg) (((pkg)->status) & 0xFF)

static u32 unf_io_success_handler(struct unf_xchg *xchg,
				  struct unf_frame_pkg *pkg, u32 up_status);
static u32 unf_ini_error_default_handler(struct unf_xchg *xchg,
					 struct unf_frame_pkg *pkg,
					 u32 up_status);
static u32 unf_io_underflow_handler(struct unf_xchg *xchg,
				    struct unf_frame_pkg *pkg, u32 up_status);
static u32 unf_ini_dif_error_handler(struct unf_xchg *xchg,
				     struct unf_frame_pkg *pkg, u32 up_status);

struct unf_ini_error_handler_s {
	u32 ini_error_code;
	u32 (*unf_ini_error_handler)(struct unf_xchg *xchg,
				     struct unf_frame_pkg *pkg, u32 up_status);
};

struct unf_ini_error_handler_s ini_error_handler_table[] = {
	 {UNF_IO_SUCCESS, unf_io_success_handler},
	 {UNF_IO_ABORTED, unf_ini_error_default_handler},
	 {UNF_IO_FAILED, unf_ini_error_default_handler},
	 {UNF_IO_ABORT_ABTS, unf_ini_error_default_handler},
	 {UNF_IO_ABORT_LOGIN, unf_ini_error_default_handler},
	 {UNF_IO_ABORT_REET, unf_ini_error_default_handler},
	 {UNF_IO_ABORT_FAILED, unf_ini_error_default_handler},
	 {UNF_IO_OUTOF_ORDER, unf_ini_error_default_handler},
	 {UNF_IO_FTO, unf_ini_error_default_handler},
	 {UNF_IO_LINK_FAILURE, unf_ini_error_default_handler},
	 {UNF_IO_OVER_FLOW, unf_ini_error_default_handler},
	 {UNF_IO_RSP_OVER, unf_ini_error_default_handler},
	 {UNF_IO_LOST_FRAME, unf_ini_error_default_handler},
	 {UNF_IO_UNDER_FLOW, unf_io_underflow_handler},
	 {UNF_IO_HOST_PROG_ERROR, unf_ini_error_default_handler},
	 {UNF_IO_SEST_PROG_ERROR, unf_ini_error_default_handler},
	 {UNF_IO_INVALID_ENTRY, unf_ini_error_default_handler},
	 {UNF_IO_ABORT_SEQ_NOT, unf_ini_error_default_handler},
	 {UNF_IO_REJECT, unf_ini_error_default_handler},
	 {UNF_IO_EDC_IN_ERROR, unf_ini_error_default_handler},
	 {UNF_IO_EDC_OUT_ERROR, unf_ini_error_default_handler},
	 {UNF_IO_UNINIT_KEK_ERR, unf_ini_error_default_handler},
	 {UNF_IO_DEK_OUTOF_RANGE, unf_ini_error_default_handler},
	 {UNF_IO_KEY_UNWRAP_ERR, unf_ini_error_default_handler},
	 {UNF_IO_KEY_TAG_ERR, unf_ini_error_default_handler},
	 {UNF_IO_KEY_ECC_ERR, unf_ini_error_default_handler},
	 {UNF_IO_BLOCK_SIZE_ERROR, unf_ini_error_default_handler},
	 {UNF_IO_ILLEGAL_CIPHER_MODE, unf_ini_error_default_handler},
	 {UNF_IO_CLEAN_UP, unf_ini_error_default_handler},
	 {UNF_IO_ABORTED_BY_TARGET, unf_ini_error_default_handler},
	 {UNF_IO_TRANSPORT_ERROR, unf_ini_error_default_handler},
	 {UNF_IO_LINK_FLASH, unf_ini_error_default_handler},
	 {UNF_IO_TIMEOUT, unf_ini_error_default_handler},
	 {UNF_IO_DMA_ERROR, unf_ini_error_default_handler},
	 {UNF_IO_DIF_ERROR, unf_ini_dif_error_handler},
	 {UNF_IO_INCOMPLETE, unf_ini_error_default_handler},
	 {UNF_IO_DIF_REF_ERROR, unf_ini_dif_error_handler},
	 {UNF_IO_DIF_GEN_ERROR, unf_ini_dif_error_handler},
	 {UNF_IO_NO_XCHG, unf_ini_error_default_handler}
	};

void unf_done_ini_xchg(struct unf_xchg *xchg)
{
	/*
	 * About I/O Done
	 * 1. normal case
	 * 2. Send ABTS & RCVD RSP
	 * 3. Send ABTS & timer timeout
	 */
	struct unf_scsi_cmnd scsi_cmd = {0};
	ulong flags = 0;
	struct unf_scsi_cmd_info *scsi_cmnd_info = NULL;
	struct unf_rport_scsi_id_image *scsi_image_table = NULL;
	u32 scsi_id = 0;

	FC_CHECK_RETURN_VOID(xchg);

	if (unlikely(!xchg->scsi_cmnd_info.scsi_cmnd))
		return;

	/* 1. Free RX_ID for INI SIRT: Do not care */

	/*
	 * 2. set & check exchange state
	 * *
	 * for Set UP_ABORT Tag:
	 * 1) L_Port destroy
	 * 2) LUN reset
	 * 3) Target/Session reset
	 * 4) SCSI send Abort(ABTS)
	 */
	spin_lock_irqsave(&xchg->xchg_state_lock, flags);
	xchg->io_state |= INI_IO_STATE_DONE;
	if (unlikely(xchg->io_state &
		     (INI_IO_STATE_UPABORT | INI_IO_STATE_UPSEND_ERR | INI_IO_STATE_TMF_ABORT))) {
		/*
		 * a. UPABORT: scsi have send ABTS
		 * --->>> do not call SCSI_Done, return directly
		 * b. UPSEND_ERR: error happened duiring LLDD send SCSI_CMD
		 * --->>> do not call SCSI_Done, scsi need retry
		 */
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_KEVENT,
			     "[event]Exchange(0x%p) Cmdsn:0x%lx upCmd:%p hottag(0x%x) with state(0x%x) has been aborted or send error",
			     xchg, (ulong)xchg->cmnd_sn, xchg->scsi_cmnd_info.scsi_cmnd,
			     xchg->hotpooltag, xchg->io_state);

		spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);
		return;
	}
	spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);

	scsi_cmnd_info = &xchg->scsi_cmnd_info;

	/*
	 * 3. Set:
	 * scsi_cmnd;
	 * cmnd_done_func;
	 * cmnd up_level_done;
	 * sense_buff_addr;
	 * resid_length;
	 * cmnd_result;
	 * dif_info
	 * **
	 * UNF_SCSI_CMND <<-- UNF_SCSI_CMND_INFO
	 */
	UNF_SET_HOST_CMND((&scsi_cmd), scsi_cmnd_info->scsi_cmnd);
	UNF_SER_CMND_DONE_FUNC((&scsi_cmd), scsi_cmnd_info->done);
	UNF_SET_UP_LEVEL_CMND_DONE_FUNC(&scsi_cmd, scsi_cmnd_info->uplevel_done);
	scsi_cmd.drv_private = xchg->lport;
	if (unlikely((UNF_SCSI_STATUS(xchg->scsi_cmnd_info.result)) & FCP_SNS_LEN_VALID_MASK)) {
		unf_save_sense_data(scsi_cmd.upper_cmnd,
				    (char *)xchg->fcp_sfs_union.fcp_rsp_entry.fcp_rsp_iu,
				    (int)xchg->fcp_sfs_union.fcp_rsp_entry.fcp_sense_len);
	}
	UNF_SET_RESID((&scsi_cmd), (u32)xchg->resid_len);
	UNF_SET_CMND_RESULT((&scsi_cmd), scsi_cmnd_info->result);
	memcpy(&scsi_cmd.dif_info, &xchg->dif_info, sizeof(struct dif_info));

	scsi_id = scsi_cmnd_info->scsi_id;

	UNF_DONE_SCSI_CMND((&scsi_cmd));

	/* 4. Update IO result CNT */
	if (likely(xchg->lport)) {
		scsi_image_table = &xchg->lport->rport_scsi_table;
		UNF_IO_RESULT_CNT(scsi_image_table, scsi_id,
				  (scsi_cmnd_info->result >> UNF_SHIFT_16));
	}
}

static inline u32 unf_ini_get_sgl_entry_buf(ini_get_sgl_entry_buf ini_get_sgl,
					    void *cmnd, void *driver_sgl,
					    void **upper_sgl, u32 *req_index,
					    u32 *index, char **buf,
					    u32 *buf_len)
{
	if (unlikely(!ini_get_sgl)) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_MAJOR,
			     "Command(0x%p) Get sgl Entry func Null.", cmnd);

		return UNF_RETURN_ERROR;
	}

	return ini_get_sgl(cmnd, driver_sgl, upper_sgl, req_index, index, buf, buf_len);
}

u32 unf_ini_get_sgl_entry(void *pkg, char **buf, u32 *buf_len)
{
	struct unf_frame_pkg *unf_pkg = (struct unf_frame_pkg *)pkg;
	struct unf_xchg *unf_xchg = NULL;
	u32 ret = RETURN_OK;

	FC_CHECK_RETURN_VALUE(pkg, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(buf, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(buf_len, UNF_RETURN_ERROR);

	unf_xchg = (struct unf_xchg *)unf_pkg->xchg_contex;
	FC_CHECK_RETURN_VALUE(unf_xchg, UNF_RETURN_ERROR);

	/* Get SGL Entry buffer for INI Mode */
	ret = unf_ini_get_sgl_entry_buf(unf_xchg->scsi_cmnd_info.unf_get_sgl_entry_buf,
					unf_xchg->scsi_cmnd_info.scsi_cmnd, NULL,
					&unf_xchg->req_sgl_info.sgl,
					&unf_xchg->scsi_cmnd_info.port_id,
					&((unf_xchg->req_sgl_info).entry_index), buf, buf_len);

	return ret;
}

u32 unf_ini_get_dif_sgl_entry(void *pkg, char **buf, u32 *buf_len)
{
	struct unf_frame_pkg *unf_pkg = (struct unf_frame_pkg *)pkg;
	struct unf_xchg *unf_xchg = NULL;
	u32 ret = RETURN_OK;

	FC_CHECK_RETURN_VALUE(pkg, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(buf, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(buf_len, UNF_RETURN_ERROR);

	unf_xchg = (struct unf_xchg *)unf_pkg->xchg_contex;
	FC_CHECK_RETURN_VALUE(unf_xchg, UNF_RETURN_ERROR);

	/* Get SGL Entry buffer for INI Mode */
	ret = unf_ini_get_sgl_entry_buf(unf_xchg->scsi_cmnd_info.unf_get_sgl_entry_buf,
					unf_xchg->scsi_cmnd_info.scsi_cmnd, NULL,
					&unf_xchg->dif_sgl_info.sgl,
					&unf_xchg->scsi_cmnd_info.port_id,
					&((unf_xchg->dif_sgl_info).entry_index), buf, buf_len);
	return ret;
}

u32 unf_get_up_level_cmnd_errcode(struct unf_ini_error_code *err_table,
				  u32 err_table_count, u32 drv_err_code)
{
	u32 loop = 0;

	/* fail return UNF_RETURN_ERROR,adjust by up level */
	if (unlikely(!err_table)) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_MAJOR,
			     "Error Code Table is Null, Error Code(0x%x).", drv_err_code);

		return (u32)UNF_SCSI_HOST(DID_ERROR);
	}

	for (loop = 0; loop < err_table_count; loop++) {
		if (err_table[loop].drv_errcode == drv_err_code)
			return err_table[loop].ap_errcode;
	}

	FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
		     "[warn]Unsupported Ap Error code by Error Code(0x%x).", drv_err_code);

	return (u32)UNF_SCSI_HOST(DID_ERROR);
}

static u32 unf_ini_status_handle(struct unf_xchg *xchg,
				 struct unf_frame_pkg *pkg)
{
	u32 loop = 0;
	u32 ret = UNF_RETURN_ERROR;
	u32 up_status = 0;

	for (loop = 0; loop < sizeof(ini_error_handler_table) /
				  sizeof(struct unf_ini_error_handler_s); loop++) {
		if (UNF_GET_LL_ERR(pkg) == ini_error_handler_table[loop].ini_error_code) {
			up_status =
			    unf_get_up_level_cmnd_errcode(xchg->scsi_cmnd_info.err_code_table,
							  xchg->scsi_cmnd_info.err_code_table_cout,
							  UNF_GET_LL_ERR(pkg));

			if (ini_error_handler_table[loop].unf_ini_error_handler) {
				ret = ini_error_handler_table[loop]
					  .unf_ini_error_handler(xchg, pkg, up_status);
			} else {
				/* set exchange->result  ---to--->>>scsi_result */
				ret = unf_ini_error_default_handler(xchg, pkg, up_status);
			}

			return ret;
		}
	}

	up_status = unf_get_up_level_cmnd_errcode(xchg->scsi_cmnd_info.err_code_table,
						  xchg->scsi_cmnd_info.err_code_table_cout,
						  UNF_IO_SOFT_ERR);

	ret = unf_ini_error_default_handler(xchg, pkg, up_status);

	FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_ERR,
		     "[err]Can not find com status, SID(0x%x) exchange(0x%p) com_status(0x%x) DID(0x%x) hot_pool_tag(0x%x)",
		     xchg->sid, xchg, pkg->status, xchg->did, xchg->hotpooltag);

	return ret;
}

static void unf_analysis_response_info(struct unf_xchg *xchg,
				       struct unf_frame_pkg *pkg,
				       u32 *up_status)
{
	u8 *resp_buf = NULL;

	/* LL_Driver use Little End, and copy RSP_INFO to COM_Driver */
	if (unlikely(pkg->unf_rsp_pload_bl.length > UNF_RESPONE_DATA_LEN)) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]Receive FCP response resp buffer len is invalid 0x%x",
			     pkg->unf_rsp_pload_bl.length);
		return;
	}

	resp_buf = (u8 *)pkg->unf_rsp_pload_bl.buffer_ptr;
	if (resp_buf) {
		/* If chip use Little End, then change it to Big End */
		if ((pkg->byte_orders & UNF_BIT_3) == 0)
			unf_cpu_to_big_end(resp_buf, pkg->unf_rsp_pload_bl.length);

		/* Chip DAM data with Big End */
		if (resp_buf[ARRAY_INDEX_3] != UNF_FCP_TM_RSP_COMPLETE) {
			*up_status = UNF_SCSI_HOST(DID_BUS_BUSY);

			FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
				     "[warn]Port(0x%p) DID bus busy, scsi_status(0x%x)",
				     xchg->lport, UNF_GET_SCSI_STATUS(pkg));
		}
	} else {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]Receive FCP response, resp buffer is NULL resp buffer len is 0x%x",
			     pkg->unf_rsp_pload_bl.length);
	}
}

static void unf_analysis_sense_info(struct unf_xchg *xchg,
				    struct unf_frame_pkg *pkg, u32 *up_status)
{
	u32 length = 0;

	/* 4 bytes Align */
	length = MIN(SCSI_SENSE_DATA_LEN, pkg->unf_sense_pload_bl.length);

	if (unlikely(pkg->unf_sense_pload_bl.length > SCSI_SENSE_DATA_LEN)) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[info]Receive FCP response resp buffer len is 0x%x",
			     pkg->unf_sense_pload_bl.length);
	}
	/*
	 * If have sense info then copy directly
	 * else, the chip has been dma the data to sense buffer
	 */

	if (length != 0 && pkg->unf_rsp_pload_bl.buffer_ptr) {
		/* has been dma to exchange buffer */
		if (unlikely(pkg->unf_rsp_pload_bl.length > UNF_RESPONE_DATA_LEN)) {
			*up_status = UNF_SCSI_HOST(DID_ERROR);

			FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
				     "[warn]Receive FCP response resp buffer len is invalid 0x%x",
				     pkg->unf_rsp_pload_bl.length);

			return;
		}

		xchg->fcp_sfs_union.fcp_rsp_entry.fcp_rsp_iu = (u8 *)kmalloc(length, GFP_ATOMIC);
		if (!xchg->fcp_sfs_union.fcp_rsp_entry.fcp_rsp_iu) {
			FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_ERR,
				     "[err]Alloc FCP sense buffer failed");
			return;
		}

		memcpy(xchg->fcp_sfs_union.fcp_rsp_entry.fcp_rsp_iu,
		       ((u8 *)(pkg->unf_rsp_pload_bl.buffer_ptr)) +
		       pkg->unf_rsp_pload_bl.length, length);

		xchg->fcp_sfs_union.fcp_rsp_entry.fcp_sense_len = length;
	} else {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]Receive FCP response, sense buffer is NULL sense buffer len is 0x%x",
			     length);
	}
}

static u32 unf_io_success_handler(struct unf_xchg *xchg,
				  struct unf_frame_pkg *pkg, u32 up_status)
{
	u8 scsi_status = 0;
	u8 control = 0;
	u32 status = up_status;

	FC_CHECK_RETURN_VALUE(xchg, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(pkg, UNF_RETURN_ERROR);

	control = UNF_GET_FCP_CTL(pkg);
	scsi_status = UNF_GET_SCSI_STATUS(pkg);

	FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_INFO,
		     "[info]Port(0x%p), Exchange(0x%p) Completed, Control(0x%x), Scsi Status(0x%x)",
		     xchg->lport, xchg, control, scsi_status);

	if (control & FCP_SNS_LEN_VALID_MASK) {
		/* has sense info */
		if (scsi_status == FCP_SCSI_STATUS_GOOD)
			scsi_status = SCSI_CHECK_CONDITION;

		unf_analysis_sense_info(xchg, pkg, &status);
	} else {
		/*
		 * When the FCP_RSP_LEN_VALID bit is set to one,
		 * the content of the SCSI STATUS CODE field is not reliable
		 * and shall be ignored by the application client.
		 */
		if (control & FCP_RSP_LEN_VALID_MASK)
			unf_analysis_response_info(xchg, pkg, &status);
	}

	xchg->scsi_cmnd_info.result = status | UNF_SCSI_STATUS(scsi_status);

	return RETURN_OK;
}

static u32 unf_ini_error_default_handler(struct unf_xchg *xchg,
					 struct unf_frame_pkg *pkg,
					 u32 up_status)
{
	/* set exchange->result  ---to--->>> scsi_cmnd->result */
	FC_CHECK_RETURN_VALUE(xchg, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(pkg, UNF_RETURN_ERROR);

	FC_DRV_PRINT(UNF_LOG_ABNORMAL, UNF_WARN,
		     "[warn]SID(0x%x) exchange(0x%p) com_status(0x%x) up_status(0x%x) DID(0x%x) hot_pool_tag(0x%x) response_len(0x%x)",
		     xchg->sid, xchg, pkg->status, up_status, xchg->did,
		     xchg->hotpooltag, pkg->residus_len);

	xchg->scsi_cmnd_info.result =
	    up_status | UNF_SCSI_STATUS(UNF_GET_SCSI_STATUS(pkg));

	return RETURN_OK;
}

static u32 unf_ini_dif_error_handler(struct unf_xchg *xchg,
				     struct unf_frame_pkg *pkg, u32 up_status)
{
	u8 *sense_data = NULL;
	u16 sense_code = 0;

	FC_CHECK_RETURN_VALUE(xchg, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(pkg, UNF_RETURN_ERROR);

	/*
	 * According to DIF scheme
	 * drive set check condition(0x2) when dif error occurs,
	 * and returns the values base on the upper-layer verification resule
	 * Check sequence: crc,Lba,App,
	 * if CRC error is found, the subsequent check is not performed
	 */
	xchg->scsi_cmnd_info.result = UNF_SCSI_STATUS(SCSI_CHECK_CONDITION);

	sense_code = (u16)pkg->status_sub_code;
	sense_data = (u8 *)kmalloc(SCSI_SENSE_DATA_LEN, GFP_ATOMIC);
	if (!sense_data) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_ERR,
			     "[err]Alloc FCP sense buffer failed");

		return UNF_RETURN_ERROR;
	}
	memset(sense_data, 0, SCSI_SENSE_DATA_LEN);
	sense_data[ARRAY_INDEX_0] = SENSE_DATA_RESPONSE_CODE; /* response code:0x70 */
	sense_data[ARRAY_INDEX_2] = ILLEGAL_REQUEST; /* sense key:0x05; */
	sense_data[ARRAY_INDEX_7] = ADDITINONAL_SENSE_LEN; /* additional sense length:0x7 */
	sense_data[ARRAY_INDEX_12] = (u8)(sense_code >> UNF_SHIFT_8);
	sense_data[ARRAY_INDEX_13] = (u8)sense_code;

	xchg->fcp_sfs_union.fcp_rsp_entry.fcp_rsp_iu = sense_data;
	xchg->fcp_sfs_union.fcp_rsp_entry.fcp_sense_len = SCSI_SENSE_DATA_LEN;

	/* valid sense data length snscode[13] */
	return RETURN_OK;
}

static u32 unf_io_underflow_handler(struct unf_xchg *xchg,
				    struct unf_frame_pkg *pkg, u32 up_status)
{
	/* under flow: residlen > 0 */
	FC_CHECK_RETURN_VALUE(xchg, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(pkg, UNF_RETURN_ERROR);

	if (xchg->fcp_cmnd.cdb[ARRAY_INDEX_0] != SCSIOPC_REPORT_LUN &&
	    xchg->fcp_cmnd.cdb[ARRAY_INDEX_0] != SCSIOPC_INQUIRY) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_INFO,
			     "[info]IO under flow: SID(0x%x) exchange(0x%p) com status(0x%x) up_status(0x%x) DID(0x%x) hot_pool_tag(0x%x) response SID(0x%x)",
			     xchg->sid, xchg, pkg->status, up_status,
			     xchg->did, xchg->hotpooltag, pkg->residus_len);
	}

	xchg->resid_len = (int)pkg->residus_len;
	(void)unf_io_success_handler(xchg, pkg, up_status);

	return RETURN_OK;
}

void unf_complete_cmnd(struct unf_scsi_cmnd *scsi_cmnd, u32 result_size)
{
	/*
	 * Exception during process Que_CMND
	 * 1. L_Port == NULL;
	 * 2. L_Port == removing;
	 * 3. R_Port == NULL;
	 * 4. Xchg == NULL.
	 */
	FC_CHECK_RETURN_VOID((UNF_GET_CMND_DONE_FUNC(scsi_cmnd)));

	FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_INFO,
		     "[info]Command(0x%p), Result(0x%x).", scsi_cmnd, result_size);

	UNF_SET_CMND_RESULT(scsi_cmnd, result_size);

	UNF_DONE_SCSI_CMND(scsi_cmnd);
}

static inline void unf_bind_xchg_scsi_cmd(struct unf_xchg *xchg,
					  struct unf_scsi_cmnd *scsi_cmnd)
{
	struct unf_scsi_cmd_info *scsi_cmnd_info = NULL;

	scsi_cmnd_info = &xchg->scsi_cmnd_info;

	/* UNF_SCSI_CMND_INFO <<-- UNF_SCSI_CMND */
	scsi_cmnd_info->err_code_table = UNF_GET_ERR_CODE_TABLE(scsi_cmnd);
	scsi_cmnd_info->err_code_table_cout = UNF_GET_ERR_CODE_TABLE_COUNT(scsi_cmnd);
	scsi_cmnd_info->done = UNF_GET_CMND_DONE_FUNC(scsi_cmnd);
	scsi_cmnd_info->scsi_cmnd = UNF_GET_HOST_CMND(scsi_cmnd);
	scsi_cmnd_info->sense_buf = (char *)UNF_GET_SENSE_BUF_ADDR(scsi_cmnd);
	scsi_cmnd_info->uplevel_done = UNF_GET_UP_LEVEL_CMND_DONE(scsi_cmnd);
	scsi_cmnd_info->unf_get_sgl_entry_buf = UNF_GET_SGL_ENTRY_BUF_FUNC(scsi_cmnd);
	scsi_cmnd_info->sgl = UNF_GET_CMND_SGL(scsi_cmnd);
	scsi_cmnd_info->time_out = scsi_cmnd->time_out;
	scsi_cmnd_info->entry_cnt = scsi_cmnd->entry_count;
	scsi_cmnd_info->port_id = (u32)scsi_cmnd->port_id;
	scsi_cmnd_info->scsi_id = UNF_GET_SCSI_ID_BY_CMND(scsi_cmnd);
}

u32 unf_ini_scsi_completed(void *lport, struct unf_frame_pkg *pkg)
{
	struct unf_lport *unf_lport = NULL;
	struct unf_xchg *unf_xchg = NULL;
	struct unf_fcp_cmnd *fcp_cmnd = NULL;
	u32 control = 0;
	u16 xchg_tag = 0x0ffff;
	u32 ret = UNF_RETURN_ERROR;
	ulong xchg_flag = 0;

	FC_CHECK_RETURN_VALUE(lport, UNF_RETURN_ERROR);
	FC_CHECK_RETURN_VALUE(pkg, UNF_RETURN_ERROR);

	unf_lport = (struct unf_lport *)lport;
	xchg_tag = (u16)pkg->private_data[PKG_PRIVATE_XCHG_HOT_POOL_INDEX];

	/* 1. Find Exchange Context */
	unf_xchg = unf_cm_lookup_xchg_by_tag(lport, (u16)xchg_tag);
	if (unlikely(!unf_xchg)) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]Port(0x%x_0x%x) can not find exchange by tag(0x%x)",
			     unf_lport->port_id, unf_lport->nport_id, xchg_tag);

		/* NOTE: return directly */
		return UNF_RETURN_ERROR;
	}

	/* 2. Consistency check */
	UNF_CHECK_ALLOCTIME_VALID(unf_lport, xchg_tag, unf_xchg,
				  pkg->private_data[PKG_PRIVATE_XCHG_ALLOC_TIME],
				  unf_xchg->private_data[PKG_PRIVATE_XCHG_ALLOC_TIME]);

	/* 3. Increase ref_cnt for exchange protecting */
	ret = unf_xchg_ref_inc(unf_xchg, INI_RESPONSE_DONE); /* hold */
	FC_CHECK_RETURN_VALUE((ret == RETURN_OK), UNF_RETURN_ERROR);

	fcp_cmnd = &unf_xchg->fcp_cmnd;
	control = fcp_cmnd->control;
	control = UNF_GET_TASK_MGMT_FLAGS(control);

	/* 4. Cancel timer if necessary */
	if (unf_xchg->scsi_cmnd_info.time_out != 0)
		unf_lport->xchg_mgr_temp.unf_xchg_cancel_timer(unf_xchg);

	/* 5. process scsi TMF if necessary */
	if (control != 0) {
		unf_process_scsi_mgmt_result(pkg, unf_xchg);
		unf_xchg_ref_dec(unf_xchg, INI_RESPONSE_DONE); /* cancel hold */

		/* NOTE: return directly */
		return RETURN_OK;
	}

	/* 6. Xchg Abort state check */
	spin_lock_irqsave(&unf_xchg->xchg_state_lock, xchg_flag);
	unf_xchg->oxid = UNF_GET_OXID(pkg);
	unf_xchg->rxid = UNF_GET_RXID(pkg);
	if (INI_IO_STATE_UPABORT & unf_xchg->io_state) {
		spin_unlock_irqrestore(&unf_xchg->xchg_state_lock, xchg_flag);

		FC_DRV_PRINT(UNF_LOG_NORMAL, UNF_WARN,
			     "[warn]Port(0x%x) find exchange(%p) state(0x%x) has been aborted",
			     unf_lport->port_id, unf_xchg, unf_xchg->io_state);

		/* NOTE: release exchange during SCSI ABORT(ABTS) */
		unf_xchg_ref_dec(unf_xchg, INI_RESPONSE_DONE); /* cancel hold */

		return ret;
	}
	spin_unlock_irqrestore(&unf_xchg->xchg_state_lock, xchg_flag);

	/*
	 * 7. INI SCSI CMND Status process
	 * set exchange->result ---to--->>> scsi_result
	 */
	ret = unf_ini_status_handle(unf_xchg, pkg);

	/* 8. release exchangenecessary */
	unf_cm_free_xchg(unf_lport, unf_xchg);

	/* 9. dec exch ref_cnt */
	unf_xchg_ref_dec(unf_xchg, INI_RESPONSE_DONE); /* cancel hold: release resource now */

	return ret;
}

u32 unf_hardware_start_io(struct unf_lport *lport, struct unf_frame_pkg *pkg)
{
	if (unlikely(!lport->low_level_func.service_op.unf_cmnd_send)) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_ERR,
			     "[err]Port(0x%x) low level send scsi function is NULL",
			     lport->port_id);

		return UNF_RETURN_ERROR;
	}

	return lport->low_level_func.service_op.unf_cmnd_send(lport->fc_port, pkg);
}

struct unf_rport *unf_find_rport_by_scsi_id(struct unf_lport *lport,
					    struct unf_ini_error_code *err_code_table,
					    u32 err_code_table_cout, u32 scsi_id, u32 *scsi_result)
{
	struct unf_rport_scsi_id_image *scsi_image_table = NULL;
	struct unf_wwpn_rport_info *wwpn_rport_info = NULL;
	struct unf_rport *unf_rport = NULL;
	ulong flags = 0;

	/* scsi_table -> session_table ->image_table */
	scsi_image_table = &lport->rport_scsi_table;

	/* 1. Scsi_Id validity check */
	if (unlikely(scsi_id >= scsi_image_table->max_scsi_id)) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_ERR,
			     "[err]Input scsi_id(0x%x) bigger than max_scsi_id(0x%x).",
			     scsi_id, scsi_image_table->max_scsi_id);

		*scsi_result = unf_get_up_level_cmnd_errcode(err_code_table, err_code_table_cout,
							     UNF_IO_SOFT_ERR); /* did_soft_error */

		return NULL;
	}

	/* 2. GetR_Port_Info/R_Port: use Scsi_Id find from L_Port's
	 * Rport_Scsi_Table (image table)
	 */
	spin_lock_irqsave(&scsi_image_table->scsi_image_table_lock, flags);
	wwpn_rport_info = &scsi_image_table->wwn_rport_info_table[scsi_id];
	unf_rport = wwpn_rport_info->rport;
	spin_unlock_irqrestore(&scsi_image_table->scsi_image_table_lock, flags);

	if (unlikely(!unf_rport)) {
		*scsi_result = unf_get_up_level_cmnd_errcode(err_code_table,
							     err_code_table_cout,
							     UNF_IO_PORT_LOGOUT);

		return NULL;
	}

	return unf_rport;
}

static u32 unf_build_xchg_fcpcmnd(struct unf_fcp_cmnd *fcp_cmnd,
				  struct unf_scsi_cmnd *scsi_cmnd)
{
	memcpy(fcp_cmnd->cdb, &UNF_GET_FCP_CMND(scsi_cmnd), scsi_cmnd->cmnd_len);

	if ((fcp_cmnd->control == UNF_FCP_WR_DATA &&
	     (IS_READ_COMMAND(fcp_cmnd->cdb[ARRAY_INDEX_0]))) ||
	    (fcp_cmnd->control == UNF_FCP_RD_DATA &&
	     (IS_WRITE_COMMAND(fcp_cmnd->cdb[ARRAY_INDEX_0])))) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_MINOR,
			     "Scsi command direction inconsistent, CDB[ARRAY_INDEX_0](0x%x), direction(0x%x).",
			     fcp_cmnd->cdb[ARRAY_INDEX_0], fcp_cmnd->control);

		return UNF_RETURN_ERROR;
	}

	memcpy(fcp_cmnd->lun, scsi_cmnd->lun_id, sizeof(fcp_cmnd->lun));

	unf_big_end_to_cpu((void *)fcp_cmnd->cdb, sizeof(fcp_cmnd->cdb));
	fcp_cmnd->data_length = UNF_GET_DATA_LEN(scsi_cmnd);

	return RETURN_OK;
}

static void unf_adjust_xchg_len(struct unf_xchg *xchg, u32 scsi_cmnd)
{
	switch (scsi_cmnd) {
	case SCSIOPC_REQUEST_SENSE: /* requires different buffer */
		xchg->data_len = UNF_SCSI_SENSE_BUFFERSIZE;

		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_MINOR, "Request Sense new.");
		break;

	case SCSIOPC_TEST_UNIT_READY:
	case SCSIOPC_RESERVE:
	case SCSIOPC_RELEASE:
	case SCSIOPC_START_STOP_UNIT:
		xchg->data_len = 0;
		break;

	default:
		break;
	}
}

static void unf_copy_dif_control(struct unf_dif_control_info *dif_control,
				 struct unf_scsi_cmnd *scsi_cmnd)
{
	dif_control->fcp_dl = scsi_cmnd->dif_control.fcp_dl;
	dif_control->protect_opcode = scsi_cmnd->dif_control.protect_opcode;
	dif_control->start_lba = scsi_cmnd->dif_control.start_lba;
	dif_control->app_tag = scsi_cmnd->dif_control.app_tag;

	dif_control->flags = scsi_cmnd->dif_control.flags;
	dif_control->dif_sge_count = scsi_cmnd->dif_control.dif_sge_count;
	dif_control->dif_sgl = scsi_cmnd->dif_control.dif_sgl;
}

static void unf_adjust_dif_pci_transfer_len(struct unf_xchg *xchg, u32 direction)
{
	struct unf_dif_control_info *dif_control = NULL;
	u32 sector_size = 0;

	dif_control = &xchg->dif_control;

	if (dif_control->protect_opcode == UNF_DIF_ACTION_NONE)
		return;
	if ((dif_control->flags & UNF_DIF_SECTSIZE_4KB) == 0)
		sector_size = SECTOR_SIZE_512;
	else
		sector_size = SECTOR_SIZE_4096;
	switch (dif_control->protect_opcode & UNF_DIF_ACTION_MASK) {
	case UNF_DIF_ACTION_INSERT:
		if (direction == DMA_TO_DEVICE) {
			/* write IO,insert,Indicates that data with DIF is
			 * transmitted over the link.
			 */
			dif_control->fcp_dl = xchg->data_len +
			    UNF_CAL_BLOCK_CNT(xchg->data_len, sector_size) * UNF_DIF_AREA_SIZE;
		} else {
			/* read IO,insert,Indicates that the internal DIf is
			 * carried, and the link does not carry the DIf.
			 */
			dif_control->fcp_dl = xchg->data_len;
		}
		break;

	case UNF_DIF_ACTION_VERIFY_AND_DELETE:
		if (direction == DMA_TO_DEVICE) {
			/* write IO,Delete,Indicates that the internal DIf is
			 * carried, and the link does not carry the DIf.
			 */
			dif_control->fcp_dl = xchg->data_len;
		} else {
			/* read IO,Delete,Indicates that data with DIF is
			 * carried on the link and does not contain DIF on
			 * internal.
			 */
			dif_control->fcp_dl = xchg->data_len +
			    UNF_CAL_BLOCK_CNT(xchg->data_len, sector_size) * UNF_DIF_AREA_SIZE;
		}
		break;

	case UNF_DIF_ACTION_VERIFY_AND_FORWARD:
		dif_control->fcp_dl = xchg->data_len +
		    UNF_CAL_BLOCK_CNT(xchg->data_len, sector_size) * UNF_DIF_AREA_SIZE;
		break;

	default:
		dif_control->fcp_dl = xchg->data_len;
		break;
	}

	xchg->fcp_cmnd.data_length = dif_control->fcp_dl;
}

static void unf_get_dma_direction(struct unf_fcp_cmnd *fcp_cmnd,
				  struct unf_scsi_cmnd *scsi_cmnd)
{
	if (UNF_GET_DATA_DIRECTION(scsi_cmnd) == DMA_TO_DEVICE) {
		fcp_cmnd->control = UNF_FCP_WR_DATA;
	} else if (UNF_GET_DATA_DIRECTION(scsi_cmnd) == DMA_FROM_DEVICE) {
		fcp_cmnd->control = UNF_FCP_RD_DATA;
	} else {
		/* DMA Direction None */
		fcp_cmnd->control = 0;
	}
}

static int unf_save_scsi_cmnd_to_xchg(struct unf_lport *lport,
				      struct unf_rport *rport,
				      struct unf_xchg *xchg,
				      struct unf_scsi_cmnd *scsi_cmnd)
{
	struct unf_lport *unf_lport = lport;
	struct unf_rport *unf_rport = rport;
	struct unf_xchg *unf_xchg = xchg;
	u32 result_size = 0;

	scsi_cmnd->driver_scribble = (void *)unf_xchg->start_jif;
	unf_xchg->rport = unf_rport;
	unf_xchg->rport_bind_jifs = unf_rport->rport_alloc_jifs;

	/* Build Xchg SCSI_CMND info */
	unf_bind_xchg_scsi_cmd(unf_xchg, scsi_cmnd);

	unf_xchg->data_len = UNF_GET_DATA_LEN(scsi_cmnd);
	unf_xchg->data_direction = UNF_GET_DATA_DIRECTION(scsi_cmnd);
	unf_xchg->sid = unf_lport->nport_id;
	unf_xchg->did = unf_rport->nport_id;
	unf_xchg->private_data[PKG_PRIVATE_XCHG_RPORT_INDEX] = unf_rport->rport_index;
	unf_xchg->world_id = scsi_cmnd->world_id;
	unf_xchg->cmnd_sn = scsi_cmnd->cmnd_sn;
	unf_xchg->pinitiator = scsi_cmnd->pinitiator;
	unf_xchg->scsi_id = scsi_cmnd->scsi_id;
	if (scsi_cmnd->qos_level == UNF_QOS_LEVEL_DEFAULT)
		unf_xchg->qos_level = unf_rport->qos_level;
	else
		unf_xchg->qos_level = scsi_cmnd->qos_level;

	unf_get_dma_direction(&unf_xchg->fcp_cmnd, scsi_cmnd);
	result_size = unf_build_xchg_fcpcmnd(&unf_xchg->fcp_cmnd, scsi_cmnd);
	if (unlikely(result_size != RETURN_OK))
		return UNF_RETURN_ERROR;

	unf_adjust_xchg_len(unf_xchg, UNF_GET_FCP_CMND(scsi_cmnd));

	unf_adjust_xchg_len(unf_xchg, UNF_GET_FCP_CMND(scsi_cmnd));

	/* Dif (control) info */
	unf_copy_dif_control(&unf_xchg->dif_control, scsi_cmnd);
	memcpy(&unf_xchg->dif_info, &scsi_cmnd->dif_info, sizeof(struct dif_info));
	unf_adjust_dif_pci_transfer_len(unf_xchg, UNF_GET_DATA_DIRECTION(scsi_cmnd));

	/* single sgl info */
	if (unf_xchg->data_direction != DMA_NONE && UNF_GET_CMND_SGL(scsi_cmnd)) {
		unf_xchg->req_sgl_info.sgl = UNF_GET_CMND_SGL(scsi_cmnd);
		unf_xchg->req_sgl_info.sgl_start = unf_xchg->req_sgl_info.sgl;
			/* Save the sgl header for easy
			 * location and printing.
			 */
		unf_xchg->req_sgl_info.req_index = 0;
		unf_xchg->req_sgl_info.entry_index = 0;
	}

	if (scsi_cmnd->dif_control.dif_sgl) {
		unf_xchg->dif_sgl_info.sgl = UNF_INI_GET_DIF_SGL(scsi_cmnd);
		unf_xchg->dif_sgl_info.entry_index = 0;
		unf_xchg->dif_sgl_info.req_index = 0;
		unf_xchg->dif_sgl_info.sgl_start = unf_xchg->dif_sgl_info.sgl;
	}

	return RETURN_OK;
}

static int unf_send_fcpcmnd(struct unf_lport *lport, struct unf_rport *rport,
			    struct unf_xchg *xchg)
{
#define UNF_MAX_PENDING_IO_CNT 3
	struct unf_scsi_cmd_info *scsi_cmnd_info = NULL;
	struct unf_lport *unf_lport = lport;
	struct unf_rport *unf_rport = rport;
	struct unf_xchg *unf_xchg = xchg;
	struct unf_frame_pkg pkg = {0};
	u32 result_size = 0;
	ulong flags = 0;

	memcpy(&pkg.dif_control, &unf_xchg->dif_control, sizeof(struct unf_dif_control_info));
	pkg.dif_control.fcp_dl = unf_xchg->dif_control.fcp_dl;
	pkg.transfer_len = unf_xchg->data_len; /* Pcie data transfer length */
	pkg.xchg_contex = unf_xchg;
	pkg.qos_level = unf_xchg->qos_level;
	scsi_cmnd_info = &xchg->scsi_cmnd_info;
	pkg.entry_count = unf_xchg->scsi_cmnd_info.entry_cnt;
	if (unf_xchg->data_direction == DMA_NONE || !scsi_cmnd_info->sgl)
		pkg.entry_count = 0;

	pkg.private_data[PKG_PRIVATE_XCHG_ALLOC_TIME] =
	    unf_xchg->private_data[PKG_PRIVATE_XCHG_ALLOC_TIME];
	pkg.private_data[PKG_PRIVATE_XCHG_VP_INDEX] = unf_lport->vp_index;
	pkg.private_data[PKG_PRIVATE_XCHG_RPORT_INDEX] = unf_rport->rport_index;
	pkg.private_data[PKG_PRIVATE_XCHG_HOT_POOL_INDEX] =
	    unf_xchg->hotpooltag | UNF_HOTTAG_FLAG;

	unf_select_sq(unf_xchg, &pkg);
	pkg.fcp_cmnd = &unf_xchg->fcp_cmnd;
	pkg.frame_head.csctl_sid = unf_lport->nport_id;
	pkg.frame_head.rctl_did = unf_rport->nport_id;
	pkg.upper_cmd = unf_xchg->scsi_cmnd_info.scsi_cmnd;

	/* exch->fcp_rsp_id --->>> pkg->buffer_ptr */
	pkg.frame_head.oxid_rxid = ((u32)unf_xchg->oxid << (u32)UNF_SHIFT_16 | unf_xchg->rxid);

	FC_DRV_PRINT(UNF_LOG_EQUIP_ATT, UNF_INFO,
		     "[info]LPort (0x%p), Nport ID(0x%x) RPort ID(0x%x) direction(0x%x) magic number(0x%x) IO to entry count(0x%x) hottag(0x%x)",
		     unf_lport, unf_lport->nport_id, unf_rport->nport_id,
		     xchg->data_direction, pkg.private_data[PKG_PRIVATE_XCHG_ALLOC_TIME],
		     pkg.entry_count, unf_xchg->hotpooltag);

	atomic_inc(&unf_rport->pending_io_cnt);
	if (unf_rport->tape_support_needed &&
	    (atomic_read(&unf_rport->pending_io_cnt) <= UNF_MAX_PENDING_IO_CNT)) {
		spin_lock_irqsave(&xchg->xchg_state_lock, flags);
		unf_xchg->io_state |= INI_IO_STATE_REC_TIMEOUT_WAIT;
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);
		scsi_cmnd_info->abort_time_out = scsi_cmnd_info->time_out;
		scsi_cmnd_info->time_out = UNF_REC_TOV;
	}
	/* 3. add INI I/O timer if necessary */
	if (scsi_cmnd_info->time_out != 0) {
		/* I/O inner timer, do not used at this time */
		unf_lport->xchg_mgr_temp.unf_xchg_add_timer(unf_xchg,
		    scsi_cmnd_info->time_out, UNF_TIMER_TYPE_REQ_IO);
	}

	/* 4. R_Port state check */
	if (unlikely(unf_rport->lport_ini_state != UNF_PORT_STATE_LINKUP ||
		     unf_rport->rp_state > UNF_RPORT_ST_READY)) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[info]Port(0x%x) RPort(0x%p) NPortId(0x%x) inistate(0x%x): RPort state(0x%x) pUpperCmd(0x%p) is not ready",
			     unf_lport->port_id, unf_rport, unf_rport->nport_id,
			     unf_rport->lport_ini_state, unf_rport->rp_state, pkg.upper_cmd);

		result_size = unf_get_up_level_cmnd_errcode(scsi_cmnd_info->err_code_table,
							    scsi_cmnd_info->err_code_table_cout,
							    UNF_IO_INCOMPLETE);
		scsi_cmnd_info->result = result_size;

		if (scsi_cmnd_info->time_out != 0)
			unf_lport->xchg_mgr_temp.unf_xchg_cancel_timer(unf_xchg);

		unf_cm_free_xchg(unf_lport, unf_xchg);

		/* DID_IMM_RETRY */
		return RETURN_OK;
	} else if (unf_rport->rp_state < UNF_RPORT_ST_READY) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[info]Port(0x%x) RPort(0x%p) NPortId(0x%x) inistate(0x%x): RPort state(0x%x) pUpperCmd(0x%p) is not ready",
			     unf_lport->port_id, unf_rport, unf_rport->nport_id,
			     unf_rport->lport_ini_state, unf_rport->rp_state, pkg.upper_cmd);

		spin_lock_irqsave(&xchg->xchg_state_lock, flags);
		unf_xchg->io_state |= INI_IO_STATE_UPSEND_ERR; /* need retry */
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);

		if (unlikely(scsi_cmnd_info->time_out != 0))
			unf_lport->xchg_mgr_temp.unf_xchg_cancel_timer((void *)unf_xchg);

		/* Host busy & need scsi retry */
		return UNF_RETURN_ERROR;
	}

	/* 5. send scsi_cmnd to FC_LL Driver */
	if (unf_hardware_start_io(unf_lport, &pkg) != RETURN_OK) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]Port (0x%x) pUpperCmd(0x%p) Hardware Send IO failed.",
			     unf_lport->port_id, pkg.upper_cmd);

		unf_release_esgls(unf_xchg);

		result_size = unf_get_up_level_cmnd_errcode(scsi_cmnd_info->err_code_table,
							    scsi_cmnd_info->err_code_table_cout,
							    UNF_IO_INCOMPLETE);
		scsi_cmnd_info->result = result_size;

		if (scsi_cmnd_info->time_out != 0)
			unf_lport->xchg_mgr_temp.unf_xchg_cancel_timer(unf_xchg);

		unf_cm_free_xchg(unf_lport, unf_xchg);

		/* SCSI_DONE */
		return RETURN_OK;
	}

	return RETURN_OK;
}

int unf_prefer_to_send_scsi_cmnd(struct unf_xchg *xchg)
{
	/*
	 * About INI_IO_STATE_DRABORT:
	 * 1. Set ABORT tag: Clean L_Port/V_Port Link Down I/O
	 * with: INI_busy_list, delay_list, delay_transfer_list, wait_list
	 * *
	 * 2. Set ABORT tag: for target session:
	 * with: INI_busy_list, delay_list, delay_transfer_list, wait_list
	 * a. R_Port remove
	 * b. Send PLOGI_ACC callback
	 * c. RCVD PLOGI
	 * d. RCVD LOGO
	 * *
	 * 3. if set ABORT: prevent send scsi_cmnd to target
	 */
	struct unf_lport *unf_lport = NULL;
	struct unf_rport *unf_rport = NULL;
	int ret = RETURN_OK;
	ulong flags = 0;

	unf_lport = xchg->lport;

	unf_rport = xchg->rport;
	if (unlikely(!unf_lport || !unf_rport)) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_ERR,
			     "[err]Port(0x%p) or RPort(0x%p) is NULL", unf_lport, unf_rport);

		/* if happened (never happen): need retry */
		return UNF_RETURN_ERROR;
	}

	/* 1. inc ref_cnt to protect exchange */
	ret = (int)unf_xchg_ref_inc(xchg, INI_SEND_CMND);
	if (unlikely(ret != RETURN_OK)) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]Port(0x%x) exhg(%p) exception ref(%d) ", unf_lport->port_id,
			     xchg, atomic_read(&xchg->ref_cnt));
		/* exchange exception, need retry */
		spin_lock_irqsave(&xchg->xchg_state_lock, flags);
		xchg->io_state |= INI_IO_STATE_UPSEND_ERR;
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);

		/* INI_IO_STATE_UPSEND_ERR: Host busy --->>> need retry */
		return UNF_RETURN_ERROR;
	}

	/* 2. Xchg Abort state check: Free EXCH if necessary */
	spin_lock_irqsave(&xchg->xchg_state_lock, flags);
	if (unlikely((xchg->io_state & INI_IO_STATE_UPABORT) ||
		     (xchg->io_state & INI_IO_STATE_DRABORT))) {
		/* Prevent to send: UP_ABORT/DRV_ABORT */
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);
		xchg->scsi_cmnd_info.result = UNF_SCSI_HOST(DID_IMM_RETRY);
		ret = RETURN_OK;

		unf_xchg_ref_dec(xchg, INI_SEND_CMND);
		unf_cm_free_xchg(unf_lport, xchg);

		/*
		 * Release exchange & return directly:
		 * 1. FC LLDD rcvd ABTS before scsi_cmnd: do nothing
		 * 2. INI_IO_STATE_UPABORT/INI_IO_STATE_DRABORT: discard this
		 * cmnd directly
		 */
		return ret;
	}
	spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);

	/* 3. Send FCP_CMND to FC_LL Driver */
	ret = unf_send_fcpcmnd(unf_lport, unf_rport, xchg);
	if (unlikely(ret != RETURN_OK)) {
		/* exchange exception, need retry */
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]Port(0x%x) send exhg(%p) hottag(0x%x) to Rport(%p) NPortID(0x%x) state(0x%x) scsi_id(0x%x) failed",
			     unf_lport->port_id, xchg, xchg->hotpooltag, unf_rport,
			     unf_rport->nport_id, unf_rport->rp_state, unf_rport->scsi_id);

		spin_lock_irqsave(&xchg->xchg_state_lock, flags);

		xchg->io_state |= INI_IO_STATE_UPSEND_ERR;
		/* need retry */
		spin_unlock_irqrestore(&xchg->xchg_state_lock, flags);
		/* INI_IO_STATE_UPSEND_ERR: Host busy --->>> need retry */
		unf_cm_free_xchg(unf_lport, xchg);
	}

	/* 4. dec ref_cnt */
	unf_xchg_ref_dec(xchg, INI_SEND_CMND);

	return ret;
}

struct unf_lport *unf_find_lport_by_scsi_cmd(struct unf_scsi_cmnd *scsi_cmnd)
{
	struct unf_lport *unf_lport = NULL;

	/* cmd -->> L_Port */
	unf_lport = (struct unf_lport *)UNF_GET_HOST_PORT_BY_CMND(scsi_cmnd);
	if (unlikely(!unf_lport)) {
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_WARN,
			     "[warn]Find Port by scsi_cmnd(0x%p) failed", scsi_cmnd);

		/* cmnd -->> scsi_host_id -->> L_Port */
		unf_lport = unf_find_lport_by_scsi_hostid(UNF_GET_SCSI_HOST_ID_BY_CMND(scsi_cmnd));
	}

	return unf_lport;
}

int unf_cm_queue_command(struct unf_scsi_cmnd *scsi_cmnd)
{
	/* SCSI Command --->>> FC FCP Command */
	struct unf_lport *unf_lport = NULL;
	struct unf_xchg *unf_xchg = NULL;
	struct unf_rport *unf_rport = NULL;
	struct unf_rport_scsi_id_image *scsi_image_table = NULL;
	u32 cmnd_result = 0;
	int ret = RETURN_OK;
	ulong flags = 0;
	u32 scsi_id = 0;
	u32 exhg_mgr_type = UNF_XCHG_MGR_TYPE_RANDOM;

	/* 1. Get L_Port */
	unf_lport = unf_find_lport_by_scsi_cmd(scsi_cmnd);

	/*
	 * corresponds to the insertion or removal scenario or the remove card
	 * scenario. This method is used to search for LPort information based
	 * on SCSI_HOST_ID. The Slave alloc is not invoked when LUNs are not
	 * scanned. Therefore, the Lport cannot be obtained. You need to obtain
	 * the Lport from the Lport linked list.
	 * *
	 * FC After Link Up, the first SCSI command is inquiry.
	 * Before inquiry, SCSI delivers slave_alloc.
	 */
	if (!unf_lport) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_ERR,
			     "[err]Find Port by scsi cmd(0x%p) failed", scsi_cmnd);

		/* find from ini_error_code_table1 */
		cmnd_result = unf_get_up_level_cmnd_errcode(scsi_cmnd->err_code_table,
							    scsi_cmnd->err_code_table_cout,
							    UNF_IO_NO_LPORT);

		/* DID_NOT_CONNECT & SCSI_DONE & RETURN_OK(0) & I/O error */
		unf_complete_cmnd(scsi_cmnd, cmnd_result);
		return RETURN_OK;
	}

	/* Get Local SCSI_Image_table & SCSI_ID */
	scsi_image_table = &unf_lport->rport_scsi_table;
	scsi_id = scsi_cmnd->scsi_id;

	/* 2. L_Port State check */
	if (unlikely(unf_lport->port_removing || unf_lport->pcie_link_down)) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[warn]Port(0x%x) is removing(%d) or pcielinkdown(%d) and return with scsi_id(0x%x)",
			     unf_lport->port_id, unf_lport->port_removing,
			     unf_lport->pcie_link_down, UNF_GET_SCSI_ID_BY_CMND(scsi_cmnd));

		cmnd_result = unf_get_up_level_cmnd_errcode(scsi_cmnd->err_code_table,
							    scsi_cmnd->err_code_table_cout,
							    UNF_IO_NO_LPORT);

		UNF_IO_RESULT_CNT(scsi_image_table, scsi_id, (cmnd_result >> UNF_SHIFT_16));

		/* DID_NOT_CONNECT & SCSI_DONE & RETURN_OK(0) & I/O error */
		unf_complete_cmnd(scsi_cmnd, cmnd_result);
		return RETURN_OK;
	}

	/* 3. Get R_Port */
	unf_rport = unf_find_rport_by_scsi_id(unf_lport, scsi_cmnd->err_code_table,
					      scsi_cmnd->err_code_table_cout,
					      UNF_GET_SCSI_ID_BY_CMND(scsi_cmnd), &cmnd_result);
	if (unlikely(!unf_rport)) {
		/* never happen: do not care */
		FC_DRV_PRINT(UNF_LOG_LOGIN_ATT, UNF_ERR,
			     "[err]Port(0x%x) find RPort by scsi_id(0x%x) failed",
			     unf_lport->port_id, UNF_GET_SCSI_ID_BY_CMND(scsi_cmnd));

		UNF_IO_RESULT_CNT(scsi_image_table, scsi_id, (cmnd_result >> UNF_SHIFT_16));

		/* DID_NOT_CONNECT/DID_SOFT_ERROR & SCSI_DONE & RETURN_OK(0) &
		 * I/O error
		 */
		unf_complete_cmnd(scsi_cmnd, cmnd_result);
		return RETURN_OK;
	}

	/* 4. Can't get exchange & return host busy, retry by uplevel */
	unf_xchg = (struct unf_xchg *)unf_cm_get_free_xchg(unf_lport,
		exhg_mgr_type << UNF_SHIFT_16 | UNF_XCHG_TYPE_INI);
	if (unlikely(!unf_xchg)) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[err]Port(0x%x) get free exchange for INI IO(0x%x) failed",
			     unf_lport->port_id, UNF_GET_SCSI_ID_BY_CMND(scsi_cmnd));

		/* NOTE: need scsi retry */
		return UNF_RETURN_ERROR;
	}

	unf_xchg->scsi_cmnd_info.result = UNF_SCSI_HOST(DID_ERROR);

	/* 5. Save the SCSI CMND information in advance. */
	ret = unf_save_scsi_cmnd_to_xchg(unf_lport, unf_rport, unf_xchg, scsi_cmnd);
	if (unlikely(ret != RETURN_OK)) {
		FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_WARN,
			     "[err]Port(0x%x) save scsi_cmnd info(0x%x) to exchange failed",
			     unf_lport->port_id, UNF_GET_SCSI_ID_BY_CMND(scsi_cmnd));

		spin_lock_irqsave(&unf_xchg->xchg_state_lock, flags);
		unf_xchg->io_state |= INI_IO_STATE_UPSEND_ERR;
		spin_unlock_irqrestore(&unf_xchg->xchg_state_lock, flags);

		/* INI_IO_STATE_UPSEND_ERR: Don't Do SCSI_DONE, need retry I/O */
		unf_cm_free_xchg(unf_lport, unf_xchg);

		/* NOTE: need scsi retry */
		return UNF_RETURN_ERROR;
	}

	FC_DRV_PRINT(UNF_LOG_IO_ATT, UNF_INFO,
		     "[info]Get exchange(0x%p) hottag(0x%x) for Pcmd:%p,Cmdsn:0x%lx,WorldId:%d",
		     unf_xchg, unf_xchg->hotpooltag, scsi_cmnd->upper_cmnd,
		     (ulong)scsi_cmnd->cmnd_sn, scsi_cmnd->world_id);
	/* 6. Send SCSI CMND */
	ret = unf_prefer_to_send_scsi_cmnd(unf_xchg);

	return ret;
}
