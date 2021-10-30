/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef UNF_IO_H
#define UNF_IO_H

#include "unf_type.h"
#include "unf_scsi_common.h"
#include "unf_exchg.h"
#include "unf_rport.h"

#define UNF_MAX_TARGET_NUMBER 2048
#define UNF_DEFAULT_MAX_LUN 0xFFFF
#define UNF_MAX_DMA_SEGS 0x400
#define UNF_MAX_SCSI_CMND_LEN 16
#define UNF_MAX_BUS_CHANNEL 0
#define UNF_DMA_BOUNDARY 0xffffffffffffffff
#define UNF_MAX_CMND_PER_LUN 64 /* LUN max command */
#define UNF_CHECK_LUN_ID_MATCH(lun_id, raw_lun_id, scsi_id, xchg)    \
	(((lun_id) == (raw_lun_id) || (lun_id) == INVALID_VALUE64) && \
	 ((scsi_id) == (xchg)->scsi_id))

#define NO_SENSE 0x00
#define RECOVERED_ERROR 0x01
#define NOT_READY 0x02
#define MEDIUM_ERROR 0x03
#define HARDWARE_ERROR 0x04
#define ILLEGAL_REQUEST 0x05
#define UNIT_ATTENTION 0x06
#define DATA_PROTECT 0x07
#define BLANK_CHECK 0x08
#define COPY_ABORTED 0x0a
#define ABORTED_COMMAND 0x0b
#define VOLUME_OVERFLOW 0x0d
#define MISCOMPARE 0x0e

#define SENSE_DATA_RESPONSE_CODE 0x70
#define ADDITINONAL_SENSE_LEN 0x7

extern u32 sector_size_flag;

#define UNF_GET_SCSI_HOST_ID_BY_CMND(cmd) ((cmd)->scsi_host_id)
#define UNF_GET_SCSI_ID_BY_CMND(cmd) ((cmd)->scsi_id)
#define UNF_GET_HOST_PORT_BY_CMND(cmd) ((cmd)->drv_private)
#define UNF_GET_FCP_CMND(cmd) ((cmd)->pcmnd[ARRAY_INDEX_0])
#define UNF_GET_DATA_LEN(cmd) ((cmd)->transfer_len)
#define UNF_GET_DATA_DIRECTION(cmd) ((cmd)->data_direction)

#define UNF_GET_HOST_CMND(cmd) ((cmd)->upper_cmnd)
#define UNF_GET_CMND_DONE_FUNC(cmd) ((cmd)->done)
#define UNF_GET_UP_LEVEL_CMND_DONE(cmd) ((cmd)->uplevel_done)
#define UNF_GET_SGL_ENTRY_BUF_FUNC(cmd) ((cmd)->unf_ini_get_sgl_entry)
#define UNF_GET_SENSE_BUF_ADDR(cmd) ((cmd)->sense_buf)
#define UNF_GET_ERR_CODE_TABLE(cmd) ((cmd)->err_code_table)
#define UNF_GET_ERR_CODE_TABLE_COUNT(cmd) ((cmd)->err_code_table_cout)

#define UNF_SET_HOST_CMND(cmd, host_cmd) ((cmd)->upper_cmnd = (host_cmd))
#define UNF_SER_CMND_DONE_FUNC(cmd, pfn) ((cmd)->done = (pfn))
#define UNF_SET_UP_LEVEL_CMND_DONE_FUNC(cmd, pfn) ((cmd)->uplevel_done = (pfn))

#define UNF_SET_RESID(cmd, uiresid) ((cmd)->resid = (uiresid))
#define UNF_SET_CMND_RESULT(cmd, uiresult) ((cmd)->result = ((int)(uiresult)))

#define UNF_DONE_SCSI_CMND(cmd) ((cmd)->done(cmd))

#define UNF_GET_CMND_SGL(cmd) ((cmd)->sgl)
#define UNF_INI_GET_DIF_SGL(cmd) ((cmd)->dif_control.dif_sgl)

u32 unf_ini_scsi_completed(void *lport, struct unf_frame_pkg *pkg);
u32 unf_ini_get_sgl_entry(void *pkg, char **buf, u32 *buf_len);
u32 unf_ini_get_dif_sgl_entry(void *pkg, char **buf, u32 *buf_len);
void unf_complete_cmnd(struct unf_scsi_cmnd *scsi_cmnd, u32 result_size);
void unf_done_ini_xchg(struct unf_xchg *xchg);
u32 unf_tmf_timeout_recovery_special(void *rport, void *xchg);
u32 unf_tmf_timeout_recovery_default(void *rport, void *xchg);
void unf_abts_timeout_recovery_default(void *rport, void *xchg);
int unf_cm_queue_command(struct unf_scsi_cmnd *scsi_cmnd);
int unf_cm_eh_abort_handler(struct unf_scsi_cmnd *scsi_cmnd);
int unf_cm_eh_device_reset_handler(struct unf_scsi_cmnd *scsi_cmnd);
int unf_cm_target_reset_handler(struct unf_scsi_cmnd *scsi_cmnd);
int unf_cm_bus_reset_handler(struct unf_scsi_cmnd *scsi_cmnd);
int unf_cm_virtual_reset_handler(struct unf_scsi_cmnd *scsi_cmnd);
struct unf_rport *unf_find_rport_by_scsi_id(struct unf_lport *lport,
					    struct unf_ini_error_code *errcode_table,
					    u32 errcode_table_count,
					    u32 scsi_id, u32 *scsi_result);
u32 UNF_IOExchgDelayProcess(struct unf_lport *lport, struct unf_xchg *xchg);
struct unf_lport *unf_find_lport_by_scsi_cmd(struct unf_scsi_cmnd *scsi_cmnd);
int unf_send_scsi_mgmt_cmnd(struct unf_xchg *xchg, struct unf_lport *lport,
			    struct unf_rport *rport,
			    struct unf_scsi_cmnd *scsi_cmnd,
			    enum unf_task_mgmt_cmd task_mgnt_cmd_type);
void unf_tmf_abnormal_recovery(struct unf_lport *lport, struct unf_rport *rport,
			       struct unf_xchg *xchg);

#endif
