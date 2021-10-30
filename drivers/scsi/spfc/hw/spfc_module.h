/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef SPFC_MODULE_H
#define SPFC_MODULE_H
#include "unf_type.h"
#include "unf_log.h"
#include "unf_common.h"
#include "spfc_utils.h"
#include "spfc_hba.h"

#define SPFC_FT_ENABLE (1)
#define SPFC_FC_DISABLE (0)

#define SPFC_P2P_DIRECT (0)
#define SPFC_P2P_FABRIC (1)
#define SPFC_LOOP (2)
#define SPFC_ATUOSPEED (1)
#define SPFC_FIXEDSPEED (0)
#define SPFC_AUTOTOPO (0)
#define SPFC_P2PTOPO (0x2)
#define SPFC_LOOPTOPO (0x1)
#define SPFC_SPEED_2G (0x2)
#define SPFC_SPEED_4G (0x4)
#define SPFC_SPEED_8G (0x8)
#define SPFC_SPEED_16G (0x10)
#define SPFC_SPEED_32G (0x20)

#define SPFC_MAX_PORT_NUM SPFC_MAX_PROBE_PORT_NUM
#define SPFC_MAX_PORT_TASK_TYPE_STAT_NUM (128)
#define SPFC_MAX_LINK_EVENT_CNT (4)
#define SPFC_MAX_LINK_REASON_CNT (256)

#define SPFC_MML_LOGCTRO_NUM (14)

#define WWN_SIZE 8 /* Size of WWPN, WWN & WWNN */

/*
 * Define the data type
 */
struct spfc_log_ctrl {
	char *log_option;
	u32 state;
};

/*
 * Declare the global function.
 */
extern struct unf_cm_handle_op spfc_cm_op_handle;
extern struct spfc_uld_info fc_uld_info;
extern u32 allowed_probe_num;
extern u32 max_speed;
extern u32 accum_db_num;
extern u32 wqe_page_size;
extern u32 dif_type;
extern u32 wqe_pre_load;
extern u32 combo_length;
extern u32 cos_bit_map;
extern u32 exit_count;
extern u32 exit_stride;
extern u32 exit_base;

extern atomic64_t rx_tx_stat[SPFC_MAX_PORT_NUM][SPFC_MAX_PORT_TASK_TYPE_STAT_NUM];
extern atomic64_t rx_tx_err[SPFC_MAX_PORT_NUM][SPFC_MAX_PORT_TASK_TYPE_STAT_NUM];
extern atomic64_t scq_err_stat[SPFC_MAX_PORT_NUM][SPFC_MAX_PORT_TASK_TYPE_STAT_NUM];
extern atomic64_t aeq_err_stat[SPFC_MAX_PORT_NUM][SPFC_MAX_PORT_TASK_TYPE_STAT_NUM];
extern atomic64_t dif_err_stat[SPFC_MAX_PORT_NUM][SPFC_MAX_PORT_TASK_TYPE_STAT_NUM];
extern atomic64_t mail_box_stat[SPFC_MAX_PORT_NUM][SPFC_MAX_PORT_TASK_TYPE_STAT_NUM];
extern atomic64_t com_up_event_err_stat[SPFC_MAX_PORT_NUM][SPFC_MAX_PORT_TASK_TYPE_STAT_NUM];
extern u64 link_event_stat[SPFC_MAX_PORT_NUM][SPFC_MAX_LINK_EVENT_CNT];
extern u64 link_reason_stat[SPFC_MAX_PORT_NUM][SPFC_MAX_LINK_REASON_CNT];
extern atomic64_t up_err_event_stat[SPFC_MAX_PORT_NUM][SPFC_MAX_PORT_TASK_TYPE_STAT_NUM];
extern u64 hba_stat[SPFC_MAX_PORT_NUM][SPFC_HBA_STAT_BUTT];
#define SPFC_LINK_EVENT_STAT(hba, link_ent) \
	(link_event_stat[(hba)->probe_index][link_ent]++)
#define SPFC_LINK_REASON_STAT(hba, link_rsn) \
	(link_reason_stat[(hba)->probe_index][link_rsn]++)
#define SPFC_HBA_STAT(hba, hba_stat_type) \
	(hba_stat[(hba)->probe_index][hba_stat_type]++)

#define SPFC_UP_ERR_EVENT_STAT(hba, err_type) \
	(atomic64_inc(&up_err_event_stat[(hba)->probe_index][err_type]))
#define SPFC_UP_ERR_EVENT_STAT_READ(probe_index, io_type) \
	(atomic64_read(&up_err_event_stat[probe_index][io_type]))
#define SPFC_DIF_ERR_STAT(hba, dif_err) \
	(atomic64_inc(&dif_err_stat[(hba)->probe_index][dif_err]))
#define SPFC_DIF_ERR_STAT_READ(probe_index, dif_err) \
	(atomic64_read(&dif_err_stat[probe_index][dif_err]))

#define SPFC_IO_STAT(hba, io_type) \
	(atomic64_inc(&rx_tx_stat[(hba)->probe_index][io_type]))
#define SPFC_IO_STAT_READ(probe_index, io_type) \
	(atomic64_read(&rx_tx_stat[probe_index][io_type]))

#define SPFC_ERR_IO_STAT(hba, io_type) \
	(atomic64_inc(&rx_tx_err[(hba)->probe_index][io_type]))
#define SPFC_ERR_IO_STAT_READ(probe_index, io_type) \
	(atomic64_read(&rx_tx_err[probe_index][io_type]))

#define SPFC_SCQ_ERR_TYPE_STAT(hba, err_type) \
	(atomic64_inc(&scq_err_stat[(hba)->probe_index][err_type]))
#define SPFC_SCQ_ERR_TYPE_STAT_READ(probe_index, io_type) \
	(atomic64_read(&scq_err_stat[probe_index][io_type]))
#define SPFC_AEQ_ERR_TYPE_STAT(hba, err_type) \
	(atomic64_inc(&aeq_err_stat[(hba)->probe_index][err_type]))
#define SPFC_AEQ_ERR_TYPE_STAT_READ(probe_index, io_type) \
	(atomic64_read(&aeq_err_stat[probe_index][io_type]))

#define SPFC_MAILBOX_STAT(hba, io_type) \
	(atomic64_inc(&mail_box_stat[(hba)->probe_index][io_type]))
#define SPFC_MAILBOX_STAT_READ(probe_index, io_type) \
	(atomic64_read(&mail_box_stat[probe_index][io_type]))

#define SPFC_COM_UP_ERR_EVENT_STAT(hba, err_type) \
	(atomic64_inc(                     \
	    &com_up_event_err_stat[(hba)->probe_index][err_type]))
#define SPFC_COM_UP_ERR_EVENT_STAT_READ(probe_index, err_type) \
	(atomic64_read(&com_up_event_err_stat[probe_index][err_type]))

#define UNF_LOWLEVEL_ALLOC_LPORT(lport, fc_port, low_level)              \
	do {                                                             \
		if (spfc_cm_op_handle.unf_alloc_local_port) {           \
			lport = spfc_cm_op_handle.unf_alloc_local_port( \
			    (fc_port), (low_level));                     \
		} else {                                                 \
			lport = NULL;                                    \
		}                                                        \
	} while (0)

#define UNF_LOWLEVEL_RECEIVE_LS_GS_PKG(ret, fc_port, pkg)               \
	do {                                                            \
		if (spfc_cm_op_handle.unf_receive_ls_gs_pkg) {         \
			ret = spfc_cm_op_handle.unf_receive_ls_gs_pkg( \
			    (fc_port), (pkg));                          \
		} else {                                                \
			ret = UNF_RETURN_ERROR;                         \
		}                                                       \
	} while (0)

#define UNF_LOWLEVEL_SEND_ELS_DONE(ret, fc_port, pkg)                         \
	do {                                                                  \
		if (spfc_cm_op_handle.unf_send_els_done) {                   \
			ret = spfc_cm_op_handle.unf_send_els_done((fc_port), \
								   (pkg));    \
		} else {                                                      \
			ret = UNF_RETURN_ERROR;                               \
		}                                                             \
	} while (0)

#define UNF_LOWLEVEL_GET_CFG_PARMS(ret, section_name, cfg_parm, cfg_value,     \
				   item_num)                                   \
	do {                                                                   \
		if (spfc_cm_op_handle.unf_get_cfg_parms) {                    \
			ret = (u32)spfc_cm_op_handle.unf_get_cfg_parms(       \
			    (section_name), (cfg_parm), (cfg_value),           \
			    (item_num));                                       \
		} else {                                                       \
			FC_DRV_PRINT(UNF_LOG_REG_ATT, UNF_WARN,                \
			    "Get config parameter function is NULL.");         \
			ret = UNF_RETURN_ERROR;                                \
		}                                                              \
	} while (0)

#define UNF_LOWLEVEL_RELEASE_LOCAL_PORT(ret, lport)                           \
	do {                                                                  \
		if (unlikely(!spfc_cm_op_handle.unf_release_local_port)) {   \
			ret = UNF_RETURN_ERROR;                               \
		} else {                                                      \
			ret =                                                 \
			    spfc_cm_op_handle.unf_release_local_port(lport); \
		}                                                             \
	} while (0)

#define UNF_CM_GET_SGL_ENTRY(ret, pkg, buf, buf_len)                      \
	do {                                                              \
		if (unlikely(!spfc_cm_op_handle.unf_cm_get_sgl_entry)) { \
			ret = UNF_RETURN_ERROR;                           \
		} else {                                                  \
			ret = spfc_cm_op_handle.unf_cm_get_sgl_entry(    \
			    pkg, buf, buf_len);                           \
		}                                                         \
	} while (0)

#define UNF_CM_GET_DIF_SGL_ENTRY(ret, pkg, buf, buf_len)                      \
	do {                                                                  \
		if (unlikely(!spfc_cm_op_handle.unf_cm_get_dif_sgl_entry)) { \
			ret = UNF_RETURN_ERROR;                               \
		} else {                                                      \
			ret = spfc_cm_op_handle.unf_cm_get_dif_sgl_entry(    \
			    pkg, buf, buf_len);                               \
		}                                                             \
	} while (0)

#define UNF_GET_SGL_ENTRY(ret, pkg, buf, buf_len, dif_flag)               \
	do {                                                              \
		if (dif_flag) {                                           \
			UNF_CM_GET_DIF_SGL_ENTRY(ret, pkg, buf, buf_len); \
		} else {                                                  \
			UNF_CM_GET_SGL_ENTRY(ret, pkg, buf, buf_len);     \
		}                                                         \
	} while (0)

#define UNF_GET_FREE_ESGL_PAGE(ret, lport, pkg)                       \
	do {                                                               \
		if (unlikely(                                              \
			!spfc_cm_op_handle.unf_get_one_free_esgl_page)) { \
			ret = NULL;                                   \
		} else {                                                   \
			ret =                                         \
			    spfc_cm_op_handle.unf_get_one_free_esgl_page( \
				lport, pkg);                               \
		}                                                          \
	} while (0)

#define UNF_LOWLEVEL_FCP_CMND_RECEIVED(ret, lport, pkg)                      \
	do {                                                                 \
		if (unlikely(!spfc_cm_op_handle.unf_process_fcp_cmnd)) {    \
			ret = UNF_RETURN_ERROR;                              \
		} else {                                                     \
			ret = spfc_cm_op_handle.unf_process_fcp_cmnd(lport, \
								      pkg);  \
		}                                                            \
	} while (0)

#define UNF_LOWLEVEL_SCSI_COMPLETED(ret, lport, pkg)                         \
	do {                                                                 \
		if (unlikely(NULL ==                                         \
			     spfc_cm_op_handle.unf_receive_ini_response)) { \
			ret = UNF_RETURN_ERROR;                              \
		} else {                                                     \
			ret = spfc_cm_op_handle.unf_receive_ini_response(   \
			    lport, pkg);                                     \
		}                                                            \
	} while (0)

#define UNF_LOWLEVEL_PORT_EVENT(ret, lport, event, input)              \
	do {                                                           \
		if (unlikely(!spfc_cm_op_handle.unf_fc_port_event)) { \
			ret = UNF_RETURN_ERROR;                        \
		} else {                                               \
			ret = spfc_cm_op_handle.unf_fc_port_event(    \
			    lport, event, input);                      \
		}                                                      \
	} while (0)

#define UNF_LOWLEVEL_RECEIVE_FC4LS_PKG(ret, fc_port, pkg)               \
	do {                                                            \
		if (spfc_cm_op_handle.unf_receive_fc4ls_pkg) {         \
			ret = spfc_cm_op_handle.unf_receive_fc4ls_pkg( \
			    (fc_port), (pkg));                          \
		} else {                                                \
			ret = UNF_RETURN_ERROR;                         \
		}                                                       \
	} while (0)

#define UNF_LOWLEVEL_SEND_FC4LS_DONE(ret, lport, pkg)                         \
	do {                                                                  \
		if (spfc_cm_op_handle.unf_send_fc4ls_done) {                 \
			ret = spfc_cm_op_handle.unf_send_fc4ls_done((lport), \
								     (pkg));  \
		} else {                                                      \
			ret = UNF_RETURN_ERROR;                               \
		}                                                             \
	} while (0)

#define UNF_LOWLEVEL_RECEIVE_BLS_PKG(ret, lport, pkg)                         \
	do {                                                                  \
		if (spfc_cm_op_handle.unf_receive_bls_pkg) {                 \
			ret = spfc_cm_op_handle.unf_receive_bls_pkg((lport), \
								     (pkg));  \
		} else {                                                      \
			ret = UNF_RETURN_ERROR;                               \
		}                                                             \
	} while (0)

#define UNF_LOWLEVEL_RECEIVE_MARKER_STS(ret, lport, pkg)                    \
	do {                                                                \
		if (spfc_cm_op_handle.unf_receive_marker_status) {         \
			ret = spfc_cm_op_handle.unf_receive_marker_status( \
			    (lport), (pkg));                                \
		} else {                                                    \
			ret = UNF_RETURN_ERROR;                             \
		}                                                           \
	} while (0)

#define UNF_LOWLEVEL_RECEIVE_ABTS_MARKER_STS(ret, lport, pkg)                  \
	do {                                                                   \
		if (spfc_cm_op_handle.unf_receive_abts_marker_status) {       \
			ret =                                                  \
			    spfc_cm_op_handle.unf_receive_abts_marker_status( \
				(lport), (pkg));                               \
		} else {                                                       \
			ret = UNF_RETURN_ERROR;                                \
		}                                                              \
	} while (0)

#endif
