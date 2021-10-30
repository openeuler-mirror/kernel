/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef SPFC_IO_H
#define SPFC_IO_H

#include "unf_type.h"
#include "unf_common.h"
#include "spfc_hba.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

#define BYTE_PER_DWORD 4
#define SPFC_TRESP_DIRECT_CARRY_LEN (23 * 4)
#define FCP_RESP_IU_LEN_BYTE_GOOD_STATUS 24
#define SPFC_TRSP_IU_CONTROL_OFFSET 2
#define SPFC_TRSP_IU_FCP_CONF_REP (1 << 12)

struct spfc_dif_io_param {
	u32 all_len;
	u32 buf_len;
	char **buf;
	char *in_buf;
	int drect;
};

enum dif_mode_type {
	DIF_MODE_NONE = 0x0,
	DIF_MODE_INSERT = 0x1,
	DIF_MODE_REMOVE = 0x2,
	DIF_MODE_FORWARD_OR_REPLACE = 0x3
};

enum ref_tag_mode_type {
	BOTH_NONE = 0x0,
	RECEIVE_INCREASE = 0x1,
	REPLACE_INCREASE = 0x2,
	BOTH_INCREASE = 0x3
};

#define SPFC_DIF_DISABLE 0
#define SPFC_DIF_ENABLE 1
#define SPFC_DIF_SINGLE_SGL 0
#define SPFC_DIF_DOUBLE_SGL 1
#define SPFC_DIF_SECTOR_512B_MODE 0
#define SPFC_DIF_SECTOR_4KB_MODE 1
#define SPFC_DIF_TYPE1 0x01
#define SPFC_DIF_TYPE3 0x03
#define SPFC_DIF_GUARD_VERIFY_ALGORITHM_CTL_T10_CRC16 0x0
#define SPFC_DIF_GUARD_VERIFY_CRC16_REPLACE_IP_CHECKSUM 0x1
#define SPFC_DIF_GUARD_VERIFY_IP_CHECKSUM_REPLACE_CRC16 0x2
#define SPFC_DIF_GUARD_VERIFY_ALGORITHM_CTL_IP_CHECKSUM 0x3
#define SPFC_DIF_CRC16_INITIAL_SELECTOR_DEFAUL 0
#define SPFC_DIF_CRC_CS_INITIAL_CONFIG_BY_REGISTER 0
#define SPFC_DIF_CRC_CS_INITIAL_CONFIG_BY_BIT0_1 0x4

#define SPFC_DIF_GARD_REF_APP_CTRL_VERIFY 0x4
#define SPFC_DIF_GARD_REF_APP_CTRL_NOT_VERIFY 0x0
#define SPFC_DIF_GARD_REF_APP_CTRL_INSERT 0x0
#define SPFC_DIF_GARD_REF_APP_CTRL_DELETE 0x1
#define SPFC_DIF_GARD_REF_APP_CTRL_FORWARD 0x2
#define SPFC_DIF_GARD_REF_APP_CTRL_REPLACE 0x3

#define SPFC_BUILD_RESPONSE_INFO_NON_GAP_MODE0 0
#define SPFC_BUILD_RESPONSE_INFO_GPA_MODE1 1
#define SPFC_CONF_SUPPORT 1
#define SPFC_CONF_NOT_SUPPORT 0
#define SPFC_XID_INTERVAL 2048

#define SPFC_DIF_ERROR_CODE_MASK 0xe
#define SPFC_DIF_ERROR_CODE_CRC 0x2
#define SPFC_DIF_ERROR_CODE_REF 0x4
#define SPFC_DIF_ERROR_CODE_APP 0x8
#define SPFC_TX_DIF_ERROR_FLAG (1 << 7)

#define SPFC_DIF_PAYLOAD_TYPE (1 << 0)
#define SPFC_DIF_CRC_TYPE (1 << 1)
#define SPFC_DIF_APP_TYPE (1 << 2)
#define SPFC_DIF_REF_TYPE (1 << 3)

#define SPFC_DIF_SEND_DIFERR_ALL (0)
#define SPFC_DIF_SEND_DIFERR_CRC (1)
#define SPFC_DIF_SEND_DIFERR_APP (2)
#define SPFC_DIF_SEND_DIFERR_REF (3)
#define SPFC_DIF_RECV_DIFERR_ALL (4)
#define SPFC_DIF_RECV_DIFERR_CRC (5)
#define SPFC_DIF_RECV_DIFERR_APP (6)
#define SPFC_DIF_RECV_DIFERR_REF (7)
#define SPFC_DIF_ERR_ENABLE (382855)
#define SPFC_DIF_ERR_DISABLE (0)

#define SPFC_DIF_LENGTH (8)
#define SPFC_SECT_SIZE_512 (512)
#define SPFC_SECT_SIZE_4096 (4096)
#define SPFC_SECT_SIZE_512_8 (520)
#define SPFC_SECT_SIZE_4096_8 (4104)
#define SPFC_DIF_SECT_SIZE_APP_OFFSET (2)
#define SPFC_DIF_SECT_SIZE_LBA_OFFSET (4)

#define SPFC_MAX_IO_TAG (2048)
#define SPFC_PRINT_WORD (8)

extern u32 dif_protect_opcode;
extern u32 dif_sect_size;
extern u32 no_dif_sect_size;
extern u32 grd_agm_ini_ctrl;
extern u32 ref_tag_mod;
extern u32 grd_ctrl;
extern u32 grd_agm_ctrl;
extern u32 cmp_app_tag_mask;
extern u32 app_tag_ctrl;
extern u32 ref_tag_ctrl;
extern u32 rep_ref_tag;
extern u32 rx_rep_ref_tag;
extern u16 cmp_app_tag;
extern u16 rep_app_tag;

#define spfc_fill_pkg_status(com_err_code, control, scsi_status) \
	(((u32)(com_err_code) << 16) | ((u32)(control) << 8) |  \
	 (u32)(scsi_status))
#define SPFC_CTRL_MASK 0x1f

u32 spfc_send_scsi_cmnd(void *hba, struct unf_frame_pkg *pkg);
u32 spfc_scq_recv_iresp(struct spfc_hba_info *hba, union spfc_scqe *wqe);
void spfc_process_dif_result(struct spfc_hba_info *hba, union spfc_scqe *wqe,
			     struct unf_frame_pkg *pkg);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* __SPFC_IO_H__ */
