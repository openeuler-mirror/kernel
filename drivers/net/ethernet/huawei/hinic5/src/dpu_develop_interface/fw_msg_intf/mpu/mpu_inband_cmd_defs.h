/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : mpu_inband_cmd_defs.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   : In-band command-related structures between the driver and the MPU
 */

#ifndef MPU_INBAND_CMD_DEFS_H
#define MPU_INBAND_CMD_DEFS_H

#include "mpu_cmd_base_defs.h"

#define HARDWARE_ID_1XX3V200_TAG 32     /* 1xx3v200 tag */
#define DUMP_16B_PER_LINE	16  /* dump 16byte alignment */
#define DUMP_4_VAR_PER_LINE	4   /* dump unit 4byte */
#define FW_UPDATE_MGMT_TIMEOUT	3000000U    /** mbox message upgrade command timeout */

#define FUNC_RESET_FLAG_MAX_VALUE ((1U << (RES_TYPE_MAX + 1)) - 1)  /* func_reset_flag boundary value */
struct comm_cmd_func_reset {    /* driver load/unload scenario, function reset resource cleanup */
	struct mgmt_msg_head head;  /* mbox message header */

	u16 func_id;    /* function id to reset */
	u16 rsvd1[3];   /* reserved field */
	u64 reset_flag;     /* bitmap of specific reset resources */
};

struct comm_cmd_ppf_flr_type_set {  /* flr scenario, set ppf flr execution range */
	struct mgmt_msg_head head;  /*  */

	u16 func_id;    /* flr function id */
	u8 rsvd1[2];    /* reserved field */
	u32 ppf_flr_type;   /* ppf flr execution range type, 0: ffp only, 1: all functions under ppf */
};

enum {
	COMM_F_API_CHAIN		= 1U << 0,   /* attribute negotiation, cpi chain */
	COMM_F_CLP			= 1U << 1,   /* attribute negotiation, clp */
	COMM_F_CHANNEL_DETECT		= 1U << 2,   /* attribute negotiation, channel detection */
	COMM_F_MBOX_SEGMENT		= 1U << 3,   /* attribute negotiation, mbox */
	COMM_F_CMDQ_NUM			= 1U << 4,   /* attribute negotiation, cmdq */
	COMM_F_VIRTIO_VQ_SIZE		= 1U << 5,   /* attribute negotiation, virtio vq size */
	COMM_F_EXTEND_CAP		= 1U << 6,   /* attribute negotiation, capability set extension */
	COMM_F_SMF_CACHE_INVALID	= 1U << 7,   /* attribute negotiation, cache invalidation */
	COMM_F_ONLY_ENHANCE_CMDQ	= 1U << 8,   /* attribute negotiation, enhanced cmdq */
	COMM_F_USE_REAL_RX_BUF_SIZE	= 1U << 9,   /* attribute negotiation, use real rx buffer */
	COMM_F_CMD_BUF_SIZE		= 1U << 10,  /* attribute negotiation, cmd buffer size */
	COMM_F_HTN_CMD			= 1U << 11,  /* attribute negotiation, Hard Tile - NIC (hardware nic) */
	COMM_F_MBOX_MSG_HEAD_SUPP_VER1	= 1U << 12,  /* attribute negotiation, mode extension */
	COMM_F_FAST_MSG			= 1U << 13,  /* attribute negotiation, fast message */
	COMM_F_UFHD			= 1U << 14,  /* attribute negotiation, Update Firmware from Host DDR
						      * - support DDR microcode hot upgrade
						      */
	COMM_F_VIRTIO_FC_CACHE_MODE	= 1U << 15,  /* attribute negotiation,
						      * driver supports Virtio function context cache mode */
	COMM_F_NON_PTP_SYNC		= 1U << 16,  /* attribute negotiation, non-ptp sync */
	COMM_F_HT_GPA			= 1U << 17,  /* attribute negotiation, HT GPA (Bank GPA) */
	COMM_F_UFHD_FLEX_SEG		= 1U << 18,  /* attribute negotiation, UFHD adds segment size negotiation capability.
						      * This feature cannot be enabled simultaneously with COMM_F_UFHD.
						      * To support segment size negotiation,
						      * COMM_F_EXTEND_CAP needs to be enabled.
						      */
};

/* mode extension version */
#define CHECK_COMM_F_SUPP_MBOX_MSG_HEAD_VER1(feature) \
		(((feature) & COMM_F_MBOX_MSG_HEAD_SUPP_VER1) > 0)

enum {
	COMM_PLUG_SRV_NIC = 0,   /* plug nic */
	COMM_PLUG_SRV_VROCE,     /* plug vroce */
	COMM_PLUG_SRV_UB,        /* plug ub */
	COMM_PLUG_SRV_BUTT,
};

#define COMM_MAX_FEATURE_QWORD 4
struct comm_cmd_feature_nego {   /* attribute negotiation */
	struct mgmt_msg_head head;  /* mbox message header */

	u16 func_id;   /* specified function id */
	u8 opcode;    /* 1: set, 0: get */
	u8 rsvd[5];   /* reserved field */
	u64 s_feature[COMM_MAX_FEATURE_QWORD];   /* negotiation information */
};

struct comm_cmd_clear_doorbell {   /* driver unload flush doorbell */
	struct mgmt_msg_head head;   /* mbox message header */

	u16 func_id;   /* specified function id */
	u16 rsvd1[3];   /* reserved field */
};

struct comm_cmd_clear_resource {   /* driver unload flush process, cleanup resources */
	struct mgmt_msg_head head;   /* mbox message header */

	u16 func_id;   /* specified function id */
	u16 rsvd1[3];   /* reserved field */
};

struct comm_global_attr {   /* get chip global attribute information */
	u8 max_host_num;   /* maximum host number */
	u8 max_pf_num;   /* maximum pf number */
	u16 vf_id_start;   /* starting vf id */

	u8 mgmt_host_node_id;    /* management host node id */
	u8 cmdq_num;   /* cmdq number */
	u16 cmd_buf_size;   /* cmd buffer size */

	u32 rsvd2[8];   /* reserved field */
};

struct comm_cmd_heart_event {   /* mbox heartbeat event between mpu and driver */
	struct mgmt_msg_head head;   /* mbox message header */

	u8 init_sta;    /* 0: mpu init ok, 1: mpu init error */
	u8 rsvd1[3];   /* reserved field */
	u32 heart;   /* heartbeat identifier */
	u32 heart_handshake;   /* should be alwasys: 0x5A5A5A5A */
};

struct comm_cmd_channel_detect {   /* channel detection */
	struct mgmt_msg_head head;   /* mbox message header */

	u16 func_id;   /* specified function id */
	u16 rsvd1[3];   /* reserved field 1 */
	u32 rsvd2[2];   /* reserved field 2 */
};

struct comm_cmd_func_svc_used_state {   /* function usage state */
	struct mgmt_msg_head head;   /* mbox message header */
	u16 func_id;   /* specified function id */
	u16 svc_type;   /* service type (not used currently) */
	u8 used_state;   /* usage state */
	u8 rsvd[35];   /*  */
};

struct comm_cmd_get_flr_info {   /* flrdx information */
	struct mgmt_msg_head head;   /* mbox message header */
	u16 func_id;   /* specified function id */
	u8 flr_valid;   /* flr valid bit */
	u8 flr_step;   /* flr state machine */
	u32 flr_used_time_ms;   /* flr elapsed time */
	u16 max_flr_time_func_id;   /* function with longest flr time */
	u32 max_flr_used_time_ms;   /* maximum flr time */
	u8 rsvd[30];   /* reserved field */
};

struct sml_table_id_info {   /* sml table information */
	u8 node_id;   /* node id */
	u8 instance_id;   /* instance id */
};

struct comm_cmd_get_sml_tbl_data {   /* sml table content */
	struct mgmt_msg_head head;    /* mbox message header */
	u8 tbl_data[512];   /* sml payload */
};

struct comm_cmd_get_glb_attr {   /* get chip global information */
	struct mgmt_msg_head head;   /* mbox message header */

	struct comm_global_attr attr;   /* global information */
};

#define HINIC5_FW_VERSION_LEN 16   /* version length */
#define HINIC5_FW_COMPILE_TIME_LEN 20   /* time length */

struct comm_cmd_get_fw_version {   /* get firmware version */
	struct mgmt_msg_head head;   /* mbox message header */

	u16 fw_type;   /* firmware type */
	u16 fw_dfx_vld : 1;   /* version type, 0: release, 1: debug */
	u16 rsvd1 : 15;   /* reserved field */
	char ver[HINIC5_FW_VERSION_LEN];   /* version */
	char time[HINIC5_FW_COMPILE_TIME_LEN];   /* time */
};

struct cmdq_ctxt_info {   /* hardware define: cmdq context */
	u64 curr_wqe_page_pfn;   /* wqe page information */
	u64 wq_block_pfn;   /* wqe address */
};

struct comm_cmd_cmdq_ctxt {   /* configure cmdq context */
	struct mgmt_msg_head head;   /* mbox message header */

	u16 func_id;   /* specified function id */
	u8 cmdq_id;   /* cmdq id */
	u8 rsvd1[5];   /* reserved field */

	struct cmdq_ctxt_info ctxt;   /* context information */
};

struct enhance_cmdq_ctxt_info {   /* hardware define: enhanced cmdq context */
	u64	eq_cfg;   /* eq cfg */
	u64	dfx_pi_ci;   /* pointer pi ci */

	u64	pft_thd;   /* pft thd */
	u64	pft_ci;   /* pft ci */

	u64	rsv;   /* reserved field */
	u64	ci_cla_addr;   /* cla address */
};

struct comm_cmd_enhance_cmdq_ctxt {   /* enhanced cmdq ctx configuration */
	struct mgmt_msg_head head;   /* mbox message header */

	u16 func_id;   /* specified function id */
	u8 cmdq_id;   /* cmdq id */
	u8 rsvd1[5];   /* reserved field */

	struct enhance_cmdq_ctxt_info ctxt;   /* ctx information */
};

struct comm_cmd_virtio_en {   /* virtio config after sdk load */
	struct mgmt_msg_head head;   /* mbox message header */
	u8 msien_snap_2_virtio_en;   /* msien virtio enable */
	u8 rsv[3];
};

struct hinic5_cqm_cmd_func_secure_mem {   /* secure memory information retrieval */
	struct mgmt_msg_head head;   /* mbox message header */
	u16 func_id;   /* specified function id */
	u16 rsvd0;   /* reserved field */
	u32 gpa_hi;   /* gpa high address */
	u32 gpa_lo;   /* gpa low address */
	u32 len;   /* length */
	u8 gpa_mode;   /* gpa mode */
	u8 valid;   /* valid bit */
	u8 rsvd1[2];   /* reserved field */
};

struct nic_plug_cap {   /* hotplug capability */
	u16 max_sqs;   /* maximum sq size */
	u16 max_rqs;   /* maximum rq size */
};

struct comm_cmd_plug_srv {   /* hotplug service */
	struct mgmt_msg_head head;   /* mbox message header */
	u16 func_id;   /* specified function id */
	u8 srv_type;   /* service type */
	u8 attach_en;   /* enable flag */
	struct nic_plug_cap nic_cap;   /* nic hotplug capability */
	u32 rsvd;   /* reserved field */
};

struct comm_cmd_fast_msg_cap {   /* fast msg capability */
	struct mgmt_msg_head head;   /* mbox message header */
	u32 func_id;   /* specified function id */
	u32 fast_msg_depth;    /* PF:2048, VF:512 */
	u32 fast_msg_page_size;    /* message page size 256(unit K) */
	u32 rsvd[9];   /* reserved field */
};

#define FAST_MSG_MAX_PAGE_NUM 32   /* fast msg page number */
struct comm_cmd_fast_msg_rq_addr {
	struct mgmt_msg_head head;
	u32 func_id;
	u32 page_num;
	u32 rsvd[2];
	u64 page_addr[FAST_MSG_MAX_PAGE_NUM];
};

struct fast_msg_rq_addr {   /* fast msg rq address */
	u64 rq_page_addr;   /* rq page address */
};

struct comm_cmd_set_fast_msg_rq_addr {   /* fast msg rq address setting */
	struct mgmt_msg_head head;   /* mbox message header */
	u32 func_id;   /* specified function id */
	u32 page_num;   /* page number */
	u32 rsvd[2];   /* reserved field */
	struct fast_msg_rq_addr page_addr[32];   /* page address */
};

struct comm_cmd_clear_fast_msg_sml_table {   /* fast msg clear table entry */
	struct mgmt_msg_head head;   /* mbox message header */
	u32 func_id;   /* specified function id */
	u32 rsvd[5]; /* reserved field, 32 Bytes total */
};

struct comm_cmd_root_ctxt {   /* root ctx configuration */
	struct mgmt_msg_head head;   /* mbox message header */

	u16 func_id;   /* specified function id */
	u8 set_cmdq_depth;   /* cmdq depth set flag */
	u8 cmdq_depth;   /* cmdq depth */
	u16 rx_buf_sz;   /* rx buffer size */
	u8 lro_en;   /* lro enable flag */
	u8 cmdq_mode;   /* cmdq mode */
	u16 sq_depth;   /* sq depth */
	u16 rq_depth;   /* rq depth */
	u32 rsvd1;   /* reserved field */
	u64 rsvd2;   /* reserved field */
};

struct comm_cmd_wq_page_size {   /* root ctx wqe configuration */
	struct mgmt_msg_head head;   /* mbox message header */

	u16 func_id;   /* specified function id */
	u8 opcode;   /* operation indicator, 0: get, 1: set */
	u8 page_size;   /* real_size=4KB*2^page_size, range(0~20) must be checked by driver */
	u32 rsvd1;   /* reserved field */
};

struct comm_cmd_msix_config {   /* msix interrupt configuration */
	struct mgmt_msg_head head;   /* mbox message header */

	u16 func_id;   /* specified function id */
	u8 opcode;   /* operation indicator, 0: get, 1: set */
	u8 rsvd1;   /* reserved field */
	u16 msix_index;   /* interrupt idx */
	u8 pending_cnt;   /* It specifies the maximum wait time for resending period. */
	u8 coalesce_timer_cnt;   /* coalesce configuration */
	u8 resend_timer_cnt;   /* resend count */
	u8 lli_timer_cnt;   /* credit compensation configuration */
	u8 lli_credit_cnt;   /* credit supplement threshold */
	u8 rsvd2[5];   /* reserved field */
};

struct comm_cmd_cfg_msix_num {   /* msix interrupt number configuration */
	struct mgmt_msg_head head;    /* mbox message header */

	u16 func_id;   /* specified function id */
	u8 op_code;    /* 1: alloc 0: free */
	u8 rsvd0;   /* reserved field */

	u16 msix_num;   /* msix number */
	u16 rsvd1;   /* reserved field */
};

struct comm_cmd_dma_attr_config {   /* dma attribute config (currently not used) */
	struct mgmt_msg_head head;   /* mbox message header */

	u16 func_id;   /* specified function id */
	u8 entry_idx;
	u8 st;
	u8 at;
	u8 ph;
	u8 no_snooping;
	u8 tph_en;
	u32 resv1;
};

struct comm_cmd_ppf_tbl_htrp_config {   /* ppf hot replace configuration */
	struct mgmt_msg_head head;   /* mbox message header */

	u32 hotreplace_flag;   /* hot replace flag */
};

struct comm_cmd_ceq_ctrl_reg {   /* ceq configuration */
	struct mgmt_msg_head head;   /* mbox message header */

	u16 func_id;   /* specified function id */
	u16 q_id;   /* q id */
	u32 ctrl0;   /* ceq ctrl0 */
	u32 ctrl1;   /* ceq ctrl1 */
	u32 rsvd1;   /* reserved field */
};

struct comm_cmd_func_tmr_bitmap_op {   /* enable smf timer bitmap operation */
	struct mgmt_msg_head head;   /* mbox message header */

	u16 func_id;   /* specified function id */
	u8 opcode;   /* 1: start, 0: stop */
	u8 rsvd1[5];   /* reserved field */
};

struct comm_cmd_ppf_tmr_op {   /* smf timer configuration */
	struct mgmt_msg_head head;   /* mbox message header */

	u8 ppf_id;   /* ppf id */
	u8 opcode;   /* 1: start, 0: stop */
	u8 rsvd1[6];   /* reserved field */
};

#define HT_GPA_CLEAR 0 /* gpa clear */
#define HT_GPA_SET 1    /* gpa set */
struct comm_cmd_ht_gpa {    /* gpa operation */
	struct mgmt_msg_head head; /* mbox message header */

	u8 host_id;   /* specified host */
	u8 opcode;  /* 1:set, 0: clear */
	u8 rsvd0[2];   /* reserved field */
	u32 rsvd1[7];   /* reserved field */
	u64 page_pa0;   /* gpa address 0 */
	u64 page_pa1;   /* gpa address 1 */
};

struct comm_cmd_get_eqm_num {   /* mqm eqm configuration */
	struct mgmt_msg_head head;   /* mbox message header */

	u8 host_id;   /* specified host */
	u8 rsvd1[3];   /* reserved field */
	u32 chunk_num;   /* chunk num */
	u32 search_gpa_num;   /* search gpa num */
};

struct comm_cmd_eqm_cfg {   /* mqm overflow configuration */
	struct mgmt_msg_head head;   /* mbox message header */

	u8 host_id;   /* specified host */
	u8 valid;   /* valid bit */
	u16 rsvd1;   /* reserved field */
	u32 page_size;   /* page size */
	u32 rsvd2;   /* reserved field */
};

struct comm_cmd_eqm_search_gpa {   /* mqm search gpa configuration */
	struct mgmt_msg_head head;   /* mbox message header */

	u8 host_id;   /* specified host */
	u8 rsvd1[3];   /* reserved field */
	u32 start_idx;   /* start idx */
	u32 num;   /* number */
	u32 rsvd2;   /* reserved field */
	u64 gpa_hi52[0];   /* gpa */
};

struct comm_cmd_set_bat_info {
	struct mgmt_msg_head head;

	u16 func_id;
	u8  smf_id;
	u8  rsvd1;
	u32 bat_offset;
	u32 data_size;
	u8  data[256];
};

struct hinic5_board_info {   /* get board information */
	u8 board_type;   /* board type */
	u8 port_num;   /* port number */
	u8 port_speed;   /* board speed */
	u8 host_width;   /* port bandwidth */
	u8 host_num;   /* supported host number */
	u8 pf_num;   /* supported pf number */
	u16 vf_total_num;   /* supported vf number */
	u8 tile_num;   /* supported tile number */
	u8 qcm_num;   /* supported qcm number */
	u8 core_num;   /* supported tile core number */
	u8 work_mode;   /* board work mode */
	u8 service_mode;   /* board service mode */
	u8 board_mode;   /* board mode */
	u8 boot_sel;   /* boot mode */
	u8 board_id;   /* board id */
	u32 cfg_addr;   /* config file address */
	u32 service_en_bitmap;   /* service enable feature */
	u8 scenes_id;   /* scene id */
	u8 cfg_template_id;   /* config template id */
	u8 hardware_id;   /* hardware id */
	u8 spu_en;   /* spu enable flag */
	u16 pf_vendor_id;   /* device vendor id */
	u8 tile_bitmap;   /* tile enable bitmap */
	u8 sm_bitmap;   /* sm enable bitmap */
	u8 smf_bitmap_hi; /* high 4bit of smf */
	u8 board_type_hi; /* high 8bit of board_type */
	u8 host_type : 2; /* see BUS_TYPE_E 0 : pcie, 1 : ubc */
	u8 pg_grade : 2; /* see PARTIAL_GOOD_GRADE_MODE, 0 : fg, 1 : pg */
	u8 rsvd0 : 4;
	u8 rsvd;
	u32 service_en_bitmap2; /* service enable feature extension */
};

struct comm_cmd_board_info {   /* get board information */
	struct mgmt_msg_head head;   /* mbox message header */

	struct hinic5_board_info info;   /* board information */
	u32 rsvd[20];   /* reserved field */
};

struct comm_cmd_sync_time {   /* driver time sync */
	struct mgmt_msg_head head;   /* mbox message header */

	u64 mstime;   /* timestamp */
	u64 sync_time;
};

struct comm_cmd_sdi_info {   /* get sdi information */
	struct mgmt_msg_head head;   /* mbox message header */
	u32 cfg_sdi_mode;   /* configure sdi mode */
};

enum tool_run_env {
	TOOL_RUN_ENV_HOST,   /* host side */
	TOOL_RUN_ENV_SPU,   /* spu side */
	TOOL_RUN_ENV_INVALID = 0xFF
};
typedef u8 tool_run_env_u8;

enum chip_ver {
	CHIP_VER_HI1823V100,   /* chip 1823v100 */
	CHIP_VER_HI1823EV100,   /* chip 1823v100e */
	CHIP_VER_HI1823V200,   /* chip 1823v200 */
	CHIP_VER_HI1872V100,   /* chip 1872v100 */
	CHIP_VER_HI1825V100,   /* chip 1825v100 */
	CHIP_VER_INVALID = 0xFF
};
typedef u8 chip_ver_u8;   /* chip version */

enum chip_type {
	CHIP_TYPE_FPGA,   /* chip fpga */
	CHIP_TYPE_ASIC,   /* chip asic */
	CHIP_TYPE_EMU,   /* chip emu */
	CHIP_TYPE_EDA,   /* chip eda */
	CHIP_TYPE_INVALID = 0xFF
};
typedef u8 chip_type_u8;   /* chip platform */

struct comm_cmd_compatible_info {   /* huoq environment information */
	struct mgmt_msg_head head;   /* mbox message header */
	chip_ver_u8 chip_ver;     /* chip version */
	tool_run_env_u8 host_env;    /* host type */
	chip_type_u8 chip_type;   /* chip type/platform */
	u8 dual_die_flag;   /* dual die enable flag 0: no(single die), 1: yes(dual die) */
	u32 mpu_ver;   /* mpu version */
	u32 npu_ver;   /* microcode version */
	u32 rsv1[31];   /* reserved field */
};

/* func flr set */
struct comm_cmd_func_flr_set {   /* set function flr type */
	struct mgmt_msg_head head;   /* mbox message header */

	u16 func_id;   /* specified function id */
	u8 type;    /* 1: close set flush */
	u8 isall;   /* whether to operate all vf under the corresponding pf 1: all vf */
	u32 rsvd;
};

struct comm_cmd_bdf_info {   /* get bdf number */
	struct mgmt_msg_head head;   /* mbox message header */

	u16 function_idx;   /* specified function id */
	u8 rsvd1[2];   /* reserved field */
	u8 bus;   /* bus number */
	u8 device;   /* device number */
	u8 function;   /* function number */
	u8 rsvd2[5];   /* reserved field */
};

struct hw_pf_info {   /* hardware pf information */
	u16 glb_func_idx;   /* global function id */
	u16 glb_pf_vf_offset;   /* starting vf id of this pf */
	u8 p2p_idx;   /* p2p idx */
	u8 itf_idx;   /* host id */
	u16 max_vfs;   /* vf number */
	u16 max_queue_num;   /* queue number */
	u16 vf_max_queue_num;   /* vf supported queue number */
	u16 port_id;   /* port id */
	u16 rsvd0;   /* reserved field */
	u32 pf_service_en_bitmap;   /* pf service en */
	u32 vf_service_en_bitmap;   /* vf service en */
	u16 rsvd1[2];   /* reserved field */

	u8 device_type;   /* device type */
	u8 bus_num;      /* bus number */
	u16 vf_stride;    /* vf stride */
	u16 vf_offset;   /* vf relative offset */
	u8 func_valid_map : 2;	/* 0: present all functions, 1: present odd functions,
				 * 2: present even functions, 3: invalid value
				 */
	u8 rsvd2 : 6;   /* reserved field */
	u8 rsvd;   /* reserved field */
};

#define CMD_MAX_MAX_PF_NUM 32   /* maximum pf number */
struct hinic5_hw_pf_infos {   /* hardware pf information */
	u8 num_pfs;   /* pf number */
	u8 rsvd1[3];   /* reserved field */

	struct hw_pf_info infos[CMD_MAX_MAX_PF_NUM];   /* hardware pf information */
};

struct comm_cmd_hw_pf_infos {   /* hardware pf information */
	struct mgmt_msg_head head;   /* mbox message header */

	struct hinic5_hw_pf_infos infos;   /* pf information */
};

#define DD_CFG_TEMPLATE_MAX_IDX 12   /* supported config template number */
#define DD_CFG_TEMPLATE_MAX_TXT_LEN 64   /* supported config template size */
#define CFG_TEMPLATE_OP_QUERY 0   /* query config template */
#define CFG_TEMPLATE_OP_SET 1   /* set config template */
#define CFG_TEMPLATE_SET_MODE_BY_IDX 0
#define CFG_TEMPLATE_SET_MODE_BY_NAME 1

struct comm_cmd_cfg_template {   /* config version configuration */
	struct mgmt_msg_head head;   /* mbox message header */
	u8 opt_type;    /* 0: query  1: set */
	u8 set_mode;    /* 0-index mode. 1-name mode. */
	u8 tp_err;   /* template error flag */
	u8 rsvd0;   /* reserved field */

	u8 cur_index;      /* Current cfg tempalte index. */
	u8 cur_max_index;    /* Max support cfg tempalte index. */
	u8 rsvd1[2];   /* reserved field */
	u8 cur_name[DD_CFG_TEMPLATE_MAX_TXT_LEN];   /* current template name */
	/* current template information */
	u8 cur_cfg_temp_info[DD_CFG_TEMPLATE_MAX_IDX][DD_CFG_TEMPLATE_MAX_TXT_LEN];

	u8 next_index;     /* Next reset cfg tempalte index. */
	u8 next_max_index;    /* Max support cfg tempalte index. */
	u8 rsvd2[2];   /* reserved field */
	u8 next_name[DD_CFG_TEMPLATE_MAX_TXT_LEN];   /* next template name */
	/* next template information */
	u8 next_cfg_temp_info[DD_CFG_TEMPLATE_MAX_IDX][DD_CFG_TEMPLATE_MAX_TXT_LEN];
};

#define MQM_SUPPORT_COS_NUM 8   /* cos number */
#define MQM_INVALID_WEIGHT 256   /* mqm table size */
#define MQM_LIMIT_SET_FLAG_READ 0   /* read */
#define MQM_LIMIT_SET_FLAG_WRITE 1   /* write */
struct comm_cmd_set_mqm_limit {   /* mqm rate limit configuration */
	struct mgmt_msg_head head;   /* mbox message header */

	u16 set_flag;   /* set this flag to indicate configuration */
	u16 func_id;   /* specified function id */
	u16 cos_weight[MQM_SUPPORT_COS_NUM];	/* weight for corresponding cos_id,
						 * 0-255, 0 is SP scheduling.
						 */
	u32 host_min_rate;        /* minimum rate supported by this host */
	u32 func_min_rate;        /* minimum rate supported by this function, unit Mbps */
	u32 func_max_rate;          /* maximum rate supported by this function, unit Mbps  */
	u8 rsvd[64];                /* reserved field */
};

enum core_type_e {
	CORE_TYPE_ARM  = 0,
	CORE_TYPE_LINX = 1
};

struct arm_core_reg_info {
	u64 elr;   /* general register */
	u64 spsr;   /* general register */
	u64 far;   /* general register */
	u64 esr;   /* general register */
	u64 xzr;   /* general register */
	u64 x30;   /* general register */
	u64 x29;   /* general register */
	u64 x28;   /* general register */
	u64 x27;   /* general register */
	u64 x26;   /* general register */
	u64 x25;   /* general register */
	u64 x24;   /* general register */
	u64 x23;   /* general register */
	u64 x22;   /* general register */
	u64 x21;   /* general register */
	u64 x20;   /* general register */
	u64 x19;   /* general register */
	u64 x18;   /* general register */
	u64 x17;   /* general register */
	u64 x16;   /* general register */
	u64 x15;   /* general register */
	u64 x14;   /* general register */
	u64 x13;   /* general register */
	u64 x12;   /* general register */
	u64 x11;   /* general register */
	u64 x10;   /* general register */
	u64 x09;   /* general register */
	u64 x08;   /* general register */
	u64 x07;   /* general register */
	u64 x06;   /* general register */
	u64 x05;   /* general register */
	u64 x04;   /* general register */
	u64 x03;   /* general register */
	u64 x02;   /* general register */
	u64 x01;   /* general register */
	u64 x00;   /* general register */
};

struct linx_core_reg_info {
	u32 s0;
	u32 s1;
	u32 s2;
	u32 s3;
	u32 s4;
	u32 s5;
	u32 s6;
	u32 s7;
	u32 s8;
	u32 s9;
	u32 s10;
	u32 s11;
	u32 ra;
	u32 gp;
	u32 tp;
	u32 t0;
	u32 t1;
	u32 t2;
	u32 t3;
	u32 t4;
	u32 t5;
	u32 t6;
	u32 a0;
	u32 a1;
	u32 a2;
	u32 a3;
	u32 a4;
	u32 a5;
	u32 a6;
	u32 a7;
	u32 mepc;
	u32 mstatus;
	u32 mcause;
	u32 rsv[39];   /* total size of this structure must match struct arm_core_reg_info */
};

#define DATA_LEN_1K 1024
struct comm_info_sw_watchdog {   /* software watchdog timeout report interface */
	struct mgmt_msg_head head;   /* mbox message header */

	/* global information */
	u32 curr_time_h;    /* time of infinite loop, cycle */
	u32 curr_time_l;    /* time of infinite loop, cycle */
	u32 task_id;       /* task of infinite loop */
	u8 core_type;     /* see core_type_e definition */
	u8 rsv[3];        /* reserved field for extension */

	/* register information, TSK_CONTEXT_S */
	u64 pc;   /* general register */

	union core_reg {
		struct arm_core_reg_info  arm_reg;
		struct linx_core_reg_info linx_reg;
	} reg_info;

	/* stack control information, STACK_INFO_S */
	u64 stack_top;    /* stack top */
	u64 stack_bottom;    /* stack bottom */
	u64 sp;      /* current stack SP pointer value */
	u32 curr_used;      /* current stack usage size */
	u32 peak_used;       /* historical peak stack usage */
	u32 is_overflow;       /* stack overflow flag */

	/* stack actual content */
	u32 stack_actlen;      /* actual stack length (<=1024) */
	u8 stack_data[DATA_LEN_1K];    /* content beyond 1024 will be truncated */
};

/* last words information */
#define XREGS_NUM 31   /* register number */
typedef struct tag_cpu_tick {   /* time */
	u32 cnt_hi;    /* cycle count high 32 bits */
	u32 cnt_lo;   /* cycle count low 32 bits */
} CPU_TICK;

typedef struct tag_ax_exc_reg_info {   /* general register */
	u64 ttbr0;   /* general register */
	u64 ttbr1;   /* general register */
	u64 tcr;   /* general register */
	u64 mair;   /* general register */
	u64 sctlr;   /* general register */
	u64 vbar;   /* general register */
	u64 current_el;   /* general register */
	u64 sp;   /* general register */
	/* memory layout of the following fields must be consistent with TskContext */
	u64 elr;      /* general register */
	u64 spsr;   /* general register */
	u64 far_r;   /* general register */
	u64 esr;   /* general register */
	u64 xzr;   /* general register */
	u64 xregs[XREGS_NUM];    /* registers 0~30: x30~x0 */
} EXC_REGS_S;

typedef struct exc_call_stack_info {
	u32 depth;  /* call stack depth */
	u64 addrList[10];  /* call stack address list */
	char nameList[10][64];  /* call stack function name list */
} exc_call_stack_info_s;

typedef struct tag_exc_info {
	char os_ver[48];	/* OS version */
	char app_ver[64];	/* product version */
	u32 exc_cause;		/* exception cause */
	u32 thread_type;	/* thread type before exception */
	u32 thread_id;		/* thread PID before exception */
	u16 byte_order;		/* byte order */
	u16 cpu_type;		/* CPU type */
	u32 cpu_id;		/* CPU ID */
	CPU_TICK cpu_tick;	/* CPU Tick */
	u32 nest_cnt;		/* exception nesting count */
	u32 fatal_errno;	/* fatal error code, valid when fatal error occurs */
	u64 uw_sp;		/* stack pointer before exception */
	u64 stack_bottom;	/* stack bottom before exception */
	/* core register context information when exception occurs, 82\57 must be at byte 152,
	 * if changed, need to update OS_EXC_REGINFO_OFFSET macro in sre_platform.eh
	 */
	EXC_REGS_S reg_info;
} EXC_INFO_S;

typedef struct tag_exc_info_all {
	char os_ver[48];	/* OS version */
	char app_ver[64];	/* product version */
	u32 exc_cause;		/* exception cause */
	u32 thread_type;	/* thread type before exception */
	u32 thread_id;		/* thread PID before exception */
	u16 byte_order;		/* byte order */
	u16 cpu_type;		/* CPU type */
	u32 cpu_id;		/* CPU ID */
	CPU_TICK cpu_tick;	/* CPU Tick */
	u32 nest_cnt;		/* exception nesting count */
	u32 fatal_errno;	/* fatal error code, valid when fatal error occurs */
	u64 uw_sp;		/* stack pointer before exception */
	u64 stack_bottom;	/* stack bottom before exception */
	/* core register context information when exception occurs, 82\57 must be at byte 152,
	 * if changed, need to update OS_EXC_REGINFO_OFFSET macro in sre_platform.eh
	 */
	EXC_REGS_S reg_info;
	exc_call_stack_info_s call_stack_info;
} EXC_INFO_ALL_S;

#define MPU_LASTWORD_SIZE 1024   /* lastword single data length */
typedef struct tag_comm_info_up_lastword {   /* up lastword module interface reported to driver */
	struct mgmt_msg_head head;   /* mbox message header */

	EXC_INFO_S stack_info;   /* stack information */

	/* stack actual content */
	u32 stack_actlen;   /* actual stack length (<=1024) */
	u8 stack_data[MPU_LASTWORD_SIZE];    /* payload content beyond 1024 will be truncated */
} comm_info_up_lastword_s;

typedef struct {
	u32 magic;
	u32 symbol_num;  /* symbol number */
	u32 code_size;  /* patch code size */
	u32 rsvd0[5];  /* reserved field */
	char git_tag[64]; /* cold baseline git tag */
	char compile_time[20]; /* compile time */
	u32 rsvd1;  /* reserved field for 8-byte alignment */
} patch_head_info_s;

struct hinic5_cmd_update_firmware {   /* firmware upgrade */
	struct mgmt_msg_head msg_head;   /* mbox message header */

	struct {
		u32 sl : 1;   /* last slice */
		u32 sf : 1;   /* first slice */
		u32 flag : 1;   /* partition flag */
		u32 bit_signed : 1;   /* signature flag */
		u32 reserved : 12;   /* reserved field */
		u32 fragment_len : 16;   /* fragment length */
	} ctl_info;   /* control information */

	struct {
		u32 section_crc;   /* sub-firmware crc */
		u32 section_type;   /* sub-firmware type */
	} section_info;   /* sub-firmware information */

	u32 total_len;   /* image length */
	u32 section_len;   /* sub-firmware length */
	u32 section_version;   /* sub-firmware version */
	u32 section_offset;   /* sub-firmware offset */
	u32 data[384];   /* image data */
};

struct hinic5_cmd_activate_firmware {   /* image activation */
	struct mgmt_msg_head msg_head;   /* mbox message header */
	u8 index;    /* config file activation idx (default use 0) */
	u8 data[7];   /* payload */
};

struct hinic5_cmd_switch_config {   /* config file switch */
	struct mgmt_msg_head msg_head;   /* mbox message header */
	u8 index;    /* config file idx 0~1 */
	u8 data[7];   /* payload */
};

/* start id defined for UB register access adaptation, used to identify UB module in interface, cannot conflict with INTERNAL_RING_NODE_ID_E */
enum hinic5_ub_mod_id {
	HINIC5_UB_D2H = 64,
	HINIC5_UB_LQ_TP = HINIC5_UB_D2H,
	HINIC5_UB_MISC,
	HINIC5_UB_LQ_MISC,
	HINIC5_UBC0_LQ_NL_DL,
	HINIC5_UBC1_LQ_NL_DL,
	HINIC5_UBC2_LQ_NL_DL,
	/* 1872 */
	HINIC5_UBG_MISC,
	HINIC5_UBG_BA,
	HINIC5_UBG_TM,
	HINIC5_UBG_DLPHY,
	HINIC5_UBG_NL,
	HINIC5_UBG_TA,
	HINIC5_UBG_TP,
	HINIC5_UBG_IMMU,
	HINIC5_UBG_OMMU,
	HINIC5_UBC_D2H,
	HINIC5_UBC_TP,
	HINIC5_UBC_MISC,
	HINIC5_UBC_NL,
	HINIC5_UBC_DLPHY,
	HINIC5_UBC_TA,
	/* 1872 */
	HINIC5_UB_END_IDX,
};
/* end node id defined for UB register access adaptation, used to identify UB module in interface, cannot conflict with INTERNAL_RING_NODE_ID_E */

#define MAX_DATA_NUM     (240)
struct csr_msg {   /* csr register read information */
	struct {
		u32 node_id	: 5;	/* node id */
		u32 data_width	: 10;	/* access width */
		u32 module_id	: 8;	/* module id, used to identify which module the address belongs to (some modules have no node_id) */
		u32 rsvd	: 9;	/* reserved field */
	} bits;
	u32 addr;   /* address */
};

struct comm_cmd_mbox_csr_rd_req {   /* csr register read request */
	struct mgmt_msg_head head;   /* mbox message header */
	struct csr_msg csr_info[MAX_DATA_NUM];   /* payload */
	u32 data_num;   /* register number */
};

struct comm_cmd_mbox_csr_rd_ret {   /* csr register read */
	struct mgmt_msg_head head;   /* mbox message header */
	u64 value[MAX_DATA_NUM];   /* register read result */
};

struct comm_cmd_mbox_csr_rd_req_ex {   /* csr register read request */
	struct mgmt_msg_head head;   /* mbox message header */
	u32 data_num;   /* register number */
	struct csr_msg csr_info[0];    /* filled according to actual read number */
};

struct comm_cmd_mbox_csr_rd_ret_ex {   /* csr register read */
	struct mgmt_msg_head head;   /* mbox message header */
	u64 value[0];    /* filled according to actual read number */
};

struct comm_cmd_mbox_csr_wt_req {   /* csr register write */
	struct mgmt_msg_head head;   /* mbox message header */
	struct csr_msg csr_info;   /* csr control register information */
	u64 value;   /* value */
};

struct comm_cmd_mbox_csr_wt_ret {   /* csr register write */
	struct mgmt_msg_head head;   /* mbox message header */
};

#define INDIR_MAX_INDEX_NUM 480
#define INDIR_MAX_WT_INDEX_NUM 32

struct comm_cmd_mbox_indir_addr {   /* indirect table operation information */
	u32 indir_ctrl_addr;   /* control register */
	u32 indir_timeout_addr;   /* timeout register */
	u32 indir_data_addr;   /* data register */
};

struct comm_cmd_mbox_indir_tab_rd_req {   /*  indirect table read request */
	struct mgmt_msg_head head;   /* mbox message header */

	struct comm_cmd_mbox_indir_addr indir_addr;   /* indirect table control information */
	u32 tab_width;   /* table entry width */
	u32 index_num;   /* offset idx */
	u32 index[INDIR_MAX_INDEX_NUM];   /* payload */
};

struct comm_cmd_mbox_indir_tab_rd_ret {   /* indirect table read request */
	struct mgmt_msg_head head;   /* mbox message header */
	u32 data[INDIR_MAX_INDEX_NUM];   /* payload */
};

struct comm_cmd_mbox_indir_tab_wt_req {   /* indirect table write request */
	struct mgmt_msg_head head;   /* mbox message header */

	struct comm_cmd_mbox_indir_addr indir_addr;   /* indirect table control information */
	u32 tab_width;   /* table entry width */
	u32 index;   /* offset idx */
	u32 data[INDIR_MAX_WT_INDEX_NUM];   /* payload */
};

struct comm_cmd_mbox_indir_tab_wt_ret {   /* indirect table write request */
	struct mgmt_msg_head head;   /* mbox message header */
};

enum {
	MPU_LOG_CLEAR = 0,   /* clear mpu log */
	SMU_LOG_CLEAR,   /* clear smu log */
	NPU_LOG_CLEAR,   /* clear npu log */
	SPU_LOG_CLEAR,   /* clear spu log */
	MPU_LASTWORD_CLEAR,   /* clear mpu lastword */
	NPU_LASTWORD_CLEAR,   /* clear microcode lastword */
	ALL_LOG_CLEAR,   /* clear all logs and lastwords */
	UBC_IMP_LOG_CLEAR,   /* clear ubc imp log */
	UBC_IMP_LASTWORD_CLEAR,   /* clear ubc imp lastword */
	ROCE_IMP_LOG_CLEAR,   /* clear roce imp log */
	ROCE_IMP_LASTWORD_CLEAR,   /* clear roce imp lastword */
	ROCE_SCC_LOG_CLEAR,   /* clear roce scc log */
	CLEAR_TYPE_BUTT,
};

struct comm_cmd_clear_log {   /* clear log */
	struct mgmt_msg_head head;    /* mbox message header */
	u32 type;   /* clear log type */
};

struct cmd_sector_info {   /* erase flash */
	struct mgmt_msg_head head;    /* mbox message header */
	u32 offset;                   /* flash address */
	u32 len;                       /* flash erase length */
};

enum flash_counter_info_req_type {
	FLASH_COUNTER_TYPE_GET_MPU_SIZE,   /* mpu counter size get type */
	FLASH_COUNTER_TYPE_GET_MPU_DATA,   /* mpu counter data get type */
	FLASH_COUNTER_TYPE_GET_NPU_SIZE,   /* npu counter size get type */
	FLASH_COUNTER_TYPE_GET_NPU_DATA,   /* npu counter data get type */
	FLASH_COUNTER_TYPE_INVALID   /* counter get type invalid value */
};

struct flash_counter_info_req {   /* get firmware counter information */
	struct mgmt_msg_head head;   /* mbox message header */
	u8 type;    /* flash_counter_info_req_type */
	u8 rsv[3];   /* reserved field */
	u32 offset;   /* address offset */
	u32 length;   /* data length */
};

#define FLASH_COUNTER_TYPE_GET_DATA_MAX_SIZE 1024
struct flash_counter_info_resp {   /* get firmware counter information */
	struct mgmt_msg_head head;   /* mbox message header */
	u32 length;   /* data length */
	u8 data[FLASH_COUNTER_TYPE_GET_DATA_MAX_SIZE];   /* payload */
};

typedef struct {
	u64 smu_images;   /* smu image */
	u64 mpu_images;   /* mpu image */
	u64 npu_images;   /* npu image */
	u64 ppe_images;   /* microcode ppe image */
	u64 cfg_images;   /* config file image */
	u64 patch_images;   /* mpu patch image */
	u64 rsvd[4];   /* reserved field */
} module_images;   /* firmware image type */

typedef struct {
	struct mgmt_msg_head head;   /* mbox message header */
	u32 rsvd[4];   /* reserved field */
} comm_cmd_query_module_images_req;   /* query image type */

typedef struct {
	struct mgmt_msg_head head;   /* mbox message header */
	module_images img;   /* firmware image */
} comm_cmd_query_module_images_rsp;   /* query image type */

typedef struct tag_mpu_ncsi_counter_info_s {
	u32 ncsi_rx_octets_total_ok;   /* ncsi register, see nmanager for details */
	u32 ncsi_rx_octets_bad;   /* ncsi register, see nmanager for details */
	u32 ncsi_rx_uc_pkts;   /* ncsi register, see nmanager for details */
	u32 ncsi_rx_mc_pkts;   /* ncsi register, see nmanager for details */
	u32 ncsi_rx_bc_pkts;   /* ncsi register, see nmanager for details */
	u32 ncsi_rx_pkts_64octets;   /* ncsi register, see nmanager for details */
	u32 ncsi_rx_pkts_65to127octets;   /* ncsi register, see nmanager for details */
	u32 ncsi_rx_pkts_128to255octets;   /* ncsi register, see nmanager for details */
	u32 ncsi_rx_pkts_255to511octets;   /* ncsi register, see nmanager for details */
	u32 ncsi_rx_pkts_512to1023octets;   /* ncsi register, see nmanager for details */
	u32 ncsi_rx_pkts_1024to1518octets;   /* ncsi register, see nmanager for details */
	u32 ncsi_rx_pkts_1519tomaxoctets;   /* ncsi register, see nmanager for details */
	u32 ncsi_rx_fcs_errs;   /* ncsi register, see nmanager for details */
	u32 ncsi_rx_tagged;   /* ncsi register, see nmanager for details */
	u32 ncsi_rx_data_errs;   /* ncsi register, see nmanager for details */
	u32 ncsi_rx_align_errs;   /* ncsi register, see nmanager for details */
	u32 ncsi_rx_long_errs;   /* ncsi register, see nmanager for details */
	u32 ncsi_rx_jabber_errs;   /* ncsi register, see nmanager for details */
	u32 ncsi_rx_pause_maccontrol_framcounter;   /* ncsi register, see nmanager for details */
	u32 ncsi_rx_unknow_maccontrol_framcounter;   /* ncsi register, see nmanager for details */
	u32 ncsi_rx_very_long_err_cnt;   /* ncsi register, see nmanager for details */
	u32 ncsi_rx_runt_err_cnt;   /* ncsi register, see nmanager for details */
	u32 ncsi_rx_short_err_cnt;   /* ncsi register, see nmanager for details */
	u32 ncsi_rx_filt_pkt_cnt;   /* ncsi register, see nmanager for details */
	u32 ncsi_rx_octets_total_filt;   /* ncsi register, see nmanager for details */
	u32 ncsi_tx_octets_transmitte_ok;   /* ncsi register, see nmanager for details */
	u32 ncsi_tx_octets_transmitte_bad;   /* ncsi register, see nmanager for details */
	u32 ncsi_tx_uc_pkts;   /* ncsi register, see nmanager for details */
	u32 ncsi_tx_mc_pkts;   /* ncsi register, see nmanager for details */
	u32 ncsi_tx_bc_pkts;   /* ncsi register, see nmanager for details */
	u32 ncsi_tx_pkts_64octets;   /* ncsi register, see nmanager for details */
	u32 ncsi_tx_pkts_65to127octets;   /* ncsi register, see nmanager for details */
	u32 ncsi_tx_pkts_128to255octets;   /* ncsi register, see nmanager for details */
	u32 ncsi_tx_pkts_255to511octets;   /* ncsi register, see nmanager for details */
	u32 ncsi_tx_pkts_512to1023octets;   /* ncsi register, see nmanager for details */
	u32 ncsi_tx_pkts_1024to1518octets;   /* ncsi register, see nmanager for details */
	u32 ncsi_tx_pkts_1519tomaxoctets;   /* ncsi register, see nmanager for details */
	u32 ncsi_tx_underrun;   /* ncsi register, see nmanager for details */
	u32 ncsi_tx_tagged;   /* ncsi register, see nmanager for details */
	u32 ncsi_tx_crc_err;   /* ncsi register, see nmanager for details */
	u32 ncsi_tx_pause_frams;   /* ncsi register, see nmanager for details */
	u32 ncsi_rx_overrun_cnt;   /* ncsi register, see nmanager for details */
	u32 ncsi_rx_lengthfield_err_cnt;   /* ncsi register, see nmanager for details */
	u32 ncsi_rx_fail_comma_cnt;   /* ncsi register, see nmanager for details */
	u32 ncsi_tx_frm_cnt;   /* ncsi register, see nmanager for details */
	u32 ncsi_tx_frm_err_cnt;   /* ncsi register, see nmanager for details */
	u32 ncsi_tx_xon_cnt;   /* ncsi register, see nmanager for details */
	u32 ncsi_tx_xoff_cnt;   /* ncsi register, see nmanager for details */
	u32 ncsi_tx_xon_err_cnt;   /* ncsi register, see nmanager for details */
	u32 ncsi_tx_empty_err_cnt;   /* ncsi register, see nmanager for details */
	u32 ncsi_app_bd_cnt;   /* ncsi register, see nmanager for details */
	u32 ncsi_add_bd_cnt;   /* ncsi register, see nmanager for details */
	u32 ncsi_rx_txbd_cnt;   /* ncsi register, see nmanager for details */
	u32 ncsi_rx_txbd_empty_cnt;   /* ncsi register, see nmanager for details */
	u32 ncsi_rx_txbd_code_err_cnt;   /* ncsi register, see nmanager for details */
	u32 ncsi_rx_txbd_min_frame_cnt;   /* ncsi register, see nmanager for details */
	u32 ncsi_rx_txbd_max_frame_cnt;   /* ncsi register, see nmanager for details */
	u32 ncsi_rls_bd_cnt;   /* ncsi register, see nmanager for details */
	u32 ncsi_rx_pt_pkt_cnt_low;   /* ncsi register, see nmanager for details */
	u32 ncsi_rx_pt_pkt_cnt_high;   /* ncsi register, see nmanager for details */
	u32 ncsi_rx_pt_pkt_disc_cnt;   /* ncsi register, see nmanager for details */
	u32 ncsi_tx_pt_ch_err_cnt0;   /* ncsi register, see nmanager for details */
	u32 ncsi_tx_pt_ch_err_cnt1;   /* ncsi register, see nmanager for details */
	u32 ncsi_tx_pt_ch_err_cnt2;   /* ncsi register, see nmanager for details */
	u32 ncsi_tx_pt_ch_err_cnt3;   /* ncsi register, see nmanager for details */
	u32 ncsi_tx_pt_pkt_cnt;   /* ncsi register, see nmanager for details */
	u32 ncsi_rx_ctrl_ok_cnt;   /* ncsi register, see nmanager for details */
	u32 ncsi_rx_ctrl_disc_cnt;   /* ncsi register, see nmanager for details */
	u32 ncsi_rx_ctrl_chksum_err_cnt;   /* ncsi register, see nmanager for details */
	u32 ncsi_tx_ctrl_pkt_cnt;   /* ncsi register, see nmanager for details */
	u32 ncsi_tx_ctrl_len_mismatch_cnt;   /* ncsi register, see nmanager for details */
	u32 ncsi_tx_ctrl_len_short;   /* ncsi register, see nmanager for details */
	u32 ncsi_rx_pt_ch_ok_cnt0;   /* ncsi register, see nmanager for details */
	u32 ncsi_rx_pt_ch_ok_cnt1;   /* ncsi register, see nmanager for details */
	u32 ncsi_rx_pt_ch_ok_cnt2;   /* ncsi register, see nmanager for details */
	u32 ncsi_rx_pt_ch_ok_cnt3;   /* ncsi register, see nmanager for details */
	u32 ncsi_rx_ctrl_pavload_len_err_cnt;   /* ncsi register, see nmanager for details */
	u32 ncsi_ipsurx_hit_count;   /* ncsi register, see nmanager for details */
	u32 pie_to_mpu_bd_cnt;   /* ncsi register, see nmanager for details */
	u32 pie_to_ipsu_bd_cnt;   /* ncsi register, see nmanager for details */
	u32 pie_to_ncsi_bd_cnt;   /* ncsi register, see nmanager for details */
	u32 rsv[10];
} mpu_ncsi_counter_info_s;   /* ncsi register, see nmanager for details */

#define NCSI_COUNT_OPT_TYPE_READ 0   /* ncsi counter read */
#define NCSI_COUNT_OPT_TYPE_CLEAR 1   /* nsci counter clear */

struct comm_cmd_ncsi_counter_req {   /* get ncsi counter */
	struct mgmt_msg_head head;    /* mbox message header */
	u8 opt_type;                  /* 0:read counter 1:counter clear */
	u8 rsvd[3];
};

struct comm_cmd_ncsi_counter_resp {   /* get ncsi counter */
	struct mgmt_msg_head head;       /* mbox message header */

	mpu_ncsi_counter_info_s ncsi_cnt_info;   /* counter information */
};
#define SINGLE_EFUSE_BIN_SIZE 512
#define SEND_EFUSE_DATA_SIZE (SINGLE_EFUSE_BIN_SIZE * 3)
struct send_efuse_data_s {   /* efuse information burn */
	struct mgmt_msg_head head;	/* mbox message header */
	u8 opt_type;			/* efuse operation type: 1: burn efuse bin,
					 * 2: hw rotpk switch to guest rotpk
					 */
	u8 rsvd0[3];			/* reserved field */
	u32 total_len;			/* entire package leng value */
	u32 data_csum;			/* entire package data count sum value */
	u8 data[SEND_EFUSE_DATA_SIZE];	/*  payload 1024B*/
};

typedef enum {
	BURN_EFUSE_BIN = 1,
	REVOKE_SEC_VER_NUM,
	BURN_HISS_EFUSE0_BIN,
	BURN_HISS_EFUSE1_BIN,
	BURN_ALL_EFUSE_BIN,
	NONE_BURN_EFUSE_BIN,
} eufse_option_type_e;

#define DFX_MAG_MAX_REG_NUM (32)
struct comm_info_dfx_mag_reg {
	struct mgmt_msg_head head;
	u16 sel;      /* direction: 0 - tx 1 - rx */
	u16 write;    /* read/write flag: 0 - read 1 - write */
	u32 reg_addr; /* register address */
	u32 reg_cnt;  /* starting from reg_addr as BASE_ADDR, number of consecutive registers to read (not bytes, but register count),
		       * maximum 32
		       */
	u32 clear;    /* read clear flag: 0 - not read clear 1 - read clear (invalid for write operation) */
	u32 data[DFX_MAG_MAX_REG_NUM]; /* returned data, up to DFX_MAG_MAX_REG_NUM,
					* actual valid data count indicated by reg_cnt
					*/
};

#define UPDATE_CMD_HEAD_NEW_VERSION 0x1  /* duplicate packet command version from tool */

/* firmware upgrade error code definition */
enum hinic5_update_fw_err_code {
	MPU_FW_UPDATE_OK = 0x00,
	MPU_FW_UPDATE_START = 0x01,
	MPU_FW_UPDATE_READ_FLASH_ERR = 0x02,
	MPU_FW_UPDATE_WRITE_FLASH_ERR = 0x03,
	MPU_FW_UPDATE_OTHER_FAIL = 0x04,
	MPU_FW_UPDATE_BUSY = 0x05,
	MPU_FW_UPDATE_OTHER_OPERAT = 0x06,
	MPU_FW_UPDATE_PARA_CHECK_ERR = 0x07,
	MPU_FW_UPDATE_DUPLICATE_SUBFW = 0x08,
	MPU_FW_UPDATE_FW_CRC_ERR = 0x09,
	MPU_FW_UPDATE_FW_VERIFY_ERR = 0x0a,
	MPU_FW_UPDATE_SUBFW_PARTIAL = 0x0b,
	MPU_FW_UPDATE_REFRESH_STATE_MACHINE_FAIL = 0x0c,
	MPU_FW_UPDATE_BOARD_TYPE_CHECK_FAIL = 0x0d,
	MPU_FW_UPDATE_PERMISSION_DENINED = 0x0e,
	MPU_FW_UPDATE_ALREADY_ACTIVED = 0x0f,
	MPU_FW_UPDATE_ALLOC_MEM_FAIL = 0x10,
	MPU_FW_UPDATE_CHECK_VERSION_FAIL = 0x11,
	MPU_FW_UPDATE_STATE_MACHINE_INVALID = 0x12,
	MPU_FW_UPDATE_INSTALL_PATCH_FAIL = 0x13,
	MPU_FW_UPDATE_UNINSTALL_PATCH_FAIL = 0x14,
	MPU_FW_UPDATE_ACTIVE_PATCH_FAIL = 0x15,
	MPU_FW_UPDATE_DEACTIVE_PATCH_FAIL = 0x16,
	MPU_FW_UPDATE_GIT_TAG_MISMATCH = 0x17,
	MPU_FW_UPDATE_ADD_SYMBOL_FAIL = 0x18,
	MPU_FW_UPDATE_PATCH_REPLACE_EXCLUSIVE = 0x19,
	MPU_FW_UPDATE_PAUSE_TASKS_FAIL = 0x1a,
	MPU_FW_UPDATE_FLR_IS_RUNNING = 0x1b,
	MPU_FW_UPDATE_RESET_CORE_FAIL = 0x1c,
	MPU_FW_UPDATE_INIT_FAIL = 0x1d,
	MPU_FW_UPDATE_HOT_UPDATE_NOT_SUPPORT = 0x1e,
	MPU_FW_UPDATE_FLUSH_FLASH_REPEAT = 0xfb,
	MPU_FW_UPDATE_OTHER_HOST_RST_SPI_BUSY = 0xfc,
	MPU_FW_UPDATE_HOT_ACTIVE_INVALID = 0xfd,
	MPU_FW_UPDATE_HOT_ACTIVE_FAIL = 0xfe,
};

struct fw_update_msg_st {   /*  */
	struct mgmt_msg_head msg_head;   /* mbox message header */
	struct {
		u32 SL : 1;           /* last slice */
		u32 SF : 1;           /* first slice */
		u32 Flag : 1;   /* partition flag */
		u32 Signed : 1;   /* signature flag */
		u32 Repeat : 1;   /* fragment operation flash */
		u32 updatefw_main_area_flag : 1;   /* main area flag */
		u32 Reserved : 10;   /* reserved field */
		u32 Fragment_Len : 16;    /* fragment length */
	} ctl_info;   /*  */

	struct {
		u32 FW_section_CRC;   /* fragment operation flash */
		u32 FW_section_type;   /* sub-firmware type */
	} section_info;   /* sub-firmware information */

	u32 total_len;            /* image length */
	u32 setion_total_len;   /* sub-firmware length */
	u32 fw_section_version;   /* sub-firmware version */
	u32 section_offset;   /* sub-firmware offset */
	u32 data[384];   /* image data */
};

/* hot activation type */
typedef enum {
	HOT_ACTIVE_NONE = 0,
	HOT_ACTIVE_MPU = 1,
	HOT_ACTIVE_NPU = 2,
	HOT_ACTIVE_MNPU = 3,
	HOT_ACTIVE_SCC = 4,
} hot_active_type_e;

/* MPU hot activation type */
typedef enum {
	MPU_HOT_ACTIVE_NONE,  /* hot upgrade not yet performed */
	MPU_HOT_ACTIVE_PATCH,  /* hot patch */
	MPU_HOT_ACTIVE_REPLACE,  /* hot replace */
} mpu_hot_active_type_e;

struct cmd_hot_active_fw {   /* hot upgrade activation */
	struct mgmt_msg_head head;     /* mbox message header */
	u8 type;                      /* activate sub-firmware type, 1: mpu; 2: ucode; 3: mpu & npu */
	u8 mpu_hot_active_type;     /* MPU hot activation type, valid when type is MPU or MNPU */
	u8 data[6];                  /* reserved field */
};

struct cmd_bat_set_info {   /* hot upgrade bat table entry operation transition information */
	struct mgmt_msg_head head;   /* mbox message header */

	u16 func_id;   /* specified function id */
	u8  smf_id;   /* smf idx */
	u8  rsvd1;   /* reserved field */
	u32 bat_offset;   /* bat offset */
	u32 data_size;   /* data size */
	u8  data[256];   /* payload */
};

/* read dbf information */
typedef struct {
	u32 device_id;
	u32 vendor_id;
} mpu_pcie_pf_info_s;

typedef struct {
	struct mgmt_msg_head head;

	mpu_pcie_pf_info_s pf_info[32];
	u32 bus_id;
	u32 pf_num;
} mpu_pcie_dev_bdf_info_s;

typedef struct {
	struct mgmt_msg_head head;
	u8 valid;  /* 1: valid */
	u8 host_id;  /* container home host, range 0 ~ 3 */
	u8 rsvd[2];
} comm_cmd_con_sel_sta;

typedef struct pf_bdf_info {
	u8 itf_idx;
	u16 bdf;
	u8 pf_bdf_info_vld;
} comm_pf_bdf_info_s;

typedef struct vf_bdf_info {
	u16 glb_pf_vf_offset; /* global_func_id offset of 1st vf in pf */
	u16 max_vfs; /* vf number */
	u16 vf_stride; /* VF_RID_SETTING.vf_stride */
	u16 vf_offset; /* VF_RID_SETTING.vf_offset */
	u8 bus_num; /* tl_cfg_bus_num */
	u8 rsv[3];
} comm_vf_bdf_info_s;

struct comm_cmd_get_bdf_info_s {
	struct mgmt_msg_head head;
	comm_pf_bdf_info_s  pf_bdf_info[PCIE_MODE_PF_NUM];
	comm_vf_bdf_info_s  vf_bdf_info[PCIE_MODE_PF_NUM];
	u32 vf_num; /* vf num */
};

typedef struct comm_virtio_dev_cmd {
	u16 device_type;
	u16 device_id;
	u32 devid_switch;
	u32 sub_vendor_id;
	u32 sub_class_code;
	u32 flash_en;
} comm_virtio_dev_cmd_s;

typedef struct comm_virtio_dev_ctl {
	u32 device_type_mark;
	u32 devid_switch_mark;
	u32 sub_vendor_id_mark;
	u32 sub_class_code_mark;
	u32 flash_en_mark;
} comm_virtio_dev_ctl_s;

struct comm_cmd_set_virtio_dev {
	struct mgmt_msg_head head;
	comm_virtio_dev_cmd_s virtio_dev_cmd;
	comm_virtio_dev_ctl_s virtio_dev_ctl;
};

#define PSM_GIT_CHAR_NUM (20)
struct cmd_get_mpu_git_code {
	struct mgmt_msg_head head; /* 8B */
	u8 rsvd[3];                   /* reserved */
	u8 psm_en;
	char mpu_git_code[64];      /* git code and compile time, 60 characters */
	char psm_git_code[PSM_GIT_CHAR_NUM + 1];      /* psm git code and compile time, 20 characters */
	u8 rsvd1[3];                /* reserved */
};

/* disable chip auto reset */
struct comm_cmd_enable_auto_rst_chip {
	struct mgmt_msg_head head;

	u8 op_code; /* 0: get  1: set */
	u8 enable; /* 1: enable auto reset chip; 0: disable auto reset chip */
	u8 rsvd[2];
};

/* chip core temperature structure definition */
struct comm_temp_in_info {
	struct mgmt_msg_head head; /* 8B */
	u8 opt_type;                /* 0:read operation 1:cfg operation */
	u8 rsv[3];
	s32 max_temp; /* chip core temperature threshold */
	s32 min_temp; /* chip core temperature threshold */
};

struct comm_temp_out_info {
	struct mgmt_msg_head head; /* 8B */
	s32 temp_data;             /* read temperature */
	s32 max_temp_threshold;    /* chip core temperature threshold */
	s32 min_temp_threshold;    /* chip core temperature threshold */
	s32 max_temp;              /* chip core temperature historical maximum */
	s32 min_temp;              /* chip core temperature historical minimum */
};

/* chip id information */
struct comm_chip_id_info {
	struct mgmt_msg_head head;

	u8 chip_id;
	u8 rsvd[3];
};

/* die id module interface */
struct comm_cmd_get_die_id {
	struct mgmt_msg_head head;

	u32 die_id_data[8];
};

typedef struct {
	struct mgmt_msg_head head;

	u8 lldp_tx_enable;
	u8 port;
	u8 rsv[2];
} comm_cmd_lldp_tx_set_s;

#define MSIX_INFO_LEN 0x200
struct comm_cmd_msix_info {
	struct mgmt_msg_head head;

	u8 rsvd1;
	u8 flag;  /* 0-second map, 1-actual map, 2-first map entry */
	u16 function_id;
};

enum log_status_operation_type {
	READ_TYPE = 0,
	WRITE_TYPE,
};

enum log_status_type {
	LOG_NORMAL = 0,
	LOG_BUSY,
};
struct mpu_log_status_info {
	struct mgmt_msg_head head;
	u8 type;       /* 0: read 1: write */
	u8 log_status; /* 0: idle 1: busy */
	u8 rsvd[2];
};

#define RQ_CXT_SIZE 64
#define SQ_CXT_SIZE 64
#define CMDQ_COUNT 2
#define CMDQ_CXT_SIZE 16
#define ENHANCE_CMDQ_CXT_SIZE 48
#define ENHANCE_CMDQ_CXT_SIZE_FRIST 16
#define ENHANCE_CMDQ_CXT_SIZE_SECOND 32

typedef struct {
	struct mgmt_msg_head head;
	u32 func_id;
	u32 smf_id;
	u32 queue_id;
	u32 smf_id_valid;            /* whether the input smf_id is valid */
} comm_cmd_root_ctx_load_req_s;

typedef struct {
	struct mgmt_msg_head head;
	u8 rq_ctx[RQ_CXT_SIZE];
	u8 sq_ctx[SQ_CXT_SIZE];
	u8 cmdq_ctx[CMDQ_CXT_SIZE * CMDQ_COUNT];
	u8 enhance_cmdq_ctx[ENHANCE_CMDQ_CXT_SIZE * CMDQ_COUNT];
} comm_cmd_root_ctx_load_ret_s;

struct cmd_query_fw {
	struct mgmt_msg_head head;	/* 8B */
	u32 offset;	/* offset, because the returned information is large, multiple returns are needed */
	u32 len;	/* data length to read */
};

#define MAX_CMD_DATA_LEN (1024 + 512)
struct cmd_fw_info {
	struct mgmt_msg_head head; /* 8B */
	u32 len;                    /* actual data length read */
	u8 data[MAX_CMD_DATA_LEN];  /* maximum 1536 bytes per read */
};

typedef struct {
	u32 tgt_speed;
	u32 cur_speed;
	u32 tgt_width;
	u32 cur_width;
} pcie_link_info_s;

typedef struct {
	u32 pf_start;
	u32 pf_end;
	u32 pf_num;
	u32 vf_start;
	u32 vf_end;
	u32 vf_num;
} pcie_pf_vf_info_s;

typedef struct {
	u32 p_tx_left_tag;
	u32 np_tx_left_tag;
	u32 cpl_tx_left_tag;
	u32 p_rx_left_tag;
	u32 np_rx_left_tag;
	u32 cpl_rx_left_tag;
} pcie_dfx_info_s;

typedef struct {
	u32 host_idx;
	u32 core_id;
	u32 port_id;
	pcie_link_info_s link_info;
	pcie_pf_vf_info_s pf_vf_info;
	pcie_dfx_info_s dfx_info;
} pcie_topo_item_s;

#define CMD_PCIE_MAX_HOST_IDX 0xD
typedef struct  {
	struct mgmt_msg_head head;
	u32 cur_host;
	u32 host_cnt;
	pcie_topo_item_s item[CMD_PCIE_MAX_HOST_IDX + 1];
} comm_cmd_get_pcie_topo_s;

typedef struct  {
	struct mgmt_msg_head head;
	u32 type;
	u32 condition1;
	u32 condition2;
	u32 opc;
	u64 data;
	u32 ret;
} comm_cmd_pcie_option_s;

#define MAX_TYPE_NAME_LEN 8

/* VF mapping flags for mqm vf_map type */
#define VF_MAP_FLAG_FUNC_ID_SET 0x01
#define VF_MAP_FLAG_VNIC_ID_SET 0x02
#define VF_MAP_FLAG_VNIC_GRP_ID_SET 0x04

struct cmd_mpu_set_shaper {
	struct mgmt_msg_head head; /* 8B */
	char option[MAX_TYPE_NAME_LEN];
	char module_name[MAX_TYPE_NAME_LEN];
	char shaper_mod[MAX_TYPE_NAME_LEN];
	char type_name[MAX_TYPE_NAME_LEN];
	u8 pqm_mod;
	u8 port_id;
	u8 tc_id;
	u8 cos_id;
	u8 mqm_type;
	u8 rsvd[3];
	u32 mqm_shaper_id;
	u32 vnic_vnic_grp_id;
	u32 cir;
	u32 cbs;
	u32 pir;
	u32 pbs;
	u32 xir;
	u32 xbs;
	u32 func_id;
	u32 vnic_id;
	u32 vnic_group_id;
	u32 vf_map_flags;
	u32 rsvds[16];
};

#define VF_SQ_RQ_MAX_NUM 128
#define PF_SQ_RQ_MAX_NUM 256
#define CFG_VF_MAX_NUM 63
#define CFG_VF_TOTAL_NUM 126
#define CFG_MSIX_MAX_NUM 3072 /* NIC QP + AEQ = 3K, NOT CONTAIN RoCE */
#define CFG_PF_MAX_NUM 16
#define CFG_INVALID_VALUE 0xFFFF
#define PF_VF_TOTAL_QUEUE_MAX_NUM 1744

#define CFG_BAR_INDEX0 0
#define CFG_BAR_INDEX1 1
#define CFG_BAR_INDEX2 2
#define CFG_BAR_INDEX3 3
#define CFG_BAR_INDEX4 4
#define CFG_BAR_INDEX5 5

#define PF_TYPE 0
#define VF_TYPE 1
#define CFG_BAR_INDEX_NUM 6
#define CFG_BAR_SIZE_MIN_NUM   4
#define CFG_PF_BAR_SIZE_MAX_NUM   64
#define CFG_PF_BAR3_SIZE_MAX_NUM   128
#define CFG_VF_BAR_SIZE_MAX_NUM   64
#define CFG_VF_BAR4_SIZE_MAX_NUM 4096
#define CFG_BAR_SIZE_INVALID_VALUE 0xFFFFFFFF
#define CFG_BAR_TRANSLATE_KB_TO_BYTE(bar_size) (((bar_size) * 1024) - 1)
#define CFG_BAR_TRANSLATE_BYTE_TO_KB(bar_size) (((bar_size) + 1) / 1024)

#define CFG_DATA_OP_GET 0
#define CFG_DATA_OP_SET 1
#define CFG_DATA_OP_CLEAR 2
#define CFG_DATA_OP_BAR_GET 3
#define CFG_DATA_OP_BAR_SET 4
#define CFG_DATA_OP_BAR_CLEAR 5
#define QUEUE_BIT_PF_SQ_RQ 0
#define QUEUE_BIT_VF_SQ_RQ 1
#define QUEUE_BIT_VF_NUM 2

#define CFG_BAR_MODE_TEMP 0
#define FLASH_BAR_MODE_TEMP 0xFFFFFFFF
#define CLEAN_BAR_REBOOT_TWICE (FLASH_BAR_MODE_TEMP - 2)
#define CFG_BAR_MODE_PERM 1
#define FLASH_BAR_MODE_PERM 0x1

#define CFG_BIT(x) (0x1U << (x))
#define CFG_GET_BIT(val, bit) (((val) >> (bit)) & 0x1)
#define CFG_SET_BIT(val, bit) ((val) |= CFG_BIT(bit))
#define CFG_CLEAR_BIT(val, bit) ((val) &= ~CFG_BIT(bit))

typedef struct mpu_nic_func_queue_s {
	u32 magic_func_sq_rq_queue;
	u16 pf_sq_rq;
	u16 vf_sq_rq;
	u16 vf_num;
	u16 rsvd0;
} mpu_nic_func_queue;

typedef struct mpu_nic_bar_s {
	u32 magic_bar_set;
	u8 pf_bar_index;    /* 0-3 */
	u8 vf_bar_index;    /* 0,2,4 */
	u8 pf_bar_set_flag;
	u8 vf_bar_set_flag;
	u32 bar_mode;       /* temp: 0 in tool, 0xFFFFFFFF in flash ;
			     * permanently: 1 in tool, 0x1 in flash
			     */
	u32 pf_bar_size[CFG_BAR_INDEX_NUM];
	u32 vf_bar_size[CFG_BAR_INDEX_NUM];
} mpu_nic_bar;

struct comm_cmd_cfg_data {
	struct mgmt_msg_head head;
	u8 opt_type; /* operation type 0: query 1: set 2: clear 4: bar set 5: bar clear */
	u8 pf_index;
	u8 queue_bitmap; /* 0: pf_sq_rq 1: vf_sq_rq 2: vf_num */
	u8 pf_num;
	u16 pf_sq_rq;
	u16 vf_sq_rq;
	u16 vf_num;
	u16 total_queue_num;
	u8 is_set_diff_template;
	u8 rsvd0[3];
	u32 rsvd1[210];
	mpu_nic_bar bar_info_current;
	mpu_nic_bar bar_info_default;
	mpu_nic_bar bar_info;
	mpu_nic_func_queue cur_func_queue[CFG_PF_MAX_NUM];
	mpu_nic_func_queue next_func_queue[CFG_PF_MAX_NUM];
};

enum voltage_type_e {
	VOLTAGE_TYPE_VRD,
	VOLTAGE_TYPE_VSENSOR,
};
typedef struct comm_cmd_voltage_info_s {
	struct mgmt_msg_head head;
	u8 type; /* see voltage_type_e */
	u8 rsv[3];
	u16 vol_integer;
	u16 vol_decimal;
} comm_cmd_voltage_info;

typedef enum {
	RTOS_INFO_TYPE_TASK_INFO,
	RTOS_INFO_TYPE_CPU_PER,
	RTOS_INFO_TYPE_VER_INFO,
	RTOS_INFO_TYPE_HWI_INFO,
	RTOS_INFO_TYPE_SEM_INFO,
	RTOS_INFO_TYPE_BUTT,
} rtos_info_type_e;

typedef struct {
	struct mgmt_msg_head head;
	u8 type;
	u8 rsv[3];
	u32 para;
} cmd_query_rtos_info;

#define MAX_RTOS_INFO_LEN (2000)
typedef struct {
	struct mgmt_msg_head head;
	u8 data[MAX_RTOS_INFO_LEN];
} cmd_rtos_info;

#define MAX_RTOS_ID_NUM 200
typedef struct {
	u16 num;
	u16 rsv;
	u32 id[MAX_RTOS_ID_NUM];
} rtos_list_info;

#define RTOS_TASK_NAME_LEN 16
typedef struct {
	u32 task_pid;
	char name[RTOS_TASK_NAME_LEN];
	u16 status;
	u16 prio;
	u64 pc;
	u64 sp;
	u32 sem_id;
} rtos_task_info;

typedef struct {
	u32 pid;
	u16 usage;
	u16 rsv;
	char name[RTOS_TASK_NAME_LEN];
} thread_cpup_info;

#define RTOS_MAX_THREAD_CPUP_NUM 50
typedef struct {
	u32 core_id;
	u32 cpup;
} core_cpup_info;

#define RTOS_MAX_CORE_NUM 4
typedef struct {
	u32 core_num;
	u32 thread_num;
	core_cpup_info cpup_info[RTOS_MAX_CORE_NUM];
	thread_cpup_info thread_info[RTOS_MAX_THREAD_CPUP_NUM];
} rtos_cpup_info;

#define RTOS_VER_INFO_LEN 1024
typedef struct {
	char version[RTOS_VER_INFO_LEN];
} rtos_ver_info;

typedef struct {
	u32 no;
	u16 type;
	u16 prio;
	u64 para;
} hwi_info;

#define RTOS_MAX_HWI_NUM 100
typedef struct {
	u32 num;
	hwi_info info[RTOS_MAX_HWI_NUM];
} rtos_hwi_info;

/*
 * @ingroup OS_sem
 * semaphore type.
 */
typedef enum {
	RTOS_SEM_TYPE_COUNT, /* counting semaphore */
	RTOS_SEM_TYPE_BIN, /* binary semaphore */
	RTOS_SEM_TYPE_BUTT
} rtos_sem_type_e;

/*
 * @ingroup OS_sem
 * wakeup mode for blocked threads in semaphore module.
 */
typedef enum {
	RTOS_SEM_MODE_FIFO,  /* semaphore FIFO wakeup mode */
	RTOS_SEM_MODE_PRIOR, /* semaphore priority wakeup mode */
	RTOS_SEM_MODE_BUTT   /* invalid semaphore wakeup mode */
} rtos_sem_mode_e;

typedef struct {
	u32 count;
	u32 owner;
	u16 sem_id;
	u8 mode; /* semaphore wakeup mode */
	u8 type;
} sem_info;

#define RTOS_MAX_SEM_NUM 128
typedef struct {
	u32 num;
	sem_info info[RTOS_MAX_SEM_NUM];
} rtos_sem_info;

#define FW_RESTORE_ENABLE 1
#define FW_RESTORE_DISABLE 0
#define FW_RESTORE_SET_MAX_NUM (200)
#define FW_RESTORE_INSTALL_SDK_MAX_TIMEOUT 30
#define FW_RESTORE_INSTALL_SDK_MIN_TIMEOUT 1
#define FW_RESTORE_MAX_FAIL_COUNT 20
#define FW_RESTORE_MIN_FAIL_COUNT 1

#define SWITCH_RESET_OPT_READ 0
#define SWITCH_RESET_OPT_WRITE 1

typedef enum {
	RESTORE_SET_TYPE_SWITCH = 0,  /* startup partition switch flag */
	RESTORE_SET_TYPE_RESET, /* auto reset flag after partition switch */
	RESTORE_SET_TYPE_FAIL_COUNT, /* set SDK load failure detection count */
	RESTORE_SET_TYPE_TIMEOUT, /* set SDK load timeout */
	RESTORE_SET_TYPE_BUTT
} fw_restore_set_e;

struct cmd_chip_switch_reset {
	struct mgmt_msg_head head;
	u8 op_code; /* 0: set  1: get */
	u8 type; /* fw_restore_set_e, reused as fail_count return value when reading */
	u8 value; /* value to set, reused as switch&reset return value when reading */
	u8 read_value; /* only used when reading, as timeout return value */
};

/* integrity */
#define GRAY_INFO_MAGIC_NUM 0xc380f8dd
#define HASH_SIG_SIZE 512
#define KEY_HASH_SIZE 32
#define PUBKEY_SIZE 1024
#define INTEGERITY_VERIFY_ENABLE 0x5A /* use magic number to indicate integrity verification is enabled */
typedef enum {
	INTEGERITY_CMD_ENABLE = 0,
	INTEGERITY_CMD_UPDATE,
	INTEGERITY_CMD_DISABLE,
	INTEGERITY_CMD_MAX,
} integrity_cmd_type;

typedef struct {
	u8 integrity_type;          /* user firmware integrity protection switch */
	u8 rsvd[3];                 /* reserved field*/
	u8 key_hash[KEY_HASH_SIZE]; /* customer root public key hash value */
	u8 pubkey[PUBKEY_SIZE];
	u8 keysig[HASH_SIG_SIZE];
	u8 newpubkey[PUBKEY_SIZE];
	u8 newkeysig[HASH_SIG_SIZE]; /* signature file used for update operation */
} cskey_status;

typedef struct {
	u32 magic_num;
	cskey_status key_hash_sign;
	u32 crc;
} gray_card_info_s;
/* integrity */

/* update err code */
typedef enum MPU_INTEGRITY_STATUS {
	MPU_INTEGRITY_OK = 0,
	MPU_INTEGRITY_NOT_ENABLE = 101,
	MPU_INTEGRITY_IS_ENABLE,
	MPU_INTEGRITY_MEMCPY_FAIL,
	MPU_INTEGRITY_WRITE_FLASH_FAIL,
	MPU_INTEGRITY_SMU_VERIFY_FAIL,
} MPU_INTEGRITY_STATUS_ENUM;

#endif