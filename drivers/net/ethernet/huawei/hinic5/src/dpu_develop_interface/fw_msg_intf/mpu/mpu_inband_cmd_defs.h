/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : mpu_inband_cmd_defs.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/09/16
 * Description   : In-band command-related structures between the driver and the MPU
 */

#ifndef MPU_INBAND_CMD_DEFS_H
#define MPU_INBAND_CMD_DEFS_H

#include "mpu_cmd_base_defs.h"

#define HARDWARE_ID_1XX3V200_TAG 32     /**< 1xx3v200 tag */
#define DUMP_16B_PER_LINE	16  /**< dump 16byte alignment */
#define DUMP_4_VAR_PER_LINE	4   /**< dump unit 4byte */
#define FW_UPDATE_MGMT_TIMEOUT	3000000U    /** mbox message upgrade command timeout */

#define FUNC_RESET_FLAG_MAX_VALUE ((1U << (RES_TYPE_MAX + 1)) - 1)  /**< Boundary value of func_reset_flag */
struct comm_cmd_func_reset {    /**< Driver load/unload scenario, function reset to clear resources */
	struct mgmt_msg_head head;  /**< mbox message header */

	u16 func_id;    /**< function id to reset */
	u16 rsvd1[3];   /**< Reserved field */
	u64 reset_flag;     /**< bitmap of specific reset resources */
};

struct comm_cmd_ppf_flr_type_set {  /**< flr scenario, set ppf flr execution scope */
	struct mgmt_msg_head head;  /**<  */

	u16 func_id;    /**< function id of flr */
	u8 rsvd1[2];    /**< Reserved field */
	u32 ppf_flr_type;   /**< ppf flr scope type, 0: only ffp, 1: all functions under this ppf */
};

enum {
	COMM_F_API_CHAIN                    = 1U << 0,   /**< Attribute negotiation, cpi chain */
	COMM_F_CLP                          = 1U << 1,   /**< Attribute negotiation, clp */
	COMM_F_CHANNEL_DETECT               = 1U << 2,   /**< Attribute negotiation, channel detect */
	COMM_F_MBOX_SEGMENT                 = 1U << 3,   /**< Attribute negotiation, mbox */
	COMM_F_CMDQ_NUM                     = 1U << 4,   /**< Attribute negotiation, cmdq */
	COMM_F_VIRTIO_VQ_SIZE               = 1U << 5,   /**< Attribute negotiation, vio vq size */
	COMM_F_EXTEND_CAP                   = 1U << 6,   /**< Attribute negotiation, capability set extension */
	COMM_F_SMF_CACHE_INVALID            = 1U << 7,   /**< Attribute negotiation, cache invalid */
	COMM_F_ONLY_ENHANCE_CMDQ            = 1U << 8,   /**< Attribute negotiation, enhanced cmdq */
	COMM_F_USE_REAL_RX_BUF_SIZE         = 1U << 9,   /**< Attribute negotiation, use real rx buf */
	COMM_F_CMD_BUF_SIZE                 = 1U << 10,  /**< Attribute negotiation, cmd buf size */
	COMM_F_HTN_CMD                      = 1U << 11,  /**< Attribute negotiation, Hard Tile - NIC (hardware nic) */
	COMM_F_MBOX_MSG_HEAD_SUPP_VER1      = 1U << 12,  /**< Attribute negotiation, mode extension */
	COMM_F_FAST_MSG                     = 1U << 13,  /**< Attribute negotiation, fast msg */
	COMM_F_UFHD                         = 1U << 14,  /**< Attribute negotiation, Update Firmware from Host DDR - Supports DDR microcode hot upgrade */
	COMM_F_VIRTIO_FC_CACHE_MODE         = 1U << 15,  /**< Attribute negotiation, driver supports Virtio function context cache mode */
	COMM_F_NON_PTP_SYNC                 = 1U << 16,  /**< Attribute negotiation, non-ptp sync */
	COMM_F_HT_GPA                       = 1U << 17,  /**< Attribute negotiation, HT GPA (Bank GPA) */
	COMM_F_UFHD_FLEX_SEG                = 1U << 18,  /**< Attribute negotiation, UFHD adds support for segment size negotiation capability.
									This feature cannot be enabled together with the COMM_F_UFHD feature.
									To support segment size negotiation, COMM_F_EXTEND_CAP needs to be enabled. */
};

/**< mode extension version */
#define CHECK_COMM_F_SUPP_MBOX_MSG_HEAD_VER1(feature) (((feature) & COMM_F_MBOX_MSG_HEAD_SUPP_VER1) > 0)

enum {
	COMM_PLUG_SRV_NIC = 0,   /**< plug nic */
	COMM_PLUG_SRV_VROCE,     /**< plug vroce */
	COMM_PLUG_SRV_UB,        /**< plug ub */
	COMM_PLUG_SRV_BUTT,
};

#define COMM_MAX_FEATURE_QWORD 4
struct comm_cmd_feature_nego {   /**< Attribute negotiation */
	struct mgmt_msg_head head;  /**< mbox message header */

	u16 func_id;   /**< Specify function id */
	u8 opcode;    /**< 1: set, 0: get */
	u8 rsvd[5];   /**< Reserved field */
	u64 s_feature[COMM_MAX_FEATURE_QWORD];   /**< Negotiation information */
};

struct comm_cmd_clear_doorbell {   /**< Driver unload flush db */
	struct mgmt_msg_head head;   /**< mbox message header */

	u16 func_id;   /**< Specify function id */
	u16 rsvd1[3];   /**< Reserved field */
};

struct comm_cmd_clear_resource {   /**< Driver unload flush process, clear resources */
	struct mgmt_msg_head head;   /**< mbox message header */

	u16 func_id;   /**< Specify function id */
	u16 rsvd1[3];   /**< Reserved field */
};

struct comm_global_attr {   /**< Get chip global attribute information */
	u8 max_host_num;   /**< Maximum host count */
	u8 max_pf_num;   /**< Maximum pf count */
	u16 vf_id_start;   /**< Start vf id */

	u8 mgmt_host_node_id;    /**< Management host node id */
	u8 cmdq_num;   /**< cmdq count */
	u16 cmd_buf_size;   /**< cmd buff size */

	u32 rsvd2[8];   /**< Reserved field */
};

struct comm_cmd_heart_event {   /**< mbox heartbeat event between mpu and driver */
	struct mgmt_msg_head head;   /**< mbox message header */

	u8 init_sta;    /**< 0: mpu init ok, 1: mpu init error */
	u8 rsvd1[3];   /**< Reserved field */
	u32 heart;   /**< Heartbeat identifier */
	u32 heart_handshake;   /**< should be alwasys: 0x5A5A5A5A */
};

struct comm_cmd_channel_detect {   /**< Channel detect */
	struct mgmt_msg_head head;   /**< mbox message header */

	u16 func_id;   /**< Specify function id */
	u16 rsvd1[3];   /**< Reserved field 1 */
	u32 rsvd2[2];   /**< Reserved field 2 */
};

struct comm_cmd_func_svc_used_state {   /**< function usage state */
	struct mgmt_msg_head head;   /**< mbox message header */
	u16 func_id;   /**< Specify function id */
	u16 svc_type;   /**< service type (currently unused) */
	u8 used_state;   /**< Usage state */
	u8 rsvd[35];   /**<  */
};

struct comm_cmd_get_flr_info {   /**< flr dfx information */
	struct mgmt_msg_head head;   /**< mbox message header */
	u16 func_id;   /**< Specify function id */
	u8 flr_valid;   /**< flr valid bit */
	u8 flr_step;   /**< flr state machine */
	u32 flr_used_time_ms;   /**< flr elapsed time */
	u16 max_flr_time_func_id;   /**< Function with longest elapsed time */
	u32 max_flr_used_time_ms;   /**< Maximum flr elapsed time */
	u8 rsvd[30];   /**< Reserved field */
};

struct sml_table_id_info {   /**< sml table information */
	u8 node_id;   /**< Node id */
	u8 instance_id;   /**< instance id */
};

struct comm_cmd_get_sml_tbl_data {   /**< sml table content */
	struct mgmt_msg_head head;    /**<mbox message header  */
	u8 tbl_data[512];   /**< sml payload */
};

struct comm_cmd_get_glb_attr {   /**< Get chip global information */
	struct mgmt_msg_head head;   /**< mbox message header */

	struct comm_global_attr attr;   /**< Global information */
};

#define HINIC5_FW_VERSION_LEN 16   /**< version length */
#define HINIC5_FW_COMPILE_TIME_LEN 20   /**< time length */

struct comm_cmd_get_fw_version {   /**< Get firmware version number */
	struct mgmt_msg_head head;   /**< mbox message header */

	u16 fw_type;   /**< Firmware type */
	u16 fw_dfx_vld : 1;   /**< Version type, 0: release, 1: debug */
	u16 rsvd1 : 15;   /**< Reserved field */
	char ver[HINIC5_FW_VERSION_LEN];   /**< Version */
	char time[HINIC5_FW_COMPILE_TIME_LEN];   /**< Time */
};

struct cmdq_ctxt_info {   /**< hardware define: cmdq context */
	u64 curr_wqe_page_pfn;   /**< wqe page information */
	u64 wq_block_pfn;   /**< wqe address */
};

struct comm_cmd_cmdq_ctxt {   /**< Configure cmdq context */
	struct mgmt_msg_head head;   /**< mbox message header */

	u16 func_id;   /**< Specify function id */
	u8 cmdq_id;   /**< cmdq id */
	u8 rsvd1[5];   /**< Reserved field */

	struct cmdq_ctxt_info ctxt;   /**< ctx information */
};

struct enhance_cmdq_ctxt_info {   /**< hardware define: enhance cmdq context */
	u64	eq_cfg;   /**< eq cfg */
	u64	dfx_pi_ci;   /**< pointer pi ci */

	u64	pft_thd;   /**< pft thd */
	u64	pft_ci;   /**< pft ci */

	u64	rsv;   /**< Reserved field */
	u64	ci_cla_addr;   /**< cla address */
};

struct comm_cmd_enhance_cmdq_ctxt {   /**< Enhanced cmdq ctx configuration */
	struct mgmt_msg_head head;   /**< mbox message header */

	u16 func_id;   /**< Specify function id */
	u8 cmdq_id;   /**< cmdq id */
	u8 rsvd1[5];   /**< Reserved field */

	struct enhance_cmdq_ctxt_info ctxt;   /**< ctx information */
};

struct comm_cmd_virtio_en {   /**< virtio configuration after sdk loading */
	struct mgmt_msg_head head;   /**< mbox message header */
	u8 msien_snap_2_virtio_en;   /**< msien virtio enable */
	u8 rsv[3];
};

struct cqm_cmd_func_secure_mem {   /**< Secure memory information acquisition */
	struct mgmt_msg_head head;   /**< mbox message header */
	u16 func_id;   /**< Specify function id */
	u16 rsvd0;   /**< Reserved field */
	u32 gpa_hi;   /**< gpa high address */
	u32 gpa_lo;   /**< gpa low address */
	u32 len;   /**< Length */
	u8 gpa_mode;   /**< gpa mode */
	u8 valid;   /**< Valid bit */
	u8 rsvd1[2];   /**< Reserved field */
};

struct nic_plug_cap {   /**< Hot-plug capability */
	u16 max_sqs;   /**< Maximum sq size */
	u16 max_rqs;   /**< Maximum rq size */
};

struct comm_cmd_plug_srv {   /**< Hot-plug service */
	struct mgmt_msg_head head;   /**< mbox message header */
	u16 func_id;   /**< Specify function id */
	u8 srv_type;   /**< service type */
	u8 attach_en;   /**< Enable flag */
	struct nic_plug_cap nic_cap;   /**< nic hot-plug capability */
	u32 rsvd;   /**< Reserved field */
};

struct comm_cmd_fast_msg_cap {   /**< fast msg capability */
	struct mgmt_msg_head head;   /**< mbox message header */
	u32 func_id;   /**< Specify function id */
	u32 fast_msg_depth;    /**< PF:2048, VF:512 */
	u32 fast_msg_page_size;    /**< Message page size 256 (unit K) */
	u32 rsvd[9];   /**< Reserved field */
};

#define FAST_MSG_MAX_PAGE_NUM 32   /**< fast msg page count */
struct comm_cmd_fast_msg_rq_addr {
	struct mgmt_msg_head head;
	u32 func_id;
	u32 page_num;
	u32 rsvd[2];
	u64 page_addr[FAST_MSG_MAX_PAGE_NUM];
};

struct fast_msg_rq_addr {   /**< fast msg rq address */
	u64 rq_page_addr;   /**< rq page address */
};

struct comm_cmd_set_fast_msg_rq_addr {   /**< fast msg rq address setting */
	struct mgmt_msg_head head;   /**< mbox message header */
	u32 func_id;   /**< Specify function id */
	u32 page_num;   /**< Page count */
	u32 rsvd[2];   /**< Reserved field */
	struct fast_msg_rq_addr page_addr[32];   /**< Page address */
};

struct comm_cmd_clear_fast_msg_sml_table {   /**< fast msg clear table entry */
	struct mgmt_msg_head head;   /**< mbox message header */
	u32 func_id;   /**< Specify function id */
	u32 rsvd[5]; /**< Reserved field, 32 Bytes total */
};

struct comm_cmd_root_ctxt {   /**< root ctx configuration */
	struct mgmt_msg_head head;   /**< mbox message header */

	u16 func_id;   /**< Specify function id */
	u8 set_cmdq_depth;   /**< cmdq depth setting flag */
	u8 cmdq_depth;   /**< cmdq depth */
	u16 rx_buf_sz;   /**< rx buff size */
	u8 lro_en;   /**< lro enable flag */
	u8 cmdq_mode;   /**< cmdq mode */
	u16 sq_depth;   /**< sq depth */
	u16 rq_depth;   /**< rq depth */
	u32 rsvd1;   /**< Reserved field */
	u64 rsvd2;   /**< Reserved field */
};

struct comm_cmd_wq_page_size {   /**< root ctx wqe configuration */
	struct mgmt_msg_head head;   /**< mbox message header */

	u16 func_id;   /**< Specify function id */
	u8 opcode;   /**< Operation flag, 0: get, 1: set */
	u8 page_size;   /**< real_size=4KB*2^page_size, range(0~20) must be checked by driver */
	u32 rsvd1;   /**< Reserved field */
};

struct comm_cmd_msix_config {   /**< msix interrupt configuration */
	struct mgmt_msg_head head;   /**< mbox message header */

	u16 func_id;   /**< Specify function id */
	u8 opcode;   /**< Operation flag, 0: get, 1: set */
	u8 rsvd1;   /**< Reserved field */
	u16 msix_index;   /**< Interrupt idx */
	u8 pending_cnt;   /**< It specifies the maximum wait time for resending period. */
	u8 coalesce_timer_cnt;   /**< Coalescing configuration */
	u8 resend_timer_cnt;   /**< Retransmit count */
	u8 lli_timer_cnt;   /**< Credit compensation configuration */
	u8 lli_credit_cnt;   /**< Credit supplement threshold */
	u8 rsvd2[5];   /**< Reserved field */
};

struct comm_cmd_cfg_msix_num {   /**< msix interrupt count configuration */
	struct mgmt_msg_head head;    /**< mbox message header */

	u16 func_id;   /**< Specify function id */
	u8 op_code;    /**< 1: alloc 0: free */
	u8 rsvd0;   /**< Reserved field */

	u16 msix_num;   /**< msix count */
	u16 rsvd1;   /**< Reserved field */
};

struct comm_cmd_dma_attr_config {   /**< dma attribute configuration (currently unused) */
	struct mgmt_msg_head head;   /**< mbox message header */

	u16 func_id;   /**< Specify function id */
	u8 entry_idx;
	u8 st;
	u8 at;
	u8 ph;
	u8 no_snooping;
	u8 tph_en;
	u32 resv1;
};

struct comm_cmd_ppf_tbl_htrp_config {   /**< ppf hot replacement configuration */
	struct mgmt_msg_head head;   /**< mbox message header */

	u32 hotreplace_flag;   /**< Hot replacement flag */
};

struct comm_cmd_ceq_ctrl_reg {   /**< ceq configuration */
	struct mgmt_msg_head head;   /**< mbox message header */

	u16 func_id;   /**< Specify function id */
	u16 q_id;   /**< q id */
	u32 ctrl0;   /**< ceq ctrl0 */
	u32 ctrl1;   /**< ceq ctrl1 */
	u32 rsvd1;   /**< Reserved field */
};

struct comm_cmd_func_tmr_bitmap_op {   /**< Enable smf timer bitmap operation */
	struct mgmt_msg_head head;   /**< mbox message header */

	u16 func_id;   /**< Specify function id */
	u8 opcode;   /**< 1: start, 0: stop */
	u8 rsvd1[5];   /**< Reserved field */
};

struct comm_cmd_ppf_tmr_op {   /**< smf timer configuration */
	struct mgmt_msg_head head;   /**< mbox message header */

	u8 ppf_id;   /**< ppf id */
	u8 opcode;   /**< 1: start, 0: stop */
	u8 rsvd1[6];   /**< Reserved field */
};

#define HT_GPA_CLEAR 0 /**< gpa clr */
#define HT_GPA_SET 1    /**< gpa set */
struct comm_cmd_ht_gpa {    /**< gpa operation */
	struct mgmt_msg_head head; /**< mbox message header */

	u8 host_id;   /**< Specify host */
	u8 opcode;  /**< 1:set, 0: clear */
	u8 rsvd0[2];   /**< Reserved field */
	u32 rsvd1[7];   /**< Reserved field */
	u64 page_pa0;   /**< gpa address 0 */
	u64 page_pa1;   /**< gpa address 1 */
};

struct comm_cmd_get_eqm_num {   /**< mqm eqm configuration */
	struct mgmt_msg_head head;   /**< mbox message header */

	u8 host_id;   /**< Specify host */
	u8 rsvd1[3];   /**< Reserved field */
	u32 chunk_num;   /**< chunk num */
	u32 search_gpa_num;   /**< search gpa num */
};

struct comm_cmd_eqm_cfg {   /**< mqm overflow configuration */
	struct mgmt_msg_head head;   /**< mbox message header */

	u8 host_id;   /**< Specify host */
	u8 valid;   /**< Valid bit */
	u16 rsvd1;   /**< Reserved field */
	u32 page_size;   /**< Page size */
	u32 rsvd2;   /**< Reserved field */
};

struct comm_cmd_eqm_search_gpa {   /**< mqm search gpa configuration */
	struct mgmt_msg_head head;   /**< mbox message header */

	u8 host_id;   /**< Specify host */
	u8 rsvd1[3];   /**< Reserved field */
	u32 start_idx;   /**< Start idx */
	u32 num;   /**< Count */
	u32 rsvd2;   /**< Reserved field */
	u64 gpa_hi52[0];   /**< gpa */
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

struct hinic5_board_info {   /**< Get board card information */
	u8 board_type;   /**< Board card type */
	u8 port_num;   /**< Network port count */
	u8 port_speed;   /**< Board card speed */
	u8 host_width;   /**< Network port bandwidth */
	u8 host_num;   /**< Supported host count */
	u8 pf_num;   /**< Supported pf count */
	u16 vf_total_num;   /**< Supported vf count */
	u8 tile_num;   /**< Supported tile count */
	u8 qcm_num;   /**< Supported qcm count */
	u8 core_num;   /**< Supported tile core count */
	u8 work_mode;   /**< Board card work mode */
	u8 service_mode;   /**< Board card supported service mode */
	u8 board_mode;   /**< Board card mode */
	u8 boot_sel;   /**< Boot mode */
	u8 board_id;   /**< Board card id */
	u32 cfg_addr;   /**< Configuration file address */
	u32 service_en_bitmap;   /**< service enable feature */
	u8 scenes_id;   /**< Scene id */
	u8 cfg_template_id;   /**< Configuration template id */
	u8 hardware_id;   /**< Hardware id */
	u8 spu_en;   /**< spu enable flag */
	u16 pf_vendor_id;   /**< Device vendor id */
	u8 tile_bitmap;   /**< tile enable bitmap */
	u8 sm_bitmap;   /**< sm enable bitmap */
	u8 smf_bitmap_hi; /**< Save high 4bit of smf */
	u8 board_type_hi; /**< Save high 8bit of board_type */
	u8 host_type : 2; /**< Value refers to BUS_TYPE_E 0 : pcie, 1 : ubc */
	u8 pg_grade : 2; /**< Value refers to PARTIAL_GOOD_GRADE_MODE, 0 : fg, 1 : pg */
	u8 rsvd0 : 4;
	u8 rsvd;
	u32 service_en_bitmap2; /**< service enable feature extension */
};

struct comm_cmd_board_info {   /**< Get board card information */
	struct mgmt_msg_head head;   /**< mbox message header */

	struct hinic5_board_info info;   /**< Board card information */
	u32 rsvd[20];   /**< Reserved field */
};

struct comm_cmd_sync_time {   /**< Driver time sync */
	struct mgmt_msg_head head;   /**< mbox message header */

	u64 mstime;   /**< Timestamp */
	u64 sync_time;
};

struct comm_cmd_sdi_info {   /**< Get sdi information */
	struct mgmt_msg_head head;   /**< mbox message header */
	u32 cfg_sdi_mode;   /**< Configure sdi mode */
};

enum tool_run_env {
	TOOL_RUN_ENV_HOST,   /**< host side */
	TOOL_RUN_ENV_SPU,   /**< spu side */
	TOOL_RUN_ENV_INVALID = 0xFF
};
typedef u8 tool_run_env_u8;

enum chip_ver {
	CHIP_VER_HI1823V100,   /**< Chip 1823v100 */
	CHIP_VER_HI1823EV100,   /**< Chip 1823v100e */
	CHIP_VER_HI1823V200,   /**< Chip 1823v200 */
	CHIP_VER_HI1872V100,   /**< Chip 1872v100 */
	CHIP_VER_HI1825V100,   /**< Chip 1825v100 */
	CHIP_VER_INVALID = 0xFF
};
typedef u8 chip_ver_u8;   /**< Chip version */

enum chip_type {
	CHIP_TYPE_FPGA,   /**< Chip fpga */
	CHIP_TYPE_ASIC,   /**< Chip asic */
	CHIP_TYPE_EMU,   /**< Chip emu */
	CHIP_TYPE_EDA,   /**< Chip eda */
	CHIP_TYPE_INVALID = 0xFF
};
typedef u8 chip_type_u8;   /**< Chip platform */

struct comm_cmd_compatible_info {   /**< huoq environment information */
	struct mgmt_msg_head head;   /**< mbox message header */
	chip_ver_u8 chip_ver;     /**< Chip version */
	tool_run_env_u8 host_env;    /**< host type */
	chip_type_u8 chip_type;   /**< Chip type/platform */
	u8 dual_die_flag;   /**< Dual-die enable flag 0: no (single die), 1: yes (dual die) */
	u32 mpu_ver;   /**< mpu version */
	u32 npu_ver;   /**< Microcode version */
	u32 rsv1[31];   /**< Reserved field */
};

/* func flr set */
struct comm_cmd_func_flr_set {   /**< Set function flr type */
	struct mgmt_msg_head head;   /**< mbox message header */

	u16 func_id;   /**< Specify function id */
	u8 type;    /**< 1: close set flush */
	u8 isall;   /**< Whether to operate all vfs under corresponding pf 1: all vf */
	u32 rsvd;
};

struct comm_cmd_bdf_info {   /**< Get bdf number */
	struct mgmt_msg_head head;   /**< mbox message header */

	u16 function_idx;   /**< Specify function id */
	u8 rsvd1[2];   /**< Reserved field */
	u8 bus;   /**< Bus number */
	u8 device;   /**< Device number */
	u8 function;   /**< function number */
	u8 rsvd2[5];   /**< Reserved field */
};

struct hw_pf_info {   /**< Hardware pf information */
	u16 glb_func_idx;   /**< Global function id */
	u16 glb_pf_vf_offset;   /**< Start vf id of this pf */
	u8 p2p_idx;   /**< p2p idx */
	u8 itf_idx;   /**< host id */
	u16 max_vfs;   /**< vf count */
	u16 max_queue_num;   /**< Queue count */
	u16 vf_max_queue_num;   /**< Queue count supported by vf */
	u16 port_id;   /**< Network port id */
	u16 rsvd0;   /**< Reserved field */
	u32 pf_service_en_bitmap;   /**< service en of pf */
	u32 vf_service_en_bitmap;   /**< service en of vf */
	u16 rsvd1[2];   /**< Reserved field */

	u8 device_type;   /**< Device type */
	u8 bus_num;      /**< Bus number */
	u16 vf_stride;    /**< vf stride */
	u16 vf_offset;   /**< vf relative offset */
	u8 func_valid_map : 2;    /**< 0: present all functions, 1: present odd functions, 2: present even functions, 3: invalid value */
	u8 rsvd2 : 6;   /**< Reserved field */
	u8 rsvd;   /**< Reserved field */
};

#define CMD_MAX_MAX_PF_NUM 32   /**< Maximum pf count */
struct hinic5_hw_pf_infos {   /**< Hardware pf information */
	u8 num_pfs;   /**< pf count */
	u8 rsvd1[3];   /**< Reserved field */

	struct hw_pf_info infos[CMD_MAX_MAX_PF_NUM];   /**< Hardware pf information */
};

struct comm_cmd_hw_pf_infos {   /**< Hardware pf information */
	struct mgmt_msg_head head;   /**< mbox message header */

	struct hinic5_hw_pf_infos infos;   /**< pf information */
};

#define DD_CFG_TEMPLATE_MAX_IDX 12   /**< Supported configuration template count */
#define DD_CFG_TEMPLATE_MAX_TXT_LEN 64   /**< Supported configuration template size */
#define CFG_TEMPLATE_OP_QUERY 0   /**< Query configuration template */
#define CFG_TEMPLATE_OP_SET 1   /**< Set configuration template */
#define CFG_TEMPLATE_SET_MODE_BY_IDX 0
#define CFG_TEMPLATE_SET_MODE_BY_NAME 1

struct comm_cmd_cfg_template {   /**< Configuration version configuration */
	struct mgmt_msg_head head;   /**< mbox message header */
	u8 opt_type;    /**< 0: query  1: set */
	u8 set_mode;    /**< 0-index mode. 1-name mode. */
	u8 tp_err;   /**< Template error flag */
	u8 rsvd0;   /**< Reserved field */

	u8 cur_index;      /**< Current cfg tempalte index. */
	u8 cur_max_index;    /**< Max support cfg tempalte index. */
	u8 rsvd1[2];   /**< Reserved field */
	u8 cur_name[DD_CFG_TEMPLATE_MAX_TXT_LEN];   /**< Current template name */
	u8 cur_cfg_temp_info[DD_CFG_TEMPLATE_MAX_IDX][DD_CFG_TEMPLATE_MAX_TXT_LEN];   /**< Current template information */

	u8 next_index;     /**< Next reset cfg tempalte index. */
	u8 next_max_index;    /**< Max support cfg tempalte index. */
	u8 rsvd2[2];   /**< Reserved field */
	u8 next_name[DD_CFG_TEMPLATE_MAX_TXT_LEN];   /**< Next template name */
	u8 next_cfg_temp_info[DD_CFG_TEMPLATE_MAX_IDX][DD_CFG_TEMPLATE_MAX_TXT_LEN];   /**< Next template information */
};

#define MQM_SUPPORT_COS_NUM 8   /**< cos count */
#define MQM_INVALID_WEIGHT 256   /**< mqm table size */
#define MQM_LIMIT_SET_FLAG_READ 0   /**< read */
#define MQM_LIMIT_SET_FLAG_WRITE 1   /**< write */
struct comm_cmd_set_mqm_limit {   /**< mqm rate limit configuration */
	struct mgmt_msg_head head;   /**< mbox message header */

	u16 set_flag;   /**< Setting this flag bit means set */
	u16 func_id;   /**< Specify function id */
	u16 cos_weight[MQM_SUPPORT_COS_NUM];    /**< Weight for corresponding cos_id, 0-255, 0 for SP scheduling. */
	u32 host_min_rate;        /**< Minimum rate limit supported by this host */
	u32 func_min_rate;        /**< Minimum rate limit supported by this function, unit Mbps */
	u32 func_max_rate;          /**< Maximum rate limit supported by this function, unit Mbps  */
	u8 rsvd[64];                /**< Reserved field */
};

enum core_type_e {
	CORE_TYPE_ARM  = 0,
	CORE_TYPE_LINX = 1
};

struct arm_core_reg_info {
	u64 elr;   /**< General purpose register */
	u64 spsr;   /**< General purpose register */
	u64 far;   /**< General purpose register */
	u64 esr;   /**< General purpose register */
	u64 xzr;   /**< General purpose register */
	u64 x30;   /**< General purpose register */
	u64 x29;   /**< General purpose register */
	u64 x28;   /**< General purpose register */
	u64 x27;   /**< General purpose register */
	u64 x26;   /**< General purpose register */
	u64 x25;   /**< General purpose register */
	u64 x24;   /**< General purpose register */
	u64 x23;   /**< General purpose register */
	u64 x22;   /**< General purpose register */
	u64 x21;   /**< General purpose register */
	u64 x20;   /**< General purpose register */
	u64 x19;   /**< General purpose register */
	u64 x18;   /**< General purpose register */
	u64 x17;   /**< General purpose register */
	u64 x16;   /**< General purpose register */
	u64 x15;   /**< General purpose register */
	u64 x14;   /**< General purpose register */
	u64 x13;   /**< General purpose register */
	u64 x12;   /**< General purpose register */
	u64 x11;   /**< General purpose register */
	u64 x10;   /**< General purpose register */
	u64 x09;   /**< General purpose register */
	u64 x08;   /**< General purpose register */
	u64 x07;   /**< General purpose register */
	u64 x06;   /**< General purpose register */
	u64 x05;   /**< General purpose register */
	u64 x04;   /**< General purpose register */
	u64 x03;   /**< General purpose register */
	u64 x02;   /**< General purpose register */
	u64 x01;   /**< General purpose register */
	u64 x00;   /**< General purpose register */
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
	u32 rsv[39];   /**< The total size of this struct is consistent with struct arm_core_reg_info */
};

#define DATA_LEN_1K 1024
struct comm_info_sw_watchdog {   /**< Software watchdog timeout information report interface */
	struct mgmt_msg_head head;   /**< mbox message header */

	/**< Global information */
	u32 curr_time_h;    /**< Time of infinite loop, cycle */
	u32 curr_time_l;    /**< Time of infinite loop, cycle */
	u32 task_id;       /**< Task of infinite loop       */
	u8 core_type;     /**< Refer to core_type_e definition   */
	u8 rsv[3];        /**< Reserved field, for extension     */

	/**< Register information, TSK_CONTEXT_S */
	u64 pc;   /**< General purpose register */

	union core_reg {
		struct arm_core_reg_info  arm_reg;
		struct linx_core_reg_info linx_reg;
	} reg_info;

	/**< Stack control information, STACK_INFO_S */
	u64 stack_top;    /**< Stack top                   */
	u64 stack_bottom;    /**< Stack bottom                   */
	u64 sp;      /**< Current SP pointer value of stack         */
	u32 curr_used;      /**< Current stack usage size       */
	u32 peak_used;       /**< Historical peak stack usage       */
	u32 is_overflow;       /**< Whether stack overflows             */

	/**< Specific stack content */
	u32 stack_actlen;      /**< Actual stack length (<=1024) */
	u8 stack_data[DATA_LEN_1K];    /**< Part exceeding 1024 will be truncated */
};

/**< Last word information */
#define XREGS_NUM 31   /**< Register count */
typedef struct tag_cpu_tick {   /**< Time */
	u32 cnt_hi;    /**<  cycle count high 32 bits */
	u32 cnt_lo;   /**< cycle count low 32 bits */
} CPU_TICK;

typedef struct tag_ax_exc_reg_info {   /**< General purpose register */
	u64 ttbr0;   /**< General purpose register */
	u64 ttbr1;   /**< General purpose register */
	u64 tcr;   /**< General purpose register */
	u64 mair;   /**< General purpose register */
	u64 sctlr;   /**< General purpose register */
	u64 vbar;   /**< General purpose register */
	u64 current_el;   /**< General purpose register */
	u64 sp;   /**< General purpose register */
	/**< The memory layout of the following fields is consistent with TskContext */
	u64 elr;      /**< General purpose register */
	u64 spsr;   /**< General purpose register */
	u64 far_r;   /**< General purpose register */
	u64 esr;   /**< General purpose register */
	u64 xzr;   /**< General purpose register */
	u64 xregs[XREGS_NUM];    /**< Registers 0~30: x30~x0 */
} EXC_REGS_S;

typedef struct exc_call_stack_info {
	u32 depth;  /* Call stack depth */
	u64 addrList[10];  /* Call stack address list */
	char nameList[10][64];  /* Call stack function name list */
} exc_call_stack_info_s;

typedef struct tag_exc_info {
	char os_ver[48];     /**< OS version number                                         */
	char app_ver[64];    /**< Product version number                                       */
	u32 exc_cause;     /**< Exception cause                                         */
	u32 thread_type;    /**< Thread type before exception                                 */
	u32 thread_id;      /**< Thread PID before exception                                    */
	u16 byte_order;     /**< Byte order                                           */
	u16 cpu_type;     /**< CPU type                                          */
	u32 cpu_id;       /**< CPU ID                                           */
	CPU_TICK cpu_tick;   /**< CPU Tick                                         */
	u32 nest_cnt;      /**< Exception nesting count                                     */
	u32 fatal_errno;     /**< Fatal error code, valid when fatal error occurs                    */
	u64 uw_sp;         /**< Stack pointer before exception                                     */
	u64 stack_bottom;    /**< Stack bottom before exception     */
	/**< On-chip register context information when exception occurs, 82\57 must be located at 152 bytes, if changed, need to update OS_EXC_REGINFO_OFFSET macro in sre_platform.eh */
	EXC_REGS_S reg_info;
} EXC_INFO_S;

typedef struct tag_exc_info_all {
	char os_ver[48];     /**< OS version number                                         */
	char app_ver[64];    /**< Product version number                                       */
	u32 exc_cause;     /**< Exception cause                                         */
	u32 thread_type;    /**< Thread type before exception                                 */
	u32 thread_id;      /**< Thread PID before exception                                    */
	u16 byte_order;     /**< Byte order                                           */
	u16 cpu_type;     /**< CPU type                                          */
	u32 cpu_id;       /**< CPU ID                                           */
	CPU_TICK cpu_tick;   /**< CPU Tick                                         */
	u32 nest_cnt;      /**< Exception nesting count                                     */
	u32 fatal_errno;     /**< Fatal error code, valid when fatal error occurs                    */
	u64 uw_sp;         /**< Stack pointer before exception                                     */
	u64 stack_bottom;    /**< Stack bottom before exception     */
	/**< On-chip register context information when exception occurs, 82\57 must be located at 152 bytes, if changed, need to update OS_EXC_REGINFO_OFFSET macro in sre_platform.eh */
	EXC_REGS_S reg_info;
	exc_call_stack_info_s call_stack_info;
} EXC_INFO_ALL_S;

#define MPU_LASTWORD_SIZE 1024   /**< Last word single data length */
typedef struct tag_comm_info_up_lastword {   /**< up lastword module interface reported to driver */
	struct mgmt_msg_head head;   /**< mbox message header */

	EXC_INFO_S stack_info;   /**< Stack information */

	/* Specific stack content */
	u32 stack_actlen;   /**<Actual stack length (<=1024) */
	u8 stack_data[MPU_LASTWORD_SIZE];    /**< payload exceeding 1024 will be truncated */
} comm_info_up_lastword_s;

typedef struct {
	u32 magic;
	u32 symbol_num;  /**< Symbol count */
	u32 code_size;  /**< Patch code size */
	u32 rsvd0[5];  /**< Reserved field */
	char git_tag[64]; /**< Cold baseline git tag */
	char compile_time[20]; /**< Compile time */
	u32 rsvd1;  /**< Reserved field for 8-byte alignment */
} patch_head_info_s;

struct hinic5_cmd_activate_firmware {   /**< Image activation */
	struct mgmt_msg_head msg_head;   /**< mbox message header */
	u8 index;    /**< Configuration file activation idx (default 0) */
	u8 data[7];   /**< payload */
};

struct hinic5_cmd_switch_config {   /**< Configuration file switch */
	struct mgmt_msg_head msg_head;   /**< mbox message header */
	u8 index;    /**< Configuration file idx0~1 */
	u8 data[7];   /**< payload */
};

/* start To adapt to ub register access, defined id used to identify UB module in interface, cannot conflict with INTERNAL_RING_NODE_ID_E */
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
/* end To adapt to ub register access, defined node id used to identify UB module in interface, cannot conflict with INTERNAL_RING_NODE_ID_E */

#define MAX_DATA_NUM     (240)
struct csr_msg {   /**< csr register read information */
	struct {
		u32 node_id             : 5;        /**< Node id */
		u32 data_width          : 10;       /**< Access width */
		u32 module_id           : 8;        /**< Module id, used to identify which module the address belongs to (some modules have no node_id) */
		u32 rsvd                : 9;        /* Reserved field */
	} bits;
	u32 addr;   /**< Address */
};

struct comm_cmd_mbox_csr_rd_req {   /**< csr register read request */
	struct mgmt_msg_head head;   /**< mbox message header */
	struct csr_msg csr_info[MAX_DATA_NUM];   /**< payload */
	u32 data_num;   /**< Register count */
};

struct comm_cmd_mbox_csr_rd_ret {   /**< csr register read */
	struct mgmt_msg_head head;   /**< mbox message header */
	u64 value[MAX_DATA_NUM];   /**< Register read result */
};

struct comm_cmd_mbox_csr_rd_req_ex {   /**< csr register read request */
	struct mgmt_msg_head head;   /**< mbox message header */
	u32 data_num;   /**< Register count */
	struct csr_msg csr_info[0];    /**< Filled according to actual read count */
};

struct comm_cmd_mbox_csr_rd_ret_ex {   /**< csr register read */
	struct mgmt_msg_head head;   /**< mbox message header */
	u64 value[0];    /**< Filled according to actual read count */
};

struct comm_cmd_mbox_csr_wt_req {   /**< csr register write */
	struct mgmt_msg_head head;   /**< mbox message header */
	struct csr_msg csr_info;   /**< csr control register information */
	u64 value;   /**< Value */
};

struct comm_cmd_mbox_csr_wt_ret {   /**< csr register write */
	struct mgmt_msg_head head;   /**< mbox message header */
};

#define INDIR_MAX_INDEX_NUM 480
#define INDIR_MAX_WT_INDEX_NUM 32

struct comm_cmd_mbox_indir_addr {   /**< Indirect table operation information */
	u32 indir_ctrl_addr;   /**< Control register */
	u32 indir_timeout_addr;   /**< Timeout register */
	u32 indir_data_addr;   /**< Data register */
};

struct comm_cmd_mbox_indir_tab_rd_req {   /**<  Indirect table read request */
	struct mgmt_msg_head head;   /**< mbox message header */

	struct comm_cmd_mbox_indir_addr indir_addr;   /**< Indirect table control information */
	u32 tab_width;   /**< Table entry width */
	u32 index_num;   /**< offset idx */
	u32 index[INDIR_MAX_INDEX_NUM];   /**< payload */
};

struct comm_cmd_mbox_indir_tab_rd_ret {   /**< Indirect table read request */
	struct mgmt_msg_head head;   /**< mbox message header */
	u32 data[INDIR_MAX_INDEX_NUM];   /**< payload */
};

struct comm_cmd_mbox_indir_tab_wt_req {   /**< Indirect table write request */
	struct mgmt_msg_head head;   /**< mbox message header */

	struct comm_cmd_mbox_indir_addr indir_addr;   /**< Indirect table control information */
	u32 tab_width;   /**< Table entry width */
	u32 index;   /**< offset idx */
	u32 data[INDIR_MAX_WT_INDEX_NUM];   /**< payload */
};

struct comm_cmd_mbox_indir_tab_wt_ret {   /**< Indirect table write request */
	struct mgmt_msg_head head;   /**< mbox message header */
};

// Restore factory flash cleanup directory
enum {
	MPU_LOG_CLEAR = 0,         /**< Clear mpu log */
	SMU_LOG_CLEAR,             /**< Clear smu log */
	NPU_LOG_CLEAR,             /**< Clear npu log */
	SPU_LOG_CLEAR,             /**< Clear spu log */
	MPU_LASTWORD_CLEAR,        /**< Clear mpu last word */
	NPU_LASTWORD_CLEAR,        /**< Clear microcode last word */
	ALL_LOG_CLEAR,             /**< Clear all logs & last words */
	UBC_IMP_LOG_CLEAR,         /**< Clear ubc imp log */
	UBC_IMP_LASTWORD_CLEAR,    /**< Clear ubc imp last word */
	ROCE_IMP_LOG_CLEAR,        /**< Clear roce imp log */
	ROCE_IMP_LASTWORD_CLEAR,   /**< Clear roce imp last word */
	ROCE_SCC_LOG_CLEAR,        /**< Clear roce scc log */
	CLEAR_TYPE_BUTT,           /**< Clear all flash */
};

struct comm_cmd_clear_flash {   /**< Clear flash */
	struct mgmt_msg_head head;    /**< mbox message header */
	u32 type;   /**< Clear log type */
};

struct cmd_sector_info {   /**< Erase flash */
	struct mgmt_msg_head head;    /**< mbox message header */
	u32 offset;                   /**< flash address */
	u32 len;                       /**< flash erase length */
};

enum flash_counter_info_req_type {
	FLASH_COUNTER_TYPE_GET_MPU_SIZE,   /**< mpu counter size acquisition type */
	FLASH_COUNTER_TYPE_GET_MPU_DATA,   /**< mpu counter data acquisition type */
	FLASH_COUNTER_TYPE_GET_NPU_SIZE,   /**< npu counter size acquisition type */
	FLASH_COUNTER_TYPE_GET_NPU_DATA,   /**< npu counter data acquisition type */
	FLASH_COUNTER_TYPE_INVALID   /**< counter acquisition type invalid value */
};

struct flash_counter_info_req {   /**< Get firmware counter information */
	struct mgmt_msg_head head;   /**< mbox message header */
	u8 type;    /**< flash_counter_info_req_type */
	u8 rsv[3];   /**< Reserved field */
	u32 offset;   /**< Address offset */
	u32 length;   /**< Data length */
};

#define FLASH_COUNTER_TYPE_GET_DATA_MAX_SIZE 1024
struct flash_counter_info_resp {   /**< Get firmware counter information */
	struct mgmt_msg_head head;   /**< mbox message header */
	u32 length;   /**< Data length */
	u8 data[FLASH_COUNTER_TYPE_GET_DATA_MAX_SIZE];   /**< payload */
};

typedef struct {
	u64 smu_images;   /**< smu image */
	u64 mpu_images;   /**< mpu image */
	u64 npu_images;   /**< npu image */
	u64 ppe_images;   /**< Microcode ppe image */
	u64 cfg_images;   /**< Configuration file image */
	u64 patch_images;   /**< mpu patch image */
	u64 rsvd[4];   /**< Reserved field */
} module_images;   /**< Firmware image type */

typedef struct {
	struct mgmt_msg_head head;   /**< mbox message header */
	u32 rsvd[4];   /**< Reserved field */
} comm_cmd_query_module_images_req;   /**< Query image type */

typedef struct {
	struct mgmt_msg_head head;   /**< mbox message header */
	module_images img;   /**< Firmware image */
} comm_cmd_query_module_images_rsp;   /**< Query image type */

#define SINGLE_EFUSE_BIN_SIZE 512
#define SEND_EFUSE_DATA_SIZE (SINGLE_EFUSE_BIN_SIZE * 3)
struct send_efuse_data_s {   /**< efuse information burning */
	struct mgmt_msg_head head;     /**< mbox message header */
	u8 opt_type;                 /**< efuse operation type: 1: burn efuse bin, 2: hw rotpk switch to guest rotpk */
	u8 rsvd0[3];   /**< Reserved field */
	u32 total_len;    /**< entire package leng value */
	u32 data_csum;    /**< entire package data count sum value */
	u8 data[SEND_EFUSE_DATA_SIZE];    /**<  payload 1024B*/
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
	u16 sel;      /**< Direction: 0 - tx 1 - rx */
	u16 write;    /**< Read/write flag: 0 - read 1 - write */
	u32 reg_addr; /**< Register address */
	u32 reg_cnt;  /**< With reg_addr as BASE_ADDR, how many consecutive registers to read (not bytes, but register count), maximum 32 */
	u32 clear;    /**< Read-clear flag: 0 - no read-clear 1 - read-clear (this parameter is invalid for write operations) */
	u32 data[DFX_MAG_MAX_REG_NUM]; /**< Returned data, up to DFX_MAG_MAX_REG_NUM, indicates actual valid data count based on reg_cnt */
};

#define UPDATE_CMD_HEAD_NEW_VERSION 0x1  // Tool-issued duplicate packet command version

/**< Firmware upgrade error code definition */
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

/* Hot activation type */
typedef enum {
	HOT_ACTIVE_NONE = 0,
	HOT_ACTIVE_MPU = 1,
	HOT_ACTIVE_NPU = 2,
	HOT_ACTIVE_MNPU = 3,
	HOT_ACTIVE_SCC = 4,
} hot_active_type_e;

/* MPU hot activation type */
typedef enum {
	MPU_HOT_ACTIVE_NONE,  /**< No hot upgrade yet */
	MPU_HOT_ACTIVE_PATCH,  /**< Hot patch */
	MPU_HOT_ACTIVE_REPLACE,  /**< Hot replacement */
} mpu_hot_active_type_e;

struct cmd_hot_active_fw {   /**< Hot upgrade activation */
	struct mgmt_msg_head head;     /**< mbox message header */
	u8 type;                      /**< Activate sub-firmware type, 1: mpu; 2: ucode; 3: mpu & npu */
	u8 mpu_hot_active_type;     /**< MPU hot activation type, valid when type is MPU or MNPU */
	u8 data[6];                  /**< Reserved field */
};

struct cmd_bat_set_info {   /**< Hot upgrade bat table entry operation transition information */
	struct mgmt_msg_head head;   /**< mbox message header */

	u16 func_id;   /**< Specify function id */
	u8  smf_id;   /**< smf idx */
	u8  rsvd1;   /**< Reserved field */
	u32 bat_offset;   /**< bat offset */
	u32 data_size;   /**< Data size */
	u8  data[256];   /**< payload */
};

/* Read dbf information */
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
	u8 host_id;  /* Container home host, range 0 ~ 3 */
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
	u32 vf_num; /**< vf num */
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
	u8 rsvd[3];                   /* Reserved */
	u8 psm_en;
	char mpu_git_code[64];      /* git number and compile time, up to 60 characters */
	char psm_git_code[PSM_GIT_CHAR_NUM + 1];      /* psm git number and compile time, up to 20 characters */
	u8 rsvd1[3];                /* Reserved */
};

/* Disable chip auto reset */
struct comm_cmd_enable_auto_rst_chip {
	struct mgmt_msg_head head;

	u8 op_code; /* 0: get  1: set */
	u8 enable; /* 1: Enable auto reset chip; 0: Disable auto reset chip */
	u8 rsvd[2];
};

/* Chip core temperature struct definition */
struct comm_temp_in_info {
	struct mgmt_msg_head head; /* 8B */
	u8 opt_type;                /* 0:read operation 1:cfg operation */
	u8 rsv[3];
	s32 max_temp; /* Chip core temperature threshold */
	s32 min_temp; /* Chip core temperature threshold */
};

struct comm_temp_out_info {
	struct mgmt_msg_head head; /* 8B */
	s32 temp_data;             /* Read temperature */
	s32 max_temp_threshold;    /* Chip core temperature threshold */
	s32 min_temp_threshold;    /* Chip core temperature threshold */
	s32 max_temp;              /* Chip core temperature historical maximum */
	s32 min_temp;              /* Chip core temperature historical minimum */
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
	u32 smf_id_valid;            // Whether the passed-in smf_id is valid
} comm_cmd_root_ctx_load_req_s;

typedef struct {
	struct mgmt_msg_head head;
	u8 rq_ctx[RQ_CXT_SIZE];
	u8 sq_ctx[SQ_CXT_SIZE];
	u8 cmdq_ctx[CMDQ_CXT_SIZE * CMDQ_COUNT];
	u8 enhance_cmdq_ctx[ENHANCE_CMDQ_CXT_SIZE * CMDQ_COUNT];
} comm_cmd_root_ctx_load_ret_s;

struct cmd_query_fw {
	struct mgmt_msg_head head; // 8B
	u32 offset;                 // Offset, since the returned information is large, multiple returns are needed
	u32 len;                    // Data length to read
};

#define MAX_CMD_DATA_LEN (1024 + 512)
struct cmd_fw_info {
	struct mgmt_msg_head head; // 8B
	u32 len;                    // Actual data length read back
	u8 data[MAX_CMD_DATA_LEN];  // Read up to 1536 bytes of data at a time
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
	u32 cpl_tx_left_Tag;
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
#define BIT_COS_MASK 3

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
	u8 pf_bar_index;    /**< 0-3 */
	u8 vf_bar_index;    /**< 0,2,4 */
	u8 pf_bar_set_flag;
	u8 vf_bar_set_flag;
	u32 bar_mode;       /**< temp: 0 in tool, 0xFFFFFFFF in flash ; permanently: 1 in tool, 0x1 in flash */
	u32 pf_bar_size[CFG_BAR_INDEX_NUM];
	u32 vf_bar_size[CFG_BAR_INDEX_NUM];
} mpu_nic_bar;

struct comm_cmd_cfg_data {
	struct mgmt_msg_head head;
	u8 opt_type; /**< operation type 0: query 1: set 2: clear 4: bar set 5: bar clear */
	u8 pf_index; /**< pf index */
	u8 queue_bitmap; /**< 0: pf_sq_rq 1: vf_sq_rq 2: vf_num 3: cos_mask */
	u8 pf_num;  /**< Number of PFs with the NIC feature enabled. */
	u16 pf_sq_rq;   /** Number of configured PF queues. */
	u16 vf_sq_rq;   /** Number of configured VF queues. */
	u16 vf_num;     /** Number of configured VFs. */
	u16 total_queue_num;     /** Total number of queues of all functions. */
	u8 is_set_diff_template;    /** Whether the template is switched. */
	u8 cos_mask;    /** Currently active cos_mask. Determine the COS allocation for NIC and RoCE */
	u8 next_cos_mask;   /** Next active cos_mask after reboot. */
	u8 rsvd0;
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
	u8 type; // Refer to voltage_type_e
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
 * Semaphore type.
 */
typedef enum {
	RTOS_SEM_TYPE_COUNT, /* Counting semaphore */
	RTOS_SEM_TYPE_BIN, /* Binary semaphore */
	RTOS_SEM_TYPE_BUTT
} rtos_sem_type_e;

/*
 * @ingroup OS_sem
 * Wakeup method for blocked threads in the semaphore module.
 */
typedef enum {
	RTOS_SEM_MODE_FIFO,  // Semaphore FIFO wakeup mode
	RTOS_SEM_MODE_PRIOR, // Semaphore priority wakeup mode
	RTOS_SEM_MODE_BUTT   // Semaphore invalid wakeup method
} rtos_sem_mode_e;

typedef struct {
	u32 count;
	u32 owner;
	u16 sem_id;
	u8 mode; // Semaphore wakeup mode
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
	RESTORE_SET_TYPE_SWITCH = 0,  // Start switch partition flag bit
	RESTORE_SET_TYPE_RESET, // Auto reset flag bit after switch partition
	RESTORE_SET_TYPE_FAIL_COUNT, // Set SDK load failure detection count
	RESTORE_SET_TYPE_TIMEOUT, // Set SDK load timeout
	RESTORE_SET_TYPE_BUTT
} fw_restore_set_e;

struct cmd_chip_switch_reset {
	struct mgmt_msg_head head;
	u8 op_code; /* 0: set  1: get */
	u8 type; /* fw_restore_set_e, reused as fail_count return value when reading */
	u8 value; /* Value to be set, reused as switch&reset return value when reading */
	u8 read_value; /* Only used when reading, as timeout return value */
};

/* integrity */
#define GRAY_INFO_MAGIC_NUM 0xc380f8dd
#define HASH_SIG_SIZE 512
#define KEY_HASH_SIZE 32
#define PUBKEY_SIZE 1024
#define INTEGERITY_VERIFY_ENABLE 0x5A /* Use magic number to indicate integrity verification enabled */
typedef enum {
	INTEGERITY_CMD_ENABLE = 0,
	INTEGERITY_CMD_UPDATE,
	INTEGERITY_CMD_DISABLE,
	INTEGERITY_CMD_MAX,
} integrity_cmd_type;

typedef struct {
	u8 integrity_type;          /* User firmware integrity protection switch */
	u8 rsvd[3];                 /* Reserved field*/
	u8 key_hash[KEY_HASH_SIZE]; /* Customer root public key hash value */
	u8 pubkey[PUBKEY_SIZE];
	u8 keysig[HASH_SIG_SIZE];
	u8 newpubkey[PUBKEY_SIZE];
	u8 newkeysig[HASH_SIG_SIZE]; /* Signature file used for update operation */
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

/**
 * @brief struct cmd_update_fw - Firmware upgrade command data structure
 * @details Tool data length is 1536 (1.5K), tool sends up to 2K, including header
 */
struct cmd_update_fw {
	struct mgmt_msg_head head;  /**< Message header */
	u16 last_slice : 1;         /**< Whether it is the tail slice */
	u16 first_slice : 1;        /**< Whether it is the first slice */
	u16 force_update : 1;       /**< Force upgrade flag, if set to 1, vendor_id and board_type are not checked */
	u16 is_signed : 1;          /**< Signature flag */
	u16 repeat : 1;             /**< Slice operation Flash flag */
	u16 update_main_area : 1;   /**< Upgrade main area flag */
	u16 rsvd : 10;              /**< Reserved field */
	u16 slice_len;              /**< Current slice length, in bytes */
	u32 fw_crc;                 /**< CRC */
	u32 fw_type;                /**< Sub-firmware type, refer to #up_fw_update_type_e */
	u32 bin_total_len;          /**< Sub-firmware total length */
	u32 bin_section_len;        /**< data length */
	u32 fw_verion;              /**< Sub-firmware version number */
	u32 fw_offset;              /**< Offset of this slice in sub-firmware */
	u32 data[384];              /**< Sub-firmware data */
};

/**
 * @brief struct cmd_cold_active_fw - Cold activation command data structure
 */
struct cmd_cold_active_fw {
	struct mgmt_msg_head head;  /**< Message header */
	u8 index;                   /**< Configuration file index, fixed to 0 */
	u8 update_main_area;        /**< Upgrade main area flag */
	u8 data[6];                 /**< Reserved */
};

#endif