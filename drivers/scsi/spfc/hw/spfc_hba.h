/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef SPFC_HBA_H
#define SPFC_HBA_H

#include "unf_type.h"
#include "unf_common.h"
#include "spfc_queue.h"
#include "sphw_crm.h"
#define SPFC_PCI_VENDOR_ID_MASK (0xffff)

#define FW_VER_LEN (32)
#define HW_VER_LEN (32)
#define FW_SUB_VER_LEN (24)

#define SPFC_LOWLEVEL_RTTOV_TAG 0
#define SPFC_LOWLEVEL_EDTOV_TAG 0
#define SPFC_LOWLEVEL_DEFAULT_LOOP_BB_CREDIT (8)
#define SPFC_LOWLEVEL_DEFAULT_32G_BB_CREDIT (255)
#define SPFC_LOWLEVEL_DEFAULT_16G_BB_CREDIT (255)
#define SPFC_LOWLEVEL_DEFAULT_8G_BB_CREDIT (255)
#define SPFC_LOWLEVEL_DEFAULT_BB_SCN 0
#define SPFC_LOWLEVEL_DEFAULT_RA_TOV UNF_DEFAULT_RATOV
#define SPFC_LOWLEVEL_DEFAULT_ED_TOV UNF_DEFAULT_EDTOV

#define SPFC_LOWLEVEL_DEFAULT_32G_ESCH_VALUE 28081
#define SPFC_LOWLEVEL_DEFAULT_16G_ESCH_VALUE 14100
#define SPFC_LOWLEVEL_DEFAULT_8G_ESCH_VALUE 7000
#define SPFC_LOWLEVEL_DEFAULT_ESCH_BUST_SIZE 0x2000

#define SPFC_PCI_STATUS 0x06

#define SPFC_SMARTIO_WORK_MODE_FC 0x1
#define SPFC_SMARTIO_WORK_MODE_OTHER 0xF
#define UNF_FUN_ID_MASK 0x07

#define UNF_SPFC_FC (0x01)
#define UNF_SPFC_MAXNPIV_NUM 64 /* If not support NPIV, Initialized to 0 */

#define SPFC_MAX_COS_NUM (8)

#define SPFC_INTR_ENABLE 0x5
#define SPFC_INTR_DISABLE 0x0
#define SPFC_CLEAR_FW_INTR 0x1
#define SPFC_REG_ENABLE_INTR 0x00000200

#define SPFC_PCI_VENDOR_ID_RAMAXEL 0x1E81

#define SPFC_SCQ_CNTX_SIZE 32
#define SPFC_SRQ_CNTX_SIZE 64

#define SPFC_PORT_INIT_TIME_SEC_MAX 1

#define SPFC_PORT_NAME_LABEL "spfc"
#define SPFC_PORT_NAME_STR_LEN (16)

#define SPFC_MAX_PROBE_PORT_NUM (64)
#define SPFC_PORT_NUM_PER_TABLE (64)
#define SPFC_MAX_CARD_NUM (32)

#define SPFC_HBA_PORT_MAX_NUM SPFC_MAX_PROBE_PORT_NUM
#define SPFC_SIRT_MIN_RXID 0
#define SPFC_SIRT_MAX_RXID 255

#define SPFC_GET_HBA_PORT_ID(hba) ((hba)->port_index)

#define SPFC_MAX_WAIT_LOOP_TIMES 10000
#define SPFC_WAIT_SESS_ENABLE_ONE_TIME_MS 1
#define SPFC_WAIT_SESS_FREE_ONE_TIME_MS 1

#define SPFC_PORT_ID_MASK 0xff0000

#define SPFC_MAX_PARENT_QPC_NUM 2048
struct spfc_port_cfg {
	u32 port_id;	   /* Port ID */
	u32 port_mode;	   /* Port mode:INI(0x20), TGT(0x10), BOTH(0x30) */
	u32 port_topology; /* Port topo:0x3:loop,0xc:p2p,0xf:auto */
	u32 port_alpa;	   /* Port ALPA */
	u32 max_queue_depth; /* Max Queue depth Registration to SCSI */
	u32 sest_num;	     /* IO burst num:512-4096 */
	u32 max_login;	     /* Max Login Session.       */
	u32 node_name_hi;    /* nodename high 32 bits */
	u32 node_name_lo;    /* nodename low 32 bits */
	u32 port_name_hi;    /* portname high 32 bits */
	u32 port_name_lo;    /* portname low 32 bits */
	u32 port_speed;	     /* Port speed 0:auto  4:4Gbps 8:8Gbps 16:16Gbps */
	u32 interrupt_delay; /* Delay times(ms) in interrupt */
	u32 tape_support;    /* tape support */
};

#define SPFC_VER_INFO_SIZE 128
struct spfc_drv_version {
	char ver[SPFC_VER_INFO_SIZE];
};

struct spfc_card_info {
	u32 card_num : 8;
	u32 func_num : 8;
	u32 base_func : 8;
	/* Card type:UNF_FC_SERVER_BOARD_32_G(6) 32G mode,
	 * UNF_FC_SERVER_BOARD_16_G(7)16G mode
	 */
	u32 card_type : 8;
};

struct spfc_card_num_manage {
	bool is_removing;
	u32 port_count;
	u64 card_number;
};

struct spfc_sim_ini_err {
	u32 err_code;
	u32 times;
};

struct spfc_sim_pcie_err {
	u32 err_code;
	u32 times;
};

struct spfc_led_state {
	u8 green_speed_led;
	u8 yellow_speed_led;
	u8 ac_led;
	u8 rsvd;
};

enum spfc_led_activity {
	SPFC_LED_CFG_ACTVE_FRAME = 0,
	SPFC_LED_CFG_ACTVE_FC = 3
};

enum spfc_queue_set_stage {
	SPFC_QUEUE_SET_STAGE_INIT = 0,
	SPFC_QUEUE_SET_STAGE_SCANNING,
	SPFC_QUEUE_SET_STAGE_FLUSHING,
	SPFC_QUEUE_SET_STAGE_FLUSHDONE,
	SPFC_QUEUE_SET_STAGE_BUTT
};

struct spfc_vport_info {
	u64 node_name;
	u64 port_name;
	u32 port_mode; /* INI, TGT or both */
	u32 nport_id;  /* maybe acquired by lowlevel and update to common */
	void *vport;
	u16 vp_index;
};

struct spfc_srq_delay_info {
	u8 srq_delay_flag; /* Check whether need to delay */
	u8 root_rq_rcvd_flag;
	u16 rsd;

	spinlock_t srq_lock;
	struct unf_frame_pkg frame_pkg;

	struct delayed_work del_work;
};

struct spfc_fw_ver_detail {
	u8 ucode_ver[SPFC_VER_LEN];
	u8 ucode_compile_time[SPFC_COMPILE_TIME_LEN];

	u8 up_ver[SPFC_VER_LEN];
	u8 up_compile_time[SPFC_COMPILE_TIME_LEN];

	u8 boot_ver[SPFC_VER_LEN];
	u8 boot_compile_time[SPFC_COMPILE_TIME_LEN];
};

/* get wwpn and wwnn */
struct spfc_chip_info {
	u8 work_mode;
	u8 tape_support;
	u64 wwpn;
	u64 wwnn;
};

/* Default SQ info */
struct spfc_default_sq_info {
	u32 sq_cid;
	u32 sq_xid;
	u32 fun_cid;
	u32 default_sq_flag;
};

struct spfc_hba_info {
	struct pci_dev *pci_dev;
	void *dev_handle;

	struct fc_service_cap service_cap; /* struct fc_service_cap pstFcoeServiceCap; */

	struct spfc_scq_info scq_info[SPFC_TOTAL_SCQ_NUM];
	struct spfc_srq_info els_srq_info;

	struct spfc_vport_info vport_info[UNF_SPFC_MAXNPIV_NUM + 1];

	/* PCI IO Memory */
	void __iomem *bar0;
	u32 bar0_len;

	struct spfc_parent_queue_mgr *parent_queue_mgr;

	/* Link list Sq WqePage Pool */
	struct spfc_sq_wqepage_pool sq_wpg_pool;

	enum spfc_queue_set_stage queue_set_stage;
	u32 next_clear_sq;
	u32 default_sqid;

	/* Port parameters, Obtained through firmware */
	u16 queue_set_max_count;
	u8 port_type;  /* FC or FCoE Port */
	u8 port_index; /* Phy Port */
	u32 default_scqn;
	char fw_ver[FW_VER_LEN]; /* FW version */
	char hw_ver[HW_VER_LEN]; /* HW version */
	char mst_fw_ver[FW_SUB_VER_LEN];
	char fc_fw_ver[FW_SUB_VER_LEN];
	u8 chip_type; /* chiptype:Smart or fc */
	u8 work_mode;
	struct spfc_card_info card_info;
	char port_name[SPFC_PORT_NAME_STR_LEN];
	u32 probe_index;

	u16 exi_base;
	u16 exi_count;
	u16 vpf_count;
	u8 vpid_start;
	u8 vpid_end;

	spinlock_t flush_state_lock;
	bool in_flushing;

	spinlock_t clear_state_lock;
	bool port_is_cleared;

	struct spfc_port_cfg port_cfg; /* Obtained through Config */

	void *lport; /* Used in UNF level */

	u8 sys_node_name[UNF_WWN_LEN];
	u8 sys_port_name[UNF_WWN_LEN];

	struct completion hba_init_complete;
	struct completion mbox_complete;
	struct completion vpf_complete;
	struct completion fcfi_complete;
	struct completion get_sfp_complete;

	u16 init_stage;
	u16 removing;
	bool sfp_on;
	bool dev_present;
	bool heart_status;
	spinlock_t hba_lock;
	u32 port_topo_cfg;
	u32 port_bb_scn_cfg;
	u32 port_loop_role;
	u32 port_speed_cfg;
	u32 max_support_speed;
	u32 min_support_speed;
	u32 server_max_speed;

	u8 remote_rttov_tag;
	u8 remote_edtov_tag;
	u16 compared_bb_scn;
	u16 remote_bb_credit;
	u32 compared_edtov_val;
	u32 compared_ratov_val;
	enum unf_act_topo active_topo;
	u32 active_port_speed;
	u32 active_rxbb_credit;
	u32 active_bb_scn;

	u32 phy_link;

	enum unf_port_mode port_mode;

	u32 fcp_cfg;

	/* loop */
	u8 active_alpa;
	u8 loop_map_valid;
	u8 loop_map[UNF_LOOPMAP_COUNT];

	/* sfp info dma */
	void *sfp_buf;
	dma_addr_t sfp_dma_addr;
	u32 sfp_status;
	int chip_temp;
	u32 sfp_posion;

	u32 cos_bitmap;
	atomic_t cos_rport_cnt[SPFC_MAX_COS_NUM];

	/* fw debug dma buffer */
	void *debug_buf;
	dma_addr_t debug_buf_dma_addr;
	void *log_buf;
	dma_addr_t fw_log_dma_addr;

	void *dma_addr;
	dma_addr_t update_dma_addr;

	struct spfc_sim_ini_err sim_ini_err;
	struct spfc_sim_pcie_err sim_pcie_err;

	struct spfc_led_state led_states;

	u32 fec_status;

	struct workqueue_struct *work_queue;
	struct work_struct els_srq_clear_work;
	u64 reset_time;

	spinlock_t spin_lock;

	struct spfc_srq_delay_info srq_delay_info;
	struct spfc_fw_ver_detail hardinfo;
	struct spfc_default_sq_info default_sq_info;
};

extern struct spfc_hba_info *spfc_hba[SPFC_HBA_PORT_MAX_NUM];
extern spinlock_t probe_spin_lock;
extern ulong probe_bit_map[SPFC_MAX_PROBE_PORT_NUM / SPFC_PORT_NUM_PER_TABLE];

u32 spfc_port_reset(struct spfc_hba_info *hba);
void spfc_flush_scq_ctx(struct spfc_hba_info *hba);
void spfc_flush_srq_ctx(struct spfc_hba_info *hba);
void spfc_set_hba_flush_state(struct spfc_hba_info *hba, bool in_flush);
void spfc_set_hba_clear_state(struct spfc_hba_info *hba, bool clear_flag);
u32 spfc_get_probe_index_by_port_id(u32 port_id, u32 *probe_index);
void spfc_get_total_probed_num(u32 *probe_cnt);
u32 spfc_sfp_switch(void *hba, void *para_in);
bool spfc_hba_is_present(struct spfc_hba_info *hba);

#endif
