/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_mt.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_MT_H
#define HINIC5_MT_H

#include <linux/types.h>

#ifdef __HIFC__     /**< If __HIFC__ macro is defined */
#define HINIC5_DRV_NAME "hifc3"     /**< Define driver name as hifc3 */
#define HINIC5_CHIP_NAME "hifc"     /**< Define chip name as hifc */
#else               /**< If __HIFC__ macro is not defined */
#define HINIC5_DRV_NAME "hisdk5"    /**< Define driver name as hisdk5 */
#define HINIC5_CHIP_NAME "hinic"    /**< Define chip name as hinic */
#endif
/* Interrupt at most records, interrupt will be recorded in the FFM */

#define NICTOOL_CMD_TYPE (0x18)

/**
 * @brief struct api_cmd_rd
 * @details Structure for receiving API commands
 */
struct api_cmd_rd {
	u32 pf_id;      /**< pf id */
	u8 dest;        /**< node id */
	u8 *cmd;        /**< Pointer to API command */
	u16 size;       /**< Command size */
	void *ack;      /**< Pointer to command acknowledgment information */
	u16 ack_size;   /**< Acknowledgment information size */
};

/**
 * @brief struct api_cmd_wr
 * @details Structure for API command write operation
 */
struct api_cmd_wr {
	u32 pf_id;      /**< pf id */
	u8 dest;        /**< node id */
	u8 *cmd;        /**< Pointer to API command */
	u16 size;       /**< Command size */
};

#define PF_DEV_INFO_NUM  32

/**
 * @brief struct pf_dev_info
 * @details Structure for storing PCI device information
 */
struct pf_dev_info {
	u64 bar0_size;     /**< bar0 size */
	u8 bus;            /**< PCI device bus number */
	u8 slot;           /**< PCI device slot number */
	u8 func;           /**< PCI device function number */
	u64 phy_addr;      /**< PCI device physical address */
};

/**
 * Indicates the maximum number of interrupts that can be recorded.
 * Subsequent interrupts are not recorded in FFM.
 */
#define FFM_RECORD_NUM_MAX 64

/**
 * @brief struct ffm_intr_info
 * @details Structure for storing interrupt information
 */
struct ffm_intr_info {
	u8 node_id;         /**< Interrupt source node ID */
	u8 err_level;       /**< Interrupt source error level */
	u16 err_type;       /**< Interrupt source error type */
	u32 err_csr_addr;   /**< Interrupt source address */
	u32 err_csr_value;  /**< Interrupt source value */
};

/**
 * @brief struct ffm_intr_tm_info
 * @details Structure for storing interrupt and time information
 */
struct ffm_intr_tm_info {
	struct ffm_intr_info intr_info; /**< Interrupt information */
	u8 times;       /**< Time */
	u8 sec;         /**< Second */
	u8 min;         /**< Minute */
	u8 hour;        /**< Hour */
	u8 mday;        /**< Day of month */
	u8 mon;         /**< Month */
	u16 year;       /**< Year */
};

/**
 * @brief struct ffm_record_info
 * @details Structure for storing FFM record information
 */
struct ffm_record_info {
	u32 ffm_num;            /**< FFM number */
	u32 last_err_csr_addr;  /**< Last error CSR address */
	u32 last_err_csr_value; /**< Last error CSR value */
	struct ffm_intr_tm_info ffm[FFM_RECORD_NUM_MAX];    /**< FFM interrupt time information array */
};

/**
 * @brief struct dbgtool_k_glb_info
 * @details Structure for storing debug tool global information
 */
struct dbgtool_k_glb_info {
	struct semaphore dbgtool_sem;   /**< Semaphore for synchronizing debug tool threads */
	struct ffm_record_info *ffm;    /**< FFM record information */
};

/**
 * @brief struct msg_2_up
 * @details Structure for storing uplink message related information
 */
struct msg_2_up {
	u8 pf_id;       /**< Protocol ID */
	u8 mod;         /**< Module ID */
	u8 cmd;         /**< Command ID */
	void *buf_in;   /**< Input buffer pointer */
	u16 in_size;    /**< Input buffer size */
	void *buf_out;  /**< Output buffer pointer */
	u16 *out_size;  /**< Output buffer size pointer */
};

/**
 * @brief struct dbgtool_param
 * @details Debug tool parameter structure
 */
struct dbgtool_param {
	union {
		struct api_cmd_rd api_rd;       /**< Read command */
		struct api_cmd_wr api_wr;       /**< Write command */
		struct pf_dev_info *dev_info;   /**< Device information */
		struct ffm_record_info *ffm_rd; /**< FFM record information */
		struct msg_2_up msg2up;         /**< Uplink message */
	} param;
	char chip_name[16];                 /**< Chip name */
};

/**
 * @brief typedef enum
 * @details Represents debug tool command types
 */
typedef enum {
	DBGTOOL_CMD_API_RD = 0,         /**< Read API command */
	DBGTOOL_CMD_API_WR,             /**< Write API command */
	DBGTOOL_CMD_FFM_RD,             /**< Read FFM command */
	DBGTOOL_CMD_FFM_CLR,            /**< Clear FFM command */
	DBGTOOL_CMD_PF_DEV_INFO_GET,    /**< Get PF device info command */
	DBGTOOL_CMD_MSG_2_UP,           /**< Send message to upper layer command */
	DBGTOOL_CMD_FREE_MEM,           /**< Free memory command */
	DBGTOOL_CMD_NUM                 /**< Number of command types */
} dbgtool_cmd;

#define PF_MAX_SIZE (16)
#define BUSINFO_LEN (32)
#define HINIC_FUNC_MAX_SIZE (4096)

/**
 * @brief enum module_name
 * @details Represents different module names
 */
enum module_name {
	SEND_TO_NPU = 1,            /**< Send to NPU module */
	SEND_TO_MPU,                /**< Send to MPU module */
	SEND_TO_SM,                 /**< Send to SM module */
	SEND_TO_HW_DRIVER,          /**< Send to hardware driver */
#define SEND_TO_SRV_DRV_BASE (SEND_TO_HW_DRIVER + 1)
	SEND_TO_NIC_DRIVER = SEND_TO_SRV_DRV_BASE,  /**< Send to network interface controller driver */
	SEND_TO_OVS_DRIVER,         /**< Send to Open vSwitch driver */
	SEND_TO_ROCE_DRIVER,        /**< Send to RDMA over Converged Ethernet driver */
	SEND_TO_TOE_DRIVER,         /**< Send to TCP offload driver */
	SEND_TO_IOE_DRIVER,         /**< Send to I/O acceleration driver */
	SEND_TO_FC_DRIVER,          /**< Send to Fibre Channel driver */
	SEND_TO_VBS_DRIVER,         /**< Send to virtual block storage driver */
	SEND_TO_IPSEC_DRIVER,       /**< Send to IPsec driver */
	SEND_TO_VIRTIO_DRIVER,      /**< Send to Virtio driver */
	SEND_TO_MIGRATE_DRIVER,     /**< Send to migration driver */
	SEND_TO_PPA_DRIVER,         /**< Send to PPA driver */
	SEND_TO_CUSTOM_DRIVER = SEND_TO_SRV_DRV_BASE + 11,  /**< Send to custom driver */
	SEND_TO_VROCE_DRIVER,       /**< Send to vRDMA over Converged Ethernet driver */
	SEND_TO_UB_DRIVER,          /**< Send to UB driver */
	SEND_TO_JBOF_DRIVER,        /**< Send to Jumbo Frame offload driver */
	SEND_TO_MACSEC_DRIVER,      /**< Send to MACsec driver */
	SEND_TO_BIFUR_DRIVER = SEND_TO_MACSEC_DRIVER + 3,
	SEND_TO_HIHTR_DRIVER,        /**< Send to Hihtr driver */
	SEND_TO_DRIVER_MAX = SEND_TO_SRV_DRV_BASE + 20, /* reserved */
};

/**
 * @brief enum driver_cmd_type
 * @details Defines driver command type enumeration
 */
enum driver_cmd_type {
	TX_INFO = 0x1,                     /**< Transmit information */
	Q_NUM = 0x2,                       /**< Queue number */
	TX_WQE_INFO = 0x3,                 /**< Transmit work queue information */
	TX_MAPPING = 0x4,                  /**< Transmit mapping */
	RX_INFO = 0x5,                     /**< Receive information */
	RX_WQE_INFO = 0x6,                 /**< Receive work queue information */
	RX_CQE_INFO = 0x7,                 /**< Receive completion queue information */
	UPRINT_FUNC_EN = 0x8,              /**< Print function enable */
	UPRINT_FUNC_RESET = 0x9,           /**< Print function reset */
	UPRINT_SET_PATH = 0xa,             /**< Set print path */
	UPRINT_GET_STATISTICS = 0xb,       /**< Get print statistics */
	FUNC_TYPE = 0xc,                   /**< Function type */
	GET_FUNC_IDX = 0xd,                /**< Get function index */
	GET_INTER_NUM = 0xe,               /**< Get internal number */
	CLOSE_TX_STREAM = 0xf,             /**< Close transmit stream */
	GET_DRV_VERSION = 0x10,            /**< Get driver version */
	CLEAR_FUNC_STASTIC = 0x11,         /**< Clear function statistics */
	GET_HW_STATS = 0x12,               /**< Get hardware statistics */
	CLEAR_HW_STATS = 0x13,             /**< Clear hardware statistics */
	GET_SELF_TEST_RES = 0x14,          /**< Get self test result */
	GET_CHIP_FAULT_STATS = 0x15,       /**< Get chip fault statistics */
	NIC_RSVD1 = 0x16,
	NIC_RSVD2 = 0x17,
	NIC_RSVD3 = 0x18,
	GET_CHIP_ID = 0x19,                /**< Get chip ID */
	GET_SINGLE_CARD_INFO = 0x1a,       /**< Get single card information */
	GET_FIRMWARE_ACTIVE_STATUS = 0x1b, /**< Get firmware active status */
	ROCE_DFX_FUNC = 0x1c,              /**< RoCE debug function */
	GET_DEVICE_ID = 0x1d,              /**< Get device ID */
	GET_PF_DEV_INFO = 0x1e,            /**< Get PF device information */
	CMD_FREE_MEM = 0x1f,               /**< Free memory */
	GET_LOOPBACK_MODE = 0x20,          /**< Get loopback mode */
	SET_LOOPBACK_MODE = 0x21,          /**< Set loopback mode */
	SET_LINK_MODE = 0x22,              /**< Set link mode */
	SET_PF_BW_LIMIT = 0x23,            /**< Set PF bandwidth limit */
	GET_PF_BW_LIMIT = 0x24,            /**< Get PF bandwidth limit */
	ROCE_CMD = 0x25,                   /**< RoCE command */
	GET_POLL_WEIGHT = 0x26,            /**< Get poll weight */
	SET_POLL_WEIGHT = 0x27,            /**< Set poll weight */
	GET_HOMOLOGUE = 0x28,              /**< Get peer information */
	SET_HOMOLOGUE = 0x29,              /**< Set peer information */
	GET_SSET_COUNT = 0x2a,             /**< Get statistics count */
	GET_SSET_ITEMS = 0x2b,             /**< Get statistics items */
	IS_DRV_IN_VM = 0x2c,               /**< Check if in VM */
	LRO_ADPT_MGMT = 0x2d,              /**< Manage LRO adapter */
	SET_INTER_COAL_PARAM = 0x2e,       /**< Set interrupt coalescing parameters */
	GET_INTER_COAL_PARAM = 0x2f,       /**< Get interrupt coalescing parameters */
	GET_CHIP_INFO = 0x30,              /**< Get chip information */
	GET_NIC_STATS_LEN = 0x31,          /**< Get NIC statistics length */
	GET_NIC_STATS_STRING = 0x32,       /**< Get NIC statistics string */
	GET_NIC_STATS_INFO = 0x33,         /**< Get NIC statistics information */
	GET_PF_ID = 0x34,                  /**< Get PF ID */
	GET_MBOX_CNT = 0x35,               /**< Get mailbox count */
	NIC_RSVD5 = 0x36,
	DCB_QOS_INFO = 0x37,               /**< DCB QoS information */
	DCB_PFC_STATE = 0x38,              /**< DCB PFC state */
	DCB_ETS_STATE = 0x39,              /**< DCB ETS state */
	DCB_STATE = 0x3a,                  /**< DCB state */
	QOS_DEV = 0x3b,                    /**< QOS device */
	GET_QOS_COS = 0x3c,                /**< Get QOS priority */
	GET_ULD_DEV_NAME = 0x3d,           /**< Get ULD device name */
	GET_TX_TIMEOUT = 0x3e,             /**< Get transmit timeout */
	SET_TX_TIMEOUT = 0x3f,             /**< Set transmit timeout */

	RSS_CFG = 0x40,                    /**< RSS configuration */
	RSS_INDIR = 0x41,                  /**< RSS indirect table */
	PORT_ID = 0x42,                    /**< Port ID */
	BOND_DFX_OPS = 0x43,               /**< BOND DFX operations */

	GET_FUNC_CAP = 0x50,               /**< Get function capability */
	GET_XSFP_PRESENT = 0x51,           /**< Get XSFP presence status */
	GET_XSFP_INFO = 0x52,              /**< Get XSFP information */
	DEV_NAME_TEST = 0x53,              /**< Device name test */
	GET_XSFP_INFO_COMP_CMIS = 0x54,    /**< Get XSFP information (CMIS supported) */
	CMD_GET_PROFILE_ID = 0x55,
	CMD_SET_PROFILE_ID = 0x56,
	CMD_MOVE_TCAM_TABLE = 0x57,

	GET_WIN_STAT = 0x60,               /**< Get window status */
	WIN_CSR_READ = 0x61,               /**< Read window CSR */
	WIN_CSR_WRITE = 0x62,              /**< Write window CSR */
	WIN_API_CMD_RD = 0x63,             /**< Read window API command */

	ROCE_CMD_SET_LDCP_PARAM = 0x70,    /**< RoCE command set LDCP parameter */

	ROCE_CMD_GET_QPC_FROM_CACHE = 0x80,     /**< Get QPC from cache */
	ROCE_CMD_GET_QPC_FROM_HOST = 0x81,      /**< Get QPC from host */
	ROCE_CMD_GET_CQC_FROM_CACHE = 0x82,     /**< Get CQC from cache */
	ROCE_CMD_GET_CQC_FROM_HOST = 0x83,      /**< Get CQC from host */
	ROCE_CMD_GET_SRQC_FROM_CACHE = 0x84,    /**< Get SRQC from cache */
	ROCE_CMD_GET_SRQC_FROM_HOST = 0x85,     /**< Get SRQC from host */
	ROCE_CMD_GET_MPT_FROM_CACHE = 0x86,     /**< Get MPT from cache */
	ROCE_CMD_GET_MPT_FROM_HOST = 0x87,      /**< Get MPT from host */
	ROCE_CMD_GET_GID_FROM_CACHE = 0x88,     /**< Get GID from cache */
	ROCE_CMD_GET_QPC_CQC_PI_CI = 0x89,      /**< Get QPC, CQC, PI, CI */
	ROCE_CMD_GET_QP_COUNT = 0x8a,           /**< Get QP count */
	ROCE_CMD_GET_DEV_ALGO = 0x8b,           /**< Get device algorithm */
	ROCE_CMD_GET_DEV_TYPE = 0x8c,           /**< Get device type */
	ROCE_CMD_GET_HW_COUNT = 0x8d,           /**< Get hardware count */
	ROCE_CMD_GET_SPECIFICATIONS = 0x8e,     /**< Get device specifications from cache */

	ROCE_CMD_START_CAP_PACKET = 0x90,       /**< Start packet capture */
	ROCE_CMD_STOP_CAP_PACKET = 0x91,        /**< Stop packet capture */
	ROCE_CMD_QUERY_CAP_INFO = 0x92,         /**< Query capture information */
	ROCE_CMD_ENABLE_QP_CAP_PACKET = 0x93,   /**< Enable QP packet capture */
	ROCE_CMD_DISABLE_QP_CAP_PACKET = 0x94,  /**< Disable QP packet capture */
	ROCE_CMD_QUERY_QP_CAP_INFO = 0x95,      /**< Query QP capture information */
	ROCE_CMD_SET_BYPASS = 0x96,             /**< Set bypass */
	ROCE_CMD_QUERY_BYPASS = 0x97,           /**< Query bypass */
	ROCE_CMD_GET_AEQC_FROM_CACHE = 0x98,    /**< Get AEQC from cache */
	ROCE_CMD_GET_AEQC_FROM_HOST = 0x99,     /**< Get AEQC from host */

	ROCE_CMD_ENABLE_BW_CTRL = 0xa0,         /**< Enable bandwidth control */
	ROCE_CMD_DISABLE_BW_CTRL = 0xa1,        /**< Disable bandwidth control */
	ROCE_CMD_CHANGE_BW_CTRL_PARAM = 0xa2,   /**< Change bandwidth control parameter */
	ROCE_CMD_QUERY_BW_CTRL_PARAM = 0xa3,    /**< Query bandwidth control parameter */
	ROCE_CMD_SET_BW_WATERLINE = 0xa4,       /**< Set bandwidth watermark */
	ROCE_CMD_GET_BW_WATERLINE = 0xa5,       /**< Get bandwidth watermark */
	ROCE_CMD_SET_VNIC_WATERLINE = 0xa6,     /**< Set VNIC watermark */
	ROCE_CMD_GET_VNIC_WATERLINE = 0xa7,     /**< Get VNIC watermark */
	ROCE_CMD_ROCE_SET = 0xa8,               /**< Set ROCE related configuration */
	ROCE_CMD_DFX_LATCH_QUERY = 0xa9,        /**< ROCE latch query */

	ROCE_CMD_TIMEOUT_ALARM = 0xb0,          /**< Timeout alarm */
	ROCE_CMD_PORT_TRAFFIC = 0Xb1,           /**< Port traffic */
	ROCE_CMD_DFX_ATTACK = 0Xb2,             /**< ROCE host side attack prevention */
	ROCE_CMD_ULD_IOCTL_EXTEND = 0xb3,       /**< User ioctl to driver entry */

	MIG_QUERY_DFX = 0xc0,                   /**< Query migration DFX */

	DRV_CMD_TYPE_RSV = 0xd0,                /**< Reserved, cannot use */

	NIC_CMD_ANTI_ATTACK = 0xd6,             /**< Anti-attack verification */

	VM_COMPAT_TEST = 0xFF,                  /**< VM compatibility test */

	SERVICE_DRV_BASE_CMD = 0x120,           /**< Service commands start from 0x120, commands before 0x120 are reserved for future product use */
};

/**
 * @brief enum api_chain_cmd_type
 * @details Defines API chain command type enumeration
 */
enum api_chain_cmd_type {
	API_CSR_READ,       /**< Read CSR (Control and Status Register) */
	API_CSR_WRITE       /**< Write CSR (Control and Status Register) */
};

/**
 * @brief sm_cmd_type
 * @details Used to represent different command types
 */
enum sm_cmd_type {
	SM_CTR_RD16 = 1,        /**< Command to read 16-bit data */
	SM_CTR_RD32,            /**< Command to read 32-bit data */
	SM_CTR_RD64_PAIR,       /**< Command to read 64-bit data pair */
	SM_CTR_RD64,            /**< Command to read 64-bit data */
	SM_CTR_RD32_CLEAR,      /**< Command to clear 32-bit data */
	SM_CTR_RD64_PAIR_CLEAR, /**< Command to clear 64-bit data pair */
	SM_CTR_RD64_CLEAR       /**< Command to clear 64-bit data */
};

#define HINIC5_CQM_AEQ_CALLBACK_CNT_MAX 128  /* Consistent with HINIC5_CQM_AEQ_BASE_T_MAX */

/**
 * @brief struct hinic5_cqm_stats
 * @details Statistics of various operations in HINIC5_CQM module
 */
struct hinic5_cqm_stats {
	atomic_t hinic5_cqm_cmd_alloc_cnt;             /**< Statistics of HINIC5_CQM command allocation count */
	atomic_t hinic5_cqm_cmd_free_cnt;              /**< Statistics of HINIC5_CQM command free count */
	atomic_t hinic5_cqm_send_cmd_box_cnt;          /**< Statistics of HINIC5_CQM send command box count */
	atomic_t hinic5_cqm_send_cmd_imm_cnt;          /**< Statistics of HINIC5_CQM send command count */
	atomic_t hinic5_cqm_db_addr_alloc_cnt;         /**< Statistics of HINIC5_CQM database address allocation count */
	atomic_t hinic5_cqm_db_addr_free_cnt;          /**< Statistics of HINIC5_CQM database address free count */
	atomic_t hinic5_cqm_fc_srq_create_cnt;         /**< Statistics of HINIC5_CQM FC SRQ creation count */
	atomic_t hinic5_cqm_srq_create_cnt;            /**< Statistics of HINIC5_CQM SRQ creation count */
	atomic_t hinic5_cqm_rq_create_cnt;             /**< Statistics of HINIC5_CQM RQ creation count */
	atomic_t hinic5_cqm_qpc_mpt_create_cnt;        /**< Statistics of HINIC5_CQM QPC and MPT creation count */
	atomic_t hinic5_cqm_nonrdma_queue_create_cnt;  /**< Statistics of HINIC5_CQM non-RDMA queue creation count */
	atomic_t hinic5_cqm_rdma_queue_create_cnt;     /**< Statistics of HINIC5_CQM RDMA queue creation count */
	atomic_t hinic5_cqm_rdma_table_create_cnt;     /**< Statistics of HINIC5_CQM RDMA table creation count */
	atomic_t hinic5_cqm_qpc_mpt_delete_cnt;        /**< Statistics of HINIC5_CQM QPC and MPT deletion count */
	atomic_t hinic5_cqm_nonrdma_queue_delete_cnt;  /**< Statistics of HINIC5_CQM non-RDMA queue deletion count */
	atomic_t hinic5_cqm_rdma_queue_delete_cnt;     /**< Statistics of HINIC5_CQM RDMA queue deletion count */
	atomic_t hinic5_cqm_rdma_table_delete_cnt;     /**< Statistics of HINIC5_CQM RDMA table deletion count */
	atomic_t hinic5_cqm_func_timer_clear_cnt;      /**< Statistics of HINIC5_CQM function timer clear count */
	atomic_t hinic5_cqm_func_hash_buf_clear_cnt;   /**< Statistics of HINIC5_CQM function hash buffer clear count */
	atomic_t hinic5_cqm_scq_callback_cnt;          /**< Statistics of HINIC5_CQM SCQ callback count */
	atomic_t hinic5_cqm_ecq_callback_cnt;          /**< Statistics of HINIC5_CQM ECQ callback count */
	atomic_t hinic5_cqm_nocq_callback_cnt;         /**< Statistics of HINIC5_CQM NOCQ callback count */
	atomic_t hinic5_cqm_aeq_callback_cnt[HINIC5_CQM_AEQ_CALLBACK_CNT_MAX];    /**< Statistics of HINIC5_CQM AEQ callback count */
};

/**
 * @brief struct link_event_stats
 * @details Used to count the number of link events
 */
struct link_event_stats {
	atomic_t link_down_stats;       /**< Number of events indicating link has been disconnected */
	atomic_t link_up_stats;         /**< Number of events indicating link has been connected */
};

/**
 * @brief enum hinic5_fault_err_level
 * @details Error level enumeration type
 */
enum hinic5_fault_err_level {
	FAULT_LEVEL_FATAL,          /**< Fatal error */
	FAULT_LEVEL_SERIOUS_RESET,  /**< Serious error, requires reset */
	FAULT_LEVEL_HOST,           /**< Host error */
	FAULT_LEVEL_SERIOUS_FLR,    /**< Serious error, requires FLR (Function Level Reset) */
	FAULT_LEVEL_GENERAL,        /**< General error */
	FAULT_LEVEL_SUGGESTION,     /**< Suggestion error */
	FAULT_LEVEL_MAX,            /**< Maximum error level value */
};

/**
 * @brief enum hinic5_fault_type
 * @details Defines possible fault types
 */
enum hinic5_fault_type {
	FAULT_TYPE_CHIP,            /**< Chip fault */
	FAULT_TYPE_UCODE,           /**< Microcode fault */
	FAULT_TYPE_MEM_RD_TIMEOUT,  /**< Memory read timeout fault */
	FAULT_TYPE_MEM_WR_TIMEOUT,  /**< Memory write timeout fault */
	FAULT_TYPE_REG_RD_TIMEOUT,  /**< Register read timeout fault */
	FAULT_TYPE_REG_WR_TIMEOUT,  /**< Register write timeout fault */
	FAULT_TYPE_PHY_FAULT,       /**< Physical fault */
	FAULT_TYPE_TSENSOR_FAULT,   /**< Temperature sensor fault */
	FAULT_TYPE_MAX,             /**< Maximum fault type value */
};

/**
 * @brief struct fault_event_stats
 * @details Fault event statistics structure
 */
struct fault_event_stats {
	/* HINIC_NODE_ID_MAX: temp use the value of 1822(22) */
	atomic_t chip_fault_stats[22][FAULT_LEVEL_MAX]; /**< Fault level statistics for each chip */
	atomic_t fault_type_stat[FAULT_TYPE_MAX];       /**< Statistics for each fault type */
	atomic_t pcie_fault_stats;                      /**< PCIE fault statistics */
};

/**
 * @brief enum hinic5_ucode_event_type
 * @details Enumeration of Ucode event types
 */
enum hinic5_ucode_event_type {
	HINIC5_INTERNAL_OTHER_FATAL_ERROR = 0x0,    /**< Internal other fatal error */
	HINIC5_HTN_PTP_EVENT = 0x1,                 /**< HTN PTP event */
	HINIC5_CHANNEL_BUSY = 0x7,                  /**< Channel busy */
	HINIC5_NIC_FATAL_ERROR_MAX = 0x8,           /**< Maximum NIC fatal error value */
};

/**
 * @brief struct hinic5_hw_stats
 * @details Hardware statistics structure
 */
struct hinic5_hw_stats {
	atomic_t heart_lost_stats;                                  /**< Heartbeat lost statistics */
	struct hinic5_cqm_stats hinic5_cqm_stats;                                 /**< HINIC5_CQM statistics */
	struct link_event_stats link_event_stats;                   /**< Link event statistics */
	struct fault_event_stats fault_event_stats;                 /**< Fault event statistics */
	atomic_t nic_ucode_event_stats[HINIC5_NIC_FATAL_ERROR_MAX]; /**< NIC microcode event statistics */
};

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

/**
 * @brief struct pf_info
 * @details Structure for storing network interface information
 */
struct pf_info {
	char name[IFNAMSIZ];        /**< Network interface name */
	char bus_info[BUSINFO_LEN]; /**< Network interface bus information */
	u32 pf_type;                /**< Network interface type */
};

/**
 * @brief struct card_info
 * @details Structure for storing card information
 * @param pf_num
 *              in_param: Accumulated pf num obtained (integer multiple of PF_MAX_SIZE)
 *              out_param: Number of pf_info obtained and sum of pf num to be obtained
 */
struct card_info {
	struct pf_info pf[PF_MAX_SIZE];     /**< Structure for storing card information */
	u32 pf_num;                         /**< Number of cards */
};

struct func_mbox_cnt_info {
	char bus_info[BUSINFO_LEN];
	u64 send_cnt;
	u64 ack_cnt;
};

struct card_mbox_cnt_info {
	struct func_mbox_cnt_info func_info[HINIC_FUNC_MAX_SIZE];
	u32 func_num;
};

/**
 * @brief struct hinic5_nic_loop_mode
 * @details Structure for loop mode
 */
struct hinic5_nic_loop_mode {
	u32 loop_mode;      /**< Loop mode identifier */
	u32 loop_ctrl;      /**< Loop control identifier */
};

/**
 * @brief struct hinic5_pf_info
 * @details Structure for storing PF information
 */
struct hinic5_pf_info {
	u32 isvalid;    /**< Flag indicating whether PF information is valid */
	u32 pf_id;      /**< PF unique identifier */
};

#define HINIC5_CHIP_FAULT_SIZE (110 * 1024)
#define MAX_DRV_BUF_SIZE 4096

/**
 * @brief struct nic_cmd_chip_fault_stats
 * @details Network interface command chip fault statistics structure
 */
struct nic_cmd_chip_fault_stats {
	u32 offset;                             /**< Offset */
	u8 chip_fault_stats[MAX_DRV_BUF_SIZE];  /**< Chip fault statistics array */
};

#define NIC_TOOL_MAGIC 'x'      /**< NIC tool magic number */

#ifdef STORAGE_PANGEA
#define CARD_MAX_SIZE (16)      /**< Maximum card size is 16 */
#else
#define CARD_MAX_SIZE (64)      /**< Maximum card size is 64 */
#endif

/**
 * @brief struct nic_card_id
 * @details Structure for storing NIC ID and count
 */
struct nic_card_id {
	u32 id[CARD_MAX_SIZE];  /**< NIC ID array, maximum length is CARD_MAX_SIZE */
	u32 num;                /**< NIC count */
};

/**
 * @brief struct func_dev_info
 * @details Structure for storing function-related dev information
 */
struct func_dev_info {
	u64 bar0_phy_addr;      /**< bar0 physical address */
	u64 bar0_size;          /**< bar0 size */
	u64 bar1_phy_addr;      /**< bar1 physical address */
	u64 bar1_size;          /**< bar1 size */
	u64 bar3_phy_addr;      /**< bar3 physical address */
	u64 bar3_size;          /**< bar3 size */
	u64 rsvd1[4];
};

/**
 * @brief struct hinic5_card_func_info
 * @details Structure for storing card function information
 */
struct hinic5_card_func_info {
	u32 num_pf;             /**< Number of physical functions */
	u32 rsvd0;
	u64 usr_api_phy_addr;   /**< User API physical address */
	struct func_dev_info dev_info[CARD_MAX_SIZE]; /**< Function dev information array */
};

#define MAX_VER_INFO_LEN 128    /**< Maximum version information length constant */
/**
 * @brief struct drv_version_info
 * @details Driver version information structure definition
 */
struct drv_version_info {
	char ver[MAX_VER_INFO_LEN]; /**< Version information character array, length is MAX_VER_INFO_LEN */
};

#define MT_EPERM        1       /**< Operation not permitted */
#define MT_EIO          2       /**< I/O error */
#define MT_EINVAL       3       /**< Invalid argument */
#define	MT_EBUSY        4       /**< Device or resource busy */
#define MT_EOPNOTSUPP   0xFF    /**< Operation not supported */

/**
 * @brief struct mt_msg_head
 * @details Structure for storing message header
 */
struct mt_msg_head {
	u8 status;      /**< Status */
	u8 rsvd1[3];    /**< Reserved field */
};

/**
 * @brief enum mt_api_type
 * @details Enumeration for different API types
 */
enum mt_api_type {
	API_TYPE_MBOX = 1,          /**< MBOX API type */
	API_TYPE_API_CHAIN_BYPASS,  /**< API chain bypass API type */
	API_TYPE_API_CHAIN_TO_MPU,  /**< API chain to MPU API type */
	API_TYPE_CLP,               /**< CLP API type */
};

/**
 * @brief struct npu_cmd_st
 * @details Structure for describing NPU command
 */
struct npu_cmd_st {
	u32 mod : 8;            /**< Module ID, occupies 8 bits of 32 bits */
	u32 cmd : 8;            /**< Command ID, occupies 8 bits of 32 bits */
	u32 ack_type : 3;       /**< Acknowledgment type, occupies 3 bits of 32 bits */
	u32 direct_resp : 1;    /**< Direct response flag, occupies 1 bit of 32 bits */
	u32 len : 12;           /**< Length, occupies 12 bits of 32 bits */
};

/**
 * @brief struct mpu_cmd_st
 * @details Structure for storing MPU command
 */
struct mpu_cmd_st {
	u32 api_type : 8;   /**< Defines a 32-bit unsigned integer for storing API type, occupies 8 bits */
	u32 mod : 8;        /**< Defines a 32-bit unsigned integer for storing module, occupies 8 bits */
	u32 cmd : 16;       /**< Defines a 32-bit unsigned integer for storing command, occupies 16 bits */
};

/**
 * @brief struct msg_module
 * @details Message module structure for storing device name, module information, command format, timeout, function index, input/output buffer size, buffer pointer, bus number, Port ID and other information
 */
struct msg_module {
	char device_name[IFNAMSIZ];     /**< Device name, stores device name */
	u32 module;                     /**< Module information, stores module related information */
	/**
	 * @brief Message format storage
	 */
	union {
		u32 msg_formate;
		struct npu_cmd_st npu_cmd;
		struct mpu_cmd_st mpu_cmd;
	};
	u32 timeout;            /**< Timeout, stores operation timeout */
	u32 func_idx;           /**< Function index, stores function index information */
	u32 buf_in_size;        /**< Input buffer size, stores input buffer size */
	u32 buf_out_size;       /**< Output buffer size, stores output buffer size */
	void *in_buf;           /**< Input buffer pointer, stores input buffer pointer */
	void *out_buf;          /**< Output buffer pointer, stores output buffer pointer */
	int bus_num;            /**< Bus number, stores bus number information */
	u8 port_id;             /**< Port ID, stores port ID information */
	u8 use_func_idx;        /**< Indicates whether func_idx is used to send commands to device, used together with func_idx */
	u8 rsvd1[2];
	u32 rsvd2[4];
};

#define  MQM_FLOW_NUM	2
#define  MQM_XID_NUM	32768
#define  MQM_COS_VLD 	1
#define  MQM_COS_INVLD 	0
#define  MQM_COS_NUM    8

typedef struct hinic5_mqm_send_db_cmd_s {
	u32 service_type;
	u32 cflag;
	u32 no_fliter;
	u32 pf_id;
	u32 cos_vld[8];
	u32 db_cnt[8];
	u32 time[8];
	u32 time_max;
	u32 speed_pps[8];
	u32 length[8];
	u32 num[8];
	u32 mode;
	u32 db_dw0_rsv;
	u32 db_dw1_value;
	u32 rand;
} mqm_send_db_cmd_s;

struct hinic5_mqm_db_num_len {
	u32	db_info;
	u32	pi_hi;
};
typedef union {
	struct {
		u32 num         	: 8;
		u32 length        	: 18;
		u32 mode         	: 2;
		u32 rsvd         	: 4;
	} bs;
	u32 value;
} u_hinic5_mqm_db_num_len;

struct hinic5_mt_msg {
	const void *buf_in;
	void *buf_out;
	u32 in_size;
	u32 out_size;
};

/**
 * @brief struct hinic5_non_ptp_info
 * @details Structure for storing non PTP time information
 */
struct hinic5_non_ptp_info {
	char name[IFNAMSIZ];                         /**< Chip device name corresponding to time */
	u64 non_ptp_time_diff_enable;                /**< Non-PTP time difference enable */
	s64 non_ptp_time_diff;                       /**< Non-PTP time difference */
	atomic_t  ref_cnt;                            /**< Reference count for using this non PTP info */
};

/**
 * @brief hinic5_set_freq_reduce_ratio
 * @param dev: device pointer
 * @param ratio: non PTP chip time frequency reduction ratio, must be greater than 0
 *
 * @return Success or failure
 * 		@retval zero: success
 * 		@retval non-zero: failure
 */
int hinic5_set_freq_reduce_ratio(void *dev, u32 ratio);

/**
 * @brief hinic5_set_non_ptp_time_diff_en
 * @param dev: device pointer
 * @param enable: non PTP chip time enable flag, 0 disable, 1 enable
 *
 * @return Success or failure
 * 		@retval zero: success
 * 		@retval non-zero: failure
 */
int hinic5_set_non_ptp_time_diff_en(void *dev, bool enable);

/**
 * @brief SDK driver command hook function
 *
 * @param lld_dev device pointer to hinic5_lld_dev
 * @param cmd Command word
 * @param nt_msg Command content
 * @param support Whether the command is supported, product needs to determine whether to support based on command word
 *
 * @details Overloaded by product
 *
 * @return: Command execution result.
 *     @retval 0 Success
 *     @retval non-zero Failure
 */
int hinic5_nictool_cmd_extend_handle(void *lld_dev, u32 cmd, struct hinic5_mt_msg *mt_msg, bool *support);

#endif /* _HINIC5_MT_H_ */
