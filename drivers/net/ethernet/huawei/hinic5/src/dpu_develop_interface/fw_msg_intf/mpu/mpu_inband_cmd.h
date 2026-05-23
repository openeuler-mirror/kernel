/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : mpu_inband_cmd.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   : In-band commands between the driver and the MPU
 */

#ifndef MPU_INBAND_CMD_H
#define MPU_INBAND_CMD_H

/**< COMM Commands between Driver to MPU */
enum hinic5_mgmt_cmd {
	/**< FLR and resource cleanup related commands */
	COMM_MGMT_CMD_FUNC_RESET = 0,   /**< Driver load/unload function reset resource cleanup */
	COMM_MGMT_CMD_FEATURE_NEGO,   /**< FW and driver compatibility attribute negotiation */
	COMM_MGMT_CMD_FLUSH_DOORBELL,   /**< Driver unload flush process, resource cleanup */
	COMM_MGMT_CMD_START_FLUSH,   /**< Driver load/unload flush handshake */
	COMM_MGMT_CMD_SET_FUNC_FLR,   /**< Driver actively triggers FLR through mbox process */
	COMM_MGMT_CMD_GET_GLOBAL_ATTR,   /**< Get SM global table */
	COMM_MGMT_CMD_SET_PPF_FLR_TYPE,   /**< Set PPF FLR execution range */
	COMM_MGMT_CMD_SET_FUNC_SVC_USED_STATE,   /**< Set whether corresponding function driver is loaded/used */
	COMM_MGMT_CMD_GET_FUNC_FLR_INFO,   /**< Get FLR execution DFX information */

	/**< Driver interrupt resources */
	COMM_MGMT_CMD_CFG_MSIX_NUM = 10,   /**< Get driver MSIX interrupt information */

	/**< Driver related configuration commands */
	COMM_MGMT_CMD_SET_CMDQ_CTXT = 20,   /**< Set CMDQ context */
	COMM_MGMT_CMD_SET_VAT,   /**< Set VAT table */
	COMM_MGMT_CMD_CFG_PAGESIZE,   /**< Configure root context page size */
	COMM_MGMT_CMD_CFG_MSIX_CTRL_REG,   /**< Configure interrupt MSIX */
	COMM_MGMT_CMD_SET_CEQ_CTRL_REG,   /**< Configure CEQ */
	COMM_MGMT_CMD_SET_DMA_ATTR,   /**< Configure driver DMA attributes */
	COMM_MGMT_CMD_SET_ENHANCE_CMDQ_CTXT,   /**< Configure enhanced CMDQ */
	COMM_MGMT_CMD_GET_FUNC_SECURE_MEM,   /**< Get secure memory identifier */
	COMM_MGMT_CMD_SET_FUNC_PLUG_SRV,   /**< Set hotplug BMP */
	COMM_MGMT_CMD_GET_FUNC_PLUG_SRV,   /**< Get hotplug BMP */
	COMM_MGMT_CMD_SET_PPF_TBL_HTR_FLG,   /**< Set hot-replacement identifier */
	COMM_MGMT_CMD_GET_FAST_MSG_CAP,   /**< Get fast message capability */
	COMM_MGMT_CMD_SET_FAST_MSG_RQ_ADDR,   /**< Set fast message address */
	COMM_MGMT_CMD_CLEAR_FAST_MSG_SML,   /**< Clear fast message table entry */

	/**< INFRA configuration related command codes */
	COMM_MGMT_CMD_GET_MQM_FIX_INFO = 40,   /**< MQM get chunk num */
	COMM_MGMT_CMD_SET_MQM_CFG_INFO,   /**< Receive PPF and page_size from driver */
	COMM_MGMT_CMD_SET_MQM_SRCH_GPA,   /**< Receive search GPA address from driver */
	COMM_MGMT_CMD_SET_PPF_TMR,   /**< Configure SMF timer */
	COMM_MGMT_CMD_SET_HT_GPA,   /**< Set HT GPA (bank GPA) address */
	COMM_MGMT_CMD_SET_FUNC_TMR_BITMAT,   /**< Enable SMF timer */
	COMM_MGMT_CMD_SET_MBX_CRDT,   /**< Set mailbox credit, for DFX performance tuning */
	COMM_MGMT_CMD_CFG_TEMPLATE,   /**< Set/get temperature alarm threshold */
	COMM_MGMT_CMD_SET_MQM_LIMIT,   /**< Set/get MQM rate limit configuration, used by 1823V100 Pangua driver */
	COMM_MGMT_CMD_SET_BAT_INFO,   /**< Set BAT information */
	COMM_MGMT_CMD_SET_VIO_EN, /**< Set CPI MSI enable*/
	COMM_MGMT_CMD_CFG_DATA, /**< Configure function related parameters in template */

	/**< Information retrieval related command codes */
	COMM_MGMT_CMD_GET_FW_VERSION = 60,   /**< Get FW version information */
	COMM_MGMT_CMD_GET_BOARD_INFO,   /**< Get board information */
	COMM_MGMT_CMD_SYNC_TIME,   /**< Sync driver timestamp */
	COMM_MGMT_CMD_GET_HW_PF_INFOS,   /**< Get hardware PF information */
	COMM_MGMT_CMD_SEND_BDF_INFO,   /**< Receive DBF information obtained by driver */
	COMM_MGMT_CMD_GET_VIRTIO_BDF_INFO,   /**< Get DBF information in virtio scenario */
	COMM_MGMT_CMD_GET_SML_TABLE_INFO,   /**< Get SMLB table entry information */
	COMM_MGMT_CMD_GET_SDI_INFO,   /**< Get SDI information (bare metal/VM) */
	COMM_MGMT_CMD_ROOT_CTX_LOAD,   /**< Get root context information */
	COMM_MGMT_CMD_GET_HW_BOND = 69, /* 1823V100 */
	COMM_MGMT_CMD_MPU_AND_NPU_VER = 70, /* 1823V100 */
	COMM_MGMT_CMD_GET_PF_BY_FUNC = 71, /* 1823V100 */
	COMM_MGMT_CMD_GET_PF_BUS_BY_DEV = 72, /* 1823V100 */

	/**< Upgrade related command codes */
	COMM_MGMT_CMD_UPDATE_FW = 80,   /**< FW upgrade */
	COMM_MGMT_CMD_ACTIVE_FW,   /**< FW cold activation */
	COMM_MGMT_CMD_HOT_ACTIVE_FW,   /**< FW hot activation */
	COMM_MGMT_CMD_HOT_ACTIVE_DONE_NOTICE,   /**< FW hot activation done (currently unused) */
	COMM_MGMT_CMD_SWITCH_CFG,   /**< Configuration file switch (currently unused) */
	COMM_MGMT_CMD_CHECK_FLASH,   /**< Storage scenario flash silent detection */
	COMM_MGMT_CMD_CHECK_FLASH_RW,   /**< Storage scenario pre-upgrade */
	COMM_MGMT_CMD_RESOURCE_CFG,   /**< Original configuration template (currently unused) */
	COMM_MGMT_CMD_UPDATE_BIOS,   /**< BIOS upgrade command (deprecated, BIOS upgrade merged with NIC upgrade) */
	COMM_MGMT_CMD_MPU_GIT_CODE,   /**< Get version git commit */
	COMM_MGMT_QUERY_MODULE_IMAGES,   /**< Image handshake, get firmware information */
	COMM_MGMT_CMD_UPDATE_CUSTOM_FW = 98,  /* Upgrade CUSTOM_FW firmware, do not modify this value */
	COMM_MGMT_CMD_ACTIVE_CUSTOM_FW = 99,  /* Activate CUSTOM_FW firmware */

	/**< Chip reset related */
	COMM_MGMT_CMD_FAULT_REPORT = 100,   /**< MPU to driver information, exception alarm */
	COMM_MGMT_CMD_WATCHDOG_INFO,   /**< MPU to driver information, watchdog alarm */
	COMM_MGMT_CMD_MGMT_RESET,   /**< MPU to driver information, MPU last word */
	COMM_MGMT_CMD_FFM_SET,    /**< MPU to driver message, exception interrupt display information */

	/**< Chip info/log related */
	COMM_MGMT_CMD_GET_LOG = 120,   /**< Get firmware log */
	COMM_MGMT_CMD_TEMP_OP,   /**< Get chip temperature */
	COMM_MGMT_CMD_EN_AUTO_RST_CHIP,   /**< Enable chip automatic reset following perst */
	COMM_MGMT_CMD_CFG_REG,   /**< Configure chip register (currently unused) */
	COMM_MGMT_CMD_GET_CHIP_ID,   /**< Get chip ID (multi-chip scenario) */
	COMM_MGMT_CMD_SYSINFO_DFX,   /**< Get chip software system DFX information */
	COMM_MGMT_CMD_PCIE_DFX_NTC,   /**< Notify driver to collect PCIE DFX information */
	COMM_MGMT_CMD_DICT_LOG_STATUS,    /**< Get log collection status */
	COMM_MGMT_CMD_MSIX_INFO,   /**< Configure MSIX information */
	COMM_MGMT_CMD_CHANNEL_DETECT,   /**< Mailbox channel detection */
	COMM_MGMT_CMD_DICT_COUNTER_STATUS,   /**< Get flash counter count */
	COMM_MGMT_CMD_UCODE_SM_COUNTER,   /**< Get SM counter count */
	COMM_MGMT_CMD_CLEAR_LOG = 132, /* 1823V100 */
	COMM_MGMT_CMD_UCODE_SM_COUNTER_PER = 133, /* 1823V100 */

	/**< Switch workmode related */
	COMM_MGMT_CMD_CHECK_IF_SWITCH_WORKMODE = 140,   /**< Configuration switch (multiple configuration files in card, deprecated) */
	COMM_MGMT_CMD_SWITCH_WORKMODE,   /**< Switch work mode (deprecated) */

	/**< MPU related */
	COMM_MGMT_CMD_MIGRATE_DFX_HPA = 150,   /**< Hot migration HPA DFX */
	COMM_MGMT_CMD_BDF_INFO,   /**< Get PCIE BDF number */
	COMM_MGMT_CMD_NCSI_CFG_INFO_GET_PROC,   /**< Get NCSI configuration information */
	COMM_MGMT_CMD_CPI_TCAM_DBG,   /**< CPI TCAM information debug (currently unused) */
	COMM_MGMT_CMD_LLDP_TX_FUNC_SET_PROC,   /**< LLDP enable */
	COMM_MGMT_CMD_FUNC_ENABLE_INFO = 155, /* 1823V100 */
	COMM_MGMT_CMD_FUNC_VIRTIO_INFO = 156, /* 1823V100 */
	COMM_MGMT_CMD_NCSI_LOW_POWER_PROC,   /* 1872V100 NCSI low power enable */

	/**< rsvd0 section */
	COMM_MGMT_CMD_SECTION_RSVD_0 = 160,
	COMM_MGMT_CMD_SWITCH_RESET_CFG,

	/**< rsvd1 section */
	COMM_MGMT_CMD_SECTION_RSVD_1 = 170,

	/**< rsvd2 section */
	COMM_MGMT_CMD_SECTION_RSVD_2 = 180,

	/**< rsvd3 section */
	COMM_MGMT_CMD_SECTION_RSVD_3 = 190,
	COMM_MGMT_CMD_GET_INDIR_TABLE,   /**< Tool read indirect table */
	COMM_MGMT_CMD_SET_INDIR_TABLE,   /**< Tool write indirect table */

	/**< Move to DFT mode */
	COMM_MGMT_CMD_GET_TDIE_ID = 199,   /**< Get totem die ID */
	COMM_MGMT_CMD_GET_UDIE_ID = 200,   /**< Get UNIC die ID */
	COMM_MGMT_CMD_GET_EFUSE_TEST,   /**< EFUSE test (currently unused) */
	COMM_MGMT_CMD_EFUSE_INFO_CFG,   /**< Program EFUSE information */
	COMM_MGMT_CMD_GPIO_CTL,   /**< GPIO test (currently unused) */
	COMM_MGMT_CMD_HI30_SERLOOP_START,    /**< HI30 start loopback */
	COMM_MGMT_CMD_HI30_SERLOOP_STOP,      /**< HI30 stop loopback */
	COMM_MGMT_CMD_HI30_MBIST_SET_FLAG,     /**< HI30 BIST test (currently unused) */
	COMM_MGMT_CMD_HI30_MBIST_GET_RESULT,   /**< HI30 get BIST test result (currently unused) */
	COMM_MGMT_CMD_ECC_TEST,   /**< Chip ECC test */
	COMM_MGMT_CMD_FUNC_BIST_TEST,    /**< Chip function BIST test */

	COMM_MGMT_CMD_VPD_SET = 210,   /**< Write VPD information to flash */
	COMM_MGMT_CMD_VPD_GET,   /**< Tool reads flash VPD information */

	COMM_MGMT_CMD_ERASE_FLASH,   /**< Erase flash (DFX version enabled) */
	COMM_MGMT_CMD_QUERY_FW_INFO,   /**< Query firmware state machine information */
	COMM_MGMT_CMD_GET_CFG_INFO,   /**< Get configuration information (function not yet enabled) */
	COMM_MGMT_CMD_GET_UART_LOG,   /**< UART redirect output */
	COMM_MGMT_CMD_SET_UART_CMD,   /**< UART redirect input */
	COMM_MGMT_CMD_SPI_TEST,   /**< SPI test (DFX version enabled) */

	COMM_MGMT_CMD_HEART_EVENT,      /**< Heartbeat detection (currently unused) */
	COMM_MGMT_CMD_NCSI_OEM_GET_DRV_INFO,   /**< Message to driver, get BDF number (scheme replaced) */
	COMM_MGMT_CMD_LASTWORD_GET,   /**< Message to driver, MPU last words */
	COMM_MGMT_CMD_READ_BIN_DATA,    /**< Get firmware bin data (deprecated) */
	COMM_MGMT_CMD_GET_REG_VAL,   /**< Read register (DFX version enabled) */
	COMM_MGMT_CMD_SET_REG_VAL,   /**< Write register (DFX version enabled) */

	/**< COMM_MGMT_CMD_WWPN_GET, TBD: move to FC? */
	/**< COMM_MGMT_CMD_WWPN_SET, TBD: move to FC? 229 */

	/**< Check if needed */
	COMM_MGMT_CMD_SET_VIRTIO_DEV = 230,   /**< Set virtio device type */
	COMM_MGMT_CMD_SET_MAC,   /**< Set hardened MAC */
	COMM_MGMT_CMD_LOAD_PATCH,   /**< Load MPU patch (deprecated) */
	COMM_MGMT_CMD_REMOVE_PATCH,   /**< Remove MPU patch (deprecated) */
	COMM_MGMT_CMD_PATCH_ACTIVE,   /**< Activate MPU patch (deprecated) */
	COMM_MGMT_CMD_PATCH_DEACTIVE,   /**< Deactivate MPU patch (deprecated) */
	COMM_MGMT_CMD_PATCH_SRAM_OPTIMIZE,   /**< Patch space refresh (deprecated) */
	COMM_MGMT_CMD_CONTAINER_HOST_PROC,   /**< Storage container scenario, set primary host */
	COMM_MGMT_CMD_NCSI_COUNTER_PROC,   /**< Get NCSI counter information */
	COMM_MGMT_CMD_CHANNEL_STATUS_CHECK,    /**< Storage scenario, channel detection */

	/**< Hot patch reserved command codes */
	COMM_MGMT_CMD_RSVD_0 = 240,   /**< Hot patch reserved command 0 */
	COMM_MGMT_CMD_RSVD_1,   /**< Hot patch reserved command 1 */
	COMM_MGMT_CMD_RSVD_2,   /**< Hot patch reserved command 2 */
	COMM_MGMT_CMD_RSVD_3,   /**< Hot patch reserved command 3 */
	COMM_MGMT_CMD_SECTION_INTEGRITY, /** Customer firmware integrity verification */

	COMM_MGMT_CMD_SEND_API_ACK_BY_UP,   /**< Invalid field, version incorporated deletion, for compilation use */

	COMM_MGMT_CMD_GET_VER_COMPATIBLE_INFO = 254,   /**< For tool version compatibility information */

	/**< Note: When adding cmd, do not modify existing command code values; please add in the preceding rsv section; ideally all branch cmd tables should be identical */
	COMM_MGMT_CMD_MAX = 255,   /**<  */
};

#endif
