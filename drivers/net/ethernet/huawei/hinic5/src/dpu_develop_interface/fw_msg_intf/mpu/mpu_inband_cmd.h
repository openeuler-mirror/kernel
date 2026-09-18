/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : mpu_inband_cmd.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/09/16
 * Description   : In-band commands between the driver and the MPU
 */

#ifndef MPU_INBAND_CMD_H
#define MPU_INBAND_CMD_H

/**< COMM Commands between Driver to MPU */
enum hinic5_mgmt_cmd {
	/**< flr and resource cleanup related commands */
	COMM_MGMT_CMD_FUNC_RESET = 0,   /**< Driver load/unload function reset to clear resources */
	COMM_MGMT_CMD_FEATURE_NEGO,   /**< fw and driver compatibility attribute negotiation */
	COMM_MGMT_CMD_FLUSH_DOORBELL,   /**< Driver unload flush process, clear resources */
	COMM_MGMT_CMD_START_FLUSH,   /**< Driver load/unload flush handshake */
	COMM_MGMT_CMD_SET_FUNC_FLR,   /**< Driver actively triggers flr through mbox process */
	COMM_MGMT_CMD_GET_GLOBAL_ATTR,   /**< Get sm global table */
	COMM_MGMT_CMD_SET_PPF_FLR_TYPE,   /**< Set ppf flr execution scope */
	COMM_MGMT_CMD_SET_FUNC_SVC_USED_STATE,   /**< Set whether the corresponding function driver is loaded/used */
	COMM_MGMT_CMD_GET_FUNC_FLR_INFO,   /**< Get flr execution dfx information */

	/**< Driver interrupt resources */
	COMM_MGMT_CMD_CFG_MSIX_NUM = 10,   /**< Get driver msix interrupt information */

	/**< Driver-related configuration commands */
	COMM_MGMT_CMD_SET_CMDQ_CTXT = 20,   /**< Set cmdq cxt */
	COMM_MGMT_CMD_SET_VAT,   /**< Set vat table */
	COMM_MGMT_CMD_CFG_PAGESIZE,   /**< Configure root cxt page size */
	COMM_MGMT_CMD_CFG_MSIX_CTRL_REG,   /**< Configure interrupt msix */
	COMM_MGMT_CMD_SET_CEQ_CTRL_REG,   /**< Configure ceq */
	COMM_MGMT_CMD_SET_DMA_ATTR,   /**< Configure driver dma attributes */
	COMM_MGMT_CMD_SET_ENHANCE_CMDQ_CTXT,   /**< Configure enhanced cmdq */
	COMM_MGMT_CMD_GET_FUNC_SECURE_MEM,   /**< Get secure memory identifier */
	COMM_MGMT_CMD_SET_FUNC_PLUG_SRV,   /**< Set hot-plug bmp */
	COMM_MGMT_CMD_GET_FUNC_PLUG_SRV,   /**< Get hot-plug bmp */
	COMM_MGMT_CMD_SET_PPF_TBL_HTR_FLG,   /**< Set hot replacement flag */
	COMM_MGMT_CMD_GET_FAST_MSG_CAP,   /**< Get fast msg capability */
	COMM_MGMT_CMD_SET_FAST_MSG_RQ_ADDR,   /**< Set fast msg address */
	COMM_MGMT_CMD_CLEAR_FAST_MSG_SML,   /**< Clear fast msg table entry */

	/**< INFRA configuration related command words */
	COMM_MGMT_CMD_GET_MQM_FIX_INFO = 40,   /**< mqm get chunk num */
	COMM_MGMT_CMD_SET_MQM_CFG_INFO,   /**< Receive ppf and page_size from driver */
	COMM_MGMT_CMD_SET_MQM_SRCH_GPA,   /**< Receive search gpa address from driver */
	COMM_MGMT_CMD_SET_PPF_TMR,   /**< Configure smf timer */
	COMM_MGMT_CMD_SET_HT_GPA,   /**< Set ht gpa (bank gpa) address */
	COMM_MGMT_CMD_SET_FUNC_TMR_BITMAT,   /**< Enable smf timer */
	COMM_MGMT_CMD_SET_MBX_CRDT,   /**< Set mbox credit, used for dfx performance tuning */
	COMM_MGMT_CMD_CFG_TEMPLATE,   /**< Set/Get temperature alarm threshold */
	COMM_MGMT_CMD_SET_MQM_LIMIT,   /**< Set/Get mqm rate limit configuration, used by 1823V100 Pangu driver. */
	COMM_MGMT_CMD_SET_BAT_INFO,   /**< Set bat information */
	COMM_MGMT_CMD_SET_VIO_EN, /**< Set cpi MSI enable*/
	COMM_MGMT_CMD_CFG_DATA, /**< Configure Function-related parameters in the template */

	/**< Information acquisition related command words */
	COMM_MGMT_CMD_GET_FW_VERSION = 60,   /**< Get fw version information */
	COMM_MGMT_CMD_GET_BOARD_INFO,   /**< Get board information */
	COMM_MGMT_CMD_SYNC_TIME,   /**< Sync driver timestamp */
	COMM_MGMT_CMD_GET_HW_PF_INFOS,   /**< Get hardware pf information */
	COMM_MGMT_CMD_SEND_BDF_INFO,   /**< Receive dbf information obtained by driver */
	COMM_MGMT_CMD_GET_VIRTIO_BDF_INFO,   /**< Get dbf information in virtio scenario */
	COMM_MGMT_CMD_GET_SML_TABLE_INFO,   /**< Get smlb table entry information */
	COMM_MGMT_CMD_GET_SDI_INFO,   /**< Get sdi information (bare metal/virtual machine) */
	COMM_MGMT_CMD_ROOT_CTX_LOAD,   /**< Get root cxt information */
	COMM_MGMT_CMD_GET_HW_BOND = 69, /* 1823V100 */
	COMM_MGMT_CMD_MPU_AND_NPU_VER = 70, /* 1823V100 */
	COMM_MGMT_CMD_GET_PF_BY_FUNC = 71, /* 1823V100 */
	COMM_MGMT_CMD_GET_PF_BUS_BY_DEV = 72, /* 1823V100 */

	/**< Upgrade related command words */
	COMM_MGMT_CMD_UPDATE_FW = 80,   /**< fw upgrade */
	COMM_MGMT_CMD_ACTIVE_FW,   /**< fw cold activation */
	COMM_MGMT_CMD_HOT_ACTIVE_FW,   /**< fw hot activation */
	COMM_MGMT_CMD_HOT_ACTIVE_DONE_NOTICE,   /**< fw hot activation complete (currently unused) */
	COMM_MGMT_CMD_SWITCH_CFG,   /**< Configuration file switch (currently unused) */
	COMM_MGMT_CMD_CHECK_FLASH,   /**< Storage scenario flash silent detection */
	COMM_MGMT_CMD_CHECK_FLASH_RW,   /**< Storage scenario before upgrade */
	COMM_MGMT_CMD_RESOURCE_CFG,   /**< Original configuration template (currently unused) */
	COMM_MGMT_CMD_UPDATE_BIOS,   /**< bios upgrade command (deprecated, bios upgrade and NIC upgrade merged) */
	COMM_MGMT_CMD_MPU_GIT_CODE,   /**< Get version git number */
	COMM_MGMT_QUERY_MODULE_IMAGES,   /**< Image handshake, get firmware information */
	COMM_MGMT_CMD_UPDATE_CUSTOM_FW = 98,  /* Upgrade CUSTOM_FW firmware, this value cannot be modified */
	COMM_MGMT_CMD_ACTIVE_CUSTOM_FW = 99,  /* Activate CUSTOM_FW firmware */

	/**< chip reset related */
	COMM_MGMT_CMD_FAULT_REPORT = 100,   /**< Message from mpu to driver, exception alarm */
	COMM_MGMT_CMD_WATCHDOG_INFO,   /**< Message from mpu to driver, watchdog alarm */
	COMM_MGMT_CMD_MGMT_RESET,   /**< Message from mpu to driver, mpu LastWord */
	COMM_MGMT_CMD_FFM_SET,    /**< Message from mpu to driver, exception interrupt display information */

	/**< chip info/log related */
	COMM_MGMT_CMD_GET_LOG = 120,   /**< Get firmware log */
	COMM_MGMT_CMD_TEMP_OP,   /**< Get chip temperature */
	COMM_MGMT_CMD_EN_AUTO_RST_CHIP,   /**< Enable chip to auto reset following perst reset */
	COMM_MGMT_CMD_CFG_REG,   /**< Configure chip register (currently unused) */
	COMM_MGMT_CMD_GET_CHIP_ID,   /**< Get chip id (multi-chip scenario) */
	COMM_MGMT_CMD_SYSINFO_DFX,   /**< Get chip software system dfx information */
	COMM_MGMT_CMD_PCIE_DFX_NTC,   /**< Notify driver to collect pcie dfx information */
	COMM_MGMT_CMD_DICT_LOG_STATUS,    /**< Get log collection status */
	COMM_MGMT_CMD_MSIX_INFO,   /**< Configure msix information */
	COMM_MGMT_CMD_CHANNEL_DETECT,   /**< mbox channel detect */
	COMM_MGMT_CMD_DICT_COUNTER_STATUS,   /**< Get flash counter count */
	COMM_MGMT_CMD_UCODE_SM_COUNTER,   /**< Get sm counter count */
	COMM_MGMT_CMD_CLEAR_LOG = 132, /* 1823V100 */
	COMM_MGMT_CMD_UCODE_SM_COUNTER_PER = 133, /* 1823V100 */

	/**< switch workmode related */
	COMM_MGMT_CMD_CHECK_IF_SWITCH_WORKMODE = 140,   /**< Configuration switch (multiple configuration files in card, deprecated) */
	COMM_MGMT_CMD_SWITCH_WORKMODE,   /**< Switch work mode (deprecated) */

	/**< mpu related */
	COMM_MGMT_CMD_MIGRATE_DFX_HPA = 150,   /**< Hot migration hpa dfx */
	COMM_MGMT_CMD_BDF_INFO,   /**< Get pcie bdf number */
	COMM_MGMT_CMD_NCSI_CFG_INFO_GET_PROC,   /**< Get ncsi configuration information */
	COMM_MGMT_CMD_CPI_TCAM_DBG,   /**< cpi tcam information debug (currently unused) */
	COMM_MGMT_CMD_LLDP_TX_FUNC_SET_PROC,   /**< lldp enable */
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
	COMM_MGMT_CMD_GET_INDIR_TABLE,   /**< tool read indirect table */
	COMM_MGMT_CMD_SET_INDIR_TABLE,   /**< tool write indirect table */

	/**< move to DFT mode */
	COMM_MGMT_CMD_GET_TDIE_ID = 199,   /**< Get totem die id */
	COMM_MGMT_CMD_GET_UDIE_ID = 200,   /**< Get unic die id */
	COMM_MGMT_CMD_GET_EFUSE_TEST,   /**< efuse test (currently unused) */
	COMM_MGMT_CMD_EFUSE_INFO_CFG,   /**< Burn efuse information */
	COMM_MGMT_CMD_GPIO_CTL,   /**< gpio test (currently unused) */
	COMM_MGMT_CMD_HI30_SERLOOP_START,    /**< hi30 start loopback */
	COMM_MGMT_CMD_HI30_SERLOOP_STOP,      /**< hi30 stop loopback */
	COMM_MGMT_CMD_HI30_MBIST_SET_FLAG,     /**< hi30 bist test (currently unused) */
	COMM_MGMT_CMD_HI30_MBIST_GET_RESULT,   /**< hi30 get bist test result (currently unused) */
	COMM_MGMT_CMD_ECC_TEST,   /**< Chip ecc test */
	COMM_MGMT_CMD_FUNC_BIST_TEST,    /**< Chip function bist test */

	COMM_MGMT_CMD_VPD_SET = 210,   /**< Write vpd information to flash */
	COMM_MGMT_CMD_VPD_GET,   /**< Tool reads flash vpd information */

	COMM_MGMT_CMD_ERASE_FLASH,   /**< Erase flash (enabled in dfx version) */
	COMM_MGMT_CMD_QUERY_FW_INFO,   /**< Query firmware state machine information */
	COMM_MGMT_CMD_GET_CFG_INFO,   /**< Get configuration information (feature not enabled yet) */
	COMM_MGMT_CMD_GET_UART_LOG,   /**< Serial port redirect output */
	COMM_MGMT_CMD_SET_UART_CMD,   /**< Serial port redirect input */
	COMM_MGMT_CMD_SPI_TEST,   /**< spi test (enabled in dfx version) */

	COMM_MGMT_CMD_HEART_EVENT,      /**< Heartbeat detection (currently unused) */
	COMM_MGMT_CMD_NCSI_OEM_GET_DRV_INFO,   /**< Message to driver, get bdf number (solution replaced) */
	COMM_MGMT_CMD_LASTWORD_GET,   /**< Message to driver, mpu last word */
	COMM_MGMT_CMD_READ_BIN_DATA,    /**< Get firmware bin data (deprecated) */
	COMM_MGMT_CMD_GET_REG_VAL,   /**< Read register (enabled in dfx version) */
	COMM_MGMT_CMD_SET_REG_VAL,   /**< Write register (enabled in dfx version) */

	/**< COMM_MGMT_CMD_WWPN_GET, TBD: move to FC? */
	/**< COMM_MGMT_CMD_WWPN_SET, TBD: move to FC? 229 */

	/**< check if needed */
	COMM_MGMT_CMD_SET_VIRTIO_DEV = 230,   /**< Set vitro device type */
	COMM_MGMT_CMD_SET_MAC,   /**< Set fixed mac */
	COMM_MGMT_CMD_LOAD_PATCH,   /**< load mpu patch (deprecated) */
	COMM_MGMT_CMD_REMOVE_PATCH,   /**< Remove mpu patch (deprecated) */
	COMM_MGMT_CMD_PATCH_ACTIVE,   /**< Activate mpu patch (deprecated) */
	COMM_MGMT_CMD_PATCH_DEACTIVE,   /**< Deactivate mpu patch (deprecated) */
	COMM_MGMT_CMD_PATCH_SRAM_OPTIMIZE,   /**< Patch space refresh (deprecated) */
	COMM_MGMT_CMD_CONTAINER_HOST_PROC,   /**< Storage container scenario, set master host */
	COMM_MGMT_CMD_NCSI_COUNTER_PROC,   /**< Get ncsi counter information */
	COMM_MGMT_CMD_CHANNEL_STATUS_CHECK,    /**< Storage scenario, channel detection */

	/**< Hot patch reserved command words */
	COMM_MGMT_CMD_RSVD_0 = 240,   /**< Hot patch reserved command 0 */
	COMM_MGMT_CMD_RSVD_1,   /**< Hot patch reserved command 1 */
	COMM_MGMT_CMD_RSVD_2,   /**< Hot patch reserved command 2 */
	COMM_MGMT_CMD_RSVD_3,   /**< Hot patch reserved command 3 */
	COMM_MGMT_CMD_SECTION_INTEGRITY, /**Customer firmware integrity verification */

	COMM_MGMT_CMD_SEND_API_ACK_BY_UP,   /**< Invalid field, version consolidation removed, used for compilation */

	COMM_MGMT_CMD_GET_VER_COMPATIBLE_INFO = 254,   /**< for tool ver compatible info */

	/**< Note: To add a cmd, do not modify the value of existing command words. Please add in the rsv section above; in principle, the cmd tables of all branches are completely identical */
	COMM_MGMT_CMD_MAX = 255,   /**<  */
};

#endif
