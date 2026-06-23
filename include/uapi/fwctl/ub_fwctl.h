/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note*/
/*
 * Copyright(c) 2025 HiSilicon Technologies CO., Limited. All rights reserved.
 */

#ifndef _UAPI_UB_FWCTL_H_
#define _UAPI_UB_FWCTL_H_

#include <linux/types.h>

#ifndef UBFWCTL_UBENGINE
#define FWCTL_DEVICE_TYPE_UB 5
#endif

/**
 * struct fwctl_rpc_ub_in - ioctl(FWCTL_RPC) input
 * @rpc_cmd: user specified opcode
 * @data_size: Length of @data
 * @version: Version passed in by the user
 * @rsvd: reserved
 * @data: user inputs specified input data
 */
struct fwctl_rpc_ub_in {
	__u32 rpc_cmd;
	__u32 data_size;
	__u32 version;
	__u32 rsvd;
	__u32 data[] __counted_by(data_size);
};

/**
 * struct fwctl_rpc_ub_out - ioctl(FWCTL_RPC) output
 * @retval: The value returned when querying data with an error message
 * @env_version: Different environmental versions
 * @data_size: Length of @data
 * @data: data transmitted to users
 */
struct fwctl_rpc_ub_out {
	int retval;
	__u32 env_version;
	__u32 data_size;
	__u32 data[];
};

/**
 * enum ub_fwctl_cmdrpc_type - Type of access for the RPC
 *
 * Refer to fwctl.rst for a more detailed discussion of these scopes.
 */
enum ub_fwctl_cmdrpc_type {
	/**
	 * @UTOOL_CMD_QUERY_NL: Query all registers at the NL layer
	 */
	UTOOL_CMD_QUERY_NL = 0x0001,
	/**
	 * @UTOOL_CMD_QUERY_NL_PKT_STATS: Query NL layer PKT_STATE related registers
	 */
	UTOOL_CMD_QUERY_NL_PKT_STATS = 0x0002,
	/**
	 * @UTOOL_CMD_QUERY_NL_SSU_STATS: Query NL layer SSU_STATS related registers
	 */
	UTOOL_CMD_QUERY_NL_SSU_STATS = 0x0003,
	/**
	 * @UTOOL_CMD_QUERY_NL_ABN: Query NL layer NL_ABN related registers
	 */
	UTOOL_CMD_QUERY_NL_ABN = 0x0004,
	/**
	 * @UTOOL_CMD_QUERY_NL_SSU_SW: Query ssu_sw non-empty dfx statistics
	 */
	UTOOL_CMD_QUERY_NL_SSU_SW = 0x0005,
	/**
	 * @UTOOL_CMD_QUERY_NL_SSU_OQ: Query ssu_oq non-empty dfx statistics
	 */
	UTOOL_CMD_QUERY_NL_SSU_OQ = 0x0006,
	/**
	 * @UTOOL_CMD_QUERY_NL_SSU_P2P: Query ssu_p2p queue non-empty dfx statistics
	 */
	UTOOL_CMD_QUERY_NL_SSU_P2P = 0x0007,
	/**
	 * @UTOOL_CMD_CONF_NL_SSU_VL_PKT: Config NL layer ssu_vl_pkt related registers
	 */
	UTOOL_CMD_CONF_NL_SSU_VL_PKT = 0x0008,
	/**
	 * @UTOOL_CMD_QUERY_NL_SSU_VL_PKT: Query NL layer ssu_vl_pkt related registers
	 */
	UTOOL_CMD_QUERY_NL_SSU_VL_PKT = 0x0009,

	/**
	 * @UTOOL_CMD_QUERY_TP: Query all registers at the TP layer
	 */
	UTOOL_CMD_QUERY_TP = 0x0021,
	/**
	 * @UTOOL_CMD_QUERY_TP_PKT_STATS: Query TP layer PKT_STATE related registers
	 */
	UTOOL_CMD_QUERY_TP_PKT_STATS = 0x0022,
	/**
	 * @UTOOL_CMD_QUERY_TP_TX_ROUTE: Query TP layer TX_ROUTE related registers
	 */
	UTOOL_CMD_QUERY_TP_TX_ROUTE = 0x0023,
	/**
	 * @UTOOL_CMD_QUERY_TP_ABN_STATS: Query TP layer ABN_STATS related registers
	 */
	UTOOL_CMD_QUERY_TP_ABN_STATS = 0x0024,
	/**
	 * @UTOOL_CMD_QUERY_TP_RX_BANK: Query TP layer RX_BANK related registers
	 */
	UTOOL_CMD_QUERY_TP_RX_BANK = 0x0025,

	/**
	 * @UTOOL_CMD_QUERY_DL: Query all registers at the DL layer
	 */
	UTOOL_CMD_QUERY_DL = 0x0011,
	/**
	 * @UTOOL_CMD_QUERY_DL_PKT_STATS: Query DL layer PKT_STATS related registers
	 */
	UTOOL_CMD_QUERY_DL_PKT_STATS = 0x0012,
	/**
	 * @UTOOL_CMD_QUERY_DL_LINK_STATUS: Query DL layer LINK_STATUS related registers
	 */
	UTOOL_CMD_QUERY_DL_LINK_STATUS = 0x0013,
	/**
	 * @UTOOL_CMD_QUERY_DL_LANE: Query DL layer LANE related registers
	 */
	UTOOL_CMD_QUERY_DL_LANE = 0x0014,
	/**
	 * @UTOOL_CMD_QUERY_DL_BIT_ERR: Query DL layer BIT_ERR related registers
	 */
	UTOOL_CMD_QUERY_DL_BIT_ERR = 0x0015,
	/**
	 * @UTOOL_CMD_QUERY_DL_LINK_TRACE: Query DL layer LINK_TRACE related registers
	 */
	UTOOL_CMD_QUERY_DL_LINK_TRACE = 0x0016,
	/**
	 * @UTOOL_CMD_QUERY_DL_BIST: Query DL layer BIST related registers
	 */
	UTOOL_CMD_QUERY_DL_BIST = 0x0017,
	/**
	 * @UTOOL_CMD_CONF_DL_BIST: Config DL layer BIST related registers
	 */
	UTOOL_CMD_CONF_DL_BIST = 0x0018,
	/**
	 * @UTOOL_CMD_QUERY_DL_BIST_ERR: Query DL layer BIST_ERR related registers
	 */
	UTOOL_CMD_QUERY_DL_BIST_ERR = 0x0019,
	/**
	 * @UTOOL_CMD_QUERY_DL_PERFORMANCE: Query DL layer PERF related registers
	 */
	UTOOL_CMD_QUERY_DL_PERFORMANCE = 0x001A,
	/**
	 * @UTOOL_CMD_QUERY_DL_ALL_PERF: Query DL layer all the PERF related registers
	 */
	UTOOL_CMD_QUERY_DL_ALL_PERF = 0x001B,
	/**
	 * @UTOOL_CMD_QUERY_DL_RT_BANDWIDTH: Query DL layer real time bandwidth
	 */
	UTOOL_CMD_QUERY_DL_RT_BANDWIDTH = 0x001C,
	/**
	 * @UTOOL_CMD_QUERY_DL_PERF_START: Enable port traffic statistics
	 */
	UTOOL_CMD_QUERY_DL_PERF_START = 0x001D,
	/**
	 * @UTOOL_CMD_QUERY_DL_PERF: Query DL layer bandwidth registers
	 */
	UTOOL_CMD_QUERY_DL_PERF = 0x001E,
	/**
	 * @UTOOL_CMD_QUERY_DL_PERF_STOP: Disable port traffic statistics
	 */
	UTOOL_CMD_QUERY_DL_PERF_STOP = 0x001F,

	/**
	 * @UTOOL_CMD_QUERY_TA: Query all registers at the TA layer
	 */
	UTOOL_CMD_QUERY_TA = 0x0031,
	/**
	 * @UTOOL_CMD_QUERY_TA_PKT_STATS: Query TA layer PKT_STATS related registers
	 */
	UTOOL_CMD_QUERY_TA_PKT_STATS = 0x0032,
	/**
	 * @UTOOL_CMD_QUERY_TA_ABN_STATS: Query TA layer ABN_STATS related registers
	 */
	UTOOL_CMD_QUERY_TA_ABN_STATS = 0x0033,
	/**
	 * @UTOOL_CMD_QUERY_TA_WQE_TIME: Query TA layer WQE_TIME related registers
	 */
	UTOOL_CMD_QUERY_TA_WQE_TIME = 0x0034,

	/**
	 * @UTOOL_CMD_QUERY_BA: Query all registers at the BA layer
	 */
	UTOOL_CMD_QUERY_BA = 0x0041,
	/**
	 * @UTOOL_CMD_QUERY_BA_PKT_STATS: Query BA layer PKT_STATS related registers
	 */
	UTOOL_CMD_QUERY_BA_PKT_STATS = 0x0042,
	/**
	 * @UTOOL_CMD_QUERY_BA_MAR: Query BA layer MAR related registers
	 */
	UTOOL_CMD_QUERY_BA_MAR = 0x0043,
	/**
	 * @UTOOL_CMD_QUERY_BA_MAR_TABLE: Query BA layer MAR_TABLE related registers
	 */
	UTOOL_CMD_QUERY_BA_MAR_TABLE = 0x0044,
	/**
	 * @UTOOL_CMD_QUERY_BA_MAR_CYC_EN: Query BA layer MAR_CYC_EN related registers
	 */
	UTOOL_CMD_QUERY_BA_MAR_CYC_EN = 0x0045,
	/**
	 * @UTOOL_CMD_CONF_BA_MAR_CYC_EN: Config BA layer MAR_CYC_EN related registers
	 */
	UTOOL_CMD_CONF_BA_MAR_CYC_EN = 0x0046,
	/**
	 * @UTOOL_CMD_CONFIG_BA_MAR_PEFR_STATS: Config BA layer MAR_PEFR_STATS related registers
	 */
	UTOOL_CMD_CONFIG_BA_MAR_PEFR_STATS = 0x0047,
	/**
	 * @UTOOL_CMD_QUERY_BA_MAR_PEFR_STATS: Query BA layer MAR_PEFR_STATS related registers
	 */
	UTOOL_CMD_QUERY_BA_MAR_PEFR_STATS = 0x0048,

	/**
	 * @UTOOL_CMD_QUERY_QOS: Query QOS related registers
	 */
	UTOOL_CMD_QUERY_QOS = 0x0051,

	/**
	 * @UTOOL_CMD_QUERY_SCC_VERSION: Query the scc version
	 */
	UTOOL_CMD_QUERY_SCC_VERSION = 0x0061,
	/**
	 * @UTOOL_CMD_QUERY_SCC_LOG: Query the scc log
	 */
	UTOOL_CMD_QUERY_SCC_LOG = 0x0062,
	/**
	 * @UTOOL_CMD_QUERY_SCC_DEBUG_EN: Query the scc debug switch
	 */
	UTOOL_CMD_QUERY_SCC_DEBUG_EN = 0x0063,
	/**
	 * @UTOOL_CMD_CONF_SCC_DEBUG_EN: Config the scc debug switch
	 */
	UTOOL_CMD_CONF_SCC_DEBUG_EN = 0x0064,

	/**
	 * @UTOOL_CMD_QUERY_MSGQ_QUE_STATS: Query MSGQ layer QUE_STATS related registers
	 */
	UTOOL_CMD_QUERY_MSGQ_QUE_STATS = 0x0071,
	/**
	 * @UTOOL_CMD_QUERY_MSGQ_ENTRY: Query MSGQ layer ENTRY related registers
	 */
	UTOOL_CMD_QUERY_MSGQ_ENTRY = 0x0072,

	/**
	 * @UTOOL_CMD_QUERY_QUEUE: Query QUEUE information
	 */
	UTOOL_CMD_QUERY_QUEUE = 0x0073,

	/**
	 * @UTOOL_CMD_QUERY_PORT_INFO: Query information about the specified port
	 */
	UTOOL_CMD_QUERY_PORT_INFO = 0x0081,
	/**
	 * @UTOOL_CMD_QUERY_IO_DIE_PORT_INFO: Query port-related information about the specified
	 * io die
	 */
	UTOOL_CMD_QUERY_IO_DIE_PORT_INFO = 0x0082,

	/**
	 * @UTOOL_CMD_QUERY_UBOMMU: Query UBOMMU related information
	 */
	UTOOL_CMD_QUERY_UBOMMU = 0x0091,

	/**
	 * @UTOOL_CMD_QUERY_UMMU_ALL: Query all information of UMMU
	 */
	UTOOL_CMD_QUERY_UMMU_ALL = 0x00A1,
	/**
	 * @UTOOL_CMD_QUERY_UMMU_SYNC: Query information of UMMU SYNC
	 */
	UTOOL_CMD_QUERY_UMMU_SYNC = 0x00A2,
	/**
	 * @UTOOL_CMD_CONFIG_UMMU_SYNC: Config information of UMMU SYNC
	 */
	UTOOL_CMD_CONFIG_UMMU_SYNC = 0x00A3,

	/**
	 * @UTOOL_CMD_QUERY_ECC_2B: Query information of ECC 2B
	 */
	UTOOL_CMD_QUERY_ECC_2B = 0x00B1,

	/**
	 * @UTOOL_CMD_QUERY_LOOPBACK: Query information of loopback
	 */
	UTOOL_CMD_QUERY_LOOPBACK = 0x00D1,
	/**
	 * @UTOOL_CMD_CONF_LOOPBACK: Configure specified loopback mode
	 */
	UTOOL_CMD_CONF_LOOPBACK = 0x00D2,
	/**
	 * @UTOOL_CMD_QUERY_PRBS_EN: Query PRBS switch status
	 */
	UTOOL_CMD_QUERY_PRBS_EN = 0x00D3,
	/**
	 * @UTOOL_CMD_CONF_PRBS_EN: Config PRBS switch
	 */
	UTOOL_CMD_CONF_PRBS_EN = 0x00D4,
	/**
	 * @UTOOL_CMD_QUERY_PRBS_RESULT: Query PRBS error count result
	 */
	UTOOL_CMD_QUERY_PRBS_RESULT = 0x00D5,

	/**
	 * @UTOOL_CMD_QUERY_FIRMWARE_VERSION: Query firmware version
	 */
	UTOOL_CMD_QUERY_FIRMWARE_VERSION = 0x00E1,
	/**
	 * @UTOOL_CMD_QUERY_PORT_PKT_STATS: Query statistical indicators at the ub and uboe port
	 */
	UTOOL_CMD_QUERY_PORT_PKT_STATS = 0x00E2,

	/**
	 * @UTOOL_CMD_QUERY_PORT_LINK_STATS: Query the historical status of port links
	 */
	UTOOL_CMD_QUERY_PORT_LINK_STATS = 0x00F1,

	/**
	 * @UTOOL_CMD_QUERY_DUMP: Dump all register data
	 */
	UTOOL_CMD_QUERY_DUMP = 0xFFFE,

	/**
	 * @UTOOL_CMD_QUERY_MAX: Maximum Command Code
	 */
	UTOOL_CMD_QUERY_MAX,
};

/**
 * struct fwctl_pkt_in_enable - ioctl(FWCTL_RPC) input
 * @enable: The value of param '-e'
 */
struct fwctl_pkt_in_enable {
	__u8 enable;
};

/**
 * struct fwctl_pkt_in_table - ioctl(FWCTL_RPC) input
 * @port_id: The value of param '-p'
 * @table_num: Length of the table
 * @index: The value of param '-i'
 */
struct fwctl_pkt_in_table {
	__u32 port_id;
	__u32 table_num;
	__u32 index;
};

/**
 * struct fwctl_pkt_in_port - ioctl(FWCTL_RPC) input
 * @port_id: The value of param '-p'
 */
struct fwctl_pkt_in_port {
	__u32 port_id;
};

/**
 * struct fwctl_pkt_in_index - ioctl(FWCTL_RPC) input
 * @index: The value of param '-i'
 */
struct fwctl_pkt_in_index {
	__u32 index;
};

/**
 * struct fwctl_pkt_in_ummuid_value - ioctl(FWCTL_RPC) input
 * @ummu_id: The value of param '-u'
 * @value: The value of param '-e'
 */
struct fwctl_pkt_in_ummuid_value {
	__u32 ummu_id;
	__u32 value;
};

/**
 * struct fwctl_pkt_in_port_time - ioctl(FWCTL_RPC) input
 * @port_id: The value of param '-p'
 * @time: The value of param '-t'
 */
struct fwctl_pkt_in_port_time {
	__u32 port_id;
	__u32 time;
};

/**
 * struct fwctl_pkt_in_time - ioctl(FWCTL_RPC) input
 * @time: The value of param '-t'
 */
struct fwctl_pkt_in_time {
	__u32 time;
};

#endif

