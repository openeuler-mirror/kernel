/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __RDFX_HW_V2__
#define __RDFX_HW_V2__

#define CNT_SNAP_PARAM_DATA_0_CNT_CLR_CE_S 0
#define CNT_SNAP_PARAM_DATA_0_SNAP_EN_S 1

struct rdfx_query_mbdb_cnt {
	__le32 mailbox_issue_cnt;
	__le32 mailbox_exe_cnt;
	__le32 doorbell_issue_cnt;
	__le32 doorbell_exe_cnt;
	__le32 eq_doorbell_issue_cnt;
	__le32 eq_doorbell_exe_cnt;
};

struct rdfx_query_mdb_dfx {
	__le32 empty_info;
	__le32 data_1;
	__le32 rsv[2];
};

#define QUERY_MDB_DFX_EMPTY_INFO_EQDB_EMPTY_S	0

#define QUERY_MDB_DFX_EMPTY_INFO_MB_EMPTY_S	1
#define QUERY_MDB_DFX_EMPTY_INFO_MB_EMPTY_M \
	(((1UL << 6) - 1) << QUERY_MDB_DFX_EMPTY_INFO_MB_EMPTY_S)

#define QUERY_MDB_DFX_EMPTY_INFO_DB_EMPTY_S	7
#define QUERY_MDB_DFX_EMPTY_INFO_DB_EMPTY_M \
	(((1UL << 4) - 1) << QUERY_MDB_DFX_EMPTY_INFO_DB_EMPTY_S)

#define QUERY_MDB_DFX_DATA_1_EQDB_FULL_S	0

#define QUERY_MDB_DFX_DATA_1_MB_FULL_S		1
#define QUERY_MDB_DFX_DATA_1_MB_FULL_M \
	(((1UL << 6) - 1) << QUERY_MDB_DFX_DATA_1_MB_FULL_S)

#define QUERY_MDB_DFX_DATA_1_DB_FULL_S		7
#define QUERY_MDB_DFX_DATA_1_DB_FULL_M \
	(((1UL << 4) - 1) << QUERY_MDB_DFX_DATA_1_DB_FULL_S)

#define QUERY_MDB_DFX_DATA_1_DB_CMD_ERR_S	11
#define QUERY_MDB_DFX_DATA_1_MB_CMD_ERR_S	12

#endif
