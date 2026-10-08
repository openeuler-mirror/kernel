/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2024 nebula-matrix Limited.
 * Author:
 */

#ifndef _GRC_COMMON_V2_H_
#define _GRC_COMMON_V2_H_

#include <rdma/ib_verbs.h>

#include "nbl_cqp_fmt_v2.h"

#define MAX_SRC_ADDR_SIZE_V2 1024 /* SRC ADDR table depth */
#define NBL_SRC_ADDR_INDEX_SEQ_NUM_MAX 16
#define NBL_SRC_IP_SIZE 16
#define NBL_SRC_MAC_SIZE 6

#define NBL_MAX_DEVX_UMEM (1 << 25)

enum grc_msg_op_code {
	GRC_MSG_OP_GET_FUNCTION_ID = 1,
	GRC_MSG_OP_SET_VOA = 2,
	GRC_MSG_OP_SET_SD_RANGE = 3,
	GRC_MSG_OP_GET_INIT_PARAM = 4,
	GRC_MSG_OP_ADD_STAT_ID = 5,
	GRC_MSG_OP_DESTROY_VOA = 6,
	GRC_MSG_OP_GET_SD_RANGE = 7,
	GRC_MSG_OP_GET_VOA_TBL = 8,
	GRC_MSG_OP_FREE_FUNC_ID = 9,
	GRC_MSG_OP_WRITE_REG = 10,
	GRC_MSG_OP_READ_REG = 11,
	GRC_MSG_OP_CQP_INIT = 12,
	GRC_MSG_OP_ADD_SRC_ADDR_INFO = 13,
	GRC_MSG_OP_DEL_SRC_ADDR_INFO = 14,
	GRC_MSG_OP_RESERVED1 = 15,
	GRC_MSG_OP_SEND_SRC_ADDR_INFO = 16,
	GRC_MSG_OP_STAT_ID_ADD = 17,
	GRC_MSG_OP_STAT_ID_DEL = 18,
	GRC_MSG_OP_STAT_ID_MOD = 19,
	GRC_MSG_OP_USED_CNT_GET = 20,
	GRC_MSG_OP_HW_STAT_GET = 21,
	GRC_MSG_OP_HW_STAT_CLEAR = 22,
	GRC_MSG_OP_ERRCODE_EN = 23,
	GRC_MSG_OP_SET_NOTIFY_INFO = 24,
	GRC_MSG_OP_HW_MISX_ID_REQ = 25,
	GRC_MSG_OP_SET_DSCH = 26,
	GRC_MSG_OP_CC_REG_SET = 27,
	GRC_MSG_OP_SET_VF_ENABLE = 28,
	GRC_MSG_OP_SET_VFID_VSI_MAP = 29,
	GRC_MSG_OP_GET_GLO_MSIX_IDX = 30,
	GRC_MSG_OP_ENA_RDMA_INTRL = 31,
	GRC_MSG_OP_UPDATE_DSCH = 32,
	GRC_MSG_OP_REGISTER_CLIENT = 33,
	GRC_MSG_OP_UNREGISTER_CLIENT = 34,
	GRC_MSG_OP_QUERY_FMR_NOFENCE = 35,
	GRC_MSG_OP_GET_COMM_ID = 36,
	GRC_MSG_OP_PUT_COMM_ID = 37,
	GRC_MSG_OP_SET_GLO_Q_VF_PF_MAP = 38,
	GRC_MSG_OP_GET_SRC_ADDR_INFO = 39,
	GRC_MSG_OP_GET_ARMCQ_FLUSH_STATUS = 40,
	GRC_MSG_OP_SET_VF_DUMP_CFG = 41,
	GRC_MSG_OP_GRC_CQP_CMD = 42,
	GRC_MSG_OP_CHK_GID_IN_SRC_ADDR = 43,
	GRC_MSG_OP_UPDATE_IDX_SRC_ADDR = 44,
	GRC_MSG_OP_CLEAR_CACHE = 45,
	GRC_MSG_OP_PRINT_SRC_ADDR_TBL = 46,
	GRC_MSG_OP_MAX,
};

/* src add related begin */
struct nbl_grc_update_idx_src_addr_info_req {
	u16 src_addr_index;
	u16 sgid_idx;
};

struct nbl_grc_send_src_addr_info_req {
	u16 src_addr_index;
	u8 smac[6];
	u8 sip[16];
	u16 function_id;
	u16 sgid_idx;
};

struct nbl_grc_del_src_addr_info_req {
	u16 src_addr_index;
	u16 function_id;
	u16 sgid_idx;
	u16 rsv;
};

struct nbl_get_src_addr_info_req {
	u16 function_id;
	u16 sgid_idx;
};

struct nbl_get_src_addr_info_resp {
	u16 src_addr_index;
	u8 sip[16];
	u8 seq_num;
	u8 rsv;
};

struct nbl_chk_src_addr_info_req {
	u16 function_id;
	union ib_gid ib_gid;
};

struct nbl_chk_src_addr_info_resp {
	u8 found;
	u8 rsv[3];
};

struct set_vf_dump_req {
	u16 vsi_id;
	u16 rx_vlan_vsi_id[4];
	u16 function_id;
	u8 enable_flag;
	u8 is_lag;
};

struct notify_info_req {
	u32 host_id;
	u16 function_id;
	u16 valid;
	u64 bar0_phy_addr;
	u16 product_type;
	u16 pcie_fn_id;
};

struct nbl_src_addr_tbl {
	u16 function_id;
	u16 sgid_index;
	u8 sgid[NBL_SRC_IP_SIZE];
	u8 seq_num; /* record the usage count of src_addr_index */
	u8 rsv[3];
};

struct nbl_src_addr_rsrc {
	spinlock_t addr_tbl_lock;
	struct nbl_src_addr_tbl addr_tbl[MAX_SRC_ADDR_SIZE_V2];
};
/* src add related end */

struct register_client_req {
	u16 vsi_id;
	u16 real_bdf;
	u16 function_id;
	u16 eth_id;
};

struct clear_cache_req {
	u32 cache_type;
};

struct print_grc_src_addr_tbl_req {
	u32 print_cnt;
};

#define RDMA_DUMP_MIRROR_ID 120
#define RDMA_DUMP_MIRROR_ID_MAX_NUM 8 /* total mirror_ids is 128, ppe already use 120 */
#define NBL_GET_MIRROR_ID(function_id)  (RDMA_DUMP_MIRROR_ID + \
					 (function_id) % RDMA_DUMP_MIRROR_ID_MAX_NUM)
#endif /* _GRC_COMMON_V2_H_ */
