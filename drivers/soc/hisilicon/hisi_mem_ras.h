/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 */

#ifndef _HISI_MEM_RAS_H
#define _HISI_MEM_RAS_H

struct hisi_mem_mbox_client_info {
	struct mbox_client client;
	struct pcc_mbox_chan *pcc_chan;
	u64 deadline_us;
	void __iomem *pcc_comm_addr;
	struct completion done;
};

#define HISI_MEM_CAP_ACLS_EN	BIT(0)
#define HISI_MEM_CAP_SPPR_EN	BIT(1)
struct hisi_mem_dev {
	struct platform_device *pdev;
	struct hisi_mem_mbox_client_info cl_info;
	struct mutex lock;
	u8 chan_id;
	u8 mem_type;
	u8 ras_cap;
};

enum hisi_mem_ras_cmd_type {
	HISI_MEM_RAS_CAP = 1,
	HISI_MEM_RAS_ACLS = 2,
	HISI_MEM_RAS_SPPR = 3,
};

enum hisi_mem_ras_subcmd_type {
	HISI_MEM_RAS_QUERY = 0,
	HISI_MEM_RAS_DO_REPAIR = 1,
};

enum hisi_mem_type {
	MEMORY_TYPE_HBM = 0,
	MEMORY_TYPE_DDR = 1,
	MEMORY_TYPE_MAX = 2,
};

#define HISI_MEM_PCC_SHARE_MEM_BYTES_MAX	128
#define HISI_MEM_PCC_SHARE_MEM_BYTES_MIN	64
#define HISI_MEM_FW_INNER_HEAD_BYTES	4
#define HISI_MEM_REQ_HEAD_BYTES		4
#define HISI_MEM_MAX_REQ_DATA_BYTES	(HISI_MEM_PCC_SHARE_MEM_BYTES_MAX - \
					 HISI_MEM_FW_INNER_HEAD_BYTES - \
					 HISI_MEM_REQ_HEAD_BYTES)
#define HISI_MEM_MAX_REQ_DATA_SIZE_MAX	(HISI_MEM_MAX_REQ_DATA_BYTES / 4)

#define HISI_MEM_RSP_HEAD_BYTES		4
#define HISI_MEM_MAX_RSP_DATA_BYTES	(HISI_MEM_PCC_SHARE_MEM_BYTES_MAX - \
					 HISI_MEM_FW_INNER_HEAD_BYTES - \
					 HISI_MEM_RSP_HEAD_BYTES)
#define HISI_MEM_MAX_RSP_DATA_SIZE_MAX	(HISI_MEM_MAX_RSP_DATA_BYTES / 4)

struct hisi_mem_req_head {
	u8 subcmd;
	u8 rsv[3];
};

/*
 * Note: Actual available size of data field also depands on the PCC header
 * bytes of the specific type. Driver needs to copy the request data to the
 * communication space based on the real length.
 */
struct hisi_mem_req_desc {
	struct hisi_mem_req_head req_head;
	u32 data[HISI_MEM_MAX_REQ_DATA_SIZE_MAX];
};

#define HISI_MEM_RAS_OK			0
#define HISI_MEM_RAS_NO_RES		1
#define HISI_MEM_RAS_REPAIR_FAIL	2
#define HISI_MEM_RAS_EINVAL		3
#define HISI_MEM_RAS_ENXIO		4
struct hisi_mem_rsp_head {
	u8 ret_status; /* 0: success, other: failure */
	u8 mem_type; /* 0: HBM, 1: DDR, other: reserved */
	u8 ras_cap; /* bit0: ACLS, bit1: SPPR, other: reserved */
	u8 rsv;
};

/*
 * Note: Actual available size of data field also depands on the PCC header
 * bytes of the specific type. Driver needs to copy the response data in the
 * communication space based on the real length.
 */
struct hisi_mem_rsp_desc {
	struct hisi_mem_rsp_head rsp_head;
	u32 data[HISI_MEM_MAX_RSP_DATA_SIZE_MAX];
};

struct hisi_mem_fw_inner_head {
	u8 cmd_type;
	u8 msg_len;
	u8 status;
	u8 need_resp;
};

struct hisi_mem_desc {
	struct hisi_mem_fw_inner_head fw_inner_head; /* 4 Bytes */
	union {
		struct hisi_mem_req_desc req;
		struct hisi_mem_rsp_desc rsp;
	};
};

#endif
