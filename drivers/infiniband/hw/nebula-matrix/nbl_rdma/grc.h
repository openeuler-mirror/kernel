/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2021, NEBULARMATRIX */

#ifndef __GRC_H
#define __GRC_H

#include "main.h"

#define RDMA_NL_DATA_RESP_ERR 1
#define RDMA_NL_DATA_RESP_OK 0

#define NBL_GRC_INPUT_SIZE 64
#define NBL_GRC_OUTPUT_SIZE 64

#define NBL_GRC_INPUT_PAYLOAD_SIZE 62 /* GRC cmd input payload max length */

struct nbl_grc_work_ent {
	void *in;
	int in_size;
	void *out;
	int out_size;
	struct completion handling;
	struct completion done;
	struct work_struct work;
	struct delayed_work dwork;
	struct nbl_grc *grc;
	int ret;
	u8 status; /* 0 for cmd exec success, 1 for failed */
};

struct get_function_id_req {
	uint32_t host_id;
	uint32_t bdf_num;
};

struct free_function_id_req {
	u32 host_id;
	u32 bdf_num;
	u16 function_id;
};

struct set_hdma_vf_enable_req {
	u16 function_id;
	u8 enable;
	u8 rsv;
};

struct set_rdma_dsch_req {
	u16 function_id;
	u8 is_valid;
	u8 rsv;
	u32 host_id;
	u16 dport_id;
	u16 rsv1;
};

struct set_vfid_vsi_map_req {
	u16 function_id;
	u16 vsi_id;
	u8 valid;
	u8 rsv[3];
};

struct register_client_req {
	u16 vsi_id;
	u16 real_bdf;
	u16 function_id;
	u8 eth_id;
};

#pragma pack(1)
struct rw_dw_reg {
	u32 offset;
	u32 data;
};

struct cqp_init_req {
	u16 function_id;
	u16 enable;
	u32 cmd_max_num;
	u64 phys_addr;
};

struct notify_info_req {
	u32 host_id;
	u16 function_id;
	u16 valid;
	u64 bar0_phy_addr;
	u16 product_type;
	u16 rsv;
};

struct hw_msix_id_req {
	u32 host_vector; /* host msix vector */
	u16 function_id;
};
#pragma pack()

int nbl_grc_exec(struct nbl_pci_f *rf, void *in, int in_size, void *out,
		int out_size);
int nbl_grc_init(struct nbl_pci_f *rf);
void nbl_grc_exit(struct nbl_pci_f *rf);
int nbl_grc_write_reg(struct nbl_pci_f *rf, u32 offset, u32 var);
int nbl_grc_read_reg(struct nbl_pci_f *rf, u32 offset, u32 *var);

#endif /* __GRC_H */
