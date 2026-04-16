/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#ifndef __ENUM_H__
#define __ENUM_H__

enum enum_cmd {
	ENUM_CMD_TOPO_QUERY = 0,
	ENUM_CMD_NA_CFG,
	ENUM_CMD_NA_QUERY
};

/*
 * enum pkt : enum_pkt_header + enum_pld_scan_header + reqX
 * reqX : enum_topo_query_req or enum_na_cfg_req or enum_na_query_req
 */
struct enum_pkt_header {
	/* DW0 */
	struct ub_link_header ulh;
	/* DW1-DW2 */
	struct compact_network_header cnth;
	/* DW3 */
	u16 rsv;
	u16 upi;

	/* DW4~ */
	char payload[];
};
#define ENUM_PKT_HEADER_SIZE 16

struct enum_pld_scan_header {
	/* DW0 */
	union {
		struct {
			u32 step : 8;
			u32 hops : 8;
			u32 hop_type : 4;
			u32 r : 1;
			u32 rsv : 11;
		} bits;
		u32 dw0;
	};
	/* DW1~ */
	u8 path[]; /* include forward & return, 4byte align */
};
#define ENUM_PLD_SCAN_HEADER_BASE_SIZE 4 /* exclusive path */

struct enum_pld_scan_pdu_common {
	/* DW0 */
	union {
		struct {
			union {
				u8 status;
				u8 slice_id;
			};
			u8 opcode;
			u8 cmd;
#define UB_ENUM_MNG_VERSION 0x1
			u8 version;
		} bits;
		u32 dw0;
	};
	/* DW1 */
	u32 msn : 16;
	u32 pdu_len : 8;
	u32 msgq_id : 8;
	/* DW2~DW5 */
	guid_t guid;
};
#define ENUM_PLD_SCAN_PDU_COMMON_SIZE 24

struct enum_topo_query_req {
	/* DW0~DW5 */
	struct enum_pld_scan_pdu_common common;
};
#define ENUM_TOPO_QUERY_REQ_SIZE 24

struct enum_tlv_port_info {
	/* DW0 */
	union {
		struct {
			u32 rsvd : 8;
			u32 s : 1;
			u32 b : 1;
			u32 w : 1;
			u32 t : 1;
			u32 rsvd1 : 4;
			u32 len : 8;
			u32 type : 8;
		} bits0;
		u32 dw0;
	};
	/* DW1 */
	u16 remote_port_idx;
	u16 local_port_idx;

	/* DW2 */
	u16 cur_rate;
	u16 max_rate;

	/* DW3~DW6 */
	guid_t remote_guid;
};
#define ENUM_TOPO_QUERY_RSP_PORT_SIZE 28

struct enum_topo_query_rsp {
	/* DW0~DW5 */
	struct enum_pld_scan_pdu_common common;
	/* DW6 */
	union {
		struct {
			u32 num_seg : 4;
			u32 rsv0 : 4;
			u32 lf : 1;
			u32 lp : 1;
			u32 rsv1 : 6;
			u32 mtu : 3;
			u32 rsv2 : 5;
			u32 sup_mtu : 3;
			u32 rsv3 : 5;
		} bits;
		u32 dw6;
	};
	/* DW7 */
	u32 num_lf_entries;
	/* DW8 */
	u32 num_lp_entries;
	/* DW9 */
	u16 num_ports; /* Number of ports in the current message */
	u16 total_num_ports; /* Total number of ports on the target device */
	/* DW10~ */
	struct enum_tlv_port_info port_info[];
};
#define ENUM_TOPO_QUERY_RSP_BASE_SIZE 40 /* exclusive port_info */

enum enum_tlv_type { /* M: Mandatory , O: optional */
	TLV_SLICE_INFO = 0, /* M */
	TLV_PORT_NUM = 1, /* M */
	TLV_PORT_INFO = 2, /* M */
	TLV_CAP_INFO = 4 /* M */
};

struct enum_tlv_common {
	u32 value : 16;
	u32 len : 8;
	u32 type : 8;
};

struct enum_tlv_slice_info {
	u32 slice_id : 8;
	u32 total_slice : 8;
	u32 len : 8;
	u32 type : 8;
};
#define ENUM_TLV_SLICE_INFO_SZ 4

struct enum_tlv_port_num {
	u32 total_num_ports : 16;
	u32 len : 8;
	u32 type : 8;

	u32 rsvd : 16;
	u32 num_port_tlv : 16;
};
#define ENUM_TLV_PORT_NUM_SZ 8

struct enum_tlv_cap_info {
	u32 da : 1;
	u32 rsvd0 : 7;
	u32 mtu : 3;
	u32 rsvd1 : 1;
	u32 sup_mtu : 3;
	u32 rsvd2 : 1;
	u32 len : 8;
	u32 type : 8;

	u32 class_code : 16;
	u32 rsvd3 : 16;
};
#define ENUM_TLV_CAP_INFO_SZ 8

void ub_enum_clear_ent_list(struct list_head *dev_list);
int ub_enum_entities_active(struct list_head *dev_list, int src);
int ub_enum_topo_scan_ports(struct ub_entity *uent, u16 start_port, u16 num,
			    struct list_head *dev_list, void *buf);
struct ub_entity *ub_enum_get_port_r_uent(struct ub_port *port, void *buf);
size_t calc_enum_pld_header_size(struct enum_pld_scan_header *header, bool req);
int ub_cfg_read_guid(struct ub_entity *uent, u32 *dw);
int ub_enum_bfs_route_cal(struct list_head *uent_list);
int ub_query_port_na(struct ub_entity *uent, void *buf);
int ub_query_ent_na(struct ub_entity *uent, void *buf);
int ub_enum_probe(void);
void ub_enum_remove(void);
bool ub_type_valid(struct ub_entity *uent, bool is_ctl);
void ub_entity_type_init(struct ub_entity *uent);

#endif /* __ENUM_H__ */
