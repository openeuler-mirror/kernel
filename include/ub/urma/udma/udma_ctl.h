/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright(c) 2025 HiSilicon Technologies CO., Ltd. All rights reserved. */

#ifndef _UB_UMDK_URMA_UDMA_UDMA_CTL_H_
#define _UB_UMDK_URMA_UDMA_UDMA_CTL_H_

#include <ub/urma/ubcore_api.h>

#define UDMA_BUS_INSTANCE_SEID_SIZE		4
#define UDMA_EID_PAIRS_COUNT			8
#define UDMA_QUERY_ALL_AUX_INFO			0xFFFFFFFFU

union udma_k_jfs_flag {
	struct {
		uint32_t sq_cstm          : 1;
		uint32_t db_cstm          : 1;
		uint32_t db_ctl_cstm      : 1;
		uint32_t reserved         : 29;
	} bs;
	uint32_t value;
};

struct udma_que_cfg_ex {
	uint32_t buff_size;
	void *buff;
};

struct udma_jfs_cstm_cfg {
	struct udma_que_cfg_ex sq; /* PA; should be converted by phys_to_virt. */
};

struct udma_jfs_cfg_ex {
	struct ubcore_jfs_cfg base_cfg;
	struct ubcore_udata udata;
	struct udma_jfs_cstm_cfg cstm_cfg;
	ubcore_event_callback_t jfae_handler;
};

struct udma_jfc_cstm_cfg {
	struct udma_que_cfg_ex cq; /* PA; should be using stars hw register addr. */
};

struct udma_jfc_cfg_ex {
	struct ubcore_jfc_cfg base_cfg;
	struct ubcore_udata udata;
	struct udma_jfc_cstm_cfg cstm_cfg;
	ubcore_comp_callback_t jfce_handler;
	ubcore_event_callback_t jfae_handler;
};

enum udma_jfc_type {
	UDMA_NORMAL_JFC_TYPE,
	UDMA_STARS_JFC_TYPE,
	UDMA_CCU_JFC_TYPE,
	UDMA_KERNEL_STARS_JFC_TYPE,
	UDMA_UCP_JFC_TYPE,
	UDMA_JFC_TYPE_NUM,
};

struct udma_set_cqe_ex {
	uint64_t addr;
	uint32_t len;
	enum udma_jfc_type jfc_type;
};

struct udma_ue_info_ex {
	uint16_t ue_id;
	uint32_t chip_id;
	uint32_t die_id;
	uint32_t offset_len;
	resource_size_t db_base_addr;
	resource_size_t dwqe_addr;
	resource_size_t register_base_addr;
};

struct udma_tp_sport_in {
	uint32_t tpn;
};

struct udma_tp_sport_out {
	uint32_t data_udp_srcport;
	uint32_t ack_udp_srcport;
};

struct udma_cqe_info_in {
	enum ubcore_cr_status status;
	uint8_t s_r;
	KABI_RESERVE(1)
	KABI_RESERVE(2)
	KABI_RESERVE(3)
	KABI_RESERVE(4)
};

enum udma_cqe_aux_info_type {
	TPP2TQEM_WR_CNT,
	DEVICE_RAS_STATUS_2,
	RXDMA_WR_PAYL_AXI_ERR,
	RXDMA_HEAD_SPLIT_ERR_FLAG0,
	RXDMA_HEAD_SPLIT_ERR_FLAG1,
	RXDMA_HEAD_SPLIT_ERR_FLAG2,
	RXDMA_HEAD_SPLIT_ERR_FLAG3,
	TP_RCP_INNER_ALM_FOR_CQE,
	TWP_AE_DFX_FOR_CQE,
	PA_OUT_PKT_ERR_CNT,
	TP_DAM_AXI_ALARM,
	TP_DAM_VFT_BT_ALARM,
	TP_EUM_AXI_ALARM,
	TP_EUM_VFT_BT_ALARM,
	TP_TPMM_AXI_ALARM,
	TP_TPMM_VFT_BT_ALARM,
	TP_TPGCM_AXI_ALARM,
	TP_TPGCM_VFT_BT_ALARM,
	TWP_ALM,
	TP_RWP_INNER_ALM_FOR_CQE,
	TWP_DFX21,
	LQC_TA_RNR_TANACK_CNT,
	FVT,
	RQMT0,
	RQMT1,
	RQMT2,
	RQMT3,
	RQMT4,
	RQMT5,
	RQMT6,
	RQMT7,
	RQMT8,
	RQMT9,
	RQMT10,
	RQMT11,
	RQMT12,
	RQMT13,
	RQMT14,
	RQMT15,
	PROC_ERROR_ALM,
	LQC_TA_TIMEOUT_TAACK_CNT,
	TP_RRP_ERR_FLG_0_FOR_CQE,
	MAX_CQE_AUX_INFO_TYPE_NUM
};

struct udma_cqe_aux_info_out {
	enum udma_cqe_aux_info_type *aux_info_type;
	uint32_t *aux_info_value;
	uint32_t aux_info_num;
	KABI_RESERVE(1)
	KABI_RESERVE(2)
	KABI_RESERVE(3)
	KABI_RESERVE(4)
};

struct udma_ae_info_in {
	uint32_t event_type;
	KABI_RESERVE(1)
	KABI_RESERVE(2)
	KABI_RESERVE(3)
	KABI_RESERVE(4)
};

struct udma_cqe_aux_info_type_arr {
	enum udma_cqe_aux_info_type *type_list;
	uint8_t type_len; /* 0: invalid type, MAX: dump all type */
};

enum udma_ae_aux_info_type {
	TP_RRP_FLUSH_TIMER_PKT_CNT,
	TPP_DFX5,
	TWP_AE_DFX_FOR_AE,
	TP_RRP_ERR_FLG_0_FOR_AE,
	TP_RRP_ERR_FLG_1,
	TP_RWP_INNER_ALM_FOR_AE,
	TP_RCP_INNER_ALM_FOR_AE,
	LQC_TA_TQEP_WQE_ERR,
	LQC_TA_CQM_CQE_INNER_ALARM,
	MAX_AE_AUX_INFO_TYPE_NUM
};

struct udma_ae_aux_info_out {
	enum udma_ae_aux_info_type *aux_info_type;
	uint32_t *aux_info_value;
	uint32_t aux_info_num;
};

struct udma_ae_aux_info_type_arr {
	enum udma_ae_aux_info_type *type_list;
	uint8_t type_len;
};

enum udma_user_ctl_opcode {
	UDMA_USER_CTL_CREATE_JFS_EX,
	UDMA_USER_CTL_DELETE_JFS_EX,
	UDMA_USER_CTL_CREATE_JFC_EX,
	UDMA_USER_CTL_DELETE_JFC_EX,
	UDMA_USER_CTL_SET_CQE_ADDR,
	UDMA_USER_CTL_QUERY_UE_INFO,
	UDMA_USER_CTL_GET_DEV_RES_RATIO,
	UDMA_USER_CTL_NPU_REGISTER_INFO_CB,
	UDMA_USER_CTL_NPU_UNREGISTER_INFO_CB,
	UDMA_USER_CTL_QUERY_TP_SPORT,
	UDMA_USER_CTL_QUERY_CQE_AUX_INFO,
	UDMA_USER_CTL_QUERY_AE_AUX_INFO,
	UDMA_USER_CTL_QUERY_UBMEM_INFO,
	UDMA_USER_CTL_QUERY_PAIR_DEVNUM,
	UDMA_USER_CTL_QUERY_HOST_UBMEM_INFO,
	UDMA_USER_CTL_MAX,
};

struct udma_ctrlq_event_nb {
	uint8_t	opcode;
	int	(*crq_handler)(struct ubcore_device *dev, void *data, uint16_t len);
};

struct udma_dev_pair_info {
	uint32_t peer_dev_id;
	uint32_t slot_id;
	uint32_t pair_num;
	struct {
		uint32_t local_eid[UDMA_BUS_INSTANCE_SEID_SIZE];
		uint32_t remote_eid[UDMA_BUS_INSTANCE_SEID_SIZE];
		uint32_t flag : 16;
		uint32_t hop : 4;
		uint32_t rsv : 12;
	} eid_pairs[UDMA_EID_PAIRS_COUNT];
};

static inline bool udma_check_base_param(uint64_t addr, uint32_t in_len, uint32_t len)
{
	return (addr == 0 || in_len != len);
}

typedef int (*udma_user_ctl_ops)(struct ubcore_device *dev, struct ubcore_ucontext *uctx,
				 struct ubcore_user_ctl_in *in, struct ubcore_user_ctl_out *out);

int udma_user_ctl(struct ubcore_device *dev, struct ubcore_user_ctl *k_user_ctl);
int udma_query_cqe_aux_info(struct ubcore_device *dev, struct ubcore_ucontext *uctx,
			    struct ubcore_user_ctl_in *in, struct ubcore_user_ctl_out *out);
int udma_query_ae_aux_info(struct ubcore_device *dev, struct ubcore_ucontext *uctx,
			   struct ubcore_user_ctl_in *in, struct ubcore_user_ctl_out *out);

#endif /* _UB_UMDK_URMA_UDMA_UDMA_CTL_H_ */
