/* SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB) */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _MGR_H
#define _MGR_H

/* pcie function_id */
#define VF_ID_START_BIT 0
#define PF_ID_START_BIT 13
#define BAR_NUM_START_BIT 20
#define EP_ID_START_BIT 23
#define FUNCTION_TYPE_START_BIT 27
#define SCENE_CODE_START_BIT 28

#define VF_ID_OFFSET (PF_ID_START_BIT - VF_ID_START_BIT) // 13
#define PF_ID_OFFSET (BAR_NUM_START_BIT - PF_ID_START_BIT) // 7
#define BAR_NUM_OFFSET (EP_ID_START_BIT - BAR_NUM_START_BIT) // 3
#define EP_ID_OFFSET (FUNCTION_TYPE_START_BIT - EP_ID_START_BIT) // 4
#define FUNCTION_TYPE_OFFSET (SCENE_CODE_START_BIT - FUNCTION_TYPE_START_BIT) // 1
#define SCENE_CODE_OFFSET (32 - SCENE_CODE_START_BIT) // 4

/* filed: VF_ID/PF_ID/BAR_NUM/EP_ID/FUNCTION_TYPE/SCENE_CODE  */
#define DH_FUNC_ID_EXTRACT(data, filed)                           \
	(((data & (~((1UL << filed##_START_BIT) - 1))) &          \
	  ((1UL << (filed##_START_BIT + filed##_OFFSET)) - 1)) >> \
	 filed##_START_BIT)

#define DH_FUNC_ID_GEN(type, ep, bar, pf, vf)                                      \
	(((type & ((1 << FUNCTION_TYPE_OFFSET) - 1)) << FUNCTION_TYPE_START_BIT) | \
	 ((ep & ((1 << EP_ID_OFFSET) - 1)) << EP_ID_START_BIT) |                   \
	 ((bar & ((1 << BAR_NUM_OFFSET) - 1)) << BAR_NUM_START_BIT) |              \
	 ((pf & ((1 << PF_ID_OFFSET) - 1)) << PF_ID_START_BIT) |                   \
	 ((vf & ((1 << VF_ID_OFFSET) - 1))))

/* bar msg status */
#define BAR_MSG_STATUS_OK (200)
#define BAR_MSG_STATUS_REQ_ERR (400)
#define BAR_MSG_STATUS_RESP_ERR (500)

/* Common configuration */
#define ZXDH_PCI_CAP_COMMON_CFG 1
/* Notifications */
#define ZXDH_PCI_CAP_NOTIFY_CFG 2
/* ISR access */
#define ZXDH_PCI_CAP_ISR_CFG 3
/* Device specific configuration */
#define ZXDH_PCI_CAP_DEVICE_CFG 4
/* PCI configuration access */
#define ZXDH_PCI_CAP_PCI_CFG 5

#define ZXDH_ZF_EPID 4
#define ZXDH_BAR_CHAN_OFFSET 0x2000
#define ZXDH_CHAN_REPS_LEN 4
#define MSG_REP_VALID 0xff
#define MSG_REP_LEN_OFFSET 1

#define MODULE_RDMA 4

#define RDMA_MGR_INIT (0)
#define RDMA_REG_READ (1)
#define RDMA_REG_WRITE (2)
#define RDMA_MP_DTCM_PARA_GET (3)
#define RDMA_MP_DTCM_PARA_SET (4)
#define RDMA_HWBOND_SPEED_SET (5)
#define RDMA_REQ_VER (6)
#define RDMA_RESP_VER (7)
#define GET_SRQ_L2D_ADDR (8)
#define RDMA_VFS_NUM_SET (9)

#define ZXDH_REQ_MSG_LEN 15
#define ZXDH_RESP_MSG_LEN 80
#define ZXDH_MSG_MIN_LEN 5
#define ZXDH_VER_HEADER_H 0xAA
#define ZXDH_VER_HEADER_L 0x55

#define RDMA_DEL_REMOTE_IP 0
#define RDMA_ADD_REMOTE_IP 1

enum BAR_DRIVER_TYPE {
	MSG_CHAN_END_MPF = 0,
	MSG_CHAN_END_PF,
	MSG_CHAN_END_VF,
	MSG_CHAN_END_RISC,
	MSG_CHAN_END_ERR,
};

struct zxdh_pci_bar_msg {
	u64 virt_addr;
	void *payload_addr;
	u16 payload_len;
	u16 emec;
	u16 src;
	u16 dst;
	u32 event_id;
	u16 src_pcieid;
	u16 dst_pcieid;
};

struct zxdh_msg_recviver_mem {
	void *recv_buffer;
	u16 buffer_len;
};

/* This is the PCI capability header: */
struct zxdh_pf_pci_cap {
	__u8 cap_vndr; /* Generic PCI field: PCI_CAP_ID_VNDR */
	__u8 cap_next; /* Generic PCI field: next ptr. */
	__u8 cap_len; /* Generic PCI field: capability length */
	__u8 cfg_type; /* Identifies the structure. */
	__u8 bar; /* Where to find it. */
	__u8 id; /* Multiple capabilities of the same type */
	__u8 padding[2]; /* Pad to full dword. */
	__le32 offset; /* Offset within bar. */
	__le32 length; /* Length of the structure, in bytes. */
};

struct dh_rdma_board_glb_cfg {
	u32 cqp_size;
	u32 qp_size;
	u32 cq_size;
	u32 ceq_size;
	u32 srq_size;
	u32 wr_cnt;
	u32 sge_cnt;
};

struct dh_rdma_vf_param {
	u32 vf_id;
	u32 vf_vhca_id;
	u32 pf_id;
	u32 pf_vhca_id;

	u32 vf_bar_offset;

	u32 qp_cnt;
	u32 cq_cnt;
	u32 srq_cnt;
	u32 ceq_cnt;
	u32 ah_cnt;

	u32 qp_id_min;
	u32 cq_id_min;
	u32 ceq_id_min;
	u32 srq_id_min;
};

struct dh_rdma_pf_param {
	u8 pf_id;
	u32 max_vf_num;
	u8 sid;

	u32 vhca_id; // vhca ID

	u32 pf_bar_offset;

	u32 qp_cnt;
	u32 cq_cnt;
	u32 srq_cnt;
	u32 ceq_cnt;

	u32 ah_cnt;

	u32 qp_id_min;
	u32 cq_id_min;
	u32 ceq_id_min;
	u32 srq_id_min;

	u32 assign_qp_cnt;
	u32 assign_cq_cnt;
	u32 assign_ceq_cnt;
	u32 assign_srq_cnt;

	u32 qp_size;
	u32 cq_size;
	u32 ceq_size;
	u32 aeq_size;
	u32 srq_size;
};

struct zxdh_mgr_par {
	u16 ftype;
	u16 ep_id;
	u16 pf_id;
	u16 vf_id;
	u32 bar_offset;
	u32 l2d_smmu_l2_offset;
	u64 l2d_smmu_addr;
	u64 nof_ioq_ddr_addr;

	u16 vhca_id;
	u16 vhca_id_pf;
	u32 max_vf_num;

	u32 qp_cnt;
	u32 cq_cnt;
	u32 srq_cnt;
	u32 ceq_cnt;
	u32 ah_cnt;
	u32 mr_cnt;
	u32 pbleq_cnt;
	u32 pblem_cnt;

	u32 vf_qp_cnt;
	u32 vf_cq_cnt;
	u32 vf_srq_cnt;
	u32 vf_ceq_cnt;
	u32 vf_ah_cnt;
	u32 vf_mr_cnt;
	u32 vf_pbleq_cnt;
	u32 vf_pblem_cnt;

	u32 base_qpn;
	u32 base_cqn;
	u32 base_srqn;
	u32 base_ceqn;

	u64 pf_hmc_size;
	u64 qp_hmc_base;
	u64 cq_hmc_base;
	u64 srq_hmc_base;
	u64 txwindow_hmc_base;
	u64 ird_hmc_base;
	u64 ah_hmc_base;
	u64 mr_hmc_base;
	u64 pbleq_hmc_base;
	u64 pblem_hmc_base;

	u8 hmc_sid;
	u8 hmc_use_dpu_ddr;
	u8 np_mode_low_lat;
	u8 mcode_type;
	u8 chip_version;

	u32 max_hw_read_sges;
	u32 max_hw_wq_frags;
	u32 dh_total_vhca;
	u16 vhca_gqp_start;
	u16 vhca_gqp_cnt;
	u16 vhca_8k_index_start;
	u16 vhca_8k_index_cnt;
	u16 vhca_ud_gqp;
	u16 vhca_ud_8k_index;
} __packed;

struct zxdh_chan_msg {
	u32 msg_len;
	void *msg;
};

enum chan_cmd_type {
	GET_PF_PARAM = 1,
	GET_VF_PARAM = 2,
};

struct zxdh_mgr_msg {
	u32 op_code;
	u8 ep_id;
	u8 pf_id;
	u16 vport_vf_id;
	u8 ftype;
	u8 rsv[3];
};

struct zxdh_mgr {
	//struct irdma_device *iwdev;
	struct pci_dev *pdev;
	u32 pf_id;
	u32 vport_vf_id;
	u32 ep_id;
	u8 ftype;
	u16 pcie_id;
	u16 device_id;
	u8 __iomem *pci_hw_addr;
	struct zxdh_mgr_par param;
};

enum e_dtcm_para_id_dcqcn {
	E_PARA_DCQCN_RPG_TIME_RESET,
	E_PARA_DCQCN_CLAMP_TGT_RAGE,
	E_PARA_DCQCN_CLAMP_TGT_RATE_AFTER_TIME_INC,
	E_PARA_DCQCN_DCE_TCP_RTT,
	E_PARA_DCQCN_DCE_TCP_G,
	E_PARA_DCQCN_RPG_GD,
	E_PARA_DCQCN_INITIAL_ALPHA_VALUE,
	E_PARA_DCQCN_MIN_DEC_FAC,
	E_PARA_DCQCN_RPG_THRESHOLD,
	E_PARA_DCQCN_RPG_RATIO_INCREASE,
	E_PARA_DCQCN_RPG_AI_RATIO,
	E_PARA_DCQCN_RPG_HAI_RATIO,
	E_PARA_DCQCN_NUM
};

enum e_dtcm_para_id_rtt {
	E_PARA_RTT_ALPHA,
	E_PARA_RTT_TLOW,
	E_PARA_RTT_THIGH,
	E_PARA_RTT_MINRTT,
	E_PARA_RTT_BETA,
	E_PARA_RTT_AI_NUM,
	E_PARA_RTT_THRED_GRADIENT,
	E_PARA_RTT_HAI_N,
	E_PARA_RTT_AI_N,
	E_PARA_RTT_NUM
};

struct rdma_chan_msg_para {
	u8 *in_buf;
	u8 *out_buf;
	size_t in_size;
	size_t out_size;
};

struct dh_rdma_reg_read_req {
	u64 phy_addr;
	u32 reg_num;
} __packed;

struct dh_rdma_reg_read_resp {
	u64 phy_addr;
	u32 reg_num;
	u32 status_code;
	u32 data[];
} __packed;

struct dh_rdma_reg_write_req {
	u64 phy_addr;
	u32 reg_num;
	u32 data[];
} __packed;

struct dh_rdma_reg_write_resp {
	u64 phy_addr;
	u32 reg_num;
	u32 status_code;
} __packed;

// mp dtcm para set/get messages
struct dh_mp_dtcm_para_set_req {
	u16 mcode_type;
	u16 para_id;
	u32 val;
} __packed;

struct dh_mp_dtcm_para_set_resp {
	u16 para_id;
	u32 status_code;
} __packed;

struct dh_mp_dtcm_para_get_req {
	u16 mcode_type;
	u16 para_id;
} __packed;

struct dh_mp_dtcm_para_get_resp {
	u16 para_id;
	u32 status_code;
	u32 val;
} __packed;

struct dh_rdma_vf_num_set_resp {
	u64 vf_pblem_cnt;
	u32 status_code;
} __packed;

struct dh_hwbond_speed_set_req {
	u32 speed;
	u8 speed_valid;
} __packed;

struct dh_rdma_vf_num_set_req {
	u16 ep_id;
	u16 pf_id;
	u16 num_vfs;
} __packed;

// channel message struct
struct zxdh_reg_read_cmd {
	u32 op_code;
	struct dh_rdma_reg_read_req req;
} __packed;
struct zxdh_reg_write_cmd {
	u32 op_code;
	struct dh_rdma_reg_write_req req;
} __packed;

struct zxdh_mp_dtcm_para_get_cmd {
	u32 op_code;
	struct dh_mp_dtcm_para_get_req req;
} __packed;
struct zxdh_mp_dtcm_para_set_cmd {
	u32 op_code;
	struct dh_mp_dtcm_para_set_req req;
} __packed;

struct zxdh_hwbond_speed_set_cmd {
	u32 op_code;
	struct dh_hwbond_speed_set_req req;
} __packed;

struct zxdh_rdma_vf_num_set_cmd {
	u32 op_code;
	struct dh_rdma_vf_num_set_req req;
} __packed;

struct zxdh_req_msg {
	u8 op_code;
	u8 buf[ZXDH_REQ_MSG_LEN];
} __packed;

struct zxdh_resp_msg {
	u8 op_code;
	u8 buf[ZXDH_RESP_MSG_LEN];
} __packed;

struct zxdh_rdma_to_eth_ip_para {
	char *ifname;
	u32 src_ip[4];
	u32 dst_ip[4];
	u64 src_mac;
	u64 dst_mac;
	u32 linked_fid;
	u8 ipv4 : 1;
	u8 mode : 1;
};

struct dh_get_srq_l2d_addr_req {
	u32 op_code;
	u32 function_id;
} __packed;

struct dh_get_srq_l2d_addr_resp {
	u64 srq_l2d_paddr;
	u32 srq_l2d_size;
	u32 rdma_ext_bar_offset;
	u32 status_code;
} __packed;

struct zxdh_rdma_sriov_event_info {
	struct pci_dev *pdev;
	u64 bar0_virt_addr;
	u16 vport_id;
	u16 num_vfs;
};

typedef void (*notify_remote_ip_update)(struct zxdh_rdma_to_eth_ip_para *info);

extern notify_remote_ip_update remote_ip_update_hook;

int rdma_chan_msg_send(struct zxdh_pci_f *rf, struct rdma_chan_msg_para *para);

int zxdh_bar_chan_sync_msg_send(struct zxdh_pci_bar_msg *in, struct zxdh_msg_recviver_mem *result);
int zxdh_chan_sync_send(struct zxdh_mgr *pmgr, struct zxdh_chan_msg *pmsg, u32 *pdata, u32 rep_len);
int zxdh_mgr_par_get(struct zxdh_mgr *dh_mgr);

int zxdh_rdma_reg_read(struct zxdh_pci_f *rf, u64 phy_addr, u32 *outdata);

int zxdh_rdma_regs_read(struct zxdh_pci_f *rf, u64 phy_addr, u32 *outdata, u32 num);

int zxdh_rdma_reg_write(struct zxdh_pci_f *rf, u64 phy_addr, u32 val);

int zxdh_mp_dtcm_para_get(struct zxdh_pci_f *rf, u16 mcode_type, u16 para_id, u32 *outdata);

int zxdh_mp_dtcm_para_set(struct zxdh_pci_f *rf, u16 mcode_type, u16 para_id, u32 val);

int dh_rdma_pf_pcie_id_get(struct zxdh_mgr *mgr);

// callback installed to net
int32_t switch_bound_master_netdev(struct net_device *primary_netdev,
				   struct net_device *linux_bond_netdev, bool hb_enable);
int32_t set_rdma_firmware_speed(struct net_device *netdev, u32 bps);
// int32_t set_rdma_hwbond_status(struct net_device *netdev, bool hb_enable);
int zxdh_req_cmd_ver(struct zxdh_pci_f *rf);
int register_remote_ip_event_handler(notify_remote_ip_update handler);
void unregister_remote_ip_event_handler(void);
void rdma_update_remote_ip(struct zxdh_rdma_to_eth_ip_para *info);
int set_rdma_vf_num(struct zxdh_rdma_sriov_event_info *sriov_info, u64 *vf_pblem_cnt);
#endif
