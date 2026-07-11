/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef _ZXDH_MSG_CHAN_PUB_H_
#define _ZXDH_MSG_CHAN_PUB_H_

#include <linux/netdevice.h>
#include <linux/workqueue.h>

struct zxdh_bar_extra_para {
	bool is_sync;
	uint16_t retrycnt;
} __packed;

#define INVALID_NUM 0xff
#define ZXDH_MPF_PCIEID 0x800
#define ZXDH_NET_ACK_OK 0
#define RISCV_MAC_OK 0xaa
#define BAR_MSG_REPS_OK 0xff
#define COMMON_TBL_OK 0xaa
#define RISCV_DEBUG_OK 0xaa
#define PCIEID_PF_ID_MASK (0x0700)
#define PCIEID_PF_ID_OFFSET (8)

#define FIND_PF_PCIE_ID(value) ((value & 0xff00) | BIT(11))
#define FIND_VF_PCIE_ID(pf_pcie_id, vf_id) ((pf_pcie_id & (~BIT(11))) | (vf_id))
#define FIND_PF_ID(pf_pcie_id) ((pf_pcie_id & PCIEID_PF_ID_MASK) >> PCIEID_PF_ID_OFFSET)
#define GET_FUNC_NO(pf_no, vf_idx) ((pf_no & 0xF) | ((vf_idx & 0xFF) << 8))

#define PFVF_FLAG_OFFSET 11

enum MSG_MODULE_ID {
	MODULE_DBG = 0,
	MODULE_TBL,
	MODULE_MSIX,
	MODULE_SDA,
	MODULE_RDMA,
	MODULE_DEMO,
	MODULE_SMMU,
	MODULE_MAC,
	MODULE_VDPA,
	MODULE_VQM,
	MODULE_MSGQ,
	MODULE_VPORT_GET,
	MODULE_BDF_GET,
	MODULE_RISC_READY,
	MODULE_REVERSE,
	MODULE_NVME,
	MODULE_NPSDK,
	MODULE_TOD,
	MODULE_VF_BAR_MSG_TO_PF,
	MODULE_PF_BAR_MSG_TO_VF,
	MODULE_DEBUG = 20,
	MODULE_PPS = 23,
	MODULE_VIRTIO = 25,
	MODULE_FLASH = 32,
	MODULE_OFFSET_GET = 33,
	MODULE_CFG_MAC = 34,
	MODULE_CFG_VQM = 36,
	MODULE_PHYPORT_QUERY = 37,
	MODULE_DHTOOL = 39,
	MODULE_RESET_MSG = 40,
	MODULE_PF_TIMER_TO_RISC_MSG = 41,
	MODULE_LOGIN_CTRL = 43,
	MODULE_PCIE_RES_QUERY = 52,
	MODULE_DTP = 53,
	MODULE_MPF_PCIE_INFO = 54,
	MODULE_HEALTH = 55,
	MODULE_VQMB = 59,
	MSG_MODULE_NUM = 60,
};

enum BAR_DRIVER_TYPE {
	MSG_CHAN_END_MPF = 0,
	MSG_CHAN_END_PF,
	MSG_CHAN_END_VF,
	MSG_CHAN_END_RISC,
	MSG_CHAN_END_ERR,
};

#define BDF_ECAM(bus, devid, func) ((((bus)&0xff) << 8) | ((func)&0x07) | (((devid)&0x1f) << 3))
#define SBDF_ECAM(domain, bus, devid, func) \
	((((domain)&0xffff) << 16) | (((bus)&0xff) << 8) | ((func)&0x07) | (((devid)&0x1f) << 3))

enum BAR_MSG_RTN {
	BAR_MSG_OK = 0,
	BAR_MSG_ERR_NULL,
	BAR_MSG_ERR_TYPE,
	BAR_MSG_ERR_MODULE,
	BAR_MSG_ERR_BODY_NULL,
	BAR_MSG_ERR_LEN,
	BAR_MSG_ERR_TIME_OUT,
	BAR_MSG_ERR_NOT_READY,
	BAR_MEG_ERR_NULL_FUNC,
	BAR_MSG_ERR_REPEAT_REGISTER,
	BAR_MSG_ERR_UNGISTER,
	BAR_MSG_ERR_NULL_PARA,
	BAR_MSG_ERR_REPSBUFF_LEN,
	BAR_MSG_ERR_MODULE_NOEXIST,
	BAR_MSG_ERR_VIRTADDR_NULL,
	BAR_MSG_ERR_REPLY,
	BAR_MSG_ERR_MSGID,
	BAR_MSG_ERR_MPF_NOT_SCANED,
	BAR_MSG_ERR_USR_RET_ERR,
	BAR_MSG_ERR_ERR_PCIEID,
	BAR_MSG_ERR_LOCK_FAILED,
	BAR_MSG_ERR_BAR_ABNORMAL,
	BAR_MSG_ERR_NOT_MATCH,
};

enum pciebar_layout_type {
	URI_VQM = 0,
	URI_SPINLOCK = 1,
	URI_FWCAP = 2,
	URI_FWSHR = 3,
	URI_DRS_SEC = 4,
	URI_RSV = 5,
	URI_CTRLCH = 6,
	URI_1588 = 7,
	URI_QBV = 8,
	URI_MACPCS = 9,
	URI_RDMA = 10,
	URI_MNP = 11,
	URI_MSPM = 12,
	URI_MVQM = 13,
	URI_MDPI = 14,
	URI_NP = 15,
	URI_MAX,
};

enum bar_msg_msix_irq_type {
	BAR_MSG_MSIX_FROM_VF = 0,
	BAR_MSG_MSIX_FROM_MPF,
	BAR_MSG_MSIX_FROM_RISCV,
	BAR_MSG_MSIX_NUM_MAX
};

struct msix_para {
	uint16_t vector_risc;
	uint16_t vector_pfvf;
	uint16_t vector_mpf;
	uint16_t driver_type;
	uint16_t pcie_id;
	struct pci_dev *pdev;
	uint64_t virt_addr;
};

struct bar_offset_params {
	uint64_t virt_addr;
	uint16_t pcie_id;
	uint16_t type;
};
struct bar_offset_res {
	uint32_t bar_offset;
	uint32_t bar_length;
};

struct zxdh_pci_bar_msg {
	uint64_t virt_addr;
	void *payload_addr;
	uint16_t payload_len;
	uint16_t emec;
	uint16_t src;
	uint16_t dst;
	uint32_t event_id;
	uint16_t src_pcieid;
	uint16_t dst_pcieid;
};

struct link_info_struct {
	uint32_t speed;
	uint32_t autoneg_enable;
	uint32_t supported_speed_modes;
	uint32_t advertising_speed_modes;
	uint8_t duplex;
};

struct zxdh_msg_recviver_mem {
	void *recv_buffer;
	uint16_t buffer_len;
};
typedef int (*zxdh_bar_chan_msg_recv_callback)(void *pay_load, uint16_t len, void *reps_buffer,
					       uint16_t *reps_len, void *dev);
int zxdh_bar_chan_sync_msg_send(struct zxdh_pci_bar_msg *in, struct zxdh_msg_recviver_mem *result);
int zxdh_bar_send_without_reps_hdr(struct zxdh_pci_bar_msg *in,
				   struct zxdh_msg_recviver_mem *result);
int zxdh_bar_chan_msg_recv_register(uint8_t event_id, zxdh_bar_chan_msg_recv_callback callback);
int zxdh_bar_chan_msg_recv_unregister(uint8_t event_id);
int zxdh_bar_callback_register_state(uint16_t event_id);
int zxdh_bar_enable_chan(struct msix_para *_msix_para, uint16_t *vport);

int zxdh_get_bar_offset(struct bar_offset_params *paras, struct bar_offset_res *res);

int32_t zxdh_send_command(uint64_t vaddr, uint16_t pcie_id, uint16_t module_id, void *msg,
			  void *ack, bool is_sync_msg);
int zxdh_bar_msg_chan_init(void);
int zxdh_bar_msg_chan_remove(void);
void zxdh_bar_reset_valid(uint64_t subchan_addr);
uint16_t zxdh_get_event_id(uint64_t subchan_addr, uint8_t src_type, uint8_t dst_type);
int zxdh_bar_irq_recv(uint8_t src, uint8_t dst, uint64_t virt_addr, void *dev);
int32_t call_msg_recv_func_tbl(uint16_t event_id, void *pay_load, uint16_t len, void *reps_buffer,
			       uint16_t *reps_len, void *dev);
int bar_chan_pf_init_spinlock(uint16_t pcie_id, uint64_t bar_base_addr);
typedef int (*zxdh_usr_msg_cache_callback)(uint16_t event_id, void *msg, uint16_t msg_len);
void zxdh_usr_msg_cache_func_register(zxdh_usr_msg_cache_callback func);
int32_t zxdh_vqm_queue_cfg(uint64_t virt_addr, uint16_t pcie_id, uint32_t phy_queue_idx);
#endif /* _ZXDH_MSG_CHAN_PUB_H_ */
