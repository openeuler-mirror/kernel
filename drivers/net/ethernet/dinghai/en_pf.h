/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef __ZXDH_EN_PF_H__
#define __ZXDH_EN_PF_H__
#include <linux/dinghai/zxdh_compat.h>
#include <linux/dinghai/device.h>
#include <linux/dinghai/driver.h>
#include <linux/refcount.h>
#include "plcr.h"
#ifdef CONFIG_DINGHAI_TSN
#include "en_tsn/zxdh_tsn.h"
#endif

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

#define ZXDH_PF_MAX_BAR_VAL 0x5
#define ZXDH_PF_ALIGN4 4
#define ZXDH_PF_ALIGN2 2
#define ZXDH_PF_MAP_MINLEN2 2

#define ZXDH_DEV_MAC_HIGH_OFFSET 4
#define ZXDH_DEV_SPEED_OFFSET 0x4c
#define ZXDH_DEV_DUPLEX_OFFSET 0x50
#define ZXDH_FW_VER_OFFSET 0x5400
#define ZXDH_QUEUE_INFO_OFFSET 0x5480
#define ZXDH_FW_CAP_OFFSET 0x1000

#define ZXDH_FWSHARE_BASE_ADDR 0x5000
#define ZXDH_DEV_QUEUE_INFO_OFFSET (ZXDH_FWSHARE_BASE_ADDR + 0x6a0)
#define ZXDH_PF_QUEUE_INFO_OFFSET (ZXDH_FWSHARE_BASE_ADDR + 0x740)
#define ZXDH_VF_QUEUE_PAIRS_OFFSET (ZXDH_FWSHARE_BASE_ADDR + 0x490)
#define ZXDH_VF_QUEUE_USER_OFFSET (ZXDH_FWSHARE_BASE_ADDR + 0x744)
#define ZXDH_VF_MAX_QUEUE_USER_OFFSET (ZXDH_FWSHARE_BASE_ADDR + 0x743)
#define ZXDH_OVS_PF_VFID_OFFSET (ZXDH_FWSHARE_BASE_ADDR + 0x77C)

#define ZXDH_NP_EXT_STATS_OFFSET (ZXDH_FWSHARE_BASE_ADDR + 0xA00)
#define ZXDH_NP_EXT_STATS_SIZE (512)

#define EPID_MASK_BIT (12)
#define PFID_MASK_BIT (8)
#define EPID_GEN_FROM_VPORT(a) (((a) & ~BIT(15)) >> EPID_MASK_BIT)
#define GLOBAL_PF_IDX(a, b) ((a)*ZXDH_PF_NUM_PER_EP + (((b)&ZXDH_PF_IDX_MASK) >> PFID_MASK_BIT))
#define GLOBAL_VF_IDX(a, b) ((a)*ZXDH_VF_NUM_MAX + ((b)&ZXDH_VF_IDX_MASK))
#define ZXDH_MAX_QPS_NUM (8)

#define ZXDH_CFG_NPSDK_TYPE 7
#define ZXDH_STOP_PXE_MODE 1

#define ZXDH_PANNEL_PORT_MAX (10)

#define TO_EP4_ADDR(addr) ((((addr)&0xFFFFFFFFFFFF0000) << 4) | ((addr)&0xFFFF))

#define ZXDH_EP_NUM 4
#define ZXDH_QUEUE_PAIRS_MAX 32
#define ZXDH_VF_IDX_MASK 0xff
#define ZXDH_PF_IDX_MASK 0x700

#define GET_COREDEV_TYPE(pdev)	\
	(((pdev->device == ZXDH_VF_DEVICE_ID || pdev->device == ZXDH_VF_E310_DEVICE_ID ||	\
	   pdev->device == ZXDH_VF_E312_DEVICE_ID || pdev->device == ZXDH_UPF_VF_I512_DEVICE_ID || \
	   pdev->device == ZXDH_INICA_RDMA_VF_DEVICE_ID ||	\
	   pdev->device == ZXDH_VF_DPUB_RDMA_DEVICE_ID ||	\
	   pdev->device == ZXDH_VF_E316_DEVICE_ID || pdev->device == ZXDH_VF_E316_XPU_DEVICE_ID || \
	   pdev->device == ZXDH_VF_E311_DEVICE_ID || pdev->device == ZXDH_VF_I511_DEVICE_ID || \
	   pdev->device == ZXDH_INICD_NE0_VF_DEVICE_ID ||	\
	   pdev->device == ZXDH_INICD_NE1_VF_DEVICE_ID ||	\
	   pdev->device == ZXDH_INICD_NE2_VF_DEVICE_ID ||	\
	   pdev->device == ZXDH_VF_E310_RDMA_DEVICE_ID ||	\
	   pdev->device == ZXDH_VF_E310S_DEVICE_ID || pdev->device == ZXDH_VF_E312S_DEVICE_ID || \
	   pdev->device == ZXDH_VF_E312_RDMA_DEVICE_ID ||	\
	   pdev->device == ZXDH_VF_I510_SRIOV_SEC_DEVICE_ID ||	\
	   pdev->device == CTC_VF_B512Y_DEVICE_ID || pdev->device == CTC_VF_B522Y_DEVICE_ID || \
	   pdev->device == ZXDH_VF_E312S_D_DEVICE_ID) || \
	   pdev->device == ZXDH_VF_E310_CMCC_DEVICE_ID) ? \
		       DH_COREDEV_VF : DH_COREDEV_PF)

#define PORT_FLAGS_ALLOC_STAT (1 << 0)

struct dh_core_dev;

struct zxdh_pf_adev {
	struct zxdh_auxiliary_device *adev;
	s32 aux_idx;
};

struct zxdh_pannle_port {
	u8 pannel_id;
	u8 phyport;
	u8 link_check_bit;
	u8 flags;
} __packed;

struct nic_sn_info {
	u8 fixed_sn_valid;
	u8 pseudo_sn_valid;
	u8 pseudoed_before;
	u8 rsv[1];
#define SN_CODE_LENGTH (12)
	u8 sn_code[SN_CODE_LENGTH];
} __packed;

struct zxdh_port_resource {
	u8 pannel_num;
	u8 bond_num;
	u8 bond_idx;
	u8 rsv;
	struct zxdh_pannle_port port[ZXDH_PANNEL_PORT_MAX];
} __packed;

#define DH_HEALTH_ATTR_NUM (5)
struct zxdh_core_health {
	struct timer_list timer;
	struct core_health riscv;
	struct core_health m7;
	u64 m7_log_offset;
	u64 riscv_crdump_size;
	unsigned long synd;
	u8 fatal;
	u8 health_version;
	u16 recovery_cnt;
	bool health_supported;
	bool reset_done;
	u8 fatal_detect_cnt;
	u8 selfhealing;
	u16 synd_statics[64];
	/* wq spinlock to synchronize draining */
	spinlock_t wq_lock;
	struct workqueue_struct *wq;
	unsigned long flags;
	struct work_struct m7_bbx_saving_work;
	struct work_struct riscv_log_saving_work;
	struct work_struct riscv_bbx_saving_work;
	struct work_struct fw_fatal_err_work;
	struct work_struct dh_reset_work;
	struct kobj_attribute attrs[DH_HEALTH_ATTR_NUM];
};

struct zxdh_fw_compat {
	u8 module_id;
	u8 major;
	int8_t fw_minor;
	u8 drv_minor;
	u16 patch;
	u16 rsv;
} __packed;

/* If feature bits are added, add the following enumeration types. */
enum fw_feature_bit {
	FW_FEATURE_COMPAT = 0,
	FW_FEATURE_RDMA = 1,
	FW_FEATURE_STD = 2,
	FW_FEATURE_NPSTAT = 3,
	FW_FEATURE_SEC = 4,
	FW_FEATURE_QUEUE_RESET = 5,
	FW_FEATURE_PFM = 6,
	FW_FEATURE_MAX,
};

#define FW_FEATURE_GET(value, bit) (((value) >> (bit)) & 1)

struct firmware_capability {
	u8 ddr_aval : 1;
	u8 multihost_aval : 1;
	u8 riscv_init_done : 1;
	u8 board_type; /* enum dh_board_type */
	u8 scen_type;
	u8 bond_pf_pnl_num;

	u8 stat_power_mask;
	u8 ctrl_power_mask;
	u64 fw_feature; /* enum fw_feature_bit */
	u16 fw_feature_extra; /* enum fw_feature_bit */
	u32 pf_rate_default;
} __packed;

struct zxdh_pf_queue_info {
	u8 pf_qp;
	u8 vf_qp;
} __packed;

struct zxdh_dev_queue_info {
	u16 total_qp;
	u16 start_id;
} __packed;

struct zxdh_np_ext_stats {
	u32 rx_vport2np_packets;
} __packed;

struct zxdh_pf_device {
	struct list_head virtqueues;

	struct zxdh_pf_pci_common_cfg __iomem *common;
	/* Device-specific data (non-legacy mode)  */
	/* Base of vq notifications (non-legacy mode). */
	void __iomem *device;
	void __iomem *notify_base;
	void __iomem *pf_sriov_cap_base;
	/* Physical base of vq notifications */
	resource_size_t notify_pa;
	/* Where to read and clear interrupt */
	u8 __iomem *isr;
	/* So we can sanity-check accesses. */
	size_t notify_len;
	size_t device_len;
	/* Capability for when we need to map notifications per-vq. */
	s32 notify_map_cap;
	/* Multiply queue_notify_off by this value. (non-legacy mode). */
	u32 notify_offset_multiplier;
	s32 modern_bars;

	u64 pci_ioremap_addr[6];
	u64 qtlb_offset;

	u32 speed;
	u32 autoneg_enable;
	u32 supported_speed_modes;
	u32 advertising_speed_modes;
	u8 duplex;
	bool bar_chan_valid;
	u16 pcie_id;
	u16 slot_id;
	u16 vport;
	struct zxdh_vf_item *vf_item;
	u16 num_vfs;
	bool vepa;
	u8 phy_port;

	bool link_up;
	bool fast_unload;
	struct work_struct riscv_ready_work;
	struct work_struct riscv2pf_msg_proc_work;
	struct work_struct vf2pf_msg_proc_work;
	struct work_struct link_info_irq_update_vf_bond_pf_work;
	struct work_struct init_vf_link_info_work;
	struct work_struct riscv_ext_pps_work;
	struct work_struct riscv_local_pps_work;
	struct work_struct mac_info_pf_work;

	u64 sriov_bar_size;

	struct zxdh_plcr_table plcr_table;
	struct zxdh_sriov_sysfs sriov;
	struct zxdh_pf_adev *adevs_table;
	s32 adevs_num;

	struct zxdh_port_resource port_resource;
	struct zxdh_lag *ldev;
	s32 pannel_port_num;

	/* initialization completion flag */
	u8 aux_comp_flag;
	u8 bond_num;
	struct zxdh_ptp_private *ptp;
#ifdef CONFIG_DINGHAI_TSN
	struct zxdh_tsn_private *tsn;
#endif
	struct zxdh_ipv6_mac_tbl *ip6mac_tbl;
	u32 dev_cfg_bar_off;
	struct zxdh_core_health health;
	struct zxdh_fw_compat fw_compat;
	u8 sn_code[SN_CODE_LENGTH];
	u8 board_type;
	u8 product_type;
	u8 vq_pairs;
	u64 mcode_feature;
	struct firmware_capability fwcap;
	struct zxdh_np_ext_stats np_ext_stats;
	u16 epbdf;
	u32 rp_sbdf;
	bool is_multi_ep;
	bool is_hwbond;
	bool is_rdma_aux_plug;
	bool is_primary_port;
	u64 spec_sbdf;
	bool quick_remove;
};

struct slot_id_array {
	u8 sn_code[SN_CODE_LENGTH];
};

struct zxdh_ipv6_mac_entry {
	spinlock_t lock;
	refcount_t refcnt;
	struct list_head list;
	u8 ipv6_mac[ETH_ALEN];
};

struct zxdh_ipv6_mac_tbl {
	unsigned int ip6mact_size;
	struct mutex mlock;
	struct list_head ip6mac_free_head;
	void *ip6mac_entry_list;
	struct list_head hash_list[];
};

#define IS_MSGQ_DEV(en_dev)						         \
	(((en_dev->ops->get_coredev_type(en_dev->parent) == DH_COREDEV_PF) && \
	  ((!en_dev->ops->is_bond(en_dev->parent)) ||                         \
	   (en_dev->ops->is_bond(en_dev->parent) && en_dev->ops->if_init(en_dev->parent)))))
#define NEED_MSGQ(en_dev) (en_dev->need_msgq)

extern struct devlink_ops dh_pf_devlink_ops;
extern struct dh_core_devlink_ops dh_pf_core_devlink_ops;

#ifdef PTP_DRIVER_INTERFACE_EN
int zxdh_ptp_init(struct dh_core_dev *zxdev);
void zxdh_ptp_stop(struct dh_core_dev *zxdev);
#endif

bool zxdh_pf_is_bond(struct dh_core_dev *dh_dev);
bool zxdh_pf_is_upf(struct dh_core_dev *dh_dev);
s32 zxdh_pf_msg_send_cmd(struct dh_core_dev *dh_dev, u16 module_id, void *msg, void *ack,
			 struct zxdh_bar_extra_para *para);
struct zxdh_vf_item *zxdh_pf_get_vf_item(struct dh_core_dev *dh_dev, u16 vf_idx);
int zxdh_pf_get_pannel_port_num(struct dh_core_dev *dh_dev);
void zxdh_pf_set_vf_mac_reg(struct zxdh_pf_device *pf_dev, u8 *mac, s32 vf_id);
void zxdh_unload_one(struct dh_core_dev *dh_dev);
int zxdh_load_one(struct dh_core_dev *dh_dev);
int zxdh_pf_status_ok(struct dh_core_dev *dh_dev);
int zxdh_vf_wait_pf_ok(struct dh_core_dev *dh_dev);
void zxdh_pf_set_bond_num(struct dh_core_dev *dh_dev, bool add);
int zxdh_pf_pcie_config_store(struct dh_core_dev *dh_dev);
s32 zxdh_pf_get_hp_irq_ctrl_status(struct dh_core_dev *dev);
s32 zxdh_pf_rp_config_init(struct dh_core_dev *dev);
u32 zxdh_pf_get_dev_type(struct dh_core_dev *dh_dev);
#endif
