/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef __DINGHAI_DRIVER_H__
#define __DINGHAI_DRIVER_H__

#include <linux/pci.h>
#include <linux/dinghai/device.h>
#include <linux/dinghai/events.h>
#include <linux/dinghai/log.h>
#include <linux/dinghai/zxdh_auxiliary_bus.h>
#include <net/devlink.h>

#define ZXDH_MODULE_ID 1
#define ZXDH_MAJOR 1
#define ZXDH_FW_MINOR 0
#define ZXDH_DRV_MINOR 0
#define ZXDH_PATCH 0

#define DH_NEW_QUEEU_ALLOC_PATCH (3)
#define DH_HPIRQ_PATCH (4)

#define ZXDH_CHECK_RET_RETURN(ret, fmt, arg...) \
	do {                                    \
		if ((ret) != 0) {               \
			LOG_ERR(fmt, ##arg);    \
			return ret;             \
		}                               \
	} while (0)

#define ZXDH_CHECK_RET_GOTO_ERR(ret, err, fmt, arg...) \
	do {                                           \
		if ((ret) != 0) {                      \
			LOG_ERR(fmt, ##arg);           \
			goto err;                      \
		}                                      \
	} while (0)

struct dh_irq_table {
	void *priv;
};

/*core dev*/
enum dh_coredev_type { DH_COREDEV_PF, DH_COREDEV_VF, DH_COREDEV_SF, DH_COREDEV_MPF };

enum {
	ZXDH_DROP_NEW_HEALTH_WORK,
	ZXDH_UNLOAD,
	ZXDH_LOAD,
	ZXDH_REMOVE,
};

typedef void (*zxdh_cmd_cbk_t)(int32_t status, void *context);

struct dh_core_dev;

struct dh_core_devlink_ops {
	int32_t (*params_register)(struct devlink *devlink);
	int32_t (*params_unregister)(struct devlink *devlink);
};

enum zxdh_device_state {
	ZXDH_DEVICE_STATE_UNINITIALIZED,
	ZXDH_DEVICE_STATE_UP,
	ZXDH_DEVICE_STATE_INTERNAL_ERROR,
	ZXDH_DEVICE_STATE_OPENED,
};

struct dh_core_dev {
	struct device *device; /* pdev->dev or zxdh auxiliary device*/
	enum dh_coredev_type coredev_type;
	enum zxdh_device_state device_state;
	uint8_t driver_process;
	uint8_t rsv;
	struct pci_dev *pdev; /* parent pdev*/
	struct pcie_zf_ep *zf_ep;
	struct dh_eq_table eq_table;
	struct dh_irq_table irq_table;
	struct dh_core_dev *parent;
	struct dh_events *events;
	int32_t numa_node;
	struct devlink *devlink;
	struct mutex lock;
	struct dh_core_devlink_ops *devlink_ops;
	char priv[] __aligned(32);
};

#define VF_MAX_UNICAST_MAC 128
#define VF_MAX_MULTICAST_MAC 32

struct k_mac_addr {
	uint8_t mac_addr[ETH_ALEN];
	uint8_t dhtool_mac_set_flag;
};

struct device_mac {
	struct k_mac_addr unicast_mac[VF_MAX_UNICAST_MAC];
	struct k_mac_addr multicast_mac[VF_MAX_MULTICAST_MAC];
	uint32_t current_unicast_num;
	uint32_t current_multicast_num;
};

struct tmp_mac {
	uint8_t mac_addr[ETH_ALEN];
};

struct recover_mac {
	struct tmp_mac umac[VF_MAX_UNICAST_MAC];
	struct tmp_mac mmac[VF_MAX_MULTICAST_MAC];
	uint32_t umac_num;
	uint32_t mmac_num;
};

struct zxdh_vf_item {
	uint8_t mac[6];
	uint16_t vlan;
	uint8_t qos;
	bool spoofchk;
	bool trusted;
	bool pf_set_mac;
	bool link_forced;
	bool link_up;
	bool promisc;
	bool mc_promisc;
	bool enable;
	uint32_t min_tx_rate;
	uint32_t max_tx_rate;
	uint16_t vf_rate_mode;
	uint16_t vport;
	bool is_probed;
	struct device_mac vf_mac_info;
	uint16_t vlan_proto;
	void *init_np_stats;
	struct mutex lock;
};

struct zxdh_en_vport_np_stats {
	uint64_t rx_vport_unicast_packets;
	uint64_t tx_vport_unicast_packets;
	uint64_t rx_vport_unicast_bytes;
	uint64_t tx_vport_unicast_bytes;
	uint64_t rx_vport_multicast_packets;
	uint64_t tx_vport_multicast_packets;
	uint64_t rx_vport_multicast_bytes;
	uint64_t tx_vport_multicast_bytes;
	uint64_t rx_vport_broadcast_packets;
	uint64_t tx_vport_broadcast_packets;
	uint64_t rx_vport_broadcast_bytes;
	uint64_t tx_vport_broadcast_bytes;
	uint64_t rx_vport_mtu_drop_packets;
	uint64_t tx_vport_mtu_drop_packets;
	uint64_t rx_vport_mtu_drop_bytes;
	uint64_t tx_vport_mtu_drop_bytes;
	uint64_t rx_vport_plcr_drop_packets;
	uint64_t tx_vport_plcr_drop_packets;
	uint64_t rx_vport_plcr_drop_bytes;
	uint64_t tx_vport_plcr_drop_bytes;
	uint64_t tx_vport_ssvpc_packets;
	uint64_t rx_vport_idma_drop_packets;
};

static inline bool dh_core_is_pf(const struct dh_core_dev *dev)
{
	return dev->coredev_type == DH_COREDEV_PF;
}

static inline bool dh_core_is_vf(const struct dh_core_dev *dev)
{
	return dev->coredev_type == DH_COREDEV_VF;
}

static inline void *dh_core_priv(struct dh_core_dev *dh_coredev)
{
	WARN_ON(!dh_coredev);
	return &dh_coredev->priv;
}

int32_t zxdh_cmd_exec(struct dh_core_dev *dev, void *in, int32_t in_size, void *out,
		      int32_t out_size);

#define zxdh_cmd_exec_inout(dev, ifc_cmd, in, out)                        \
	({                                                                \
		zxdh_cmd_exec(dev, in, DH_ST_SZ_BYTES(ifc_cmd##_in), out, \
			      DH_ST_SZ_BYTES(ifc_cmd##_out));             \
	})

#define zxdh_cmd_exec_in(dev, ifc_cmd, in)                      \
	({                                                      \
		uint32_t _out[DH_ST_SZ_DW(ifc_cmd##_out)] = {}; \
		zxdh_cmd_exec_inout(dev, ifc_cmd, in, _out);    \
	})

#define LOG_ERR(fmt, arg...) DH_LOG_ERR(MODULE_PF, fmt, ##arg)
#define LOG_INFO(fmt, arg...) DH_LOG_INFO(MODULE_PF, fmt, ##arg)
#define LOG_DEBUG(fmt, arg...) DH_LOG_DEBUG(MODULE_PF, fmt, ##arg)
#define LOG_WARN(fmt, arg...) DH_LOG_WARNING(MODULE_PF, fmt, ##arg)

#define HEAL_ERR(fmt, arg...) DH_LOG_ERR(MODULE_HEAL, fmt, ##arg)
#define HEAL_INFO(fmt, arg...) DH_LOG_INFO(MODULE_HEAL, fmt, ##arg)
#define HEAL_DEBUG(fmt, arg...) DH_LOG_DEBUG(MODULE_HEAL, fmt, ##arg)

#define ZXDH_EN_SF_NAME "zxdh_en"
#define ZXDH_EN_DEV_ID_NAME "en_aux"
#define ZXDH_PF_EN_SF_DEV_ID_NAME "pf_en_sf"
#define ZXDH_PF_NAME "dinghai10e"
#define ZXDH_MPF_EN_SF_DEV_ID_NAME "mpf_en_sf"
#define ZXDH_RDMA_DEV_NAME "rdma_aux"
#define ZXDH_SEC_DEV_NAME "sec_aux"

#define ZXDH_PF_BSI_VENDOR_ID 0x16c3
#define ZXDH_PF_VENDOR_ID 0x1cf2
#define ZXDH_PF_DEVICE_ID 0x8040
#define ZXDH_VF_DEVICE_ID 0x8041
#define ZXDH_INICA_BOND_DEVICE_ID 0x8045
#define ZXDH_INICB_BOND_DEVICE_ID 0x8063
#define ZXDH_INICC_BOND_DEVICE_ID 0x8066
#define ZXDH_INICD_BOND0_DEVICE_ID 0x8075
#define ZXDH_INICD_BOND1_DEVICE_ID 0x8078
#define ZXDH_DPUA_BOND_DEVICE_ID 0x8047
#define ZXDH_PF_DPUB_NOF_DEVICE_ID 0x804a
#define ZXDH_PF_DPUB_PF_DEVICE_ID 0x804b
#define ZXDH_PF_DPUB_INITIATOR1_DEVICE_ID 0x804c
#define ZXDH_PF_DPUB_INITIATOR2_DEVICE_ID 0x804d
#define ZXDH_PF_DPUB_RDMA_DEVICE_ID 0x806b
#define ZXDH_VF_DPUB_RDMA_DEVICE_ID 0x806c
#define ZXDH_PF_DPUB_SRIOV0_DEVICE_ID 0x8089
#define ZXDH_PF_DPUB_SRIOV1_DEVICE_ID 0x808a

#define ZXDH_PF_E310_DEVICE_ID 0x8061
#define ZXDH_VF_E310_DEVICE_ID 0x8062
#define ZXDH_PF_E310_CMCC_DEVICE_ID 0x80b0
#define ZXDH_VF_E310_CMCC_DEVICE_ID 0x80b1
#define ZXDH_PF_E312_DEVICE_ID 0x80a0
#define ZXDH_VF_E312_DEVICE_ID 0x80a1
#define ZXDH_UPF_PF_I512_DEVICE_ID 0x804e
#define ZXDH_UPF_VF_I512_DEVICE_ID 0x804f
#define ZXDH_INICA_RDMA_PF_DEVICE_ID 0x806d
#define ZXDH_INICA_RDMA_VF_DEVICE_ID 0x806e
#define ZXDH_INICA_UPF_BOND_DEVICE_ID 0x806f
#define ZXDH_PF_E316_DEVICE_ID 0x807e
#define ZXDH_VF_E316_DEVICE_ID 0x807f
#define ZXDH_PF_E311_DEVICE_ID 0x8080
#define ZXDH_VF_E311_DEVICE_ID 0x8081
#define ZXDH_PF_I511_DEVICE_ID 0x8082
#define ZXDH_VF_I511_DEVICE_ID 0x8083
#define ZXDH_INICD_NE0_PF_DEVICE_ID 0x8076
#define ZXDH_INICD_NE0_VF_DEVICE_ID 0x8077
#define ZXDH_INICD_NE1_PF_DEVICE_ID 0x8079
#define ZXDH_INICD_NE1_VF_DEVICE_ID 0x807A
#define ZXDH_INICD_NE2_PF_DEVICE_ID 0x807B
#define ZXDH_INICD_NE2_VF_DEVICE_ID 0x807C

/* e310 net rdma */
#define ZXDH_PF_E310_RDMA_DEVICE_ID 0x8084
#define ZXDH_VF_E310_RDMA_DEVICE_ID 0x8085

#define ZXDH_PF_E310S_DEVICE_ID 0x80b6
#define ZXDH_VF_E310S_DEVICE_ID 0x80b7

#define ZXDH_PF_E312S_DEVICE_ID 0x807d
#define ZXDH_VF_E312S_DEVICE_ID 0x8088

#define ZXDH_PF_I510_SRIOV_SEC_DEVICE_ID 0x8086
#define ZXDH_VF_I510_SRIOV_SEC_DEVICE_ID 0x8087
/* e312 rdma */
#define ZXDH_PF_E312_RDMA_DEVICE_ID 0x8049
#define ZXDH_VF_E312_RDMA_DEVICE_ID 0x8060
/* zxinic_i512_offload */
#define ZXDH_PF_INICA_OFFLOAD_DEVICE_ID 0x80a4

/* B512Y-CTCZ100 */
#define CTC_PF_B512Y_DEVICE_ID 0x1100
#define CTC_VF_B512Y_DEVICE_ID 0x1101

/* B522Y-CTCZ100 */
#define CTC_PF_B522Y_DEVICE_ID 0x1110
#define CTC_VF_B522Y_DEVICE_ID 0x1111

/* CTC */
#define CTC_PF_VENDOR_ID 0x1b18

/* XPU */
#define ZXDH_PF_E316_XPU_DEVICE_ID 0x8601
#define ZXDH_VF_E316_XPU_DEVICE_ID 0x8602

#define ZXDH_PF_E316_XPU_VENDER_ID 0x8848

#define ZXDH_PF_E312S_D_DEVICE_ID 0x80a2
#define ZXDH_VF_E312S_D_DEVICE_ID 0x80a3

#define ZXDH_BAR_MSG_OFFSET 0x2000
#define ZXDH_BAR_PFVF_MSG_OFFSET 0x1000
#define ZXDH_BAR_MSG_BASE(vaddr) (ZXDH_BAR_MSG_OFFSET + vaddr)

#define ZXDH_BAR_FWCAP(vaddr) (0x1000 + vaddr)
#define ZXDH_BOARD_TYPE (0X1)
#define ZXDH_PRODUCT_TYPE (0X2)
#define ZXDH_PANNEL_PORT_NUM (0X3)

#define ZXDH_SWITCH_DEVICE_ID (0x8036)

enum dh_board_type {
	DH_DPUA, //x510
	DH_DPUB, //x512
	DH_INICA, //i512
	DH_INICB, //i510
	DH_STDA, //e312 e316
	DH_STDB, //e310
	DH_EVB_EP0,
	DH_EVB_DPU,
	DH_INICC, //i511
	DH_STDC, //e311
	DH_INICD, //vgcf
	DH_STD_E312S, //e312s
	DH_STD_E312S_D, //e312s_d
	DH_STD_E310S, //e310s
};

#define IS_STD_BOARD(type)                                                                        \
	((type) == DH_STDA || (type) == DH_STDB || (type) == DH_STDC || (type) == DH_STD_E312S || \
	 (type) == DH_STD_E312S_D || (type) == DH_STD_E310S)

#define IS_INIC_BOARD(type)                                                                     \
	((type) == DH_INICA || (type) == DH_INICB || (type) == DH_INICC || (type) == DH_DPUA || \
	 (type) == DH_DPUB)

/* Warning: Must be modified together with firmware */
enum {
	ZXDH_PRODUCT_STD = 0,
	ZXDH_PRODUCT_DPI = 1,
	ZXDH_PRODUCT_NEO = 2,
	ZXDH_PRODUCT_OVS = 3,
	ZXDH_PRODUCT_EVB_EP0 = 4,
	ZXDH_PRODUCT_EVB_EP0_EP4 = 5,
};

enum {
	ZXDH_DEV_UNKNOW = 0,
	ZXDH_DEV_UPF = 1,
	ZXDH_DEV_NE0 = 2,
	ZXDH_DEV_NE1 = 3,
};

#define ZXDH_VF_NUM_MAX 256
#define ZXDH_PF_NUM_PER_EP 8

struct resource_range {
	phys_addr_t base;
	resource_size_t size;
};

struct dh_sf_dev {
	struct zxdh_auxiliary_device adev;
	struct dh_core_dev *parent_mdev;
	struct dh_core_dev *mdev;
	int32_t res_num;
	struct resource_range *ranges;
};

struct zf_rbp_info {
	bool host; /* true: host addr  false: zf addr*/
	uint32_t pfid; /* bit7: 0-pf 1-vf */
	uint32_t vfid;
	uint32_t epid;
};

struct zf_dma_addr_rbp {
	dma_addr_t addr; /* src/dst addr */
	uint32_t flag; /* no support */
	struct zf_rbp_info rbp_info;
};

void zxdh_dev_list_lock(void);
void zxdh_dev_list_unlock(void);
int zxdh_dev_list_trylock(void);
int zxdh_health_init(struct dh_core_dev *dev);
int dh_pf_wait_riscv_ready(struct dh_core_dev *dh_dev);
void zxdh_health_cleanup(struct dh_core_dev *dev);
void zxdh_drain_health_wq(struct dh_core_dev *dev);

enum {
	act_health_info_show,
	act_bbx_log_dump,
	act_reset,
	act_reload,
};

#endif
