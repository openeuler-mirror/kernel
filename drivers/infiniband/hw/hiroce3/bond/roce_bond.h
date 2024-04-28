/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2024 Huawei Technologies Co., Ltd */

#ifndef ROCE_BOND_H
#define ROCE_BOND_H

#include <net/bonding.h>
#include <linux/netdevice.h>

#include "hinic3_bond.h"

#include "roce.h"
#include "roce_qp.h"
#include "roce_cmd.h"
#include "roce_verbs_attr.h"

#define ROCE_BOND_MAX_GROUPS 2
#define ROCE_BOND_2_100G_MAX_GROUPS 1
#define ROCE_BOND_4_25G_MAX_GROUPS 2

/* Adding two roce at a time consumes one bit of the array.
 * Currently, a maximum of 33 nodes are supported, and at least 17.
 * To support roce hot swap, the code logic needs to be reconstructed.
 */
#define ROCE_BOND_HCA_NUM 17

#define ROCE_BOND_MAX_PORTS 4
#define ROCE_BOND_MAX_FUNCS 4

#define ROCE_BOND_NO_VLAN_ID 0
#define ROCE_BOND_RSVD_VLAN_ID 4095

#define ROCE_BOND_PORT_ENABLE 1
#define ROCE_BOND_PORT_DISABLE 0

#define ROCE_BOND_ADD_MAC_TBL 1
#define ROCE_BOND_DEL_MAC_TBL 0

#define ROCE_BOND_FWD_ID_TBL_ALL_BITS 32
#define ROCE_BOND_FWD_ID_TBL_PER_BITS 3
#define ROCE_BOND_FWD_ID_TBL_PER_BITS_MASK 0x7

#define ROCE_BOND_MAX_ACX_QP_NUM 32
#define ROCE_BOND_ACX_QP_ENABLE 1
#define ROCE_BOND_ACX_QP_DISABLE 0

#define ROCE_BOND_WAIT_ACTIVE_500MS 500
enum {
	ROCE_BOND_FUNC_OWN_FLAG = (1 << 0)
};

enum {
	ROCE_BOND_FLAG = (1 << 0)
};

enum {
	ROCE_BOND_WANT_TWO_SLAVES = 2,		/* 2 slaves per bond_dev */
	ROCE_BOND_WANT_THREE_SLAVES = 3,	/* 3 slaves per bond_dev */
	ROCE_BOND_WANT_FOUR_SLAVES = 4		/* 4 slaves per bond_dev */
};

enum {
	ROCE_BOND_WANT_TWO_SLAVES_MASK = 0x3,
	ROCE_BOND_WANT_THREE_SLAVES_MASK = 0x7,
	ROCE_BOND_WANT_FOUR_SLAVES_MASK = 0xf
};

enum {
	ROCE_BOND_2_PORT_NUM = 2,
	ROCE_BOND_4_PORT_NUM = 4
};

enum {
	ROCE_BOND_25G_PORT_SPEED = 25,
	ROCE_BOND_100G_PORT_SPEED = 100
};

enum {
	ROCE_BOND_2_FUNC_NUM = 2,
	ROCE_BOND_4_FUNC_NUM = 4
};

enum {
	ROCE_BOND_INVALID_HCA = -1,
	ROCE_BOND_2_100G_HCA = 0,
	ROCE_BOND_4_25G_HCA = 1,
	ROCE_BOND_2_25G_HCA = 2
};

#define SDI_BOND_SUPPORT_ROCE_FUNC_BIT 1
#define SDI_BOND_SUPPORT_ROCE_FUNC_CNT 1
#define SDI_BOND_SLAVES_FUNC_NUM 2

struct roce3_bond_slave {
	struct net_device *netdev;
	struct hinic3_lld_dev *lld_dev;
	struct hinic3_lld_dev *ppf_dev;
	struct netdev_lag_lower_state_info netdev_state;
	u32 update_cnt;
	u16 func_id;
	u8 er_id;
	bool is_ppf;
};

typedef void (*roce3_bond_service_func)(const char *bond_name, struct bond_attr *attr);

struct roce3_bond_device {
	char name[IFNAMSIZ];
	struct list_head entry;
	struct roce3_bond_slave slaves[ROCE_BOND_MAX_FUNCS];
	struct mutex slave_lock;
	u32 slave_cnt;
	atomic_t next_port;
	struct work_struct detach_work;
	struct roce3_device *attached_rdev;
	struct bond_attr attr;
};

bool roce3_bond_is_active(struct roce3_device *rdev);
struct net_device *roce3_bond_get_netdev(struct roce3_device *rdev);

int roce3_add_bond_real_slave_mac(struct roce3_device *rdev, u8 *mac);
int roce3_add_bond_vlan_slave_mac(struct roce3_device *rdev, u8 *mac, u16 vlan_id);
void roce3_del_bond_real_slave_mac(struct roce3_device *rdev);
void roce3_del_bond_vlan_slave_mac(struct roce3_device *rdev, u8 *mac, u16 vlan_id);

int roce3_bond_is_eth_port_of_netdev(struct roce3_device *rdev,
				     struct net_device *event_ndev);

void roce3_bond_rr_set_flow(struct roce3_device *rdev,
			    struct roce3_qp *rqp, struct tag_roce_verbs_qp_attr *qp_attr);

int roce3_bond_event_cfg_rdev(struct hinic3_lld_dev *lld_dev,
			      void *uld_dev, struct roce3_device **rdev);
int roce3_bonded_port_event_report(struct roce3_device *rdev,
				   const struct hinic3_event_info *event);
void roce3_handle_bonded_port_state_event(struct roce3_device *rdev);

bool roce3_get_bond_ipsurx_en(void);
void roce3_set_bond_ipsurx_en(bool ipsurx_en);

int roce3_bond_attach(struct roce3_device *rdev);
int roce3_bond_init(void);
void roce3_bond_pre_exit(void);
void roce3_bond_exit(void);

#endif
