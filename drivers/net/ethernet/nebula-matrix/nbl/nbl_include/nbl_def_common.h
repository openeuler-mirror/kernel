/* SPDX-License-Identifier: GPL-2.0*/
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#ifndef _NBL_DEF_COMMON_H_
#define _NBL_DEF_COMMON_H_

#include "nbl_include.h"
#include <linux/netdevice.h>
#include <linux/netdev_features.h>

#define NBL_OK 0
#define NBL_CONTINUE 1
#define NBL_FAIL -1

#define NBL_HASH_CFT_MAX				4
#define NBL_HASH_CFT_AVL				2

#define NBL_CRC16_CCITT(data, size)		\
			nbl_calc_crc16(data, size, 0x1021, 0x0000, 1, 0x0000)
#define NBL_CRC16_CCITT_FALSE(data, size)	\
			nbl_calc_crc16(data, size, 0x1021, 0xFFFF, 0, 0x0000)
#define NBL_CRC16_XMODEM(data, size)		\
			nbl_calc_crc16(data, size, 0x1021, 0x0000, 0, 0x0000)
#define NBL_CRC16_IBM(data, size)		\
			nbl_calc_crc16(data, size, 0x8005, 0x0000, 1, 0x0000)

static inline void nbl_tcam_truth_value_convert(u64 *data, u64 *mask)
{
	u64 tcam_x = 0;
	u64 tcam_y = 0;

	tcam_x = *data & ~(*mask);
	tcam_y = ~(*data) & ~(*mask);

	*data = tcam_x;
	*mask = tcam_y;
}

static inline u8 nbl_invert_uint8(const u8 data)
{
	u8 i, result = 0;

	for (i = 0; i < 8; i++) {
		if (data & (1 << i))
			result |= 1 << (7 - i);
	}

	return result;
}

static inline u16 nbl_invert_uint16(const u16 data)
{
	u16 i, result = 0;

	for (i = 0; i < 16; i++) {
		if (data & (1 << i))
			result |= 1 << (15 - i);
	}

	return result;
}

static inline u16 nbl_calc_crc16(const u8 *data, u32 size, u16 crc_poly,
				 u16 init_value, u8 ref_flag, u16 xorout)
{
	u16 crc_reg = init_value, tmp = 0;
	u8 j, byte = 0;

	while (size--) {
		byte = *(data++);
		if (ref_flag)
			byte = nbl_invert_uint8(byte);
		crc_reg ^= byte << 8;
		for (j = 0; j < 8; j++) {
			tmp = crc_reg & 0x8000;
			crc_reg <<= 1;
			if (tmp)
				crc_reg ^= crc_poly;
		}
	}

	if (ref_flag)
		crc_reg = nbl_invert_uint16(crc_reg);

	crc_reg = crc_reg ^ xorout;
	return crc_reg;
}

static inline u16 nbl_hash_transfer(u16 hash, u16 power, u16 depth)
{
	u16 temp = 0;
	u16 val = 0;
	u32 val2 = 0;
	u16 off = 16 - power;

	temp = (hash >> power);
	val = hash << off;
	val = val >> off;

	if (depth == 0) {
		val = temp + val;
		val = val << off;
		val = val >> off;
	} else {
		val2 = val;
		val2 *= depth;
		val2 = val2 >> power;
		val = (u16)val2;
	}

	return val;
}

/* debug masks - set these bits in adapter->debug_mask to control output */
enum nbl_debug_mask {
	/* BIT0~BIT30 use to define adapter debug_mask */
	NBL_DEBUG_MAIN			= 0x00000001,
	NBL_DEBUG_COMMON		= 0x00000002,
	NBL_DEBUG_DEBUGFS		= 0x00000004,
	NBL_DEBUG_PHY			= 0x00000008,
	NBL_DEBUG_FLOW			= 0x00000010,
	NBL_DEBUG_RESOURCE		= 0x00000020,
	NBL_DEBUG_QUEUE			= 0x00000040,
	NBL_DEBUG_INTR			= 0x00000080,
	NBL_DEBUG_ADMINQ		= 0x00000100,
	NBL_DEBUG_DEVLINK		= 0x00000200,
	NBL_DEBUG_ACCEL			= 0x00000400,
	NBL_DEBUG_MBX			= 0x00000800,
	NBL_DEBUG_ST			= 0x00001000,
	NBL_DEBUG_VSI			= 0x00002000,
	NBL_DEBUG_CUSTOMIZED_P4		= 0x00004000,

	/* BIT31 use to distinguish netif debug level or adapter debug_mask */
	NBL_DEBUG_USER			= 0x80000000,

	/* Means turn on all adapter debug_mask */
	NBL_DEBUG_ALL			= 0xFFFFFFFF
};

#define nbl_err(common, lvl, fmt, ...)						\
do {										\
	typeof(common) _common = (common);					\
	if (((lvl) & NBL_COMMON_TO_DEBUG_LVL(_common)))				\
		dev_err(NBL_COMMON_TO_DEV(_common), fmt, ##__VA_ARGS__);	\
} while (0)

#define nbl_warn(common, lvl, fmt, ...)						\
do {										\
	typeof(common) _common = (common);					\
	if (((lvl) & NBL_COMMON_TO_DEBUG_LVL(_common)))				\
		dev_warn(NBL_COMMON_TO_DEV(_common), fmt, ##__VA_ARGS__);	\
} while (0)

#define nbl_info(common, lvl, fmt, ...)						\
do {										\
	typeof(common) _common = (common);					\
	if (((lvl) & NBL_COMMON_TO_DEBUG_LVL(_common)))				\
		dev_info(NBL_COMMON_TO_DEV(_common), fmt, ##__VA_ARGS__);	\
} while (0)

#define nbl_debug(common, lvl, fmt, ...)					\
do {										\
	typeof(common) _common = (common);					\
	if (((lvl) & NBL_COMMON_TO_DEBUG_LVL(_common)))				\
		dev_dbg(NBL_COMMON_TO_DEV(_common), fmt, ##__VA_ARGS__);	\
} while (0)

#define NBL_COMMON_TO_PDEV(common)		((common)->pdev)
#define NBL_COMMON_TO_DEV(common)		((common)->dev)
#define NBL_COMMON_TO_DMA_DEV(common)		((common)->dma_dev)
#define NBL_COMMON_TO_VSI_ID(common)		((common)->vsi_id)
#define NBL_COMMON_TO_ETH_ID(common)		((common)->eth_id)
#define NBL_COMMON_TO_ETH_MODE(common)		((common)->eth_mode)
#define NBL_COMMON_TO_DEBUG_LVL(common)		((common)->debug_lvl)
#define NBL_COMMON_TO_VF_CAP(common)		((common)->is_vf)
#define NBL_COMMON_TO_PCI_USING_DAC(common)	((common)->pci_using_dac)
#define NBL_COMMON_TO_MGT_PF(common)		((common)->mgt_pf)
#define NBL_COMMON_TO_PCI_FUNC_ID(common)	((common)->function)
#define NBL_COMMON_TO_BOARD_ID(common)		((common)->board_id)

#define NBL_ONE_ETHERNET_PORT			(1)
#define NBL_TWO_ETHERNET_PORT			(2)
#define NBL_FOUR_ETHERNET_PORT			(4)
#define NBL_TWO_ETHERNET_VSI_ID_GAP		(512)
#define NBL_FOUR_ETHERNET_VSI_ID_GAP		(256)
#define NBL_VSI_ID_GAP(mode)			((mode) == NBL_FOUR_ETHERNET_PORT ?	\
						 NBL_FOUR_ETHERNET_VSI_ID_GAP :		\
						 NBL_TWO_ETHERNET_VSI_ID_GAP)

#define NBL_BOOTIS_ECPU_ETH0_FUNCTION		(2)
#define NBL_BOOTIS_ECPU_ETH1_FUNCTION		(3)
#define NBL_BOOTIS_ECPU_ETH0_VSI		(2020)
#define NBL_BOOTIS_ECPU_ETH1_VSI		(2021)

#define NBL_REP_FILL_EXT_HDR			(1)
#define NBL_PF_FILL_EXT_HDR			(2)

#define NBL_SKB_FILL_VSI_ID_OFF			(32)
#define NBL_SKB_FILL_EXT_HDR_OFF		(34)

#define NBL_INDEX_SIZE_MAX  (64 * 1024)  /* index max sise */

#define NBL_INDEX_TBL_KEY_INIT(key, dev_arg, start_index_arg, index_size_arg, key_size_arg)	\
do {												\
	typeof(key)	__key   = key;								\
	__key->dev		= dev_arg;							\
	__key->start_index	= start_index_arg;						\
	__key->index_size	= index_size_arg;						\
	__key->key_size		= key_size_arg;							\
} while (0)

struct nbl_common_info {
	struct pci_dev *pdev;
	struct device *dev;
	struct device *dma_dev;
	u32 debug_lvl;
	u32 msg_enable;
	u16 vsi_id;
	u8 eth_id;
	u8 eth_mode;
	u8 is_vf;

	u8 function;
	u8 devid;
	u8 bus;

	u16 mgt_pf;
	u8 board_id;

	bool pci_using_dac;
	u8 tc_inst_id; /* for tc flow and cmdq */

	enum nbl_product_type product_type;
};

struct nbl_netdev_rep_attr {
	struct attribute attr;
	ssize_t (*show)(struct device *dev,
			struct nbl_netdev_rep_attr *attr, char *buf);
	ssize_t (*store)(struct device *dev,
			 struct nbl_netdev_rep_attr *attr, const char *buf, size_t len);
	int rep_id;
};

struct nbl_index_tbl_key {
	struct device *dev;
	u32 start_index;
	u32 index_size; /* the avail index is [start_index, start_index + index_size) */
	u32 key_size;
};

struct nbl_hash_tbl_key {
	struct device *dev;
	u16 key_size;
	u16 data_size; /* no include key or node member */
	u16 bucket_size;
	u8 lock_need;  /* true: support multi thread operation */
	u8 resv;
};

#define NBL_HASH_TBL_KEY_INIT(key, dev_arg, key_size_arg, data_size_arg, bucket_size_arg,	\
			      lock_need_args)							\
do {												\
	typeof(key)	__key   = key;								\
	__key->dev		= dev_arg;							\
	__key->key_size		= key_size_arg;							\
	__key->data_size	= data_size_arg;						\
	__key->bucket_size	= bucket_size_arg;						\
	__key->lock_need	= lock_need_args;						\
	__key->resv		= 0;								\
} while (0)

enum nbl_hash_tbl_op_type {
	NBL_HASH_TBL_OP_SHOW = 0,
	NBL_HASH_TBL_OP_DELETE,
};

struct nbl_hash_tbl_del_key {
	void *action_priv;
	void (*action_func)(void *priv, void *key, void *data);
};

#define NBL_HASH_TBL_DEL_KEY_INIT(key, priv_arg, act_func_arg)					\
do {												\
	typeof(key)	__key   = key;								\
	__key->action_priv	= priv_arg;							\
	__key->action_func	= act_func_arg;							\
} while (0)

struct nbl_hash_tbl_scan_key {
	enum nbl_hash_tbl_op_type op_type;
	void *match_condition;
	 /* match ret value must be 0  if the node accord with the condition */
	int (*match_func)(void *condition, void *key, void *data);
	void *action_priv;
	void (*action_func)(void *priv, void *key, void *data);
};

#define NBL_HASH_TBL_SCAN_KEY_INIT(key, op_type_arg, con_arg, match_func_arg, priv_arg,		\
				   act_func_arg)						\
do {												\
	typeof(key)	__key   = key;								\
	__key->op_type		= op_type_arg;							\
	__key->match_condition	= con_arg;							\
	__key->match_func	= match_func_arg;						\
	__key->action_priv	= priv_arg;							\
	__key->action_func	= act_func_arg;							\
} while (0)

struct nbl_hash_xy_tbl_key {
	struct device *dev;
	u16 x_axis_key_size;
	u16 y_axis_key_size; /* y_axis_key_len = key_len - x_axis_key_len */
	u16 data_size; /* no include key or node member */
	u16 bucket_size;
	u16 x_axis_bucket_size;
	u16 y_axis_bucket_size;
	u8 lock_need;  /* true: support multi thread operation */
	u8 resv[3];
};

#define NBL_HASH_XY_TBL_KEY_INIT(key, dev_arg, x_key_size_arg, y_key_size_arg, data_size_arg,	\
				 bucket_size_args, x_bucket_size_arg, y_bucket_size_arg,	\
				 lock_need_args)						\
do {												\
	typeof(key)	__key   = key;								\
	__key->dev		= dev_arg;							\
	__key->x_axis_key_size	= x_key_size_arg;						\
	__key->y_axis_key_size	= y_key_size_arg;						\
	__key->data_size	= data_size_arg;						\
	__key->bucket_size	= bucket_size_args;						\
	__key->x_axis_bucket_size	= x_bucket_size_arg;					\
	__key->y_axis_bucket_size	= y_bucket_size_arg;					\
	__key->lock_need	= lock_need_args;						\
	memset(__key->resv, 0, sizeof(__key->resv));						\
} while (0)

enum nbl_hash_xy_tbl_scan_type {
	NBL_HASH_TBL_ALL_SCAN = 0,
	NBL_HASH_TBL_X_AXIS_SCAN,
	NBL_HASH_TBL_Y_AXIS_SCAN,
};

/* true: only query the match one, eg. if x_axis: mac; y_axist: vlan*/
/**
 * member "only_query_exist" use
 * if true: only query the match one, eg. if x_axis: mac; y_axis: vlan, if only to query the tbl
 * has a gevin "mac", the nbl_hash_xy_tbl_scan_key struct use as flow:
 * op_type = NBL_HASH_TBL_OP_SHOW;
 * scan_type = NBL_HASH_TBL_X_AXIS_SCAN;
 * only_query_exist = true;
 * x_key = the mac_addr;
 * y_key = NULL;
 * match_func = NULL;
 * action_func = NULL;
 */
struct nbl_hash_xy_tbl_scan_key {
	enum nbl_hash_tbl_op_type op_type;
	enum nbl_hash_xy_tbl_scan_type scan_type;
	bool only_query_exist;
	u8 resv[3];
	void *x_key;
	void *y_key;
	void *match_condition;
	 /* match ret value must be 0  if the node accord with the condition */
	int (*match_func)(void *condition, void *x_key, void *y_key, void *data);
	void *action_priv;
	void (*action_func)(void *priv, void *x_key, void *y_key, void *data);
};

#define NBL_HASH_XY_TBL_SCAN_KEY_INIT(key, op_type_arg, scan_type_arg, query_flag_arg,		\
				      x_key_arg, y_key_arg, con_arg, match_func_arg,		\
				      priv_arg, act_func_arg)					\
do {												\
	typeof(key)	__key   = key;								\
	__key->op_type		= op_type_arg;							\
	__key->scan_type	= scan_type_arg;						\
	__key->only_query_exist	= query_flag_arg;						\
	memset(__key->resv, 0, sizeof(__key->resv));						\
	__key->x_key		= x_key_arg;							\
	__key->y_key		= y_key_arg;							\
	__key->match_condition	= con_arg;							\
	__key->match_func	= match_func_arg;						\
	__key->action_priv	= priv_arg;							\
	__key->action_func	= act_func_arg;							\
} while (0)

struct nbl_hash_xy_tbl_del_key {
	void *action_priv;
	void (*action_func)(void *priv, void *x_key, void *y_key, void *data);
};

#define NBL_HASH_XY_TBL_DEL_KEY_INIT(key, priv_arg, act_func_arg)				\
do {												\
	typeof(key)	__key   = key;								\
	__key->action_priv	= priv_arg;							\
	__key->action_func	= act_func_arg;							\
} while (0)

void nbl_convert_mac(u8 *mac, u8 *reverse_mac);

void nbl_common_queue_work(struct work_struct *task, bool ctrl_task, bool singlethread);
void nbl_common_queue_work_rdma(struct work_struct *task);
void nbl_common_queue_delayed_work(struct delayed_work *task,  u32 msec,
				   bool ctrl_task, bool singlethread);
void nbl_common_queue_delayed_work_keepalive(struct delayed_work *task, u32 msec);
void nbl_common_release_task(struct work_struct *task);
void nbl_common_alloc_task(struct work_struct *task, void *func);
void nbl_common_release_delayed_task(struct delayed_work *task);
void nbl_common_alloc_delayed_task(struct delayed_work *task, void *func);
void nbl_common_flush_task(struct work_struct *task);

void nbl_common_destroy_wq(void);
int nbl_common_create_wq(void);

void nbl_debugfs_func_init(void *p, struct nbl_init_param *param);
void nbl_debugfs_func_remove(void *p);

bool nbl_dma_iommu_status(struct pci_dev *pdev);
bool nbl_dma_remap_status(struct pci_dev *pdev);
void nbl_net_addr_rep_attr(struct nbl_netdev_rep_attr *rep_attr, int rep_id);
u32 nbl_common_pf_id_subtraction_mgtpf_id(struct nbl_common_info *common, u32 pf_id);
void *nbl_common_init_index_table(struct nbl_index_tbl_key *key);
void nbl_common_remove_index_table(void *priv);
int nbl_common_get_index(void *priv, void *key, u32 key_size);
void nbl_common_free_index(void *priv, void *key, u32 key_size);

/* ----  EVENT-NOTIFIER  ---- */
enum nbl_event_type {
	NBL_EVENT_LAG_UPDATE = 0,
	NBL_EVENT_OFFLOAD_STATUS_CHANGED,
	NBL_EVENT_LINK_STATE_UPDATE,
	NBL_EVENT_DEV_MODE_SWITCH,
	NBL_EVENT_RDMA_ADEV_UPDATE,
	NBL_EVENT_MAX,
};

struct nbl_event_callback {
	int (*callback)(u16 type, void *event_data, void *callback_data);
	void *callback_data;
};

struct nbl_event_dev_mode_switch_data {
	int op;
	int ret;
};

void nbl_event_notify(enum nbl_event_type type, void *event_data, u16 src_vsi_id, u16 board_id);
int nbl_event_register(enum nbl_event_type type, struct nbl_event_callback *callback,
		       u16 src_vsi_id, u16 board_id);
void nbl_event_unregister(enum nbl_event_type type, struct nbl_event_callback *callback,
			  u16 src_vsi_id, u16 board_id);
int nbl_event_init(void);
void nbl_event_remove(void);

void *nbl_common_init_hash_table(struct nbl_hash_tbl_key *key);
void nbl_common_remove_hash_table(void *priv, struct nbl_hash_tbl_del_key *key);
int nbl_common_alloc_hash_node(void *priv, void *key, void *data);
void *nbl_common_get_hash_node(void *priv, void *key);
void nbl_common_free_hash_node(void *priv, void *key);
void nbl_common_scan_hash_node(void *priv, struct nbl_hash_tbl_scan_key *key);
u16 nbl_common_get_hash_node_num(void *priv);

void *nbl_common_init_hash_xy_table(struct nbl_hash_xy_tbl_key *key);
void nbl_common_remove_hash_xy_table(void *priv, struct nbl_hash_xy_tbl_del_key *key);
int nbl_common_alloc_hash_xy_node(void *priv, void *x_key, void *y_key, void *data);
void *nbl_common_get_hash_xy_node(void *priv, void *x_key, void *y_key);
void nbl_common_free_hash_xy_node(void *priv, void *x_key, void *y_key);
u16 nbl_common_scan_hash_xy_node(void *priv, struct nbl_hash_xy_tbl_scan_key *key);
u16 nbl_common_get_hash_xy_node_num(void *priv);
#endif
