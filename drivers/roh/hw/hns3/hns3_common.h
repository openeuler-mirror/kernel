/* SPDX-License-Identifier: GPL-2.0+ */
// Copyright (c) 2022 Hisilicon Limited.
#ifndef __HNS3_ROH_COMMON_H__
#define __HNS3_ROH_COMMON_H__

#include "core.h"
#include "hnae3.h"

#define HNS3_ROH_VERSION "1.0"

#define HNS3_ROH_MIN_VECTOR_NUM 2

#define HNS3_ROH_NAME "roh"
#define HNS3_ROH_INT_NAME_LEN 32

#define HNS3_ROH_DESC_DATA_LEN 6

#define HNS3_ROH_RD_FIRST_STATS_NUM 3
#define HNS3_ROH_RD_OTHER_STATS_NUM 4

#define HNS3_ROH_HW_RST_UNINT_DELAY 100

struct hns3_roh_desc {
	__le16 opcode;

#define HNS3_ROH_CMDQ_RX_INVLD_B 0
#define HNS3_ROH_CMDQ_RX_OUTVLD_B 1

	__le16 flag;
	__le16 retval;
	__le16 rsv;
	__le32 data[HNS3_ROH_DESC_DATA_LEN];
};

struct hns3_roh_cmdq_ring {
	dma_addr_t desc_dma_addr;
	struct hns3_roh_desc *desc;
	u32 head;
	u32 tail;

	u16 buf_size;
	u16 desc_num;
	int next_to_use;
	int next_to_clean;
	u8 flag;
	spinlock_t lock; /* CMDq lock */
};

struct hns3_roh_cmdq {
	struct hns3_roh_cmdq_ring csq;
	struct hns3_roh_cmdq_ring crq;
	u16 tx_timeout;
	u16 last_status;
};

struct hns3_roh_priv {
	struct hnae3_handle *handle;
	struct hns3_roh_cmdq cmdq;
	unsigned long state;
};

struct hns3_roh_intr_info {
	u16 base_vector;
	u16 vector_offset;
	u16 vector_num;
};

struct hns3_roh_abn_vector {
	u8 __iomem *addr;
	int vector_irq;
	char name[HNS3_ROH_INT_NAME_LEN];
};

struct hns3_roh_device {
	struct roh_device roh_dev;
	struct pci_dev *pdev;
	struct device *dev;
	bool active;
	struct net_device *netdev;

	u8 __iomem *reg_base;
	const struct hns3_roh_hw *hw;
	struct hns3_roh_priv *priv;

	struct hns3_roh_intr_info intr_info;
	struct hns3_roh_abn_vector abn_vector;
	unsigned long last_processed;
	unsigned long state;
	struct delayed_work srv_task;
	struct dentry *dfx_debugfs;
};

struct hns3_roh_hw {
	int (*cmdq_init)(struct hns3_roh_device *hroh_dev);
	void (*cmdq_exit)(struct hns3_roh_device *hroh_dev);
};

static inline struct hns3_roh_device *to_hroh_dev(struct roh_device *rohdev)
{
	return container_of(rohdev, struct hns3_roh_device, roh_dev);
}

#define hns3_roh_set_field(origin, mask, shift, val) \
	do { \
		(origin) &= (~(mask)); \
		(origin) |= ((val) << (shift)) & (mask); \
	} while (0)
#define hns3_roh_get_field(origin, mask, shift) (((origin) & (mask)) >> (shift))

#define hns3_roh_set_bit(origin, shift, val) \
	hns3_roh_set_field(origin, 0x1 << (shift), shift, val)
#define hns3_roh_get_bit(origin, shift) \
	hns3_roh_get_field(origin, 0x1 << (shift), shift)

void hns3_roh_task_schedule(struct hns3_roh_device *hroh_dev,
			    unsigned long delay_time);
void hns3_roh_mbx_handler(struct hns3_roh_device *hroh_dev);
void hns3_roh_mbx_task_schedule(struct hns3_roh_device *hroh_dev);
#endif
