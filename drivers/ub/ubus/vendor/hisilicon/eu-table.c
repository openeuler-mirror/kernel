// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#define pr_fmt(fmt) "ubus hisi eu: " fmt

#include <linux/debugfs.h>
#include "../../ubus.h"
#include "../../msg.h"
#include "../../eu.h"
#include "hisi-msg.h"
#include "hisi-ubus.h"

enum hi_eu_cfg_msg_code {
	EU_CFG_READ,
	EU_CFG_WRITE
};

enum hi_eu_cfg_mode {
	EU_CFG_SERIAL,
	EU_CFG_DISCRETE
};

enum hi_eu_cfg_status {
	EU_CFG_FAIL,
	EU_CFG_SUCCESS
};

struct hi_eu_cfg_req {
	u32 eu_msg_code:4;
	u32 cfg_entry_num:10;
	u32 tbl_cfg_mode:1;
	u32 tbl_cfg_status:1;
	u32 entry_start_id:16;

	u32 eid:20;
	u32 rsv0:12;

	u32 upi:16;
	u32 rsv1:16;
};
#define HI_EU_CFG_REQ_SIZE 12

struct hi_eu_cfg_rsp {
	u32 eu_msg_code:4;
	u32 cfg_entry_num:10;
	u32 tbl_cfg_mode:1;
	u32 tbl_cfg_status:1;
	u32 entry_start_id:16;
};
#define HI_EU_CFG_RSP_SIZE 4

struct hi_eu_cfg_pld {
	union {
		struct hi_eu_cfg_req req;
		struct hi_eu_cfg_rsp rsp;
	};
};

struct hi_eu_table_private {
	u32 entries;
	unsigned long *bitmap;
	u32 *map;
	struct mutex lock;
};

static int query_bit;

static int hi_eu_query(struct ub_bus_controller *ubc, int bit, u32 *eid, u16 *upi)
{
	struct hi_eu_cfg_pld pld = {};
	struct msg_info info = {};
	int ret;

	/*
	 * The format of the query response packet is the same as that of the
	 * configuration request packet. The format of the query request packet
	 * is the same as that of the configuration response packet. Therefore,
	 * the data structure is directly reused.
	 */

	pld.req.eu_msg_code = EU_CFG_READ;
	pld.req.cfg_entry_num = 1;
	pld.req.tbl_cfg_mode = EU_CFG_SERIAL;
	pld.req.entry_start_id = (u16)bit;

	message_info_init(&info, ubc->uent, &pld, &pld,
			  (HI_EU_CFG_RSP_SIZE << MSG_REQ_SIZE_OFFSET) |
			  HI_EU_CFG_REQ_SIZE);

	ret = hi_message_private(ubc->mdev, &info, EU_TABLE_CFG_CMD);
	if (ret || pld.rsp.tbl_cfg_status != EU_CFG_SUCCESS) {
		dev_err(&ubc->dev, "eu query bit(%d) failed, ret=%d, status=%u\n",
			bit, ret, pld.rsp.tbl_cfg_status);
		return ret ? ret : -EBUSY;
	}

	*eid = pld.req.eid;
	*upi = pld.req.upi;

	return 0;
}

static ssize_t hi_eu_table_info_read(struct file *file, char __user *ubuf,
				     size_t size, loff_t *loff)
{
	struct ub_bus_controller *ubc =
		(struct ub_bus_controller *)file->f_inode->i_private;
	char buf[SZ_64];
	size_t len;
	u32 eid;
	u16 upi;
	int ret;

	ret = hi_eu_query(ubc, query_bit, &eid, &upi);
	if (ret)
		return ret;

	len = (size_t)scnprintf(buf, sizeof(buf),
				"eu query bit %d eid %#05x upi %#04x\n",
				query_bit, eid, upi);

	return simple_read_from_buffer(ubuf, size, loff, buf, len);
}

static ssize_t hi_eu_table_info_write(struct file *file,
				      const char __user *ubuf,
				      size_t size, loff_t *loff)
{
	struct ub_bus_controller *ubc =
		(struct ub_bus_controller *)file->f_inode->i_private;
#define BUF_SIZE 8
	int len, bit, ret;
	char buf[BUF_SIZE];

	if (*loff != 0)
		return 0;

	if (size >= BUF_SIZE)
		return -ENOSPC;

	len = simple_write_to_buffer(buf, BUF_SIZE - 1, loff, ubuf, size);
	if (len < 0)
		return len;

	buf[len] = '\0';
	ret = kstrtoint(buf, 10, &bit);
	if (ret < 0)
		return ret;

	if (bit >= (int)ubc->uent->eu_table->entries) {
		pr_err("eu table query bit(%d) invalid\n", bit);
		return -EINVAL;
	}

	query_bit = bit;
	return size;
}

static const struct file_operations hi_eu_table_info_ops = {
	.read = hi_eu_table_info_read,
	.write = hi_eu_table_info_write,
};

static void hi_eu_table_debugfs_init(struct ub_bus_controller *ubc)
{
	if (ubc->cluster)
		return;

	debugfs_create_file("eu_table", 0600, ubc->debug_root,
			    ubc, &hi_eu_table_info_ops);
}

static void hi_eu_table_debugfs_uninit(struct ub_bus_controller *ubc)
{
	if (ubc->cluster)
		return;

	debugfs_lookup_and_remove("eu_table", ubc->debug_root);
}

int hi_eu_table_init(struct ub_bus_controller *ubc)
{
	struct ub_eu_table *t = ubc->uent->eu_table;
	struct hi_eu_table_private *p;
	size_t size;

	if (t->entries >= INT_MAX)
		return -EINVAL;

	p = kzalloc(sizeof(*p), GFP_KERNEL);
	if (!p)
		return -ENOMEM;

	p->entries = t->entries;

	size = BITS_TO_LONGS(p->entries) * sizeof(unsigned long);
	p->bitmap = kzalloc(size, GFP_KERNEL);
	if (!p->bitmap)
		goto free;

	p->map = kcalloc(p->entries, sizeof(u32), GFP_KERNEL);
	if (!p->map)
		goto free_bitmap;

	mutex_init(&p->lock);
	t->private_data = p;

	hi_eu_table_debugfs_init(ubc);
	return 0;

free_bitmap:
	kfree(p->bitmap);
free:
	kfree(p);
	return -ENOMEM;
}

void hi_eu_table_uninit(struct ub_bus_controller *ubc)
{
	struct ub_eu_table *t = ubc->uent->eu_table;
	struct hi_eu_table_private *p;

	hi_eu_table_debugfs_uninit(ubc);

	p = (struct hi_eu_table_private *)t->private_data;
	kfree(p->map);
	kfree(p->bitmap);
	kfree(p);
	t->private_data = NULL;
}

static int hi_eu_get_bit(struct hi_eu_table_private *p)
{
	int bit, ret;

	mutex_lock(&p->lock);
	bit = (int)find_first_zero_bit(p->bitmap, p->entries);
	if (bit != (int)p->entries) {
		set_bit(bit, p->bitmap);
		ret = bit;
	} else {
		ret = -ENOSPC;
	}
	mutex_unlock(&p->lock);

	return ret;
}

static void hi_eu_put_bit(struct hi_eu_table_private *p, int bit)
{
	mutex_lock(&p->lock);
	clear_bit(bit, p->bitmap);
	mutex_unlock(&p->lock);
}

static int hi_eu_find_bit_and_mask(struct hi_eu_table_private *p, u32 eid)
{
	u32 bit;

	mutex_lock(&p->lock);
	for_each_set_bit(bit, p->bitmap, p->entries)
		if (p->map[bit] == eid) {
			p->map[bit] = 0;
			break;
		}
	mutex_unlock(&p->lock);

	if (bit == p->entries)
		return -EINVAL;

	return bit;
}

int hi_eu_cfg(struct ub_bus_controller *ubc, bool add, u32 eid, u16 upi)
{
	struct ub_eu_table *eu = ubc->uent->eu_table;
	struct hi_eu_cfg_pld pld = {};
	struct hi_eu_table_private *p;
	struct msg_info info = {};
	struct ub_eu_entry *entry;
	int ret, bit;

	if (!eu)
		return -EINVAL;

	p = (struct hi_eu_table_private *)eu->private_data;

	if (add)
		bit = hi_eu_get_bit(p);
	else
		bit = hi_eu_find_bit_and_mask(p, eid);

	if (bit < 0)
		return bit;

	pld.req.eu_msg_code = EU_CFG_WRITE;
	pld.req.cfg_entry_num = 1;
	pld.req.tbl_cfg_mode = EU_CFG_SERIAL;
	pld.req.entry_start_id = (u16)bit;
	pld.req.eid = add ? eid : 0;
	pld.req.upi = add ? upi : 0;

	message_info_init(&info, ubc->uent, &pld, &pld,
			  (HI_EU_CFG_REQ_SIZE << MSG_REQ_SIZE_OFFSET) |
			  HI_EU_CFG_RSP_SIZE);

	ret = hi_message_private(ubc->mdev, &info, EU_TABLE_CFG_CMD);
	if (ret || pld.rsp.tbl_cfg_status != EU_CFG_SUCCESS) {
		dev_err(&ubc->dev, "eu cfg failed, eid %#05x upi %#04x, ret=%d, status=%u\n",
			eid, upi, ret, pld.rsp.tbl_cfg_status);
		if (add)
			hi_eu_put_bit(p, bit);
		else
			p->map[bit] = eid;
		return ret ? ret : -EBUSY;
	}

	entry = (struct ub_eu_entry *)eu->addr + bit;

	if (add) {
		p->map[bit] = eid;
		entry->eid[0] = eid;
		entry->upi = upi;
	} else {
		entry->eid[0] = 0;
		entry->upi = 0;
		hi_eu_put_bit(p, bit);
	}

	dev_info(&ubc->dev, "eu cfg bit(%d) type(%d) eid %#05x upi %#04x\n",
		 bit, add, eid, upi);

	return 0;
}
