/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_bond.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": [BOND]" fmt

#include <net/sock.h>
#include <net/bonding.h>
#include <net/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/net.h>
#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/list.h>

#include "comm_defs.h"
#include "cfg_mgmt_mpu_cmd_defs.h"
#include "hinic5_lld.h"
#include "hinic5_vram_common.h"
#include "hinic5_srv_nic.h"
#include "hinic5_hw.h"
#include "bond_mpu_cmd_defs.h"
#include "bond_cfm_cmd.h"
#include "cfm_cmd.h"
#include "hinic5_bond_inner.h"
#include "ossl_knl.h"
#include "hinic5_bond.h"

enum bond_service_proc_pos {
	BOND_BEFORE_ACTIVE,
	BOND_AFTER_ACTIVE,
	BOND_BEFORE_MODIFY,
	BOND_AFTER_MODIFY,
	BOND_BEFORE_DEACTIVE,
	BOND_AFTER_DEACTIVE,
	BOND_POS_MAX
};

#define PCI_DBDF(dom, bus, dev, func) \
	(((dom) << 16) | ((bus) << 8) | ((dev) << 3) | ((func) & 0x7))

struct hinic5_bond_mngr {
	u32 cnt;
	struct hinic5_bond_dev __rcu **bond_dev;
	struct socket *rtnl_sock;
	struct list_head bond_chip_list;
};

enum bond_event_cmd {
	BOND_CREATE_CMD = 0,
	BOND_DELETE_CMD,
	BOND_SET_CMD,
	BOND_EVENT_CMD_NUM,
};

static u16 g_cfm_cmd_covert[BOND_EVENT_CMD_NUM] = {
	CFM_MPU_CMD_BOND_CREATE,
	CFM_MPU_CMD_BOND_DELETE,
	CFM_MPU_CMD_BOND_SET,
};

static u16 g_cmd_covert[BOND_EVENT_CMD_NUM] = {
	MPU_CMD_BOND_CREATE,
	MPU_CMD_BOND_DELETE,
	MPU_CMD_BOND_SET_ATTR,
};

static DEFINE_MUTEX(g_bond_event_func_mutex);
static event_func g_bond_event_func[HINIC5_BOND_USER_NUM][BOND_POS_MAX];

static DEFINE_MUTEX(g_bond_attach_func_mutex);
static attach_func g_bond_attach_func[HINIC5_BOND_USER_NUM];

static DEFINE_MUTEX(g_bond_mutex);
static struct hinic5_bond_mngr bond_mngr = {
	.cnt = 0,
	.rtnl_sock = NULL,
	.bond_dev = NULL,
};

struct srcu_struct bdev_srcu; /* cfm bond global SRCU lock */

#define BDEV_IS_VALID(id) (bond_mngr.bond_dev && bond_mngr.bond_dev[(id)])

struct socket *hinic5_get_bond_mngr_sock(void)
{
	return bond_mngr.rtnl_sock;
}

struct socket **hinic5_get_bond_mngr_sock_addr(void)
{
	return &bond_mngr.rtnl_sock;
}

bool bond_call_srv_attach_func(enum hinic5_bond_user user, struct bonding *bond)
{
	bool need_attach = false;

	mutex_lock(&g_bond_attach_func_mutex);
	if (g_bond_attach_func[user])
		need_attach = g_bond_attach_func[user](bond);
	mutex_unlock(&g_bond_attach_func_mutex);

	return need_attach;
}

static bool bond_dev_is_activated(struct hinic5_bond_dev *bdev)
{
	bool is_activated = false;

	spin_lock(&bdev->lock);
	is_activated = (bdev->status == BOND_DEV_STATUS_ACTIVATED);
	spin_unlock(&bdev->lock);
	return is_activated;
}

static u32 bond_gen_uplink_id(struct hinic5_bond_dev *bdev)
{
	struct hinic5_lld_dev *lld_dev = NULL;
	struct pci_dev *pdev = NULL;
	u32 domain, bus, dev, func;
	u32 uplink_id = 0;
	u8 i;

	spin_lock(&bdev->lock);
	for (i = 0; i < BOND_PORT_MAX_NUM; i++) {
		if (BITMAP_JUDGE(bdev->bond_attr.slaves, i) != 0) {
			if (bdev->tracker.ndev[i] == NULL) {
				continue;
			}
			lld_dev = hinic5_get_lld_dev_by_netdev(bdev->tracker.ndev[i]);
			if (lld_dev == NULL) {
				continue;
			}
			/* TODO: Waiting for SDK to provide interface */
			pdev = to_pci_dev(lld_dev->dev);
			domain = (u32)pci_domain_nr(pdev->bus);
			bus = pdev->bus->number;
			dev = PCI_SLOT(pdev->devfn);
			func = PCI_FUNC(pdev->devfn);
			uplink_id = PCI_DBDF(domain, bus, dev, func);
			break;
		}
	}
	spin_unlock(&bdev->lock);

	return uplink_id;
}

void bond_dev_free_chip_bond_id(struct hinic5_bond_dev *bdev)
{
	struct hinic5_bond_chip *node_tmp = NULL;
	struct hinic5_bond_chip *bond_chip = NULL;
	u32 chip_bid = HINIC5_BOND_START_ID;

	mutex_lock(&g_bond_mutex);
	list_for_each_entry(node_tmp, &bond_mngr.bond_chip_list, node) {
		if (strncmp(node_tmp->chip_name, bdev->chip_name, IFNAMSIZ) == 0) {
			bond_chip = node_tmp;
			break;
		}
	}

	if (bond_chip) {
		/* find chip_bond_id is exit */
		for (; chip_bid < HINIC5_MAX_BOND_ID_PER_CARD; chip_bid++) {
			if (bond_chip->chip_bond_id[chip_bid] == bdev->bond_attr.bond_id) {
				bond_chip->chip_bond_id[chip_bid] = HINIC5_INVALID_BOND_ID;
				bond_chip->bond_num--;
				bond_master_info(bdev->bond->dev,
						 "Bond chip %s bond id %u free success\n",
						 bdev->chip_name, chip_bid);
				break;
			}
		}

		if (bond_chip->bond_num == 0) {
			list_del(&bond_chip->node);
			kfree(bond_chip);
			bond_master_info(bdev->bond->dev, "Bond chip node %s free success\n",
					 bdev->chip_name);
		}
	}
	mutex_unlock(&g_bond_mutex);
}

static int bond_dev_alloc_chip_bond_id(struct hinic5_bond_dev *bdev, char *chip_name, const u32 chip_name_len)
{
	struct hinic5_bond_chip *node_tmp = NULL;
	struct hinic5_bond_chip *bond_chip = NULL;
	u32 chip_bid = HINIC5_BOND_START_ID;
	int err = 0;

	mutex_lock(&g_bond_mutex);
	/* Initialize bdev chip name */
	if (chip_name_len >= sizeof(bdev->chip_name)) {
		err = -EINVAL;
		goto exit;
	}
	memcpy(bdev->chip_name, chip_name, chip_name_len);
	bdev->chip_name[chip_name_len] = '\0';

	list_for_each_entry(node_tmp, &bond_mngr.bond_chip_list, node) {
		if (strncmp(node_tmp->chip_name, chip_name, chip_name_len) == 0) {
			bond_chip = node_tmp;
			break;
		}
	}

	if (bond_chip) {
		/* find chip_bond_id is exit */
		for (; chip_bid < HINIC5_MAX_BOND_ID_PER_CARD; chip_bid++) {
			if (bond_chip->chip_bond_id[chip_bid] == bdev->bond_attr.bond_id)
				goto exit;
		}

		/* find new chip_bond_id */
		for (chip_bid = HINIC5_BOND_START_ID; chip_bid < HINIC5_MAX_BOND_ID_PER_CARD; chip_bid++) {
			if (bond_chip->chip_bond_id[chip_bid] == HINIC5_INVALID_BOND_ID) {
				bdev->chip_bond_id = chip_bid;
				bond_chip->chip_bond_id[chip_bid] = (u8)bdev->bond_attr.bond_id;
				bond_chip->bond_num++;
				bond_master_info(bdev->bond->dev,
						 "Bond chip %s bond id %u alloc success\n",
						 bdev->chip_name, chip_bid);
				break;
			}
		}

		if (chip_bid >= HINIC5_MAX_BOND_ID_PER_CARD) {
			bond_master_err(bdev->bond->dev, "bond_dev_get_chip_bond_id: chip_bond_id is full\n");
			err = -EINVAL;
		}
	} else {
		bond_chip = kzalloc(sizeof(struct hinic5_bond_chip), GFP_KERNEL);
		if (!bond_chip) {
			bond_master_err(bdev->bond->dev, "Bond chip %s node alloc failed\n", chip_name);
			err = -ENOMEM;
			goto exit;
		}
		bond_master_info(bdev->bond->dev, "bond chip %s node alloc success\n", chip_name);

		bdev->chip_bond_id = chip_bid;
		memcpy(bond_chip->chip_name, chip_name, chip_name_len);
		bond_master_info(bdev->bond->dev, "Bond chip %s bond id %u alloc success\n", bdev->chip_name, chip_bid);
		bond_chip->chip_bond_id[chip_bid++] = (u8)bdev->bond_attr.bond_id;
		bond_chip->bond_num++;

		for (; chip_bid < HINIC5_MAX_BOND_ID_PER_CARD; chip_bid++) {
			bond_chip->chip_bond_id[chip_bid] = HINIC5_INVALID_BOND_ID;
		}

		list_add_tail(&bond_chip->node, &bond_mngr.bond_chip_list);
	}
exit:
	if (err != 0)
		memset(bdev->chip_name, 0, sizeof(bdev->chip_name)); /* Clear bdev chip name */
	mutex_unlock(&g_bond_mutex);
	return err;
}

/* get index of physical port and initialize the tracker of bdev */
u8 bond_dev_track_port(struct hinic5_bond_dev *bdev, struct net_device *ndev)
{
	struct hinic5_lld_dev *lld_dev = NULL;
	char chip_name[IFNAMSIZ] = {0};
	char ndev_name[IFNAMSIZ] = {0};
	bool is_replaced = false;
	u32 tracker_cnt = 0;
	u8 port_id = 0;
	int err = 0;

	lld_dev = hinic5_get_lld_dev_by_netdev(ndev);
	if (lld_dev == NULL || hinic5_func_type(lld_dev->hwdev) == TYPE_VF) {
		bond_slave_err(bdev->bond->dev, ndev, "invalid slave: %s\n", ndev->name);
		return PORT_INVALID_ID;
	}

	bond_slave_info(bdev->bond->dev, ndev, "track ndev name: %s\n", ndev->name);
	port_id = hinic5_physical_port_id(lld_dev->hwdev);

	err = hinic5_get_chip_name(lld_dev, chip_name, sizeof(chip_name));
	if (err != 0) {
		bond_slave_err(bdev->bond->dev, ndev, "Bond Slave get chip name err %d\n", err);
		return PORT_INVALID_ID;
	}

	spin_lock(&bdev->lock);
	/* check chip name consistency, must be same card */
	if (bdev->tracker.cnt > 0 && strcmp(bdev->chip_name, chip_name) != 0) {
		/* Only support bond for same card */
		spin_unlock(&bdev->lock);
		bond_slave_err(bdev->bond->dev, ndev,
			       "Bond track err, slave not for same card, bond dev chip_name %s, slave chip name %s\n",
			       bdev->chip_name, chip_name);
		return PORT_INVALID_ID;
	}
	tracker_cnt = bdev->tracker.cnt;
	spin_unlock(&bdev->lock);

	/* first slave device , save chip name into bdev */
	if (tracker_cnt == 0) {
		err = bond_dev_alloc_chip_bond_id(bdev, chip_name, IFNAMSIZ);
		if (err != 0) {
			bond_slave_err(bdev->bond->dev, ndev, "Alloc bond chip id err %d\n", err);
			return PORT_INVALID_ID;
		}
	}

	spin_lock(&bdev->lock);
	/* attach netdev to the port position associated with it */
	if (bdev->tracker.ndev[port_id]) {
		is_replaced = true;
		memcpy(ndev_name, bdev->tracker.ndev[port_id]->name,
		       sizeof(bdev->tracker.ndev[port_id]->name));
	} else {
		bdev->tracker.cnt++;
	}
	tracker_cnt = bdev->tracker.cnt;
	bdev->tracker.ndev[port_id] = ndev;
	bdev->tracker.netdev_state[port_id].link_up = 0;
	bdev->tracker.netdev_state[port_id].tx_enabled = 0;
	spin_unlock(&bdev->lock);
	if (is_replaced)
		bond_slave_warn(bdev->bond->dev, ndev, "Old ndev: %s is replaced\n", ndev_name);
	bond_slave_info(bdev->bond->dev, ndev, "TRACK cnt: %u, slave ndev name: %s\n",
			tracker_cnt, ndev->name);

	return port_id;
}

struct hinic5_bond_dev *bond_get_bdev(const struct bonding *bond)
{
	struct hinic5_bond_dev *bdev = NULL;
	int bid;

	mutex_lock(&g_bond_mutex);
	for (bid = HINIC5_BOND_START_ID; bid < HINIC5_MAX_BODN_ID_NUM; bid++) {
		bdev = bond_mngr.bond_dev[bid];
		if (bdev == NULL)
			continue;

		if (bond == bdev->bond) {
			mutex_unlock(&g_bond_mutex);
			return bdev;
		}
	}
	mutex_unlock(&g_bond_mutex);
	return NULL;
}

static int bond_get_service_en_bitmap(struct hinic5_bond_dev *bdev)
{
	int err;
	struct hinic5_board_info info = {0};
	struct hinic5_lld_dev *lld_dev = hinic5_get_lld_dev_by_chip_name(bdev->chip_name);

	if (!lld_dev) {
		bond_master_err(bdev->bond->dev, "no available hinic5 lld device, chip_name: %s\n",
				bdev->chip_name);
		return -ENXIO;
	}
	err = hinic5_get_board_info(lld_dev->hwdev, &info, HINIC5_CHANNEL_NIC);
	if (err != 0) {
		bond_master_err(bdev->bond->dev, "bond get board info failed\n");
		return err;
	}

	bond_master_info(bdev->bond->dev, "get service_en_bitmap success: %d", info.service_en_bitmap);
	bdev->service_en_bitmap = info.service_en_bitmap;

	return 0;
}

static int bond_send_mpu_cfm_msg(struct hinic5_bond_dev *bdev, struct hinic5_bond_cmd *cmd_info, u8 cmd_type)
{
	int err = 0;
	u16 msg_cmd_type = g_cfm_cmd_covert[cmd_type];
	u16 out_size = sizeof(cfm_bond_cmd_s);
	cfm_bond_cmd_s cfm_bond_cmd_info = {0};
	struct hinic5_lld_dev *lld_dev = hinic5_get_lld_dev_by_chip_name(bdev->chip_name);

	if (!lld_dev) {
		bond_master_err(bdev->bond->dev,
				"no available hinic5 lld device(cfm), chip_name: %s\n",
				bdev->chip_name);
		return -ENXIO;
	}

	memcpy(&cfm_bond_cmd_info, (const void *)cmd_info, sizeof(struct hinic5_bond_cmd));
	err = hinic5_msg_to_mgmt_sync(lld_dev->hwdev, HINIC5_MOD_CFM, msg_cmd_type,
				      &cfm_bond_cmd_info, sizeof(cfm_bond_cmd_s),
				      &cfm_bond_cmd_info, &out_size,
				      HINIC5_BOND_MSG_TIMEOUT_MS, HINIC5_CHANNEL_NIC);
	if (err != 0 || out_size == 0 || cfm_bond_cmd_info.comm_head.status != 0) {
		bond_master_err(bdev->bond->dev,
				"bond msg cmd type: %u failed, err: %d, " \
				"cfm bond sts: %u, out size: %u\n",
				msg_cmd_type, err, cfm_bond_cmd_info.comm_head.status, out_size);
		err = -EIO;
	}
	return err;
}

static int bond_send_mpu_ovs_msg(struct hinic5_bond_dev *bdev, struct hinic5_bond_cmd *cmd_info, u8 cmd_type)
{
	int err = 0;
	u16 msg_cmd_type = g_cmd_covert[cmd_type];
	u16 out_size = sizeof(struct hinic5_bond_cmd);
	struct hinic5_lld_dev *lld_dev = hinic5_get_lld_dev_by_chip_name(bdev->chip_name);

	if (!lld_dev) {
		bond_master_err(bdev->bond->dev,
				"no available hinic5 lld device(ovs), chip_name: %s\n",
				bdev->chip_name);
		return -ENXIO;
	}

	err = hinic5_msg_to_mgmt_sync(lld_dev->hwdev, HINIC5_MOD_OVS, msg_cmd_type, cmd_info,
				      sizeof(struct hinic5_bond_cmd), cmd_info, &out_size, 0,
				      HINIC5_CHANNEL_NIC);
	if (err != 0 || out_size == 0 || cmd_info->comm_head.status != 0) {
		bond_master_err(bdev->bond->dev,
				"bond msg cmd type: %u failed, err: %d, sts: %u, out size: %u\n",
				msg_cmd_type, err, cmd_info->comm_head.status, out_size);
		err = -EIO;
	}
	return err;
}

static int bond_send_mpu_msg(struct hinic5_bond_dev *bdev, struct hinic5_bond_cmd *cmd_info, u8 cmd_type)
{
	int err = 0;

	if (bdev->service_en_bitmap == 0) {
		err = bond_get_service_en_bitmap(bdev);
		if (err != 0)
			return err;
	}
	if (BITMAP_JUDGE(bdev->service_en_bitmap, SERVICE_BIT_CFM) != 0)
		return bond_send_mpu_cfm_msg(bdev, cmd_info, cmd_type);
	return bond_send_mpu_ovs_msg(bdev, cmd_info, cmd_type);
}

static int bond_send_upcmd(struct hinic5_bond_dev *bdev, struct bond_attr *attr, u8 cmd_type)
{
	struct hinic5_bond_cmd cmd_info = {{0}, 0};

	cmd_info.sub_cmd = 0;
	cmd_info.comm_head.status = 0;

	if (attr)
		memcpy((void *)&cmd_info.attr, attr, sizeof(*attr));
	else
		cmd_info.attr.slaves = bdev->bond_attr.slaves;

	/* cmd_info bond_id is chip bond id */
	cmd_info.attr.bond_id = (u16)bdev->chip_bond_id;

	if (cmd_type == BOND_CREATE_CMD) {
		strncpy((char *)cmd_info.attr.bond_name, bdev->name, sizeof(cmd_info.attr.bond_name));
		cmd_info.attr.bond_name[sizeof(cmd_info.attr.bond_name) - 1] = '\0';
	}

	return bond_send_mpu_msg(bdev, &cmd_info, cmd_type);
}

static int bond_upcmd_deactivate(struct hinic5_bond_dev *bdev)
{
	int err;
	u16 id_tmp;
	enum bond_dev_status status;

	spin_lock(&bdev->lock);
	status = bdev->status;
	spin_unlock(&bdev->lock);
	if (status == BOND_DEV_STATUS_IDLE)
		return 0;

	bond_master_info(bdev->bond->dev, "hinic5_bond: deactivate bond: %u\n", bdev->bond_attr.bond_id);

	err = bond_send_upcmd(bdev, NULL, BOND_DELETE_CMD);
	if (err == 0) {
		spin_lock(&bdev->lock);
		id_tmp = bdev->bond_attr.bond_id;
		memset(&bdev->bond_attr, 0, sizeof(bdev->bond_attr));
		bdev->status = BOND_DEV_STATUS_IDLE;
		bdev->bond_attr.bond_id = id_tmp;
		spin_unlock(&bdev->lock);
	}

	return err;
}

static void bond_update_slave_info(struct hinic5_bond_dev *bdev, struct bond_attr *attr)
{
	struct net_device *ndev = NULL;
	u8 port_id;

	/* if bond dev down(ifconfig down), slave dev is up, should not set active slaves */
	if (!netif_running(bdev->bond->dev))
		return;

	if (attr->bond_mode == BOND_MODE_ACTIVEBACKUP) {
		rcu_read_lock();
		ndev = bond_option_active_slave_get_rcu(bdev->bond);
		rcu_read_unlock();
	}

	for (port_id = 0; port_id < BOND_PORT_MAX_NUM; port_id++) {
		if (bdev->tracker.netdev_state[port_id].tx_enabled == 0)
			continue;

		if (attr->bond_mode == BOND_MODE_8023AD) {
			BITMAP_SET(attr->active_slaves, port_id);
			BITMAP_SET(attr->lacp_collect_slaves, port_id);
		} else if (attr->bond_mode == BOND_MODE_XOR) {
			BITMAP_SET(attr->active_slaves, port_id);
		} else if (ndev && (ndev == bdev->tracker.ndev[port_id])) {
			/* BOND_MODE_ACTIVEBACKUP */
			BITMAP_SET(attr->active_slaves, port_id);
		}
	}
}

void bond_print_bdev_attr(struct hinic5_bond_dev *bdev, struct bond_attr *attr)
{
	bond_master_info(bdev->bond->dev,
			 "mode: %u, up_delay: %u, down_delay: %u, hash: %u, lacp_collect_slaves: %u, tracker cnt: %u\n",
			 attr->bond_mode,
			 attr->up_delay,
			 attr->down_delay,
			 attr->xmit_hash_policy,
			 attr->lacp_collect_slaves,
			 bdev->tracker.cnt);
	bond_master_info(bdev->bond->dev, "slave ports bitmap: 0x%x\n", attr->slaves);
	bond_master_info(bdev->bond->dev, "active slave ports bitmap: 0x%x\n", attr->active_slaves);
	bond_master_info(bdev->bond->dev, "slave pf bitmap: 0x%x\n", attr->bond_pf_bitmap);
	bond_master_info(bdev->bond->dev, "user bitmap: 0x%x\n", attr->user_bitmap);
}

static int bond_upcmd_config(struct hinic5_bond_dev *bdev, struct bond_attr *attr)
{
	int err;

	bond_update_slave_info(bdev, attr);

	if (memcmp(&bdev->bond_attr, attr, sizeof(struct bond_attr)) == 0)
		return 0;

	bond_master_info(bdev->bond->dev, "Config bond id: %u\n", attr->bond_id);
	bond_print_bdev_attr(bdev, attr);

	err = bond_send_upcmd(bdev, attr, BOND_SET_CMD);
	if (err == 0)
		memcpy(&bdev->bond_attr, attr, sizeof(struct bond_attr));

	return err;
}

static int bond_upcmd_activate(struct hinic5_bond_dev *bdev, struct bond_attr *attr)
{
	int err;

	if (bond_dev_is_activated(bdev))
		return 0;

	bond_update_slave_info(bdev, attr);
	bond_master_info(bdev->bond->dev, "Active bond id: %u\n", bdev->bond_attr.bond_id);
	bond_print_bdev_attr(bdev, attr);

	err = bond_send_upcmd(bdev, attr, BOND_CREATE_CMD);
	if (err == 0) {
		spin_lock(&bdev->lock);
		bdev->status = BOND_DEV_STATUS_ACTIVATED;
		spin_unlock(&bdev->lock);
		err = bond_upcmd_config(bdev, attr); /* create first, then set, for compatibility with old firmware mpu processing flow */
	}

	return err;
}

static void bond_call_service_func(struct hinic5_bond_dev *bdev, struct bond_attr *attr,
	enum bond_service_proc_pos pos, int err)
{
	u32 user;

	mutex_lock(&g_bond_event_func_mutex);
	for (user = HINIC5_BOND_USER_OVS; user < HINIC5_BOND_USER_NUM; user++) {
		if (g_bond_event_func[user][pos])
			g_bond_event_func[user][pos](bdev->name, attr, err);
	}
	mutex_unlock(&g_bond_event_func_mutex);
}

static u32 bond_get_user_bitmap(struct hinic5_bond_dev *bdev)
{
	u32 user_bitmap = 0;
	u32 user;

	for (user = HINIC5_BOND_USER_OVS; user < HINIC5_BOND_USER_NUM; user++) {
		if (bdev->slot_used[user] == 1) {
			BITMAP_SET(user_bitmap, user);
		}
	}
	return user_bitmap;
}

static void bond_do_work(struct work_struct *work)
{
	bool is_bonded = 0;
	struct bond_attr attr;
	int is_in_kexec;
	int err = 0;
	struct delayed_work *delayed_work = to_delayed_work(work);
	struct hinic5_bond_dev *bdev = container_of(delayed_work, struct hinic5_bond_dev, bond_work);

	is_in_kexec = hinic5_vram_get_kexec_flag();
	if (is_in_kexec != 0) {
		bond_master_info(bdev->bond->dev, "Skip changing bond status during os replace\n");
		return;
	}

	spin_lock(&bdev->lock);
	is_bonded = bdev->tracker.is_bonded;
	attr = bdev->new_attr;
	spin_unlock(&bdev->lock);
	attr.user_bitmap = bond_get_user_bitmap(bdev);

	bond_master_info(bdev->bond->dev,
			 "bond_do_work is_bonded: %d, bond_dev_is_activated(bdev): %d\n",
			 is_bonded, bond_dev_is_activated(bdev));

	/* is_bonded indicates whether bond should be activated. */
	if (is_bonded && !bond_dev_is_activated(bdev)) {
		bond_call_service_func(bdev, &attr, BOND_BEFORE_ACTIVE, 0);
		err = bond_upcmd_activate(bdev, &attr);
		bond_call_service_func(bdev, &attr, BOND_AFTER_ACTIVE, err);
	} else if (is_bonded && bond_dev_is_activated(bdev)) {
		bond_call_service_func(bdev, &attr, BOND_BEFORE_MODIFY, 0);
		err = bond_upcmd_config(bdev, &attr);
		bond_call_service_func(bdev, &attr, BOND_AFTER_MODIFY, err);
	} else if (!is_bonded && bond_dev_is_activated(bdev)) {
		bond_call_service_func(bdev, &attr, BOND_BEFORE_DEACTIVE, 0);
		err = bond_upcmd_deactivate(bdev);
		bond_call_service_func(bdev, &attr, BOND_AFTER_DEACTIVE, err);
	}

	if (err != 0)
		bond_master_err(bdev->bond->dev, "hinic5_bond: Do bond failed, err: %d\n", err);
}

static void bond_put_knl_bonding(struct bonding *bond)
{
	dev_put(bond->dev);
}

static void bond_dev_deinit(struct hinic5_bond_dev *bdev)
{
	spin_lock(&bdev->lock);
	WRITE_ONCE(bdev->dead, true);
	spin_unlock(&bdev->lock);

	/* Block and wait for bond_work task to finish */
	cancel_delayed_work_sync(&bdev->bond_work);
	/* Block and wait for all srcu read operations to finish */
	synchronize_srcu(&bdev_srcu);
	if (bdev->wq) {
		destroy_workqueue(bdev->wq);
	}
	if (bdev->bond != NULL) {
		bond_put_knl_bonding(bdev->bond);
		bdev->bond = NULL;
	}
	kfree(bdev);
}

static struct hinic5_bond_dev *bond_dev_init(struct bonding *bond, const char *name)
{
	struct hinic5_bond_dev *bdev = NULL;

	bdev = kzalloc(sizeof(*bdev), GFP_KERNEL);
	if (bdev == NULL)
		return NULL;

	bdev->wq = create_singlethread_workqueue("hinic5_bond_wq");
	if (!bdev->wq) {
		pr_err("hinic5_bond: Failed to create workqueue\n");
		goto bdev_wq_err;
	}

	if (strlen(name) >= sizeof(bdev->name)) {
		pr_err("hinic5_bond: bond name too long: %s (max %zu)\n",
			name, sizeof(bdev->name) - 1);
		goto bdev_name_err;
	}
	strncpy(bdev->name, name, sizeof(bdev->name));

	INIT_DELAYED_WORK(&bdev->bond_work, bond_do_work);
	bdev->status = BOND_DEV_STATUS_IDLE;

	spin_lock_init(&bdev->lock);

	dev_hold(bond->dev);
	bdev->bond = bond;

	return bdev;

bdev_name_err:
	destroy_workqueue(bdev->wq);
bdev_wq_err:
	kfree(bdev);
	return NULL;
}

static struct bonding *bond_get_knl_bonding(const char *name)
{
	struct net_device *ndev_tmp = NULL;

	rtnl_lock();
	for_each_netdev(&init_net, ndev_tmp) {
		if (netif_is_bond_master(ndev_tmp) && (strcmp(ndev_tmp->name, name) == 0)) {
			dev_hold(ndev_tmp);
			rtnl_unlock();
			return netdev_priv(ndev_tmp);
		}
	}
	rtnl_unlock();
	return NULL;
}

static int bond_dev_release(struct hinic5_bond_dev *bdev)
{
	int err;
	u8 i;

	err = bond_upcmd_deactivate(bdev);
	if (err != 0) {
		mutex_unlock(&g_bond_mutex);
		bond_master_err(bdev->bond->dev, "Failed to deactivate dev\n");
		return err;
	}

	for (i = HINIC5_BOND_START_ID; i < HINIC5_MAX_BODN_ID_NUM; i++) {
		if (bond_mngr.bond_dev[i] == bdev) {
			bond_mngr.bond_dev[i] = NULL;
			bond_mngr.cnt--;
			bond_master_info(bdev->bond->dev, "Free bond, id: %u mngr_cnt:%u\n", i, bond_mngr.cnt);
			break;
		}
	}

	mutex_unlock(&g_bond_mutex);
	bond_dev_free_chip_bond_id(bdev);
	bond_dev_deinit(bdev);

	return err;
}

static void bond_dev_free(struct kref *ref)
{
	struct hinic5_bond_dev *bdev = NULL;

	bdev = container_of(ref, struct hinic5_bond_dev, ref);
	bond_dev_release(bdev);
}

static struct hinic5_bond_dev *bond_dev_alloc(const char *name, struct bonding *bond)
{
	struct hinic5_bond_dev *bdev = NULL;
	u16 i;

	bdev = bond_dev_init(bond, name);
	if (bdev == NULL) {
		return NULL;
	}

	for (i = HINIC5_BOND_START_ID; i < HINIC5_MAX_BODN_ID_NUM; i++) {
		if ((bond_mngr.bond_dev != NULL) && (bond_mngr.bond_dev[i] == NULL)) {
			bdev->bond_attr.bond_id = i;
			bond_mngr.bond_dev[i] = bdev;
			bond_mngr.cnt++;
			bond_master_info(bond->dev,
					 "Create bond dev: %s, bond id: %u, bond cnt: %u\n",
					 name, i, bond_mngr.cnt);
			break;
		}
	}

	if (i >= HINIC5_MAX_BODN_ID_NUM) {
		bond_dev_deinit(bdev);
		bdev = NULL;
		pr_err("Bond dev: %s: Failed to get free bond id\n", name);
	}

	return bdev;
}

static void bond_init_all_slave(struct hinic5_bond_dev *bdev, struct bonding *bond)
{
	int i = 0, cnt = 0;
	struct slave *slave = NULL;
	struct list_head *iter = NULL;
	struct net_device *slave_ndev[BOND_PORT_MAX_NUM];

	rcu_read_lock();
	bond_for_each_slave_rcu(bond, slave, iter) {
		if (cnt >= BOND_PORT_MAX_NUM)
			break;
		slave_ndev[cnt] = slave->dev;
		dev_hold(slave_ndev[cnt++]);
		(void)iter;
	}
	rcu_read_unlock();

	/* TODO: Check if this flow is redundant, to be confirmed later */
	for (i = 0; i < cnt; ++i) {
		if (bond_dev_track_port(bdev, slave_ndev[i]) == PORT_INVALID_ID)
			continue;
	}
	for (i = 0; i < cnt; ++i)
		bond_handle_rtnl_event(slave_ndev[i]);
	bond_handle_rtnl_event(bond->dev);

	while (cnt != 0)
		dev_put(slave_ndev[--cnt]);
}

static struct hinic5_bond_dev *bond_dev_by_name(const char *name)
{
	struct hinic5_bond_dev *bdev = NULL;
	int i;

	for (i = HINIC5_BOND_START_ID; i < HINIC5_MAX_BODN_ID_NUM; i++) {
		if (BDEV_IS_VALID(i) && (strcmp(bond_mngr.bond_dev[i]->name, name) == 0)) {
			bdev = bond_mngr.bond_dev[i];
			break;
		}
	}

	return bdev;
}

static void bond_dev_user_attach(struct hinic5_bond_dev *bdev, enum hinic5_bond_user user)
{
	u32 user_bitmap;
	if (user < 0 || user >= HINIC5_BOND_USER_NUM || bdev->slot_used[user] != 0) {
		return;
	}

	bdev->slot_used[user] = 1;
	if (kref_get_unless_zero(&bdev->ref) == 0) {
		kref_init(&bdev->ref);
	} else {
		user_bitmap = bond_get_user_bitmap(bdev);
		bond_master_info(bdev->bond->dev, "Bond user %u attach bond %s, user_bitmap %#x\n",
				 user, bdev->name, user_bitmap);
		queue_delayed_work(bdev->wq, &bdev->bond_work, 0);
	}
}

static void bond_dev_user_detach(struct hinic5_bond_dev *bdev,
				 enum hinic5_bond_user user, bool *freed)
{
	u32 user_bitmap;
	if (user < 0 || user >= HINIC5_BOND_USER_NUM) {
		return;
	}

	if (bdev->slot_used[user] != 0) {
		bdev->slot_used[user] = 0;
		if (kref_read(&bdev->ref) == 1)
			*freed = true;
		if (kref_put(&bdev->ref, bond_dev_free) == 0) {
			user_bitmap = bond_get_user_bitmap(bdev);
			bond_master_info(bdev->bond->dev, "Bond: user %u detach bond %s, " \
					 "user_bitmap %#x\n", user, bdev->name, user_bitmap);
			queue_delayed_work(bdev->wq, &bdev->bond_work, 0);
		}
	}
}

/* Bind bond when bond event is reported */
int hinic5_bond_event_attach(struct bonding *bond, enum hinic5_bond_user user)
{
	struct hinic5_bond_dev *bdev = NULL;

	if (bond->params.mode != BOND_MODE_8023AD &&
		bond->params.mode != BOND_MODE_XOR &&
		bond->params.mode != BOND_MODE_ACTIVEBACKUP) {
		bond_master_err(bond->dev, "bond mode:%d is not supported\n", bond->params.mode);
		return -EINVAL;
	}

	mutex_lock(&g_bond_mutex);
	bdev = bond_dev_by_name(bond->dev->name);
	if (bdev == NULL) {
		bdev = bond_dev_alloc(bond->dev->name, bond);
		if (bdev == NULL) {
			mutex_unlock(&g_bond_mutex);
			return -ENODEV;
		}
	} else {
		bond_master_info(bdev->bond->dev,
				 "Bond event attach %s already exist\n", bond->dev->name);
	}

	bond_dev_user_attach(bdev, user);
	mutex_unlock(&g_bond_mutex);

	return 0;
}

bool hinic5_bond_slave_is_match(struct bonding *bond)
{
	struct hinic5_lld_dev *lld_dev = NULL;
	struct list_head *iter = NULL;
	struct slave *slave = NULL;
	char chip_name[IFNAMSIZ] = {0};
	char tmp_name[IFNAMSIZ] = {0};
	int err = 0;

	if (!bond_has_slaves(bond)) {
		bond_master_info(bond->dev, "Have no slaves");
		return true;
	}

	rcu_read_lock();
	bond_for_each_slave_rcu(bond, slave, iter) {
		lld_dev = hinic5_get_lld_dev_by_netdev(slave->dev);
		if (lld_dev == NULL) {
			bond_slave_warn(bond->dev, slave->dev, "Bond Slave device mismatch, is not hinic5 netdev\n");
			goto out;
		}

		/* If the function in bond group contains vf, print warning */
		if (hinic5_func_type(lld_dev->hwdev) == TYPE_VF) {
			bond_slave_warn(bond->dev, slave->dev, "Bond Slave device is VF\n");
			continue;;
		}

		err = hinic5_get_chip_name(lld_dev, tmp_name, sizeof(chip_name));
		if (err != 0) {
			bond_slave_err(bond->dev, slave->dev,
					"Bond Slave get chip name err %d\n", err);
			goto out;
		}

		if (strlen(chip_name) == 0) {
			memcpy(chip_name, tmp_name, sizeof(tmp_name));
			continue;
		}

		/* Only support bond for same card */
		if (strcmp(tmp_name, chip_name) != 0) {
			bond_slave_err(bond->dev, slave->dev,
				       "Bond Slave not match err, bond dev chip_name %s, " \
				       "slave chip name %s\n",
					chip_name, tmp_name);
			goto out;
		}
	}
	rcu_read_unlock();
	return true;

out:
	rcu_read_unlock();
	return false;
}

int hinic5_bond_get_id_by_name(u8 *bond_name, u16 *bond_id)
{
	u16 i;

	if ((bond_name == NULL) || (bond_id == NULL)) {
		pr_err("hinic5_bond: invalid input param\n");
		return -EINVAL;
	}

	for (i = HINIC5_BOND_START_ID; i < HINIC5_MAX_BODN_ID_NUM; i++) {
		if (!BDEV_IS_VALID(i)) {
			continue;
		}

		if (strcmp(bond_name, bond_mngr.bond_dev[i]->name) == 0) {
			*bond_id = bond_mngr.bond_dev[i]->bond_attr.bond_id;
			return 0;
		}
	}

	return -EINVAL;
}

int hinic5_bond_attach(const char *name, enum hinic5_bond_user user, u16 *bond_id)
{
	struct hinic5_bond_dev *bdev = NULL;
	struct bonding *bond = NULL;
	bool is_new_dev = false;

	if (user >= HINIC5_BOND_USER_NUM)
		return -EINVAL;

	if (!name || !bond_id)
		return -EINVAL;

	bond = bond_get_knl_bonding(name);
	if (bond == NULL) {
		pr_warn("hinic5_bond: Kernel bond %s not exist.\n", name);
		return -ENODEV;
	}

	if (bond->params.mode != BOND_MODE_8023AD &&
		bond->params.mode != BOND_MODE_XOR &&
		bond->params.mode != BOND_MODE_ACTIVEBACKUP) {
		bond_master_warn(bond->dev, "bond mode:%d is not supported\n", bond->params.mode);
	}

	/* Need to return bond id, so only print warning log */
	if (!hinic5_bond_slave_is_match(bond)) {
		bond_master_warn(bond->dev, "Bond attach slaves invalid or not exist\n");
	}

	mutex_lock(&g_bond_mutex);
	bdev = bond_dev_by_name(name);
	if (bdev == NULL) {
		/* if bond_dev_alloc return success, will increment the bond netdev reference count. */
		bdev = bond_dev_alloc(name, bond);
		if (bdev == NULL) {
			mutex_unlock(&g_bond_mutex);
			bond_put_knl_bonding(bond);
			return -ENODEV;
		}
		is_new_dev = true;
	} else {
		bond_master_info(bdev->bond->dev, "Attach %s already exist\n", name);
	}

	bond_dev_user_attach(bdev, user);
	mutex_unlock(&g_bond_mutex);

	if (is_new_dev) {
		bond_init_all_slave(bdev, bond);
		flush_delayed_work(&bdev->bond_work);
	}

	bond_put_knl_bonding(bond);

	*bond_id = bdev->bond_attr.bond_id;
	return 0;
}
EXPORT_SYMBOL(hinic5_bond_attach);

int hinic5_bond_detach(u16 bond_id, enum hinic5_bond_user user)
{
	int err = 0;
	bool lock_freed = false;
	if (user >= HINIC5_BOND_USER_NUM) {
		pr_err("Bond attach user num error: %u\n", user);
		return -EINVAL;
	}

	if (!HINIC5_BOND_ID_IS_VALID(bond_id)) {
		pr_warn("hinic5_bond: user:%u Invalid bond id:%u to delete\n", user, bond_id);
		return -EINVAL;
	}

	mutex_lock(&g_bond_mutex);
	if (!BDEV_IS_VALID(bond_id))
		err = -ENODEV;
	else
		bond_dev_user_detach(bond_mngr.bond_dev[bond_id], user, &lock_freed);

	if (!lock_freed)
		mutex_unlock(&g_bond_mutex);
	return err;
}
EXPORT_SYMBOL(hinic5_bond_detach);

void hinic5_bond_clean_user(enum hinic5_bond_user user)
{
	int i = 0;
	bool lock_freed = false;

	if (user >= HINIC5_BOND_USER_NUM) {
		pr_err("Bond clean user num error: %u\n", user);
		return;
	}

	mutex_lock(&g_bond_mutex);
	for (i = HINIC5_BOND_START_ID; i < HINIC5_MAX_BODN_ID_NUM; i++) {
		if (BDEV_IS_VALID(i)) {
			bond_dev_user_detach(bond_mngr.bond_dev[i], user, &lock_freed);
			if (lock_freed) {
				mutex_lock(&g_bond_mutex);
				lock_freed = false;
			}
		}
	}
	if (!lock_freed)
		mutex_unlock(&g_bond_mutex);
}
EXPORT_SYMBOL(hinic5_bond_clean_user);

int hinic5_bond_get_uplink_id(u16 bond_id, u32 *uplink_id)
{
	if (!HINIC5_BOND_ID_IS_VALID(bond_id) || !uplink_id) {
		pr_warn("hinic5_bond: Invalid args, bond id: %u, uplink: %d\n",
			bond_id, !!uplink_id);
		return -EINVAL;
	}

	mutex_lock(&g_bond_mutex);
	if (BDEV_IS_VALID(bond_id))
		*uplink_id = bond_gen_uplink_id(bond_mngr.bond_dev[bond_id]);
	mutex_unlock(&g_bond_mutex);

	return 0;
}
EXPORT_SYMBOL(hinic5_bond_get_uplink_id);

int hinic5_bond_register_service_func(enum hinic5_bond_user user, struct bond_srv_func *func)
{
	if (user >= HINIC5_BOND_USER_NUM || func == NULL)
		return -EINVAL;

	mutex_lock(&g_bond_event_func_mutex);
	g_bond_event_func[user][BOND_BEFORE_ACTIVE] = func->before_active;
	g_bond_event_func[user][BOND_AFTER_ACTIVE] = func->after_active;
	g_bond_event_func[user][BOND_BEFORE_MODIFY] = func->before_modify;
	g_bond_event_func[user][BOND_AFTER_MODIFY] = func->after_modify;
	g_bond_event_func[user][BOND_BEFORE_DEACTIVE] = func->before_deactive;
	g_bond_event_func[user][BOND_AFTER_DEACTIVE] = func->after_deactive;
	mutex_unlock(&g_bond_event_func_mutex);

	mutex_lock(&g_bond_attach_func_mutex);
	g_bond_attach_func[user] = func->can_attach;
	mutex_unlock(&g_bond_attach_func_mutex);

	return 0;
}
EXPORT_SYMBOL(hinic5_bond_register_service_func);

int hinic5_bond_unregister_service_func(enum hinic5_bond_user user)
{
	if (user >= HINIC5_BOND_USER_NUM) {
		return -EINVAL;
	}

	mutex_lock(&g_bond_event_func_mutex);
	g_bond_event_func[user][BOND_BEFORE_ACTIVE] = NULL;
	g_bond_event_func[user][BOND_AFTER_ACTIVE] = NULL;
	g_bond_event_func[user][BOND_BEFORE_MODIFY] = NULL;
	g_bond_event_func[user][BOND_AFTER_MODIFY] = NULL;
	g_bond_event_func[user][BOND_BEFORE_DEACTIVE] = NULL;
	g_bond_event_func[user][BOND_AFTER_DEACTIVE] = NULL;
	mutex_unlock(&g_bond_event_func_mutex);

	mutex_lock(&g_bond_attach_func_mutex);
	g_bond_attach_func[user] = NULL;
	mutex_unlock(&g_bond_attach_func_mutex);

	return 0;
}
EXPORT_SYMBOL(hinic5_bond_unregister_service_func);

int hinic5_bond_get_slaves(u16 bond_id, struct hinic5_bond_info_s *info)
{
	struct bond_tracker *tracker = NULL;
	int size;
	int i;

	if (!info || !HINIC5_BOND_ID_IS_VALID(bond_id)) {
		pr_warn("hinic5_bond: Invalid args, info: %d, bond id: %u\n",
			!!info, bond_id);
		return -EINVAL;
	}

	size = ARRAY_LEN(info->slaves_name);
	if (size < BOND_PORT_MAX_NUM) {
		pr_warn("hinic5_bond: Invalid args, size: %u\n",
			size);
		return -EINVAL;
	}

	mutex_lock(&g_bond_mutex);
	if (!BDEV_IS_VALID(bond_id)) {
		mutex_unlock(&g_bond_mutex);
		return 0;
	}
	info->slaves = bond_mngr.bond_dev[bond_id]->bond_attr.slaves;
	tracker = &bond_mngr.bond_dev[bond_id]->tracker;
	info->cnt = 0;
	for (i = 0; i < BOND_PORT_MAX_NUM; i++) {
		if ((BITMAP_JUDGE(info->slaves, i) != 0) && tracker->ndev[i]) {
			if (strlen(tracker->ndev[i]->name) >= sizeof(info->slaves_name[0])) {
				bond_master_err(bond_mngr.bond_dev[bond_id]->bond->dev,
						"hinic5_bond: port name too long: %s (max %zu)\n",
						tracker->ndev[i]->name, sizeof(info->slaves_name[0]) - 1);
				mutex_unlock(&g_bond_mutex);
				return -EINVAL;
			}
			strncpy(info->slaves_name[info->cnt], tracker->ndev[i]->name, sizeof(info->slaves_name[0]));
			info->cnt++;
		}
	}
	mutex_unlock(&g_bond_mutex);
	return 0;
}
EXPORT_SYMBOL(hinic5_bond_get_slaves);

struct net_device *hinic5_bond_get_netdev_by_portid(const char *bond_name, u8 port_id)
{
	struct hinic5_bond_dev *bdev = NULL;

	if (!bond_name || port_id >= BOND_PORT_MAX_NUM) {
		return NULL;
	}

	mutex_lock(&g_bond_mutex);
	bdev = bond_dev_by_name(bond_name);
	if (bdev == NULL) {
		mutex_unlock(&g_bond_mutex);
		return NULL;
	}
	mutex_unlock(&g_bond_mutex);
	return bdev->tracker.ndev[port_id];
}
EXPORT_SYMBOL(hinic5_bond_get_netdev_by_portid);

int hinic5_get_bond_tracker_by_name(const char *name, struct bond_tracker *tracker)
{
	struct hinic5_bond_dev *bdev = NULL;
	int i;

	if (!name || !tracker)
		return -EINVAL;

	mutex_lock(&g_bond_mutex);
	for (i = HINIC5_BOND_START_ID; i < HINIC5_MAX_BODN_ID_NUM; i++) {
		if (BDEV_IS_VALID(i) && (strcmp(bond_mngr.bond_dev[i]->name, name) == 0)) {
			bdev = bond_mngr.bond_dev[i];
			spin_lock(&bdev->lock);
			*tracker = bdev->tracker;
			spin_unlock(&bdev->lock);
			mutex_unlock(&g_bond_mutex);
			return 0;
		}
	}
	mutex_unlock(&g_bond_mutex);
	return -ENODEV;
}
EXPORT_SYMBOL(hinic5_get_bond_tracker_by_name);

int hinic5_bond_init(void)
{
	int ret = init_srcu_struct(&bdev_srcu);
	if (ret != 0) {
		pr_err("Failed to initialize bdev_srcu\n");
		return -ENOMEM;
	}

	bond_mngr.bond_dev = kzalloc(sizeof(struct hinic5_bond_dev *) * HINIC5_MAX_BODN_ID_NUM, GFP_KERNEL);
	if (bond_mngr.bond_dev == NULL) {
		pr_err("Bond dev kzalloc failed\n");
		return -ENOMEM;
	}
	INIT_LIST_HEAD(&bond_mngr.bond_chip_list);

	ret = bond_enable_netdev_event();
	if (ret != 0) {
		pr_err("Bond enable netdev event err: %d\n", ret);
		goto bond_dev_err;
	}

	return 0;

bond_dev_err:
	kfree(bond_mngr.bond_dev);
	bond_mngr.bond_dev = NULL;

	return ret;
}

void hinic5_bond_deinit(void)
{
	bond_disable_netdev_event();
	if (bond_mngr.bond_dev) {
		kfree(bond_mngr.bond_dev);
		bond_mngr.bond_dev = NULL;
	}
	cleanup_srcu_struct(&bdev_srcu);
}