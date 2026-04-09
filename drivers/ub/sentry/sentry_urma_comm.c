// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
 * Description: urma communication module
 * Author: sxt1001
 * Create: 2025-03-18
 */

#include <linux/in.h>
#include <linux/in6.h>
#include <linux/inet.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/kfifo.h>
#include <linux/delay.h>
#include <linux/acpi.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/kthread.h>
#include <linux/inet.h>
#include <linux/mutex.h>
#include <ub/urma/ubcore_api.h>
#include <ub/urma/ubcore_uapi.h>

#include "smh_common_type.h"

static int heartbeat_thread(void *arg);
static int rebuild_tjetty(int idx, int die_index);
static int sentry_post_jetty_send_wr(const struct sentry_binary_msg *buf,
		int tjetty_idx, int die_index);
static int sentry_poll_jfc(struct ubcore_jfc *jfc, int cr_cnt, struct ubcore_cr *cr, int die_index);

#define PROC_DEVICE_PATH		"sentry_urma_comm"
#define PROC_DEVICE_NAME		"client_info"
#define PROC_HEARTBEAT_SWITCH		"heartbeat"
#define ENABLE_VALUE_MAX_LEN		4 /* 'off' + '\n' */
#define MAX_JFC_DEPTH			96
#define MAX_JFR_DEPTH			96
#define MAX_JFS_DEPTH			96
#define MAX_SGE				1
#define MIN_RNR_TIMER			17 /* timeout time is 2^17*4.096usec≈536ms */
#define SGE_MAX_LEN			4096
#define DEFAULT_INVALID_JETTY_ID	(-1)
#define MIN_JETTY_ID			3
#define MAX_JETTY_ID			1023
#define JETTY_ID_MAX_LEN		6
#define UVS_IPV4_MAP_IPV6_PREFIX	0x0000ffff
#define URMA_CNT_MAX_NUM		(1U << 20)
#define HB_WAIT_ACK_SLEEP_MS		3000
#define HEARTBEAT_INTERVAL_MS		60000  /* 60s */
#define URMA_LOCK			1
#define URMA_UNLOCK			0
#define EID_PART_NUM			8
#define CLIENT_INFO_MAX_LEN		(((EID_MAX_LEN + 1) * MAX_NODE_NUM - 1) * 2 + 1 + 1 + \
					 JETTY_ID_MAX_LEN + 1)
/* The maximum length of the server_eid content in client info */
#define SERVER_EID_PART_MAX_LEN		(((EID_MAX_LEN + 1) * MAX_NODE_NUM - 1) * 2 + 1 + 1)
#define SINGLE_SERVER_PART_LEN		((EID_MAX_LEN + 1) * MAX_NODE_NUM - 1 + 1)

/*
 * 32 * （EID_MAX_LEN + 1） + 32 (31 * ";" + 1 * " ") + jetty_id + '\n' + '\0' +
 * "server_id:, client_jetty_id:"
 */
#define CLIENT_INFO_BUF_MAX_LEN ((MAX_NODE_NUM + 1) * (EID_MAX_LEN + 1) + JETTY_ID_MAX_LEN + 35)

struct ubcore_dev_list {
	struct ubcore_device *dev;
	struct list_head list;
};

LIST_HEAD(ub_dev_list_head);

static struct ubcore_jfc_cfg default_jfc_cfg = {
	.depth = MAX_JFC_DEPTH,
	.flag.bs.lock_free = false,
	.flag.bs.jfc_inline = false,
	.ceqn = 0,
};

static struct ubcore_jfr_cfg default_jfr_cfg = {
	.depth = MAX_JFR_DEPTH,
	.flag.bs.token_policy = UBCORE_TOKEN_NONE,
	.flag.bs.lock_free = false,
	.flag.bs.tag_matching = false,
	.trans_mode = UBCORE_TP_RM,
	.max_sge = MAX_SGE,
	.min_rnr_timer = MIN_RNR_TIMER,
};

#undef pr_fmt
#define pr_fmt(fmt) "[sentry][urma]: " fmt

struct sentry_ubcore_resource {
	bool is_created;

	/* dev resource */
	struct ubcore_device *sentry_ubcore_dev;
	struct ubcore_tjetty *tjetty[MAX_NODE_NUM];
	struct ubcore_jfs_wr jfs_wr[MAX_NODE_NUM];
	struct ubcore_jfr_wr jfr_wr[MAX_NODE_NUM];
	struct ubcore_sge s_sge[MAX_NODE_NUM];
	struct ubcore_sge r_sge[MAX_NODE_NUM];
	struct ubcore_jetty *jetty;
	struct ubcore_jfc *sender_jfc;
	struct ubcore_jfc *receiver_jfc;
	struct ubcore_jfr *jetty_jfr;
	struct ubcore_target_seg *s_seg;
	struct ubcore_target_seg *r_seg;
	void *s_seg_va;
	void *r_seg_va;

	/* eid info */
	union ubcore_eid local_eid;
	union ubcore_eid server_eid[MAX_NODE_NUM];
	char server_eid_array[MAX_NODE_NUM][EID_MAX_LEN];
	int server_eid_valid_num;
	uint32_t primary_eid_index;

	/* cnt for retry */
	atomic_t send_cnt[MAX_NODE_NUM];
	atomic_t remote_recv_cnt[MAX_NODE_NUM];
	atomic_t urma_hb_ack_list[MAX_NODE_NUM];  /* 0 = down, 1 = up */
};

struct sentry_urma_context {
	/* Heartbeat threads and state */
	struct task_struct *hb_thread;
	bool heartbeat_enable;

	uint32_t client_jetty_id;
	int local_eid_num_configured;
	int server_eid_num_configured;
	bool is_panic_mode;

	char *client_info_buf; /* for proc_read */
	bool is_valid_client_info;

	struct ubcore_cr *update_recv_cnt_cr;
	struct ubcore_cr *heartbeat_thread_cr;
	struct ubcore_cr *urma_recv_cr;
	struct ubcore_cr *urma_recv_sender_cr;

	bool is_register_ubcore_client;

	struct proc_dir_entry *proc_dir;
};

static DEFINE_MUTEX(sentry_urma_mutex);
static struct sentry_ubcore_resource sentry_urma_dev[MAX_DIE_NUM];
static struct sentry_urma_context sentry_urma_ctx;

bool g_is_created_ubcore_resource;
EXPORT_SYMBOL(g_is_created_ubcore_resource);

/**
 * urma_mutex_lock_op - Lock or unlock the URMA mutex based on panic mode
 * @is_to_lock: URMA_LOCK to lock, URMA_UNLOCK to unlock
 *
 * This function handles mutex locking/unlocking only when not in panic mode
 * to avoid deadlocks during system panic.
 */
static void urma_mutex_lock_op(int is_to_lock)
{
	if (!sentry_urma_ctx.is_panic_mode) {
		if (is_to_lock)
			mutex_lock(&sentry_urma_mutex);
		else
			mutex_unlock(&sentry_urma_mutex);
	}
}

/**
 * swap_eid_byteorder - Swap byte order of EID
 * @dst: Destination EID buffer
 * @src: Source EID buffer
 *
 * This function swaps the byte order of EID from big-endian to little-endian.
 */
static inline void swap_eid_byteorder(uint8_t dst[UBCORE_EID_SIZE],
				      const uint8_t src[UBCORE_EID_SIZE])
{
	int i;

	for (i = 0; i < UBCORE_EID_SIZE; i++)
		dst[i] = src[UBCORE_EID_SIZE - 1 - i];
}

/**
 * compare_ubcore_eid - Compare two URMA EIDs with byte order handling
 * @src_eid: Source EID to compare
 * @dst_eid: Destination EID to compare against
 *
 * Return: 0 if EIDs match, -EINVAL if they don't match even after byte order swap
 *
 * This function compares two EIDs and handles potential byte order differences
 * by attempting a byte-swapped comparison if the initial comparison fails.
 */
static int compare_ubcore_eid(const union ubcore_eid src_eid,
			      const union ubcore_eid dst_eid)
{
	if (memcmp(&src_eid, &dst_eid, sizeof(union ubcore_eid)) == 0)
		return 0;

	/*
	 * The byte order of the saved data may differ;
	 * compare again after conversion.
	 */
	union ubcore_eid new_src_eid;

	swap_eid_byteorder(new_src_eid.raw, src_eid.raw);
	if (memcmp(&new_src_eid, &dst_eid, sizeof(union ubcore_eid)) == 0) {
		pr_info("change byte order to match success, src eid:%llx, %x, %x, new src eid: %llx, %x, %x\n",
			src_eid.in4.reserved, src_eid.in4.prefix, src_eid.in4.addr,
			new_src_eid.in4.reserved, new_src_eid.in4.prefix,
			new_src_eid.in4.addr);
		return 0;
	}
	return -EINVAL;
}


/**
 * unimport_tjetty - Unimport all target jetties for a specific die
 * @die_index: Index of the die to unimport jetties from
 *
 * Return: 0 on success, -EINVAL on invalid die_index
 *
 * This function unimports all target jetties associated with a specific die
 * index and cleans up the references.
 */
static int unimport_tjetty(int die_index)
{
        int i;

        if (die_index < 0 || die_index >= MAX_DIE_NUM) {
                pr_err("invalid die_index (%d), range is [0, %d]\n",
                       die_index, MAX_DIE_NUM - 1);
                return -EINVAL;
        }

        for (i = 0; i < MAX_NODE_NUM; i++) {
                if (sentry_urma_dev[die_index].tjetty[i]) {
                        ubcore_unimport_jetty(sentry_urma_dev[die_index].tjetty[i]);
                        sentry_urma_dev[die_index].tjetty[i] = NULL;
                }
        }

        return 0;
}


static void release_urma_dev_source(int die_index)
{

	if (!sentry_urma_dev[die_index].sentry_ubcore_dev) {
		pr_info("urma %d dev is not exist, ignore to release the urma source.\n", die_index);
		return;
	}

	unimport_tjetty(die_index);

	if (sentry_urma_dev[die_index].jetty) {
		ubcore_delete_jetty(sentry_urma_dev[die_index].jetty);
		sentry_urma_dev[die_index].jetty = NULL;
	}

	if (sentry_urma_dev[die_index].s_seg) {
		ubcore_unregister_seg(sentry_urma_dev[die_index].s_seg);
		sentry_urma_dev[die_index].s_seg = NULL;
		kfree(sentry_urma_dev[die_index].s_seg_va);
		sentry_urma_dev[die_index].s_seg_va = NULL;
	}

	if (sentry_urma_dev[die_index].r_seg) {
		ubcore_unregister_seg(sentry_urma_dev[die_index].r_seg);
		sentry_urma_dev[die_index].r_seg = NULL;
		kfree(sentry_urma_dev[die_index].r_seg_va);
		sentry_urma_dev[die_index].r_seg_va = NULL;
	}

	if (sentry_urma_dev[die_index].jetty_jfr) {
		ubcore_delete_jfr(sentry_urma_dev[die_index].jetty_jfr);
		sentry_urma_dev[die_index].jetty_jfr = NULL;
	}

	if (sentry_urma_dev[die_index].receiver_jfc) {
		ubcore_delete_jfc(sentry_urma_dev[die_index].receiver_jfc);
		sentry_urma_dev[die_index].receiver_jfc = NULL;
	}

	if (sentry_urma_dev[die_index].sender_jfc) {
		ubcore_delete_jfc(sentry_urma_dev[die_index].sender_jfc);
		sentry_urma_dev[die_index].sender_jfc = NULL;
	}

	sentry_urma_dev[die_index].sentry_ubcore_dev = NULL;
	sentry_urma_dev[die_index].is_created = false;

	sentry_urma_dev[die_index].server_eid_valid_num = 0;
	memset(&sentry_urma_dev[die_index].local_eid, 0, sizeof(sentry_urma_dev[die_index].local_eid));
	memset(sentry_urma_dev[die_index].server_eid, 0, sizeof(sentry_urma_dev[die_index].server_eid));
	memset(sentry_urma_dev[die_index].server_eid_array, 0, MAX_NODE_NUM * EID_MAX_LEN * sizeof(char));
}

/**
 * sentry_add_device - Add URMA device to the device list
 * @dev: URMA device to add
 *
 * Return: 0 on success, -ENOMEM on memory allocation failure
 *
 * This function allocates and initializes a device node and adds it to
 * the global URMA device list.
 */
static int sentry_add_device(struct ubcore_device *dev)
{
	struct ubcore_dev_list *dev_node;

	dev_node = kmalloc(sizeof(*dev_node), GFP_KERNEL);
	if (!dev_node) {
		pr_err("failed to allocate dev node\n");
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&dev_node->list);
	dev_node->dev = dev;
	list_add_tail(&dev_node->list, &ub_dev_list_head);

	return 0;
}

/**
 * sentry_remove_device - Remove URMA device from the device list
 * @dev: URMA device to remove
 * @d: Unused parameter
 *
 * This function searches for the specified device in the global list
 * and removes it, freeing the associated memory.
 */
static void sentry_remove_device(struct ubcore_device *dev, void *d __always_unused)
{
	struct ubcore_dev_list *dev_node;
	int die_index = 0;

	urma_mutex_lock_op(URMA_LOCK);
	list_for_each_entry(dev_node, &ub_dev_list_head, list) {
		if (dev_node->dev == dev) {
			for (die_index = 0; die_index < MAX_DIE_NUM; die_index++) {
				if (sentry_urma_dev[die_index].sentry_ubcore_dev == dev) {
					pr_info("release the urma %d dev before remove the urma device\n", die_index);
					release_urma_dev_source(die_index);
					break;
				}
			}
			list_del(&dev_node->list);
			kfree(dev_node);
			break;
		}
	}
	urma_mutex_lock_op(URMA_UNLOCK);
}

static struct ubcore_client sentry_ubcore_client = {
	.list_node = LIST_HEAD_INIT(sentry_ubcore_client.list_node),
	.client_name = "sentry_ubcore_client",
	.add = sentry_add_device,
	.remove = sentry_remove_device,
};

/**
 * free_global_char - Free all dynamically allocated global character buffers
 *
 * This function safely frees all global character buffers used in the module
 * and sets the pointers to NULL to prevent use-after-free.
 */
void free_global_char(void)
{
	kfree(sentry_urma_ctx.client_info_buf);
	sentry_urma_ctx.client_info_buf = NULL;

	kfree(sentry_urma_ctx.update_recv_cnt_cr);
	sentry_urma_ctx.update_recv_cnt_cr = NULL;

	kfree(sentry_urma_ctx.heartbeat_thread_cr);
	sentry_urma_ctx.heartbeat_thread_cr = NULL;

	kfree(sentry_urma_ctx.urma_recv_cr);
	sentry_urma_ctx.urma_recv_cr = NULL;

	kfree(sentry_urma_ctx.urma_recv_sender_cr);
	sentry_urma_ctx.urma_recv_sender_cr = NULL;
}


/**
 * init_global_char - Initialize global character buffers
 *
 * Return: 0 on success, -ENOMEM on allocation failure
 *
 * This function allocates and initializes all global character buffers
 * used for client information storage and communication.
 */
int init_global_char(void)
{
	sentry_urma_ctx.client_info_buf = kzalloc(CLIENT_INFO_BUF_MAX_LEN, GFP_KERNEL);
	if (!sentry_urma_ctx.client_info_buf) {
		pr_err("kzalloc client_info_buf failed\n");
		goto err_free;
	}

	sentry_urma_ctx.update_recv_cnt_cr = kzalloc(sizeof(struct ubcore_cr) * MAX_NODE_NUM, GFP_KERNEL);
	if (!sentry_urma_ctx.update_recv_cnt_cr) {
		pr_err("kzalloc update_recv_cnt_cr failed\n");
		goto err_free;
	}
	sentry_urma_ctx.heartbeat_thread_cr = kzalloc(sizeof(struct ubcore_cr) * MAX_NODE_NUM, GFP_KERNEL);
	if (!sentry_urma_ctx.heartbeat_thread_cr) {
		pr_err("kzalloc heartbeat_thread_cr failed\n");
		goto err_free;
	}
	sentry_urma_ctx.urma_recv_cr = kzalloc(sizeof(struct ubcore_cr) * MAX_NODE_NUM, GFP_KERNEL);
	if (!sentry_urma_ctx.urma_recv_cr) {
		pr_err("kzalloc urma_recv_cr failed\n");
		goto err_free;
	}
	sentry_urma_ctx.urma_recv_sender_cr = kzalloc(sizeof(struct ubcore_cr) * MAX_NODE_NUM, GFP_KERNEL);
	if (!sentry_urma_ctx.urma_recv_sender_cr) {
		pr_err("kzalloc urma_recv_sender_cr failed\n");
		goto err_free;
	}

	return 0;

err_free:
	free_global_char();
	return -ENOMEM;
}

/**
 * init_ubcore - Initialize URMA core functionality
 *
 * Return: 0 on success, appropriate error code on failure
 *
 * This function registers the URMA client and verifies that at least one
 * URMA device is available. It handles the initialization of URMA core
 * components.
 */
int init_ubcore(void)
{
	int ret;

	if (!list_empty(&ub_dev_list_head)) {
		pr_err("hw_clear is already setup\n");
		return -EEXIST;
	}

	ret = ubcore_register_client(&sentry_ubcore_client);
	if (ret) {
		pr_err("fail to register ubcore client\n");
		return -EFAULT;
	}

	sentry_urma_ctx.is_register_ubcore_client = true;
	pr_info("ubcore_register_client success\n");

	if (list_empty(&ub_dev_list_head)) {
		pr_err("fail to get ubcore device\n");
		ret = -ENODEV;
		goto init_ubcore_fail;
	}

	return 0;

init_ubcore_fail:
	ubcore_unregister_client(&sentry_ubcore_client);
	sentry_urma_ctx.is_register_ubcore_client = false;
	return ret;
}


/**
 * release_ubcore_resource - Release all URMA resources for all dies
 *
 * This function stops the heartbeat thread and releases all URMA resources
 * including jetties, segments, JFRs, and JFCs for all die indices.
 * It handles resource cleanup in the proper order to avoid dependency issues.
 */
static void release_ubcore_resource(void)
{
	int die_index;

	urma_mutex_lock_op(URMA_LOCK);

	if (sentry_urma_ctx.hb_thread) {
		kthread_stop(sentry_urma_ctx.hb_thread);
		sentry_urma_ctx.hb_thread = NULL;
		pr_info("urma_hb_all thread stopped\n");
	}

	g_is_created_ubcore_resource = false;

	/* Release resources for each die */
	for (die_index = 0; die_index < MAX_DIE_NUM; die_index++) {
		release_urma_dev_source(die_index);
	}

	urma_mutex_lock_op(URMA_UNLOCK);
}

/**
 * release_all_resource - Release all URMA resources and unregister client
 *
 * This function cleans up all allocated URMA resources including device
 * resources and unregisters the URMA client if it was registered.
 */
static void release_all_resource(void)
{
	release_ubcore_resource();

	if (sentry_urma_ctx.is_register_ubcore_client) {
		ubcore_unregister_client(&sentry_ubcore_client);
		sentry_urma_ctx.is_register_ubcore_client = false;
	}
}

/**
 * str_to_eid - Convert string representation to URMA EID
 * @eid_str: String representation of EID
 * @eid: Pointer to store converted EID
 *
 * Return: 0 on success, -EINVAL on invalid input
 *
 * This function converts a string representation of an EID to the binary
 * format used by URMA, supporting IPv6 notation.
 */
int str_to_eid(const char *eid_str, union ubcore_eid *eid)
{
	if (!eid_str || !eid || strlen(eid_str) != EID_MAX_LEN - 1) {
		pr_err("eid str %s len is invalid, failed to transfer\n", eid_str);
		return -EINVAL;
	}

	if (in6_pton(eid_str, EID_MAX_LEN, (u8 *)eid, '\0', NULL) > 0) {
		pr_info("parse eid success, config eid: %llx, %x, %x\n",
			eid->in4.reserved, eid->in4.prefix, eid->in4.addr);
		return 0;
	}

	pr_err("parse eid string [%s] failed\n", eid_str);
	return -EINVAL;
}
EXPORT_SYMBOL(str_to_eid);

/**
 * ubcore_eid_to_str_full - Convert URMA EID to string representation
 * @eid: URMA EID
 * @dst_eid_str: Pointer to store converted EID
 *
 * Return: 0 on success, -EINVAL on invalid input
 *
 * This function converts the binary format used by URMA of an EID to
 * a string representation of an EID.
 */
int ubcore_eid_to_str_full(const union ubcore_eid *eid, char *dst_eid_str, int len)
{
	if (!eid || !dst_eid_str || len < EID_MAX_LEN) {
		pr_err("%s: invalid params or buffer too small\n", __func__);
		return -EINVAL;
	}

	int ret = snprintf(dst_eid_str, len,
			"%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
			(unsigned int)eid->raw[0] << 8 | eid->raw[1],
			(unsigned int)eid->raw[2] << 8 | eid->raw[3],
			(unsigned int)eid->raw[4] << 8 | eid->raw[5],
			(unsigned int)eid->raw[6] << 8 | eid->raw[7],
			(unsigned int)eid->raw[8] << 8 | eid->raw[9],
			(unsigned int)eid->raw[10] << 8 | eid->raw[11],
			(unsigned int)eid->raw[12] << 8 | eid->raw[13],
			(unsigned int)eid->raw[14] << 8 | eid->raw[15]);
	if (ret < 0 || ret >= len) {
		pr_err("%s:snprintf failed or buffer overflow\n", __func__);
		return -EINVAL;
	}

	pr_info("%s: Covert ubcore eid to full string: %s\n", __func__, dst_eid_str);
	return 0;
}
EXPORT_SYMBOL(ubcore_eid_to_str_full);

/**
 * set_urma_panic_mode - Set URMA panic mode status
 * @is_panic: true to in panic mode, false to otherwise
 *
 * This function sets the panic mode flag which affects mutex locking
 * behavior during system panic conditions.
 */
void set_urma_panic_mode(bool is_panic)
{
	sentry_urma_ctx.is_panic_mode = is_panic;
}
EXPORT_SYMBOL(set_urma_panic_mode);

/**
 * sentry_register_seg - Register a segment for URMA operations
 * @dev: URMA device to register segment with
 * @num_sge: Number of scatter-gather elements
 * @is_send: true for send segment, false for receive segment
 * @die_index: Index of the die for resource tracking
 *
 * Return: Pointer to registered segment on success, ERR_PTR on failure
 *
 * This function registers a memory segment with the URMA device for
 * send or receive operations.
 */
static struct ubcore_target_seg *sentry_register_seg(struct ubcore_device *dev,
						     uint32_t num_sge, bool is_send,
						     int die_index)
{
	union ubcore_reg_seg_flag flag = {0};
	uint64_t seg_len = SGE_MAX_LEN * num_sge;
	struct ubcore_seg_cfg cfg = {0};
	struct ubcore_target_seg *ret;
	void *seg_va;

	if (die_index < 0 || die_index >= MAX_DIE_NUM) {
		pr_err("invalid die_index (%d), range is [0, %d]\n",
		       die_index, MAX_DIE_NUM - 1);
		return ERR_PTR(-EINVAL);
	}

	seg_va = kzalloc(seg_len, GFP_KERNEL);
	if (!seg_va)
		return ERR_PTR(-ENOMEM);

	flag.bs.token_policy = UBCORE_TOKEN_NONE;
	flag.bs.cacheable = UBCORE_NON_CACHEABLE;
	flag.bs.access = UBCORE_ACCESS_LOCAL_ONLY;
	cfg.va = (uint64_t)seg_va;
	cfg.len = seg_len;
	cfg.flag = flag;

	ret = ubcore_register_seg(dev, &cfg, NULL);
	if (IS_ERR_OR_NULL(ret)) {
		pr_err("reg seg failed\n");
		goto free_seg;
	}

	if (is_send)
		sentry_urma_dev[die_index].s_seg_va = seg_va;
	else
		sentry_urma_dev[die_index].r_seg_va = seg_va;

	return ret;

free_seg:
	kfree(seg_va);
	return ret;
}

static int sentry_jetty_set_priority(struct ubcore_device *device,
		  struct ubcore_jetty_cfg *jetty_cfg)
{
	struct ubcore_device_attr attr = {0};
	int set_priority_ret = 0;
	int ret = 0;
	int i;

	ret = ubcore_query_device_attr(device, &attr);
	if (ret == 0) {
		for (i = 0; i < UBCORE_MAX_PRIORITY_CNT; ++i) {
			if (attr.dev_cap.priority_info[i].tp_type.bs.ctp == 1) {
				jetty_cfg->priority = i;
				pr_info(
					"create jetty set priority : %d, tp_type : ctp\n", i);
				set_priority_ret = 1;
				break;
			}
		}
		if (set_priority_ret == 0) {
			pr_err("set priority default value : 0\n");
			return -EINVAL;
		}
	} else {
		pr_err("Failed to ubcore get dev_attr!\n");
		return -EINVAL;
	}
	return 0;
}

/**
 * sentry_create_jetty - Create a URMA jetty endpoint
 * @device: URMA device to create jetty on
 * @eid_index: eid index
 * @jfc_s: Send completion queue
 * @jfc_r: Receive completion queue
 * @jfr: Receive work queue
 * @jetty_id: Jetty identifier
 *
 * Return: Pointer to created jetty on success, NULL on failure
 *
 * This function creates a jetty endpoint with the specified configuration
 * for URMA communication.
 */
static struct ubcore_jetty *sentry_create_jetty(struct ubcore_device *device,
						uint32_t eid_index,
						struct ubcore_jfc *jfc_s,
						struct ubcore_jfc *jfc_r,
						struct ubcore_jfr *jfr,
						uint32_t jetty_id)
{
	int ret;

	struct ubcore_jetty_cfg jetty_cfg = {
		.id = jetty_id,
		.flag.bs.share_jfr = 1,
		.trans_mode = UBCORE_TP_RM,
		.eid_index = eid_index,
		.jfs_depth = MAX_JFS_DEPTH,
		.priority = 0, /* Highest priority */
		.max_send_sge = 1,
		.max_send_rsge = 1,
		.jfr_depth = MAX_JFR_DEPTH,
		.max_recv_sge = 1,
		.send_jfc = jfc_s,
		.recv_jfc = jfc_r,
		.jfr = jfr,
	};

	ret = sentry_jetty_set_priority(device, &jetty_cfg);
	if (ret)
		pr_info("set priority failed, use default value : 0\n");

	return ubcore_create_jetty(device, &jetty_cfg, NULL, NULL);
}

/**
 * sentry_post_recv - Post a receive work request to a jetty
 * @r_jetty: Receive jetty to post to
 * @recv_seg: Receive segment to use
 * @node_idx: Node index for scatter-gather element
 * @die_index: Die index for resource access
 *
 * Return: 0 on success, negative error code on failure
 *
 * This function posts a receive work request to the specified jetty
 * for asynchronous data reception.
 */
int sentry_post_recv(struct ubcore_jetty *r_jetty, struct ubcore_target_seg *recv_seg,
		     int node_idx, int die_index)
{
	uint64_t sge_addr;
	struct ubcore_jfr_wr *jfr_bad_wr = NULL;
	int ret;

	if (die_index < 0 || die_index >= MAX_DIE_NUM) {
		pr_err("invalid die_index (%d), range is [0, %d]\n",
		       die_index, MAX_DIE_NUM - 1);
		return -EINVAL;
	}

	if (!sentry_urma_dev[die_index].sentry_ubcore_dev) {
		pr_err("%s failed: urma %d dev is not exist\n", __func__, die_index);
		return -EINVAL;
	}

	sge_addr = (uint64_t)sentry_urma_dev[die_index].r_seg_va + SGE_MAX_LEN * node_idx;
	sentry_urma_dev[die_index].r_sge[node_idx].addr = sge_addr;
	sentry_urma_dev[die_index].r_sge[node_idx].len = SGE_MAX_LEN;
	sentry_urma_dev[die_index].r_sge[node_idx].tseg = recv_seg;
	sentry_urma_dev[die_index].jfr_wr[node_idx].src.sge =
		&sentry_urma_dev[die_index].r_sge[node_idx];
	sentry_urma_dev[die_index].jfr_wr[node_idx].src.num_sge = 1;
	sentry_urma_dev[die_index].jfr_wr[node_idx].user_ctx = sge_addr;

	ret = ubcore_post_jetty_recv_wr(r_jetty,
					&sentry_urma_dev[die_index].jfr_wr[node_idx],
					&jfr_bad_wr);
	if (ret != 0 && ret != -ENOMEM) {
		pr_err("sentry_post_recv: ubcore_post_jetty_recv_wr failed, ret %d\n", ret);
		return ret;
	}

	return 0;
}

/**
 * create_ubcore_resource - Create URMA core resources for a specific die
 * @die_index: Index of the die to create resources for
 *
 * Return: 0 on success, negative error code on failure
 *
 * This function creates all necessary URMA resources including JFCs, JFRs,
 * segments, and jetties for the specified die index.
 */
static int create_ubcore_resource(int die_index)
{
	int ret;

	if (die_index < 0 || die_index >= MAX_DIE_NUM) {
		pr_err("invalid die_index (%d), range is [0, %d]\n",
		       die_index, MAX_DIE_NUM - 1);
		return -EINVAL;
	}

	urma_mutex_lock_op(URMA_LOCK);

	if (!sentry_urma_dev[die_index].sentry_ubcore_dev) {
		urma_mutex_lock_op(URMA_UNLOCK);
		pr_err("Please set eid first\n");
		return -EINVAL;
	}

	/* Create sender JFC */
	sentry_urma_dev[die_index].sender_jfc =
		ubcore_create_jfc(sentry_urma_dev[die_index].sentry_ubcore_dev,
				  &default_jfc_cfg, NULL, NULL, NULL);
	if (IS_ERR_OR_NULL(sentry_urma_dev[die_index].sender_jfc)) {
		pr_err("ubcore_create_jfc err\n");
		sentry_urma_dev[die_index].sender_jfc = NULL;
		ret = -EFAULT;
		goto err_create_urma_resource;
	}

	ret = ubcore_rearm_jfc(sentry_urma_dev[die_index].sender_jfc, false);
	if (ret != 0) {
		pr_err("rearm jfc_r failed, ret %d\n", ret);
		goto err_create_urma_resource;
	}
	pr_info("ubcore_create_jfc success\n");

	/* Create receiver JFC */
	sentry_urma_dev[die_index].receiver_jfc =
		ubcore_create_jfc(sentry_urma_dev[die_index].sentry_ubcore_dev,
				  &default_jfc_cfg, NULL, NULL, NULL);
	if (IS_ERR_OR_NULL(sentry_urma_dev[die_index].receiver_jfc)) {
		pr_err("ubcore_create_jfc err\n");
		sentry_urma_dev[die_index].receiver_jfc = NULL;
		ret = -EFAULT;
		goto err_create_urma_resource;
	}

	ret = ubcore_rearm_jfc(sentry_urma_dev[die_index].receiver_jfc, false);
	if (ret != 0) {
		pr_err("rearm jfc_r failed, ret %d\n", ret);
		goto err_create_urma_resource;
	}
	pr_info("ubcore_create_jfc success\n");

	/* Create JFR */
	default_jfr_cfg.eid_index = sentry_urma_dev[die_index].primary_eid_index;
	default_jfr_cfg.jfc = sentry_urma_dev[die_index].receiver_jfc;
	sentry_urma_dev[die_index].jetty_jfr =
		ubcore_create_jfr(sentry_urma_dev[die_index].sentry_ubcore_dev,
				  &default_jfr_cfg, NULL, NULL);
	if (IS_ERR_OR_NULL(sentry_urma_dev[die_index].jetty_jfr)) {
		pr_err("ubcore_create_jfr err\n");
		sentry_urma_dev[die_index].jetty_jfr = NULL;
		ret = -EFAULT;
		goto err_create_urma_resource;
	}
	pr_info("ubcore_create_jfr success\n");

	/* Register send segment */
	sentry_urma_dev[die_index].s_seg =
		sentry_register_seg(sentry_urma_dev[die_index].sentry_ubcore_dev,
				    MAX_NODE_NUM, true, die_index);
	if (IS_ERR_OR_NULL(sentry_urma_dev[die_index].s_seg)) {
		pr_err("ubcore_register_s_seg err\n");
		sentry_urma_dev[die_index].s_seg = NULL;
		ret = -EFAULT;
		goto err_create_urma_resource;
	}

	/* Register receive segment */
	sentry_urma_dev[die_index].r_seg =
		sentry_register_seg(sentry_urma_dev[die_index].sentry_ubcore_dev,
				    MAX_NODE_NUM, false, die_index);
	if (IS_ERR_OR_NULL(sentry_urma_dev[die_index].r_seg)) {
		pr_err("ubcore_register_r_seg err\n");
		sentry_urma_dev[die_index].r_seg = NULL;
		ret = -EFAULT;
		goto err_create_urma_resource;
	}

	sentry_urma_dev[die_index].is_created = true;
	pr_info("ubcore_register_seg success\n");
	urma_mutex_lock_op(URMA_UNLOCK);

	return 0;

err_create_urma_resource:
	urma_mutex_lock_op(URMA_UNLOCK);
	release_ubcore_resource();
	return ret;
}

/**
 * create_tjetty - Create a target jetty for remote communication
 * @tjetty_cfg: Target jetty configuration
 * @eid_index: EID index for the target
 * @die_index: Die index for resource access
 *
 * Return: Pointer to created target jetty on success, NULL on failure
 *
 * This function creates a target jetty for communication with a remote
 * endpoint specified by the EID index.
 */
static struct ubcore_tjetty *create_tjetty(struct ubcore_tjetty_cfg *tjetty_cfg,
					   int eid_index, int die_index)
{
	int ret;

	if (!sentry_urma_dev[die_index].sentry_ubcore_dev) {
		pr_err("%s failed: urma %d dev is not exist\n", __func__, die_index);
		return NULL;
	}

	struct ubcore_get_tp_cfg tp_cfg = {
		.flag.bs.ctp = 1,
		.trans_mode = UBCORE_TP_RM,
		.local_eid = sentry_urma_dev[die_index].local_eid,
		.peer_eid = sentry_urma_dev[die_index].server_eid[eid_index],
	};
	uint32_t tp_cnt = 1;
	struct ubcore_tp_info tp_list = {};
	struct ubcore_active_tp_cfg active_tp_cfg = {};

	ret = ubcore_get_tp_list(sentry_urma_dev[die_index].sentry_ubcore_dev,
				 &tp_cfg, &tp_cnt, &tp_list, NULL);
	if (ret != 0) {
		pr_err("ubcore_get_tp_list failed, ret %d, server eid %s\n",
		       ret, sentry_urma_dev[die_index].server_eid_array[eid_index]);
		return NULL;
	}

	active_tp_cfg.tp_handle = tp_list.tp_handle;
	return ubcore_import_jetty_ex(sentry_urma_dev[die_index].sentry_ubcore_dev,
				      tjetty_cfg, &active_tp_cfg, NULL);
}

/**
 * import - Import and configure URMA jetties for all dies
 *
 * Return: 0 on success, -EFAULT on failure
 *
 * This function imports and configures URMA jetties for all configured dies,
 * creates local jetties, posts receive work requests, and starts the heartbeat
 * thread if enabled. It handles the complete initialization of URMA communication
 * endpoints.
 */
int import(void)
{
	struct ubcore_tjetty_cfg tjetty_cfg = {0};
	int ret = 0;
	int die_index;
	int tjetty_valid_num;

	if (sentry_urma_ctx.client_jetty_id == DEFAULT_INVALID_JETTY_ID) {
		pr_err("client_jetty_id not set, import failed\n");
		return -EFAULT;
	}

	urma_mutex_lock_op(URMA_LOCK);

	g_is_created_ubcore_resource = false;

	/* Stop existing heartbeat thread */
	if (sentry_urma_ctx.hb_thread) {
		kthread_stop(sentry_urma_ctx.hb_thread);
		sentry_urma_ctx.hb_thread = NULL;
		pr_info("urma_hb_all thread stopped\n");
	}

	/* Configure target jetty */
	tjetty_cfg.id.id = sentry_urma_ctx.client_jetty_id;
	tjetty_cfg.flag.bs.token_policy = UBCORE_TOKEN_NONE;
	tjetty_cfg.trans_mode = UBCORE_TP_RM;
	tjetty_cfg.type = UBCORE_JETTY;

	/* Process each die */
	for (die_index = 0; die_index < sentry_urma_ctx.server_eid_num_configured; die_index++) {
		int i;

		tjetty_valid_num = 0;

		if (!sentry_urma_dev[die_index].sentry_ubcore_dev) {
			pr_err("Please set eid first\n");
			goto print_import_result;
		}

		/* Clean existing jetties */
		unimport_tjetty(die_index);
		if (sentry_urma_dev[die_index].jetty) {
			ubcore_delete_jetty(sentry_urma_dev[die_index].jetty);
			sentry_urma_dev[die_index].jetty = NULL;
		}

		/* Create local jetty */
		sentry_urma_dev[die_index].jetty =
			sentry_create_jetty(sentry_urma_dev[die_index].sentry_ubcore_dev,
						sentry_urma_dev[die_index].primary_eid_index,
						sentry_urma_dev[die_index].sender_jfc,
						sentry_urma_dev[die_index].receiver_jfc,
						sentry_urma_dev[die_index].jetty_jfr,
						sentry_urma_ctx.client_jetty_id);
		if (IS_ERR_OR_NULL(sentry_urma_dev[die_index].jetty)) {
			sentry_urma_dev[die_index].jetty = NULL;
			pr_err("ubcore_create_jetty failed for device %s\n",
			       sentry_urma_dev[die_index].sentry_ubcore_dev->dev_name);
			goto print_import_result;
		}
		pr_info("ubcore_create_jetty success for device %s\n",
			sentry_urma_dev[die_index].sentry_ubcore_dev->dev_name);

		/* Post receive work requests */
		for (i = 0; i < MAX_NODE_NUM; i++) {
			ret = sentry_post_recv(sentry_urma_dev[die_index].jetty,
					       sentry_urma_dev[die_index].r_seg, i, die_index);
			if (ret != 0) {
				pr_err("No. %u post recv failed, device %s ret %d\n", i,
				       sentry_urma_dev[die_index].sentry_ubcore_dev->dev_name, ret);
				ubcore_delete_jetty(sentry_urma_dev[die_index].jetty);
				sentry_urma_dev[die_index].jetty = NULL;
				goto print_import_result;
			}
		}

		g_is_created_ubcore_resource = true;

		/* Import target jetties for remote servers (skip local EID at index 0) */
		for (i = 1; i < sentry_urma_dev[die_index].server_eid_valid_num; i++) {
			tjetty_cfg.id.eid = sentry_urma_dev[die_index].server_eid[i];
			sentry_urma_dev[die_index].tjetty[i] =
				create_tjetty(&tjetty_cfg, i, die_index);
			if (IS_ERR_OR_NULL(sentry_urma_dev[die_index].tjetty[i])) {
				pr_warn("ubcore_import_jetty_ex err, server eid %s\n",
					sentry_urma_dev[die_index].server_eid_array[i]);
				sentry_urma_dev[die_index].tjetty[i] = NULL;
				continue;
			}
			tjetty_valid_num++;
		}

print_import_result:
		pr_info("import: %d/%d success for device %s\n",
			tjetty_valid_num,
			sentry_urma_dev[die_index].server_eid_valid_num - 1, /* Exclude local EID */
			sentry_urma_dev[die_index].sentry_ubcore_dev->dev_name);
	}

	/* Start heartbeat thread if enabled */
	if (sentry_urma_ctx.heartbeat_enable) {
		sentry_urma_ctx.hb_thread = kthread_run(heartbeat_thread, NULL, "urma_hb_all");
		if (IS_ERR(sentry_urma_ctx.hb_thread)) {
			pr_err("failed to start heartbeat thread\n");
			sentry_urma_ctx.hb_thread = NULL;
		} else {
			pr_info("urma_hb_all thread start success\n");
		}
	}

	urma_mutex_lock_op(URMA_UNLOCK);
	return g_is_created_ubcore_resource ? 0 : -EFAULT;
}

/**
 * match_dev_by_local_eid - Find URMA device matching the specified local EID
 * @eid: Local EID to match
 * @eid_index: Output parameter for EID index
 *
 * Return: Pointer to matching URMA device, NULL if not found
 *
 * This function searches through all registered URMA devices to find one
 * that has an EID matching the specified local EID.
 */
static struct ubcore_device *match_dev_by_local_eid(const union ubcore_eid *eid,
						    uint32_t *eid_index)
{
	int cnt = 0;
	struct ubcore_dev_list *dev_node;
	struct ubcore_eid_info *eid_list;

	list_for_each_entry(dev_node, &ub_dev_list_head, list) {
		struct ubcore_eid_info *eid_info = ubcore_get_eid_list(dev_node->dev, &cnt);
		int i;

		if (IS_ERR_OR_NULL(eid_info)) {
			pr_warn("ubcore_get_eid_list failed\n");
			continue;
		}

		eid_list = eid_info;
		/* One device may have multiple EIDs */
		for (i = 0; i < cnt; i++) {
			pr_info("eid_info->eid: %llx, %x, %x, try to match\n",
				eid_info->eid.in4.reserved, eid_info->eid.in4.prefix,
				eid_info->eid.in4.addr);

			if (compare_ubcore_eid(eid_info->eid, *eid) == 0) {
				pr_info("Match device %s, use it to send/recv data\n",
					dev_node->dev->dev_name);
				*eid_index = eid_info->eid_index;
				ubcore_free_eid_list(eid_list);
				return dev_node->dev;
			}
			eid_info++;
		}
		ubcore_free_eid_list(eid_list);
	}

	pr_err("Cannot find dev by eid: %llx, %x, %x\n",
	       eid->in4.reserved, eid->in4.prefix, eid->in4.addr);
	return NULL;
}

/**
 * match_index_by_remote_ub_eid - Find node and die indices by remote EID
 * @remote_eid: Remote EID to search for
 * @node_index: Output parameter for node index
 * @die_index: Input/Output parameter for die index
 *
 * Return: 0 on success, -EINVAL if not found
 *
 * This function searches for a remote EID across all configured dies and nodes.
 * If die_index is -1 on input, it will be set to the found die index.
 * If die_index is specified, it verifies consistency.
 */
int match_index_by_remote_ub_eid(union ubcore_eid remote_eid, int *node_index, int *die_index)
{
	int i, j;

	if (!node_index || !die_index) {
		pr_err("Invalid param, failed to match index\n");
		return -EINVAL;
	}

	for (i = 0; i < sentry_urma_ctx.local_eid_num_configured; i++) {
		if (!sentry_urma_dev[i].is_created) {
			pr_err("invalid value for sentry_urma_dev[%d].is_created\n", i);
			return -EINVAL;
		}

		for (j = 0; j < sentry_urma_dev[i].server_eid_valid_num; j++) {
			if (memcmp(&sentry_urma_dev[i].server_eid[j], &remote_eid,
				   sizeof(union ubcore_eid)) == 0) {
				*node_index = j;
				if (*die_index == -1) {
					*die_index = i;
				} else if (*die_index != i) {
					pr_err("%s error, get die_index %d, input die_index %d\n",
					       __func__, i, *die_index);
					return -1;
				}
				return 0;
			}
		}
	}

	return -EINVAL;
}
EXPORT_SYMBOL(match_index_by_remote_ub_eid);

/**
 * sentry_create_urma_resource - Create URMA resources for specified EIDs
 * @eid: Array of local EIDs to create resources for
 * @eid_num: Number of EIDs in the array
 *
 * Return: 0 on success, negative error code on failure
 *
 * This function initializes URMA core, creates resources for each specified EID,
 * and matches devices to the provided EIDs. It handles both initial setup and
 * reconfiguration scenarios.
 */
int sentry_create_urma_resource(union ubcore_eid eid[], int eid_num)
{
	int ret, i;

	/* Prepare for new device matching by cleaning up old resources */
	release_all_resource();

	ret = init_ubcore();
	if (ret) {
		pr_err("ubcore init failed\n");
		return -EINVAL;
	}
	pr_info("ubcore init success\n");

	/* Create resources for each EID */
	for (i = 0; i < eid_num; i++) {
		sentry_urma_dev[i].sentry_ubcore_dev =
			match_dev_by_local_eid(&eid[i], &sentry_urma_dev[i].primary_eid_index);
		if (IS_ERR_OR_NULL(sentry_urma_dev[i].sentry_ubcore_dev))
			return -EINVAL;

		/* Re-create new URMA resource (e.g., jfs/jfc/jfr/seg) */
		ret = create_ubcore_resource(i);
		if (ret) {
			pr_err("create_ubcore_resource failed for %llx, %x, %x\n",
			       eid[i].in4.reserved, eid[i].in4.prefix, eid[i].in4.addr);
			release_ubcore_resource();
			return ret;
		}

		/* Update URMA EID after successful resource creation */
		memcpy(&sentry_urma_dev[i].local_eid, &eid[i], sizeof(union ubcore_eid));
	}

	sentry_urma_ctx.local_eid_num_configured = eid_num;
	return 0;
}
EXPORT_SYMBOL(sentry_create_urma_resource);

/**
 * format_client_info_show_str - Format client information for display
 *
 * This function formats the client information string for procfs display,
 * including server EIDs and client jetty ID in a human-readable format.
 */
static void format_client_info_show_str(void)
{
	bool is_not_single_die = false;
	char *p;
	int i, j;

	/* Clean up old data */
	if (sentry_urma_ctx.client_info_buf && sentry_urma_ctx.is_valid_client_info)
		memset(sentry_urma_ctx.client_info_buf, 0, CLIENT_INFO_BUF_MAX_LEN);

	if (sentry_urma_ctx.is_valid_client_info) {
		p = sentry_urma_ctx.client_info_buf;

		for (i = 0; i < sentry_urma_ctx.local_eid_num_configured; i++) {
			if (!sentry_urma_dev[i].is_created) {
				pr_err("invalid value for sentry_urma_dev[%d].is_created\n", i);
				break;
			}

			if (is_not_single_die)
				p += snprintf(p, CLIENT_INFO_BUF_MAX_LEN, "%s", ";");
			else
				p += snprintf(p, CLIENT_INFO_BUF_MAX_LEN, "%s", "server_eid:");

			for (j = 0; j < sentry_urma_dev[i].server_eid_valid_num; j++) {
				p += snprintf(p, CLIENT_INFO_BUF_MAX_LEN - (p - sentry_urma_ctx.client_info_buf),
					      "%s%s", sentry_urma_dev[i].server_eid_array[j],
					      j != sentry_urma_dev[i].server_eid_valid_num - 1 ? "," : "");
			}
			is_not_single_die = true;
		}

		snprintf(p, CLIENT_INFO_BUF_MAX_LEN, ", client_jetty_id:%d\n",
			 sentry_urma_ctx.client_jetty_id);
	} else {
		snprintf(sentry_urma_ctx.client_info_buf, CLIENT_INFO_BUF_MAX_LEN,
			 "server_eid:%s, client_jetty_id:%d\n", "null", DEFAULT_INVALID_JETTY_ID);
	}
}

/**
 * process_multi_eid_string - Process multiple EID strings from a buffer
 * @eid_buf: Buffer containing EID strings
 * @eid_array: Output array for EID strings
 * @eid_tmp: Output array for parsed EIDs
 * @sepstr: Separator string for tokenizing
 * @eid_max_num: Maximum number of EIDs to process
 *
 * Return: Number of EIDs processed on success, negative error code on failure
 *
 * This function parses a buffer containing multiple EID strings separated by
 * the specified separator and converts them to binary EID format.
 */
int process_multi_eid_string(char *eid_buf, char eid_array[][EID_MAX_LEN],
			     union ubcore_eid eid_tmp[], const char *sepstr, int eid_max_num)
{
	int ret;
	int eid_num = 0;
	char *eid_part;

	if (!eid_buf || !sepstr) {
		pr_err("Invalid param, failed to process multi eid string\n");
		return -EINVAL;
	}

	while ((eid_part = strsep(&eid_buf, sepstr)) != NULL) {
		if (eid_num >= eid_max_num) {
			pr_err("Invalid eid format: max num %d, current input exceeds\n",
			       eid_max_num);
			return -EINVAL;
		}

		if (strlen(eid_part) >= EID_MAX_LEN) {
			pr_err("Invalid eid format: str too long: %s\n", eid_part);
			return -EINVAL;
		}

		ret = str_to_eid(eid_part, &eid_tmp[eid_num]);
		if (ret) {
			pr_err("Invalid eid format: eid str %s\n", eid_part);
			return -EINVAL;
		}

		memset(eid_array[eid_num], 0, EID_MAX_LEN);
		memcpy(eid_array[eid_num], eid_part, strnlen(eid_part, EID_MAX_LEN));
		eid_num++;
	}

	return eid_num;
}
EXPORT_SYMBOL(process_multi_eid_string);

/**
 * process_server_eid_str - Process server EID string for multiple dies
 * @server_buf: Buffer containing server EID strings
 * @server_ub_eid_tmp: Output array for parsed server EIDs
 * @server_eid_valid_num: Output array for valid EID counts per die
 *
 * Return: 0 on success, negative error code on failure
 *
 * This function processes server EID strings for multiple dies, validating
 * that local EIDs match the configured values.
 */
static int process_server_eid_str(char *server_buf,
				  union ubcore_eid server_ub_eid_tmp[MAX_DIE_NUM][MAX_NODE_NUM],
				  int *server_eid_valid_num)
{
	int ret;
	int die_index = 0;
	char *single_server_eid_part;

	while ((single_server_eid_part = strsep(&server_buf, ";")) != NULL) {
		if (die_index >= MAX_DIE_NUM) {
			pr_err("Invalid eid format: max num %d, current input exceeds\n",
			       MAX_DIE_NUM);
			return -EINVAL;
		}

		if (strlen(single_server_eid_part) > SINGLE_SERVER_PART_LEN) {
			pr_err("Invalid server eid format: str too long: %s\n",
			       single_server_eid_part);
			return -EINVAL;
		}

		ret = process_multi_eid_string(single_server_eid_part,
					       sentry_urma_dev[die_index].server_eid_array,
					       server_ub_eid_tmp[die_index], ",", MAX_NODE_NUM);
		if (ret < 0)
			return ret;

		server_eid_valid_num[die_index] = ret;

		/* Verify local EID in server EID matches configured EID */
		if (memcmp(&server_ub_eid_tmp[die_index][0],
			   &sentry_urma_dev[die_index].local_eid,
			   sizeof(union ubcore_eid)) != 0) {
			pr_err("Error: local eid in server eid %llx%llx does not match configured eid %llx%llx\n",
			       server_ub_eid_tmp[die_index][0].in6.subnet_prefix,
			       server_ub_eid_tmp[die_index][0].in6.interface_id,
			       sentry_urma_dev[die_index].local_eid.in6.subnet_prefix,
			       sentry_urma_dev[die_index].local_eid.in6.interface_id);
			return -EINVAL;
		}
		die_index++;
	}

	return 0;
}

/**
 * proc_client_info_write - Write handler for client info proc file
 * @file: proc file pointer
 * @user_buf: user space buffer
 * @count: number of bytes to write
 * @ppos: file position
 *
 * Return: number of bytes written on success, negative error code on failure
 *
 * This function processes client information input from userspace, including
 * server EIDs and client jetty ID, and configures the URMA resources accordingly.
 */
static ssize_t proc_client_info_write(struct file *file, const char __user *user_buf,
				      size_t count, loff_t *ppos)
{
	int n = 0;
	int ret;
	union ubcore_eid server_ub_eid_tmp[MAX_DIE_NUM][MAX_NODE_NUM];
	int server_eid_valid_num[MAX_DIE_NUM] = {0};
	uint32_t client_jetty_id;
	int i;
	char *kbuf; /* server_buf, save service eid info and client_jetty_id info */
	char *server_buf_part; /* save service eid strings */
	char *client_jetty_id_part; /* save jetty id */

	if (count > CLIENT_INFO_MAX_LEN - 1) {
		pr_err("invalid server eid info, max len %d, actual %lu\n",
		       CLIENT_INFO_MAX_LEN - 1, count);
		return -EINVAL;
	}

	kbuf = kzalloc(CLIENT_INFO_MAX_LEN, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	server_buf_part = kzalloc(SERVER_EID_PART_MAX_LEN, GFP_KERNEL);
	if (!server_buf_part) {
		kfree(kbuf);
		return -ENOMEM;
	}

	client_jetty_id_part = kzalloc(JETTY_ID_MAX_LEN, GFP_KERNEL);
	if (!client_jetty_id_part) {
		kfree(kbuf);
		kfree(server_buf_part);
		return -ENOMEM;
	}

	if (copy_from_user(kbuf, user_buf, count)) {
		pr_err("failed parse client info input: copy_from_user failed\n");
		ret = -EFAULT;
		goto free_client_info;
	}
	kbuf[count] = '\0';
	pr_info("%s kbuf is %s\n", __func__, kbuf);

	/*
	 * Parse server EID part and client jetty ID part
	 * ((39 + 1) * 32 - 1) * 2 + 1 = 2559
	 */
	ret = sscanf(kbuf, "%2559[^ ] %6[^\n]%n",
		     server_buf_part,
		     client_jetty_id_part,
		     &n);
	if (ret != 2) {
		pr_err("Invalid msg str format and parse client info failed! str [%s]\n", kbuf);
		ret = -EINVAL;
		goto free_client_info;
	}

	/* Process server EIDs */
	ret = process_server_eid_str(server_buf_part,
				     server_ub_eid_tmp, server_eid_valid_num);
	if (ret)
		goto free_client_info;

	/* Process client jetty ID */
	ret = kstrtou32(client_jetty_id_part, 10, &client_jetty_id);
	if (ret < 0) {
		pr_err("Invalid format for client_jetty_id, str %s\n", client_jetty_id_part);
		ret = -EINVAL;
		goto free_client_info;
	}

	if (client_jetty_id < MIN_JETTY_ID || client_jetty_id > MAX_JETTY_ID) {
		pr_err("client_jetty_id %u out of range [%d, %d]\n",
		       client_jetty_id, MIN_JETTY_ID, MAX_JETTY_ID);
		ret = -EINVAL;
		goto free_client_info;
	}
	pr_info("client_jetty_id is %u\n", client_jetty_id);

	/* Update global configuration */
	urma_mutex_lock_op(URMA_LOCK);
	for (i = 0; i < MAX_DIE_NUM; i++) {
		if (server_eid_valid_num[i] == 0)
			break;
		sentry_urma_ctx.server_eid_num_configured = i + 1;
	}

	if (sentry_urma_ctx.server_eid_num_configured >
			sentry_urma_ctx.local_eid_num_configured) {
		pr_err("server eid num %d > local eid num %d\n",
				sentry_urma_ctx.server_eid_num_configured,
				sentry_urma_ctx.local_eid_num_configured);
		ret = -EINVAL;
		urma_mutex_lock_op(URMA_UNLOCK);
		goto free_client_info;
	}
	sentry_urma_ctx.is_valid_client_info = true;
	sentry_urma_ctx.client_jetty_id = client_jetty_id;

	for (i = 0; i < MAX_DIE_NUM; i++) {
		memcpy(sentry_urma_dev[i].server_eid, server_ub_eid_tmp[i],
		       sizeof(union ubcore_eid) * MAX_NODE_NUM);
		sentry_urma_dev[i].server_eid_valid_num = server_eid_valid_num[i];
	}
	urma_mutex_lock_op(URMA_UNLOCK);

	/* Import URMA resources */
	ret = import();
	if (ret != 0) {
		pr_err("ubcore import failed\n");
		ret = -EINVAL;
		goto free_client_info;
	}

	ret = count;

free_client_info:
	kfree(kbuf);
	kfree(server_buf_part);
	kfree(client_jetty_id_part);
	return ret;
}

/**
 * proc_client_info_show - Read handler for client info proc file
 * @file: proc file pointer
 * @buf: user space buffer
 * @count: number of bytes to read
 * @ppos: file position
 *
 * Return: number of bytes read on success, negative error code on failure
 *
 * This function displays the current client configuration including server EIDs
 * and client jetty ID in a human-readable format.
 */
static ssize_t proc_client_info_show(struct file *file, char __user *buf,
				     size_t count, loff_t *ppos)
{
	format_client_info_show_str();
	return simple_read_from_buffer(buf, count, ppos,
				       sentry_urma_ctx.client_info_buf,
				       strlen(sentry_urma_ctx.client_info_buf));
}

static const struct proc_ops proc_client_info_file_operations = {
	.proc_read	= proc_client_info_show,
	.proc_write	= proc_client_info_write,
};

/**
 * proc_heartbeat_write - Write handler for heartbeat control proc file
 * @file: proc file pointer
 * @ubuf: user space buffer
 * @cnt: number of bytes to write
 * @ppos: file position
 *
 * Return: number of bytes written on success, negative error code on failure
 *
 * This function controls the heartbeat thread based on user input ("on" or "off").
 * It starts or stops the heartbeat monitoring thread accordingly.
 */
static ssize_t proc_heartbeat_write(struct file *file, const char __user *ubuf,
				    size_t cnt, loff_t *ppos)
{
	int ret;
	char enable_str[ENABLE_VALUE_MAX_LEN + 1] = {0};

	if (cnt > ENABLE_VALUE_MAX_LEN) {
		pr_err("invalid value for /proc/%s/%s, only 'off' or 'on' allowed\n",
		       PROC_DEVICE_PATH, PROC_HEARTBEAT_SWITCH);
		return -EINVAL;
	}

	ret = copy_from_user(enable_str, ubuf, cnt);
	if (ret) {
		pr_err("set /proc/%s/%s failed\n", PROC_DEVICE_PATH, PROC_HEARTBEAT_SWITCH);
		return -EFAULT;
	}

	/* Remove trailing newline if present */
	if (cnt > 0 && enable_str[cnt - 1] == '\n')
		enable_str[cnt - 1] = '\0';

	if (strcmp(enable_str, "on") == 0) {
		if (!g_is_created_ubcore_resource) {
			sentry_urma_ctx.heartbeat_enable = false;
			pr_warn("Failed to start heartbeat: local eid not set\n");
			return -EINVAL;
		}

		sentry_urma_ctx.hb_thread = kthread_run(heartbeat_thread, NULL, "urma_hb_all");
		if (IS_ERR(sentry_urma_ctx.hb_thread)) {
			sentry_urma_ctx.heartbeat_enable = false;
			pr_err("failed to start heartbeat thread\n");
			sentry_urma_ctx.hb_thread = NULL;
			return -EINVAL;
		}
		sentry_urma_ctx.heartbeat_enable = true;
		pr_info("heartbeat thread enabled\n");

	} else if (strcmp(enable_str, "off") == 0) {
		sentry_urma_ctx.heartbeat_enable = false;
		pr_info("heartbeat thread disabled\n");

		if (sentry_urma_ctx.hb_thread) {
			kthread_stop(sentry_urma_ctx.hb_thread);
			sentry_urma_ctx.hb_thread = NULL;
		}
	} else {
		pr_err("invalid value for /proc/%s/%s\n",
		       PROC_DEVICE_PATH, PROC_HEARTBEAT_SWITCH);
		return -EINVAL;
	}

	return cnt;
}

/**
 * proc_heartbeat_show - Read handler for heartbeat control proc file
 * @file: proc file pointer
 * @buf: user space buffer
 * @count: number of bytes to read
 * @ppos: file position
 *
 * Return: number of bytes read on success, negative error code on failure
 *
 * This function displays the current heartbeat thread status ("on" or "off").
 */
static ssize_t proc_heartbeat_show(struct file *file, char __user *buf,
				   size_t count, loff_t *ppos)
{
	const char *status = sentry_urma_ctx.heartbeat_enable ? "on" : "off";
	size_t len = sentry_urma_ctx.heartbeat_enable ? 2 : 3;

	return simple_read_from_buffer(buf, count, ppos, status, len);
}

static const struct proc_ops proc_heartbeat_file_operations = {
	.proc_read	= proc_heartbeat_show,
	.proc_write	= proc_heartbeat_write,
};

/**
 * heartbeat_thread - Heartbeat monitoring thread function
 * @arg: thread argument (unused)
 *
 * Return: 0 on thread exit
 *
 * This function implements the heartbeat monitoring mechanism for URMA nodes.
 * It periodically sends heartbeat messages, checks for acknowledgments, and
 * attempts to rebuild connections to unresponsive nodes.
 */
static int heartbeat_thread(void *arg)
{
	int i, cnt;
	int die_index;

	struct sentry_binary_msg heartbeat_msg = {0};

	heartbeat_msg.type = SMH_MESSAGE_HEARTBEAT;

	while (!kthread_should_stop()) {
		if (!sentry_urma_ctx.heartbeat_enable) {
			msleep_interruptible(HB_WAIT_ACK_SLEEP_MS);
			continue;
		}

		uint64_t start_time = ktime_get_ns();

		/* Reset heartbeat acknowledgment status for all nodes */
		for (die_index = 0; die_index < MAX_DIE_NUM; die_index++) {
			for (i = 1; i < sentry_urma_dev[die_index].server_eid_valid_num; i++)
				atomic_set(&sentry_urma_dev[die_index].urma_hb_ack_list[i], 0);
		}
		pr_info("start to detect heartbeat\n");

		/* Send heartbeat to inactive nodes */
		for (die_index = 0; die_index < MAX_DIE_NUM; die_index++) {
			bool need_rebuild[MAX_NODE_NUM] = {false};
			bool rebuilt = false;

			if (!sentry_urma_dev[die_index].is_created)
				break;

			/* sentry_urma_dev[die_index].server_eid_array[0] is local_eid */
			for (i = 1; i < sentry_urma_dev[die_index].server_eid_valid_num; i++) {
				pr_info("send heartbeat to node %d (eid=%s)\n", i,
					sentry_urma_dev[die_index].server_eid_array[i]);
				sentry_post_jetty_send_wr(&heartbeat_msg, i, die_index);
			}

			msleep_interruptible(HB_WAIT_ACK_SLEEP_MS);

			/* Check for heartbeat acknowledgments */
			if (!sentry_urma_ctx.is_panic_mode &&
			    !mutex_trylock(&sentry_urma_mutex))
				continue;

			memset(sentry_urma_ctx.heartbeat_thread_cr, 0, sizeof(struct ubcore_cr) * MAX_NODE_NUM);
			cnt = sentry_poll_jfc(sentry_urma_dev[die_index].sender_jfc,
					      MAX_NODE_NUM, sentry_urma_ctx.heartbeat_thread_cr, die_index);
			urma_mutex_lock_op(URMA_UNLOCK);

			if (cnt > 0) {
				for (int k = 0; k < cnt; k++)
					pr_info("heartbeat cr[%d].status=%d\n", k, sentry_urma_ctx.heartbeat_thread_cr[k].status);
			}

			/* Check final heartbeat result and rebuild if needed */
			for (i = 1; i < sentry_urma_dev[die_index].server_eid_valid_num; i++) {
				if (!atomic_read(&sentry_urma_dev[die_index].urma_hb_ack_list[i])) {
					/* Link down, try to rebuild link */
					pr_info("Failed to detect heartbeat of node %d (eid=%s), start rebuild link\n",
						i, sentry_urma_dev[die_index].server_eid_array[i]);
					if (rebuild_tjetty(i, die_index) == 0) {
						pr_info("after rebuild, retry heartbeat for node %d (eid=%s)\n",
							i, sentry_urma_dev[die_index].server_eid_array[i]);
						sentry_post_jetty_send_wr(&heartbeat_msg,
								i, die_index);
						need_rebuild[i] = true;
						rebuilt = true;
					}
				} else {
					pr_info("succeed to detect heartbeat of node %d (eid=%s)\n",
						i, sentry_urma_dev[die_index].server_eid_array[i]);
				}
			}

			/* Verify rebuilt connections */
			if (rebuilt) {
				msleep_interruptible(HB_WAIT_ACK_SLEEP_MS);
				memset(sentry_urma_ctx.heartbeat_thread_cr, 0, sizeof(struct ubcore_cr) * MAX_NODE_NUM);

				if (!sentry_urma_ctx.is_panic_mode &&
				    !mutex_trylock(&sentry_urma_mutex))
					continue;

				sentry_poll_jfc(sentry_urma_dev[die_index].sender_jfc,
						MAX_NODE_NUM, sentry_urma_ctx.heartbeat_thread_cr, die_index);
				urma_mutex_lock_op(URMA_UNLOCK);

				pr_info("check rebuilt node heartbeat\n");
				for (i = 1; i < sentry_urma_dev[die_index].server_eid_valid_num; i++) {
					if (!need_rebuild[i])
						continue;

					pr_info("node[%s] heartbeat recover %s\n",
						sentry_urma_dev[die_index].server_eid_array[i],
						!atomic_read(&sentry_urma_dev[die_index].urma_hb_ack_list[i]) ?
						"failed" : "success");
				}
			}
		}

		/* Calculate sleep time to maintain heartbeat interval */
		int msleep_time = HEARTBEAT_INTERVAL_MS -
				 (int)((ktime_get_ns() - start_time) / NSEC_PER_MSEC);

		if (msleep_time > 0)
			msleep_interruptible(msleep_time);
	}

	return 0;
}

/**
 * sentry_poll_jfc - Poll completion queue for heartbeat acknowledgments
 * @jfc: Jetty completion queue to poll
 * @cr_cnt: Maximum number of completions to retrieve
 * @cr: Array to store completions
 * @die_index: Die index for resource access
 *
 * Return: Number of completions retrieved, negative on error
 *
 * This function polls the completion queue for heartbeat acknowledgments
 * and updates the remote receive counters for successful completions.
 */
static int sentry_poll_jfc(struct ubcore_jfc *jfc, int cr_cnt, struct ubcore_cr *cr,
			   int die_index)
{
	int cnt;
	int k;

	if (die_index < 0 || die_index >= MAX_DIE_NUM) {
		pr_err("invalid die_index (%d), range is [0, %d]\n",
		       die_index, MAX_DIE_NUM - 1);
		return -EINVAL;
	}

	cnt = ubcore_poll_jfc(jfc, cr_cnt, cr);
	pr_info("ubcore_poll_jfc cr.status is %d\n", cr->status);
	if (cnt <= 0)
		return cnt;

	/* Process successful completions */
	for (k = 0; k < cnt; k++) {
		int idx = -1;
		int tmp_die_index = die_index;

		if (cr[k].status == 0) {
			match_index_by_remote_ub_eid(cr[k].remote_id.eid, &idx, &tmp_die_index);
			if (idx >= 0)
				atomic_inc(&sentry_urma_dev[tmp_die_index].remote_recv_cnt[idx]);
		}
	}

	return cnt;
}

/**
 * update_remote_recv_cnt - Update remote receive counters by polling completion queue
 * @die_index: Die index for resource access
 *
 * Return: 0 on success, negative error code on failure
 *
 * This function polls the sender completion queue to update the remote
 * receive counters for the specified die index.
 */
static int update_remote_recv_cnt(int die_index)
{
	int cnt;

	if (die_index < 0 || die_index >= MAX_DIE_NUM) {
		pr_err("invalid die_index (%d), range is [0, %d]\n",
		       die_index, MAX_DIE_NUM - 1);
		return -EINVAL;
	}

	if (!sentry_urma_ctx.is_panic_mode && !mutex_trylock(&sentry_urma_mutex))
		return -EBUSY;

	memset(sentry_urma_ctx.update_recv_cnt_cr, 0, sizeof(struct ubcore_cr) * MAX_NODE_NUM);
	cnt = sentry_poll_jfc(sentry_urma_dev[die_index].sender_jfc, MAX_NODE_NUM, sentry_urma_ctx.update_recv_cnt_cr, die_index);
	urma_mutex_lock_op(URMA_UNLOCK);

	if (cnt < 0) {
		pr_err("update_remote_recv_cnt: poll sender_jfc error, ret %d\n", cnt);
		return -EFAULT;
	}

	return 0;
}

/**
 * rebuild_tjetty - Rebuild a target jetty for a specific node
 * @idx: Node index to rebuild
 * @die_index: Die index for resource access
 *
 * Return: 0 on success, negative error code on failure
 *
 * This function rebuilds a target jetty for a specific node when connectivity
 * issues are detected. It creates a new tjetty, replaces the old one, and
 * resets the send/receive counters.
 */
static int rebuild_tjetty(int idx, int die_index)
{
	struct ubcore_tjetty *tjetty_tmp = NULL;
	struct ubcore_tjetty *tjetty_to_clear = NULL;

	if (!sentry_urma_dev[die_index].sentry_ubcore_dev) {
		pr_err("%s failed: urma %d dev is not exist\n", __func__, die_index);
		return -EINVAL;
	}

	struct ubcore_tjetty_cfg cfg = {
		.id.id = sentry_urma_ctx.client_jetty_id,
		.id.eid = sentry_urma_dev[die_index].server_eid[idx],
		.trans_mode = UBCORE_TP_RM,
		.type = UBCORE_JETTY,
	};

	if (die_index < 0 || die_index >= MAX_DIE_NUM) {
		pr_err("invalid die_index (%d), range is [0, %d]\n",
		       die_index, MAX_DIE_NUM - 1);
		return -EINVAL;
	}

	if (!sentry_urma_ctx.is_panic_mode &&
	    !mutex_trylock(&sentry_urma_mutex)) {
		pr_debug("rebuild_tjetty: lock busy, skipping node %d, eid %s\n",
			 idx, sentry_urma_dev[die_index].server_eid_array[idx]);
		return -EBUSY;
	}

	tjetty_tmp = create_tjetty(&cfg, idx, die_index);
	if (IS_ERR_OR_NULL(tjetty_tmp)) {
		urma_mutex_lock_op(URMA_UNLOCK);
		pr_err("rebuild_tjetty: tjetty[%d] ubcore_import_jetty_ex err, eid %s\n",
		       idx, sentry_urma_dev[die_index].server_eid_array[idx]);
		return -EFAULT;
	}

	/* Replace old tjetty if it exists */
	if (sentry_urma_dev[die_index].tjetty[idx])
		tjetty_to_clear = sentry_urma_dev[die_index].tjetty[idx];

	sentry_urma_dev[die_index].tjetty[idx] = tjetty_tmp;

	/* Reset counters */
	atomic_set(&sentry_urma_dev[die_index].send_cnt[idx], 0);
	atomic_set(&sentry_urma_dev[die_index].remote_recv_cnt[idx], 0);

	/* Clean up old tjetty */
	if (tjetty_to_clear)
		ubcore_unimport_jetty(tjetty_to_clear);

	/* Repost receive work request */
	sentry_post_recv(sentry_urma_dev[die_index].jetty,
			 sentry_urma_dev[die_index].r_seg, idx, die_index);

	urma_mutex_lock_op(URMA_UNLOCK);
	pr_info("rebuild_tjetty: tjetty[%d] rebuilt OK\n", idx);
	return 0;
}

/**
 * check_and_rebuild_single_tjetty - Check and rebuild tjetty if needed
 * @idx: Node index to check
 * @die_index: Die index for resource access
 *
 * Return: 0 on success, negative error code on failure or if rebuild not needed
 *
 * This function checks the send and receive counters for a specific node and
 * rebuilds the tjetty if the difference exceeds the rebuild threshold.
 * It also handles counter overflow by resetting when they reach maximum values.
 */
static int check_and_rebuild_single_tjetty(int idx, int die_index)
{
	int ret = 0;
	int scnt, rcnt;

	if (die_index < 0 || die_index >= MAX_DIE_NUM) {
		pr_err("invalid die_index (%d), range is [0, %d]\n",
		       die_index, MAX_DIE_NUM - 1);
		return -EINVAL;
	}

	scnt = atomic_read(&sentry_urma_dev[die_index].send_cnt[idx]);
	rcnt = atomic_read(&sentry_urma_dev[die_index].remote_recv_cnt[idx]);

	/* Check if rebuild threshold is exceeded */
	if (scnt - rcnt > URMA_REBUILD_THRESHOLD) {
		pr_info("tjetty[%d] %s check failed: send_cnt=%d, remote_recv_cnt=%d, rebuild\n",
			idx, sentry_urma_dev[die_index].server_eid_array[idx], scnt, rcnt);
		/* Reset counters and rebuild */
		atomic_set(&sentry_urma_dev[die_index].send_cnt[idx], 0);
		atomic_set(&sentry_urma_dev[die_index].remote_recv_cnt[idx], 0);
		ret = rebuild_tjetty(idx, die_index);
	}

	/* Handle counter overflow */
	if (scnt > URMA_CNT_MAX_NUM && rcnt > URMA_CNT_MAX_NUM) {
		atomic_set(&sentry_urma_dev[die_index].send_cnt[idx], 0);
		atomic_set(&sentry_urma_dev[die_index].remote_recv_cnt[idx], 0);
	}

	return ret;
}

/**
 * sentry_post_jetty_send_wr - Post a send work request to a jetty
 * @buf: Data buffer to send
 * @tjetty_idx: Target jetty index
 * @die_index: Die index for resource access
 *
 * Return: 0 on success, negative error code on failure
 *
 * This function posts a send work request to the specified target jetty,
 * copying the data to the send segment and updating the send counters.
 */
int sentry_post_jetty_send_wr(const struct sentry_binary_msg *buf, int tjetty_idx,
				     int die_index)
{
	int ret;
	struct ubcore_jfs_wr *bad_wr = NULL;
	struct ubcore_tjetty *tj_i;
	uint64_t s_seg_va_i;

	if (die_index < 0 || die_index >= MAX_DIE_NUM) {
		pr_err("invalid die_index (%d), range is [0, %d]\n",
		       die_index, MAX_DIE_NUM - 1);
		return -EINVAL;
	}

	if (!sentry_urma_ctx.is_panic_mode &&
	    !mutex_trylock(&sentry_urma_mutex)) {
		pr_debug("%s: lock busy, skipping %d\n", __func__, tjetty_idx);
		return 0;
	}

	if (!sentry_urma_dev[die_index].sentry_ubcore_dev) {
		pr_err("%s failed: urma %d dev is not exist\n", __func__, die_index);
		urma_mutex_lock_op(URMA_UNLOCK);
		return -EINVAL;
	}

	tj_i = sentry_urma_dev[die_index].tjetty[tjetty_idx];

	if (!sentry_urma_dev[die_index].jetty) {
		pr_err("jetty not created! Please establish a link first\n");
		urma_mutex_lock_op(URMA_UNLOCK);
		return COMM_PARM_NOT_SET;
	}

	if (!tj_i) {
		urma_mutex_lock_op(URMA_UNLOCK);
		return -ENODEV;
	}

	/* Configure send work request */
	sentry_urma_dev[die_index].jfs_wr[tjetty_idx].opcode = UBCORE_OPC_SEND;
	sentry_urma_dev[die_index].jfs_wr[tjetty_idx].tjetty = tj_i;
	s_seg_va_i = (uint64_t)sentry_urma_dev[die_index].s_seg_va +
		     (SGE_MAX_LEN * tjetty_idx);

	/* Copy data to send segment */
	memcpy((struct sentry_binary_msg *)s_seg_va_i, buf, sizeof(struct sentry_binary_msg));

	/* Set up scatter-gather element */
	sentry_urma_dev[die_index].s_sge[tjetty_idx].addr = s_seg_va_i;
	sentry_urma_dev[die_index].s_sge[tjetty_idx].len = sizeof(struct sentry_binary_msg);
	sentry_urma_dev[die_index].s_sge[tjetty_idx].tseg =
		sentry_urma_dev[die_index].s_seg;

	/* Configure work request */
	sentry_urma_dev[die_index].jfs_wr[tjetty_idx].send.src.sge =
		&sentry_urma_dev[die_index].s_sge[tjetty_idx];
	sentry_urma_dev[die_index].jfs_wr[tjetty_idx].send.src.num_sge = 1;
	sentry_urma_dev[die_index].jfs_wr[tjetty_idx].user_ctx = s_seg_va_i;
	sentry_urma_dev[die_index].jfs_wr[tjetty_idx].flag.bs.complete_enable = 1;

	/* Post send work request */
	ret = ubcore_post_jetty_send_wr(sentry_urma_dev[die_index].jetty,
					&sentry_urma_dev[die_index].jfs_wr[tjetty_idx],
					&bad_wr);
	if (ret) {
		pr_err("ubcore_post_jetty_send_wr err, send [%s] msg to %s failed\n",
				get_msg_type_name(buf->type),
				sentry_urma_dev[die_index].server_eid_array[tjetty_idx]);
	} else {
		atomic_inc(&sentry_urma_dev[die_index].send_cnt[tjetty_idx]);
		pr_info("ubcore_post_jetty_send_wr success, send [%s] msg to %s success\n",
				get_msg_type_name(buf->type),
				sentry_urma_dev[die_index].server_eid_array[tjetty_idx]);
	}

	urma_mutex_lock_op(URMA_UNLOCK);
	return ret;
}

/**
 * urma_send_to_all_nodes - Send data to all configured nodes
 * @buf: Data buffer to send
 * @die_index: Die index for resource access
 *
 * Return: Number of successful sends, negative error code on failure
 *
 * This function sends data to all configured remote nodes for a specific die,
 * performing necessary checks and potential tjetty rebuilds before sending.
 */
static int urma_send_to_all_nodes(const struct sentry_binary_msg *buf, int die_index)
{
	int cnt = 0;
	int i;

	if (!buf)
		return -EINVAL;

	if (die_index < 0 || die_index >= MAX_DIE_NUM) {
		pr_err("invalid die_index (%d), range is [0, %d]\n",
		       die_index, MAX_DIE_NUM - 1);
		return -EINVAL;
	}

	/* Update remote receive counters */
	if (update_remote_recv_cnt(die_index))
		return -EFAULT;

	/* sentry_urma_dev[die_index].server_eid[0] is local_eid */
	for (i = 1; i < sentry_urma_dev[die_index].server_eid_valid_num; i++) {
		int ret = 0;

		/* Check and rebuild tjetty if needed (skip in panic mode) */
		if (!sentry_urma_ctx.is_panic_mode)
			ret = check_and_rebuild_single_tjetty(i, die_index);

		if (!ret) {
			pr_info("start to send msg to [%s]\n",
				sentry_urma_dev[die_index].server_eid_array[i]);
			ret = sentry_post_jetty_send_wr(buf, i, die_index);
		}

		if (ret == COMM_PARM_NOT_SET)
			return COMM_PARM_NOT_SET;

		if (ret == 0)
			cnt++;
	}

	return cnt;
}

/**
 * urma_send_to_given_node - Send data to a specific node
 * @buf: Data buffer to send
 * @dst_eid: Destination EID string
 * @die_index: Die index for resource access (-1 if unknown)
 *
 * Return: 1 on successful send, 0 if not sent, negative error code on failure
 *
 * This function sends data to a specific node identified by EID, performing
 * necessary validation and potential tjetty rebuild before sending.
 */
static int urma_send_to_given_node(const struct sentry_binary_msg *buf,
				   const char *dst_eid, int die_index)
{
	int cnt = 0;
	int ret;
	int node_idx = -1;
	union ubcore_eid dst_ubcore_eid;

	if (!buf || !dst_eid)
		return -EINVAL;

	/* Convert EID string to binary format */
	if (str_to_eid(dst_eid, &dst_ubcore_eid) < 0) {
		pr_err("urma_send: invalid dst eid [%s]\n", dst_eid);
		return -EINVAL;
	}

	/* Find node and die indices */
	match_index_by_remote_ub_eid(dst_ubcore_eid, &node_idx, &die_index);
	if (node_idx < 0) {
		pr_warn("urma_send: msg format invalid, dst eid is %s\n", dst_eid);
		return 0;
	}

	/* Update remote receive counters */
	ret = update_remote_recv_cnt(die_index);
	if (ret)
		return ret;

	/* Check and rebuild tjetty if needed (skip in panic mode) */
	if (!sentry_urma_ctx.is_panic_mode)
		ret = check_and_rebuild_single_tjetty(node_idx, die_index);

	if (!ret) {
		pr_info("start to send msg to [%s]\n", dst_eid);
		ret = sentry_post_jetty_send_wr(buf, node_idx, die_index);
	}

	if (!ret)
		cnt++;

	return cnt;
}

/**
 * urma_send - Send data to URMA nodes
 * @buf: Data buffer to send
 * @dst_eid: Destination EID (NULL for broadcast to all nodes)
 * @die_index: Die index (-1 for auto-detect, 0/1 for specific die)
 *
 * Return: Number of successful sends, negative error code on failure
 *
 * This function provides the main interface for sending data via URMA,
 * supporting both broadcast and unicast modes.
 */
int urma_send(const struct sentry_binary_msg *buf, const char *dst_eid, int die_index)
{
	int cnt = 0;

	if (!g_is_created_ubcore_resource)
		return -ENODEV;

	/* at broadcast mode, dst_eid is NULL */
	if (!buf) {
		pr_err("%s: Invalid param, failed to send data\n", __func__);
		return -EINVAL;
	}

	if (!dst_eid && die_index >= 0) {
		/* Broadcast mode: send to all nodes */
		cnt = urma_send_to_all_nodes(buf, die_index);
	} else {
		/* Unicast mode: send to specific node */
		cnt = urma_send_to_given_node(buf, dst_eid, die_index);
	}

	return cnt;
}
EXPORT_SYMBOL(urma_send);

/**
 * urma_recv - Receive data from URMA nodes
 * @buf_arr: Array of buffers to store received messages
 * @array_size: array size for received message
 *
 * Return: Number of valid messages received, negative error code on failure
 *
 * This function polls for incoming messages, handles heartbeat protocol,
 * and returns valid event messages to the caller.
 */
int urma_recv(struct sentry_binary_msg *buf_arr, size_t array_size)
{
	int ret;
	int valid_msg_num = 0;
	int die_index;

	if (!buf_arr)
		return -EINVAL;

	if (!sentry_urma_ctx.is_panic_mode &&
	    !mutex_trylock(&sentry_urma_mutex))
		return -EBUSY;

	if (!g_is_created_ubcore_resource) {
		urma_mutex_lock_op(URMA_UNLOCK);
		return -ENODEV;
	}
	urma_mutex_lock_op(URMA_UNLOCK);

	/* Check each die for incoming messages */
	for (die_index = 0; die_index < sentry_urma_ctx.local_eid_num_configured; die_index++) {
		int cnt;
		memset(sentry_urma_ctx.urma_recv_cr, 0, sizeof(struct ubcore_cr) * MAX_NODE_NUM);

		if (!sentry_urma_ctx.is_panic_mode &&
		    !mutex_trylock(&sentry_urma_mutex))
			continue;

		if (!sentry_urma_dev[die_index].is_created) {
			urma_mutex_lock_op(URMA_UNLOCK);
			break;
		}

		cnt = ubcore_poll_jfc(sentry_urma_dev[die_index].receiver_jfc,
				      MAX_NODE_NUM, sentry_urma_ctx.urma_recv_cr);
		urma_mutex_lock_op(URMA_UNLOCK);

		if (cnt < 0) {
			pr_err("%s: ubcore_poll_jfc failed for eid %s, ret %d\n",
			       __func__,
			       sentry_urma_dev[die_index].server_eid_array[0],
			       cnt);
			continue;
		} else if (cnt == 0) {
			/* No messages available */
			continue;
		}

		/* Process each completion */
		for (int i = 0; i < cnt; i++) {
			int node_idx = -1;
			int tmp_die_index = die_index;
			struct sentry_binary_msg *binary_msg = NULL;

			/* Match remote EID to node index */
			match_index_by_remote_ub_eid(sentry_urma_ctx.urma_recv_cr[i].remote_id.eid, &node_idx, &tmp_die_index);
			if (node_idx < 0) {
				pr_warn("%s: cr[%d] eid (%llx, %x, %x) not matched\n",
					__func__,
					i,
					sentry_urma_ctx.urma_recv_cr[i].remote_id.eid.in4.reserved,
					sentry_urma_ctx.urma_recv_cr[i].remote_id.eid.in4.prefix,
					sentry_urma_ctx.urma_recv_cr[i].remote_id.eid.in4.addr);
				continue;
			}

			/* Check if binary message */
			binary_msg = (struct sentry_binary_msg *)
				sentry_urma_ctx.urma_recv_cr[i].user_ctx;
			pr_info("%s: cr[%d] get msg from node[%d] eid=%s\n",
				__func__,
				i,
				node_idx,
				sentry_urma_dev[tmp_die_index].server_eid_array[node_idx]);

			/* Handle different message types */
			if (binary_msg->type == SMH_MESSAGE_HEARTBEAT) {
				/* Heartbeat request - send acknowledgment */
				pr_info("%s: received heartbeat from node[%d] eid=%s, send ack\n",
					__func__,
					node_idx,
					sentry_urma_dev[tmp_die_index].server_eid_array[node_idx]);

				struct sentry_binary_msg heartbeat_msg = {0};

				heartbeat_msg.type = SMH_MESSAGE_HEARTBEAT_ACK;
				sentry_post_jetty_send_wr(&heartbeat_msg,
						node_idx, tmp_die_index);

				if (!sentry_urma_ctx.is_panic_mode &&
				    !mutex_trylock(&sentry_urma_mutex))
					continue;

				memset(sentry_urma_ctx.urma_recv_sender_cr, 0, sizeof(struct ubcore_cr) * MAX_NODE_NUM);
				sentry_poll_jfc(sentry_urma_dev[tmp_die_index].sender_jfc,
						MAX_NODE_NUM, sentry_urma_ctx.urma_recv_sender_cr, tmp_die_index);
				urma_mutex_lock_op(URMA_UNLOCK);
			} else if (binary_msg->type == SMH_MESSAGE_HEARTBEAT_ACK) {
				/* Heartbeat acknowledgment - update status */
				pr_info("%s: received heartbeat ack from node[%d] eid=%s\n",
					__func__,
					node_idx,
					sentry_urma_dev[tmp_die_index].server_eid_array[node_idx]);
				atomic_set(&sentry_urma_dev[tmp_die_index].urma_hb_ack_list[node_idx], 1);
			} else {
				/* Event message - store for caller */
				if (valid_msg_num >= array_size) {
					pr_warn("%s: recv msg num exceeds the msg array size\n",
						__func__);
					return valid_msg_num;
				}
				memcpy(&buf_arr[valid_msg_num], binary_msg, sizeof(*binary_msg));
				valid_msg_num++;
			}

			/* Repost receive work request */
			if (!sentry_urma_ctx.is_panic_mode &&
			    !mutex_trylock(&sentry_urma_mutex))
				continue;

			ret = sentry_post_recv(sentry_urma_dev[tmp_die_index].jetty,
					       sentry_urma_dev[tmp_die_index].r_seg,
					       node_idx, tmp_die_index);
			urma_mutex_lock_op(URMA_UNLOCK);

			if (ret < 0)
				pr_warn("%s: sentry_post_recv failed, ret %d\n", __func__, ret);
		}
	}

	return valid_msg_num;
}
EXPORT_SYMBOL(urma_recv);

/**
 * reboot_cleanup_notifier - System reboot notifier callback
 * @nb: Notifier block
 * @action: Reboot action
 * @data: Notifier data
 *
 * Return: NOTIFY_DONE
 *
 * This function ensures proper cleanup of URMA resources during system reboot.
 */
static int reboot_cleanup_notifier(struct notifier_block *nb,
				   unsigned long action, void *data)
{
	if (action == SYS_RESTART && sentry_urma_ctx.hb_thread) {
		kthread_stop(sentry_urma_ctx.hb_thread);
		sentry_urma_ctx.hb_thread = NULL;
		pr_info("urma_hb_all thread stopped\n");
	}
	return NOTIFY_DONE;
}

static struct notifier_block reboot_cleanup_nb = {
	.notifier_call = reboot_cleanup_notifier,
	.priority = INT_MAX,
};

/**
 * sentry_urma_comm_init - Module initialization function
 *
 * Return: 0 on success, negative error code on failure
 *
 * This function initializes the URMA communication module, creating proc
 * files, allocating buffers, and registering reboot notifier.
 */
static int __init sentry_urma_comm_init(void)
{
	int ret = 0;

	sentry_urma_ctx.proc_dir = proc_mkdir_mode(PROC_DEVICE_PATH, PROC_DIR_PERMISSION, NULL);
	if (!sentry_urma_ctx.proc_dir) {
		pr_err("create /proc/%s dir failed\n", PROC_DEVICE_PATH);
		return -ENOMEM;
	}

	ret |= sentry_create_proc_file(PROC_DEVICE_NAME, sentry_urma_ctx.proc_dir,
				       &proc_client_info_file_operations);
	ret |= sentry_create_proc_file(PROC_HEARTBEAT_SWITCH, sentry_urma_ctx.proc_dir,
				       &proc_heartbeat_file_operations);
	if (ret < 0)
		goto remove_proc_dir;

	ret = init_global_char();
	if (ret)
		goto remove_proc_dir;

	ret = register_reboot_notifier(&reboot_cleanup_nb);
	if (ret) {
		pr_info("reboot_cleanup_nb register failed: %d\n", ret);
		goto free_mem;
	}

	pr_info("reboot_cleanup_nb registered\n");
	return 0;

free_mem:
	free_global_char();
remove_proc_dir:
	proc_remove(sentry_urma_ctx.proc_dir);
	return ret;
}

/**
 * sentry_urma_comm_exit - Module cleanup function
 *
 * This function cleans up all URMA resources, stops threads, and removes
 * proc files during module unload.
 */
static void __exit sentry_urma_comm_exit(void)
{
	unregister_reboot_notifier(&reboot_cleanup_nb);
	pr_info("reboot_cleanup_nb unregistered\n");

	if (sentry_urma_ctx.hb_thread) {
		kthread_stop(sentry_urma_ctx.hb_thread);
		sentry_urma_ctx.hb_thread = NULL;
		pr_info("urma_hb_all thread stopped\n");
	}

	release_all_resource();

	if (sentry_urma_ctx.proc_dir)
		proc_remove(sentry_urma_ctx.proc_dir);

	pr_info("ubcore release\n");
	free_global_char();
}

module_init(sentry_urma_comm_init);
module_exit(sentry_urma_comm_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("luckky");
MODULE_DESCRIPTION("Kernel module to transport msg via URMA");
