// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
 * Description: support UVB communication
 * Author: sxt1001
 * Create: 2025-04-23
 */

#include <linux/firmware/uvb/cis.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/proc_fs.h>

#include "smh_common_type.h"
#include "smh_message.h"

#undef pr_fmt
#define pr_fmt(fmt) "[sentry][uvb]: " fmt

uint32_t g_local_cna = -1;
EXPORT_SYMBOL(g_local_cna);

static struct proc_dir_entry *uvb_proc_dir;
static char *g_kbuf_server_cna; // cna1;cna2;cna3...cnan
uint32_t g_server_cna_array[MAX_NODE_NUM];
int g_server_cna_valid_num;
EXPORT_SYMBOL(g_server_cna_array);
EXPORT_SYMBOL(g_server_cna_valid_num);

/*
 * @brief send data to server by UVB
 *
 * @param1: Data to be sent
 * @param2: Indicates the CNA information of the specified server.
 *          If dst_cna is greater than CNA_MAX_VALUE, no server is
 *          specified. In this case, data needs to be sent to all nodes.
 * @param3: UVB mode. If env is in panic status, We need to use
 *          synchronization mode, set is_sync to true.
 * @return Number of nodes that are successfully sent
 * */
int uvb_send(const struct sentry_binary_msg *str, uint32_t dst_cna, bool is_sync)
{
	int res, cnt = 0;

	if (!str) {
		pr_err("%s: Invalid param, failed to send data\n", __func__);
		return -EINVAL;
	}

	struct cis_message msg = {0};

	msg.input = (char *)str;
	msg.input_size = sizeof(struct sentry_binary_msg);
	msg.output = NULL;
	msg.p_output_size = NULL;

	if (dst_cna < CNA_MAX_VALUE) { // dst cna is valid, send data to specific node
		res = cis_call_by_uvb(UBIOS_CALL_ID_PANIC_CALL, UVB_SENDER_ID_SYSSENTRY,
			      UVB_RECEIVER_ID_SYSSENTRY(dst_cna), &msg, is_sync);
		if (res != 0) {
			pr_err("Send to a specified node, uvb send [%s] msg to %u failed.\n",
					get_msg_type_name(str->type), dst_cna);
			return -1;
		}
		cnt++;
		pr_info("Send to a specified node, uvb send [%s] msg to %u success.\n",
				get_msg_type_name(str->type), dst_cna);
		return cnt;
	}

	// dst_cna is invalid, send data to all nodes.
	for (int i = 0; i < g_server_cna_valid_num; i++) {
		if (g_server_cna_array[i] < CNA_MAX_VALUE) {
			pr_info("Broadcast mode. receiver cna is %d, received id is %#x.\n",
				g_server_cna_array[i],
				UVB_RECEIVER_ID_SYSSENTRY(g_server_cna_array[i]));
			res = cis_call_by_uvb(UBIOS_CALL_ID_PANIC_CALL, UVB_SENDER_ID_SYSSENTRY,
					  UVB_RECEIVER_ID_SYSSENTRY(g_server_cna_array[i]), &msg, is_sync);
			if (res != 0) {
				pr_err("uvb send [%s] msg to %u failed.\n",
					get_msg_type_name(str->type), g_server_cna_array[i]);
				continue;
			}
			pr_info("uvb send [%s] msg to %u success.\n",
					get_msg_type_name(str->type), g_server_cna_array[i]);
			cnt++;
		}
	}
	return cnt;
}
EXPORT_SYMBOL(uvb_send);

static int convert_server_cna_str_to_u32_array(const char *server_cna)
{
    int server_cna_valid_num = 0, ret = 0;
    uint32_t server_cna_array[MAX_NODE_NUM] = {0};
    char *token;

    char *server_cna_copy = kstrdup(server_cna, GFP_KERNEL);
    if (!server_cna_copy) {
		pr_err("%s: kstrdup failed!\n", __func__);
		return -ENOMEM;
    }

    char *rest = server_cna_copy;

    while ((token = strsep(&rest, ";"))) {
		if (server_cna_valid_num >= MAX_NODE_NUM) {
			pr_err("Invalid format for server_cna: cna max num is %d, the current input server_cna exceeds %d nodes.\n", MAX_NODE_NUM, MAX_NODE_NUM);
			kfree(server_cna_copy);
			return -EINVAL;
		}
		if (*token != '\0') {
			ret = kstrtou32(token, 10, &server_cna_array[server_cna_valid_num]);
			if (ret < 0) {
				pr_err("Invalid format for server cna, str is %s\n", token);
				kfree(server_cna_copy);
				return -EINVAL;
			}
			if (server_cna_array[server_cna_valid_num] > CNA_MAX_VALUE) {
				pr_err("Found invalid cna (%s), it should not be greater than %d\n", token, CNA_MAX_VALUE);
				kfree(server_cna_copy);
				return -EINVAL;
			}
			++server_cna_valid_num;
		}
    }
    pr_info("server cna num is %d\n", server_cna_valid_num);

    kfree(server_cna_copy);

    // input server_cna is valid, start to update global variables such as g_server_cna_valid_num and g_server_cna_array
    g_server_cna_valid_num = server_cna_valid_num;
    for (int i = 0; i < g_server_cna_valid_num; i++) {
		g_server_cna_array[i] = server_cna_array[i];
    }
    return 0;
}

static ssize_t proc_uvb_server_cna_show(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
    return simple_read_from_buffer(buf, count, ppos, g_kbuf_server_cna, strlen(g_kbuf_server_cna));
}

static ssize_t proc_uvb_server_cna_write(struct file *file, const char __user *user_buf,
    size_t count, loff_t *ppos)
{
    int ret = 0;
    char server_cna_buf[(MAX_NODE_NUM + 1) * INTEGER_TO_STR_MAX_LEN] = {0};

    if (count > (MAX_NODE_NUM + 1) * INTEGER_TO_STR_MAX_LEN - 1) {
		pr_err("invalid value for server_cna mode.\n");
		return -EINVAL;
    }
    if (copy_from_user(server_cna_buf, user_buf, count)) {
		pr_err("failed parse client info input: copy_from_user failed.\n");
		return -EFAULT;
    }
    server_cna_buf[count] = '\0';
    pr_info("proc_uvb_server_cna_write server_cna is %s\n", server_cna_buf);

    ret = convert_server_cna_str_to_u32_array(server_cna_buf);
    if (ret) {
		pr_err("convert_server_cna_str_to_u32_array failed\n");
		return -EINVAL;
    }
    snprintf(g_kbuf_server_cna, (MAX_NODE_NUM + 1) * INTEGER_TO_STR_MAX_LEN, "%s", server_cna_buf);
    return count;
}

static const struct proc_ops proc_uvb_server_cna_file_operations = {
    .proc_read = proc_uvb_server_cna_show,
    .proc_write = proc_uvb_server_cna_write,
};

static int __init uvb_comm_init(void)
{
    int ret = 0;

    for (int i = 0; i < MAX_NODE_NUM; i++) {
		g_server_cna_array[i] = (uint32_t)-1;
    }

    uvb_proc_dir = proc_mkdir_mode("sentry_uvb_comm", PROC_DIR_PERMISSION, NULL);
    if (!uvb_proc_dir) {
		pr_err("create /proc/sentry_uvb_comm dir failed.\n");
		return -ENOMEM;
    }

    ret = sentry_create_proc_file("server_cna", uvb_proc_dir, &proc_uvb_server_cna_file_operations);
    if (ret == -ENOMEM) {
		goto remove_uvb_proc_dir;
    }

    g_kbuf_server_cna = kzalloc((MAX_NODE_NUM + 1) * INTEGER_TO_STR_MAX_LEN, GFP_KERNEL);
    if (!g_kbuf_server_cna) {
		pr_err("kzalloc g_kbuf_server_cna failed!\n");
		ret = -ENOMEM;
		goto remove_uvb_proc_dir;
    }
    pr_info("uvb communication is enabled.\n");
    return 0;

remove_uvb_proc_dir:
    proc_remove(uvb_proc_dir);
    return ret;
}

static void __exit uvb_comm_exit(void)
{
    if (uvb_proc_dir) {
		proc_remove(uvb_proc_dir);
    }
    if (g_kbuf_server_cna) {
		kfree(g_kbuf_server_cna);
		g_kbuf_server_cna = NULL;
    }
    pr_info("uvb communication module unloaded\n");
}

module_init(uvb_comm_init);
module_exit(uvb_comm_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("sxt1001");
MODULE_DESCRIPTION("Kernel module to send msg via UVB");
