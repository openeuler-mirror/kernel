/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_nictool.c
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": [COMM]" fmt

#include <net/sock.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/interrupt.h>

#include "comm_defs.h"
#include "ossl_knl.h"
#include "mpu_inband_cmd.h"
#include "hinic5_mt.h"
#include "hinic5_crm.h"
#include "hinic5_hw.h"
#include "hinic5_hw_cfg.h"
#include "hinic5_hwdev.h"
#include "hinic5_lld.h"
#include "hinic5_lld_inner.h"
#include "hinic5_hw_mt.h"
#include "hinic5_dev_mgmt.h"
#include "hinic5_wq.h"
#include "sdk_pub_cmd.h"
#include "hisec_pub_cmd.h"
#include "hinic5_comm_cmd.h"
#include "hinic5_cmdq.h"
#include "hinic5_sdk_attack.h"
#include "hinic5_nictool.h"

static int g_nictool_ref_cnt;

static dev_t g_dev_id = {0};
static struct class *g_nictool_class;
static struct cdev g_nictool_cdev;

#define HINIC5_MAX_BUF_SIZE (2048 * 1024)
#define HINIC5_S_TO_US_UNIT 1000000

void *hinic5_g_card_node_array[MAX_CARD_NUM] = {0};
void *hinic5_g_card_vir_addr[MAX_CARD_NUM] = {0};
u64 hinic5_g_card_phy_addr[MAX_CARD_NUM] = {0};
int hinic5_card_id;

#ifdef __HIFC__
#define HIADM3_DEV_PATH		"/dev/hifc_dev"
#define HIADM3_DEV_CLASS	"hifc_class"
#define HIADM3_DEV_NAME		"hifc_dev"
#else
#define HIADM3_DEV_PATH		"/dev/hinic5_nictool_dev"
#define HIADM3_DEV_CLASS	"hinic5_nictool_class"
#define HIADM3_DEV_NAME		"hinic5_nictool_dev"
#endif

typedef int (*hw_driv_module)(struct hinic5_lld_dev *lld_dev,
			      const void *buf_in, u32 in_size, void *buf_out, u32 *out_size);
struct hw_drv_module_handle {
	u32	driv_cmd_name;
	hw_driv_module		driv_func;
};

static bool check_cmd_compatible(u32 in_size, u32 expect_in_size,
				 u32 out_size, u32 expect_out_size)
{
	if (unlikely(in_size != expect_in_size)) {
		pr_err("Incompatible hw driver cmd, in size %u, expect %u\n",
		       in_size, expect_in_size);
		return false;
	}

	if (unlikely(out_size != expect_out_size)) {
		pr_err("Incompatible hw driver cmd, out size %u, expect %u\n",
		       out_size, expect_out_size);
		return false;
	}

	return true;
}

static int get_single_card_info(struct hinic5_lld_dev *lld_dev, const void *buf_in,
				u32 in_size, void *buf_out, u32 *out_size)
{
	if (!buf_in || in_size != sizeof(struct card_info)) {
		pr_err("buf_in is NULL, or in_size(%u) != expect_in_size(%lu)\n",
		       in_size, sizeof(struct card_info));
		return -EINVAL;
	}

	if (!buf_out || *out_size != sizeof(struct card_info)) {
		pr_err("buf_out is NULL, or out_size(%u) != expect_out_size(%lu)\n",
		       *out_size, sizeof(struct card_info));
		return -EINVAL;
	}

	hinic5_get_card_info(hinic5_get_sdk_hwdev_by_lld(lld_dev), buf_in, buf_out);

	return 0;
}

static int is_driver_in_vm(struct hinic5_lld_dev *lld_dev, const void *buf_in, u32 in_size,
			   void *buf_out, u32 *out_size)
{
	bool in_host = false;

	if (!buf_out || (*out_size != sizeof(u8))) {
		pr_err("buf_out is NULL, or out_size != %lu\n", sizeof(u8));
		return -EINVAL;
	}

	in_host = hinic5_is_in_host();
	if (in_host)
		*((u8 *)buf_out) = 0;
	else
		*((u8 *)buf_out) = 1;

	return 0;
}

static int get_all_chip_id_cmd(struct hinic5_lld_dev *lld_dev, const void *buf_in, u32 in_size,
			       void *buf_out, u32 *out_size)
{
	if (*out_size != sizeof(struct nic_card_id) || !buf_out) {
		pr_err("Invalid parameter: out_buf_size %u, expect %lu\n",
		       *out_size, sizeof(struct nic_card_id));
		return -EFAULT;
	}

	hinic5_get_all_chip_id(buf_out);

	return 0;
}

static int get_card_usr_api_chain_mem(int card_idx)
{
	void *tmp = NULL;
	int i;

	hinic5_card_id = card_idx;
	if (!hinic5_g_card_vir_addr[card_idx]) {
		hinic5_g_card_vir_addr[card_idx] =
			(void *)(uintptr_t)__get_free_pages(GFP_KERNEL,
						 DBGTOOL_PAGE_ORDER);
		if (!hinic5_g_card_vir_addr[card_idx]) {
			pr_err("Alloc api chain memory fail for card %d!\n", card_idx);
			return -EFAULT;
		}

		memset(hinic5_g_card_vir_addr[card_idx], 0,
		       PAGE_SIZE * (1 << DBGTOOL_PAGE_ORDER));

		hinic5_g_card_phy_addr[card_idx] =
			virt_to_phys(hinic5_g_card_vir_addr[card_idx]);
		if (hinic5_g_card_phy_addr[card_idx] == 0) {
			pr_err("phy addr for card %d is 0\n", card_idx);
			free_pages((unsigned long)(uintptr_t)hinic5_g_card_vir_addr[card_idx],
				   DBGTOOL_PAGE_ORDER);
			hinic5_g_card_vir_addr[card_idx] = NULL;
			return -EFAULT;
		}

		tmp = hinic5_g_card_vir_addr[card_idx];
		for (i = 0; i < (1 << DBGTOOL_PAGE_ORDER); i++) {
			SetPageReserved(virt_to_page(tmp));
			tmp += PAGE_SIZE;
		}
	}

	return 0;
}

static void dbgtool_knl_free_mem(u32 id)
{
	void *tmp = NULL;
	int i;

	if (!hinic5_g_card_vir_addr[id])
		return;

	tmp = hinic5_g_card_vir_addr[id];
	for (i = 0; i < (1 << DBGTOOL_PAGE_ORDER); i++) {
		ClearPageReserved(virt_to_page(tmp));
		tmp += PAGE_SIZE;
	}

	free_pages((unsigned long)(uintptr_t)hinic5_g_card_vir_addr[id], DBGTOOL_PAGE_ORDER);
	hinic5_g_card_vir_addr[id] = NULL;
	hinic5_g_card_phy_addr[id] = 0;
}

static int card_info_param_valid(const char *dev_name, const void *buf_out,
				 u32 buf_out_size, int *id)
{
	int err;

	if (!buf_out || buf_out_size != sizeof(struct hinic5_card_func_info)) {
		pr_err("Invalid parameter: out_buf_size %u, expect %lu\n",
		       buf_out_size, sizeof(struct hinic5_card_func_info));
		return -EINVAL;
	}

	err = memcmp(dev_name, HINIC5_CHIP_NAME, strlen(HINIC5_CHIP_NAME));
	if (err != 0) {
		pr_err("Invalid chip name %s\n", dev_name);
		return err;
	}

	err = sscanf(dev_name, HINIC5_CHIP_NAME "%d", id);
	if (err != 1) {
		pr_err("Failed to get card id\n");
		return err;
	}

	if (*id >= MAX_CARD_NUM || *id < 0) {
		pr_err("chip id %d exceed limit[0-%d]\n",
		       *id, MAX_CARD_NUM - 1);
		return -EINVAL;
	}

	return 0;
}

static void hinic5_get_card_func_info_by_card_name(const char *chip_name,
						   struct hinic5_card_func_info *card_func)
{
	struct list_head *chip_list = get_hinic5_chip_list();
	struct card_node *chip_node = NULL;
	struct func_dev_info *dev_info = NULL;
	struct hinic5_adev *adev = NULL;

	card_func->num_pf = 0;

	hinic5_lld_hold();

	list_for_each_entry(chip_node, chip_list, node) {
		if (strncmp(chip_node->chip_name, chip_name, IFNAMSIZ) != 0)
			continue;

		list_for_each_entry(adev, &chip_node->func_list, node) {
			if (hinic5_func_type(adev->hwdev) == TYPE_VF)
				continue;

			dev_info = &card_func->dev_info[card_func->num_pf];
			dev_info->bar1_size = adev->cfg_base_len;
			dev_info->bar1_phy_addr = adev->cfg_base_phy;

			dev_info->bar3_size = adev->mgmt_base_len;
			dev_info->bar3_phy_addr = adev->mgmt_base_phy;

			card_func->num_pf++;
			if (card_func->num_pf >= CARD_MAX_SIZE) {
				hinic5_lld_put();
				return;
			}
		}
	}

	hinic5_lld_put();
}

static int get_card_func_info(struct hinic5_lld_dev *lld_dev, const void *buf_in, u32 in_size,
			      void *buf_out, u32 *out_size)
{
	struct hinic5_card_func_info *card_func_info = buf_out;
	struct card_node *card_info = hinic5_get_chip_node_by_lld(lld_dev);
	int err, id = 0;

	err = card_info_param_valid(card_info->chip_name, buf_out, *out_size, &id);
	if (err != 0)
		return err;

	hinic5_get_card_func_info_by_card_name(card_info->chip_name, card_func_info);

	if (card_func_info->num_pf == 0) {
		pr_err("None function found for %s\n", card_info->chip_name);
		return -EFAULT;
	}

	err = get_card_usr_api_chain_mem(id);
	if (err != 0) {
		pr_err("Faile to get api chain memory for userspace %s\n",
		       card_info->chip_name);
		return -EFAULT;
	}

	card_func_info->usr_api_phy_addr = hinic5_g_card_phy_addr[id];

	return 0;
}

static int get_pf_cap_info(struct hinic5_lld_dev *lld_dev, const void *buf_in, u32 in_size,
			   void *buf_out, u32 *out_size)
{
	struct service_cap *func_cap = NULL;
	struct hinic5_hwdev *hwdev = NULL;
	struct card_node *card_info = hinic5_get_chip_node_by_lld(lld_dev);
	struct svc_cap_info *svc_cap_info_in = (struct svc_cap_info *)buf_in;
	struct svc_cap_info *svc_cap_info_out = (struct svc_cap_info *)buf_out;

	if (*out_size != sizeof(struct svc_cap_info) || in_size != sizeof(struct svc_cap_info) ||
	    !buf_in || !buf_out) {
		pr_err("Invalid parameter: out_buf_size %u, in_size: %u, expect %lu\n",
		       *out_size, in_size, sizeof(struct svc_cap_info));
		return -EINVAL;
	}

	if (svc_cap_info_in->func_idx >= MAX_FUNCTION_NUM) {
		pr_err("func_idx is illegal. func_idx: %u, max_num: %u\n",
		       svc_cap_info_in->func_idx, MAX_FUNCTION_NUM);
		return -EINVAL;
	}

	hinic5_lld_hold();
	hwdev = (struct hinic5_hwdev *)(card_info->func_handle_array)[svc_cap_info_in->func_idx];
	if (!hwdev) {
		hinic5_lld_put();
		return -EINVAL;
	}

	func_cap = &hwdev->cfg_mgmt->svc_cap;
	memcpy(&svc_cap_info_out->cap, func_cap, sizeof(struct service_cap));
	hinic5_lld_put();

	return 0;
}

static int get_hw_drv_version(struct hinic5_lld_dev *lld_dev, const void *buf_in, u32 in_size,
			      void *buf_out, u32 *out_size)
{
	struct drv_version_info *ver_info = buf_out;
	int err;

	if (!buf_out) {
		pr_err("Buf_out is NULL.\n");
		return -EINVAL;
	}

	if (*out_size != sizeof(*ver_info)) {
		pr_err("Unexpect out buf size from user :%u, expect: %lu\n",
		       *out_size, sizeof(*ver_info));
		return -EINVAL;
	}

	err = snprintf(ver_info->ver, sizeof(ver_info->ver), "%s  %s",
		       HINIC5_DRV_VERSION, "2026-05-20_00:00:00");
	if (err < 0)
		return -EINVAL;

	return 0;
}

static int get_pf_id(struct hinic5_lld_dev *lld_dev, const void *buf_in, u32 in_size,
		     void *buf_out, u32 *out_size)
{
	struct hinic5_pf_info *pf_info = NULL;
	struct card_node *chip_node = hinic5_get_chip_node_by_lld(lld_dev);
	u32 port_id;
	int err;

	if (!chip_node)
		return -ENODEV;

	if (!buf_out || (*out_size != sizeof(*pf_info)) || !buf_in || in_size != sizeof(u32)) {
		pr_err("Unexpect out buf size from user :%u, expect: %lu, in size:%u\n",
		       *out_size, sizeof(*pf_info), in_size);
		return -EINVAL;
	}

	port_id = *((u32 *)buf_in);
	pf_info = (struct hinic5_pf_info *)buf_out;
	err = hinic5_get_pf_id(chip_node, port_id, &pf_info->pf_id, &pf_info->isvalid);
	if (err != 0)
		return err;

	*out_size = sizeof(*pf_info);

	return 0;
}

#ifdef CONFIG_HINIC5_SDK_DEBUG
static int set_frequency_reduction_ratio(struct hinic5_lld_dev *lld_dev, const void *buf_in,
					 u32 in_size, void *buf_out, u32 *out_size)
{
	u32 ratio;
	int err;

	if (!buf_in || in_size != sizeof(u32)) {
		pr_err("Unexpect out buf size from user in size:%u\n", in_size);
		return -EINVAL;
	}

	ratio = *((u32 *)buf_in);
	err = hinic5_set_freq_reduce_ratio(lld_dev->hwdev, ratio);
	if (err != 0) {
		pr_err("set freq reduce ratio err %d\n", err);
		return err;
	}

	return 0;
}

static int set_time_diff_enable(struct hinic5_lld_dev *lld_dev, const void *buf_in, u32 in_size,
				void *buf_out, u32 *out_size)
{
	u32 enable;
	int err;

	if (!lld_dev || !buf_in || in_size != sizeof(u32)) {
		pr_err("Unexpect out buf size from user in size:%u\n", in_size);
		return -EINVAL;
	}

	enable = *((u32 *)buf_in);
	err = hinic5_set_non_ptp_time_diff_en(lld_dev->hwdev, enable);
	if (err != 0) {
		pr_err("set time diff enable err %d\n", err);
		return err;
	}

	return 0;
}

static int get_time_diff(struct hinic5_lld_dev *lld_dev, const void *buf_in, u32 in_size,
			 void *buf_out, u32 *out_size)
{
	int err;

	if (!lld_dev || !buf_out) {
		pr_err("Unexpect out buf size from user in size:%u\n", in_size);
		return -EINVAL;
	}

	err = hinic5_get_non_ptp_time_diff(lld_dev->hwdev, (s64 *)buf_out);
	if (err != 0) {
		pr_err("get time diff err %d\n", err);
		return err;
	}
	*out_size = sizeof(s64);
	return 0;
}
#endif

static int get_cmdq_info(struct hinic5_lld_dev *lld_dev, const void *buf_in, u32 in_size,
			 void *buf_out, u32 *out_size)
{
	u16 cmdq_id;

	if (!check_cmd_compatible(in_size, sizeof(u32),
				  *out_size, sizeof(struct hinic5_wq)))
		return -EINVAL;

	cmdq_id = (u16)(*((u32 *)buf_in));
	return hinic5_dump_cmdq_wq(lld_dev->hwdev, cmdq_id, buf_out);
}

typedef struct tag_cmdq_npu_dft {
	u32 type;
	u32 value;
	u32 rsvd0;
	u32 rsvd1;
} cmdq_npu_dft_s;

#ifdef CONFIG_HINIC5_SDK_DEBUG
static int detect_cmdq_channel(struct hinic5_lld_dev *lld_dev,
			       const void *buf_in, u32 in_size, void *buf_out,
			       u32 *out_size)
{
	struct hinic5_adev *adev = to_hinic5_adev(lld_dev);
	struct hinic5_cmd_buf *cmd_buf = NULL;
	int err;
	u16 cmdq_id;
	u64 out_param;
	cmdq_npu_dft_s *cmdq_info = NULL;

	if (!buf_in || !buf_out || !out_size) {
		sdk_err(adev->dev, "Buf_in or buf_out or out_size is NULL.\n");
		return -EINVAL;
	}

	if (in_size != sizeof(u32)) {
		sdk_err(adev->dev, "Unexpect in buf size from user :%u, expect: %lu\n",
			in_size, sizeof(u32));
		return -EINVAL;
	}

	if (*out_size != sizeof(u32)) {
		sdk_err(adev->dev, "Unexpect out buf size from user :%u, expect: %lu\n",
			*out_size, sizeof(struct hinic5_wq));
		return -EINVAL;
	}

	cmdq_id = (u16)(*((u32 *)buf_in));

	sdk_info(adev->dev, "debug: cmdq detect q_id=%d\n", cmdq_id);

	cmd_buf = hinic5_alloc_cmd_buf(adev->hwdev);
	if (!cmd_buf) {
		sdk_err(adev->hwdev, "Failed to allocate cmd buf\n");
		return -ENOMEM;
	}

	/* Use dft_npu test command type = DFT_CMDQ_TYPE_NPU_CHANNEL_TEST,
	 * value = DFT_CMDQ_VALUE_CHANNEL_TEST_LOG for connectivity test
	 */
	cmd_buf->size = sizeof(cmdq_npu_dft_s);
	cmdq_info = (cmdq_npu_dft_s *)cmd_buf->buf;
	cmdq_info->type = 0;
	cmdq_info->value = 0;
	hinic5_cpu_to_be32(cmd_buf->buf, cmd_buf->size);

	err = hinic5_cos_id_direct_resp
		(adev->hwdev, HINIC5_MOD_COMM, COMM_CMD_SEND_NPU_DFT_CMD, cmdq_id, cmd_buf,
		 &out_param, 0, HINIC5_CHANNEL_COMM);
	if (err != 0 || out_param != 0) {
		sdk_err(adev->dev, "Failed to send cmdq channel detect\n");
		err = -EFAULT;
	}

	hinic5_free_cmd_buf(adev->hwdev, cmd_buf);

	*(u32 *)buf_out = 0;
	*out_size = sizeof(u32);

	return err;
}
#endif

static int get_cmdq_wqe_desc(struct hinic5_lld_dev *lld_dev, const void *buf_in, u32 in_size,
			     void *buf_out, u32 *out_size)
{
	const struct cmdq_wqe_info *info = buf_in;

	if (!check_cmd_compatible(in_size, sizeof(struct cmdq_wqe_info),
				  *out_size, sizeof(struct sdk_cmdq_wqe_desc)))
		return -EINVAL;

	return hinic5_dump_cmdq_wqebb(lld_dev->hwdev,
				      (u16)info->q_id, (u16)info->wqebb_id, buf_out);
}

/* not support fc yet */
static int get_mbox_cnt(struct hinic5_lld_dev *lld_dev, const void *buf_in,
			u32 in_size, void *buf_out, u32 *out_size)
{
	if (!buf_out) {
		pr_err("buf_out is NULL");
		return -EINVAL;
	}

	if (*out_size != sizeof(struct card_mbox_cnt_info)) {
		pr_err("out_size != %lu\n", sizeof(struct card_mbox_cnt_info));
		return -EINVAL;
	}

	hinic5_get_mbox_cnt(hinic5_get_sdk_hwdev_by_lld(lld_dev), buf_out);

	return 0;
}

struct hw_drv_module_handle hinic5_hw_driv_module_cmd_handle[] = {
	{FUNC_TYPE,		(hw_driv_module)hinic5_get_func_type},
	{GET_FUNC_IDX,		(hw_driv_module)hinic5_get_func_id},
	{GET_HW_STATS,		(hw_driv_module)hinic5_get_hw_driver_stats},
	{CLEAR_HW_STATS,	(hw_driv_module)hinic5_clear_hw_driver_stats},
	{GET_SELF_TEST_RES,	(hw_driv_module)hinic5_get_self_test_result},
	{GET_CHIP_FAULT_STATS,	(hw_driv_module)hinic5_get_chip_faults_stats},
	{GET_SINGLE_CARD_INFO,	(hw_driv_module)get_single_card_info},
	{IS_DRV_IN_VM,		is_driver_in_vm},
	{GET_CHIP_ID,		get_all_chip_id_cmd},
	{GET_CHIP_INFO,		get_card_func_info},
	{GET_FUNC_CAP,		get_pf_cap_info},
	{GET_DRV_VERSION,	get_hw_drv_version},
	{GET_PF_ID,		get_pf_id},
	{SDK_CMD_GET_CMDQ_INFO, get_cmdq_info},
	{SDK_CMD_GET_CMDQ_WQE_DESC, get_cmdq_wqe_desc},
	{GET_MBOX_CNT,      (hw_driv_module)get_mbox_cnt},
#ifdef CONFIG_HINIC5_SDK_DEBUG
	{SDK_CMD_CMDQ_CHANNEL_DETECT, detect_cmdq_channel},
	{SDK_CMD_SET_FREQ_REDUCE_RATIO, set_frequency_reduction_ratio},
	{SDK_CMD_SET_TIME_DIFF_ENABLE, set_time_diff_enable},
	{SDK_CMD_GET_TIME_DIFF, get_time_diff},
	{SDK_CMD_ATTACK_TEST, hinic5_sdk_attack_handler},
#endif
};

static int alloc_tmp_buf(void *hwdev, struct msg_module *nt_msg, u32 in_size,
			 void **buf_in, u32 out_size, void **buf_out)
{
	int ret;

	ret = hinic5_alloc_buff_in(hwdev, nt_msg, in_size, buf_in);
	if (ret != 0) {
		pr_err("Alloc tool cmd buff in failed\n");
		return ret;
	}

	ret = hinic5_alloc_buff_out(hwdev, nt_msg, out_size, buf_out);
	if (ret != 0) {
		pr_err("Alloc tool cmd buff out failed\n");
		goto out_free_buf_in;
	}

	return 0;

out_free_buf_in:
	hinic5_free_buff_in(hwdev, nt_msg, *buf_in);

	return ret;
}

static void free_tmp_buf(void *hwdev, struct msg_module *nt_msg,
			 void *buf_in, void *buf_out)
{
	hinic5_free_buff_out(hwdev, nt_msg, buf_out);
	hinic5_free_buff_in(hwdev, nt_msg, buf_in);
}

__weak int hinic5_nictool_cmd_extend_handle(void *lld_dev, u32 cmd,
					    struct hinic5_mt_msg *mt_msg, bool *support)
{
	*support = false;

	return 0;
}

static int send_to_hw_driver(struct hinic5_lld_dev *lld_dev, struct msg_module *nt_msg,
			     const void *buf_in, u32 in_size, void *buf_out, u32 *out_size)
{
	int index, num_cmds = (int)(sizeof(hinic5_hw_driv_module_cmd_handle) /
				sizeof(hinic5_hw_driv_module_cmd_handle[0]));
	enum driver_cmd_type cmd_type =
				(enum driver_cmd_type)(nt_msg->msg_formate);
	struct hinic5_mt_msg mt_msg;
	bool support = false;
	int err = 0;

	for (index = 0; index < num_cmds; index++) {
		if (cmd_type != hinic5_hw_driv_module_cmd_handle[index].driv_cmd_name)
			continue;
		err = hinic5_hw_driv_module_cmd_handle[index].driv_func
				(lld_dev, buf_in, in_size, buf_out, out_size);
		if (err != 0)
			pr_err("Hw driver cmd %u process failed, err %d\n", cmd_type, err);
		return err;
	}

	mt_msg.buf_in = buf_in;
	mt_msg.buf_out = buf_out;
	mt_msg.in_size = in_size;
	mt_msg.out_size = *out_size;
	err = hinic5_nictool_cmd_extend_handle((void *)lld_dev, (u32)cmd_type, &mt_msg, &support);
	if (!support) {
		pr_err("Can't find callback for %d\n", cmd_type);
		return -EINVAL;
	}

	if (err != 0)
		pr_err("extend cmd %d process failed, err:%d\n", cmd_type, err);
	*out_size = mt_msg.out_size;

	return err;
}

static int send_to_service_driver(struct hinic5_lld_dev *lld_dev, struct msg_module *nt_msg,
				  const void *buf_in, u32 in_size, void *buf_out, u32 *out_size)
{
	const struct hinic5_uld_info *uld_info = NULL;
	const char **service_name = NULL;
	enum hinic5_service_type type;
	void *uld_dev = NULL;
	int ret = -EINVAL;

	service_name = hinic5_get_uld_names();
	type = nt_msg->module - SEND_TO_SRV_DRV_BASE;
	if (type >= SERVICE_T_MAX) {
		pr_err("Ioctl input module id: %u is incorrectly\n", nt_msg->module);
		return -EINVAL;
	}

	uld_dev = hinic5_get_uld_dev(lld_dev, type);
	if (!uld_dev) {
		if (nt_msg->msg_formate == GET_DRV_VERSION)
			return 0;

		pr_err("Can not get the uld dev correctly: %s driver may be not register\n",
		       service_name[type]);
		return -EINVAL;
	}

	uld_info = hinic5_get_uld_info_by_type(type);
	if (!uld_info || !uld_info->ioctl)
		return -EFAULT;

	ret = uld_info->ioctl(uld_dev, nt_msg->msg_formate,
						buf_in, in_size, buf_out, out_size);
	hinic5_uld_dev_put(lld_dev, type);

	return ret;
}

static int nictool_exec_cmd(struct hinic5_lld_dev *lld_dev, struct msg_module *nt_msg,
			    void *buf_in, u32 in_size, void *buf_out, u32 *out_size)
{
	int ret = 0;

	switch (nt_msg->module) {
	case SEND_TO_HW_DRIVER:
		ret = send_to_hw_driver(lld_dev, nt_msg, buf_in, in_size, buf_out, out_size);
		break;
	case SEND_TO_MPU:
		ret = hinic5_send_to_mpu(hinic5_get_sdk_hwdev_by_lld(lld_dev),
				  nt_msg, buf_in, in_size, buf_out, out_size);
		break;
	case SEND_TO_SM:
		ret = hinic5_send_to_sm(hinic5_get_sdk_hwdev_by_lld(lld_dev),
				 nt_msg, buf_in, in_size, buf_out, out_size);
		break;
	case SEND_TO_NPU:
		ret = hinic5_send_to_npu(hinic5_get_sdk_hwdev_by_lld(lld_dev),
				  nt_msg, buf_in, in_size, buf_out, out_size);
		break;
	default:
		ret = send_to_service_driver(lld_dev, nt_msg, buf_in, in_size, buf_out, out_size);
		break;
	}

	return ret;
}

static int cmd_parameter_valid(struct msg_module *nt_msg, ulong arg,
			       u32 *out_size_expect, u32 *in_size)
{
	if (copy_from_user(nt_msg, (void *)(uintptr_t)arg, sizeof(*nt_msg)) != 0) {
		pr_err("Copy information from user failed\n");
		return -EFAULT;
	}

	*out_size_expect = nt_msg->buf_out_size;
	*in_size = nt_msg->buf_in_size;
	if (*out_size_expect > HINIC5_MAX_BUF_SIZE ||
	    *in_size > HINIC5_MAX_BUF_SIZE) {
		pr_err("Invalid in size: %u or out size: %u\n",
		       *in_size, *out_size_expect);
		return -EFAULT;
	}

	nt_msg->device_name[IFNAMSIZ - 1] = '\0';

	return 0;
}

static inline bool is_send_to_srv_drv(uint32_t module)
{
	return ((module >= SEND_TO_SRV_DRV_BASE) && (module < SEND_TO_DRIVER_MAX));
}

#define ROCE_DRV_SCC_CMD_MIN (SERVICE_DRV_BASE_CMD + 1)
#define ROCE_DRV_SCC_CMD_MAX (SERVICE_DRV_BASE_CMD + 4)

struct hinic5_lld_dev *get_lld_dev_by_nt_msg(struct msg_module *nt_msg)
{
	struct hinic5_lld_dev *lld_dev = NULL;
	enum mt_api_type api_type;
	u8 mod = 0;
	u16 cmd = 0;

	if (nt_msg->module == SEND_TO_MPU) {
		api_type = (enum mt_api_type)nt_msg->mpu_cmd.api_type;
		mod = nt_msg->mpu_cmd.mod;
		cmd = nt_msg->mpu_cmd.cmd;

		if (api_type == API_TYPE_MBOX && mod == HINIC5_MOD_COMM &&
		    (cmd == COMM_MGMT_CMD_UPDATE_FW || cmd == COMM_MGMT_CMD_ACTIVE_FW ||
		     cmd == COMM_MGMT_CMD_HOT_ACTIVE_FW)) {
			lld_dev = hinic5_get_lld_dev_with_l3i_enabled(nt_msg->device_name);
			if (lld_dev)
				return lld_dev;
		}
	}

	if (nt_msg->module == SEND_TO_NIC_DRIVER &&
	    (nt_msg->msg_formate == GET_XSFP_INFO || nt_msg->msg_formate == GET_XSFP_PRESENT ||
	     nt_msg->msg_formate == GET_XSFP_INFO_COMP_CMIS)) {
		return hinic5_get_lld_dev_by_chip_and_port(nt_msg->device_name, nt_msg->port_id);
	}

	if (nt_msg->module == SEND_TO_HIHTR_DRIVER &&
	    (nt_msg->msg_formate == ROCE_CMD_SET_BYPASS ||
	    nt_msg->msg_formate == ROCE_CMD_QUERY_BYPASS)) {
		return hinic5_get_lld_dev_by_chip_name(nt_msg->device_name);
	}

	if (nt_msg->module == SEND_TO_HIHTR_DRIVER &&
	    (nt_msg->msg_formate >= ROCE_DRV_SCC_CMD_MIN &&
	    nt_msg->msg_formate <= ROCE_DRV_SCC_CMD_MAX)) {
		return hinic5_get_lld_dev_by_chip_name(nt_msg->device_name);
	}

	if (nt_msg->module == SEND_TO_CUSTOM_DRIVER)
		return hinic5_get_lld_dev_by_chip_name(nt_msg->device_name);

	if (nt_msg->module == SEND_TO_BIFUR_DRIVER) {
		lld_dev = hinic5_get_lld_dev_by_chip_name(nt_msg->device_name);
		if (!lld_dev)
			lld_dev =
				hinic5_get_lld_dev_by_dev_name(nt_msg->device_name, SERVICE_T_NIC);
		return lld_dev;
	}

	if (nt_msg->module == SEND_TO_IPSEC_DRIVER &&
	    (nt_msg->msg_formate == HISEC_DRIVER_CMD_GET_TRNG ||
	    nt_msg->msg_formate == HISEC_DRIVER_CMD_GET_IPSEC_INFO)) {
		return hinic5_get_lld_dev_by_chip_name(nt_msg->device_name);
	}

	if (is_send_to_srv_drv(nt_msg->module) && nt_msg->msg_formate != GET_DRV_VERSION) {
		lld_dev = hinic5_get_lld_dev_by_dev_name(nt_msg->device_name,
							 nt_msg->module - SEND_TO_SRV_DRV_BASE);
		if (!lld_dev)
			lld_dev = hinic5_get_lld_dev_by_chip_name(nt_msg->device_name);
		return lld_dev;
	}

	/* Support sdk sending dfx commands by specifying function id */
	if (nt_msg->module == SEND_TO_HW_DRIVER && nt_msg->use_func_idx == 1)
		return hinic5_get_lld_dev_by_func_id(nt_msg->device_name, nt_msg->func_idx);

	lld_dev = hinic5_get_lld_dev_by_chip_name(nt_msg->device_name);
	if (!lld_dev)
		lld_dev = hinic5_get_lld_dev_by_dev_name(nt_msg->device_name, SERVICE_T_MAX);

	return lld_dev;
}

static long hinicadm_k_unlocked_ioctl(struct file *pfile, ulong arg)
{
	struct hinic5_lld_dev *lld_dev = NULL;
	struct msg_module nt_msg;
	void *buf_out = NULL;
	void *buf_in = NULL;
	u32 out_size_expect = 0;
	u32 out_size = 0;
	u32 in_size = 0;
	int ret = 0;

	memset(&nt_msg, 0, sizeof(nt_msg));
	if (cmd_parameter_valid(&nt_msg, arg, &out_size_expect, &in_size) != 0)
		return -EFAULT;

	lld_dev = get_lld_dev_by_nt_msg(&nt_msg);
	if (!lld_dev) {
		if (nt_msg.msg_formate != DEV_NAME_TEST)
			pr_err("Can not find device %s for module %u\n",
			       nt_msg.device_name, nt_msg.module);

		return -ENODEV;
	}

	if (nt_msg.msg_formate == DEV_NAME_TEST) {
		hinic5_lld_dev_put(lld_dev);
		return 0;
	}

	ret = alloc_tmp_buf(hinic5_get_sdk_hwdev_by_lld(lld_dev), &nt_msg,
			    in_size, &buf_in, out_size_expect, &buf_out);
	if (ret != 0) {
		pr_err("Alloc tmp buff failed\n");
		goto out_free_lock;
	}

	out_size = out_size_expect;

	ret = nictool_exec_cmd(lld_dev, &nt_msg, buf_in, in_size, buf_out, &out_size);
	if (ret != 0) {
		pr_err("nictool_exec_cmd failed, module: %u, ret: %d.\n", nt_msg.module, ret);
		goto out_free_buf;
	}

	if (out_size > out_size_expect) {
		ret = -EFAULT;
		pr_err("Out size is greater than expected out size from user: %u, out size: %u\n",
		       out_size_expect, out_size);
		goto out_free_buf;
	}

	ret = hinic5_copy_buf_out_to_user(&nt_msg, out_size, buf_out);
	if (ret != 0)
		pr_err("Copy information to user failed\n");

out_free_buf:
	free_tmp_buf(hinic5_get_sdk_hwdev_by_lld(lld_dev), &nt_msg, buf_in, buf_out);

out_free_lock:
	hinic5_lld_dev_put(lld_dev);
	return (long)ret;
}

/**
 * dbgtool_knl_ffm_info_rd - Read ffm information
 * @para: the dbgtool parameter
 * @dbgtool_info: the dbgtool info
 **/
static int dbgtool_knl_ffm_info_rd(struct dbgtool_param *para,
				   struct dbgtool_k_glb_info *dbgtool_info)
{
	if (!para->param.ffm_rd || !dbgtool_info->ffm)
		return -EINVAL;

	/* Copy the ffm_info to user mode */
	if (copy_to_user(para->param.ffm_rd, dbgtool_info->ffm,
			 (unsigned int)sizeof(struct ffm_record_info)) != 0) {
		pr_err("Copy ffm_info to user fail\n");
		return -EFAULT;
	}

	return 0;
}

static long dbgtool_k_unlocked_ioctl(struct file *pfile,
				     unsigned int real_cmd, ulong arg)
{
	int ret;
	struct dbgtool_param param;
	struct dbgtool_k_glb_info *dbgtool_info = NULL;
	struct card_node *card_info = NULL;
	int i;

	memset(&param, 0, sizeof(param));

	if (copy_from_user(&param, (void *)(uintptr_t)arg, sizeof(param)) != 0) {
		pr_err("Copy param from user fail\n");
		return -EFAULT;
	}

	hinic5_lld_hold();
	for (i = 0; i < MAX_CARD_NUM; i++) {
		card_info = (struct card_node *)hinic5_g_card_node_array[i];
		if (!card_info)
			continue;
		if (memcmp(param.chip_name, card_info->chip_name,
			   strlen(card_info->chip_name) + 1) == 0)
			break;
	}

	if (i == MAX_CARD_NUM || !card_info) {
		hinic5_lld_put();
		pr_err("Can't find this card %s\n", param.chip_name);
		return -EFAULT;
	}

	hinic5_card_id = i;
	dbgtool_info = (struct dbgtool_k_glb_info *)card_info->dbgtool_info;

	down(&dbgtool_info->dbgtool_sem);

	switch (real_cmd) {
	case DBGTOOL_CMD_FFM_RD:
		ret = dbgtool_knl_ffm_info_rd(&param, dbgtool_info);
		break;
	case DBGTOOL_CMD_MSG_2_UP:
		pr_err("Not suppose to use this cmd(0x%x).\n", real_cmd);
		ret = 0;
		break;
	default:
		pr_err("Dbgtool cmd(0x%x) not support now\n", real_cmd);
		ret = -EFAULT;
	}

	up(&dbgtool_info->dbgtool_sem);

	hinic5_lld_put();

	return (long)ret;
}

static int nictool_k_release(struct inode *pnode, struct file *pfile)
{
	return 0;
}

static int nictool_k_open(struct inode *pnode, struct file *pfile)
{
	return 0;
}

static ssize_t nictool_k_read(struct file *pfile, char __user *ubuf,
			      size_t size, loff_t *ppos)
{
	return 0;
}

static ssize_t nictool_k_write(struct file *pfile, const char __user *ubuf,
			       size_t size, loff_t *ppos)
{
	return 0;
}

static long nictool_k_unlocked_ioctl(struct file *pfile,
				     unsigned int cmd, unsigned long arg)
{
	unsigned int real_cmd;

	real_cmd = _IOC_NR(cmd);

	return (real_cmd == NICTOOL_CMD_TYPE) ?
		hinicadm_k_unlocked_ioctl(pfile, arg) :
		dbgtool_k_unlocked_ioctl(pfile, real_cmd, arg);
}

static int hinic5_bar_mmap_param_valid(phys_addr_t phy_addr, u64 vmsize)
{
	struct list_head *chip_list = get_hinic5_chip_list();
	struct card_node *chip_node = NULL;
	struct hinic5_adev *adev = NULL;

	hinic5_lld_hold();

	/* get PF bar1 or bar3 physical address to verify */
	list_for_each_entry(chip_node, chip_list, node) {
		list_for_each_entry(adev, &chip_node->func_list, node) {
			if (hinic5_func_type(adev->hwdev) == TYPE_VF)
				continue;

			if (((phy_addr >= adev->cfg_base_phy) &&
			     (phy_addr + vmsize <= (adev->cfg_base_phy + adev->cfg_base_len))) ||
			    ((phy_addr >= adev->mgmt_base_phy) &&
			     (phy_addr + vmsize <= (adev->mgmt_base_phy + adev->mgmt_base_len)))) {
				hinic5_lld_put();
				return 0;
			}
		}
	}

	hinic5_lld_put();
	return -EINVAL;
}

static int hinic5_mem_mmap(struct file *filp, struct vm_area_struct *vma)
{
	u64 vmsize = vma->vm_end - vma->vm_start;
	phys_addr_t offset = (phys_addr_t)vma->vm_pgoff << PAGE_SHIFT;
	phys_addr_t phy_addr;
	int err = 0;

	if (vmsize > (PAGE_SIZE * (1 << DBGTOOL_PAGE_ORDER))) {
		pr_err("Map size = %llu is bigger than alloc\n", vmsize);
		return -EAGAIN;
	}

	/* old version of tool set vma->vm_pgoff to 0 */
	phy_addr = (offset != 0) ? offset : hinic5_g_card_phy_addr[hinic5_card_id];

	/* check phy_addr valid */
	if (phy_addr != hinic5_g_card_phy_addr[hinic5_card_id]) {
		err = hinic5_bar_mmap_param_valid(phy_addr, vmsize);
		if (err != 0) {
			pr_err("mmap param invalid, err: %d\n", err);
			return err;
		}
	}

	/* Disable cache and write buffer in the mapping area */
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	if (remap_pfn_range(vma, vma->vm_start, (phy_addr >> PAGE_SHIFT),
			    vmsize, vma->vm_page_prot) != 0) {
		pr_err("Remap pfn range failed.\n");
		return -EAGAIN;
	}

	return 0;
}

static const struct file_operations fifo_operations = {
	.owner = THIS_MODULE,
	.release = nictool_k_release,
	.open = nictool_k_open,
	.read = nictool_k_read,
	.write = nictool_k_write,
	.unlocked_ioctl = nictool_k_unlocked_ioctl,
	.mmap = hinic5_mem_mmap,
};

static void free_dbgtool_info(void *hwdev, struct card_node *chip_info)
{
	struct dbgtool_k_glb_info *dbgtool_info = NULL;
	int err;
	u32 id;

	if (hinic5_func_type(hwdev) != TYPE_VF)
		chip_info->func_handle_array[hinic5_global_func_id(hwdev)] = NULL;

	if (chip_info->func_num == 0) {
		pr_err("dbgtool already free.\n");
		return;
	}

	--chip_info->func_num;
	if (chip_info->func_num > 0)
		return;

	err = sscanf(chip_info->chip_name, HINIC5_CHIP_NAME "%u", &id);
	if (err != 1)
		pr_err("Failed to get card id\n");

	if (id < MAX_CARD_NUM)
		hinic5_g_card_node_array[id] = NULL;

	dbgtool_info = chip_info->dbgtool_info;
	/* FFM deinit */
	kfree(dbgtool_info->ffm);
	dbgtool_info->ffm = NULL;

	kfree(dbgtool_info);
	chip_info->dbgtool_info = NULL;

	if (id < MAX_CARD_NUM)
		dbgtool_knl_free_mem(id);
}

static int alloc_dbgtool_info(void *hwdev, struct card_node *chip_info)
{
	struct dbgtool_k_glb_info *dbgtool_info = NULL;
	int err, id = 0;

	if (hinic5_func_type(hwdev) != TYPE_VF)
		chip_info->func_handle_array[hinic5_global_func_id(hwdev)] = hwdev;

	// Only the first function applies for dbgtool_info,
	// subsequent functions only need to increment reference count, no memory allocation needed
	if (chip_info->func_num != 0) {
		chip_info->func_num++;
		return 0;
	}

	chip_info->func_num++;
	dbgtool_info = (struct dbgtool_k_glb_info *)
			kzalloc(sizeof(struct dbgtool_k_glb_info), GFP_KERNEL);
	if (!dbgtool_info) {
		pr_err("Failed to allocate dbgtool_info\n");
		goto dbgtool_info_fail;
	}

	chip_info->dbgtool_info = dbgtool_info;

	/* FFM init */
	dbgtool_info->ffm = (struct ffm_record_info *)
			kzalloc(sizeof(struct ffm_record_info), GFP_KERNEL);
	if (!dbgtool_info->ffm) {
		pr_err("Failed to allocate cell contexts for a chain\n");
		goto dbgtool_info_ffm_fail;
	}

	sema_init(&dbgtool_info->dbgtool_sem, 1);

	err = sscanf(chip_info->chip_name, HINIC5_CHIP_NAME "%d", &id);
	if (err < 0) {
		pr_err("Failed to get card id\n");
		goto sscanf_chdev_fail;
	}

	hinic5_g_card_node_array[id] = chip_info;

	return 0;

sscanf_chdev_fail:
	kfree(dbgtool_info->ffm);

dbgtool_info_ffm_fail:
	kfree(dbgtool_info);
	chip_info->dbgtool_info = NULL;

dbgtool_info_fail:
	if (hinic5_func_type(hwdev) != TYPE_VF)
		chip_info->func_handle_array[hinic5_global_func_id(hwdev)] = NULL;
	chip_info->func_num--;
	return -ENOMEM;
}

/**
 * hinic5_nictool_k_init - initialize the hw interface
 **/
/* temp for dbgtool_info */
int hinic5_nictool_k_init(void *hwdev, void *chip_node)
{
	struct card_node *chip_info = (struct card_node *)chip_node;
	struct device *pdevice = NULL;
	int err;

	err = alloc_dbgtool_info(hwdev, chip_info);
	if (err != 0)
		return err;

	// Only the first function initializes and creates the character device, subsequent functions only need to increment reference count
	if (g_nictool_ref_cnt != 0) {
		/* already initialized */
		g_nictool_ref_cnt++;
		return 0;
	}

	g_nictool_ref_cnt++;
	err = alloc_chrdev_region(&g_dev_id, 0, 1, HIADM3_DEV_NAME);
	if (err != 0) {
		pr_err("Register nictool_dev failed(0x%x)\n", err);
		goto alloc_chdev_fail;
	}

	/* Create equipment */
	g_nictool_class = class_create(THIS_MODULE, HIADM3_DEV_CLASS);
	if (IS_ERR(g_nictool_class)) {
		pr_err("Create nictool_class fail\n");
		err = -EFAULT;
		goto class_create_err;
	}

	/* Initializing the character device */
	cdev_init(&g_nictool_cdev, &fifo_operations);

	/* Add devices to the operating system */
	err = cdev_add(&g_nictool_cdev, g_dev_id, 1);
	if (err < 0) {
		pr_err("Add nictool_dev to operating system fail(0x%x)\n", err);
		goto cdev_add_err;
	}

	/* Export device information to user space
	 * (/sys/class/class name/device name)
	 */
	pdevice = device_create(g_nictool_class, NULL,
				g_dev_id, NULL, HIADM3_DEV_NAME);
	if (IS_ERR(pdevice)) {
		pr_err("Export nictool device information to user space fail\n");
		err = -EFAULT;
		goto device_create_err;
	}

	pr_info("Register nictool_dev to system succeed\n");

	return 0;

device_create_err:
	cdev_del(&g_nictool_cdev);

cdev_add_err:
	class_destroy(g_nictool_class);

class_create_err:
	g_nictool_class = NULL;
	unregister_chrdev_region(g_dev_id, 1);

alloc_chdev_fail:
	g_nictool_ref_cnt--;
	free_dbgtool_info(hwdev, chip_info);

	return err;
}

void hinic5_nictool_k_uninit(void *hwdev, void *chip_node)
{
	struct card_node *chip_info = (struct card_node *)chip_node;

	free_dbgtool_info(hwdev, chip_info);

	if (g_nictool_ref_cnt == 0) {
		pr_err("Nictool Unregister.\n");
		return;
	}

	--g_nictool_ref_cnt;
	if (g_nictool_ref_cnt != 0)
		return;

	if (IS_ERR(g_nictool_class)) {
		pr_err("Nictool class is NULL.\n");
		return;
	}

	device_destroy(g_nictool_class, g_dev_id);
	cdev_del(&g_nictool_cdev);
	class_destroy(g_nictool_class);
	g_nictool_class = NULL;

	unregister_chrdev_region(g_dev_id, 1);

	pr_info("Unregister nictool_dev succeed\n");
}

