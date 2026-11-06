// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 *
 * Description: Report NL SSU link credit overtime error record to userspace
 *		via the GHES vendor record notifier.
 * Author: sxt1001
 * Create: 2026-10-28
 */

#include <linux/types.h>
#include <linux/bits.h>
#include <linux/sizes.h>
#include <linux/math.h>
#include <linux/kernel.h>
#include <linux/ktime.h>
#include <linux/limits.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/notifier.h>
#include <linux/compiler.h>
#include <linux/module.h>
#include <linux/init.h>
#include <acpi/ghes.h>

#include "../ubus/vendor/hisilicon/local-ras.h"
#include "smh_message.h"
#include "sentry_report_comm.h"
#include "sentry_local_ras.h"

#undef pr_fmt
#define pr_fmt(fmt) "[sentry][local_ras]: " fmt

#define LQC_MODULE_ERR_BIT	7
#define LQC_MODULE_ERR_MISC	1

/* Sub-module ID of the Nimbus-Lite (NL) port */
#define NL_PORT_MODULE_ID	0x4

/*
 * Platform match table, mirrored from the ubus vendor driver
 * (drivers/ub/ubus/vendor/hisilicon/local-ras.c).
 */
#define RAS_V1 BIT(0)
#define RAS_V2 BIT(1)

#define VALID_SOC_ID	(1U << 0)
#define VALID_VERSION	(1U << 1)
#define VALID_NIMBUS_ID	(1U << 2)
#define VALID_MODULE_ID	(1U << 3)

#define HIP12_VERSION 8
#define HIP12_SOC_ID 1
#define HIP12_UB_MODULE_ID 0x2d
#define HIP13A_VERSION 15 /* HP13A and HP13B's define may be changed later */
#define HIP13B_VERSION 16
#define HIP13_SOC_ID 1
#define HIP13_UB_MODULE_ID 0x2d
#define ASCEND950_UB_MODULE_ID 0x31
#define ASCEND950_VERSION 2
#define ASCEND950_SOC_ID 0x13
#define UNION_DIE 1
#define ZHULONG855_VERSION 1
#define ZHULONG855_SOC_ID 0x20
#define ZHULONG855_UB_MODULE_ID 0x2d

struct ubus_error_match {
	u8 soc_id;
	u8 version;
	u8 nimbus_id;
	u8 module_id;
	u8 valid_bit; /* used to identify which field require matching verification */
	u8 ctl_calc;
	u64 ras_ver; /* version mask */
};

enum ubus_controller_cal_mode {
	SOCKET_MODE,
	NIMBUS_MODE,
	COMBINE_MODE,
};

/* only support on HIP12/13 and ASCEND950 and ZHULONG855. */
static const struct ubus_error_match ubus_error_table[] = {
	{ HIP12_SOC_ID, HIP12_VERSION, UNION_DIE, HIP12_UB_MODULE_ID,
	  VALID_SOC_ID | VALID_VERSION | VALID_NIMBUS_ID | VALID_MODULE_ID,
	  SOCKET_MODE, RAS_V1 },
	{ HIP13_SOC_ID, HIP13A_VERSION, 0, HIP13_UB_MODULE_ID,
	  VALID_SOC_ID | VALID_VERSION | VALID_MODULE_ID,
	  COMBINE_MODE, RAS_V2 },
	{ HIP13_SOC_ID, HIP13B_VERSION, 0, HIP13_UB_MODULE_ID,
	  VALID_SOC_ID | VALID_VERSION | VALID_MODULE_ID,
	  COMBINE_MODE, RAS_V2 },
	{ ASCEND950_SOC_ID, ASCEND950_VERSION, 0, ASCEND950_UB_MODULE_ID,
	  VALID_SOC_ID | VALID_VERSION | VALID_MODULE_ID, NIMBUS_MODE,
	  RAS_V1 },
	{ ZHULONG855_SOC_ID, ZHULONG855_VERSION, 0, ZHULONG855_UB_MODULE_ID,
	  VALID_SOC_ID | VALID_VERSION | VALID_MODULE_ID, SOCKET_MODE,
	  RAS_V1 },
};

/*
 * Sub-module name table, mirrored from the ubus vendor driver
 * (drivers/ub/ubus/vendor/hisilicon/local-ras.c).
 */
struct sub_module_entry {
	u32 sub_module_id;
	const char *name;
	u64 ras_ver;
};

static const struct sub_module_entry hisi_ubus_sub_modules[] = {
	{0x01, "MISC.MISC_SLV", RAS_V1 | RAS_V2},
	{0x02, "MISC.IMP", RAS_V1 | RAS_V2},
	{0x03, "BA", RAS_V1 | RAS_V2},
	{0x04, "NL PORT", RAS_V1 | RAS_V2},
	{0x05, "NL DEVICE", RAS_V1 | RAS_V2},
	{0x06, "DLMAC", RAS_V1 | RAS_V2},
	{0x07, "MUXPCS", RAS_V1 | RAS_V2},
	{0x1D, "ETH", RAS_V1},
	{0x20, "TP_DAM", RAS_V1 | RAS_V2},
	{0x21, "TP_EUM", RAS_V1 | RAS_V2},
	{0x22, "TP_LRB", RAS_V1 | RAS_V2},
	{0x23, "TP_PPP", RAS_V1 | RAS_V2},
	{0x24, "TP_RQM", RAS_V1 | RAS_V2},
	{0x25, "TP_RXDMA_HEAD", RAS_V1 | RAS_V2},
	{0x26, "TP_RXP", RAS_V1 | RAS_V2},
	{0x27, "TP_SCC", RAS_V1 | RAS_V2},
	{0x28, "TP_TAI", RAS_V1 | RAS_V2},
	{0x29, "TP_TIMER", RAS_V1 | RAS_V2},
	{0x2a, "TP_TPCM", RAS_V1 | RAS_V2},
	{0x2b, "TP_TPGCM", RAS_V1 | RAS_V2},
	{0x2c, "TP_TPMM", RAS_V1 | RAS_V2},
	{0x2d, "TP_TPP", RAS_V1 | RAS_V2},
	{0x2e, "TP_TQEM", RAS_V1},
	{0x2e, "TP_WQEM", RAS_V2},
	{0x2f, "TP_TQS", RAS_V1 | RAS_V2},
	{0x30, "TP_UBOMMU", RAS_V1},
	{0x40, "TA_CQM", RAS_V1 | RAS_V2},
	{0x41, "TA_MRD", RAS_V1 | RAS_V2},
	{0x42, "TA_RSP", RAS_V1 | RAS_V2},
	{0x43, "TA_TM", RAS_V1 | RAS_V2},
	{0x44, "TA_TOM", RAS_V1 | RAS_V2},
	{0x45, "TA_TQC", RAS_V1 | RAS_V2},
	{0x46, "TA_TQEB", RAS_V1},
	{0x46, "TA_WQEM", RAS_V2},
	{0x47, "TA_TQMS", RAS_V1 | RAS_V2},
	{0x48, "TA_USI", RAS_V1 | RAS_V2},
	{0x49, "TA_RIG", RAS_V2},
	{0x4a, "TA_DM", RAS_V2},
	{0x4b, "TA_IDEV", RAS_V2},
	{0x4c, "TA_TQEP", RAS_V2},
	{0x4d, "TA_EIP", RAS_V2},
	{0x60, "ETH_CORE_TXMAC", RAS_V1},
	{0x61, "ETH_CORE_TDM", RAS_V1},
	{0x62, "ETH_CORE_TXPCS", RAS_V1},
	{0x63, "ETH_CORE_TXRSFEC", RAS_V1},
	{0x64, "ETH_CORE_MIB", RAS_V1},
	{0x65, "ETH_CORE_RXMAC", RAS_V1},
	{0x66, "ETH_CORE_RXPCS", RAS_V1},
	{0x67, "ETH_CORE_RXRSFEC", RAS_V1},
	{0x68, "ETH_CORE_RXPMACORE", RAS_V1},
	{0x69, "ETH_CORE_TXPMAL0", RAS_V1},
	{0x6b, "ETH_CORE_TXBRFEC", RAS_V1},
	{0x6c, "ETH_CORE_RXBRFEC", RAS_V1},
};

static inline bool ubus_field_match(u8 valid_bit, u8 field, u8 match_field, u8 bit_flag)
{
	if (valid_bit & bit_flag)
		return field == match_field;

	return true;
}

static inline bool is_nl_local_ras(u8 sub_module_id)
{
	return sub_module_id == NL_PORT_MODULE_ID;
}

static inline bool is_nl_ssu_link_credit_overtime_err(const struct hisi_ubus_error_data *edata)
{
	if (DIV_ROUND_UP(edata->register_array_size, SZ_4) <= LQC_MODULE_ERR_MISC)
		return false;

	return !!(edata->err_misc[LQC_MODULE_ERR_MISC] & (1U << LQC_MODULE_ERR_BIT));
}

static const char *get_sub_module_name(u64 ras_ver, u32 id)
{
	u32 i;

	for (i = 0; i < ARRAY_SIZE(hisi_ubus_sub_modules); i++) {
		if (hisi_ubus_sub_modules[i].sub_module_id == id &&
		    hisi_ubus_sub_modules[i].ras_ver & ras_ver)
			return hisi_ubus_sub_modules[i].name;
	}

	return "Unknown";
}

static const struct ubus_error_match *ubus_error_find_match(
	const struct hisi_ubus_error_data *edata)
{
	const struct ubus_error_match *match;
	int i;

	for (i = 0; i < ARRAY_SIZE(ubus_error_table); i++) {
		match = &ubus_error_table[i];

		if (!ubus_field_match(match->valid_bit,
		    edata->soc_id, match->soc_id, VALID_SOC_ID))
			continue;

		if (!ubus_field_match(match->valid_bit,
		    edata->version, match->version, VALID_VERSION))
			continue;

		if (!ubus_field_match(match->valid_bit,
		    edata->nimbus_id, match->nimbus_id, VALID_NIMBUS_ID))
			continue;

		if (!ubus_field_match(match->valid_bit,
		    edata->module_id, match->module_id, VALID_MODULE_ID))
			continue;

		return match;
	}

	return NULL;
}

static bool g_local_ras_enable;

/* Section type GUID of the local RAS error record to filter and forward
 * to userspace.
 */
static guid_t sentry_local_ras_sec_guid =
	GUID_INIT(0xC8B328A8, 0x9917, 0x4AF6, 0x9A, 0x13, 0x2E,
		  0x08, 0xAB, 0x2E, 0x75, 0x86);

/**
 * local_ras_event_handler - Build and send a NL SSU link credit overtime
 * error message to userspace.
 * @edata: NL SSU link credit overtime error record matched from the GHES
 * vendor record
 * @ras_ver: RAS version mask (from ubus_error_find_match) used to resolve the
 * sub-module name, disambiguating the ras_ver-dependent ids (0x2e / 0x46)
 *
 * Map the relevant hisi_ubus_error_data fields into a sentry message and forward
 * it fire-and-forget (ack == false).
 */
static void local_ras_event_handler(const struct hisi_ubus_error_data *edata,
			     u64 ras_ver)
{
	struct sentry_msg_helper_msg msg = {0};
	int ret;

	msg.type = SMH_MESSAGE_LOCAL_RAS;
	msg.msgid = smh_get_new_msg_id();
	msg.start_send_time = ktime_get_ns();
	msg.timeout_time = ULLONG_MAX;
	msg.helper_msg_info.local_ras_info.val_bits = edata->val_bits;
	msg.helper_msg_info.local_ras_info.version = edata->version;

	if (!(edata->val_bits & HISI_UBUS_LOCAL_VALID_MODULE_ID))
		pr_warn("module id valid bit is not set, msgid=%llu\n", msg.msgid);
	if (!(edata->val_bits & HISI_UBUS_LOCAL_VALID_SUB_MODULE_ID))
		pr_warn("sub module id valid bit is not set, msgid=%llu\n", msg.msgid);
	if (!(edata->val_bits & HISI_UBUS_LOCAL_VALID_NIMBUS_ID))
		pr_warn("nimbus id valid bit is not set, msgid=%llu\n", msg.msgid);
	if (!(edata->val_bits & HISI_UBUS_LOCAL_VALID_SOC_ID))
		pr_warn("soc id valid bit is not set, msgid=%llu\n", msg.msgid);
	if (!(edata->val_bits & HISI_UBUS_LOCAL_VALID_SOCKET_ID))
		pr_warn("socket id valid bit is not set, msgid=%llu\n", msg.msgid);
	if (!(edata->val_bits & HISI_UBUS_LOCAL_VALID_CORE_ID))
		pr_warn("core id valid bit is not set, msgid=%llu\n", msg.msgid);
	if (!(edata->val_bits & HISI_UBUS_LOCAL_VALID_PORT_ID))
		pr_warn("port id valid bit is not set, msgid=%llu\n", msg.msgid);
	if (!(edata->val_bits & HISI_UBUS_LOCAL_VALID_ERR_SEVERITY))
		pr_warn("error severity valid bit is not set, msgid=%llu\n", msg.msgid);
	if (!(edata->val_bits & HISI_UBUS_LOCAL_VALID_ERR_TYPE))
		pr_warn("error type valid bit is not set, msgid=%llu\n", msg.msgid);
	if (!(edata->val_bits & HISI_UBUS_LOCAL_VALID_REG_SIZE))
		pr_warn("reg size valid bit is not set, msgid=%llu\n", msg.msgid);

	msg.helper_msg_info.local_ras_info.soc_id = edata->soc_id;
	msg.helper_msg_info.local_ras_info.nimbus_id = edata->nimbus_id;
	msg.helper_msg_info.local_ras_info.module_id = edata->module_id;
	msg.helper_msg_info.local_ras_info.socket_id = edata->socket_id;
	msg.helper_msg_info.local_ras_info.core_id = edata->core_id;
	msg.helper_msg_info.local_ras_info.port_id = edata->port_id;
	strscpy(msg.helper_msg_info.local_ras_info.sub_module_name,
		get_sub_module_name(ras_ver, edata->sub_module_id),
		sizeof(msg.helper_msg_info.local_ras_info.sub_module_name));
	msg.helper_msg_info.local_ras_info.err_severity = edata->err_severity;
	msg.helper_msg_info.local_ras_info.err_type = edata->err_type;

	/* ack == false: never block the GHES error handling path. */
	ret = smh_message_send(&msg, false);
	if (ret)
		pr_err("failed to send link credit overtime error, ret=%d, msgid=%llu\n",
			ret, msg.msgid);
	else
		pr_info("send link credit overtime error successfully, msgid=%llu\n", msg.msgid);
}

/**
 * sentry_local_ras_notifier - GHES vendor record notifier callback
 * @nb: Notifier block
 * @event: Event type (unused)
 * @data: Pointer to struct acpi_hest_generic_data
 *
 * Filter the GHES vendor record by section type GUID and, on match, print the
 * error and forward it to userspace through the sentry message helper. The
 * record is also matched against the supported platform table
 * (ubus_error_find_match, mirrored from the ubus vendor driver).
 *
 * Return: NOTIFY_DONE.
 */
static int sentry_local_ras_notifier(struct notifier_block *nb, unsigned long event,
			      void *data)
{
	const struct hisi_ubus_error_data *err_data;
	const struct ubus_error_match *match;
	struct acpi_hest_generic_data *gdata;
	guid_t sec_guid;
	u32 plen;
	u32 misc_slots;

	if (!READ_ONCE(g_local_ras_enable))
		return NOTIFY_DONE;

	gdata = (struct acpi_hest_generic_data *)data;
	/* Only the one custom record we care about. */
	import_guid(&sec_guid, gdata->section_type);
	if (!guid_equal(&sec_guid, &sentry_local_ras_sec_guid))
		return NOTIFY_DONE;

	err_data = (struct hisi_ubus_error_data *)acpi_hest_get_payload(gdata);
	plen = acpi_hest_get_error_length(gdata);
	/* err_misc[] is a flexible array at the end of the fixed header; this only
	 * guarantees the fixed fields (val_bits, sub_module_id, register_array_size)
	 * are readable. The err_misc slots are bounded separately against plen
	 * before any of them is read.
	 */
	if (!err_data || plen < sizeof(struct hisi_ubus_error_data)) {
		pr_err("invalid local ras record: plen=%u header=%zu\n",
		       plen, sizeof(struct hisi_ubus_error_data));
		return NOTIFY_DONE;
	}

	/* Match the record against the supported platform table, the same way the
	 * ubus vendor driver does (ubus_error_find_match).
	 */
	match = ubus_error_find_match(err_data);
	if (!match) {
		pr_warn("local ras record from unsupported platform: soc=%u version=%u nimbus=%u module=%#x\n",
			err_data->soc_id, err_data->version,
			err_data->nimbus_id, err_data->module_id);
		return NOTIFY_DONE;
	}

	/* Only NL SSU link credit overtime errors are reported. NL-port records
	 * are reported only when is_nl_ssu_link_credit_overtime_err() holds; any
	 * other record is dropped and not forwarded.
	 */
	if (!is_nl_local_ras(err_data->sub_module_id)) {
		pr_info("not link credit overtime error: sub_module_id=%#x is not NL PORT, skip reporting (port=%u)\n",
			err_data->sub_module_id, err_data->port_id);
		return NOTIFY_DONE;
	}

	misc_slots = (plen - (u32)sizeof(struct hisi_ubus_error_data)) / sizeof(u32);
	if (misc_slots <= LQC_MODULE_ERR_MISC) {
		pr_info("cannot determine link credit overtime error: err_misc[%u] missing (plen=%u) (port=%u)\n",
			LQC_MODULE_ERR_MISC, plen, err_data->port_id);
		return NOTIFY_DONE;
	}

	if (!is_nl_ssu_link_credit_overtime_err(err_data)) {
		pr_info("not link credit overtime error: err_misc[%u]=%#x register_array_size=%u, bit%u (port=%u)\n",
			LQC_MODULE_ERR_MISC, err_data->err_misc[LQC_MODULE_ERR_MISC],
			err_data->register_array_size, LQC_MODULE_ERR_BIT, err_data->port_id);
		return NOTIFY_DONE;
	}

	/* Forward the link-credit-overtime record to userspace. */
	pr_info("preparing to send link credit overtime error msg to userspace\n");
	local_ras_event_handler(err_data, match->ras_ver);

	return NOTIFY_DONE;
}

/**
 * proc_local_ras_enable_write - Write handler for local_ras proc file
 * @file: File structure
 * @ubuf: User buffer
 * @cnt: Number of bytes to write
 * @ppos: File position
 *
 * Return: Number of bytes written on success, negative error code on failure
 */
static ssize_t proc_local_ras_enable_write(struct file *file,
					   const char __user *ubuf,
					   size_t cnt, loff_t *ppos)
{
	char enable[ENABLE_VALUE_MAX_LEN + 1] = {0};
	int ret;

	if (cnt == 0 || cnt > ENABLE_VALUE_MAX_LEN) {
		pr_err("invalid value for local_ras, the value can only be 'off' or 'on'.\n");
		return -EINVAL;
	}

	ret = copy_from_user(enable, ubuf, cnt);
	if (ret) {
		pr_err("set local_ras failed\n");
		return -EFAULT;
	}

	if (cnt > 0 && enable[cnt - 1] == '\n')
		enable[cnt - 1] = '\0';

	if (strcmp(enable, "on") == 0) {
		WRITE_ONCE(g_local_ras_enable, true);
	} else if (strcmp(enable, "off") == 0) {
		WRITE_ONCE(g_local_ras_enable, false);
	} else {
		pr_err("invalid value for local_ras\n");
		return -EINVAL;
	}

	pr_info("%s NL SSU link credit overtime error event report\n",
		READ_ONCE(g_local_ras_enable) ? "enable" : "disable");
	return cnt;
}

/**
 * proc_local_ras_enable_show - Read handler for local_ras proc file
 * @file: File structure
 * @buf: User buffer
 * @count: Number of bytes to read
 * @ppos: File position
 *
 * Return: Number of bytes read on success, negative error code on failure
 */
static ssize_t proc_local_ras_enable_show(struct file *file,
					 char __user *buf,
					 size_t count, loff_t *ppos)
{
	bool enabled = READ_ONCE(g_local_ras_enable);
	const char *value = enabled ? "on" : "off";
	size_t len = enabled ? 2 : 3;

	return simple_read_from_buffer(buf, count, ppos, value, len);
}

const struct proc_ops proc_local_ras_file_operations = {
	.proc_read	= proc_local_ras_enable_show,
	.proc_write	= proc_local_ras_enable_write,
};

static struct notifier_block sentry_local_ras_nb = {
	.notifier_call = sentry_local_ras_notifier,
	.priority = 0,
};

/**
 * sentry_local_ras_init - Register the GHES vendor record notifier
 *
 * Return: 0 on success, negative error code on failure
 */
int sentry_local_ras_init(void)
{
	int ret;

	ret = ghes_register_vendor_record_notifier(&sentry_local_ras_nb);
	if (ret) {
		pr_err("register ghes vendor record notifier failed, ret=%d\n", ret);
		return ret;
	}

	pr_info("ghes vendor record notifier registered\n");
	return 0;
}

/**
 * sentry_local_ras_exit - Unregister the GHES vendor record notifier
 */
void sentry_local_ras_exit(void)
{
	ghes_unregister_vendor_record_notifier(&sentry_local_ras_nb);
	pr_info("ghes vendor record notifier unregistered\n");
}
