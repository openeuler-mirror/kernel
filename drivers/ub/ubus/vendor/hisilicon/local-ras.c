// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#define pr_fmt(fmt) "ubus hisi local_ras: " fmt

#include <acpi/ghes.h>
#include "../../ubus.h"
#include "../../ubus_driver.h"
#include "../../reset.h"
#include "../../port.h"
#include "local-ras.h"
#include "hisi-ubus.h"

#define RAS_V1 BIT(0)
#define RAS_V2 BIT(1)

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

static const char * const hisi_ubus_error_sev[] = {
	[HISI_UBUS_ERR_SEV_RECOVERABLE] = "recoverable",
	[HISI_UBUS_ERR_SEV_FATAL] = "fatal",
	[HISI_UBUS_ERR_SEV_CORRECTED] = "corrected",
	[HISI_UBUS_ERR_SEV_NONE] = "none",
};

struct ras_err_info {
	u32 val_bit;
	const char *err_msg;
	u8 val;
};

struct ubus_error_match {
	u8 soc_id;
	u8 version;
	u8 nimbus_id;
	u8 module_id;
	u8 valid_bit; /* used to identify which field require matching verification */
	u8 ctl_calc;
	u64 ras_ver; /* version mask for sub-module lookup */
};

enum ubus_controller_cal_mode {
	SOCKET_MODE,
	NIMBUS_MODE,
	COMBINE_MODE,
};

#define VALID_SOC_ID	(1U << 0)
#define VALID_VERSION	(1U << 1)
#define VALID_NIMBUS_ID	(1U << 2)
#define VALID_MODULE_ID	(1U << 3)

static guid_t hisi_ubus_sec_guid =
	GUID_INIT(0xC8B328A8, 0x9917, 0x4AF6, 0x9A, 0x13, 0x2E,
		  0x08, 0xAB, 0x2E, 0x75, 0x86);

static inline const char *hisi_ubus_get_string(
	const char * const *array, size_t n, u32 id)
{
	return id < n && array[id] ? array[id] : "Unknown";
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
#define NIMBUS_NUM 2
#define UNION_DIE 1
#define ZHULONG855_VERSION 1
#define ZHULONG855_SOC_ID 0x20
#define ZHULONG855_UB_MODULE_ID 0x2d

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

static u32 ubus_calc_ctl_no(const struct ubus_error_match *match,
			    const struct hisi_ubus_error_data *edata)
{
	switch (match->ctl_calc) {
	case SOCKET_MODE:
		return (u32)edata->socket_id;
	case NIMBUS_MODE:
		return (u32)edata->nimbus_id;
	case COMBINE_MODE:
		return (u32)edata->socket_id * NIMBUS_NUM +
		       (u32)edata->nimbus_id;
	default:
		return U32_MAX;
	}
}

static inline bool ubus_field_match(u8 valid_bit, u8 field, u8 match_field, u8 bit_flag)
{
	if (valid_bit & bit_flag)
		return field == match_field;

	return true;
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

static bool ubus_error_supported(const struct hisi_ubus_error_data *error_data)
{
	if (!(error_data->val_bits & HISI_UBUS_LOCAL_VALID_MODULE_ID) ||
	    !(error_data->val_bits & HISI_UBUS_LOCAL_VALID_NIMBUS_ID) ||
	    !(error_data->val_bits & HISI_UBUS_LOCAL_VALID_SOC_ID))
		return false;

	return true;
}

static struct ub_bus_controller *find_bus_controller_by_errdata(
	const struct hisi_ubus_error_data *edata,
	const struct ubus_error_match *match)
{
	u32 ctl_no;

	ctl_no = ubus_calc_ctl_no(match, edata);
	if (ctl_no == U32_MAX)
		return NULL;

	return ub_find_bus_controller(ctl_no);
}

static void hisi_ubus_ras_print(struct ub_entity *uent,
				const struct hisi_ubus_error_data *edata,
				u64 ras_ver)
{
	struct ras_err_info ras_err_info[] = {
		{HISI_UBUS_LOCAL_VALID_SOC_ID,
		 "SOC ID = %u\n", edata->soc_id},
		{HISI_UBUS_LOCAL_VALID_SOCKET_ID,
		 "Socket ID = %u\n", edata->socket_id},
		{HISI_UBUS_LOCAL_VALID_NIMBUS_ID,
		 "Nimbus ID = %u\n", edata->nimbus_id},
		{HISI_UBUS_LOCAL_VALID_CORE_ID,
		 "Core ID = core%u\n", edata->core_id},
		{HISI_UBUS_LOCAL_VALID_PORT_ID,
		 "Port ID = port%u\n", edata->port_id},
	};
	u8 i;

	ub_info(uent, "HISI: Ubus local RAS error\n");
	ub_info(uent, "Table version = %u\n", edata->version);
	for (i = 0; i < ARRAY_SIZE(ras_err_info); i++)
		if (edata->val_bits & ras_err_info[i].val_bit)
			ub_info(uent, ras_err_info[i].err_msg,
				ras_err_info[i].val);

	if (edata->val_bits & HISI_UBUS_LOCAL_VALID_SUB_MODULE_ID)
		ub_info(uent, "Sub Module = %s\n",
			get_sub_module_name(ras_ver, (u32)edata->sub_module_id));

	if (edata->val_bits & HISI_UBUS_LOCAL_VALID_ERR_SEVERITY)
		ub_info(uent, "Error severity = %s\n",
			 hisi_ubus_get_string(hisi_ubus_error_sev,
					      ARRAY_SIZE(hisi_ubus_error_sev),
					      (u32)edata->err_severity));

	if (edata->val_bits & HISI_UBUS_LOCAL_VALID_ERR_TYPE)
		ub_info(uent, "Error type = %#x\n", edata->err_type);
}

#define NL_PORT_MODULE_ID 0x4
static inline bool is_nl_local_ras(u8 sub_module_id)
{
	return sub_module_id == NL_PORT_MODULE_ID;
}

#define LQC_MODULE_ERR_BIT 7
#define LQC_MODULE_ERR_MISC 1
static inline bool is_nl_ssu_link_credit_overtime_err(const struct hisi_ubus_error_data *edata)
{
	if (DIV_ROUND_UP(edata->register_array_size, SZ_4) <= LQC_MODULE_ERR_MISC)
		return false;

	return !!(edata->err_misc[LQC_MODULE_ERR_MISC] & (1U << LQC_MODULE_ERR_BIT));
}

static bool ubus_need_recover(const struct hisi_ubus_error_data *edata)
{
	if (edata->err_severity != HISI_UBUS_ERR_SEV_RECOVERABLE)
		return false;

	if (!(edata->val_bits & HISI_UBUS_LOCAL_VALID_PORT_ID))
		return false;

	if (is_nl_local_ras(edata->sub_module_id))
		return is_nl_ssu_link_credit_overtime_err(edata);

	return true;
}

static int ubus_port_recover(struct ub_entity *uent, u16 port_id)
{
	if (port_id < uent->port_nums && uent->ports[port_id].type == PHYSICAL)
		return ub_port_reset(uent, port_id);

	ub_info(uent, "port[%u] no need reset by ubus.\n", port_id);
	return 0;
}

static int ubus_port_recover_cluster(struct ub_entity *uent, u16 port_id)
{
	struct ub_port *port;
	int ret;

	if (port_id >= uent->port_nums || uent->ports[port_id].type != PHYSICAL) {
		pr_err("port id is over port nums or port type is not physical\n");
		return -EINVAL;
	}

	port = uent->ports + port_id;
	mutex_lock(port->port_lock);
	ub_notify_share_port(port, UB_PORT_EVENT_RESET_PREPARE);

	ret = hi_send_port_reset_msg(uent, port_id);
	if (ret) {
		pr_err("ub vdm port reset failed, ret:%d\n", ret);
		ub_notify_share_port(port, UB_PORT_EVENT_RESET_FAILED);
		mutex_unlock(port->port_lock);
		return ret;
	}

	ub_notify_share_port(port, UB_PORT_EVENT_RESET_DONE);
	mutex_unlock(port->port_lock);

	return 0;
}

static int ubus_recover(struct ub_entity *uent,
			 const struct hisi_ubus_error_data *edata)
{
	int port_id;

	port_id = (int)edata->port_id;
	if (uent->ubc->cluster)
		return ubus_port_recover_cluster(uent, port_id);
	else
		return ubus_port_recover(uent, port_id);
}

static void hisi_ubus_handle_error(struct ub_entity *uent,
				   const struct hisi_ubus_error_data *edata,
				   u64 ras_ver)
{
	int ret;
	u32 i;

	hisi_ubus_ras_print(uent, edata, ras_ver);
	ub_info(uent, "Reg Dump:\n");
#define REGISTER_ARRAY_MAX_SIZE 256
	for (i = 0; i < DIV_ROUND_UP(
	     min(edata->register_array_size, REGISTER_ARRAY_MAX_SIZE), SZ_4); i++)
		ub_info(uent, "ERR_MISC_%u = %#x\n", i, edata->err_misc[i]);
	if (edata->register_array_size > REGISTER_ARRAY_MAX_SIZE)
		ub_warn(uent, "register array size exceeds max array size %d, only parts of data were printed.\n",
			REGISTER_ARRAY_MAX_SIZE);

	if (!ubus_need_recover(edata)) {
		ub_info(uent, "ubus no need to recover.\n");
		return;
	}

	ret = ubus_recover(uent, edata);
	if (ret)
		ub_err(uent, "ubus recovery failed, ret=%d\n", ret);
}

static int hisi_ubus_notify_error(struct notifier_block *nb, unsigned long event, void *data)
{
	const struct hisi_ubus_error_data *error_data;
	struct acpi_hest_generic_data *gdata;
	const struct ubus_error_match *match;
	struct ub_bus_controller *ubc;
	guid_t err_sec_guid;

	gdata = (struct acpi_hest_generic_data *)data;
	import_guid(&err_sec_guid, gdata->section_type);
	if (!guid_equal(&err_sec_guid, &hisi_ubus_sec_guid))
		return NOTIFY_DONE;

	error_data = (struct hisi_ubus_error_data *)acpi_hest_get_payload(gdata);
	if (!ubus_error_supported(error_data))
		return NOTIFY_DONE;

	match = ubus_error_find_match(error_data);
	if (!match)
		return NOTIFY_DONE;

	ubc = find_bus_controller_by_errdata(error_data, match);
	if (!ubc)
		return NOTIFY_DONE;

	hisi_ubus_handle_error(ubc->uent, error_data, match->ras_ver);
	return NOTIFY_OK;
}

static struct hisi_ubus_error_private *hisi_ubus_error_private_p;

void ub_ras_handler_remove(void)
{
	if (hisi_ubus_error_private_p) {
		ghes_unregister_vendor_record_notifier(
			&hisi_ubus_error_private_p->nb);
		kfree(hisi_ubus_error_private_p);
		hisi_ubus_error_private_p = NULL;
	}
}

int ub_ras_handler_probe(void)
{
	int ret;

	hisi_ubus_error_private_p = kzalloc(sizeof(struct hisi_ubus_error_private),
				    GFP_KERNEL);
	if (!hisi_ubus_error_private_p)
		return -ENOMEM;

	hisi_ubus_error_private_p->nb.notifier_call = hisi_ubus_notify_error;
	ret = ghes_register_vendor_record_notifier(
		&hisi_ubus_error_private_p->nb);
	if (ret) {
		pr_err("register ubus error handler with apei failed\n");
		kfree(hisi_ubus_error_private_p);
		hisi_ubus_error_private_p = NULL;
	}

	return ret;
}
