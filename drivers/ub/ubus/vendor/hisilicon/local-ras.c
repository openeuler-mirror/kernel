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

struct sub_module_info {
	u32 sub_module_id;
	const char *sub_module_name;
};

static struct sub_module_info hisi_ubus_sub_module[] = {
	{0x1, "MISC.MISC_SLV"},
	{0x2, "MISC.IMP"},
	{0x3, "BA"},
	{0x4, "NL PORT"},
	{0x5, "NL DEVICE"},
	{0x6, "DLMAC"},
	{0x7, "MUXPCS"},
	{0x1D, "ETH"},
	{0x20, "TP_DAM"},
	{0x21, "TP_EUM"},
	{0x22, "TP_LRB"},
	{0x23, "TP_PPP"},
	{0x24, "TP_RQM"},
	{0x25, "TP_RXDMA_HEAD"},
	{0x26, "TP_RXP"},
	{0x27, "TP_SCC"},
	{0x28, "TP_TAI"},
	{0x29, "TP_TIMER"},
	{0x2a, "TP_TPCM"},
	{0x2b, "TP_TPGCM"},
	{0x2c, "TP_TPMM"},
	{0x2d, "TP_TPP"},
	{0x2e, "TP_TQEM"},
	{0x2f, "TP_TQS"},
	{0x30, "TP_UBOMMU"},
	{0x40, "TA_CQM"},
	{0x41, "TA_MRD"},
	{0x42, "TA_RSP"},
	{0x43, "TA_TM"},
	{0x44, "TA_TOM"},
	{0x45, "TA_TQC"},
	{0x46, "TA_TQEB"},
	{0x47, "TA_TQMS"},
	{0x48, "TA_USI"},
	{0x60, "ETH.CORE_TXMAC"},
	{0x61, "ETH.CORE_TDM"},
	{0x62, "ETH.CORE_TXPCS"},
	{0x63, "ETH.CORE_TXRSFEC"},
	{0x64, "ETH.CORE_MIB"},
	{0x65, "ETH.CORE_RXMAC"},
	{0x66, "ETH.CORE_RXPCS"},
	{0x67, "ETH.CORE_RXRSFEC"},
	{0x68, "ETH.CORE_RXPMACORE"},
	{0x69, "ETH.CORE_TXPMAL0"},
	{0x6b, "ETH.CORE_TXBRFEC"},
	{0x6c, "ETH.CORE_RXBRFEC"},
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

static guid_t hisi_ubus_sec_guid =
	GUID_INIT(0xC8B328A8, 0x9917, 0x4AF6, 0x9A, 0x13, 0x2E,
		  0x08, 0xAB, 0x2E, 0x75, 0x86);

static inline const char *hisi_ubus_get_string(
	const char * const *array, size_t n, u32 id)
{
	return id < n && array[id] ? array[id] : "Unknown";
}

static const char *get_sub_module_name(u32 id)
{
	u8 i;

	for (i = 0; i <  ARRAY_SIZE(hisi_ubus_sub_module); i++) {
		if (hisi_ubus_sub_module[i].sub_module_id == id)
			return hisi_ubus_sub_module[i].sub_module_name;
	}

	return "Unknown";
}

#define HIP12_VERSION 8
#define HIP12_SOC_ID 1
#define ASCEND950_VERSION 2
#define ASCEND950_SOC_ID 0x13
static inline struct ub_bus_controller *find_bus_controller_by_errdata(
	const struct hisi_ubus_error_data *edata)
{
	u32 ctl_no;

	/* only support on HIP12 and ASCEND950. */
	if (edata->version == HIP12_VERSION && edata->soc_id == HIP12_SOC_ID)
		ctl_no = (u32)edata->socket_id;
	else if (edata->version == ASCEND950_VERSION && edata->soc_id == ASCEND950_SOC_ID)
		ctl_no = (u32)edata->nimbus_id;
	else
		return NULL;

	return ub_find_bus_controller(ctl_no);
}

static void hisi_ubus_ras_print(struct ub_entity *uent,
				const struct hisi_ubus_error_data *edata)
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

	ub_info(uent, "HISI : Ubus local RAS error\n");
	ub_info(uent, "Table version = %u\n", edata->version);
	for (i = 0; i < ARRAY_SIZE(ras_err_info); i++)
		if (edata->val_bits & ras_err_info[i].val_bit)
			ub_info(uent, ras_err_info[i].err_msg,
				ras_err_info[i].val);

	if (edata->val_bits & HISI_UBUS_LOCAL_VALID_SUB_MODULE_ID)
		ub_info(uent, "Sub Module = %s\n",
			get_sub_module_name((u32)edata->sub_module_id));

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

#define LQC_MOUDULE_ERR_BIT 7
#define LQC_MOUDULE_ERR_MISC 1
static inline bool is_nl_ssu_link_credi_overtime_err(const struct hisi_ubus_error_data *edata)
{
	if (DIV_ROUND_UP(edata->register_array_size, SZ_4) <= LQC_MOUDULE_ERR_MISC)
		return false;

	return !!(edata->err_misc[LQC_MOUDULE_ERR_MISC] & (1U << LQC_MOUDULE_ERR_BIT));
}

static bool ubus_need_recover(const struct hisi_ubus_error_data *edata)
{
	if (edata->err_severity != HISI_UBUS_ERR_SEV_RECOVERABLE)
		return false;

	if (!(edata->val_bits & HISI_UBUS_LOCAL_VALID_PORT_ID))
		return false;

	if (is_nl_local_ras(edata->sub_module_id))
		return is_nl_ssu_link_credi_overtime_err(edata);

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
	ub_notify_share_port(port, UB_PORT_EVENT_RESET_PREPARE);

	ret = hi_send_port_reset_msg(uent, port_id);
	if (ret) {
		pr_err("ub vdm port reset failed, ret:%d\n", ret);
		return ret;
	}

	ub_notify_share_port(port, UB_PORT_EVENT_RESET_DONE);

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
				   const struct hisi_ubus_error_data *edata)
{
	int ret;
	u32 i;

	hisi_ubus_ras_print(uent, edata);
	ub_info(uent, "Reg Dump:\n");
#define REGISTER_ARRAY_MAX_SIZE 256
	for (i = 0; i < DIV_ROUND_UP(
	     min(edata->register_array_size, REGISTER_ARRAY_MAX_SIZE), SZ_4); i++)
		ub_info(uent, "ERR_MISC_%u = %#x\n", i, edata->err_misc[i]);
	if (edata->register_array_size > REGISTER_ARRAY_MAX_SIZE)
		ub_warn(uent, "register array size is exceed max array size %d, only parts of data were printed.\n",
			REGISTER_ARRAY_MAX_SIZE);

	if (!ubus_need_recover(edata)) {
		ub_info(uent, "ubus no need recover.\n");
		return;
	}

	ret = ubus_recover(uent, edata);
	if (ret)
		ub_err(uent, "ubus recover failed, ret=%d\n", ret);
}

static bool ubus_error_supported(const struct hisi_ubus_error_data *error_data)
{
#define UNION_DIE 1
#define HIP12_UB_MODULE_ID 0x2d
#define ASCEND950_UB_MODULE_ID 0x31
	if (!(HISI_UBUS_LOCAL_VALID_MODULE_ID & error_data->val_bits) ||
	    !(HISI_UBUS_LOCAL_VALID_NIMBUS_ID & error_data->val_bits) ||
	    !(HISI_UBUS_LOCAL_VALID_SOC_ID & error_data->soc_id))
		return false;

	if (error_data->soc_id == HIP12_SOC_ID)
		return error_data->nimbus_id == UNION_DIE &&
		       error_data->module_id == HIP12_UB_MODULE_ID;

	if (error_data->soc_id == ASCEND950_SOC_ID)
		return error_data->module_id == ASCEND950_UB_MODULE_ID;

	return false;
}

static int hisi_ubus_notify_error(struct notifier_block *nb, unsigned long event, void *data)
{
	const struct hisi_ubus_error_data *error_data;
	struct acpi_hest_generic_data *gdata;
	struct ub_bus_controller *ubc;
	guid_t err_sec_guid;

	gdata = (struct acpi_hest_generic_data *)data;
	import_guid(&err_sec_guid, gdata->section_type);
	if (!guid_equal(&err_sec_guid, &hisi_ubus_sec_guid))
		return NOTIFY_DONE;

	error_data = (struct hisi_ubus_error_data *)acpi_hest_get_payload(gdata);
	if (!ubus_error_supported(error_data))
		return NOTIFY_DONE;

	ubc = find_bus_controller_by_errdata(error_data);
	if (!ubc)
		return NOTIFY_DONE;

	hisi_ubus_handle_error(ubc->uent, error_data);
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
