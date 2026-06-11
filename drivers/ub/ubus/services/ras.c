// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#define pr_fmt(fmt)	"ubus ras: " fmt

#include <linux/cper.h>
#include <ub/ubus/uber.h>
#include <linux/kfifo.h>

#include "../ubus.h"
#include "../msg.h"
#include "../reset.h"
#include "ras.h"
#include "service.h"

#define RAS_CE 0
#define RAS_UC_NFE 1
#define RAS_UC_FE 2
#define RAS_RECOVER_RING_SIZE 16
#define RAS_SEVERITY_STR(severity) \
	((severity) == RAS_CE ? "CORRECTABLE" : \
	(severity) == RAS_UC_NFE ? "UNCORRECTABLE NONFATAL" : \
	(severity) == RAS_UC_FE ? "UNCORRECTABLE FATAL" : \
	"UNKNOWN")

enum ras_err_level {
	RAS_ERR_PORT_LEVEL,
	RAS_ERR_DEVICE_LEVEL,
};

static int cper_severity_to_ub_ras(int cper_severity)
{
	switch (cper_severity) {
	case CPER_SEV_FATAL:
		return RAS_UC_FE;
	case CPER_SEV_RECOVERABLE:
		return RAS_UC_NFE;
	default:
		return RAS_CE;
	}
}

static void print_ub_err_info(struct ub_entity *uent, u32 *spec_info, u32 *vendor_info)
{
#define DW_EACH_ROUND 4
#define DW_0 0
#define DW_1 1
#define DW_2 2
#define DW_3 3
	for (int i = 0; i < RAS_SPEC_ERR_PKG_LEN; i += DW_EACH_ROUND)
		ub_err(uent, "SPEC Err Pkg Header=%08x %08x %08x %08x\n",
		       spec_info[i], spec_info[i + DW_1],
		       spec_info[i + DW_2], spec_info[i + DW_3]);

	ub_err(uent, "VENDOR Err Pkg Header=%08x %08x\n", vendor_info[DW_0], vendor_info[DW_1]);
}

static void cper_print_ub_err(struct ub_entity *uent, struct ras_recover_entry *entry)
{
	struct ras_cap_regs *reg = entry->regs;

	ub_err(uent, "UBUS ERR type=%s.\n", RAS_SEVERITY_STR(entry->severity));

	if (entry->err_level == RAS_ERR_PORT_LEVEL)
		ub_err(uent, "Error level: PORT ERR, port=%u.\n", entry->port);
	else
		ub_err(uent, "Error level: DEVICE ERR.\n");

	if (!reg) {
		ub_err(uent, "No error detail need to show.\n");
		return;
	}

	ub_err(uent, "Uncorrectable ERR status=%#08llx, mask=%#08llx, severity=%#08llx\n",
		       reg->uncor_status, reg->uncor_mask, reg->uncor_severity);
	ub_err(uent, "Correctable ERR status=%#08llx, mask=%#08llx, severity=%#08llx\n",
		       reg->cor_status, reg->cor_mask, reg->cor_severity);

	print_ub_err_info(uent, reg->spec_def_err_info, reg->vendor_def_err_info);
}

static ub_ers_result_t ras_merge_result(ub_ers_result_t orig,
					ub_ers_result_t new_one)
{
	ub_ers_result_t ret = orig;

	if (new_one == UB_ERS_RESULT_NO_ERR_DRIVER)
		return UB_ERS_RESULT_NO_ERR_DRIVER;

	if (new_one == UB_ERS_RESULT_NONE)
		return ret;

	switch (orig) {
	case UB_ERS_RESULT_CAN_RECOVER:
	case UB_ERS_RESULT_RECOVERED:
		ret = new_one;
		break;
	case UB_ERS_RESULT_DISCONNECT:
		if (new_one == UB_ERS_RESULT_NEED_RESET)
			ret = new_one;
		break;
	default:
		pr_err("unused ras error result %d\n", new_one);
		break;
	}

	return ret;
}

static ub_ers_result_t report_resource_enabled(struct ub_entity *uent,
					       ub_ers_result_t orig)
{
	ub_ers_result_t result, new_one;
	struct ub_driver *udrv;

	device_lock(&uent->dev);
	udrv = uent->driver;
	if (!udrv || !udrv->err_handler || !udrv->err_handler->ub_resource_enabled) {
		result = orig;
		goto out;
	}

	new_one = udrv->err_handler->ub_resource_enabled(uent);
	result = ras_merge_result(orig, new_one);
out:
	device_unlock(&uent->dev);
	return result;
}

static void ub_uevent_ers(struct ub_entity *uent, ub_ers_result_t err_type)
{
#define MAX_ENVP 3
	char *envp[MAX_ENVP];
	int idx = 0;

	switch (err_type) {
	case UB_ERS_RESULT_NONE:
	case UB_ERS_RESULT_CAN_RECOVER:
		envp[idx++] = "ERROR_EVENT=BEGIN_RECOVERY";
		envp[idx++] = "DEVICE_ONLINE=0";
		break;
	case UB_ERS_RESULT_RECOVERED:
		envp[idx++] = "ERROR_EVENT=SUCCESSFUL_RECOVERY";
		envp[idx++] = "DEVICE_ONLINE=1";
		break;
	case UB_ERS_RESULT_DISCONNECT:
		envp[idx++] = "ERROR_EVENT=FAILED_RECOVERY";
		envp[idx++] = "DEVICE_ONLINE=0";
		break;
	default:
		pr_err("unused uevent ras err_type %d\n", err_type);
		break;
	}

	if (idx > 0) {
		envp[idx++] = NULL;
		kobject_uevent_env(&uent->dev.kobj, KOBJ_CHANGE, envp);
	}
}

static ub_ers_result_t ub_error_report(struct ub_entity *uent, ub_channel_state_t state)
{
	struct ub_driver *udrv;
	ub_ers_result_t result;

	device_lock(&uent->dev);
	udrv = uent->driver;
	if (!udrv || !udrv->err_handler || !udrv->err_handler->ub_error_detected) {
		ub_warn(uent, "No driver bounded or no handler provided.\n");
		result = UB_ERS_RESULT_NO_ERR_DRIVER;
		goto exit;
	}

	result = udrv->err_handler->ub_error_detected(uent, state);
	ub_uevent_ers(uent, result);
	result = ras_merge_result(UB_ERS_RESULT_CAN_RECOVER, result);
exit:
	device_unlock(&uent->dev);
	return result;
}

static void ub_do_recovery(struct ub_entity *uent, ub_channel_state_t state,
			   struct ras_recover_entry *entry)
{
	u32 port_id = entry->port;
	ub_ers_result_t ret;
	int recovery;

	ret = ub_error_report(uent, state);
	if (ret == UB_ERS_RESULT_NEED_RESET) {
		if (entry->err_level == RAS_ERR_PORT_LEVEL)
			recovery = ub_port_reset(uent, port_id);
		else
			recovery = is_ibus_controller(uent) ? 0 : ub_device_reset(uent);

		if (!recovery)
			ret = UB_ERS_RESULT_RECOVERED;
		else
			goto failed;
	}

	if (ret == UB_ERS_RESULT_CAN_RECOVER)
		ret = report_resource_enabled(uent, UB_ERS_RESULT_RECOVERED);

	if (ret != UB_ERS_RESULT_RECOVERED)
		goto failed;

	ub_info(uent, "uent ras recovery succeeded\n");
	return;
failed:
	ub_uevent_ers(uent, UB_ERS_RESULT_DISCONNECT);
	ub_err(uent, "uent ras recovery failed\n");
}

static inline void ras_cap_regs_free(struct ras_cap_regs **regs)
{
	if (!regs || !(*regs))
		return;

	kfree(*regs);
	*regs = NULL;
}

static DEFINE_KFIFO(ras_recover_ring, struct ras_recover_entry,
		    RAS_RECOVER_RING_SIZE);

static void ub_ras_recover_work_func(struct work_struct *work)
{
	struct ras_recover_entry entry;
	struct ub_entity *uent;

	while (kfifo_get(&ras_recover_ring, &entry)) {
		uent = ub_get_ent_by_eid(entry.eid);
		if (!uent) {
			pr_err("can not find ub entity by eid=%#05x\n",
			       entry.eid);
			ras_cap_regs_free(&entry.regs);
			continue;
		}

		cper_print_ub_err(uent, &entry);
		if (uent->ubc->cluster) {
			ub_err(uent, "UB RAS: no need to recover with cluster mode\n");
		} else {
			if (entry.severity == RAS_UC_FE)
				ub_do_recovery(uent, ub_channel_io_frozen, &entry);
			else if (entry.severity == RAS_UC_NFE)
				ub_do_recovery(uent, ub_channel_io_normal, &entry);
		}

		ras_cap_regs_free(&entry.regs);
		ub_entity_put(uent);
	}
}

static inline void ras_recover_entry_init(struct ras_recover_entry *entry,
					  struct cper_sec_ubus *ubus_err)
{
	entry->eid = ubus_err->eid;
	entry->cna = ubus_err->cna;
	entry->port = ubus_err->port;
	entry->vendor = ubus_err->vendor;
	entry->device = ubus_err->device;
	entry->type = ubus_err->type;
	entry->class_code = ubus_err->class_code;
}

static DEFINE_SPINLOCK(ub_ras_recover_ring_lock);
static DECLARE_WORK(ub_ras_recover_work, ub_ras_recover_work_func);

static void ub_ras_recover_queue(struct cper_sec_ubus *ubus_err, int severity)
{
#define PORT_VALID_BIT 0b100ULL
#define OVERFLOW_FLAG_BIT 0b10000ULL
	int ub_severity = cper_severity_to_ub_ras(severity);
	struct ras_cap_regs *ras_cap, *tmp_cap;
	struct ras_recover_entry entry = {};
	u32 overflow = 0;
	u32 err_status;
	u32 err_level;

	if (ubus_err->validation_bits & OVERFLOW_FLAG_BIT) {
		overflow = ubus_err->overflow_flag;
		pr_info("severity %s is overflowed, flag=%#x\n",
			RAS_SEVERITY_STR(ub_severity), overflow);
	}

	tmp_cap = (struct ras_cap_regs *)ubus_err->err_info;
	err_status = (ub_severity == RAS_CE) ?
		     tmp_cap->cor_status : tmp_cap->uncor_status;
	if (err_status == 0 && overflow == 0) {
		pr_info("no need to handle ras with err_status=0x%x, severity=%s\n",
			err_status, RAS_SEVERITY_STR(ub_severity));
		return;
	}

	ras_cap = kzalloc(sizeof(*ras_cap), GFP_ATOMIC);
	if (!ras_cap)
		return;

	memcpy(ras_cap, tmp_cap, sizeof(struct ras_cap_regs));
	err_level = (ubus_err->validation_bits & PORT_VALID_BIT) ?
		    RAS_ERR_PORT_LEVEL : RAS_ERR_DEVICE_LEVEL;
	ras_recover_entry_init(&entry, ubus_err);
	entry.err_level = err_level;
	entry.severity = ub_severity;
	entry.overflow = overflow;
	entry.regs = ras_cap;

	if (kfifo_in_spinlocked(&ras_recover_ring, &entry, 1,
				&ub_ras_recover_ring_lock)) {
		schedule_work(&ub_ras_recover_work);
		return;
	}

	if (ub_severity == RAS_UC_FE)
		pr_err("FIFO ring overflow when recovering error for eid:%05x, severity:%s\n",
				ubus_err->eid, RAS_SEVERITY_STR(ub_severity));
	else
		pr_err("FIFO ring overflow when recovering error for eid:%05x, port:%u, severity:%s\n",
				ubus_err->eid, ubus_err->port,
				RAS_SEVERITY_STR(ub_severity));

	kfree(ras_cap);
}

void ub_ras_init(void)
{
	ub_ras_register_recover_func(ub_ras_recover_queue);
}

void ub_ras_uninit(void)
{
	ub_ras_register_recover_func(NULL);
	(void)flush_work(&ub_ras_recover_work);
}
