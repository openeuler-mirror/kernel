// SPDX-License-Identifier: GPL-2.0
/*
* HISI IPMI Page Soft Offline driver
*
* Copyright (c) 2026, Huawei Technologies Co., Ltd.
*/

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/bits.h>
#include <linux/ipmi.h>
#include <linux/ipmi_smi.h>
#include <linux/completion.h>
#include <linux/notifier.h>
#include <linux/reboot.h>
#include <linux/acpi.h>

#ifdef CONFIG_ARM64
#include <asm/cputype.h>
#endif

/* OEM NetFn and Cmd for page soft offline control */
#define OEM_NETFN   0x30
#define OEM_CMD     0x92

#define PSO_DRIVER_NAME "[hisi pso] "

/* Command payload: IANA (3 bytes) + subcmd(0x42) + enable(0x05)/disable(0x04) */
static const u8 enable_data[]  = { 0xdb, 0x07, 0x00, 0x42, 0x05 };
static const u8 disable_data[] = { 0xdb, 0x07, 0x00, 0x42, 0x04 };

/* Bound IPMI user and interface number (-1 if not bound) */
static struct ipmi_user *ipmi_pso_user;
static int pso_ifnum = -1;

/**
* struct pso_txn - Per-request context for synchronous send
* @done:  completion to wait on until BMC response arrives
* @cc:    IPMI completion code from response (or negative errno)
*/
struct pso_txn {
	struct completion done;
	int cc;
};

/**
* pso_recv - IPMI response callback
* @msg:           response message from BMC
* @user_msg_data: &pso_txn for this request (passed via ipmi_request_settime)
*
* Fills txn->cc from the first byte of response (completion code) and
* wakes up the thread waiting in pso_send().
*/
static void pso_recv(struct ipmi_recv_msg *msg, void *user_msg_data)
{
	struct pso_txn *txn = msg->user_msg_data;

	if (txn) {
		pr_debug(PSO_DRIVER_NAME "response received: msg_id=%ld\n", msg->msgid);
		txn->cc = (msg->msg.data_len >= 1) ? msg->msg.data[0] : -EIO;
		complete(&txn->done);
	}
	ipmi_free_recv_msg(msg);
}

static const struct ipmi_user_hndl pso_hndl = {
	.ipmi_recv_hndl = pso_recv,
};

/**
* pso_send - Send enable or disable command to BMC (blocking)
* @enable: true = enable page soft offline, false = disable
*
* Uses system interface address and OEM netfn/cmd. Payload: IANA + 0x42 + 0x05/0x04.
* Waits up to 3s for response. Returns 0 on success (BMC completion code 0),
* negative errno on failure.
*/
static int pso_send(bool enable)
{
	struct ipmi_system_interface_addr addr;
	struct kernel_ipmi_msg msg;
	struct pso_txn txn;
	u8 data[5];
	int rv;

	if (!ipmi_pso_user) {
		pr_err(PSO_DRIVER_NAME "send failed: no ipmi user (ENODEV)\n");
		return -ENODEV;
	}

	pr_info(PSO_DRIVER_NAME "sending %s command (netfn=0x%02x cmd=0x%02x)\n",
			enable ? "enable" : "disable", OEM_NETFN, OEM_CMD);

	init_completion(&txn.done);
	txn.cc = -ETIMEDOUT;

	/* Target: local BMC system interface */
	addr.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
	addr.channel = IPMI_BMC_CHANNEL;
	addr.lun = 0;

	msg.netfn = OEM_NETFN;
	msg.cmd = OEM_CMD;
	msg.data_len = sizeof(data);
	msg.data = data;
	memcpy(data, enable ? enable_data : disable_data, sizeof(data));

	rv = ipmi_request_settime(ipmi_pso_user, (struct ipmi_addr *)&addr,
				enable ? 1 : 2, &msg, &txn, 0, 0, 0);
	if (rv) {
		pr_err(PSO_DRIVER_NAME "ipmi_request_settime failed: %d\n", rv);
		return rv;
	}

	if (!wait_for_completion_timeout(&txn.done, msecs_to_jiffies(3000))) {
		pr_err(PSO_DRIVER_NAME "wait for BMC response timeout\n");
		return -ETIMEDOUT;
	}

	if (txn.cc == 0) {
		pr_info(PSO_DRIVER_NAME "%s command completed successfully\n",
			enable ? "enable" : "disable");
		return 0;
	}
	pr_err(PSO_DRIVER_NAME "%s command failed: completion code 0x%02x\n",
		enable ? "enable" : "disable", (unsigned int)(txn.cc & 0xff));
	return (txn.cc < 0) ? txn.cc : -EIO;
}

/**
* is_hisi_soc - check if the system is running on a HISI SoC
* HiSilicon SoC only supports ARM64 architecture.
*/
static bool is_hisi_soc(void)
{
#ifdef CONFIG_ARM64
	return read_cpuid_implementor() == ARM_CPU_IMP_HISI;
#else
	return false;
#endif
}

extern int sysctl_apei_page_offline_policy;

/* sysctl_apei_page_offline_policy bit definitions */
#define PSO_ENABLE              BIT(0)   /* bit 0: enable/disable page soft offline */

/*
* ipmi_pso_notifier_call - notifier callback function
* @nb: notifier block
* @action: action
* @data: data
*
* This function is called when the unsigned long control variable changes.
* The function sends the PSO command based on the value of the unsigned long control variable.
*/
static int ipmi_pso_notifier_call(struct notifier_block *nb, unsigned long action, void *data)
{
	int *policy_ptr = (int *)data;
	int policy = *policy_ptr;

	pr_info(PSO_DRIVER_NAME "notifier policy val: %d\n", policy);
	if (pso_send((policy & PSO_ENABLE) ? true : false)) {
		pr_warn(PSO_DRIVER_NAME "notifier: pso_send failed \n");
	}
	return NOTIFY_OK;
}

static struct notifier_block ipmi_pso_nb = {
	.notifier_call = ipmi_pso_notifier_call,
};

/**
* ipmi_pso_new_smi - Watcher callback when a new IPMI interface appears
* @if_num: interface number assigned by IPMI message handler
* @dev:    device associated with the interface (may be NULL)
*
* Binds to the first interface we see: creates user and sends enable command.
* Ignores further interfaces if already bound.
*/
static void ipmi_pso_new_smi(int if_num, struct device *dev)
{
	int rv;

	if (ipmi_pso_user) {
		pr_debug(PSO_DRIVER_NAME "new_smi if%d: already bound to if%d, skip\n",
			if_num, pso_ifnum);
		return;
	}

	pr_info(PSO_DRIVER_NAME "new IPMI interface if%d, creating user\n", if_num);
	rv = ipmi_create_user(if_num, &pso_hndl, NULL, &ipmi_pso_user);
	if (rv) {
		pr_err(PSO_DRIVER_NAME "ipmi_create_user(if%d) failed: %d\n", if_num, rv);
		return;
	}

	pso_ifnum = if_num;
	rv = pso_send(true);
	if (rv) {
		pr_warn(PSO_DRIVER_NAME "enable command failed on if%d: %d\n", if_num, rv);
	} else {
		sysctl_apei_page_offline_policy |= PSO_ENABLE;
		pr_info(PSO_DRIVER_NAME "enable command succeeded, set sysctl_apei_page_offline_policy=%d\n",
			sysctl_apei_page_offline_policy);
	}
}

/**
* pso_smi_gone - Watcher callback when an IPMI interface is removed
* @if_num: interface number (-1 when called from module exit)
*
* If @if_num is our bound interface (or -1 on unload), sends disable command
* when @if_num == -1, then destroys the user.
*/
static void ipmi_pso_smi_gone(int if_num)
{
	int rv;

	if (!ipmi_pso_user)
		return;
	if (if_num >= 0 && if_num != pso_ifnum) {
		pr_debug(PSO_DRIVER_NAME "smi_gone if%d: not our interface (bound to if%d)\n",
			if_num, pso_ifnum);
		return;
	}

	if (if_num == -1) {
		rv = pso_send(false);
		if (rv) {
			pr_warn(PSO_DRIVER_NAME "disable command failed: %d\n", rv);
		} else {
			sysctl_apei_page_offline_policy &= ~PSO_ENABLE;
		}
	} else {
		pr_info(PSO_DRIVER_NAME "interface if%d gone, unbinding\n", if_num);
	}

	ipmi_destroy_user(ipmi_pso_user);
	ipmi_pso_user = NULL;
	pso_ifnum = -1;
	pr_info(PSO_DRIVER_NAME "user destroyed\n");
}

/* Watcher: notified when an IPMI interface is added or removed */
static struct ipmi_smi_watcher ipmi_pso_watcher = {
	.owner    = THIS_MODULE,
	.new_smi  = ipmi_pso_new_smi,
	.smi_gone = ipmi_pso_smi_gone,
};

/**
* ipmi_pso_reboot_handler - Reboot notifier: send disable to BMC before reboot/halt/power_off
* @nb: notifier block
* @code: code
* @unused: unused
*
* This function is called when the system is rebooted/halted/power off.
* The function sends the disable command to the BMC.
*/
static int ipmi_pso_reboot_handler(struct notifier_block *nb, unsigned long code, void *unused)
{
	if (!ipmi_pso_user) {
		return NOTIFY_OK;
	}

	if (code != SYS_RESTART && code != SYS_HALT && code != SYS_POWER_OFF) {
		return NOTIFY_OK;
	}

	if (pso_send(false) == 0) {
		sysctl_apei_page_offline_policy &= ~PSO_ENABLE;
	}
	return NOTIFY_OK;
}

static struct notifier_block ipmi_pso_reboot_nb = {
	.notifier_call = ipmi_pso_reboot_handler,
	.priority     = 0,
};

/**
* ipmi_pso_init - Module init: register watcher and wait for interface
*
* When an IPMI interface appears, ipmi_pso_new_smi() will bind and send enable.
*/
static int __init ipmi_pso_init(void)
{
	int rv;

	if (!is_hisi_soc()) {
		pr_debug(PSO_DRIVER_NAME "not HISi SoC (MIDR)\n");
		return 0;
	}

	rv = ipmi_smi_watcher_register(&ipmi_pso_watcher);
	if (rv) {
		pr_err(PSO_DRIVER_NAME "ipmi_smi_watcher_register failed: %d\n", rv);
		return rv;
	}
	pr_info(PSO_DRIVER_NAME "watcher registered, waiting for IPMI interface\n");

	rv = register_reboot_notifier(&ipmi_pso_reboot_nb);
	if (rv) {
		pr_err(PSO_DRIVER_NAME "register_reboot_notifier failed: %d\n", rv);
		ipmi_smi_watcher_unregister(&ipmi_pso_watcher);
		return rv;
	}
	pr_info(PSO_DRIVER_NAME "reboot notifier registered\n");

	rv = register_apei_page_offline_notifier(&ipmi_pso_nb);
	if (rv) {
		pr_err(PSO_DRIVER_NAME "register_apei_page_offline_notifier failed: %d\n", rv);
		unregister_reboot_notifier(&ipmi_pso_reboot_nb);
		ipmi_smi_watcher_unregister(&ipmi_pso_watcher);
		return rv;
	}
	pr_info(PSO_DRIVER_NAME "notifier registered\n");
	return 0;
}

/**
* ipmi_pso_exit - Module exit: unregister watcher, send disable, destroy user
*/
static void __exit ipmi_pso_exit(void)
{
	if (!is_hisi_soc()) {
		pr_debug(PSO_DRIVER_NAME "not HISi SoC (MIDR)\n");
		return;
	}

	unregister_apei_page_offline_notifier(&ipmi_pso_nb);
	unregister_reboot_notifier(&ipmi_pso_reboot_nb);
	ipmi_smi_watcher_unregister(&ipmi_pso_watcher);
	ipmi_pso_smi_gone(-1);
	pr_info(PSO_DRIVER_NAME "module unloaded\n");
}

module_init(ipmi_pso_init);
module_exit(ipmi_pso_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("HISI IPMI Page Soft Offline enable/disable");
MODULE_AUTHOR("hewanhan@h-partners.com");
