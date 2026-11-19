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
#include <linux/ipmi_msgdefs.h>
#include <linux/ipmi_smi.h>
#include <linux/notifier.h>
#include <linux/reboot.h>
#include <linux/acpi.h>
#include <linux/workqueue.h>
#include <linux/kfifo.h>
#include <linux/delay.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/mm.h>
#include <linux/nodemask.h>
#include <asm/unaligned.h>

#ifdef CONFIG_ARM64
#include <asm/cputype.h>
#endif

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

/* OEM NetFn and Cmd */
#define OEM_NETFN	0x30
#define OEM_CMD		0x92

/*
 * Max OEM payload size (msg.data_len).  The local IPMI interface caps
 * data_len at IPMI_MAX_MSG_LENGTH - 2 (NetFn/LUN + Cmd header bytes).
 */
#define PSO_OEM_PAYLOAD_MAX	(IPMI_MAX_MSG_LENGTH - 2)

#define PSO_OEM_IANA_0		0xdb
#define PSO_OEM_IANA_1		0x07
#define PSO_OEM_IANA_2		0x00
#define PSO_OEM_HDR_LEN		4	/* IANA(3) + SubCmd(1) */

#define PSO_SUBCMD_POLICY	0x42
#define PSO_SUBCMD_EVENT	0x65

/* Policy subcommand payload values */
#define PSO_POLICY_ENABLE_VAL	0x05
#define PSO_POLICY_DISABLE_VAL	0x04

#define PSO_DRIVER_NAME "[hisi pso] "

/* Bound IPMI user and interface number (-1 if not bound) */
static struct ipmi_user *ipmi_pso_user;
static int pso_ifnum = -1;

/* Monotonically increasing message id for response correlation */
static atomic_t pso_msg_seq = ATOMIC_INIT(0);

/**
 * pso_send_oem - shared transport for all PSO OEM commands
 * @subcmd: SubCmd discriminator (4th payload byte)
 * @tail: payload bytes following the common IANA+SubCmd header
 * @tail_len: number of bytes in @tail
 *
 * Frames the common IANA+SubCmd header plus the command-specific tail
 * and submits it via ipmi_request_settime().  The BMC response arrives
 * asynchronously via pso_recv(); a 0 return only means submission OK.
 */
static int pso_send_oem(u8 subcmd, const u8 *tail, u8 tail_len)
{
	struct ipmi_system_interface_addr addr;
	struct kernel_ipmi_msg msg;
	u8 data[PSO_OEM_PAYLOAD_MAX];
	long msgid;
	int rv;

	if (!ipmi_pso_user) {
		pr_err(PSO_DRIVER_NAME "send failed: no ipmi user (ENODEV)\n");
		return -ENODEV;
	}
	if (tail_len > PSO_OEM_PAYLOAD_MAX - PSO_OEM_HDR_LEN) {
		pr_err(PSO_DRIVER_NAME "payload too long: %u bytes\n",
			tail_len);
		return -EINVAL;
	}

	data[0] = PSO_OEM_IANA_0;
	data[1] = PSO_OEM_IANA_1;
	data[2] = PSO_OEM_IANA_2;
	data[3] = subcmd;
	if (tail_len)
		memcpy(data + PSO_OEM_HDR_LEN, tail, tail_len);

	/* Target: local BMC system interface */
	addr.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
	addr.channel = IPMI_BMC_CHANNEL;
	addr.lun = 0;

	msg.netfn = OEM_NETFN;
	msg.cmd = OEM_CMD;
	msg.data_len = PSO_OEM_HDR_LEN + tail_len;
	msg.data = data;

	msgid = atomic_inc_return(&pso_msg_seq);
	rv = ipmi_request_settime(ipmi_pso_user, (struct ipmi_addr *)&addr,
				msgid, &msg, NULL, 0, 0, 0);
	if (rv) {
		pr_err(PSO_DRIVER_NAME "ipmi_request_settime failed: %d\n", rv);
		return rv;
	}

	pr_info(PSO_DRIVER_NAME "sent SubCmd %#x, msg_id=%ld\n", subcmd, msgid);
	print_hex_dump_debug(PSO_DRIVER_NAME, DUMP_PREFIX_NONE, 16, 1,
				data, msg.data_len, false);
	return 0;
}

/* ------------------------------------------------------------------ */
/*
 * Page offline event reporting: forward isolated page events to the
 * BMC.  The hwpoison notifier callback only copies the event into a
 * kfifo and queues a work item; the work handler does the IPMI send.
 */

/* Isolated page event as reported over IPMI */
struct pso_event {
	u64 phys_base;		/* (un)isolated compound page base address */
	u64 size_mask;		/* isolation granularity mask: size = mask + 1 */
	bool online;		/* direction: true = restored (record removal),
				 * false = isolated (record addition) */
	bool hard;		/* severity, offline events only: true = UCE
				 * hard offline; always false for online */
	bool success;		/* offline result: true = isolated, false =
				 * offline failed; always true for online */
	int reason;		/* raw failure code from mm (errno / mf_result),
				 * meaningful on !success */
};

#define PSO_EVENT_FIFO_DEPTH		256
#define PSO_EVENT_BATCH_MAX		32
#define PSO_EVENT_RETRY_DELAY_MS	10
#define PSO_EVENT_MAX_ATTEMPTS		3

static DEFINE_KFIFO(pso_event_fifo, struct pso_event, PSO_EVENT_FIFO_DEPTH);
static DEFINE_SPINLOCK(pso_event_lock);
static struct work_struct pso_event_work;
static struct workqueue_struct *pso_event_wq;

/*
 * Event subcommand (0x65) payload tail layout, 35 bytes total:
 *
 *   [0]      global system id, fixed 0x01
 *   [1]      local system id, fixed 0x00
 *   [2]      operation type: 0x06 = report isolation,
 *            0x11 = clear isolation record (reboot bulk clear: result
 *            byte followed by all 0xff wildcard, see pso_send_clear_all)
 *   [3]      execution result: bit7 = 1 failed / 0 succeeded,
 *            bit[0:6] = failure reason (see PSO_FAIL_*)
 *   [4]      isolation type, fixed 0x06 = single-address fault
 *   [5:12]   isolated base address, 8 bytes, little-endian
 *   [13:16]  page size mask, 4 bytes, little-endian
 *   [17]     page online status: 0x00 = offline, 0x01 = online
 *   [18:34]  reserved, 17 bytes, must be 0xff
 *
 * NOTE: the protocol has no field carrying the hard/soft offline
 * discriminator (event->hard); it is not reported until the BMC
 * extends byte[9] (isolation type) for it.
 */
#define PSO_EVENT_TAIL_LEN	35

#define PSO_EVENT_GLOBAL_SYSID	0x01
#define PSO_EVENT_LOCAL_SYSID	0x00
#define PSO_EVENT_OP_REPORT	0x06
#define PSO_EVENT_OP_CLEAR	0x11
#define PSO_EVENT_ISOLATE_TYPE	0x06
#define PSO_EVENT_ONLINE	0x01
#define PSO_EVENT_OFFLINE	0x00

/* tail byte offsets */
#define PSO_TAIL_GLOBAL_SYSID	0
#define PSO_TAIL_LOCAL_SYSID	1
#define PSO_TAIL_OP		2
#define PSO_TAIL_RESULT		3
#define PSO_TAIL_ISOLATE_TYPE	4
#define PSO_TAIL_PHYS_BASE	5	/* 8 bytes, little-endian */
#define PSO_TAIL_SIZE_MASK	13	/* 4 bytes, little-endian */
#define PSO_TAIL_ONLINE		17
#define PSO_TAIL_RESERVED	18	/* 17 bytes, 0xff */

/* execution result byte (tail offset 3) */
#define PSO_RESULT_FAILED	BIT(7)
#define PSO_FAIL_INVALID_PARAM	0x02	/* 2: invalid address parameter */
#define PSO_FAIL_ISOLATE	0x04	/* 4: offline execution failed */

/**
* pso_send_event - SubCmd PSO_SUBCMD_EVENT: report one isolation event
* @event: the isolation event to report
*
* Builds the 35-byte OEM event tail and submits it via the shared
* transport.  An offline event maps to operation 0x06 (report); an
* online event (page restored, BMC record must be removed) maps to
* operation 0x11 (clear).
*/
static int pso_send_event(const struct pso_event *event)
{
	u8 tail[PSO_EVENT_TAIL_LEN];

	/*
	 * The protocol carries no soft/hard discriminator: both
	 * severities are reported identically on the wire.  Log it
	 * locally so the severity stays observable in dmesg.
	 */
	pr_info(PSO_DRIVER_NAME "event: base=%#llx mask=%#llx online=%d hard=%d success=%d reason=%d\n",
		event->phys_base, event->size_mask, event->online,
		event->hard, event->success, event->reason);

	/* fill everything first: reserved bytes default to 0xff */
	memset(tail, 0xff, sizeof(tail));
	tail[PSO_TAIL_GLOBAL_SYSID] = PSO_EVENT_GLOBAL_SYSID;
	tail[PSO_TAIL_LOCAL_SYSID] = PSO_EVENT_LOCAL_SYSID;
	tail[PSO_TAIL_OP] = event->online ?
				PSO_EVENT_OP_CLEAR : PSO_EVENT_OP_REPORT;
	/*
	 * Map the raw mm failure code onto the wire reason:
	 *   -ENXIO (invalid address) -> PSO_FAIL_INVALID_PARAM
	 *   everything else          -> PSO_FAIL_ISOLATE
	 */
	tail[PSO_TAIL_RESULT] = event->success ? 0 :
				(PSO_RESULT_FAILED |
				 (event->reason == -ENXIO ?
				  PSO_FAIL_INVALID_PARAM : PSO_FAIL_ISOLATE));
	tail[PSO_TAIL_ISOLATE_TYPE] = PSO_EVENT_ISOLATE_TYPE;
	put_unaligned_le64(event->phys_base, &tail[PSO_TAIL_PHYS_BASE]);
	/* granularity mask (4K = 0xfff, 2M = 0x1fffff) fits in 32 bits */
	put_unaligned_le32((u32)event->size_mask, &tail[PSO_TAIL_SIZE_MASK]);
	tail[PSO_TAIL_ONLINE] = event->online ?
				PSO_EVENT_ONLINE : PSO_EVENT_OFFLINE;

	return pso_send_oem(PSO_SUBCMD_EVENT, tail, PSO_EVENT_TAIL_LEN);
}

/**
* pso_send_clear_all - SubCmd PSO_SUBCMD_EVENT: clear all BMC records
*
* Bulk clear sent on the reboot path: op = 0x11, result = success, and
* every byte after the result field is the 0xff wildcard, so the BMC
* drops the whole record table instead of matching one (base, mask).
*
* The BMC must not clear implicitly on disable (0x42): module unload
* sends disable too, and its records have to survive.  Clearing is
* therefore an explicit OS notification at end of kernel lifetime.
*/
static int pso_send_clear_all(void)
{
	u8 tail[PSO_EVENT_TAIL_LEN];

	memset(tail, 0xff, sizeof(tail));
	tail[PSO_TAIL_GLOBAL_SYSID] = PSO_EVENT_GLOBAL_SYSID;
	tail[PSO_TAIL_LOCAL_SYSID] = PSO_EVENT_LOCAL_SYSID;
	tail[PSO_TAIL_OP] = PSO_EVENT_OP_CLEAR;
	tail[PSO_TAIL_RESULT] = 0;

	return pso_send_oem(PSO_SUBCMD_EVENT, tail, PSO_EVENT_TAIL_LEN);
}

/*
 * DDR-only scope: the BMC interface currently covers DDR isolation only.
 * HBM (and any other non-DDR tier, e.g. CXL) comes online as CPU-less
 * memory-only NUMA nodes, while DDR nodes always host CPUs.  The kernel
 * has no first-class HBM marker, so the CPU-less memory node test is
 * used as the HBM proxy.  Set ddr_only=0 once the protocol grows HBM
 * coverage.
 */
static bool ddr_only = true;
module_param(ddr_only, bool, 0444);
MODULE_PARM_DESC(ddr_only,
	"report DDR pages only, skip memory-only NUMA nodes such as HBM (default: Y)");

/**
* pso_is_hbm - test whether @phys_base belongs to non-DDR memory
* @phys_base: base address of the reported (compound) page
*/
static bool pso_is_hbm(u64 phys_base)
{
	unsigned long pfn = phys_base >> PAGE_SHIFT;
	int nid;

	/* Invalid address: cannot determine the NUMA node, keep the event. */
	if (!pfn_valid(pfn))
		return false;

	nid = page_to_nid(pfn_to_page(pfn));

	return node_state(nid, N_MEMORY) && !node_state(nid, N_CPU);
}

/**
* ipmi_pso_event_call - hwpoison notifier callback
* @nb: unused
* @action: unused
* @data: struct hwpoison_event snapshot (stack object: copy, don't retain)
*
* Copies the snapshot into the fifo and queues pso_event_work.  Stays
* atomic-context safe: no allocation, no sleeping, no IPMI I/O.
*/
static int ipmi_pso_event_call(struct notifier_block *nb,
			       unsigned long action, void *data)
{
	struct hwpoison_event *ev = data;
	struct pso_event event;
	unsigned long flags;

	if (!ev)
		return NOTIFY_DONE;

	/* Only DDR isolation is in scope; skip HBM (memory-only nodes). */
	if (ddr_only && pso_is_hbm(ev->phys_base)) {
		pr_info_ratelimited(PSO_DRIVER_NAME "drop HBM event: base=%#llx online=%d\n",
			ev->phys_base, ev->online);
		return NOTIFY_DONE;
	}

	event = (struct pso_event){
		.phys_base = ev->phys_base,
		.size_mask = ev->size_mask,
		.online = ev->online,
		.hard = ev->hard,
		.success = ev->success,
		.reason = ev->reason,
	};

	spin_lock_irqsave(&pso_event_lock, flags);
	if (kfifo_in(&pso_event_fifo, &event, 1) != 1) {
		spin_unlock_irqrestore(&pso_event_lock, flags);
		pr_warn_ratelimited(PSO_DRIVER_NAME "event fifo full, dropped\n");
		return NOTIFY_DONE;
	}
	spin_unlock_irqrestore(&pso_event_lock, flags);

	queue_work(pso_event_wq, &pso_event_work);
	return NOTIFY_OK;
}

static struct notifier_block pso_event_nb = {
	.notifier_call = ipmi_pso_event_call,
};

/**
* pso_event_work_handler - dequeue events and report them to the BMC
*
* Serialized by the ordered workqueue: retrying the head event in place
* preserves strict FIFO order.  Each event is tried up to
* PSO_EVENT_MAX_ATTEMPTS times, then dropped.
*
* Events are drained in bounded batches: one lock acquisition pops up to
* PSO_EVENT_BATCH_MAX events, amortizing the lock cost against the many
* producers during an error storm.
*/
static void pso_event_work_handler(struct work_struct *work)
{
	struct pso_event batch[PSO_EVENT_BATCH_MAX];
	unsigned int out, i;
	unsigned long flags;
	int attempt;

	for (;;) {
		spin_lock_irqsave(&pso_event_lock, flags);
		out = kfifo_out(&pso_event_fifo, batch, PSO_EVENT_BATCH_MAX);
		spin_unlock_irqrestore(&pso_event_lock, flags);

		if (!out)
			return;		/* fifo empty */

		for (i = 0; i < out; i++) {
			for (attempt = 0; attempt < PSO_EVENT_MAX_ATTEMPTS; attempt++) {
				if (!pso_send_event(&batch[i]))
					break;
				msleep(PSO_EVENT_RETRY_DELAY_MS);
			}

			if (attempt >= PSO_EVENT_MAX_ATTEMPTS)
				pr_warn_ratelimited(PSO_DRIVER_NAME
					"event report failed after %d attempts, dropped (base=%#llx online=%d)\n",
					attempt, batch[i].phys_base, batch[i].online);
		}
	}
}

/**
* pso_event_fifo_reset - drop all queued events (called on reboot path)
*
* Caller must have canceled pso_event_work first.
*/
static void pso_event_fifo_reset(void)
{
	unsigned long flags;

	spin_lock_irqsave(&pso_event_lock, flags);
	kfifo_reset(&pso_event_fifo);
	spin_unlock_irqrestore(&pso_event_lock, flags);
}

extern int sysctl_apei_page_offline_policy;

/* sysctl_apei_page_offline_policy bit definitions */
#define PSO_POLICY_ENABLE	BIT(0)   /* bit 0: PSO on/off */

static struct work_struct pso_policy_work;
static bool pso_target_policy;

/**
 * pso_send_policy - interface 1 (SubCmd PSO_SUBCMD_POLICY): sync PSO enable/disable
 * @enable: true = enable, false = disable
 *
 * Payload tail is a single byte: 0x05 enable / 0x04 disable.
 */
static int pso_send_policy(bool enable)
{
	u8 tail = enable ? PSO_POLICY_ENABLE_VAL : PSO_POLICY_DISABLE_VAL;

	return pso_send_oem(PSO_SUBCMD_POLICY, &tail, sizeof(tail));
}

/**
 * pso_policy_work_handler - send the policy command for the current target
 */
static void pso_policy_work_handler(struct work_struct *work)
{
	pso_send_policy(READ_ONCE(pso_target_policy));
}

/**
 * pso_send_policy_async - defer a policy send
 * @enable: desired state (true = enable, false = disable)
 */
static void pso_send_policy_async(bool enable)
{
	WRITE_ONCE(pso_target_policy, enable);
	if (ipmi_pso_user)
		schedule_work(&pso_policy_work);
	else
		pr_err(PSO_DRIVER_NAME "ipmi_pso_user is NULL, dropping command\n");
}

/**
* pso_policy_notifier_call - APEI policy notifier: sync PSO policy state
* @data: pointer to sysctl_apei_page_offline_policy value
*/
static int pso_policy_notifier_call(struct notifier_block *nb, unsigned long action, void *data)
{
	int policy = *(int *)data;

	pso_send_policy_async(policy & PSO_POLICY_ENABLE);
	return NOTIFY_OK;
}

static struct notifier_block pso_policy_nb = {
	.notifier_call = pso_policy_notifier_call,
};

/**
* ipmi_pso_reboot_handler - Reboot notifier: drop queued events, clear
* all BMC records, then disable
* @code: reboot/halt/poweroff code
*/
static int ipmi_pso_reboot_handler(struct notifier_block *nb, unsigned long code, void *cmd)
{
	if (!ipmi_pso_user) {
		return NOTIFY_OK;
	}

	if (code != SYS_RESTART && code != SYS_HALT && code != SYS_POWER_OFF) {
		return NOTIFY_OK;
	}

	cancel_work_sync(&pso_event_work);
	pso_event_fifo_reset();

	/*
	 * Explicit bulk clear (0x65 op=0x11, wildcard tail): the BMC
	 * must not act on disable alone, because rmmod sends disable
	 * too and its records must survive.  Sent before the disable
	 * below: 0x65 is only accepted while the feature is enabled.
	 */
	if (pso_send_clear_all())
		pr_warn(PSO_DRIVER_NAME "clear-all command failed on reboot\n");

	cancel_work_sync(&pso_policy_work);
	if (pso_send_policy(false) == 0)
		sysctl_apei_page_offline_policy &= ~PSO_POLICY_ENABLE;

	return NOTIFY_OK;
}

static struct notifier_block ipmi_pso_reboot_nb = {
	.notifier_call = ipmi_pso_reboot_handler,
	.priority     = 0,
};

/**
* pso_recv - IPMI response callback: log result, free message
*
* The first response data byte is the completion code: 0x00 means the
* BMC accepted the command.  No further response parsing is needed.
*/
static void pso_recv(struct ipmi_recv_msg *msg, void *user_msg_data)
{
	if (msg->msg.data_len >= 1) {
		u8 cc = msg->msg.data[0];

		if (cc == 0)
			pr_info(PSO_DRIVER_NAME "BMC command succeeded, msg_id=%ld\n", msg->msgid);
		else
			pr_warn(PSO_DRIVER_NAME "BMC command failed, msg_id=%ld, cc=0x%02x\n",
				msg->msgid, cc);
	}
	ipmi_free_recv_msg(msg);
}

static const struct ipmi_user_hndl pso_hndl = {
	.ipmi_recv_hndl = pso_recv,
};

/**
* ipmi_pso_new_smi - Watcher callback when a new IPMI interface appears
*
* Binds to the first interface seen: creates user and sends enable.
* Further interfaces are ignored once bound.
*/
static void ipmi_pso_new_smi(int if_num, struct device *dev)
{
	int rv;

	if (ipmi_pso_user) {
		pr_debug(PSO_DRIVER_NAME "new_smi if%d: already bound to if%d, skip\n",
			if_num, pso_ifnum);
		return;
	}

	rv = ipmi_create_user(if_num, &pso_hndl, NULL, &ipmi_pso_user);
	if (rv) {
		pr_err(PSO_DRIVER_NAME "ipmi_create_user(if%d) failed: %d\n", if_num, rv);
		return;
	}
	pr_info(PSO_DRIVER_NAME "new IPMI interface if%d, creating user\n", if_num);

	pso_ifnum = if_num;
	rv = pso_send_policy(true);
	if (rv)
		pr_warn(PSO_DRIVER_NAME "enable command failed on if%d: %d\n", if_num, rv);
	else {
		sysctl_apei_page_offline_policy |= PSO_POLICY_ENABLE;
		pr_info(PSO_DRIVER_NAME "enable command succeeded, set sysctl_apei_page_offline_policy=%d\n",
			sysctl_apei_page_offline_policy);
	}
}

/**
* ipmi_pso_smi_gone - Watcher callback when an IPMI interface is removed
* @if_num: interface number (-1 when called from module exit)
*
* On module exit (@if_num == -1) sends disable first, then destroys
* the user.
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
		rv = pso_send_policy(false);
		if (rv)
			pr_warn(PSO_DRIVER_NAME "disable command failed: %d\n", rv);
		else
			sysctl_apei_page_offline_policy &= ~PSO_POLICY_ENABLE;
	} else {
		pr_info(PSO_DRIVER_NAME "interface if%d gone, unbinding\n", if_num);
		cancel_work_sync(&pso_event_work);
		cancel_work_sync(&pso_policy_work);
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
* ipmi_pso_init - Module init: register SMI watcher, reboot/APEI policy/
* hwpoison notifiers and the event workqueue.  Failure rolls back in
* reverse order.
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

	rv = register_reboot_notifier(&ipmi_pso_reboot_nb);
	if (rv) {
		pr_err(PSO_DRIVER_NAME "register_reboot_notifier failed: %d\n", rv);
		goto out_unreg_watcher;
	}

	INIT_WORK(&pso_policy_work, pso_policy_work_handler);
	rv = register_apei_page_offline_notifier(&pso_policy_nb);
	if (rv) {
		pr_err(PSO_DRIVER_NAME "register_apei_page_offline_notifier failed: %d\n", rv);
		goto out_unreg_reboot;
	}

	pso_event_wq = alloc_ordered_workqueue("hisi-pso-event", 0);
	if (!pso_event_wq) {
		pr_err(PSO_DRIVER_NAME "alloc_ordered_workqueue failed\n");
		rv = -ENOMEM;
		goto out_unreg_policy;
	}

	INIT_WORK(&pso_event_work, pso_event_work_handler);
	rv = register_hwpoison_notifier(&pso_event_nb);
	if (rv) {
		pr_err(PSO_DRIVER_NAME "register_hwpoison_notifier failed: %d\n", rv);
		goto out_destroy_wq;
	}
	pr_info(PSO_DRIVER_NAME "module loaded\n");

	return 0;

out_destroy_wq:
	destroy_workqueue(pso_event_wq);
	pso_event_wq = NULL;
out_unreg_policy:
	unregister_apei_page_offline_notifier(&pso_policy_nb);
out_unreg_reboot:
	unregister_reboot_notifier(&ipmi_pso_reboot_nb);
out_unreg_watcher:
	ipmi_smi_watcher_unregister(&ipmi_pso_watcher);
	return rv;
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

	unregister_apei_page_offline_notifier(&pso_policy_nb);
	unregister_hwpoison_notifier(&pso_event_nb);
	cancel_work_sync(&pso_event_work);
	destroy_workqueue(pso_event_wq);
	pso_event_wq = NULL;
	cancel_work_sync(&pso_policy_work);
	unregister_reboot_notifier(&ipmi_pso_reboot_nb);
	ipmi_smi_watcher_unregister(&ipmi_pso_watcher);
	ipmi_pso_smi_gone(-1);
	pr_info(PSO_DRIVER_NAME "module unloaded\n");
}

module_init(ipmi_pso_init);
module_exit(ipmi_pso_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("HISI IPMI Page Soft Offline policy sync and event reporting");
MODULE_AUTHOR("hewanhan1@huawei.com");
