// SPDX-License-Identifier: GPL-2.0-only
/*
 * HiSilicon uncore frequency scaling driver
 *
 * Copyright (c) 2025 HiSilicon Co., Ltd
 */

#include <linux/acpi.h>
#include <linux/bits.h>
#include <linux/cleanup.h>
#include <linux/cpumask.h>
#include <linux/devfreq.h>
#include <linux/devfreq-event.h>
#include <linux/device.h>
#include <linux/dev_printk.h>
#include <linux/errno.h>
#include <linux/iopoll.h>
#include <linux/kernel.h>
#include <linux/ktime.h>
#include <linux/math64.h>
#include <linux/mailbox_client.h>
#include <linux/module.h>
#include <linux/mod_devicetable.h>
#include <linux/mutex.h>
#include <linux/perf_event.h>
#include <linux/perf/hisi_pmu.h>
#include <linux/platform_device.h>
#include <linux/pm_opp.h>
#include <linux/property.h>
#include <linux/smp.h>
#include <linux/topology.h>
#include <linux/units.h>
#include <acpi/pcc.h>
#include <asm/cputype.h>

#include "governor.h"

struct hisi_uncore_pcc_data {
	u16 status;
	u16 resv;
	u32 data;
};

struct hisi_uncore_pcc_shmem {
	struct acpi_pcct_shared_memory head;
	struct hisi_uncore_pcc_data pcc_data;
};

enum hisi_uncore_pcc_cmd_type {
	HUCF_PCC_CMD_GET_CAP = 0,
	HUCF_PCC_CMD_GET_FREQ,
	HUCF_PCC_CMD_SET_FREQ,
	HUCF_PCC_CMD_GET_MODE,
	HUCF_PCC_CMD_SET_MODE,
	HUCF_PCC_CMD_GET_PLAT_FREQ_NUM,
	HUCF_PCC_CMD_GET_PLAT_FREQ_BY_IDX,
	HUCF_PCC_CMD_MAX = 256
};

static int hisi_platform_gov_usage;
static DEFINE_MUTEX(hisi_platform_gov_usage_lock);

enum hisi_uncore_freq_mode {
	HUCF_MODE_PLATFORM = 0,
	HUCF_MODE_OS,
	HUCF_MODE_MAX
};

#define HUCF_CAP_PLATFORM_CTRL	BIT(0)

/*
 * Upper bound for SCCL ids encoded in MPIDR affinity levels. Used to
 * size the per-domain sccl bitmap; far above any realistic Kunpeng
 * configuration (SCCL ids are typically single digits).
 */
#define HISI_MAX_SCCL		32

/**
 * struct hisi_uncore_freq - hisi uncore frequency scaling device data
 * @dev:		device of this frequency scaling driver
 * @cl:			mailbox client object
 * @pchan:		PCC mailbox channel
 * @chan_id:		PCC channel ID
 * @last_cmd_cmpl_time:	timestamp of the last completed PCC command
 * @pcc_lock:		PCC channel lock
 * @devfreq:		devfreq data of this hisi_uncore_freq device
 * @related_cpus:	CPUs whose performance is majorly affected by this
 *			uncore frequency domain
 * @domain_sccl:	bitmap of MPIDR-derived sccl ids covered by this
 *			freq domain; populated from related_cpus and used
 *			to match hisi uncore PMUs by their hisilicon,scl-id
 *			firmware property
 * @edev:		devfreq-event device backing get_dev_status, or NULL
 *			when no L3C PMU was matched for this freq domain
 * @ondemand_data:	tuning knobs for the simple_ondemand governor,
 *			chosen by L3C PMU revision during event registration
 * @cap:		capability flag
 */
struct hisi_uncore_freq {
	struct device *dev;
	struct mbox_client cl;
	struct pcc_mbox_chan *pchan;
	int chan_id;
	ktime_t last_cmd_cmpl_time;
	struct mutex pcc_lock;
	struct devfreq *devfreq;
	struct cpumask related_cpus;
	DECLARE_BITMAP(domain_sccl, HISI_MAX_SCCL);
	struct devfreq_event_dev *edev;
	struct devfreq_simple_ondemand_data *ondemand_data;
	u32 cap;
};

/* PCC channel timeout = PCC nominal latency * NUM */
#define HUCF_PCC_POLL_TIMEOUT_NUM	1000
#define HUCF_PCC_POLL_INTERVAL_US	5

/* Default polling interval in ms for devfreq governors*/
#define HUCF_DEFAULT_POLLING_MS 100

#define HISI_L3C_EVENT_CYCLES	0x7f

/*
 * A PMU's utilization counter measures either busy or idle cycles,
 * depending on the L3C revision. Record which, so the read path can
 * normalise both to busy (busy = total - idle for the idle case).
 */
enum hucf_util_kind {
	HUCF_UTIL_BUSY,
	HUCF_UTIL_IDLE,
};

/*
 * Per-HID description of the L3C uncore PMU. To support a new revision,
 * add a row with its ACPI HID, the utilization event, its polarity, and
 * the simple_ondemand tuning parameters for that revision.
 */
struct hisi_l3c_pmu_info {
	const char *hid;
	u32 util_event;
	enum hucf_util_kind util_kind;
	struct devfreq_simple_ondemand_data *ondemand_data;
};

static struct devfreq_simple_ondemand_data hisi_l3c_0214_odata = {
	.upthreshold = 10,
	.downdifferential = 0,
};

static struct devfreq_simple_ondemand_data hisi_l3c_0215_odata = {
	.upthreshold = 75,
	.downdifferential = 0,
};

static const struct hisi_l3c_pmu_info hisi_l3c_pmus[] = {
	{ "HISI0214", 0x90, HUCF_UTIL_BUSY, &hisi_l3c_0214_odata },
	{ "HISI0215", 0x96, HUCF_UTIL_IDLE, &hisi_l3c_0215_odata },
};

struct evset {
	struct perf_event *util;
	struct perf_event *total;
	u64 prev_util;
	u64 prev_total;
	enum hucf_util_kind util_kind;
};

struct hisi_uncore_event {
	struct evset *evset;
	int nr_ev;
};

static const struct hisi_l3c_pmu_info *hisi_l3c_pmu_info_get(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(hisi_l3c_pmus); i++)
		if (acpi_dev_present(hisi_l3c_pmus[i].hid, NULL, -1))
			return &hisi_l3c_pmus[i];

	return NULL;
}

static void hisi_uncore_read_mpidr_cb(void *info)
{
	u64 *mpidr = info;

	*mpidr = read_cpuid_mpidr();
}

/*
 * Decode the SCCL and CCL ids for a remote @cpu from its MPIDR.
 * Returns 0 on success, or a negative errno if @cpu is offline or otherwise
 * unreachable.
 */
static int hisi_uncore_cpu_sccl_ccl(int cpu, int *sccl, int *ccl)
{
	u64 mpidr;
	int rc;

	rc = smp_call_function_single(cpu, hisi_uncore_read_mpidr_cb,
				      &mpidr, 1);
	if (rc)
		return rc;

	if (mpidr & MPIDR_MT_BITMASK) {
		*sccl = MPIDR_AFFINITY_LEVEL(mpidr, 3);
		*ccl  = MPIDR_AFFINITY_LEVEL(mpidr, 2);
	} else {
		*sccl = MPIDR_AFFINITY_LEVEL(mpidr, 2);
		*ccl  = MPIDR_AFFINITY_LEVEL(mpidr, 1);
	}

	return 0;
}

/*
 * Build the per-domain bitmap of MPIDR-derived sccl ids covered by
 * @uncore. Run after related_cpus has been populated and before any
 * PMU matching is done.
 *
 * Only online CPUs are consulted (IPI-based MPIDR read can't reach
 * offline CPUs). At probe time the related CPUs are normally all
 * online; any SCCL that has at least one online CPU in the domain is
 * recorded, which is sufficient for PMU matching.
 */
static void hisi_uncore_build_domain_sccl(struct hisi_uncore_freq *uncore)
{
	int cpu;

	bitmap_zero(uncore->domain_sccl, HISI_MAX_SCCL);

	for_each_cpu_and(cpu, &uncore->related_cpus, cpu_online_mask) {
		int sccl, ccl;

		if (hisi_uncore_cpu_sccl_ccl(cpu, &sccl, &ccl))
			continue;
		if (sccl >= 0 && sccl < HISI_MAX_SCCL)
			set_bit(sccl, uncore->domain_sccl);
	}
}

/*
 * Is the hisi uncore PMU described by @adev part of @uncore's freq
 * domain? The PMU advertises its SCCL via hisilicon,scl-id; matching
 * is a constant-time lookup in the precomputed domain_sccl bitmap.
 */
static bool hisi_uncore_pmu_in_domain(struct hisi_uncore_freq *uncore,
				      struct acpi_device *adev)
{
	u32 pmu_sccl;

	if (fwnode_property_read_u32(acpi_fwnode_handle(adev),
				     "hisilicon,scl-id", &pmu_sccl))
		return false;

	return pmu_sccl < HISI_MAX_SCCL &&
	       test_bit(pmu_sccl, uncore->domain_sccl);
}

static int hisi_uncore_event_enable(struct devfreq_event_dev *edev)
{
	struct hisi_uncore_event *event = devfreq_event_get_drvdata(edev);
	int i;

	for (i = 0; i < event->nr_ev; i++) {
		perf_event_enable(event->evset[i].util);
		perf_event_enable(event->evset[i].total);
	}
	return 0;
}

static int hisi_uncore_event_disable(struct devfreq_event_dev *edev)
{
	struct hisi_uncore_event *event = devfreq_event_get_drvdata(edev);
	int i;

	for (i = 0; i < event->nr_ev; i++) {
		perf_event_disable(event->evset[i].util);
		perf_event_disable(event->evset[i].total);
	}
	return 0;
}

static int hisi_uncore_event_set(struct devfreq_event_dev *edev)
{
	return 0;
}

/*
 * Return the highest load/total pair from the PMU in this freq domain over the
 * latest poll interval.  A PMU's utilization counter measures busy or idle
 * cycles; both are normalised to load here.
 */
static int hisi_uncore_event_get(struct devfreq_event_dev *edev,
				 struct devfreq_event_data *edata)
{
	struct hisi_uncore_event *event = devfreq_event_get_drvdata(edev);
	u64 cur_util, cur_total, d_util, d_total;
	u64 max_load = 0, max_total = 1;
	u64 ena_u, run_u, ena_t, run_t;
	struct evset *e;
	int i, shift;

	for (i = 0; i < event->nr_ev; i++) {
		e = &event->evset[i];

		cur_util  = perf_event_read_value(e->util,  &ena_u, &run_u);
		cur_total = perf_event_read_value(e->total, &ena_t, &run_t);

		d_util  = cur_util  - e->prev_util;
		d_total = cur_total - e->prev_total;
		e->prev_util  = cur_util;
		e->prev_total = cur_total;

		if (!d_total)
			continue;

		/*
		 * If the PMU was multiplexed (running < enabled), scale the
		 * raw delta up to estimate the full-interval count.
		 */
		if (run_u && run_u != ena_u)
			d_util = mul_u64_u64_div_u64(d_util, ena_u, run_u);
		if (run_t && run_t != ena_t)
			d_total = mul_u64_u64_div_u64(d_total, ena_t, run_t);

		d_util = min(d_util, d_total);
		d_util = (e->util_kind == HUCF_UTIL_IDLE) ? d_total - d_util
							  : d_util;

		/*
		 * Scale down to 32 bits so the following cross multiplication
		 * can't overflow, in case of a long sampling window and
		 * possibly large deltas.
		 */
		shift = fls64(d_total) - 32;
		if (shift > 0) {
			d_util  >>= shift;
			d_total >>= shift;
		}

		if (d_util * max_total > max_load * d_total) {
			max_load  = d_util;
			max_total = d_total;
		}
	}

	edata->load_count  = max_load;
	edata->total_count = max_total;

	return 0;
}

static const struct devfreq_event_ops hisi_uncore_event_ops = {
	.enable    = hisi_uncore_event_enable,
	.disable   = hisi_uncore_event_disable,
	.set_event = hisi_uncore_event_set,
	.get_event = hisi_uncore_event_get,
};

static void devm_hisi_uncore_disable_edev(void *data)
{
	devfreq_event_disable_edev(data);
}

static void hisi_uncore_release_perf_events(void *data)
{
	struct hisi_uncore_event *event = data;
	int i;

	for (i = 0; i < event->nr_ev; i++) {
		if (event->evset[i].util)
			perf_event_release_kernel(event->evset[i].util);
		if (event->evset[i].total)
			perf_event_release_kernel(event->evset[i].total);
	}
}

static int hisi_uncore_create_pmu_events(struct hisi_uncore_freq *uncore,
					 struct acpi_device *adev,
					 const struct hisi_l3c_pmu_info *info,
					 struct evset *evset)
{
	struct device *pmu_dev = acpi_get_first_physical_node(adev);
	struct perf_event_attr attr = {
		.size		= sizeof(attr),
		.disabled	= 1,
	};
	struct perf_event *pe_util, *pe_total;
	int cpu, type;

	/*
	 * The L3C PMU may not be registered yet, e.g. when both drivers are
	 * built in and this one probes first. Wait for it, but not forever,
	 * as basic frequency control works without it.
	 */
	type = pmu_dev ? hisi_uncore_pmu_get_type(pmu_dev) : -ENODEV;
	if (type < 0)
		return driver_deferred_probe_check_state(uncore->dev);

	cpu = cpumask_first_and(&uncore->related_cpus, cpu_online_mask);
	if (cpu >= nr_cpu_ids)
		return -EAGAIN;

	attr.type = type;
	attr.config = info->util_event;
	pe_util = perf_event_create_kernel_counter(&attr, cpu, NULL, NULL, NULL);
	if (IS_ERR(pe_util))
		return PTR_ERR(pe_util);

	attr.config = HISI_L3C_EVENT_CYCLES;
	pe_total = perf_event_create_kernel_counter(&attr, cpu, NULL, NULL, NULL);
	if (IS_ERR(pe_total)) {
		perf_event_release_kernel(pe_util);
		return PTR_ERR(pe_total);
	}

	evset->util  = pe_util;
	evset->total = pe_total;
	evset->util_kind = info->util_kind;

	return 0;
}

static int hisi_uncore_devfreq_event_register(struct hisi_uncore_freq *uncore)
{
	const struct hisi_l3c_pmu_info *pmu_info;
	struct device *dev = uncore->dev;
	struct hisi_uncore_event *event;
	struct devfreq_event_desc *desc;
	struct devfreq_event_dev *edev;
	struct acpi_device *adev;
	int rc, max_pmus = 0;

	if (!IS_ENABLED(CONFIG_HISI_PMU))
		return 0;

	pmu_info = hisi_l3c_pmu_info_get();
	if (!pmu_info)
		return 0;

	for_each_acpi_dev_match(adev, pmu_info->hid, NULL, -1)
		max_pmus++;

	if (!max_pmus)
		return 0;

	hisi_uncore_build_domain_sccl(uncore);

	event = devm_kzalloc(dev, sizeof(*event), GFP_KERNEL);
	if (!event)
		return -ENOMEM;

	event->evset = devm_kcalloc(dev, max_pmus, sizeof(*event->evset),
				    GFP_KERNEL);
	if (!event->evset)
		return -ENOMEM;

	/* Release any partially created perf events on probe failure. */
	rc = devm_add_action_or_reset(dev, hisi_uncore_release_perf_events,
				      event);
	if (rc)
		return rc;

	for_each_acpi_dev_match(adev, pmu_info->hid, NULL, -1) {
		if (!hisi_uncore_pmu_in_domain(uncore, adev))
			continue;

		rc = hisi_uncore_create_pmu_events(uncore, adev, pmu_info,
						   &event->evset[event->nr_ev]);
		if (rc) {
			acpi_dev_put(adev);
			/*
			 * PMU event support is optional. Defer the probe while
			 * the PMU may still show up, otherwise carry on.
			 */
			if (rc == -ETIMEDOUT || rc == -ENODEV || rc == -EAGAIN) {
				dev_info(dev, "PMU unavailable, continue without devfreq-event support\n");
				return 0;
			}
			return rc;
		}
		event->nr_ev++;
	}

	if (!event->nr_ev)
		return 0;

	uncore->ondemand_data = pmu_info->ondemand_data;

	desc = devm_kzalloc(dev, sizeof(*desc), GFP_KERNEL);
	if (!desc)
		return -ENOMEM;

	*desc = (struct devfreq_event_desc) {
		.name = dev_name(dev),
		.driver_data = event,
		.ops = &hisi_uncore_event_ops,
	};

	edev = devm_devfreq_event_add_edev(dev, desc);
	if (IS_ERR(edev))
		return PTR_ERR(edev);

	uncore->edev = edev;

	rc = devfreq_event_enable_edev(edev);
	if (rc)
		return dev_err_probe(dev, rc, "Failed to enable devfreq-event\n");

	return devm_add_action_or_reset(dev, devm_hisi_uncore_disable_edev, edev);
}

/*
 * Load the L3C PMU first when available so its perf PMU is registered before we
 * look it up.  This is a soft dependency: PMU event support is optional and the
 * driver still provides basic frequency control without it.
 */
MODULE_SOFTDEP("pre: hisi_uncore_l3c_pmu");
MODULE_IMPORT_NS(HISI_PMU);

static void hisi_uncore_free_pcc_chan(struct hisi_uncore_freq *uncore)
{
	guard(mutex)(&uncore->pcc_lock);
	pcc_mbox_free_channel(uncore->pchan);
	uncore->pchan = NULL;
}

static void devm_hisi_uncore_free_pcc_chan(void *data)
{
	hisi_uncore_free_pcc_chan(data);
}

static int hisi_uncore_request_pcc_chan(struct hisi_uncore_freq *uncore)
{
	struct device *dev = uncore->dev;
	struct pcc_mbox_chan *pcc_chan;

	uncore->cl = (struct mbox_client) {
		.dev = dev,
		.tx_block = false,
		.knows_txdone = true,
	};

	pcc_chan = pcc_mbox_request_channel(&uncore->cl, uncore->chan_id);
	if (IS_ERR(pcc_chan))
		return dev_err_probe(dev, PTR_ERR(pcc_chan),
			"Failed to request PCC channel %u\n", uncore->chan_id);

	if (!pcc_chan->shmem_base_addr) {
		pcc_mbox_free_channel(pcc_chan);
		return dev_err_probe(dev, -EINVAL,
			"Invalid PCC shared memory address\n");
	}

	if (pcc_chan->shmem_size < sizeof(struct hisi_uncore_pcc_shmem)) {
		pcc_mbox_free_channel(pcc_chan);
		return dev_err_probe(dev, -EINVAL,
			"Invalid PCC shared memory size (%lluB)\n",
			pcc_chan->shmem_size);
	}

	uncore->pchan = pcc_chan;

	return devm_add_action_or_reset(uncore->dev,
					devm_hisi_uncore_free_pcc_chan, uncore);
}

static acpi_status hisi_uncore_pcc_reg_scan(struct acpi_resource *res,
					    void *ctx)
{
	struct acpi_resource_generic_register *reg;
	struct hisi_uncore_freq *uncore;

	if (!res || res->type != ACPI_RESOURCE_TYPE_GENERIC_REGISTER)
		return AE_OK;

	reg = &res->data.generic_reg;
	if (reg->space_id != ACPI_ADR_SPACE_PLATFORM_COMM)
		return AE_OK;

	if (!ctx)
		return AE_ERROR;

	uncore = ctx;
	/* PCC subspace ID stored in Access Size */
	uncore->chan_id = reg->access_size;

	return AE_CTRL_TERMINATE;
}

static int hisi_uncore_init_pcc_chan(struct hisi_uncore_freq *uncore)
{
	acpi_handle handle = ACPI_HANDLE(uncore->dev);
	acpi_status status;
	int rc;

	uncore->chan_id = -1;
	status = acpi_walk_resources(handle, METHOD_NAME__CRS,
				     hisi_uncore_pcc_reg_scan, uncore);
	if (ACPI_FAILURE(status) || uncore->chan_id < 0)
		return dev_err_probe(uncore->dev, -ENODEV,
			"Failed to get a PCC channel\n");


	rc = devm_mutex_init(uncore->dev, &uncore->pcc_lock);
	if (rc)
		return rc;

	return hisi_uncore_request_pcc_chan(uncore);
}

static int hisi_uncore_cmd_send(struct hisi_uncore_freq *uncore,
				u8 cmd, u32 *data)
{
	struct hisi_uncore_pcc_shmem __iomem *addr;
	struct hisi_uncore_pcc_shmem shmem;
	struct pcc_mbox_chan *pchan;
	unsigned int mrtt;
	s64 time_delta;
	u16 status;
	int rc;

	guard(mutex)(&uncore->pcc_lock);

	pchan = uncore->pchan;
	if (!pchan)
		return -ENODEV;

	addr = (struct hisi_uncore_pcc_shmem __iomem *)pchan->shmem;
	if (!addr)
		return -EINVAL;

	/* Handle the Minimum Request Turnaround Time (MRTT) */
	mrtt = pchan->min_turnaround_time;
	time_delta = ktime_us_delta(ktime_get(), uncore->last_cmd_cmpl_time);
	if (mrtt > time_delta)
		udelay(mrtt - time_delta);

	/* Copy data */
	shmem.head = (struct acpi_pcct_shared_memory) {
		.signature = PCC_SIGNATURE | uncore->chan_id,
		.command = cmd,
	};
	shmem.pcc_data.data = *data;
	memcpy_toio(addr, &shmem, sizeof(shmem));

	/* Ring doorbell */
	rc = mbox_send_message(pchan->mchan, &cmd);
	if (rc < 0) {
		dev_err(uncore->dev, "Failed to send mbox message, %d\n", rc);
		return rc;
	}

	/* Wait status */
	rc = readw_poll_timeout(&addr->head.status, status,
				status & (PCC_STATUS_CMD_COMPLETE |
					  PCC_STATUS_ERROR),
				HUCF_PCC_POLL_INTERVAL_US,
				pchan->latency * HUCF_PCC_POLL_TIMEOUT_NUM);
	if (rc) {
		dev_err(uncore->dev, "PCC channel response timeout, cmd=%u\n", cmd);
	} else if (status & PCC_STATUS_ERROR) {
		dev_err(uncore->dev, "PCC cmd error, cmd=%u\n", cmd);
		rc = -EIO;
	}

	uncore->last_cmd_cmpl_time = ktime_get();

	/* Copy data back */
	memcpy_fromio(data, &addr->pcc_data.data, sizeof(*data));

	/* Clear mailbox active req */
	mbox_client_txdone(pchan->mchan, rc);

	return rc;
}

static int hisi_uncore_target(struct device *dev, unsigned long *freq,
			      u32 flags)
{
	struct hisi_uncore_freq *uncore = dev_get_drvdata(dev);
	struct dev_pm_opp *opp;
	u32 data;

	if (WARN_ON(!uncore || !uncore->pchan))
		return -ENODEV;

	opp = devfreq_recommended_opp(dev, freq, flags);
	if (IS_ERR(opp)) {
		dev_err(dev, "Failed to get opp for freq %lu hz\n", *freq);
		return PTR_ERR(opp);
	}

	data = (u32)(dev_pm_opp_get_freq(opp) / HZ_PER_MHZ);

	dev_pm_opp_put(opp);

	return hisi_uncore_cmd_send(uncore, HUCF_PCC_CMD_SET_FREQ, &data);
}

static int hisi_uncore_get_dev_status(struct device *dev,
				      struct devfreq_dev_status *stat)
{
	struct hisi_uncore_freq *uncore = dev_get_drvdata(dev);
	struct devfreq_event_data edata;
	int rc;

	/*
	 * Without the L3C PMU there's no load data. Report a zero total time,
	 * which makes simple_ondemand stay at the max frequency, instead of
	 * failing on every poll.
	 */
	if (!uncore->edev) {
		*stat = (struct devfreq_dev_status) { };
		return 0;
	}

	rc = devfreq_event_get_event(uncore->edev, &edata);
	if (rc < 0)
		return rc;

	stat->busy_time = edata.load_count;
	stat->total_time = edata.total_count;
	stat->current_frequency = uncore->devfreq ?
				  uncore->devfreq->previous_freq : 0;

	return 0;
}

static int hisi_uncore_get_cur_freq(struct device *dev, unsigned long *freq)
{
	struct hisi_uncore_freq *uncore = dev_get_drvdata(dev);
	u32 data = 0;
	int rc;

	if (WARN_ON(!uncore || !uncore->pchan))
		return -ENODEV;

	rc = hisi_uncore_cmd_send(uncore, HUCF_PCC_CMD_GET_FREQ, &data);

	/*
	 * Upon a failure, 'data' remains 0 and 'freq' is set to 0 rather than a
	 * random value.  devfreq shouldn't use 'freq' in that case though.
	 */
	*freq = data * HZ_PER_MHZ;

	return rc;
}

static void devm_hisi_uncore_remove_opp(void *data)
{
	struct hisi_uncore_freq *uncore = data;

	dev_pm_opp_remove_all_dynamic(uncore->dev);
}

static int hisi_uncore_init_opp(struct hisi_uncore_freq *uncore)
{
	struct device *dev = uncore->dev;
	unsigned long freq_mhz;
	u32 num, index;
	u32 data = 0;
	int rc;

	rc = hisi_uncore_cmd_send(uncore, HUCF_PCC_CMD_GET_PLAT_FREQ_NUM,
				  &data);
	if (rc)
		return dev_err_probe(dev, rc, "Failed to get plat freq num\n");

	num = data;

	for (index = 0; index < num; index++) {
		data = index;
		rc = hisi_uncore_cmd_send(uncore,
					  HUCF_PCC_CMD_GET_PLAT_FREQ_BY_IDX,
					  &data);
		if (rc) {
			dev_pm_opp_remove_all_dynamic(dev);
			return dev_err_probe(dev, rc,
				"Failed to get plat freq at index %u\n", index);
		}
		freq_mhz = data;

		/* Don't care OPP voltage, take 1V as default */
		rc = dev_pm_opp_add(dev, freq_mhz * HZ_PER_MHZ, 1000000);
		if (rc) {
			dev_pm_opp_remove_all_dynamic(dev);
			return dev_err_probe(dev, rc,
				"Add OPP %lu failed\n", freq_mhz);
		}
	}

	return devm_add_action_or_reset(dev, devm_hisi_uncore_remove_opp,
					uncore);
}

static int hisi_platform_gov_func(struct devfreq *df, unsigned long *freq)
{
	/*
	 * Platform-controlled mode doesn't care the frequency issued from
	 * devfreq, so just pick the max freq.
	 */
	*freq = DEVFREQ_MAX_FREQ;

	return 0;
}

static int hisi_platform_gov_handler(struct devfreq *df, unsigned int event,
				     void *val)
{
	struct hisi_uncore_freq *uncore = dev_get_drvdata(df->dev.parent);
	int rc = 0;
	u32 data;

	if (WARN_ON(!uncore || !uncore->pchan))
		return -ENODEV;

	switch (event) {
	case DEVFREQ_GOV_START:
		data = HUCF_MODE_PLATFORM;
		rc = hisi_uncore_cmd_send(uncore, HUCF_PCC_CMD_SET_MODE, &data);
		if (rc)
			dev_err(uncore->dev, "Failed to set platform mode (%d)\n", rc);
		break;
	case DEVFREQ_GOV_STOP:
		data = HUCF_MODE_OS;
		rc = hisi_uncore_cmd_send(uncore, HUCF_PCC_CMD_SET_MODE, &data);
		if (rc)
			dev_err(uncore->dev, "Failed to set os mode (%d)\n", rc);
		break;
	default:
		break;
	}

	return rc;
}

/*
 * In the platform-controlled mode, the platform decides the uncore frequency
 * and ignores the frequency issued from the driver.
 * Thus, create a pseudo 'hisi_platform' governor that stops devfreq monitor
 * from working so as to save meaningless overhead.
 */
static struct devfreq_governor hisi_platform_governor = {
	.name = "hisi_platform",
	/*
	 * Set interrupt_driven to skip the devfreq monitor mechanism, though
	 * this governor is not interrupt-driven.
	 */
	.flags = DEVFREQ_GOV_FLAG_IRQ_DRIVEN,
	.get_target_freq = hisi_platform_gov_func,
	.event_handler = hisi_platform_gov_handler,
};

static void hisi_uncore_remove_platform_gov(struct hisi_uncore_freq *uncore)
{
	u32 data = HUCF_MODE_PLATFORM;
	int rc;

	if (!(uncore->cap & HUCF_CAP_PLATFORM_CTRL))
		return;

	guard(mutex)(&hisi_platform_gov_usage_lock);

	if (--hisi_platform_gov_usage == 0) {
		rc = devfreq_remove_governor(&hisi_platform_governor);
		if (rc)
			dev_err(uncore->dev, "Failed to remove hisi_platform gov (%d)\n", rc);
	}

	/*
	 * Set to the platform-controlled mode on exit if supported, so as to
	 * have a certain behaviour when the driver is detached.
	 */
	rc = hisi_uncore_cmd_send(uncore, HUCF_PCC_CMD_SET_MODE, &data);
	if (rc)
		dev_err(uncore->dev, "Failed to set platform mode on exit (%d)\n", rc);
}

static void devm_hisi_uncore_remove_platform_gov(void *data)
{
	hisi_uncore_remove_platform_gov(data);
}

static int hisi_uncore_add_platform_gov(struct hisi_uncore_freq *uncore)
{
	if (!(uncore->cap & HUCF_CAP_PLATFORM_CTRL))
		return 0;

	guard(mutex)(&hisi_platform_gov_usage_lock);

	if (hisi_platform_gov_usage == 0) {
		int rc = devfreq_add_governor(&hisi_platform_governor);

		if (rc)
			return rc;
	}
	hisi_platform_gov_usage++;

	return devm_add_action_or_reset(uncore->dev,
					devm_hisi_uncore_remove_platform_gov,
					uncore);
}

/*
 * Returns:
 * 0 if success, uncore->related_cpus is set.
 * -EINVAL if property not found, or property found but without elements in it,
 * or invalid arguments received in any of the subroutine.
 * Other error codes if it goes wrong.
 */
static int hisi_uncore_mark_related_cpus(struct hisi_uncore_freq *uncore,
				 char *property, int (*get_topo_id)(int cpu),
				 const struct cpumask *(*get_cpumask)(int cpu))
{
	unsigned int i, cpu;
	size_t len;
	int rc;

	rc = device_property_count_u32(uncore->dev, property);
	if (rc < 0)
		return rc;
	if (rc == 0)
		return -EINVAL;

	len = rc;
	u32 *num __free(kfree) = kcalloc(len, sizeof(*num), GFP_KERNEL);
	if (!num)
		return -ENOMEM;

	rc = device_property_read_u32_array(uncore->dev, property, num, len);
	if (rc)
		return rc;

	for (i = 0; i < len; i++) {
		for_each_possible_cpu(cpu) {
			if (get_topo_id(cpu) != num[i])
				continue;

			cpumask_or(&uncore->related_cpus,
				   &uncore->related_cpus, get_cpumask(cpu));
			break;
		}
	}

	return 0;
}

static int get_package_id(int cpu)
{
	return topology_physical_package_id(cpu);
}

static const struct cpumask *get_package_cpumask(int cpu)
{
	return topology_core_cpumask(cpu);
}

static int get_cluster_id(int cpu)
{
	return topology_cluster_id(cpu);
}

static const struct cpumask *get_cluster_cpumask(int cpu)
{
	return topology_cluster_cpumask(cpu);
}

static int hisi_uncore_mark_related_cpus_wrap(struct hisi_uncore_freq *uncore)
{
	int rc;

	cpumask_clear(&uncore->related_cpus);

	rc = hisi_uncore_mark_related_cpus(uncore, "related-package",
					   get_package_id,
					   get_package_cpumask);
	/* Success, or firmware probably broken */
	if (!rc || rc != -EINVAL)
		return rc;

	/* Try another property name if rc == -EINVAL */
	return hisi_uncore_mark_related_cpus(uncore, "related-cluster",
					     get_cluster_id,
					     get_cluster_cpumask);
}

static ssize_t related_cpus_show(struct device *dev,
				 struct device_attribute *attr, char *buf)
{
	struct hisi_uncore_freq *uncore = dev_get_drvdata(dev->parent);

	return cpumap_print_to_pagebuf(true, buf, &uncore->related_cpus);
}

static DEVICE_ATTR_RO(related_cpus);

static struct attribute *hisi_uncore_freq_attrs[] = {
	&dev_attr_related_cpus.attr,
	NULL
};
ATTRIBUTE_GROUPS(hisi_uncore_freq);

static int hisi_uncore_devfreq_register(struct hisi_uncore_freq *uncore)
{
	struct devfreq_dev_profile *profile;
	struct device *dev = uncore->dev;
	unsigned long freq;
	u32 data;
	int rc;

	rc = hisi_uncore_get_cur_freq(dev, &freq);
	if (rc)
		return dev_err_probe(dev, rc, "Failed to get plat init freq\n");

	profile = devm_kzalloc(dev, sizeof(*profile), GFP_KERNEL);
	if (!profile)
		return -ENOMEM;

	*profile = (struct devfreq_dev_profile) {
		.initial_freq = freq,
		.polling_ms = HUCF_DEFAULT_POLLING_MS,
		.timer = DEVFREQ_TIMER_DELAYED,
		.target = hisi_uncore_target,
		.get_dev_status = hisi_uncore_get_dev_status,
		.get_cur_freq = hisi_uncore_get_cur_freq,
		.dev_groups = hisi_uncore_freq_groups,
	};

	rc = hisi_uncore_cmd_send(uncore, HUCF_PCC_CMD_GET_MODE, &data);
	if (rc)
		return dev_err_probe(dev, rc, "Failed to get operate mode\n");

	if (data == HUCF_MODE_PLATFORM)
		uncore->devfreq = devm_devfreq_add_device(dev, profile,
					  hisi_platform_governor.name,
					  uncore->ondemand_data);
	else
		uncore->devfreq = devm_devfreq_add_device(dev, profile,
					  DEVFREQ_GOV_PERFORMANCE,
					  uncore->ondemand_data);
	if (IS_ERR(uncore->devfreq))
		return dev_err_probe(dev, PTR_ERR(uncore->devfreq),
			"Failed to add devfreq device\n");

	return 0;
}

static int hisi_uncore_freq_probe(struct platform_device *pdev)
{
	struct hisi_uncore_freq *uncore;
	struct device *dev = &pdev->dev;
	u32 cap;
	int rc;

	uncore = devm_kzalloc(dev, sizeof(*uncore), GFP_KERNEL);
	if (!uncore)
		return -ENOMEM;

	uncore->dev = dev;
	platform_set_drvdata(pdev, uncore);

	rc = hisi_uncore_mark_related_cpus_wrap(uncore);
	if (rc)
		return dev_err_probe(dev, rc, "Failed to mark related cpus\n");

	/* Do this first as it may defer the probe. */
	rc = hisi_uncore_devfreq_event_register(uncore);
	if (rc)
		return rc;

	rc = hisi_uncore_init_pcc_chan(uncore);
	if (rc)
		return dev_err_probe(dev, rc, "Failed to init PCC channel\n");

	rc = hisi_uncore_init_opp(uncore);
	if (rc)
		return dev_err_probe(dev, rc, "Failed to init OPP\n");

	rc = hisi_uncore_cmd_send(uncore, HUCF_PCC_CMD_GET_CAP, &cap);
	if (rc)
		return dev_err_probe(dev, rc, "Failed to get capability\n");

	uncore->cap = cap;

	rc = hisi_uncore_add_platform_gov(uncore);
	if (rc)
		return dev_err_probe(dev, rc, "Failed to add hisi_platform governor\n");

	rc = hisi_uncore_devfreq_register(uncore);
	if (rc)
		return dev_err_probe(dev, rc, "Failed to register devfreq\n");

	return 0;
}

static const struct acpi_device_id hisi_uncore_freq_acpi_match[] = {
	{ "HISI04F1", },
	{ }
};
MODULE_DEVICE_TABLE(acpi, hisi_uncore_freq_acpi_match);

static struct platform_driver hisi_uncore_freq_drv = {
	.probe	= hisi_uncore_freq_probe,
	.driver = {
		.name = "hisi_uncore_freq",
		.acpi_match_table = hisi_uncore_freq_acpi_match,
	},
};
module_platform_driver(hisi_uncore_freq_drv);

MODULE_DESCRIPTION("HiSilicon uncore frequency scaling driver");
MODULE_AUTHOR("Jie Zhan <zhanjie9@hisilicon.com>");
MODULE_LICENSE("GPL");
