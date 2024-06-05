// SPDX-License-Identifier: GPL-2.0-only
/*
 * spe.c: Arm Statistical Profiling Extensions support
 * Copyright (c) 2019-2020, Arm Ltd.
 * Copyright (c) 2024-2025, Huawei Technologies Ltd.
 */

#define PMUNAME "arm_spe"
#define DRVNAME PMUNAME "_driver"
#define pr_fmt(fmt) DRVNAME ": " fmt

#include <linux/of_device.h>
#include <linux/of_irq.h>
#include <linux/perf/arm_pmu.h>
#include <linux/platform_device.h>
#include <linux/mem_sampling.h>

#include "spe-decoder/arm-spe-decoder.h"
#include "spe-decoder/arm-spe-pkt-decoder.h"
#include "spe.h"

static long __percpu irq_dev_id;

static struct arm_spe *spe;

#define SPE_INIT_FAIL	0
#define SPE_INIT_SUCC	1
static int spe_probe_status = SPE_INIT_FAIL;

/* Keep track of our dynamic hotplug state */
static enum cpuhp_state arm_spe_online;

DEFINE_PER_CPU(struct arm_spe_buf, per_cpu_spe_buf);

mem_sampling_cb_type arm_spe_sampling_cb;
void arm_spe_record_capture_callback_register(mem_sampling_cb_type cb)
{
	arm_spe_sampling_cb = cb;
}

static inline int arm_spe_per_buffer_alloc(int cpu)
{
	struct arm_spe_buf *spe_buf = &per_cpu(per_cpu_spe_buf, cpu);
	void *alloc_base;

	if (spe_buf->base && spe_buf->record_base)
		return 0;

	/* alloc spe raw data buffer */
	alloc_base = kzalloc_node(SPE_BUFFER_MAX_SIZE, GFP_KERNEL, cpu_to_node(cpu));
	if (unlikely(!alloc_base)) {
		pr_err("alloc spe raw data buffer failed.\n");
		return -ENOMEM;
	}

	spe_buf->base = alloc_base;
	spe_buf->size = SPE_BUFFER_SIZE;
	spe_buf->cur = alloc_base + SPE_BUFFER_MAX_SIZE - SPE_BUFFER_SIZE;
	spe_buf->period = SPE_SAMPLE_PERIOD;

	/* alloc record buffer */
	spe_buf->record_size = SPE_RECORD_ENTRY_SIZE * SPE_RECORD_BUFFER_MAX_RECORDS;
	spe_buf->record_base = kzalloc_node(spe_buf->record_size, GFP_KERNEL, cpu_to_node(cpu));
	if (unlikely(!spe_buf->record_base)) {
		pr_err("alloc spe record buffer failed.\n");
		return -ENOMEM;
	}

	return 0;
}

static int arm_spe_buffer_alloc(void)
{
	int cpu, ret = 0;
	cpumask_t *mask = &spe->supported_cpus;

	for_each_possible_cpu(cpu) {
		if (!cpumask_test_cpu(cpu, mask))
			continue;
		ret = arm_spe_per_buffer_alloc(cpu);
		if (ret)
			return ret;
	}
	return ret;
}

static inline void arm_spe_per_buffer_free(int cpu)
{
	struct arm_spe_buf *spe_buf = &per_cpu(per_cpu_spe_buf, cpu);

	if (!spe_buf->base)
		return;

	kfree(spe_buf->base);
	spe_buf->cur = NULL;
	spe_buf->base = NULL;
	spe_buf->size = 0;

	kfree(spe_buf->record_base);
	spe_buf->record_base = NULL;
	spe_buf->record_size = 0;
}

static inline void arm_spe_buffer_free(void)
{
	cpumask_t *mask = &spe->supported_cpus;
	int cpu;

	for_each_possible_cpu(cpu) {
		if (!cpumask_test_cpu(cpu, mask))
			continue;
		arm_spe_per_buffer_free(cpu);
	}
}

static void arm_spe_buffer_init(void)
{
	u64 base, limit;
	struct arm_spe_buf *spe_buf = this_cpu_ptr(&per_cpu_spe_buf);

	if (!spe_buf || !spe_buf->cur || !spe_buf->size) {
		/*
		 * We still need to clear the limit pointer, since the
		 * profiler might only be disabled by virtue of a fault.
		 */
		limit = 0;
		goto out_write_limit;
	}

	base = (u64)spe_buf->cur;
	limit = ((u64)spe_buf->cur + spe_buf->size) | PMBLIMITR_EL1_E;
	write_sysreg_s(base, SYS_PMBPTR_EL1);

out_write_limit:
	write_sysreg_s(limit, SYS_PMBLIMITR_EL1);

}

static void arm_spe_disable_and_drain_local(void)
{
	/* Disable profiling at EL0 and EL1 */
	write_sysreg_s(0, SYS_PMSCR_EL1);
	isb();

	/* Drain any buffered data */
	psb_csync();
	dsb(nsh);

	/* Disable the profiling buffer */
	write_sysreg_s(0, SYS_PMBLIMITR_EL1);
	isb();
}

/* IRQ handling */
static enum arm_spe_buf_fault_action arm_spe_buf_get_fault_act(void)
{
	const char *err_str;
	u64 pmbsr;
	enum arm_spe_buf_fault_action ret;

	/*
	 * Ensure new profiling data is visible to the CPU and any external
	 * aborts have been resolved.
	 */
	psb_csync();
	dsb(nsh);

	/* Ensure hardware updates to PMBPTR_EL1 are visible */
	isb();

	/* Service required? */
	pmbsr = read_sysreg_s(SYS_PMBSR_EL1);
	if (!FIELD_GET(PMBSR_EL1_S, pmbsr))
		return SPE_PMU_BUF_FAULT_ACT_SPURIOUS;

	/* We only expect buffer management events */
	switch (FIELD_GET(PMBSR_EL1_EC, pmbsr)) {
	case PMBSR_EL1_EC_BUF:
		/* Handled below */
		break;
	case PMBSR_EL1_EC_FAULT_S1:
	case PMBSR_EL1_EC_FAULT_S2:
		err_str = "Unexpected buffer fault";
		goto out_err;
	default:
		err_str = "Unknown error code";
		goto out_err;
	}

	/* Buffer management event */
	switch (FIELD_GET(PMBSR_EL1_BUF_BSC_MASK, pmbsr)) {
	case PMBSR_EL1_BUF_BSC_FULL:
		ret = SPE_PMU_BUF_FAULT_ACT_OK;
		goto out_stop;
	default:
		err_str = "Unknown buffer status code";
	}

out_err:
	pr_err_ratelimited(
		"%s on CPU %d [PMBSR=0x%016llx, PMBPTR=0x%016llx, PMBLIMITR=0x%016llx]\n",
		err_str, smp_processor_id(), pmbsr,
		read_sysreg_s(SYS_PMBPTR_EL1),
		read_sysreg_s(SYS_PMBLIMITR_EL1));
	ret = SPE_PMU_BUF_FAULT_ACT_FATAL;

out_stop:
	return ret;
}

void arm_spe_stop(void)
{
	arm_spe_disable_and_drain_local();
}

static u64 arm_spe_to_pmsfcr(void)
{
	u64 reg = 0;

	if (spe->load_filter)
		reg |= PMSFCR_EL1_LD;

	if (spe->store_filter)
		reg |= PMSFCR_EL1_ST;

	if (spe->branch_filter)
		reg |= PMSFCR_EL1_B;

	if (reg)
		reg |= PMSFCR_EL1_FT;

	if (spe->event_filter)
		reg |= PMSFCR_EL1_FE;

	if (spe->inv_event_filter)
		reg |= PMSFCR_EL1_FnE;

	if (spe->min_latency)
		reg |= PMSFCR_EL1_FL;

	return reg;
}

static u64 arm_spe_to_pmsevfr(void)
{
	return spe->event_filter;
}

static u64 arm_spe_to_pmsnevfr(void)
{
	return spe->inv_event_filter;
}

static u64 arm_spe_to_pmslatfr(void)
{
	return spe->min_latency;
}

static void arm_spe_sanitise_period(struct arm_spe_buf *spe_buf)
{
	u64 period = spe_buf->period;
	u64 max_period = PMSIRR_EL1_INTERVAL_MASK;

	if (period < spe->min_period)
		period = spe->min_period;
	else if (period > max_period)
		period = max_period;
	else
		period &= max_period;

	spe_buf->period = period;
}

static u64 arm_spe_to_pmsirr(void)
{
	u64 reg = 0;
	struct arm_spe_buf *spe_buf = this_cpu_ptr(&per_cpu_spe_buf);

	arm_spe_sanitise_period(spe_buf);

	if (spe->jitter)
		reg |= 0x1;

	reg |= spe_buf->period << 8;

	return reg;
}

static u64 arm_spe_to_pmscr(void)
{
	u64 reg = 0;

	if (spe->ts_enable)
		reg |= PMSCR_EL1_TS;

	if (spe->pa_enable)
		reg |= PMSCR_EL1_PA;

	if (spe->pct_enable < 0x4)
		reg |= spe->pct_enable << 6;

	if (spe->exclude_user)
		reg |= PMSCR_EL1_E0SPE;

	if (spe->exclude_kernel)
		reg |= PMSCR_EL1_E1SPE;

	if (IS_ENABLED(CONFIG_PID_IN_CONTEXTIDR))
		reg |= PMSCR_EL1_CX;

	return reg;
}

int arm_spe_start(void)
{
	u64 reg;
	int cpu = smp_processor_id();

	if (!cpumask_test_cpu(cpu, &spe->supported_cpus))
		return -ENOENT;

	arm_spe_buffer_init();

	reg = arm_spe_to_pmsfcr();
	write_sysreg_s(reg, SYS_PMSFCR_EL1);

	reg = arm_spe_to_pmsevfr();
	write_sysreg_s(reg, SYS_PMSEVFR_EL1);

	if (spe->features & SPE_PMU_FEAT_INV_FILT_EVT) {
		reg = arm_spe_to_pmsnevfr();
		write_sysreg_s(reg, SYS_PMSNEVFR_EL1);
	}

	reg = arm_spe_to_pmslatfr();

	write_sysreg_s(reg, SYS_PMSLATFR_EL1);

	reg = arm_spe_to_pmsirr();
	write_sysreg_s(reg, SYS_PMSIRR_EL1);
	isb();

	reg = arm_spe_to_pmscr();
	isb();
	write_sysreg_s(reg, SYS_PMSCR_EL1);
	return 0;
}

void arm_spe_continue(void)
{
	int reg;

	arm_spe_buffer_init();
	reg = arm_spe_to_pmscr();

	isb();
	write_sysreg_s(reg, SYS_PMSCR_EL1);
}

int arm_spe_enabled(void)
{
	return spe_probe_status == SPE_INIT_SUCC;
}

static irqreturn_t arm_spe_irq_handler(int irq, void *dev)
{
	enum arm_spe_buf_fault_action act;
	struct arm_spe_buf *spe_buf = this_cpu_ptr(&per_cpu_spe_buf);

	act = arm_spe_buf_get_fault_act();

	switch (act) {
	case SPE_PMU_BUF_FAULT_ACT_FATAL:
		/*
		 * If a fatal exception occurred then leaving the profiling
		 * buffer enabled is a recipe waiting to happen. Since
		 * fatal faults don't always imply truncation, make sure
		 * that the profiling buffer is disabled explicitly before
		 * clearing the syndrome register.
		 */
		arm_spe_disable_and_drain_local();
		break;
	case SPE_PMU_BUF_FAULT_ACT_OK:
		spe_buf->nr_records = 0;
		arm_spe_decode_buf(spe_buf->cur, spe_buf->size);

		/*
		 * Callback function processing record data.
		 * Call one: arm_spe_sampling_cb - mem_sampling layer.
		 * TODO: use per CPU workqueue to process data and reduce
		 * interrupt processing time
		 */
		if (arm_spe_sampling_cb)
			arm_spe_sampling_cb((struct mem_sampling_record *)spe_buf->record_base,
						   spe_buf->nr_records);
		break;

	case SPE_PMU_BUF_FAULT_ACT_SPURIOUS:
		/* We've seen you before, but GCC has the memory of a sieve. */
		arm_spe_stop();
		break;
	}

	/* The buffer pointers are now sane, so resume profiling. */
	write_sysreg_s(0, SYS_PMBSR_EL1);
	return IRQ_HANDLED;
}


static void __arm_spe_dev_probe(void *data)
{
	int fld;
	u64 reg;

	fld = cpuid_feature_extract_unsigned_field(
		read_cpuid(ID_AA64DFR0_EL1), ID_AA64DFR0_EL1_PMSVer_SHIFT);
	if (!fld) {
		pr_err("unsupported ID_AA64DFR0_EL1.PMSVer [%d] on CPU %d\n",
		       fld, smp_processor_id());
		return;
	}
	spe->pmsver = (u16)fld;

	/* Read PMBIDR first to determine whether or not we have access */
	reg = read_sysreg_s(SYS_PMBIDR_EL1);
	if (FIELD_GET(PMBIDR_EL1_P, reg)) {
		pr_err("profiling buffer owned by higher exception level\n");
		return;
	}

	/* Minimum alignment. If it's out-of-range, then fail the probe */
	fld = FIELD_GET(PMBIDR_EL1_ALIGN, reg);
	spe->align = 1 << fld;
	if (spe->align > SZ_2K) {
		pr_err("unsupported PMBIDR.Align [%d] on CPU %d\n", fld,
		       smp_processor_id());
		return;
	}

	/* It's now safe to read PMSIDR and figure out what we've got */
	reg = read_sysreg_s(SYS_PMSIDR_EL1);
	if (FIELD_GET(PMSIDR_EL1_FE, reg))
		spe->features |= SPE_PMU_FEAT_FILT_EVT;

	if (FIELD_GET(PMSIDR_EL1_FnE, reg))
		spe->features |= SPE_PMU_FEAT_INV_FILT_EVT;

	if (FIELD_GET(PMSIDR_EL1_FT, reg))
		spe->features |= SPE_PMU_FEAT_FILT_TYP;

	if (FIELD_GET(PMSIDR_EL1_FL, reg))
		spe->features |= SPE_PMU_FEAT_FILT_LAT;

	if (FIELD_GET(PMSIDR_EL1_ARCHINST, reg))
		spe->features |= SPE_PMU_FEAT_ARCH_INST;

	if (FIELD_GET(PMSIDR_EL1_LDS, reg))
		spe->features |= SPE_PMU_FEAT_LDS;

	if (FIELD_GET(PMSIDR_EL1_ERND, reg))
		spe->features |= SPE_PMU_FEAT_ERND;

	/* This field has a spaced out encoding, so just use a look-up */
	fld = FIELD_GET(PMSIDR_EL1_INTERVAL, reg);
	switch (fld) {
	case PMSIDR_EL1_INTERVAL_256:
		spe->min_period = 256;
		break;
	case PMSIDR_EL1_INTERVAL_512:
		spe->min_period = 512;
		break;
	case PMSIDR_EL1_INTERVAL_768:
		spe->min_period = 768;
		break;
	case PMSIDR_EL1_INTERVAL_1024:
		spe->min_period = 1024;
		break;
	case PMSIDR_EL1_INTERVAL_1536:
		spe->min_period = 1536;
		break;
	case PMSIDR_EL1_INTERVAL_2048:
		spe->min_period = 2048;
		break;
	case PMSIDR_EL1_INTERVAL_3072:
		spe->min_period = 3072;
		break;
	case PMSIDR_EL1_INTERVAL_4096:
		spe->min_period = 4096;
		break;
	default:
		pr_warn("unknown PMSIDR_EL1.Interval [%d]; assuming 8\n", fld);
		fallthrough;
	}

	/* Maximum record size. If it's out-of-range, then fail the probe */
	fld = FIELD_GET(PMSIDR_EL1_MAXSIZE, reg);
	spe->max_record_sz = 1 << fld;
	if (spe->max_record_sz > SZ_2K || spe->max_record_sz < 16) {
		pr_err("unsupported PMSIDR_EL1.MaxSize [%d] on CPU %d\n", fld,
		       smp_processor_id());
		return;
	}

	fld = FIELD_GET(PMSIDR_EL1_COUNTSIZE, reg);
	switch (fld) {
	case PMSIDR_EL1_COUNTSIZE_12_BIT_SAT:
		spe->counter_sz = 12;
		break;
	case PMSIDR_EL1_COUNTSIZE_16_BIT_SAT:
		spe->counter_sz = 16;
		break;
	default:
		pr_warn("unknown PMSIDR_EL1.CountSize [%d]; assuming 2\n", fld);
		fallthrough;
	}

	pr_info("probed SPEv1.%d for CPUs %*pbl [max_record_sz %u, min_period %u, align %u, features 0x%llx]\n",
		spe->pmsver - 1, cpumask_pr_args(&spe->supported_cpus),
		spe->max_record_sz, spe->min_period, spe->align, spe->features);

	spe->features |= SPE_PMU_FEAT_DEV_PROBED;
}

static void __arm_spe_reset_local(void)
{
	/*
	 * This is probably overkill, as we have no idea where we're
	 * draining any buffered data to...
	 */
	arm_spe_disable_and_drain_local();

	/* Reset the buffer base pointer */
	write_sysreg_s(0, SYS_PMBPTR_EL1);
	isb();

	/* Clear any pending management interrupts */
	write_sysreg_s(0, SYS_PMBSR_EL1);
	isb();
}

static void __arm_spe_setup_one(void)
{
	__arm_spe_reset_local();
	enable_percpu_irq(spe->irq, IRQ_TYPE_NONE);
}

static void __arm_spe_stop_one(void)
{
	disable_percpu_irq(spe->irq);
	__arm_spe_reset_local();
}

static int arm_spe_cpu_startup(unsigned int cpu, struct hlist_node *node)
{
	struct arm_spe *spe;

	spe = hlist_entry_safe(node, struct arm_spe, hotplug_node);
	if (!cpumask_test_cpu(cpu, &spe->supported_cpus))
		return 0;

	/* Alloc per cpu spe buffer */
	arm_spe_per_buffer_alloc(cpu);

	/* Reset pmu and enable irq */
	__arm_spe_setup_one();

	return 0;
}

static int arm_spe_cpu_teardown(unsigned int cpu, struct hlist_node *node)
{
	struct arm_spe *spe;

	spe = hlist_entry_safe(node, struct arm_spe, hotplug_node);
	if (!cpumask_test_cpu(cpu, &spe->supported_cpus))
		return 0;

	/* Disable irq and reset pmu */
	__arm_spe_stop_one();

	/* Release per cpu spe buffer */
	arm_spe_per_buffer_free(cpu);

	return 0;
}

static int arm_spe_dev_init(void)
{
	int ret;
	cpumask_t *mask = &spe->supported_cpus;


	/* Make sure we probe the hardware on a relevant CPU */
	ret = smp_call_function_any(mask, __arm_spe_dev_probe, NULL, 1);
	if (ret || !(spe->features & SPE_PMU_FEAT_DEV_PROBED))
		return -ENXIO;

	/* Request our PPIs (note that the IRQ is still disabled) */
	ret = request_percpu_irq(spe->irq, arm_spe_irq_handler, DRVNAME,
				 &irq_dev_id);
	if (ret)
		return ret;

	/*
	 * Register our hotplug notifier now so we don't miss any events.
	 * This will enable the IRQ for any supported CPUs that are already
	 * up.
	 */
	ret = cpuhp_state_add_instance(arm_spe_online,
				       &spe->hotplug_node);
	if (ret)
		free_percpu_irq(spe->irq, &irq_dev_id);

	return ret;
}

static void arm_spe_dev_teardown(void)
{
	arm_spe_buffer_free();
	cpuhp_state_remove_instance(arm_spe_online, &spe->hotplug_node);
	free_percpu_irq(spe->irq, &irq_dev_id);
}

static const struct of_device_id arm_spe_of_match[] = {
	{ .compatible = "arm,statistical-profiling-extension-v1",
	  .data = (void *)1 },
	{ /* Sentinel */ },
};
MODULE_DEVICE_TABLE(of, arm_spe_of_match);

static const struct platform_device_id arm_spe_match[] = {
	{ ARMV8_SPE_PDEV_NAME, 0 },
	{}
};
MODULE_DEVICE_TABLE(platform, arm_spe_match);

/* Driver and device probing */
static int arm_spe_irq_probe(void)
{
	struct platform_device *pdev = spe->pdev;
	int irq = platform_get_irq(pdev, 0);

	if (irq < 0)
		return -ENXIO;

	if (!irq_is_percpu(irq)) {
		dev_err(&pdev->dev, "expected PPI but got SPI (%d)\n", irq);
		return -EINVAL;
	}

	if (irq_get_percpu_devid_partition(irq, &spe->supported_cpus)) {
		dev_err(&pdev->dev, "failed to get PPI partition (%d)\n", irq);
		return -EINVAL;
	}

	spe->irq = irq;
	return 0;
}

static void arm_spe_sample_para_init(void)
{
	spe->sample_period = SPE_SAMPLE_PERIOD;
	spe->jitter = 1;
	spe->load_filter = 1;
	spe->store_filter = 1;
	spe->branch_filter = 0;
	spe->inv_event_filter = 0;
	spe->event_filter = 0x2;

	spe->ts_enable = 1;
	spe->pa_enable = 1;
	spe->pct_enable = 0;

	spe->exclude_user = 1;
	spe->exclude_kernel = 0;

	spe->min_latency = 120;
}

void arm_spe_record_enqueue(struct arm_spe_record *record)
{
	struct arm_spe_buf *spe_buf = this_cpu_ptr(&per_cpu_spe_buf);
	struct mem_sampling_record *record_tail;

	if (spe_buf->nr_records >= SPE_RECORD_BUFFER_MAX_RECORDS) {
		pr_err("nr_records exceeded!\n");
		return;
	}

	record_tail = spe_buf->record_base +
			spe_buf->nr_records * SPE_RECORD_ENTRY_SIZE;
	*record_tail = *(struct mem_sampling_record *)record;
	spe_buf->nr_records++;

}

static int arm_spe_device_probe(struct platform_device *pdev)
{

	int ret;
	struct device *dev = &pdev->dev;

	/*
	 * If kernelspace is unmapped when running at EL0, then the SPE
	 * buffer will fault and prematurely terminate the AUX session.
	 */
	if (arm64_kernel_unmapped_at_el0()) {
		dev_warn_once(dev, "buffer inaccessible. Try passing \"kpti=off\" on the kernel command line\n");
		return -EPERM;
	}

	spe = devm_kzalloc(dev, sizeof(*spe), GFP_KERNEL);
	if (!spe)
		return -ENOMEM;

	spe->pdev = pdev;
	platform_set_drvdata(pdev, spe);

	ret = arm_spe_irq_probe();
	if (ret)
		goto out_free;

	ret = arm_spe_dev_init();
	if (ret)
		goto out_free;

	/*
	 * Ensure that all CPUs that support SPE can apply for the cache
	 * area, with each CPU defaulting to 4K * 2. Failure to do so will
	 * result in the inability to collect SPE data in kernel mode.
	 */
	ret = arm_spe_buffer_alloc();
	if (ret)
		goto out_teardown;

	arm_spe_sample_para_init();

	spe_probe_status = SPE_INIT_SUCC;

	return 0;

out_teardown:
	arm_spe_dev_teardown();
out_free:
	kfree(spe);
	return ret;
}

static int arm_spe_device_remove(struct platform_device *pdev)
{
	arm_spe_dev_teardown();
	return 0;
}

static struct platform_driver arm_spe_driver = {
	.id_table = arm_spe_match,
	.driver	= {
		.name		= DRVNAME,
		.of_match_table	= of_match_ptr(arm_spe_of_match),
		.suppress_bind_attrs = true,
	},
	.probe	= arm_spe_device_probe,
	.remove	= arm_spe_device_remove,
};

static int __init arm_spe_init(void)
{
	int ret;

	ret = cpuhp_setup_state_multi(CPUHP_AP_ONLINE_DYN, DRVNAME,
				      arm_spe_cpu_startup,
				      arm_spe_cpu_teardown);
	if (ret < 0)
		return ret;
	arm_spe_online = ret;

	ret = platform_driver_register(&arm_spe_driver);

	if (ret)
		cpuhp_remove_multi_state(arm_spe_online);

	return ret;
}

static void __exit arm_spe_exit(void)
{
	/*
	 * TODO: Find a clean way to disable SPE so that SPE
	 * can be used for perf.
	 */
	platform_driver_unregister(&arm_spe_driver);
	cpuhp_remove_multi_state(arm_spe_online);
	arm_spe_buffer_free();
}

module_init(arm_spe_init);
module_exit(arm_spe_exit);
