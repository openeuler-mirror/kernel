// SPDX-License-Identifier: GPL-2.0-only
/*
 * HiSilicon SoC L3T uncore Hardware event counters support
 *
 * Copyright (C) 2017 Hisilicon Limited
 * Author: Anurup M <anurup.m@huawei.com>
 *         Shaokun Zhang <zhangshaokun@hisilicon.com>
 *
 * This code is based on the uncore PMUs like arm-cci and arm-ccn.
 */
#include <linux/acpi.h>
#include <linux/bug.h>
#include <linux/cpuhotplug.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/list.h>
#include <linux/smp.h>

#include "hisi_uncore_pmu.h"

/* L3T register definition */
#define L3T_PERF_CTRL		0x0408
#define L3T_INT_MASK		0x0800
#define L3T_INT_STATUS		0x0808
#define L3T_INT_CLEAR		0x080c
#define L3T_EVENT_CTRL	        0x1c00
#define L3T_VERSION		0x1cf0
#define L3T_EVENT_TYPE0		0x1d00
/*
 * If the HW version only supports a 48-bit counter, then
 * bits [63:48] are reserved, which are Read-As-Zero and
 * Writes-Ignored.
 */
#define L3T_CNTR0_LOWER		0x1e00

/* L3T has 8-counters */
#define L3T_NR_COUNTERS		0x8

#define L3T_PERF_CTRL_EN	0x20000
#define L3T_EVTYPE_NONE		0xff
#define L3T_NR_EVENTS		0x59

/*
 * Select the counter register offset using the counter index
 */
static u32 hisi_l3t_pmu_get_counter_offset(int cntr_idx)
{
	return (L3T_CNTR0_LOWER + (cntr_idx * 8));
}

static u64 hisi_l3t_pmu_read_counter(struct hisi_pmu *l3t_pmu,
				     struct hw_perf_event *hwc)
{
	return readq(l3t_pmu->base + hisi_l3t_pmu_get_counter_offset(hwc->idx));
}

static void hisi_l3t_pmu_write_counter(struct hisi_pmu *l3t_pmu,
				       struct hw_perf_event *hwc, u64 val)
{
	writeq(val, l3t_pmu->base + hisi_l3t_pmu_get_counter_offset(hwc->idx));
}

static void hisi_l3t_pmu_write_evtype(struct hisi_pmu *l3t_pmu, int idx,
				      u32 type)
{
	u32 reg, reg_idx, shift, val;

	/*
	 * Select the appropriate event select register(L3T_EVENT_TYPE0/1).
	 * There are 2 event select registers for the 8 hardware counters.
	 * Event code is 8-bits and for the former 4 hardware counters,
	 * L3T_EVENT_TYPE0 is chosen. For the latter 4 hardware counters,
	 * L3T_EVENT_TYPE1 is chosen.
	 */
	reg = L3T_EVENT_TYPE0 + (idx / 4) * 4;
	reg_idx = idx % 4;
	shift = 8 * reg_idx;

	/* Write event code to L3T_EVENT_TYPEx Register */
	val = readl(l3t_pmu->base + reg);
	val &= ~(L3T_EVTYPE_NONE << shift);
	val |= (type << shift);
	writel(val, l3t_pmu->base + reg);
}

static void hisi_l3t_pmu_start_counters(struct hisi_pmu *l3t_pmu)
{
	u32 val;

	/*
	 * Set perf_enable bit in L3T_PERF_CTRL register to start counting
	 * for all enabled counters.
	 */
	val = readl(l3t_pmu->base + L3T_PERF_CTRL);
	val |= L3T_PERF_CTRL_EN;
	writel(val, l3t_pmu->base + L3T_PERF_CTRL);
}

static void hisi_l3t_pmu_stop_counters(struct hisi_pmu *l3t_pmu)
{
	u32 val;

	/*
	 * Clear perf_enable bit in L3T_PERF_CTRL register to stop counting
	 * for all enabled counters.
	 */
	val = readl(l3t_pmu->base + L3T_PERF_CTRL);
	val &= ~(L3T_PERF_CTRL_EN);
	writel(val, l3t_pmu->base + L3T_PERF_CTRL);
}

static void hisi_l3t_pmu_enable_counter(struct hisi_pmu *l3t_pmu,
					struct hw_perf_event *hwc)
{
	u32 val;

	/* Enable counter index in L3T_EVENT_CTRL register */
	val = readl(l3t_pmu->base + L3T_EVENT_CTRL);
	val |= (1 << hwc->idx);
	writel(val, l3t_pmu->base + L3T_EVENT_CTRL);
}

static void hisi_l3t_pmu_disable_counter(struct hisi_pmu *l3t_pmu,
					 struct hw_perf_event *hwc)
{
	u32 val;

	/* Clear counter index in L3T_EVENT_CTRL register */
	val = readl(l3t_pmu->base + L3T_EVENT_CTRL);
	val &= ~(1 << hwc->idx);
	writel(val, l3t_pmu->base + L3T_EVENT_CTRL);
}

static void hisi_l3t_pmu_enable_counter_int(struct hisi_pmu *l3t_pmu,
					    struct hw_perf_event *hwc)
{
	u32 val;

	val = readl(l3t_pmu->base + L3T_INT_MASK);
	/* Write 0 to enable interrupt */
	val &= ~(1 << hwc->idx);
	writel(val, l3t_pmu->base + L3T_INT_MASK);
}

static void hisi_l3t_pmu_disable_counter_int(struct hisi_pmu *l3t_pmu,
					     struct hw_perf_event *hwc)
{
	u32 val;

	val = readl(l3t_pmu->base + L3T_INT_MASK);
	/* Write 1 to mask interrupt */
	val |= (1 << hwc->idx);
	writel(val, l3t_pmu->base + L3T_INT_MASK);
}

static u32 hisi_l3t_pmu_get_int_status(struct hisi_pmu *l3t_pmu)
{
	return readl(l3t_pmu->base + L3T_INT_STATUS);
}

static void hisi_l3t_pmu_clear_int_status(struct hisi_pmu *l3t_pmu, int idx)
{
	writel(1 << idx, l3t_pmu->base + L3T_INT_CLEAR);
}

static const struct acpi_device_id hisi_l3t_pmu_acpi_match[] = {
	{}
};
MODULE_DEVICE_TABLE(acpi, hisi_l3t_pmu_acpi_match);

static const struct of_device_id l3t_of_match[] = {
	{ .compatible = "hisilicon,l3t-pmu", },
	{},
};

static int hisi_l3t_pmu_init_data(struct platform_device *pdev,
				  struct hisi_pmu *l3t_pmu)
{
	/*
	 * Use the SCCL_ID and CCL_ID to identify the L3T PMU, while
	 * SCCL_ID is in MPIDR[aff2] and CCL_ID is in MPIDR[aff1].
	 */
	if (device_property_read_u32(&pdev->dev, "hisilicon,scl-id",
				     &l3t_pmu->sccl_id)) {
		dev_err(&pdev->dev, "Can not read l3t sccl-id!\n");
		return -EINVAL;
	}

	if (device_property_read_u32(&pdev->dev, "hisilicon,ccl-id",
				     &l3t_pmu->ccl_id)) {
		dev_err(&pdev->dev, "Can not read l3t ccl-id!\n");
		return -EINVAL;
	}

	l3t_pmu->base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(l3t_pmu->base)) {
		dev_err(&pdev->dev, "ioremap failed for l3t_pmu resource\n");
		return PTR_ERR(l3t_pmu->base);
	}

	l3t_pmu->identifier = readl(l3t_pmu->base + L3T_VERSION);

	return 0;
}

static struct attribute *hisi_l3t_pmu_v1_format_attr[] = {
	HISI_PMU_FORMAT_ATTR(event, "config:0-7"),
	NULL,
};

static const struct attribute_group hisi_l3t_pmu_v1_format_group = {
	.name = "format",
	.attrs = hisi_l3t_pmu_v1_format_attr,
};

static struct attribute *hisi_l3t_pmu_v1_events_attr[] = {
	HISI_PMU_EVENT_ATTR(rd_cpipe,		0x00),
	HISI_PMU_EVENT_ATTR(wr_cpipe,		0x01),
	HISI_PMU_EVENT_ATTR(rd_hit_cpipe,	0x02),
	HISI_PMU_EVENT_ATTR(wr_hit_cpipe,	0x03),
	HISI_PMU_EVENT_ATTR(victim_num,		0x04),
	HISI_PMU_EVENT_ATTR(rd_spipe,		0x20),
	HISI_PMU_EVENT_ATTR(wr_spipe,		0x21),
	HISI_PMU_EVENT_ATTR(rd_hit_spipe,	0x22),
	HISI_PMU_EVENT_ATTR(wr_hit_spipe,	0x23),
	HISI_PMU_EVENT_ATTR(back_invalid,	0x29),
	HISI_PMU_EVENT_ATTR(retry_cpu,		0x40),
	HISI_PMU_EVENT_ATTR(retry_ring,		0x41),
	HISI_PMU_EVENT_ATTR(prefetch_drop,	0x42),
	NULL,
};

static const struct attribute_group hisi_l3t_pmu_v1_events_group = {
	.name = "events",
	.attrs = hisi_l3t_pmu_v1_events_attr,
};

static DEVICE_ATTR(cpumask, 0444, hisi_cpumask_sysfs_show, NULL);

static struct attribute *hisi_l3t_pmu_cpumask_attrs[] = {
	&dev_attr_cpumask.attr,
	NULL,
};

static const struct attribute_group hisi_l3t_pmu_cpumask_attr_group = {
	.attrs = hisi_l3t_pmu_cpumask_attrs,
};

static struct device_attribute hisi_l3t_pmu_identifier_attr =
	__ATTR(identifier, 0444, hisi_uncore_pmu_identifier_attr_show, NULL);

static struct attribute *hisi_l3t_pmu_identifier_attrs[] = {
	&hisi_l3t_pmu_identifier_attr.attr,
	NULL
};

static struct attribute_group hisi_l3t_pmu_identifier_group = {
	.attrs = hisi_l3t_pmu_identifier_attrs,
};

static const struct attribute_group *hisi_l3t_pmu_v1_attr_groups[] = {
	&hisi_l3t_pmu_v1_format_group,
	&hisi_l3t_pmu_v1_events_group,
	&hisi_l3t_pmu_cpumask_attr_group,
	&hisi_l3t_pmu_identifier_group,
	NULL,
};

static const struct hisi_uncore_ops hisi_uncore_l3t_ops = {
	.write_evtype		= hisi_l3t_pmu_write_evtype,
	.get_event_idx		= hisi_uncore_pmu_get_event_idx,
	.start_counters		= hisi_l3t_pmu_start_counters,
	.stop_counters		= hisi_l3t_pmu_stop_counters,
	.enable_counter		= hisi_l3t_pmu_enable_counter,
	.disable_counter	= hisi_l3t_pmu_disable_counter,
	.enable_counter_int	= hisi_l3t_pmu_enable_counter_int,
	.disable_counter_int	= hisi_l3t_pmu_disable_counter_int,
	.write_counter		= hisi_l3t_pmu_write_counter,
	.read_counter		= hisi_l3t_pmu_read_counter,
	.get_int_status		= hisi_l3t_pmu_get_int_status,
	.clear_int_status	= hisi_l3t_pmu_clear_int_status,
};

static int hisi_l3t_pmu_dev_probe(struct platform_device *pdev,
				  struct hisi_pmu *l3t_pmu)
{
	int ret;

	ret = hisi_l3t_pmu_init_data(pdev, l3t_pmu);
	if (ret)
		return ret;

	ret = hisi_uncore_pmu_init_irq(l3t_pmu, pdev);
	if (ret)
		return ret;

	l3t_pmu->counter_bits = 48;
	l3t_pmu->check_event = L3T_NR_EVENTS;
	l3t_pmu->pmu_events.attr_groups = hisi_l3t_pmu_v1_attr_groups;

	l3t_pmu->num_counters = L3T_NR_COUNTERS;
	l3t_pmu->ops = &hisi_uncore_l3t_ops;
	l3t_pmu->dev = &pdev->dev;
	l3t_pmu->on_cpu = -1;

	return 0;
}

static int hisi_l3t_pmu_probe(struct platform_device *pdev)
{
	struct hisi_pmu *l3t_pmu;
	char *name;
	int ret;

	l3t_pmu = devm_kzalloc(&pdev->dev, sizeof(*l3t_pmu), GFP_KERNEL);
	if (!l3t_pmu)
		return -ENOMEM;

	platform_set_drvdata(pdev, l3t_pmu);

	ret = hisi_l3t_pmu_dev_probe(pdev, l3t_pmu);
	if (ret)
		return ret;

	if (device_property_read_u32(&pdev->dev, "hisilicon,index-id", &l3t_pmu->index_id)) {
		dev_err(&pdev->dev, "Can not read l3t index-id!\n");
		return -EINVAL;
	}

	/*
	 * CCL_ID is used to identify the L3T in the same SCCL which was
	 * used _UID by mistake.
	 */
	name = devm_kasprintf(&pdev->dev, GFP_KERNEL, "hisi_sccl%u_l3t%u",
			      l3t_pmu->sccl_id, l3t_pmu->index_id);
	l3t_pmu->pmu = (struct pmu) {
		.name		= name,
		.module		= THIS_MODULE,
		.task_ctx_nr	= perf_invalid_context,
		.event_init	= hisi_uncore_pmu_event_init,
		.pmu_enable	= hisi_uncore_pmu_enable,
		.pmu_disable	= hisi_uncore_pmu_disable,
		.add		= hisi_uncore_pmu_add,
		.del		= hisi_uncore_pmu_del,
		.start		= hisi_uncore_pmu_start,
		.stop		= hisi_uncore_pmu_stop,
		.read		= hisi_uncore_pmu_read,
		.attr_groups	= l3t_pmu->pmu_events.attr_groups,
		.capabilities	= PERF_PMU_CAP_NO_EXCLUDE,
	};

	/* Pick one core to use for cpumask attributes */
	cpumask_set_cpu(smp_processor_id(), &l3t_pmu->associated_cpus);

	l3t_pmu->on_cpu = cpumask_first(&l3t_pmu->associated_cpus);
	if (l3t_pmu->on_cpu >= nr_cpu_ids)
		return -EINVAL;

	ret = perf_pmu_register(&l3t_pmu->pmu, name, -1);

	return ret;
}

static int hisi_l3t_pmu_remove(struct platform_device *pdev)
{
	struct hisi_pmu *l3t_pmu = platform_get_drvdata(pdev);

	perf_pmu_unregister(&l3t_pmu->pmu);

	return 0;
}

static struct platform_driver hisi_l3t_pmu_driver = {
	.driver = {
		.name = "hisi_l3t_pmu",
		.acpi_match_table = ACPI_PTR(hisi_l3t_pmu_acpi_match),
		.of_match_table = l3t_of_match,
		.suppress_bind_attrs = true,
	},
	.probe = hisi_l3t_pmu_probe,
	.remove = hisi_l3t_pmu_remove,
};

static int __init hisi_l3t_pmu_module_init(void)
{
	int ret;

	ret = platform_driver_register(&hisi_l3t_pmu_driver);

	return ret;
}
module_init(hisi_l3t_pmu_module_init);

static void __exit hisi_l3t_pmu_module_exit(void)
{
	platform_driver_unregister(&hisi_l3t_pmu_driver);
}
module_exit(hisi_l3t_pmu_module_exit);

MODULE_DESCRIPTION("HiSilicon SoC L3T uncore PMU driver");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Anurup M <anurup.m@huawei.com>");
MODULE_AUTHOR("Shaokun Zhang <zhangshaokun@hisilicon.com>");
