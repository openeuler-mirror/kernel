// SPDX-License-Identifier: GPL-2.0-only
/*
 * CPUFreq driver for the Loongson-3 processors.
 *
 * All revisions of Loongson-3 processor support cpu_has_scalefreq feature.
 *
 * Author: Huacai Chen <chenhuacai@loongson.cn>
 * Copyright (C) 2024 Loongson Technology Corporation Limited
 */
#include <linux/acpi.h>
#include <linux/cpufreq.h>
#include <linux/delay.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/units.h>
#include <acpi/processor.h>
#include <asm/idle.h>
#include <asm/loongarch.h>
#include <asm/loongson.h>

/* Message */
union smc_message {
	u32 value;
	struct {
		u32 id		: 8;
		u32 info	: 4;
		u32 val		: 12;
		u32 cmd		: 6;
		u32 extra	: 1;
		u32 complete	: 1;
	};
};

union smc_message_v0 {
	u32 value;
	struct {
		u32 info	: 24;
		u32 cmd		: 7;
		u32 complete	: 1;
	};
};

/* Command return values */
#define CMD_OK				0 /* No error */
#define CMD_ERROR			1 /* Regular error */
#define CMD_NOCMD			2 /* Command does not support */
#define CMD_INVAL			3 /* Invalid Parameter */

/* Version commands */
/*
 * CMD_GET_VERSION - Get interface version
 * Input: none
 * Output: version
 */
#define CMD_GET_VERSION			0x1

/* Feature commands */
/*
 * CMD_GET_FEATURE - Get feature state
 * Input: feature ID
 * Output: feature flag
 */
#define CMD_GET_FEATURE			0x2

/*
 * CMD_SET_FEATURE - Set feature state
 * Input: feature ID, feature flag
 * output: none
 */
#define CMD_SET_FEATURE			0x3

/* Feature IDs */
#define FEATURE_SENSOR			0
#define FEATURE_FAN			1
#define FEATURE_DVFS			2

/* Sensor feature flags */
#define FEATURE_SENSOR_ENABLE		BIT(0)
#define FEATURE_SENSOR_SAMPLE		BIT(1)

/* Fan feature flags */
#define FEATURE_FAN_ENABLE		BIT(0)
#define FEATURE_FAN_AUTO		BIT(1)

/* DVFS feature flags */
#define FEATURE_DVFS_ENABLE		BIT(0)
#define FEATURE_DVFS_BOOST		BIT(1)
#define FEATURE_DVFS_AUTO		BIT(2)
#define FEATURE_DVFS_SINGLE_BOOST	BIT(3)

/* Sensor commands */
/*
 * CMD_GET_SENSOR_NUM - Get number of sensors
 * Input: none
 * Output: number
 */
#define CMD_GET_SENSOR_NUM		0x4

/*
 * CMD_GET_SENSOR_STATUS - Get sensor status
 * Input: sensor ID, type
 * Output: sensor status
 */
#define CMD_GET_SENSOR_STATUS		0x5

/* Sensor types */
#define SENSOR_INFO_TYPE		0
#define SENSOR_INFO_TYPE_TEMP		1

/* Fan commands */
/*
 * CMD_GET_FAN_NUM - Get number of fans
 * Input: none
 * Output: number
 */
#define CMD_GET_FAN_NUM			0x6

/*
 * CMD_GET_FAN_INFO - Get fan status
 * Input: fan ID, type
 * Output: fan info
 */
#define CMD_GET_FAN_INFO		0x7

/*
 * CMD_SET_FAN_INFO - Set fan status
 * Input: fan ID, type, value
 * Output: none
 */
#define CMD_SET_FAN_INFO		0x8

/* Fan types */
#define FAN_INFO_TYPE_LEVEL		0

/* DVFS commands */
/*
 * CMD_GET_FREQ_LEVEL_NUM - Get number of freq levels
 * Input: CPU ID
 * Output: number
 */
#define CMD_GET_FREQ_LEVEL_NUM		0x9

/*
 * CMD_GET_FREQ_BOOST_LEVEL - Get the first boost level
 * Input: CPU ID
 * Output: number
 */
#define CMD_GET_FREQ_BOOST_LEVEL	0x10

/*
 * CMD_GET_FREQ_LEVEL_INFO - Get freq level info
 * Input: CPU ID, level ID
 * Output: level info
 */
#define CMD_GET_FREQ_LEVEL_INFO		0x11

/*
 * CMD_GET_FREQ_INFO - Get freq info
 * Input: CPU ID, type
 * Output: freq info
 */
#define CMD_GET_FREQ_INFO		0x12

/*
 * CMD_SET_FREQ_INFO - Set freq info
 * Input: CPU ID, type, value
 * Output: none
 */
#define CMD_SET_FREQ_INFO		0x13

/*
 * CMD_SET_FREQ_INFO_V0 - Used in SMC_VERSION_V0
 */
#define CMD_SET_FREQ_INFO_V0		0x21

/* Freq types */
#define FREQ_INFO_TYPE_FREQ		0
#define FREQ_INFO_TYPE_LEVEL		1

#define FREQ_MAX_LEVEL			16

#define MMIO_SMCMBX(node) \
	((void __iomem *)(nid_to_addrbase(node) | IO_BASE | \
	LOONGSON_REG_BASE | LOONGARCH_IOCSR_SMCMBX))

#define MMIO_MISC_FUNC(node) \
	((void __iomem *)(nid_to_addrbase(node) | IO_BASE | \
	LOONGSON_REG_BASE | LOONGARCH_IOCSR_MISC_FUNC))

struct loongson3_freq_data {
	unsigned int def_freq_level;
	unsigned int def_freq_value;
	struct cpufreq_frequency_table table[];
};

enum smc_version {
	SMC_VERSION_V0,
	SMC_VERSION_V1,
};

static int smc_version;
static struct mutex cpufreq_mutex[MAX_NUMNODES];
static struct cpufreq_driver loongson3_cpufreq_driver;
static DEFINE_PER_CPU(struct loongson3_freq_data *, freq_data);
static DEFINE_PER_CPU(struct acpi_processor_performance *, acpi_perf_data);

static inline int do_service_request(u32 id, u32 info, u32 cmd, u32 val, u32 extra)
{
	int retries;
	unsigned int cpu = 0, nid;
	union smc_message msg, last;

#ifdef CONFIG_SMP
	switch (cmd) {
	case CMD_GET_FREQ_INFO:
	case CMD_SET_FREQ_INFO:
	case CMD_GET_FREQ_LEVEL_NUM:
	case CMD_GET_FREQ_LEVEL_INFO:
	case CMD_GET_FREQ_BOOST_LEVEL:
		cpu = cpu_number_map(id);
		break;
	default:
		cpu = raw_smp_processor_id();
	}
#endif
	nid = cpu_to_node(cpu);

	mutex_lock(&cpufreq_mutex[nid]);

	last.value = readl(MMIO_SMCMBX(nid));
	if (!last.complete) {
		mutex_unlock(&cpufreq_mutex[nid]);
		return -EPERM;
	}

	msg.id		= id;
	msg.info	= info;
	msg.cmd		= cmd;
	msg.val		= val;
	msg.extra	= extra;
	msg.complete	= 0;

	writel(msg.value, MMIO_SMCMBX(nid));
	writel(readl(MMIO_MISC_FUNC(nid)) | IOCSR_MISC_FUNC_SOFT_INT,
		MMIO_MISC_FUNC(nid));

	for (retries = 0; retries < 10000; retries++) {
		msg.value = readl(MMIO_SMCMBX(nid));
		if (msg.complete)
			break;

		usleep_range(8, 12);
	}

	if (!msg.complete || msg.cmd != CMD_OK) {
		mutex_unlock(&cpufreq_mutex[nid]);
		return -EPERM;
	}

	mutex_unlock(&cpufreq_mutex[nid]);

	return msg.val;
}

static inline  int do_service_request_v0(u32 info, u32 cmd)
{
	int retries;
	union smc_message_v0 msg;
	unsigned int cpu = 0;
	unsigned int nid = cpu_to_node(cpu);

	mutex_lock(&cpufreq_mutex[nid]);

	msg.value = readl(MMIO_SMCMBX(nid));
	if (!msg.complete) {
		mutex_unlock(&cpufreq_mutex[nid]);
		return -EPERM;
	}

	msg.info	= info;
	msg.cmd		= cmd;
	msg.complete	= 0;

	writel(msg.value, MMIO_SMCMBX(nid));
	writel(readl(MMIO_MISC_FUNC(nid)) | IOCSR_MISC_FUNC_SOFT_INT,
		MMIO_MISC_FUNC(nid));

	for (retries = 0; retries < 10000; retries++) {
		msg.value = readl(MMIO_SMCMBX(nid));
		if (msg.complete)
			break;

		usleep_range(8, 12);
	}

	if (!msg.complete) {
		msg.complete = 1;
		writel(msg.value, MMIO_SMCMBX(nid));
		mutex_unlock(&cpufreq_mutex[nid]);
		return -EPERM;
	}

	msg.complete = 0;

	mutex_unlock(&cpufreq_mutex[nid]);

	return msg.value;
}

static unsigned int loongson3_cpufreq_get(unsigned int cpu)
{
	int ret = 0;
	struct cpufreq_policy *policy = cpufreq_cpu_get_raw(cpu);
	unsigned int core = cpu_logical_map(cpu);

	if (smc_version == SMC_VERSION_V1)
		ret = do_service_request(core, FREQ_INFO_TYPE_FREQ,
					 CMD_GET_FREQ_INFO, 0, 0);
	if (ret <= 0)
		ret = policy->cur;
	else
		ret = ret * KILO;

	pr_debug("get cpufreq for cpu%d: %dKHz\n", cpu, ret);

	return ret;
}

static int loongson3_cpufreq_target(struct cpufreq_policy *policy, unsigned int index)
{
	int ret;
	unsigned int core = cpu_logical_map(policy->cpu);

	if (smc_version == SMC_VERSION_V1)
		ret = do_service_request(core, FREQ_INFO_TYPE_LEVEL,
					 CMD_SET_FREQ_INFO, index, 0);
	else {
		struct acpi_processor_performance *perf =
			per_cpu(acpi_perf_data, policy->cpu);
		unsigned int level = perf->states[index].control & 0xf;
		u32 info = (((core >> 4) & 0xf) << 8) | (level << 4) |
			    (core & 0xf);

		ret = do_service_request_v0(info, CMD_SET_FREQ_INFO_V0);
	}

	pr_debug("cpufreq target for cpu%d: index = %u, ret = %d\n",
		 policy->cpu, index, ret);

	return (ret >= 0) ? 0 : ret;
}

static int configure_freq_table(int cpu)
{
	int i, ret, core, boost_level, max_level, freq_level;
	struct platform_device *pdev = cpufreq_get_driver_data();
	struct loongson3_freq_data *data;

	if (per_cpu(freq_data, cpu))
		return 0;

	core = cpu_logical_map(cpu);

	ret = do_service_request(core, 0, CMD_GET_FREQ_LEVEL_NUM, 0, 0);
	if (ret < 0)
		return ret;
	max_level = ret;

	ret = do_service_request(core, 0, CMD_GET_FREQ_BOOST_LEVEL, 0, 0);
	if (ret < 0)
		return ret;
	boost_level = ret;

	freq_level = min(max_level, FREQ_MAX_LEVEL);
	data = devm_kzalloc(&pdev->dev, struct_size(data, table, freq_level + 1), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	data->def_freq_level = boost_level - 1;

	for (i = 0; i < freq_level; i++) {
		ret = do_service_request(core, FREQ_INFO_TYPE_FREQ, CMD_GET_FREQ_LEVEL_INFO, i, 0);
		if (ret < 0) {
			devm_kfree(&pdev->dev, data);
			return ret;
		}

		data->table[i].frequency = ret * KILO;
		data->table[i].flags = (i >= boost_level) ? CPUFREQ_BOOST_FREQ : 0;
	}

	data->table[freq_level].flags = 0;
	data->table[freq_level].frequency = CPUFREQ_TABLE_END;
	data->def_freq_value = data->table[data->def_freq_level].frequency;

	per_cpu(freq_data, cpu) = data;

	return 0;
}

static int configure_freq_table_acpi(int cpu)
{
	int i, ret, normal_max_level = 0, normal_max_freq = 0;
	struct platform_device *pdev = cpufreq_get_driver_data();
	struct loongson3_freq_data *data;
	struct acpi_processor_performance *perf;

	if (per_cpu(freq_data, cpu))
		return 0;

	perf = devm_kzalloc(&pdev->dev, sizeof(*perf), GFP_KERNEL);
	if (!perf)
		return -ENOMEM;

	if (!zalloc_cpumask_var_node(&perf->shared_cpu_map, GFP_KERNEL,
	    cpu_to_node(cpu)))
		return -ENOMEM;

	ret = acpi_processor_register_performance(perf, cpu);
	if (ret)
		return ret;

	if (perf->state_count < 2) {
		acpi_processor_unregister_performance(cpu);
		return -EINVAL;
	}

	data = devm_kzalloc(&pdev->dev, struct_size(data, table,
			    perf->state_count + 1), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	for (i = 0; i < perf->state_count; i++) {
		data->table[i].frequency = perf->states[i].core_frequency *
					   KILO;
		data->table[i].flags = (perf->states[i].control & (0x1 << 8)) ?
					CPUFREQ_BOOST_FREQ : 0;
		if (!(data->table[i].flags)) {
			if (perf->states[i].core_frequency > normal_max_freq) {
				normal_max_freq = perf->states[i].core_frequency;
				normal_max_level = perf->states[i].control;
			}
		}
	}

	data->table[i].flags = 0;
	data->table[i].frequency = CPUFREQ_TABLE_END;
	data->def_freq_level = normal_max_level;
	data->def_freq_value = normal_max_freq * KILO;
	per_cpu(freq_data, cpu) = data;
	per_cpu(acpi_perf_data, cpu) = perf;

	return 0;
}

static int loongson3_cpufreq_cpu_init(struct cpufreq_policy *policy)
{
	int i, ret, cpu = policy->cpu;

	if (smc_version == SMC_VERSION_V1)
		ret = configure_freq_table(cpu);
	else
		ret = configure_freq_table_acpi(cpu);
	if (ret < 0)
		return ret;

	policy->cpuinfo.transition_latency = 10000;
	policy->freq_table = per_cpu(freq_data, cpu)->table;
	policy->suspend_freq = per_cpu(freq_data, cpu)->def_freq_value;
	policy->cur = per_cpu(freq_data, cpu)->def_freq_value;

	cpumask_copy(policy->cpus, topology_sibling_cpumask(cpu));
	for_each_cpu(i, policy->cpus) {
		if (i != cpu) {
			per_cpu(freq_data, i) = per_cpu(freq_data, cpu);
			per_cpu(acpi_perf_data, i) =
				per_cpu(acpi_perf_data, cpu);
		}
	}

	pr_info("cpu %d: loongson3 cpufreq init.\n", cpu);

	return 0;
}

static void loongson3_cpufreq_cpu_exit(struct cpufreq_policy *policy)
{
	unsigned int index;
	unsigned int cpu = policy->cpu;
	unsigned int target_freq = per_cpu(freq_data, cpu)->def_freq_value;

	index = cpufreq_frequency_table_target(policy, target_freq, policy->min, policy->max,
				       CPUFREQ_RELATION_H);
	loongson3_cpufreq_target(policy, index);

	if (smc_version != SMC_VERSION_V1)
		acpi_processor_unregister_performance(cpu);

	pr_info("cpu %d: loongson3 cpufreq exit.\n", cpu);

	return;
}

static int loongson3_cpufreq_cpu_online(struct cpufreq_policy *policy)
{
	return 0;
}

static int loongson3_cpufreq_cpu_offline(struct cpufreq_policy *policy)
{
	return 0;
}

static int loongson3_cpufreq_smc_detect(void)
{
	union smc_message msg;
	unsigned int cpu = 0;
	unsigned int nid = cpu_to_node(cpu);

	mutex_lock(&cpufreq_mutex[nid]);

	msg.value = readl(MMIO_SMCMBX(nid));
	if (!msg.complete) {
		pr_warn("cpufreq smc inactive.\n");
		mutex_unlock(&cpufreq_mutex[nid]);
		return -EPERM;
	}

	mutex_unlock(&cpufreq_mutex[nid]);

	return 0;
}

static struct cpufreq_driver loongson3_cpufreq_driver = {
	.name = "loongson3",
	.flags = CPUFREQ_CONST_LOOPS,
	.init = loongson3_cpufreq_cpu_init,
	.exit = loongson3_cpufreq_cpu_exit,
	.online = loongson3_cpufreq_cpu_online,
	.offline = loongson3_cpufreq_cpu_offline,
	.get = loongson3_cpufreq_get,
	.target_index = loongson3_cpufreq_target,
	.verify = cpufreq_generic_frequency_table_verify,
	.set_boost = cpufreq_boost_set_sw,
	.suspend = cpufreq_generic_suspend,
};

static int loongson3_cpufreq_probe(struct platform_device *pdev)
{
	int i, ret;

	if (cpufreq_get_current_driver()) {
		pr_warn("Loongson-3: cpufreq driver already exist\n");
		return -EEXIST;
	}

	for (i = 0; i < MAX_NUMNODES; i++) {
		ret = devm_mutex_init(&pdev->dev, &cpufreq_mutex[i]);
		if (ret)
			return ret;
	}

	ret = loongson3_cpufreq_smc_detect();
	if (ret)
		return ret;

	ret = do_service_request(0, 0, CMD_GET_VERSION, 0, 0);
	if (ret <= 0)
		smc_version = SMC_VERSION_V0;
	else
		smc_version = SMC_VERSION_V1;

	if (smc_version == SMC_VERSION_V1) {
		ret = do_service_request(FEATURE_DVFS, 0, CMD_SET_FEATURE,
				 FEATURE_DVFS_ENABLE | FEATURE_DVFS_BOOST, 0);
		if (ret < 0)
			return -EPERM;
	}

	loongson3_cpufreq_driver.driver_data = pdev;

	ret = cpufreq_register_driver(&loongson3_cpufreq_driver);
	if (ret)
		return ret;

	pr_info("cpufreq (smc %d): Loongson-3 CPU frequency driver.\n",
		smc_version);

	return 0;
}

static int loongson3_cpufreq_remove(struct platform_device *pdev)
{
	cpufreq_unregister_driver(&loongson3_cpufreq_driver);
	return 0;
}

static struct platform_device_id cpufreq_id_table[] = {
	{ "loongson3_cpufreq", },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(platform, cpufreq_id_table);

static struct platform_driver loongson3_platform_driver = {
	.driver = {
		.name = "loongson3_cpufreq",
	},
	.id_table = cpufreq_id_table,
	.probe = loongson3_cpufreq_probe,
	.remove = loongson3_cpufreq_remove,
};
module_platform_driver(loongson3_platform_driver);

MODULE_AUTHOR("Huacai Chen <chenhuacai@loongson.cn>");
MODULE_DESCRIPTION("CPUFreq driver for Loongson-3 processors");
MODULE_LICENSE("GPL");
