// SPDX-License-Identifier: GPL-2.0
/*
 * VIP-SMT support for ARM64
 *
 * Copyright (C) 2026 Huawei Technologies Co., Ltd.
 */

#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/node.h>
#include <linux/percpu-defs.h>
#include <linux/smp.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <linux/topology.h>
#include <asm/cpu.h>
#include <asm/cputype.h>
#include <asm/smp.h>
#include <asm/sysreg.h>
#include <asm/vip_smt.h>

/* ============================================================================
 * Global Variables
 * ============================================================================
 */

/* VIP-SMT control state */
static enum vip_smt_control vip_smt_control = VIP_SMT_ENABLED;

static DEFINE_PER_CPU(u64, vip_smt_ifu_actlr1);
static DEFINE_PER_CPU(u64, vip_smt_ooo_dec_rob_sha_ctlr);
static DEFINE_PER_CPU(u64, vip_smt_ooo_dec_dsp_ctlr);
static DEFINE_PER_CPU(u64, vip_smt_is_init);

/* ========================================================================
 * Field Definition Arrays
 * ========================================================================
 */

/* IFU_ACTLR1 fields */
static const struct vip_smt_field ifu_actlr1_fields[] = {
	{ "SCH1_EN",		IFU_ACTLR1_IMPL_SMT_QOS_SCH1_EN },
	{ "SCH1_THR",		IFU_ACTLR1_IMPL_SMT_QOS_SCH1_THR_MASK },
	{ "SCH2_EN",		IFU_ACTLR1_IMPL_SMT_QOS_SCH2_EN },
	{ "SCH2_PLUS_EN",	IFU_ACTLR1_IMPL_SMT_QOS_SCH2_PLUS_EN },
	{ "SCH2_THR",		IFU_ACTLR1_IMPL_SMT_QOS_SCH2_THR_MASK },
	{ "SCH2_TWICE_EN",	IFU_ACTLR1_IMPL_SMT_QOS_SCH2_TWICE_EN },
};

/* OOO_DEC_ROB_SHA_CTLR fields */
static const struct vip_smt_field ooo_dec_rob_sha_ctlr_fields[] = {
	{ "TSLOT_EN",		OOO_DEC_ROB_SHA_CTLR_OOO_DEC_SMT_QOS_TSLOT_EN },
	{ "STARVE_QOS_THRED",	OOO_DEC_ROB_SHA_CTLR_OOO_ROB_STARVE_QOS_THRED_MASK },
	{ "SAFE_MODE",		OOO_DEC_ROB_SHA_CTLR_OOO_ROB_STARVE_QOS_SAFE_MODE },
	{ "DEV_QOS_MODEL_SEL",	OOO_DEC_ROB_SHA_CTLR_OOO_DEV_QOS_MODEL_SEL },
	{ "FRC_IFU_THREAD_RR",	OOO_DEC_ROB_SHA_CTLR_OOO_FRC_IFU_THREAD_RR },
};

/* OOO_DEC_DSP_CTLR fields */
static const struct vip_smt_field ooo_dec_dsp_ctlr_fields[] = {
	{ "DSP_THRESHOLD",	OOO_DEC_DSP_CTLR_OOO_DSP_THRESHOLD },
	{ "ISSQ_THRESHOLD_ISU",	OOO_DEC_DSP_CTLR_OOO_ISSQ_THRESHOLD_ISU_MASK },
	{ "ISSQ_THRESHOLD_ALU",	OOO_DEC_DSP_CTLR_OOO_ISSQ_THRESHOLD_ALU_MASK },
	{ "SMT_QOS_EN",		OOO_DEC_DSP_CTLR_OOO_SMT_QOS_EN },
	{ "THREAD_CYCLE_FRC",	OOO_DEC_DSP_CTLR_OOO_DEC_THREAD_CYCLE_FRC_MASK },
	{ "ICOUNT_CFG",		OOO_DEC_DSP_CTLR_OOO_DEC_ICOUNT_CFG_MASK },
};

/* ========================================================================
 * Helper Functions
 * ========================================================================
 */

/**
 * vip_smt_core_has_smt - Check if physical core supports SMT
 * @cpu: Logical CPU number
 *
 * Returns: true if SMT is supported
 */
static bool vip_smt_core_has_smt(int cpu)
{
	if (!cpu_smt_possible())
		return false;

	return topology_core_has_smt(cpu);
}

/**
 * vip_smt_parse_field_name - Parse FIELD_NAME=value format input
 * @buf: Input buffer containing the string
 * @count: Buffer size
 * @fields: Field definition array
 * @num_fields: Number of fields in array
 * @out_value: Output value to write (will be shifted to correct bit position)
 * @out_mask: Output mask for the field
 *
 * Returns: 0 on success, -EINVAL on failure
 *
 * Parse format: FIELD_NAME=value
 * Example: "SCH1_EN=1" or "SCH1_THR=7"
 */
static int vip_smt_parse_field_name(const char *buf, size_t count,
				     const struct vip_smt_field *fields,
				     int num_fields,
				     u64 *out_value, u64 *out_mask)
{
	char *kbuf;
	char *name, *value_str;
	u64 value;
	int i;
	int ret = -EINVAL;

	/* Make a null-terminated copy */
	kbuf = kstrndup(buf, count, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	/* Remove trailing newline */
	strim(kbuf);

	/* Find the '=' separator */
	value_str = strchr(kbuf, '=');
	if (!value_str)
		goto out;

	*value_str = '\0';
	value_str++;

	/* Parse the value */
	if (kstrtoull(value_str, 0, &value) < 0)
		goto out;

	/* Find matching field by name */
	name = kbuf;
	for (i = 0; i < num_fields; i++) {
		if (strcmp(name, fields[i].name) == 0)
			break;
	}

	if (i >= num_fields)
		goto out;

	u64 mask = fields[i].bitmask;
	int shift = __ffs(mask);

	/* Validate value fits in the field width */
	if (value > mask >> shift) {
		pr_err("VIP-SMT: value 0x%llx exceeds field width for %s\n",
			value, name);
		goto out;
	}

	*out_value = value << shift;
	*out_mask = mask;
	ret = 0;

out:
	kfree(kbuf);
	return ret;
}

/**
 * vip_smt_find_base_cpu - Find the base CPU for a physical core
 * @cpu: Any CPU in the physical core
 *
 * For a 2-SMT-thread physical core, the "base CPU" (even CPU with sibling
 * index 0) is designated as the single authority for managing shared register
 * state and performing restore operations. This prevents concurrent writes
 * to the same physical register from multiple SMT threads.
 *
 * For single-thread cores, returns the CPU itself.
 *
 * Returns: The base CPU number for the physical core
 */
static int vip_smt_find_base_cpu(int cpu, u64 mask)
{
	const struct cpumask *siblings = topology_sibling_cpumask(cpu);
	int first_cpu = cpumask_first(siblings);

	if (mask != ooo_dec_rob_sha_ctlr_allow_mask)
		return cpu;

	return first_cpu;
}

/* ============================================================================
 * Register Access Functions (executed on target CPU)
 * ============================================================================
 */

/**
 * Parameters for register read/write operations
 */
struct vip_smt_reg_data {
	u64 val;
	int cpu;
	u64 mask;
};

/* ============================================================================
 * VIP-SMT API Functions
 * ============================================================================
 */

/**
 * vip_smt_available - Check if VIP-SMT is supported on current system
 *
 * Returns: true if VIP-SMT is available
 */
bool vip_smt_available(void)
{
	return (vip_smt_control == VIP_SMT_ENABLED) && cpus_have_cap(ARM64_HAS_VIP_SMT);
}
EXPORT_SYMBOL_GPL(vip_smt_available);

/* ============================================================================
 * sysfs Interface Implementation
 * ============================================================================
 */

/**
 * vip_smt_get_cpu - Get CPU number from sysfs attribute
 * @dev: device structure
 *
 * Returns: CPU number
 */
static int vip_smt_get_cpu(struct kobject *kobj)
{
	struct cpuinfo_arm64 *info;
	int cpu = nr_cpu_ids;
	int index;

	info = container_of(kobj, struct cpuinfo_arm64, kobj);
	for_each_possible_cpu(index) {
		if (info == &per_cpu(cpu_data, index)) {
			cpu = index;
			break;
		}
	}
	return cpu;
}

#define VIPSMT_SYS_FUNC(_name)									\
	static long __vip_smt_read_raw_##_name(void *val)					\
	{											\
		u64 *ret = val;									\
		if (!ret)									\
			return 0;								\
		*ret = read_sysreg_s(sys_##_name);						\
		return 0;									\
	}											\
	static void __vip_smt_read_##_name(void *info)						\
	{											\
		struct vip_smt_reg_data *data = info;						\
		work_on_cpu(data->cpu, __vip_smt_read_raw_##_name, &(data->val));		\
	}											\
	static void __vip_smt_write_##_name(void *info)						\
	{											\
		struct vip_smt_reg_data *data = info;						\
		u64 mask = data->mask;								\
		u64 reg;									\
		unsigned long flags;								\
		local_irq_save(flags);								\
		reg = __this_cpu_read(vip_smt_##_name);						\
		reg = (reg & ~mask) | (data->val & mask);					\
		write_sysreg_s(reg, sys_##_name);						\
		__this_cpu_write(vip_smt_##_name, reg);						\
		local_irq_restore(flags);							\
	}

#define VIPSMT_ATTR_RW(_name, _fields, _num_fields)						\
	VIPSMT_SYS_FUNC(_name)									\
	static u64 vip_smt_read_##_name(int cpu)						\
	{											\
		struct vip_smt_reg_data data = { .cpu = cpu, .val = 0 };			\
		__vip_smt_read_##_name(&data);							\
		return data.val;								\
	}											\
	static void vip_smt_write_##_name(int cpu, u64 val, u64 maskval, u64 regmask)		\
	{											\
		struct vip_smt_reg_data data = { .cpu = cpu, .val = val, .mask = maskval };	\
		smp_call_function_single(vip_smt_find_base_cpu(cpu, regmask),			\
					 __vip_smt_write_##_name, &data, true);			\
	}											\
	static ssize_t _name##_show(struct kobject *kobj,					\
				    struct kobj_attribute *attr, char *buf)			\
	{											\
		int cpu = vip_smt_get_cpu(kobj);						\
		u64 reg;									\
		ssize_t len = 0;								\
		int i;										\
		if (cpu < 0 || cpu >= nr_cpu_ids)						\
			return -EINVAL;								\
		if (!vip_smt_available() || !vip_smt_core_has_smt(cpu))				\
			return -ENODEV;								\
		reg = vip_smt_read_##_name(cpu);						\
		/* Output original register value */						\
		len += snprintf(buf + len, 64, #_name":0x%016llx(0x%016llx)\n",			\
			       reg, _name##_allow_mask);					\
		/* Output field names and values */						\
		for (i = 0; i < _num_fields; i++) {						\
			u64 mask = _fields[i].bitmask;						\
			u64 value;								\
			int shift = __ffs(mask);						\
			int width = __fls(mask) - shift + 1;					\
			value = (reg & mask) >> shift;						\
			if (width == 1)								\
				len += snprintf(buf + len, 64, "%s(bit %d)=0x%llx\n",		\
						_fields[i].name, shift, value);			\
			else									\
				len += snprintf(buf + len, 64, "%s(bit %d-%d)=0x%llx\n",	\
					_fields[i].name, shift + width - 1, shift, value);	\
		}										\
		len += snprintf(buf + len, 2, "\n");						\
		return len;									\
	}											\
	static ssize_t _name##_store(struct kobject *kobj,					\
				     struct kobj_attribute *attr,				\
				     const char *buf,						\
				     size_t count)						\
	{											\
		int cpu = vip_smt_get_cpu(kobj);						\
		u64 reg = 0;									\
		u64 mask = _name##_allow_mask;							\
		int ret;									\
		if (cpu < 0 || cpu >= nr_cpu_ids)						\
			return -EINVAL;								\
		if (!vip_smt_available() || !vip_smt_core_has_smt(cpu))				\
			return -ENODEV;								\
		/* Try to parse FIELD_NAME=value format first */				\
		ret = vip_smt_parse_field_name(buf, count, _fields, _num_fields,		\
					       &reg, &mask);					\
		if (ret != 0)									\
			return -EINVAL;								\
		vip_smt_write_##_name(cpu, reg, mask, _name##_allow_mask);			\
		return count;									\
	}											\
	static struct kobj_attribute cpuregs_attr_##_name = __ATTR_RW(_name)

VIPSMT_ATTR_RW(ifu_actlr1, ifu_actlr1_fields, ARRAY_SIZE(ifu_actlr1_fields));
VIPSMT_ATTR_RW(ooo_dec_rob_sha_ctlr, ooo_dec_rob_sha_ctlr_fields,
	       ARRAY_SIZE(ooo_dec_rob_sha_ctlr_fields));
VIPSMT_ATTR_RW(ooo_dec_dsp_ctlr, ooo_dec_dsp_ctlr_fields,
	       ARRAY_SIZE(ooo_dec_dsp_ctlr_fields));

static struct attribute *vip_smt_attrs[] = {
	&cpuregs_attr_ifu_actlr1.attr,
	&cpuregs_attr_ooo_dec_rob_sha_ctlr.attr,
	&cpuregs_attr_ooo_dec_dsp_ctlr.attr,
	NULL
};

static const struct attribute_group vip_smt_attr_group = {
	.attrs = vip_smt_attrs,
	.name = "vip-smt"
};

int vip_smt_cpu_sysfs_create(unsigned int cpu, struct cpuinfo_arm64 *info)
{
	if (vip_smt_control != VIP_SMT_ENABLED)
		return -1;

	if (!vip_smt_core_has_smt(cpu))
		return -1;

	if (!cpus_have_cap(ARM64_HAS_VIP_SMT))
		return -1;

	/* Store register which maybe clear after core powerdown(LPI) */
	__this_cpu_write(vip_smt_ifu_actlr1,
			 read_sysreg_s(sys_ifu_actlr1));
	__this_cpu_write(vip_smt_ooo_dec_rob_sha_ctlr,
			 read_sysreg_s(sys_ooo_dec_rob_sha_ctlr));
	__this_cpu_write(vip_smt_ooo_dec_dsp_ctlr,
			 read_sysreg_s(sys_ooo_dec_dsp_ctlr));
	__this_cpu_write(vip_smt_is_init, 1);
	return sysfs_create_group(&info->kobj, &vip_smt_attr_group);
}

void vip_smt_enter_idle(void)
{
	/* No need Store value here */
}

static void restore_shared_register(void *info)
{
	unsigned long flags;
	u64 reg;

	local_irq_save(flags);
	reg = __this_cpu_read(vip_smt_ooo_dec_rob_sha_ctlr);
	write_sysreg_s(reg, sys_ooo_dec_rob_sha_ctlr);
	local_irq_restore(flags);
}

void vip_smt_exit_idle(void)
{
	if (!vip_smt_available() || !vip_smt_core_has_smt(smp_processor_id()))
		return;

	if (__this_cpu_read(vip_smt_is_init)) {
		/* There is no need restore for shared register */
		write_sysreg_s(__this_cpu_read(vip_smt_ifu_actlr1), sys_ifu_actlr1);
		write_sysreg_s(__this_cpu_read(vip_smt_ooo_dec_dsp_ctlr), sys_ooo_dec_dsp_ctlr);
		/* For Shared register we need always restore base cpu value */
		smp_call_function_single(vip_smt_find_base_cpu(smp_processor_id(),
							       ooo_dec_rob_sha_ctlr_allow_mask),
					 restore_shared_register, NULL, true);
	}
}

/**
 * vip_smt_disable - Disable VIP-SMT feature
 * @state: Disable state ("force" means force disable)
 */
static void __init vip_smt_disable(char *state)
{
	if (!state) {
		vip_smt_control = VIP_SMT_DISABLED;
		pr_info("VIP-SMT: Disabled via cmdline\n");
	} else if (strcmp(state, "force") == 0) {
		vip_smt_control = VIP_SMT_FORCE_DISABLED;
		pr_info("VIP-SMT: Force disabled via cmdline\n");
	} else {
		vip_smt_control = VIP_SMT_DISABLED;
	}
}

/**
 * vip_smt_cmdline_disable - cmdline parameter handler
 */
static int __init vip_smt_cmdline_disable(char *str)
{
	vip_smt_disable(str);
	return 0;
}
early_param("novipsmt", vip_smt_cmdline_disable);

/**
 * vip_smt_probe - Detect hardware support for VIP-SMT
 *
 * Determine by MIDR.
 */
static bool vip_smt_probe(void)
{
	/* List of CPUs that support VIP-SMT */
	static const struct midr_range hip13_cpus[] = {
		MIDR_ALL_VERSIONS(MIDR_HISI_HIP13),
		{ /* sentinel */ }
	};

	if (is_midr_in_range_list(hip13_cpus))
		return true;

	return false;
}

bool has_vip_smt_support(const struct arm64_cpu_capabilities *entry, int __unused)
{
	/* If hardware not supported or disabled, set to NOT_SUPPORTED */
	if (vip_smt_control != VIP_SMT_ENABLED) {
		pr_info("VIP-SMT: Disabled in cmdline.\n");
		return false;
	}

	/* Only can access from el2 for now!, configure in el3. */
	if (!is_kernel_in_hyp_mode()) {
		pr_info("VIP-SMT: Only support in EL2 for now.\n");
		return false;
	}

	/* Check if current CPU has SMT enabled */
	if (!vip_smt_core_has_smt(smp_processor_id())) {
		pr_info("VIP-SMT: SMT not enabled on CPU%d\n", smp_processor_id());
		return false;
	}

	return vip_smt_probe();
}
