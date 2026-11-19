// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * Description: This driver adds support for perf events to use the Performance
 * Monitor Counter Groups (PMCG) associated with an UMMU node to monitor that node.
 */

#include <linux/acpi.h>
#include <linux/of.h>
#include <linux/cpuhotplug.h>
#include <linux/cpumask.h>
#include <linux/interrupt.h>
#include <linux/mod_devicetable.h>
#include <linux/platform_device.h>
#include <linux/perf_event.h>
#include <linux/msi.h>

#define UMMU_PMCG_MAX_COUNTERS 8

struct ummu_pmu {
	struct pmu pmu;
	struct hlist_node node;
	struct perf_event *events[UMMU_PMCG_MAX_COUNTERS];
	DECLARE_BITMAP(used_counters, UMMU_PMCG_MAX_COUNTERS);
	uint32_t irq;
	uint32_t on_cpu;
	uint32_t num_counters;
	struct device *dev;
	void __iomem *reg_base;
};

/* registers offset address */
#define UMMU_PMCG_GLB_CTRL 0x0
#define UMMU_PMCG_GLB_CTRL_COMMON_CLR BIT(4)
#define UMMU_PMCG_GLB_CTRL_COMMON_ENABLE BIT(0)
#define UMMU_PMCG_OVF_USI_ADDR0 0x08
#define UMMU_PMCG_OVF_USI_ADDR1 0x0C
#define UMMU_PMCG_OVF_USI_ADDR_MASK GENMASK_ULL(51, 2)
#define UMMU_PMCG_OVF_USI_DATA 0x10
#define UMMU_PMCG_OVF_USI_ATTR 0x14

#define UMMU_PMCG_INT_EN 0x18
#define UMMU_PMCG_INT_OVF_EN BIT(0)
#define UMMU_PMCG_USI_MPAM 0x1C
#define UMMU_PMCG_USI_MPAM_NS BIT(24)
#define UMMU_PMCG_USI_MPAM_PMG GENMASK(23, 16)
#define UMMU_PMCG_USI_MPAM_PARTID GENMASK(15, 0)
#define UMMU_PMCG_USI_MPAM_PMG_MAX 0x03
#define UMMU_PMCG_USI_MPAM_PARTID_MAX 0x0FF
#define UMMU_PMCG_USI_IDX 0x20
#define UMMU_PMCG_ICG_EN 0x24
#define UMMU_PMCG_ICG_EN_ICG BIT(0)

#define UMMU_PMCG_COM_CTRL(n) (0x0 + (n)*0x40)
#define UMMU_PMCG_COM_CTRL_EVENT_CLR BIT(24)
#define UMMU_PMCG_COM_CTRL_EVENT_EN BIT(16)
#define UMMU_PMCG_COM_CTRL_EVENT_CODE GENMASK(7, 0)
#define UMMU_PMCG_OVF_INT_STS(n) (0x08 + (n)*0x40)
#define UMMU_PMCG_CNT1_OVERFLOW_INT_STS BIT(1)
#define UMMU_PMCG_CNT0_OVERFLOW_INT_STS BIT(0)
#define UMMU_PMCG_OVF_INT_MSK(n) (0x0C + (n)*0x40)
#define UMMU_PMCG_CNT1_OVERFLOW_INT_MSK BIT(1)
#define UMMU_PMCG_CNT0_OVERFLOW_INT_MSK BIT(0)
#define UMMU_PMCG_FILT_COND_L(n) (0x10 + (n)*0x40)
#define UMMU_PMCG_FILT_COND_L_MASTER_ID GENMASK(31, 20)
#define UMMU_PMCG_FILT_COND_L_TOKEN_ID GENMASK(19, 0)
#define UMMU_PMCG_FILT_COND_H(n) (0x14 + (n)*0x40)
#define UMMU_PMCG_FILT_COND_H_USER_DEF_ID GENMASK(31, 16)
#define UMMU_PMCG_FILT_COND_H_TECT_TAG GENMASK(15, 0)
#define UMMU_PMCG_FILT_MSK_L(n) (0x18 + (n)*0x40)
#define UMMU_PMCG_FILT_MSK_L_MASTER_ID GENMASK(31, 20)
#define UMMU_PMCG_FILT_MSK_L_TOKEN_ID GENMASK(19, 0)
#define UMMU_PMCG_FILT_MSK_H(n) (0x1C + (n)*0x40)
#define UMMU_PMCG_FILT_MSK_H_USER_DEF_ID GENMASK(31, 16)
#define UMMU_PMCG_FILT_MSK_H_TECT_TAG GENMASK(15, 0)
#define UMMU_PMCG_COM_CNT0_L(n) (0x20 + (n)*0x40)
#define UMMU_PMCG_COM_CNT0_H(n) (0x24 + (n)*0x40)
#define UMMU_PMCG_COM_CNT1_L(n) (0x28 + (n)*0x40)
#define UMMU_PMCG_COM_CNT1_H(n) (0x2C + (n)*0x40)

/* define support event numbers. */
#define UMMU_TCU_PPTW_REQ_NUM 0x00
#define UMMU_TCU_CNTX_CACHE_MISS_NUM 0x01
#define UMMU_TBU_TLB_CACHE_HIT_RATE 0x20
#define UMMU_TBU_PLB_CACHE_HIT_RATE 0x21
#define UMMU_TCU_TPTW_CACHE_HIT_RATE 0x22
#define UMMU_TCU_PPTW_CACHE_HIT_RATE 0x23
#define UMMU_REQ_RATE 0x4B
#define UMMU_RSP_RATE 0x4E
#define UMMU_REQ_AVERAGE_LATENCY 0x6B
#define UMMU_KV_TABLE_RD_AVERAGE_LATENCY 0x6F
#define UMMU_SWIF_CMD_SEND_NUM 0x04
#define UMMU_SWIF_DVM_SYNC_LATENCY 0x64
#define UMMU_SWIF_KCMD_S_SYNC_LATENCY 0x65
#define UMMU_SWIF_KCMD_NS_SYNC_LATENCY 0x66
#define UMMU_SWIF_UCMD_SYNC_LATENCY 0x67
#define UMMU_UBIF_KV_CACHE_HIT_RATE 0x2F
#define UMMU_TCU_GPC_CACHE_HIT_RATE 0x2A
#define UMMU_TCU_TPTW_REQ_LATENCY 0x68
#define UMMU_TCU_PPTW_REQ_LATENCY 0x69
#define UMMU_TCU_GPC_REQ_LATENCY 0x6A
#define UMMU_TBU_PTW_PACK_RATE 0x4C
#define UMMU_TBU_PPTW_PACK_RATE 0x4D
#define UMMU_TBU_PTW_LATENCY 0x6C
#define UMMU_TBU_PPTW_LATENCY 0x6D
#define UMMU_TBU_RAB_BUF_USE_RATE 0x8E
#define UMMU_SWIF_KCMD_GPC_SYNC_LATENCY 0x70
#define UMMU_SWIF_KCMD_REALM_SYNC_LATENCY 0x71

#define UMMU_PMCG_CFGR_SIZE 32
#define UMMU_EVTYPE_SHIFT 5
#define UMMU_PMCG_MASTER_ID_SHIFT 20
#define UMMU_PMCG_USER_DEF_ID_SHIFT 16
#define UMMU_PMCG_MASTER_ID_MSK_SHIFT 20
#define UMMU_PMCG_USER_DEF_ID_MSK_SHIFT 16
#define UMMU_PMCG_PA_SHIFT 12
#define UMMU_USI_MEMATTR_DEVICE_nGnRE 0x01
#define UMMU_COUNTER_LEN 31

static int g_partid;
static int g_pmg;
#define NUMBER_BASE_DECIMAL 10
#define UMMU_PMU_MULTIPLES_RATE 100

#define UMMU_PMU_DRV_NAME "ummu_pmu"

#define to_ummu_pmu(p) (container_of(p, struct ummu_pmu, pmu))

#define UMMU_PMU_EVENT_ATTR_EXTRACTOR(_name, _config, _start, _end)  \
	static inline uint32_t get_##_name(struct perf_event *event) \
	{                                                            \
		return FIELD_GET(GENMASK_ULL(_end, _start),          \
				 event->attr._config);               \
	}

UMMU_PMU_EVENT_ATTR_EXTRACTOR(event, config, 0, 7);
UMMU_PMU_EVENT_ATTR_EXTRACTOR(token_id, config1, 0, 19);
UMMU_PMU_EVENT_ATTR_EXTRACTOR(master_id, config1, 20, 31);
UMMU_PMU_EVENT_ATTR_EXTRACTOR(tect_tag, config1, 32, 47);
UMMU_PMU_EVENT_ATTR_EXTRACTOR(user_define_id, config1, 48, 63);
UMMU_PMU_EVENT_ATTR_EXTRACTOR(token_id_flt_msk, config2, 0, 19);
UMMU_PMU_EVENT_ATTR_EXTRACTOR(master_id_flt_msk, config2, 20, 31);
UMMU_PMU_EVENT_ATTR_EXTRACTOR(tect_tag_flt_msk, config2, 32, 47);
UMMU_PMU_EVENT_ATTR_EXTRACTOR(user_define_id_flt_msk, config2, 48, 63);

enum ummu_pmu_event_type {
	UMMU_PMU_EVENT_TYPE_NUM = 0x00,
	UMMU_PMU_EVENT_TYPE_HIT_RATE = 0x01,
	UMMU_PMU_EVENT_TYPE_FREQ = 0x02,
	UMMU_PMU_EVENT_TYPE_AVER_LATENCY = 0x03,
	UMMU_PMU_EVENT_TYPE_BUF_OCCUPY_RATE = 0x04,
};

static atomic_t ummu_pmu_index = ATOMIC_INIT(0);
static int ummu_pmu_cpuhp_state;

/* events attributes */
static ssize_t ummu_pmu_events_sysfs_show(struct device *dev,
					  struct device_attribute *attr,
					  char *buf)
{
	struct perf_pmu_events_attr *ummu_pmu_attr;

	ummu_pmu_attr = container_of(attr, struct perf_pmu_events_attr, attr);

	return sysfs_emit(buf, "event=0x%08llx\n", ummu_pmu_attr->id);
}

#define UMMU_EVENT_ATTR(name, config) \
	PMU_EVENT_ATTR_ID(name, ummu_pmu_events_sysfs_show, config)

static struct attribute *ummu_pmu_events_attrs[] = {
	UMMU_EVENT_ATTR(tcu_pptw_req_num, UMMU_TCU_PPTW_REQ_NUM),
	UMMU_EVENT_ATTR(tcu_cntx_cache_miss_num, UMMU_TCU_CNTX_CACHE_MISS_NUM),
	UMMU_EVENT_ATTR(tbu_tlb_cache_hit_rate, UMMU_TBU_TLB_CACHE_HIT_RATE),
	UMMU_EVENT_ATTR(tbu_plb_cache_hit_rate, UMMU_TBU_PLB_CACHE_HIT_RATE),
	UMMU_EVENT_ATTR(tcu_tptw_cache_hit_rate, UMMU_TCU_TPTW_CACHE_HIT_RATE),
	UMMU_EVENT_ATTR(tcu_pptw_cache_hit_rate, UMMU_TCU_PPTW_CACHE_HIT_RATE),
	UMMU_EVENT_ATTR(ummu_req_rate, UMMU_REQ_RATE),
	UMMU_EVENT_ATTR(ummu_rsp_rate, UMMU_RSP_RATE),
	UMMU_EVENT_ATTR(ummu_req_average_latency, UMMU_REQ_AVERAGE_LATENCY),
	UMMU_EVENT_ATTR(kv_table_rd_average_latency, UMMU_KV_TABLE_RD_AVERAGE_LATENCY),
	UMMU_EVENT_ATTR(swif_cmd_send_num, UMMU_SWIF_CMD_SEND_NUM),
	UMMU_EVENT_ATTR(swif_dvm_sync_latency, UMMU_SWIF_DVM_SYNC_LATENCY),
	UMMU_EVENT_ATTR(swif_kcmd_s_sync_latency, UMMU_SWIF_KCMD_S_SYNC_LATENCY),
	UMMU_EVENT_ATTR(swif_kcmd_ns_sync_latency, UMMU_SWIF_KCMD_NS_SYNC_LATENCY),
	UMMU_EVENT_ATTR(swif_ucmd_sync_latency, UMMU_SWIF_UCMD_SYNC_LATENCY),
	UMMU_EVENT_ATTR(ubif_kv_cache_hit_rate, UMMU_UBIF_KV_CACHE_HIT_RATE),
	UMMU_EVENT_ATTR(tcu_gpc_cache_hit_rate, UMMU_TCU_GPC_CACHE_HIT_RATE),
	UMMU_EVENT_ATTR(tcu_tptw_req_latency, UMMU_TCU_TPTW_REQ_LATENCY),
	UMMU_EVENT_ATTR(tcu_pptw_req_latency, UMMU_TCU_PPTW_REQ_LATENCY),
	UMMU_EVENT_ATTR(tcu_gpc_req_latency, UMMU_TCU_GPC_REQ_LATENCY),
	UMMU_EVENT_ATTR(tbu_ptw_pack_rate, UMMU_TBU_PTW_PACK_RATE),
	UMMU_EVENT_ATTR(tbu_pptw_pack_rate, UMMU_TBU_PPTW_PACK_RATE),
	UMMU_EVENT_ATTR(tbu_ptw_latency, UMMU_TBU_PTW_LATENCY),
	UMMU_EVENT_ATTR(tbu_pptw_latency, UMMU_TBU_PPTW_LATENCY),
	UMMU_EVENT_ATTR(tbu_rab_buf_use_rate, UMMU_TBU_RAB_BUF_USE_RATE),
	UMMU_EVENT_ATTR(swif_kcmd_gpc_sync_latency, UMMU_SWIF_KCMD_GPC_SYNC_LATENCY),
	UMMU_EVENT_ATTR(swif_kcmd_realm_sync_latency, UMMU_SWIF_KCMD_REALM_SYNC_LATENCY),
	NULL
};

static const struct attribute_group ummu_pmu_events_attr_group = {
	.name = "events",
	.attrs = ummu_pmu_events_attrs
};

#define PRE_CNT1_MAX_IDX (ARRAY_SIZE(ummu_pmu_events_attrs) - 1)
static	uint32_t pre_count1_idx[UMMU_PMCG_MAX_COUNTERS];
static	local64_t pre_count1[ARRAY_SIZE(ummu_pmu_events_attrs)];
#define PRE_CNT1_ADDR(cnt_idx) (&pre_count1[pre_count1_idx[cnt_idx]])

static uint32_t get_local_pre_count_idx(uint32_t event_id)
{
	struct perf_pmu_events_attr *pmu_attr;
	uint32_t idx;

	for (idx = 0; idx < ARRAY_SIZE(ummu_pmu_events_attrs) &&
		      ummu_pmu_events_attrs[idx]; idx++) {
		pmu_attr = container_of(container_of(ummu_pmu_events_attrs[idx],
						     struct device_attribute,
						     attr),
					struct perf_pmu_events_attr, attr);

		if (pmu_attr && pmu_attr->id == event_id)
			return idx;
	}

	return PRE_CNT1_MAX_IDX;
}

static irqreturn_t ummu_pmu_handle_irq(int irq, void *data)
{
	struct ummu_pmu *ummu_pmu = (struct ummu_pmu *)data;
	u32 overflow;
	int idx;

	/*
	 * Find the counter index which overflowed if the bit was set and handle it.
	 */
	for (idx = 0; idx < UMMU_PMCG_MAX_COUNTERS; idx++) {
		overflow = readl(ummu_pmu->reg_base + UMMU_PMCG_OVF_INT_STS(idx + 1));
		/*
		 * As each counter will restart from 0 when it is overflowed,
		 * extra processing is no need, just clear interrupt status.
		 */
		if (overflow)
			writel(0, ummu_pmu->reg_base + UMMU_PMCG_OVF_INT_STS(idx + 1));
	}

	return IRQ_HANDLED;
}

static void ummu_pmu_free_msis(void *data)
{
	struct device *dev = (struct device *)data;

	platform_msi_domain_free_irqs(dev);
}

static void ummu_pmu_write_msi_msg(struct msi_desc *desc, struct msi_msg *msg)
{
	struct ummu_pmu *ummu_pmu;
	phys_addr_t doorbell;
	struct device *dev;

	dev = msi_desc_to_dev(desc);
	ummu_pmu = (struct ummu_pmu *)dev_get_drvdata(dev);
	/* 32-bit addresses are converted to 64-bit addresses. */
	doorbell = (((u64)msg->address_hi) << 32) | msg->address_lo;
	doorbell &= UMMU_PMCG_OVF_USI_ADDR_MASK;

	writeq_relaxed(doorbell, ummu_pmu->reg_base + UMMU_PMCG_OVF_USI_ADDR0);
	writel_relaxed(msg->data, ummu_pmu->reg_base + UMMU_PMCG_OVF_USI_DATA);
	writel_relaxed(UMMU_USI_MEMATTR_DEVICE_nGnRE, ummu_pmu->reg_base + UMMU_PMCG_OVF_USI_ATTR);
}

static void ummu_pmu_setup_irq_affinity(struct ummu_pmu *ummu_pmu,
					 const char *affinity_prop)
{
	struct device_node *np = ummu_pmu->dev->of_node;
	struct cpumask affinity_mask;
	int phandle_num, cpu, i;
	struct device_node *dn;
	int ret;

	if (!np)
		return;

	phandle_num = of_count_phandle_with_args(np, affinity_prop, NULL);
	if (phandle_num <= 0)
		return;

	cpumask_clear(&affinity_mask);
	for (i = 0; i < phandle_num; i++) {
		dn = of_parse_phandle(np, affinity_prop, i);
		if (!dn) {
			dev_warn(ummu_pmu->dev,
				 "failed to parse %s[%d]\n", affinity_prop, i);
			continue;
		}

		cpu = of_cpu_node_to_id(dn);
		of_node_put(dn);
		if (cpu < 0) {
			dev_warn(ummu_pmu->dev,
				 "failed to find logical CPU for phandle[%d]\n", i);
			continue;
		}

		cpumask_set_cpu(cpu, &affinity_mask);
	}

	if (cpumask_empty(&affinity_mask))
		return;

	ret = irq_set_affinity(ummu_pmu->irq, &affinity_mask);
	if (ret)
		dev_warn(ummu_pmu->dev,
			 "failed to set irq affinity=%*pb, ret=%d\n",
			 cpumask_pr_args(&affinity_mask), ret);
}

static int ummu_pmu_setup_irq(struct ummu_pmu *ummu_pmu)
{
	unsigned long flags = IRQF_NOBALANCING | IRQF_SHARED | IRQF_NO_THREAD;
	uint32_t val = UMMU_PMCG_INT_OVF_EN, irq;
	struct device *dev = ummu_pmu->dev;
	int ret;

	/* Clear MSI address reg */
	writeq_relaxed(0, ummu_pmu->reg_base + UMMU_PMCG_OVF_USI_ADDR0);

	writel_relaxed(val, ummu_pmu->reg_base + UMMU_PMCG_INT_EN);
	ret = platform_msi_domain_alloc_irqs(dev, 1, ummu_pmu_write_msi_msg);
	if (ret) {
		dev_warn(dev, "failed to allocate MSIs, ret = %d\n", ret);
		return ret;
	}

	irq = msi_get_virq(dev, 0);
	if (!irq) {
		dev_err(ummu_pmu->dev, "msi get irq failed, irq = %u\n", irq);
		platform_msi_domain_free_irqs(dev);
		return -ENXIO;
	}
	ummu_pmu->irq = irq;

	/* Add callback to free MSIs on teardown */
	ret = devm_add_action_or_reset(dev, ummu_pmu_free_msis, dev);
	if (ret) {
		dev_err(dev, "failed to add free msis action (%d).\n", ret);
		return ret;
	}

	ret = devm_request_irq(ummu_pmu->dev, irq, ummu_pmu_handle_irq, flags,
				dev_name(ummu_pmu->dev), ummu_pmu);
	if (ret)
		return ret;

	ummu_pmu_setup_irq_affinity(ummu_pmu, "interrupt-affinity");

	return 0;
}

static int ummu_pmu_reset(struct ummu_pmu *ummu_pmu)
{
	uint32_t val;
	int ret;

	val = readl_relaxed(ummu_pmu->reg_base + UMMU_PMCG_GLB_CTRL);
	val |= UMMU_PMCG_GLB_CTRL_COMMON_CLR;
	writel_relaxed(val, ummu_pmu->reg_base + UMMU_PMCG_GLB_CTRL);

	val &= ~UMMU_PMCG_GLB_CTRL_COMMON_CLR;
	writel_relaxed(val, ummu_pmu->reg_base + UMMU_PMCG_GLB_CTRL);

	ummu_pmu->num_counters = UMMU_PMCG_MAX_COUNTERS;
	ret = ummu_pmu_setup_irq(ummu_pmu);
	if (ret) {
		dev_err(ummu_pmu->dev, "error %d setup irq failed!\n", ret);
		return ret;
	}

	val |= UMMU_PMCG_ICG_EN_ICG;
	writel_relaxed(val, ummu_pmu->reg_base + UMMU_PMCG_ICG_EN);

	/* Pick one CPU to be the preferred one to use */
	ummu_pmu->on_cpu = smp_processor_id();
	ret = cpuhp_state_add_instance_nocalls(
		(enum cpuhp_state)ummu_pmu_cpuhp_state, &ummu_pmu->node);
	if (ret)
		dev_err(ummu_pmu->dev, "error %d registering hotplug!\n", ret);

	return ret;
}

static void ummu_pmu_enable(struct pmu *pmu)
{
	struct ummu_pmu *ummu_pmu = to_ummu_pmu(pmu);
	uint32_t val;

	val = readl(ummu_pmu->reg_base + UMMU_PMCG_GLB_CTRL);
	val |= UMMU_PMCG_GLB_CTRL_COMMON_ENABLE;
	val &= ~UMMU_PMCG_GLB_CTRL_COMMON_CLR;
	writel(val, ummu_pmu->reg_base + UMMU_PMCG_GLB_CTRL);
}

static void ummu_pmu_disable(struct pmu *pmu)
{
	struct ummu_pmu *ummu_pmu = to_ummu_pmu(pmu);
	uint32_t val;

	val = readl(ummu_pmu->reg_base + UMMU_PMCG_GLB_CTRL);
	val &= ~UMMU_PMCG_GLB_CTRL_COMMON_ENABLE;
	writel(val, ummu_pmu->reg_base + UMMU_PMCG_GLB_CTRL);
}

static void ummu_pmu_counter_get_value(struct ummu_pmu *ummu_pmu, int idx,
				       uint64_t *cnt0, uint64_t *cnt1)
{
	uint64_t val0_high, val0_low, val1_high, val1_low;

	val0_low = readl(ummu_pmu->reg_base + UMMU_PMCG_COM_CNT0_L(idx + 1));
	val0_high = readl(ummu_pmu->reg_base + UMMU_PMCG_COM_CNT0_H(idx + 1));
	*cnt0 = val0_high << UMMU_PMCG_CFGR_SIZE | val0_low;

	val1_low = readl(ummu_pmu->reg_base + UMMU_PMCG_COM_CNT1_L(idx + 1));
	val1_high = readl(ummu_pmu->reg_base + UMMU_PMCG_COM_CNT1_H(idx + 1));
	*cnt1 = val1_high << UMMU_PMCG_CFGR_SIZE | val1_low;
}

static void ummu_pmu_counter_set_value(struct ummu_pmu *ummu_pmu, int idx,
				       uint64_t pre_cnt0, uint64_t pre_cnt1)
{
	uint64_t val0_high, val0_low, val1_high, val1_low;

	val0_low = pre_cnt0 & GENMASK_ULL(UMMU_COUNTER_LEN, 0);
	val0_high = pre_cnt0 >> UMMU_PMCG_CFGR_SIZE;
	val1_low = pre_cnt1 & GENMASK_ULL(UMMU_COUNTER_LEN, 0);
	val1_high = pre_cnt1 >> UMMU_PMCG_CFGR_SIZE;

	writel(val0_low, ummu_pmu->reg_base + UMMU_PMCG_COM_CNT0_L(idx + 1));
	writel(val0_high, ummu_pmu->reg_base + UMMU_PMCG_COM_CNT0_H(idx + 1));
	writel(val1_low, ummu_pmu->reg_base + UMMU_PMCG_COM_CNT1_L(idx + 1));
	writel(val1_high, ummu_pmu->reg_base + UMMU_PMCG_COM_CNT1_H(idx + 1));
}

static void ummu_pmu_counter_enable(struct ummu_pmu *ummu_pmu, int idx)
{
	uint32_t val;

	val = readl(ummu_pmu->reg_base + UMMU_PMCG_COM_CTRL(idx + 1));
	val |= UMMU_PMCG_COM_CTRL_EVENT_EN;
	writel(val, ummu_pmu->reg_base + UMMU_PMCG_COM_CTRL(idx + 1));
}

static void ummu_pmu_counter_disable(struct ummu_pmu *ummu_pmu, int idx)
{
	uint32_t val;

	val = readl(ummu_pmu->reg_base + UMMU_PMCG_COM_CTRL(idx + 1));
	val &= ~UMMU_PMCG_COM_CTRL_EVENT_EN;
	writel(val, ummu_pmu->reg_base + UMMU_PMCG_COM_CTRL(idx + 1));
}

static void ummu_pmu_counter_clear_enable(struct ummu_pmu *ummu_pmu, int idx)
{
	uint32_t val;

	val = readl(ummu_pmu->reg_base + UMMU_PMCG_COM_CTRL(idx + 1));
	val |= UMMU_PMCG_COM_CTRL_EVENT_CLR;
	writel(val, ummu_pmu->reg_base + UMMU_PMCG_COM_CTRL(idx + 1));
}

static void ummu_pmu_counter_clear_disable(struct ummu_pmu *ummu_pmu, int idx)
{
	uint32_t val;

	val = readl(ummu_pmu->reg_base + UMMU_PMCG_COM_CTRL(idx + 1));
	val &= ~UMMU_PMCG_COM_CTRL_EVENT_CLR;
	writel(val, ummu_pmu->reg_base + UMMU_PMCG_COM_CTRL(idx + 1));
}

static bool ummu_pmu_validate_event_count(struct perf_event *event)
{
	struct ummu_pmu *ummu_pmu = to_ummu_pmu(event->pmu);
	struct perf_cpu_pmu_context *cpc;

	cpc = per_cpu_ptr(event->pmu->cpu_pmu_context, ummu_pmu->on_cpu);
	if (!cpc) {
		dev_err(ummu_pmu->dev, "cpc is null.\n");
		return false;
	}

	/* The events count must less than the counters in the HW */
	return cpc->epc.nr_events < ummu_pmu->num_counters;
}

static int ummu_pmu_event_init(struct perf_event *event)
{
	struct ummu_pmu *ummu_pmu = to_ummu_pmu(event->pmu);
	struct hw_perf_event *hwc = &event->hw;
	struct device *dev = ummu_pmu->dev;
	uint32_t pre_cnt1_idx;

	if (event->attr.type != event->pmu->type)
		return -ENOENT;

	if (hwc->sample_period) {
		dev_err(dev, "sampling not supported!\n");
		return -EOPNOTSUPP;
	}

	if (event->cpu < 0) {
		dev_err(dev, "per-task mode not supported!\n");
		return -EOPNOTSUPP;
	}

	if (event->attach_state & PERF_ATTACH_TASK) {
		dev_err(dev, "per-task counter cannot allocate!\n");
		return -EOPNOTSUPP;
	}

	/*
	 * Validate if the events in group does not exceed the
	 * available counters in hardware.
	 */
	if (!ummu_pmu_validate_event_count(event)) {
		dev_err(dev, "event count exceeds the available counters!\n");
		return -EINVAL;
	}

	/* Clear the allocated counter */
	hwc->idx = -1;

	/*
	 * Ensure all events are on the same cpu so all events are in the
	 * same cpu context, to avoid races on pmu_enable etc.
	 */
	event->cpu = ummu_pmu->on_cpu;

	pre_cnt1_idx = get_local_pre_count_idx(get_event(event));
	if (pre_cnt1_idx >= PRE_CNT1_MAX_IDX) {
		dev_err(dev, "pre counter1 index invalid, event maybe wrong.\n");
		return -EINVAL;
	}

	local64_set(&hwc->prev_count, 0);
	local64_set(&pre_count1[pre_cnt1_idx], 0);

	return 0;
}

static void ummu_pmu_config_event_type(struct ummu_pmu *ummu_pmu,
				       struct perf_event *event, int idx)
{
	uint32_t type = get_event(event) & UMMU_PMCG_COM_CTRL_EVENT_CODE;
	uint32_t val;

	val = readl(ummu_pmu->reg_base + UMMU_PMCG_COM_CTRL(idx + 1));
	val &= ~UMMU_PMCG_COM_CTRL_EVENT_CODE;
	val |= type;
	writel(val, ummu_pmu->reg_base + UMMU_PMCG_COM_CTRL(idx + 1));
}

static void ummu_pmu_config_event_filter(struct ummu_pmu *ummu_pmu,
					 struct perf_event *event, int idx)
{
	uint32_t user_def_id = get_user_define_id(event);
	uint32_t master_id = get_master_id(event);
	uint32_t tect_tag = get_tect_tag(event);
	uint32_t tid = get_token_id(event);
	uint32_t val;

	val = readl(ummu_pmu->reg_base + UMMU_PMCG_FILT_COND_L(idx + 1));
	if (tid)
		val |= tid;
	if (master_id)
		val |= master_id << UMMU_PMCG_MASTER_ID_SHIFT;

	writel(val, ummu_pmu->reg_base + UMMU_PMCG_FILT_COND_L(idx + 1));

	val = readl(ummu_pmu->reg_base + UMMU_PMCG_FILT_COND_H(idx + 1));
	if (tect_tag)
		val |= tect_tag;
	if (user_def_id)
		val |= user_def_id << UMMU_PMCG_USER_DEF_ID_SHIFT;

	writel(val, ummu_pmu->reg_base + UMMU_PMCG_FILT_COND_H(idx + 1));
}

static void ummu_pmu_config_event_filter_mask(struct ummu_pmu *ummu_pmu,
					      struct perf_event *event, int idx)
{
	uint32_t val, tid_msk, master_id_msk, tect_tag_msk, user_def_id_msk;

	tid_msk = get_token_id_flt_msk(event);
	master_id_msk = get_master_id_flt_msk(event);
	tect_tag_msk = get_tect_tag_flt_msk(event);
	user_def_id_msk = get_user_define_id_flt_msk(event);

	val = readl(ummu_pmu->reg_base + UMMU_PMCG_FILT_MSK_L(idx + 1));

	if (tid_msk) {
		val &= ~UMMU_PMCG_FILT_MSK_L_TOKEN_ID;
		val |= tid_msk;
	}
	if (master_id_msk) {
		val &= ~UMMU_PMCG_FILT_MSK_L_MASTER_ID;
		val |= master_id_msk << UMMU_PMCG_MASTER_ID_MSK_SHIFT;
	}

	writel(val, ummu_pmu->reg_base + UMMU_PMCG_FILT_MSK_L(idx + 1));

	val = readl(ummu_pmu->reg_base + UMMU_PMCG_FILT_MSK_H(idx + 1));

	if (tect_tag_msk) {
		val &= ~UMMU_PMCG_FILT_COND_H_TECT_TAG;
		val |= tect_tag_msk;
	}
	if (user_def_id_msk) {
		val &= ~UMMU_PMCG_FILT_COND_H_USER_DEF_ID;
		val |= user_def_id_msk << UMMU_PMCG_USER_DEF_ID_MSK_SHIFT;
	}

	writel(val, ummu_pmu->reg_base + UMMU_PMCG_FILT_MSK_H(idx + 1));
}

static void ummu_pmu_config_event(struct ummu_pmu *ummu_pmu,
				  struct perf_event *event, int idx)
{
	ummu_pmu_config_event_type(ummu_pmu, event, idx);
	ummu_pmu_config_event_filter(ummu_pmu, event, idx);
	ummu_pmu_config_event_filter_mask(ummu_pmu, event, idx);
}

static void ummu_pmu_config_overflow_int_mask(struct ummu_pmu *ummu_pmu,
						    struct perf_event *event,
						    int idx)
{
	uint32_t val;

	val = readl(ummu_pmu->reg_base + UMMU_PMCG_OVF_INT_MSK(idx + 1));
	val &= ~UMMU_PMCG_CNT0_OVERFLOW_INT_MSK;
	val &= ~UMMU_PMCG_CNT1_OVERFLOW_INT_MSK;
	writel(val, ummu_pmu->reg_base + UMMU_PMCG_OVF_INT_MSK(idx + 1));
}

static void ummu_pmu_event_start(struct perf_event *event, int flags)
{
	struct ummu_pmu *ummu_pmu = to_ummu_pmu(event->pmu);
	struct hw_perf_event *hwc = &event->hw;
	uint64_t prev_count0, prev_count1;
	int idx = hwc->idx;

	if (WARN_ON_ONCE(!(hwc->state & PERF_HES_STOPPED)))
		return;

	WARN_ON_ONCE(!(hwc->state & PERF_HES_UPTODATE));
	hwc->state = 0;

	ummu_pmu_config_event(ummu_pmu, event, idx);

	if (flags & PERF_EF_RELOAD) {
		prev_count0 = (uint64_t)local64_read(&hwc->prev_count);
		prev_count1 = (uint64_t)local64_read(PRE_CNT1_ADDR(idx));
		ummu_pmu_counter_set_value(ummu_pmu, idx, prev_count0, prev_count1);
	}

	ummu_pmu_counter_enable(ummu_pmu, idx);
	ummu_pmu_config_overflow_int_mask(ummu_pmu, event, idx);
	/* Propagate changes to the userspace mapping. */
	perf_event_update_userpage(event);
}

static uint64_t ummu_pmu_calculate(uint8_t event_id, uint64_t cnt0,
				   uint64_t cnt1)
{
	uint8_t event_type = event_id >> UMMU_EVTYPE_SHIFT;
	uint64_t result;

	switch (event_type) {
	case UMMU_PMU_EVENT_TYPE_NUM:
		result = cnt0;
		break;
	case UMMU_PMU_EVENT_TYPE_HIT_RATE:
	case UMMU_PMU_EVENT_TYPE_FREQ:
	case UMMU_PMU_EVENT_TYPE_AVER_LATENCY:
	case UMMU_PMU_EVENT_TYPE_BUF_OCCUPY_RATE:
		if (!cnt0 || !cnt1)
			return 0;
		result = cnt0 * UMMU_PMU_MULTIPLES_RATE / cnt1;
		break;
	default:
		result = 0;
		break;
	}

	return result;
}

static void ummu_pmu_event_update(struct perf_event *event)
{
	struct ummu_pmu *ummu_pmu = to_ummu_pmu(event->pmu);
	struct hw_perf_event *hwc = &event->hw;
	uint64_t new_cnt0, prev_cnt0, new_cnt1;
	int idx = hwc->idx;

	do {
		prev_cnt0 = local64_read(&hwc->prev_count);
		ummu_pmu_counter_get_value(ummu_pmu, idx, &new_cnt0, &new_cnt1);
	} while (local64_cmpxchg(&hwc->prev_count, prev_cnt0, new_cnt0) !=
		 prev_cnt0);

	local64_set(PRE_CNT1_ADDR(idx), new_cnt1);

	local64_set(&event->count,
		    ummu_pmu_calculate(get_event(event), new_cnt0, new_cnt1));

	dev_dbg(ummu_pmu->dev, "pmu event [0x%x] idx [%d] cnt0 [%llu] cnt1 [%llu].\n",
		get_event(event), idx, new_cnt0, new_cnt1);
}

static void ummu_pmu_reset_config_event_type(struct ummu_pmu *ummu_pmu,
					     struct perf_event *event, int idx)
{
	uint32_t val;

	val = readl(ummu_pmu->reg_base + UMMU_PMCG_COM_CTRL(idx + 1));
	val &= ~UMMU_PMCG_COM_CTRL_EVENT_CODE;
	writel(val, ummu_pmu->reg_base + UMMU_PMCG_COM_CTRL(idx + 1));
}

static void ummu_pmu_reset_config_event_filter(struct ummu_pmu *ummu_pmu,
					       struct perf_event *event,
					       int idx)
{
	/* register default value equals to 0x0 */
	writel(0, ummu_pmu->reg_base + UMMU_PMCG_FILT_COND_L(idx + 1));
	writel(0, ummu_pmu->reg_base + UMMU_PMCG_FILT_COND_H(idx + 1));
}

static void ummu_pmu_reset_config_event_filter_mask(struct ummu_pmu *ummu_pmu,
						    struct perf_event *event,
						    int idx)
{
	/* register default value equals to 0x0000000000000000 */
	writel(0, ummu_pmu->reg_base + UMMU_PMCG_FILT_MSK_L(idx + 1));

	writel(0, ummu_pmu->reg_base + UMMU_PMCG_FILT_MSK_H(idx + 1));
}

static void ummu_pmu_reset_config_event(struct ummu_pmu *ummu_pmu,
					struct perf_event *event, int idx)
{
	ummu_pmu_reset_config_event_type(ummu_pmu, event, idx);
	ummu_pmu_config_overflow_int_mask(ummu_pmu, event, idx);
	ummu_pmu_reset_config_event_filter(ummu_pmu, event, idx);
	ummu_pmu_reset_config_event_filter_mask(ummu_pmu, event, idx);
}

static void ummu_pmu_event_stop(struct perf_event *event, int flags)
{
	struct ummu_pmu *ummu_pmu = to_ummu_pmu(event->pmu);
	struct hw_perf_event *hwc = &event->hw;
	int idx = hwc->idx;

	if (hwc->state & PERF_HES_STOPPED)
		return;

	ummu_pmu_counter_disable(ummu_pmu, idx);
	ummu_pmu_reset_config_event(ummu_pmu, event, idx);

	/* Read hardware counter and update the perf counter statistics */
	ummu_pmu_event_update(event);
	hwc->state = hwc->state | PERF_HES_STOPPED | PERF_HES_UPTODATE;
}

static int ummu_pmu_get_event_idx(struct ummu_pmu *ummu_pmu,
				  struct perf_event *event)
{
	uint32_t num_counts = ummu_pmu->num_counters;
	int idx;

	idx = find_first_zero_bit(ummu_pmu->used_counters, num_counts);
	if (idx == num_counts)
		/* The counters are all in use. */
		return -EAGAIN;

	set_bit(idx, ummu_pmu->used_counters);

	return idx;
}

static void ummu_pmu_clear_counter(struct ummu_pmu *ummu_pmu, int idx)
{
	ummu_pmu_counter_clear_enable(ummu_pmu, idx);
	ummu_pmu_counter_clear_disable(ummu_pmu, idx);
}

static int ummu_pmu_event_add(struct perf_event *event, int flags)
{
	struct ummu_pmu *ummu_pmu = to_ummu_pmu(event->pmu);
	struct hw_perf_event *hwc = &event->hw;
	int idx;

	/* Get an available counter index for counting */
	idx = ummu_pmu_get_event_idx(ummu_pmu, event);
	if (idx < 0 || idx >= UMMU_PMCG_MAX_COUNTERS)
		return -EINVAL;

	pre_count1_idx[idx] = get_local_pre_count_idx(get_event(event));
	if (pre_count1_idx[idx] >= PRE_CNT1_MAX_IDX) {
		dev_err(ummu_pmu->dev, "pre counter1 [%u] index invalid, event maybe wrong.\n",
			get_event(event));
		return -EINVAL;
	}

	ummu_pmu_clear_counter(ummu_pmu, idx);

	ummu_pmu->events[idx] = event;
	hwc->idx = idx;
	hwc->state = PERF_HES_STOPPED | PERF_HES_UPTODATE;

	if (flags & PERF_EF_START)
		ummu_pmu_event_start(event, PERF_EF_RELOAD);

	dev_dbg(ummu_pmu->dev, "pmu event [0x%x] idx [%d] pre_cnt1 idx [%u] add finished.\n",
		get_event(event), idx, pre_count1_idx[idx]);

	return 0;
}

static void ummu_pmu_event_del(struct perf_event *event, int flags)
{
	struct ummu_pmu *ummu_pmu = to_ummu_pmu(event->pmu);
	struct hw_perf_event *hwc = &event->hw;
	int idx = hwc->idx;

	if (idx < 0) {
		dev_err(ummu_pmu->dev, "event no exist!\n");
		return;
	}

	ummu_pmu_event_stop(event, flags | PERF_EF_UPDATE);
	ummu_pmu->events[idx] = NULL;
	pre_count1_idx[idx] = PRE_CNT1_MAX_IDX;
	clear_bit(idx, ummu_pmu->used_counters);

	perf_event_update_userpage(event);
}

static void ummu_pmu_event_read(struct perf_event *event)
{
	ummu_pmu_event_update(event);
}

/* cpumask attributes */
static ssize_t ummu_pmu_cpumask_show(struct device *dev,
				     struct device_attribute *attr, char *buf)
{
	struct ummu_pmu *ummu_pmu = to_ummu_pmu(dev_get_drvdata(dev));

	return cpumap_print_to_pagebuf(true, buf, cpumask_of(ummu_pmu->on_cpu));
}

static struct device_attribute ummu_pmu_cpumask_attr =
	__ATTR(cpumask, 0444, ummu_pmu_cpumask_show, NULL);

static struct attribute *ummu_pmu_cpumask_attrs[] = {
	&ummu_pmu_cpumask_attr.attr,
	NULL
};

static const struct attribute_group ummu_pmu_cpumask_attr_group = {
	.attrs = ummu_pmu_cpumask_attrs
};

/* format attributes */
static ssize_t ummu_pmu_format_show(struct device *dev,
				    struct device_attribute *attr, char *buf)
{
	struct dev_ext_attribute *eattr;

	eattr = container_of(attr, struct dev_ext_attribute, attr);
	return sysfs_emit(buf, "%s\n", (char *)eattr->var);
}

#define UMMU_PMU_FORMAT(_name, _func, _config)                                \
	(&((struct dev_ext_attribute[]){                                      \
		{ __ATTR(_name, 0444, _func, NULL), _config} })[0]            \
		  .attr.attr)

#define UMMU_PMU_FORMAT_ATTR(_name, _format) \
	UMMU_PMU_FORMAT(_name, ummu_pmu_format_show, _format)

static struct attribute *ummu_pmu_formats_attrs[] = {
	UMMU_PMU_FORMAT_ATTR(event, "config:0-7"),
	UMMU_PMU_FORMAT_ATTR(token_id, "config1:0-19"),
	UMMU_PMU_FORMAT_ATTR(master_id, "config1:20-31"),
	UMMU_PMU_FORMAT_ATTR(tect_tag, "config1:32-47"),
	UMMU_PMU_FORMAT_ATTR(user_define_id, "config1:48-63"),
	UMMU_PMU_FORMAT_ATTR(token_id_flt_msk, "config2:0-19"),
	UMMU_PMU_FORMAT_ATTR(master_id_flt_msk, "config2:20-31"),
	UMMU_PMU_FORMAT_ATTR(tect_tag_flt_msk, "config2:32-47"),
	UMMU_PMU_FORMAT_ATTR(user_define_id_flt_msk, "config2:48-63"),
	NULL
};

static const struct attribute_group ummu_pmu_format_attr_group = {
	.name = "format",
	.attrs = ummu_pmu_formats_attrs
};

static int ummu_pmu_check_usi_mpam_cap(struct ummu_pmu *pmu, int partid, int pmg)
{
	if (partid < 0 || partid > UMMU_PMCG_USI_MPAM_PARTID_MAX) {
		dev_err(pmu->dev, "usi_mpam partid exceeds range: partid[0, %d]\n",
			UMMU_PMCG_USI_MPAM_PARTID_MAX);
		return -ERANGE;
	}

	if (pmg < 0 || pmg > UMMU_PMCG_USI_MPAM_PMG_MAX) {
		dev_err(pmu->dev, "usi_mpam pmg exceeds range: pmg[0, %d]\n",
			UMMU_PMCG_USI_MPAM_PMG_MAX);
		return -ERANGE;
	}

	return 0;
}

static const struct attribute_group *ummu_pmu_attr_groups[] = {
	&ummu_pmu_cpumask_attr_group,
	&ummu_pmu_events_attr_group,
	&ummu_pmu_format_attr_group,
	NULL
};

static int ummu_pmu_set_usi_mpam(struct ummu_pmu *pmu, int partid, int pmg)
{
	uint32_t reg;
	int ret;

	if (!pmu)
		return -EINVAL;

	ret = ummu_pmu_check_usi_mpam_cap(pmu, partid, pmg);
	if (ret)
		return ret;

	reg = UMMU_PMCG_USI_MPAM_NS;
	reg |= FIELD_PREP(UMMU_PMCG_USI_MPAM_PMG, pmg);
	reg |= FIELD_PREP(UMMU_PMCG_USI_MPAM_PARTID, partid);
	writel_relaxed(reg, pmu->reg_base + UMMU_PMCG_USI_MPAM);

	return 0;
}

static int ummu_pmu_get_usi_mpam(struct ummu_pmu *pmu, int *partid, int *pmg)
{
	uint32_t reg;

	if (!pmu)
		return -EINVAL;

	reg = readl_relaxed(pmu->reg_base + UMMU_PMCG_USI_MPAM);
	*partid = FIELD_GET(UMMU_PMCG_USI_MPAM_PARTID, reg);
	*pmg = FIELD_GET(UMMU_PMCG_USI_MPAM_PMG, reg);
	return 0;
}

static int ummu_pmu_offline_cpu(uint32_t cpu, struct hlist_node *node)
{
	struct ummu_pmu *ummu_pmu;
	uint32_t target;

	ummu_pmu = hlist_entry_safe(node, struct ummu_pmu, node);
	if (!ummu_pmu)
		return -ENODEV;

	/* Nothing to do if this CPU doesn't own the PMU */
	if (cpu != ummu_pmu->on_cpu)
		return 0;

	/* Choose a new CPU from all online cpus */
	target = cpumask_any_but(cpu_online_mask, cpu);
	if (target >= nr_cpu_ids)
		return 0;

	perf_pmu_migrate_context(&ummu_pmu->pmu, cpu, target);
	/* Use this CPU for event counting */
	ummu_pmu->on_cpu = target;

	return 0;
}

static void ummu_pmu_init_ops(struct ummu_pmu *ummu_pmu, struct module *module)
{
	ummu_pmu->pmu = (struct pmu) {
		.module = module,
		.attr_groups = ummu_pmu_attr_groups,
		.capabilities = PERF_PMU_CAP_NO_EXCLUDE,
		.task_ctx_nr = perf_invalid_context,
		.pmu_enable = ummu_pmu_enable,
		.pmu_disable = ummu_pmu_disable,
		.event_init = ummu_pmu_event_init,
		.add = ummu_pmu_event_add,
		.del = ummu_pmu_event_del,
		.start = ummu_pmu_event_start,
		.stop = ummu_pmu_event_stop,
		.read = ummu_pmu_event_read
	};
}

static int ummu_pmu_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct ummu_pmu *ummu_pmu;
	struct resource *res;
	char *name;
	int ret;

	ummu_pmu = devm_kzalloc(dev, sizeof(*ummu_pmu), GFP_KERNEL);
	if (!ummu_pmu)
		return dev_err_probe(dev, -ENOMEM, "failed to kzalloc for pmu\n");

	ummu_pmu->dev = dev;
	platform_set_drvdata(pdev, ummu_pmu);

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (unlikely(res == NULL))
		return dev_err_probe(dev, -EINVAL, "IO resource is null\n");

	ummu_pmu->reg_base = devm_ioremap_resource(dev, res);
	if (IS_ERR(ummu_pmu->reg_base))
		return dev_err_probe(dev, PTR_ERR(ummu_pmu->reg_base), "Ioremap failed\n");

	name = devm_kasprintf(dev, GFP_KERNEL, "ummu_pmcg_%d",
			      atomic_inc_return(&ummu_pmu_index) - 1);
	if (!name)
		return dev_err_probe(dev, -ENOMEM, "Create ummu pmu name failed\n");

	ret = ummu_pmu_reset(ummu_pmu);
	if (ret)
		return dev_err_probe(dev, ret, "reset pmu failed\n");

	ummu_pmu_init_ops(ummu_pmu, THIS_MODULE);
	ret = perf_pmu_register(&ummu_pmu->pmu, name, -1);
	if (ret) {
		cpuhp_state_remove_instance_nocalls(
			(enum cpuhp_state)ummu_pmu_cpuhp_state,
			&ummu_pmu->node);
		return dev_err_probe(dev, ret, "registering PMU failed\n");
	}

	return 0;
}

static int ummu_pmu_remove(struct platform_device *pdev)
{
	struct ummu_pmu *ummu_pmu = platform_get_drvdata(pdev);

	if (!ummu_pmu) {
		pr_err("pmu device remove get invalid platform device!\n");
		return -ENODEV;
	}

	perf_pmu_unregister(&ummu_pmu->pmu);
	cpuhp_state_remove_instance_nocalls(
		(enum cpuhp_state)ummu_pmu_cpuhp_state, &ummu_pmu->node);

	return 0;
}

static void ummu_pmu_shutdown(struct platform_device *pdev)
{
	struct ummu_pmu *ummu_pmu = platform_get_drvdata(pdev);

	if (!ummu_pmu) {
		pr_err("pmu device shutdown get invalid platform device!\n");
		return;
	}

	ummu_pmu_disable(&ummu_pmu->pmu);
}

#ifdef CONFIG_OF
static const struct of_device_id hisi_ummu_pmu_of_match[] = {
	{ .compatible = "ub,ummu_pmu", },
	{ }
};
MODULE_DEVICE_TABLE(of, hisi_ummu_pmu_of_match);
#endif

#ifdef CONFIG_ACPI
static const struct acpi_device_id hisi_ummu_pmu_acpi_match[] = {
	{"HISI0571", 0 },
	{ }
};
MODULE_DEVICE_TABLE(acpi, hisi_ummu_pmu_acpi_match);
#endif

static ssize_t partid_store(struct device *kobj, struct device_attribute *attr,
			    const char *buf, size_t count)
{
	int var, ret;

	ret = kstrtoint(buf, NUMBER_BASE_DECIMAL, &var);
	if (ret < 0)
		return ret;

	g_partid = var;
	dev_info(kobj, "ummu mpam input partid = %d.\n", var);
	return count;
}

static ssize_t pmg_store(struct device *kobj, struct device_attribute *attr,
			 const char *buf, size_t count)
{
	int var, ret;

	ret = kstrtoint(buf, NUMBER_BASE_DECIMAL, &var);
	if (ret < 0)
		return ret;

	g_pmg = var;
	dev_info(kobj, "ummu mpam input pmg = %d.\n", var);
	return count;
}

static int check_input_buf(const char *buf)
{
	int var, ret;

	ret = kstrtoint(buf, NUMBER_BASE_DECIMAL, &var);
	if (ret)
		return ret;

	if (var != 1)
		return -EINVAL;

	return 0;
}

static ssize_t run_store(struct device *dev, struct device_attribute *attr,
			 const char *buf, size_t count)
{
	struct ummu_pmu *pmu;
	int ret;

	ret = check_input_buf(buf);
	if (ret)
		return ret;

	pmu = (struct ummu_pmu *)dev_get_drvdata(dev);
	ret = ummu_pmu_set_usi_mpam(pmu, g_partid, g_pmg);
	if (ret) {
		dev_err(dev,
			"ummu_pmu set usi_mpam(partid[%d], pmg[%d]) failed, ret[%d]\n",
			g_partid, g_pmg, ret);
		return ret;
	}

	return count;
}

static ssize_t mpam_info_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct ummu_pmu *pmu = (struct ummu_pmu *)dev_get_drvdata(dev);
	int partid = 0, pmg = 0, ret;

	ret = ummu_pmu_get_usi_mpam(pmu, &partid, &pmg);
	if (ret)
		return ret;
	return sysfs_emit(buf, "partid:%d\npmg:%d\n", partid, pmg);
}

static DEVICE_ATTR_WO(partid);
static DEVICE_ATTR_WO(pmg);
static DEVICE_ATTR_WO(run);
static DEVICE_ATTR_RO(mpam_info);

static struct attribute *ummu_pmu_usi_mpam_attrs[] = {
	&dev_attr_partid.attr,
	&dev_attr_pmg.attr,
	&dev_attr_run.attr,
	&dev_attr_mpam_info.attr,
	NULL
};

static const struct attribute_group ummu_pmu_usi_mpam_attr_group = {
	.name = "usi_mpam",
	.attrs = ummu_pmu_usi_mpam_attrs
};

static const struct attribute_group *ummu_pmu_groups[] = {
	&ummu_pmu_usi_mpam_attr_group,
	NULL
};

static struct platform_driver ummu_pmu_driver = {
	.driver = {
		.name = UMMU_PMU_DRV_NAME,
		.suppress_bind_attrs = true,
		.of_match_table = of_match_ptr(hisi_ummu_pmu_of_match),
		.acpi_match_table = ACPI_PTR(hisi_ummu_pmu_acpi_match),
		.dev_groups = ummu_pmu_groups
	},
	.probe = ummu_pmu_probe,
	.remove = ummu_pmu_remove,
	.shutdown = ummu_pmu_shutdown
};

static int __init ummu_pmu_module_init(void)
{
	int ret;

	ret = cpuhp_setup_state_multi(CPUHP_AP_ONLINE_DYN,
				      "perf/ummu/pmcg:online", NULL,
				      ummu_pmu_offline_cpu);
	if (ret < 0) {
		pr_err("ummu pmu: setup hotplug failed, ret = %d\n", ret);
		return ret;
	}
	ummu_pmu_cpuhp_state = ret;

	ret = platform_driver_register(&ummu_pmu_driver);
	if (ret)
		cpuhp_remove_multi_state(
			(enum cpuhp_state)ummu_pmu_cpuhp_state);

	return ret;
}
module_init(ummu_pmu_module_init);

static void __exit ummu_pmu_module_exit(void)
{
	platform_driver_unregister(&ummu_pmu_driver);
	cpuhp_remove_multi_state((enum cpuhp_state)ummu_pmu_cpuhp_state);
}
module_exit(ummu_pmu_module_exit);

MODULE_DESCRIPTION("PMU driver for UMMU Performance Monitors Extension");
MODULE_LICENSE("GPL");
MODULE_SOFTDEP("pre: ubfi");
MODULE_ALIAS("platform:" UMMU_PMU_DRV_NAME);
