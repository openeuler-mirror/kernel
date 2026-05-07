// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2021, NEBULARMATRIX */
#include <linux/fs.h>
#include "main.h"
#include "counters.h"

/* traffic_class sysfs */
#define TCLASS_MAX_CMD 100

struct tc_attribute {
	struct attribute attr;
	ssize_t (*show)(struct nbl_tc_data *tcd, struct tc_attribute *attr, char *buf);
	ssize_t (*store)(struct nbl_tc_data *tcd, struct tc_attribute *attr,
			 const char *buf, size_t count);
};

static ssize_t traffic_class_show(struct nbl_tc_data *tcd, struct tc_attribute *unused, char *buf)
{
	size_t count = 0;

	mutex_lock(&tcd->lock);
	if (tcd->val >= 0)
		count = snprintf(buf, PAGE_SIZE, "Global tclass=%d\n", tcd->val);
	mutex_unlock(&tcd->lock);

	return count;
}

static int tclass_parse_tclass(const char *str, int *ptr)
{
	int *tclass = ptr;
	int ret;

	ret = kstrtoint(str, 0, tclass);

	if (ret || *tclass > 0xff)
		return -EINVAL;

	return 0;
}

static ssize_t traffic_class_store(struct nbl_tc_data *tcd, struct tc_attribute *unused,
				   const char *buf, size_t count)
{
	char cmd[TCLASS_MAX_CMD + 1] = {};
	int ret;
	int tclass;

	if (count > TCLASS_MAX_CMD)
		return -EINVAL;
	memcpy(cmd, buf, count);

	ret = tclass_parse_tclass(cmd, &tclass);
	if (ret)
		return -EINVAL;

	mutex_lock(&tcd->lock);
	tcd->val = tclass;
	mutex_unlock(&tcd->lock);

	return count;
}

#define TC_ATTR(_name, _mode, _show, _store) \
	struct tc_attribute tc_attr_##_name = __ATTR(_name, _mode, _show, _store)

static TC_ATTR(traffic_class, 0644, traffic_class_show, traffic_class_store);

static struct attribute *tc_attrs[] = {
	&tc_attr_traffic_class.attr,
	NULL
};

static ssize_t tc_attr_show(struct kobject *kobj, struct attribute *attr, char *buf)
{
	struct tc_attribute *tc_attr = container_of(attr, struct tc_attribute, attr);
	struct nbl_tc_data *tcd = container_of(kobj, struct nbl_tc_data, kobj);

	if (!tc_attr->show)
		return -EIO;

	return tc_attr->show(tcd, tc_attr, buf);
}

static ssize_t tc_attr_store(struct kobject *kobj, struct attribute *attr,
					const char *buf, size_t count)
{
	struct tc_attribute *tc_attr = container_of(attr, struct tc_attribute, attr);
	struct nbl_tc_data *tcd = container_of(kobj, struct nbl_tc_data, kobj);

	if (!tc_attr->store)
		return -EIO;

	return tc_attr->store(tcd, tc_attr, buf, count);
}

static const struct sysfs_ops tc_sysfs_ops = {
	.show = tc_attr_show,
	.store = tc_attr_store
};

ATTRIBUTE_GROUPS(tc);

static const struct kobj_type tc_type = {
	.sysfs_ops     = &tc_sysfs_ops,
	.default_groups = tc_groups
};

static void cleanup_tc_sysfs(struct nbl_device *nbldev)
{
	if (nbldev->tc_kobj) {
		int port;

		kobject_put(nbldev->tc_kobj);
		nbldev->tc_kobj = NULL;
		for (port = 0; port < NBL_MAX_PORT; port++) {
			struct nbl_tc_data *tcd = &nbldev->tcd[port];

			if (tcd->initialized)
				kobject_put(&tcd->kobj);
		}
	}
}

static void init_tc_sysfs(struct nbl_device *nbldev)
{
	struct device *device = &nbldev->ibdev.dev;
	int port = 0;
	int err = 0;

	nbldev->tc_kobj = kobject_create_and_add("tc", &device->kobj);
	if (!nbldev->tc_kobj)
		return;

	for (port = 0; port < NBL_MAX_PORT; port++) {
		struct nbl_tc_data *tcd = &nbldev->tcd[port];

		err = kobject_init_and_add(&tcd->kobj, &tc_type, nbldev->tc_kobj, "%d", port+1);
		if (err)
			goto err;
		tcd->val = -1;
		tcd->nbldev = nbldev;
		tcd->initialized = true;
		mutex_init(&tcd->lock);
	}
	return;

err:
	cleanup_tc_sysfs(nbldev);
}

/* ecn sysfs */
static const char *nbl_get_cong_protocol(int protocol)
{
	switch (protocol) {
	case NBL_CONG_PROTOCOL_ROCE_RP:
			return "roce_rp";
	case NBL_CONG_PROTOCOL_ROCE_NP:
			return "roce_np";
	}
	return "";
}

/* ecn roce_np */
static ssize_t nbl_show_qcn_sendcnp_time_th(struct kobject *kobj,
								struct kobj_attribute *attr,
								char *buf)
{
	struct nbl_ecn_np_attributes *np_attr = container_of(attr,
								struct nbl_ecn_np_attributes,
								qcn_sendcnp_time_th);
	u32 var = -1;

	var = show_cc_param(np_attr->nbldev, NBL_CFG_QCN_SENDCNP_TIME_TH);

	return sprintf(buf, "%d\n", var);
}

static ssize_t nbl_store_qcn_sendcnp_time_th(struct kobject *kobj,
								struct kobj_attribute *attr,
								const char *buf, size_t count)
{
	struct nbl_ecn_np_attributes *np_attr = container_of(attr,
								struct nbl_ecn_np_attributes,
								qcn_sendcnp_time_th);
	int var;
	int ret;

	if (kstrtoint(buf, 0, &var) != 0)
		return -EINVAL;

	ret = config_cc_param(np_attr->nbldev, NBL_CFG_QCN_SENDCNP_TIME_TH, var);

	return ret ? ret : count;
}

static ssize_t nbl_show_qcn_sendcnp_flag(struct kobject *kobj,
								struct kobj_attribute *attr,
								char *buf)
{
	struct nbl_ecn_np_attributes *np_attr = container_of(attr,
								struct nbl_ecn_np_attributes,
								qcn_sendcnp_flag);
	u32 var = -1;

	var = show_cc_param(np_attr->nbldev, NBL_CFG_QCN_SENDCNP_FLAG);

	return sprintf(buf, "%d\n", var);
}

static ssize_t nbl_store_qcn_sendcnp_flag(struct kobject *kobj,
								struct kobj_attribute *attr,
								const char *buf, size_t count)
{
	struct nbl_ecn_np_attributes *np_attr = container_of(attr,
								struct nbl_ecn_np_attributes,
								qcn_sendcnp_flag);
	int var;
	int ret;

	if (kstrtoint(buf, 0, &var) != 0)
		return -EINVAL;

	ret = config_cc_param(np_attr->nbldev, NBL_CFG_QCN_SENDCNP_FLAG, var);

	return ret ? ret : count;
}

/* ecn roce_rp */
#define TO_UPPER_AND_PREFIX(name) NBL_CFG_##name

#define DEFINE_NBL_SHOW_FUNC(name, cfg_name) \
static ssize_t nbl_show_##name(struct kobject *kobj, \
						struct kobj_attribute *attr, \
						char *buf) \
{ \
	struct nbl_ecn_rp_attributes *rp_attr = container_of(attr, \
								struct nbl_ecn_rp_attributes, \
								name); \
	u32 var = -1; \
\
	var = show_cc_param(rp_attr->nbldev, cfg_name); \
	return sprintf(buf, "%d\n", var); \
}

#define DEFINE_NBL_STORE_FUNC(name, cfg_name) \
static ssize_t nbl_store_##name(struct kobject *kobj, \
						struct kobj_attribute *attr, \
						const char *buf, size_t count) \
{ \
	struct nbl_ecn_rp_attributes *rp_attr = container_of(attr, \
								struct nbl_ecn_rp_attributes, \
								name); \
	int var, ret; \
\
	if (kstrtoint(buf, 0, &var) != 0) \
		return -EINVAL; \
\
	ret = config_cc_param(rp_attr->nbldev, cfg_name, var); \
	return ret ? ret : count; \
}

DEFINE_NBL_SHOW_FUNC(qcn_rr_th, TO_UPPER_AND_PREFIX(QCN_RR_TH))
DEFINE_NBL_STORE_FUNC(qcn_rr_th, TO_UPPER_AND_PREFIX(QCN_RR_TH))

DEFINE_NBL_SHOW_FUNC(qcn_quick_start_flag, TO_UPPER_AND_PREFIX(QCN_QUICK_START_FLAG))
DEFINE_NBL_STORE_FUNC(qcn_quick_start_flag, TO_UPPER_AND_PREFIX(QCN_QUICK_START_FLAG))

DEFINE_NBL_SHOW_FUNC(qcn_ai_rp, TO_UPPER_AND_PREFIX(QCN_AI_RP))
DEFINE_NBL_STORE_FUNC(qcn_ai_rp, TO_UPPER_AND_PREFIX(QCN_AI_RP))

DEFINE_NBL_SHOW_FUNC(qcn_hai_rp, TO_UPPER_AND_PREFIX(QCN_HAI_RP))
DEFINE_NBL_STORE_FUNC(qcn_hai_rp, TO_UPPER_AND_PREFIX(QCN_HAI_RP))

DEFINE_NBL_SHOW_FUNC(qcn_max_rate_rp, TO_UPPER_AND_PREFIX(QCN_MAX_RATE_RP))
DEFINE_NBL_STORE_FUNC(qcn_max_rate_rp, TO_UPPER_AND_PREFIX(QCN_MAX_RATE_RP))

DEFINE_NBL_SHOW_FUNC(qcn_min_rate_rp, TO_UPPER_AND_PREFIX(QCN_MIN_RATE_RP))
DEFINE_NBL_STORE_FUNC(qcn_min_rate_rp, TO_UPPER_AND_PREFIX(QCN_MIN_RATE_RP))

DEFINE_NBL_SHOW_FUNC(qcn_start_rate, TO_UPPER_AND_PREFIX(QCN_START_RATE))
DEFINE_NBL_STORE_FUNC(qcn_start_rate, TO_UPPER_AND_PREFIX(QCN_START_RATE))

DEFINE_NBL_SHOW_FUNC(qcn_rr_mode, TO_UPPER_AND_PREFIX(QCN_RR_MODE))
DEFINE_NBL_STORE_FUNC(qcn_rr_mode, TO_UPPER_AND_PREFIX(QCN_RR_MODE))

DEFINE_NBL_SHOW_FUNC(qcn_mid_sendblk_th_high, TO_UPPER_AND_PREFIX(QCN_MID_SENDBLK_TH_HIGH))
DEFINE_NBL_STORE_FUNC(qcn_mid_sendblk_th_high, TO_UPPER_AND_PREFIX(QCN_MID_SENDBLK_TH_HIGH))

DEFINE_NBL_SHOW_FUNC(qcn_mid_sendblk_th_low, TO_UPPER_AND_PREFIX(QCN_MID_SENDBLK_TH_LOW))
DEFINE_NBL_STORE_FUNC(qcn_mid_sendblk_th_low, TO_UPPER_AND_PREFIX(QCN_MID_SENDBLK_TH_LOW))

DEFINE_NBL_SHOW_FUNC(qcn_mid_sendtime_th_high, TO_UPPER_AND_PREFIX(QCN_MID_SENDTIME_TH_HIGH))
DEFINE_NBL_STORE_FUNC(qcn_mid_sendtime_th_high, TO_UPPER_AND_PREFIX(QCN_MID_SENDTIME_TH_HIGH))

DEFINE_NBL_SHOW_FUNC(qcn_mid_sendtime_th_low, TO_UPPER_AND_PREFIX(QCN_MID_SENDTIME_TH_LOW))
DEFINE_NBL_STORE_FUNC(qcn_mid_sendtime_th_low, TO_UPPER_AND_PREFIX(QCN_MID_SENDTIME_TH_LOW))

DEFINE_NBL_SHOW_FUNC(qcn_extra_quanta, TO_UPPER_AND_PREFIX(QCN_EXTRA_QUANTA))
DEFINE_NBL_STORE_FUNC(qcn_extra_quanta, TO_UPPER_AND_PREFIX(QCN_EXTRA_QUANTA))

DEFINE_NBL_SHOW_FUNC(qcn_fast_reduce_mode, TO_UPPER_AND_PREFIX(QCN_FAST_REDUCE_MODE))
DEFINE_NBL_STORE_FUNC(qcn_fast_reduce_mode, TO_UPPER_AND_PREFIX(QCN_FAST_REDUCE_MODE))

DEFINE_NBL_SHOW_FUNC(qcn_reduce_coe, TO_UPPER_AND_PREFIX(QCN_REDUCE_COE))
DEFINE_NBL_STORE_FUNC(qcn_reduce_coe, TO_UPPER_AND_PREFIX(QCN_REDUCE_COE))

/* ecn cc_en cc_mode */
static ssize_t nbl_show_cc_mode(struct kobject *kobj,
						struct kobj_attribute *attr,
						char *buf)
{
	struct nbl_device *nbldev = container_of(attr, struct nbl_device, cc_mode);
	u32 var = -1;

	var = show_cc_param(nbldev, NBL_CFG_CC_MODE);
	return sprintf(buf, "%d\n", var);
}

static ssize_t nbl_store_cc_mode(struct kobject *kobj,
						struct kobj_attribute *attr,
						const char *buf, size_t count)
{
	struct nbl_device *nbldev = container_of(attr, struct nbl_device, cc_mode);
	int var, ret;

	if (kstrtoint(buf, 0, &var) != 0)
		return -EINVAL;

	ret = config_cc_param(nbldev, NBL_CFG_CC_MODE, var);
	return ret ? ret : count;
}

static void nbl_fill_rp_attributes(struct kobject *kobj,
							struct nbl_device *nbldev,
							struct nbl_ecn_rp_attributes *rp_attr)
{
	int err;

	rp_attr->nbldev = nbldev;

	// Initialize and create sysfs file for qcn_rr_th
	sysfs_attr_init(&rp_attr->qcn_rr_th.attr);
	rp_attr->qcn_rr_th.attr.name = "qcn_rr_th";
	rp_attr->qcn_rr_th.attr.mode = 0644;
	rp_attr->qcn_rr_th.show = nbl_show_qcn_rr_th;
	rp_attr->qcn_rr_th.store = nbl_store_qcn_rr_th;
	err = sysfs_create_file(kobj, &rp_attr->qcn_rr_th.attr);
	if (err)
		pr_err("Failed to create qcn_rr_th sysfs file\n");

	// Initialize and create sysfs file for qcn_quick_start_flag
	sysfs_attr_init(&rp_attr->qcn_quick_start_flag.attr);
	rp_attr->qcn_quick_start_flag.attr.name = "qcn_quick_start_flag";
	rp_attr->qcn_quick_start_flag.attr.mode = 0644;
	rp_attr->qcn_quick_start_flag.show = nbl_show_qcn_quick_start_flag;
	rp_attr->qcn_quick_start_flag.store = nbl_store_qcn_quick_start_flag;
	err = sysfs_create_file(kobj, &rp_attr->qcn_quick_start_flag.attr);
	if (err)
		pr_err("Failed to create qcn_quick_start_flag sysfs file\n");

	// Initialize and create sysfs file for qcn_ai_rp
	sysfs_attr_init(&rp_attr->qcn_ai_rp.attr);
	rp_attr->qcn_ai_rp.attr.name = "qcn_ai_rp";
	rp_attr->qcn_ai_rp.attr.mode = 0644;
	rp_attr->qcn_ai_rp.show = nbl_show_qcn_ai_rp;
	rp_attr->qcn_ai_rp.store = nbl_store_qcn_ai_rp;
	err = sysfs_create_file(kobj, &rp_attr->qcn_ai_rp.attr);
	if (err)
		pr_err("Failed to create qcn_ai_rp sysfs file\n");

	// Initialize and create sysfs file for qcn_hai_rp
	sysfs_attr_init(&rp_attr->qcn_hai_rp.attr);
	rp_attr->qcn_hai_rp.attr.name = "qcn_hai_rp";
	rp_attr->qcn_hai_rp.attr.mode = 0644;
	rp_attr->qcn_hai_rp.show = nbl_show_qcn_hai_rp;
	rp_attr->qcn_hai_rp.store = nbl_store_qcn_hai_rp;
	err = sysfs_create_file(kobj, &rp_attr->qcn_hai_rp.attr);
	if (err)
		pr_err("Failed to create qcn_hai_rp sysfs file\n");

	// Initialize and create sysfs file for qcn_max_rate_rp
	sysfs_attr_init(&rp_attr->qcn_max_rate_rp.attr);
	rp_attr->qcn_max_rate_rp.attr.name = "qcn_max_rate_rp";
	rp_attr->qcn_max_rate_rp.attr.mode = 0644;
	rp_attr->qcn_max_rate_rp.show = nbl_show_qcn_max_rate_rp;
	rp_attr->qcn_max_rate_rp.store = nbl_store_qcn_max_rate_rp;
	err = sysfs_create_file(kobj, &rp_attr->qcn_max_rate_rp.attr);
	if (err)
		pr_err("Failed to create qcn_max_rate_rp sysfs file\n");

	// Initialize and create sysfs file for qcn_min_rate_rp
	sysfs_attr_init(&rp_attr->qcn_min_rate_rp.attr);
	rp_attr->qcn_min_rate_rp.attr.name = "qcn_min_rate_rp";
	rp_attr->qcn_min_rate_rp.attr.mode = 0644;
	rp_attr->qcn_min_rate_rp.show = nbl_show_qcn_min_rate_rp;
	rp_attr->qcn_min_rate_rp.store = nbl_store_qcn_min_rate_rp;
	err = sysfs_create_file(kobj, &rp_attr->qcn_min_rate_rp.attr);
	if (err)
		pr_err("Failed to create qcn_min_rate_rp sysfs file\n");

	// Initialize and create sysfs file for qcn_start_rate
	sysfs_attr_init(&rp_attr->qcn_start_rate.attr);
	rp_attr->qcn_start_rate.attr.name = "qcn_start_rate";
	rp_attr->qcn_start_rate.attr.mode = 0644;
	rp_attr->qcn_start_rate.show = nbl_show_qcn_start_rate;
	rp_attr->qcn_start_rate.store = nbl_store_qcn_start_rate;
	err = sysfs_create_file(kobj, &rp_attr->qcn_start_rate.attr);
	if (err)
		pr_err("Failed to create qcn_start_rate sysfs file\n");

	// Initialize and create sysfs file for qcn_rr_mode
	sysfs_attr_init(&rp_attr->qcn_rr_mode.attr);
	rp_attr->qcn_rr_mode.attr.name = "qcn_rr_mode";
	rp_attr->qcn_rr_mode.attr.mode = 0644;
	rp_attr->qcn_rr_mode.show = nbl_show_qcn_rr_mode;
	rp_attr->qcn_rr_mode.store = nbl_store_qcn_rr_mode;
	err = sysfs_create_file(kobj, &rp_attr->qcn_rr_mode.attr);
	if (err)
		pr_err("Failed to create qcn_rr_mode sysfs file\n");

	// Initialize and create sysfs file for qcn_mid_sendblk_th_high
	sysfs_attr_init(&rp_attr->qcn_mid_sendblk_th_high.attr);
	rp_attr->qcn_mid_sendblk_th_high.attr.name = "qcn_mid_sendblk_th_high";
	rp_attr->qcn_mid_sendblk_th_high.attr.mode = 0644;
	rp_attr->qcn_mid_sendblk_th_high.show = nbl_show_qcn_mid_sendblk_th_high;
	rp_attr->qcn_mid_sendblk_th_high.store = nbl_store_qcn_mid_sendblk_th_high;
	err = sysfs_create_file(kobj, &rp_attr->qcn_mid_sendblk_th_high.attr);
	if (err)
		pr_err("Failed to create qcn_mid_sendblk_th_high sysfs file\n");

	// Initialize and create sysfs file for qcn_mid_sendblk_th_low
	sysfs_attr_init(&rp_attr->qcn_mid_sendblk_th_low.attr);
	rp_attr->qcn_mid_sendblk_th_low.attr.name = "qcn_mid_sendblk_th_low";
	rp_attr->qcn_mid_sendblk_th_low.attr.mode = 0644;
	rp_attr->qcn_mid_sendblk_th_low.show = nbl_show_qcn_mid_sendblk_th_low;
	rp_attr->qcn_mid_sendblk_th_low.store = nbl_store_qcn_mid_sendblk_th_low;
	err = sysfs_create_file(kobj, &rp_attr->qcn_mid_sendblk_th_low.attr);
	if (err)
		pr_err("Failed to create qcn_mid_sendblk_th_low sysfs file\n");

	// Initialize and create sysfs file for qcn_mid_sendtime_th_high
	sysfs_attr_init(&rp_attr->qcn_mid_sendtime_th_high.attr);
	rp_attr->qcn_mid_sendtime_th_high.attr.name = "qcn_mid_sendtime_th_high";
	rp_attr->qcn_mid_sendtime_th_high.attr.mode = 0644;
	rp_attr->qcn_mid_sendtime_th_high.show = nbl_show_qcn_mid_sendtime_th_high;
	rp_attr->qcn_mid_sendtime_th_high.store = nbl_store_qcn_mid_sendtime_th_high;
	err = sysfs_create_file(kobj, &rp_attr->qcn_mid_sendtime_th_high.attr);
	if (err)
		pr_err("Failed to create qcn_mid_sendtime_th_high sysfs file\n");

	// Initialize and create sysfs file for qcn_mid_sendtime_th_low
	sysfs_attr_init(&rp_attr->qcn_mid_sendtime_th_low.attr);
	rp_attr->qcn_mid_sendtime_th_low.attr.name = "qcn_mid_sendtime_th_low";
	rp_attr->qcn_mid_sendtime_th_low.attr.mode = 0644;
	rp_attr->qcn_mid_sendtime_th_low.show = nbl_show_qcn_mid_sendtime_th_low;
	rp_attr->qcn_mid_sendtime_th_low.store = nbl_store_qcn_mid_sendtime_th_low;
	err = sysfs_create_file(kobj, &rp_attr->qcn_mid_sendtime_th_low.attr);
	if (err)
		pr_err("Failed to create qcn_mid_sendtime_th_low sysfs file\n");

	// Initialize and create sysfs file for qcn_extra_quanta
	sysfs_attr_init(&rp_attr->qcn_extra_quanta.attr);
	rp_attr->qcn_extra_quanta.attr.name = "qcn_extra_quanta";
	rp_attr->qcn_extra_quanta.attr.mode = 0644;
	rp_attr->qcn_extra_quanta.show = nbl_show_qcn_extra_quanta;
	rp_attr->qcn_extra_quanta.store = nbl_store_qcn_extra_quanta;
	err = sysfs_create_file(kobj, &rp_attr->qcn_extra_quanta.attr);
	if (err)
		pr_err("Failed to create qcn_extra_quanta sysfs file\n");

	// Initialize and create sysfs file for qcn_fast_reduce_mode
	sysfs_attr_init(&rp_attr->qcn_fast_reduce_mode.attr);
	rp_attr->qcn_fast_reduce_mode.attr.name = "qcn_fast_reduce_mode";
	rp_attr->qcn_fast_reduce_mode.attr.mode = 0644;
	rp_attr->qcn_fast_reduce_mode.show = nbl_show_qcn_fast_reduce_mode;
	rp_attr->qcn_fast_reduce_mode.store = nbl_store_qcn_fast_reduce_mode;
	err = sysfs_create_file(kobj, &rp_attr->qcn_fast_reduce_mode.attr);
	if (err)
		pr_err("Failed to create qcn_fast_reduce_mode sysfs file\n");

	// Initialize and create sysfs file for qcn_reduce_coe
	sysfs_attr_init(&rp_attr->qcn_reduce_coe.attr);
	rp_attr->qcn_reduce_coe.attr.name = "qcn_reduce_coe";
	rp_attr->qcn_reduce_coe.attr.mode = 0644;
	rp_attr->qcn_reduce_coe.show = nbl_show_qcn_reduce_coe;
	rp_attr->qcn_reduce_coe.store = nbl_store_qcn_reduce_coe;
	err = sysfs_create_file(kobj, &rp_attr->qcn_reduce_coe.attr);
	if (err)
		pr_err("Failed to create qcn_reduce_coe sysfs file\n");
}

static void nbl_remove_rp_attributes(struct kobject *kobj, struct nbl_ecn_rp_attributes *rp_attr)
{
	sysfs_remove_file(kobj, &rp_attr->qcn_rr_th.attr);
	sysfs_remove_file(kobj, &rp_attr->qcn_quick_start_flag.attr);
	sysfs_remove_file(kobj, &rp_attr->qcn_ai_rp.attr);
	sysfs_remove_file(kobj, &rp_attr->qcn_hai_rp.attr);
	sysfs_remove_file(kobj, &rp_attr->qcn_max_rate_rp.attr);
	sysfs_remove_file(kobj, &rp_attr->qcn_min_rate_rp.attr);
	sysfs_remove_file(kobj, &rp_attr->qcn_start_rate.attr);
	sysfs_remove_file(kobj, &rp_attr->qcn_rr_mode.attr);
	sysfs_remove_file(kobj, &rp_attr->qcn_mid_sendblk_th_high.attr);
	sysfs_remove_file(kobj, &rp_attr->qcn_mid_sendblk_th_low.attr);
	sysfs_remove_file(kobj, &rp_attr->qcn_mid_sendtime_th_high.attr);
	sysfs_remove_file(kobj, &rp_attr->qcn_mid_sendtime_th_low.attr);
	sysfs_remove_file(kobj, &rp_attr->qcn_extra_quanta.attr);
	sysfs_remove_file(kobj, &rp_attr->qcn_fast_reduce_mode.attr);
	sysfs_remove_file(kobj, &rp_attr->qcn_reduce_coe.attr);
}

static void nbl_fill_np_attributes(struct kobject *kobj, struct nbl_device *nbldev,
							struct nbl_ecn_np_attributes *np_attr)
{
	int err;

	np_attr->nbldev = nbldev;

	sysfs_attr_init(&np_attr->qcn_sendcnp_flag.attr);
	np_attr->qcn_sendcnp_flag.attr.name = "qcn_sendcnp_flag";
	np_attr->qcn_sendcnp_flag.attr.mode = 0644;
	np_attr->qcn_sendcnp_flag.show  = nbl_show_qcn_sendcnp_flag;
	np_attr->qcn_sendcnp_flag.store = nbl_store_qcn_sendcnp_flag;
	err = sysfs_create_file(kobj, &np_attr->qcn_sendcnp_flag.attr);
	if (err)
		pr_err("Failed to create qcn_sendcnp_flag sysfs file\n");

	sysfs_attr_init(&np_attr->qcn_sendcnp_time_th.attr);
	np_attr->qcn_sendcnp_time_th.attr.name = "qcn_sendcnp_time_th";
	np_attr->qcn_sendcnp_time_th.attr.mode = 0644;
	np_attr->qcn_sendcnp_time_th.show  = nbl_show_qcn_sendcnp_time_th;
	np_attr->qcn_sendcnp_time_th.store = nbl_store_qcn_sendcnp_time_th;
	err = sysfs_create_file(kobj, &np_attr->qcn_sendcnp_time_th.attr);
	if (err)
		pr_err("Failed to create qcn_sendcnp_time_th sysfs file\n");
}

static void nbl_remove_np_attributes(struct kobject *kobj, struct nbl_ecn_np_attributes *np_attr)
{
	sysfs_remove_file(kobj, &np_attr->qcn_sendcnp_flag.attr);
	sysfs_remove_file(kobj, &np_attr->qcn_sendcnp_time_th.attr);
}

static void nbl_fill_ecn_attributes(struct nbl_device *nbldev, int proto)
{
	struct nbl_ecn_ctx *ecn_ctx = &nbldev->ecn_ctx[proto];

	switch (proto) {
	case NBL_CONG_PROTOCOL_ROCE_RP:
		return nbl_fill_rp_attributes(ecn_ctx->ecn_proto_kobj, nbldev,
									&ecn_ctx->ecn_attr.rp_attr);
	case NBL_CONG_PROTOCOL_ROCE_NP:
		return nbl_fill_np_attributes(ecn_ctx->ecn_proto_kobj, nbldev,
									&ecn_ctx->ecn_attr.np_attr);
	}
}

static void nbl_remove_ecn_attributes(struct nbl_device *nbldev, int proto)
{
	struct nbl_ecn_ctx *ecn_ctx = &nbldev->ecn_ctx[proto];

	switch (proto) {
	case NBL_CONG_PROTOCOL_ROCE_RP:
		nbl_remove_rp_attributes(ecn_ctx->ecn_proto_kobj, &ecn_ctx->ecn_attr.rp_attr);
		break;
	case NBL_CONG_PROTOCOL_ROCE_NP:
		nbl_remove_np_attributes(ecn_ctx->ecn_proto_kobj, &ecn_ctx->ecn_attr.np_attr);
		break;
	}
}

static void init_ecn_sysfs(struct nbl_device *nbldev)
{
	struct nbl_core_dev_info *cdev_info = (struct nbl_core_dev_info *)nbldev->rf->cdev;
	struct net_device *dev = cdev_info->netdev;
	int i;
	int err;

	nbldev->ecn_root_kobj = kobject_create_and_add("ecn", &dev->dev.kobj);
	if (!nbldev->ecn_root_kobj)
		return;

	sysfs_attr_init(&nbldev->cc_mode.attr);
	nbldev->cc_mode.attr.name = "cc_mode";
	nbldev->cc_mode.attr.mode = 0644;
	nbldev->cc_mode.show = nbl_show_cc_mode;
	nbldev->cc_mode.store = nbl_store_cc_mode;
	err = sysfs_create_file(nbldev->ecn_root_kobj, &nbldev->cc_mode.attr);
	if (err)
		pr_err("Failed to create cc_mode sysfs file\n");

	for (i = 0; i < NBL_CONG_PROTOCOL_NUM; i++) {
		nbldev->ecn_ctx[i].ecn_proto_kobj =
			kobject_create_and_add(nbl_get_cong_protocol(i), nbldev->ecn_root_kobj);
		nbl_fill_ecn_attributes(nbldev, i);
	}
}

static void cleanup_ecn_sysfs(struct nbl_device *nbldev)
{
	int i;

	if (!nbldev->ecn_root_kobj)
		return;

	for (i = 0; i < NBL_CONG_PROTOCOL_NUM; i++) {
		nbl_remove_ecn_attributes(nbldev, i);
		kobject_put(nbldev->ecn_ctx[i].ecn_proto_kobj);
	}

	sysfs_remove_file(nbldev->ecn_root_kobj, &nbldev->cc_mode.attr);
	kobject_put(nbldev->ecn_root_kobj);
	nbldev->ecn_root_kobj = NULL;
}

/* nbl-cc sysfs */
#define DEFINE_NBL_CC_SHOW_FUNC(name, cfg_name) \
static ssize_t nbl_cc_show_##name(struct kobject *kobj, \
						struct kobj_attribute *attr, \
						char *buf) \
{ \
	struct nbl_sysfs_cc_params *cc_params = container_of(attr, \
								struct nbl_sysfs_cc_params, \
								name); \
	u32 var = -1; \
\
	var = show_cc_param(cc_params->nbldev, cfg_name); \
	return sprintf(buf, "%d\n", var); \
}

#define DEFINE_NBL_CC_STORE_FUNC(name, cfg_name) \
static ssize_t nbl_cc_store_##name(struct kobject *kobj, \
						struct kobj_attribute *attr, \
						const char *buf, size_t count) \
{ \
	struct nbl_sysfs_cc_params *cc_params = container_of(attr, \
								struct nbl_sysfs_cc_params, \
								name); \
	int var, ret; \
\
	if (kstrtoint(buf, 0, &var) != 0) \
		return -EINVAL; \
\
	ret = config_cc_param(cc_params->nbldev, cfg_name, var); \
	return ret ? ret : count; \
}

DEFINE_NBL_CC_SHOW_FUNC(cc_mode, TO_UPPER_AND_PREFIX(CC_MODE))
DEFINE_NBL_CC_STORE_FUNC(cc_mode, TO_UPPER_AND_PREFIX(CC_MODE))

DEFINE_NBL_CC_SHOW_FUNC(cc_oamreq_tc_en, TO_UPPER_AND_PREFIX(CC_OAMREQ_TC_EN))
DEFINE_NBL_CC_STORE_FUNC(cc_oamreq_tc_en, TO_UPPER_AND_PREFIX(CC_OAMREQ_TC_EN))

DEFINE_NBL_CC_SHOW_FUNC(cc_oamreq_net_tc, TO_UPPER_AND_PREFIX(CC_OAMREQ_NET_TC))
DEFINE_NBL_CC_STORE_FUNC(cc_oamreq_net_tc, TO_UPPER_AND_PREFIX(CC_OAMREQ_NET_TC))

DEFINE_NBL_CC_SHOW_FUNC(cc_oamack_tc_en, TO_UPPER_AND_PREFIX(CC_OAMACK_TC_EN))
DEFINE_NBL_CC_STORE_FUNC(cc_oamack_tc_en, TO_UPPER_AND_PREFIX(CC_OAMACK_TC_EN))

DEFINE_NBL_CC_SHOW_FUNC(cc_oamack_net_tc, TO_UPPER_AND_PREFIX(CC_OAMACK_NET_TC))
DEFINE_NBL_CC_STORE_FUNC(cc_oamack_net_tc, TO_UPPER_AND_PREFIX(CC_OAMACK_NET_TC))

DEFINE_NBL_CC_SHOW_FUNC(cc_oamack_blk_th, TO_UPPER_AND_PREFIX(CC_OAMACK_BLK_TH))
DEFINE_NBL_CC_STORE_FUNC(cc_oamack_blk_th, TO_UPPER_AND_PREFIX(CC_OAMACK_BLK_TH))

DEFINE_NBL_CC_SHOW_FUNC(cc_targetwin_min, TO_UPPER_AND_PREFIX(CC_TARGETWIN_MIN))
DEFINE_NBL_CC_STORE_FUNC(cc_targetwin_min, TO_UPPER_AND_PREFIX(CC_TARGETWIN_MIN))

DEFINE_NBL_CC_SHOW_FUNC(cc_pkt_num_en, TO_UPPER_AND_PREFIX(CC_PKT_NUM_EN))
DEFINE_NBL_CC_STORE_FUNC(cc_pkt_num_en, TO_UPPER_AND_PREFIX(CC_PKT_NUM_EN))

DEFINE_NBL_CC_SHOW_FUNC(cc_high_rtt_fraction, TO_UPPER_AND_PREFIX(CC_HIGH_RTT_FRACTION))
DEFINE_NBL_CC_STORE_FUNC(cc_high_rtt_fraction, TO_UPPER_AND_PREFIX(CC_HIGH_RTT_FRACTION))

DEFINE_NBL_CC_SHOW_FUNC(cc_low_rtt_fraction, TO_UPPER_AND_PREFIX(CC_LOW_RTT_FRACTION))
DEFINE_NBL_CC_STORE_FUNC(cc_low_rtt_fraction, TO_UPPER_AND_PREFIX(CC_LOW_RTT_FRACTION))

DEFINE_NBL_CC_SHOW_FUNC(cc_inc_tarwinth, TO_UPPER_AND_PREFIX(CC_INC_TARWINTH))
DEFINE_NBL_CC_STORE_FUNC(cc_inc_tarwinth, TO_UPPER_AND_PREFIX(CC_INC_TARWINTH))

DEFINE_NBL_CC_SHOW_FUNC(cc_dec_tarwinth, TO_UPPER_AND_PREFIX(CC_DEC_TARWINTH))
DEFINE_NBL_CC_STORE_FUNC(cc_dec_tarwinth, TO_UPPER_AND_PREFIX(CC_DEC_TARWINTH))

DEFINE_NBL_CC_SHOW_FUNC(cc_targetwin, TO_UPPER_AND_PREFIX(CC_TARGETWIN))
DEFINE_NBL_CC_STORE_FUNC(cc_targetwin, TO_UPPER_AND_PREFIX(CC_TARGETWIN))

DEFINE_NBL_CC_SHOW_FUNC(cc_rtt_offset, TO_UPPER_AND_PREFIX(CC_RTT_OFFSET))
DEFINE_NBL_CC_STORE_FUNC(cc_rtt_offset, TO_UPPER_AND_PREFIX(CC_RTT_OFFSET))

DEFINE_NBL_CC_SHOW_FUNC(cc_rtt_probe_invl, TO_UPPER_AND_PREFIX(CC_RTT_PROBE_INVL))
DEFINE_NBL_CC_STORE_FUNC(cc_rtt_probe_invl, TO_UPPER_AND_PREFIX(CC_RTT_PROBE_INVL))

DEFINE_NBL_CC_SHOW_FUNC(cc_high_pri_rtt_invl, TO_UPPER_AND_PREFIX(CC_HIGH_PRI_RTT_INVL))
DEFINE_NBL_CC_STORE_FUNC(cc_high_pri_rtt_invl, TO_UPPER_AND_PREFIX(CC_HIGH_PRI_RTT_INVL))

DEFINE_NBL_CC_SHOW_FUNC(cc_high_pri_rtt_en, TO_UPPER_AND_PREFIX(CC_HIGH_PRI_RTT_EN))
DEFINE_NBL_CC_STORE_FUNC(cc_high_pri_rtt_en, TO_UPPER_AND_PREFIX(CC_HIGH_PRI_RTT_EN))

DEFINE_NBL_CC_SHOW_FUNC(cc_rst_win_high, TO_UPPER_AND_PREFIX(CC_RST_WIN_HIGH))
DEFINE_NBL_CC_STORE_FUNC(cc_rst_win_high, TO_UPPER_AND_PREFIX(CC_RST_WIN_HIGH))

DEFINE_NBL_CC_SHOW_FUNC(cc_rst_win_en, TO_UPPER_AND_PREFIX(CC_RST_WIN_EN))
DEFINE_NBL_CC_STORE_FUNC(cc_rst_win_en, TO_UPPER_AND_PREFIX(CC_RST_WIN_EN))

DEFINE_NBL_CC_SHOW_FUNC(cc_rst_win_low, TO_UPPER_AND_PREFIX(CC_RST_WIN_LOW))
DEFINE_NBL_CC_STORE_FUNC(cc_rst_win_low, TO_UPPER_AND_PREFIX(CC_RST_WIN_LOW))

DEFINE_NBL_CC_SHOW_FUNC(cc_rst_win_rtt_int, TO_UPPER_AND_PREFIX(CC_RST_WIN_RTT_INT))
DEFINE_NBL_CC_STORE_FUNC(cc_rst_win_rtt_int, TO_UPPER_AND_PREFIX(CC_RST_WIN_RTT_INT))

DEFINE_NBL_CC_SHOW_FUNC(cc_rst_win_rtt_fraction, TO_UPPER_AND_PREFIX(CC_RST_WIN_RTT_FRACTION))
DEFINE_NBL_CC_STORE_FUNC(cc_rst_win_rtt_fraction, TO_UPPER_AND_PREFIX(CC_RST_WIN_RTT_FRACTION))

DEFINE_NBL_CC_SHOW_FUNC(cc_dyn_rtt_offset_en, TO_UPPER_AND_PREFIX(CC_DYN_RTT_OFFSET_EN))
DEFINE_NBL_CC_STORE_FUNC(cc_dyn_rtt_offset_en, TO_UPPER_AND_PREFIX(CC_DYN_RTT_OFFSET_EN))

DEFINE_NBL_CC_SHOW_FUNC(cc_remove_remote_time, TO_UPPER_AND_PREFIX(CC_REMOVE_REMOTE_TIME))
DEFINE_NBL_CC_STORE_FUNC(cc_remove_remote_time, TO_UPPER_AND_PREFIX(CC_REMOVE_REMOTE_TIME))

DEFINE_NBL_CC_SHOW_FUNC(cc_high_rtt_int, TO_UPPER_AND_PREFIX(CC_HIGH_RTT_INT))
DEFINE_NBL_CC_STORE_FUNC(cc_high_rtt_int, TO_UPPER_AND_PREFIX(CC_HIGH_RTT_INT))

DEFINE_NBL_CC_SHOW_FUNC(cc_low_rtt_int, TO_UPPER_AND_PREFIX(CC_LOW_RTT_INT))
DEFINE_NBL_CC_STORE_FUNC(cc_low_rtt_int, TO_UPPER_AND_PREFIX(CC_LOW_RTT_INT))

DEFINE_NBL_CC_SHOW_FUNC(cc_rdma_time_sel, TO_UPPER_AND_PREFIX(CC_RDMA_TIME_SEL))
DEFINE_NBL_CC_STORE_FUNC(cc_rdma_time_sel, TO_UPPER_AND_PREFIX(CC_RDMA_TIME_SEL))

DEFINE_NBL_CC_SHOW_FUNC(cc_cmp_rtt_qp_mult, TO_UPPER_AND_PREFIX(CC_CMP_RTT_QP_MULT))
DEFINE_NBL_CC_STORE_FUNC(cc_cmp_rtt_qp_mult, TO_UPPER_AND_PREFIX(CC_CMP_RTT_QP_MULT))

DEFINE_NBL_CC_SHOW_FUNC(cc_low_rtt_offset, TO_UPPER_AND_PREFIX(CC_LOW_RTT_OFFSET))
DEFINE_NBL_CC_STORE_FUNC(cc_low_rtt_offset, TO_UPPER_AND_PREFIX(CC_LOW_RTT_OFFSET))

DEFINE_NBL_CC_SHOW_FUNC(cc_high_rtt_offset, TO_UPPER_AND_PREFIX(CC_HIGH_RTT_OFFSET))
DEFINE_NBL_CC_STORE_FUNC(cc_high_rtt_offset, TO_UPPER_AND_PREFIX(CC_HIGH_RTT_OFFSET))

DEFINE_NBL_CC_SHOW_FUNC(cc_rst_win_rtt_offset, TO_UPPER_AND_PREFIX(CC_RST_WIN_RTT_OFFSET))
DEFINE_NBL_CC_STORE_FUNC(cc_rst_win_rtt_offset, TO_UPPER_AND_PREFIX(CC_RST_WIN_RTT_OFFSET))

DEFINE_NBL_CC_SHOW_FUNC(cc_txp_sendreq_db_cfg, TO_UPPER_AND_PREFIX(CC_TXP_SENDREQ_DB_CFG))
DEFINE_NBL_CC_STORE_FUNC(cc_txp_sendreq_db_cfg, TO_UPPER_AND_PREFIX(CC_TXP_SENDREQ_DB_CFG))

static void init_nblcc_sysfs(struct nbl_device *nbldev)
{
	struct nbl_core_dev_info *cdev_info = (struct nbl_core_dev_info *)nbldev->rf->cdev;
	struct net_device *dev = cdev_info->netdev;
	struct nbl_sysfs_cc_params *cc_params = &nbldev->sysfs_cc_params;
	int err;

	cc_params->cc_root_kobj = kobject_create_and_add("nbl_cc", &dev->dev.kobj);
	if (!cc_params->cc_root_kobj)
		return;
	cc_params->nbldev = nbldev;

#define INIT_CC_ATTR(type) \
	do { \
		sysfs_attr_init(&cc_params->type.attr); \
		cc_params->type.attr.name = #type; \
		cc_params->type.attr.mode = 0644; \
		cc_params->type.show = nbl_cc_show_##type; \
		cc_params->type.store = nbl_cc_store_##type; \
		err = sysfs_create_file(cc_params->cc_root_kobj, &cc_params->type.attr); \
		if (err) \
			pr_err("Failed to create %s sysfs file\n", #type); \
	} while (0)

	INIT_CC_ATTR(cc_mode);
	INIT_CC_ATTR(cc_oamreq_tc_en);
	INIT_CC_ATTR(cc_oamreq_net_tc);
	INIT_CC_ATTR(cc_oamack_tc_en);
	INIT_CC_ATTR(cc_oamack_net_tc);
	INIT_CC_ATTR(cc_oamack_blk_th);
	INIT_CC_ATTR(cc_targetwin_min);
	INIT_CC_ATTR(cc_pkt_num_en);
	INIT_CC_ATTR(cc_high_rtt_fraction);
	INIT_CC_ATTR(cc_low_rtt_fraction);
	INIT_CC_ATTR(cc_inc_tarwinth);
	INIT_CC_ATTR(cc_dec_tarwinth);
	INIT_CC_ATTR(cc_targetwin);
	INIT_CC_ATTR(cc_rtt_offset);
	INIT_CC_ATTR(cc_rtt_probe_invl);
	INIT_CC_ATTR(cc_high_pri_rtt_invl);
	INIT_CC_ATTR(cc_high_pri_rtt_en);
	INIT_CC_ATTR(cc_rst_win_high);
	INIT_CC_ATTR(cc_rst_win_en);
	INIT_CC_ATTR(cc_rst_win_low);
	INIT_CC_ATTR(cc_rst_win_rtt_int);
	INIT_CC_ATTR(cc_rst_win_rtt_fraction);
	INIT_CC_ATTR(cc_dyn_rtt_offset_en);
	INIT_CC_ATTR(cc_remove_remote_time);
	INIT_CC_ATTR(cc_high_rtt_int);
	INIT_CC_ATTR(cc_low_rtt_int);
	INIT_CC_ATTR(cc_rdma_time_sel);
	INIT_CC_ATTR(cc_cmp_rtt_qp_mult);
	INIT_CC_ATTR(cc_low_rtt_offset);
	INIT_CC_ATTR(cc_high_rtt_offset);
	INIT_CC_ATTR(cc_rst_win_rtt_offset);
	INIT_CC_ATTR(cc_txp_sendreq_db_cfg);
#undef INIT_CC_ATTR
}

static void nbl_remove_nblcc_attributes(struct nbl_device *nbldev)
{
	struct nbl_sysfs_cc_params *cc_params = &nbldev->sysfs_cc_params;
	struct kobject *kobj = cc_params->cc_root_kobj;

	sysfs_remove_file(kobj, &cc_params->cc_mode.attr);
	sysfs_remove_file(kobj, &cc_params->cc_oamreq_tc_en.attr);
	sysfs_remove_file(kobj, &cc_params->cc_oamreq_net_tc.attr);
	sysfs_remove_file(kobj, &cc_params->cc_oamack_tc_en.attr);
	sysfs_remove_file(kobj, &cc_params->cc_oamack_net_tc.attr);
	sysfs_remove_file(kobj, &cc_params->cc_oamack_blk_th.attr);
	sysfs_remove_file(kobj, &cc_params->cc_targetwin_min.attr);
	sysfs_remove_file(kobj, &cc_params->cc_pkt_num_en.attr);
	sysfs_remove_file(kobj, &cc_params->cc_high_rtt_fraction.attr);
	sysfs_remove_file(kobj, &cc_params->cc_low_rtt_fraction.attr);
	sysfs_remove_file(kobj, &cc_params->cc_inc_tarwinth.attr);
	sysfs_remove_file(kobj, &cc_params->cc_dec_tarwinth.attr);
	sysfs_remove_file(kobj, &cc_params->cc_targetwin.attr);
	sysfs_remove_file(kobj, &cc_params->cc_rtt_offset.attr);
	sysfs_remove_file(kobj, &cc_params->cc_rtt_probe_invl.attr);
	sysfs_remove_file(kobj, &cc_params->cc_high_pri_rtt_invl.attr);
	sysfs_remove_file(kobj, &cc_params->cc_high_pri_rtt_en.attr);
	sysfs_remove_file(kobj, &cc_params->cc_rst_win_high.attr);
	sysfs_remove_file(kobj, &cc_params->cc_rst_win_en.attr);
	sysfs_remove_file(kobj, &cc_params->cc_rst_win_low.attr);
	sysfs_remove_file(kobj, &cc_params->cc_rst_win_rtt_int.attr);
	sysfs_remove_file(kobj, &cc_params->cc_rst_win_rtt_fraction.attr);
	sysfs_remove_file(kobj, &cc_params->cc_dyn_rtt_offset_en.attr);
	sysfs_remove_file(kobj, &cc_params->cc_remove_remote_time.attr);
	sysfs_remove_file(kobj, &cc_params->cc_high_rtt_int.attr);
	sysfs_remove_file(kobj, &cc_params->cc_low_rtt_int.attr);
	sysfs_remove_file(kobj, &cc_params->cc_rdma_time_sel.attr);
	sysfs_remove_file(kobj, &cc_params->cc_cmp_rtt_qp_mult.attr);
	sysfs_remove_file(kobj, &cc_params->cc_low_rtt_offset.attr);
	sysfs_remove_file(kobj, &cc_params->cc_high_rtt_offset.attr);
	sysfs_remove_file(kobj, &cc_params->cc_rst_win_rtt_offset.attr);
	sysfs_remove_file(kobj, &cc_params->cc_txp_sendreq_db_cfg.attr);
}

static void cleanup_nblcc_sysfs(struct nbl_device *nbldev)
{
	if (!nbldev->sysfs_cc_params.cc_root_kobj)
		return;

	nbl_remove_nblcc_attributes(nbldev);
	kobject_put(nbldev->sysfs_cc_params.cc_root_kobj);
	nbldev->sysfs_cc_params.cc_root_kobj = NULL;
}

/* qos sysfs */
extern const char *const nbl_dbg_qos_name[];
static void cleanup_qos_sysfs(struct nbl_device *nbldev)
{
	struct nbl_sysfs_qos_params *qos_params = &nbldev->sysfs_qos_params;
	int i;

	if (!qos_params || !qos_params->qos_root_kobj)
		return;

	for (i = NBL_CFG_QOS_SAVE; i < NBL_CFG_QOS_TYPE_MAX; i++)
		sysfs_remove_file(qos_params->qos_root_kobj, &qos_params->params[i].kobj_attr.attr);

	kobject_put(qos_params->qos_root_kobj);
	qos_params->qos_root_kobj = NULL;
}

static ssize_t nbl_qos_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct nbl_sysfs_qos_info *qos_info = container_of(attr,
		struct nbl_sysfs_qos_info, kobj_attr);
	int ret;
	char lbuf[NBL_PARAM_LEN];

	ret = show_qos_param(qos_info->nbldev, qos_info->offset, lbuf);

	return ret < 0 ? ret : sprintf(buf, "%s\n", lbuf);
}

static ssize_t nbl_qos_store(struct kobject *kobj, struct kobj_attribute *attr,
					const char *buf, size_t count)
{
	struct nbl_sysfs_qos_info *qos_info = container_of(attr,
		struct nbl_sysfs_qos_info, kobj_attr);
	ssize_t ret;
	char save_buf[NBL_PARAM_LEN] = {0};

	strscpy(save_buf, buf, sizeof(save_buf));
	ret = config_qos_param(qos_info->nbldev, qos_info->offset, save_buf);
	return ret ? ret : count;
}

static void nbl_fill_default_cfg(struct nbl_device *dev)
{
	struct nbl_pci_f *rf = dev->rf;

	rf->sc_dev.tc_wgt.tc0_wgt = NBL_QOS_DEFAULT_SQ_WGT;
	rf->sc_dev.tc_wgt.tc1_wgt = NBL_QOS_DEFAULT_RAQ_WGT;
	rf->sc_dev.tc_wgt.tc2_wgt = NBL_QOS_DEFAULT_SQ_WGT;
	rf->sc_dev.tc_wgt.tc3_wgt = NBL_QOS_DEFAULT_RAQ_WGT;
	rf->sc_dev.tc_wgt.tc4_wgt = NBL_QOS_DEFAULT_SQ_WGT;
	rf->sc_dev.tc_wgt.tc5_wgt = NBL_QOS_DEFAULT_RAQ_WGT;
	rf->sc_dev.tc_wgt.tc6_wgt = NBL_QOS_DEFAULT_SQ_WGT;
	rf->sc_dev.tc_wgt.tc7_wgt = NBL_QOS_DEFAULT_RAQ_WGT;

	/* set default qos config val */
	snprintf(rf->sc_dev.qos_dbgfs_params[NBL_CFG_SPWRR], NBL_PARAM_LEN, "0\n");
}

static void init_qos_sysfs(struct nbl_device *nbldev)
{
	struct device *device = &nbldev->ibdev.dev;
	struct nbl_sysfs_qos_params *qos_params = &nbldev->sysfs_qos_params;
	int i;
	int err;

	qos_params->qos_root_kobj = kobject_create_and_add("qos", &device->kobj);
	if (!qos_params->qos_root_kobj)
		return;

	for (i = NBL_CFG_QOS_SAVE; i < NBL_CFG_QOS_TYPE_MAX; i++) {
		qos_params->params[i].offset = i;
		qos_params->params[i].nbldev = nbldev;

		sysfs_attr_init(&qos_params->params[i].kobj_attr.attr);
		qos_params->params[i].kobj_attr.attr.name = nbl_dbg_qos_name[i];
		qos_params->params[i].kobj_attr.attr.mode = 0644;
		qos_params->params[i].kobj_attr.show = nbl_qos_show;
		qos_params->params[i].kobj_attr.store = nbl_qos_store;
		err = sysfs_create_file(qos_params->qos_root_kobj,
			 &qos_params->params[i].kobj_attr.attr);
		if (err)
			pr_err("Failed to create %s sysfs file\n", nbl_dbg_qos_name[i]);
	}

	nbl_fill_default_cfg(nbldev);
}

/* statistics sysfs */
static ssize_t nbl_stats_read(struct file *filp, struct kobject *kobj,
								struct bin_attribute *attr,
								char *buf, loff_t pos, size_t count)
{
	struct nbl_sysfs_stats_params *stats_params = container_of(attr,
		struct nbl_sysfs_stats_params, stats);
	struct nbl_func_file *func_file = &stats_params->nbldev->func_stat->func_file;
	ssize_t len;

	mutex_lock(&stats_params->lock);
	len = min_t(ssize_t, func_file->used_len - pos, count);
	if (len <= 0) {
		mutex_unlock(&stats_params->lock);
		return 0;
	}

	memcpy(buf, func_file->buf + pos, len);
	pos += len;
	mutex_unlock(&stats_params->lock);

	nbl_pr_dbg("READ: pos=%lld, len=%ld\n", pos, len);
	return len;
}

static ssize_t nbl_store_stats(struct file *filp, struct kobject *kobj,
								struct bin_attribute *attr,
								char *buf, loff_t pos, size_t count)
{
	struct nbl_sysfs_stats_params *stats_params = container_of(attr,
			struct nbl_sysfs_stats_params, stats);
	char save_buf[NBL_PARAM_LEN] = {0};
	ssize_t ret;

	mutex_lock(&stats_params->lock);
	strscpy(save_buf, buf, sizeof(save_buf));
	ret = config_stats_param(stats_params->nbldev, save_buf, count);
	mutex_unlock(&stats_params->lock);

	return ret ? ret : count;
}

static void cleanup_stats_sysfs(struct nbl_device *nbldev)
{
	u32 port;

	for (port = 0; port < NBL_MAX_PORT; port++) {
		struct nbl_sysfs_stats_params *stats_params = &nbldev->sysfs_stats_params[port];

		if (!stats_params || !stats_params->stats_root_kobj)
			continue;

		sysfs_remove_file(stats_params->stats_root_kobj, &stats_params->stats.attr);

		kobject_put(stats_params->stats_root_kobj);
		stats_params->stats_root_kobj = NULL;
	}
}

static void init_stats_sysfs(struct nbl_device *nbldev)
{
	struct ib_device *device = &nbldev->ibdev;
	struct ib_core_device *coredev = &device->coredev;
	u32 port = 0;
	int err = 0;
	struct kobject *p, *t;

	list_for_each_entry_safe(p, t, &coredev->port_list, entry) {
		struct nbl_sysfs_stats_params *stats_params = &nbldev->sysfs_stats_params[port++];

		stats_params->stats_root_kobj = kobject_create_and_add("counters", p);
		stats_params->nbldev = nbldev;

		sysfs_attr_init(&stats_params->stats.attr);
		stats_params->stats.attr.name = "stat";
		stats_params->stats.attr.mode = 0644;
		stats_params->stats.size = 0;
		stats_params->stats.read = nbl_stats_read;
		stats_params->stats.write = nbl_store_stats;

		err = sysfs_create_bin_file(stats_params->stats_root_kobj,
			&stats_params->stats);
		if (err)
			pr_err("Failed to create stats sysfs file\n");

		mutex_init(&stats_params->lock);

		if (port >= NBL_MAX_PORT)
			break;
	}
}

void nbl_sysfs_init(struct nbl_device *nbldev)
{
	init_tc_sysfs(nbldev);
	init_ecn_sysfs(nbldev);
	init_nblcc_sysfs(nbldev);
	init_qos_sysfs(nbldev);
	init_stats_sysfs(nbldev);
}

void nbl_sysfs_exit(struct nbl_device *nbldev)
{
	if (!nbldev)
		return;

	cleanup_stats_sysfs(nbldev);
	cleanup_qos_sysfs(nbldev);
	cleanup_nblcc_sysfs(nbldev);
	cleanup_ecn_sysfs(nbldev);
	cleanup_tc_sysfs(nbldev);
}
