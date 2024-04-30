// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2024 Huawei Technologies Co., Ltd

#include <linux/types.h>

#include "hinic3_hw.h"
#include "rdma_context_format.h"
#include "roce.h"
#include "roce_dfx.h"
#include "roce_cmd.h"
#include "roce_qp.h"

#include "roce_sysfs.h"

#define ROCE_DEFAULT_IP_EABLE_EN 1
#define ROCE_DEFAULT_IP_EABLE_DIS 0
#define ROCE_DEFAULT_MIN_CNP_PERIOD 16
#define ROCE_DEFAULT_ALPHA_DEC_PERIOD 160
#define ROCE_DEFAULT_RATE_DEC_PERIOD 32
#define ROCE_DEFAULT_RATE_INC_PERIOD 480
#define ROCE_DEFAULT_ALPHA_THRESHOLD 4 // 32, uint 8
#define ROCE_DEFAULT_CNP_CNT_THRESHOLD 6
#define ROCE_DEFAULT_PORT_MODE_25G 0
#define ROCE_DEFAULT_FACTOR_GITA 7
#define ROCE_DEFAULT_INITIAL_ALPHA 1023
#define ROCE_DEFAULT_RATE_INC_AI 2
#define ROCE_DEFAULT_RATE_INC_HAI 8
#define ROCE_DEFAULT_RATE_FIRST_SET 1024
#define ROCE_DEFAULT_RATE_TARGET_CLAMP 1
#define ROCE_DEFAULT_QUICK_AJ_ENABLE 0
#define ROCE_DEFAULT_CNP_PRIO_ENABLE 0
#define ROCE_DEFAULT_CNP_PRIO 0
#define ROCE_DEFAULT_TOKEN_PERIOD 16
#define ROCE_DEFAULT_MIN_RATE 1
#define ROCE_DEFAULT_WND_RESET_RATIO 0
#define ROCE_DEFAULT_WND_RESET_TIMEOUT 0
#define ROCE_PORT_MODE_MASK 0xfffffffe
#define ROCE_QUICK_AJ_EN_MASK 0xfffffffe
#define ROCE_CNP_PRIO_EN_MASK 0xfffffffe
#define ROCE_RT_CLAMP_MASK 0xfffffffe
#define ROCE_PRIO_EN_MASK 0xfffffffe
#define ROCE_MIN_RATE_INC_HAI 1
#define ROCE_MAX_RATE_INC_HAI 255
#define ROCE_MIN_RATE_INC_AI 1
#define ROCE_MAX_RATE_INC_AI 63
#define ROCE_MIN_INITIAL_ALPHA 127
#define ROCE_MAX_INITIAL_ALPHA 1023
#define ROCE_MIN_RATE_INC_PERIOD 1
#define ROCE_MAX_RATE_INC_PERIOD 1024
#define ROCE_MIN_ALPHA_DEC_PERIOD 1
#define ROCE_MAX_ALPHA_DEC_PERIOD 1024
#define ROCE_MIN_TOKEN_PERIOD 4
#define ROCE_MAX_TOKEN_PERIOD 255
#define ROCE_MIN_FLOW_MIN_RATE 1
#define ROCE_MAX_FLOW_MIN_RATE 64
#define ROCE_MIN_WND_RESET_RATIO 0
#define ROCE_MAX_WND_RESET_RATIO 0xf
#define ROCE_MIN_WND_RESET_TIMEOUT 0
#define ROCE_MAX_WND_RESET_TIMEOUT 0xf
#define ROCE_MIN_ALPHA_THRESHOLD 8
#define ROCE_MAX_ALPHA_THRESHOLD 248
#define ROCE_MIN_CNP_CNT_THRESHOLD 1
#define ROCE_MAX_CNP_CNT_THRESHOLD 15
#define ROCE_MIN_RATE_DEC_PERIOD 1
#define ROCE_MAX_RATE_DEC_PERIOD 255
#define ROCE_MIN_MIN_CNP_PERIOD 1
#define ROCE_MAX_MIN_CNP_PERIOD 255
#define ROCE_MIN_FACTOR_GITA 1
#define ROCE_MAX_FACTOR_GITA 15
#define ROCE_MIN_RATE_FIRST_SET 128
#define ROCE_MAX_RATE_FIRST_SET 8191

#define MAX_STRING_FORMAT_LEN 64

/* ECN VER */
#define ECN_VER_DCQCN 0
#define ECN_VER_PATHQCN 1

enum {
	ROCE_DCQCN_NP = 0,
	ROCE_DCQCN_RP = 1
};

#define to_roce3_ecn_ctx(_kobj) container_of(_kobj, struct roce3_ecn_ctx, ecn_root)
#define to_roce3_ecn_np_ctx(_kobj) container_of(_kobj, struct roce3_ecn_np_ctx, ecn_np_root)
#define to_roce3_ecn_rp_ctx(_kobj) container_of(_kobj, struct roce3_ecn_rp_ctx, ecn_rp_root)

#define INIT_ROCE_KOBJ_ATTR(_name, _mode, _show, _store) \
	{ \
		.attr	= { .name = __stringify(_name), .mode = _mode }, \
	.show	= (_show), \
	.store	= (_store), \
	}

#define ROCE_ATTR_RW(_name, _show, _store) \
	static struct kobj_attribute roce_attr_##_name = \
		INIT_ROCE_KOBJ_ATTR(_name, 0640, _show, _store)

#define ROCE_ATTR_PTR(_name) (&roce_attr_##_name.attr)

static int roce3_update_cfg_ccf_param(struct roce3_device *rdev,
	const struct roce3_ecn_ctx *ecn_ctx)
{
	const struct roce3_prio_enable_ctx *prio_enable_ctx = NULL;
	const struct roce3_ip_prio_enable_ctx *ip_prio_enable_ctx = NULL;
	struct roce_ccf_param ccf_param;
	int ret, i;

	memset(&ccf_param, 0, sizeof(ccf_param));

	for (i = 0; i < PRI_ARRAY_LEN; i++) {
		prio_enable_ctx = &ecn_ctx->np_ctx.enable_ctx.prio_enable[i];
		ccf_param.dw0.bs.np_enable |= (prio_enable_ctx->prio_en << prio_enable_ctx->prio);
		prio_enable_ctx = &ecn_ctx->rp_ctx.enable_ctx.prio_enable[i];
		ccf_param.dw0.bs.rp_enable |= (prio_enable_ctx->prio_en << prio_enable_ctx->prio);
		ip_prio_enable_ctx = &ecn_ctx->ip_enable_ctx.ip_prio_enable[i];
		ccf_param.dw0.bs.ip_enable |=
			(ip_prio_enable_ctx->prio_en << ip_prio_enable_ctx->prio);
	}

	ccf_param.dw0.bs.cnp_prio_enable = ecn_ctx->np_ctx.cnp_prio_enable;
	ccf_param.dw0.bs.port_mode = ecn_ctx->np_ctx.port_mode;
	ccf_param.dw1.bs.cnp_prio = ecn_ctx->np_ctx.cnp_prio;
	ccf_param.dw1.bs.cnp_cos = roce3_get_db_cos_from_vlan_pri(rdev, ccf_param.dw1.bs.cnp_prio);
	ccf_param.dw1.bs.ccf_appid = ecn_ctx->cc_algo;

	ret = roce3_set_cfg_ccf_param(rdev->hwdev, rdev->glb_func_id, (u32 *)&ccf_param);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] : Failed to set ccf param, func_id(%d) ret(%d)\n",
			rdev->glb_func_id, ret);
	}

	return ret;
}

static int roce3_update_dcqcn_param(struct roce3_device *rdev, const struct roce3_ecn_ctx *ecn_ctx)
{
	struct roce_dcqcn_param dcqcn_param;
	int ret;

	memset(&dcqcn_param, 0, sizeof(dcqcn_param));

	dcqcn_param.dw0.bs.token_period = ecn_ctx->rp_ctx.token_period;
	dcqcn_param.dw0.bs.flow_min_rate = ecn_ctx->rp_ctx.min_rate;
	dcqcn_param.dw1.bs.rate_inc_period = ecn_ctx->rp_ctx.rate_inc_period;
	dcqcn_param.dw1.bs.alpha_threshold = ecn_ctx->rp_ctx.alpha_threshold;
	dcqcn_param.dw1.bs.cnp_cnt_threshold = ecn_ctx->rp_ctx.cnp_cnt_threshold;
	dcqcn_param.dw1.bs.alpha_dec_period = ecn_ctx->rp_ctx.alpha_dec_period;
	dcqcn_param.dw2.bs.rate_inc_ai = ecn_ctx->rp_ctx.rate_inc_ai;
	dcqcn_param.dw2.bs.rate_inc_hai = ecn_ctx->rp_ctx.rate_inc_hai;
	dcqcn_param.dw2.bs.rate_dec_period = ecn_ctx->rp_ctx.rate_dec_period;
	dcqcn_param.dw2.bs.min_cnp_period = ecn_ctx->np_ctx.min_cnp_period;
	dcqcn_param.dw3.bs.factor_gita = ecn_ctx->rp_ctx.factor_gita;
	dcqcn_param.dw3.bs.rt_clamp = ecn_ctx->rp_ctx.rate_target_clamp;
	dcqcn_param.dw3.bs.initial_alpha = ecn_ctx->rp_ctx.initial_alpha;
	// adjust_en
	dcqcn_param.dw3.bs.rate_first_set = ecn_ctx->rp_ctx.rate_first_set;

	ret = roce3_set_cfg_dcqcn_param(rdev->hwdev, rdev->glb_func_id,
		(u32 *)(void *)&dcqcn_param);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] : Failed to set dcqcn param, func_id(%d), ret(%d)\n",
			rdev->glb_func_id, ret);
	}

	return ret;
}

static int roce3_update_ipqcn_param(struct roce3_device *rdev, const struct roce3_ecn_ctx *ecn_ctx)
{
	struct roce_ipqcn_param ipqcn_param;
	int ret;

	memset(&ipqcn_param, 0, sizeof(ipqcn_param));

	ipqcn_param.dw0.bs.token_period = ecn_ctx->rp_ctx.token_period;
	ipqcn_param.dw0.bs.flow_min_rate = ecn_ctx->rp_ctx.min_rate;
	ipqcn_param.dw1.bs.rate_inc_period = ecn_ctx->rp_ctx.rate_inc_period;
	ipqcn_param.dw1.bs.alpha_threshold = ecn_ctx->rp_ctx.alpha_threshold;
	ipqcn_param.dw1.bs.cnp_cnt_threshold = ecn_ctx->rp_ctx.cnp_cnt_threshold;
	ipqcn_param.dw1.bs.alpha_dec_period = ecn_ctx->rp_ctx.alpha_dec_period;
	ipqcn_param.dw2.bs.rate_inc_ai = ecn_ctx->rp_ctx.rate_inc_ai;
	ipqcn_param.dw2.bs.rate_inc_hai = ecn_ctx->rp_ctx.rate_inc_hai;
	ipqcn_param.dw2.bs.rate_dec_period = ecn_ctx->rp_ctx.rate_dec_period;
	ipqcn_param.dw2.bs.min_cnp_period = ecn_ctx->np_ctx.min_cnp_period;
	ipqcn_param.dw3.bs.factor_gita = ecn_ctx->rp_ctx.factor_gita;
	ipqcn_param.dw3.bs.rt_clamp = ecn_ctx->rp_ctx.rate_target_clamp;
	ipqcn_param.dw3.bs.initial_alpha = ecn_ctx->rp_ctx.initial_alpha;
	ipqcn_param.dw3.bs.rate_first_set = ecn_ctx->rp_ctx.rate_first_set;

	ret = roce3_set_cfg_ipqcn_param(rdev->hwdev, rdev->glb_func_id,
		(u32 *)(void *)&ipqcn_param);
	if (ret != 0) {
		dev_err(rdev->hwdev_hdl,
			"[ROCE, ERR] : Failed to set ipqcn param, func_id(%d) ret(%d)\n",
			rdev->glb_func_id, ret);
	}

	return ret;
}

typedef int (*roce3_update_param_t)(struct roce3_device *rdev, const struct roce3_ecn_ctx *ecn_ctx);

static roce3_update_param_t roce3_update_param_funcs[] = {
	roce3_update_cfg_ccf_param,
	roce3_update_dcqcn_param,
	roce3_update_ipqcn_param,
};

int roce3_update_ecn_param(const struct roce3_ecn_ctx *ecn_ctx)
{
	unsigned int i;
	int ret = 0;
	struct roce3_device *rdev = container_of(ecn_ctx, struct roce3_device, ecn_ctx);

	for (i = 0; i < (sizeof(roce3_update_param_funcs) / sizeof(roce3_update_param_t)); i++) {
		ret = roce3_update_param_funcs[i](rdev, ecn_ctx);
		if (ret != 0)
			ret = -EINVAL;
	}

	return ret;
}

static ssize_t roce3_show_cc_algo(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct roce3_ecn_ctx *ecn_ctx = to_roce3_ecn_ctx(kobj);

	if ((attr == NULL) || (buf == NULL)) {
		pr_err("[ROCE] %s: attr or buf is null\n", __func__);
		return -EINVAL;
	}

	switch ((int)ecn_ctx->cc_algo) {
	case ROCE_CC_DISABLE:
		return sprintf(buf, "%s\n", "disable");
	case ROCE_CC_DCQCN_ALGO:
		return sprintf(buf, "%s\n", "dcqcn");
	case ROCE_CC_LDCP_ALGO:
		return sprintf(buf, "%s\n", "ldcp");
	case ROCE_CC_IPQCN_ALGO:
		return sprintf(buf, "%s\n", "hc3_1/ipqcn");
	default:
		return sprintf(buf, "%s\n", "error_type");
	}
}

static ssize_t roce3_store_cc_algo(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	struct roce3_ecn_ctx *ecn_ctx = to_roce3_ecn_ctx(kobj);
	u32 old_cc_algo = 0;
	int cc_algo = 0;
	ssize_t ret;

	if ((attr == NULL) || (buf == NULL)) {
		pr_err("[ROCE] %s: attr or buf is null\n", __func__);
		return -EINVAL;
	}

	/* dcqcn -> 0x0, ldcp -> 0x2, hc3_1 -> 0x80 */
	if (strncmp(buf, "disable", strlen("disable")) == 0) {
		cc_algo = ROCE_CC_DISABLE;
	} else if (strncmp(buf, "dcqcn", strlen("dcqcn")) == 0) {
		cc_algo = ROCE_CC_DCQCN_ALGO;
	} else if ((strncmp(buf, "ipqcn", strlen("ipqcn")) == 0) ||
		(strncmp(buf, "hc3_1", strlen("hc3_1")) == 0)) {
		cc_algo = ROCE_CC_IPQCN_ALGO;
	} else if (strncmp(buf, "ldcp", strlen("ldcp")) == 0) {
		cc_algo = ROCE_CC_LDCP_ALGO;
	} else {
		pr_err("[ROCE] %s: Invalid cc_algo(%d),buf(%s)\n", __func__, cc_algo, buf);
		return -EIO;
	}

	if (ecn_ctx->cc_algo != (u32)cc_algo) {
		mutex_lock(&ecn_ctx->ecn_mutex);
		old_cc_algo = ecn_ctx->cc_algo;
		ecn_ctx->cc_algo = (u32)cc_algo;
		ret = (ssize_t)roce3_update_ecn_param(ecn_ctx);
		if (ret != 0) {
			pr_err("[ROCE] %s: Failed to update cc_algo param, ret(%d)",
				__func__, (int)ret);
			ecn_ctx->cc_algo = old_cc_algo;
			mutex_unlock(&ecn_ctx->ecn_mutex);
			return -EIO;
		}
		mutex_unlock(&ecn_ctx->ecn_mutex);
	}

	return (ssize_t)count;
}

static ssize_t roce3_show_ecn_prio_enable(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	struct roce3_prio_enable_ctx *prio_enable_ctx =
		container_of(attr, struct roce3_prio_enable_ctx, enable);

	return sprintf(buf, "%d\n", (int)prio_enable_ctx->prio_en);
}

static ssize_t roce3_store_ecn_prio_enable(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	ssize_t ret = 0;
	int prio_en = 0;
	u32 old_prio_en = 0;
	struct roce3_ecn_rp_ctx *rp_ctx = NULL;
	struct roce3_ecn_np_ctx *np_ctx = NULL;
	struct roce3_ecn_ctx *ecn_ctx = NULL;
	struct roce3_prio_enable_ctx *prio_enable_ctx =
		container_of(attr, struct roce3_prio_enable_ctx, enable);
	struct roce3_ecn_enable_ctx *ecn_enable_ctx =
		(struct roce3_ecn_enable_ctx *)prio_enable_ctx->ecn_enable_ctx;

	if (ecn_enable_ctx->np_rp == ROCE_DCQCN_NP) {
		np_ctx = container_of(ecn_enable_ctx, struct roce3_ecn_np_ctx, enable_ctx);
		ecn_ctx = container_of(np_ctx, struct roce3_ecn_ctx, np_ctx);
	} else {
		rp_ctx = container_of(ecn_enable_ctx, struct roce3_ecn_rp_ctx, enable_ctx);
		ecn_ctx = container_of(rp_ctx, struct roce3_ecn_ctx, rp_ctx);
	}

	ret = kstrtoint(buf, 10, &prio_en);
	if (ret != 0)
		return -EIO;

	if (((u32)prio_en & ROCE_PRIO_EN_MASK) != 0)
		return -EIO;

	if (prio_enable_ctx->prio_en != (u32)prio_en) {
		mutex_lock(&ecn_ctx->ecn_mutex);
		old_prio_en = prio_enable_ctx->prio_en;
		prio_enable_ctx->prio_en = (u32)prio_en;
		ret = (ssize_t)roce3_update_ecn_param(ecn_ctx);
		if (ret != 0) {
			prio_enable_ctx->prio_en = old_prio_en;
			mutex_unlock(&ecn_ctx->ecn_mutex);
			return -EIO;
		}
		mutex_unlock(&ecn_ctx->ecn_mutex);
	}

	return (ssize_t)count;
}

static ssize_t roce3_show_ecn_ip_prio_enable(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	struct roce3_ip_prio_enable_ctx *ip_prio_enable_ctx =
		container_of(attr, struct roce3_ip_prio_enable_ctx, ip_enable);

	return sprintf(buf, "%d\n", (int)ip_prio_enable_ctx->prio_en);
}

static ssize_t roce3_store_ecn_ip_prio_enable(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	ssize_t ret = 0;
	int prio_en = 0;
	u32 old_prio_en = 0;
	struct roce3_ip_prio_enable_ctx *ip_prio_enable_ctx =
		container_of(attr, struct roce3_ip_prio_enable_ctx, ip_enable);
	struct roce3_ecn_ip_enable_ctx *ip_enable_ctx =
		(struct roce3_ecn_ip_enable_ctx *)ip_prio_enable_ctx->ecn_ip_enable_ctx;
	struct roce3_ecn_ctx *ecn_ctx = container_of(ip_enable_ctx,
		struct roce3_ecn_ctx, ip_enable_ctx);

	ret = kstrtoint(buf, 10, &prio_en);
	if (ret != 0)
		return -EIO;

	if (((u32)prio_en & ROCE_PRIO_EN_MASK) != 0)
		return -EIO;

	if (ip_prio_enable_ctx->prio_en != (u32)prio_en) {
		mutex_lock(&ecn_ctx->ecn_mutex);
		old_prio_en = ip_prio_enable_ctx->prio_en;
		ip_prio_enable_ctx->prio_en = (u32)prio_en;
		ret = (ssize_t)roce3_update_ecn_param(ecn_ctx);
		if (ret != 0) {
			ip_prio_enable_ctx->prio_en = old_prio_en;
			mutex_unlock(&ecn_ctx->ecn_mutex);
			return -EIO;
		}
		mutex_unlock(&ecn_ctx->ecn_mutex);
	}

	return (ssize_t)count;
}

static ssize_t roce3_show_rate_inc_hai(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct roce3_ecn_rp_ctx *ecn_rp_ctx = to_roce3_ecn_rp_ctx(kobj);

	return sprintf(buf, "%d\n", (int)ecn_rp_ctx->rate_inc_hai);
}

static ssize_t roce3_store_rate_inc_hai(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	ssize_t ret = 0;
	int rate_inc_hai = 0;
	u32 old_rate_inc_hai = 0;
	struct roce3_ecn_ctx *ecn_ctx = to_roce3_ecn_ctx(kobj->parent);
	struct roce3_ecn_rp_ctx *ecn_rp_ctx = to_roce3_ecn_rp_ctx(kobj);

	ret = kstrtoint(buf, 10, &rate_inc_hai);
	if (ret != 0)
		return -EIO;

	if ((rate_inc_hai < ROCE_MIN_RATE_INC_HAI) || (rate_inc_hai > ROCE_MAX_RATE_INC_HAI))
		return -EIO;

	if (ecn_rp_ctx->rate_inc_hai != (u32)rate_inc_hai) {
		mutex_lock(&ecn_ctx->ecn_mutex);
		old_rate_inc_hai = ecn_rp_ctx->rate_inc_hai;
		ecn_rp_ctx->rate_inc_hai = (u32)rate_inc_hai;
		ret = (ssize_t)roce3_update_ecn_param(ecn_ctx);
		if (ret != 0) {
			ecn_rp_ctx->rate_inc_hai = old_rate_inc_hai;
			mutex_unlock(&ecn_ctx->ecn_mutex);
			return -EIO;
		}
		mutex_unlock(&ecn_ctx->ecn_mutex);
	}

	return (ssize_t)count;
}

static ssize_t roce3_show_rate_inc_ai(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct roce3_ecn_rp_ctx *ecn_rp_ctx = to_roce3_ecn_rp_ctx(kobj);

	return sprintf(buf, "%d\n", (int)ecn_rp_ctx->rate_inc_ai);
}

static ssize_t roce3_store_rate_inc_ai(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	ssize_t ret = 0;
	int rate_inc_ai = 0;
	u32 old_rate_inc_ai = 0;
	struct roce3_ecn_ctx *ecn_ctx = to_roce3_ecn_ctx(kobj->parent);
	struct roce3_ecn_rp_ctx *ecn_rp_ctx = to_roce3_ecn_rp_ctx(kobj);

	ret = kstrtoint(buf, 10, &rate_inc_ai);
	if (ret != 0)
		return -EIO;

	if ((rate_inc_ai < ROCE_MIN_RATE_INC_AI) || (rate_inc_ai > ROCE_MAX_RATE_INC_AI))
		return -EIO;

	if (ecn_rp_ctx->rate_inc_ai != (u32)rate_inc_ai) {
		mutex_lock(&ecn_ctx->ecn_mutex);
		old_rate_inc_ai = ecn_rp_ctx->rate_inc_ai;
		ecn_rp_ctx->rate_inc_ai = (u32)rate_inc_ai;
		ret = (ssize_t)roce3_update_ecn_param(ecn_ctx);
		if (ret != 0) {
			ecn_rp_ctx->rate_inc_ai = old_rate_inc_ai;
			mutex_unlock(&ecn_ctx->ecn_mutex);
			return -EIO;
		}
		mutex_unlock(&ecn_ctx->ecn_mutex);
	}

	return (ssize_t)count;
}

static ssize_t roce3_show_initial_alpha(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	struct roce3_ecn_rp_ctx *ecn_rp_ctx = to_roce3_ecn_rp_ctx(kobj);

	return sprintf(buf, "%d\n", (int)ecn_rp_ctx->initial_alpha);
}

static ssize_t roce3_store_initial_alpha(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	ssize_t ret = 0;
	int initial_alpha = 0;
	u32 old_initial_alpha = 0;
	struct roce3_ecn_ctx *ecn_ctx = to_roce3_ecn_ctx(kobj->parent);
	struct roce3_ecn_rp_ctx *ecn_rp_ctx = to_roce3_ecn_rp_ctx(kobj);

	ret = kstrtoint(buf, 10, &initial_alpha);
	if (ret != 0)
		return -EIO;

	if ((initial_alpha < ROCE_MIN_INITIAL_ALPHA) || (initial_alpha > ROCE_MAX_INITIAL_ALPHA))
		return -EIO;

	if (ecn_rp_ctx->initial_alpha != (u32)initial_alpha) {
		mutex_lock(&ecn_ctx->ecn_mutex);
		old_initial_alpha = ecn_rp_ctx->initial_alpha;
		ecn_rp_ctx->initial_alpha = (u32)initial_alpha;
		ret = (ssize_t)roce3_update_ecn_param(ecn_ctx);
		if (ret != 0) {
			ecn_rp_ctx->initial_alpha = old_initial_alpha;
			mutex_unlock(&ecn_ctx->ecn_mutex);
			return -EIO;
		}
		mutex_unlock(&ecn_ctx->ecn_mutex);
	}

	return (ssize_t)count;
}

static ssize_t roce3_show_factor_gita(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct roce3_ecn_rp_ctx *ecn_rp_ctx = to_roce3_ecn_rp_ctx(kobj);

	return sprintf(buf, "%d\n", (int)ecn_rp_ctx->factor_gita);
}

static ssize_t roce3_store_factor_gita(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	ssize_t ret = 0;
	int factor_gita = 0;
	u32 old_factor_gita = 0;
	struct roce3_ecn_ctx *ecn_ctx = to_roce3_ecn_ctx(kobj->parent);
	struct roce3_ecn_rp_ctx *ecn_rp_ctx = to_roce3_ecn_rp_ctx(kobj);

	ret = kstrtoint(buf, 10, &factor_gita);
	if (ret != 0)
		return -EIO;

	if ((factor_gita < ROCE_MIN_FACTOR_GITA) || (factor_gita > ROCE_MAX_FACTOR_GITA))
		return -EIO;

	if (ecn_rp_ctx->factor_gita != (u32)factor_gita) {
		mutex_lock(&ecn_ctx->ecn_mutex);
		old_factor_gita = ecn_rp_ctx->factor_gita;
		ecn_rp_ctx->factor_gita = (u32)factor_gita;
		ret = (ssize_t)roce3_update_ecn_param(ecn_ctx);
		if (ret != 0) {
			ecn_rp_ctx->factor_gita = old_factor_gita;
			mutex_unlock(&ecn_ctx->ecn_mutex);
			return -EIO;
		}
		mutex_unlock(&ecn_ctx->ecn_mutex);
	}

	return (ssize_t)count;
}

static ssize_t roce3_show_rate_inc_period(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	struct roce3_ecn_rp_ctx *ecn_rp_ctx = to_roce3_ecn_rp_ctx(kobj);

	return sprintf(buf, "%d\n", (int)ecn_rp_ctx->rate_inc_period);
}

static ssize_t roce3_store_rate_inc_period(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	ssize_t ret = 0;
	int rate_inc_period = 0;
	u32 old_rate_inc_period = 0;
	struct roce3_ecn_ctx *ecn_ctx = to_roce3_ecn_ctx(kobj->parent);
	struct roce3_ecn_rp_ctx *ecn_rp_ctx = to_roce3_ecn_rp_ctx(kobj);

	ret = kstrtoint(buf, 10, &rate_inc_period);
	if (ret != 0)
		return -EIO;

	if ((rate_inc_period < ROCE_MIN_RATE_INC_PERIOD) ||
		(rate_inc_period > ROCE_MAX_RATE_INC_PERIOD))
		return -EIO;

	if (ecn_rp_ctx->rate_inc_period != (u32)rate_inc_period) {
		mutex_lock(&ecn_ctx->ecn_mutex);
		old_rate_inc_period = ecn_rp_ctx->rate_inc_period;
		ecn_rp_ctx->rate_inc_period = (u32)rate_inc_period;
		ret = (ssize_t)roce3_update_ecn_param(ecn_ctx);
		if (ret != 0) {
			ecn_rp_ctx->rate_inc_period = old_rate_inc_period;
			mutex_unlock(&ecn_ctx->ecn_mutex);
			return -EIO;
		}
		mutex_unlock(&ecn_ctx->ecn_mutex);
	}

	return (ssize_t)count;
}

static ssize_t roce3_show_cnp_cnt_threshold(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	struct roce3_ecn_rp_ctx *ecn_rp_ctx = to_roce3_ecn_rp_ctx(kobj);

	return sprintf(buf, "%d\n", (int)ecn_rp_ctx->cnp_cnt_threshold);
}

static ssize_t roce3_store_cnp_cnt_threshold(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	ssize_t ret = 0;
	int cnp_cnt_threshold = 0;
	u32 old_cnp_cnt_threshold = 0;
	struct roce3_ecn_ctx *ecn_ctx = to_roce3_ecn_ctx(kobj->parent);
	struct roce3_ecn_rp_ctx *ecn_rp_ctx = to_roce3_ecn_rp_ctx(kobj);

	ret = kstrtoint(buf, 10, &cnp_cnt_threshold);
	if (ret != 0)
		return -EIO;

	if ((cnp_cnt_threshold < ROCE_MIN_CNP_CNT_THRESHOLD) ||
		(cnp_cnt_threshold > ROCE_MAX_CNP_CNT_THRESHOLD))
		return -EIO;

	if (ecn_rp_ctx->cnp_cnt_threshold != (u32)cnp_cnt_threshold) {
		mutex_lock(&ecn_ctx->ecn_mutex);
		old_cnp_cnt_threshold = ecn_rp_ctx->cnp_cnt_threshold;
		ecn_rp_ctx->cnp_cnt_threshold = (u32)cnp_cnt_threshold;
		ret = (ssize_t)roce3_update_ecn_param(ecn_ctx);
		if (ret != 0) {
			ecn_rp_ctx->cnp_cnt_threshold = old_cnp_cnt_threshold;
			mutex_unlock(&ecn_ctx->ecn_mutex);
			return -EIO;
		}
		mutex_unlock(&ecn_ctx->ecn_mutex);
	}

	return (ssize_t)count;
}

static ssize_t roce3_show_alpha_threshold(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	struct roce3_ecn_rp_ctx *ecn_rp_ctx = to_roce3_ecn_rp_ctx(kobj);

	return sprintf(buf, "%d\n",
		(int)(ecn_rp_ctx->alpha_threshold << ALPHA_THREADHOLD_UNIT_SHIFT));
}

static ssize_t roce3_store_alpha_threshold(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	ssize_t ret = 0;
	u32 alpha_threshold = 0;
	u32 old_alpha_threshold = 0;
	struct roce3_ecn_ctx *ecn_ctx = to_roce3_ecn_ctx(kobj->parent);
	struct roce3_ecn_rp_ctx *ecn_rp_ctx = to_roce3_ecn_rp_ctx(kobj);

	ret = kstrtoint(buf, 10, &alpha_threshold);
	if (ret != 0)
		return -EIO;

	if ((alpha_threshold < ROCE_MIN_ALPHA_THRESHOLD) ||
		(alpha_threshold > ROCE_MAX_ALPHA_THRESHOLD))
		return -EIO;
	alpha_threshold = ((u32)alpha_threshold >> ALPHA_THREADHOLD_UNIT_SHIFT);

	if (ecn_rp_ctx->alpha_threshold != (u32)alpha_threshold) {
		mutex_lock(&ecn_ctx->ecn_mutex);
		old_alpha_threshold = ecn_rp_ctx->alpha_threshold;
		ecn_rp_ctx->alpha_threshold = (u32)alpha_threshold;
		ret = (ssize_t)roce3_update_ecn_param(ecn_ctx);
		if (ret != 0) {
			ecn_rp_ctx->alpha_threshold = old_alpha_threshold;
			mutex_unlock(&ecn_ctx->ecn_mutex);
			return -EIO;
		}
		mutex_unlock(&ecn_ctx->ecn_mutex);
	}

	return (ssize_t)count;
}

static ssize_t roce3_show_rate_dec_period(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	struct roce3_ecn_rp_ctx *ecn_rp_ctx = to_roce3_ecn_rp_ctx(kobj);

	return sprintf(buf, "%d\n", (int)ecn_rp_ctx->rate_dec_period);
}

static ssize_t roce3_store_rate_dec_period(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	ssize_t ret = 0;
	int rate_dec_period = 0;
	u32 old_rate_dec_period = 0;
	struct roce3_ecn_ctx *ecn_ctx = to_roce3_ecn_ctx(kobj->parent);
	struct roce3_ecn_rp_ctx *ecn_rp_ctx = to_roce3_ecn_rp_ctx(kobj);

	ret = kstrtoint(buf, 10, &rate_dec_period);
	if (ret != 0)
		return -EIO;

	if ((rate_dec_period < ROCE_MIN_RATE_DEC_PERIOD) ||
		(rate_dec_period > ROCE_MAX_RATE_DEC_PERIOD))
		return -EIO;

	if (ecn_rp_ctx->rate_dec_period != (u32)rate_dec_period) {
		mutex_lock(&ecn_ctx->ecn_mutex);
		old_rate_dec_period = ecn_rp_ctx->rate_dec_period;
		ecn_rp_ctx->rate_dec_period = (u32)rate_dec_period;
		ret = (ssize_t)roce3_update_ecn_param(ecn_ctx);
		if (ret != 0) {
			ecn_rp_ctx->rate_dec_period = old_rate_dec_period;
			mutex_unlock(&ecn_ctx->ecn_mutex);
			return -EIO;
		}
		mutex_unlock(&ecn_ctx->ecn_mutex);
	}

	return (ssize_t)count;
}

static ssize_t roce3_show_token_period(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct roce3_ecn_rp_ctx *ecn_rp_ctx = to_roce3_ecn_rp_ctx(kobj);

	return sprintf(buf, "%d\n", (int)ecn_rp_ctx->token_period);
}

static ssize_t roce3_store_token_period(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	ssize_t ret = 0;
	int token_period = 0;
	u32 old_token_period = 0;
	struct roce3_ecn_ctx *ecn_ctx = to_roce3_ecn_ctx(kobj->parent);
	struct roce3_ecn_rp_ctx *ecn_rp_ctx = to_roce3_ecn_rp_ctx(kobj);

	ret = kstrtoint(buf, 10, &token_period);
	if (ret != 0)
		return -EIO;

	if ((token_period < ROCE_MIN_TOKEN_PERIOD) ||
		(token_period > ROCE_MAX_TOKEN_PERIOD))
		return -EIO;

	if (ecn_rp_ctx->token_period != (u32)token_period) {
		mutex_lock(&ecn_ctx->ecn_mutex);
		old_token_period = ecn_rp_ctx->token_period;
		ecn_rp_ctx->token_period = (u32)token_period;
		ret = (ssize_t)roce3_update_ecn_param(ecn_ctx);
		if (ret != 0) {
			ecn_rp_ctx->token_period = old_token_period;
			mutex_unlock(&ecn_ctx->ecn_mutex);
			return -EIO;
		}
		mutex_unlock(&ecn_ctx->ecn_mutex);
	}

	return (ssize_t)count;
}

static ssize_t roce3_show_min_rate(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct roce3_ecn_rp_ctx *ecn_rp_ctx = to_roce3_ecn_rp_ctx(kobj);

	return sprintf(buf, "%d\n", (int)ecn_rp_ctx->min_rate);
}

static ssize_t roce3_store_min_rate(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	ssize_t ret = 0;
	int min_rate = 0;
	u32 old_min_rate = 0;
	struct roce3_ecn_ctx *ecn_ctx = to_roce3_ecn_ctx(kobj->parent);
	struct roce3_ecn_rp_ctx *ecn_rp_ctx = to_roce3_ecn_rp_ctx(kobj);

	ret = kstrtoint(buf, 10, &min_rate);
	if (ret != 0)
		return -EIO;

	if ((min_rate < ROCE_MIN_FLOW_MIN_RATE) || (min_rate > ROCE_MAX_FLOW_MIN_RATE))
		return -EIO;

	if (ecn_rp_ctx->token_period != (u32)min_rate) {
		mutex_lock(&ecn_ctx->ecn_mutex);
		old_min_rate = ecn_rp_ctx->min_rate;
		ecn_rp_ctx->min_rate = (u32)min_rate;
		ret = (ssize_t)roce3_update_ecn_param(ecn_ctx);
		if (ret != 0) {
			ecn_rp_ctx->min_rate = old_min_rate;
			mutex_unlock(&ecn_ctx->ecn_mutex);
			return -EIO;
		}
		mutex_unlock(&ecn_ctx->ecn_mutex);
	}

	return (ssize_t)count;
}

static ssize_t roce3_show_alpha_dec_period(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	struct roce3_ecn_rp_ctx *ecn_rp_ctx = to_roce3_ecn_rp_ctx(kobj);

	return sprintf(buf, "%d\n", (int)ecn_rp_ctx->alpha_dec_period);
}

static ssize_t roce3_store_alpha_dec_period(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	ssize_t ret = 0;
	int alpha_dec_period = 0;
	u32 old_alpha_dec_period = 0;
	struct roce3_ecn_ctx *ecn_ctx = to_roce3_ecn_ctx(kobj->parent);
	struct roce3_ecn_rp_ctx *ecn_rp_ctx = to_roce3_ecn_rp_ctx(kobj);

	ret = kstrtoint(buf, 10, &alpha_dec_period);
	if (ret != 0)
		return -EIO;

	if ((alpha_dec_period < ROCE_MIN_ALPHA_DEC_PERIOD) ||
		(alpha_dec_period > ROCE_MAX_ALPHA_DEC_PERIOD))
		return -EIO;

	if (ecn_rp_ctx->alpha_dec_period != (u32)alpha_dec_period) {
		mutex_lock(&ecn_ctx->ecn_mutex);
		old_alpha_dec_period = ecn_rp_ctx->alpha_dec_period;
		ecn_rp_ctx->alpha_dec_period = (u32)alpha_dec_period;
		ret = (ssize_t)roce3_update_ecn_param(ecn_ctx);
		if (ret != 0) {
			ecn_rp_ctx->alpha_dec_period = old_alpha_dec_period;
			mutex_unlock(&ecn_ctx->ecn_mutex);
			return -EIO;
		}
		mutex_unlock(&ecn_ctx->ecn_mutex);
	}

	return (ssize_t)count;
}

static ssize_t roce3_show_rate_first_set(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	struct roce3_ecn_rp_ctx *ecn_rp_ctx = to_roce3_ecn_rp_ctx(kobj);

	return sprintf(buf, "%d\n", (int)ecn_rp_ctx->rate_first_set);
}

static ssize_t roce3_store_rate_first_set(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	ssize_t ret = 0;
	int rate_first_set = 0;
	u32 old_rate_first_set = 0;
	struct roce3_ecn_ctx *ecn_ctx = to_roce3_ecn_ctx(kobj->parent);
	struct roce3_ecn_rp_ctx *ecn_rp_ctx = to_roce3_ecn_rp_ctx(kobj);

	ret = kstrtoint(buf, 10, &rate_first_set);
	if (ret != 0)
		return -EIO;

	if ((rate_first_set < ROCE_MIN_RATE_FIRST_SET) ||
		(rate_first_set > ROCE_MAX_RATE_FIRST_SET))
		return -EIO;

	if (ecn_rp_ctx->rate_first_set != (u32)rate_first_set) {
		mutex_lock(&ecn_ctx->ecn_mutex);
		old_rate_first_set = ecn_rp_ctx->rate_first_set;
		ecn_rp_ctx->rate_first_set = (u32)rate_first_set;
		ret = (ssize_t)roce3_update_ecn_param(ecn_ctx);
		if (ret != 0) {
			ecn_rp_ctx->rate_first_set = old_rate_first_set;
			mutex_unlock(&ecn_ctx->ecn_mutex);
			return -EIO;
		}
		mutex_unlock(&ecn_ctx->ecn_mutex);
	}

	return (ssize_t)count;
}

static ssize_t roce3_show_rate_target_clamp(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	struct roce3_ecn_rp_ctx *ecn_rp_ctx = to_roce3_ecn_rp_ctx(kobj);

	return sprintf(buf, "%d\n", (int)ecn_rp_ctx->rate_target_clamp);
}

static ssize_t roce3_store_rate_target_clamp(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	ssize_t ret = 0;
	int rate_target_clamp = 0;
	u32 old_rate_target_clamp = 0;
	struct roce3_ecn_ctx *ecn_ctx = to_roce3_ecn_ctx(kobj->parent);
	struct roce3_ecn_rp_ctx *ecn_rp_ctx = to_roce3_ecn_rp_ctx(kobj);

	ret = kstrtoint(buf, 10, &rate_target_clamp);
	if (ret != 0)
		return -EIO;

	if (((u32)rate_target_clamp & ROCE_RT_CLAMP_MASK) != 0)
		return -EIO;

	if (ecn_rp_ctx->rate_target_clamp != (u32)rate_target_clamp) {
		mutex_lock(&ecn_ctx->ecn_mutex);
		old_rate_target_clamp = ecn_rp_ctx->rate_target_clamp;
		ecn_rp_ctx->rate_target_clamp = (u32)rate_target_clamp;
		ret = (ssize_t)roce3_update_ecn_param(ecn_ctx);
		if (ret != 0) {
			ecn_rp_ctx->rate_target_clamp = old_rate_target_clamp;
			mutex_unlock(&ecn_ctx->ecn_mutex);
			return -EIO;
		}
		mutex_unlock(&ecn_ctx->ecn_mutex);
	}

	return (ssize_t)count;
}

static ssize_t roce3_show_min_cnp_period(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	struct roce3_ecn_np_ctx *ecn_np_ctx = to_roce3_ecn_np_ctx(kobj);

	return sprintf(buf, "%d\n", (int)ecn_np_ctx->min_cnp_period);
}

static ssize_t roce3_store_min_cnp_period(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	ssize_t ret = 0;
	int min_cnp_period = 0;
	u32 old_min_cnp_period = 0;
	struct roce3_ecn_ctx *ecn_ctx = to_roce3_ecn_ctx(kobj->parent);
	struct roce3_ecn_np_ctx *ecn_np_ctx = to_roce3_ecn_np_ctx(kobj);

	ret = kstrtoint(buf, 10, &min_cnp_period);
	if (ret != 0)
		return -EIO;

	if ((min_cnp_period < ROCE_MIN_MIN_CNP_PERIOD) ||
		(min_cnp_period > ROCE_MAX_MIN_CNP_PERIOD))
		return -EIO;

	if (ecn_np_ctx->min_cnp_period != (u32)min_cnp_period) {
		mutex_lock(&ecn_ctx->ecn_mutex);
		old_min_cnp_period = ecn_np_ctx->min_cnp_period;
		ecn_np_ctx->min_cnp_period = (u32)min_cnp_period;
		ret = (ssize_t)roce3_update_ecn_param(ecn_ctx);
		if (ret != 0) {
			ecn_np_ctx->min_cnp_period = old_min_cnp_period;
			mutex_unlock(&ecn_ctx->ecn_mutex);
			return -EIO;
		}
		mutex_unlock(&ecn_ctx->ecn_mutex);
	}

	return (ssize_t)count;
}

static ssize_t roce3_show_port_mode(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct roce3_ecn_np_ctx *ecn_np_ctx = to_roce3_ecn_np_ctx(kobj);

	return sprintf(buf, "%d\n", (int)ecn_np_ctx->port_mode);
}

static ssize_t roce3_store_port_mode(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	ssize_t ret = 0;
	int port_mode = 0;
	u32 old_port_mode = 0;
	struct roce3_ecn_ctx *ecn_ctx = to_roce3_ecn_ctx(kobj->parent);
	struct roce3_ecn_np_ctx *ecn_np_ctx = to_roce3_ecn_np_ctx(kobj);

	ret = kstrtoint(buf, 10, &port_mode);
	if (ret != 0)
		return -EIO;

	if (((u32)port_mode & ROCE_PORT_MODE_MASK) != 0)
		return -EIO;

	if (ecn_np_ctx->port_mode != (u32)port_mode) {
		mutex_lock(&ecn_ctx->ecn_mutex);
		old_port_mode = ecn_np_ctx->port_mode;
		ecn_np_ctx->port_mode = (u32)port_mode;
		ret = (ssize_t)roce3_update_ecn_param(ecn_ctx);
		if (ret != 0) {
			ecn_np_ctx->port_mode = old_port_mode;
			mutex_unlock(&ecn_ctx->ecn_mutex);
			return -EIO;
		}
		mutex_unlock(&ecn_ctx->ecn_mutex);
	}

	return (ssize_t)count;
}

static ssize_t roce3_show_quick_adjust_en(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	struct roce3_ecn_np_ctx *ecn_np_ctx = to_roce3_ecn_np_ctx(kobj);

	return sprintf(buf, "%d\n", (int)ecn_np_ctx->quick_adjust_en);
}

static ssize_t roce3_store_quick_adjust_en(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	ssize_t ret = 0;
	int quick_adjust_en = 0;
	u32 old_quick_adjust_en = 0;
	struct roce3_ecn_ctx *ecn_ctx = to_roce3_ecn_ctx(kobj->parent);
	struct roce3_ecn_np_ctx *ecn_np_ctx = to_roce3_ecn_np_ctx(kobj);

	ret = kstrtoint(buf, 10, &quick_adjust_en);
	if (ret != 0)
		return -EIO;

	if (((u32)quick_adjust_en & ROCE_QUICK_AJ_EN_MASK) != 0)
		return -EIO;

	if (ecn_np_ctx->quick_adjust_en != (u32)quick_adjust_en) {
		mutex_lock(&ecn_ctx->ecn_mutex);
		old_quick_adjust_en = ecn_np_ctx->quick_adjust_en;
		ecn_np_ctx->quick_adjust_en = (u32)quick_adjust_en;
		ret = (ssize_t)roce3_update_ecn_param(ecn_ctx);
		if (ret != 0) {
			ecn_np_ctx->quick_adjust_en = old_quick_adjust_en;
			mutex_unlock(&ecn_ctx->ecn_mutex);
			return -EIO;
		}
		mutex_unlock(&ecn_ctx->ecn_mutex);
	}

	return (ssize_t)count;
}

static ssize_t roce3_show_cnp_prio_enable(struct kobject *kobj,
	struct kobj_attribute *attr, char *buf)
{
	struct roce3_ecn_np_ctx *ecn_np_ctx = to_roce3_ecn_np_ctx(kobj);

	return sprintf(buf, "%d\n", (int)ecn_np_ctx->cnp_prio_enable);
}

static ssize_t roce3_store_cnp_prio_enable(struct kobject *kobj,
	struct kobj_attribute *attr, const char *buf, size_t count)
{
	ssize_t ret = 0;
	int cnp_prio_enable = 0;
	u32 old_cnp_prio_enable = 0;
	struct roce3_ecn_ctx *ecn_ctx = to_roce3_ecn_ctx(kobj->parent);
	struct roce3_ecn_np_ctx *ecn_np_ctx = to_roce3_ecn_np_ctx(kobj);

	ret = kstrtoint(buf, 10, &cnp_prio_enable);
	if (ret != 0)
		return -EIO;

	if (((u32)cnp_prio_enable & ROCE_CNP_PRIO_EN_MASK) != 0)
		return -EIO;

	if (ecn_np_ctx->cnp_prio_enable != (u32)cnp_prio_enable) {
		mutex_lock(&ecn_ctx->ecn_mutex);
		old_cnp_prio_enable = ecn_np_ctx->cnp_prio_enable;
		ecn_np_ctx->cnp_prio_enable = (u32)cnp_prio_enable;
		ret = (ssize_t)roce3_update_ecn_param(ecn_ctx);
		if (ret != 0) {
			ecn_np_ctx->cnp_prio_enable = old_cnp_prio_enable;
			mutex_unlock(&ecn_ctx->ecn_mutex);
			return -EIO;
		}
		mutex_unlock(&ecn_ctx->ecn_mutex);
	}

	return (ssize_t)count;
}

static ssize_t roce3_show_cnp_prio(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct roce3_ecn_np_ctx *ecn_np_ctx = to_roce3_ecn_np_ctx(kobj);

	return sprintf(buf, "%d\n", (int)ecn_np_ctx->cnp_prio);
}

static ssize_t roce3_store_cnp_prio(struct kobject *kobj, struct kobj_attribute *attr,
	const char *buf, size_t count)
{
	ssize_t ret = 0;
	int cnp_prio = 0;
	u32 old_cnp_prio = 0;
	struct roce3_ecn_ctx *ecn_ctx = to_roce3_ecn_ctx(kobj->parent);
	struct roce3_ecn_np_ctx *ecn_np_ctx = to_roce3_ecn_np_ctx(kobj);

	ret = kstrtoint(buf, 10, &cnp_prio);
	if (ret != 0)
		return -EIO;

	if (((u32)cnp_prio) > (PRI_ARRAY_LEN - 1))
		return -EIO;

	if (ecn_np_ctx->cnp_prio != (u32)cnp_prio) {
		mutex_lock(&ecn_ctx->ecn_mutex);
		old_cnp_prio = ecn_np_ctx->cnp_prio;
		ecn_np_ctx->cnp_prio = (u32)cnp_prio;
		ret = (ssize_t)roce3_update_ecn_param(ecn_ctx);
		if (ret != 0) {
			ecn_np_ctx->cnp_prio = old_cnp_prio;
			mutex_unlock(&ecn_ctx->ecn_mutex);
			return -EIO;
		}
		mutex_unlock(&ecn_ctx->ecn_mutex);
	}

	return (ssize_t)count;
}

static int roce3_init_ecn_enable_sysfs(struct kobject *kobj,
	struct roce3_ecn_enable_ctx *ecn_enable_ctx)
{
	int ret = 0;
	int i = 0;
	int j = 0;
	const char *prio_arr[8] = {"0", "1", "2", "3", "4", "5", "6", "7"};
	struct roce3_prio_enable_ctx *prio_enable = NULL;

	ecn_enable_ctx->enable_root = kobject_create_and_add("enable", kobj);
	if (ecn_enable_ctx->enable_root == NULL) {
		pr_err("[ROCE, ERR] %s: Failed to create kobject for ecn enable.(ret:%d)\n",
			__func__, ret);
		return -ENOMEM;
	}

	for (i = 0; i < PRI_ARRAY_LEN; i++) {
		prio_enable = &ecn_enable_ctx->prio_enable[i];
		prio_enable->ecn_enable_ctx = (void *)ecn_enable_ctx;
		prio_enable->prio = (u32)i;
		prio_enable->prio_en = 1;
		sysfs_attr_init(&prio_enable->enable.attr);
		prio_enable->enable.attr.name = prio_arr[i];
		prio_enable->enable.attr.mode = 0640;
		prio_enable->enable.show = roce3_show_ecn_prio_enable;
		prio_enable->enable.store = roce3_store_ecn_prio_enable;
		ret = sysfs_create_file(ecn_enable_ctx->enable_root, &prio_enable->enable.attr);
		if (ret != 0) {
			pr_err("[ROCE, ERR] %s: Failed to create file for ecn enable.(ret:%d)\n",
			__func__, ret);
			goto err_create_file;
		}
	}

	return 0;

err_create_file:
	for (j = i - 1; j >= 0; j--) {
		sysfs_remove_file(ecn_enable_ctx->enable_root,
			&ecn_enable_ctx->prio_enable[i].enable.attr);
	}

	kobject_put(ecn_enable_ctx->enable_root);

	return ret;
}

static void roce3_remove_ecn_enable_sysfs(struct kobject *kobj,
	struct roce3_ecn_enable_ctx *ecn_enable_ctx)
{
	int i;

	for (i = 0; i < PRI_ARRAY_LEN; i++) {
		sysfs_remove_file(ecn_enable_ctx->enable_root,
			&ecn_enable_ctx->prio_enable[i].enable.attr);
	}

	kobject_put(ecn_enable_ctx->enable_root);
}

static int roce3_init_ecn_ip_enable_sysfs(struct kobject *kobj,
	struct roce3_ecn_ip_enable_ctx *ip_enable_ctx)
{
	int ret = 0;
	int i = 0;
	int j = 0;
	const char *prio_arr[8] = {"0", "1", "2", "3", "4", "5", "6", "7"};
	struct roce3_ip_prio_enable_ctx *ip_prio_enable = NULL;

	ip_enable_ctx->ip_enable_root = kobject_create_and_add("ip_enable", kobj);
	if (ip_enable_ctx->ip_enable_root == NULL) {
		pr_err("[ROCE, ERR] %s: Failed to create kobject for ecn ip enable.(ret:%d)\n",
		__func__, ret);
		return -ENOMEM;
	}

	for (i = 0; i < PRI_ARRAY_LEN; i++) {
		ip_prio_enable = &ip_enable_ctx->ip_prio_enable[i];
		ip_prio_enable->ecn_ip_enable_ctx = (void *)ip_enable_ctx;
		ip_prio_enable->prio = (u32)i;
		ip_prio_enable->prio_en = ROCE_DEFAULT_IP_EABLE_EN;
		sysfs_attr_init(&ip_prio_enable->ip_enable.attr);
		ip_prio_enable->ip_enable.attr.name = prio_arr[i];
		ip_prio_enable->ip_enable.attr.mode = 0640;
		ip_prio_enable->ip_enable.show = roce3_show_ecn_ip_prio_enable;
		ip_prio_enable->ip_enable.store = roce3_store_ecn_ip_prio_enable;
		ret = sysfs_create_file(ip_enable_ctx->ip_enable_root,
			&ip_prio_enable->ip_enable.attr);
		if (ret != 0) {
			pr_err("[ROCE, ERR] %s: Failed to create file for ecn ip enable.(ret:%d)\n",
				__func__, ret);
			goto err_create_file;
		}
	}

	return 0;

err_create_file:
	for (j = i - 1; j >= 0; j--) {
		sysfs_remove_file(ip_enable_ctx->ip_enable_root,
			&ip_enable_ctx->ip_prio_enable[i].ip_enable.attr);
	}

	kobject_put(ip_enable_ctx->ip_enable_root);

	return ret;
}

static void roce3_remove_ecn_ip_enable_sysfs(struct kobject *kobj,
	struct roce3_ecn_ip_enable_ctx *ip_enable_ctx)
{
	int i;

	for (i = 0; i < PRI_ARRAY_LEN; i++) {
		sysfs_remove_file(ip_enable_ctx->ip_enable_root,
			&ip_enable_ctx->ip_prio_enable[i].ip_enable.attr);
	}

	kobject_put(ip_enable_ctx->ip_enable_root);
}

ROCE_ATTR_RW(alpha_dec_period, roce3_show_alpha_dec_period, roce3_store_alpha_dec_period);
ROCE_ATTR_RW(rate_dec_period, roce3_show_rate_dec_period, roce3_store_rate_dec_period);
ROCE_ATTR_RW(rate_inc_period, roce3_show_rate_inc_period, roce3_store_rate_inc_period);
ROCE_ATTR_RW(cnp_cnt_threshold, roce3_show_cnp_cnt_threshold, roce3_store_cnp_cnt_threshold);
ROCE_ATTR_RW(alpha_threshold, roce3_show_alpha_threshold, roce3_store_alpha_threshold);
ROCE_ATTR_RW(factor_gita, roce3_show_factor_gita, roce3_store_factor_gita);
ROCE_ATTR_RW(initial_alpha, roce3_show_initial_alpha, roce3_store_initial_alpha);
ROCE_ATTR_RW(rate_inc_ai, roce3_show_rate_inc_ai, roce3_store_rate_inc_ai);
ROCE_ATTR_RW(rate_inc_hai, roce3_show_rate_inc_hai, roce3_store_rate_inc_hai);
ROCE_ATTR_RW(rate_first_set, roce3_show_rate_first_set, roce3_store_rate_first_set);
ROCE_ATTR_RW(rate_target_clamp, roce3_show_rate_target_clamp, roce3_store_rate_target_clamp);
ROCE_ATTR_RW(token_period, roce3_show_token_period, roce3_store_token_period);
ROCE_ATTR_RW(min_rate, roce3_show_min_rate, roce3_store_min_rate);

static struct attribute *ecn_rp_ctx_attrs[] = {
	ROCE_ATTR_PTR(alpha_dec_period),
	ROCE_ATTR_PTR(rate_dec_period),
	ROCE_ATTR_PTR(rate_inc_period),
	ROCE_ATTR_PTR(cnp_cnt_threshold),
	ROCE_ATTR_PTR(alpha_threshold),
	ROCE_ATTR_PTR(factor_gita),
	ROCE_ATTR_PTR(initial_alpha),
	ROCE_ATTR_PTR(rate_inc_ai),
	ROCE_ATTR_PTR(rate_inc_hai),
	ROCE_ATTR_PTR(rate_first_set),
	ROCE_ATTR_PTR(rate_target_clamp),
	ROCE_ATTR_PTR(token_period),
	ROCE_ATTR_PTR(min_rate),
	NULL,
};
ATTRIBUTE_GROUPS(ecn_rp_ctx);

static void roce_ecn_rp_sysfs_release(struct kobject *kobj) {}

static struct kobj_type roce_ecn_rp_ktype = {
	.sysfs_ops = &kobj_sysfs_ops,
	.release = roce_ecn_rp_sysfs_release,
	.default_groups = ecn_rp_ctx_groups,
};

static int roce3_init_ecn_rp_sysfs(struct kobject *kobj, struct roce3_ecn_rp_ctx *ecn_rp_ctx)
{
	int ret = 0;

	ecn_rp_ctx->alpha_dec_period = ROCE_DEFAULT_ALPHA_DEC_PERIOD;
	ecn_rp_ctx->rate_dec_period = ROCE_DEFAULT_RATE_DEC_PERIOD;
	ecn_rp_ctx->rate_inc_period = ROCE_DEFAULT_RATE_INC_PERIOD;
	ecn_rp_ctx->alpha_threshold = ROCE_DEFAULT_ALPHA_THRESHOLD;
	ecn_rp_ctx->cnp_cnt_threshold = ROCE_DEFAULT_CNP_CNT_THRESHOLD;
	ecn_rp_ctx->factor_gita = ROCE_DEFAULT_FACTOR_GITA;
	ecn_rp_ctx->initial_alpha = ROCE_DEFAULT_INITIAL_ALPHA;
	ecn_rp_ctx->rate_inc_ai = ROCE_DEFAULT_RATE_INC_AI;
	ecn_rp_ctx->rate_inc_hai = ROCE_DEFAULT_RATE_INC_HAI;
	ecn_rp_ctx->rate_first_set = ROCE_DEFAULT_RATE_FIRST_SET;
	ecn_rp_ctx->rate_target_clamp = ROCE_DEFAULT_RATE_TARGET_CLAMP;
	ecn_rp_ctx->token_period = ROCE_DEFAULT_TOKEN_PERIOD;
	ecn_rp_ctx->min_rate = ROCE_DEFAULT_MIN_RATE;
	ret = kobject_init_and_add(&ecn_rp_ctx->ecn_rp_root, &roce_ecn_rp_ktype, kobj, "roce3_rp");
	if (ret != 0) {
		pr_err("[ROCE, ERR] %s: Failed to add kobject roce3_rp.(ret:%d)\n", __func__, ret);
		kobject_put(&ecn_rp_ctx->ecn_rp_root);
		return ret;
	}

	ecn_rp_ctx->enable_ctx.np_rp = ROCE_DCQCN_RP;
	ret = roce3_init_ecn_enable_sysfs(&ecn_rp_ctx->ecn_rp_root, &ecn_rp_ctx->enable_ctx);
	if (ret != 0)
		goto err_init_prio_enable_sysfs;

	return 0;

err_init_prio_enable_sysfs:
	kobject_put(&ecn_rp_ctx->ecn_rp_root);

	return ret;
}

static void roce3_remove_ecn_rp_sysfs(struct kobject *kobj, struct roce3_ecn_rp_ctx *ecn_rp_ctx)
{
	roce3_remove_ecn_enable_sysfs(&ecn_rp_ctx->ecn_rp_root, &ecn_rp_ctx->enable_ctx);

	kobject_put(&ecn_rp_ctx->ecn_rp_root);
}

ROCE_ATTR_RW(min_cnp_period, roce3_show_min_cnp_period, roce3_store_min_cnp_period);
ROCE_ATTR_RW(quick_adjust_en, roce3_show_quick_adjust_en, roce3_store_quick_adjust_en);
ROCE_ATTR_RW(port_mode, roce3_show_port_mode, roce3_store_port_mode);
ROCE_ATTR_RW(cnp_prio_enable, roce3_show_cnp_prio_enable, roce3_store_cnp_prio_enable);
ROCE_ATTR_RW(cnp_prio, roce3_show_cnp_prio, roce3_store_cnp_prio);

static struct attribute *ecn_np_ctx_attrs[] = {
	ROCE_ATTR_PTR(min_cnp_period),
	ROCE_ATTR_PTR(quick_adjust_en),
	ROCE_ATTR_PTR(port_mode),
	ROCE_ATTR_PTR(cnp_prio_enable),
	ROCE_ATTR_PTR(cnp_prio),
	NULL,
};
ATTRIBUTE_GROUPS(ecn_np_ctx);

static void roce_ecn_np_sysfs_release(struct kobject *kobj) {}

static struct kobj_type roce_ecn_np_ktype = {
	.sysfs_ops = &kobj_sysfs_ops,
	.release = roce_ecn_np_sysfs_release,
	.default_groups = ecn_np_ctx_groups,
};

static int roce3_init_ecn_np_sysfs(struct kobject *kobj, struct roce3_ecn_np_ctx *ecn_np_ctx)
{
	int ret = 0;

	ecn_np_ctx->min_cnp_period = ROCE_DEFAULT_MIN_CNP_PERIOD;
	ecn_np_ctx->quick_adjust_en = ROCE_DEFAULT_QUICK_AJ_ENABLE;
	ecn_np_ctx->port_mode = ROCE_DEFAULT_PORT_MODE_25G;
	ecn_np_ctx->cnp_prio_enable = ROCE_DEFAULT_CNP_PRIO_ENABLE;
	ecn_np_ctx->cnp_prio = ROCE_DEFAULT_CNP_PRIO;
	ret = kobject_init_and_add(&ecn_np_ctx->ecn_np_root, &roce_ecn_np_ktype, kobj, "roce3_np");
	if (ret != 0) {
		pr_err("[ROCE, ERR] %s: Failed to add kobject roce3_np.(ret:%d)\n", __func__, ret);
		kobject_put(&ecn_np_ctx->ecn_np_root);
		return ret;
	}

	ecn_np_ctx->enable_ctx.np_rp = ROCE_DCQCN_NP;
	ret = roce3_init_ecn_enable_sysfs(&ecn_np_ctx->ecn_np_root, &ecn_np_ctx->enable_ctx);
	if (ret != 0)
		goto err_init_prio_enable_sysfs;

	return 0;

err_init_prio_enable_sysfs:
	kobject_put(&ecn_np_ctx->ecn_np_root);
	return ret;
}

static void roce3_remove_ecn_np_sysfs(struct kobject *kobj, struct roce3_ecn_np_ctx *ecn_np_ctx)
{
	roce3_remove_ecn_enable_sysfs(&ecn_np_ctx->ecn_np_root, &ecn_np_ctx->enable_ctx);

	kobject_put(&ecn_np_ctx->ecn_np_root);
}

static ssize_t roce3_show_ecn_ver(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct roce3_ecn_ctx *ecn_ctx = to_roce3_ecn_ctx(kobj);

	return sprintf(buf, "%d\n", (int)ecn_ctx->ecn_ver);
}

static ssize_t roce3_store_ecn_ver(struct kobject *kobj, struct kobj_attribute *attr,
	const char *buf, size_t count)
{
	ssize_t ret = 0;
	int ecn_ver = 0;
	u32 old_ecn_ver = 0;
	struct roce3_ecn_ctx *ecn_ctx = to_roce3_ecn_ctx(kobj);

	ret = kstrtoint(buf, 10, &ecn_ver);
	if (ret != 0)
		return -EIO;

	if ((ecn_ver < ECN_VER_DCQCN) || (ecn_ver > ECN_VER_PATHQCN))
		return -EIO;

	if (ecn_ctx->ecn_ver != (u32)ecn_ver) {
		mutex_lock(&ecn_ctx->ecn_mutex);
		old_ecn_ver = ecn_ctx->ecn_ver;
		ecn_ctx->ecn_ver = (u32)ecn_ver;
		ret = (ssize_t)roce3_update_ecn_param(ecn_ctx);
		if (ret != 0) {
			ecn_ctx->ecn_ver = old_ecn_ver;
			mutex_unlock(&ecn_ctx->ecn_mutex);
			return -EIO;
		}
		mutex_unlock(&ecn_ctx->ecn_mutex);
	}

	return (ssize_t)count;
}

ROCE_ATTR_RW(ecn_ver, roce3_show_ecn_ver, roce3_store_ecn_ver);
ROCE_ATTR_RW(cc_algo, roce3_show_cc_algo, roce3_store_cc_algo);

static struct attribute *ecn_ctx_attrs[] = {
	ROCE_ATTR_PTR(ecn_ver),
	ROCE_ATTR_PTR(cc_algo),
	NULL,
};
ATTRIBUTE_GROUPS(ecn_ctx);

static void roce_ecn_sysfs_release(struct kobject *kobj) {}

static struct kobj_type roce_ecn_ktype = {
	.sysfs_ops = &kobj_sysfs_ops,
	.release = roce_ecn_sysfs_release,
	.default_groups = ecn_ctx_groups,
};

static int roce3_init_ecn_sysfs(struct net_device *ndev, struct roce3_ecn_ctx *ecn_ctx)
{
	int ret = 0;

	memset(ecn_ctx, 0, sizeof(*ecn_ctx));

	mutex_init(&ecn_ctx->ecn_mutex);

	ecn_ctx->ecn_ver = ECN_VER_DCQCN;
#ifdef ROCE_COMPUTE
#ifdef EULER_2_10_OFED_4_18
	ecn_ctx->cc_algo = ROCE_CC_LDCP_ALGO;
#else
	ecn_ctx->cc_algo = ROCE_CC_DCQCN_ALGO;
#endif
#elif defined(ROCE_VBS_EN) || defined(ROCE_STANDARD)
	ecn_ctx->cc_algo = ROCE_CC_LDCP_ALGO;
#else
	ecn_ctx->cc_algo = ROCE_CC_DISABLE;
#endif

	ret = kobject_init_and_add(&ecn_ctx->ecn_root, &roce_ecn_ktype, &ndev->dev.kobj, "ecn");
	if (ret != 0) {
		pr_err("[ROCE, ERR] %s: Failed to add kobject ecn.(ret:%d)\n", __func__, ret);
		kobject_put(&ecn_ctx->ecn_root);
		return ret;
	}

	ret = roce3_init_ecn_np_sysfs(&ecn_ctx->ecn_root, &ecn_ctx->np_ctx);
	if (ret != 0)
		goto err_init_np_sysfs;

	ret = roce3_init_ecn_rp_sysfs(&ecn_ctx->ecn_root, &ecn_ctx->rp_ctx);
	if (ret != 0)
		goto err_init_rp_sysfs;

	ret = roce3_init_ecn_ip_enable_sysfs(&ecn_ctx->ecn_root, &ecn_ctx->ip_enable_ctx);
	if (ret != 0)
		goto err_init_ip_enable_sysfs;

	ret = roce3_update_ecn_param(ecn_ctx);
	if (ret != 0)
		goto err_update;

	return 0;

err_update:
	roce3_remove_ecn_ip_enable_sysfs(&ecn_ctx->ecn_root, &ecn_ctx->ip_enable_ctx);
err_init_ip_enable_sysfs:
	roce3_remove_ecn_rp_sysfs(&ecn_ctx->ecn_root, &ecn_ctx->rp_ctx);
err_init_rp_sysfs:
	roce3_remove_ecn_np_sysfs(&ecn_ctx->ecn_root, &ecn_ctx->np_ctx);
err_init_np_sysfs:
	kobject_put(&ecn_ctx->ecn_root);
	return ret;
}

static void roce3_prase_qpc(struct roce_qp_context *qpc)
{
	qpc->chip_seg.sqc.dw2.value = be32_to_cpu(qpc->chip_seg.sqc.dw2.value);
	qpc->chip_seg.sqc.dw3.value = be32_to_cpu(qpc->chip_seg.sqc.dw3.value);
	qpc->chip_seg.sqac.dw3.value = be32_to_cpu(qpc->chip_seg.sqac.dw3.value);
	qpc->chip_seg.sqac.dw7.value = be32_to_cpu(qpc->chip_seg.sqac.dw7.value);
	qpc->chip_seg.rqc.dw3.value = be32_to_cpu(qpc->chip_seg.rqc.dw3.value);
	qpc->chip_seg.rqc.dw7.value = be32_to_cpu(qpc->chip_seg.rqc.dw7.value);
	qpc->sw_seg.ucode_seg.common.dw3.value =
		be32_to_cpu(qpc->sw_seg.ucode_seg.common.dw3.value);
	qpc->sw_seg.ucode_seg.sq_ctx.dw9.value =
		be32_to_cpu(qpc->sw_seg.ucode_seg.sq_ctx.dw9.value);
	qpc->sw_seg.ucode_seg.sq_ctx.ack_ctx.dw15.value =
		be32_to_cpu(qpc->sw_seg.ucode_seg.sq_ctx.ack_ctx.dw15.value);
	qpc->sw_seg.ucode_seg.rq_ctx.dw22.value =
		be32_to_cpu(qpc->sw_seg.ucode_seg.rq_ctx.dw22.value);
	qpc->sw_seg.ucode_seg.rq_ctx.ack_ctx.dw27.value =
		be32_to_cpu(qpc->sw_seg.ucode_seg.rq_ctx.ack_ctx.dw27.value);
}

static ssize_t roce3_store_dfx_qpc(struct kobject *kobj, struct kobj_attribute *attr,
	const char *buf, size_t count)
{
	int ret;
	u32 qpn;
	struct roce3_dfx_qpc_ctx *qpc_ctx = NULL;
	struct roce3_dfx_ctx *dfx_ctx = NULL;
	struct roce3_device *rdev = NULL;
	struct roce_qp_context qpc;
	struct rdma_service_cap *rdma_cap = NULL;

	if (kobj == NULL || attr == NULL || buf == NULL || count == 0) {
		pr_err("[ROCE] %s: Invalid input para\n", __func__);
		return -EINVAL;
	}

	qpc_ctx = container_of(attr, struct roce3_dfx_qpc_ctx, kattr);
	dfx_ctx = container_of(qpc_ctx, struct roce3_dfx_ctx, qpc_ctx);
	rdev = container_of(dfx_ctx, struct roce3_device, dfx_ctx);

	memset(&qpc, 0, sizeof(struct roce_qp_context));

	ret = (int)kstrtou32(buf, 10, &qpn);
	if (ret != 0) {
		pr_err("[ROCE] %s: Failed to do sscanf_s, ret(%d)\n", __func__, ret);
		return -EIO;
	}

	rdma_cap = &rdev->rdma_cap;
	if ((qpn >= rdma_cap->dev_rdma_cap.roce_own_cap.max_qps) || (qpn < ROCE_MIN_QPN)) {
		pr_err("[ROCE] %s: Invalid qpn(%u), max_qps(%u)\n",
			__func__, qpn, rdma_cap->dev_rdma_cap.roce_own_cap.max_qps);
		return -EIO;
	}

	ret = roce3_dfx_cmd_query_qp(rdev, qpn, &qpc);
	if (ret != 0) {
		pr_err("[ROCE] %s: Failed to query qpc, ret(%d)\n", __func__, ret);
		return (ssize_t)ret;
	}

	roce3_prase_qpc(&qpc);

	roce3_dfx_print("qpn(0x%x): sqc pi(0x%x), sqc ci(0x%x), ccf_appid(0x%x)\n",
		qpn, qpc.chip_seg.sqc.dw2.bs.sq_pi, qpc.chip_seg.sqc.dw3.bs.sq_ci,
		qpc.sw_seg.ucode_seg.common.dw0.bs.ccf_appid);
	roce3_dfx_print("sqac ci(0x%x), sqac wqe_prefetch_ci(0x%x), rqc pi(0x%x), rqc ci(0x%x)\n",
		qpc.chip_seg.sqac.dw3.bs.sqa_ci, qpc.chip_seg.sqac.dw7.bs.sqa_wqe_prefetch_ci,
		qpc.chip_seg.rqc.dw7.bs.rq_pi, qpc.chip_seg.rqc.dw3.bs.rq_ci);
	roce3_dfx_print("sq_ssn(0x%x), sq_rcv_msn(0x%x), rq_last_msn(0x%x), rqa_msn(0x%x)\n",
		qpc.sw_seg.ucode_seg.sq_ctx.dw9.bs.ssn,
		qpc.sw_seg.ucode_seg.sq_ctx.ack_ctx.dw15.bs.sq_rcv_msn,
		qpc.sw_seg.ucode_seg.rq_ctx.dw22.bs.last_msn,
		qpc.sw_seg.ucode_seg.rq_ctx.ack_ctx.dw27.bs.msn);

	return (ssize_t)count;
}

static ssize_t roce3_store_dfx_cqc(struct kobject *kobj, struct kobj_attribute *attr,
	const char *buf, size_t count)
{
	int ret;
	u32 cqn;
	struct roce3_dfx_cqc_ctx *cqc_ctx = NULL;
	struct roce3_dfx_ctx *dfx_ctx = NULL;
	struct roce3_device *rdev = NULL;
	struct roce_cq_context cqc;
	struct rdma_service_cap *rdma_cap = NULL;

	if (kobj == NULL || attr == NULL || buf == NULL || count == 0) {
		pr_err("[ROCE] %s: Invalid input para\n", __func__);
		return -EINVAL;
	}

	cqc_ctx = container_of(attr, struct roce3_dfx_cqc_ctx, kattr);
	dfx_ctx = container_of(cqc_ctx, struct roce3_dfx_ctx, cqc_ctx);
	rdev = container_of(dfx_ctx, struct roce3_device, dfx_ctx);

	memset(&cqc, 0, sizeof(struct roce_cq_context));

	ret = (int)kstrtou32(buf, 10, &cqn);
	if (ret != 0) {
		pr_err("[ROCE] %s: Failed to do sscanf_s, ret(%d)\n", __func__, ret);
		return -EIO;
	}

	rdma_cap = &rdev->rdma_cap;
	if (cqn >= rdma_cap->dev_rdma_cap.roce_own_cap.max_cqs) {
		pr_err("[ROCE] %s: Invalid cqn(%u), max_cqs(%u)\n", __func__, cqn,
			rdma_cap->dev_rdma_cap.roce_own_cap.max_cqs);
		return -EIO;
	}

	ret = roce3_dfx_cmd_query_cq(rdev, cqn, &cqc);
	if (ret != 0) {
		pr_err("[ROCE] %s: Failed to query cqc, ret(%d)\n", __func__, ret);
		return (ssize_t)ret;
	}

	cqc.dw2.value = be32_to_cpu(cqc.dw2.value);
	cqc.dw1.value = be32_to_cpu(cqc.dw1.value);

	roce3_dfx_print("cqn(0x%x): pi(0x%x), ci(0x%x)\n", cqn, cqc.dw2.bs.pi, cqc.dw1.bs.ci);

	return (ssize_t)count;
}

static ssize_t roce3_store_dfx_srqc(struct kobject *kobj, struct kobj_attribute *attr,
	const char *buf, size_t count)
{
	int ret;
	u32 srqn;
	struct roce3_dfx_srqc_ctx *srqc_ctx = NULL;
	struct roce3_dfx_ctx *dfx_ctx = NULL;
	struct roce3_device *rdev = NULL;
	struct roce_srq_context srqc;
	struct rdma_service_cap *rdma_cap = NULL;

	if (kobj == NULL || attr == NULL || buf == NULL || count == 0) {
		pr_err("[ROCE] %s: Invalid input para\n", __func__);
		return -EINVAL;
	}

	srqc_ctx = container_of(attr, struct roce3_dfx_srqc_ctx, kattr);
	dfx_ctx = container_of(srqc_ctx, struct roce3_dfx_ctx, srqc_ctx);
	rdev = container_of(dfx_ctx, struct roce3_device, dfx_ctx);

	memset(&srqc, 0, sizeof(struct roce_srq_context));

	ret = (int)kstrtou32(buf, 10, &srqn);
	if (ret != 0) {
		pr_err("[ROCE] %s: Failed to do sscanf_s, ret(%d)\n", __func__, ret);
		return -EIO;
	}

	rdma_cap = &rdev->rdma_cap;
	if (srqn >= rdma_cap->dev_rdma_cap.roce_own_cap.max_srqs) {
		pr_err("[ROCE] %s: Invalid srqn(%u), max_srqs(%u)\n", __func__, srqn,
			rdma_cap->dev_rdma_cap.roce_own_cap.max_srqs);
		return -EIO;
	}

	ret = roce3_dfx_cmd_query_srq(rdev, srqn, &srqc);
	if (ret != 0) {
		pr_err("[ROCE] %s: Failed to query srqc, ret(%d)\n", __func__, ret);
		return (ssize_t)ret;
	}

	srqc.dw4.value = be32_to_cpu(srqc.dw4.value);

	roce3_dfx_print("srqn(0x%x): pcnt(0x%x), ccnt(0x%x)\n",
		srqn, srqc.dw4.bs.pcnt, srqc.dw4.bs.ccnt);

	return (ssize_t)count;
}

static int roce3_init_dfx_sub_ctx_sysfs(struct kobject *kobj, struct roce3_dfx_ctx *dfx_ctx)
{
	int ret;
	struct kobj_attribute *qpc_kattr = NULL;
	struct kobj_attribute *cqc_kattr = NULL;
	struct kobj_attribute *srqc_kattr = NULL;

	if (kobj == NULL || dfx_ctx == NULL) {
		pr_err("[ROCE] %s: Invalid kobj or dfx_ctx\n", __func__);
		return -EINVAL;
	}

	qpc_kattr = &dfx_ctx->qpc_ctx.kattr;
	cqc_kattr = &dfx_ctx->cqc_ctx.kattr;
	srqc_kattr = &dfx_ctx->srqc_ctx.kattr;

	sysfs_attr_init(&qpc_kattr->attr);
	qpc_kattr->attr.name = "qpc";
	qpc_kattr->attr.mode = 0640;
	qpc_kattr->store = roce3_store_dfx_qpc;
	ret = sysfs_create_file(kobj, &qpc_kattr->attr);
	if (ret != 0) {
		pr_err("[ROCE] %s: QPC failed to do sysfs_create_file, ret(%d)\n", __func__, ret);
		return ret;
	}

	sysfs_attr_init(&cqc_kattr->attr);
	cqc_kattr->attr.name = "cqc";
	cqc_kattr->attr.mode = 0640;
	cqc_kattr->store = roce3_store_dfx_cqc;
	ret = sysfs_create_file(kobj, &cqc_kattr->attr);
	if (ret != 0) {
		pr_err("[ROCE] %s: CQC failed to do sysfs_create_file, ret(%d)\n", __func__, ret);
		goto err_create_cqc_sysfs;
	}

	sysfs_attr_init(&srqc_kattr->attr);
	srqc_kattr->attr.name = "srqc";
	srqc_kattr->attr.mode = 0640;
	srqc_kattr->store = roce3_store_dfx_srqc;
	ret = sysfs_create_file(kobj, &srqc_kattr->attr);
	if (ret != 0) {
		pr_err("[ROCE] %s: SRQC failed to do sysfs_create_file, ret(%d)\n", __func__, ret);
		goto err_create_srqc_sysfs;
	}

	return 0;

err_create_srqc_sysfs:
	sysfs_remove_file(kobj, &cqc_kattr->attr);

err_create_cqc_sysfs:
	sysfs_remove_file(kobj, &qpc_kattr->attr);

	return ret;
}

static int roce3_init_dfx_sysfs(struct net_device *ndev, struct roce3_dfx_ctx *dfx_ctx)
{
	int ret;

	memset(dfx_ctx, 0, sizeof(*dfx_ctx));

	dfx_ctx->dfx_root = kobject_create_and_add("roce3_dfx", &ndev->dev.kobj);
	if (dfx_ctx->dfx_root == NULL) {
		pr_err("[ROCE] %s: Failed to do kobject_create_and_add\n", __func__);
		return -ENOMEM;
	}

	ret = roce3_init_dfx_sub_ctx_sysfs(dfx_ctx->dfx_root, dfx_ctx);
	if (ret != 0) {
		pr_err("[ROCE] %s: Failed to init dfx sub ctx sysfs, ret(%d)\n", __func__, ret);
		kobject_put(dfx_ctx->dfx_root);
		return ret;
	}

	return 0;
}

static void roce3_remove_ecn_sysfs(struct roce3_ecn_ctx *ecn_ctx)
{
	roce3_remove_ecn_ip_enable_sysfs(&ecn_ctx->ecn_root, &ecn_ctx->ip_enable_ctx);

	roce3_remove_ecn_rp_sysfs(&ecn_ctx->ecn_root, &ecn_ctx->rp_ctx);

	roce3_remove_ecn_np_sysfs(&ecn_ctx->ecn_root, &ecn_ctx->np_ctx);

	kobject_put(&ecn_ctx->ecn_root);
}

int roce3_init_sysfs(struct roce3_device *rdev)
{
	int ret;

	ret = roce3_init_ecn_sysfs(rdev->ndev, &rdev->ecn_ctx);
	if (ret != 0) {
		pr_err("[ROCE] %s: Failed to init ecn sysfs, ret(%d)\n", __func__, ret);
		return ret;
	}

	ret = roce3_init_dfx_sysfs(rdev->ndev, &rdev->dfx_ctx);
	if (ret != 0) {
		pr_err("[ROCE] %s: Failed to init dfx sysfs, ret(%d)\n", __func__, ret);
		return ret;
	}

	return 0;
}

static void roce3_remove_dfx_sub_sysfs(struct roce3_dfx_ctx *dfx_ctx)
{
	if (dfx_ctx->dfx_root != NULL) {
		sysfs_remove_file(dfx_ctx->dfx_root, &dfx_ctx->srqc_ctx.kattr.attr);

		sysfs_remove_file(dfx_ctx->dfx_root, &dfx_ctx->cqc_ctx.kattr.attr);

		sysfs_remove_file(dfx_ctx->dfx_root, &dfx_ctx->qpc_ctx.kattr.attr);

		kobject_put(dfx_ctx->dfx_root);

		dfx_ctx->dfx_root = NULL;
	}
}


void roce3_remove_sysfs(struct roce3_device *rdev)
{
	roce3_remove_dfx_sub_sysfs(&rdev->dfx_ctx);
	roce3_remove_ecn_sysfs(&rdev->ecn_ctx);
}
