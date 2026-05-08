// SPDX-License-Identifier: GPL-2.0
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_drv_rdma_configfs.c
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#include <linux/configfs.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/bitfield.h>
#include "sxe2_drv_main.h"
#include "sxe2_drv_hw.h"
#include "sxe2_drv_rdma_common.h"
#include "sxe2_drv_rdma_log.h"
#include "sxe2_drv_rdma_configfs.h"

#ifdef SXE2_SUPPORT_CONFIGFS

#define SXE2_MIN_INT_RATE_LIMIT		     3968
#define SXE2_MAX_INT_RATE_LIMIT		     250000
#define SXE2_USECS_PER_SEC		     1000000
#define SXE2_USECS_PER_UNIT		     4
#define SXE2_MAX_SUPPORTED_INT_RATE_INTERVAL 0x3F

#define SXE2_MAX_ITR	       8190
#define SXE2_MAX_RD_FENCE_RATE 255

enum sxe2_configfs_attr_type {
	SXE2_ATTR_ROCE_TIMELY,
	SXE2_ATTR_ROCE_DCQCN,
};

struct sxe2_vsi_grp {
	struct config_group group;
	struct sxe2_rdma_device *dev;
};

static struct config_group *sxe2rdma_group;

void sxe2_rdma_set_irq_rate_limit(struct sxe2_rdma_ctx_dev *dev, u32 idx,
				  u32 interval)
{
	u32 value;
	u32 rate_limit_reg;
	u32 credit_max_value_reg;

	if (interval == 0) {
		value = 0;
	} else {
		if (interval > SXE2_MAX_SUPPORTED_INT_RATE_INTERVAL)
			interval = SXE2_MAX_SUPPORTED_INT_RATE_INTERVAL;

		rate_limit_reg =
			FIELD_PREP(SXE2_PF_INT_RATE_CREDIT_INTERVAL,
				   interval);
		credit_max_value_reg =
			SXE2_PF_INT_RATE_CREDIT_MAX_VALUE;

		value = rate_limit_reg | credit_max_value_reg |
			SXE2_PF_INT_RATE_INTRL_ENABLE;
	}
	SXE2_BAR_WRITE_32(value, dev->hw_regs[PF_INT_RATE] + idx);
}

static struct sxe2_rdma_device *sxe2_find_device_by_name(const char *name)
{
	struct sxe2_rdma_handler *hdl;
	struct sxe2_rdma_device *dev;
	unsigned long flags;

	spin_lock_irqsave(&sxe2_handler_lock, flags);
	list_for_each_entry(hdl, &sxe2_handlers, list) {
		dev = hdl->dev;
		if (!strcmp(name, dev->ibdev.name)) {
			spin_unlock_irqrestore(&sxe2_handler_lock, flags);
			return dev;
		}
	}
	spin_unlock_irqrestore(&sxe2_handler_lock, flags);

	return NULL;
}

static int sxe2_configfs_set_vsi_attr(struct config_item *item, const char *buf,
				      enum sxe2_configfs_attr_type attr_type)
{
	struct sxe2_vsi_grp *grp =
		container_of(to_config_group(item), struct sxe2_vsi_grp, group);

	struct sxe2_rdma_device *dev = grp->dev;
	bool enable;

	int ret = 0;

	if (kstrtobool(buf, &enable)) {
		ret = -EINVAL;
		goto done;
	}

	switch (attr_type) {
	case SXE2_ATTR_ROCE_TIMELY:
		dev->rdma_func->cc_params.timely_enable = enable;
		break;
	case SXE2_ATTR_ROCE_DCQCN:
		dev->rdma_func->cc_params.dcqcn_enable = enable;
		break;

	default:
		ret = -EINVAL;
	}

done:
	return ret;
}

static ssize_t ceq_intrl_store(struct config_item *item, const char *buf,
			       size_t count)
{
	struct sxe2_vsi_grp *grp =
		container_of(to_config_group(item), struct sxe2_vsi_grp, group);
	struct sxe2_rdma_device *rdma_dev = grp->dev;
	struct sxe2_rdma_msix_vector *msix_vec;
	u32 intrl, interval = 0;
	int i;

	if (kstrtou32(buf, 0, &intrl))
		return -EINVAL;

	if (intrl && intrl < SXE2_MIN_INT_RATE_LIMIT)
		intrl = SXE2_MIN_INT_RATE_LIMIT;
	if (intrl > SXE2_MAX_INT_RATE_LIMIT)
		intrl = SXE2_MAX_INT_RATE_LIMIT;

	rdma_dev->ceq_intrl = intrl;
	if (intrl) {
		interval = (SXE2_USECS_PER_SEC / intrl) /
			   SXE2_USECS_PER_UNIT;

		DRV_RDMA_LOG_DEV_DEBUG(
			"CEQ Interrupt rate Limit enabled with interval = %d\n",
			interval);
	} else {
		DRV_RDMA_LOG_DEV_DEBUG("CEQ Interrupt rate Limit disabled\n");
	}

	if (rdma_dev->rdma_func->msix_shared)
		msix_vec = &rdma_dev->rdma_func->sxe2_msixtbl[1];
	else
		msix_vec = &rdma_dev->rdma_func->sxe2_msixtbl[2];

	for (i = 1; i < rdma_dev->rdma_func->ceqs_count; i++, msix_vec++)
		sxe2_rdma_set_irq_rate_limit(&rdma_dev->rdma_func->ctx_dev,
					     msix_vec->idx, interval);
	return count;
}

static ssize_t ceq_intrl_show(struct config_item *item, char *buf)
{
	struct sxe2_vsi_grp *grp =
		container_of(to_config_group(item), struct sxe2_vsi_grp, group);
	struct sxe2_rdma_device *dev = grp->dev;
	ssize_t ret;

	ret = sprintf(buf, "%d\n", dev->ceq_intrl);

	return ret;
}

static ssize_t roce_rtomin_store(struct config_item *item, const char *buf,
				 size_t count)
{
	struct sxe2_vsi_grp *grp =
		container_of(to_config_group(item), struct sxe2_vsi_grp, group);
	struct sxe2_rdma_device *dev = grp->dev;
	u8 rtomin;

	if (kstrtou8(buf, 0, &rtomin))
		return -EINVAL;

	if (rtomin > SXE2_MAX_ACK_TIMEOUT_VAL)
		rtomin = SXE2_MAX_ACK_TIMEOUT_VAL;

	dev->roce_rtomin     = rtomin;
	dev->override_rtomin = true;

	return count;
}

static ssize_t roce_rtomin_show(struct config_item *item, char *buf)
{
	struct sxe2_vsi_grp *grp =
		container_of(to_config_group(item), struct sxe2_vsi_grp, group);
	struct sxe2_rdma_device *dev = grp->dev;
	ssize_t ret;

	ret = sprintf(buf, "%d\n", dev->roce_rtomin);

	return ret;
}

static ssize_t kernel_llwqe_mode_show(struct config_item *item, char *buf)
{
	struct sxe2_vsi_grp *grp =
		container_of(to_config_group(item), struct sxe2_vsi_grp, group);
	struct sxe2_rdma_device *dev = grp->dev;
	ssize_t ret;

	ret = sprintf(buf, "%d\n", dev->kernel_llwqe_mode);

	return ret;
}

static ssize_t kernel_llwqe_mode_store(struct config_item *item,
				       const char *buf, size_t count)
{
	struct sxe2_vsi_grp *grp =
		container_of(to_config_group(item), struct sxe2_vsi_grp, group);
	struct sxe2_rdma_device *dev = grp->dev;
	bool enable;

	if (kstrtobool(buf, &enable))
		return -EINVAL;

	dev->kernel_llwqe_mode = enable;

	return count;
}

static ssize_t roce_timely_enable_show(struct config_item *item, char *buf)
{
	struct sxe2_vsi_grp *grp =
		container_of(to_config_group(item), struct sxe2_vsi_grp, group);
	struct sxe2_rdma_device *dev = grp->dev;
	ssize_t ret;

	ret = sprintf(buf, "%d\n", dev->rdma_func->cc_params.timely_enable);

	return ret;
}

static ssize_t roce_timely_enable_store(struct config_item *item,
					const char *buf, size_t count)
{
	int ret;

	ret = sxe2_configfs_set_vsi_attr(item, buf, SXE2_ATTR_ROCE_TIMELY);
	if (ret)
		return ret;

	return count;
}

static ssize_t roce_dcqcn_enable_show(struct config_item *item, char *buf)
{
	struct sxe2_vsi_grp *grp =
		container_of(to_config_group(item), struct sxe2_vsi_grp, group);
	struct sxe2_rdma_device *dev = grp->dev;
	ssize_t ret;

	ret = sprintf(buf, "%d\n", dev->rdma_func->cc_params.dcqcn_enable);

	return ret;
}

static ssize_t roce_dcqcn_enable_store(struct config_item *item,
				       const char *buf, size_t count)
{
	int ret;

	ret = sxe2_configfs_set_vsi_attr(item, buf, SXE2_ATTR_ROCE_DCQCN);
	if (ret)
		return ret;

	return count;
}

static ssize_t roce_rd_fence_rate_show(struct config_item *item, char *buf)
{
	struct sxe2_vsi_grp *grp =
		container_of(to_config_group(item), struct sxe2_vsi_grp, group);
	struct sxe2_rdma_device *dev = grp->dev;
	ssize_t ret;

	ret = sprintf(buf, "%d\n", dev->rd_fence_rate);

	return ret;
}

static ssize_t roce_rd_fence_rate_store(struct config_item *item,
					const char *buf, size_t count)
{
	struct sxe2_vsi_grp *grp =
		container_of(to_config_group(item), struct sxe2_vsi_grp, group);
	struct sxe2_rdma_device *dev = grp->dev;
	u32 rd_fence_rate;

	if (kstrtou32(buf, 0, &rd_fence_rate))
		return -EINVAL;

	if (rd_fence_rate > SXE2_MAX_RD_FENCE_RATE)
		rd_fence_rate = SXE2_MAX_RD_FENCE_RATE;

	dev->rd_fence_rate	    = rd_fence_rate;
	dev->override_rd_fence_rate = true;

	return count;
}

static ssize_t roce_enable_tph_show(struct config_item *item, char *buf)
{
	struct sxe2_vsi_grp *grp =
		container_of(to_config_group(item), struct sxe2_vsi_grp, group);
	struct sxe2_rdma_device *dev = grp->dev;
	ssize_t ret;

	ret = sprintf(buf, "%d\n", dev->roce_enable_tph);

	return ret;
}

static ssize_t roce_enable_tph_store(struct config_item *item,
				       const char *buf, size_t count)
{
	struct sxe2_vsi_grp *grp =
		container_of(to_config_group(item), struct sxe2_vsi_grp, group);
	struct sxe2_rdma_device *rdma_dev = grp->dev;
	bool state;

	if (kstrtobool(buf, &state))
		return -EINVAL;

	if (check_bridge_tph_is_support(rdma_dev)) {
		pci_dev_set_tph_request_cap(rdma_dev, state);
		rdma_dev->roce_enable_tph = state;
	} else {
		DRV_RDMA_LOG_DEV_WARN("upstream rp not support tph comp.\n");
	}

	return count;
}

CONFIGFS_ATTR(, kernel_llwqe_mode);
CONFIGFS_ATTR(, roce_timely_enable);
CONFIGFS_ATTR(, roce_dcqcn_enable);
CONFIGFS_ATTR(, ceq_intrl);
CONFIGFS_ATTR(, roce_rtomin);
CONFIGFS_ATTR(, roce_rd_fence_rate);
CONFIGFS_ATTR(, roce_enable_tph);

static struct configfs_attribute *sxe2_roce_vsi_attrs_pf[] = {
	&attr_kernel_llwqe_mode,
	&attr_roce_timely_enable,
	&attr_roce_dcqcn_enable,
	&attr_ceq_intrl,
	&attr_roce_rtomin,
	&attr_roce_rd_fence_rate,
	&attr_roce_enable_tph,
	NULL,
};

static struct configfs_attribute *sxe2_roce_vsi_attrs_vf[] = {
	&attr_kernel_llwqe_mode,  &attr_roce_timely_enable,
	&attr_roce_dcqcn_enable,  &attr_roce_rtomin,
	&attr_roce_rd_fence_rate, &attr_roce_enable_tph, NULL,
};

static void sxe2_release_vsi_grp(struct config_item *item)
{
	struct config_group *group =
		container_of(item, struct config_group, cg_item);
	struct sxe2_vsi_grp *vsi_grp =
		container_of(group, struct sxe2_vsi_grp, group);

	kfree(vsi_grp);
}

static struct configfs_item_operations sxe2_vsi_ops = {
	.release = sxe2_release_vsi_grp
};

static struct config_item_type sxe2_roce_vsi_type_pf = {
	.ct_attrs    = sxe2_roce_vsi_attrs_pf,
	.ct_item_ops = &sxe2_vsi_ops,
	.ct_owner    = THIS_MODULE,
};

static struct config_item_type sxe2_roce_vsi_type_vf = {
	.ct_attrs    = sxe2_roce_vsi_attrs_vf,
	.ct_item_ops = &sxe2_vsi_ops,
	.ct_owner    = THIS_MODULE,
};

static struct config_group *sxe2_vsi_make_group(struct config_group *group,
						const char *name)
{
	struct sxe2_vsi_grp *vsi_grp;
	struct sxe2_rdma_device *dev;
	u8 hw_ver;

	dev = sxe2_find_device_by_name(name);
	if (!dev)
		return ERR_PTR(-ENODEV);

	hw_ver = dev->rdma_func->ctx_dev.hw_attrs.uk_attrs.hw_rev;

	vsi_grp = kzalloc(sizeof(*vsi_grp), GFP_KERNEL);
	if (!vsi_grp)
		return ERR_PTR(-ENOMEM);

	vsi_grp->dev = dev;

	config_group_init(&vsi_grp->group);
	if (dev->rdma_func->ctx_dev.privileged) {
		config_group_init_type_name(&vsi_grp->group, name,
					    &sxe2_roce_vsi_type_pf);
	} else {
		config_group_init_type_name(&vsi_grp->group, name,
					    &sxe2_roce_vsi_type_vf);
	}

	return &vsi_grp->group;
}

static struct configfs_group_operations sxe2_vsi_group_ops = {
	.make_group = sxe2_vsi_make_group,
};

static struct config_item_type sxe2_subsys_type = {
	.ct_group_ops = &sxe2_vsi_group_ops,
	.ct_owner     = THIS_MODULE,
};

static struct configfs_subsystem cfs_subsys = {
	.su_group = {
		.cg_item = {
			.ci_namebuf = "sxe2rdma",
			.ci_type = &sxe2_subsys_type,
		},
	},
};

int sxe2_configfs_init(void)
{
	int ret;

	config_group_init(&cfs_subsys.su_group);
	mutex_init(&cfs_subsys.su_mutex);
	ret = configfs_register_subsystem(&cfs_subsys);
	if (ret)
		goto end;

	sxe2rdma_group = &cfs_subsys.su_group;
end:
	return ret;
}

void sxe2_configfs_exit(void)
{
	configfs_unregister_subsystem(&cfs_subsys);
	mutex_destroy(&cfs_subsys.su_mutex);
	sxe2rdma_group = NULL;
}

int sxe2_rdma_create_configfs_subdir(const char *name, struct sxe2_rdma_device *dev)
{
	int ret = 0;
	struct sxe2_vsi_grp *vsi_grp;

	if (!name || !*name) {
		DRV_RDMA_LOG_ERROR("Invalid directory name\n");
		ret = -EINVAL;
		goto end;
	}

	if (!sxe2rdma_group) {
		DRV_RDMA_LOG_ERROR("Parent directory not initialized\n");
		ret = -ENODEV;
		goto end;
	}

	vsi_grp = kzalloc(sizeof(*vsi_grp), GFP_KERNEL);
	if (!vsi_grp) {
		ret = -ENOMEM;
		goto end;
	}

	vsi_grp->dev = dev;
	config_group_init(&vsi_grp->group);

	if (dev->rdma_func->ctx_dev.privileged) {
		config_group_init_type_name(&vsi_grp->group, name,
									&sxe2_roce_vsi_type_pf);
	} else {
		config_group_init_type_name(&vsi_grp->group, name,
									&sxe2_roce_vsi_type_vf);
	}

	ret = configfs_register_group(sxe2rdma_group, &vsi_grp->group);
	if (ret) {
		DRV_RDMA_LOG_ERROR("Failed to create dir %s: %d\n", name, ret);
		kfree(vsi_grp);
	}
end:
	return ret;
}

void sxe2_rdma_remove_configfs_subdir(const char *name)
{
	struct config_group *parent_group = sxe2rdma_group;
	struct sxe2_vsi_grp *vsi_grp = NULL;
	struct config_item *item;
	struct config_item *tmp;

	if (!parent_group || !name || !*name) {
		DRV_RDMA_LOG_ERROR("Invalid parameters\n");
		return;
	}

	mutex_lock(&cfs_subsys.su_mutex);
	list_for_each_entry_safe(item, tmp, &parent_group->cg_children, ci_entry) {
		if (!item) {
			DRV_RDMA_LOG_WARN("NULL item encountered in list\n");
			continue;
		}

		if (strcmp(config_item_name(item), name) == 0) {
			vsi_grp = container_of(to_config_group(item), struct sxe2_vsi_grp, group);
			break;
		}
	}
	mutex_unlock(&cfs_subsys.su_mutex);

	if (vsi_grp) {
		configfs_unregister_group(&vsi_grp->group);
		kfree(vsi_grp);

		DRV_RDMA_LOG_INFO("Removed directory: %s\n", name);
	} else {
		DRV_RDMA_LOG_ERROR("Directory %s not found\n", name);
	}

}
#endif
