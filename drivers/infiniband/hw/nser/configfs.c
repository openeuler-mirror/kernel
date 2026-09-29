// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
/* Copyright (c) 2018 - 2025 Beijing WangXun Technology Co., Ltd. */
#include <linux/configfs.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include "main.h"

#if IS_ENABLED(CONFIG_CONFIGFS_FS)
enum nser_configfs_attr_type {
	NSER_ATTR_IW_DCTCP,
	NSER_ATTR_IW_TIMELY,
	NSER_ATTR_ROCE_ECN,
	NSER_ATTR_ROCE_TIMELY,
	NSER_ATTR_ROCE_DCQCN,
	NSER_ATTR_ROCE_DCTCP,
	NSER_ATTR_ROCE_ENABLE,
	NSER_ATTR_IW_OOO,
	NSER_ATTR_ROCE_NO_ICRC,
	NSER_ATTR_ENABLE_UP_MAP,
	NSER_ATTR_CNP_DSCP_PRIO,
};

struct nser_vsi_grp {
	struct config_group group;
	struct nser_device *iwdev;
};

/**
 * nser_find_device_by_name - find a vsi device given a name
 * @name: name of iwdev
 */
static struct nser_device *nser_find_device_by_name(const char *name)
{
	struct nser_handler *hdl;
	struct nser_device *iwdev;
	unsigned long flags;

	spin_lock_irqsave(&nser_handler_lock, flags);
	list_for_each_entry(hdl, &nser_handlers, list) {
		iwdev = hdl->iwdev;
		if (!strcmp(name, iwdev->ibdev.name)) {
			spin_unlock_irqrestore(&nser_handler_lock, flags);
			return iwdev;
		}
	}
	spin_unlock_irqrestore(&nser_handler_lock, flags);

	return NULL;
}

/*
 * nser_configfs_set_vsi_attr - set vsi configfs attribute
 * @item_name: config item name
 * @buf: buffer
 * @nser_configfs_type_attr: vsi attribute type to set
 */
static int nser_configfs_set_vsi_attr(struct config_item *item,
				      const char *buf,
				      enum nser_configfs_attr_type attr_type)
{
	struct nser_vsi_grp *grp = container_of(to_config_group(item),
						 struct nser_vsi_grp,
						 group);

	struct nser_device *iwdev = grp->iwdev;
	struct nser_up_info up_map_info = {};
	struct nser_cnp_info cnp_info = {};
	bool enable;
	int ret = 0;

	if (kstrtobool(buf, &enable)) {
		ret = -EINVAL;
		goto done;
	}

	switch (attr_type) {
	case NSER_ATTR_ENABLE_UP_MAP:
		iwdev->up_map_en = enable;
		if (enable) {
			*((u64 *)up_map_info.map) = iwdev->up_up_map;
			up_map_info.use_cnp_up_override = true;
			up_map_info.cnp_up_override = iwdev->cnp_up_override;
		} else {
			*((u64 *)up_map_info.map) = NSER_DEFAULT_UP_UP_MAP;
			up_map_info.use_cnp_up_override = false;
		}
		up_map_info.hmc_fcn_idx = iwdev->rf->sc_dev.hmc_fn_id;
		nser_cqp_up_map_cmd(&iwdev->rf->sc_dev, NSER_OP_SET_UP_MAP, &up_map_info);
		break;
	case NSER_ATTR_CNP_DSCP_PRIO:
		iwdev->cnp_en = enable;
		if (enable) {
			cnp_info.cnp_802p_prio = iwdev->cnp_802p_prio;
			cnp_info.cnp_dscp = iwdev->cnp_dscp;
			nser_cqp_cnp_cmd(&iwdev->rf->sc_dev, NSER_OP_SET_CNP, &cnp_info);
		}
		break;
	case NSER_ATTR_ROCE_NO_ICRC:
		iwdev->roce_no_icrc_en = enable;
		break;
	case NSER_ATTR_ROCE_TIMELY:
		iwdev->roce_timely_en = enable;
		break;
	case NSER_ATTR_ROCE_DCQCN:
		iwdev->roce_dcqcn_en = enable;
		break;
	case NSER_ATTR_ROCE_ECN:
		iwdev->roce_ecn_en = enable;
		break;
	case NSER_ATTR_ROCE_ENABLE:
		//rf->roce_en = enable; FIXME: Add when roce/iwarp in configFS
		break;
	default:
		ret = -EINVAL;
	}

done:
	return ret;
}

/**
 * roce_cwnd_show - Show the value of RoCE cwnd
 * @item: config item
 * @buf: buffer to write to
 */
static ssize_t roce_cwnd_show(struct config_item *item, char *buf)
{
	struct nser_vsi_grp *grp = container_of(to_config_group(item),
						 struct nser_vsi_grp,
						 group);

	struct nser_device *iwdev = grp->iwdev;
	ssize_t ret;

	ret = sprintf(buf, "%d\n", iwdev->roce_cwnd);

	return ret;
}

/**
 * roce_cwnd_store - Store value for roce_cwnd
 * @item: config item
 * @buf: buf to read from
 * @count: size of buf
 */
static ssize_t roce_cwnd_store(struct config_item *item,
			       const char *buf,
			       size_t count)
{
	struct nser_vsi_grp *grp = container_of(to_config_group(item),
						 struct nser_vsi_grp,
						 group);

	struct nser_device *iwdev = grp->iwdev;
	u32 rsrc_cwnd;

	if (kstrtou32(buf, 0, &rsrc_cwnd))
		return -EINVAL;

	if (!rsrc_cwnd || rsrc_cwnd > 0x400)
		return -EINVAL;

	iwdev->roce_cwnd = rsrc_cwnd;
	iwdev->override_cwnd = true;

	return count;
}

/*
 * roce_rd_fence_rate_show - Show RoCE read fence rate
 * @item: config item
 * @buf: buffer to write to
 */
static ssize_t roce_rd_fence_rate_show(struct config_item *item, char *buf)
{
	struct nser_vsi_grp *grp = container_of(to_config_group(item),
						 struct nser_vsi_grp,
						 group);

	struct nser_device *iwdev = grp->iwdev;
	ssize_t ret;

	ret = sprintf(buf, "%d\n", iwdev->rd_fence_rate);

	return ret;
}

/**
 * roce_rd_fence_rate_store - Store RoCE read fence rate
 * @item: config item
 * @buf: buf to read from
 * @count: size of buf
 */
static ssize_t roce_rd_fence_rate_store(struct config_item *item,
					const char *buf, size_t count)
{
	struct nser_vsi_grp *grp = container_of(to_config_group(item),
						 struct nser_vsi_grp,
						 group);

	struct nser_device *iwdev = grp->iwdev;
	u32 rd_fence_rate;

	if (kstrtou32(buf, 0, &rd_fence_rate))
		return -EINVAL;

	if (rd_fence_rate > 256)
		return -EINVAL;

	iwdev->rd_fence_rate = rd_fence_rate;
	iwdev->override_rd_fence_rate = true;

	return count;
}

/*
 * cnp_dscp_show - Show cnp dscp value for ipv6
 * @item: config item
 * @buf: buffer to write to
 */
static ssize_t cnp_dscp_show(struct config_item *item, char *buf)
{
	struct nser_vsi_grp *grp = container_of(to_config_group(item),
						 struct nser_vsi_grp,
						 group);

	struct nser_device *iwdev = grp->iwdev;
	ssize_t ret;

	ret = sprintf(buf, "%d\n", iwdev->cnp_dscp);

	return ret;
}

/**
 * cnp_dscp_store - Store cnp dscp value for ipv6
 * @item: config item
 * @buf: buf to read from
 * @count: size of buf
 */
static ssize_t cnp_dscp_store(struct config_item *item, const char *buf, size_t count)
{
	struct nser_vsi_grp *grp = container_of(to_config_group(item),
						 struct nser_vsi_grp,
						 group);

	struct nser_device *iwdev = grp->iwdev;
	u8 cnp_dscp;

	if (kstrtou8(buf, 0, &cnp_dscp))
		return -EINVAL;

	if (cnp_dscp > 64)
		return -EINVAL;

	iwdev->cnp_dscp = cnp_dscp;

	return count;
}

/*
 * cnp_802p_prio_show - Show cnp 802p prio for ipv4
 * @item: config item
 * @buf: buffer to write to
 */
static ssize_t cnp_802p_prio_show(struct config_item *item, char *buf)
{
	struct nser_vsi_grp *grp = container_of(to_config_group(item),
						 struct nser_vsi_grp,
						 group);

	struct nser_device *iwdev = grp->iwdev;
	ssize_t ret;

	ret = sprintf(buf, "%d\n", iwdev->cnp_802p_prio);

	return ret;
}

/**
 * cnp_802p_prio_store - Store cnp 802p prio for ipv4
 * @item: config item
 * @buf: buf to read from
 * @count: size of buf
 */
static ssize_t cnp_802p_prio_store(struct config_item *item, const char *buf, size_t count)
{
	struct nser_vsi_grp *grp = container_of(to_config_group(item),
						 struct nser_vsi_grp,
						 group);

	struct nser_device *iwdev = grp->iwdev;
	u8 cnp_802p_prio;

	if (kstrtou8(buf, 0, &cnp_802p_prio))
		return -EINVAL;

	if (cnp_802p_prio > 7)
		return -EINVAL;

	iwdev->cnp_802p_prio = cnp_802p_prio;

	return count;
}

/**
 * cnp_enable_store - Store cnp priority setting enabling or not
 * @item: config item
 * @buf: buf to read from
 * @count: size of buf
 */
static ssize_t cnp_enable_store(struct config_item *item, const char *buf, size_t count)
{
	int ret;

	ret = nser_configfs_set_vsi_attr(item, buf, NSER_ATTR_CNP_DSCP_PRIO);
	if (ret)
		return ret;

	return count;
}

/**
 * cnp_enable_show - Show cnp priority setting enabling or not
 * @item: config item
 * @buf: buffer to write to
 */
static ssize_t cnp_enable_show(struct config_item *item, char *buf)
{
	struct nser_vsi_grp *grp = container_of(to_config_group(item),
						 struct nser_vsi_grp,
						 group);

	struct nser_device *iwdev = grp->iwdev;
	ssize_t ret;

	ret = sprintf(buf, "%d\n", iwdev->cnp_en);

	return ret;
}

/**
 * roce_ackcreds_show - Show the value of RoCE ack_creds
 * @item: config item
 * @buf: buffer to write to
 */
static ssize_t roce_ackcreds_show(struct config_item *item, char *buf)
{
	struct nser_vsi_grp *grp = container_of(to_config_group(item),
						 struct nser_vsi_grp,
						 group);

	struct nser_device *iwdev = grp->iwdev;
	ssize_t ret;

	ret = sprintf(buf, "%d\n", iwdev->roce_ackcreds);

	return ret;
}

/**
 * roce_ackcreds_store - Store value for roce_ackcreds
 * @item: config item
 * @buf: buf to read from
 * @count: size of buf
 */
static ssize_t roce_ackcreds_store(struct config_item *item, const char *buf, size_t count)
{
	struct nser_vsi_grp *grp = container_of(to_config_group(item),
						 struct nser_vsi_grp,
						 group);

	struct nser_device *iwdev = grp->iwdev;
	u32 rsrc_ackcreds;

	if (kstrtou32(buf, 0, &rsrc_ackcreds))
		return -EINVAL;

	if (!rsrc_ackcreds || rsrc_ackcreds > 0x1E)
		return -EINVAL;

	iwdev->roce_ackcreds = rsrc_ackcreds;
	iwdev->override_ackcreds = true;

	return count;
}

/**
 * cnp_up_override_store - Store value for CNP override
 * @item: config item
 * @buf: buf to read from
 * @count: size of buf
 */
static ssize_t cnp_up_override_store(struct config_item *item,
				     const char *buf,
				     size_t count)
{
	struct nser_vsi_grp *grp = container_of(to_config_group(item),
						 struct nser_vsi_grp,
						 group);

	struct nser_device *iwdev = grp->iwdev;
	u8 cnp_override;

	if (kstrtou8(buf, 0, &cnp_override))
		return -EINVAL;

	if (cnp_override > 0x3F)
		return -EINVAL;

	iwdev->cnp_up_override = cnp_override;

	return count;
}

/**
 * cnp_up_override_show - Show value of CNP UP override
 * @item: config item
 * @buf: buffer to write to
 */
static ssize_t cnp_up_override_show(struct config_item *item, char *buf)
{
	struct nser_vsi_grp *grp = container_of(to_config_group(item),
						 struct nser_vsi_grp,
						 group);

	struct nser_device *iwdev = grp->iwdev;
	ssize_t ret;

	ret = sprintf(buf, "%d\n", iwdev->cnp_up_override);

	return ret;
}

/**
 * up_up_map_store - Store value for UP-UP map
 * @item: config item
 * @buf: buf to read from
 * @count: size of buf
 */
static ssize_t up_up_map_store(struct config_item *item,
			       const char *buf,
			       size_t count)
{
	struct nser_vsi_grp *grp = container_of(to_config_group(item),
						 struct nser_vsi_grp,
						 group);

	struct nser_device *iwdev = grp->iwdev;
	u64 up_map;

	if (kstrtou64(buf, 0, &up_map))
		return -EINVAL;

	iwdev->up_up_map = up_map;
	return count;
}

/**
 * up_up_map_show - Show value of IP-UP map
 * @item: config item
 * @buf: buffer to write to
 */
static ssize_t up_up_map_show(struct config_item *item, char *buf)
{
	struct nser_vsi_grp *grp = container_of(to_config_group(item),
						 struct nser_vsi_grp,
						 group);

	struct nser_device *iwdev = grp->iwdev;
	ssize_t ret;

	ret = sprintf(buf, "0x%llx\n", iwdev->up_up_map);

	return ret;
}

/**
 * roce_timely_enable_show - Show value of roce_timely_enable for vsi
 * @item: config item
 * @buf: buffer to write to
 */
static ssize_t roce_timely_enable_show(struct config_item *item, char *buf)
{
	struct nser_vsi_grp *grp = container_of(to_config_group(item),
						 struct nser_vsi_grp,
						 group);

	struct nser_device *iwdev = grp->iwdev;
	ssize_t ret;

	ret = sprintf(buf, "%d\n", iwdev->roce_timely_en);

	return ret;
}

/**
 * roce_timely_enable_store - Store value of roce_timely_enable for vsi
 * @item: config item
 * @buf: buf to read from
 * @count: size of buf
 */
static ssize_t roce_timely_enable_store(struct config_item *item,
					const char *buf,
					size_t count)
{
	int ret;

	ret = nser_configfs_set_vsi_attr(item, buf, NSER_ATTR_ROCE_TIMELY);
	if (ret)
		return ret;

	return count;
}

/**
 * roce_no_icrc_enable_show - Show value of no_icrc for vsi
 * @item: config item
 * @buf: buffer to write to
 */
static ssize_t roce_no_icrc_enable_show(struct config_item *item, char *buf)
{
	struct nser_vsi_grp *grp = container_of(to_config_group(item),
						 struct nser_vsi_grp,
						 group);

	struct nser_device *iwdev = grp->iwdev;
	ssize_t ret;

	ret = sprintf(buf, "%d\n", iwdev->roce_no_icrc_en);

	return ret;
}

/**
 * roce_no_icrc_enable_store - Store value of roce_no_icrc for vsi
 * @item: config item
 * @buf: buf to read from
 * @count: size of buf
 */
static ssize_t roce_no_icrc_enable_store(struct config_item *item,
					 const char *buf,
					 size_t count)
{
	int ret;

	ret = nser_configfs_set_vsi_attr(item, buf, NSER_ATTR_ROCE_NO_ICRC);
	if (ret)
		return ret;

	return count;
}

/**
 * up_map_enable_show - Show value of up_map_enable for PF
 * @item: config item
 * @buf: buffer to write to
 */
static ssize_t up_map_enable_show(struct config_item *item, char *buf)
{
	struct nser_vsi_grp *grp = container_of(to_config_group(item),
						 struct nser_vsi_grp,
						 group);

	struct nser_device *iwdev = grp->iwdev;
	ssize_t ret;

	ret = sprintf(buf, "%d\n", iwdev->up_map_en);

	return ret;
}

/**
 * up_map_enable_store - Store value of up_map_enable for PF
 * @item: config item
 * @buf: buf to read from
 * @count: size of buf
 */
static ssize_t up_map_enable_store(struct config_item *item,
				   const char *buf,
				   size_t count)
{
	int ret;

	ret = nser_configfs_set_vsi_attr(item, buf, NSER_ATTR_ENABLE_UP_MAP);
	if (ret)
		return ret;

	return count;
}

/**
 * roce_dcqcn_enable_show - Show the value of roce_dcqcn_enable for vsi
 * @item: config item
 * @buf: buffer to write to
 */
static ssize_t roce_dcqcn_enable_show(struct config_item *item, char *buf)
{
	struct nser_vsi_grp *grp = container_of(to_config_group(item),
						 struct nser_vsi_grp,
						 group);
	struct nser_device *iwdev = grp->iwdev;
	ssize_t ret;

	ret = sprintf(buf, "%d\n", iwdev->roce_dcqcn_en);

	return ret;
}

/**
 * roce_dcqcn_enable_store - Store value of roce_dcqcn_enable for vsi
 * @item: config item
 * @buf: buf to read from
 * @count: size of buf
 */
static ssize_t roce_dcqcn_enable_store(struct config_item *item,
				       const char *buf,
				       size_t count)
{
	int ret;

	ret = nser_configfs_set_vsi_attr(item, buf, NSER_ATTR_ROCE_DCQCN);
	if (ret)
		return ret;

	return count;
}

/* roce_ecn_enable_show - Show the value of roce_ecn_enable for vsi
 * @item: config item
 * @buf: buffer to write to
 */
static ssize_t roce_ecn_enable_show(struct config_item *item, char *buf)
{
	struct nser_vsi_grp *grp = container_of(to_config_group(item),
						 struct nser_vsi_grp,
						 group);
	struct nser_device *iwdev = grp->iwdev;
	ssize_t ret;

	ret = sprintf(buf, "%d\n", iwdev->roce_ecn_en);

	return ret;
}

/**
 * roce_ecn_enable_store - Store value of roce_ecn_enable for vsi
 * @item: config item
 * @buf: buf to read from
 * @count: size of buf
 */
static ssize_t roce_ecn_enable_store(struct config_item *item, const char *buf, size_t count)
{
	int ret;

	ret = nser_configfs_set_vsi_attr(item, buf, NSER_ATTR_ROCE_ECN);
	if (ret)
		return ret;

	return count;
}

CONFIGFS_ATTR(, up_map_enable);
CONFIGFS_ATTR(, cnp_up_override);
CONFIGFS_ATTR(, up_up_map);
CONFIGFS_ATTR(, roce_timely_enable);
CONFIGFS_ATTR(, roce_no_icrc_enable);
CONFIGFS_ATTR(, roce_dcqcn_enable);
CONFIGFS_ATTR(, roce_ecn_enable);
CONFIGFS_ATTR(, roce_cwnd);
CONFIGFS_ATTR(, roce_rd_fence_rate);
CONFIGFS_ATTR(, roce_ackcreds);
CONFIGFS_ATTR(, cnp_802p_prio);
CONFIGFS_ATTR(, cnp_dscp);
CONFIGFS_ATTR(, cnp_enable);

static struct configfs_attribute *nser_roce_vsi_attrs[] = {
	&attr_roce_cwnd,
	&attr_roce_rd_fence_rate,
	&attr_roce_ackcreds,
	&attr_roce_timely_enable,
	&attr_roce_no_icrc_enable,
	&attr_roce_dcqcn_enable,
	&attr_roce_ecn_enable,
	&attr_cnp_up_override,
	&attr_up_map_enable,
	&attr_up_up_map,
	&attr_cnp_dscp,
	&attr_cnp_802p_prio,
	&attr_cnp_enable,
	NULL,
};

static void nser_release_vsi_grp(struct config_item *item)
{
	struct config_group *group = container_of(item, struct config_group,
						  cg_item);
	struct nser_vsi_grp *vsi_grp = container_of(group,
						     struct nser_vsi_grp,
						     group);

	kfree(vsi_grp);
}

static struct configfs_item_operations nser_vsi_ops = {
	.release = nser_release_vsi_grp
};

static struct config_item_type nser_roce_vsi_type = {
	.ct_attrs = nser_roce_vsi_attrs,
	.ct_item_ops = &nser_vsi_ops,
	.ct_owner = THIS_MODULE,
};

/**
 * nser_vsi_make_group - Creation of subsystem groups
 * @group: config group
 * @name: name of the group
 */
static struct config_group *nser_vsi_make_group(struct config_group *group, const char *name)
{
	struct nser_vsi_grp *vsi_grp;
	struct nser_device *iwdev;

	iwdev = nser_find_device_by_name(name);
	if (!iwdev)
		return ERR_PTR(-ENODEV);

	vsi_grp = kzalloc(sizeof(*vsi_grp), GFP_KERNEL);
	if (!vsi_grp)
		return ERR_PTR(-ENOMEM);

	vsi_grp->iwdev = iwdev;

	config_group_init(&vsi_grp->group);
	config_group_init_type_name(&vsi_grp->group, name, &nser_roce_vsi_type);

	return &vsi_grp->group;
}

static struct configfs_group_operations nser_vsi_group_ops = {
	.make_group = nser_vsi_make_group,
};

static struct config_item_type nser_subsys_type = {
	.ct_group_ops = &nser_vsi_group_ops,
	.ct_owner = THIS_MODULE,
};

static struct configfs_subsystem cfs_subsys = {
	.su_group = {
		.cg_item = {
			.ci_namebuf = "nser",
			.ci_type = &nser_subsys_type,
		},
	},
};

int nser_configfs_init(void)
{
	config_group_init(&cfs_subsys.su_group);
	mutex_init(&cfs_subsys.su_mutex);
	return configfs_register_subsystem(&cfs_subsys);
}

void nser_configfs_exit(void)
{
	configfs_unregister_subsystem(&cfs_subsys);
}
#endif /* CONFIG_CONFIGFS_FS */
