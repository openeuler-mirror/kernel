// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include <linux/pci.h>
#include <linux/sysfs.h>
#include <linux/etherdevice.h>
#include "common/xsc_core.h"
#include "common/vport.h"
#ifdef CONFIG_XSC_ESWITCH
#include "eswitch.h"
#endif

struct vf_attributes {
	struct attribute attr;
	ssize_t (*show)(struct xsc_sriov_vf *vf, struct vf_attributes *attr,
			char *buf);
	ssize_t (*store)(struct xsc_sriov_vf *vf, struct vf_attributes *attr,
			 const char *buf, size_t count);
};

static ssize_t vf_attr_show(struct kobject *kobj,
			    struct attribute *attr, char *buf)
{
	struct vf_attributes *ga =
		container_of(attr, struct vf_attributes, attr);
	struct xsc_sriov_vf *g = container_of(kobj, struct xsc_sriov_vf, kobj);

	if (!ga->show)
		return -EIO;

	return ga->show(g, ga, buf);
}

static ssize_t vf_attr_store(struct kobject *kobj,
			     struct attribute *attr,
			     const char *buf, size_t size)
{
	struct vf_attributes *ga =
		container_of(attr, struct vf_attributes, attr);
	struct xsc_sriov_vf *g = container_of(kobj, struct xsc_sriov_vf, kobj);

	if (!ga->store)
		return -EIO;

	return ga->store(g, ga, buf, size);
}

struct vf_group_attributes {
	struct attribute attr;
	ssize_t (*show)(struct xsc_vgroup *g, struct vf_group_attributes *attr,
			char *buf);
	ssize_t (*store)(struct xsc_vgroup *g, struct vf_group_attributes *attr,
			 const char *buf, size_t count);
};

static ssize_t vf_group_attr_show(struct kobject *kobj,
				  struct attribute *attr, char *buf)
{
	struct vf_group_attributes *ga =
		container_of(attr, struct vf_group_attributes, attr);
	struct xsc_vgroup *g = container_of(kobj, struct xsc_vgroup, kobj);

	if (!ga->show)
		return -EIO;

	return ga->show(g, ga, buf);
}

static ssize_t vf_group_attr_store(struct kobject *kobj,
				   struct attribute *attr,
				   const char *buf, size_t size)
{
	struct vf_group_attributes *ga =
		container_of(attr, struct vf_group_attributes, attr);
	struct xsc_vgroup *g = container_of(kobj, struct xsc_vgroup, kobj);

	if (!ga->store)
		return -EIO;

	return ga->store(g, ga, buf, size);
}

static ssize_t port_show(struct xsc_sriov_vf *g, struct vf_attributes *oa,
			 char *buf)
{
	struct xsc_core_device *dev = g->dev;
	union ib_gid gid;
	int err;
	u8 *p;

	err = xsc_query_hca_vport_gid(dev, 1, 1, g->vf, 0, &gid);
	if (err) {
		xsc_core_warn(dev, "failed to query gid at index 0 for vf %d\n", g->vf);
		return err;
	}

	p = &gid.raw[8];
	err = sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
		      p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);
	return err;
}

static ssize_t port_store(struct xsc_sriov_vf *g, struct vf_attributes *oa,
			  const char *buf, size_t count)
{
	struct xsc_core_device *dev = g->dev;
	struct xsc_vf_context *vfs_ctx = dev->priv.sriov.vfs_ctx;
	struct xsc_hca_vport_context *in;
	u64 guid = 0;
	int err;
	int tmp[8];
	int i;

	err = sscanf(buf, "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
		     &tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4], &tmp[5], &tmp[6], &tmp[7]);
	if (err != 8)
		return -EINVAL;

	for (i = 0; i < 8; i++)
		guid += ((u64)tmp[i] << ((7 - i) * 8));

	in = kzalloc(sizeof(*in), GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	in->field_select = XSC_HCA_VPORT_SEL_PORT_GUID;
	in->port_guid = guid;
	err = xsc_modify_hca_vport_context(dev, 1, 1, g->vf + 1, in);
	kfree(in);
	if (err)
		return err;

	vfs_ctx[g->vf].port_guid = guid;

	return count;
}

static int show_nic_node_guid(struct xsc_core_device *dev, u16 vf,
			      __be64 *node_guid)
{
	int err;

	err = xsc_query_nic_vport_node_guid(dev, vf + 1, node_guid);
	if (!err)
		*node_guid = cpu_to_be64(*node_guid);

	return err;
}

static ssize_t node_show(struct xsc_sriov_vf *g, struct vf_attributes *oa,
			 char *buf)
{
	struct xsc_core_device *dev = g->dev;
	__be64 guid;

	int err;
	u8 *p;

	err = show_nic_node_guid(dev, g->vf, &guid);
	if (err) {
		xsc_core_warn(dev, "failed to query node guid for vf %d (%d)\n",
			      g->vf, err);
		return err;
	}

	p = (u8 *)&guid;
	err = sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
		      p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);

	return err;
}

static int modify_nic_node_guid(struct xsc_core_device *dev, u16 vf,
				u64 node_guid)
{
	return xsc_modify_other_nic_vport_node_guid(dev, vf + 1, node_guid);
}

static ssize_t node_store(struct xsc_sriov_vf *g, struct vf_attributes *oa,
			  const char *buf, size_t count)
{
	struct xsc_core_device *dev = g->dev;
	u64 guid = 0;
	int err;
	int tmp[8];
	int i;

	err = sscanf(buf, "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
		     &tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4], &tmp[5], &tmp[6], &tmp[7]);
	if (err != 8)
		return -EINVAL;

	for (i = 0; i < 8; i++)
		guid += ((u64)tmp[i] << ((7 - i) * 8));

	err = modify_nic_node_guid(dev, g->vf, guid);
	if (err) {
		xsc_core_warn(dev, "failed to modify node guid for vf %d (%d)\n",
			      g->vf, err);
		return err;
	}

	return count;
}

static const char *policy_str(enum port_state_policy policy)
{
	switch (policy) {
	case XSC_POLICY_DOWN:		return "Down\n";
	case XSC_POLICY_UP:		return "Up\n";
	case XSC_POLICY_FOLLOW:		return "Follow\n";
	default:			return "Invalid policy\n";
	}
}

static ssize_t policy_show(struct xsc_sriov_vf *g, struct vf_attributes *oa,
			   char *buf)
{
	struct xsc_core_device *dev = g->dev;
	struct xsc_hca_vport_context *rep;
	const char *p = NULL;
	int err;

	rep = kzalloc(sizeof(*rep), GFP_KERNEL);
	if (!rep)
		return -ENOMEM;

	err = xsc_query_hca_vport_context(dev, 1, 1,  g->vf, rep);
	if (err) {
		xsc_core_warn(dev, "failed to query port policy for vf %d (%d)\n",
			      g->vf, err);
		goto free;
	}
	p = policy_str(rep->vport_state_policy);
	strscpy(buf, p, strlen(p));

free:
	kfree(rep);
	return p ? strlen(p) : err;
}

static int strpolicy(const char *buf, enum port_state_policy *policy)
{
	if (sysfs_streq(buf, "Down")) {
		*policy = XSC_POLICY_DOWN;
		return 0;
	}

	if (sysfs_streq(buf, "Up")) {
		*policy = XSC_POLICY_UP;
		return 0;
	}

	if (sysfs_streq(buf, "Follow")) {
		*policy = XSC_POLICY_FOLLOW;
		return 0;
	}
	return -EINVAL;
}

static ssize_t policy_store(struct xsc_sriov_vf *g, struct vf_attributes *oa,
			    const char *buf, size_t count)
{
	struct xsc_core_device *dev = g->dev;
	struct xsc_vf_context *vfs_ctx = dev->priv.sriov.vfs_ctx;
	struct xsc_hca_vport_context *in;
	enum port_state_policy policy;
	int err;

	err = strpolicy(buf, &policy);
	if (err)
		return err;

	in = kzalloc(sizeof(*in), GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	in->vport_state_policy = policy;
	in->field_select = XSC_HCA_VPORT_SEL_STATE_POLICY;
	err = xsc_modify_hca_vport_context(dev, 1, 1, g->vf + 1, in);
	kfree(in);
	if (err)
		return err;

	vfs_ctx[g->vf].policy = policy;

	return count;
}

#ifdef CONFIG_XSC_ESWITCH
/* ETH SRIOV SYSFS */
static ssize_t mac_show(struct xsc_sriov_vf *g, struct vf_attributes *oa,
			char *buf)
{
	return sprintf(buf,
		       "usage: write <LLADDR|Random> to set VF Mac Address\n");
}

static ssize_t mac_store(struct xsc_sriov_vf *g, struct vf_attributes *oa,
			 const char *buf, size_t count)
{
	struct xsc_core_device *dev = g->dev;
	u8 mac[ETH_ALEN];
	int err;

	err = sscanf(buf, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		     &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
	if (err == 6)
		goto set_mac;

	if (sysfs_streq(buf, "Random"))
		eth_random_addr(mac);
	else
		return -EINVAL;

set_mac:
	err = xsc_eswitch_set_vport_mac(dev->priv.eswitch, g->vf + 1, mac);
	return err ? err : count;
}

static ssize_t vlan_show(struct xsc_sriov_vf *g, struct vf_attributes *oa,
			 char *buf)
{
	return sprintf(buf, "<Vlan:Qos[:Proto]>: set VF Vlan, Qos, Vlan Proto(default 802.1Q)\n");
}

static ssize_t vlan_store(struct xsc_sriov_vf *g, struct vf_attributes *oa,
			  const char *buf, size_t count)
{
	struct xsc_core_device *dev = g->dev;
	char vproto_ext[5] = {'\0'};
	__be16 vlan_proto;
	u16 vlan_id;
	u8 qos;
	int err;

	err = sscanf(buf, "%hu:%hhu:802.%4s", &vlan_id, &qos, vproto_ext);
	if (err == 3) {
		if ((strcmp(vproto_ext, "1AD") == 0) ||
		    (strcmp(vproto_ext, "1ad") == 0))
			vlan_proto = htons(ETH_P_8021AD);
		else if ((strcmp(vproto_ext, "1Q") == 0) ||
			 (strcmp(vproto_ext, "1q") == 0))
			vlan_proto = htons(ETH_P_8021Q);
		else
			return -EINVAL;
	} else {
		err = sscanf(buf, "%hu:%hhu", &vlan_id, &qos);
		if (err != 2)
			return -EINVAL;
		vlan_proto = htons(ETH_P_8021Q);
	}

	err = xsc_eswitch_set_vport_vlan(dev->priv.eswitch, g->vf + 1,
					 vlan_id, qos, vlan_proto);
	return err ? err : count;
}

static const char *vlan_proto_str(u16 vlan, u8 qos, __be16 vlan_proto)
{
	if (!vlan && !qos)
		return "N/A";

	switch (vlan_proto) {
	case htons(ETH_P_8021AD):	return "802.1ad";
	case htons(ETH_P_8021Q):	return "802.1Q";
	default:			return "Invalid vlan protocol";
	}
}

static ssize_t spoofcheck_show(struct xsc_sriov_vf *g,
			       struct vf_attributes *oa,
			       char *buf)
{
	return sprintf(buf,
		       "usage: write <ON|OFF> to enable|disable VF SpoofCheck\n"
		       );
}

static ssize_t spoofcheck_store(struct xsc_sriov_vf *g,
				struct vf_attributes *oa,
				const char *buf,
				size_t count)
{
	struct xsc_core_device *dev = g->dev;
	bool settings;
	int err;

	if (sysfs_streq(buf, "ON"))
		settings = true;
	else if (sysfs_streq(buf, "OFF"))
		settings = false;
	else
		return -EINVAL;

	err = xsc_eswitch_set_vport_spoofchk(dev->priv.eswitch, g->vf + 1, settings);
	return err ? err : count;
}

static ssize_t trust_show(struct xsc_sriov_vf *g,
			  struct vf_attributes *oa,
			  char *buf)
{
	return sprintf(buf,
		       "usage: write <ON|OFF> to trust|untrust VF\n"
		       );
}

static ssize_t trust_store(struct xsc_sriov_vf *g,
			   struct vf_attributes *oa,
			   const char *buf,
			   size_t count)
{
	struct xsc_core_device *dev = g->dev;
	bool settings;
	int err;

	if (sysfs_streq(buf, "ON"))
		settings = true;
	else if (sysfs_streq(buf, "OFF"))
		settings = false;
	else
		return -EINVAL;

	err = xsc_eswitch_set_vport_trust(dev->priv.eswitch, g->vf + 1, settings);
	return err ? err : count;
}

static ssize_t link_state_show(struct xsc_sriov_vf *g,
			       struct vf_attributes *oa,
			       char *buf)
{
	return sprintf(buf, "usage: write <Up|Down|Follow> to set VF State\n");
}

static ssize_t link_state_store(struct xsc_sriov_vf *g,
				struct vf_attributes *oa,
				const char *buf,
				size_t count)
{
	struct xsc_core_device *dev = g->dev;
	enum port_state_policy policy;
	int err;

	err = strpolicy(buf, &policy);
	if (err)
		return err;

	err = xsc_eswitch_set_vport_state(dev->priv.eswitch, g->vf + 1, policy);
	return err ? err : count;
}

static ssize_t max_tx_rate_show(struct xsc_sriov_vf *g,
				struct vf_attributes *oa,
				char *buf)
{
	return sprintf(buf,
		       "usage: write <Rate (Mbit/s)> to set VF max rate\n");
}

static ssize_t max_tx_rate_store(struct xsc_sriov_vf *g,
				 struct vf_attributes *oa,
				 const char *buf, size_t count)
{
	struct xsc_core_device *dev = g->dev;
	struct xsc_eswitch *esw = dev->priv.eswitch;
	u32 max_tx_rate;
	u32 min_tx_rate;
	int err;

	mutex_lock(&esw->state_lock);
	min_tx_rate = esw->vports[g->vf + 1].info.min_rate;
	mutex_unlock(&esw->state_lock);

	err = kstrtouint(buf, 10, &max_tx_rate);
	if (err != 1)
		return -EINVAL;

	err = xsc_eswitch_set_vport_rate(dev->priv.eswitch, g->vf + 1,
					 max_tx_rate, min_tx_rate);
	return err ? err : count;
}

static ssize_t min_tx_rate_show(struct xsc_sriov_vf *g,
				struct vf_attributes *oa,
				char *buf)
{
	return sprintf(buf,
		       "usage: write <Rate (Mbit/s)> to set VF min rate\n");
}

static ssize_t min_tx_rate_store(struct xsc_sriov_vf *g,
				 struct vf_attributes *oa,
				 const char *buf, size_t count)
{
	struct xsc_core_device *dev = g->dev;
	struct xsc_eswitch *esw = dev->priv.eswitch;
	u32 min_tx_rate;
	u32 max_tx_rate;
	int err;

	mutex_lock(&esw->state_lock);
	max_tx_rate = esw->vports[g->vf + 1].info.max_rate;
	mutex_unlock(&esw->state_lock);

	err = kstrtouint(buf, 10, &min_tx_rate);
	if (err != 1)
		return -EINVAL;

	err = xsc_eswitch_set_vport_rate(dev->priv.eswitch, g->vf + 1,
					 max_tx_rate, min_tx_rate);
	return err ? err : count;
}

static ssize_t min_pf_tx_rate_show(struct xsc_sriov_vf *g,
				   struct vf_attributes *oa,
				   char *buf)
{
	return sprintf(buf, "usage: write <Rate (Mbit/s)> to set PF min rate\n");
}

static ssize_t min_pf_tx_rate_store(struct xsc_sriov_vf *g,
				    struct vf_attributes *oa,
				    const char *buf, size_t count)
{
	struct xsc_core_device *dev = g->dev;
	struct xsc_eswitch *esw = dev->priv.eswitch;
	u32 min_tx_rate;
	u32 max_tx_rate;
	int err;

	mutex_lock(&esw->state_lock);
	max_tx_rate = esw->vports[g->vf].info.max_rate;
	mutex_unlock(&esw->state_lock);

	err = kstrtouint(buf, 10, &min_tx_rate);
	if (err != 1)
		return -EINVAL;

	err = xsc_eswitch_set_vport_rate(dev->priv.eswitch, g->vf,
					 max_tx_rate, min_tx_rate);
	return err ? err : count;
}

static ssize_t group_show(struct xsc_sriov_vf *g,
			  struct vf_attributes *oa,
			  char *buf)
{
	return sprintf(buf,
		       "usage: write <Group 0-255> to set VF vport group\n");
}

static ssize_t group_store(struct xsc_sriov_vf *g,
			   struct vf_attributes *oa,
			   const char *buf, size_t count)
{
	struct xsc_core_device *dev = g->dev;
	struct xsc_eswitch *esw = dev->priv.eswitch;
	u32 group_id;
	int err;

	err = kstrtouint(buf, 10, &group_id);
	if (err != 1)
		return -EINVAL;

	if (group_id > 255)
		return -EINVAL;

	err = xsc_eswitch_vport_update_group(esw, g->vf + 1, group_id);

	return err ? err : count;
}

static ssize_t max_tx_rate_group_show(struct xsc_vgroup *g,
				      struct vf_group_attributes *oa,
				      char *buf)
{
	return sprintf(buf,
		       "usage: write <Rate (Mbps)> to set VF group max rate\n");
}

static ssize_t max_tx_rate_group_store(struct xsc_vgroup *g,
				       struct vf_group_attributes *oa,
				       const char *buf, size_t count)
{
	struct xsc_core_device *dev = g->dev;
	struct xsc_eswitch *esw = dev->priv.eswitch;
	u32 max_rate;
	int err;

	err = kstrtouint(buf, 10, &max_rate);
	if (err != 1)
		return -EINVAL;

	err = xsc_eswitch_set_vgroup_max_rate(esw, g->group_id, max_rate);

	return err ? err : count;
}

static ssize_t min_tx_rate_group_show(struct xsc_vgroup *g,
				      struct vf_group_attributes *oa,
				      char *buf)
{
	return sprintf(buf,
		       "usage: write <Rate (Mbit/s)> to set VF group min rate\n");
}

static ssize_t min_tx_rate_group_store(struct xsc_vgroup *g,
				       struct vf_group_attributes *oa,
				       const char *buf, size_t count)
{
	struct xsc_core_device *dev = g->dev;
	struct xsc_eswitch *esw = dev->priv.eswitch;
	u32 min_rate;
	int err;

	err = kstrtouint(buf, 10, &min_rate);
	if (err != 1)
		return -EINVAL;

	err = xsc_eswitch_set_vgroup_min_rate(esw, g->group_id, min_rate);

	return err ? err : count;
}

#define _sprintf(p, buf, format, arg...)				\
	((PAGE_SIZE - (int)((p) - (buf))) <= 0 ? 0 :			\
	scnprintf((p), PAGE_SIZE - (int)((p) - (buf)), format, ## arg))

static ssize_t trunk_show(struct xsc_sriov_vf *g,
			  struct vf_attributes *oa,
			  char *buf)
{
	struct xsc_core_device *dev = g->dev;
	struct xsc_eswitch *esw = dev->priv.eswitch;
	struct xsc_vport *vport = &esw->vports[g->vf + 1];
	u16 vlan_id = 0;
	char *ret = buf;

	mutex_lock(&esw->state_lock);
	if (!!bitmap_weight(vport->info.vlan_trunk_8021q_bitmap, VLAN_N_VID)) {
		ret += _sprintf(ret, buf, "Allowed 802.1Q VLANs:");
		for_each_set_bit(vlan_id, vport->info.vlan_trunk_8021q_bitmap, VLAN_N_VID)
			ret += _sprintf(ret, buf, " %d", vlan_id);
		ret += _sprintf(ret, buf, "\n");
	}
	mutex_unlock(&esw->state_lock);

	return (ssize_t)(ret - buf);
}

static ssize_t trunk_store(struct xsc_sriov_vf *g,
			   struct vf_attributes *oa,
			   const char *buf,
			   size_t count)
{
	struct xsc_core_device *dev = g->dev;
	u16 start_vid, end_vid;
	char op[5];
	int err;

	err = sscanf(buf, "%4s %hu %hu", op, &start_vid, &end_vid);
	if (err != 3)
		return -EINVAL;

	if (!strcmp(op, "add"))
		err = xsc_eswitch_add_vport_trunk_range(dev->priv.eswitch,
							g->vf + 1,
							start_vid, end_vid);
	else if (!strcmp(op, "rem"))
		err = xsc_eswitch_del_vport_trunk_range(dev->priv.eswitch,
							g->vf + 1,
							start_vid, end_vid);
	else
		return -EINVAL;

	return err ? err : count;
}

static ssize_t config_show(struct xsc_sriov_vf *g, struct vf_attributes *oa,
			   char *buf)
{
	struct xsc_core_device *dev = g->dev;
	struct xsc_eswitch *esw = dev->priv.eswitch;
	struct xsc_vport_info *ivi;
	int vport = g->vf + 1;
	char *p = buf;

	if (!esw || !xsc_core_is_vport_manager(dev))
		return -EPERM;
	if (!(vport >= 0 && vport < esw->total_vports))
		return -EINVAL;

	mutex_lock(&esw->state_lock);
	ivi = &esw->vports[vport].info;
	p += _sprintf(p, buf, "VF         : %d\n", g->vf);
	p += _sprintf(p, buf, "MAC        : %pM\n", ivi->mac);
	p += _sprintf(p, buf, "VLAN       : %d\n", ivi->vlan);
	p += _sprintf(p, buf, "QoS        : %d\n", ivi->qos);
	p += _sprintf(p, buf, "VLAN Proto : %s\n",
		      vlan_proto_str(ivi->vlan, ivi->qos, ivi->vlan_proto));
	p += _sprintf(p, buf, "SpoofCheck : %s\n", ivi->spoofchk ? "ON" : "OFF");
	p += _sprintf(p, buf, "Trust      : %s\n", ivi->trusted ? "ON" : "OFF");
	p += _sprintf(p, buf, "LinkState  : %s",   policy_str(ivi->link_state));
	p += _sprintf(p, buf, "MinTxRate  : %d\n", ivi->min_rate);
	p += _sprintf(p, buf, "MaxTxRate  : %d\n", ivi->max_rate);
	p += _sprintf(p, buf, "VGT+       : %s\n",
		      !!bitmap_weight(ivi->vlan_trunk_8021q_bitmap, VLAN_N_VID) ?
		      "ON" : "OFF");
	p += _sprintf(p, buf, "RateGroup  : %d\n", ivi->group);
	mutex_unlock(&esw->state_lock);

	return (ssize_t)(p - buf);
}

static ssize_t config_store(struct xsc_sriov_vf *g,
			    struct vf_attributes *oa,
			    const char *buf, size_t count)
{
	return -EOPNOTSUPP;
}

static ssize_t config_group_show(struct xsc_vgroup *g,
				 struct vf_group_attributes *oa,
				 char *buf)
{
	struct xsc_core_device *dev = g->dev;
	struct xsc_eswitch *esw = dev->priv.eswitch;
	char *p = buf;

	if (!esw || !xsc_core_is_vport_manager(dev))
		return -EPERM;

	mutex_lock(&esw->state_lock);
	p += _sprintf(p, buf, "Num VFs    : %d\n", g->num_vports);
	p += _sprintf(p, buf, "MaxRate    : %d\n", g->max_rate);
	p += _sprintf(p, buf, "MinRate    : %d\n", g->min_rate);
	p += _sprintf(p, buf, "BWShare(Indirect cfg)    : %d\n", g->bw_share);
	mutex_unlock(&esw->state_lock);

	return (ssize_t)(p - buf);
}

static ssize_t config_group_store(struct xsc_vgroup *g,
				  struct vf_group_attributes *oa,
				  const char *buf, size_t count)
{
	return -EOPNOTSUPP;
}

static ssize_t stats_show(struct xsc_sriov_vf *g, struct vf_attributes *oa,
			  char *buf)
{
	struct xsc_core_device *dev = g->dev;
	struct xsc_vport *vport = xsc_eswitch_get_vport(dev->priv.eswitch, g->vf + 1);
	struct ifla_vf_stats ifi;
	struct xsc_vport_drop_stats stats = {};
	int err;
	char *p = buf;

	err = xsc_eswitch_get_vport_stats(dev->priv.eswitch, g->vf + 1, &ifi);
	if (err)
		return -EINVAL;

	err = xsc_eswitch_query_vport_drop_stats(dev, vport, &stats);
	if (err)
		return -EINVAL;

	p += _sprintf(p, buf, "tx_packets    : %llu\n", ifi.tx_packets);
	p += _sprintf(p, buf, "tx_bytes      : %llu\n", ifi.tx_bytes);
	p += _sprintf(p, buf, "tx_dropped    : %llu\n", stats.tx_dropped);
	p += _sprintf(p, buf, "rx_packets    : %llu\n", ifi.rx_packets);
	p += _sprintf(p, buf, "rx_bytes      : %llu\n", ifi.rx_bytes);
	p += _sprintf(p, buf, "rx_broadcast  : %llu\n", ifi.broadcast);
	p += _sprintf(p, buf, "rx_multicast  : %llu\n", ifi.multicast);
	p += _sprintf(p, buf, "rx_dropped    : %llu\n", stats.rx_dropped);

	return (ssize_t)(p - buf);
}

static ssize_t stats_store(struct xsc_sriov_vf *g, struct vf_attributes *oa,
			   const char *buf, size_t count)
{
	return -EOPNOTSUPP;
}
#endif /* CONFIG_XSC_ESWITCH */

static ssize_t num_vfs_store(struct device *device, struct device_attribute *attr,
			     const char *buf, size_t count)
{
	struct pci_dev *pdev = container_of(device, struct pci_dev, dev);
	int req_vfs;
	int err;

	if (kstrtoint(buf, 0, &req_vfs) || req_vfs < 0 ||
	    req_vfs > pci_sriov_get_totalvfs(pdev))
		return -EINVAL;

	err = xsc_core_sriov_configure(pdev, req_vfs);
	if (err < 0)
		return err;

	return count;
}

static ssize_t num_vfs_show(struct device *device, struct device_attribute *attr,
			    char *buf)
{
	struct pci_dev *pdev = container_of(device, struct pci_dev, dev);
	struct xsc_core_device *dev = pci_get_drvdata(pdev);
	struct xsc_core_sriov *sriov = &dev->priv.sriov;

	return sprintf(buf, "%d\n", sriov->num_vfs);
}

static DEVICE_ATTR_RW(num_vfs);

static const struct sysfs_ops vf_sysfs_ops = {
	.show = vf_attr_show,
	.store = vf_attr_store,
};

static const struct sysfs_ops vf_group_sysfs_ops = {
	.show = vf_group_attr_show,
	.store = vf_group_attr_store,
};

#define VF_RATE_GROUP_ATTR(_name) struct vf_group_attributes vf_group_attr_##_name = \
	__ATTR(_name, 0644, _name##_group_show, _name##_group_store)
#define VF_ATTR(_name) struct vf_attributes vf_attr_##_name = \
	__ATTR(_name, 0644, _name##_show, _name##_store)

VF_ATTR(node);
VF_ATTR(port);
VF_ATTR(policy);

#ifdef CONFIG_XSC_ESWITCH
VF_ATTR(mac);
VF_ATTR(vlan);
VF_ATTR(link_state);
VF_ATTR(spoofcheck);
VF_ATTR(trust);
VF_ATTR(max_tx_rate);
VF_ATTR(min_tx_rate);
VF_ATTR(config);
VF_ATTR(trunk);
VF_ATTR(stats);
VF_ATTR(group);
VF_RATE_GROUP_ATTR(max_tx_rate);
VF_RATE_GROUP_ATTR(min_tx_rate);
VF_RATE_GROUP_ATTR(config);

static struct attribute *vf_eth_attrs[] = {
	&vf_attr_node.attr,
	&vf_attr_mac.attr,
	&vf_attr_vlan.attr,
	&vf_attr_link_state.attr,
	&vf_attr_spoofcheck.attr,
	&vf_attr_trust.attr,
	&vf_attr_max_tx_rate.attr,
	&vf_attr_min_tx_rate.attr,
	&vf_attr_config.attr,
	&vf_attr_trunk.attr,
	&vf_attr_stats.attr,
	&vf_attr_group.attr,
	NULL
};
ATTRIBUTE_GROUPS(vf_eth);

static struct attribute *vf_group_attrs[] = {
	&vf_group_attr_max_tx_rate.attr,
	&vf_group_attr_min_tx_rate.attr,
	&vf_group_attr_config.attr,
	NULL
};
ATTRIBUTE_GROUPS(vf_group);

static const struct kobj_type vf_type_eth = {
	.sysfs_ops     = &vf_sysfs_ops,
	.default_groups = vf_eth_groups,
};

static const struct kobj_type vf_group = {
	.sysfs_ops     = &vf_group_sysfs_ops,
	.default_groups = vf_group_groups,
};

static struct vf_attributes pf_attr_min_pf_tx_rate =
	__ATTR(min_tx_rate, 0644, min_pf_tx_rate_show, min_pf_tx_rate_store);

static struct attribute *pf_eth_attrs[] = {
	&pf_attr_min_pf_tx_rate.attr,
	NULL,
};
ATTRIBUTE_GROUPS(pf_eth);

static const struct kobj_type pf_type_eth = {
	.sysfs_ops     = &vf_sysfs_ops,
	.default_groups = pf_eth_groups,
};
#endif /* CONFIG_XSC_ESWITCH */

static struct attribute *vf_ib_attrs[] = {
	&vf_attr_node.attr,
	&vf_attr_port.attr,
	&vf_attr_policy.attr,
	NULL
};
ATTRIBUTE_GROUPS(vf_ib);

static const struct kobj_type vf_type_ib = {
	.sysfs_ops     = &vf_sysfs_ops,
	.default_groups = vf_ib_groups,
};

static struct device_attribute *xsc_class_attributes[] = {
	&dev_attr_num_vfs,
};

int xsc_sriov_sysfs_init(struct xsc_core_device *dev)
{
	struct xsc_core_sriov *sriov = &dev->priv.sriov;
	struct device *device = &dev->pdev->dev;
	int err;
	int i;

	sriov->config = kobject_create_and_add("sriov", &device->kobj);
	if (!sriov->config)
		return -ENOMEM;

#ifdef CONFIG_XSC_ESWITCH
	if (dev->caps.log_esw_max_sched_depth) {
		sriov->groups_config = kobject_create_and_add("groups",
							      sriov->config);
		if (!sriov->groups_config) {
			err = -ENOMEM;
			goto err_groups;
		}
	}
#endif

	for (i = 0; i < ARRAY_SIZE(xsc_class_attributes); i++) {
		err = device_create_file(device, xsc_class_attributes[i]);
		if (err)
			goto err_attr;
	}

	return 0;

err_attr:
#ifdef CONFIG_XSC_ESWITCH
	if (sriov->groups_config) {
		kobject_put(sriov->groups_config);
		sriov->groups_config = NULL;
	}

err_groups:
#endif
	kobject_put(sriov->config);
	sriov->config = NULL;
	return err;
}

void xsc_sriov_sysfs_cleanup(struct xsc_core_device *dev)
{
	struct xsc_core_sriov *sriov = &dev->priv.sriov;
	struct device *device = &dev->pdev->dev;
	int i;

	for (i = 0; i < ARRAY_SIZE(xsc_class_attributes); i++)
		device_remove_file(device, xsc_class_attributes[i]);

	if (dev->caps.log_esw_max_sched_depth)
		kobject_put(sriov->groups_config);
	kobject_put(sriov->config);
	sriov->config = NULL;
}

int xsc_create_vf_group_sysfs(struct xsc_core_device *dev,
			      u32 group_id, struct kobject *group_kobj)
{
#ifdef CONFIG_XSC_ESWITCH
	struct xsc_core_sriov *sriov = &dev->priv.sriov;
	int err;

	err = kobject_init_and_add(group_kobj, &vf_group, sriov->groups_config,
				   "%d", group_id);
	if (err)
		return err;

	kobject_uevent(group_kobj, KOBJ_ADD);
#endif

	return 0;
}

void xsc_destroy_vf_group_sysfs(struct xsc_core_device *dev,
				struct kobject *group_kobj)
{
#ifdef CONFIG_XSC_ESWITCH
	kobject_put(group_kobj);
#endif
}

int xsc_create_vfs_sysfs(struct xsc_core_device *dev, int num_vfs)
{
	struct xsc_core_sriov *sriov = &dev->priv.sriov;
	struct xsc_sriov_vf *tmp;
	static const struct kobj_type *sysfs;
	int err;
	int vf;

	sysfs = &vf_type_ib;

#ifdef CONFIG_XSC_ESWITCH
	sysfs = &vf_type_eth;
#endif

	sriov->vfs = kcalloc(num_vfs + 1, sizeof(*sriov->vfs), GFP_KERNEL);
	if (!sriov->vfs)
		return -ENOMEM;

	for (vf = 0; vf < num_vfs; vf++) {
		tmp = &sriov->vfs[vf];
		tmp->dev = dev;
		tmp->vf = vf;
		err = kobject_init_and_add(&tmp->kobj, sysfs, sriov->config,
					   "%d", vf);
		if (err)
			goto err_vf;

		kobject_uevent(&tmp->kobj, KOBJ_ADD);
	}

#ifdef CONFIG_XSC_ESWITCH
	tmp = &sriov->vfs[vf];
	tmp->dev = dev;
	tmp->vf = 0;
	err = kobject_init_and_add(&tmp->kobj, &pf_type_eth,
				   sriov->config, "%s", "pf");
	if (err) {
		--vf;
		goto err_vf;
	}

	kobject_uevent(&tmp->kobj, KOBJ_ADD);
#endif

	return 0;

err_vf:
	for (; vf >= 0; vf--) {
		tmp = &sriov->vfs[vf];
		kobject_put(&tmp->kobj);
	}

	kfree(sriov->vfs);
	sriov->vfs = NULL;
	return err;
}

void xsc_destroy_vfs_sysfs(struct xsc_core_device *dev, int num_vfs)
{
	struct xsc_core_sriov *sriov = &dev->priv.sriov;
	struct xsc_sriov_vf *tmp;
	int vf;

#ifdef CONFIG_XSC_ESWITCH
	if (num_vfs) {
		tmp = &sriov->vfs[num_vfs];
		kobject_put(&tmp->kobj);
	}
#endif
	for (vf = 0; vf < num_vfs; vf++) {
		tmp = &sriov->vfs[vf];
		kobject_put(&tmp->kobj);
	}

	kfree(sriov->vfs);
	sriov->vfs = NULL;
}
