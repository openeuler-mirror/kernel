// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 nebula-matrix Limited.
 * Author:
 */

#include "nbl_devcomm.h"

static LIST_HEAD(devcomm_comp_list);
/* protect component list */
static DEFINE_MUTEX(comp_list_lock);

#define devcomm_for_each_component(iter) \
	list_for_each_entry(iter, &devcomm_comp_list, comp_list)

static struct nbl_devcomm_comp *
nbl_devcomm_comp_alloc(u64 id, const struct nbl_devcomm_match_attr *attr,
		       int (*event_cb)(int event, void *priv_data, void *event_data))
{
	struct nbl_devcomm_comp *comp;

	comp = kzalloc(sizeof(*comp), GFP_KERNEL);
	if (!comp)
		return NULL;

	comp->id = id;
	comp->key.key = attr->key;
	comp->key.flags = attr->flags;
	if (attr->flags & NBL_DEVCOMM_MATCH_FLAGS_NS)
		write_pnet(&comp->key.net, attr->net);

	comp->event_cb = event_cb;
	init_rwsem(&comp->sem);
	kref_init(&comp->ref);
	INIT_LIST_HEAD(&comp->comp_dev_list_head);

	return comp;
}

static void
nbl_devcomm_comp_release(struct kref *ref)
{
	struct nbl_devcomm_comp *comp = container_of(ref, struct nbl_devcomm_comp, ref);

	mutex_lock(&comp_list_lock);
	list_del(&comp->comp_list);
	mutex_unlock(&comp_list_lock);
	kfree(comp);
}

static struct nbl_devcomm_comp_dev *
nbl_devcomm_alloc_comp_dev(struct nbl_devcomm_comp *comp,
			   void *data)
{
	struct nbl_devcomm_comp_dev *dev;

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return NULL;

	dev->comp = comp;
	dev->data = data;

	down_write(&comp->sem);
	list_add_tail(&dev->list, &comp->comp_dev_list_head);
	up_write(&comp->sem);

	return dev;
}

static void
nbl_devcomm_free_comp_dev(struct nbl_devcomm_comp_dev *dev)
{
	struct nbl_devcomm_comp *comp = dev->comp;

	down_write(&comp->sem);
	list_del(&dev->list);
	up_write(&comp->sem);
	kfree(dev);
	kref_put(&comp->ref, nbl_devcomm_comp_release);
}

static bool
nbl_devcomm_component_equal(struct nbl_devcomm_comp *devcomm,
			    enum nbl_devcomm_comp_type id,
			    const struct nbl_devcomm_match_attr *attr)
{
	if (devcomm->id != id)
		return false;

	if (devcomm->key.flags != attr->flags)
		return false;

	if (memcmp(&devcomm->key.key, &attr->key, sizeof(devcomm->key.key)))
		return false;

	if (devcomm->key.flags & NBL_DEVCOMM_MATCH_FLAGS_NS &&
	    !net_eq(read_pnet(&devcomm->key.net), attr->net))
		return false;

	return true;
}

static struct nbl_devcomm_comp *
nbl_devcomm_component_get(enum nbl_devcomm_comp_type id,
			  const struct nbl_devcomm_match_attr *attr)
{
	struct nbl_devcomm_comp *comp;

	devcomm_for_each_component(comp) {
		if (nbl_devcomm_component_equal(comp, id, attr)) {
			kref_get(&comp->ref);
			return comp;
		}
	}

	return NULL;
}

struct nbl_devcomm_comp_dev *
nbl_devcomm_register_component(enum nbl_devcomm_comp_type id,
			       const struct nbl_devcomm_match_attr *attr,
			       int (*event_cb)(int event, void *priv_data, void *event_data),
			       void *data)
{
	struct nbl_devcomm_comp_dev *dev = NULL;
	struct nbl_devcomm_comp *comp;

	mutex_lock(&comp_list_lock);
	comp = nbl_devcomm_component_get(id, attr);
	if (IS_ERR(comp))
		goto out_unlock;

	if (!comp) {
		comp = nbl_devcomm_comp_alloc(id, attr, event_cb);
		if (!comp)
			goto out_unlock;

		list_add_tail(&comp->comp_list, &devcomm_comp_list);
	}

	mutex_unlock(&comp_list_lock);

	dev = nbl_devcomm_alloc_comp_dev(comp, data);
	if (!dev)
		kref_put(&comp->ref, nbl_devcomm_comp_release);

	return dev;

out_unlock:
	mutex_unlock(&comp_list_lock);
	return dev;
}

void nbl_devcomm_unregister_component(struct nbl_devcomm_comp_dev *dev)
{
	if (!dev)
		return;

	nbl_devcomm_free_comp_dev(dev);
}

int nbl_devcomm_comp_get_size(struct nbl_devcomm_comp_dev *dev)
{
	struct nbl_devcomm_comp *comp = dev->comp;

	return kref_read(&comp->ref);
}

int nbl_devcomm_send_event(struct nbl_devcomm_comp_dev *dev,
			   int event, int rollback_event,
			   void *event_data)
{
	struct nbl_devcomm_comp_dev *pos;
	struct nbl_devcomm_comp *comp;
	int err = 0;
	void *data;

	if (!dev)
		return -ENODEV;

	comp = dev->comp;
	down_write(&comp->sem);
	list_for_each_entry(pos, &comp->comp_dev_list_head, list) {
		data = pos->data;
		if (pos != dev && data) {
			err = comp->event_cb(event, data, event_data);
			if (err)
				goto rollback;
		}
	}

	up_write(&comp->sem);
	return 0;

rollback:
	if (nbl_list_entry_is_head(pos, &comp->comp_dev_list_head, list))
		goto out;

	pos = list_prev_entry(pos, list);
	list_for_each_entry_from_reverse(pos, &comp->comp_dev_list_head, list) {
		data = pos->data;
		if (pos != dev && data)
			comp->event_cb(rollback_event, data, event_data);
	}
out:
	up_write(&comp->sem);
	return err;
}

bool nbl_devcomm_list_each_peer_begin(struct nbl_devcomm_comp_dev *dev)
{
	struct nbl_devcomm_comp *comp;

	if (!dev)
		return false;

	comp = dev->comp;
	down_read(&comp->sem);

	return true;
}

void nbl_devcomm_list_each_peer_end(struct nbl_devcomm_comp_dev *dev)
{
	struct nbl_devcomm_comp *comp = dev->comp;

	up_read(&comp->sem);
}

void *nbl_devcomm_get_next_peer_data(struct nbl_devcomm_comp_dev *dev,
				     struct nbl_devcomm_comp_dev **pos)
{
	struct nbl_devcomm_comp *comp = dev->comp;
	struct nbl_devcomm_comp_dev *tmp;
	void *data;

	tmp = list_prepare_entry(*pos, &comp->comp_dev_list_head, list);

	list_for_each_entry_continue(tmp, &comp->comp_dev_list_head, list) {
		if (tmp != dev) {
			data = tmp->data;
			if (data)
				break;
		}
	}

	if (nbl_list_entry_is_head(tmp, &comp->comp_dev_list_head, list))
		return NULL;

	*pos = tmp;
	return data;
}

void nbl_devcomm_comp_lock(struct nbl_devcomm_comp_dev *dev)
{
	struct nbl_devcomm_comp *comp;

	if (!dev)
		return;

	comp = dev->comp;
	down_write(&comp->sem);
}

void nbl_devcomm_comp_unlock(struct nbl_devcomm_comp_dev *dev)
{
	struct nbl_devcomm_comp *comp;

	if (!dev)
		return;

	comp = dev->comp;
	up_write(&comp->sem);
}

int nbl_devcomm_comp_trylock(struct nbl_devcomm_comp_dev *dev)
{
	struct nbl_devcomm_comp *comp;

	if (!dev)
		return 0;

	comp = dev->comp;
	return down_write_trylock(&comp->sem);
}
