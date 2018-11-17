// SPDX-License-Identifier: GPL-2.0+
#include <linux/anon_inodes.h>
#include <linux/idr.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/vfio_spimdev.h>

struct _mdev_pool_entry {
	struct vfio_spimdev_queue *q;
	bool is_free;
};

struct _spimdev {
	const char *mdev;
	void *pool;
	atomic_t ref;
	int group_id;
	int pid;
	struct list_head next;
	struct spimdev_mdev_state *mstate;
	struct mutex lock;
};

struct spimdev_mdev_state {
	struct vfio_spimdev *spimdev;
	struct mutex lock;
	atomic_t users;
	struct list_head mdev_list;
};

static struct class *spimdev_class;

static void *vfio_spimdev_iommu_open(unsigned long arg)
{
	if (arg != VFIO_SPIMDEV_IOMMU)
		return ERR_PTR(-EINVAL);
	if (!capable(CAP_SYS_RAWIO))
		return ERR_PTR(-EPERM);

	return NULL;
}

static void vfio_spimdev_iommu_release(void *iommu_data)
{
}

static long vfio_spimdev_iommu_ioctl(void *iommu_data,
			       unsigned int cmd, unsigned long arg)
{
	if (cmd == VFIO_CHECK_EXTENSION)
		return arg == VFIO_SPIMDEV_IOMMU ? 1 : -EINVAL;

	return -ENOTTY;
}

static int vfio_spimdev_iommu_attach_group(void *iommu_data,
				     struct iommu_group *iommu_group)
{
	return 0;
}

static void vfio_spimdev_iommu_detach_group(void *iommu_data,
				      struct iommu_group *iommu_group)
{
}

static const struct vfio_iommu_driver_ops vfio_spimdev_iommu_ops = {
	.name = "vfio-spimdev-iommu",
	.owner = THIS_MODULE,
	.open = vfio_spimdev_iommu_open,
	.release = vfio_spimdev_iommu_release,
	.ioctl = vfio_spimdev_iommu_ioctl,
	.attach_group = vfio_spimdev_iommu_attach_group,
	.detach_group = vfio_spimdev_iommu_detach_group,
};

static void _spimdev_get(struct _spimdev *dev)
{
	atomic_inc(&dev->ref);
	dev->pid = current->pid;
}

static void _spimdev_put(struct _spimdev *dev)
{
	if (atomic_dec_if_positive(&dev->ref) == 0)
		dev->pid = -1;
}

static int vfio_spimdev_dev_exist(struct device *dev, void *data)
{
	return !strcmp(dev_name(dev), dev_name((struct device *)data));
}

#ifdef CONFIG_IOMMU_SVA
static bool vfio_spimdev_is_valid_pasid(int pasid)
{
	struct mm_struct *mm;

	mm = iommu_sva_find(pasid);
	if (mm) {
		mmput(mm);
		return mm == current->mm;
	}

	return false;
}
#endif

/* Check if the device is a mediated device belongs to vfio_spimdev */
int vfio_spimdev_is_spimdev(struct device *dev)
{
	struct mdev_device *mdev;
	struct device *pdev;

	mdev = mdev_from_dev(dev);
	if (!mdev)
		return 0;

	pdev = mdev_parent_dev(mdev);
	if (!pdev)
		return 0;

	return class_for_each_device(spimdev_class, NULL, pdev,
			vfio_spimdev_dev_exist);
}
EXPORT_SYMBOL_GPL(vfio_spimdev_is_spimdev);

struct vfio_spimdev *vfio_spimdev_pdev_spimdev(struct device *dev)
{
	struct device *class_dev;

	if (!dev)
		return ERR_PTR(-EINVAL);

	class_dev = class_find_device(spimdev_class, NULL, dev,
		(int(*)(struct device *, const void *))vfio_spimdev_dev_exist);
	if (!class_dev)
		return ERR_PTR(-ENODEV);

	return container_of(class_dev, struct vfio_spimdev, cls_dev);
}
EXPORT_SYMBOL_GPL(vfio_spimdev_pdev_spimdev);

struct vfio_spimdev *mdev_spimdev(struct mdev_device *mdev)
{
	struct device *pdev = mdev_parent_dev(mdev);

	return vfio_spimdev_pdev_spimdev(pdev);
}
EXPORT_SYMBOL_GPL(mdev_spimdev);

static ssize_t iommu_type_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	struct vfio_spimdev *spimdev = vfio_spimdev_pdev_spimdev(dev);

	if (!spimdev)
		return -ENODEV;

	return sprintf(buf, "%d\n", spimdev->iommu_type);
}

static DEVICE_ATTR_RO(iommu_type);

static ssize_t dma_flag_show(struct device *dev,
			     struct device_attribute *attr, char *buf)
{
	struct vfio_spimdev *spimdev = vfio_spimdev_pdev_spimdev(dev);

	if (!spimdev)
		return -ENODEV;

	return sprintf(buf, "%d\n", spimdev->dma_flag);
}

static DEVICE_ATTR_RO(dma_flag);

static ssize_t node_id_show(struct device *dev, struct device_attribute *attr,
			    char *buf)
{
	struct vfio_spimdev *spimdev = vfio_spimdev_pdev_spimdev(dev);

	if (!spimdev)
		return -ENODEV;

#ifndef CONFIG_NUMA
	return sprintf(buf, "%d\n", -1);
#else
	return sprintf(buf, "%d\n", spimdev->node_id);
#endif
}

static DEVICE_ATTR_RO(node_id);

#ifdef CONFIG_NUMA
static ssize_t numa_distance_show(struct device *dev,
				struct device_attribute *attr,
				char *buf)
{
	struct vfio_spimdev *spimdev = vfio_spimdev_pdev_spimdev(dev);
	int distance;

	if (!spimdev)
		return -ENODEV;
	distance = cpu_to_node(smp_processor_id()) - spimdev->node_id;

	return sprintf(buf, "%d\n", abs(distance));
}

static DEVICE_ATTR_RO(numa_distance);
#endif

static ssize_t mdev_get_show(struct device *dev,
			 struct device_attribute *attr,
			 char *buf)
{
	struct vfio_spimdev *spimdev = vfio_spimdev_pdev_spimdev(dev);
	struct spimdev_mdev_state *mdev_state;
	struct _spimdev *mdev;

	if (!spimdev)
		return -ENODEV;
	mdev_state = spimdev->mstate;
	mutex_lock(&mdev_state->lock);
	list_for_each_entry(mdev, &mdev_state->mdev_list, next) {
		if (atomic_read(&mdev->ref))
			continue;
		_spimdev_get(mdev);
		mutex_unlock(&mdev_state->lock);
		return sprintf(buf, "%s_%d\n", mdev->mdev, mdev->group_id);
	}
	mutex_unlock(&mdev_state->lock);

	return -ENODEV;
}

static DEVICE_ATTR_RO(mdev_get);

/* mdev->dev_attr_groups */
static struct attribute *vfio_spimdev_attrs[] = {
	&dev_attr_iommu_type.attr,
	&dev_attr_dma_flag.attr,
	&dev_attr_node_id.attr,
#ifdef CONFIG_NUMA
	&dev_attr_numa_distance.attr,
#endif
	&dev_attr_mdev_get.attr,
	NULL,
};
static const struct attribute_group vfio_spimdev_group = {
	.name  = VFIO_SPIMDEV_PDEV_ATTRS_GRP,
	.attrs = vfio_spimdev_attrs,
};
const struct attribute_group *vfio_spimdev_groups[] = {
	&vfio_spimdev_group,
	NULL,
};

static ssize_t type_show(struct kobject *kobj, struct device *dev, char *buf)
{
	struct vfio_spimdev *spimdev = vfio_spimdev_pdev_spimdev(dev);
	struct attribute_group **groups;
	int i = 0;

	if (!spimdev)
		return -ENODEV;
	groups = spimdev->mdev_fops.supported_type_groups;
	while (groups[i]) {
		if (strstr(kobj->name, groups[i]->name))
			return sprintf(buf, "%d\n", i);
		i++;
	}

	return -ENODEV;
}
MDEV_TYPE_ATTR_RO(type);
EXPORT_SYMBOL_GPL(mdev_type_attr_type);

static ssize_t device_api_show(struct kobject *kobj, struct device *dev,
			       char *buf)
{
	struct vfio_spimdev *spimdev = vfio_spimdev_pdev_spimdev(dev);

	if (!spimdev)
		return -ENODEV;
	return sprintf(buf, "%s\n", spimdev->api_ver);
}
MDEV_TYPE_ATTR_RO(device_api);
EXPORT_SYMBOL_GPL(mdev_type_attr_device_api);

/* this return total queue left, not mdev left */
static ssize_t
available_instances_show(struct kobject *kobj, struct device *dev, char *buf)
{
	struct vfio_spimdev *spimdev = vfio_spimdev_pdev_spimdev(dev);

	if (spimdev->ops->get_available_instances)
		return sprintf(buf, "%d\n",
			spimdev->ops->get_available_instances(spimdev));
	else
		return -ENODEV;
}
MDEV_TYPE_ATTR_RO(available_instances);
EXPORT_SYMBOL_GPL(mdev_type_attr_available_instances);

static ssize_t
pid_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct mdev_device *mdev;
	struct _spimdev *smdev;

	mdev = mdev_from_dev(dev);
	smdev = mdev_get_drvdata(mdev);
	if (!smdev)
		return -ENODEV;

	return sprintf(buf, "%d\n", smdev->pid);
}
DEVICE_ATTR_RO(pid);
EXPORT_SYMBOL_GPL(dev_attr_pid);

static void _vfio_spimdev_add_mdev(struct spimdev_mdev_state *state,
				    struct _spimdev *spimdev)
{
	mutex_lock(&state->lock);
	list_add(&spimdev->next, &state->mdev_list);
	mutex_unlock(&state->lock);
	atomic_inc(&state->users);
}

static void *_mdev_create_qpool(struct vfio_spimdev *spimdev,
				struct mdev_device *mdev)
{
	const char *alg;
	int ret, size = 0, i = 0;
	struct _mdev_pool_entry *pool;
	struct device *dev = mdev_dev(mdev);
	struct attribute_group **groups;

	groups = spimdev->mdev_fops.supported_type_groups;
	if (spimdev->flags & VFIO_SPIMDEV_SAME_ALG_QFLG) {
		pool = devm_kzalloc(dev, sizeof(*pool), GFP_KERNEL);
		if (!pool)
			return pool;
		alg = groups[0]->name;
		ret = spimdev->ops->get_queue(spimdev, alg, &pool[0].q);
		if (ret < 0)
			return NULL;
		pool[0].is_free = true;

		return pool;
	} else if (spimdev->flags & VFIO_SPIMDEV_DIFF_ALG_QFLG) {
		while (groups[size])
			size++;
		if (size < 1)
			return NULL;
		pool = devm_kzalloc(dev, size * sizeof(*pool), GFP_KERNEL);
		if (!pool)
			return pool;
		for (i = 0; i < size; i++) {
			alg = groups[i]->name;
			ret = spimdev->ops->get_queue(spimdev, alg, &pool[i].q);
			if (ret < 0)
				goto create_pool_fail;
			pool[i].is_free = true;
		}
		return pool;
	} else
		return NULL;
create_pool_fail:
	while (i >= 0 && pool[i].q) {
		spimdev->ops->put_queue(pool[i].q);
		i--;
	}
	return NULL;
}

static void _mdev_destroy_qpool(struct vfio_spimdev *spimdev,
				struct _spimdev *smdev)
{
	struct _mdev_pool_entry *pool = smdev->pool;
	int i = 0;

	/* all the pool queues should be free, while remove mdev */
	while (pool[i].is_free && pool[i].q) {
		spimdev->ops->put_queue(pool[i].q);
		i++;
	}
}

static int vfio_spimdev_mdev_create(struct kobject *kobj,
	struct mdev_device *mdev)
{
	struct device *dev = mdev_dev(mdev);
	struct device *pdev = mdev_parent_dev(mdev);
	struct vfio_spimdev *spimdev = mdev_spimdev(mdev);
	struct spimdev_mdev_state *mdev_state = spimdev->mstate;
	struct _spimdev *smdev;
	struct iommu_group *group;
	int ret = 0;

	if (!spimdev->ops->get_queue)
		return -ENODEV;
	group = iommu_group_get(dev);
	if (!group)
		return -ENODEV;
	dev->iommu_fwspec = pdev->iommu_fwspec;
	get_device(pdev);
	__module_get(spimdev->owner);
	smdev = devm_kzalloc(dev, sizeof(*smdev), GFP_KERNEL);
	if (!smdev) {
		ret = -ENOMEM;
		goto create_mdev_fail;
	}
	atomic_set(&smdev->ref, 0);
	smdev->pool = _mdev_create_qpool(spimdev, mdev);
	if (!smdev->pool) {
		ret = -ENODEV;
		goto create_mdev_fail;
	}
	smdev->mdev = dev_name(dev);
	smdev->pid = -1;
	smdev->group_id = iommu_group_id(group);
	smdev->mstate = mdev_state;
	mutex_init(&smdev->lock);
	iommu_group_put(group);
	_vfio_spimdev_add_mdev(mdev_state, smdev);
	mdev_set_drvdata(mdev, smdev);

	return 0;

create_mdev_fail:
	module_put(spimdev->owner);
	iommu_group_put(group);

	return ret;
}

static int _vfio_spimdev_del_mdev(struct spimdev_mdev_state *state,
				  struct device *dev)
{
	const char *name = dev_name(dev);
	struct _spimdev *mdev, *lmdev;
	struct vfio_spimdev *spimdev = state->spimdev;

	mutex_lock(&state->lock);
	list_for_each_entry_safe(mdev, lmdev, &state->mdev_list, next) {
		if (name == mdev->mdev) {
			if (atomic_read(&mdev->ref))
				return -EBUSY;
			atomic_dec(&state->users);
			list_del(&mdev->next);
			mutex_unlock(&state->lock);
			_mdev_destroy_qpool(spimdev, mdev);

			return 0;
		}
	}
	mutex_unlock(&state->lock);

	return -ENODEV;
}

static int vfio_spimdev_mdev_remove(struct mdev_device *mdev)
{
	struct device *dev = mdev_dev(mdev);
	struct device *pdev = mdev_parent_dev(mdev);
	struct vfio_spimdev *spimdev = mdev_spimdev(mdev);
	struct spimdev_mdev_state *mdev_state = spimdev->mstate;
	int ret;

	ret = _vfio_spimdev_del_mdev(mdev_state, dev);
	if (ret)
		return ret;
	put_device(pdev);
	module_put(spimdev->owner);
	dev->iommu_fwspec = NULL;
	mdev_set_drvdata(mdev, NULL);

	return 0;
}

/* Wake up the process who is waiting this queue */
void vfio_spimdev_wake_up(struct vfio_spimdev_queue *q)
{
	wake_up(&q->wait);
}
EXPORT_SYMBOL_GPL(vfio_spimdev_wake_up);

static int _get_queue_from_pool(struct mdev_device *mdev, const char *alg,
				struct vfio_spimdev_queue **q)
{
	struct _spimdev *smdev;
	struct _mdev_pool_entry *pool;
	struct spimdev_mdev_state *mdev_state;
	struct vfio_spimdev *spimdev;
	struct attribute_group **groups;
	int i = 0;

	smdev = mdev_get_drvdata(mdev);
	if (!smdev)
		return -ENODEV;
	mdev_state = smdev->mstate;
	spimdev = mdev_state->spimdev;
	if (!spimdev)
		return -ENODEV;
	pool = smdev->pool;
	mutex_lock(&smdev->lock);
	if (spimdev->flags & VFIO_SPIMDEV_SAME_ALG_QFLG) {
		if (pool[0].is_free) {
			*q = pool[0].q;
			pool[0].is_free = false;
			mutex_unlock(&smdev->lock);

			return 0;
		}
		mutex_unlock(&smdev->lock);
		return -ENODEV;
	}

	groups = spimdev->mdev_fops.supported_type_groups;
	while (groups[i]) {
		if (pool[i].is_free && !strncmp(groups[i]->name, alg,
		    strlen(alg))) {
			*q = pool[i].q;
			pool[i].is_free = false;
			mutex_unlock(&smdev->lock);
			return 0;
		}
		i++;
	}
	mutex_unlock(&smdev->lock);

	return -ENODEV;
}

static int _put_queue_to_pool(struct mdev_device *mdev,
			      struct vfio_spimdev_queue *q)
{
	struct attribute_group **groups;
	struct spimdev_mdev_state *mdev_state;
	struct vfio_spimdev *spimdev;
	struct _spimdev *smdev;
	struct _mdev_pool_entry *pool;
	int i = 0;

	smdev = mdev_get_drvdata(mdev);
	if (!smdev)
		return -ENODEV;
	mdev_state = smdev->mstate;
	spimdev = mdev_state->spimdev;
	if (!spimdev)
		return -ENODEV;
	groups = spimdev->mdev_fops.supported_type_groups;
	pool = smdev->pool;
	mutex_lock(&smdev->lock);
	if (spimdev->flags & VFIO_SPIMDEV_SAME_ALG_QFLG) {
		if (pool[0].is_free) {
			mutex_unlock(&smdev->lock);
			return -EEXIST;
		} else if (pool[0].q == q) {
			pool[0].is_free = true;
			if (spimdev->ops->reset_queue)
				(void)spimdev->ops->reset_queue(q);
			mutex_unlock(&smdev->lock);

			return 0;
		}
		mutex_unlock(&smdev->lock);
		return -EEXIST;
	}
	while (groups[i]) {
		if (!strncmp(groups[i]->name, q->alg, strlen(q->alg))) {
			if (pool[i].is_free) {
				continue;
			} else if (pool[i].q == q) {
				pool[i].is_free = true;
				if (spimdev->ops->reset_queue)
					(void)spimdev->ops->reset_queue(q);
				mutex_unlock(&smdev->lock);

				return 0;
			}
		}
		i++;
	}

	mutex_unlock(&smdev->lock);
	return -EINVAL;
}

static int vfio_spimdev_q_file_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int vfio_spimdev_q_file_release(struct inode *inode, struct file *file)
{
	struct vfio_spimdev_queue *q =
		(struct vfio_spimdev_queue *)file->private_data;
	struct vfio_spimdev *spimdev = q->spimdev;
	int ret;

	if (_put_queue_to_pool(q->mdev, q)) {
		ret = spimdev->ops->put_queue(q);
		if (ret) {
			dev_err(spimdev->dev, "drv put queue fail!\n");
			return ret;
		}
	}
	put_device(mdev_dev(q->mdev));

	return 0;
}

static long vfio_spimdev_q_file_ioctl(struct file *file, unsigned int cmd,
				      unsigned long arg)
{
	struct vfio_spimdev_queue *q =
		(struct vfio_spimdev_queue *)file->private_data;
	struct vfio_spimdev *spimdev = q->spimdev;

	if (spimdev->ops->ioctl)
		return spimdev->ops->ioctl(q, cmd, arg);

	dev_err(spimdev->dev, "ioctl cmd (%d) is not supported!\n", cmd);

	return -EINVAL;
}

static int vfio_spimdev_q_file_mmap(struct file *file,
		struct vm_area_struct *vma)
{
	struct vfio_spimdev_queue *q =
		(struct vfio_spimdev_queue *)file->private_data;
	struct vfio_spimdev *spimdev = q->spimdev;

	if (spimdev->ops->mmap)
		return spimdev->ops->mmap(q, vma);

	dev_err(spimdev->dev, "no driver mmap!\n");
	return -EINVAL;
}

static __poll_t vfio_spimdev_q_file_poll(struct file *file, poll_table *wait)
{
	struct vfio_spimdev_queue *q =
		(struct vfio_spimdev_queue *)file->private_data;
	struct vfio_spimdev *spimdev = q->spimdev;

	poll_wait(file, &q->wait, wait);
	if (spimdev->ops->is_q_updated(q))
		return EPOLLIN | EPOLLRDNORM;

	return 0;
}

static const struct file_operations spimdev_q_file_ops = {
	.owner = THIS_MODULE,
	.open = vfio_spimdev_q_file_open,
	.unlocked_ioctl = vfio_spimdev_q_file_ioctl,
	.release = vfio_spimdev_q_file_release,
	.poll = vfio_spimdev_q_file_poll,
	.mmap = vfio_spimdev_q_file_mmap,
};

static long vfio_spimdev_mdev_get_queue(struct mdev_device *mdev,
		struct vfio_spimdev *spimdev, unsigned long arg)
{
	struct vfio_spimdev_queue *q;
	int ret;
	const char *alg;
	struct attribute_group **groups;
#ifdef CONFIG_IOMMU_SVA
	int pasid = arg;

	/* To be fixed while PASID solution is ok in mainline
	 * I don't think we should set pasid from user space.
	 * PASID must not be exposed to user space.
	 */
	if (!vfio_spimdev_is_valid_pasid(pasid))
		return -EINVAL;
#endif
	if (arg > VFIO_SPIMDEV_MAX_TYPES)
		return -EINVAL;
	groups = spimdev->mdev_fops.supported_type_groups;
	if (!groups[arg])
		return -EINVAL;
	alg = groups[arg]->name;
	ret = _get_queue_from_pool(mdev, alg, &q);
	if (ret) {
		ret = spimdev->ops->get_queue(spimdev, alg, &q);
		if (ret < 0) {
			dev_err(spimdev->dev, "get_queue failed\n");
			return -ENODEV;
		}
	}
	ret = anon_inode_getfd("spimdev_q", &spimdev_q_file_ops,
			q, O_CLOEXEC | O_RDWR);
	if (ret < 0) {
		dev_err(spimdev->dev, "get queue fd fail %d\n", ret);
		goto err_with_queue;
	}

	q->fd = ret;
	q->spimdev = spimdev;
	q->mdev = mdev;
	init_waitqueue_head(&q->wait);
	get_device(mdev_dev(mdev));

	return ret;

err_with_queue:
	if (_put_queue_to_pool(mdev, q))
		spimdev->ops->put_queue(q);
	return ret;
}

static long vfio_spimdev_mdev_ioctl(struct mdev_device *mdev, unsigned int cmd,
			       unsigned long arg)
{
	struct spimdev_mdev_state *mdev_state;
	struct vfio_spimdev *spimdev;
	struct _spimdev *smdev;

	if (!mdev)
		return -ENODEV;

	smdev = mdev_get_drvdata(mdev);
	if (!smdev)
		return -ENODEV;
	mdev_state = smdev->mstate;
	spimdev = mdev_state->spimdev;
	if (!spimdev)
		return -ENODEV;

	if (cmd == VFIO_SPIMDEV_CMD_GET_Q)
		return vfio_spimdev_mdev_get_queue(mdev, spimdev, arg);

	dev_err(spimdev->dev,
		"%s, ioctl cmd (0x%x) is not supported!\n", __func__, cmd);
	return -EINVAL;
}

static void vfio_spimdev_release(struct device *dev) { }

static int _vfio_mdev_release(struct device *dev, void *data)
{
	struct _spimdev *smdev;
	struct mdev_device *mdev = mdev_from_dev(dev);

	if (mdev) {
		smdev = mdev_get_drvdata(mdev);
		if (!smdev)
			return -ENODEV;
		if (smdev->pid == current->pid)
			_spimdev_put(smdev);
	}

	return 0;
}

static int _vfio_mdevs_release(struct device *dev, void *data)
{
	struct device *pdev = dev->parent;

	return device_for_each_child(pdev, data, _vfio_mdev_release);
}

static void vfio_spimdev_mdev_release(struct mdev_device *mdev)
{
	struct _spimdev *smdev;

	smdev = mdev_get_drvdata(mdev);
	if (!smdev)
		return;
	(void)class_for_each_device(spimdev_class, NULL, NULL,
			_vfio_mdevs_release);
}

static int vfio_spimdev_mdev_open(struct mdev_device *mdev)
{
	return 0;
}

/**
 *	vfio_spimdev_register - register a spimdev
 *	@spimdev: device structure
 */
int vfio_spimdev_register(struct vfio_spimdev *spimdev)
{
	int ret;
	const char *drv_name;
	static atomic_t id = ATOMIC_INIT(-1);
	struct spimdev_mdev_state *mdev_state;

	if (!spimdev->dev)
		return -ENODEV;

	drv_name = dev_driver_string(spimdev->dev);
	if (strstr(drv_name, "-")) {
		pr_err("spimdev: parent driver name cannot include '-'!\n");
		return -EINVAL;
	}
	spimdev->dev_id = (int)atomic_inc_return(&id);
#ifdef CONFIG_NUMA
	spimdev->node_id = spimdev->dev->numa_node;
#endif
	atomic_set(&spimdev->ref, 0);
	spimdev->cls_dev.parent = spimdev->dev;
	spimdev->cls_dev.class = spimdev_class;
	spimdev->cls_dev.release = vfio_spimdev_release;
	dev_set_name(&spimdev->cls_dev, "%s", dev_name(spimdev->dev));
	ret = device_register(&spimdev->cls_dev);
	if (ret)
		return ret;
	mdev_state = devm_kzalloc(spimdev->dev, sizeof(*mdev_state),
				  GFP_KERNEL);
	if (!mdev_state)
		return -ENOMEM;
	mdev_state->spimdev = spimdev;
	atomic_set(&mdev_state->users, 0);
	mutex_init(&mdev_state->lock);
	INIT_LIST_HEAD(&mdev_state->mdev_list);
	spimdev->mstate = mdev_state;
	spimdev->mdev_fops.owner		= spimdev->owner;
	spimdev->mdev_fops.dev_attr_groups	= vfio_spimdev_groups;
	WARN_ON(!spimdev->mdev_fops.supported_type_groups);
	spimdev->mdev_fops.create		= vfio_spimdev_mdev_create;
	spimdev->mdev_fops.remove		= vfio_spimdev_mdev_remove;
	spimdev->mdev_fops.ioctl		= vfio_spimdev_mdev_ioctl;
	spimdev->mdev_fops.open		= vfio_spimdev_mdev_open;
	spimdev->mdev_fops.release		= vfio_spimdev_mdev_release;

	ret = mdev_register_device(spimdev->dev, &spimdev->mdev_fops);
	if (ret)
		device_unregister(&spimdev->cls_dev);

	return ret;
}
EXPORT_SYMBOL_GPL(vfio_spimdev_register);

/**
 * vfio_spimdev_unregister - unregisters a spimdev
 * @spimdev: device to unregister
 *
 * Unregister a miscellaneous device that wat previously successully registered
 * with vfio_spimdev_register().
 */
void vfio_spimdev_unregister(struct vfio_spimdev *spimdev)
{
	struct spimdev_mdev_state *mdev_state = spimdev->mstate;

	if (atomic_read(&mdev_state->users)) {
		dev_warn(spimdev->dev, "\nWARN:some user is on the SPIMDEV!");
		return;
	}
	mdev_unregister_device(spimdev->dev);
	device_unregister(&spimdev->cls_dev);
}
EXPORT_SYMBOL_GPL(vfio_spimdev_unregister);

static int __init vfio_spimdev_init(void)
{
	spimdev_class = class_create(THIS_MODULE, VFIO_SPIMDEV_CLASS_NAME);
	if (IS_ERR(spimdev_class))
		return PTR_ERR_OR_ZERO(spimdev_class);

	/* To support legacy mode well inside, we need this iommu driver */
	return vfio_register_iommu_driver(&vfio_spimdev_iommu_ops);
}

static __exit void vfio_spimdev_exit(void)
{
	vfio_unregister_iommu_driver(&vfio_spimdev_iommu_ops);
	class_destroy(spimdev_class);
}

module_init(vfio_spimdev_init);
module_exit(vfio_spimdev_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Hisilicon Tech. Co., Ltd.");
MODULE_DESCRIPTION("VFIO Share Parent's IOMMU Mediated Device");
