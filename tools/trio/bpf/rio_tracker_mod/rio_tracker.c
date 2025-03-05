// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2025 Huawei Technologies Co., Ltd
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>

#include <linux/dcache.h>
#include <linux/string.h>
#include <asm/current.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/spinlock.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/mm.h>
#include <linux/uio.h>
#include <linux/err.h>
#include <linux/nsproxy.h>
#include <linux/utsname.h>
#include <linux/printk.h>

/* 20MB for default, changed as your needs */
static uint32_t tracker_buffer_size = 20971520;
module_param(tracker_buffer_size, uint, 0444);

static char *tracker_output = "/";
module_param(tracker_output, charp, 0444);
MODULE_PARM_DESC(tracker_output, "Must be set by the user.");

struct rio_tracker_mgr {
	bool		enable;
	struct kobject	*object;
	char		*host_ns;

	/* buffer for trace */
	spinlock_t	lock;
	char		*data;
	uint32_t	pos;
};

enum {
	TAG_READ = 0,
	TAG_PRE_FAULT = 1,
	TAG_POST_FAULT = 2
};

static struct rio_tracker_mgr rtracker = {0};

ssize_t enable_show(struct kobject *kobj, struct kobj_attribute *attr,
			char *buf)
{
	return sprintf(buf, "%d\n", rtracker.enable);
}

ssize_t enable_store(struct kobject *kobj, struct kobj_attribute *attr,
			 const char *buf, size_t count)
{
	ssize_t ret;
	int value;

	ret = kstrtoint(buf, 10, &value);
	if (ret < 0) {
		pr_err("store attr failed\n");
		return -EINVAL;
	}

	if (0 != value && 1 != value)
		return -EINVAL;

	rtracker.enable = value;
	return count;
}

static void _dump_trace(void)
{
	struct file *filp;
	void *buffer;
	ssize_t ret;
	loff_t pos;

	spin_lock(&rtracker.lock);
	rtracker.data[rtracker.pos] = '\0';
	buffer = rtracker.data;
	spin_unlock(&rtracker.lock);

	filp = filp_open(tracker_output, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (IS_ERR(filp)) {
		pr_warn("dump failed, file(%s) open failed, err:%ld\n",
			tracker_output, PTR_ERR(filp));
		return;
	}

	pos = 0;
	ret = kernel_write(filp, buffer, rtracker.pos, &pos);
	if (ret < 0)
		pr_warn("dump failed, file(%s) write failed, err:%ld, len:%u\n",
			tracker_output, ret, rtracker.pos);
	else
		pr_info("dump to %s %ld bytes successfully!\n",
			tracker_output, ret);
	filp_close(filp, NULL);
}

ssize_t dump_store(struct kobject *kobj, struct kobj_attribute *attr,
		      const char *buf, size_t count)
{
	_dump_trace();
	return count;
}

ssize_t reset_store(struct kobject *kobj, struct kobj_attribute *attr,
			const char *buf, size_t count)
{
	spin_lock(&rtracker.lock);
	rtracker.pos = 0;
	spin_unlock(&rtracker.lock);
	return count;
}

ssize_t host_ns_show(struct kobject *kobj, struct kobj_attribute *attr,
			char *buf)
{
	return sprintf(buf, "%s\n", rtracker.host_ns);
}

ssize_t host_ns_store(struct kobject *kobj, struct kobj_attribute *attr,
			const char *buf, size_t count)
{
	char *new_prefix = kstrdup(buf, GFP_KERNEL);

	if (!new_prefix)
		return -ENOMEM;

	swap(rtracker.host_ns, new_prefix);
	kfree(new_prefix);
	return count;
}

static struct kobj_attribute enable_attr =
	__ATTR(enable, 0664, enable_show, enable_store);
struct kobj_attribute dump_attr =
	__ATTR(dump, 0200, NULL, dump_store);
struct kobj_attribute reset_attr =
	__ATTR(reset, 0200, NULL, reset_store);
struct kobj_attribute host_ns_attr =
	__ATTR(host_ns, 0664, host_ns_show, host_ns_store);

static struct attribute *tracker_kobj_attrs[] = {
	&enable_attr.attr,
	&dump_attr.attr,
	&reset_attr.attr,
	&host_ns_attr.attr,
	NULL,
};

const struct attribute_group tracker_attr_group = {
	.attrs = tracker_kobj_attrs,
};

__diag_push();
__diag_ignore_all("-Wmissing-prototypes",
"Global functions as their definitions will be in rio_tracker.ko BTF");

static inline bool _target_process(const char *name)
{
	if (!rtracker.host_ns)
		return false;

	return !!str_has_prefix(name, rtracker.host_ns);
}

static void mark_rio(struct file *file, unsigned long off, unsigned long len)
{
	const struct path *path = (const struct path *)&(file->f_path);
	char buff[256] = {0};
	char *ret_path = NULL;
	int written;

	/* only track regular file */
	if (!S_ISREG(file_inode(file)->i_mode))
		return;

	ret_path = d_path(path, buff, sizeof(buff));
	if (IS_ERR(ret_path)) {
		pr_err("get fpath failed, ret:%ld\n", PTR_ERR(ret_path));
		return;
	}

	spin_lock(&rtracker.lock);
	if (rtracker.pos >= tracker_buffer_size) {
		spin_unlock(&rtracker.lock);
		pr_err("tracker buffer is not enough, please enlarge it!\n");
		return;
	}

	/* fill each trace item */
	written = snprintf(rtracker.data + rtracker.pos,
			   tracker_buffer_size - rtracker.pos, "%s,%lu,%lu,%lu\n",
			   ret_path, file_inode(file)->i_ino, off, len);
	if (written >= 0 && written <= tracker_buffer_size - rtracker.pos) {
		rtracker.pos += written;
	} else {
		pr_warn("trace data append failed for path:%s, off:%lu, len:%lu\n",
			ret_path, off, len);
	}
	spin_unlock(&rtracker.lock);
}

void bpf_tracker_rio_read(unsigned long addr1, unsigned long addr2)
{
	struct kiocb *iocb = (struct kiocb *)addr1;
	struct iov_iter *to = (struct iov_iter *)addr2;
	struct file *filp;
	size_t size, count;
	loff_t foff;

	filp = iocb->ki_filp;
	count = iov_iter_count(to);
	foff = (iocb->ki_pos >> PAGE_SHIFT) << PAGE_SHIFT;
	size = ((count >> PAGE_SHIFT) + 1) << PAGE_SHIFT;
	mark_rio(filp, foff, size);
}

void bpf_tracker_rio_pre_fault(unsigned long addr)
{
	struct vm_fault *vmf = (struct vm_fault *)addr;
	struct file *file = vmf->vma->vm_file;
	struct inode *inode;
	struct address_space *mapping;
	struct folio *folio;
	pgoff_t max_idx, index;
	loff_t off;
	size_t len;

	if (!file)
		return;

	mapping = file->f_mapping;
	inode = mapping->host;
	index = vmf->pgoff;
	max_idx = DIV_ROUND_UP(i_size_read(inode), PAGE_SIZE);
	if (index >= max_idx)
		return;
	folio = filemap_get_folio(mapping, index);
	if (IS_ERR(folio))
		return;
	off = folio_pos(folio);
	len = folio_size(folio);
	folio_put(folio);

	mark_rio(file, off, len);
}

void bpf_tracker_rio_post_fault(unsigned long addr)
{
	struct vm_fault *vmf = (struct vm_fault *)addr;
	struct vm_area_struct *vma = vmf->vma;
	bool is_cow = (vmf->flags & FAULT_FLAG_WRITE) &&
		      !(vma->vm_flags & VM_SHARED);
	struct file *file = vmf->vma->vm_file;
	struct folio *folio;

	/* only tracker the fault by reading */
	if (is_cow)
		return;

	if (!file)
		return;

	folio = page_folio(vmf->page);
	mark_rio(file, folio_pos(folio), folio_size(folio));
}

__bpf_kfunc void bpf_tracker_rio(unsigned long addr1, unsigned long addr2,
				      int tag)
{
	if (!rtracker.enable)
		return;

	/* only track the matched UTS namespace */
	if (!_target_process(current->nsproxy->uts_ns->name.nodename))
		return;

	switch (tag) {
	case TAG_READ:
		bpf_tracker_rio_read(addr1, addr2);
		break;
	case TAG_PRE_FAULT:
		bpf_tracker_rio_pre_fault(addr1);
		break;
	case TAG_POST_FAULT:
		bpf_tracker_rio_post_fault(addr1);
		break;
	}
}

__diag_pop();

BTF_SET8_START(bpf_rio_tracker_ids)
BTF_ID_FLAGS(func, bpf_tracker_rio)
BTF_SET8_END(bpf_rio_tracker_ids)

static const struct btf_kfunc_id_set kfuncs_set = {
	.owner = THIS_MODULE,
	.set = &bpf_rio_tracker_ids,
};

static __init int rio_tracker_init(void)
{
	struct file *filp = filp_open(tracker_output, O_RDWR | O_CREAT, 0644);
	int ret;

	if (IS_ERR(filp)) {
		pr_err("rio tracker parameter error, %s is invalid, err:%ld\n",
		       tracker_output, PTR_ERR(filp));
		return -EINVAL;
	}
	filp_close(filp, NULL);

	rtracker.enable = false;
	rtracker.object = kobject_create_and_add("rio_tracker", kernel_kobj);
	ret = sysfs_create_group(rtracker.object, &tracker_attr_group);
	if (ret < 0) {
		pr_err("rio tracker init failed, sysfs kobject create failed\n");
		kobject_put(rtracker.object);
		return ret;
	}

	rtracker.data = vmalloc(tracker_buffer_size + 1);
	if (!rtracker.data) {
		ret = -ENOMEM;
		goto cleanup;
	}
	spin_lock_init(&rtracker.lock);
	rtracker.pos = 0;

	/* register self-defined bpf helper */
	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC, &kfuncs_set);
	if (ret) {
		pr_err("register btf kfunc error with retcode:%d\n", ret);
		goto cleanup;
	}

	pr_info("rio tracker init success!\n");
	return 0;

cleanup:
	if (rtracker.data)
		vfree(rtracker.data);
	kobject_put(rtracker.object);
	return ret;
}

static __exit void rio_tracker_exit(void)
{
	_dump_trace();
	kfree(rtracker.host_ns);
	vfree(rtracker.data);
	kobject_put(rtracker.object);
	pr_info("rio tracker exit\n");
}

module_init(rio_tracker_init);
module_exit(rio_tracker_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("Runtime io Tracker module!");
