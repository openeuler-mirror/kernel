/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/gmem_dev.h>

static int gmem_get_hnid(unsigned long arg)
{
	void __user *buf = (void __user *)arg;
	struct gmem_hnid_arg gmem_hnid;
	gm_context_t *ctx, *tmp;
	gm_dev_t *gm_dev = NULL;
	gm_as_t *as = NULL;
	int hnuma_id;

	if (!access_ok(buf, sizeof(struct gmem_hnid_arg))) {
		pr_err("access_ok failed\n");
		return -EFAULT;
	}

	if (copy_from_user(&gmem_hnid, buf, sizeof(struct gmem_hnid_arg))) {
		pr_err("copy_from_user failed.\n");
		return -EFAULT;
	}

	if (!current->mm) {
		pr_err("current's mm is null.\n");
		return -EFAULT;
	}

	as = current->mm->gm_as;
	if (!as) {
		pr_err("current isn't gmem task failed.\n");
		return -ENODEV;
	}

	list_for_each_entry_safe(ctx, tmp, &as->gm_ctx_list, gm_as_link) {
		gm_dev = ctx->dev;
		if (gm_dev)
			break;
	}

	if (!gm_dev) {
		pr_err("gmem_id_to_device failed.\n");
		return -ENODEV;
	}

	hnuma_id = first_node(gm_dev->registered_hnodes);
	if (copy_to_user(gmem_hnid.hnuma_id, &hnuma_id, sizeof(int))) {
		pr_err("copy_to_user failed.\n");
		return -EFAULT;
	}

	return 0;
}

static int gmem_hmadvise(unsigned long arg)
{
	struct hmadvise_arg harg;
	void __user *buf;
	int ret;

	buf = (void __user *)arg;
	if (!access_ok(buf, sizeof(struct hmadvise_arg))) {
		pr_err("access_ok failed.\n");
		return -EFAULT;
	}

	if (copy_from_user(&harg, buf, sizeof(struct hmadvise_arg))) {
		pr_err("copy_from_user failed.\n");
		return -EFAULT;
	}

	ret = hmadvise_inner(harg.hnid, harg.start, harg.len_in, harg.behavior);
	return ret;
}

static long gmem_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	long ret = 0;

	if (_IOC_TYPE(cmd) != GMEM_MAGIC) {
		pr_err("invalid cmd magic number '%#x', should '%#x'.\n",
				_IOC_TYPE(cmd), GMEM_MAGIC);
		return -EINVAL;
	}

	switch (cmd) {
	case GMEM_GET_HNUMA_ID:
		ret = gmem_get_hnid(arg);
		break;
	case GMEM_MADVISE:
		ret = gmem_hmadvise(arg);
		break;
	default:
		pr_err("invalid cmd '%#x'.\n", cmd);
		return -EINVAL;
	}

	return ret;
}

static const struct file_operations gmem_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl	= gmem_ioctl,
	.compat_ioctl	= gmem_ioctl,
};

static struct miscdevice gmem_miscdev = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name	= "gmem",
	.fops	= &gmem_fops,
};

builtin_misc_device(gmem_miscdev);
