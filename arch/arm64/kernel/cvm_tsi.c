// SPDX-License-Identifier: GPL-2.0-only
#include <linux/module.h>
#include <linux/memblock.h>
#include <linux/slab.h>
#include <linux/miscdevice.h>
#include <linux/preempt.h>
#include <asm/cvm_smc.h>
#include <asm/cvm_tsi.h>

#define GRANULE_SIZE PAGE_SIZE

struct attestation_token {
	void *buf;
	unsigned long size;
};

static struct attestation_token token;

static long tmm_tsi_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
static int tmm_tsi_release(struct inode *inode, struct file *file);
static ssize_t tmm_token_read(struct file *file, char __user *user_buffer,
	size_t size, loff_t *offset);

static int tmm_get_tsi_version(struct cvm_tsi_version __user *arg);
static int tmm_get_attestation_token(struct cvm_attestation_cmd __user *arg,
	struct attestation_token *attest_token);
static int tmm_get_device_cert(struct cca_device_cert __user *arg);

static const struct file_operations tmm_tsi_fops = {
	.owner          = THIS_MODULE,
	.read           = tmm_token_read,
	.release        = tmm_tsi_release,
	.unlocked_ioctl = tmm_tsi_ioctl
};

static struct miscdevice ioctl_dev = {
	MISC_DYNAMIC_MINOR,
	"tsi",
	&tmm_tsi_fops,
};

static int __init tmm_tsi_init(void)
{
	unsigned long ver;
	int ret;

	ver = tsi_get_version();
	if (ver == SMCCC_RET_NOT_SUPPORTED) {
		pr_err("tmm_tsi: SMC return not supported!\n");
		return -EIO;
	}

	ret = misc_register(&ioctl_dev);
	if (ret) {
		pr_err("tmm_tsi: misc device register failed (%d)!\n", ret);
		return ret;
	}

	pr_warn("tmm_tsi: module loaded (version %lu.%lu).\n",
			TSI_ABI_VERSION_GET_MAJOR(ver),
			TSI_ABI_VERSION_GET_MINOR(ver));

	return 0;
}

static void __exit tmm_tsi_exit(void)
{
	if (token.buf != NULL)
		kfree(token.buf);
	misc_deregister(&ioctl_dev);
	pr_warn("tmm_tsi: module unloaded.\n");
}

static long tmm_tsi_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret;

	switch (cmd) {
	case TMM_GET_TSI_VERSION:
		ret = tmm_get_tsi_version((struct cvm_tsi_version *)arg);
		break;
	case TMM_GET_ATTESTATION_TOKEN:
		ret = tmm_get_attestation_token((struct cvm_attestation_cmd *)arg, &token);
		break;
	case TMM_GET_DEVICE_CERT:
		ret = tmm_get_device_cert((struct cca_device_cert *)arg);
		break;
	default:
		pr_err("tmm_tsi: unknown ioctl command (0x%x)!\n", cmd);
		return -ENOTTY;
	}

	return ret;
}

static ssize_t tmm_token_read(struct file *file, char __user *user_buffer,
	size_t size, loff_t *offset)
{
	int ret;
	int to_copy;

	if (*offset >= token.size)
		return 0;

	to_copy = min((int)size, (int)(token.size - *offset));
	ret = copy_to_user(user_buffer, token.buf + *offset, to_copy);
	if (ret) {
		pr_err("tmm_tsi: copy token to user failed (%d)!\n", ret);
		return -1;
	}

	*offset += to_copy;
	return to_copy;
}

static int tmm_tsi_release(struct inode *inode, struct file *file)
{
	if (token.buf != NULL) {
		memset(token.buf, 0, GRANULE_SIZE * MAX_TOKEN_GRANULE_PAGE);
		kfree(token.buf);
	}
	return 0;
}

static int tmm_get_tsi_version(struct cvm_tsi_version __user *arg)
{
	struct cvm_tsi_version ver_measured = {0};
	unsigned long ver;
	unsigned long ret;

	ver = tsi_get_version();
	ver_measured.major = TSI_ABI_VERSION_GET_MAJOR(ver);
	ver_measured.minor = TSI_ABI_VERSION_GET_MINOR(ver);

	ret = copy_to_user(arg, &ver_measured, sizeof(struct cvm_tsi_version));
	if (ret) {
		pr_err("tmm_tsi: copy data to user failed (%lu)!\n", ret);
		return -EFAULT;
	}

	return 0;
}

static int tmm_get_attestation_token(struct cvm_attestation_cmd __user *arg,
	struct attestation_token *attest_token)
{
	unsigned long ret;
	struct cvm_attestation_cmd cmd = {0};

	ret = copy_from_user(&(cmd.challenge), &(arg->challenge), sizeof(cmd.challenge));
	if (ret) {
		pr_err("tmm_tsi: copy data from user failed (%lu)!\n", ret);
		return -EFAULT;
	}

	/* Allocate a large memory */
	attest_token->buf = kmalloc(GRANULE_SIZE * MAX_TOKEN_GRANULE_PAGE, GFP_KERNEL);
	if (!attest_token->buf)
		return -ENOMEM;
	cmd.granule_head = attest_token->buf;
	cmd.granule_ipa  = cmd.granule_head;

	/* preempt_disable(); */

	ret = tsi_attestation_token_init(&cmd);
	if (ret) {
		pr_err("tmm_tsi: tsi call tsi_attestation_token_init failed (%lu)!\n", ret);
		return -EIO;
	}

	do { /* Retrieve one Granule of data per loop iteration */
		cmd.granule_ipa = cmd.granule_head +
			(unsigned long)(cmd.granule_count * GRANULE_SIZE);
		cmd.offset = 0;

		do { /* Retrieve sub-Granule chunk of data per loop iteration */
			cmd.size = GRANULE_SIZE - cmd.offset;
			ret = tsi_attestation_token_continue(&cmd);
			cmd.offset += cmd.num_wr_bytes;
		} while (ret == TSI_INCOMPLETE && cmd.offset < GRANULE_SIZE);

		cmd.granule_count += 1;
		if (cmd.granule_count >= MAX_TOKEN_GRANULE_PAGE && ret == TSI_INCOMPLETE) {
			pr_err("tmm_tsi: macro MAX_TOKEN_GRANULE_PAGE (%d) is too small!\n",
				MAX_TOKEN_GRANULE_PAGE);
			return -ENOMEM;
		}

	} while (ret == TSI_INCOMPLETE);

	/* preempt_enable(); */

	/* Send to user space the total size of the token */
	cmd.granule_count = cmd.granule_count - 1;
	cmd.token_size = (unsigned long)(GRANULE_SIZE * cmd.granule_count) + cmd.offset;
	attest_token->size = cmd.token_size;

	ret = copy_to_user(&(arg->token_size), &(cmd.token_size), sizeof(cmd.token_size));
	if (ret) {
		pr_err("tmm_tsi: copy data to user failed (%lu)!\n", ret);
		return -EFAULT;
	}

	return 0;
}

static int tmm_get_device_cert(struct cca_device_cert __user *arg)
{
	unsigned long ret;
	unsigned char *device_cert;
	unsigned long device_cert_size;

	device_cert_size = MAX_DEV_CERT_SIZE;
	device_cert = kmalloc(device_cert_size, GFP_KERNEL);
	if (!device_cert)
		return -ENOMEM;
	ret = tsi_get_device_cert(device_cert, &device_cert_size);
	if (ret != TSI_SUCCESS) {
		pr_err("tmm_tsi: tsi call tsi_get_device_cert failed (%lu)!\n", ret);
		kfree(device_cert);
		return -EIO;
	}

	ret = copy_to_user(arg->value, device_cert, device_cert_size);
	if (ret) {
		pr_err("tmm_tsi: copy data to user failed (%lu)!\n", ret);
		kfree(device_cert);
		return -EFAULT;
	}
	kfree(device_cert);

	ret = copy_to_user(&(arg->size), &device_cert_size, sizeof(device_cert_size));
	if (ret) {
		pr_err("tmm_tsi: copy data to user failed (%lu)!\n", ret);
		return -EFAULT;
	}

	return 0;
}

module_init(tmm_tsi_init);
module_exit(tmm_tsi_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("HUAWEI TECHNOLOGIES CO., LTD.");
MODULE_DESCRIPTION("Interacting with TMM through TSI interface from user space.");
