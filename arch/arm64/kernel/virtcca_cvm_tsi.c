// SPDX-License-Identifier: GPL-2.0-only
#include <linux/module.h>
#include <linux/memblock.h>
#include <linux/slab.h>
#include <linux/miscdevice.h>
#include <linux/preempt.h>
#include <asm/virtcca_cvm_guest.h>
#include <asm/virtcca_cvm_smc.h>
#include <asm/virtcca_cvm_tsi.h>

struct attestation_token {
	void *buf;
	unsigned long size;
};

static struct attestation_token token;

static DEFINE_MUTEX(token_lock);

static long tmm_tsi_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

static int tmm_get_tsi_version(struct virtcca_cvm_tsi_version __user *arg);
static int tmm_get_attestation_token(struct virtcca_cvm_attestation_cmd __user *arg);
static int tmm_get_device_cert(struct virtcca_device_cert __user *arg);

static const struct file_operations tmm_tsi_fops = {
	.owner          = THIS_MODULE,
	.unlocked_ioctl = tmm_tsi_ioctl
};

static struct miscdevice ioctl_dev = {
	MISC_DYNAMIC_MINOR,
	"tsi",
	&tmm_tsi_fops,
};

static int __init tmm_tsi_init(void)
{
	int ret;

	if (!is_virtcca_cvm_world())
		return -EIO;

	ret = misc_register(&ioctl_dev);
	if (ret) {
		pr_err("tmm_tsi: misc device register failed (%d)!\n", ret);
		return ret;
	}

	/* Allocate a large memory */
	token.buf = kzalloc(GRANULE_SIZE * MAX_TOKEN_GRANULE_COUNT, GFP_KERNEL);
	if (!token.buf)
		return -ENOMEM;

	return 0;
}

static void __exit tmm_tsi_exit(void)
{
	if (token.buf != NULL) {
		memset(token.buf, 0, GRANULE_SIZE * MAX_TOKEN_GRANULE_COUNT);
		kfree(token.buf);
	}
	misc_deregister(&ioctl_dev);
	pr_warn("tmm_tsi: module unloaded.\n");
}

static long tmm_tsi_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret;

	switch (cmd) {
	case TMM_GET_TSI_VERSION:
		ret = tmm_get_tsi_version((struct virtcca_cvm_tsi_version *)arg);
		break;
	case TMM_GET_ATTESTATION_TOKEN:
		ret = tmm_get_attestation_token((struct virtcca_cvm_attestation_cmd *)arg);
		break;
	case TMM_GET_DEVICE_CERT:
		ret = tmm_get_device_cert((struct virtcca_device_cert *)arg);
		break;
	default:
		pr_err("tmm_tsi: unknown ioctl command (0x%x)!\n", cmd);
		return -ENOTTY;
	}

	return ret;
}

static int tmm_get_tsi_version(struct virtcca_cvm_tsi_version __user *arg)
{
	struct virtcca_cvm_tsi_version ver_measured = {0};
	unsigned long ver;
	unsigned long ret;

	ver = tsi_get_version();
	ver_measured.major = TSI_ABI_VERSION_GET_MAJOR(ver);
	ver_measured.minor = TSI_ABI_VERSION_GET_MINOR(ver);

	ret = copy_to_user(arg, &ver_measured, sizeof(struct virtcca_cvm_tsi_version));
	if (ret) {
		pr_err("tmm_tsi: copy data to user failed (%lu)!\n", ret);
		return -EFAULT;
	}

	return 0;
}

static int tmm_get_attestation_token(struct virtcca_cvm_attestation_cmd __user *arg)
{
	unsigned long ret;
	struct virtcca_cvm_token_granule token_granule = {0};
	unsigned char challenge[CHALLENGE_SIZE];

	ret = copy_from_user(challenge, &(arg->challenge), CHALLENGE_SIZE);
	if (ret) {
		pr_err("tmm_tsi: copy challenge from user failed (%lu)!\n", ret);
		return -EFAULT;
	}

	mutex_lock(&token_lock);
	token_granule.head = token.buf;
	token_granule.ipa  = token_granule.head;

	ret = tsi_attestation_token_init(challenge);
	if (ret) {
		pr_err("tmm_tsi: tsi call tsi_attestation_token_init failed (%lu)!\n", ret);
		mutex_unlock(&token_lock);
		return -EIO;
	}

	do { /* Retrieve one Granule of data per loop iteration */
		if (token_granule.count + 1 > MAX_TOKEN_GRANULE_COUNT) {
			pr_err("tmm_tsi: macro MAX_TOKEN_GRANULE_COUNT (%d) is too small!\n",
				MAX_TOKEN_GRANULE_COUNT);
			mutex_unlock(&token_lock);
			return -ENOMEM;
		}
		token_granule.ipa = token_granule.head + (token_granule.count * GRANULE_SIZE);
		token_granule.offset = 0;

		do { /* Retrieve sub-Granule chunk of data per loop iteration */
			token_granule.size = GRANULE_SIZE - token_granule.offset;
			ret = tsi_attestation_token_continue(&token_granule);
			token_granule.offset += token_granule.num_wr_bytes;
		} while (ret == TSI_INCOMPLETE && token_granule.offset < GRANULE_SIZE);

		token_granule.count++;

	} while (ret == TSI_INCOMPLETE);

	/* Send to user space the total size of the token */
	token.size = (GRANULE_SIZE * (token_granule.count - 1)) + token_granule.offset;

	ret = copy_to_user(&(arg->token_size), &(token.size), sizeof(token.size));
	if (ret) {
		pr_err("tmm_tsi: copy token_size to user failed (%lu)!\n", ret);
		mutex_unlock(&token_lock);
		return -EFAULT;
	}

	ret = copy_to_user(arg->token, token.buf, token.size);
	if (ret) {
		pr_err("tmm_tsi: copy token to user failed (%lu)!\n", ret);
		mutex_unlock(&token_lock);
		return -EFAULT;
	}
	mutex_unlock(&token_lock);

	return 0;
}

static int tmm_get_device_cert(struct virtcca_device_cert __user *arg)
{
	unsigned long ret;
	unsigned char *device_cert;
	unsigned long device_cert_size;

	device_cert_size = MAX_DEV_CERT_SIZE;
	device_cert = kzalloc(device_cert_size, GFP_KERNEL);
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
