// SPDX-License-Identifier: GPL-2.0-only
#include <linux/module.h>
#include <linux/memblock.h>
#include <linux/slab.h>
#include <linux/miscdevice.h>
#include <linux/preempt.h>
#include <asm/virtcca_cvm_guest.h>
#include <asm/virtcca_cvm_smc.h>
#include <asm/virtcca_cvm_tsi.h>
#include <linux/virtcca_cvm_domain.h>

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
static int tmm_get_set_migration_info(struct virtcca_migvm_info __user *arg);
static int tmm_migvm_mem_checksum_loop(struct virtcca_migvm_checksum_info checksum_info);
static int tmm_tsi_data_key_gen(struct virtcca_tsi_data_key_attr __user *arg);
static int tmm_tsi_data_key_enc(struct virtcca_usr_data_key_enc_s __user *arg);

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
	struct virtcca_migvm_checksum_info checksum_info;
	void __user *argp = (void __user *)arg;

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
	case TMM_GET_MIGRATION_INFO:
		ret = tmm_get_set_migration_info((struct virtcca_migvm_info *)arg);
		break;
	case TMM_GET_MIGVM_MEM_CHECKSUM:
		if (copy_from_user(&checksum_info, argp,
			sizeof(struct virtcca_migvm_checksum_info))) {
			pr_err("tmm_tsi: mem checksum copy data from user failed\n");
			return -ENOTTY;
		}
		ret = tmm_migvm_mem_checksum_loop(checksum_info);
		break;
	case TMM_DATA_KEY_GEN:
		ret = tmm_tsi_data_key_gen((struct virtcca_tsi_data_key_attr __user *)arg);
		break;
	case TMM_DATA_KEY_ENC:
		ret = tmm_tsi_data_key_enc((struct virtcca_usr_data_key_enc_s __user *)arg);
		break;
	default:
		pr_err("tmm_tsi: unknown ioctl command (0x%x)!\n", cmd);
		return -ENOTTY;
	}

	return ret;
}

static int tmm_migvm_mem_checksum_loop(struct virtcca_migvm_checksum_info checksum_info)
{
	unsigned long ret;

	ret = tsi_mig_integrity_checksum_loop(checksum_info.guest_rd, checksum_info.thread_id);

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

static int tmm_get_set_migration_info(struct virtcca_migvm_info __user *arg)
{
	unsigned long ret = 0;
	struct virtcca_migvm_info migvm_info = {0};
	struct pending_guest_rd_s *rdcontent = NULL;

	if (!access_ok(arg, sizeof(*arg))) {
		pr_err("tmm_tsi: invalid user pointer\n");
		ret = -EFAULT;
		goto out;
	}

	ret = copy_from_user(&migvm_info, arg, sizeof(struct virtcca_migvm_info));
	if (ret) {
		pr_err("tmm_tsi: copy challenge from user failed (%lu)!\n", ret);
		ret = -EFAULT;
		goto out;
	}

	if (migvm_info.content) {
		if (!access_ok(migvm_info.content, migvm_info.size)) {
			pr_err("tmm_tsi: invalid content address\n");
			ret = -EFAULT;
			goto out;
		}
	} else {
		pr_err("tmm_tsi: invalid content pointer\n");
		goto out;
	}

	struct migration_info *kcontent = kmalloc(sizeof(struct migration_info), GFP_KERNEL);

	if (!kcontent) {
		ret = -ENOMEM;
		goto out;
	}
	if (sizeof(struct migration_info) != migvm_info.size) {
		pr_err("tmm_tsi: size mismatch\n");
		ret = -EINVAL;
		goto out;
	}

	switch (migvm_info.ops) {
	case OP_MIGRATE_GET_ATTR: {
		if (copy_from_user(kcontent, migvm_info.content, migvm_info.size)) {
			pr_err("tmm_tsi: copy slot value failed\n");
			ret = -EFAULT;
			goto out;
		}
		ret = tsi_migvm_get_attr(migvm_info.guest_rd, kcontent);
		if (!ret) {
			if (copy_to_user(migvm_info.content, kcontent, migvm_info.size)) {
				pr_err("tmm_tsi: copy to user failed\n");
				ret = -EFAULT;
			}
			pr_info("tmm_tsi: OP_MIGRATE_GET_ATTRT\n");
		} else {
			pr_err("tmm_tsi: get attr failed, ret = 0x%lx\n", ret);
		}

		break;
	}
	case OP_MIGRATE_SET_SLOT: {
		if (copy_from_user(kcontent, migvm_info.content, migvm_info.size)) {
			pr_err("tmm_tsi: copy slot value failed\n");
			ret = -EFAULT;
			goto out;
		}
		ret = tsi_migvm_set_slot(migvm_info.guest_rd, kcontent);
		if (ret) {
			pr_err("tmm_tsi: set slot failed, ret = %lx\n", ret);
			ret = -EINVAL;
		}
		break;
	}
	case OP_MIGRATE_PEEK_RDS: {
		if (copy_from_user(kcontent, migvm_info.content, migvm_info.size)) {
			pr_err("tmm_tsi: copy slot value failed\n");
			ret = -EFAULT;
			goto out;
		}

		if (kcontent->pending_guest_rds) {
			if (!access_ok(kcontent->pending_guest_rds,
				sizeof(struct pending_guest_rd_s))) {
				pr_err("tmm_tsi: invalid content pending guest rds address\n");
				ret = -EFAULT;
				goto out;
			}
		} else {
			pr_err("tmm_tsi: invalid content pending guest rds pointer\n");
			ret = -ENOMEM;
			goto out;
		}

		rdcontent = kmalloc(sizeof(struct pending_guest_rd_s), GFP_KERNEL);
		if (!rdcontent) {
			ret = -ENOMEM;
			goto out;
		}

		if (copy_from_user(rdcontent, kcontent->pending_guest_rds,
			sizeof(struct pending_guest_rd_s))) {
			pr_err("tmm_tsi: copy slot value failed\n");
			ret = -EFAULT;
			goto out;
		}

		ret = tsi_peek_binding_list(rdcontent);
		if (!ret) {
			if (copy_to_user(kcontent->pending_guest_rds, rdcontent,
			sizeof(struct pending_guest_rd_s))) {
				pr_err("tmm_tsi: copy to user failed\n");
				ret = -EFAULT;
			}
		} else {
			pr_err("tmm_tsi: peek rds failed, ret = 0x%lx\n", ret);
		}
		break;
	}
	default:
		pr_err("tmm_tsi: invalid operation (%u)!\n", migvm_info.ops);
		ret = -EINVAL;
	}

out:
	kfree(kcontent);
	kfree(rdcontent);

	return ret;
}

static int tmm_tsi_data_key_gen(struct virtcca_tsi_data_key_attr __user *arg)
{
	int ret = 0;
	struct virtcca_tsi_data_key_attr *key_attr = NULL;

	if (!arg) {
		pr_err("tmm_tsi: tsi_data_key_gen: arg is NULL\n");
		return -EINVAL;
	}

	key_attr = kmalloc(sizeof(struct virtcca_tsi_data_key_attr), GFP_KERNEL);
	if (!key_attr)
		return -ENOMEM;

	if (copy_from_user(key_attr, arg,
						sizeof(struct virtcca_tsi_data_key_attr))) {
		pr_err("tmm_tsi: tsi_data_key_gen: failed to copy key_attr from user\n");
		ret = -EFAULT;
		goto out;
	}

	ret = tsi_data_key_gen(key_attr);
	if (ret) {
		pr_err("tmm_tsi: tsi_data_key_gen failed, ret=%d\n", ret);
		ret = -EFAULT;
		goto out;
	}

	if (copy_to_user(arg, key_attr,
		sizeof(struct virtcca_tsi_data_key_attr))) {
		ret = -EFAULT;
		goto out;
	}

out:
	kfree(key_attr);
	return ret;
}

static int tmm_tsi_data_key_enc(struct virtcca_usr_data_key_enc_s __user *arg)
{
	int ret = 0;
	struct virtcca_usr_data_key_enc_s *usr_data = NULL;
	struct virtcca_raw_data_kern_ctx kern_ctx = {0};

	if (!arg) {
		pr_err("tmm_tsi: tsi_data_key_enc: arg is NULL\n");
		return -EINVAL;
	}

	usr_data = kmalloc(sizeof(struct virtcca_usr_data_key_enc_s), GFP_KERNEL);
	if (!usr_data)
		return -ENOMEM;

	if (copy_from_user(usr_data, arg,
						sizeof(struct virtcca_usr_data_key_enc_s))) {
		pr_err("tmm_tsi: tsi_data_key_enc: failed to copy usr_data from user\n");
		ret = -EFAULT;
		goto out;
	}

	if (usr_data->raw_data_attr.mode != DATA_ENC_MODE &&
		usr_data->raw_data_attr.mode != DATA_DEC_MODE) {
		pr_err("%s: invalid mode %d, must be %d(ENC) or %d(DEC)\n",
			__func__, usr_data->raw_data_attr.mode, DATA_ENC_MODE, DATA_DEC_MODE);
		ret = -EINVAL;
		goto out;
	}

	if (usr_data->raw_data_attr.ciphertext_len > MAX_DATA_KEY_BUF_SIZE ||
		usr_data->raw_data_attr.plaintext_len > MAX_DATA_KEY_BUF_SIZE) {
		pr_err("%s: buffer size exceeds limit, ciphertext_len=%u, plaintext_len=%u, max=%d\n",
			__func__, usr_data->raw_data_attr.ciphertext_len,
			usr_data->raw_data_attr.plaintext_len, MAX_DATA_KEY_BUF_SIZE);
		ret = -EINVAL;
		goto out;
	}

	if (!access_ok((void __user *)usr_data->raw_data_attr.ciphertext_p,
							usr_data->raw_data_attr.ciphertext_len) ||
		!access_ok((void __user *)usr_data->raw_data_attr.plaintext_p,
							usr_data->raw_data_attr.plaintext_len)) {
		pr_err("%s: invalid user data pointer\n", __func__);
		ret = -EFAULT;
		goto out;
	}

	ret = virtcca_raw_data_attr_user_to_kernel(usr_data, &kern_ctx);
	if (ret)
		goto out;

	if (kern_ctx.ciphertext_buf)
		kern_ctx.kern_attr->ciphertext_p = (uint64_t)__pa(kern_ctx.ciphertext_buf);
	if (kern_ctx.plaintext_buf)
		kern_ctx.kern_attr->plaintext_p = (uint64_t)__pa(kern_ctx.plaintext_buf);

	ret = tsi_data_key_enc(kern_ctx.kern_key_attr, kern_ctx.kern_attr);
	if (ret) {
		pr_err("tmm_tsi: tsi_data_key_enc failed, ret=%d\n", ret);
		ret = -EFAULT;
		goto out_cleanup;
	}

	ret = virtcca_raw_data_attr_kernel_to_user(arg, usr_data, &kern_ctx);
	if (ret)
		goto out;

	goto out;

out_cleanup:
	virtcca_raw_data_kern_ctx_cleanup(&kern_ctx);
out:
	kfree(usr_data);

	return ret;
}


module_init(tmm_tsi_init);
module_exit(tmm_tsi_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("HUAWEI TECHNOLOGIES CO., LTD.");
MODULE_DESCRIPTION("Interacting with TMM through TSI interface from user space.");
