// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/anon_inodes.h>
#include <linux/uio.h>
#include "internal.h"

static int cachefiles_ondemand_fd_release(struct inode *inode,
					  struct file *file)
{
	struct cachefiles_object *object = file->private_data;
	int object_id = object->ondemand_id;
	struct cachefiles_cache *cache;
	void **slot;
	struct radix_tree_iter iter;
	struct cachefiles_req *req;

	cache = container_of(object->fscache.cache,
			     struct cachefiles_cache, cache);

	xa_lock(&cache->reqs);
	object->ondemand_id = CACHEFILES_ONDEMAND_ID_CLOSED;
	/*
	 * Flush all pending READ requests since their completion depends on
	 * anon_fd.
	 */
	radix_tree_for_each_slot(slot, &cache->reqs, &iter, 0) {
		req = radix_tree_deref_slot_protected(slot,
						      &cache->reqs.xa_lock);
		if (WARN_ON(!req))
			continue;
		if (req->msg.object_id == object_id &&
		    req->msg.opcode == CACHEFILES_OP_READ) {
			req->error = -EIO;
			complete(&req->done);
			radix_tree_iter_delete(&cache->reqs, &iter, slot);
		}
	}
	xa_unlock(&cache->reqs);

	xa_lock(&cache->ondemand_ids.idr_rt);
	idr_remove(&cache->ondemand_ids, object_id);
	xa_unlock(&cache->ondemand_ids.idr_rt);
	object->fscache.cache->ops->put_object(&object->fscache,
			cachefiles_obj_put_ondemand_fd);
	cachefiles_put_unbind_pincount(cache);
	return 0;
}

static ssize_t cachefiles_ondemand_fd_write_iter(struct kiocb *kiocb,
						 struct iov_iter *iter)
{
	struct cachefiles_object *object = kiocb->ki_filp->private_data;
	size_t len = iter->count;
	loff_t pos = kiocb->ki_pos;
	int ret;

	if (!object->file)
		return -ENOBUFS;

	ret = vfs_iter_write(object->file, iter, &pos, 0);
	if (ret != len)
		return -EIO;
	return len;
}

static long cachefiles_ondemand_fd_ioctl(struct file *filp, unsigned int ioctl,
					 unsigned long arg)
{
	struct cachefiles_object *object = filp->private_data;
	struct cachefiles_cache *cache;
	struct cachefiles_req *req;
	unsigned long id;

	if (ioctl != CACHEFILES_IOC_READ_COMPLETE)
		return -EINVAL;

	cache = container_of(object->fscache.cache,
			     struct cachefiles_cache, cache);

	if (!test_bit(CACHEFILES_ONDEMAND_MODE, &cache->flags))
		return -EOPNOTSUPP;

	id = arg;
	xa_lock(&cache->reqs);
	req = radix_tree_delete(&cache->reqs, id);
	xa_unlock(&cache->reqs);
	if (!req)
		return -EINVAL;

	complete(&req->done);
	return 0;
}

static const struct file_operations cachefiles_ondemand_fd_fops = {
	.owner		= THIS_MODULE,
	.release	= cachefiles_ondemand_fd_release,
	.write_iter	= cachefiles_ondemand_fd_write_iter,
	.unlocked_ioctl	= cachefiles_ondemand_fd_ioctl,
};

/*
 * OPEN request Completion (copen)
 * - command: "copen <id>,<cache_size>"
 *   <cache_size> indicates the object size if >=0, error code if negative
 */
int cachefiles_ondemand_copen(struct cachefiles_cache *cache, char *args)
{
	struct cachefiles_req *req;
	struct fscache_cookie *cookie;
	char *pid, *psize;
	unsigned long id;
	long size;
	int ret;

	if (!test_bit(CACHEFILES_ONDEMAND_MODE, &cache->flags))
		return -EOPNOTSUPP;

	if (!*args) {
		pr_err("Empty id specified\n");
		return -EINVAL;
	}

	pid = args;
	psize = strchr(args, ',');
	if (!psize) {
		pr_err("Cache size is not specified\n");
		return -EINVAL;
	}

	*psize = 0;
	psize++;

	ret = kstrtoul(pid, 0, &id);
	if (ret)
		return ret;

	xa_lock(&cache->reqs);
	req = radix_tree_delete(&cache->reqs, id);
	xa_unlock(&cache->reqs);
	if (!req)
		return -EINVAL;

	/* fail OPEN request if copen format is invalid */
	ret = kstrtol(psize, 0, &size);
	if (ret) {
		req->error = ret;
		goto out;
	}

	/* fail OPEN request if daemon reports an error */
	if (size < 0) {
		if (!IS_ERR_VALUE(size)) {
			req->error = -EINVAL;
			ret = -EINVAL;
		} else {
			req->error = size;
			ret = 0;
		}
		goto out;
	}

	cookie = req->object->fscache.cookie;
	fscache_set_store_limit(&req->object->fscache, size);
	if (size)
		clear_bit(FSCACHE_COOKIE_NO_DATA_YET, &cookie->flags);
	else
		set_bit(FSCACHE_COOKIE_NO_DATA_YET, &cookie->flags);

out:
	complete(&req->done);
	return ret;
}

static int cachefiles_ondemand_get_fd(struct cachefiles_req *req)
{
	struct cachefiles_object *object = req->object;
	struct cachefiles_cache *cache;
	struct cachefiles_open *load;
	struct file *file;
	u32 object_id;
	int ret, fd;

	ret = object->fscache.cache->ops->grab_object(&object->fscache,
			cachefiles_obj_get_ondemand_fd) ? 0 : -EAGAIN;
	if (ret)
		return ret;

	cache = container_of(object->fscache.cache,
			     struct cachefiles_cache, cache);
	idr_preload(GFP_KERNEL);
	xa_lock(&cache->ondemand_ids.idr_rt);
	ret = idr_alloc_cyclic(&cache->ondemand_ids, NULL,
			       1, INT_MAX, GFP_ATOMIC);
	xa_unlock(&cache->ondemand_ids.idr_rt);
	idr_preload_end();
	if (ret < 0)
		goto err;
	object_id = ret;

	fd = get_unused_fd_flags(O_WRONLY);
	if (fd < 0) {
		ret = fd;
		goto err_free_id;
	}

	file = anon_inode_getfile("[cachefiles]", &cachefiles_ondemand_fd_fops,
				  object, O_WRONLY);
	if (IS_ERR(file)) {
		ret = PTR_ERR(file);
		goto err_put_fd;
	}

	file->f_mode |= FMODE_PWRITE | FMODE_LSEEK;
	fd_install(fd, file);

	load = (void *)req->msg.data;
	load->fd = fd;
	req->msg.object_id = object_id;
	object->ondemand_id = object_id;

	cachefiles_get_unbind_pincount(cache);
	return 0;

err_put_fd:
	put_unused_fd(fd);
err_free_id:
	xa_lock(&cache->ondemand_ids.idr_rt);
	idr_remove(&cache->ondemand_ids, object_id);
	xa_unlock(&cache->ondemand_ids.idr_rt);
err:
	object->fscache.cache->ops->put_object(&object->fscache,
			cachefiles_obj_put_ondemand_fd);
	return ret;
}

ssize_t cachefiles_ondemand_daemon_read(struct cachefiles_cache *cache,
					char __user *_buffer, size_t buflen, loff_t *pos)
{
	struct cachefiles_req *req = NULL;
	struct cachefiles_msg *msg;
	unsigned long id = 0;
	size_t n;
	int ret = 0;
	struct radix_tree_iter iter;
	void **slot;

	/*
	 * Cyclically search for a request that has not ever been processed,
	 * to prevent requests from being processed repeatedly, and make
	 * request distribution fair.
	 */
	xa_lock(&cache->reqs);
	radix_tree_for_each_tagged(slot, &cache->reqs, &iter, cache->req_id_next,
				   CACHEFILES_REQ_NEW) {
		req = radix_tree_deref_slot_protected(slot, &cache->reqs.xa_lock);
		WARN_ON(!req);
		break;
	}

	if (!req && cache->req_id_next > 0) {
		radix_tree_for_each_tagged(slot, &cache->reqs, &iter, 0,
				CACHEFILES_REQ_NEW) {
			if (iter.index >= cache->req_id_next)
				break;
			req = radix_tree_deref_slot_protected(slot, &cache->reqs.xa_lock);
			WARN_ON(!req);
			break;
		}
	}

	/* no request tagged with CACHEFILES_REQ_NEW found */
	if (!req) {
		xa_unlock(&cache->reqs);
		return 0;
	}

	msg = &req->msg;
	n = msg->len;

	if (n > buflen) {
		xa_unlock(&cache->reqs);
		return -EMSGSIZE;
	}

	radix_tree_iter_tag_clear(&cache->reqs, &iter, CACHEFILES_REQ_NEW);
	cache->req_id_next = iter.index + 1;
	xa_unlock(&cache->reqs);

	id = iter.index;
	msg->msg_id = id;

	if (msg->opcode == CACHEFILES_OP_OPEN) {
		ret = cachefiles_ondemand_get_fd(req);
		if (ret)
			goto error;
	}

	if (copy_to_user(_buffer, msg, n) != 0) {
		ret = -EFAULT;
		goto err_put_fd;
	}

	/* CLOSE request has no reply */
	if (msg->opcode == CACHEFILES_OP_CLOSE) {
		xa_lock(&cache->reqs);
		radix_tree_delete(&cache->reqs, id);
		xa_unlock(&cache->reqs);
		complete(&req->done);
	}
	return n;

err_put_fd:
	if (msg->opcode == CACHEFILES_OP_OPEN)
		__close_fd(current->files,
			   ((struct cachefiles_open *)msg->data)->fd);
error:
	xa_lock(&cache->reqs);
	radix_tree_delete(&cache->reqs, id);
	xa_unlock(&cache->reqs);
	req->error = ret;
	complete(&req->done);
	return ret;
}

typedef int (*init_req_fn)(struct cachefiles_req *req, void *private);

static int cachefiles_ondemand_send_req(struct cachefiles_object *object,
					enum cachefiles_opcode opcode,
					size_t data_len,
					init_req_fn init_req,
					void *private)
{
	static atomic64_t global_index = ATOMIC64_INIT(0);
	struct cachefiles_cache *cache;
	struct cachefiles_req *req;
	long id;
	int ret;

	cache = container_of(object->fscache.cache,
			     struct cachefiles_cache, cache);

	if (!test_bit(CACHEFILES_ONDEMAND_MODE, &cache->flags))
		return 0;

	if (test_bit(CACHEFILES_DEAD, &cache->flags))
		return -EIO;

	req = kzalloc(sizeof(*req) + data_len, GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	req->object = object;
	init_completion(&req->done);
	req->msg.opcode = opcode;
	req->msg.len = sizeof(struct cachefiles_msg) + data_len;

	ret = init_req(req, private);
	if (ret)
		goto out;

	/*
	 * Stop enqueuing the request when daemon is dying. The
	 * following two operations need to be atomic as a whole.
	 *   1) check cache state, and
	 *   2) enqueue request if cache is alive.
	 * Otherwise the request may be enqueued after xarray has been
	 * flushed, leaving the orphan request never being completed.
	 *
	 * CPU 1			CPU 2
	 * =====			=====
	 *				test CACHEFILES_DEAD bit
	 * set CACHEFILES_DEAD bit
	 * flush requests in the xarray
	 *				enqueue the request
	 */
	xa_lock(&cache->reqs);

	if (test_bit(CACHEFILES_DEAD, &cache->flags)) {
		xa_unlock(&cache->reqs);
		ret = -EIO;
		goto out;
	}

	/* coupled with the barrier in cachefiles_flush_reqs() */
	smp_mb();

	if (opcode != CACHEFILES_OP_OPEN && object->ondemand_id <= 0) {
		WARN_ON_ONCE(object->ondemand_id == 0);
		xa_unlock(&cache->reqs);
		ret = -EIO;
		goto out;
	}

	while (radix_tree_insert(&cache->reqs,
				 id = atomic64_read(&global_index), req))
		atomic64_inc(&global_index);

	radix_tree_tag_set(&cache->reqs, id, CACHEFILES_REQ_NEW);
	xa_unlock(&cache->reqs);

	wake_up_all(&cache->daemon_pollwq);
	wait_for_completion(&req->done);
	ret = req->error;
out:
	kfree(req);
	return ret;
}

static int cachefiles_ondemand_init_open_req(struct cachefiles_req *req,
					     void *private)
{
	struct cachefiles_object *object = req->object;
	struct fscache_cookie *cookie = object->fscache.cookie;
	struct fscache_cookie *volume = object->fscache.parent->cookie;
	struct cachefiles_open *load = (void *)req->msg.data;
	size_t volume_key_size, cookie_key_size;
	char *cookie_key, *volume_key;

	/*
	 * cookie_key is a string without trailing '\0', while cachefiles_open
	 * expects cookie key a string without trailing '\0'.
	 */
	cookie_key_size = cookie->key_len;
	if (cookie->key_len <= sizeof(cookie->inline_key))
		cookie_key = cookie->inline_key;
	else
		cookie_key = cookie->key;

	/*
	 * volume_key is a string without trailing '\0', while cachefiles_open
	 * expects volume key a string with trailing '\0'.
	 */
	volume_key_size = volume->key_len + 1;
	if (volume->key_len <= sizeof(volume->inline_key))
		volume_key = volume->inline_key;
	else
		volume_key = volume->key;

	load->volume_key_size = volume_key_size;
	load->cookie_key_size = cookie_key_size;
	memcpy(load->data, volume_key, volume->key_len);
	load->data[volume_key_size - 1] = '\0';
	memcpy(load->data + volume_key_size, cookie_key, cookie_key_size);
	return 0;
}

static int cachefiles_ondemand_init_close_req(struct cachefiles_req *req,
					      void *private)
{
	struct cachefiles_object *object = req->object;
	int object_id = object->ondemand_id;

	/*
	 * It's possible that object id is still 0 if the cookie looking up
	 * phase failed before OPEN request has ever been sent. Also avoid
	 * sending CLOSE request for CACHEFILES_ONDEMAND_ID_CLOSED, which means
	 * anon_fd has already been closed.
	 */
	if (object_id <= 0)
		return -ENOENT;

	req->msg.object_id = object_id;
	return 0;
}

struct cachefiles_read_ctx {
	loff_t off;
	size_t len;
};

static int cachefiles_ondemand_init_read_req(struct cachefiles_req *req,
					     void *private)
{
	struct cachefiles_object *object = req->object;
	struct cachefiles_read *load = (void *)req->msg.data;
	struct cachefiles_read_ctx *read_ctx = private;
	int object_id = object->ondemand_id;

	/* Stop enqueuing requests when daemon has closed anon_fd. */
	if (object_id <= 0) {
		WARN_ON_ONCE(object_id == 0);
		pr_info_once("READ: anonymous fd closed prematurely.\n");
		return -EIO;
	}

	req->msg.object_id = object_id;
	load->off = read_ctx->off;
	load->len = read_ctx->len;
	return 0;
}

int cachefiles_ondemand_init_object(struct cachefiles_object *object)
{
	struct fscache_cookie *cookie = object->fscache.cookie;
	size_t volume_key_size, cookie_key_size, data_len;

	/*
	 * CacheFiles will firstly check the cache file under the root cache
	 * directory. If the coherency check failed, it will fallback to
	 * creating a new tmpfile as the cache file. Reuse the previously
	 * allocated object ID if any.
	 */
	if (object->ondemand_id > 0 || object->type == FSCACHE_COOKIE_TYPE_INDEX)
		return 0;

	volume_key_size = object->fscache.parent->cookie->key_len + 1;
	cookie_key_size = cookie->key_len;
	data_len = sizeof(struct cachefiles_open) + volume_key_size + cookie_key_size;

	return cachefiles_ondemand_send_req(object, CACHEFILES_OP_OPEN,
			data_len, cachefiles_ondemand_init_open_req, NULL);
}

void cachefiles_ondemand_clean_object(struct cachefiles_object *object)
{
	cachefiles_ondemand_send_req(object, CACHEFILES_OP_CLOSE, 0,
			cachefiles_ondemand_init_close_req, NULL);
}

int cachefiles_ondemand_read(struct cachefiles_object *object,
			     loff_t pos, size_t len)
{
	struct cachefiles_read_ctx read_ctx = {pos, len};

	return cachefiles_ondemand_send_req(object, CACHEFILES_OP_READ,
			sizeof(struct cachefiles_read),
			cachefiles_ondemand_init_read_req, &read_ctx);
}
