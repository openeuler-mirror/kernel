// SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
#include <linux/debugfs.h>
#include <linux/timer.h>
#include "grc.h"
#include "main.h"
#include "dbgfs.h"

// 1000ms
#define NBL_CACHE_HIT_INTERVAL_MAX 1000
#define NBL_IN_PARAM_LEN 8
#define NBL_OUT_PARAM_LEN 896

static const char *const nbl_dbg_cache_hit_name[] = {
	"all_cache_hit",
};

static const char *const nbl_dbg_cache_hit_print[] = {
	"qpcc",
	"cqcc",
	"mrtc",
	"pblc",
	"sqrqec",
	"unaqc",
	"srqc",
	"pdc",
	"iorqec",
	"raqec",
};

static void nbl_dump_hw_cache_hit(struct nbl_device *nbl_dev)
{
	u32 i;
	u32 reg_base[NBL_CACHE_HIT_MAX];
	u32 total_stats[NBL_CACHE_HIT_MAX] = {0};
	u32 miss_stats[NBL_CACHE_HIT_MAX] = {0};

	for (i = 0; i < NBL_CACHE_HIT_MAX; i++) {
		switch (i) {
		case NBL_CACHE_HIT_QPCC:
			reg_base[i] = NBL_REG_QPCC_BASE(&nbl_dev->rf->hw);
			break;
		case NBL_CACHE_HIT_CQCC:
			reg_base[i] = NBL_REG_CQCC_BASE(&nbl_dev->rf->hw);
			break;
		case NBL_CACHE_HIT_MRTC:
			reg_base[i] = NBL_REG_MRTC_BASE(&nbl_dev->rf->hw);
			break;
		case NBL_CACHE_HIT_PBLC:
			reg_base[i] = NBL_REG_PBLC_BASE(&nbl_dev->rf->hw);
			break;
		case NBL_CACHE_HIT_SQRQEC:
			reg_base[i] = NBL_REG_SQRQEC_BASE(&nbl_dev->rf->hw);
			break;
		case NBL_CACHE_HIT_UNAQC:
			reg_base[i] = NBL_REG_UNAQC_BASE(&nbl_dev->rf->hw);
			break;
		case NBL_CACHE_HIT_SRQC:
			reg_base[i] = NBL_REG_SRQC_BASE(&nbl_dev->rf->hw);
			break;
		case NBL_CACHE_HIT_PDC:
			reg_base[i] = NBL_REG_PDC_BASE(&nbl_dev->rf->hw);
			break;
		case NBL_CACHE_HIT_IORQEC:
			reg_base[i] = NBL_REG_IORQEC_BASE(&nbl_dev->rf->hw);
			break;
		case NBL_CACHE_HIT_RAQEC:
			reg_base[i] = NBL_REG_RAQEC_BASE(&nbl_dev->rf->hw);
			break;
		default:
			break;
		}

		nbl_grc_write_reg(nbl_dev->rf, reg_base[i] + NBL_RDMA_CACHE_EN,
			(u32)nbl_dev->cache_hit_info->enable);
		nbl_grc_read_reg(nbl_dev->rf, reg_base[i] + NBL_RDMA_CACHE_TOTAL,
			&total_stats[i]);
		nbl_grc_read_reg(nbl_dev->rf, reg_base[i] + NBL_RDMA_CACHE_MISS,
			&miss_stats[i]);

		nbl_pr_dbg("read cache[type:%d] hit reg:%#x total_stats:%#x, miss_stats:%#x\n",
				i, reg_base[i], total_stats[i], miss_stats[i]);

		nbl_dev->cache_hit_info->result[i].total_stats += (u64)total_stats[i];
		nbl_dev->cache_hit_info->result[i].miss_stats += (u64)miss_stats[i];
	}
}

static void nbl_cache_hit_worker(struct work_struct *work)
{
	struct cache_hit_work *cachework = container_of(work, struct cache_hit_work, work);
	struct nbl_device *nbl_dev = cachework->nbl_dev;
	u64 start;

	start = ktime_get_ns();
	nbl_pr_dbg("%s start(%lldns).\n", __func__, start);

	nbl_dump_hw_cache_hit(nbl_dev);
}

static inline void nbl_do_cache_hit_work(struct nbl_device *nbl_dev)
{
	nbl_dev->cache_hit_info->cachework->nbl_dev = nbl_dev;

	INIT_WORK(&nbl_dev->cache_hit_info->cachework->work, nbl_cache_hit_worker);

	if (!queue_work(nbl_dev->cache_hit_info->cache_hit_wq,
		&nbl_dev->cache_hit_info->cachework->work))
		nbl_pr_err("failed to do cache hit work\n");
}

static void nbl_cache_hit_timeout(struct timer_list *t)
{
	struct nbl_cache_hit_info *cache_hit_info =
		from_timer(cache_hit_info, t, cache_hit_timer);
	struct nbl_device *nbl_dev = cache_hit_info->nbldev;

	nbl_do_cache_hit_work(nbl_dev);

	mod_timer(&cache_hit_info->cache_hit_timer,
		jiffies + msecs_to_jiffies(NBL_CACHE_HIT_INTERVAL_MAX));
}

static void nbl_cache_hit_start_timer(struct nbl_device *nbl_dev)
{
	timer_setup(&nbl_dev->cache_hit_info->cache_hit_timer, nbl_cache_hit_timeout, 0);
	mod_timer(&nbl_dev->cache_hit_info->cache_hit_timer,
		jiffies + msecs_to_jiffies(NBL_CACHE_HIT_INTERVAL_MAX));
}

static void nbl_cache_hit_stop_timer(struct nbl_device *nbl_dev)
{
	timer_delete_sync(&nbl_dev->cache_hit_info->cache_hit_timer);
}

static ssize_t set_cache_hit_param(struct file *filp, const char __user *buf,
			 size_t count, loff_t *pos)
{
	struct nbl_ib_dbg_param *param = filp->private_data;
	struct nbl_device *nbl_dev = param->dev;
	int offset = param->offset;
	char lbuf[NBL_IN_PARAM_LEN] = { 0 };
	u32 var;
	bool status_last;
	bool status_next;

	if (count > sizeof(lbuf))
		return -EINVAL;

	if (copy_from_user(lbuf, buf, count))
		return -EFAULT;

	lbuf[sizeof(lbuf) - 1] = '\0';
	if (kstrtou32(lbuf, 0, &var))
		return -EINVAL;

	memset(&nbl_dev->cache_hit_info->result[offset], 0, sizeof(struct nbl_cache_hit_stats));
	status_last = nbl_dev->cache_hit_info->enable;

	nbl_dev->cache_hit_info->enable = !!var;

	status_next = nbl_dev->cache_hit_info->enable;
	if (status_next != status_last) {
		if (var)
			nbl_cache_hit_start_timer(nbl_dev);
		else
			nbl_cache_hit_stop_timer(nbl_dev);
	}

	return count;
}

static u64 divide64_fixed(u64 a, u64 b)
{
	if (b == 0)
		return 0;

	return div64_u64(a * 100 * 100ULL, b);
}

static ssize_t get_cache_hit_param(struct file *filp, char __user *buf, size_t count, loff_t *pos)
{
	struct nbl_ib_dbg_param *param = filp->private_data;
	struct nbl_device *nbl_dev = param->dev;
	struct nbl_cache_hit_stats *result;
	int offset = param->offset;
	int len = 0;
	char lbuf[NBL_OUT_PARAM_LEN];
	u64 miss_rto;
	u64 miss_whole;
	u64 miss_frac;

	for (offset = 0; offset < NBL_CACHE_HIT_MAX; offset++) {
		result = &nbl_dev->cache_hit_info->result[offset];
		len += snprintf(lbuf+len, sizeof(lbuf)-len, "%s\n",
		nbl_dbg_cache_hit_print[offset]);
		len += snprintf(lbuf+len, sizeof(lbuf)-len, "  miss %lld\n",
		result->miss_stats);
		len += snprintf(lbuf+len, sizeof(lbuf)-len, "  total %lld\n",
		result->total_stats);
		miss_rto = divide64_fixed(result->miss_stats, result->total_stats);
		miss_whole = div64_u64_rem(miss_rto, 100, &miss_frac);
		len += snprintf(lbuf+len, sizeof(lbuf)-len,
			"  ratio %llu.%02llu%%\n",
			miss_whole, miss_frac);
		memset(&nbl_dev->cache_hit_info->result[offset], 0,
		sizeof(struct nbl_cache_hit_stats));
	}

	if (len < 0)
		return len;

	return simple_read_from_buffer(buf, count, pos, lbuf, len);
}

static const struct file_operations dbg_cache_hit_fops = {
	.owner	= THIS_MODULE,
	.open	= simple_open,
	.write	= set_cache_hit_param,
	.read	= get_cache_hit_param,
};

static void nbl_ib_deinit_cache_hit_debugfs(struct nbl_device *nbl_dev)
{
	if (!nbl_dev->func_dbg_dir || !nbl_dev->cache_hit_params)
		return;

	nbl_cache_hit_stop_timer(nbl_dev);
	if (nbl_dev->cache_hit_info->cache_hit_wq)
		destroy_workqueue(nbl_dev->cache_hit_info->cache_hit_wq);

	kfree(nbl_dev->cache_hit_info->cachework);
	kfree(nbl_dev->cache_hit_info);
	debugfs_remove_recursive(nbl_dev->cache_hit_params->cache_hit_root);
	kfree(nbl_dev->cache_hit_params);
}

static void nbl_ib_init_cache_hit_debugfs(struct nbl_device *dev)
{
	struct nbl_ib_dbg_cache_hit_params *cache_hit_params;
	int i;

	if (!dev->func_dbg_dir)
		return;

	cache_hit_params = kzalloc(sizeof(*cache_hit_params), GFP_KERNEL);
	if (!cache_hit_params)
		goto err;

	dev->cache_hit_params = cache_hit_params;

	cache_hit_params->cache_hit_root = debugfs_create_dir("cache_hit",
				dev->func_dbg_dir);
	if (!cache_hit_params->cache_hit_root) {
		nbl_pr_err("init cache hit directory failed\n");
		goto err;
	}

	for (i = 0; i < ARRAY_SIZE(nbl_dbg_cache_hit_name); i++) {
		cache_hit_params->params[i].offset = i;
		cache_hit_params->params[i].dev = dev;
		cache_hit_params->params[i].dentry =
			debugfs_create_file(nbl_dbg_cache_hit_name[i],
					    0600, cache_hit_params->cache_hit_root,
					    &cache_hit_params->params[i],
					    &dbg_cache_hit_fops);
	}

	dev->cache_hit_info = kzalloc(sizeof(struct nbl_cache_hit_info), GFP_KERNEL);
	if (!dev->cache_hit_info)
		goto err;
	dev->cache_hit_info->nbldev = dev;

	dev->cache_hit_info->cache_hit_wq = create_singlethread_workqueue("nbl_cache_hit_wq");
	if (!dev->cache_hit_info->cache_hit_wq) {
		nbl_ib_err(&dev->rf->sc_dev, "alloc cache_hit_wq failed\n");
		goto err;
	}

	dev->cache_hit_info->cachework = kzalloc(sizeof(struct cache_hit_work), GFP_ATOMIC);
	if (!dev->cache_hit_info->cachework)
		goto err;

	nbl_pr_dbg("init cache_hit debugfs successfully\n");
	return;

err:
	nbl_pr_err("cache_hit debugfs failure\n");
	nbl_ib_deinit_cache_hit_debugfs(dev);
}

void nbl_dbgfs_cache_hit_init(struct nbl_device *dev)
{
	nbl_ib_init_cache_hit_debugfs(dev);
}

void nbl_dbgfs_cache_hit_deinit(struct nbl_device *dev)
{
	nbl_ib_deinit_cache_hit_debugfs(dev);
}
