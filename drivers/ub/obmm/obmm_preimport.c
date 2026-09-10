// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2025. All rights reserved.
 */

#include <linux/mutex.h>
#include <linux/memory.h>
#include <linux/topology.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/numa_remote.h>

#include "obmm_preimport.h"
#include "obmm_import.h"

static char not_ready_dummy;
void *not_ready_ptr = &not_ready_dummy;

static DEFINE_MUTEX(list_mutex);
static LIST_HEAD(pr_list);

bool is_numa_base_dist_valid(uint8_t base_dist)
{
	if (base_dist > MAX_NUMA_DIST) {
		pr_err("invalid numa base distance %d: out of valid range.\n", base_dist);
		return false;
	}
	if (base_dist != 0 && base_dist <= LOCAL_DISTANCE) {
		pr_err("invalid numa base distance %d: reserved values used.\n", base_dist);
		return false;
	}
	return true;
}

int obmm_set_numa_distance(unsigned int cna, int nid_remote, uint8_t base_dist)
{
	int nid_local, nid, min_dist, i = 0;
	int node_distances[OBMM_MAX_LOCAL_NUMA_NODES];
	int nids[OBMM_MAX_LOCAL_NUMA_NODES];

	if (!is_numa_base_dist_valid(base_dist))
		return -EINVAL;

	nid_local = ub_mem_get_numa_id(cna);
	pr_debug("for cna = %#x, get local node = %d\n", cna, nid_local);
	if (nid_local < 0) {
		pr_err("failed to set numa distance: bus controller with CNA=%u has nid=%d.", cna,
		       nid_local);
		return -ENODEV;
	}

	if (base_dist == 0)
		return 0;

	min_dist = __node_distance(nid_local, nid_local);

	for_each_online_local_node(nid) {
		nids[i] = nid;
		node_distances[i++] =
			min(MAX_NUMA_DIST, base_dist + __node_distance(nid_local, nid) - min_dist);
	}

	return numa_remote_set_distance(nid_remote, nids, node_distances, i);
}

int check_preimport_cmd_common(const struct obmm_cmd_preimport *cmd)
{
	/* OBMM_BASIC_GRANU is always smaller than or equal to memory_block_size_bytes(). No need
	 * to check for OBMM_BASIC_GRANU here.
	 */
	if (cmd->length % memory_block_size_bytes() != 0) {
		pr_err("preimport length not aligned to %#lx.\n",
		       memory_block_size_bytes());
		return -EINVAL;
	}
	if (cmd->pa % memory_block_size_bytes()) {
		pr_err("preimport base PA not aligned to %#lx.\n",
		       memory_block_size_bytes());
		return -EINVAL;
	}
	if (cmd->length > ULLONG_MAX - cmd->pa) {
		pr_err("preimport PA range overflowed.\n");
		return -EINVAL;
	}
	if (cmd->length == 0) {
		pr_err("invalid preimport length 0.\n");
		return -EINVAL;
	}
	if (cmd->flags & ~OBMM_PREIMPORT_FLAG_MASK) {
		pr_err("undefined preimport flags specified in %#llx.\n", cmd->flags);
		return -EINVAL;
	}
	/* scna is mandatory parameter, always required to initialize NUMA distance */
	if (!validate_scna(cmd->scna))
		return -ENODEV;
	if (!is_numa_base_dist_valid(cmd->base_dist))
		return -EINVAL;
	return 0;
}

int preimport_prepare_common(struct preimport_range *pr, uint8_t base_dist)
{
	int ret, ret_err;

	if (!ub_memory_validate_pa(pr->scna, pr->start, pr->end, true)) {
		pr_err("PA range invalid. Cacheable memory cannot be managed with preimport\n");
		return -EINVAL;
	}

	pr_debug("call external: add_memory_remote(nid=%d, flags=MEMORY_KEEP_ISOLATED)\n",
		pr->numa_id);
	ret = add_memory_remote(pr->numa_id, pr->start, pr->end - pr->start + 1,
				MEMORY_KEEP_ISOLATED);
	pr_debug("external called: add_memory_remote() returned %d\n", ret);
	if (ret < 0) {
		pr_err("failed to call add_memory_remote(nid=%d): %pe\n",
		       pr->numa_id, ERR_PTR(ret));
		return -EPERM;
	}
	WARN_ON(pr->numa_id != NUMA_NO_NODE && pr->numa_id != ret);
	pr->numa_id = ret;

	ret = obmm_set_numa_distance(pr->scna, pr->numa_id, base_dist);
	if (ret < 0) {
		pr_err("Failed to set numa distance for remote numa: %pe\n", ERR_PTR(ret));
		goto err_remove_memory_remote;
	}

	mutex_lock(&list_mutex);
	list_add(&pr->node, &pr_list);
	mutex_unlock(&list_mutex);

	return 0;

err_remove_memory_remote:
	pr_debug("call external: remove_memory_remote(nid=%d)\n", pr->numa_id);
	ret_err = remove_memory_remote(pr->numa_id, pr->start, pr->end - pr->start + 1);
	pr_debug("external called: remove_memory_remote() returned %d\n", ret_err);
	if (ret_err)
		pr_err("failed to roll back add_memory_remote(nid=%d, pa=%#llx): %pe; remote memory may be orphaned.\n",
		       pr->numa_id, pr->start, ERR_PTR(ret_err));
	return ret;
}

int preimport_release_common(struct preimport_range *pr, bool force)
{
	int ret;

	pr_debug("call external: remove_memory_remote(nid=%d)\n", pr->numa_id);
	ret = remove_memory_remote(pr->numa_id, pr->start, pr->end - pr->start + 1);
	pr_debug("external called: remove_memory_remote() returned %pe\n", ERR_PTR(ret));
	if (ret && !force) {
		pr_err("failed to call remove_memory_remote(nid=%d, size=%#llx): ret=%pe.\n",
		       pr->numa_id, pr->end - pr->start + 1, ERR_PTR(ret));
		return ret;
	}

	mutex_lock(&list_mutex);
	list_del(&pr->node);
	mutex_unlock(&list_mutex);
	return ret;
}

int check_preimport_datapath_common(const struct preimport_range *pr,
				    const struct obmm_datapath *datapath)
{
	if (pr->scna != datapath->scna || pr->dcna != datapath->dcna) {
		pr_err("scna-dcna pair mismatch: <%#x, %#x> used in import; <%#x, %#x> in preimport.\n",
		       datapath->scna, datapath->dcna, pr->scna, pr->dcna);
		return -EINVAL;
	}
	if (memcmp(pr->seid, datapath->seid, EID_BYTES)) {
		pr_err("seid mismatch: " EID_FMT64 " used in import; " EID_FMT64 " in preimport.\n",
		       EID_ARGS64_H(datapath->seid), EID_ARGS64_L(datapath->seid),
		       EID_ARGS64_H(pr->seid), EID_ARGS64_L(pr->seid));
		return -EINVAL;
	}
	if (memcmp(pr->deid, datapath->deid, EID_BYTES)) {
		pr_err("deid mismatch: " EID_FMT64 " used in import; " EID_FMT64 " in preimport.\n",
		       EID_ARGS64_H(datapath->deid), EID_ARGS64_L(datapath->deid),
		       EID_ARGS64_H(pr->deid), EID_ARGS64_L(pr->deid));
		return -EINVAL;
	}

	return 0;
}

static void print_preimport_param(const struct obmm_cmd_preimport *cmd)
{
	pr_debug("obmm_preimport: pa=%#llx length=%#llx scna=%#x dcna=%#x flags=%#llx nid=%d base_dist=%u deid="
		EID_FMT64 " seid=" EID_FMT64 " priv_len=%u\n",
		cmd->pa, cmd->length, cmd->scna, cmd->dcna, cmd->flags, cmd->numa_id,
		cmd->base_dist, EID_ARGS64_H(cmd->deid), EID_ARGS64_L(cmd->deid),
		EID_ARGS64_H(cmd->seid), EID_ARGS64_L(cmd->seid), cmd->priv_len);
}

int obmm_preimport(struct obmm_cmd_preimport *cmd)
{
	int ret;

	print_preimport_param(cmd);
	if (!try_module_get(THIS_MODULE)) {
		pr_err("Module is dying. Reject all preimport requests\n");
		return -EPERM;
	}

	ret = preimport_prepare_prefilled(cmd);

	if (ret)
		module_put(THIS_MODULE);
	else
		pr_debug("%s: preimport on nid=%d finished.\n", __func__, cmd->numa_id);
	return ret;
}

static int check_unpreimport_cmd_common(const struct obmm_cmd_preimport *cmd)
{
	if (cmd->flags & ~OBMM_UNPREIMPORT_FLAG_MASK) {
		pr_err("undefined unpreimport flags specified in %#llx.\n", cmd->flags);
		return -EINVAL;
	}
	return 0;
}

static void print_unpreimport_param(const struct obmm_cmd_preimport *cmd)
{
	pr_debug("obmm_unpreimport: pa=%#llx, length=%#llx.\n", cmd->pa, cmd->length);
}

int obmm_unpreimport(struct obmm_cmd_preimport *cmd)
{
	int ret;

	print_unpreimport_param(cmd);
	ret = check_unpreimport_cmd_common(cmd);
	if (ret)
		return ret;

	ret = preimport_release_prefilled(cmd->pa, cmd->pa + cmd->length - 1);
	if (ret == 0)
		module_put(THIS_MODULE);
	pr_debug("%s: unpreimport on pa=%#llx finished.\n", __func__, cmd->pa);

	return ret;
}

static void *preimp_info_seq_start(struct seq_file *m __always_unused, loff_t *pos)
{
	mutex_lock(&list_mutex);
	/* Shift the position by 1 to make place for table header. */
	if (*pos == 0)
		return SEQ_START_TOKEN;
	return seq_list_start(&pr_list, *pos - 1);
}

static void *preimp_info_seq_next(struct seq_file *m __always_unused, void *v, loff_t *pos)
{
	/* SEQ_START_TOKEN is a reserved which matches with the dummy header of list. The next
	 * element of the dummy header is the first real element.
	 */
	if (v == SEQ_START_TOKEN)
		v = &pr_list;
	return seq_list_next(v, &pr_list, pos);
}

static void preimp_info_seq_stop(struct seq_file *m __always_unused, void *v __always_unused)
{
	mutex_unlock(&list_mutex);
}

#define PA_WIDTH	16
#define CNA_WIDTH	8
#define HALF_EID_WIDTH	18
#define FULL_EID_WIDTH	(2 * HALF_EID_WIDTH + 1)
#define NID_WIDTH	3
static int preimp_info_seq_show(struct seq_file *m, void *v)
{
	const struct preimport_range *pr = list_entry(v, struct preimport_range, node);

	if (v == SEQ_START_TOKEN)
		seq_printf(m, "%-*s - %-*s : %-*s %-*s    %-*s %-*s    %-*s\n", PA_WIDTH,
			   "pa_start", PA_WIDTH, "pa_end", CNA_WIDTH, "dcna", CNA_WIDTH, "scna",
			   FULL_EID_WIDTH, "deid", FULL_EID_WIDTH, "seid", NID_WIDTH, "nid");
	else
		seq_printf(m,
			   "%-*llx - %-*llx : %#-*x %#-*x    "
			   EID_ALIGNED_FMT64 " " EID_ALIGNED_FMT64 "    %-*d\n",
			   PA_WIDTH, pr->start, PA_WIDTH, pr->end, CNA_WIDTH, pr->dcna, CNA_WIDTH,
			   pr->scna, HALF_EID_WIDTH, EID_ARGS64_H(pr->deid), HALF_EID_WIDTH,
			   EID_ARGS64_L(pr->deid), HALF_EID_WIDTH, EID_ARGS64_H(pr->seid),
			   HALF_EID_WIDTH, EID_ARGS64_L(pr->seid), NID_WIDTH, pr->numa_id);
	return 0;
}

static const struct seq_operations preimp_info_sops = {
	.start = preimp_info_seq_start,
	.stop = preimp_info_seq_stop,
	.next = preimp_info_seq_next,
	.show = preimp_info_seq_show,
};

static int init_preimport_info_seqfile(void)
{
	struct proc_dir_entry *p;

	p = proc_mkdir("obmm", NULL);
	if (!p) {
		pr_err("failed to init obmm proc dir.\n");
		return -ENOMEM;
	}
	p = proc_create_seq("obmm/preimport_info", 0, NULL, &preimp_info_sops);
	if (!p) {
		pr_err("failed to init obmm proc file.\n");

		remove_proc_subtree("obmm", NULL);
		return -ENOMEM;
	}
	return 0;
}

int module_preimport_init(void)
{
	int ret;

	ret = init_preimport_info_seqfile();
	if (ret)
		return ret;

	preimport_init_prefilled();

	return 0;
}

void module_preimport_exit(void)
{
	preimport_exit_prefilled();

	WARN_ON(remove_proc_subtree("obmm", NULL));
}
