// SPDX-License-Identifier: GPL-2.0-only

#include <linux/rmap.h>
#include <linux/kprobes.h>

#include "../../msg_handler.h"
#include "../../svm_proc_mng.h"

#include "ksymbol.h"
#include "swap_policy/swap_policy.h"

extern struct swap_policy swap_policy_list_lru;

static struct swap_manager {
	struct swap_policy *policy;
} manager;

int add_swap_page(struct page *page)
{
	if (manager.policy)
		return manager.policy->add_page(page);

	return -ENODEV;
}

int del_swap_page(struct page *page)
{
	if (manager.policy)
		return manager.policy->del_page(page);

	return -ENODEV;
}

int update_page(struct page *page)
{
	if (manager.policy)
		return manager.policy->update_page(page);

	return -ENODEV;
}

static int pick_victim_pages(struct list_head *page_list, int nid, unsigned long *nr)
{
	if (manager.policy)
		return manager.policy->pick_victim_pages(page_list, nid, nr);

	return -ENODEV;
}

static bool __do_swap_one_page(struct page *page, struct vm_area_struct *vma,
							   unsigned long addr, void *args)
{
	struct gm_evict_page_msg_rq req;
	struct svm_proc *proc;
	struct wait_station *ws;
	struct comm_msg_rsp *rsp;
	int ret = 0;

	proc = search_svm_proc_by_mm(vma->vm_mm);
	if (!proc) {
		pr_err("can not find proc of mm\n");
		return 0; /* return 0 if failed */
	}

	get_page(page);

	ws = get_wait_station();
	req.peer_pid = proc->peer_pid;
	req.va = addr;
	req.size = PageCompound(page) ? HPAGE_PMD_SIZE : PAGE_SIZE;
	req.ws = ws->id;
	ret = msg_send_nid(GMEM_EVICT_PAGE_REQUEST, proc->nid, proc->peer_nid, &req, sizeof(req));
	if (ret) {
		pr_err("send GMEM_EVICT_PAGE_REQUEST failed\n");
		put_wait_station(ws);
		goto out;
	}

	rsp = wait_at_station(ws);
	if (IS_ERR(rsp)) {
		ret = PTR_ERR(rsp);
	} else {
		ret = rsp->ret;
		kfree(rsp);
	}

	if (ret)
		pr_err("GMEM_EVICT_PAGE_REQUEST receive %d\n", ret);

out:
	put_page(page);

	return !ret; /* return 1 if success */
}

static int do_swap_one_page(struct page *page)
{
	struct rmap_walk_control rwc = {
		.rmap_one = __do_swap_one_page,
	};

	rmap_walk_anon_symbol(page, &rwc, false);

	return 0;
}

static int do_swap_pages(struct list_head *page_list)
{
	struct list_head *list = page_list;
	struct page *page, *tmp;

	list_for_each_entry_safe(page, tmp, list, lru)
		do_swap_one_page(page);

	return 0;
}

static int swap_one_page_node(int nid)
{
	LIST_HEAD(evict_pages);
	unsigned long nr_to_evict = 1;

	pick_victim_pages(&evict_pages, nid, &nr_to_evict);

	do_swap_pages(&evict_pages);

	return 0;
}

#define HBM_WATERMARK_LOW	0x8000000 /* 128M */
#define HBM_WATERMARK_HIG	(2 * HBM_WATERMARK_LOW)

static unsigned long zone_node_page_free(int node)
{
	struct zone *zones = NODE_DATA(node)->node_zones;
	int i;
	unsigned long count = 0;

	for (i = 0; i < MAX_NR_ZONES; i++)
		count += zone_page_state(zones + i, NR_FREE_PAGES);

	return count * PAGE_SIZE;
}

int need_wake_up_swapd_node(int nid)
{
	return zone_node_page_free(nid) < HBM_WATERMARK_LOW;
}

int need_wake_up_swapd(void)
{
	int nid;

	for_each_node_state(nid, N_NORMAL_MEMORY) {
		if (zone_node_page_free(nid) < HBM_WATERMARK_LOW)
			return 1;
	}

	return 0;
}

int do_swap_node(int nid)
{
	swap_one_page_node(nid);

	return 0;
}

int do_swap(void)
{
	int nid;

	for_each_node_state(nid, N_NORMAL_MEMORY) {
		swap_one_page_node(nid);
	}

	return 0;
}

static int swapd_func(void *id)
{
	int nid = (unsigned long)id;

	while (!kthread_should_stop()) {
		swap_one_page_node(nid);
		if (zone_node_page_free(nid) > HBM_WATERMARK_HIG) {
			set_current_state(TASK_INTERRUPTIBLE);
			schedule();
		} else {
			cond_resched();
		}
	}

	return 0;
}

static struct task_struct *swapd_task[MAX_NUMNODES];

static void init_swapd(void)
{
	unsigned long nid;

	for_each_online_node(nid) {
		swapd_task[nid] = kthread_run(swapd_func, (void *)nid, "swapd");
		if (IS_ERR(swapd_task[nid]))
			/* TODO: free task */
			swapd_task[nid] = NULL;
	}
}

static void wake_up_swapd_node(int nid)
{
	struct task_struct *tsk = swapd_task[nid];

	if (likely(tsk))
		wake_up_process(tsk);
}

void wake_up_swapd(void)
{
	unsigned long nid;

	for_each_online_node(nid)
		wake_up_swapd_node(nid);
}

int init_swap_manager(char *policy_name)
{
	int ret = 0;

	ret = kernel_symbol_init();
	if (ret) {
		panic("Can not get all symbol\n");
		return ret;
	}

	if (!policy_name)
		return -EINVAL;

	if (!strncmp(policy_name, "list_lru", strlen("list_lru")))
		manager.policy = &swap_policy_list_lru;

	if (!manager.policy)
		return -ENOENT;

	if (manager.policy->init) {
		ret = manager.policy->init();
		if (ret)
			return ret;
	}

	init_swapd();

	return 0;
}

