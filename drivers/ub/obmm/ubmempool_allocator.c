// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2025. All rights reserved.
 * Description：OBMM Framework's implementations.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/bitmap.h>
#include <linux/mm.h>
#include <linux/memory.h>
#include <linux/kthread.h>
#include <linux/dma-mapping.h>
#include <linux/io.h>
#include <linux/wait.h>
#include <linux/mmzone.h>
#include <linux/hugetlb.h>
#include <linux/numa_remote.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <acpi/ghes.h>

#include "obmm_core.h"
#include "conti_mem_allocator.h"
#include "obmm_cache.h"
#include "ubmempool_allocator.h"

#define MAX_DEFAULT_PARAM_LENGTH 20
static char default_mempool_size[MAX_DEFAULT_PARAM_LENGTH] = "1G";
static char *mempool_size = default_mempool_size;
module_param(mempool_size, charp, 0440);
MODULE_PARM_DESC(mempool_size, "Max aviliable cached memory total.");

/* contract 1T when receive lowmem notify */
static size_t mempool_contract_size = 1ULL << 40;

static int mempool_refill_timeout = 30000;
module_param(mempool_refill_timeout, int, 0440);
MODULE_PARM_DESC(mempool_refill_timeout,
	"After detecting a memory shortage, attempt to expand the memory pool again after a period of time.");

struct mem_allocator {
	struct timer_list refill_timer;
	struct conti_mem_allocator allocator;
	size_t pool_size;
	bool can_expand;
};

static inline struct mem_allocator *refill_timer_to_mem_allocator(struct timer_list *timer)
{
	return container_of(timer, struct mem_allocator, refill_timer);
}
static inline struct mem_allocator *
conti_mem_to_mem_allocator(struct conti_mem_allocator *allocator)
{
	return container_of(allocator, struct mem_allocator, allocator);
}

static void refill_timeout(struct timer_list *timer)
{
	struct mem_allocator *m = refill_timer_to_mem_allocator(timer);

	m->can_expand = true;
}

static struct mem_allocator mem_allocators[OBMM_MAX_LOCAL_NUMA_NODES];

/* Global parent kobject for mempool sysfs entries */
static struct kobject *mempool_kobj;

static void pool_delay_expand(int nid)
{
	if (is_online_local_node(nid) && mem_allocators[nid].allocator.initialized) {
		mem_allocators[nid].can_expand = false;
		mem_allocators[nid].refill_timer.expires =
			jiffies + msecs_to_jiffies(mempool_refill_timeout);
		mod_timer(&mem_allocators[nid].refill_timer,
			  mem_allocators[nid].refill_timer.expires);
	}
}

void free_memory_contiguous(struct mem_description_pool *desc)
{
	int i;

	for (i = 0; i < OBMM_MAX_LOCAL_NUMA_NODES; i++) {
		if (list_empty(&desc->head[i]))
			continue;

		conti_free_memory(&mem_allocators[i].allocator, &desc->head[i]);
	}
}

static int clear_block(struct conti_mem_allocator *a __always_unused, struct memseg_node *p)
{
	phys_addr_t pa = p->addr;
	size_t size = p->size;
	void *va;
	int ret;

	ret = set_linear_mapping_invalid(pa >> PAGE_SHIFT, (pa + size) >> PAGE_SHIFT, false);
	if (ret < 0) {
		pr_err_ratelimited("%s: error setting kernel pagetable; set_inval=false", __func__);
		return ret;
	}
	va = ioremap_cache(pa, size);
	if (!va) {
		pr_err_ratelimited("%s: failed to run ioremap.\n", __func__);
		ret = -ENOMEM;
		goto out_recover_kernel_pagetable;
	}
	memset(va, 0, size);
	iounmap(va);
	/* flush cache after set_linear_mapping_invalid */
	ret = set_linear_mapping_invalid(pa >> PAGE_SHIFT, (pa + size) >> PAGE_SHIFT, true);
	if (ret < 0) {
		pr_err_ratelimited("%s: error setting kernel pagetable; set_inval=false", __func__);
		return ret;
	}
	ret = flush_cache_by_pa(pa, size, OBMM_SHM_CACHE_WB_INVAL);
	if (ret) {
		pr_err_ratelimited("%s: failed to flush cache: %d; retval=%d\n", __func__,
				   OBMM_SHM_CACHE_INVAL, ret);
		return ret;
	}
	return 0;
out_recover_kernel_pagetable:
	WARN_ON(set_linear_mapping_invalid(pa >> PAGE_SHIFT, (pa + size) >> PAGE_SHIFT, true));
	return ret;
}

int allocate_memory_contiguous(uint64_t size[], int length, struct mem_description_pool *desc,
			       bool zero, bool allow_slow)
{
	int i, ret;
	struct list_head head;
	size_t allocated;

	for (i = 0; i < OBMM_MAX_LOCAL_NUMA_NODES; i++)
		INIT_LIST_HEAD(&desc->head[i]);

	for (i = 0; i < length; i++) {
		INIT_LIST_HEAD(&head);
		if (size[i] == 0)
			continue;
		if (!mem_allocators[i].allocator.initialized) {
			pr_err("%s:no allocator working on node %d\n", __func__, i);
			ret = -ENODEV;
			goto err_free_memory;
		}
		if (size[i] % mem_allocators[i].allocator.granu) {
			pr_err("%s: size %#llx not aligned to allocator granu %#lx on node %d\n",
			       __func__, size[i], mem_allocators[i].allocator.granu, i);
			ret = -EINVAL;
			goto err_free_memory;
		}
		allocated = conti_alloc_memory(&mem_allocators[i].allocator, size[i], &head, zero,
					       allow_slow);
		list_replace(&head, &desc->head[i]);
		if (allocated < size[i]) {
			pr_err("%s: failed to alloc %#llx bytes for node %d\n", __func__, size[i],
			       i);
			ret = -ENOMEM;
			goto err_free_memory;
		}
	}

	return 0;
err_free_memory:
	free_memory_contiguous(desc);
	return ret;
}

static size_t cma_contract_size(struct conti_mem_allocator *a)
{
	struct mem_allocator *m = conti_mem_to_mem_allocator(a);
	ssize_t size = (ssize_t)(ALIGN(conti_get_avail(a) - m->pool_size, a->granu));

	return size > 0 ? size : 0;
}

static bool cma_need_contract(struct conti_mem_allocator *a)
{
	return cma_contract_size(a) > 0;
}

static size_t cma_expand_size(struct conti_mem_allocator *a)
{
	struct mem_allocator *m = conti_mem_to_mem_allocator(a);
	ssize_t size = (ssize_t)ALIGN_DOWN(m->pool_size - conti_get_avail(a), a->granu);

	return size > 0 ? size : 0;
}

static bool cma_need_expand(struct conti_mem_allocator *a)
{
	struct mem_allocator *m = conti_mem_to_mem_allocator(a);

	if (m->can_expand)
		return cma_expand_size(a) > 0;
	return false;
}

static int set_memseg_linear_mapping_invalid(struct memseg_node *node, bool set_nc)
{
	int ret;
	unsigned long start_pfn, end_pfn;

	start_pfn = PHYS_PFN(node->addr);
	end_pfn = PHYS_PFN(node->addr + node->size);
	pr_debug("call external: set_linear_mapping_invalid(set_nc=%d)\n", set_nc);
	ret = set_linear_mapping_invalid(start_pfn, end_pfn, set_nc);
	if (ret) {
		pr_err("failed to update kernel linear mapping cacheability: error=%pe.\n",
		       ERR_PTR(ret));
		return ret;
	}
	pr_debug("external called: set_linear_mapping_invalid(set_nc=%d, ret=%pe)\n",
		 set_nc, ERR_PTR(ret));
	return 0;
}

static struct memseg_node *hugetlb_pmd_alloc_memseg(struct conti_mem_allocator *a)
{
	int ret;
	struct folio *folio;
	struct memseg_node *node = kzalloc(sizeof(*node), GFP_KERNEL);

	if (unlikely(!node))
		return NULL;

	folio = hugetlb_pool_alloc_size(a->nid, PMD_SIZE);
	if (IS_ERR(folio)) {
		pr_debug("hugetlb_pool_alloc(%d) returned %ld.\n", a->nid, PTR_ERR(folio));
		pool_delay_expand(a->nid);
		goto out_free_node;
	}

	node->size = folio_size(folio);
	node->addr = folio_pfn(folio) << PAGE_SHIFT;
	if (unlikely(node->size != a->granu)) {
		pr_err("hugetlb_pool_alloc() returned folio smaller than expected, expect=%#zx, actual=%#zx\n",
		       a->granu, node->size);
		goto out_free_seg;
	}

	ret = set_memseg_linear_mapping_invalid(node, true);
	if (unlikely(ret))
		goto out_free_seg;

	return node;

out_free_seg:
	ret = hugetlb_pool_free(folio);
	if (unlikely(ret != 0))
		pr_err("failed to free hugetlb folio on roll back, retval=%d.\n", ret);
out_free_node:
	kfree(node);
	return NULL;
}

static void hugetlb_free_memseg(struct conti_mem_allocator *a __always_unused,
				struct memseg_node *node)
{
	int ret;
	struct folio *folio;

	if (unlikely(!node)) {
		pr_err("attempted to free NULL hugetlb memseg.\n");
		return;
	}

	folio = pfn_folio(node->addr >> PAGE_SHIFT);

	set_memseg_linear_mapping_invalid(node, false);

	ret = hugetlb_pool_free(folio);
	if (unlikely(ret != 0))
		pr_err("failed to free hugetlb folio, ret=%pe.\n", ERR_PTR(ret));

	kfree(node);
}

static struct memseg_node *hugetlb_pud_alloc_memseg(struct conti_mem_allocator *a)
{
	int ret;
	struct folio *folio;
	struct memseg_node *node = kzalloc(sizeof(*node), GFP_KERNEL);

	if (unlikely(!node))
		return NULL;

	folio = hugetlb_pool_alloc_size(a->nid, PUD_SIZE);
	if (IS_ERR(folio)) {
		pr_debug("hugetlb_pool_alloc(%d) returned %ld.\n", a->nid, PTR_ERR(folio));
		pool_delay_expand(a->nid);
		goto out_free_node;
	}

	node->size = folio_size(folio);
	node->addr = folio_pfn(folio) << PAGE_SHIFT;
	if (unlikely(node->size != a->granu)) {
		pr_err("hugetlb_pool_alloc() returned folio smaller than expected, expect=%#zx, actual=%#zx\n",
		       a->granu, node->size);
		goto out_free_seg;
	}

	ret = set_memseg_linear_mapping_invalid(node, true);
	if (unlikely(ret))
		goto out_free_seg;

	return node;

out_free_seg:
	ret = hugetlb_pool_free(folio);
	if (unlikely(ret != 0))
		pr_err("failed to free hugetlb folio on roll back, ret=%pe.\n", ERR_PTR(ret));
out_free_node:
	kfree(node);
	return NULL;
}

static void buddy_free_memseg(struct conti_mem_allocator *a __always_unused,
			      struct memseg_node *node)
{
	int ret;
	struct folio *folio;

	if (unlikely(!node)) {
		pr_err("attempted to free NULL buddy memseg.\n");
		return;
	}

	folio = pfn_folio(node->addr >> PAGE_SHIFT);

	set_memseg_linear_mapping_invalid(node, false);

	ret = pfn_range_free(folio);
	if (unlikely(ret != 0))
		pr_err("failed to free buddy folio, ret=%pe.\n", ERR_PTR(ret));

	kfree(node);
}

static struct memseg_node *buddy_alloc_memseg(struct conti_mem_allocator *a)
{
	int ret;
	struct folio *folio;
	struct memseg_node *node = kzalloc(sizeof(*node), GFP_KERNEL);

	if (unlikely(!node))
		return NULL;

	folio = pfn_range_alloc(a->granu >> PAGE_SHIFT, a->nid);
	if (IS_ERR(folio)) {
		pr_debug("pfn_range_alloc(%#lx, %d) returned %ld.\n", a->granu >> PAGE_SHIFT,
			 a->nid, PTR_ERR(folio));
		pool_delay_expand(a->nid);
		goto out_free_node;
	}

	node->size = folio_size(folio);
	node->addr = folio_pfn(folio) << PAGE_SHIFT;
	if (unlikely(node->size != a->granu)) {
		pr_err("pfn_range_alloc() returned folio smaller than expected, expect=%#zx, actual=%#zx\n",
		       a->granu, node->size);
		goto out_free_seg;
	}

	ret = set_memseg_linear_mapping_invalid(node, true);
	if (unlikely(ret))
		goto out_free_seg;

	return node;

out_free_seg:
	ret = pfn_range_free(folio);
	if (unlikely(ret != 0))
		pr_err("failed to free buddy folio on roll back, ret=%pe.\n", ERR_PTR(ret));
out_free_node:
	kfree(node);
	return NULL;
}

static struct conti_mempool_ops hugetlb_pmd_ops = {
	.clear_memseg = clear_block,
	.pool_free_memseg = hugetlb_free_memseg,
	.pool_alloc_memseg = hugetlb_pmd_alloc_memseg,
	.need_contract = cma_need_contract,
	.contract_size = cma_contract_size,
	.need_expand = cma_need_expand,
	.expand_size = cma_expand_size,
};

static struct conti_mempool_ops hugetlb_pud_ops = {
	.clear_memseg = clear_block,
	.pool_free_memseg = hugetlb_free_memseg,
	.pool_alloc_memseg = hugetlb_pud_alloc_memseg,
	.need_contract = cma_need_contract,
	.contract_size = cma_contract_size,
	.need_expand = cma_need_expand,
	.expand_size = cma_expand_size,
};

static struct conti_mempool_ops buddy_ops = {
	.clear_memseg = clear_block,
	.pool_free_memseg = buddy_free_memseg,
	.pool_alloc_memseg = buddy_alloc_memseg,
	.need_contract = cma_need_contract,
	.contract_size = cma_contract_size,
	.need_expand = cma_need_expand,
	.expand_size = cma_expand_size,
};

static void mem_allocator_uninit_one(int nid)
{
	conti_mem_allocator_deinit(&mem_allocators[nid].allocator);
	timer_shutdown_sync(&mem_allocators[nid].refill_timer);
}

static char default_mempool_allocator[MAX_DEFAULT_PARAM_LENGTH] = "buddy_highmem";
static char *mempool_allocator = default_mempool_allocator;
module_param(mempool_allocator, charp, 0440);
MODULE_PARM_DESC(mempool_allocator,
		 "OBMM mempool allocator. If not set, use buddy_highmem allocator.");
static const char * const allocator_names[] = {
	"hugetlb_pmd",
	"hugetlb_pud",
	"buddy_highmem",
};
static const struct conti_mempool_ops *allocator_ops[] = {
	&hugetlb_pmd_ops,
	&hugetlb_pud_ops,
	&buddy_ops,
	NULL
};
enum allocator_id {
	ALLOCATOR_HUGETLB_PMD = 0,
	ALLOCATOR_HUGETLB_PUD,
	ALLOCATOR_BUDDY_HIGHMEM,
	ALLOCATOR_MAX
};

static char *mem_allocator_granu;
module_param(mem_allocator_granu, charp, 0440);
MODULE_PARM_DESC(mem_allocator_granu, "Basic granu of obmm memory allocator.");

static int select_mem_allocator(void)
{
	int i;

	for (i = 0; i < ALLOCATOR_MAX; i++) {
		if (!strcmp(allocator_names[i], mempool_allocator))
			break;
	}
	if (i == ALLOCATOR_MAX) {
		pr_err("invalid mem allocator specified: %s\n", mempool_allocator);
		return ALLOCATOR_MAX;
	}
#ifndef CONFIG_ARM64_64K_PAGES
	if (contig_mem_pool_percent != 100 && i == ALLOCATOR_HUGETLB_PMD) {
		pr_err("using allocator %s when pmd_mapping not 100%%\n", allocator_names[i]);
		i = ALLOCATOR_MAX;
	}
#endif

	return i;
}

static void print_granu(char s[MAX_DEFAULT_PARAM_LENGTH], size_t granu)
{
	static const char * const units[] = {"", "K", "M", "G", "T"};
	int i = 0;

	while (granu >= 1024 && i < ARRAY_SIZE(units) - 1) {
		granu >>= 10;
		i++;
	}
	snprintf(s, MAX_DEFAULT_PARAM_LENGTH, "%lu%s", granu, units[i]);
}

static int init_mem_allocator_granu(enum allocator_id aid)
{
	static char def_granu[MAX_DEFAULT_PARAM_LENGTH];
	char *p = mem_allocator_granu;

	if (!mem_allocator_granu) {
		if (aid == ALLOCATOR_HUGETLB_PUD)
			__obmm_memseg_size = PUD_SIZE;
		else if (aid == ALLOCATOR_HUGETLB_PMD)
			__obmm_memseg_size = PMD_SIZE;
		else
			__obmm_memseg_size = OBMM_BASIC_GRANU;

		print_granu(def_granu, __obmm_memseg_size);
		mem_allocator_granu = def_granu;
		return 0;
	}

	__obmm_memseg_size = memparse(p, &p);
	if (*p != '\0') {
		pr_err("invalid mem_allocator_granu: %s\n", mem_allocator_granu);
		return -EINVAL;
	}
	if (__obmm_memseg_size < OBMM_BASIC_GRANU || __obmm_memseg_size % OBMM_BASIC_GRANU) {
		pr_err("unsupported mem_allocator_granu: %s\n", mem_allocator_granu);
		return -EINVAL;
	}
	if (!is_power_of_2(__obmm_memseg_size)) {
		pr_err("mem_allocator_granu must be power of 2: %s\n", mem_allocator_granu);
		return -EINVAL;
	}
	if (aid == ALLOCATOR_HUGETLB_PUD && __obmm_memseg_size != PUD_SIZE) {
		pr_err("unsupported mem_allocator_granu for hugetlb_pud allocator: %s\n",
		       mem_allocator_granu);
		return -EINVAL;
	}
	if (aid == ALLOCATOR_HUGETLB_PMD && __obmm_memseg_size != PMD_SIZE) {
		pr_err("unsupported mem_allocator_granu for hugetlb_pmd allocator: %s\n",
		       mem_allocator_granu);
		return -EINVAL;
	}

	return 0;
}

static int mem_allocator_init_one(int nid, enum allocator_id aid)
{
	struct conti_mem_allocator *allocator = &mem_allocators[nid].allocator;
	int ret;

	mem_allocators[nid].can_expand = true;
	timer_setup(&mem_allocators[nid].refill_timer, refill_timeout, 0);

	ret = conti_mem_allocator_init(allocator, nid, OBMM_MEMSEG_SIZE, allocator_ops[aid],
				       mempool_kobj, "obmm-%d", nid);
	if (ret)
		goto err_del_timer;

	return 0;
err_del_timer:
	timer_shutdown_sync(&mem_allocators[nid].refill_timer);
	return ret;
}

size_t ubmempool_contract(int nid, bool is_hugepage)
{
	struct conti_mem_allocator *a;
	bool is_hugetlb_pool;

	if (!is_online_local_node(nid)) {
		pr_err_ratelimited(
			"obmm tried to contract to alleviate lowmem, but nid(%d) is not valid.\n",
			nid);
		return 0;
	}

	pr_debug_ratelimited("contract memory on nid: %d, is_hugepage: %d\n", nid, is_hugepage);
	/* try to contract memory only when it is helpful */
	a = &mem_allocators[nid].allocator;
	is_hugetlb_pool = a->ops == &hugetlb_pmd_ops || a->ops == &hugetlb_pud_ops;
	if (is_hugepage == is_hugetlb_pool) {
		pool_delay_expand(nid);
		return conti_mem_allocator_contract(a, mempool_contract_size);
	}
	pr_debug_ratelimited("Not contracting;\n");

	return 0;
}

static int mempool_size_parse(char *p, int local_cnt)
{
	int nid;
	size_t mempool = memparse(p, &p);

	if (local_cnt == 0) {
		pr_err("There is no local numa, failed\n");
		return -EINVAL;
	}

	for_each_online_local_node(nid) {
		mem_allocators[nid].pool_size = div64_ul(mempool, local_cnt);
		pr_info("nid=%d, pool size = %#lx bytes.\n", nid, mem_allocators[nid].pool_size);
	}
	return 0;
}

/* Run in IRQ context. */
static int handle_ghes_mem_ras(struct notifier_block *nb __always_unused,
			       unsigned long severity __always_unused, void *data)
{
	const struct cper_sec_mem_err *mem_err = (const struct cper_sec_mem_err *)data;
	unsigned long pfn;
	int nid;

	/* A defensive check for future Linux version. Currently GHES are
	 * handled in IRQ context. If it switches to NMI context, this handler
	 * no longer works.
	 */
	if (WARN_ON_ONCE(in_nmi()))
		return NOTIFY_DONE;

	if (!(mem_err->validation_bits & CPER_MEM_VALID_PA))
		return NOTIFY_DONE;

	pfn = PHYS_PFN(mem_err->physical_addr);
	if (!pfn_valid(pfn))
		return NOTIFY_DONE;

	nid = page_to_nid(pfn_to_page(pfn));
	if (!is_online_local_node(nid))
		return NOTIFY_DONE;

	(void)conti_mem_allocator_isolate_memseg(&mem_allocators[nid].allocator,
						 mem_err->physical_addr);
	return NOTIFY_OK;
}

static struct notifier_block ghes_mem_ras_notifier_block = {
	.notifier_call = handle_ghes_mem_ras,
	.priority = 0,
};

int ubmempool_allocator_init(void)
{
	int i, j, nid, ret = 0, local_cnt = 0;
	enum allocator_id aid;

	for_each_online_local_node(nid) {
		if (nid >= OBMM_MAX_LOCAL_NUMA_NODES) {
			pr_err("Too many local NUMA nodes. OBMM rebuild required.\n");
			return -EOPNOTSUPP;
		}
		local_cnt++;
	}

	memset(mem_allocators, 0, sizeof(struct mem_allocator) * OBMM_MAX_LOCAL_NUMA_NODES);
	if (mempool_size)
		ret = mempool_size_parse(mempool_size, local_cnt);

	if (ret) {
		pr_err("memory allocator init failed.\n");
		return ret;
	}

	aid = select_mem_allocator();
	if (aid == ALLOCATOR_MAX)
		return -EINVAL;

	ret = init_mem_allocator_granu(aid);
	if (ret)
		return ret;

	mempool_kobj = kobject_create_and_add("obmm_mempool", kernel_kobj);
	if (!mempool_kobj) {
		pr_err("Failed to create mempool sysfs directory\n");
		return -ENOMEM;
	}

	for_each_online_local_node(i) {
		ret = mem_allocator_init_one(i, aid);
		if (ret)
			goto failed;
	}

	ghes_register_report_chain(&ghes_mem_ras_notifier_block);

	return 0;

failed:
	for_each_online_local_node(j) {
		if (j < i)
			mem_allocator_uninit_one(j);
	}
	kobject_put(mempool_kobj);
	mempool_kobj = NULL;

	return ret;
}

void ubmempool_allocator_exit(void)
{
	int i;

	ghes_unregister_report_chain(&ghes_mem_ras_notifier_block);

	for_each_online_local_node(i) {
		if (!mem_allocators[i].allocator.initialized)
			continue;

		mem_allocator_uninit_one(i);
	}

	if (mempool_kobj) {
		kobject_put(mempool_kobj);
		mempool_kobj = NULL;
	}
}
