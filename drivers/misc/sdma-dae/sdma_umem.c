// SPDX-License-Identifier: GPL-2.0-or-later
#include "sdma_umem.h"

static struct hisi_sdma_ht *g_hash_table;

int sdma_hash_init(void)
{
	g_hash_table = kmalloc(sizeof(struct hisi_sdma_ht), GFP_KERNEL);
	if (!g_hash_table)
		return -ENOMEM;

	hash_init(g_hash_table->sdma_fd_ht);
	spin_lock_init(&g_hash_table->hash_lock);

	return 0;
}

static void free_region(struct list_head *list_head)
{
	struct p_list *node_remove = NULL;
	struct p_list *node_next = NULL;

	list_for_each_entry_safe(node_remove, node_next, list_head, list) {
		unpin_user_pages(node_remove->pnode.page_list, node_remove->pnode.pinned);
		free_pages((uintptr_t)(void *)node_remove->pnode.page_list,
			   get_order(node_remove->pnode.pinned * sizeof(struct page *)));
		list_del(&node_remove->list);
		kfree(node_remove);
	}
}

static int region_cleanup(int id, void *p, void *data)
{
	struct pin_mem *pmem = p;

	WARN_ON(pmem->idr != id);
	pr_debug("%s: free region idr = %d\n", __func__, id);
	free_region(pmem->list_head);
	kfree(pmem->list_head);
	kfree(p);

	return 0;
}

static void entry_free_idr(struct hash_entry *entry)
{
	idr_for_each(&entry->pin_mem_region, region_cleanup, &entry->pin_mem_region);
	idr_destroy(&entry->pin_mem_region);

	hash_del(&entry->node);
	kfree(entry);
}

struct hash_entry *hash_lookup_entry(int ida)
{
	struct hash_entry *entry;

	hash_for_each_possible(g_hash_table->sdma_fd_ht, entry, node, ida)
		if (entry->ida == ida)
			return entry;

	return NULL;
}

void sdma_hash_free_entry(int key)
{
	struct hash_entry *entry;
	struct hlist_node *node_tmp;

	pr_debug("%s: free ida %d\n", __func__, key);
	spin_lock(&g_hash_table->hash_lock);

	hash_for_each_possible_safe(g_hash_table->sdma_fd_ht, entry, node_tmp, node, key)
		if (entry->ida == key)
			entry_free_idr(entry);

	spin_unlock(&g_hash_table->hash_lock);
}

void sdma_hash_free(void)
{
	struct hash_entry *entry;
	struct hlist_node *tmp;
	u32 bkt;

	spin_lock(&g_hash_table->hash_lock);

	hash_for_each_safe(g_hash_table->sdma_fd_ht, bkt, tmp, entry, node)
		entry_free_idr(entry);

	spin_unlock(&g_hash_table->hash_lock);

	kfree(g_hash_table);
	g_hash_table = NULL;
}

static int record_umem(u64 addr, struct list_head *list_head, int ida, u64 *cookie)
{
	struct hash_entry *entry;
	bool entry_find = true;
	struct pin_mem *pmem;
	int ret, idr;

	pmem = kzalloc(sizeof(*pmem), GFP_KERNEL);
	if (!pmem)
		return -ENOMEM;

	pmem->addr = addr;
	pmem->list_head = list_head;

	spin_lock(&g_hash_table->hash_lock);
	entry = hash_lookup_entry(ida);
	if (!entry) {
		entry = kzalloc(sizeof(*entry), GFP_KERNEL);
		if (!entry) {
			ret = -ENOMEM;
			spin_unlock(&g_hash_table->hash_lock);
			pr_err("Sdma failed to alloc hash_entry!\n");
			goto free_pmem;
		}
		entry_find = false;
		entry->ida = ida;
		idr_init(&entry->pin_mem_region);
		hash_add(g_hash_table->sdma_fd_ht, &entry->node, ida);
	}

	idr = idr_alloc(&entry->pin_mem_region, pmem, 0, 0, GFP_ATOMIC);
	if (idr < 0) {
		ret = idr;
		if (entry_find == false)
			hash_del(&entry->node);
		spin_unlock(&g_hash_table->hash_lock);
		pr_err("Sdma failed to alloc idr!\n");
		if (entry_find)
			goto free_pmem;
		else
			goto free_entry;
	}

	pmem->idr = idr;
	spin_unlock(&g_hash_table->hash_lock);
	*cookie = ((u64)ida << COOKIE_IDA_SHIFT) + idr;
	pr_debug("record addr: ida = %d, idr = %d\n", ida, idr);

	return 0;

free_entry:
	kfree(entry);
free_pmem:
	kfree(pmem);
	return ret;
}

static int pin_umem(u64 addr, int npages, struct list_head *p_head)
{
	int pinned, to_pin_pages, unpin_pages, ret = 0;
	size_t node_size = sizeof(struct p_list);
	struct page **page_list;
	struct p_list *cur_node;
	u64 pin_addr = addr;

	to_pin_pages = unpin_pages = npages;
	while (unpin_pages != 0) {
		if (to_pin_pages > HISI_SDMA_MAX_ALLOC_SIZE / sizeof(struct page *))
			to_pin_pages = HISI_SDMA_MAX_ALLOC_SIZE / sizeof(struct page *);
		page_list = (struct page **)(uintptr_t)__get_free_pages(GFP_KERNEL,
				get_order(to_pin_pages * sizeof(struct page *)));
		if (!page_list) {
			pr_err("Sdma failed to alloc page list!\n");
			return -ENOMEM;
		}

		pinned = pin_user_pages_fast(pin_addr, to_pin_pages, FOLL_WRITE, page_list);
		if (pinned < 0) {
			pr_err("Sdma failed to pin user pages!\n");
			ret = pinned;
			goto free_pages;
		} else if (pinned != to_pin_pages) {
			pr_err("Invalid number of pages. Sdma pinned %d pages, expect %d pages\n",
			       pinned, to_pin_pages);
			ret = -EINVAL;
			goto unpin_page;
		}

		cur_node = NULL;
		cur_node = kzalloc(node_size, GFP_KERNEL);
		if (!cur_node) {
			ret = -ENOMEM;
			goto unpin_page;
		}
		cur_node->pnode.page_list = page_list;
		cur_node->pnode.pinned = pinned;
		list_add(&cur_node->list, p_head);
		unpin_pages -= to_pin_pages;
		if (unpin_pages > 0)
			pin_addr += to_pin_pages * PAGE_SIZE;
		to_pin_pages = unpin_pages;
	}
	goto exit;
unpin_page:
	unpin_user_pages(page_list, pinned);
free_pages:
	free_pages((uintptr_t)(void *)page_list, get_order(to_pin_pages * sizeof(struct page *)));
exit:
	return ret;
}

int sdma_umem_get(u64 addr, u32 size, int ida, u64 *cookie)
{
	struct list_head *p_head;
	int npages;
	int ret;

	/* Check overflow */
	if (((addr + size) < addr) || PAGE_ALIGN(addr + size) < (addr + size)) {
		pr_err("Sdma input size is overflow!\n");
		return -EINVAL;
	}

	p_head = kzalloc(sizeof(struct list_head), GFP_KERNEL);
	if (!p_head)
		return -ENOMEM;

	INIT_LIST_HEAD(p_head);
	npages = (PAGE_ALIGN(addr + size) - ALIGN_DOWN(addr, PAGE_SIZE)) / PAGE_SIZE;
	ret = pin_umem(addr, npages, p_head);
	if (ret != 0) {
		pr_err("Sdma failed to pin_umem\n");
		free_region(p_head);
		kfree(p_head);
		return ret;
	}

	ret = record_umem(addr, p_head, ida, cookie);
	if (ret) {
		pr_err("Sdma failed to record umem\n");
		free_region(p_head);
		kfree(p_head);
		return ret;
	}

	return ret;
}

int sdma_umem_release(u64 cookie)
{
	struct hash_entry *entry;
	struct pin_mem *pmem;
	int fd_ida, idr;

	fd_ida = (int)(cookie >> COOKIE_IDA_SHIFT);
	idr = (int)(cookie & COOKIE_IDA_MASK);

	pr_debug("release addr: ida = %d, idr = %d\n", fd_ida, idr);
	spin_lock(&g_hash_table->hash_lock);
	entry = hash_lookup_entry(fd_ida);
	if (!entry) {
		spin_unlock(&g_hash_table->hash_lock);
		pr_err("Sdma cookie_ida is invalid!\n");
		return -EFAULT;
	}

	pmem = idr_find(&entry->pin_mem_region, idr);
	if (!pmem) {
		spin_unlock(&g_hash_table->hash_lock);
		pr_err("Sdma cookie_idr is invalid!\n");
		return -EFAULT;
	}

	idr_remove(&entry->pin_mem_region, idr);
	spin_unlock(&g_hash_table->hash_lock);
	free_region(pmem->list_head);
	kfree((void *)pmem->list_head);
	kfree(pmem);
	return 0;
}
