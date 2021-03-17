// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021. Huawei Technologies Co., Ltd. All rights reserved.
 * Provide the pin memory method for checkpoint and restore task.
 */
#ifdef CONFIG_PIN_MEMORY
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/time.h>
#include <linux/sched/cputime.h>
#include <linux/tick.h>
#include <linux/mm.h>
#include <linux/pin_mem.h>
#include <linux/idr.h>
#include <linux/page-isolation.h>
#include <linux/sched/mm.h>
#include <linux/ctype.h>
#include <linux/highmem.h>
#include <crypto/sha.h>

#define MAX_PIN_PID_NUM  128
static DEFINE_SPINLOCK(page_map_entry_lock);
static DEFINE_MUTEX(pin_mem_mutex);
struct pin_mem_dump_info *pin_mem_dump_start;
unsigned int pin_pid_num;
static unsigned int *pin_pid_num_addr;
static struct page_map_entry *__page_map_entry_start;
static unsigned long page_map_entry_end;
static struct page_map_info *user_space_reserve_start;
static struct page_map_entry *page_map_entry_start;
unsigned int max_pin_pid_num __read_mostly;
unsigned long redirect_space_size;
unsigned long redirect_space_start;
#define DEFAULT_REDIRECT_SPACE_SIZE  0x100000
void *pin_mem_pagemapread;
unsigned long *pagemap_buffer;

static int __init setup_max_pin_pid_num(char *str)
{
	int ret = 0;

	if (!str)
		goto out;

	ret = kstrtouint(str, 10, &max_pin_pid_num);
out:
	if (ret) {
		pr_warn("Unable to parse max pin pid num.\n");
	} else {
		if (max_pin_pid_num > MAX_PIN_PID_NUM) {
			max_pin_pid_num = 0;
			pr_warn("Input max_pin_pid_num is too large.\n");
		}
	}
	return ret;
}
early_param("max_pin_pid_num", setup_max_pin_pid_num);

static int __init setup_redirect_space_size(char *str)
{
	if (!str)
		goto out;

	redirect_space_size = memparse(str, NULL);
out:
	if (!redirect_space_size) {
		pr_warn("Unable to parse redirect space size, use the default value.\n");
		redirect_space_size = DEFAULT_REDIRECT_SPACE_SIZE;
	}
	return 0;
}
early_param("redirect_space_size", setup_redirect_space_size);

struct page_map_info *create_page_map_info(int pid)
{
	struct page_map_info *new;

	if (!user_space_reserve_start)
		return NULL;

	if (pin_pid_num >= max_pin_pid_num) {
		pr_warn("Pin pid num too large than max_pin_pid_num, fail create: %d!", pid);
		return NULL;
	}
	new = (struct page_map_info *)(user_space_reserve_start + pin_pid_num);
	new->pid = pid;
	new->pme = NULL;
	new->entry_num = 0;
	new->pid_reserved = false;
	new->disable_free_page = false;
	(*pin_pid_num_addr)++;
	pin_pid_num++;
	return new;
}
EXPORT_SYMBOL_GPL(create_page_map_info);

struct page_map_info *get_page_map_info(int pid)
{
	int i;

	if (!user_space_reserve_start)
		return NULL;

	for (i = 0; i < pin_pid_num; i++) {
		if (user_space_reserve_start[i].pid == pid)
			return &(user_space_reserve_start[i]);
	}
	return NULL;
}
EXPORT_SYMBOL_GPL(get_page_map_info);

static struct page *find_head_page(struct page *page)
{
	struct page *p = page;

	while (!PageBuddy(p)) {
		if (PageLRU(p))
			return NULL;
		p--;
	}
	return p;
}

static void spilt_page_area_left(struct zone *zone, struct free_area *area, struct page *page,
	unsigned long size, int order)
{
	unsigned long cur_size = 1 << order;
	unsigned long total_size = 0;

	while (size && cur_size > size) {
		cur_size >>= 1;
		order--;
		area--;
		if (cur_size <= size) {
			list_add(&page[total_size].lru, &area->free_list[MIGRATE_MOVABLE]);
			atomic_set(&(page[total_size]._mapcount), PAGE_BUDDY_MAPCOUNT_VALUE);
			set_page_private(&page[total_size], order);
			set_pageblock_migratetype(&page[total_size], MIGRATE_MOVABLE);
			area->nr_free++;
			total_size += cur_size;
			size -= cur_size;
		}
	}
}

static void spilt_page_area_right(struct zone *zone, struct free_area *area, struct page *page,
		unsigned long size, int order)
{
	unsigned long cur_size = 1 << order;
	struct page *right_page, *head_page;

	right_page = page + size;
	while (size && cur_size > size) {
		cur_size >>= 1;
		order--;
		area--;
		if (cur_size <= size) {
			head_page = right_page - cur_size;
			list_add(&head_page->lru, &area->free_list[MIGRATE_MOVABLE]);
			atomic_set(&(head_page->_mapcount), PAGE_BUDDY_MAPCOUNT_VALUE);
			set_page_private(head_page, order);
			set_pageblock_migratetype(head_page, MIGRATE_MOVABLE);
			area->nr_free++;
			size -= cur_size;
			right_page = head_page;
		}
	}
}

void reserve_page_from_buddy(unsigned long nr_pages, struct page *page)
{
	unsigned int current_order;
	struct page *page_end;
	struct free_area *area;
	struct zone *zone;
	struct page *head_page;

	head_page = find_head_page(page);
	if (!head_page) {
		pr_warn("Find page head fail.");
		return;
	}
	current_order = head_page->private;
	page_end = head_page + (1 << current_order);
	zone = page_zone(head_page);
	area = &(zone->free_area[current_order]);
	list_del(&head_page->lru);
	atomic_set(&head_page->_mapcount, -1);
	set_page_private(head_page, 0);
	area->nr_free--;
	if (head_page != page)
		spilt_page_area_left(zone, area, head_page,
			(unsigned long)(page - head_page), current_order);
	page = page + nr_pages;
	if (page < page_end) {
		spilt_page_area_right(zone, area, page,
			(unsigned long)(page_end - page), current_order);
	} else if (page > page_end) {
		pr_warn("Find page end smaller than page.");
	}
}

static inline void reserve_user_normal_pages(struct page *page)
{
	atomic_inc(&page->_refcount);
	reserve_page_from_buddy(1, page);
}

static void init_huge_pmd_pages(struct page *head_page)
{
	int i = 0;
	struct page *page = head_page;

	__set_bit(PG_head, &page->flags);
	__set_bit(PG_active, &page->flags);
	atomic_set(&page->_refcount, 1);
	page++;
	i++;
	page->compound_head = (unsigned long)head_page + 1;
	page->compound_dtor = HUGETLB_PAGE_DTOR + 1;
	page->compound_order = HPAGE_PMD_ORDER;
	page++;
	i++;
	page->compound_head = (unsigned long)head_page + 1;
	i++;
	INIT_LIST_HEAD(&(page->deferred_list));
	for (; i < HPAGE_PMD_NR; i++) {
		page = head_page + i;
		page->compound_head = (unsigned long)head_page + 1;
	}
}

static inline void reserve_user_huge_pmd_pages(struct page *page)
{
	atomic_inc(&page->_refcount);
	reserve_page_from_buddy((1 << HPAGE_PMD_ORDER), page);
	init_huge_pmd_pages(page);
}

int reserve_user_map_pages_fail;

void free_user_map_pages(unsigned int pid_index, unsigned int entry_index, unsigned int page_index)
{
	unsigned int i, j, index, order;
	struct page_map_info *pmi;
	struct page_map_entry *pme;
	struct page *page;
	unsigned long phy_addr;

	for (index = 0; index < pid_index; index++) {
		pmi = &(user_space_reserve_start[index]);
		pme = pmi->pme;
		for (i = 0; i < pmi->entry_num; i++) {
			for (j = 0; j < pme->nr_pages; j++) {
				order = pme->is_huge_page ? HPAGE_PMD_ORDER : 0;
				phy_addr = pme->phy_addr_array[j];
				if (phy_addr) {
					page = phys_to_page(phy_addr);
					if (!(page->flags & PAGE_FLAGS_CHECK_RESERVED)) {
						__free_pages(page, order);
						pme->phy_addr_array[j] = 0;
					}
				}
			}
			pme = (struct page_map_entry *)next_pme(pme);
		}
	}
	pmi = &(user_space_reserve_start[index]);
	pme = pmi->pme;
	for (i = 0; i < entry_index; i++) {
		for (j = 0; j < pme->nr_pages; j++) {
			order = pme->is_huge_page ? HPAGE_PMD_ORDER : 0;
			phy_addr = pme->phy_addr_array[j];
			if (phy_addr) {
				page = phys_to_page(phy_addr);
				if (!(page->flags & PAGE_FLAGS_CHECK_RESERVED)) {
					__free_pages(page, order);
					pme->phy_addr_array[j] = 0;
				}
			}
		}
		pme = (struct page_map_entry *)next_pme(pme);
	}
	for (j = 0; j < page_index; j++) {
		order = pme->is_huge_page ? HPAGE_PMD_ORDER : 0;
		phy_addr = pme->phy_addr_array[j];
		if (phy_addr) {
			page = phys_to_page(phy_addr);
			if (!(page->flags & PAGE_FLAGS_CHECK_RESERVED)) {
				__free_pages(page, order);
				pme->phy_addr_array[j] = 0;
			}
		}
	}
}

bool check_redirect_end_valid(struct redirect_info *redirect_start,
			unsigned long max_redirect_page_num)
{
	unsigned long redirect_end;

	redirect_end = ((unsigned long)(redirect_start + 1) +
		max_redirect_page_num * sizeof(unsigned int));
	if (redirect_end > redirect_space_start + redirect_space_size)
		return false;
	return false;
}

static void reserve_user_space_map_pages(void)
{
	struct page_map_info *pmi;
	struct page_map_entry *pme;
	unsigned int i, j, index;
	struct page *page;
	unsigned long flags;
	unsigned long phy_addr;
	unsigned long redirect_pages = 0;
	struct redirect_info *redirect_start = (struct redirect_info *)redirect_space_start;

	if (!user_space_reserve_start || !redirect_start)
		return;
	spin_lock_irqsave(&page_map_entry_lock, flags);
	for (index = 0; index < pin_pid_num; index++) {
		pmi = &(user_space_reserve_start[index]);
		pme = pmi->pme;
		for (i = 0; i < pmi->entry_num; i++) {
			redirect_pages = 0;
			if (!check_redirect_end_valid(redirect_start, pme->nr_pages))
				redirect_start = NULL;
			for (j = 0; j < pme->nr_pages; j++) {
				phy_addr = pme->phy_addr_array[j];
				if (!phy_addr)
					continue;
				page = phys_to_page(phy_addr);
				if (atomic_read(&page->_refcount)) {
					if ((page->flags & PAGE_FLAGS_CHECK_RESERVED)
						&& !pme->redirect_start)
						pme->redirect_start =
							(unsigned long)redirect_start;
					if (redirect_start &&
						(page->flags & PAGE_FLAGS_CHECK_RESERVED)) {
						redirect_start->redirect_index[redirect_pages] = j;
						redirect_pages++;
						continue;
					} else {
						reserve_user_map_pages_fail = 1;
						pr_warn("Page %pK refcount %d large than zero, no need reserve.\n",
						page, atomic_read(&page->_refcount));
						goto free_pages;
					}
				}
				if (!pme->is_huge_page)
					reserve_user_normal_pages(page);
				else
					reserve_user_huge_pmd_pages(page);
			}
			pme = (struct page_map_entry *)next_pme(pme);
			if (redirect_pages && redirect_start) {
				redirect_start->redirect_pages = redirect_pages;
				redirect_start = (struct redirect_info *)(
					(unsigned long)(redirect_start + 1) +
					redirect_start->redirect_pages * sizeof(unsigned int));
			}
		}
	}
	spin_unlock(&page_map_entry_lock);
	return;
free_pages:
	free_user_map_pages(index, i, j);
	spin_unlock(&page_map_entry_lock);
}


int calculate_pin_mem_digest(struct pin_mem_dump_info *pmdi, char *digest)
{
	int i;
	struct sha256_state sctx;

	if (!digest)
		digest = pmdi->sha_digest;
	sha256_init(&sctx);
	sha256_update(&sctx, (unsigned char *)(&(pmdi->magic)),
		sizeof(struct pin_mem_dump_info) - SHA256_DIGEST_SIZE);
	for (i = 0; i < pmdi->pin_pid_num; i++) {
		sha256_update(&sctx, (unsigned char *)(&(pmdi->pmi_array[i])),
			sizeof(struct page_map_info));
	}
	sha256_final(&sctx, digest);
	return 0;
}

static int check_sha_digest(struct pin_mem_dump_info *pmdi)
{
	int ret = 0;
	char digest[SHA256_DIGEST_SIZE] = {0};

	ret = calculate_pin_mem_digest(pmdi, digest);
	if (ret) {
		pr_warn("calculate pin mem digest fail:%d\n", ret);
		return ret;
	}
	if (memcmp(pmdi->sha_digest, digest, SHA256_DIGEST_SIZE)) {
		pr_warn("pin mem dump info sha256 digest match error!\n");
		return -EFAULT;
	}
	return ret;
}

/*
 * The whole page map entry collect process must be Sequentially.
 * The user_space_reserve_start points to the first page map info for
 * the first dump task. And the page_map_entry_start points to
 * the first page map entry of the first dump vma.
 */
static void init_page_map_info(struct pin_mem_dump_info *pmdi, unsigned long map_len)
{
	if (pin_mem_dump_start || !max_pin_pid_num) {
		pr_warn("pin page map already init or max_pin_pid_num not set.\n");
		return;
	}
	if (map_len < sizeof(struct pin_mem_dump_info) +
		max_pin_pid_num * sizeof(struct page_map_info) + redirect_space_size) {
		pr_warn("pin memory reserved memblock too small.\n");
		return;
	}
	if ((pmdi->magic != PIN_MEM_DUMP_MAGIC) || (pmdi->pin_pid_num > max_pin_pid_num) ||
		check_sha_digest(pmdi))
		memset(pmdi, 0, sizeof(struct pin_mem_dump_info));
	pin_mem_dump_start = pmdi;
	pin_pid_num = pmdi->pin_pid_num;
	pr_info("pin_pid_num: %d\n", pin_pid_num);
	pin_pid_num_addr = &(pmdi->pin_pid_num);
	user_space_reserve_start =
		(struct page_map_info *)pmdi->pmi_array;
	page_map_entry_start =
		(struct page_map_entry *)(user_space_reserve_start + max_pin_pid_num);
	__page_map_entry_start = page_map_entry_start;
	page_map_entry_end = (unsigned long)pmdi + map_len - redirect_space_size;
	redirect_space_start = page_map_entry_end;
	if (pin_pid_num > 0)
		reserve_user_space_map_pages();
}

int finish_pin_mem_dump(void)
{
	int ret;

	if (!pin_mem_dump_start)
		return -EFAULT;
	pin_mem_dump_start->magic = PIN_MEM_DUMP_MAGIC;
	memset(pin_mem_dump_start->sha_digest, 0, SHA256_DIGEST_SIZE);
	ret = calculate_pin_mem_digest(pin_mem_dump_start, NULL);
	if (ret) {
		pr_warn("calculate pin mem digest fail:%d\n", ret);
		return ret;
	}
	return ret;
}
EXPORT_SYMBOL_GPL(finish_pin_mem_dump);

int collect_pmd_huge_pages(struct task_struct *task,
	unsigned long start_addr, unsigned long end_addr, struct page_map_entry *pme)
{
	int ret, i, res;
	int index = 0;
	unsigned long start = start_addr;
	struct page *temp_page;
	unsigned long *pte_entry = pagemap_buffer;
	unsigned int count;
	struct mm_struct *mm = task->mm;

	while (start < end_addr) {
		temp_page = NULL;
		count = 0;
		ret = pagemap_get(mm, pin_mem_pagemapread,
			start, start + HPAGE_PMD_SIZE, pte_entry, &count);
		if (ret || !count) {
			pr_warn("Get huge page fail: %d.", ret);
			return COLLECT_PAGES_FAIL;
		}
		/* For huge page, get one map entry per time. */
		if ((pte_entry[0] & PM_SWAP) && (count == 1)) {
			res = get_user_pages_remote(mm, start,
				1, FOLL_TOUCH | FOLL_GET, &temp_page, NULL, NULL);
			if (!res) {
				pr_warn("Swap in huge page fail.\n");
				return COLLECT_PAGES_FAIL;
			}
			pme->phy_addr_array[index] = page_to_phys(temp_page);
			start += HPAGE_PMD_SIZE;
			index++;
			continue;
		}
		if (IS_PTE_PRESENT(pte_entry[0])) {
			temp_page = pfn_to_page(pte_entry[0] & PM_PFRAME_MASK);
			if (PageHead(temp_page)) {
				atomic_inc(&((temp_page)->_refcount));
				start += HPAGE_PMD_SIZE;
				pme->phy_addr_array[index] = page_to_phys(temp_page);
				index++;
			} else {
				/* If the page is not compound head, goto collect normal pages. */
				pme->nr_pages = index;
				return COLLECT_PAGES_NEED_CONTINUE;
			}
		} else {
			for (i = 1; i < count; i++) {
				if (pte_entry[i] & PM_PFRAME_MASK) {
					pme->nr_pages = index;
					return COLLECT_PAGES_NEED_CONTINUE;
				}
			}
			start += HPAGE_PMD_SIZE;
			pme->phy_addr_array[index] = 0;
			index++;
		}
	}
	pme->nr_pages = index;
	return COLLECT_PAGES_FINISH;
}

int collect_normal_pages(struct task_struct *task,
	unsigned long start_addr, unsigned long end_addr, struct page_map_entry *pme)
{
	int ret, res;
	unsigned long next;
	unsigned long i, nr_pages;
	struct page *tmp_page;
	unsigned long *phy_addr_array = pme->phy_addr_array;
	unsigned int count;
	unsigned long *pte_entry = pagemap_buffer;
	struct mm_struct *mm = task->mm;

	next = (start_addr & HPAGE_PMD_MASK) + HPAGE_PMD_SIZE;
	next = (next > end_addr) ? end_addr : next;
	pme->nr_pages = 0;
	while (start_addr < next) {
		count = 0;
		nr_pages = (PAGE_ALIGN(next) - start_addr) / PAGE_SIZE;
		ret = pagemap_get(mm, pin_mem_pagemapread,
			start_addr, next, pte_entry, &count);
		if (ret || !count) {
			pr_warn("Get user page fail: %d, count: %u.\n",
				ret, count);
			return COLLECT_PAGES_FAIL;
		}

		if (IS_PTE_PRESENT(pte_entry[0])) {
			tmp_page = pfn_to_page(pte_entry[0] & PM_PFRAME_MASK);
			/* If the page is compound head, goto collect huge pages. */
			if (PageHead(tmp_page))
				return COLLECT_PAGES_NEED_CONTINUE;
			if (PageTail(tmp_page)) {
				start_addr = next;
				pme->virt_addr = start_addr;
				next = NEXT_PIN_ADDR(next, end_addr);
				continue;
			}
		}
		for (i = 0; i < count; i++) {
			if (pte_entry[i] & PM_SWAP) {
				res = get_user_pages_remote(mm, start_addr + i * PAGE_SIZE,
					1, FOLL_TOUCH | FOLL_GET, &tmp_page, NULL, NULL);
				if (!res) {
					pr_warn("Swap in page fail.\n");
					return COLLECT_PAGES_FAIL;
				}
				phy_addr_array[i] = page_to_phys(tmp_page);
				continue;
			}
			if (!IS_PTE_PRESENT(pte_entry[i])) {
				phy_addr_array[i] = 0;
				continue;
			}
			tmp_page = pfn_to_page(pte_entry[i] & PM_PFRAME_MASK);
			atomic_inc(&(tmp_page->_refcount));
			phy_addr_array[i] = ((pte_entry[i] & PM_PFRAME_MASK) << PAGE_SHIFT);
		}
		pme->nr_pages += count;
		phy_addr_array += count;
		start_addr = next;
		next = NEXT_PIN_ADDR(next, end_addr);
	}
	return COLLECT_PAGES_FINISH;
}

void free_pin_pages(struct page_map_entry *pme)
{
	unsigned long i;
	struct page *tmp_page;

	for (i = 0; i < pme->nr_pages; i++) {
		if (pme->phy_addr_array[i]) {
			tmp_page = phys_to_page(pme->phy_addr_array[i]);
			atomic_dec(&(tmp_page->_refcount));
			pme->phy_addr_array[i] = 0;
		}
	}
}

int init_pagemap_read(void)
{
	int ret = -ENOMEM;

	if (pin_mem_pagemapread)
		return 0;

	mutex_lock(&pin_mem_mutex);
	pin_mem_pagemapread = create_pagemapread();
	if (!pin_mem_pagemapread)
		goto out;
	pagemap_buffer = (unsigned long *)kmalloc((PMD_SIZE >> PAGE_SHIFT) *
		sizeof(unsigned long), GFP_KERNEL);
	if (!pagemap_buffer)
		goto free;

	ret = 0;
out:
	mutex_unlock(&pin_mem_mutex);
	return ret;
free:
	kfree(pin_mem_pagemapread);
	pin_mem_pagemapread = NULL;
	goto out;
}
EXPORT_SYMBOL_GPL(init_pagemap_read);

/* Users make sure that the pin memory belongs to anonymous vma. */
int pin_mem_area(struct task_struct *task, struct mm_struct *mm,
		unsigned long start_addr, unsigned long end_addr)
{
	int pid, ret;
	int is_huge_page = false;
	unsigned int page_size;
	unsigned long nr_pages, flags;
	struct page_map_entry *pme;
	struct page_map_info *pmi;
	struct vm_area_struct *vma;
	unsigned long i;
	struct page *tmp_page;

	if (!page_map_entry_start
		|| !task || !mm
		|| start_addr >= end_addr || !pin_mem_pagemapread)
		return -EFAULT;

	pid = task->pid;
	spin_lock_irqsave(&page_map_entry_lock, flags);
	nr_pages = ((end_addr - start_addr) / PAGE_SIZE);
	if ((unsigned long)page_map_entry_start + nr_pages * sizeof(struct page *) >=
		page_map_entry_end) {
		pr_warn("Page map entry use up!\n");
		ret = -EFAULT;
		goto finish;
	}
	vma = find_extend_vma(mm, start_addr);
	if (!vma) {
		pr_warn("Find no match vma!\n");
		ret = -EFAULT;
		goto finish;
	}
	if (start_addr == (start_addr & HPAGE_PMD_MASK) &&
		transparent_hugepage_enabled(vma)) {
		page_size = HPAGE_PMD_SIZE;
		is_huge_page = true;
	} else {
		page_size = PAGE_SIZE;
	}
	pme = page_map_entry_start;
	pme->virt_addr = start_addr;
	pme->redirect_start = 0;
	pme->is_huge_page = is_huge_page;
	memset(pme->phy_addr_array, 0, nr_pages * sizeof(unsigned long));
	down_read(&mm->mmap_lock);
	if (!is_huge_page) {
		ret = collect_normal_pages(task, start_addr, end_addr, pme);
		if (ret != COLLECT_PAGES_FAIL && !pme->nr_pages) {
			if (ret == COLLECT_PAGES_FINISH) {
				ret = 0;
				up_read(&mm->mmap_lock);
				goto finish;
			}
			pme->is_huge_page = true;
			page_size = HPAGE_PMD_SIZE;
			ret = collect_pmd_huge_pages(task, pme->virt_addr, end_addr, pme);
		}
	} else {
		ret = collect_pmd_huge_pages(task, start_addr, end_addr, pme);
		if (ret != COLLECT_PAGES_FAIL && !pme->nr_pages) {
			if (ret == COLLECT_PAGES_FINISH) {
				ret = 0;
				up_read(&mm->mmap_lock);
				goto finish;
			}
			pme->is_huge_page = false;
			page_size = PAGE_SIZE;
			ret = collect_normal_pages(task, pme->virt_addr, end_addr, pme);
		}
	}
	up_read(&mm->mmap_lock);
	if (ret == COLLECT_PAGES_FAIL) {
		ret = -EFAULT;
		goto finish;
	}

	/* check for zero pages */
	for (i = 0; i < pme->nr_pages; i++) {
		tmp_page = phys_to_page(pme->phy_addr_array[i]);
		if (!pme->is_huge_page) {
			if (page_to_pfn(tmp_page) == my_zero_pfn(pme->virt_addr + i * PAGE_SIZE))
				pme->phy_addr_array[i] = 0;
		} else if (is_huge_zero_page(tmp_page))
			pme->phy_addr_array[i] = 0;
	}

	page_map_entry_start = (struct page_map_entry *)(next_pme(pme));
	pmi = get_page_map_info(pid);
	if (!pmi)
		pmi = create_page_map_info(pid);
	if (!pmi) {
		pr_warn("Create page map info fail for pid: %d!\n", pid);
		ret = -EFAULT;
		goto finish;
	}
	if (!pmi->pme)
		pmi->pme = pme;
	pmi->entry_num++;
	spin_unlock_irqrestore(&page_map_entry_lock, flags);
	if (ret == COLLECT_PAGES_NEED_CONTINUE)
		ret = pin_mem_area(task, mm, pme->virt_addr + pme->nr_pages * page_size, end_addr);
	return ret;
finish:
	if (ret)
		free_pin_pages(pme);
	spin_unlock_irqrestore(&page_map_entry_lock, flags);
	return ret;
}
EXPORT_SYMBOL_GPL(pin_mem_area);

vm_fault_t remap_normal_pages(struct mm_struct *mm, struct vm_area_struct *vma,
		struct page_map_entry *pme)
{
	int ret;
	unsigned int j, i;
	pgd_t *pgd;
	p4d_t *p4d;
	pmd_t *pmd;
	pud_t *pud;
	struct page *page, *new;
	unsigned long address;
	unsigned long phy_addr;
	unsigned int redirect_pages = 0;
	struct redirect_info *redirect_start;

	redirect_start = (struct redirect_info *)pme->redirect_start;
	for (j = 0; j < pme->nr_pages; j++) {
		address = pme->virt_addr + j * PAGE_SIZE;
		phy_addr = pme->phy_addr_array[j];
		if (!phy_addr)
			continue;
		page = phys_to_page(phy_addr);
		if (page_to_pfn(page) == my_zero_pfn(address)) {
			pme->phy_addr_array[j] = 0;
			continue;
		}
		pme->phy_addr_array[j] = 0;
		if (redirect_start && (redirect_pages < redirect_start->redirect_pages) &&
			(j == redirect_start->redirect_index[redirect_pages])) {
			new = alloc_zeroed_user_highpage_movable(vma, address);
			if (!new) {
				pr_warn("Redirect alloc page fail\n");
				continue;
			}
			copy_page(page_to_virt(new), phys_to_virt(phy_addr));
			page = new;
			redirect_pages++;
		}
		page->mapping = NULL;
		pgd = pgd_offset(mm, address);
		p4d = p4d_alloc(mm, pgd, address);
		if (!p4d) {
			ret = VM_FAULT_OOM;
			goto free;
		}
		pud = pud_alloc(mm, p4d, address);
		if (!pud) {
			ret = VM_FAULT_OOM;
			goto free;
		}
		pmd = pmd_alloc(mm, pud, address);
		if (!pmd) {
			ret = VM_FAULT_OOM;
			goto free;
		}
		ret = do_anon_page_remap(vma, address, pmd, page);
		if (ret)
			goto free;
	}
	return 0;
free:
	for (i = j; i < pme->nr_pages; i++) {
		phy_addr = pme->phy_addr_array[i];
		if (phy_addr) {
			__free_page(phys_to_page(phy_addr));
			pme->phy_addr_array[i] = 0;
		}
	}
	return ret;
}

static inline gfp_t get_hugepage_gfpmask(struct vm_area_struct *vma)
{
	const bool vma_madvised = !!(vma->vm_flags & VM_HUGEPAGE);

	if (test_bit(TRANSPARENT_HUGEPAGE_DEFRAG_DIRECT_FLAG, &transparent_hugepage_flags))
		return GFP_TRANSHUGE | (vma_madvised ? 0 : __GFP_NORETRY);
	if (test_bit(TRANSPARENT_HUGEPAGE_DEFRAG_KSWAPD_FLAG, &transparent_hugepage_flags))
		return GFP_TRANSHUGE_LIGHT | __GFP_KSWAPD_RECLAIM;
	if (test_bit(TRANSPARENT_HUGEPAGE_DEFRAG_KSWAPD_OR_MADV_FLAG, &transparent_hugepage_flags))
		return GFP_TRANSHUGE_LIGHT | (vma_madvised ? __GFP_DIRECT_RECLAIM :
							     __GFP_KSWAPD_RECLAIM);
	if (test_bit(TRANSPARENT_HUGEPAGE_DEFRAG_REQ_MADV_FLAG, &transparent_hugepage_flags))
		return GFP_TRANSHUGE_LIGHT | (vma_madvised ? __GFP_DIRECT_RECLAIM :
							     0);
	return GFP_TRANSHUGE_LIGHT;
}

vm_fault_t remap_huge_pmd_pages(struct mm_struct *mm, struct vm_area_struct *vma,
		struct page_map_entry *pme)
{
	int ret;
	unsigned int j, i;
	pgd_t *pgd;
	p4d_t *p4d;
	pmd_t *pmd;
	pud_t *pud;
	gfp_t gfp;
	struct page *page, *new;
	unsigned long address;
	unsigned long phy_addr;
	unsigned int redirect_pages = 0;
	struct redirect_info *redirect_start;

	redirect_start = (struct redirect_info *)pme->redirect_start;
	for (j = 0; j < pme->nr_pages; j++) {
		address = pme->virt_addr + j * HPAGE_PMD_SIZE;
		phy_addr = pme->phy_addr_array[j];
		if (!phy_addr)
			continue;
		page = phys_to_page(phy_addr);
		if (is_huge_zero_page(page)) {
			pme->phy_addr_array[j] = 0;
			continue;
		}
		pme->phy_addr_array[j] = 0;
		if (redirect_start && (redirect_pages < redirect_start->redirect_pages) &&
			(j == redirect_start->redirect_index[redirect_pages])) {
			gfp = get_hugepage_gfpmask(vma);
			new = alloc_hugepage_vma(gfp, vma, address, HPAGE_PMD_ORDER);
			if (!new) {
				pr_warn("Redirect alloc huge page fail\n");
				continue;
			}
			memcpy(page_to_virt(new), phys_to_virt(phy_addr), HPAGE_PMD_SIZE);
			page = new;
			redirect_pages++;
		}
		pgd = pgd_offset(mm, address);
		p4d = p4d_alloc(mm, pgd, address);
		if (!p4d) {
			ret = VM_FAULT_OOM;
			goto free;
		}
		pud = pud_alloc(mm, p4d, address);
		if (!pud) {
			ret = VM_FAULT_OOM;
			goto free;
		}
		pmd = pmd_alloc(mm, pud, address);
		if (!pmd) {
			ret = VM_FAULT_OOM;
			goto free;
		}
		ret = do_anon_huge_page_remap(vma, address, pmd, page);
		if (ret)
			goto free;
	}
	return 0;
free:
	for (i = j; i < pme->nr_pages; i++) {
		phy_addr = pme->phy_addr_array[i];
		if (phy_addr) {
			page = phys_to_page(phy_addr);
			if (!(page->flags & PAGE_FLAGS_CHECK_RESERVED)) {
				__free_pages(page, HPAGE_PMD_ORDER);
				pme->phy_addr_array[i] = 0;
			}
		}
	}
	return ret;
}

static void free_unmap_pages(struct page_map_info *pmi,
			struct page_map_entry *pme,
			unsigned int index)
{
	unsigned int i, j;
	unsigned long phy_addr;
	unsigned int order;
	struct page *page;

	pme = (struct page_map_entry *)(next_pme(pme));
	for (i = index; i < pmi->entry_num; i++) {
		for (j = 0; j < pme->nr_pages; j++) {
			phy_addr = pme->phy_addr_array[i];
			if (phy_addr) {
				page = phys_to_page(phy_addr);
				order = pme->is_huge_page ? HPAGE_PMD_ORDER : 0;
				if (!(page->flags & PAGE_FLAGS_CHECK_RESERVED)) {
					__free_pages(page, order);
					pme->phy_addr_array[i] = 0;
				}
			}
		}
		pme = (struct page_map_entry *)(next_pme(pme));
	}
}

vm_fault_t do_mem_remap(int pid, struct mm_struct *mm)
{
	unsigned int i = 0;
	vm_fault_t ret = 0;
	struct vm_area_struct *vma;
	struct page_map_info *pmi;
	struct page_map_entry *pme;
	unsigned long flags;

	if (reserve_user_map_pages_fail)
		return -EFAULT;
	pmi = get_page_map_info(pid);
	if (!pmi)
		return -EFAULT;

	spin_lock_irqsave(&page_map_entry_lock, flags);
	pmi->disable_free_page = true;
	spin_unlock(&page_map_entry_lock);
	down_write(&mm->mmap_lock);
	pme = pmi->pme;
	vma = mm->mmap;
	while ((i < pmi->entry_num) && (vma != NULL)) {
		if (pme->virt_addr >= vma->vm_start && pme->virt_addr < vma->vm_end) {
			i++;
			if (!vma_is_anonymous(vma)) {
				pme = (struct page_map_entry *)(next_pme(pme));
				continue;
			}
			if (!pme->is_huge_page) {
				ret = remap_normal_pages(mm, vma, pme);
				if (ret < 0)
					goto free;
			} else {
				ret = remap_huge_pmd_pages(mm, vma, pme);
				if (ret < 0)
					goto free;
			}
			pme = (struct page_map_entry *)(next_pme(pme));
		} else {
			vma = vma->vm_next;
		}
	}
	up_write(&mm->mmap_lock);
	return 0;
free:
	free_unmap_pages(pmi, pme, i);
	up_write(&mm->mmap_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(do_mem_remap);

#if defined(CONFIG_ARM64)
void init_reserve_page_map(unsigned long map_addr, unsigned long map_size)
{
	void *addr;

	if (!map_addr || !map_size)
		return;
	addr = phys_to_virt(map_addr);
	init_page_map_info((struct pin_mem_dump_info *)addr, map_size);
}
#else
void init_reserve_page_map(unsigned long map_addr, unsigned long map_size)
{
}
#endif

static void free_all_reserved_pages(void)
{
	unsigned int i, j, index, order;
	struct page_map_info *pmi;
	struct page_map_entry *pme;
	struct page *page;
	unsigned long phy_addr;

	if (!user_space_reserve_start || reserve_user_map_pages_fail)
		return;

	for (index = 0; index < pin_pid_num; index++) {
		pmi = &(user_space_reserve_start[index]);
		if (pmi->disable_free_page)
			continue;
		pme = pmi->pme;
		for (i = 0; i < pmi->entry_num; i++) {
			for (j = 0; j < pme->nr_pages; j++) {
				order = pme->is_huge_page ? HPAGE_PMD_ORDER : 0;
				phy_addr = pme->phy_addr_array[j];
				if (phy_addr) {
					page = phys_to_page(phy_addr);
					if (!(page->flags & PAGE_FLAGS_CHECK_RESERVED)) {
						__free_pages(page, order);
						pme->phy_addr_array[j] = 0;
					}
				}
			}
			pme = (struct page_map_entry *)next_pme(pme);
		}
	}
}

/* Clear all pin memory record. */
void clear_pin_memory_record(void)
{
	unsigned long flags;

	spin_lock_irqsave(&page_map_entry_lock, flags);
	free_all_reserved_pages();
	if (pin_pid_num_addr) {
		*pin_pid_num_addr = 0;
		pin_pid_num = 0;
		page_map_entry_start = __page_map_entry_start;
	}
	spin_unlock(&page_map_entry_lock);
}
EXPORT_SYMBOL_GPL(clear_pin_memory_record);

#ifdef CONFIG_PID_RESERVE
struct idr *reserve_idr;

/* test if there exist pin memory tasks */
bool is_need_reserve_pids(void)
{
	return (pin_pid_num > 0);
}

void free_reserved_pid(struct idr *idr, int pid)
{
	unsigned int index;
	struct page_map_info *pmi;

	if (!max_pin_pid_num || idr != reserve_idr)
		return;

	for (index = 0; index < pin_pid_num; index++) {
		pmi = &(user_space_reserve_start[index]);
		if (pmi->pid == pid && pmi->pid_reserved) {
			idr_remove(idr, pid);
			return;
		}
	}
}

/* reserve pids for check point tasks which pinned memory */
void reserve_pids(struct idr *idr, int pid_max)
{
	int alloc_pid;
	unsigned int index;
	struct page_map_info *pmi;

	if (!max_pin_pid_num)
		return;
	reserve_idr = idr;
	for (index = 0; index < pin_pid_num; index++) {
		pmi = &(user_space_reserve_start[index]);
		pmi->pid_reserved = true;
		alloc_pid = idr_alloc(idr, NULL, pmi->pid, pid_max, GFP_ATOMIC);
		if (alloc_pid != pmi->pid) {
			if (alloc_pid > 0)
				idr_remove(idr, alloc_pid);
			pr_warn("Reserve pid (%d) fail, real pid is %d.\n", alloc_pid, pmi->pid);
			pmi->pid_reserved = false;
			continue;
		}
	}
}
#endif /* CONFIG_PID_RESERVE */

#endif /* CONFIG_PIN_MEMORY */
