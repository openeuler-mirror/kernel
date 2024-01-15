.. SPDX-License-Identifier: GPL-2.0

===============
Dynamic Hugetlb
===============

Overview
========

Dynamic hugetlb is a self-developed feature based on the hugetlb and memcontrol.
It supports to split huge page dynamically in a memory cgroup. There is a new structure
dhugetlb_pool in every mem_cgroup to manage the pages configured to the mem_cgroup.
For the mem_cgroup configured with dhugetlb_pool, processes in the mem_cgroup will
preferentially use the pages in dhugetlb_pool.

Dynamic hugetlb supports three types of pages, including 1G/2M huge pages and 4K pages.
For the mem_cgroup configured with dhugetlb_pool, processes will be limited to alloc
1G/2M huge pages only from dhugetlb_pool. But there is no such constraint for 4K pages.
If there are insufficient 4K pages in the dhugetlb_pool, pages can also be allocated from
buddy system. So before using dynamic hugetlb, user must know how many huge pages they
need.

Conflict
========

1. Conflict with THP
--------------------

When THP is enabled, the allocation of a page(order=0) may be converted to
an allocation of pages(order>0). In this case, the allocation will skip the
dhugetlb_pool. When we want to use dynamic hugetlb feature, we have to
disable THP for now.

2. Conflict with hugetlb_vmemmap
--------------------------------

The dynamic_hugetlb feature need to split and merge pages frequently.
hugetlb_vmemmap will affects the perforemance of page split and merge.
If want to use dynamic hugetlb, please disable hugetlb_vmemmap.

Usage
=====

1) Add 'dynamic_hugetlb=on' in cmdline to enable dynamic hugetlb feature.

2) Prealloc some 1G hugepages through hugetlb.

3) Create a mem_cgroup and configure dhugetlb_pool to mem_cgroup.

4) Configure the count of 1G/2M hugepages, and the remaining pages in dhugetlb_pool will
   be used as basic pages.

5) Bound the process to mem_cgroup. then the memory for it will be allocated from dhugetlb_pool.

User control
============

1. dynamic_hugetlb=
-------------------

Add ``dynamic_hugtlb=on`` in cmdline to enable dynamic hugetlb feature.
By default, the feature si disabled.

2. dhugetlb.nr_pages
--------------------

In each memory cgroup, there is a ``dhugetlb.nr_pages`` interface used to create and configure dynamic
hugetlb. If this interface is not configured, the original functions are not affected. If configured,
then the memory used by processes in this memory cgroup will be allocated from corresponding hpool.

Usage:
	``echo <nid> <nr_pages> > /sys/fs/cgroup/memory/<memory cgroup>/dhugetlb.nr_pages``:

	Create a dynamic hugetlb pool and add <nr_pages> 1G hugepages from numa node <nid> to the pool.

	``cat /sys/fs/cgroup/memory/<memory cgroup>/dhugetlb.nr_pages``:

	Reads the memory information in the hpool, include the free amount and used amount of huge pages and
	normal pages.

3. dhugetlb.1G.reserved_pages
-----------------------------

In each memory cgroup, there is a ``dhugetlb.nr_pages`` interface used to reserved 1G huge pages.
By default, all memory configured to a dynamic hugetlb pool can be used only as normal pages, if want to use
it as 1G huge pages, need to configure the number of 1G huge pages by this interface firstly.

Usage:
	``echo <nr_pages> > /sys/fs/cgroup/memory/<memory cgroup>/dhugetlb.1G.reserved_pages``

4. dhugetlb.2M.reserved_pages
-----------------------------

Similar to the previous interface, this is used to configure the number of 2M huge pages.

Usage:
	``echo <nr_pages> > /sys/fs/cgroup/memory/<memory cgroup>/dhugetlb.2M.reserved_pages``

---
Liu Shixin, Jan 2022
