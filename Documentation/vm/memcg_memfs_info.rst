.. SPDX-License-Identifier: GPL-2.0+

================
Memcg Memfs Info
================

Overview
========

Support to print rootfs files and tmpfs files that having pages charged
in given memory cgroup. The files infomations can be printed through
interface "memory.memfs_files_info" or printed when OOM is triggered.

User control
============

1. /sys/kernel/mm/memcg_memfs_info/enable
-----------------------------------------

Boolean type. The default value is 0, set it to 1 to enable the feature.

2. /sys/kernel/mm/memcg_memfs_info/max_print_files_in_oom
---------------------------------------------------------

Unsigned long type. The default value is 500, indicating that the maximum of
files can be print to console when OOM is triggered.

3. /sys/kernel/mm/memcg_memfs_info/size_threshold
-------------------------------------------------

Unsigned long type. The default value is 0, indicating that the minimum size of
files that can be printed.

4. /sys/fs/cgroup/memory/<memory>/memory.memfs_files_info
---------------------------------------------------------

Outputs the files who use memory in this memory cgroup.

---
Liu Shixin, Jan 2022
