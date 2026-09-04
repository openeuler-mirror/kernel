.. SPDX-License-Identifier: GPL-2.0

====================
ZRAM Reclaim Policy
====================

Overview
========

``CONFIG_ZRAM_RECLAIM`` adds a memcg-scoped reclaim policy for selected
ARM64 systems where reclaiming anonymous memory through compressed swap is
preferable to reclaiming file cache.

The policy tracks per-memcg anonymous and file refault cost and uses that
information during classic reclaim balancing.  When enabled, the policy can
prefer anonymous reclaim for a cgroup.  When the anonymous reclaim path is
judged overloaded, reclaim falls back to the regular balancing logic with a
higher swappiness hint.

This mechanism is only active when all of the following are true:

* ``CONFIG_ZRAM_RECLAIM=y``
* ``CONFIG_MEMCG=y``
* ``CONFIG_SWAP=y``
* the kernel is running on a supported ARM64 platform
* multigenerational LRU is not active for the reclaim decision

Beyond enabling the policy, whether it actually biases reclaim on a given
reclaim cycle is a best-effort heuristic subject to additional runtime gates:

* the memcg must have an enabled ``memory.zram_reclaim`` state
* direct reclaim near OOM (priority below the policy floor) is left to the
  normal VM path
* anonymous pages must be at least half of file pages (cache-heavy workloads
  are not forced toward anonymous reclaim)
* when a non-zero ``limit_ratio`` is set, the memcg must have swap in use,
  and the swap-to-(swap+anon) ratio must stay below the configured limit

The policy is a heuristic tuned for ZRAM + slow file backend topologies; it
does not guarantee intervention on every reclaim cycle.

Supported platforms
===================

The userspace control file is registered only on supported ARM64 platforms.
Current support is limited to the following HiSilicon CPU families:

* TSV110
* LinxiCore 9100
* HIP11
* HIP12

On other platforms the kernel does not create ``memory.zram_reclaim``.

Control file
============

The policy is controlled per memory cgroup through ``memory.zram_reclaim``.
The file is created for non-root cgroups in both cgroup v1 and cgroup v2 on
supported platforms.

Reading the file returns two whitespace-separated fields::

  <enabled> <limit_ratio>

``enabled``
  ``0`` if the policy is disabled for the cgroup, ``1`` if enabled.

``limit_ratio``
  The configured swap ratio limit.  A value of ``0`` means disabled.

Writing the file accepts one of the following forms::

  echo 1 > memory.zram_reclaim
  echo "1 <limit_ratio>" > memory.zram_reclaim
  echo "0 0" > memory.zram_reclaim

When enabling the policy:

* ``echo 1`` enables the policy with the default ``limit_ratio`` of ``30``.
* ``limit_ratio`` may be set explicitly in the range ``1`` to ``60``.

When disabling the policy:

* the accepted disable form is ``0 0``.

Behavior notes
==============

The ``limit_ratio`` bounds when the policy remains active for a cgroup.  If
the cgroup's swap footprint grows beyond the configured ratio of the sum of
swap and anonymous pages (i.e. ``swap / (swap + anon)``), the reclaim
decision falls back to the normal path.  For example, the default ratio of
30 falls back once swap exceeds 30% of ``swap + anon``.

Changing ``limit_ratio`` while the policy is already enabled is rejected.  To
apply a different ratio, disable the policy first and then enable it again with
the new value.

The policy uses internal cost accounting driven by:

* anonymous swapin events
* file and anonymous refault events

The accounting is reset when the policy is disabled and enabled again.

NUMA note
=========

The ``limit_ratio`` gate compares the memcg's total swap usage against the
anonymous page count of the lruvec being scanned.  On multi-NODE machines the
swap figure is aggregated across all nodes while the anonymous figure is
per-node, so the effective ratio is scaled by the number of nodes and the gate
falls back earlier than the configured value.  Single-NUMA deployments (the
common case for the target ARM64 platforms) are unaffected.
