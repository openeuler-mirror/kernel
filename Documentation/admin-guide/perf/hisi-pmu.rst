======================================================
HiSilicon SoC uncore Performance Monitoring Unit (PMU)
======================================================

The HiSilicon SoC chip includes various independent system device PMUs
such as L3 cache (L3C), Hydra Home Agent (HHA) and DDRC. These PMUs are
independent and have hardware logic to gather statistics and performance
information.

The HiSilicon SoC encapsulates multiple CPU and IO dies. Each CPU cluster
(CCL) is made up of 4 cpu cores sharing one L3 cache; each CPU die is
called Super CPU cluster (SCCL) and is made up of 6 CCLs. Each SCCL has
two HHAs (0 - 1) and four DDRCs (0 - 3), respectively.

HiSilicon SoC uncore PMU driver
-------------------------------

Each device PMU has separate registers for event counting, control and
interrupt, and the PMU driver shall register perf PMU drivers like L3C,
HHA and DDRC etc. The available events and configuration options shall
be described in the sysfs, see::

/sys/bus/event_source/devices/hisi_sccl{X}_<l3c{Y}/hha{Y}/ddrc{Y}>

or::

/sys/devices/hisi_sccl{X}_<l3c{Y}/hha{Y}/ddrc{Y}>
The "perf list" command shall list the available events from sysfs.

Each L3C, HHA and DDRC is registered as a separate PMU with perf. The PMU
name will appear in event listing as hisi_sccl<sccl-id>_module<index-id>.
where "sccl-id" is the identifier of the SCCL and "index-id" is the index of
module.

e.g. hisi_sccl3_l3c0/rd_hit_cpipe is READ_HIT_CPIPE event of L3C index #0 in
SCCL ID #3.

e.g. hisi_sccl1_hha0/rx_operations is RX_OPERATIONS event of HHA index #0 in
SCCL ID #1.

The driver also provides a "cpumask" sysfs attribute, which shows the CPU core
ID used to count the uncore PMU event. An "associated_cpus" sysfs attribute is
also provided to show the CPUs associated with this PMU. The "cpumask" indicates
the CPUs to open the events, usually as a hint for userspaces tools like perf.
It only contains one associated CPU from the "associated_cpus".

Example usage of perf::

  $# perf list
  hisi_sccl3_l3c0/rd_hit_cpipe/ [kernel PMU event]
  ------------------------------------------
  hisi_sccl3_l3c0/wr_hit_cpipe/ [kernel PMU event]
  ------------------------------------------
  hisi_sccl1_l3c0/rd_hit_cpipe/ [kernel PMU event]
  ------------------------------------------
  hisi_sccl1_l3c0/wr_hit_cpipe/ [kernel PMU event]
  ------------------------------------------

  $# perf stat -a -e hisi_sccl3_l3c0/rd_hit_cpipe/ sleep 5
  $# perf stat -a -e hisi_sccl3_l3c0/config=0x02/ sleep 5

6. ch: NoC PMU supports filtering the event counts of certain transaction
channel with this option. The current supported channels are as follows:

- 3'b010: Request channel
- 3'b100: Snoop channel
- 3'b110: Response channel
- 3'b111: Data channel

7. tt_en: NoC PMU supports counting only transactions that have tracetag set
if this option is set. See the 2nd list for more information about tracetag.

For HiSilicon uncore PMU v3 whose identifier is 0x40, some uncore PMUs are
further divided into parts for finer granularity of tracing, each part has its
own dedicated PMU, and all such PMUs together cover the monitoring job of events
on particular uncore device. Such PMUs are described in sysfs with name format
slightly changed::

/sys/bus/event_source/devices/hisi_sccl{X}_<l3c{Y}_{Z}/ddrc{Y}_{Z}/noc{Y}_{Z}>

Z is the sub-id, indicating different PMUs for part of hardware device.

Usage of most PMUs with different sub-ids are identical.  Specially, L3C PMU
provides ``ext`` operand to allow exploration of even finer granual statistics
of L3C PMU.  L3C PMU driver uses that as hint of termination when delivering
perf command to hardware:

- ext=0: Default, could be used with event names.
- ext=1 and ext=2: Must be used with event codes, event names are not supported.

An example of perf command could be::

  $# perf stat -a -e hisi_sccl0_l3c1_0/rd_spipe/ sleep 5

or::

  $# perf stat -a -e hisi_sccl0_l3c1_0/event=0x1,ext=1/ sleep 5

As above, ``hisi_sccl0_l3c1_0`` locates PMU of Super CPU CLuster 0, L3 cache 1
pipe0.

First command locates the first part of L3C since ``ext=0`` is implied by
default.  Second command issues the counting on another part of L3C with the
event ``0x1``.

The current driver does not support sampling. So "perf record" is unsupported.
Also attach to a task is unsupported as the events are all uncore.

Note: Please contact the maintainer for a complete list of events supported for
the PMU devices in the SoC and its information if needed.
