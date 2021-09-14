%global Arch $(echo %{_host_cpu} | sed -e s/i.86/x86/ -e s/x86_64/x86/ -e s/aarch64.*/arm64/)

%global KernelVer %{version}-%{release}.raspi.%{_target_cpu}

%global hulkrelease 2109.5.0

%global debug_package %{nil}

Name:	 raspberrypi-kernel
Version: 4.19.90
Release: %{hulkrelease}.0030
Summary: Linux Kernel
License: GPL-1.0 and GPL+ and GPLv2 and GPLv2+ and LGPLv2 and LGPLv2+ and LGPLv2.1 and LGPLv2.1+ and ISC and BSD and Apache-2.0 and MIT
URL:	 http://www.kernel.org/
Source0: kernel.tar.gz
Patch0000: 0000-raspberrypi-kernel.patch

BuildRequires: module-init-tools, patch >= 2.5.4, bash >= 2.03, tar
BuildRequires: bzip2, xz, findutils, gzip, m4, perl, make >= 3.78, diffutils, gawk
BuildRequires: gcc >= 3.4.2, binutils >= 2.12
BuildRequires: hostname, net-tools, bc
BuildRequires: xmlto, asciidoc
BuildRequires: openssl-devel
BuildRequires: hmaccalc
BuildRequires: ncurses-devel
BuildRequires: elfutils-libelf-devel
BuildRequires: rpm >= 4.14.2
BuildRequires: elfutils-devel zlib-devel binutils-devel newt-devel python-devel perl(ExtUtils::Embed) bison
BuildRequires: audit-libs-devel
BuildRequires: pciutils-devel gettext
BuildRequires: rpm-build, elfutils
BuildRequires: numactl-devel python3-devel glibc-static python3-docutils
BuildRequires: perl-generators perl(Carp) libunwind-devel gtk2-devel libbabeltrace-devel java-1.8.0-openjdk
AutoReq: no
AutoProv: yes

Provides: raspberrypi-kernel-aarch64 = %{version}-%{release}

ExclusiveArch: aarch64
ExclusiveOS: Linux

%description
The Linux Kernel image for RaspberryPi.

%prep
%setup -q -n kernel-%{version} -c
mv kernel linux-%{version}
cp -a linux-%{version} linux-%{KernelVer}

cd linux-%{KernelVer}
%patch0000 -p1

find . \( -name "*.orig" -o -name "*~" \) -exec rm -f {} \; >/dev/null
find . -name .gitignore -exec rm -f {} \; >/dev/null

%build
cd linux-%{KernelVer}

perl -p -i -e "s/^EXTRAVERSION.*/EXTRAVERSION = -%{release}.raspi.%{_target_cpu}/" Makefile

make ARCH=%{Arch} %{?_smp_mflags} openeuler-raspi_defconfig

make ARCH=%{Arch} %{?_smp_mflags} KERNELRELEASE=%{KernelVer}

%install
cd linux-%{KernelVer}

## install linux

make ARCH=%{Arch} INSTALL_MOD_PATH=$RPM_BUILD_ROOT modules_install KERNELRELEASE=%{KernelVer}
rm -rf $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/source $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/build

mkdir -p $RPM_BUILD_ROOT/boot
TargetImage=$(make -s image_name)
TargetImage=${TargetImage%.*}
install -m 755 $TargetImage $RPM_BUILD_ROOT/boot/vmlinuz-%{KernelVer}
install -m 644 .config $RPM_BUILD_ROOT/boot/config-%{KernelVer}
install -m 644 System.map $RPM_BUILD_ROOT/boot/System.map-%{KernelVer}

mkdir -p $RPM_BUILD_ROOT/boot/dtb-%{KernelVer}/overlays
install -m 644 $(find arch/%{Arch}/boot/dts/broadcom/ -name "*.dtb") $RPM_BUILD_ROOT/boot/dtb-%{KernelVer}/
install -m 644 $(find arch/%{Arch}/boot/dts/overlays/ -name "*.dtbo") $RPM_BUILD_ROOT/boot/dtb-%{KernelVer}/overlays/
if ls arch/%{Arch}/boot/dts/overlays/*.dtb > /dev/null 2>&1; then
    install -m 644 $(find arch/%{Arch}/boot/dts/overlays/ -name "*.dtb") $RPM_BUILD_ROOT/boot/dtb-%{KernelVer}/overlays/
fi
install -m 644 arch/%{Arch}/boot/dts/overlays/README $RPM_BUILD_ROOT/boot/dtb-%{KernelVer}/overlays/

%postun
version_old=0
if [ "$1" == "0" ]; then
    version_old=old
else
    version_tmp=0
    name_len=`echo -n %{name}-|wc -c`
    for item in `rpm -qa %{name} 2>/dev/null`
    do
        cur_version=${item:name_len}
        cpu_version=${cur_version##*.}
        if [ "$cpu_version" == "%{_target_cpu}" ]; then
            cur_version=${cur_version%.*}
            cur_version=$cur_version.raspi.$cpu_version
            if [[ "$cur_version" != "%{KernelVer}" && "$cur_version" > "$version_tmp" ]]; then
                version_tmp=$cur_version
            fi
        fi
    done
    if [[ "$version_tmp" < "%{KernelVer}" ]]; then
        version_old=$version_tmp
    fi
fi
if [ "$version_old" != "0" ]; then
    if [ -f /boot/vmlinuz-$version_old ] && [ -d /boot/dtb-$version_old ] && ( [ "$version_old" == "old" ] || [ -d /lib/modules/$version_old ] ); then
        ls /boot/dtb-$version_old/overlays/*.dtbo > /dev/null 2>&1
        if [ "$?" == "0" ]; then
            ls /boot/dtb-$version_old/*.dtb > /dev/null 2>&1
            if [ "$?" == "0" ]; then
                rm -rf /boot/*.dtb /boot/overlays /boot/kernel8.img
                mkdir /boot/overlays
                install -m 755 /boot/vmlinuz-$version_old /boot/kernel8.img
                for file in `ls /boot/dtb-$version_old/*.dtb 2>/dev/null`
                do
                    if [ -f $file ]; then
                        install -m 644 $file /boot/`basename $file`
                    fi
                done
                install -m 644 $(find /boot/dtb-$version_old/overlays/ -name "*.dtbo") /boot/overlays/
                if ls /boot/dtb-$version_old/overlays/*.dtb > /dev/null 2>&1; then
                    install -m 644 $(find /boot/dtb-$version_old/overlays/ -name "*.dtb") /boot/overlays/
                fi
                install -m 644 /boot/dtb-$version_old/overlays/README /boot/overlays/
            else
                echo "warning: files in /boot/dtb-$version_old/*.dtb missing when resetting kernel as $version_old, something may go wrong when starting this device next time."
            fi
        else
            echo "warning: files in /boot/dtb-$version_old/overlays missing when resetting kernel as $version_old, something may go wrong when starting this device next time."
        fi
    else
        echo "warning: files missing when resetting kernel as $version_old, something may go wrong when starting this device next time."
    fi
fi

%posttrans
if [ "$1" == "1" ]; then
    if [ ! -f /boot/vmlinuz-old ] && [ -f /boot/kernel8.img ]; then
        mkdir /boot/dtb-old
        mv /boot/*.dtb /boot/dtb-old
        mv /boot/overlays /boot/dtb-old/
        mv /boot/kernel8.img /boot/vmlinuz-old
    fi
fi
rm -rf /boot/*.dtb /boot/overlays /boot/kernel8.img
mkdir -p /boot/overlays
install -m 755 /boot/vmlinuz-%{KernelVer} /boot/kernel8.img
for file in `ls /boot/dtb-%{KernelVer}/*.dtb 2>/dev/null`
do
    if [ -f $file ]; then
        install -m 644 $file /boot/`basename $file`
    fi
done
install -m 644 $(find /boot/dtb-%{KernelVer}/overlays/ -name "*.dtbo") /boot/overlays/
if ls /boot/dtb-%{KernelVer}/overlays/*.dtb > /dev/null 2>&1; then
    install -m 644 $(find /boot/dtb-%{KernelVer}/overlays/ -name "*.dtb") /boot/overlays/
fi
install -m 644 /boot/dtb-%{KernelVer}/overlays/README /boot/overlays/


%files
%defattr (-, root, root)
%doc
/boot/config-*
/boot/System.map-*
/boot/vmlinuz-*
/boot/dtb-*
/lib/modules/%{KernelVer}

%changelog
* Tue Sep 14 2021 Yafen Fang <yafen@iscas.ac.cn> - 4.19.90-2109.5.0.0030
- nvme-pci: Use u32 for nvme_dev.q_depth and nvme_queue.q_depth
- nvme-pci: use unsigned for io queue depth
- net: hns3: update hns3 version to 21.9.2
- net: hns3: the pointer is cast to another pointer in a different type, which is incompatible.
- net: hns3: cleanup for some print type miss match and blank lines
- net: hns3: remove tc enable checking
- net: hns3: Constify static structs
- net: hns3: fix kernel crash when unload VF while it is being reset
- net: hns3: fix memory override when bd_num is bigger than the ring size
- net: hns3: pad the short tunnel frame before sending to hardware
- net: hns3: check the return of skb_checksum_help()
- net: hns3: add 'QoS' support for port based VLAN configuration
- net: hns3: remove unused parameter from hclge_set_vf_vlan_common()
- net: hns3: disable port VLAN filter when support function level VLAN filter control
- net: hns3: remove redundant param mbx_event_pending
- net: hns3: remove the useless debugfs file node cmd
- net: hns3: fix get wrong pfc_en when query PFC configuration
- net: hns3: fix mixed flag HCLGE_FLAG_MQPRIO_ENABLE and HCLGE_FLAG_DCB_ENABLE
- net: hns3: add support for tc mqprio offload
- net: hns3: add debugfs support for vlan configuration
- net: hns3: add support for VF modify VLAN filter state
- net: hns3: add query basic info support for VF
- net: hns3: add support for modify VLAN filter state
- Revert: net: hns3: adds support for extended VLAN mode and 'QOS' in vlan 802.1Q protocol.
- net: hns3: change the method of getting cmd index in debugfs
- net: hns3: refactor dump mac tbl of debugfs
- net: hns3: add support for dumping MAC umv counter in debugfs
- net: hns3: refactor dump serv info of debugfs
- net: hns3: refactor dump mac tnl status of debugfs
- net: hns3: refactor dump qs shaper of debugfs
- net: hns3: refactor dump qos buf cfg of debugfs
- net: hns3: split out hclge_dbg_dump_qos_buf_cfg()
- net: hns3: refactor dump qos pri map of debugfs
- net: hns3: refactor dump qos pause cfg of debugfs
- net: hns3: refactor dump tc of debugfs
- net: hns3: refactor dump tm of debugfs
- net: hns3: refactor dump tm map of debugfs
- net: hns3: refactor dump fd tcam of debugfs
- net: hns3: refactor queue info of debugfs
- net: hns3: refactor queue map of debugfs
- net: hns3: refactor dump reg dcb info of debugfs
- net: hns3: refactor dump reg of debugfs
- net: hns3: Constify static structs
- net: hns3: refactor dump ncl config of debugfs
- net: hns3: refactor dump m7 info of debugfs
- net: hns3: refactor dump reset info of debugfs
- net: hns3: refactor dump intr of debugfs
- net: hns3: refactor dump loopback of debugfs
- net: hns3: refactor dump mng tbl of debugfs
- net: hns3: refactor dump mac list of debugfs
- net: hns3: refactor dump bd info of debugfs
- net: hns3: refactor the debugfs process
- net: hns3: add debugfs support for tm priority and qset info
- net: hns3: add interfaces to query information of tm priority/qset
- net: hns3: change the value of the SEPARATOR_VALUE macro in hclgevf_main.c
- net: hns3: fix for vxlan gpe tx checksum bug
- net: hns3: Fix for geneve tx checksum bug
- net: hns3: refine the struct hane3_tc_info
- net: hns3: VF not request link status when PF support push link status feature
- net: hns3: remove a duplicate pf reset counting
- net: hns3: remediate a potential overflow risk of bd_num_list
- net: hns3: fix query vlan mask value error for flow director
- net: hns3: fix error mask definition of flow director
- net: hns3: cleanup for endian issue for VF RSS
- net: hns3: fix incorrect handling of sctp6 rss tuple
- net: hns3: refine function hclge_set_vf_vlan_cfg()
- net: hns3: dump tqp enable status in debugfs
- hisilicon/hns3: convert comma to semicolon
- net: hns3: remove a misused pragma packed
- net: hns3: add debugfs of dumping pf interrupt resources
- net: hns3: Supply missing hclge_dcb.h include file
- net: hns3: print out speed info when parsing speed fails
- net: hns3: add a missing mutex destroy in hclge_init_ad_dev()
- net: hns3: add a print for initializing CMDQ when reset pending
- net: hns3: replace snprintf with scnprintf in hns3_update_strings
- net: hns3: change affinity_mask to numa node range
- net: hns3: change hclge/hclgevf workqueue to WQ_UNBOUND mode
- tcp_comp: Del compressed_data and remaining_data from tcp_comp_context_rx
- tcp_comp: Add dpkt to save decompressed skb
- tcp_comp: Fix ZSTD_decompressStream failed
- mm: downgrade the print level in do_shrink_slab
- uio: introduce UIO_MEM_IOVA
- mm/mempolicy.c: fix checking unmapped holes for mbind
- mm/mempolicy.c: check range first in queue_pages_test_walk
- net: qrtr: fix another OOB Read in qrtr_endpoint_post
- net: qrtr: fix OOB Read in qrtr_endpoint_post
- mm, slab, slub: stop taking cpu hotplug lock
- mm, slab, slub: stop taking memory hotplug lock
- mm, slub: stop freeing kmem_cache_node structures on node offline
- kernel/hung_task.c: introduce sysctl to print all traces when a hung task is detected
- vt_kdsetmode: extend console locking

* Mon Sep 13 2021 Yafen Fang<yafen@iscas.ac.cn> - 4.19.90-2109.2.0.0029
- cpuidle: menu: Avoid computations when result will be discarded
- virtio_blk: fix handling single range discard request
- virtio_blk: add discard and write zeroes support
- iommu/arm-smmu-v3: add bit field SFM into GERROR_ERR_MASK
- page_alloc: consider highatomic reserve in watermark fast
- mm/filemap.c: fix a data race in filemap_fault()
- scsi/hifc: Fix memory leakage bug
- RDMA/hns: Fix wrong timer context buffer page size
- RDMA/hns: Bugfix for posting multiple srq work request
- RDMA/hns: Fix 0-length sge calculation error
- RDMA/hns: Fix configuration of ack_req_freq in QPC
- RDMA/hns: Add check for the validity of sl configuration
- RDMA/hns: Fix bug during CMDQ initialization
- RDMA/hns: Fixed wrong judgments in the goto branch
- RDMA/hns: Bugfix for checking whether the srq is full when post wr
- RDMA/hns: Fix wrong parameters when initial mtt of srq->idx_que
- RDMA/hns: Force rewrite inline flag of WQE
- RDMA/hns: Fix missing assignment of max_inline_data
- RDMA/hns: Avoid enabling RQ inline on UD
- RDMA/hns: Support to query firmware version
- RDMA/hns: Force srq_limit to 0 when creating SRQ
- RDMA/hns: Add interception for resizing SRQs
- RDMA/hns: Fix an cmd queue issue when resetting

* Fri Sep 3  2021 Yafen Fang<yafen@iscas.ac.cn> - 4.19.90-2109.1.0.0028
- iommu: smmuv2: Using the SMMU_BYPASS_DEV to bypass SMMU for some SoCs
- iommu: dev_bypass: cleanup dev bypass code
- arm64: phytium: using MIDR_PHYTIUM_FT2000PLUS instead of ARM_CPU_IMP_PHYTIUM
- arm64: Add MIDR encoding for PHYTIUM CPUs
- arm64: Add MIDR encoding for HiSilicon Taishan CPUs
- sched: Fix sched_fork() access an invalid sched_task_group
- KVM: nSVM: avoid picking up unsupported bits from L2 in int_ctl (CVE-2021-3653)
- KVM: nSVM: always intercept VMLOAD/VMSAVE when nested (CVE-2021-3656)
- Bluetooth: switch to lock_sock in SCO
- Bluetooth: avoid circular locks in sco_sock_connect
- Bluetooth: schedule SCO timeouts with delayed_work
- Bluetooth: defer cleanup of resources in hci_unregister_dev()

* Tue Aug 31 2021 Yafen Fang<yafen@iscas.ac.cn> - 4.19.90-2108.9.0.0027
- tcp_comp: Fix comp_read_size return value
- virtio-blk: Add validation for block size in config space
- blk-mq: fix divide by zero crash in tg_may_dispatch()
- mm, vmscan: guarantee drop_slab_node() termination
- jump_label: skip resource release if jump label is not relocated
- ext4: prevent getting empty inode buffer
- ext4: move ext4_fill_raw_inode() related functions before __ext4_get_inode_loc()
- ext4: factor out ext4_fill_raw_inode()
- ext4: make the updating inode data procedure atomic
- KVM: X86: MMU: Use the correct inherited permissions to get shadow page
- x86/config: Enable CONFIG_USERSWAP for openeuler_defconfig
- ext4: fix panic when mount failed with parallel flush_stashed_error_work
- device core: Consolidate locking and unlocking of parent and device
- Revert "ext4: flush s_error_work before journal destroy in ext4_fill_super"
- ext2: Strengthen xattr block checks
- ext2: Merge loops in ext2_xattr_set()
- ext2: introduce helper for xattr entry validation
- mm: rmap: explicitly reset vma->anon_vma in unlink_anon_vmas()

* Mon Aug 16 2021 Yafen Fang<yafen@iscas.ac.cn> - 4.19.90-2108.5.0.0026
- update kernel version to openEuler 4.19.90-2108.5.0

* Sun Aug 8  2021 Yafen Fang<yafen@iscas.ac.cn> - 4.19.90-2108.2.0.0025
- update kernel version to openEuler 4.19.90-2108.2.0

* Mon Jul 12 2021 Yafen Fang<yafen@iscas.ac.cn> - 4.19.90-2107.1.1.0024
- update kernel version to openEuler 4.19.90-2107.1.0
- add default config of raspi into openeuler-raspi_defconfig

* Thu Jun 17 2021 Yafen Fang<yafen@iscas.ac.cn> - 4.19.90-2106.3.0.0023
- update kernel version to openEuler 4.19.90-2106.3.0

* Wed Jun 9  2021 Yafen Fang<yafen@iscas.ac.cn> - 4.19.90-2105.9.0.0022
- update kernel version to openEuler 4.19.90-2105.9.0

* Thu Jun 3  2021 Yafen Fang<yafen@iscas.ac.cn> - 4.19.90-2105.6.0.0021
- update kernel version to openEuler 4.19.90-2105.6.0

* Thu May 27 2021 Yafen Fang<yafen@iscas.ac.cn> - 4.19.90-2105.4.0.0020
- update kernel version to openEuler 4.19.90-2105.4.0

* Wed May 12 2021 Yafen Fang<yafen@iscas.ac.cn> - 4.19.90-2105.2.0.0019
- update kernel version to openEuler 4.19.90-2105.2.0

* Wed Apr 28 2021 Yafen Fang<yafen@iscas.ac.cn> - 4.19.90-2104.22.0.0018
- update kernel version to openEuler 4.19.90-2104.22.0

* Wed Apr 7  2021 Yafen Fang<yafen@iscas.ac.cn> - 4.19.90-2104.1.0.0017
- add licenses missing in spec file

* Fri Apr 2  2021 Yafen Fang<yafen@iscas.ac.cn> - 4.19.90-2104.1.0.0016
- update kernel version to openEuler 4.19.90-2104.1.0

* Fri Mar 5  2021 Yafen Fang<yafen@iscas.ac.cn> - 4.19.90-2102.3.0.0015
- update kernel version to openEuler 4.19.90-2102.3.0

* Mon Jan 18 2021 Yafen Fang<yafen@iscas.ac.cn> - 4.19.90-2101.1.0.0014
- update kernel version to openEuler 4.19.90-2101.1.0

* Wed Dec 23 2020 Yafen Fang<yafen@iscas.ac.cn> - 4.19.90-2012.5.0.0013
- update kernel version to openEuler 4.19.90-2012.5.0

* Tue Dec 22 2020 Yafen Fang<yafen@iscas.ac.cn> - 4.19.90-2012.4.0.0012
- update kernel version to openEuler 4.19.90-2012.4.0

* Fri Dec 18 2020 Yafen Fang<yafen@iscas.ac.cn> - 4.19.90-2012.3.0.0011
- update kernel version to openEuler 4.19.90-2012.3.0

* Thu Dec 17 2020 Yafen Fang<yafen@iscas.ac.cn> - 4.19.90-2012.2.0.0010
- update kernel version to openEuler 4.19.90-2012.2.0

* Fri Dec 11 2020 Yafen Fang<yafen@iscas.ac.cn> - 4.19.90-2012.1.0.0009
- update kernel version to openEuler 4.19.90-2012.1.0

* Thu Dec 3  2020 Yafen Fang<yafen@iscas.ac.cn> - 4.19.90-2011.6.0.0008
- update kernel version to openEuler 4.19.90-2011.6.0

* Tue Nov 24 2020 Yafen Fang<yafen@iscas.ac.cn> - 4.19.90-2011.4.0.0007
- update kernel version to openEuler 4.19.90-2011.4.0

* Mon Nov 23 2020 Yafen Fang<yafen@iscas.ac.cn> - 4.19.90-2011.3.0.0006
- update kernel version to openEuler 4.19.90-2011.3.0

* Thu Nov 19 2020 Yafen Fang<yafen@iscas.ac.cn> - 4.19.90-2010.2.1.0005
- update to the latest kernel version(4.19.127) of raspberrypi upstream kernel

* Fri Oct 30 2020 Yafen Fang<yafen@iscas.ac.cn> - 4.19.90-2010.2.0.0004
- Update kernel version to 4.19.90-2010.2.0.

* Fri Sep 25 2020 Yafen Fang<yafen@iscas.ac.cn> - 4.19.90-2009.3.0.0003
- Update kernel version to 4.19.90-2009.3.0.

* Tue Jul 21 2020 Yafen Fang<yafen@iscas.ac.cn> - 4.19.90-2005.2.0.0002
- Override old files in /boot.

* Tue Jul 7  2020 Yafen Fang<yafen@iscas.ac.cn> - 4.19.90-2005.2.0.0001
- Add spec file to generate RaspberryPi kernel image rpm.