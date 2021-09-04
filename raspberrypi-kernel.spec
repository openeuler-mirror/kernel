%global Arch $(echo %{_host_cpu} | sed -e s/i.86/x86/ -e s/x86_64/x86/ -e s/aarch64.*/arm64/)

%global KernelVer %{version}-%{release}.raspi.%{_target_cpu}

%global hulkrelease 5.9.0

%global debug_package %{nil}

Name:	 raspberrypi-kernel
Version: 5.10.0
Release: %{hulkrelease}.7
Summary: Linux Kernel
License: GPLv2
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
BuildRequires: elfutils-devel zlib-devel binutils-devel newt-devel perl(ExtUtils::Embed) bison
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

make ARCH=%{Arch} %{?_smp_mflags} bcm2711_defconfig

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
* Sat Sep 4 2021 Zheng Zengkai <zhengzengkai@huawei.com> - 5.10.0-5.9.0.7
- mm/page_alloc: further fix __alloc_pages_bulk() return value
- mm/page_alloc: correct return value when failing at preparing
- mm/page_alloc: avoid page allocator recursion with pagesets.lock held
- mm: vmscan: shrink deferred objects proportional to priority
- mm: memcontrol: reparent nr_deferred when memcg offline
- mm: vmscan: don't need allocate shrinker->nr_deferred for memcg aware shrinkers
- mm: vmscan: use per memcg nr_deferred of shrinker
- mm: vmscan: add per memcg shrinker nr_deferred
- mm: vmscan: use a new flag to indicate shrinker is registered
- mm: vmscan: add shrinker_info_protected() helper
- mm: memcontrol: rename shrinker_map to shrinker_info
- mm: vmscan: use kvfree_rcu instead of call_rcu
- mm: vmscan: remove memcg_shrinker_map_size
- mm: vmscan: use shrinker_rwsem to protect shrinker_maps allocation
- mm: vmscan: consolidate shrinker_maps handling code
- mm: vmscan: use nid from shrink_control for tracepoint
- scsi/hifc: Fix memory leakage bug
- crypto: hisilicon/qm - set a qp error flag for userspace
- vfio/hisilicon: add acc live migration driver
- vfio/hisilicon: modify QM for live migration driver
- vfio/pci: provide customized live migration VFIO driver framework
- PCI: Set dma-can-stall for HiSilicon chips
- PCI: Add a quirk to set pasid_no_tlp for HiSilicon chips
- PCI: PASID can be enabled without TLP prefix
- crypto: hisilicon/sec - fix the CTR mode BD configuration
- crypto: hisilicon/sec - fix the max length of AAD for the CCM mode
- crypto: hisilicon/sec - fixup icv checking enabled on Kunpeng 930
- crypto: hisilicon - check _PS0 and _PR0 method
- crypto: hisilicon - change parameter passing of debugfs function
- crypto: hisilicon - support runtime PM for accelerator device
- crypto: hisilicon - add runtime PM ops
- crypto: hisilicon - using 'debugfs_create_file' instead of 'debugfs_create_regset32'
- crypto: hisilicon/sec - modify the hardware endian configuration
- crypto: hisilicon/sec - fix the abnormal exiting process
- crypto: hisilicon - enable hpre device clock gating
- crypto: hisilicon - enable sec device clock gating
- crypto: hisilicon - enable zip device clock gating
- crypto: hisilicon/sec - fix the process of disabling sva prefetching

* Thu Aug 26 2021 Zheng Zengkai <zhengzengkai@huawei.com> - 5.10.0-5.8.0.6
- mm/page_alloc: correct return value of populated elements if bulk array is populated
- mm: fix oom killing for disabled pid

* Tue Aug 24 2021 Zheng Zengkai <zhengzengkai@huawei.com> - 5.10.0-5.7.0.5
- X86/config: Enable CONFIG_USERSWAP

* Mon Aug 23 2021 Zheng Zengkai <zhengzengkai@huawei.com> - 5.10.0-5.6.0.4
- eulerfs: change default config file
- eulerfs: add Kconfig and Makefile
- eulerfs: add super_operations and module_init/exit
- eulerfs: add inode_operations for symlink inode
- eulerfs: add file_operations for dir inode
- eulerfs: add inode_operations for dir inode and special inode
- eulerfs: add file operations and inode operations for regular file
- eulerfs: add dax operations
- eulerfs: add inode related interfaces
- eulerfs: add dependency operations
- eulerfs: add nv dict operations
- eulerfs: add filename interfaces
- eulerfs: add interfaces for page wear
- eulerfs: add interfaces for inode lock transfer
- eulerfs: add flush interfaces
- eulerfs: add memory allocation interfaces
- eulerfs: add kmeme_cache definitions and interfaces
- eulerfs: common definitions

* Sat Aug 21 2021 Zheng Zengkai <zhengzengkai@huawei.com> - 5.10.0-5.4.0.3
- vfio/pci: Fix wrong return value when get iommu attribute DOMAIN_ATTR_NESTING
- net: hns3: remove always exist devlink pointer check
- net: hns3: add support ethtool extended link state
- net: hns3: add header file hns3_ethtoo.h
- ethtool: add two link extended substates of bad signal integrity
- docs: ethtool: Add two link extended substates of bad signal integrity
- net: hns3: add support for triggering reset by ethtool

* Mon Aug 16 2021 Yafen Fang<yafen@iscas.ac.cn> - 5.10.0-5.3.0.2
- package init based on openEuler 5.10.0-5.3.0

* Mon Aug 9  2021 Yafen Fang<yafen@iscas.ac.cn> - 5.10.0-5.1.0.1
- package init based on openEuler 5.10.0-5.1.0