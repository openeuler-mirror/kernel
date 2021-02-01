%define with_signmodules  1
%define with_kabichk 0

%define modsign_cmd %{SOURCE10}

%global Arch $(echo %{_host_cpu} | sed -e s/i.86/x86/ -e s/x86_64/x86/ -e s/aarch64.*/arm64/)

%global KernelVer %{version}-%{release}.%{_target_cpu}
%global debuginfodir /usr/lib/debug

%global upstream_version    5.10
%global upstream_sublevel   0
%global devel_release       2
%global maintenance_release .0.0
%global pkg_release         .11

%define with_debuginfo 1
# Do not recompute the build-id of vmlinux in find-debuginfo.sh
%global _missing_build_ids_terminate_build 1
%global _no_recompute_build_ids 1
%undefine _include_minidebuginfo
%undefine _include_gdb_index
%undefine _unique_build_ids

%define with_source 1

%define with_python2 0

# failed if there is new config options
%define listnewconfig_fail 0

#defualt is enabled. You can disable it with --without option
%define with_perf    %{?_without_perf: 0} %{?!_without_perf: 1}

Name:	 kernel
Version: %{upstream_version}.%{upstream_sublevel}
Release: %{devel_release}%{?maintenance_release}%{?pkg_release}%{?extra_release}
Summary: Linux Kernel
License: GPLv2
URL:	 http://www.kernel.org/
Source0: kernel.tar.gz
Source10: sign-modules
Source11: x509.genkey
Source12: extra_certificates

%if 0%{?with_kabichk}
Source18: check-kabi
Source20: Module.kabi_aarch64
%endif

Source200: mkgrub-menu-aarch64.sh

Source2000: cpupower.service
Source2001: cpupower.config

Source3000: kernel-5.10.0-aarch64.config
Source3001: kernel-5.10.0-x86_64.config

%if 0%{?with_patch}
Source9000: apply-patches
Source9001: guards
Source9002: series.conf
Source9998: patches.tar.bz2
%endif

#BuildRequires:
BuildRequires: module-init-tools, patch >= 2.5.4, bash >= 2.03, tar
BuildRequires: bzip2, xz, findutils, gzip, m4, perl, make >= 3.78, diffutils, gawk
BuildRequires: libcap-devel, libcap-ng-devel, rsync
BuildRequires: gcc >= 3.4.2, binutils >= 2.12
BuildRequires: hostname, net-tools, bc
BuildRequires: xmlto, asciidoc
BuildRequires: openssl-devel
BuildRequires: hmaccalc
BuildRequires: ncurses-devel
#BuildRequires: pesign >= 0.109-4
BuildRequires: elfutils-libelf-devel
BuildRequires: rpm >= 4.14.2
#BuildRequires: sparse >= 0.4.1
%if 0%{?with_python2}
BuildRequires: python-devel
%endif

BuildRequires: elfutils-devel zlib-devel binutils-devel newt-devel perl(ExtUtils::Embed) bison
BuildRequires: audit-libs-devel
BuildRequires: pciutils-devel gettext
BuildRequires: rpm-build, elfutils
BuildRequires: numactl-devel python3-devel glibc-static python3-docutils
BuildRequires: perl-generators perl(Carp) libunwind-devel gtk2-devel libbabeltrace-devel java-1.8.0-openjdk
AutoReq: no
AutoProv: yes

Conflicts: device-mapper-libs < 1.02.63-2 e2fsprogs < 1.37-4 initscripts < 7.23 iptables < 1.3.2-1
Conflicts: ipw2200-firmware < 2.4 isdn4k-utils < 3.2-32 iwl4965-firmware < 228.57.2 jfsutils < 1.1.7-2
Conflicts: mdadm < 3.2.1-5 nfs-utils < 1.0.7-12 oprofile < 0.9.1-2 ppp < 2.4.3-3 procps < 3.2.5-6.3
Conflicts: reiserfs-utils < 3.6.19-2 selinux-policy-targeted < 1.25.3-14 squashfs-tools < 4.0
Conflicts: udev < 063-6 util-linux < 2.12 wireless-tools < 29-3 xfsprogs < 2.6.13-4

Provides: kernel-aarch64 = %{version}-%{release} kernel-drm = 4.3.0 kernel-drm-nouveau = 16 kernel-modeset = 1
Provides: kernel-uname-r = %{KernelVer} kernel=%{KernelVer}

Requires: dracut >= 001-7 grubby >= 8.28-2 initscripts >= 8.11.1-1 linux-firmware >= 20100806-2 module-init-tools >= 3.16-2

ExclusiveArch: noarch aarch64 i686 x86_64
ExclusiveOS: Linux

%if %{with_perf}
BuildRequires: flex xz-devel libzstd-devel 
BuildRequires: java-devel
%endif


%description
The Linux Kernel, the operating system core itself.

%package headers
Summary: Header files for the Linux kernel for use by glibc
Obsoletes: glibc-kernheaders < 3.0-46
Provides: glibc-kernheaders = 3.0-46
%description headers
Kernel-headers includes the C header files that specify the interface
between the Linux kernel and userspace libraries and programs.  The
header files define structures and constants that are needed for
building most standard programs and are also needed for rebuilding the
glibc package.


%package devel
Summary: Development package for building kernel modules to match the %{KernelVer} kernel
AutoReqProv: no
Provides: kernel-devel-uname-r = %{KernelVer}
Provides: kernel-devel-%{_target_cpu} = %{version}-%{release}
Requires: perl findutils

%description devel
This package provides kernel headers and makefiles sufficient to build modules
against the %{KernelVer} kernel package.

%package tools
Summary: Assortment of tools for the Linux kernel
Provides: %{name}-tools-libs
Obsoletes: %{name}-tools-libs
Provides:  cpufreq-utils = 1:009-0.6.p1
Provides:  cpufrequtils = 1:009-0.6.p1
Obsoletes: cpufreq-utils < 1:009-0.6.p1
Obsoletes: cpufrequtils < 1:009-0.6.p1
Obsoletes: cpuspeed < 1:1.5-16
%description tools
This package contains the tools/ directory from the kernel source
and the supporting documentation.

%package tools-devel
Summary: Assortment of tools for the Linux kernel
Requires: kernel-tools = %{version}-%{release}
Requires: kernel-tools-libs = %{version}-%{release}
Provides: kernel-tools-libs-devel = %{version}-%{release}
Obsoletes: kernel-tools-libs-devel
%description tools-devel
This package contains the development files for the tools/ directory from
the kernel source.

%if %{with_perf}
%package -n perf
Summary: Performance monitoring for the Linux kernel
%description -n perf
This package contains the perf tool, which enables performance monitoring
of the Linux kernel.

%if 0%{?with_python2}
%package -n python2-perf
Provides: python-perf = %{version}-%{release}
Obsoletes: python-perf
Summary: Python bindings for apps which will manipulate perf events

%description -n python2-perf
A Python module that permits applications written in the Python programming
language to use the interface to manipulate perf events.
%endif

%package -n python3-perf
Summary: Python bindings for apps which will manipulate perf events
%description -n python3-perf
A Python module that permits applications written in the Python programming
language to use the interface to manipulate perf events.
# with_perf
%endif

%package -n bpftool
Summary: Inspection and simple manipulation of eBPF programs and maps
%description -n bpftool
This package contains the bpftool, which allows inspection and simple
manipulation of eBPF programs and maps.

%package source
Summary: the kernel source
%description source
This package contains vaious source files from the kernel.

%if 0%{?with_debuginfo}
%define _debuginfo_template %{nil}
%define _debuginfo_subpackages 0

%define debuginfo_template(n:) \
%package -n %{-n*}-debuginfo\
Summary: Debug information for package %{-n*}\
Group: Development/Debug\
AutoReq: 0\
AutoProv: 1\
%description -n %{-n*}-debuginfo\
This package provides debug information for package %{-n*}.\
Debug information is useful when developing applications that use this\
package or when debugging this package.\
%{nil}

%debuginfo_template -n kernel
%files -n kernel-debuginfo -f debugfiles.list

%debuginfo_template -n bpftool
%files -n bpftool-debuginfo -f bpftool-debugfiles.list
%{expand:%%global _find_debuginfo_opts %{?_find_debuginfo_opts} -p '.*%{_sbindir}/bpftool.*(\.debug)?|XXX' -o bpftool-debugfiles.list}

%debuginfo_template -n kernel-tools
%files -n kernel-tools-debuginfo -f kernel-tools-debugfiles.list
%{expand:%%global _find_debuginfo_opts %{?_find_debuginfo_opts} -p '.*%{_bindir}/centrino-decode.*(\.debug)?|.*%{_bindir}/powernow-k8-decode.*(\.debug)?|.*%{_bindir}/cpupower.*(\.debug)?|.*%{_libdir}/libcpupower.*|.*%{_libdir}/libcpupower.*|.*%{_bindir}/turbostat.(\.debug)?|.*%{_bindir}/.*gpio.*(\.debug)?|.*%{_bindir}/.*iio.*(\.debug)?|.*%{_bindir}/tmon.*(.debug)?|XXX' -o kernel-tools-debugfiles.list}

%if %{with_perf}
%debuginfo_template -n perf
%files -n perf-debuginfo -f perf-debugfiles.list
%{expand:%%global _find_debuginfo_opts %{?_find_debuginfo_opts} -p '.*%{_bindir}/perf.*(\.debug)?|.*%{_libexecdir}/perf-core/.*|.*%{_libdir}/traceevent/.*|XXX' -o perf-debugfiles.list}

%if 0%{?with_python2}
%debuginfo_template -n python2-perf
%files -n python2-perf-debuginfo -f python2-perf-debugfiles.list
%{expand:%%global _find_debuginfo_opts %{?_find_debuginfo_opts} -p '.*%{python2_sitearch}/perf.*(.debug)?|XXX' -o python2-perf-debugfiles.list}
%endif

%debuginfo_template -n python3-perf
%files -n python3-perf-debuginfo -f python3-perf-debugfiles.list
%{expand:%%global _find_debuginfo_opts %{?_find_debuginfo_opts} -p '.*%{python3_sitearch}/perf.*(.debug)?|XXX' -o python3-perf-debugfiles.list}
#with_perf
%endif

%endif

%prep

%if 0%{?with_patch}
if [ ! -d kernel-%{version}/vanilla-%{TarballVer} ];then
%setup -q -n kernel-%{version} -a 9998 -c
    mv linux-%{TarballVer} vanilla-%{TarballVer}
else
    cd kernel-%{version}
fi
cp -rl vanilla-%{TarballVer} linux-%{KernelVer}
%else
%setup -q -n kernel-%{version} -c
if [ -d "kernel" ]; then
    mv kernel linux-%{version}
    cp -rl linux-%{version} linux-%{KernelVer}
else
    echo "**** ERROR: no kernel source directory ****"
fi
%endif

cd linux-%{KernelVer}

%if 0%{?with_patch}
cp %{SOURCE9000} .
cp %{SOURCE9001} .
cp %{SOURCE9002} .

if [ ! -d patches ];then
    mv ../patches .
fi

Applypatches()
{
    set -e
    set -o pipefail
    local SERIESCONF=$1
    local PATCH_DIR=$2
    sed -i '/^#/d'  $SERIESCONF
    sed -i '/^[\s]*$/d' $SERIESCONF
    (
        echo "trap 'echo \"*** patch \$_ failed ***\"' ERR"
        echo "set -ex"
        cat $SERIESCONF | \
        sed "s!^!patch -s -F0 -E -p1 --no-backup-if-mismatch -i $PATCH_DIR/!" \
    ) | sh
}

Applypatches series.conf %{_builddir}/kernel-%{version}/linux-%{KernelVer}
%endif

touch .scmversion

find . \( -name "*.orig" -o -name "*~" \) -exec rm -f {} \; >/dev/null
find . -name .gitignore -exec rm -f {} \; >/dev/null

%if 0%{?with_signmodules}
    cp %{SOURCE11} certs/.
%endif

pathfix.py -pni "/usr/bin/python" tools/power/pm-graph/sleepgraph.py tools/power/pm-graph/bootgraph.py tools/perf/scripts/python/exported-sql-viewer.py

%if 0%{?with_source}
# Copy directory backup for kernel-source
cp -a ../linux-%{KernelVer} ../linux-%{KernelVer}-source
find ../linux-%{KernelVer}-source -type f -name "\.*" -exec rm -rf {} \; >/dev/null
%endif

cp -a tools/perf tools/python3-perf

%build
cd linux-%{KernelVer}

perl -p -i -e "s/^EXTRAVERSION.*/EXTRAVERSION = -%{release}.%{_target_cpu}/" Makefile

## make linux
make mrproper %{_smp_mflags}

make ARCH=%{Arch} openeuler_defconfig

TargetImage=$(basename $(make -s image_name))

make ARCH=%{Arch} $TargetImage %{?_smp_mflags}
make ARCH=%{Arch} modules %{?_smp_mflags}

%if 0%{?with_kabichk}
    chmod 0755 %{SOURCE18}
    if [ -e $RPM_SOURCE_DIR/Module.kabi_%{_target_cpu} ]; then
        ##%{SOURCE18} -k $RPM_SOURCE_DIR/Module.kabi_%{_target_cpu} -s Module.symvers || exit 1
	echo "**** NOTE: now don't check Kabi. ****"
    else
        echo "**** NOTE: Cannot find reference Module.kabi file. ****"
    fi
%endif

# aarch64 make dtbs
%ifarch aarch64
    make ARCH=%{Arch} dtbs
%endif

## make tools
%if %{with_perf}
# perf
%global perf_make \
    make EXTRA_CFLAGS="-Wl,-z,now -g -Wall -fstack-protector-strong -fPIC" EXTRA_PERFLIBS="-fpie -pie" %{?_smp_mflags} -s V=1 WERROR=0 NO_LIBUNWIND=1 HAVE_CPLUS_DEMANGLE=1 NO_GTK2=1 NO_LIBNUMA=1 NO_STRLCPY=1 prefix=%{_prefix}
%if 0%{?with_python2}
%global perf_python2 -C tools/perf PYTHON=%{__python2}
%global perf_python3 -C tools/python3-perf PYTHON=%{__python3}
%else
%global perf_python3 -C tools/perf PYTHON=%{__python3}
%endif

chmod +x tools/perf/check-headers.sh
# perf
%if 0%{?with_python2}
%{perf_make} %{perf_python2} all
%endif

# make sure check-headers.sh is executable
chmod +x tools/python3-perf/check-headers.sh
%{perf_make} %{perf_python3} all

pushd tools/perf/Documentation/
make %{?_smp_mflags} man
popd
%endif

# bpftool
pushd tools/bpf/bpftool
make
popd

# cpupower
chmod +x tools/power/cpupower/utils/version-gen.sh
make %{?_smp_mflags} -C tools/power/cpupower CPUFREQ_BENCH=false
%ifarch %{ix86}
    pushd tools/power/cpupower/debug/i386
    make %{?_smp_mflags} centrino-decode powernow-k8-decode
    popd
%endif
%ifarch x86_64
    pushd tools/power/cpupower/debug/x86_64
    make %{?_smp_mflags} centrino-decode powernow-k8-decode
    popd
%endif
%ifarch %{ix86} x86_64
    pushd tools/power/x86/x86_energy_perf_policy/
    make
    popd
    pushd tools/power/x86/turbostat
    make
    popd
%endif
# thermal
pushd tools/thermal/tmon/
make
popd
# iio
pushd tools/iio/
make
popd
# gpio
pushd tools/gpio/
make
popd
# kvm
pushd tools/kvm/kvm_stat/
make %{?_smp_mflags} man
popd

%install
%if 0%{?with_source}
    %define _python_bytecompile_errors_terminate_build 0
    mkdir -p $RPM_BUILD_ROOT/usr/src/
    mv linux-%{KernelVer}-source $RPM_BUILD_ROOT/usr/src/linux-%{KernelVer}
    cp linux-%{KernelVer}/.config $RPM_BUILD_ROOT/usr/src/linux-%{KernelVer}/
    cp linux-%{KernelVer}/.scmversion $RPM_BUILD_ROOT/usr/src/linux-%{KernelVer}/
%endif

cd linux-%{KernelVer}

## install linux

# deal with kernel-source, now we don't need kernel-source
#mkdir $RPM_BUILD_ROOT/usr/src/linux-%{KernelVer}
#tar cf - --exclude SCCS --exclude BitKeeper --exclude .svn --exclude CVS --exclude .pc --exclude .hg --exclude .git --exclude=.tmp_versions --exclude=*vmlinux* --exclude=*.o --exclude=*.ko --exclude=*.cmd --exclude=Documentation --exclude=.config.old --exclude=.missing-syscalls.d --exclude=patches . | tar xf - -C %{buildroot}/usr/src/linux-%{KernelVer}

mkdir -p $RPM_BUILD_ROOT/boot
dd if=/dev/zero of=$RPM_BUILD_ROOT/boot/initramfs-%{KernelVer}.img bs=1M count=20

install -m 755 $(make -s image_name) $RPM_BUILD_ROOT/boot/vmlinuz-%{KernelVer}
pushd $RPM_BUILD_ROOT/boot
sha512hmac ./vmlinuz-%{KernelVer} >./.vmlinuz-%{KernelVer}.hmac
popd

install -m 644 .config $RPM_BUILD_ROOT/boot/config-%{KernelVer}
install -m 644 System.map $RPM_BUILD_ROOT/boot/System.map-%{KernelVer}

gzip -c9 < Module.symvers > $RPM_BUILD_ROOT/boot/symvers-%{KernelVer}.gz

mkdir -p $RPM_BUILD_ROOT%{_sbindir}
install -m 755 %{SOURCE200} $RPM_BUILD_ROOT%{_sbindir}/mkgrub-menu-%{devel_release}.sh


%if 0%{?with_debuginfo}
    mkdir -p $RPM_BUILD_ROOT%{debuginfodir}/lib/modules/%{KernelVer}
    cp vmlinux $RPM_BUILD_ROOT%{debuginfodir}/lib/modules/%{KernelVer}
%endif

# deal with module, if not kdump
make ARCH=%{Arch} INSTALL_MOD_PATH=$RPM_BUILD_ROOT modules_install KERNELRELEASE=%{KernelVer} mod-fw=
######## to collect ko to module.filelist about netwoking. block. drm. modesetting ###############
pushd $RPM_BUILD_ROOT/lib/modules/%{KernelVer}
find -type f -name "*.ko" >modnames

# mark modules executable so that strip-to-file can strip them
xargs --no-run-if-empty chmod u+x < modnames

# Generate a list of modules for block and networking.

grep -F /drivers/ modnames | xargs --no-run-if-empty nm -upA |
sed -n 's,^.*/\([^/]*\.ko\):  *U \(.*\)$,\1 \2,p' > drivers.undef

collect_modules_list()
{
    sed -r -n -e "s/^([^ ]+) \\.?($2)\$/\\1/p" drivers.undef |
    LC_ALL=C sort -u > modules.$1
    if [ ! -z "$3" ]; then
        sed -r -e "/^($3)\$/d" -i modules.$1
    fi
}

collect_modules_list networking \
			 'register_netdev|ieee80211_register_hw|usbnet_probe|phy_driver_register|rt2x00(pci|usb)_probe|register_netdevice'
collect_modules_list block \
		 'ata_scsi_ioctl|scsi_add_host|scsi_add_host_with_dma|blk_alloc_queue|blk_init_queue|register_mtd_blktrans|scsi_esp_register|scsi_register_device_handler|blk_queue_physical_block_size|ahci_platform_get_resources' 'pktcdvd.ko|dm-mod.ko'
collect_modules_list drm \
			 'drm_open|drm_init'
collect_modules_list modesetting \
			 'drm_crtc_init'

# detect missing or incorrect license tags
rm -f modinfo
while read i
do
    echo -n "$i " >> modinfo
    /sbin/modinfo -l $i >> modinfo
done < modnames

grep -E -v \
	  'GPL( v2)?$|Dual BSD/GPL$|Dual MPL/GPL$|GPL and additional rights$' \
  modinfo && exit 1

rm -f modinfo modnames drivers.undef

for i in alias alias.bin builtin.bin ccwmap dep dep.bin ieee1394map inputmap isapnpmap ofmap pcimap seriomap symbols symbols.bin usbmap
do
    rm -f $RPM_BUILD_ROOT/lib/modules/$KernelVer/modules.$i
done
popd
# modsign module ko;need after find-debuginfo,strip
%define __modsign_install_post \
    if [ "%{with_signmodules}" -eq "1" ];then \
        cp certs/signing_key.pem . \
        cp certs/signing_key.x509 . \
        chmod 0755 %{modsign_cmd} \
        %{modsign_cmd} $RPM_BUILD_ROOT/lib/modules/%{KernelVer} || exit 1 \
    fi \
%{nil}

# deal with header
make ARCH=%{Arch} INSTALL_HDR_PATH=$RPM_BUILD_ROOT/usr KBUILD_SRC= headers_install
make ARCH=%{Arch} INSTALL_HDR_PATH=$RPM_BUILD_ROOT/usr headers_check
find $RPM_BUILD_ROOT/usr/include -name "\.*"  -exec rm -rf {} \;

# aarch64 dtbs install
%ifarch aarch64
    mkdir -p $RPM_BUILD_ROOT/boot/dtb-%{KernelVer}
    install -m 644 $(find arch/%{Arch}/boot -name "*.dtb") $RPM_BUILD_ROOT/boot/dtb-%{KernelVer}/
    rm -f $(find arch/$Arch/boot -name "*.dtb")
%endif

# deal with vdso
make -s ARCH=%{Arch} INSTALL_MOD_PATH=$RPM_BUILD_ROOT vdso_install KERNELRELEASE=%{KernelVer}
if [ ! -s ldconfig-kernel.conf ]; then
    echo "# Placeholder file, no vDSO hwcap entries used in this kernel." >ldconfig-kernel.conf
fi
install -D -m 444 ldconfig-kernel.conf $RPM_BUILD_ROOT/etc/ld.so.conf.d/kernel-%{KernelVer}.conf

# deal with /lib/module/ path- sub path: build source kernel
rm -f $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/build
rm -f $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/source
mkdir -p $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/build
mkdir -p $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/extra
mkdir -p $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/updates
mkdir -p $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/weak-updates
############ to do collect devel file  #########
# 1. Makefile And Kconfig, .config sysmbol
# 2. scrpits dir
# 3. .h file
find -type f \( -name "Makefile*" -o -name "Kconfig*" \) -exec cp --parents {} $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/build \;
for f in Module.symvers System.map Module.markers .config;do
    test -f $f || continue
    cp $f $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/build
done

cp -a scripts $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/build
if [ -d arch/%{Arch}/scripts ]; then
    cp -a arch/%{Arch}/scripts $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/build/arch/%{_arch} || :
fi
if [ -f arch/%{Arch}/*lds ]; then
    cp -a arch/%{Arch}/*lds $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/build/arch/%{_arch}/ || :
fi
find $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/build/scripts/ -name "*.o" -exec rm -rf {} \;

if [ -d arch/%{Arch}/include ]; then
    cp -a --parents arch/%{Arch}/include $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/build/
fi
cp -a include $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/build/include

if [ -f arch/%{Arch}/kernel/module.lds ]; then
    cp -a --parents arch/%{Arch}/kernel/module.lds $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/build/
fi

# module.lds is moved to scripts by commit 596b0474d3d9 in linux 5.10.
if [ -f scripts/module.lds ]; then
    cp -a --parents scripts/module.lds $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/build/
fi

%ifarch aarch64
    cp -a --parents arch/arm/include/asm $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/build/
%endif

# copy objtool for kernel-devel (needed for building external modules)
if grep -q CONFIG_STACK_VALIDATION=y .config; then
    mkdir -p $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/build/tools/objtool
    cp -a tools/objtool/objtool $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/build/tools/objtool
fi

# Make sure the Makefile and version.h have a matching timestamp so that
# external modules can be built
touch -r $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/build/Makefile $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/build/include/generated/uapi/linux/version.h
touch -r $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/build/.config $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/build/include/generated/autoconf.h
# for make prepare
if [ ! -f $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/build/include/config/auto.conf ];then
    cp .config $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/build/include/config/auto.conf
fi

mkdir -p %{buildroot}/usr/src/kernels
mv $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/build $RPM_BUILD_ROOT/usr/src/kernels/%{KernelVer}

find $RPM_BUILD_ROOT/usr/src/kernels/%{KernelVer} -name ".*.cmd" -exec rm -f {} \;

pushd $RPM_BUILD_ROOT/lib/modules/%{KernelVer}
ln -sf /usr/src/kernels/%{KernelVer} build
ln -sf build source
popd


# deal with doc , now we don't need


# deal with kernel abi whitelists. now we don't need


## install tools
%if %{with_perf}
# perf
# perf tool binary and supporting scripts/binaries
%if 0%{?with_python2}
%{perf_make} %{perf_python2} DESTDIR=%{buildroot} lib=%{_lib} install-bin install-traceevent-plugins
%else
%{perf_make} %{perf_python3} DESTDIR=%{buildroot} lib=%{_lib} install-bin install-traceevent-plugins
%endif
# remove the 'trace' symlink.
rm -f %{buildroot}%{_bindir}/trace

# remove examples
rm -rf %{buildroot}/usr/lib/perf/examples
# remove the stray header file that somehow got packaged in examples
rm -rf %{buildroot}/usr/lib/perf/include/bpf/

# python-perf extension
%{perf_make} %{perf_python3} DESTDIR=%{buildroot} install-python_ext
%if 0%{?with_python2}
%{perf_make} %{perf_python2} DESTDIR=%{buildroot} install-python_ext
%endif

# perf man pages (note: implicit rpm magic compresses them later)
install -d %{buildroot}/%{_mandir}/man1
install -pm0644 tools/kvm/kvm_stat/kvm_stat.1 %{buildroot}/%{_mandir}/man1/
install -pm0644 tools/perf/Documentation/*.1 %{buildroot}/%{_mandir}/man1/
%endif

# bpftool
pushd tools/bpf/bpftool
make DESTDIR=%{buildroot} prefix=%{_prefix} bash_compdir=%{_sysconfdir}/bash_completion.d/ mandir=%{_mandir} install doc-install
popd
# cpupower
make -C tools/power/cpupower DESTDIR=%{buildroot} libdir=%{_libdir} mandir=%{_mandir} CPUFREQ_BENCH=false install
rm -f %{buildroot}%{_libdir}/*.{a,la}
%find_lang cpupower
mv cpupower.lang ../
%ifarch %{ix86}
    pushd tools/power/cpupower/debug/i386
    install -m755 centrino-decode %{buildroot}%{_bindir}/centrino-decode
    install -m755 powernow-k8-decode %{buildroot}%{_bindir}/powernow-k8-decode
    popd
%endif
%ifarch x86_64
    pushd tools/power/cpupower/debug/x86_64
    install -m755 centrino-decode %{buildroot}%{_bindir}/centrino-decode
    install -m755 powernow-k8-decode %{buildroot}%{_bindir}/powernow-k8-decode
    popd
%endif
chmod 0755 %{buildroot}%{_libdir}/libcpupower.so*
mkdir -p %{buildroot}%{_unitdir} %{buildroot}%{_sysconfdir}/sysconfig
install -m644 %{SOURCE2000} %{buildroot}%{_unitdir}/cpupower.service
install -m644 %{SOURCE2001} %{buildroot}%{_sysconfdir}/sysconfig/cpupower
%ifarch %{ix86} x86_64
    mkdir -p %{buildroot}%{_mandir}/man8
    pushd tools/power/x86/x86_energy_perf_policy
    make DESTDIR=%{buildroot} install
    popd
    pushd tools/power/x86/turbostat
    make DESTDIR=%{buildroot} install
    popd
%endif
# thermal
pushd tools/thermal/tmon
make INSTALL_ROOT=%{buildroot} install
popd
# iio
pushd tools/iio
make DESTDIR=%{buildroot} install
popd
# gpio
pushd tools/gpio
make DESTDIR=%{buildroot} install
popd
# kvm
pushd tools/kvm/kvm_stat
make INSTALL_ROOT=%{buildroot} install-tools
popd

%define __spec_install_post\
%{?__debug_package:%{__debug_install_post}}\
%{__arch_install_post}\
%{__os_install_post}\
%{__modsign_install_post}\
%{nil}

%post
%{_sbindir}/new-kernel-pkg --package kernel --install %{KernelVer} || exit $?

%preun
if [ `uname -i` == "aarch64" ] &&
        [ -f /boot/EFI/grub2/grub.cfg ]; then
    /usr/bin/sh  %{_sbindir}/mkgrub-menu-%{devel_release}.sh %{version}-%{devel_release}.aarch64  /boot/EFI/grub2/grub.cfg  remove
fi

%postun
%{_sbindir}/new-kernel-pkg --rminitrd --rmmoddep --remove %{KernelVer} || exit $?
if [ -x %{_sbindir}/weak-modules ]
then
    %{_sbindir}/weak-modules --remove-kernel %{KernelVer} || exit $?
fi

# remove empty directory
if [ -d /lib/modules/%{KernelVer} ] && [ "`ls -A  /lib/modules/%{KernelVer}`" = "" ]; then
    rm -rf /lib/modules/%{KernelVer}
fi

%posttrans
%{_sbindir}/new-kernel-pkg --package kernel --mkinitrd --dracut --depmod --update %{KernelVer} || exit $?
%{_sbindir}/new-kernel-pkg --package kernel --rpmposttrans %{KernelVer} || exit $?
if [ `uname -i` == "aarch64" ] &&
        [ -f /boot/EFI/grub2/grub.cfg ]; then
	/usr/bin/sh %{_sbindir}/mkgrub-menu-%{devel_release}.sh %{version}-%{devel_release}.aarch64  /boot/EFI/grub2/grub.cfg  update  
fi
if [ -x %{_sbindir}/weak-modules ]
then
    %{_sbindir}/weak-modules --add-kernel %{KernelVer} || exit $?
fi
%{_sbindir}/new-kernel-pkg --package kernel --mkinitrd --dracut --depmod --update %{KernelVer} || exit $?
%{_sbindir}/new-kernel-pkg --package kernel --rpmposttrans %{KernelVer} || exit $?

%post devel
if [ -f /etc/sysconfig/kernel ]
then
    . /etc/sysconfig/kernel || exit $?
fi
if [ "$HARDLINK" != "no" -a -x /usr/sbin/hardlink ]
then
    (cd /usr/src/kernels/%{KernelVer} &&
     /usr/bin/find . -type f | while read f; do
       hardlink -c /usr/src/kernels/*.oe*.*/$f $f
     done)
fi

%post -n kernel-tools
/sbin/ldconfig
%systemd_post cpupower.service

%preun -n kernel-tools
%systemd_preun cpupower.service

%postun -n kernel-tools
/sbin/ldconfig
%systemd_postun cpupower.service

%files
%defattr (-, root, root)
%doc
/boot/config-*
%ifarch aarch64
/boot/dtb-*
%endif
/boot/symvers-*
/boot/System.map-*
/boot/vmlinuz-*
%ghost /boot/initramfs-%{KernelVer}.img
/boot/.vmlinuz-*.hmac
/etc/ld.so.conf.d/*
/lib/modules/%{KernelVer}/
%exclude /lib/modules/%{KernelVer}/source
%exclude /lib/modules/%{KernelVer}/build
%{_sbindir}/mkgrub-menu*.sh

%files devel
%defattr (-, root, root)
%doc
/lib/modules/%{KernelVer}/source
/lib/modules/%{KernelVer}/build
/usr/src/kernels/%{KernelVer}

%files headers
%defattr (-, root, root)
/usr/include/*

%if %{with_perf}
%files -n perf
%{_bindir}/perf
%{_libdir}/libperf-jvmti.so
%dir %{_libdir}/traceevent
%{_libdir}/traceevent/plugins/
%{_libexecdir}/perf-core
%{_datadir}/perf-core/
%{_mandir}/man[1-8]/perf*
%{_sysconfdir}/bash_completion.d/perf
%doc linux-%{KernelVer}/tools/perf/Documentation/examples.txt
%dir %{_datadir}/doc/perf-tip
%{_datadir}/doc/perf-tip/*
%license linux-%{KernelVer}/COPYING

%if 0%{?with_python2}
%files -n python2-perf
%license linux-%{KernelVer}/COPYING
%{python2_sitearch}/*
%endif

%files -n python3-perf
%license linux-%{KernelVer}/COPYING
%{python3_sitearch}/*
%endif

%files -n kernel-tools -f cpupower.lang
%{_bindir}/cpupower
%ifarch %{ix86} x86_64
%{_bindir}/centrino-decode
%{_bindir}/powernow-k8-decode
%endif
%{_unitdir}/cpupower.service
%{_datadir}/bash-completion/completions/cpupower
%{_mandir}/man[1-8]/cpupower*
%config(noreplace) %{_sysconfdir}/sysconfig/cpupower
%ifarch %{ix86} x86_64
%{_bindir}/x86_energy_perf_policy
%{_mandir}/man8/x86_energy_perf_policy*
%{_bindir}/turbostat
%{_mandir}/man8/turbostat*
%endif
%{_bindir}/tmon
%{_bindir}/iio_event_monitor
%{_bindir}/iio_generic_buffer
%{_bindir}/lsiio
%{_bindir}/lsgpio
%{_bindir}/gpio-hammer
%{_bindir}/gpio-event-mon
%{_bindir}/gpio-watch
%{_mandir}/man1/kvm_stat*
%{_bindir}/kvm_stat
%{_libdir}/libcpupower.so.0
%{_libdir}/libcpupower.so.0.0.1
%license linux-%{KernelVer}/COPYING

%files -n kernel-tools-devel
%{_libdir}/libcpupower.so
%{_includedir}/cpufreq.h
%{_includedir}/cpuidle.h

%files -n bpftool
%{_sbindir}/bpftool
%{_sysconfdir}/bash_completion.d/bpftool
%{_mandir}/man8/bpftool-cgroup.8.gz
%{_mandir}/man8/bpftool-map.8.gz
%{_mandir}/man8/bpftool-prog.8.gz
%{_mandir}/man8/bpftool-perf.8.gz
%{_mandir}/man8/bpftool.8.gz
%{_mandir}/man8/bpftool-btf.8.gz
%{_mandir}/man8/bpftool-feature.8.gz
%{_mandir}/man8/bpftool-gen.8.gz
%{_mandir}/man8/bpftool-iter.8.gz
%{_mandir}/man8/bpftool-link.8.gz
%{_mandir}/man8/bpftool-net.8.gz
%{_mandir}/man8/bpftool-struct_ops.8.gz
%{_mandir}/man7/bpf-helpers.7.gz
%license linux-%{KernelVer}/COPYING

%if 0%{?with_source}
%files source
%defattr(-,root,root)
/usr/src/linux-%{KernelVer}/*
/usr/src/linux-%{KernelVer}/.config
/usr/src/linux-%{KernelVer}/.scmversion
%endif

%changelog
* Mon Feb 01 2021 Xie XiuQi <xiexiuqi@huawei.com> - 5.10.0-2.0.0.11
- config: add initial openeuler_defconfig for x86
- config: add initial openeuler_defconfig for arm64
- spi: cadence: cache reference clock rate during probe
- spi: fsl: Fix driver breakage when SPI_CS_HIGH is not set in spi->mode
- cxgb4/chtls: Fix tid stuck due to wrong update of qid
- net: dsa: unbind all switches from tree when DSA master unbinds
- mac80211: check if atf has been disabled in __ieee80211_schedule_txq
- mac80211: do not drop tx nulldata packets on encrypted links
- drm/panel: otm8009a: allow using non-continuous dsi clock
- can: mcp251xfd: mcp251xfd_handle_rxif_one(): fix wrong NULL pointer check
- net: stmmac: use __napi_schedule() for PREEMPT_RT
- rxrpc: Fix handling of an unsupported token type in rxrpc_read()
- net: dsa: clear devlink port type before unregistering slave netdevs
- net: phy: smsc: fix clk error handling
- dt-bindings: net: renesas,etheravb: RZ/G2H needs tx-internal-delay-ps
- net: avoid 32 x truesize under-estimation for tiny skbs
- net: stmmac: fix taprio configuration when base_time is in the past
- net: stmmac: fix taprio schedule configuration
- net: sit: unregister_netdevice on newlink's error path
- net: stmmac: Fixed mtu channged by cache aligned
- i40e: fix potential NULL pointer dereferencing
- rxrpc: Call state should be read with READ_ONCE() under some circumstances
- net: dcb: Accept RTM_GETDCB messages carrying set-like DCB commands
- net: dcb: Validate netlink message in DCB handler
- esp: avoid unneeded kmap_atomic call
- rndis_host: set proper input size for OID_GEN_PHYSICAL_MEDIUM request
- net: mvpp2: Remove Pause and Asym_Pause support
- mlxsw: core: Increase critical threshold for ASIC thermal zone
- mlxsw: core: Add validation of transceiver temperature thresholds
- tipc: fix NULL deref in tipc_link_xmit()
- net: ipv6: Validate GSO SKB before finish IPv6 processing
- netxen_nic: fix MSI/MSI-x interrupts
- udp: Prevent reuseport_select_sock from reading uninitialized socks
- net: fix use-after-free when UDP GRO with shared fraglist
- net: ipa: modem: add missing SET_NETDEV_DEV() for proper sysfs links
- bpf: Fix helper bpf_map_peek_elem_proto pointing to wrong callback
- bpf: Support PTR_TO_MEM{,_OR_NULL} register spilling
- bpf: Don't leak memory in bpf getsockopt when optlen == 0
- nfsd4: readdirplus shouldn't return parent of export
- X.509: Fix crash caused by NULL pointer
- bpf: Fix signed_{sub,add32}_overflows type handling
- drm/amdgpu/display: drop DCN support for aarch64
- x86/hyperv: Initialize clockevents after LAPIC is initialized
- bpf: Fix selftest compilation on clang 11
- Revert "kconfig: remove 'kvmconfig' and 'xenconfig' shorthands"
- kretprobe: check re-registration of the same kretprobe earlier
- perf tools: set the default length of HW_BREAKPOINT_X as 4 for non X86_64
- ARM: LPAE: Use phys_addr_t instead of unsigned long in outercache hooks
- aio: add timeout validity check for io_[p]getevents
- ARM: kprobes: fix gcc-7 build warning
- proc: fix ubsan warning in mem_lseek
- netfilter: nf_nat: Fix memleak in nf_nat_init
- netfilter: conntrack: fix reading nf_conntrack_buckets
- ALSA: firewire-tascam: Fix integer overflow in midi_port_work()
- ALSA: fireface: Fix integer overflow in transmit_midi_msg()
- dm: eliminate potential source of excessive kernel log noise
- selftests: netfilter: Pass family parameter "-f" to conntrack tool
- net: sunrpc: interpret the return value of kstrtou32 correctly
- iommu/vt-d: Fix unaligned addresses for intel_flush_svm_range_dev()
- riscv: Trace irq on only interrupt is enabled
- mm, slub: consider rest of partial list if acquire_slab() fails
- drm/i915/gt: Restore clear-residual mitigations for Ivybridge, Baytrail
- drm/i915/icl: Fix initing the DSI DSC power refcount during HW readout
- drm/i915/dsi: Use unconditional msleep for the panel_on_delay when there is no reset-deassert MIPI-sequence
- dm zoned: select CONFIG_CRC32
- umount(2): move the flag validity checks first
- IB/mlx5: Fix error unwinding when set_has_smi_cap fails
- RDMA/mlx5: Fix wrong free of blue flame register on error
- bnxt_en: Improve stats context resource accounting with RDMA driver loaded.
- RDMA/usnic: Fix memleak in find_free_vf_and_create_qp_grp
- RDMA/restrack: Don't treat as an error allocation ID wrapping
- ext4: fix superblock checksum failure when setting password salt
- scsi: ufs: Fix possible power drain during system suspend
- NFS: nfs_igrab_and_active must first reference the superblock
- NFS: nfs_delegation_find_inode_server must first reference the superblock
- NFS/pNFS: Fix a leak of the layout 'plh_outstanding' counter
- NFS/pNFS: Don't leak DS commits in pnfs_generic_retry_commit()
- NFS/pNFS: Don't call pnfs_free_bucket_lseg() before removing the request
- NFS: Adjust fs_context error logging
- pNFS: Stricter ordering of layoutget and layoutreturn
- pNFS: Mark layout for return if return-on-close was not sent
- pNFS: We want return-on-close to complete when evicting the inode
- NFS4: Fix use-after-free in trace_event_raw_event_nfs4_set_lock
- nvme-tcp: Fix warning with CONFIG_DEBUG_PREEMPT
- nvme-tcp: fix possible data corruption with bio merges
- nvme: don't intialize hwmon for discovery controllers
- nvmet-rdma: Fix NULL deref when setting pi_enable and traddr INADDR_ANY
- ASoC: Intel: fix error code cnl_set_dsp_D0()
- ASoC: meson: axg-tdmin: fix axg skew offset
- ASoC: meson: axg-tdm-interface: fix loopback
- dump_common_audit_data(): fix racy accesses to ->d_name
- perf intel-pt: Fix 'CPU too large' error
- mm: don't put pinned pages into the swap cache
- mm: don't play games with pinned pages in clear_page_refs
- mm: fix clear_refs_write locking
- blk-mq-debugfs: Add decode for BLK_MQ_F_TAG_HCTX_SHARED
- net/mlx5: E-Switch, fix changing vf VLANID
- net/mlx5: Fix passing zero to 'PTR_ERR'
- net/mlx5e: CT: Use per flow counter when CT flow accounting is enabled
- iommu/vt-d: Update domain geometry in iommu_ops.at(de)tach_dev
- nvme-fc: avoid calling _nvme_fc_abort_outstanding_ios from interrupt context
- cfg80211: select CONFIG_CRC32
- x86/sev-es: Fix SEV-ES OUT/IN immediate opcode vc handling
- bpf: Save correct stopping point in file seq iteration
- bpf: Simplify task_file_seq_get_next()
- rcu-tasks: Move RCU-tasks initialization to before early_initcall()
- poll: fix performance regression due to out-of-line __put_user()
- ARM: picoxcell: fix missing interrupt-parent properties
- drm/msm: Call msm_init_vram before binding the gpu
- ACPI: scan: add stub acpi_create_platform_device() for !CONFIG_ACPI
- iommu/vt-d: Fix lockdep splat in sva bind()/unbind()
- usb: typec: Fix copy paste error for NVIDIA alt-mode description
- drm/amdgpu: fix potential memory leak during navi12 deinitialization
- drm/amd/pm: fix the failure when change power profile for renoir
- drm/amdgpu: fix a GPU hang issue when remove device
- drm/amd/display: fix sysfs amdgpu_current_backlight_pwm NULL pointer issue
- nvmet-rdma: Fix list_del corruption on queue establishment failure
- nvme: avoid possible double fetch in handling CQE
- nvme-pci: mark Samsung PM1725a as IGNORE_DEV_SUBNQN
- selftests: fix the return value for UDP GRO test
- net: ethernet: fs_enet: Add missing MODULE_LICENSE
- misdn: dsp: select CONFIG_BITREVERSE
- arch/arc: add copy_user_page() to <asm/page.h> to fix build error on ARC
- bfq: Fix computation of shallow depth
- io_uring: drop file refs after task cancel
- spi: fix the divide by 0 error when calculating xfer waiting time
- kconfig: remove 'kvmconfig' and 'xenconfig' shorthands
- lib/raid6: Let $(UNROLL) rules work with macOS userland
- hwmon: (pwm-fan) Ensure that calculation doesn't discard big period values
- habanalabs: Fix memleak in hl_device_reset
- spi: altera: fix return value for altera_spi_txrx()
- staging: spmi: hisi-spmi-controller: Fix some error handling paths
- habanalabs: register to pci shutdown callback
- habanalabs/gaudi: retry loading TPC f/w on -EINTR
- habanalabs: adjust pci controller init to new firmware
- ARM: dts: ux500/golden: Set display max brightness
- ethernet: ucc_geth: fix definition and size of ucc_geth_tx_global_pram
- regulator: bd718x7: Add enable times
- btrfs: fix transaction leak and crash after RO remount caused by qgroup rescan
- btrfs: merge critical sections of discard lock in workfn
- btrfs: fix async discard stall
- ath11k: qmi: try to allocate a big block of DMA memory first
- netfilter: ipset: fixes possible oops in mtype_resize
- ath11k: fix crash caused by NULL rx_channel
- ARM: omap2: pmic-cpcap: fix maximum voltage to be consistent with defaults on xt875
- ARC: build: move symlink creation to arch/arc/Makefile to avoid race
- ARC: build: add boot_targets to PHONY
- ARC: build: add uImage.lzma to the top-level target
- ARC: build: remove non-existing bootpImage from KBUILD_IMAGE
- io_uring: drop mm and files after task_work_run
- io_uring: don't take files/mm for a dead task
- ext4: don't leak old mountpoint samples
- btrfs: tree-checker: check if chunk item end overflows
- r8152: Add Lenovo Powered USB-C Travel Hub
- stmmac: intel: change all EHL/TGL to auto detect phy addr
- dm crypt: defer decryption to a tasklet if interrupts disabled
- dm crypt: do not call bio_endio() from the dm-crypt tasklet
- dm crypt: do not wait for backlogged crypto request completion in softirq
- dm crypt: use GFP_ATOMIC when allocating crypto requests from softirq
- dm integrity: fix the maximum number of arguments
- dm integrity: fix flush with external metadata device
- dm snapshot: flush merged data before committing metadata
- dm raid: fix discard limits for raid1
- mm/process_vm_access.c: include compat.h
- mm/hugetlb: fix potential missing huge page size info
- mm/vmalloc.c: fix potential memory leak
- compiler.h: Raise minimum version of GCC to 5.1 for arm64
- xen/privcmd: allow fetching resource sizes
- ACPI: scan: Harden acpi_device_add() against device ID overflows
- RDMA/ocrdma: Fix use after free in ocrdma_dealloc_ucontext_pd()
- MIPS: relocatable: fix possible boot hangup with KASLR enabled
- MIPS: Fix malformed NT_FILE and NT_SIGINFO in 32bit coredumps
- MIPS: boot: Fix unaligned access with CONFIG_MIPS_RAW_APPENDED_DTB
- mips: lib: uncached: fix non-standard usage of variable 'sp'
- mips: fix Section mismatch in reference
- riscv: Fix KASAN memory mapping.
- riscv: Fixup CONFIG_GENERIC_TIME_VSYSCALL
- riscv: return -ENOSYS for syscall -1
- riscv: Drop a duplicated PAGE_KERNEL_EXEC
- cifs: fix interrupted close commands
- cifs: check pointer before freeing
- ext4: fix wrong list_splice in ext4_fc_cleanup
- ext4: use IS_ERR instead of IS_ERR_OR_NULL and set inode null when IS_ERR
- tools/bootconfig: Add tracing_on support to helper scripts
- tracing/kprobes: Do the notrace functions check without kprobes on ftrace
- drm/bridge: sii902x: Enable I/O and core VCC supplies if present
- dt-bindings: display: sii902x: Add supply bindings
- drm/bridge: sii902x: Refactor init code into separate function
- drm/i915/backlight: fix CPU mode backlight takeover on LPT
- drm/i915/gt: Limit VFE threads based on GT
- drm/i915: Allow the sysadmin to override security mitigations
- drm/amdgpu: add new device id for Renior
- Revert "drm/amd/display: Fixed Intermittent blue screen on OLED panel"
- drm/amdgpu: fix DRM_INFO flood if display core is not supported (bug 210921)
- drm/amdgpu: add green_sardine device id (v2)
- x86/hyperv: check cpu mask after interrupt has been disabled
- ASoC: dapm: remove widget from dirty list on free
- ASoC: AMD Renoir - add DMI entry for Lenovo ThinkPad X395
- ALSA: doc: Fix reference to mixart.rst
- ALSA: hda/realtek: fix right sounds and mute/micmute LEDs for HP machines
- btrfs: prevent NULL pointer dereference in extent_io_tree_panic
- btrfs: reloc: fix wrong file extent type check to avoid false ENOENT
- sched/rt.c: pick and check task if double_lock_balance() unlock the rq
- sched/deadline.c: pick and check task if double_lock_balance() unlock the rq
- tools headers UAPI: Sync linux/fscrypt.h with the kernel sources
- drm/panfrost: Remove unused variables in panfrost_job_close()
- regmap: debugfs: Fix a reversed if statement in regmap_debugfs_init()
- net: drop bogus skb with CHECKSUM_PARTIAL and offset beyond end of trimmed packet
- block: fix use-after-free in disk_part_iter_next
- can: isotp: isotp_getname(): fix kernel information leak
- block/rnbd-clt: avoid module unload race with close confirmation
- xsk: Rollback reservation at NETDEV_TX_BUSY
- xsk: Fix race in SKB mode transmit with shared cq
- KVM: arm64: Don't access PMCR_EL0 when no PMU is available
- selftests: fib_nexthops: Fix wrong mausezahn invocation
- net: mvneta: fix error message when MTU too large for XDP
- drm/i915/dp: Track pm_qos per connector
- net: mvpp2: disable force link UP during port init procedure
- regulator: qcom-rpmh-regulator: correct hfsmps515 definition
- arm64: cpufeature: remove non-exist CONFIG_KVM_ARM_HOST
- wan: ds26522: select CONFIG_BITREVERSE
- regmap: debugfs: Fix a memory leak when calling regmap_attach_dev
- net/mlx5e: Fix two double free cases
- net/mlx5e: Fix memleak in mlx5e_create_l2_table_groups
- nvme-tcp: Fix possible race of io_work and direct send
- bpftool: Fix compilation failure for net.o with older glibc
- iommu/intel: Fix memleak in intel_irq_remapping_alloc
- iommu/vt-d: Fix misuse of ALIGN in qi_flush_piotlb()
- zonefs: select CONFIG_CRC32
- lightnvm: select CONFIG_CRC32
- block: rsxx: select CONFIG_CRC32
- wil6210: select CONFIG_CRC32
- phy: dp83640: select CONFIG_CRC32
- qed: select CONFIG_CRC32
- arm64: mm: Fix ARCH_LOW_ADDRESS_LIMIT when !CONFIG_ZONE_DMA
- dmaengine: xilinx_dma: fix mixed_enum_type coverity warning
- dmaengine: xilinx_dma: fix incompatible param warning in _child_probe()
- dmaengine: xilinx_dma: check dma_async_device_register return value
- dmaengine: milbeaut-xdmac: Fix a resource leak in the error handling path of the probe function
- dmaengine: mediatek: mtk-hsdma: Fix a resource leak in the error handling path of the probe function
- interconnect: qcom: fix rpmh link failures
- interconnect: imx: Add a missing of_node_put after of_device_is_available
- bcache: set bcache device into read-only mode for BCH_FEATURE_INCOMPAT_OBSO_LARGE_BUCKET
- i2c: mediatek: Fix apdma and i2c hand-shake timeout
- i2c: i801: Fix the i2c-mux gpiod_lookup_table not being properly terminated
- spi: stm32: FIFO threshold level - fix align packet size
- spi: spi-geni-qcom: Fix geni_spi_isr() NULL dereference in timeout case
- cpufreq: powernow-k8: pass policy rather than use cpufreq_cpu_get()
- spi: spi-geni-qcom: Fail new xfers if xfer/cancel/abort pending
- can: kvaser_pciefd: select CONFIG_CRC32
- can: m_can: m_can_class_unregister(): remove erroneous m_can_clk_stop()
- can: tcan4x5x: fix bittiming const, use common bittiming from m_can driver
- selftests/bpf: Clarify build error if no vmlinux
- dmaengine: dw-edma: Fix use after free in dw_edma_alloc_chunk()
- i2c: sprd: use a specific timeout to avoid system hang up issue
- ARM: OMAP2+: omap_device: fix idling of devices during probe
- fanotify: Fix sys_fanotify_mark() on native x86-32
- HID: wacom: Fix memory leakage caused by kfifo_alloc
- ionic: start queues before announcing link up
- scsi: lpfc: Fix variable 'vport' set but not used in lpfc_sli4_abts_err_handler()
- net/mlx5: Check if lag is supported before creating one
- net/mlx5e: In skb build skip setting mark in switchdev mode
- net/mlx5e: ethtool, Fix restriction of autoneg with 56G
- net/mlx5: Use port_num 1 instead of 0 when delete a RoCE address
- net: dsa: lantiq_gswip: Exclude RMII from modes that report 1 GbE
- s390/qeth: fix L2 header access in qeth_l3_osa_features_check()
- s390/qeth: fix locking for discipline setup / removal
- s390/qeth: fix deadlock during recovery
- nexthop: Bounce NHA_GATEWAY in FDB nexthop groups
- nexthop: Unlink nexthop group entry in error path
- nexthop: Fix off-by-one error in error path
- octeontx2-af: fix memory leak of lmac and lmac->name
- chtls: Fix chtls resources release sequence
- chtls: Added a check to avoid NULL pointer dereference
- chtls: Replace skb_dequeue with skb_peek
- chtls: Avoid unnecessary freeing of oreq pointer
- chtls: Fix panic when route to peer not configured
- chtls: Remove invalid set_tcb call
- chtls: Fix hardware tid leak
- net: ip: always refragment ip defragmented packets
- net: fix pmtu check in nopmtudisc mode
- tools: selftests: add test for changing routes with PTMU exceptions
- net: ipv6: fib: flush exceptions when purging route
- ptp: ptp_ines: prevent build when HAS_IOMEM is not set
- net: bareudp: add missing error handling for bareudp_link_config()
- net/sonic: Fix some resource leaks in error handling paths
- net: vlan: avoid leaks on register_vlan_dev() failures
- net: stmmac: dwmac-sun8i: Balance syscon (de)initialization
- net: stmmac: dwmac-sun8i: Balance internal PHY power
- net: stmmac: dwmac-sun8i: Balance internal PHY resource references
- net: stmmac: dwmac-sun8i: Fix probe error handling
- net: hns3: fix a phy loopback fail issue
- net: hns3: fix the number of queues actually used by ARQ
- net: hns3: fix incorrect handling of sctp6 rss tuple
- net: cdc_ncm: correct overhead in delayed_ndp_size
- btrfs: shrink delalloc pages instead of full inodes
- btrfs: fix deadlock when cloning inline extent and low on free metadata space
- btrfs: skip unnecessary searches for xattrs when logging an inode
- scsi: ufs: Fix -Wsometimes-uninitialized warning
- io_uring: Fix return value from alloc_fixed_file_ref_node
- drm/panfrost: Don't corrupt the queue mutex on open/close
- iommu/arm-smmu-qcom: Initialize SCTLR of the bypass context
- RDMA/hns: Avoid filling sl in high 3 bits of vlan_id
- io_uring: patch up IOPOLL overflow_flush sync
- io_uring: limit {io|sq}poll submit locking scope
- io_uring: synchronise IOPOLL on task_submit fail
- powerpc/32s: Fix RTAS machine check with VMAP stack
- ARM: 9031/1: hyp-stub: remove unused .L__boot_cpu_mode_offset symbol
- ARM: kvm: replace open coded VA->PA calculations with adr_l call
- ARM: head.S: use PC relative insn sequence to calculate PHYS_OFFSET
- ARM: sleep.S: use PC-relative insn sequence for sleep_save_sp/mpidr_hash
- ARM: head: use PC-relative insn sequence for __smp_alt
- ARM: kernel: use relative references for UP/SMP alternatives
- ARM: head.S: use PC-relative insn sequence for secondary_data
- ARM: head-common.S: use PC-relative insn sequence for idmap creation
- ARM: head-common.S: use PC-relative insn sequence for __proc_info
- ARM: efistub: replace adrl pseudo-op with adr_l macro invocation
- ARM: p2v: reduce p2v alignment requirement to 2 MiB
- ARM: p2v: switch to MOVW for Thumb2 and ARM/LPAE
- ARM: p2v: simplify __fixup_pv_table()
- ARM: p2v: use relative references in patch site arrays
- ARM: p2v: drop redundant 'type' argument from __pv_stub
- ARM: p2v: factor out BE8 handling
- ARM: p2v: factor out shared loop processing
- ARM: p2v: move patching code to separate assembler source file
- ARM: module: add support for place relative relocations
- ARM: assembler: introduce adr_l, ldr_l and str_l macros
- scsi: target: Fix XCOPY NAA identifier lookup
- rtlwifi: rise completion at the last step of firmware callback
- xsk: Fix memory leak for failed bind
- KVM: x86: fix shift out of bounds reported by UBSAN
- x86/mtrr: Correct the range check before performing MTRR type lookups
- dmaengine: idxd: off by one in cleanup code
- netfilter: nft_dynset: report EOPNOTSUPP on missing set feature
- netfilter: xt_RATEEST: reject non-null terminated string from userspace
- netfilter: ipset: fix shift-out-of-bounds in htable_bits()
- netfilter: x_tables: Update remaining dereference to RCU
- ARM: dts: OMAP3: disable AES on N950/N9
- net/mlx5e: Fix SWP offsets when vlan inserted by driver
- bcache: introduce BCH_FEATURE_INCOMPAT_LOG_LARGE_BUCKET_SIZE for large bucket
- bcache: check unsupported feature sets for bcache register
- bcache: fix typo from SUUP to SUPP in features.h
- drm/i915: clear the gpu reloc batch
- drm/i915: clear the shadow batch
- arm64: link with -z norelro for LLD or aarch64-elf
- dmabuf: fix use-after-free of dmabuf's file->f_inode
- Revert "device property: Keep secondary firmware node secondary by type"
- btrfs: send: fix wrong file path when there is an inode with a pending rmdir
- btrfs: qgroup: don't try to wait flushing if we're already holding a transaction
- iommu/vt-d: Move intel_iommu info from struct intel_svm to struct intel_svm_dev
- ALSA: hda/realtek: Add two "Intel Reference board" SSID in the ALC256.
- ALSA: hda/realtek: Enable mute and micmute LED on HP EliteBook 850 G7
- ALSA: hda/realtek: Add mute LED quirk for more HP laptops
- ALSA: hda/realtek - Fix speaker volume control on Lenovo C940
- ALSA: hda/conexant: add a new hda codec CX11970
- ALSA: hda/via: Fix runtime PM for Clevo W35xSS
- blk-iocost: fix NULL iocg deref from racing against initialization
- x86/resctrl: Don't move a task to the same resource group
- x86/resctrl: Use an IPI instead of task_work_add() to update PQR_ASSOC MSR
- KVM: x86/mmu: Ensure TDP MMU roots are freed after yield
- kvm: check tlbs_dirty directly
- KVM: x86/mmu: Get root level from walkers when retrieving MMIO SPTE
- KVM: x86/mmu: Use -1 to flag an undefined spte in get_mmio_spte()
- x86/mm: Fix leak of pmd ptlock
- mm: make wait_on_page_writeback() wait for multiple pending writebacks
- hwmon: (amd_energy) fix allocation of hwmon_channel_info config
- USB: serial: keyspan_pda: remove unused variable
- usb: gadget: configfs: Fix use-after-free issue with udc_name
- usb: gadget: configfs: Preserve function ordering after bind failure
- usb: gadget: Fix spinlock lockup on usb_function_deactivate
- USB: gadget: legacy: fix return error code in acm_ms_bind()
- usb: gadget: u_ether: Fix MTU size mismatch with RX packet size
- usb: gadget: function: printer: Fix a memory leak for interface descriptor
- usb: gadget: f_uac2: reset wMaxPacketSize
- USB: Gadget: dummy-hcd: Fix shift-out-of-bounds bug
- usb: gadget: select CONFIG_CRC32
- ALSA: usb-audio: Fix UBSAN warnings for MIDI jacks
- USB: usblp: fix DMA to stack
- USB: yurex: fix control-URB timeout handling
- USB: serial: option: add Quectel EM160R-GL
- USB: serial: option: add LongSung M5710 module support
- USB: serial: iuu_phoenix: fix DMA from stack
- usb: uas: Add PNY USB Portable SSD to unusual_uas
- usb: usbip: vhci_hcd: protect shift size
- USB: xhci: fix U1/U2 handling for hardware with XHCI_INTEL_HOST quirk set
- usb: chipidea: ci_hdrc_imx: add missing put_device() call in usbmisc_get_init_data()
- usb: dwc3: ulpi: Fix USB2.0 HS/FS/LS PHY suspend regression
- usb: dwc3: ulpi: Replace CPU-based busyloop with Protocol-based one
- usb: dwc3: ulpi: Use VStsDone to detect PHY regs access completion
- usb: dwc3: gadget: Clear wait flag on dequeue
- usb: dwc3: gadget: Restart DWC3 gadget when enabling pullup
- usb: dwc3: meson-g12a: disable clk on error handling path in probe
- usb: typec: intel_pmc_mux: Configure HPD first for HPD+IRQ request
- USB: cdc-wdm: Fix use after free in service_outstanding_interrupt().
- USB: cdc-acm: blacklist another IR Droid device
- usb: gadget: enable super speed plus
- staging: mt7621-dma: Fix a resource leak in an error handling path
- Staging: comedi: Return -EFAULT if copy_to_user() fails
- powerpc: Handle .text.{hot,unlikely}.* in linker script
- crypto: asym_tpm: correct zero out potential secrets
- crypto: ecdh - avoid buffer overflow in ecdh_set_secret()
- scsi: block: Do not accept any requests while suspended
- scsi: block: Remove RQF_PREEMPT and BLK_MQ_REQ_PREEMPT
- Bluetooth: revert: hci_h5: close serdev device and free hu in h5_close
- kbuild: don't hardcode depmod path
- scsi: ufs: Clear UAC for FFU and RPMB LUNs
- depmod: handle the case of /sbin/depmod without /sbin in PATH
- lib/genalloc: fix the overflow when size is too big
- local64.h: make <asm/local64.h> mandatory
- scsi: core: Only process PM requests if rpm_status != RPM_ACTIVE
- scsi: scsi_transport_spi: Set RQF_PM for domain validation commands
- scsi: ide: Mark power management requests with RQF_PM instead of RQF_PREEMPT
- scsi: ide: Do not set the RQF_PREEMPT flag for sense requests
- scsi: block: Introduce BLK_MQ_REQ_PM
- scsi: ufs-pci: Enable UFSHCD_CAP_RPM_AUTOSUSPEND for Intel controllers
- scsi: ufs-pci: Fix recovery from hibernate exit errors for Intel controllers
- scsi: ufs-pci: Ensure UFS device is in PowerDown mode for suspend-to-disk ->poweroff()
- scsi: ufs-pci: Fix restore from S4 for Intel controllers
- scsi: ufs: Fix wrong print message in dev_err()
- workqueue: Kick a worker based on the actual activation of delayed works
- block: add debugfs stanza for QUEUE_FLAG_NOWAIT
- selftests/vm: fix building protection keys test
- stmmac: intel: Add PCI IDs for TGL-H platform
- selftests: mlxsw: Set headroom size of correct port
- net: usb: qmi_wwan: add Quectel EM160R-GL
- ibmvnic: fix: NULL pointer dereference.
- CDC-NCM: remove "connected" log message
- net: dsa: lantiq_gswip: Fix GSWIP_MII_CFG(p) register access
- net: dsa: lantiq_gswip: Enable GSWIP_MII_CFG_EN also for internal PHYs
- r8169: work around power-saving bug on some chip versions
- vhost_net: fix ubuf refcount incorrectly when sendmsg fails
- bareudp: Fix use of incorrect min_headroom size
- bareudp: set NETIF_F_LLTX flag
- net: hdlc_ppp: Fix issues when mod_timer is called while timer is running
- erspan: fix version 1 check in gre_parse_header()
- net: hns: fix return value check in __lb_other_process()
- net: sched: prevent invalid Scell_log shift count
- ipv4: Ignore ECN bits for fib lookups in fib_compute_spec_dst()
- bnxt_en: Fix AER recovery.
- net: mvpp2: fix pkt coalescing int-threshold configuration
- bnxt_en: Check TQM rings for maximum supported value.
- e1000e: Export S0ix flags to ethtool
- Revert "e1000e: disable s0ix entry and exit flows for ME systems"
- e1000e: bump up timeout to wait when ME un-configures ULP mode
- e1000e: Only run S0ix flows if shutdown succeeded
- tun: fix return value when the number of iovs exceeds MAX_SKB_FRAGS
- net: ethernet: ti: cpts: fix ethtool output when no ptp_clock registered
- net-sysfs: take the rtnl lock when accessing xps_rxqs_map and num_tc
- net-sysfs: take the rtnl lock when storing xps_rxqs
- net-sysfs: take the rtnl lock when accessing xps_cpus_map and num_tc
- net-sysfs: take the rtnl lock when storing xps_cpus
- net: ethernet: Fix memleak in ethoc_probe
- net/ncsi: Use real net-device for response handler
- virtio_net: Fix recursive call to cpus_read_lock()
- qede: fix offload for IPIP tunnel packets
- net: ethernet: mvneta: Fix error handling in mvneta_probe
- ibmvnic: continue fatal error reset after passive init
- ibmvnic: fix login buffer memory leak
- net: stmmac: dwmac-meson8b: ignore the second clock input
- net: mvpp2: Fix GoP port 3 Networking Complex Control configurations
- atm: idt77252: call pci_disable_device() on error path
- ionic: account for vlan tag len in rx buffer len
- ethernet: ucc_geth: set dev->max_mtu to 1518
- ethernet: ucc_geth: fix use-after-free in ucc_geth_remove()
- net: systemport: set dev->max_mtu to UMAC_MAX_MTU_SIZE
- net: mvpp2: prs: fix PPPoE with ipv6 packet parse
- net: mvpp2: Add TCAM entry to drop flow control pause frames
- net/sched: sch_taprio: ensure to reset/destroy all child qdiscs
- iavf: fix double-release of rtnl_lock
- i40e: Fix Error I40E_AQ_RC_EINVAL when removing VFs
- mwifiex: Fix possible buffer overflows in mwifiex_cmd_802_11_ad_hoc_start
- exec: Transform exec_update_mutex into a rw_semaphore
- rwsem: Implement down_read_interruptible
- rwsem: Implement down_read_killable_nested
- perf: Break deadlock involving exec_update_mutex
- fuse: fix bad inode
- RDMA/siw,rxe: Make emulated devices virtual in the device tree
- RDMA/core: remove use of dma_virt_ops
- scsi: ufs: Re-enable WriteBooster after device reset
- scsi: ufs: Allow an error return value from ->device_reset()
- drm/i915/tgl: Fix Combo PHY DPLL fractional divider for 38.4MHz ref clock
- ALSA: hda/hdmi: Fix incorrect mutex unlock in silent_stream_disable()
- ALSA: hda/realtek - Modify Dell platform name
- Bluetooth: Fix attempting to set RPA timeout when unsupported
- kdev_t: always inline major/minor helper functions
- dt-bindings: rtc: add reset-source property
- rtc: pcf2127: only use watchdog when explicitly available
- rtc: pcf2127: move watchdog initialisation to a separate function
- Revert "mtd: spinand: Fix OOB read"
- Revert "drm/amd/display: Fix memory leaks in S3 resume"
- ext4: fix bug for rename with RENAME_WHITEOUT
- device-dax: Fix range release
- ext4: avoid s_mb_prefetch to be zero in individual scenarios
- dm verity: skip verity work if I/O error when system is shutting down
- ALSA: pcm: Clear the full allocated memory at hw_params
- io_uring: remove racy overflow list fast checks
- s390: always clear kernel stack backchain before calling functions
- tick/sched: Remove bogus boot "safety" check
- drm/amd/display: updated wm table for Renoir
- ceph: fix inode refcount leak when ceph_fill_inode on non-I_NEW inode fails
- NFSv4.2: Don't error when exiting early on a READ_PLUS buffer overflow
- um: ubd: Submit all data segments atomically
- um: random: Register random as hwrng-core device
- watchdog: rti-wdt: fix reference leak in rti_wdt_probe
- fs/namespace.c: WARN if mnt_count has become negative
- powerpc/64: irq replay remove decrementer overflow check
- module: delay kobject uevent until after module init call
- f2fs: fix race of pending_pages in decompression
- f2fs: avoid race condition for shrinker count
- NFSv4: Fix a pNFS layout related use-after-free race when freeing the inode
- i3c master: fix missing destroy_workqueue() on error in i3c_master_register
- powerpc: sysdev: add missing iounmap() on error in mpic_msgr_probe()
- rtc: pl031: fix resource leak in pl031_probe
- quota: Don't overflow quota file offsets
- module: set MODULE_STATE_GOING state when a module fails to load
- rtc: sun6i: Fix memleak in sun6i_rtc_clk_init
- io_uring: check kthread stopped flag when sq thread is unparked
- fcntl: Fix potential deadlock in send_sig{io, urg}()
- ext4: check for invalid block size early when mounting a file system
- bfs: don't use WARNING: string when it's just info.
- ALSA: rawmidi: Access runtime->avail always in spinlock
- ALSA: seq: Use bool for snd_seq_queue internal flags
- f2fs: fix shift-out-of-bounds in sanity_check_raw_super()
- media: gp8psk: initialize stats at power control logic
- misc: vmw_vmci: fix kernel info-leak by initializing dbells in vmci_ctx_get_chkpt_doorbells()
- reiserfs: add check for an invalid ih_entry_count
- fbcon: Disable accelerated scrolling
- Bluetooth: hci_h5: close serdev device and free hu in h5_close
- scsi: cxgb4i: Fix TLS dependency
- zlib: move EXPORT_SYMBOL() and MODULE_LICENSE() out of dfltcc_syms.c
- cgroup: Fix memory leak when parsing multiple source parameters
- tools headers UAPI: Sync linux/const.h with the kernel headers
- uapi: move constants from <linux/kernel.h> to <linux/const.h>
- io_uring: fix io_sqe_files_unregister() hangs
- io_uring: add a helper for setting a ref node
- io_uring: use bottom half safe lock for fixed file data
- io_uring: don't assume mm is constant across submits
- lib/zlib: fix inflating zlib streams on s390
- mm: memmap defer init doesn't work as expected
- mm/hugetlb: fix deadlock in hugetlb_cow error path
- scsi: block: Fix a race in the runtime power management code
- opp: Call the missing clk_put() on error
- opp: fix memory leak in _allocate_opp_table
- spi: dw-bt1: Fix undefined devm_mux_control_get symbol
- jffs2: Fix NULL pointer dereference in rp_size fs option parsing
- jffs2: Allow setting rp_size to zero during remounting
- io_uring: close a small race gap for files cancel
- drm/amd/display: Add get_dig_frontend implementation for DCEx
- md/raid10: initialize r10_bio->read_slot before use.
- ethtool: fix string set id check
- ethtool: fix error paths in ethnl_set_channels()
- mptcp: fix security context on server socket
- net/sched: sch_taprio: reset child qdiscs before freeing them

* Tue Jan 29 2021 Yuan Zhichang <erik.yuan@arm.com> - 5.10.0-1.0.0.10
- Add the option of "with_perf"
- Output jvmti plug-in as part of perf building

* Tue Jan 26 2021 Chunsheng Luo <luochunsheng@huawei.com> - 5.10.0-1.0.0.9
- split from kernel-devel to kernel-headers and kernel-devel

* Tue Jan 12 2021 Xie XiuQi <xiexiuqi@huawei.com> - 5.10.0-1.0.0.8
- kvm: debugfs: Export x86 kvm exits to vcpu_stat
- kvm: debugfs: aarch64 export cpu time related items to debugfs
- kvm: debugfs: export remaining aarch64 kvm exit reasons to debugfs
- kvm: debugfs: Export vcpu stat via debugfs
- RISCV: KVM: fix bug in migration
- RISC-V: Enable KVM for RV64 and RV32
- RISC-V: KVM: Add MAINTAINERS entry
- RISC-V: KVM: Document RISC-V specific parts of KVM API
- RISC-V: KVM: Add SBI v0.1 support
- RISC-V: KVM: Implement ONE REG interface for FP registers
- RISC-V: KVM: FP lazy save/restore
- RISC-V: KVM: Add timer functionality
- RISC-V: KVM: Implement MMU notifiers
- RISC-V: KVM: Implement stage2 page table programming
- RISC-V: KVM: Implement VMID allocator
- RISC-V: KVM: Handle WFI exits for VCPU
- RISC-V: KVM: Handle MMIO exits for VCPU
- RISC-V: KVM: Implement VCPU world-switch
- RISC-V: KVM: Implement KVM_GET_ONE_REG/KVM_SET_ONE_REG ioctls
- RISC-V: KVM: Implement VCPU interrupts and requests handling
- RISC-V: KVM: Implement VCPU create, init and destroy functions
- RISC-V: Add initial skeletal KVM support
- RISC-V: Add hypervisor extension related CSR defines
- RISC-V: Enable drivers for Microchip PolarFire ICICLE board
- RISC-V: Initial DTS for Microchip ICICLE board
- RISC-V: Add Microchip PolarFire kconfig option
- Microchip Polarfire SoC Clock Driver
- RISC-V: Enable CPU Hotplug in defconfigs
- Revert "riscv: Use latest system call ABI"
- RISC-V: Add fragmented config for debug options
- x86/CPU/AMD: Save AMD NodeId as cpu_die_id
- drm/edid: fix objtool warning in drm_cvt_modes()
- null_blk: Fail zone append to conventional zones
- null_blk: Fix zone size initialization
- Revert: "ring-buffer: Remove HAVE_64BIT_ALIGNED_ACCESS"
- rtc: ep93xx: Fix NULL pointer dereference in ep93xx_rtc_read_time
- thermal/drivers/cpufreq_cooling: Update cpufreq_state only if state has changed
- remoteproc: sysmon: Ensure remote notification ordering
- regulator: axp20x: Fix DLDO2 voltage control register mask for AXP22x
- PCI: Fix pci_slot_release() NULL pointer dereference
- of: fix linker-section match-table corruption
- mt76: add back the SUPPORTS_REORDERING_BUFFER flag
- tracing: Disable ftrace selftests when any tracer is running
- platform/x86: intel-vbtn: Allow switch events on Acer Switch Alpha 12
- libnvdimm/namespace: Fix reaping of invalidated block-window-namespace labels
- memory: renesas-rpc-if: Fix unbalanced pm_runtime_enable in rpcif_{enable,disable}_rpm
- memory: renesas-rpc-if: Return correct value to the caller of rpcif_manual_xfer()
- memory: renesas-rpc-if: Fix a node reference leak in rpcif_probe()
- memory: jz4780_nemc: Fix an error pointer vs NULL check in probe()
- xenbus/xenbus_backend: Disallow pending watch messages
- xen/xenbus: Count pending messages for each watch
- xen/xenbus/xen_bus_type: Support will_handle watch callback
- xen/xenbus: Add 'will_handle' callback support in xenbus_watch_path()
- xen/xenbus: Allow watches discard events before queueing
- xen-blkback: set ring->xenblkd to NULL after kthread_stop()
- driver: core: Fix list corruption after device_del()
- dma-buf/dma-resv: Respect num_fences when initializing the shared fence list.
- device-dax/core: Fix memory leak when rmmod dax.ko
- counter: microchip-tcb-capture: Fix CMR value check
- clk: tegra: Do not return 0 on failure
- clk: mvebu: a3700: fix the XTAL MODE pin to MPP1_9
- clk: ingenic: Fix divider calculation with div tables
- pinctrl: sunxi: Always call chained_irq_{enter, exit} in sunxi_pinctrl_irq_handler
- md/cluster: fix deadlock when node is doing resync job
- md/cluster: block reshape with remote resync job
- iio:adc:ti-ads124s08: Fix alignment and data leak issues.
- iio:adc:ti-ads124s08: Fix buffer being too long.
- iio:imu:bmi160: Fix alignment and data leak issues
- iio:imu:bmi160: Fix too large a buffer.
- iio:pressure:mpl3115: Force alignment of buffer
- iio:magnetometer:mag3110: Fix alignment and data leak issues.
- iio:light:st_uvis25: Fix timestamp alignment and prevent data leak.
- iio:light:rpr0521: Fix timestamp alignment and prevent data leak.
- iio: imu: st_lsm6dsx: fix edge-trigger interrupts
- iio: adc: rockchip_saradc: fix missing clk_disable_unprepare() on error in rockchip_saradc_resume
- iio: buffer: Fix demux update
- openat2: reject RESOLVE_BENEATH|RESOLVE_IN_ROOT
- scsi: lpfc: Re-fix use after free in lpfc_rq_buf_free()
- scsi: lpfc: Fix scheduling call while in softirq context in lpfc_unreg_rpi
- scsi: lpfc: Fix invalid sleeping context in lpfc_sli4_nvmet_alloc()
- scsi: qla2xxx: Fix crash during driver load on big endian machines
- mtd: rawnand: meson: fix meson_nfc_dma_buffer_release() arguments
- mtd: rawnand: qcom: Fix DMA sync on FLASH_STATUS register read
- mtd: core: Fix refcounting for unpartitioned MTDs
- mtd: parser: cmdline: Fix parsing of part-names with colons
- mtd: spinand: Fix OOB read
- soc: qcom: smp2p: Safely acquire spinlock without IRQs
- spi: atmel-quadspi: Fix AHB memory accesses
- spi: atmel-quadspi: Disable clock in probe error path
- spi: mt7621: Don't leak SPI master in probe error path
- spi: mt7621: Disable clock in probe error path
- spi: synquacer: Disable clock in probe error path
- spi: st-ssc4: Fix unbalanced pm_runtime_disable() in probe error path
- spi: spi-qcom-qspi: Fix use-after-free on unbind
- spi: spi-geni-qcom: Fix use-after-free on unbind
- spi: sc18is602: Don't leak SPI master in probe error path
- spi: rpc-if: Fix use-after-free on unbind
- spi: rb4xx: Don't leak SPI master in probe error path
- spi: pic32: Don't leak DMA channels in probe error path
- spi: npcm-fiu: Disable clock in probe error path
- spi: mxic: Don't leak SPI master in probe error path
- spi: gpio: Don't leak SPI master in probe error path
- spi: fsl: fix use of spisel_boot signal on MPC8309
- spi: davinci: Fix use-after-free on unbind
- spi: ar934x: Don't leak SPI master in probe error path
- spi: spi-mtk-nor: Don't leak SPI master in probe error path
- spi: atmel-quadspi: Fix use-after-free on unbind
- spi: spi-sh: Fix use-after-free on unbind
- spi: pxa2xx: Fix use-after-free on unbind
- iio: ad_sigma_delta: Don't put SPI transfer buffer on the stack
- drm/i915: Fix mismatch between misplaced vma check and vma insert
- drm/dp_aux_dev: check aux_dev before use in drm_dp_aux_dev_get_by_minor()
- drm/amd/display: Fix memory leaks in S3 resume
- drm/amdgpu: only set DP subconnector type on DP and eDP connectors
- platform/x86: mlx-platform: remove an unused variable
- drm/panfrost: Move the GPU reset bits outside the timeout handler
- drm/panfrost: Fix job timeout handling
- jfs: Fix array index bounds check in dbAdjTree
- fsnotify: fix events reported to watching parent and child
- inotify: convert to handle_inode_event() interface
- fsnotify: generalize handle_inode_event()
- jffs2: Fix ignoring mounting options problem during remounting
- jffs2: Fix GC exit abnormally
- ubifs: wbuf: Don't leak kernel memory to flash
- SMB3.1.1: do not log warning message if server doesn't populate salt
- SMB3.1.1: remove confusing mount warning when no SPNEGO info on negprot rsp
- SMB3: avoid confusing warning message on mount to Azure
- ceph: fix race in concurrent __ceph_remove_cap invocations
- um: Fix time-travel mode
- um: Remove use of asprinf in umid.c
- ima: Don't modify file descriptor mode on the fly
- ovl: make ioctl() safe
- powerpc/powernv/memtrace: Fix crashing the kernel when enabling concurrently
- powerpc/powernv/memtrace: Don't leak kernel memory to user space
- powerpc/powernv/npu: Do not attempt NPU2 setup on POWER8NVL NPU
- powerpc/mm: Fix verification of MMU_FTR_TYPE_44x
- powerpc/8xx: Fix early debug when SMC1 is relocated
- powerpc/xmon: Change printk() to pr_cont()
- powerpc/feature: Add CPU_FTR_NOEXECUTE to G2_LE
- powerpc/bitops: Fix possible undefined behaviour with fls() and fls64()
- powerpc/rtas: Fix typo of ibm,open-errinjct in RTAS filter
- powerpc: Fix incorrect stw{, ux, u, x} instructions in __set_pte_at
- powerpc/32: Fix vmap stack - Properly set r1 before activating MMU on syscall too
- xprtrdma: Fix XDRBUF_SPARSE_PAGES support
- ARM: tegra: Populate OPP table for Tegra20 Ventana
- ARM: dts: at91: sama5d2: fix CAN message ram offset and size
- ARM: dts: pandaboard: fix pinmux for gpio user button of Pandaboard ES
- iommu/arm-smmu-qcom: Implement S2CR quirk
- iommu/arm-smmu-qcom: Read back stream mappings
- iommu/arm-smmu: Allow implementation specific write_s2cr
- KVM: SVM: Remove the call to sev_platform_status() during setup
- KVM: x86: reinstate vendor-agnostic check on SPEC_CTRL cpuid bits
- KVM: arm64: Introduce handling of AArch32 TTBCR2 traps
- arm64: dts: marvell: keep SMMU disabled by default for Armada 7040 and 8040
- arm64: dts: ti: k3-am65: mark dss as dma-coherent
- RISC-V: Fix usage of memblock_enforce_memory_limit
- ext4: don't remount read-only with errors=continue on reboot
- ext4: fix deadlock with fs freezing and EA inodes
- ext4: fix a memory leak of ext4_free_data
- ext4: fix an IS_ERR() vs NULL check
- btrfs: fix race when defragmenting leads to unnecessary IO
- btrfs: update last_byte_to_unpin in switch_commit_roots
- btrfs: do not shorten unpin len for caching block groups
- USB: serial: keyspan_pda: fix write unthrottling
- USB: serial: keyspan_pda: fix tx-unthrottle use-after-free
- USB: serial: keyspan_pda: fix write-wakeup use-after-free
- USB: serial: keyspan_pda: fix stalled writes
- USB: serial: keyspan_pda: fix write deadlock
- USB: serial: keyspan_pda: fix dropped unthrottle interrupts
- USB: serial: digi_acceleport: fix write-wakeup deadlocks
- USB: serial: mos7720: fix parallel-port state restore
- dyndbg: fix use before null check
- cpuset: fix race between hotplug work and later CPU offline
- EDAC/amd64: Fix PCI component registration
- EDAC/i10nm: Use readl() to access MMIO registers
- Documentation: seqlock: s/LOCKTYPE/LOCKNAME/g
- m68k: Fix WARNING splat in pmac_zilog driver
- crypto: arm/aes-ce - work around Cortex-A57/A72 silion errata
- crypto: ecdh - avoid unaligned accesses in ecdh_set_secret()
- cpufreq: intel_pstate: Use most recent guaranteed performance values
- powerpc/perf: Exclude kernel samples while counting events in user space.
- perf/x86/intel/lbr: Fix the return type of get_lbr_cycles()
- perf/x86/intel: Fix rtm_abort_event encoding on Ice Lake
- perf/x86/intel: Add event constraint for CYCLE_ACTIVITY.STALLS_MEM_ANY
- z3fold: stricter locking and more careful reclaim
- z3fold: simplify freeing slots
- staging: comedi: mf6x4: Fix AI end-of-conversion detection
- ASoC: AMD Raven/Renoir - fix the PCI probe (PCI revision)
- ASoC: AMD Renoir - add DMI table to avoid the ACP mic probe (broken BIOS)
- ASoC: cx2072x: Fix doubly definitions of Playback and Capture streams
- binder: add flag to clear buffer on txn complete
- s390/dasd: fix list corruption of lcu list
- s390/dasd: fix list corruption of pavgroup group list
- s390/dasd: prevent inconsistent LCU device data
- s390/dasd: fix hanging device offline processing
- s390/idle: fix accounting with machine checks
- s390/idle: add missing mt_cycles calculation
- s390/kexec_file: fix diag308 subcode when loading crash kernel
- s390/smp: perform initial CPU reset also for SMT siblings
- ALSA: core: memalloc: add page alignment for iram
- ALSA: usb-audio: Add alias entry for ASUS PRIME TRX40 PRO-S
- ALSA: usb-audio: Disable sample read check if firmware doesn't give back
- ALSA: usb-audio: Add VID to support native DSD reproduction on FiiO devices
- ALSA: hda/realtek - Supported Dell fixed type headset
- ALSA: hda/realtek: Remove dummy lineout on Acer TravelMate P648/P658
- ALSA: hda/realtek: Apply jack fixup for Quanta NL3
- ALSA: hda/realtek: Add quirk for MSI-GP73
- ALSA/hda: apply jack fixup for the Acer Veriton N4640G/N6640G/N2510G
- ALSA: pcm: oss: Fix a few more UBSAN fixes
- ALSA: hda/realtek - Add supported for more Lenovo ALC285 Headset Button
- ALSA: hda/realtek - Enable headset mic of ASUS Q524UQK with ALC255
- ALSA: hda/realtek - Enable headset mic of ASUS X430UN with ALC256
- ALSA: hda/realtek: make bass spk volume adjustable on a yoga laptop
- ALSA: hda/ca0132 - Fix AE-5 rear headphone pincfg.
- ALSA: hda: Fix regressions on clear and reconfig sysfs
- ACPI: PNP: compare the string length in the matching_id()
- Revert "ACPI / resources: Use AE_CTRL_TERMINATE to terminate resources walks"
- PM: ACPI: PCI: Drop acpi_pm_set_bridge_wakeup()
- ACPI: NFIT: Fix input validation of bus-family
- ALSA: hda/ca0132 - Change Input Source enum strings.
- Input: cyapa_gen6 - fix out-of-bounds stack access
- media: ipu3-cio2: Make the field on subdev format V4L2_FIELD_NONE
- media: ipu3-cio2: Validate mbus format in setting subdev format
- media: ipu3-cio2: Serialise access to pad format
- media: ipu3-cio2: Return actual subdev format
- media: ipu3-cio2: Remove traces of returned buffers
- media: netup_unidvb: Don't leak SPI master in probe error path
- media: sunxi-cir: ensure IR is handled when it is continuous
- io_uring: make ctx cancel on exit targeted to actual ctx
- io_uring: fix double io_uring free
- io_uring: fix ignoring xa_store errors
- io_uring: hold uring_lock while completing failed polled io in io_wq_submit_work()
- io_uring: fix 0-iov read buffer select
- io_uring: fix io_wqe->work_list corruption
- media: gspca: Fix memory leak in probe
- vfio/pci/nvlink2: Do not attempt NPU2 setup on POWER8NVL NPU
- vfio/pci: Move dummy_resources_list init in vfio_pci_probe()
- io_uring: always let io_iopoll_complete() complete polled io
- io_uring: fix racy IOPOLL completions
- io_uring: fix io_cqring_events()'s noflush
- proc mountinfo: make splice available again
- Smack: Handle io_uring kernel thread privileges
- io_uring: cancel reqs shouldn't kill overflow list
- io_uring: fix racy IOPOLL flush overflow
- perf probe: Fix memory leak when synthesizing SDT probes
- ARM: 9036/1: uncompress: Fix dbgadtb size parameter name
- ARM: 9044/1: vfp: use undef hook for VFP support detection
- powerpc/smp: Add __init to init_big_cores()
- powerpc/boot: Fix build of dts/fsl
- kconfig: fix return value of do_error_if()
- clk: vc5: Use "idt,voltage-microvolt" instead of "idt,voltage-microvolts"
- clk: sunxi-ng: Make sure divider tables have sentinel
- clk: s2mps11: Fix a resource leak in error handling paths in the probe function
- clk: at91: sam9x60: remove atmel,osc-bypass support
- clk: at91: sama7g5: fix compilation error
- clk: bcm: dvp: Add MODULE_DEVICE_TABLE()
- epoll: check for events when removing a timed out thread from the wait queue
- vhost scsi: fix error return code in vhost_scsi_set_endpoint()
- virtio_ring: Fix two use after free bugs
- virtio_net: Fix error code in probe()
- virtio_ring: Cut and paste bugs in vring_create_virtqueue_packed()
- vdpa/mlx5: Use write memory barrier after updating CQ index
- nfp: move indirect block cleanup to flower app stop callback
- qlcnic: Fix error code in probe
- perf record: Fix memory leak when using '--user-regs=?' to list registers
- tools build: Add missing libcap to test-all.bin target
- io_uring: cancel only requests of current task
- pwm: sun4i: Remove erroneous else branch
- pwm: imx27: Fix overflow for bigger periods
- pwm: lp3943: Dynamically allocate PWM chip base
- pwm: zx: Add missing cleanup in error path
- clk: ti: Fix memleak in ti_fapll_synth_setup
- watchdog: coh901327: add COMMON_CLK dependency
- watchdog: qcom: Avoid context switch in restart handler
- powerpc/32s: Fix cleanup_cpu_mmu_context() compile bug
- libnvdimm/label: Return -ENXIO for no slot in __blk_label_update
- devlink: use _BITUL() macro instead of BIT() in the UAPI header
- net: korina: fix return value
- NFS/pNFS: Fix a typo in ff_layout_resend_pnfs_read()
- block/rnbd-clt: Fix possible memleak
- block/rnbd-clt: Get rid of warning regarding size argument in strlcpy
- net: allwinner: Fix some resources leak in the error handling path of the probe and in the remove function
- net: mscc: ocelot: Fix a resource leak in the error handling path of the probe function
- net: bcmgenet: Fix a resource leak in an error handling path in the probe functin
- dpaa2-eth: fix the size of the mapped SGT buffer
- net: dsa: qca: ar9331: fix sleeping function called from invalid context bug
- i40e, xsk: clear the status bits for the next_to_use descriptor
- ice, xsk: clear the status bits for the next_to_use descriptor
- lan743x: fix rx_napi_poll/interrupt ping-pong
- s390/test_unwind: fix CALL_ON_STACK tests
- checkpatch: fix unescaped left brace
- proc: fix lookup in /proc/net subdirectories after setns(2)
- mm: don't wake kswapd prematurely when watermark boosting is disabled
- hugetlb: fix an error code in hugetlb_reserve_pages()
- mm,memory_failure: always pin the page in madvise_inject_error
- mm/vmalloc.c: fix kasan shadow poisoning size
- mm/vmalloc: Fix unlock order in s_stop()
- sparc: fix handling of page table constructor failure
- mm/rmap: always do TTU_IGNORE_ACCESS
- mm: memcg/slab: fix use after free in obj_cgroup_charge
- mm: memcg/slab: fix return of child memcg objcg for root memcg
- mm/gup: combine put_compound_head() and unpin_user_page()
- mm/gup: prevent gup_fast from racing with COW during fork
- mm/gup: reorganize internal_get_user_pages_fast()
- drm/amdgpu: fix regression in vbios reservation handling on headless
- perf test: Fix metric parsing test
- powerpc/ps3: use dma_mapping_error()
- powerpc/perf: Fix Threshold Event Counter Multiplier width for P10
- drm: mxsfb: Silence -EPROBE_DEFER while waiting for bridge
- nfc: s3fwrn5: Release the nfc firmware
- RDMA/cma: Don't overwrite sgid_attr after device is released
- RDMA/mlx5: Fix MR cache memory leak
- sunrpc: fix xs_read_xdr_buf for partial pages receive
- um: chan_xterm: Fix fd leak
- um: tty: Fix handling of close in tty lines
- um: Monitor error events in IRQ controller
- ubifs: Fix error return code in ubifs_init_authentication()
- watchdog: Fix potential dereferencing of null pointer
- watchdog: sprd: check busy bit before new loading rather than after that
- watchdog: sprd: remove watchdog disable from resume fail path
- watchdog: sirfsoc: Add missing dependency on HAS_IOMEM
- watchdog: armada_37xx: Add missing dependency on HAS_IOMEM
- irqchip/qcom-pdc: Fix phantom irq when changing between rising/falling
- ath11k: Fix incorrect tlvs in scan start command
- gpiolib: irq hooks: fix recursion in gpiochip_irq_unmask
- RDMA/hns: Do shift on traffic class when using RoCEv2
- RDMA/hns: Normalization the judgment of some features
- RDMA/hns: Limit the length of data copied between kernel and userspace
- dmaengine: ti: k3-udma: Correct normal channel offset when uchan_cnt is not 0
- irqchip/ti-sci-intr: Fix freeing of irqs
- irqchip/ti-sci-inta: Fix printing of inta id on probe success
- irqchip/alpine-msi: Fix freeing of interrupts on allocation error path
- ASoC: wm_adsp: remove "ctl" from list on error in wm_adsp_create_control()
- mac80211: fix a mistake check for rx_stats update
- mac80211: don't set set TDLS STA bandwidth wider than possible
- crypto: atmel-i2c - select CONFIG_BITREVERSE
- extcon: max77693: Fix modalias string
- fs: Handle I_DONTCACHE in iput_final() instead of generic_drop_inode()
- samples/bpf: Fix possible hang in xdpsock with multiple threads
- mtd: rawnand: gpmi: Fix the random DMA timeout issue
- mtd: rawnand: meson: Fix a resource leak in init
- mtd: rawnand: gpmi: fix reference count leak in gpmi ops
- clk: tegra: Fix duplicated SE clock entry
- clk: qcom: gcc-sc7180: Use floor ops for sdcc clks
- remoteproc/mediatek: unprepare clk if scp_before_load fails
- remoteproc: qcom: Fix potential NULL dereference in adsp_init_mmio()
- remoteproc: k3-dsp: Fix return value check in k3_dsp_rproc_of_get_memories()
- remoteproc: qcom: pas: fix error handling in adsp_pds_enable
- remoteproc: qcom: fix reference leak in adsp_start
- remoteproc: q6v5-mss: fix error handling in q6v5_pds_enable
- remoteproc/mtk_scp: surround DT device IDs with CONFIG_OF
- remoteproc/mediatek: change MT8192 CFG register base
- RDMA/uverbs: Fix incorrect variable type
- RDMA/core: Do not indicate device ready when device enablement fails
- ALSA: hda/hdmi: fix silent stream for first playback to DP
- slimbus: qcom: fix potential NULL dereference in qcom_slim_prg_slew()
- powerpc/sstep: Cover new VSX instructions under CONFIG_VSX
- powerpc/sstep: Emulate prefixed instructions only when CPU_FTR_ARCH_31 is set
- can: m_can: m_can_config_endisable(): remove double clearing of clock stop request bit
- clk: renesas: r8a779a0: Fix R and OSC clocks
- erofs: avoid using generic_block_bmap
- iwlwifi: mvm: hook up missing RX handlers
- iwlwifi: dbg-tlv: fix old length in is_trig_data_contained()
- s390/cio: fix use-after-free in ccw_device_destroy_console
- fsi: Aspeed: Add mutex to protect HW access
- bus: fsl-mc: fix error return code in fsl_mc_object_allocate()
- bus: fsl-mc: add back accidentally dropped error check
- misc: pci_endpoint_test: fix return value of error branch
- platform/chrome: cros_ec_spi: Don't overwrite spi::mode
- scsi: qla2xxx: Fix N2N and NVMe connect retry failure
- scsi: qla2xxx: Fix FW initialization error on big endian machines
- x86/kprobes: Restore BTF if the single-stepping is cancelled
- nfs_common: need lock during iterate through the list
- NFSD: Fix 5 seconds delay when doing inter server copy
- nfsd: Fix message level for normal termination
- speakup: fix uninitialized flush_lock
- usb: oxu210hp-hcd: Fix memory leak in oxu_create
- usb: ehci-omap: Fix PM disable depth umbalance in ehci_hcd_omap_probe
- powerpc/mm: sanity_check_fault() should work for all, not only BOOK3S
- ASoC: max98390: Fix error codes in max98390_dsm_init()
- coresight: remove broken __exit annotations
- ASoC: amd: change clk_get() to devm_clk_get() and add missed checks
- drm/mediatek: avoid dereferencing a null hdmi_phy on an error message
- powerpc/powermac: Fix low_sleep_handler with CONFIG_VMAP_STACK
- powerpc/pseries/hibernation: remove redundant cacheinfo update
- powerpc/pseries/hibernation: drop pseries_suspend_begin() from suspend ops
- ARM: 9030/1: entry: omit FP emulation for UND exceptions taken in kernel mode
- platform/x86: mlx-platform: Fix item counter assignment for MSN2700/ComEx system
- platform/x86: mlx-platform: Fix item counter assignment for MSN2700, MSN24xx systems
- scsi: fnic: Fix error return code in fnic_probe()
- seq_buf: Avoid type mismatch for seq_buf_init
- scsi: iscsi: Fix inappropriate use of put_device()
- scsi: pm80xx: Fix error return in pm8001_pci_probe()
- scsi: qedi: Fix missing destroy_workqueue() on error in __qedi_probe
- clk: fsl-sai: fix memory leak
- arm64: dts: meson: g12b: w400: fix PHY deassert timing requirements
- arm64: dts: meson: g12a: x96-max: fix PHY deassert timing requirements
- ARM: dts: meson: fix PHY deassert timing requirements
- arm64: dts: meson: fix PHY deassert timing requirements
- arm64: dts: meson: g12b: odroid-n2: fix PHY deassert timing requirements
- mtd: spi-nor: atmel: fix unlock_all() for AT25FS010/040
- mtd: spi-nor: atmel: remove global protection flag
- mtd: spi-nor: ignore errors in spi_nor_unlock_all()
- mtd: spi-nor: sst: fix BPn bits for the SST25VF064C
- adm8211: fix error return code in adm8211_probe()
- platform/x86: intel-vbtn: Fix SW_TABLET_MODE always reporting 1 on some HP x360 models
- Bluetooth: btusb: Fix detection of some fake CSR controllers with a bcdDevice val of 0x0134
- block/rnbd: fix a null pointer dereference on dev->blk_symlink_name
- block/rnbd-clt: Dynamically alloc buffer for pathname & blk_symlink_name
- Bluetooth: sco: Fix crash when using BT_SNDMTU/BT_RCVMTU option
- Bluetooth: btmtksdio: Add the missed release_firmware() in mtk_setup_firmware()
- Bluetooth: btusb: Add the missed release_firmware() in btusb_mtk_setup_firmware()
- spi: dw: Fix error return code in dw_spi_bt1_probe()
- staging: greybus: audio: Fix possible leak free widgets in gbaudio_dapm_free_controls
- staging: bcm2835: fix vchiq_mmal dependencies
- macintosh/adb-iop: Send correct poll command
- macintosh/adb-iop: Always wait for reply message from IOP
- cpufreq: imx: fix NVMEM_IMX_OCOTP dependency
- cpufreq: vexpress-spc: Add missing MODULE_ALIAS
- cpufreq: scpi: Add missing MODULE_ALIAS
- cpufreq: loongson1: Add missing MODULE_ALIAS
- cpufreq: sun50i: Add missing MODULE_DEVICE_TABLE
- cpufreq: st: Add missing MODULE_DEVICE_TABLE
- cpufreq: qcom: Add missing MODULE_DEVICE_TABLE
- cpufreq: mediatek: Add missing MODULE_DEVICE_TABLE
- cpufreq: highbank: Add missing MODULE_DEVICE_TABLE
- cpufreq: ap806: Add missing MODULE_DEVICE_TABLE
- clocksource/drivers/arm_arch_timer: Correct fault programming of CNTKCTL_EL1.EVNTI
- clocksource/drivers/arm_arch_timer: Use stable count reader in erratum sne
- drm/msm: add IOMMU_SUPPORT dependency
- drm/msm: a5xx: Make preemption reset case reentrant
- memory: jz4780_nemc: Fix potential NULL dereference in jz4780_nemc_probe()
- memory: ti-emif-sram: only build for ARMv7
- phy: renesas: rcar-gen3-usb2: disable runtime pm in case of failure
- phy: mediatek: allow compile-testing the hdmi phy
- ASoC: qcom: fix QDSP6 dependencies, attempt #3
- ASoC: atmel: mchp-spdifrx needs COMMON_CLK
- ASoC: cros_ec_codec: fix uninitialized memory read
- dm ioctl: fix error return code in target_message
- ASoC: q6afe-clocks: Add missing parent clock rate
- ASoC: jz4740-i2s: add missed checks for clk_get()
- mt76: fix tkip configuration for mt7615/7663 devices
- mt76: fix memory leak if device probing fails
- net/mlx5: Properly convey driver version to firmware
- mt76: dma: fix possible deadlock running mt76_dma_cleanup
- mt76: set fops_tx_stats.owner to THIS_MODULE
- mt76: mt7915: set fops_sta_stats.owner to THIS_MODULE
- mt76: mt7663s: fix a possible ple quota underflow
- MIPS: Don't round up kernel sections size for memblock_add()
- memstick: r592: Fix error return in r592_probe()
- arm64: dts: rockchip: Fix UART pull-ups on rk3328
- soc: rockchip: io-domain: Fix error return code in rockchip_iodomain_probe()
- pinctrl: falcon: add missing put_device() call in pinctrl_falcon_probe()
- selftests/bpf: Fix invalid use of strncat in test_sockmap
- bpf: Fix bpf_put_raw_tracepoint()'s use of __module_address()
- scripts: kernel-doc: fix parsing function-like typedefs
- ARM: dts: at91: sama5d2: map securam as device
- ARM: dts: at91: sam9x60ek: remove bypass property
- libbpf: Sanitise map names before pinning
- iio: hrtimer-trigger: Mark hrtimer to expire in hard interrupt context
- arm64: mte: fix prctl(PR_GET_TAGGED_ADDR_CTRL) if TCF0=NONE
- clocksource/drivers/riscv: Make RISCV_TIMER depends on RISCV_SBI
- clocksource/drivers/ingenic: Fix section mismatch
- clocksource/drivers/cadence_ttc: Fix memory leak in ttc_setup_clockevent()
- clocksource/drivers/orion: Add missing clk_disable_unprepare() on error path
- powerpc/perf: Fix the PMU group constraints for threshold events in power10
- powerpc/perf: Update the PMU group constraints for l2l3 events in power10
- powerpc/perf: Fix to update radix_scope_qual in power10
- powerpc/xmon: Fix build failure for 8xx
- powerpc/64: Fix an EMIT_BUG_ENTRY in head_64.S
- powerpc/perf: Fix crash with is_sier_available when pmu is not set
- media: saa7146: fix array overflow in vidioc_s_audio()
- media: tvp5150: Fix wrong return value of tvp5150_parse_dt()
- f2fs: fix double free of unicode map
- hwmon: (ina3221) Fix PM usage counter unbalance in ina3221_write_enable
- vfio-pci: Use io_remap_pfn_range() for PCI IO memory
- selftests/seccomp: Update kernel config
- NFS: switch nfsiod to be an UNBOUND workqueue.
- lockd: don't use interval-based rebinding over TCP
- net: sunrpc: Fix 'snprintf' return value check in 'do_xprt_debugfs'
- NFSv4: Fix the alignment of page data in the getdeviceinfo reply
- SUNRPC: xprt_load_transport() needs to support the netid "rdma6"
- NFSv4.2: condition READDIR's mask for security label based on LSM state
- SUNRPC: rpc_wake_up() should wake up tasks in the correct order
- ath10k: Release some resources in an error handling path
- ath10k: Fix an error handling path
- ath10k: Fix the parsing error in service available event
- ath11k: Fix an error handling path
- ath11k: Reset ath11k_skb_cb before setting new flags
- ath11k: Don't cast ath11k_skb_cb to ieee80211_tx_info.control
- media: i2c: imx219: Selection compliance fixes
- media: rdacm20: Enable GPIO1 explicitly
- media: max9271: Fix GPIO enable/disable
- ASoC: Intel: Boards: tgl_max98373: update TDM slot_width
- platform/x86: dell-smbios-base: Fix error return code in dell_smbios_init
- soundwire: master: use pm_runtime_set_active() on add
- mailbox: arm_mhu_db: Fix mhu_db_shutdown by replacing kfree with devm_kfree
- RDMA/hns: Bugfix for calculation of extended sge
- RDMA/hns: Fix 0-length sge calculation error
- ARM: dts: at91: at91sam9rl: fix ADC triggers
- spi: spi-fsl-dspi: Use max_native_cs instead of num_chipselect to set SPI_MCR
- scsi: pm80xx: Do not sleep in atomic context
- scsi: hisi_sas: Fix up probe error handling for v3 hw
- soc: amlogic: canvas: add missing put_device() call in meson_canvas_get()
- arm64: dts: meson-sm1: fix typo in opp table
- arm64: dts: meson: fix spi-max-frequency on Khadas VIM2
- PCI: iproc: Invalidate correct PAXB inbound windows
- PCI: iproc: Fix out-of-bound array accesses
- PCI: Fix overflow in command-line resource alignment requests
- PCI: Bounds-check command-line resource alignment requests
- arm64: dts: qcom: c630: Fix pinctrl pins properties
- arm64: dts: qcom: c630: Polish i2c-hid devices
- phy: tegra: xusb: Fix usb_phy device driver field
- arm64: dts: freescale: sl28: combine SPI MTD partitions
- arm64: dts: ls1028a: fix FlexSPI clock input
- arm64: dts: ls1028a: fix ENETC PTP clock input
- genirq/irqdomain: Don't try to free an interrupt that has no mapping
- power: supply: bq24190_charger: fix reference leak
- power: supply: axp288_charger: Fix HP Pavilion x2 10 DMI matching
- power: supply: max17042_battery: Fix current_{avg,now} hiding with no current sense
- arm64: dts: rockchip: Set dr_mode to "host" for OTG on rk3328-roc-cc
- power: supply: bq25890: Use the correct range for IILIM register
- arm64: dts: armada-3720-turris-mox: update ethernet-phy handle name
- ARM: dts: Remove non-existent i2c1 from 98dx3236
- HSI: omap_ssi: Don't jump to free ID in ssi_add_controller()
- drm/mediatek: Use correct aliases name for ovl
- RDMA/core: Track device memory MRs
- slimbus: qcom-ngd-ctrl: Avoid sending power requests without QMI
- media: max2175: fix max2175_set_csm_mode() error code
- mips: cdmm: fix use-after-free in mips_cdmm_bus_discover
- media: imx214: Fix stop streaming
- samples: bpf: Fix lwt_len_hist reusing previous BPF map
- serial: 8250-mtk: Fix reference leak in mtk8250_probe
- RDMA/hns: Avoid setting loopback indicator when smac is same as dmac
- RDMA/hns: Fix missing fields in address vector
- RDMA/hns: Only record vlan info for HIP08
- arm64: dts: qcom: sc7180: limit IPA iommu streams
- platform/x86: mlx-platform: Remove PSU EEPROM from MSN274x platform configuration
- platform/x86: mlx-platform: Remove PSU EEPROM from default platform configuration
- media: siano: fix memory leak of debugfs members in smsdvb_hotplug
- drm/imx/dcss: fix rotations for Vivante tiled formats
- soundwire: qcom: Fix build failure when slimbus is module
- RDMA/cma: Fix deadlock on &lock in rdma_cma_listen_on_all() error unwind
- arm64: tegra: Fix DT binding for IO High Voltage entry
- leds: turris-omnia: check for LED_COLOR_ID_RGB instead LED_COLOR_ID_MULTI
- leds: lp50xx: Fix an error handling path in 'lp50xx_probe_dt()'
- leds: netxbig: add missing put_device() call in netxbig_leds_get_of_pdata()
- arm64: dts: qcom: sdm845: Limit ipa iommu streams
- dmaengine: mv_xor_v2: Fix error return code in mv_xor_v2_probe()
- cw1200: fix missing destroy_workqueue() on error in cw1200_init_common
- rsi: fix error return code in rsi_reset_card()
- qtnfmac: fix error return code in qtnf_pcie_probe()
- orinoco: Move context allocation after processing the skb
- brcmfmac: fix error return code in brcmf_cfg80211_connect()
- mmc: pxamci: Fix error return code in pxamci_probe
- ARM: dts: at91: sama5d3_xplained: add pincontrol for USB Host
- ARM: dts: at91: sama5d4_xplained: add pincontrol for USB Host
- ARM: dts: at91: sam9x60: add pincontrol for USB Host
- memstick: fix a double-free bug in memstick_check
- pinctrl: sunxi: fix irq bank map for the Allwinner A100 pin controller
- soundwire: Fix DEBUG_LOCKS_WARN_ON for uninitialized attribute
- RDMA/cxgb4: Validate the number of CQEs
- ath11k: Fix the rx_filter flag setting for peer rssi stats
- staging: mfd: hi6421-spmi-pmic: fix error return code in hi6421_spmi_pmic_probe()
- clk: meson: Kconfig: fix dependency for G12A
- Input: omap4-keypad - fix runtime PM error handling
- arm64: dts: qcom: msm8916-samsung-a2015: Disable muic i2c pin bias
- arm64: dts: qcom: sm8250: correct compatible for sm8250-mtp
- soc: qcom: initialize local variable
- drivers: soc: ti: knav_qmss_queue: Fix error return code in knav_queue_probe
- soc: ti: Fix reference imbalance in knav_dma_probe
- soc: ti: knav_qmss: fix reference leak in knav_queue_probe
- PCI: brcmstb: Initialize "tmp" before use
- PCI: Disable MSI for Pericom PCIe-USB adapter
- drm/meson: dw-hdmi: Enable the iahb clock early enough
- drm/meson: dw-hdmi: Disable clocks on driver teardown
- spi: fix resource leak for drivers without .remove callback
- crypto: sun8i-ce - fix two error path's memory leak
- crypto: omap-aes - Fix PM disable depth imbalance in omap_aes_probe
- crypto: crypto4xx - Replace bitwise OR with logical OR in crypto4xx_build_pd
- rcu/tree: Defer kvfree_rcu() allocation to a clean context
- rcu,ftrace: Fix ftrace recursion
- rcu: Allow rcu_irq_enter_check_tick() from NMI
- scsi: ufs: Fix clkgating on/off
- scsi: ufs: Avoid to call REQ_CLKS_OFF to CLKS_OFF
- EDAC/mce_amd: Use struct cpuinfo_x86.cpu_die_id for AMD NodeId
- mfd: cpcap: Fix interrupt regression with regmap clear_ack
- mfd: stmfx: Fix dev_err_probe() call in stmfx_chip_init()
- mfd: MFD_SL28CPLD should depend on ARCH_LAYERSCAPE
- mfd: htc-i2cpld: Add the missed i2c_put_adapter() in htcpld_register_chip_i2c()
- powerpc/powernv/sriov: fix unsigned int win compared to less than zero
- Revert "powerpc/pseries/hotplug-cpu: Remove double free in error path"
- ARM: dts: tacoma: Fix node vs reg mismatch for flash memory
- powerpc/feature: Fix CPU_FTRS_ALWAYS by removing CPU_FTRS_GENERIC_32
- powerpc: Avoid broken GCC __attribute__((optimize))
- selftests/bpf: Fix broken riscv build
- spi: mxs: fix reference leak in mxs_spi_probe
- usb/max3421: fix return error code in max3421_probe()
- bus: mhi: core: Fix null pointer access when parsing MHI configuration
- bus: mhi: core: Remove double locking from mhi_driver_remove()
- Input: ads7846 - fix unaligned access on 7845
- Input: ads7846 - fix integer overflow on Rt calculation
- Input: ads7846 - fix race that causes missing releases
- iommu/vt-d: include conditionally on CONFIG_INTEL_IOMMU_SVM
- ASoC: intel: SND_SOC_INTEL_KEEMBAY should depend on ARCH_KEEMBAY
- drm/meson: dw-hdmi: Ensure that clocks are enabled before touching the TOP registers
- drm/meson: dw-hdmi: Register a callback to disable the regulator
- drm/meson: Unbind all connectors on module removal
- drm/meson: Free RDMA resources after tearing down DRM
- drm/omap: dmm_tiler: fix return error code in omap_dmm_probe()
- mmc: sdhci: tegra: fix wrong unit with busy_timeout
- video: fbdev: atmel_lcdfb: fix return error code in atmel_lcdfb_of_init()
- media: solo6x10: fix missing snd_card_free in error handling case
- media: venus: put dummy vote on video-mem path after last session release
- scsi: core: Fix VPD LUN ID designator priorities
- spi: dw: fix build error by selecting MULTIPLEXER
- ASoC: meson: fix COMPILE_TEST error
- RDMA/cma: Add missing error handling of listen_id
- media: venus: core: vote with average bandwidth and peak bandwidth as zero
- media: venus: core: vote for video-mem path
- media: venus: core: change clk enable and disable order in resume and suspend
- media: platform: add missing put_device() call in mtk_jpeg_probe() and mtk_jpeg_remove()
- media: cedrus: fix reference leak in cedrus_start_streaming
- media: staging: rkisp1: cap: fix runtime PM imbalance on error
- media: ov5640: fix support of BT656 bus mode
- media: v4l2-fwnode: v4l2_fwnode_endpoint_parse caller must init vep argument
- media: v4l2-fwnode: Return -EINVAL for invalid bus-type
- media: mtk-vcodec: add missing put_device() call in mtk_vcodec_init_enc_pm()
- media: mtk-vcodec: add missing put_device() call in mtk_vcodec_release_dec_pm()
- media: mtk-vcodec: add missing put_device() call in mtk_vcodec_init_dec_pm()
- media: platform: add missing put_device() call in mtk_jpeg_clk_init()
- media: tm6000: Fix sizeof() mismatches
- ionic: change set_rx_mode from_ndo to can_sleep
- ionic: flatten calls to ionic_lif_rx_mode
- ionic: use mc sync for multicast filters
- drm/amdkfd: Put ACPI table after using it
- scripts: kernel-doc: Restore anonymous enum parsing
- staging: gasket: interrupt: fix the missed eventfd_ctx_put() in gasket_interrupt.c
- staging: greybus: codecs: Fix reference counter leak in error handling
- drm/udl: Fix missing error code in udl_handle_damage()
- firmware: arm_scmi: Fix missing destroy_workqueue()
- crypto: qat - fix status check in qat_hal_put_rel_rd_xfer()
- crypto: Kconfig - CRYPTO_MANAGER_EXTRA_TESTS requires the manager
- soc: ti: omap-prm: Do not check rstst bit on deassert if already deasserted
- drm/amdgpu: fix compute queue priority if num_kcq is less than 4
- MIPS: BCM47XX: fix kconfig dependency bug for BCM47XX_BCMA
- arm64: dts: ti: k3-am65*/j721e*: Fix unit address format error for dss node
- ASoC: SOF: Intel: fix Kconfig dependency for SND_INTEL_DSP_CONFIG
- RDMa/mthca: Work around -Wenum-conversion warning
- ASoC: arizona: Fix a wrong free in wm8997_probe
- virtiofs fix leak in setup
- spi: sprd: fix reference leak in sprd_spi_remove
- ASoC: wm8998: Fix PM disable depth imbalance on error
- ASoC: wm8994: Fix PM disable depth imbalance on error
- selftest/bpf: Add missed ip6ip6 test back
- selftests/run_kselftest.sh: fix dry-run typo
- drm/msm/dp: do not notify audio subsystem if sink doesn't support audio
- drm/msm/dp: skip checking LINK_STATUS_UPDATED bit
- drm/msm/dp: return correct connection status after suspend
- firmware: tegra: fix strncpy()/strncat() confusion
- drm/msm/a5xx: Clear shadow on suspend
- drm/msm/a6xx: Clear shadow on suspend
- mwifiex: fix mwifiex_shutdown_sw() causing sw reset failure
- ath11k: Handle errors if peer creation fails
- ASoC: qcom: common: Fix refcounting in qcom_snd_parse_of()
- spi: imx: fix reference leak in two imx operations
- spi: bcm63xx-hsspi: fix missing clk_disable_unprepare() on error in bcm63xx_hsspi_resume
- spi: tegra114: fix reference leak in tegra spi ops
- spi: tegra20-sflash: fix reference leak in tegra_sflash_resume
- spi: tegra20-slink: fix reference leak in slink ops of tegra20
- spi: mt7621: fix missing clk_disable_unprepare() on error in mt7621_spi_probe
- spi: spi-ti-qspi: fix reference leak in ti_qspi_setup
- spi: stm32-qspi: fix reference leak in stm32 qspi operations
- Bluetooth: hci_h5: fix memory leak in h5_close
- Bluetooth: Fix: LL PRivacy BLE device fails to connect
- Bluetooth: Fix null pointer dereference in hci_event_packet()
- drm/panel: simple: Add flags to boe_nv133fhm_n61
- arm64: dts: exynos: Correct psci compatible used on Exynos7
- arm64: dts: exynos: Include common syscon restart/poweroff for Exynos7
- brcmfmac: Fix memory leak for unpaired brcmf_{alloc/free}
- ath11k: fix wmi init configuration
- ath11k: Fix number of rules in filtered ETSI regdomain
- ath11k: Initialize complete alpha2 for regulatory change
- drm/edid: Fix uninitialized variable in drm_cvt_modes()
- x86/mce: Correct the detection of invalid notifier priorities
- bpf: Fix tests for local_storage
- spi: stm32: fix reference leak in stm32_spi_resume
- nl80211/cfg80211: fix potential infinite loop
- selinux: fix inode_doinit_with_dentry() LABEL_INVALID error handling
- crypto: caam - fix printing on xts fallback allocation error path
- crypto: arm/aes-neonbs - fix usage of cbc(aes) fallback
- crypto: arm64/poly1305-neon - reorder PAC authentication with SP update
- drm/bridge: tpd12s015: Fix irq registering in tpd12s015_probe
- ASoC: pcm: DRAIN support reactivation
- pinctrl: core: Add missing #ifdef CONFIG_GPIOLIB
- scsi: aacraid: Improve compat_ioctl handlers
- spi: spi-mem: fix reference leak in spi_mem_access_start
- drm/msm/dpu: fix clock scaling on non-sc7180 board
- drm/msm/dsi_pll_10nm: restore VCO rate during restore_state
- drm/msm/dsi_pll_7nm: restore VCO rate during restore_state
- drm/msm/dp: DisplayPort PHY compliance tests fixup
- perf test: Use generic event for expand_libpfm_events()
- RDMA/mlx5: Fix corruption of reg_pages in mlx5_ib_rereg_user_mr()
- f2fs: call f2fs_get_meta_page_retry for nat page
- spi: img-spfi: fix reference leak in img_spfi_resume
- powerpc/64: Set up a kernel stack for secondaries before cpu_restore()
- drm/amdgpu: fix build_coefficients() argument
- ARM: dts: aspeed: tiogapass: Remove vuart
- drm/msm: Add missing stub definition
- ASoC: sun4i-i2s: Fix lrck_period computation for I2S justified mode
- crypto: inside-secure - Fix sizeof() mismatch
- crypto: talitos - Fix return type of current_desc_hdr()
- crypto: talitos - Endianess in current_desc_hdr()
- drm/amdgpu: fix incorrect enum type
- sched: Reenable interrupts in do_sched_yield()
- sched/deadline: Fix sched_dl_global_validate()
- ASoC: qcom: fix unsigned int bitwidth compared to less than zero
- x86/apic: Fix x2apic enablement without interrupt remapping
- RDMA/rtrs-srv: Don't guard the whole __alloc_srv with srv_mutex
- RDMA/rtrs-clt: Missing error from rtrs_rdma_conn_established
- RDMA/rtrs-clt: Remove destroy_con_cq_qp in case route resolving failed
- ARM: p2v: fix handling of LPAE translation in BE mode
- x86/mm/ident_map: Check for errors from ident_pud_init()
- RDMA/rxe: Compute PSN windows correctly
- RDMA/core: Fix error return in _ib_modify_qp()
- ARM: dts: aspeed: s2600wf: Fix VGA memory region location
- ARM: dts: aspeed-g6: Fix the GPIO memory size
- selinux: fix error initialization in inode_doinit_with_dentry()
- RDMA/bnxt_re: Fix entry size during SRQ create
- rtc: pcf2127: fix pcf2127_nvmem_read/write() returns
- RDMA/bnxt_re: Set queue pair state when being queried
- Revert "i2c: i2c-qcom-geni: Fix DMA transfer race"
- soc: qcom: geni: More properly switch to DMA mode
- arm64: dts: qcom: sc7180: Fix one forgotten interconnect reference
- arm64: dts: ipq6018: update the reserved-memory node
- arm64: dts: mediatek: mt8183: fix gce incorrect mbox-cells value
- soc: mediatek: Check if power domains can be powered on at boot time
- soc: renesas: rmobile-sysc: Fix some leaks in rmobile_init_pm_domains()
- arm64: dts: renesas: cat875: Remove rxc-skew-ps from ethernet-phy node
- arm64: dts: renesas: hihope-rzg2-ex: Drop rxc-skew-ps from ethernet-phy node
- drm/tve200: Fix handling of platform_get_irq() error
- drm/mcde: Fix handling of platform_get_irq() error
- drm/aspeed: Fix Kconfig warning & subsequent build errors
- iio: adc: at91_adc: add Kconfig dep on the OF symbol and remove of_match_ptr()
- drm/gma500: fix double free of gma_connector
- hwmon: (k10temp) Remove support for displaying voltage and current on Zen CPUs
- md: fix a warning caused by a race between concurrent md_ioctl()s
- nl80211: validate key indexes for cfg80211_registered_device
- crypto: af_alg - avoid undefined behavior accessing salg_name
- media: msi2500: assign SPI bus number dynamically
- fs: quota: fix array-index-out-of-bounds bug by passing correct argument to vfs_cleanup_quota_inode()
- quota: Sanity-check quota file headers on load
- Bluetooth: Fix slab-out-of-bounds read in hci_le_direct_adv_report_evt()
- f2fs: prevent creating duplicate encrypted filenames
- ext4: prevent creating duplicate encrypted filenames
- ubifs: prevent creating duplicate encrypted filenames
- fscrypt: add fscrypt_is_nokey_name()
- fscrypt: remove kernel-internal constants from UAPI header
- serial_core: Check for port state when tty is in error state
- HID: i2c-hid: add Vero K147 to descriptor override
- scsi: megaraid_sas: Check user-provided offsets
- f2fs: init dirty_secmap incorrectly
- f2fs: fix to seek incorrect data offset in inline data file
- coresight: etm4x: Handle TRCVIPCSSCTLR accesses
- coresight: etm4x: Fix accesses to TRCPROCSELR
- coresight: etm4x: Fix accesses to TRCCIDCTLR1
- coresight: etm4x: Fix accesses to TRCVMIDCTLR1
- coresight: etm4x: Skip setting LPOVERRIDE bit for qcom, skip-power-up
- coresight: etb10: Fix possible NULL ptr dereference in etb_enable_perf()
- coresight: tmc-etr: Fix barrier packet insertion for perf buffer
- coresight: tmc-etr: Check if page is valid before dma_map_page()
- coresight: tmc-etf: Fix NULL ptr dereference in tmc_enable_etf_sink_perf()
- ARM: dts: exynos: fix USB 3.0 pins supply being turned off on Odroid XU
- ARM: dts: exynos: fix USB 3.0 VBUS control and over-current pins on Exynos5410
- ARM: dts: exynos: fix roles of USB 3.0 ports on Odroid XU
- usb: chipidea: ci_hdrc_imx: Pass DISABLE_DEVICE_STREAMING flag to imx6ul
- USB: gadget: f_rndis: fix bitrate for SuperSpeed and above
- usb: gadget: f_fs: Re-use SS descriptors for SuperSpeedPlus
- USB: gadget: f_midi: setup SuperSpeed Plus descriptors
- USB: gadget: f_acm: add support for SuperSpeed Plus
- USB: serial: option: add interface-number sanity check to flag handling
- usb: mtu3: fix memory corruption in mtu3_debugfs_regset()
- soc/tegra: fuse: Fix index bug in get_process_id
- exfat: Avoid allocating upcase table using kcalloc()
- x86/split-lock: Avoid returning with interrupts enabled
- net: ipconfig: Avoid spurious blank lines in boot log
- serial: 8250_omap: Avoid FIFO corruption caused by MDR1 access
- ALSA: pcm: oss: Fix potential out-of-bounds shift
- USB: sisusbvga: Make console support depend on BROKEN
- USB: UAS: introduce a quirk to set no_write_same
- xhci-pci: Allow host runtime PM as default for Intel Maple Ridge xHCI
- xhci-pci: Allow host runtime PM as default for Intel Alpine Ridge LP
- usb: xhci: Set quirk for XHCI_SG_TRB_CACHE_SIZE_QUIRK
- xhci: Give USB2 ports time to enter U3 in bus suspend
- ALSA: usb-audio: Fix control 'access overflow' errors from chmap
- ALSA: usb-audio: Fix potential out-of-bounds shift
- USB: add RESET_RESUME quirk for Snapscan 1212
- USB: dummy-hcd: Fix uninitialized array use in init()
- USB: legotower: fix logical error in recent commit
- ktest.pl: Fix the logic for truncating the size of the log file for email
- ktest.pl: If size of log is too big to email, email error message
- ptrace: Prevent kernel-infoleak in ptrace_get_syscall_info()
- arm64: cache: Export and add cache invalidation and clean ABIs for module use
- arm64: cache: Add flush_dcache_area() for module use
- security: restrict init parameters by configuration
- PCI: Add MCFG quirks for some Hisilicon Chip host controllers
- fs/dirty_pages: remove set but not used variable 'm'
- fs/dirty_pages: fix kernel panic in concurrency mode
- fs/dirty_pages: Adjust position of some code to improve the code
- fs/dirty_pages: fix wrong 'buff_num' after invalid input
- fs/dirty_pages: fix index out of bounds and integer overflow
- fs/dirty_pages: dump the number of dirty pages for each inode
- mm, page_alloc: avoid page_to_pfn() in move_freepages()
- dt-bindings/irqchip/mbigen: add example of MBIGEN generate SPIs
- irqchip/mbigen: add support for a MBIGEN generating SPIs
- irqchip/mbigen: rename register marcros
- ilp32: skip ARM erratum 1418040 for ilp32 application
- ilp32: avoid clearing upper 32 bits of syscall return value for ilp32
- arm64: secomp: fix the secure computing mode 1 syscall check for ilp32
- arm64:ilp32: add ARM64_ILP32 to Kconfig
- arm64:ilp32: add vdso-ilp32 and use for signal return
- arm64: ptrace: handle ptrace_request differently for aarch32 and ilp32
- arm64: ilp32: introduce ilp32-specific sigframe and ucontext
- arm64: signal32: move ilp32 and aarch32 common code to separated file
- arm64: signal: share lp64 signal structures and routines to ilp32
- arm64: ilp32: introduce syscall table for ILP32
- arm64: ilp32: share aarch32 syscall handlers
- arm64: ilp32: introduce binfmt_ilp32.c
- arm64: change compat_elf_hwcap and compat_elf_hwcap2 prefix to a32
- arm64: introduce binfmt_elf32.c
- arm64: introduce AUDIT_ARCH_AARCH64ILP32 for ilp32
- arm64: ilp32: add is_ilp32_compat_{task,thread} and TIF_32BIT_AARCH64
- arm64: introduce is_a32_compat_{task,thread} for AArch32 compat
- arm64: uapi: set __BITS_PER_LONG correctly for ILP32 and LP64
- arm64: rename functions that reference compat term
- arm64: rename COMPAT to AARCH32_EL0
- arm64: ilp32: add documentation on the ILP32 ABI for ARM64
- thread: move thread bits accessors to separated file
- ptrace: Add compat PTRACE_{G,S}ETSIGMASK handlers
- arm64: signal: Make parse_user_sigframe() independent of rt_sigframe layout
- ARM: mm: non-LPAE systems HugeTLB support for hulk
- Revert "dm raid: fix discard limits for raid1 and raid10"
- Revert "md: change mddev 'chunk_sectors' from int to unsigned"

* Wed Dec 16 2020 Xie XiuQi <xiexiuqi@huawei.com> - 5.10.0-0.0.0.7
- rebase on top of v5.10

* Wed Dec 09 2020 Xie XiuQi <xiexiuqi@huawei.com> - 5.10.0-rc7.0.0.6
- rebase on top of v5.10-rc7

* Tue Nov 17 2020 Xie XiuQi <xiexiuqi@huawei.com> - 5.10.0-rc4.0.0.5
- rebase on top of v5.10-rc4
- kernel.spec: privode config files in src package

* Mon Nov 09 2020 Xie XiuQi <xiexiuqi@huawei.com> - 5.10.0-rc3.0.0.4
- use rcX for v5.10-rcX source release
- rebase on top of v5.10-rc3
- kernel.spec: add missing debuginfodir

* Mon Nov 02 2020 Xie XiuQi <xiexiuqi@huawei.com> - 5.10.0-rc2.0.0.3
- rebase on top of v5.10-rc2
- provide /boot/symvers-kernelver.gz even no kabichk
- fix warning on uninstall kernel rpm

* Sat Oct 31 2020 Xie XiuQi <xiexiuqi@huawei.com> - 5.10.0-rc1.0.0.2
- enable access to .config through /proc/config.gz

* Tue Oct 27 2020 Xie XiuQi <xiexiuqi@huawei.com> - 5.10.0-rc1.0.0.1
- package init based on upstream v5.10-rc1
