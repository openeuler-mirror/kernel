%define with_signmodules  1
%define with_kabichk 0

%define modsign_cmd %{SOURCE10}

%global Arch $(echo %{_host_cpu} | sed -e s/i.86/x86/ -e s/x86_64/x86/ -e s/aarch64.*/arm64/)

%global KernelVer %{version}-%{release}.%{_target_cpu}
%global debuginfodir /usr/lib/debug

%global upstream_version    5.10
%global upstream_sublevel   0
%global devel_release       5
%global maintenance_release .0.0
%global pkg_release         .14

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
BuildRequires: perl-generators perl(Carp) libunwind-devel gtk2-devel libbabeltrace-devel java-1.8.0-openjdk perl-devel
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
* Wed Jul 7 2021 Zheng Zengkai <zhengzengkai@huawei.com> - 5.10.0-5.0.0.14
- arm64: errata: enable HISILICON_ERRATUM_HIP08_RU_PREFETCH
- arm64: errata: add option to disable cache readunique prefetch on HIP08
- config: disable config ARM64_BOOTPARAM_HOTPLUG_CPU0 by default
- arm64: Add config switch and kernel parameter for CPU0 hotplug
- iommu/vt-d: Check for allocation failure in aux_detach_device()
- iommu/vt-d: Fix ineffective devTLB invalidation for subdevices
- iommu/vt-d: Fix general protection fault in aux_detach_device()
- NFSv4: Refactor to use user namespaces for nfs4idmap
- NFS: NFSv2/NFSv3: Use cred from fs_context during mount
- seccomp: Remove bogus __user annotations
- seccomp/cache: Report cache data through /proc/pid/seccomp_cache
- xtensa: Enable seccomp architecture tracking
- sh: Enable seccomp architecture tracking
- s390: Enable seccomp architecture tracking
- riscv: Enable seccomp architecture tracking
- powerpc: Enable seccomp architecture tracking
- parisc: Enable seccomp architecture tracking
- csky: Enable seccomp architecture tracking
- arm: Enable seccomp architecture tracking
- arm64: Enable seccomp architecture tracking
- selftests/seccomp: Compare bitmap vs filter overhead
- x86: Enable seccomp architecture tracking
- seccomp/cache: Add "emulator" to check if filter is constant allow
- seccomp/cache: Lookup syscall allowlist bitmap for fast path
- usb: dwc3: core: fix kernel panic when do reboot
- usb: dwc3: debugfs: Add and remove endpoint dirs dynamically
- perf beauty: Update copy of linux/socket.h with the kernel sources
- tools headers UAPI: Sync linux/in.h copy with the kernel sources
- net: fec_ptp: add clock rate zero check
- net: stmmac: disable clocks in stmmac_remove_config_dt()
- mm/slub.c: include swab.h
- mm/slub: actually fix freelist pointer vs redzoning
- mm/slub: fix redzoning for small allocations
- mm/slub: clarify verification reporting
- mm/swap: fix pte_same_as_swp() not removing uffd-wp bit when compare
- net: bridge: fix vlan tunnel dst refcnt when egressing
- net: bridge: fix vlan tunnel dst null pointer dereference
- net: ll_temac: Fix TX BD buffer overwrite
- net: ll_temac: Make sure to free skb when it is completely used
- drm/amdgpu/gfx9: fix the doorbell missing when in CGPG issue.
- drm/amdgpu/gfx10: enlarge CP_MEC_DOORBELL_RANGE_UPPER to cover full doorbell.
- cfg80211: avoid double free of PMSR request
- cfg80211: make certificate generation more robust
- mac80211: Fix NULL ptr deref for injected rate info
- dmaengine: pl330: fix wrong usage of spinlock flags in dma_cyclc
- crash_core, vmcoreinfo: append 'SECTION_SIZE_BITS' to vmcoreinfo
- x86/fpu: Reset state for all signal restore failures
- x86/fpu: Invalidate FPU state after a failed XRSTOR from a user buffer
- x86/fpu: Prevent state corruption in __fpu__restore_sig()
- x86/pkru: Write hardware init value to PKRU when xstate is init
- x86/ioremap: Map EFI-reserved memory as encrypted for SEV
- x86/process: Check PF_KTHREAD and not current->mm for kernel threads
- x86/mm: Avoid truncating memblocks for SGX memory
- ARCv2: save ABI registers across signal handling
- s390/ap: Fix hanging ioctl caused by wrong msg counter
- s390/mcck: fix calculation of SIE critical section size
- KVM: X86: Fix x86_emulator slab cache leak
- KVM: x86/mmu: Calculate and check "full" mmu_role for nested MMU
- KVM: x86: Immediately reset the MMU context when the SMM flag is cleared
- PCI: Work around Huawei Intelligent NIC VF FLR erratum
- PCI: Add ACS quirk for Broadcom BCM57414 NIC
- PCI: aardvark: Fix kernel panic during PIO transfer
- PCI: Mark some NVIDIA GPUs to avoid bus reset
- PCI: Mark TI C667X to avoid bus reset
- tracing: Do no increment trace_clock_global() by one
- tracing: Do not stop recording comms if the trace file is being read
- tracing: Do not stop recording cmdlines when tracing is off
- usb: chipidea: imx: Fix Battery Charger 1.2 CDP detection
- usb: core: hub: Disable autosuspend for Cypress CY7C65632
- can: mcba_usb: fix memory leak in mcba_usb
- can: j1939: fix Use-after-Free, hold skb ref while in use
- can: bcm/raw/isotp: use per module netdevice notifier
- can: bcm: fix infoleak in struct bcm_msg_head
- bpf: Do not mark insn as seen under speculative path verification
- bpf: Inherit expanded/patched seen count from old aux data
- irqchip/gic-v3: Workaround inconsistent PMR setting on NMI entry
- mm: relocate 'write_protect_seq' in struct mm_struct
- hwmon: (scpi-hwmon) shows the negative temperature properly
- radeon: use memcpy_to/fromio for UVD fw upload
- ASoC: qcom: lpass-cpu: Fix pop noise during audio capture begin
- drm/sun4i: dw-hdmi: Make HDMI PHY into a platform device
- pinctrl: ralink: rt2880: avoid to error in calls is pin is already enabled
- ASoC: rt5682: Fix the fast discharge for headset unplugging in soundwire mode
- regulator: rt4801: Fix NULL pointer dereference if priv->enable_gpios is NULL
- spi: stm32-qspi: Always wait BUSY bit to be cleared in stm32_qspi_wait_cmd()
- ASoC: tas2562: Fix TDM_CFG0_SAMPRATE values
- sched/pelt: Ensure that *_sum is always synced with *_avg
- spi: spi-zynq-qspi: Fix some wrong goto jumps & missing error code
- regulator: rtmv20: Fix to make regcache value first reading back from HW
- ASoC: fsl-asoc-card: Set .owner attribute when registering card.
- phy: phy-mtk-tphy: Fix some resource leaks in mtk_phy_init()
- ASoC: rt5659: Fix the lost powers for the HDA header
- platform/x86: thinkpad_acpi: Add X1 Carbon Gen 9 second fan support
- regulator: bd70528: Fix off-by-one for buck123 .n_voltages setting
- regulator: cros-ec: Fix error code in dev_err message
- net: ethernet: fix potential use-after-free in ec_bhf_remove
- icmp: don't send out ICMP messages with a source address of 0.0.0.0
- bnxt_en: Call bnxt_ethtool_free() in bnxt_init_one() error path
- bnxt_en: Fix TQM fastpath ring backing store computation
- bnxt_en: Rediscover PHY capabilities after firmware reset
- cxgb4: fix wrong shift.
- net: cdc_eem: fix tx fixup skb leak
- net: hamradio: fix memory leak in mkiss_close
- be2net: Fix an error handling path in 'be_probe()'
- net/mlx5: Reset mkey index on creation
- net/mlx5: E-Switch, Allow setting GUID for host PF vport
- net/mlx5: E-Switch, Read PF mac address
- net/af_unix: fix a data-race in unix_dgram_sendmsg / unix_release_sock
- net: ipv4: fix memory leak in ip_mc_add1_src
- net: fec_ptp: fix issue caused by refactor the fec_devtype
- net: usb: fix possible use-after-free in smsc75xx_bind
- lantiq: net: fix duplicated skb in rx descriptor ring
- net: cdc_ncm: switch to eth%d interface naming
- ptp: improve max_adj check against unreasonable values
- bpf: Fix leakage under speculation on mispredicted branches
- net: qrtr: fix OOB Read in qrtr_endpoint_post
- ipv4: Fix device used for dst_alloc with local routes
- cxgb4: fix wrong ethtool n-tuple rule lookup
- netxen_nic: Fix an error handling path in 'netxen_nic_probe()'
- qlcnic: Fix an error handling path in 'qlcnic_probe()'
- ethtool: strset: fix message length calculation
- net: qualcomm: rmnet: don't over-count statistics
- net: qualcomm: rmnet: Update rmnet device MTU based on real device
- net: make get_net_ns return error if NET_NS is disabled
- net: stmmac: dwmac1000: Fix extended MAC address registers definition
- cxgb4: halt chip before flashing PHY firmware image
- cxgb4: fix sleep in atomic when flashing PHY firmware
- cxgb4: fix endianness when flashing boot image
- alx: Fix an error handling path in 'alx_probe()'
- selftests: mptcp: enable syncookie only in absence of reorders
- mptcp: do not warn on bad input from the network
- mptcp: try harder to borrow memory from subflow under pressure
- sch_cake: Fix out of bounds when parsing TCP options and header
- mptcp: Fix out of bounds when parsing TCP options
- netfilter: synproxy: Fix out of bounds when parsing TCP options
- net/mlx5e: Block offload of outer header csum for UDP tunnels
- net/mlx5: DR, Don't use SW steering when RoCE is not supported
- net/mlx5: DR, Allow SW steering for sw_owner_v2 devices
- net/mlx5: Consider RoCE cap before init RDMA resources
- net/mlx5e: Fix page reclaim for dead peer hairpin
- net/mlx5e: Remove dependency in IPsec initialization flows
- net/sched: act_ct: handle DNAT tuple collision
- rtnetlink: Fix regression in bridge VLAN configuration
- udp: fix race between close() and udp_abort()
- ice: parameterize functions responsible for Tx ring management
- ice: add ndo_bpf callback for safe mode netdev ops
- netfilter: nft_fib_ipv6: skip ipv6 packets from any to link-local
- net: lantiq: disable interrupt before sheduling NAPI
- net: dsa: felix: re-enable TX flow control in ocelot_port_flush()
- net: rds: fix memory leak in rds_recvmsg
- vrf: fix maximum MTU
- net: ipv4: fix memory leak in netlbl_cipsov4_add_std
- libbpf: Fixes incorrect rx_ring_setup_done
- mlxsw: core: Set thermal zone polling delay argument to real value at init
- mlxsw: reg: Spectrum-3: Enforce lowest max-shaper burst size of 11
- mac80211: fix skb length check in ieee80211_scan_rx()
- batman-adv: Avoid WARN_ON timing related checks
- kvm: LAPIC: Restore guard to prevent illegal APIC register access
- afs: Fix an IS_ERR() vs NULL check
- dmaengine: stedma40: add missing iounmap() on error in d40_probe()
- dmaengine: SF_PDMA depends on HAS_IOMEM
- dmaengine: QCOM_HIDMA_MGMT depends on HAS_IOMEM
- dmaengine: ALTERA_MSGDMA depends on HAS_IOMEM
- dmaengine: xilinx: dpdma: initialize registers before request_irq
- dmaengine: fsl-dpaa2-qdma: Fix error return code in two functions
- dmaengine: idxd: add missing dsa driver unregister
- ext4: fix memory leak in ext4_fill_super
- Revert "Revert "scsi: megaraid_sas: Added support for shared host tagset for cpuhotplug""
- Revert "block: Fix a lockdep complaint triggered by request queue flushing"
- nvme-loop: use blk_mq_hctx_set_fq_lock_class to set loop's lock class
- blk-mq: add new API of blk_mq_hctx_set_fq_lock_class
- block: check disk exist before trying to add partition
- block: avoid creating invalid symlink file for patitions
- block: take bd_mutex around delete_partitions in del_gendisk
- scsi: remove unused kobj map for sd devie to avoid memleak
- scsi: libsas: Add LUN number check in .slave_alloc callback
- dm btree remove: assign new_root only when removal succeeds
- scsi: libiscsi: Reset max/exp cmdsn during recovery
- scsi: iscsi_tcp: Fix shost can_queue initialization
- scsi: libiscsi: Add helper to calculate max SCSI cmds per session
- scsi: libiscsi: Fix iSCSI host workq destruction
- scsi: libiscsi: Fix iscsi_task use after free()
- scsi: libiscsi: Drop taskqueuelock
- ext4: stop return ENOSPC from ext4_issue_zeroout
- scsi: sd: Call sd_revalidate_disk() for ioctl(BLKRRPART)
- powerpc/fsl_booke/kaslr: rename kaslr-booke32.rst to kaslr-booke.rst and add 64bit part
- powerpc/fsl_booke/64: clear the original kernel if randomized
- powerpc/fsl_booke/64: do not clear the BSS for the second pass
- powerpc/fsl_booke/64: implement KASLR for fsl_booke64
- powerpc/fsl_booke/64: introduce reloc_kernel_entry() helper
- powerpc/fsl_booke/kaslr: refactor kaslr_legal_offset() and kaslr_early_init()
- arm64: Force NO_BLOCK_MAPPINGS if crashkernel reservation is required
- exec: Move unshare_files to fix posix file locking during exec
- exec: Don't open code get_close_on_exec
- ARM: mm: Fix PXN process with LPAE feature
- ARM: mm: Provide die_kernel_fault() helper
- ARM: mm: Kill page table base print in show_pte()
- ARM: mm: Cleanup access_error()
- ARM: mm: Kill task_struct argument for __do_page_fault()
- ARM: mm: Rafactor the __do_page_fault()
- fanotify: fix copy_event_to_user() fid error clean up
- block: fix inflight statistics of part0
- debugfs: fix security_locked_down() call for SELinux
- vti6: fix ipv4 pmtu check to honor ip header df
- vti: fix ipv4 pmtu check to honor ip header df
- alinux: random: speed up the initialization of module
- mm: set the sleep_mapped to true for zbud and z3fold
- mm/zswap: add the flag can_sleep_mapped
- kasan: fix null pointer dereference in kasan_record_aux_stack
- bpf: Fix NULL pointer dereference in bpf_get_local_storage() helper
- fib: Return the correct errno code
- net: Return the correct errno code
- net/x25: Return the correct errno code
- rtnetlink: Fix missing error code in rtnl_bridge_notify()
- drm/amd/amdgpu:save psp ring wptr to avoid attack
- drm/amd/display: Fix potential memory leak in DMUB hw_init
- drm/amdgpu: refine amdgpu_fru_get_product_info
- drm/amd/display: Allow bandwidth validation for 0 streams.
- net: ipconfig: Don't override command-line hostnames or domains
- nvme-loop: do not warn for deleted controllers during reset
- nvme-loop: check for NVME_LOOP_Q_LIVE in nvme_loop_destroy_admin_queue()
- nvme-loop: clear NVME_LOOP_Q_LIVE when nvme_loop_configure_admin_queue() fails
- nvme-loop: reset queue count to 1 in nvme_loop_destroy_io_queues()
- scsi: scsi_devinfo: Add blacklist entry for HPE OPEN-V
- Bluetooth: Add a new USB ID for RTL8822CE
- scsi: qedf: Do not put host in qedf_vport_create() unconditionally
- ethernet: myri10ge: Fix missing error code in myri10ge_probe()
- scsi: target: core: Fix warning on realtime kernels
- gfs2: Fix use-after-free in gfs2_glock_shrink_scan
- riscv: Use -mno-relax when using lld linker
- HID: gt683r: add missing MODULE_DEVICE_TABLE
- gfs2: fix a deadlock on withdraw-during-mount
- gfs2: Prevent direct-I/O write fallback errors from getting lost
- ARM: OMAP2+: Fix build warning when mmc_omap is not built
- ARM: OMAP1: Fix use of possibly uninitialized irq variable
- drm/tegra: sor: Fully initialize SOR before registration
- gpu: host1x: Split up client initalization and registration
- drm/tegra: sor: Do not leak runtime PM reference
- HID: usbhid: fix info leak in hid_submit_ctrl
- HID: Add BUS_VIRTUAL to hid_connect logging
- HID: multitouch: set Stylus suffix for Stylus-application devices, too
- HID: quirks: Add quirk for Lenovo optical mouse
- HID: hid-sensor-hub: Return error for hid_set_field() failure
- HID: hid-input: add mapping for emoji picker key
- HID: a4tech: use A4_2WHEEL_MOUSE_HACK_B8 for A4TECH NB-95
- HID: quirks: Set INCREMENT_USAGE_ON_DUPLICATE for Saitek X65
- net: ieee802154: fix null deref in parse dev addr
- livepatch: fix unload hook could not be excuted
- mm/memory-failure: make sure wait for page writeback in memory_failure
- iommu: sva: Fix compile error in iommu_sva_bind_group
- proc: only require mm_struct for writing
- tracing: Correct the length check which causes memory corruption
- scsi: core: Only put parent device if host state differs from SHOST_CREATED
- scsi: core: Put .shost_dev in failure path if host state changes to RUNNING
- scsi: core: Fix failure handling of scsi_add_host_with_dma()
- scsi: core: Fix error handling of scsi_host_alloc()
- NFSv4: nfs4_proc_set_acl needs to restore NFS_CAP_UIDGID_NOMAP on error.
- NFSv4: Fix second deadlock in nfs4_evict_inode()
- NFS: Fix use-after-free in nfs4_init_client()
- kvm: fix previous commit for 32-bit builds
- perf session: Correct buffer copying when peeking events
- NFSv4: Fix deadlock between nfs4_evict_inode() and nfs4_opendata_get_inode()
- NFS: Fix a potential NULL dereference in nfs_get_client()
- IB/mlx5: Fix initializing CQ fragments buffer
- KVM: x86: Ensure liveliness of nested VM-Enter fail tracepoint message
- x86/nmi_watchdog: Fix old-style NMI watchdog regression on old Intel CPUs
- sched/fair: Fix util_est UTIL_AVG_UNCHANGED handling
- sched/fair: Make sure to update tg contrib for blocked load
- sched/fair: Keep load_avg and load_sum synced
- perf: Fix data race between pin_count increment/decrement
- gpio: wcd934x: Fix shift-out-of-bounds error
- phy: ti: Fix an error code in wiz_probe()
- ASoC: meson: gx-card: fix sound-dai dt schema
- ASoC: core: Fix Null-point-dereference in fmt_single_name()
- phy: cadence: Sierra: Fix error return code in cdns_sierra_phy_probe()
- tools/bootconfig: Fix error return code in apply_xbc()
- vmlinux.lds.h: Avoid orphan section with !SMP
- ARM: cpuidle: Avoid orphan section warning
- RDMA/mlx4: Do not map the core_clock page to user space unless enabled
- RDMA/ipoib: Fix warning caused by destroying non-initial netns
- drm/msm/a6xx: avoid shadow NULL reference in failure path
- drm/msm/a6xx: update/fix CP_PROTECT initialization
- drm/msm/a6xx: fix incorrectly set uavflagprd_inv field for A650
- drm/mcde: Fix off by 10^3 in calculation
- usb: typec: mux: Fix copy-paste mistake in typec_mux_match
- usb: dwc3: gadget: Disable gadget IRQ during pullup disable
- phy: usb: Fix misuse of IS_ENABLED
- regulator: rtmv20: Fix .set_current_limit/.get_current_limit callbacks
- regulator: bd71828: Fix .n_voltages settings
- regulator: fan53880: Fix missing n_voltages setting
- regulator: bd718x7: Fix the BUCK7 voltage setting on BD71837
- regulator: max77620: Use device_set_of_node_from_dev()
- regulator: core: resolve supply for boot-on/always-on regulators
- usb: typec: tcpm: cancel frs hrtimer when unregister tcpm port
- usb: typec: tcpm: cancel vdm and state machine hrtimer when unregister tcpm port
- usb: fix various gadget panics on 10gbps cabling
- usb: fix various gadgets null ptr deref on 10gbps cabling.
- usb: gadget: eem: fix wrong eem header operation
- USB: serial: cp210x: fix alternate function for CP2102N QFN20
- USB: serial: quatech2: fix control-request directions
- USB: serial: omninet: add device id for Zyxel Omni 56K Plus
- USB: serial: ftdi_sio: add NovaTech OrionMX product ID
- usb: gadget: f_fs: Ensure io_completion_wq is idle during unbind
- usb: typec: intel_pmc_mux: Add missed error check for devm_ioremap_resource()
- usb: typec: intel_pmc_mux: Put fwnode in error case during ->probe()
- usb: typec: ucsi: Clear PPM capability data in ucsi_init() error path
- usb: typec: wcove: Use LE to CPU conversion when accessing msg->header
- usb: musb: fix MUSB_QUIRK_B_DISCONNECT_99 handling
- usb: dwc3: ep0: fix NULL pointer exception
- usb: dwc3: gadget: Bail from dwc3_gadget_exit() if dwc->gadget is NULL
- usb: dwc3: meson-g12a: Disable the regulator in the error handling path of the probe
- usb: dwc3-meson-g12a: fix usb2 PHY glue init when phy0 is disabled
- usb: pd: Set PD_T_SINK_WAIT_CAP to 310ms
- usb: f_ncm: only first packet of aggregate needs to start timer
- USB: f_ncm: ncm_bitrate (speed) is unsigned
- mmc: renesas_sdhi: Fix HS400 on R-Car M3-W+
- mmc: renesas_sdhi: abort tuning when timeout detected
- ftrace: Do not blindly read the ip address in ftrace_bug()
- cgroup1: don't allow '\n' in renaming
- btrfs: promote debugging asserts to full-fledged checks in validate_super
- btrfs: return value from btrfs_mark_extent_written() in case of error
- async_xor: check src_offs is not NULL before updating it
- staging: rtl8723bs: Fix uninitialized variables
- kvm: avoid speculation-based attacks from out-of-range memslot accesses
- KVM: X86: MMU: Use the correct inherited permissions to get shadow page
- perf/x86/intel/uncore: Fix M2M event umask for Ice Lake server
- drm: Lock pointer access in drm_master_release()
- drm: Fix use-after-free read in drm_getunique()
- Revert "ACPI: sleep: Put the FACS table after using it"
- spi: bcm2835: Fix out-of-bounds access with more than 4 slaves
- ALSA: hda/realtek: fix mute/micmute LEDs for HP ZBook Power G8
- ALSA: hda/realtek: fix mute/micmute LEDs for HP EliteBook 840 Aero G8
- ALSA: hda/realtek: fix mute/micmute LEDs and speaker for HP EliteBook x360 1040 G8
- ALSA: hda/realtek: fix mute/micmute LEDs and speaker for HP Elite Dragonfly G2
- ALSA: hda/realtek: headphone and mic don't work on an Acer laptop
- ALSA: firewire-lib: fix the context to call snd_pcm_stop_xrun()
- ALSA: seq: Fix race of snd_seq_timer_open()
- i2c: mpc: implement erratum A-004447 workaround
- i2c: mpc: Make use of i2c_recover_bus()
- spi: Cleanup on failure of initial setup
- spi: Don't have controller clean up spi device before driver unbind
- powerpc/fsl: set fsl,i2c-erratum-a004447 flag for P1010 i2c controllers
- powerpc/fsl: set fsl,i2c-erratum-a004447 flag for P2041 i2c controllers
- nvmet: fix false keep-alive timeout when a controller is torn down
- nvme-tcp: remove incorrect Kconfig dep in BLK_DEV_NVME
- bnx2x: Fix missing error code in bnx2x_iov_init_one()
- dm verity: fix require_signatures module_param permissions
- MIPS: Fix kernel hang under FUNCTION_GRAPH_TRACER and PREEMPT_TRACER
- nvme-fabrics: decode host pathing error for connect
- net: dsa: microchip: enable phy errata workaround on 9567
- net: appletalk: cops: Fix data race in cops_probe1
- net: macb: ensure the device is available before accessing GEMGXL control registers
- scsi: target: qla2xxx: Wait for stop_phase1 at WWN removal
- scsi: hisi_sas: Drop free_irq() of devm_request_irq() allocated irq
- scsi: vmw_pvscsi: Set correct residual data length
- scsi: bnx2fc: Return failure if io_req is already in ABTS processing
- net:sfc: fix non-freed irq in legacy irq mode
- RDS tcp loopback connection can hang
- net/qla3xxx: fix schedule while atomic in ql_sem_spinlock
- wq: handle VM suspension in stall detection
- cgroup: disable controllers at parse time
- net: mdiobus: get rid of a BUG_ON()
- netlink: disable IRQs for netlink_lock_table()
- bonding: init notify_work earlier to avoid uninitialized use
- isdn: mISDN: netjet: Fix crash in nj_probe:
- usb: chipidea: udc: assign interrupt number to USB gadget structure
- spi: sprd: Add missing MODULE_DEVICE_TABLE
- ASoC: sti-sas: add missing MODULE_DEVICE_TABLE
- vfio-ccw: Serialize FSM IDLE state with I/O completion
- vfio-ccw: Reset FSM state to IDLE inside FSM
- ASoC: Intel: bytcr_rt5640: Add quirk for the Lenovo Miix 3-830 tablet
- ASoC: Intel: bytcr_rt5640: Add quirk for the Glavey TM800A550L tablet
- usb: cdns3: Fix runtime PM imbalance on error
- net/nfc/rawsock.c: fix a permission check bug
- bpf: Forbid trampoline attach for functions with variable arguments
- spi: spi-zynq-qspi: Fix stack violation bug
- spi: Fix spi device unregister flow
- ASoC: amd: fix for pcm_read() error
- ASoC: max98088: fix ni clock divider calculation
- proc: Track /proc/$pid/attr/ opener mm_struct
- mtd: mtd_blkdevs: Initialize rq.limits.discard_granularity
- block, bfq: set next_rq to waker_bfqq->next_rq in waker injection
- bdev: Do not return EBUSY if bdev discard races with write
- powerpc/perf: Invoke per-CPU variable access with disabled interrupts
- perf annotate: Fix jump parsing for C++ code.
- perf tools: Fix arm64 build error with gcc-11
- perf record: Fix memory leak in vDSO found using ASAN
- perf parse-events: Check if the software events array slots are populated
- perf symbol-elf: Fix memory leak by freeing sdt_note.args
- perf env: Fix memory leak of bpf_prog_info_linear member
- scsi: iscsi: Fix iSCSI cls conn state
- scsi: iscsi: Fix race condition between login and sync thread
- Revert "perf kmem: Do not pass additional arguments
- neighbour: allow NUD_NOARP entries to be forced GCed
- xen-netback: take a reference to the RX task thread
- netfilter: nf_tables: missing error reporting for not selected expressions
- i2c: qcom-geni: Suspend and resume the bus during SYSTEM_SLEEP_PM ops
- lib/lz4: explicitly support in-place decompression
- x86/kvm: Disable all PV features on crash
- x86/kvm: Disable kvmclock on all CPUs on shutdown
- x86/kvm: Teardown PV features on boot CPU as well
- KVM: arm64: Fix debug register indexing
- KVM: SVM: Truncate GPR value for DR and CR accesses in !64-bit mode
- btrfs: fix unmountable seed device after fstrim
- drm/msm/dpu: always use mdp device to scale bandwidth
- mm, hugetlb: fix simple resv_huge_pages underflow on UFFDIO_COPY
- btrfs: fix deadlock when cloning inline extents and low on available space
- btrfs: abort in rename_exchange if we fail to insert the second ref
- btrfs: fixup error handling in fixup_inode_link_counts
- btrfs: return errors from btrfs_del_csums in cleanup_ref_head
- btrfs: fix error handling in btrfs_del_csums
- btrfs: mark ordered extent and inode with error if we fail to finish
- powerpc/kprobes: Fix validation of prefixed instructions across page boundary
- x86/apic: Mark _all_ legacy interrupts when IO/APIC is missing
- drm/amdgpu: make sure we unpin the UVD BO
- drm/amdgpu: Don't query CE and UE errors
- nfc: fix NULL ptr dereference in llcp_sock_getname() after failed connect
- x86/sev: Check SME/SEV support in CPUID first
- x86/cpufeatures: Force disable X86_FEATURE_ENQCMD and remove update_pasid()
- mm/page_alloc: fix counting of free pages after take off from buddy
- mm/debug_vm_pgtable: fix alignment for pmd/pud_advanced_tests()
- ocfs2: fix data corruption by fallocate
- pid: take a reference when initializing `cad_pid`
- usb: dwc2: Fix build in periphal-only mode
- ext4: fix accessing uninit percpu counter variable with fast_commit
- ext4: fix memory leak in ext4_mb_init_backend on error path.
- ext4: fix fast commit alignment issues
- ext4: fix memory leak in ext4_fill_super
- ARM: dts: imx6q-dhcom: Add PU,VDD1P1,VDD2P5 regulators
- ARM: dts: imx6dl-yapp4: Fix RGMII connection to QCA8334 switch
- ALSA: hda: update the power_state during the direct-complete
- ALSA: hda: Fix for mute key LED for HP Pavilion 15-CK0xx
- ALSA: timer: Fix master timer notification
- gfs2: fix scheduling while atomic bug in glocks
- HID: multitouch: require Finger field to mark Win8 reports as MT
- HID: magicmouse: fix NULL-deref on disconnect
- HID: i2c-hid: Skip ELAN power-on command after reset
- net: caif: fix memory leak in cfusbl_device_notify
- net: caif: fix memory leak in caif_device_notify
- net: caif: add proper error handling
- net: caif: added cfserl_release function
- wireguard: allowedips: free empty intermediate nodes when removing single node
- wireguard: allowedips: allocate nodes in kmem_cache
- wireguard: allowedips: remove nodes in O(1)
- wireguard: allowedips: initialize list head in selftest
- wireguard: selftests: make sure rp_filter is disabled on vethc
- wireguard: selftests: remove old conntrack kconfig value
- wireguard: use synchronize_net rather than synchronize_rcu
- wireguard: peer: allocate in kmem_cache
- wireguard: do not use -O3
- Bluetooth: use correct lock to prevent UAF of hdev object
- Bluetooth: fix the erroneous flush_work() order
- drm/amdgpu/jpeg3: add cancel_delayed_work_sync before power gate
- drm/amdgpu/jpeg2.5: add cancel_delayed_work_sync before power gate
- drm/amdgpu/vcn3: add cancel_delayed_work_sync before power gate
- io_uring: use better types for cflags
- io_uring: fix link timeout refs
- riscv: vdso: fix and clean-up Makefile
- serial: stm32: fix threaded interrupt handling
- tipc: fix unique bearer names sanity check
- tipc: add extack messages for bearer/media failure
- bus: ti-sysc: Fix flakey idling of uarts and stop using swsup_sidle_act
- ARM: dts: imx: emcon-avari: Fix nxp,pca8574 #gpio-cells
- ARM: dts: imx7d-pico: Fix the 'tuning-step' property
- ARM: dts: imx7d-meerkat96: Fix the 'tuning-step' property
- arm64: dts: freescale: sl28: var4: fix RGMII clock and voltage
- arm64: dts: zii-ultra: fix 12V_MAIN voltage
- arm64: dts: ls1028a: fix memory node
- bus: ti-sysc: Fix am335x resume hang for usb otg module
- optee: use export_uuid() to copy client UUID
- arm64: dts: ti: j7200-main: Mark Main NAVSS as dma-coherent
- ixgbe: add correct exception tracing for XDP
- ixgbe: optimize for XDP_REDIRECT in xsk path
- ice: add correct exception tracing for XDP
- ice: optimize for XDP_REDIRECT in xsk path
- ice: simplify ice_run_xdp
- i40e: add correct exception tracing for XDP
- i40e: optimize for XDP_REDIRECT in xsk path
- cxgb4: avoid link re-train during TC-MQPRIO configuration
- i2c: qcom-geni: Add shutdown callback for i2c
- ice: Allow all LLDP packets from PF to Tx
- ice: report supported and advertised autoneg using PHY capabilities
- ice: handle the VF VSI rebuild failure
- ice: Fix VFR issues for AVF drivers that expect ATQLEN cleared
- ice: Fix allowing VF to request more/less queues via virtchnl
- ipv6: Fix KASAN: slab-out-of-bounds Read in fib6_nh_flush_exceptions
- cxgb4: fix regression with HASH tc prio value update
- ixgbevf: add correct exception tracing for XDP
- igb: add correct exception tracing for XDP
- ieee802154: fix error return code in ieee802154_llsec_getparams()
- ieee802154: fix error return code in ieee802154_add_iface()
- bpf, lockdown, audit: Fix buggy SELinux lockdown permission checks
- bpf: Simplify cases in bpf_base_func_proto
- drm/i915/selftests: Fix return value check in live_breadcrumbs_smoketest()
- netfilter: nfnetlink_cthelper: hit EBUSY on updates if size mismatches
- netfilter: nft_ct: skip expectations for confirmed conntrack
- nvmet: fix freeing unallocated p2pmem
- net/mlx5: DR, Create multi-destination flow table with level less than 64
- net/mlx5e: Check for needed capability for cvlan matching
- net/mlx5: Check firmware sync reset requested is set before trying to abort it
- net/mlx5e: Fix incompatible casting
- net/tls: Fix use-after-free after the TLS device goes down and up
- net/tls: Replace TLS_RX_SYNC_RUNNING with RCU
- net: sock: fix in-kernel mark setting
- net: dsa: tag_8021q: fix the VLAN IDs used for encoding sub-VLANs
- perf probe: Fix NULL pointer dereference in convert_variable_location()
- ACPICA: Clean up context mutex during object deletion
- nvme-rdma: fix in-casule data send for chained sgls
- mptcp: always parse mptcp options for MPC reqsk
- net/sched: act_ct: Fix ct template allocation for zone 0
- net/sched: act_ct: Offload connections with commit action
- devlink: Correct VIRTUAL port to not have phys_port attributes
- HID: i2c-hid: fix format string mismatch
- HID: pidff: fix error return code in hid_pidff_init()
- HID: logitech-hidpp: initialize level variable
- ipvs: ignore IP_VS_SVC_F_HASHED flag when adding service
- vfio/platform: fix module_put call in error flow
- samples: vfio-mdev: fix error handing in mdpy_fb_probe()
- vfio/pci: zap_vma_ptes() needs MMU
- vfio/pci: Fix error return code in vfio_ecap_init()
- efi: cper: fix snprintf() use in cper_dimm_err_location()
- efi/libstub: prevent read overflow in find_file_option()
- efi: Allow EFI_MEMORY_XP and EFI_MEMORY_RO both to be cleared
- efi/fdt: fix panic when no valid fdt found
- netfilter: conntrack: unregister ipv4 sockopts on error unwind
- hwmon: (pmbus/isl68137) remove READ_TEMPERATURE_3 for RAA228228
- hwmon: (dell-smm-hwmon) Fix index values
- net: usb: cdc_ncm: don't spew notifications
- btrfs: tree-checker: do not error out if extent ref hash doesn't match
- ext4: fix bug on in ext4_es_cache_extent as ext4_split_extent_at failed
- usb: core: reduce power-on-good delay time of root hub
- neighbour: Prevent Race condition in neighbour subsytem
- scripts/clang-tools: switch explicitly to Python 3
- net: hso: bail out on interrupt URB allocation failure
- Revert "Revert "ALSA: usx2y: Fix potential NULL pointer dereference""
- SUNRPC: More fixes for backlog congestion
- bpftool: Add sock_release help info for cgroup attach/prog load command
- net: hns3: check the return of skb_checksum_help()
- samples/bpf: Consider frame size in tx_only of xdpsock sample
- i915: fix build warning in intel_dp_get_link_status()
- net: mvpp2: add buffer header handling in RX
- net: zero-initialize tc skb extension on allocation
- MIPS: ralink: export rt_sysc_membase for rt2880_wdt.c
- MIPS: alchemy: xxs1500: add gpio-au1000.h header file
- net: hsr: fix mac_len checks
- sch_dsmark: fix a NULL deref in qdisc_reset()
- net: ethernet: mtk_eth_soc: Fix packet statistics support for MT7628/88
- ALSA: usb-audio: scarlett2: snd_scarlett_gen2_controls_create() can be static
- ipv6: record frag_max_size in atomic fragments in input path
- net: lantiq: fix memory corruption in RX ring
- scsi: libsas: Use _safe() loop in sas_resume_port()
- ASoC: qcom: lpass-cpu: Use optional clk APIs
- ixgbe: fix large MTU request from VF
- bpf: Set mac_len in bpf_skb_change_head
- bpf, offload: Reorder offload callback 'prepare' in verifier
- ASoC: cs35l33: fix an error code in probe()
- staging: emxx_udc: fix loop in _nbu2ss_nuke()
- cxgb4: avoid accessing registers when clearing filters
- iommu/vt-d: Use user privilege for RID2PASID translation
- net: hns3: put off calling register_netdev() until client initialize complete
- net: hns3: fix incorrect resp_msg issue
- iommu/virtio: Add missing MODULE_DEVICE_TABLE
- gve: Correct SKB queue index validation.
- gve: Upgrade memory barrier in poll routine
- gve: Add NULL pointer checks when freeing irqs.
- gve: Update mgmt_msix_idx if num_ntfy changes
- gve: Check TX QPL was actually assigned
- net/smc: remove device from smcd_dev_list after failed device_add()
- mld: fix panic in mld_newpack()
- bnxt_en: Fix context memory setup for 64K page size.
- bnxt_en: Include new P5 HV definition in VF check.
- net: bnx2: Fix error return code in bnx2_init_board()
- net: hso: check for allocation failure in hso_create_bulk_serial_device()
- net: sched: fix tx action reschedule issue with stopped queue
- net: sched: fix tx action rescheduling issue during deactivation
- net: sched: fix packet stuck problem for lockless qdisc
- tls splice: check SPLICE_F_NONBLOCK instead of MSG_DONTWAIT
- openvswitch: meter: fix race when getting now_ms.
- cxgb4/ch_ktls: Clear resources when pf4 device is removed
- net: mdio: octeon: Fix some double free issues
- net: mdio: thunder: Fix a double free issue in the .remove function
- chelsio/chtls: unlock on error in chtls_pt_recvmsg()
- net: fec: fix the potential memory leak in fec_enet_init()
- net: packetmmap: fix only tx timestamp on request
- net: really orphan skbs tied to closing sk
- spi: Assume GPIO CS active high in ACPI case
- vfio-ccw: Check initialized flag in cp_init()
- net: ipa: memory region array is variable size
- net: stmmac: Fix MAC WoL not working if PHY does not support WoL
- ASoC: cs42l42: Regmap must use_single_read/write
- interconnect: qcom: Add missing MODULE_DEVICE_TABLE
- interconnect: qcom: bcm-voter: add a missing of_node_put()
- net: dsa: fix error code getting shifted with 4 in dsa_slave_get_sset_count
- net: netcp: Fix an error message
- linux/bits.h: fix compilation error with GENMASK
- block: fix a race between del_gendisk and BLKRRPART
- platform/x86: touchscreen_dmi: Add info for the Chuwi Hi10 Pro (CWI529) tablet
- drm/amdgpu: stop touching sched.ready in the backend
- drm/amd/amdgpu: fix a potential deadlock in gpu reset
- drm/amdgpu: Fix a use-after-free
- drm/amd/amdgpu: fix refcount leak
- drm/amd/display: Disconnect non-DP with no EDID
- SMB3: incorrect file id in requests compounded with open
- platform/x86: touchscreen_dmi: Add info for the Mediacom Winpad 7.0 W700 tablet
- platform/x86: intel_punit_ipc: Append MODULE_DEVICE_TABLE for ACPI
- platform/x86: hp-wireless: add AMD's hardware id to the supported list
- btrfs: do not BUG_ON in link_to_fixup_dir
- btrfs: release path before starting transaction when cloning inline extent
- scsi: pm80xx: Fix drives missing during rmmod/insmod loop
- openrisc: Define memory barrier mb
- scsi: BusLogic: Fix 64-bit system enumeration error for Buslogic
- scsi: ufs: ufs-mediatek: Fix power down spec violation
- btrfs: return whole extents in fiemap
- brcmfmac: properly check for bus register errors
- Revert "brcmfmac: add a check for the status of usb_register"
- net: liquidio: Add missing null pointer checks
- Revert "net: liquidio: fix a NULL pointer dereference"
- media: gspca: properly check for errors in po1030_probe()
- Revert "media: gspca: Check the return value of write_bridge for timeout"
- media: gspca: mt9m111: Check write_bridge for timeout
- Revert "media: gspca: mt9m111: Check write_bridge for timeout"
- media: dvb: Add check on sp8870_readreg return
- Revert "media: dvb: Add check on sp8870_readreg"
- ASoC: cs43130: handle errors in cs43130_probe() properly
- Revert "ASoC: cs43130: fix a NULL pointer dereference"
- libertas: register sysfs groups properly
- Revert "libertas: add checks for the return value of sysfs_create_group"
- dmaengine: qcom_hidma: comment platform_driver_register call
- Revert "dmaengine: qcom_hidma: Check for driver register failure"
- isdn: mISDN: correctly handle ph_info allocation failure in hfcsusb_ph_info
- Revert "isdn: mISDN: Fix potential NULL pointer dereference of kzalloc"
- ath6kl: return error code in ath6kl_wmi_set_roam_lrssi_cmd()
- Revert "ath6kl: return error code in ath6kl_wmi_set_roam_lrssi_cmd()"
- isdn: mISDNinfineon: check/cleanup ioremap failure correctly in setup_io
- Revert "isdn: mISDNinfineon: fix potential NULL pointer dereference"
- Revert "ALSA: usx2y: Fix potential NULL pointer dereference"
- Revert "ALSA: gus: add a check of the status of snd_ctl_add"
- char: hpet: add checks after calling ioremap
- Revert "char: hpet: fix a missing check of ioremap"
- net: caif: remove BUG_ON(dev == NULL) in caif_xmit
- Revert "net: caif: replace BUG_ON with recovery code"
- net/smc: properly handle workqueue allocation failure
- Revert "net/smc: fix a NULL pointer dereference"
- net: fujitsu: fix potential null-ptr-deref
- Revert "net: fujitsu: fix a potential NULL pointer dereference"
- serial: max310x: unregister uart driver in case of failure and abort
- Revert "serial: max310x: pass return value of spi_register_driver"
- Revert "ALSA: sb: fix a missing check of snd_ctl_add"
- Revert "media: usb: gspca: add a missed check for goto_low_power"
- Revert "crypto: cavium/nitrox - add an error message to explain the failure of pci_request_mem_regions"
- gpio: cadence: Add missing MODULE_DEVICE_TABLE
- platform/x86: hp_accel: Avoid invoking _INI to speed up resume
- mptcp: fix data stream corruption
- mptcp: drop unconditional pr_warn on bad opt
- mptcp: avoid error message on infinite mapping
- nvmet-tcp: fix inline data size comparison in nvmet_tcp_queue_response
- perf jevents: Fix getting maximum number of fds
- afs: Fix the nlink handling of dir-over-dir rename
- i2c: sh_mobile: Use new clock calculation formulas for RZ/G2E
- i2c: i801: Don't generate an interrupt on bus reset
- i2c: mediatek: Disable i2c start_en and clear intr_stat brfore reset
- i2c: s3c2410: fix possible NULL pointer deref on read message after write
- net: dsa: sja1105: fix VL lookup command packing for P/Q/R/S
- net: dsa: sja1105: call dsa_unregister_switch when allocating memory fails
- net: dsa: sja1105: add error handling in sja1105_setup()
- net: dsa: sja1105: error out on unsupported PHY mode
- net: dsa: sja1105: use 4095 as the private VLAN for untagged traffic
- net: dsa: sja1105: update existing VLANs from the bridge VLAN list
- net: dsa: fix a crash if ->get_sset_count() fails
- net: dsa: mt7530: fix VLAN traffic leaks
- netfilter: flowtable: Remove redundant hw refresh bit
- spi: spi-fsl-dspi: Fix a resource leak in an error handling path
- tipc: skb_linearize the head skb when reassembling msgs
- tipc: wait and exit until all work queues are done
- Revert "net:tipc: Fix a double free in tipc_sk_mcast_rcv"
- SUNRPC in case of backlog, hand free slots directly to waiting task
- net/mlx5: Set term table as an unmanaged flow table
- net/mlx4: Fix EEPROM dump support
- net/mlx5e: Fix null deref accessing lag dev
- net/mlx5: Set reformat action when needed for termination rules
- net/mlx5e: Fix nullptr in add_vlan_push_action()
- {net,vdpa}/mlx5: Configure interface MAC into mpfs L2 table
- net/mlx5e: Fix error path of updating netdev queues
- net/mlx5e: Fix multipath lag activation
- net/mlx5e: reset XPS on error flow if netdev isn't registered yet
- drm/meson: fix shutdown crash when component not probed
- NFSv4: Fix v4.0/v4.1 SEEK_DATA return -ENOTSUPP when set NFS_V4_2 config
- NFS: Don't corrupt the value of pg_bytes_written in nfs_do_recoalesce()
- NFS: Fix an Oopsable condition in __nfs_pageio_add_request()
- NFS: fix an incorrect limit in filelayout_decode_layout()
- fs/nfs: Use fatal_signal_pending instead of signal_pending
- Bluetooth: cmtp: fix file refcount when cmtp_attach_device fails
- net: usb: fix memory leak in smsc75xx_bind
- usb: typec: mux: Fix matching with typec_altmode_desc
- usb: gadget: udc: renesas_usb3: Fix a race in usb3_start_pipen()
- usb: dwc3: gadget: Properly track pending and queued SG
- thermal/drivers/intel: Initialize RW trip to THERMAL_TEMP_INVALID
- USB: serial: pl2303: add device id for ADLINK ND-6530 GC
- USB: serial: ftdi_sio: add IDs for IDS GmbH Products
- USB: serial: option: add Telit LE910-S1 compositions 0x7010, 0x7011
- USB: serial: ti_usb_3410_5052: add startech.com device id
- serial: rp2: use 'request_firmware' instead of 'request_firmware_nowait'
- serial: sh-sci: Fix off-by-one error in FIFO threshold register setting
- serial: tegra: Fix a mask operation that is always true
- drivers: base: Fix device link removal
- USB: usbfs: Don't WARN about excessively large memory allocations
- Revert "irqbypass: do not start cons/prod when failed connect"
- USB: trancevibrator: fix control-request direction
- serial: 8250_pci: handle FL_NOIRQ board flag
- serial: 8250_pci: Add support for new HPE serial device
- serial: 8250_dw: Add device HID for new AMD UART controller
- serial: 8250: Add UART_BUG_TXRACE workaround for Aspeed VUART
- iio: adc: ad7192: handle regulator voltage error first
- iio: adc: ad7192: Avoid disabling a clock that was never enabled.
- iio: adc: ad7793: Add missing error code in ad7793_setup()
- iio: adc: ad7923: Fix undersized rx buffer.
- iio: adc: ad7124: Fix potential overflow due to non sequential channel numbers
- iio: adc: ad7124: Fix missbalanced regulator enable / disable on error.
- iio: adc: ad7768-1: Fix too small buffer passed to iio_push_to_buffers_with_timestamp()
- iio: dac: ad5770r: Put fwnode in error case during ->probe()
- iio: gyro: fxas21002c: balance runtime power in error path
- staging: iio: cdc: ad7746: avoid overwrite of num_channels
- mei: request autosuspend after sending rx flow control
- KVM: arm64: Prevent mixed-width VM creation
- KVM: X86: Fix vCPU preempted state from guest's point of view
- thunderbolt: dma_port: Fix NVM read buffer bounds and offset issue
- thunderbolt: usb4: Fix NVM read buffer bounds and offset issue
- misc/uss720: fix memory leak in uss720_probe
- serial: core: fix suspicious security_locked_down() call
- seccomp: Refactor notification handler to prepare for new semantics
- Documentation: seccomp: Fix user notification documentation
- kgdb: fix gcc-11 warnings harder
- selftests/gpio: Fix build when source tree is read only
- selftests/gpio: Move include of lib.mk up
- selftests/gpio: Use TEST_GEN_PROGS_EXTENDED
- drm/amdgpu/jpeg2.0: add cancel_delayed_work_sync before power gate
- drm/amdgpu/vcn2.5: add cancel_delayed_work_sync before power gate
- drm/amdgpu/vcn2.0: add cancel_delayed_work_sync before power gate
- drm/amdkfd: correct sienna_cichlid SDMA RLC register offset error
- drm/amdgpu/vcn1: add cancel_delayed_work_sync before power gate
- drm/amd/pm: correct MGpuFanBoost setting
- dm snapshot: properly fix a crash when an origin has no snapshots
- ath11k: Clear the fragment cache during key install
- ath10k: Validate first subframe of A-MSDU before processing the list
- ath10k: Fix TKIP Michael MIC verification for PCIe
- ath10k: drop MPDU which has discard flag set by firmware for SDIO
- ath10k: drop fragments with multicast DA for SDIO
- ath10k: drop fragments with multicast DA for PCIe
- ath10k: add CCMP PN replay protection for fragmented frames for PCIe
- mac80211: extend protection against mixed key and fragment cache attacks
- mac80211: do not accept/forward invalid EAPOL frames
- mac80211: prevent attacks on TKIP/WEP as well
- mac80211: check defrag PN against current frame
- mac80211: add fragment cache to sta_info
- mac80211: drop A-MSDUs on old ciphers
- cfg80211: mitigate A-MSDU aggregation attacks
- mac80211: properly handle A-MSDUs that start with an RFC 1042 header
- mac80211: prevent mixed key and fragment cache attacks
- mac80211: assure all fragments are encrypted
- netfilter: nft_set_pipapo_avx2: Add irq_fpu_usable() check, fallback to non-AVX2 version
- net/sched: fq_pie: fix OOB access in the traffic path
- net/sched: fq_pie: re-factor fix for fq_pie endless loop
- net: hso: fix control-request directions
- proc: Check /proc/$pid/attr/ writes against file opener
- perf scripts python: exported-sql-viewer.py: Fix warning display
- perf scripts python: exported-sql-viewer.py: Fix Array TypeError
- perf scripts python: exported-sql-viewer.py: Fix copy to clipboard from Top Calls by elapsed Time report
- perf intel-pt: Fix transaction abort handling
- perf intel-pt: Fix sample instruction bytes
- iommu/vt-d: Fix sysfs leak in alloc_iommu()
- NFSv4: Fix a NULL pointer dereference in pnfs_mark_matching_lsegs_return()
- cifs: set server->cipher_type to AES-128-CCM for SMB3.0
- ALSA: usb-audio: scarlett2: Improve driver startup messages
- ALSA: usb-audio: scarlett2: Fix device hang with ehci-pci
- ALSA: hda/realtek: fix mute/micmute LEDs and speaker for HP Zbook Fury 17 G8
- ALSA: hda/realtek: fix mute/micmute LEDs and speaker for HP Zbook Fury 15 G8
- ALSA: hda/realtek: fix mute/micmute LEDs and speaker for HP Zbook G8
- ALSA: hda/realtek: fix mute/micmute LEDs for HP 855 G8
- ALSA: hda/realtek: Chain in pop reduction fixup for ThinkStation P340
- ALSA: hda/realtek: Headphone volume is controlled by Front mixer
- ALSA: hda/realtek: the bass speaker can't output sound on Yoga 9i
- sched: export sched_setscheduler symbol
- arm32: kaslr: Bugfix of BSS size calculation when enabled kaslr
- mm: Move HOLES_IN_ZONE into mm
- mm,hwpoison: return -EBUSY when migration fails
- livepatch: put memory alloc and free out stop machine
- livepatch/core: Support function force patched/unpatched
- livepatch/ppc64: Enable livepatch without ftrace
- livepatch/ppc64: Sample testcase fix ppc64
- livepatch/ppc64: Ignore the first frame when checking stack
- livepatch/ppc64: Make sure caller function in stack
- livepatch/ppc64: Use module_alloc to alloc func_node
- livepatch/ppc64: Implement per func_node livepatch trampoline
- livepatch/ppc64: Check active func in consistency stack checking
- livepatch/ppc64: Support use func_descr for new_func
- livepatch/ppc64: Implement livepatch without ftrace for ppc64be
- livepatch/ppc32: Ignore the first frame when checking stack
- livepatch/ppc32: Check active func in consistency stack checking
- livepatch/ppc32: Fix current backtracking in klp_check_calltrace
- livepatch/ppc32: Fix func size less than limit
- livepatch/ppc32: Add support for longjump
- livepatch/ppc32: Support livepatch without ftrace
- livepatch/x86: check active func in consistency stack checking
- livepatch/x86: support livepatch without ftrace
- livepatch/core: Revert module_enable_ro and module_disable_ro
- livepatch/arm: Check active func in consistency stack checking
- livepatch/arm: Add support for livepatch plt
- livepatch/arm: Fix current backtracking in klp_check_calltrace
- livepatch/arm: Support livepatch without ftrace
- livepatch/core: Add support for arm for klp relocation
- arm/module: Use plt section indices for relocations
- livepatch/core: Add livepatch consistency depends
- livepatch/arm64: check active func in consistency stack checking
- livepatch/arm64: Fix current backtracking in klp_check_calltrace
- livepatch/arm64: Fix func size less than limit
- livepatch/arm64: Support livepatch without ftrace
- livepatch/core: Support jump_label
- livepatch/core: Supprt load and unload hooks
- livepatch/core: Split livepatch consistency
- livepatch/core: Restrict livepatch patched/unpatched when plant kprobe
- livepatch/core: Allow implementation without ftrace
- DEBUG: iommu: Sanity-check of page requests
- DEBUG: iommu/arm-smmu-v3: Add SVA trace events
- TESTING: vfio: Add support for Shared Virtual Addressing
- iommu: Add group variant for SVA bind/unbind
- mm: export symbol mmput_async
- mm: export symbol find_get_task_by_vpid
- mm: export symbol mm_access
- iommu/arm-smmu-v3: Support auxiliary domains
- iommu: Use device fault trace event
- trace/iommu: Add sva trace events
- iommu: handle page response timeout
- iommu: Add a timeout parameter for PRQ response
- iommu: Introduce attach/detach_pasid_table API
- Documentation: Generalize the "pci=noats" boot parameter
- PCI: Support ats-supported device-tree property
- arm64: dts: fast models: Enable PCIe ATS for Base RevC FVP
- dt-bindings: PCI: generic: Add ats-supported property
- iommu/arm-smmu-v3: Ratelimit event dump
- iommu/arm-smmu-v3: Add support for Hardware Translation Table Update
- iommu/arm-smmu-v3: Enable broadcast TLB maintenance
- iommu/arm-smmu-v3: Add support for PRI
- PCI/ATS: Export PRI functions
- PCI/ATS: Add PRI stubs
- mm: notify remote TLBs when dirtying a PTE
- iommu/arm-smmu-v3: Add stall support for platform devices
- ACPI/IORT: Enable stall support for platform devices
- dt-bindings: document stall property for IOMMU masters
- NFC: nci: fix memory leak in nci_allocate_device
- perf unwind: Set userdata for all __report_module() paths
- perf unwind: Fix separate debug info files when using elfutils' libdw's unwinder
- KVM: x86: Defer vtime accounting 'til after IRQ handling
- context_tracking: Move guest exit vtime accounting to separate helpers
- context_tracking: Move guest exit context tracking to separate helpers
- bpf: No need to simulate speculative domain for immediates
- bpf: Fix mask direction swap upon off reg sign change
- bpf: Wrap aux data inside bpf_sanitize_info container
- mm/page_alloc: fix counting of managed_pages
- mm: page_alloc: refactor setup_per_zone_lowmem_reserve()
- dm verity: allow only one error handling mode
- Bluetooth: SMP: Fail if remote and local public keys are identical
- video: hgafb: correctly handle card detect failure during probe
- nvmet: use new ana_log_size instead the old one
- x86/boot/compressed/64: Check SEV encryption in the 32-bit boot-path
- rtc: pcf85063: fallback to parent of_node
- nvme-multipath: fix double initialization of ANA state
- x86/Xen: swap NX determination and GDT setup on BSP
- openrisc: mm/init.c: remove unused memblock_region variable in map_ram()
- drm/i915/gt: Disable HiZ Raw Stall Optimization on broken gen7
- tty: vt: always invoke vc->vc_sw->con_resize callback
- vt: Fix character height handling with VT_RESIZEX
- vt_ioctl: Revert VT_RESIZEX parameter handling removal
- vgacon: Record video mode changes with VT_RESIZEX
- video: hgafb: fix potential NULL pointer dereference
- qlcnic: Add null check after calling netdev_alloc_skb
- leds: lp5523: check return value of lp5xx_read and jump to cleanup code
- ics932s401: fix broken handling of errors when word reading fails
- net: rtlwifi: properly check for alloc_workqueue() failure
- scsi: ufs: handle cleanup correctly on devm_reset_control_get error
- net: stmicro: handle clk_prepare() failure during init
- ethernet: sun: niu: fix missing checks of niu_pci_eeprom_read()
- Revert "niu: fix missing checks of niu_pci_eeprom_read"
- Revert "qlcnic: Avoid potential NULL pointer dereference"
- Revert "rtlwifi: fix a potential NULL pointer dereference"
- Revert "media: rcar_drif: fix a memory disclosure"
- cdrom: gdrom: initialize global variable at init time
- cdrom: gdrom: deallocate struct gdrom_unit fields in remove_gdrom
- Revert "gdrom: fix a memory leak bug"
- Revert "scsi: ufs: fix a missing check of devm_reset_control_get"
- Revert "ecryptfs: replace BUG_ON with error handling code"
- Revert "video: imsttfb: fix potential NULL pointer dereferences"
- Revert "hwmon: (lm80) fix a missing check of bus read in lm80 probe"
- Revert "leds: lp5523: fix a missing check of return value of lp55xx_read"
- Revert "net: stmicro: fix a missing check of clk_prepare"
- Revert "video: hgafb: fix potential NULL pointer dereference"
- kcsan: Fix debugfs initcall return type
- dm snapshot: fix crash with transient storage and zero chunk size
- ipc/mqueue, msg, sem: avoid relying on a stack reference past its expiry
- xen-pciback: reconfigure also from backend watch handler
- xen-pciback: redo VF placement in the virtual topology
- mmc: sdhci-pci-gli: increase 1.8V regulator wait
- powerpc/64s/syscall: Fix ptrace syscall info with scv syscalls
- powerpc/64s/syscall: Use pt_regs.trap to distinguish syscall ABI difference between sc and scv syscalls
- drm/amdgpu: update sdma golden setting for Navi12
- drm/amdgpu: update gc golden setting for Navi12
- drm/amdgpu: disable 3DCGCG on picasso/raven1 to avoid compute hang
- drm/amdgpu: Fix GPU TLB update error when PAGE_SIZE > AMDGPU_PAGE_SIZE
- x86/sev-es: Forward page-faults which happen during emulation
- x86/sev-es: Use __put_user()/__get_user() for data accesses
- x86/sev-es: Don't return NULL from sev_es_get_ghcb()
- x86/sev-es: Invalidate the GHCB after completing VMGEXIT
- x86/sev-es: Move sev_es_put_ghcb() in prep for follow on patch
- nvme-tcp: fix possible use-after-completion
- Revert "serial: mvebu-uart: Fix to avoid a potential NULL pointer dereference"
- rapidio: handle create_workqueue() failure
- Revert "rapidio: fix a NULL pointer dereference when create_workqueue() fails"
- uio_hv_generic: Fix a memory leak in error handling paths
- ALSA: hda/realtek: Add fixup for HP Spectre x360 15-df0xxx
- ALSA: hda/realtek: Add fixup for HP OMEN laptop
- ALSA: hda/realtek: Fix silent headphone output on ASUS UX430UA
- ALSA: hda/realtek: Add some CLOVE SSIDs of ALC293
- ALSA: hda/realtek: reset eapd coeff to default value for alc287
- ALSA: firewire-lib: fix check for the size of isochronous packet payload
- Revert "ALSA: sb8: add a check for request_region"
- ALSA: hda: fixup headset for ASUS GU502 laptop
- ALSA: bebob/oxfw: fix Kconfig entry for Mackie d.2 Pro
- ALSA: usb-audio: Validate MS endpoint descriptors
- ALSA: firewire-lib: fix calculation for size of IR context payload
- ALSA: dice: fix stream format at middle sampling rate for Alesis iO 26
- ALSA: line6: Fix racy initialization of LINE6 MIDI
- ALSA: firewire-lib: fix amdtp_packet tracepoints event for packet_index field
- ALSA: intel8x0: Don't update period unless prepared
- ALSA: dice: fix stream format for TC Electronic Konnekt Live at high sampling transfer frequency
- misc: eeprom: at24: check suspend status before disable regulator
- cifs: fix memory leak in smb2_copychunk_range
- btrfs: avoid RCU stalls while running delayed iputs
- powerpc: Fix early setup to make early_ioremap() work
- locking/mutex: clear MUTEX_FLAGS if wait_list is empty due to signal
- locking/lockdep: Correct calling tracepoints
- perf/x86: Avoid touching LBR_TOS MSR for Arch LBR
- nvmet: seset ns->file when open fails
- ptrace: make ptrace() fail if the tracee changed its pid unexpectedly
- powerpc/pseries: Fix hcall tracing recursion in pv queued spinlocks
- tools/testing/selftests/exec: fix link error
- RDMA/uverbs: Fix a NULL vs IS_ERR() bug
- RDMA/mlx5: Fix query DCT via DEVX
- platform/x86: dell-smbios-wmi: Fix oops on rmmod dell_smbios
- platform/x86: intel_int0002_vgpio: Only call enable_irq_wake() when using s2idle
- platform/mellanox: mlxbf-tmfifo: Fix a memory barrier issue
- nvme-fc: clear q_live at beginning of association teardown
- nvme-tcp: rerun io_work if req_list is not empty
- nvme-loop: fix memory leak in nvme_loop_create_ctrl()
- nvmet: fix memory leak in nvmet_alloc_ctrl()
- nvmet: remove unused ctrl->cqs
- RDMA/core: Don't access cm_id after its destruction
- RDMA/mlx5: Recover from fatal event in dual port mode
- scsi: qla2xxx: Fix error return code in qla82xx_write_flash_dword()
- scsi: qedf: Add pointer checks in qedf_update_link_speed()
- scsi: ufs: core: Increase the usable queue depth
- RDMA/rxe: Clear all QP fields if creation failed
- RDMA/core: Prevent divide-by-zero error triggered by the user
- RDMA/siw: Release xarray entry
- RDMA/siw: Properly check send and receive CQ pointers
- tee: amdtee: unload TA only when its refcount becomes 0
- openrisc: Fix a memory leak
- firmware: arm_scpi: Prevent the ternary sign expansion bug
- scripts: switch explicitly to Python 3
- tweewide: Fix most Shebang lines
- ipv6: remove extra dev_hold() for fallback tunnels
- ip6_tunnel: sit: proper dev_{hold|put} in ndo_[un]init methods
- sit: proper dev_{hold|put} in ndo_[un]init methods
- ip6_gre: proper dev_{hold|put} in ndo_[un]init methods
- net: stmmac: Do not enable RX FIFO overflow interrupts
- lib: stackdepot: turn depot_lock spinlock to raw_spinlock
- block: reexpand iov_iter after read/write
- ALSA: hda: generic: change the DAC ctl name for LO+SPK or LO+HP
- net:CXGB4: fix leak if sk_buff is not used
- gpiolib: acpi: Add quirk to ignore EC wakeups on Dell Venue 10 Pro 5055
- drm/amd/display: Fix two cursor duplication when using overlay
- nvmet: remove unsupported command noise
- net: hsr: check skb can contain struct hsr_ethhdr in fill_frame_info
- bridge: Fix possible races between assigning rx_handler_data and setting IFF_BRIDGE_PORT bit
- amdgpu/pm: Prevent force of DCEFCLK on NAVI10 and SIENNA_CICHLID
- scsi: target: tcmu: Return from tcmu_handle_completions() if cmd_id not found
- ceph: don't allow access to MDS-private inodes
- ceph: don't clobber i_snap_caps on non-I_NEW inode
- ceph: fix fscache invalidation
- scsi: lpfc: Fix illegal memory access on Abort IOCBs
- riscv: Workaround mcount name prior to clang-13
- scripts/recordmcount.pl: Fix RISC-V regex for clang
- riscv: Use $(LD) instead of $(CC) to link vDSO
- platform/chrome: cros_ec_typec: Add DP mode check
- ARM: 9075/1: kernel: Fix interrupted SMC calls
- um: Disable CONFIG_GCOV with MODULES
- um: Mark all kernel symbols as local
- NFS: NFS_INO_REVAL_PAGECACHE should mark the change attribute invalid
- Input: silead - add workaround for x86 BIOS-es which bring the chip up in a stuck state
- Input: elants_i2c - do not bind to i2c-hid compatible ACPI instantiated devices
- PCI: tegra: Fix runtime PM imbalance in pex_ep_event_pex_rst_deassert()
- ACPI / hotplug / PCI: Fix reference count leak in enable_slot()
- ARM: 9066/1: ftrace: pause/unpause function graph tracer in cpu_suspend()
- dmaengine: dw-edma: Fix crash on loading/unloading driver
- PCI: thunder: Fix compile testing
- virtio_net: Do not pull payload in skb->head
- isdn: capi: fix mismatched prototypes
- cxgb4: Fix the -Wmisleading-indentation warning
- usb: sl811-hcd: improve misleading indentation
- kgdb: fix gcc-11 warning on indentation
- airo: work around stack usage warning
- drm/i915/display: fix compiler warning about array overrun
- x86/msr: Fix wr/rdmsr_safe_regs_on_cpu() prototypes
- ASoC: rsnd: check all BUSIF status when error
- nvme: do not try to reconfigure APST when the controller is not live
- ext4: fix debug format string warning
- debugfs: Make debugfs_allow RO after init
- dt-bindings: serial: 8250: Remove duplicated compatible strings
- dt-bindings: media: renesas,vin: Make resets optional on R-Car Gen1
- i2c: mediatek: Fix send master code at more than 1MHz
- media: rkvdec: Remove of_match_ptr()
- clk: exynos7: Mark aclk_fsys1_200 as critical
- drm/i915: Fix crash in auto_retire
- drm/i915/overlay: Fix active retire callback alignment
- drm/i915: Read C0DRB3/C1DRB3 as 16 bits again
- drm/i915/gt: Fix a double free in gen8_preallocate_top_level_pdp
- kobject_uevent: remove warning in init_uevent_argv()
- usb: typec: tcpm: Fix error while calculating PPS out values
- clocksource/drivers/timer-ti-dm: Handle dra7 timer wrap errata i940
- clocksource/drivers/timer-ti-dm: Prepare to handle dra7 timer wrap issue
- MIPS: Avoid handcoded DIVU in `__div64_32' altogether
- MIPS: Avoid DIVU in `__div64_32' is result would be zero
- MIPS: Reinstate platform `__div64_32' handler
- mm: fix struct page layout on 32-bit systems
- iommu/vt-d: Remove WO permissions on second-level paging entries
- iommu/vt-d: Preset Access/Dirty bits for IOVA over FL
- Revert "iommu/vt-d: Preset Access/Dirty bits for IOVA over FL"
- Revert "iommu/vt-d: Remove WO permissions on second-level paging entries"
- KVM: VMX: Disable preemption when probing user return MSRs
- KVM: VMX: Do not advertise RDPID if ENABLE_RDTSCP control is unsupported
- KVM: nVMX: Always make an attempt to map eVMCS after migration
- KVM: x86: Move RDPID emulation intercept to its own enum
- KVM: x86: Emulate RDPID only if RDTSCP is supported
- xen/gntdev: fix gntdev_mmap() error exit path
- cdc-wdm: untangle a circular dependency between callback and softint
- iio: tsl2583: Fix division by a zero lux_val
- iio: gyro: mpu3050: Fix reported temperature value
- xhci: Add reset resume quirk for AMD xhci controller.
- xhci: Do not use GFP_KERNEL in (potentially) atomic context
- xhci-pci: Allow host runtime PM as default for Intel Alder Lake xHCI
- usb: typec: ucsi: Put fwnode in any case during ->probe()
- usb: typec: ucsi: Retrieve all the PDOs instead of just the first 4
- usb: dwc3: gadget: Return success always for kick transfer in ep queue
- usb: dwc3: gadget: Enable suspend events
- usb: core: hub: fix race condition about TRSMRCY of resume
- usb: dwc2: Fix gadget DMA unmap direction
- usb: xhci: Increase timeout for HC halt
- usb: dwc3: pci: Enable usb2-gadget-lpm-disable for Intel Merrifield
- usb: dwc3: omap: improve extcon initialization
- blk-mq: Swap two calls in blk_mq_exit_queue()
- blk-mq: plug request for shared sbitmap
- nbd: Fix NULL pointer in flush_workqueue
- f2fs: compress: fix to assign cc.cluster_idx correctly
- f2fs: compress: fix race condition of overwrite vs truncate
- f2fs: compress: fix to free compress page correctly
- nvmet-rdma: Fix NULL deref when SEND is completed with error
- nvmet: fix inline bio check for bdev-ns
- nvmet: add lba to sect conversion helpers
- kyber: fix out of bounds access when preempted
- ACPI: scan: Fix a memory leak in an error handling path
- usb: musb: Fix an error message
- hwmon: (occ) Fix poll rate limiting
- usb: fotg210-hcd: Fix an error message
- iio: hid-sensors: select IIO_TRIGGERED_BUFFER under HID_SENSOR_IIO_TRIGGER
- iio: proximity: pulsedlight: Fix rumtime PM imbalance on error
- iio: light: gp2ap002: Fix rumtime PM imbalance on error
- usb: dwc3: gadget: Free gadget structure only after freeing endpoints
- perf tools: Fix dynamic libbpf link
- xen/unpopulated-alloc: fix error return code in fill_list()
- xen/unpopulated-alloc: consolidate pgmap manipulation
- dax: Wake up all waiters after invalidating dax entry
- dax: Add a wakeup mode parameter to put_unlocked_entry()
- dax: Add an enum for specifying dax wakup mode
- KVM: x86: Prevent deadlock against tk_core.seq
- KVM: x86: Cancel pvclock_gtod_work on module removal
- drm/msm/dp: initialize audio_comp when audio starts
- KVM: LAPIC: Accurately guarantee busy wait for timer to expire when using hv_timer
- kvm: exit halt polling on need_resched() as well
- drm/i915: Avoid div-by-zero on gen2
- drm/amd/display: Initialize attribute for hdcp_srm sysfs file
- drm/radeon/dpm: Disable sclk switching on Oland when two 4K 60Hz monitors are connected
- btrfs: fix race leading to unpersisted data and metadata on fsync
- arm64: Fix race condition on PG_dcache_clean in __sync_icache_dcache()
- arm64: mte: initialize RGSR_EL1.SEED in __cpu_setup
- blk-iocost: fix weight updates of inner active iocgs
- mm/hugetlb: fix F_SEAL_FUTURE_WRITE
- kasan: fix unit tests with CONFIG_UBSAN_LOCAL_BOUNDS enabled
- userfaultfd: release page in error path to avoid BUG_ON
- squashfs: fix divide error in calculate_skip()
- hfsplus: prevent corruption in shrinking truncate
- powerpc/64s: Fix crashes when toggling entry flush barrier
- powerpc/64s: Fix crashes when toggling stf barrier
- ARC: mm: Use max_high_pfn as a HIGHMEM zone border
- ARC: mm: PAE: use 40-bit physical page mask
- ARC: entry: fix off-by-one error in syscall number validation
- f2fs: avoid unneeded data copy in f2fs_ioc_move_range()
- mptcp: fix splat when closing unaccepted socket
- i40e: Fix PHY type identifiers for 2.5G and 5G adapters
- i40e: fix the restart auto-negotiation after FEC modified
- i40e: Fix use-after-free in i40e_client_subtask()
- i40e: fix broken XDP support
- netfilter: nftables: avoid overflows in nft_hash_buckets()
- kernel/resource: make walk_mem_res() find all busy IORESOURCE_MEM resources
- kernel/resource: make walk_system_ram_res() find all busy IORESOURCE_SYSTEM_RAM resources
- kernel: kexec_file: fix error return code of kexec_calculate_store_digests()
- fs/proc/generic.c: fix incorrect pde_is_permanent check
- sched/fair: Fix unfairness caused by missing load decay
- sched: Fix out-of-bound access in uclamp
- can: m_can: m_can_tx_work_queue(): fix tx_skb race condition
- can: mcp251x: fix resume from sleep before interface was brought up
- can: mcp251xfd: mcp251xfd_probe(): add missing can_rx_offload_del() in error path
- netfilter: nftables: Fix a memleak from userdata error path in new objects
- netfilter: nfnetlink_osf: Fix a missing skb_header_pointer() NULL check
- smc: disallow TCP_ULP in smc_setsockopt()
- net: fix nla_strcmp to handle more then one trailing null character
- ethtool: fix missing NLM_F_MULTI flag when dumping
- mm/gup: check for isolation errors
- mm/gup: return an error on migration failure
- mm/gup: check every subpage of a compound page during isolation
- ksm: fix potential missing rmap_item for stable_node
- mm/migrate.c: fix potential indeterminate pte entry in migrate_vma_insert_page()
- mm/hugeltb: handle the error case in hugetlb_fix_reserve_counts()
- khugepaged: fix wrong result value for trace_mm_collapse_huge_page_isolate()
- arm64: entry: always set GIC_PRIO_PSR_I_SET during entry
- arm64: entry: factor irq triage logic into macros
- drm/radeon: Avoid power table parsing memory leaks
- drm/radeon: Fix off-by-one power_state index heap overwrite
- net: stmmac: Clear receive all(RA) bit when promiscuous mode is off
- xsk: Fix for xp_aligned_validate_desc() when len == chunk_size
- netfilter: xt_SECMARK: add new revision to fix structure layout
- sctp: fix a SCTP_MIB_CURRESTAB leak in sctp_sf_do_dupcook_b
- ethernet:enic: Fix a use after free bug in enic_hard_start_xmit
- block/rnbd-clt: Check the return value of the function rtrs_clt_query
- block/rnbd-clt: Change queue_depth type in rnbd_clt_session to size_t
- libbpf: Fix signed overflow in ringbuf_process_ring
- sunrpc: Fix misplaced barrier in call_decode
- RISC-V: Fix error code returned by riscv_hartid_to_cpuid()
- sctp: do asoc update earlier in sctp_sf_do_dupcook_a
- net: hns3: disable phy loopback setting in hclge_mac_start_phy
- net: hns3: use netif_tx_disable to stop the transmit queue
- net: hns3: fix for vxlan gpe tx checksum bug
- net: hns3: add check for HNS3_NIC_STATE_INITED in hns3_reset_notify_up_enet()
- net: hns3: initialize the message content in hclge_get_link_mode()
- net: hns3: fix incorrect configuration for igu_egu_hw_err
- rtc: ds1307: Fix wday settings for rx8130
- scsi: ufs: core: Narrow down fast path in system suspend path
- scsi: ufs: core: Cancel rpm_dev_flush_recheck_work during system suspend
- scsi: ufs: core: Do not put UFS power into LPM if link is broken
- scsi: qla2xxx: Prevent PRLI in target mode
- ceph: fix inode leak on getattr error in __fh_to_dentry
- swiotlb: Fix the type of index
- xprtrdma: rpcrdma_mr_pop() already does list_del_init()
- xprtrdma: Fix cwnd update ordering
- xprtrdma: Avoid Receive Queue wrapping
- pwm: atmel: Fix duty cycle calculation in .get_state()
- SUNRPC: fix ternary sign expansion bug in tracing
- dmaengine: idxd: fix cdev setup and free device lifetime issues
- dmaengine: idxd: fix dma device lifetime
- dmaengine: idxd: Fix potential null dereference on pointer status
- rtc: fsl-ftm-alarm: add MODULE_TABLE()
- nfsd: ensure new clients break delegations
- NFSv4.x: Don't return NFS4ERR_NOMATCHING_LAYOUT if we're unmounting
- thermal/drivers/tsens: Fix missing put_device error
- SUNRPC: Handle major timeout in xprt_adjust_timeout()
- SUNRPC: Remove trace_xprt_transmit_queued
- SUNRPC: Move fault injection call sites
- NFSv4.2 fix handling of sr_eof in SEEK's reply
- pNFS/flexfiles: fix incorrect size check in decode_nfs_fh()
- PCI: endpoint: Fix missing destroy_workqueue()
- NFS: Deal correctly with attribute generation counter overflow
- NFSv4.2: Always flush out writes in nfs42_proc_fallocate()
- NFS: Fix attribute bitmask in _nfs42_proc_fallocate()
- NFS: nfs4_bitmask_adjust() must not change the server global bitmasks
- rpmsg: qcom_glink_native: fix error return code of qcom_glink_rx_data()
- f2fs: fix to avoid accessing invalid fio in f2fs_allocate_data_block()
- f2fs: Fix a hungtask problem in atomic write
- f2fs: fix to cover __allocate_new_section() with curseg_lock
- f2fs: fix to avoid touching checkpointed data in get_victim()
- PCI: endpoint: Fix NULL pointer dereference for ->get_features()
- PCI: endpoint: Make *_free_bar() to return error codes on failure
- PCI: endpoint: Add helper API to get the 'next' unreserved BAR
- PCI: endpoint: Make *_get_first_free_bar() take into account 64 bit BAR
- f2fs: fix to update last i_size if fallocate partially succeeds
- f2fs: fix to align to section for fallocate() on pinned file
- PCI: Release OF node in pci_scan_device()'s error path
- PCI: iproc: Fix return value of iproc_msi_irq_domain_alloc()
- remoteproc: qcom_q6v5_mss: Validate p_filesz in ELF loader
- remoteproc: qcom_q6v5_mss: Replace ioremap with memremap
- f2fs: fix a redundant call to f2fs_balance_fs if an error occurs
- f2fs: fix panic during f2fs_resize_fs()
- f2fs: fix to allow migrating fully valid segment
- f2fs: fix compat F2FS_IOC_{MOVE,GARBAGE_COLLECT}_RANGE
- f2fs: move ioctl interface definitions to separated file
- thermal: thermal_of: Fix error return code of thermal_of_populate_bind_params()
- ASoC: rt286: Make RT286_SET_GPIO_* readable and writable
- watchdog: fix barriers when printing backtraces from all CPUs
- watchdog/softlockup: remove logic that tried to prevent repeated reports
- watchdog: explicitly update timestamp when reporting softlockup
- watchdog: rename __touch_watchdog() to a better descriptive name
- ia64: module: fix symbolizer crash on fdescr
- bnxt_en: Add PCI IDs for Hyper-V VF devices.
- kbuild: generate Module.symvers only when vmlinux exists
- selftests: mlxsw: Fix mausezahn invocation in ERSPAN scale test
- selftests: mlxsw: Increase the tolerance of backlog buildup
- net: ethernet: mtk_eth_soc: fix RX VLAN offload
- iavf: remove duplicate free resources calls
- powerpc/iommu: Annotate nested lock for lockdep
- qtnfmac: Fix possible buffer overflow in qtnf_event_handle_external_auth
- wl3501_cs: Fix out-of-bounds warnings in wl3501_mgmt_join
- wl3501_cs: Fix out-of-bounds warnings in wl3501_send_pkt
- crypto: ccp: Free SEV device if SEV init fails
- mt76: mt7615: fix entering driver-own state on mt7663
- drm/amdgpu: Add mem sync flag for IB allocated by SA
- drm/amd/display: add handling for hdcp2 rx id list validation
- drm/amd/display: fixed divide by zero kernel crash during dsc enablement
- powerpc/pseries: Stop calling printk in rtas_stop_self()
- samples/bpf: Fix broken tracex1 due to kprobe argument change
- net: sched: tapr: prevent cycle_time == 0 in parse_taprio_schedule
- ethtool: ioctl: Fix out-of-bounds warning in store_link_ksettings_for_user()
- ASoC: rt286: Generalize support for ALC3263 codec
- powerpc/smp: Set numa node before updating mask
- flow_dissector: Fix out-of-bounds warning in __skb_flow_bpf_to_target()
- sctp: Fix out-of-bounds warning in sctp_process_asconf_param()
- ALSA: hda/hdmi: fix race in handling acomp ELD notification at resume
- ASoC: Intel: sof_sdw: add quirk for new ADL-P Rvp
- ALSA: hda/realtek: Add quirk for Lenovo Ideapad S740
- kconfig: nconf: stop endless search loops
- selftests: Set CC to clang in lib.mk if LLVM is set
- drm/amd/display: Force vsync flip when reconfiguring MPCC
- iommu/amd: Remove performance counter pre-initialization test
- Revert "iommu/amd: Fix performance counter initialization"
- ASoC: rsnd: call rsnd_ssi_master_clk_start() from rsnd_ssi_init()
- powerpc/mm: Add cond_resched() while removing hpte mappings
- iwlwifi: pcie: make cfg vs. trans_cfg more robust
- cuse: prevent clone
- virtiofs: fix userns
- fuse: invalidate attrs when page writeback completes
- mt76: mt7915: fix txpower init for TSSI off chips
- mt76: mt76x0: disable GTK offloading
- mt76: mt7615: support loading EEPROM for MT7613BE
- rtw88: 8822c: add LC calibration for RTL8822C
- pinctrl: samsung: use 'int' for register masks in Exynos
- mac80211: clear the beacon's CRC after channel switch
- IB/hfi1: Correct oversized ring allocation
- coresight: Do not scan for graph if none is present
- MIPS: Loongson64: Use _CACHE_UNCACHED instead of _CACHE_UNCACHED_ACCELERATED
- i2c: Add I2C_AQ_NO_REP_START adapter quirk
- ASoC: rt5670: Add a quirk for the Dell Venue 10 Pro 5055
- Bluetooth: btusb: Enable quirk boolean flag for Mediatek Chip.
- ice: handle increasing Tx or Rx ring sizes
- ASoC: Intel: bytcr_rt5640: Add quirk for the Chuwi Hi8 tablet
- ip6_vti: proper dev_{hold|put} in ndo_[un]init methods
- net: hns3: add handling for xmit skb with recursive fraglist
- net: hns3: remediate a potential overflow risk of bd_num_list
- powerpc/32: Statically initialise first emergency context
- selftests/powerpc: Fix L1D flushing tests for Power10
- Bluetooth: check for zapped sk before connecting
- net: bridge: when suppression is enabled exclude RARP packets
- net/sched: cls_flower: use ntohs for struct flow_dissector_key_ports
- Bluetooth: initialize skb_queue_head at l2cap_chan_create()
- Bluetooth: Set CONF_NOT_COMPLETE as l2cap_chan default
- ALSA: bebob: enable to deliver MIDI messages for multiple ports
- ALSA: rme9652: don't disable if not enabled
- ALSA: hdspm: don't disable if not enabled
- ALSA: hdsp: don't disable if not enabled
- i2c: bail out early when RDWR parameters are wrong
- Bluetooth: Fix incorrect status handling in LE PHY UPDATE event
- ASoC: rsnd: core: Check convert rate in rsnd_hw_params
- net: stmmac: Set FIFO sizes for ipq806x
- net/mlx5e: Use net_prefetchw instead of prefetchw in MPWQE TX datapath
- ASoC: Intel: bytcr_rt5640: Enable jack-detect support on Asus T100TAF
- tipc: convert dest node's address to network order
- fs: dlm: flush swork on shutdown
- fs: dlm: check on minimum msglen size
- fs: dlm: add errno handling to check callback
- fs: dlm: fix debugfs dump
- ath11k: fix thermal temperature read
- kvm: Cap halt polling at kvm->max_halt_poll_ns
- cpufreq: intel_pstate: Use HWP if enabled by platform firmware
- PM: runtime: Fix unpaired parent child_count for force_resume
- ACPI: PM: Add ACPI ID of Alder Lake Fan
- KVM/VMX: Invoke NMI non-IST entry instead of IST entry
- KVM: x86/mmu: Remove the defunct update_pte() paging hook
- tpm, tpm_tis: Reserve locality in tpm_tis_resume()
- tpm, tpm_tis: Extend locality handling to TPM2 in tpm_tis_gen_interrupt()
- tpm: fix error return code in tpm2_get_cc_attrs_tbl()
- KEYS: trusted: Fix memory leak on object td
- sctp: delay auto_asconf init until binding the first addr
- Revert "net/sctp: fix race condition in sctp_destroy_sock"
- smp: Fix smp_call_function_single_async prototype
- net: Only allow init netns to set default tcp cong to a restricted algo
- bpf: Prevent writable memory-mapping of read-only ringbuf pages
- bpf, ringbuf: Deny reserve of buffers larger than ringbuf
- bpf: Fix alu32 const subreg bound tracking on bitwise operations
- afs: Fix speculative status fetches
- mm/memory-failure: unnecessary amount of unmapping
- mm/sparse: add the missing sparse_buffer_fini() in error branch
- mm: memcontrol: slab: fix obtain a reference to a freeing memcg
- mm/sl?b.c: remove ctor argument from kmem_cache_flags
- kfifo: fix ternary sign extension bugs
- ia64: fix EFI_DEBUG build
- perf session: Add swap operation for event TIME_CONV
- perf jit: Let convert_timestamp() to be backwards-compatible
- perf tools: Change fields type in perf_record_time_conv
- net:nfc:digital: Fix a double free in digital_tg_recv_dep_req
- net: bridge: mcast: fix broken length + header check for MRDv6 Adv.
- RDMA/bnxt_re: Fix a double free in bnxt_qplib_alloc_res
- RDMA/siw: Fix a use after free in siw_alloc_mr
- bpf: Fix propagation of 32 bit unsigned bounds from 64 bit bounds
- selftests/bpf: Fix core_reloc test runner
- selftests/bpf: Fix field existence CO-RE reloc tests
- selftests/bpf: Fix BPF_CORE_READ_BITFIELD() macro
- net:emac/emac-mac: Fix a use after free in emac_mac_tx_buf_send
- KVM: VMX: Intercept FS/GS_BASE MSR accesses for 32-bit KVM
- bnxt_en: Fix RX consumer index logic in the error path.
- selftests: mlxsw: Remove a redundant if statement in tc_flower_scale test
- selftests: net: mirror_gre_vlan_bridge_1q: Make an FDB entry static
- net: geneve: modify IP header check in geneve6_xmit_skb and geneve_xmit_skb
- arm64: dts: uniphier: Change phy-mode to RGMII-ID to enable delay pins for RTL8211E
- ARM: dts: uniphier: Change phy-mode to RGMII-ID to enable delay pins for RTL8211E
- bnxt_en: fix ternary sign extension bug in bnxt_show_temp()
- net: enetc: fix link error again
- net: phy: marvell: fix m88e1111_set_downshift
- net: phy: marvell: fix m88e1011_set_downshift
- powerpc/52xx: Fix an invalid ASM expression ('addi' used instead of 'add')
- powerpc/perf: Fix the threshold event selection for memory events in power10
- wlcore: Fix buffer overrun by snprintf due to incorrect buffer size
- ath10k: Fix ath10k_wmi_tlv_op_pull_peer_stats_info() unlock without lock
- ath10k: Fix a use after free in ath10k_htc_send_bundle
- ath9k: Fix error check in ath9k_hw_read_revisions() for PCI devices
- powerpc/64: Fix the definition of the fixmap area
- RDMA/core: Add CM to restrack after successful attachment to a device
- RDMA/rxe: Fix a bug in rxe_fill_ip_info()
- net: phy: intel-xway: enable integrated led functions
- net: renesas: ravb: Fix a stuck issue when a lot of frames are received
- net: stmmac: fix TSO and TBS feature enabling during driver open
- nfp: devlink: initialize the devlink port attribute "lanes"
- crypto: ccp: Detect and reject "invalid" addresses destined for PSP
- mt76: mt7615: fix memleak when mt7615_unregister_device()
- net: davinci_emac: Fix incorrect masking of tx and rx error channel
- net: marvell: prestera: fix port event handling on init
- vsock/virtio: free queued packets when closing socket
- sfc: ef10: fix TX queue lookup in TX event handling
- ALSA: usb: midi: don't return -ENOMEM when usb_urb_ep_type_check fails
- RDMA/i40iw: Fix error unwinding when i40iw_hmc_sd_one fails
- RDMA/cxgb4: add missing qpid increment
- gro: fix napi_gro_frags() Fast GRO breakage due to IP alignment check
- net: ethernet: ixp4xx: Set the DMA masks explicitly
- libbpf: Initialize the bpf_seq_printf parameters array field by field
- vsock/vmci: log once the failed queue pair allocation
- netfilter: nftables_offload: special ethertype handling for VLAN
- netfilter: nftables_offload: VLAN id needs host byteorder in flow dissector
- netfilter: nft_payload: fix C-VLAN offload support
- mwl8k: Fix a double Free in mwl8k_probe_hw
- i2c: mediatek: Fix wrong dma sync flag
- i2c: sh7760: fix IRQ error path
- wlcore: fix overlapping snprintf arguments in debugfs
- rtlwifi: 8821ae: upgrade PHY and RF parameters
- KVM: x86: dump_vmcs should not assume GUEST_IA32_EFER is valid
- powerpc/smp: Reintroduce cpu_core_mask
- powerpc/pseries: extract host bridge from pci_bus prior to bus removal
- MIPS: pci-legacy: stop using of_pci_range_to_resource
- drm/amd/pm: fix error code in smu_set_power_limit()
- perf beauty: Fix fsconfig generator
- iommu/amd: Put newline after closing bracket in warning
- drm/i915/gvt: Fix error code in intel_gvt_init_device()
- net/packet: remove data races in fanout operations
- net/packet: make packet_fanout.arr size configurable up to 64K
- net/mlx5: Fix bit-wise and with zero
- ASoC: ak5558: correct reset polarity
- powerpc/xive: Fix xmon command "dxi"
- powerpc/xive: Drop check on irq_data in xive_core_debug_show()
- i2c: sh7760: add IRQ check
- i2c: rcar: add IRQ check
- i2c: rcar: protect against supurious interrupts on V3U
- i2c: rcar: make sure irq is not threaded on Gen2 and earlier
- i2c: mlxbf: add IRQ check
- i2c: jz4780: add IRQ check
- i2c: emev2: add IRQ check
- i2c: cadence: add IRQ check
- i2c: xiic: fix reference leak when pm_runtime_get_sync fails
- i2c: stm32f7: fix reference leak when pm_runtime_get_sync fails
- i2c: sprd: fix reference leak when pm_runtime_get_sync fails
- i2c: omap: fix reference leak when pm_runtime_get_sync fails
- i2c: imx: fix reference leak when pm_runtime_get_sync fails
- i2c: imx-lpi2c: fix reference leak when pm_runtime_get_sync fails
- i2c: img-scb: fix reference leak when pm_runtime_get_sync fails
- i2c: cadence: fix reference leak when pm_runtime_get_sync fails
- RDMA/rtrs-clt: destroy sysfs after removing session from active list
- RDMA/srpt: Fix error return code in srpt_cm_req_recv()
- net: thunderx: Fix unintentional sign extension issue
- cxgb4: Fix unintentional sign extension issues
- RDMA/bnxt_re: Fix error return code in bnxt_qplib_cq_process_terminal()
- IB/hfi1: Fix error return code in parse_platform_config()
- RDMA/qedr: Fix error return code in qedr_iw_connect()
- ovl: invalidate readdir cache on changes to dir with origin
- KVM: PPC: Book3S HV P9: Restore host CTRL SPR after guest exit
- mt76: mt7663s: fix the possible device hang in high traffic
- mt76: mt7663s: make all of packets 4-bytes aligned in sdio tx aggregation
- mt76: mt7915: fix mib stats counter reporting to mac80211
- mt76: mt7615: fix mib stats counter reporting to mac80211
- mt76: mt7915: fix aggr len debugfs node
- mt76: mt7915: fix tx skb dma unmap
- mt76: mt7615: fix tx skb dma unmap
- mt7601u: fix always true expression
- rtw88: Fix an error code in rtw_debugfs_set_rsvd_page()
- xfs: fix return of uninitialized value in variable error
- perf vendor events amd: Fix broken L2 Cache Hits from L2 HWPF metric
- mac80211: bail out if cipher schemes are invalid
- powerpc: iommu: fix build when neither PCI or IBMVIO is set
- powerpc/perf: Fix PMU constraint check for EBB events
- powerpc/64s: Fix pte update for kernel memory on radix
- IB/hfi1: Use kzalloc() for mmu_rb_handler allocation
- liquidio: Fix unintented sign extension of a left shift of a u16
- ASoC: simple-card: fix possible uninitialized single_cpu local variable
- KVM: arm64: Initialize VCPU mdcr_el2 before loading it
- HID: lenovo: Map mic-mute button to KEY_F20 instead of KEY_MICMUTE
- HID: lenovo: Check hid_get_drvdata() returns non NULL in lenovo_event()
- HID: lenovo: Fix lenovo_led_set_tp10ubkbd() error handling
- HID: lenovo: Use brightness_set_blocking callback for setting LEDs brightness
- ALSA: usb-audio: Add error checks for usb_driver_claim_interface() calls
- iommu/vt-d: Invalidate PASID cache when root/context entry changed
- iommu/vt-d: Remove WO permissions on second-level paging entries
- iommu/vt-d: Preset Access/Dirty bits for IOVA over FL
- iommu/vt-d: Report the right page fault address
- iommu/vt-d: Report right snoop capability when using FL for IOVA
- iommu: Fix a boundary issue to avoid performance drop
- iommu/vt-d: Don't set then clear private data in prq_event_thread()
- mips: bmips: fix syscon-reboot nodes
- net: hns3: Limiting the scope of vector_ring_chain variable
- nfc: pn533: prevent potential memory corruption
- RDMA/core: Fix corrupted SL on passive side
- bug: Remove redundant condition check in report_bug
- net/tipc: fix missing destroy_workqueue() on error in tipc_crypto_start()
- powerpc/pseries: Only register vio drivers if vio bus exists
- udp: never accept GSO_FRAGLIST packets
- net: phy: lan87xx: fix access to wrong register of LAN87xx
- ALSA: core: remove redundant spin_lock pair in snd_card_disconnect
- gpio: guard gpiochip_irqchip_add_domain() with GPIOLIB_IRQCHIP
- MIPS/bpf: Enable bpf_probe_read{, str}() on MIPS again
- powerpc: Fix HAVE_HARDLOCKUP_DETECTOR_ARCH build configuration
- IB/isert: Fix a use after free in isert_connect_request
- RDMA/mlx5: Fix drop packet rule in egress table
- iommu/arm-smmu-v3: add bit field SFM into GERROR_ERR_MASK
- ASoC: wm8960: Remove bitclk relax condition in wm8960_configure_sysclk
- MIPS: loongson64: fix bug when PAGE_SIZE > 16KB
- pinctrl: pinctrl-single: fix pcs_pin_dbg_show() when bits_per_mux is not zero
- pinctrl: pinctrl-single: remove unused parameter
- inet: use bigger hash table for IP ID generation
- ima: Fix the error code for restoring the PCR value
- MIPS: fix local_irq_{disable,enable} in asmmacro.h
- powerpc/prom: Mark identical_pvr_fixup as __init
- powerpc/fadump: Mark fadump_calculate_reserve_size as __init
- libbpf: Add explicit padding to btf_dump_emit_type_decl_opts
- selftests/bpf: Re-generate vmlinux.h and BPF skeletons if bpftool changed
- iommu/vt-d: Reject unsupported page request modes
- iommu: Check dev->iommu in iommu_dev_xxx functions
- bpftool: Fix maybe-uninitialized warnings
- libbpf: Add explicit padding to bpf_xdp_set_link_opts
- net: lapbether: Prevent racing when checking whether the netif is running
- Bluetooth: avoid deadlock between hci_dev->lock and socket lock
- KVM: x86/mmu: Retry page faults that hit an invalid memslot
- wilc1000: write value to WILC_INTR2_ENABLE register
- RDMA/mlx5: Fix mlx5 rates to IB rates map
- ASoC: Intel: Skylake: Compile when any configuration is selected
- ASoC: Intel: boards: sof-wm8804: add check for PLL setting
- perf symbols: Fix dso__fprintf_symbols_by_name() to return the number of printed chars
- HID: plantronics: Workaround for double volume key presses
- xsk: Respect device's headroom and tailroom on generic xmit path
- drivers/block/null_blk/main: Fix a double free in null_init.
- sched/debug: Fix cgroup_path[] serialization
- io_uring: fix overflows checks in provide buffers
- perf/amd/uncore: Fix sysfs type mismatch
- x86/events/amd/iommu: Fix sysfs type mismatch
- HSI: core: fix resource leaks in hsi_add_client_from_dt()
- media: cedrus: Fix H265 status definitions
- nvme-pci: don't simple map sgl when sgls are disabled
- nvmet-tcp: fix a segmentation fault during io parsing error
- mfd: stm32-timers: Avoid clearing auto reload register
- mailbox: sprd: Introduce refcnt when clients requests/free channels
- scsi: ibmvfc: Fix invalid state machine BUG_ON()
- scsi: sni_53c710: Add IRQ check
- scsi: sun3x_esp: Add IRQ check
- scsi: jazz_esp: Add IRQ check
- scsi: hisi_sas: Fix IRQ checks
- scsi: ufs: ufshcd-pltfrm: Fix deferred probing
- scsi: pm80xx: Fix potential infinite loop
- scsi: pm80xx: Increase timeout for pm80xx mpi_uninit_check()
- clk: uniphier: Fix potential infinite loop
- drm/radeon: Fix a missing check bug in radeon_dp_mst_detect()
- drm/amd/display: use GFP_ATOMIC in dcn20_resource_construct
- clk: qcom: apss-ipq-pll: Add missing MODULE_DEVICE_TABLE
- clk: qcom: a53-pll: Add missing MODULE_DEVICE_TABLE
- drm: xlnx: zynqmp: fix a memset in zynqmp_dp_train()
- clk: zynqmp: pll: add set_pll_mode to check condition in zynqmp_pll_enable
- clk: zynqmp: move zynqmp_pll_set_mode out of round_rate callback
- vfio/mdev: Do not allow a mdev_type to have a NULL parent pointer
- vfio/pci: Re-order vfio_pci_probe()
- vfio/pci: Move VGA and VF initialization to functions
- vfio/fsl-mc: Re-order vfio_fsl_mc_probe()
- media: v4l2-ctrls.c: fix race condition in hdl->requests list
- media: i2c: imx219: Balance runtime PM use-count
- media: i2c: imx219: Move out locking/unlocking of vflip and hflip controls from imx219_set_stream
- nvme: retrigger ANA log update if group descriptor isn't found
- power: supply: bq25980: Move props from battery node
- clk: imx: Fix reparenting of UARTs not associated with stdout
- nvmet-tcp: fix incorrect locking in state_change sk callback
- nvme-tcp: block BH in sk state_change sk callback
- seccomp: Fix CONFIG tests for Seccomp_filters
- ata: libahci_platform: fix IRQ check
- sata_mv: add IRQ checks
- pata_ipx4xx_cf: fix IRQ check
- pata_arasan_cf: fix IRQ check
- selftests: fix prepending $(OUTPUT) to $(TEST_PROGS)
- x86/kprobes: Fix to check non boostable prefixes correctly
- of: overlay: fix for_each_child.cocci warnings
- drm/amdkfd: fix build error with AMD_IOMMU_V2=m
- media: atomisp: Fix use after free in atomisp_alloc_css_stat_bufs()
- media: m88rs6000t: avoid potential out-of-bounds reads on arrays
- media: atomisp: Fixed error handling path
- media: [next] staging: media: atomisp: fix memory leak of object flash
- media: docs: Fix data organization of MEDIA_BUS_FMT_RGB101010_1X30
- media: m88ds3103: fix return value check in m88ds3103_probe()
- media: platform: sunxi: sun6i-csi: fix error return code of sun6i_video_start_streaming()
- media: venus: core: Fix some resource leaks in the error path of 'venus_probe()'
- drm/probe-helper: Check epoch counter in output_poll_execute()
- media: aspeed: fix clock handling logic
- media: rkisp1: rsz: crash fix when setting src format
- media: omap4iss: return error code when omap4iss_get() failed
- media: saa7146: use sg_dma_len when building pgtable
- media: saa7134: use sg_dma_len when building pgtable
- media: vivid: fix assignment of dev->fbuf_out_flags
- rcu: Remove spurious instrumentation_end() in rcu_nmi_enter()
- afs: Fix updating of i_mode due to 3rd party change
- sched/fair: Fix shift-out-of-bounds in load_balance()
- drm/mcde/panel: Inverse misunderstood flag
- drm/amd/display: Fix off by one in hdmi_14_process_transaction()
- drm/stm: Fix bus_flags handling
- drm/tilcdc: send vblank event when disabling crtc
- soc: aspeed: fix a ternary sign expansion bug
- xen-blkback: fix compatibility bug with single page rings
- serial: omap: fix rs485 half-duplex filtering
- serial: omap: don't disable rs485 if rts gpio is missing
- ttyprintk: Add TTY hangup callback.
- usb: dwc2: Fix hibernation between host and device modes.
- usb: dwc2: Fix host mode hibernation exit with remote wakeup flow.
- PM: hibernate: x86: Use crc32 instead of md5 for hibernation e820 integrity check
- Drivers: hv: vmbus: Increase wait time for VMbus unload
- hwmon: (pmbus/pxe1610) don't bail out when not all pages are active
- x86/platform/uv: Fix !KEXEC build failure
- spi: spi-zynqmp-gqspi: return -ENOMEM if dma_map_single fails
- spi: spi-zynqmp-gqspi: fix use-after-free in zynqmp_qspi_exec_op
- spi: spi-zynqmp-gqspi: fix hang issue when suspend/resume
- spi: spi-zynqmp-gqspi: fix clk_enable/disable imbalance issue
- Drivers: hv: vmbus: Use after free in __vmbus_open()
- ARM: dts: aspeed: Rainier: Fix humidity sensor bus address
- platform/x86: pmc_atom: Match all Beckhoff Automation baytrail boards with critclk_systems DMI table
- security: keys: trusted: fix TPM2 authorizations
- memory: samsung: exynos5422-dmc: handle clk_set_parent() failure
- memory: renesas-rpc-if: fix possible NULL pointer dereference of resource
- spi: spi-zynqmp-gqspi: Fix missing unlock on error in zynqmp_qspi_exec_op()
- m68k: Add missing mmap_read_lock() to sys_cacheflush()
- usbip: vudc: fix missing unlock on error in usbip_sockfd_store()
- crypto: chelsio - Read rxchannel-id from firmware
- node: fix device cleanups in error handling code
- firmware: qcom-scm: Fix QCOM_SCM configuration
- serial: core: return early on unsupported ioctls
- tty: fix return value for unsupported termiox ioctls
- tty: Remove dead termiox code
- tty: fix return value for unsupported ioctls
- tty: actually undefine superseded ASYNC flags
- USB: cdc-acm: fix TIOCGSERIAL implementation
- USB: cdc-acm: fix unprivileged TIOCCSERIAL
- usb: gadget: r8a66597: Add missing null check on return from platform_get_resource
- spi: fsl-lpspi: Fix PM reference leak in lpspi_prepare_xfer_hardware()
- spi: spi-zynqmp-gqspi: fix incorrect operating mode in zynqmp_qspi_read_op
- spi: spi-zynqmp-gqspi: transmit dummy circles by using the controller's internal functionality
- spi: spi-zynqmp-gqspi: add mutex locking for exec_op
- spi: spi-zynqmp-gqspi: use wait_for_completion_timeout to make zynqmp_qspi_exec_op not interruptible
- cpufreq: armada-37xx: Fix determining base CPU frequency
- cpufreq: armada-37xx: Fix driver cleanup when registration failed
- clk: mvebu: armada-37xx-periph: Fix workaround for switching from L1 to L0
- clk: mvebu: armada-37xx-periph: Fix switching CPU freq from 250 Mhz to 1 GHz
- cpufreq: armada-37xx: Fix the AVS value for load L1
- clk: mvebu: armada-37xx-periph: remove .set_parent method for CPU PM clock
- cpufreq: armada-37xx: Fix setting TBG parent for load levels
- crypto: qat - Fix a double free in adf_create_ring
- crypto: sa2ul - Fix memory leak of rxd
- crypto: sun8i-ss - Fix memory leak of pad
- crypto: allwinner - add missing CRYPTO_ prefix
- ACPI: CPPC: Replace cppc_attr with kobj_attribute
- cpuidle: Fix ARM_QCOM_SPM_CPUIDLE configuration
- PM: runtime: Replace inline function pm_runtime_callbacks_present()
- soc: qcom: mdt_loader: Detect truncated read of segments
- soc: qcom: mdt_loader: Validate that p_filesz < p_memsz
- spi: fsl: add missing iounmap() on error in of_fsl_spi_probe()
- spi: Fix use-after-free with devm_spi_alloc_*
- clocksource/drivers/ingenic_ost: Fix return value check in ingenic_ost_probe()
- clocksource/drivers/timer-ti-dm: Add missing set_state_oneshot_stopped
- clocksource/drivers/timer-ti-dm: Fix posted mode status check order
- PM / devfreq: Use more accurate returned new_freq as resume_freq
- soc: qcom: pdr: Fix error return code in pdr_register_listener
- staging: greybus: uart: fix unprivileged TIOCCSERIAL
- staging: fwserial: fix TIOCGSERIAL implementation
- staging: fwserial: fix TIOCSSERIAL implementation
- staging: rtl8192u: Fix potential infinite loop
- staging: comedi: tests: ni_routes_test: Fix compilation error
- irqchip/gic-v3: Fix OF_BAD_ADDR error handling
- mtd: rawnand: gpmi: Fix a double free in gpmi_nand_init
- iio: adc: Kconfig: make AD9467 depend on ADI_AXI_ADC symbol
- firmware: qcom_scm: Workaround lack of "is available" call on SC7180
- firmware: qcom_scm: Reduce locking section for __get_convention()
- firmware: qcom_scm: Make __qcom_scm_is_call_available() return bool
- m68k: mvme147,mvme16x: Don't wipe PCC timer config bits
- soundwire: stream: fix memory leak in stream config error path
- memory: pl353: fix mask of ECC page_size config register
- driver core: platform: Declare early_platform_cleanup() prototype
- drivers: nvmem: Fix voltage settings for QTI qfprom-efuse
- USB: gadget: udc: fix wrong pointer passed to IS_ERR() and PTR_ERR()
- usb: gadget: aspeed: fix dma map failure
- crypto: qat - fix error path in adf_isr_resource_alloc()
- crypto: poly1305 - fix poly1305_core_setkey() declaration
- NFSv4.2: fix copy stateid copying for the async copy
- NFSD: Fix sparse warning in nfs4proc.c
- arm64: dts: mediatek: fix reset GPIO level on pumpkin
- phy: marvell: ARMADA375_USBCLUSTER_PHY should not default to y, unconditionally
- phy: ti: j721e-wiz: Delete "clk_div_sel" clk provider during cleanup
- soundwire: bus: Fix device found flag correctly
- bus: qcom: Put child node before return
- arm64: dts: renesas: r8a779a0: Fix PMU interrupt
- mtd: require write permissions for locking and badblock ioctls
- dt-bindings: serial: stm32: Use 'type: object' instead of false for 'additionalProperties'
- usb: gadget: s3c: Fix the error handling path in 's3c2410_udc_probe()'
- usb: gadget: s3c: Fix incorrect resources releasing
- fotg210-udc: Complete OUT requests on short packets
- fotg210-udc: Don't DMA more than the buffer can take
- fotg210-udc: Mask GRP2 interrupts we don't handle
- fotg210-udc: Remove a dubious condition leading to fotg210_done
- fotg210-udc: Fix EP0 IN requests bigger than two packets
- fotg210-udc: Fix DMA on EP0 for length > max packet size
- crypto: qat - ADF_STATUS_PF_RUNNING should be set after adf_dev_init
- crypto: qat - don't release uninitialized resources
- crypto: ccp - fix command queuing to TEE ring buffer
- usb: gadget: pch_udc: Provide a GPIO line used on Intel Minnowboard (v1)
- usb: gadget: pch_udc: Initialize device pointer before use
- usb: gadget: pch_udc: Check for DMA mapping error
- usb: gadget: pch_udc: Check if driver is present before calling ->setup()
- usb: gadget: pch_udc: Replace cpu_to_le32() by lower_32_bits()
- devtmpfs: fix placement of complete() call
- x86/microcode: Check for offline CPUs before requesting new microcode
- spi: stm32: Fix use-after-free on unbind
- arm64: dts: renesas: r8a77980: Fix vin4-7 endpoint binding
- regulator: bd9576: Fix return from bd957x_probe()
- spi: stm32: drop devres version of spi_register_master
- crypto: sun8i-ss - Fix memory leak of object d when dma_iv fails to map
- arm64: dts: qcom: db845c: fix correct powerdown pin for WSA881x
- arm64: dts: qcom: sm8250: fix number of pins in 'gpio-ranges'
- arm64: dts: qcom: sm8150: fix number of pins in 'gpio-ranges'
- arm64: dts: qcom: sdm845: fix number of pins in 'gpio-ranges'
- arm64: dts: qcom: sm8250: Fix timer interrupt to specify EL2 physical timer
- arm64: dts: qcom: sm8250: Fix level triggered PMU interrupt polarity
- ARM: dts: stm32: fix usart 2 & 3 pinconf to wake up with flow control
- mtd: maps: fix error return code of physmap_flash_remove()
- mtd: don't lock when recursively deleting partitions
- mtd: rawnand: qcom: Return actual error code instead of -ENODEV
- mtd: Handle possible -EPROBE_DEFER from parse_mtd_partitions()
- mtd: rawnand: brcmnand: fix OOB R/W with Hamming ECC
- mtd: rawnand: fsmc: Fix error code in fsmc_nand_probe()
- spi: rockchip: avoid objtool warning
- regmap: set debugfs_name to NULL after it is freed
- usb: typec: stusb160x: fix return value check in stusb160x_probe()
- usb: typec: tps6598x: Fix return value check in tps6598x_probe()
- usb: typec: tcpci: Check ROLE_CONTROL while interpreting CC_STATUS
- serial: stm32: fix tx_empty condition
- serial: stm32: add FIFO flush when port is closed
- serial: stm32: fix FIFO flush in startup and set_termios
- serial: stm32: call stm32_transmit_chars locked
- serial: stm32: fix tx dma completion, release channel
- serial: stm32: fix a deadlock in set_termios
- serial: stm32: fix wake-up flag handling
- serial: stm32: fix a deadlock condition with wakeup event
- serial: stm32: fix TX and RX FIFO thresholds
- serial: stm32: fix incorrect characters on console
- serial: stm32: fix startup by enabling usart for reception
- serial: stm32: Use of_device_get_match_data()
- serial: stm32: fix probe and remove order for dma
- serial: stm32: add "_usart" prefix in functions name
- serial: stm32: fix code cleaning warnings and checks
- x86/platform/uv: Set section block size for hubless architectures
- arm64: dts: renesas: Add mmc aliases into board dts files
- ARM: dts: renesas: Add mmc aliases into R-Car Gen2 board dts files
- ARM: dts: s5pv210: correct fuel gauge interrupt trigger level on Fascinate family
- ARM: dts: exynos: correct PMIC interrupt trigger level on Snow
- ARM: dts: exynos: correct PMIC interrupt trigger level on SMDK5250
- ARM: dts: exynos: correct PMIC interrupt trigger level on Odroid X/U3 family
- ARM: dts: exynos: correct PMIC interrupt trigger level on Midas family
- ARM: dts: exynos: correct MUIC interrupt trigger level on Midas family
- ARM: dts: exynos: correct fuel gauge interrupt trigger level on Midas family
- ARM: dts: exynos: correct fuel gauge interrupt trigger level on GT-I9100
- memory: gpmc: fix out of bounds read and dereference on gpmc_cs[]
- crypto: sun8i-ss - fix result memory leak on error path
- fpga: fpga-mgr: xilinx-spi: fix error messages on -EPROBE_DEFER
- firmware: xilinx: Remove zynqmp_pm_get_eemi_ops() in IS_REACHABLE(CONFIG_ZYNQMP_FIRMWARE)
- firmware: xilinx: Add a blank line after function declaration
- firmware: xilinx: Fix dereferencing freed memory
- Revert "tools/power turbostat: adjust for temperature offset"
- usb: gadget: pch_udc: Revert d3cb25a12138 completely
- Revert "drm/qxl: do not run release if qxl failed to init"
- ovl: fix missing revert_creds() on error path
- Revert "i3c master: fix missing destroy_workqueue() on error in i3c_master_register"
- Revert "drivers/net/wan/hdlc_fr: Fix a double free in pvc_xmit"
- KVM: arm64: Fix KVM_VGIC_V3_ADDR_TYPE_REDIST_REGION read
- KVM: arm64: Fully zero the vcpu state on reset
- KVM: Stop looking for coalesced MMIO zones if the bus is destroyed
- KVM: Destroy I/O bus devices on unregister failure _after_ sync'ing SRCU
- KVM: arm/arm64: Fix KVM_VGIC_V3_ADDR_TYPE_REDIST read
- KVM: nVMX: Truncate base/index GPR value on address calc in !64-bit
- KVM: nVMX: Truncate bits 63:32 of VMCS field on nested check in !64-bit
- KVM: nVMX: Defer the MMU reload to the normal path on an EPTP switch
- KVM: SVM: Inject #GP on guest MSR_TSC_AUX accesses if RDTSCP unsupported
- KVM: SVM: Do not allow SEV/SEV-ES initialization after vCPUs are created
- KVM: SVM: Don't strip the C-bit from CR2 on #PF interception
- KVM: nSVM: Set the shadow root level to the TDP level for nested NPT
- KVM: x86: Remove emulator's broken checks on CR0/CR3/CR4 loads
- KVM: x86/mmu: Alloc page for PDPTEs when shadowing 32-bit NPT with 64-bit
- KVM: s390: extend kvm_s390_shadow_fault to return entry pointer
- KVM: s390: split kvm_s390_real_to_abs
- KVM: s390: VSIE: fix MVPG handling for prefixing and MSO
- s390: fix detection of vector enhancements facility 1 vs. vector packed decimal facility
- KVM: s390: fix guarded storage control register handling
- KVM: s390: split kvm_s390_logical_to_effective
- KVM: s390: VSIE: correctly handle MVPG when in VSIE
- ALSA: hda/realtek: Fix speaker amp on HP Envy AiO 32
- ALSA: hda/realtek: ALC285 Thinkpad jack pin quirk is unreachable
- ALSA: hda/realtek: Remove redundant entry for ALC861 Haier/Uniwill devices
- ALSA: hda/realtek: Re-order ALC662 quirk table entries
- ALSA: hda/realtek: Re-order remaining ALC269 quirk table entries
- ALSA: hda/realtek: Re-order ALC269 Lenovo quirk table entries
- ALSA: hda/realtek: Re-order ALC269 Sony quirk table entries
- ALSA: hda/realtek: Re-order ALC269 ASUS quirk table entries
- ALSA: hda/realtek: Re-order ALC269 Dell quirk table entries
- ALSA: hda/realtek: Re-order ALC269 Acer quirk table entries
- ALSA: hda/realtek: Re-order ALC269 HP quirk table entries
- ALSA: hda/realtek: Re-order ALC882 Clevo quirk table entries
- ALSA: hda/realtek: Re-order ALC882 Sony quirk table entries
- ALSA: hda/realtek: Re-order ALC882 Acer quirk table entries
- drm/amdgpu: fix concurrent VM flushes on Vega/Navi v2
- drm/amd/display: Reject non-zero src_y and src_x for video planes
- drm: bridge/panel: Cleanup connector on bridge detach
- drm/dp_mst: Set CLEAR_PAYLOAD_ID_TABLE as broadcast
- drm/dp_mst: Revise broadcast msg lct & lcr
- drm/radeon: fix copy of uninitialized variable back to userspace
- drm/panfrost: Don't try to map pages that are already mapped
- drm/panfrost: Clear MMU irqs before handling the fault
- drm/qxl: use ttm bo priorities
- drm/i915/gvt: Fix vfio_edid issue for BXT/APL
- drm/i915/gvt: Fix virtual display setup for BXT/APL
- FDDI: defxx: Make MMIO the configuration default except for EISA
- mt76: fix potential DMA mapping leak
- rtw88: Fix array overrun in rtw_get_tx_power_params()
- cfg80211: scan: drop entry from hidden_list on overflow
- ipw2x00: potential buffer overflow in libipw_wx_set_encodeext()
- mt76: mt7615: use ieee80211_free_txskb() in mt7615_tx_token_put()
- md: Fix missing unused status line of /proc/mdstat
- md: md_open returns -EBUSY when entering racing area
- md: factor out a mddev_find_locked helper from mddev_find
- md: split mddev_find
- md-cluster: fix use-after-free issue when removing rdev
- md/bitmap: wait for external bitmap writes to complete during tear down
- async_xor: increase src_offs when dropping destination page
- x86, sched: Treat Intel SNC topology as default, COD as exception
- selinux: add proper NULL termination to the secclass_map permissions
- misc: vmw_vmci: explicitly initialize vmci_datagram payload
- misc: vmw_vmci: explicitly initialize vmci_notify_bm_set_msg struct
- phy: ti: j721e-wiz: Invoke wiz_init() before of_platform_device_create()
- misc: lis3lv02d: Fix false-positive WARN on various HP models
- phy: cadence: Sierra: Fix PHY power_on sequence
- sc16is7xx: Defer probe if device read fails
- iio:adc:ad7476: Fix remove handling
- iio:accel:adis16201: Fix wrong axis assignment that prevents loading
- iio: inv_mpu6050: Fully validate gyro and accel scale writes
- soc/tegra: regulators: Fix locking up when voltage-spread is out of range
- PM / devfreq: Unlock mutex and free devfreq struct in error path
- PCI: keystone: Let AM65 use the pci_ops defined in pcie-designware-host.c
- PCI: xgene: Fix cfg resource mapping
- KVM: x86: Defer the MMU unload to the normal path on an global INVPCID
- PCI: Allow VPD access for QLogic ISP2722
- FDDI: defxx: Bail out gracefully with unassigned PCI resource for CSR
- MIPS: pci-rt2880: fix slot 0 configuration
- MIPS: pci-mt7620: fix PLL lock check
- ASoC: tlv320aic32x4: Increase maximum register in regmap
- ASoC: tlv320aic32x4: Register clocks before registering component
- ASoC: Intel: kbl_da7219_max98927: Fix kabylake_ssp_fixup function
- ASoC: samsung: tm2_wm5110: check of of_parse return value
- usb: xhci-mtk: improve bandwidth scheduling with TT
- usb: xhci-mtk: remove or operator for setting schedule parameters
- usb: typec: tcpm: update power supply once partner accepts
- usb: typec: tcpm: Address incorrect values of tcpm psy for pps supply
- usb: typec: tcpm: Address incorrect values of tcpm psy for fixed supply
- drm: bridge: fix LONTIUM use of mipi_dsi_() functions
- staging: fwserial: fix TIOCSSERIAL permission check
- tty: moxa: fix TIOCSSERIAL permission check
- staging: fwserial: fix TIOCSSERIAL jiffies conversions
- USB: serial: ti_usb_3410_5052: fix TIOCSSERIAL permission check
- staging: greybus: uart: fix TIOCSSERIAL jiffies conversions
- USB: serial: usb_wwan: fix TIOCSSERIAL jiffies conversions
- tty: amiserial: fix TIOCSSERIAL permission check
- tty: moxa: fix TIOCSSERIAL jiffies conversions
- usb: roles: Call try_module_get() from usb_role_switch_find_by_fwnode()
- Revert "USB: cdc-acm: fix rounding error in TIOCSSERIAL"
- io_uring: truncate lengths larger than MAX_RW_COUNT on provide buffers
- net/nfc: fix use-after-free llcp_sock_bind/connect
- bluetooth: eliminate the potential race condition when removing the HCI controller
- Bluetooth: verify AMP hci_chan before amp_destroy
- thermal/core/fair share: Lock the thermal zone while looping over instances
- thermal/drivers/cpufreq_cooling: Fix slab OOB issue
- lib/vsprintf.c: remove leftover 'f' and 'F' cases from bstr_printf()
- dm rq: fix double free of blk_mq_tag_set in dev remove after table load fails
- dm integrity: fix missing goto in bitmap_flush_interval error handling
- dm space map common: fix division bug in sm_ll_find_free_block()
- dm persistent data: packed struct should have an aligned() attribute too
- tracing: Restructure trace_clock_global() to never block
- tracing: Map all PIDs to command lines
- tools/power turbostat: Fix offset overflow issue in index converting
- rsi: Use resume_noirq for SDIO
- tty: fix memory leak in vc_deallocate
- usb: dwc2: Fix session request interrupt handler
- usb: dwc3: core: Do core softreset when switch mode
- usb: dwc3: gadget: Fix START_TRANSFER link state check
- usb: dwc3: gadget: Remove FS bInterval_m1 limitation
- usb: gadget/function/f_fs string table fix for multiple languages
- usb: gadget: Fix double free of device descriptor pointers
- usb: gadget: dummy_hcd: fix gpf in gadget_setup
- media: venus: hfi_parser: Don't initialize parser on v1
- media: v4l2-ctrls: fix reference to freed memory
- media: staging/intel-ipu3: Fix race condition during set_fmt
- media: staging/intel-ipu3: Fix set_fmt error handling
- media: staging/intel-ipu3: Fix memory leak in imu_fmt
- media: dvb-usb: Fix memory leak at error in dvb_usb_device_init()
- media: dvb-usb: Fix use-after-free access
- media: dvbdev: Fix memory leak in dvb_media_device_free()
- ext4: Fix occasional generic/418 failure
- ext4: allow the dax flag to be set and cleared on inline directories
- ext4: fix error return code in ext4_fc_perform_commit()
- ext4: fix ext4_error_err save negative errno into superblock
- ext4: fix error code in ext4_commit_super
- ext4: annotate data race in jbd2_journal_dirty_metadata()
- ext4: annotate data race in start_this_handle()
- kbuild: update config_data.gz only when the content of .config is changed
- x86/cpu: Initialize MSR_TSC_AUX if RDTSCP *or* RDPID is supported
- futex: Do not apply time namespace adjustment on FUTEX_LOCK_PI
- Revert 337f13046ff0 ("futex: Allow FUTEX_CLOCK_REALTIME with FUTEX_WAIT op")
- smb3: do not attempt multichannel to server which does not support it
- smb3: when mounting with multichannel include it in requested capabilities
- Fix misc new gcc warnings
- security: commoncap: fix -Wstringop-overread warning
- sfc: farch: fix TX queue lookup in TX event handling
- sfc: farch: fix TX queue lookup in TX flush done handling
- exfat: fix erroneous discard when clear cluster bit
- fuse: fix write deadlock
- dm raid: fix inconclusive reshape layout on fast raid4/5/6 table reload sequences
- md/raid1: properly indicate failure when ending a failed write request
- crypto: rng - fix crypto_rng_reset() refcounting when !CRYPTO_STATS
- crypto: arm/curve25519 - Move '.fpu' after '.arch'
- tpm: vtpm_proxy: Avoid reading host log when using a virtual device
- tpm: efi: Use local variable for calculating final log size
- intel_th: pci: Add Alder Lake-M support
- powerpc: fix EDEADLOCK redefinition error in uapi/asm/errno.h
- powerpc/32: Fix boot failure with CONFIG_STACKPROTECTOR
- powerpc/kexec_file: Use current CPU info while setting up FDT
- powerpc/eeh: Fix EEH handling for hugepages in ioremap space.
- powerpc/powernv: Enable HAIL (HV AIL) for ISA v3.1 processors
- jffs2: Hook up splice_write callback
- jffs2: Fix kasan slab-out-of-bounds problem
- Input: ili210x - add missing negation for touch indication on ili210x
- NFSv4: Don't discard segments marked for return in _pnfs_return_layout()
- NFS: Don't discard pNFS layout segments that are marked for return
- NFS: fs_context: validate UDP retrans to prevent shift out-of-bounds
- ACPI: GTDT: Don't corrupt interrupt mappings on watchdow probe failure
- openvswitch: fix stack OOB read while fragmenting IPv4 packets
- mlxsw: spectrum_mr: Update egress RIF list before route's action
- f2fs: fix to avoid out-of-bounds memory access
- f2fs: fix error handling in f2fs_end_enable_verity()
- ubifs: Only check replay with inode type to judge if inode linked
- kcsan, debugfs: Move debugfs file creation out of early init
- virtiofs: fix memory leak in virtio_fs_probe()
- fs: fix reporting supported extra file attributes for statx()
- Makefile: Move -Wno-unused-but-set-variable out of GCC only block
- arm64/vdso: Discard .note.gnu.property sections in vDSO
- btrfs: fix race when picking most recent mod log operation for an old root
- tools/power/turbostat: Fix turbostat for AMD Zen CPUs
- ALSA: hda/realtek: Add quirk for Intel Clevo PCx0Dx
- ALSA: hda/realtek: fix static noise on ALC285 Lenovo laptops
- ALSA: hda/realtek - Headset Mic issue on HP platform
- ALSA: hda/realtek: fix mic boost on Intel NUC 8
- ALSA: hda/realtek: GA503 use same quirks as GA401
- ALSA: hda/realtek: fix mute/micmute LEDs for HP ProBook 445 G7
- ALSA: usb-audio: Add dB range mapping for Sennheiser Communications Headset PC 8
- ALSA: usb-audio: Explicitly set up the clock selector
- ALSA: sb: Fix two use after free in snd_sb_qsound_build
- ALSA: hda/conexant: Re-order CX5066 quirk table entries
- ALSA: emu8000: Fix a use after free in snd_emu8000_create_mixer
- power: supply: cpcap-battery: fix invalid usage of list cursor
- sched,psi: Handle potential task count underflow bugs more gracefully
- s390/archrandom: add parameter check for s390_arch_random_generate
- block/rnbd-clt: Fix missing a memory free when unloading the module
- sched,fair: Alternative sched_slice()
- perf: Rework perf_event_exit_event()
- scsi: libfc: Fix a format specifier
- mfd: arizona: Fix rumtime PM imbalance on error
- mfd: da9063: Support SMBus and I2C mode
- mfd: intel-m10-bmc: Fix the register access range
- scsi: lpfc: Remove unsupported mbox PORT_CAPABILITIES logic
- scsi: lpfc: Fix error handling for mailboxes completed in MBX_POLL mode
- scsi: lpfc: Fix crash when a REG_RPI mailbox fails triggering a LOGO response
- drm/amdgpu: fix NULL pointer dereference
- drm/amd/display: Try YCbCr420 color when YCbCr444 fails
- amdgpu: avoid incorrect %hu format string
- drm/amdkfd: Fix cat debugfs hang_hws file causes system crash bug
- drm/amd/display: Fix UBSAN: shift-out-of-bounds warning
- drm/amd/display: Fix debugfs link_settings entry
- drm/radeon/ttm: Fix memory leak userptr pages
- drm/amdgpu/ttm: Fix memory leak userptr pages
- drm/msm/mdp5: Do not multiply vclk line count by 100
- drm/msm/mdp5: Configure PP_SYNC_HEIGHT to double the vtotal
- sched/fair: Ignore percpu threads for imbalance pulls
- media: gscpa/stv06xx: fix memory leak
- media: dvb-usb: fix memory leak in dvb_usb_adapter_init
- media: sun8i-di: Fix runtime PM imbalance in deinterlace_start_streaming
- media: platform: sti: Fix runtime PM imbalance in regs_show
- media: i2c: adv7842: fix possible use-after-free in adv7842_remove()
- media: i2c: tda1997: Fix possible use-after-free in tda1997x_remove()
- media: i2c: adv7511-v4l2: fix possible use-after-free in adv7511_remove()
- media: adv7604: fix possible use-after-free in adv76xx_remove()
- media: tc358743: fix possible use-after-free in tc358743_remove()
- power: supply: s3c_adc_battery: fix possible use-after-free in s3c_adc_bat_remove()
- power: supply: generic-adc-battery: fix possible use-after-free in gab_remove()
- clk: socfpga: arria10: Fix memory leak of socfpga_clk on error return
- drm/msm/dp: Fix incorrect NULL check kbot warnings in DP driver
- media: vivid: update EDID
- media: em28xx: fix memory leak
- scsi: scsi_dh_alua: Remove check for ASC 24h in alua_rtpg()
- scsi: smartpqi: Add new PCI IDs
- scsi: smartpqi: Correct request leakage during reset operations
- scsi: smartpqi: Use host-wide tag space
- power: supply: cpcap-charger: Add usleep to cpcap charger to avoid usb plug bounce
- selftests/resctrl: Fix checking for < 0 for unsigned values
- selftests/resctrl: Fix incorrect parsing of iMC counters
- selftests/resctrl: Use resctrl/info for feature detection
- selftests/resctrl: Fix missing options "-n" and "-p"
- selftests/resctrl: Clean up resctrl features check
- selftests/resctrl: Fix compilation issues for other global variables
- selftests/resctrl: Fix compilation issues for global variables
- selftests/resctrl: Enable gcc checks to detect buffer overflows
- nvmet: return proper error code from discovery ctrl
- drm/komeda: Fix bit check to import to value of proper type
- ata: ahci: Disable SXS for Hisilicon Kunpeng920
- mmc: sdhci-brcmstb: Remove CQE quirk
- mmc: sdhci-pci: Add PCI IDs for Intel LKF
- mmc: sdhci-esdhc-imx: validate pinctrl before use it
- scsi: qla2xxx: Fix use after free in bsg
- drm/vkms: fix misuse of WARN_ON
- scsi: qla2xxx: Always check the return value of qla24xx_get_isp_stats()
- drm/amd/display: fix dml prefetch validation
- drm/amd/display: DCHUB underflow counter increasing in some scenarios
- drm/amd/display: Fix UBSAN warning for not a valid value for type '_Bool'
- drm/amd/pm: fix workload mismatch on vega10
- drm/amdgpu : Fix asic reset regression issue introduce by 8f211fe8ac7c4f
- drm/amdkfd: Fix UBSAN shift-out-of-bounds warning
- drm/amdgpu: mask the xgmi number of hops reported from psp to kfd
- backlight: qcom-wled: Fix FSC update issue for WLED5
- backlight: qcom-wled: Use sink_addr for sync toggle
- power: supply: Use IRQF_ONESHOT
- media: gspca/sq905.c: fix uninitialized variable
- media: media/saa7164: fix saa7164_encoder_register() memory leak bugs
- extcon: arizona: Fix various races on driver unbind
- extcon: arizona: Fix some issues when HPDET IRQ fires after the jack has been unplugged
- power: supply: bq27xxx: fix power_avg for newer ICs
- atomisp: don't let it go past pipes array
- media: imx: capture: Return -EPIPE from __capture_legacy_try_fmt()
- media: drivers: media: pci: sta2x11: fix Kconfig dependency on GPIOLIB
- media: ite-cir: check for receive overflow
- scsi: target: pscsi: Fix warning in pscsi_complete_cmd()
- kvfree_rcu: Use same set of GFP flags as does single-argument
- sched/pelt: Fix task util_est update filtering
- drm/amdgpu: Fix some unload driver issues
- scsi: lpfc: Fix pt2pt connection does not recover after LOGO
- scsi: lpfc: Fix incorrect dbde assignment when building target abts wqe
- drm/amd/display/dc/dce/dce_aux: Remove duplicate line causing 'field overwritten' issue
- drm/amdgpu/display: buffer INTERRUPT_LOW_IRQ_CONTEXT interrupt work
- drm/amd/display: Don't optimize bandwidth before disabling planes
- drm/amd/display: Check for DSC support instead of ASIC revision
- drm/ast: fix memory leak when unload the driver
- drm/amd/display: changing sr exit latency
- drm/ast: Fix invalid usage of AST_MAX_HWC_WIDTH in cursor atomic_check
- drm/qxl: release shadow on shutdown
- drm/qxl: do not run release if qxl failed to init
- drm: Added orientation quirk for OneGX1 Pro
- btrfs: convert logic BUG_ON()'s in replace_path to ASSERT()'s
- btrfs: do proper error handling in btrfs_update_reloc_root
- btrfs: do proper error handling in create_reloc_root
- spi: sync up initial chipselect state
- platform/x86: intel_pmc_core: Don't use global pmcdev in quirks
- crypto: omap-aes - Fix PM reference leak on omap-aes.c
- crypto: sa2ul - Fix PM reference leak in sa_ul_probe()
- crypto: stm32/cryp - Fix PM reference leak on stm32-cryp.c
- crypto: stm32/hash - Fix PM reference leak on stm32-hash.c
- crypto: sun8i-ce - Fix PM reference leak in sun8i_ce_probe()
- crypto: sun8i-ss - Fix PM reference leak when pm_runtime_get_sync() fails
- phy: phy-twl4030-usb: Fix possible use-after-free in twl4030_usb_remove()
- intel_th: Consistency and off-by-one fix
- tty: n_gsm: check error while registering tty devices
- usb: dwc3: gadget: Check for disabled LPM quirk
- usb: core: hub: Fix PM reference leak in usb_port_resume()
- usb: musb: fix PM reference leak in musb_irq_work()
- usb: gadget: tegra-xudc: Fix possible use-after-free in tegra_xudc_remove()
- spi: qup: fix PM reference leak in spi_qup_remove()
- spi: omap-100k: Fix reference leak to master
- spi: dln2: Fix reference leak to master
- platform/x86: ISST: Account for increased timeout in some cases
- tools/power/x86/intel-speed-select: Increase string size
- ARM: dts: at91: change the key code of the gpio key
- bus: mhi: core: Clear context for stopped channels from remove()
- xhci: fix potential array out of bounds with several interrupters
- xhci: check control context is valid before dereferencing it.
- xhci: check port array allocation was successful before dereferencing it
- fpga: dfl: pci: add DID for D5005 PAC cards
- usb: xhci-mtk: support quirk to disable usb2 lpm
- random: initialize ChaCha20 constants with correct endianness
- perf/arm_pmu_platform: Fix error handling
- perf/arm_pmu_platform: Use dev_err_probe() for IRQ errors
- soundwire: cadence: only prepare attached devices on clock stop
- tee: optee: do not check memref size on return from Secure World
- arm64: dts: imx8mq-librem5-r3: Mark buck3 as always on
- soc/tegra: pmc: Fix completion of power-gate toggling
- efi/libstub: Add $(CLANG_FLAGS) to x86 flags
- x86/boot: Add $(CLANG_FLAGS) to compressed KBUILD_CFLAGS
- x86/build: Propagate $(CLANG_FLAGS) to $(REALMODE_FLAGS)
- ARM: dts: ux500: Fix up TVK R3 sensors
- ARM: dts: BCM5301X: fix "reg" formatting in /memory node
- kselftest/arm64: mte: Fix MTE feature detection
- PCI: PM: Do not read power state in pci_enable_device_flags()
- ARM: tegra: acer-a500: Rename avdd to vdda of touchscreen node
- kselftest/arm64: mte: Fix compilation with native compiler
- usb: xhci: Fix port minor revision
- usb: dwc3: gadget: Ignore EP queue requests during bus reset
- usb: gadget: f_uac1: validate input parameters
- usb: gadget: f_uac2: validate input parameters
- genirq/matrix: Prevent allocation counter corruption
- crypto: hisilicon/sec - fixes a printing error
- x86/sev: Do not require Hypervisor CPUID bit for SEV guests
- usb: webcam: Invalid size of Processing Unit Descriptor
- usb: gadget: uvc: add bInterval checking for HS mode
- crypto: qat - fix unmap invalid dma address
- crypto: api - check for ERR pointers in crypto_destroy_tfm()
- bus: mhi: core: Destroy SBL devices when moving to mission mode
- spi: ath79: remove spi-master setup and cleanup assignment
- spi: ath79: always call chipselect function
- staging: wimax/i2400m: fix byte-order issue
- bus: ti-sysc: Probe for l4_wkup and l4_cfg interconnect devices first
- cpuidle: tegra: Fix C7 idling state on Tegra114
- fbdev: zero-fill colormap in fbcmap.c
- btrfs: fix race between transaction aborts and fsyncs leading to use-after-free
- intel_th: pci: Add Rocket Lake CPU support
- btrfs: fix metadata extent leak after failure to create subvolume
- x86/build: Disable HIGHMEM64G selection for M486SX
- btrfs: handle remount to no compress during compression
- smb2: fix use-after-free in smb2_ioctl_query_info()
- cifs: detect dead connections only when echoes are enabled.
- cifs: fix out-of-bound memory access when calling smb3_notify() at mount point
- cifs: Return correct error code from smb2_get_enc_key
- irqchip/gic-v3: Do not enable irqs when handling spurious interrups
- mmc: core: Fix hanging on I/O during system suspend for removable cards
- mmc: core: Set read only for SD cards with permanent write protect bit
- mmc: core: Do a power cycle when the CMD11 fails
- mmc: block: Issue a cache flush only when it's enabled
- mmc: block: Update ext_csd.cache_ctrl if it was written
- mmc: sdhci-tegra: Add required callbacks to set/clear CQE_EN bit
- mmc: sdhci-pci: Fix initialization of some SD cards for Intel BYT-based controllers
- mmc: sdhci: Check for reset prior to DMA address unmap
- mmc: uniphier-sd: Fix a resource leak in the remove function
- mmc: uniphier-sd: Fix an error handling path in uniphier_sd_probe()
- scsi: mpt3sas: Block PCI config access from userspace during reset
- scsi: qla2xxx: Fix crash in qla2xxx_mqueuecommand()
- spi: spi-ti-qspi: Free DMA resources
- spi: stm32-qspi: fix pm_runtime usage_count counter
- erofs: add unsupported inode i_format check
- mtd: physmap: physmap-bt1-rom: Fix unintentional stack access
- mtd: rawnand: atmel: Update ecc_stats.corrected counter
- mtd: spinand: core: add missing MODULE_DEVICE_TABLE()
- Revert "mtd: spi-nor: macronix: Add support for mx25l51245g"
- mtd: spi-nor: core: Fix an issue of releasing resources during read/write
- fs/epoll: restore waking from ep_done_scan()
- ecryptfs: fix kernel panic with null dev_name
- arm64: dts: mt8173: fix property typo of 'phys' in dsi node
- arm64: dts: marvell: armada-37xx: add syscon compatible to NB clk node
- ARM: 9056/1: decompressor: fix BSS size calculation for LLVM ld.lld
- ftrace: Handle commands when closing set_ftrace_filter file
- ACPI: custom_method: fix a possible memory leak
- ACPI: custom_method: fix potential use-after-free issue
- tpm: acpi: Check eventlog signature before using it
- vhost-vdpa: fix vm_flags for virtqueue doorbell mapping
- s390/zcrypt: fix zcard and zqueue hot-unplug memleak
- s390/disassembler: increase ebpf disasm buffer size
- dyndbg: fix parsing file query without a line-range suffix
- nitro_enclaves: Fix stale file descriptors on failed usercopy
- bus: mhi: core: Sanity check values from remote device before use
- bus: mhi: core: Clear configuration from channel context during reset
- bus: mhi: core: Fix check for syserr at power_up
- vfio: Depend on MMU
- perf/core: Fix unconditional security_locked_down() call
- platform/x86: thinkpad_acpi: Correct thermal sensor allocation
- USB: Add reset-resume quirk for WD19's Realtek Hub
- USB: Add LPM quirk for Lenovo ThinkPad USB-C Dock Gen2 Ethernet
- ALSA: usb-audio: Add MIDI quirk for Vox ToneLab EX
- ovl: allow upperdir inside lowerdir
- ovl: fix leaked dentry
- nvme-pci: set min_align_mask
- swiotlb: respect min_align_mask
- swiotlb: don't modify orig_addr in swiotlb_tbl_sync_single
- swiotlb: refactor swiotlb_tbl_map_single
- swiotlb: clean up swiotlb_tbl_unmap_single
- swiotlb: factor out a nr_slots helper
- swiotlb: factor out an io_tlb_offset helper
- swiotlb: add a IO_TLB_SIZE define
- driver core: add a min_align_mask field to struct device_dma_parameters
- tools/cgroup/slabinfo.py: updated to work on current kernel
- perf ftrace: Fix access to pid in array when setting a pid filter
- capabilities: require CAP_SETFCAP to map uid 0
- perf data: Fix error return code in perf_data__create_dir()
- net: qrtr: Avoid potential use after free in MHI send
- bpf: Fix leakage of uninitialized bpf stack under speculation
- bpf: Fix masking negation logic upon negative dst register
- igb: Enable RSS for Intel I211 Ethernet Controller
- net: usb: ax88179_178a: initialize local variables before use
- netfilter: conntrack: Make global sysctls readonly in non-init netns
- mips: Do not include hi and lo in clobber list for R6
- mei: me: add Alder Lake P device id.
- iwlwifi: Fix softirq/hardirq disabling in iwl_pcie_gen2_enqueue_hcmd()
- ext4: fix check to prevent false positive report of incorrect used inodes
- iommu/arm-smmu-v3: Maintain a SID->device structure
- iommu: Add a page fault handler
- uacce: Enable IOMMU_DEV_FEAT_IOPF
- iommu/vt-d: Support IOMMU_DEV_FEAT_IOPF
- iommu: Separate IOMMU_DEV_FEAT_IOPF from IOMMU_DEV_FEAT_SVA
- iommu/arm-smmu-v3: Use device properties for pasid-num-bits
- iommu: Fix comment for struct iommu_fwspec
- iommu: Switch gather->end to the inclusive end
- iommu: Add iova and size as parameters in iotlb_sync_map
- iommu/arm-smmu-v3: Add support for VHE
- iommu/arm-smmu-v3: Make BTM optional for SVA
- iommu/arm-smmu-v3: Split arm_smmu_tlb_inv_range()
- iommu/io-pgtable: Remove tlb_flush_leaf
- iommu/arm-smmu-v3: Remove the page 1 fixup
- iommu/arm-smmu-v3: Use DEFINE_RES_MEM() to simplify code
- iommu/arm-smmu-v3: Assign boolean values to a bool variable
- iommu/arm-smmu-v3: Hook up ATC invalidation to mm ops
- iommu/arm-smmu-v3: Implement iommu_sva_bind/unbind()
- iommu/sva: Add PASID helpers
- iommu/ioasid: Add ioasid references
- ext4: do not set SB_ACTIVE in ext4_orphan_cleanup()
- arm64: Remove arm64_dma32_phys_limit and its uses
- USB: CDC-ACM: fix poison/unpoison imbalance
- net: hso: fix NULL-deref on disconnect regression
- x86/crash: Fix crash_setup_memmap_entries() out-of-bounds access
- ia64: tools: remove duplicate definition of ia64_mf() on ia64
- ia64: fix discontig.c section mismatches
- csky: change a Kconfig symbol name to fix e1000 build error
- kasan: fix hwasan build for gcc
- cavium/liquidio: Fix duplicate argument
- xen-netback: Check for hotplug-status existence before watching
- arm64: kprobes: Restore local irqflag if kprobes is cancelled
- s390/entry: save the caller of psw_idle
- dmaengine: tegra20: Fix runtime PM imbalance on error
- net: geneve: check skb is large enough for IPv4/IPv6 header
- ARM: dts: Fix swapped mmc order for omap3
- dmaengine: xilinx: dpdma: Fix race condition in done IRQ
- dmaengine: xilinx: dpdma: Fix descriptor issuing on video group
- soc: qcom: geni: shield geni_icc_get() for ACPI boot
- HID: wacom: Assign boolean values to a bool variable
- HID cp2112: fix support for multiple gpiochips
- HID: alps: fix error return code in alps_input_configured()
- HID: google: add don USB id
- perf map: Fix error return code in maps__clone()
- perf auxtrace: Fix potential NULL pointer dereference
- perf/x86/kvm: Fix Broadwell Xeon stepping in isolation_ucodes[]
- perf/x86/intel/uncore: Remove uncore extra PCI dev HSWEP_PCI_PCU_3
- locking/qrwlock: Fix ordering in queued_write_lock_slowpath()
- bpf: Tighten speculative pointer arithmetic mask
- bpf: Refactor and streamline bounds check into helper
- bpf: Allow variable-offset stack access
- bpf: Permits pointers on stack for helper calls
- arm64: dts: allwinner: Revert SD card CD GPIO for Pine64-LTS
- pinctrl: core: Show pin numbers for the controllers with base = 0
- block: return -EBUSY when there are open partitions in blkdev_reread_part
- pinctrl: lewisburg: Update number of pins in community
- vdpa/mlx5: Set err = -ENOMEM in case dma_map_sg_attrs fails
- KEYS: trusted: Fix TPM reservation for seal/unseal
- gpio: omap: Save and restore sysconfig
- vhost-vdpa: protect concurrent access to vhost device iotlb
- arm32: kaslr: Bugfix of fiq when enabled kaslr
- perf kmem: Do not pass additional arguments to 'perf record'
- arm_pmu: Fix write counter error in ARMv7 big-endian mode
- kdump: replace memblock_phys_alloc_range() with memblock_find_in_range() + memblock_reserve()
- openeuler_defconfig: Enable hifc driver as module
- scsi/hifc: add FC service module of hifc driver
- scsi/hifc: add scsi module of hifc driver
- scsi/hifc: add io module of hifc driver
- scsi/hifc: add port resource module of hifc driver
- scsi/hifc: add port manager module of hifc driver
- scsi/hifc: add chip resource module of hifc driver
- net: phy: marvell: fix detection of PHY on Topaz switches
- bpf: Move sanitize_val_alu out of op switch
- bpf: Improve verifier error messages for users
- bpf: Rework ptr_limit into alu_limit and add common error path
- arm64: mte: Ensure TIF_MTE_ASYNC_FAULT is set atomically
- ARM: 9071/1: uprobes: Don't hook on thumb instructions
- bpf: Move off_reg into sanitize_ptr_alu
- bpf: Ensure off_reg has no mixed signed bounds for all types
- r8169: don't advertise pause in jumbo mode
- r8169: tweak max read request size for newer chips also in jumbo mtu mode
- KVM: VMX: Don't use vcpu->run->internal.ndata as an array index
- KVM: VMX: Convert vcpu_vmx.exit_reason to a union
- bpf: Use correct permission flag for mixed signed bounds arithmetic
- arm64: dts: allwinner: h6: beelink-gs1: Remove ext. 32 kHz osc reference
- arm64: dts: allwinner: Fix SD card CD GPIO for SOPine systems
- ARM: OMAP2+: Fix uninitialized sr_inst
- ARM: footbridge: fix PCI interrupt mapping
- ARM: 9069/1: NOMMU: Fix conversion for_each_membock() to for_each_mem_range()
- ARM: OMAP2+: Fix warning for omap_init_time_of()
- gro: ensure frag0 meets IP header alignment
- ch_ktls: do not send snd_una update to TCB in middle
- ch_ktls: tcb close causes tls connection failure
- ch_ktls: fix device connection close
- ch_ktls: Fix kernel panic
- ibmvnic: remove duplicate napi_schedule call in open function
- ibmvnic: remove duplicate napi_schedule call in do_reset function
- ibmvnic: avoid calling napi_disable() twice
- ia64: tools: remove inclusion of ia64-specific version of errno.h header
- ia64: remove duplicate entries in generic_defconfig
- ethtool: pause: make sure we init driver stats
- i40e: fix the panic when running bpf in xdpdrv mode
- net: Make tcp_allowed_congestion_control readonly in non-init netns
- mm: ptdump: fix build failure
- net: ip6_tunnel: Unregister catch-all devices
- net: sit: Unregister catch-all devices
- net: davicom: Fix regulator not turned off on failed probe
- net/mlx5e: Fix setting of RS FEC mode
- netfilter: nft_limit: avoid possible divide error in nft_limit_init
- net/mlx5e: fix ingress_ifindex check in mlx5e_flower_parse_meta
- net: macb: fix the restore of cmp registers
- libbpf: Fix potential NULL pointer dereference
- netfilter: arp_tables: add pre_exit hook for table unregister
- netfilter: bridge: add pre_exit hooks for ebtable unregistration
- libnvdimm/region: Fix nvdimm_has_flush() to handle ND_REGION_ASYNC
- ice: Fix potential infinite loop when using u8 loop counter
- netfilter: conntrack: do not print icmpv6 as unknown via /proc
- netfilter: flowtable: fix NAT IPv6 offload mangling
- ixgbe: fix unbalanced device enable/disable in suspend/resume
- scsi: libsas: Reset num_scatter if libata marks qc as NODATA
- riscv: Fix spelling mistake "SPARSEMEM" to "SPARSMEM"
- vfio/pci: Add missing range check in vfio_pci_mmap
- arm64: alternatives: Move length validation in alternative_{insn, endif}
- arm64: fix inline asm in load_unaligned_zeropad()
- readdir: make sure to verify directory entry for legacy interfaces too
- dm verity fec: fix misaligned RS roots IO
- HID: wacom: set EV_KEY and EV_ABS only for non-HID_GENERIC type of devices
- Input: i8042 - fix Pegatron C15B ID entry
- Input: s6sy761 - fix coordinate read bit shift
- lib: fix kconfig dependency on ARCH_WANT_FRAME_POINTERS
- virt_wifi: Return micros for BSS TSF values
- mac80211: clear sta->fast_rx when STA removed from 4-addr VLAN
- pcnet32: Use pci_resource_len to validate PCI resource
- net: ieee802154: forbid monitor for add llsec seclevel
- net: ieee802154: stop dump llsec seclevels for monitors
- net: ieee802154: forbid monitor for del llsec devkey
- net: ieee802154: forbid monitor for add llsec devkey
- net: ieee802154: stop dump llsec devkeys for monitors
- net: ieee802154: forbid monitor for del llsec dev
- net: ieee802154: forbid monitor for add llsec dev
- net: ieee802154: stop dump llsec devs for monitors
- net: ieee802154: forbid monitor for del llsec key
- net: ieee802154: forbid monitor for add llsec key
- net: ieee802154: stop dump llsec keys for monitors
- iwlwifi: add support for Qu with AX201 device
- scsi: scsi_transport_srp: Don't block target in SRP_PORT_LOST state
- ASoC: fsl_esai: Fix TDM slot setup for I2S mode
- drm/msm: Fix a5xx/a6xx timestamps
- ARM: omap1: fix building with clang IAS
- ARM: keystone: fix integer overflow warning
- neighbour: Disregard DEAD dst in neigh_update
- gpu/xen: Fix a use after free in xen_drm_drv_init
- ASoC: max98373: Added 30ms turn on/off time delay
- ASoC: max98373: Changed amp shutdown register as volatile
- xfrm: BEET mode doesn't support fragments for inner packets
- iwlwifi: Fix softirq/hardirq disabling in iwl_pcie_enqueue_hcmd()
- arc: kernel: Return -EFAULT if copy_to_user() fails
- lockdep: Add a missing initialization hint to the "INFO: Trying to register non-static key" message
- ARM: dts: Fix moving mmc devices with aliases for omap4 & 5
- ARM: dts: Drop duplicate sha2md5_fck to fix clk_disable race
- ACPI: x86: Call acpi_boot_table_init() after acpi_table_upgrade()
- dmaengine: idxd: fix wq cleanup of WQCFG registers
- dmaengine: plx_dma: add a missing put_device() on error path
- dmaengine: Fix a double free in dma_async_device_register
- dmaengine: dw: Make it dependent to HAS_IOMEM
- dmaengine: idxd: fix wq size store permission state
- dmaengine: idxd: fix opcap sysfs attribute output
- dmaengine: idxd: fix delta_rec and crc size field for completion record
- dmaengine: idxd: Fix clobbering of SWERR overflow bit on writeback
- gpio: sysfs: Obey valid_mask
- Input: nspire-keypad - enable interrupts only when opened
- mtd: rawnand: mtk: Fix WAITRDY break condition and timeout
- net/sctp: fix race condition in sctp_destroy_sock
- xen/events: fix setting irq affinity
- net: sfp: cope with SFPs that set both LOS normal and LOS inverted
- net: sfp: relax bitrate-derived mode check
- perf map: Tighten snprintf() string precision to pass gcc check on some 32-bit arches
- netfilter: x_tables: fix compat match/target pad out-of-bound write
- block: don't ignore REQ_NOWAIT for direct IO
- riscv,entry: fix misaligned base for excp_vect_table
- io_uring: don't mark S_ISBLK async work as unbounded
- null_blk: fix command timeout completion handling
- idr test suite: Create anchor before launching throbber
- idr test suite: Take RCU read lock in idr_find_test_1
- radix tree test suite: Register the main thread with the RCU library
- block: only update parent bi_status when bio fail
- XArray: Fix splitting to non-zero orders
- gpu: host1x: Use different lock classes for each client
- drm/tegra: dc: Don't set PLL clock to 0Hz
- tools/kvm_stat: Add restart delay
- ftrace: Check if pages were allocated before calling free_pages()
- gfs2: report "already frozen/thawed" errors
- drm/imx: imx-ldb: fix out of bounds array access warning
- KVM: arm64: Disable guest access to trace filter controls
- KVM: arm64: Hide system instruction access to Trace registers
- gfs2: Flag a withdraw if init_threads() fails
- interconnect: core: fix error return code of icc_link_destroy()
- Revert "net: sched: bump refcount for new action in ACT replace mode"
- net: ieee802154: stop dump llsec params for monitors
- net: ieee802154: forbid monitor for del llsec seclevel
- net: ieee802154: forbid monitor for set llsec params
- net: ieee802154: fix nl802154 del llsec devkey
- net: ieee802154: fix nl802154 add llsec key
- net: ieee802154: fix nl802154 del llsec dev
- net: ieee802154: fix nl802154 del llsec key
- net: ieee802154: nl-mac: fix check on panid
- net: mac802154: Fix general protection fault
- drivers: net: fix memory leak in peak_usb_create_dev
- drivers: net: fix memory leak in atusb_probe
- net: tun: set tun->dev->addr_len during TUNSETLINK processing
- cfg80211: remove WARN_ON() in cfg80211_sme_connect
- gpiolib: Read "gpio-line-names" from a firmware node
- net: sched: bump refcount for new action in ACT replace mode
- dt-bindings: net: ethernet-controller: fix typo in NVMEM
- lockdep: Address clang -Wformat warning printing for %hd
- clk: socfpga: fix iomem pointer cast on 64-bit
- RAS/CEC: Correct ce_add_elem()'s returned values
- vdpa/mlx5: Fix wrong use of bit numbers
- vdpa/mlx5: should exclude header length and fcs from mtu
- RDMA/addr: Be strict with gid size
- i40e: Fix parameters in aq_get_phy_register()
- drm/vc4: crtc: Reduce PV fifo threshold on hvs4
- RDMA/qedr: Fix kernel panic when trying to access recv_cq
- perf report: Fix wrong LBR block sorting
- RDMA/cxgb4: check for ipv6 address properly while destroying listener
- net/mlx5: Fix PBMC register mapping
- net/mlx5: Fix PPLM register mapping
- net/mlx5: Fix placement of log_max_flow_counter
- net: hns3: clear VF down state bit before request link status
- tipc: increment the tmp aead refcnt before attaching it
- can: mcp251x: fix support for half duplex SPI host controllers
- iwlwifi: fix 11ax disabled bit in the regulatory capability flags
- i2c: designware: Adjust bus_freq_hz when refuse high speed mode set
- openvswitch: fix send of uninitialized stack memory in ct limit reply
- net: openvswitch: conntrack: simplify the return expression of ovs_ct_limit_get_default_limit()
- perf inject: Fix repipe usage
- s390/cpcmd: fix inline assembly register clobbering
- workqueue: Move the position of debug_work_activate() in __queue_work()
- clk: fix invalid usage of list cursor in unregister
- clk: fix invalid usage of list cursor in register
- net: macb: restore cmp registers on resume path
- net: cls_api: Fix uninitialised struct field bo->unlocked_driver_cb
- scsi: ufs: core: Fix wrong Task Tag used in task management request UPIUs
- scsi: ufs: core: Fix task management request completion timeout
- mptcp: forbit mcast-related sockopt on MPTCP sockets
- net: udp: Add support for getsockopt(..., ..., UDP_GRO, ..., ...);
- drm/msm: Set drvdata to NULL when msm_drm_init() fails
- RDMA/rtrs-clt: Close rtrs client conn before destroying rtrs clt session files
- i40e: Fix display statistics for veb_tc
- soc/fsl: qbman: fix conflicting alignment attributes
- xdp: fix xdp_return_frame() kernel BUG throw for page_pool memory model
- net/rds: Fix a use after free in rds_message_map_pages
- net/mlx5: Don't request more than supported EQs
- net/mlx5e: Fix ethtool indication of connector type
- net/mlx5e: Fix mapping of ct_label zero
- ASoC: sunxi: sun4i-codec: fill ASoC card owner
- I2C: JZ4780: Fix bug for Ingenic X1000.
- net: phy: broadcom: Only advertise EEE for supported modes
- nfp: flower: ignore duplicate merge hints from FW
- net: qrtr: Fix memory leak on qrtr_tx_wait failure
- net/ncsi: Avoid channel_monitor hrtimer deadlock
- ARM: dts: imx6: pbab01: Set vmmc supply for both SD interfaces
- net:tipc: Fix a double free in tipc_sk_mcast_rcv
- cxgb4: avoid collecting SGE_QBASE regs during traffic
- net: dsa: Fix type was not set for devlink port
- gianfar: Handle error code at MAC address change
- ethernet: myri10ge: Fix a use after free in myri10ge_sw_tso
- mlxsw: spectrum: Fix ECN marking in tunnel decapsulation
- can: isotp: fix msg_namelen values depending on CAN_REQUIRED_SIZE
- can: bcm/raw: fix msg_namelen values depending on CAN_REQUIRED_SIZE
- xfrm: Provide private skb extensions for segmented and hw offloaded ESP packets
- arm64: dts: imx8mm/q: Fix pad control of SD1_DATA0
- drivers/net/wan/hdlc_fr: Fix a double free in pvc_xmit
- sch_red: fix off-by-one checks in red_check_params()
- geneve: do not modify the shared tunnel info when PMTU triggers an ICMP reply
- vxlan: do not modify the shared tunnel info when PMTU triggers an ICMP reply
- amd-xgbe: Update DMA coherency values
- hostfs: fix memory handling in follow_link()
- i40e: Fix kernel oops when i40e driver removes VF's
- i40e: Added Asym_Pause to supported link modes
- virtchnl: Fix layout of RSS structures
- xfrm: Fix NULL pointer dereference on policy lookup
- ASoC: wm8960: Fix wrong bclk and lrclk with pll enabled for some chips
- ASoC: SOF: Intel: HDA: fix core status verification
- esp: delete NETIF_F_SCTP_CRC bit from features for esp offload
- net: xfrm: Localize sequence counter per network namespace
- ARM: OMAP4: PM: update ROM return address for OSWR and OFF
- ARM: OMAP4: Fix PMIC voltage domains for bionic
- regulator: bd9571mwv: Fix AVS and DVFS voltage range
- remoteproc: qcom: pil_info: avoid 64-bit division
- xfrm: Use actual socket sk instead of skb socket for xfrm_output_resume
- xfrm: interface: fix ipv4 pmtu check to honor ip header df
- ice: Recognize 860 as iSCSI port in CEE mode
- ice: Refactor DCB related variables out of the ice_port_info struct
- net: sched: fix err handler in tcf_action_init()
- KVM: x86/mmu: preserve pending TLB flush across calls to kvm_tdp_mmu_zap_sp
- KVM: x86/mmu: Don't allow TDP MMU to yield when recovering NX pages
- KVM: x86/mmu: Ensure TLBs are flushed for TDP MMU during NX zapping
- KVM: x86/mmu: Ensure TLBs are flushed when yielding during GFN range zap
- KVM: x86/mmu: Yield in TDU MMU iter even if no SPTES changed
- KVM: x86/mmu: Ensure forward progress when yielding in TDP MMU iter
- KVM: x86/mmu: Rename goal_gfn to next_last_level_gfn
- KVM: x86/mmu: Merge flush and non-flush tdp_mmu_iter_cond_resched
- KVM: x86/mmu: change TDP MMU yield function returns to match cond_resched
- i2c: turn recovery error on init to debug
- percpu: make pcpu_nr_empty_pop_pages per chunk type
- scsi: target: iscsi: Fix zero tag inside a trace event
- scsi: pm80xx: Fix chip initialization failure
- driver core: Fix locking bug in deferred_probe_timeout_work_func()
- usbip: synchronize event handler with sysfs code paths
- usbip: vudc synchronize sysfs code paths
- usbip: stub-dev synchronize sysfs code paths
- usbip: add sysfs_lock to synchronize sysfs code paths
- thunderbolt: Fix off by one in tb_port_find_retimer()
- thunderbolt: Fix a leak in tb_retimer_add()
- net: let skb_orphan_partial wake-up waiters.
- net-ipv6: bugfix - raw & sctp - switch to ipv6_can_nonlocal_bind()
- net: hsr: Reset MAC header for Tx path
- mac80211: fix TXQ AC confusion
- mac80211: fix time-is-after bug in mlme
- cfg80211: check S1G beacon compat element length
- nl80211: fix potential leak of ACL params
- nl80211: fix beacon head validation
- net: sched: fix action overwrite reference counting
- net: sched: sch_teql: fix null-pointer dereference
- vdpa/mlx5: Fix suspend/resume index restoration
- i40e: Fix sparse errors in i40e_txrx.c
- i40e: Fix sparse error: uninitialized symbol 'ring'
- i40e: Fix sparse error: 'vsi->netdev' could be null
- i40e: Fix sparse warning: missing error code 'err'
- net: ensure mac header is set in virtio_net_hdr_to_skb()
- bpf, sockmap: Fix incorrect fwd_alloc accounting
- bpf, sockmap: Fix sk->prot unhash op reset
- bpf: Refcount task stack in bpf_get_task_stack
- libbpf: Only create rx and tx XDP rings when necessary
- libbpf: Restore umem state after socket create failure
- libbpf: Ensure umem pointer is non-NULL before dereferencing
- ethernet/netronome/nfp: Fix a use after free in nfp_bpf_ctrl_msg_rx
- bpf: link: Refuse non-O_RDWR flags in BPF_OBJ_GET
- bpf: Enforce that struct_ops programs be GPL-only
- libbpf: Fix bail out from 'ringbuf_process_ring()' on error
- net: hso: fix null-ptr-deref during tty device unregistration
- ice: fix memory leak of aRFS after resuming from suspend
- iwlwifi: pcie: properly set LTR workarounds on 22000 devices
- ice: Cleanup fltr list in case of allocation issues
- ice: Use port number instead of PF ID for WoL
- ice: Fix for dereference of NULL pointer
- ice: remove DCBNL_DEVRESET bit from PF state
- ice: fix memory allocation call
- ice: prevent ice_open and ice_stop during reset
- ice: Increase control queue timeout
- ice: Continue probe on link/PHY errors
- batman-adv: initialize "struct batadv_tvlv_tt_vlan_data"->reserved field
- ARM: dts: turris-omnia: configure LED[2]/INTn pin as interrupt pin
- parisc: avoid a warning on u8 cast for cmpxchg on u8 pointers
- parisc: parisc-agp requires SBA IOMMU driver
- of: property: fw_devlink: do not link ".*,nr-gpios"
- ethtool: fix incorrect datatype in set_eee ops
- fs: direct-io: fix missing sdio->boundary
- ocfs2: fix deadlock between setattr and dio_end_io_write
- nds32: flush_dcache_page: use page_mapping_file to avoid races with swapoff
- ia64: fix user_stack_pointer() for ptrace()
- gcov: re-fix clang-11+ support
- LOOKUP_MOUNTPOINT: we are cleaning "jumped" flag too late
- IB/hfi1: Fix probe time panic when AIP is enabled with a buggy BIOS
- ACPI: processor: Fix build when CONFIG_ACPI_PROCESSOR=m
- drm/i915: Fix invalid access to ACPI _DSM objects
- net: dsa: lantiq_gswip: Configure all remaining GSWIP_MII_CFG bits
- net: dsa: lantiq_gswip: Don't use PHY auto polling
- net: dsa: lantiq_gswip: Let GSWIP automatically set the xMII clock
- net: ipv6: check for validity before dereferencing cfg->fc_nlinfo.nlh
- xen/evtchn: Change irq_info lock to raw_spinlock_t
- selinux: fix race between old and new sidtab
- selinux: fix cond_list corruption when changing booleans
- selinux: make nslot handling in avtab more robust
- nfc: Avoid endless loops caused by repeated llcp_sock_connect()
- nfc: fix memory leak in llcp_sock_connect()
- nfc: fix refcount leak in llcp_sock_connect()
- nfc: fix refcount leak in llcp_sock_bind()
- ASoC: intel: atom: Stop advertising non working S24LE support
- ALSA: hda/conexant: Apply quirk for another HP ZBook G5 model
- ALSA: hda/realtek: Fix speaker amp setup on Acer Aspire E1
- ALSA: aloop: Fix initialization of controls
- xfrm/compat: Cleanup WARN()s that can be user-triggered
- arm64: fix USER_DS definition problem in non-compat mode
- init/Kconfig: make COMPILE_TEST depend on HAS_IOMEM
- init/Kconfig: make COMPILE_TEST depend on !S390
- bpf, x86: Validate computation of branch displacements for x86-32
- bpf, x86: Validate computation of branch displacements for x86-64
- tools/resolve_btfids: Add /libbpf to .gitignore
- kbuild: Do not clean resolve_btfids if the output does not exist
- kbuild: Add resolve_btfids clean to root clean target
- tools/resolve_btfids: Set srctree variable unconditionally
- tools/resolve_btfids: Check objects before removing
- tools/resolve_btfids: Build libbpf and libsubcmd in separate directories
- math: Export mul_u64_u64_div_u64
- io_uring: fix timeout cancel return code
- cifs: Silently ignore unknown oplock break handle
- cifs: revalidate mapping when we open files for SMB1 POSIX
- ia64: fix format strings for err_inject
- ia64: mca: allocate early mca with GFP_ATOMIC
- selftests/vm: fix out-of-tree build
- scsi: target: pscsi: Clean up after failure in pscsi_map_sg()
- ptp_qoriq: fix overflow in ptp_qoriq_adjfine() u64 calcalation
- platform/x86: intel_pmc_core: Ignore GBE LTR on Tiger Lake platforms
- block: clear GD_NEED_PART_SCAN later in bdev_disk_changed
- x86/build: Turn off -fcf-protection for realmode targets
- drm/msm/disp/dpu1: icc path needs to be set before dpu runtime resume
- kselftest/arm64: sve: Do not use non-canonical FFR register value
- platform/x86: thinkpad_acpi: Allow the FnLock LED to change state
- net: ipa: fix init header command validation
- netfilter: nftables: skip hook overlap logic if flowtable is stale
- netfilter: conntrack: Fix gre tunneling over ipv6
- drm/msm: Ratelimit invalid-fence message
- drm/msm/adreno: a5xx_power: Don't apply A540 lm_setup to other GPUs
- drm/msm/dsi_pll_7nm: Fix variable usage for pll_lockdet_rate
- mac80211: choose first enabled channel for monitor
- mac80211: Check crypto_aead_encrypt for errors
- mISDN: fix crash in fritzpci
- kunit: tool: Fix a python tuple typing error
- net: pxa168_eth: Fix a potential data race in pxa168_eth_remove
- net/mlx5e: Enforce minimum value check for ICOSQ size
- bpf, x86: Use kvmalloc_array instead kmalloc_array in bpf_jit_comp
- platform/x86: intel-hid: Support Lenovo ThinkPad X1 Tablet Gen 2
- bus: ti-sysc: Fix warning on unbind if reset is not deasserted
- ARM: dts: am33xx: add aliases for mmc interfaces
- bpf: Use NOP_ATOMIC5 instead of emit_nops(&prog, 5) for BPF_TRAMP_F_CALL_ORIG
- Revert "kernel: freezer should treat PF_IO_WORKER like PF_KTHREAD for freezing"
- riscv: evaluate put_user() arg before enabling user access
- drivers: video: fbcon: fix NULL dereference in fbcon_cursor()
- driver core: clear deferred probe reason on probe retry
- staging: rtl8192e: Change state information from u16 to u8
- staging: rtl8192e: Fix incorrect source in memcpy()
- soc: qcom-geni-se: Cleanup the code to remove proxy votes
- usb: dwc3: gadget: Clear DEP flags after stop transfers in ep disable
- usb: dwc3: qcom: skip interconnect init for ACPI probe
- usb: dwc2: Prevent core suspend when port connection flag is 0
- usb: dwc2: Fix HPRT0.PrtSusp bit setting for HiKey 960 board.
- usb: gadget: udc: amd5536udc_pci fix null-ptr-dereference
- USB: cdc-acm: fix use-after-free after probe failure
- USB: cdc-acm: fix double free on probe failure
- USB: cdc-acm: downgrade message to debug
- USB: cdc-acm: untangle a circular dependency between callback and softint
- cdc-acm: fix BREAK rx code path adding necessary calls
- usb: xhci-mtk: fix broken streams issue on 0.96 xHCI
- usb: musb: Fix suspend with devices connected for a64
- USB: quirks: ignore remote wake-up on Fibocom L850-GL LTE modem
- usbip: vhci_hcd fix shift out-of-bounds in vhci_hub_control()
- firewire: nosy: Fix a use-after-free bug in nosy_ioctl()
- video: hyperv_fb: Fix a double free in hvfb_probe
- usb: dwc3: pci: Enable dis_uX_susphy_quirk for Intel Merrifield
- firmware: stratix10-svc: reset COMMAND_RECONFIG_FLAG_PARTIAL to 0
- extcon: Fix error handling in extcon_dev_register
- extcon: Add stubs for extcon_register_notifier_all() functions
- pinctrl: rockchip: fix restore error in resume
- vfio/nvlink: Add missing SPAPR_TCE_IOMMU depends
- drm/tegra: sor: Grab runtime PM reference across reset
- drm/tegra: dc: Restore coupling of display controllers
- drm/imx: fix memory leak when fails to init
- reiserfs: update reiserfs_xattrs_initialized() condition
- drm/amdgpu: check alignment on CPU page for bo map
- drm/amdgpu: fix offset calculation in amdgpu_vm_bo_clear_mappings()
- drm/amdkfd: dqm fence memory corruption
- mm: fix race by making init_zero_pfn() early_initcall
- s390/vdso: fix tod_steering_delta type
- s390/vdso: copy tod_steering_delta value to vdso_data page
- tracing: Fix stack trace event size
- PM: runtime: Fix ordering in pm_runtime_get_suppliers()
- PM: runtime: Fix race getting/putting suppliers at probe
- KVM: SVM: ensure that EFER.SVME is set when running nested guest or on nested vmexit
- KVM: SVM: load control fields from VMCB12 before checking them
- xtensa: move coprocessor_flush to the .text section
- xtensa: fix uaccess-related livelock in do_page_fault
- ALSA: hda/realtek: fix mute/micmute LEDs for HP 640 G8
- ALSA: hda/realtek: call alc_update_headset_mode() in hp_automute_hook
- ALSA: hda/realtek: fix a determine_headset_type issue for a Dell AIO
- ALSA: hda: Add missing sanity checks in PM prepare/complete callbacks
- ALSA: hda: Re-add dropped snd_poewr_change_state() calls
- ALSA: usb-audio: Apply sample rate quirk to Logitech Connect
- ACPI: processor: Fix CPU0 wakeup in acpi_idle_play_dead()
- ACPI: tables: x86: Reserve memory occupied by ACPI tables
- bpf: Remove MTU check in __bpf_skb_max_len
- net: 9p: advance iov on empty read
- net: wan/lmc: unregister device when no matching device is found
- net: ipa: fix register write command validation
- net: ipa: remove two unused register definitions
- appletalk: Fix skb allocation size in loopback case
- net: ethernet: aquantia: Handle error cleanup of start on open
- ath10k: hold RCU lock when calling ieee80211_find_sta_by_ifaddr()
- iwlwifi: pcie: don't disable interrupts for reg_lock
- netdevsim: dev: Initialize FIB module after debugfs
- rtw88: coex: 8821c: correct antenna switch function
- ath11k: add ieee80211_unregister_hw to avoid kernel crash caused by NULL pointer
- brcmfmac: clear EAP/association status bits on linkdown events
- can: tcan4x5x: fix max register value
- net: introduce CAN specific pointer in the struct net_device
- can: dev: move driver related infrastructure into separate subdir
- flow_dissector: fix TTL and TOS dissection on IPv4 fragments
- net: mvpp2: fix interrupt mask/unmask skip condition
- io_uring: call req_set_fail_links() on short send[msg]()/recv[msg]() with MSG_WAITALL
- ext4: do not iput inode under running transaction in ext4_rename()
- static_call: Align static_call_is_init() patching condition
- io_uring: imply MSG_NOSIGNAL for send[msg]()/recv[msg]() calls
- nvmet-tcp: fix kmap leak when data digest in use
- locking/ww_mutex: Fix acquire/release imbalance in ww_acquire_init()/ww_acquire_fini()
- locking/ww_mutex: Simplify use_ww_ctx & ww_ctx handling
- thermal/core: Add NULL pointer check before using cooling device stats
- ASoC: rt711: add snd_soc_component remove callback
- ASoC: rt5659: Update MCLK rate in set_sysclk()
- staging: comedi: cb_pcidas64: fix request_irq() warn
- staging: comedi: cb_pcidas: fix request_irq() warn
- scsi: qla2xxx: Fix broken #endif placement
- scsi: st: Fix a use after free in st_open()
- io_uring: fix ->flags races by linked timeouts
- vhost: Fix vhost_vq_reset()
- kernel: freezer should treat PF_IO_WORKER like PF_KTHREAD for freezing
- NFSD: fix error handling in NFSv4.0 callbacks
- ASoC: cs42l42: Always wait at least 3ms after reset
- ASoC: cs42l42: Fix mixer volume control
- ASoC: cs42l42: Fix channel width support
- ASoC: cs42l42: Fix Bitclock polarity inversion
- ASoC: soc-core: Prevent warning if no DMI table is present
- ASoC: es8316: Simplify adc_pga_gain_tlv table
- ASoC: sgtl5000: set DAP_AVC_CTRL register to correct default value on probe
- ASoC: rt5651: Fix dac- and adc- vol-tlv values being off by a factor of 10
- ASoC: rt5640: Fix dac- and adc- vol-tlv values being off by a factor of 10
- ASoC: rt1015: fix i2c communication error
- iomap: Fix negative assignment to unsigned sis->pages in iomap_swapfile_activate
- rpc: fix NULL dereference on kmalloc failure
- fs: nfsd: fix kconfig dependency warning for NFSD_V4
- ext4: fix bh ref count on error paths
- ext4: shrink race window in ext4_should_retry_alloc()
- virtiofs: Fail dax mount if device does not support it
- bpf: Fix fexit trampoline.
- arm64: mm: correct the inside linear map range during hotplug check
- io_uring: convert io_buffer_idr to XArray
- io_uring: Convert personality_idr to XArray
- io_uring: simplify io_remove_personalities()
- posix-timers: Preserve return value in clock_adjtime32()
- arm64: fix current_thread_info()->addr_limit setup
- xen-blkback: don't leak persistent grants from xen_blkbk_map()
- can: peak_usb: Revert "can: peak_usb: add forgotten supported devices"
- nvme: fix the nsid value to print in nvme_validate_or_alloc_ns
- Revert "net: bonding: fix error return code of bond_neigh_init()"
- Revert "xen: fix p2m size in dom0 for disabled memory hotplug case"
- fs/ext4: fix integer overflow in s_log_groups_per_flex
- ext4: add reclaim checks to xattr code
- mac80211: fix double free in ibss_leave
- net: dsa: b53: VLAN filtering is global to all users
- r8169: fix DMA being used after buffer free if WoL is enabled
- can: dev: Move device back to init netns on owning netns delete
- ch_ktls: fix enum-conversion warning
- fs/cachefiles: Remove wait_bit_key layout dependency
- mm/memcg: fix 5.10 backport of splitting page memcg
- x86/mem_encrypt: Correct physical address calculation in __set_clr_pte_enc()
- locking/mutex: Fix non debug version of mutex_lock_io_nested()
- cifs: Adjust key sizes and key generation routines for AES256 encryption
- smb3: fix cached file size problems in duplicate extents (reflink)
- scsi: mpt3sas: Fix error return code of mpt3sas_base_attach()
- scsi: qedi: Fix error return code of qedi_alloc_global_queues()
- scsi: Revert "qla2xxx: Make sure that aborted commands are freed"
- block: recalculate segment count for multi-segment discards correctly
- io_uring: fix provide_buffers sign extension
- perf synthetic events: Avoid write of uninitialized memory when generating PERF_RECORD_MMAP* records
- perf auxtrace: Fix auxtrace queue conflict
- ACPI: scan: Use unique number for instance_no
- ACPI: scan: Rearrange memory allocation in acpi_device_add()
- Revert "netfilter: x_tables: Update remaining dereference to RCU"
- mm/mmu_notifiers: ensure range_end() is paired with range_start()
- dm table: Fix zoned model check and zone sectors check
- netfilter: x_tables: Use correct memory barriers.
- Revert "netfilter: x_tables: Switch synchronization to RCU"
- net: phy: broadcom: Fix RGMII delays for BCM50160 and BCM50610M
- net: phy: broadcom: Set proper 1000BaseX/SGMII interface mode for BCM54616S
- net: phy: broadcom: Avoid forward for bcm54xx_config_clock_delay()
- net: phy: introduce phydev->port
- net: axienet: Fix probe error cleanup
- net: axienet: Properly handle PCS/PMA PHY for 1000BaseX mode
- igb: avoid premature Rx buffer reuse
- net, bpf: Fix ip6ip6 crash with collect_md populated skbs
- net: Consolidate common blackhole dst ops
- bpf: Don't do bpf_cgroup_storage_set() for kuprobe/tp programs
- RDMA/cxgb4: Fix adapter LE hash errors while destroying ipv6 listening server
- xen/x86: make XEN_BALLOON_MEMORY_HOTPLUG_LIMIT depend on MEMORY_HOTPLUG
- octeontx2-af: Fix memory leak of object buf
- net: bridge: don't notify switchdev for local FDB addresses
- PM: EM: postpone creating the debugfs dir till fs_initcall
- net/mlx5e: Fix error path for ethtool set-priv-flag
- net/mlx5e: Offload tuple rewrite for non-CT flows
- net/mlx5e: Allow to match on MPLS parameters only for MPLS over UDP
- net/mlx5: Add back multicast stats for uplink representor
- PM: runtime: Defer suspending suppliers
- arm64: kdump: update ppos when reading elfcorehdr
- drm/msm: Fix suspend/resume on i.MX5
- drm/msm: fix shutdown hook in case GPU components failed to bind
- can: isotp: tx-path: zero initialize outgoing CAN frames
- bpf: Fix umd memory leak in copy_process()
- libbpf: Fix BTF dump of pointer-to-array-of-struct
- selftests: forwarding: vxlan_bridge_1d: Fix vxlan ecn decapsulate value
- selinux: vsock: Set SID for socket returned by accept()
- net: stmmac: dwmac-sun8i: Provide TX and RX fifo sizes
- r8152: limit the RX buffer size of RTL8153A for USB 2.0
- igb: check timestamp validity
- net: cdc-phonet: fix data-interface release on probe failure
- net: check all name nodes in __dev_alloc_name
- octeontx2-af: fix infinite loop in unmapping NPC counter
- octeontx2-pf: Clear RSS enable flag on interace down
- octeontx2-af: Fix irq free in rvu teardown
- octeontx2-af: Remove TOS field from MKEX TX
- octeontx2-af: Modify default KEX profile to extract TX packet fields
- octeontx2-af: Formatting debugfs entry rsrc_alloc.
- ipv6: weaken the v4mapped source check
- ARM: dts: imx6ull: fix ubi filesystem mount failed
- libbpf: Use SOCK_CLOEXEC when opening the netlink socket
- libbpf: Fix error path in bpf_object__elf_init()
- netfilter: flowtable: Make sure GC works periodically in idle system
- netfilter: nftables: allow to update flowtable flags
- netfilter: nftables: report EOPNOTSUPP on unsupported flowtable flags
- net/sched: cls_flower: fix only mask bit check in the validate_ct_state
- ionic: linearize tso skb with too many frags
- drm/msm/dsi: fix check-before-set in the 7nm dsi_pll code
- ftrace: Fix modify_ftrace_direct.
- nfp: flower: fix pre_tun mask id allocation
- nfp: flower: add ipv6 bit to pre_tunnel control message
- nfp: flower: fix unsupported pre_tunnel flows
- selftests/net: fix warnings on reuseaddr_ports_exhausted
- mac80211: Allow HE operation to be longer than expected.
- mac80211: fix rate mask reset
- can: m_can: m_can_rx_peripheral(): fix RX being blocked by errors
- can: m_can: m_can_do_rx_poll(): fix extraneous msg loss warning
- can: c_can: move runtime PM enable/disable to c_can_platform
- can: c_can_pci: c_can_pci_remove(): fix use-after-free
- can: kvaser_pciefd: Always disable bus load reporting
- can: flexcan: flexcan_chip_freeze(): fix chip freeze for missing bitrate
- can: peak_usb: add forgotten supported devices
- can: isotp: TX-path: ensure that CAN frame flags are initialized
- can: isotp: isotp_setsockopt(): only allow to set low level TX flags for CAN-FD
- tcp: relookup sock for RST+ACK packets handled by obsolete req sock
- tipc: better validate user input in tipc_nl_retrieve_key()
- net: phylink: Fix phylink_err() function name error in phylink_major_config
- net: hdlc_x25: Prevent racing between "x25_close" and "x25_xmit"/"x25_rx"
- netfilter: ctnetlink: fix dump of the expect mask attribute
- selftests/bpf: Set gopt opt_class to 0 if get tunnel opt failed
- flow_dissector: fix byteorder of dissected ICMP ID
- net: qrtr: fix a kernel-infoleak in qrtr_recvmsg()
- net: ipa: terminate message handler arrays
- clk: qcom: gcc-sc7180: Use floor ops for the correct sdcc1 clk
- ftgmac100: Restart MAC HW once
- net: phy: broadcom: Add power down exit reset state delay
- net/qlcnic: Fix a use after free in qlcnic_83xx_get_minidump_template
- e1000e: Fix error handling in e1000_set_d0_lplu_state_82571
- e1000e: add rtnl_lock() to e1000_reset_task
- igc: Fix igc_ptp_rx_pktstamp()
- igc: Fix Supported Pause Frame Link Setting
- igc: Fix Pause Frame Advertising
- igc: reinit_locked() should be called with rtnl_lock
- net: dsa: bcm_sf2: Qualify phydev->dev_flags based on port
- net: sched: validate stab values
- macvlan: macvlan_count_rx() needs to be aware of preemption
- drop_monitor: Perform cleanup upon probe registration failure
- ipv6: fix suspecious RCU usage warning
- net/mlx5e: Don't match on Geneve options in case option masks are all zero
- net/mlx5e: When changing XDP program without reset, take refs for XSK RQs
- net/mlx5e: RX, Mind the MPWQE gaps when calculating offsets
- libbpf: Fix INSTALL flag order
- bpf: Change inode_storage's lookup_elem return value from NULL to -EBADF
- veth: Store queue_mapping independently of XDP prog presence
- soc: ti: omap-prm: Fix occasional abort on reset deassert for dra7 iva
- ARM: OMAP2+: Fix smartreflex init regression after dropping legacy data
- bus: omap_l3_noc: mark l3 irqs as IRQF_NO_THREAD
- dm ioctl: fix out of bounds array access when no devices
- dm verity: fix DM_VERITY_OPTS_MAX value
- drm/i915: Fix the GT fence revocation runtime PM logic
- drm/amdgpu: Add additional Sienna Cichlid PCI ID
- drm/amdgpu/display: restore AUX_DPHY_TX_CONTROL for DCN2.x
- drm/amd/pm: workaround for audio noise issue
- drm/etnaviv: Use FOLL_FORCE for userptr
- integrity: double check iint_cache was initialized
- ARM: dts: at91-sama5d27_som1: fix phy address to 7
- ARM: dts: at91: sam9x60: fix mux-mask to match product's datasheet
- ARM: dts: at91: sam9x60: fix mux-mask for PA7 so it can be set to A, B and C
- arm64: dts: ls1043a: mark crypto engine dma coherent
- arm64: dts: ls1012a: mark crypto engine dma coherent
- arm64: dts: ls1046a: mark crypto engine dma coherent
- arm64: stacktrace: don't trace arch_stack_walk()
- ACPICA: Always create namespace nodes using acpi_ns_create_node()
- ACPI: video: Add missing callback back for Sony VPCEH3U1E
- gcov: fix clang-11+ support
- kasan: fix per-page tags for non-page_alloc pages
- hugetlb_cgroup: fix imbalanced css_get and css_put pair for shared mappings
- squashfs: fix xattr id and id lookup sanity checks
- squashfs: fix inode lookup sanity checks
- z3fold: prevent reclaim/free race for headless pages
- psample: Fix user API breakage
- platform/x86: intel-vbtn: Stop reporting SW_DOCK events
- netsec: restore phy power state after controller reset
- selinux: fix variable scope issue in live sidtab conversion
- selinux: don't log MAC_POLICY_LOAD record on failed policy load
- btrfs: fix sleep while in non-sleep context during qgroup removal
- KVM: x86: Protect userspace MSR filter with SRCU, and set atomically-ish
- static_call: Fix static_call_set_init()
- static_call: Fix the module key fixup
- static_call: Allow module use without exposing static_call_key
- static_call: Pull some static_call declarations to the type headers
- ia64: fix ptrace(PTRACE_SYSCALL_INFO_EXIT) sign
- ia64: fix ia64_syscall_get_set_arguments() for break-based syscalls
- mm/fork: clear PASID for new mm
- block: Suppress uevent for hidden device when removed
- nfs: we don't support removing system.nfs4_acl
- nvme-pci: add the DISABLE_WRITE_ZEROES quirk for a Samsung PM1725a
- nvme-rdma: Fix a use after free in nvmet_rdma_write_data_done
- nvme-core: check ctrl css before setting up zns
- nvme-fc: return NVME_SC_HOST_ABORTED_CMD when a command has been aborted
- nvme-fc: set NVME_REQ_CANCELLED in nvme_fc_terminate_exchange()
- nvme: add NVME_REQ_CANCELLED flag in nvme_cancel_request()
- nvme: simplify error logic in nvme_validate_ns()
- drm/radeon: fix AGP dependency
- drm/amdgpu: fb BO should be ttm_bo_type_device
- drm/amd/display: Revert dram_clock_change_latency for DCN2.1
- block: Fix REQ_OP_ZONE_RESET_ALL handling
- regulator: qcom-rpmh: Correct the pmic5_hfsmps515 buck
- kselftest: arm64: Fix exit code of sve-ptrace
- u64_stats,lockdep: Fix u64_stats_init() vs lockdep
- staging: rtl8192e: fix kconfig dependency on CRYPTO
- habanalabs: Call put_pid() when releasing control device
- sparc64: Fix opcode filtering in handling of no fault loads
- umem: fix error return code in mm_pci_probe()
- kbuild: dummy-tools: fix inverted tests for gcc
- kbuild: add image_name to no-sync-config-targets
- irqchip/ingenic: Add support for the JZ4760
- cifs: change noisy error message to FYI
- atm: idt77252: fix null-ptr-dereference
- atm: uPD98402: fix incorrect allocation
- net: enetc: set MAC RX FIFO to recommended value
- net: davicom: Use platform_get_irq_optional()
- net: wan: fix error return code of uhdlc_init()
- net: hisilicon: hns: fix error return code of hns_nic_clear_all_rx_fetch()
- NFS: Correct size calculation for create reply length
- nfs: fix PNFS_FLEXFILE_LAYOUT Kconfig default
- gpiolib: acpi: Add missing IRQF_ONESHOT
- cpufreq: blacklist Arm Vexpress platforms in cpufreq-dt-platdev
- gfs2: fix use-after-free in trans_drain
- cifs: ask for more credit on async read/write code paths
- gianfar: fix jumbo packets+napi+rx overrun crash
- sun/niu: fix wrong RXMAC_BC_FRM_CNT_COUNT count
- net: intel: iavf: fix error return code of iavf_init_get_resources()
- net: tehuti: fix error return code in bdx_probe()
- blk-cgroup: Fix the recursive blkg rwstat
- scsi: ufs: ufs-qcom: Disable interrupt in reset path
- ixgbe: Fix memleak in ixgbe_configure_clsu32
- ALSA: hda: ignore invalid NHLT table
- Revert "r8152: adjust the settings about MAC clock speed down for RTL8153"
- atm: lanai: dont run lanai_dev_close if not open
- atm: eni: dont release is never initialized
- powerpc/4xx: Fix build errors from mfdcr()
- net: fec: ptp: avoid register access when ipg clock is disabled
- net: stmmac: fix dma physical address of descriptor when display ring
- mt76: fix tx skb error handling in mt76_dma_tx_queue_skb
- mm/memcg: set memcg when splitting page
- mm/memcg: rename mem_cgroup_split_huge_fixup to split_page_memcg and add nr_pages argument
- kvm: debugfs: add EXIT_REASON_PREEMPTION_TIMER to vcpu_stat
- kvm: debugfs: add fastpath msr_wr exits to debugfs statistics
- arm64/mpam: fix a possible deadlock in mpam_enable
- RDMA/hns: Optimize the base address table config for MTR
- fs: fix files.usage bug when move tasks
- files_cgroup: fix error pointer when kvm_vm_worker_thread
- fs/filescontrol: add a switch to enable / disable accounting of open fds
- cgroup/files: use task_get_css() to get a valid css during dup_fd()
- cgroups: Resource controller for open files
- openeuler_defconfig: enable CONFIG_CGROUP_FILES by default
- x86: config: disable CONFIG_BOOTPARAM_HOTPLUG_CPU0 by default
- ima: fix a memory leak in ima_del_digest_data_entry
- config: add digest list options for arm64 and x86
- evm: Propagate choice of HMAC algorithm in evm_crypto.c
- evm: Extend evm= with x509. allow_metadata_writes and complete values
- ima: Execute parser to upload digest lists not recognizable by the kernel
- ima: Add parser keyword to the policy
- ima: Allow direct upload of digest lists to securityfs
- ima: Search key in the built-in keyrings
- certs: Introduce search_trusted_key()
- KEYS: Introduce load_pgp_public_keyring()
- KEYS: Provide a function to load keys from a PGP keyring blob
- KEYS: Provide PGP key description autogeneration
- KEYS: PGP data parser
- PGPLIB: Basic packet parser
- PGPLIB: PGP definitions (RFC 4880)
- rsa: add parser of raw format
- mpi: introduce mpi_key_length()
- evm: Reset status even when security.evm is modified
- ima: Add Documentation/security/IMA-digest-lists.txt
- ima: Introduce appraise_exec_immutable policy
- ima: Introduce appraise_exec_tcb policy
- ima: Introduce exec_tcb policy
- ima: Add meta_immutable appraisal type
- evm: Add support for digest lists of metadata
- ima: Add support for appraisal with digest lists
- ima: Add support for measurement with digest lists
- ima: Load all digest lists from a directory at boot time
- ima: Introduce new hook DIGEST_LIST_CHECK
- ima: Introduce new securityfs files
- ima: Prevent usage of digest lists not measured or appraised
- ima: Add parser of compact digest list
- ima: Use ima_show_htable_value to show violations and hash table data
- ima: Generalize policy file operations
- ima: Generalize ima_write_policy() and raise uploaded data size limit
- ima: Generalize ima_read_policy()
- ima: Allow choice of file hash algorithm for measurement and audit
- ima: Add enforce-evm and log-evm modes to strictly check EVM status
- init: Add kernel option to force usage of tmpfs for rootfs
- gen_init_cpio: add support for file metadata
- initramfs: read metadata from special file METADATA!!!
- initramfs: add file metadata
- ima: Don't remove security.ima if file must not be appraised
- ima: Introduce template field evmsig and write to field sig as fallback
- ima: Allow imasig requirement to be satisfied by EVM portable signatures
- evm: Allow setxattr() and setattr() for unmodified metadata
- evm: Allow xattr/attr operations for portable signatures
- evm: Ignore INTEGRITY_NOLABEL/INTEGRITY_NOXATTRS if conditions are safe
- evm: Introduce evm_status_revalidate()
- ima: Move ima_reset_appraise_flags() call to post hooks
- evm: Refuse EVM_ALLOW_METADATA_WRITES only if an HMAC key is loaded
- evm: Load EVM key in ima_load_x509() to avoid appraisal
- evm: Execute evm_inode_init_security() only when an HMAC key is loaded
- cgroup: disable kernel memory accounting for all memory cgroups by default
- etmem: Modify the memig feature name to etmem
- memig: fix compile error when CONFIG_NUMA is turned off
- memig: add memig-swap feature to openEuler
- memig: add memig-scan feature to openEuler
- arm64: fix compile error when CONFIG_ACPI is not enabled
- arm64: ipi_nmi: fix compile error when CONFIG_KGDB is disabled
- arm64: kgdb: Roundup cpus using IPI as NMI
- kgdb: Expose default CPUs roundup fallback mechanism
- arm64: ipi_nmi: Add support for NMI backtrace
- nmi: backtrace: Allow runtime arch specific override
- arm64: smp: Assign and setup an IPI as NMI
- irqchip/gic-v3: Enable support for SGIs to act as NMIs
- arm64: Add framework to turn IPI as NMI
- openeuler_defconfig: Enable NMI watchdog
- arm64: watchdog: add switch to select sdei_watchdog/pmu_watchdog
- arm64: add new config CONFIG_PMU_WATCHDOG
- arm64: Add support for hard lockup by using pmu counter
- config: enable CONFIG_CPU_IDLE_GOV_HALTPOLL and CONFIG_HALTPOLL_CPUIDLE for arm
- ARM: cpuidle: Add support for cpuidle-haltpoll driver for ARM
- cpuidle: haltpoll: Only check boot_option_idle_override in x86
- arm64: Add some definitions of kvm_para*
- cpuidle-haltpoll: Use arch_cpu_idle() to replace default_idle()
- arm64: Optimize ttwu IPI
- kvm: arm64: add KVM_CAP_ARM_CPU_FEATURE extension
- kvm: arm64: make ID_AA64PFR0_EL1 configurable
- kvm: arm64: make ID registers configurable
- kvm: arm64: emulate the ID registers
- arm64: add a helper function to traverse arm64_ftr_regs
- KVM: arm64: Add tracepoints for PV qspinlock
- KVM: arm64: Enable PV qspinlock
- KVM: arm64: Add interface to support PV qspinlock
- KVM: arm64: Implement PV_SCHED_KICK_CPU call
- KVM: arm64: Add SMCCC PV-sched to kick cpu
- KVM: arm64: Support the vCPU preemption check
- KVM: arm64: Add interface to support vCPU preempted check
- KVM: arm64: Support pvsched preempted via shared structure
- KVM: arm64: Implement PV_SCHED_FEATURES call
- KVM: arm64: Document PV-sched interface
- arm64: fix the compile error when CONFIG_NUMA is disabled
- arm64: Add CPU hotplug support
- arm64: mark all the GICC nodes in MADT as possible cpu
- loop: fix I/O error on fsync() in detached loop devices
- sysrq: avoid concurrently info printing by 'sysrq-trigger'
- jffs2: check the validity of dstlen in jffs2_zlib_compress()
- cifs: Fix preauth hash corruption
- x86/apic/of: Fix CPU devicetree-node lookups
- genirq: Disable interrupts for force threaded handlers
- firmware/efi: Fix a use after bug in efi_mem_reserve_persistent
- efi: use 32-bit alignment for efi_guid_t literals
- static_call: Fix static_call_update() sanity check
- MAINTAINERS: move the staging subsystem to lists.linux.dev
- MAINTAINERS: move some real subsystems off of the staging mailing list
- ext4: fix rename whiteout with fast commit
- ext4: fix potential error in ext4_do_update_inode
- ext4: do not try to set xattr into ea_inode if value is empty
- ext4: stop inode update before return
- ext4: fix error handling in ext4_end_enable_verity()
- efivars: respect EFI_UNSUPPORTED return from firmware
- x86: Introduce TS_COMPAT_RESTART to fix get_nr_restart_syscall()
- x86: Move TS_COMPAT back to asm/thread_info.h
- kernel, fs: Introduce and use set_restart_fn() and arch_set_restart_data()
- x86/ioapic: Ignore IRQ2 again
- perf/x86/intel: Fix unchecked MSR access error caused by VLBR_EVENT
- perf/x86/intel: Fix a crash caused by zero PEBS status
- PCI: rpadlpar: Fix potential drc_name corruption in store functions
- counter: stm32-timer-cnt: fix ceiling miss-alignment with reload register
- counter: stm32-timer-cnt: fix ceiling write max value
- iio: hid-sensor-temperature: Fix issues of timestamp channel
- iio: hid-sensor-prox: Fix scale not correct issue
- iio: hid-sensor-humidity: Fix alignment issue of timestamp channel
- iio: adc: adi-axi-adc: add proper Kconfig dependencies
- iio: adc: ad7949: fix wrong ADC result due to incorrect bit mask
- iio: adc: ab8500-gpadc: Fix off by 10 to 3
- iio: gyro: mpu3050: Fix error handling in mpu3050_trigger_handler
- iio: adis16400: Fix an error code in adis16400_initial_setup()
- iio:adc:qcom-spmi-vadc: add default scale to LR_MUX2_BAT_ID channel
- iio:adc:stm32-adc: Add HAS_IOMEM dependency
- thunderbolt: Increase runtime PM reference count on DP tunnel discovery
- thunderbolt: Initialize HopID IDAs in tb_switch_alloc()
- usb: dwc3: gadget: Prevent EP queuing while stopping transfers
- usb: dwc3: gadget: Allow runtime suspend if UDC unbinded
- usb: typec: tcpm: Invoke power_supply_changed for tcpm-source-psy-
- usb: typec: Remove vdo[3] part of tps6598x_rx_identity_reg struct
- usb: gadget: configfs: Fix KASAN use-after-free
- usbip: Fix incorrect double assignment to udc->ud.tcp_rx
- usb-storage: Add quirk to defeat Kindle's automatic unload
- powerpc: Force inlining of cpu_has_feature() to avoid build failure
- gfs2: bypass signal_our_withdraw if no journal
- gfs2: move freeze glock outside the make_fs_rw and _ro functions
- gfs2: Add common helper for holding and releasing the freeze glock
- regulator: pca9450: Clear PRESET_EN bit to fix BUCK1/2/3 voltage setting
- regulator: pca9450: Enable system reset on WDOG_B assertion
- regulator: pca9450: Add SD_VSEL GPIO for LDO5
- net: bonding: fix error return code of bond_neigh_init()
- io_uring: clear IOCB_WAITQ for non -EIOCBQUEUED return
- io_uring: don't attempt IO reissue from the ring exit path
- drm/amd/pm: fulfill the Polaris implementation for get_clock_by_type_with_latency()
- s390/qeth: schedule TX NAPI on QAOB completion
- ibmvnic: remove excessive irqsave
- media: cedrus: h264: Support profile controls
- io_uring: fix inconsistent lock state
- iwlwifi: Add a new card for MA family
- drm/amd/display: turn DPMS off on connector unplug
- MIPS: compressed: fix build with enabled UBSAN
- net: phy: micrel: set soft_reset callback to genphy_soft_reset for KSZ8081
- i40e: Fix endianness conversions
- powerpc/sstep: Fix darn emulation
- powerpc/sstep: Fix load-store and update emulation
- RDMA/mlx5: Allow creating all QPs even when non RDMA profile is used
- scsi: isci: Pass gfp_t flags in isci_port_bc_change_received()
- scsi: isci: Pass gfp_t flags in isci_port_link_up()
- scsi: isci: Pass gfp_t flags in isci_port_link_down()
- scsi: mvsas: Pass gfp_t flags to libsas event notifiers
- scsi: libsas: Introduce a _gfp() variant of event notifiers
- scsi: libsas: Remove notifier indirection
- scsi: pm8001: Neaten debug logging macros and uses
- scsi: pm80xx: Fix pm8001_mpi_get_nvmd_resp() race condition
- scsi: pm80xx: Make running_req atomic
- scsi: pm80xx: Make mpi_build_cmd locking consistent
- module: harden ELF info handling
- module: avoid *goto*s in module_sig_check()
- module: merge repetitive strings in module_sig_check()
- RDMA/rtrs: Fix KASAN: stack-out-of-bounds bug
- RDMA/rtrs: Introduce rtrs_post_send
- RDMA/rtrs-srv: Jump to dereg_mr label if allocate iu fails
- RDMA/rtrs: Remove unnecessary argument dir of rtrs_iu_free
- bpf: Declare __bpf_free_used_maps() unconditionally
- serial: stm32: fix DMA initialization error handling
- tty: serial: stm32-usart: Remove set but unused 'cookie' variables
- ibmvnic: serialize access to work queue on remove
- ibmvnic: add some debugs
- nvme-rdma: fix possible hang when failing to set io queues
- gpiolib: Assign fwnode to parent's if no primary one provided
- counter: stm32-timer-cnt: Report count function when SLAVE_MODE_DISABLED
- RISC-V: correct enum sbi_ext_rfence_fid
- scsi: ufs: ufs-mediatek: Correct operator & -> &&
- scsi: myrs: Fix a double free in myrs_cleanup()
- scsi: lpfc: Fix some error codes in debugfs
- riscv: Correct SPARSEMEM configuration
- cifs: fix allocation size on newly created files
- kbuild: Fix <linux/version.h> for empty SUBLEVEL or PATCHLEVEL again
- net/qrtr: fix __netdev_alloc_skb call
- io_uring: ensure that SQPOLL thread is started for exit
- pstore: Fix warning in pstore_kill_sb()
- i915/perf: Start hrtimer only if sampling the OA buffer
- sunrpc: fix refcount leak for rpc auth modules
- vhost_vdpa: fix the missing irq_bypass_unregister_producer() invocation
- vfio: IOMMU_API should be selected
- svcrdma: disable timeouts on rdma backchannel
- NFSD: fix dest to src mount in inter-server COPY
- NFSD: Repair misuse of sv_lock in 5.10.16-rt30.
- nfsd: don't abort copies early
- nfsd: Don't keep looking up unhashed files in the nfsd file cache
- nvmet: don't check iosqes,iocqes for discovery controllers
- nvme-tcp: fix a NULL deref when receiving a 0-length r2t PDU
- nvme-tcp: fix possible hang when failing to set io queues
- nvme-tcp: fix misuse of __smp_processor_id with preemption enabled
- nvme: fix Write Zeroes limitations
- ALSA: usb-audio: Fix unintentional sign extension issue
- afs: Stop listxattr() from listing "afs.*" attributes
- afs: Fix accessing YFS xattrs on a non-YFS server
- ASoC: simple-card-utils: Do not handle device clock
- ASoC: qcom: lpass-cpu: Fix lpass dai ids parse
- ASoC: codecs: wcd934x: add a sanity check in set channel map
- ASoC: qcom: sdm845: Fix array out of range on rx slim channels
- ASoC: qcom: sdm845: Fix array out of bounds access
- ASoC: SOF: intel: fix wrong poll bits in dsp power down
- ASoC: SOF: Intel: unregister DMIC device on probe error
- ASoC: Intel: bytcr_rt5640: Fix HP Pavilion x2 10-p0XX OVCD current threshold
- ASoC: fsl_ssi: Fix TDM slot setup for I2S mode
- drm/amd/display: Correct algorithm for reversed gamma
- vhost-vdpa: set v->config_ctx to NULL if eventfd_ctx_fdget() fails
- vhost-vdpa: fix use-after-free of v->config_ctx
- btrfs: fix slab cache flags for free space tree bitmap
- btrfs: fix race when cloning extent buffer during rewind of an old root
- zonefs: fix to update .i_wr_refcnt correctly in zonefs_open_zone()
- zonefs: prevent use of seq files as swap file
- zonefs: Fix O_APPEND async write handling
- s390/pci: fix leak of PCI device structure
- s390/pci: remove superfluous zdev->zbus check
- s390/pci: refactor zpci_create_device()
- s390/vtime: fix increased steal time accounting
- Revert "PM: runtime: Update device status before letting suppliers suspend"
- ALSA: hda/realtek: fix mute/micmute LEDs for HP 850 G8
- ALSA: hda/realtek: fix mute/micmute LEDs for HP 440 G8
- ALSA: hda/realtek: fix mute/micmute LEDs for HP 840 G8
- ALSA: hda/realtek: Apply headset-mic quirks for Xiaomi Redmibook Air
- ALSA: hda: generic: Fix the micmute led init state
- ALSA: hda/realtek: apply pin quirk for XiaomiNotebook Pro
- ALSA: dice: fix null pointer dereference when node is disconnected
- spi: cadence: set cqspi to the driver_data field of struct device
- ASoC: ak5558: Add MODULE_DEVICE_TABLE
- ASoC: ak4458: Add MODULE_DEVICE_TABLE
- sdei_watchdog: Fix compile error when PPC_WATCHDOG is disable on PowerPC
- net: dsa: b53: Support setting learning on port
- ALSA: usb-audio: Don't avoid stopping the stream at disconnection
- Revert "nfsd4: a client's own opens needn't prevent delegations"
- Revert "nfsd4: remove check_conflicting_opens warning"
- fuse: fix live lock in fuse_iget()
- RDMA/srp: Fix support for unpopulated and unbalanced NUMA nodes
- bpf, selftests: Fix up some test_verifier cases for unprivileged
- bpf: Add sanity check for upper ptr_limit
- bpf: Simplify alu_limit masking for pointer arithmetic
- bpf: Fix off-by-one for area size in creating mask to left
- bpf: Prohibit alu ops for pointer types not defining ptr_limit
- crypto: x86/aes-ni-xts - use direct calls to and 4-way stride
- crypto: aesni - Use TEST %reg,%reg instead of CMP $0,%reg
- arm32: kaslr: Fix clock_gettime and gettimeofday performance degradation when configure CONFIG_RANDOMIZE_BASE
- arm32: kaslr: Print the real kaslr offset when kernel panic
- arm32: kaslr: Fix the bug of symbols relocation
- arm32: kaslr: Adapt dts files of multiple memory nodes
- arm32: kaslr: Fix the bug of hidden symbols when decompressing code is compiled
- arm32: kaslr: Fix the bug of module install failure
- arm32: kaslr: Add missing sections about relocatable
- arm64: Enable passing IMA log to next kernel on kexec
- powerpc: Delete unused function delete_fdt_mem_rsv()
- kexec: Use fdt_appendprop_addrrange() to add ima buffer to FDT
- powerpc: Move arch independent ima kexec functions to drivers/of/kexec.c
- powerpc: Enable passing IMA log to next kernel on kexec
- powerpc: Move ima buffer fields to struct kimage
- powerpc: Use common of_kexec_alloc_and_setup_fdt()
- arm64: Use common of_kexec_alloc_and_setup_fdt()
- of: Add a common kexec FDT setup function
- x86: Use ELF fields defined in 'struct kimage'
- powerpc: Use ELF fields defined in 'struct kimage'
- arm64: Use ELF fields defined in 'struct kimage'
- kexec: Move ELF fields to struct kimage
- ext4: fix timer use-after-free on failed mount
- ext4: drop ext4_handle_dirty_super()
- ext4: use sbi instead of EXT4_SB(sb) in ext4_update_super()
- ext4: save error info to sb through journal if available
- ext4: protect superblock modifications with a buffer lock
- ext4: drop sync argument of ext4_commit_super()
- ext4: combine ext4_handle_error() and save_error_info()
- ext4: defer saving error info from atomic context
- ext4: simplify ext4 error translation
- ext4: move functions in super.c
- ext4: make ext4_abort() use __ext4_error()
- ext4: standardize error message in ext4_protect_reserved_inode()
- ext4: remove redundant sb checksum recomputation
- RDMA/umem: Use ib_dma_max_seg_size instead of dma_get_max_seg_size
- KVM: arm64: Fix nVHE hyp panic host context restore
- xen/events: avoid handling the same event on two cpus at the same time
- xen/events: don't unmask an event channel when an eoi is pending
- mm/page_alloc.c: refactor initialization of struct page for holes in memory layout
- KVM: arm64: Ensure I-cache isolation between vcpus of a same VM
- mm/madvise: replace ptrace attach requirement for process_madvise
- mm/userfaultfd: fix memory corruption due to writeprotect
- KVM: arm64: Fix exclusive limit for IPA size
- KVM: arm64: Reject VM creation when the default IPA size is unsupported
- KVM: arm64: nvhe: Save the SPE context early
- KVM: arm64: Avoid corrupting vCPU context register in guest exit
- KVM: arm64: Fix range alignment when walking page tables
- KVM: kvmclock: Fix vCPUs > 64 can't be online/hotpluged
- KVM: x86: Ensure deadline timer has truly expired before posting its IRQ
- x86/entry: Fix entry/exit mismatch on failed fast 32-bit syscalls
- x86/sev-es: Use __copy_from_user_inatomic()
- x86/sev-es: Correctly track IRQ states in runtime #VC handler
- x86/entry: Move nmi entry/exit into common code
- x86/sev-es: Check regs->sp is trusted before adjusting #VC IST stack
- x86/sev-es: Introduce ip_within_syscall_gap() helper
- x86/unwind/orc: Disable KASAN checking in the ORC unwinder, part 2
- binfmt_misc: fix possible deadlock in bm_register_write
- powerpc: Fix missing declaration of [en/dis]able_kernel_vsx()
- powerpc: Fix inverted SET_FULL_REGS bitop
- powerpc/64s: Fix instruction encoding for lis in ppc_function_entry()
- efi: stub: omit SetVirtualAddressMap() if marked unsupported in RT_PROP table
- sched/membarrier: fix missing local execution of ipi_sync_rq_state()
- linux/compiler-clang.h: define HAVE_BUILTIN_BSWAP*
- zram: fix return value on writeback_store
- include/linux/sched/mm.h: use rcu_dereference in in_vfork()
- stop_machine: mark helpers __always_inline
- seqlock,lockdep: Fix seqcount_latch_init()
- powerpc/64s/exception: Clean up a missed SRR specifier
- hrtimer: Update softirq_expires_next correctly after __hrtimer_get_next_event()
- perf/x86/intel: Set PERF_ATTACH_SCHED_CB for large PEBS and LBR
- perf/core: Flush PMU internal buffers for per-CPU events
- arm64: mm: use a 48-bit ID map when possible on 52-bit VA builds
- configfs: fix a use-after-free in __configfs_open_file
- nvme-fc: fix racing controller reset and create association
- block: rsxx: fix error return code of rsxx_pci_probe()
- NFSv4.2: fix return value of _nfs4_get_security_label()
- NFS: Don't gratuitously clear the inode cache when lookup failed
- NFS: Don't revalidate the directory permissions on a lookup failure
- SUNRPC: Set memalloc_nofs_save() for sync tasks
- arm64/mm: Fix pfn_valid() for ZONE_DEVICE based memory
- cpufreq: qcom-hw: Fix return value check in qcom_cpufreq_hw_cpu_init()
- cpufreq: qcom-hw: fix dereferencing freed memory 'data'
- sh_eth: fix TRSCER mask for R7S72100
- staging: comedi: pcl818: Fix endian problem for AI command data
- staging: comedi: pcl711: Fix endian problem for AI command data
- staging: comedi: me4000: Fix endian problem for AI command data
- staging: comedi: dmm32at: Fix endian problem for AI command data
- staging: comedi: das800: Fix endian problem for AI command data
- staging: comedi: das6402: Fix endian problem for AI command data
- staging: comedi: adv_pci1710: Fix endian problem for AI command data
- staging: comedi: addi_apci_1500: Fix endian problem for command sample
- staging: comedi: addi_apci_1032: Fix endian problem for COS sample
- staging: rtl8192e: Fix possible buffer overflow in _rtl92e_wx_set_scan
- staging: rtl8712: Fix possible buffer overflow in r8712_sitesurvey_cmd
- staging: ks7010: prevent buffer overflow in ks_wlan_set_scan()
- staging: rtl8188eu: fix potential memory corruption in rtw_check_beacon_data()
- staging: rtl8712: unterminated string leads to read overflow
- staging: rtl8188eu: prevent ->ssid overflow in rtw_wx_set_scan()
- staging: rtl8192u: fix ->ssid overflow in r8192_wx_set_scan()
- misc: fastrpc: restrict user apps from sending kernel RPC messages
- misc/pvpanic: Export module FDT device table
- Revert "serial: max310x: rework RX interrupt handling"
- usbip: fix vudc usbip_sockfd_store races leading to gpf
- usbip: fix vhci_hcd attach_store() races leading to gpf
- usbip: fix stub_dev usbip_sockfd_store() races leading to gpf
- usbip: fix vudc to check for stream socket
- usbip: fix vhci_hcd to check for stream socket
- usbip: fix stub_dev to check for stream socket
- USB: serial: cp210x: add some more GE USB IDs
- USB: serial: cp210x: add ID for Acuity Brands nLight Air Adapter
- USB: serial: ch341: add new Product ID
- USB: serial: io_edgeport: fix memory leak in edge_startup
- xhci: Fix repeated xhci wake after suspend due to uncleared internal wake state
- usb: xhci: Fix ASMedia ASM1042A and ASM3242 DMA addressing
- xhci: Improve detection of device initiated wake signal.
- usb: xhci: do not perform Soft Retry for some xHCI hosts
- usb: renesas_usbhs: Clear PIPECFG for re-enabling pipe with other EPNUM
- USB: usblp: fix a hang in poll() if disconnected
- usb: dwc3: qcom: Honor wakeup enabled/disabled state
- usb: dwc3: qcom: add ACPI device id for sc8180x
- usb: dwc3: qcom: add URS Host support for sdm845 ACPI boot
- usb: dwc3: qcom: Add missing DWC3 OF node refcount decrement
- usb: gadget: f_uac1: stop playback on function disable
- usb: gadget: f_uac2: always increase endpoint max_packet_size by one audio slot
- USB: gadget: u_ether: Fix a configfs return code
- USB: gadget: udc: s3c2410_udc: fix return value check in s3c2410_udc_probe()
- Goodix Fingerprint device is not a modem
- cifs: do not send close in compound create+close requests
- mmc: cqhci: Fix random crash when remove mmc module/card
- mmc: core: Fix partition switch time for eMMC
- mmc: mmci: Add MMC_CAP_NEED_RSP_BUSY for the stm32 variants
- xen/events: reset affinity of 2-level event when tearing it down
- software node: Fix node registration
- s390/dasd: fix hanging IO request during DASD driver unbind
- s390/dasd: fix hanging DASD driver unbind
- arm64: perf: Fix 64-bit event counter read truncation
- arm64: mte: Map hotplugged memory as Normal Tagged
- arm64: kasan: fix page_alloc tagging with DEBUG_VIRTUAL
- block: Try to handle busy underlying device on discard
- block: Discard page cache of zone reset target range
- Revert 95ebabde382c ("capabilities: Don't allow writing ambiguous v3 file capabilities")
- ALSA: usb-audio: fix use after free in usb_audio_disconnect
- ALSA: usb-audio: fix NULL ptr dereference in usb_audio_probe
- ALSA: usb-audio: Disable USB autosuspend properly in setup_disable_autosuspend()
- ALSA: usb-audio: Apply the control quirk to Plantronics headsets
- ALSA: usb-audio: Fix "cannot get freq eq" errors on Dell AE515 sound bar
- ALSA: hda: Avoid spurious unsol event handling during S3/S4
- ALSA: hda: Flush pending unsolicited events before suspend
- ALSA: hda: Drop the BATCH workaround for AMD controllers
- ALSA: hda/ca0132: Add Sound BlasterX AE-5 Plus support
- ALSA: hda/conexant: Add quirk for mute LED control on HP ZBook G5
- ALSA: hda/hdmi: Cancel pending works before suspend
- ALSA: usb: Add Plantronics C320-M USB ctrl msg delay quirk
- ARM: 9029/1: Make iwmmxt.S support Clang's integrated assembler
- mmc: sdhci: Update firmware interface API
- clk: qcom: gpucc-msm8998: Add resets, cxc, fix flags on gpu_gx_gdsc
- scsi: target: core: Prevent underflow for service actions
- scsi: target: core: Add cmd length set before cmd complete
- scsi: libiscsi: Fix iscsi_prep_scsi_cmd_pdu() error handling
- sysctl.c: fix underflow value setting risk in vm_table
- drivers/base/memory: don't store phys_device in memory blocks
- s390/smp: __smp_rescan_cpus() - move cpumask away from stack
- kasan: fix memory corruption in kasan_bitops_tags test
- i40e: Fix memory leak in i40e_probe
- PCI: Fix pci_register_io_range() memory leak
- kbuild: clamp SUBLEVEL to 255
- ext4: don't try to processed freed blocks until mballoc is initialized
- PCI/LINK: Remove bandwidth notification
- drivers/base: build kunit tests without structleak plugin
- PCI: mediatek: Add missing of_node_put() to fix reference leak
- PCI: xgene-msi: Fix race in installing chained irq handler
- Input: applespi - don't wait for responses to commands indefinitely.
- sparc64: Use arch_validate_flags() to validate ADI flag
- sparc32: Limit memblock allocation to low memory
- clk: qcom: gdsc: Implement NO_RET_PERIPH flag
- iommu/amd: Fix performance counter initialization
- powerpc/64: Fix stack trace not displaying final frame
- HID: logitech-dj: add support for the new lightspeed connection iteration
- powerpc/perf: Record counter overflow always if SAMPLE_IP is unset
- powerpc: improve handling of unrecoverable system reset
- spi: stm32: make spurious and overrun interrupts visible
- powerpc/pci: Add ppc_md.discover_phbs()
- Platform: OLPC: Fix probe error handling
- mmc: sdhci-iproc: Add ACPI bindings for the RPi
- mmc: mediatek: fix race condition between msdc_request_timeout and irq
- mmc: mxs-mmc: Fix a resource leak in an error handling path in 'mxs_mmc_probe()'
- iommu/vt-d: Clear PRQ overflow only when PRQ is empty
- udf: fix silent AED tagLocation corruption
- scsi: ufs: WB is only available on LUN #0 to #7
- i2c: rcar: optimize cacheline to minimize HW race condition
- i2c: rcar: faster irq code to minimize HW race condition
- ath11k: fix AP mode for QCA6390
- ath11k: start vdev if a bss peer is already created
- ath11k: peer delete synchronization with firmware
- net: enetc: initialize RFS/RSS memories for unused ports too
- enetc: Fix unused var build warning for CONFIG_OF
- net: dsa: tag_mtk: fix 802.1ad VLAN egress
- net: dsa: tag_ar9331: let DSA core deal with TX reallocation
- net: dsa: tag_gswip: let DSA core deal with TX reallocation
- net: dsa: tag_dsa: let DSA core deal with TX reallocation
- net: dsa: tag_brcm: let DSA core deal with TX reallocation
- net: dsa: tag_edsa: let DSA core deal with TX reallocation
- net: dsa: tag_lan9303: let DSA core deal with TX reallocation
- net: dsa: tag_mtk: let DSA core deal with TX reallocation
- net: dsa: tag_ocelot: let DSA core deal with TX reallocation
- net: dsa: tag_qca: let DSA core deal with TX reallocation
- net: dsa: trailer: don't allocate additional memory for padding/tagging
- net: dsa: tag_ksz: don't allocate additional memory for padding/tagging
- net: dsa: implement a central TX reallocation procedure
- s390/qeth: fix notification for pending buffers during teardown
- s390/qeth: improve completion of pending TX buffers
- s390/qeth: remove QETH_QDIO_BUF_HANDLED_DELAYED state
- s390/qeth: don't replace a fully completed async TX buffer
- net: hns3: fix error mask definition of flow director
- cifs: fix credit accounting for extra channel
- media: rc: compile rc-cec.c into rc-core
- media: v4l: vsp1: Fix bru null pointer access
- media: v4l: vsp1: Fix uif null pointer access
- media: rkisp1: params: fix wrong bits settings
- media: usbtv: Fix deadlock on suspend
- sh_eth: fix TRSCER mask for R7S9210
- qxl: Fix uninitialised struct field head.surface_id
- s390/crypto: return -EFAULT if copy_to_user() fails
- s390/cio: return -EFAULT if copy_to_user() fails
- drm/i915: Wedge the GPU if command parser setup fails
- drm/shmem-helpers: vunmap: Don't put pages for dma-buf
- drm: meson_drv add shutdown function
- drm: Use USB controller's DMA mask when importing dmabufs
- drm/shmem-helper: Don't remove the offset in vm_area_struct pgoff
- drm/shmem-helper: Check for purged buffers in fault handler
- drm/amdgpu/display: handle aux backlight in backlight_get_brightness
- drm/amdgpu/display: don't assert in set backlight function
- drm/amdgpu/display: simplify backlight setting
- drm/amd/pm: bug fix for pcie dpm
- drm/amd/display: Fix nested FPU context in dcn21_validate_bandwidth()
- drm/amdgpu/display: use GFP_ATOMIC in dcn21_validate_bandwidth_fp()
- drm/amd/display: Add a backlight module option
- drm/compat: Clear bounce structures
- gpio: fix gpio-device list corruption
- gpio: pca953x: Set IRQ type when handle Intel Galileo Gen 2
- gpiolib: acpi: Allow to find GpioInt() resource by name and index
- gpiolib: acpi: Add ACPI_GPIO_QUIRK_ABSOLUTE_NUMBER quirk
- bnxt_en: reliably allocate IRQ table on reset to avoid crash
- s390/cio: return -EFAULT if copy_to_user() fails again
- net: hns3: fix bug when calculating the TCAM table info
- net: hns3: fix query vlan mask value error for flow director
- perf report: Fix -F for branch & mem modes
- perf traceevent: Ensure read cmdlines are null terminated.
- mlxsw: spectrum_ethtool: Add an external speed to PTYS register
- selftests: forwarding: Fix race condition in mirror installation
- net: phy: make mdio_bus_phy_suspend/resume as __maybe_unused
- ethtool: fix the check logic of at least one channel for RX/TX
- net: stmmac: fix wrongly set buffer2 valid when sph unsupport
- net: stmmac: fix watchdog timeout during suspend/resume stress test
- net: stmmac: stop each tx channel independently
- perf build: Fix ccache usage in $(CC) when generating arch errno table
- tools/resolve_btfids: Fix build error with older host toolchains
- ixgbe: fail to create xfrm offload of IPsec tunnel mode SA
- r8169: fix r8168fp_adjust_ocp_cmd function
- s390/qeth: fix memory leak after failed TX Buffer allocation
- net: qrtr: fix error return code of qrtr_sendmsg()
- net: enetc: allow hardware timestamping on TX queues with tc-etf enabled
- net: davicom: Fix regulator not turned off on driver removal
- net: davicom: Fix regulator not turned off on failed probe
- net: lapbether: Remove netif_start_queue / netif_stop_queue
- stmmac: intel: Fixes clock registration error seen for multiple interfaces
- net: stmmac: Fix VLAN filter delete timeout issue in Intel mGBE SGMII
- cipso,calipso: resolve a number of problems with the DOI refcounts
- netdevsim: init u64 stats for 32bit hardware
- net: usb: qmi_wwan: allow qmimux add/del with master up
- net: dsa: sja1105: fix SGMII PCS being forced to SPEED_UNKNOWN instead of SPEED_10
- net: mscc: ocelot: properly reject destination IP keys in VCAP IS1
- net: sched: avoid duplicates in classes dump
- nexthop: Do not flush blackhole nexthops when loopback goes down
- net: stmmac: fix incorrect DMA channel intr enable setting of EQoS v4.10
- net/mlx4_en: update moderation when config reset
- net: ethernet: mtk-star-emac: fix wrong unmap in RX handling
- net: enetc: keep RX ring consumer index in sync with hardware
- net: enetc: remove bogus write to SIRXIDR from enetc_setup_rxbdr
- net: enetc: force the RGMII speed and duplex instead of operating in inband mode
- net: enetc: don't disable VLAN filtering in IFF_PROMISC mode
- net: enetc: fix incorrect TPID when receiving 802.1ad tagged packets
- net: enetc: take the MDIO lock only once per NAPI poll cycle
- net: enetc: don't overwrite the RSS indirection table when initializing
- sh_eth: fix TRSCER mask for SH771x
- net: dsa: tag_rtl4_a: fix egress tags
- docs: networking: drop special stable handling
- Revert "mm, slub: consider rest of partial list if acquire_slab() fails"
- cifs: return proper error code in statfs(2)
- mount: fix mounting of detached mounts onto targets that reside on shared mounts
- powerpc/603: Fix protection of user pages mapped with PROT_NONE
- mt76: dma: do not report truncated frames to mac80211
- ibmvnic: always store valid MAC address
- ibmvnic: Fix possibly uninitialized old_num_tx_queues variable warning.
- libbpf: Clear map_info before each bpf_obj_get_info_by_fd
- samples, bpf: Add missing munmap in xdpsock
- selftests/bpf: Mask bpf_csum_diff() return value to 16 bits in test_verifier
- selftests/bpf: No need to drop the packet when there is no geneve opt
- selftests/bpf: Use the last page in test_snprintf_btf on s390
- net: phy: fix save wrong speed and duplex problem if autoneg is on
- net: always use icmp{,v6}_ndo_send from ndo_start_xmit
- netfilter: x_tables: gpf inside xt_find_revision()
- netfilter: nf_nat: undo erroneous tcp edemux lookup
- tcp: add sanity tests to TCP_QUEUE_SEQ
- tcp: Fix sign comparison bug in getsockopt(TCP_ZEROCOPY_RECEIVE)
- can: tcan4x5x: tcan4x5x_init(): fix initialization - clear MRAM before entering Normal Mode
- can: flexcan: invoke flexcan_chip_freeze() to enter freeze mode
- can: flexcan: enable RX FIFO after FRZ/HALT valid
- can: flexcan: assert FRZ bit in flexcan_chip_freeze()
- can: skb: can_skb_set_owner(): fix ref counting if socket was closed before setting skb ownership
- net: l2tp: reduce log level of messages in receive path, add counter instead
- net: avoid infinite loop in mpls_gso_segment when mpls_hlen == 0
- net: check if protocol extracted by virtio_net_hdr_set_proto is correct
- net: Fix gro aggregation for udp encaps with zero csum
- ath9k: fix transmitting to stations in dynamic SMPS mode
- crypto: mips/poly1305 - enable for all MIPS processors
- ethernet: alx: fix order of calls on resume
- powerpc/pseries: Don't enforce MSI affinity with kdump
- powerpc/perf: Fix handling of privilege level checks in perf interrupt context
- uapi: nfnetlink_cthelper.h: fix userspace compilation error
- arm64/mpam: fix a memleak in add_schema
- cacheinfo: workaround cacheinfo's info_list uninitialized error
- openeuler_defconfig: Enable MPAM by default
- arm64/mpam: Sort domains when cpu online
- arm64/mpam: resctrl: Refresh cpu mask for handling cpuhp
- arm64/mpam: resctrl: Allow setting register MPAMCFG_MBW_MIN to 0
- arm64/mpam: resctrl: Use resctrl_group_init_alloc() for default group
- arm64/mpam: resctrl: Add proper error handling to resctrl_mount()
- arm64/mpam: Use fs_context to parse mount options
- arm64/mpam: Supplement additional useful ctrl features for mount options
- arm64/mpam: Set per-cpu's closid to none zero for cdp
- arm64/mpam: Simplify mpamid cdp mapping process
- arm64/mpam: Filter schema control type with ctrl features
- arm64/mpam: resctrl: Add rmid file in resctrl sysfs
- arm64/mpam: Split header files into suitable location
- arm64/mpam: resctrl: Export resource's properties to info directory
- arm64/mpam: Add resctrl_ctrl_feature structure to manage ctrl features
- arm64/mpam: Add wait queue for monitor alloc and free
- arm64/mpam: Remap reqpartid,pmg to rmid and intpartid to closid
- arm64/mpam: Separate internal and downstream priority event
- arm64/mpam: Enabling registering and logging error interrupts
- arm64/mpam: Fix MPAM_ESR intPARTID_range error
- arm64/mpam: Integrate monitor data for Memory Bandwidth if cdp enabled
- arm64/mpam: Add hook-events id for ctrl features
- arm64/mpam: Re-plan intpartid narrowing process
- arm64/mpam: Restore extend ctrls' max width for checking schemata input
- arm64/mpam: Squash default priority from mpam device to class
- arm64/mpam: Store intpri and dspri for mpam device reset
- arm64/mpam: resctrl: Support priority and hardlimit(Memory bandwidth) configuration
- arm64/mpam: resctrl: Support cpus' monitoring for mon group
- arm64/mpam: resctrl: collect child mon group's monitor data
- arm64/mpam: Using software-defined id for rdtgroup instead of 32-bit integer
- arm64/mpam: Implement intpartid narrowing process
- arm64/mpam: resctrl: Remove unnecessary CONFIG_ARM64
- arm64/mpam: resctrl: Remove ctrlmon sysfile
- arm64/mpam: Clean up header files and rearrange declarations
- arm64/mpam: resctrl: Support cdp on monitoring data
- arm64/mpam: Support cdp on allocating monitors
- arm64/mpam: resctrl: Move ctrlmon sysfile write/read function to mpam_ctrlmon.c
- arm64/mpam: resctrl: Update closid alloc and free process with bitmap
- arm64/mpam: resctrl: Update resources reset process
- arm64/mpam: Support cdp in mpam_sched_in()
- arm64/mpam: resctrl: Write and read schemata by schema_list
- arm64/mpam: resctrl: Use resctrl_group_init_alloc() to init schema list
- arm64/mpam: resctrl: Add helpers for init and destroy schemata list
- arm64/mpam: resctrl: Supplement cdpl2,cdpl3 for mount options
- arm64/mpam: resctrl: Append schemata CDP definitions
- arm64/mpam: resctrl: Rebuild configuration and monitoring pipeline
- arm64/mpam: Probe partid,pmg and feature capabilities' ranges from classes
- arm64/mpam: Add helper for getting MSCs' configuration
- arm64/mpam: Migrate old MSCs' discovery process to new branch
- drivers: base: cacheinfo: Add helper to search cacheinfo by of_node
- arm64/mpam: Implement helpers for handling configuration and monitoring
- arm64/mpam: resctrl: Handle cpuhp and resctrl_dom allocation
- arm64/mpam: resctrl: Re-synchronise resctrl's view of online CPUs
- arm64/mpam: Init resctrl resources' info from resctrl_res selected
- arm64/mpam: Pick MPAM resources and events for resctrl_res exported
- arm64/mpam: Allocate mpam component configuration arrays
- arm64/mpam: Summarize feature support during mpam_enable()
- arm64/mpam: Reset controls when CPUs come online
- arm64/mpam: Add helper for getting mpam sysprops
- arm64/mpam: Probe the features resctrl supports
- arm64/mpam: Supplement MPAM MSC register layout definitions
- arm64/mpam: Probe supported partid/pmg ranges from devices
- arm64/mpam: Add mpam driver discovery phase and kbuild boiler plate
- arm64/mpam: Preparing for MPAM refactoring
- arm64/mpam: Supplement err tips in info/last_cmd_status
- arm64/mpam: Fix unreset resources when mkdir ctrl group or umount resctrl
- MPAM / ACPI: Refactoring MPAM init process and set MPAM ACPI as entrance
- ACPI 6.x: Add definitions for MPAM table
- ACPI / PPTT: cacheinfo: Label caches based on fw_token
- ACPI / PPTT: Filthy hack to find _a_ backwards reference in the PPTT [ROTTEN]
- ACPI / PPTT: Add helper to validate cache nodes from an offset [dead]
- ACPI / processor: Add helper to convert acpi_id to a phys_cpuid
- arm64/mpam: cleanup the source file's licence
- mpam : fix monitor's disorder from
- mpam : fix missing fill MSMON_CFG_MON_SEL register
- arm64/mpam: use snprintf instead of sprintf
- arm64/mpam: cleanup debuging code
- arm64/mpam: fix a missing unlock in error branch
- arm64/mpam: remove unnecessary debug message and dead code
- arm64/mpam: correct num of partid/pmg
- arm64/mpam: get num_partids from system regs instead of hard code
- arm64/mpam: update group flags only when enable sucsses
- arm64/mpam: remove unsupported resource
- arm64/mpam: only add new domain node to domain list
- arm64/mpam: unmap all previous address when failed
- arm64/mpam: destroy domain list when failed to init
- arm64/mpam: fix hard code address map for 1620 2P
- mpam: fix potential resource leak in mpam_domains_init
- mpam: Code security rectification
- cmetrics: remove dead code in mpam_ctrlmon.c and resctrlfs.c
- arm64/mpam: fix compile warning
- arm64/mpam: add cmdline option: mpam
- resctrlfs: fix up RESCTRL dependency
- arm64/mpam: hard code mpam resource for Hi1620 2P
- arm64/mpam: support L3TALL, HHALL
- arm64/mpam: debug: remove debug pr_info at schemata
- arm64/mpam: use 5% as min memory bandwidth
- arm64/mpam: don't allowd create mon_groups when out of mon/pmg
- arm64/mpam: fix HHA MAX SET/GET operation
- arm64/mpam: monitor pmg as a property of partid
- arm64/mpam: enable alloc/mon capable when MPAM enabled
- arm64/mpam: add L3TALL & HHALL
- arm64/mpam: alloc/mon capable/enabled debug
- arm64/mpam: get alloc/mon capable/enabled from h/w
- arm64/mpam: don't reserve mon 0, we can use it as nomarl
- arm64/mpam: get num_mon & num_pmg from hardware
- arm64/mpam: add num_monitors in info dir
- arm64/mpam: mon: add WARN_ON for debug free_pmg
- arm64/mpam: free mon when remove momgroups
- arm64/mpam: operation not permitted when remove a ctrl group with a mondata
- arm64/mpam: support monitor
- arm64/mpam: disable MPAM_SYS_REG_DEBUG
- arm64/mpam: print mpam caps info when booting
- arm64/mpam: add mpam extension runtime detection
- arm64/mpam: support num_partids/num_pmgs
- arm64/mpam: support monitor
- arm64/mpam: support monitor read
- arm64/mpam: pass rdtgroup when create mon_data dir
- arm64/mpam: add group partid/pmg to tasks show
- arm64/mpam: debug: print debug info when create mon_data
- arm64/mpam: debug: print more useful info for mon_data
- resctrlfs: mpam: Build basic framework for mpam
- resctrlfs: init support resctrlfs
- nvme-pci: add quirks for Lexar 256GB SSD
- nvme-pci: mark Seagate Nytro XM1440 as QUIRK_NO_NS_DESC_LIST.
- KVM: SVM: Clear the CR4 register on reset
- scsi: ufs: Fix a duplicate dev quirk number
- ASoC: Intel: sof_sdw: add quirk for HP Spectre x360 convertible
- ASoC: Intel: sof_sdw: reorganize quirks by generation
- PCI: cadence: Retrain Link to work around Gen2 training defect
- ALSA: usb-audio: add mixer quirks for Pioneer DJM-900NXS2
- ALSA: usb-audio: Add DJM750 to Pioneer mixer quirk
- HID: i2c-hid: Add I2C_HID_QUIRK_NO_IRQ_AFTER_RESET for ITE8568 EC on Voyo Winpad A15
- mmc: sdhci-of-dwcmshc: set SDHCI_QUIRK2_PRESET_VALUE_BROKEN
- drm/msm/a5xx: Remove overwriting A5XX_PC_DBG_ECO_CNTL register
- scsi: ufs: ufs-exynos: Use UFSHCD_QUIRK_ALIGN_SG_WITH_PAGE_SIZE
- scsi: ufs: ufs-exynos: Apply vendor-specific values for three timeouts
- scsi: ufs: Introduce a quirk to allow only page-aligned sg entries
- misc: eeprom_93xx46: Add quirk to support Microchip 93LC46B eeprom
- scsi: ufs: Add a quirk to permit overriding UniPro defaults
- scsi: ufs-mediatek: Enable UFSHCI_QUIRK_SKIP_MANUAL_WB_FLUSH_CTRL
- ASoC: Intel: sof_sdw: add missing TGL_HDMI quirk for Dell SKU 0A32
- KVM: x86: Supplement __cr4_reserved_bits() with X86_FEATURE_PCID check
- PCI: Add function 1 DMA alias quirk for Marvell 9215 SATA controller
- usb: cdns3: fix NULL pointer dereference on no platform data
- usb: cdns3: add quirk for enable runtime pm by default
- usb: cdns3: host: add xhci_plat_priv quirk XHCI_SKIP_PHY_INIT
- usb: cdns3: host: add .suspend_quirk for xhci-plat.c
- ASoC: Intel: bytcr_rt5640: Add quirk for ARCHOS Cesium 140
- ACPI: video: Add DMI quirk for GIGABYTE GB-BXBT-2807
- media: cx23885: add more quirks for reset DMA on some AMD IOMMU
- HID: mf: add support for 0079:1846 Mayflash/Dragonrise USB Gamecube Adapter
- platform/x86: acer-wmi: Add ACER_CAP_KBD_DOCK quirk for the Aspire Switch 10E SW3-016
- platform/x86: acer-wmi: Add support for SW_TABLET_MODE on Switch devices
- platform/x86: acer-wmi: Add ACER_CAP_SET_FUNCTION_MODE capability flag
- platform/x86: acer-wmi: Add new force_caps module parameter
- platform/x86: acer-wmi: Cleanup accelerometer device handling
- platform/x86: acer-wmi: Cleanup ACER_CAP_FOO defines
- bus: ti-sysc: Implement GPMC debug quirk to drop platform data
- ASoC: Intel: sof_sdw: add quirk for new TigerLake-SDCA device
- mwifiex: pcie: skip cancel_work_sync() on reset failure path
- Bluetooth: btqca: Add valid le states quirk
- iommu/amd: Fix sleeping in atomic in increase_address_space()
- btrfs: don't flush from btrfs_delayed_inode_reserve_metadata
- btrfs: export and rename qgroup_reserve_meta
- arm64: Make CPU_BIG_ENDIAN depend on ld.bfd or ld.lld 13.0.0+
- parisc: Enable -mlong-calls gcc option with CONFIG_COMPILE_TEST
- nvme-pci: mark Kingston SKC2000 as not supporting the deepest power state
- ASoC: SOF: Intel: broadwell: fix mutual exclusion with catpt driver
- ACPICA: Fix race in generic_serial_bus (I2C) and GPIO op_region parameter handling
- r8169: fix resuming from suspend on RTL8105e if machine runs on battery
- tomoyo: recognize kernel threads correctly
- Revert "arm64: dts: amlogic: add missing ethernet reset ID"
- iommu/vt-d: Fix status code for Allocate/Free PASID command
- rsxx: Return -EFAULT if copy_to_user() fails
- ftrace: Have recordmcount use w8 to read relp->r_info in arm64_is_fake_mcount
- ALSA: hda: intel-nhlt: verify config type
- IB/mlx5: Add missing error code
- RDMA/rxe: Fix missing kconfig dependency on CRYPTO
- RDMA/cm: Fix IRQ restore in ib_send_cm_sidr_rep
- ALSA: ctxfi: cthw20k2: fix mask on conf to allow 4 bits
- drm/amdgpu: fix parameter error of RREG32_PCIE() in amdgpu_regs_pcie
- drm/amdgpu:disable VCN for Navi12 SKU
- dm verity: fix FEC for RS roots unaligned to block size
- dm bufio: subtract the number of initial sectors in dm_bufio_get_device_size
- io_uring: ignore double poll add on the same waitqueue head
- ring-buffer: Force before_stamp and write_stamp to be different on discard
- PM: runtime: Update device status before letting suppliers suspend
- btrfs: fix warning when creating a directory with smack enabled
- btrfs: unlock extents in btrfs_zero_range in case of quota reservation errors
- btrfs: free correct amount of space in btrfs_delayed_inode_reserve_metadata
- btrfs: validate qgroup inherit for SNAP_CREATE_V2 ioctl
- btrfs: fix race between extent freeing/allocation when using bitmaps
- btrfs: fix stale data exposure after cloning a hole with NO_HOLES enabled
- btrfs: fix race between swap file activation and snapshot creation
- btrfs: fix race between writes to swap files and scrub
- btrfs: fix raid6 qstripe kmap
- btrfs: avoid double put of block group when emptying cluster
- tpm, tpm_tis: Decorate tpm_get_timeouts() with request_locality()
- tpm, tpm_tis: Decorate tpm_tis_gen_interrupt() with request_locality()
- ALSA: usb-audio: Drop bogus dB range in too low level
- ALSA: usb-audio: use Corsair Virtuoso mapping for Corsair Virtuoso SE
- ALSA: hda/realtek: Enable headset mic of Acer SWIFT with ALC256
- powerpc: Do not compile any dts if CONFIG_OF_ALL_DTBS=y
- ext4: find old entry again if failed to rename whiteout
- net: sfp: add workaround for Realtek RTL8672 and RTL9601C chips
- net: sfp: VSOL V2801F / CarlitoxxPro CPGOS03-0490 v2.0 workaround
- ALSA: hda/realtek: Apply dual codec quirks for MSI Godlike X570 board
- ALSA: hda/realtek: Add quirk for Intel NUC 10
- ALSA: hda/realtek: Add quirk for Clevo NH55RZQ
- media: v4l: ioctl: Fix memory leak in video_usercopy
- tty: teach the n_tty ICANON case about the new "cookie continuations" too
- tty: teach n_tty line discipline about the new "cookie continuations"
- tty: clean up legacy leftovers from n_tty line discipline
- tty: fix up hung_up_tty_read() conversion
- tty: fix up iterate_tty_read() EOVERFLOW handling
- powerpc/sstep: Fix incorrect return from analyze_instr()
- powerpc/sstep: Check instruction validity against ISA version before emulation
- swap: fix swapfile read/write offset
- remoteproc/mediatek: Fix kernel test robot warning
- zsmalloc: account the number of compacted pages correctly
- xen: fix p2m size in dom0 for disabled memory hotplug case
- xen-netback: respect gnttab_map_refs()'s return value
- Xen/gnttab: handle p2m update errors on a per-slot basis
- scsi: iscsi: Verify lengths on passthrough PDUs
- scsi: iscsi: Ensure sysfs attributes are limited to PAGE_SIZE
- scsi: iscsi: Restrict sessions and handles to admin capabilities
- ASoC: Intel: bytcr_rt5640: Add quirk for the Acer One S1002 tablet
- ASoC: Intel: bytcr_rt5651: Add quirk for the Jumper EZpad 7 tablet
- ASoC: Intel: bytcr_rt5640: Add quirk for the Voyo Winpad A15 tablet
- ASoC: Intel: bytcr_rt5640: Add quirk for the Estar Beauty HD MID 7316R tablet
- sched/features: Fix hrtick reprogramming
- parisc: Bump 64-bit IRQ stack size to 64 KB
- ASoC: Intel: sof_sdw: detect DMIC number based on mach params
- ASoC: Intel: sof-sdw: indent and add quirks consistently
- perf/x86/kvm: Add Cascade Lake Xeon steppings to isolation_ucodes[]
- btrfs: fix error handling in commit_fs_roots
- ASoC: Intel: Add DMI quirk table to soc_intel_is_byt_cr()
- nvme-tcp: add clean action for failed reconnection
- nvme-rdma: add clean action for failed reconnection
- nvme-core: add cancel tagset helpers
- f2fs: fix to set/clear I_LINKABLE under i_lock
- f2fs: handle unallocated section and zone on pinned/atgc
- media: uvcvideo: Allow entities with no pads
- drm/amd/amdgpu: add error handling to amdgpu_virt_read_pf2vf_data
- drm/amd/display: Guard against NULL pointer deref when get_i2c_info fails
- ASoC: Intel: bytcr_rt5640: Add new BYT_RT5640_NO_SPEAKERS quirk-flag
- PCI: Add a REBAR size quirk for Sapphire RX 5600 XT Pulse
- drm/amdgpu: Add check to prevent IH overflow
- fs: make unlazy_walk() error handling consistent
- crypto: tcrypt - avoid signed overflow in byte count
- drm/hisilicon: Fix use-after-free
- brcmfmac: Add DMI nvram filename quirk for Voyo winpad A15 tablet
- brcmfmac: Add DMI nvram filename quirk for Predia Basic tablet
- staging: bcm2835-audio: Replace unsafe strcpy() with strscpy()
- staging: most: sound: add sanity check for function argument
- Bluetooth: Fix null pointer dereference in amp_read_loc_assoc_final_data
- Bluetooth: Add new HCI_QUIRK_NO_SUSPEND_NOTIFIER quirk
- net: sfp: add mode quirk for GPON module Ubiquiti U-Fiber Instant
- ath10k: fix wmi mgmt tx queue full due to race condition
- pktgen: fix misuse of BUG_ON() in pktgen_thread_worker()
- mt76: mt7615: reset token when mac_reset happens
- Bluetooth: btusb: fix memory leak on suspend and resume
- Bluetooth: hci_h5: Set HCI_QUIRK_SIMULTANEOUS_DISCOVERY for btrtl
- wlcore: Fix command execute failure 19 for wl12xx
- vt/consolemap: do font sum unsigned
- x86/reboot: Add Zotac ZBOX CI327 nano PCI reboot quirk
- staging: fwserial: Fix error handling in fwserial_create
- EDAC/amd64: Do not load on family 0x15, model 0x13
- rsi: Move card interrupt handling to RX thread
- rsi: Fix TX EAPOL packet handling against iwlwifi AP
- ASoC: qcom: Remove useless debug print
- dt-bindings: net: btusb: DT fix s/interrupt-name/interrupt-names/
- dt-bindings: ethernet-controller: fix fixed-link specification
- net: fix dev_ifsioc_locked() race condition
- net: psample: Fix netlink skb length with tunnel info
- net: hsr: add support for EntryForgetTime
- net: ag71xx: remove unnecessary MTU reservation
- net: dsa: tag_rtl4_a: Support also egress tags
- net/sched: cls_flower: Reject invalid ct_state flags rules
- net: bridge: use switchdev for port flags set through sysfs too
- mptcp: do not wakeup listener for MPJ subflows
- tcp: fix tcp_rmem documentation
- RDMA/rtrs-srv: Do not signal REG_MR
- RDMA/rtrs-clt: Use bitmask to check sess->flags
- RDMA/rtrs: Do not signal for heatbeat
- mm/hugetlb.c: fix unnecessary address expansion of pmd sharing
- nbd: handle device refs for DESTROY_ON_DISCONNECT properly
- riscv: Get rid of MAX_EARLY_MAPPING_SIZE
- net: fix up truesize of cloned skb in skb_prepare_for_shift()
- tomoyo: ignore data race while checking quota
- smackfs: restrict bytes count in smackfs write functions
- net/af_iucv: remove WARN_ONCE on malformed RX packets
- xfs: Fix assert failure in xfs_setattr_size()
- media: v4l2-ctrls.c: fix shift-out-of-bounds in std_validate
- erofs: fix shift-out-of-bounds of blkszbits
- media: mceusb: sanity check for prescaler value
- udlfb: Fix memory leak in dlfb_usb_probe
- sched/core: Allow try_invoke_on_locked_down_task() with irqs disabled
- JFS: more checks for invalid superblock
- x86/build: Treat R_386_PLT32 relocation as R_386_PC32
- drm/virtio: use kvmalloc for large allocations
- Input: elan_i2c - add new trackpoint report type 0x5F
- Input: elantech - fix protocol errors for some trackpoints in SMBus mode
- net: usb: qmi_wwan: support ZTE P685M modem
- ARM: dts: aspeed: Add LCLK to lpc-snoop
- net_sched: fix RTNL deadlock again caused by request_module()
- net: qrtr: Fix memory leak in qrtr_tun_open
- net: sched: fix police ext initialization
- wireguard: queueing: get rid of per-peer ring buffers
- wireguard: selftests: test multiple parallel streams
- net: icmp: pass zeroed opts from icmp{,v6}_ndo_send before sending
- ipv6: silence compilation warning for non-IPV6 builds
- kgdb: fix to kill breakpoints on initmem after boot
- drm/i915: Reject 446-480MHz HDMI clock on GLK
- dm era: only resize metadata in preresume
- dm era: Reinitialize bitset cache before digesting a new writeset
- dm era: Use correct value size in equality function of writeset tree
- dm era: Fix bitset memory leaks
- dm era: Verify the data block size hasn't changed
- dm era: Update in-core bitset after committing the metadata
- dm era: Recover committed writeset after crash
- dm writecache: fix writing beyond end of underlying device when shrinking
- dm writecache: return the exact table values that were set
- dm writecache: fix performance degradation in ssd mode
- dm table: fix zoned iterate_devices based device capability checks
- dm table: fix DAX iterate_devices based device capability checks
- dm table: fix iterate_devices based device capability checks
- dm: fix deadlock when swapping to encrypted device
- gfs2: Recursive gfs2_quota_hold in gfs2_iomap_end
- gfs2: Lock imbalance on error path in gfs2_recover_one
- gfs2: Don't skip dlm unlock if glock has an lvb
- gfs2: fix glock confusion in function signal_our_withdraw
- spi: spi-synquacer: fix set_cs handling
- spi: fsl: invert spisel_boot signal on MPC8309
- sparc32: fix a user-triggerable oops in clear_user()
- f2fs: flush data when enabling checkpoint back
- f2fs: enforce the immutable flag on open files
- f2fs: fix out-of-repair __setattr_copy()
- irqchip/loongson-pch-msi: Use bitmap_zalloc() to allocate bitmap
- um: defer killing userspace on page table update failures
- um: mm: check more comprehensively for stub changes
- virtio/s390: implement virtio-ccw revision 2 correctly
- s390/vtime: fix inline assembly clobber list
- proc: don't allow async path resolution of /proc/thread-self components
- cpufreq: intel_pstate: Get per-CPU max freq via MSR_HWP_CAPABILITIES if available
- cpufreq: intel_pstate: Change intel_pstate_get_hwp_max() argument
- cpufreq: qcom-hw: drop devm_xxx() calls from init/exit hooks
- thermal: cpufreq_cooling: freq_qos_update_request() returns < 0 on error
- kcmp: Support selection of SYS_kcmp without CHECKPOINT_RESTORE
- zonefs: Fix file size of zones in full condition
- exfat: fix shift-out-of-bounds in exfat_fill_super()
- printk: fix deadlock when kernel panic
- mfd: gateworks-gsc: Fix interrupt type
- gpio: pcf857x: Fix missing first interrupt
- mei: me: add adler lake point LP DID
- mei: me: add adler lake point S DID
- mei: me: emmitsburg workstation DID
- mei: fix transfer over dma with extended header
- spmi: spmi-pmic-arb: Fix hw_irq overflow
- powerpc/32s: Add missing call to kuep_lock on syscall entry
- powerpc/kexec_file: fix FDT size estimation for kdump kernel
- powerpc/32: Preserve cr1 in exception prolog stack check to fix build error
- mmc: sdhci-pci-o2micro: Bug fix for SDR104 HW tuning failure
- mmc: sdhci-esdhc-imx: fix kernel panic when remove module
- module: Ignore _GLOBAL_OFFSET_TABLE_ when warning for undefined symbols
- nvmem: qcom-spmi-sdam: Fix uninitialized pdev pointer
- KVM: nSVM: fix running nested guests when npt=0
- mm, compaction: make fast_isolate_freepages() stay within zone
- mm/vmscan: restore zone_reclaim_mode ABI
- hugetlb: fix copy_huge_page_from_user contig page struct assumption
- hugetlb: fix update_and_free_page contig page struct assumption
- mm: memcontrol: fix get_active_memcg return value
- mm: memcontrol: fix swap undercounting in cgroup2
- x86: fix seq_file iteration for pat/memtype.c
- seq_file: document how per-entry resources are managed.
- fs/affs: release old buffer head on error path
- mtd: spi-nor: hisi-sfc: Put child node np on error path
- mtd: spi-nor: core: Add erase size check for erase command initialization
- mtd: spi-nor: core: Fix erase type discovery for overlaid region
- mtd: spi-nor: sfdp: Fix wrong erase type bitmask for overlaid region
- mtd: spi-nor: sfdp: Fix last erase region marking
- coresight: etm4x: Handle accesses to TRCSTALLCTLR
- watchdog: mei_wdt: request stop on unregister
- watchdog: qcom: Remove incorrect usage of QCOM_WDT_ENABLE_IRQ
- riscv: Disable KSAN_SANITIZE for vDSO
- arm64: spectre: Prevent lockdep splat on v4 mitigation enable path
- arm64 module: set plt* section addresses to 0x0
- arm64: uprobe: Return EOPNOTSUPP for AARCH32 instruction probing
- arm64: kexec_file: fix memory leakage in create_dtb() when fdt_open_into() fails
- iommu/arm-smmu-qcom: Fix mask extraction for bootloader programmed SMRs
- arm64: Extend workaround for erratum 1024718 to all versions of Cortex-A55
- kprobes: Fix to delay the kprobes jump optimization
- rcu/nocb: Perform deferred wake up before last idle's need_resched() check
- rcu: Pull deferred rcuog wake up to rcu_eqs_enter() callers
- powerpc/prom: Fix "ibm,arch-vec-5-platform-support" scan
- x86/entry: Fix instrumentation annotation
- x86/fault: Fix AMD erratum #91 errata fixup for user code
- x86/reboot: Force all cpus to exit VMX root if VMX is supported
- x86/virt: Eat faults on VMXOFF in reboot flows
- media: smipcie: fix interrupt handling and IR timeout
- media: marvell-ccic: power up the device on mclk enable
- media: ipu3-cio2: Fix mbus_code processing in cio2_subdev_set_fmt()
- media: ir_toy: add another IR Droid device
- media: i2c: max9286: fix access to unallocated memory
- floppy: reintroduce O_NDELAY fix
- staging: rtl8188eu: Add Edimax EW-7811UN V2 to device table
- staging: gdm724x: Fix DMA from stack
- staging/mt7621-dma: mtk-hsdma.c->hsdma-mt7621.c
- arm64: dts: agilex: fix phy interface bit shift for gmac1 and gmac2
- dts64: mt7622: fix slow sd card access
- pstore: Fix typo in compression option name
- drivers/misc/vmw_vmci: restrict too big queue size in qp_host_alloc_queue
- misc: rtsx: init of rts522a add OCP power off when no card is present
- arm64: ptrace: Fix seccomp of traced syscall -1 (NO_SYSCALL)
- seccomp: Add missing return in non-void function
- soc: samsung: exynos-asv: handle reading revision register error
- soc: samsung: exynos-asv: don't defer early on not-supported SoCs
- crypto: sun4i-ss - initialize need_fallback
- crypto: sun4i-ss - handle BigEndian for cipher
- crypto: sun4i-ss - IV register does not work on A10 and A13
- crypto: sun4i-ss - checking sg length is not sufficient
- crypto: michael_mic - fix broken misalignment handling
- crypto: aesni - prevent misaligned buffers on the stack
- crypto: arm64/sha - add missing module aliases
- drm/i915/gt: Correct surface base address for renderclear
- drm/i915/gt: Flush before changing register state
- btrfs: fix extent buffer leak on failure to copy root
- btrfs: account for new extents being deleted in total_bytes_pinned
- btrfs: handle space_info::total_bytes_pinned inside the delayed ref itself
- btrfs: splice remaining dirty_bg's onto the transaction dirty bg list
- btrfs: fix reloc root leak with 0 ref reloc roots on recovery
- btrfs: abort the transaction if we fail to inc ref in btrfs_copy_root
- btrfs: add asserts for deleting backref cache nodes
- btrfs: do not warn if we can't find the reloc root when looking up backref
- btrfs: do not cleanup upper nodes in btrfs_backref_cleanup_node
- KEYS: trusted: Reserve TPM for seal and unseal operations
- KEYS: trusted: Fix migratable=1 failing
- KEYS: trusted: Fix incorrect handling of tpm_get_random()
- tpm_tis: Clean up locality release
- tpm_tis: Fix check_locality for correct locality acquisition
- erofs: initialized fields can only be observed after bit is set
- selinux: fix inconsistency between inode_getxattr and inode_listsecurity
- ASoC: siu: Fix build error by a wrong const prefix
- drm/rockchip: Require the YTR modifier for AFBC
- drm/panel: kd35t133: allow using non-continuous dsi clock
- drm/sched: Cancel and flush all outstanding jobs before finish.
- drm/modes: Switch to 64bit maths to avoid integer overflow
- drm/nouveau/kms: handle mDP connectors
- drm/amdgpu: Set reference clock to 100Mhz on Renoir (v2)
- drm/amdkfd: Fix recursive lock warnings
- drm/amd/display: Add vupdate_no_lock interrupts for DCN2.1
- drm/amd/display: Remove Assert from dcn10_get_dig_frontend
- drm/amd/display: Add FPU wrappers to dcn21_validate_bandwidth()
- Revert "drm/amd/display: Update NV1x SR latency values"
- bcache: Move journal work to new flush wq
- bcache: Give btree_io_wq correct semantics again
- Revert "bcache: Kill btree_io_wq"
- Revert "MIPS: Octeon: Remove special handling of CONFIG_MIPS_ELF_APPENDED_DTB=y"
- MIPS: VDSO: Use CLANG_FLAGS instead of filtering out '--target='
- MIPS: Support binutils configured with --enable-mips-fix-loongson3-llsc=yes
- MIPS: Ingenic: Disable HPTLB for D0 XBurst CPUs too
- ALSA: hda/realtek: Quirk for HP Spectre x360 14 amp setup
- ALSA: hda/realtek: modify EAPD in the ALC886
- ALSA: hda/hdmi: Drop bogus check at closing a stream
- ALSA: hda: Add another CometLake-H PCI ID
- ALSA: fireface: fix to parse sync status register of latter protocol
- phy: lantiq: rcu-usb2: wait after clock enable
- USB: serial: mos7720: fix error code in mos7720_write()
- USB: serial: mos7840: fix error code in mos7840_write()
- USB: serial: pl2303: fix line-speed handling on newer chips
- USB: serial: ftdi_sio: fix FTX sub-integer prescaler
- usb: dwc3: gadget: Fix dep->interval for fullspeed interrupt
- usb: dwc3: gadget: Fix setting of DEPCFG.bInterval_m1
- usb: musb: Fix runtime PM race in musb_queue_resume_work
- USB: serial: option: update interface mapping for ZTE P685M
- media: mceusb: Fix potential out-of-bounds shift
- Input: i8042 - add ASUS Zenbook Flip to noselftest list
- Input: joydev - prevent potential read overflow in ioctl
- Input: xpad - add support for PowerA Enhanced Wired Controller for Xbox Series X|S
- Input: raydium_ts_i2c - do not send zero length
- HID: wacom: Ignore attempts to overwrite the touch_max value from HID
- HID: logitech-dj: add support for keyboard events in eQUAD step 4 Gaming
- cpufreq: ACPI: Set cpuinfo.max_freq directly if max boost is known
- ACPI: configfs: add missing check after configfs_register_default_group()
- ACPI: property: Fix fwnode string properties matching
- soundwire: intel: fix possible crash when no device is detected
- blk-settings: align max_sectors on "logical_block_size" boundary
- scsi: sd: Fix Opal support
- ide/falconide: Fix module unload
- block: reopen the device in blkdev_reread_part
- scsi: sd: sd_zbc: Don't pass GFP_NOIO to kvcalloc
- scsi: bnx2fc: Fix Kconfig warning & CNIC build errors
- csky: Fix a size determination in gpr_get()
- proc: use kvzalloc for our kernel buffer
- mm/rmap: fix potential pte_unmap on an not mapped pte
- mm: fix memory_failure() handling of dax-namespace metadata
- mm,thp,shmem: make khugepaged obey tmpfs mount flags
- i2c: exynos5: Preserve high speed master code
- i2c: brcmstb: Fix brcmstd_send_i2c_cmd condition
- arm64: Add missing ISB after invalidating TLB in __primary_switch
- KVM: x86/mmu: Expand collapsible SPTE zap for TDP MMU to ZONE_DEVICE and HugeTLB pages
- KVM: SVM: Intercept INVPCID when it's disabled to inject #UD
- NFSv4: Fixes for nfs4_bitmask_adjust()
- r8169: fix jumbo packet handling on RTL8168e
- mm/compaction: fix misbehaviors of fast_find_migrateblock()
- mm/hugetlb: suppress wrong warning info when alloc gigantic page
- mm/hugetlb: fix potential double free in hugetlb_register_node() error path
- mm/memory.c: fix potential pte_unmap_unlock pte error
- mm: memcontrol: fix slub memory accounting
- mm: memcontrol: fix NR_ANON_THPS accounting in charge moving
- ocfs2: fix a use after free on error
- wireguard: kconfig: use arm chacha even with no neon
- wireguard: device: do not generate ICMP for non-IP packets
- vxlan: move debug check after netdev unregister
- PCI: rockchip: Make 'ep-gpios' DT property optional
- net/mlx4_core: Add missed mlx4_free_cmd_mailbox()
- net: stmmac: fix CBS idleslope and sendslope calculation
- ice: update the number of available RSS queues
- ice: Fix state bits on LLDP mode switch
- ice: Account for port VLAN in VF max packet size calculation
- ice: report correct max number of TCs
- vfio/type1: Use follow_pte()
- pwm: iqs620a: Fix overflow and optimize calculations
- octeontx2-af: Fix an off by one in rvu_dbg_qsize_write()
- i40e: Fix add TC filter for IPv6
- nios2: fixed broken sys_clone syscall
- Take mmap lock in cacheflush syscall
- i40e: Fix VFs not created
- i40e: Fix addition of RX filters after enabling FW LLDP agent
- i40e: Fix overwriting flow control settings during driver loading
- i40e: Add zero-initialization of AQ command structures
- i40e: Fix flow for IPv6 next header (extension header)
- PCI: cadence: Fix DMA range mapping early return error
- PCI: pci-bridge-emul: Fix array overruns, improve safety
- device-dax: Fix default return code of range_parse()
- mailbox: sprd: correct definition of SPRD_OUTBOX_FIFO_FULL
- ext: EXT4_KUNIT_TESTS should depend on EXT4_FS instead of selecting it
- regmap: sdw: use _no_pm functions in regmap_read/write
- remoteproc/mediatek: acknowledge watchdog IRQ after handled
- misc: fastrpc: fix incorrect usage of dma_map_sgtable
- soundwire: bus: fix confusion on device used by pm_runtime
- soundwire: export sdw_write/read_no_pm functions
- soundwire: bus: use sdw_write_no_pm when setting the bus scale registers
- soundwire: bus: use sdw_update_no_pm when initializing a device
- nvmem: core: skip child nodes not matching binding
- nvmem: core: Fix a resource leak on error in nvmem_add_cells_from_of()
- coresight: etm4x: Skip accessing TRCPDCR in save/restore
- phy: USB_LGM_PHY should depend on X86
- ext4: fix potential htree index checksum corruption
- vfio-pci/zdev: fix possible segmentation fault issue
- vfio/iommu_type1: Fix some sanity checks in detach group
- vfio/iommu_type1: Populate full dirty when detach non-pinned group
- drm/msm/dp: trigger unplug event in msm_dp_display_disable
- drm/msm: Fix races managing the OOB state for timestamp vs timestamps.
- drm/msm: Fix race of GPU init vs timestamp power management.
- drm/msm/mdp5: Fix wait-for-commit for cmd panels
- drm/msm/dsi: Correct io_start for MSM8994 (20nm PHY)
- drm/msm: Fix MSM_INFO_GET_IOVA with carveout
- mei: hbm: call mei_set_devstate() on hbm stop response
- PCI: Align checking of syscall user config accessors
- VMCI: Use set_page_dirty_lock() when unregistering guest memory
- PCI: xilinx-cpm: Fix reference count leak on error path
- pwm: rockchip: Eliminate potential race condition when probing
- pwm: rockchip: rockchip_pwm_probe(): Remove superfluous clk_unprepare()
- pwm: rockchip: Enable APB clock during register access while probing
- soundwire: cadence: fix ACK/NAK handling
- PCI: rcar: Always allocate MSI addresses in 32bit space
- misc: eeprom_93xx46: Add module alias to avoid breaking support for non device tree users
- phy: cadence-torrent: Fix error code in cdns_torrent_phy_probe()
- phy: rockchip-emmc: emmc_phy_init() always return 0
- misc: eeprom_93xx46: Fix module alias to enable module autoprobe
- ARM: 9065/1: OABI compat: fix build when EPOLL is not enabled
- Input: zinitix - fix return type of zinitix_init_touch()
- sparc: fix led.c driver when PROC_FS is not enabled
- sparc64: only select COMPAT_BINFMT_ELF if BINFMT_ELF is set
- Input: elo - fix an error code in elo_connect()
- perf test: Fix unaligned access in sample parsing test
- perf intel-pt: Fix IPC with CYC threshold
- perf intel-pt: Fix premature IPC
- perf intel-pt: Fix missing CYC processing in PSB
- perf record: Fix continue profiling after draining the buffer
- Input: sur40 - fix an error code in sur40_probe()
- RDMA/rtrs-srv: Do not pass a valid pointer to PTR_ERR()
- RDMA/rtrs-srv-sysfs: fix missing put_device
- RDMA/rtrs-srv: fix memory leak by missing kobject free
- RDMA/rtrs: Only allow addition of path to an already established session
- RDMA/rtrs-srv: Fix stack-out-of-bounds
- RDMA/ucma: Fix use-after-free bug in ucma_create_uevent
- RDMA/hns: Fixes missing error code of CMDQ
- ceph: fix flush_snap logic after putting caps
- svcrdma: Hold private mutex while invoking rdma_accept()
- nfsd: register pernet ops last, unregister first
- perf symbols: Fix return value when loading PE DSO
- printk: avoid prb_first_valid_seq() where possible
- spi: Skip zero-length transfers in spi_transfer_one_message()
- spi: dw: Avoid stack content exposure
- regulator: bd718x7, bd71828, Fix dvs voltage levels
- perf symbols: Use (long) for iterator for bfd symbols
- selftests/ftrace: Update synthetic event syntax errors
- clk: aspeed: Fix APLL calculate formula from ast2600-A2
- regulator: qcom-rpmh: fix pm8009 ldo7
- powerpc/kuap: Restore AMR after replaying soft interrupts
- powerpc/uaccess: Avoid might_fault() when user access is enabled
- spi: pxa2xx: Fix the controller numbering for Wildcat Point
- clk: divider: fix initialization with parent_hw
- RDMA/hns: Disable RQ inline by default
- RDMA/hns: Fix type of sq_signal_bits
- RDMA/siw: Fix calculation of tx_valid_cpus size
- RDMA/hns: Fixed wrong judgments in the goto branch
- kselftests: dmabuf-heaps: Fix Makefile's inclusion of the kernel's usr/include dir
- kunit: tool: fix unit test cleanup handling
- clk: qcom: gcc-msm8998: Fix Alpha PLL type for all GPLLs
- powerpc/8xx: Fix software emulation interrupt
- powerpc/pseries/dlpar: handle ibm, configure-connector delay status
- mfd: wm831x-auxadc: Prevent use after free in wm831x_auxadc_read_irq()
- mfd: altera-sysmgr: Fix physical address storing more
- spi: stm32: properly handle 0 byte transfer
- RDMA/rxe: Correct skb on loopback path
- RDMA/rxe: Fix coding error in rxe_rcv_mcast_pkt
- RDMA/rxe: Fix coding error in rxe_recv.c
- perf vendor events arm64: Fix Ampere eMag event typo
- perf tools: Fix DSO filtering when not finding a map for a sampled address
- rtc: zynqmp: depend on HAS_IOMEM
- tracepoint: Do not fail unregistering a probe due to memory failure
- IB/cm: Avoid a loop when device has 255 ports
- IB/mlx5: Return appropriate error code instead of ENOMEM
- iommu: Properly pass gfp_t in _iommu_map() to avoid atomic sleeping
- iommu: Move iotlb_sync_map out from __iommu_map
- amba: Fix resource leak for drivers without .remove
- i2c: qcom-geni: Store DMA mapping data in geni_i2c_dev struct
- ARM: 9046/1: decompressor: Do not clear SCTLR.nTLSMD for ARMv7+ cores
- mmc: renesas_sdhi_internal_dmac: Fix DMA buffer alignment from 8 to 128-bytes
- mmc: usdhi6rol0: Fix a resource leak in the error handling path of the probe
- mmc: sdhci-sprd: Fix some resource leaks in the remove function
- mmc: owl-mmc: Fix a resource leak in an error handling path and in the remove function
- powerpc/time: Enable sched clock for irqtime
- powerpc/47x: Disable 256k page size
- KVM: PPC: Make the VMX instruction emulation routines static
- IB/umad: Return EPOLLERR in case of when device disassociated
- IB/umad: Return EIO in case of when device disassociated
- iommu: Switch gather->end to the inclusive end
- scsi: lpfc: Fix ancient double free
- objtool: Fix ".cold" section suffix check for newer versions of GCC
- objtool: Fix retpoline detection in asm code
- objtool: Fix error handling for STD/CLD warnings
- auxdisplay: ht16k33: Fix refresh rate handling
- watchdog: intel-mid_wdt: Postpone IRQ handler registration till SCU is ready
- isofs: release buffer head before return
- regulator: core: Avoid debugfs: Directory ... already present! error
- power: supply: smb347-charger: Fix interrupt usage if interrupt is unavailable
- power: supply: axp20x_usb_power: Init work before enabling IRQs
- regulator: s5m8767: Drop regulators OF node reference
- spi: atmel: Put allocated master before return
- regulator: s5m8767: Fix reference count leak
- certs: Fix blacklist flag type confusion
- watch_queue: Drop references to /dev/watch_queue
- regulator: axp20x: Fix reference cout leak
- platform/chrome: cros_ec_proto: Add LID and BATTERY to default mask
- platform/chrome: cros_ec_proto: Use EC_HOST_EVENT_MASK not BIT
- clk: sunxi-ng: h6: Fix clock divider range on some clocks
- IB/mlx5: Add mutex destroy call to cap_mask_mutex mutex
- RDMA/mlx5: Use the correct obj_id upon DEVX TIR creation
- spi: imx: Don't print error on -EPROBEDEFER
- clocksource/drivers/mxs_timer: Add missing semicolon when DEBUG is defined
- clocksource/drivers/ixp4xx: Select TIMER_OF when needed
- power: supply: fix sbs-charger build, needs REGMAP_I2C
- dmaengine: idxd: set DMA channel to be private
- rtc: s5m: select REGMAP_I2C
- power: reset: at91-sama5d2_shdwc: fix wkupdbc mask
- RDMA/rtrs-srv: Init wr_cnt as 1
- RDMA/rtrs-clt: Refactor the failure cases in alloc_clt
- RDMA/rtrs-srv: Fix missing wr_cqe
- RDMA/rtrs: Call kobject_put in the failure path
- RDMA/rtrs-clt: Set mininum limit when create QP
- RDMA/rtrs-srv: Use sysfs_remove_file_self for disconnect
- RDMA/rtrs-srv: Release lock before call into close_sess
- RDMA/rtrs: Extend ibtrs_cq_qp_create
- of/fdt: Make sure no-map does not remove already reserved regions
- fdt: Properly handle "no-map" field in the memory region
- power: supply: cpcap-charger: Fix power_supply_put on null battery pointer
- power: supply: cpcap-battery: Fix missing power_supply_put()
- power: supply: cpcap-charger: Fix missing power_supply_put()
- mfd: bd9571mwv: Use devm_mfd_add_devices()
- dmaengine: hsu: disable spurious interrupt
- dmaengine: owl-dma: Fix a resource leak in the remove function
- dmaengine: fsldma: Fix a resource leak in an error handling path of the probe function
- dmaengine: fsldma: Fix a resource leak in the remove function
- RDMA/siw: Fix handling of zero-sized Read and Receive Queues.
- HID: core: detect and skip invalid inputs to snto32()
- clk: renesas: r8a779a0: Fix parent of CBFUSA clock
- clk: renesas: r8a779a0: Remove non-existent S2 clock
- clk: sunxi-ng: h6: Fix CEC clock
- spi: cadence-quadspi: Abort read if dummy cycles required are too many
- i2c: iproc: handle master read request
- i2c: iproc: update slave isr mask (ISR_MASK_SLAVE)
- i2c: iproc: handle only slave interrupts which are enabled
- quota: Fix memory leak when handling corrupted quota file
- arm64: dts: qcom: qrb5165-rb5: fix pm8009 regulators
- regulator: qcom-rpmh-regulator: add pm8009-1 chip revision
- selftests/powerpc: Make the test check in eeh-basic.sh posix compliant
- clk: meson: clk-pll: propagate the error from meson_clk_pll_set_rate()
- clk: meson: clk-pll: make "ret" a signed integer
- clk: meson: clk-pll: fix initializing the old rate (fallback) for a PLL
- power: supply: cpcap: Add missing IRQF_ONESHOT to fix regression
- HSI: Fix PM usage counter unbalance in ssi_hw_init
- capabilities: Don't allow writing ambiguous v3 file capabilities
- drm/amdgpu/display: remove hdcp_srm sysfs on device removal
- smp: Process pending softirqs in flush_smp_call_function_from_idle()
- irqchip/imx: IMX_INTMUX should not default to y, unconditionally
- ubifs: Fix error return code in alloc_wbufs()
- ubifs: replay: Fix high stack usage, again
- ubifs: Fix memleak in ubifs_init_authentication
- jffs2: fix use after free in jffs2_sum_write_data()
- fs/jfs: fix potential integer overflow on shift of a int
- ASoC: simple-card-utils: Fix device module clock
- ima: Free IMA measurement buffer after kexec syscall
- ima: Free IMA measurement buffer on error
- ASoC: SOF: sof-pci-dev: add missing Up-Extreme quirk
- nvmet: set status to 0 in case for invalid nsid
- nvmet: remove extra variable in identify ns
- nvme-multipath: set nr_zones for zoned namespaces
- nvmet-tcp: fix potential race of tcp socket closing accept_work
- nvmet-tcp: fix receive data digest calculation for multiple h2cdata PDUs
- io_uring: fix possible deadlock in io_uring_poll
- crypto: ecdh_helper - Ensure 'len >= secret.len' in decode_key()
- hwrng: timeriomem - Fix cooldown period calculation
- drm/dp_mst: Don't cache EDIDs for physical ports
- drm/lima: fix reference leak in lima_pm_busy
- drm/vc4: hdmi: Update the CEC clock divider on HSM rate change
- drm/vc4: hdmi: Compute the CEC clock divider from the clock rate
- drm/vc4: hdmi: Restore cec physical address on reconnect
- drm/vc4: hdmi: Fix up CEC registers
- drm/vc4: hdmi: Fix register offset with longer CEC messages
- drm/vc4: hdmi: Move hdmi reset to bind
- s390/zcrypt: return EIO when msg retry limit reached
- KVM: x86: Restore all 64 bits of DR6 and DR7 during RSM on x86-64
- btrfs: fix double accounting of ordered extent for subpage case in btrfs_invalidapge
- btrfs: clarify error returns values in __load_free_space_cache
- ASoC: SOF: debug: Fix a potential issue on string buffer termination
- ASoC: rt5682: Fix panic in rt5682_jack_detect_handler happening during system shutdown
- ASoC: qcom: lpass: Fix i2s ctl register bit map
- locking/lockdep: Avoid unmatched unlock
- ASoC: Intel: sof_sdw: add missing TGL_HDMI quirk for Dell SKU 0A3E
- ASoC: Intel: sof_sdw: add missing TGL_HDMI quirk for Dell SKU 0A5E
- Drivers: hv: vmbus: Avoid use-after-free in vmbus_onoffer_rescind()
- drm/mediatek: Check if fb is null
- KVM: nSVM: Don't strip host's C-bit from guest's CR3 when reading PDPTRs
- ASoC: qcom: Fix typo error in HDMI regmap config callbacks
- f2fs: fix a wrong condition in __submit_bio
- drm/amdgpu: Prevent shift wrapping in amdgpu_read_mask()
- f2fs: fix to avoid inconsistent quota data
- mtd: parsers: afs: Fix freeing the part name memory in failure
- ASoC: codecs: add missing max_register in regmap config
- ASoC: cpcap: fix microphone timeslot mask
- ata: ahci_brcm: Add back regulators management
- mm: proc: Invalidate TLB after clearing soft-dirty page state
- drm/nouveau: bail out of nouveau_channel_new if channel init fails
- crypto: talitos - Fix ctr(aes) on SEC1
- crypto: talitos - Work around SEC6 ERRATA (AES-CTR mode data size error)
- mtd: parser: imagetag: fix error codes in bcm963xx_parse_imagetag_partitions()
- perf/arm-cmn: Move IRQs when migrating context
- perf/arm-cmn: Fix PMU instance naming
- ASoC: SOF: Intel: hda: cancel D0i3 work during runtime suspend
- ASoC: qcom: lpass-cpu: Remove bit clock state check
- f2fs: compress: fix potential deadlock
- sched/eas: Don't update misfit status if the task is pinned
- media: uvcvideo: Accept invalid bFormatIndex and bFrameIndex values
- media: pxa_camera: declare variable when DEBUG is defined
- media: mtk-vcodec: fix argument used when DEBUG is defined
- media: cx25821: Fix a bug when reallocating some dma memory
- media: qm1d1c0042: fix error return code in qm1d1c0042_init()
- media: atomisp: Fix a buffer overflow in debug code
- media: vidtv: psi: fix missing crc for PMT
- media: lmedm04: Fix misuse of comma
- media: software_node: Fix refcounts in software_node_get_next_child()
- drm/amd/display: Fix HDMI deep color output for DCE 6-11.
- drm/amd/display: Fix 10/12 bpc setup in DCE output bit depth reduction.
- macintosh/adb-iop: Use big-endian autopoll mask
- bsg: free the request before return error code
- drm/amdgpu: toggle on DF Cstate after finishing xgmi injection
- drm/tegra: Fix reference leak when pm_runtime_get_sync() fails
- MIPS: Compare __SYNC_loongson3_war against 0
- MIPS: properly stop .eh_frame generation
- media: ti-vpe: cal: fix write to unallocated memory
- media: imx7: csi: Fix pad link validation
- media: imx7: csi: Fix regression for parallel cameras on i.MX6UL
- drm/sun4i: tcon: fix inverted DCLK polarity
- sched/fair: Avoid stale CPU util_est value for schedutil in task dequeue
- crypto: bcm - Rename struct device_private to bcm_device_private
- evm: Fix memleak in init_desc
- ASoC: qcom: qdsp6: Move frontend AIFs to q6asm-dai
- ASoC: cs42l56: fix up error handling in probe
- media: aspeed: fix error return code in aspeed_video_setup_video()
- media: tm6000: Fix memleak in tm6000_start_stream
- media: media/pci: Fix memleak in empress_init
- media: em28xx: Fix use-after-free in em28xx_alloc_urbs
- media: vsp1: Fix an error handling path in the probe function
- media: camss: missing error code in msm_video_register()
- media: mtk-vcodec: fix error return code in vdec_vp9_decode()
- media: imx: Fix csc/scaler unregister
- media: imx: Unregister csc/scaler only if registered
- media: i2c: ov5670: Fix PIXEL_RATE minimum value
- media: ipu3-cio2: Build only for x86
- drm/fourcc: fix Amlogic format modifier masks
- drm/virtio: make sure context is created in gem open
- MIPS: lantiq: Explicitly compare LTQ_EBU_PCC_ISTAT against 0
- MIPS: c-r4k: Fix section mismatch for loongson2_sc_init
- drm/amdgpu: Fix macro name _AMDGPU_TRACE_H_ in preprocessor if condition
- drm: rcar-du: Fix the return check of of_parse_phandle and of_find_device_by_node
- drm: rcar-du: Fix crash when using LVDS1 clock for CRTC
- drm: rcar-du: Fix PM reference leak in rcar_cmm_enable()
- kcsan: Rewrite kcsan_prandom_u32_max() without prandom_u32_state()
- media: allegro: Fix use after free on error
- hwrng: ingenic - Fix a resource leak in an error handling path
- crypto: arm64/aes-ce - really hide slower algos when faster ones are enabled
- crypto: sun4i-ss - fix kmap usage
- crypto: sun4i-ss - linearize buffers content must be kept
- drm/vc4: hdmi: Take into account the clock doubling flag in atomic_check
- drm/panel: mantix: Tweak init sequence
- drm/fb-helper: Add missed unlocks in setcmap_legacy()
- gma500: clean up error handling in init
- drm/gma500: Fix error return code in psb_driver_load()
- fbdev: aty: SPARC64 requires FB_ATY_CT
- tty: implement read_iter
- tty: convert tty_ldisc_ops 'read()' function to take a kernel pointer
- net: enetc: fix destroyed phylink dereference during unbind
- net: mvneta: Remove per-cpu queue mapping for Armada 3700
- net: amd-xgbe: Fix network fluctuations when using 1G BELFUSE SFP
- net: amd-xgbe: Reset link when the link never comes back
- net: amd-xgbe: Fix NETDEV WATCHDOG transmit queue timeout warning
- net: amd-xgbe: Reset the PHY rx data path when mailbox command timeout
- net: phy: mscc: adding LCPLL reset to VSC8514
- net: dsa: felix: don't deinitialize unused ports
- net: dsa: felix: perform teardown in reverse order of setup
- ibmvnic: skip send_request_unmap for timeout reset
- ibmvnic: add memory barrier to protect long term buffer
- bpf: Clear subreg_def for global function return values
- b43: N-PHY: Fix the update of coef for the PHY revision >= 3case
- cxgb4/chtls/cxgbit: Keeping the max ofld immediate data size same in cxgb4 and ulds
- net: axienet: Handle deferred probe on clock properly
- tcp: fix SO_RCVLOWAT related hangs under mem pressure
- selftests: mptcp: fix ACKRX debug message
- bpf: Fix bpf_fib_lookup helper MTU check for SKB ctx
- bpf, devmap: Use GFP_KERNEL for xdp bulk queue allocation
- bpf: Fix an unitialized value in bpf_iter
- libbpf: Ignore non function pointer member in struct_ops
- mac80211: fix potential overflow when multiplying to u32 integers
- net/mlx5e: Check tunnel offload is required before setting SWP
- net/mlx5e: CT: manage the lifetime of the ct entry object
- net/mlx5: Disable devlink reload for lag devices
- net/mlx5: Disallow RoCE on lag device
- net/mlx5: Disallow RoCE on multi port slave device
- net/mlx5: Disable devlink reload for multi port slave device
- net/mlx5e: kTLS, Use refcounts to free kTLS RX priv context
- net/mlx5e: Replace synchronize_rcu with synchronize_net
- net/mlx5: Fix health error state handling
- net/mlx5e: Change interrupt moderation channel params also when channels are closed
- net/mlx5e: Don't change interrupt moderation params when DIM is enabled
- net: phy: consider that suspend2ram may cut off PHY power
- dpaa2-eth: fix memory leak in XDP_REDIRECT
- xen/netback: fix spurious event detection for common event case
- bnxt_en: Fix devlink info's stored fw.psid version format.
- bnxt_en: reverse order of TX disable and carrier off
- ibmvnic: Set to CLOSED state even on error
- selftests/bpf: Convert test_xdp_redirect.sh to bash
- ath9k: fix data bus crash when setting nf_override via debugfs
- iwlwifi: pnvm: increment the pointer before checking the TLV
- iwlwifi: pnvm: set the PNVM again if it was already loaded
- bpf_lru_list: Read double-checked variable once without lock
- iwlwifi: mvm: don't check if CSA event is running before removing
- iwlwifi: mvm: assign SAR table revision to the command later
- iwlwifi: mvm: send stored PPAG command instead of local
- iwlwifi: mvm: store PPAG enabled/disabled flag properly
- iwlwifi: mvm: fix the type we use in the PPAG table validity checks
- soc: aspeed: snoop: Add clock control logic
- ath11k: fix a locking bug in ath11k_mac_op_start()
- ath10k: Fix lockdep assertion warning in ath10k_sta_statistics
- ath10k: Fix suspicious RCU usage warning in ath10k_wmi_tlv_parse_peer_stats_info()
- ARM: at91: use proper asm syntax in pm_suspend
- staging: wfx: fix possible panic with re-queued frames
- optee: simplify i2c access
- ARM: s3c: fix fiq for clang IAS
- iwlwifi: mvm: set enabled in the PPAG command properly
- arm64: dts: meson: fix broken wifi node for Khadas VIM3L
- arm64: dts: msm8916: Fix reserved and rfsa nodes unit address
- soc: qcom: ocmem: don't return NULL in of_get_ocmem
- Bluetooth: btusb: Fix memory leak in btusb_mtk_wmt_recv
- opp: Correct debug message in _opp_add_static_v2()
- arm64: dts: armada-3720-turris-mox: rename u-boot mtd partition to a53-firmware
- ARM: dts: armada388-helios4: assign pinctrl to each fan
- ARM: dts: armada388-helios4: assign pinctrl to LEDs
- can: mcp251xfd: mcp251xfd_probe(): fix errata reference
- arm64: dts: renesas: beacon: Fix EEPROM compatible value
- x86/MSR: Filter MSR writes through X86_IOC_WRMSR_REGS ioctl too
- staging: rtl8723bs: wifi_regd.c: Fix incorrect number of regulatory rules
- usb: dwc2: Make "trimming xfer length" a debug message
- usb: dwc2: Abort transaction after errors with unknown reason
- usb: dwc2: Do not update data length if it is 0 on inbound transfers
- ARM: dts: Configure missing thermal interrupt for 4430
- memory: ti-aemif: Drop child node when jumping out loop
- Bluetooth: Put HCI device if inquiry procedure interrupts
- Bluetooth: drop HCI device reference before return
- staging: media: atomisp: Fix size_t format specifier in hmm_alloc() debug statemenet
- soc: ti: pm33xx: Fix some resource leak in the error handling paths of the probe function
- soc: qcom: socinfo: Fix an off by one in qcom_show_pmic_model()
- arm64: dts: qcom: sdm845-db845c: Fix reset-pin of ov8856 node
- usb: gadget: u_audio: Free requests only after callback
- ACPICA: Fix exception code class checks
- arm64: dts: rockchip: rk3328: Add clock_in_out property to gmac2phy node
- cpufreq: brcmstb-avs-cpufreq: Fix resource leaks in ->remove()
- cpufreq: brcmstb-avs-cpufreq: Free resources in error path
- arm64: dts: qcom: msm8916-samsung-a2015: Fix sensors
- arm64: dts: allwinner: A64: Limit MMC2 bus frequency to 150 MHz
- arm64: dts: allwinner: H6: Allow up to 150 MHz MMC bus frequency
- arm64: dts: allwinner: Drop non-removable from SoPine/LTS SD card
- arm64: dts: allwinner: H6: properly connect USB PHY to port 0
- arm64: dts: allwinner: A64: properly connect USB PHY to port 0
- firmware: arm_scmi: Fix call site of scmi_notification_exit
- bpf: Avoid warning when re-casting __bpf_call_base into __bpf_call_base_args
- bpf: Add bpf_patch_call_args prototype to include/linux/bpf.h
- net: stmmac: dwmac-meson8b: fix enabling the timing-adjustment clock
- arm64: dts: qcom: msm8916-samsung-a5u: Fix iris compatible
- staging: vchiq: Fix bulk transfers on 64-bit builds
- staging: vchiq: Fix bulk userdata handling
- Bluetooth: hci_qca: Fix memleak in qca_controller_memdump
- memory: mtk-smi: Fix PM usage counter unbalance in mtk_smi ops
- arm64: dts: exynos: correct PMIC interrupt trigger level on Espresso
- arm64: dts: exynos: correct PMIC interrupt trigger level on TM2
- ARM: dts: exynos: correct PMIC interrupt trigger level on Odroid XU3 family
- ARM: dts: exynos: correct PMIC interrupt trigger level on Arndale Octa
- ARM: dts: exynos: correct PMIC interrupt trigger level on Spring
- ARM: dts: exynos: correct PMIC interrupt trigger level on Rinato
- ARM: dts: exynos: correct PMIC interrupt trigger level on Monk
- ARM: dts: exynos: correct PMIC interrupt trigger level on Artik 5
- arm64: dts: renesas: beacon: Fix audio-1.8V pin enable
- arm64: dts: renesas: beacon kit: Fix choppy Bluetooth Audio
- Bluetooth: Fix initializing response id after clearing struct
- Bluetooth: hci_uart: Fix a race for write_work scheduling
- Bluetooth: btqcomsmd: Fix a resource leak in error handling paths in the probe function
- ath10k: Fix error handling in case of CE pipe init failure
- drm/i915/gt: One more flush for Baytrail clear residuals
- ALSA: pcm: Don't call sync_stop if it hasn't been stopped
- ALSA: pcm: Assure sync with the pending stop operation at suspend
- ALSA: pcm: Call sync_stop at disconnection
- random: fix the RNDRESEEDCRNG ioctl
- vmlinux.lds.h: Define SANTIZER_DISCARDS with CONFIG_GCOV_KERNEL=y
- MIPS: vmlinux.lds.S: add missing PAGE_ALIGNED_DATA() section
- ALSA: usb-audio: Fix PCM buffer allocation in non-vmalloc mode
- bfq: Avoid false bfq queue merging
- virt: vbox: Do not use wait_event_interruptible when called from kernel context
- PCI: Decline to resize resources if boot config must be preserved
- PCI: qcom: Use PHY_REFCLK_USE_PAD only for ipq8064
- w1: w1_therm: Fix conversion result for negative temperatures
- kdb: Make memory allocations more robust
- scsi: qla2xxx: Fix mailbox Ch erroneous error
- scsi: libsas: docs: Remove notify_ha_event()
- debugfs: do not attempt to create a new file before the filesystem is initalized
- debugfs: be more robust at handling improper input in debugfs_lookup()
- vdpa/mlx5: fix param validation in mlx5_vdpa_get_config()
- vmlinux.lds.h: add DWARF v5 sections
- scripts/recordmcount.pl: support big endian for ARCH sh
- kbuild: fix CONFIG_TRIM_UNUSED_KSYMS build for ppc64
- cifs: Set CIFS_MOUNT_USE_PREFIX_PATH flag on setting cifs_sb->prepath.
- cxgb4: Add new T6 PCI device id 0x6092
- NET: usb: qmi_wwan: Adding support for Cinterion MV31
- drm/xlnx: fix kmemleak by sending vblank_event in atomic_disable
- KVM: Use kvm_pfn_t for local PFN variable in hva_to_pfn_remapped()
- mm: provide a saner PTE walking API for modules
- KVM: do not assume PTE is writable after follow_pfn
- mm: simplify follow_pte{,pmd}
- mm: unexport follow_pte_pmd
- KVM: x86: Zap the oldest MMU pages, not the newest
- hwmon: (dell-smm) Add XPS 15 L502X to fan control blacklist
- arm64: tegra: Add power-domain for Tegra210 HDA
- Bluetooth: btusb: Some Qualcomm Bluetooth adapters stop working
- ntfs: check for valid standard information attribute
- ceph: downgrade warning from mdsmap decode to debug
- usb: quirks: add quirk to start video capture on ELMO L-12F document camera reliable
- USB: quirks: sort quirk entries
- nvme-rdma: Use ibdev_to_node instead of dereferencing ->dma_device
- RDMA: Lift ibdev_to_node from rds to common code
- HID: make arrays usage and value to be the same
- bpf: Fix truncation handling for mod32 dst reg wrt zero
- of: unittest: Fix build on architectures without CONFIG_OF_ADDRESS
- mm: Remove examples from enum zone_type comment
- arm64: mm: Set ZONE_DMA size based on early IORT scan
- arm64: mm: Set ZONE_DMA size based on devicetree's dma-ranges
- of: unittest: Add test for of_dma_get_max_cpu_address()
- of/address: Introduce of_dma_get_max_cpu_address()
- arm64: mm: Move zone_dma_bits initialization into zone_sizes_init()
- arm64: mm: Move reserve_crashkernel() into mem_init()
- rockchip: Make cdn_dp_resume depend on CONFIG_PM_SLEEP
- crypto - shash: reduce minimum alignment of shash_desc structure
- arm32: kaslr: print kaslr offset when kernel panic
- arm32: kaslr: pop visibility when compile decompress boot code as we need relocate BSS by GOT.
- arm32: kaslr: When boot with vxboot, we must adjust dtb address before kaslr_early_init, and store dtb address after init.
- arm: kaslr: Fix memtop calculate, when there is no memory top info, we can't use zero instead it.
- arm32: kaslr: Add missing sections about relocatable
- No idea why this broke ...
- ARM: decompressor: add KASLR support
- ARM: decompressor: explicitly map decompressor binary cacheable
- ARM: kernel: implement randomization of the kernel load address
- arm: vectors: use local symbol names for vector entry points
- ARM: kernel: refer to swapper_pg_dir via its symbol
- ARM: mm: export default vmalloc base address
- ARM: kernel: use PC relative symbol references in suspend/resume code
- ARM: kernel: use PC-relative symbol references in MMU switch code
- ARM: kernel: make vmlinux buildable as a PIE executable
- ARM: kernel: switch to relative exception tables
- arm-soc: various: replace open coded VA->PA calculation of pen_release
- arm-soc: mvebu: replace open coded VA->PA conversion
- arm-soc: exynos: replace open coded VA->PA conversions
- asm-generic: add .data.rel.ro sections to __ro_after_init
- Revert "[Huawei] Microchip Polarfire SoC Clock Driver"
- Revert "[Huawei] RISC-V: Add Microchip PolarFire kconfig option"
- sdei_watchdog: avoid possible false hardlockup
- kprobes/arm64: Blacklist sdei watchdog callback functions
- sdei_watchdog: set secure timer period base on 'watchdog_thresh'
- sdei_watchdog: clear EOI of the secure timer before kdump
- sdei_watchdog: refresh 'last_timestamp' when enabling nmi_watchdog
- watchdog: add nmi_watchdog support for arm64 based on SDEI
- lockup_detector: init lockup detector after all the init_calls
- firmware: arm_sdei: make 'sdei_api_event_disable/enable' public
- firmware: arm_sdei: add interrupt binding api
- watchdog: make hardlockup detect code public
- ARM: hw_breakpoint: Do not directly check the event's overflow_handler hook
- net/hinic: Remove the initialization of the global variable g_uld_info
- media: pwc: Use correct device for DMA
- btrfs: fix crash after non-aligned direct IO write with O_DSYNC
- btrfs: fix backport of 2175bf57dc952 in 5.10.13
- Bluetooth: btusb: Always fallback to alt 1 for WBS
- tty: protect tty_write from odd low-level tty disciplines
- xen-blkback: fix error handling in xen_blkbk_map()
- xen-scsiback: don't "handle" error by BUG()
- xen-netback: don't "handle" error by BUG()
- xen-blkback: don't "handle" error by BUG()
- xen/arm: don't ignore return errors from set_phys_to_machine
- Xen/gntdev: correct error checking in gntdev_map_grant_pages()
- Xen/gntdev: correct dev_bus_addr handling in gntdev_map_grant_pages()
- Xen/x86: also check kernel mapping in set_foreign_p2m_mapping()
- Xen/x86: don't bail early from clear_foreign_p2m_mapping()
- net: fix proc_fs init handling in af_packet and tls
- net: bridge: Fix a warning when del bridge sysfs
- net: openvswitch: fix TTL decrement exception action execution
- net: sched: incorrect Kconfig dependencies on Netfilter modules
- mt76: mt7615: fix rdd mcu cmd endianness
- mt76: mt7915: fix endian issues
- net/sched: fix miss init the mru in qdisc_skb_cb
- mptcp: skip to next candidate if subflow has unacked data
- net: qrtr: Fix port ID for control messages
- IB/isert: add module param to set sg_tablesize for IO cmd
- vdpa_sim: add get_config callback in vdpasim_dev_attr
- vdpa_sim: make 'config' generic and usable for any device type
- vdpa_sim: store parsed MAC address in a buffer
- vdpa_sim: add struct vdpasim_dev_attr for device attributes
- vdpa_sim: remove hard-coded virtq count
- kcov, usb: only collect coverage from __usb_hcd_giveback_urb in softirq
- ovl: expand warning in ovl_d_real()
- net/qrtr: restrict user-controlled length in qrtr_tun_write_iter()
- net/rds: restrict iovecs length for RDS_CMSG_RDMA_ARGS
- vsock: fix locking in vsock_shutdown()
- vsock/virtio: update credit only if socket is not closed
- switchdev: mrp: Remove SWITCHDEV_ATTR_ID_MRP_PORT_STAT
- bridge: mrp: Fix the usage of br_mrp_port_switchdev_set_state
- net: watchdog: hold device global xmit lock during tx disable
- net/vmw_vsock: improve locking in vsock_connect_timeout()
- net/vmw_vsock: fix NULL pointer dereference
- net: fix iteration for sctp transport seq_files
- net: gro: do not keep too many GRO packets in napi->rx_list
- cpufreq: ACPI: Update arch scale-invariance max perf ratio if CPPC is not there
- cpufreq: ACPI: Extend frequency tables to cover boost frequencies
- net: dsa: call teardown method on probe failure
- udp: fix skb_copy_and_csum_datagram with odd segment sizes
- rxrpc: Fix clearance of Tx/Rx ring when releasing a call
- arm64: mte: Allow PTRACE_PEEKMTETAGS access to the zero page
- x86/pci: Create PCI/MSI irqdomain after x86_init.pci.arch_init()
- scripts: set proper OpenSSL include dir also for sign-file
- h8300: fix PREEMPTION build, TI_PRE_COUNT undefined
- i2c: stm32f7: fix configuration of the digital filter
- clk: sunxi-ng: mp: fix parent rate change flag check
- drm/sun4i: dw-hdmi: Fix max. frequency for H6
- drm/sun4i: Fix H6 HDMI PHY configuration
- drm/sun4i: dw-hdmi: always set clock rate
- drm/sun4i: tcon: set sync polarity for tcon1 channel
- firmware_loader: align .builtin_fw to 8
- net: hns3: add a check for index in hclge_get_rss_key()
- net: hns3: add a check for tqp_index in hclge_get_ring_chain_from_mbx()
- net: hns3: add a check for queue_id in hclge_reset_vf_queue()
- net: dsa: felix: implement port flushing on .phylink_mac_link_down
- x86/build: Disable CET instrumentation in the kernel for 32-bit too
- scsi: scsi_debug: Fix a memory leak
- netfilter: conntrack: skip identical origin tuple in same zone only
- ibmvnic: Clear failover_pending if unable to schedule
- net: stmmac: set TxQ mode back to DCB after disabling CBS
- selftests: txtimestamp: fix compilation issue
- net: enetc: initialize the RFS and RSS memories
- hv_netvsc: Reset the RSC count if NVSP_STAT_FAIL in netvsc_receive()
- net: ipa: set error code in gsi_channel_setup()
- net: hdlc_x25: Return meaningful error code in x25_open
- xen/netback: avoid race in xenvif_rx_ring_slots_available()
- netfilter: flowtable: fix tcp and udp header checksum update
- netfilter: nftables: fix possible UAF over chains from packet path in netns
- selftests: netfilter: fix current year
- netfilter: xt_recent: Fix attempt to update deleted entry
- bpf: Check for integer overflow when using roundup_pow_of_two()
- bpf: Unbreak BPF_PROG_TYPE_KPROBE when kprobe is called via do_int3
- dmaengine: idxd: check device state before issue command
- drm/vc4: hvs: Fix buffer overflow with the dlist handling
- mt76: dma: fix a possible memory leak in mt76_add_fragment()
- ath9k: fix build error with LEDS_CLASS=m
- dmaengine: idxd: fix misc interrupt completion
- cgroup-v1: add disabled controller check in cgroup1_parse_param()
- KVM: x86: cleanup CR3 reserved bits checks
- lkdtm: don't move ctors to .rodata
- x86/efi: Remove EFI PGD build time checks
- Revert "lib: Restrict cpumask_local_spread to houskeeping CPUs"
- ubsan: implement __ubsan_handle_alignment_assumption
- ARM: kexec: fix oops after TLB are invalidated
- ARM: ensure the signal page contains defined contents
- kallsyms: fix nonconverging kallsyms table with lld
- ARM: dts: lpc32xx: Revert set default clock rate of HCLK PLL
- bfq-iosched: Revert "bfq: Fix computation of shallow depth"
- riscv: virt_addr_valid must check the address belongs to linear mapping
- drm/amd/display: Decrement refcount of dc_sink before reassignment
- drm/amd/display: Free atomic state after drm_atomic_commit
- drm/amd/display: Fix dc_sink kref count in emulated_link_detect
- drm/amd/display: Release DSC before acquiring
- drm/amd/display: Add more Clock Sources to DCN2.1
- drm/amd/display: Fix DPCD translation for LTTPR AUX_RD_INTERVAL
- nvme-pci: ignore the subsysem NQN on Phison E16
- x86/split_lock: Enable the split lock feature on another Alder Lake CPU
- scsi: lpfc: Fix EEH encountering oops with NVMe traffic
- ovl: skip getxattr of security labels
- cap: fix conversions on getxattr
- ovl: perform vfs_getxattr() with mounter creds
- arm64: dts: rockchip: Disable display for NanoPi R2S
- platform/x86: hp-wmi: Disable tablet-mode reporting by default
- arm64: dts: rockchip: remove interrupt-names property from rk3399 vdec node
- ARM: OMAP2+: Fix suspcious RCU usage splats for omap_enter_idle_coupled
- arm64: dts: qcom: sdm845: Reserve LPASS clocks in gcc
- arm64: dts: rockchip: Fix PCIe DT properties on rk3399
- soc: ti: omap-prm: Fix boot time errors for rst_map_012 bits 0 and 1
- tmpfs: disallow CONFIG_TMPFS_INODE64 on alpha
- tmpfs: disallow CONFIG_TMPFS_INODE64 on s390
- dmaengine: move channel device_node deletion to driver
- drm/dp_mst: Don't report ports connected if nothing is attached to them
- drm/i915/tgl+: Make sure TypeC FIA is powered up when initializing it
- Revert "drm/amd/display: Update NV1x SR latency values"
- cgroup: fix psi monitor for root cgroup
- arm/xen: Don't probe xenbus as part of an early initcall
- drm/i915: Fix overlay frontbuffer tracking
- tracing: Check length before giving out the filter buffer
- tracing: Do not count ftrace events in top level enable output
- gpio: ep93xx: Fix single irqchip with multi gpiochips
- gpio: ep93xx: fix BUG_ON port F usage
- gpio: mxs: GPIO_MXS should not default to y unconditionally
- Revert "dts: phy: add GPIO number and active state used for phy reset"
- objtool: Fix seg fault with Clang non-section symbols
- squashfs: add more sanity checks in xattr id lookup
- squashfs: add more sanity checks in inode lookup
- squashfs: add more sanity checks in id lookup
- squashfs: avoid out of bounds writes in decompressors
- Revert "mm: memcontrol: avoid workload stalls when lowering memory.high"
- nilfs2: make splice write available again
- drm/i915: Skip vswing programming for TBT
- drm/i915: Fix ICL MG PHY vswing handling
- bpf: Fix verifier jsgt branch analysis on max bound
- bpf: Fix 32 bit src register truncation on div/mod
- bpf: Fix verifier jmp32 pruning decision logic
- regulator: Fix lockdep warning resolving supplies
- blk-cgroup: Use cond_resched() when destroy blkgs
- i2c: mediatek: Move suspend and resume handling to NOIRQ phase
- SUNRPC: Handle 0 length opaque XDR object data properly
- SUNRPC: Move simple_get_bytes and simple_get_netobj into private header
- iwlwifi: queue: bail out on invalid freeing
- iwlwifi: mvm: guard against device removal in reprobe
- iwlwifi: pcie: add rules to match Qu with Hr2
- iwlwifi: mvm: invalidate IDs of internal stations at mvm start
- iwlwifi: pcie: fix context info memory leak
- iwlwifi: pcie: add a NULL check in iwl_pcie_txq_unmap
- iwlwifi: mvm: take mutex for calling iwl_mvm_get_sync_time()
- iwlwifi: mvm: skip power command when unbinding vif during CSA
- ASoC: Intel: sof_sdw: set proper flags for Dell TGL-H SKU 0A5E
- ASoC: ak4458: correct reset polarity
- ALSA: hda: intel-dsp-config: add PCI id for TGL-H
- pNFS/NFSv4: Improve rejection of out-of-order layouts
- pNFS/NFSv4: Try to return invalid layout in pnfs_layout_process()
- chtls: Fix potential resource leak
- ASoC: Intel: Skylake: Zero snd_ctl_elem_value
- mac80211: 160MHz with extended NSS BW in CSA
- drm/nouveau/nvif: fix method count when pushing an array
- ASoC: wm_adsp: Fix control name parsing for multi-fw
- regulator: core: avoid regulator_resolve_supply() race condition
- af_key: relax availability checks for skb size calculation
- powerpc/64/signal: Fix regression in __kernel_sigtramp_rt64() semantics
- gpiolib: cdev: clear debounce period if line set to output
- io_uring: drop mm/files between task_work_submit
- io_uring: reinforce cancel on flush during exit
- io_uring: fix sqo ownership false positive warning
- io_uring: fix list corruption for splice file_get
- io_uring: fix flush cqring overflow list while TASK_INTERRUPTIBLE
- io_uring: fix cancellation taking mutex while TASK_UNINTERRUPTIBLE
- io_uring: replace inflight_wait with tctx->wait
- io_uring: fix __io_uring_files_cancel() with TASK_UNINTERRUPTIBLE
- io_uring: if we see flush on exit, cancel related tasks
- io_uring: account io_uring internal files as REQ_F_INFLIGHT
- io_uring: fix files cancellation
- io_uring: always batch cancel in *cancel_files()
- io_uring: pass files into kill timeouts/poll
- io_uring: don't iterate io_uring_cancel_files()
- io_uring: add a {task,files} pair matching helper
- io_uring: simplify io_task_match()
- net: sched: replaced invalid qdisc tree flush helper in qdisc_replace
- net: dsa: mv88e6xxx: override existent unicast portvec in port_fdb_add
- udp: ipv4: manipulate network header of NATed UDP GRO fraglist
- net: ip_tunnel: fix mtu calculation
- neighbour: Prevent a dead entry from updating gc_list
- igc: Report speed and duplex as unknown when device is runtime suspended
- md: Set prev_flush_start and flush_bio in an atomic way
- Input: ili210x - implement pressure reporting for ILI251x
- Input: xpad - sync supported devices with fork on GitHub
- Input: goodix - add support for Goodix GT9286 chip
- x86/apic: Add extra serialization for non-serializing MSRs
- x86/debug: Prevent data breakpoints on cpu_dr7
- x86/debug: Prevent data breakpoints on __per_cpu_offset
- x86/debug: Fix DR6 handling
- x86/build: Disable CET instrumentation in the kernel
- mm/filemap: add missing mem_cgroup_uncharge() to __add_to_page_cache_locked()
- mm: thp: fix MADV_REMOVE deadlock on shmem THP
- mm/vmalloc: separate put pages and flush VM flags
- mm, compaction: move high_pfn to the for loop scope
- mm: hugetlb: remove VM_BUG_ON_PAGE from page_huge_active
- mm: hugetlb: fix a race between isolating and freeing page
- mm: hugetlb: fix a race between freeing and dissolving the page
- mm: hugetlbfs: fix cannot migrate the fallocated HugeTLB page
- ARM: 9043/1: tegra: Fix misplaced tegra_uart_config in decompressor
- ARM: footbridge: fix dc21285 PCI configuration accessors
- ARM: dts; gta04: SPI panel chip select is active low
- DTS: ARM: gta04: remove legacy spi-cs-high to make display work again
- KVM: x86: Set so called 'reserved CR3 bits in LM mask' at vCPU reset
- KVM: x86: Update emulator context mode if SYSENTER xfers to 64-bit mode
- KVM: x86: fix CPUID entries returned by KVM_GET_CPUID2 ioctl
- KVM: x86: Allow guests to see MSR_IA32_TSX_CTRL even if tsx=off
- KVM: x86/mmu: Fix TDP MMU zap collapsible SPTEs
- KVM: SVM: Treat SVM as unsupported when running as an SEV guest
- nvme-pci: avoid the deepest sleep state on Kingston A2000 SSDs
- io_uring: don't modify identity's files uncess identity is cowed
- drm/amd/display: Revert "Fix EDID parsing after resume from suspend"
- drm/i915: Power up combo PHY lanes for for HDMI as well
- drm/i915: Extract intel_ddi_power_up_lanes()
- drm/i915/display: Prevent double YUV range correction on HDR planes
- drm/i915/gt: Close race between enable_breadcrumbs and cancel_breadcrumbs
- drm/i915/gem: Drop lru bumping on display unpinning
- drm/i915: Fix the MST PBN divider calculation
- drm/dp/mst: Export drm_dp_get_vc_payload_bw()
- Fix unsynchronized access to sev members through svm_register_enc_region
- mmc: core: Limit retries when analyse of SDIO tuples fails
- mmc: sdhci-pltfm: Fix linking err for sdhci-brcmstb
- smb3: fix crediting for compounding when only one request in flight
- smb3: Fix out-of-bounds bug in SMB2_negotiate()
- iommu: Check dev->iommu in dev_iommu_priv_get() before dereferencing it
- cifs: report error instead of invalid when revalidating a dentry fails
- RISC-V: Define MAXPHYSMEM_1GB only for RV32
- xhci: fix bounce buffer usage for non-sg list case
- scripts: use pkg-config to locate libcrypto
- genirq/msi: Activate Multi-MSI early when MSI_FLAG_ACTIVATE_EARLY is set
- genirq: Prevent [devm_]irq_alloc_desc from returning irq 0
- libnvdimm/dimm: Avoid race between probe and available_slots_show()
- libnvdimm/namespace: Fix visibility of namespace resource attribute
- tracepoint: Fix race between tracing and removing tracepoint
- tracing: Use pause-on-trace with the latency tracers
- kretprobe: Avoid re-registration of the same kretprobe earlier
- tracing/kprobe: Fix to support kretprobe events on unloaded modules
- fgraph: Initialize tracing_graph_pause at task creation
- gpiolib: free device name on error path to fix kmemleak
- mac80211: fix station rate table updates on assoc
- ovl: implement volatile-specific fsync error behaviour
- ovl: avoid deadlock on directory ioctl
- ovl: fix dentry leak in ovl_get_redirect
- thunderbolt: Fix possible NULL pointer dereference in tb_acpi_add_link()
- kbuild: fix duplicated flags in DEBUG_CFLAGS
- memblock: do not start bottom-up allocations with kernel_end
- vdpa/mlx5: Restore the hardware used index after change map
- nvmet-tcp: fix out-of-bounds access when receiving multiple h2cdata PDUs
- ARM: dts: sun7i: a20: bananapro: Fix ethernet phy-mode
- net: ipa: pass correct dma_handle to dma_free_coherent()
- r8169: fix WoL on shutdown if CONFIG_DEBUG_SHIRQ is set
- net: mvpp2: TCAM entry enable should be written after SRAM data
- net: lapb: Copy the skb before sending a packet
- net/mlx5e: Release skb in case of failure in tc update skb
- net/mlx5e: Update max_opened_tc also when channels are closed
- net/mlx5: Fix leak upon failure of rule creation
- net/mlx5: Fix function calculation for page trees
- ibmvnic: device remove has higher precedence over reset
- i40e: Revert "i40e: don't report link up for a VF who hasn't enabled queues"
- igc: check return value of ret_val in igc_config_fc_after_link_up
- igc: set the default return value to -IGC_ERR_NVM in igc_write_nvm_srwr
- SUNRPC: Fix NFS READs that start at non-page-aligned offsets
- arm64: dts: ls1046a: fix dcfg address range
- rxrpc: Fix deadlock around release of dst cached on udp tunnel
- r8169: work around RTL8125 UDP hw bug
- arm64: dts: meson: switch TFLASH_VDD_EN pin to open drain on Odroid-C4
- bpf, preload: Fix build when $(O) points to a relative path
- um: virtio: free vu_dev only with the contained struct device
- bpf, inode_storage: Put file handler if no storage was found
- bpf, cgroup: Fix problematic bounds check
- bpf, cgroup: Fix optlen WARN_ON_ONCE toctou
- vdpa/mlx5: Fix memory key MTT population
- ARM: dts: stm32: Fix GPIO hog flags on DHCOM DRC02
- ARM: dts: stm32: Disable optional TSC2004 on DRC02 board
- ARM: dts: stm32: Disable WP on DHCOM uSD slot
- ARM: dts: stm32: Connect card-detect signal on DHCOM
- ARM: dts: stm32: Fix polarity of the DH DRC02 uSD card detect
- arm64: dts: rockchip: Use only supported PCIe link speed on Pinebook Pro
- arm64: dts: rockchip: fix vopl iommu irq on px30
- arm64: dts: amlogic: meson-g12: Set FL-adj property value
- Input: i8042 - unbreak Pegatron C15B
- arm64: dts: qcom: c630: keep both touchpad devices enabled
- ARM: OMAP1: OSK: fix ohci-omap breakage
- usb: xhci-mtk: break loop when find the endpoint to drop
- usb: xhci-mtk: skip dropping bandwidth of unchecked endpoints
- usb: xhci-mtk: fix unreleased bandwidth data
- usb: dwc3: fix clock issue during resume in OTG mode
- usb: dwc2: Fix endpoint direction check in ep_from_windex
- usb: renesas_usbhs: Clear pipe running flag in usbhs_pkt_pop()
- USB: usblp: don't call usb_set_interface if there's a single alt
- usb: gadget: aspeed: add missing of_node_put
- USB: gadget: legacy: fix an error code in eth_bind()
- usb: host: xhci: mvebu: make USB 3.0 PHY optional for Armada 3720
- USB: serial: option: Adding support for Cinterion MV31
- USB: serial: cp210x: add new VID/PID for supporting Teraoka AD2000
- USB: serial: cp210x: add pid/vid for WSDA-200-USB

* Fri Feb 19 2021 Xie XiuQi <xiexiuqi@huawei.com> - 5.10.0-4.0.0.13
- net/hinic: Add NIC Layer
- net/hinic: Update Hardware Abstract Layer
- workqueue: Restrict affinity change to rescuer
- kthread: Extract KTHREAD_IS_PER_CPU
- x86/cpu: Add another Alder Lake CPU to the Intel family
- objtool: Don't fail the kernel build on fatal errors
- habanalabs: disable FW events on device removal
- habanalabs: fix backward compatibility of idle check
- habanalabs: zero pci counters packet before submit to FW
- drm/amd/display: Fixed corruptions on HPDRX link loss restore
- drm/amd/display: Use hardware sequencer functions for PG control
- drm/amd/display: Change function decide_dp_link_settings to avoid infinite looping
- drm/amd/display: Allow PSTATE chnage when no displays are enabled
- drm/amd/display: Update dram_clock_change_latency for DCN2.1
- selftests/powerpc: Only test lwm/stmw on big endian
- platform/x86: thinkpad_acpi: Add P53/73 firmware to fan_quirk_table for dual fan control
- nvmet: set right status on error in id-ns handler
- nvme-pci: allow use of cmb on v1.4 controllers
- nvme-tcp: avoid request double completion for concurrent nvme_tcp_timeout
- nvme-rdma: avoid request double completion for concurrent nvme_rdma_timeout
- nvme: check the PRINFO bit before deciding the host buffer length
- udf: fix the problem that the disc content is not displayed
- i2c: tegra: Create i2c_writesl_vi() to use with VI I2C for filling TX FIFO
- ALSA: hda: Add Cometlake-R PCI ID
- scsi: ibmvfc: Set default timeout to avoid crash during migration
- mac80211: fix encryption key selection for 802.3 xmit
- mac80211: fix fast-rx encryption check
- mac80211: fix incorrect strlen of .write in debugfs
- objtool: Don't add empty symbols to the rbtree
- ALSA: hda: Add AlderLake-P PCI ID and HDMI codec vid
- ASoC: SOF: Intel: hda: Resume codec to do jack detection
- scsi: fnic: Fix memleak in vnic_dev_init_devcmd2
- scsi: libfc: Avoid invoking response handler twice if ep is already completed
- scsi: scsi_transport_srp: Don't block target in failfast state
- x86: __always_inline __{rd,wr}msr()
- locking/lockdep: Avoid noinstr warning for DEBUG_LOCKDEP
- habanalabs: fix dma_addr passed to dma_mmap_coherent
- platform/x86: intel-vbtn: Support for tablet mode on Dell Inspiron 7352
- platform/x86: touchscreen_dmi: Add swap-x-y quirk for Goodix touchscreen on Estar Beauty HD tablet
- tools/power/x86/intel-speed-select: Set higher of cpuinfo_max_freq or base_frequency
- tools/power/x86/intel-speed-select: Set scaling_max_freq to base_frequency
- phy: cpcap-usb: Fix warning for missing regulator_disable
- iommu/vt-d: Do not use flush-queue when caching-mode is on
- ARM: 9025/1: Kconfig: CPU_BIG_ENDIAN depends on !LD_IS_LLD
- Revert "x86/setup: don't remove E820_TYPE_RAM for pfn 0"
- arm64: Do not pass tagged addresses to __is_lm_address()
- arm64: Fix kernel address detection of __is_lm_address()
- arm64: dts: meson: Describe G12b GPU as coherent
- drm/panfrost: Support cache-coherent integrations
- iommu/io-pgtable-arm: Support coherency for Mali LPAE
- ibmvnic: Ensure that CRQ entry read are correctly ordered
- net: switchdev: don't set port_obj_info->handled true when -EOPNOTSUPP
- net: dsa: bcm_sf2: put device node before return
- mlxsw: spectrum_span: Do not overwrite policer configuration
- stmmac: intel: Configure EHL PSE0 GbE and PSE1 GbE to 32 bits DMA addressing
- net: octeontx2: Make sure the buffer is 128 byte aligned
- net: fec: put child node on error path
- net: stmmac: dwmac-intel-plat: remove config data on error
- net: dsa: microchip: Adjust reset release timing to match reference reset circuit
- vsock: fix the race conditions in multi-transport support
- tcp: fix TLP timer not set when CA_STATE changes from DISORDER to OPEN
- tcp: make TCP_USER_TIMEOUT accurate for zero window probes
- team: protect features update by RCU to avoid deadlock
- scsi: qla2xxx: Fix description for parameter ql2xenforce_iocb_limit
- ASoC: topology: Fix memory corruption in soc_tplg_denum_create_values()
- ASoC: topology: Properly unregister DAI on removal
- ASoC: mediatek: mt8183-mt6358: ignore TDM DAI link by default
- ASoC: mediatek: mt8183-da7219: ignore TDM DAI link by default
- NFC: fix possible resource leak
- NFC: fix resource leak when target index is invalid
- rxrpc: Fix memory leak in rxrpc_lookup_local
- selftests: forwarding: Specify interface when invoking mausezahn
- nvme-multipath: Early exit if no path is available
- iommu/vt-d: Correctly check addr alignment in qi_flush_dev_iotlb_pasid()
- iommu/amd: Use IVHD EFR for early initialization of IOMMU features
- of/device: Update dma_range_map only when dev has valid dma-ranges
- ACPI/IORT: Do not blindly trust DMA masks from firmware
- can: dev: prevent potential information leak in can_fill_info()
- net/mlx5: CT: Fix incorrect removal of tuple_nat_node from nat rhashtable
- net/mlx5e: Revert parameters on errors when changing MTU and LRO state without reset
- net/mlx5e: Revert parameters on errors when changing trust state without reset
- net/mlx5e: Correctly handle changing the number of queues when the interface is down
- net/mlx5e: Fix CT rule + encap slow path offload and deletion
- net/mlx5e: Disable hw-tc-offload when MLX5_CLS_ACT config is disabled
- net/mlx5: Maintain separate page trees for ECPF and PF functions
- net/mlx5e: Reduce tc unsupported key print level
- net/mlx5e: free page before return
- net/mlx5e: E-switch, Fix rate calculation for overflow
- net/mlx5: Fix memory leak on flow table creation error flow
- igc: fix link speed advertising
- i40e: acquire VSI pointer only after VF is initialized
- ice: Fix MSI-X vector fallback logic
- ice: Don't allow more channels than LAN MSI-X available
- ice: update dev_addr in ice_set_mac_address even if HW filter exists
- ice: Implement flow for IPv6 next header (extension header)
- ice: fix FDir IPv6 flexbyte
- mac80211: pause TX while changing interface type
- iwlwifi: pcie: reschedule in long-running memory reads
- iwlwifi: pcie: use jiffies for memory read spin time limit
- iwlwifi: pcie: set LTR on more devices
- iwlwifi: pnvm: don't try to load after failures
- iwlwifi: pnvm: don't skip everything when not reloading
- iwlwifi: pcie: avoid potential PNVM leaks
- ASoC: qcom: lpass: Fix out-of-bounds DAI ID lookup
- ASoC: SOF: Intel: soundwire: fix select/depend unmet dependencies
- pNFS/NFSv4: Update the layout barrier when we schedule a layoutreturn
- pNFS/NFSv4: Fix a layout segment leak in pnfs_layout_process()
- powerpc/64s: prevent recursive replay_soft_interrupts causing superfluous interrupt
- ASoC: Intel: Skylake: skl-topology: Fix OOPs ib skl_tplg_complete
- spi: altera: Fix memory leak on error path
- ASoC: qcom: lpass-ipq806x: fix bitwidth regmap field
- ASoC: qcom: Fix broken support to MI2S TERTIARY and QUATERNARY
- ASoC: qcom: Fix incorrect volatile registers
- ASoC: dt-bindings: lpass: Fix and common up lpass dai ids
- RDMA/cxgb4: Fix the reported max_recv_sge value
- firmware: imx: select SOC_BUS to fix firmware build
- arm64: dts: imx8mp: Correct the gpio ranges of gpio3
- ARM: dts: imx6qdl-sr-som: fix some cubox-i platforms
- ARM: dts: imx6qdl-kontron-samx6i: fix i2c_lcd/cam default status
- ARM: imx: fix imx8m dependencies
- arm64: dts: ls1028a: fix the offset of the reset register
- xfrm: Fix wraparound in xfrm_policy_addr_delta()
- selftests: xfrm: fix test return value override issue in xfrm_policy.sh
- xfrm: fix disable_xfrm sysctl when used on xfrm interfaces
- xfrm: Fix oops in xfrm_replay_advance_bmp
- Revert "block: simplify set_init_blocksize" to regain lost performance
- Revert "RDMA/mlx5: Fix devlink deadlock on net namespace deletion"
- netfilter: nft_dynset: add timeout extension to template
- ARM: zImage: atags_to_fdt: Fix node names on added root nodes
- ARM: imx: build suspend-imx6.S with arm instruction set
- clk: qcom: gcc-sm250: Use floor ops for sdcc clks
- clk: mmp2: fix build without CONFIG_PM
- clk: imx: fix Kconfig warning for i.MX SCU clk
- blk-mq: test QUEUE_FLAG_HCTX_ACTIVE for sbitmap_shared in hctx_may_queue
- xen-blkfront: allow discard-* nodes to be optional
- tee: optee: replace might_sleep with cond_resched
- KVM: Documentation: Fix spec for KVM_CAP_ENABLE_CAP_VM
- uapi: fix big endian definition of ipv6_rpl_sr_hdr
- drm/i915/selftest: Fix potential memory leak
- drm/i915: Check for all subplatform bits
- drm/nouveau/dispnv50: Restore pushing of all data.
- drm/vc4: Correct POS1_SCL for hvs5
- drm/vc4: Correct lbm size and calculation
- drm/nouveau/svm: fail NOUVEAU_SVM_INIT ioctl on unsupported devices
- ARM: dts: imx6qdl-kontron-samx6i: fix pwms for lcd-backlight
- net/mlx5e: Fix IPSEC stats
- drm/i915/pmu: Don't grab wakeref when enabling events
- drm/i915/gt: Clear CACHE_MODE prior to clearing residuals
- iwlwifi: Fix IWL_SUBDEVICE_NO_160 macro to use the correct bit.
- mt7601u: fix rx buffer refcounting
- mt76: mt7663s: fix rx buffer refcounting
- mt7601u: fix kernel crash unplugging the device
- arm64: dts: broadcom: Fix USB DMA address translation for Stingray
- leds: trigger: fix potential deadlock with libata
- xen: Fix XenStore initialisation for XS_LOCAL
- io_uring: fix wqe->lock/completion_lock deadlock
- KVM: Forbid the use of tagged userspace addresses for memslots
- KVM: x86: get smi pending status correctly
- KVM: nVMX: Sync unsync'd vmcs02 state to vmcs12 on migration
- KVM: x86: allow KVM_REQ_GET_NESTED_STATE_PAGES outside guest mode for VMX
- KVM: nSVM: cancel KVM_REQ_GET_NESTED_STATE_PAGES on nested vmexit
- KVM: arm64: Filter out v8.1+ events on v8.0 HW
- KVM: x86/pmu: Fix UBSAN shift-out-of-bounds warning in intel_pmu_refresh()
- KVM: x86/pmu: Fix HW_REF_CPU_CYCLES event pseudo-encoding in intel_arch_events[]
- btrfs: fix possible free space tree corruption with online conversion
- btrfs: fix lockdep warning due to seqcount_mutex on 32bit arch
- drivers: soc: atmel: add null entry at the end of at91_soc_allowed_list[]
- drivers: soc: atmel: Avoid calling at91_soc_init on non AT91 SoCs
- crypto: marvel/cesa - Fix tdma descriptor on 64-bit
- efi/apple-properties: Reinstate support for boolean properties
- x86/entry: Emit a symbol for register restoring thunk
- PM: hibernate: flush swap writer after marking
- s390/vfio-ap: No need to disable IRQ after queue reset
- s390: uv: Fix sysfs max number of VCPUs reporting
- net: usb: qmi_wwan: added support for Thales Cinterion PLSx3 modem family
- bcache: only check feature sets when sb->version >= BCACHE_SB_VERSION_CDEV_WITH_FEATURES
- drivers/nouveau/kms/nv50-: Reject format modifiers for cursor planes
- drm/i915/gt: Always try to reserve GGTT address 0x0
- drm/i915: Always flush the active worker before returning from the wait
- drm/nouveau/kms/gk104-gp1xx: Fix > 64x64 cursors
- Revert "drm/amdgpu/swsmu: drop set_fan_speed_percent (v2)"
- ASoC: AMD Renoir - refine DMI entries for some Lenovo products
- x86/xen: avoid warning in Xen pv guest with CONFIG_AMD_MEM_ENCRYPT enabled
- wext: fix NULL-ptr-dereference with cfg80211's lack of commit()
- ARM: dts: imx6qdl-gw52xx: fix duplicate regulator naming
- ARM: dts: ux500: Reserve memory carveouts
- ARM: dts: tbs2910: rename MMC node aliases
- media: rc: ensure that uevent can be read directly after rc device register
- media: rc: ite-cir: fix min_timeout calculation
- media: rc: fix timeout handling after switch to microsecond durations
- media: hantro: Fix reset_raw_fmt initialization
- media: cedrus: Fix H264 decoding
- media: cec: add stm32 driver
- parisc: Enable -mlong-calls gcc option by default when !CONFIG_MODULES
- ALSA: hda/via: Apply the workaround generically for Clevo machines
- ALSA: hda/realtek: Enable headset of ASUS B1400CEPE with ALC256
- kernel: kexec: remove the lock operation of system_transition_mutex
- ACPI: thermal: Do not call acpi_thermal_check() directly
- ACPI: sysfs: Prefer "compatible" modalias
- tty: avoid using vfs_iocb_iter_write() for redirected console writes
- nbd: freeze the queue while we're adding connections
- iwlwifi: provide gso_type to GSO packets

* Mon Feb 08 2021 Xie XiuQi <xiexiuqi@huawei.com> - 5.10.0-3.0.0.12
- kdump: update Documentation about crashkernel
- arm64: kdump: add memory for devices by DT property linux,usable-memory-range
- x86, arm64: Add ARCH_WANT_RESERVE_CRASH_KERNEL config
- arm64: kdump: reimplement crashkernel=X
- arm64: kdump: introduce some macroes for crash kernel reservation
- x86/elf: Move vmcore_elf_check_arch_cross to arch/x86/include/asm/elf.h
- x86: kdump: move reserve_crashkernel[_low]() into crash_core.c
- x86: kdump: move xen_pv_domain() check and insert_resource() to setup_arch()
- x86: kdump: use macro CRASH_ADDR_LOW_MAX in functions reserve_crashkernel()
- x86: kdump: make the lower bound of crash kernel reservation consistent
- x86: kdump: replace the hard-coded alignment with macro CRASH_ALIGN
- ARM: kdump: Add LPAE support
- ARM: kdump: fix timer interrupts panic, could not boot capture_kernel
- driver: input: fix UBSAN warning in input_defuzz_abs_event
- vdso: do cntvct workaround in the VDSO
- arm64: arch_timer: Disable CNTVCT_EL0 trap if workaround is enabled
- cgroup: Return ERSCH when add Z process into task
- ARM: 9027/1: head.S: explicitly map DT even if it lives in the first physical section
- ARM: 9028/1: disable KASAN in call stack capturing routines
- ARM: 9022/1: Change arch/arm/lib/mem*.S to use WEAK instead of .weak
- ARM: 9020/1: mm: use correct section size macro to describe the FDT virtual address
- ARM: 9017/2: Enable KASan for ARM
- ARM: 9016/2: Initialize the mapping of KASan shadow memory
- ARM: 9015/2: Define the virtual space of KASan's shadow region
- ARM: 9014/2: Replace string mem* functions for KASan
- ARM: 9013/2: Disable KASan instrumentation for some code
- ARM: 9012/1: move device tree mapping out of linear region
- ARM: 9011/1: centralize phys-to-virt conversion of DT/ATAGS address
- drm/radeon: check the alloc_workqueue return value
- printk: fix string termination for record_print_text()
- printk: fix buffer overflow potential for print_text()
- tools: Factor HOSTCC, HOSTLD, HOSTAR definitions
- mm: fix a race on nr_swap_pages
- mm/page_alloc: add a missing mm_page_alloc_zone_locked() tracepoint
- objtool: Don't fail on missing symbol table
- io_uring: fix sleeping under spin in __io_clean_op
- io_uring: dont kill fasync under completion_lock
- io_uring: fix skipping disabling sqo on exec
- io_uring: fix uring_flush in exit_files() warning
- io_uring: fix false positive sqo warning on flush
- io_uring: do sqo disable on install_fd error
- io_uring: fix null-deref in io_disable_sqo_submit
- io_uring: stop SQPOLL submit on creator's death
- io_uring: add warn_once for io_uring_flush()
- io_uring: inline io_uring_attempt_task_drop()
- kernel/io_uring: cancel io_uring before task works
- iwlwifi: dbg: Don't touch the tlv data
- RDMA/vmw_pvrdma: Fix network_hdr_type reported in WC
- media: v4l2-subdev.h: BIT() is not available in userspace
- media: Revert "media: videobuf2: Fix length check for single plane dmabuf queueing"
- HID: multitouch: Apply MT_QUIRK_CONFIDENCE quirk for multi-input devices
- HID: wacom: Correct NULL dereference on AES pen proximity
- futex: Handle faults correctly for PI futexes
- futex: Simplify fixup_pi_state_owner()
- futex: Use pi_state_update_owner() in put_pi_state()
- rtmutex: Remove unused argument from rt_mutex_proxy_unlock()
- futex: Provide and use pi_state_update_owner()
- futex: Replace pointless printk in fixup_owner()
- futex: Ensure the correct return value from futex_lock_pi()
- Revert "mm/slub: fix a memory leak in sysfs_slab_add()"
- gpio: mvebu: fix pwm .get_state period calculation
- PCI/AER: increments pci bus reference count in aer-inject process
- PCI: add a member in 'struct pci_bus' to record the original 'pci_ops'
- sched, rt: fix isolated CPUs leaving task_group indefinitely throttled
- cgroup: wait for cgroup destruction to complete when umount
- cgroup: check if cgroup root is alive in cgroupstats_show()
- mtd:avoid blktrans_open/release race and avoid insmod ftl.ko deadlock
- jffs2: move jffs2_init_inode_info() just after allocating inode
- jffs2: protect no-raw-node-ref check of inocache by erase_completion_lock
- jffs2: handle INO_STATE_CLEARING in jffs2_do_read_inode()
- jffs2: reset pino_nlink to 0 when inode creation failed
- jffs2: GC deadlock reading a page that is used in jffs2_write_begin()
- jffs2: make the overwritten xattr invisible after remount
- Revert "mm: fix initialization of struct page for holes in memory layout"
- mm: fix initialization of struct page for holes in memory layout
- Commit 9bb48c82aced ("tty: implement write_iter") converted the tty layer to use write_iter.
- fs/pipe: allow sendfile() to pipe again
- interconnect: imx8mq: Use icc_sync_state
- kernfs: wire up ->splice_read and ->splice_write
- kernfs: implement ->write_iter
- kernfs: implement ->read_iter
- bpf: Local storage helpers should check nullness of owner ptr passed
- drm/i915/hdcp: Get conn while content_type changed
- ASoC: SOF: Intel: hda: Avoid checking jack on system suspend
- tcp: Fix potential use-after-free due to double kfree()
- x86/sev-es: Handle string port IO to kernel memory properly
- net: systemport: free dev before on error path
- tty: fix up hung_up_tty_write() conversion
- tty: implement write_iter
- x86/sev: Fix nonistr violation
- pinctrl: qcom: Don't clear pending interrupts when enabling
- pinctrl: qcom: Properly clear "intr_ack_high" interrupts when unmasking
- pinctrl: qcom: No need to read-modify-write the interrupt status
- pinctrl: qcom: Allow SoCs to specify a GPIO function that's not 0
- net: core: devlink: use right genl user_ptr when handling port param get/set
- net: mscc: ocelot: Fix multicast to the CPU port
- tcp: fix TCP_USER_TIMEOUT with zero window
- tcp: do not mess with cloned skbs in tcp_add_backlog()
- net: dsa: b53: fix an off by one in checking "vlan->vid"
- net: Disable NETIF_F_HW_TLS_RX when RXCSUM is disabled
- net: mscc: ocelot: allow offloading of bridge on top of LAG
- ipv6: set multicast flag on the multicast route
- net_sched: reject silly cell_log in qdisc_get_rtab()
- net_sched: avoid shift-out-of-bounds in tcindex_set_parms()
- ipv6: create multicast route with RTPROT_KERNEL
- udp: mask TOS bits in udp_v4_early_demux()
- net_sched: gen_estimator: support large ewma log
- tcp: fix TCP socket rehash stats mis-accounting
- kasan: fix incorrect arguments passing in kasan_add_zero_shadow
- kasan: fix unaligned address is unhandled in kasan_remove_zero_shadow
- skbuff: back tiny skbs with kmalloc() in __netdev_alloc_skb() too
- lightnvm: fix memory leak when submit fails
- cachefiles: Drop superfluous readpages aops NULL check
- nvme-pci: fix error unwind in nvme_map_data
- nvme-pci: refactor nvme_unmap_data
- sh_eth: Fix power down vs. is_opened flag ordering
- selftests/powerpc: Fix exit status of pkey tests
- net: dsa: mv88e6xxx: also read STU state in mv88e6250_g1_vtu_getnext
- octeontx2-af: Fix missing check bugs in rvu_cgx.c
- ASoC: SOF: Intel: fix page fault at probe if i915 init fails
- locking/lockdep: Cure noinstr fail
- sh: Remove unused HAVE_COPY_THREAD_TLS macro
- sh: dma: fix kconfig dependency for G2_DMA
- drm/i915/hdcp: Update CP property in update_pipe
- tools: gpio: fix %llu warning in gpio-watch.c
- tools: gpio: fix %llu warning in gpio-event-mon.c
- netfilter: rpfilter: mask ecn bits before fib lookup
- cls_flower: call nla_ok() before nla_next()
- x86/cpu/amd: Set __max_die_per_package on AMD
- x86/entry: Fix noinstr fail
- drm/i915: Only enable DFP 4:4:4->4:2:0 conversion when outputting YCbCr 4:4:4
- drm/i915: s/intel_dp_sink_dpms/intel_dp_set_power/
- driver core: Extend device_is_dependent()
- driver core: Fix device link device name collision
- drivers core: Free dma_range_map when driver probe failed
- xhci: tegra: Delay for disabling LFPS detector
- xhci: make sure TRB is fully written before giving it to the controller
- usb: cdns3: imx: fix can't create core device the second time issue
- usb: cdns3: imx: fix writing read-only memory issue
- usb: bdc: Make bdc pci driver depend on BROKEN
- usb: udc: core: Use lock when write to soft_connect
- USB: gadget: dummy-hcd: Fix errors in port-reset handling
- usb: gadget: aspeed: fix stop dma register setting.
- USB: ehci: fix an interrupt calltrace error
- ehci: fix EHCI host controller initialization sequence
- serial: mvebu-uart: fix tx lost characters at power off
- stm class: Fix module init return on allocation failure
- intel_th: pci: Add Alder Lake-P support
- io_uring: fix short read retries for non-reg files
- io_uring: fix SQPOLL IORING_OP_CLOSE cancelation state
- io_uring: iopoll requests should also wake task ->in_idle state
- mm: fix numa stats for thp migration
- mm: memcg: fix memcg file_dirty numa stat
- mm: memcg/slab: optimize objcg stock draining
- proc_sysctl: fix oops caused by incorrect command parameters
- x86/setup: don't remove E820_TYPE_RAM for pfn 0
- x86/mmx: Use KFPU_387 for MMX string operations
- x86/topology: Make __max_die_per_package available unconditionally
- x86/fpu: Add kernel_fpu_begin_mask() to selectively initialize state
- irqchip/mips-cpu: Set IPI domain parent chip
- cifs: do not fail __smb_send_rqst if non-fatal signals are pending
- powerpc/64s: fix scv entry fallback flush vs interrupt
- counter:ti-eqep: remove floor
- iio: adc: ti_am335x_adc: remove omitted iio_kfifo_free()
- drivers: iio: temperature: Add delay after the addressed reset command in mlx90632.c
- iio: ad5504: Fix setting power-down state
- iio: common: st_sensors: fix possible infinite loop in st_sensors_irq_thread
- i2c: sprd: depend on COMMON_CLK to fix compile tests
- perf evlist: Fix id index for heterogeneous systems
- can: peak_usb: fix use after free bugs
- can: vxcan: vxcan_xmit: fix use after free bug
- can: dev: can_restart: fix use after free bug
- selftests: net: fib_tests: remove duplicate log test
- xsk: Clear pool even for inactive queues
- ALSA: hda: Balance runtime/system PM if direct-complete is disabled
- gpio: sifive: select IRQ_DOMAIN_HIERARCHY rather than depend on it
- platform/x86: hp-wmi: Don't log a warning on HPWMI_RET_UNKNOWN_COMMAND errors
- platform/x86: intel-vbtn: Drop HP Stream x360 Convertible PC 11 from allow-list
- drm/vc4: Unify PCM card's driver_name
- i2c: octeon: check correct size of maximum RECV_LEN packet
- iov_iter: fix the uaccess area in copy_compat_iovec_from_user
- printk: fix kmsg_dump_get_buffer length calulations
- printk: ringbuffer: fix line counting
- RDMA/cma: Fix error flow in default_roce_mode_store
- RDMA/umem: Avoid undefined behavior of rounddown_pow_of_two()
- drm/amdkfd: Fix out-of-bounds read in kdf_create_vcrat_image_cpu()
- bpf: Reject too big ctx_size_in for raw_tp test run
- arm64: entry: remove redundant IRQ flag tracing
- powerpc: Fix alignment bug within the init sections
- powerpc: Use the common INIT_DATA_SECTION macro in vmlinux.lds.S
- bpf: Prevent double bpf_prog_put call from bpf_tracing_prog_attach
- crypto: omap-sham - Fix link error without crypto-engine
- scsi: ufs: Fix tm request when non-fatal error happens
- scsi: ufs: ufshcd-pltfrm depends on HAS_IOMEM
- scsi: megaraid_sas: Fix MEGASAS_IOC_FIRMWARE regression
- btrfs: print the actual offset in btrfs_root_name
- RDMA/ucma: Do not miss ctx destruction steps in some cases
- pinctrl: mediatek: Fix fallback call path
- pinctrl: aspeed: g6: Fix PWMG0 pinctrl setting
- gpiolib: cdev: fix frame size warning in gpio_ioctl()
- nfsd: Don't set eof on a truncated READ_PLUS
- nfsd: Fixes for nfsd4_encode_read_plus_data()
- x86/xen: fix 'nopvspin' build error
- RISC-V: Fix maximum allowed phsyical memory for RV32
- RISC-V: Set current memblock limit
- libperf tests: Fail when failing to get a tracepoint id
- libperf tests: If a test fails return non-zero
- io_uring: flush timeouts that should already have expired
- drm/nouveau/kms/nv50-: fix case where notifier buffer is at offset 0
- drm/nouveau/mmu: fix vram heap sizing
- drm/nouveau/i2c/gm200: increase width of aux semaphore owner fields
- drm/nouveau/privring: ack interrupts the same way as RM
- drm/nouveau/bios: fix issue shadowing expansion ROMs
- drm/amd/display: Fix to be able to stop crc calculation
- HID: logitech-hidpp: Add product ID for MX Ergo in Bluetooth mode
- drm/amd/display: disable dcn10 pipe split by default
- drm/amdgpu/psp: fix psp gfx ctrl cmds
- riscv: defconfig: enable gpio support for HiFive Unleashed
- dts: phy: add GPIO number and active state used for phy reset
- dts: phy: fix missing mdio device and probe failure of vsc8541-01 device
- x86/xen: Fix xen_hvm_smp_init() when vector callback not available
- x86/xen: Add xen_no_vector_callback option to test PCI INTX delivery
- xen: Fix event channel callback via INTX/GSI
- arm64: make atomic helpers __always_inline
- riscv: cacheinfo: Fix using smp_processor_id() in preemptible
- ALSA: hda/tegra: fix tegra-hda on tegra30 soc
- clk: tegra30: Add hda clock default rates to clock driver
- HID: Ignore battery for Elan touchscreen on ASUS UX550
- HID: logitech-dj: add the G602 receiver
- riscv: Enable interrupts during syscalls with M-Mode
- riscv: Fix sifive serial driver
- riscv: Fix kernel time_init()
- scsi: sd: Suppress spurious errors when WRITE SAME is being disabled
- scsi: scsi_debug: Fix memleak in scsi_debug_init()
- scsi: qedi: Correct max length of CHAP secret
- scsi: ufs: Correct the LUN used in eh_device_reset_handler() callback
- scsi: ufs: Relax the condition of UFSHCI_QUIRK_SKIP_MANUAL_WB_FLUSH_CTRL
- x86/hyperv: Fix kexec panic/hang issues
- dm integrity: select CRYPTO_SKCIPHER
- HID: sony: select CONFIG_CRC32
- HID: multitouch: Enable multi-input for Synaptics pointstick/touchpad device
- SUNRPC: Handle TCP socket sends with kernel_sendpage() again
- ASoC: rt711: mutex between calibration and power state changes
- ASoC: Intel: haswell: Add missing pm_ops
- drm/i915: Check for rq->hwsp validity after acquiring RCU lock
- drm/i915/gt: Prevent use of engine->wa_ctx after error
- drm/amd/display: DCN2X Find Secondary Pipe properly in MPO + ODM Case
- drm/amdgpu: remove gpu info firmware of green sardine
- drm/syncobj: Fix use-after-free
- drm/atomic: put state on error path
- dm integrity: conditionally disable "recalculate" feature
- dm integrity: fix a crash if "recalculate" used without "internal_hash"
- dm: avoid filesystem lookup in dm_get_dev_t()
- mmc: sdhci-brcmstb: Fix mmc timeout errors on S5 suspend
- mmc: sdhci-xenon: fix 1.8v regulator stabilization
- mmc: sdhci-of-dwcmshc: fix rpmb access
- mmc: core: don't initialize block size from ext_csd if not present
- pinctrl: ingenic: Fix JZ4760 support
- fs: fix lazytime expiration handling in __writeback_single_inode()
- btrfs: send: fix invalid clone operations when cloning from the same file and root
- btrfs: don't clear ret in btrfs_start_dirty_block_groups
- btrfs: fix lockdep splat in btrfs_recover_relocation
- btrfs: do not double free backref nodes on error
- btrfs: don't get an EINTR during drop_snapshot for reloc
- ACPI: scan: Make acpi_bus_get_device() clear return pointer on error
- dm crypt: fix copy and paste bug in crypt_alloc_req_aead
- crypto: xor - Fix divide error in do_xor_speed()
- ALSA: hda/via: Add minimum mute flag
- ALSA: hda/realtek - Limit int mic boost on Acer Aspire E5-575T
- ALSA: seq: oss: Fix missing error check in snd_seq_oss_synth_make_info()
- platform/x86: ideapad-laptop: Disable touchpad_switch for ELAN0634
- platform/x86: i2c-multi-instantiate: Don't create platform device for INT3515 ACPI nodes
- i2c: bpmp-tegra: Ignore unknown I2C_M flags
- i2c: tegra: Wait for config load atomically while in ISR
- mtd: rawnand: nandsim: Fix the logic when selecting Hamming soft ECC engine
- mtd: rawnand: gpmi: fix dst bit offset when extracting raw payload
- scsi: target: tcmu: Fix use-after-free of se_cmd->priv
- mtd: phram: use div_u64_rem to stop overwrite len in phram_setup
- mtd: phram: Allow the user to set the erase page size.

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
