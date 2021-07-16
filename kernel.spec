

%define with_signmodules  1

%define with_kabichk 1

%define modsign_cmd %{SOURCE10}

%global Arch $(echo %{_host_cpu} | sed -e s/i.86/x86/ -e s/x86_64/x86/ -e s/aarch64.*/arm64/)

%global TarballVer 4.19.194

%global KernelVer %{version}-%{release}.%{_target_cpu}

%global hulkrelease 2106.1.0

%define with_patch 0

%define debuginfodir /usr/lib/debug

%define with_debuginfo 1

%define with_perf 1
# Do not recompute the build-id of vmlinux in find-debuginfo.sh
%global _missing_build_ids_terminate_build 1
%global _no_recompute_build_ids 1
%undefine _include_minidebuginfo
%undefine _include_gdb_index
%undefine _unique_build_ids

%define with_source 1

Name:	 kernel
Version: 4.19.194
Release: %{hulkrelease}.0086
Summary: Linux Kernel
License: GPLv2
URL:	 http://www.kernel.org/
%if 0%{?with_patch}
Source0: linux-%{TarballVer}.tar.gz
%else
Source0: linux-%{version}.tar.gz#/kernel.tar.gz
%endif
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

%if 0%{?with_patch}
Source9000: apply-patches
Source9001: guards
Source9002: series.conf
Source9998: patches.tar.bz2
%endif

#BuildRequires:
BuildRequires: module-init-tools, patch >= 2.5.4, bash >= 2.03, tar
BuildRequires: bzip2, xz, findutils, gzip, m4, perl, make >= 3.78, diffutils, gawk
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
BuildRequires: elfutils-devel zlib-devel binutils-devel newt-devel python-devel perl(ExtUtils::Embed) bison
BuildRequires: audit-libs-devel
BuildRequires: pciutils-devel gettext
BuildRequires: rpm-build, elfutils
BuildRequires: numactl-devel python3-devel glibc-static python3-docutils
BuildRequires: perl-generators perl(Carp) libunwind-devel gtk2-devel
%if 0%{?with_perf}
# libbabeltrace-devel >= 1.3.0
BuildRequires: libbabeltrace-devel java-1.8.0-openjdk-devel perl-devel
%endif
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

%description
The Linux Kernel, the operating system core itself.

%package devel
Summary: Development package for building kernel modules to match the %{KernelVer} kernel
AutoReqProv: no
Provides: %{name}-headers
Obsoletes: %{name}-headers
Provides: glibc-kernheaders
Provides: kernel-devel-uname-r = %{KernelVer}
Provides: kernel-devel-aarch64 = %{version}-%{release}
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

%if 0%{?with_perf}
%package -n perf
Summary: Performance monitoring for the Linux kernel
%description -n perf
This package contains the perf tool, which enables performance monitoring
of the Linux kernel.

%package -n python2-perf
Provides: python-perf = %{version}-%{release}
Obsoletes: python-perf
Summary: Python bindings for apps which will manipulate perf events

%description -n python2-perf
A Python module that permits applications written in the Python programming
language to use the interface to manipulate perf events.

%package -n python3-perf
Summary: Python bindings for apps which will manipulate perf events
%description -n python3-perf
A Python module that permits applications written in the Python programming
language to use the interface to manipulate perf events.
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

%if 0%{?with_perf}
%debuginfo_template -n perf
%files -n perf-debuginfo -f perf-debugfiles.list
%{expand:%%global _find_debuginfo_opts %{?_find_debuginfo_opts} -p '.*%{_bindir}/perf.*(\.debug)?|.*%{_libexecdir}/perf-core/.*|.*%{_libdir}/traceevent/.*|XXX' -o perf-debugfiles.list}


%debuginfo_template -n python2-perf
%files -n python2-perf-debuginfo -f python2-perf-debugfiles.list
%{expand:%%global _find_debuginfo_opts %{?_find_debuginfo_opts} -p '.*%{python2_sitearch}/perf.*(.debug)?|XXX' -o python2-perf-debugfiles.list}

%debuginfo_template -n python3-perf
%files -n python3-perf-debuginfo -f python3-perf-debugfiles.list
%{expand:%%global _find_debuginfo_opts %{?_find_debuginfo_opts} -p '.*%{python3_sitearch}/perf.*(.debug)?|XXX' -o python3-perf-debugfiles.list}
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
mv kernel linux-%{version}
cp -rl linux-%{version} linux-%{KernelVer}
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

%if 0%{?with_source}
# Copy directory backup for kernel-source
cp -a ../linux-%{KernelVer} ../linux-%{KernelVer}-Source
find ../linux-%{KernelVer}-Source -type f -name "\.*" -exec rm -rf {} \; >/dev/null
%endif

%if 0%{?with_perf}
cp -a tools/perf tools/python3-perf
%endif

%build
cd linux-%{KernelVer}

perl -p -i -e "s/^EXTRAVERSION.*/EXTRAVERSION = -%{release}.%{_target_cpu}/" Makefile

## make linux
make mrproper %{_smp_mflags}

make ARCH=%{Arch} openeuler_defconfig
make ARCH=%{Arch} olddefconfig

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
%if 0%{?with_perf}
# perf
%global perf_make \
    make EXTRA_CFLAGS="-Wl,-z,now -g -Wall -fstack-protector-strong -fPIC" EXTRA_PERFLIBS="-fpie -pie" %{?_smp_mflags} -s V=1 WERROR=0 NO_LIBUNWIND=1 HAVE_CPLUS_DEMANGLE=1 NO_GTK2=1 NO_LIBNUMA=1 NO_STRLCPY=1 prefix=%{_prefix}
%global perf_python2 -C tools/perf PYTHON=%{__python2}
%global perf_python3 -C tools/python3-perf PYTHON=%{__python3}
# perf
chmod +x tools/perf/check-headers.sh
%{perf_make} %{perf_python2} all

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
%define _python_bytecompile_errors_terminate_build 0
%if 0%{?with_source}
    mkdir -p $RPM_BUILD_ROOT/usr/src/
    mv linux-%{KernelVer}-Source $RPM_BUILD_ROOT/usr/src/linux-%{KernelVer}
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

%if 0%{?with_kabichk}
    gzip -c9 < Module.symvers > $RPM_BUILD_ROOT/boot/symvers-%{KernelVer}.gz
%endif

mkdir -p $RPM_BUILD_ROOT%{_sbindir}
install -m 755 %{SOURCE200} $RPM_BUILD_ROOT%{_sbindir}/mkgrub-menu-%{hulkrelease}.sh


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

%ifarch aarch64
    # Needed for systemtap
    cp -a --parents arch/arm64/kernel/module.lds $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/build/
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
%if 0%{?with_perf}
# perf
# perf tool binary and supporting scripts/binaries
%{perf_make} %{perf_python2} DESTDIR=%{buildroot} lib=%{_lib} install-bin install-traceevent-plugins
# remove the 'trace' symlink.
rm -f %{buildroot}%{_bindir}/trace

# remove examples
rm -rf %{buildroot}/usr/lib/perf/examples
# remove the stray header file that somehow got packaged in examples
rm -rf %{buildroot}/usr/lib/perf/include/bpf/

# python-perf extension
%{perf_make} %{perf_python3} DESTDIR=%{buildroot} install-python_ext
%{perf_make} %{perf_python2} DESTDIR=%{buildroot} install-python_ext
%endif

install -d %{buildroot}/%{_mandir}/man1
install -pm0644 tools/kvm/kvm_stat/kvm_stat.1 %{buildroot}/%{_mandir}/man1/
# perf man pages (note: implicit rpm magic compresses them later)
%if 0%{?with_perf}
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
    /usr/bin/sh  %{_sbindir}/mkgrub-menu-%{hulkrelease}.sh %{version}-%{hulkrelease}.aarch64  /boot/EFI/grub2/grub.cfg  remove
fi

%postun
%{_sbindir}/new-kernel-pkg --rminitrd --rmmoddep --remove %{KernelVer} || exit $?
if [ -x %{_sbindir}/weak-modules ]
then
    %{_sbindir}/weak-modules --remove-kernel %{KernelVer} || exit $?
fi
if [ "`ls -A  /lib/modules/%{KernelVer}`" = "" ]; then
    rm -rf /lib/modules/%{KernelVer}
fi

%posttrans
%{_sbindir}/new-kernel-pkg --package kernel --mkinitrd --dracut --depmod --update %{KernelVer} || exit $?
%{_sbindir}/new-kernel-pkg --package kernel --rpmposttrans %{KernelVer} || exit $?
if [ `uname -i` == "aarch64" ] &&
        [ -f /boot/EFI/grub2/grub.cfg ]; then
	/usr/bin/sh %{_sbindir}/mkgrub-menu-%{hulkrelease}.sh %{version}-%{hulkrelease}.aarch64  /boot/EFI/grub2/grub.cfg  update  
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
%if 0%{?with_kabichk}
/boot/symvers-*
%endif
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
/usr/include/*


%if 0%{?with_perf}
%files -n perf
%{_libdir}/libperf*
%{_bindir}/perf
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

%files -n python2-perf
%license linux-%{KernelVer}/COPYING
%{python2_sitearch}/*

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


* Thu July 8 2021 Senlin Xia <xiasenlin1@huawei.com> - 4.19.90-2106.3.0.0096
- add buildrequire: perl-devel for with_perf

* Tue Jun 15 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.194-2106.1.0.0085
- openeuler_defconfig: Enable ARCH_PHYTIUM and ARM_GIC_PHYTIUM_2500
- config: Enable Phytium FT-2500 support configs for hulk_defconfig
- irqchip: phytium-2500: Add interrupt controller driver
- iomap: Make sure iomap_end is called after iomap_begin
- x86/kvm: Add "nopvspin" parameter to disable PV spinlocks
- scsi: libsas: add lun number check in .slave_alloc callback
- blk-iocost: fix NULL iocg deref from racing against initialization
- Linux 4.19.194
- xen-pciback: redo VF placement in the virtual topology
- ACPI: EC: Look for ECDT EC after calling acpi_load_tables()
- ACPI: probe ECDT before loading AML tables regardless of module-level code flag
- KVM: arm64: Fix debug register indexing
- KVM: SVM: Truncate GPR value for DR and CR accesses in !64-bit mode
- btrfs: fix unmountable seed device after fstrim
- perf/core: Fix corner case in perf_rotate_context()
- perf/cgroups: Don't rotate events for cgroups unnecessarily
- bnxt_en: Remove the setting of dev_port.
- selftests/bpf: Avoid running unprivileged tests with alignment requirements
- selftests/bpf: add "any alignment" annotation for some tests
- bpf: Apply F_NEEDS_EFFICIENT_UNALIGNED_ACCESS to more ACCEPT test cases.
- bpf: Make more use of 'any' alignment in test_verifier.c
- bpf: Adjust F_NEEDS_EFFICIENT_UNALIGNED_ACCESS handling in test_verifier.c
- bpf: Add BPF_F_ANY_ALIGNMENT.
- selftests/bpf: Generalize dummy program types
- bpf: test make sure to run unpriv test cases in test_verifier
- bpf: fix test suite to enable all unpriv program types
- mm, hugetlb: fix simple resv_huge_pages underflow on UFFDIO_COPY
- btrfs: fixup error handling in fixup_inode_link_counts
- btrfs: return errors from btrfs_del_csums in cleanup_ref_head
- btrfs: fix error handling in btrfs_del_csums
- btrfs: mark ordered extent and inode with error if we fail to finish
- x86/apic: Mark _all_ legacy interrupts when IO/APIC is missing
- nfc: fix NULL ptr dereference in llcp_sock_getname() after failed connect
- ocfs2: fix data corruption by fallocate
- pid: take a reference when initializing `cad_pid`
- usb: dwc2: Fix build in periphal-only mode
- ALSA: hda: Fix for mute key LED for HP Pavilion 15-CK0xx
- ALSA: timer: Fix master timer notification
- HID: multitouch: require Finger field to mark Win8 reports as MT
- net: caif: fix memory leak in cfusbl_device_notify
- net: caif: fix memory leak in caif_device_notify
- net: caif: add proper error handling
- net: caif: added cfserl_release function
- Bluetooth: use correct lock to prevent UAF of hdev object
- Bluetooth: fix the erroneous flush_work() order
- tipc: fix unique bearer names sanity check
- tipc: add extack messages for bearer/media failure
- ixgbevf: add correct exception tracing for XDP
- ieee802154: fix error return code in ieee802154_llsec_getparams()
- ieee802154: fix error return code in ieee802154_add_iface()
- netfilter: nfnetlink_cthelper: hit EBUSY on updates if size mismatches
- HID: i2c-hid: fix format string mismatch
- HID: pidff: fix error return code in hid_pidff_init()
- ipvs: ignore IP_VS_SVC_F_HASHED flag when adding service
- vfio/platform: fix module_put call in error flow
- samples: vfio-mdev: fix error handing in mdpy_fb_probe()
- vfio/pci: zap_vma_ptes() needs MMU
- vfio/pci: Fix error return code in vfio_ecap_init()
- efi: cper: fix snprintf() use in cper_dimm_err_location()
- efi: Allow EFI_MEMORY_XP and EFI_MEMORY_RO both to be cleared
- nl80211: validate key indexes for cfg80211_registered_device
- ALSA: usb: update old-style static const declaration
- net: usb: cdc_ncm: don't spew notifications
- USB:ehci:fix Kunpeng920 ehci hardware problem
- nvme: don't warn on block content change effects
- block: recalculate segment count for multi-segment discards correctly
- nbd: Fix NULL pointer in flush_workqueue
- block: avoid creating invalid symlink file for patitions
- block: take bd_mutex around delete_partitions in del_gendisk
- NFSv4: Fix second deadlock in nfs4_evict_inode()
- NFSv4: Fix deadlock between nfs4_evict_inode() and nfs4_opendata_get_inode()
- NFSv4.1: fix handling of backchannel binding in BIND_CONN_TO_SESSION
- NFS: Don't gratuitously clear the inode cache when lookup failed
- NFS: Don't revalidate the directory permissions on a lookup failure
- NFS: nfs_delegation_find_inode_server must first reference the superblock
- nfs4: strengthen error check to avoid unexpected result
- NFS: Fix interrupted slots by sending a solo SEQUENCE operation
- NFS: Ensure we time out if a delegreturn does not complete
- NFSv4.0: nfs4_do_fsinfo() should not do implicit lease renewals
- NFS: Use kmemdup_nul() in nfs_readdir_make_qstr()
- NFSv3: FIx bug when using chacl and chmod to change acl
- NFSv4.x: Handle bad/dead sessions correctly in nfs41_sequence_process()
- NFSv4.1: Only reap expired delegations
- NFSv4.1: Fix open stateid recovery
- NFSv4.1: Don't process the sequence op more than once.
- NFS: Ensure NFS writeback allocations don't recurse back into NFS.
- nfs_remount(): don't leak, don't ignore LSM options quietly
- UACCE backport from mainline
- crypto: hisilicon-Cap block size at 2^31
- crypto: hisilicon-hpre add req check when callback
- crypto: hisilicon- count send_ref when sending bd
- crypto: hisilicon-enhancement of qm DFX
- crypto: hisilicon-memory management optimization
- net: hns3: update hns3 version to 1.9.38.12
- net: hns3: add match_id to check mailbox response from PF to VF
- net: hns3: fix possible mismatches resp of mailbox
- net: hns3: fix the logic for clearing resp_msg
- net: hns3: fix queue id check error when configure flow director rule by ethtool
- net: hns3: add check for HNS3_NIC_STATE_INITED before net open
- net: hns3: add waiting time before cmdq memory is released
- net: hns3: disable firmware compatible features when uninstall PF
- net: hns3: fix change RSS 'hfunc' ineffective issue
- net: hns3: fix inconsistent vf id print
- net: hns3: remove redundant variable initialization
- net: hns3: replace the tab before the left brace with one space
- net: hns3: fix hns3_cae_pfc_storm.h missing header guard problem
- net: hns3: modify an error type configuration
- net: hns3: put off calling register_netdev() until client initialize complete
- net: hns3: replace disable_irq by IRQ_NOAUTOEN flag
- net: hns3: update rss indirection table after setup tc
- net: hns3: don't change tc mqprio configuration when client is unregistered
- net: hns3: remove redundant client_setup_tc handle
- arm64/mpam: Fix use-after-free in mkdir_resctrl_prepare()
- share_pool: Fix concurrency problem when a process adding sp_group is killed
- share_pool: Fix address checker
- Linux 4.19.193
- usb: core: reduce power-on-good delay time of root hub
- net: hns3: check the return of skb_checksum_help()
- drivers/net/ethernet: clean up unused assignments
- hugetlbfs: hugetlb_fault_mutex_hash() cleanup
- MIPS: ralink: export rt_sysc_membase for rt2880_wdt.c
- MIPS: alchemy: xxs1500: add gpio-au1000.h header file
- sch_dsmark: fix a NULL deref in qdisc_reset()
- ipv6: record frag_max_size in atomic fragments in input path
- scsi: libsas: Use _safe() loop in sas_resume_port()
- ixgbe: fix large MTU request from VF
- bpf: Set mac_len in bpf_skb_change_head
- ASoC: cs35l33: fix an error code in probe()
- staging: emxx_udc: fix loop in _nbu2ss_nuke()
- mld: fix panic in mld_newpack()
- net: bnx2: Fix error return code in bnx2_init_board()
- openvswitch: meter: fix race when getting now_ms.
- net: mdio: octeon: Fix some double free issues
- net: mdio: thunder: Fix a double free issue in the .remove function
- net: fec: fix the potential memory leak in fec_enet_init()
- net: dsa: fix error code getting shifted with 4 in dsa_slave_get_sset_count
- net: netcp: Fix an error message
- drm/amdgpu: Fix a use-after-free
- drm/amd/amdgpu: fix refcount leak
- drm/amd/display: Disconnect non-DP with no EDID
- SMB3: incorrect file id in requests compounded with open
- platform/x86: intel_punit_ipc: Append MODULE_DEVICE_TABLE for ACPI
- platform/x86: hp-wireless: add AMD's hardware id to the supported list
- btrfs: do not BUG_ON in link_to_fixup_dir
- openrisc: Define memory barrier mb
- scsi: BusLogic: Fix 64-bit system enumeration error for Buslogic
- media: gspca: properly check for errors in po1030_probe()
- media: dvb: Add check on sp8870_readreg return
- ASoC: cs43130: handle errors in cs43130_probe() properly
- libertas: register sysfs groups properly
- dmaengine: qcom_hidma: comment platform_driver_register call
- isdn: mISDNinfineon: check/cleanup ioremap failure correctly in setup_io
- char: hpet: add checks after calling ioremap
- net: caif: remove BUG_ON(dev == NULL) in caif_xmit
- net: fujitsu: fix potential null-ptr-deref
- serial: max310x: unregister uart driver in case of failure and abort
- platform/x86: hp_accel: Avoid invoking _INI to speed up resume
- perf jevents: Fix getting maximum number of fds
- i2c: i801: Don't generate an interrupt on bus reset
- i2c: s3c2410: fix possible NULL pointer deref on read message after write
- net: dsa: fix a crash if ->get_sset_count() fails
- net: dsa: mt7530: fix VLAN traffic leaks
- tipc: skb_linearize the head skb when reassembling msgs
- Revert "net:tipc: Fix a double free in tipc_sk_mcast_rcv"
- net/mlx4: Fix EEPROM dump support
- drm/meson: fix shutdown crash when component not probed
- NFSv4: Fix v4.0/v4.1 SEEK_DATA return -ENOTSUPP when set NFS_V4_2 config
- NFS: Don't corrupt the value of pg_bytes_written in nfs_do_recoalesce()
- NFS: fix an incorrect limit in filelayout_decode_layout()
- Bluetooth: cmtp: fix file refcount when cmtp_attach_device fails
- spi: mt7621: Don't leak SPI master in probe error path
- spi: mt7621: Disable clock in probe error path
- spi: gpio: Don't leak SPI master in probe error path
- bpf: Update selftests to reflect new error states
- bpf, test_verifier: switch bpf_get_stack's 0 s> r8 test
- bpf: Test_verifier, bpf_get_stack return value add <0
- bpf: extend is_branch_taken to registers
- selftests/bpf: add selftest part of "bpf: improve verifier branch analysis"
- selftests/bpf: Test narrow loads with off > 0 in test_verifier
- bpf, selftests: Fix up some test_verifier cases for unprivileged
- bpf: fix up selftests after backports were fixed
- net: usb: fix memory leak in smsc75xx_bind
- usb: gadget: udc: renesas_usb3: Fix a race in usb3_start_pipen()
- usb: dwc3: gadget: Properly track pending and queued SG
- USB: serial: pl2303: add device id for ADLINK ND-6530 GC
- USB: serial: ftdi_sio: add IDs for IDS GmbH Products
- USB: serial: option: add Telit LE910-S1 compositions 0x7010, 0x7011
- USB: serial: ti_usb_3410_5052: add startech.com device id
- serial: rp2: use 'request_firmware' instead of 'request_firmware_nowait'
- serial: sh-sci: Fix off-by-one error in FIFO threshold register setting
- USB: usbfs: Don't WARN about excessively large memory allocations
- USB: trancevibrator: fix control-request direction
- iio: adc: ad7793: Add missing error code in ad7793_setup()
- staging: iio: cdc: ad7746: avoid overwrite of num_channels
- mei: request autosuspend after sending rx flow control
- thunderbolt: dma_port: Fix NVM read buffer bounds and offset issue
- misc/uss720: fix memory leak in uss720_probe
- kgdb: fix gcc-11 warnings harder
- dm snapshot: properly fix a crash when an origin has no snapshots
- ath10k: Validate first subframe of A-MSDU before processing the list
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
- net: hso: fix control-request directions
- proc: Check /proc/$pid/attr/ writes against file opener
- perf intel-pt: Fix transaction abort handling
- perf intel-pt: Fix sample instruction bytes
- iommu/vt-d: Fix sysfs leak in alloc_iommu()
- NFSv4: Fix a NULL pointer dereference in pnfs_mark_matching_lsegs_return()
- cifs: set server->cipher_type to AES-128-CCM for SMB3.0
- NFC: nci: fix memory leak in nci_allocate_device
- usb: dwc3: gadget: Enable suspend events
- selftests/bpf: add test_xfs_file.c and test_set_xfs_file.c
- bpf: add bpf_probe_read_str into bpf_helpers.h
- xfs: add writable tracepoint for xfs file buffer read
- readahead: introduce FMODE_WILLNEED to read first 2MB of file
- tools: libbpf: fix compiler error
- bpf: fix kabi for struct bpf_prog_aux and struct bpf_raw_event_map
- tools: bpftool: add raw_tracepoint_writable prog type to header
- tools: sync bpf.h
- bpf: add writable context for raw tracepoints
- x86/tsc: Respect tsc command line paraemeter for clocksource_tsc_early
- bpf: No need to simulate speculative domain for immediates
- bpf: Fix mask direction swap upon off reg sign change
- bpf: Wrap aux data inside bpf_sanitize_info container
- ata: ahci: Disable SXS for Hisilicon Kunpeng920
- fuse: don't ignore errors from fuse_writepages_fill()
- NFS: finish_automount() requires us to hold 2 refs to the mount record
- NFS: If nfs_mountpoint_expiry_timeout < 0, do not expire submounts
- NFS: remove unused check for negative dentry
- NFSv3: use nfs_add_or_obtain() to create and reference inodes
- NFS: Refactor nfs_instantiate() for dentry referencing callers
- shmem/ascend: charge pages to the memcg of current task
- sysfs: Remove address alignment constraint in sysfs_emit{_at}
- Revert "mm, sl[aou]b: guarantee natural alignment for kmalloc(power-of-two)"
- Revert "mm, sl[ou]b: improve memory accounting"
- Revert "mm: memcontrol: fix slub memory accounting"
- Linux 4.19.192
- Bluetooth: SMP: Fail if remote and local public keys are identical
- video: hgafb: correctly handle card detect failure during probe
- tty: vt: always invoke vc->vc_sw->con_resize callback
- vt: Fix character height handling with VT_RESIZEX
- vgacon: Record video mode changes with VT_RESIZEX
- video: hgafb: fix potential NULL pointer dereference
- qlcnic: Add null check after calling netdev_alloc_skb
- leds: lp5523: check return value of lp5xx_read and jump to cleanup code
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
- dm snapshot: fix crash with transient storage and zero chunk size
- xen-pciback: reconfigure also from backend watch handler
- Revert "serial: mvebu-uart: Fix to avoid a potential NULL pointer dereference"
- rapidio: handle create_workqueue() failure
- Revert "rapidio: fix a NULL pointer dereference when create_workqueue() fails"
- ALSA: hda/realtek: Add some CLOVE SSIDs of ALC293
- ALSA: hda/realtek: reset eapd coeff to default value for alc287
- Revert "ALSA: sb8: add a check for request_region"
- ALSA: bebob/oxfw: fix Kconfig entry for Mackie d.2 Pro
- ALSA: usb-audio: Validate MS endpoint descriptors
- ALSA: dice: fix stream format at middle sampling rate for Alesis iO 26
- ALSA: line6: Fix racy initialization of LINE6 MIDI
- ALSA: dice: fix stream format for TC Electronic Konnekt Live at high sampling transfer frequency
- cifs: fix memory leak in smb2_copychunk_range
- locking/mutex: clear MUTEX_FLAGS if wait_list is empty due to signal
- nvmet: seset ns->file when open fails
- ptrace: make ptrace() fail if the tracee changed its pid unexpectedly
- platform/x86: dell-smbios-wmi: Fix oops on rmmod dell_smbios
- RDMA/mlx5: Recover from fatal event in dual port mode
- scsi: qla2xxx: Fix error return code in qla82xx_write_flash_dword()
- RDMA/rxe: Clear all QP fields if creation failed
- openrisc: Fix a memory leak
- firmware: arm_scpi: Prevent the ternary sign expansion bug
- arm/ras: Report ARM processor information to userspace
- fuse: update attr_version counter on fuse_notify_inval_inode()
- alinux: random: speed up the initialization of module
- Linux 4.19.191
- scripts: switch explicitly to Python 3
- tweewide: Fix most Shebang lines
- KVM: arm64: Initialize VCPU mdcr_el2 before loading it
- ipv6: remove extra dev_hold() for fallback tunnels
- ip6_tunnel: sit: proper dev_{hold|put} in ndo_[un]init methods
- sit: proper dev_{hold|put} in ndo_[un]init methods
- ip6_gre: proper dev_{hold|put} in ndo_[un]init methods
- net: stmmac: Do not enable RX FIFO overflow interrupts
- lib: stackdepot: turn depot_lock spinlock to raw_spinlock
- block: reexpand iov_iter after read/write
- ALSA: hda: generic: change the DAC ctl name for LO+SPK or LO+HP
- gpiolib: acpi: Add quirk to ignore EC wakeups on Dell Venue 10 Pro 5055
- scsi: target: tcmu: Return from tcmu_handle_completions() if cmd_id not found
- ceph: fix fscache invalidation
- riscv: Workaround mcount name prior to clang-13
- scripts/recordmcount.pl: Fix RISC-V regex for clang
- ARM: 9075/1: kernel: Fix interrupted SMC calls
- um: Mark all kernel symbols as local
- Input: silead - add workaround for x86 BIOS-es which bring the chip up in a stuck state
- Input: elants_i2c - do not bind to i2c-hid compatible ACPI instantiated devices
- ACPI / hotplug / PCI: Fix reference count leak in enable_slot()
- ARM: 9066/1: ftrace: pause/unpause function graph tracer in cpu_suspend()
- PCI: thunder: Fix compile testing
- xsk: Simplify detection of empty and full rings
- pinctrl: ingenic: Improve unreachable code generation
- isdn: capi: fix mismatched prototypes
- cxgb4: Fix the -Wmisleading-indentation warning
- usb: sl811-hcd: improve misleading indentation
- kgdb: fix gcc-11 warning on indentation
- x86/msr: Fix wr/rdmsr_safe_regs_on_cpu() prototypes
- nvme: do not try to reconfigure APST when the controller is not live
- clk: exynos7: Mark aclk_fsys1_200 as critical
- netfilter: conntrack: Make global sysctls readonly in non-init netns
- kobject_uevent: remove warning in init_uevent_argv()
- thermal/core/fair share: Lock the thermal zone while looping over instances
- MIPS: Avoid handcoded DIVU in `__div64_32' altogether
- MIPS: Avoid DIVU in `__div64_32' is result would be zero
- MIPS: Reinstate platform `__div64_32' handler
- FDDI: defxx: Make MMIO the configuration default except for EISA
- KVM: x86: Cancel pvclock_gtod_work on module removal
- cdc-wdm: untangle a circular dependency between callback and softint
- iio: tsl2583: Fix division by a zero lux_val
- iio: gyro: mpu3050: Fix reported temperature value
- xhci: Add reset resume quirk for AMD xhci controller.
- xhci: Do not use GFP_KERNEL in (potentially) atomic context
- usb: dwc3: gadget: Return success always for kick transfer in ep queue
- usb: core: hub: fix race condition about TRSMRCY of resume
- usb: dwc2: Fix gadget DMA unmap direction
- usb: xhci: Increase timeout for HC halt
- usb: dwc3: pci: Enable usb2-gadget-lpm-disable for Intel Merrifield
- usb: dwc3: omap: improve extcon initialization
- blk-mq: Swap two calls in blk_mq_exit_queue()
- ACPI: scan: Fix a memory leak in an error handling path
- usb: fotg210-hcd: Fix an error message
- iio: proximity: pulsedlight: Fix rumtime PM imbalance on error
- drm/radeon/dpm: Disable sclk switching on Oland when two 4K 60Hz monitors are connected
- userfaultfd: release page in error path to avoid BUG_ON
- squashfs: fix divide error in calculate_skip()
- hfsplus: prevent corruption in shrinking truncate
- powerpc/64s: Fix crashes when toggling entry flush barrier
- powerpc/64s: Fix crashes when toggling stf barrier
- ARC: entry: fix off-by-one error in syscall number validation
- i40e: Fix use-after-free in i40e_client_subtask()
- netfilter: nftables: avoid overflows in nft_hash_buckets()
- kernel: kexec_file: fix error return code of kexec_calculate_store_digests()
- sched/fair: Fix unfairness caused by missing load decay
- netfilter: nfnetlink_osf: Fix a missing skb_header_pointer() NULL check
- smc: disallow TCP_ULP in smc_setsockopt()
- net: fix nla_strcmp to handle more then one trailing null character
- ksm: fix potential missing rmap_item for stable_node
- mm/hugeltb: handle the error case in hugetlb_fix_reserve_counts()
- khugepaged: fix wrong result value for trace_mm_collapse_huge_page_isolate()
- drm/radeon: Avoid power table parsing memory leaks
- drm/radeon: Fix off-by-one power_state index heap overwrite
- netfilter: xt_SECMARK: add new revision to fix structure layout
- sctp: fix a SCTP_MIB_CURRESTAB leak in sctp_sf_do_dupcook_b
- ethernet:enic: Fix a use after free bug in enic_hard_start_xmit
- sctp: do asoc update earlier in sctp_sf_do_dupcook_a
- rtc: ds1307: Fix wday settings for rx8130
- NFSv4.2 fix handling of sr_eof in SEEK's reply
- pNFS/flexfiles: fix incorrect size check in decode_nfs_fh()
- PCI: endpoint: Fix missing destroy_workqueue()
- NFS: Deal correctly with attribute generation counter overflow
- NFSv4.2: Always flush out writes in nfs42_proc_fallocate()
- rpmsg: qcom_glink_native: fix error return code of qcom_glink_rx_data()
- ARM: 9064/1: hw_breakpoint: Do not directly check the event's overflow_handler hook
- PCI: Release OF node in pci_scan_device()'s error path
- PCI: iproc: Fix return value of iproc_msi_irq_domain_alloc()
- f2fs: fix a redundant call to f2fs_balance_fs if an error occurs
- ASoC: rt286: Make RT286_SET_GPIO_* readable and writable
- ia64: module: fix symbolizer crash on fdescr
- net: ethernet: mtk_eth_soc: fix RX VLAN offload
- powerpc/iommu: Annotate nested lock for lockdep
- wl3501_cs: Fix out-of-bounds warnings in wl3501_mgmt_join
- wl3501_cs: Fix out-of-bounds warnings in wl3501_send_pkt
- powerpc/pseries: Stop calling printk in rtas_stop_self()
- samples/bpf: Fix broken tracex1 due to kprobe argument change
- ethtool: ioctl: Fix out-of-bounds warning in store_link_ksettings_for_user()
- ASoC: rt286: Generalize support for ALC3263 codec
- powerpc/smp: Set numa node before updating mask
- sctp: Fix out-of-bounds warning in sctp_process_asconf_param()
- kconfig: nconf: stop endless search loops
- selftests: Set CC to clang in lib.mk if LLVM is set
- cuse: prevent clone
- pinctrl: samsung: use 'int' for register masks in Exynos
- mac80211: clear the beacon's CRC after channel switch
- i2c: Add I2C_AQ_NO_REP_START adapter quirk
- ASoC: Intel: bytcr_rt5640: Add quirk for the Chuwi Hi8 tablet
- ip6_vti: proper dev_{hold|put} in ndo_[un]init methods
- Bluetooth: check for zapped sk before connecting
- net: bridge: when suppression is enabled exclude RARP packets
- Bluetooth: initialize skb_queue_head at l2cap_chan_create()
- Bluetooth: Set CONF_NOT_COMPLETE as l2cap_chan default
- ALSA: rme9652: don't disable if not enabled
- ALSA: hdspm: don't disable if not enabled
- ALSA: hdsp: don't disable if not enabled
- i2c: bail out early when RDWR parameters are wrong
- net: stmmac: Set FIFO sizes for ipq806x
- ASoC: Intel: bytcr_rt5640: Enable jack-detect support on Asus T100TAF
- tipc: convert dest node's address to network order
- fs: dlm: fix debugfs dump
- tpm: fix error return code in tpm2_get_cc_attrs_tbl()
- Revert "fdt: Properly handle "no-map" field in the memory region"
- Revert "of/fdt: Make sure no-map does not remove already reserved regions"
- sctp: delay auto_asconf init until binding the first addr
- Revert "net/sctp: fix race condition in sctp_destroy_sock"
- smp: Fix smp_call_function_single_async prototype
- net: Only allow init netns to set default tcp cong to a restricted algo
- mm/memory-failure: unnecessary amount of unmapping
- mm/sparse: add the missing sparse_buffer_fini() in error branch
- kfifo: fix ternary sign extension bugs
- net:nfc:digital: Fix a double free in digital_tg_recv_dep_req
- RDMA/bnxt_re: Fix a double free in bnxt_qplib_alloc_res
- net:emac/emac-mac: Fix a use after free in emac_mac_tx_buf_send
- net: geneve: modify IP header check in geneve6_xmit_skb and geneve_xmit_skb
- arm64: dts: uniphier: Change phy-mode to RGMII-ID to enable delay pins for RTL8211E
- ARM: dts: uniphier: Change phy-mode to RGMII-ID to enable delay pins for RTL8211E
- bnxt_en: fix ternary sign extension bug in bnxt_show_temp()
- powerpc/52xx: Fix an invalid ASM expression ('addi' used instead of 'add')
- ath10k: Fix ath10k_wmi_tlv_op_pull_peer_stats_info() unlock without lock
- ath9k: Fix error check in ath9k_hw_read_revisions() for PCI devices
- net: davinci_emac: Fix incorrect masking of tx and rx error channel
- ALSA: usb: midi: don't return -ENOMEM when usb_urb_ep_type_check fails
- RDMA/i40iw: Fix error unwinding when i40iw_hmc_sd_one fails
- vsock/vmci: log once the failed queue pair allocation
- mwl8k: Fix a double Free in mwl8k_probe_hw
- i2c: sh7760: fix IRQ error path
- rtlwifi: 8821ae: upgrade PHY and RF parameters
- powerpc/pseries: extract host bridge from pci_bus prior to bus removal
- MIPS: pci-legacy: stop using of_pci_range_to_resource
- drm/i915/gvt: Fix error code in intel_gvt_init_device()
- ASoC: ak5558: correct reset polarity
- i2c: sh7760: add IRQ check
- i2c: jz4780: add IRQ check
- i2c: emev2: add IRQ check
- i2c: cadence: add IRQ check
- RDMA/srpt: Fix error return code in srpt_cm_req_recv()
- net: thunderx: Fix unintentional sign extension issue
- IB/hfi1: Fix error return code in parse_platform_config()
- mt7601u: fix always true expression
- mac80211: bail out if cipher schemes are invalid
- powerpc: iommu: fix build when neither PCI or IBMVIO is set
- powerpc/perf: Fix PMU constraint check for EBB events
- powerpc/64s: Fix pte update for kernel memory on radix
- liquidio: Fix unintented sign extension of a left shift of a u16
- ALSA: usb-audio: Add error checks for usb_driver_claim_interface() calls
- net: hns3: Limiting the scope of vector_ring_chain variable
- nfc: pn533: prevent potential memory corruption
- bug: Remove redundant condition check in report_bug
- ALSA: core: remove redundant spin_lock pair in snd_card_disconnect
- powerpc: Fix HAVE_HARDLOCKUP_DETECTOR_ARCH build configuration
- powerpc/prom: Mark identical_pvr_fixup as __init
- net: lapbether: Prevent racing when checking whether the netif is running
- perf symbols: Fix dso__fprintf_symbols_by_name() to return the number of printed chars
- HID: plantronics: Workaround for double volume key presses
- drivers/block/null_blk/main: Fix a double free in null_init.
- sched/debug: Fix cgroup_path[] serialization
- x86/events/amd/iommu: Fix sysfs type mismatch
- HSI: core: fix resource leaks in hsi_add_client_from_dt()
- mfd: stm32-timers: Avoid clearing auto reload register
- scsi: ibmvfc: Fix invalid state machine BUG_ON()
- scsi: sni_53c710: Add IRQ check
- scsi: sun3x_esp: Add IRQ check
- scsi: jazz_esp: Add IRQ check
- clk: uniphier: Fix potential infinite loop
- clk: qcom: a53-pll: Add missing MODULE_DEVICE_TABLE
- vfio/mdev: Do not allow a mdev_type to have a NULL parent pointer
- nvme: retrigger ANA log update if group descriptor isn't found
- ata: libahci_platform: fix IRQ check
- sata_mv: add IRQ checks
- pata_ipx4xx_cf: fix IRQ check
- pata_arasan_cf: fix IRQ check
- x86/kprobes: Fix to check non boostable prefixes correctly
- drm/amdkfd: fix build error with AMD_IOMMU_V2=m
- media: m88rs6000t: avoid potential out-of-bounds reads on arrays
- media: omap4iss: return error code when omap4iss_get() failed
- media: vivid: fix assignment of dev->fbuf_out_flags
- soc: aspeed: fix a ternary sign expansion bug
- ttyprintk: Add TTY hangup callback.
- usb: dwc2: Fix hibernation between host and device modes.
- usb: dwc2: Fix host mode hibernation exit with remote wakeup flow.
- Drivers: hv: vmbus: Increase wait time for VMbus unload
- x86/platform/uv: Fix !KEXEC build failure
- platform/x86: pmc_atom: Match all Beckhoff Automation baytrail boards with critclk_systems DMI table
- usbip: vudc: fix missing unlock on error in usbip_sockfd_store()
- firmware: qcom-scm: Fix QCOM_SCM configuration
- tty: fix return value for unsupported ioctls
- tty: actually undefine superseded ASYNC flags
- USB: cdc-acm: fix unprivileged TIOCCSERIAL
- usb: gadget: r8a66597: Add missing null check on return from platform_get_resource
- cpufreq: armada-37xx: Fix determining base CPU frequency
- cpufreq: armada-37xx: Fix driver cleanup when registration failed
- clk: mvebu: armada-37xx-periph: Fix workaround for switching from L1 to L0
- clk: mvebu: armada-37xx-periph: Fix switching CPU freq from 250 Mhz to 1 GHz
- cpufreq: armada-37xx: Fix the AVS value for load L1
- clk: mvebu: armada-37xx-periph: remove .set_parent method for CPU PM clock
- cpufreq: armada-37xx: Fix setting TBG parent for load levels
- crypto: qat - Fix a double free in adf_create_ring
- ACPI: CPPC: Replace cppc_attr with kobj_attribute
- soc: qcom: mdt_loader: Detect truncated read of segments
- soc: qcom: mdt_loader: Validate that p_filesz < p_memsz
- spi: Fix use-after-free with devm_spi_alloc_*
- staging: greybus: uart: fix unprivileged TIOCCSERIAL
- staging: rtl8192u: Fix potential infinite loop
- irqchip/gic-v3: Fix OF_BAD_ADDR error handling
- mtd: rawnand: gpmi: Fix a double free in gpmi_nand_init
- soundwire: stream: fix memory leak in stream config error path
- USB: gadget: udc: fix wrong pointer passed to IS_ERR() and PTR_ERR()
- usb: gadget: aspeed: fix dma map failure
- crypto: qat - fix error path in adf_isr_resource_alloc()
- phy: marvell: ARMADA375_USBCLUSTER_PHY should not default to y, unconditionally
- soundwire: bus: Fix device found flag correctly
- bus: qcom: Put child node before return
- mtd: require write permissions for locking and badblock ioctls
- fotg210-udc: Complete OUT requests on short packets
- fotg210-udc: Don't DMA more than the buffer can take
- fotg210-udc: Mask GRP2 interrupts we don't handle
- fotg210-udc: Remove a dubious condition leading to fotg210_done
- fotg210-udc: Fix EP0 IN requests bigger than two packets
- fotg210-udc: Fix DMA on EP0 for length > max packet size
- crypto: qat - ADF_STATUS_PF_RUNNING should be set after adf_dev_init
- crypto: qat - don't release uninitialized resources
- usb: gadget: pch_udc: Check for DMA mapping error
- usb: gadget: pch_udc: Check if driver is present before calling ->setup()
- usb: gadget: pch_udc: Replace cpu_to_le32() by lower_32_bits()
- x86/microcode: Check for offline CPUs before requesting new microcode
- mtd: rawnand: qcom: Return actual error code instead of -ENODEV
- mtd: Handle possible -EPROBE_DEFER from parse_mtd_partitions()
- mtd: rawnand: brcmnand: fix OOB R/W with Hamming ECC
- mtd: rawnand: fsmc: Fix error code in fsmc_nand_probe()
- regmap: set debugfs_name to NULL after it is freed
- usb: typec: tcpci: Check ROLE_CONTROL while interpreting CC_STATUS
- serial: stm32: fix tx_empty condition
- serial: stm32: fix incorrect characters on console
- ARM: dts: exynos: correct PMIC interrupt trigger level on Snow
- ARM: dts: exynos: correct PMIC interrupt trigger level on SMDK5250
- ARM: dts: exynos: correct PMIC interrupt trigger level on Odroid X/U3 family
- ARM: dts: exynos: correct PMIC interrupt trigger level on Midas family
- ARM: dts: exynos: correct MUIC interrupt trigger level on Midas family
- ARM: dts: exynos: correct fuel gauge interrupt trigger level on Midas family
- memory: gpmc: fix out of bounds read and dereference on gpmc_cs[]
- usb: gadget: pch_udc: Revert d3cb25a12138 completely
- ovl: fix missing revert_creds() on error path
- KVM: s390: split kvm_s390_real_to_abs
- KVM: s390: fix guarded storage control register handling
- KVM: s390: split kvm_s390_logical_to_effective
- x86/cpu: Initialize MSR_TSC_AUX if RDTSCP *or* RDPID is supported
- ALSA: hda/realtek: Remove redundant entry for ALC861 Haier/Uniwill devices
- ALSA: hda/realtek: Re-order ALC269 Lenovo quirk table entries
- ALSA: hda/realtek: Re-order ALC269 Sony quirk table entries
- ALSA: hda/realtek: Re-order ALC269 Dell quirk table entries
- ALSA: hda/realtek: Re-order ALC269 HP quirk table entries
- ALSA: hda/realtek: Re-order ALC882 Clevo quirk table entries
- ALSA: hda/realtek: Re-order ALC882 Sony quirk table entries
- ALSA: hda/realtek: Re-order ALC882 Acer quirk table entries
- drm/radeon: fix copy of uninitialized variable back to userspace
- cfg80211: scan: drop entry from hidden_list on overflow
- ipw2x00: potential buffer overflow in libipw_wx_set_encodeext()
- md: Fix missing unused status line of /proc/mdstat
- md: md_open returns -EBUSY when entering racing area
- md: factor out a mddev_find_locked helper from mddev_find
- md: split mddev_find
- md-cluster: fix use-after-free issue when removing rdev
- md/bitmap: wait for external bitmap writes to complete during tear down
- misc: vmw_vmci: explicitly initialize vmci_datagram payload
- misc: vmw_vmci: explicitly initialize vmci_notify_bm_set_msg struct
- misc: lis3lv02d: Fix false-positive WARN on various HP models
- iio:accel:adis16201: Fix wrong axis assignment that prevents loading
- FDDI: defxx: Bail out gracefully with unassigned PCI resource for CSR
- MIPS: pci-rt2880: fix slot 0 configuration
- MIPS: pci-mt7620: fix PLL lock check
- ASoC: samsung: tm2_wm5110: check of of_parse return value
- net/nfc: fix use-after-free llcp_sock_bind/connect
- hsr: use netdev_err() instead of WARN_ONCE()
- Bluetooth: verify AMP hci_chan before amp_destroy
- modules: inherit TAINT_PROPRIETARY_MODULE
- modules: return licensing information from find_symbol
- modules: rename the licence field in struct symsearch to license
- modules: unexport __module_address
- modules: unexport __module_text_address
- modules: mark each_symbol_section static
- modules: mark find_symbol static
- modules: mark ref_module static
- dm rq: fix double free of blk_mq_tag_set in dev remove after table load fails
- dm space map common: fix division bug in sm_ll_find_free_block()
- dm persistent data: packed struct should have an aligned() attribute too
- tracing: Restructure trace_clock_global() to never block
- tracing: Map all PIDs to command lines
- rsi: Use resume_noirq for SDIO
- tty: fix memory leak in vc_deallocate
- usb: dwc2: Fix session request interrupt handler
- usb: dwc3: gadget: Fix START_TRANSFER link state check
- usb: gadget/function/f_fs string table fix for multiple languages
- usb: gadget: Fix double free of device descriptor pointers
- usb: gadget: dummy_hcd: fix gpf in gadget_setup
- media: dvbdev: Fix memory leak in dvb_media_device_free()
- ext4: fix error code in ext4_commit_super
- posix-timers: Preserve return value in clock_adjtime32()
- Revert 337f13046ff0 ("futex: Allow FUTEX_CLOCK_REALTIME with FUTEX_WAIT op")
- jffs2: check the validity of dstlen in jffs2_zlib_compress()
- Fix misc new gcc warnings
- security: commoncap: fix -Wstringop-overread warning
- dm raid: fix inconclusive reshape layout on fast raid4/5/6 table reload sequences
- md/raid1: properly indicate failure when ending a failed write request
- tpm: vtpm_proxy: Avoid reading host log when using a virtual device
- intel_th: pci: Add Alder Lake-M support
- powerpc: fix EDEADLOCK redefinition error in uapi/asm/errno.h
- powerpc/eeh: Fix EEH handling for hugepages in ioremap space.
- jffs2: Fix kasan slab-out-of-bounds problem
- NFSv4: Don't discard segments marked for return in _pnfs_return_layout()
- NFS: Don't discard pNFS layout segments that are marked for return
- ACPI: GTDT: Don't corrupt interrupt mappings on watchdow probe failure
- openvswitch: fix stack OOB read while fragmenting IPv4 packets
- mlxsw: spectrum_mr: Update egress RIF list before route's action
- ubifs: Only check replay with inode type to judge if inode linked
- arm64/vdso: Discard .note.gnu.property sections in vDSO
- btrfs: fix race when picking most recent mod log operation for an old root
- ALSA: hda/realtek: Add quirk for Intel Clevo PCx0Dx
- ALSA: usb-audio: Add dB range mapping for Sennheiser Communications Headset PC 8
- ALSA: usb-audio: More constifications
- ALSA: usb-audio: Explicitly set up the clock selector
- ALSA: sb: Fix two use after free in snd_sb_qsound_build
- ALSA: hda/conexant: Re-order CX5066 quirk table entries
- ALSA: emu8000: Fix a use after free in snd_emu8000_create_mixer
- s390/archrandom: add parameter check for s390_arch_random_generate
- scsi: libfc: Fix a format specifier
- scsi: lpfc: Remove unsupported mbox PORT_CAPABILITIES logic
- scsi: lpfc: Fix crash when a REG_RPI mailbox fails triggering a LOGO response
- drm/amdgpu: fix NULL pointer dereference
- amdgpu: avoid incorrect %hu format string
- drm/msm/mdp5: Configure PP_SYNC_HEIGHT to double the vtotal
- media: gscpa/stv06xx: fix memory leak
- media: dvb-usb: fix memory leak in dvb_usb_adapter_init
- media: i2c: adv7842: fix possible use-after-free in adv7842_remove()
- media: i2c: adv7511-v4l2: fix possible use-after-free in adv7511_remove()
- media: adv7604: fix possible use-after-free in adv76xx_remove()
- media: tc358743: fix possible use-after-free in tc358743_remove()
- power: supply: s3c_adc_battery: fix possible use-after-free in s3c_adc_bat_remove()
- power: supply: generic-adc-battery: fix possible use-after-free in gab_remove()
- clk: socfpga: arria10: Fix memory leak of socfpga_clk on error return
- media: vivid: update EDID
- media: em28xx: fix memory leak
- scsi: scsi_dh_alua: Remove check for ASC 24h in alua_rtpg()
- scsi: qla2xxx: Fix use after free in bsg
- scsi: qla2xxx: Always check the return value of qla24xx_get_isp_stats()
- drm/amdgpu : Fix asic reset regression issue introduce by 8f211fe8ac7c4f
- power: supply: Use IRQF_ONESHOT
- media: gspca/sq905.c: fix uninitialized variable
- media: media/saa7164: fix saa7164_encoder_register() memory leak bugs
- extcon: arizona: Fix some issues when HPDET IRQ fires after the jack has been unplugged
- power: supply: bq27xxx: fix power_avg for newer ICs
- media: drivers: media: pci: sta2x11: fix Kconfig dependency on GPIOLIB
- media: ite-cir: check for receive overflow
- scsi: target: pscsi: Fix warning in pscsi_complete_cmd()
- scsi: lpfc: Fix pt2pt connection does not recover after LOGO
- scsi: lpfc: Fix incorrect dbde assignment when building target abts wqe
- btrfs: convert logic BUG_ON()'s in replace_path to ASSERT()'s
- phy: phy-twl4030-usb: Fix possible use-after-free in twl4030_usb_remove()
- intel_th: Consistency and off-by-one fix
- spi: omap-100k: Fix reference leak to master
- spi: dln2: Fix reference leak to master
- xhci: fix potential array out of bounds with several interrupters
- xhci: check control context is valid before dereferencing it.
- usb: xhci-mtk: support quirk to disable usb2 lpm
- perf/arm_pmu_platform: Fix error handling
- tee: optee: do not check memref size on return from Secure World
- x86/build: Propagate $(CLANG_FLAGS) to $(REALMODE_FLAGS)
- PCI: PM: Do not read power state in pci_enable_device_flags()
- usb: xhci: Fix port minor revision
- usb: dwc3: gadget: Ignore EP queue requests during bus reset
- usb: gadget: f_uac1: validate input parameters
- genirq/matrix: Prevent allocation counter corruption
- usb: gadget: uvc: add bInterval checking for HS mode
- crypto: api - check for ERR pointers in crypto_destroy_tfm()
- staging: wimax/i2400m: fix byte-order issue
- fbdev: zero-fill colormap in fbcmap.c
- intel_th: pci: Add Rocket Lake CPU support
- btrfs: fix metadata extent leak after failure to create subvolume
- cifs: Return correct error code from smb2_get_enc_key
- erofs: add unsupported inode i_format check
- mmc: core: Set read only for SD cards with permanent write protect bit
- mmc: core: Do a power cycle when the CMD11 fails
- mmc: block: Issue a cache flush only when it's enabled
- mmc: block: Update ext_csd.cache_ctrl if it was written
- mmc: sdhci-pci: Fix initialization of some SD cards for Intel BYT-based controllers
- scsi: qla2xxx: Fix crash in qla2xxx_mqueuecommand()
- spi: spi-ti-qspi: Free DMA resources
- mtd: rawnand: atmel: Update ecc_stats.corrected counter
- mtd: spinand: core: add missing MODULE_DEVICE_TABLE()
- ecryptfs: fix kernel panic with null dev_name
- arm64: dts: mt8173: fix property typo of 'phys' in dsi node
- arm64: dts: marvell: armada-37xx: add syscon compatible to NB clk node
- ARM: 9056/1: decompressor: fix BSS size calculation for LLVM ld.lld
- ftrace: Handle commands when closing set_ftrace_filter file
- ACPI: custom_method: fix a possible memory leak
- ACPI: custom_method: fix potential use-after-free issue
- s390/disassembler: increase ebpf disasm buffer size
- x86: Select HARDIRQS_SW_RESEND on x86
- x86/apic/vector: Force interupt handler invocation to irq context
- tools arch x86: Sync asm/cpufeatures.h with the with the kernel
- cpufreq: intel_pstate: Also use CPPC nominal_perf for base_frequency
- ACPI / CPPC: Fix guaranteed performance handling
- perf vendor events: Add JSON metrics for Cascadelake server
- perf vendor events: Add stepping in CPUID string for x86
- cpufreq: intel_pstate: Fix compilation for !CONFIG_ACPI
- cpufreq: intel_pstate: Add base_frequency attribute
- ACPI / CPPC: Add support for guaranteed performance
- EDAC, skx: Fix randconfig builds in a better way
- EDAC, skx: Fix randconfig builds
- EDAC, skx_edac: Add address translation for non-volatile DIMMs
- ACPI/ADXL: Add address translation interface using an ACPI DSM
- x86/mce: Add macros for the corrected error count bit field
- x86/mce: Use BIT_ULL(x) for bit mask definitions
- x86/cpufeatures: Enumerate the new AVX512 BFLOAT16 instructions
- genirq: Sanitize state handling in check_irq_resend()
- genirq: Add return value to check_irq_resend()
- irqchip/gic-v2, v3: Prevent SW resends entirely
- irqchip/git-v3-its: Implement irq_retrigger callback for device-triggered LPIs
- irqchip/gic-v2, v3: Implement irq_chip->irq_retrigger()
- genirq: Walk the irq_data hierarchy when resending an interrupt
- genirq: Add protection against unsafe usage of generic_handle_irq()
- tools/testing/selftests/exec: fix link error
- NFSv4.1: Don't rebind to the same source port when reconnecting to the server
- jbd2: don't abort the journal when freeing buffers
- jbd2: ensure abort the journal if detect IO error when writing original buffer back
- jbd2: remove the out label in __jbd2_journal_remove_checkpoint()
- x86/unwind/orc: Remove boot-time ORC unwind tables sorting
- scripts/sorttable: Implement build-time ORC unwind table sorting
- scripts/sorttable: Rename 'sortextable' to 'sorttable'
- scripts/sortextable: Refactor the do_func() function
- scripts/sortextable: Remove dead code
- scripts/sortextable: Clean up the code to meet the kernel coding style better
- scripts/sortextable: Rewrite error/success handling
- treewide: Replace GPLv2 boilerplate/reference with SPDX - rule 378
- ext4: Fix bug on in ext4_es_cache_extent as ext4_split_extent_at failed
- Revert "ext4: Fix bug on in ext4_es_cache_extent as ext4_split_extent_at failed"
- nfs4.0: Refetch lease_time after clientid update
- nfs4: Rename nfs41_setup_state_renewal
- nfs4: Make nfs4_proc_get_lease_time available for nfs4.0
- nfs: Fix copy-and-paste error in debug message
- ext4: cleanup in-core orphan list if ext4_truncate() failed to get a transaction handle
- bluetooth: eliminate the potential race condition when removing the HCI controller
- mm: enhance variables check and sync for pin mem
- Ascend/cdm:alloc hugepage from the specified CDM node
- Ascend/hugetlb:support alloc normal and temporary hugepge
- Ascend/memcg: Use CONFIG_ASCEND_FEATURES for customized interfaces
- perf jit: Fix inaccurate DWARF line table
- perf jvmti: Remove redundant jitdump line table entries
- perf jvmti: Fix demangling Java symbols
- perf tests: Add test for the java demangler
- perf jvmti: Do not report error when missing debug information
- perf jvmti: Fix jitdump for methods without debug info
- bpf: Fix leakage of uninitialized bpf stack under speculation
- config: set default value of CONFIG_ITRACE
- itrace: Add documentation for itrace
- itrace: Add irqsoff trace support
- itrace: Add interrupts trace support
- mm/page_alloc: fix managed_pages of zone is incorrect and out of bounds
- freezer: Add unsafe version of freezable_schedule_timeout_interruptible() for NFS
- NFS: Allow signal interruption of NFS4ERR_DELAYed operations
- SUNRPC: Make "no retrans timeout" soft tasks behave like softconn for timeouts
- SUNRPC: Don't let RPC_SOFTCONN tasks time out if the transport is connected
- ext4: fix check to prevent false positive report of incorrect used inodes
- livepatch/x86_64: Fix the deadlock when insmoding livepatch kernel module
- tools/testing/selftests: add self-test for verifying load alignment
- fs/binfmt_elf: use PT_LOAD p_align values for suitable start address
- ext4: introduce ext4_sb_bread_unmovable() to replace sb_bread_unmovable()
- ext4: use ext4_sb_bread() instead of sb_bread()
- ext4: introduce ext4_sb_breadahead_unmovable() to replace sb_breadahead_unmovable()
- ext4: use ext4_buffer_uptodate() in __ext4_get_inode_loc()
- ext4: use common helpers in all places reading metadata buffers
- ext4: introduce new metadata buffer read helpers
- ext4: treat buffers contining write errors as valid in ext4_sb_bread()
- bpf: Fix truncation handling for mod32 dst reg wrt zero
- bpf: Fix 32 bit src register truncation on div/mod
- arm64: bpf: implement jitting of JMP32
- x86_64: bpf: implement jitting of JMP32
- bpf: JIT blinds support JMP32
- bpf: interpreter support for JMP32
- tools: bpftool: teach cfg code about JMP32
- bpf: disassembler support JMP32
- bpf: verifier support JMP32
- bpf: refactor verifier min/max code for condition jump
- bpf: allocate 0x06 to new eBPF instruction class JMP32
- cgroup/files: support boot parameter to control if disable files cgroup
- RDMA/hns: Allocate one more recv SGE for HIP08
- mm: memcontrol: fix slub memory accounting
- mm, sl[ou]b: improve memory accounting
- mm: fix numa stats for thp migration
- mm: memcg/slab: fix root memcg vmstats
- mm/vmscan: count layzfree pages and fix nr_isolated_* mismatch
- Linux 4.19.190
- ovl: allow upperdir inside lowerdir
- platform/x86: thinkpad_acpi: Correct thermal sensor allocation
- USB: Add reset-resume quirk for WD19's Realtek Hub
- USB: Add LPM quirk for Lenovo ThinkPad USB-C Dock Gen2 Ethernet
- ALSA: usb-audio: Add MIDI quirk for Vox ToneLab EX
- iwlwifi: Fix softirq/hardirq disabling in iwl_pcie_gen2_enqueue_hcmd()
- bpf: Fix masking negation logic upon negative dst register
- mips: Do not include hi and lo in clobber list for R6
- iwlwifi: Fix softirq/hardirq disabling in iwl_pcie_enqueue_hcmd()
- net: usb: ax88179_178a: initialize local variables before use
- ACPI: x86: Call acpi_boot_table_init() after acpi_table_upgrade()
- ACPI: tables: x86: Reserve memory occupied by ACPI tables
- erofs: fix extended inode could cross boundary
- SUNRPC: Close a race with transport setup and module put
- sunrpc: Change the place of endtime in struct krb5_ctx
- bpf: Tighten speculative pointer arithmetic mask
- bpf: Move sanitize_val_alu out of op switch
- bpf: Refactor and streamline bounds check into helper
- bpf: Improve verifier error messages for users
- bpf: Rework ptr_limit into alu_limit and add common error path
- bpf: Ensure off_reg has no mixed signed bounds for all types
- bpf: Move off_reg into sanitize_ptr_alu

* Sat May 08 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.189-2104.7.0.0084
- config: enable kernel hotupgrade features by default
- kexec: Add quick kexec support for kernel
- arm64: smp: Add support for cpu park
- pid: add pid reserve method for checkpoint and restore
- mm: add pin memory method for checkpoint add restore
- Revert "sched: Introduce qos scheduler for co-location"
- Revert "sched: Throttle qos cfs_rq when current cpu is running online task"
- Revert "sched: Enable qos scheduler config"
- Revert "memcg: support priority for oom"
- Revert "memcg: enable CONFIG_MEMCG_QOS by default"
- Linux 4.19.189
- USB: CDC-ACM: fix poison/unpoison imbalance
- net: hso: fix NULL-deref on disconnect regression
- x86/crash: Fix crash_setup_memmap_entries() out-of-bounds access
- ia64: tools: remove duplicate definition of ia64_mf() on ia64
- ia64: fix discontig.c section mismatches
- cavium/liquidio: Fix duplicate argument
- xen-netback: Check for hotplug-status existence before watching
- s390/entry: save the caller of psw_idle
- net: geneve: check skb is large enough for IPv4/IPv6 header
- ARM: dts: Fix swapped mmc order for omap3
- HID: wacom: Assign boolean values to a bool variable
- HID: alps: fix error return code in alps_input_configured()
- HID: google: add don USB id
- perf/x86/intel/uncore: Remove uncore extra PCI dev HSWEP_PCI_PCU_3
- locking/qrwlock: Fix ordering in queued_write_lock_slowpath()
- pinctrl: lewisburg: Update number of pins in community
- gup: document and work around "COW can break either way" issue
- net: phy: marvell: fix detection of PHY on Topaz switches
- ARM: 9071/1: uprobes: Don't hook on thumb instructions
- ARM: footbridge: fix PCI interrupt mapping
- ibmvnic: remove duplicate napi_schedule call in open function
- ibmvnic: remove duplicate napi_schedule call in do_reset function
- ibmvnic: avoid calling napi_disable() twice
- i40e: fix the panic when running bpf in xdpdrv mode
- net: ip6_tunnel: Unregister catch-all devices
- net: sit: Unregister catch-all devices
- net: davicom: Fix regulator not turned off on failed probe
- netfilter: nft_limit: avoid possible divide error in nft_limit_init
- netfilter: conntrack: do not print icmpv6 as unknown via /proc
- scsi: libsas: Reset num_scatter if libata marks qc as NODATA
- arm64: alternatives: Move length validation in alternative_{insn, endif}
- arm64: fix inline asm in load_unaligned_zeropad()
- readdir: make sure to verify directory entry for legacy interfaces too
- dm verity fec: fix misaligned RS roots IO
- HID: wacom: set EV_KEY and EV_ABS only for non-HID_GENERIC type of devices
- Input: i8042 - fix Pegatron C15B ID entry
- Input: s6sy761 - fix coordinate read bit shift
- mac80211: clear sta->fast_rx when STA removed from 4-addr VLAN
- pcnet32: Use pci_resource_len to validate PCI resource
- net: ieee802154: forbid monitor for add llsec seclevel
- net: ieee802154: stop dump llsec seclevels for monitors
- net: ieee802154: forbid monitor for add llsec devkey
- net: ieee802154: stop dump llsec devkeys for monitors
- net: ieee802154: forbid monitor for add llsec dev
- net: ieee802154: stop dump llsec devs for monitors
- net: ieee802154: stop dump llsec keys for monitors
- scsi: scsi_transport_srp: Don't block target in SRP_PORT_LOST state
- ASoC: fsl_esai: Fix TDM slot setup for I2S mode
- drm/msm: Fix a5xx/a6xx timestamps
- ARM: keystone: fix integer overflow warning
- neighbour: Disregard DEAD dst in neigh_update
- arc: kernel: Return -EFAULT if copy_to_user() fails
- lockdep: Add a missing initialization hint to the "INFO: Trying to register non-static key" message
- ARM: dts: Fix moving mmc devices with aliases for omap4 & 5
- ARM: dts: Drop duplicate sha2md5_fck to fix clk_disable race
- dmaengine: dw: Make it dependent to HAS_IOMEM
- gpio: sysfs: Obey valid_mask
- Input: nspire-keypad - enable interrupts only when opened
- f2fs: fix to avoid out-of-bounds memory access
- ext4: Reduce ext4 timestamp warnings
- livepatch: Restoring code segment permissions after stop_machine completed
- livepatch: Delete redundant variable 'flag'
- memcg: enable CONFIG_MEMCG_QOS by default
- memcg: support priority for oom
- sched: Enable qos scheduler config
- sched: Throttle qos cfs_rq when current cpu is running online task
- sched: Introduce qos scheduler for co-location
- ipv6: route: convert comma to semicolon
- ipv6/route: Add a missing check on proc_dointvec
- netfilter: xtables: avoid BUG_ON
- SUNRPC: Test whether the task is queued before grabbing the queue spinlocks
- SUNRPC: If there is no reply expected, bail early from call_decode
- SUNRPC: Fix backchannel latency metrics
- sunrpc: convert to time64_t for expiry
- sunrpc: Fix potential leaks in sunrpc_cache_unhash()
- SUNRPC: Skip zero-refcount transports
- SUNRPC: Fix buffer handling of GSS MIC without slack
- SUNRPC: Don't allow compiler optimisation of svc_xprt_release_slot()
- SUNRPC/nfs: Fix return value for nfs4_callback_compound()
- net/sunrpc: return 0 on attempt to write to "transports"
- net/sunrpc: Fix return value for sysctl sunrpc.transports
- sunrpc: raise kernel RPC channel buffer size
- sunrpc: add missing newline when printing parameter 'pool_mode' by sysfs
- xprtrdma: Fix trace point use-after-free race
- SUNRPC: Fix backchannel RPC soft lockups
- SUNRPC/cache: Fix unsafe traverse caused double-free in cache_purge
- nfsd: export upcalls must not return ESTALE when mountd is down
- sunrpc/cache: handle missing listeners better.
- xprtrdma: Fix handling of RDMA_ERROR replies
- xprtrdma: Expose transport header errors
- sunrpc: destroy rpc_inode_cachep after unregister_filesystem
- xprtrdma: fix incorrect header size calculations
- nvme: fix ns removal hang when failing to revalidate due to a transient error
- kernel/cputime: do not update cputime when cpu offline
- irqchip/gic-v3: Do not enable irqs when handling spurious interrups
- bcache: Rewrite patch to delay to invalidate cache data
- config: enable CONFIG_HW_RANDOM_HISI_V2 by default
- hwrng: add data_mode to support rand data with post process
- hwrng: add HiSilicon TRNG driver
- share_pool: Update kernel-doc comments
- share_pool: Fix warning symbol was not declared
- share_pool: Fix warning missing braces around initializer
- net/hinic: Fix null pointer dereference in hinic_physical_port_id
- kvm: debugfs: Export x86 kvm exits to vcpu_stat
- ext4: fix time overflow
- ext4: drop legacy pre-1970 encoding workaround
- fuse: fix live lock in fuse_iget()
- fuse: fix bad inode
- net/sctp: fix race condition in sctp_destroy_sock

* Sat May 08 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.188-2104.4.0.0083
- Initialize SPEC for kernel-4.19. This branch is the next branch of OpenEuler 20.03

* Sun Apr 25 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2104.21.0.0083
- bcache: Rewrite patch to delay to invalidate cache data
- nfc: Avoid endless loops caused by repeated llcp_sock_connect()
- nfc: fix memory leak in llcp_sock_connect()
- nfc: fix refcount leak in llcp_sock_connect()
- nfc: fix refcount leak in llcp_sock_bind()

* Thu Apr 22 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2104.19.0.0082
- KVM: arm64: Support the vCPU preemption check
- KVM: arm64: Add interface to support vCPU preempted check
- KVM: arm64: Support pvsched preempted via shared structure
- KVM: arm64: Implement PV_SCHED_FEATURES call
- KVM: arm64: Document PV-sched interface
- KVM: Check preempted_in_kernel for involuntary preemption
- KVM: Boost vCPUs that are delivering interrupts
- arm64/spinlock: fix a -Wunused-function warning
- locking/osq: Use optimized spinning loop for arm64
- arm/arm64: Make use of the SMCCC 1.1 wrapper
- arm/arm64: Provide a wrapper for SMCCC 1.1 calls
- KVM: Implement kvm_put_guest()
- KVM: arm/arm64: Factor out hypercall handling from PSCI code

* Thu Apr 22 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2104.18.0.0081
- bcache: Add a sample of userspace prefetch client
- bcache: Delay to invalidate cache data in writearound write
- bcache: inflight prefetch requests block overlapped normal requests
- bcache: provide a switch to bypass all IO requests
- bcache: add a framework to perform prefetch

* Thu Apr 22 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2104.17.0.0080
- net/hinic: Fix null pointer dereference in hinic_physical_port_id
- kvm: debugfs: Export x86 kvm exits to vcpu_stat
- ext4: fix time overflow
- ext4: drop legacy pre-1970 encoding workaround
- fuse: fix live lock in fuse_iget()
- fuse: fix bad inode
- net/sctp: fix race condition in sctp_destroy_sock
- config: set config hip08 prefetch default value
- ext4: do not set SB_ACTIVE in ext4_orphan_cleanup()
- RDMA/hns: add eq and cq time cfg compatibility support.
- nvme: fix incorrect behavior when BLKROSET is called by the user
- nvme-fc: fix error loop in create_hw_io_queues
- nvme-fc: Fix wrong return value in __nvme_fc_init_request()
- nvme-multipath: fix deadlock between ana_work and scan_work
- nvme: fix deadlock caused by ANA update wrong locking
- nvme-multipath: Fix memory leak with ana_log_buf
- nvme-fc: fix module unloads while lports still pending
- ipmi: remve duplicate code in __ipmi_bmc_register()
- ipmi_si_intf: Fix race in timer shutdown handling
- ipmi_ssif: fix unexpected driver unregister warning
- ipmi_si: fix unexpected driver unregister warning
- ipmi:ssif: Only unregister the platform driver if it was registered
- ipmi: Make ipmi_interfaces_srcu variable static
- ipmi: Fix return value when a message is truncated
- ipmi: Free the address list on module cleanup
- net: hns3: clear VF down state bit before request link status
- config: disable config ARM64_BOOTPARAM_HOTPLUG_CPU0 by default
- config: disable CONFIG_SATA_ZHAOXIN by default

* Thu Apr 15 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2104.16.0.0079
- config/arm64: fix kabi by disable CONFIG_NVME_MULTIPATH

* Thu Apr 15 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2104.15.0.0078
- config/x86: enable SHRINK_PAGECACHE
- arm64: Add config switch and kernel parameter for CPU0 hotplug

* Thu Apr 15 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2104.14.0.0077
- arm64: errata: enable HISILICON_ERRATUM_HIP08_RU_PREFETCH
- arm64: errata: fix kabi changed for cpu_errata
- arm64: errata: add option to disable cache readunique prefetch on 1620

* Thu Apr 15 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2104.13.0.0076
- firewire: nosy: Fix a use-after-free bug in nosy_ioctl()

* Thu Apr 15 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2104.12.0.0075
- iommu/arm-smmu-v3: Reduce contention during command-queue insertion
- iommu/arm-smmu-v3: Operate directly on low-level queue where possible
- iommu/arm-smmu-v3: Move low-level queue fields out of arm_smmu_queue
- iommu/arm-smmu-v3: Drop unused 'q' argument from Q_OVF macro
- iommu/arm-smmu-v3: Separate s/w and h/w views of prod and cons indexes
- iommu/io-pgtable: Rename iommu_gather_ops to iommu_flush_ops
- iommu/io-pgtable-arm: Remove redundant call to io_pgtable_tlb_sync()
- iommu/arm-smmu-v3: Increase maximum size of queues
- iommu/io-pgtable: Replace IO_PGTABLE_QUIRK_NO_DMA with specific flag
- iommu: Allow io-pgtable to be used outside of drivers/iommu/
- iommu: Fix flush_tlb_all typo
- iommu: Change tlb_range_add to iotlb_range_add and tlb_sync to iotlb_sync

* Thu Apr 15 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2104.11.0.0074
- io_uring: order refnode recycling
- io_uring: get an active ref_node from files_data
- io_uring: fix racy req->flags modification
- io_uring: defer file table grabbing request cleanup for locked requests
- io_uring: batch put_task_struct()
- tasks: add put_task_struct_many()
- io_uring: fix missing io_queue_linked_timeout()
- io_uring: deduplicate io_grab_files() calls
- io_uring: don't do opcode prep twice
- io_uring: don't open-code recv kbuf managment
- io_uring: extract io_put_kbuf() helper
- io_uring: simplify file ref tracking in submission state
- io_uring: move BUFFER_SELECT check into *recv[msg]
- io_uring: free selected-bufs if error'ed
- io_uring: don't forget cflags in io_recv()
- io_uring: remove extra checks in send/recv
- io_uring: indent left {send,recv}[msg]()
- io-wq: update hash bits
- io_uring: get rid of atomic FAA for cq_timeouts
- io_uring: consolidate *_check_overflow accounting
- io_uring: de-unionise io_kiocb
- io_uring: follow **iovec idiom in io_import_iovec
- io_uring: mark ->work uninitialised after cleanup
- io_uring/io-wq: move RLIMIT_FSIZE to io-wq
- io_uring: alloc ->io in io_req_defer_prep()
- io_uring: inline io_req_work_grab_env()
- io_uring: fix racy IOPOLL completions
- io_uring: always let io_iopoll_complete() complete polled io
- io_uring: don't recurse on tsk->sighand->siglock with signalfd
- io_uring: don't use poll handler if file can't be nonblocking read/written
- io_uring: fix linked deferred ->files cancellation
- io_uring: fix cancel of deferred reqs with ->files
- io_uring: flush timeouts that should already have expired
- io_uring: find and cancel head link async work on files exit
- io_uring: always plug for any number of IOs
- io_uring: fix recursive completion locking on oveflow flush
- io_uring: enable lookup of links holding inflight files
- io_uring: place cflags into completion data
- io_uring: remove sequence from io_kiocb
- io_uring: use non-intrusive list for defer
- io_uring: remove init for unused list
- io_uring: add req->timeout.list
- io_uring: use completion list for CQ overflow
- io_uring: use inflight_entry list for iopoll'ing
- io_uring: rename ctx->poll into ctx->iopoll
- io_uring: share completion list w/ per-op space
- io_uring: get rid of __req_need_defer()
- io_uring: only call kfree() for a non-zero pointer
- io_uring: fix a use after free in io_async_task_func()
- io_uring: remove nr_events arg from iopoll_check()
- io_uring: don't delay iopoll'ed req completion
- io_uring: fix lost cqe->flags
- io_uring: keep queue_sqe()'s fail path separately
- io_uring: fix mis-refcounting linked timeouts
- io_uring: use new io_req_task_work_add() helper throughout
- io_uring: abstract out task work running
- io_uring: do grab_env() just before punting
- io_uring: factor out grab_env() from defer_prep()
- io_uring: do init work in grab_env()
- io_uring: don't pass def into io_req_work_grab_env
- io_uring: fix function args for !CONFIG_NET
- io_uring: set @poll->file after @poll init
- io_uring: remove REQ_F_MUST_PUNT
- io_uring: remove setting REQ_F_MUST_PUNT in rw
- io_uring: optimise io_req_find_next() fast check
- io_uring: kill REQ_F_TIMEOUT_NOSEQ
- io_uring: kill REQ_F_TIMEOUT
- io_uring: replace find_next() out param with ret
- io_uring: fix missing io_grab_files()
- io_uring: don't mark link's head for_async
- io_uring: fix feeding io-wq with uninit reqs
- io_uring: fix punting req w/o grabbed env
- io_uring: fix req->work corruption
- io_uring: simplify io_async_task_func()
- io_uring: fix NULL mm in io_poll_task_func()
- io_uring: use task_work for links if possible
- io_uring: do task_work_run() during iopoll
- io_uring: clean up req->result setting by rw
- io_uring: cosmetic changes for batch free
- io_uring: batch-free linked requests as well
- io_uring: dismantle req early and remove need_iter
- io_uring: remove inflight batching in free_many()
- io_uring: fix refs underflow in io_iopoll_queue()
- io_uring: enable READ/WRITE to use deferred completions
- io_uring: pass in completion state to appropriate issue side handlers
- io_uring: pass down completion state on the issue side
- io_uring: add 'io_comp_state' to struct io_submit_state
- io_uring: provide generic io_req_complete() helper
- io_uring: add missing REQ_F_COMP_LOCKED for nested requests
- io_uring: clean up io_kill_linked_timeout() locking
- io_uring: deduplicate freeing linked timeouts
- io_uring: kill REQ_F_LINK_NEXT
- io_uring: fix stalled deferred requests
- io_uring: add IORING_OP_OPENAT2 for compatablity
- arm64: fix kabi with io_uring interface
- x86: fix kabi with io_uring interface
- io_uring: fix provide_buffers sign extension
- io_uring: ignore double poll add on the same waitqueue head
- io_uring: fix SQPOLL IORING_OP_CLOSE cancelation state
- io_uring: make ctx cancel on exit targeted to actual ctx
- io_uring: fix error path cleanup in io_sqe_files_register()
- io_uring: ensure open/openat2 name is cleaned on cancelation
- io_uring: sanitize double poll handling
- io_uring: fail poll arm on queue proc failure
- io_uring: allow non-fixed files with SQPOLL
- io_uring: ensure consistent view of original task ->mm from SQPOLL
- io_uring: stash ctx task reference for SQPOLL
- io_uring: don't miscount pinned memory
- io_uring: don't burn CPU for iopoll on exit
- io_uring: fix imbalanced sqo_mm accounting
- io_uring: return locked and pinned page accounting
- io_uring: fix missing ->mm on exit
- io_uring: fix NULL-mm for linked reqs
- io_uring: account locked memory before potential error case
- io_uring: don't touch 'ctx' after installing file descriptor
- io_uring: remove dead 'ctx' argument and move forward declaration
- io_uring: fix recvmsg setup with compat buf-select
- io_uring: fix shift-out-of-bounds when round up cq size
- io_uring: round-up cq size before comparing with rounded sq size
- io_uring: use type appropriate io_kiocb handler for double poll
- io_uring: fix double poll mask init
- io_uring: Fix sizeof() mismatch
- io_uring: keep a pointer ref_node in file_data
- io_uring: refactor *files_register()'s error paths
- io_uring: clean file_data access in files_register
- io-wq: fix use-after-free in io_wq_worker_running
- io_uring: fix potential ABBA deadlock in ->show_fdinfo()
- io_uring: always delete double poll wait entry on match
- io-wq: fix hang after cancelling pending hashed work
- io_uring: fix racy overflow count reporting
- io_uring: partially inline io_iopoll_getevents()
- io_uring: briefly loose locks while reaping events
- io_uring: fix stopping iopoll'ing too early
- io_uring: fix potential use after free on fallback request free
- io_uring: set table->files[i] to NULL when io_sqe_file_register failed
- io_uring: fix removing the wrong file in __io_sqe_files_update()
- io_uring: fix IOPOLL -EAGAIN retries
- io_uring: clear req->result on IOPOLL re-issue
- io_uring: hold 'ctx' reference around task_work queue + execute
- io_uring: use TWA_SIGNAL for task_work uncondtionally
- io_uring: Fix NULL pointer dereference in loop_rw_iter()
- io_uring: clear IORING_SQ_NEED_WAKEUP after executing task works
- io_uring: add a helper for async rw iovec prep
- io_uring: simplify io_req_map_rw()
- io_uring: extract io_sendmsg_copy_hdr()
- io_uring: use more specific type in rcv/snd msg cp
- io_uring: rename sr->msg into umsg
- io_uring: fix sq array offset calculation
- io_uring: fix lockup in io_fail_links()
- io_uring: fix ->work corruption with poll_add
- io_uring: missed req_init_async() for IOSQE_ASYNC
- io_uring: always allow drain/link/hardlink/async sqe flags
- io_uring: ensure double poll additions work with both request types
- io_uring: fix recvmsg memory leak with buffer selection
- io_uring: fix not initialised work->flags
- io_uring: fix missing msg_name assignment
- io_uring: account user memory freed when exit has been queued
- io_uring: fix memleak in io_sqe_files_register()
- io_uring: fix memleak in __io_sqe_files_update()
- io_uring: export cq overflow status to userspace
- io_uring: fix regression with always ignoring signals in io_cqring_wait()
- io_uring: use signal based task_work running
- task_work: teach task_work_add() to do signal_wake_up()
- io_uring: fix current->mm NULL dereference on exit
- io_uring: fix hanging iopoll in case of -EAGAIN
- io_uring: fix io_sq_thread no schedule when busy
- io-wq: return next work from ->do_work() directly
- io-wq: compact io-wq flags numbers
- io_uring: separate reporting of ring pages from registered pages
- io_uring: report pinned memory usage
- io_uring: rename ctx->account_mem field
- io_uring: add wrappers for memory accounting
- io_uring: use EPOLLEXCLUSIVE flag to aoid thundering herd type behavior
- io_uring: change the poll type to be 32-bits
- io_uring: fix possible race condition against REQ_F_NEED_CLEANUP
- io_uring: reap poll completions while waiting for refs to drop on exit
- io_uring: acquire 'mm' for task_work for SQPOLL
- io_uring: add memory barrier to synchronize io_kiocb's result and iopoll_completed
- io_uring: don't fail links for EAGAIN error in IOPOLL mode
- io_uring: cancel by ->task not pid
- io_uring: lazy get task
- io_uring: batch cancel in io_uring_cancel_files()
- io_uring: cancel all task's requests on exit
- io-wq: add an option to cancel all matched reqs
- io-wq: reorder cancellation pending -> running
- io_uring: fix lazy work init
- io_uring: fix io_kiocb.flags modification race in IOPOLL mode
- io_uring: check file O_NONBLOCK state for accept
- io_uring: avoid unnecessary io_wq_work copy for fast poll feature
- io_uring: avoid whole io_wq_work copy for requests completed inline
- io_uring: allow O_NONBLOCK async retry
- io_wq: add per-wq work handler instead of per work
- io_uring: don't arm a timeout through work.func
- io_uring: remove custom ->func handlers
- io_uring: don't derive close state from ->func
- io_uring: use kvfree() in io_sqe_buffer_register()
- io_uring: validate the full range of provided buffers for access
- io_uring: re-set iov base/len for buffer select retry
- io_uring: move send/recv IOPOLL check into prep
- io_uring: fix {SQ,IO}POLL with unsupported opcodes
- io_uring: disallow close of ring itself
- io_uring: fix overflowed reqs cancellation
- io_uring: off timeouts based only on completions
- io_uring: move timeouts flushing to a helper
- statx: hide interfaces no longer used by io_uring
- io_uring: call statx directly
- statx: allow system call to be invoked from io_uring
- io_uring: add io_statx structure
- io_uring: get rid of manual punting in io_close
- io_uring: separate DRAIN flushing into a cold path
- io_uring: don't re-read sqe->off in timeout_prep()
- io_uring: simplify io_timeout locking
- io_uring: fix flush req->refs underflow
- io_uring: don't submit sqes when ctx->refs is dying
- io_uring: async task poll trigger cleanup
- io_uring: add tee(2) support
- splice: export do_tee()
- io_uring: don't repeat valid flag list
- io_uring: rename io_file_put()
- io_uring: remove req->needs_fixed_files
- io_uring: cleanup io_poll_remove_one() logic
- io_uring: file registration list and lock optimization
- io_uring: add IORING_CQ_EVENTFD_DISABLED to the CQ ring flags
- io_uring: add 'cq_flags' field for the CQ ring
- io_uring: allow POLL_ADD with double poll_wait() users
- io_uring: batch reap of dead file registrations
- io_uring: name sq thread and ref completions
- io_uring: remove duplicate semicolon at the end of line
- io_uring: remove obsolete 'state' parameter
- io_uring: remove 'fd is io_uring' from close path
- io_uring: reset -EBUSY error when io sq thread is waken up
- io_uring: don't add non-IO requests to iopoll pending list
- io_uring: don't use kiocb.private to store buf_index
- io_uring: cancel work if task_work_add() fails
- io_uring: remove dead check in io_splice()
- io_uring: fix FORCE_ASYNC req preparation
- io_uring: don't prepare DRAIN reqs twice
- io_uring: initialize ctx->sqo_wait earlier
- io_uring: polled fixed file must go through free iteration
- io_uring: fix zero len do_splice()
- io_uring: don't use 'fd' for openat/openat2/statx
- splice: move f_mode checks to do_{splice,tee}()
- io_uring: handle -EFAULT properly in io_uring_setup()
- io_uring: fix mismatched finish_wait() calls in io_uring_cancel_files()
- io_uring: punt splice async because of inode mutex
- io_uring: check non-sync defer_list carefully
- io_uring: fix extra put in sync_file_range()
- io_uring: use cond_resched() in io_ring_ctx_wait_and_kill()
- io_uring: use proper references for fallback_req locking
- io_uring: only force async punt if poll based retry can't handle it
- io_uring: enable poll retry for any file with ->read_iter / ->write_iter
- io_uring: statx must grab the file table for valid fd
- io_uring: only restore req->work for req that needs do completion
- io_uring: don't count rqs failed after current one
- io_uring: kill already cached timeout.seq_offset
- io_uring: fix cached_sq_head in io_timeout()
- io_uring: only post events in io_poll_remove_all() if we completed some
- io_uring: io_async_task_func() should check and honor cancelation
- io_uring: check for need to re-wait in polled async handling
- io_uring: correct O_NONBLOCK check for splice punt
- io_uring: restore req->work when canceling poll request
- io_uring: move all request init code in one place
- io_uring: keep all sqe->flags in req->flags
- io_uring: early submission req fail code
- io_uring: track mm through current->mm
- io_uring: remove obsolete @mm_fault
- io_uring: punt final io_ring_ctx wait-and-free to workqueue
- io_uring: fix fs cleanup on cqe overflow
- io_uring: don't read user-shared sqe flags twice
- io_uring: remove req init from io_get_req()
- io_uring: alloc req only after getting sqe
- io_uring: simplify io_get_sqring
- io_uring: do not always copy iovec in io_req_map_rw()
- io_uring: ensure openat sets O_LARGEFILE if needed
- io_uring: initialize fixed_file_data lock
- io_uring: remove redundant variable pointer nxt and io_wq_assign_next call
- io_uring: fix ctx refcounting in io_submit_sqes()
- io_uring: process requests completed with -EAGAIN on poll list
- io_uring: remove bogus RLIMIT_NOFILE check in file registration
- io_uring: use io-wq manager as backup task if task is exiting
- io_uring: grab task reference for poll requests
- io_uring: retry poll if we got woken with non-matching mask
- io_uring: add missing finish_wait() in io_sq_thread()
- io_uring: refactor file register/unregister/update handling
- io_uring: cleanup io_alloc_async_ctx()
- io_uring: fix missing 'return' in comment
- io-wq: handle hashed writes in chains
- io-uring: drop 'free_pfile' in struct io_file_put
- io-uring: drop completion when removing file
- io_uring: Fix ->data corruption on re-enqueue
- io-wq: close cancel gap for hashed linked work
- io_uring: make spdxcheck.py happy
- io_uring: honor original task RLIMIT_FSIZE
- io-wq: hash dependent work
- io-wq: split hashing and enqueueing
- io-wq: don't resched if there is no work
- io-wq: remove duplicated cancel code
- io_uring: fix truncated async read/readv and write/writev retry
- io_uring: dual license io_uring.h uapi header
- io_uring: io_uring_enter(2) don't poll while SETUP_IOPOLL|SETUP_SQPOLL enabled
- io_uring: Fix unused function warnings
- io_uring: add end-of-bits marker and build time verify it
- io_uring: provide means of removing buffers
- io_uring: add IOSQE_BUFFER_SELECT support for IORING_OP_RECVMSG
- net: abstract out normal and compat msghdr import
- io_uring: add IOSQE_BUFFER_SELECT support for IORING_OP_READV
- io_uring: support buffer selection for OP_READ and OP_RECV
- io_uring: add IORING_OP_PROVIDE_BUFFERS
- io_uring: buffer registration infrastructure
- io_uring/io-wq: forward submission ref to async
- io-wq: optimise out *next_work() double lock
- io-wq: optimise locking in io_worker_handle_work()
- io-wq: shuffle io_worker_handle_work() code
- io_uring: get next work with submission ref drop
- io_uring: remove @nxt from handlers
- io_uring: make submission ref putting consistent
- io_uring: clean up io_close
- io_uring: Ensure mask is initialized in io_arm_poll_handler
- io_uring: remove io_prep_next_work()
- io_uring: remove extra nxt check after punt
- io_uring: use poll driven retry for files that support it
- io_uring: mark requests that we can do poll async in io_op_defs
- io_uring: add per-task callback handler
- io_uring: store io_kiocb in wait->private
- task_work_run: don't take ->pi_lock unconditionally
- io-wq: use BIT for ulong hash
- io_uring: remove IO_WQ_WORK_CB
- io-wq: remove unused IO_WQ_WORK_HAS_MM
- io_uring: extract kmsg copy helper
- io_uring: clean io_poll_complete
- io_uring: add splice(2) support
- io_uring: add interface for getting files
- splice: make do_splice public
- io_uring: remove req->in_async
- io_uring: don't do full *prep_worker() from io-wq
- io_uring: don't call work.func from sync ctx
- io_uring: io_accept() should hold on to submit reference on retry
- io_uring: consider any io_read/write -EAGAIN as final
- io_uring: make sure accept honor rlimit nofile
- io_uring: make sure openat/openat2 honor rlimit nofile
- io_uring: NULL-deref for IOSQE_{ASYNC,DRAIN}
- io_uring: ensure RCU callback ordering with rcu_barrier()
- io_uring: fix lockup with timeouts
- io_uring: free fixed_file_data after RCU grace period
- io-wq: remove io_wq_flush and IO_WQ_WORK_INTERNAL
- io-wq: fix IO_WQ_WORK_NO_CANCEL cancellation
- io_uring: fix 32-bit compatability with sendmsg/recvmsg
- io_uring: define and set show_fdinfo only if procfs is enabled
- io_uring: drop file set ref put/get on switch
- io_uring: import_single_range() returns 0/-ERROR
- io_uring: pick up link work on submit reference drop
- io-wq: ensure work->task_pid is cleared on init
- io-wq: remove spin-for-work optimization
- io_uring: fix poll_list race for SETUP_IOPOLL|SETUP_SQPOLL
- io_uring: fix personality idr leak
- io_uring: handle multiple personalities in link chains
- io_uring: fix __io_iopoll_check deadlock in io_sq_thread
- io_uring: prevent sq_thread from spinning when it should stop
- io_uring: fix use-after-free by io_cleanup_req()
- io_uring: remove unnecessary NULL checks
- io_uring: add missing io_req_cancelled()
- io_uring: prune request from overflow list on flush
- io-wq: don't call kXalloc_node() with non-online node
- io_uring: retain sockaddr_storage across send/recvmsg async punt
- io_uring: cancel pending async work if task exits
- io-wq: add io_wq_cancel_pid() to cancel based on a specific pid
- io-wq: make io_wqe_cancel_work() take a match handler
- io_uring: fix openat/statx's filename leak
- io_uring: fix double prep iovec leak
- io_uring: fix async close() with f_op->flush()
- io_uring: allow AT_FDCWD for non-file openat/openat2/statx
- io_uring: grab ->fs as part of async preparation
- io-wq: add support for inheriting ->fs
- io_uring: retry raw bdev writes if we hit -EOPNOTSUPP
- io_uring: add cleanup for openat()/statx()
- io_uring: fix iovec leaks
- io_uring: remove unused struct io_async_open
- io_uring: flush overflowed CQ events in the io_uring_poll()
- io_uring: statx/openat/openat2 don't support fixed files
- io_uring: fix deferred req iovec leak
- io_uring: fix 1-bit bitfields to be unsigned
- io_uring: get rid of delayed mm check
- io_uring: cleanup fixed file data table references
- io_uring: spin for sq thread to idle on shutdown
- io_uring: put the flag changing code in the same spot
- io_uring: iterate req cache backwards
- io_uring: punt even fadvise() WILLNEED to async context
- io_uring: fix sporadic double CQE entry for close
- io_uring: remove extra ->file check
- io_uring: don't map read/write iovec potentially twice
- io_uring: use the proper helpers for io_send/recv
- io_uring: prevent potential eventfd recursion on poll
- io_uring: add BUILD_BUG_ON() to assert the layout of struct io_uring_sqe
- io_uring: add ->show_fdinfo() for the io_uring file descriptor
- io_uring: add support for epoll_ctl(2)
- eventpoll: support non-blocking do_epoll_ctl() calls
- eventpoll: abstract out epoll_ctl() handler
- io_uring: fix linked command file table usage
- io_uring: support using a registered personality for commands
- io_uring: allow registering credentials
- io_uring: add io-wq workqueue sharing
- io-wq: allow grabbing existing io-wq
- io_uring/io-wq: don't use static creds/mm assignments
- io-wq: make the io_wq ref counted
- io_uring: fix refcounting with batched allocations at OOM
- io_uring: add comment for drain_next
- io_uring: don't attempt to copy iovec for READ/WRITE
- io_uring: honor IOSQE_ASYNC for linked reqs
- io_uring: prep req when do IOSQE_ASYNC
- io_uring: use labeled array init in io_op_defs
- io_uring: optimise sqe-to-req flags translation
- io_uring: remove REQ_F_IO_DRAINED
- io_uring: file switch work needs to get flushed on exit
- io_uring: hide uring_fd in ctx
- io_uring: remove extra check in __io_commit_cqring
- io_uring: optimise use of ctx->drain_next
- io_uring: add support for probing opcodes
- io_uring: account fixed file references correctly in batch
- io_uring: add opcode to issue trace event
- io_uring: remove 'fname' from io_open structure
- io_uring: enable option to only trigger eventfd for async completions
- io_uring: change io_ring_ctx bool fields into bit fields
- io_uring: file set registration should use interruptible waits
- io_uring: Remove unnecessary null check
- io_uring: add support for send(2) and recv(2)
- io_uring: remove extra io_wq_current_is_worker()
- io_uring: optimise commit_sqring() for common case
- io_uring: optimise head checks in io_get_sqring()
- io_uring: clamp to_submit in io_submit_sqes()
- io_uring: add support for IORING_SETUP_CLAMP
- io_uring: extend batch freeing to cover more cases
- io_uring: wrap multi-req freeing in struct req_batch
- io_uring: batch getting pcpu references
- pcpu_ref: add percpu_ref_tryget_many()
- io_uring: add IORING_OP_MADVISE
- mm: make do_madvise() available internally
- io_uring: add IORING_OP_FADVISE
- io_uring: allow use of offset == -1 to mean file position
- io_uring: add non-vectored read/write commands
- io_uring: improve poll completion performance
- io_uring: split overflow state into SQ and CQ side
- io_uring: add lookup table for various opcode needs
- io_uring: remove two unnecessary function declarations
- io_uring: move *queue_link_head() from common path
- io_uring: rename prev to head
- io_uring: add IOSQE_ASYNC
- io-wq: support concurrent non-blocking work
- io_uring: add support for IORING_OP_STATX
- fs: make two stat prep helpers available
- io_uring: avoid ring quiesce for fixed file set unregister and update
- io_uring: add support for IORING_OP_CLOSE
- io-wq: add support for uncancellable work
- percpu-refcount: Introduce percpu_ref_resurrect()
- percpu_ref: introduce PERCPU_REF_ALLOW_REINIT flag
- fs: make filename_lookup available externally
- fs: introduce __close_fd_get_file to support IORING_OP_CLOSE for io_uring
- io_uring: add support for IORING_OP_OPENAT
- fs: make build_open_flags() available internally
- io_uring: add support for fallocate()
- io_uring: don't cancel all work on process exit
- Revert "io_uring: only allow submit from owning task"
- io_uring: fix compat for IORING_REGISTER_FILES_UPDATE
- io_uring: only allow submit from owning task
- io_uring: ensure workqueue offload grabs ring mutex for poll list
- io_uring: clear req->result always before issuing a read/write request
- io_uring: be consistent in assigning next work from handler
- io-wq: cancel work if we fail getting a mm reference
- io_uring: don't setup async context for read/write fixed
- io_uring: remove punt of short reads to async context
- io-wq: add cond_resched() to worker thread
- io-wq: remove unused busy list from io_sqe
- io_uring: pass in 'sqe' to the prep handlers
- io_uring: standardize the prep methods
- io_uring: read 'count' for IORING_OP_TIMEOUT in prep handler
- io_uring: move all prep state for IORING_OP_{SEND,RECV}_MGS to prep handler
- io_uring: move all prep state for IORING_OP_CONNECT to prep handler
- io_uring: add and use struct io_rw for read/writes
- io_uring: use u64_to_user_ptr() consistently
- io_uring: io_wq_submit_work() should not touch req->rw
- io_uring: don't wait when under-submitting
- io_uring: warn about unhandled opcode
- io_uring: read opcode and user_data from SQE exactly once
- io_uring: make IORING_OP_TIMEOUT_REMOVE deferrable
- io_uring: make IORING_OP_CANCEL_ASYNC deferrable
- io_uring: make IORING_POLL_ADD and IORING_POLL_REMOVE deferrable
- io_uring: make HARDLINK imply LINK
- io_uring: any deferred command must have stable sqe data
- io_uring: remove 'sqe' parameter to the OP helpers that take it
- io_uring: fix pre-prepped issue with force_nonblock == true
- io-wq: re-add io_wq_current_is_worker()
- io_uring: fix sporadic -EFAULT from IORING_OP_RECVMSG
- io_uring: fix stale comment and a few typos
- io_uring: ensure we return -EINVAL on unknown opcode
- io_uring: add sockets to list of files that support non-blocking issue
- io_uring: only hash regular files for async work execution
- io_uring: run next sqe inline if possible
- io_uring: don't dynamically allocate poll data
- io_uring: deferred send/recvmsg should assign iov
- io_uring: sqthread should grab ctx->uring_lock for submissions
- io-wq: briefly spin for new work after finishing work
- io-wq: remove worker->wait waitqueue
- io_uring: allow unbreakable links
- io_uring: fix a typo in a comment
- io_uring: hook all linked requests via link_list
- io_uring: fix error handling in io_queue_link_head
- io_uring: use hash table for poll command lookups
- io-wq: clear node->next on list deletion
- io_uring: ensure deferred timeouts copy necessary data
- io_uring: allow IO_SQE_* flags on IORING_OP_TIMEOUT
- io_uring: handle connect -EINPROGRESS like -EAGAIN
- io_uring: remove io_wq_current_is_worker
- io_uring: remove parameter ctx of io_submit_state_start
- io_uring: mark us with IORING_FEAT_SUBMIT_STABLE
- io_uring: ensure async punted connect requests copy data
- io_uring: ensure async punted sendmsg/recvmsg requests copy data
- net: disallow ancillary data for __sys_{send,recv}msg_file()
- net: separate out the msghdr copy from ___sys_{send,recv}msg()
- io_uring: ensure async punted read/write requests copy iovec
- io_uring: add general async offload context
- io_uring: transform send/recvmsg() -ERESTARTSYS to -EINTR
- io_uring: use current task creds instead of allocating a new one
- io_uring: fix missing kmap() declaration on powerpc
- io_uring: add mapping support for NOMMU archs
- io_uring: make poll->wait dynamically allocated
- io-wq: shrink io_wq_work a bit
- io-wq: fix handling of NUMA node IDs
- io_uring: use kzalloc instead of kcalloc for single-element allocations
- io_uring: cleanup io_import_fixed()
- io_uring: inline struct sqe_submit
- io_uring: store timeout's sqe->off in proper place
- io_uring: remove superfluous check for sqe->off in io_accept()
- io_uring: async workers should inherit the user creds
- io-wq: have io_wq_create() take a 'data' argument
- io_uring: fix dead-hung for non-iter fixed rw
- io_uring: add support for IORING_OP_CONNECT
- net: add __sys_connect_file() helper
- io_uring: only return -EBUSY for submit on non-flushed backlog
- io_uring: only !null ptr to io_issue_sqe()
- io_uring: simplify io_req_link_next()
- io_uring: pass only !null to io_req_find_next()
- io_uring: remove io_free_req_find_next()
- io_uring: add likely/unlikely in io_get_sqring()
- io_uring: rename __io_submit_sqe()
- io_uring: improve trace_io_uring_defer() trace point
- io_uring: drain next sqe instead of shadowing
- io_uring: close lookup gap for dependent next work
- io_uring: allow finding next link independent of req reference count
- io_uring: io_allocate_scq_urings() should return a sane state
- io_uring: Always REQ_F_FREE_SQE for allocated sqe
- io_uring: io_fail_links() should only consider first linked timeout
- io_uring: Fix leaking linked timeouts
- io_uring: remove redundant check
- io_uring: break links for failed defer
- io-wq: remove extra space characters
- io-wq: wait for io_wq_create() to setup necessary workers
- io_uring: request cancellations should break links
- io_uring: correct poll cancel and linked timeout expiration completion
- io_uring: remove dead REQ_F_SEQ_PREV flag
- io_uring: fix sequencing issues with linked timeouts
- io_uring: make req->timeout be dynamically allocated
- io_uring: make io_double_put_req() use normal completion path
- io_uring: cleanup return values from the queueing functions
- io_uring: io_async_cancel() should pass in 'nxt' request pointer
- io_uring: make POLL_ADD/POLL_REMOVE scale better
- io-wq: remove now redundant struct io_wq_nulls_list
- io_uring: Fix getting file for non-fd opcodes
- io_uring: introduce req_need_defer()
- io_uring: clean up io_uring_cancel_files()
- io-wq: ensure free/busy list browsing see all items
- io_uring: ensure registered buffer import returns the IO length
- io-wq: ensure we have a stable view of ->cur_work for cancellations
- io_wq: add get/put_work handlers to io_wq_create()
- io_uring: Fix getting file for timeout
- io_uring: check for validity of ->rings in teardown
- io_uring: fix potential deadlock in io_poll_wake()
- io_uring: use correct "is IO worker" helper
- io_uring: make timeout sequence == 0 mean no sequence
- io_uring: fix -ENOENT issue with linked timer with short timeout
- io_uring: don't do flush cancel under inflight_lock
- io_uring: flag SQPOLL busy condition to userspace
- io_uring: make ASYNC_CANCEL work with poll and timeout
- io_uring: provide fallback request for OOM situations
- io_uring: convert accept4() -ERESTARTSYS into -EINTR
- io_uring: fix error clear of ->file_table in io_sqe_files_register()
- io_uring: separate the io_free_req and io_free_req_find_next interface
- io_uring: keep io_put_req only responsible for release and put req
- io_uring: remove passed in 'ctx' function parameter ctx if possible
- io_uring: reduce/pack size of io_ring_ctx
- io_uring: properly mark async work as bounded vs unbounded
- io-wq: add support for bounded vs unbunded work
- io-wq: io_wqe_run_queue() doesn't need to use list_empty_careful()
- io_uring: add support for backlogged CQ ring
- io_uring: pass in io_kiocb to fill/add CQ handlers
- io_uring: make io_cqring_events() take 'ctx' as argument
- io_uring: add support for linked SQE timeouts
- io_uring: abstract out io_async_cancel_one() helper
- io_uring: use inlined struct sqe_submit
- io_uring: Use submit info inlined into req
- io_uring: allocate io_kiocb upfront
- io_uring: io_queue_link*() right after submit
- io_uring: Merge io_submit_sqes and io_ring_submit
- io_uring: kill dead REQ_F_LINK_DONE flag
- io_uring: fixup a few spots where link failure isn't flagged
- io_uring: enable optimized link handling for IORING_OP_POLL_ADD
- io-wq: use proper nesting IRQ disabling spinlocks for cancel
- io_uring: add completion trace event
- io-wq: use kfree_rcu() to simplify the code
- io_uring: set -EINTR directly when a signal wakes up in io_cqring_wait
- io_uring: support for generic async request cancel
- io_uring: ensure we clear io_kiocb->result before each issue
- io_uring: io_wq_create() returns an error pointer, not NULL
- io_uring: fix race with canceling timeouts
- io_uring: support for larger fixed file sets
- io_uring: protect fixed file indexing with array_index_nospec()
- io_uring: add support for IORING_OP_ACCEPT
- net: add __sys_accept4_file() helper
- io_uring: io_uring: add support for async work inheriting files
- io_uring: replace workqueue usage with io-wq
- io-wq: small threadpool implementation for io_uring
- sched/core, workqueues: Distangle worker accounting from rq lock
- sched: Remove stale PF_MUTEX_TESTER bit
- io_uring: Fix mm_fault with READ/WRITE_FIXED
- io_uring: remove index from sqe_submit
- io_uring: add set of tracing events
- io_uring: add support for canceling timeout requests
- io_uring: add support for absolute timeouts
- io_uring: replace s->needs_lock with s->in_async
- io_uring: allow application controlled CQ ring size
- io_uring: add support for IORING_REGISTER_FILES_UPDATE
- io_uring: allow sparse fixed file sets
- io_uring: run dependent links inline if possible
- io_uring: don't touch ctx in setup after ring fd install
- io_uring: Fix leaked shadow_req
- io_uring: fix bad inflight accounting for SETUP_IOPOLL|SETUP_SQTHREAD
- io_uring: used cached copies of sq->dropped and cq->overflow
- io_uring: Fix race for sqes with userspace
- io_uring: Fix broken links with offloading
- io_uring: Fix corrupted user_data
- io_uring: correct timeout req sequence when inserting a new entry
- io_uring : correct timeout req sequence when waiting timeout
- io_uring: revert "io_uring: optimize submit_and_wait API"
- io_uring: fix logic error in io_timeout
- io_uring: fix up O_NONBLOCK handling for sockets
- io_uring: consider the overflow of sequence for timeout req
- io_uring: fix sequence logic for timeout requests
- io_uring: only flush workqueues on fileset removal
- io_uring: remove wait loop spurious wakeups
- io_uring: fix reversed nonblock flag for link submission
- io_uring: use __kernel_timespec in timeout ABI
- io_uring: make CQ ring wakeups be more efficient
- io_uring: compare cached_cq_tail with cq.head in_io_uring_poll
- io_uring: correctly handle non ->{read,write}_iter() file_operations
- io_uring: IORING_OP_TIMEOUT support
- io_uring: use cond_resched() in sqthread
- io_uring: fix potential crash issue due to io_get_req failure
- io_uring: ensure poll commands clear ->sqe
- io_uring: fix use-after-free of shadow_req
- io_uring: use kmemdup instead of kmalloc and memcpy
- io_uring: increase IORING_MAX_ENTRIES to 32K
- io_uring: make sqpoll wakeup possible with getevents
- io_uring: extend async work merging
- io_uring: limit parallelism of buffered writes
- io_uring: add io_queue_async_work() helper
- io_uring: optimize submit_and_wait API
- io_uring: add support for link with drain
- io_uring: fix wrong sequence setting logic
- io_uring: expose single mmap capability
- io_uring: allocate the two rings together
- io_uring: add need_resched() check in inner poll loop
- io_uring: don't enter poll loop if we have CQEs pending
- io_uring: fix potential hang with polled IO
- io_uring: fix an issue when IOSQE_IO_LINK is inserted into defer list
- io_uring: fix manual setup of iov_iter for fixed buffers
- io_uring: fix KASAN use after free in io_sq_wq_submit_work
- io_uring: ensure ->list is initialized for poll commands
- io_uring: track io length in async_list based on bytes
- io_uring: don't use iov_iter_advance() for fixed buffers
- io_uring: add a memory barrier before atomic_read
- io_uring: fix counter inc/dec mismatch in async_list
- io_uring: fix the sequence comparison in io_sequence_defer
- io_uring: fix io_sq_thread_stop running in front of io_sq_thread
- io_uring: add support for recvmsg()
- io_uring: add support for sendmsg()
- io_uring: add support for sqe links
- io_uring: punt short reads to async context
- uio: make import_iovec()/compat_import_iovec() return bytes on success
- io_uring: ensure req->file is cleared on allocation
- io_uring: fix memory leak of UNIX domain socket inode
- io_uring: Fix __io_uring_register() false success
- tools/io_uring: sync with liburing
- tools/io_uring: fix Makefile for pthread library link
- select: shift restore_saved_sigmask_unless() into poll_select_copy_remaining()
- select: change do_poll() to return -ERESTARTNOHAND rather than -EINTR
- signal: simplify set_user_sigmask/restore_user_sigmask
- signal: remove the wrong signal_pending() check in restore_user_sigmask()
- io_uring: use wait_event_interruptible for cq_wait conditional wait
- io_uring: adjust smp_rmb inside io_cqring_events
- io_uring: fix infinite wait in khread_park() on io_finish_async()
- io_uring: remove 'ev_flags' argument
- io_uring: fix failure to verify SQ_AFF cpu
- io_uring: fix race condition reading SQE data
- io_uring: use cpu_online() to check p->sq_thread_cpu instead of cpu_possible()
- io_uring: fix shadowed variable ret return code being not checked
- req->error only used for iopoll
- io_uring: add support for eventfd notifications
- io_uring: add support for IORING_OP_SYNC_FILE_RANGE
- io_uring: add support for marking commands as draining
- fs: add sync_file_range() helper
- io_uring: avoid page allocation warnings
- io_uring: drop req submit reference always in async punt
- io_uring: free allocated io_memory once
- io_uring: fix SQPOLL cpu validation
- io_uring: have submission side sqe errors post a cqe
- io_uring: remove unnecessary barrier after unsetting IORING_SQ_NEED_WAKEUP
- io_uring: remove unnecessary barrier after incrementing dropped counter
- io_uring: remove unnecessary barrier before reading SQ tail
- io_uring: remove unnecessary barrier after updating SQ head
- io_uring: remove unnecessary barrier before reading cq head
- io_uring: remove unnecessary barrier before wq_has_sleeper
- io_uring: fix notes on barriers
- io_uring: fix handling SQEs requesting NOWAIT
- io_uring: remove 'state' argument from io_{read,write} path
- io_uring: fix poll full SQ detection
- io_uring: fix race condition when sq threads goes sleeping
- io_uring: fix race condition reading SQ entries
- io_uring: fail io_uring_register(2) on a dying io_uring instance
- io_uring: fix CQ overflow condition
- io_uring: fix possible deadlock between io_uring_{enter,register}
- io_uring: drop io_file_put() 'file' argument
- io_uring: only test SQPOLL cpu after we've verified it
- io_uring: park SQPOLL thread if it's percpu
- io_uring: restrict IORING_SETUP_SQPOLL to root
- io_uring: fix double free in case of fileset regitration failure
- io_uring: offload write to async worker in case of -EAGAIN
- io_uring: fix big-endian compat signal mask handling
- io_uring: retry bulk slab allocs as single allocs
- io_uring: fix poll races
- io_uring: fix fget/fput handling
- io_uring: add prepped flag
- io_uring: make io_read/write return an integer
- io_uring: use regular request ref counts
- tools/io_uring: remove IOCQE_FLAG_CACHEHIT
- io_uring: add a few test tools
- io_uring: allow workqueue item to handle multiple buffered requests
- io_uring: add support for IORING_OP_POLL
- io_uring: add io_kiocb ref count
- io_uring: add submission polling
- io_uring: add file set registration
- net: split out functions related to registering inflight socket files
- io_uring: add support for pre-mapped user IO buffers
- io_uring: batch io_kiocb allocation
- io_uring: use fget/fput_many() for file references
- fs: add fget_many() and fput_many()
- io_uring: support for IO polling
- io_uring: add fsync support
- Add io_uring IO interface
- io_pgetevents: use __kernel_timespec
- pselect6: use __kernel_timespec
- ppoll: use __kernel_timespec
- signal: Add restore_user_sigmask()
- signal: Add set_user_sigmask()
- block: Initialize BIO I/O priority early
- block: prevent merging of requests with different priorities
- aio: Fix fallback I/O priority value
- block: Introduce get_current_ioprio()
- aio: Comment use of IOCB_FLAG_IOPRIO aio flag
- fs: fix kabi change since add iopoll
- fs: add an iopoll method to struct file_operations
- signal: Allow cifs and drbd to receive their terminating signals
- cifs: fix rmmod regression in cifs.ko caused by force_sig changes
- signal/cifs: Fix cifs_put_tcp_session to call send_sig instead of force_sig

* Thu Apr 15 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2104.10.0.0073
- bpf, x86: Validate computation of branch displacements for x86-32
- bpf, x86: Validate computation of branch displacements for x86-64

* Thu Apr 15 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2104.9.0.0072
- mm/vmalloc.c: fix percpu free VM area search criteria
- mm/vmalloc.c: avoid bogus -Wmaybe-uninitialized warning
- mm/vmap: add DEBUG_AUGMENT_LOWEST_MATCH_CHECK macro
- mm/vmap: add DEBUG_AUGMENT_PROPAGATE_CHECK macro
- mm/vmalloc.c: keep track of free blocks for vmap allocation

* Thu Apr 15 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2104.8.0.0071
- config: Enable CONFIG_USERSWAP
- userswap: support userswap via userfaultfd
- userswap: add a new flag 'MAP_REPLACE' for mmap()
- mm, mempolicy: fix up gup usage in lookup_node
- mm/mempolicy: Allow lookup_node() to handle fatal signal
- mm/gup: Let __get_user_pages_locked() return -EINTR for fatal signal
- mm/gup: fix fixup_user_fault() on multiple retries
- mm/gup: allow VM_FAULT_RETRY for multiple times
- mm: allow VM_FAULT_RETRY for multiple times

* Thu Apr 15 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2104.7.0.0070
- sched/fair: fix kabi broken due to adding fields in rq and sched_domain_shared
- sched/fair: fix try_steal compile error
- config: enable CONFIG_SCHED_STEAL by default
- sched/fair: introduce SCHED_STEAL
- disable stealing by default
- sched/fair: Provide idle search schedstats
- sched/fair: disable stealing if too many NUMA nodes
- sched/fair: Steal work from an overloaded CPU when CPU goes idle
- sched/fair: Provide can_migrate_task_llc
- sched/fair: Generalize the detach_task interface
- sched/fair: Hoist idle_stamp up from idle_balance
- sched/fair: Dynamically update cfs_overload_cpus
- sched/topology: Provide cfs_overload_cpus bitmap
- sched/topology: Provide hooks to allocate data shared per LLC
- sched: Provide sparsemask, a reduced contention bitmap

* Thu Apr 15 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2104.6.0.0069
- sched/fair: fix kabi broken due to adding idle_h_nr_running in cfs_rq
- sched/fair: Make sched-idle CPU selection consistent throughout
- sched/fair: Optimize select_idle_cpu
- sched/fair: Fall back to sched-idle CPU if idle CPU isn't found
- sched/fair: Start tracking SCHED_IDLE tasks count in cfs_rq
- sched/core: Create task_has_idle_policy() helper

* Thu Apr 15 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2104.5.0.0068
- ext4: add reclaim checks to xattr code
- locking/mutex: Fix non debug version of mutex_lock_io_nested()
- dm verity: add root hash pkcs#7 signature verification
- Revert "netfilter: x_tables: Update remaining dereference to RCU"
- netfilter: x_tables: Use correct memory barriers.
- Revert "netfilter: x_tables: Switch synchronization to RCU"
- arm64: kdump: update ppos when reading elfcorehdr
- netfilter: ctnetlink: fix dump of the expect mask attribute
- dm ioctl: fix out of bounds array access when no devices
- block: Suppress uevent for hidden device when removed
- NFS: Correct size calculation for create reply length
- cifs: Fix preauth hash corruption
- ext4: do not try to set xattr into ea_inode if value is empty
- kernel, fs: Introduce and use set_restart_fn() and arch_set_restart_data()
- nvme-rdma: fix possible hang when failing to set io queues
- sunrpc: fix refcount leak for rpc auth modules
- include/linux/sched/mm.h: use rcu_dereference in in_vfork()
- hrtimer: Update softirq_expires_next correctly after __hrtimer_get_next_event()
- scsi: target: core: Prevent underflow for service actions
- scsi: target: core: Add cmd length set before cmd complete
- PCI: Fix pci_register_io_range() memory leak
- Revert "mm, slub: consider rest of partial list if acquire_slab() fails"
- cifs: return proper error code in statfs(2)
- tcp: add sanity tests to TCP_QUEUE_SEQ
- tcp: annotate tp->write_seq lockless reads
- tcp: annotate tp->copied_seq lockless reads
- netfilter: x_tables: gpf inside xt_find_revision()
- net: Fix gro aggregation for udp encaps with zero csum
- dm table: fix zoned iterate_devices based device capability checks
- dm table: fix DAX iterate_devices based device capability checks
- dm table: fix iterate_devices based device capability checks
- dm bufio: subtract the number of initial sectors in dm_bufio_get_device_size
- swap: fix swapfile read/write offset
- mm/hugetlb.c: fix unnecessary address expansion of pmd sharing
- net: fix up truesize of cloned skb in skb_prepare_for_shift()
- xfs: Fix assert failure in xfs_setattr_size()
- arm64 module: set plt* section addresses to 0x0
- hugetlb: fix update_and_free_page contig page struct assumption
- net: icmp: pass zeroed opts from icmp{,v6}_ndo_send before sending
- ipv6: silence compilation warning for non-IPV6 builds
- ipv6: icmp6: avoid indirect call for icmpv6_send()
- xfrm: interface: use icmp_ndo_send helper
- sunvnet: use icmp_ndo_send helper
- gtp: use icmp_ndo_send helper
- icmp: allow icmpv6_ndo_send to work with CONFIG_IPV6=n
- icmp: introduce helper for nat'd source address in network device context
- dm: fix deadlock when swapping to encrypted device
- printk: fix deadlock when kernel panic
- module: Ignore _GLOBAL_OFFSET_TABLE_ when warning for undefined symbols
- hugetlb: fix copy_huge_page_from_user contig page struct assumption
- x86: fix seq_file iteration for pat/memtype.c
- ACPI: property: Fix fwnode string properties matching
- blk-settings: align max_sectors on "logical_block_size" boundary
- mm/rmap: fix potential pte_unmap on an not mapped pte
- arm64: Add missing ISB after invalidating TLB in __primary_switch
- mm/hugetlb: fix potential double free in hugetlb_register_node() error path
- mm/memory.c: fix potential pte_unmap_unlock pte error
- ocfs2: fix a use after free on error
- tracepoint: Do not fail unregistering a probe due to memory failure
- isofs: release buffer head before return
- tcp: fix SO_RCVLOWAT related hangs under mem pressure
- random: fix the RNDRESEEDCRNG ioctl
- bfq: Avoid false bfq queue merging
- locking/static_key: Fix false positive warnings on concurrent dec/inc
- jump_label/lockdep: Assert we hold the hotplug lock for _cpuslocked() operations
- KVM: fix memory leak in kvm_io_bus_unregister_dev()
- net: qrtr: fix a kernel-infoleak in qrtr_recvmsg()
- xen-blkback: don't leak persistent grants from xen_blkbk_map()
- KVM: SVM: Periodically schedule when unregistering regions on destroy
- gianfar: fix jumbo packets+napi+rx overrun crash
- usbip: fix stub_dev usbip_sockfd_store() races leading to gpf
- media: v4l: ioctl: Fix memory leak in video_usercopy
- block: only update parent bi_status when bio fail
- RDMA/hns: fix timer, gid_type, scc cfg
- block: respect queue limit of max discard segment
- block: Use non _rcu version of list functions for tag_set_list

* Thu Apr 15 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2104.4.0.0067
- ext4: fix potential error in ext4_do_update_inode
- mm, sl[aou]b: guarantee natural alignment for kmalloc(power-of-two)
- mm,hwpoison: return -EBUSY when migration fails
- config: Enable files cgroup on x86
- ext4: Fix unreport netlink message to userspace when fs abort
- ext4: don't leak old mountpoint samples
- scsi: libiscsi: convert change of struct iscsi_conn to fix KABI
- scsi: libiscsi: Reset max/exp cmdsn during recovery
- scsi: iscsi_tcp: Fix shost can_queue initialization
- scsi: libiscsi: Add helper to calculate max SCSI cmds per session
- scsi: libiscsi: Fix iSCSI host workq destruction
- scsi: libiscsi: Fix iscsi_task use after free()
- scsi: libiscsi: Drop taskqueuelock
- scsi: libiscsi: Fix iscsi_prep_scsi_cmd_pdu() error handling
- scsi: libiscsi: Fix error count for active session
- ext4: fix timer use-after-free on failed mount
- loop: fix I/O error on fsync() in detached loop devices
- md/bitmap: fix memory leak of temporary bitmap
- md: get sysfs entry after redundancy attr group create
- md: fix deadlock causing by sysfs_notify
- md: fix the checking of wrong work queue
- md: flush md_rdev_misc_wq for HOT_ADD_DISK case
- md: don't flush workqueue unconditionally in md_open
- md: add new workqueue for delete rdev

* Tue Apr 13 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2104.3.0.0066
- nvme-fabrics: fix kabi broken due to adding fields in struct nvme_ctrl

* Thu Apr 1 2021 Jiachen Fan <fanjiachen3@huawei.com> - 4.19.90-2104.1.0.0065
- Add the option of "with_perf"
- Output jvmti plug-in as part of perf building

* Wed Apr 07 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2104.2.0.0064
- x86/Kconfig: Drop vendor dependency for X86_UMIP
- x86/Kconfig: Rename UMIP config parameter
- iommu/vt-d:Add support for detecting ACPI device in RMRR
- USB:Fix kernel NULL pointer when unbind UHCI form vfio-pci
- x86/apic: Mask IOAPIC entries when disabling the local APIC
- xhci: fix issue with resume from system Sx state
- xhci: Adjust the UHCI Controllers bit value
- ALSA: hda: Add support of Zhaoxin NB HDAC codec
- ALSA: hda: Add support of Zhaoxin NB HDAC
- ALSA: hda: Add support of Zhaoxin SB HDAC
- xhci: Show Zhaoxin XHCI root hub speed correctly
- xhci: fix issue of cross page boundary in TRB prefetch
- PCI: Add ACS quirk for Zhaoxin Root/Downstream Ports
- PCI: Add ACS quirk for Zhaoxin multi-function devices
- xhci: Add Zhaoxin xHCI LPM U1/U2 feature support
- ata: sata_zhaoxin: Add support for Zhaoxin Serial ATA
- PCI: Add Zhaoxin Vendor ID
- x86/perf: Add hardware performance events support for Zhaoxin CPU.
- crypto: x86/crc32c-intel - Don't match some Zhaoxin CPUs
- x86/speculation/swapgs: Exclude Zhaoxin CPUs from SWAPGS vulnerability
- x86/speculation/spectre_v2: Exclude Zhaoxin CPUs from SPECTRE_V2
- x86/mce: Add Zhaoxin LMCE support
- x86/mce: Add Zhaoxin CMCI support
- x86/mce: Add Zhaoxin MCE support
- x86/acpi/cstate: Add Zhaoxin processors support for cache flush policy in C3
- x86/power: Optimize C3 entry on Centaur CPUs
- ACPI, x86: Add Zhaoxin processors support for NONSTOP TSC
- x86/cpu: Add detect extended topology for Zhaoxin CPUs
- x86/cpufeatures: Add Zhaoxin feature bits
- x86/cpu/centaur: Add Centaur family >=7 CPUs initialization support
- x86/cpu/centaur: Replace two-condition switch-case with an if statement
- x86/cpu: Remove redundant cpu_detect_cache_sizes() call
- x86/cpu: Create Zhaoxin processors architecture support file
- xhci: apply XHCI_PME_STUCK_QUIRK to Intel Comet Lake platforms
- xhci: Fix memory leak when caching protocol extended capability PSI tables - take 2
- xhci: fix runtime pm enabling for quirky Intel hosts
- xhci: Force Maximum Packet size for Full-speed bulk devices to valid range.

* Thu Apr 01 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2104.1.0.0063
- configs: add config BMA to config files
- Huawei BMA: Adding Huawei BMA driver: host_kbox_drv
- Huawei BMA: Adding Huawei BMA driver: cdev_veth_drv
- Huawei BMA: Adding Huawei BMA driver: host_veth_drv
- Huawei BMA: Adding Huawei BMA driver: host_cdev_drv
- Huawei BMA: Adding Huawei BMA driver: host_edma_drv
- scsi: ses: Fix crash caused by kfree an invalid pointer
- net: hns3: PF add support for pushing link status to VFs
- net: hns: update hns version to 21.2.1
- net: hns: Remove unused macro AE_NAME_PORT_ID_IDX
- net: hns: use IRQ_NOAUTOEN to avoid irq is enabled due to request_irq
- net: hns: Replace zero-length array with flexible-array member
- hisilicon/hns: convert comma to semicolon
- net: hns: make arrays static, makes object smaller
- net: hns: Move static keyword to the front of declaration
- net: hns: use eth_broadcast_addr() to assign broadcast address
- net: hns: use true,false for bool variables
- net: hns: fix wrong display of "Advertised link modes"
- net: hns: fix ping failed when setting "autoneg off speed 100 duplex half"
- net: hns: fix variable used when DEBUG is defined
- net: hns: fix non-promiscuous mode does not take effect problem
- net: hns: remove redundant variable initialization
- treewide: Replace GPLv2 boilerplate/reference with SPDX - rule 152
- net/hinic: update hinic version to 2.3.2.18
- net/hinic: Add support for hinic PMD on VF
- net/hinic: Add XDP support for pass and drop actions
- net/hinic: permit configuration of rx-vlan-filter with ethtool
- locks: fix a memory leak bug in __break_lease()

* Mon Mar 29 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2103.4.0.0062
- mm/vmscan: fix uncleaned mem_cgroup_uncharge
- staging: rtl8188eu: prevent ->ssid overflow in rtw_wx_set_scan()
- PCI: rpadlpar: Fix potential drc_name corruption in store functions
- perf/x86/intel: Fix a crash caused by zero PEBS status
- btrfs: fix race when cloning extent buffer during rewind of an old root
- bpf: Fix off-by-one for area size in creating mask to left
- bpf: Prohibit alu ops for pointer types not defining ptr_limit
- net/x25: prevent a couple of overflows
- drm/ttm/nouveau: don't call tt destroy callback on alloc failure.
- cgroup: Fix kabi broken by files_cgroup introduced
- arm64/mpam: fix a possible deadlock in mpam_enable
- config: arm64: build TCM driver to modules by default
- staging: TCM: add GMJS(Nationz Tech) TCM driver.
- config: enable config TXGBE by default
- x86/config: Set CONFIG_TXGBE=m by default
- net: txgbe: Add support for Netswift 10G NIC

* Mon Mar 22 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2103.3.0.0061
- arm64/mpam: fix a memleak in add_schema
- scsi: check the whole result for reading write protect flag
- ext4: Fix bug on in ext4_es_cache_extent as ext4_split_extent_at failed
- md: add checkings before flush md_misc_wq
- dm: use noio when sending kobject event
- ext4: fix potential htree index checksum corruption
- quota: Fix memory leak when handling corrupted quota file
- quota: Sanity-check quota file headers on load
- block, bfq: invoke flush_idle_tree after reparent_active_queues in pd_offline
- block, bfq: make reparent_leaf_entity actually work only on leaf entities
- block, bfq: turn put_queue into release_process_ref in __bfq_bic_change_cgroup
- block, bfq: move forward the getting of an extra ref in bfq_bfqq_move
- block, bfq: get extra ref to prevent a queue from being freed during a group move
- perf/ftrace: Fix use-after-free in __ftrace_ops_list_func()
- fs/xfs: fix time overflow
- ext4: remove set but not used variable 'es' in ext4_jbd2.c
- ext4: remove set but not used variable 'es'
- ext4: don't try to processed freed blocks until mballoc is initialized
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
- ext4: save all error info in save_error_info() and drop ext4_set_errno()
- ext4: save the error code which triggered an ext4_error() in the superblock
- ext4: remove redundant sb checksum recomputation
- Revert "ext4: Protect superblock modifications with a buffer lock"

* Mon Mar 15 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2103.2.0.0060
- xen-netback: respect gnttab_map_refs()'s return value
- Xen/gnttab: handle p2m update errors on a per-slot basis
- sysfs: fix kabi broken when add sysfs_emit and sysfs_emit_at
- scsi: iscsi: Verify lengths on passthrough PDUs
- scsi: iscsi: Ensure sysfs attributes are limited to PAGE_SIZE
- sysfs: Add sysfs_emit and sysfs_emit_at to format sysfs output
- scsi: iscsi: Restrict sessions and handles to admin capabilities
- ovl: do not fail because of O_NOATIME
- ovl: check permission to open real file
- ovl: call secutiry hook in ovl_real_ioctl()
- ovl: verify permissions in ovl_path_open()
- ovl: switch to mounter creds in readdir
- ovl: pass correct flags for opening real directory
- mm/swapfile.c: fix potential memory leak in sys_swapon
- hibernate: Allow uswsusp to write to swap
- mm/swapfile.c: move inode_lock out of claim_swapfile
- mm/swapfile.c: fix a comment in sys_swapon()
- vfs: don't allow writes to swap files
- mm: set S_SWAPFILE on blockdev swap devices
- block_dump: remove block_dump feature when dirting inode
- virtio-blk: modernize sysfs attribute creation
- nvme: register ns_id attributes as default sysfs groups
- ext4: Fix not report exception message when mount with errors=continue
- xen-blkback: fix error handling in xen_blkbk_map()
- xen-scsiback: don't "handle" error by BUG()
- xen-netback: don't "handle" error by BUG()
- xen-blkback: don't "handle" error by BUG()
- xen/arm: don't ignore return errors from set_phys_to_machine
- Xen/gntdev: correct error checking in gntdev_map_grant_pages()
- Xen/gntdev: correct dev_bus_addr handling in gntdev_map_grant_pages()
- Xen/x86: also check kernel mapping in set_foreign_p2m_mapping()
- Xen/x86: don't bail early from clear_foreign_p2m_mapping()

* Thu Mar 11 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2103.1.0.0059
- brcmfmac: Loading the correct firmware for brcm43456
- config: Enable the config option of the etmem feature
- etmem: add etmem-swap feature
- etmem: add etmem-scan feature
- moduleparam: Save information about built-in modules in separate file
- ovl: expand warning in ovl_d_real()
- net: watchdog: hold device global xmit lock during tx disable
- bfq-iosched: Revert "bfq: Fix computation of shallow depth"
- ovl: skip getxattr of security labels
- cap: fix conversions on getxattr
- ovl: perform vfs_getxattr() with mounter creds
- tracing: Check length before giving out the filter buffer
- tracing: Do not count ftrace events in top level enable output
- blk-mq: don't hold q->sysfs_lock in blk_mq_map_swqueue
- block: don't hold q->sysfs_lock in elevator_init_mq
- SUNRPC: Handle 0 length opaque XDR object data properly
- SUNRPC: Move simple_get_bytes and simple_get_netobj into private header
- fgraph: Initialize tracing_graph_pause at task creation
- tracing/kprobe: Fix to support kretprobe events on unloaded modules
- md: Set prev_flush_start and flush_bio in an atomic way
- mm: thp: fix MADV_REMOVE deadlock on shmem THP
- mm: hugetlb: remove VM_BUG_ON_PAGE from page_huge_active
- mm: hugetlb: fix a race between isolating and freeing page
- mm: hugetlb: fix a race between freeing and dissolving the page
- mm: hugetlbfs: fix cannot migrate the fallocated HugeTLB page
- smb3: Fix out-of-bounds bug in SMB2_negotiate()
- cifs: report error instead of invalid when revalidating a dentry fails
- genirq/msi: Activate Multi-MSI early when MSI_FLAG_ACTIVATE_EARLY is set
- kretprobe: Avoid re-registration of the same kretprobe earlier
- ovl: fix dentry leak in ovl_get_redirect
- memblock: do not start bottom-up allocations with kernel_end
- workqueue: Restrict affinity change to rescuer
- kthread: Extract KTHREAD_IS_PER_CPU
- sysctl: handle overflow in proc_get_long
- fs: fix lazytime expiration handling in __writeback_single_inode()
- writeback: Drop I_DIRTY_TIME_EXPIRE
- dm integrity: conditionally disable "recalculate" feature
- tracing: Fix race in trace_open and buffer resize call
- Revert "mm/slub: fix a memory leak in sysfs_slab_add()"
- net/rds: restrict iovecs length for RDS_CMSG_RDMA_ARGS
- net: fix iteration for sctp transport seq_files
- netfilter: conntrack: skip identical origin tuple in same zone only
- netfilter: flowtable: fix tcp and udp header checksum update
- netfilter: xt_recent: Fix attempt to update deleted entry
- af_key: relax availability checks for skb size calculation
- net: ip_tunnel: fix mtu calculation
- net_sched: gen_estimator: support large ewma log
- tcp: fix TLP timer not set when CA_STATE changes from DISORDER to OPEN
- net/mlx5: Fix memory leak on flow table creation error flow
- xfrm: fix disable_xfrm sysctl when used on xfrm interfaces
- xfrm: Fix oops in xfrm_replay_advance_bmp
- netfilter: nft_dynset: add timeout extension to template
- net: sit: unregister_netdevice on newlink's error path
- esp: avoid unneeded kmap_atomic call
- udp: Prevent reuseport_select_sock from reading uninitialized socks
- vrf: Fix fast path output packet handling with async Netfilter rules
- livepatch/core: Fix jump_label_apply_nops called multi times
- gpu: hibmc: Fix stuck when switch GUI to text.
- gpu: hibmc: Use drm get pci dev api.
- gpu: hibmc: Fix erratic display during startup stage.
- net: hns3: update hns3 version to 1.9.38.11
- net: hns3: fix 'ret' may be used uninitialized problem
- net: hns3: update hns3 version to 1.9.38.10
- net: hns3: adds support for setting pf max tx rate via sysfs
- ext4: find old entry again if failed to rename whiteout
- config: disable config TMPFS_INODE64 by default
- tmpfs: restore functionality of nr_inodes=0
- tmpfs: support 64-bit inums per-sb
- tmpfs: per-superblock i_ino support
- Revert "scsi: sg: fix memory leak in sg_build_indirect"
- scsi: fix kabi for scsi_device
- scsi: core: Only re-run queue in scsi_end_request() if device queue is busy
- scsi: core: Run queue in case of I/O resource contention failure
- Revert "scsi: sd: block: Fix read-only flag residuals when partition table change"
- scsi: sd: block: Fix kabi change by 'scsi: sd: block: Fix regressions in read-only block device handling'
- scsi: sd: block: Fix read-only flag residuals when partition table change
- scsi: sd: block: Fix regressions in read-only block device handling
- proc/mounts: Fix kabi broken
- proc/mounts: add cursor
- list: introduce list_for_each_continue()

* Wed Feb 24 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2102.3.0.0058
- arm64/mpam: Fix compile warning
- arm64/mpam: Sort domains when cpu online
- arm64/mpam: resctrl: Refresh cpu mask for handling cpuhp
- arm64/mpam: resctrl: Allow setting register MPAMCFG_MBW_MIN to 0
- arm64/mpam: resctrl: Use resctrl_group_init_alloc() for default group
- arm64/mpam: resctrl: Add proper error handling to resctrl_mount()
- arm64/mpam: Supplement additional useful ctrl features for mount options
- ACPI/MPAM: Use acpi_map_pxm_to_node() to get node id for memory node
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
- cacheinfo: Provide a helper to find a cacheinfo leaf
- arm64/mpam: Add mpam driver discovery phase and kbuild boiler plate
- arm64/mpam: Preparing for MPAM refactoring


* Mon Feb 22 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2102.2.0.0057
- powerpc: fix a compiling error for 'access_ok'
- mmap: fix a compiling error for 'MAP_CHECKNODE'
- futex: sched: fix UAF when free futex_exit_mutex in free_task()
- futex: sched: fix kabi broken in task_struct
- futex: Prevent exit livelock
- futex: Provide distinct return value when owner is exiting
- futex: Add mutex around futex exit
- futex: Provide state handling for exec() as well
- futex: Sanitize exit state handling
- futex: Mark the begin of futex exit explicitly
- futex: Set task::futex_state to DEAD right after handling futex exit
- futex: Split futex_mm_release() for exit/exec
- exit/exec: Seperate mm_release()
- futex: Replace PF_EXITPIDONE with a state
- futex: Move futex exit handling into futex code
- net: Disable NETIF_F_HW_TLS_RX when RXCSUM is disabled
- ipv6: set multicast flag on the multicast route
- net_sched: reject silly cell_log in qdisc_get_rtab()
- net_sched: avoid shift-out-of-bounds in tcindex_set_parms()
- ipv6: create multicast route with RTPROT_KERNEL
- udp: mask TOS bits in udp_v4_early_demux()
- kasan: fix incorrect arguments passing in kasan_add_zero_shadow
- kasan: fix unaligned address is unhandled in kasan_remove_zero_shadow
- skbuff: back tiny skbs with kmalloc() in __netdev_alloc_skb() too
- netfilter: rpfilter: mask ecn bits before fib lookup
- driver core: Extend device_is_dependent()
- dm integrity: fix a crash if "recalculate" used without "internal_hash"
- dm: avoid filesystem lookup in dm_get_dev_t()
- ACPI: scan: Make acpi_bus_get_device() clear return pointer on error
- net: ipv6: Validate GSO SKB before finish IPv6 processing
- net: skbuff: disambiguate argument and member for skb_list_walk_safe helper
- net: introduce skb_list_walk_safe for skb segment walking
- tipc: fix NULL deref in tipc_link_xmit()
- net: avoid 32 x truesize under-estimation for tiny skbs
- dm integrity: fix flush with external metadata device
- netfilter: nf_nat: Fix memleak in nf_nat_init
- netfilter: conntrack: fix reading nf_conntrack_buckets
- net: sunrpc: interpret the return value of kstrtou32 correctly
- mm, slub: consider rest of partial list if acquire_slab() fails
- ext4: fix superblock checksum failure when setting password salt
- NFS: nfs_igrab_and_active must first reference the superblock
- NFS/pNFS: Fix a leak of the layout 'plh_outstanding' counter
- pNFS: Mark layout for return if return-on-close was not sent
- NFS4: Fix use-after-free in trace_event_raw_event_nfs4_set_lock
- dump_common_audit_data(): fix racy accesses to ->d_name
- bfq: Fix computation of shallow depth
- dm integrity: fix the maximum number of arguments
- dm snapshot: flush merged data before committing metadata
- mm/hugetlb: fix potential missing huge page size info
- ACPI: scan: Harden acpi_device_add() against device ID overflows
- block: fix use-after-free in disk_part_iter_next
- vhost_net: fix ubuf refcount incorrectly when sendmsg fails
- virtio_net: Fix recursive call to cpus_read_lock()
- proc: fix lookup in /proc/net subdirectories after setns(2)
- proc: change ->nlink under proc_subdir_lock
- lib/genalloc: fix the overflow when size is too big
- scsi: scsi_transport_spi: Set RQF_PM for domain validation commands
- workqueue: Kick a worker based on the actual activation of delayed works
- dm verity: skip verity work if I/O error when system is shutting down
- module: delay kobject uevent until after module init call
- NFSv4: Fix a pNFS layout related use-after-free race when freeing the inode
- quota: Don't overflow quota file offsets
- module: set MODULE_STATE_GOING state when a module fails to load
- fcntl: Fix potential deadlock in send_sig{io, urg}()
- null_blk: Fix zone size initialization
- ext4: don't remount read-only with errors=continue on reboot
- vfio/pci: Move dummy_resources_list init in vfio_pci_probe()
- arm64: module/ftrace: intialize PLT at load time
- arm64: module: rework special section handling
- net: drop bogus skb with CHECKSUM_PARTIAL and offset beyond end of trimmed packet
- net/mlx5e: Fix two double free cases
- net/mlx5e: Fix memleak in mlx5e_create_l2_table_groups
- net: ipv6: fib: flush exceptions when purging route
- net: fix pmtu check in nopmtudisc mode
- net: ip: always refragment ip defragmented packets
- net: vlan: avoid leaks on register_vlan_dev() failures
- netfilter: xt_RATEEST: reject non-null terminated string from userspace
- netfilter: ipset: fix shift-out-of-bounds in htable_bits()
- netfilter: x_tables: Update remaining dereference to RCU
- net-sysfs: take the rtnl lock when accessing xps_rxqs_map and num_tc
- net-sysfs: take the rtnl lock when storing xps_rxqs
- net: sched: prevent invalid Scell_log shift count
- erspan: fix version 1 check in gre_parse_header()
- net: hns: fix return value check in __lb_other_process()
- ipv4: Ignore ECN bits for fib lookups in fib_compute_spec_dst()
- net-sysfs: take the rtnl lock when accessing xps_cpus_map and num_tc
- net-sysfs: take the rtnl lock when storing xps_cpus
- i40e: Fix Error I40E_AQ_RC_EINVAL when removing VFs
- lwt: Disable BH too in run_lwt_bpf()
- net/mlx5: Properly convey driver version to firmware
- vxlan: Copy needed_tailroom from lowerdev
- vxlan: Add needed_headroom for lower device
- ixgbe: avoid premature Rx buffer reuse
- xsk: Fix xsk_poll()'s return type
- net/mlx4_en: Handle TX error CQE
- net/mlx4_en: Avoid scheduling restart task if it is already running
- net/mlx5: Fix wrong address reclaim when command interface is down
- i40e: Fix removing driver while bare-metal VFs pass traffic
- net/tls: Protect from calling tls_dev_del for TLS RX twice
- net/tls: missing received data after fast remote close
- clocksource/drivers/arch_timer: Fix vdso_fix compile error for arm32
- scsi/hifc:Fix the bug that the system may be oops during unintall hifc module.
- KVM: Enable PUD huge mappings only on 1620
- fs: fix files.usage bug when move tasks
- scsi: do quiesce for enclosure driver
- ext4: fix bug for rename with RENAME_WHITEOUT
- mm: fix kabi broken
- mm: memcontrol: add struct mem_cgroup_extension
- mm: thp: don't need care deferred split queue in memcg charge move path
- mm: vmscan: protect shrinker idr replace with CONFIG_MEMCG
- mm: thp: make deferred split shrinker memcg aware
- mm: shrinker: make shrinker not depend on memcg kmem
- mm: move mem_cgroup_uncharge out of __page_cache_release()
- mm: thp: extract split_queue_* into a struct
- bonding: add documentation for peer_notif_delay
- bonding: fix value exported by Netlink for peer_notif_delay
- bonding: add an option to specify a delay between peer notifications
- arm64/ascend: mm: Fix hugetlb check node error
- fix virtio_gpu use-after-free while creating dumb
- ext4: add ext3 report error to userspace by netlink
- arm64/ascend: mm: Fix arm32 compile warnings
- Kconfig: disable KTASK by default
- netpoll: accept NULL np argument in netpoll_send_skb()
- netpoll: netpoll_send_skb() returns transmit status
- netpoll: move netpoll_send_skb() out of line
- netpoll: remove dev argument from netpoll_send_skb_on_dev()
- efi/arm: Revert "Defer persistent reservations until after paging_init()"
- arm64, mm, efi: Account for GICv3 LPI tables in static memblock reserve table
- block: better deal with the delayed not supported case in blk_cloned_rq_check_limits
- block: Return blk_status_t instead of errno codes
- ASoC: msm8916-wcd-digital: Select REGMAP_MMIO to fix build error
- irqchip/gic-v3: Fix compiling error on ARM32 with GICv3
- PCI: Fix pci_slot_release() NULL pointer dereference
- md/cluster: fix deadlock when node is doing resync job
- md/cluster: block reshape with remote resync job
- ext4: fix deadlock with fs freezing and EA inodes
- ext4: fix a memory leak of ext4_free_data
- ACPI: PNP: compare the string length in the matching_id()
- Revert "ACPI / resources: Use AE_CTRL_TERMINATE to terminate resources walks"
- nfs_common: need lock during iterate through the list
- clocksource/drivers/arm_arch_timer: Correct fault programming of CNTKCTL_EL1.EVNTI
- NFS: switch nfsiod to be an UNBOUND workqueue.
- lockd: don't use interval-based rebinding over TCP
- SUNRPC: xprt_load_transport() needs to support the netid "rdma6"
- PCI: iproc: Fix out-of-bound array accesses
- PCI: Fix overflow in command-line resource alignment requests
- PCI: Bounds-check command-line resource alignment requests
- genirq/irqdomain: Don't try to free an interrupt that has no mapping
- spi: fix resource leak for drivers without .remove callback
- scsi: core: Fix VPD LUN ID designator priorities
- selinux: fix inode_doinit_with_dentry() LABEL_INVALID error handling
- sched: Reenable interrupts in do_sched_yield()
- sched/deadline: Fix sched_dl_global_validate()
- selinux: fix error initialization in inode_doinit_with_dentry()
- serial_core: Check for port state when tty is in error state
- arm64: syscall: exit userspace before unmasking exceptions
- netfilter: x_tables: Switch synchronization to RCU
- block: factor out requeue handling from dispatch code
- arm64: Change .weak to SYM_FUNC_START_WEAK_PI for arch/arm64/lib/mem*.S
- arm64: lse: Fix LSE atomics with LLVM
- arm64: lse: fix LSE atomics with LLVM's integrated assembler
- net: bridge: vlan: fix error return code in __vlan_add()
- tcp: fix cwnd-limited bug for TSO deferral where we send nothing
- tcp: select sane initial rcvq_space.space for big MSS
- netfilter: nf_tables: avoid false-postive lockdep splat
- tracing: Fix userstacktrace option for instances
- mm/swapfile: do not sleep with a spin lock held
- mm: list_lru: set shrinker map bit when child nr_items is not zero
- cifs: fix potential use-after-free in cifs_echo_request()
- ftrace: Fix updating FTRACE_FL_TRAMP
- net: ip6_gre: set dev->hard_header_len when using header_ops
- ipv4: Fix tos mask in inet_rtm_getroute()
- netfilter: bridge: reset skb->pkt_type after NF_INET_POST_ROUTING traversal
- bonding: wait for sysfs kobject destruction before freeing struct slave
- tcp: Set INET_ECN_xmit configuration in tcp_reinit_congestion_control
- sock: set sk_err to ee_errno on dequeue from errq
- ipv6: addrlabel: fix possible memory leak in ip6addrlbl_net_init
- efivarfs: revert "fix memory leak in efivarfs_create()"
- scsi: libiscsi: Fix NOP race condition
- nvme: free sq/cq dbbuf pointers when dbbuf set fails
- proc: don't allow async path resolution of /proc/self components
- arm64: pgtable: Ensure dirty bit is preserved across pte_wrprotect()
- arm64: pgtable: Fix pte_accessible()
- scsi: libiscsi: fix task hung when iscsid deamon exited
- mmap: fix a compiling error for 'MAP_PA32BIT'
- hifc: remove unnecessary __init specifier
- armv7 fix compile error
- cputime: fix undefined reference to get_idle_time when CONFIG_PROC_FS disabled
- memcg/ascend: enable kmem cgroup by default for ascend
- memcg/ascend: Check sysctl oom config for memcg oom
- bdi: fix compiler error in bdi_get_dev_name()
- arm64: fix compile error when CONFIG_HOTPLUG_CPU is disabled
- scsi: target: iscsi: Fix cmd abort fabric stop race
- scsi: target: fix hang when multiple threads try to destroy the same iscsi session
- scsi: target: remove boilerplate code
- ext4: Protect superblock modifications with a buffer lock
- arm64: arch_timer: only do cntvct workaround on VDSO path on D05
- libata: transport: Use scnprintf() for avoiding potential buffer overflow
- Document: In the binding document, add enable-init-all-GICR field description.
- irqchip/irq-gic-v3: Add workaround bindings in device tree to init ts core GICR.
- asm-generic/io.h: Fix !CONFIG_GENERIC_IOMAP pci_iounmap() implementation
- hugetlbfs: Add dependency with ascend memory features
- net/mlx5: Disable QoS when min_rates on all VFs are zero
- sctp: change to hold/put transport for proto_unreach_timer
- net: Have netpoll bring-up DSA management interface
- mlxsw: core: Use variable timeout for EMAD retries
- ah6: fix error return code in ah6_input()
- tipc: fix memory leak in tipc_topsrv_start()
- sctp: Fix COMM_LOST/CANT_STR_ASSOC err reporting on big-endian platforms
- libceph: clear con->out_msg on Policy::stateful_server faults
- mlxsw: core: Fix use-after-free in mlxsw_emad_trans_finish()
- tipc: fix memory leak caused by tipc_buf_append()
- mlxsw: core: Fix memory leak on module removal
- irqchip/gic-v3-its: Unconditionally save/restore the ITS state on suspend.
- sbsa_gwdt: Add WDIOF_PRETIMEOUT flag to watchdog_info at defination
- NMI: Enable arm-pmu interrupt as NMI in Acensed.
- arm64/ascend: mm: Add MAP_CHECKNODE flag to check node hugetlb
- config: enable CONFIG_NVME_MULTIPATH by default
- mm/userfaultfd: do not access vma->vm_mm after calling handle_userfault()
- ext4: fix bogus warning in ext4_update_dx_flag()
- efivarfs: fix memory leak in efivarfs_create()
- libfs: fix error cast of negative value in simple_attr_write()
- xfs: revert "xfs: fix rmap key and record comparison functions"
- fail_function: Remove a redundant mutex unlock
- xfs: strengthen rmap record flags checking
- xfs: fix the minrecs logic when dealing with inode root child blocks
- ip_tunnels: Set tunnel option flag when tunnel metadata is present
- perf lock: Don't free "lock_seq_stat" if read_count isn't zero
- vfs: remove lockdep bogosity in __sb_start_write
- arm64: psci: Avoid printing in cpu_psci_cpu_die()
- tcp: only postpone PROBE_RTT if RTT is < current min_rtt estimate
- page_frag: Recover from memory pressure
- net: bridge: add missing counters to ndo_get_stats64 callback
- inet_diag: Fix error path to cancel the meseage in inet_req_diag_fill()
- devlink: Add missing genlmsg_cancel() in devlink_nl_sb_port_pool_fill()
- Convert trailing spaces and periods in path components
- net: sch_generic: fix the missing new qdisc assignment bug
- reboot: fix overflow parsing reboot cpu number
- Revert "kernel/reboot.c: convert simple_strtoul to kstrtoint"
- perf scripting python: Avoid declaring function pointers with a visibility attribute
- random32: make prandom_u32() output unpredictable
- net: Update window_clamp if SOCK_RCVBUF is set
- IPv6: Set SIT tunnel hard_header_len to zero
- don't dump the threads that had been already exiting when zapped.
- selinux: Fix error return code in sel_ib_pkey_sid_slow()
- ocfs2: initialize ip_next_orphan
- futex: Don't enable IRQs unconditionally in put_pi_state()
- uio: Fix use-after-free in uio_unregister_device()
- ext4: unlock xattr_sem properly in ext4_inline_data_truncate()
- ext4: correctly report "not supported" for {usr, grp}jquota when !CONFIG_QUOTA
- perf: Fix get_recursion_context()
- xfs: fix a missing unlock on error in xfs_fs_map_blocks
- xfs: fix brainos in the refcount scrubber's rmap fragment processor
- xfs: fix rmap key and record comparison functions
- xfs: set the unwritten bit in rmap lookup flags in xchk_bmap_get_rmapextents
- xfs: fix flags argument to rmap lookup when converting shared file rmaps
- nbd: fix a block_device refcount leak in nbd_release
- tick/common: Touch watchdog in tick_unfreeze() on all CPUs
- netfilter: use actual socket sk rather than skb sk when routing harder
- tpm: efi: Don't create binary_bios_measurements file for an empty log
- xfs: fix scrub flagging rtinherit even if there is no rt device
- xfs: flush new eof page on truncate to avoid post-eof corruption
- perf tools: Add missing swap for ino_generation
- netfilter: ipset: Update byte and packet counters regardless of whether they match
- xfs: set xefi_discard when creating a deferred agfl free log intent item
- net: xfrm: fix a race condition during allocing spi
- time: Prevent undefined behaviour in timespec64_to_ns()
- fork: fix copy_process(CLONE_PARENT) race with the exiting ->real_parent
- scsi: core: Don't start concurrent async scan on same host
- blk-cgroup: Pre-allocate tree node on blkg_conf_prep
- blk-cgroup: Fix memleak on error path
- futex: Handle transient "ownerless" rtmutex state correctly
- tracing: Fix out of bounds write in get_trace_buf
- ftrace: Handle tracing when switching between context
- ftrace: Fix recursion check for NMI test
- ring-buffer: Fix recursion protection transitions between interrupt context
- kthread_worker: prevent queuing delayed work from timer_fn when it is being canceled
- mm: mempolicy: fix potential pte_unmap_unlock pte error
- Fonts: Replace discarded const qualifier
- ptrace: fix task_join_group_stop() for the case when current is traced
- device property: Don't clear secondary pointer for shared primary firmware node
- device property: Keep secondary firmware node secondary by type
- ext4: fix invalid inode checksum
- ext4: fix error handling code in add_new_gdb
- ext4: fix leaking sysfs kobject after failed mount
- ring-buffer: Return 0 on success from ring_buffer_resize()
- perf python scripting: Fix printable strings in python3 scripts
- sgl_alloc_order: fix memory leak
- nbd: make the config put is called before the notifying the waiter
- cifs: handle -EINTR in cifs_setattr
- ext4: Detect already used quota file early
- ACPI: Add out of bounds and numa_off protections to pxm_to_node()
- xfs: don't free rt blocks when we're doing a REMAP bunmapi call
- arm64/mm: return cpu_all_mask when node is NUMA_NO_NODE
- uio: free uio id after uio file node is freed
- arm64: topology: Stop using MPIDR for topology information
- xfs: fix realtime bitmap/summary file truncation when growing rt volume
- mm: fix exec activate_mm vs TLB shootdown and lazy tlb switching race
- futex: Fix incorrect should_fail_futex() handling
- serial: pl011: Fix lockdep splat when handling magic-sysrq interrupt
- fuse: fix page dereference after free
- tcp: Prevent low rmem stalls with SO_RCVLOWAT.
- netem: fix zero division in tabledist
- efivarfs: Replace invalid slashes with exclamation marks in dentries.
- arm64: Run ARCH_WORKAROUND_1 enabling code on all CPUs
- config: set default value of CONFIG_TEST_FREE_PAGES
- mm/page_alloc.c: fix freeing non-compound pages
- mm, hwpoison: double-check page count in __get_any_page()
- mm: fix a race during THP splitting
- mm: fix check_move_unevictable_pages() on THP
- mlock: fix unevictable_pgs event counts on THP
- mm: swap: memcg: fix memcg stats for huge pages
- mm: swap: fix vmstats for huge pages
- mm: move nr_deactivate accounting to shrink_active_list()
- blk-throttle: don't check whether or not lower limit is valid if CONFIG_BLK_DEV_THROTTLING_LOW is off
- blk-cgroup: prevent rcu_sched detected stalls warnings in blkg_destroy_all()


* Tue Feb 09 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2102.1.0.0056
- nbd: freeze the queue while we're adding connections
- nbd: Fix memory leak in nbd_add_socket
- futex: Handle faults correctly for PI futexes
- futex: Simplify fixup_pi_state_owner()
- futex: Use pi_state_update_owner() in put_pi_state()
- rtmutex: Remove unused argument from rt_mutex_proxy_unlock()
- futex: Provide and use pi_state_update_owner()
- futex: Replace pointless printk in fixup_owner()
- futex: Ensure the correct return value from futex_lock_pi()
- inet: do not call sublist_rcv on empty list
- netfilter: add and use nf_hook_slow_list()
- netfilter: clear skb->next in NF_HOOK_LIST()
- scsi: target: Fix XCOPY NAA identifier lookup
- nfsd4: readdirplus shouldn't return parent of export
- HID: core: Correctly handle ReportSize being zero

* Mon Jan 11 2021 Yang Yingliang <yangyingliang@huawei.com> - 4.19.90-2101.1.0.0055
- net: hns3: update hns3 version to 1.9.38.9
- net: hns3: optimize the process of queue reset
- net: hns3: fix loopback test of serdes and phy is failed if duplex is half
- net: hns3: format the output of the MAC address
- net: hns3: rename hns-customer to hns3_extension
- net: hns3: fix RoCE calling the wrong function problem
- net: hns3: Clear the CMDQ registers before unmapping BAR region
- net: hns3: fix for loopback failure when vlan filter is enable
- net: hns3: replace snprintf with scnprintf in hns3_dbg_cmd_read
- net: hns3: delete unused codes
- net: hns3: fix missing help info in debugfs
- net: hns3: add trace event support for PF/VF mailbox
- net: hns3: fix loopback failed when phy has no .set_loopback interface
- net: hns3: clear hardware resource when loading driver
- net: hns3: fix incorrect print value of vf_id and vport_id
- net: hns3: fix bug when initialize the RSS tuples for SCTP6
- net: hns3: solve the problem of array uninitialized
- net: hns3: clean up for some coding style.
- net: hns3: adds a kernel message when restart autoneg.
- net: hns3: modify a print message
- net: hns3: provide .get_cmdq_stat interface for the client
- net: hns3: add a hardware error detect type
- net: hns3: implement .process_hw_error for hns3 client
- net: hns3: modify location of one print information
- net/hinic: update hinic version to 2.3.2.17
- net/hinic: Modify the printing level of some logs
- net/hinic: Fix oops when memory is insufficient
- net/hinic: Set default features when probe netdev
- RDMA/hns: fix eth extended SGE err
- scsi: hisi_sas: Delete down() when handle Block-IO
- nvme-fabrics: reject I/O to offline device
- PCI: Add pci reset quirk for Huawei Intelligent NIC virtual function
- nvme: fix nvme_stop_queues cost long time error
- scsi: hisi_sas: fix logic bug when alloc device with MAX device num == 1
- scsi: hisi_sas: mask corresponding RAS interrupts for hilink DFX exception
- scsi: hisi_sas: Directly trigger SCSI error handling for completion errors
- scsi: hisi_sas: use wait_for_completion_timeout() when clearing ITCT
- scsi: hisi_sas: Fix the conflict between device gone and host reset
- scsi: hisi_sas: Update all the registers after suspend and resume
- scsi: hisi_sas: Make slot buf minimum allocation of PAGE_SIZE
- scsi: hisi_sas: Reduce HISI_SAS_SGE_PAGE_CNT in size
- scsi: flip the default on use_clustering
- RDMA/hns: Disable UD on HIP08
- powerpc/rtas: Restrict RTAS requests from userspace
- mwifiex: Fix possible buffer overflows in mwifiex_cmd_802_11_ad_hoc_start
- xenbus/xenbus_backend: Disallow pending watch messages
- xen/xenbus: Count pending messages for each watch
- xen/xenbus/xen_bus_type: Support will_handle watch callback
- xen/xenbus: Add 'will_handle' callback support in xenbus_watch_path()
- xen/xenbus: Allow watches discard events before queueing
- xen-blkback: set ring->xenblkd to NULL after kthread_stop()
- HID: core: Sanitize event code and type when mapping input
- cfg80211: add missing policy for NL80211_ATTR_STATUS_CODE
- speakup: Reject setting the speakup line discipline outside of speakup
- tty: Fix ->session locking
- tty: Fix ->pgrp locking in tiocspgrp()
- ALSA: rawmidi: Fix racy buffer resize under concurrent accesses
- jfs: Fix array index bounds check in dbAdjTree

* Tue Dec 22 2020 Yang Yingliang <yangyingliang@huawei.com> - 4.19.90-2012.5.0.0054
- Revert "mm/memory_hotplug: refrain from adding memory into an impossible node"

* Mon Dec 21 2020 Yang Yingliang <yangyingliang@huawei.com> - 4.19.90-2012.4.0.0053
- defconfig: update the defconfigs to support NVDIMM

* Thu Dec 17 2020 Yang Yingliang <yangyingliang@huawei.com> - 4.19.90-2012.3.0.0052
- scsi/hifc: fix the issue that the system is suspended during the pres
- mm: thp: make the THP mapcount atomic against __split_huge_pmd_locked()
- romfs: fix uninitialized memory leak in romfs_dev_read()

* Tue Dec 15 2020 Yang Yingliang <yangyingliang@huawei.com> - 4.19.90-2012.2.0.0051
- scsi: libiscsi: Fix cmds hung when sd_shutdown

* Thu Dec 10 2020 Yang Yingliang <yangyingliang@huawei.com> - 4.19.90-2012.1.0.0050
- fanotify: fix merging marks masks with FAN_ONDIR
- scsi/hifc: fix the issue of npiv cannot be deleted

* Sat Nov 28 2020 Yang Yingliang <yangyingliang@huawei.com> - 4.19.90-2011.6.0.0049
- refcount_t: Add ACQUIRE ordering on success for dec(sub)_and_test() variants
- x86/asm: 'Simplify' GEN_*_RMWcc() macros
- Revert "refcount_t: Add ACQUIRE ordering on success for dec(sub)_and_test() variants"
- refcount_t: Add ACQUIRE ordering on success for dec(sub)_and_test() variants
- powerpc/64s: flush L1D after user accesses
- powerpc/uaccess: Evaluate macro arguments once, before user access is allowed
- powerpc: Fix __clear_user() with KUAP enabled
- powerpc: Implement user_access_begin and friends
- powerpc: Add a framework for user access tracking
- powerpc/64s: flush L1D on kernel entry
- powerpc/64s: move some exception handlers out of line

* Mon Nov 23 2020 Yang Yingliang <yangyingliang@huawei.com> - 4.19.90-2011.4.0.0048
- Bluetooth: fix kernel oops in store_pending_adv_report
- vt: Disable KD_FONT_OP_COPY
- fbcon: Fix global-out-of-bounds read in fbcon_get_font()
- Fonts: Support FONT_EXTRA_WORDS macros for built-in fonts
- fbdev, newport_con: Move FONT_EXTRA_WORDS macros into linux/font.h
- speakup: Do not let the line discipline be used several times
- mm/page_idle.c: skip offline pages
- mm/memory_hotplug: refrain from adding memory into an impossible node
- khugepaged: drain LRU add pagevec after swapin
- khugepaged: drain all LRU caches before scanning pages
- khugepaged: do not stop collapse if less than half PTEs are referenced
- powercap: restrict energy meter to root access
- Input: sunkbd - avoid use-after-free in teardown paths
- nbd: don't update block size after device is started

* Wed Nov 18 2020 Yang Yingliang <yangyingliang@huawei.com> - 4.19.90-2011.3.0.0047
- tools: perf: Fix build error in v4.19.y
- nvme-fabrics: modify default value to reconnect forever
- nvme-rdma: add module param to turn off inline data dynamically
- nvme-rdma: fix crash casue by destroy id while resolving addr
- nvme-rdma: avoid race between time out and tear down
- nvme-core: introduce sync io queues
- nvme-rdma: avoid repeated request completion
- nvme-rdma: fix crash due to incorrect cqe
- nvme-multipath: fix crash in nvme_mpath_clear_ctrl_paths
- nvme: fix controller removal race with scan work
- nvme-multipath: fix bogus request queue reference put
- nvme-multipath: fix deadlock due to head->lock
- nvme: don't protect ns mutation with ns->head->lock
- nvme: clear any SGL flags in passthru commands
- nvme: disable streams when get stream params failed
- nvme: revalidate after verifying identifiers
- nvme: release namespace head reference on error
- nvme: unlink head after removing last namespace
- nvme: Make nvme_uninit_ctrl symmetric to nvme_init_ctrl
- nvme: Fix ctrl use-after-free during sysfs deletion
- nvme-rdma: fix crash when connect rejected
- nvme-rdma: fix timeout handler
- nvme: Fix parsing of ANA log page
- nvme: release ida resources
- nvme: Add compat_ioctl handler for NVME_IOCTL_SUBMIT_IO
- nvme: introduce "Command Aborted By host" status code
- nvme: enable aen regardless of the presence of I/O queues
- nvme: make nvme_identify_ns propagate errors back
- nvme: pass status to nvme_error_status
- nvme: don't abort completed request in nvme_cancel_request
- nvme: put ns_head ref if namespace fails allocation
- nvme: implement Enhanced Command Retry
- nvme: wait until all completed request's complete fn is called
- blk-mq: introduce blk_mq_tagset_wait_completed_request()
- blk-mq: introduce blk_mq_request_completed()
- nvme-rdma: fix a segmentation fault during module unload
- mlx5: remove support for ib_get_vector_affinity
- nvme-rdma: fix possible use-after-free in connect timeout
- nvme-rdma: fix possible use-after-free in connect error flow
- nvme-rdma: use dynamic dma mapping per command
- nvme-rdma: remove redundant reference between ib_device and tagset
- scsi/hifc: add hifc driver compile config module
- scsi/hifc: add hifc driver FC service module
- scsi/hifc: add hifc driver scsi module
- scsi/hifc: add hifc driver io module
- scsi/hifc: add hifc driver port resource module
- scsi/hifc: add hifc driver port manager module
- scsi/hifc: add hifc driver chip resource module
- perf/core: Fix a memory leak in perf_event_parse_addr_filter()
- mm/rmap: fixup copying of soft dirty and uffd ptes
- mm: madvise: fix vma user-after-free
- svcrdma: fix bounce buffers for unaligned offsets and multiple pages
- net/mlx5: Don't call timecounter cyc2time directly from 1PPS flow
- net/tls: sendfile fails with ktls offload
- tipc: fix the skb_unshare() in tipc_buf_append()
- mlx4: handle non-napi callers to napi_poll
- net/mlx5e: Fix VLAN create flow
- net/mlx5e: Fix VLAN cleanup flow
- openvswitch: handle DNAT tuple collision
- xfrmi: drop ignore_df check before updating pmtu
- net: openvswitch: use div_u64() for 64-by-32 divisions
- e1000: Do not perform reset in reset_task if we are already down
- tipc: fix memory leak in service subscripting
- net: openvswitch: use u64 for meter bucket
- svcrdma: Fix leak of transport addresses
- net: sch_generic: aviod concurrent reset and enqueue op for lockless qdisc
- cpufreq: CPPC: put ACPI table after using it
- cpufreq : CPPC: Break out if HiSilicon CPPC workaround is matched
- tty/amba-pl011: Call acpi_put_table() to fix memory leak
- irqchip/gicv3: Call acpi_put_table() to fix memory leak
- partitions/efi: Fix partition name parsing in GUID partition entry
- tty: make FONTX ioctl use the tty pointer they were actually passed
- vt: keyboard, extend func_buf_lock to readers
- vt: keyboard, simplify vt_kdgkbsent
- binder: fix UAF when releasing todo list
- bpf: Fix clobbering of r2 in bpf_gen_ld_abs
- bpf: Remove recursion prevention from rcu free callback
- ipvs: Fix uninit-value in do_ip_vs_set_ctl()
- xfs: make sure the rt allocator doesn't run off the end
- ip_gre: set dev->hard_header_len and dev->needed_headroom properly
- crypto: ccp - fix error handling
- netfilter: nf_fwd_netdev: clear timestamp in forwarding path
- netfilter: conntrack: connection timeout after re-register
- vfio iommu type1: Fix memory leak in vfio_iommu_type1_pin_pages
- vfio/pci: Clear token on bypass registration failure
- ext4: limit entries returned when counting fsmap records
- watchdog: Use put_device on error
- watchdog: Fix memleak in watchdog_cdev_register
- watchdog: initialize device before misc_register
- ramfs: fix nommu mmap with gaps in the page cache
- lib/crc32.c: fix trivial typo in preprocessor condition
- xfs: fix high key handling in the rt allocator's query_range function
- xfs: limit entries returned when counting fsmap records
- mm, oom_adj: don't loop through tasks in __set_oom_adj when not necessary
- mm/memcg: fix device private memcg accounting
- netfilter: nf_log: missing vlan offload tag and proto
- ipvs: clear skb->tstamp in forwarding path
- cifs: Return the error from crypt_message when enc/dec key not found.
- cifs: remove bogus debug code
- icmp: randomize the global rate limiter
- tcp: fix to update snd_wl1 in bulk receiver fast path
- net/sched: act_tunnel_key: fix OOB write in case of IPv6 ERSPAN tunnels
- net/ipv4: always honour route mtu during forwarding
- net: fix pos incrementment in ipv6_route_seq_next
- ipv4: Restore flowi4_oif update before call to xfrm_lookup_route
- mm: khugepaged: recalculate min_free_kbytes after memory hotplug as expected by khugepaged
- perf: Fix task_function_call() error handling
- bonding: set dev->needed_headroom in bond_setup_by_slave()
- xfrm: Use correct address family in xfrm_state_find
- xfrm: clone whole liftime_cur structure in xfrm_do_migrate
- xfrm: clone XFRMA_SEC_CTX in xfrm_do_migrate
- xfrm: clone XFRMA_REPLAY_ESN_VAL in xfrm_do_migrate
- xfrm: clone XFRMA_SET_MARK in xfrm_do_migrate
- sctp: fix sctp_auth_init_hmacs() error path
- cifs: Fix incomplete memory allocation on setxattr path
- mm/khugepaged: fix filemap page_to_pgoff(page) != offset
- nvme-core: put ctrl ref when module ref get fail
- usermodehelper: reset umask to default before executing user process
- netfilter: ctnetlink: add a range check for l3/l4 protonum
- ep_create_wakeup_source(): dentry name can change under you...
- epoll: EPOLL_CTL_ADD: close the race in decision to take fast path
- epoll: replace ->visited/visited_list with generation count
- epoll: do not insert into poll queues until all sanity checks are done
- mm: don't rely on system state to detect hot-plug operations
- mm: replace memmap_context by meminit_context
- random32: Restore __latent_entropy attribute on net_rand_state
- nfs: Fix security label length not being reset
- nvme-core: get/put ctrl and transport module in nvme_dev_open/release()
- ftrace: Move RCU is watching check after recursion check
- mm, THP, swap: fix allocating cluster for swapfile by mistake
- kprobes: Fix to check probe enabled before disarm_kprobe_ftrace()
- tracing: fix double free
- bpf: Fix a rcu warning for bpffs map pretty-print
- lockdep: fix order in trace_hardirqs_off_caller()
- nvme: explicitly update mpath disk capacity on revalidation
- perf parse-events: Use strcmp() to compare the PMU name
- vfio/pci: fix racy on error and request eventfd ctx
- nvme: fix possible deadlock when I/O is blocked
- cifs: Fix double add page to memcg when cifs_readpages
- vfio/pci: Clear error and request eventfd ctx after releasing
- perf kcore_copy: Fix module map when there are no modules loaded
- perf metricgroup: Free metric_events on error
- perf util: Fix memory leak of prefix_if_not_in
- perf stat: Fix duration_time value for higher intervals
- perf evsel: Fix 2 memory leaks
- vfio/pci: fix memory leaks of eventfd ctx
- printk: handle blank console arguments passed in.
- arm64/cpufeature: Drop TraceFilt feature exposure from ID_DFR0 register
- fuse: don't check refcount after stealing page
- perf mem2node: Avoid double free related to realloc
- bdev: Reduce time holding bd_mutex in sync in blkdev_close()
- mm/mmap.c: initialize align_offset explicitly for vm_unmapped_area
- mm/vmscan.c: fix data races using kswapd_classzone_idx
- mm/filemap.c: clear page error before actual read
- mm/kmemleak.c: use address-of operator on section symbols
- NFS: Fix races nfs_page_group_destroy() vs nfs_destroy_unlinked_subrequests()
- PCI: pciehp: Fix MSI interrupt race
- SUNRPC: Fix a potential buffer overflow in 'svc_print_xprts()'
- nvme-multipath: do not reset on unknown status
- perf cpumap: Fix snprintf overflow check
- serial: 8250: 8250_omap: Terminate DMA before pushing data on RX timeout
- serial: 8250_omap: Fix sleeping function called from invalid context during probe
- serial: 8250_port: Don't service RX FIFO if throttled
- perf parse-events: Fix 3 use after frees found with clang ASAN
- xfs: mark dir corrupt when lookup-by-hash fails
- xfs: don't ever return a stale pointer from __xfs_dir3_free_read
- mm: avoid data corruption on CoW fault into PFN-mapped VMA
- perf jevents: Fix leak of mapfile memory
- random: fix data races at timer_rand_state
- selinux: sel_avc_get_stat_idx should increase position index
- audit: CONFIG_CHANGE don't log internal bookkeeping as an event
- skbuff: fix a data race in skb_queue_len()
- mm/swapfile.c: swap_next should increase position index
- tracing: Set kernel_stack's caller size properly
- ACPI: EC: Reference count query handlers under lock
- sctp: move trace_sctp_probe_path into sctp_outq_sack
- ipv6_route_seq_next should increase position index
- rt_cpu_seq_next should increase position index
- neigh_stat_seq_next() should increase position index
- xfs: fix log reservation overflows when allocating large rt extents
- kernel/sys.c: avoid copying possible padding bytes in copy_to_user
- xfs: fix attr leaf header freemap.size underflow
- fix dget_parent() fastpath race
- net: silence data-races on sk_backlog.tail
- mm: fix double page fault on arm64 if PTE_AF is cleared
- sdei_watchdog: avoid possible false hardlockup
- xen/pciback: use lateeoi irq binding
- xen/pvcallsback: use lateeoi irq binding
- xen/scsiback: use lateeoi irq binding
- xen/netback: use lateeoi irq binding
- xen/blkback: use lateeoi irq binding
- xen/events: fix race in evtchn_fifo_unmask()
- xen/events: add a proper barrier to 2-level uevent unmasking
- arm64: fix abi change caused by ILP32

* Fri Oct 30 2020 Yang Yingliang <yangyingliang@huawei.com> - 4.19.90-2010.2.0.0046
- rtc: cmos: Revert "rtc: Fix the AltCentury value on AMD/Hygon platform"
- NTB: Fix static check warning in perf_clear_test
- NTB: ntb_perf: Fix address err in perf_copy_chunk
- NTB: Fix an error in get link status
- rtc: Fix the AltCentury value on AMD/Hygon platform
- tools/power turbostat: Add support for Hygon Fam 18h (Dhyana) RAPL
- tools/power turbostat: Fix caller parameter of get_tdp_amd()
- tools/power turbostat: Also read package power on AMD F17h (Zen)
- tools/power turbostat: Add support for AMD Fam 17h (Zen) RAPL
- NTB: Add Hygon Device ID
- x86/amd_nb: Make hygon_nb_misc_ids static
- i2c-piix4: Add Hygon Dhyana SMBus support
- x86/CPU/hygon: Fix phys_proc_id calculation logic for multi-die processors
- hwmon: (k10temp) Add Hygon Dhyana support
- tools/cpupower: Add Hygon Dhyana support
- EDAC, amd64: Add Hygon Dhyana support
- cpufreq: Add Hygon Dhyana support
- ACPI: Add Hygon Dhyana support
- x86/xen: Add Hygon Dhyana support to Xen
- x86/kvm: Add Hygon Dhyana support to KVM
- x86/mce: Add Hygon Dhyana support to the MCA infrastructure
- x86/bugs: Add Hygon Dhyana to the respective mitigation machinery
- x86/apic: Add Hygon Dhyana support
- x86/pci, x86/amd_nb: Add Hygon Dhyana support to PCI and northbridge
- x86/amd_nb: Check vendor in AMD-only functions
- x86/alternative: Init ideal_nops for Hygon Dhyana
- x86/events: Add Hygon Dhyana support to PMU infrastructure
- x86/smpboot: Do not use BSP INIT delay and MWAIT to idle on Dhyana
- x86/cpu/mtrr: Support TOP_MEM2 and get MTRR number
- x86/cpu: Get cache info and setup cache cpumap for Hygon Dhyana
- x86/cpu: Create Hygon Dhyana architecture support file
- kvm: debugfs: aarch64 export cpu time related items to debugfs
- kvm: debugfs: export remaining aarch64 kvm exit reasons to debugfs
- kvm: debugfs: Export vcpu stat via debugfs
- kvm: fix compile error when including linux/kvm.h
- kvm: arm64: add KVM_CAP_ARM_CPU_FEATURE extension
- kvm: arm64: make ID registers configurable
- kvm: arm64: emulate the ID registers
- arm64: add a helper function to traverse arm64_ftr_regs
- xen/events: defer eoi in case of excessive number of events
- xen/events: use a common cpu hotplug hook for event channels
- xen/events: switch user event channels to lateeoi model
- xen/events: add a new "late EOI" evtchn framework
- xen/events: avoid removing an event channel while handling it
- net/hinic: update hinic version to 2.3.2.16
- net/hinic: Allowed to send commands when only hot activation of ucode
- net/hinic: Fix ethtool loopback test failure
- net/hinic: VF is not allowed to configure global resources
- net/hinic: Allow to remove administratively set MAC on VFs
- net/hinic: Fix the driver does not report an error when setting MAC fails
- Bluetooth: MGMT: Fix not checking if BT_HS is enabled
- Bluetooth: Disable High Speed by default
- Bluetooth: L2CAP: Fix calling sk_filter on non-socket based channel
- Bluetooth: A2MP: Fix not initializing all members
- perf/core: Fix race in the perf_mmap_close() function
- geneve: add transport ports in route lookup for geneve
- ext4: only set last error block when check system zone failed
- xfs: Fix tail rounding in xfs_alloc_file_space()
- KEYS: reaching the keys quotas correctly
- serial: 8250: Avoid error message on reprobe
- mm: memcg: fix memcg reclaim soft lockup
- mm/thp: fix __split_huge_pmd_locked() for migration PMD
- kprobes: fix kill kprobe which has been marked as gone
- percpu: fix first chunk size calculation for populated bitmap
- spi: Fix memory leak on splited transfers
- nvme-rdma: cancel async events before freeing event struct
- nvme-fc: cancel async events before freeing event struct
- NFS: Zero-stateid SETATTR should first return delegation
- scsi: target: iscsi: Fix hang in iscsit_access_np() when getting tpg->np_login_sem
- scsi: target: iscsi: Fix data digest calculation
- xfs: initialize the shortform attr header padding entry
- block: ensure bdi->io_pages is always initialized
- dm writecache: handle DAX to partitions on persistent memory correctly
- libata: implement ATA_HORKAGE_MAX_TRIM_128M and apply to Sandisks
- uaccess: Add non-pagefault user-space write function
- uaccess: Add non-pagefault user-space read functions
- xfs: don't update mtime on COW faults
- include/linux/log2.h: add missing () around n in roundup_pow_of_two()
- perf jevents: Fix suspicious code in fixregex()
- xfs: fix xfs_bmap_validate_extent_raw when checking attr fork of rt files
- fix regression in "epoll: Keep a reference on files added to the check list"
- perf tools: Correct SNOOPX field offset
- cpuidle: Fixup IRQ state
- tpm: Unify the mismatching TPM space buffer sizes
- device property: Fix the secondary firmware node handling in set_primary_fwnode()
- PM: sleep: core: Fix the handling of pending runtime resume requests
- writeback: Fix sync livelock due to b_dirty_time processing
- writeback: Avoid skipping inode writeback
- writeback: Protect inode->i_io_list with inode->i_lock
- serial: 8250: change lock order in serial8250_do_startup()
- serial: 8250_exar: Fix number of ports for Commtech PCIe cards
- serial: pl011: Don't leak amba_ports entry on driver register error
- serial: pl011: Fix oops on -EPROBE_DEFER
- vt_ioctl: change VT_RESIZEX ioctl to check for error return from vc_resize()
- vt: defer kfree() of vc_screenbuf in vc_do_resize()
- blk-mq: order adding requests to hctx->dispatch and checking SCHED_RESTART
- fs: prevent BUG_ON in submit_bh_wbc()
- ext4: handle option set by mount flags correctly
- ext4: handle read only external journal device
- ext4: don't BUG on inconsistent journal feature
- jbd2: make sure jh have b_transaction set in refile/unfile_buffer
- scsi: fcoe: Memory leak fix in fcoe_sysfs_fcf_del()
- scsi: iscsi: Do not put host in iscsi_set_flashnode_param()
- locking/lockdep: Fix overflow in presentation of average lock-time
- PCI: Fix pci_create_slot() reference count leak
- xfs: Don't allow logging of XFS_ISTALE inodes
- iommu/iova: Don't BUG on invalid PFNs
- mm/hugetlb: fix calculation of adjust_range_if_pmd_sharing_possible
- do_epoll_ctl(): clean the failure exits up a bit
- epoll: Keep a reference on files added to the check list
- efi: add missed destroy_workqueue when efisubsys_init fails
- RDMA/bnxt_re: Do not add user qps to flushlist
- vfio/type1: Add proper error unwind for vfio_iommu_replay()
- fs/signalfd.c: fix inconsistent return codes for signalfd4
- xfs: Fix UBSAN null-ptr-deref in xfs_sysfs_init
- virtio_ring: Avoid loop when vq is broken in virtqueue_poll
- xfs: fix inode quota reservation checks
- scsi: target: tcmu: Fix crash in tcmu_flush_dcache_range on ARM
- spi: Prevent adding devices below an unregistering controller
- jbd2: add the missing unlock_buffer() in the error path of jbd2_write_superblock()
- ext4: fix checking of directory entry validity for inline directories
- mm, page_alloc: fix core hung in free_pcppages_bulk()
- mm: include CMA pages in lowmem_reserve at boot
- kernel/relay.c: fix memleak on destroy relay channel
- khugepaged: adjust VM_BUG_ON_MM() in __khugepaged_enter()
- khugepaged: khugepaged_test_exit() check mmget_still_valid()
- perf probe: Fix memory leakage when the probe point is not found
- xfs: fix duplicate verification from xfs_qm_dqflush()
- xfs: reset buffer write failure state on successful completion
- xfs: fix partially uninitialized structure in xfs_reflink_remap_extent
- xfs: clear PF_MEMALLOC before exiting xfsaild thread
- xfs: acquire superblock freeze protection on eofblocks scans
- xfs: Fix deadlock between AGI and AGF with RENAME_WHITEOUT
- macvlan: validate setting of multiple remote source MAC addresses
- blk-mq: insert flush request to the front of dispatch queue
- blk-mq: Rerun dispatching in the case of budget contention
- blk-mq: Add blk_mq_delay_run_hw_queues() API call
- blk-mq: In blk_mq_dispatch_rq_list() "no budget" is a reason to kick
- blk-mq: Put driver tag in blk_mq_dispatch_rq_list() when no budget
- blk-mq: insert passthrough request into hctx->dispatch directly
- arm64/ascend: Fix register_persistent_clock definition
- net: add __must_check to skb_put_padto()
- netfilter: nf_tables: incorrect enum nft_list_attributes definition
- tcp_bbr: adapt cwnd based on ack aggregation estimation
- tcp_bbr: refactor bbr_target_cwnd() for general inflight provisioning
- ipv4: Update exception handling for multipath routes via same device
- tipc: use skb_unshare() instead in tipc_buf_append()
- tipc: fix shutdown() of connection oriented socket
- tipc: Fix memory leak in tipc_group_create_member()
- ipv6: avoid lockdep issue in fib6_del()
- ip: fix tos reflection in ack and reset packets
- af_key: pfkey_dump needs parameter validation
- SUNRPC: stop printk reading past end of string
- net: handle the return value of pskb_carve_frag_list() correctly
- net/mlx5e: Don't support phys switch id if not in switchdev mode
- net: disable netpoll on fresh napis
- tipc: fix shutdown() of connectionless socket
- sctp: not disable bh in the whole sctp_get_port_local()
- net: ethernet: mlx4: Fix memory allocation in mlx4_buddy_init()
- netfilter: nfnetlink: nfnetlink_unicast() reports EAGAIN instead of ENOBUFS
- netfilter: nf_tables: fix destination register zeroing
- netfilter: nf_tables: add NFTA_SET_USERDATA if not null
- scsi: fcoe: Fix I/O path allocation
- ipvlan: fix device features
- tipc: fix uninit skb->data in tipc_nl_compat_dumpit()
- net: Fix potential wrong skb->protocol in skb_vlan_untag()
- gre6: Fix reception with IP6_TNL_F_RCV_DSCP_COPY
- bonding: fix active-backup failover for current ARP slave
- bonding: fix a potential double-unregister
- bonding: show saner speed for broadcast mode
- i40e: Fix crash during removing i40e driver
- i40e: Set RX_ONLY mode for unicast promiscuous on VLAN
- svcrdma: Fix another Receive buffer leak
- net/compat: Add missing sock updates for SCM_RIGHTS
- net: initialize fastreuse on inet_inherit_port
- net: refactor bind_bucket fastreuse into helper
- net/tls: Fix kmap usage
- net: Set fput_needed iff FDPUT_FPUT is set
- af_packet: TPACKET_V3: fix fill status rwlock imbalance
- ipvs: allow connection reuse for unconfirmed conntrack
- xfrm: Fix crash when the hold queue is used.
- net sched: fix reporting the first-time use timestamp
- IB/mlx5: Replace tunnel mpls capability bits for tunnel_offloads
- fib: add missing attribute validation for tun_id
- net/mlx5: Fix mlx5_ifc_query_lag_out_bits
- mpls: fix warning with multi-label encap
- hdlc_ppp: add range checks in ppp_cp_parse_cr()
- spi/ascend: Add spi-cpld to device tree compatibility list
- net: hns3: update hns3 version to 1.9.38.8
- net: hns3: modify the sensitive words
- block: allow for_each_bvec to support zero len bvec
- HID: hid-input: clear unmapped usages
- net/nfc/rawsock.c: add CAP_NET_RAW check.
- arm64/ascend: Implement the read_persistend_clock64 for aarch64
- ext4: clear buffer verified flag if read metadata from disk
- ext4: Fix bdev write error check failed when mount fs with ro
- loop: Report EOPNOTSUPP properly

* Wed Sep 23 2020 Yang Yingliang <yangyingliang@huawei.com> - 4.19.90-2009.3.0.0045
- acpi/arm64: check the returned logical CPU number of 'acpi_map_cpuid()'
- staging: most: net: fix buffer overflow
- block: Do not discard buffers under a mounted filesystem
- block: refactor bd_start_claiming
- fs: Don't invalidate page buffers in block_write_full_page()
- ilp32: fix compile problem when ARM64_ILP32 and UBSAN are both enabled
- locking/percpu-rwsem: use this_cpu_{inc|dec}() for read_count
- scsi: libsas: Set data_dir as DMA_NONE if libata marks qc as NODATA
- Btrfs: fix selftests failure due to uninitialized i_mode in test inodes
- btrfs: inode: Verify inode mode to avoid NULL pointer dereference
- drm/ttm: fix incrementing the page pointer for huge pages
- drm/ttm: fix start page for huge page check in ttm_put_pages()
- media: uvcvideo: Avoid cyclic entity chains due to malformed USB descriptors
- fbcon: remove now unusued 'softback_lines' cursor() argument
- fbcon: remove soft scrollback code
- mm/hugetlb: fix a race between hugetlb sysctl handlers
- nfs: Fix getxattr kernel panic and memory overflow
- net/packet: fix overflow in tpacket_rcv
- net/packet: make tp_drops atomic
- ext4: fix potential negative array index in do_split()
- rbd: require global CAP_SYS_ADMIN for mapping and unmapping
- xfs: fix boundary test in xfs_attr_shortform_verify
- xfs: use the latest extent at writeback delalloc conversion time
- xfs: validate writeback mapping using data fork seq counter
- xfs: create delalloc bmapi wrapper for full extent allocation
- xfs: refactor AGI unlinked bucket updates
- xfs: add xfs_verify_agino_or_null helper
- xfs: clean up iunlink functions
- arm64/ascend: enable ascend features for Ascend910 platform
- arm64/ascend: Add auto tuning hugepage module
- arm64/ascend: Enable CONFIG_ASCEND_AUTO_TUNING_HUGEPAGE for hulk_defconfig
- arm64/ascend: Notifier will return a freed val to indecate print logs
- arm64/ascend: Add hugepage flags change interface
- arm64/ascend: Add set hugepage number helper function
- arm64/ascend: Add mmap hook when alloc hugepage
- arm64/ascend: Add new CONFIG for auto-tuning hugepage
- dm thin metadata: Fix use-after-free in dm_bm_set_read_only
- dm thin metadata: Avoid returning cmd->bm wild pointer on error
- dm cache metadata: Avoid returning cmd->bm wild pointer on error
- watchdog: Enable CONFIG_ASCEND_WATCHDOG_SYSFS_CONFIGURE in hulk_defconfig
- watchdog: Add interface to config timeout and pretimeout in sysfs
- mm/swapfile: fix and annotate various data races
- serial: 8250: fix null-ptr-deref in serial8250_start_tx()
- timekeeping: Prevent 32bit truncation in scale64_check_overflow()
- lib : kobject: fix refcount imblance on kobject_rename
- genirq/debugfs: Add missing sanity checks to interrupt injection
- ovl: fix WARN_ON nlink drop to zero
- ovl: fix some xino configurations
- ovl: fix corner case of non-constant st_dev; st_ino
- ovl: fix corner case of conflicting lower layer uuid
- ovl: generalize the lower_fs[] array
- ovl: simplify ovl_same_sb() helper
- ovl: generalize the lower_layers[] array
- ovl: fix lookup failure on multi lower squashfs
- fat: don't allow to mount if the FAT length == 0
- serial: amba-pl011: Make sure we initialize the port.lock spinlock
- perf top: Fix wrong hottest instruction highlighted
- xfs: prohibit fs freezing when using empty transactions
- xfs: Use scnprintf() for avoiding potential buffer overflow
- xfs: use bitops interface for buf log item AIL flag check
- xfs: fix some memory leaks in log recovery
- xfs: convert EIO to EFSCORRUPTED when log contents are invalid
- xfs: fix inode fork extent count overflow
- nvme: fix memory leak caused by incorrect subsystem free
- nvme: fix possible deadlock when nvme_update_formats fails
- dm verity: don't prefetch hash blocks for already-verified data
- arm64: kprobes: Recover pstate.D in single-step exception handler
- nbd: fix possible page fault for nbd disk
- nbd: rename the runtime flags as NBD_RT_ prefixed
- jbd2: flush_descriptor(): Do not decrease buffer head's ref count
- Revert "dm crypt: use WQ_HIGHPRI for the IO and crypt workqueues"
- ACPICA: Win OSL: Replace get_tick_count with get_tick_count64
- ext4: avoid fetching btime in ext4_getattr() unless requested
- mm: pagewalk: fix termination condition in walk_pte_range()
- mm/huge_memory.c: use head to check huge zero page
- mm/page-writeback.c: improve arithmetic divisions
- mm/page-writeback.c: use div64_ul() for u64-by-unsigned-long divide
- PCI: PM/ACPI: Refresh all stale power state data in pci_pm_complete()
- ACPI: PM: Fix regression in acpi_device_set_power()
- ACPI: PM: Allow transitions to D0 to occur in special cases
- ACPI: PM: Avoid evaluating _PS3 on transitions from D3hot to D3cold
- iommu/arm-smmu: Mark expected switch fall-through
- efi/memreserve: Register reservations as 'reserved' in /proc/iomem
- compat_ioctl: handle SIOCOUTQNSD
- mm: slub: fix conversion of freelist_corrupted()
- khugepaged: retract_page_tables() remember to test exit
- kprobes: Fix NULL pointer dereference at kprobe_ftrace_handler
- ftrace: Setup correct FTRACE_FL_REGS flags for module
- mm/page_counter.c: fix protection usage propagation
- driver core: Avoid binding drivers to dead devices
- genirq/affinity: Make affinity setting if activated opt-in
- mm/mmap.c: Add cond_resched() for exit_mmap() CPU stalls
- sched: correct SD_flags returned by tl->sd_flags()
- sched/fair: Fix NOHZ next idle balance
- xattr: break delegations in {set, remove}xattr
- firmware: Fix a reference count leak.
- ext4: fix direct I/O read error
- arm64: csum: Fix handling of bad packets
- arm64/alternatives: move length validation inside the subsection
- bpf: Fix map leak in HASH_OF_MAPS map
- dm integrity: fix integrity recalculation that is improperly skipped
- io-mapping: indicate mapping failure
- vt: Reject zero-sized screen buffer size.
- fuse: fix weird page warning
- printk: queue wake_up_klogd irq_work only if per-CPU areas are ready
- genirq/affinity: Handle affinity setting on inactive interrupts correctly
- sched/fair: handle case of task_h_load() returning 0
- sched: Fix unreliable rseq cpu_id for new tasks
- timer: Fix wheel index calculation on last level
- timer: Prevent base->clk from moving backward
- uio_pdrv_genirq: fix use without device tree and no interrupt
- fuse: Fix parameter for FS_IOC_{GET, SET}FLAGS
- ovl: fix unneeded call to ovl_change_flags()
- ovl: relax WARN_ON() when decoding lower directory file handle
- ovl: inode reference leak in ovl_is_inuse true case.
- arm64/alternatives: don't patch up internal branches
- arm64/alternatives: use subsections for replacement sequences
- block: release bip in a right way in error path
- cifs: update ctime and mtime during truncate
- dm zoned: assign max_io_len correctly
- virtio-blk: free vblk-vqs in error path of virtblk_probe()
- mm/slub: fix stack overruns with SLUB_STATS
- mm/slub.c: fix corrupted freechain in deactivate_slab()
- mm: fix swap cache node allocation mask
- dm writecache: add cond_resched to loop in persistent_memory_claim()
- dm writecache: correct uncommitted_block when discarding uncommitted entry
- ring-buffer: Zero out time extend if it is nested and not absolute
- mm/slab: use memzero_explicit() in kzfree()
- sched/core: Fix PI boosting between RT and DEADLINE tasks
- sched/deadline: Initialize ->dl_boosted
- efi/esrt: Fix reference count leak in esre_create_sysfs_entry.
- loop: replace kill_bdev with invalidate_bdev
- fanotify: fix ignore mask logic for events on child and on dir
- md: add feature flag MD_FEATURE_RAID0_LAYOUT
- kretprobe: Prevent triggering kretprobe from within kprobe_flush_task
- ext4: avoid race conditions when remounting with options that change dax
- ext4: fix partial cluster initialization when splitting extent
- selinux: fix double free
- arm64: hw_breakpoint: Don't invoke overflow handler on uaccess watchpoints
- lib/zlib: remove outdated and incorrect pre-increment optimization
- vfio/mdev: Fix reference count leak in add_mdev_supported_type
- PCI: dwc: Fix inner MSI IRQ domain registration
- dm zoned: return NULL if dmz_get_zone_for_reclaim() fails to find a zone
- ipmi: use vzalloc instead of kmalloc for user creation
- PCI: Fix pci_register_host_bridge() device_register() error handling
- drivers: base: Fix NULL pointer exception in __platform_driver_probe() if a driver developer is foolish
- scsi: sr: Fix sr_probe() missing deallocate of device minor
- vfio/pci: fix memory leaks in alloc_perm_bits()
- PCI: Allow pci_resize_resource() for devices on root bus
- ipmi: fix sleep-in-atomic in free_user at cleanup SRCU user->release_barrier
- Revert "ipmi: fix sleep-in-atomic in free_user at cleanup SRCU user->release_barrier"
- kernel/cpu_pm: Fix uninitted local in cpu_pm
- ext4: fix race between ext4_sync_parent() and rename()
- ext4: fix EXT_MAX_EXTENT/INDEX to check for zeroed eh_max
- mm: initialize deferred pages with interrupts enabled
- cpuidle: Fix three reference count leaks
- spi: dw: Return any value retrieved from the dma_transfer callback
- PCI: Don't disable decoding when mmio_always_on is set
- sched/core: Fix illegal RCU from offline CPUs
- audit: fix a net reference leak in audit_list_rules_send()
- audit: fix a net reference leak in audit_send_reply()
- spi: dw: Fix Rx-only DMA transfers
- spi: dw: Enable interrupts in accordance with DMA xfer mode
- arm64: insn: Fix two bugs in encoding 32-bit logical immediates
- spi: dw: Zero DMA Tx and Rx configurations on stack
- perf: Add cond_resched() to task_function_call()
- mm/slub: fix a memory leak in sysfs_slab_add()
- proc: Use new_inode not new_inode_pseudo
- ovl: initialize error in ovl_copy_xattr
- spi: Fix controller unregister order
- spi: No need to assign dummy value in spi_unregister_controller()
- spi: dw: Fix controller unregister order
- ACPI: CPPC: Fix reference count leak in acpi_cppc_processor_probe()
- ACPI: sysfs: Fix reference count leak in acpi_sysfs_add_hotplug_profile()
- efi/efivars: Add missing kobject_put() in sysfs entry creation error path
- aio: fix async fsync creds
- mm: add kvfree_sensitive() for freeing sensitive data objects
- sched/fair: Don't NUMA balance for kthreads
- lib: Reduce user_access_begin() boundaries in strncpy_from_user() and strnlen_user()
- tun: correct header offsets in napi frags mode
- spi: dw: use "smp_mb()" to avoid sending spi data error
- Revert "cgroup: Add memory barriers to plug cgroup_rstat_updated() race window"
- iommu: Fix reference count leak in iommu_group_alloc.
- mm: remove VM_BUG_ON(PageSlab()) from page_mapcount()
- exec: Always set cap_ambient in cap_bprm_set_creds
- padata: purge get_cpu and reorder_via_wq from padata_do_serial
- padata: initialize pd->cpu with effective cpumask
- padata: Replace delayed timer with immediate workqueue in padata_reorder
- fix multiplication overflow in copy_fdtable()
- exec: Move would_dump into flush_old_exec
- cifs: fix leaked reference on requeued write
- arm64: fix the flush_icache_range arguments in machine_kexec
- NFSv4: Fix fscache cookie aux_data to ensure change_attr is included
- nfs: fscache: use timespec64 in inode auxdata
- NFS: Fix fscache super_cookie index_key from changing after umount
- ipc/util.c: sysvipc_find_ipc() incorrectly updates position index
- net: phy: fix aneg restart in phy_ethtool_set_eee
- virtio-blk: handle block_device_operations callbacks after hot unplug
- shmem: fix possible deadlocks on shmlock_user_lock
- ipc/mqueue.c: change __do_notify() to bypass check_kill_permission()
- coredump: fix crash when umh is disabled
- mm/page_alloc: fix watchdog soft lockups during set_zone_contiguous()
- arm64: hugetlb: avoid potential NULL dereference
- cifs: protect updating server->dstaddr with a spinlock
- vfio: avoid possible overflow in vfio_iommu_type1_pin_pages
- propagate_one(): mnt_set_mountpoint() needs mount_lock
- ext4: check for non-zero journal inum in ext4_calculate_overhead
- ext4: convert BUG_ON's to WARN_ON's in mballoc.c
- ext4: increase wait time needed before reuse of deleted inode numbers
- ext4: use matching invalidatepage in ext4_writepage
- mm: shmem: disable interrupt when acquiring info->lock in userfaultfd_copy path
- perf/core: fix parent pid/tid in task exit events
- vt: don't hardcode the mem allocation upper bound
- audit: check the length of userspace generated audit records
- tpm/tpm_tis: Free IRQ if probing fails
- mm/ksm: fix NULL pointer dereference when KSM zero page is enabled
- mm/hugetlb: fix a addressing exception caused by huge_pte_offset
- vmalloc: fix remap_vmalloc_range() bounds checks
- KEYS: Avoid false positive ENOMEM error on key read
- loop: Better discard support for block devices
- ipc/util.c: sysvipc_find_ipc() should increase position index
- scsi: iscsi: Report unbind session event when the target has been removed
- watchdog: reset last_hw_keepalive time at start
- ext4: fix extent_status fragmentation for plain files
- bpf: fix buggy r0 retval refinement for tracing helpers
- NFS: Fix memory leaks in nfs_pageio_stop_mirroring()
- percpu_counter: fix a data race at vm_committed_as
- cifs: Allocate encryption header through kmalloc
- ext4: do not commit super on read-only bdev
- NFS: direct.c: Fix memory leak of dreq when nfs_get_lock_context fails
- irqchip/mbigen: Free msi_desc on device teardown
- ext4: use non-movable memory for superblock readahead
- mm/vmalloc.c: move 'area->pages' after if statement
- ext4: do not zeroout extents beyond i_disksize
- tracing: Fix the race between registering 'snapshot' event trigger and triggering 'snapshot' operation
- keys: Fix proc_keys_next to increase position index
- ext4: fix incorrect inodes per group in error message
- ext4: fix incorrect group count in ext4_fill_super error message
- ovl: fix value of i_ino for lower hardlink corner case
- dm zoned: remove duplicate nr_rnd_zones increase in dmz_init_zone()
- ipmi: fix hung processes in __get_guid()
- libata: Return correct status in sata_pmp_eh_recover_pm() when ATA_DFLAG_DETACH is set
- kmod: make request_module() return an error when autoloading is disabled
- NFS: Fix a page leak in nfs_destroy_unlinked_subrequests()
- dm verity fec: fix memory leak in verity_fec_dtr
- dm writecache: add cond_resched to avoid CPU hangs
- mm: Use fixed constant in page_frag_alloc instead of size + 1
- tpm: tpm2_bios_measurements_next should increase position index
- tpm: tpm1_bios_measurements_next should increase position index
- tpm: Don't make log failures fatal
- PCI/ASPM: Clear the correct bits when enabling L1 substates
- md: check arrays is suspended in mddev_detach before call quiesce operations
- irqchip/gic-v4: Provide irq_retrigger to avoid circular locking dependency
- block: Fix use-after-free issue accessing struct io_cq
- genirq/irqdomain: Check pointer in irq_domain_alloc_irqs_hierarchy()
- libata: Remove extra scsi_host_put() in ata_scsi_add_hosts()
- sched: Avoid scale real weight down to zero
- block: keep bdi->io_pages in sync with max_sectors_kb for stacked devices
- firmware: arm_sdei: fix double-lock on hibernate with shared events
- arm64: Fix size of __early_cpu_boot_status
- random: always use batched entropy for get_random_u{32, 64}
- padata: always acquire cpu_hotplug_lock before pinst->lock
- bpf: Explicitly memset some bpf info structures declared on the stack
- bpf: Explicitly memset the bpf_attr structure
- libfs: fix infoleak in simple_attr_read()
- bpf/btf: Fix BTF verification of enum members in struct/union
- genirq: Fix reference leaks on irq affinity notifiers
- scsi: sd: Fix optimal I/O size for devices that change reported values
- scsi: ipr: Fix softlockup when rescanning devices in petitboot
- nfs: add minor version to nfs_server_key for fscache
- arm64: smp: fix crash_smp_send_stop() behaviour
- arm64: smp: fix smp_send_stop() behaviour
- mm, slub: prevent kmalloc_node crashes and memory leaks
- mm: slub: be more careful about the double cmpxchg of freelist
- block, bfq: fix overwrite of bfq_group pointer in bfq_find_set_group()
- mm: slub: add missing TID bump in kmem_cache_alloc_bulk()
- driver core: Fix creation of device links with PM-runtime flags
- driver core: Remove device link creation limitation
- driver core: Add device link flag DL_FLAG_AUTOPROBE_CONSUMER
- driver core: Make driver core own stateful device links
- driver core: Fix adding device links to probing suppliers
- driver core: Remove the link if there is no driver with AUTO flag
- jbd2: fix data races at struct journal_head
- signal: avoid double atomic counter increments for user accounting
- cifs_atomic_open(): fix double-put on late allocation failure
- workqueue: don't use wq_select_unbound_cpu() for bound works
- virtio-blk: fix hw_queue stopped on arbitrary error
- dm writecache: verify watermark during resume
- dm: report suspended device during destroy
- dm cache: fix a crash due to incorrect work item cancelling
- mm: fix possible PMD dirty bit lost in set_pmd_migration_entry()
- mm, numa: fix bad pmd by atomically check for pmd_trans_huge when marking page tables prot_numa
- cifs: don't leak -EAGAIN for stat() during reconnect
- audit: always check the netlink payload length in audit_receive_msg()
- audit: fix error handling in audit_data_to_entry()
- ext4: potential crash on allocation error in ext4_alloc_flex_bg_array()
- cifs: Fix mode output in debugging statements
- ipmi:ssif: Handle a possible NULL pointer reference
- irqchip/gic-v3-its: Fix misuse of GENMASK macro
- ata: ahci: Add shutdown to freeze hardware resources of ahci
- bpf, offload: Replace bitwise AND by logical AND in bpf_prog_offload_info_fill
- genirq/proc: Reject invalid affinity masks (again)
- ext4: fix race between writepages and enabling EXT4_EXTENTS_FL
- ext4: rename s_journal_flag_rwsem to s_writepages_rwsem
- ext4: fix mount failure with quota configured as module
- ext4: fix potential race between s_flex_groups online resizing and access
- ext4: fix potential race between s_group_info online resizing and access
- ext4: fix potential race between online resizing and write operations
- ext4: fix a data race in EXT4_I(inode)->i_disksize
- genirq/irqdomain: Make sure all irq domain flags are distinct
- Revert "ipc, sem: remove uneeded sem_undo_list lock usage in exit_sem()"
- jbd2: fix ocfs2 corrupt when clearing block group bits
- vt: vt_ioctl: fix race in VT_RESIZEX
- vt: fix scrollback flushing on background consoles
- NFS: Fix memory leaks
- brd: check and limit max_part par
- irqchip/gic-v3-its: Reference to its_invall_cmd descriptor when building INVALL
- irqchip/gic-v3: Only provision redistributors that are enabled in ACPI
- bpf: map_seq_next should always increase position index
- cifs: fix NULL dereference in match_prepath
- driver core: platform: fix u32 greater or equal to zero comparison
- irqchip/mbigen: Set driver .suppress_bind_attrs to avoid remove problems
- module: avoid setting info->name early in case we can fall back to info->mod->name
- watchdog/softlockup: Enforce that timestamp is valid on boot
- arm64: fix alternatives with LLVM's integrated assembler
- scsi: iscsi: Don't destroy session if there are outstanding connections
- iommu/arm-smmu-v3: Use WRITE_ONCE() when changing validity of an STE
- driver core: platform: Prevent resouce overflow from causing infinite loops
- selinux: ensure we cleanup the internal AVC counters on error in avc_update()
- selinux: ensure we cleanup the internal AVC counters on error in avc_insert()
- jbd2: clear JBD2_ABORT flag before journal_reset to update log tail info when load journal
- uio: fix a sleep-in-atomic-context bug in uio_dmem_genirq_irqcontrol()
- ext4: fix ext4_dax_read/write inode locking sequence for IOCB_NOWAIT
- cpu/hotplug, stop_machine: Fix stop_machine vs hotplug order
- nvme: fix the parameter order for nvme_get_log in nvme_get_fw_slot_info
- arm64: ssbs: Fix context-switch when SSBS is present on all CPUs
- ext4: improve explanation of a mount failure caused by a misconfigured kernel
- ext4: fix checksum errors with indexed dirs
- ext4: don't assume that mmp_nodename/bdevname have NUL
- arm64: nofpsmid: Handle TIF_FOREIGN_FPSTATE flag cleanly
- arm64: cpufeature: Set the FP/SIMD compat HWCAP bits properly
- padata: fix null pointer deref of pd->pinst
- arm64: ptrace: nofpsimd: Fail FP/SIMD regset operations
- arm64: cpufeature: Fix the type of no FP/SIMD capability
- NFSv4: try lease recovery on NFS4ERR_EXPIRED
- NFS: Revalidate the file size on a fatal write error
- nfs: NFS_SWAP should depend on SWAP
- PCI: Don't disable bridge BARs when assigning bus resources
- perf/core: Fix mlock accounting in perf_mmap()
- clocksource: Prevent double add_timer_on() for watchdog_timer
- x86/apic/msi: Plug non-maskable MSI affinity race
- mm/page_alloc.c: fix uninitialized memmaps on a partially populated last section
- mm: return zero_resv_unavail optimization
- mm: zero remaining unavailable struct pages
- ext4: fix deadlock allocating crypto bounce page from mempool
- aio: prevent potential eventfd recursion on poll
- eventfd: track eventfd_signal() recursion depth
- watchdog: fix UAF in reboot notifier handling in watchdog core code
- jbd2_seq_info_next should increase position index
- NFS: Directory page cache pages need to be locked when read
- NFS: Fix memory leaks and corruption in readdir
- padata: Remove broken queue flushing
- dm writecache: fix incorrect flush sequence when doing SSD mode commit
- dm: fix potential for q->make_request_fn NULL pointer
- dm crypt: fix benbi IV constructor crash if used in authenticated mode
- dm space map common: fix to ensure new block isn't already in use
- dm zoned: support zone sizes smaller than 128MiB
- ovl: fix wrong WARN_ON() in ovl_cache_update_ino()
- alarmtimer: Unregister wakeup source when module get fails
- irqdomain: Fix a memory leak in irq_domain_push_irq()
- rcu: Avoid data-race in rcu_gp_fqs_check_wake()
- ipc/msg.c: consolidate all xxxctl_down() functions
- kernel/module: Fix memleak in module_add_modinfo_attrs()
- mm/migrate.c: also overwrite error when it is bigger than zero
- mm/memory_hotplug: shrink zones when offlining memory
- mm/memory_hotplug: fix try_offline_node()
- mm/memunmap: don't access uninitialized memmap in memunmap_pages()
- drivers/base/node.c: simplify unregister_memory_block_under_nodes()
- mm/hotplug: kill is_dev_zone() usage in __remove_pages()
- mm/memory_hotplug: remove "zone" parameter from sparse_remove_one_section
- mm/memory_hotplug: make unregister_memory_block_under_nodes() never fail
- mm/memory_hotplug: remove memory block devices before arch_remove_memory()
- mm/memory_hotplug: create memory block devices after arch_add_memory()
- drivers/base/memory: pass a block_id to init_memory_block()
- mm/memory_hotplug: allow arch_remove_memory() without CONFIG_MEMORY_HOTREMOVE
- s390x/mm: implement arch_remove_memory()
- mm/memory_hotplug: make __remove_pages() and arch_remove_memory() never fail
- powerpc/mm: Fix section mismatch warning
- mm/memory_hotplug: make __remove_section() never fail
- mm/memory_hotplug: make unregister_memory_section() never fail
- mm, memory_hotplug: update a comment in unregister_memory()
- drivers/base/memory.c: clean up relics in function parameters
- mm/memory_hotplug: release memory resource after arch_remove_memory()
- mm, memory_hotplug: add nid parameter to arch_remove_memory
- drivers/base/memory.c: remove an unnecessary check on NR_MEM_SECTIONS
- mm, sparse: pass nid instead of pgdat to sparse_add_one_section()
- mm, sparse: drop pgdat_resize_lock in sparse_add/remove_one_section()
- arm64/mm: add temporary arch_remove_memory() implementation
- s390x/mm: fail when an altmap is used for arch_add_memory()
- mm/memory_hotplug: simplify and fix check_hotplug_memory_range()
- scsi: iscsi: Avoid potential deadlock in iscsi_if_rx func
- sd: Fix REQ_OP_ZONE_REPORT completion handling
- tun: add mutex_unlock() call and napi.skb clearing in tun_get_user()
- bpf: fix BTF limits
- scsi: libfc: fix null pointer dereference on a null lport
- iommu: Use right function to get group for device
- NFSv4/flexfiles: Fix invalid deref in FF_LAYOUT_DEVID_NODE()
- NFS: Add missing encode / decode sequence_maxsz to v4.2 operations
- driver core: Fix PM-runtime for links added during consumer probe
- driver core: Fix possible supplier PM-usage counter imbalance
- net: phy: fixed_phy: Fix fixed_phy not checking GPIO
- driver core: Do not call rpm_put_suppliers() in pm_runtime_drop_link()
- driver core: Fix handling of runtime PM flags in device_link_add()
- driver core: Do not resume suppliers under device_links_write_lock()
- driver core: Avoid careless re-use of existing device links
- driver core: Fix DL_FLAG_AUTOREMOVE_SUPPLIER device link flag handling
- Revert "efi: Fix debugobjects warning on 'efi_rts_work'"
- scsi: core: scsi_trace: Use get_unaligned_be*()
- scsi: sd: enable compat ioctls for sed-opal
- NFSv4.x: Drop the slot if nfs4_delegreturn_prepare waits for layoutreturn
- NFSv2: Fix a typo in encode_sattr()
- scsi: sd: Clear sdkp->protection_type if disk is reformatted without PI
- scsi: enclosure: Fix stale device oops with hot replug
- xprtrdma: Fix completion wait during device removal
- xprtrdma: Fix use-after-free in rpcrdma_post_recvs
- tcp: cache line align MAX_TCP_HEADER
- svcrdma: Fix trace point use-after-free race
- net: stricter validation of untrusted gso packets
- net: bridge: enfore alignment for ethernet address
- net: use correct this_cpu primitive in dev_recursion_level
- net: core: reduce recursion limit value
- ipv4: fill fl4_icmp_{type, code} in ping_v4_sendmsg
- net: Added pointer check for dst->ops->neigh_lookup in dst_neigh_lookup_skb
- vlan: consolidate VLAN parsing code and limit max parsing depth
- svcrdma: Fix page leak in svc_rdma_recv_read_chunk()
- i40e: Memory leak in i40e_config_iwarp_qvlist
- i40e: Fix of memory leak and integer truncation in i40e_virtchnl.c
- i40e: Wrong truncation from u16 to u8
- i40e: add num_vectors checker in iwarp handler
- Revert "vxlan: fix tos value before xmit"
- openvswitch: Prevent kernel-infoleak in ovs_ct_put_key()
- net: gre: recompute gre csum for sctp over gre tunnels
- vxlan: Ensure FDB dump is performed under RCU
- ipv6: fix memory leaks on IPV6_ADDRFORM path
- ipv4: Silence suspicious RCU usage warning
- igb: reinit_locked() should be called with rtnl_lock
- net/mlx5e: fix bpf_prog reference count leaks in mlx5e_alloc_rq
- mlxsw: core: Free EMAD transactions using kfree_rcu()
- mlxsw: core: Increase scope of RCU read-side critical section
- mlx4: disable device on shutdown
- net/mlx5: Verify Hardware supports requested ptp function on a given pin
- rds: Prevent kernel-infoleak in rds_notify_queue_get()
- rtnetlink: Fix memory(net_device) leak when ->newlink fails
- udp: Improve load balancing for SO_REUSEPORT.
- udp: Copy has_conns in reuseport_grow().
- sctp: shrink stream outq when fails to do addstream reconf
- sctp: shrink stream outq only when new outcnt < old outcnt
- tcp: allow at most one TLP probe per flight
- net: udp: Fix wrong clean up for IS_UDPLITE macro
- net-sysfs: add a newline when printing 'tx_timeout' by sysfs
- ip6_gre: fix null-ptr-deref in ip6gre_init_net()
- dev: Defer free of skbs in flush_backlog
- bonding: check return value of register_netdevice() in bond_newlink()
- ipvs: fix the connection sync failed in some cases
- mlxsw: destroy workqueue when trap_register in mlxsw_emad_init
- bonding: check error value of register_netdevice() immediately
- tipc: clean up skb list lock handling on send path
- libceph: don't omit recovery_deletes in target_copy()
- sched: consistently handle layer3 header accesses in the presence of VLANs
- tcp: md5: allow changing MD5 keys in all socket states
- tcp: md5: refine tcp_md5_do_add()/tcp_md5_hash_key() barriers
- tcp: md5: do not send silly options in SYNCOOKIES
- tcp: md5: add missing memory barriers in tcp_md5_do_add()/tcp_md5_hash_key()
- tcp: make sure listeners don't initialize congestion-control state
- tcp: fix SO_RCVLOWAT possible hangs under high mem pressure
- net_sched: fix a memory leak in atm_tc_init()
- llc: make sure applications use ARPHRD_ETHER
- l2tp: remove skb_dst_set() from l2tp_xmit_skb()
- mlxsw: spectrum_router: Remove inappropriate usage of WARN_ON()
- i40e: protect ring accesses with READ- and WRITE_ONCE
- ixgbe: protect ring accesses with READ- and WRITE_ONCE
- SUNRPC: Properly set the @subbuf parameter of xdr_buf_subsegment()
- sunrpc: fixed rollback in rpc_gssd_dummy_populate()
- netfilter: ipset: fix unaligned atomic access
- xfrm: Fix double ESP trailer insertion in IPsec crypto offload.
- net: Do not clear the sock TX queue in sk_set_socket()
- net: Fix the arp error in some cases
- sch_cake: don't call diffserv parsing code when it is not needed
- tcp_cubic: fix spurious HYSTART_DELAY exit upon drop in min RTT
- sch_cake: fix a few style nits
- sch_cake: don't try to reallocate or unshare skb unconditionally
- ip_tunnel: fix use-after-free in ip_tunnel_lookup()
- ip6_gre: fix use-after-free in ip6gre_tunnel_lookup()
- tcp: grow window for OOO packets only for SACK flows
- tcp: don't ignore ECN CWR on pure ACK
- sctp: Don't advertise IPv4 addresses if ipv6only is set on the socket
- net: increment xmit_recursion level in dev_direct_xmit()
- net: place xmit recursion in softnet data
- net: fix memleak in register_netdevice()
- mld: fix memory leak in ipv6_mc_destroy_dev()
- net: sched: export __netdev_watchdog_up()
- net: core: device_rename: Use rwsem instead of a seqcount
- sched/rt, net: Use CONFIG_PREEMPTION.patch
- e1000e: Do not wake up the system via WOL if device wakeup is disabled
- xdp: Fix xsk_generic_xmit errno
- net/filter: Permit reading NET in load_bytes_relative when MAC not set
- net: sunrpc: Fix off-by-one issues in 'rpc_ntop6'
- igb: Report speed and duplex as unknown when device is runtime suspended
- e1000e: Relax condition to trigger reset for ME workaround
- e1000e: Disable TSO for buffer overrun workaround
- ixgbe: fix signed-integer-overflow warning
- macvlan: Skip loopback packets in RX handler
- net/mlx5e: IPoIB, Drop multicast packets that this interface sent
- netfilter: nft_nat: return EOPNOTSUPP if type or flags are not supported
- e1000: Distribute switch variables for initialization
- ixgbe: Fix XDP redirect on archs with PAGE_SIZE above 4K
- vxlan: Avoid infinite loop when suppressing NS messages with invalid options
- bridge: Avoid infinite loop when suppressing NS messages with invalid options
- ipv6: fix IPV6_ADDRFORM operation logic
- l2tp: do not use inet_hash()/inet_unhash()
- l2tp: add sk_family checks to l2tp_validate_socket
- devinet: fix memleak in inetdev_init()
- netfilter: nf_conntrack_pptp: fix compilation warning with W=1 build
- bonding: Fix reference count leak in bond_sysfs_slave_add.
- xsk: Add overflow check for u64 division, stored into u32
- esp6: get the right proto for transport mode in esp6_gso_encap
- netfilter: nf_conntrack_pptp: prevent buffer overflows in debug code
- netfilter: nfnetlink_cthelper: unbreak userspace helper support
- netfilter: ipset: Fix subcounter update skip
- netfilter: nft_reject_bridge: enable reject with bridge vlan
- ip_vti: receive ipip packet by calling ip_tunnel_rcv
- vti4: eliminated some duplicate code.
- xfrm: fix a NULL-ptr deref in xfrm_local_error
- xfrm: fix a warning in xfrm_policy_insert_list
- xfrm interface: fix oops when deleting a x-netns interface
- xfrm: call xfrm_output_gso when inner_protocol is set in xfrm_output
- xfrm: allow to accept packets with ipv6 NEXTHDR_HOP in xfrm_input
- libceph: ignore pool overlay and cache logic on redirects
- mlxsw: spectrum: Fix use-after-free of split/unsplit/type_set in case reload fails
- net/mlx4_core: fix a memory leak bug.
- net/mlx5e: Update netdev txq on completions during closure
- sctp: Start shutdown on association restart if in SHUTDOWN-SENT state and socket is closed
- sctp: Don't add the shutdown timer if its already been added
- net/mlx5: Add command entry handling completion
- net: ipip: fix wrong address family in init error path
- net: inet_csk: Fix so_reuseport bind-address cache in tb->fast*
- __netif_receive_skb_core: pass skb by reference
- netfilter: nft_set_rbtree: Introduce and use nft_rbtree_interval_start()
- tcp: fix SO_RCVLOWAT hangs with fat skbs
- net: tcp: fix rx timestamp behavior for tcp_recvmsg
- net: ipv4: really enforce backoff for redirects
- tcp: fix error recovery in tcp_zerocopy_receive()
- Revert "ipv6: add mtu lock check in __ip6_rt_update_pmtu"
- net: fix a potential recursive NETDEV_FEAT_CHANGE
- drop_monitor: work around gcc-10 stringop-overflow warning
- netfilter: nf_osf: avoid passing pointer to local var
- netfilter: nat: never update the UDP checksum when it's 0
- sctp: Fix bundling of SHUTDOWN with COOKIE-ACK
- net/mlx5: Fix command entry leak in Internal Error State
- net/mlx5: Fix forced completion access non initialized command entry
- tipc: fix partial topology connection closure
- sch_sfq: validate silly quantum values
- sch_choke: avoid potential panic in choke_reset()
- net_sched: sch_skbprio: add message validation to skbprio_change()
- net/mlx4_core: Fix use of ENOSPC around mlx4_counter_alloc()
- fq_codel: fix TCA_FQ_CODEL_DROP_BATCH_SIZE sanity checks
- cgroup, netclassid: remove double cond_resched
- sctp: Fix SHUTDOWN CTSN Ack in the peer restart case
- net/mlx5: Fix failing fw tracer allocation on s390
- svcrdma: Fix leak of svc_rdma_recv_ctxt objects
- mlxsw: Fix some IS_ERR() vs NULL bugs
- vrf: Check skb for XFRM_TRANSFORMED flag
- xfrm: Always set XFRM_TRANSFORMED in xfrm{4, 6}_output_finish
- vrf: Fix IPv6 with qdisc and xfrm
- sched: etf: do not assume all sockets are full blown
- macvlan: fix null dereference in macvlan_device_event()
- ipv6: fix restrict IPV6_ADDRFORM operation
- ipv6: restrict IPV6_ADDRFORM operation
- arm64/ascend: Set mem_sleep_current to PM_SUSPEND_ON for ascend platform
- mm/swap_state: fix a data race in swapin_nr_pages
- arm64: secomp: fix the secure computing mode 1 syscall check for ilp32
- vti4: removed duplicate log message.
- KEYS: Don't write out to userspace while holding key semaphore
- netfilter: nf_tables: report EOPNOTSUPP on unsupported flags/object type
- net: revert default NAPI poll timeout to 2 jiffies
- net: ipv6: do not consider routes via gateways for anycast address check
- net: ipv4: devinet: Fix crash when add/del multicast IP with autojoin
- mlxsw: spectrum_flower: Do not stop at FLOW_ACTION_VLAN_MANGLE
- ipv6: don't auto-add link-local address to lag ports
- net: Fix Tx hash bound checking
- sctp: fix possibly using a bad saddr with a given dst
- sctp: fix refcount bug in sctp_wfree
- net, ip_tunnel: fix interface lookup with no key
- ipv4: fix a RCU-list lock in fib_triestat_seq_show
- vti6: Fix memory leak of skb if input policy check fails
- netfilter: nft_fwd_netdev: validate family and chain type
- netfilter: flowtable: reload ip{v6}h in nf_flow_tuple_ip{v6}
- xfrm: policy: Fix doulbe free in xfrm_policy_timer
- xfrm: add the missing verify_sec_ctx_len check in xfrm_add_acquire
- xfrm: fix uctx len check in verify_sec_ctx_len
- vti[6]: fix packet tx through bpf_redirect() in XinY cases
- xfrm: handle NETDEV_UNREGISTER for xfrm device
- ceph: check POOL_FLAG_FULL/NEARFULL in addition to OSDMAP_FULL/NEARFULL
- vxlan: check return value of gro_cells_init()
- tcp: repair: fix TCP_QUEUE_SEQ implementation
- net: ip_gre: Accept IFLA_INFO_DATA-less configuration
- net: ip_gre: Separate ERSPAN newlink / changelink callbacks
- net_sched: keep alloc_hash updated after hash allocation
- net_sched: cls_route: remove the right filter from hashtable
- net/packet: tpacket_rcv: avoid a producer race condition
- net: cbs: Fix software cbs to consider packet sending time
- mlxsw: spectrum_mr: Fix list iteration in error path
- Revert "ipv6: Fix handling of LLA with VRF and sockets bound to VRF"
- Revert "vrf: mark skb for multicast or link-local as enslaved to VRF"
- ipv4: ensure rcu_read_lock() in cipso_v4_error()
- netfilter: nft_tunnel: add missing attribute validation for tunnels
- netfilter: nft_payload: add missing attribute validation for payload csum flags
- netfilter: cthelper: add missing attribute validation for cthelper
- netfilter: x_tables: xt_mttg_seq_next should increase position index
- netfilter: xt_recent: recent_seq_next should increase position index
- netfilter: synproxy: synproxy_cpu_seq_next should increase position index
- netfilter: nf_conntrack: ct_cpu_seq_next should increase position index
- macvlan: add cond_resched() during multicast processing
- bonding/alb: make sure arp header is pulled before accessing it
- devlink: validate length of region addr/len
- tipc: add missing attribute validation for MTU property
- net/ipv6: remove the old peer route if change it to a new one
- net/ipv6: need update peer route when modify metric
- net: fq: add missing attribute validation for orphan mask
- devlink: validate length of param values
- net/packet: tpacket_rcv: do not increment ring index on drop
- netlink: Use netlink header as base to calculate bad attribute offset
- net/ipv6: use configured metric when add peer route
- ipvlan: don't deref eth hdr before checking it's set
- ipvlan: do not use cond_resched_rcu() in ipvlan_process_multicast()
- ipvlan: do not add hardware address of master to its unicast filter list
- ipvlan: add cond_resched_rcu() while processing muticast backlog
- ipv6/addrconf: call ipv6_mc_up() for non-Ethernet interface
- inet_diag: return classid for all socket types
- gre: fix uninit-value in __iptunnel_pull_header
- cgroup, netclassid: periodically release file_lock on classid updating
- netfilter: nf_flowtable: fix documentation
- netfilter: nft_tunnel: no need to call htons() when dumping ports
- net: netlink: cap max groups which will be considered in netlink_bind()
- net/tls: Fix to avoid gettig invalid tls record
- ipv6: Fix nlmsg_flags when splitting a multipath route
- ipv6: Fix route replacement with dev-only route
- sctp: move the format error check out of __sctp_sf_do_9_1_abort
- net: sched: correct flower port blocking
- net: fib_rules: Correctly set table field when table number exceeds 8 bits
- netfilter: xt_hashlimit: limit the max size of hashtable
- mlxsw: spectrum_dpipe: Add missing error path
- bpf: Return -EBADRQC for invalid map type in __bpf_tx_xdp_map
- mlx5: work around high stack usage with gcc
- netfilter: nft_tunnel: add the missing ERSPAN_VERSION nla_policy
- net/sched: flower: add missing validation of TCA_FLOWER_FLAGS
- net/sched: matchall: add missing validation of TCA_MATCHALL_FLAGS
- core: Don't skip generic XDP program execution for cloned SKBs
- net/mlx5: IPsec, fix memory leak at mlx5_fpga_ipsec_delete_sa_ctx
- net/mlx5: IPsec, Fix esp modify function attribute
- net_sched: fix a resource leak in tcindex_set_parms()
- bonding/alb: properly access headers in bond_alb_xmit()
- sunrpc: expiry_time should be seconds not timeval
- tcp: clear tp->segs_{in|out} in tcp_disconnect()
- tcp: clear tp->data_segs{in|out} in tcp_disconnect()
- tcp: clear tp->delivered in tcp_disconnect()
- tcp: clear tp->total_retrans in tcp_disconnect()
- net_sched: fix an OOB access in cls_tcindex
- l2tp: Allow duplicate session creation with UDP
- cls_rsvp: fix rsvp_policy
- net: Fix skb->csum update in inet_proto_csum_replace16().
- xfrm: interface: do not confirm neighbor when do pmtu update
- xfrm interface: fix packet tx through bpf_redirect()
- vti[6]: fix packet tx through bpf_redirect()
- netfilter: nft_tunnel: ERSPAN_VERSION must not be null
- igb: Fix SGMII SFP module discovery for 100FX/LX.
- ixgbe: Fix calculation of queue with VFs and flow director on interface flap
- ixgbevf: Remove limit of 10 entries for unicast filter list
- net_sched: ematch: reject invalid TCF_EM_SIMPLE
- netfilter: nf_tables: add __nft_chain_type_get()
- netfilter: ipset: use bitmap infrastructure completely
- netfilter: nft_osf: add missing check for DREG attribute
- tcp: do not leave dangling pointers in tp->highest_sack
- tcp_bbr: improve arithmetic division in bbr_update_bw()
- Revert "udp: do rmem bulk free even if the rx sk queue is empty"
- net-sysfs: Fix reference count leak
- net_sched: fix datalen for ematch
- net: rtnetlink: validate IFLA_MTU attribute in rtnl_create_link()
- net, ip_tunnel: fix namespaces move
- net, ip6_tunnel: fix namespaces move
- net: ip6_gre: fix moving ip6gre between namespaces
- ipv6: sr: remove SKB_GSO_IPXIP6 on End.D* actions
- packet: fix data-race in fanout_flow_is_huge()
- net: neigh: use long type to store jiffies delta
- xsk: Fix registration of Rx-only sockets
- net: netem: correct the parent's backlog when corrupted packet was dropped
- net: netem: fix error path for corrupted GSO frames
- act_mirred: Fix mirred_init_module error handling
- ip6erspan: remove the incorrect mtu limit for ip6erspan
- llc: fix sk_buff refcounting in llc_conn_state_process()
- llc: fix another potential sk_buff leak in llc_ui_sendmsg()
- net: sched: cbs: Avoid division by zero when calculating the port rate
- net/rds: Fix 'ib_evt_handler_call' element in 'rds_ib_stat_names'
- xsk: avoid store-tearing when assigning umem
- xsk: avoid store-tearing when assigning queues
- net/sched: cbs: Set default link speed to 10 Mbps in cbs_set_port_rate
- i40e: reduce stack usage in i40e_set_fc
- net/rds: Add a few missing rds_stat_names entries
- net: fix bpf_xdp_adjust_head regression for generic-XDP
- tipc: reduce risk of wakeup queue starvation
- xfrm interface: ifname may be wrong in logs
- xdp: fix possible cq entry leak
- net/tls: fix socket wmem accounting on fallback with netem
- net: netem: fix backlog accounting for corrupted GSO frames
- bpf: fix the check that forwarding is enabled in bpf_ipv6_fib_lookup
- net: core: support XDP generic on stacked devices.
- signal/bpfilter: Fix bpfilter_kernl to use send_sig not force_sig
- net/mlx5: Delete unused FPGA QPN variable
- mlxsw: spectrum: Set minimum shaper on MC TCs
- mlxsw: reg: QEEC: Add minimum shaper fields
- tipc: fix wrong timeout input for tipc_wait_for_cond()
- tipc: update mon's self addr when node addr generated
- mlxsw: spectrum_qdisc: Include MC TCs in Qdisc counters
- mlxsw: spectrum: Wipe xstats.backlog of down ports
- tcp: fix marked lost packets not being retransmitted
- af_unix: add compat_ioctl support
- ethtool: reduce stack usage with clang
- fs: fix kabi broken introduced by fixing CVE-2020-14381
- futex: Unbreak futex hashing
- futex: Fix inode life-time issue
- block/bio-integrity: don't free 'buf' if bio_integrity_add_page() failed
- arm64/ascend: set the correct dvpp mmap area when no MAP_DVPP flags
- ext4: fix error pointer dereference
- ext4: Avoid freeing inodes on dirty list
- writeback: Export inode_io_list_del()
- blktrace: ensure our debugfs dir exists
- blktrace: fix debugfs use after free
- loop: be paranoid on exit and prevent new additions / removals
- Revert "block: rename 'q->debugfs_dir' and 'q->blk_trace->dir' in blk_unregister_queue()"
- ext4: force buffer up-to-date while marking it dirty
- ext4: fix a data race at inode->i_disksize
- ext4: fix a data race at inode->i_blocks
- jbd2: abort journal if free a async write error metadata buffer
- ext4: abort the filesystem if failed to async write metadata buffer
- net: hns3: update hns3 version to 1.9.38.7
- net: hns3: initialize the message content sent to the VF
- net: hns3: check vlan id before using it
- net: hns3: check RSS key index before using
- net: hns3: check cmdq message parameters sent from VF
- config: add certs dir to CONFIG_MODULE_SIG_KEY
- net/hinic: Fix Oops when probing hinic driver

* Sun Sep 14 2020 xinghe <xinghe1@huawei.com> - 4.19.90-2008.6.0.0044
- add perf-tip file fix cannot load perf-tips warning

* Mon Aug 31 2020 Yang Yingliang <yangyingliang@huawei.com> - 4.19.90-2008.6.0.0043
- arm64/config: enable TIPC module for openEuler
- net: hns3: update hns3 version to 1.9.38.6
- net: hns3: add support for dumping MAC umv counter in debugfs
- net: hns3: fix bug when PF set the duplicate MAC address for VFs
- net/hinic: Check the legality of out_size in nictool
- net/hinic: Fix out-of-bounds access when setting ets
- net/hinic: Rename camelCase used in nictool
- net/hinic: Fix alignment and code style
- net/hinic: Delete unused heartbeat enhancement feature
- net/hinic: Delete the unused chip fault handling process
- net/hinic: Delete unused microcode back pressure feature
- net/hinic: Fix misspelled word and wrong print format
- net/hinic: update hinic version to 2.3.2.15
- net/hinic: Add the maximum value of the module parameter poll_weight
- net/hinic: Add pause/pfc mutual exclusion protection
- net/hinic: Add lock for mgmt channel event_flag
- net/hinic: Fix signed integer overflow
- nfsd: apply umask on fs without ACL support
- arm64/ascend: use ascend_enable_full to enable ascend platform
- sbsa_gwdt: Enable ARM_SBSA_WATCHDOG_PANIC_NOTIFIER in hulk_defconfig
- sbsa_gwdt: Introduce a panic notifier
- memcg/ascend: Support not account pages of cdm for memcg
- dt-bindings: iommu: Add Message Based SPI for hisilicon
- iommu: support message based spi for smmu
- nbd_genl_status: null check for nla_nest_start
- config: Add default value for CONFIG_ASCEND_INIT_ALL_GICR
- irq-gic-v3: Add support to init ts core GICR
- ascend: mm/hugetlb: Enable ASCEND_CHARGE_MIGRAGE_HUGEPAGES for hulk_defconfig
- ascend: mm/hugetlb: Enable charge migrate hugepages
- config: Add default value for CONFIG_SERIAL_ATTACHED_MBIGEN
- serial: amba-pl011: Fix serial port discard interrupt when interrupt signal line of serial port is connected to mbigen.
- iommu: fix a mistake for iommu_unregister_device_fault_handler
- printk: Export a symbol.
- arm64/ascend: Enable ASCEND_IOPF_HIPRI for hulk_defconfig
- arm64/ascend: Enable iopf hipri feature for Ascend Platform
- mm: Check numa node hugepages enough when mmap hugetlb
- arm64/ascend: Enable CONFIG_ASCEND_OOM for hulk_defconfig
- arm64/ascend: Add new enable_oom_killer interface for oom contrl
- svm: add support for allocing memory which is within 4G physical address in svm_mmap
- suspend: export cpu_suspend/cpu_resume/psci_ops
- printk: export log_buf_addr_get/log_buf_len_get
- arm64/ascend: fix memleak when remove svm
- iommu: fix NULL pointer when release iopf queue
- arm64/ascend: Enable ASCEND_DVPP_MMAP for hulk_defconfig
- arm64/ascend: Don't use the DvPP mmap space for svm.
- arm64/ascend: Enable DvPP mmap features for Ascend Platform
- usb: xhci: Add workaround for phytium
- arm64: topology: Support PHYTIUM CPU
- arm64: mm: define NET_IP_ALIGN to 0
- arm64: ilp32: fix kabi change
- config: add CONFIG_ARM64_ILP32 in defconfigs
- arm64: ilp32: fix compile warning cause by 'VA_BITS'
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
- arm64: ilp32: add is_ilp32_compat_{task, thread} and TIF_32BIT_AARCH64
- arm64: introduce is_a32_compat_{task, thread} for AArch32 compat
- arm64: uapi: set __BITS_PER_LONG correctly for ILP32 and LP64
- arm64: rename functions that reference compat term
- arm64: rename COMPAT to AARCH32_EL0
- arm64: ilp32: add documentation on the ILP32 ABI for ARM64
- thread: move thread bits accessors to separated file
- asm-generic: Drop getrlimit and setrlimit syscalls from default list
- 32-bit userspace ABI: introduce ARCH_32BIT_OFF_T config option
- compat ABI: use non-compat openat and open_by_handle_at variants
- ptrace: Add compat PTRACE_{G, S}ETSIGMASK handlers
- arm64: signal: Make parse_user_sigframe() independent of rt_sigframe layout
- scsi: libsas: Check link status in ATA prereset()
- scsi: libsas: Remove postreset from sas_sata_ops

* Wed Aug 19 2020 Yang Yingliang <yangyingliang@huawei.com> - 4.19.90-2008.3.0.0042
- x86/mm: split vmalloc_sync_all()
- kexec/uefi: copy secure_boot flag in boot params across kexec reboot
- x86/config: enable CONFIG_HINIC by default
- cgroup: add missing skcd->no_refcnt check in cgroup_sk_clone()
- Revert "cgroup: add missing skcd->no_refcnt check in cgroup_sk_clone()"
- cgroup: add missing skcd->no_refcnt check in cgroup_sk_clone()
- ext4: Correctly restore system zone info when remount fails
- ext4: Handle add_system_zone() failure in ext4_setup_system_zone()
- ext4: Fold ext4_data_block_valid_rcu() into the caller
- ext4: Check journal inode extents more carefully
- ext4: Don't allow overlapping system zones
- ext4: Handle error of ext4_setup_system_zone() on remount
- nfs: set invalid blocks after NFSv4 writes
- cgroup1: don't call release_agent when it is ""
- cgroup-v1: cgroup_pidlist_next should update position index
- cgroup: Iterate tasks that did not finish do_exit()
- cgroup: cgroup_procs_next should increase position index
- mm/vmscan.c: don't round up scan size for online memory cgroup
- cgroup: saner refcounting for cgroup_root
- cgroup: Prevent double killing of css when enabling threaded cgroup
- mm: memcg/slab: fix memory leak at non-root kmem_cache destroy
- mm: memcg/slab: synchronize access to kmem_cache dying flag using a spinlock
- mm/memcg: fix refcount error while moving and swapping
- memcg: fix NULL pointer dereference in __mem_cgroup_usage_unregister_event
- mm/memcontrol.c: lost css_put in memcg_expand_shrinker_maps()
- random32: move the pseudo-random 32-bit definitions to prandom.h
- random32: remove net_rand_state from the latent entropy gcc plugin
- random: fix circular include dependency on arm64 after addition of percpu.h
- ARM: percpu.h: fix build error
- random32: update the net random state on interrupt and activity
- vgacon: Fix for missing check in scrollback handling
- memcg: fix memcg_kmem_bypass() for remote memcg charging
- arm64/numa: cdm: Cacheline aligned cdmmask to improve performance
- mm/page_alloc.c: ratelimit allocation failure warnings more aggressively
- iomap: fix sub-page uptodate handling
- net/hinic: Add dfx information
- net/hinic: Add read chip register interface
- net/hinic: Synchronize time to firmware every hour
- net: add {READ|WRITE}_ONCE() annotations on ->rskq_accept_head
- net: avoid possible false sharing in sk_leave_memory_pressure()
- sctp: add chunks to sk_backlog when the newsk sk_socket is not set
- netfilter: ctnetlink: honor IPS_OFFLOAD flag
- fork, memcg: alloc_thread_stack_node needs to set tsk->stack
- net/udp_gso: Allow TX timestamp with UDP GSO
- inet: frags: call inet_frags_fini() after unregister_pernet_subsys()
- netfilter: ebtables: CONFIG_COMPAT: reject trailing data after last rule
- netfilter: nft_flow_offload: add entry to flowtable after confirmation
- perf/core: Fix the address filtering fix
- netfilter: nft_set_hash: bogus element self comparison from deactivation path
- fs/nfs: Fix nfs_parse_devname to not modify it's argument
- ip_tunnel: Fix route fl4 init in ip_md_tunnel_xmit
- net/mlx5: Take lock with IRQs disabled to avoid deadlock
- xfs: Sanity check flags of Q_XQUOTARM call
- cgroup: fix KABI broken by "cgroup: fix cgroup_sk_alloc() for sk_clone_lock()"
- cgroup: fix cgroup_sk_alloc() for sk_clone_lock()
- net: memcg: fix lockdep splat in inet_csk_accept()
- net: memcg: late association of sock to memcg
- cgroup: memcg: net: do not associate sock with unrelated cgroup
- net/hinic: Retry to get ack after VF message timeout
- net/hinic: Fix register_chrdev_region fails for major number 921
- net/hinic: Fix mgmt message timeout during firmware hot upgrade
- net/hinic: Correct return and features from set_features callback
- net/hinic: Hinic only supports csum offloading of vxlan/ipip tunnel packets
- net/hinic: Set net device link down when the chip fault
- net/hinic: Delete unused UFO codes
- net/hinic: Delete the remaining old linux kernel adaptation interface
- net/hinic: Delete the old kernel version adaptation interface in netdev ops
- net/hinic: Delete the old kernel version adaptation interface in ethtool ops
- net/hinic: Delete useless linux adaptation functions
- net/hinic: Delete unused functions and macro definitions in ossl
- netfilter: nat: check the bounds of nf_nat_l3protos and nf_nat_l4protos

* Fri Jul 29 2020 Yang Yingliang <yangyingliang@huawei.com> - 4.19.90-2007.2.0.0041
- mm, vmstat: reduce zone->lock holding time by /proc/pagetypeinfo
- kernel/notifier.c: intercept duplicate registrations to avoid infinite loops
- macvlan: use skb_reset_mac_header() in macvlan_queue_xmit()
- scsi: qedf: remove memset/memcpy to nfunc and use func instead
- ext4: Send ext4_handle_error message after set sb->s_flags
- tcp: refine rule to allow EPOLLOUT generation under mem pressure
- netfilter: nf_tables: fix flowtable list del corruption
- netfilter: nf_tables: store transaction list locally while requesting module
- netfilter: nf_tables: remove WARN and add NLA_STRING upper limits
- netfilter: nft_tunnel: fix null-attribute check
- netfilter: arp_tables: init netns pointer in xt_tgdtor_param struct
- netfilter: fix a use-after-free in mtype_destroy()
- mm/huge_memory.c: thp: fix conflict of above-47bit hint address and PMD alignment
- mm/huge_memory.c: make __thp_get_unmapped_area static
- mm/page-writeback.c: avoid potential division by zero in wb_min_max_ratio()
- mm: memcg/slab: call flush_memcg_workqueue() only if memcg workqueue is valid
- mm/shmem.c: thp, shmem: fix conflict of above-47bit hint address and PMD alignment
- iommu: Remove device link to group on failure
- netfilter: ipset: avoid null deref when IPSET_ATTR_LINENO is present
- netfilter: conntrack: dccp, sctp: handle null timeout argument
- netfilter: arp_tables: init netns pointer in xt_tgchk_param struct
- tty: always relink the port
- tty: link tty and port before configuring it as console
- chardev: Avoid potential use-after-free in 'chrdev_open()'
- net: hns3: update hns3 version to 1.9.38.5
- net: hns3: fix the number of queues
- net: hns3: fixes a promoiscuous mode
- net: hns3: fix driver bug
- net: hns3: fix for VLAN config when reset
- net: hns3: fix bug when calculating the
- net: hns3: fix speed unknown issue in bond
- net: hns3: fix a missing return in hclge_set_vlan_filter()
- net: hns3: update hns3 version to 1.9.38.3
- net: hns3: remove redundant codes entered by mistake
- net/hinic: Fix out-of-bounds when receiving mbox messages
- RDMA/hns: Modify the code based on the review comments
- Revert "zram: convert remaining CLASS_ATTR() to CLASS_ATTR_RO()"
- config: set CONFIG_CAN_DEBUG_DEVICES for arm64 hulk_defconfig
- config: add CONFIG_CAN_J1939 in defconfigs
- can: j1939: fix address claim code example
- can: j1939: j1939_sk_bind(): take priv after lock is held
- can: j1939: warn if resources are still linked on destroy
- can: j1939: j1939_can_recv(): add priv refcounting
- can: j1939: transport: j1939_cancel_active_session(): use hrtimer_try_to_cancel() instead of hrtimer_cancel()
- can: j1939: make sure socket is held as long as session exists
- can: j1939: transport: make sure the aborted session will be deactivated only once
- can: j1939: socket: rework socket locking for j1939_sk_release() and j1939_sk_sendmsg()
- can: j1939: main: j1939_ndev_to_priv(): avoid crash if can_ml_priv is NULL
- can: j1939: move j1939_priv_put() into sk_destruct callback
- can: af_can: export can_sock_destruct()
- can: j1939: transport: j1939_xtp_rx_eoma_one(): Add sanity check for correct total message size
- can: j1939: transport: j1939_session_fresh_new(): make sure EOMA is send with the total message size set
- can: j1939: fix memory leak if filters was set
- can: j1939: fix resource leak of skb on error return paths
- can: add support of SAE J1939 protocol
- can: af_can: use spin_lock_bh() for &net->can.can_rcvlists_lock
- can: af_can: remove NULL-ptr checks from users of can_dev_rcv_lists_find()
- can: make use of preallocated can_ml_priv for per device struct can_dev_rcv_lists
- can: af_can: can_pernet_exit(): no need to iterate over and cleanup registered CAN devices
- can: af_can: can_rx_register(): use max() instead of open coding it
- can: af_can: give variable holding the CAN receiver and the receiver list a sensible name
- can: af_can: rename find_dev_rcv_lists() to can_dev_rcv_lists_find()
- can: af_can: rename find_rcv_list() to can_rcv_list_find()
- can: proc: give variable holding the CAN per device receive lists a sensible name
- can: af_can: give variable holding the CAN per device receive lists a sensible name
- can: proc: give variables holding CAN statistics a sensible name
- can: af_can: give variables holding CAN statistics a sensible name
- can: af_can: can_pernet_init(): Use preferred style kzalloc(sizeof()) usage
- can: extend sockaddr_can to include j1939 members
- can: add socket type for CAN_J1939
- can: introduce CAN_REQUIRED_SIZE macro
- can: introduce CAN midlayer private and allocate it automatically
- net: hns3: update hns3 version to 1.9.38.3
- net: hns3: clean code for security
- net: hns3: modify an incorrect type in
- net: hns3: check queue id range before
- net: hns3: fix error handling for desc filling
- net: hns3: fix for not calculating tx BD send size correctly
- net: hns3: fix for not unmapping tx buffer correctly
- net: hns3: fix desc filling bug when skb is expanded or lineared
- net: hns3: drop the WQ_MEM_RECLAIM flag when allocating wq
- net: hns3: optimize the parameter of hclge_update_port_base_vlan_cfg and ignore the send mailbox failure when VF is unalive
- net: hns3: use netif_tx_disable to stop the transmit queue
- net: hns3: add support of dumping mac reg in debugfs
- net: hns3: fix a fake tx timeout issue
- net: hns3: fix use-after-free when doing self test
- net: hns3: add a log for switching VLAN filter state
- net: hns3: fix problem of missing updating port information
- net: hns3: add vlan list lock to protect vlan list and fix duplicate node in vlan list
- net: hns3: fix bug for port base vlan configuration
- net: hns3: skip periodic service task if reset failed
- net: hns3: check reset pending after FLR prepare
- net: hns3: fix for mishandle of asserting VF reset fail
- net: hns3: fix for missing uninit debugfs when unload driver
- net: hns3: unify format of failed print information for clean up
- net: hns3: modify location of one print information
- net: hns3: fix return value error when query mac link status fail
- net: hns3: remove unnecessary mac enable in app loopback
- net: hns3: remove some useless code
- net: hns3: fix an inappropriate type assignment
- net: hns3: update hns3 version to 1.9.38.2
- net: hns3: fix reset bug
- sdei_watchdog: fix compile error when CONFIG_HARDLOCKUP_DETECTOR is not set
- net/hinic: Add support for 128 qps
- net/hinic: Add support for X86 Arch
- fs/filescontrol: add a switch to enable / disable accounting of open fds
- usb: usbtest: fix missing kfree(dev->buf) in usbtest_disconnect
- vfio/pci: Fix SR-IOV VF handling with MMIO blocking
- signal: Export tracepoint symbol signal_generate
- x86/speculation: PR_SPEC_FORCE_DISABLE enforcement for indirect branches.
- x86/speculation: Avoid force-disabling IBPB based on STIBP and enhanced IBRS.
- x86/speculation: Add support for STIBP always-on preferred mode
- x86/speculation: Change misspelled STIPB to STIBP
- x86/speculation: Prevent rogue cross-process SSBD shutdown
- vfio-pci: Invalidate mmaps and block MMIO access on disabled memory
- vfio-pci: Fault mmaps to enable vma tracking
- vfio/type1: Support faulting PFNMAP vmas
- vfio/type1: Fix VA->PA translation for PFNMAP VMAs in vaddr_get_pfn()
- vfio_pci: Enable memory accesses before calling pci_map_rom
- net/hinic: Fix copying out of bounds when using tools to get statistics
- uacce: fix problem of parameter check
- net: hns3: update hns3 version to 1.9.38.1
- net: hns3: add device name valid check
- ext4, jbd2: ensure panic by fix a race between jbd2 abort and ext4 error handlers
- Revert "ext4, jbd2: switch to use completion variable instead of JBD2_REC_ERR"
- x86/speculation: Add Ivy Bridge to affected list
- x86/speculation: Add SRBDS vulnerability and mitigation documentation
- x86/speculation: Add Special Register Buffer Data Sampling (SRBDS) mitigation
- x86/cpu: Add 'table' argument to cpu_matches()
- x86/cpu: Add a steppings field to struct x86_cpu_id
- ext4: stop overwrite the errcode in ext4_setup_super
- panic/printk: fix zap_lock
- vt: keyboard: avoid signed integer overflow in k_ascii
- ext4: Fix block bitmap corruption when io error
- mm: Fix mremap not considering huge pmd devmap
- net-sysfs: Call dev_hold always in rx_queue_add_kobject
- net-sysfs: Call dev_hold always in netdev_queue_add_kobject
- net-sysfs: fix netdev_queue_add_kobject() breakage
- net-sysfs: Fix reference count leak in rx|netdev_queue_add_kobject
- SUNRPC: Fix xprt->timer use-after-free
- printk/panic: Avoid deadlock in printk()
- block: Fix use-after-free in blkdev_get()
- ata/libata: Fix usage of page address by page_address in ata_scsi_mode_select_xlat function
- media: go7007: fix a miss of snd_card_free
- vt: fix unicode console freeing with a common interface
- vt: don't use kmalloc() for the unicode screen buffer
- scsi: Fix kabi change due to add offline_already member in struct scsi_device
- scsi: core: avoid repetitive logging of device offline messages
- hfs: fix null-ptr-deref in hfs_find_init()
- ext4, jbd2: switch to use completion variable instead of JBD2_REC_ERR
- jbd2: clean __jbd2_journal_abort_hard() and __journal_abort_soft()
- jbd2: make sure ESHUTDOWN to be recorded in the journal superblock
- vt: vt_ioctl: fix use-after-free in vt_in_use()
- vt: vt_ioctl: fix VT_DISALLOCATE freeing in-use virtual console
- vt: vt_ioctl: remove unnecessary console allocation checks
- vt: switch vt_dont_switch to bool
- vt: ioctl, switch VT_IS_IN_USE and VT_BUSY to inlines
- vt: selection, introduce vc_is_sel
- ALSA: proc: Avoid possible leaks of snd_info_entry objects
- net/hinic: update hinic version to 2.3.2.14
- net/hinic: Fix memleak when create_singlethread_workqueue() is failed
- net/hinic: Fix VF driver loading failure during the firmware hot upgrade process
- net/hinic: Fix data inconsistency in the forwarding scenario when DCB is turned on
- net/hinic: Fix reboot -f stuck for a long time
- net/hinic: Add tx timeout dfx information
- net/hinic: Add a lock when registering the driver's global netdevice notifier
- net/hinic: Fix VF has a low probability of network failure on the virtual machine
- net/hinic: Fix the firmware compatibility bug in the MAC reuse scenario
- irqchip/gic-v3-its: Probe ITS page size for all GITS_BASERn registers
- selinux: properly handle multiple messages in selinux_netlink_send()
- media: tw5864: Fix possible NULL pointer dereference in tw5864_handle_frame
- arm64/mpam: Supplement err tips in info/last_cmd_status
- arm64/mpam: Fix unreset resources when mkdir ctrl group or umount resctrl
- MPAM / ACPI: Refactoring MPAM init process and set MPAM ACPI as entrance
- ACPI 6.x: Add definitions for MPAM table
- ACPI / PPTT: cacheinfo: Label caches based on fw_token
- ACPI / PPTT: Filthy hack to find _a_ backwards reference in the PPTT [ROTTEN]
- ACPI / PPTT: Add helper to validate cache nodes from an offset [dead]
- ACPI / processor: Add helper to convert acpi_id to a phys_cpuid
- ext4: report error to userspace by netlink
- pcie_cae add judgement about chip type
- Enable trust mode control for SR-IOV ports
- Added ethtool_ops interface to query optical module information
- Revert "consolemap: Fix a memory leaking bug in drivers/tty/vt/consolemap.c"
- ext4: fix support for inode sizes > 1024 bytes
- ext4: validate the debug_want_extra_isize mount option at parse time
- sunrpc: clean up properly in gss_mech_unregister()
- sunrpc: svcauth_gss_register_pseudoflavor must reject duplicate registrations.
- sunrpc: check that domain table is empty at module unload.
- arm64: smp: Increase secondary CPU boot timeout value
- KVM: arm64: Only flush VM for the first and the last vcpu
- media: remove videobuf-core.c
- ext4: mark block bitmap corrupted when found instead of BUGON
- bcache: fix potential deadlock problem in btree_gc_coalesce
- fs/binfmt_elf.c: allocate initialized memory in fill_thread_core_info()
- USB: gadget: fix illegal array access in binding with UDC

* Wed Jun 3 2020 Xie XiuQi <xiexiuqi@huawei.com> - 4.19.90-2005.2.0.0040
- update req_distinguished_name for x509.genkey

* Fri May 22 2020 Yang Yingliang <yangyingliang@huawei.com> - 4.19.90-2005.2.0.0039
- signal: fix kabi changes in struct task_struct
- signal: Extend exec_id to 64bits
- livepatch/core: Fix compile error when CONFIG_JUMP_LABEL closed
- net/hinic: Adjust AEQ interrupt retransmission settings
- net/hinic: Number of VF queues cleared during initialization
- net/hinic: Reduce VF EQ queue depth in SDI mode
- net/hinic: Disable the CSUM offload capability of TUNNEL in SDI mode
- net/hinic: VF does not display firmware statistics
- net/hinic: SDI bare metal VF supports dynamic queue
- net/hinic: Support doorbell BAR size of 256K in SDI mode
- net/hinic: Supports variable SDI master host ppf_id
- net/hinic: Optimize SDI interrupt aggregation parameters
- netlabel: cope with NULL catmap
- netprio_cgroup: Fix unlimited memory leak of v2 cgroups
- net: hns3: update hns3 version to 1.9.38.0
- net: hns3: solve the unlock 2 times when rocee init fault
- scsi: sg: add sg_remove_request in sg_write
- KVM: SVM: Fix potential memory leak in svm_cpu_init()
- ptp: free ptp device pin descriptors properly
- spi: spi-dw: Add lock protect dw_spi rx/tx to prevent concurrent calls
- drivers sfc: Fix cross page write error
- drivers sysctl: add read and write interface of pmbus
- net/hinic: Fix TX timeout under ipip tunnel packet
- xsk: Add missing check on user supplied headroom size
- fs/namespace.c: fix mountpoint reference counter race
- USB: core: Fix free-while-in-use bug in the USB S-Glibrary
- block, bfq: fix use-after-free in bfq_idle_slice_timer_body
- mwifiex: Fix possible buffer overflows in mwifiex_cmd_append_vsie_tlv()
- mwifiex: Fix possible buffer overflows in mwifiex_ret_wmm_get_status()
- scsi: mptfusion: Fix double fetch bug in ioctl
- mt76: fix array overflow on receiving too many fragments for a packet
- net: hns3: change the order of reinitializing RoCE and VF during reset
- net: hns3: update hns3 version to 1.9.37.9
- Revert "scsi: fix failing unload of a LLDD module"
- s390/mm: fix page table upgrade vs 2ndary address mode accesses
- pcie_cae support getting chipnums of this system
- net: hns3: remove the unnecessary ccflags

* Wed May 6 2020 Yang Yingliang <yangyingliang@huawei.com> - 4.19.90-2005.1.0.0038
- perf: Make perf able to build with latest libbfd
- nbd: use blk_mq_queue_tag_inflight_iter()
- blk-mq: use blk_mq_queue_tag_inflight_iter() in debugfs

* Tue Apr 28 2020 Yang Yingliang <yangyingliang@huawei.com> - 4.19.90-2004.1.0.0037
- net: hns3: update hns3 version to 1.9.37.8
- net: hns3: optimize FD tuple inspect
- net: hns3: fix unsupported config for RSS
- net: hns3: disable auto-negotiation off with 1000M setting in ethtool
- net: hns3: update VF mac list configuration as PF
- net: hns3: modify magic number in hclge_dbg_dump_ncl_config
- net: hns3: do mac configuration instead of rollback when malloc mac node fail
- net: hns3: update the device mac address asynchronously
- net: hns3: add one parameter for function hns3_nic_maybe_stop_tx()
- net: hns3: delete unnecessary logs after kzalloc fails
- net: hns3: fix some coding style found by codereview
- net: hns3: use uniform format "failed to xxx" to print fail message
- net: hns3: add debug information for flow table when failed
- net: hns3: modify hclge_restore_fd_entries()'s return type to void
- net: hns3: splice two "if" logic as one
- net: hns3: clean up some coding style issue
- net: hns3: modify definition location of struct hclge_mac_ethertype_idx_rd_cmd
- net: hns3: modify comment of macro HNAE3_MIN_VECTOR_NUM
- net: hns3: modify one macro into unsigned type
- net: hns3: delete unused macro HCLGEVF_MPF_ENBALE
- net: hns3: modify definition location of struct hclge_vf_vlan_cfg
- net: hns3: remove unnecessary 'ret' variable in hclge_misc_err_recovery()
- net: hns3: remove unnecessary register info in hclge_reset_err_handle()
- net: hns3: misc cleanup for VF reset
- net: hns3: merge mac state HCLGE_MAC_TO_DEL and HCLGE_MAC_DEL_FAIL
- net: hns3: update hns3 version to 1.9.37.7
- scsi: hisi_sas: do not reset the timer to wait for phyup when phy already up
- net: hns3: add suspend/resume function for hns3 driver
- btrfs: tree-checker: Enhance chunk checker to validate chunk profile
- net/hinic: fix the problem that out-of-bounds access
- scsi: sg: fix memory leak in sg_build_indirect
- scsi: sg: add sg_remove_request in sg_common_write
- btrfs: Don't submit any btree write bio if the fs has errors
- btrfs: extent_io: Handle errors better in extent_write_full_page()
- net/hinic: Delete useless header files
- powerpc/powernv/idle: Restore AMR/UAMOR/AMOR after idle
- media: xirlink_cit: add missing descriptor sanity checks
- Input: add safety guards to input_set_keycode()
- f2fs: fix to avoid memory leakage in f2fs_listxattr
- media: stv06xx: add missing descriptor sanity checks
- media: ov519: add missing endpoint sanity checks
- btrfs: tree-checker: Verify inode item
- btrfs: delayed-inode: Kill the BUG_ON() in btrfs_delete_delayed_dir_index()
- net: hns3: update hns3 version to 1.9.37.6
- net: hns3: ignore the send mailbox failure by VF is unalive
- net: hns3: update hns3 version to 1.9.37.5
- net: hns3: fix "tc qdisc del" failed issue
- net: hns3: rename two functions from periodical to periodic
- net: hns3: modify some print messages for cleanup and keep style consistent
- net: hns3: add some blank lines for cleanup
- net: hns3: sync some code from linux mainline
- net: hns3: fix mailbox send to VF failed issue
- net: hns3: disable phy loopback setting in hclge_mac_start_phy
- net: hns3: delete some useless code
- net: hns3: remove the limitation of MAC address duplicate configuration
- net: hns3: delete the unused struct hns3_link_mode_mapping
- net: hns3: rename one parameter in hclge_add_fd_entry_by_arfs()
- net: hns3: modify the location of macro HCLGE_LINK_STATUS_MS definition
- net: hns3: modify some unsuitable parameter type of RSS
- net: hns3: move some definition location
- net: hns3: add judgement for hclgevf_update_port_base_vlan_info()
- net: hns3: check null pointer in function hclge_fd_config_rule()
- net: hns3: optimize deletion of the flow direction table
- net: hns3: fix a ipv6 address copy problem in hclge_fd_get_flow_tuples()
- net: hns3: fix VF bandwidth does not take effect in some case
- net: hns3: synchronize some print relating to reset issue
- net: hns3: delete unnecessary 5s delay judgement in hclgevf_reset_event()
- net: hns3: delete unnecessary reset handling judgement in hclgevf_reset_tqp()
- net: hns3: delete unnecessary judgement in hns3_get_regs()
- net: hns3: delete one variable in hclge_get_sset_count() for optimization
- net: hns3: optimize return process for phy loop back
- net: hns3: fix "mac exist" problem
- net: hns3: add one printing information in hnae3_unregister_client() function
- slcan: Don't transmit uninitialized stack data in padding
- mm: mempolicy: require at least one nodeid for MPOL_PREFERRED
- livepatch/core: fix kabi for klp_rel_state
- livepatch/core: support jump_label
- arm64: entry: SP Alignment Fault doesn't write to FAR_EL1
- arm64: mark (__)cpus_have_const_cap as __always_inline
- arm64/module: revert to unsigned interpretation of ABS16/32 relocations
- arm64/module: deal with ambiguity in PRELxx relocation ranges
- i2c: designware: Add ACPI HID for Hisilicon Hip08-Lite I2C controller
- ACPI / APD: Add clock frequency for Hisilicon Hip08-Lite I2C controller
- qm: fix packet loss for acc
- net/hinic: Solve the problem that 1822 NIC reports 5d0 error
- net: hns3: Rectification of driver code review
- net: hns3: update hns3 version to 1.9.37.4
- net: hns3: additional fix for fraglist handling
- net: hns3: fix for fraglist skb headlen not handling correctly
- net: hns3: update hns3 version to 1.9.37.3
- sec: modify driver to adapt dm-crypt
- qm: reinforce reset failure scene
- zip: fix decompress a empty file
- hpre: dfx for IO operation and delay
- RDMA/hns: optimize mtr management and fix mtr addressing bug
- RDMA/hns: fix bug of accessing null pointer
- sec: Overall optimization of sec code
- qm: optimize the maximum number of VF and delete invalid addr
- qm: optimize set hw_reset flag logic for user
- qm: fixup the problem of wrong judgement of used parameter
- qm: Move all the same logic functions of hisilicon crypto to qm
- drivers : localbus cleancode
- drivers : sysctl cleancode
- drivers : sfc cleancode
- kretprobe: check re-registration of the same kretprobe earlier
- vhost: Check docket sk_family instead of call getname
- btrfs: tree-checker: Add EXTENT_ITEM and METADATA_ITEM check
- block: fix possible memory leak in 'blk_prepare_release_queue'
- Revert "dm-crypt: Add IV generation templates"
- Revert "dm-crypt: modify dm-crypt to rely on IV generation templates"

* Sat Mar 21 2020 Yang Yingliang <yangyingliang@huawei.com> - 4.19.90-2003.4.0.0036
- x86/config: enable CONFIG_CFQ_GROUP_IOSCHED
- x86/openeuler_config: disable CONFIG_EFI_VARS

* Fri Mar 20 2020 Yang Yingliang <yangyingliang@huawei.com> - 4.19.90-2003.3.0.0035
- btrfs: don't use WARN_ON when ret is -ENOTENT in __btrfs_free_extent()
- cifs: fix panic in smb2_reconnect

* Wed Mar 18 2020 Yang Yingliang <yangyingliang@huawei.com> - 4.19.90-2003.2.0.0034
- xfs: avoid f_bfree overflow
- xfs: always init fdblocks in mount
- xfs: devirtualize ->sf_entsize and ->sf_nextentry
- block: fix inaccurate io_ticks
- block: delete part_round_stats and switch to less precise counting
- CIFS: Fix bug which the return value by asynchronous read is error
- net/hinic: Magic number rectification
- net/hinic: slove the problem that VF may be disconnected when vm reboot and receive lots of broadcast packets.
- openeuler/config: disable CONFIG_EFI_VARS
- pagecache: support percpu refcount to imporve performance
- arm64: mm: support setting page attributes for debugging
- staging: android: ashmem: Disallow ashmem memory from being remapped
- mm/resource: Return real error codes from walk failures
- vt: selection, push sel_lock up
- vt: selection, push console lock down
- net: ipv6_stub: use ip6_dst_lookup_flow instead of ip6_dst_lookup
- net: ipv6: add net argument to ip6_dst_lookup_flow

* Mon Mar 16 2020 Luo Chunsheng <luochunsheng@huawei.com> - 4.19.90-2003.1.1.0033
- fix kernel-devel upgrade running scriptlet failed

* Sat Mar 14 2020 Yang Yingliang <yangyingliang@huawei.com> - 4.19.90-2003.1.1.0032
- openeuler/config: enable CONFIG_FCOE
- openeuler/config: disable unused debug config
- net: hns3: update the number of version
- net: hns3: add dumping vlan filter config in debugfs
- net: hns3: Increase vlan tag0 when close the port_base_vlan
- net: hns3: adds support for extended VLAN mode and 'QOS' in vlan 802.1Q protocol.

* Thu Mar 12 2020 Yang Yingliang <yangyingliang@huawei.com> - 4.19.90-2003.1.0.0031
- net/hinic: driver code compliance rectification
- net/hinic: Solve the problem that the network card hangs when receiving the skb which frag_size=0
- net: hns3: adds support for reading module eeprom info
- net: hns3: update hns3 version to 1.9.37.1
- btrfs: tree-checker: Remove comprehensive root owner check
- xfs: add agf freeblocks verify in xfs_agf_verify
- blktrace: fix dereference after null check
- blktrace: Protect q->blk_trace with RCU
- vgacon: Fix a UAF in vgacon_invert_region
- can, slip: Protect tty->disc_data in write_wakeup and close with RCU
- relay: handle alloc_percpu returning NULL in relay_open
- drm/radeon: check the alloc_workqueue return value
- apparmor: Fix use-after-free in aa_audit_rule_init

* Wed Mar 4 2020 Luo Chunsheng <luochunsheng@huawei.com> - 4.19.95-2002.6.0.0030
- delete useless directory

* Tue Mar 3 2020 Yang Yingliang <yangyingliang@huawei.com> - 4.19.95-2002.6.0.0029
- livepatch/x86: enable livepatch config openeuler
- livepatch/x86: enable livepatch config for hulk
- livepatch/arm64: check active func in consistency stack checking
- livepatch/x86: check active func in consistency stack checking
- livepatch/x86: support livepatch without ftrace
- KVM: nVMX: Check IO instruction VM-exit conditions
- KVM: nVMX: Refactor IO bitmap checks into helper function
- KVM: nVMX: Don't emulate instructions in guest mode
- floppy: check FDC index for errors before assigning it
- ext4: add cond_resched() to __ext4_find_entry()
* Fri Feb 28 2020 Yang Yingliang <yangyingliang@huawei.com> - 4.19.95-2002.5.0.0028
- x86 / config: add openeuler_defconfig
- files_cgroup: Fix soft lockup when refcnt overflow.
- vt: selection, close sel_buffer race
- vt: selection, handle pending signals in paste_selection
- RDMA/hns: Compilation Configuration update
- jbd2: do not clear the BH_Mapped flag when forgetting a metadata buffer
- jbd2: move the clearing of b_modified flag to the journal_unmap_buffer()
- iscsi: use dynamic single thread workqueue to improve performance
- workqueue: implement NUMA affinity for single thread workqueue
- iscsi: add member for NUMA aware order workqueue
- Revert "debugfs: fix kabi for function debugfs_remove_recursive"
- Revert "bdi: fix kabi for struct backing_dev_info"
- Revert "membarrier/kabi: fix kabi for membarrier_state"
- Revert "PCI: fix kabi change in struct pci_bus"
- files_cgroup: fix error pointer when kvm_vm_worker_thread
- bdi: get device name under rcu protect
- x86/kvm: Be careful not to clear KVM_VCPU_FLUSH_TLB bit
- timer_list: avoid other cpu soft lockup when printing timer list
- sysrq: avoid concurrently info printing by 'sysrq-trigger'
- bdi: fix memleak in bdi_register_va()
- iommu/iova: avoid softlockup in fq_flush_timeout
- qm: fix the way judge whether q stop in user space
- net: hns3: clear devil number for hns3_cae
- net: hns3: fix compile error when CONFIG_HNS3_DCB is not set
- qm: fixup compilation dependency
- rde: optimize debug regs clear logic
- sec: change sec_control reg config
- hpre: add likely and unlikey in result judgement
- hpre: optimize key process before free
- net: hns3: fix bug when parameter check
- drivers : sysctl fixup some param dont check the legitimacy
- net: hns3: add protect for parameters and remove unused functions
- qm: remove invalid addr print
- zip: use offset fields in sqe to avoid SG_SPLIT
- qm: fix wrong number of sg elements after dma map
- RDMA/hns:security review update
- RDMA/hns: some robust optimize in rdfx
- RDMA/hns: fix the bug of out-of-bonds-read in post send
- net: hns3: Remove the function of vf check mac address
- net: hns3: update hns3 version to 1.9.35.1
- uacce: Remove uacce mode 1 relatives
- acc: Remove uacce mode 1 logic below hisilicon
- RDMA/hns: Add roce dfx of arm_cnt
- RDMA/hns: avoid potential overflow of
- RDMA/hns: handle device err after device state to UNIT
- net: hns3: change version to 1.9.35.0
- net: hns3: fix missing help info for qs shaper in debugfs
- net: hns3: set VF's default reset_type to HNAE3_NONE_RESET
- net: hns3: fix port base vlan add fail when concurrent with reset
- net: hns3: skip mac speed and duplex modification checking for fibre port support autoneg
- net: hns3: modify timing of reading register in hclge_reset_wait()
- net: hns3: support of dump mac id and loopback status in debugfs
- net: hns3: optimize parameter of hclge_set_phy_loopback() function
- net: hns3: optimize parameter of hclge_phy_link_status_wait() function
- net: hns3: delete unnecessary judgement in hns3_get_stats()
- net: hns3: no need to check return value of debugfs_create functions
- net: hns3: make array spec_opcode static const, makes object smaller
- net: hns: replace space with tab for cleanup
- net: hns3: modify return value in hns3_dbg_cmd_write
- net: hns3: rename variable flag in hnae3_unregister_client()
- net: hns3: move struct hclge_mdio_cfg_cmd declaration
- net: hns3: modify error process of hclge_phy_link_status_wait()
- net: hns3: support query vf ring and vector map relation
- net: hns3: add enabled tc numbers and dwrr weight info in debugfs
- net: hns3: add error process in hclge_mac_link_status_wait() function
- net: hns3: modify code of hclge_mac_phy_link_status_wait() function
- net: hns3: replace goto with return in function hns3_set_ringparam()
- net: hns3: modify print format in hns3_set_ringpa()
- net: hns: replace goto with return in function hclge_set_vf_uc_mac_addr
- net: hns3: modify the irq name of misc vectors
- net: hns3: optimize code of hns3_parse_vlan_tag() function
- net: hns3: optimize local variable of hclge_set_loopback() function
- net: hns3: optimize code of hclge_init_kdump_kernel_config() function
- net: hns: remove unnecessary newline
- net: hns: modify print function used in hclge_init_ae_dev()
- net: hns3: modify the irq name of tqp vectors
- net: hns3: delete blank lines and space for cleanup
- net: hns3: do not schedule the periodical task when reset fail
- net: hns3: modify the location of updating the hardware reset done counter
- net: hns3: refactor the notification scheme of PF reset
- net: hns3: refactor the procedure of VF FLR
- net: hns3: modify hclge_func_reset_sync_vf()'s return type to void
- net: hns3: enlarge HCLGE_RESET_WAIT_CNT
- net: hns3: refactor the precedure of PF FLR
- net: hns3: split hclgevf_reset() into preparing and rebuilding part
- net: hns3: split hclge_reset() into preparing and rebuilding part
- net: hns3: Add "mac table" information query function
- net: hns3: fix bug that PF set VF mac didn't work
- net: hns3: delete some useless repeated printing
- net: hns3: delete some useless function and definication
- net: hns3: sync some code from net-next part1
- net: hns3: refactor the promisc mode setting
- net: hns3: refine mac address configure for VF
- net: hns3: use mutex vport_lock intead of spin lock umv_lock
- net: hns3: opmitize the table entry restore when resetting
- net: hns3: refine mac address configure for PF
- net: fix bug and change version to 1.9.33.0
- net: hns3: cae clear warnings
- drivers : sysctl remove rcu_lock
- RDMA/hns:remove useless header in cmd
- hac: sec: add initial configuration in sec_engine_init
- net: hns3: cae security review
- net: hns3: cae io_param definition updated
- debugfs: fix kabi for function debugfs_remove_recursive
- simple_recursive_removal(): kernel-side rm -rf for ramfs-style filesystems
- debugfs: simplify __debugfs_remove_file()
- block: rename 'q->debugfs_dir' and 'q->blk_trace->dir' in blk_unregister_queue()
- ext4: add cond_resched() to ext4_protect_reserved_inode
- bdi: fix kabi for struct backing_dev_info
- bdi: fix use-after-free for the bdi device
- vfs: fix do_last() regression
- do_last(): fetch directory ->i_mode and ->i_uid before it's too late
- ext4: reserve revoke credits in __ext4_new_inode
- jbd2: make jbd2_handle_buffer_credits() handle reserved handles
- jbd2: Fine tune estimate of necessary descriptor blocks
- jbd2: Provide trace event for handle restarts
- ext4: Reserve revoke credits for freed blocks
- jbd2: Make credit checking more strict
- jbd2: Rename h_buffer_credits to h_total_credits
- jbd2: Reserve space for revoke descriptor blocks
- jbd2: Drop jbd2_space_needed()
- jbd2: remove repeated assignments in __jbd2_log_wait_for_space()
- jbd2: Account descriptor blocks into t_outstanding_credits
- jbd2: Factor out common parts of stopping and restarting a handle
- jbd2: Drop pointless wakeup from jbd2_journal_stop()
- jbd2: Drop pointless check from jbd2_journal_stop()
- jbd2: Reorganize jbd2_journal_stop()
- ocfs2: Use accessor function for h_buffer_credits
- ext4, jbd2: Provide accessor function for handle credits
- ext4: Provide function to handle transaction restarts
- ext4: Avoid unnecessary revokes in ext4_alloc_branch()
- ext4: Use ext4_journal_extend() instead of jbd2_journal_extend()
- ext4: Fix ext4_should_journal_data() for EA inodes
- ext4: Do not iput inode under running transaction
- ext4: Move marking of handle as sync to ext4_add_nondir()
- jbd2: Completely fill journal descriptor blocks
- jbd2: Fixup stale comment in commit code
- libertas: Fix two buffer overflows at parsing bss descriptor
* Fri Feb 7 2020 Xie XiuQi <xiexiuqi@huawei.com> - 4.19.95-2002.1.0.0027
- drm/i915/gen9: Clear residual context state on context switch
- selftest/membarrier: fix build error
- membarrier/kabi: fix kabi for membarrier_state
- membarrier: Fix RCU locking bug caused by faulty merge
- sched/membarrier: Return -ENOMEM to userspace on memory allocation failure
- sched/membarrier: Skip IPIs when mm->mm_users == 1
- selftests, sched/membarrier: Add multi-threaded test
- sched/membarrier: Fix p->mm->membarrier_state racy load
- sched: Clean up active_mm reference counting
- sched/membarrier: Remove redundant check
- drm/i915: Fix use-after-free when destroying GEM context
- PCI: fix kabi change in struct pci_bus
- PCI: add a member in 'struct pci_bus' to record the original 'pci_ops'
- KVM: tools/kvm_stat: Fix kvm_exit filter name
- KVM: arm/arm64: use esr_ec as trace field of kvm_exit tracepoint
- PCI/AER: increments pci bus reference count in aer-inject process
- irqchip/gic-v3-its: its support herbination
- PM / hibernate: introduce system_in_hibernation
- config: enable CONFIG_SMMU_BYPASS_DEV by default
- f2fs: support swap file w/ DIO
- mac80211: Do not send Layer 2 Update frame before authorization
- cfg80211/mac80211: make ieee80211_send_layer2_update a public function
- PCI/AER: Refactor error injection fallbacks
- net/sched: act_mirred: Pull mac prior redir to non mac_header_xmit device
- kernfs: fix potential null pointer dereference
- arm64: fix calling nmi_enter() repeatedly when IPI_CPU_CRASH_STOP
- usb: missing parentheses in USE_NEW_SCHEME
- USB: serial: option: add Telit ME910G1 0x110a composition
- USB: core: fix check for duplicate endpoints
- usb: dwc3: gadget: Fix request complete check
- net: sch_prio: When ungrafting, replace with FIFO
- mlxsw: spectrum_qdisc: Ignore grafting of invisible FIFO
- vlan: vlan_changelink() should propagate errors
- vlan: fix memory leak in vlan_dev_set_egress_priority
- vxlan: fix tos value before xmit
- tcp: fix "old stuff" D-SACK causing SACK to be treated as D-SACK
- sctp: free cmd->obj.chunk for the unprocessed SCTP_CMD_REPLY
- sch_cake: avoid possible divide by zero in cake_enqueue()
- pkt_sched: fq: do not accept silly TCA_FQ_QUANTUM
- net: usb: lan78xx: fix possible skb leak
- net: stmmac: dwmac-sunxi: Allow all RGMII modes
- net: stmmac: dwmac-sun8i: Allow all RGMII modes
- net: dsa: mv88e6xxx: Preserve priority when setting CPU port.
- macvlan: do not assume mac_header is set in macvlan_broadcast()
- gtp: fix bad unlock balance in gtp_encap_enable_socket
- PCI/switchtec: Read all 64 bits of part_event_bitmap
- ARM: dts: imx6ul: use nvmem-cells for cpu speed grading
- cpufreq: imx6q: read OCOTP through nvmem for imx6ul/imx6ull
- powerpc/spinlocks: Include correct header for static key
- powerpc/vcpu: Assume dedicated processors as non-preempt
- hv_netvsc: Fix unwanted rx_table reset
- llc2: Fix return statement of llc_stat_ev_rx_null_dsap_xid_c (and _test_c)
- parisc: Fix compiler warnings in debug_core.c
- block: fix memleak when __blk_rq_map_user_iov() is failed
- s390/dasd: fix memleak in path handling error case
- s390/dasd/cio: Interpret ccw_device_get_mdc return value correctly
- drm/exynos: gsc: add missed component_del
- s390/purgatory: do not build purgatory with kcov, kasan and friends
- net: stmmac: Always arm TX Timer at end of transmission start
- net: stmmac: RX buffer size must be 16 byte aligned
- net: stmmac: xgmac: Clear previous RX buffer size
- net: stmmac: Do not accept invalid MTU values
- fs: avoid softlockups in s_inodes iterators
- perf/x86/intel: Fix PT PMI handling
- kconfig: don't crash on NULL expressions in expr_eq()
- iommu/iova: Init the struct iova to fix the possible memleak
- regulator: rn5t618: fix module aliases
- ASoC: wm8962: fix lambda value
- rfkill: Fix incorrect check to avoid NULL pointer dereference
- parisc: add missing __init annotation
- net: usb: lan78xx: Fix error message format specifier
- cxgb4: Fix kernel panic while accessing sge_info
- bnx2x: Fix logic to get total no. of PFs per engine
- bnx2x: Do not handle requests from VFs after parity
- bpf: Clear skb->tstamp in bpf_redirect when necessary
- btrfs: Fix error messages in qgroup_rescan_init
- powerpc: Ensure that swiotlb buffer is allocated from low memory
- samples: bpf: fix syscall_tp due to unused syscall
- samples: bpf: Replace symbol compare of trace_event
- ARM: dts: am437x-gp/epos-evm: fix panel compatible
- spi: spi-ti-qspi: Fix a bug when accessing non default CS
- bpf, mips: Limit to 33 tail calls
- bnxt_en: Return error if FW returns more data than dump length
- ARM: dts: bcm283x: Fix critical trip point
- ASoC: topology: Check return value for soc_tplg_pcm_create()
- spi: spi-cavium-thunderx: Add missing pci_release_regions()
- ARM: dts: Cygnus: Fix MDIO node address/size cells
- selftests/ftrace: Fix multiple kprobe testcase
- ARM: dts: BCM5301X: Fix MDIO node address/size cells
- netfilter: nf_tables: validate NFT_DATA_VALUE after nft_data_init()
- netfilter: nf_tables: validate NFT_SET_ELEM_INTERVAL_END
- netfilter: nft_set_rbtree: bogus lookup/get on consecutive elements in named sets
- netfilter: uapi: Avoid undefined left-shift in xt_sctp.h
- ARM: vexpress: Set-up shared OPP table instead of individual for each CPU
- ARM: dts: imx6ul: imx6ul-14x14-evk.dtsi: Fix SPI NOR probing
- efi/gop: Fix memory leak in __gop_query32/64()
- efi/gop: Return EFI_SUCCESS if a usable GOP was found
- efi/gop: Return EFI_NOT_FOUND if there are no usable GOPs
- ASoC: Intel: bytcr_rt5640: Update quirk for Teclast X89
- x86/efi: Update e820 with reserved EFI boot services data to fix kexec breakage
- libtraceevent: Fix lib installation with O=
- netfilter: ctnetlink: netns exit must wait for callbacks
- locking/spinlock/debug: Fix various data races
- ASoC: max98090: fix possible race conditions
- regulator: fix use after free issue
- bpf: Fix passing modified ctx to ld/abs/ind instruction
- USB: dummy-hcd: increase max number of devices to 32
- USB: dummy-hcd: use usb_urb_dir_in instead of usb_pipein
- block: fix use-after-free on cached last_lookup partition
- perf/x86/intel/bts: Fix the use of page_private()
- xen/blkback: Avoid unmapping unmapped grant pages
- s390/smp: fix physical to logical CPU map for SMT
- ubifs: ubifs_tnc_start_commit: Fix OOB in layout_in_gaps
- net: add annotations on hh->hh_len lockless accesses
- xfs: periodically yield scrub threads to the scheduler
- ath9k_htc: Discard undersized packets
- ath9k_htc: Modify byte order for an error message
- net: core: limit nested device depth
- rxrpc: Fix possible NULL pointer access in ICMP handling
- KVM: PPC: Book3S HV: use smp_mb() when setting/clearing host_ipi flag
- selftests: rtnetlink: add addresses with fixed life time
- powerpc/pseries/hvconsole: Fix stack overread via udbg
- drm/mst: Fix MST sideband up-reply failure handling
- scsi: qedf: Do not retry ELS request if qedf_alloc_cmd fails
- bdev: Refresh bdev size for disks without partitioning
- bdev: Factor out bdev revalidation into a common helper
- fix compat handling of FICLONERANGE, FIDEDUPERANGE and FS_IOC_FIEMAP
- tty: serial: msm_serial: Fix lockup for sysrq and oops
- arm64: dts: meson: odroid-c2: Disable usb_otg bus to avoid power failed warning
- dt-bindings: clock: renesas: rcar-usb2-clock-sel: Fix typo in example
- regulator: ab8500: Remove AB8505 USB regulator
- media: flexcop-usb: ensure -EIO is returned on error condition
- Bluetooth: Fix memory leak in hci_connect_le_scan
- Bluetooth: delete a stray unlock
- Bluetooth: btusb: fix PM leak in error case of setup
- platform/x86: pmc_atom: Add Siemens CONNECT X300 to critclk_systems DMI table
- xfs: don't check for AG deadlock for realtime files in bunmapi
- ACPI: sysfs: Change ACPI_MASKABLE_GPE_MAX to 0x100
- HID: i2c-hid: Reset ALPS touchpads on resume
- nfsd4: fix up replay_matches_cache()
- PM / devfreq: Check NULL governor in available_governors_show
- drm/msm: include linux/sched/task.h
- ftrace: Avoid potential division by zero in function profiler
- arm64: Revert support for execute-only user mappings
- exit: panic before exit_mm() on global init exit
- ALSA: firewire-motu: Correct a typo in the clock proc string
- ALSA: cs4236: fix error return comparison of an unsigned integer
- apparmor: fix aa_xattrs_match() may sleep while holding a RCU lock
- tracing: Fix endianness bug in histogram trigger
- tracing: Have the histogram compare functions convert to u64 first
- tracing: Avoid memory leak in process_system_preds()
- tracing: Fix lock inversion in trace_event_enable_tgid_record()
- rseq/selftests: Fix: Namespace gettid() for compatibility with glibc 2.30
- riscv: ftrace: correct the condition logic in function graph tracer
- gpiolib: fix up emulated open drain outputs
- libata: Fix retrieving of active qcs
- ata: ahci_brcm: BCM7425 AHCI requires AHCI_HFLAG_DELAY_ENGINE
- ata: ahci_brcm: Add missing clock management during recovery
- ata: ahci_brcm: Allow optional reset controller to be used
- ata: ahci_brcm: Fix AHCI resources management
- ata: libahci_platform: Export again ahci_platform_<en/dis>able_phys()
- compat_ioctl: block: handle BLKREPORTZONE/BLKRESETZONE
- compat_ioctl: block: handle Persistent Reservations
- dmaengine: Fix access to uninitialized dma_slave_caps
- locks: print unsigned ino in /proc/locks
- pstore/ram: Write new dumps to start of recycled zones
- mm: move_pages: return valid node id in status if the page is already on the target node
- memcg: account security cred as well to kmemcg
- mm/zsmalloc.c: fix the migrated zspage statistics.
- media: cec: check 'transmit_in_progress', not 'transmitting'
- media: cec: avoid decrementing transmit_queue_sz if it is 0
- media: cec: CEC 2.0-only bcast messages were ignored
- media: pulse8-cec: fix lost cec_transmit_attempt_done() call
- MIPS: Avoid VDSO ABI breakage due to global register variable
- drm/sun4i: hdmi: Remove duplicate cleanup calls
- ALSA: hda/realtek - Add headset Mic no shutup for ALC283
- ALSA: usb-audio: set the interface format after resume on Dell WD19
- ALSA: usb-audio: fix set_format altsetting sanity check
- ALSA: ice1724: Fix sleep-in-atomic in Infrasonic Quartet support code
- netfilter: nft_tproxy: Fix port selector on Big Endian
- drm: limit to INT_MAX in create_blob ioctl
- taskstats: fix data-race
- xfs: fix mount failure crash on invalid iclog memory access
- ALSA: hda - fixup for the bass speaker on Lenovo Carbon X1 7th gen
- ALSA: hda/realtek - Enable the bass speaker of ASUS UX431FLC
- ALSA: hda/realtek - Add Bass Speaker and fixed dac for bass speaker
- PM / hibernate: memory_bm_find_bit(): Tighten node optimisation
- xen/balloon: fix ballooned page accounting without hotplug enabled
- xen-blkback: prevent premature module unload
- IB/mlx5: Fix steering rule of drop and count
- IB/mlx4: Follow mirror sequence of device add during device removal
- s390/cpum_sf: Avoid SBD overflow condition in irq handler
- s390/cpum_sf: Adjust sampling interval to avoid hitting sample limits
- md: raid1: check rdev before reference in raid1_sync_request func
- afs: Fix creation calls in the dynamic root to fail with EOPNOTSUPP
- net: make socket read/write_iter() honor IOCB_NOWAIT
- usb: gadget: fix wrong endpoint desc
- drm/nouveau: Move the declaration of struct nouveau_conn_atom up a bit
- scsi: iscsi: qla4xxx: fix double free in probe
- scsi: qla2xxx: Ignore PORT UPDATE after N2N PLOGI
- scsi: qla2xxx: Send Notify ACK after N2N PLOGI
- scsi: qla2xxx: Configure local loop for N2N target
- scsi: qla2xxx: Fix PLOGI payload and ELS IOCB dump length
- scsi: qla2xxx: Don't call qlt_async_event twice
- scsi: qla2xxx: Drop superfluous INIT_WORK of del_work
- scsi: lpfc: Fix memory leak on lpfc_bsg_write_ebuf_set func
- rxe: correctly calculate iCRC for unaligned payloads
- RDMA/cma: add missed unregister_pernet_subsys in init failure
- afs: Fix SELinux setting security label on /afs
- afs: Fix afs_find_server lookups for ipv4 peers
- PM / devfreq: Don't fail devfreq_dev_release if not in list
- PM / devfreq: Set scaling_max_freq to max on OPP notifier error
- PM / devfreq: Fix devfreq_notifier_call returning errno
- iio: adc: max9611: Fix too short conversion time delay
- drm/amd/display: Fixed kernel panic when booting with DP-to-HDMI dongle
- drm/amdgpu: add cache flush workaround to gfx8 emit_fence
- drm/amdgpu: add check before enabling/disabling broadcast mode
- nvme-fc: fix double-free scenarios on hw queues
- nvme_fc: add module to ops template to allow module references
- spi: fsl: use platform_get_irq() instead of of_irq_to_resource()
- pinctrl: baytrail: Really serialize all register accesses
- tty/serial: atmel: fix out of range clock divider handling
- spi: fsl: don't map irq during probe
- gtp: avoid zero size hashtable
- gtp: fix an use-after-free in ipv4_pdp_find()
- gtp: fix wrong condition in gtp_genl_dump_pdp()
- tcp: do not send empty skb from tcp_write_xmit()
- tcp/dccp: fix possible race __inet_lookup_established()
- net: marvell: mvpp2: phylink requires the link interrupt
- gtp: do not allow adding duplicate tid and ms_addr pdp context
- net/dst: do not confirm neighbor for vxlan and geneve pmtu update
- sit: do not confirm neighbor when do pmtu update
- vti: do not confirm neighbor when do pmtu update
- tunnel: do not confirm neighbor when do pmtu update
- net/dst: add new function skb_dst_update_pmtu_no_confirm
- gtp: do not confirm neighbor when do pmtu update
- ip6_gre: do not confirm neighbor when do pmtu update
- net: add bool confirm_neigh parameter for dst_ops.update_pmtu
- vhost/vsock: accept only packets with the right dst_cid
- udp: fix integer overflow while computing available space in sk_rcvbuf
- tcp: Fix highest_sack and highest_sack_seq
- ptp: fix the race between the release of ptp_clock and cdev
- net: stmmac: dwmac-meson8b: Fix the RGMII TX delay on Meson8b/8m2 SoCs
- net/mlxfw: Fix out-of-memory error in mfa2 flash burning
- net: ena: fix napi handler misbehavior when the napi budget is zero
- hrtimer: Annotate lockless access to timer->state
- net: icmp: fix data-race in cmp_global_allow()
- net: add a READ_ONCE() in skb_peek_tail()
- inetpeer: fix data-race in inet_putpeer / inet_putpeer
- netfilter: bridge: make sure to pull arp header in br_nf_forward_arp()
- 6pack,mkiss: fix possible deadlock
- netfilter: ebtables: compat: reject all padding in matches/watchers
- bonding: fix active-backup transition after link failure
- ALSA: hda - Downgrade error message for single-cmd fallback
- netfilter: nf_queue: enqueue skbs with NULL dst
- net, sysctl: Fix compiler warning when only cBPF is present
- x86/mce: Fix possibly incorrect severity calculation on AMD
- Revert "powerpc/vcpu: Assume dedicated processors as non-preempt"
- userfaultfd: require CAP_SYS_PTRACE for UFFD_FEATURE_EVENT_FORK
- kernel: sysctl: make drop_caches write-only
- mailbox: imx: Fix Tx doorbell shutdown path
- ocfs2: fix passing zero to 'PTR_ERR' warning
- s390/cpum_sf: Check for SDBT and SDB consistency
- libfdt: define INT32_MAX and UINT32_MAX in libfdt_env.h
- s390/zcrypt: handle new reply code FILTERED_BY_HYPERVISOR
- perf regs: Make perf_reg_name() return "unknown" instead of NULL
- perf script: Fix brstackinsn for AUXTRACE
- cdrom: respect device capabilities during opening action
- powerpc: Don't add -mabi= flags when building with Clang
- scripts/kallsyms: fix definitely-lost memory leak
- apparmor: fix unsigned len comparison with less than zero
- gpio: mpc8xxx: Don't overwrite default irq_set_type callback
- scsi: target: iscsi: Wait for all commands to finish before freeing a session
- scsi: iscsi: Don't send data to unbound connection
- scsi: NCR5380: Add disconnect_mask module parameter
- scsi: scsi_debug: num_tgts must be >= 0
- scsi: ufs: Fix error handing during hibern8 enter
- scsi: pm80xx: Fix for SATA device discovery
- watchdog: Fix the race between the release of watchdog_core_data and cdev
- HID: rmi: Check that the RMI_STARTED bit is set before unregistering the RMI transport device
- HID: Improve Windows Precision Touchpad detection.
- libnvdimm/btt: fix variable 'rc' set but not used
- ARM: 8937/1: spectre-v2: remove Brahma-B53 from hardening
- HID: logitech-hidpp: Silence intermittent get_battery_capacity errors
- HID: quirks: Add quirk for HP MSU1465 PIXART OEM mouse
- bcache: at least try to shrink 1 node in bch_mca_scan()
- clk: pxa: fix one of the pxa RTC clocks
- scsi: atari_scsi: sun3_scsi: Set sg_tablesize to 1 instead of SG_NONE
- powerpc/security: Fix wrong message when RFI Flush is disable
- PCI: rpaphp: Correctly match ibm, my-drc-index to drc-name when using drc-info
- PCI: rpaphp: Annotate and correctly byte swap DRC properties
- PCI: rpaphp: Don't rely on firmware feature to imply drc-info support
- powerpc/pseries/cmm: Implement release() function for sysfs device
- scsi: ufs: fix potential bug which ends in system hang
- PCI: rpaphp: Fix up pointer to first drc-info entry
- scsi: lpfc: fix: Coverity: lpfc_cmpl_els_rsp(): Null pointer dereferences
- fs/quota: handle overflows of sysctl fs.quota.* and report as unsigned long
- irqchip: ingenic: Error out if IRQ domain creation failed
- irqchip/irq-bcm7038-l1: Enable parent IRQ if necessary
- clk: clk-gpio: propagate rate change to parent
- clk: qcom: Allow constant ratio freq tables for rcg
- f2fs: fix to update dir's i_pino during cross_rename
- scsi: lpfc: Fix duplicate unreg_rpi error in port offline flow
- scsi: tracing: Fix handling of TRANSFER LENGTH == 0 for READ(6) and WRITE(6)
- jbd2: Fix statistics for the number of logged blocks
- ext4: iomap that extends beyond EOF should be marked dirty
- powerpc/book3s64/hash: Add cond_resched to avoid soft lockup warning
- powerpc/security/book3s64: Report L1TF status in sysfs
- clocksource/drivers/timer-of: Use unique device name instead of timer
- clocksource/drivers/asm9260: Add a check for of_clk_get
- leds: lm3692x: Handle failure to probe the regulator
- dma-debug: add a schedule point in debug_dma_dump_mappings()
- powerpc/tools: Don't quote $objdump in scripts
- powerpc/pseries: Don't fail hash page table insert for bolted mapping
- powerpc/pseries: Mark accumulate_stolen_time() as notrace
- scsi: hisi_sas: Replace in_softirq() check in hisi_sas_task_exec()
- scsi: csiostor: Don't enable IRQs too early
- scsi: lpfc: Fix SLI3 hba in loop mode not discovering devices
- scsi: target: compare full CHAP_A Algorithm strings
- dmaengine: xilinx_dma: Clear desc_pendingcount in xilinx_dma_reset
- iommu/tegra-smmu: Fix page tables in > 4 GiB memory
- iommu: rockchip: Free domain on .domain_free
- f2fs: fix to update time in lazytime mode
- Input: atmel_mxt_ts - disable IRQ across suspend
- scsi: lpfc: Fix locking on mailbox command completion
- scsi: mpt3sas: Fix clear pending bit in ioctl status
- scsi: lpfc: Fix discovery failures when target device connectivity bounces
- perf probe: Fix to show function entry line as probe-able
- mmc: sdhci: Add a quirk for broken command queuing
- mmc: sdhci: Workaround broken command queuing on Intel GLK
- mmc: sdhci-of-esdhc: fix P2020 errata handling
- mmc: sdhci: Update the tuning failed messages to pr_debug level
- mmc: sdhci-of-esdhc: Revert "mmc: sdhci-of-esdhc: add erratum A-009204 support"
- mmc: sdhci-msm: Correct the offset and value for DDR_CONFIG register
- powerpc/irq: fix stack overflow verification
- powerpc/vcpu: Assume dedicated processors as non-preempt
- x86/MCE/AMD: Allow Reserved types to be overwritten in smca_banks[]
- x86/MCE/AMD: Do not use rdmsr_safe_on_cpu() in smca_configure()
- KVM: arm64: Ensure 'params' is initialised when looking up sys register
- ext4: unlock on error in ext4_expand_extra_isize()
- staging: comedi: gsc_hpdi: check dma_alloc_coherent() return value
- platform/x86: hp-wmi: Make buffer for HPWMI_FEATURE2_QUERY 128 bytes
- intel_th: pci: Add Elkhart Lake SOC support
- intel_th: pci: Add Comet Lake PCH-V support
- USB: EHCI: Do not return -EPIPE when hub is disconnected
- cpufreq: Avoid leaving stale IRQ work items during CPU offline
- usbip: Fix error path of vhci_recv_ret_submit()
- usbip: Fix receive error in vhci-hcd when using scatter-gather
- btrfs: return error pointer from alloc_test_extent_buffer
- s390/ftrace: fix endless recursion in function_graph tracer
- drm/amdgpu: fix uninitialized variable pasid_mapping_needed
- usb: xhci: Fix build warning seen with CONFIG_PM=n
- can: kvaser_usb: kvaser_usb_leaf: Fix some info-leaks to USB devices
- mmc: mediatek: fix CMD_TA to 2 for MT8173 HS200/HS400 mode
- Revert "mmc: sdhci: Fix incorrect switch to HS mode"
- btrfs: don't prematurely free work in scrub_missing_raid56_worker()
- btrfs: don't prematurely free work in reada_start_machine_worker()
- net: phy: initialise phydev speed and duplex sanely
- drm/amdgpu: fix bad DMA from INTERRUPT_CNTL2
- mips: fix build when "48 bits virtual memory" is enabled
- libtraceevent: Fix memory leakage in copy_filter_type
- crypto: vmx - Avoid weird build failures
- mac80211: consider QoS Null frames for STA_NULLFUNC_ACKED
- crypto: sun4i-ss - Fix 64-bit size_t warnings on sun4i-ss-hash.c
- crypto: sun4i-ss - Fix 64-bit size_t warnings
- net: ethernet: ti: ale: clean ale tbl on init and intf restart
- fbtft: Make sure string is NULL terminated
- iwlwifi: check kasprintf() return value
- brcmfmac: remove monitor interface when detaching
- x86/insn: Add some Intel instructions to the opcode map
- ASoC: Intel: bytcr_rt5640: Update quirk for Acer Switch 10 SW5-012 2-in-1
- ASoC: wm5100: add missed pm_runtime_disable
- spi: st-ssc4: add missed pm_runtime_disable
- ASoC: wm2200: add missed operations in remove and probe failure
- btrfs: don't prematurely free work in run_ordered_work()
- btrfs: don't prematurely free work in end_workqueue_fn()
- mmc: tmio: Add MMC_CAP_ERASE to allow erase/discard/trim requests
- crypto: virtio - deal with unsupported input sizes
- tun: fix data-race in gro_normal_list()
- spi: tegra20-slink: add missed clk_unprepare
- ASoC: wm8904: fix regcache handling
- iwlwifi: mvm: fix unaligned read of rx_pkt_status
- bcache: fix deadlock in bcache_allocator
- tracing/kprobe: Check whether the non-suffixed symbol is notrace
- tracing: use kvcalloc for tgid_map array allocation
- x86/crash: Add a forward declaration of struct kimage
- cpufreq: Register drivers only after CPU devices have been registered
- bcache: fix static checker warning in bcache_device_free()
- parport: load lowlevel driver if ports not found
- nvme: Discard workaround for non-conformant devices
- s390/disassembler: don't hide instruction addresses
- ASoC: Intel: kbl_rt5663_rt5514_max98927: Add dmic format constraint
- iio: dac: ad5446: Add support for new AD5600 DAC
- ASoC: rt5677: Mark reg RT5677_PWR_ANLG2 as volatile
- spi: pxa2xx: Add missed security checks
- EDAC/ghes: Fix grain calculation
- media: si470x-i2c: add missed operations in remove
- ice: delay less
- crypto: atmel - Fix authenc support when it is set to m
- soundwire: intel: fix PDI/stream mapping for Bulk
- media: pvrusb2: Fix oops on tear-down when radio support is not present
- fsi: core: Fix small accesses and unaligned offsets via sysfs
- ath10k: fix get invalid tx rate for Mesh metric
- perf probe: Filter out instances except for inlined subroutine and subprogram
- perf probe: Skip end-of-sequence and non statement lines
- perf probe: Fix to show calling lines of inlined functions
- perf probe: Return a better scope DIE if there is no best scope
- perf probe: Skip overlapped location on searching variables
- perf parse: If pmu configuration fails free terms
- xen/gntdev: Use select for DMA_SHARED_BUFFER
- drm/amdgpu: fix potential double drop fence reference
- drm/amdgpu: disallow direct upload save restore list from gfx driver
- perf tools: Splice events onto evlist even on error
- perf probe: Fix to probe a function which has no entry pc
- libsubcmd: Use -O0 with DEBUG=1
- perf probe: Fix to show inlined function callsite without entry_pc
- perf probe: Fix to show ranges of variables in functions without entry_pc
- perf probe: Fix to probe an inline function which has no entry pc
- perf probe: Walk function lines in lexical blocks
- perf jevents: Fix resource leak in process_mapfile() and main()
- perf probe: Fix to list probe event with correct line number
- perf probe: Fix to find range-only function instance
- rtlwifi: fix memory leak in rtl92c_set_fw_rsvdpagepkt()
- ALSA: timer: Limit max amount of slave instances
- spi: img-spfi: fix potential double release
- bnx2x: Fix PF-VF communication over multi-cos queues.
- rfkill: allocate static minor
- nvmem: imx-ocotp: reset error status on probe
- media: v4l2-core: fix touch support in v4l_g_fmt
- ixgbe: protect TX timestamping from API misuse
- pinctrl: amd: fix __iomem annotation in amd_gpio_irq_handler()
- Bluetooth: Fix advertising duplicated flags
- libbpf: Fix error handling in bpf_map__reuse_fd()
- iio: dln2-adc: fix iio_triggered_buffer_postenable() position
- pinctrl: sh-pfc: sh7734: Fix duplicate TCLK1_B
- loop: fix no-unmap write-zeroes request behavior
- libata: Ensure ata_port probe has completed before detach
- s390/mm: add mm_pxd_folded() checks to pxd_free()
- s390/time: ensure get_clock_monotonic() returns monotonic values
- phy: qcom-usb-hs: Fix extcon double register after power cycle
- net: dsa: LAN9303: select REGMAP when LAN9303 enable
- gpu: host1x: Allocate gather copy for host1x
- RDMA/qedr: Fix memory leak in user qp and mr
- ACPI: button: Add DMI quirk for Medion Akoya E2215T
- spi: sprd: adi: Add missing lock protection when rebooting
- drm/tegra: sor: Use correct SOR index on Tegra210
- net: phy: dp83867: enable robust auto-mdix
- i40e: initialize ITRN registers with correct values
- arm64: psci: Reduce the waiting time for cpu_psci_cpu_kill()
- md/bitmap: avoid race window between md_bitmap_resize and bitmap_file_clear_bit
- media: smiapp: Register sensor after enabling runtime PM on the device
- x86/ioapic: Prevent inconsistent state when moving an interrupt
- ipmi: Don't allow device module unload when in use
- rtl8xxxu: fix RTL8723BU connection failure issue after warm reboot
- drm/gma500: fix memory disclosures due to uninitialized bytes
- perf tests: Disable bp_signal testing for arm64
- x86/mce: Lower throttling MCE messages' priority to warning
- bpf/stackmap: Fix deadlock with rq_lock in bpf_get_stack()
- Bluetooth: hci_core: fix init for HCI_USER_CHANNEL
- Bluetooth: Workaround directed advertising bug in Broadcom controllers
- Bluetooth: missed cpu_to_le16 conversion in hci_init4_req
- iio: adc: max1027: Reset the device at probe time
- usb: usbfs: Suppress problematic bind and unbind uevents.
- perf report: Add warning when libunwind not compiled in
- perf test: Report failure for mmap events
- drm/bridge: dw-hdmi: Restore audio when setting a mode
- ath10k: Correct error handling of dma_map_single()
- x86/mm: Use the correct function type for native_set_fixmap()
- extcon: sm5502: Reset registers during initialization
- drm/amd/display: Fix dongle_caps containing stale information.
- syscalls/x86: Use the correct function type in SYSCALL_DEFINE0
- media: ti-vpe: vpe: fix a v4l2-compliance failure about invalid sizeimage
- media: ti-vpe: vpe: ensure buffers are cleaned up properly in abort cases
- media: ti-vpe: vpe: fix a v4l2-compliance failure causing a kernel panic
- media: ti-vpe: vpe: Make sure YUYV is set as default format
- media: ti-vpe: vpe: fix a v4l2-compliance failure about frame sequence number
- media: ti-vpe: vpe: fix a v4l2-compliance warning about invalid pixel format
- media: ti-vpe: vpe: Fix Motion Vector vpdma stride
- media: cx88: Fix some error handling path in 'cx8800_initdev()'
- drm/drm_vblank: Change EINVAL by the correct errno
- block: Fix writeback throttling W=1 compiler warnings
- samples: pktgen: fix proc_cmd command result check logic
- drm/bridge: dw-hdmi: Refuse DDC/CI transfers on the internal I2C controller
- media: cec-funcs.h: add status_req checks
- media: flexcop-usb: fix NULL-ptr deref in flexcop_usb_transfer_init()
- regulator: max8907: Fix the usage of uninitialized variable in max8907_regulator_probe()
- hwrng: omap3-rom - Call clk_disable_unprepare() on exit only if not idled
- usb: renesas_usbhs: add suspend event support in gadget mode
- media: venus: Fix occasionally failures to suspend
- selftests/bpf: Correct path to include msg + path
- pinctrl: devicetree: Avoid taking direct reference to device name string
- ath10k: fix offchannel tx failure when no ath10k_mac_tx_frm_has_freq
- media: venus: core: Fix msm8996 frequency table
- tools/power/cpupower: Fix initializer override in hsw_ext_cstates
- media: ov6650: Fix stored crop rectangle not in sync with hardware
- media: ov6650: Fix stored frame format not in sync with hardware
- media: i2c: ov2659: Fix missing 720p register config
- media: ov6650: Fix crop rectangle alignment not passed back
- media: i2c: ov2659: fix s_stream return value
- media: am437x-vpfe: Setting STD to current value is not an error
- IB/iser: bound protection_sg size by data_sg size
- ath10k: fix backtrace on coredump
- staging: rtl8188eu: fix possible null dereference
- staging: rtl8192u: fix multiple memory leaks on error path
- spi: Add call to spi_slave_abort() function when spidev driver is released
- drm/amdgpu: grab the id mgr lock while accessing passid_mapping
- iio: light: bh1750: Resolve compiler warning and make code more readable
- drm/bridge: analogix-anx78xx: silence -EPROBE_DEFER warnings
- drm/panel: Add missing drm_panel_init() in panel drivers
- drm: mst: Fix query_payload ack reply struct
- ALSA: hda/ca0132 - Fix work handling in delayed HP detection
- ALSA: hda/ca0132 - Avoid endless loop
- ALSA: hda/ca0132 - Keep power on during processing DSP response
- ALSA: pcm: Avoid possible info leaks from PCM stream buffers
- Btrfs: fix removal logic of the tree mod log that leads to use-after-free issues
- btrfs: handle ENOENT in btrfs_uuid_tree_iterate
- btrfs: do not leak reloc root if we fail to read the fs root
- btrfs: skip log replay on orphaned roots
- btrfs: abort transaction after failed inode updates in create_subvol
- btrfs: send: remove WARN_ON for readonly mount
- Btrfs: fix missing data checksums after replaying a log tree
- btrfs: do not call synchronize_srcu() in inode_tree_del
- btrfs: don't double lock the subvol_sem for rename exchange
- selftests: forwarding: Delete IPv6 address at the end
- sctp: fully initialize v4 addr in some functions
- qede: Fix multicast mac configuration
- qede: Disable hardware gro when xdp prog is installed
- net: usb: lan78xx: Fix suspend/resume PHY register access error
- net: qlogic: Fix error paths in ql_alloc_large_buffers()
- net: nfc: nci: fix a possible sleep-in-atomic-context bug in nci_uart_tty_receive()
- net: hisilicon: Fix a BUG trigered by wrong bytes_compl
- net: gemini: Fix memory leak in gmac_setup_txqs
- net: dst: Force 4-byte alignment of dst_metrics
- mod_devicetable: fix PHY module format
- fjes: fix missed check in fjes_acpi_add
- sock: fix potential memory leak in proto_register()
- arm64/sve: Fix missing SVE/FPSIMD endianness conversions
- svm: Delete ifdef CONFIG_ACPI in svm
- svm: Delete svm_unbind_cores() in svm_notifier_release call
- svm: Fix unpin_memory calculate nr_pages error
- vrf: Do not attempt to create IPv6 mcast rule if IPv6 is disabled
- iommu: Add missing new line for dma type
- xhci: fix USB3 device initiated resume race with roothub autosuspend
- drm/radeon: fix r1xx/r2xx register checker for POT textures
- scsi: iscsi: Fix a potential deadlock in the timeout handler
- dm mpath: remove harmful bio-based optimization
- drm: meson: venc: cvbs: fix CVBS mode matching
- dma-buf: Fix memory leak in sync_file_merge()
- vfio/pci: call irq_bypass_unregister_producer() before freeing irq
- ARM: tegra: Fix FLOW_CTLR_HALT register clobbering by tegra_resume()
- ARM: dts: s3c64xx: Fix init order of clock providers
- CIFS: Close open handle after interrupted close
- CIFS: Respect O_SYNC and O_DIRECT flags during reconnect
- cifs: Don't display RDMA transport on reconnect
- cifs: smbd: Return -EINVAL when the number of iovs exceeds SMBDIRECT_MAX_SGE
- cifs: smbd: Add messages on RDMA session destroy and reconnection
- cifs: smbd: Return -EAGAIN when transport is reconnecting
- rpmsg: glink: Free pending deferred work on remove
- rpmsg: glink: Don't send pending rx_done during remove
- rpmsg: glink: Fix rpmsg_register_device err handling
- rpmsg: glink: Put an extra reference during cleanup
- rpmsg: glink: Fix use after free in open_ack TIMEOUT case
- rpmsg: glink: Fix reuse intents memory leak issue
- rpmsg: glink: Set tail pointer to 0 at end of FIFO
- xtensa: fix TLB sanity checker
- PCI: Apply Cavium ACS quirk to ThunderX2 and ThunderX3
- PCI/MSI: Fix incorrect MSI-X masking on resume
- PCI: Fix Intel ACS quirk UPDCR register address
- PCI/PM: Always return devices to D0 when thawing
- mmc: block: Add CMD13 polling for MMC IOCTLS with R1B response
- mmc: block: Make card_busy_detect() a bit more generic
- Revert "arm64: preempt: Fix big-endian when checking preempt count in assembly"
- tcp: Protect accesses to .ts_recent_stamp with {READ, WRITE}_ONCE()
- tcp: tighten acceptance of ACKs not matching a child socket
- tcp: fix rejected syncookies due to stale timestamps
- net/mlx5e: Query global pause state before setting prio2buffer
- tipc: fix ordering of tipc module init and exit routine
- tcp: md5: fix potential overestimation of TCP option space
- openvswitch: support asymmetric conntrack
- net: thunderx: start phy before starting autonegotiation
- net: sched: fix dump qlen for sch_mq/sch_mqprio with NOLOCK subqueues
- net: ethernet: ti: cpsw: fix extra rx interrupt
- net: dsa: fix flow dissection on Tx path
- net: bridge: deny dev_set_mac_address() when unregistering
- mqprio: Fix out-of-bounds access in mqprio_dump
- inet: protect against too small mtu values.
- ext4: check for directory entries too close to block end
- ext4: fix ext4_empty_dir() for directories with holes

* Mon Jan 13 2020 luochunsheng<luochunsheng@huawei.com> - 4.19.90-vhulk1912.2.1.0026
- fix compile error when debugfiles.list is empty

* Mon Jan 13 2020 luochunsheng<luochunsheng@huawei.com> - 4.19.90-vhulk1912.2.1.0025
- update kernel code from https://gitee.com/openeuler/kernel/ 

* Mon Jan  6 2020 zhanghailiang<zhang.zhanghailiang@huawei.com> - 4.19.90-vhulk1912.2.1.0024
- support more than 256 vcpus for VM

* Tue Dec 31 2019 linfeilong<linfeilong@huawei.com> - 4.19.90-vhulk1912.2.1.0023
- delete some unuseful file

* Mon Dec 30 2019 yuxiangyang<yuxiangyang4@huawei.com> - 4.19.90-vhulk1912.2.1.0022
- update Huawei copyright

* Mon Dec 30 2019 caomeng<caomeng5@huawei.com> - 4.19.90-vhulk1912.2.1.0021
- modefied README.md

* Sat Dec 28 2019 caomeng<caomeng5@huawei.com> - 4.19.90-vhulk1912.2.1.0020
- change tag and change config_ktask

* Sat Dec 28 2019 caomeng<caomeng5@huawei.com> - 4.19.90-vhulk1907.1.0.0019
- modefied license

* Wed Dec 25 2019 luochunsheng<luochunsheng@huawei.com> - 4.19.90-vhulk1907.1.0.0018
- update Module.kabi_aarch64
- fix patch kernel-SMMU-V3-support-Virtualization-with-3408iMR-3.patch

* Tue Dec 24 2019 Pan Zhang<zhangpan26@huawei.com> - 4.19.90-vhulk1907.1.0.0017
- fix get_user_pages_fast with evmm issue

* Tue Dec 24 2019 caihongda <caihongda@huawei.com> - 4.19.90-vhulk1907.1.0.0016
- cpu/freq:remove unused patches

* Tue Dec 24 2019 shenkai <shenkai8@huawei.com> - 4.19.90-vhulk1907.1.0.0015
- modify vmap allocation start address

* Tue Dec 24 2019 caomeng<caomeng5@huawei.com> - 4.19.90-vhulk1907.1.0.0014
- fix some problem about rebase hulk

* Mon Dec 23 2019 yuxiangyang<yuxiangyang4@huawei.com> - 4.19.90-vhulk1907.1.0.0013
- fix CONFIG_EULEROS_USE_IDLE_NO_CSTATES compile error
- add a new method of cpu usage

* Mon Dec 23 2019 caomeng <caomeng5@huawei.com> - 4.19.90-vhulk1907.1.0.0012
- change version

* Mon Dec 23 2019 luochunsheng <luochunsheng@huawei.com> - 4.19.36-vhulk1907.1.0.0011
- fix mkgrub-menu-*.sh path
- SMMU supports bypass of configured PCI devices by cmdline smmu.bypassdev

* Mon Dec 23 2019 chenmaodong<chenmaodong@huawei.com> - 4.19.36-vhulk1907.1.0.0010
- drm/radeon: Fix potential buffer overflow in ci_dpm.c

* Mon Dec 23 2019 wuxu<wuxu.wu@huawei.com> - 4.19.36-vhulk1907.1.0.0009
- add security compile noexecstack option for vdso

* Mon Dec 23 2019 caomeng<caomeng5@huawei.com> - 4.19.36-vhulk1907.1.0.0008
- rebase hulk patches

* Fri Dec 20 2019 yeyunfeng<yeyunfeng@huawei.com> - 4.19.36-vhulk1907.1.0.0007
- perf/smmuv3: fix possible sleep in preempt context
- crypto: user - prevent operating on larval algorithms

* Thu Dec 19 2019 luochunsheng <luochunsheng@huawei.com> - 4.19.36-vhulk1907.1.0.0006
- update release to satisfy upgrade

* Wed Nov 27 2019 lihongjiang <lihongjiang6@huawei.com> - 4.19.36-vhulk1907.1.0.h005
- change page size from 4K to 64K

* Thu Nov 21 2019 caomeng <caomeng5@huawei.com> - 4.19.36-vhulk1907.1.0.h004
- fix problem about x86 compile: change signing_key.pem to certs/signing_key.pem
- in file arch/x86/configs/euleros_defconfig

* Mon Nov 4 2019 caomeng <caomeng5@huawei.com> - 4.19.36-vhulk1907.1.0.h003
- Add buildrequires ncurlses-devel

* Fri Oct 25 2019 luochunsheng <luochunsheng@huawei.com> - 4.19.36-vhulk1907.1.0.h002
- Add vmlinx to debuginfo package and add kernel-source package

* Wed Sep 04 2019 openEuler Buildteam <buildteam@openeuler.org> - 4.19.36-vhulk1907.1.0.h001
- Package init
