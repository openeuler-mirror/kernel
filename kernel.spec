

%define with_signmodules  1

%define with_kabichk 1

%define modsign_cmd %{SOURCE10}

%global Arch $(echo %{_host_cpu} | sed -e s/i.86/x86/ -e s/x86_64/x86/ -e s/aarch64.*/arm64/)

%global TarballVer 4.19.90

%global KernelVer %{version}-%{release}.%{_target_cpu}

%global hulkrelease 2004.1.0

%define with_patch 0

%define debuginfodir /usr/lib/debug

%define with_debuginfo 1

%define with_source 1

Name:	 kernel
Version: 4.19.90
Release: %{hulkrelease}.0037
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

cp -a tools/perf tools/python3-perf

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
# perf
# perf tool binary and supporting scripts/binaries
%{perf_make} %{perf_python2} DESTDIR=%{buildroot} lib=%{_lib} install-bin install-traceevent-plugins
# remove the 'trace' symlink.
rm -f %{buildroot}%{_bindir}/trace
# remove the perf-tips
rm -rf %{buildroot}%{_docdir}/perf-tip

# remove examples
rm -rf %{buildroot}/usr/lib/perf/examples
# remove the stray header file that somehow got packaged in examples
rm -rf %{buildroot}/usr/lib/perf/include/bpf/

# python-perf extension
%{perf_make} %{perf_python3} DESTDIR=%{buildroot} install-python_ext
%{perf_make} %{perf_python2} DESTDIR=%{buildroot} install-python_ext

# perf man pages (note: implicit rpm magic compresses them later)
install -d %{buildroot}/%{_mandir}/man1
install -pm0644 tools/kvm/kvm_stat/kvm_stat.1 %{buildroot}/%{_mandir}/man1/
install -pm0644 tools/perf/Documentation/*.1 %{buildroot}/%{_mandir}/man1/

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

%files -n perf
%{_bindir}/perf
%dir %{_libdir}/traceevent
%{_libdir}/traceevent/plugins/
%{_libexecdir}/perf-core
%{_datadir}/perf-core/
%{_mandir}/man[1-8]/perf*
%{_sysconfdir}/bash_completion.d/perf
%doc linux-%{KernelVer}/tools/perf/Documentation/examples.txt
%license linux-%{KernelVer}/COPYING

%files -n python2-perf
%license linux-%{KernelVer}/COPYING
%{python2_sitearch}/*

%files -n python3-perf
%license linux-%{KernelVer}/COPYING
%{python3_sitearch}/*

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
* Tue Apr 28 2020 Yang Yingliang <yangyingliang@huawei.com> - 4.19.90-2004.1.0.0037
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

* Thu Mar 14 2020 Yang Yingliang <yangyingliang@huawei.com> - 4.19.90-2003.1.1.0032
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
- Linux 4.19.95
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
- Linux 4.19.94
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
- Linux 4.19.93
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
- Linux 4.19.92
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
- Linux 4.19.91
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
