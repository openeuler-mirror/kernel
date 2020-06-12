

%define with_signmodules  1

%define with_kabichk 1

%define modsign_cmd %{SOURCE10}

%global Arch $(echo %{_host_cpu} | sed -e s/i.86/x86/ -e s/x86_64/x86/ -e s/aarch64.*/arm64/)

%global TarballVer 4.19.126

%global KernelVer %{version}-%{release}.%{_target_cpu}

%global hulkrelease 

%define with_patch 0

%define debuginfodir /usr/lib/debug

%define with_debuginfo 1

%define with_source 1

Name:	 kernel
Version: 4.19.126
Release: %{hulkrelease}.0036
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
* Fri Jun 12 2020 Yang Yingliang <yangyingliang@huawei.com> - 4.19.9127

- Linux 4.19.127
- net: smsc911x: Fix runtime PM imbalance on error
- net: ethernet: stmmac: Enable interface clocks on probe for IPQ806x
- net/ethernet/freescale: rework quiesce/activate for ucc_geth
- null_blk: return error for invalid zone size
- s390/mm: fix set_huge_pte_at() for empty ptes
- drm/edid: Add Oculus Rift S to non-desktop list
- net: bmac: Fix read of MAC address from ROM
- x86/mmiotrace: Use cpumask_available() for cpumask_var_t variables
- i2c: altera: Fix race between xfer_msg and isr thread
- evm: Fix RCU list related warnings
- ARC: [plat-eznps]: Restrict to CONFIG_ISA_ARCOMPACT
- ARC: Fix ICCM & DCCM runtime size checks
- s390/ftrace: save traced function caller
- spi: dw: use "smp_mb()" to avoid sending spi data error
- powerpc/powernv: Avoid re-registration of imc debugfs directory
- drm/i915: fix port checks for MST support on gen >= 11
- airo: Fix read overflows sending packets
- net: dsa: mt7530: set CPU port to fallback mode
- scsi: ufs: Release clock if DMA map fails
- mmc: fix compilation of user API
- p54usb: add AirVasT USB stick device-id
- HID: i2c-hid: add Schneider SCL142ALM to descriptor override
- HID: sony: Fix for broken buttons on DS3 USB dongles
- libnvdimm: Fix endian conversion issues 
- Revert "cgroup: Add memory barriers to plug cgroup_rstat_updated() race window"
- Linux 4.19.126
- netfilter: nf_conntrack_pptp: fix compilation warning with W=1 build
- bonding: Fix reference count leak in bond_sysfs_slave_add.
- crypto: chelsio/chtls: properly set tp->lsndtime
- qlcnic: fix missing release in qlcnic_83xx_interrupt_test.
- xsk: Add overflow check for u64 division, stored into u32
- bnxt_en: Fix accumulation of bp->net_stats_prev.
- esp6: get the right proto for transport mode in esp6_gso_encap
- netfilter: nf_conntrack_pptp: prevent buffer overflows in debug code
- netfilter: nfnetlink_cthelper: unbreak userspace helper support
- netfilter: ipset: Fix subcounter update skip
- netfilter: nft_reject_bridge: enable reject with bridge vlan
- ip_vti: receive ipip packet by calling ip_tunnel_rcv
- vti4: eliminated some duplicate code.
- xfrm: fix error in comment
- xfrm: fix a NULL-ptr deref in xfrm_local_error
- xfrm: fix a warning in xfrm_policy_insert_list
- xfrm interface: fix oops when deleting a x-netns interface
- xfrm: call xfrm_output_gso when inner_protocol is set in xfrm_output
- xfrm: allow to accept packets with ipv6 NEXTHDR_HOP in xfrm_input
- copy_xstate_to_kernel(): don't leave parts of destination uninitialized
- x86/dma: Fix max PFN arithmetic overflow on 32 bit systems
- mac80211: mesh: fix discovery timer re-arming issue / crash
- RDMA/core: Fix double destruction of uobject
- mmc: core: Fix recursive locking issue in CQE recovery path
- parisc: Fix kernel panic in mem_init()
- iommu: Fix reference count leak in iommu_group_alloc.
- include/asm-generic/topology.h: guard cpumask_of_node() macro argument
- mm: remove VM_BUG_ON(PageSlab()) from page_mapcount()
- IB/ipoib: Fix double free of skb in case of multicast traffic in CM mode
- libceph: ignore pool overlay and cache logic on redirects
- ALSA: hda/realtek - Add new codec supported for ALC287
- ALSA: usb-audio: Quirks for Gigabyte TRX40 Aorus Master onboard audio
- exec: Always set cap_ambient in cap_bprm_set_creds
- ALSA: usb-audio: mixer: volume quirk for ESS Technology Asus USB DAC
- ALSA: hda/realtek - Add a model for Thinkpad T570 without DAC workaround
- ALSA: hwdep: fix a left shifting 1 by 31 UB bug
- RDMA/pvrdma: Fix missing pci disable in pvrdma_pci_probe()
- mmc: block: Fix use-after-free issue for rpmb
- ARM: dts: bcm: HR2: Fix PPI interrupt types
- ARM: dts: bcm2835-rpi-zero-w: Fix led polarity
- ARM: dts/imx6q-bx50v3: Set display interface clock parents
- IB/qib: Call kobject_put() when kobject_init_and_add() fails
- gpio: exar: Fix bad handling for ida_simple_get error path
- ARM: uaccess: fix DACR mismatch with nested exceptions
- ARM: uaccess: integrate uaccess_save and uaccess_restore
- ARM: uaccess: consolidate uaccess asm to asm/uaccess-asm.h
- ARM: 8843/1: use unified assembler in headers
- ARM: 8970/1: decompressor: increase tag size
- Input: synaptics-rmi4 - fix error return code in rmi_driver_probe()
- Input: synaptics-rmi4 - really fix attn_data use-after-free
- Input: i8042 - add ThinkPad S230u to i8042 reset list
- Input: dlink-dir685-touchkeys - fix a typo in driver name
- Input: xpad - add custom init packet for Xbox One S controllers
- Input: evdev - call input_flush_device() on release(), not flush()
- Input: usbtouchscreen - add support for BonXeon TP
- samples: bpf: Fix build error
- cifs: Fix null pointer check in cifs_read
- riscv: stacktrace: Fix undefined reference to `walk_stackframe'
- IB/i40iw: Remove bogus call to netdev_master_upper_dev_get()
- net: freescale: select CONFIG_FIXED_PHY where needed
- usb: gadget: legacy: fix redundant initialization warnings
- usb: dwc3: pci: Enable extcon driver for Intel Merrifield
- cachefiles: Fix race between read_waiter and read_copier involving op->to_do
- gfs2: move privileged user check to gfs2_quota_lock_check
- net: microchip: encx24j600: add missed kthread_stop
- ALSA: usb-audio: add mapping for ASRock TRX40 Creator
- gpio: tegra: mask GPIO IRQs during IRQ shutdown
- ARM: dts: rockchip: fix pinctrl sub nodename for spi in rk322x.dtsi
- ARM: dts: rockchip: swap clock-names of gpu nodes
- arm64: dts: rockchip: swap interrupts interrupt-names rk3399 gpu node
- arm64: dts: rockchip: fix status for &gmac2phy in rk3328-evb.dts
- ARM: dts: rockchip: fix phy nodename for rk3228-evb
- mlxsw: spectrum: Fix use-after-free of split/unsplit/type_set in case reload fails
- net/mlx4_core: fix a memory leak bug.
- net: sun: fix missing release regions in cas_init_one().
- net/mlx5: Annotate mutex destroy for root ns
- net/mlx5e: Update netdev txq on completions during closure
- sctp: Start shutdown on association restart if in SHUTDOWN-SENT state and socket is closed
- sctp: Don't add the shutdown timer if its already been added
- r8152: support additional Microsoft Surface Ethernet Adapter variant
- net sched: fix reporting the first-time use timestamp
- net: qrtr: Fix passing invalid reference to qrtr_local_enqueue()
- net/mlx5: Add command entry handling completion
- net: ipip: fix wrong address family in init error path
- net: inet_csk: Fix so_reuseport bind-address cache in tb->fast*
- __netif_receive_skb_core: pass skb by reference
- net: dsa: mt7530: fix roaming from DSA user ports
- dpaa_eth: fix usage as DSA master, try 3
- ax25: fix setsockopt(SO_BINDTODEVICE)
- ALSA: proc: Avoid possible leaks of snd_info_entry objects
- vt: keyboard: avoid signed integer overflow in k_ascii
- ext4: Fix block bitmap corruption when io error
- mm: Fix mremap not considering huge pmd devmap
- SUNRPC: Fix xprt->timer use-after-free
- printk/panic: Avoid deadlock in printk()
- block: Fix use-after-free in blkdev_get()
- ata/libata: Fix usage of page address by page_address in ata_scsi_mode_select_xlat function
- media: go7007: fix a miss of snd_card_free
- scsi: core: avoid repetitive logging of device offline messages
- hfs: fix null-ptr-deref in hfs_find_init()
- ext4, jbd2: switch to use completion variable instead of JBD2_REC_ERR
- jbd2: clean __jbd2_journal_abort_hard() and __journal_abort_soft()
- Linux 4.19.125
- rxrpc: Fix ack discard
- rxrpc: Trace discarded ACKs
- iio: adc: stm32-dfsdm: fix device used to request dma
- iio: adc: stm32-dfsdm: Use dma_request_chan() instead dma_request_slave_channel()
- iio: adc: stm32-adc: fix device used to request dma
- iio: adc: stm32-adc: Use dma_request_chan() instead dma_request_slave_channel()
- x86/unwind/orc: Fix unwind_get_return_address_ptr() for inactive tasks
- rxrpc: Fix a memory leak in rxkad_verify_response()
- rapidio: fix an error in get_user_pages_fast() error handling
- ipack: tpci200: fix error return code in tpci200_register()
- mei: release me_cl object reference
- misc: rtsx: Add short delay after exit from ASPM
- iio: dac: vf610: Fix an error handling path in 'vf610_dac_probe()'
- iio: sca3000: Remove an erroneous 'get_device()'
- staging: greybus: Fix uninitialized scalar variable
- staging: iio: ad2s1210: Fix SPI reading
- Revert "gfs2: Don't demote a glock until its revokes are written"
- brcmfmac: abort and release host after error
- tty: serial: qcom_geni_serial: Fix wrap around of TX buffer
- cxgb4/cxgb4vf: Fix mac_hlist initialization and free
- cxgb4: free mac_hlist properly
- net: bcmgenet: abort suspend on error
- net: bcmgenet: code movement
- Revert "net/ibmvnic: Fix EOI when running in XIVE mode"
- media: fdp1: Fix R-Car M3-N naming in debug message
- thunderbolt: Drop duplicated get_switch_at_route()
- staging: most: core: replace strcpy() by strscpy()
- libnvdimm/btt: Fix LBA masking during 'free list' population
- libnvdimm/btt: Remove unnecessary code in btt_freelist_init
- nfit: Add Hyper-V NVDIMM DSM command set to white list
- powerpc/64s: Disable STRICT_KERNEL_RWX
- powerpc: Remove STRICT_KERNEL_RWX incompatibility with RELOCATABLE
- drm/i915/gvt: Init DPLL/DDI vreg for virtual display instead of inheritance.
- dmaengine: owl: Use correct lock in owl_dma_get_pchan()
- dmaengine: tegra210-adma: Fix an error handling path in 'tegra_adma_probe()'
- apparmor: Fix aa_label refcnt leak in policy_update
- apparmor: fix potential label refcnt leak in aa_change_profile
- drm/etnaviv: fix perfmon domain interation
- ALSA: hda/realtek - Add more fixup entries for Clevo machines
- ALSA: hda/realtek - Fix silent output on Gigabyte X570 Aorus Xtreme
- ALSA: pcm: fix incorrect hw_base increase
- ALSA: iec1712: Initialize STDSP24 properly when using the model=staudio option
- padata: purge get_cpu and reorder_via_wq from padata_do_serial
- padata: initialize pd->cpu with effective cpumask
- padata: Replace delayed timer with immediate workqueue in padata_reorder
- ARM: futex: Address build warning
- platform/x86: asus-nb-wmi: Do not load on Asus T100TA and T200TA
- USB: core: Fix misleading driver bug report
- stmmac: fix pointer check after utilization in stmmac_interrupt
- ceph: fix double unlock in handle_cap_export()
- HID: quirks: Add HID_QUIRK_NO_INIT_REPORTS quirk for Dell K12A keyboard-dock
- gtp: set NLM_F_MULTI flag in gtp_genl_dump_pdp()
- x86/apic: Move TSC deadline timer debug printk
- HID: i2c-hid: reset Synaptics SYNA2393 on resume
- scsi: ibmvscsi: Fix WARN_ON during event pool release
- component: Silence bind error on -EPROBE_DEFER
- aquantia: Fix the media type of AQC100 ethernet controller in the driver
- vhost/vsock: fix packet delivery order to monitoring devices
- configfs: fix config_item refcnt leak in configfs_rmdir()
- scsi: qla2xxx: Delete all sessions before unregister local nvme port
- scsi: qla2xxx: Fix hang when issuing nvme disconnect-all in NPIV
- HID: alps: ALPS_1657 is too specific; use U1_UNICORN_LEGACY instead
- HID: alps: Add AUI1657 device ID
- HID: multitouch: add eGalaxTouch P80H84 support
- gcc-common.h: Update for GCC 10
- ubi: Fix seq_file usage in detailed_erase_block_info debugfs file
- i2c: mux: demux-pinctrl: Fix an error handling path in 'i2c_demux_pinctrl_probe()'
- iommu/amd: Fix over-read of ACPI UID from IVRS table
- ubifs: remove broken lazytime support
- fix multiplication overflow in copy_fdtable()
- mtd: spinand: Propagate ECC information to the MTD structure
- ima: Fix return value of ima_write_policy()
- evm: Check also if *tfm is an error pointer in init_desc()
- ima: Set file->f_mode instead of file->f_flags in ima_calc_file_hash()
- riscv: set max_pfn to the PFN of the last page
- i2c: dev: Fix the race between the release of i2c_dev and cdev
- ubsan: build ubsan.c more conservatively
- x86/uaccess, ubsan: Fix UBSAN vs. SMAP
- Linux 4.19.124
- Makefile: disallow data races on gcc-10 as well
- KVM: x86: Fix off-by-one error in kvm_vcpu_ioctl_x86_setup_mce
- ARM: dts: r8a7740: Add missing extal2 to CPG node
- arm64: dts: renesas: r8a77980: Fix IPMMU VIP[01] nodes
- ARM: dts: r8a73a4: Add missing CMT1 interrupts
- arm64: dts: rockchip: Rename dwc3 device nodes on rk3399 to make dtc happy
- arm64: dts: rockchip: Replace RK805 PMIC node name with "pmic" on rk3328 boards
- clk: Unlink clock if failed to prepare or enable
- Revert "ALSA: hda/realtek: Fix pop noise on ALC225"
- usb: gadget: legacy: fix error return code in cdc_bind()
- usb: gadget: legacy: fix error return code in gncm_bind()
- usb: gadget: audio: Fix a missing error return value in audio_bind()
- usb: gadget: net2272: Fix a memory leak in an error handling path in 'net2272_plat_probe()'
- dwc3: Remove check for HWO flag in dwc3_gadget_ep_reclaim_trb_sg()
- clk: rockchip: fix incorrect configuration of rk3228 aclk_gpu* clocks
- exec: Move would_dump into flush_old_exec
- x86/unwind/orc: Fix error handling in __unwind_start()
- x86: Fix early boot crash on gcc-10, third try
- cifs: fix leaked reference on requeued write
- ARM: dts: imx27-phytec-phycard-s-rdk: Fix the I2C1 pinctrl entries
- ARM: dts: dra7: Fix bus_dma_limit for PCIe
- usb: xhci: Fix NULL pointer dereference when enqueuing trbs from urb sg list
- usb: host: xhci-plat: keep runtime active when removing host
- usb: core: hub: limit HUB_QUIRK_DISABLE_AUTOSUSPEND to USB5534B
- ALSA: usb-audio: Add control message quirk delay for Kingston HyperX headset
- ALSA: rawmidi: Fix racy buffer resize under concurrent accesses
- ALSA: hda/realtek - Limit int mic boost for Thinkpad T530
- gcc-10: avoid shadowing standard library 'free()' in crypto
- gcc-10: disable 'restrict' warning for now
- gcc-10: disable 'stringop-overflow' warning for now
- gcc-10: disable 'array-bounds' warning for now
- gcc-10: disable 'zero-length-bounds' warning for now
- Stop the ad-hoc games with -Wno-maybe-initialized
- kbuild: compute false-positive -Wmaybe-uninitialized cases in Kconfig
- gcc-10 warnings: fix low-hanging fruit
- pnp: Use list_for_each_entry() instead of open coding
- hwmon: (da9052) Synchronize access with mfd
- IB/mlx4: Test return value of calls to ib_get_cached_pkey
- netfilter: nft_set_rbtree: Introduce and use nft_rbtree_interval_start()
- arm64: fix the flush_icache_range arguments in machine_kexec
- netfilter: conntrack: avoid gcc-10 zero-length-bounds warning
- NFSv4: Fix fscache cookie aux_data to ensure change_attr is included
- nfs: fscache: use timespec64 in inode auxdata
- NFS: Fix fscache super_cookie index_key from changing after umount
- mmc: block: Fix request completion in the CQE timeout path
- mmc: core: Check request type before completing the request
- i40iw: Fix error handling in i40iw_manage_arp_cache()
- pinctrl: cherryview: Add missing spinlock usage in chv_gpio_irq_handler
- pinctrl: baytrail: Enable pin configuration setting for GPIO chip
- gfs2: Another gfs2_walk_metadata fix
- ALSA: hda/realtek - Fix S3 pop noise on Dell Wyse
- ipc/util.c: sysvipc_find_ipc() incorrectly updates position index
- drm/qxl: lost qxl_bo_kunmap_atomic_page in qxl_image_init_helper()
- ALSA: hda/hdmi: fix race in monitor detection during probe
- cpufreq: intel_pstate: Only mention the BIOS disabling turbo mode once
- dmaengine: mmp_tdma: Reset channel error on release
- dmaengine: pch_dma.c: Avoid data race between probe and irq handler
- riscv: fix vdso build with lld
- tcp: fix SO_RCVLOWAT hangs with fat skbs
- net: tcp: fix rx timestamp behavior for tcp_recvmsg
- net: ipv4: really enforce backoff for redirects
- net: dsa: loop: Add module soft dependency
- virtio_net: fix lockdep warning on 32 bit
- tcp: fix error recovery in tcp_zerocopy_receive()
- Revert "ipv6: add mtu lock check in __ip6_rt_update_pmtu"
- pppoe: only process PADT targeted at local interfaces
- net: phy: fix aneg restart in phy_ethtool_set_eee
- net: fix a potential recursive NETDEV_FEAT_CHANGE
- mmc: sdhci-acpi: Add SDHCI_QUIRK2_BROKEN_64_BIT_DMA for AMDI0040
- virtio-blk: handle block_device_operations callbacks after hot unplug
- drop_monitor: work around gcc-10 stringop-overflow warning
- net: moxa: Fix a potential double 'free_irq()'
- net/sonic: Fix a resource leak in an error handling path in 'jazz_sonic_probe()'
- shmem: fix possible deadlocks on shmlock_user_lock
- net: dsa: Do not make user port errors fatal
- Linux 4.19.123
- ipc/mqueue.c: change __do_notify() to bypass check_kill_permission()
- scripts/decodecode: fix trapping instruction formatting
- objtool: Fix stack offset tracking for indirect CFAs
- netfilter: nf_osf: avoid passing pointer to local var
- netfilter: nat: never update the UDP checksum when it's 0
- x86/unwind/orc: Fix premature unwind stoppage due to IRET frames
- x86/unwind/orc: Fix error path for bad ORC entry type
- x86/unwind/orc: Prevent unwinding before ORC initialization
- x86/unwind/orc: Don't skip the first frame for inactive tasks
- x86/entry/64: Fix unwind hints in rewind_stack_do_exit()
- x86/entry/64: Fix unwind hints in kernel exit path
- x86/entry/64: Fix unwind hints in register clearing code
- batman-adv: Fix refcnt leak in batadv_v_ogm_process
- batman-adv: Fix refcnt leak in batadv_store_throughput_override
- batman-adv: Fix refcnt leak in batadv_show_throughput_override
- batman-adv: fix batadv_nc_random_weight_tq
- KVM: VMX: Mark RCX, RDX and RSI as clobbered in vmx_vcpu_run()'s asm blob
- KVM: VMX: Explicitly reference RCX as the vmx_vcpu pointer in asm blobs
- coredump: fix crash when umh is disabled
- staging: gasket: Check the return value of gasket_get_bar_index()
- mm/page_alloc: fix watchdog soft lockups during set_zone_contiguous()
- arm64: hugetlb: avoid potential NULL dereference
- KVM: arm64: Fix 32bit PC wrap-around
- KVM: arm: vgic: Fix limit condition when writing to GICD_I[CS]ACTIVER
- tracing: Add a vmalloc_sync_mappings() for safe measure
- USB: serial: garmin_gps: add sanity checking for data length
- USB: uas: add quirk for LaCie 2Big Quadra
- HID: usbhid: Fix race between usbhid_close() and usbhid_stop()
- sctp: Fix bundling of SHUTDOWN with COOKIE-ACK
- HID: wacom: Read HID_DG_CONTACTMAX directly for non-generic devices
- net: stricter validation of untrusted gso packets
- bnxt_en: Fix VF anti-spoof filter setup.
- bnxt_en: Improve AER slot reset.
- net/mlx5: Fix command entry leak in Internal Error State
- net/mlx5: Fix forced completion access non initialized command entry
- bnxt_en: Fix VLAN acceleration handling in bnxt_fix_features().
- tipc: fix partial topology connection closure
- sch_sfq: validate silly quantum values
- sch_choke: avoid potential panic in choke_reset()
- net: usb: qmi_wwan: add support for DW5816e
- net_sched: sch_skbprio: add message validation to skbprio_change()
- net/mlx4_core: Fix use of ENOSPC around mlx4_counter_alloc()
- net: macsec: preserve ingress frame ordering
- fq_codel: fix TCA_FQ_CODEL_DROP_BATCH_SIZE sanity checks
- dp83640: reverse arguments to list_add_tail
- vt: fix unicode console freeing with a common interface
- tracing/kprobes: Fix a double initialization typo
- USB: serial: qcserial: Add DW5816e support
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
- mdev: Send uevents around parent device registration
- vfio/mdev: Synchronize device create/remove with parent removal
- vfio/mdev: Avoid creating sysfs remove file on stale device removal
- vfio/mdev: Improve the create/remove sequence
- arm64/mpam: Supplement err tips in info/last_cmd_status
- arm64/mpam: Fix unreset resources when mkdir ctrl group or umount resctrl
- ext4: report error to userspace by netlink
- pcie_cae add judgement about chip type
- Enable trust mode control for SR-IOV ports
- Added ethtool_ops interface to query optical module information
- Revert "consolemap: Fix a memory leaking bug in drivers/tty/vt/consolemap.c"
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
- config: disable CONFIG_ARM64_ERRATUM_1542419 by default
- Linux 4.19.122
- drm/atomic: Take the atomic toys away from X
- cgroup, netclassid: remove double cond_resched
- mac80211: add ieee80211_is_any_nullfunc()
- platform/x86: GPD pocket fan: Fix error message when temp-limits are out of range
- ALSA: hda: Match both PCI ID and SSID for driver blacklist
- hexagon: define ioremap_uc
- hexagon: clean up ioremap
- mfd: intel-lpss: Use devm_ioremap_uc for MMIO
- lib: devres: add a helper function for ioremap_uc
- drm/amdgpu: Fix oops when pp_funcs is unset in ACPI event
- sctp: Fix SHUTDOWN CTSN Ack in the peer restart case
- net: systemport: suppress warnings on failed Rx SKB allocations
- net: bcmgenet: suppress warnings on failed Rx SKB allocations
- lib/mpi: Fix building for powerpc with clang
- scripts/config: allow colons in option strings for sed
- s390/ftrace: fix potential crashes when switching tracers
- cifs: protect updating server->dstaddr with a spinlock
- ASoC: rsnd: Fix "status check failed" spam for multi-SSI
- ASoC: rsnd: Don't treat master SSI in multi SSI setup as parent
- net: stmmac: Fix sub-second increment
- net: stmmac: fix enabling socfpga's ptp_ref_clock
- wimax/i2400m: Fix potential urb refcnt leak
- drm/amdgpu: Correctly initialize thermal controller for GPUs with Powerplay table v0 (e.g Hawaii)
- ASoC: codecs: hdac_hdmi: Fix incorrect use of list_for_each_entry
- ASoC: rsnd: Fix HDMI channel mapping for multi-SSI mode
- ASoC: rsnd: Fix parent SSI start/stop in multi-SSI mode
- usb: dwc3: gadget: Properly set maxpacket limit
- ASoC: sgtl5000: Fix VAG power-on handling
- selftests/ipc: Fix test failure seen after initial test run
- ASoC: topology: Check return value of pcm_new_ver
- powerpc/pci/of: Parse unassigned resources
- vhost: vsock: kick send_pkt worker once device is started
- Linux 4.19.121
- mmc: meson-mx-sdio: remove the broken ->card_busy() op
- mmc: meson-mx-sdio: Set MMC_CAP_WAIT_WHILE_BUSY
- mmc: sdhci-msm: Enable host capabilities pertains to R1b response
- mmc: sdhci-pci: Fix eMMC driver strength for BYT-based controllers
- mmc: sdhci-xenon: fix annoying 1.8V regulator warning
- mmc: cqhci: Avoid false "cqhci: CQE stuck on" by not open-coding timeout loop
- btrfs: transaction: Avoid deadlock due to bad initialization timing of fs_info::journal_info
- btrfs: fix partial loss of prealloc extent past i_size after fsync
- selinux: properly handle multiple messages in selinux_netlink_send()
- dmaengine: dmatest: Fix iteration non-stop logic
- nfs: Fix potential posix_acl refcnt leak in nfs3_set_acl
- ALSA: opti9xx: shut up gcc-10 range warning
- iommu/amd: Fix legacy interrupt remapping for x2APIC-enabled system
- scsi: target/iblock: fix WRITE SAME zeroing
- iommu/qcom: Fix local_base status check
- vfio/type1: Fix VA->PA translation for PFNMAP VMAs in vaddr_get_pfn()
- vfio: avoid possible overflow in vfio_iommu_type1_pin_pages
- RDMA/core: Fix race between destroy and release FD object
- RDMA/core: Prevent mixed use of FDs between shared ufiles
- RDMA/mlx4: Initialize ib_spec on the stack
- RDMA/mlx5: Set GRH fields in query QP on RoCE
- scsi: qla2xxx: check UNLOADING before posting async work
- scsi: qla2xxx: set UNLOADING before waiting for session deletion
- dm multipath: use updated MPATHF_QUEUE_IO on mapping for bio-based mpath
- dm writecache: fix data corruption when reloading the target
- dm verity fec: fix hash block number in verity_fec_decode
- PM: hibernate: Freeze kernel threads in software_resume()
- PM: ACPI: Output correct message on target power state
- ALSA: pcm: oss: Place the plugin buffer overflow checks correctly
- ALSA: hda/hdmi: fix without unlocked before return
- ALSA: usb-audio: Correct a typo of NuPrime DAC-10 USB ID
- ALSA: hda/realtek - Two front mics on a Lenovo ThinkCenter
- btrfs: fix block group leak when removing fails
- drm/qxl: qxl_release use after free
- drm/qxl: qxl_release leak in qxl_hw_surface_alloc()
- drm/qxl: qxl_release leak in qxl_draw_dirty_fb()
- drm/edid: Fix off-by-one in DispID DTD pixel clock
- Linux 4.19.120
- propagate_one(): mnt_set_mountpoint() needs mount_lock
- ext4: check for non-zero journal inum in ext4_calculate_overhead
- qed: Fix use after free in qed_chain_free
- bpf, x86_32: Fix clobbering of dst for BPF_JSET
- hwmon: (jc42) Fix name to have no illegal characters
- ext4: convert BUG_ON's to WARN_ON's in mballoc.c
- ext4: increase wait time needed before reuse of deleted inode numbers
- ext4: use matching invalidatepage in ext4_writepage
- arm64: Delete the space separator in __emit_inst
- ALSA: hda: call runtime_allow() for all hda controllers
- xen/xenbus: ensure xenbus_map_ring_valloc() returns proper grant status
- objtool: Support Clang non-section symbols in ORC dump
- objtool: Fix CONFIG_UBSAN_TRAP unreachable warnings
- scsi: target: tcmu: reset_ring should reset TCMU_DEV_BIT_BROKEN
- scsi: target: fix PR IN / READ FULL STATUS for FC
- ALSA: hda: Explicitly permit using autosuspend if runtime PM is supported
- ALSA: hda: Keep the controller initialization even if no codecs found
- xfs: fix partially uninitialized structure in xfs_reflink_remap_extent
- x86: hyperv: report value of misc_features
- net: fec: set GPR bit on suspend by DT configuration.
- bpf, x86: Fix encoding for lower 8-bit registers in BPF_STX BPF_B
- xfs: clear PF_MEMALLOC before exiting xfsaild thread
- mm: shmem: disable interrupt when acquiring info->lock in userfaultfd_copy path
- bpf, x86_32: Fix incorrect encoding in BPF_LDX zero-extension
- perf/core: fix parent pid/tid in task exit events
- net/mlx5: Fix failing fw tracer allocation on s390
- cpumap: Avoid warning when CONFIG_DEBUG_PER_CPU_MAPS is enabled
- ARM: dts: bcm283x: Disable dsi0 node
- PCI: Move Apex Edge TPU class quirk to fix BAR assignment
- PCI: Avoid ASMedia XHCI USB PME# from D0 defect
- svcrdma: Fix leak of svc_rdma_recv_ctxt objects
- svcrdma: Fix trace point use-after-free race
- xfs: acquire superblock freeze protection on eofblocks scans
- net/cxgb4: Check the return from t4_query_params properly
- rxrpc: Fix DATA Tx to disable nofrag for UDP on AF_INET6 socket
- i2c: altera: use proper variable to hold errno
- nfsd: memory corruption in nfsd4_lock()
- ASoC: wm8960: Fix wrong clock after suspend & resume
- ASoC: tas571x: disable regulators on failed probe
- ASoC: q6dsp6: q6afe-dai: add missing channels to MI2S DAIs
- iio:ad7797: Use correct attribute_group
- usb: gadget: udc: bdc: Remove unnecessary NULL checks in bdc_req_complete
- usb: dwc3: gadget: Do link recovery for SS and SSP
- binder: take read mode of mmap_sem in binder_alloc_free_page()
- include/uapi/linux/swab.h: fix userspace breakage, use __BITS_PER_LONG for swap
- mtd: cfi: fix deadloop in cfi_cmdset_0002.c do_write_buffer
- remoteproc: Fix wrong rvring index computation
- Linux 4.19.119
- xfs: Fix deadlock between AGI and AGF with RENAME_WHITEOUT
- serial: sh-sci: Make sure status register SCxSR is read in correct sequence
- xhci: prevent bus suspend if a roothub port detected a over-current condition
- usb: f_fs: Clear OS Extended descriptor counts to zero in ffs_data_reset()
- usb: dwc3: gadget: Fix request completion check
- UAS: fix deadlock in error handling and PM flushing work
- UAS: no use logging any details in case of ENODEV
- cdc-acm: introduce a cool down
- cdc-acm: close race betrween suspend() and acm_softint
- staging: vt6656: Power save stop wake_up_count wrap around.
- staging: vt6656: Fix pairwise key entry save.
- staging: vt6656: Fix drivers TBTT timing counter.
- staging: vt6656: Fix calling conditions of vnt_set_bss_mode
- staging: vt6656: Don't set RCR_MULTICAST or RCR_BROADCAST by default.
- vt: don't use kmalloc() for the unicode screen buffer
- vt: don't hardcode the mem allocation upper bound
- staging: comedi: Fix comedi_device refcnt leak in comedi_open
- staging: comedi: dt2815: fix writing hi byte of analog output
- powerpc/setup_64: Set cache-line-size based on cache-block-size
- ARM: imx: provide v7_cpu_resume() only on ARM_CPU_SUSPEND=y
- iwlwifi: mvm: beacon statistics shouldn't go backwards
- iwlwifi: pcie: actually release queue memory in TVQM
- ASoC: dapm: fixup dapm kcontrol widget
- audit: check the length of userspace generated audit records
- usb-storage: Add unusual_devs entry for JMicron JMS566
- tty: rocket, avoid OOB access
- tty: hvc: fix buffer overflow during hvc_alloc().
- KVM: VMX: Enable machine check support for 32bit targets
- KVM: Check validity of resolved slot when searching memslots
- KVM: s390: Return last valid slot if approx index is out-of-bounds
- tpm: ibmvtpm: retry on H_CLOSED in tpm_ibmvtpm_send()
- tpm/tpm_tis: Free IRQ if probing fails
- ALSA: usb-audio: Filter out unsupported sample rates on Focusrite devices
- ALSA: usb-audio: Fix usb audio refcnt leak when getting spdif
- ALSA: hda/realtek - Add new codec supported for ALC245
- ALSA: hda/realtek - Fix unexpected init_amp override
- ALSA: usx2y: Fix potential NULL dereference
- tools/vm: fix cross-compile build
- mm/ksm: fix NULL pointer dereference when KSM zero page is enabled
- mm/hugetlb: fix a addressing exception caused by huge_pte_offset
- vmalloc: fix remap_vmalloc_range() bounds checks
- USB: hub: Fix handling of connect changes during sleep
- USB: early: Handle AMD's spec-compliant identifiers, too
- USB: Add USB_QUIRK_DELAY_CTRL_MSG and USB_QUIRK_DELAY_INIT for Corsair K70 RGB RAPIDFIRE
- USB: sisusbvga: Change port variable from signed to unsigned
- iio: xilinx-xadc: Make sure not exceed maximum samplerate
- iio: xilinx-xadc: Fix sequencer configuration for aux channels in simultaneous mode
- iio: xilinx-xadc: Fix clearing interrupt when enabling trigger
- iio: xilinx-xadc: Fix ADC-B powerdown
- iio: adc: stm32-adc: fix sleep in atomic context
- iio: st_sensors: rely on odr mask to know if odr can be set
- iio: core: remove extra semi-colon from devm_iio_device_register() macro
- ALSA: usb-audio: Add connector notifier delegation
- ALSA: usb-audio: Add static mapping table for ALC1220-VB-based mobos
- ALSA: hda: Remove ASUS ROG Zenith from the blacklist
- KEYS: Avoid false positive ENOMEM error on key read
- mlxsw: Fix some IS_ERR() vs NULL bugs
- vrf: Check skb for XFRM_TRANSFORMED flag
- xfrm: Always set XFRM_TRANSFORMED in xfrm{4,6}_output_finish
- net: dsa: b53: b53_arl_rw_op() needs to select IVL or SVL
- net: dsa: b53: Rework ARL bin logic
- net: dsa: b53: Fix ARL register definitions
- net: dsa: b53: Lookup VID in ARL searches when VLAN is enabled
- vrf: Fix IPv6 with qdisc and xfrm
- team: fix hang in team_mode_get()
- tcp: cache line align MAX_TCP_HEADER
- sched: etf: do not assume all sockets are full blown
- net/x25: Fix x25_neigh refcnt leak when receiving frame
- net: stmmac: dwmac-meson8b: Add missing boundary to RGMII TX clock array
- net: netrom: Fix potential nr_neigh refcnt leak in nr_add_node
- net: bcmgenet: correct per TX/RX ring statistics
- macvlan: fix null dereference in macvlan_device_event()
- macsec: avoid to set wrong mtu
- ipv6: fix restrict IPV6_ADDRFORM operation
- cxgb4: fix large delays in PTP synchronization
- cxgb4: fix adapter crash due to wrong MC size
- x86/KVM: Clean up host's steal time structure
- x86/KVM: Make sure KVM_VCPU_FLUSH_TLB flag is not missed
- x86/kvm: Cache gfn to pfn translation
- x86/kvm: Introduce kvm_(un)map_gfn()
- KVM: Properly check if "page" is valid in kvm_vcpu_unmap
- kvm: fix compile on s390 part 2
- kvm: fix compilation on s390
- kvm: fix compilation on aarch64
- KVM: Introduce a new guest mapping API
- KVM: nVMX: Always sync GUEST_BNDCFGS when it comes from vmcs01
- KVM: VMX: Zero out *all* general purpose registers after VM-Exit
- PCI/ASPM: Allow re-enabling Clock PM
- scsi: smartpqi: fix call trace in device discovery
- virtio-blk: improve virtqueue error to BLK_STS
- tracing/selftests: Turn off timeout setting
- drm/amd/display: Not doing optimize bandwidth if flip pending.
- xhci: Ensure link state is U3 after setting USB_SS_PORT_LS_U3
- ASoC: Intel: bytcr_rt5640: Add quirk for MPMAN MPWIN895CL tablet
- perf/core: Disable page faults when getting phys address
- pwm: bcm2835: Dynamically allocate base
- pwm: renesas-tpu: Fix late Runtime PM enablement
- Revert "powerpc/64: irq_work avoid interrupt when called with hardware irqs enabled"
- loop: Better discard support for block devices
- s390/cio: avoid duplicated 'ADD' uevents
- kconfig: qconf: Fix a few alignment issues
- ipc/util.c: sysvipc_find_ipc() should increase position index
- selftests: kmod: fix handling test numbers above 9
- kernel/gcov/fs.c: gcov_seq_next() should increase position index
- nvme: fix deadlock caused by ANA update wrong locking
- ASoC: Intel: atom: Take the drv->lock mutex before calling sst_send_slot_map()
- scsi: iscsi: Report unbind session event when the target has been removed
- pwm: rcar: Fix late Runtime PM enablement
- ceph: don't skip updating wanted caps when cap is stale
- ceph: return ceph_mdsc_do_request() errors from __get_parent()
- scsi: lpfc: Fix crash in target side cable pulls hitting WAIT_FOR_UNREG
- scsi: lpfc: Fix kasan slab-out-of-bounds error in lpfc_unreg_login
- watchdog: reset last_hw_keepalive time at start
- arm64: Silence clang warning on mismatched value/register sizes
- arm64: compat: Workaround Neoverse-N1 #1542419 for compat user-space
- arm64: Fake the IminLine size on systems affected by Neoverse-N1 #1542419
- arm64: errata: Hide CTR_EL0.DIC on systems affected by Neoverse-N1 #1542419
- arm64: Add part number for Neoverse N1
- vti4: removed duplicate log message.
- crypto: mxs-dcp - make symbols 'sha1_null_hash' and 'sha256_null_hash' static
- bpftool: Fix printing incorrect pointer in btf_dump_ptr
- drm/msm: Use the correct dma_sync calls harder
- ext4: fix extent_status fragmentation for plain files
- Linux 4.19.118
- bpf: fix buggy r0 retval refinement for tracing helpers
- KEYS: Don't write out to userspace while holding key semaphore
- mtd: phram: fix a double free issue in error path
- mtd: lpddr: Fix a double free in probe()
- mtd: spinand: Explicitly use MTD_OPS_RAW to write the bad block marker to OOB
- locktorture: Print ratio of acquisitions, not failures
- tty: evh_bytechan: Fix out of bounds accesses
- iio: si1133: read 24-bit signed integer for measurement
- fbdev: potential information leak in do_fb_ioctl()
- net: dsa: bcm_sf2: Fix overflow checks
- f2fs: fix to wait all node page writeback
- iommu/amd: Fix the configuration of GCR3 table root pointer
- libnvdimm: Out of bounds read in __nd_ioctl()
- power: supply: axp288_fuel_gauge: Broaden vendor check for Intel Compute Sticks.
- ext2: fix debug reference to ext2_xattr_cache
- ext2: fix empty body warnings when -Wextra is used
- drm/vc4: Fix HDMI mode validation
- f2fs: fix NULL pointer dereference in f2fs_write_begin()
- NFS: Fix memory leaks in nfs_pageio_stop_mirroring()
- drm/amdkfd: kfree the wrong pointer
- x86: ACPI: fix CPU hotplug deadlock
- KVM: s390: vsie: Fix possible race when shadowing region 3 tables
- compiler.h: fix error in BUILD_BUG_ON() reporting
- percpu_counter: fix a data race at vm_committed_as
- include/linux/swapops.h: correct guards for non_swap_entry()
- cifs: Allocate encryption header through kmalloc
- um: ubd: Prevent buffer overrun on command completion
- ext4: do not commit super on read-only bdev
- s390/cpum_sf: Fix wrong page count in error message
- powerpc/maple: Fix declaration made after definition
- s390/cpuinfo: fix wrong output when CPU0 is offline
- NFS: direct.c: Fix memory leak of dreq when nfs_get_lock_context fails
- NFSv4/pnfs: Return valid stateids in nfs_layout_find_inode_by_stateid()
- rtc: 88pm860x: fix possible race condition
- soc: imx: gpc: fix power up sequencing
- clk: tegra: Fix Tegra PMC clock out parents
- power: supply: bq27xxx_battery: Silence deferred-probe error
- clk: at91: usb: continue if clk_hw_round_rate() return zero
- x86/Hyper-V: Report crash data in die() when panic_on_oops is set
- x86/Hyper-V: Report crash register data when sysctl_record_panic_msg is not set
- x86/Hyper-V: Trigger crash enlightenment only once during system crash.
- x86/Hyper-V: Free hv_panic_page when fail to register kmsg dump
- x86/Hyper-V: Unload vmbus channel in hv panic callback
- rbd: call rbd_dev_unprobe() after unwatching and flushing notifies
- rbd: avoid a deadlock on header_rwsem when flushing notifies
- video: fbdev: sis: Remove unnecessary parentheses and commented code
- lib/raid6: use vdupq_n_u8 to avoid endianness warnings
- x86/Hyper-V: Report crash register data or kmsg before running crash kernel
- of: overlay: kmemleak in dup_and_fixup_symbol_prop()
- of: unittest: kmemleak in of_unittest_overlay_high_level()
- of: unittest: kmemleak in of_unittest_platform_populate()
- of: unittest: kmemleak on changeset destroy
- ALSA: hda: Don't release card at firmware loading error
- irqchip/mbigen: Free msi_desc on device teardown
- netfilter: nf_tables: report EOPNOTSUPP on unsupported flags/object type
- ARM: dts: imx6: Use gpc for FEC interrupt controller to fix wake on LAN.
- arm, bpf: Fix bugs with ALU64 {RSH, ARSH} BPF_K shift by 0
- watchdog: sp805: fix restart handler
- ext4: use non-movable memory for superblock readahead
- objtool: Fix switch table detection in .text.unlikely
- arm, bpf: Fix offset overflow for BPF_MEM BPF_DW
- drivers sfc: Fix cross page write error
- drivers sysctl: add read and write interface of pmbus
- net/hinic: Fix TX timeout under ipip tunnel packet
- xsk: Add missing check on user supplied headroom size
- fs/namespace.c: fix mountpoint reference counter race
- USB: core: Fix free-while-in-use bug in the USB S-Glibrary
- net: hns3: change the order of reinitializing RoCE and VF during reset
- net: hns3: update hns3 version to 1.9.37.9
- Revert "scsi: fix failing unload of a LLDD module"
- s390/mm: fix page table upgrade vs 2ndary address mode accesses
- perf: Make perf able to build with latest libbfd
- nbd: use blk_mq_queue_tag_inflight_iter()
- blk-mq: use blk_mq_queue_tag_inflight_iter() in debugfs
- blk-mq: use static_rqs instead of rqs to iterate tags
- pcie_cae support getting chipnums of this system
- net: hns3: remove the unnecessary ccflags
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
- Linux 4.19.117
- mm/vmalloc.c: move 'area->pages' after if statement
- wil6210: remove reset file from debugfs
- wil6210: make sure Rx ring sizes are correlated
- wil6210: add general initialization/size checks
- wil6210: ignore HALP ICR if already handled
- wil6210: check rx_buff_mgmt before accessing it
- x86/resctrl: Fix invalid attempt at removing the default resource group
- x86/resctrl: Preserve CDP enable over CPU hotplug
- x86/microcode/AMD: Increase microcode PATCH_MAX_SIZE
- scsi: target: fix hang when multiple threads try to destroy the same iscsi session
- scsi: target: remove boilerplate code
- kvm: x86: Host feature SSBD doesn't imply guest feature SPEC_CTRL_SSBD
- ext4: do not zeroout extents beyond i_disksize
- drm/amd/powerplay: force the trim of the mclk dpm_levels if OD is enabled
- usb: dwc3: gadget: Don't clear flags before transfer ended
- usb: dwc3: gadget: don't enable interrupt when disabling endpoint
- mac80211_hwsim: Use kstrndup() in place of kasprintf()
- btrfs: check commit root generation in should_ignore_root
- tracing: Fix the race between registering 'snapshot' event trigger and triggering 'snapshot' operation
- keys: Fix proc_keys_next to increase position index
- ALSA: usb-audio: Check mapping at creating connector controls, too
- ALSA: usb-audio: Don't create jack controls for PCM terminals
- ALSA: usb-audio: Don't override ignore_ctl_error value from the map
- ALSA: usb-audio: Filter error from connector kctl ops, too
- ASoC: Intel: mrfld: return error codes when an error occurs
- ASoC: Intel: mrfld: fix incorrect check on p->sink
- ext4: fix incorrect inodes per group in error message
- ext4: fix incorrect group count in ext4_fill_super error message
- pwm: pca9685: Fix PWM/GPIO inter-operation
- jbd2: improve comments about freeing data buffers whose page mapping is NULL
- scsi: ufs: Fix ufshcd_hold() caused scheduling while atomic
- ovl: fix value of i_ino for lower hardlink corner case
- net: dsa: mt7530: fix tagged frames pass-through in VLAN-unaware mode
- net: stmmac: dwmac-sunxi: Provide TX and RX fifo sizes
- net: revert default NAPI poll timeout to 2 jiffies
- net: qrtr: send msgs from local of same id as broadcast
- net: ipv6: do not consider routes via gateways for anycast address check
- net: ipv4: devinet: Fix crash when add/del multicast IP with autojoin
- hsr: check protocol version in hsr_newlink()
- amd-xgbe: Use __napi_schedule() in BH context
- scsi: hisi_sas: do not reset the timer to wait for phyup when phy already up
- net: hns3: update hns3 version to 1.9.37.7
- net: hns3: add suspend/resume function for hns3 driver
- btrfs: tree-checker: Enhance chunk checker to validate chunk profile
- Linux 4.19.116
- efi/x86: Fix the deletion of variables in mixed mode
- mfd: dln2: Fix sanity checking for endpoints
- etnaviv: perfmon: fix total and idle HI cyleces readout
- misc: echo: Remove unnecessary parentheses and simplify check for zero
- powerpc/fsl_booke: Avoid creating duplicate tlb1 entry
- ftrace/kprobe: Show the maxactive number on kprobe_events
- drm: Remove PageReserved manipulation from drm_pci_alloc
- drm/dp_mst: Fix clearing payload state on topology disable
- Revert "drm/dp_mst: Remove VCPI while disabling topology mgr"
- crypto: ccree - only try to map auth tag if needed
- crypto: ccree - dec auth tag size from cryptlen map
- crypto: ccree - don't mangle the request assoclen
- crypto: ccree - zero out internal struct before use
- crypto: ccree - improve error handling
- crypto: caam - update xts sector size for large input length
- dm zoned: remove duplicate nr_rnd_zones increase in dmz_init_zone()
- btrfs: use nofs allocations for running delayed items
- powerpc: Make setjmp/longjmp signature standard
- powerpc: Add attributes for setjmp/longjmp
- scsi: mpt3sas: Fix kernel panic observed on soft HBA unplug
- powerpc/kprobes: Ignore traps that happened in real mode
- powerpc/xive: Use XIVE_BAD_IRQ instead of zero to catch non configured IPIs
- powerpc/hash64/devmap: Use H_PAGE_THP_HUGE when setting up huge devmap PTE entries
- powerpc/64/tm: Don't let userspace set regs->trap via sigreturn
- xen/blkfront: fix memory allocation flags in blkfront_setup_indirect()
- ipmi: fix hung processes in __get_guid()
- libata: Return correct status in sata_pmp_eh_recover_pm() when ATA_DFLAG_DETACH is set
- hfsplus: fix crash and filesystem corruption when deleting files
- cpufreq: powernv: Fix use-after-free
- kmod: make request_module() return an error when autoloading is disabled
- clk: ingenic/jz4770: Exit with error if CGU init failed
- Input: i8042 - add Acer Aspire 5738z to nomux list
- s390/diag: fix display of diagnose call statistics
- perf tools: Support Python 3.8+ in Makefile
- ocfs2: no need try to truncate file beyond i_size
- fs/filesystems.c: downgrade user-reachable WARN_ONCE() to pr_warn_once()
- ext4: fix a data race at inode->i_blocks
- NFS: Fix a page leak in nfs_destroy_unlinked_subrequests()
- powerpc/pseries: Avoid NULL pointer dereference when drmem is unavailable
- drm/etnaviv: rework perfmon query infrastructure
- rtc: omap: Use define directive for PIN_CONFIG_ACTIVE_HIGH
- selftests: vm: drop dependencies on page flags from mlock2 tests
- arm64: armv8_deprecated: Fix undef_hook mask for thumb setend
- scsi: zfcp: fix missing erp_lock in port recovery trigger for point-to-point
- dm verity fec: fix memory leak in verity_fec_dtr
- dm writecache: add cond_resched to avoid CPU hangs
- arm64: dts: allwinner: h6: Fix PMU compatible
- net: qualcomm: rmnet: Allow configuration updates to existing devices
- mm: Use fixed constant in page_frag_alloc instead of size + 1
- tools: gpio: Fix out-of-tree build regression
- x86/speculation: Remove redundant arch_smt_update() invocation
- powerpc/pseries: Drop pointless static qualifier in vpa_debugfs_init()
- erofs: correct the remaining shrink objects
- crypto: mxs-dcp - fix scatterlist linearization for hash
- btrfs: fix missing semaphore unlock in btrfs_sync_file
- btrfs: fix missing file extent item for hole after ranged fsync
- btrfs: drop block from cache on error in relocation
- btrfs: set update the uuid generation as soon as possible
- Btrfs: fix crash during unmount due to race with delayed inode workers
- mtd: spinand: Do not erase the block before writing a bad block marker
- mtd: spinand: Stop using spinand->oobbuf for buffering bad block markers
- KVM: VMX: fix crash cleanup when KVM wasn't used
- KVM: x86: Gracefully handle __vmalloc() failure during VM allocation
- KVM: VMX: Always VMCLEAR in-use VMCSes during crash with kexec support
- KVM: x86: Allocate new rmap and large page tracking when moving memslot
- KVM: s390: vsie: Fix delivery of addressing exceptions
- KVM: s390: vsie: Fix region 1 ASCE sanity shadow address checks
- KVM: nVMX: Properly handle userspace interrupt window request
- x86/entry/32: Add missing ASM_CLAC to general_protection entry
- signal: Extend exec_id to 64bits
- ath9k: Handle txpower changes even when TPC is disabled
- MIPS: OCTEON: irq: Fix potential NULL pointer dereference
- MIPS/tlbex: Fix LDDIR usage in setup_pw() for Loongson-3
- pstore: pstore_ftrace_seq_next should increase position index
- irqchip/versatile-fpga: Apply clear-mask earlier
- KEYS: reaching the keys quotas correctly
- tpm: tpm2_bios_measurements_next should increase position index
- tpm: tpm1_bios_measurements_next should increase position index
- tpm: Don't make log failures fatal
- PCI: endpoint: Fix for concurrent memory allocation in OB address region
- PCI: Add boot interrupt quirk mechanism for Xeon chipsets
- PCI/ASPM: Clear the correct bits when enabling L1 substates
- PCI: pciehp: Fix indefinite wait on sysfs requests
- nvme: Treat discovery subsystems as unique subsystems
- nvme-fc: Revert "add module to ops template to allow module references"
- thermal: devfreq_cooling: inline all stubs for CONFIG_DEVFREQ_THERMAL=n
- acpi/x86: ignore unspecified bit positions in the ACPI global lock field
- media: ti-vpe: cal: fix disable_irqs to only the intended target
- ALSA: hda/realtek - Add quirk for MSI GL63
- ALSA: hda/realtek - Remove now-unnecessary XPS 13 headphone noise fixups
- ALSA: hda/realtek - Set principled PC Beep configuration for ALC256
- ALSA: doc: Document PC Beep Hidden Register on Realtek ALC256
- ALSA: pcm: oss: Fix regression by buffer overflow fix
- ALSA: ice1724: Fix invalid access for enumerated ctl items
- ALSA: hda: Fix potential access overflow in beep helper
- ALSA: hda: Add driver blacklist
- ALSA: usb-audio: Add mixer workaround for TRX40 and co
- usb: gadget: composite: Inform controller driver of self-powered
- usb: gadget: f_fs: Fix use after free issue as part of queue failure
- ASoC: topology: use name_prefix for new kcontrol
- ASoC: dpcm: allow start or stop during pause for backend
- ASoC: dapm: connect virtual mux with default value
- ASoC: fix regwmask
- slub: improve bit diffusion for freelist ptr obfuscation
- uapi: rename ext2_swab() to swab() and share globally in swab.h
- IB/mlx5: Replace tunnel mpls capability bits for tunnel_offloads
- btrfs: track reloc roots based on their commit root bytenr
- btrfs: remove a BUG_ON() from merge_reloc_roots()
- btrfs: qgroup: ensure qgroup_rescan_running is only set when the worker is at least queued
- block, bfq: fix use-after-free in bfq_idle_slice_timer_body
- locking/lockdep: Avoid recursion in lockdep_count_{for,back}ward_deps()
- firmware: fix a double abort case with fw_load_sysfs_fallback
- md: check arrays is suspended in mddev_detach before call quiesce operations
- irqchip/gic-v4: Provide irq_retrigger to avoid circular locking dependency
- usb: dwc3: core: add support for disabling SS instances in park mode
- media: i2c: ov5695: Fix power on and off sequences
- block: Fix use-after-free issue accessing struct io_cq
- genirq/irqdomain: Check pointer in irq_domain_alloc_irqs_hierarchy()
- efi/x86: Ignore the memory attributes table on i386
- x86/boot: Use unsigned comparison for addresses
- gfs2: Don't demote a glock until its revokes are written
- pstore/platform: fix potential mem leak if pstore_init_fs failed
- libata: Remove extra scsi_host_put() in ata_scsi_add_hosts()
- media: i2c: video-i2c: fix build errors due to 'imply hwmon'
- PCI/switchtec: Fix init_completion race condition with poll_wait()
- selftests/x86/ptrace_syscall_32: Fix no-vDSO segfault
- sched: Avoid scale real weight down to zero
- irqchip/versatile-fpga: Handle chained IRQs properly
- block: keep bdi->io_pages in sync with max_sectors_kb for stacked devices
- x86: Don't let pgprot_modify() change the page encryption bit
- xhci: bail out early if driver can't accress host in resume
- null_blk: fix spurious IO errors after failed past-wp access
- null_blk: Handle null_add_dev() failures properly
- null_blk: Fix the null_add_dev() error path
- firmware: arm_sdei: fix double-lock on hibernate with shared events
- media: venus: hfi_parser: Ignore HEVC encoding for V1
- cpufreq: imx6q: Fixes unwanted cpu overclocking on i.MX6ULL
- i2c: st: fix missing struct parameter description
- qlcnic: Fix bad kzalloc null test
- cxgb4/ptp: pass the sign of offset delta in FW CMD
- net: vxge: fix wrong __VA_ARGS__ usage
- bus: sunxi-rsb: Return correct data when mixing 16-bit and 8-bit reads
- ARM: dts: sun8i-a83t-tbs-a711: HM5065 doesn't like such a high voltage
- Linux 4.19.115
- drm/msm: Use the correct dma_sync calls in msm_gem
- drm_dp_mst_topology: fix broken drm_dp_sideband_parse_remote_dpcd_read()
- usb: dwc3: don't set gadget->is_otg flag
- rpmsg: glink: Remove chunk size word align warning
- arm64: Fix size of __early_cpu_boot_status
- drm/msm: stop abusing dma_map/unmap for cache
- clk: qcom: rcg: Return failure for RCG update
- fbcon: fix null-ptr-deref in fbcon_switch
- RDMA/cm: Update num_paths in cma_resolve_iboe_route error flow
- Bluetooth: RFCOMM: fix ODEBUG bug in rfcomm_dev_ioctl
- RDMA/cma: Teach lockdep about the order of rtnl and lock
- RDMA/ucma: Put a lock around every call to the rdma_cm layer
- ceph: canonicalize server path in place
- ceph: remove the extra slashes in the server path
- IB/hfi1: Fix memory leaks in sysfs registration and unregistration
- IB/hfi1: Call kobject_put() when kobject_init_and_add() fails
- ASoC: jz4740-i2s: Fix divider written at incorrect offset in register
- hwrng: imx-rngc - fix an error path
- tools/accounting/getdelays.c: fix netlink attribute length
- usb: dwc3: gadget: Wrap around when skip TRBs
- random: always use batched entropy for get_random_u{32, 64}
- mlxsw: spectrum_flower: Do not stop at FLOW_ACTION_VLAN_MANGLE
- net: stmmac: dwmac1000: fix out-of-bounds mac address reg setting
- net: phy: micrel: kszphy_resume(): add delay after genphy_resume() before accessing PHY registers
- net: dsa: bcm_sf2: Ensure correct sub-node is parsed
- net: dsa: bcm_sf2: Do not register slave MDIO bus with OF
- ipv6: don't auto-add link-local address to lag ports
- padata: always acquire cpu_hotplug_lock before pinst->lock
- net: Fix Tx hash bound checking
- rxrpc: Fix sendmsg(MSG_WAITALL) handling
- ALSA: hda/ca0132 - Add Recon3Di quirk to handle integrated sound on EVGA X99 Classified motherboard
- power: supply: axp288_charger: Add special handling for HP Pavilion x2 10
- extcon: axp288: Add wakeup support
- mei: me: add cedar fork device ids
- coresight: do not use the BIT() macro in the UAPI header
- misc: pci_endpoint_test: Avoid using module parameter to determine irqtype
- misc: pci_endpoint_test: Fix to support > 10 pci-endpoint-test devices
- misc: rtsx: set correct pcr_ops for rts522A
- media: rc: IR signal for Panasonic air conditioner too long
- drm/etnaviv: replace MMU flush marker with flush sequence
- tools/power turbostat: Fix missing SYS_LPI counter on some Chromebooks
- tools/power turbostat: Fix gcc build warnings
- drm/amdgpu: fix typo for vcn1 idle check
- initramfs: restore default compression behavior
- drm/bochs: downgrade pci_request_region failure from error to warning
- drm/amd/display: Add link_rate quirk for Apple 15" MBP 2017
- nvme-rdma: Avoid double freeing of async event data
- sctp: fix possibly using a bad saddr with a given dst
- sctp: fix refcount bug in sctp_wfree
- net, ip_tunnel: fix interface lookup with no key
- ipv4: fix a RCU-list lock in fib_triestat_seq_show
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
- iommu/vt-d: Fix mm reference leak
- iommu/dma: Fix for dereferencing before null checking
- net/hinic: fix the problem that out-of-bounds access
- scsi: sg: fix memory leak in sg_build_indirect
- scsi: sg: add sg_remove_request in sg_common_write
- srcu: Apply *_ONCE() to ->srcu_last_gp_end
- btrfs: Don't submit any btree write bio if the fs has errors
- btrfs: extent_io: Handle errors better in extent_write_full_page()
- net/hinic: Delete useless header files
- powerpc/powernv/idle: Restore AMR/UAMOR/AMOR after idle
- f2fs: fix to avoid memory leakage in f2fs_listxattr
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
- Linux 4.19.114
- arm64: dts: ls1046ardb: set RGMII interfaces to RGMII_ID mode
- arm64: dts: ls1043a-rdb: correct RGMII delay mode to rgmii-id
- ARM: dts: N900: fix onenand timings
- ARM: dts: imx6: phycore-som: fix arm and soc minimum voltage
- ARM: bcm2835-rpi-zero-w: Add missing pinctrl name
- ARM: dts: oxnas: Fix clear-mask property
- perf map: Fix off by one in strncpy() size argument
- arm64: alternative: fix build with clang integrated assembler
- net: ks8851-ml: Fix IO operations, again
- gpiolib: acpi: Add quirk to ignore EC wakeups on HP x2 10 CHT + AXP288 model
- bpf: Explicitly memset some bpf info structures declared on the stack
- bpf: Explicitly memset the bpf_attr structure
- platform/x86: pmc_atom: Add Lex 2I385SW to critclk_systems DMI table
- vt: vt_ioctl: fix use-after-free in vt_in_use()
- vt: vt_ioctl: fix VT_DISALLOCATE freeing in-use virtual console
- vt: vt_ioctl: remove unnecessary console allocation checks
- vt: switch vt_dont_switch to bool
- vt: ioctl, switch VT_IS_IN_USE and VT_BUSY to inlines
- vt: selection, introduce vc_is_sel
- mac80211: fix authentication with iwlwifi/mvm
- mac80211: Check port authorization in the ieee80211_tx_dequeue() case
- media: xirlink_cit: add missing descriptor sanity checks
- media: stv06xx: add missing descriptor sanity checks
- media: dib0700: fix rc endpoint lookup
- media: ov519: add missing endpoint sanity checks
- libfs: fix infoleak in simple_attr_read()
- ahci: Add Intel Comet Lake H RAID PCI ID
- staging: wlan-ng: fix use-after-free Read in hfa384x_usbin_callback
- staging: wlan-ng: fix ODEBUG bug in prism2sta_disconnect_usb
- staging: rtl8188eu: Add ASUS USB-N10 Nano B1 to device table
- media: usbtv: fix control-message timeouts
- media: flexcop-usb: fix endpoint sanity check
- usb: musb: fix crash with highmen PIO and usbmon
- USB: serial: io_edgeport: fix slab-out-of-bounds read in edge_interrupt_callback
- USB: cdc-acm: restore capability check order
- USB: serial: option: add Wistron Neweb D19Q1
- USB: serial: option: add BroadMobi BM806U
- USB: serial: option: add support for ASKEY WWHC050
- mac80211: set IEEE80211_TX_CTRL_PORT_CTRL_PROTO for nl80211 TX
- mac80211: add option for setting control flags
- Revert "r8169: check that Realtek PHY driver module is loaded"
- vti6: Fix memory leak of skb if input policy check fails
- bpf/btf: Fix BTF verification of enum members in struct/union
- netfilter: nft_fwd_netdev: validate family and chain type
- netfilter: flowtable: reload ip{v6}h in nf_flow_tuple_ip{v6}
- afs: Fix some tracing details
- xfrm: policy: Fix doulbe free in xfrm_policy_timer
- xfrm: add the missing verify_sec_ctx_len check in xfrm_add_acquire
- xfrm: fix uctx len check in verify_sec_ctx_len
- RDMA/mlx5: Block delay drop to unprivileged users
- vti[6]: fix packet tx through bpf_redirect() in XinY cases
- xfrm: handle NETDEV_UNREGISTER for xfrm device
- genirq: Fix reference leaks on irq affinity notifiers
- RDMA/core: Ensure security pkey modify is not lost
- gpiolib: acpi: Add quirk to ignore EC wakeups on HP x2 10 BYT + AXP288 model
- gpiolib: acpi: Rework honor_wakeup option into an ignore_wake option
- gpiolib: acpi: Correct comment for HP x2 10 honor_wakeup quirk
- mac80211: mark station unauthorized before key removal
- nl80211: fix NL80211_ATTR_CHANNEL_WIDTH attribute type
- scsi: sd: Fix optimal I/O size for devices that change reported values
- scripts/dtc: Remove redundant YYLOC global declaration
- tools: Let O= makes handle a relative path with -C option
- perf probe: Do not depend on dwfl_module_addrsym()
- ARM: dts: omap5: Add bus_dma_limit for L3 bus
- ARM: dts: dra7: Add bus_dma_limit for L3 bus
- ceph: check POOL_FLAG_FULL/NEARFULL in addition to OSDMAP_FULL/NEARFULL
- Input: avoid BIT() macro usage in the serio.h UAPI header
- Input: synaptics - enable RMI on HP Envy 13-ad105ng
- Input: raydium_i2c_ts - fix error codes in raydium_i2c_boot_trigger()
- i2c: hix5hd2: add missed clk_disable_unprepare in remove
- ftrace/x86: Anotate text_mutex split between ftrace_arch_code_modify_post_process() and ftrace_arch_code_modify_prepare()
- sxgbe: Fix off by one in samsung driver strncpy size arg
- dpaa_eth: Remove unnecessary boolean expression in dpaa_get_headroom
- mac80211: Do not send mesh HWMP PREQ if HWMP is disabled
- scsi: ipr: Fix softlockup when rescanning devices in petitboot
- s390/qeth: handle error when backing RX buffer
- fsl/fman: detect FMan erratum A050385
- arm64: dts: ls1043a: FMan erratum A050385
- dt-bindings: net: FMan erratum A050385
- cgroup1: don't call release_agent when it is ""
- drivers/of/of_mdio.c:fix of_mdiobus_register()
- cpupower: avoid multiple definition with gcc -fno-common
- nfs: add minor version to nfs_server_key for fscache
- cgroup-v1: cgroup_pidlist_next should update position index
- hsr: set .netnsok flag
- hsr: add restart routine into hsr_get_node_list()
- hsr: use rcu_read_lock() in hsr_get_node_{list/status}()
- vxlan: check return value of gro_cells_init()
- tcp: repair: fix TCP_QUEUE_SEQ implementation
- r8169: re-enable MSI on RTL8168c
- net: phy: mdio-mux-bcm-iproc: check clk_prepare_enable() return value
- net: dsa: mt7530: Change the LINK bit to reflect the link status
- net: ip_gre: Accept IFLA_INFO_DATA-less configuration
- net: ip_gre: Separate ERSPAN newlink / changelink callbacks
- bnxt_en: Reset rings if ring reservation fails during open()
- bnxt_en: fix memory leaks in bnxt_dcbnl_ieee_getets()
- slcan: not call free_netdev before rtnl_unlock in slcan_open
- NFC: fdp: Fix a signedness bug in fdp_nci_send_patch()
- net: stmmac: dwmac-rk: fix error path in rk_gmac_probe
- net_sched: keep alloc_hash updated after hash allocation
- net_sched: cls_route: remove the right filter from hashtable
- net: qmi_wwan: add support for ASKEY WWHC050
- net/packet: tpacket_rcv: avoid a producer race condition
- net: mvneta: Fix the case where the last poll did not process all rx
- net: dsa: Fix duplicate frames flooded by learning
- net: cbs: Fix software cbs to consider packet sending time
- mlxsw: spectrum_mr: Fix list iteration in error path
- macsec: restrict to ethernet devices
- hsr: fix general protection fault in hsr_addr_is_self()
- geneve: move debug check after netdev unregister
- Revert "drm/dp_mst: Skip validating ports during destruction, just ref"
- mmc: sdhci-tegra: Fix busy detection by enabling MMC_CAP_NEED_RSP_BUSY
- mmc: sdhci-omap: Fix busy detection by enabling MMC_CAP_NEED_RSP_BUSY
- mmc: core: Respect MMC_CAP_NEED_RSP_BUSY for eMMC sleep command
- mmc: core: Respect MMC_CAP_NEED_RSP_BUSY for erase/trim/discard
- mmc: core: Allow host controllers to require R1B for CMD6
- qm: fix packet loss for acc
- net/hinic: Solve the problem that 1822 NIC reports 5d0 error
- nvme: fix memory leak caused by incorrect subsystem free
- nvme: fix possible deadlock when nvme_update_formats fails
- dm verity: don't prefetch hash blocks for already-verified data
- kretprobe: check re-registration of the same kretprobe earlier
- Linux 4.19.113
- staging: greybus: loopback_test: fix potential path truncations
- staging: greybus: loopback_test: fix potential path truncation
- drm/bridge: dw-hdmi: fix AVI frame colorimetry
- arm64: smp: fix crash_smp_send_stop() behaviour
- arm64: smp: fix smp_send_stop() behaviour
- ALSA: hda/realtek: Fix pop noise on ALC225
- Revert "ipv6: Fix handling of LLA with VRF and sockets bound to VRF"
- Revert "vrf: mark skb for multicast or link-local as enslaved to VRF"
- futex: Unbreak futex hashing
- futex: Fix inode life-time issue
- kbuild: Disable -Wpointer-to-enum-cast
- iio: light: vcnl4000: update sampling periods for vcnl4200
- USB: cdc-acm: fix rounding error in TIOCSSERIAL
- USB: cdc-acm: fix close_delay and closing_wait units in TIOCSSERIAL
- x86/mm: split vmalloc_sync_all()
- page-flags: fix a crash at SetPageError(THP_SWAP)
- mm, slub: prevent kmalloc_node crashes and memory leaks
- mm: slub: be more careful about the double cmpxchg of freelist
- memcg: fix NULL pointer dereference in __mem_cgroup_usage_unregister_event
- drm/lease: fix WARNING in idr_destroy
- drm/amd/amdgpu: Fix GPR read from debugfs (v2)
- btrfs: fix log context list corruption after rename whiteout error
- xhci: Do not open code __print_symbolic() in xhci trace events
- rtc: max8907: add missing select REGMAP_IRQ
- intel_th: pci: Add Elkhart Lake CPU support
- intel_th: Fix user-visible error codes
- staging/speakup: fix get_word non-space look-ahead
- staging: greybus: loopback_test: fix poll-mask build breakage
- staging: rtl8188eu: Add device id for MERCUSYS MW150US v2
- mmc: sdhci-of-at91: fix cd-gpios for SAMA5D2
- mmc: rtsx_pci: Fix support for speed-modes that relies on tuning
- iio: adc: at91-sama5d2_adc: fix differential channels in triggered mode
- iio: magnetometer: ak8974: Fix negative raw values in sysfs
- iio: trigger: stm32-timer: disable master mode when stopping
- iio: st_sensors: remap SMO8840 to LIS2DH12
- ALSA: pcm: oss: Remove WARNING from snd_pcm_plug_alloc() checks
- ALSA: pcm: oss: Avoid plugin buffer overflow
- ALSA: seq: oss: Fix running status after receiving sysex
- ALSA: seq: virmidi: Fix running status after receiving sysex
- ALSA: line6: Fix endless MIDI read loop
- usb: xhci: apply XHCI_SUSPEND_DELAY to AMD XHCI controller 1022:145c
- USB: serial: pl2303: add device-id for HP LD381
- usb: host: xhci-plat: add a shutdown
- USB: serial: option: add ME910G1 ECM composition 0x110b
- usb: quirks: add NO_LPM quirk for RTL8153 based ethernet adapters
- USB: Disable LPM on WD19's Realtek Hub
- parse-maintainers: Mark as executable
- block, bfq: fix overwrite of bfq_group pointer in bfq_find_set_group()
- xenbus: req->err should be updated before req->state
- xenbus: req->body should be updated before req->state
- drm/amd/display: fix dcc swath size calculations on dcn1
- drm/amd/display: Clear link settings on MST disable connector
- riscv: avoid the PIC offset of static percpu data in module beyond 2G limits
- dm integrity: use dm_bio_record and dm_bio_restore
- dm bio record: save/restore bi_end_io and bi_integrity
- altera-stapl: altera_get_note: prevent write beyond end of 'key'
- drivers/perf: arm_pmu_acpi: Fix incorrect checking of gicc pointer
- drm/exynos: dsi: fix workaround for the legacy clock name
- drm/exynos: dsi: propagate error value and silence meaningless warning
- spi/zynqmp: remove entry that causes a cs glitch
- spi: pxa2xx: Add CS control clock quirk
- ARM: dts: dra7: Add "dma-ranges" property to PCIe RC DT nodes
- powerpc: Include .BTF section
- spi: qup: call spi_qup_pm_resume_runtime before suspending
- drm/mediatek: Find the cursor plane instead of hard coding it
- net: hns3: Rectification of driver code review
- net: hns3: update hns3 version to 1.9.37.4
- Linux 4.19.112
- ipv4: ensure rcu_read_lock() in cipso_v4_error()
- efi: Fix debugobjects warning on 'efi_rts_work'
- HID: google: add moonball USB id
- mm: slub: add missing TID bump in kmem_cache_alloc_bulk()
- ARM: 8958/1: rename missed uaccess .fixup section
- ARM: 8957/1: VDSO: Match ARMv8 timer in cntvct_functional()
- net: qrtr: fix len of skb_put_padto in qrtr_node_enqueue
- driver core: Fix creation of device links with PM-runtime flags
- driver core: Remove device link creation limitation
- driver core: Add device link flag DL_FLAG_AUTOPROBE_CONSUMER
- driver core: Make driver core own stateful device links
- driver core: Fix adding device links to probing suppliers
- driver core: Remove the link if there is no driver with AUTO flag
- mmc: sdhci-omap: Fix Tuning procedure for temperatures < -20C
- mmc: sdhci-omap: Don't finish_mrq() on a command error during tuning
- jbd2: fix data races at struct journal_head
- sfc: fix timestamp reconstruction at 16-bit rollover points
- net: rmnet: fix packet forwarding in rmnet bridge mode
- net: rmnet: fix bridge mode bugs
- net: rmnet: use upper/lower device infrastructure
- net: rmnet: do not allow to change mux id if mux id is duplicated
- net: rmnet: remove rcu_read_lock in rmnet_force_unassociate_device()
- net: rmnet: fix suspicious RCU usage
- net: rmnet: fix NULL pointer dereference in rmnet_changelink()
- net: rmnet: fix NULL pointer dereference in rmnet_newlink()
- slip: not call free_netdev before rtnl_unlock in slip_open
- signal: avoid double atomic counter increments for user accounting
- mac80211: rx: avoid RCU list traversal under mutex
- net: ks8851-ml: Fix IRQ handling and locking
- net: usb: qmi_wwan: restore mtu min/max values after raw_ip switch
- scsi: libfc: free response frame from GPN_ID
- cfg80211: check reg_rule for NULL in handle_channel_custom()
- HID: i2c-hid: add Trekstor Surfbook E11B to descriptor override
- HID: apple: Add support for recent firmware on Magic Keyboards
- ACPI: watchdog: Allow disabling WDAT at boot
- mmc: host: Fix Kconfig warnings on keystone_defconfig
- mmc: sdhci-omap: Workaround errata regarding SDR104/HS200 tuning failures (i929)
- mmc: sdhci-omap: Add platform specific reset callback
- perf/amd/uncore: Replace manual sampling check with CAP_NO_INTERRUPT flag
- livepatch/core: support jump_label
- btrfs: tree-checker: Add EXTENT_ITEM and METADATA_ITEM check
- net: hns3: additional fix for fraglist handling
- net: hns3: fix for fraglist skb headlen not handling correctly
- net: hns3: update hns3 version to 1.9.37.3
- sec: modify driver to adapt dm-crypt
- qm: reinforce reset failure scene
- zip: fix decompress a empty file
- hpre: dfx for IO operation and delay
- Linux 4.19.111
- batman-adv: Avoid free/alloc race when handling OGM2 buffer
- efi: Add a sanity check to efivar_store_raw()
- net/smc: cancel event worker during device removal
- net/smc: check for valid ib_client_data
- ipv6: restrict IPV6_ADDRFORM operation
- i2c: acpi: put device when verifying client fails
- iommu/vt-d: Ignore devices with out-of-spec domain number
- iommu/vt-d: Fix the wrong printing in RHSA parsing
- netfilter: nft_tunnel: add missing attribute validation for tunnels
- netfilter: nft_payload: add missing attribute validation for payload csum flags
- netfilter: cthelper: add missing attribute validation for cthelper
- perf bench futex-wake: Restore thread count default to online CPU count
- nl80211: add missing attribute validation for channel switch
- nl80211: add missing attribute validation for beacon report scanning
- nl80211: add missing attribute validation for critical protocol indication
- i2c: gpio: suppress error on probe defer
- drm/i915/gvt: Fix unnecessary schedule timer when no vGPU exits
- pinctrl: core: Remove extra kref_get which blocks hogs being freed
- pinctrl: meson-gxl: fix GPIOX sdio pins
- batman-adv: Don't schedule OGM for disabled interface
- iommu/vt-d: Fix a bug in intel_iommu_iova_to_phys() for huge page
- iommu/vt-d: dmar: replace WARN_TAINT with pr_warn + add_taint
- iommu/dma: Fix MSI reservation allocation
- x86/mce: Fix logic and comments around MSR_PPIN_CTL
- mt76: fix array overflow on receiving too many fragments for a packet
- efi: Make efi_rts_work accessible to efi page fault handler
- efi: Fix a race and a buffer overflow while reading efivars via sysfs
- macintosh: windfarm: fix MODINFO regression
- ARC: define __ALIGN_STR and __ALIGN symbols for ARC
- KVM: x86: clear stale x86_emulate_ctxt->intercept value
- gfs2_atomic_open(): fix O_EXCL|O_CREAT handling on cold dcache
- cifs_atomic_open(): fix double-put on late allocation failure
- ktest: Add timeout for ssh sync testing
- drm/amd/display: remove duplicated assignment to grph_obj_type
- workqueue: don't use wq_select_unbound_cpu() for bound works
- netfilter: x_tables: xt_mttg_seq_next should increase position index
- netfilter: xt_recent: recent_seq_next should increase position index
- netfilter: synproxy: synproxy_cpu_seq_next should increase position index
- netfilter: nf_conntrack: ct_cpu_seq_next should increase position index
- iommu/vt-d: quirk_ioat_snb_local_iommu: replace WARN_TAINT with pr_warn + add_taint
- virtio-blk: fix hw_queue stopped on arbitrary error
- iwlwifi: mvm: Do not require PHY_SKU NVM section for 3168 devices
- cgroup: Iterate tasks that did not finish do_exit()
- cgroup: cgroup_procs_next should increase position index
- macvlan: add cond_resched() during multicast processing
- net: fec: validate the new settings in fec_enet_set_coalesce()
- slip: make slhc_compress() more robust against malicious packets
- bonding/alb: make sure arp header is pulled before accessing it
- devlink: validate length of region addr/len
- tipc: add missing attribute validation for MTU property
- net/ipv6: remove the old peer route if change it to a new one
- net/ipv6: need update peer route when modify metric
- selftests/net/fib_tests: update addr_metric_test for peer route testing
- net: phy: fix MDIO bus PM PHY resuming
- nfc: add missing attribute validation for vendor subcommand
- nfc: add missing attribute validation for deactivate target
- nfc: add missing attribute validation for SE API
- team: add missing attribute validation for array index
- team: add missing attribute validation for port ifindex
- net: fq: add missing attribute validation for orphan mask
- macsec: add missing attribute validation for port
- can: add missing attribute validation for termination
- nl802154: add missing attribute validation for dev_type
- nl802154: add missing attribute validation
- fib: add missing attribute validation for tun_id
- devlink: validate length of param values
- net: memcg: fix lockdep splat in inet_csk_accept()
- net: memcg: late association of sock to memcg
- cgroup: memcg: net: do not associate sock with unrelated cgroup
- bnxt_en: reinitialize IRQs when MTU is modified
- sfc: detach from cb_page in efx_copy_channel()
- r8152: check disconnect status after long sleep
- net: systemport: fix index check to avoid an array out of bounds access
- net: stmmac: dwmac1000: Disable ACS if enhanced descs are not used
- net/packet: tpacket_rcv: do not increment ring index on drop
- net: nfc: fix bounds checking bugs on "pipe"
- net: macsec: update SCI upon MAC address change.
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
- net: phy: Avoid multiple suspends
- phy: Revert toggling reset changes.
- Linux 4.19.110
- KVM: SVM: fix up incorrect backport
- block: fix possible memory leak in 'blk_prepare_release_queue'
- dm crypt: fix benbi IV constructor crash if used in authenticated mode
- Revert "dm-crypt: Add IV generation templates"
- Revert "dm-crypt: modify dm-crypt to rely on IV generation templates"
- Revert "dm crypt: fix benbi IV constructor crash if used in authenticated mode"
- x86/config: enable CONFIG_CFQ_GROUP_IOSCHED
- x86/openeuler_config: disable CONFIG_EFI_VARS
- btrfs: don't use WARN_ON when ret is -ENOTENT in __btrfs_free_extent()
- cifs: fix panic in smb2_reconnect
- arm64: clear_page: Add new implementation of clear_page() by STNP
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
- mm/resource: Return real error codes from walk failures
- RDMA/hns: optimize mtr management and fix mtr addressing bug
- openeuler/config: enable CONFIG_FCOE
- net: ipv6_stub: use ip6_dst_lookup_flow instead of ip6_dst_lookup
- net: ipv6: add net argument to ip6_dst_lookup_flow
- openeuler/config: disable unused debug config
- Linux 4.19.109
- scsi: pm80xx: Fixed kernel panic during error recovery for SATA drive
- dm integrity: fix a deadlock due to offloading to an incorrect workqueue
- efi/x86: Handle by-ref arguments covering multiple pages in mixed mode
- efi/x86: Align GUIDs to their size in the mixed mode runtime wrapper
- powerpc: fix hardware PMU exception bug on PowerVM compatibility mode systems
- dmaengine: coh901318: Fix a double lock bug in dma_tc_handle()
- hwmon: (adt7462) Fix an error return in ADT7462_REG_VOLT()
- ARM: dts: imx7-colibri: Fix frequency for sd/mmc
- ARM: dts: am437x-idk-evm: Fix incorrect OPP node names
- ARM: imx: build v7_cpu_resume() unconditionally
- IB/hfi1, qib: Ensure RCU is locked when accessing list
- RMDA/cm: Fix missing ib_cm_destroy_id() in ib_cm_insert_listen()
- RDMA/iwcm: Fix iwcm work deallocation
- ARM: dts: imx6: phycore-som: fix emmc supply
- phy: mapphone-mdm6600: Fix write timeouts with shorter GPIO toggle interval
- phy: mapphone-mdm6600: Fix timeouts by adding wake-up handling
- drm/sun4i: de2/de3: Remove unsupported VI layer formats
- drm/sun4i: Fix DE2 VI layer format support
- ASoC: dapm: Correct DAPM handling of active widgets during shutdown
- ASoC: pcm512x: Fix unbalanced regulator enable call in probe error path
- ASoC: pcm: Fix possible buffer overflow in dpcm state sysfs output
- dmaengine: imx-sdma: remove dma_slave_config direction usage and leave sdma_event_enable()
- ASoC: intel: skl: Fix possible buffer overflow in debug outputs
- ASoC: intel: skl: Fix pin debug prints
- ASoC: topology: Fix memleak in soc_tplg_manifest_load()
- ASoC: topology: Fix memleak in soc_tplg_link_elems_load()
- spi: bcm63xx-hsspi: Really keep pll clk enabled
- ARM: dts: ls1021a: Restore MDIO compatible to gianfar
- dm writecache: verify watermark during resume
- dm: report suspended device during destroy
- dm cache: fix a crash due to incorrect work item cancelling
- dmaengine: tegra-apb: Prevent race conditions of tasklet vs free list
- dmaengine: tegra-apb: Fix use-after-free
- x86/pkeys: Manually set X86_FEATURE_OSPKE to preserve existing changes
- media: v4l2-mem2mem.c: fix broken links
- vt: selection, push sel_lock up
- vt: selection, push console lock down
- serial: 8250_exar: add support for ACCES cards
- tty:serial:mvebu-uart:fix a wrong return
- arm: dts: dra76x: Fix mmc3 max-frequency
- fat: fix uninit-memory access for partial initialized inode
- mm: fix possible PMD dirty bit lost in set_pmd_migration_entry()
- mm, numa: fix bad pmd by atomically check for pmd_trans_huge when marking page tables prot_numa
- usb: core: port: do error out if usb_autopm_get_interface() fails
- usb: core: hub: do error out if usb_autopm_get_interface() fails
- usb: core: hub: fix unhandled return by employing a void function
- usb: dwc3: gadget: Update chain bit correctly when using sg list
- usb: quirks: add NO_LPM quirk for Logitech Screen Share
- usb: storage: Add quirk for Samsung Fit flash
- cifs: don't leak -EAGAIN for stat() during reconnect
- ALSA: hda/realtek - Fix silent output on Gigabyte X570 Aorus Master
- ALSA: hda/realtek - Add Headset Mic supported
- net: thunderx: workaround BGX TX Underflow issue
- x86/xen: Distribute switch variables for initialization
- ice: Don't tell the OS that link is going down
- nvme: Fix uninitialized-variable warning
- s390/qdio: fill SL with absolute addresses
- x86/boot/compressed: Don't declare __force_order in kaslr_64.c
- s390: make 'install' not depend on vmlinux
- s390/cio: cio_ignore_proc_seq_next should increase position index
- watchdog: da9062: do not ping the hw during stop()
- net: ks8851-ml: Fix 16-bit IO operation
- net: ks8851-ml: Fix 16-bit data access
- net: ks8851-ml: Remove 8-bit bus accessors
- net: dsa: b53: Ensure the default VID is untagged
- selftests: forwarding: use proto icmp for {gretap, ip6gretap}_mac testing
- drm/msm/dsi/pll: call vco set rate explicitly
- drm/msm/dsi: save pll state before dsi host is powered off
- scsi: megaraid_sas: silence a warning
- drm: msm: Fix return type of dsi_mgr_connector_mode_valid for kCFI
- drm/msm/mdp5: rate limit pp done timeout warnings
- usb: gadget: serial: fix Tx stall after buffer overflow
- usb: gadget: ffs: ffs_aio_cancel(): Save/restore IRQ flags
- usb: gadget: composite: Support more than 500mA MaxPower
- selftests: fix too long argument
- serial: ar933x_uart: set UART_CS_{RX, TX}_READY_ORIDE
- ALSA: hda: do not override bus codec_mask in link_get()
- kprobes: Fix optimize_kprobe()/unoptimize_kprobe() cancellation logic
- RDMA/core: Fix use of logical OR in get_new_pps
- RDMA/core: Fix pkey and port assignment in get_new_pps
- net: dsa: bcm_sf2: Forcibly configure IMP port for 1Gb/sec
- ALSA: hda/realtek - Fix a regression for mute led on Lenovo Carbon X1
- EDAC/amd64: Set grain per DIMM
- Linux 4.19.108
- audit: always check the netlink payload length in audit_receive_msg()
- netfilter: nf_flowtable: fix documentation
- netfilter: nft_tunnel: no need to call htons() when dumping ports
- thermal: brcmstb_thermal: Do not use DT coefficients
- KVM: x86: Remove spurious clearing of async #PF MSR
- KVM: x86: Remove spurious kvm_mmu_unload() from vcpu destruction path
- perf hists browser: Restore ESC as "Zoom out" of DSO/thread/etc
- pwm: omap-dmtimer: put_device() after of_find_device_by_node()
- kprobes: Set unoptimized flag after unoptimizing code
- drivers: net: xgene: Fix the order of the arguments of 'alloc_etherdev_mqs()'
- KVM: Check for a bad hva before dropping into the ghc slow path
- KVM: SVM: Override default MMIO mask if memory encryption is enabled
- mwifiex: delete unused mwifiex_get_intf_num()
- mwifiex: drop most magic numbers from mwifiex_process_tdls_action_frame()
- namei: only return -ECHILD from follow_dotdot_rcu()
- net: ena: make ena rxfh support ETH_RSS_HASH_NO_CHANGE
- net/smc: no peer ID in CLC decline for SMCD
- net: atlantic: fix potential error handling
- net: atlantic: fix use after free kasan warn
- net: netlink: cap max groups which will be considered in netlink_bind()
- s390/qeth: vnicc Fix EOPNOTSUPP precedence
- usb: charger: assign specific number for enum value
- hv_netvsc: Fix unwanted wakeup in netvsc_attach()
- drm/i915/gvt: Separate display reset from ALL_ENGINES reset
- drm/i915/gvt: Fix orphan vgpu dmabuf_objs' lifetime
- i2c: jz4780: silence log flood on txabrt
- i2c: altera: Fix potential integer overflow
- MIPS: VPE: Fix a double free and a memory leak in 'release_vpe()'
- HID: hiddev: Fix race in in hiddev_disconnect()
- HID: alps: Fix an error handling path in 'alps_input_configured()'
- vhost: Check docket sk_family instead of call getname
- amdgpu/gmc_v9: save/restore sdpif regs during S3
- Revert "PM / devfreq: Modify the device name as devfreq(X) for sysfs"
- tracing: Disable trace_printk() on post poned tests
- macintosh: therm_windtunnel: fix regression when instantiating devices
- HID: core: increase HID report buffer size to 8KiB
- HID: core: fix off-by-one memset in hid_report_raw_event()
- HID: ite: Only bind to keyboard USB interface on Acer SW5-012 keyboard dock
- KVM: VMX: check descriptor table exits on instruction emulation
- ACPI: watchdog: Fix gas->access_width usage
- ACPICA: Introduce ACPI_ACCESS_BYTE_WIDTH() macro
- audit: fix error handling in audit_data_to_entry()
- ext4: potential crash on allocation error in ext4_alloc_flex_bg_array()
- net/tls: Fix to avoid gettig invalid tls record
- qede: Fix race between rdma destroy workqueue and link change event
- ipv6: Fix nlmsg_flags when splitting a multipath route
- ipv6: Fix route replacement with dev-only route
- sctp: move the format error check out of __sctp_sf_do_9_1_abort
- nfc: pn544: Fix occasional HW initialization failure
- net: sched: correct flower port blocking
- net: phy: restore mdio regs in the iproc mdio driver
- net: mscc: fix in frame extraction
- net: fib_rules: Correctly set table field when table number exceeds 8 bits
- cfg80211: add missing policy for NL80211_ATTR_STATUS_CODE
- cifs: Fix mode output in debugging statements
- net: ena: ena-com.c: prevent NULL pointer dereference
- net: ena: ethtool: use correct value for crc32 hash
- net: ena: fix incorrectly saving queue numbers when setting RSS indirection table
- net: ena: rss: store hash function as values and not bits
- net: ena: rss: fix failure to get indirection table
- net: ena: fix incorrect default RSS key
- net: ena: add missing ethtool TX timestamping indication
- net: ena: fix uses of round_jiffies()
- net: ena: fix potential crash when rxfh key is NULL
- soc/tegra: fuse: Fix build with Tegra194 configuration
- ARM: dts: sti: fixup sound frame-inversion for stihxxx-b2120.dtsi
- qmi_wwan: unconditionally reject 2 ep interfaces
- qmi_wwan: re-add DW5821e pre-production variant
- s390/zcrypt: fix card and queue total counter wrap
- cfg80211: check wiphy driver existence for drvinfo report
- mac80211: consider more elements in parsing CRC
- dax: pass NOWAIT flag to iomap_apply
- drm/msm: Set dma maximum segment size for mdss
- ipmi:ssif: Handle a possible NULL pointer reference
- irqchip/gic-v3-its: Fix misuse of GENMASK macro
- net: hns3: update the number of version
- net: hns3: add dumping vlan filter config in debugfs
- net: hns3: Increase vlan tag0 when close the port_base_vlan
- net: hns3: adds support for extended VLAN mode and 'QOS' in vlan 802.1Q protocol.
- RDMA/hns: fix bug of accessing null pointer
- sec: Overall optimization of sec code
- net/hinic: driver code compliance rectification
- net/hinic: Solve the problem that the network card hangs when receiving the skb which frag_size=0
- btrfs: tree-checker: Remove comprehensive root owner check
- xfs: add agf freeblocks verify in xfs_agf_verify
- blktrace: fix dereference after null check
- blktrace: Protect q->blk_trace with RCU
- vgacon: Fix a UAF in vgacon_invert_region
- arm64: kprobes: Recover pstate.D in single-step exception handler
- relay: handle alloc_percpu returning NULL in relay_open
- drm/radeon: check the alloc_workqueue return value
- net: hns3: adds support for reading module eeprom info
- net: hns3: update hns3 version to 1.9.37.1
- arm64: Kconfig: select HAVE_FUTEX_CMPXCHG
- qm: optimize the maximum number of VF and delete invalid addr
- apparmor: Fix use-after-free in aa_audit_rule_init
- nbd: fix possible page fault for nbd disk
- nbd: rename the runtime flags as NBD_RT_ prefixed
- jbd2: flush_descriptor(): Do not decrease buffer head's ref count
- Revert "dm crypt: use WQ_HIGHPRI for the IO and crypt workqueues"
- livepatch/x86: enable livepatch config openeuler
- livepatch/x86: enable livepatch config for hulk
- livepatch/arm64: check active func in consistency stack checking
- livepatch/x86: check active func in consistency stack checking
- livepatch/x86: support livepatch without ftrace
- ACPICA: Win OSL: Replace get_tick_count with get_tick_count64
- Linux 4.19.107
- Revert "char/random: silence a lockdep splat with printk()"
- s390/mm: Explicitly compare PAGE_DEFAULT_KEY against zero in storage_key_init_range
- xen: Enable interrupts when calling _cond_resched()
- ata: ahci: Add shutdown to freeze hardware resources of ahci
- rxrpc: Fix call RCU cleanup using non-bh-safe locks
- netfilter: xt_hashlimit: limit the max size of hashtable
- ALSA: seq: Fix concurrent access to queue current tick/time
- ALSA: seq: Avoid concurrent access to queue flags
- ALSA: rawmidi: Avoid bit fields for state flags
- bpf, offload: Replace bitwise AND by logical AND in bpf_prog_offload_info_fill
- genirq/proc: Reject invalid affinity masks (again)
- iommu/vt-d: Fix compile warning from intel-svm.h
- ecryptfs: replace BUG_ON with error handling code
- staging: greybus: use after free in gb_audio_manager_remove_all()
- staging: rtl8723bs: fix copy of overlapping memory
- usb: dwc2: Fix in ISOC request length checking
- usb: gadget: composite: Fix bMaxPower for SuperSpeedPlus
- scsi: Revert "target: iscsi: Wait for all commands to finish before freeing a session"
- scsi: Revert "RDMA/isert: Fix a recently introduced regression related to logout"
- Revert "dmaengine: imx-sdma: Fix memory leak"
- Btrfs: fix btrfs_wait_ordered_range() so that it waits for all ordered extents
- btrfs: do not check delayed items are empty for single transaction cleanup
- btrfs: reset fs_root to NULL on error in open_ctree
- btrfs: fix bytes_may_use underflow in prealloc error condtition
- KVM: apic: avoid calculating pending eoi from an uninitialized val
- KVM: nVMX: handle nested posted interrupts when apicv is disabled for L1
- KVM: nVMX: Check IO instruction VM-exit conditions
- KVM: nVMX: Refactor IO bitmap checks into helper function
- ext4: fix race between writepages and enabling EXT4_EXTENTS_FL
- ext4: rename s_journal_flag_rwsem to s_writepages_rwsem
- ext4: fix mount failure with quota configured as module
- ext4: fix potential race between s_flex_groups online resizing and access
- ext4: fix potential race between s_group_info online resizing and access
- ext4: fix potential race between online resizing and write operations
- ext4: fix a data race in EXT4_I(inode)->i_disksize
- drm/nouveau/kms/gv100-: Re-set LUT after clearing for modesets
- lib/stackdepot.c: fix global out-of-bounds in stack_slabs
- tty: serial: qcom_geni_serial: Fix RX cancel command failure
- tty: serial: qcom_geni_serial: Remove xfer_mode variable
- tty: serial: qcom_geni_serial: Remove set_rfr_wm() and related variables
- tty: serial: qcom_geni_serial: Remove use of *_relaxed() and mb()
- tty: serial: qcom_geni_serial: Remove interrupt storm
- tty: serial: qcom_geni_serial: Fix UART hang
- KVM: x86: don't notify userspace IOAPIC on edge-triggered interrupt EOI
- KVM: nVMX: Don't emulate instructions in guest mode
- xhci: apply XHCI_PME_STUCK_QUIRK to Intel Comet Lake platforms
- drm/amdgpu/soc15: fix xclk for raven
- mm/vmscan.c: don't round up scan size for online memory cgroup
- genirq/irqdomain: Make sure all irq domain flags are distinct
- nvme-multipath: Fix memory leak with ana_log_buf
- Revert "ipc, sem: remove uneeded sem_undo_list lock usage in exit_sem()"
- MAINTAINERS: Update drm/i915 bug filing URL
- serdev: ttyport: restore client ops on deregistration
- tty: serial: imx: setup the correct sg entry for tx dma
- tty/serial: atmel: manage shutdown in case of RS485 or ISO7816 mode
- serial: 8250: Check UPF_IRQ_SHARED in advance
- x86/cpu/amd: Enable the fixed Instructions Retired counter IRPERF
- x86/mce/amd: Fix kobject lifetime
- x86/mce/amd: Publish the bank pointer only after setup has succeeded
- jbd2: fix ocfs2 corrupt when clearing block group bits
- powerpc/tm: Fix clearing MSR[TS] in current when reclaiming on signal delivery
- staging: rtl8723bs: Fix potential overuse of kernel memory
- staging: rtl8723bs: Fix potential security hole
- staging: rtl8188eu: Fix potential overuse of kernel memory
- staging: rtl8188eu: Fix potential security hole
- usb: dwc3: gadget: Check for IOC/LST bit in TRB->ctrl fields
- usb: dwc2: Fix SET/CLEAR_FEATURE and GET_STATUS flows
- USB: hub: Fix the broken detection of USB3 device in SMSC hub
- USB: hub: Don't record a connect-change event during reset-resume
- USB: Fix novation SourceControl XL after suspend
- usb: uas: fix a plug & unplug racing
- USB: quirks: blacklist duplicate ep on Sound Devices USBPre2
- USB: core: add endpoint-blacklist quirk
- usb: host: xhci: update event ring dequeue pointer on purpose
- xhci: Fix memory leak when caching protocol extended capability PSI tables - take 2
- xhci: fix runtime pm enabling for quirky Intel hosts
- xhci: Force Maximum Packet size for Full-speed bulk devices to valid range.
- staging: vt6656: fix sign of rx_dbm to bb_pre_ed_rssi.
- staging: android: ashmem: Disallow ashmem memory from being remapped
- vt: vt_ioctl: fix race in VT_RESIZEX
- vt: fix scrollback flushing on background consoles
- floppy: check FDC index for errors before assigning it
- USB: misc: iowarrior: add support for the 100 device
- USB: misc: iowarrior: add support for the 28 and 28L devices
- USB: misc: iowarrior: add support for 2 OEMed devices
- thunderbolt: Prevent crash if non-active NVMem file is read
- ecryptfs: fix a memory leak bug in ecryptfs_init_messaging()
- ecryptfs: fix a memory leak bug in parse_tag_1_packet()
- ASoC: sun8i-codec: Fix setting DAI data format
- ALSA: hda/realtek - Apply quirk for yet another MSI laptop
- ALSA: hda/realtek - Apply quirk for MSI GP63, too
- ALSA: hda: Use scnprintf() for printing texts for sysfs/procfs
- iommu/qcom: Fix bogus detach logic
- Linux 4.19.106
- drm/amdgpu/display: handle multiple numbers of fclks in dcn_calcs.c (v2)
- mlxsw: spectrum_dpipe: Add missing error path
- virtio_balloon: prevent pfn array overflow
- cifs: log warning message (once) if out of disk space
- help_next should increase position index
- NFS: Fix memory leaks
- drm/amdgpu/smu10: fix smu10_get_clock_by_type_with_voltage
- drm/amdgpu/smu10: fix smu10_get_clock_by_type_with_latency
- brd: check and limit max_part par
- microblaze: Prevent the overflow of the start
- iwlwifi: mvm: Fix thermal zone registration
- irqchip/gic-v3-its: Reference to its_invall_cmd descriptor when building INVALL
- bcache: explicity type cast in bset_bkey_last()
- reiserfs: prevent NULL pointer dereference in reiserfs_insert_item()
- lib/scatterlist.c: adjust indentation in __sg_alloc_table
- ocfs2: fix a NULL pointer dereference when call ocfs2_update_inode_fsync_trans()
- radeon: insert 10ms sleep in dce5_crtc_load_lut
- trigger_next should increase position index
- ftrace: fpid_next() should increase position index
- drm/nouveau/disp/nv50-: prevent oops when no channel method map provided
- irqchip/gic-v3: Only provision redistributors that are enabled in ACPI
- rbd: work around -Wuninitialized warning
- ceph: check availability of mds cluster on mount after wait timeout
- bpf: map_seq_next should always increase position index
- cifs: fix NULL dereference in match_prepath
- iwlegacy: ensure loop counter addr does not wrap and cause an infinite loop
- hostap: Adjust indentation in prism2_hostapd_add_sta
- ARM: 8951/1: Fix Kexec compilation issue.
- jbd2: make sure ESHUTDOWN to be recorded in the journal superblock
- selftests: bpf: Reset global state between reuseport test runs
- iommu/vt-d: Remove unnecessary WARN_ON_ONCE()
- bcache: cached_dev_free needs to put the sb page
- powerpc/sriov: Remove VF eeh_dev state when disabling SR-IOV
- drm/nouveau/mmu: fix comptag memory leak
- ALSA: hda - Add docking station support for Lenovo Thinkpad T420s
- driver core: platform: fix u32 greater or equal to zero comparison
- s390/ftrace: generate traced function stack frame
- s390: adjust -mpacked-stack support check for clang 10
- x86/decoder: Add TEST opcode to Group3-2
- kbuild: use -S instead of -E for precise cc-option test in Kconfig
- ALSA: hda/hdmi - add retry logic to parse_intel_hdmi()
- irqchip/mbigen: Set driver .suppress_bind_attrs to avoid remove problems
- remoteproc: Initialize rproc_class before use
- module: avoid setting info->name early in case we can fall back to info->mod->name
- btrfs: device stats, log when stats are zeroed
- btrfs: safely advance counter when looking up bio csums
- btrfs: fix possible NULL-pointer dereference in integrity checks
- pwm: Remove set but not set variable 'pwm'
- ide: serverworks: potential overflow in svwks_set_pio_mode()
- cmd64x: potential buffer overflow in cmd64x_program_timings()
- pwm: omap-dmtimer: Remove PWM chip in .remove before making it unfunctional
- x86/mm: Fix NX bit clearing issue in kernel_map_pages_in_pgd
- f2fs: fix memleak of kobject
- watchdog/softlockup: Enforce that timestamp is valid on boot
- drm/amd/display: fixup DML dependencies
- arm64: fix alternatives with LLVM's integrated assembler
- scsi: iscsi: Don't destroy session if there are outstanding connections
- f2fs: free sysfs kobject
- f2fs: set I_LINKABLE early to avoid wrong access by vfs
- iommu/arm-smmu-v3: Use WRITE_ONCE() when changing validity of an STE
- usb: musb: omap2430: Get rid of musb .set_vbus for omap2430 glue
- drm/vmwgfx: prevent memory leak in vmw_cmdbuf_res_add
- drm/nouveau/fault/gv100-: fix memory leak on module unload
- drm/nouveau/drm/ttm: Remove set but not used variable 'mem'
- drm/nouveau: Fix copy-paste error in nouveau_fence_wait_uevent_handler
- drm/nouveau/gr/gk20a, gm200-: add terminators to method lists read from fw
- drm/nouveau/secboot/gm20b: initialize pointer in gm20b_secboot_new()
- vme: bridges: reduce stack usage
- bpf: Return -EBADRQC for invalid map type in __bpf_tx_xdp_map
- driver core: Print device when resources present in really_probe()
- driver core: platform: Prevent resouce overflow from causing infinite loops
- visorbus: fix uninitialized variable access
- tty: synclink_gt: Adjust indentation in several functions
- tty: synclinkmp: Adjust indentation in several functions
- ASoC: atmel: fix build error with CONFIG_SND_ATMEL_SOC_DMA=m
- wan: ixp4xx_hss: fix compile-testing on 64-bit
- x86/nmi: Remove irq_work from the long duration NMI handler
- Input: edt-ft5x06 - work around first register access error
- rcu: Use WRITE_ONCE() for assignments to ->pprev for hlist_nulls
- efi/x86: Don't panic or BUG() on non-critical error conditions
- soc/tegra: fuse: Correct straps' address for older Tegra124 device trees
- IB/hfi1: Add software counter for ctxt0 seq drop
- staging: rtl8188: avoid excessive stack usage
- udf: Fix free space reporting for metadata and virtual partitions
- usbip: Fix unsafe unaligned pointer usage
- ARM: dts: stm32: Add power-supply for DSI panel on stm32f469-disco
- drm: remove the newline for CRC source name.
- mlx5: work around high stack usage with gcc
- ACPI: button: Add DMI quirk for Razer Blade Stealth 13 late 2019 lid switch
- tools lib api fs: Fix gcc9 stringop-truncation compilation error
- ALSA: sh: Fix compile warning wrt const
- clk: uniphier: Add SCSSI clock gate for each channel
- ALSA: sh: Fix unused variable warnings
- clk: sunxi-ng: add mux and pll notifiers for A64 CPU clock
- RDMA/rxe: Fix error type of mmap_offset
- reset: uniphier: Add SCSSI reset control for each channel
- pinctrl: sh-pfc: sh7269: Fix CAN function GPIOs
- PM / devfreq: rk3399_dmc: Add COMPILE_TEST and HAVE_ARM_SMCCC dependency
- x86/vdso: Provide missing include file
- crypto: chtls - Fixed memory leak
- dmaengine: imx-sdma: Fix memory leak
- dmaengine: Store module owner in dma_device struct
- selinux: ensure we cleanup the internal AVC counters on error in avc_update()
- ARM: dts: r8a7779: Add device node for ARM global timer
- drm/mediatek: handle events when enabling/disabling crtc
- scsi: aic7xxx: Adjust indentation in ahc_find_syncrate
- scsi: ufs: Complete pending requests in host reset and restore path
- ACPICA: Disassembler: create buffer fields in ACPI_PARSE_LOAD_PASS1
- orinoco: avoid assertion in case of NULL pointer
- rtlwifi: rtl_pci: Fix -Wcast-function-type
- iwlegacy: Fix -Wcast-function-type
- ipw2x00: Fix -Wcast-function-type
- b43legacy: Fix -Wcast-function-type
- ALSA: usx2y: Adjust indentation in snd_usX2Y_hwdep_dsp_status
- netfilter: nft_tunnel: add the missing ERSPAN_VERSION nla_policy
- fore200e: Fix incorrect checks of NULL pointer dereference
- r8169: check that Realtek PHY driver module is loaded
- reiserfs: Fix spurious unlock in reiserfs_fill_super() error handling
- media: v4l2-device.h: Explicitly compare grp{id, mask} to zero in v4l2_device macros
- PCI: Increase D3 delay for AMD Ryzen5/7 XHCI controllers
- PCI: Add generic quirk for increasing D3hot delay
- media: cx23885: Add support for AVerMedia CE310B
- PCI: iproc: Apply quirk_paxc_bridge() for module as well as built-in
- ARM: dts: imx6: rdu2: Limit USBH1 to Full Speed
- ARM: dts: imx6: rdu2: Disable WP for USDHC2 and USDHC3
- arm64: dts: qcom: msm8996: Disable USB2 PHY suspend by core
- selinux: ensure we cleanup the internal AVC counters on error in avc_insert()
- arm: dts: allwinner: H3: Add PMU node
- arm64: dts: allwinner: H6: Add PMU mode
- selinux: fall back to ref-walk if audit is required
- NFC: port100: Convert cpu_to_le16(le16_to_cpu(E1) + E2) to use le16_add_cpu().
- net/wan/fsl_ucc_hdlc: reject muram offsets above 64K
- regulator: rk808: Lower log level on optional GPIOs being not available
- drm/amdgpu: Ensure ret is always initialized when using SOC15_WAIT_ON_RREG
- drm/amdgpu: remove 4 set but not used variable in amdgpu_atombios_get_connector_info_from_object_table
- clk: qcom: rcg2: Don't crash if our parent can't be found; return an error
- kconfig: fix broken dependency in randconfig-generated .config
- KVM: s390: ENOTSUPP -> EOPNOTSUPP fixups
- nbd: add a flush_workqueue in nbd_start_device
- drm/amd/display: Retrain dongles when SINK_COUNT becomes non-zero
- ath10k: Correct the DMA direction for management tx buffers
- ARM: 8952/1: Disable kmemleak on XIP kernels
- tracing: Fix very unlikely race of registering two stat tracers
- tracing: Fix tracing_stat return values in error handling paths
- powerpc/iov: Move VF pdev fixup into pcibios_fixup_iov()
- s390/pci: Fix possible deadlock in recover_store()
- pwm: omap-dmtimer: Simplify error handling
- jbd2: clear JBD2_ABORT flag before journal_reset to update log tail info when load journal
- kselftest: Minimise dependency of get_size on C library interfaces
- clocksource/drivers/bcm2835_timer: Fix memory leak of timer
- usb: dwc2: Fix IN FIFO allocation
- usb: gadget: udc: fix possible sleep-in-atomic-context bugs in gr_probe()
- uio: fix a sleep-in-atomic-context bug in uio_dmem_genirq_irqcontrol()
- sparc: Add .exit.data section.
- MIPS: Loongson: Fix potential NULL dereference in loongson3_platform_init()
- efi/x86: Map the entire EFI vendor string before copying it
- pinctrl: baytrail: Do not clear IRQ flags on direct-irq enabled pins
- media: sti: bdisp: fix a possible sleep-in-atomic-context bug in bdisp_device_run()
- char/random: silence a lockdep splat with printk()
- iommu/vt-d: Fix off-by-one in PASID allocation
- gpio: gpio-grgpio: fix possible sleep-in-atomic-context bugs in grgpio_irq_map/unmap()
- powerpc/powernv/iov: Ensure the pdn for VFs always contains a valid PE number
- media: i2c: mt9v032: fix enum mbus codes and frame sizes
- pxa168fb: Fix the function used to release some memory in an error handling path
- pinctrl: sh-pfc: sh7264: Fix CAN function GPIOs
- gianfar: Fix TX timestamping with a stacked DSA driver
- ALSA: ctl: allow TLV read operation for callback type of element in locked case
- ext4: fix ext4_dax_read/write inode locking sequence for IOCB_NOWAIT
- leds: pca963x: Fix open-drain initialization
- brcmfmac: Fix use after free in brcmf_sdio_readframes()
- cpu/hotplug, stop_machine: Fix stop_machine vs hotplug order
- drm/gma500: Fixup fbdev stolen size usage evaluation
- KVM: nVMX: Use correct root level for nested EPT shadow page tables
- Revert "KVM: VMX: Add non-canonical check on writes to RTIT address MSRs"
- Revert "KVM: nVMX: Use correct root level for nested EPT shadow page tables"
- net/sched: flower: add missing validation of TCA_FLOWER_FLAGS
- net/sched: matchall: add missing validation of TCA_MATCHALL_FLAGS
- net: dsa: tag_qca: Make sure there is headroom for tag
- net/smc: fix leak of kernel memory to user space
- enic: prevent waking up stopped tx queues over watchdog reset
- core: Don't skip generic XDP program execution for cloned SKBs
- kill kernfs_pin_sb()
- cgroup: saner refcounting for cgroup_root
- qm: optimize set hw_reset flag logic for user
- qm: fixup the problem of wrong judgement of used parameter
- ext4: add cond_resched() to __ext4_find_entry()
- ext4: avoid fetching btime in ext4_getattr() unless requested
- mm/memcontrol.c: lost css_put in memcg_expand_shrinker_maps()
- mm: pagewalk: fix termination condition in walk_pte_range()
- mm/huge_memory.c: use head to check huge zero page
- mm, thp: fix defrag setting if newline is not used
- mm/page-writeback.c: improve arithmetic divisions
- mm/page-writeback.c: use div64_ul() for u64-by-unsigned-long divide
- nfsd: Clone should commit src file metadata too
- nfsd: Ensure CLONE persists data and metadata changes to the target file
- x86 / config: add openeuler_defconfig
- bcache: don't export symbols
- bcache: remove the extra cflags for request.o
- bcache: add idle_max_writeback_rate sysfs interface
- bcache: add code comments in bch_btree_leaf_dirty()
- bcache: add code comment bch_keylist_pop() and bch_keylist_pop_front()
- bcache: deleted code comments for dead code in bch_data_insert_keys()
- bcache: add more accurate error messages in read_super()
- bcache: fix a lost wake-up problem caused by mca_cannibalize_lock
- bcache: add cond_resched() in __bch_cache_cmp()
- bcache: fix possible memory leak in bch_cached_dev_run()
- bcache: add reclaimed_journal_buckets to struct cache_set
- bcache: remove retry_flush_write from struct cache_set
- bcache: set largest seq to ja->seq[bucket_index] in journal_read_bucket()
- bcache: add code comments for journal_read_bucket()
- bcache: acquire bch_register_lock later in cached_dev_detach_finish()
- bcache: avoid a deadlock in bcache_reboot()
- bcache: stop writeback kthread and kworker when bch_cached_dev_run() failed
- bcache: add pendings_cleanup to stop pending bcache device
- bcache: make bset_search_tree() be more understandable
- bcache: remove "XXX:" comment line from run_cache_set()
- bcache: improve error message in bch_cached_dev_run()
- bcache: add more error message in bch_cached_dev_attach()
- bcache: more detailed error message to bcache_device_link()
- bcache: remove unncessary code in bch_btree_keys_init()
- bcache: add return value check to bch_cached_dev_run()
- bcache: remove unnecessary prefetch() in bset_search_tree()
- bcache: add io error counting in write_bdev_super_endio()
- bcache: avoid flushing btree node in cache_set_flush() if io disabled
- bcache: fix return value error in bch_journal_read()
- bcache: don't set max writeback rate if gc is running
- bcache: make is_discard_enabled() static
- bcache: fix wrong usage use-after-freed on keylist in out_nocoalesce branch of btree_gc_coalesce
- bcache: improve bcache_reboot()
- bcache: add comments for closure_fn to be called in closure_queue()
- bcache: Add comments for blkdev_put() in registration code path
- bcache: add error check for calling register_bdev()
- bcache: add comments for kobj release callback routine
- bcache: move definition of 'int ret' out of macro read_bucket()
- bcache: Clean up bch_get_congested()
- bcache: use kmemdup_nul for CACHED_LABEL buffer
- bcache: fix inaccurate result of unused buckets
- bcache: fix crashes stopping bcache device before read miss done
- bcache: avoid to use bio_for_each_segment_all() in bch_bio_alloc_pages()
- bcache: fix input overflow to cache set io_error_limit
- bcache: fix input overflow to journal_delay_ms
- bcache: fix input overflow to writeback_delay
- bcache: use sysfs_strtoul_bool() to set bit-field variables
- bcache: add sysfs_strtoul_bool() for setting bit-field variables
- bcache: fix input integer overflow of congested threshold
- bcache: fix indentation issue, remove tabs on a hunk of code
- bcache: export backing_dev_uuid via sysfs
- bcache: export backing_dev_name via sysfs
- bcache: fix memory corruption in bch_cache_accounting_clear()
- bcache: not use hard coded memset size in bch_cache_accounting_clear()
- bcache: print number of keys in trace_bcache_journal_write
- bcache: set writeback_percent in a flexible range
- bcache: make cutoff_writeback and cutoff_writeback_sync tunable
- bcache: add MODULE_DESCRIPTION information
- bcache: option to automatically run gc thread after writeback
- bcache: introduce force_wake_up_gc()
- bcache: cannot set writeback_running via sysfs if no writeback kthread created
- bcache: update comment in sysfs.c
- bcache: update comment for bch_data_insert
- bcache: add comment for cache_set->fill_iter
- bcache: panic fix for making cache device
- bcache: split combined if-condition code into separate ones
- bcache: use MAX_CACHES_PER_SET instead of magic number 8 in __bch_bucket_alloc_set
- bcache: remove useless parameter of bch_debug_init()
- bcache: remove unused bch_passthrough_cache
- bcache: fix typo in code comments of closure_return_with_destructor()
- files_cgroup: Fix soft lockup when refcnt overflow.
- vt: selection, close sel_buffer race
- vt: selection, handle pending signals in paste_selection
- iscsi: use dynamic single thread workqueue to improve performance
- workqueue: implement NUMA affinity for single thread workqueue
- qm: Move all the same logic functions of hisilicon crypto to qm
- RDMA/hns: Compilation Configuration update
- Document: add guideline to submitting patches to openEuler
- arm64: entry: SP Alignment Fault doesn't write to FAR_EL1
- x86/sysfb: Fix check for bad VRAM size
- PCI: PM/ACPI: Refresh all stale power state data in pci_pm_complete()
- ACPI: PM: Fix regression in acpi_device_set_power()
- ACPI: PM: Allow transitions to D0 to occur in special cases
- ACPI: PM: Avoid evaluating _PS3 on transitions from D3hot to D3cold
- arm64: mark (__)cpus_have_const_cap as __always_inline
- arm64/module: revert to unsigned interpretation of ABS16/32 relocations
- arm64/module: deal with ambiguity in PRELxx relocation ranges
- x86/timer: Force PIT initialization when !X86_FEATURE_ARAT
- x86/timer: Don't skip PIT setup when APIC is disabled or in legacy mode
- x86/timer: Skip PIT initialization on modern chipsets
- x86/apic: Rename 'lapic_timer_frequency' to 'lapic_timer_period'
- i2c: designware: Add ACPI HID for Hisilicon Hip08-Lite I2C controller
- ACPI / APD: Add clock frequency for Hisilicon Hip08-Lite I2C controller
- iommu/vt-d: Handle PCI bridge RMRR device scopes in intel_iommu_get_resv_regions
- iommu/vt-d: Handle RMRR with PCI bridge device scopes
- iommu/vt-d: Introduce is_downstream_to_pci_bridge helper
- drivers : localbus cleancode
- drivers : sysctl cleancode
- drivers : sfc cleancode
- Linux 4.19.105
- KVM: x86/mmu: Fix struct guest_walker arrays for 5-level paging
- jbd2: do not clear the BH_Mapped flag when forgetting a metadata buffer
- jbd2: move the clearing of b_modified flag to the journal_unmap_buffer()
- NFSv4.1 make cachethis=no for writes
- hwmon: (pmbus/ltc2978) Fix PMBus polling of MFR_COMMON definitions.
- perf/x86/intel: Fix inaccurate period in context switch for auto-reload
- s390/time: Fix clk type in get_tod_clock
- RDMA/core: Fix protection fault in get_pkey_idx_qp_list
- RDMA/rxe: Fix soft lockup problem due to using tasklets in softirq
- RDMA/hfi1: Fix memory leak in _dev_comp_vect_mappings_create
- RDMA/core: Fix invalid memory access in spec_filter_size
- IB/rdmavt: Reset all QPs when the device is shut down
- IB/hfi1: Close window for pq and request coliding
- IB/hfi1: Acquire lock to release TID entries when user file is closed
- nvme: fix the parameter order for nvme_get_log in nvme_get_fw_slot_info
- perf/x86/amd: Add missing L2 misses event spec to AMD Family 17h's event map
- KVM: nVMX: Use correct root level for nested EPT shadow page tables
- arm64: ssbs: Fix context-switch when SSBS is present on all CPUs
- ARM: npcm: Bring back GPIOLIB support
- btrfs: log message when rw remount is attempted with unclean tree-log
- btrfs: print message when tree-log replay starts
- btrfs: ref-verify: fix memory leaks
- Btrfs: fix race between using extent maps and merging them
- ext4: improve explanation of a mount failure caused by a misconfigured kernel
- ext4: fix checksum errors with indexed dirs
- ext4: fix support for inode sizes > 1024 bytes
- ext4: don't assume that mmp_nodename/bdevname have NUL
- ALSA: usb-audio: Add clock validity quirk for Denon MC7000/MCX8000
- ALSA: usb-audio: sound: usb: usb true/false for bool return type
- arm64: nofpsmid: Handle TIF_FOREIGN_FPSTATE flag cleanly
- arm64: cpufeature: Set the FP/SIMD compat HWCAP bits properly
- ALSA: usb-audio: Apply sample rate quirk for Audioengine D1
- ALSA: hda/realtek - Fix silent output on MSI-GL73
- ALSA: usb-audio: Fix UAC2/3 effect unit parsing
- Input: synaptics - remove the LEN0049 dmi id from topbuttonpad list
- Input: synaptics - enable SMBus on ThinkPad L470
- Input: synaptics - switch T470s to RMI4 by default
- files_cgroup: fix error pointer when kvm_vm_worker_thread
- bdi: get device name under rcu protect
- timer_list: avoid other cpu soft lockup when printing timer list
- sysrq: avoid concurrently info printing by 'sysrq-trigger'
- bdi: fix memleak in bdi_register_va()
- iommu/iova: avoid softlockup in fq_flush_timeout
- simple_recursive_removal(): kernel-side rm -rf for ramfs-style filesystems
- debugfs: simplify __debugfs_remove_file()
- block: rename 'q->debugfs_dir' and 'q->blk_trace->dir' in blk_unregister_queue()
- ext4: add cond_resched() to ext4_protect_reserved_inode
- bdi: fix use-after-free for the bdi device
- config: remove SHA_MB config
- crypto: x86 - remove SHA multibuffer routines and mcryptd
- Linux 4.19.104
- padata: fix null pointer deref of pd->pinst
- serial: uartps: Move the spinlock after the read of the tx empty
- x86/stackframe, x86/ftrace: Add pt_regs frame annotations
- x86/stackframe: Move ENCODE_FRAME_POINTER to asm/frame.h
- scsi: megaraid_sas: Do not initiate OCR if controller is not in ready state
- libertas: make lbs_ibss_join_existing() return error code on rates overflow
- libertas: don't exit from lbs_ibss_join_existing() with RCU read lock held
- mwifiex: Fix possible buffer overflows in mwifiex_cmd_append_vsie_tlv()
- mwifiex: Fix possible buffer overflows in mwifiex_ret_wmm_get_status()
- pinctrl: sh-pfc: r8a7778: Fix duplicate SDSELF_B and SD1_CLK_B
- media: i2c: adv748x: Fix unsafe macros
- crypto: atmel-sha - fix error handling when setting hmac key
- crypto: artpec6 - return correct error code for failed setkey()
- mtd: sharpslpart: Fix unsigned comparison to zero
- mtd: onenand_base: Adjust indentation in onenand_read_ops_nolock
- KVM: arm64: pmu: Don't increment SW_INCR if PMCR.E is unset
- KVM: arm: Make inject_abt32() inject an external abort instead
- KVM: arm: Fix DFSR setting for non-LPAE aarch32 guests
- KVM: arm/arm64: Fix young bit from mmu notifier
- arm64: ptrace: nofpsimd: Fail FP/SIMD regset operations
- arm64: cpufeature: Fix the type of no FP/SIMD capability
- ARM: 8949/1: mm: mark free_memmap as __init
- KVM: arm/arm64: vgic-its: Fix restoration of unmapped collections
- iommu/arm-smmu-v3: Populate VMID field for CMDQ_OP_TLBI_NH_VA
- powerpc/pseries: Allow not having ibm, hypertas-functions::hcall-multi-tce for DDW
- powerpc/pseries/vio: Fix iommu_table use-after-free refcount warning
- tools/power/acpi: fix compilation error
- ARM: dts: at91: sama5d3: define clock rate range for tcb1
- ARM: dts: at91: sama5d3: fix maximum peripheral clock rates
- ARM: dts: am43xx: add support for clkout1 clock
- ARM: dts: at91: Reenable UART TX pull-ups
- platform/x86: intel_mid_powerbtn: Take a copy of ddata
- ARC: [plat-axs10x]: Add missing multicast filter number to GMAC node
- rtc: cmos: Stop using shared IRQ
- rtc: hym8563: Return -EINVAL if the time is known to be invalid
- spi: spi-mem: Fix inverted logic in op sanity check
- spi: spi-mem: Add extra sanity checks on the op param
- gpio: zynq: Report gpio direction at boot
- serial: uartps: Add a timeout to the tx empty wait
- NFSv4: try lease recovery on NFS4ERR_EXPIRED
- NFS/pnfs: Fix pnfs_generic_prepare_to_resend_writes()
- NFS: Revalidate the file size on a fatal write error
- nfs: NFS_SWAP should depend on SWAP
- PCI: Don't disable bridge BARs when assigning bus resources
- PCI/switchtec: Fix vep_vector_number ioread width
- ath10k: pci: Only dump ATH10K_MEM_REGION_TYPE_IOREG when safe
- PCI/IOV: Fix memory leak in pci_iov_add_virtfn()
- scsi: ufs: Fix ufshcd_probe_hba() reture value in case ufshcd_scsi_add_wlus() fails
- RDMA/uverbs: Verify MR access flags
- RDMA/core: Fix locking in ib_uverbs_event_read
- RDMA/netlink: Do not always generate an ACK for some netlink operations
- IB/mlx4: Fix memory leak in add_gid error flow
- hv_sock: Remove the accept port restriction
- ASoC: pcm: update FE/BE trigger order based on the command
- qm: fix the way judge whether q stop in user space
- net: hns3: clear devil number for hns3_cae
- net: hns3: fix compile error when CONFIG_HNS3_DCB is not set
- qm: fixup compilation dependency
- rde: optimize debug regs clear logic
- Linux 4.19.103
- rxrpc: Fix service call disconnection
- perf/core: Fix mlock accounting in perf_mmap()
- clocksource: Prevent double add_timer_on() for watchdog_timer
- x86/apic/msi: Plug non-maskable MSI affinity race
- cifs: fail i/o on soft mounts if sessionsetup errors out
- mm/page_alloc.c: fix uninitialized memmaps on a partially populated last section
- mm: return zero_resv_unavail optimization
- mm: zero remaining unavailable struct pages
- KVM: Play nice with read-only memslots when querying host page size
- KVM: Use vcpu-specific gva->hva translation when querying host page size
- KVM: nVMX: vmread should not set rflags to specify success in case of #PF
- KVM: VMX: Add non-canonical check on writes to RTIT address MSRs
- KVM: x86: Use gpa_t for cr2/gpa to fix TDP support on 32-bit KVM
- KVM: x86/mmu: Apply max PA check for MMIO sptes to 32-bit KVM
- btrfs: flush write bio if we loop in extent_write_cache_pages
- drm/dp_mst: Remove VCPI while disabling topology mgr
- drm: atmel-hlcdc: enable clock before configuring timing engine
- btrfs: free block groups after free'ing fs trees
- btrfs: use bool argument in free_root_pointers()
- ext4: fix deadlock allocating crypto bounce page from mempool
- net: dsa: b53: Always use dev->vlan_enabled in b53_configure_vlan()
- net: macb: Limit maximum GEM TX length in TSO
- net: macb: Remove unnecessary alignment check for TSO
- net/mlx5: IPsec, fix memory leak at mlx5_fpga_ipsec_delete_sa_ctx
- net/mlx5: IPsec, Fix esp modify function attribute
- net: systemport: Avoid RBUF stuck in Wake-on-LAN mode
- net_sched: fix a resource leak in tcindex_set_parms()
- net: mvneta: move rx_dropped and rx_errors in per-cpu stats
- net: dsa: bcm_sf2: Only 7278 supports 2Gb/sec IMP port
- bonding/alb: properly access headers in bond_alb_xmit()
- mfd: rn5t618: Mark ADC control register volatile
- mfd: da9062: Fix watchdog compatible string
- ubi: Fix an error pointer dereference in error handling code
- ubi: fastmap: Fix inverted logic in seen selfcheck
- nfsd: Return the correct number of bytes written to the file
- nfsd: fix jiffies/time_t mixup in LRU list
- nfsd: fix delay timer on 32-bit architectures
- IB/core: Fix ODP get user pages flow
- IB/mlx5: Fix outstanding_pi index for GSI qps
- net: tulip: Adjust indentation in {dmfe, uli526x}_init_module
- net: smc911x: Adjust indentation in smc911x_phy_configure
- ppp: Adjust indentation into ppp_async_input
- NFC: pn544: Adjust indentation in pn544_hci_check_presence
- drm: msm: mdp4: Adjust indentation in mdp4_dsi_encoder_enable
- powerpc/44x: Adjust indentation in ibm4xx_denali_fixup_memsize
- ext2: Adjust indentation in ext2_fill_super
- phy: qualcomm: Adjust indentation in read_poll_timeout
- scsi: ufs: Recheck bkops level if bkops is disabled
- scsi: qla4xxx: Adjust indentation in qla4xxx_mem_free
- scsi: csiostor: Adjust indentation in csio_device_reset
- scsi: qla2xxx: Fix the endianness of the qla82xx_get_fw_size() return type
- percpu: Separate decrypted varaibles anytime encryption can be enabled
- drm/amd/dm/mst: Ignore payload update failures
- clk: tegra: Mark fuse clock as critical
- KVM: s390: do not clobber registers during guest reset/store status
- KVM: x86: Free wbinvd_dirty_mask if vCPU creation fails
- KVM: x86: Don't let userspace set host-reserved cr4 bits
- x86/kvm: Be careful not to clear KVM_VCPU_FLUSH_TLB bit
- KVM: PPC: Book3S PR: Free shared page if mmu initialization fails
- KVM: PPC: Book3S HV: Uninit vCPU if vcore creation fails
- KVM: x86: Fix potential put_fpu() w/o load_fpu() on MPX platform
- KVM: x86: Protect MSR-based index computations in fixed_msr_to_seg_unit() from Spectre-v1/L1TF attacks
- KVM: x86: Protect x86_decode_insn from Spectre-v1/L1TF attacks
- KVM: x86: Protect MSR-based index computations from Spectre-v1/L1TF attacks in x86.c
- KVM: x86: Protect ioapic_read_indirect() from Spectre-v1/L1TF attacks
- KVM: x86: Protect MSR-based index computations in pmu.h from Spectre-v1/L1TF attacks
- KVM: x86: Protect ioapic_write_indirect() from Spectre-v1/L1TF attacks
- KVM: x86: Protect kvm_hv_msr_[get|set]_crash_data() from Spectre-v1/L1TF attacks
- KVM: x86: Protect kvm_lapic_reg_write() from Spectre-v1/L1TF attacks
- KVM: x86: Protect DR-based index computations from Spectre-v1/L1TF attacks
- KVM: x86: Protect pmu_intel.c from Spectre-v1/L1TF attacks
- KVM: x86: Refactor prefix decoding to prevent Spectre-v1/L1TF attacks
- KVM: x86: Refactor picdev_write() to prevent Spectre-v1/L1TF attacks
- aio: prevent potential eventfd recursion on poll
- eventfd: track eventfd_signal() recursion depth
- bcache: add readahead cache policy options via sysfs interface
- watchdog: fix UAF in reboot notifier handling in watchdog core code
- xen/balloon: Support xend-based toolstack take two
- media: rc: ensure lirc is initialized before registering input device
- drm/rect: Avoid division by zero
- gfs2: fix O_SYNC write handling
- gfs2: move setting current->backing_dev_info
- sunrpc: expiry_time should be seconds not timeval
- mwifiex: fix unbalanced locking in mwifiex_process_country_ie()
- iwlwifi: don't throw error when trying to remove IGTK
- ARM: tegra: Enable PLLP bypass during Tegra124 LP1
- Btrfs: fix race between adding and putting tree mod seq elements and nodes
- btrfs: set trans->drity in btrfs_commit_transaction
- Btrfs: fix missing hole after hole punching and fsync when using NO_HOLES
- jbd2_seq_info_next should increase position index
- NFS: Directory page cache pages need to be locked when read
- NFS: Fix memory leaks and corruption in readdir
- scsi: qla2xxx: Fix unbound NVME response length
- crypto: picoxcell - adjust the position of tasklet_init and fix missed tasklet_kill
- crypto: api - Fix race condition in crypto_spawn_alg
- crypto: atmel-aes - Fix counter overflow in CTR mode
- crypto: pcrypt - Do not clear MAY_SLEEP flag in original request
- crypto: ccp - set max RSA modulus size for v3 platform devices as well
- samples/bpf: Don't try to remove user's homedir on clean
- ftrace: Protect ftrace_graph_hash with ftrace_sync
- ftrace: Add comment to why rcu_dereference_sched() is open coded
- tracing: Annotate ftrace_graph_notrace_hash pointer with __rcu
- tracing: Annotate ftrace_graph_hash pointer with __rcu
- padata: Remove broken queue flushing
- dm writecache: fix incorrect flush sequence when doing SSD mode commit
- dm: fix potential for q->make_request_fn NULL pointer
- dm crypt: fix benbi IV constructor crash if used in authenticated mode
- dm space map common: fix to ensure new block isn't already in use
- dm zoned: support zone sizes smaller than 128MiB
- of: Add OF_DMA_DEFAULT_COHERENT & select it on powerpc
- PM: core: Fix handling of devices deleted during system-wide resume
- f2fs: code cleanup for f2fs_statfs_project()
- f2fs: fix miscounted block limit in f2fs_statfs_project()
- f2fs: choose hardlimit when softlimit is larger than hardlimit in f2fs_statfs_project()
- ovl: fix wrong WARN_ON() in ovl_cache_update_ino()
- power: supply: ltc2941-battery-gauge: fix use-after-free
- scsi: qla2xxx: Fix mtcp dump collection failure
- scripts/find-unused-docs: Fix massive false positives
- crypto: ccree - fix PM race condition
- crypto: ccree - fix pm wrongful error reporting
- crypto: ccree - fix backlog memory leak
- crypto: api - Check spawn->alg under lock in crypto_drop_spawn
- mfd: axp20x: Mark AXP20X_VBUS_IPSOUT_MGMT as volatile
- hv_balloon: Balloon up according to request page number
- mmc: sdhci-of-at91: fix memleak on clk_get failure
- PCI: keystone: Fix link training retries initiation
- crypto: geode-aes - convert to skcipher API and make thread-safe
- ubifs: Fix deadlock in concurrent bulk-read and writepage
- ubifs: Fix FS_IOC_SETFLAGS unexpectedly clearing encrypt flag
- ubifs: don't trigger assertion on invalid no-key filename
- ubifs: Reject unsupported ioctl flags explicitly
- alarmtimer: Unregister wakeup source when module get fails
- ACPI / battery: Deal better with neither design nor full capacity not being reported
- ACPI / battery: Use design-cap for capacity calculations if full-cap is not available
- ACPI / battery: Deal with design or full capacity being reported as -1
- ACPI: video: Do not export a non working backlight interface on MSI MS-7721 boards
- mmc: spi: Toggle SPI polarity, do not hardcode it
- PCI: tegra: Fix return value check of pm_runtime_get_sync()
- smb3: fix signing verification of large reads
- powerpc/pseries: Advance pfn if section is not present in lmb_is_removable()
- powerpc/xmon: don't access ASDR in VMs
- s390/mm: fix dynamic pagetable upgrade for hugetlbfs
- MIPS: boot: fix typo in 'vmlinux.lzma.its' target
- MIPS: fix indentation of the 'RELOCS' message
- KVM: arm64: Only sign-extend MMIO up to register width
- KVM: arm/arm64: Correct AArch32 SPSR on exception entry
- KVM: arm/arm64: Correct CPSR on exception entry
- KVM: arm64: Correct PSTATE on exception entry
- ALSA: hda: Add Clevo W65_67SB the power_save blacklist
- platform/x86: intel_scu_ipc: Fix interrupt support
- irqdomain: Fix a memory leak in irq_domain_push_irq()
- lib/test_kasan.c: fix memory leak in kmalloc_oob_krealloc_more()
- media: v4l2-rect.h: fix v4l2_rect_map_inside() top/left adjustments
- media: v4l2-core: compat: ignore native command codes
- media/v4l2-core: set pages dirty upon releasing DMA buffers
- mm: move_pages: report the number of non-attempted pages
- mm/memory_hotplug: fix remove_memory() lockdep splat
- ALSA: dummy: Fix PCM format loop in proc output
- ALSA: usb-audio: Fix endianess in descriptor validation
- usb: gadget: f_ecm: Use atomic_t to track in-flight request
- usb: gadget: f_ncm: Use atomic_t to track in-flight request
- usb: gadget: legacy: set max_speed to super-speed
- usb: typec: tcpci: mask event interrupts when remove driver
- brcmfmac: Fix memory leak in brcmf_usbdev_qinit
- rcu: Avoid data-race in rcu_gp_fqs_check_wake()
- tracing: Fix sched switch start/stop refcount racy updates
- ipc/msg.c: consolidate all xxxctl_down() functions
- mfd: dln2: More sanity checking for endpoints
- media: uvcvideo: Avoid cyclic entity chains due to malformed USB descriptors
- rxrpc: Fix NULL pointer deref due to call->conn being cleared on disconnect
- rxrpc: Fix missing active use pinning of rxrpc_local object
- rxrpc: Fix insufficient receive notification generation
- rxrpc: Fix use-after-free in rxrpc_put_local()
- tcp: clear tp->segs_{in|out} in tcp_disconnect()
- tcp: clear tp->data_segs{in|out} in tcp_disconnect()
- tcp: clear tp->delivered in tcp_disconnect()
- tcp: clear tp->total_retrans in tcp_disconnect()
- bnxt_en: Fix TC queue mapping.
- net: stmmac: Delete txtimer in suspend()
- net_sched: fix an OOB access in cls_tcindex
- net: hsr: fix possible NULL deref in hsr_handle_frame()
- l2tp: Allow duplicate session creation with UDP
- gtp: use __GFP_NOWARN to avoid memalloc warning
- cls_rsvp: fix rsvp_policy
- sparc32: fix struct ipc64_perm type definition
- iwlwifi: mvm: fix NVM check for 3168 devices
- printk: fix exclusive_console replaying
- udf: Allow writing to 'Rewritable' partitions
- x86/cpu: Update cached HLE state on write to TSX_CTRL_CPUID_CLEAR
- ocfs2: fix oops when writing cloned file
- media: iguanair: fix endpoint sanity check
- kernel/module: Fix memleak in module_add_modinfo_attrs()
- ovl: fix lseek overflow on 32bit
- Revert "drm/sun4i: dsi: Change the start delay calculation"
- sec: change sec_control reg config
- hpre: add likely and unlikey in result judgement
- hpre: optimize key process before free
- net: hns3: fix bug when parameter check
- Linux 4.19.102
- mm/migrate.c: also overwrite error when it is bigger than zero
- perf report: Fix no libunwind compiled warning break s390 issue
- btrfs: do not zero f_bavail if we have available space
- net: Fix skb->csum update in inet_proto_csum_replace16().
- l2t_seq_next should increase position index
- seq_tab_next() should increase position index
- net: fsl/fman: rename IF_MODE_XGMII to IF_MODE_10G
- net/fsl: treat fsl,erratum-a011043
- powerpc/fsl/dts: add fsl, erratum-a011043
- qlcnic: Fix CPU soft lockup while collecting firmware dump
- ARM: dts: am43x-epos-evm: set data pin directions for spi0 and spi1
- r8152: get default setting of WOL before initializing
- airo: Add missing CAP_NET_ADMIN check in AIROOLDIOCTL/SIOCDEVPRIVATE
- airo: Fix possible info leak in AIROOLDIOCTL/SIOCDEVPRIVATE
- tee: optee: Fix compilation issue with nommu
- ARM: 8955/1: virt: Relax arch timer version check during early boot
- scsi: fnic: do not queue commands during fwreset
- xfrm: interface: do not confirm neighbor when do pmtu update
- xfrm interface: fix packet tx through bpf_redirect()
- vti[6]: fix packet tx through bpf_redirect()
- ARM: dts: am335x-boneblack-common: fix memory size
- iwlwifi: Don't ignore the cap field upon mcc update
- riscv: delete temporary files
- bnxt_en: Fix ipv6 RFS filter matching logic.
- net: dsa: bcm_sf2: Configure IMP port for 2Gb/sec
- netfilter: nft_tunnel: ERSPAN_VERSION must not be null
- wireless: wext: avoid gcc -O3 warning
- mac80211: Fix TKIP replay protection immediately after key setup
- cfg80211: Fix radar event during another phy CAC
- wireless: fix enabling channel 12 for custom regulatory domain
- parisc: Use proper printk format for resource_size_t
- qmi_wwan: Add support for Quectel RM500Q
- ASoC: sti: fix possible sleep-in-atomic
- platform/x86: GPD pocket fan: Allow somewhat lower/higher temperature limits
- igb: Fix SGMII SFP module discovery for 100FX/LX.
- ixgbe: Fix calculation of queue with VFs and flow director on interface flap
- ixgbevf: Remove limit of 10 entries for unicast filter list
- ASoC: rt5640: Fix NULL dereference on module unload
- clk: mmp2: Fix the order of timer mux parents
- mac80211: mesh: restrict airtime metric to peered established plinks
- clk: sunxi-ng: h6-r: Fix AR100/R_APB2 parent order
- rseq: Unregister rseq for clone CLONE_VM
- tools lib traceevent: Fix memory leakage in filter_event
- soc: ti: wkup_m3_ipc: Fix race condition with rproc_boot
- ARM: dts: beagle-x15-common: Model 5V0 regulator
- ARM: dts: am57xx-beagle-x15/am57xx-idk: Remove "gpios" for endpoint dt nodes
- ARM: dts: sun8i: a83t: Correct USB3503 GPIOs polarity
- media: si470x-i2c: Move free() past last use of 'radio'
- cgroup: Prevent double killing of css when enabling threaded cgroup
- Bluetooth: Fix race condition in hci_release_sock()
- ttyprintk: fix a potential deadlock in interrupt context issue
- tomoyo: Use atomic_t for statistics counter
- media: dvb-usb/dvb-usb-urb.c: initialize actlen to 0
- media: gspca: zero usb_buf
- media: vp7045: do not read uninitialized values if usb transfer fails
- media: af9005: uninitialized variable printked
- media: digitv: don't continue if remote control state can't be read
- reiserfs: Fix memory leak of journal device string
- mm/mempolicy.c: fix out of bounds write in mpol_parse_str()
- ext4: validate the debug_want_extra_isize mount option at parse time
- arm64: kbuild: remove compressed images on 'make ARCH=arm64 (dist)clean'
- tools lib: Fix builds when glibc contains strlcpy()
- PM / devfreq: Add new name attribute for sysfs
- perf c2c: Fix return type for histogram sorting comparision functions
- rsi: fix use-after-free on failed probe and unbind
- rsi: add hci detach for hibernation and poweroff
- crypto: pcrypt - Fix user-after-free on module unload
- x86/resctrl: Fix a deadlock due to inaccurate reference
- x86/resctrl: Fix use-after-free due to inaccurate refcount of rdtgroup
- x86/resctrl: Fix use-after-free when deleting resource groups
- vfs: fix do_last() regression
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
- Linux 4.19.101
- KVM: arm64: Write arch.mdcr_el2 changes since last vcpu_load on VHE
- random: try to actively add entropy rather than passively wait for it
- crypto: af_alg - Use bh_lock_sock in sk_destruct
- rsi: fix non-atomic allocation in completion handler
- rsi: fix memory leak on failed URB submission
- rsi: fix use-after-free on probe errors
- usb-storage: Disable UAS on JMicron SATA enclosure
- ARM: OMAP2+: SmartReflex: add omap_sr_pdata definition
- iommu/amd: Support multiple PCI DMA aliases in IRQ Remapping
- PCI: Add DMA alias quirk for Intel VCA NTB
- platform/x86: dell-laptop: disable kbd backlight on Inspiron 10xx
- HID: steam: Fix input device disappearing
- atm: eni: fix uninitialized variable warning
- gpio: max77620: Add missing dependency on GPIOLIB_IRQCHIP
- net: wan: sdla: Fix cast from pointer to integer of different size
- drivers/net/b44: Change to non-atomic bit operations on pwol_mask
- spi: spi-dw: Add lock protect dw_spi rx/tx to prevent concurrent calls
- watchdog: rn5t618_wdt: fix module aliases
- watchdog: max77620_wdt: fix potential build errors
- phy: cpcap-usb: Prevent USB line glitches from waking up modem
- phy: qcom-qmp: Increase PHY ready timeout
- drivers/hid/hid-multitouch.c: fix a possible null pointer access.
- HID: Add quirk for incorrect input length on Lenovo Y720
- HID: ite: Add USB id match for Acer SW5-012 keyboard dock
- HID: Add quirk for Xin-Mo Dual Controller
- arc: eznps: fix allmodconfig kconfig warning
- HID: multitouch: Add LG MELF0410 I2C touchscreen support
- net_sched: fix ops->bind_class() implementations
- net_sched: ematch: reject invalid TCF_EM_SIMPLE
- zd1211rw: fix storage endpoint lookup
- rtl8xxxu: fix interface sanity check
- brcmfmac: fix interface sanity check
- ath9k: fix storage endpoint lookup
- cifs: Fix memory allocation in __smb2_handle_cancelled_cmd()
- crypto: chelsio - fix writing tfm flags to wrong place
- iio: st_gyro: Correct data for LSM9DS0 gyro
- mei: me: add comet point (lake) H device ids
- component: do not dereference opaque pointer in debugfs
- serial: 8250_bcm2835aux: Fix line mismatch on driver unbind
- staging: vt6656: Fix false Tx excessive retries reporting.
- staging: vt6656: use NULLFUCTION stack on mac80211
- staging: vt6656: correct packet types for CTS protect, mode.
- staging: wlan-ng: ensure error return is actually returned
- staging: most: net: fix buffer overflow
- usb: dwc3: turn off VBUS when leaving host mode
- Linux 4.19.100
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
- net/x25: fix nonblocking connect
- netfilter: nf_tables: add __nft_chain_type_get()
- netfilter: ipset: use bitmap infrastructure completely
- scsi: iscsi: Avoid potential deadlock in iscsi_if_rx func
- media: v4l2-ioctl.c: zero reserved fields for S/TRY_FMT
- libertas: Fix two buffer overflows at parsing bss descriptor
- coresight: tmc-etf: Do not call smp_processor_id from preemptible
- coresight: etb10: Do not call smp_processor_id from preemptible
- crypto: geode-aes - switch to skcipher for cbc(aes) fallback
- sd: Fix REQ_OP_ZONE_REPORT completion handling
- tracing: Fix histogram code when expression has same var as value
- tracing: Remove open-coding of hist trigger var_ref management
- tracing: Use hist trigger's var_ref array to destroy var_refs
- net/sonic: Prevent tx watchdog timeout
- net/sonic: Fix CAM initialization
- net/sonic: Fix command register usage
- net/sonic: Quiesce SONIC before re-initializing descriptor memory
- net/sonic: Fix receive buffer replenishment
- net/sonic: Improve receive descriptor status flag check
- net/sonic: Avoid needless receive descriptor EOL flag updates
- net/sonic: Fix receive buffer handling
- net/sonic: Fix interface error stats collection
- net/sonic: Use MMIO accessors
- net/sonic: Clear interrupt flags immediately
- net/sonic: Add mutual exclusion for accessing shared state
- do_last(): fetch directory ->i_mode and ->i_uid before it's too late
- tracing: xen: Ordered comparison of function pointers
- scsi: RDMA/isert: Fix a recently introduced regression related to logout
- hwmon: (nct7802) Fix voltage limits to wrong registers
- netfilter: nft_osf: add missing check for DREG attribute
- Input: sun4i-ts - add a check for devm_thermal_zone_of_sensor_register
- Input: pegasus_notetaker - fix endpoint sanity check
- Input: aiptek - fix endpoint sanity check
- Input: gtco - fix endpoint sanity check
- Input: sur40 - fix interface sanity checks
- Input: pm8xxx-vib - fix handling of separate enable register
- mmc: sdhci: fix minimum clock rate for v3 controller
- mmc: tegra: fix SDR50 tuning override
- ARM: 8950/1: ftrace/recordmcount: filter relocation types
- Revert "Input: synaptics-rmi4 - don't increment rmiaddr for SMBus transfers"
- Input: keyspan-remote - fix control-message timeouts
- tracing: trigger: Replace unneeded RCU-list traversals
- PCI: Mark AMD Navi14 GPU rev 0xc5 ATS as broken
- hwmon: (core) Do not use device managed functions for memory allocations
- hwmon: (adt7475) Make volt2reg return same reg as reg2volt input
- afs: Fix characters allowed into cell names
- tun: add mutex_unlock() call and napi.skb clearing in tun_get_user()
- tcp: do not leave dangling pointers in tp->highest_sack
- tcp_bbr: improve arithmetic division in bbr_update_bw()
- Revert "udp: do rmem bulk free even if the rx sk queue is empty"
- net: usb: lan78xx: Add .ndo_features_check
- net-sysfs: Fix reference count leak
- net-sysfs: Call dev_hold always in rx_queue_add_kobject
- net-sysfs: Call dev_hold always in netdev_queue_add_kobject
- net-sysfs: fix netdev_queue_add_kobject() breakage
- net-sysfs: Fix reference count leak in rx|netdev_queue_add_kobject
- net_sched: fix datalen for ematch
- net: rtnetlink: validate IFLA_MTU attribute in rtnl_create_link()
- net, ip_tunnel: fix namespaces move
- net, ip6_tunnel: fix namespaces move
- net: ip6_gre: fix moving ip6gre between namespaces
- net: cxgb3_main: Add CAP_NET_ADMIN check to CHELSIO_GET_MEM
- net: bcmgenet: Use netif_tx_napi_add() for TX NAPI
- ipv6: sr: remove SKB_GSO_IPXIP6 on End.D* actions
- gtp: make sure only SOCK_DGRAM UDP sockets are accepted
- firestream: fix memory leaks
- can, slip: Protect tty->disc_data in write_wakeup and close with RCU
- arm64/mm: add temporary arch_remove_memory() implementation
- s390x/mm: fail when an altmap is used for arch_add_memory()
- mm/memory_hotplug: simplify and fix check_hotplug_memory_range()
- Linux 4.19.99
- m68k: Call timer_interrupt() with interrupts disabled
- arm64: dts: meson-gxm-khadas-vim2: fix uart_A bluetooth node
- serial: stm32: fix clearing interrupt error flags
- usb: dwc3: Allow building USB_DWC3_QCOM without EXTCON
- samples/bpf: Fix broken xdp_rxq_info due to map order assumptions
- arm64: dts: juno: Fix UART frequency
- drm/radeon: fix bad DMA from INTERRUPT_CNTL2
- dmaengine: ti: edma: fix missed failure handling
- afs: Remove set but not used variables 'before', 'after'
- affs: fix a memory leak in affs_remount
- mmc: core: fix wl1251 sdio quirks
- mmc: sdio: fix wl1251 vendor id
- i2c: stm32f7: report dma error during probe
- packet: fix data-race in fanout_flow_is_huge()
- net: neigh: use long type to store jiffies delta
- hv_netvsc: flag software created hash value
- MIPS: Loongson: Fix return value of loongson_hwmon_init
- dpaa_eth: avoid timestamp read on error paths
- dpaa_eth: perform DMA unmapping before read
- hwrng: omap3-rom - Fix missing clock by probing with device tree
- drm: panel-lvds: Potential Oops in probe error handling
- afs: Fix large file support
- hv_netvsc: Fix send_table offset in case of a host bug
- hv_netvsc: Fix offset usage in netvsc_send_table()
- net: qca_spi: Move reset_count to struct qcaspi
- afs: Fix missing timeout reset
- bpf, offload: Unlock on error in bpf_offload_dev_create()
- xsk: Fix registration of Rx-only sockets
- net: netem: correct the parent's backlog when corrupted packet was dropped
- net: netem: fix error path for corrupted GSO frames
- arm64: hibernate: check pgd table allocation
- dmaengine: imx-sdma: fix size check for sdma script_number
- vhost/test: stop device before reset
- drm/msm/dsi: Implement reset correctly
- net/smc: receive pending data after RCV_SHUTDOWN
- net/smc: receive returns without data
- net: add {READ|WRITE}_ONCE() annotations on ->rskq_accept_head
- net: avoid possible false sharing in sk_leave_memory_pressure()
- act_mirred: Fix mirred_init_module error handling
- s390/qeth: Fix initialization of vnicc cmd masks during set online
- s390/qeth: Fix error handling during VNICC initialization
- sctp: add chunks to sk_backlog when the newsk sk_socket is not set
- net: stmmac: fix disabling flexible PPS output
- net: stmmac: fix length of PTP clock's name string
- ip6erspan: remove the incorrect mtu limit for ip6erspan
- llc: fix sk_buff refcounting in llc_conn_state_process()
- llc: fix another potential sk_buff leak in llc_ui_sendmsg()
- mac80211: accept deauth frames in IBSS mode
- rxrpc: Fix trace-after-put looking at the put connection record
- net: stmmac: gmac4+: Not all Unicast addresses may be available
- nvme: retain split access workaround for capability reads
- net: sched: cbs: Avoid division by zero when calculating the port rate
- net: ethernet: stmmac: Fix signedness bug in ipq806x_gmac_of_parse()
- net: nixge: Fix a signedness bug in nixge_probe()
- of: mdio: Fix a signedness bug in of_phy_get_and_connect()
- net: axienet: fix a signedness bug in probe
- net: stmmac: dwmac-meson8b: Fix signedness bug in probe
- net: socionext: Fix a signedness bug in ave_probe()
- net: netsec: Fix signedness bug in netsec_probe()
- net: broadcom/bcmsysport: Fix signedness in bcm_sysport_probe()
- net: hisilicon: Fix signedness bug in hix5hd2_dev_probe()
- cxgb4: Signedness bug in init_one()
- net: aquantia: Fix aq_vec_isr_legacy() return value
- iommu/amd: Wait for completion of IOTLB flush in attach_device
- bpf: fix BTF limits
- powerpc/mm/mce: Keep irqs disabled during lockless page table walk
- clk: actions: Fix factor clk struct member access
- mailbox: qcom-apcs: fix max_register value
- f2fs: fix to avoid accessing uninitialized field of inode page in is_alive()
- bnxt_en: Increase timeout for HWRM_DBG_COREDUMP_XX commands
- um: Fix off by one error in IRQ enumeration
- net/rds: Fix 'ib_evt_handler_call' element in 'rds_ib_stat_names'
- RDMA/cma: Fix false error message
- ath10k: adjust skb length in ath10k_sdio_mbox_rx_packet
- gpio/aspeed: Fix incorrect number of banks
- pinctrl: iproc-gpio: Fix incorrect pinconf configurations
- net: sonic: replace dev_kfree_skb in sonic_send_packet
- hwmon: (shtc1) fix shtc1 and shtw1 id mask
- btrfs: use correct count in btrfs_file_write_iter()
- Btrfs: fix inode cache waiters hanging on path allocation failure
- Btrfs: fix inode cache waiters hanging on failure to start caching thread
- Btrfs: fix hang when loading existing inode cache off disk
- scsi: fnic: fix msix interrupt allocation
- f2fs: fix error path of f2fs_convert_inline_page()
- f2fs: fix wrong error injection path in inc_valid_block_count()
- ARM: dts: logicpd-som-lv: Fix i2c2 and i2c3 Pin mux
- rtlwifi: Fix file release memory leak
- net: sonic: return NETDEV_TX_OK if failed to map buffer
- led: triggers: Fix dereferencing of null pointer
- xsk: avoid store-tearing when assigning umem
- xsk: avoid store-tearing when assigning queues
- ARM: dts: aspeed-g5: Fixe gpio-ranges upper limit
- tty: serial: fsl_lpuart: Use appropriate lpuart32_* I/O funcs
- wcn36xx: use dynamic allocation for large variables
- ath9k: dynack: fix possible deadlock in ath_dynack_node_{de}init
- netfilter: ctnetlink: honor IPS_OFFLOAD flag
- iio: dac: ad5380: fix incorrect assignment to val
- bcache: Fix an error code in bch_dump_read()
- usb: typec: tps6598x: Fix build error without CONFIG_REGMAP_I2C
- bcma: fix incorrect update of BCMA_CORE_PCI_MDIO_DATA
- staging: greybus: light: fix a couple double frees
- x86, perf: Fix the dependency of the x86 insn decoder selftest
- power: supply: Init device wakeup after device_add()
- net/sched: cbs: Set default link speed to 10 Mbps in cbs_set_port_rate
- hwmon: (lm75) Fix write operations for negative temperatures
- Partially revert "kfifo: fix kfifo_alloc() and kfifo_init()"
- rxrpc: Fix lack of conn cleanup when local endpoint is cleaned up [ver #2]
- ahci: Do not export local variable ahci_em_messages
- iommu/mediatek: Fix iova_to_phys PA start for 4GB mode
- media: em28xx: Fix exception handling in em28xx_alloc_urbs()
- mips: avoid explicit UB in assignment of mips_io_port_base
- rtc: pcf2127: bugfix: read rtc disables watchdog
- ARM: 8896/1: VDSO: Don't leak kernel addresses
- media: atmel: atmel-isi: fix timeout value for stop streaming
- i40e: reduce stack usage in i40e_set_fc
- mac80211: minstrel_ht: fix per-group max throughput rate initialization
- rtc: rv3029: revert error handling patch to rv3029_eeprom_write()
- dmaengine: dw: platform: Switch to acpi_dma_controller_register()
- ASoC: sun4i-i2s: RX and TX counter registers are swapped
- powerpc/64s/radix: Fix memory hot-unplug page table split
- signal: Allow cifs and drbd to receive their terminating signals
- bnxt_en: Fix handling FRAG_ERR when NVM_INSTALL_UPDATE cmd fails
- drm: rcar-du: lvds: Fix bridge_to_rcar_lvds
- tools: bpftool: fix format strings and arguments for jsonw_printf()
- tools: bpftool: fix arguments for p_err() in do_event_pipe()
- net/rds: Add a few missing rds_stat_names entries
- ASoC: wm8737: Fix copy-paste error in wm8737_snd_controls
- ASoC: cs4349: Use PM ops 'cs4349_runtime_pm'
- ASoC: es8328: Fix copy-paste error in es8328_right_line_controls
- ext4: set error return correctly when ext4_htree_store_dirent fails
- crypto: caam - free resources in case caam_rng registration failed
- cxgb4: smt: Add lock for atomic_dec_and_test
- spi: bcm-qspi: Fix BSPI QUAD and DUAL mode support when using flex mode
- net: fix bpf_xdp_adjust_head regression for generic-XDP
- iio: tsl2772: Use devm_add_action_or_reset for tsl2772_chip_off
- cifs: fix rmmod regression in cifs.ko caused by force_sig changes
- net/mlx5: Fix mlx5_ifc_query_lag_out_bits
- ARM: dts: stm32: add missing vdda-supply to adc on stm32h743i-eval
- tipc: reduce risk of wakeup queue starvation
- arm64: dts: renesas: r8a77995: Fix register range of display node
- ALSA: aoa: onyx: always initialize register read value
- crypto: ccp - Reduce maximum stack usage
- x86/kgbd: Use NMI_VECTOR not APIC_DM_NMI
- mic: avoid statically declaring a 'struct device'.
- media: rcar-vin: Clean up correct notifier in error path
- qed: reduce maximum stack frame size
- libertas_tf: Use correct channel range in lbtf_geo_init
- clk: sunxi-ng: v3s: add the missing PLL_DDR1
- drm/panel: make drm_panel.h self-contained
- xfrm interface: ifname may be wrong in logs
- scsi: libfc: fix null pointer dereference on a null lport
- ARM: stm32: use "depends on" instead of "if" after prompt
- xdp: fix possible cq entry leak
- x86/pgtable/32: Fix LOWMEM_PAGES constant
- net/tls: fix socket wmem accounting on fallback with netem
- net: pasemi: fix an use-after-free in pasemi_mac_phy_init()
- ceph: fix "ceph.dir.rctime" vxattr value
- PCI: mobiveil: Fix the valid check for inbound and outbound windows
- PCI: mobiveil: Fix devfn check in mobiveil_pcie_valid_device()
- PCI: mobiveil: Remove the flag MSI_FLAG_MULTI_PCI_MSI
- fsi: sbefifo: Don't fail operations when in SBE IPL state
- devres: allow const resource arguments
- fsi/core: Fix error paths on CFAM init
- ACPI: PM: Introduce "poweroff" callbacks for ACPI PM domain and LPSS
- ACPI: PM: Simplify and fix PM domain hibernation callbacks
- um: Fix IRQ controller regression on console read
- xprtrdma: Fix use-after-free in rpcrdma_post_recvs
- rxrpc: Fix uninitialized error code in rxrpc_send_data_packet()
- mfd: intel-lpss: Release IDA resources
- iommu/amd: Make iommu_disable safer
- bnxt_en: Suppress error messages when querying DSCP DCB capabilities.
- bnxt_en: Fix ethtool selftest crash under error conditions.
- fork, memcg: alloc_thread_stack_node needs to set tsk->stack
- backlight: pwm_bl: Fix heuristic to determine number of brightness levels
- tools: bpftool: use correct argument in cgroup errors
- nvmem: imx-ocotp: Change TIMING calculation to u-boot algorithm
- nvmem: imx-ocotp: Ensure WAIT bits are preserved when setting timing
- clk: qcom: Fix -Wunused-const-variable
- dmaengine: hsu: Revert "set HSU_CH_MTSR to memory width"
- perf/ioctl: Add check for the sample_period value
- drm/msm/a3xx: remove TPL1 regs from snapshot
- arm64: dts: allwinner: h6: Pine H64: Add interrupt line for RTC
- ARM: dts: iwg20d-q7-common: Fix SDHI1 VccQ regularor
- rtc: pcf8563: Clear event flags and disable interrupts before requesting irq
- rtc: pcf8563: Fix interrupt trigger method
- ASoC: ti: davinci-mcasp: Fix slot mask settings when using multiple AXRs
- net/af_iucv: always register net_device notifier
- net/af_iucv: build proper skbs for HiperTransport
- net/udp_gso: Allow TX timestamp with UDP GSO
- net: netem: fix backlog accounting for corrupted GSO frames
- drm/msm/mdp5: Fix mdp5_cfg_init error return
- IB/hfi1: Handle port down properly in pio
- bpf: fix the check that forwarding is enabled in bpf_ipv6_fib_lookup
- powerpc/pseries/mobility: rebuild cacheinfo hierarchy post-migration
- powerpc/cacheinfo: add cacheinfo_teardown, cacheinfo_rebuild
- qed: iWARP - fix uninitialized callback
- qed: iWARP - Use READ_ONCE and smp_store_release to access ep->state
- ASoC: meson: axg-tdmout: right_j is not supported
- ASoC: meson: axg-tdmin: right_j is not supported
- ntb_hw_switchtec: potential shift wrapping bug in switchtec_ntb_init_sndev()
- firmware: arm_scmi: update rate_discrete in clock_describe_rates_get
- firmware: arm_scmi: fix bitfield definitions for SENSOR_DESC attributes
- phy: usb: phy-brcm-usb: Remove sysfs attributes upon driver removal
- iommu/vt-d: Duplicate iommu_resv_region objects per device list
- arm64: dts: meson-gxm-khadas-vim2: fix Bluetooth support
- arm64: dts: meson-gxm-khadas-vim2: fix gpio-keys-polled node
- serial: stm32: fix a recursive locking in stm32_config_rs485
- mpls: fix warning with multi-label encap
- arm64: dts: renesas: ebisu: Remove renesas, no-ether-link property
- crypto: inside-secure - fix queued len computation
- crypto: inside-secure - fix zeroing of the request in ahash_exit_inv
- media: vivid: fix incorrect assignment operation when setting video mode
- clk: sunxi-ng: sun50i-h6-r: Fix incorrect W1 clock gate register
- cpufreq: brcmstb-avs-cpufreq: Fix types for voltage/frequency
- cpufreq: brcmstb-avs-cpufreq: Fix initial command check
- phy: qcom-qusb2: fix missing assignment of ret when calling clk_prepare_enable
- RDMA/uverbs: check for allocation failure in uapi_add_elm()
- net: core: support XDP generic on stacked devices.
- netvsc: unshare skb in VF rx handler
- crypto: talitos - fix AEAD processing.
- inet: frags: call inet_frags_fini() after unregister_pernet_subsys()
- signal/cifs: Fix cifs_put_tcp_session to call send_sig instead of force_sig
- signal/bpfilter: Fix bpfilter_kernl to use send_sig not force_sig
- iommu: Use right function to get group for device
- misc: sgi-xp: Properly initialize buf in xpc_get_rsvd_page_pa
- serial: stm32: fix wakeup source initialization
- serial: stm32: Add support of TC bit status check
- serial: stm32: fix transmit_chars when tx is stopped
- serial: stm32: fix rx data length when parity enabled
- serial: stm32: fix rx error handling
- serial: stm32: fix word length configuration
- crypto: ccp - Fix 3DES complaint from ccp-crypto module
- crypto: ccp - fix AES CFB error exposed by new test vectors
- spi: spi-fsl-spi: call spi_finalize_current_message() at the end
- RDMA/qedr: Fix incorrect device rate.
- arm64: dts: meson: libretech-cc: set eMMC as removable
- dmaengine: tegra210-adma: Fix crash during probe
- clk: meson: axg: spread spectrum is on mpll2
- clk: meson: gxbb: no spread spectrum on mpll0
- ARM: dts: sun8i-h3: Fix wifi in Beelink X2 DT
- afs: Fix double inc of vnode->cb_break
- afs: Fix lock-wait/callback-break double locking
- afs: Don't invalidate callback if AFS_VNODE_DIR_VALID not set
- afs: Fix key leak in afs_release() and afs_evict_inode()
- thermal: cpu_cooling: Actually trace CPU load in thermal_power_cpu_get_power
- thermal: rcar_gen3_thermal: fix interrupt type
- backlight: lm3630a: Return 0 on success in update_status functions
- kdb: do a sanity check on the cpu in kdb_per_cpu()
- nfp: bpf: fix static check error through tightening shift amount adjustment
- ARM: riscpc: fix lack of keyboard interrupts after irq conversion
- pwm: meson: Don't disable PWM when setting duty repeatedly
- pwm: meson: Consider 128 a valid pre-divider
- netfilter: ebtables: CONFIG_COMPAT: reject trailing data after last rule
- crypto: caam - fix caam_dump_sg that iterates through scatterlist
- platform/x86: alienware-wmi: printing the wrong error code
- media: davinci/vpbe: array underflow in vpbe_enum_outputs()
- media: omap_vout: potential buffer overflow in vidioc_dqbuf()
- ALSA: aica: Fix a long-time build breakage
- afs: Fix the afs.cell and afs.volume xattr handlers
- ath10k: Fix encoding for protected management frames
- lightnvm: pblk: fix lock order in pblk_rb_tear_down_check
- mmc: core: fix possible use after free of host
- watchdog: rtd119x_wdt: Fix remove function
- dmaengine: tegra210-adma: restore channel status
- net: ena: fix ena_com_fill_hash_function() implementation
- net: ena: fix incorrect test of supported hash function
- net: ena: fix: Free napi resources when ena_up() fails
- net: ena: fix swapped parameters when calling ena_com_indirect_table_fill_entry
- RDMA/rxe: Consider skb reserve space based on netdev of GID
- IB/mlx5: Add missing XRC options to QP optional params mask
- dwc2: gadget: Fix completed transfer size calculation in DDMA
- usb: gadget: fsl: fix link error against usb-gadget module
- ASoC: fix valid stream condition
- ARM: dts: logicpd-som-lv: Fix MMC1 card detect
- PCI: iproc: Enable iProc config read for PAXBv2
- netfilter: nft_flow_offload: add entry to flowtable after confirmation
- KVM: PPC: Book3S HV: Fix lockdep warning when entering the guest
- scsi: qla2xxx: Avoid that qlt_send_resp_ctio() corrupts memory
- scsi: qla2xxx: Fix error handling in qlt_alloc_qfull_cmd()
- scsi: qla2xxx: Fix a format specifier
- s390/kexec_file: Fix potential segment overlap in ELF loader
- coresight: catu: fix clang build warning
- afs: Further fix file locking
- afs: Fix AFS file locking to allow fine grained locks
- ALSA: usb-audio: Handle the error from snd_usb_mixer_apply_create_quirk()
- dmaengine: axi-dmac: Don't check the number of frames for alignment
- media: ov2659: fix unbalanced mutex_lock/unlock
- ARM: dts: ls1021: Fix SGMII PCS link remaining down after PHY disconnect
- powerpc: vdso: Make vdso32 installation conditional in vdso_install
- selftests/ipc: Fix msgque compiler warnings
- usb: typec: tcpm: Notify the tcpc to start connection-detection for SRPs
- platform/x86: alienware-wmi: fix kfree on potentially uninitialized pointer
- soc: amlogic: meson-gx-pwrc-vpu: Fix power on/off register bitmask
- staging: android: vsoc: fix copy_from_user overrun
- perf/core: Fix the address filtering fix
- hwmon: (w83627hf) Use request_muxed_region for Super-IO accesses
- PCI: rockchip: Fix rockchip_pcie_ep_assert_intx() bitwise operations
- ARM: pxa: ssp: Fix "WARNING: invalid free of devm_ allocated data"
- brcmfmac: fix leak of mypkt on error return path
- scsi: target/core: Fix a race condition in the LUN lookup code
- rxrpc: Fix detection of out of order acks
- firmware: arm_scmi: fix of_node leak in scmi_mailbox_check
- clk: qcom: Skip halt checks on gcc_pcie_0_pipe_clk for 8998
- of: use correct function prototype for of_overlay_fdt_apply()
- scsi: qla2xxx: Unregister chrdev if module initialization fails
- drm/vmwgfx: Remove set but not used variable 'restart'
- bpf: Add missed newline in verifier verbose log
- ehea: Fix a copy-paste err in ehea_init_port_res
- rtc: mt6397: Don't call irq_dispose_mapping.
- drm/fb-helper: generic: Call drm_client_add() after setup is done
- spi: bcm2835aux: fix driver to not allow 65535 (=-1) cs-gpios
- soc/fsl/qe: Fix an error code in qe_pin_request()
- bus: ti-sysc: Fix sysc_unprepare() when no clocks have been allocated
- spi: tegra114: configure dma burst size to fifo trig level
- spi: tegra114: flush fifos
- spi: tegra114: terminate dma and reset on transfer timeout
- spi: tegra114: fix for unpacked mode transfers
- spi: tegra114: clear packed bit for unpacked mode
- media: tw5864: Fix possible NULL pointer dereference in tw5864_handle_frame
- media: davinci-isif: avoid uninitialized variable use
- soc: qcom: cmd-db: Fix an error code in cmd_db_dev_probe()
- net: dsa: Avoid null pointer when failing to connect to PHY
- ARM: OMAP2+: Fix potentially uninitialized return value for _setup_reset()
- net: phy: don't clear BMCR in genphy_soft_reset
- ARM: dts: sun9i: optimus: Fix fixed-regulators
- arm64: dts: allwinner: a64: Add missing PIO clocks
- ARM: dts: sun8i: a33: Reintroduce default pinctrl muxing
- m68k: mac: Fix VIA timer counter accesses
- jfs: fix bogus variable self-initialization
- crypto: ccree - reduce kernel stack usage with clang
- regulator: tps65086: Fix tps65086_ldoa1_ranges for selector 0xB
- media: cx23885: check allocation return
- media: wl128x: Fix an error code in fm_download_firmware()
- media: cx18: update *pos correctly in cx18_read_pos()
- media: ivtv: update *pos correctly in ivtv_read_pos()
- soc: amlogic: gx-socinfo: Add mask for each SoC packages
- regulator: lp87565: Fix missing register for LP87565_BUCK_0
- net: sh_eth: fix a missing check of of_get_phy_mode
- xen, cpu_hotplug: Prevent an out of bounds access
- drivers/rapidio/rio_cm.c: fix potential oops in riocm_ch_listen()
- nfp: fix simple vNIC mailbox length
- scsi: megaraid_sas: reduce module load time
- x86/mm: Remove unused variable 'cpu'
- nios2: ksyms: Add missing symbol exports
- rbd: clear ->xferred on error from rbd_obj_issue_copyup()
- media: dvb/earth-pt1: fix wrong initialization for demod blocks
- powerpc/mm: Check secondary hash page table
- net: aquantia: fixed instack structure overflow
- NFSv4/flexfiles: Fix invalid deref in FF_LAYOUT_DEVID_NODE()
- NFS: Add missing encode / decode sequence_maxsz to v4.2 operations
- hwrng: bcm2835 - fix probe as platform device
- netfilter: nft_set_hash: bogus element self comparison from deactivation path
- ath10k: Fix length of wmi tlv command for protected mgmt frames
- regulator: wm831x-dcdc: Fix list of wm831x_dcdc_ilim from mA to uA
- ARM: 8849/1: NOMMU: Fix encodings for PMSAv8's PRBAR4/PRLAR4
- ARM: 8848/1: virt: Align GIC version check with arm64 counterpart
- ARM: 8847/1: pm: fix HYP/SVC mode mismatch when MCPM is used
- mmc: sdhci-brcmstb: handle mmc_of_parse() errors during probe
- NFS/pnfs: Bulk destroy of layouts needs to be safe w.r.t. umount
- platform/x86: wmi: fix potential null pointer dereference
- clocksource/drivers/exynos_mct: Fix error path in timer resources initialization
- clocksource/drivers/sun5i: Fail gracefully when clock rate is unavailable
- powerpc/64s: Fix logic when handling unknown CPU features
- staging: rtlwifi: Use proper enum for return in halmac_parse_psd_data_88xx
- fs/nfs: Fix nfs_parse_devname to not modify it's argument
- net: dsa: fix unintended change of bridge interface STP state
- ASoC: qcom: Fix of-node refcount unbalance in apq8016_sbc_parse_of()
- driver core: Fix PM-runtime for links added during consumer probe
- drm/nouveau: fix missing break in switch statement
- drm/nouveau/pmu: don't print reply values if exec is false
- drm/nouveau/bios/ramcfg: fix missing parentheses when calculating RON
- net/mlx5: Delete unused FPGA QPN variable
- net: dsa: qca8k: Enable delay for RGMII_ID mode
- regulator: pv88090: Fix array out-of-bounds access
- regulator: pv88080: Fix array out-of-bounds access
- regulator: pv88060: Fix array out-of-bounds access
- brcmfmac: create debugfs files for bus-specific layer
- cdc-wdm: pass return value of recover_from_urb_loss
- dmaengine: mv_xor: Use correct device for DMA API
- staging: r8822be: check kzalloc return or bail
- KVM: PPC: Release all hardware TCE tables attached to a group
- mdio_bus: Fix PTR_ERR() usage after initialization to constant
- hwmon: (pmbus/tps53679) Fix driver info initialization in probe routine
- vfio_pci: Enable memory accesses before calling pci_map_rom
- media: sh: migor: Include missing dma-mapping header
- mt76: usb: fix possible memory leak in mt76u_buf_free
- net: dsa: b53: Do not program CPU port's PVID
- net: dsa: b53: Properly account for VLAN filtering
- net: dsa: b53: Fix default VLAN ID
- usb: phy: twl6030-usb: fix possible use-after-free on remove
- driver core: Fix possible supplier PM-usage counter imbalance
- RDMA/mlx5: Fix memory leak in case we fail to add an IB device
- pinctrl: sh-pfc: sh73a0: Fix fsic_spdif pin groups
- pinctrl: sh-pfc: r8a7792: Fix vin1_data18_b pin group
- pinctrl: sh-pfc: r8a7791: Fix scifb2_data_c pin group
- pinctrl: sh-pfc: emev2: Add missing pinmux functions
- ntb_hw_switchtec: NT req id mapping table register entry number should be 512
- ntb_hw_switchtec: debug print 64bit aligned crosslink BAR Numbers
- drm/etnaviv: potential NULL dereference
- iw_cxgb4: use tos when finding ipv6 routes
- iw_cxgb4: use tos when importing the endpoint
- fbdev: chipsfb: remove set but not used variable 'size'
- rtc: pm8xxx: fix unintended sign extension
- rtc: 88pm80x: fix unintended sign extension
- rtc: 88pm860x: fix unintended sign extension
- net/smc: original socket family in inet_sock_diag
- rtc: ds1307: rx8130: Fix alarm handling
- net: phy: fixed_phy: Fix fixed_phy not checking GPIO
- ath10k: fix dma unmap direction for management frames
- arm64: dts: msm8916: remove bogus argument to the cpu clock
- thermal: mediatek: fix register index error
- rtc: ds1672: fix unintended sign extension
- clk: ingenic: jz4740: Fix gating of UDC clock
- staging: most: cdev: add missing check for cdev_add failure
- iwlwifi: mvm: fix RSS config command
- drm/xen-front: Fix mmap attributes for display buffers
- ARM: dts: lpc32xx: phy3250: fix SD card regulator voltage
- ARM: dts: lpc32xx: fix ARM PrimeCell LCD controller clocks property
- ARM: dts: lpc32xx: fix ARM PrimeCell LCD controller variant
- ARM: dts: lpc32xx: reparent keypad controller to SIC1
- ARM: dts: lpc32xx: add required clocks property to keypad device node
- driver core: Do not call rpm_put_suppliers() in pm_runtime_drop_link()
- driver core: Fix handling of runtime PM flags in device_link_add()
- driver core: Do not resume suppliers under device_links_write_lock()
- driver core: Avoid careless re-use of existing device links
- driver core: Fix DL_FLAG_AUTOREMOVE_SUPPLIER device link flag handling
- crypto: crypto4xx - Fix wrong ppc4xx_trng_probe()/ppc4xx_trng_remove() arguments
- tty: ipwireless: Fix potential NULL pointer dereference
- bus: ti-sysc: Fix timer handling with drop pm_runtime_irq_safe()
- iwlwifi: mvm: fix A-MPDU reference assignment
- arm64: dts: allwinner: h6: Move GIC device node fix base address ordering
- ip_tunnel: Fix route fl4 init in ip_md_tunnel_xmit
- net/mlx5: Take lock with IRQs disabled to avoid deadlock
- iwlwifi: mvm: avoid possible access out of array.
- clk: sunxi-ng: sun8i-a23: Enable PLL-MIPI LDOs when ungating it
- ARM: dts: sun8i-a23-a33: Move NAND controller device node to sort by address
- spi/topcliff_pch: Fix potential NULL dereference on allocation error
- rtc: cmos: ignore bogus century byte
- media: tw9910: Unregister subdevice with v4l2-async
- ASoC: imx-sgtl5000: put of nodes if finding codec fails
- crypto: brcm - Fix some set-but-not-used warning
- kbuild: mark prepare0 as PHONY to fix external module build
- media: s5p-jpeg: Correct step and max values for V4L2_CID_JPEG_RESTART_INTERVAL
- drm/etnaviv: NULL vs IS_ERR() buf in etnaviv_core_dump()
- memory: tegra: Don't invoke Tegra30+ specific memory timing setup on Tegra20
- RDMA/iw_cxgb4: Fix the unchecked ep dereference
- spi: cadence: Correct initialisation of runtime PM
- arm64: dts: apq8016-sbc: Increase load on l11 for SDCARD
- drm/shmob: Fix return value check in shmob_drm_probe
- RDMA/qedr: Fix out of bounds index check in query pkey
- RDMA/ocrdma: Fix out of bounds index check in query pkey
- drm/fb-helper: generic: Fix setup error path
- drm/etnaviv: fix some off by one bugs
- ARM: dts: r8a7743: Remove generic compatible string from iic3
- drm: Fix error handling in drm_legacy_addctx
- remoteproc: qcom: q6v5-mss: Add missing regulator for MSM8996
- remoteproc: qcom: q6v5-mss: Add missing clocks for MSM8996
- arm64: defconfig: Re-enable bcm2835-thermal driver
- MIPS: BCM63XX: drop unused and broken DSP platform device
- clk: dove: fix refcount leak in dove_clk_init()
- clk: mv98dx3236: fix refcount leak in mv98dx3236_clk_init()
- clk: armada-xp: fix refcount leak in axp_clk_init()
- clk: kirkwood: fix refcount leak in kirkwood_clk_init()
- clk: armada-370: fix refcount leak in a370_clk_init()
- clk: vf610: fix refcount leak in vf610_clocks_init()
- clk: imx7d: fix refcount leak in imx7d_clocks_init()
- clk: imx6sx: fix refcount leak in imx6sx_clocks_init()
- clk: imx6q: fix refcount leak in imx6q_clocks_init()
- clk: samsung: exynos4: fix refcount leak in exynos4_get_xom()
- clk: socfpga: fix refcount leak
- clk: ti: fix refcount leak in ti_dt_clocks_register()
- clk: qoriq: fix refcount leak in clockgen_init()
- clk: highbank: fix refcount leak in hb_clk_init()
- Input: nomadik-ske-keypad - fix a loop timeout test
- pinctrl: sh-pfc: sh7734: Remove bogus IPSR10 value
- pinctrl: sh-pfc: sh7269: Add missing PCIOR0 field
- pinctrl: sh-pfc: r8a77995: Remove bogus SEL_PWM[0-3]_3 configurations
- pinctrl: sh-pfc: sh7734: Add missing IPSR11 field
- pinctrl: sh-pfc: r8a77980: Add missing MOD_SEL0 field
- pinctrl: sh-pfc: r8a77970: Add missing MOD_SEL0 field
- pinctrl: sh-pfc: r8a7794: Remove bogus IPSR9 field
- pinctrl: sh-pfc: sh73a0: Add missing TO pin to tpu4_to3 group
- pinctrl: sh-pfc: r8a7791: Remove bogus marks from vin1_b_data18 group
- pinctrl: sh-pfc: r8a7791: Remove bogus ctrl marks from qspi_data4_b group
- pinctrl: sh-pfc: r8a7740: Add missing LCD0 marks to lcd0_data24_1 group
- pinctrl: sh-pfc: r8a7740: Add missing REF125CK pin to gether_gmii group
- switchtec: Remove immediate status check after submitting MRPC command
- staging: bcm2835-camera: fix module autoloading
- staging: bcm2835-camera: Abort probe if there is no camera
- mailbox: ti-msgmgr: Off by one in ti_msgmgr_of_xlate()
- IB/rxe: Fix incorrect cache cleanup in error flow
- OPP: Fix missing debugfs supply directory for OPPs
- IB/hfi1: Correctly process FECN and BECN in packets
- net: phy: Fix not to call phy_resume() if PHY is not attached
- arm64: dts: renesas: r8a7795-es1: Add missing power domains to IPMMU nodes
- arm64: dts: meson-gx: Add hdmi_5v regulator as hdmi tx supply
- drm/dp_mst: Skip validating ports during destruction, just ref
- drm: rcar-du: Fix vblank initialization
- drm: rcar-du: Fix the return value in case of error in 'rcar_du_crtc_set_crc_source()'
- bus: ti-sysc: Add mcasp optional clocks flag
- pinctrl: meson-gxl: remove invalid GPIOX tsin_a pins
- ASoC: sun8i-codec: add missing route for ADC
- ARM: dts: bcm283x: Correct mailbox register sizes
- ASoC: wm97xx: fix uninitialized regmap pointer problem
- mlxsw: spectrum: Set minimum shaper on MC TCs
- mlxsw: reg: QEEC: Add minimum shaper fields
- drm/sun4i: hdmi: Fix double flag assignation
- net: socionext: Add dummy PHY register read in phy_write()
- powerpc/kgdb: add kgdb_arch_set/remove_breakpoint()
- rtlwifi: rtl8821ae: replace _rtl8821ae_mrate_idx_to_arfr_id with generic version
- powerpc/pseries/memory-hotplug: Fix return value type of find_aa_index
- pwm: lpss: Release runtime-pm reference from the driver's remove callback
- staging: comedi: ni_mio_common: protect register write overflow
- iwlwifi: nvm: get num of hw addresses from firmware
- ALSA: usb-audio: update quirk for B&W PX to remove microphone
- drm/msm: fix unsigned comparison with less than zero
- mei: replace POLL* with EPOLL* for write queues.
- cfg80211: regulatory: make initialization more robust
- usb: gadget: fsl_udc_core: check allocation return value and cleanup on failure
- usb: dwc3: add EXTCON dependency for qcom
- IB/rxe: replace kvfree with vfree
- mailbox: mediatek: Add check for possible failure of kzalloc
- ASoC: wm9712: fix unused variable warning
- signal/ia64: Use the force_sig(SIGSEGV, ...) in ia64_rt_sigreturn
- signal/ia64: Use the generic force_sigsegv in setup_frame
- PCI: iproc: Remove PAXC slot check to allow VF support
- firmware: coreboot: Let OF core populate platform device
- ARM: qcom_defconfig: Enable MAILBOX
- apparmor: don't try to replace stale label in ptrace access check
- ALSA: hda: fix unused variable warning
- apparmor: Fix network performance issue in aa_label_sk_perm
- iio: fix position relative kernel version
- drm/virtio: fix bounds check in virtio_gpu_cmd_get_capset()
- ARM: dts: at91: nattis: make the SD-card slot work
- ARM: dts: at91: nattis: set the PRLUD and HIPOW signals low
- drm/sti: do not remove the drm_bridge that was never added
- watchdog: sprd: Fix the incorrect pointer getting from driver data
- soc: aspeed: Fix snoop_file_poll()'s return type
- perf map: No need to adjust the long name of modules
- crypto: sun4i-ss - fix big endian issues
- mt7601u: fix bbp version check in mt7601u_wait_bbp_ready
- tipc: fix wrong timeout input for tipc_wait_for_cond()
- tipc: update mon's self addr when node addr generated
- powerpc/archrandom: fix arch_get_random_seed_int()
- powerpc/pseries: Enable support for ibm, drc-info property
- SUNRPC: Fix svcauth_gss_proxy_init()
- mfd: intel-lpss: Add default I2C device properties for Gemini Lake
- i2c: i2c-stm32f7: fix 10-bits check in slave free id search loop
- i2c: stm32f7: rework slave_id allocation
- xfs: Sanity check flags of Q_XQUOTARM call
- Revert "efi: Fix debugobjects warning on 'efi_rts_work'"
- selftest/membarrier: fix build error
- Linux 4.19.98
- hwmon: (pmbus/ibm-cffps) Switch LEDs to blocking brightness call
- regulator: ab8500: Remove SYSCLKREQ from enum ab8505_regulator_id
- clk: sprd: Use IS_ERR() to validate the return value of syscon_regmap_lookup_by_phandle()
- perf probe: Fix wrong address verification
- scsi: core: scsi_trace: Use get_unaligned_be*()
- scsi: qla2xxx: fix rports not being mark as lost in sync fabric scan
- scsi: qla2xxx: Fix qla2x00_request_irqs() for MSI
- scsi: target: core: Fix a pr_debug() argument
- scsi: bnx2i: fix potential use after free
- scsi: qla4xxx: fix double free bug
- scsi: esas2r: unlock on error in esas2r_nvram_read_direct()
- reiserfs: fix handling of -EOPNOTSUPP in reiserfs_for_each_xattr
- drm/nouveau/mmu: qualify vmm during dtor
- drm/nouveau/bar/gf100: ensure BAR is mapped
- drm/nouveau/bar/nv50: check bar1 vmm return value
- mtd: devices: fix mchp23k256 read and write
- Revert "arm64: dts: juno: add dma-ranges property"
- arm64: dts: marvell: Fix CP110 NAND controller node multi-line comment alignment
- tick/sched: Annotate lockless access to last_jiffies_update
- cfg80211: check for set_wiphy_params
- arm64: dts: meson-gxl-s905x-khadas-vim: fix gpio-keys-polled node
- cw1200: Fix a signedness bug in cw1200_load_firmware()
- irqchip: Place CONFIG_SIFIVE_PLIC into the menu
- tcp: refine rule to allow EPOLLOUT generation under mem pressure
- xen/blkfront: Adjust indentation in xlvbd_alloc_gendisk
- mlxsw: spectrum_qdisc: Include MC TCs in Qdisc counters
- mlxsw: spectrum: Wipe xstats.backlog of down ports
- sh_eth: check sh_eth_cpu_data::dual_port when dumping registers
- tcp: fix marked lost packets not being retransmitted
- r8152: add missing endpoint sanity check
- ptp: free ptp device pin descriptors properly
- net/wan/fsl_ucc_hdlc: fix out of bounds write on array utdm_info
- net: usb: lan78xx: limit size of local TSO packets
- net: hns: fix soft lockup when there is not enough memory
- net: dsa: tag_qca: fix doubled Tx statistics
- hv_netvsc: Fix memory leak when removing rndis device
- macvlan: use skb_reset_mac_header() in macvlan_queue_xmit()
- batman-adv: Fix DAT candidate selection on little endian systems
- NFC: pn533: fix bulk-message timeout
- netfilter: nf_tables: fix flowtable list del corruption
- netfilter: nf_tables: store transaction list locally while requesting module
- netfilter: nf_tables: remove WARN and add NLA_STRING upper limits
- netfilter: nft_tunnel: fix null-attribute check
- netfilter: arp_tables: init netns pointer in xt_tgdtor_param struct
- netfilter: fix a use-after-free in mtype_destroy()
- cfg80211: fix page refcount issue in A-MSDU decap
- cfg80211: fix memory leak in cfg80211_cqm_rssi_update
- cfg80211: fix deadlocks in autodisconnect work
- bpf: Fix incorrect verifier simulation of ARSH under ALU32
- arm64: dts: agilex/stratix10: fix pmu interrupt numbers
- mm/huge_memory.c: thp: fix conflict of above-47bit hint address and PMD alignment
- mm/huge_memory.c: make __thp_get_unmapped_area static
- net: stmmac: Enable 16KB buffer size
- net: stmmac: 16KB buffer must be 16 byte aligned
- ARM: dts: imx7: Fix Toradex Colibri iMX7S 256MB NAND flash support
- ARM: dts: imx6q-icore-mipi: Use 1.5 version of i.Core MX6DL
- ARM: dts: imx6qdl: Add Engicam i.Core 1.5 MX6
- mm/page-writeback.c: avoid potential division by zero in wb_min_max_ratio()
- btrfs: fix memory leak in qgroup accounting
- btrfs: do not delete mismatched root refs
- btrfs: fix invalid removal of root ref
- btrfs: rework arguments of btrfs_unlink_subvol
- mm: memcg/slab: call flush_memcg_workqueue() only if memcg workqueue is valid
- mm/shmem.c: thp, shmem: fix conflict of above-47bit hint address and PMD alignment
- perf report: Fix incorrectly added dimensions as switch perf data file
- perf hists: Fix variable name's inconsistency in hists__for_each() macro
- x86/resctrl: Fix potential memory leak
- drm/i915: Add missing include file <linux/math64.h>
- x86/efistub: Disable paging at mixed mode entry
- x86/CPU/AMD: Ensure clearing of SME/SEV features is maintained
- x86/resctrl: Fix an imbalance in domain_remove_cpu()
- usb: core: hub: Improved device recognition on remote wakeup
- ptrace: reintroduce usage of subjective credentials in ptrace_has_cap()
- LSM: generalize flag passing to security_capable
- ARM: dts: am571x-idk: Fix gpios property to have the correct gpio number
- block: fix an integer overflow in logical block size
- Fix built-in early-load Intel microcode alignment
- arm64: dts: allwinner: a64: olinuxino: Fix SDIO supply regulator
- ALSA: usb-audio: fix sync-ep altsetting sanity check
- ALSA: seq: Fix racy access for queue timer in proc read
- ALSA: dice: fix fallback from protocol extension into limited functionality
- ARM: dts: imx6q-dhcom: Fix SGTL5000 VDDIO regulator connection
- ASoC: msm8916-wcd-analog: Fix MIC BIAS Internal1
- ASoC: msm8916-wcd-analog: Fix selected events for MIC BIAS External1
- scsi: mptfusion: Fix double fetch bug in ioctl
- scsi: fnic: fix invalid stack access
- USB: serial: quatech2: handle unbound ports
- USB: serial: keyspan: handle unbound ports
- USB: serial: io_edgeport: add missing active-port sanity check
- USB: serial: io_edgeport: handle unbound ports on URB completion
- USB: serial: ch341: handle unbound port at reset_resume
- USB: serial: suppress driver bind attributes
- USB: serial: option: add support for Quectel RM500Q in QDL mode
- USB: serial: opticon: fix control-message timeouts
- USB: serial: option: Add support for Quectel RM500Q
- USB: serial: simple: Add Motorola Solutions TETRA MTP3xxx and MTP85xx
- iio: buffer: align the size of scan bytes to size of the largest element
- ASoC: msm8916-wcd-digital: Reset RX interpolation path after use
- clk: Don't try to enable critical clocks if prepare failed
- ARM: dts: imx6q-dhcom: fix rtc compatible
- dt-bindings: reset: meson8b: fix duplicate reset IDs
- clk: qcom: gcc-sdm845: Add missing flag to votable GDSCs
- ARM: dts: meson8: fix the size of the PMU registers
- membarrier: Fix RCU locking bug caused by faulty merge
- sched/membarrier: Return -ENOMEM to userspace on memory allocation failure
- sched/membarrier: Skip IPIs when mm->mm_users == 1
- selftests, sched/membarrier: Add multi-threaded test
- sched/membarrier: Fix p->mm->membarrier_state racy load
- sched: Clean up active_mm reference counting
- sched/membarrier: Remove redundant check
- PCI: add a member in 'struct pci_bus' to record the original 'pci_ops'
- KVM: tools/kvm_stat: Fix kvm_exit filter name
- KVM: arm/arm64: use esr_ec as trace field of kvm_exit tracepoint
- net: fix bug and change version to 1.9.33.0
- net: hns3: cae clear warnings
- drivers : sysctl remove rcu_lock
- RDMA/hns:remove useless header in cmd
- hac: sec: add initial configuration in sec_engine_init
- Linux 4.19.97
- ocfs2: call journal flush to mark journal as empty after journal recovery when mount
- hexagon: work around compiler crash
- hexagon: parenthesize registers in asm predicates
- ioat: ioat_alloc_ring() failure handling.
- dmaengine: k3dma: Avoid null pointer traversal
- drm/arm/mali: make malidp_mw_connector_helper_funcs static
- MIPS: Prevent link failure with kcov instrumentation
- mips: cacheinfo: report shared CPU map
- rseq/selftests: Turn off timeout setting
- selftests: firmware: Fix it to do root uid check and skip
- scsi: libcxgbi: fix NULL pointer dereference in cxgbi_device_destroy()
- gpio: mpc8xxx: Add platform device to gpiochip->parent
- rtc: brcmstb-waketimer: add missed clk_disable_unprepare
- rtc: msm6242: Fix reading of 10-hour digit
- f2fs: fix potential overflow
- rtlwifi: Remove unnecessary NULL check in rtl_regd_init
- spi: atmel: fix handling of cs_change set on non-last xfer
- mtd: spi-nor: fix silent truncation in spi_nor_read_raw()
- mtd: spi-nor: fix silent truncation in spi_nor_read()
- iommu/mediatek: Correct the flush_iotlb_all callback
- media: exynos4-is: Fix recursive locking in isp_video_release()
- media: v4l: cadence: Fix how unsued lanes are handled in 'csi2rx_start()'
- media: rcar-vin: Fix incorrect return statement in rvin_try_format()
- media: ov6650: Fix .get_fmt() V4L2_SUBDEV_FORMAT_TRY support
- media: ov6650: Fix some format attributes not under control
- media: ov6650: Fix incorrect use of JPEG colorspace
- tty: serial: pch_uart: correct usage of dma_unmap_sg
- tty: serial: imx: use the sg count from dma_map_sg
- powerpc/powernv: Disable native PCIe port management
- PCI/PTM: Remove spurious "d" from granularity message
- PCI: dwc: Fix find_next_bit() usage
- af_unix: add compat_ioctl support
- arm64: dts: apq8096-db820c: Increase load on l21 for SDCARD
- scsi: sd: enable compat ioctls for sed-opal
- pinctrl: lewisburg: Update pin list according to v1.1v6
- pinctl: ti: iodelay: fix error checking on pinctrl_count_index_with_args call
- clk: samsung: exynos5420: Preserve CPU clocks configuration during suspend/resume
- mei: fix modalias documentation
- iio: imu: adis16480: assign bias value only if operation succeeded
- NFSv4.x: Drop the slot if nfs4_delegreturn_prepare waits for layoutreturn
- NFSv2: Fix a typo in encode_sattr()
- crypto: virtio - implement missing support for output IVs
- xprtrdma: Fix completion wait during device removal
- platform/x86: GPD pocket fan: Use default values when wrong modparams are given
- platform/x86: asus-wmi: Fix keyboard brightness cannot be set to 0
- scsi: sd: Clear sdkp->protection_type if disk is reformatted without PI
- scsi: enclosure: Fix stale device oops with hot replug
- RDMA/srpt: Report the SCSI residual to the initiator
- RDMA/mlx5: Return proper error value
- btrfs: simplify inode locking for RWF_NOWAIT
- drm/ttm: fix incrementing the page pointer for huge pages
- drm/ttm: fix start page for huge page check in ttm_put_pages()
- afs: Fix missing cell comparison in afs_test_super()
- cifs: Adjust indentation in smb2_open_file
- s390/qeth: Fix vnicc_is_in_use if rx_bcast not set
- s390/qeth: fix false reporting of VNIC CHAR config failure
- hsr: reset network header when supervision frame is created
- gpio: Fix error message on out-of-range GPIO in lookup table
- iommu: Remove device link to group on failure
- gpio: zynq: Fix for bug in zynq_gpio_restore_context API
- mtd: onenand: omap2: Pass correct flags for prep_dma_memcpy
- ASoC: stm32: spdifrx: fix race condition in irq handler
- ASoC: stm32: spdifrx: fix inconsistent lock state
- ASoC: soc-core: Set dpcm_playback / dpcm_capture
- RDMA/bnxt_re: Fix Send Work Entry state check while polling completions
- RDMA/bnxt_re: Avoid freeing MR resources if dereg fails
- rtc: mt6397: fix alarm register overwrite
- drm/i915: Fix use-after-free when destroying GEM context
- fs/select: avoid clang stack usage warning
- ethtool: reduce stack usage with clang
- HID: hidraw, uhid: Always report EPOLLOUT
- HID: hidraw: Fix returning EPOLLOUT from hidraw_poll
- hidraw: Return EPOLLOUT from hidraw_poll
- iommu/arm-smmu: Mark expected switch fall-through
- PCI/AER: increments pci bus reference count in aer-inject process
- irqchip/gic-v3-its: its support herbination
- PM / hibernate: introduce system_in_hibernation
- efi/memreserve: Register reservations as 'reserved' in /proc/iomem
- net: hns3: cae security review
- net: hns3: cae io_param definition updated
- config: enable CONFIG_SMMU_BYPASS_DEV by default
- compat_ioctl: handle SIOCOUTQNSD
- openeuler_defconfig: CONFIG_SMMU_BYPASS_DEV=y
- iommu: smmu-v3 support Virtualization feature when 3408iMR/3416iMRraid card exist
- MPAM / ACPI: Refactoring MPAM init process and set MPAM ACPI as entrance
- ACPI 6.x: Add definitions for MPAM table
- ACPI / PPTT: cacheinfo: Label caches based on fw_token
- ACPI / PPTT: Filthy hack to find _a_ backwards reference in the PPTT [ROTTEN]
- ACPI / PPTT: Add helper to validate cache nodes from an offset [dead]
- ACPI / processor: Add helper to convert acpi_id to a phys_cpuid
- f2fs: support swap file w/ DIO
- Linux 4.19.96
- drm/i915/gen9: Clear residual context state on context switch
- netfilter: ipset: avoid null deref when IPSET_ATTR_LINENO is present
- netfilter: conntrack: dccp, sctp: handle null timeout argument
- netfilter: arp_tables: init netns pointer in xt_tgchk_param struct
- phy: cpcap-usb: Fix flakey host idling and enumerating of devices
- phy: cpcap-usb: Fix error path when no host driver is loaded
- USB: Fix: Don't skip endpoint descriptors with maxpacket=0
- HID: hiddev: fix mess in hiddev_open()
- tty: always relink the port
- tty: link tty and port before configuring it as console
- serdev: Don't claim unsupported ACPI serial devices
- staging: rtl8188eu: Add device code for TP-Link TL-WN727N v5.21
- staging: comedi: adv_pci1710: fix AI channels 16-31 for PCI-1713
- usb: musb: dma: Correct parameter passed to IRQ handler
- usb: musb: Disable pullup at init
- usb: musb: fix idling for suspend after disconnect interrupt
- USB: serial: option: add ZLP support for 0x1bc7/0x9010
- staging: vt6656: set usb_set_intfdata on driver fail.
- gpiolib: acpi: Add honor_wakeup module-option + quirk mechanism
- gpiolib: acpi: Turn dmi_system_id table into a generic quirk table
- can: can_dropped_invalid_skb(): ensure an initialized headroom in outgoing CAN sk_buffs
- can: mscan: mscan_rx_poll(): fix rx path lockup when returning from polling to irq mode
- can: gs_usb: gs_usb_probe(): use descriptors of current altsetting
- can: kvaser_usb: fix interface sanity check
- drm/dp_mst: correct the shifting in DP_REMOTE_I2C_READ
- drm/fb-helper: Round up bits_per_pixel if possible
- drm/sun4i: tcon: Set RGB DCLK min. divider based on hardware model
- Input: input_event - fix struct padding on sparc64
- Input: add safety guards to input_set_keycode()
- HID: hid-input: clear unmapped usages
- HID: uhid: Fix returning EPOLLOUT from uhid_char_poll
- HID: Fix slab-out-of-bounds read in hid_field_extract
- tracing: Change offset type to s32 in preempt/irq tracepoints
- tracing: Have stack tracer compile when MCOUNT_INSN_SIZE is not defined
- kernel/trace: Fix do not unregister tracepoints when register sched_migrate_task fail
- ALSA: hda/realtek - Add quirk for the bass speaker on Lenovo Yoga X1 7th gen
- ALSA: hda/realtek - Set EAPD control to default for ALC222
- ALSA: hda/realtek - Add new codec supported for ALCS1200A
- ALSA: usb-audio: Apply the sample rate quirk for Bose Companion 5
- usb: chipidea: host: Disable port power only if previously enabled
- i2c: fix bus recovery stop mode timing
- chardev: Avoid potential use-after-free in 'chrdev_open()'
- mac80211: Do not send Layer 2 Update frame before authorization
- cfg80211/mac80211: make ieee80211_send_layer2_update a public function
- KVM: arm/arm64: vgic: Allow more than 256 vcpus for KVM_IRQ_LINE
- KVM: arm/arm64: vgic: Use a single IO device per redistributor
- KVM: arm/arm64: Only probe CPU type and ncsnp info in hypervisor
- kvm: arm/arm64: add irqsave for lpi_cache_lock
- KVM: arm/arm64: vgic-its: Do not execute invalidate MSI-LPI translation cache on movi command
- KVM: arm/arm64: vgic-its: Introduce multiple LPI translation caches
- KVM: arm/arm64: Avoid the unnecessary stage 2 translation faults
- KVM: arm/arm64: Re-create event when setting counter value
- kvm/vgic-its: flush pending LPIs when nuking DT
- irqchip/gic-v3-its: Set VPENDING table as inner-shareable
- irqchip/gic-v3-its: Make vlpi_lock a spinlock
- KVM: Call kvm_arch_vcpu_blocking early into the blocking sequence
- fbcon: fix ypos over boundary issue
- perf, kvm/arm64: perf-kvm-stat to report VM TRAP
- perf, kvm/arm64: Add stat support on arm64
- perf tools arm64: Add support for get_cpuid() function
- KVM: arm/arm64: Adjust entry/exit and trap related tracepoints
- KVM: arm/arm64: Add support for probing Hisi ncsnp capability
- KVM: arm/arm64: Probe Hisi CPU TYPE from ACPI/DTB
- KVM: arm/arm64: vgic-irqfd: Implement kvm_arch_set_irq_inatomic
- KVM: arm/arm64: vgic-its: Check the LPI translation cache on MSI injection
- KVM: arm/arm64: vgic-its: Cache successful MSI->LPI translation
- KVM: arm/arm64: vgic-its: Invalidate MSI-LPI translation cache on vgic teardown
- KVM: arm/arm64: vgic-its: Invalidate MSI-LPI translation cache on ITS disable
- KVM: arm/arm64: vgic-its: Invalidate MSI-LPI translation cache on disabling LPIs
- KVM: arm/arm64: vgic-its: Invalidate MSI-LPI translation cache on specific commands
- KVM: arm/arm64: vgic-its: Add MSI-LPI translation cache invalidation
- KVM: arm/arm64: vgic: Add __vgic_put_lpi_locked primitive
- KVM: arm/arm64: vgic: Add LPI translation cache definition
- KVM: arm/arm64: Initialise host's MPIDRs by reading the actual register
- KVM: arm64: Move pmu hyp code under hyp's Makefile to avoid instrumentation
- arm64: KVM: Fix perf cycle counter support for VHE
- arm64: docs: Document perf event attributes
- arm64: KVM: Avoid isb's by using direct pmxevtyper sysreg
- arm64: KVM: Enable VHE support for :G/:H perf event modifiers
- arm64: KVM: Enable !VHE support for :G/:H perf event modifiers
- arm64: arm_pmu: Add !VHE support for exclude_host/exclude_guest attributes
- arm64: KVM: Add accessors to track guest/host only counters
- arm64: KVM: Encapsulate kvm_cpu_context in kvm_host_data
- arm64: arm_pmu: Remove unnecessary isb instruction
- kvm: arm: Skip stage2 huge mappings for unaligned ipa backed by THP
- KVM: arm/arm64: vgic-v3: Retire pending interrupts on disabling LPIs
- KVM: arm/arm64: Fix handling of stage2 huge mappings
- KVM: arm/arm64: Enforce PTE mappings at stage2 when needed
- arm64: KVM: Always set ICH_HCR_EL2.EN if GICv4 is enabled
- KVM: arm/arm64: Simplify bg_timer programming
- arm/arm64: KVM: Statically configure the host's view of MPIDR
- KVM: arm64: Relax the restriction on using stage2 PUD huge mapping
- arm: KVM: Add missing kvm_stage2_has_pmd() helper
- KVM: arm/arm64: vgic: Make vgic_cpu->ap_list_lock a raw_spinlock
- KVM: arm/arm64: vgic: Make vgic_irq->irq_lock a raw_spinlock
- arm: KVM: Add S2_PMD_{MASK, SIZE} constants
- arm/arm64: KVM: Add ARM_EXCEPTION_IS_TRAP macro
- KVM: arm/arm64: Fix unintended stage 2 PMD mappings
- arm64: KVM: Add trapped system register access tracepoint
- KVM: arm64: Make vcpu const in vcpu_read_sys_reg
- KVM: arm/arm64: Remove arch timer workqueue
- KVM: arm/arm64: Fixup the kvm_exit tracepoint
- KVM: arm/arm64: vgic: Consider priority and active state for pending irq
- KVM: arm64: Clarify explanation of STAGE2_PGTABLE_LEVELS
- KVM: arm64: Add support for creating PUD hugepages at stage 2
- KVM: arm64: Update age handlers to support PUD hugepages
- KVM: arm64: Support handling access faults for PUD hugepages
- KVM: arm64: Support PUD hugepage in stage2_is_exec()
- KVM: arm64: Support dirty page tracking for PUD hugepages
- KVM: arm/arm64: Introduce helpers to manipulate page table entries
- KVM: arm/arm64: Re-factor setting the Stage 2 entry to exec on fault
- KVM: arm/arm64: Share common code in user_mem_abort()
- KVM: arm/arm64: Log PSTATE for unhandled sysregs
- KVM: arm64: Safety check PSTATE when entering guest and handle IL
- kvm: arm64: Allow tuning the physical address size for VM
- kvm: arm64: Limit the minimum number of page table levels
- kvm: arm64: Set a limit on the IPA size
- kvm: arm64: Add 52bit support for PAR to HPFAR conversoin
- vgic: Add support for 52bit guest physical address
- kvm: arm64: Switch to per VM IPA limit
- kvm: arm64: Configure VTCR_EL2.SL0 per VM
- kvm: arm64: Dynamic configuration of VTTBR mask
- kvm: arm64: Make stage2 page table layout dynamic
- kvm: arm64: Prepare for dynamic stage2 page table layout
- kvm: arm/arm64: Prepare for VM specific stage2 translations
- kvm: arm64: Configure VTCR_EL2 per VM
- kvm: arm/arm64: Allow arch specific configurations for VM
- kvm: arm64: Clean up VTCR_EL2 initialisation
- arm64: Add a helper for PARange to physical shift conversion
- kvm: arm64: Add helper for loading the stage2 setting for a VM
- kvm: arm/arm64: Remove spurious WARN_ON
- KVM: arm/arm64: vgic: Replace spin_is_locked() with lockdep
- PCI/AER: Refactor error injection fallbacks
- net/sched: act_mirred: Pull mac prior redir to non mac_header_xmit device
- kernfs: fix potential null pointer dereference
- arm64: fix calling nmi_enter() repeatedly when IPI_CPU_CRASH_STOP
- config: add openeuler_defconfig
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
