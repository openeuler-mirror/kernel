%global Arch $(echo %{_host_cpu} | sed -e s/i.86/x86/ -e s/x86_64/x86/ -e s/aarch64.*/arm64/)

%global KernelVer %{version}-%{release}.raspi.%{_target_cpu}

%global hulkrelease 1.0.0

%global debug_package %{nil}

Name:	 raspberrypi-kernel
Version: 6.1.19
Release: %{hulkrelease}.2
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
    echo "warning: something may go wrong when starting this device next time after uninstalling raspberrypi-kernel."
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
    if [ -f /boot/vmlinuz-$version_old ] && [ -d /boot/dtb-$version_old ] && [ -d /lib/modules/$version_old ]; then
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
                echo "warning: files in /boot/dtb-$version_old/*.dtb missing when resetting raspberrypi-kernel as $version_old, something may go wrong when starting this device next time."
            fi
        else
            echo "warning: files in /boot/dtb-$version_old/overlays missing when resetting raspberrypi-kernel as $version_old, something may go wrong when starting this device next time."
        fi
    else
        echo "warning: files missing when resetting raspberrypi-kernel as $version_old, something may go wrong when starting this device next time."
    fi
fi

%posttrans
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
* Tue Mar 21 2023 Yafen Fang <yafen@iscas.ac.cn> - 6.1.19-1.0.0.2
- update kernel version to upstream v6.1.19

* Fri Mar 03 2023 Yafen Fang <yafen@iscas.ac.cn> - 6.1.14-1.0.0.1
- package init based on upstream v6.1.14
