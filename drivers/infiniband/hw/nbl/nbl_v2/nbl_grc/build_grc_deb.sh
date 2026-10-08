#!/bin/bash
# SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB
set -e

# globals
KERNEL_RELEASE="${1:-5.14.21-2-bootis}"
TAG_VERSION=$(git describe --tags --abbrev=0 HEAD)
PACKAGE_VERSION=${TAG_VERSION:6}
echo "version:$PACKAGE_VERSION"
: ${PACKAGE_ARCH:="x86_64"}

while getopts "a:v:k:" opt; do
    case $opt in
        a)
            PACKAGE_ARCH=$OPTARG
            ;;
        v)
            PACKAGE_VERSION=$OPTARG
            ;;
        k)
            KERNEL_RELEASE=$OPTARG
            ;;
        ?)
            echo "unkonw opts"
            ;;
    esac
done

echo "architecture: $PACKAGE_ARCH"
echo "version: $PACKAGE_VERSION"
echo "kernel reelase: $KERNEL_RELEASE"

# create floders corresponding to the debian package
mkdir -p debpkgs/DEBIAN
mkdir -p debpkgs/lib/modules/${KERNEL_RELEASE}/extra

# compile *.ko file
if [ $PACKAGE_ARCH = "x86_64" ]; then
    make snic
    ARCH_NAME=amd64
else
    echo "the architecture of $ARCH is not support"
    rm -rf debpkgs
    exit 1
fi

# copy the *.ko file to target folder
cp *.ko debpkgs/lib/modules/${KERNEL_RELEASE}/extra

# generate control, postinst, postrm files
cat > debpkgs/DEBIAN/control << EOF
Package: nbl-rdma-grc-driver
Version: $PACKAGE_VERSION
Architecture: $ARCH_NAME
Depends: linux-image-${KERNEL_RELEASE}
Maintainer:  Nebula matrix Louis.li <louis.li@nebula-matrix.com>
Homepage:http://gerrit.dpu.tech/nmx-rdma-kernel
Description: nbl rdma grc driver
EOF

cat > debpkgs/DEBIAN/postinst << EOF
depmod ${KERNEL_RELEASE}
if (lsmod | grep -q nbl_grc); then
    modprobe -r nbl_grc > /dev/null 2>&1
fi
modprobe nbl_grc > /dev/null 2>&1
EOF

cat > debpkgs/DEBIAN/postrm << EOF
modprobe -r nbl_grc > /dev/null 2>&1
depmod ${KERNEL_RELEASE}
EOF

# grant executable permissions and package
chmod +x debpkgs/DEBIAN/post*
ls -l debpkgs
dpkg-deb -b debpkgs .

if [ $PACKAGE_ARCH = "x86_64" ]; then
    make clean
fi

rm -rf debpkgs
