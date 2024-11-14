#!/bin/bash
# Script outline to install and build kernel.
# Author: Siddhant Jajoo.

set -e
set -u

OUTDIR=/tmp/aeld
KERNEL_REPO=git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git
KERNEL_VERSION=v5.15.163
BUSYBOX_VERSION=1_33_1
FINDER_APP_DIR=$(realpath $(dirname $0))
ARCH=arm64
CROSS_COMPILE=aarch64-none-linux-gnu-
SYSROOT=$(aarch64-none-linux-gnu-gcc -print-sysroot)

if [ $# -lt 1 ]
then
	echo "Using default directory ${OUTDIR} for output"
else
	OUTDIR=$1
	echo "Using passed directory ${OUTDIR} for output"
fi

mkdir -p ${OUTDIR}

cd "$OUTDIR"
if [ ! -d "${OUTDIR}/linux-stable" ]; then
    #Clone only if the repository does not exist.
	echo "CLONING GIT LINUX STABLE VERSION ${KERNEL_VERSION} IN ${OUTDIR}"
	git clone ${KERNEL_REPO} --depth 1 --single-branch --branch ${KERNEL_VERSION}
fi
if [ ! -e ${OUTDIR}/linux-stable/arch/${ARCH}/boot/Image ]; then
    cd linux-stable
    echo "Checking out version ${KERNEL_VERSION}"
    git checkout ${KERNEL_VERSION}

    # TODO: Add your kernel build steps here

    # clean
    make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} mrproper

    # defconfig
    make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} defconfig

    # vmlinux
    make -j4 ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} all

    # modules
    make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} modules

    # devicetree
    make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} dtbs

fi

echo "Adding the Image in outdir"
cp ${OUTDIR}/linux-stable/arch/${ARCH}/boot/Image ${OUTDIR}

echo "Creating the staging directory for the root filesystem"
cd "$OUTDIR"
if [ -d "${OUTDIR}/rootfs" ]
then
	echo "Deleting rootfs directory at ${OUTDIR}/rootfs and starting over"
    sudo rm  -rf ${OUTDIR}/rootfs
fi

# TODO: Create necessary base directories
ROOT_FS=${OUTDIR}/rootfs
mkdir -p ${ROOT_FS}
cd ${ROOT_FS}
mkdir -p bin dev etc home lib lib64 proc sbin sys tmp usr var
mkdir -p usr/bin usr/lib usr/sbin
mkdir -p var/log

cd "$OUTDIR"
if [ ! -d "${OUTDIR}/busybox" ]
then
git clone git://busybox.net/busybox.git
    cd busybox
    git checkout ${BUSYBOX_VERSION}
    # TODO:  Configure busybox
    make distclean
    make defconfig

else
    cd busybox
fi

# TODO: Make and install busybox
make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE}
make CONFIG_PREFIX=${ROOT_FS} ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} install

echo "Library dependencies"
#${CROSS_COMPILE}readelf -a bin/busybox | grep "program interpreter"
#${CROSS_COMPILE}readelf -a bin/busybox | grep "Shared library"

# TODO: Add library dependencies to rootfs
# Need to copy the following from sysroot:
#   - aarch64-none-linux-gnu-readelf -a bin/busybox | grep "program interpreter"
#       -> /lib/ld-linux-aarch64.so.1
#       -> Copy to /lib
#   - aarch64-none-linux-gnu-readelf -a bin/busybox | grep "Shared library"
#       -> libm.so.6
#       -> libresolv.so.2
#       -> libc.so.6
#       -> Copy to /lib64
cp ${SYSROOT}/lib/ld-linux-aarch64.so.1 ${ROOT_FS}/lib/ld-linux-aarch64.so.1
cp ${SYSROOT}/lib64/libm.so.6 ${ROOT_FS}/lib64/libm.so.6
cp ${SYSROOT}/lib64/libresolv.so.2 ${ROOT_FS}/lib64/libresolv.so.2
cp ${SYSROOT}/lib64/libc.so.6 ${ROOT_FS}/lib64/libc.so.6

# TODO: Make device nodes
# - Null device
#   -> major 1 minor 3
sudo mknod -m 666 ${ROOT_FS}/dev/null c 1 3

# - Console device
#   -> major 5 minor 1
sudo mknod -m 600 ${ROOT_FS}/dev/console c 5 1

# TODO: Clean and build the writer utility
cd ${FINDER_APP_DIR}
make clean
make CROSS_COMPILE=aarch64-none-linux-gnu-
cp writer ${ROOT_FS}/home

# TODO: Copy the finder related scripts and executables to the /home directory
# on the target rootfs
cp finder.sh finder-test.sh ${ROOT_FS}/home
mkdir -p ${ROOT_FS}/home/conf
cp conf/username.txt conf/assignment.txt ${ROOT_FS}/home/conf
sed -i 's/..\/conf\/assignment.txt/conf\/assignment.txt/g' ${ROOT_FS}/home/finder-test.sh
cp autorun-qemu.sh ${ROOT_FS}/home

# TODO: Chown the root directory
sudo chown -R root:root ${ROOT_FS}

# TODO: Create initramfs.cpio.gz
cd ${ROOT_FS}
find . | cpio -H newc -ov --owner root:root > ${OUTDIR}/initramfs.cpio
gzip -f ${OUTDIR}/initramfs.cpio
