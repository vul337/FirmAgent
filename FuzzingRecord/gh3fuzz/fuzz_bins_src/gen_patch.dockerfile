# build AFL and install it to /AFLplusplus_release
from jkjh1jkjh1/aflplusplus

run apt-get update

workdir /AFLplusplus

# build aflplusplus once to initialize all the dependencies and apply patches
copy afl-common.c /AFLplusplus/src/afl-common.c
run STATIC=1 make -j distrib

run cd qemu_mode/qemuafl; git fetch --depth=100; git stash; git checkout a120c3feb573d4cade292cdeb7c1f6b1ce109efe
# copy afl_gh.patch /afl_gh.patch
# run cd qemu_mode/qemuafl; git apply /afl_gh.patch

# build afl-qemu-trace for different architectures
# run cd qemu_mode; NO_CHECKOUT=1 CPU_TARGET=x86_64 STATIC=1 ./build_qemu_support.sh
# run mv afl-qemu-trace afl-qemu-trace-x86_64
# run cd qemu_mode; NO_CHECKOUT=1 CPU_TARGET=i386 STATIC=1 ./build_qemu_support.sh
# run mv afl-qemu-trace afl-qemu-trace-i386
# run cd qemu_mode; NO_CHECKOUT=1 CPU_TARGET=mips STATIC=1 ./build_qemu_support.sh
# run mv afl-qemu-trace afl-qemu-trace-mips
# run cd qemu_mode; NO_CHECKOUT=1 CPU_TARGET=mipsel STATIC=1 ./build_qemu_support.sh
# run mv afl-qemu-trace afl-qemu-trace-mipsel
# run cd qemu_mode; NO_CHECKOUT=1 CPU_TARGET=arm STATIC=1 ./build_qemu_support.sh
# run mv afl-qemu-trace afl-qemu-trace-arm
# run cd qemu_mode; NO_CHECKOUT=1 CPU_TARGET=armeb STATIC=1 ./build_qemu_support.sh
# run mv afl-qemu-trace afl-qemu-trace-armeb
# run cd qemu_mode; NO_CHECKOUT=1 CPU_TARGET=aarch64 STATIC=1 ./build_qemu_support.sh
# run mv afl-qemu-trace afl-qemu-trace-aarch64
# run mkdir -p /AFLplusplus_release; PREFIX=/AFLplusplus_release make install
# 
# # copy in utils
# copy util_bins /AFLplusplus_release/utils
# copy ghup_bins /AFLplusplus_release/ghup_bins

## build busybox for different architectures
#run mkdir -p /AFLplusplus_release/busybox
#run git clone --branch 1_35_stable --depth 1 https://github.com/mirror/busybox /busybox
#workdir /busybox
#run make defconfig
#run make CFLAGS="-static" CC="gcc -m32" -j16 busybox_unstripped && mv busybox_unstripped /AFLplusplus_release/busybox/busybox_i386
#run make CFLAGS="-static" CC="gcc" -j16 busybox_unstripped && mv busybox_unstripped /AFLplusplus_release/busybox/busybox_x86_64
#run apt-get install -y gcc-mips-linux-gnu gcc-mipsel-linux-gnu gcc-arm-linux-gnueabi gcc-aarch64-linux-gnu
#run make LDFLAGS="-static" CC="mips-linux-gnu-gcc" -j16 busybox_unstripped && mv busybox_unstripped /AFLplusplus_release/busybox/busybox_mips
#run make CFLAGS="-static" CC="mipsel-linux-gnu-gcc" -j16 busybox_unstripped && mv busybox_unstripped /AFLplusplus_release/busybox/busybox_mipsel
#run make CFLAGS="-static" CC="arm-linux-gnueabi-gcc" -j16 busybox_unstripped && mv busybox_unstripped /AFLplusplus_release/busybox/busybox_arm
#run make CFLAGS="-static" CC="aarch64-linux-gnu-gcc" -j16 busybox_unstripped && mv busybox_unstripped /AFLplusplus_release/busybox/busybox_aarch64

cmd bash
