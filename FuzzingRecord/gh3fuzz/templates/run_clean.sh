#!/bin/sh

/run_setup.sh

/qemu-mips-static -hackbind -hackproc -hacksysinfo -execve "/qemu-mips-static -hackbind -hackproc -hacksysinfo " -E LD_PRELOAD="libnvram-faker.so" /bin/sh /run_background.sh > /GREENHOUSE_BGLOG 2>&1


/qemu-mips-static -hackbind -hackproc -hacksysinfo -execve "/qemu-mips-static -hackbind -hackproc -hacksysinfo " -E LD_PRELOAD="libnvram-faker.so" /bin/sh qemu_run.sh
while true; do /greenhouse/busybox sleep 100000; done