#!/bin/sh

/greenhouse/busybox sh /setup_dev.sh /greenhouse/busybox /ghdev
/greenhouse/busybox cp -r /ghtmp/* /tmp
/greenhouse/busybox cp -r /ghetc/* /etc

/greenhouse/ip link add dummy0 type dummy
/greenhouse/ip addr add 192.168.0.50/24 dev dummy0
/greenhouse/ip link set dummy0 up
