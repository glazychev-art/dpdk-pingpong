# DPDK Ping-Pong

A simple program to evaluate raw DPDK latency.

The client sends a packet to server as a `ping`, then the server returns it back to client as a `pong`. 
The client records such ping-pong round trip time.

`Note` that the following steps have been evaluated on 2 Ubuntu 20.04 virtual machines (KVM) with DPDK 20.11.6.

## Prepare

The following operations are tested on Ubuntu 20.04 with DPDK 20.11.6

### Setup DPDK

```shell
sudo apt-get install make gcc libnuma-dev pkgconf python
make config T=x86_64-native-linuxapp-gcc
make

echo "export RTE_SDK=/root/dpdk-18.05" >> ~/.profile
echo "export RTE_TARGET=build" >> ~/.profile
. ~/.profile

```

### Setup huge memory pages

1. Enable huge memory page by default.

``` shell
vim /etc/default/grub

# Append "default_hugepagesz=1GB hugepagesz=1G hugepages=8" to the end of line GRUB_CMDLINE_LINUX_DEFAULT.

update-grub
```

2. Mount huge tlb by default.

```shell
vim /etc/fstab

# Append "nodev /mnt/huge hugetlbfs defaults 0 0" to the end of file.
```

### Install user space NIC driver
```shell
modprobe uio
cd $RTE_SDK/build/kmod
insmod igb_uio.ko
```

### Bind NIC to userspace driver

```shell
cd $RTE_SDK/usertools
./dpdk-devbind.py -s
./dpdk-devbind.py -b igb_uio $YOUR_NIC
```

## Build

```shell
export RTE_SDK=/path/to/dpdk-20.08/
export RTE_TARGET=build
make
```

The valid parameters are: 
`-p` to specify the id of  which port to use, 0 by default (both sides), 
`-n` to customize how many ping-pong rounds, 100 by default (both sides), 
`-s` to enable server mode (server side),
`-c` to enable client mode (client side),
`-S` to set server MAC address (both sides),
`-C` to set client MAC address (client side),

## Run
1. Make sure that NIC is properly binded to the DPDK-compible driver and huge memory page is configured on both client and server.

2. On the server side
```shell
sudo ./build/pingpong -l 1,2 -- -p 0 -s -n 100 -S 0a:11:22:33:44:55
```

3. On the client side
```shell
sudo ./build/pingpong -l 1,2 -- -p 0 -c -n 200 -C 0a:55:44:33:22:11 -S 0a:11:22:33:44:55
```

`Note` that >= 2 lcores are needed.

The output shoud be like this
```
====== ping-pong statistics =====
tx 200 ping packets
rx 200 pong packets
dropped 0 packets
min rtt: 50 us
max rtt: 15808 us
average rtt: 427 us
=================================
```
Note that this test is run on virtual machines, ignore the numbers.

## Issues

1. The 1st ping-pong round is very slow.
2. Only support directly connectted client and server NICs.
