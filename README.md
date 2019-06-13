# end.ac
SRv6 function of multi-tenant proxy by SRH caching over AF_XDP

<img src="img/linapen.png" width="480">
*Thanks to pero-san*

## Usage
See -h option for latest information.
```
$ sudo ./main.out -h

Usage:
  -c [cpulist] : CPU cores to use
  -p [ifnamelist] : Interfaces to use
  -n [n] : NUMA node (default=0)
  -m [n] : MTU length (default=1522)
  -b [n] : Number of packet buffer per port(default=8192)
  -d : Force XDP Driver mode
  -z : Force XDP Zero copy mode
  -h : Show this help
  -s [v6in-ifidx],[v4out-ifidx],[v4in-ifidx],[v6out-ifidx],[v4out-dmac],[v6out-dmac],[sid],[sidlen],[argoffset]
  -s 0,1,2,3,aa:aa:aa:aa:aa:aa,bb:bb:bb:bb:bb:bb,fd00::,64,80
```

### An example
```
$ sudo ./main.out -c 0,1,2,3 -p eth0,eth1,eth2,eth3 -s 0,2,3,1,aa:aa:aa:aa:aa:aa,bb:bb:bb:bb:bb,fd00:0:0:1::,64,120 -s 1,3,2,0,cc:cc:cc:cc:cc:cc,dd:dd:dd:dd:dd:dd,fd00:0:0:2::,64,120
```

## Build and Install
Kernel >= 4.19 required. Tested on Ubuntu 18.04.
```
$ wget -c http://kernel.ubuntu.com/~kernel-ppa/mainline/v4.19/linux-headers-4.19.0-041900_4.19.0-041900.201810221809_all.deb
$ wget -c http://kernel.ubuntu.com/~kernel-ppa/mainline/v4.19/linux-headers-4.19.0-041900-generic_4.19.0-041900.201810221809_amd64.deb
$ wget -c http://kernel.ubuntu.com/~kernel-ppa/mainline/v4.19/linux-image-unsigned-4.19.0-041900-generic_4.19.0-041900.201810221809_amd64.deb
$ wget -c http://kernel.ubuntu.com/~kernel-ppa/mainline/v4.19/linux-modules-4.19.0-041900-generic_4.19.0-041900.201810221809_amd64.deb
$ sudo dpkg -i *.deb
```

Build & Install libbpf
```
$ sudo apt-get install build-essential
$ wget https://cdn.kernel.org/pub/linux/kernel/v4.x/linux-4.19.tar.xz
$ tar -xf linux-4.19.tar.xz
$ sudo cp ~/linux-4.19/include/uapi/linux/if_xdp.h /usr/include/linux/if_xdp.h
$ sudo cp ~/linux-4.19/include/uapi/linux/if_link.h /usr/include/linux/if_link.h
$ sudo cp ~/linux-4.19/include/uapi/linux/bpf.h  /usr/include/linux/bpf.h

$ sudo apt-get install libelf-dev
$ cd ~/linux-4.19/tools/lib/bpf
$ make
$ sudo make install
$ sudo make install_headers
$ sudo ln -sf /usr/local/lib64/libbpf.a /lib/libbpf.a
$ sudo ln -sf /usr/local/lib64/libbpf.so /lib/libbpf.so
```

Build bpf binary
```
$ cd end.ac/
$ clang -O2 -Wall -target bpf -c bpf.c -o bpf.o
```

Build main binary
```
$ cd end.ac/
$ make
```

If you met this error:
```
/usr/include/linux/types.h:4:10: fatal error: 'asm/types.h' file not found
```

Do following:
```
$ sudo ln -s /usr/include/x86_64-linux-gnu/asm/ /usr/include/asm
```
