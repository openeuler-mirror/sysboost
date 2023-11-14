KDIR ?= /lib/modules/$(shell uname -r)/build

obj-m := sysboost_loader.o
sysboost_loader-objs := main.o loader_device.o netlink_kernel.o

# 5.10内核和6.4内核binfmt_elf.c差异较大, 因此拆分不同文件
ifeq ($(findstring 5.10, $(KDIR)), 5.10)
sysboost_loader-objs += binfmt_rto.o rto_populate.o
else
sysboost_loader-objs += binfmt_rto_604.o rto_populate_604.o
endif

PWD := $(shell pwd)

modules:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

install:
	rmmod sysboost_loader || true
	insmod sysboost_loader.ko use_rto=1 debug=1

.PHONEY: clean

clean:
	rm -f *.o
	rm -f *.ko
	rm -f .*.cmd
	rm -rf .tmp_versions
	rm -f *.mod.c
	rm -f Module.symvers
	rm -f modules.order
	rm -f *.mod
