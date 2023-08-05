KDIR ?= /lib/modules/$(shell uname -r)/build

obj-m := sysboost_loader.o
sysboost_loader-objs := main.o binfmt_rto.o loader_device.o
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
