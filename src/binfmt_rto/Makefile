KDIR ?= /lib/modules/$(shell uname -r)/build

obj-m := binfmt_rto.o
PWD := $(shell pwd)

modules:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

install:
	rmmod binfmt_rto || true
	insmod binfmt_rto.ko use_rto=1 debug=1

.PHONEY: clean

clean:
	rm -f *.o
	rm -f *.ko
	rm -f .*.cmd
	rm -rf .tmp_versions
	rm -f *.mod.c
	rm -f Module.symvers
	rm -f modules.order
