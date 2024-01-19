ifneq ($(KERNELRELEASE),)
   obj-m := max_latency.o preempt_proc.o cust_topo.o cust_capacity.o
else

KERNELDIR ?= /lib/modules/$(shell uname -r)/build

PWD := $(shell pwd)

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
endif
