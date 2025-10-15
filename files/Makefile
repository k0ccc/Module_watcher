# Standart makefile for kernel module.
obj-m += watchpoint-mod.o

PWD := $(CURDIR)

all:
	$(MAKE) -C $(KERNEL_SRC) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNEL_SRC) M=$(PWD) clean
