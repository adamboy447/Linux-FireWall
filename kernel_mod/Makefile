MODULE_NAME := myfw
KDIR ?= /lib/modules/$(shell uname -r)/build

obj-m := $(MODULE_NAME).o
$(MODULE_NAME)-objs := mod_main.o hooks.o pkt.o rules.o conn.o nat.o log.o netlink.o
ccflags-y := -I$(src)/../include -Wall

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean

.PHONY: all clean
