# myfw - top level build
#
#   make                 build the kernel module and the uapp CLI
#   sudo make load       insert the module (pass module options with OPTS="udp_timeout=30")
#   sudo make unload     remove the module
#   sudo make install    install uapp to /usr/local/sbin and the module for modprobe
#   make test            build everything and run the full test suite in a QEMU VM

KDIR   ?= /lib/modules/$(shell uname -r)/build
KVER   ?= $(shell uname -r)
PREFIX ?= /usr/local
OPTS   ?=

all: module uapp

module:
	$(MAKE) -C kernel_mod KDIR=$(KDIR)

uapp:
	$(MAKE) -C cmd

load: all
	insmod kernel_mod/myfw.ko $(OPTS)

unload:
	rmmod myfw

install: all
	install -D -m 0755 cmd/uapp $(DESTDIR)$(PREFIX)/sbin/uapp
	install -D -m 0644 kernel_mod/myfw.ko $(DESTDIR)/lib/modules/$(KVER)/extra/myfw.ko
	depmod -a $(KVER)

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/sbin/uapp $(DESTDIR)/lib/modules/$(KVER)/extra/myfw.ko
	depmod -a $(KVER)

test:
	./test/vm/run.sh

clean:
	$(MAKE) -C kernel_mod KDIR=$(KDIR) clean
	$(MAKE) -C cmd clean
	rm -f test/fwtest

.PHONY: all module uapp load unload install uninstall test clean
