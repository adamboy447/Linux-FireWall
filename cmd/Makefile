CC      ?= gcc
CFLAGS  ?= -O2 -g
CFLAGS  += -Wall -Wextra -I../include
LDFLAGS ?=

uapp: main.o nl.o util.o
	$(CC) $(LDFLAGS) -o $@ $^

%.o: %.c uapp.h ../include/fw_proto.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f uapp *.o

.PHONY: clean
