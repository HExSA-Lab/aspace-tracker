CC:=gcc
AR:=ar
MCFLAGS:=-Wall -O2
OBJS:=zpage test

all: kzpage.ko zpage 

zpage.o: zpage.c
	$(CC) $(MCFLAGS) -o $@ -c $<

hashtable.o: hashtable.c hashtable.h
	$(CC) $(MCFLAGS) -o $@ -c $<

zpage: zpage.o hashtable.o libpt_scan.a 
	$(CC) -L. -lpt_scan -o $@ zpage.o hashtable.o -lpt_scan

obj-m+=kzpage.o

libpt_scan.a: pt_scan.o
	$(AR) rv libpt_scan.a pt_scan.o

pt_scan.o: pt_scan.c pt_scan.h
	$(CC) $(MCFLAGS) -static -c pt_scan.c

test: test.c
	$(CC) -Wall -o $@ $<

kzpage.ko: kzpage.c
	$(MAKE) -C /lib/modules/`uname -r`/build M=$(PWD) modules

clean: 
	rm -f *.o *.ko $(OBJS)
	$(MAKE) -C /lib/modules/`uname -r`/build M=$(PWD) clean

