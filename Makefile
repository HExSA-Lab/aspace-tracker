CC:=gcc
AR:=ar
MCFLAGS:=-Wall -O2
OBJS:=ztrace test

all: kztrace.ko ztrace 

ztrace.o: ztrace.c
	$(CC) $(MCFLAGS) -o $@ -c $<

hashtable.o: hashtable.c hashtable.h
	$(CC) $(MCFLAGS) -o $@ -c $<

ztrace: ztrace.o hashtable.o libpt_scan.a 
	$(CC) -L. -lpt_scan -o $@ ztrace.o hashtable.o -lpt_scan

obj-m+=kztrace.o

libpt_scan.a: pt_scan.o
	$(AR) rv libpt_scan.a pt_scan.o

pt_scan.o: pt_scan.c pt_scan.h
	$(CC) $(MCFLAGS) -static -c pt_scan.c

test: test.c
	$(CC) -Wno-unused-but-set-variable -Wall -o $@ $<

kztrace.ko: kztrace.c
	$(MAKE) -C /lib/modules/`uname -r`/build M=$(PWD) modules

clean: 
	rm -f *.o *.ko $(OBJS)
	$(MAKE) -C /lib/modules/`uname -r`/build M=$(PWD) clean

