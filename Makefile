CC:=gcc
AR:=ar
MCFLAGS:=-Wall -O2
OBJS:=zpage

all: kzpage.ko zpage 

zpage: zpage.c libpt_scan.a
	$(CC) $(MCFLAGS) -L. -lpt_scan -o $@ $< -lpt_scan

obj-m+=kzpage.o

libpt_scan.a: pt_scan.o
	$(AR) ruv libpt_scan.a pt_scan.o

pt_scan.o: pt_scan.c pt_scan.h
	$(CC) $(MCFLAGS) -static -c pt_scan.c

kzpage.ko: kzpage.c
	$(MAKE) -C /lib/modules/`uname -r`/build M=$(PWD) modules

clean: 
	rm -f *.o *.ko $(OBJS)
	$(MAKE) -C /lib/modules/`uname -r`/build M=$(PWD) clean

