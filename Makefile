obj-m := kinject.o
ccflags-y := -g -Wno-unused-variable

KVERSION := $(shell uname -r)

all:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean
