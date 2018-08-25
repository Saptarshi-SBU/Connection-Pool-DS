ccflags-y := -g -Wall -DCONFIG_CACHEOBJS_STATS
obj-m := conntable_ktest.o
conntable_ktest-y := connpool.o conntable_test.o
#conntable_ktest-y := connhash.o conntable_test.o

all:
	make -C /lib/modules/`uname -r`/build M=`pwd` modules 
clean:
	make -C /lib/modules/`uname -r`/build M=`pwd` clean
