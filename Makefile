#ccflags-y := -Werror -g -Wall -DCONFIG_CACHEOBJS_STATS
#ccflags-y := -g -Wall -DCONFIG_CACHEOBJS_STATS
ccflags-y := -g -Wall -DCONFIG_CACHEOBJS_STATS -DCONFIG_CACHEOBJS_CONNPOOL
obj-m := conntable_ktest.o
conntable_ktest-y := conntable_v2.o conntable_test.o
#conntable_ktest-y := conntable_v1.o conntable_test.o

all:
	make -C /lib/modules/`uname -r`/build M=`pwd` modules 
clean:
	make -C /lib/modules/`uname -r`/build M=`pwd` clean
