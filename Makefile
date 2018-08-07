#ccflags-y := -Werror -g -Wall
obj-m := conntable_ktest.o
conntable_ktest-y := conntable.o conntable_test.o

all:
	make -C /lib/modules/`uname -r`/build M=`pwd` modules 
clean:
	make -C /lib/modules/`uname -r`/build M=`pwd` clean
