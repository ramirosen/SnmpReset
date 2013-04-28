# Developed by: Rami Rosen: http://ramirose.wix.com/ramirosen 
# ramirose@gmail.com 

obj-m += snmp_reset.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
