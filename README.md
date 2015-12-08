This project provides a Linux Kernel Module for resetting IPv4 
SNMP counters (The counters that you see in netstat -s or under procfs).

The Makefile is for Fedora 20; in order to build the module, you should 
first clone the repository by 
git clone https://github.com/ramirosen/SnmpReset.git
and then simply
cd into SnmpReset, and run "make".
You should have kernel-devel package in order to build this module.
With Fedora, this is done by "yum install kernel-devel" on older distros or by 
"dnf install kernel-devel" on newer distros.

In order to reset the SNMP counters, simply run:
insmod snmp_reset.ko 

In order to build for Fedora 22, you nead to run:
make EXTRA_CFLAGS=-DF22
or run ./buildFedora22.sh

In order to build for CENTOS7, you nead to run:
make EXTRA_CFLAGS=-DCENTOS
or run ./buildCentos7.sh

If you uncomment the line "#define F20" in snmp_reset.c, the kernel 
module will built succesfully under
CetnOS EL6 (2.6.32-358.2.1.el6.x86_64 kernel)


