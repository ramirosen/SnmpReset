This project provides a Linux Kernel Module for resetting IPv4 
SNMP counters (The counters that you see in netstat -s or under procfs).

The Makefile is for Fedora 20; in order to build the module, you should 
first clone the repository by 
git clone https://github.com/ramirosen/SnmpReset.git
and thensimply
cd into SnmpReset, and run "make".
You should have kernel-devel package in order to build this module.
With fedora, this is done by "yum install kernel-devel".

In order to reset the SNMP counters, simply run:
insmod snmp_reset.ko 


If you uncomment the line "#define F20" in snmp_reset.c, the kernel 
module will built succesfully under
CetnOS EL6 (2.6.32-358.2.1.el6.x86_64 kernel)


