This project provides a Linux Kernel Module for resetting IPv4 
SNMP counters (The counters that you see in netstat -s).

In order to build, you need kernel-devel package installed.

The Makefile is for CetnOS EL6 (2.6.32-358.2.1.el6.x86_64 kernel)

For F18, run
make -f Makefile.f18

With fedora, this is done by "yum install kernel-devel".
