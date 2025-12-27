# root directory Makefile
# Compiler Settings
CC = gcc
CFLAGS = -Wall -Wextra -I./common/include

# define sub-directories
SUBDIRS = common dhcp dns nat

.PHONY: all make_common dhcp_module dns_module nat_module clean
# default target: to compile all models
all: make_common dhcp_module
	@ echo "it will compile common and dhcp. Future Support: DNS/NAT Models!"
# compile common repository(to generate .o for other person usage)
make_common:
	$(MAKE) -C common
# compile DHCP
dhcp_module: make_common
	$(MAKE) -C dhcp
# add in the future: compile dns module
dns_module: make_common
	#$(MAKE) -C dns
# nat_module: make_common
	#$(MAKE) -C nat

clean:
	$(MAKE) -C common clean
	$(MAKE) -C dhcp clean
	#$(MAKE) -C dns clean
	#$(MAKE) -C nat clean
