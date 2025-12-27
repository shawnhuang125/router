# Hroute/dhcp/Makefile
CC = gcc
# the include and ../common/include must be import at once
CFLAGS = -Wall -Wextra -Iinclude -I../common/include
# the final executable file need to be putted in root/bin/
TARGET = ../bin/my_dhcp
# fetch all .c file in dhcp/src
SRCS = $(wildcard src/*.c)
OBJS = $(SRCS:.c=.o)
# it will fetched the .o file which is compiled in the ../common/src
# it will link the logger module made in /common/src/logger.c
COMMON_OBJS = $(wildcard ../common/src/*.o)

.PHONY: all clean

all: $(TARGET)

# LINK: it will merged the .o file in DHCP module and .o file in common to be a executable file
$(TARGET): $(OBJS)
	@mkdir -p ../bin
	$(CC) $(OBJS) $(COMMON_OBJS) -o $(TARGET)
	@echo "DHCP Server built successfully: $(TARGET)"

# Compile
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f src/*.o $(TARGET)
