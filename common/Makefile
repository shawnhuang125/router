# Hroute/common/Makefile

# compiler settings
CC = gcc
# -Iinclude lets the code can find the header files in include/ directory  
#include "logger.h"
CFLAGS = -Wall -Wextra -Iinclude

# try to fetch all .c file in src/
#  for example: src/logger.c src/network_utils.c
SRCS = $(wildcard src/*.c)

# rename .c file to be .o file
# for example: src/logger.o src/network_utils.o
OBJS = $(SRCS:.c=.o)

.PHONY: all clean
# default target: only compile .o files, do not link into a executable.
all: $(OBJS)
	@echo "Common Library Compiled Successfully!"
# compile role: how to turn a .c file into a .o file
# $< stands for a source file(.c), $@ stands for the target file(.o)
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# clean all file be formed by compiler
clean:
	rm -f src/*.o



