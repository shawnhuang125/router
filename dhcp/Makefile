# Hroute/dhcp/Makefile
CC = gcc
# the include and ../common/include must be import at once
CFLAGS = -Wall -Wextra -Iinclude -I../common/include
# the final executable file need to be putted in root/bin/
TARGET = ../bin/my_dhcp
# fetch all .c file in dhcp/src
SRCS = $(wildcard src/*.c)
OBJS = $(SRCS:.c=.o)

# 2. 處理 Common 模組 (logger 等)
# 我們明確指定需要哪些物件檔，這樣 make 才知道去哪裡找
COMMON_SRCS = ../common/src/logger.c
COMMON_OBJS = ../common/src/logger.o

# 3. 所有的 Header 檔相依項 (改了 .h 就會觸發重新編譯)
HEADERS = $(wildcard include/*.h) $(wildcard ../common/include/*.h)

.PHONY: all clean

all: $(TARGET)

# LINK: it will merged the .o file in DHCP module and .o file in common to be a executable file
$(TARGET): $(OBJS) $(COMMON_OBJS)
	@mkdir -p ../bin
	$(CC) $(OBJS) $(COMMON_OBJS) -o $(TARGET)
	@echo "DHCP Server built successfully: $(TARGET)"

# 編譯規則 A：處理 dhcp/src/ 下的 .c 檔
src/%.o: src/%.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

# 編譯規則 B：處理 ../common/src/ 下的 .c 檔
# 這就是你剛剛決定加上的保險規則
../common/src/%.o: ../common/src/%.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f src/*.o ../common/src/*.o $(TARGET)
	@echo "Cleaned up all object files and executable."
