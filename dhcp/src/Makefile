# 編譯器與參數設定
CC = gcc
# 加入 -I 來告訴編譯器頭文件在哪裡
CFLAGS = -Wall -Wextra -g -I. -I../../common/include


# 目標執行檔名稱
TARGET = dhcp_server

# 所有的原始碼檔案
SRCS = main.c protocol.c network.c ../../common/src/logger.c
# 將 .c 檔案路徑轉換為 .o 檔案路徑
OBJS = $(SRCS:.c=.o)

# 預設目標：編譯執行檔
all: $(TARGET)

# 如何連結 .o 檔案生成執行檔
$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET)

# 如何編譯 .c 檔案生成 .o 檔案
%.o: %.c dhcp.h ../../common/include/logger.h
	$(CC) $(CFLAGS) -c $< -o $@

# 清理編譯產生的檔案
clean:
	rm -f $(OBJS) $(TARGET) ../../common/src/logger.o
