#include "ip_manager.h"   // 引用自己的標頭檔
#include <arpa/inet.h>    // 為了使用 inet_addr, ntohl, htonl
#include <string.h>       // 為了使用 memset, memcpy
#include <stdio.h>

// 1. 定義內部使用的結構體（這部分不用寫在 .h，放在 .c 即可，屬於隱私資料）
typedef struct {
    uint32_t ip_addr;       // 主機序 (Host Byte Order)
    uint8_t  mac[6];        // 紀錄借給哪個 MAC
    int      is_allocated;  // 狀態：0 = 可用, 1 = 已分配
} ip_entry_t;

// 2. 建立資源池陣列
static ip_entry_t ip_pool[POOL_SIZE];

// 3. 實作：初始化資源池
void init_ip_pool(const char *start_ip_str) {
    uint32_t start_ip_h = ntohl(inet_addr(start_ip_str));

    for (int i = 0; i < POOL_SIZE; i++) {
        ip_pool[i].ip_addr = start_ip_h + i; // 根據起點自動加 i
        ip_pool[i].is_allocated = 0;
        memset(ip_pool[i].mac, 0, 6);
    }
    printf("IP Pool Initialized: Starting from %s\n", start_ip_str);
}

// 4. 實作：分配 IP (用於 DHCPOFFER)
uint32_t allocate_ip(uint8_t *client_mac) {
    for (int i = 0; i < POOL_SIZE; i++) {
        if (!ip_pool[i].is_allocated) {
            ip_pool[i].is_allocated = 1;
            memcpy(ip_pool[i].mac, client_mac, 6);
            return htonl(ip_pool[i].ip_addr); // 回傳網路序供封包使用
        }
    }
    return 0; // 池子滿了
}

// 5. 實作：釋放 IP (用於 DHCPRELEASE)
void release_ip(uint32_t ip_n) {
    uint32_t ip_h = ntohl(ip_n); // 先轉回主機序好做比較
    for (int i = 0; i < POOL_SIZE; i++) {
        if (ip_pool[i].ip_addr == ip_h) {
            ip_pool[i].is_allocated = 0; // 標記為可用
            memset(ip_pool[i].mac, 0, 6); // 清空 MAC 紀錄
            break;
        }
    }
}
