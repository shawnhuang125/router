#ifndef CONFIG_MANAGER_H
#define CONFIG_MANAGER_H

#include <stdint.h>

#define MAX_DNS 3

/**
 * @brief DHCP 伺服器配置結構體
 * 儲存從 dhcp.conf 讀取的設定參數
 */
typedef struct {
    char interface[16];   // 監聽的網路介面名稱 (例如: eth0, enp5s0)
    uint32_t server_ip;   // DHCP 伺服器本身的 IP (網路序)
    uint32_t netmask;     // 子網路遮罩 (網路序)
    uint32_t router;      // 預設閘道 (網路序)
    uint32_t ip_start;    // IP 位址池起始位址 (網路序)
    uint32_t ip_end;      // IP 位址池結束位址 (網路序)
    uint32_t lease_time;  // 租約時間，單位：秒 (例如: 3600)
    uint32_t dns_servers[MAX_DNS]; // 存放解析後的 IP
    int dns_count;                 // 實際讀到了幾個 DNS
} DHCPConfig;

/**
 * @brief 宣告全域配置變數
 * 使用 extern 讓其他檔案 (如 ip_manager.c) 知道 config 存在於其他編譯單元中
 */
extern DHCPConfig config;

/**
 * @brief 載入設定檔函式
 * @param path 設定檔路徑
 * @return int 成功傳回 0，失敗傳回 -1
 */
int load_config(const char *path);

/**
 * @brief 顯示目前載入的配置資訊 (除錯用)
 */
void print_config();

#endif // CONFIG_MANAGER_H
