#include <stdio.h>      // 解決 FILE, fopen, fgets, sscanf
#include <stdlib.h>     // 解決 exit, atoi
#include <string.h>     // 解決 strcmp, strcpy
#include <stdint.h>     // 解決 uint32_t
#include <arpa/inet.h>  // 解決 inet_addr
#include "config_manager.h"           // 引入結構定義
#include "../../common/include/logger.h" // 解決 log_message, LOG_INFO, LOG_ERROR

// 定義全域變數
DHCPConfig config;

// 解析 dhcp.conf
int load_config(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        log_message(LOG_ERROR, "Cannot open config file: %s", path);
        return -1;
    }

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        // 跳過註解與空行
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') continue;

        char key[64], value_buf[128];
        // 改用 %[^\n] 讀取等號後面的所有內容（包含空格）
        if (sscanf(line, "%63[^=]=%127[^\n\r]", key, value_buf) == 2) {
            
            if (strcmp(key, "interface") == 0) {
                strcpy(config.interface, value_buf);
            } else if (strcmp(key, "server_ip") == 0) {
                config.server_ip = inet_addr(value_buf);
            } else if (strcmp(key, "netmask") == 0) {
                config.netmask = inet_addr(value_buf);
            } else if (strcmp(key, "router") == 0) {
                config.router = inet_addr(value_buf);
            } else if (strcmp(key, "ip_start") == 0) {
                config.ip_start = inet_addr(value_buf);
            } else if (strcmp(key, "ip_end") == 0) {
                config.ip_end = inet_addr(value_buf);
            } else if (strcmp(key, "lease_time") == 0) {
                config.lease_time = htonl(atoi(value_buf)); // 注意租約時間通常存為網路序
            } 
            // --- 處理多個 DNS ---
            else if (strcmp(key, "dns") == 0) {
                config.dns_count = 0;
                char *token = strtok(value_buf, " ");
                while (token != NULL && config.dns_count < MAX_DNS) { // 假設最多 3 個
                    config.dns_servers[config.dns_count] = inet_addr(token);
                    if (config.dns_servers[config.dns_count] != INADDR_NONE) {
                        config.dns_count++;
                    }
                    token = strtok(NULL, " ");
                }
            }
        }
    }
    fclose(fp);
    log_message(LOG_INFO, "Configuration loaded successfully from %s (DNS count: %d)", path, config.dns_count);
    return 0;
}
