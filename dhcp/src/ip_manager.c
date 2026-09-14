#include "ip_manager.h"   // 引用自己的標頭檔
#include <arpa/inet.h>    // 為了使用 inet_addr, ntohl, htonl
#include <string.h>       // 為了使用 memset, memcpy
#include <stdio.h>
#include <time.h>
#include "ip_manager.h"
#include "../../common/include/logger.h"
#include "config_manager.h"

// 分配記憶體空間
ip_entry_t ip_pool[POOL_SIZE];
int pool_size = POOL_SIZE;

// 初始化資源池
void init_ip_pool(const char *start_ip_str) {
    // 1. 先將字串轉為網路序 (Network Byte Order) 的二進位資料
    uint32_t start_ip_n = inet_addr(start_ip_str);
    
    // 2. 將網路序轉為主機序 (Host Byte Order)，這樣加法運算才會正確
    uint32_t start_ip_h = ntohl(start_ip_n);

    for (int i = 0; i < pool_size; i++) {
        // 3. 重點：計算後的結果必須用 htonl 轉回網路序儲存
        // 這樣在發送 DHCP 封包時才不會發生位元組反轉
        ip_pool[i].ip = htonl(start_ip_h + i); 
        
        ip_pool[i].is_assigned = 0;
        ip_pool[i].expiry = 0;
        memset(ip_pool[i].mac, 0, 6);
    }
    printf("IP Pool Initialized: Starting from %s\n", start_ip_str);
}

// 分配 IP (用於 DHCPOFFER)
uint32_t allocate_ip(uint8_t *client_mac) {
    for (int i = 0; i < POOL_SIZE; i++) {
        if (!ip_pool[i].is_assigned) {
            ip_pool[i].is_assigned = 1;
            memcpy(ip_pool[i].mac, client_mac, 6);

            // 設定過期時間
            // 根據流程圖，分配時必須紀錄：當前時間 + 設定檔的租約時間
            ip_pool[i].expiry = time(NULL) + config.lease_time; 

            // 確保這裡的成員名稱與 ip_manager.h 一致
            return ip_pool[i].ip; 
        }
    }
    return 0; // 池子滿了
}

// 釋放 IP (用於 DHCPRELEASE)
void release_ip(uint32_t ip_n) {
    uint32_t ip_h = ntohl(ip_n); // 先轉回主機序好做比較
    for (int i = 0; i < POOL_SIZE; i++) {
        if (ip_pool[i].ip == ip_h) {
            ip_pool[i].is_assigned = 0; // 標記為可用
            memset(ip_pool[i].mac, 0, 6); // 清空 MAC 紀錄
            break;
        }
    }
}
// 找尋已經顯示is_allocated = 1的IP
uint32_t get_assigned_ip(uint8_t *client_mac) {
    for (int i = 0; i < POOL_SIZE; i++) {
        // 檢查是否已分配，且 MAC 地址是否吻合
        if (ip_pool[i].is_assigned && memcmp(ip_pool[i].mac, client_mac, 6) == 0) {
            return htonl(ip_pool[i].ip); // 找到原本分配的 IP，轉成網路序回傳
        }
    }
    return 0; // 沒找到紀錄
}

//檢查所有IP的租約狀態
void check_lease_expiration() {
    time_t now = time(NULL); // 取得當前系統時間
    int reclaimed_count = 0;

    for (int i = 0; i < POOL_SIZE; i++) {
        // 條件：1. 該位置已被分配 2. 目前時間已超過預定的過期時間
        if (ip_pool[i].is_assigned && now > ip_pool[i].expiry) {

            struct in_addr addr;
            addr.s_addr = ip_pool[i].ip;

            log_message(LOG_INFO, "Lease EXPIRED for IP: %s (Client MAC: %02x:%02x:%02x:%02x:%02x:%02x)",
                        inet_ntoa(addr),
                        ip_pool[i].mac[0], ip_pool[i].mac[1], ip_pool[i].mac[2],
                        ip_pool[i].mac[3], ip_pool[i].mac[4], ip_pool[i].mac[5]);

            // 執行回收動作
            ip_pool[i].is_assigned = 0; 
            memset(ip_pool[i].mac, 0, 6);
            ip_pool[i].expiry = 0;

            reclaimed_count++;

        }
    }

    // 如果有任何 IP 被回收，立即更新數據庫檔案
    if (reclaimed_count > 0) {
        log_message(LOG_INFO, "Total %d expired leases reclaimed.", reclaimed_count);
        save_leases(LEASE_FILE_PATH);
    }
}

// 輔助函式：將 MAC 字串 (aa:bb:cc:dd:ee:ff) 轉為 uint8_t[6]
void parse_mac(const char *mac_str, uint8_t *mac_bin) {
    sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &mac_bin[0], &mac_bin[1], &mac_bin[2],
           &mac_bin[3], &mac_bin[4], &mac_bin[5]);
}

int load_leases(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        log_message(LOG_INFO, "No existing lease file found. Starting fresh.");
        return 0;
    }

    char mac_str[18], ip_str[16];
    uint32_t expiry_val;
    int loaded_count = 0;
    time_t now = time(NULL);

    // 格式: 0c:9d:92:5e:69:4b 192.168.1.200 1705141243
    while (fscanf(fp, "%17s %15s %u", mac_str, ip_str, &expiry_val) == 3) {

        //將 ip_str 轉為網路序的 uint32_t
        uint32_t loaded_ip = inet_addr(ip_str);

        //檢查租約是否已經過期 (如果過期了就不載入，讓它變回可用 IP)
        if (expiry_val > 0 && (time_t)expiry_val < now) {
            continue;
        }

        //在 ip_pool 陣列中尋找對應的 IP 位置
        for (int i = 0; i < POOL_SIZE; i++) {
            if (ip_pool[i].ip == loaded_ip) {

                // 解析 MAC 並填入結構體
                parse_mac(mac_str, ip_pool[i].mac);

                // 設定狀態與過期時間
                ip_pool[i].is_assigned = 1;
                ip_pool[i].expiry = (time_t)expiry_val;

                loaded_count++;
                break; // 找到對應 IP 後跳出內層迴圈
            }
        }
    }

    fclose(fp);
    log_message(LOG_INFO, "Successfully reloaded %d active leases from %s", loaded_count, path);
    return loaded_count;
}


//儲存本次IP狀態提供下次重啟使用
void save_leases(const char *path) {
    FILE *fp = fopen(path, "w");
    if (!fp) {
        log_message(LOG_ERROR, "Failed to save leases to %s", path);
        return;
    }

    for (int i = 0; i < POOL_SIZE; i++) {
        if (ip_pool[i].is_assigned) {

            struct in_addr temp_addr;
            temp_addr.s_addr = ip_pool[i].ip;

            fprintf(fp, "%02x:%02x:%02x:%02x:%02x:%02x %s %u\n",
                    ip_pool[i].mac[0], ip_pool[i].mac[1], ip_pool[i].mac[2],
                    ip_pool[i].mac[3], ip_pool[i].mac[4], ip_pool[i].mac[5],
                    inet_ntoa(temp_addr), // inet_ntoa 會幫你轉成字串
                    (uint32_t)ip_pool[i].expiry);
        }
    }
    fclose(fp);
}
