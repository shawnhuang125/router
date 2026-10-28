#ifndef IP_MANAGER_H
#define IP_MANAGER_H

#include <stdint.h>
#include <time.h>    // 必須包含這個，解決 time_t 未定義問題

#define POOL_SIZE 101

#define LEASE_FILE_PATH "var/dhcp.leases"

typedef struct {
    uint32_t ip;
    uint8_t mac[6];
    int is_assigned; // 統一使用 is_assigned
    time_t expiry;   // 統一使用 expiry
} ip_entry_t;

// 確保這些全域變數可以被 ip_manager.c 看到
extern ip_entry_t ip_pool[POOL_SIZE]; 
extern int pool_size;

void check_lease_expiration(); 
void save_leases(const char *path);
int load_leases(const char *path);

// 初始化資源池，start_ip_str 可以由用戶輸入（例如 "192.168.2.50"）
void init_ip_pool(const char *start_ip_str);

// 分配一個 IP 給指定的 MAC
uint32_t allocate_ip(uint8_t *client_mac);

// 釋放 IP (當收到 DHCPRELEASE 時使用)
void release_ip(uint32_t ip);

/**
 * @brief Checks if a specific IP address is valid and currently unallocate>
 * @param ip Target IPv4 address to check (Host-Endian).
 * @return 1 if the IP is available, 0 if it is already allocated or invali>
 */
int is_ip_available(uint32_t ip);

/**
 * @brief Binds a specific IP address directly to a client's MAC address.
 * @param chaddr Client hardware address (6-byte MAC).
 * @param ip Target IPv4 address to assign (Host-Endian).
 * @return 0 on success, -1 on failure (e.g., IP not found in pool).
 */
int bind_specific_ip(uint8_t *chaddr, uint32_t ip);

//或許is_allocated = 1的IP (DHCPACK時使用)
uint32_t get_assigned_ip(uint8_t *client_mac);

#endif
