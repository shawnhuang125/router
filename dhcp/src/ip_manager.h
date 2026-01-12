#ifndef IP_MANAGER_H
#define IP_MANAGER_H

#include <stdint.h>

#define POOL_SIZE 101

// 初始化資源池，start_ip_str 可以由用戶輸入（例如 "192.168.2.50"）
void init_ip_pool(const char *start_ip_str);

// 分配一個 IP 給指定的 MAC
uint32_t allocate_ip(uint8_t *client_mac);

// 釋放 IP (當收到 DHCPRELEASE 時使用)
void release_ip(uint32_t ip);

//或許is_allocated = 1的IP (DHCPACK時使用)
uint32_t get_assigned_ip(uint8_t *client_mac);

#endif
