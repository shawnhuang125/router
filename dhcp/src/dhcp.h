#ifndef DHCP_H
#define DHCP_H

#include <stdint.h>

// 常數定義
#define DHCP_SERVER_PORT    67
#define DHCP_CLIENT_PORT    68
#define DHCP_MAGIC_COOKIE   0x63825363  // RFC 1497 定義的 Magic Cookie

// DHCP 訊息類型 (Option 53 的數值)
#define DHCPDISCOVER        1
#define DHCPOFFER          2
#define DHCPREQUEST        3
#define DHCPDECLINE        4
#define DHCPACK            5
#define DHCPNAK            6
#define DHCPRELEASE        7
#define DHCPINFORM         8

// DHCP Option 代碼定義
#define OPT_SUBNET_MASK    1
#define OPT_ROUTER         3
#define OPT_DNS_SERVER     6
#define OPT_HOST_NAME      12
#define OPT_REQUESTED_IP   50
#define OPT_LEASE_TIME     51
#define OPT_MSG_TYPE       53
#define OPT_SERVER_ID      54
#define OPT_PARAMETER_REQ  55
#define OPT_END            255

// --- DHCP 封包結構 (RFC 2131 Section 2) ---
// 使用 packed 確保結構體與網路封包位元組一致
struct dhcp_packet {
    uint8_t  op;            // 訊息操作代碼 (1=BOOTREQUEST, 2=BOOTREPLY)
    uint8_t  htype;         // 硬體位址類型 (1=Ethernet)
    uint8_t  hlen;          // 硬體位址長度 (6 for MAC)
    uint8_t  hops;          // 中繼跳數，Client 設為 0
    uint32_t xid;           // 交易 ID (Transaction ID)
    uint16_t secs;          // 開始獲取位址後經過的秒數
    uint16_t flags;         // 標誌 (例如廣播位元)
    uint32_t ciaddr;        // 客戶端 IP (Client IP, 僅續約時使用)
    uint32_t yiaddr;        // 「你的」IP (Your IP, Server 分配給 Client)
    uint32_t siaddr;        // 下一個伺服器 IP (Next Server IP)
    uint32_t giaddr;        // 中繼代理 IP (Relay Agent IP)
    uint8_t  chaddr[16];    // 客戶端硬體位址 (Client Hardware Address)
    uint8_t  sname[64];     // 伺服器主機名稱 (選用)
    uint8_t  file[128];     // 啟動檔案名稱 (選用)
    uint32_t magic_cookie;  // Magic Cookie (0x63825363)
    uint8_t  options[308];  // 選項區域 (最小長度要求，通常設為 308 以達總長 576 bytes)
} __attribute__((packed));

// --- 客戶端狀態機定義 ---
typedef enum {
    STATE_INIT,
    STATE_SELECTING,
    STATE_REQUESTING,
    STATE_BOUND,
    STATE_RENEWING,
    STATE_RELEASING
} dhcp_state_t;

// --- 客戶端內部資訊結構 ---
struct dhcp_client {
    uint32_t xid;                   // 當前交易 ID
    uint8_t  mac_addr[6];           // 自己的 MAC
    dhcp_state_t state;             // 當前狀態
    
    // 從 Server 取得的資訊
    uint32_t offered_ip;            // yiaddr
    uint32_t selected_server_ip;    // Option 54: Server Identifier
    uint32_t netmask;               // Option 1
    uint32_t gateway;               // Option 3
    uint32_t lease_time;            // Option 51
    
    // 重傳控制
    uint16_t secs;
    int      retry_count;
    time_t   last_transmit;
};

#endif // DHCP_H

