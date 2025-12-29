#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "dhcp.h"

/**
 * 從 DHCP Options 區域中提取特定的 Option 數值
 * @param packet 指向收到的 DHCP 封包
 * @param code   想要尋找的 Option Code (例如 OPT_MSG_TYPE)
 * @param out    輸出的緩衝區
 * @param max_len 輸出緩衝區的最大長度
 * @return 實際讀取的長度，若未找到則回傳 0
 */
int get_dhcp_option(struct dhcp_packet *packet, uint8_t code, void *out, int max_len) {
    uint8_t *curr = packet->options;
    uint8_t *end = packet->options + sizeof(packet->options);

    while (curr < end && *curr != OPT_END) {
        uint8_t type = *curr;
        
        if (type == 0) { // Padding, 忽略
            curr++;
            continue;
        }
        if (curr +1 >= end) break; //確保不會讀取到超過 end 的記憶體
        uint8_t len = *(curr + 1);
        uint8_t *val = curr + 2;
        if (val + len > end) break; //確保 Value 的長度不會超出封包邊界

        if (type == code) {
            int copy_len = (len < max_len) ? len : max_len;
            memcpy(out, val, copy_len);
            return copy_len;
        }

        // 跳到下一個 Option: Type(1) + Len(1) + Value(len)
        curr += (2 + len);
    }
    return 0; // 未找到
}

/**
 * 填充一個基礎的 DHCP 封包 Header
 */
void fill_common_header(struct dhcp_packet *packet, struct dhcp_client *client) {
    memset(packet, 0, sizeof(struct dhcp_packet));
    
    packet->op = 1;              // BOOTREQUEST
    packet->htype = 1;           // Ethernet
    packet->hlen = 6;            // MAC Length
    packet->xid = client->xid;   // 使用 client 結構中的交易 ID
    memcpy(packet->chaddr, client->mac_addr, 6);
    packet->magic_cookie = htonl(DHCP_MAGIC_COOKIE);
}

/**
 * 建立並發送 DHCPDISCOVER
 */
void send_dhcp_discover(int fd, struct dhcp_client *client) {
    struct dhcp_packet packet;
    fill_common_header(&packet, client);

    uint8_t *opt = packet.options;

    // Option 53: DHCP Message Type = DISCOVER
    *opt++ = OPT_MSG_TYPE;
    *opt++ = 1;
    *opt++ = DHCPDISCOVER;

    // Option 55: Parameter Request List (請求子網遮罩、路由、DNS)
    *opt++ = OPT_PARAMETER_REQ;
    *opt++ = 3; 
    *opt++ = OPT_SUBNET_MASK;
    *opt++ = OPT_ROUTER;
    *opt++ = OPT_DNS_SERVER;

    // 結束標記
    *opt++ = OPT_END;

    // 設定發送目標 (廣播位址)
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(DHCP_SERVER_PORT);
    dest.sin_addr.s_addr = INADDR_BROADCAST; // 255.255.255.255

    sendto(fd, &packet, sizeof(packet), 0, (struct sockaddr *)&dest, sizeof(dest));
}
/**
 * 建立並發送 DHCPREQUEST
 */
void send_dhcp_request(int fd, struct dhcp_client *client) {
    struct dhcp_packet packet;
    fill_common_header(&packet, client); // 使用相同的 xid 和 MAC

    uint8_t *opt = packet.options;

    // 1. Option 53: Message Type = REQUEST
    *opt++ = OPT_MSG_TYPE;
    *opt++ = 1;
    *opt++ = DHCPREQUEST;

    // 2. Option 54: Server Identifier (必須！告訴其他 Server 釋放 IP)
    *opt++ = OPT_SERVER_ID;
    *opt++ = 4;
    memcpy(opt, &client->selected_server_ip, 4);
    opt += 4;

    // 3. Option 50: Requested IP Address (必須！指定要租哪個 IP)
    *opt++ = OPT_REQUESTED_IP;
    *opt++ = 4;
    memcpy(opt, &client->offered_ip, 4);
    opt += 4;

    // 4. Option 55: Parameter Request List (同樣請求基本參數)
    *opt++ = OPT_PARAMETER_REQ;
    *opt++ = 3; 
    *opt++ = OPT_SUBNET_MASK;
    *opt++ = OPT_ROUTER;
    *opt++ = OPT_DNS_SERVER;

    // 結束標記
    *opt++ = OPT_END;

    // 設定發送目標 (依然使用廣播 255.255.255.255)
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(DHCP_SERVER_PORT);
    dest.sin_addr.s_addr = INADDR_BROADCAST;

    printf("Sending DHCPREQUEST for IP %s to Server %s...\n", 
           inet_ntoa(*(struct in_addr *)&client->offered_ip),
           inet_ntoa(*(struct in_addr *)&client->selected_server_ip));

    sendto(fd, &packet, sizeof(packet), 0, (struct sockaddr *)&dest, sizeof(dest));
}
void handle_timeout(int fd, struct dhcp_client *client) {
    client->retry_count++;
    if (client->retry_count > 4) {
        printf("Too many retries, resetting to INIT...\n");
        client->state = STATE_INIT;
        client->retry_count = 0;
        send_dhcp_discover(fd, client);
    } else {
        if (client->state == STATE_SELECTING) {
            send_dhcp_discover(fd, client);
        } else if (client->state == STATE_REQUESTING) {
            send_dhcp_request(fd, client);
        }
    }
}
/**
 * 建立並發送 DHCPDECLINE (當 ARP 檢查發現 IP 衝突時)
 */
void send_dhcp_decline(int fd, struct dhcp_client *client) {
    struct dhcp_packet packet;
    fill_common_header(&packet, client);

    uint8_t *opt = packet.options;

    // 1. Option 53: Message Type = DECLINE
    *opt++ = OPT_MSG_TYPE;
    *opt++ = 1;
    *opt++ = DHCPDECLINE;

    // 2. Option 54: Server Identifier
    *opt++ = OPT_SERVER_ID;
    *opt++ = 4;
    memcpy(opt, &client->selected_server_ip, 4);
    opt += 4;

    // 3. Option 50: Requested IP Address (告訴 Server 哪個 IP 不能用)
    *opt++ = OPT_REQUESTED_IP;
    *opt++ = 4;
    memcpy(opt, &client->offered_ip, 4);
    opt += 4;

    // 結束標記
    *opt++ = OPT_END;

    // 設定發送目標 (廣播)
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(DHCP_SERVER_PORT);
    dest.sin_addr.s_addr = INADDR_BROADCAST;

    printf("IP %s is in use! Sending DHCPDECLINE to Server...\n", 
           inet_ntoa(*(struct in_addr *)&client->offered_ip));

    sendto(fd, &packet, sizeof(packet), 0, (struct sockaddr *)&dest, sizeof(dest));
}

