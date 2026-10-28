#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "protocol.h"
/**
 * 從 DHCP Options 區域中提取特定的 Option 數值
 * @param packet 指向收到的 DHCP 封包
 * @param code   想要尋找的 Option Code (例如 OPT_MSG_TYPE)
 * @param out    輸出的緩衝區
 * @param max_len 輸出緩衝區的最大長度
 * @return 實際讀取的長度，若未找到則回傳 0
 */


// 檢查並自動修復 Client 端傳入的 Byte-swapped IP
void normalize_requested_ip(struct in_addr *req_addr, uint32_t server_netmask, uint32_t server_subnet) {
    if (!req_addr || req_addr->s_addr == 0) return;

    // 1. 先用標準網路序檢查：是否在伺服器網段內？
    if ((req_addr->s_addr & server_netmask) == server_subnet) {
        return; // 符合標準規範，直接使用
    }

    // 2. 若不在網段內，嘗試反轉 32-bit 整數（偵測 Little-Endian 韌體缺陷）
    uint32_t flipped_ip = htonl(req_addr->s_addr);
    if ((flipped_ip & server_netmask) == server_subnet) {
        log_message(LOG_WARNING, "Detected broken client firmware (Little-Endian Option 50). Auto-correcting byte order.");
        req_addr->s_addr = flipped_ip;
        return;
    }

    // 3. 兩者皆不在網段內，維持原值讓後續邏輯送出 DHCPNAK
}

int get_dhcp_option(struct dhcp_packet *packet, uint8_t code, void *out, int max_len) {
    printf("DEBUG: Packet Magic Cookie = 0x%08X\n", ntohl(packet->magic_cookie));
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

int send_dhcp_offer(int sockfd, struct dhcp_packet *client_pkt, uint32_t offered_ip) {
    struct dhcp_packet offer_pkt;
    memset(&offer_pkt, 0, sizeof(offer_pkt));

    // 1. BOOTP 核心標頭 (嚴格遵循 RFC 2131)
    offer_pkt.op     = 2;                       // Boot Reply
    offer_pkt.htype  = client_pkt->htype;       // 1 (Ethernet)
    offer_pkt.hlen   = client_pkt->hlen;        // 6
    offer_pkt.hops   = 0;
    offer_pkt.xid    = client_pkt->xid;         // 照抄 client 的 Transaction ID
    offer_pkt.secs   = 0;
    offer_pkt.flags  = client_pkt->flags;       // 保留 client 的 Broadcast flag
    offer_pkt.ciaddr = 0;
    offer_pkt.yiaddr = htonl(offered_ip);       // 轉為網路位元序
    offer_pkt.siaddr = 0;
    offer_pkt.giaddr = client_pkt->giaddr;      // 保留 Relay Agent 位址
    memcpy(offer_pkt.chaddr, client_pkt->chaddr, 16);
    offer_pkt.magic_cookie = htonl(DHCP_MAGIC_COOKIE);

    // 2. DHCP Options
    uint8_t *ptr = offer_pkt.options;

    // Option 53: DHCP Message Type = 2 (DHCPOFFER)
    *ptr++ = 53; *ptr++ = 1; *ptr++ = 2;

    // Option 54: Server Identifier
    *ptr++ = 54; *ptr++ = 4;
    memcpy(ptr, &config.server_ip, 4);
    ptr += 4;

    // Option 1: Subnet Mask
    *ptr++ = 1; *ptr++ = 4;
    memcpy(ptr, &config.netmask, 4);
    ptr += 4;

    // Option 3: Router
    *ptr++ = 3; *ptr++ = 4;
    memcpy(ptr, &config.router, 4);
    ptr += 4;

    // Option 51: Lease Time
    *ptr++ = 51; *ptr++ = 4;
    memcpy(ptr, &config.lease_time, 4);
    ptr += 4;

    // Option 6: DNS Servers
    if (config.dns_count > 0) {
        *ptr++ = 6;
        *ptr++ = config.dns_count * 4;
        for (int i = 0; i < config.dns_count; i++) {
            memcpy(ptr, &config.dns_servers[i], 4);
            ptr += 4;
        }
    }

    // Option 255: End
    *ptr++ = 255;

    // 3. 長度保證：不得小於 BOOTP 最小長度 300 bytes
    ssize_t actual_len = (uint8_t *)ptr - (uint8_t *)&offer_pkt;
    if (actual_len < 300) {
        actual_len = 300;
    }

    // 4. 廣播發送
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(DHCP_CLIENT_PORT);
    dest_addr.sin_addr.s_addr = INADDR_BROADCAST;

    ssize_t sent_len = sendto(sockfd, &offer_pkt, actual_len, 0,
                              (struct sockaddr *)&dest_addr, sizeof(dest_addr));

    if (sent_len < 0) {
        log_message(LOG_ERROR, "Failed to send DHCPOFFER!");
        return -1;
    }

    log_message(LOG_INFO, "DHCPOFFER sent to 255.255.255.255:68 (Total Size: %ld bytes)", sent_len);
    return 0;
}

//發送NAK封包:在CLIENT要續約IP RELEASE TIME的時候
void send_dhcp_nak(int sockfd, struct dhcp_packet *client_pkt, struct sockaddr_in *client_addr) {
    (void)client_addr;
    struct dhcp_packet nak_pkt;
    memset(&nak_pkt, 0, sizeof(nak_pkt));

    // 1. 基本標頭設定
    nak_pkt.op = 2;              // Boot Reply
    nak_pkt.htype = 1;           // Ethernet
    nak_pkt.hlen = 6;
    nak_pkt.xid = client_pkt->xid;          // 必須與 Client 發過來的一致
    nak_pkt.flags = client_pkt->flags;      //補齊flag
    nak_pkt.giaddr = client_pkt->giaddr;    // Relay Agent 欄位一致
    memcpy(nak_pkt.chaddr, client_pkt->chaddr, 6);
    nak_pkt.magic_cookie = htonl(0x63825363);

    // 2. DHCP Options
    uint8_t *ptr = nak_pkt.options;

    // Option 53: DHCP Message Type = 6 (NAK)
    *ptr++ = 53; *ptr++ = 1; *ptr++ = 6;

    // Option 54: Server Identifier (Server本身的IP)
    *ptr++ = 54; *ptr++ = 4;
    memcpy(ptr, &config.server_ip, 4);
    ptr += 4;

    // Option 56: Message (告訴 Client 為什麼被拒絕，選配)
    const char *msg = "Requested IP not available";
    uint8_t msg_len = strlen(msg);
    *ptr++ = 56; *ptr++ = msg_len;
    memcpy(ptr, msg, msg_len);
    ptr += msg_len;

    // End Option
    *ptr++ = 255;

    //計算長度
    ssize_t actual_len = (uint8_t *)ptr - (uint8_t *)&nak_pkt;
    if(actual_len < 300){
        actual_len = 300; //補齊至 BOOTP 最小長度，末端已由 memset 清 0
    }
    //設定廣播目的地資訊 (關鍵修改處)
    struct sockaddr_in broadcast_addr;
    memset(&broadcast_addr, 0, sizeof(broadcast_addr));
    broadcast_addr.sin_family = AF_INET;
    broadcast_addr.sin_port = htons(68);
    broadcast_addr.sin_addr.s_addr = INADDR_BROADCAST;

    //發送封包
    ssize_t sent_len = sendto(sockfd, &nak_pkt, actual_len, 0, 
                              (struct sockaddr *)&broadcast_addr, sizeof(broadcast_addr));
    //確認廣播封包的發送狀態
    if (sent_len < 0) {
        log_message(LOG_ERROR, "Failed to broadcast DHCPNAK!");
    } else {
        log_message(LOG_INFO, "DHCPNAK broadcasted to 255.255.255.255 (Size: %ld bytes)", sent_len);
    }

    log_message(LOG_INFO, "DHCPNAK sent to Client %02x:%02x:%02x:%02x:%02x:%02x",
                client_pkt->chaddr[0], client_pkt->chaddr[1], client_pkt->chaddr[2],
                client_pkt->chaddr[3], client_pkt->chaddr[4], client_pkt->chaddr[5]);
}

