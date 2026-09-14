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

//發送NAK封包:在CLIENT要續約IP RELEASE TIME的時候
void send_dhcp_nak(int sockfd, struct dhcp_packet *client_pkt, struct sockaddr_in *client_addr) {
    struct dhcp_packet nak_pkt;
    memset(&nak_pkt, 0, sizeof(nak_pkt));

    // 1. 基本標頭設定
    nak_pkt.op = 2;              // Boot Reply
    nak_pkt.htype = 1;           // Ethernet
    nak_pkt.hlen = 6;
    nak_pkt.xid = client_pkt->xid; // 必須與 Client 發過來的一致
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
    //設定廣播目的地資訊 (關鍵修改處)
    struct sockaddr_in broadcast_addr;
    memset(&broadcast_addr, 0, sizeof(broadcast_addr));
    broadcast_addr.sin_family = AF_INET;
    broadcast_addr.sin_port = htons(68);
    broadcast_addr.sin_addr.s_addr = INADDR_BROADCAST;

    // 發送封包 (廣播)
    int broadcastPermission = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &broadcastPermission, sizeof(broadcastPermission));

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

