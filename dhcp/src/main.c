#include <stdio.h>
#include <arpa/inet.h>
#include "dhcp.h"
#include "../../common/include/logger.h"

extern int init_dhcp_socket();
extern int get_dhcp_option(struct dhcp_packet *packet, uint8_t code, void *out, int max_len);

int main(){
    int sockfd;
    struct dhcp_packet recv_packet;
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);

    //初始化logger
    init_logger();
    log_message(LOG_INFO, "Logger initialized successfully.");

    //init socket
    sockfd = init_dhcp_socket();
    if (sockfd < 0){
        log_message(LOG_ERROR, "Failed to initailize DHCP Socket.");
        return 1;
    }
    printf("DHCP Server detection is starting..., listed on port 67\n");

    while(1){
        //printf("Waiting for DHCP packets...\n");
        ssize_t n = recvfrom(sockfd, &recv_packet, sizeof(recv_packet), 0,
                             (struct sockaddr *)&client_addr, &addr_len);
        if(n<0){
            log_message(LOG_ERROR, "Receive error");
            continue;
        }
        //如果執行到以下片段,代表socket有收到封包
        uint8_t msg_type;
        //使用get_dhcp_option()抓出option 53
        if(get_dhcp_option(&recv_packet, OPT_MSG_TYPE, &msg_type, 1) > 0) {

            switch(msg_type) {

                case DHCPDISCOVER:   //使用在/dhcp/src/network.h定義的#define DHCPDISCOVER 1
                    log_message(LOG_INFO, "Detected DHCP DISCOVER FROM CLIENT!");
                    log_message(LOG_INFO, "Client MAC Address: %02x:%02x:%02x:%02x:%02x:%02x",
                recv_packet.chaddr[0], recv_packet.chaddr[1], recv_packet.chaddr[2],
                recv_packet.chaddr[3], recv_packet.chaddr[4], recv_packet.chaddr[5]);
                    struct dhcp_packet offer_packet;
                    memset(&offer_packet, 0, sizeof(offer_packet));//初始化要回傳的封包
                    offer_packet.xid = recv_packet.xid;//回傳xid
                    offer_packet.op = 2; // 設定訊息類型 (op)DHCP 規範中,1是代表Client寄出的請求(Request),2是代表Server寄出的回應(Reply)
                    offer_packet.yiaddr = inet_addr("192.168.1.100");//在yiaddr欄位填上藥指定的ip地址
                    memcpy(offer_packet.chaddr, recv_packet.chaddr, 6);  //複製硬體地址 (chaddr)
                    offer_packet.magic_cookie = htonl(DHCP_MAGIC_COOKIE);  //填寫 Magic Cookie
                    //填寫OPTION 53 OFFER告訴CLIENT端這是DHCPDISCOVER的回傳訊息
                    uint8_t *ptr = offer_packet.options;
                    *ptr++ = 53;    // Type
                    *ptr++ = 1;    // Length
                    *ptr++ = 2;    // Value (DHCPOFFER)

                    //提供OPTION 1(SUBMASK)
                    *ptr++ = 54;    // Type
                    *ptr++ = 4;    // Length
                    //提供server的ip
                    uint32_t server_ip = inet_addr("192.168.1.1");
                    memcpy(ptr, &server_ip, 4);
                    ptr += 4;
                    //提供網路遮罩(network mask)
                    *ptr++ = 1;    // Type: 1 代表 Subnet Mask
                    *ptr++ = 4;    // Length: IP 長度固定是 4 bytes
                    uint32_t mask = inet_addr("255.255.255.0");
                    memcpy(ptr, &mask, 4);
                    ptr += 4;
                    *ptr++ = 51;    // Type: 51 代表 IP Address Lease Time
                    *ptr++ = 4;     // Length: 4 bytes
                    uint32_t lease_time = htonl(3600); // 租約 1 小時，注意要轉成網路位元組序
                    memcpy(ptr, &lease_time, 4);
                    ptr += 4;
                    *ptr++ = 255;   // Option 255: End
                    int broadcastPermission = 1;    //設定發送廣播封包的權限
                    setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &broadcastPermission, sizeof(broadcastPermission));    //發送OFFER封包
                    // 準備目的地地址資訊
                    struct sockaddr_in dest_addr;
                    memset(&dest_addr, 0, sizeof(dest_addr));
                    dest_addr.sin_family = AF_INET;
                    dest_addr.sin_port = htons(68);
                    dest_addr.sin_addr.s_addr = INADDR_BROADCAST;
                    ssize_t sent_len = sendto(sockfd, &offer_packet, sizeof(offer_packet), 0,
                         (struct sockaddr *)&dest_addr, sizeof(dest_addr));
                    if (sent_len < 0) {
                        log_message(LOG_ERROR, "Failed to send DHCPOFFER!");
                    } else {
                        log_message(LOG_INFO, "DHCPOFFER sent to 255.255.255.255:68");
                    }
                    break;
            }
        }

    }
}
