#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>    // 為了 memset, memcpy
#include <stdlib.h>    // 為了 exit() 或其他標準工具
#include "ip_manager.h"
#include "../../common/include/logger.h"
#include "config_manager.h"
#include "protocol.h"
extern int init_dhcp_socket();
extern int get_dhcp_option(struct dhcp_packet *packet, uint8_t code, void *out, int max_len);

int main(int argc, char *argv[]){
    //初始化logger
    init_logger();
    log_message(LOG_INFO, "Logger initialized successfully.");

    // 建議：檢查有沒有傳入自定義路徑，如果沒有就用預設的
    const char *config_path = "etc/dhcp.conf"; 
    if (argc > 1) {
        config_path = argv[1]; // 讓你可以用 sudo ./my_dhcp /abs/path/to/conf
    }

    if (load_config(config_path) != 0) {
        log_message(LOG_ERROR, "Failed to load config from %s", config_path);
        return 1;
    }

    // 之後可以直接使用全域變數 config
    printf("Starting DHCP on %s...\n", config.interface);

    //根據conf檔案的變數宣告要動態配置的起始IP
    struct in_addr addr;
    addr.s_addr = config.ip_start;
    char *start_ip_str = inet_ntoa(addr);

    // 初始化 IP Manager
    init_ip_pool(start_ip_str);

    //讀取IP Release Pool的上一次記憶
    load_leases(LEASE_FILE_PATH);
    log_message(LOG_INFO, "DHCP Server started on %s. IP Pool starts from: %s", config.interface, start_ip_str);

    //輸出DHCP模組已啟用
    printf("Starting DHCP on %s...\n", config.interface);
    log_message(LOG_INFO, "DHCP Server started on %s. IP Pool starts from: %s",
                config.interface, start_ip_str);

    int sockfd;
    struct dhcp_packet recv_packet;
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);

    //init socket
    sockfd = init_dhcp_socket();
    if (sockfd < 0){
        log_message(LOG_ERROR, "Failed to initailize DHCP Socket.");
        return 1;
    }
    printf("DHCP Server detection is starting..., listed on port 67\n");

    while(1){
        // --- 這裡加入自動檢查過期 ---
        // 建議實作一個 check_lease_expiration() 放在 ip_manager.c
        // 它會遍歷 pool，把 now > expire_time 的 IP 標記為 is_allocated = 0
        check_lease_expiration();
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

            //先定義server的IP與Submask與lease_time
            uint32_t server_ip = config.server_ip;    //定義伺服器IP為192.168.1.1,變數的類別是32位元變數
            uint32_t netmask = config.netmask;    // 定義網路遮罩為255.255.255.0,變數的類別是32位元變數
            uint32_t lease_time = htonl(config.lease_time);    //// 定義client被分配的租約時間為1hr(3600sec),變數的類別是32位元變數

            switch(msg_type) {

                case DHCPDISCOVER: {  //使用在/dhcp/src/network.h定義的#define DHCPDISCOVER 1
                    log_message(LOG_INFO, "Detected DHCP DISCOVER FROM CLIENT!");
                    log_message(LOG_INFO, "Client MAC Address: %02x:%02x:%02x:%02x:%02x:%02x",
                recv_packet.chaddr[0], recv_packet.chaddr[1], recv_packet.chaddr[2],
                recv_packet.chaddr[3], recv_packet.chaddr[4], recv_packet.chaddr[5]);

                    //使用struct定義要傳送的封包變數
                    struct dhcp_packet offer_packet;
                    memset(&offer_packet, 0, sizeof(offer_packet));//初始化要回傳的封包

                    //自動找一個可用的 IP
                    uint32_t offered_ip = allocate_ip(recv_packet.chaddr);
                    if (offered_ip == 0) {
                        log_message(LOG_ERROR, "No IP addresses left in the pool!");
                        break;
                    }
                    //發送OFFER封包
                    send_dhcp_offer(sockfd, &recv_packet, offered_ip);

                    break;
                }
                case DHCPREQUEST: {  //使用在/dhcp/src/network.h定義的#define DHCPREQUEST 3
                    log_message(LOG_INFO, "Detected DHCP REQUEST FROM CLIENT!");
                    log_message(LOG_INFO, "Client MAC Address: %02x:%02x:%02x:%02x:%02x:%02x",
                recv_packet.chaddr[0], recv_packet.chaddr[1], recv_packet.chaddr[2],
                recv_packet.chaddr[3], recv_packet.chaddr[4], recv_packet.chaddr[5]);

                    //檢查Server_Identifier(option 54),確保server找對台
                    uint32_t requested_server_ip = 0;
                    if(get_dhcp_option(&recv_packet, 54, &requested_server_ip, sizeof(requested_server_ip))){
                        //如果Server IP(Server_Identifier(option 53))不一樣,代表client正在呼叫別台DHCP Server
                        if(requested_server_ip != server_ip){
                            //顯示日誌:client正在尋找別台DHCP Server並跳出
                            log_message(LOG_INFO, "DHCPREQUEST is for another server (%s). Ignoring.", inet_ntoa(*(struct in_addr*)&requested_server_ip));
                            break;
                        }
                    }


                    //檢查IP的的is_allocated是否=1(代表被分配過了)
                    //get_assigned_ip()檢查：1. 是否已分配 2. MAC 地址是否完全吻合
                    uint32_t assigned_ip = get_assigned_ip(recv_packet.chaddr);

                    //檢查Requested IP(Option 50)
                    struct in_addr req_addr = {0};
                    int opt50_len = get_dhcp_option(&recv_packet, 50, &req_addr.s_addr, sizeof(req_addr.s_addr));

                    // 2. 如果沒 Option 50，檢查 ciaddr (封包頭部)
                    if (opt50_len <= 0 && recv_packet.ciaddr != 0) {
                        req_addr.s_addr = recv_packet.ciaddr;
                    }

                    // 自動判定是否為倒裝的 IP
                    // config.netmask 與 config.server_ip 皆為網路序
                    normalize_requested_ip(&req_addr, config.netmask, (config.server_ip & config.netmask));

                    // 3. Pool 裡的 assigned_ip 是主機序 (0xC0A801CA)，轉為網路序放進 struct
                    struct in_addr ass_addr = {0};
                    ass_addr.s_addr = htonl(assigned_ip);

                    // 印出 Hex 觀察
                    printf("DEBUG: Requested_IP_HEX = 0x%08X\n", ntohl(req_addr.s_addr));
                    printf("DEBUG: Assigned_IP_HEX  = 0x%08X\n", assigned_ip);

                    // 4. 檢查是否有分配紀錄
                    if (assigned_ip == 0) {
                        log_message(LOG_WARNING, "assigned_ip is ZERO! record not found.");
                        send_dhcp_nak(sockfd, &recv_packet, &client_addr);
                        break;
                    }

                    // 5. 比對 IP (直接比對 s_addr 二進位值)
                    // 轉為可讀字串 (供日誌使用)
                    // 1. 轉成字串
                    char req_str[INET_ADDRSTRLEN] = {0};
                    char ass_str[INET_ADDRSTRLEN] = {0};
                    inet_ntop(AF_INET, &req_addr, req_str, sizeof(req_str));
                    inet_ntop(AF_INET, &ass_addr, ass_str, sizeof(ass_str));

                    // 2. 檢查是否有分配紀錄
                    if (assigned_ip == 0) {
                        log_message(LOG_WARNING, "assigned_ip is ZERO! record not found.");
                        send_dhcp_nak(sockfd, &recv_packet, &client_addr);
                        break;
                    }

                    // 3. 比對 IP：若不吻合，檢查是否能順應client端
                    if (req_addr.s_addr != 0 && req_addr.s_addr != ass_addr.s_addr) {
                        uint32_t req_ip_host = ntohl(req_addr.s_addr);

                        // 判斷客戶端請求的 IP 是否在可用池內且未被佔用
                        if (is_ip_available(req_ip_host)) {
                            log_message(LOG_INFO, "Stubborn client insists on %s. Reallocating IP!", req_str);
                            
                            // 釋放原本 OFFER 的 IP，改綁client端要的 IP
                            release_ip(assigned_ip);
                            bind_specific_ip(recv_packet.chaddr, req_ip_host);
                            
                            assigned_ip = req_ip_host;
                            ass_addr.s_addr = req_addr.s_addr; // 同步比對結果
                        } else {
                            if ((req_addr.s_addr & config.netmask) != (ass_addr.s_addr & config.netmask)) {
                                log_message(LOG_WARNING, "Requested IP is in different subnet!");
                            }
                            log_message(LOG_WARNING, "IP Mismatch and unavailable! Client asked for %s, but Pool says %s", req_str, ass_str);
                            send_dhcp_nak(sockfd, &recv_packet, &client_addr);
                            break;
                        }
                    }

                    // C. 如果一切正常 (requested_ip == assigned_ip 或續約流程)
                    log_message(LOG_INFO, "Validation Passed! Sending ACK.");

                    //準備發送ACK,初始化DHCPACK封包結構
                    struct dhcp_packet ack_packet;
                    memset(&ack_packet, 0, sizeof(ack_packet));
                    //基本欄位填充
                    ack_packet.op     = 2;                       // Boot Reply
                    ack_packet.htype  = recv_packet.htype;       // 照抄 client 的硬體類型 (Ethernet=1)
                    ack_packet.hlen   = recv_packet.hlen;        // 照抄硬體長度 (6)
                    ack_packet.hops   = 0;
                    ack_packet.xid    = recv_packet.xid;         // 必須與 Request 的 xid 完全一致
                    ack_packet.secs   = 0;
                    ack_packet.flags  = recv_packet.flags;       // 【關鍵】必須照抄 client 的 Broadcast Flag
                    ack_packet.ciaddr = recv_packet.ciaddr;      // 續約時若有 ciaddr 需帶回
                    ack_packet.yiaddr = htonl(assigned_ip);      // 正式指派的 IP (轉為網路序)
                    ack_packet.siaddr = 0;
                    ack_packet.giaddr = recv_packet.giaddr;      // 【關鍵】保留 Relay Agent 欄位
                    memcpy(ack_packet.chaddr, recv_packet.chaddr, 16);
                    ack_packet.magic_cookie = htonl(DHCP_MAGIC_COOKIE);

                    //填充 Options (TLV 串列)
                    uint8_t *ptr = ack_packet.options;

                    //Options 53: DHCP Message Type = 5(ACK)
                    *ptr++ = 53; *ptr++ = 1; *ptr++ = 5;

                    //Option 54: Server Identifier(這台server的ip)
                    *ptr++ = 54; *ptr++ = 4;
                    memcpy(ptr, &server_ip, 4);
                    ptr += 4;

                    //Option 51: Address Release Time
                    *ptr++ = 51; *ptr++ = 4;
                    uint32_t lease_time_net = htonl(lease_time); // 轉為網路序
                    memcpy(ptr, &lease_time_net, 4);
                    ptr += 4;

                    //Option 1: Submask
                    *ptr++ = 1; *ptr++ = 4;
                    memcpy(ptr, &netmask, 4);
                    ptr += 4;

                    //Option 3: Router(Default Gateway, Usually is Server IP)
                    *ptr++ = 3; *ptr++ = 4;
                    memcpy(ptr, &server_ip, 4);
                    ptr += 4;

                    //Option 6: DNS Server
                    if (config.dns_count > 0) {
                        *ptr++ = 6;                          // Type: DNS
                        *ptr++ = config.dns_count * 4;       // Length: 4 * DNS 數量
                        for (int i = 0; i < config.dns_count; i++) {
                            memcpy(ptr, &config.dns_servers[i], 4);
                            ptr += 4;
                        }
                    }

                    //Option 255:End
                    *ptr++ = 255;

                    //計算 Options 的結束點到封包開頭的總長度,必須把指標都轉成 uint8_t* 才能精確按 byte 相減
                    ssize_t actual_len = (uint8_t *)ptr - (uint8_t *)&ack_packet;
                    //紀錄日誌時也可以顯示精確長度
                    log_message(LOG_INFO, "DHCPACK sent (Total Size: %ld bytes)", actual_len);

                    struct sockaddr_in dest_addr;
                    memset(&dest_addr, 0, sizeof(dest_addr));
                    dest_addr.sin_family = AF_INET;
                    dest_addr.sin_port = htons(DHCP_CLIENT_PORT);
                    dest_addr.sin_addr.s_addr = INADDR_BROADCAST; //使用廣播進行封包發送

                    ssize_t sen_len = sendto(sockfd, &ack_packet, actual_len, 0,
                                            (struct sockaddr *)&dest_addr, sizeof(dest_addr));

                    if(sen_len < 0){
                        log_message(LOG_ERROR, "Failed to send DHCPACK!");
                    }else {
                        // 1. 宣告變數 (確保這行存在)
                        struct in_addr leased_addr;

                        // 2. 賦值 (把 print_addr 改成 leased_addr)
                        leased_addr.s_addr = ack_packet.yiaddr;

                        // 3. 列印 Log (同樣改成 leased_addr)
                        log_message(LOG_INFO, "DHCPACK sent! IP %s is now officially leased to Client.", inet_ntoa(leased_addr));
                    }

                    //分配成功後立刻存檔
                    save_leases(LEASE_FILE_PATH);

                    break;
                }
                case DHCPRELEASE: {
                    log_message(LOG_INFO, "Detected DHCP RELEASE FROM CLIENT!");

                    // 根據 RFC，釋放的 IP 放在 ciaddr
                    uint32_t ip_to_release = recv_packet.ciaddr;

                    if (ip_to_release != 0) {
                        release_ip(ip_to_release); // 呼叫 ip_manager 的回收函數
                        // 如果有實作 save_leases()，要在這裡存檔到 lease.db
                        // save_leases(); 
                        log_message(LOG_INFO, "IP %s has been recovered to pool.", 
                                    inet_ntoa(*(struct in_addr*)&ip_to_release));
                    }
                    break;
                }

            }
        }

    }
}
