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


                    offer_packet.op = 2; // 設定訊息類型 (op)DHCP 規範中,1是代表Client寄出的請求(Request),2是代表Server寄出的回應(Reply)
                    offer_packet.htype = 1;    //// 必須固定為 1 (Ethernet)
                    offer_packet.hlen = 6;                      // 必須固定為 6
                    offer_packet.xid = recv_packet.xid;//回傳xid

                    offer_packet.yiaddr = offered_ip;//在yiaddr欄位填上藥指定的ip地址
                    memcpy(offer_packet.chaddr, recv_packet.chaddr, 16);  //複製硬體地址 (chaddr)
                    offer_packet.magic_cookie = htonl(DHCP_MAGIC_COOKIE);  //填寫 Magic Cookie
                    //填寫OPTION 53 OFFER告訴CLIENT端這是DHCPDISCOVER的回傳訊息
                    uint8_t *ptr = offer_packet.options;
                    // Message Type: OFFER
                    //先把第0格然後賦值為53然後往下走1 byte(8bits)
                    *ptr++ = 53;
                    //賦值為1然後往下走1 byte(8bits)
                    *ptr++ = 1;
                    //賦值為2然後往下走1 byte(8bits)
                    *ptr++ = 2;
                    //這裡是Server Identifier
                    //賦值為54然後往下走1 byte(8bits)
                    *ptr++ = 54;
                    //賦值為4然後往下走1 byte(8bits)
                    *ptr++ = 4;
                    //使用memory copy記憶體複製的方式從&server_ip開始連續取出4bytes的資料貼到
                    //貼到目前ptr指向的記憶體位置
                    // *ptr = server_ip;要捨棄,是因為ptr是一個byte所以如果馬上在賦值編譯器會把
                    //&server_ip的後3bytes複寫掉
                    memcpy(ptr, &server_ip, 4);
                    //一次往後移動4bytes(32bits)跳過剛剛寫入的ipv4的資料的記憶體位址避免下次複寫
                    //將指標指向server_ip變數之後的記憶體位址
                    ptr += 4;

                    // 提供預設網關 (Router - Option 3)
                    *ptr++ = 3;    // Type: 3 代表 Router
                    *ptr++ = 4;    // Length: 4 bytes
                    memcpy(ptr, &config.router, 4); // 確保從 config 讀取 router IP
                    ptr += 4;

                    //提供網路遮罩(network mask)
                    //賦值為1然後往下走1 byte(8bits)
                    *ptr++ = 1;    // Type: 1 代表 Subnet Mask
                    //賦值為4然後往下走1 byte(8bits)
                    *ptr++ = 4;    // Length: IP 長度固定是 4 bytes

                    //使用memory copy記憶體複製的方式從&mask開始連續取出4bytes的資料貼到
                    //貼到目前ptr指向的記憶體位置
                    memcpy(ptr, &netmask, 4);
                    //往下走4 bytes(32bits)將指標指向submask變數之後的記憶體位址
                    ptr += 4;

                    //先賦值51再往下1 byte(8bits)
                    *ptr++ = 51;    // Type: 51 代表 IP Address Lease Time
                    //先賦值4再往下1 byte(8bits)
                    *ptr++ = 4;     // Length: 4 bytes

                    //使用memory copy記憶體複製的方式從&least_time開始連續取出4bytes的資料貼到
                    //貼到目前ptr指向的記憶體位置
                    memcpy(ptr, &lease_time, 4);
                    //往下走4bytes(32bits)將指標指向lease_time變數之後的記憶體位址
                    ptr += 4;

                    //提供dns server(option6)
                    if (config.dns_count > 0) {
                        *ptr++ = 6;
                        *ptr++ = config.dns_count * 4;
                        for (int i = 0; i < config.dns_count; i++) {
                            memcpy(ptr, &config.dns_servers[i], 4);
                            ptr += 4;
                        }
                    }

                    //先賦值255再往下1 byte(8bits)
                    *ptr++ = 255;   // Option 255: End結束
                    //共計整個TLV串列指標共移動並寫入了22Bytes(176bits)


                    //在預設情況下,系統是不允許一個程式隨便發送廣播(Broadcast)封包
                    // 設定發送廣播封包的權限,broadcastPermission=1,代表 ON 開啟
                    int broadcastPermission = 1;
                    //這是一個 Linux/Unix 系統內建的標準Socket API,它屬於 BSD Socket 介面
                    //sockfd:你要設定哪一個 Socket
                    //SOL_SOCKET:設定的層級。這代表你要設定的是(通用 Socket 層)的選項
                    //而不是特定於 TCP 或 IP 層的設定
                    //SO_BROADCAST:這是你要開啟的功能名稱。它的意思是開啟發送廣播封包的權限
                    //&broadcastPermission:這是一個指標,指向你想要設定的值
                    //Server的OFFER(也就是程式要發出的封包)要用廣播發出(發送到 255.255.255.255)
                    //這樣網段內還沒有 IP 的 Client 才能收到。
                    setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &broadcastPermission, sizeof(broadcastPermission));    //發送OFFER封包
                    //準備目的地地址資訊
                    //這是Linux用來儲存網路位址資訊的標準結構體
                    struct sockaddr_in dest_addr;
                    //
                    memset(&dest_addr, 0, sizeof(dest_addr));
                    // AF_INET:告訴系統要使用IPv4通訊協定
                    dest_addr.sin_family = AF_INET;
                    //htons(DHCP_CLIENT_PORT):設定目的地的Port
                    //htons:(Host to Network Short)把數字轉成網路位元組序,確保大端序(Big-Endian)正確
                    dest_addr.sin_port = htons(DHCP_CLIENT_PORT);
                    //INADDR_BROADCAST:這是系統定義的常數,代表255.255.255.255
                    //這封信是廣播給網段內的所有人,因為Client目前還沒有IP,只能透過廣播接收
                    dest_addr.sin_addr.s_addr = INADDR_BROADCAST;
                    //計算 Options 的結束點到封包開頭的總長度,必須把指標都轉成 uint8_t* 才能精確按 byte 相減
                    ssize_t actual_len = (uint8_t *)ptr - (uint8_t *)&offer_packet;
                    //紀錄日誌時也可以顯示精確長度
                    log_message(LOG_INFO, "DHCPOFFER sent (Total Size: %ld bytes)", actual_len);
                    //這是 UDP 通訊的核心 API，它不需要像 TCP 那樣先建立連線，直接把封包丟向目的地
                    //&offer_packet: 要寄出的資料開頭。
                    //sizeof(offer_packet): 這是一個小細節
                    //目前是把整個結構體的大小包含後面沒用到的空白Padding都寄出去
                    //(struct sockaddr *)&dest_addr: 把剛剛準備好的信封傳進去，告訴系統要寄到哪裡
                    //使用計算出的 actual_len 發送
                    ssize_t sent_len = sendto(sockfd, &offer_packet, actual_len, 0,
                         (struct sockaddr *)&dest_addr, sizeof(dest_addr));
                    //sent_len < 0:如果發送失敗,可能忘記開啟 SO_BROADCAST 權限，或者網卡沒插線那sendto 會回傳 -1
                    if (sent_len < 0) {
                        log_message(LOG_ERROR, "Failed to send DHCPOFFER!");
                    } else {
                        log_message(LOG_INFO, "DHCPOFFER sent to 255.255.255.255:68");
                    }
                    //收到一個 DISCOVER,成功發送OFFER,任務完成,跳出switch
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
                    uint32_t requested_ip = 0;
                    get_dhcp_option(&recv_packet, 50, &requested_ip, sizeof(requested_ip));

                    // 3. 如果 Option 50 沒抓到，檢查 ciaddr (封包頭部)
                    if (requested_ip == 0 && recv_packet.ciaddr != 0) {
                        requested_ip = recv_packet.ciaddr;
                    }

                    printf("DEBUG: Requested_IP_HEX = 0x%08X\n", requested_ip);
                    printf("DEBUG: Assigned_IP_HEX  = 0x%08X\n", assigned_ip);

                    //如果client要求的IP與IP Pool中記錄不符合
                    // 1. 檢查是否真的有分配紀錄
                    if (assigned_ip == 0) {
                        log_message(LOG_WARNING, "assigned_ip is ZERO! record not found.");
                        send_dhcp_nak(sockfd, &recv_packet, &client_addr);
                        break;
                    }

                    if (requested_ip != 0) {
                        // 1. 將抓到的 requested_ip 統一視為網路序，轉成主機序
                        uint32_t req_host = ntohl(requested_ip);

                        // 2. 將 Pool 裡的 assigned_ip 統一視為網路序，轉成主機序
                        uint32_t ass_host = ntohl(assigned_ip);

                        // 3. 進行比較
                        if (req_host != ass_host) {
                            // 如果兩者轉成人類易讀的主機序後仍不相等，才代表 IP 真的不符
                            log_message(LOG_WARNING, "IP Mismatch! Client asked for %s, but Pool says %s",
                                        inet_ntoa(*(struct in_addr*)&requested_ip),
                                        inet_ntoa(*(struct in_addr*)&assigned_ip));
                            // 【關鍵優化】如果發現抓到的 IP 根本不在你的網段內 (例如 192.168.1.x)
                            // 則高機率是解析器 Offset 錯誤，這時「不要」發送 NAK，直接發 ACK 給正確的 IP
                            if ((req_host & 0xFFFFFF00) != (ass_host & 0xFFFFFF00)) {
                                log_message(LOG_ERROR, "Requested IP looks like garbage due to parsing error. Bypassing NAK.");
                            } else {
                                // 只有當要求的是同網段但不同 IP 時，才發 NAK
                                send_dhcp_nak(sockfd, &recv_packet, &client_addr);
                                return; // 或 break
                            }
                        }
                    }
                    // C. 如果一切正常 (requested_ip == assigned_ip 或續約流程)
                    log_message(LOG_INFO, "Validation Passed! Sending ACK.");

                    //準備發送ACK,初始化DHCPACK封包結構
                    struct dhcp_packet ack_packet;
                    memset(&ack_packet, 0, sizeof(ack_packet));
                    //基本欄位填充
                    ack_packet.xid = recv_packet.xid; //必須與Request的IP一致
                    ack_packet.op = 2;    //boot reply
                    ack_packet.htype = 1;  // 確保是 1
                    ack_packet.hlen = 6;   // 確保是 6

                    //從之前的 allocate_ip 或資料庫中找出該 MAC 對應的 IP
                    ack_packet.yiaddr = htonl(assigned_ip);    //正式將IP分配給client
                    memcpy(ack_packet.chaddr, recv_packet.chaddr, 6);
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
