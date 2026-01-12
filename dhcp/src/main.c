#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>    // 為了 memset, memcpy
#include <stdlib.h>    // 為了 exit() 或其他標準工具
#include "dhcp.h"
#include "ip_manager.h"
#include "../../common/include/logger.h"

extern int init_dhcp_socket();
extern int get_dhcp_option(struct dhcp_packet *packet, uint8_t code, void *out, int max_len);

int main(int argc, char *argv[]){
    //初始化logger
    init_logger();
    log_message(LOG_INFO, "Logger initialized successfully.");

    const char *start_ip = "192.168.1.200";
    // 如果用戶執行時有輸入參數，例如: ./dhcp_server 192.168.5.50
    if (argc > 1) {
        start_ip = argv[1];
    }

    // 初始化 IP Manager
    init_ip_pool(start_ip);
    log_message(LOG_INFO, "DHCP Server started. IP Pool starts from: %s", start_ip);

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
            uint32_t server_ip = inet_addr("192.168.1.1");    //定義伺服器IP為192.168.1.1,變數的類別是32位元變數
            uint32_t netmask = inet_addr("255.255.255.0");    // 定義網路遮罩為255.255.255.0,變數的類別是32位元變數
            uint32_t lease_time = htonl(3600);    //// 定義client被分配的租約時間為1hr(3600sec),變數的類別是32位元變數

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

                    offer_packet.xid = recv_packet.xid;//回傳xid
                    offer_packet.op = 2; // 設定訊息類型 (op)DHCP 規範中,1是代表Client寄出的請求(Request),2是代表Server寄出的回應(Reply)
                    offer_packet.yiaddr = offered_ip;//在yiaddr欄位填上藥指定的ip地址
                    memcpy(offer_packet.chaddr, recv_packet.chaddr, 6);  //複製硬體地址 (chaddr)
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

                    //檢查Server_Identifier(option 53),確保server找對台
                    uint32_t requested_server_ip = 0;
                    if(get_dhcp_option(&recv_packet, 54, &requested_server_ip, sizeof(requested_server_ip))){
                        //如果Server IP(Server_Identifier(option 53))不一樣,代表client正在呼叫別台DHCP Server
                        if(requested_server_ip != server_ip){
                            //顯示日誌:client正在尋找別台DHCP Server並跳出
                            log_message(LOG_INFO, "DHCPREQUEST is for another server (%s). Ignoring.", inet_ntoa(*(struct in_addr*)&requested_server_ip));
                            break;
                        }
                    }

                    //檢查Requested IP(Option 50)
                    uint32_t requested_ip = 0;
                    get_dhcp_option(&recv_packet, 50, &requested_ip, sizeof(requested_ip));

                    //檢查IP的的is_allocated是否=1(代表被分配過了)
                    //get_assigned_ip()檢查：1. 是否已分配 2. MAC 地址是否完全吻合
                    uint32_t assigned_ip = get_assigned_ip(recv_packet.chaddr);

                   //如果client要求的IP與IP Pool中記錄不符合
                    if(requested_ip != 0 && requested_ip != assigned_ip){
                        //先輸出日誌訊息後續再補nak
                        log_message(LOG_WARNING, "Client requested wrong IP, Send NAK.");
                        // Todo: 實作 send_dhcp_nak(sockfd, &recv_packet);
                        break;
                    }

                    //如果assigned_ip = 0代表沒有這台client的紀錄
                    if(assigned_ip == 0){
                        log_message(LOG_WARNING, "No record for this client, Igoring.");
                        break;
                    }

                    //準備發送ACK,初始化DHCPACK封包結構
                    struct dhcp_packet ack_packet;
                    memset(&ack_packet, 0, sizeof(ack_packet));
                    //基本欄位填充
                    ack_packet.xid = recv_packet.xid; //必須與Request的IP一致
                    ack_packet.op = 2;    //boot reply
                    //從之前的 allocate_ip 或資料庫中找出該 MAC 對應的 IP
                    ack_packet.yiaddr = assigned_ip;    //正式將IP分配給client
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
                    memcpy(ptr, &lease_time, 4);
                    ptr += 4;

                    //Option 1: Submask
                    *ptr++ = 1; *ptr++ = 4;
                    memcpy(ptr, &netmask, 4);
                    ptr += 4;

                    //Option 3: Router(Default Gateway, Usually is Server IP)
                    *ptr++ = 3; *ptr++ = 4;
                    memcpy(ptr, &server_ip, 4);
                    ptr += 4;

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
                        log_message(LOG_INFO, "DHCPACK sent! IP %s is now officially leased to Client.",
                                    inet_ntoa(*(struct in_addr*)&assigned_ip));
                    }

                    break;
                }
            }
        }

    }
}
