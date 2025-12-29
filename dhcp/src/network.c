#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "dhcp.h"
#include "../../common/include/logger.h"
#include "logger.h"

#define INTERFACE_NAME "enp5s0" // 根據內部網卡名稱修改

/**
 * 初始化 DHCP UDP Socket
 */
int init_dhcp_socket() {
    int sockfd;
    int broadcast_enable = 1;
    struct sockaddr_in addr;

    // 1. 建立 UDP Socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        perror("socket");
        log_message(LOG_ERROR, "Socket creation failed!");
        return -1;
    }

    // 2. 允許廣播 (SO_BROADCAST)
    if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &broadcast_enable, sizeof(broadcast_enable)) < 0) {
        perror("setsockopt (SO_BROADCAST)");
        log_message(LOG_ERROR, "Failed to set SO_BROADCAST");
        close(sockfd);
        return -1;
    }

    // 3. 綁定 Port 67
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, INTERFACE_NAME, IFNAMSIZ - 1);
    //繼續寫綁定網卡的日誌輸出訊息,不然衝沙小都看不到
    if(setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) < 0) {
        log_message(LOG_ERROR, "Bind to device %s failed! (Are you sudo?)", INTERFACE_NAME);
        close(sockfd);
        return -1;
    }




    //要改成port 67
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(DHCP_SERVER_PORT);
    addr.sin_addr.s_addr = INADDR_ANY; // 監聽所有介面

    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        log_message(LOG_ERROR, "Bind to Port 67 failed! (Check if other DHCP server is running)");
        close(sockfd);
        return -1;
    }

    return sockfd;
}

/**
 * 從系統獲取指定網卡的 MAC 位址
 */
int get_my_mac(uint8_t *mac) {
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (fd < 0) return -1;

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, INTERFACE_NAME, IFNAMSIZ - 1);

    // 使用 ioctl 獲取硬體位址 (SIOCGIFHWADDR)
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl(SIOCGIFHWADDR)");
        close(fd);
        return -1;
    }

    close(fd);
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    
    printf("Local MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
           
    return 0;
}

/**
 * 簡易的 ARP Check (示意)
 * 實作中通常會發送一個 ARP Request 並等待回應
 */
int arp_check(uint32_t ip) {
    // 實務上這需要使用 Raw Socket 發送 ARP 封包
    // 這裡暫時回傳 SUCCESS 代表沒衝突
    printf("Performing ARP Check for %s...\n", inet_ntoa(*(struct in_addr *)&ip));
    return 0; // 0 = SUCCESS, 1 = CONFLICT
}
/**
 * 將 DHCP 取得的參數套用到系統網卡
 */
int apply_network_config(struct dhcp_client *client) {
    char cmd[256];
    char ip_str[16], mask_str[16], gw_str[16];

    // 將二進位 IP 轉為字串
    strcpy(ip_str, inet_ntoa(*(struct in_addr *)&client->offered_ip));
    strcpy(mask_str, inet_ntoa(*(struct in_addr *)&client->netmask));
    strcpy(gw_str, inet_ntoa(*(struct in_addr *)&client->gateway));

    // 1. 設定 IP 與 子網遮罩 (例如: ip addr add 192.168.1.10/24 dev eth0)
    // 這裡需要算遮罩長度，簡易做法可用 ifconfig
    sprintf(cmd, "sudo ifconfig %s %s netmask %s up", INTERFACE_NAME, ip_str, mask_str);
    system(cmd);

    // 2. 設定預設網關 (Default Gateway)
    sprintf(cmd, "sudo route add default gw %s %s", gw_str, INTERFACE_NAME);
    system(cmd);

    // 3. 設定 DNS (寫入 /etc/resolv.conf)
    // 取得 DNS Option 後執行：
    // sprintf(cmd, "echo \"nameserver %s\" > /etc/resolv.conf", dns_str);
    // system(cmd);

    return 0;
}

