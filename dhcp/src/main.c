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

    //init socket
    sockfd = init_dhcp_socket();
    if (sockfd < 0){
        log_message(LOG_ERROR, "Failed to initailize DHCP Socket.");
        return 1;
    }
    printf("DHCP Server detection is starting..., listed on port 67\n");

    while(1){
        printf("Waiting for DHCP packets...\n");
    }
}
