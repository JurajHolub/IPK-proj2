//
// Created by juraj on 05/04/19.
//

#ifndef PROJ2_TCP_SCANNER_H
#define PROJ2_TCP_SCANNER_H

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <pcap.h>
#include "scanner.h"

#define BUFSIZE 4096

struct tcp_csum_t {
    u_int32_t src_addr;
    u_int32_t dst_addr;
    u_int8_t pholder;
    u_int8_t proto;
    u_int16_t len;
};

class TCP_Scanner : public Scanner{
    char *buffer = (char*)malloc(sizeof(char)*BUFSIZ);
    int sock;
    struct iphdr *iphdr;
    struct tcphdr *tcphdr;
    struct sockaddr_in dest_address;
public:

    TCP_Scanner();
    void create_ip_hdr();
    void create_tcp_hdr();

    scan_result_e scan_port(int dst_port, string dst_addr);

};
#endif //PROJ2_TCP_SCANNER_H
