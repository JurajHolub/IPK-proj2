/**
 * @file udp_scanner.cpp
 * @brief Udp port scanner.
 * @author Juraj Holub <xholub40>
 * @project IPK - project 2
 * @date April 2019
 */

#ifndef PROJ2_UDP_SCANNER_H
#define PROJ2_UDP_SCANNER_H

#include <iostream>

#define PACKET_LEN 512

using namespace std;

struct ipheader_t {
    unsigned char       iph_ihl:5, iph_ver:4;
    unsigned char       iph_tos;
    unsigned short int  iph_len;
    unsigned short int  iph_ident;
    unsigned char       iph_flag;
    unsigned short int  iph_offset;
    unsigned char       iph_ttl;
    unsigned char       iph_protocol;
    unsigned short int  iph_chksum;
    unsigned int        iph_sourceip;
    unsigned int        iph_destip;
};

struct udpheader_t {
    unsigned short int udph_srcport;
    unsigned short int udph_destport;
    unsigned short int udph_len;
    unsigned short int udph_chksum;
};

class UDP_Scanner {
public:

    int src_port;
    int dst_port;
    string src_addr;
    string dst_addr;

    UDP_Scanner();

    int send_packet(int dst_port, string dst_addr);
    string get_local_ipaddr();

    unsigned short csum(unsigned short *buf, int nwords);
};

#endif //PROJ2_UDP_SCANNER_H
