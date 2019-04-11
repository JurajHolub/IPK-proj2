/**
 * @file tcp_scanner.h
 * @brief Tcp port scanner. Based on sending SYN packets.
 * @author Juraj Holub <xholub40>
 * @project IPK - project 2
 * @date April 2019
 */

#ifndef PROJ2_TCP_SCANNER_H
#define PROJ2_TCP_SCANNER_H

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <pcap.h>
#include "scanner.h"
#include <string>

/**
 * TCP scanner which using SYN packet.
 */
class TCP_Scanner : public Scanner{
public:

    TCP_Scanner(string iface):Scanner(iface)
    {
        this->iface = iface;
        buffer = (char*)malloc(sizeof(char)*BUFSIZE);
        iphdr = (struct iphdr*)buffer;
        tcphdr = (struct tcphdr*)(buffer + sizeof(struct iphdr));
    };
    ~TCP_Scanner()
    {
        free(buffer);
    };

    /**
     * Fill raw tcp header of packets which will be send for scanning purposes.
     */
    void create_tcp_hdr();

    /**
     * Create TCP SYN packet and send it to destination port and addres and
     * check if it is open/closed or filtered.
     * @param dst_port Destination port.
     * @param dst_addr Ip address of destination port.
     * @return Result of scanning (open, closed, filtered).
     */
    scan_result_e scan_port(int dst_port, string dst_addr);

};

#endif //PROJ2_TCP_SCANNER_H
