/**
 * @file udp_scanner.h
 * @brief Udp port scanner. Based on recieving ICMP port unreachable.
 * @author Juraj Holub <xholub40>
 * @project IPK - project 2
 * @date April 2019
 */

#ifndef PROJ2_UDP_SCANNER_H
#define PROJ2_UDP_SCANNER_H

#include <iostream>
#include "scanner.h"
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <pcap.h>

using namespace std;

class UDP_Scanner : public Scanner{
public:

    UDP_Scanner(string iface):Scanner(iface)
    {
        this->iface = iface;
        buffer = (char*)malloc(sizeof(char)*BUFSIZE);
        iphdr = (struct iphdr*)buffer;
        udphdr = (struct udphdr*)(buffer + sizeof(struct iphdr));
    };
    ~UDP_Scanner()
    {
        free(buffer);
    };

    scan_result_e scan_port(int dst_port, string dst_addr);
};

#endif //PROJ2_UDP_SCANNER_H
