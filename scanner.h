//
// Created by juraj on 08/04/19.
//

#include <string>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <pcap.h>

#ifndef PROJ2_SCANNER_H
#define PROJ2_SCANNER_H

#define BUFSIZE 4096

using namespace std;

/**
 * Result of scanning.
 */
enum scan_result_e {
    open, ///< Port is open.
    closed, ///< Port is closed.
    filtered ///< Port is filtered.
};

/**
 * Pseudo header used for checksum calculations. Inspired by binarytidies.
 * @see https://www.binarytides.com/raw-udp-sockets-c-linux/
 */
struct csum_t {
    u_int32_t src_addr;
    u_int32_t dst_addr;
    u_int8_t pholder;
    u_int8_t proto;
    u_int16_t len;
};

/**
 * Parent class of TCP or UDP scanners. Contain functionality which uses
 * both child classes (UDP and TCP scanners).
 */
class Scanner {
protected:
    char *buffer; ///< Packet data which scanner sent.
    int sock; ///< Id of socket which will be created for purpose of port scanning.
    struct iphdr *iphdr; ///< Ip header of packet which will be sent.
    struct tcphdr *tcphdr; ///< Tcp header of packet in case of TCP scanning.
    struct udphdr *udphdr; ///< Udp header of packet in case of UDP scanning.
    struct sockaddr_in dest_address; ///< Address where will be packet send.
    string iface; ///< Name of ethernet interface.
    string ipv4_addr; ///< IPv4 address of this machine.
    string ipv6_addr; ///< IPv4 address of this machine.
    string lo_addr; ///< IP addr of localhost.
public:

    Scanner(string iface)
    {
        this->iface = iface;
    };
    /**
     * Calculate checksum of input data from buffer. Inspired by binarytidies.
     * @see https://www.binarytides.com/raw-sockets-c-code-linux/
     * @param buffer Input data over which checksum is calculated.
     * @param size Number of bytes in buffer.
     * @return Calculated checksum.
     */
    unsigned short csum(unsigned short *buffer,int size);
    /**
     * Found ip-addres of machine where program is running.
     * @return Ip addres of actual machine.
     */
    string get_local_ipaddr();
    /**
     * Fill ip header of raw UDP or TCP packet.
     * @param transport_layer Type of transport layer IPPROTO_TCP / IPPROTO_UDP.
     */
    void create_ip_hdr(int transport_layer);
    void find_iface(string dst_addr);
};

#endif //PROJ2_SCANNER_H
