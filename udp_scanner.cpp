/**
 * @file udp_scanner.cpp
 * @brief Udp port scanner.
 * @author Juraj Holub <xholub40>
 * @project IPK - project 2
 * @date April 2019
 */

#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "udp_scanner.h"
#include <cstring>

UDP_Scanner::UDP_Scanner()
{
    this->src_port = 8080;
    this->src_addr = get_local_ipaddr();
}

int UDP_Scanner::send_packet(int dst_port, string dst_addr)
{
    int sd;
    char buffer[PACKET_LEN];
    ipheader_t *ip = (ipheader_t *)buffer;
    udpheader_t *udp =(udpheader_t *)(buffer+ sizeof(ipheader_t));
    struct sockaddr_in addr;
    struct hostent *host;
    int one = 1;
    const int *val = &one;
    memset(buffer, 0, PACKET_LEN);

    if (!(host = gethostbyname((dst_addr.c_str()))))
    {
        cerr << "No such host as " << dst_addr << "\n";
        return 1;
    }

    bzero((char *)&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    bcopy((char *)host->h_addr_list[0], (char *)&addr.sin_addr.s_addr, host->h_length);
    addr.sin_port = htons(dst_port);

    sd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sd <= 0)
    {
        cerr << "Create socket error\n";
        return 1;
    }

    /*
    sin.sin_family = AF_INET;
    din.sin_family = AF_INET;

    sin.sin_port = htons(this->src_port);
    din.sin_port = htons(this->dst_port);

    sin.sin_addr.s_addr = inet_addr(this->src_addr.c_str());
    din.sin_addr.s_addr = inet_addr(this->dst_addr.c_str());

    ip->iph_ihl = 5;
    ip->iph_ver = 4;
    ip->iph_tos = 16;
    ip->iph_len = sizeof(ipheader_t) + sizeof(udpheader_t);
    ip->iph_ident = htons(54321);
    ip->iph_ttl = 64;
    ip->iph_protocol = 17; //UDP
    ip->iph_sourceip = inet_addr(this->src_addr.c_str());
    ip->iph_destip = inet_addr(this->dst_addr.c_str());
    ip->iph_chksum = csum((unsigned short *)buffer, sizeof(ipheader_t) + sizeof(udpheader_t));

    udp->udph_srcport = htons(this->src_port);
    udp->udph_destport = htons(this->dst_port);
    udp->udph_len = htons(sizeof(udpheader_t));

    if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
    {
        cerr << "Setsocket err.\n";
        return 1;
    }
*/
    socklen_t serverlen = sizeof(addr);
    if (sendto(sd, buffer, ip->iph_len, 0, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        cerr << "Sendto error.\n";
        return 1;
    }

    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(sd, &rfds);

    if (select(sd+1, &rfds, NULL, NULL, NULL) == -1)
    {
        cerr << "Select error.\n";
        return 1;
    }


    return 0;
}

unsigned short UDP_Scanner::csum(unsigned short *buf, int nwords)
{
    unsigned long sum;
    for (sum = 0; nwords > 0; nwords--)
        sum += *buf++;

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

string UDP_Scanner::get_local_ipaddr()
{
    char hostbuffer[256];
    struct hostent *hostentry;

    if (gethostname(hostbuffer, sizeof(hostbuffer)) == -1)
    {
        cerr << "Gethostname error.\n";
        return "";
    }

    if (!(hostentry = gethostbyname(hostbuffer)))
    {
        cerr << "Gethostbyname error\n";
        return "";
    }

    return string(inet_ntoa(*((struct in_addr*)hostentry->h_addr_list[0])));
}