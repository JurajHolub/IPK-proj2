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
#include <signal.h>
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <stdio.h>
#include <time.h>
#include <netinet/if_ether.h>

/**
 * Pointer to created pcab filter. Used in pcap_dispatch() which wait for incoming packets.
 */
pcap_t *handle;
scan_result_e udp_scan_result = open; ///< Result of scanning.

/**
 * Callback function which handle situation if max time of waiting for response
 * packet is reached. If we didn't recieve ICMP packet than port is possibly open.
 */
void udp_dst_not_response(int sig)
{
    pcap_breakloop(handle);
}

/**
 * Parse incoming packets from scanned port. It must be ICMP packetype 3 (port unreachable).
 * @param packet Incoming packet.
 */
void udp_packet_handler(
        u_char *args,
        const struct pcap_pkthdr *header,
        const u_char *packet
)
{
    signal(SIGALRM, SIG_IGN);// i recieve msg, so it is not filtered, disable timer

    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;
    int link_layer_length;

    int link_type = pcap_datalink(handle);
    if (link_type == DLT_LINUX_SLL)
    {
        link_layer_length = 16; // It is Linux cooked capture -> always 16B
    }
    else if (ntohs(eth_header->ether_type) == ETHERTYPE_IP)
    {
        link_layer_length = 14; // It is ethernet -> always 14B
    }
    else
    {
        udp_scan_result = open;
        return;
    }

    int ip_header_length;

    const u_char *ip_header;
    const u_char *icmp_header;

    struct iphdr *iphdr;
    struct icmp6_hdr *icmphdr;


    ip_header = packet + link_layer_length;
    iphdr = (struct iphdr*)ip_header;

    ip_header_length = ((*ip_header) & 0x0F);
    ip_header_length = ip_header_length * 4;

    icmp_header = packet + link_layer_length + ip_header_length;
    icmphdr = (struct icmp6_hdr*)(icmp_header);

    if (iphdr->protocol != IPPROTO_ICMP)
    {
        udp_scan_result = open;
        return;
    }

    if (icmphdr->icmp6_type == 3 and icmphdr->icmp6_code == 3)
    {
        udp_scan_result = closed;
    }
}

scan_result_e UDP_Scanner::scan_port(int dst_port, string dst_addr)
{
    memset(buffer, 0, BUFSIZE);

    dest_address.sin_addr.s_addr = inet_addr(dst_addr.c_str());
    dest_address.sin_port = htons(dst_port);
    dest_address.sin_family = AF_INET;

    create_ip_hdr(IPPROTO_UDP);

    udphdr->source = htons((5000+rand()%100)); // source port is random
    udphdr->dest = dest_address.sin_port;
    udphdr->len = htons(sizeof(struct udphdr));

    // udp checksum calculation, see https://www.binarytides.com/raw-sockets-c-code-linux/
    struct csum_t udp_csum;
    udp_csum.src_addr = iphdr->saddr;
    udp_csum.dst_addr = iphdr->daddr;
    udp_csum.pholder = 0;
    udp_csum.proto = IPPROTO_UDP;
    udp_csum.len = htons(sizeof(struct udphdr));
    char *csum_buff = (char *)malloc(sizeof(struct csum_t) + sizeof(struct udphdr));
    memcpy(csum_buff, (char*)&udp_csum, sizeof(struct csum_t));
    memcpy(csum_buff+ sizeof(struct csum_t), udphdr, sizeof(struct udphdr));

    udphdr->check = csum((unsigned short*)csum_buff, sizeof(struct csum_t) + sizeof(struct udphdr));


    if ((sock = socket(PF_INET, SOCK_RAW, IPPROTO_UDP)) < 0)
    {
        perror("ERROR: socket");
        exit(EXIT_FAILURE);
    }

    int one = 1;
    const int *val = &one;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
    {
        perror("ERROR: setsockopt");
        exit(EXIT_FAILURE);
    }

    char error_buffer[PCAP_ERRBUF_SIZE];
    bpf_u_int32 subnet_mask, net;
    string filter_exp = "icmp and src host "+dst_addr;
    struct bpf_program filter;

    handle = pcap_open_live(
            "any",
            BUFSIZ,
            false,
            1000,
            error_buffer
    );
    if (handle == NULL)
    {
        fprintf(stderr, "Could not open device \"lo\": %s\n", error_buffer);
        exit(2);
    }
    if (pcap_compile(handle, &filter, filter_exp.c_str(), 0, net) == -1)
    {
        printf("Bad filter - %s\n", pcap_geterr(handle));
        exit(2);
    }
    if (pcap_setfilter(handle, &filter) == -1)
    {
        printf("Error setting filter - %s\n", pcap_geterr(handle));
        exit(2);
    }
    if (sendto(sock, buffer, iphdr->tot_len, 0, (struct sockaddr *)&dest_address, sizeof(dest_address)) < 0)
    {
        perror("ERROR: sendto udp packet");
        exit(EXIT_FAILURE);
    }

    alarm(1);
    signal(SIGALRM, udp_dst_not_response);
    pcap_dispatch(handle, 1, udp_packet_handler, NULL);

    pcap_close(handle);
    close(sock);

    return udp_scan_result;
}
