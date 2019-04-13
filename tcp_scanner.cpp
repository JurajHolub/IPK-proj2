/**
 * @file tcp_scanner.cpp
 * @brief Tcp port scanner. Based on sending SYN packets.
 * @author Juraj Holub <xholub40>
 * @project IPK - project 2
 * @date April 2019
 */

#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <cstring>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "scanner.h"
#include "tcp_scanner.h"
#include <pcap.h>
#include <iostream>
#include <stdio.h>
#include <time.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <signal.h>
#include <sys/un.h>

/**
 * Pointer to created pcab filter. Used in pcap_dispatch() which wait for incoming packets.
 */
pcap_t *tcp_handle;

scan_result_e tcp_scan_result = filtered; ///< Result of scanning.

/**
 * Callback function which handle situation if max time of waiting for response
 * packet is reached. We expected that packet is lost -> filtered by traffic.
 */
void tcp_dst_not_response(int sig)
{
    tcp_scan_result = filtered;
    pcap_breakloop(tcp_handle);
}

/**
 * Parse incoming packets from scanned port. Two situations could happend:
 * 1. We recieve packet with flags SYN and ACK -> port is open.
 * 2. We recieve packet with flags ACK and RST -> port is closed.
 * @param packet Incoming packet.
 */
void tcp_packet_handler(
        u_char *args,
        const struct pcap_pkthdr *header,
        const u_char *packet
)
{
    signal(SIGALRM, SIG_IGN);// i recieve msg, so it is not filtered, disable timer

    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;
    int link_layer_length;

    int link_type = pcap_datalink(tcp_handle);
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
        tcp_scan_result = closed;
        return;
    }

    int ip_header_length;

    const u_char *ip_header;
    const u_char *tcp_header;

    struct iphdr *iphdr;
    struct tcphdr *tcphdr;


    ip_header = packet + link_layer_length;
    iphdr = (struct iphdr*)ip_header;

    ip_header_length = ((*ip_header) & 0x0F);
    ip_header_length = ip_header_length * 4;

    tcp_header = packet + link_layer_length + ip_header_length;
    tcphdr = (struct tcphdr*)(tcp_header);

    if (iphdr->protocol != IPPROTO_TCP)
    {
        tcp_scan_result = closed;
        return;
    }

    //cout << "FIN: " << tcphdr->fin << "\n";
    //cout << "SYN: " << tcphdr->syn << "\n"; // SYN packet
    //cout << "RST: " << tcphdr->rst << "\n";
    //cout << "PSH: " << tcphdr->psh << "\n";
    //cout << "ACK: " << tcphdr->ack << "\n";
    //cout << "URG: " << tcphdr->urg << "\n";

    if (tcphdr->syn == 1 and tcphdr->ack == 1) // port is open
        tcp_scan_result = open;
    else if (tcphdr->ack == 1 and tcphdr->rst == 1) // port is closed
        tcp_scan_result = closed;
}

void TCP_Scanner::create_tcp_hdr()
{
    tcphdr->source = htons((5000+rand()%100)); // source port is random
    tcphdr->dest = dest_address.sin_port;
    tcphdr->seq = htonl(1);
    tcphdr->ack_seq = 0;
    tcphdr->doff = 5; //tcp hdr size
    tcphdr->window = htons(1024); //max win size
    tcphdr->check = 0;

    tcphdr->fin = 0;
    tcphdr->syn = 1; // SYN packet
    tcphdr->rst = 0;
    tcphdr->psh = 0;
    tcphdr->ack = 0;
    tcphdr->urg = 0;

    // tcp checksum calculation, see https://www.binarytides.com/raw-sockets-c-code-linux/
    struct csum_t tcp_csum;
    tcp_csum.src_addr = iphdr->saddr;
    tcp_csum.dst_addr = iphdr->daddr;
    tcp_csum.pholder = 0;
    tcp_csum.proto = IPPROTO_TCP;
    tcp_csum.len = htons(sizeof(struct tcphdr));
    char *tcp_csum_buff = (char *)malloc(sizeof(struct csum_t) + sizeof(struct tcphdr));
    memcpy(tcp_csum_buff, (char*)&tcp_csum, sizeof(struct csum_t));
    memcpy(tcp_csum_buff+ sizeof(struct csum_t), tcphdr, sizeof(struct tcphdr));

    tcphdr->check = csum((unsigned short*)tcp_csum_buff, sizeof(struct csum_t) + sizeof(struct tcphdr));

}

scan_result_e TCP_Scanner::scan_port(int dst_port, string dst_addr)
{
    memset(buffer, 0, BUFSIZE);

    dest_address.sin_addr.s_addr = inet_addr(dst_addr.c_str());
    dest_address.sin_port = htons(dst_port);
    dest_address.sin_family = AF_INET;

    create_ip_hdr(IPPROTO_TCP);
    create_tcp_hdr();

    if ((sock = socket(PF_INET, SOCK_RAW, IPPROTO_TCP)) < 0)
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

    // Create pcap filter which waiting for packet from scanned port.
    char error_buffer[PCAP_ERRBUF_SIZE];
    bpf_u_int32 net;
    string filter_exp = "tcp and src port "+to_string(dst_port)+" and src host "+dst_addr;
    struct bpf_program filter;
    tcp_handle = pcap_open_live(
            "any",
            BUFSIZ,
            false,
            1000,
            error_buffer
    );
    if (tcp_handle == NULL)
    {
        fprintf(stderr, "Could not open device \"lo\": %s\n", error_buffer);
        exit(2);
    }
    if (pcap_compile(tcp_handle, &filter, filter_exp.c_str(), 0, net) == -1)
    {
        printf("Bad filter - %s\n", pcap_geterr(tcp_handle));
        exit(2);
    }
    if (pcap_setfilter(tcp_handle, &filter) == -1)
    {
        printf("Error setting filter - %s\n", pcap_geterr(tcp_handle));
        exit(2);
    }

    // Send SYN packet
    if (sendto(sock, buffer, iphdr->tot_len, 0, (struct sockaddr *)&dest_address, sizeof(dest_address)) < 0)
    {
        perror("ERROR: sendto syn packet");
        exit(EXIT_FAILURE);
    }

    alarm(1);//Set max waiting delay for response packet.
    signal(SIGALRM, tcp_dst_not_response);
    pcap_loop(tcp_handle, 1, tcp_packet_handler, NULL);

    pcap_close(tcp_handle);
    close(sock);

    return tcp_scan_result;
}


