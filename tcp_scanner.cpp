//
// Created by juraj on 05/04/19.
//
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "udp_scanner.h"
#include "tcp_scanner.h"
#include <cstring>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <stdio.h>
#include <time.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <signal.h>

pcap_t *handle;
scan_result_e scan_result;

void dst_not_response(int sig)
{
    scan_result = closed;
    pcap_breakloop(handle);
}

void my_packet_handler(
        u_char *args,
        const struct pcap_pkthdr *header,
        const u_char *packet
)
{
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP)
    {
        scan_result = closed;
        return;
    }

    int ethernet_header_length = 14; //always 14B
    int ip_header_length;

    const u_char *ip_header;
    const u_char *tcp_header;

    struct iphdr *iphdr;
    struct tcphdr *tcphdr;


    ip_header = packet + ethernet_header_length;
    iphdr = (struct iphdr*)ip_header;

    ip_header_length = ((*ip_header) & 0x0F);
    ip_header_length = ip_header_length * 4;

    tcp_header = packet + ethernet_header_length + ip_header_length;
    tcphdr = (struct tcphdr*)(tcp_header);

    if (iphdr->protocol != IPPROTO_TCP)
    {
        scan_result = closed;
        return;
    }


    //cout << "FIN: " << tcphdr->fin << "\n";
    //cout << "SYN: " << tcphdr->syn << "\n"; // SYN packet
    //cout << "RST: " << tcphdr->rst << "\n";
    //cout << "PSH: " << tcphdr->psh << "\n";
    //cout << "ACK: " << tcphdr->ack << "\n";
    //cout << "URG: " << tcphdr->urg << "\n";
    if (tcphdr->syn == 1 and tcphdr->ack == 1) // port is open
    {
        //cout << "port " << ntohs(tcphdr->source) << " is open\n";
        scan_result = open;
    }
    else if (tcphdr->ack == 1 and tcphdr->rst == 1) // port is closed
    {
        //cout << "port  " << ntohs(tcphdr->source) << " is closed\n";
        scan_result = closed;
    }
}

TCP_Scanner::TCP_Scanner()
{
    buffer = (char*)malloc(sizeof(char)*BUFSIZE);
    iphdr = (struct iphdr*)buffer;
    tcphdr = (struct tcphdr*)(buffer + sizeof(struct iphdr));
}

void TCP_Scanner::create_ip_hdr()
{
    iphdr->ihl = 5;
    iphdr->version = 4;
    iphdr->tos = 0;
    iphdr->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    iphdr->id = htons(20290); // port of this packet -> from range 49152 – 65535:Dynamic and/or Private Ports
    iphdr->frag_off = 0;
    iphdr->ttl = 64; // 64 hops
    iphdr->protocol = IPPROTO_TCP;
    iphdr->check = 0;
    iphdr->saddr = inet_addr(get_local_ipaddr().c_str());
    iphdr->daddr = dest_address.sin_addr.s_addr;
    iphdr->check = csum((unsigned short*)buffer, iphdr->tot_len);

}

void TCP_Scanner::create_tcp_hdr()
{
    tcphdr->source = htons(56800); // source port is random
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
    struct tcp_csum_t tcp_csum;
    tcp_csum.src_addr = iphdr->saddr;
    tcp_csum.dst_addr = iphdr->daddr;
    tcp_csum.pholder = 0;
    tcp_csum.proto = IPPROTO_TCP;
    tcp_csum.len = htons(sizeof(struct tcphdr));
    char *tcp_csum_buff = (char *)malloc(sizeof(struct tcp_csum_t) + sizeof(struct tcphdr));
    memcpy(tcp_csum_buff, (char*)&tcp_csum, sizeof(struct tcp_csum_t));
    memcpy(tcp_csum_buff+ sizeof(struct tcp_csum_t), tcphdr, sizeof(struct tcphdr));

    tcphdr->check = csum((unsigned short*)tcp_csum_buff, sizeof(struct tcp_csum_t) + sizeof(struct tcphdr));

}

    scan_result_e TCP_Scanner::scan_port(int dst_port, string dst_addr)
    {
        memset(buffer, 0, BUFSIZE);

        dest_address.sin_addr.s_addr = inet_addr(dst_addr.c_str());
        dest_address.sin_port = htons(dst_port);
        dest_address.sin_family = AF_INET;

        create_ip_hdr();
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

        char error_buffer[PCAP_ERRBUF_SIZE];
        bpf_u_int32 subnet_mask, net;
        string filter_exp = "src port "+to_string(dst_port)+" and host "+dst_addr;
        struct bpf_program filter;

        handle = pcap_open_live(
                "lo",
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
            perror("ERROR: sendto syn packet");
            exit(EXIT_FAILURE);
        }

        alarm(2);
        signal(SIGALRM, dst_not_response);
        pcap_loop(handle, 1, my_packet_handler, NULL);
        pcap_close(handle);
        close(sock);

        return scan_result;
    }


