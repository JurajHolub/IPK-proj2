//
// Created by juraj on 08/04/19.
//

#include "scanner.h"
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

/**
 * @brief Simple checksum function inspired by binarytidies.
 * @see https://www.binarytides.com/raw-sockets-c-code-linux/
 */
unsigned short Scanner::csum(unsigned short *buffer,int size)
{
    long sum = 0;
    unsigned short oddbyte;

    while (size > 1)
    {
        sum += *buffer++;
        size -= 2;
    }

    if (size == 1)
    {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)buffer;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    return ~sum;
}

string Scanner::get_local_ipaddr()
{
    int sock;
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("ERROR: socket");
        exit(EXIT_FAILURE);
    }
    int domain_name_server_port = 53;
    struct sockaddr_in addr;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("8.8.8.8"); // google public dns ip https://developers.google.com/speed/public-dns/docs/using
    addr.sin_port = htons(domain_name_server_port);

    if (connect(sock, (const struct sockaddr *) &addr, sizeof(addr)) != 0)
    {
        perror("ERROR: connect");
        exit(EXIT_FAILURE);
    }
    struct sockaddr_in name;
    socklen_t len = sizeof(name);

    if (getsockname(sock, (struct sockaddr*)&name, &len) != 0)
    {
        perror("ERROR: getsockname");
        exit(EXIT_FAILURE);
    }

    char buff[256];
    inet_ntop(AF_INET, &name.sin_addr, buff, 256);
    close(sock);

    return string(buff);
}
