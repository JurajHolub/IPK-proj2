/**
 * @file argument_parser.h
 * @brief Parsing of command line arguments.
 * @author Juraj Holub <xholub40>
 * @project IPK - project 2
 * @date April 2019
 */

#define MIN_PORT_RANGE 0
#define MAX_PORT_RANGE 65535

#include "argument_parser.h"
#include <sstream>
#include <algorithm>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>

bool ArgumentParser::parse_args()
{
    list<string> args_left;
    for (int i = 1; i < argc; i++)
        args_left.push_front(string(argv[i]));

    int opt;
    while ((opt = getopt_long_only(argc, argv, "", long_options, nullptr)) != -1)
    {
        if (opt == TCP_SCAN)
        {
            args_left.remove("-pt");
            args_left.remove(string(optarg));
            if (not parse_ports(this->tcp_ports, optarg, "TCP"))
                return false;
        }
        else if (opt == UDP_SCAN)
        {
            args_left.remove("-pu");
            args_left.remove(string(optarg));
            if (not parse_ports(this->udp_ports, optarg, "UDP"))
                return false;
        }
        else if (opt == IFACE)
        {
            args_left.remove("-i");
            args_left.remove(string(optarg));
            this->iface = string(optarg);
        }
    }

    if (args_left.size() == 1)
        this->ip_address = parse_ipaddr(args_left.front());

    if (this->iface.empty()) // user not set iface so I found one by myself
        this->iface = get_iface();

    return true;
}

bool ArgumentParser::try_set_port_range(vector<int>& ports, string raw_str)
{
    if (raw_str[0] == '-')
        return false;

    try
    {
        split_ports(ports, raw_str, '-');
        if (ports.size() == 2) // it is range interval
        {
            int bot = ports.at(0);
            int top = ports.at(1);
            ports.clear();
            for (int i = bot; i <= top; i++)
                ports.push_back(i);
        }
    }
    catch (InvalidPort& e)
    {
        return false;
    }
    return true;
}

bool ArgumentParser::parse_ports(vector<int> &ports, string raw_str, string protocol)
{
    bool success = try_set_port_range(ports, raw_str);
    if (success)
        return true;

    try
    {
        split_ports(ports, raw_str, ',');
        return true;
    }
    catch (InvalidPort& e)
    {
        cerr << "Invalid " << protocol << " port value: \"" << e.port << "\"\n";
    }

    return false;
}

void ArgumentParser::split_ports(vector<int>& items, const string &str, char delim)
{
    int port;
    string item;
    istringstream items_stream(str);

    while (getline(items_stream, item, delim))
    {
        if (is_digits(item))
        {
            istringstream str_to_int(item);
            str_to_int >> port;

            if (MIN_PORT_RANGE <= port and port <= MAX_PORT_RANGE)
                items.push_back(port);
            else throw(InvalidPort(item));
        }
        else throw(InvalidPort(item));
    }
}

bool ArgumentParser::is_digits(string str)
{
    return str.find_first_not_of("0123456789") == string::npos;
}

string ArgumentParser::parse_ipaddr(string domain)
{
    struct hostent *hostent = gethostbyname(domain.c_str());
    if (hostent == NULL)
    {
        herror("gethostbyname");
        exit(1);
    }

    char *ip_addr = inet_ntoa(*((struct in_addr*)hostent->h_addr_list[0]));

    return string(ip_addr);
}

string ArgumentParser::get_iface()
{
    pcap_if_t *devices;
    char errbuff[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&devices, errbuff))
    {
        perror("pcap_findalldevs");
        exit(1);
    }

    for (pcap_if_t *i = devices; i != NULL; i=i->next)
    {
        if (i->flags != PCAP_IF_LOOPBACK)
        {
            string name = i->name;
            pcap_freealldevs(devices);
            return name;
        }
    }
    pcap_freealldevs(devices);
    return "any";
}
