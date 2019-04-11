/**
 * @file main.cpp
 * @brief Simple TCP/UDP scanner of network ports.
 * @author Juraj Holub <xholub40>
 * @project IPK - project 2
 * @date April 2019
 */

#include <tuple>
#include <iostream>
#include <getopt.h>
#include <cstring>
#include <list>
#include "argument_parser.h"
#include "udp_scanner.h"
#include "tcp_scanner.h"

using namespace std;

int main(int argc, char **argv)
{
    // list where will be saved result of scanning, it will be printed at the end
    list<tuple<string, string>> scan_results;

    //parse command line arguments
    ArgumentParser parser = ArgumentParser(argc, argv);
    if (not parser.parse_args())
        return 1;

    //scan tcp ports
    TCP_Scanner tcp_scanner = TCP_Scanner(parser.iface);
    for (auto tcp_port : parser.tcp_ports)
    {
        string port = to_string(tcp_port);
        int res = tcp_scanner.scan_port(tcp_port, parser.ip_address);
        if (res == open)
            scan_results.push_back(make_tuple(port+"/tcp", "open"));
        else if (res == closed)
            scan_results.push_back(make_tuple(port+"/tcp", "closed"));
        else if (res == filtered)//scan possible filtered, try one more time
        {
            int second_try = tcp_scanner.scan_port(tcp_port, parser.ip_address); // try one more time
            if (second_try == open)
                scan_results.push_back(make_tuple(port+"/tcp", "open"));
            else if (second_try == closed)
                scan_results.push_back(make_tuple(port+"/tcp", "closed"));
            else if (second_try == filtered)
                scan_results.push_back(make_tuple(port+"/tcp", "filtered"));
        }
    }

    //scan udp ports
    UDP_Scanner udp_scanner = UDP_Scanner(parser.iface);
    for (auto udp_port : parser.udp_ports)
    {
        string port = to_string(udp_port);
        int res;
        for (int i = 0; i < 5; i++) // try scan 5 time if it is open
        {
            res = udp_scanner.scan_port(udp_port, parser.ip_address);
            if (res == closed)
            {
                scan_results.push_back(make_tuple(port+"/udp", "closed"));
                break;
            }
        }
        if (res == open)
            scan_results.push_back(make_tuple(port+"/udp", "open"));
    }

    //print results of scannig
    printf("%-20s%s\n", "PORT", "STATE");
    for (auto port : scan_results)
        printf("%-20s%s\n", get<0>(port).c_str(), get<1>(port).c_str());

    return 0;
}