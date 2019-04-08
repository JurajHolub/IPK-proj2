/**
 * @file main.cpp
 * @brief Simple TCP/UDP scanner of network ports.
 * @author Juraj Holub <xholub40>
 * @project IPK - project 2
 * @date April 2019
 */

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
    ArgumentParser parser = ArgumentParser(argc, argv);
    if (not parser.parse_args())
        return 1;

    TCP_Scanner tcp_scanner;
    for (auto tcp_port : parser.tcp_ports)
    {
        switch (tcp_scanner.scan_port(tcp_port, parser.ip_address))
        {
            case open:
                cout << tcp_port << "/open\n";
                break;
            case closed:
                cout << tcp_port << "/closed\n";
                break;
            case filtered:
                cout << tcp_port << "/filtered\n";
                break;
        }
    }


    return 0;
}