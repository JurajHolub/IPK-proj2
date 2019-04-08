/**
 * @file argument_parser.h
 * @brief Parsing of command line arguments.
 * @author Juraj Holub <xholub40>
 * @project IPK - project 2
 * @date April 2019
 */

#ifndef PROJ2_ARGUMENT_PARSER_H
#define PROJ2_ARGUMENT_PARSER_H

#define TCP_SCAN 0
#define UDP_SCAN 1

#include <stropts.h>
#include <getopt.h>
#include <list>
#include <iostream>
#include <vector>

using namespace std;

class ArgumentParser {

private:
    int argc;
    char **argv;
    int opt;
    const struct option long_options[2] = {
            {"pt" ,required_argument, 0, TCP_SCAN},
            {"pu" ,required_argument, 0, UDP_SCAN}
    };

public:

    vector<int> tcp_ports;
    vector<int> udp_ports;
    string ip_address;

    ArgumentParser(int argc, char **argv)
    {
        this->argc = argc;
        this->argv = argv;
    }

    bool parse_args();

    bool try_set_port_range(vector<int>& ports, string raw_str);
    bool parse_ports(vector<int> &ports, string raw_str, string protocol);
    bool is_digits(string str);
    void split_ports(vector<int>& items, const string &str, char delim);
    string parse_ipaddr(string str);

};

class InvalidPort
{
public:
    string port;
    InvalidPort(string port)
    {
        this->port = port;
    }

};

#endif //PROJ2_ARGUMENT_PARSER_H
