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

    string tcp_ports;
    string udp_ports;
    string domain_name;
    string ip_address;

    ArgumentParser(int argc, char **argv)
    {
        this->argc = argc;
        this->argv = argv;
    }

    void parse_args();

    void parse_tcp_ports(string raw_str);
    bool is_digits(string str);
    vector<string> split_by_comma(string str);


};

#endif //PROJ2_ARGUMENT_PARSER_H
