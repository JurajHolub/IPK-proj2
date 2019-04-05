/**
 * @file argument_parser.h
 * @brief Parsing of command line arguments.
 * @author Juraj Holub <xholub40>
 * @project IPK - project 2
 * @date April 2019
 */

#include "argument_parser.h"
#include <sstream>
#include <algorithm>
#include <boost/algorithm/string.hpp>

void ArgumentParser::parse_args()
{
    list<string> args_left;
    for (int i = 1; i < argc; i++)
        args_left.push_front(string(argv[i]));

    while ((opt = getopt_long_only(argc, argv, "", long_options, nullptr)) != -1)
    {
        if (opt == TCP_SCAN)
        {
            args_left.remove("-pt");
            args_left.remove(string(optarg));
            this->tcp_ports = string(optarg);
            parse_tcp_ports(optarg);
        }
        else if (opt == UDP_SCAN)
        {
            args_left.remove("-pu");
            args_left.remove(string(optarg));
            this->udp_ports = string(optarg);
        }
    }

    for (auto i: args_left)
        cout << i << "\n";

}

void ArgumentParser::parse_tcp_ports(string raw_str)
{
    cout << raw_str << " ";
    if (is_digits(raw_str))
        cout << " valid string\n";
    else
        cout << " invalid string\n";

    int port;
    istringstream is_int(raw_str);
    is_int >> port;
    cout << port << "\n";
}

vector<string> ArgumentParser::split_by_comma(std::string str)
{
    vector<string> items;
    boost::split(items, str, [](char c){return c == ',';});
    return items;
}

bool ArgumentParser::is_digits(string str)
{
    return str.find_first_not_of("0123456789") == string::npos;
}
