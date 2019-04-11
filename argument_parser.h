/**
 * @file argument_parser.cpp
 * @brief Parsing of command line arguments.
 * @author Juraj Holub <xholub40>
 * @project IPK - project 2
 * @date April 2019
 */

#ifndef PROJ2_ARGUMENT_PARSER_H
#define PROJ2_ARGUMENT_PARSER_H

#define TCP_SCAN 0
#define UDP_SCAN 1
#define IFACE 2

#include <stropts.h>
#include <getopt.h>
#include <list>
#include <iostream>
#include <vector>

using namespace std;

/**
 * Parse command line argument (tcp/udp ports, domain-name/ip-addr, ethernet
 * interface).
 */
class ArgumentParser {

private:
    int argc; ///< Number of command line arguments.
    char **argv; ///< Array of command line arguments.
    /**
     * Inicialised options for getopt_long_only().
     */
    const struct option long_options[3] = {
            {"pt" ,required_argument, 0, TCP_SCAN},
            {"pu" ,required_argument, 0, UDP_SCAN},
            {"i" , required_argument, 0, IFACE},
    };

public:

    vector<int> tcp_ports; ///< Parsed tcp ports.
    vector<int> udp_ports; ///< Parsed udp ports.
    string ip_address; ///< Parsed ip-addres.
    /**
     * Parsed interface (or by default first ethernet interface which is found
     * on this machine.
     */
    string iface;

    ArgumentParser(int argc, char **argv)
    {
        this->iface = "";
        this->argc = argc;
        this->argv = argv;
    }

    /**
     * Parse command line arguments.
     * @return True if command line match else false.
     */
    bool parse_args();
    /**
     * If command line port is actually range(e.g. 25-50) not just enumeration.
     * @param ports Filled vector of port interval.
     * @param raw_str Input string which is parsed.
     * @return True if it is port range (then ports contain valid data) else false.
     */
    bool try_set_port_range(vector<int>& ports, string raw_str);
    /**
     * Parse raw string which should contain port numbers.
     * @param ports Outpud vector of parsed ports.
     * @param raw_str Input string of ports.
     * @param protocol Type of port protocol.
     * @return True if input string is valid.
     */
    bool parse_ports(vector<int> &ports, string raw_str, string protocol);
    /**
     * Check if string is valid integer.
     * @param str Input string.
     * @return True if string is number else false.
     */
    bool is_digits(string str);
    /**
     * Split string of ports by passed delimeter.
     * @param items Output vector of parsed ports.
     * @param str Input raw string.
     * @param delim Delimeter which split string to substrings.
     */
    void split_ports(vector<int>& items, const string &str, char delim);
    /**
     * Validate and parse ip-addres or domain name to ip-addres.
     * @param str Input string which should contain ip addres or domain name.
     * @return Parsed ip addres
     */
    string parse_ipaddr(string str);
    /**
     * Search for first ethernet interface. Use pcap library.
     * @return Name of first ethernet interface or 'any' if not found.
     */
    string get_iface();

};

/**
 * Exception class for catching invalid port exception.
 */
class InvalidPort
{
public:
    string port; ///< Value of invalid port.
    InvalidPort(string port)
    {
        this->port = port;
    }

};

#endif //PROJ2_ARGUMENT_PARSER_H
