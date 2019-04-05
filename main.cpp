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

using namespace std;

int main(int argc, char **argv) {

    ArgumentParser parser = ArgumentParser(argc, argv);
    parser.parse_args();

    return 0;
}