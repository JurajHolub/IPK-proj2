//
// Created by juraj on 08/04/19.
//

#include <string>

#ifndef PROJ2_SCANNER_H
#define PROJ2_SCANNER_H

using namespace std;

enum scan_result_e {
    open, closed, filtered
};

class Scanner {
public:
    unsigned short csum(unsigned short *buffer,int size);
    string get_local_ipaddr();
};

#endif //PROJ2_SCANNER_H
