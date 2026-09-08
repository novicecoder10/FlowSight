#include "sniffer.h"
#include <string>
#include <iostream>

int main(int argc, char* argv[]) {
    std::string device = "any";
    if (argc > 1 && argv[1] && argv[1][0] != '\0') {
        device = argv[1];
    }
    start_sniffing(device.c_str());
    return 0;
}