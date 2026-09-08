#include "utils.h"
#include <pcap.h>
#include <iostream>

void list_devices() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return;
    }
    for (pcap_if_t* d = alldevs; d; d = d->next) {
        std::cout << (d->name ? d->name : "Unknown") << std::endl;
    }
    pcap_freealldevs(alldevs);
}