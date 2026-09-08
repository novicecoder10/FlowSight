#pragma once
#include <pcap.h>
#include <string>

void start_sniffing(const char* device);
void send_ipfix(const std::string& ipfix_data);