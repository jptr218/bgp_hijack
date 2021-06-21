#pragma once

#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <iostream>
#include <vector>
#include <string>

#include <pcap/pcap.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include "packet.h"

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

using namespace std;

USHORT checksum(USHORT* buffer, int size);
void strToIp(const char* s, uint8_t* ip);
vector<string> getDevices();

bool open_conn(pcap_t* handle, uint8_t* target, uint8_t* ndest, uint8_t* gateway, uint32_t seq);
bool hijack(pcap_t* handle, uint8_t* target, uint8_t* odest, uint8_t* ndest, uint8_t* gateway, uint32_t seq);
bool keepalive(pcap_t* handle, uint8_t* target, uint8_t* ndest, uint8_t* gateway, uint32_t seq);
