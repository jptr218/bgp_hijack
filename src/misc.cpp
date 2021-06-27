#include "alastor.h"

USHORT checksum(USHORT* buffer, int size)
{
	unsigned long cksum = 0;

	while (size > 1)
	{
		cksum += *buffer++;
		size -= sizeof(USHORT);
	}
	if (size)
	{
		cksum += *(UCHAR*)buffer;
	}
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);

	return (USHORT)((~cksum) & 0xffff);
}

void strToIp(const char* s, uint8_t* ip) {
	char temp_c;
	uint8_t oi = 0;
	uint8_t op = 0;
	for (uint8_t i = 0; i < strlen(s); i++) {
		temp_c = s[i];
		if (temp_c == '.') {
			ip[op] = oi;
			oi = 0;
			op += 1;
		}
		else {
			oi *= 10;
			oi += temp_c - '0';
		}
	}
	ip[op] = oi;
}

vector<iface> getDevices() {
	vector<iface> o;
	pcap_if_t* d;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (pcap_findalldevs(&d, errbuf) == -1)
	{
		cout << "This program requires the WinPCap driver." << endl;
		exit(E_ABORT);
	}

	for (; d != nullptr; d = d->next) {
		iface i;
		i.name = string(d->name);
		for (pcap_addr_t* a = d->addresses; a != NULL; a = a->next) {
			if (a->addr->sa_family == AF_INET) {
				strToIp(inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr), i.ip);
			}
		}
		o.push_back(i);
	}

	return o;
}
