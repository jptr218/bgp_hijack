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

vector<string> getDevices() {
	vector<string> o;
	pcap_if_t* d;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (pcap_findalldevs(&d, errbuf) == -1)
	{
		cout << "This program requires the WinPCap driver." << endl;
		exit(E_ABORT);
	}

	for (; d != nullptr; d = d->next) {
		o.push_back(d->name);
	}

	return o;
}