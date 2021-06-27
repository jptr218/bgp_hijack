#pragma once
#include "alastor.h"

struct ether_header
{
	uint8_t  dest[6];
	uint8_t  src[6];
	uint16_t type;
};

struct ip_hdr
{
	uint8_t ihl : 4;
	uint8_t ver : 4;
	uint8_t ecn : 2;
	uint8_t dscp : 6;
	uint16_t len;
	uint16_t id;
	uint16_t fOff : 13;
	uint16_t flags : 3;
	uint8_t ttl;
	uint8_t proto;
	uint16_t csum;
	uint8_t src[4];
	uint8_t dest[4];
};

struct tcp_hdr {
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t seq;
	uint32_t ack_seq;
	uint16_t res1 : 4;
	uint16_t doff : 4;
	uint16_t fin : 1;
	uint16_t syn : 1;
	uint16_t rst : 1;
	uint16_t psh : 1;
	uint16_t ack : 1;
	uint16_t urg : 1;
	uint16_t ece : 1;
	uint16_t cwr : 1;
	uint16_t window_size;
	uint16_t checksum;
	uint16_t urgent_p;
};

uint8_t bgp_update_prebuilt[46] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0x00, 0x2e, 0x02, 0x00, 0x00, 0x00, 0x12, 0x00,
	0x01, 0x01, 0x00, 0x00, 0x02, 0x04, 0x02, 0x01, 0x00, 0x00, 0x00, 0x03,
	0x04, 0x0c, 0x22, 0x38, 0x4e, 0x20, 0x01, 0x02, 0x03, 0x04
};
