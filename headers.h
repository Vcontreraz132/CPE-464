#ifndef HEADERS_H
#define HEADERS_H
#include <stdint.h>

#define LAN_addr_len 6 //define ethernet address size of 6 bytes
#define IP_addr_len 4 //define IP address size of 4 bytes

// ethernet header struct
struct enet_header {
	uint8_t dest_addr[LAN_addr_len];
	uint8_t src_addr[LAN_addr_len];
	uint16_t enet_type;
}__attributes__((packed));

// ARP header struct
struct arp_header {
	uint16_t htype;
	uint16_t ptype;
	uint8_t hlen;
	uint8_t plen;
	uint16_t opcode;
	uint8_t src_mac[LAN_addr_len];
	uint8_t src_ip[IP_addr_len];
	uint8_t dest_mac[LAN_addr_len];
	uint8_t dest_ip[IP_addr_len];
}__attributes__((packed));

// IP header struct
struct IP_header {
	uint8_t version_IHL;
	uint8_t TOS;
	uint16_t total_len;
	uint16_t ident;
	uint16_t flag_offset;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t checksum;
	uint8_t src_addr[IP_addr_len];
	uint8_t dest_addr[IP_addr_len];
}__attributes__((packed));

// ICMP header struct
struct ICMP_header {
	uint8_t type;
	uint8_t code;
	uint16_t checksum;
	uint16_t identifier;
	uint16_t sequence_num;
}__attributes__((packed));

// TCP header struct
struct TCP_header {
	uint16_t src_port;
	uint16_t dest_port;
	uint32_t sequence_num;
	uint32_t ack_num;
	uint8_t data_offset;
	uint8_t flags;
	uint16_t window_size;
	uint16_t checksum;
	uint16_t pointer;
}__attributes__((packed));

// UDP header struct
struct UDP_header {
	uint16_t src_port;
	uint16_t dest_port;
	uint16_t length;
	uint16_t checksum;
}__attributes__((packed));





#endif
