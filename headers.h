#indef HEADERS_H
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


