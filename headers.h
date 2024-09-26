#indef HEADERS_H
#define HEADERS_H
#include <stdint.h>


// ethernet header struct
struct enet_header {
	uint8_t dest_addr[6];
	uint8_t src_addr[6];
	uint16_t enet_type;
}__attributes__((packed));

// ARP header struct
struct arp_header {
	uint16_t htype;
	uint16_t ptype;
	uint8_t hlen;
	uint8_t plen;
	uint16_t opcode;
	uint8_t src_mac[6];
	uint8_t src_ip[4];
	uint8_t dest_mac[6];
	uint8_t dest_ip[4];
}__attributes__((packed));
