#ifndef TRACE_H
#define TRACE_H
#include <stdint.h>
#include <arpa/inet.h>
#include "checksum.h"
#include <string.h>
//#include <checksum.c>

#define LAN_addr_len 6 //define ethernet address size of 6 bytes
#define IP_addr_len 4 //define IP address size of 4 bytes

// ethernet header struct
struct enet_header {
	uint8_t dest_addr[LAN_addr_len];
	uint8_t src_addr[LAN_addr_len];
	uint16_t enet_type;
}__attribute__((packed));

static void print_mac_addr(uint8_t *mac) {
	printf("%x:%x:%x:%x:%x:%x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void ethernet_parser(const u_char *packet) {
	struct enet_header *eth = (struct enet_header *)packet;
	printf("\tEthernet Header\n");
	printf("\t\tDest MAC: ");
	print_mac_addr(eth->dest_addr);
	printf("\t\tSource MAC: ");
	print_mac_addr(eth->src_addr);
	printf("\t\tType: ");
	switch(ntohs(eth->enet_type)) {
		case 0x0800:
			printf("IP\n");
			break;
		case 0x0806:
			printf("ARP\n");
			break;
		default:
			printf("Uknown type\n");
			break;
	}
	printf("\n");
}

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
}__attribute__((packed));

static void print_ip_addr(uint8_t *ip) {
	printf("%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
}

static void arp_parser(const u_char *packet) {
	struct arp_header *arp = (struct arp_header *)packet;
	printf("\tARP Header\n");
	printf("\t\tOpcode: ");
	switch(ntohs(arp->opcode)) {
		case 0x0001:
			printf("Request\n");
			break;
		case 0x0002:
			printf("Reply\n");
			break;
		default:
			printf("Uknown Opcode\n");
			break;
	}
	printf("\t\tSender MAC: ");
	print_mac_addr(arp->src_mac);
	printf("\t\tSender IP: ");
	print_ip_addr(arp->src_ip);
	printf("\n");
	printf("\t\tTarget MAC: ");
	print_mac_addr(arp->dest_mac);
	printf("\t\tTarget IP: ");
	print_ip_addr(arp->dest_ip);
	printf("\n");
}


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
}__attribute__((packed));

static void ip_parser(const u_char *packet) {
	struct IP_header *ip = (struct IP_header *)packet;
	int unknown_protocol = 0;
	printf("\tIP Header\n");
	
	printf("\t\tTOS: 0x%x\n", ip->TOS);
	
	printf("\t\tTTL: %d\n", ip->ttl);
	
	printf("\t\tProtocol: ");
	switch(ip->protocol) {
		case 0x01:
			printf("ICMP\n");
			break;
		case 0x02:
			printf("IGMP\n");
			break;
		case 0x06:
			printf("TCP\n");
			break;
		case 0x11:
			printf("UDP\n");
			break;
		default:
			printf("Unknown\n");
			unknown_protocol = 1;
			break;
	}

	printf("\t\tChecksum: ");
	
	uint8_t ip_headlen = (ip->version_IHL & 0x0F) * 4;
	uint8_t buff[ip_headlen];
	memcpy(buff, packet, ip_headlen);
	uint16_t chksum = ntohs(ip->checksum);
	uint16_t calc_checksum = in_cksum((unsigned short *)buff, ip_headlen);

	(calc_checksum == 0) ? printf("Correct (0x%x)\n", chksum) : printf("Incorrect (0x%x)\n", chksum);

	printf("\t\tSender IP: ");
	print_ip_addr(ip->src_addr);
	printf("\n");
	
	printf("\t\tDest IP: ");
	print_ip_addr(ip->dest_addr);
	if(!unknown_protocol) {
		printf("\n");
	}
}

// ICMP header struct
struct ICMP_header {
	uint8_t type;
	uint8_t code;
	uint16_t checksum;
	uint16_t identifier;
	uint16_t sequence_num;
}__attribute__((packed));

static void icmp_parser(const u_char *packet) {
	struct ICMP_header *icmp = (struct ICMP_header *)packet;
	printf("\tICMP Header\n");
	printf("\t\tType: ");
	switch(icmp->type) {
		case 0x0:
			printf("Reply\n");
			break;
		case 0x08:
			printf("Request\n");
			break;
		default:
			printf("Unknown\n");
			break;
	}
	//printf("\n");
}

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
}__attribute__((packed));

static void port_printer(uint16_t port) {
	switch(port) {
		case 80:
			printf("HTTP\n");
			break;
		case 23:
			printf("Telnet\n");
			break;
		case 20:
			printf("FTP\n");
			break;
		case 21:
			printf("FTP\n");
			break;
		case 110:
			printf("Pop3\n");
			break;
		case 25:
			printf("SMTP\n");
			break;
		default:
			printf("%d\n", port);
			break;
	}
}

static void tcp_parser(const u_char *packet) {
	struct TCP_header *tcp = (struct TCP_header *)packet;
	printf("\tTCP Header\n");
	printf("\t\tSource Port: ");
	port_printer(tcp->src_port);
	printf("\t\tDestination Port: ");
	port_printer(tcp->dest_port);
	printf("\t\tSequence number: %u\n", ntohs(tcp->sequence_num));
	printf("\t\tAck Number: %u\n", ntohs(tcp->ack_num));
	printf("\t\tSYN flag: ");
	(tcp->flags == 0x02) ? printf("Yes\n") : printf("No\n");
	printf("\t\tReset flag: ");
	(tcp->flags == 0x04) ? printf("Yes\n") : printf("No\n");
	printf("\t\tFIN flag: ");
	(tcp->flags == 0x01) ? printf("Yes\n") : printf("No\n");
	printf("\t\tWindow Size: %u", ntohs(tcp->window_size));
	printf("\t\tChecksum: ");
	/*
	uint8_t TCP_headlen = (tcp->version_IHL & 0x0F) * 4;
	uint8_t buff[ip_headlen];
	memcpy(buff, packet, ip_headlen);
	uint16_t chksum = ntohs(ip->checksum);
	uint16_t calc_checksum = in_cksum((unsigned short *)buff, ip_headlen);
	(calc_checksum == 0) ? printf("Correct (0x%x)\n", chksum) : printf("Incorrect (0x%x)\n", chksum);
	*/
}

// UDP header struct
struct UDP_header {
	uint16_t src_port;
	uint16_t dest_port;
	uint16_t length;
	uint16_t checksum;
}__attribute__((packed));

static void udp_parser(const u_char *packet) {
	struct UDP_header *udp = (struct UDP_header *)packet;
	printf("\tUDP Header\n");
	printf("\t\tSource Port: ");
	port_printer(udp->src_port);
	printf("\t\tDestination Port ");
	port_printer(udp->dest_port);
	printf("\n");
}

#endif
