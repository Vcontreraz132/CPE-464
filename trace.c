#include <stdio.h>
#include <stdlib.h>
#include "trace.h"
#include <pcap.h>
#include "smartalloc.h"

	int packet_num = 0;

	typedef struct {
		u_char *packet_buffer;
		int pack_total;
	} parser_data;

	void packet_parser(u_char *user_data, const struct pcap_pkthdr *header, const u_char *packet) {

		parser_data *data = (parser_data *)user_data;

		memcpy(data->packet_buffer, packet, header->len);
		int packet_total = data->pack_total;
					
		packet_num++;
		
		printf("Packet number: %d  Packet Len: %d\n\n",packet_num, header->len);

		struct enet_header *enet = (struct enet_header *)packet;

		ethernet_parser(packet);
		packet = packet + 14; // ethernet header is 14 bytes long, advance pointer
		
		switch(ntohs(enet->enet_type)) {
			case 0x0800:
				ip_parser(packet);
				
				const u_char *ip_packet = packet;

				struct IP_header *ip_head = (struct IP_header *)packet;
				uint8_t ip_head_len = (ip_head->version_IHL & 0x0F) * 4; // calc IP header length by masking verison and IHL field
				packet = packet + ip_head_len; // advance packet pointer
				
				if (packet_num < packet_total) {
					printf("\n");
				}

				switch(ip_head->protocol) {
					case 0x01:
						icmp_parser(packet);
						break;
					// case 0x02:
					// 	tcp_parser(packet, ip_packet);
					// 	break;
					case 0x06:
						tcp_parser(packet, ip_packet);
						break;
					case 0x11:
						udp_parser(packet, ip_packet);
						break;
					default:
						break;
				}
				break;


			case 0x0806:
				arp_parser(packet);
				packet = packet + 28; // ARP headers are 28 bytes
				break;
			default:
				printf("Error: Uknown header type");
				break;
		}

		if (packet_num < packet_total) {
			printf("\n");
		}

	}

	int packet_counter(pcap_t *handle) {
		int total_packs = 0;
		struct pcap_pkthdr *header;
		const u_char *packet;
		while(pcap_next_ex(handle, &header, &packet) == 1) {
			total_packs++;
		}
		return total_packs;
	}

	int main(int argc, char *argv[]) {

		//check for correct command line argument
		if(argc != 2) {
			fprintf(stderr, "Invalid command\n");
			//return error
			return 1;
		}
		//else continue

		// open the trace file

		char errbuf[PCAP_ERRBUF_SIZE];
		pcap_t *handle = pcap_open_offline(argv[1], errbuf);

		// if pcap_open_offline returns null, trace could not be opened
		if(handle == NULL) {
			fprintf(stderr, "ERROR: cannot open trace file\n");
			return 1;
		}

		u_char *packet_buffer = (u_char *)malloc(1500 * sizeof(u_char));
		if(packet_buffer == NULL) {
			fprintf(stderr, "Unable to allocate memory\n");
			pcap_close(handle);
			return 1;
		}

		parser_data data;
		data.packet_buffer = packet_buffer;
		data.pack_total = packet_counter(handle);
		
		pcap_close(handle);
		handle = pcap_open_offline(argv[1], errbuf);

		// instead of pcap_next_ex, use pcap_loop to read all packets
		printf("\n");
		int loop_return = pcap_loop(handle, -1, packet_parser, (u_char *)&data);


		if(loop_return == -1) {
			fprintf(stderr, "ERROR unable to read packet\n");
			pcap_close(handle);
			return 1;
		}

		free(packet_buffer);
		pcap_close(handle);

		return 0;
	}
