#include <stdio.h>
#include <stdlib.h>
#include "trace.h"
#include <pcap.h>

	void packet_parser(u_char *user_data, const struct pcap_pkthdr *header, const u_char *packet) {
		(void)user_data;
		printf("Packet length: %d bytes\n", header->len);

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

		// int ex_return = pcap_next_ex(handle, &header, &packet); // pcap_next_ex returns a value based on success or failure
		// instead of pcap_next_ex, use pcap_loop to read all packets
		int loop_return = pcap_loop(handle, -1, packet_parser, NULL);


		if(loop_return == -1) {
			fprintf(stderr, "ERROR unable to read packet\n");
			pcap_close(handle);
			return 1;
		}

		pcap_close(handle);
		printf("Trace file closed\n");

		return 0;
	}
