#include <stdio.h>
#include <stdlib.h>
#include "trace.h"
#include <pcap.h>

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

		struct pcap_pkthdr *header;
		const u_char *packet;

		int ex_return = pcap_next_ex(handle, &header, &packet); // pcap_next_ex returns a value based on success or failure

		if(ex_return == -1) {
			fprintf(stderr, "ERROR unable to read packet\n");
			pcap_close(handle);
			return 1;
		}

		printf("Packet length: %d bydes\n", header->len);

		pcap_close(handle);
		printf("Trace file closed\n");

		return 0;
	}
