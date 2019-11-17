#include "tcp_block.h"

char *block_host;
pcap_t* handle;

void usage() {
	printf("syntax: tcp_block <interface> <host>\n");
	printf("example: tcp_block wlan0 test.gilgil.net\n");
	return;
}

int main(int argc, char *argv[]) {
	if(argc != 3) {
		usage();
		return -1;
	}
	block_host = argv[2];
	char *dev = argv[1];

	//open pcap
	char errbuf[PCAP_ERRBUF_SIZE];
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

	while(true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == -1 || res == -2) {
			fprintf(stderr, "packet capture error");
			break;
		}

		if( host_check(packet) == 1) {
			int length = header->caplen;
			forward(packet, length);
			//backward(packet, length);
			printf("***%s is blocked\n", block_host);
		}
	}
}
