#include "tcp_block.h"

void print_IP(uint8_t* ip) {
  printf("%d.%d.%d.%d\n\n", ip[0], ip[1], ip[2], ip[3]);
  return;
}

void print_mac(uint8_t* mac) {
  printf("%02x:%02x:%02x:%02x:%02x:%02x\n\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return;
}

uint16_t IP_checksum(unsigned char* pk) {
	uint16_t tmp1 = 0, tmp2 = 0;
	uint32_t sum = 0;
	for(int i = 0; i < 20; i+=2) {
		tmp1 = (uint16_t)pk[i];
		tmp2 = (uint16_t)pk[i+1];
		sum = sum + ((tmp1 << 8) & 0xff00) + (tmp2 & 0x00ff);
	}

	while(sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	sum = ~sum;
	return (uint16_t)sum;
}

uint16_t tcp_checksum(unsigned char* pseudo_header, unsigned char* pk) {
	uint16_t tmp1 = 0, tmp2 = 0;
	uint32_t sum = 0;
	for(int i = 0; i < 12; i += 2) {
		tmp1 = (uint16_t)pseudo_header[i];
		tmp2 = (uint16_t)pseudo_header[i+1];
		sum = sum + ((tmp1 << 8) % 0xff00) + (tmp2 & 0x00ff);
	}
	for(int i = 0; i < 20; i += 2) {
		tmp1 = (uint16_t)pk[i];
		tmp2 = (uint16_t)pk[i+1];
		sum = sum + ((tmp1 << 8) % 0xff00) + (tmp2 & 0x00ff);
	}
	
	while(sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	sum = ~sum;
	return (uint16_t)sum;
}

int host_check(const unsigned char *data) {
	uint8_t ip_header_length, tcp_header_length;
        ip_header_length = (data[0] & 0x0F) * 4;
        tcp_header_length = ((data[ip_header_length + 12] & 0xF0) >> 4) * 4;
        int http_offset = ip_header_length + tcp_header_length;
        int k;
        char method[6][10] = {"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS"};

        //check tcp segment is http
        for(k = 0; k < 6; k++) {
                if(!memcmp(data + http_offset, method[k], strlen(method[k]))){
                        break;
                }
        }
        int i = 0;

        //check captured host in block_host vector
        if(k != 6) {
                while(1) {
                        if(!memcmp(data + http_offset + i, "Host: ", 6)) {
                                i += 6;
                                char *captured_host;
                                int length = 0;
                                while(1) {
                                        if(!memcmp(data + http_offset + i, "\r\n", 2)) {
                                                break;
                                        }
                                        i++;
					length++;
				}
				memcpy(captured_host, data + http_offset + i, length);
				if(!memcmp(captured_host, block_host, length)) {
					return 1;
				}
                                break;
                        }
                        i++;
                }
        }
        return 0;
}

void forward(const unsigned char *pk, int length) {
	//send rst packet
	unsigned char rst[54];
	memcpy(rst, pk, 54);
	rst[15] = 0x44; //Differentiated Services Field
	rst[16] = 0x00; 
	rst[17] = 0x28; //Total Length
	rst[22] = 0xff; //Time to live
	memset(rst+24, 0x00, 2); //Set ip checksum 0x00
	uint16_t checksum = htons(IP_checksum(rst + 14));
	memcpy(rst+24, &checksum, 2); //Calculate ip checksum
	uint32_t seq_num;
	memcpy(&seq_num, pk+38, 4);
	seq_num = htons(seq_num + length - 53);
	memcpy(rst+38, &seq_num, 4); //Set tcp sequence num
	rst[47] = 0x14; //Set rst flg
	memset(rst+48, 0x00, 6);
	unsigned char pseudo_header[12]; //make pseudo header for tcp checksum
	memcpy(pseudo_header, pk+26, 4);
	memcpy(pseudo_header+4, pk+30, 4);
	pseudo_header[8] = 0x00;
	pseudo_header[9] = 0x06;
	memcpy(pseudo_header+10, "0x0020", 2);
	checksum = htons(tcp_checksum(pseudo_header, rst+34));
	memcpy(rst+34, &checksum, 4); //Calculate tcp checksum

	pcap_sendpacket(handle, rst, 54);

	//send fin packet
	unsigned char fin[54];
	memcpy(fin, rst, 54);
	fin[15] = 0x00; //Differentiated Services Field
	memset(fin+24, 0x00, 2);
	checksum = htons(IP_checksum(fin+14));
	memcpy(fin+24, &checksum, 2); //Calculate ip checksum
	fin[47] = 0x11; //Set fin flg
	memset(fin+48, 0x00, 6);
	checksum = htons(tcp_checksum(pseudo_header, fin+34));
	memcpy(fin+34, &checksum, 4); //Calculate tcp checksum

	pcap_sendpacket(handle, fin, 54);

	backward(rst, fin, length);
	return;
}

void backward(unsigned char *RST, unsigned char *FIN, int length) {
	//send rst packet
	unsigned char rst[54];
	memcpy(rst, RST, 54);
	swap_ranges(rst, rst+6, rst+6);
	swap_ranges(rst+26, rst+30, rst+30);
	swap_ranges(rst+34, rst+36, rst+36);
	swap_ranges(rst+38, rst+42, rst+42);
	pcap_sendpacket(handle, rst, length);	

	//send fin packet
	unsigned char fin[54];
	memcpy(fin, FIN, 54);
	swap_ranges(fin, fin+6, fin+6);
	swap_ranges(fin+26, fin+30, fin+30);
	swap_ranges(fin+34, fin+36, fin+36);
	swap_ranges(fin+38, fin+42, fin+42);
	pcap_sendpacket(handle, fin, length);

	return;
}

