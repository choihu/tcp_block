#include <stdint.h>
#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <algorithm>
#include <vector>
using namespace std;

extern char* block_host;
extern pcap_t* handle;

void print_IP(uint8_t* ip);
void print_mac(uint8_t* mac);
uint16_t IP_checksum(unsigned char* pk);
uint16_t tcp_checksum(unsigned char* pseudo_header, unsigned char* pk);
int host_check(const unsigned char *data);
void forward(const unsigned char *pk, int length);
void backward(const unsigned char *pk, int length);

