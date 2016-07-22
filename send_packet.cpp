#define _WINSOCKAPI_   
#include <windows.h>	

#include <IPHlpApi.h>	
#pragma comment(lib, "iphlpapi.lib")

#include <stdlib.h>
#include <stdio.h>
#define HAVE_REMOTE
#include <pcap\pcap.h>

#define IP 0x800
#define UDP 17
#define tcp 6

unsigned int my_ip;
unsigned int my_mac;
unsigned int Gateway;
unsigned int vip;
unsigned int vmac;


//* 4 bytes IP address */

struct ethernet {
	unsigned char eth_dst_addr[6];
	unsigned char eth_src_addr[6];
	unsigned short frame_type; // 0x0806 (ARP)
};

struct arp {
	unsigned short hard_type;	// 0x0001 (Ethernet)
	unsigned short prot_type;	// 0x0800 (IP)
	unsigned char hard_size;	// 6
	unsigned char prot_size;	// 4
	unsigned short op;			// 0x0001 (ARP request) 0x0002 (ARP reply)
	unsigned char sender_eth_addr[6];
	unsigned char sender_ip_addr[4];
	unsigned char target_eth_addr[6];
	unsigned char target_ip_addr[4];
};

typedef struct ip_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header {
	u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
	u_char  tos;            // Type of service 
	u_short tlen;           // Total length 
	u_short identification; // Identification
	u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
	u_char  ttl;            // Time to live
	u_char  proto;          // Protocol
	u_short crc;            // Header checksum
	ip_address  saddr;      // Source address
	ip_address  daddr;      // Destination address
	u_int   op_pad;         // Option + Padding
}ip_header;

/* UDP header*/
typedef struct udp_header {
	u_short sport;          // Source port
	u_short dport;          // Destination port
	u_short len;            // Datagram length
	u_short crc;            // Checksum
}udp_header;

/* prototype of the packet handler */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);



int main(int argc, char* argv[])
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	char packet_filter[] = "ip and udp";
	struct bpf_program fcode;
	int check;
	struct ethernet* eth_head = (struct ethernet*)malloc(sizeof(struct arp));
	struct arp* arp_head = (struct arp*)malloc(sizeof(struct arp));
	char* tmp;
	int ip, k;
	struct pcap_pkthdr *hd;
	const u_char *asdf;

	PIP_ADAPTER_INFO pai = 0;
	DWORD size = sizeof(PIP_ADAPTER_INFO);
	check = GetAdaptersInfo(pai, &size);
	pai = (PIP_ADAPTER_INFO)malloc(size);
	GetAdaptersInfo(pai, &size);
	u_char packet[42];

	for (i = 0; i < 6; i++)	eth_head->eth_dst_addr[i] = 0xff;
	for (i = 0; i < 6; i++) eth_head->eth_src_addr[i] = pai->Address[i];
	eth_head->frame_type = htons(0x0806);

	arp_head->hard_type = htons(0x0001);
	arp_head->prot_type = htons(0x0800);
	arp_head->hard_size = 0x06;
	arp_head->prot_size = 0x04;
	arp_head->op = htons(0x0001);

	for (i = 0; i < 6; i++) arp_head->sender_eth_addr[i] = pai->Address[i];
	
	tmp = pai->IpAddressList.IpAddress.String;
	ip = 0;
	k = 0;
	for (i = 0; i < strlen(tmp); i++) {
		if (tmp[i] == '.') {
			arp_head->sender_ip_addr[k] = ip;
			ip = 0;
			k++;
		}
		else ip = (ip * 10) + tmp[i] - '0';
	}
	arp_head->sender_ip_addr[k] = ip;

	for (i = 0; i < 6;i++)	arp_head->target_eth_addr[i] = 0x00;
	
	tmp = argv[1];
	ip = 0;
	k = 0;
	for (i = 0; i < strlen(argv[1]); i++) {
		if (tmp[i] == '.') {
			arp_head->target_ip_addr[k] = ip;
			ip = 0;
			k++;
		}
		else ip = (ip * 10) + tmp[i] - '0';
	}
	arp_head->target_ip_addr[k] = ip;

	memcpy(packet, (u_char*)eth_head, 14);
	memcpy(&packet[14], (u_char*)arp_head, 28);

	for (i = 0; i < 42; i++) {
		printf("%02x ", packet[i]);
	}
	

	
	
	
	//for (i = 0; i < 6;i++) printf("%02x ", eth_head->eth_dst_addr[i]);


	printf("\n");

	/* Retrieve the device list */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
	i = 0;
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			inum = i;
			//printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	/*
	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list 
		pcap_freealldevs(alldevs);
		return -1;
	}
	*/

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/* Open the adapter */
	if ((adhandle = pcap_open(d->name,  // name of the device
		65536,     // portion of the packet to capture. 
				   // 65536 grants that the whole packet will be captured on all the MACs.
		PCAP_OPENFLAG_PROMISCUOUS,         // promiscuous mode
		1000,      // read timeout
		NULL,      // remote authentication
		errbuf     // error buffer
		)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. is not supported by WinPcap\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	pcap_sendpacket(adhandle, packet, 42);



	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);

	/* start the capture */
	//pcap_loop(adhandle, 0, packet_handler, NULL);
	while (k = pcap_next_ex(adhandle, &hd, &asdf) >= 0) {
		if (k == 0) continue;
		else {
			if (asdf[12] == 0x08 && asdf[13] == 0x06 && asdf[20] == 0x00 && asdf[21] == 0x02) {
				if (((unsigned int*)&asdf[28])[0] == ((unsigned int*)&packet[38])[0]) {
					for (i = 0; i < 6; i++) {
						packet[i] = asdf[6 + i];
						packet[32+i] = asdf[6 + i];
					}
					break;
				}
			}
		}
	}

	packet[21] = 0x02;

	for (i = 0; i < 4; i++) {
		packet[28 + i] = inet_addr(pai->GatewayList.IpAddress.String) >> (8 * i) & 0xff;
	}

	pcap_sendpacket(adhandle, packet, 42);

	return 0;
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm *ltime;
	char timestr[16];
	ip_header *ih;
	udp_header *uh;
	u_int ip_len;
	u_short sport, dport;
	time_t local_tv_sec;



	printf("D MAC : ");
	for (int i = 1; i < 6; i++) {
		printf("%02x ", *(unsigned char*)(pkt_data + i));
	}
	printf("     S MAC : ");
	for (int i = 6; i < 12; i++) {
		printf("%02x ", *(unsigned char*)(pkt_data + i));
	}
	printf("\n");

	printf("    sip : ");
	for (int i = 26; i < 30; i++) {
		printf("%d ", *(unsigned char*)(pkt_data + i));
	}
	printf("      dip   : ");
	for (int i = 30; i < 34; i++) {
		printf("%d ", *(unsigned char*)(pkt_data + i));
	}
	printf("\n");
	printf("ether type : %02X", ntohs(*((unsigned short *)(pkt_data + 12))));

	if (*((unsigned short *)(pkt_data + 12)) == (unsigned short)IP) {

	}
	printf("     protocol  : ");
	for (int i = 23; i < 24; i++) {
		printf("%d ", *(unsigned char*)(pkt_data + i));
	}


	printf("  sport : ");
	printf("%d", ntohs(*(unsigned short*)(pkt_data + 34)));

	printf("  dport : ");

	printf("%d", ntohs(*(unsigned short*)(pkt_data + 36)));

	printf("\n");
	printf("====================================================\n");

	printf("\n");
}