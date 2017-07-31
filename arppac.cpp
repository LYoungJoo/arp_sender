#include <iostream>
#include <cstdint>
#include <pcap.h>
#include <net/ethernet.h>
#include <stdlib.h>

using namespace std;

struct eth {
	u_int8_t srcmac[6];
	u_int8_t destmac[6];
	u_int16_t type;

	void printSrcMAC(eth *eth_header){
		cout << "Src MAC - ";
		for(int i = 0; i < 6; ++i) {
			printf("%02X", (int *)((*eth_header).srcmac[i]));
			if ( i != 5)
				printf(":");
		}
		cout << endl;
	}

	void printDestMAC(eth *eth_header){
		cout << "Dest MAC - ";
		for(int i = 0; i < 6; ++i) {
			printf("%02X", (int *)((*eth_header).destmac[i]));
			if ( i != 5)
				printf(":");
		}
		cout << endl;
	}
};

struct sendingarp {
    u_int8_t srcmac[6];
    u_int8_t destmac[6];
    u_int16_t type;
    u_int16_t hardware_type;
    u_int16_t protocol_type;
    u_int8_t hardware_len;
    u_int8_t protocol_len;
    u_int16_t operation_code;
    u_int8_t sender_mac[6];
    u_int8_t sender_ip[4];
    u_int8_t target_mac[6];
    u_int8_t target_ip[4];
};

struct arp_s {
	u_int16_t hardware_type;
	u_int16_t protocol_type;
	u_int8_t hardware_len;
	u_int8_t protocol_len;
	u_int16_t operation_code;
	u_int8_t sender_mac[6];
	u_int8_t sender_ip[4];
	u_int8_t target_mac[6];
	u_int8_t target_ip[4];

	void printarp(arp_s *arp_header){
		printf("hardware_type %x\n",ntohs(arp_header->hardware_type));
		printf("protocol_type : %x\n",arp_header->protocol_type);
		printf("hardware_len : %x\n", arp_header->hardware_len);
		printf("protocol_len : %x\n", arp_header->protocol_len);
		printf("operation_code : %x\n" , ntohs(arp_header->operation_code));
	}

};

const char *getmac(char dev[20], char my_mac[20])
{
    FILE *fp;
    int state;
    char sum[200] = "ifconfig ";
    char buff[17];
    char tmp[20];
    char *ptr;

	
    strcpy(tmp,dev);
    strcat(tmp," | grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}'");
    strcat(sum, tmp);

    fp = popen(sum, "r");
    fgets(buff, 19, fp);
	strcpy(my_mac,buff);
	return buff;
}

int main(int argc, char *argv[])
{
	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	//char filter_exp[] = "port 80";	/* The filter expression */
	char filter_exp[0];
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr *header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */
	bool chk;
	char my_mac[20];
	eth *eth_header;
	arp_s *arp_header;
	sendingarp *send_arp;

	if( argc < 2 ){ 
		dev = pcap_lookupdev(errbuf);
		pcap_lookupnet(dev, &net, &mask, errbuf);
	}
	else {
		dev = argv[1]; 
	}
	getmac(dev, my_mac);
	
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	pcap_compile(handle, &fp, filter_exp, 0, net);
	pcap_setfilter(handle, &fp);

	
	for(int i=0; i < 6; ++i)
		send_arp->destmac[i] = 0xff;
	send_arp->srcmac[0] = 0x12;
	send_arp->srcmac[1] = 0x12;
	send_arp->srcmac[2] = 0x12;
	send_arp->srcmac[3] = 0x12;
	send_arp->srcmac[4] = 0x12;
	send_arp->srcmac[5] = 0x12;
	send_arp->type = 0x0806;


	//printf("%s",send_arp);

	pcap_sendpacket(handle,(const u_char *)send_arp,60);

	while(0 <= (chk = pcap_next_ex(handle, &header, &packet)))
	{
		if (chk == 0)
			continue;
		else {
			cout << "======================== PACKET ========================" << endl;
			cout << "1) ETH HEADER" << endl;
			eth_header = (eth *)packet;
			eth_header->printSrcMAC(eth_header);
			eth_header->printDestMAC(eth_header);

			if ((*eth_header).type == ntohs(0x0806)) {
				cout << "2) ARP HEADER" << endl;
				arp_header = (arp_s*)(packet+14);
				arp_header->printarp(arp_header);
				
			}
		}
	}
}
