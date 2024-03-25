#ifndef GETPACKET_H
#define GETPACKET_H

#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

int getMyMac(const char* dev, EthArpPacket &packet);

int getMyIp(const char* dev, EthArpPacket &packet);

bool getSenderMac(pcap_t* handle, EthArpPacket &packet);

bool sendArpSpoof(pcap_t* handle, EthArpPacket &packet);

void relay_packet(pcap_t* handle);

#endif // GETPACKET_H