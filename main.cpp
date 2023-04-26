#include <cstdio>
#include <pcap.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <netinet/ether.h>
#include <sys/wait.h>

#include "ethhdr.h"
#include "arphdr.h"
#include "spoof-agent.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

pid_t* childs;
int child_cnt;
char MY_IP[32];
char MY_MAC[32];

void usage() {
	printf("syntax: send-arp-test <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: send-arp-test wlan0 192.168.10.2 192.168.10.1\n");
}

EthArpPacket to_broadcast_packet(char* ip){
	EthArpPacket packet;

	packet.eth_.dmac_ = Mac::broadcastMac();
	packet.eth_.smac_ = Mac(MY_MAC);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(MY_MAC);
	packet.arp_.sip_ = htonl(Ip(MY_IP));
	packet.arp_.tmac_ = Mac::nullMac();
	packet.arp_.tip_ = htonl(Ip(ip));

	return packet;
}

void get_my_mac(char *dev, char* MY_MAC){
	int fd;
	struct ifreq ifr;
	
	memset(&ifr, 0x00, sizeof(ifr));
    strcpy(ifr.ifr_name, dev);

    fd = socket(AF_INET, SOCK_STREAM, 0);
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    std::stringstream ss;
    for (int i = 0; i < 6; ++i) {
       	ss << std::setfill('0') << std::setw(2) << std::hex << static_cast<unsigned int> (static_cast<unsigned char>(ifr.ifr_hwaddr.sa_data[i]));
       	if (i < 5) {
         	ss << ":";
		}
	}
	strncpy(MY_MAC, ss.str().c_str(), 32);
    close(fd);
}

void get_my_ip(char *dev, char* MY_IP){
	int fd;
	struct ifreq ifr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);

	memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFADDR, &ifr);
	inet_ntop(AF_INET, ifr.ifr_addr.sa_data + 2, MY_IP, sizeof(struct sockaddr));
    close(fd);
}

int find_mac(pcap_t* handle, char* ip, char* mac){
	int res;
	EthArpPacket to_broadcast_p = to_broadcast_packet(ip);
	//make own packet and send to broadcast
	res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&to_broadcast_p), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		return -1;
	}
	while(1){
		struct pcap_pkthdr* header;
		const u_char* tp;
		
		int input_packet = pcap_next_ex(handle, &header, &tp);
		if(input_packet == 0) continue; //if there is no input packet, continuing receiving
		else if(input_packet == PCAP_ERROR || input_packet == PCAP_ERROR_BREAK){
			fprintf(stderr, "pcap_next_ex return %d error=%s\n", input_packet, pcap_geterr(handle));
			return -1;
		}
		EthArpPacket* recieved_packet = (EthArpPacket*)tp;

		if(recieved_packet->eth_.type() == EthHdr::Arp && recieved_packet->arp_.op() == ArpHdr::Reply && recieved_packet->arp_.sip() == Ip(ip) && recieved_packet->arp_.tmac() == Mac(MY_MAC)){
			strncpy(mac, std::string(recieved_packet->arp_.smac()).c_str(), 32);
			return 0;
		}
	}

	return -1; /* unreachable */
}

int spawn_agent(char* dev, char* sender_ip, char* target_ip, char* sender_mac, char* target_mac){
	pid_t pid;
	char *argv[AGENT_ARGC + 1];

	pid = fork();
	if (pid < 0){
		fprintf(stderr, "Failed to fork process\n");
		return -1;
	}

	if (pid > 0){ 	// parent
		childs[child_cnt++] = pid;
	} else{ 		// child
		argv[0] = AGENT_PATH;
		argv[1] = dev;
		argv[2] = MY_IP;
		argv[3] = MY_MAC;
		argv[4] = sender_ip;
		argv[5] = sender_mac;
		argv[6] = target_ip;
		argv[7] = target_mac;
		argv[8] = NULL;
		execv(AGENT_PATH, argv);
	}

	return 0;
}

int pid2idx(pid_t pid, int cnt){
	int i;
	for (i = 0; i < cnt; i++){
		if (childs[i] == pid)
			return i;
	}

	return -1;
}

int main(int argc, char* argv[]) {
	if (argc <= 3 || argc & 1 != 0) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	int res;
	int cnt = (argc / 2) - 1;

	get_my_mac(dev, MY_MAC);
    get_my_ip(dev, MY_IP);

	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	childs = (pid_t*)malloc(cnt * sizeof(pid_t));

	for(int i = 0; i < cnt; i++){
		char sender_mac[32];
		char target_mac[32];
		res = find_mac(handle, argv[2*i + 2], sender_mac);
		if (res < 0){
			free(childs);
			pcap_close(handle);
			exit(1);
		}
		res = find_mac(handle, argv[2*i + 3], target_mac);
		if (res < 0){
			free(childs);
			pcap_close(handle);
			exit(1);
		}

		res = spawn_agent(dev, argv[2*i + 2], argv[2*i + 3], sender_mac, target_mac);
		if (res < 0){
			free(childs);
			pcap_close(handle);
			exit(1);
		}
	}
	pcap_close(handle);
	wait(0);

	free(childs);
	
	return 0;
}
