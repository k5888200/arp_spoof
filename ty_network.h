#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <ifaddrs.h>
#include <bits/stdc++.h>
#include <unistd.h>

#define IP_ADDR_LEN 4
#define INTERVAL_ARP	1.0

#pragma pack(1)
struct arp_payload{
	struct ether_addr 	SenderHA;
	struct in_addr		SenderIP;
	struct ether_addr 	TargetHA;
	struct in_addr		TargetIP;	
};

struct session_data{
	static int status;
	static std::mutex mtx_status;
	struct in_addr		AttackIP, SenderIP, TargetIP;
	struct ether_addr	AttackHA, SenderHA, TargetHA;
};


char *usr_ether_ntoa_r (const struct ether_addr *addr, char *buf);
char *usr_ether_ntoa (const struct ether_addr *addr);

void my_assert(bool cond, const char* format, ...)
__attribute__ ((format (printf, 2, 3)));

int GetLocalIP(struct in_addr* IP, const char *interface);

int GetLocalHA(struct ether_addr* HA, const char *interface);

int GetHA(pcap_t *handle, const struct ether_addr *srcHA, const struct in_addr *srcIP, struct ether_addr *dstHA, const struct in_addr *dstIP);

size_t GenEtherPacket(unsigned char *packet, const struct ether_addr* dst_ha, const struct ether_addr* src_ha, u_int16_t ether_type);

size_t GenARPPacket(unsigned char *packet, const u_int16_t opcode, const struct ether_addr *SenderHA, const struct in_addr *SenderIP, const struct ether_addr *TargetHA, const struct in_addr *TargetIP);

void *ArpSpoof(const char *interface, struct session_data *se_data);

void *SpoofedToRelay(void *data);

int CheckPacket(const unsigned char* packet, int packet_len, struct session_data *se_data);

int Relay(pcap_t *handle, const unsigned char* packet, int packet_len, struct session_data *se_data);

int Recovery(pcap_t *handle, struct session_data *se_data);
