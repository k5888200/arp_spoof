all: arp_spoof

arp_spoof: main.o ty_network.o
	g++ -o arp_spoof ty_network.o main.o -lpcap -O2 -std=c++11 -pthread

ty_network.o: ty_network.cpp ty_network.h
	g++ -c -o ty_network.o ty_network.cpp -std=c++11

main.o: main.cpp ty_network.h
	g++ -c -o main.o main.cpp -std=c++11

clean:
	rm *.o send_arp
