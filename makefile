CXXFLAGS = -g
LDLIBS=-lpcap

all: arp-spoof spoof-agent

main.o: mac.h ip.h ethhdr.h arphdr.h spoof-agent.h main.cpp

spoof-agent.o: mac.h ip.h ethhdr.h arphdr.h spoof-agent.h spoof-agent.cpp

arphdr.o: mac.h ip.h arphdr.h arphdr.cpp

ethhdr.o: mac.h ethhdr.h ethhdr.cpp

ip.o: ip.h ip.cpp

mac.o : mac.h mac.cpp

arp-spoof: main.o arphdr.o ethhdr.o ip.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

spoof-agent: spoof-agent.o arphdr.o ethhdr.o ip.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f arp-spoof spoof-agent *.o
