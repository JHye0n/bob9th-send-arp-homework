LDLIB=-lpcap

all: send-arp-test

send-arp-test: main.o arphdr.o ethhdr.o ip.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIB) -o $@

clean:
	rm -rf send-arp-test *.o
