APP=pcapdata

all: 
	gcc -o $(APP) pcap-sample.c TCPFlow.c -lpcap

clean: 
	rm -f $(APP)
	rm -f *~