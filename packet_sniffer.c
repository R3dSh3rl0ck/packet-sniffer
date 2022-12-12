#include <pcap.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>

// Error handling function.
void pcap_fatal(const char *failed_in, const char *errbuf) {
	printf("Fatal Error in %s: %s\n", failed_in, errbuf);
	exit(1);
}

int main(int argc, char* argv[]) 
{
	struct pcap_pkthdr header;
	const u_char *packet;
	char errbuf[PCAP_ERRBUF_SIZE];
	char *device;
	pcap_t *pcap_handle;
	
	// Device
	device = pcap_lookupdev(errbuf);
	if(device == NULL)
		pcap_fatal("pcap_lookupdev", errbuf);

	printf("Sniffing on device %s\n\n", device);

	// Capturing..
	pcap_handle = pcap_open_live(device, 4096, 1, 0, errbuf);
	if(pcap_handle == NULL)
		pcap_fatal("pcap_open_live", errbuf);
	
	//Dumper - Create the pcap file
	pcap_dumper_t *pd = pcap_dump_open(pcap_handle, "dump.pcap");
	

	for(int i=0; i < 10; i++) {
		packet = pcap_next(pcap_handle, &header);
		printf("Got a %d byte packet\n", header.len);
		// dump the captured data in pcap file.
		pcap_dump((u_char*) pd, &header, packet);
	}
	pcap_close(pcap_handle);
	pcap_dump_close(pd);

	
	return 0;
}
