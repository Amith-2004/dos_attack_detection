#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>

#define THRESHOLD 1000  // Threshold for DOS detection

// Structure to store packet information
struct ipheader {
    unsigned char      iph_ihl:4, iph_ver:4;
    unsigned char      iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    unsigned char      iph_flag;
    unsigned short int iph_offset;
    unsigned char      iph_ttl;
    unsigned char      iph_protocol;
    unsigned short int iph_chksum;
    struct  in_addr    iph_sourceip;
    struct  in_addr    iph_destip;
};

// Function to process packets
void process_packet(const struct pcap_pkthdr *header, const u_char *data) {
    struct ipheader *iph = (struct ipheader *)(data + 14); // Skip ethernet header

    // Extract source IP address
    char source_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(iph->iph_sourceip), source_ip, INET_ADDRSTRLEN);

    // Extract destination IP address
    char dest_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(iph->iph_destip), dest_ip, INET_ADDRSTRLEN);

    // For now, we simply print the IP addresses (Future: Add detection mechanism)
    printf("Source IP: %s -> Destination IP: %s\n", source_ip, dest_ip);

    // To be implemented: Check for packet flooding or abnormal traffic patterns
    // e.g., count the number of packets from a particular IP address.
    // TODO: Implement DOS detection algorithm
}

// Main function to capture packets
int main() {
    char *dev = "eth0";  // Device to sniff on
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // Open device for packet capture
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", dev, errbuf);
        return 2;
    }

    // Capture packets in a loop
    pcap_loop(handle, 10, process_packet, NULL);  // Capture 10 packets (for now)

    pcap_close(handle);
    return 0;
}
