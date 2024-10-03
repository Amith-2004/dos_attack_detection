#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <time.h>
#include <ctype.h>


#define MAX_PACKETS 10000
#define THRESHOLD 100 // Number of packets from a single IP within the interval to be considered as a DOS attack
#define INTERVAL 5 // Time interval in seconds for checking DOS attack

// Structure to keep track of packet information
struct packet_info {
    char src_ip[INET_ADDRSTRLEN];
    int count;
    time_t first_seen;
};

// Global array to hold packet info
struct packet_info packets[MAX_PACKETS];
int packet_count = 0;

// Function prototypes
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void check_for_dos_attack();
void log_attack(const char *src_ip, int packet_count);
void cleanup_expired_entries();

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // Open the default network device for packet capture
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device: %s\n", errbuf);
        return 1;
    }

    // Start capturing packets
    pcap_loop(handle, 0, packet_handler, NULL);

    // Close the capture handle
    pcap_close(handle);

    return 0;
}

// Function to handle each captured packet
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    (void)user_data; // Unused parameter

    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    char src_ip[INET_ADDRSTRLEN];

    // Convert the IP address to a string
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);

    // Check if this source IP is already in our packet_info array
    int found = 0;
    for (int i = 0; i < packet_count; i++) {
        if (strcmp(packets[i].src_ip, src_ip) == 0) {
            packets[i].count++;
            found = 1;
            break;
        }
    }

    // If not found, add it to the array
    if (!found) {
        strcpy(packets[packet_count].src_ip, src_ip);
        packets[packet_count].count = 1;
        packets[packet_count].first_seen = time(NULL);
        packet_count++;
    }

    // Check for DOS attack
    check_for_dos_attack();

    // Cleanup expired entries
    cleanup_expired_entries();
}

// Function to check for a DOS attack
void check_for_dos_attack() {
    time_t now = time(NULL);

    for (int i = 0; i < packet_count; i++) {
        // If the number of packets from this IP exceeds the threshold within the interval, it's a DOS attack
        if (packets[i].count >= THRESHOLD && difftime(now, packets[i].first_seen) <= INTERVAL) {
            log_attack(packets[i].src_ip, packets[i].count);
        }
    }
}

// Function to log a detected DOS attack
void log_attack(const char *src_ip, int packet_count) {
    FILE *log_file = fopen("dos_attack.log", "a");
    if (log_file == NULL) {
        fprintf(stderr, "Could not open log file\n");
        return;
    }

    time_t now = time(NULL);
    char *timestamp = ctime(&now);
    timestamp[strlen(timestamp) - 1] = '\0'; // Remove the newline character

    fprintf(log_file, "DOS ATTACK DETECTED:\n");
    fprintf(log_file, "Source IP: %s\n", src_ip);
    fprintf(log_file, "Packet Count: %d\n", packet_count);
    fprintf(log_file, "Timestamp: %s\n", timestamp);
    fprintf(log_file, "-----------------------------------\n");

    fclose(log_file);
}

// Function to clean up expired entries in the packet_info array
void cleanup_expired_entries() {
    time_t now = time(NULL);

    for (int i = 0; i < packet_count; i++) {
        if (difftime(now, packets[i].first_seen) > INTERVAL) {
            // Shift the rest of the array down
            for (int j = i; j < packet_count - 1; j++) {
                packets[j] = packets[j + 1];
            }
            packet_count--;
            i--; // Adjust index after shifting
        }
    }
}

// Detailed packet analysis (additional functionality)
void analyze_packet(const u_char *packet, int length) {
    struct ether_header *eth_header = (struct ether_header *)packet;
    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));

    printf("Packet Analysis:\n");
    printf("Ethernet Header\n");
    printf("   |-Source MAC: %s\n", ether_ntoa((struct ether_addr *)&eth_header->ether_shost));
    printf("   |-Destination MAC: %s\n", ether_ntoa((struct ether_addr *)&eth_header->ether_dhost));
    printf("IP Header\n");
    printf("   |-Source IP: %s\n", inet_ntoa(ip_header->ip_src));
    printf("   |-Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
    printf("   |-Total Length: %d\n", ntohs(ip_header->ip_len));
    printf("   |-TTL: %d\n", ip_header->ip_ttl);
    printf("   |-Protocol: %d\n", ip_header->ip_p);
    printf("   |-Checksum: %d\n", ntohs(ip_header->ip_sum));

    // Additional analysis like TCP/UDP headers can be added here
}

// Example code to trigger packet analysis
void packet_handler_with_analysis(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    (void)user_data; // Unused parameter

    // Analyze the packet
    analyze_packet(packet, pkthdr->len);

    // Continue with regular packet handling
    packet_handler(user_data, pkthdr, packet);
}

// Advanced DOS detection: analyzing payloads
void analyze_payload(const u_char *payload, int length) {
    printf("Payload Analysis:\n");
    printf("   |-Payload Length: %d\n", length);
    printf("   |-Payload Content:\n");

    for (int i = 0; i < length; i++) {
        if (isprint(payload[i]))
            printf("%c", payload[i]);
        else
            printf(".");
    }
    printf("\n");
}

// Integrating payload analysis into packet handler
void packet_handler_with_payload_analysis(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    (void)user_data; // Unused parameter

    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    int ip_header_len = ip_header->ip_hl * 4;
    int total_len = ntohs(ip_header->ip_len);

    // Calculate the payload offset
    int payload_offset = sizeof(struct ether_header) + ip_header_len;

    // Calculate payload length
    int payload_length = total_len - ip_header_len;

    // Analyze the payload
    if (payload_length > 0) {
        const u_char *payload = packet + payload_offset;
        analyze_payload(payload, payload_length);
    }

    // Continue with regular packet handling
    packet_handler(user_data, pkthdr, packet);
}
