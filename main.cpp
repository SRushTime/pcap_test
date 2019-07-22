#include <pcap.h>
#include <stdio.h>
#include <stdint.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void Eth_mac(const u_char *packet){
    printf("Eth_DMac  : %02X:%02X:%02X:%02X:%02X:%02X\n", packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]);
    printf("Eth_SMac  : %02X:%02X:%02X:%02X:%02X:%02X\n", packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);
}

void Ip_addr(const u_char *packet){
    if(packet[12]==0x08)
            printf("IP_SIp    : %02d.%02d.%02d.%02d\n", packet[26], packet[27], packet[28], packet[29]);
            printf("IP_DIp    : %02d.%02d.%02d.%02d\n", packet[30], packet[31], packet[32], packet[33]);
}
void Tcp_port(const u_char *packet){
        if(packet[23]==0x06)
            printf("Tcp_Sport : %02d\n", packet[34]*256+packet[35]);
            printf("Tcp_Dport : %02d\n", packet[36]*256+packet[37]);
            if (packet[54])
                printf("Data      : %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X\n", packet[54], packet[55], packet[56]
                        , packet[57], packet[58], packet[59], packet[60], packet[61], packet[62], packet[63]);
}



int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }
  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }
  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    Eth_mac(packet);
    Ip_addr(packet);
    Tcp_port(packet);
    printf("%u bytes captured\n", header->caplen);
    printf("\n");
  }

    pcap_close(handle);
    return 0;
}
