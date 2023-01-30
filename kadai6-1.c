/*
 * sample-2.c
 */
#include <stdio.h>
#include <stdlib.h>
/*
  * pcap_*関数を利用するために必要
  */
#include <pcap/pcap.h>
#include <netinet/tcp.h> 
  /*
   * pcap_*関数で使用
   */

#include <arpa/inet.h> /* for ntohl() and ntohs() functions */
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <ctype.h>
char errbuf[PCAP_ERRBUF_SIZE];

void print_ethernet(u_char* packet);
void print_arp(u_char* packet);
void print_ipv4(u_char* packet);
void print_icmp(u_char* packet);
void print_udp(u_char* packet);
void print_tcp(u_char* packet);

char toc(int c) {
  if (isprint(c) == 0) return '.';
  else return (char) (c);
}

int main(int argc, char* argv[])
{
    int cnt = 0;  /* 捕まえたパケットの数を数える */
    pcap_if_t* alldevsp;
    char* device; /* パケットキャプチャ可能なインタフェース名を格納 */
    pcap_t* p;    /* パケットキャプチャのデスクリプタを格納 */

    u_char* packet;       /* 捕まえたパケットの先頭アドレスを格納 */
    struct pcap_pkthdr h; /* pcap_*関数で使用 */

     /*
      * キャプチャ可能なインタフェースを探す
      */
    if (pcap_findalldevs(&alldevsp, errbuf) == -1) { /* エラーの場合 */
        fprintf(stderr, "%s\n", errbuf);
        exit(1);
    }
    if (alldevsp == NULL) { /* 見つからなかった場合 */
        fprintf(stderr, "%s\n", errbuf);
        exit(1);
    }
    device = alldevsp->name;
    
    /*
     * 指定したインタフェースでキャプチャを開始する
     *
     * 第1引数：キャプチャするインタフェース名を指定
     * 第2引数：キャプチャするパケットのサイズを指定(単位：バイト)
     * 第3引数：promiscuos modeの指定
     * 第4引数：パケットが捕まらない時にあきらめるまでの時間(単位：ミリ秒)
     * 第5引数：エラーが発生した場合のメッセージを格納
     */
    p = pcap_open_live(device, 96, 1, 500, errbuf);
    if (p == NULL) {      /* エラーの場合 */
        fprintf(stderr, "%s\n", errbuf);
        exit(2);
    }
    setbuf(stdout, NULL);

    while (cnt < 20) {    /* パケット20個捕まえるまで繰り返す */
       /*
        * パケット1個捕まえてくる
        */
        packet = (u_char*)pcap_next(p, &h);

        /*
         * パケットを捕まえたら…
         */
        if (packet != NULL) {
            cnt++;                    /* 捕まえたパケット数をカウント */
            printf("[%02d]\n", cnt);  /* 何番目のパケットか表示 */
            print_ethernet(packet);   /* Ethernetフレームを表示する */
            print_arp(packet);
            print_ipv4(packet);
            if(packet[23] == 1) {
              /* ICMPパケットの場合、print_icmpを呼び出す */
              print_icmp(packet);
            }
            print_udp(packet);
            print_tcp(packet);
        }
    }
    printf("\n%d packets have been captured.\n", cnt);

    /*
     * キャプチャを終了する
     */
    pcap_close(p);

    /*
     * 終了
     */
    return 0;
}

/*
 * Ethernetフレームを表示する関数
 */


void print_ethernet(u_char* packet) {
    /* Ethernetフレームのヘッダを表示 */
    int n;

    printf("================================\n");
    printf("Dest. Mac. Addr : ");
    for (n = 0; n < 6; n++) {
        printf("%02x ", packet[n]);     /* 1～6バイト目を表示 */
    }
    printf("\n");

    printf("Src. Mac. Addr : ");
    for (n = 6; n < 12; n++) {
        printf("%02x ", packet[n]);     /* 6～11バイト目を表示 */
    }
    printf("\n");
    if (packet[12] == 0x08 && packet[13] == 0x00) {
        printf("Type : IPv4\n");
    }
    else if (packet[12] == 0x08 && packet[13] == 0x06) {
        printf("Type : ARP\n");
    }
    else {
        printf("Type : unknown\n");
    }


    /* パケットデータの上位8バイトを表示 */
    printf("Data : ");
    for (n = 14; n < 22; n++) {
        printf("%02x ", packet[n]);     /* 6～11バイト目を表示 */
    }
    printf("\n");


}



void print_arp(u_char* packet)
{
    /*
     * ARPパケットの表示
     *
     * packet[14-15]：Hardware type
     * packet[16-17]：Protocol type
     * packet[18]：Hardware size
     * packet[19]：Protocol size
     * packet[20-21]：Opcode
     * packet[22-27]：Sender MAC address
     * packet[28-31]：Sender IP address
     * packet[32-37]：Target MAC address
     * packet[38-41]：Target IP address
     */
    printf("ARP packet:\n");
    if (packet[14] == 0x00 && packet[15] == 0x01) {
        printf("Hardware type: Ethernet\n");
    } 
    else {
        printf("Hardware type: Unknown\n");
    }
    if (packet[16] == 0x08 && packet[17] == 0x00) {
        printf("Protocol type: IPv4\n");
    }
    else {
        printf("Protocol type: Other\n");
    }
    printf("  Hardware size: %d\n", packet[18]);
    printf("  Protocol size: %d\n", packet[19]);
    if (packet[20] == 0x00 && packet[21] == 0x02) {
        printf("Opcode: REPLY\n");
    }
    else if (packet[20] == 0x00 && packet[21] == 0x01) {
        printf("Opcode: REQUEST\n");
    }
    else {
        printf("Opcode: Unknown\n");
    }
    printf("  Sender MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n", packet[22], packet[23], packet[24], packet[25], packet[26], packet[27]);
    printf("  Sender IP address: %d.%d.%d.%d\n", packet[28], packet[29], packet[30], packet[31]);
    printf("  Target MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n", packet[32], packet[33], packet[34], packet[35], packet[36], packet[37]);
    printf("  Target IP address: %d.%d.%d.%d\n", packet[38], packet[39], packet[40], packet[41]);
}

void print_ipv4(u_char* packet) {
  /*
   * Define variables to store the header information
   */
  u_char version;
  u_char header_length;
  u_char type_of_service;
  u_short total_length;
  u_short identification;
  u_short fragment_offset;
  u_char time_to_live;
  u_char protocol;
  u_short header_checksum;
  struct in_addr source_address;
  struct in_addr destination_address;

  /*
   * Set the variables to the values in the header
   *
   * The IPv4 header is located at an offset of 14 bytes from the beginning
   * of the Ethernet frame, so we need to add 14 to the packet pointer to
   * get the location of the IPv4 header.
   */
  version = (*(packet + 14) & 0xf0) >> 4;
  header_length = (*(packet + 14) & 0x0f) * 4;
  type_of_service = *(packet + 15);
  total_length = (*(packet + 16) << 8) | *(packet + 17);
  identification = (*(packet + 18) << 8) | *(packet + 19);
  fragment_offset = (*(packet + 20) << 8) | *(packet + 21);
  time_to_live = *(packet + 22);
  protocol = *(packet + 23);
  header_checksum = (*(packet + 24) << 8) | *(packet + 25);
  source_address.s_addr = (*(packet + 26) << 24) | (*(packet + 27) << 16) | (*(packet + 28) << 8) | *(packet + 29);
  destination_address.s_addr = (*(packet + 30) << 24) | (*(packet + 31) << 16) | (*(packet + 32) << 8) | *(packet + 33);

  printf("IP version: %d\n", version);
  printf("IP header length: %d bytes\n", header_length);
  printf("Type of service: 0x%02x\n", type_of_service);
  printf("Total length: %d bytes\n", total_length);
  printf("Identification: 0x%04x\n", identification);
  printf("Fragment offset: %d bytes\n", fragment_offset);
  printf("Time to live: %d\n", time_to_live);


  if (protocol == 1) {
    printf("Protocol: ICMP\n");
  } else if (protocol == 6) {
    printf("Protocol: TCP\n");
  } else if (protocol == 17) {
    printf("Protocol: UDP\n");
  } else {
    printf("Protocol: Unknown\n");
  }
  printf("Header checksum: 0x%04x\n", header_checksum);
  printf("Source address: %s\n", inet_ntoa(source_address));
  printf("Destination address: %s\n", inet_ntoa(destination_address));

}


void print_icmp(u_char* packet)
{
  /* ICMPヘッダ */
  printf("--- ICMP ---\n");
  if (packet[34] == 0) {
    printf("Type: Echo Reply (pingの応答)\n");
  } else if (packet[34] == 3) {
    printf("Type: Destination Unreachable (宛先不達)\n");
  } else if (packet[34] == 8) {   
    printf("Type: Echo Request (ping要求)\n");
  } else if (packet[34] == 11) {
      printf("Type: Time Exceeded (タイムアウト)\n");
  } else {
    printf("Unknown ICMP Type\n");
  }
  printf("Type: %d\n", packet[34]);
  printf("Code: %d\n", packet[35]);
  printf("Checksum: %02X%02X\n", packet[36], packet[37]);
  printf("Identifier: %02X%02X\n", packet[38], packet[39]);
  printf("Sequence Number: %02X%02X\n", packet[40], packet[41]);
}


void print_udp(u_char* packet)
{
  /* UDPヘッダ */
  printf("--- UDP ---\n");
  printf("Source Port: %d\n", (packet[34] << 8) + packet[35]);
  printf("Destination Port: %d\n", (packet[36] << 8) + packet[37]);
  printf("Length: %d\n", (packet[38] << 8) + packet[39]);
  printf("Checksum: %02X%02X\n", packet[40], packet[41]);
  printf("Urgent Pointer: %d\n", (packet[42] << 8) + packet[43]);
  printf("Data Offset: %d\n", packet[44]);
  struct servent* service = getservbyport((packet[34] << 8) + packet[35],"udp");
  if(service)
    printf("Port service name: %s\n", service->s_name);
  else
    printf("Port service name: Not found\n");
  struct udphdr* udp_header;
  udp_header = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
  int data_size = ntohs(udp_header->len) - sizeof(struct udphdr);
  printf("Window: %d\n", (packet[46] << 8) + packet[47]);
  printf("UDP Data (base 16): ");
  for (int i = 0; i < (16 < data_size ? 16 : data_size); i++) {
    printf("%02X ", packet[sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr) + i]);
  }
  printf("\n");
  printf("UDP Data (ascii): ");
  for (int i = 0; i < (16 < data_size ? 16 : data_size); i++) {
    printf("%c ", toc(packet[sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr) + i]));
  }
  printf("\n");
}


void print_tcp(u_char* packet)
{
  struct tcphdr* tcp_header;
  tcp_header = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
  printf("TCP: ");

  /* check the control flags and print their meaning */
  if (tcp_header->th_flags & TH_FIN)
    printf("FIN ");
  if (tcp_header->th_flags & TH_SYN)
    printf("SYN ");
  if (tcp_header->th_flags & TH_RST)
    printf("RST ");
  if (tcp_header->th_flags & TH_PUSH)
    printf("PUSH ");
  if (tcp_header->th_flags & TH_ACK)
    printf("ACK ");
  if (tcp_header->th_flags & TH_URG)
    printf("URG ");
  printf("\n");
  
  /* TCPデータを表示する */
  printf("TCP data: ");
  int data_size = 0;
  
  /* TCPヘッダを指すようにする */
  tcp_header = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
  
  /* TCPデータのサイズを計算する */
  data_size = ntohs(tcp_header->doff << 2) - sizeof(struct tcphdr);
  
  /* TCPデータを表示する */
  printf("TCP data (base 16): ");
  for (int i = 0; i < (16 < data_size ? 16 : data_size); i++) {
    printf("%02x ", packet[sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr) + i]);
  }
  printf("\n");
  printf("TCP data (ascii): ");
  for (int i = 0; i < (16 < data_size ? 16 : data_size); i++) {
    printf("%c ", toc(packet[sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr) + i]));
  }
  printf("\n");
}
