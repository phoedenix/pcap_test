#include <stdio.h>
#include <pcap/pcap.h>          // 패킷 캡쳐를 위한 헤더파일
#include <netinet/if_ether.h>   // ethernet 헤더 구조체의 헤더파일
#include <netinet/ip.h>         // ip 헤더 구조체의 헤더파일
#include <netinet/tcp.h>        // tcp header 구조체의 헤더파일
#include <arpa/inet.h>          // inet_ntoa를 위한 헤더파일

int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];  // pcap 에러메시지를 담는 변수

    pcap_t *handle;                 // session handle
    handle = pcap_open_live("eth0", 65535, 1, 1000, errbuf);
                                    // dev이름, 패킷의최대크기, promiscuous모드(모든패킷캡쳐), timeout, 에러메시지
    if (handle == NULL) {
             fprintf(stderr, "Couldn't open device %s: %s\n", "eth0", errbuf);
             return(2);             // handle이 열리지 않을 경우 에러처리
    }
    struct pcap_pkthdr *pkthdr;     // 캡쳐한 패킷에 관한 함수
    const u_char *data;             // unsigned인 이유는 패킷이 음수로 오지 않기 때문.

    struct ether_header *ethHdr;    // ethernet header구조체 선언
    struct ip *ipHdr;               // ip Header 구조체 선언
    int where = 0;                  // 현재 위치를 저장할 변수

    while(1) {
        int res = pcap_next_ex(handle, &pkthdr, &data);     // pcap_next_ex는 fread와 같이 패킷을 읽는 함수.
                                                            // data에 값이 들어감.
                                                            // res가 음수일때 에러가 있거나 읽어올 패킷이 없을때, 0은 timeout, 1이면 계속 읽음
        ethHdr = (struct ether_header *)data;               // data가 u_char이었기 때문에 형변환을 해줌
        printf("Ethernet D.MAC: ");
        for(int i=0; i<6; i++) {                            // Ethernet 헤더의 Dest MAC은 6byte이므로 1byte씩 읽으니까 6번 반복
            if(i==5) {                                      // 맨 마지막은 구분자 -를 없애기 위해 따로 처리
                printf("%02x\t", ethHdr->ether_dhost[i]);   // ether_header안의 구조체 멤버 ether_dhost로 Dest MAC를 표시.
                break;
            }
            printf("%02x-",ethHdr->ether_dhost[i]);
        }
        printf("Ethernet S.MAC: ");
        for(int i=0; i<6; i++) {
            if(i==5) {
                printf("%02x\n", ethHdr->ether_shost[i]);   // ether_header안의 구조체 멤버 ether_shost로 Src MAC를 표시.
                break;
            }
            printf("%02x-",ethHdr->ether_shost[i]);
        }
        where = sizeof(struct ether_header);            // ethernet header 뒤에 ether data와 CRC가 붙기 때문에,
                                                        // ip header의 위치로 가기 위해 ether_header 구조체 크기를 구함.
        struct ip *ipHdr = (struct ip *)(data + where); // ip header가 있는 위치로 이동시키기 위해 data에 ethernet 헤더의 길이를 더하여,
                                                        // ip 헤더 구조체로 위치를 옮겨 다시 읽도록 함.

                                                        // IPv4는 0800이니까, 0800과 EtherType이 같으면 상위 계층 IP로.
        if(0x0800 == ntohs(ethHdr->ether_type)){        // ntohs는 2바이트(s)의 네트워크바이트(Big endian)을 호스트바이트(Little endian)로 변환시켜 줌.
               printf("S.IP: ");
               printf("%s\t\t\t", inet_ntoa(ipHdr->ip_src));  // ip 헤더의 in_addr 구조체 안의 ip_scr로 Src IP를 가져올 수 있음.
                                                        // inet_ntoa는 ip주소의 32비트의 16진수 값을 10진수와 dot을 넣어서 변환시켜 줌. char형이니 %S로 받음.
               printf("D.IP: ");
               printf("%s\n", inet_ntoa(ipHdr->ip_dst));

               where += (ipHdr->ip_hl) * 4;             // ip header 뒤에 TCP 또는 UDP가 오기때문에 위치 변경을 위해
                                                        // 위치 저장 변수 where에 총 ip 헤더의 길이를 더함
                                                        // ipv4의 header length는 4바이트(32bit). 필드값은 대부분 5이고, 헤더의 길이는 20바이트일 경우가 높음.
               if(6 == ipHdr->ip_p){                    // Protocol Identifier값이 6이면 상위계층 프로토콜은 TCP. (16 = UDP, 1 = ICMP)
                   struct tcphdr *tcpHdr = (struct tcphdr *)(data + where);
                                                        // tcp 헤더의 위치로 가기 위해 data에 ip 헤더의 길이를 더함.
                   printf("TCP.S.PORT: %d\t\t\t", ntohs(tcpHdr->th_sport)); // tcphdr 구조체에 정의된 th_sport 멤버로 Src port를 읽어옴.
                   printf("TCP.D.PORT: %d\n", ntohs(tcpHdr->th_dport));     // tcphdr 구조체에 정의된 th_dport 멤버로 Dest port를 읽어옴.
                   printf("------------------------------------------------------\n");
                   where += (tcpHdr->th_off) * 4;       // tcp 헤더의 크기는 가변적이므로 tcphdr 구조체의 th_off가 순서상 헤더 길이 필드라고 생각하여 마찬가지로 4 btye 단위를 곱해줌.
                   int count = 0;
                   printf("Data: \n");
                   while(where < (int)pkthdr->caplen) {  // 위치표시 변수가 캡쳐한 패킷의 크기를 넘으면 false가 되어 자동으로 나갈 수 있음.
                       printf("%02x ", data[where]);     // 위치 변수를 이용하여 데이터를 1 btye씩 읽어옴.
                       where++;                          // 위치 변수값 증가
                       count++;                          // 16개씩 읽고 단을 나눠 가독성을 살리기 위해 count 변수 선언
                       if ((count % 8) == 0 ) printf(" "); // 와이어샤크처럼 보이게 하기위해 8 byte에서 띄어쓰기 해줌.
                       if (count % 16 == 0 && count != 0)  // 16개를 다 읽고 count가 남아있다면 단락을 나눔.
                           printf("\n");
                   }
               }
        }
        printf("\n");   // 반복이 되므로 가독성을 위한 구분선과 띄어쓰기를 해줌
        printf("=========================================================================\n");
    }

    pcap_close(handle); // 종료 전 열어둔 handle을 닫기 !!
    return 0;
}

