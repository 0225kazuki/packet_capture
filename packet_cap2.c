#include "pcap.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
//#include "if_ether.h"

  

/* イーサネットアドレス（MACアドレス）は6バイト*/
#define ETHER_ADDR_LEN	6

struct ethhdr
{
unsigned char   h_dest[ETHER_ADDR_LEN];   // destination eth addr
unsigned char   h_source[ETHER_ADDR_LEN]; // source ether addr
unsigned short  h_proto;  	      // packet type ID field
};



//arp構造体。sourceipをstruct in_addrで、inet_ntoaで表記しようとするとうまくいかなかった。
struct arp
{
  u_short hd_type;
  u_short proto_type;
  u_char hlen,plen;//それぞれ6,4を示しているはず
  u_short op;
  u_char source_mac[6];
  //struct in_addr source_ip;
  u_char source_ip[4];
  u_char tell_mac[6];
  struct in_addr tell_ip;
};


char * convmac_tostr(u_char *hwaddr,char *mac,size_t size){
  snprintf(mac,size,"%02x:%02x:%02x:%02x:%02x:%02x",
  hwaddr[0],hwaddr[1],hwaddr[2],
  hwaddr[3],hwaddr[4],hwaddr[5]);
  return mac;
}

static void
print_arp(char *p)
{
  struct arp *arp;
  char mac[18]={0};
  arp = (struct arp *)p;
  int i=0;
  printf("arp_hd_type = %d\n", ntohs(arp->hd_type ));
  printf("arp_proto_type = %.02x\n", ntohs(arp->proto_type ));
  printf("arp_hlen = 0x%x\n", ntohs(arp->hlen) );
  printf("arp_plen = 0x%x\n", ntohs(arp->plen) );
  printf("arp_op = %d\n", ntohs(arp->op));
  printf("arp_source = %s\n", convmac_tostr(arp->source_mac,mac,sizeof(mac) ));
  printf("arp_source_ip = ");
  for(i=0; i<4;i++) printf("%d.", arp->source_ip[i]);
  printf("\narp_tell_mac = %s\n", convmac_tostr(arp->tell_mac,mac,sizeof(mac) ));
  printf("arp_tell_ip = %s\n", inet_ntoa(arp->tell_ip));
  printf("\n");

}

//ethhdr->h_destは 8*6=48 biteある(6byte分)。u_char(1byte)で区切って16進数表示させたい。
//もともとh->dest,sourceはu_char[6]の配列なので、受け取って配列一個ずつ変換していくと良い。
static char*
print_ethheader(char *p)
{
  struct ethhdr *ethhdr;
  char mac[18]={0};
  ethhdr = (struct ethhdr *)p;
  char *hdr_type;

  switch (ntohs(ethhdr->h_proto)){
    case 0x0800:
    hdr_type = "IPv4";
    break;
    case 0x0806:
    hdr_type = "ARP";
    break;
    default :
    hdr_type = "Other";
    break;
  }
  printf("ethhdr_dest = %s\n", convmac_tostr(ethhdr->h_dest,mac,sizeof(mac) ));
  printf("ethhdr_source = %s\n", convmac_tostr(ethhdr->h_source,mac,sizeof(mac) ));
  printf("ethhdr proto = 0x%.4x : %s\n", ntohs(ethhdr->h_proto),hdr_type);
  printf("\n");
  return hdr_type;
}


static void
print_ipheader(char *p)
{
  struct ip *ip;
  ip = (struct ip *)p;
  printf("ip_version = 0x%d\n", ip->ip_v);
  printf("ip_header length = 0x%x\n", ip->ip_hl);
  printf("ip_type of service = 0x%.2x\n", ip->ip_tos);
  printf("ip_len = %d bytes\n", ntohs(ip->ip_len));
  printf("ip_id = 0x%.4x\t0x%.4x\n", ntohs(ip->ip_id),ip->ip_id);
  printf("ip_offset = 0x%.4x\n", ntohs(ip->ip_off));
  printf("ip_time to live = 0x%.2x\n", ip->ip_ttl);
  printf("ip_protocol = 0x%.2x\n", ip->ip_p);
  printf("ip_ check sum = 0x%.4x\n", ntohs(ip->ip_sum));
  printf("ip_src = %s\n", inet_ntoa(ip->ip_src));
  printf("ip_dst = %s\n", inet_ntoa(ip->ip_dst));
  printf("\n");
}


int main(int argc, char *argv[])
{
  //デバイス名(標準入力)とエラー吐き出し用配列
  if(argv[1] == NULL){
    fprintf(stderr,"Device Name is not inputed\n");
    exit(1);
  }
  char *dev = argv[1], errbuf[PCAP_ERRBUF_SIZE];
  char filter_exp[] = "port 23"; //監視したいポート
  struct bpf_program fp;
  struct pcap_pkthdr header;
  const u_char *packet;

  //デバイスオープン、プロミスキャスモード(全パケット取得)
  pcap_t *handle;
  handle = pcap_open_live(dev,1500,1,1000,errbuf);
  if(handle == NULL){
    fprintf(stderr,"pcap open live err:%s\n",errbuf);
    exit(1);
  }

  /*
  //フィルタのコンパイル
  if(pcap_compile(handle,&fp,filter_exp,0,"255.255...") == -1){
  fprintf(stderr,"pcap compile err:%s\n",errbuf);
  exit(1);
}
//フィルタの実行
if(pcap_setfilter(handle,&fp) == -1){
fprintf(stderr,"pcap setfilter err:%s\n",errbuf);
exit(1);
}
*/

//packetカウンター
int cnt = 0;
char *hdr_type;
while(1){
  packet = pcap_next(handle,&header);
  if(packet != NULL){
    cnt++;
    printf("packet num %d\n",cnt);
    hdr_type = print_ethheader( (char *)(packet) );
    if(!strcmp(hdr_type,"IPv4")){
      print_ipheader((char *)(packet+sizeof(struct ether_header)));
    }else if (!strcmp(hdr_type,"ARP")){
      print_arp((char *)(packet+sizeof(struct ether_header)));
    }
  }
}
pcap_close(handle);
return(0);
}
