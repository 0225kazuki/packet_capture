#include <pcap.h>
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


/* イーサネットアドレス（MACアドレス）は6バイト*/
#define ETHER_ADDR_LEN	6

/* イーサネットヘッダ */
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* 送信先ホストアドレス */
	u_char ether_shost[ETHER_ADDR_LEN]; /* 送信元ホストアドレス */
	u_short ether_type; /* IP? ARP? RARP? など */
};

/* IPヘッダ */
struct sniff_ip {
	u_char ip_vhl;		/* バージョン（上位4ビット）、ヘッダ長（下位4ビット） */
	u_char ip_tos;		/* サービスタイプ */
	u_short ip_len;		/* パケット長 */
	u_short ip_id;		/* 識別子 */
	u_short ip_off;		/* フラグメントオフセット */
	#define IP_RF 0x8000		/* 未使用フラグ（必ず0が立つ） */
	#define IP_DF 0x4000		/* 分割禁止フラグ */
	#define IP_MF 0x2000		/* more fragments フラグ */
	#define IP_OFFMASK 0x1fff	/* フラグメントビットマスク */
	u_char ip_ttl;		/* 生存時間（TTL） */
	u_char ip_p;		/* プロトコル */
	u_short ip_sum;		/* チェックサム */
	struct in_addr ip_src,ip_dst; /* 送信元、送信先IPアドレス */
};

//関数マクロ表記
#define IP_HL(ip)		( ( (ip) -> ip_vhl) & 0x0f )
#define IP_V(ip)		( ( (ip) -> ip_vhl) >> 4 )

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
	u_short th_sport;	/* 送信元ポート */
	u_short th_dport;	/* 送信先ポート */
	tcp_seq th_seq;		/* シーケンス番号 */
	tcp_seq th_ack;		/* 確認応答番号 */
	u_char th_offx2;	/* データオフセット、予約ビット */
	#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST 0x04
	#define TH_PUSH 0x08
	#define TH_ACK 0x10
	#define TH_URG 0x20
	#define TH_ECE 0x40
	#define TH_CWR 0x80
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* ウインドサイズ */
	u_short th_sum;		/* チェックサム */
	u_short th_urp;		/* 緊急ポインタ */
};


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

	/* イーサネットヘッダは常にちょうど14バイト */
	#define SIZE_ETHERNET 14

	const struct sniff_ethernet *ethernet;	/* イーサネットヘッダ */
	const struct sniff_ip *ip;		/* IPヘッダ */
	const struct sniff_tcp *tcp;		/* TCPヘッダ */
	const char *payload;			/* パケットペイロード */

	u_int size_ip;
	u_int size_tcp;


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

while(1){
	packet = pcap_next(handle,&header);
	if(header.len!=0){
		cnt++;
		ethernet = (struct sniff_ethernet*)(packet);
		ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
		printf("sizeof IPHL : %lu\n pointer:%p\n",sizeof(IP_HL(ip)*4) , &(ip->ip_vhl));
		size_ip = IP_HL(ip)*4;
		if (size_ip < 20) {
			printf("   * 不正なIPヘッダ長: %u bytes\n", size_ip);
			//return(1);
		}
		tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
		size_tcp = TH_OFF(tcp)*4;
		if (size_tcp < 20) {
			printf("   * 不正なTCPヘッダ長: %u bytes\n", size_tcp);
			//return(1);
		}

		//pyloadのトコでwarning出る
		payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
		printf("\npacket num::%d\n",cnt);
		printf("\tip header length\t:\t%u\n", size_ip);
		printf("\tFrom            \t:\t%s\n", inet_ntoa(ip->ip_src));
		printf("\tTo              \t:\t%s\n", inet_ntoa(ip->ip_dst));
		switch(ip->ip_p) {
			case IPPROTO_TCP:
			printf("\tProtocol        \t:\tTCP\n");
			break;
			case IPPROTO_UDP:
			printf("\tProtocol        \t:\tUDP\n");
			break;
			case IPPROTO_ICMP:
			printf("\tProtocol        \t:\tICMP\n");
			break;
			case IPPROTO_IP:
			printf("\tProtocol        \t:\tIP\n");
			break;
			default:
			printf("\tProtocol        \t:\tunknown\n");
			break;
		}
	}
}

pcap_close(handle);
return(0);



}
