#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>

/* Ethernet header */
struct sniff_eth {
    u_char  ether_dhost[6];    /* destination host address */
    u_char  ether_shost[6];    /* source host address */
    u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP Header */
struct sniff_ip {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address
  struct  in_addr    iph_destip;   //Destination IP address
};

/* TCP Header */
struct sniff_tcp {
    u_short tcp_sport;               /* source port */
    u_short tcp_dport;               /* destination port */
    u_int   tcp_seq;                 /* sequence number */
    u_int   tcp_ack;                 /* acknowledgement number */
    u_char  tcp_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;                 /* window */
    u_short tcp_sum;                 /* checksum */
    u_short tcp_urp;                 /* urgent pointer */
};


void got_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packet) {
  

  struct sniff_eth* eth = (struct sniff_eth *)packet;

  if (ntohs(eth->ether_type) == 0x0800) { 
    

    //defining our IP header offset
    struct sniff_ip * ip = (struct sniff_ip *)(packet + sizeof(struct sniff_eth)); 
        
        printf("Source IP: %s\n", inet_ntoa(ip->iph_sourceip));  
        printf("Destination IP: %s\n", inet_ntoa(ip->iph_destip));
    
    //defining our TCP header offset
    struct sniff_tcp *tcp = (struct sniff_tcp *)(packet + sizeof(struct sniff_eth) + sizeof(struct sniff_ip));
		
        printf("Source IP: %d\n", ntohs(tcp->tcph_srcport));
		printf("Destination IP: %d\n", ntohs(tcp->tcph_destport));   



    //determining the protocol we want to use when our filters are implemented.
    switch(ip->iph_protocol) {                               
        case IPPROTO_TCP:
            printf("Protocol: TCP\n");
            break;
        case IPPROTO_UDP:
            printf("Protocol: UDP\n");
            break;
        case IPPROTO_ICMP:
            printf("Protocol: ICMP\n");
            break;
        default:
            printf("Protocol: etc...\n");
            break;
    }

    //printing out the data that our packets contain
    char *data = (u_char *)packet + sizeof(struct sniff_eth) + sizeof(struct sniff_ip) + sizeof(struct sniff_tcp);
	int size_payload = ntohs(ip->iph_len) - (sizeof(struct sniff_ip) + sizeof(struct sniff_tcp));
	if (size_payload > 0) {
		printf("Payload (%d bytes):\n", size_payload);
		data+=12;
		printf("...%c\n", *data);

	} 
    
  }
}

int main() {

	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[] = "tcp and portrange 10-100";
	bpf_u_int32 net;

	// Step 1: Open live pcap session on NIC with name that matches my machine
	handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

	// step 2: compile filter_exp into BPF pseudo-code
	pcap_compile(handle, &fp, filter_exp, 0, net);
	if(pcap_setfilter(handle, &fp) !=0) {
		pcap_perror(handle,"Error:");
		exit(EXIT_FAILURE);
	}

	// step 3: capture packets
	pcap_loop(handle, -1, got_packet, NULL);

	pcap_close(handle); // close the handle
	return 0;
}