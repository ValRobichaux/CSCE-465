#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <stdlib.h>

// Creating the IP Header
struct ipheader {
    unsigned char iph_ihl:4, iph_ver:4;
    unsigned char iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    unsigned short int iph_flag:3, iph_offset:13;
    unsigned char iph_ttl;
    unsigned char iph_protocol;
    unsigned short int iph_chksum;
    struct in_addr iph_sourceip;
    struct in_addr iph_destip;
};

// Creating the ICMP Header
struct icmpheader {
    unsigned char icmp_type;
    unsigned char icmp_code;
    unsigned short int icmp_chksum;
    unsigned short int icmp_id;
    unsigned short int icmp_seq;
};

void send_raw_ip_packet (struct ipheader *ip) {
    int sd;
    int enable = 1;
    struct sockaddr_in sin;
    // Creating a raw socket with IP protocol. 
    //The IP header here will already be included in this
    sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(sd < 0) {
        perror("socket() error");
        exit(-1);
    }
    setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));
    
    //when using raw socktes we will not need to fill out this data
    sin.sin_family = AF_INET;
    sin.sin_addr = ip->iph_destip;
    
    //sending out the raw packet and if there are any errors we should be able to catch them
    if(sendto(sd, ip, ntohs(ip->iph_len), 0, (struct sockaddr *)&sin,sizeof(sin)) < 0) {
        perror("sendto() error"); 
        exit(-1);
    }
}
unsigned short in_chksum(unsigned short *buf, int length) {
    unsigned short *w = buf;
    int nleft = length;
    int sum = 0;
    unsigned short temp = 0;
    while(nleft > 1) {
        sum+= *w++;
        nleft -=2;
    }
    if (nleft == 1) {
        *(u_char *)(&temp) = *(u_char *)w;
        sum+=temp;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum>>16);
    return (unsigned short)(~sum);
}
int main() {
    char buffer[1500];
    memset(buffer, 0, 1500);
    struct ipheader *ip = (struct ipheader *) buffer;
    struct icmpheader *icmp = (struct icmpheader *) (buffer + sizeof(struct ipheader));

    //Fill out the IP header
    ip->iph_ver = 4;
    ip->iph_ihl = 5;
    ip->iph_ttl = 20;
    ip->iph_sourceip.s_addr = inet_addr("1.2.3.4");
    ip->iph_destip.s_addr = inet_addr("10.9.0.1");
    ip->iph_protocol = IPPROTO_ICMP;
    ip -> iph_len = htons(1000);
    ip->iph_len=htons(sizeof(struct ipheader)+sizeof(struct icmpheader));
    
    //Fill out the ICMP header
    icmp->icmp_type=8;
    icmp->icmp_chksum=0;
    icmp->icmp_chksum = in_chksum((unsigned short *)icmp, sizeof(struct ipheader));
    
    // Spoofing the packet
    send_raw_ip_packet(ip);
    return 0;
}