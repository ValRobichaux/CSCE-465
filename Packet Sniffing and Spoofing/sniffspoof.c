#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>



struct sniff_eth {
  u_char  ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
  u_char  ether_shost[ETHER_ADDR_LEN]; /* source host address */
  u_short ether_type;                  /* IP? ARP? RARP? etc */
};



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


struct sniff_icmp {
  unsigned char icmp_type; // ICMP message type
  unsigned char icmp_code; // Error code
  unsigned short int icmp_chksum; //Checksum for ICMP Header and data
  unsigned short int icmp_id;     //Used for identifying request
  unsigned short int icmp_seq;    //Sequence number
};





unsigned short in_cksum (unsigned short *buf, int length)
{
   unsigned short *w = buf;
   int nleft = length;
   int sum = 0;
   unsigned short temp=0;

   while (nleft > 1)  {
       sum += *w++;
       nleft -= 2;
   }

   if (nleft == 1) {
        *(u_char *)(&temp) = *(u_char *)w ;
        sum += temp;
   }

   sum = (sum >> 16) + (sum & 0xffff);  
   sum += (sum >> 16);                  
   return (unsigned short)(~sum);
}
  
void send_raw_ip_packet(struct sniff_ip* ip)
{
    struct sockaddr_in dest_info;
    int enable = 1;

    // Creating a raw network socket
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    // Setting our socket option
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, 
                     &enable, sizeof(enable));

    // provide all the information we need for the destination
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_destip;

    // Sending out the packet
    sendto(sock, ip, ntohs(ip->iph_len), 0, 
           (struct sockaddr *)&dest_info, sizeof(dest_info));
    close(sock);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

  struct sniff_eth* eth = (struct sniff_eth *)packet;

  if (ntohs(eth->ether_type) == 0x0800) { 
    struct sniff_ip * ip = (struct sniff_ip *)(packet + sizeof(struct sniff_eth)); 
      int size_ip = ip->iph_ihl*4;
      

    printf("From: %s\n", inet_ntoa(ip->iph_sourceip));  
    printf("To: %s\n", inet_ntoa(ip->iph_destip));


     //determening the protocol 
    switch(ip->iph_protocol) {                               
        case IPPROTO_TCP:
            printf("   Protocol: TCP\n");
            
            break;
        case IPPROTO_UDP:
            printf("   Protocol: UDP\n");
            break;
        case IPPROTO_ICMP:
            printf("   Protocol: ICMP\n");
            
           struct sniff_icmp* icmpData=(struct sniff_icmp*)((u_char *)packet + sizeof(struct sniff_eth)+size_ip);

          	char buffer[1500];
         	
         	int data_len = header->len-(sizeof(struct sniff_eth)+sizeof(struct sniff_ip)+sizeof(struct sniff_icmp));
		char* data= packet+sizeof(struct sniff_eth)+sizeof(struct sniff_ip)+sizeof(struct sniff_icmp);

   		memcpy(buffer+sizeof(struct sniff_ip)+sizeof(struct sniff_icmp), data, data_len);
   		
   		// Filling out our new IP header
   		struct sniff_ip *ip2 = (struct sniff_ip *) buffer;
  		ip2->iph_ver = 4;
  		ip2->iph_ihl = 5;
  		ip2->iph_ttl = 20;
   		ip2->iph_sourceip = ip->iph_destip;
   		ip2->iph_destip = ip->iph_sourceip;
   		ip2->iph_protocol = IPPROTO_ICMP; 
   		ip2->iph_chksum=0;
               ip2->iph_chksum = in_cksum((unsigned short *)ip2, 
                                 sizeof(struct sniff_ip));

   		ip2->iph_len = htons(sizeof(struct sniff_ip) + 
               		        sizeof(struct sniff_icmp)+data_len);
               
		// building out our new icmp header
   		struct sniff_icmp *icmp = (struct sniff_icmp *) 
                             (buffer + (ip->iph_ihl*4));
                
                        
   		icmp->icmp_type = 0; //ICMP Type: 8 is request, 0 is reply.
   		icmp->icmp_code = icmpData->icmp_code;
   		icmp->icmp_id = icmpData->icmp_id;
   		icmp->icmp_seq = icmpData->icmp_seq;
   		
   		// Calculate the checksum
   		icmp->icmp_chksum = 0;
   		icmp->icmp_chksum = in_cksum((unsigned short *)icmp, 
                                 sizeof(struct sniff_icmp)+data_len);
                     

   		

//send the raw IP packet
        
   send_raw_ip_packet (ip2);

            break;
        default:
            printf("   Protocol: others\n");
            break;
    }

	} 
    
  }


int main() {

	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[] = "icmp";
	bpf_u_int32 net;

	// step 1: open live pcap session on NIC with the name that matches my machine
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