#define SIO_RCVALL _WSAIOW(IOC_VENDOR,1)
#define MAX_ADDR_LEN 16
#define MAX_HOSTNAME_LAN 255

USHORT checksum(USHORT *buffer, int size);

struct tcp_hdr {
 unsigned short int th_sport;
 unsigned short int th_dport;
 unsigned int th_seq;
 unsigned int th_ack;
 unsigned char th_x2:4, th_off:4;
 unsigned char th_flags;
 unsigned short int th_win;
 unsigned short int th_sum;
 unsigned short int th_urp;
}; /* total tcp header length: 20 bytes (=160 bits) */


struct ip_hdr {
 unsigned char ip_hl:4, ip_v:4; /* this means that each member is 4 bits */
 unsigned char ip_tos;
 unsigned short int ip_len;
 unsigned short int ip_id;
 unsigned short int ip_off;
 unsigned char ip_ttl;
 unsigned char ip_p;
 unsigned short int ip_sum;
 unsigned int ip_src;
 unsigned int ip_dst;
}; /* total ip header length: 20 bytes (=160 bits) */


typedef struct ps_hdr
{
    unsigned int   source_address;   // Source Address		 =>	  4 Bytes
    unsigned int   dest_address;     // Destination Address	 =>	  4 Bytes
    unsigned char  placeholder;	     // Place Holder		 =>	  1 Bytes
    unsigned char  protocol;	     // Protocol		 =>	  1 Bytes
    unsigned short tcp_length;	     // TCP Length		 =>    +  2 Bytes
				     //				       = 12 Bytes
    struct tcp_hdr tcp;

}PS_HDR;


typedef struct udp_hdr
{
    unsigned short sport;	     // Source Port		 =>	  2 Bytes
    unsigned short dport;	     // Destination Port	 =>	  2 Bytes
    unsigned short Length; 	     // Length			 =>	  2 Bytes
    unsigned short Checksum;	     // Checksum		 =>    +  2 Bytes
				     //				       =  8 Bytes
}UDP_HDR;
USHORT checksum(USHORT *buffer, int size)
{
    unsigned long cksum=0;
    while (size > 1)
    {
        cksum += *buffer++;
        size  -= sizeof(USHORT);   
    }
    if (size)
    {
        cksum += *(UCHAR*)buffer;   
    }
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >>16); 
    return (USHORT)(~cksum); 
}

