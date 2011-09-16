#define HAS_WSOCK2 1
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "win_scan_engine.h"
#pragma comment( lib, "Ws2_32.lib" )
struct hostent *host;
struct timeval timeout;
char *local_ip;
int STOP_SNIFFER;
int STARTED_SNIFFER = 0;
void set_sniffer(int scan_type);
enum{
SYN,
FIN,
XMAS,
NULL_S,
UDP,
};

inline int udp_scan(int port)
{
int is_opened = FALSE;
return is_opened;
}

inline int tcp_scan(int port)
{
  int sock = 0;
  int is_opened = FALSE;
  struct sockaddr_in tcp_dest;
  int success = -1;
  if((sock = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
      printf("Couldn't make socket!\n");
      exit(-1);
    }

  tcp_dest.sin_family = AF_INET;
  tcp_dest.sin_port = htons(port);
  tcp_dest.sin_addr = *((struct in_addr *)host->h_addr);
  memset(&(tcp_dest.sin_zero), '\0', 8);
  success = connect(sock , (struct sockaddr *)&tcp_dest, sizeof(struct sockaddr));
    if (success != -1)
      {
	is_opened = TRUE;
      }
    else
      {
	is_opened = FALSE;
      }
  closesocket(sock);
  return is_opened;
}

inline int raw_scan(int port, int scan_type)
{
int is_opened = FALSE;
char packet[sizeof(struct tcp_hdr)+sizeof(struct ip_hdr)];
struct ip_hdr *ip = (struct ip_hdr *) packet + sizeof(struct ip_hdr);
struct tcp_hdr *tcp = (struct tcp_hdr *) packet + sizeof(struct ip_hdr);
struct in_addr dest;
struct sockaddr_in sin;
PS_HDR pseudo;
int sock;
int on = 1;
dest = *((struct in_addr *)host->h_addr);
sin.sin_family = AF_INET;
sin.sin_port = htons(port);
sin.sin_addr = dest;
memset (packet, 0, sizeof(packet));
ip->ip_hl = 5;
ip->ip_v = 4;
ip->ip_tos = 0;
ip->ip_len = sizeof(struct ip_hdr) + sizeof(struct tcp_hdr);
ip->ip_id = 1;
ip->ip_off = 0;
ip->ip_ttl = 255;
ip->ip_p = 6;
ip->ip_sum = 0;
ip->ip_src = inet_addr(local_ip);
ip->ip_dst = dest.s_addr;
tcp->th_sport = htons(rand()%65535);
tcp->th_dport = htons(port);
tcp->th_seq = rand();
tcp->th_ack = 0;
tcp->th_x2 = 0;
tcp->th_off = 0;
tcp->th_flags = 2;
tcp->th_win = htons(65535);
tcp->th_sum = 0;
tcp->th_urp = 0;
pseudo.source_address = inet_addr(local_ip);
pseudo.dest_address = dest.s_addr;
pseudo.placeholder = 0;
pseudo.protocol = IPPROTO_TCP;
pseudo.tcp_length = htons(sizeof(struct tcp_hdr));
tcp->th_sum = checksum((unsigned short *)&pseudo, sizeof(pseudo));
ip->ip_sum = checksum((unsigned short *)&ip, sizeof(struct ip_hdr));

if ((sock = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
    {
    perror("socket");
    exit(1);
    }
if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (char *)&on, sizeof(on)) == SOCKET_ERROR)
    {
    perror("setsockopt");
    exit(1);
    }
/*
if (sendto(sock, packet, sizeof(packet), 0, (struct sockaddr *)&sin, sizeof(sin)) == SOCKET_ERROR)
    {
    perror("sendto");
    exit(1);
    }
*/
closesocket(sock);    
return is_opened;
}

void set_sniffer(int scan_type)
{
int sock;
char temp[MAX_HOSTNAME_LAN];
char buffer[sizeof(struct tcp_hdr) + sizeof(struct ip_hdr)];
struct tcp_hdr *tcp = (struct tcp_hdr *) (buffer + sizeof(struct ip_hdr));
struct hostent *h;
DWORD dwBytesRet;
int optval = 1;
SOCKADDR_IN sa;
gethostname(temp, MAX_HOSTNAME_LAN);
h = gethostbyname(temp);
sa.sin_family = AF_INET;
sa.sin_port = htons(0);
sock = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
memcpy(&sa.sin_addr.S_un.S_addr, h->h_addr_list[0], h->h_length);
//setsockopt(sock,IPPROTO_TCP,IP_HDRINCL, (char*)&optval, sizeof(optval));
bind(sock, (SOCKADDR *)&sa, sizeof(sa));
WSAIoctl(sock, SIO_RCVALL, &optval, sizeof(optval), NULL, 0, &dwBytesRet, NULL, NULL);
printf("starting sniffer\n");
STARTED_SNIFFER = 1;
while(1)
    {
    memset(buffer, 0, sizeof(buffer));
	recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
	printf("received packet %s\n", buffer);
    }
closesocket(sock);
STARTED_SNIFFER = 0;
}

void get_ip()
{
char temp[MAX_HOSTNAME_LAN];
struct hostent *h;
gethostname(temp, MAX_HOSTNAME_LAN);
h = gethostbyname(temp);
local_ip = inet_ntoa(*((struct in_addr *)h->h_addr));
}

