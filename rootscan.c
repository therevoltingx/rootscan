#include <stdio.h>
#include <stdlib.h>
#ifdef WIN32
#include "pthreads/include/pthread.h"
#else
#include <pthread.h>
#endif
#include <errno.h>
#ifndef WIN32
#include "scan_engine.c"
#else
#include "getopt.c"
#include "win_scan_engine.c"
#endif
#define TCP_SCAN 1
#define UDP_SCAN 2
#define SYN_SCAN 3
#define FIN_SCAN 4
#define NULL_SCAN 5
#define XMAS_SCAN 6
#define NO 0
#define YES 1
int parallel = NO;
int verbose = NO;
int timeout_sec;
int scan_type;
int packet_delay;
char *host_addr;
int port_list[65535];
int start_port = 1;
int end_port = 65535;
struct timeval timeout;

void usage(char progname[]);
void scan_engine();
void *try_tcp_port(void *);
void *try_udp_port(void *);
void *try_raw_port(void *);
void *sniffer_thread(void *tmp);
void iterate_ports();
void opened_raw_port(int port);
unsigned short in_cksum(unsigned short *addr,int len);

int main(int argc, char *argv[])
{
  char ch;
  if(argc < 2) {
    usage(argv[0]);
    exit(-1);
  }
#ifdef WIN32
WSADATA wsaData;
WSAStartup(MAKEWORD(1, 1), &wsaData);
atexit((void *)WSACleanup);
#endif
  optarg = NULL;
  timeout_sec = 2;
  packet_delay = .0001;
  scan_type = TCP_SCAN;
  parallel = YES;
  while ((ch = getopt(argc, argv, "sufnxtpvhd:b:e:c:")) != -1)
    switch (ch)
      {
      case 's':
	scan_type = SYN_SCAN;
	break;
      case 'u':
	scan_type = UDP_SCAN;
	break;
      case 't':
	scan_type = TCP_SCAN;
	break;
      case 'f':
        scan_type = FIN_SCAN;
	break;
      case 'n':
        scan_type = NULL_SCAN;
	break;
      case 'x':
        scan_type = XMAS_SCAN;
	break;
      case 'b':
	start_port = atoi(optarg);
	break;
      case 'e':
	end_port = atoi(optarg);
	break;
      case 'p':
	parallel = NO;
	break;
      case 'c':
	timeout_sec = atoi(optarg);
	break;
      case 'd':
        packet_delay = atoi(optarg);
	break;
      case 'v':
	verbose = YES;
	break;
      case 'h':
	usage(argv[0]);
	break;
      default:
	break;
      }

  host_addr = argv[optind]; /*This could segfault if user specifies an option but not a host*/

  scan_engine();
  if (parallel == YES) pthread_exit(NULL);
  else
    return 0;
} /* End of main() */

void scan_engine()
{
  int n_threads = 0;
  int count = 0;
  int x;
  struct timespec delay;
  get_ip();
  if (verbose == YES) printf("Scanning host: %s\n", host_addr);
  if (verbose == YES) printf("From: %s\n", local_ip);
#ifdef WIN32
if (scan_type != TCP_SCAN)
if (!strcmp("127.0.0.1", local_ip))
    {
    printf("Win32 Error: Cannot use raw scan on loopback device.\n");
    exit(1);
    }
#endif    
  if (verbose == YES)
  switch (scan_type){
  case TCP_SCAN:
  printf("Using TCP connect() scan...\n");
  break;
  case SYN_SCAN:
  printf("Using SYN scan...\n");
  break;
  case UDP_SCAN:
  printf("Using UDP Scan...\n");
  break;
  case FIN_SCAN:
  printf("Using FIN Scan...\n");
  break;
  case XMAS_SCAN:
  printf("Using XMAS Scan....\n");
  break;
  case NULL_SCAN:
  printf("Using NULL Scan...\n");
  break;
  default:
  break;
  }
/*this is for port iterating, not really important, only for FIN, XMAS, and NULL type scans*/
int z = 0;
for (; z < 65535; z++)
port_list[z] = 1;
/*end of iterating*/

  if((host = gethostbyname(host_addr)) == NULL)
    {
      printf("Couldn't resolve %s\n", host_addr);
      exit(-1);
    }
  printf("\t\tPort\t\tState\t\tService\n\n");

/*if raw scan start sniffer*/
if (scan_type != TCP_SCAN && scan_type != UDP_SCAN)
{
pthread_t sniff_thread_t;
pthread_detach(sniff_thread_t);
if (pthread_create(&sniff_thread_t, NULL, sniffer_thread, (void *)scan_type))
	{
	perror("pthread_create");
	exit(1);
	}
//sniffer_thread((void *)scan_type);
/*We wait until sniffer has started before sending packets*/
while (!STARTED_SNIFFER);
}
  switch (scan_type)
    {
      /*****************************************************************/
      /****************************TCP_SCAN*****************************/
      /*****************************************************************/
    case TCP_SCAN:
      /* Start for loop to connect to each port */
      for(count = start_port; count <= end_port; count++)
	{
	  if (parallel == YES)
	    {
	      pthread_t thread_t;
	      pthread_detach(thread_t);
	      n_threads++;
	      if (pthread_create(&thread_t, NULL, try_tcp_port, (void *)count))
		{
		  count--;
		  n_threads--;
		}
	    }
	  else	{
	    try_tcp_port((void *)count);
	  }
	}/* End the for loop */
      break;
      /*****************************************************************/
      /****************************UDP_SCAN*****************************/
      /*****************************************************************/
    case UDP_SCAN:
#ifndef WIN32
      if (getuid() != 0)
	{
	  printf("You must be root to use this scan method!\n");
	  exit(1);
	}
#endif
      for(count = start_port; count <= end_port; count++)
	{
	  if (parallel == YES)
	    {
	      pthread_t thread_t;
	      pthread_detach(thread_t);
	      n_threads++;
	      if (pthread_create(&thread_t, NULL, try_udp_port, (void *)count))
		{
			perror("thread");
		  count--;
		  n_threads--;
		}
	    }
	  else
	    {
	      try_udp_port((void *)count);
	    }
	}
      break;
      /*****************************************************************/
      /****************************RAW_SCAN*****************************/
      /***********************(SYN|FIN|XMAS|NULL)***********************/
    case SYN_SCAN:
    case FIN_SCAN:
    case XMAS_SCAN:
    case NULL_SCAN:
#ifndef WIN32
      if (getuid() != 0)
	{
	  printf("You must be root to use this scan method!\n");
	  exit(1);
	}
#endif      
      for(count = start_port; count <= end_port; count++) {
   	if (parallel == YES)
	  {
	    pthread_t thread_t;
	    pthread_detach(thread_t);
	    n_threads++;
	    if (pthread_create(&thread_t, NULL, try_raw_port, (void *)count))
	      {
		count--;
		n_threads--;
	      }
	  }
	else
	  {
	    try_raw_port((void *)count);
	  }
      }  /* End for() */
      break;
    default:
      exit(1);
      break;
    }
/*this waits a few seconds to make sure we received all packages*/
if (scan_type != TCP_SCAN && scan_type != SYN_SCAN)
  {
  sleep(.5);
  iterate_ports();/*we iterate through the port_list array*/
  }
printf("Scan Complete.\n");
exit(0);
}


void opened_port(int port)
{
/*Opened tcp connect() port*/
struct servent *serv;
if (scan_type == UDP_SCAN)
  serv = getservbyport(htons(port), "udp");
else
  serv = getservbyport(htons(port), "tcp");
printf("\t\t%d \t\t Open \t\t %s\n", port, (serv == NULL) ? "UNKNOWN" : serv->s_name);
if (port_list[port] != 0)
port_list[port] = 0;
}

void *try_tcp_port(void *tmp)
{
int port = (int)(tmp);
#ifdef WIN32
printf("%d\r", port);
#else
/*if (verbose == YES) printf("%d\r", port);*/
#endif

if (tcp_scan(port))
	{
	opened_port(port);
	}
else
	{
	if (parallel == YES) pthread_exit(NULL);
	else
	return NULL;
	}
}

void *try_udp_port(void *tmp)
{
int port = (int)(tmp);

}

void *try_raw_port(void *tmp)
{
int port = (int)(tmp);
sleep(packet_delay);
#ifdef WIN32
printf("%d\r", port);
#else
/*if (verbose == YES) printf("%d\r", port);*/
#endif
switch(scan_type)
	{
	case SYN_SCAN:
	raw_scan(port, SYN);
	break;
	case FIN_SCAN:
        raw_scan(port, FIN);
	break;
	case XMAS_SCAN:
        raw_scan(port, XMAS);
	break;
	case NULL_SCAN:
        raw_scan(port, NULL_S);
	break;
	}
}

void closed_raw_port(int port)
{
port_list[port] = 0;
}

void iterate_ports()
{
int x;
for (x = start_port; x <= end_port; x++)
   {
   if (port_list[x] != 0)
   opened_raw_port(x);
   }
}

void opened_raw_port(int port)
{
struct servent *serv;
if (scan_type == UDP_SCAN)
  serv = getservbyport(htons(port), "udp");
else
  serv = getservbyport(htons(port), "tcp");
printf("\t\t%d \t\t Open \t\t %s\n", port, (serv == NULL) ? "UNKNOWN" : serv->s_name);
if (port_list[port] != 0)
port_list[port] = 0;
}

void *sniffer_thread(void *tmp)
{
int type = (int)(tmp);
switch(type)
	{
	case SYN_SCAN:
	set_sniffer(SYN);
	break;
	case FIN_SCAN:
	set_sniffer(FIN);
	break;
	case NULL_SCAN:
	set_sniffer(NULL_S);
	break;
	case XMAS_SCAN:
	set_sniffer(XMAS);
	break;
	}
pthread_exit(NULL);
return NULL;
}

void usage(char *progname) {
  printf("Usage: %s  [options] host/ip\n", progname);
  printf("\t-p : Disable threads\n");
  printf("\t-b number: start scanning at port number. (default = 1)\n");
  printf("\t-e number: stop scanning at port number. (default = 65535)\n");
  printf("\t-c number: Set timeout (default = 3, \n");
  printf("\t-v: Be verbose (mostly for debugging or checking speed)\n");
  printf("\n\nRootscan was written by shaunige@yahoo.co.uk,\nEckz - mrx@netlane.com - http://freewebs.com/bh_x,\nand Ozzy.\n");
  printf("\nNote: UDP scan sucks for now.\n");
  exit(-1);
}  /* End function */

