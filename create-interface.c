#include<error.h>
#include <netinet/in.h>    
#include <sys/ioctl.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <linux/wireless.h>
#include <errno.h>
#include <math.h>

typedef unsigned char      uchar; 


int config_radio_interface(const char device[])
{
  int sd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
  struct iwreq    wrq;
  memset(&wrq, 0, sizeof(wrq));
  strncpy(wrq.ifr_name, device, IFNAMSIZ);
  
  wrq.u.mode = IW_MODE_MONITOR;
  if (0 > ioctl(sd, SIOCSIWMODE, &wrq)) {
    printf("ioctl(SIOCSIWMODE) : %s\n", strerror(errno));
    syslog(LOG_ERR, "ioctl(SIOCSIWMODE): %s\n", strerror(errno));
    return 1;
  }
#if  0
	
  if(wrq.u.mode == IW_MODE_MONITOR){
    printf("The device is in monitor mode \n");
  } 
  wrq.u.mode = 2;//6 {6 is monitor mode}; //b/g  mode <= this is what mode Jigsaw guys used (mode=2), but that doesn't make sense ?
  wrq.u.data.length = 3;
  wrq.u.data.flags = 0;
  if (0 > ioctl(sd, SIOCIWFIRSTPRIV, &wrq)) {
    printf("ioctl(SIOCIWFIRSTPRIV) : %s\n", strerror(errno));
    syslog(LOG_ERR, "ioctl(SIOCIWFIRSTPRIV): %s\n", strerror(errno));
    return 1;
  }
  
#endif
	return 0;
}

int up_radio_interface(const char device[])
{
  int sd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, device, IFNAMSIZ);
  if (-1 == ioctl(sd, SIOCGIFFLAGS, &ifr)) {
    printf("ioctl(SIOCGIFFLAGS) : %s\n", strerror(errno));
    syslog(LOG_ERR, "ioctl(SIOCGIFFLAGS): %s\n", strerror(errno));
    return 1;
  }
  const int flags = IFF_UP|IFF_RUNNING|IFF_PROMISC;
  if (ifr.ifr_flags  == flags)
    return 0;
  ifr.ifr_flags = flags;
  if (-1 == ioctl(sd, SIOCSIFFLAGS, &ifr)) {
    printf("ioctl(SIOCSIFFLAGS) : %s\n", strerror(errno));
    syslog(LOG_ERR, "ioctl(SIOCSIFFLAGS): %s\n", strerror(errno));
    return 1;
  }
  
  return 0;
}

int down_radio_interface(const char device[])
{
  int sd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, device, IFNAMSIZ);
  if (-1 == ioctl(sd, SIOCGIFFLAGS, &ifr)) {
    printf("ioctl(SIOCGIFLAGS) : %s\n", strerror(errno));
    syslog(LOG_ERR, "ioctl(SIOCGIFFLAGS): %s\n", strerror(errno));
    return 1;
  }
  if (0 == ifr.ifr_flags)
    return 0;
  ifr.ifr_flags = 0;
  if (-1 == ioctl(sd, SIOCSIFFLAGS, &ifr)) {
    printf("ioctl(SIOCSIWMODE) : %s\n", strerror(errno));
    syslog(LOG_ERR, "ioctl(SIOCSIFFLAGS): %s\n", strerror(errno));
    return 1;
  }
  return 0;
}

int open_infd(const char device[])
{
  int skbsz ;
  skbsz = 1U << 23 ; 
  int in_fd ;
  in_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (in_fd < 0) {
    printf("socket(PF_PACKET): %s\n", strerror(errno));
    return -1;
  }
  struct ifreq ifr;
  strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
  
  if (0 > ioctl(in_fd, SIOCGIFINDEX, &ifr)) {
    printf("ioctl(SIOGIFINDEX): %s\n", strerror(errno));
    return -1;
  }
  //printf("the ifindex of device is %d\n",ifr.ifr_ifindex);
  struct sockaddr_ll sll;
  memset(&sll, 0, sizeof(sll));
  sll.sll_family  = AF_PACKET;
  sll.sll_ifindex = ifr.ifr_ifindex;
  sll.sll_protocol= htons(ETH_P_ALL);
  if (0 > bind(in_fd, (struct sockaddr *) &sll, sizeof(sll))) {
    printf("bind(): %s\n", strerror(errno));
    return -1;
  }
  if (0 > setsockopt(in_fd, SOL_SOCKET, SO_RCVBUF, &skbsz, sizeof(skbsz))) {
    printf("setsockopt(in_fd, SO_RCVBUF): %s\n", strerror(errno));
    return -1;
  }
  int skbsz_l = sizeof(skbsz);
  if (0 > getsockopt(in_fd, SOL_SOCKET, SO_RCVBUF, &skbsz,
		     (socklen_t*)&skbsz_l)) {
    printf("getsockopt(in_fd, SO_RCVBUF): %s\n", strerror(errno));
    return -1;
  }
  int rcv_timeo = 600;
  struct timeval rto = { rcv_timeo, 0};
  if (rcv_timeo > 0 &&
      0 > setsockopt(in_fd, SOL_SOCKET, SO_RCVTIMEO, &rto, sizeof(rto))) {
    printf( "setsockopt(in_fd, SO_RCVTIMEO): %s\n", strerror(errno));
    return -1;
  }
  //close (in_fd) ;
  return in_fd ;
}

int checkup(char * device){
  if (down_radio_interface(device))
    return 1;
  if (up_radio_interface(device))
    return 1;
  if (config_radio_interface(device))
    return 1;
  int in_fd ;
  in_fd = open_infd(device);
  
  return 0;
}
