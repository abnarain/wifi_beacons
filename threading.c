#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <inttypes.h>
#include <signal.h>
#define DE 1
#define SLEEP_PERIOD 2
static pthread_t signal_thread;
static pthread_t update_thread;


void write_update(int a){
printf("wrote update %d\n",a);

}
void my_callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char*
        packet)
{
   printf(".");
}
static void* updater(void* arg) {
  while (1) {
    sleep(SLEEP_PERIOD);
    if (pthread_mutex_lock(&update_lock)) {
      perror("Error acquiring mutex for update");
      exit(1);
    }
    write_update(1);
    if (pthread_mutex_unlock(&update_lock)) {
      perror("Error unlocking update mutex");
      exit(1);
    }
  }
}

static void* handle_signals(void* arg) {
  sigset_t* signal_set = (sigset_t*)arg;
  int signal_handled;
  while (1) {
    if (sigwait(signal_set, &signal_handled)) {
      perror("Error handling signal");
      continue;
    }
    if (pthread_mutex_lock(&update_lock)) {
      perror("Error acquiring mutex for update");
      exit(1);
    }
    write_update(2);
    exit(0);
  }
}



int main(int argc,char **argv)
{ 
    int i;
    char *dev; 
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    const u_char *packet;
    struct pcap_pkthdr hdr;     /* pcap.h */
    struct ether_header *eptr;  /* net/ethernet.h */
  sigset_t signal_set;
  sigemptyset(&signal_set);
  sigaddset(&signal_set, SIGINT);
  sigaddset(&signal_set, SIGTERM);
  if (pthread_sigmask(SIG_BLOCK, &signal_set, NULL)) {
    perror("Error calling pthread_sigmask");
    return 1;
  }
 if (pthread_create(&signal_thread, NULL, handle_signals, &signal_set)) {
    perror("Error creating signal handling thread");
    return 1;
  }

if (pthread_create(&update_thread, NULL, updater, NULL)) {
    perror("Error creating updates thread");
    return 1;
  }
    /* grab a device to peak into... */
    dev = pcap_lookupdev(errbuf);
    if(dev == NULL)
    { printf("%s\n",errbuf); exit(1); }
    /* open device for reading */
    descr = pcap_open_live(dev,BUFSIZ,0,-1,errbuf);
    if(descr == NULL)
    { printf("pcap_open_live(): %s\n",errbuf); exit(1); }
    pcap_loop(descr,-1,my_callback,NULL);
    return 0;
}
