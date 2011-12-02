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
#include <pcap.h>
#include "util.h"
#include "ieee80211_radiotap.h"
#include "abhinav.h"
#include "ieee80211.h"
#include "tcpdump.h"
#define IEEE802_11_AP_LEN 6



struct mgmt_header_t {
  u_int16_t    fc;               /* 2 bytes */
  u_int16_t    duration;         /* 2 bytes */
  u_int8_t     da[6];            /* 6 bytes */
  u_int8_t     sa[6];            /* 6 bytes */
  u_int8_t     bssid[6];         /* 6 bytes */
  u_int16_t    seq_ctrl;         /* 2 bytes */

};

const char* ether_sprintf(const unsigned char *mac)
{
  static char etherbuf[18];
  snprintf(etherbuf, sizeof(etherbuf), "%02x:%02x:%02x:%02x:%02x:%02x",
         mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return etherbuf;
}


u8* ieee80211_get_bssid(struct ieee80211_hdr *hdr, size_t len)
{
  __le16 fc;

  if (len < 24)
    return NULL;

  fc = le16_to_cpu(hdr->frame_control);

  switch (fc & IEEE80211_FCTL_FTYPE) {
    
  case IEEE80211_FTYPE_DATA:
    switch (fc & (IEEE80211_FCTL_TODS | IEEE80211_FCTL_FROMDS)) {
    case IEEE80211_FCTL_TODS:
      return hdr->addr1;
    case (IEEE80211_FCTL_TODS | IEEE80211_FCTL_FROMDS):
      return NULL;
    case IEEE80211_FCTL_FROMDS:
      return hdr->addr2;
    case 0:
      return hdr->addr3;
    }
    break;   
  case IEEE80211_FTYPE_MGMT:
    return hdr->addr3;
  case IEEE80211_FTYPE_CTL:
    if ((fc & IEEE80211_FCTL_STYPE) == IEEE80211_STYPE_PSPOLL)
      return hdr->addr1;
    else
      return NULL;
  }

  return NULL;
}

void ieee802_11_parse_elems(unsigned char *start, size_t len, struct packet_p *p)
{
  int left = len;
  //  int a;
  unsigned char *pos = start;
  while (left >= 2) {
    u8 id, elen;
    id = *pos++;
    elen = *pos++;
    left -= 2;
    if (elen > left)
      return;
    switch (id) {
    case WLAN_EID_SSID:
      /* printf("essid in parse : ");
      for(a=0;a<elen;a++){
	printf("%c",pos[a]);
      }
      printf("\n");
      memcpy(p->wlan_essid, pos, elen);
      */
      break;
    case WLAN_EID_DS_PARAMS:
      p->wlan_channel = *pos;
      break;
    default:
      break;
    }
    left -= elen;
    pos += elen;
  }
}



int ieee80211_get_hdrlen(u16 fc)
{
  int hdrlen = 24;

  switch (fc & IEEE80211_FCTL_FTYPE) {
  case IEEE80211_FTYPE_DATA:
    if ((fc & IEEE80211_FCTL_FROMDS) && (fc & IEEE80211_FCTL_TODS))
      hdrlen = 30; /* Addr4 */
    /*
     * The QoS Control field is two bytes and its presence is
     * indicated by the IEEE80211_STYPE_QOS_DATA bit. Add 2 to
     * hdrlen if that bit is set.
     * This works by masking out the bit and shifting it to
     * bit position 1 so the result has the value 0 or 2.
     */
    hdrlen += (fc & IEEE80211_STYPE_QOS_DATA) >> 6;
    break;
  case IEEE80211_FTYPE_CTL:
    /*
     * ACK and CTS are 10 bytes, all others 16. To see how
     * to get this condition consider
     *   subtype mask:   0b0000000011110000 (0x00F0)
     *   ACK subtype:    0b0000000011010000 (0x00D0)
     *   CTS subtype:    0b0000000011000000 (0x00C0)
     *   bits that matter:         ^^^      (0x00E0)
     *   value of those: 0b0000000011000000 (0x00C0)
     */
    if ((fc & 0xE0) == 0xC0)
      hdrlen = 10;
    else
      hdrlen = 16;
    break;
  }

  return hdrlen;
}

int ieee80211_frequency_to_channel(int freq)
{
  int base;

  if (freq == 2484)
    return 14;
  if (freq < 2484)
    base = 2407;
  else if (freq >= 4910 && freq <= 4980)
    base = 4000;
  else
    base = 5000;
  return (freq - base) / 5;
}

static int parse_80211_header(unsigned char** buf, int len, struct packet_p* p)
{
  struct ieee80211_hdr* wh;
  struct ieee80211_mgmt* whm;
  int hdrlen;
  u8* sa = NULL;
  u8* da = NULL;
  u8* bssid = NULL;
  u16 fc, cap_i;

  if (len < 2) // not even enough space for fc
    return -1;

  wh = (struct ieee80211_hdr*)*buf;
  fc = le16toh(wh->frame_control);
  hdrlen = ieee80211_get_hdrlen(fc);
  //  printf("len %d hdrlen %d\n", len, hdrlen);
  if (len < hdrlen)
    return -1;
  p->wlan_len = len;
  unsigned int wlan_type ;
  wlan_type= (fc & (IEEE80211_FCTL_FTYPE | IEEE80211_FCTL_STYPE));
  unsigned int pkt_types; 
  //printf("wlan_type %x - type %x - stype %x\n", fc,fc & IEEE80211_FCTL_FTYPE, fc & IEEE80211_FCTL_STYPE );
  
  bssid = ieee80211_get_bssid(wh, len);
  switch (wlan_type & IEEE80211_FCTL_FTYPE) {
  case IEEE80211_FTYPE_MGMT:
    pkt_types = PKT_TYPE_MGMT;
    whm = (struct ieee80211_mgmt*)*buf;
    sa = whm->sa;
    da = whm->da;
    p->wlan_seqno = le16toh(wh->seq_ctrl);
    printf("MGMT SEQ %d\n", p->wlan_seqno);
    if (fc & IEEE80211_FCTL_RETRY){
      printf("retries\n");
      p->wlan_retry = 1;
    }
    switch (wlan_type & IEEE80211_FCTL_STYPE) {
    case IEEE80211_STYPE_BEACON:
      pkt_types |= PKT_TYPE_BEACON;
      p->wlan_tsf = le64toh(whm->u.beacon.timestamp);
      p->wlan_bintval = le16toh(whm->u.beacon.beacon_int);
      ieee802_11_parse_elems(whm->u.beacon.variable,
                             len - sizeof(struct ieee80211_mgmt) - 4 , p); //4 is fcs
      // printf("ESSID %s \n", p->wlan_essid );
      //printf("CHAN %d \n", p->wlan_channel );
      cap_i = le16toh(whm->u.beacon.capab_info);
      if (cap_i & WLAN_CAPABILITY_IBSS)
	printf("capability: mode IBSS\n");// p->wlan_mode = WLAN_MODE_IBSS;
      else if (cap_i & WLAN_CAPABILITY_ESS)
        printf("capability: ess mode AP \n"); //p->wlan_mode = WLAN_MODE_AP;
      if (cap_i & WLAN_CAPABILITY_PRIVACY)
        printf("capability : privacy\n");//p->wlan_wep = 1;
      break;
    }
    break;
  }
  if (sa != NULL) {
    memcpy(p->wlan_src, sa, MAC_LEN);
    printf("SA    %s\n", ether_sprintf(sa));
  }
  if (da != NULL) {
    memcpy(p->wlan_dst, da, MAC_LEN);
    printf("DA    %s\n", ether_sprintf(da));
  }
  if (bssid!=NULL) {
    memcpy(p->wlan_bssid, bssid, MAC_LEN);
    printf("BSSID %s\n", ether_sprintf(bssid));
  }

  return 0;
}

static int parse_radiotap_header(unsigned char** buf , int len)
{
  struct ieee80211_radiotap_header* rh;
  __le32 present; // the present bitmap 
  unsigned char* b; // current byte 
  int i;
  u_int16_t rt_len, x;
  printf("RADIOTAP HEADER\n");
  //  printf("len: %d\n", len);
  //  printf("size of radiotap header =%d\n",sizeof(struct ieee80211_radiotap_header));
  //  if (len < sizeof(struct ieee80211_radiotap_header))
  // return -1;
  rh = (struct ieee80211_radiotap_header*)*buf;
  b = *buf + sizeof(struct ieee80211_radiotap_header);
  present = le32toh_(rh->it_present);
  rt_len = le16toh_(rh->it_len);
  //  printf("radiotap header len: %d\n", rt_len);
  // check for header extension - ignore for now, just advance current position 
  while (present & 0x80000000  && b - *buf < rt_len) {
    printf("extension\n");
    b = b + 4;
    present = le32toh_(*(__le32*)b);
  }
  present = le32toh_(rh->it_present); // in case it moved
  // radiotap bitmap has 32 bit, but  only interrested until bit 12 (IEEE80211_RADIOTAP_DB_ANTSIGNAL) ie i<13 
  for (i = 0; i < 13 && b - *buf < rt_len; i++) {
    if ((present >> i) & 1) {
      switch (i) {
      case IEEE80211_RADIOTAP_TSFT:
        printf("tsft [+8 %0x]", le16toh_(*(u_int64_t*)b));
        b = b + 8;
        break;
      case IEEE80211_RADIOTAP_DBM_TX_POWER:
      case IEEE80211_RADIOTAP_ANTENNA:
      case IEEE80211_RADIOTAP_RTS_RETRIES:
      case IEEE80211_RADIOTAP_DATA_RETRIES:
        printf("tx [+1 %d]",*b);
        b++;
        break;
      case IEEE80211_RADIOTAP_EXT:
        printf("[+4 %d]",le16toh_(*(u_int32_t*)b));
        b = b + 4;
        break;
      case IEEE80211_RADIOTAP_FHSS:
      case IEEE80211_RADIOTAP_LOCK_QUALITY:
      case IEEE80211_RADIOTAP_TX_ATTENUATION:
      case IEEE80211_RADIOTAP_RX_FLAGS:
      case IEEE80211_RADIOTAP_TX_FLAGS:
      case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
        printf("flags [+2 %x]",le16toh_(*(u_int16_t*)b));
        b = b + 2;
        break;
      case IEEE80211_RADIOTAP_RATE:
        printf("[rate %0x]", *b);
	if (*b & 0x80){
	  PRINT_HT_RATE("", *b, " Mb/s ");
	}
	else{
	  PRINT_RATE("", *b, " Mb/s ");
	}
        b++;
        break;
      case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
        printf("[sig %0x]", *b);
        b++;
        break;
      case IEEE80211_RADIOTAP_DBM_ANTNOISE:
        printf("[noise %0x]", *b);
        b++;
        break;
      case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
        printf("[snr %0x]", *b);
        b++;
        break;
      case IEEE80211_RADIOTAP_FLAGS:
	printf("[flags %0x", *b);
	if (*b & IEEE80211_RADIOTAP_F_CFP)
	  printf("cfp ");
	if (*b & IEEE80211_RADIOTAP_F_WEP)
	  printf("wep ");
	if (*b & IEEE80211_RADIOTAP_F_FRAG)
	  printf("fragmented ");
	if (*b & IEEE80211_RADIOTAP_F_SHORTPRE) {
          printf("short preamble");
        }
        if (*b & IEEE80211_RADIOTAP_F_BADFCS) {
          printf(" bad fcs");
        }
        printf("]");
        b++;
        break;
      case IEEE80211_RADIOTAP_CHANNEL:
        //channel & channel type 
        printf("[freq %d chan %d", le16toh_(*(u_int16_t*)b), ieee80211_frequency_to_channel(le16toh_(*(u_int16_t*)b)));
        b = b + 2;
        x = le16toh(*(u_int16_t*)b);
	/*	if (IS_CHAN_FHSS(x))
	  printf(" FHSS");
        if (IS_CHAN_A(x)) {
	  if (x & IEEE80211_CHAN_HALF)
	    printf(" 11a/10Mhz");
	  else if (x & IEEE80211_CHAN_QUARTER)
	    printf(" 11a/5Mhz");
	  else
	    printf(" 11a");
        }
        if (IS_CHAN_ANYG(x)) {
	  if (x & IEEE80211_CHAN_HALF)
	    printf(" 11g/10Mhz");
	  else if (x & IEEE80211_CHAN_QUARTER)
	    printf(" 11g/5Mhz");
	  else
	    printf(" 11g");
        } else if (IS_CHAN_B(x))
	  printf(" 11b");
        if (x & IEEE80211_CHAN_TURBO)
	  printf(" Turbo");
        if (x & IEEE80211_CHAN_HT20)
	  printf(" ht/20");
        else if (x & IEEE80211_CHAN_HT40D)
	  printf(" ht/40-");
        else if (x & IEEE80211_CHAN_HT40U)
	  printf(" ht/40+");
        printf("] ");
	*/
        if (x & IEEE80211_CHAN_A) {
          printf("A]");
        }
        else if (x & IEEE80211_CHAN_G) {
          printf("G]");
        }
        else if (x & IEEE80211_CHAN_B) {
          printf("B]");

        }/*
	else if(x & IEEE80211_CHAN_PUREG) {
	printf("PG]");
	}
	else if(x & IEEE80211_CHAN_BPLUS) {
	printf("BP]");
	}
	else if(x & IEEE80211_IS_CHAN_TA) {
	printf("TA]");
	}
	else if(x & IEEE80211_IS_CHAN_TB) {
	printf("TB]");
	}*/	
        b = b + 2;
        break;
      }
    }   
  }
  printf("\n");
  *buf = *buf + rt_len;
  return len - rt_len;
}
 
void process_packet (u_char * args, const struct pcap_pkthdr *header, const u_char * packet)
{
  struct ieee80211_radiotap_header *hdr;
  hdr = (struct ieee80211_radiotap_header *) packet;
  struct mgmt_header_t *mac_header;
  u_char *ptr;
  int length=header->len;
  int i;
  struct  packet_p * p ;
  p=malloc(sizeof(struct packet_p));
  int radiotapheader_length ;
  radiotapheader_length = ((EXTRACT_LE_16BITS(&hdr->it_len)));
  mac_header = (struct mgmt_header_t*)(packet+radiotapheader_length);
  //  printf("fc :           %d\n" ,mac_header->fc); this doesnt give additional information in case of beacons as filter is already placed by pcap
  printf("duration :     %u\n" ,mac_header->duration);
  printf("seq_ctrl :     %u\n" ,mac_header->seq_ctrl);
  ptr= mac_header->bssid;
  i=6;
  printf("bssid    :");   
  do{
    printf("%s%x",(i == 6) ? " " : ":",*ptr++);
  }while(--i>0);
  printf("\n");
    
  ptr = mac_header->da;
  i = 6;
  printf("Destination Address:  ");
  do{
    printf("%s%x",(i == 6) ? " " : ":",*ptr++);
  }while(--i>0);
  printf("\n");
  i=6;
  printf("Source Address     :  ");
  do{
    printf("%s%x",(i == 6) ? " " : ":",*ptr++);
  }while(--i>0);
  printf("\n");
  length=parse_radiotap_header(&packet, length);
  parse_80211_header(&packet,length,p);
  printf("------------------------------------\n");
  free(p);
}

int main(int argc, char* argv[])
{

  char errbuf[PCAP_ERRBUF_SIZE]; 
  bpf_u_int32 netp;   
  bpf_u_int32 maskp;  
  struct bpf_program fp; 
  int r;  
  char *device= argv[1];
  pcap_t *handle;  
  char *filter = "type mgt subtype beacon"; //the awesome one liner

  if (device == NULL) {
      device = pcap_lookupdev (errbuf); 
      if (device == NULL){  printf ("%s", errbuf); exit (1);}
    }
  handle = pcap_open_live (device, BUFSIZ,1,0,errbuf); 
  if (handle == NULL) { fprintf (stderr, "%s", errbuf);
      exit (1);
    }
  if (pcap_compile (handle, &fp, filter, 0, maskp) == -1){
      fprintf (stderr, "Compile: %s\n", pcap_geterr (handle)); exit (1);
    }

  if (pcap_setfilter (handle, &fp) == -1){
      fprintf (stderr, "Setfilter: %s", pcap_geterr (handle)); exit (1);
    }
  pcap_freecode (&fp);

  if ((r = pcap_loop(handle, -1, process_packet, NULL)) < 0){
    if (r == -1){  fprintf (stderr, "Loop: %s", pcap_geterr (handle)); exit (1);
    } // -2 : breakoff from pcap loop
  }
  /* close our devices */
  pcap_close (handle);
   return 0 ;
}






