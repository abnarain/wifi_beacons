#include <unistd.h>
#include <error.h>
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
#include <ctype.h>
#include <inttypes.h>
#include <signal.h>
#include <zlib.h>
#include "util.h"
#include "ieee80211_radiotap.h"
#include "ieee80211.h"
#include "td-util.h"
#include "create-interface.h"
#include "pkts.h"
#include<pthread.h>
//#include "drop_statistics.h"
#define UPDATE_FILENAME_COUNTS "/tmp/bismark-uploads/wifi-beacons/%s-%" PRIu64 "-ag-%d.gz"
#define PENDING_UPDATE_FILENAME_COUNTS "/tmp/sniffer/current-ag-update.gz"
/* Set of signals that get blocked while processing a packet. */
sigset_t block_set;

static int sequence_number = 0;
#define BISMARK_ID_FILENAME "/etc/bismark/ID"
#define UPDATE_FILENAME "/tmp/bismark-uploads/wifi-beacons/%s-%" PRIu64 "-%d.gz"
#define PENDING_UPDATE_FILENAME "/tmp/sniffer/current-update.gz"
static char bismark_id[256];

static int64_t start_timestamp_microseconds;
#define NUM_MICROS_PER_SECOND 1e6

int UPDATE_PERIOD_SECS =60 ; //default value

void write_update();

//#define MODE_DEBUG 0

void mgmt_header_print(const u_char *p, const u_int8_t **srcp,  const u_int8_t **dstp, struct r_packet* paket)
{
    const struct mgmt_header_t *hp = (const struct mgmt_header_t *) p;
    
    if (srcp != NULL)
      *srcp = hp->sa;
    if (dstp != NULL)
      *dstp = hp->da;    

    u_char *ptr;
    ptr = hp->sa;
    char temp[18];

    sprintf(temp,"%02x:%02x:%02x:%02x:%02x:%02x",ptr[0],ptr[1],ptr[2],ptr[3],ptr[4],ptr[5]);
    temp[17]='\0';
      
      memcpy(paket->mac_address,temp,strlen(temp));
#ifdef MODE_DEBUG
    printf("mac address =*%s* ",paket->mac_address );
    printf("BSSID: %s  \n",temp);
#endif
}

void print_chaninfo(int freq, int flags, struct r_packet * paket)
{
  paket->freq= freq ;
#ifdef MODE_DEBUG
  printf("%u MHz", freq);
#endif

  if (IS_CHAN_FHSS(flags)){
    memcpy(paket->channel_info,"FHSS",4);
#ifdef MODE_DEBUG
    printf("FHSS");
#endif
  }
  if (IS_CHAN_A(flags)) {
    if (flags & IEEE80211_CHAN_HALF){
      memcpy(paket->channel_info,"A10M",4);
#ifdef MODE_DEBUG
      printf("A10M");
#endif
    }
    else if (flags & IEEE80211_CHAN_QUARTER){
      memcpy(paket->channel_info,"A5M",3);
#ifdef MODE_DEBUG
      printf("A5M");
#endif
    }
    else{
      memcpy(paket->channel_info,"A",1);
#ifdef MODE_DEBUG
      printf("A");
#endif
    }

  }
  if (IS_CHAN_ANYG(flags)){
    if (flags & IEEE80211_CHAN_HALF){
      memcpy(paket->channel_info,"G10M",4);
#ifdef MODE_DEBUG
      printf("G10M");
#endif
    }
    else if (flags & IEEE80211_CHAN_QUARTER){
      memcpy(paket->channel_info,"G5M",3);
#ifdef MODE_DEBUG
      printf("G5M");
#endif
    }
    else{
 memcpy(paket->channel_info,"G",1);
#ifdef MODE_DEBUG
      printf("G");
#endif
    }
  } else if (IS_CHAN_B(flags)){
    memcpy(paket->channel_info,"B",1);
#ifdef MODE_DEBUG
    printf("B");
#endif
  }
  if (flags & IEEE80211_CHAN_TURBO){
    memcpy(paket->channel_info,"T",1);
#ifdef MODE_DEBUG
    printf("T");
#endif
  }
  if (flags & IEEE80211_CHAN_HT20){
    memcpy(paket->channel_info,"HT20",4);
#ifdef MODE_DEBUG
    printf("HT20");
#endif
  }
  else if (flags & IEEE80211_CHAN_HT40D){
    memcpy(paket->channel_info,"HT4-",4);
#ifdef MODE_DEBUG
    printf("HT4-");
#endif
  }
  else if (flags & IEEE80211_CHAN_HT40U){
    memcpy(paket->channel_info,"HT4+",4);
#ifdef MODE_DEBUG
    printf("HT4+");
#endif
  }
  
}

void ieee_802_11_hdr_print(u_int16_t fc, const u_char *p, u_int hdrlen, const u_int8_t **srcp, const u_int8_t **dstp, struct r_packet *paket)
{
  int vflag;
  vflag=1;
  if (vflag) {
    if (FC_MORE_DATA(fc))
      if (FC_MORE_FLAG(fc)){
	paket->more_frag =1;
#ifdef MODE_DEBUG
	printf("More Fragments ");
#endif
	}
    if (FC_POWER_MGMT(fc)){
      paket->pwr_mgmt=1;
#ifdef MODE_DEBUG
      printf("PM");
#endif
}
    if (FC_RETRY(fc)){
      paket->retry=1;
#ifdef MODE_DEBUG
      printf("R ");
#endif
}
    if (FC_ORDER(fc)){
      paket->strictly_ordered=1;
#ifdef MODE_DEBUG
      printf("SO ");
#endif
}
    if (FC_WEP(fc)){
      paket->wep_enc=1;
#ifdef MODE_DEBUG
      printf("WEP Encrypted ");
#endif
}
    if (FC_TYPE(fc) != T_CTRL || FC_SUBTYPE(fc) != CTRL_PS_POLL){
#ifdef MODE_DEBUG
      printf(" dur: %d ", EXTRACT_LE_16BITS(&((const struct mgmt_header_t *)p)->duration));
#endif
} 
 }
  switch (FC_TYPE(fc)) {
  case T_MGMT:
    mgmt_header_print(p, srcp, dstp,paket);
    break;
  default:
#ifdef MODE_DEBUG
    printf("UH%d",FC_TYPE(fc));
#endif
    *srcp = NULL;
    *dstp = NULL;
    break;
  }
}

/* * Print out a null-terminated filename (or other ascii string). If ep is NULL, assume no truncation check is needed.
 * Return true if truncated.
 */
int
fn_print(register const u_char *s, register const u_char *ep, struct r_packet * paket)
{
  register int ret;
  register u_char c;
  char temp[48];
  int i = 0; 
  ret = 1;                        /* assume truncated */
 while (ep == NULL || s < ep) {
    c = *s++;
    if (c == '\0') {
      temp[i]=c ;
      ret = 0;
      break;
    }
    if (!isascii(c)) {
      c = toascii(c);
      temp[i]='-';//c prev
      continue; 
#ifdef MODE_DEBUG
      putchar('M');
      putchar('-');
#endif
    }
    if (!isprint(c)) {
      c ^= 0x40;      /* DEL to ?, others to alpha */
      temp[i]='^';//c prev
      continue; 
#ifdef MODE_DEBUG
      putchar('^');
#endif
    }
    temp[i]=c;
    #ifdef MODE_DEBUG
    putchar(c);
    #endif
    i++;
 }
 if(ret==1)
   temp[i]='\0';
 // printf("!!%s!!",temp);
  memcpy(paket->essid,temp, strlen(temp));
  return(ret);
}
//==============================================================
#define cpack_int8(__s, __p)    cpack_uint8((__s),  (u_int8_t*)(__p))

int cpack_init(struct cpack_state *, u_int8_t *, size_t);
int cpack_uint8(struct cpack_state *, u_int8_t *);
int cpack_uint16(struct cpack_state *, u_int16_t *);
int cpack_uint32(struct cpack_state *, u_int32_t *);
int cpack_uint64(struct cpack_state *, u_int64_t *);

u_int8_t * cpack_next_boundary(u_int8_t *buf, u_int8_t *p, size_t alignment)
{
  size_t misalignment = (size_t)(p - buf) % alignment;

  if (misalignment == 0)
    return p;

  return p + (alignment - misalignment);
}

u_int8_t * cpack_align_and_reserve(struct cpack_state *cs, size_t wordsize)
{
  u_int8_t *next;
  next = cpack_next_boundary(cs->c_buf, cs->c_next, wordsize);
  if (next - cs->c_buf + wordsize > cs->c_len)
    return NULL;

  return next;
}

int cpack_uint32(struct cpack_state *cs, u_int32_t *u)
{
  u_int8_t *next;

  if ((next = cpack_align_and_reserve(cs, sizeof(*u))) == NULL)
    return -1;

  *u = EXTRACT_LE_32BITS(next);
  cs->c_next = next + sizeof(*u);
  return 0;
}
int cpack_uint16(struct cpack_state *cs, u_int16_t *u)
{
  u_int8_t *next;

  if ((next = cpack_align_and_reserve(cs, sizeof(*u))) == NULL)
    return -1;

  *u = EXTRACT_LE_16BITS(next);

  cs->c_next = next + sizeof(*u);
  return 0;
}


int cpack_uint8(struct cpack_state *cs, u_int8_t *u)
{

  if ((size_t)(cs->c_next - cs->c_buf) >= cs->c_len)
    return -1;

  *u = *cs->c_next;
  cs->c_next++;
  return 0;
}


int
cpack_init(struct cpack_state *cs, u_int8_t *buf, size_t buflen)
{
  memset(cs, 0, sizeof(*cs));

  cs->c_buf = buf;
  cs->c_len = buflen;
  cs->c_next = cs->c_buf;

  return 0;
}

int cpack_uint64(struct cpack_state *cs, u_int64_t *u)
{
  u_int8_t *next;

  if ((next = cpack_align_and_reserve(cs, sizeof(*u))) == NULL)
    return -1;
  *u = EXTRACT_LE_64BITS(next);
  cs->c_next = next + sizeof(*u);
  return 0;
}
//========================================================

int parse_elements(struct mgmt_body_t *pbody, const u_char *p, int offset,u_int length)
{
  struct ssid_t ssid;
  struct challenge_t challenge;
  struct rates_t rates;
  struct ds_t ds;
  struct cf_t cf;
  struct tim_t tim;

  pbody->challenge_present = 0;
  pbody->ssid_present = 0;
  pbody->rates_present = 0;
  pbody->ds_present = 0;
  pbody->cf_present = 0;
  pbody->tim_present = 0;

  while (length != 0) {
    if (!TTEST2(*(p + offset), 1))
      return 0;
    if (length < 1)
      return 0;
    switch (*(p + offset)) {
    case E_SSID:
      if (!TTEST2(*(p + offset), 2))
	return 0;
      if (length < 2)
	return 0;
      memcpy(&ssid, p + offset, 2);
      offset += 2;
      length -= 2;
      if (ssid.length != 0) {
	if (ssid.length > sizeof(ssid.ssid) - 1)
	  return 0;
	if (!TTEST2(*(p + offset), ssid.length))
	  return 0;
	if (length < ssid.length)
	  return 0;
	memcpy(&ssid.ssid, p + offset, ssid.length);
	offset += ssid.length;
	length -= ssid.length;
      }
      ssid.ssid[ssid.length] = '\0';
      //
      if (!pbody->ssid_present) {
	pbody->ssid = ssid;
	pbody->ssid_present = 1;
      }
      break;
    case E_CHALLENGE:
      if (!TTEST2(*(p + offset), 2))
	return 0;
      if (length < 2)
	return 0;
      memcpy(&challenge, p + offset, 2);
      offset += 2;
      length -= 2;
      if (challenge.length != 0) {
	if (challenge.length >
	    sizeof(challenge.text) - 1)
	  return 0;
	if (!TTEST2(*(p + offset), challenge.length))
	  return 0;
	if (length < challenge.length)
	  return 0;
	memcpy(&challenge.text, p + offset,
	       challenge.length);
	offset += challenge.length;
	length -= challenge.length;
      }
      challenge.text[challenge.length] = '\0';
      //
      if (!pbody->challenge_present) {
	pbody->challenge = challenge;
	pbody->challenge_present = 1;
      }
      break;
    case E_RATES:
      if (!TTEST2(*(p + offset), 2))
	return 0;
      if (length < 2)
	return 0;
      memcpy(&rates, p + offset, 2);
      offset += 2;
      length -= 2;
      if (rates.length != 0) {
	if (rates.length > sizeof rates.rate)
	  return 0;
	if (!TTEST2(*(p + offset), rates.length))
	  return 0;
	if (length < rates.length)
	  return 0;
	memcpy(&rates.rate, p + offset, rates.length);
	offset += rates.length;
	length -= rates.length;
      }
      if (!pbody->rates_present && rates.length != 0) {
	pbody->rates = rates;
	pbody->rates_present = 1;
      }
      break;
    case E_DS:
      if (!TTEST2(*(p + offset), 3))
	return 0;
      if (length < 3)
	return 0;
      memcpy(&ds, p + offset, 3);
      offset += 3;
      length -= 3;
      if (!pbody->ds_present) {
	pbody->ds = ds;
	pbody->ds_present = 1;
      }
      break;
    case E_CF:
      if (!TTEST2(*(p + offset), 8))
	return 0;
      if (length < 8)
	return 0;
      memcpy(&cf, p + offset, 8);
      offset += 8;
      length -= 8;
      if (!pbody->cf_present) {
	pbody->cf = cf;
	pbody->cf_present = 1;
      }
      break;
    case E_TIM:
      if (!TTEST2(*(p + offset), 2))
	return 0;
      if (length < 2)
	return 0;
      memcpy(&tim, p + offset, 2);
      offset += 2;
      length -= 2;
      if (!TTEST2(*(p + offset), 3))
	return 0;
      if (length < 3)
	return 0;
      memcpy(&tim.count, p + offset, 3);
      offset += 3;
      length -= 3;

      if (tim.length <= 3)
	break;
      if (tim.length - 3 > (int)sizeof tim.bitmap)
	return 0;
      if (!TTEST2(*(p + offset), tim.length - 3))
	return 0;
      if (length < (u_int)(tim.length - 3))
	return 0;
      memcpy(tim.bitmap, p + (tim.length - 3),
	     (tim.length - 3));
      offset += tim.length - 3;
      length -= tim.length - 3;
      if (!pbody->tim_present) {
	pbody->tim = tim;
	pbody->tim_present = 1;
      }
      break;
    default:
      if (!TTEST2(*(p + offset), 2))
	return 0;
      if (length < 2)
	return 0;
      if (!TTEST2(*(p + offset + 2), *(p + offset + 1)))
	return 0;
      if (length < (u_int)(*(p + offset + 1) + 2))
	return 0;
      offset += *(p + offset + 1) + 2;
      length -= *(p + offset + 1) + 2;
      break;
    }
  }

  return 1;
}

void PRINT_HT_RATE(char* _sep,  u_int8_t _r, char* _suf,struct r_packet * paket){
#ifdef MODE_DEBUG
  printf("  %s%.1f%s ", _sep, (.5 * ieee80211_htrates[(_r) & 0xf]), _suf);
#endif  
  paket->rate=(.5 * ieee80211_htrates[(_r) & 0xf]);
  
}

void PRINT_SSID( struct mgmt_body_t p,struct r_packet* paket){ 
  if (p.ssid_present) { 
#ifdef MODE_DEBUG   
    printf(" ( "); 
#endif
    
    fn_print(p.ssid.ssid, NULL,paket); 
#ifdef MODE_DEBUG
    printf(")"); 
#endif
  }
}

void PRINT_RATE(char* _sep,  u_int8_t _r, char* _suf,struct r_packet * paket ) {
#ifdef MODE_DEBUG
  printf("  %s%2.1f%s ", _sep, (.5 * ((_r) & 0x7f)), _suf);
#endif
  paket->rate=(float)((.5 * ((_r) & 0x7f)));
  
}

//call to this function is commented out 
void PRINT_RATES(struct mgmt_body_t p, struct r_packet* paket) {
  if (p.rates_present) {
  int z; 
 const char *sep = " ["; 
  for (z = 0; z < p.rates.length ; z++) { 
    PRINT_RATE(sep, p.rates.rate[z], (p.rates.rate[z] & 0x80 ? "*" : ""),paket); 
  sep = " "; 
  } 
  if (p.rates.length != 0) 
    printf(" Mbit] "); 
  }

}
void PRINT_DS_CHANNEL( struct mgmt_body_t  p, struct r_packet* paket){
  if (p.ds_present) {
#ifdef MODE_DEBUG
    printf(" CH: %u", p.ds.channel);
#endif
    paket->channel= p.ds.channel;
  } 
#ifdef MODE_DEBUG
  printf("%s ", CAPABILITY_PRIVACY(p.capability_info) ? ", PRIVACY" : "" );
#endif
  paket->cap_privacy=  CAPABILITY_PRIVACY(p.capability_info) ? 1 :0 ;
}

int handle_beacon(const u_char *p, u_int length, struct r_packet * paket)
{
  struct mgmt_body_t pbody;
  int offset = 0;
  int ret;
  
  memset(&pbody, 0, sizeof(pbody));
	
  if (!TTEST2(*p, IEEE802_11_TSTAMP_LEN + IEEE802_11_BCNINT_LEN +
	      IEEE802_11_CAPINFO_LEN))
    return 0;
  if (length < IEEE802_11_TSTAMP_LEN + IEEE802_11_BCNINT_LEN +
      IEEE802_11_CAPINFO_LEN)
    return 0;
  memcpy(&pbody.timestamp, p, IEEE802_11_TSTAMP_LEN);
  offset += IEEE802_11_TSTAMP_LEN;
  length -= IEEE802_11_TSTAMP_LEN;
  pbody.beacon_interval = EXTRACT_LE_16BITS(p+offset);
  offset += IEEE802_11_BCNINT_LEN;
  length -= IEEE802_11_BCNINT_LEN;
  pbody.capability_info = EXTRACT_LE_16BITS(p+offset);
  offset += IEEE802_11_CAPINFO_LEN;
  length -= IEEE802_11_CAPINFO_LEN;
  
  ret = parse_elements(&pbody, p, offset, length);
  
  PRINT_SSID(pbody,paket);
  PRINT_DS_CHANNEL(pbody,paket);
  
#ifdef MODE_DEBUG
  PRINT_RATES(pbody,paket);
  printf(" %s",	 CAPABILITY_ESS(pbody.capability_info) ? "ESS" : "IBSS");
#endif
  paket->cap_ess_ibss =55;
  paket->cap_ess_ibss=  CAPABILITY_ESS(pbody.capability_info) ? 1:2;
  return ret;
}

int mgmt_body_print(u_int16_t fc, const struct mgmt_header_t *pmh, const u_char *p, u_int length, struct r_packet * paket)
{
  switch (FC_SUBTYPE(fc)) {
  case ST_BEACON:
//    printf("Beacon");
    return handle_beacon(p, length, paket);
  }
  return 0; 
}

u_int ieee802_11_print(const u_char *p, u_int length, u_int orig_caplen, int pad, u_int fcslen, struct r_packet * paket)
{
  u_int16_t fc;
  u_int caplen, hdrlen;
  const u_int8_t *src, *dst;
  
  caplen = orig_caplen;
  /* Remove FCS, if present */
  if (length < fcslen) {
#ifdef MODE_DEBUG
    printf("len<fcslen");
#endif
    return caplen;
        }
  length -= fcslen;
  if (caplen > length) {
    /* Amount of FCS in actual packet data, if any */
    fcslen = caplen - length;
    caplen -= fcslen;
    snapend -= fcslen;
  }
  
  if (caplen < IEEE802_11_FC_LEN) {
#ifdef MODE_DEBUG
    printf("cap<fcslen");
#endif
    return orig_caplen;
  }
  fc = EXTRACT_LE_16BITS(p);
  hdrlen = MGMT_HDRLEN; 
  if (pad)
    hdrlen = roundup2(hdrlen, 4);
      
  if (caplen < hdrlen) {
#ifdef MODE_DEBUG
    printf("caplen<hdrlen");
#endif
    return hdrlen;
  }
  ieee_802_11_hdr_print(fc, p, hdrlen, &src, &dst,paket);
  length -= hdrlen;
  caplen -= hdrlen;
  p += hdrlen;
  
  switch (FC_TYPE(fc)) {
  case T_MGMT:
    if (!mgmt_body_print(fc,
			 (const struct mgmt_header_t *)(p - hdrlen), p, length,paket)) {
#ifdef MODE_DEBUG
      printf("done");
#endif
      return hdrlen;
    }
    break;
  default:
#ifdef MODE_DEBUG
    printf("UH (%d)", FC_TYPE(fc)); //unknown header
#endif
    break;
  }
  
  return hdrlen;
}

int print_radiotap_field(struct cpack_state *s, u_int32_t bit, u_int8_t *flags, struct r_packet* paket)
{
  union {
    int8_t          i8;
    u_int8_t        u8;
    int16_t         i16;
    u_int16_t       u16;
    u_int32_t       u32;
    u_int64_t       u64;
  } u, u2, u3, u4;
  int rc;
  switch (bit) {
  case IEEE80211_RADIOTAP_FLAGS:
    rc = cpack_uint8(s, &u.u8);
    *flags = u.u8;
    break;
  case IEEE80211_RADIOTAP_RATE:
  case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
  case IEEE80211_RADIOTAP_DB_ANTNOISE:
  case IEEE80211_RADIOTAP_ANTENNA:
    rc = cpack_uint8(s, &u.u8);
    break;
  case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
  case IEEE80211_RADIOTAP_DBM_ANTNOISE:
    rc = cpack_int8(s, &u.i8);
    break;
  case IEEE80211_RADIOTAP_CHANNEL:
    rc = cpack_uint16(s, &u.u16);
    if (rc != 0)
      break;
    rc = cpack_uint16(s, &u2.u16);
    break;
  case IEEE80211_RADIOTAP_FHSS:
  case IEEE80211_RADIOTAP_LOCK_QUALITY:
  case IEEE80211_RADIOTAP_TX_ATTENUATION:
    rc = cpack_uint16(s, &u.u16);
    break;
  case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
    rc = cpack_uint8(s, &u.u8);
    break;
  case IEEE80211_RADIOTAP_DBM_TX_POWER:
    rc = cpack_int8(s, &u.i8);
    break;
  case IEEE80211_RADIOTAP_TSFT:
    rc = cpack_uint64(s, &u.u64);
    break;
  case IEEE80211_RADIOTAP_XCHANNEL:
    rc = cpack_uint32(s, &u.u32);
    if (rc != 0)
      break;
    rc = cpack_uint16(s, &u2.u16);
    if (rc != 0)
      break;
    rc = cpack_uint8(s, &u3.u8);
    if (rc != 0)
      break;
    rc = cpack_uint8(s, &u4.u8);
    break;
  default:
    // this bit indicates a field whos size we do not know, so we cannot proceed.  Just print the bit number.     
#ifdef MODE_DEBUG
    printf("[bit %u] ", bit);
#endif
    return -1;
  }
  if (rc != 0) {
#ifdef MODE_DEBUG
    printf("[|802.11]");
#endif
    return rc;
  }

  switch (bit) {
  case IEEE80211_RADIOTAP_CHANNEL:
    print_chaninfo(u.u16, u2.u16,paket);
    break;
  case IEEE80211_RADIOTAP_FHSS:
#ifdef MODE_DEBUG
    printf("fhset %d fhpat %d ", u.u16 & 0xff, (u.u16 >> 8) & 0xff);
#endif
    break;
  case IEEE80211_RADIOTAP_RATE:
    if (u.u8 & 0x80){    
      //paket->rate=u.u8;
      //#ifdef MODE_DEBUG
      PRINT_HT_RATE("", u.u8, "Mb/s ",paket);
      //#endif
    }
    else{    
      PRINT_RATE("", u.u8, "Mb/s ",paket);
      //  printf(" rate is %f main ", paket->rate);
      //printf("rate **%2.1f**\n", paket->rate);
    }    
    break;
  case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
    paket->dbm_sig=u.i8;
#ifdef MODE_DEBUG
    printf("%ddB  signal ", u.i8);
#endif
    break;
  case IEEE80211_RADIOTAP_DBM_ANTNOISE:
    paket->dbm_noise=u.i8;
#ifdef MODE_DEBUG
    printf("%ddB  noise ", u.i8);
#endif
    break;
  case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
    paket->db_sig=u.u8;
#ifdef MODE_DEBUG
    printf("%ddB signal ", u.u8);
#endif
    break;
  case IEEE80211_RADIOTAP_DB_ANTNOISE:
    paket->db_noise=u.u8;
#ifdef MODE_DEBUG
    printf("%ddB noise ", u.u8);
#endif
    break;
  case IEEE80211_RADIOTAP_LOCK_QUALITY:
#ifdef MODE_DEBUG
    printf("%u sq ", u.u16);
#endif
    break;
  case IEEE80211_RADIOTAP_TX_ATTENUATION:
#ifdef MODE_DEBUG
    printf("%d tx power ", -(int)u.u16);
#endif
    break;
  case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
#ifdef MODE_DEBUG
    printf("%ddB tx power ", -(int)u.u8);
#endif
    break;
  case IEEE80211_RADIOTAP_DBM_TX_POWER:
#ifdef MODE_DEBUG
    printf("%ddBm tx power ", u.i8);
#endif
    break;
  case IEEE80211_RADIOTAP_FLAGS:
    if (u.u8 & IEEE80211_RADIOTAP_F_CFP){
      paket->cfp_err=1;
#ifdef MODE_DEBUG
      printf("cfp ");
#endif
    }
    if (u.u8 & IEEE80211_RADIOTAP_F_SHORTPRE){
      paket->short_preamble_err =1;
#ifdef MODE_DEBUG
      printf("short preamble ");
#endif
    }
    if (u.u8 & IEEE80211_RADIOTAP_F_WEP){
      paket->radiotap_wep_err =1;
#ifdef MODE_DEBUG
      printf("wep ");
#endif
  }
    if (u.u8 & IEEE80211_RADIOTAP_F_FRAG){
      paket->frag_err=1;
#ifdef MODE_DEBUG
      printf("fragmented ");
#endif
    }
    if (u.u8 & IEEE80211_RADIOTAP_F_BADFCS){
      paket->bad_fcs_err=1;
#ifdef MODE_DEBUG
      printf("bad-fcs ");
#endif
    }
    break;
  case IEEE80211_RADIOTAP_ANTENNA:
    paket->antenna= u.u8;
#ifdef MODE_DEBUG
    printf("antenna %d ", u.u8);
#endif
    break;
  case IEEE80211_RADIOTAP_TSFT:
#ifdef MODE_DEBUG
    printf(/*% PRIu64 */" tsft "/*, u.u64*/);
#endif
    break;
  case IEEE80211_RADIOTAP_XCHANNEL:
    print_chaninfo(u2.u16, u.u32,paket);
    break;
  }
  return 0;
}

u_int ieee802_11_radio_print(const u_char *p, u_int length, u_int caplen, struct r_packet* paket)
{
#define BITNO_32(x) (((x) >> 16) ? 16 + BITNO_16((x) >> 16) : BITNO_16((x)))
#define BITNO_16(x) (((x) >> 8) ? 8 + BITNO_8((x) >> 8) : BITNO_8((x)))
#define BITNO_8(x) (((x) >> 4) ? 4 + BITNO_4((x) >> 4) : BITNO_4((x)))
#define BITNO_4(x) (((x) >> 2) ? 2 + BITNO_2((x) >> 2) : BITNO_2((x)))
#define BITNO_2(x) (((x) & 2) ? 1 : 0)
#define BIT(n)  (1U << n)
#define IS_EXTENDED(__p)        \
  (EXTRACT_LE_32BITS(__p) & BIT(IEEE80211_RADIOTAP_EXT)) != 0

  struct cpack_state cpacker;
  struct ieee80211_radiotap_header *hdr;
  u_int32_t present, next_present;
  u_int32_t *presentp, *last_presentp;
  enum ieee80211_radiotap_type bit;
  int bit0;
  const u_char *iter;
  u_int len;
  u_int8_t flags;
  int pad;
  u_int fcslen;

  if (caplen < sizeof(*hdr)) {
#ifdef MODE_DEBUG
    printf("caplen<hdr");
#endif
    return caplen;
  }
  hdr = (struct ieee80211_radiotap_header *)p;
  len = EXTRACT_LE_16BITS(&hdr->it_len);
  if (caplen < len) {
#ifdef MODE_DEBUG
    printf("caplen<len");
#endif
    return caplen;
  }
  for (last_presentp = &hdr->it_present;
       IS_EXTENDED(last_presentp) &&
	 (u_char*)(last_presentp + 1) <= p + len;
       last_presentp++);
  if (IS_EXTENDED(last_presentp)) {
#ifdef MODE_DEBUG
    printf("more bitmap ext than bytes");
#endif
    return caplen;
  }
  iter = (u_char*)(last_presentp + 1);

  if (cpack_init(&cpacker, (u_int8_t*)iter, len - (iter - p)) != 0) {
    /* XXX */
#ifdef MODE_DEBUG
    printf("XXX");
#endif
    return caplen;
  }

  flags = 0;
  pad = 0;
  fcslen = 0;
  for (bit0 = 0, presentp = &hdr->it_present; presentp <= last_presentp;
       presentp++, bit0 += 32) {
    for (present = EXTRACT_LE_32BITS(presentp); present;
	 present = next_present) {
      next_present = present & (present - 1);
      bit = (enum ieee80211_radiotap_type)
	(bit0 + BITNO_32(present ^ next_present));

      if (print_radiotap_field(&cpacker, bit, &flags,paket) != 0)
	goto out;
    }
  }

  if (flags & IEEE80211_RADIOTAP_F_DATAPAD)
    pad = 1;
  if (flags & IEEE80211_RADIOTAP_F_FCS)
    fcslen = 4;
 out:
  return len + ieee802_11_print(p + len, length - len, caplen - len, pad,fcslen,paket);
#undef BITNO_32
#undef BITNO_16
#undef BITNO_8
#undef BITNO_4
#undef BITNO_2
#undef BIT
}


void address_table_init(address_table_t* table) {
  memset(table, '\0', sizeof(*table));
}
#define MODULUS(m, d)  ((((m) % (d)) + (d)) % (d))
#define NORM(m)  (MODULUS(m, MAC_TABLE_ENTRIES))

int address_table_lookup(address_table_t*  table,struct r_packet* paket) {
  char m_address[sizeof(paket->mac_address)];

  //   printf("In lookup %s\n", paket->mac_address);
  //   printf("Must be assci **** %s ****\n", paket->essid);

  memcpy(m_address,paket->mac_address,sizeof(paket->mac_address));
  if (table->length > 0) {
    /* Search table starting w/ most recent MAC addresses. */
    int idx;
    for (idx = 0; idx < table->length; ++idx) {
      int mac_id = NORM(table->last - idx);
      if (!memcmp(table->entries[mac_id].mac_add, m_address, sizeof(m_address))) /*||
	(  memcmp(table->entries[mac_id].mac_add, m_address, sizeof(m_address))==0 && table->entries[mac_id].freq=! paket->freq  ) 	     
	)*/ {
	//memcpy(table->entries[mac_id].mac_add, m_address, sizeof(m_address));
	table->entries[mac_id].packet_count++;
	if(paket->bad_fcs_err)
	  table->entries[mac_id].bad_fcs_err_count++;
	if(paket->short_preamble_err)
	  table->entries[mac_id].short_preamble_err_count++;
	if(paket->radiotap_wep_err)
	  table->entries[mac_id].radiotap_wep_err_count++;
	if(paket->frag_err)
	  table->entries[mac_id].frag_err_count++;
	if( paket->cfp_err)
	  table->entries[mac_id].cfp_err_count++ ;
	if(paket->retry)
	  table->entries[mac_id].retry_err_count++; 
	if(paket->strictly_ordered)
	  table->entries[mac_id].strictly_ordered_err=paket->strictly_ordered;
	if(paket->pwr_mgmt)
	  table->entries[mac_id].pwr_mgmt_count++;
	if(paket->wep_enc)
	  table->entries[mac_id].wep_enc_count++;
	if(paket->more_frag)
	  table->entries[mac_id].more_frag_count++;
	table->entries[mac_id].db_signal_sum = table->entries[mac_id].db_signal_sum+ paket->db_sig; 

	table->entries[mac_id].db_noise_sum= table->entries[mac_id].db_noise_sum +paket->db_noise;
	
	table->entries[mac_id].dbm_noise_sum =	table->entries[mac_id].dbm_noise_sum + paket->dbm_noise ;

	table->entries[mac_id].dbm_signal_sum =(float)-(paket->dbm_sig) + table->entries[mac_id].dbm_signal_sum ;
	table->entries[mac_id].rate = table->entries[mac_id].rate +paket->rate ;
	

#if 0
	//printf("sig after %2.1f \n",table->entries[mac_id].dbm_signal_sum) ;
	printf("Before essid  %s,  %s \n",table->entries[mac_id].essid,paket->essid);
	printf("mac address  %s \n",table->entries[mac_id].mac_add);
	printf("pkt count=%d,\n", table->entries[mac_id].packet_count);
	
	memcpy(table->entries[mac_id].essid, paket->essid, sizeof(paket->essid));
	memcpy(table->entries[mac_id].mac_add, m_address, sizeof(m_address));

	printf("After essid of existing  %s,  %s \n",table->entries[mac_id].essid,paket->essid );
#endif
        return mac_id;
      }
    }
  }

  if (table->length == MAC_TABLE_ENTRIES-1) {
    /* Discard the oldest MAC address. */
    table->first = NORM(table->first + 1);
    //table is full, write it to a file
    write_update();
  } else {
    ++table->length;
  }
  if (table->length > 1) {
    table->last = NORM(table->last + 1);
  }

  memcpy(table->entries[table->last].essid, paket->essid, sizeof(paket->essid)); 
  memcpy(table->entries[table->last].mac_add, paket->mac_address, sizeof(m_address));
  table->entries[table->last].packet_count =  table->entries[table->last].packet_count+1;  
  table->entries[table->last].db_signal_sum=paket->db_sig; 
  table->entries[table->last].db_noise_sum=paket->db_noise;
 
  table->entries[table->last].dbm_noise_sum =paket->dbm_noise ;
  table->entries[table->last].dbm_signal_sum =((float)-(paket->dbm_sig));    
  //  printf("Essid first time : %s , %s\n",table->entries[table->last].essid,paket->essid );  
  //counters 
  table->entries[table->last].bad_fcs_err_count=paket->bad_fcs_err;    
  table->entries[table->last].short_preamble_err_count = paket->short_preamble_err;
  table->entries[table->last].radiotap_wep_err_count= paket->radiotap_wep_err;
  table->entries[table->last].frag_err_count =paket->frag_err;
  table->entries[table->last].cfp_err_count = paket->cfp_err ;
  table->entries[table->last].retry_err_count =paket->retry ;  
  table->entries[table->last].strictly_ordered_err=paket->strictly_ordered;
  table->entries[table->last].pwr_mgmt_count =paket->pwr_mgmt;
  table->entries[table->last].wep_enc_count=paket->wep_enc;
  table->entries[table->last].more_frag_count= paket->more_frag;

  table->entries[table->last].cap_privacy =paket->cap_privacy;
  table->entries[table->last].cap_ess_ibss =paket->cap_ess_ibss;
  table->entries[table->last].freq =paket->freq ; 
  table->entries[table->last].channel= paket->channel;
  memcpy(table->entries[table->last].channel_info, paket->channel_info, sizeof(paket->channel_info));
  //printf("packet rate is %f \n",paket->rate );
  table->entries[table->last].rate = paket->rate ;

  if (table->added_since_last_update < MAC_TABLE_ENTRIES) {
    ++table->added_since_last_update;
  }
  return table->last;
}

static int initialize_bismark_id() {  
  FILE* handle = fopen(BISMARK_ID_FILENAME, "r");
  if (!handle) {
    perror("Cannot open Bismark ID file " BISMARK_ID_FILENAME);
    return -1;
  }
  if(fscanf(handle, "%255s\n", bismark_id) < 1) {
    perror("Cannot read Bismark ID file " BISMARK_ID_FILENAME);
    return -1;
  }
  fclose(handle);
  
  return 0;
}

int address_table_write_update(address_table_t* table,gzFile handle) {

  int idx;
  for (idx = table->added_since_last_update; idx > 0; --idx) {
    int mac_id = NORM(table->last - idx + 1);
    
#if 0
    printf("%s|%s|privacy%u|ibss%u|f%u|c%u|%s|r%2.1f",table->entries[mac_id].mac_add,
	   table->entries[mac_id].essid, 
	   table->entries[mac_id].cap_privacy,
	   table->entries[mac_id].cap_ess_ibss, 
	   table->entries[mac_id].freq ,
	   table->entries[mac_id].channel,
	   table->entries[mac_id].channel_info, 
	   table->entries[mac_id].rate/table->entries[mac_id].packet_count);
    
   printf("pc%d|bfs%d|sp%d|wep%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|noise%d|%2.1f|%2.1f\n",
	  table->entries[mac_id].packet_count,
	  table->entries[mac_id].bad_fcs_err_count,
	  table->entries[mac_id].short_preamble_err_count,
	  table->entries[mac_id].radiotap_wep_err_count,
	  table->entries[mac_id].frag_err_count,
	  table->entries[mac_id].cfp_err_count,
	  table->entries[mac_id].retry_err_count,
	  table->entries[mac_id].strictly_ordered_err,
	  table->entries[mac_id].pwr_mgmt_count, 
	  table->entries[mac_id].wep_enc_count,
	  table->entries[mac_id].more_frag_count,
	  table->entries[mac_id].db_signal_sum,
	  table->entries[mac_id].db_noise_sum,	
	  table->entries[mac_id].dbm_noise_sum ,
	  table->entries[mac_id].dbm_signal_sum, (table->entries[mac_id].dbm_signal_sum/table->entries[mac_id].packet_count));

   printf("**%s %f %d %f**\n", table->entries[mac_id].mac_add, table->entries[mac_id].dbm_signal_sum,table->entries[mac_id].packet_count,
 	  table->entries[mac_id].dbm_signal_sum/ table->entries[mac_id].packet_count);
#endif
   if(!gzprintf(handle,"%s|%s|%u|%u|%d|%d|%s|%2.1f",table->entries[mac_id].mac_add,
		table->entries[mac_id].essid, 
		table->entries[mac_id].cap_privacy,
		table->entries[mac_id].cap_ess_ibss, 
		table->entries[mac_id].freq ,
		table->entries[mac_id].channel,
		table->entries[mac_id].channel_info, 
		(table->entries[mac_id].rate/table->entries[mac_id].packet_count))){
     perror("error writing the zip file ");
     exit(0);

   }    
   if(!gzprintf(handle,"|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%2.1f|%2.1f\n",
		table->entries[mac_id].packet_count,
		table->entries[mac_id].bad_fcs_err_count,
		table->entries[mac_id].short_preamble_err_count,
		table->entries[mac_id].radiotap_wep_err_count,
		table->entries[mac_id].frag_err_count,
		table->entries[mac_id].cfp_err_count,
		table->entries[mac_id].retry_err_count,
		table->entries[mac_id].strictly_ordered_err,
		table->entries[mac_id].pwr_mgmt_count, 
		table->entries[mac_id].wep_enc_count,
		table->entries[mac_id].more_frag_count,
		table->entries[mac_id].db_signal_sum,
		table->entries[mac_id].db_noise_sum,
		0,
		(table->entries[mac_id].dbm_noise_sum/table->entries[mac_id].packet_count),	
		(table->entries[mac_id].dbm_signal_sum/table->entries[mac_id].packet_count))){
     perror("error writing the zip file");
     exit(0);
   }

  } 
  return 0; 
}


static unsigned  int prev_rx_packets_1=0;
static  unsigned int prev_tx_bytes_1=0; 
static unsigned int prev_rx_bytes_1 =0; 
static  unsigned int prev_tx_retries_1=0;  
static unsigned  int prev_tx_packets_1 =0; 
static unsigned  int prev_tx_failed_1=0;
static int check=0;

int agg_data(gzFile handle_counts){

  static char buff[1024]; /*minimize stack size*/
  static unsigned int prev_crc_err = 0;
  static unsigned int prev_phy_err = 0;
  static unsigned int prev_rx_pkts_all = 0;
  static unsigned int prev_rx_bytes_all = 0;
  FILE *fproc = NULL;

  int phy_err_delta=0;
  int crc_err_delta=0;
  int rx_pkts_all_delta=0;
  int rx_bytes_all_delta=0;

  unsigned int phy_err=0;
  unsigned int crc_err=0;
  unsigned int rx_pkts_all=0;
  unsigned int rx_bytes_all=0;
  int a =~(1<<31);


  if((fproc = fopen("/sys/kernel/debug/ieee80211/phy0/ath9k/recv", "r")) == NULL ){
    perror("Can't read from debugs phy0");
    exit(1);
  }
  while ((fgets(buff, sizeof(buff), fproc)) != NULL) {
    if (strncmp(buff,"           CRC ERR :",18) == 0) {
      sscanf(buff,"           CRC ERR :%u ", &crc_err);     
    }

    if (strncmp(buff,"           PHY ERR :",18) == 0) {
      sscanf(buff,"           PHY ERR :%u ", &phy_err);  
    }

    if (strncmp(buff,"       RX-Pkts-All :", 18) == 0) {
      sscanf(buff,"       RX-Pkts-All :%u ", &rx_pkts_all);
    }
    if (strncmp(buff,"      RX-Bytes-All :", 18) == 0) {
      sscanf(buff,"      RX-Bytes-All :%u ", &rx_bytes_all);
    }
  }
  fclose(fproc);
  fproc=NULL;

  crc_err_delta= crc_err - prev_crc_err;
  if(crc_err_delta<0){  
    crc_err_delta= ( a - prev_crc_err)+crc_err;
  }
  phy_err_delta= phy_err - prev_phy_err ;
  if(phy_err_delta<0){
    phy_err_delta= ( a - prev_phy_err) + (phy_err);
  }


  rx_pkts_all_delta=  rx_pkts_all - prev_rx_pkts_all ;
  if(rx_pkts_all_delta<0){
    rx_pkts_all_delta= ( a - prev_rx_pkts_all) +rx_pkts_all;
  }

  rx_bytes_all_delta=   rx_bytes_all - prev_rx_bytes_all ;
  if(rx_bytes_all_delta<0){
    rx_bytes_all_delta= ( a - prev_rx_bytes_all) +rx_bytes_all;
  }

  prev_crc_err =crc_err;
  prev_phy_err =    phy_err ;
  prev_rx_pkts_all =  rx_pkts_all ;
  prev_rx_bytes_all =rx_bytes_all ;


#if 0
  printf("crc_err is %u\n",crc_err);
  printf("phy_err is %u\n",phy_err);
  printf("rx_bytes_all is %u\n",rx_bytes_all);
  printf("rx_pkts_all is %u\n",rx_pkts_all);

  printf("prev, crc_err_delta is %u %u\n",prev_crc_err, crc_err_delta);
  printf("prev, phy_err_delta is %u %u\n",prev_phy_err, phy_err_delta);
  printf("prev, rx_bytes_all_delta is %u %u\n",prev_rx_bytes_all,rx_bytes_all_delta);
  printf("prev, rx_pkts_all_delta is %u %u\n",prev_rx_pkts_all,rx_pkts_all_delta);
#endif

  if(check==0){
    if(!gzprintf(handle_counts,"%u|%u|%u|%u\n",prev_crc_err, prev_phy_err,prev_rx_bytes_all,prev_rx_pkts_all))
    {
      perror("error writing the zip file :from debugfs 0 ");
      exit(1);
    }
    check++;
  }

  if(!gzprintf(handle_counts,"%d|%d|%d|%d\n",crc_err_delta, phy_err_delta,rx_bytes_all_delta,rx_pkts_all_delta))
    {
      perror("error writing the zip file :from debugfs 0 ");
      exit(1);
    }


  //-----------------------------------------------------
  if((fproc = fopen("/sys/kernel/debug/ieee80211/phy1/ath9k/recv", "r")) == NULL ){
    perror("Can't read from debugfs phy1");
    exit(1);
  }
  while ((fgets(buff, sizeof(buff), fproc)) != NULL) {
    if (strncmp(buff,"           CRC ERR :",18) == 0) {
      sscanf(buff,"           CRC ERR :%u ", &crc_err);
    }


    if (strncmp(buff,"           PHY ERR :",18) == 0) {
      sscanf(buff,"           PHY ERR :%u ", &phy_err);
    }

    if (strncmp(buff,"       RX-Pkts-All :", 18) == 0) {
      sscanf(buff,"       RX-Pkts-All :%u ", &rx_pkts_all);
    }
    if (strncmp(buff,"      RX-Bytes-All :", 18) == 0) {
      sscanf(buff,"      RX-Bytes-All :%u ", &rx_bytes_all);
    }
  }
  fclose(fproc);

  static unsigned int prev_crc_err_1 = 0;
  static unsigned int prev_phy_err_1 = 0;
  static unsigned int prev_rx_pkts_all_1 = 0;
  static unsigned int prev_rx_bytes_all_1 = 0;
  
  phy_err_delta= phy_err - prev_phy_err_1 ;
  if(phy_err_delta<0){
    phy_err_delta= ( a - prev_phy_err_1) + (phy_err);
  }

  crc_err_delta= crc_err - prev_crc_err_1;
  if(crc_err_delta<0){
    crc_err_delta= ( a - prev_crc_err_1)+crc_err;
  }

  rx_pkts_all_delta=  rx_pkts_all - prev_rx_pkts_all_1 ;
  if(rx_pkts_all_delta<0){
    rx_pkts_all_delta= ( a - prev_rx_pkts_all_1) +rx_pkts_all;
  }

  rx_bytes_all_delta=   rx_bytes_all - prev_rx_bytes_all_1 ;
  if(rx_bytes_all_delta<0){
    rx_bytes_all_delta= ( a - prev_rx_bytes_all_1) +rx_bytes_all;
  }

  prev_crc_err_1 =crc_err ;
  prev_phy_err_1 =    phy_err ;
  prev_rx_pkts_all_1 =  rx_pkts_all ;
  prev_rx_bytes_all_1 =rx_bytes_all ;

#if 0
  printf("crc_err is %u\n",crc_err);
  printf("phy_err is %u\n",phy_err);
  printf("rx_bytes_all is %u\n",rx_bytes_all);
  printf("rx_pkts_all is %u\n",rx_pkts_all);

  printf("prev, crc_err_delta is %u %u\n",prev_crc_err_1, crc_err_delta);
  printf("prev, phy_err_delta is %u %u\n",prev_phy_err_1, phy_err_delta);
  printf("prev, rx_bytes_all_delta is %u %u\n",prev_rx_bytes_all_1,rx_bytes_all_delta);
  printf("prev, rx_pkts_all_delta is %u %u\n",prev_rx_pkts_all_1,rx_pkts_all_delta);
#endif

  if(check==1){
  if(!gzprintf(handle_counts,"%u|%u|%u|%u\n",prev_crc_err_1, prev_phy_err_1,prev_rx_bytes_all_1,prev_rx_pkts_all_1))
    {
      perror("error writing the zip file :from debugfs 1 ");
      exit(1);
    }
  check++;
  }
  if(!gzprintf(handle_counts,"%d|%d|%d|%d\n",crc_err_delta, phy_err_delta,rx_bytes_all_delta,rx_pkts_all_delta))
    {
      perror("error writing the zip file :from debugfs 1 ");
      exit(1);
    }


  //============================= Done with copying from /sys ========================

   char path[1035];
  /* Open the command for reading. */
   FILE *fp=NULL;
  fp = popen("iw wlan0 station dump", "r");
  if (fp == NULL) {
    perror("Failed to run wlan0 station dump command\n" );
    exit(0);
  }
  int rx_bytes=0;  int rx_packets=0;
  int tx_bytes=0;  int tx_packets=0;
  int tx_retries =0;  int tx_failed=0;
  //  int rx_bitrate=0;  int tx_bitrate=0;

  static unsigned  int prev_rx_packets=0;static  unsigned int prev_tx_bytes=0; 
  static unsigned int prev_rx_bytes =0; static  unsigned int prev_tx_retries=0;  
  static unsigned  int prev_tx_packets =0;  static unsigned  int prev_tx_failed=0;

  int delta_rx_packets=0;     int delta_tx_bytes=0;
  int delta_rx_bytes =0;      int delta_tx_retries=0;
  int delta_tx_packets =0;       int delta_tx_failed=0;

  int tx_rate_i =0; int tx_rate_d=0;
  int rx_rate_i =0; int rx_rate_d=0; int signal_avg=0;

 
  while (fgets(path, sizeof(path)-1, fp) != NULL) {
    if (strncmp(path, "\trx bytes:",7) == 0) {
      sscanf (path, "\trx bytes:%u ",&rx_bytes );
    }
    if (strncmp(path, "\trx packets:", 8) == 0) {
      sscanf (path,  "\trx packets:%u ",&rx_packets );
    }

    if (strncmp(path, "\ttx bytes:",7) == 0) {
      sscanf (path, "\ttx bytes:%u ",&tx_bytes );
    }

    if (strncmp(path, "\ttx packets:", 8) == 0) {
      sscanf (path,  "\ttx packets:%u ",&tx_packets );
    }
    if (strncmp(path, "\ttx retries:", 8) == 0) {
      sscanf (path,  "\ttx retries:%u ",&tx_retries);
    }
    if (strncmp(path, "\ttx failed:", 8) == 0) {
      sscanf (path,  "\ttx failed:%u ",&tx_failed );
    }
    if (strncmp(path, "\ttx bitrate:", 8) == 0) {
      sscanf (path,  "\ttx bitrate:\t%d.%d ",&tx_rate_i,&tx_rate_d);
    }
    if (strncmp(path, "\trx bitrate:", 8) == 0) {
      sscanf (path,  "\trx bitrate:\t%d.%d ",&rx_rate_i,&rx_rate_d);  
    }
    if (strncmp(path, "\tsignal avg:", 11) == 0) {
      sscanf (path,  "\tsignal avg:\t%d ",&signal_avg);  
    }
  }
  pclose(fp);
  fp=NULL;

  delta_rx_packets= rx_packets-prev_rx_packets;
  delta_tx_bytes=tx_bytes- prev_tx_bytes;
  delta_rx_bytes = rx_bytes-prev_rx_bytes ;
  delta_tx_retries=tx_retries-prev_tx_retries;
  delta_tx_packets =  tx_packets-prev_tx_packets;       
  delta_tx_failed=tx_failed- prev_tx_failed;

  if(delta_rx_packets< 0 ) {
    delta_rx_packets=  a- prev_rx_packets + rx_packets; 
  }
  if(delta_tx_bytes < 0 ){
    delta_tx_bytes=  a- prev_tx_bytes+tx_bytes;
  }
  if(  delta_rx_bytes < 0 )  {
    delta_rx_bytes =  a- prev_rx_bytes +rx_bytes; 
  }
  if(   delta_tx_retries < 0 ){
    delta_tx_retries=  a- prev_tx_retries+tx_retries;
  }
  if(delta_tx_packets < 0 )  {
    delta_tx_packets =   a- prev_tx_packets +tx_packets;
  }
  if( delta_tx_failed< 0 ){
    delta_tx_failed=  a- prev_tx_failed+tx_failed;;
  }
  prev_rx_packets=rx_packets;    prev_tx_bytes=tx_bytes;
  prev_rx_bytes =rx_bytes;     prev_tx_retries=tx_retries;
  prev_tx_packets =tx_packets;      prev_tx_failed=tx_failed;
  
  if(check==2){
  if(!gzprintf(handle_counts,"%u|%u|%u|%u|%u|%u\n",prev_rx_packets,prev_rx_bytes ,
	       prev_tx_packets,prev_tx_bytes, prev_tx_retries,prev_tx_failed))
    {
      syslog(LOG_ERR,"error writing the zip file :from wlan0");
      //      perror("error writing the zip file :from wlan0");
      //though the command is having null output, One has to continue to read others, hence no returns/ exits
    }
     check++;
  }
  

  //  printf("going to print iw details \n");
  if(!gzprintf(handle_counts,"%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d\n",delta_rx_packets,delta_rx_bytes ,
	       delta_tx_packets,delta_tx_bytes, delta_tx_retries,delta_tx_failed,
	       tx_rate_i,tx_rate_d,rx_rate_i,rx_rate_d,-signal_avg));
    {
      syslog(LOG_ERR,"error writing the zip file :from wlan0");
      //      perror("error writing the zip file :from wlan0");
      //though the command is having null output, One has to continue to read others, hence no returns/ exits
    }
#if 0    
  printf("WLAN0 stats \n");
  printf("rx packets =%d, bytes=%d\n", rx_packets,rx_bytes);
  printf("tx packets =%d, bytes=%d\n", tx_packets,tx_bytes);
  printf("tx retries =%d, failed=%d\n", tx_retries,tx_failed);
  printf("delta : rx_packet=%d,rx_byte=%d tx_packet=%d,tx_bytes=%d,tx_retries=%d,tx_failed=%d\n",delta_rx_packets,delta_rx_bytes , delta_tx_packets,delta_tx_bytes, delta_tx_retries,delta_tx_failed) ;
#endif



  //  printf("tx bitrate =%d, rx bitrate=%d\n", tx_bitrate,rx_bitrate);
  //------------------------------------------------------

  fp = popen("iw wlan1 station dump", "r");
  if (fp == NULL) {
    perror("Failed on wlan1 command\n" );
    exit(1);
  }
 
  int delta_rx_packets_1=0;     int delta_tx_bytes_1=0;
  int delta_rx_bytes_1 =0;      int delta_tx_retries_1=0;
  int delta_tx_packets_1 =0;       int delta_tx_failed_1=0;

  while (fgets(path, sizeof(path)-1, fp) != NULL) {
    if (strncmp(path, "\trx bytes:",7) == 0) {
      sscanf (path, "\trx bytes:%u ",&rx_bytes );
    }
    if (strncmp(path, "\trx packets:", 8) == 0) {
      sscanf (path,  "\trx packets:%u ",&rx_packets );
    }

    if (strncmp(path, "\ttx bytes:",7) == 0) {
      sscanf (path, "\ttx bytes:%u ",&tx_bytes );
    }

    if (strncmp(path, "\ttx packets:", 8) == 0) {
      sscanf (path,  "\ttx packets:%u ",&tx_packets );
    }
    if (strncmp(path, "\ttx retries:", 8) == 0) {
      sscanf (path,  "\ttx retries:%u ",&tx_retries);
    }
    if (strncmp(path, "\ttx failed:", 8) == 0) {
      sscanf (path,  "\ttx failed:%u ",&tx_failed );
    }
    if (strncmp(path, "\ttx bitrate:", 8) == 0) {
      sscanf (path,  "\ttx bitrate:\t%d.%d ",&tx_rate_i,&tx_rate_d);
    }
    if (strncmp(path, "\trx bitrate:", 8) == 0) {
      sscanf (path,  "\trx bitrate:\t%d.%d ",&rx_rate_i,&rx_rate_d);  
    }
    if (strncmp(path, "\tsignal avg:", 11) == 0) {
      sscanf (path,  "\tsignal avg:\t%d ",&signal_avg);  
    }    
  }
  pclose(fp);

  delta_rx_bytes_1 =rx_bytes- prev_rx_bytes_1 ;
  delta_rx_packets_1=  rx_packets- prev_rx_packets_1 ;
  delta_tx_bytes_1= tx_bytes-prev_tx_bytes_1;
  delta_tx_retries_1 = tx_retries-prev_tx_retries_1 ;
  delta_tx_packets_1 =   tx_packets-prev_tx_packets_1;
  delta_tx_failed_1 = prev_tx_failed_1- tx_failed;  
#if 0
  printf("tx_pa %d %d %d\n", prev_tx_packets_1, delta_tx_packets_1, tx_packets);
  printf("tx_re %d %d %d\n", prev_tx_retries_1, delta_tx_retries_1, tx_retries);
#endif  
  
  if(delta_rx_packets_1< 0 ) {
    delta_rx_packets_1=  a- prev_rx_packets_1 + rx_packets; 
  }
  if(delta_tx_bytes_1 < 0 ){
    delta_tx_bytes_1=  a- prev_tx_bytes_1+tx_bytes;
  }
  if(  delta_rx_bytes_1 < 0 )  {
    delta_rx_bytes_1 =  a- prev_rx_bytes_1 +rx_bytes; 
  }
  if(   delta_tx_retries < 0 ){
    delta_tx_retries_1=  a- prev_tx_retries+tx_retries;
  }
  if(delta_tx_packets_1 < 0 )  {
    delta_tx_packets_1 =   a- prev_tx_packets_1 +tx_packets;
  }
  if( delta_tx_failed_1< 0 ){
    delta_tx_failed_1=  a- prev_tx_failed_1 + tx_failed ;
  }
#if 0
  printf("WLAN1 stats \n");
  printf("delta : rx_packet=%2d,rx_byte=%2d tx_packet=%2d,tx_bytes=%2d,tx_retries=%2d,tx_failed=%d",delta_rx_packets_1,delta_rx_bytes_1 , delta_tx_packets_1,delta_tx_bytes_1, delta_tx_retries_1,delta_tx_failed_1) ;
  printf("rx packets =%d, bytes=%d\n", rx_packets,rx_bytes);
  printf("tx packets =%d, bytes=%d\n", tx_packets,tx_bytes);
  printf("tx retries =%d, failed=%d\n", tx_retries,tx_failed);
  printf("prev rx_bytes=%d,rx_packets=%d \n",prev_rx_bytes_1,prev_rx_packets_1);
#endif
  prev_rx_packets_1=rx_packets;    prev_tx_bytes_1=tx_bytes;
  prev_rx_bytes_1 =rx_bytes;     prev_tx_retries_1=tx_retries;
  prev_tx_packets_1 =tx_packets;      prev_tx_failed_1=tx_failed;
  
  if(check==3){
  if(!gzprintf(handle_counts,"%u|%u|%u|%u|%u|%u\n",prev_rx_packets_1,prev_rx_bytes_1 , 
	       prev_tx_packets_1,prev_tx_bytes_1, prev_tx_retries_1,prev_tx_failed_1)){
    syslog(LOG_ERR,"error writing the zip file :from wlan1");
      //the command need not give output, hence nothing to be written, but still cannot return/exit
  }
  check++;
  }

  if(!gzprintf(handle_counts,"%d|%d|%d|%d|%d|%d|%d|%d|%d|%d|%d\n",delta_rx_packets_1,delta_rx_bytes_1 , 
	       delta_tx_packets_1,delta_tx_bytes_1, delta_tx_retries_1,delta_tx_failed_1,
	       tx_rate_i,tx_rate_d,rx_rate_i,rx_rate_d,-signal_avg)) {
    syslog(LOG_ERR,"error writing the zip file :from wlan1");
      //the command need not give output, hence nothing to be written, but still cannot return/exit
    }
  if(!gzprintf(handle_counts,"%s\n","-" )) {
    syslog(LOG_ERR,"error writing the zip file :end of set");
      //the command need not give output, hence nothing to be written, but still cannot return/exit
    }
  
  return 0; 
}

void write_update(){
#ifdef MODE_DEBUG
printf("*********************wrote update **************************\n");
#endif
gzFile handle = gzopen (PENDING_UPDATE_FILENAME, "wb");
 if (!handle) {
   perror("Could not open update file for writing\n");
   exit(1);
 }
 time_t current_timestamp = time(NULL);
 if (!gzprintf(handle,"%s %" PRId64 " %d %" PRId64 "\n",bismark_id,start_timestamp_microseconds,sequence_number,(int64_t)current_timestamp)) {
   perror("Error writing update\n");
   exit(1);
 }

 address_table_write_update(&address_table,handle);
 gzclose(handle);

 char update_filename[FILENAME_MAX];
 snprintf(update_filename,FILENAME_MAX,UPDATE_FILENAME,bismark_id,start_timestamp_microseconds,sequence_number);
 if (rename(PENDING_UPDATE_FILENAME, update_filename)) {
   perror("Could not stage update\n");
   exit(1);
 }


 //fix this filename
 gzFile handle_counts = gzopen (PENDING_UPDATE_FILENAME_COUNTS, "wb");
 if (!handle_counts) {
   perror("Could not open update file for writing aggregate data \n");
   exit(1);
 }
 current_timestamp = time(NULL);
 if (!gzprintf(handle_counts,"%s %" PRId64 " %d %" PRId64 "\n",bismark_id,start_timestamp_microseconds,sequence_number,(int64_t)current_timestamp)) {
   perror("Error writing update for aggregate data\n");
   exit(1);
 }

 agg_data(handle_counts);
 gzclose(handle_counts);

 char update_filename_for_counts[FILENAME_MAX];
 snprintf(update_filename_for_counts,FILENAME_MAX,UPDATE_FILENAME_COUNTS,bismark_id,start_timestamp_microseconds,sequence_number);
 if (rename(PENDING_UPDATE_FILENAME_COUNTS, update_filename_for_counts)) {
   perror("Could not stage update for counts");
   exit(1);
 }

 ++sequence_number;
 address_table_init(&address_table);

}

static void set_next_alarm() {
  alarm(UPDATE_PERIOD_SECS);
}

static void handle_signals(int sig) {
  if (sig == SIGINT || sig == SIGTERM) {
    write_update();
    exit(0);
  } else if (sig == SIGALRM) {
    write_update();
    set_next_alarm();
  }
}

static void initialize_signal_handler() {
  struct sigaction action;
  action.sa_handler = handle_signals;
  sigemptyset(&action.sa_mask);
  action.sa_flags = SA_RESTART;
  if (sigaction(SIGINT, &action, NULL) < 0
      || sigaction(SIGTERM, &action, NULL) < 0
      || sigaction(SIGALRM, &action, NULL)) {
    perror("sigaction");
    exit(1);
  }
  sigemptyset(&block_set);
  sigaddset(&block_set, SIGINT);
  sigaddset(&block_set, SIGTERM);
  sigaddset(&block_set, SIGALRM);
}

void process_packet (u_char * args, const struct pcap_pkthdr *header, const u_char * packet)
{
  if (sigprocmask(SIG_BLOCK, &block_set, NULL) < 0) {
    perror("sigprocmask");
    exit(1);
  }

  snapend = packet+ header->caplen; 
  struct r_packet paket ;
 
   memset(&paket,'\0',sizeof(paket));
   ieee802_11_radio_print(packet, header->len, header->caplen,&paket);
   address_table_lookup(&address_table,&paket);

#ifdef MODE_DEBUG
  printf("\n------------------------------------\n");
#endif

  if (sigprocmask(SIG_UNBLOCK, &block_set, NULL) < 0) {
    perror("sigprocmask");
    exit(1);
  }
}


int main(int argc, char* argv[])
{
  if (argc<2){
    printf("Usage: sniffer  <time interval(seconds)> \n");
    exit(1); 
  }

  initialize_bismark_id();

  if( atoi(argv[1])){
  UPDATE_PERIOD_SECS= atoi(argv[1]);
  printf("new value of secs is =%d\n",   UPDATE_PERIOD_SECS);
  }
  else {
    printf("using the 60 secs %d\n",   UPDATE_PERIOD_SECS);
  }
  printf("update period=%d%\n",UPDATE_PERIOD_SECS );

  struct timeval start_timeval; 
  gettimeofday(&start_timeval, NULL);
  start_timestamp_microseconds  = start_timeval.tv_sec * NUM_MICROS_PER_SECOND + start_timeval.tv_usec;

  initialize_signal_handler();
  set_next_alarm();
  char *filter = "type mgt subtype beacon"; //the awesome one liner
  int               t;
  fd_set            fd_wait;
  struct timeval    st;
  struct pcap      *pcap0=NULL;
  struct pcap      *pcap1=NULL;
  char              errbuf[PCAP_ERRBUF_SIZE];
  char              errbuf1[PCAP_ERRBUF_SIZE];
  bpf_u_int32 netp;   
  bpf_u_int32 maskp;  
  struct bpf_program fp; 
  char  *device0="phy0";
  char  *device1="phy1";

  checkup(device0);
  checkup(device1);
  //declaring the two handles 
  pcap0 = pcap_open_live(device0, BUFSIZ, 1, -1, errbuf);
  pcap1 = pcap_open_live(device1, BUFSIZ, 1, -1, errbuf1);

  //setting the filter on phy0
 if (pcap_compile (pcap0, &fp, filter, 0, maskp) == -1){
      fprintf (stderr, "Compile: %s\n", pcap_geterr (pcap0)); exit (1);
  }
  
  if (pcap_setfilter (pcap0, &fp) == -1){
    fprintf (stderr, "Setfilter: %s", pcap_geterr (pcap0)); exit (1);
  }

  //setting the filter on phy1
 if (pcap_compile (pcap1, &fp, filter, 0, maskp) == -1){
      fprintf (stderr, "Compile: %s\n", pcap_geterr (pcap1)); exit (1);
  }
  
  if (pcap_setfilter (pcap1, &fp) == -1){
    fprintf (stderr, "Setfilter: %s", pcap_geterr (pcap1)); exit (1);
  }
  pcap_freecode (&fp); 
  //set them non blocking
  if(pcap_setnonblock(pcap0, 1, errbuf) == 1)
    {
      printf("Could not set device \"%s\" to non-blocking: %s\n", device0,errbuf);
      exit(1);
    }  
  
  if(pcap_setnonblock(pcap1, 1, errbuf) == 1){
      printf("Could not set device \"%s\" to non-blocking: %s\n", device1,errbuf1);
      exit(1);
    }

  address_table_init(&address_table);  

  for(/*ever*/;;)
    {
      FD_ZERO(&fd_wait);
      FD_SET(pcap_fileno(pcap0), &fd_wait);
      FD_SET(pcap_fileno(pcap1), &fd_wait);
      
      st.tv_sec  = 0;
      st.tv_usec = 500; 
      t=select(FD_SETSIZE, &fd_wait, NULL, NULL, &st);
      switch(t)
	{
	case EINTR:// printf("#%d\n", EINTR);
	  continue;  
	case -1://  printf("#%d\n", EINTR);
	  continue;
	case  0:  
	  //perror(".");
	  break;
	default:
	  if( FD_ISSET(pcap_fileno(pcap0), &fd_wait)) {
	    // printf("for phy0\n");
	    pcap_dispatch(pcap0,-1, (void *) process_packet, NULL);
	  }
	  if( FD_ISSET(pcap_fileno(pcap1), &fd_wait)) {
	    pcap_dispatch(pcap1,-1, (void *) process_packet, NULL);
	  }
	}
      // comes here when select times out or when a packet is processed
    }
    pcap_close (pcap0);
    pcap_close (pcap1);
  return 0 ;
}
