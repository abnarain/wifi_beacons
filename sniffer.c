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
#include "util.h"
#include "ieee80211_radiotap.h"
#include "ieee80211.h"
#include "tcpdump.h"
#include "create-interface.h"

#define MODE_DEBUG 0

typedef struct r_packet{
  int freq ;
  int signal;
  int noise; 
  int channel;
  int rate; 
  char mac_address[11];
  char * essid ; 
  int fcs_err;
  int short_pr_err;
  int wep; 
  int fragmented;
  int cfp ;
  int strictly_ordered;
  int pw_mgmt; 
}r_packet ;



static inline struct enamemem *
lookup_emem(const u_char *ep)
{
  register u_int i, j, k;
  struct enamemem *tp;
  k = (ep[0] << 8) | ep[1];
  j = (ep[2] << 8) | ep[3];
  i = (ep[4] << 8) | ep[5];

  tp = &enametable[(i ^ j) & (HASHNAMESIZE-1)];
  while (tp->e_nxt)
    if (tp->e_addr0 == i &&
                    tp->e_addr1 == j &&
	tp->e_addr2 == k)
      return tp;
    else
      tp = tp->e_nxt;
  tp->e_addr0 = i;
  tp->e_addr1 = j;
  tp->e_addr2 = k;
  tp->e_nxt = (struct enamemem *)calloc(1, sizeof(*tp));
  if (tp->e_nxt == NULL){
#ifdef MODE_DEBUG
    printf("lookup_emem: calloc");
#endif
  }
  return tp;
}

/* Convert a token value to a string; use "fmt" if not found.  */
const char *
tok2strbuf(register const struct tok *lp, register const char *fmt,
           register int v, char *buf, size_t bufsize)
{
  if (lp != NULL) {
    while (lp->s != NULL) {
      if (lp->v == v)
	return (lp->s);
      ++lp;
    }
  }
  if (fmt == NULL)
    fmt = "#%d";

  (void)snprintf(buf, bufsize, fmt, v);
  return (const char *)buf;
}

/*Convert a token value to a string; use "fmt" if not found.  */
const char * tok2str(register const struct tok *lp, register const char *fmt,
        register int v)
{
  static char buf[4][128];
  static int idx = 0;
  char *ret;

  ret = buf[idx];
  idx = (idx+1) & 3;
  return tok2strbuf(lp, fmt, v, ret, sizeof(buf[0]));
}
static const char hex[] = "0123456789abcdef";


const char * etheraddr_string(register const u_char *ep)
{
  int nflag;
  nflag=1; 
  register int i;
  register char *cp;
  register struct enamemem *tp;
  int oui;
  char buf[BUFSIZE];

  tp = lookup_emem(ep);
  if (tp->e_name)
    return (tp->e_name);
#ifdef USE_ETHER_NTOHOST
  if (!nflag) {
    char buf2[BUFSIZE];
    if (ether_ntohost(buf2, (struct ether_addr *)ep) == 0) {
      tp->e_name = strdup(buf2);
      return (tp->e_name);
    }
  }
#endif
  cp = buf;
  oui = EXTRACT_24BITS(ep);
  *cp++ = hex[*ep >> 4 ];
  *cp++ = hex[*ep++ & 0xf];
  for (i = 5; --i >= 0;) {
    *cp++ = ':';
    *cp++ = hex[*ep >> 4 ];
    *cp++ = hex[*ep++ & 0xf];
  }

  if (!nflag) {
    snprintf(cp, BUFSIZE - (2 + 5*3), " (oui %s)",
	     tok2str(oui_values, "Unknown", oui));
  } else
    *cp = '\0';
  tp->e_name = strdup(buf);
  return (tp->e_name);
}

void mgmt_header_print(const u_char *p, const u_int8_t **srcp,  const u_int8_t **dstp)
{
  const struct mgmt_header_t *hp = (const struct mgmt_header_t *) p;

  if (srcp != NULL)
    *srcp = hp->sa;
  if (dstp != NULL)
    *dstp = hp->da;
 

#ifdef MODE_DEBUG
  printf("BSSID:%s DA:%s SA:%s ",
	 etheraddr_string((hp)->bssid), etheraddr_string((hp)->da),
	 etheraddr_string((hp)->sa));
#endif

}

void print_chaninfo(int freq, int flags)
{
#ifdef MODE_DEBUG
  printf("%u MHz", freq);
#endif

  if (IS_CHAN_FHSS(flags)){
#ifdef MODE_DEBUG
    printf(" FHSS");
#endif
  }
  if (IS_CHAN_A(flags)) {
    if (flags & IEEE80211_CHAN_HALF){
#ifdef MODE_DEBUG
      printf(" 11a/10Mhz");
#endif
    }
    else if (flags & IEEE80211_CHAN_QUARTER){
#ifdef MODE_DEBUG
      printf(" 11a/5Mhz");
#endif
    }
    else{
#ifdef MODE_DEBUG
      printf(" 11a");
#endif
    }

  }
  if (IS_CHAN_ANYG(flags)){
    if (flags & IEEE80211_CHAN_HALF){
#ifdef MODE_DEBUG
      printf(" 11g/10Mhz");
#endif
    }
    else if (flags & IEEE80211_CHAN_QUARTER){
#ifdef MODE_DEBUG
      printf(" 11g/5Mhz");
#endif
    }
    else{
#ifdef MODE_DEBUG
      printf(" 11g");
#endif
    }
  } else if (IS_CHAN_B(flags)){
#ifdef MODE_DEBUG
    printf(" 11b");
#endif
  }
  if (flags & IEEE80211_CHAN_TURBO){
#ifdef MODE_DEBUG
    printf(" Turbo");
#endif
  }
  if (flags & IEEE80211_CHAN_HT20){
#ifdef MODE_DEBUG
    printf(" ht/20");
#endif
  }
  else if (flags & IEEE80211_CHAN_HT40D){
#ifdef MODE_DEBUG
    printf(" ht/40-");
#endif
  }
  else if (flags & IEEE80211_CHAN_HT40U){
#ifdef MODE_DEBUG
    printf(" ht/40+");
#endif
  }
  
}

void ieee_802_11_hdr_print(u_int16_t fc, const u_char *p, u_int hdrlen,
    u_int meshdrlen, const u_int8_t **srcp, const u_int8_t **dstp)
{
  int vflag;
  vflag=1;
  if (vflag) {
    if (FC_MORE_DATA(fc))
      if (FC_MORE_FLAG(fc)){
#ifdef MODE_DEBUG
	printf("More Fragments ");
#endif
	}
    if (FC_POWER_MGMT(fc)){
#ifdef MODE_DEBUG
      printf("Pwr Mgmt ");
#endif
}
    if (FC_RETRY(fc)){
#ifdef MODE_DEBUG
      printf("Retry ");
#endif
}
    if (FC_ORDER(fc)){
#ifdef MODE_DEBUG
      printf("Strictly Ordered ");
#endif
}
    if (FC_WEP(fc)){
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
    mgmt_header_print(p, srcp, dstp);
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
fn_print(register const u_char *s, register const u_char *ep)
{
  register int ret;
  register u_char c;
  
  ret = 1;                        /* assume truncated */
  while (ep == NULL || s < ep) {
    c = *s++;
    if (c == '\0') {
      ret = 0;
      break;
    }
    if (!isascii(c)) {
      c = toascii(c);
#ifdef MODE_DEBUG
      putchar('M');
      putchar('-');
#endif
    }
    if (!isprint(c)) {
#ifdef MODE_DEBUG
      c ^= 0x40;      /* DEL to ?, others to alpha */
      putchar('^');
#endif
    }
#ifdef MODE_DEBUG
    putchar(c);
#endif
  }
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


void PRINT_HT_RATE(char* _sep,  u_int8_t _r, char* _suf){
  printf("  %s%.1f%s ", _sep, (.5 * ieee80211_htrates[(_r) & 0xf]), _suf);
}

void PRINT_SSID( struct mgmt_body_t p){ 
  if (p.ssid_present) { 
    printf(" ( "); 
    fn_print(p.ssid.ssid, NULL); 
    printf(")"); 
  }
}
void PRINT_RATE(char* _sep,  u_int8_t _r, char* _suf) {
printf(" SRATE %s%2.1f%s ERATE ", _sep, (.5 * ((_r) & 0x7f)), _suf);
}
void PRINT_RATES(struct mgmt_body_t p) {
  if (p.rates_present) {
  int z; 
  const char *sep = " ["; 
  for (z = 0; z < p.rates.length ; z++) { 
  PRINT_RATE(sep, p.rates.rate[z], (p.rates.rate[z] & 0x80 ? "*" : "")); 
  sep = " "; 
  } 
  if (p.rates.length != 0) 
    printf(" Mbit] "); 
  }

}
void PRINT_DS_CHANNEL( struct mgmt_body_t  p){
  if (p.ds_present) {
    printf(" CH: %u", p.ds.channel);
  } 
  printf("%s $$ ", CAPABILITY_PRIVACY(p.capability_info) ? ", PRIVACY" : "" );

}

int handle_beacon(const u_char *p, u_int length)
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
  

#ifdef MODE_DEBUG
  PRINT_SSID(pbody);
  PRINT_RATES(pbody);
  printf(" %s",	 CAPABILITY_ESS(pbody.capability_info) ? "ESS" : "IBSS");
  PRINT_DS_CHANNEL(pbody);
#endif
        return ret;
}


int mgmt_body_print(u_int16_t fc, const struct mgmt_header_t *pmh, const u_char *p, u_int length)
{
  switch (FC_SUBTYPE(fc)) {
  case ST_BEACON:
//    printf("Beacon");
    return handle_beacon(p, length);
  }
  return 0; 
}

u_int ieee802_11_print(const u_char *p, u_int length, u_int orig_caplen, int pad, u_int fcslen)
{
  u_int16_t fc;
  u_int caplen, hdrlen, meshdrlen;
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
  hdrlen = MGMT_HDRLEN; //extract_header_length(fc);
  if (pad)
    hdrlen = roundup2(hdrlen, 4);
  meshdrlen = 0;
    
  if (caplen < hdrlen) {
#ifdef MODE_DEBUG
    printf("caplen<hdrlen");
#endif
    return hdrlen;
  }

  ieee_802_11_hdr_print(fc, p, hdrlen, meshdrlen, &src, &dst);
  length -= hdrlen;
  caplen -= hdrlen;
  p += hdrlen;
  
  switch (FC_TYPE(fc)) {
  case T_MGMT:
    if (!mgmt_body_print(fc,
			 (const struct mgmt_header_t *)(p - hdrlen), p, length)) {
#ifdef MODE_DEBUG
      printf("[|802.11]");
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


int print_radiotap_field(struct cpack_state *s, u_int32_t bit, u_int8_t *flags)
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
    print_chaninfo(u.u16, u2.u16);
    break;
  case IEEE80211_RADIOTAP_FHSS:
#ifdef MODE_DEBUG
    printf("fhset %d fhpat %d ", u.u16 & 0xff, (u.u16 >> 8) & 0xff);
#endif
    break;
  case IEEE80211_RADIOTAP_RATE:
    if (u.u8 & 0x80){    
      
#ifdef MODE_DEBUG
      PRINT_HT_RATE("", u.u8, " THIS IS IT Mb/s ");
#endif
    }
    else{
#ifdef MODE_DEBUG
      PRINT_RATE("", u.u8, "**Mb/s ");
#endif
    }
    break;
  case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
#ifdef MODE_DEBUG
    printf("%ddB GOTS!! signal ", u.i8);
#endif
    break;
  case IEEE80211_RADIOTAP_DBM_ANTNOISE:
#ifdef MODE_DEBUG
    printf("%ddB GOTN!! noise ", u.i8);
#endif
    break;
  case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
#ifdef MODE_DEBUG
    printf("%ddB signal ", u.u8);
#endif
    break;
  case IEEE80211_RADIOTAP_DB_ANTNOISE:
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
#ifdef MODE_DEBUG
      printf("cfp ");
#endif
    }
    if (u.u8 & IEEE80211_RADIOTAP_F_SHORTPRE){
#ifdef MODE_DEBUG
      printf("short preamble ");
#endif
    }
    if (u.u8 & IEEE80211_RADIOTAP_F_WEP){
#ifdef MODE_DEBUG
      printf("wep ");
#endif
  }
    if (u.u8 & IEEE80211_RADIOTAP_F_FRAG){
#ifdef MODE_DEBUG
      printf("fragmented ");
#endif
    }
    if (u.u8 & IEEE80211_RADIOTAP_F_BADFCS){
#ifdef MODE_DEBUG
      printf("bad-fcs ");
#endif
    }
    break;
  case IEEE80211_RADIOTAP_ANTENNA:
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
    print_chaninfo(u2.u16, u.u32);
    break;
  }
  return 0;
}

 u_int ieee802_11_radio_print(const u_char *p, u_int length, u_int caplen)
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

  /* are there more bitmap extensions than bytes in header? */
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

      if (print_radiotap_field(&cpacker, bit, &flags) != 0)
	goto out;
    }
  }

  if (flags & IEEE80211_RADIOTAP_F_DATAPAD)
    pad = 1;
  if (flags & IEEE80211_RADIOTAP_F_FCS)
    fcslen = 4;
 out:
  return len + ieee802_11_print(p + len, length - len, caplen - len, pad,fcslen);
#undef BITNO_32
#undef BITNO_16
#undef BITNO_8
#undef BITNO_4
#undef BITNO_2
#undef BIT
}


u_int ieee802_11_if_print(const struct pcap_pkthdr *h, const u_char *p)
{
        return ieee802_11_radio_print(p, h->len, h->caplen);
}

void process_packet (u_char * args, const struct pcap_pkthdr *header, const u_char * packet)
{

  snapend = packet+ header->caplen; 
  ieee802_11_if_print(header,packet) ;
#ifdef MODE_DEBUG
  printf("\n------------------------------------\n");
#endif
}


int instantion_pcap (char* device){
 
  checkup(device);
  
  char errbuf[PCAP_ERRBUF_SIZE]; 
  bpf_u_int32 netp;   
  bpf_u_int32 maskp;  
  struct bpf_program fp; 
  int r;  
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
  pcap_close (handle);
 
}


static pthread_t signal_thread;
static pthread_t update_thread;
static pthread_mutex_t update_lock;
#define SLEEP_PERIOD 2


void write_update(int a){
printf("*********************wrote update **************************\%d\n",a);

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


int main(int argc, char* argv[])
{
  char *device= argv[1];
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

  instantion_pcap (device);
  return 0 ;
}
