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
#include "ieee80211.h"
#include "tcpdump.h"
#include <ctype.h>



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
  if (tp->e_nxt == NULL)
    printf("lookup_emem: calloc");

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
const char *
tok2str(register const struct tok *lp, register const char *fmt,
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


const char *
etheraddr_string(register const u_char *ep)
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

    /*
     * We don't cast it to "const struct ether_addr *"
     * because some systems fail to declare the second
     * argument as a "const" pointer, even though they
     * don't modify what it points to.
     */
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

void mgmt_header_print(const u_char *p, const u_int8_t **srcp,
		  const u_int8_t **dstp)
{
  const struct mgmt_header_t *hp = (const struct mgmt_header_t *) p;

  if (srcp != NULL)
    *srcp = hp->sa;
  if (dstp != NULL)
    *dstp = hp->da;
 
  // if (!eflag)
  //return;
  
  printf("BSSID:%s DA:%s SA:%s ",
	 etheraddr_string((hp)->bssid), etheraddr_string((hp)->da),
	 etheraddr_string((hp)->sa));
 

}

void print_chaninfo(int freq, int flags)
{
        printf("%u MHz", freq);
        if (IS_CHAN_FHSS(flags))
                printf(" FHSS");
        if (IS_CHAN_A(flags)) {
                if (flags & IEEE80211_CHAN_HALF)
                        printf(" 11a/10Mhz");
                else if (flags & IEEE80211_CHAN_QUARTER)
                        printf(" 11a/5Mhz");
                else
                        printf(" 11a");
        }
        if (IS_CHAN_ANYG(flags)) {
                if (flags & IEEE80211_CHAN_HALF)
                        printf(" 11g/10Mhz");
                else if (flags & IEEE80211_CHAN_QUARTER)
                        printf(" 11g/5Mhz");
                else
                        printf(" 11g");
        } else if (IS_CHAN_B(flags))
                printf(" 11b");
        if (flags & IEEE80211_CHAN_TURBO)
                printf(" Turbo");
        if (flags & IEEE80211_CHAN_HT20)
                printf(" ht/20");
        else if (flags & IEEE80211_CHAN_HT40D)
                printf(" ht/40-");
        else if (flags & IEEE80211_CHAN_HT40U)
                printf(" ht/40+");
        printf(" ");
}




void ieee_802_11_hdr_print(u_int16_t fc, const u_char *p, u_int hdrlen,
    u_int meshdrlen, const u_int8_t **srcp, const u_int8_t **dstp)
{
  int vflag;
  vflag=1;
  if (vflag) {
    if (FC_MORE_DATA(fc))
      printf("More Data ");
                if (FC_MORE_FLAG(fc))
                        printf("More Fragments ");
                if (FC_POWER_MGMT(fc))
                        printf("Pwr Mgmt ");
                if (FC_RETRY(fc))
                        printf("Retry ");
                if (FC_ORDER(fc))
                        printf("Strictly Ordered ");
                if (FC_WEP(fc))
                        printf("WEP Encrypted ");
                if (FC_TYPE(fc) != T_CTRL || FC_SUBTYPE(fc) != CTRL_PS_POLL)
                        printf("%dus ",
                            EXTRACT_LE_16BITS(
                                &((const struct mgmt_header_t *)p)->duration));
        }
        switch (FC_TYPE(fc)) {
        case T_MGMT:
                mgmt_header_print(p, srcp, dstp);
                break;
        default:
                printf("(header) unknown IEEE802.11 frame type (%d)",
                    FC_TYPE(fc));
                *srcp = NULL;
                *dstp = NULL;
                break;
        }
}
/*
static int extract_header_length(u_int16_t fc)
{
    switch (FC_TYPE(fc)) {
        case T_MGMT:
                return MGMT_HDRLEN;
	
}
return 0 ; 
}
*/

/*
 * Print out a null-terminated filename (or other ascii string).
 * If ep is NULL, assume no truncation check is needed.
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
      putchar('M');
      putchar('-');
    }
    if (!isprint(c)) {
      c ^= 0x40;      /* DEL to ?, others to alpha */
      putchar('^');
    }
    putchar(c);
  }
  return(ret);
}




#define PRINT_SSID(p) \
  if (p.ssid_present) { \
  printf(" ("); \
  fn_print(p.ssid.ssid, NULL); \
  printf(")"); \
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

  /* Ensure alignment. */
  next = cpack_next_boundary(cs->c_buf, cs->c_next, wordsize);

  /* Too little space for wordsize bytes? */
  if (next - cs->c_buf + wordsize > cs->c_len)
    return NULL;

  return next;
}

int
cpack_uint32(struct cpack_state *cs, u_int32_t *u)
{
  u_int8_t *next;

  if ((next = cpack_align_and_reserve(cs, sizeof(*u))) == NULL)
    return -1;

  *u = EXTRACT_LE_32BITS(next);

  /* Move pointer past the u_int32_t. */
  cs->c_next = next + sizeof(*u);
  return 0;
}

/* Unpack a 16-bit unsigned integer. */
int
cpack_uint16(struct cpack_state *cs, u_int16_t *u)
{
  u_int8_t *next;

  if ((next = cpack_align_and_reserve(cs, sizeof(*u))) == NULL)
    return -1;

  *u = EXTRACT_LE_16BITS(next);

  /* Move pointer past the u_int16_t. */
  cs->c_next = next + sizeof(*u);
  return 0;
}

/* Unpack an 8-bit unsigned integer. */
int
cpack_uint8(struct cpack_state *cs, u_int8_t *u)
{
  /* No space left? */
  if ((size_t)(cs->c_next - cs->c_buf) >= cs->c_len)
    return -1;

  *u = *cs->c_next;

  /* Move pointer past the u_int8_t. */
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

/* Unpack a 64-bit unsigned integer. */
int
cpack_uint64(struct cpack_state *cs, u_int64_t *u)
{
  u_int8_t *next;

  if ((next = cpack_align_and_reserve(cs, sizeof(*u))) == NULL)
    return -1;

  *u = EXTRACT_LE_64BITS(next);

  /* Move pointer past the u_int64_t. */
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
      /*
       * Present and not truncated.
       *
       * If we haven't already seen an SSID IE,
       * copy this one, otherwise ignore this one,
       * so we later report the first one we saw.
       */
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
      /*
       * Present and not truncated.
       *
       * If we haven't already seen a challenge IE,
       * copy this one, otherwise ignore this one,
       * so we later report the first one we saw.
       */
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

	PRINT_SSID(pbody);
        PRINT_RATES(pbody);
        printf(" %s",
            CAPABILITY_ESS(pbody.capability_info) ? "ESS" : "IBSS");
        PRINT_DS_CHANNEL(pbody);

        return ret;
}


int mgmt_body_print(u_int16_t fc, const struct mgmt_header_t *pmh, const u_char *p, u_int length)
{
  switch (FC_SUBTYPE(fc)) {
  case ST_BEACON:
    printf("Beacon");
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
    printf("[|802.11]");
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
    printf("[|802.11]");
    return orig_caplen;
  }

  fc = EXTRACT_LE_16BITS(p);
  hdrlen = MGMT_HDRLEN; //extract_header_length(fc);
  if (pad)
    hdrlen = roundup2(hdrlen, 4);
  meshdrlen = 0;
    
  if (caplen < hdrlen) {
    printf("[|802.11]");
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
      printf("[|802.11]");
      return hdrlen;
    }
    break;
  default:
    printf("unknown 802.11 frame type (%d)", FC_TYPE(fc));
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
    /* this bit indicates a field whose
     * size we do not know, so we cannot
     * proceed.  Just print the bit number.
     */
    printf("[bit %u] ", bit);
    return -1;
  }
  if (rc != 0) {
    printf("[|802.11]");
    return rc;
  }

  switch (bit) {
  case IEEE80211_RADIOTAP_CHANNEL:
    print_chaninfo(u.u16, u2.u16);
    break;
  case IEEE80211_RADIOTAP_FHSS:
    printf("fhset %d fhpat %d ", u.u16 & 0xff, (u.u16 >> 8) & 0xff);
    break;
  case IEEE80211_RADIOTAP_RATE:
    if (u.u8 & 0x80)
      PRINT_HT_RATE("", u.u8, " Mb/s ");
    else
      PRINT_RATE("", u.u8, " Mb/s ");
    break;
  case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
    printf("%ddB signal ", u.i8);
    break;
  case IEEE80211_RADIOTAP_DBM_ANTNOISE:
    printf("%ddB noise ", u.i8);
    break;
  case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
    printf("%ddB signal ", u.u8);
    break;
  case IEEE80211_RADIOTAP_DB_ANTNOISE:
    printf("%ddB noise ", u.u8);
    break;
  case IEEE80211_RADIOTAP_LOCK_QUALITY:
    printf("%u sq ", u.u16);
    break;
  case IEEE80211_RADIOTAP_TX_ATTENUATION:
    printf("%d tx power ", -(int)u.u16);
    break;
  case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
    printf("%ddB tx power ", -(int)u.u8);
    break;
  case IEEE80211_RADIOTAP_DBM_TX_POWER:
    printf("%ddBm tx power ", u.i8);
    break;
  case IEEE80211_RADIOTAP_FLAGS:
    if (u.u8 & IEEE80211_RADIOTAP_F_CFP)
      printf("cfp ");
    if (u.u8 & IEEE80211_RADIOTAP_F_SHORTPRE)
      printf("short preamble ");
    if (u.u8 & IEEE80211_RADIOTAP_F_WEP)
      printf("wep ");
    if (u.u8 & IEEE80211_RADIOTAP_F_FRAG)
      printf("fragmented ");
    if (u.u8 & IEEE80211_RADIOTAP_F_BADFCS)
      printf("bad-fcs ");
    break;
  case IEEE80211_RADIOTAP_ANTENNA:
    printf("antenna %d ", u.u8);
    break;
  case IEEE80211_RADIOTAP_TSFT:
    printf(/*% PRIu64 */"us tsft "/*, u.u64*/);
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
    printf("[|802.11]");
    return caplen;
  }

  hdr = (struct ieee80211_radiotap_header *)p;

  len = EXTRACT_LE_16BITS(&hdr->it_len);

  if (caplen < len) {
    printf("[|802.11]");
    return caplen;
  }
  for (last_presentp = &hdr->it_present;
       IS_EXTENDED(last_presentp) &&
	 (u_char*)(last_presentp + 1) <= p + len;
       last_presentp++);

  /* are there more bitmap extensions than bytes in header? */
  if (IS_EXTENDED(last_presentp)) {
    printf("[|802.11]");
    return caplen;
  }
  iter = (u_char*)(last_presentp + 1);

  if (cpack_init(&cpacker, (u_int8_t*)iter, len - (iter - p)) != 0) {
    /* XXX */
    printf("[|802.11]");
    return caplen;
  }

  /* Assume no flags */
  flags = 0;
  /* Assume no Atheros padding between 802.11 header and body */
  pad = 0;
  /* Assume no FCS at end of frame */
  fcslen = 0;
  for (bit0 = 0, presentp = &hdr->it_present; presentp <= last_presentp;
       presentp++, bit0 += 32) {
    for (present = EXTRACT_LE_32BITS(presentp); present;
	 present = next_present) {
      /* clear the least significant bit that is set */
      next_present = present & (present - 1);

      /* extract the least significant bit that is set */
      bit = (enum ieee80211_radiotap_type)
	(bit0 + BITNO_32(present ^ next_present));

      if (print_radiotap_field(&cpacker, bit, &flags) != 0)
	goto out;
    }
  }

  if (flags & IEEE80211_RADIOTAP_F_DATAPAD)
    pad = 1;        /* Atheros padding */
  if (flags & IEEE80211_RADIOTAP_F_FCS)
    fcslen = 4;     /* FCS at end of packet */
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
  printf("\n------------------------------------\n");
}


static pthread_t signal_thread;
static pthread_t update_thread;


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
  printf("hi \n"); 
  pcap_close (handle);
   return 0 ;



}
