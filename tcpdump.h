#define IEEE802_11_TSTAMP_LEN           8
#define IEEE802_11_BCNINT_LEN           2
#define IEEE802_11_CAPINFO_LEN          2
#define IEEE802_11_LISTENINT_LEN        2
#define IEEE802_11_AP_LEN               6
#define HASHNAMESIZE 4096
#define BUFSIZE 128

#define E_SSID          0
#define E_RATES         1
#define E_FH            2
#define E_DS            3
#define E_CF            4
#define E_TIM           5
#define E_IBSS          6
#define E_CHALLENGE     16



#ifndef roundup2
#define roundup2(x, y)  (((x)+((y)-1))&(~((y)-1))) /* if y is powers of two */
#endif

static const int ieee80211_htrates[16] = {
  13,             /* IFM_IEEE80211_MCS0 */
  26,             /* IFM_IEEE80211_MCS1 */
  39,             /* IFM_IEEE80211_MCS2 */
  52,             /* IFM_IEEE80211_MCS3 */
  78,             /* IFM_IEEE80211_MCS4 */
  104,            /* IFM_IEEE80211_MCS5 */
  117,            /* IFM_IEEE80211_MCS6 */
  130,            /* IFM_IEEE80211_MCS7 */
  26,             /* IFM_IEEE80211_MCS8 */
  52,             /* IFM_IEEE80211_MCS9 */
  78,             /* IFM_IEEE80211_MCS10 */
  104,            /* IFM_IEEE80211_MCS11 */
  156,            /* IFM_IEEE80211_MCS12 */
  208,            /* IFM_IEEE80211_MCS13 */
  234,            /* IFM_IEEE80211_MCS14 */
  260,            /* IFM_IEEE80211_MCS15 */
};
#define PRINT_HT_RATE(_sep, _r, _suf) \
  printf("%s%.1f%s", _sep, (.5 * ieee80211_htrates[(_r) & 0xf]), _suf)

struct tok {
  int v;                  /* value */
  const char *s;          /* string */
};

struct enamemem {
  u_short e_addr0;
  u_short e_addr1;
  u_short e_addr2;
  const char *e_name;
  u_char *e_nsap;                 /* used only for nsaptable[] */
#define e_bs e_nsap                     /* for bytestringtable */
  struct enamemem *e_nxt;
};
static struct enamemem enametable[HASHNAMESIZE];

struct mgmt_header_t {
  u_int16_t    fc;               /* 2 bytes */
  u_int16_t    duration;         /* 2 bytes */
  u_int8_t     da[6];            /* 6 bytes */
  u_int8_t     sa[6];            /* 6 bytes */
  u_int8_t     bssid[6];         /* 6 bytes */
  u_int16_t    seq_ctrl;         /* 2 bytes */

};

struct rates_t {
  u_int8_t        element_id;
  u_int8_t        length;
  u_int8_t        rate[16];
};

struct challenge_t {
  u_int8_t        element_id;
  u_int8_t        length;
  u_int8_t        text[254]; /* 1-253 + 1 for null */
};

struct fh_t {
  u_int8_t        element_id;
  u_int8_t        length;
  u_int16_t       dwell_time;
  u_int8_t        hop_set;
  u_int8_t        hop_pattern;
  u_int8_t        hop_index;
};

struct ds_t {
  u_int8_t        element_id;
  u_int8_t        length;
  u_int8_t        channel;
};

struct cf_t {
  u_int8_t        element_id;
  u_int8_t        length;
  u_int8_t        count;
  u_int8_t        period;
  u_int16_t       max_duration;
  u_int16_t       dur_remaing;
};

struct tim_t {
  u_int8_t        element_id;
  u_int8_t        length;
  u_int8_t        count;
  u_int8_t        period;
  u_int8_t        bitmap_control;
  u_int8_t        bitmap[251];
};

struct ssid_t {
  u_int8_t        element_id;
  u_int8_t        length;
  u_char          ssid[33];  /* 32 + 1 for null */
};

struct mgmt_body_t {
  u_int8_t        timestamp[IEEE802_11_TSTAMP_LEN];
  u_int16_t       beacon_interval;
  u_int16_t       listen_interval;
  u_int16_t       status_code;
  u_int16_t       aid;
  u_char          ap[IEEE802_11_AP_LEN];
  u_int16_t       reason_code;
  u_int16_t       auth_alg;
  u_int16_t       auth_trans_seq_num;
  int             challenge_present;
  struct challenge_t  challenge;
  u_int16_t       capability_info;
  int             ssid_present;
  struct ssid_t   ssid;
  int             rates_present;
  struct rates_t  rates;
  int             ds_present;
  struct ds_t     ds;
  int             cf_present;
  struct cf_t     cf;
  int             fh_present;
  struct fh_t     fh;
  int             tim_present;
  struct tim_t    tim;
};


#define T_MGMT 0x0  /* management */
#define T_CTRL 0x1  /* control */
#define T_DATA 0x2 /* data */

#define IEEE802_11_FC_LEN               2
#define IEEE802_11_DUR_LEN              2
#define IEEE802_11_DA_LEN               6
#define IEEE802_11_SA_LEN               6
#define IEEE802_11_BSSID_LEN            6
#define IEEE802_11_RA_LEN               6
#define IEEE802_11_TA_LEN               6
#define IEEE802_11_SEQ_LEN              2
#define IEEE802_11_CTL_LEN              2
#define IEEE802_11_IV_LEN               3
#define IEEE802_11_KID_LEN              1

/* Frame check sequence length. */
#define IEEE802_11_FCS_LEN              4

/* Lengths of beacon components. */

#define ST_BEACON               0x8

#define MGMT_HDRLEN     (IEEE802_11_FC_LEN+IEEE802_11_DUR_LEN+\
                         IEEE802_11_DA_LEN+IEEE802_11_SA_LEN+\
                         IEEE802_11_BSSID_LEN+IEEE802_11_SEQ_LEN)



#define TTEST2(var, l) (snapend - (l) <= snapend && \
			(const u_char *)&(var) <= snapend - (l))

#define T_MGMT 0x0  /* management */
#define T_CTRL 0x1  /* control */
#define T_DATA 0x2 /* data */


#define CAPABILITY_ESS(cap)     ((cap) & 0x0001)
#define CAPABILITY_IBSS(cap)    ((cap) & 0x0002)
#define CAPABILITY_CFP(cap)     ((cap) & 0x0004)
#define CAPABILITY_CFP_REQ(cap) ((cap) & 0x0008)
#define CAPABILITY_PRIVACY(cap) ((cap) & 0x0010)

#define CTRL_PS_POLL    0xA

#define FC_TO_DS(fc)            ((fc) & 0x0100)
#define FC_FROM_DS(fc)          ((fc) & 0x0200)
#define FC_MORE_FLAG(fc)        ((fc) & 0x0400)
#define FC_RETRY(fc)            ((fc) & 0x0800)
#define FC_POWER_MGMT(fc)       ((fc) & 0x1000)
#define FC_MORE_DATA(fc)        ((fc) & 0x2000)
#define FC_WEP(fc)              ((fc) & 0x4000)
#define FC_ORDER(fc)            ((fc) & 0x8000)
#define FC_TYPE(fc)             (((fc) >> 2) & 0x3)
#define FC_SUBTYPE(fc)          (((fc) >> 4) & 0xF)



#define IEEE80211_CHAN_FHSS \
        (IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_GFSK)
#define IEEE80211_CHAN_A \
        (IEEE80211_CHAN_5GHZ | IEEE80211_CHAN_OFDM)
#define IEEE80211_CHAN_B \
        (IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_CCK)
#define IEEE80211_CHAN_PUREG \
        (IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_OFDM)
#define IEEE80211_CHAN_G \
        (IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_DYN)

#define IS_CHAN_FHSS(flags) \
        ((flags & IEEE80211_CHAN_FHSS) == IEEE80211_CHAN_FHSS)
#define IS_CHAN_A(flags) \
        ((flags & IEEE80211_CHAN_A) == IEEE80211_CHAN_A)
#define IS_CHAN_B(flags) \
        ((flags & IEEE80211_CHAN_B) == IEEE80211_CHAN_B)
#define IS_CHAN_PUREG(flags) \
        ((flags & IEEE80211_CHAN_PUREG) == IEEE80211_CHAN_PUREG)
#define IS_CHAN_G(flags) \
        ((flags & IEEE80211_CHAN_G) == IEEE80211_CHAN_G)
#define IS_CHAN_ANYG(flags) \
        (IS_CHAN_PUREG(flags) || IS_CHAN_G(flags))


#define PRINT_RATE(_sep, _r, _suf) \
  printf("%s%2.1f%s", _sep, (.5 * ((_r) & 0x7f)), _suf)
#define PRINT_RATES(p) \
  if (p.rates_present) { \
  int z; \
  const char *sep = " ["; \
  for (z = 0; z < p.rates.length ; z++) { \
  PRINT_RATE(sep, p.rates.rate[z], \
	     (p.rates.rate[z] & 0x80 ? "*" : "")); \
  sep = " "; \
  } \
  if (p.rates.length != 0) \
    printf(" Mbit]"); \
  }

#define PRINT_DS_CHANNEL(p) \
  if (p.ds_present) \
    printf(" CH: %u", p.ds.channel); \
  printf("%s", \
	 CAPABILITY_PRIVACY(p.capability_info) ? ", PRIVACY" : "" );


/*
#define EXTRACT_LE_32BITS(p) \
  ((u_int32_t)((u_int32_t)*((const u_int8_t *)(p) + 3) << 24 | \
  (u_int32_t)*((const u_int8_t *)(p) + 2) << 16 | \
  (u_int32_t)*((const u_int8_t *)(p) + 1) << 8 | \
	       (u_int32_t)*((const u_int8_t *)(p) + 0)))

#define EXTRACT_64BITS(p) \
  ((u_int64_t)((u_int64_t)*((const u_int8_t *)(p) + 0) << 56 | \
  (u_int64_t)*((const u_int8_t *)(p) + 1) << 48 | \
  (u_int64_t)*((const u_int8_t *)(p) + 2) << 40 | \
  (u_int64_t)*((const u_int8_t *)(p) + 3) << 32 | \
  (u_int64_t)*((const u_int8_t *)(p) + 4) << 24 | \
  (u_int64_t)*((const u_int8_t *)(p) + 5) << 16 | \
  (u_int64_t)*((const u_int8_t *)(p) + 6) << 8 | \
	       (u_int64_t)*((const u_int8_t *)(p) + 7)))


#define EXTRACT_LE_64BITS(p) \
  ((u_int64_t)((u_int64_t)*((const u_int8_t *)(p) + 7) << 56 | \
  (u_int64_t)*((const u_int8_t *)(p) + 6) << 48 | \
  (u_int64_t)*((const u_int8_t *)(p) + 5) << 40 | \
  (u_int64_t)*((const u_int8_t *)(p) + 4) << 32 | \
  (u_int64_t)*((const u_int8_t *)(p) + 3) << 24 | \
  (u_int64_t)*((const u_int8_t *)(p) + 2) << 16 | \
  (u_int64_t)*((const u_int8_t *)(p) + 1) << 8 | \
	       (u_int64_t)*((const u_int8_t *)(p) + 0)))

*/

#ifdef LBL_ALIGN

#ifdef HAVE___ATTRIBUTE__
/*
 * We have __attribute__; we assume that means we have __attribute__((packed)).
 * Declare packed structures containing a u_int16_t and a u_int32_t,
 * cast the pointer to point to one of those, and fetch through it;
 * the GCC manual doesn't appear to explicitly say that
 * __attribute__((packed)) causes the compiler to generate unaligned-safe
 * code, but it apppears to do so.
 *
 * We do this in case the compiler can generate, for this instruction set,
 * better code to do an unaligned load and pass stuff to "ntohs()" or
 * "ntohl()" than the code to fetch the bytes one at a time and
 * assemble them.  (That might not be the case on a little-endian platform,
 * where "ntohs()" and "ntohl()" might not be done inline.)
 */
typedef struct {
        u_int16_t       val;
} __attribute__((packed)) unaligned_u_int16_t;

typedef struct {
        u_int32_t       val;
} __attribute__((packed)) unaligned_u_int32_t;

#define EXTRACT_16BITS(p) \
        ((u_int16_t)ntohs(((const unaligned_u_int16_t *)(p))->val))
#define EXTRACT_32BITS(p) \
        ((u_int32_t)ntohl(((const unaligned_u_int32_t *)(p))->val))
#define EXTRACT_64BITS(p) \
        ((u_int64_t)(((u_int64_t)ntohl(((const unaligned_u_int32_t *)(p) + 0)->val)) << 32 | \
                     ((u_int64_t)ntohl(((const unaligned_u_int32_t *)(p) + 1)->val)) << 0))

#else /* HAVE___ATTRIBUTE__ */
/*
 * We don't have __attribute__, so do unaligned loads of big-endian
 * quantities the hard way - fetch the bytes one at a time and
 * assemble them.
 */
#define EXTRACT_16BITS(p) \
        ((u_int16_t)((u_int16_t)*((const u_int8_t *)(p) + 0) << 8 | \
                     (u_int16_t)*((const u_int8_t *)(p) + 1)))
#define EXTRACT_32BITS(p) \
        ((u_int32_t)((u_int32_t)*((const u_int8_t *)(p) + 0) << 24 | \
                     (u_int32_t)*((const u_int8_t *)(p) + 1) << 16 | \
                     (u_int32_t)*((const u_int8_t *)(p) + 2) << 8 | \
                     (u_int32_t)*((const u_int8_t *)(p) + 3)))
#define EXTRACT_64BITS(p) \
        ((u_int64_t)((u_int64_t)*((const u_int8_t *)(p) + 0) << 56 | \
                     (u_int64_t)*((const u_int8_t *)(p) + 1) << 48 | \
                     (u_int64_t)*((const u_int8_t *)(p) + 2) << 40 | \
                     (u_int64_t)*((const u_int8_t *)(p) + 3) << 32 | \
                     (u_int64_t)*((const u_int8_t *)(p) + 4) << 24 | \
                     (u_int64_t)*((const u_int8_t *)(p) + 5) << 16 | \
                     (u_int64_t)*((const u_int8_t *)(p) + 6) << 8 | \
                     (u_int64_t)*((const u_int8_t *)(p) + 7)))
#endif /* HAVE___ATTRIBUTE__ */
#else /* LBL_ALIGN */
/*
 * The processor natively handles unaligned loads, so we can just
 * cast the pointer and fetch through it.
 */
#define EXTRACT_16BITS(p) \
        ((u_int16_t)ntohs(*(const u_int16_t *)(p)))
#define EXTRACT_32BITS(p) \
        ((u_int32_t)ntohl(*(const u_int32_t *)(p)))
#define EXTRACT_64BITS(p) \
        ((u_int64_t)(((u_int64_t)ntohl(*((const u_int32_t *)(p) + 0))) << 32 | \
                     ((u_int64_t)ntohl(*((const u_int32_t *)(p) + 1))) << 0))
#endif /* LBL_ALIGN */

#define EXTRACT_24BITS(p) \
        ((u_int32_t)((u_int32_t)*((const u_int8_t *)(p) + 0) << 16 | \
                     (u_int32_t)*((const u_int8_t *)(p) + 1) << 8 | \
                     (u_int32_t)*((const u_int8_t *)(p) + 2)))

/*
 * Macros to extract possibly-unaligned little-endian integral values.
 * XXX - do loads on little-endian machines that support unaligned loads?
 */
#define EXTRACT_LE_8BITS(p) (*(p))
#define EXTRACT_LE_16BITS(p) \
        ((u_int16_t)((u_int16_t)*((const u_int8_t *)(p) + 1) << 8 | \
                     (u_int16_t)*((const u_int8_t *)(p) + 0)))
#define EXTRACT_LE_32BITS(p) \
        ((u_int32_t)((u_int32_t)*((const u_int8_t *)(p) + 3) << 24 | \
                     (u_int32_t)*((const u_int8_t *)(p) + 2) << 16 | \
                     (u_int32_t)*((const u_int8_t *)(p) + 1) << 8 | \
                     (u_int32_t)*((const u_int8_t *)(p) + 0)))
#define EXTRACT_LE_24BITS(p) \
        ((u_int32_t)((u_int32_t)*((const u_int8_t *)(p) + 2) << 16 | \
                     (u_int32_t)*((const u_int8_t *)(p) + 1) << 8 | \
                     (u_int32_t)*((const u_int8_t *)(p) + 0)))
#define EXTRACT_LE_64BITS(p) \
        ((u_int64_t)((u_int64_t)*((const u_int8_t *)(p) + 7) << 56 | \
                     (u_int64_t)*((const u_int8_t *)(p) + 6) << 48 | \
                     (u_int64_t)*((const u_int8_t *)(p) + 5) << 40 | \
                     (u_int64_t)*((const u_int8_t *)(p) + 4) << 32 | \
                     (u_int64_t)*((const u_int8_t *)(p) + 3) << 24 | \
                     (u_int64_t)*((const u_int8_t *)(p) + 2) << 16 | \
                     (u_int64_t)*((const u_int8_t *)(p) + 1) << 8 | \
                     (u_int64_t)*((const u_int8_t *)(p) + 0)))
                                                                                
struct cpack_state {
        u_int8_t                                        *c_buf;
        u_int8_t                                        *c_next;
        size_t                                           c_len;
};

unsigned char *snapend;



#define OUI_ENCAP_ETHER 0x000000        /* encapsulated Ethernet */
#define OUI_CISCO       0x00000c        /* Cisco protocols */
#define OUI_NORTEL      0x000081        /* Nortel SONMP */
#define OUI_CISCO_90    0x0000f8        /* Cisco bridging */
#define OUI_RFC2684     0x0080c2        /* RFC 2427/2684 bridged Ethernet */
#define OUI_ATM_FORUM   0x00A03E        /* ATM Forum */
#define OUI_CABLE_BPDU  0x00E02F        /* DOCSIS spanning tree BPDU */
#define OUI_APPLETALK   0x080007        /* Appletalk */
#define OUI_JUNIPER     0x009069        /* Juniper */
#define OUI_HP          0x080009        /* Hewlett-Packard */
#define OUI_IEEE_8021_PRIVATE 0x0080c2      /* IEEE 802.1 Organisation Specific - Annex F */
#define OUI_IEEE_8023_PRIVATE 0x00120f      /* IEEE 802.3 Organisation Specific - Annex G */
#define OUI_TIA         0x0012bb        /* TIA - Telecommunications Industry Association - ANSI/TIA-1057- 2006 */



/* Find the hash node that corresponds the ether address 'ep' */
const struct tok oui_values[] = {
  { OUI_ENCAP_ETHER, "Ethernet" },
  { OUI_CISCO, "Cisco" },
  { OUI_NORTEL, "Nortel Networks SONMP" },
  { OUI_CISCO_90, "Cisco bridged" },
  { OUI_RFC2684, "Ethernet bridged" },
  { OUI_ATM_FORUM, "ATM Forum" },
  { OUI_CABLE_BPDU, "DOCSIS Spanning Tree" },
  { OUI_APPLETALK, "Appletalk" },
  { OUI_JUNIPER, "Juniper" },
  { OUI_HP, "Hewlett-Packard" },
  { OUI_IEEE_8021_PRIVATE, "IEEE 802.1 Private"},
  { OUI_IEEE_8023_PRIVATE, "IEEE 802.3 Private"},
  { OUI_TIA, "ANSI/TIA"},
  { 0, NULL }
};

