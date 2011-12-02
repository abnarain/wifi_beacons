#define MAX_ESSID_LEN		32
#define MAC_LEN                 6


#define PKT_TYPE_CTRL           0x000001
#define PKT_TYPE_MGMT           0x000002
#define PKT_TYPE_DATA           0x000004

#define PKT_TYPE_BEACON         0x000010
#define PKT_TYPE_PROBE          0x000020
#define PKT_TYPE_ASSOC          0x000040
#define PKT_TYPE_AUTH           0x000080
#define PKT_TYPE_RTS            0x000100
#define PKT_TYPE_CTS            0x000200
#define PKT_TYPE_ACK            0x000400
#define PKT_TYPE_NULL           0x000800

#define PKT_TYPE_ARP            0x001000
#define PKT_TYPE_IP             0x002000
#define PKT_TYPE_ICMP           0x004000
#define PKT_TYPE_UDP            0x008000
#define PKT_TYPE_TCP            0x010000
#define PKT_TYPE_OLSR           0x020000
#define PKT_TYPE_OLSR_LQ        0x040000
#define PKT_TYPE_OLSR_GW        0x080000
#define PKT_TYPE_BATMAN         0x100000
#define PKT_TYPE_MESHZ          0x200000
#define PKT_TYPE_ALL_MGMT       (PKT_TYPE_BEACON | PKT_TYPE_PROBE | PKT_TYPE_ASSOC | PKT_TYPE_AUTH)
#define PKT_TYPE_ALL_CTRL       (PKT_TYPE_RTS | PKT_TYPE_CTS | PKT_TYPE_ACK)
#define PKT_TYPE_ALL_DATA       (PKT_TYPE_NULL | PKT_TYPE_ARP | PKT_TYPE_ICMP | PKT_TYPE_IP | \
                                 PKT_TYPE_UDP | PKT_TYPE_TCP | PKT_TYPE_OLSR | PKT_TYPE_OLSR_LQ | \
                                 PKT_TYPE_OLSR_GW | PKT_TYPE_BATMAN | PKT_TYPE_MESHZ)

#define WLAN_MODE_AP            0x01
#define WLAN_MODE_IBSS          0x02
#define WLAN_MODE_STA           0x04
#define WLAN_MODE_PROBE         0x08

#define PHY_FLAG_SHORTPRE       0x0001
#define PHY_FLAG_BADFCS         0x0002
#define PHY_FLAG_A              0x0010
#define PHY_FLAG_B              0x0020
#define PHY_FLAG_G              0x0040
#define PHY_FLAG_MODE_MASK      0x00f0

/* Lengths of beacon components. */
#define IEEE802_11_TSTAMP_LEN           8
#define IEEE802_11_BCNINT_LEN           2
#define IEEE802_11_CAPINFO_LEN          2
#define IEEE802_11_LISTENINT_LEN        2

#define IEEE802_11_AID_LEN              2
#define IEEE802_11_STATUS_LEN           2
#define IEEE802_11_REASON_LEN           2


#define	IEEE802_11_TSTAMP_LEN		8



struct packet_p {
        /* general */
        unsigned int            pkt_types;      /* bitmask of packet types */

        /* wlan phy (from radiotap) */
        int                     phy_signal;     /* signal strength (usually dBm) */
        int                     phy_noise;      /* noise level (usually dBm) */
        unsigned int            phy_snr;        /* signal to noise ratio */
        unsigned int            phy_rate;       /* physical rate */
        unsigned int            phy_freq;       /* frequency from driver */
        unsigned char           phy_chan;       /* channel from driver */
        unsigned int            phy_flags;      /* A, B, G, shortpre */

        /* wlan mac */
        unsigned int            wlan_len;       /* packet length */
        unsigned int            wlan_type;      /* frame control field */
        unsigned char           wlan_src[MAC_LEN];
        unsigned char           wlan_dst[MAC_LEN];
        unsigned char           wlan_bssid[MAC_LEN];
        char                    wlan_essid[MAX_ESSID_LEN];
        u_int64_t               wlan_tsf;       /* timestamp from beacon */
        unsigned int            wlan_bintval;   /* beacon interval */
        unsigned int            wlan_mode;      /* AP, STA or IBSS */
        unsigned char           wlan_channel;   /* channel from beacon, probe */
        unsigned char           wlan_qos_class; /* for QDATA frames */
        unsigned int            wlan_nav;       /* frame NAV duration */
        unsigned int            wlan_seqno;     /* sequence number */

        /* flags */
        unsigned int            wlan_wep:1,     /* WEP on/off */
                                wlan_retry:1;



};

struct pkt_names {
  char c;
  const char* name;
};
#define EXTRACT_LE_16BITS(p) \
  ((u_int16_t)((u_int16_t)*((const u_int8_t *)(p) + 1) << 8 | \
	       (u_int16_t)*((const u_int8_t *)(p) + 0)))

