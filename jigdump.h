#ifndef _JIGDUMP_H_
#define _JIGDUMP_H_

#define JIGDUMP_HDR_VERSION 0xae
#define JIGDUMP_HDR_SNAPLEN 120 // 802.11 (24) + LLC (4) + IP(88) + FCS (4)
#define JIGDUMP_HDR_SNAPLEN_DHCP 400
#define JIGDUMP_HDR_SNAPLEN_MAX 400
#define JIGDUMP_HDR_F_RX    0x0
#define JIGDUMP_HDR_F_TX    0x1
#define JIGDUMP_HDR_F_MAC_TIME 0x2
#define JIGDUMP_HDR_F_FCS   0x4
#define JIGDUMP_HDR_F_TSF_SLAVE   0x8
#define JIGDUMP_HDR_F_TSF_CARRY 0x10
#define JIGDUMP_HDR_F_PREV_ERRS_OVERFLOW 0x20
#define JIGDUMP_HDR_F_TSF_LEAP   0x40
#define JIGDUMP_HDR_F_MAC_TSC   0x80
//#include <sys/types.h>
struct phyerr_hdr
{
	u_int16_t offset_:14;
	u_int16_t type_:2;
} __attribute__ ((packed));

struct jigdump_hdr
{
	u_int8_t version_;
	u_int8_t hdrlen_;
	u_int8_t status_;
	u_int8_t phyerr_;

	u_int8_t rssi_;
	u_int8_t flags_;
	u_int8_t channel_;
	u_int8_t rate_;

	u_int16_t caplen_;
	u_int16_t snaplen_;

	u_int16_t rxdelay_; // delay between hal to ath_rx_capture()
	u_int16_t prev_errs_;

	//tsf when first bit arrives mac (note corresponds to last bit in phy)
	u_int64_t mac_tsf_; 

	u_int64_t mac_time_; //epoch time when first bit arrives mac

	u_int32_t fcs_;
	// these are only valid in tx frame
} __attribute__ ((packed));

#if 0
struct jigphy_hdr
{
	u_int64_t version_:8;
	u_int64_t phyerr_:6;
	u_int64_t mac_tsf_:50;
	// these are only valid in tx frame
} __attribute__ ((packed));
#endif
#if 0
struct jigdump_hdr2
{
	u_int8_t version_:4;
	u_int8_t status_:2;
	u_int8_t phyerr_:5;
	u_int8_t channel_:4;

	u_int8_t hdrlen_;
	u_int8_t rssi_;
	u_int8_t flags_;
	u_int8_t rate_;

	u_int16_t caplen_:12;
	u_int16_t snaplen_:10;

	//u_int16_t rxdelay_; // delay between hal to ath_rx_capture()
	//u_int16_t prev_errs_;

	u_int64_t mac_tsf_:50; //tsf when first bit arrives mac

	u_int64_t mac_time_:50; //epoch time when first bit arrives mac

	u_int32_t fcs_;
	// these are only valid in tx frame
} __attribute__ ((packed));

jigdump_hdr2 xyz;
#endif

#define JIGBLOCK_MAX_SIZE (16000)
struct jigblk_hdr
{
	u_int32_t magic_;
	int32_t cmpr_sz_;
	int32_t orig_sz_;
	int32_t bid_;
	int32_t pid_;
	int32_t seek_; 
	int64_t time_; /* start time */
	int64_t duration_; /* end time - start time */
	u_int16_t n_pkts_;
} __attribute__ ((packed));

struct pstat
{
	int64_t time_; /* start time */
	u_int32_t n_pkts_;
	u_int32_t n_empty_;
	u_int32_t n_crc_[14];
	u_int32_t n_ok_ [14];
	u_int32_t n_80211_mgmt_;
	u_int32_t n_80211_beacon_;
	u_int32_t n_80211_probe_;
	u_int32_t n_80211_ctrl_;
	u_int32_t n_80211_rts_;
	u_int32_t n_80211_cts_;
	u_int32_t n_80211_ack_;
	u_int32_t n_80211_data_;
	u_int32_t n_80211_data_d_[4];
	u_int32_t n_80211_data_n_[4];
	u_int32_t n_arp_[4];
	u_int32_t n_icmp_[4];
	u_int32_t n_tcp_[4];
	u_int32_t n_udp_[4];
} __attribute__ ((packed));

#define JIGBLK_HDR_MAGIC (0xa4b3c2f3)


#endif
