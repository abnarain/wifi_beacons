/*
    This file is part of Kismet

    Kismet is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    Kismet is distributed in the hope that it will be useful,
      but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Kismet; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifndef __PACKET_H__
#define __PACKET_H__

//#include "config.h"

#include <stdio.h>
#include <ctype.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#define DEVNAME_LEN 16
#define MAX_PACKET_LEN 10240

#define SSID_SIZE 255

#define MAC_LEN 6
#define MAC_STR_LEN ((MAC_LEN * 2) + 6)

// Parmeters to the packet info
struct packet_parm {
    int fuzzy_crypt;
	int fuzzy_decode;
};

// Signalling layer info - what protocol are we seeing data on?
// Not all of these types are currently supported, of course
enum carrier_type {
    carrier_unknown,
    carrier_80211b,
    carrier_80211bplus,
    carrier_80211a,
    carrier_80211g,
    carrier_80211fhss,
    carrier_80211dsss,
    carrier_80211n20,
    carrier_80211n40
};

// Packet encoding info - how are packets encoded?
enum encoding_type {
    encoding_unknown,
    encoding_cck,
    encoding_pbcc,
    encoding_ofdm
};

// Very similar to pcap_pkthdr and wtap_pkthdr.  This is our
// common packet header that we convert everything to.
typedef struct {
    unsigned int len;		// The amount of data we've actually got
    unsigned int caplen;	// The amount of data originally captured
    struct timeval ts;          // Capture timestamp
    int quality;                // Signal quality
    int signal;                 // Signal strength
    int noise;                  // Noise level
    int error;                  // Capture source told us this was a bad packet
    int channel;                // Hardware receive channel, if the drivers tell us
    int modified;               // Has moddata been populated?
    uint8_t *data;              // Raw packet data
    uint8_t *moddata;           // Modified packet data
    char sourcename[32];        // Name of the source that generated the data
  //    carrier_type carrier;       // Signal carrier
  //  encoding_type encoding;     // Signal encoding
    int datarate;               // Data rate in units of 100 kbps
    float gps_lat;              // GPS coordinates
    float gps_lon;
    float gps_alt;
    float gps_spd;
    float gps_heading;
    int gps_fix;
  //    packet_parm parm;           // Parameters from the packet source that trickle down
} kis_packet;

#ifdef WORDS_BIGENDIAN
// Byte ordering for bigendian systems.  Bitwise strcts are so funky.
typedef struct {
    unsigned short subtype : 4 __attribute__ ((packed));
    unsigned short type : 2 __attribute__ ((packed));
    unsigned short version : 2 __attribute__ ((packed));

    unsigned short order : 1 __attribute__ ((packed));
    unsigned short wep : 1 __attribute__ ((packed));
    unsigned short more_data : 1 __attribute__ ((packed));
    unsigned short power_management : 1 __attribute__ ((packed));

    unsigned short retry : 1 __attribute__ ((packed));
    unsigned short more_fragments : 1 __attribute__ ((packed));
    unsigned short from_ds : 1 __attribute__ ((packed));
    unsigned short to_ds : 1 __attribute__ ((packed));
} frame_control;

typedef struct {
    unsigned short frag : 12 __attribute__ ((packed));
    unsigned short sequence : 4 __attribute__ ((packed));
} wireless_fragseq;

typedef struct {
    uint8_t timestamp[8];

    // This field must be converted to host-endian before being used
    unsigned int beacon : 16 __attribute__ ((packed));

    unsigned short agility : 1 __attribute__ ((packed));
    unsigned short pbcc : 1 __attribute__ ((packed));
    unsigned short short_preamble : 1 __attribute__ ((packed));
    unsigned short wep : 1 __attribute__ ((packed));

    unsigned short unused2 : 1 __attribute__ ((packed));
    unsigned short unused1 : 1 __attribute__ ((packed));
    unsigned short ibss : 1 __attribute__ ((packed));
    unsigned short ess : 1 __attribute__ ((packed));

    unsigned int coordinator : 8 __attribute__ ((packed));

} fixed_parameters;

#else
// And 802.11 packet frame header
typedef struct {
    unsigned short version : 2 __attribute__ ((packed));
    unsigned short type : 2 __attribute__ ((packed));
    unsigned short subtype : 4 __attribute__ ((packed));

    unsigned short to_ds : 1 __attribute__ ((packed));
    unsigned short from_ds : 1 __attribute__ ((packed));
    unsigned short more_fragments : 1 __attribute__ ((packed));
    unsigned short retry : 1 __attribute__ ((packed));

    unsigned short power_management : 1 __attribute__ ((packed));
    unsigned short more_data : 1 __attribute__ ((packed));
    unsigned short wep : 1 __attribute__ ((packed));
    unsigned short order : 1 __attribute__ ((packed));
} frame_control;

typedef struct {
    unsigned short frag : 4 __attribute__ ((packed));
    unsigned short sequence : 12 __attribute__ ((packed));
} wireless_fragseq;

typedef struct {
    uint8_t timestamp[8];

    // This field must be converted to host-endian before being used
    unsigned int beacon : 16 __attribute__ ((packed));

    unsigned short ess : 1 __attribute__ ((packed));
    unsigned short ibss : 1 __attribute__ ((packed));
    unsigned short unused1 : 1 __attribute__ ((packed));
    unsigned short unused2 : 1 __attribute__ ((packed));

    unsigned short wep : 1 __attribute__ ((packed));
    unsigned short short_preamble : 1 __attribute__ ((packed));
    unsigned short pbcc : 1 __attribute__ ((packed));
    unsigned short agility : 1 __attribute__ ((packed));

    unsigned int coordinator : 8 __attribute__ ((packed));
} fixed_parameters;


#endif

enum protocol_info_type {
    proto_unknown,
    proto_udp, proto_misc_tcp, proto_arp, proto_dhcp_server,
    proto_cdp,
    proto_netbios, proto_netbios_tcp,
    proto_ipx,
    proto_ipx_tcp,
    proto_turbocell,
    proto_netstumbler,
    proto_lucenttest,
    proto_wellenreiter,
    proto_iapp,
    proto_leap,
    proto_ttls,
    proto_tls,
    proto_peap,
    proto_isakmp,
    proto_pptp,
};

enum protocol_netbios_type {
    proto_netbios_unknown,
    proto_netbios_host, proto_netbios_master,
    proto_netbios_domain, proto_netbios_query, proto_netbios_pdcquery
};

// CDP
// Cisco Discovery Protocol
// This spews a tremendous amount of revealing information about the
// internals of a network, if they have cisco equipment.
typedef struct {
    unsigned int : 8 __attribute__ ((packed));
    unsigned int : 8 __attribute__ ((packed));

    unsigned int : 8 __attribute__ ((packed));
    unsigned int : 1 __attribute__ ((packed));
    unsigned int level1 : 1 __attribute__ ((packed));
    unsigned int igmp_forward : 1 __attribute__ ((packed));
    unsigned int nlp : 1 __attribute__ ((packed));
    unsigned int level2_switching : 1 __attribute__ ((packed));
    unsigned int level2_sourceroute : 1 __attribute__ ((packed));
    unsigned int level2_transparent : 1 __attribute__ ((packed));
    unsigned int level3 : 1 __attribute__ ((packed));
} cdp_capabilities;

typedef struct {
    char dev_id[128];
    uint8_t ip[4];
    char interface[128];
    cdp_capabilities cap;
    char software[512];
    char platform[128];
} cdp_packet;

typedef struct {
    unsigned int type : 16 __attribute__ ((packed));
    unsigned int length : 16 __attribute__ ((packed));
    char data;
} cdp_element;

// 802.1x Header
typedef struct dot1x_header {
    uint8_t    version;
    uint8_t    type;
    uint16_t   length;
} __attribute__ ((packed)) dot1x_header_t;

// EAP Packet header
typedef struct eap_packet {
    uint8_t    code; /* 1=request, 2=response, 3=success, 4=failure */
    uint8_t    identifier; /* Sequential counter, not sure what it's for */
    uint16_t   length; /* Length of the entire EAP message */
    uint8_t    type; /* 0x11 for LEAP */
    /* The fields that follow the type octet are variable, depending on the
       type and code values.  This information isn't important for us. */
} __attribute__ ((packed)) eap_packet_t;

// ISAKMP packet header
typedef struct isakmp_packet {
    uint8_t    init_cookie[8];
    uint8_t    resp_cookie[8];
    uint8_t    next_payload;
    uint8_t    version;
    uint8_t    exchtype;
    uint8_t    flags;
    uint32_t   messageid;
    uint32_t   length;
} __attribute__ ((packed)) isakmp_packet_t;

typedef struct {
    unsigned int type : 8 __attribute__ ((packed));
    unsigned int length : 8 __attribute__ ((packed));
    unsigned int proto : 8 __attribute__ ((packed));
    unsigned int : 8 __attribute__ ((packed));
    unsigned int proto_length : 8 __attribute__ ((packed));
    char addr;
} cdp_proto_element;

// Info about a protocol
#endif

